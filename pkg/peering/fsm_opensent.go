package peering

import (
	"context"
	"net"
	"os"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/pkg/errors"
)

func (fsm *fsm) opensent(ctx context.Context) *FSMStateTransition {
	conn := fsm.conn.Load()

	for {
		select {
		case <-ctx.Done():
			return TransitionDying.Copy()
		case conn := <-fsm.tracking.connCh:
			// if we cannot accept the connection, we just ignore it
			_ = fsm.acceptConn(conn)
			_ = fsm.acceptAllWaitingConns(ctx)
		case <-fsm.timers.gracefulRestartTimer.C:
			fsm.common.Lock.RLock()
			restarting := fsm.common.PeerConf.GracefulRestart.State.PeerRestarting
			fsm.common.Lock.RUnlock()

			if !restarting {
				continue
			}

			return TransitionGracefulRestartTimerExpired.Copy()
		case tc := <-fsm.tracking.bestCh:
			// a new connection is the best one
			// and must have received the open message back from the peer.
			fsm.ceaseConn(conn)
			tc = fsm.drainBestCh(tc)
			fsm.conn.Store(tc)
			return TransitionOpenMsgReceived.Copy()
		case transition := <-fsm.transitionCh:
			return transition
		case stateOp := <-fsm.adminStateCh:
			fsm.changeAdminState(stateOp.state)
			switch stateOp.state {
			case AdminStateDown:
				err := bgp.NewMessageError(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN, nil, stateOp.communication)
				return TransitionAdminDown.Copy(WithData(err))
			default:
			}
		}
	}
}

func (fsm *fsm) opensentConn(tc *trackedConn) *FSMStateTransition {
	tc.SetReadDeadline(time.Now().Add(tc.holdTime))

	msg, err := fsm.recvMessageWithError(tc)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		// hold timer is expired
		return TransitionHoldTimerExpired.Copy()
	} else if errors.Is(err, TransitionReadFailed) {
		// return to active state if the tcp connection is closed
		return err.(*FSMStateTransition).Copy(WithNewState(bgp.BGP_FSM_ACTIVE))
	} else if err != nil {
		return err.(*FSMStateTransition)
	}

	m := msg.Message
	if m.Header.Type != bgp.BGP_MSG_OPEN {
		err = bgp.NewMessageError(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_RECEIVE_UNEXPECTED_MESSAGE_IN_OPENSENT_STATE, nil, "unexpected message in opensent state")
		return TransitionUnexpectedMsg.Copy(WithData(err))
	}

	fsmPeerAs := fsm.common.PeerConf.Config.PeerAs
	localAs := fsm.common.PeerConf.Config.LocalAs
	routerID := net.ParseIP(fsm.common.GlobalConf.Config.RouterId)

	body := m.Body.(*bgp.BGPOpen)
	peerAs := uint32(0)
	peerAs, err = bgp.ValidateOpenMsg(body, fsmPeerAs, localAs, routerID)
	if err != nil {
		return TransitionUnexpectedMsg.Copy(WithData(err))
	}

	keepalive := bgp.NewBGPKeepAliveMessage()
	if err := fsm.send(tc, keepalive); err != nil {
		return TransitionWriteFailed.Copy(WithData(err))
	}

	tc.recvdOpen = body
	tc.peerAs = peerAs

	holdTime := fsm.timers.holdTime
	keepAliveInterval := fsm.timers.keepAliveInterval

	// calculate HoldTime
	// RFC 4271 P.13
	// a BGP speaker MUST calculate the value of the Hold Timer
	// by using the smaller of its configured Hold Time and the Hold Time
	// received in the OPEN message.
	peerHoldTime := time.Second * time.Duration(body.HoldTime)
	if peerHoldTime < holdTime {
		holdTime = peerHoldTime
		keepAliveInterval = holdTime / 3
	}

	tc.holdTime = holdTime
	tc.keepAliveInterval = keepAliveInterval

	// we need the open message to determine the best connection.
	// we let only a strictly better connection to proceed.
	// this ensure that we only have one connection in the open confirm state
	// at a given time.
	if !fsm.tracking.strictlyBetterConn(tc) {
		return TransitionCollisionDetected.Copy()
	}

	// remove the deadline for the read operation
	tc.SetReadDeadline(time.Time{})

	// this is the best connection that we have so far
	return TransitionOpenMsgReceived.Copy()
}
