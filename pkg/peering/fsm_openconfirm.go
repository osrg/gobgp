package peering

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func (fsm *fsm) openconfirm(ctx context.Context) *FSMStateTransition {
	// we enter this state when the first time a connection receive an
	// open message back from the peer.

	var holdTime, keepAliveInterval time.Duration
	wg := &sync.WaitGroup{}
	keepAlive := bgp.NewBGPKeepAliveMessage()
	recvChan := make(chan *FSMMsg, 1)

	conn := fsm.conn.Load()

	updateConn := func() {
		holdTime = conn.holdTime
		keepAliveInterval = conn.keepAliveInterval
		fsm.timers.holdTimer.Stop()
		if holdTime > 0 {
			fsm.timers.holdTimer.Reset(holdTime)
		}
		fsm.timers.keepAliveTimer.Stop()
		if keepAliveInterval > 0 {
			fsm.timers.keepAliveTimer.Reset(keepAliveInterval)
		}

		wg.Add(1)
		go fsm.recvMessage(ctx, conn, recvChan, wg)
	}

	updateConn()

	defer func() {
		conn.SetReadDeadline(time.Now())
		fsm.timers.holdTimer.Stop()
		fsm.timers.keepAliveTimer.Stop()
		wg.Wait()
		close(recvChan)
		conn.SetReadDeadline(time.Time{})
	}()

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
		case <-fsm.timers.keepAliveTimer.C:
			if err := fsm.send(conn, keepAlive); err != nil {
				return TransitionWriteFailed.Copy(WithData(err))
			}
			fsm.timers.keepAliveTimer.Reset(keepAliveInterval)
		case <-fsm.timers.holdTimer.C:
			return TransitionHoldTimerExpired.Copy()
		case msg := <-recvChan:
			// before moving to the next state, we must check if the
			// there is no best connection in the tracking channel.
			tc := fsm.drainBestCh(nil)
			if tc == nil {
				// no best connection, so we can process the received message
				return openconfirmRecvMsg(msg)
			}

			// there is a best connection, so we must cease the current one
			// and switch to the best one.
			// we must restart the hold timer because the best connection
			// might have a different hold time.
			fsm.ceaseConn(conn)
			conn = fsm.conn.Swap(tc)
			updateConn()
		case tc := <-fsm.tracking.bestCh:
			// a new connection is the best one
			// and must have received the open message back from the peer.
			fsm.ceaseConn(conn)
			tc = fsm.drainBestCh(tc)
			conn = fsm.conn.Swap(tc)
			updateConn()
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

func openconfirmRecvMsg(msg *FSMMsg) *FSMStateTransition {
	m := msg.Message
	switch m.Header.Type {
	case bgp.BGP_MSG_KEEPALIVE:
		return TransitionOpenMsgNegotiated.Copy()
	case bgp.BGP_MSG_NOTIFICATION:
		notif := m.Body.(*bgp.BGPNotification)
		return TransitionNotificationRecv.Copy(WithData(notif))
	default:
		err := bgp.NewMessageError(bgp.BGP_ERROR_FSM_ERROR, 0, nil, "unexpected message type in OpenConfirm state: "+strconv.Itoa(int(m.Header.Type)))
		return TransitionUnexpectedMsg.Copy(WithData(err))
	}
}
