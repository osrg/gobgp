package peering

import (
	"context"
	"errors"
	"net"

	"github.com/osrg/gobgp/v4/pkg/bgputils"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func (fsm *fsm) newFSMTrackedConn(conn net.Conn) *trackedConn {
	return &trackedConn{
		Conn:   conn,
		common: fsm.common,
		// used in OpenSent state, where we start tracking the connection
		holdTime: OpenSentHoldTime,
	}
}

func (t *connTracking) strictlyBetterConn(tc *trackedConn) bool {
	t.lock.Lock()
	defer t.lock.Unlock()
	if t.best == nil || bgputils.CompareRouterID(t.best.recvdOpen.ID, tc.recvdOpen.ID) <= 0 {
		t.best = tc
		t.bestCh <- tc
		return true
	}
	return false
}

func (tc *trackedConn) Close() error {
	if tc.closed.Swap(true) {
		return nil
	}
	return tc.Conn.Close()
}

func (fsm *fsm) trackConn(tc *trackedConn) {
	transition := fsm.opensentConn(tc)
	transition.OldState = bgp.BGP_FSM_OPENSENT
	fsm.handleErrorForConn(tc, transition.Data)

	fsm.tracking.lock.RLock()
	activeConns := len(fsm.tracking.conns)
	fsm.tracking.lock.RUnlock()

	if !transition.IsAdvancing() {
		// close the connection if it failed to advance
		fsm.killTrackedConn(tc)
		// If this is the only active connection, and it failed
		// to advance, we need to send a state transition to the FSM.
		if activeConns == 1 {
			fsm.sendStateTransition(transition.NewState, transition.Reason, transition.Data)
		}
	}
}

func (fsm *fsm) killTrackedConn(tc *trackedConn) {
	if tc == nil || tc.closed.Load() {
		return
	}
	tc.Close()
	fsm.tracking.lock.Lock()
	delete(fsm.tracking.conns, tc.RemoteAddr())
	fsm.tracking.lock.Unlock()
}

func (fsm *fsm) ceaseConn(tc *trackedConn) {
	if tc == nil || tc.closed.Load() {
		return
	}
	fsm.sendNotification(tc, bgp.BGP_ERROR_CEASE, 0, "collision detected, not best")
	fsm.killTrackedConn(tc)
}

func (fsm *fsm) ceaseTrackedConns() {
	fsm.tracking.lock.Lock()
	defer fsm.tracking.lock.Unlock()
	for _, tc := range fsm.tracking.conns {
		fsm.sendNotification(tc, bgp.BGP_ERROR_CEASE, 0, "collision detected, not best")
		tc.Close()
	}
	clear(fsm.tracking.conns)
}

func (fsm *fsm) drainBestCh(initTC *trackedConn) *trackedConn {
	last := initTC
	for {
		select {
		case item := <-fsm.tracking.bestCh:
			if last != nil {
				fsm.ceaseConn(last)
			}
			last = item
		default:
			return last
		}
	}
}

func (fsm *fsm) acceptAllWaitingConns(ctx context.Context) *FSMStateTransition {
	// accept all the connections that are in the channel
	for {
		select {
		case <-ctx.Done():
			return TransitionDying.Copy()
		case conn := <-fsm.tracking.connCh:
			if err := fsm.acceptConn(conn); err != nil {
				return TransitionConnectFailed.Copy(WithData(err))
			}
		default:
			return TransitionNewConnection.Copy()
		}
	}
}

// acceptConn accepts a new connection and initializes it for BGP communication.
// It sets the TTL and MSS options, sends an OPEN message, and tracks the connection.
func (fsm *fsm) acceptConn(conn net.Conn) error {
	if conn == nil {
		return errors.New("nil connection")
	}
	state := fsm.state.Load()

	neighborAddress := conn.RemoteAddr().String()
	if err := fsm.common.SetPeerConnTTL(conn); err != nil {
		fsm.logger.Warn("failed to set peer connection TTL",
			log.Fields{
				"Topic": "Peer",
				"Key":   neighborAddress,
				"State": state.String(),
				"Error": err,
			})
	} else if err := fsm.common.SetPeerConnMSS(conn); err != nil {
		fsm.logger.Warn("failed to set peer connection MSS",
			log.Fields{
				"Topic": "Peer",
				"Key":   neighborAddress,
				"State": state.String(),
				"Error": err,
			})
	} else if err := fsm.send(conn, fsm.common.SentOpen); err != nil {
		fsm.logger.Warn("failed to send OPEN message",
			log.Fields{
				"Topic": "Peer",
				"Key":   neighborAddress,
				"State": state.String(),
				"Error": err,
			})
		conn.Close()
		return err
	}

	tc := fsm.newFSMTrackedConn(conn)
	fsm.tracking.lock.Lock()
	fsm.tracking.conns[tc.RemoteAddr()] = tc
	fsm.tracking.lock.Unlock()

	go fsm.trackConn(tc)

	return nil
}

func (t *connTracking) killTrackedConns() {
	t.lock.Lock()
	defer t.lock.Unlock()
	for _, tc := range t.conns {
		tc.Close()
	}
	clear(t.conns)
}

// killConns closes all tracked connections and the established connection.
func (fsm *fsm) killConns() {
	fsm.tracking.killTrackedConns()

	conn := fsm.conn.Swap(nil)
	if conn != nil {
		conn.Close()
	}
}
