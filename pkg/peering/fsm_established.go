package peering

import (
	"context"
	"sync"
	"time"

	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func (fsm *fsm) established(ctx context.Context) (bgp.FSMState, *FSMStateReason) {
	c, cancel := context.WithCancel(ctx)
	stateReasonCh := make(chan *FSMStateReason, 1)
	wg := &sync.WaitGroup{}
	wg.Add(2)

	defer func() {
		cancel()
		wg.Wait()
		close(stateReasonCh)
	}()

	go fsm.sendMessageloop(c, stateReasonCh, wg)
	go fsm.recvMessageloop(c, stateReasonCh, wg)

	var holdTimer *time.Timer
	if fsm.PeerConf.Timers.State.NegotiatedHoldTime == 0 {
		holdTimer = &time.Timer{}
	} else {
		fsm.Lock.RLock()
		holdTimer = time.NewTimer(time.Second * time.Duration(fsm.PeerConf.Timers.State.NegotiatedHoldTime))
		fsm.Lock.RUnlock()
	}

	fsm.GracefulRestartTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			select {
			case m := <-fsm.Notification:
				// RFC8538 defines a Hard Reset notification subcode which
				// indicates that the BGP speaker wants to reset the session
				// without triggering graceful restart procedures. Here we map
				// notification subcodes to the Hard Reset subcode following
				// the RFC8538 suggestion.
				//
				// We check Status instead of Config because RFC8538 states
				// that A BGP speaker SHOULD NOT send a Hard Reset to a peer
				// from which it has not received the "N" bit.
				if fsm.PeerConf.GracefulRestart.State.NotificationEnabled {
					if body := m.Body.(*bgp.BGPNotification); body.ErrorCode == bgp.BGP_ERROR_CEASE && bgp.ShouldHardReset(body.ErrorSubcode, false) {
						body.ErrorSubcode = bgp.BGP_ERROR_SUB_HARD_RESET
					}
				}
				b, _ := m.Serialize(fsm.MarshallingOptions)
				fsm.Conn.Write(b)
			default:
				// nothing to do
			}
			fsm.Conn.Close()
			return bgp.BGP_FSM_IDLE, NewfsmStateReason(FSMDying, nil, nil)
		case conn, ok := <-fsm.ConnCh:
			if !ok {
				break
			}
			conn.Close()
			fsm.Lock.RLock()
			fsm.Logger.Warn("Closed an accepted connection",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.PeerConf.State.NeighborAddress,
					"State": fsm.State.String(),
				})
			fsm.Lock.RUnlock()
		case err := <-stateReasonCh:
			fsm.Conn.Close()
			// if recv goroutine hit an error and sent to
			// stateReasonCh, then tx goroutine might take
			// long until it exits because it waits for
			// ctx.Done() or keepalive timer. So let kill
			// it now.
			fsm.OutgoingCh.In() <- err
			fsm.Lock.RLock()
			if s := fsm.PeerConf.GracefulRestart.State; s.Enabled {
				if s.NotificationEnabled && err.Type == FSMNotificationRecv ||
					err.Type == FSMNotificationSent &&
						err.BGPNotification.Body.(*bgp.BGPNotification).ErrorCode == bgp.BGP_ERROR_HOLD_TIMER_EXPIRED ||
					err.Type == FSMReadFailed ||
					err.Type == FSMWriteFailed {
					err = NewfsmStateReason(FSMGracefulRestart, nil, nil)
					fsm.Logger.Info("peer graceful restart",
						log.Fields{
							"Topic": "Peer",
							"Key":   fsm.PeerConf.State.NeighborAddress,
							"State": fsm.State.String(),
						})
					fsm.GracefulRestartTimer.Reset(time.Duration(fsm.PeerConf.GracefulRestart.State.PeerRestartTime) * time.Second)
				}
			}
			fsm.Lock.RUnlock()
			return bgp.BGP_FSM_IDLE, err
		case <-holdTimer.C:
			fsm.Lock.RLock()
			fsm.Logger.Warn("hold timer expired",
				log.Fields{
					"Topic": "Peer",
					"Key":   fsm.PeerConf.State.NeighborAddress,
					"State": fsm.State.String(),
				})
			fsm.Lock.RUnlock()
			m := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED, 0, nil)
			// wait for fsmOutgoingMsg to be sent
			// to avoid a race condition
			sending := make(chan any)
			fsm.OutgoingCh.In() <- &FSMOutgoingMsg{Notification: m, sending: sending}
			<-sending
			fsm.Lock.RLock()
			s := fsm.PeerConf.GracefulRestart.State
			fsm.Lock.RUnlock()
			// Do not return hold timer expired to server if graceful restart is enabled
			// Let it fallback to read/write error or fsmNotificationSent handled above
			// Reference: https://github.com/osrg/gobgp/issues/2174
			if !s.Enabled {
				return bgp.BGP_FSM_IDLE, NewfsmStateReason(FSMHoldTimerExpired, m, nil)
			}
		case <-fsm.HoldTimerResetCh:
			fsm.Lock.RLock()
			if fsm.PeerConf.Timers.State.NegotiatedHoldTime != 0 {
				holdTimer.Reset(time.Second * time.Duration(fsm.PeerConf.Timers.State.NegotiatedHoldTime))
			}
			fsm.Lock.RUnlock()
		case stateOp := <-fsm.AdminStateCh:
			err := fsm.changeAdminState(stateOp.State)
			if err == nil {
				switch stateOp.State {
				case AdminStateDown:
					m := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN, stateOp.Communication)
					fsm.OutgoingCh.In() <- &FSMOutgoingMsg{Notification: m}
				}
			}
		}
	}
}
