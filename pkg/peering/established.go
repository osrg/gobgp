package peering

import (
	"context"
	"sync"
	"time"

	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func (fsm *FSM) established(ctx context.Context) (bgp.FSMState, *FSMStateReason) {
	c, cancel := context.WithCancel(ctx)
	loopWg := &sync.WaitGroup{}
	loopWg.Add(2)

	reasonChan := make(chan *FSMStateReason, 2)
	sendChan := fsm.OutgoingCh
	recvChan := fsm.IncomingCh.In()
	go fsm.sendMessageLoop(c, loopWg, sendChan, reasonChan)
	go fsm.recvMessageLoop(c, loopWg, recvChan, reasonChan)

	defer func() {
		cancel()
		loopWg.Wait()
		close(reasonChan)
	}()

	fsm.Lock.RLock()
	holdTime := fsm.PeerConf.Timers.State.NegotiatedHoldTime
	fsm.Lock.RUnlock()

	var holdTimer *time.Timer
	if holdTime == 0 {
		holdTimer = &time.Timer{}
	} else {
		holdTimer = time.NewTimer(time.Second * time.Duration(holdTime))
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
			return -1, NewFSMStateReason(FSMDying, nil, nil)
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
		case err := <-reasonChan:
			fsm.Lock.RLock()
			if s := fsm.PeerConf.GracefulRestart.State; s.Enabled {
				if s.NotificationEnabled && err.Type == FSMNotificationRecv ||
					err.Type == FSMNotificationSent &&
						err.BGPNotification.Body.(*bgp.BGPNotification).ErrorCode == bgp.BGP_ERROR_HOLD_TIMER_EXPIRED ||
					err.Type == FSMReadFailed ||
					err.Type == FSMWriteFailed {
					err = NewFSMStateReason(FSMGracefulRestart, nil, nil)
					restartTime := fsm.PeerConf.GracefulRestart.State.PeerRestartTime
					fsm.Logger.Info("peer graceful restart",
						log.Fields{
							"Topic":       "Peer",
							"Key":         fsm.PeerConf.State.NeighborAddress,
							"State":       fsm.State.String(),
							"restartTime": restartTime,
						})
					fsm.GracefulRestartTimer.Reset(time.Duration(restartTime) * time.Second)
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
			sendChan <- &FSMOutgoingMsg{Notification: m}
			fsm.Lock.RLock()
			s := fsm.PeerConf.GracefulRestart.State
			fsm.Lock.RUnlock()
			// Do not return hold timer expired to server if graceful restart is enabled
			// Let it fallback to read/write error or fsmNotificationSent handled above
			// Reference: https://github.com/osrg/gobgp/issues/2174
			if !s.Enabled {
				return bgp.BGP_FSM_IDLE, NewFSMStateReason(FSMHoldTimerExpired, m, nil)
			}
		case <-fsm.holdTimerResetCh:
			fsm.Lock.RLock()
			if fsm.PeerConf.Timers.State.NegotiatedHoldTime != 0 {
				holdTimer.Reset(time.Second * time.Duration(fsm.PeerConf.Timers.State.NegotiatedHoldTime))
			}
			fsm.Lock.RUnlock()
		case stateOp := <-fsm.AdminStateCh:
			err := fsm.changeadminState(stateOp.State)
			if err == nil {
				switch stateOp.State {
				case AdminStateDown:
					m := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN, stateOp.Communication)
					sendChan <- &FSMOutgoingMsg{Notification: m}
				}
			}
		}
	}
}
