package peering

import (
	"context"
	"time"

	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func (fsm *fsm) idle(ctx context.Context) (bgp.FSMState, *FSMStateReason) {
	fsm.Lock.RLock()
	idleHoldTimer := time.NewTimer(time.Second * time.Duration(fsm.IdleHoldTime))
	adminStateUp := !fsm.PeerConf.State.AdminDown
	fsm.Lock.RUnlock()

	// If the admin state is down, we don't start the idle hold timer.
	if !adminStateUp {
		idleHoldTimer.Stop()
	}

	for {
		select {
		case <-ctx.Done():
			return bgp.BGP_FSM_IDLE, NewfsmStateReason(FSMDying, nil, nil)
		case <-fsm.GracefulRestartTimer.C:
			fsm.Lock.RLock()
			restarting := fsm.PeerConf.GracefulRestart.State.PeerRestarting
			fsm.Lock.RUnlock()

			if restarting {
				fsm.Lock.RLock()
				fsm.Logger.Warn("graceful restart timer expired",
					log.Fields{
						"Topic": "Peer",
						"Key":   fsm.PeerConf.State.NeighborAddress,
						"State": fsm.State.String(),
					})
				fsm.Lock.RUnlock()
				return bgp.BGP_FSM_IDLE, NewfsmStateReason(FSMRestartTimerExpired, nil, nil)
			}
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
		case <-idleHoldTimer.C:
			// only occurs when the admin state is up
			fsm.Lock.Lock()
			fsm.Logger.Debug("IdleHoldTimer expired",
				log.Fields{
					"Topic":    "Peer",
					"Key":      fsm.PeerConf.State.NeighborAddress,
					"Duration": fsm.IdleHoldTime,
				})
			fsm.IdleHoldTime = HoldTimeIdle
			fsm.Lock.Unlock()
			return bgp.BGP_FSM_ACTIVE, NewfsmStateReason(FSMIdleTimerExpired, nil, nil)
		case stateOp := <-fsm.AdminStateCh:
			err := fsm.changeAdminState(stateOp.State)
			if err == nil {
				switch stateOp.State {
				case AdminStateDown:
					// stop idle hold timer
					idleHoldTimer.Stop()

				case AdminStateUp:
					// restart idle hold timer
					fsm.Lock.RLock()
					idleHoldTimer.Reset(time.Second * time.Duration(fsm.IdleHoldTime))
					fsm.Lock.RUnlock()
				}
			}
		}
	}
}
