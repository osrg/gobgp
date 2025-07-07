package peering

import (
	"context"
	"time"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func (fsm *fsm) idle(ctx context.Context) (bgp.FSMState, *FSMStateReason) {
	fsm.Lock.RLock()
	idleHoldTime := time.Duration(fsm.IdleHoldTime) * time.Second
	adminStateUp := !fsm.PeerConf.State.AdminDown
	neighborAddress := fsm.PeerConf.State.NeighborAddress
	fsm.Lock.RUnlock()

	idleHoldTimer := time.NewTimer(idleHoldTime)
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

			if !restarting {
				continue
			}

			fsm.Logger.Warn("graceful restart timer expired",
				log.Fields{
					"Topic": "Peer",
					"Key":   neighborAddress,
					"State": oc.SESSION_STATE_IDLE,
				})
			return bgp.BGP_FSM_IDLE, NewfsmStateReason(FSMRestartTimerExpired, nil, nil)
		case conn, ok := <-fsm.ConnCh:
			if !ok {
				break
			}
			conn.Close()
			fsm.Logger.Warn("Closed an accepted connection",
				log.Fields{
					"Topic": "Peer",
					"Key":   neighborAddress,
					"State": oc.SESSION_STATE_IDLE,
				})
		case <-idleHoldTimer.C:
			// only occurs when the admin state is up
			fsm.Logger.Debug("IdleHoldTimer expired",
				log.Fields{
					"Topic":    "Peer",
					"Key":      neighborAddress,
					"Duration": idleHoldTime,
				})
			fsm.Lock.Lock()
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
					idleHoldTimer.Reset(idleHoldTime)
				}
			}
		}
	}
}
