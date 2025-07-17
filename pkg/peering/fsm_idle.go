package peering

import (
	"context"
)

func (fsm *fsm) idle(ctx context.Context) *FSMStateTransition {
	adminStateUp := fsm.adminState.Load() == AdminStateUp
	idleHoldTime := fsm.timers.idleHoldTime
	passive := fsm.common.PeerConf.Transport.Config.PassiveMode

	// If the admin state is down, we don't start the idle hold timer.
	if !adminStateUp {
		fsm.timers.idleHoldTimer.Stop()
	} else {
		fsm.timers.idleHoldTimer.Reset(idleHoldTime)
		// the first time we enter idle, the timer value is 0.
		// we set the idle hold time to the default value.
		fsm.timers.idleHoldTime = IdleHoldTime
	}

	for {
		select {
		case <-ctx.Done():
			return TransitionDying.Copy()
		case conn := <-fsm.tracking.connCh:
			conn.Close()
		case <-fsm.timers.gracefulRestartTimer.C:
			fsm.common.Lock.RLock()
			restarting := fsm.common.PeerConf.GracefulRestart.State.PeerRestarting
			fsm.common.Lock.RUnlock()

			if !restarting {
				continue
			}
			return TransitionGracefulRestartTimerExpired.Copy()
		case <-fsm.timers.idleHoldTimer.C:
			if passive {
				return TransitionPassiveIdleHoldTimerExpired.Copy()
			} else {
				return TransitionIdleHoldTimerExpired.Copy()
			}
		case stateOp := <-fsm.adminStateCh:
			fsm.changeAdminState(stateOp.state)
			switch stateOp.state {
			case AdminStateDown:
				// stop idle hold timer
				fsm.timers.idleHoldTimer.Stop()
			case AdminStateUp:
				// restart idle hold timer
				fsm.timers.idleHoldTimer.Reset(idleHoldTime)
			}
		}
	}
}
