package peering

import (
	"context"
)

func (fsm *fsm) active(ctx context.Context) *FSMStateTransition {
	connectRetryTime := fsm.timers.connectRetryTime

	passive := fsm.common.PeerConf.Transport.Config.PassiveMode
	if !passive {
		fsm.timers.connectRetryTimer.Reset(connectRetryTime)
	}

	for {
		select {
		case <-ctx.Done():
			return TransitionDying.Copy()
		case conn := <-fsm.tracking.connCh:
			if err := fsm.acceptConn(conn); err != nil {
				return TransitionConnectFailed.Copy()
			}
			// we don't implement delayed open timer so move to opensent right
			// away.
			return TransitionNewConnection.Copy()
		case <-fsm.timers.connectRetryTimer.C:
			return TransitionConnectRetryExpired.Copy()
		case <-fsm.timers.gracefulRestartTimer.C:
			fsm.common.Lock.RLock()
			restarting := fsm.common.PeerConf.GracefulRestart.State.PeerRestarting
			fsm.common.Lock.RUnlock()

			if !restarting {
				continue
			}
			return TransitionGracefulRestartTimerExpired.Copy()
		case stateOp := <-fsm.adminStateCh:
			fsm.changeAdminState(stateOp.state)
			switch stateOp.state {
			case AdminStateDown:
				return TransitionAdminDown.Copy()
			default:
			}
		}
	}
}
