package peering

import (
	"context"
	"sync"
	"time"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func (fsm *fsm) established(ctx context.Context) *FSMStateTransition {
	c, cancel := context.WithCancel(ctx)
	wg := &sync.WaitGroup{}
	wg.Add(2)

	go fsm.sendMessageLoop(c, wg)
	go fsm.recvMessageLoop(c, wg)

	fsm.common.Lock.RLock()
	neighborAddress := fsm.common.PeerConf.State.NeighborAddress
	gracefulEnabled := fsm.common.PeerConf.GracefulRestart.State.Enabled
	notificationEnabled := fsm.common.PeerConf.GracefulRestart.State.NotificationEnabled
	fsm.common.Lock.RUnlock()

	holdTime := fsm.timers.holdTime
	keepAliveInterval := fsm.timers.keepAliveInterval
	gracefulRestartTime := fsm.timers.gracefulRestartTime
	fsm.timers.holdTimer.Stop()
	if holdTime > 0 {
		fsm.timers.holdTimer.Reset(holdTime)
	}
	fsm.timers.keepAliveTimer.Stop()
	if keepAliveInterval > 0 {
		fsm.timers.keepAliveTimer.Reset(keepAliveInterval)
	}
	fsm.timers.gracefulRestartTimer.Stop()

	keepAlive := bgp.NewBGPKeepAliveMessage()

	conn := fsm.conn.Load()

	defer func() {
		fsm.timers.keepAliveTimer.Stop()
		fsm.timers.holdTimer.Stop()
		cancel()
		conn.SetReadDeadline(time.Now())
		wg.Wait()
	}()

	for {
		select {
		case <-ctx.Done():
			select {
			case m := <-fsm.endNotificationCh:
				// RFC8538 defines a Hard Reset notification subcode which
				// indicates that the BGP speaker wants to reset the session
				// without triggering graceful restart procedures. Here we map
				// notification subcodes to the Hard Reset subcode following
				// the RFC8538 suggestion.
				//
				// We check Status instead of Config because RFC8538 states
				// that A BGP speaker SHOULD NOT send a Hard Reset to a peer
				// from which it has not received the "N" bit.
				if notificationEnabled {
					if body := m.Body.(*bgp.BGPNotification); body.ErrorCode == bgp.BGP_ERROR_CEASE && bgp.ShouldHardReset(body.ErrorSubcode, false) {
						body.ErrorSubcode = bgp.BGP_ERROR_SUB_HARD_RESET
					}
				}
				b, _ := m.Serialize(fsm.marshallingOptions.Load())
				conn.Write(b)
			default:
				// nothing to do
			}
			return TransitionDying.Copy()
		case conn := <-fsm.tracking.connCh:
			// stop accepting new connections
			conn.Close()
		case transition := <-fsm.transitionCh:
			if gracefulEnabled && (notificationEnabled && transition.Reason == FSMNotificationRecv ||
				transition.Reason == FSMReadFailed ||
				transition.Reason == FSMWriteFailed) {
				fsm.logger.Info("Graceful restart",
					log.Fields{
						"Topic": "Peer",
						"Key":   neighborAddress,
						"State": oc.SESSION_STATE_ESTABLISHED,
					})
				fsm.timers.gracefulRestartTimer.Reset(gracefulRestartTime)
				return TransitionGracefulRestart.Copy(WithData(transition.Data))
			}
			return transition
		case <-fsm.timers.keepAliveTimer.C:
			err := fsm.send(conn, keepAlive)
			if err != nil {
				return TransitionWriteFailed.Copy(WithData(err))
			}
			fsm.timers.keepAliveTimer.Reset(keepAliveInterval)
		case <-fsm.timers.holdTimer.C:
			err := bgp.NewMessageError(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED, 0, nil, "hold timer expired")
			if gracefulEnabled {
				fsm.timers.gracefulRestartTimer.Reset(gracefulRestartTime)
				return TransitionGracefulRestart.Copy(WithData(err))
			}
			return TransitionHoldTimerExpired.Copy(WithData(err))
		case stateOp := <-fsm.adminStateCh:
			fsm.changeAdminState(stateOp.state)
			switch stateOp.state {
			case AdminStateDown:
				err := bgp.NewMessageError(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN, nil, stateOp.communication)
				return TransitionAdminDown.Copy(WithData(err))
			case AdminStatePfxCt:
				err := bgp.NewMessageError(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_MAXIMUM_NUMBER_OF_PREFIXES_REACHED, nil, stateOp.communication)
				return TransitionAdminPfxCt.Copy(WithData(err))
			default:
			}
		}
	}
}
