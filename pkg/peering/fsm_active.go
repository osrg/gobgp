package peering

import (
	"context"
	"sync"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func (fsm *fsm) active(ctx context.Context) (bgp.FSMState, *FSMStateReason) {
	c, cancel := context.WithCancel(ctx)
	wg := &sync.WaitGroup{}

	fsm.Lock.RLock()
	tryConnect := !fsm.PeerConf.Transport.Config.PassiveMode
	neighborAddress := fsm.PeerConf.Config.NeighborAddress
	fsm.Lock.RUnlock()

	if tryConnect {
		wg.Add(1)
		go fsm.connectLoop(c, wg)
	}

	defer func() {
		cancel()
		wg.Wait()
	}()

	for {
		select {
		case <-ctx.Done():
			return bgp.BGP_FSM_IDLE, NewfsmStateReason(FSMDying, nil, nil)
		case conn, ok := <-fsm.ConnCh:
			if !ok {
				break
			}
			fsm.Lock.Lock()
			fsm.Conn = conn
			fsm.Lock.Unlock()

			if err := fsm.SetPeerConnTTL(); err != nil {
				fsm.Logger.Warn("cannot set TTL for peer",
					log.Fields{
						"Topic": "Peer",
						"Key":   neighborAddress,
						"State": oc.SESSION_STATE_ACTIVE,
						"Error": err,
					})
			}
			if err := fsm.SetPeerConnMSS(); err != nil {
				fsm.Logger.Warn("cannot set MSS for peer",
					log.Fields{
						"Topic": "Peer",
						"Key":   neighborAddress,
						"State": oc.SESSION_STATE_ACTIVE,
						"Error": err,
					})
			}
			// we don't implement delayed open timer so move to opensent right
			// away.
			return bgp.BGP_FSM_OPENSENT, NewfsmStateReason(FSMNewConnection, nil, nil)
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
					"State": oc.SESSION_STATE_ACTIVE,
				})
			return bgp.BGP_FSM_IDLE, NewfsmStateReason(FSMRestartTimerExpired, nil, nil)
		case stateOp := <-fsm.AdminStateCh:
			err := fsm.changeAdminState(stateOp.State)
			if err != nil {
				continue
			}

			switch stateOp.State {
			case AdminStateDown:
				return bgp.BGP_FSM_IDLE, NewfsmStateReason(FSMAdminDown, nil, nil)
			case AdminStateUp:
				fsm.Logger.Panic("code logic bug",
					log.Fields{
						"Topic":      "Peer",
						"Key":        neighborAddress,
						"State":      oc.SESSION_STATE_ACTIVE,
						"AdminState": oc.ADMIN_STATE_UP,
					})
			}
		}
	}
}
