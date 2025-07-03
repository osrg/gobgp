package peering

import (
	"context"
	"sync"

	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func (fsm *fsm) active(ctx context.Context) (bgp.FSMState, *FSMStateReason) {
	fsm.Lock.RLock()
	tryConnect := !fsm.PeerConf.Transport.Config.PassiveMode
	fsm.Lock.RUnlock()

	c, cancel := context.WithCancel(ctx)
	connectWg := &sync.WaitGroup{}
	if tryConnect {
		connectWg.Add(1)
		go fsm.connectLoop(c, connectWg)
	}
	defer func() {
		cancel()
		connectWg.Wait()
	}()

	for {
		select {
		case <-ctx.Done():
			return bgp.BGP_FSM_IDLE, NewFSMStateReason(FSMDying, nil, nil)
		case conn, ok := <-fsm.ConnCh:
			if !ok {
				break
			}
			fsm.Lock.Lock()
			fsm.Conn = conn
			fsm.Lock.Unlock()

			fsm.Lock.RLock()
			if err := fsm.SetPeerConnTTL(); err != nil {
				fsm.Logger.Warn("cannot set TTL for peer",
					log.Fields{
						"Topic": "Peer",
						"Key":   fsm.PeerConf.Config.NeighborAddress,
						"State": fsm.State.String(),
						"Error": err,
					})
			}
			if err := fsm.SetPeerConnMSS(); err != nil {
				fsm.Logger.Warn("cannot set MSS for peer",
					log.Fields{
						"Topic": "Peer",
						"Key":   fsm.PeerConf.Config.NeighborAddress,
						"State": fsm.State.String(),
						"Error": err,
					})
			}
			fsm.Lock.RUnlock()
			// we don't implement delayed open timer so move to opensent right
			// away.
			return bgp.BGP_FSM_OPENSENT, NewFSMStateReason(FSMNewConnection, nil, nil)
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
				return bgp.BGP_FSM_IDLE, NewFSMStateReason(FMSRestartTimerExpired, nil, nil)
			}
		case stateOp := <-fsm.AdminStateCh:
			err := fsm.changeAdminState(stateOp.State)
			if err == nil {
				switch stateOp.State {
				case AdminStateDown:
					return bgp.BGP_FSM_IDLE, NewFSMStateReason(FSMAdminDown, nil, nil)
				case AdminStateUp:
					fsm.Logger.Panic("code logic bug",
						log.Fields{
							"Topic":      "Peer",
							"Key":        fsm.PeerConf.State.NeighborAddress,
							"State":      fsm.State.String(),
							"AdminState": stateOp.State.String(),
						})
				}
			}
		}
	}
}
