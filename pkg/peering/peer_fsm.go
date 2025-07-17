package peering

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func (peer *Peer) StartFSM(wg *sync.WaitGroup, bgpCallback FSMBGPCallback, transitionCallback FSMTransitionCallback) {
	ctx, cancel := context.WithCancel(context.Background())
	fsm := newFSM(peer.Common, bgpCallback, transitionCallback, peer.Logger)

	peer.Lock.Lock()
	peer.ctx = ctx
	peer.cancel = cancel
	peer.fsm = fsm
	peer.Lock.Unlock()

	wg.Add(1)
	go peer.fsm.loop(ctx, wg)
}

func (peer *Peer) StopFSM() {
	peer.Lock.RLock()
	defer peer.Lock.RUnlock()
	if peer.fsm == nil {
		return // already stopped
	}
	peer.cancel()
	peer.fsm = nil
}

func (peer *Peer) connLocalAddressValid(conn net.Conn) bool {
	laddr := peer.Common.PeerConf.Transport.Config.LocalAddress
	bindInterface := peer.Common.PeerConf.Transport.Config.BindInterface

	if laddr == "0.0.0.0" || laddr == "::" {
		return true
	}

	l := conn.LocalAddr()
	if l == nil {
		// already closed
		return false
	}

	host, _, _ := net.SplitHostPort(l.String())
	return host == laddr || bindInterface != ""
}

func (peer *Peer) PassConn(conn net.Conn) {
	adminState := peer.fsm.adminState.Load()
	if adminState != AdminStateUp {
		peer.Logger.Debug("new connection for administratively down peer",
			log.Fields{
				"Topic":       "Peer",
				"Remote Addr": conn.RemoteAddr().String(),
				"Admin State": adminState.String(),
			})
		conn.Close()
		return
	}

	laddr := peer.Common.PeerConf.Transport.Config.LocalAddress
	if !peer.connLocalAddressValid(conn) {
		peer.Logger.Debug("peer tries to connect with mismatched local address",
			log.Fields{
				"Topic":         "Peer",
				"ExpectedLocal": laddr,
				"ConnLocal":     conn.LocalAddr().String(),
				"ConnRemote":    conn.RemoteAddr().String(),
			})

		conn.Close()
		return
	}

	peer.Logger.Debug("peer tries to connect",
		log.Fields{
			"Topic": "Peer",
			"Key":   conn.RemoteAddr().String(),
		})

	select {
	case peer.fsm.tracking.connCh <- conn:
	default:
		conn.Close()
	}
}

func (peer *Peer) SetAdminState(state AdminState, communication string) {
	operation := &AdminStateOperation{
		state:         state,
		communication: communication,
	}
	select {
	case peer.fsm.adminStateCh <- operation:
	default:
		peer.Common.Lock.RLock()
		neighiborAddress := peer.Common.PeerConf.State.NeighborAddress
		peer.Common.Lock.RUnlock()
		peer.Logger.Warn("previous setting admin state request is still remaining",
			log.Fields{
				"Topic": "Peer",
				"Key":   neighiborAddress,
			})
	}
}

func (peer *Peer) Reset(communication string) error {
	peer.Common.Lock.RLock()
	idleHoldTime := peer.Common.PeerConf.Timers.Config.IdleHoldTimeAfterReset
	peer.Common.Lock.RUnlock()

	peer.fsm.timers.idleHoldTime = time.Second * time.Duration(idleHoldTime)

	return peer.fsm.sendNotificationToAll(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET, communication)
}
