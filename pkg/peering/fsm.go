// Copyright (C) 2014-2021 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package peering

import (
	"context"
	"maps"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eapache/channels"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/osrg/gobgp/v4/pkg/bgputils"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/utils"
)

func newFSM(common *FSMCommon, bgpCallback FSMBGPCallback, transitionCallback FSMTransitionCallback, logger log.Logger) *fsm {
	if bgpCallback == nil {
		bgpCallback = func(*FSMMsg) {}
	}
	if transitionCallback == nil {
		transitionCallback = func(*FSMStateTransition) {}
	}
	adminState := AdminStateUp
	if common.PeerConf.Config.AdminDown {
		adminState = AdminStateDown
	}
	tracking := &connTracking{
		connCh: make(chan net.Conn, 10),
		conns:  map[net.Addr]*trackedConn{},
		bestCh: make(chan *trackedConn, 10),
	}
	return &fsm{
		common:             common,
		adminState:         utils.NewAtomic(adminState),
		adminStateCh:       make(chan *AdminStateOperation, 1),
		tracking:           tracking,
		conn:               atomic.Pointer[trackedConn]{},
		state:              utils.NewAtomic(bgp.BGP_FSM_IDLE),
		outgoingCh:         channels.NewInfiniteChannel(),
		transitionCh:       make(chan *FSMStateTransition, 1),
		endNotificationCh:  make(chan *bgp.BGPMessage, 1),
		stats:              &fsmStats{},
		marshallingOptions: atomic.Pointer[bgp.MarshallingOption]{},
		timers:             newFSMTimers(common),
		bgpCallback:        bgpCallback,
		transitionCallback: transitionCallback,
		logger:             logger,
	}
}

func (fsm *fsm) RemoteHostPort() (string, uint16) {
	conn := fsm.conn.Load()
	if conn == nil {
		return "", 0
	}
	return netutils.HostPort(conn.RemoteAddr())
}

func (fsm *fsm) LocalHostPort() (string, uint16) {
	conn := fsm.conn.Load()
	if conn == nil {
		return "", 0
	}
	return netutils.HostPort(conn.LocalAddr())
}

func (fsm *fsm) step(ctx context.Context) *FSMStateTransition {
	oldState := fsm.state.Load()

	var transition *FSMStateTransition
	switch oldState {
	case bgp.BGP_FSM_IDLE:
		transition = fsm.idle(ctx)
	case bgp.BGP_FSM_CONNECT:
		transition = fsm.connect(ctx)
	case bgp.BGP_FSM_ACTIVE:
		transition = fsm.active(ctx)
	case bgp.BGP_FSM_OPENSENT:
		transition = fsm.opensent(ctx)
	case bgp.BGP_FSM_OPENCONFIRM:
		transition = fsm.openconfirm(ctx)
	case bgp.BGP_FSM_ESTABLISHED:
		transition = fsm.established(ctx)
	}

	transition.OldState = oldState
	fsm.handleError(transition.Data)
	fsm.stateChange(transition)

	// do not execute the callback if the context is done
	if ctx.Err() != nil {
		return transition
	}

	fsm.transitionCallback(transition)
	return transition
}

func (fsm *fsm) loop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	for ctx.Err() == nil {
		fsm.step(ctx)
	}

	fsm.stop()
}

func (fsm *fsm) stop() {
	conn := fsm.conn.Load()
	// context is done, so we need to close the connection
	if conn != nil {
		err := conn.Close()
		if err != nil {
			fsm.logger.Error("failed to close existing tcp connection",
				log.Fields{
					"Topic": "Peer",
					"Key":   conn.RemoteAddr().String(),
					"State": fsm.state.Load().String(),
				})
		}
	}

	fsm.outgoingCh.Close()
}

func (c *FSMCommon) updateFromBestConn(tc *trackedConn) {
	fsmPeerAs := c.PeerConf.Config.PeerAs
	peerType := c.PeerConf.Config.PeerType
	localAs := c.PeerConf.Config.LocalAs
	gracefulRestartEnabled := c.PeerConf.GracefulRestart.Config.Enabled
	longLivedEnabled := c.PeerConf.GracefulRestart.Config.LongLivedEnabled

	c.Lock.RLock()
	// peerRestarting := c.PeerConf.GracefulRestart.St
	localRestarting := c.PeerConf.GracefulRestart.State.LocalRestarting
	c.Lock.RUnlock()

	// ASN negotiation
	if fsmPeerAs == 0 {
		typ := oc.PEER_TYPE_EXTERNAL
		if localAs == tc.peerAs {
			typ = oc.PEER_TYPE_INTERNAL
		}
		peerType = typ
	}

	body := tc.recvdOpen

	c.Lock.Lock()
	defer c.Lock.Unlock()

	c.PeerConf.State.PeerType = peerType
	c.PeerConf.State.PeerAs = tc.peerAs
	c.PeerConf.State.RemoteRouterId = body.ID.String()

	c.PeerInfo.AS = tc.peerAs
	c.PeerInfo.ID = body.ID
	capMap, rfMap := bgputils.Open2Cap(body, c.PeerConf)
	c.CapMap = capMap
	c.RFMap = rfMap

	gr, grOk := capMap[bgp.BGP_CAP_GRACEFUL_RESTART]
	if gracefulRestartEnabled && grOk {
		cap := gr[len(gr)-1].(*bgp.CapGracefulRestart)

		c.PeerConf.GracefulRestart.State.PeerRestartTime = cap.Time
		c.PeerConf.GracefulRestart.State.Enabled = true

		for _, t := range cap.Tuples {
			n := bgp.AddressFamilyNameMap[bgp.NewFamily(t.AFI, t.SAFI)]
			for i, a := range c.PeerConf.AfiSafis {
				if string(a.Config.AfiSafiName) == n {
					c.PeerConf.AfiSafis[i].MpGracefulRestart.State.Enabled = true
					c.PeerConf.AfiSafis[i].MpGracefulRestart.State.Received = true
					break
				}
			}
		}

		// RFC 4724 4.1
		// To re-establish the session with its peer, the Restarting Speaker
		// MUST set the "Restart State" bit in the Graceful Restart Capability
		// of the OPEN message.
		// if peerRestarting && cap.Flags&0x08 == 0 {
		// just ignore
		// }

		// RFC 4724 3
		// The most significant bit is defined as the Restart State (R)
		// bit, ...(snip)... When set (value 1), this bit
		// indicates that the BGP speaker has restarted, and its peer MUST
		// NOT wait for the End-of-RIB marker from the speaker before
		// advertising routing information to the speaker.
		if localRestarting && cap.Flags&0x08 != 0 {
			for i := range c.PeerConf.AfiSafis {
				c.PeerConf.AfiSafis[i].MpGracefulRestart.State.EndOfRibReceived = true
			}
		}
		if c.PeerConf.GracefulRestart.Config.NotificationEnabled && cap.Flags&0x04 > 0 {
			c.PeerConf.GracefulRestart.State.NotificationEnabled = true
		}
	}

	llgr, llgrOk := capMap[bgp.BGP_CAP_LONG_LIVED_GRACEFUL_RESTART]
	if longLivedEnabled && grOk && llgrOk {
		c.PeerConf.GracefulRestart.State.LongLivedEnabled = true
		cap := llgr[len(llgr)-1].(*bgp.CapLongLivedGracefulRestart)
		for _, t := range cap.Tuples {
			n := bgp.AddressFamilyNameMap[bgp.NewFamily(t.AFI, t.SAFI)]
			for i, a := range c.PeerConf.AfiSafis {
				if string(a.Config.AfiSafiName) == n {
					c.PeerConf.AfiSafis[i].LongLivedGracefulRestart.State.Enabled = true
					c.PeerConf.AfiSafis[i].LongLivedGracefulRestart.State.Received = true
					c.PeerConf.AfiSafis[i].LongLivedGracefulRestart.State.PeerRestartTime = t.RestartTime
					break
				}
			}
		}
	}

	serializedOpen, _ := body.Serialize()
	bgpOpen, _ := bgp.ParseBGPMessage(serializedOpen)

	c.PeerConf.Transport.State.LocalAddress, c.PeerConf.Transport.State.LocalPort = netutils.HostPort(tc.LocalAddr())
	c.PeerConf.Transport.State.RemoteAddress, c.PeerConf.Transport.State.RemotePort = netutils.HostPort(tc.RemoteAddr())

	c.PeerConf.State.ReceivedOpenMessage = bgpOpen

	laddr := c.PeerConf.Transport.State.LocalAddress
	// exclude zone info
	ipaddr, _ := net.ResolveIPAddr("ip", laddr)
	c.PeerInfo.LocalAddress = ipaddr.IP
	if c.PeerConf.Transport.Config.LocalAddress != netip.IPv4Unspecified().String() && c.PeerConf.Transport.Config.LocalAddress != netip.IPv6Unspecified().String() {
		// Exclude zone info for v6 address like "fe80::1ff:fe23:4567:890a%eth2".
		p := laddr
		if i := strings.IndexByte(p, '%'); i != -1 {
			p = p[:i]
		}
		ipaddr := net.ParseIP(p)

		c.PeerInfo.LocalAddress = ipaddr
		c.PeerConf.Transport.State.LocalAddress = ipaddr.String()
	}
}

func (fsm *fsm) peerUp(_ *FSMStateTransition) {
	conn := fsm.conn.Load()

	fsm.tracking.lock.Lock()
	delete(fsm.tracking.conns, conn.RemoteAddr())
	fsm.tracking.lock.Unlock()
	fsm.ceaseTrackedConns()

	fsm.common.updateFromBestConn(conn)

	fsm.common.Lock.RLock()
	neighborAddress := fsm.common.PeerConf.State.NeighborAddress
	_, capFourOctetASNumber := fsm.common.CapMap[bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER]
	_, capAddPAth := fsm.common.CapMap[bgp.BGP_CAP_ADD_PATH]
	capabilities := fsm.common.PeerConf.Capabilities()
	gracefulRestartTime := time.Second * time.Duration(fsm.common.PeerConf.GracefulRestart.State.PeerRestartTime)
	fsm.common.Lock.RUnlock()

	fsm.logger.Info("Peer Up",
		log.Fields{
			"Topic": "Peer",
			"Key":   neighborAddress,
		})

	fsm.stats.establishedCounter++
	fsm.stats.upSince = time.Now()

	// reset the state set by the previous session
	twoByteAsTrans := false
	if !capFourOctetASNumber {
		twoByteAsTrans = true
	} else {
		twoByteAsTrans = true
		for _, c := range capabilities {
			if _, ok := c.(*bgp.CapFourOctetASNumber); ok {
				twoByteAsTrans = false
				break
			}
		}
	}
	fsm.twoByteAsTrans.Store(twoByteAsTrans)

	var marshallingOptions *bgp.MarshallingOption
	if capAddPAth {
		fsm.common.Lock.RLock()
		rfMap := maps.Clone(fsm.common.RFMap)
		fsm.common.Lock.RUnlock()
		marshallingOptions = &bgp.MarshallingOption{
			AddPath: rfMap,
		}
	}
	fsm.marshallingOptions.Store(marshallingOptions)

	fsm.timers.holdTime = conn.holdTime
	fsm.timers.keepAliveInterval = conn.keepAliveInterval
	fsm.timers.gracefulRestartTime = gracefulRestartTime
}

func (fsm *fsm) peerDown(transition *FSMStateTransition) {
	fsm.common.Lock.RLock()
	neighborAddress := fsm.common.PeerConf.State.NeighborAddress
	fsm.common.Lock.RUnlock()

	fsm.logger.Info("Peer Down",
		log.Fields{
			"Topic": "Peer",
			"Key":   neighborAddress,
		})

	t := time.Now()

	fsm.common.Lock.Lock()
	if t.Sub(time.Unix(fsm.common.PeerConf.Timers.State.Uptime, 0)) < FlopThreshold {
		fsm.common.PeerConf.State.Flops++
	}
	if transition.Reason == FSMGracefulRestart {
		fsm.common.PeerConf.GracefulRestart.State.PeerRestarting = true
	}

	// Always clear EndOfRibReceived state on PeerDown
	for i := range fsm.common.PeerConf.AfiSafis {
		fsm.common.PeerConf.AfiSafis[i].MpGracefulRestart.State.EndOfRibReceived = false
	}

	if fsm.common.PeerConf.Config.PeerAs == 0 {
		fsm.common.PeerConf.State.PeerAs = 0
		fsm.common.PeerInfo.AS = 0
	}

	fsm.common.Lock.Unlock()
}

func (fsm *fsm) stateChange(transition *FSMStateTransition) {
	fsm.common.Lock.RLock()
	neighborAddress := fsm.common.PeerConf.State.NeighborAddress
	fsm.common.Lock.RUnlock()

	newState := transition.NewState
	oldState := transition.OldState

	fsm.logger.Debug("State changed",
		log.Fields{
			"Topic":     "Peer",
			"Key":       neighborAddress,
			"Old State": oldState.String(),
			"New State": newState.String(),
			"Reason":    transition.Reason.String(),
		})

	fsm.state.Store(newState)

	fsm.common.Lock.Lock()
	fsm.common.PeerConf.State.SessionState = oc.IntToSessionStateMap[int(newState)]
	fsm.common.Lock.Unlock()

	// peer up
	if newState == bgp.BGP_FSM_ESTABLISHED {
		fsm.peerUp(transition)
		// peer down
	} else if oldState == bgp.BGP_FSM_ESTABLISHED {
		fsm.peerDown(transition)
	}
}

func (fsm *fsm) changeAdminState(s AdminState) {
	fsm.common.Lock.RLock()
	neighborAddress := fsm.common.PeerConf.State.NeighborAddress
	fsm.common.Lock.RUnlock()

	adminState := fsm.adminState.Load()
	state := fsm.state.Load()

	if adminState == s {
		return
	}
	fsm.logger.Debug("Admin state changed",
		log.Fields{
			"Topic":      "Peer",
			"Key":        neighborAddress,
			"State":      state.String(),
			"AdminState": s.String(),
		})

	fsm.adminState.Store(s)

	fsm.common.Lock.Lock()
	fsm.common.PeerConf.State.AdminDown = s != AdminStateUp
	fsm.common.PeerConf.State.AdminState = oc.IntToAdminStateMap[int(s)]
	fsm.common.Lock.Unlock()
}

func (c *FSMCommon) afiSafiDisable(rf bgp.Family) string {
	c.Lock.Lock()
	defer c.Lock.Unlock()

	n := bgp.AddressFamilyNameMap[rf]

	for i, a := range c.PeerConf.AfiSafis {
		if string(a.Config.AfiSafiName) == n {
			c.PeerConf.AfiSafis[i].State.Enabled = false
			break
		}
	}
	newList := make([]bgp.ParameterCapabilityInterface, 0)
	for _, c := range c.CapMap[bgp.BGP_CAP_MULTIPROTOCOL] {
		if c.(*bgp.CapMultiProtocol).CapValue == rf {
			continue
		}
		newList = append(newList, c)
	}
	c.CapMap[bgp.BGP_CAP_MULTIPROTOCOL] = newList
	return n
}
