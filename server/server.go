// Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/armon/go-radix"
	"github.com/eapache/channels"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/osrg/gobgp/packet/bmp"
	"github.com/osrg/gobgp/table"
	"github.com/satori/go.uuid"
)

var policyMutex sync.RWMutex

type SenderMsg struct {
	ch  chan *FsmOutgoingMsg
	msg *FsmOutgoingMsg
}

type TCPListener struct {
	l  *net.TCPListener
	ch chan struct{}
}

func (l *TCPListener) Close() error {
	if err := l.l.Close(); err != nil {
		return err
	}
	t := time.NewTicker(time.Second)
	select {
	case <-l.ch:
	case <-t.C:
		return fmt.Errorf("close timeout")
	}
	return nil
}

// avoid mapped IPv6 address
func NewTCPListener(address string, port uint32, ch chan *net.TCPConn) (*TCPListener, error) {
	proto := "tcp4"
	if ip := net.ParseIP(address); ip == nil {
		return nil, fmt.Errorf("can't listen on %s", address)
	} else if ip.To4() == nil {
		proto = "tcp6"
	}
	addr, err := net.ResolveTCPAddr(proto, net.JoinHostPort(address, strconv.Itoa(int(port))))
	if err != nil {
		return nil, err
	}

	l, err := net.ListenTCP(proto, addr)
	if err != nil {
		return nil, err
	}
	closeCh := make(chan struct{})
	go func() error {
		for {
			conn, err := l.AcceptTCP()
			if err != nil {
				close(closeCh)
				log.Warn(err)
				return err
			}
			ch <- conn
		}
	}()
	return &TCPListener{
		l:  l,
		ch: closeCh,
	}, nil
}

type BgpServer struct {
	bgpConfig     config.Bgp
	fsmincomingCh *channels.InfiniteChannel
	fsmStateCh    chan *FsmMsg
	acceptCh      chan *net.TCPConn
	collector     *Collector

	GrpcReqCh   chan *GrpcRequest
	policy      *table.RoutingPolicy
	listeners   []*TCPListener
	neighborMap map[string]*Peer
	globalRib   *table.TableManager
	roaManager  *roaManager
	shutdown    bool
	watchers    *watcherManager
}

func NewBgpServer() *BgpServer {
	roaManager, _ := NewROAManager(0)
	return &BgpServer{
		GrpcReqCh:   make(chan *GrpcRequest, 1),
		neighborMap: make(map[string]*Peer),
		policy:      table.NewRoutingPolicy(),
		roaManager:  roaManager,
		watchers:    newWatcherManager(),
	}
}

func (server *BgpServer) Listeners(addr string) []*net.TCPListener {
	list := make([]*net.TCPListener, 0, len(server.listeners))
	rhs := net.ParseIP(addr).To4() != nil
	for _, l := range server.listeners {
		host, _, _ := net.SplitHostPort(l.l.Addr().String())
		lhs := net.ParseIP(host).To4() != nil
		if lhs == rhs {
			list = append(list, l.l)
		}
	}
	return list
}

func (server *BgpServer) Serve() {
	w, _ := newGrpcWatcher()
	server.watchers.addWatcher(WATCHER_GRPC_MONITOR, w)

	senderCh := make(chan *SenderMsg, 1<<16)
	go func(ch chan *SenderMsg) {
		w := func(c chan *FsmOutgoingMsg, msg *FsmOutgoingMsg) {
			// nasty but the peer could already become non established state before here.
			defer func() { recover() }()
			c <- msg
		}

		for m := range ch {
			// TODO: must be more clever. Slow peer makes other peers slow too.
			w(m.ch, m.msg)
		}

	}(senderCh)

	server.listeners = make([]*TCPListener, 0, 2)
	server.fsmincomingCh = channels.NewInfiniteChannel()
	server.fsmStateCh = make(chan *FsmMsg, 4096)
	var senderMsgs []*SenderMsg

	handleFsmMsg := func(e *FsmMsg) {
		peer, found := server.neighborMap[e.MsgSrc]
		if !found {
			log.Warn("Can't find the neighbor ", e.MsgSrc)
			return
		}
		if e.Version != peer.fsm.version {
			log.Debug("FSM Version inconsistent")
			return
		}
		m := server.handleFSMMessage(peer, e)
		if len(m) > 0 {
			senderMsgs = append(senderMsgs, m...)
		}
	}

	for {
		var firstMsg *SenderMsg
		var sCh chan *SenderMsg
		if len(senderMsgs) > 0 {
			sCh = senderCh
			firstMsg = senderMsgs[0]
		}

		passConn := func(conn *net.TCPConn) {
			host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			ipaddr, _ := net.ResolveIPAddr("ip", host)
			remoteAddr := ipaddr.IP.String()
			peer, found := server.neighborMap[remoteAddr]
			if found {
				if peer.fsm.adminState != ADMIN_STATE_UP {
					log.Debug("new connection for non admin-state-up peer ", remoteAddr, peer.fsm.adminState)
					conn.Close()
					return
				}
				localAddrValid := func(laddr string) bool {
					if laddr == "0.0.0.0" || laddr == "::" {
						return true
					}
					l := conn.LocalAddr()
					if l == nil {
						// already closed
						return false
					}

					host, _, _ := net.SplitHostPort(l.String())
					if host != laddr {
						log.WithFields(log.Fields{
							"Topic":           "Peer",
							"Key":             remoteAddr,
							"Configured addr": laddr,
							"Addr":            host,
						}).Info("Mismatched local address")
						return false
					}
					return true
				}(peer.fsm.pConf.Transport.Config.LocalAddress)
				if localAddrValid == false {
					conn.Close()
					return
				}
				log.Debug("accepted a new passive connection from ", remoteAddr)
				peer.PassConn(conn)
			} else {
				log.Info("can't find configuration for a new passive connection from ", remoteAddr)
				conn.Close()
			}
		}

		select {
		case grpcReq := <-server.GrpcReqCh:
			m := server.handleGrpc(grpcReq)
			if len(m) > 0 {
				senderMsgs = append(senderMsgs, m...)
			}
		case conn := <-server.acceptCh:
			passConn(conn)
		default:
		}

		for {
			select {
			case e := <-server.fsmStateCh:
				handleFsmMsg(e)
			default:
				goto CONT
			}
		}
	CONT:

		select {
		case rmsg := <-server.roaManager.ReceiveROA():
			server.roaManager.HandleROAEvent(rmsg)
		case conn := <-server.acceptCh:
			passConn(conn)
		case e, ok := <-server.fsmincomingCh.Out():
			if !ok {
				continue
			}
			handleFsmMsg(e.(*FsmMsg))
		case e := <-server.fsmStateCh:
			handleFsmMsg(e)
		case sCh <- firstMsg:
			senderMsgs = senderMsgs[1:]
		case grpcReq := <-server.GrpcReqCh:
			m := server.handleGrpc(grpcReq)
			if len(m) > 0 {
				senderMsgs = append(senderMsgs, m...)
			}
		}
	}
}

func newSenderMsg(peer *Peer, paths []*table.Path, notification *bgp.BGPMessage, stayIdle bool) *SenderMsg {
	return &SenderMsg{
		ch: peer.outgoing,
		msg: &FsmOutgoingMsg{
			Paths:        paths,
			Notification: notification,
			StayIdle:     stayIdle,
		},
	}
}

func isASLoop(peer *Peer, path *table.Path) bool {
	for _, as := range path.GetAsList() {
		if as == peer.fsm.pConf.Config.PeerAs {
			return true
		}
	}
	return false
}

func filterpath(peer *Peer, path *table.Path) *table.Path {
	if path == nil {
		return nil
	}
	if _, ok := peer.fsm.rfMap[path.GetRouteFamily()]; !ok {
		return nil
	}

	//iBGP handling
	if peer.isIBGPPeer() {
		ignore := false
		//RFC4684 Constrained Route Distribution
		if peer.fsm.rfMap[bgp.RF_RTC_UC] && path.GetRouteFamily() != bgp.RF_RTC_UC {
			ignore = true
			for _, ext := range path.GetExtCommunities() {
				for _, path := range peer.adjRibIn.PathList([]bgp.RouteFamily{bgp.RF_RTC_UC}, true) {
					rt := path.GetNlri().(*bgp.RouteTargetMembershipNLRI).RouteTarget
					if ext.String() == rt.String() {
						ignore = false
						break
					}
				}
				if !ignore {
					break
				}
			}
		}

		if !path.IsLocal() {
			ignore = true
			info := path.GetSource()
			//if the path comes from eBGP peer
			if info.AS != peer.fsm.pConf.Config.PeerAs {
				ignore = false
			}
			// RFC4456 8. Avoiding Routing Information Loops
			// A router that recognizes the ORIGINATOR_ID attribute SHOULD
			// ignore a route received with its BGP Identifier as the ORIGINATOR_ID.
			if id := path.GetOriginatorID(); peer.fsm.gConf.Config.RouterId == id.String() {
				log.WithFields(log.Fields{
					"Topic":        "Peer",
					"Key":          peer.ID(),
					"OriginatorID": id,
					"Data":         path,
				}).Debug("Originator ID is mine, ignore")
				return nil
			}
			if info.RouteReflectorClient {
				ignore = false
			}
			if peer.isRouteReflectorClient() {
				// RFC4456 8. Avoiding Routing Information Loops
				// If the local CLUSTER_ID is found in the CLUSTER_LIST,
				// the advertisement received SHOULD be ignored.
				for _, clusterId := range path.GetClusterList() {
					if clusterId.Equal(peer.fsm.peerInfo.RouteReflectorClusterID) {
						log.WithFields(log.Fields{
							"Topic":     "Peer",
							"Key":       peer.ID(),
							"ClusterID": clusterId,
							"Data":      path,
						}).Debug("cluster list path attribute has local cluster id, ignore")
						return nil
					}
				}
				ignore = false
			}
		}

		if ignore {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.ID(),
				"Data":  path,
			}).Debug("From same AS, ignore.")
			return nil
		}
	}

	if peer.ID() == path.GetSource().Address.String() {
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   peer.ID(),
			"Data":  path,
		}).Debug("From me, ignore.")
		return nil
	}

	if !peer.isRouteServerClient() && isASLoop(peer, path) {
		return nil
	}
	return path
}

func (server *BgpServer) dropPeerAllRoutes(peer *Peer, families []bgp.RouteFamily) []*SenderMsg {
	ids := make([]string, 0, len(server.neighborMap))
	msgs := make([]*SenderMsg, 0, len(server.neighborMap))
	if peer.isRouteServerClient() {
		for _, targetPeer := range server.neighborMap {
			if !targetPeer.isRouteServerClient() || targetPeer == peer || targetPeer.fsm.state != bgp.BGP_FSM_ESTABLISHED {
				continue
			}
			ids = append(ids, targetPeer.TableID())
		}
	} else {
		ids = append(ids, table.GLOBAL_RIB_NAME)
	}
	for _, rf := range families {
		best, _, multipath := server.globalRib.DeletePathsByPeer(ids, peer.fsm.peerInfo, rf)

		if !peer.isRouteServerClient() {
			server.watchers.notify(WATCHER_EVENT_BESTPATH_CHANGE, &watcherEventBestPathMsg{pathList: best[table.GLOBAL_RIB_NAME], multiPathList: multipath})
		}

		for _, targetPeer := range server.neighborMap {
			if peer.isRouteServerClient() != targetPeer.isRouteServerClient() || targetPeer == peer {
				continue
			}
			if paths := targetPeer.processOutgoingPaths(best[targetPeer.TableID()], nil); len(paths) > 0 {
				msgs = append(msgs, newSenderMsg(targetPeer, paths, nil, false))
			}
		}
	}
	return msgs
}

func (server *BgpServer) broadcastPeerState(peer *Peer, oldState bgp.FSMState) {
	newState := peer.fsm.state
	if oldState == bgp.BGP_FSM_ESTABLISHED || newState == bgp.BGP_FSM_ESTABLISHED {
		if server.watchers.watching(WATCHER_EVENT_STATE_CHANGE) {
			_, rport := peer.fsm.RemoteHostPort()
			laddr, lport := peer.fsm.LocalHostPort()
			sentOpen := buildopen(peer.fsm.gConf, peer.fsm.pConf)
			recvOpen := peer.fsm.recvOpen
			ev := &watcherEventStateChangedMsg{
				peerAS:       peer.fsm.peerInfo.AS,
				localAS:      peer.fsm.peerInfo.LocalAS,
				peerAddress:  peer.fsm.peerInfo.Address,
				localAddress: net.ParseIP(laddr),
				peerPort:     rport,
				localPort:    lport,
				peerID:       peer.fsm.peerInfo.ID,
				sentOpen:     sentOpen,
				recvOpen:     recvOpen,
				state:        newState,
				adminState:   peer.fsm.adminState,
				timestamp:    time.Now(),
			}
			server.watchers.notify(WATCHER_EVENT_STATE_CHANGE, ev)
		}
	}
}

func (server *BgpServer) RSimportPaths(peer *Peer, pathList []*table.Path) []*table.Path {
	moded := make([]*table.Path, 0, len(pathList)/2)
	for _, before := range pathList {
		if isASLoop(peer, before) {
			before.Filter(peer.ID(), table.POLICY_DIRECTION_IMPORT)
			continue
		}
		after := server.policy.ApplyPolicy(peer.TableID(), table.POLICY_DIRECTION_IMPORT, before, nil)
		if after == nil {
			before.Filter(peer.ID(), table.POLICY_DIRECTION_IMPORT)
		} else if after != before {
			before.Filter(peer.ID(), table.POLICY_DIRECTION_IMPORT)
			for _, n := range server.neighborMap {
				if n == peer {
					continue
				}
				after.Filter(n.ID(), table.POLICY_DIRECTION_IMPORT)
			}
			moded = append(moded, after)
		}
	}
	return moded
}

func (server *BgpServer) propagateUpdate(peer *Peer, pathList []*table.Path) ([]*SenderMsg, []*table.Path) {
	rib := server.globalRib
	var alteredPathList, withdrawn []*table.Path
	var best map[string][]*table.Path
	msgs := make([]*SenderMsg, 0, len(server.neighborMap))

	if peer != nil && peer.isRouteServerClient() {
		for _, path := range pathList {
			path.Filter(peer.ID(), table.POLICY_DIRECTION_IMPORT)
			path.Filter(table.GLOBAL_RIB_NAME, table.POLICY_DIRECTION_IMPORT)
		}
		moded := make([]*table.Path, 0)
		for _, targetPeer := range server.neighborMap {
			if !targetPeer.isRouteServerClient() || peer == targetPeer {
				continue
			}
			moded = append(moded, server.RSimportPaths(targetPeer, pathList)...)
		}
		isTarget := func(p *Peer) bool {
			return p.isRouteServerClient() && p.fsm.state == bgp.BGP_FSM_ESTABLISHED && !p.fsm.pConf.GracefulRestart.State.LocalRestarting
		}

		ids := make([]string, 0, len(server.neighborMap))
		for _, targetPeer := range server.neighborMap {
			if isTarget(targetPeer) {
				ids = append(ids, targetPeer.TableID())
			}
		}
		best, withdrawn, _ = rib.ProcessPaths(ids, append(pathList, moded...))
	} else {
		for idx, path := range pathList {
			path = server.policy.ApplyPolicy(table.GLOBAL_RIB_NAME, table.POLICY_DIRECTION_IMPORT, path, nil)
			pathList[idx] = path
			// RFC4684 Constrained Route Distribution 6. Operation
			//
			// When a BGP speaker receives a BGP UPDATE that advertises or withdraws
			// a given Route Target membership NLRI, it should examine the RIB-OUTs
			// of VPN NLRIs and re-evaluate the advertisement status of routes that
			// match the Route Target in question.
			//
			// A BGP speaker should generate the minimum set of BGP VPN route
			// updates (advertisements and/or withdrawls) necessary to transition
			// between the previous and current state of the route distribution
			// graph that is derived from Route Target membership information.
			if peer != nil && path != nil && path.GetRouteFamily() == bgp.RF_RTC_UC {
				rt := path.GetNlri().(*bgp.RouteTargetMembershipNLRI).RouteTarget
				fs := make([]bgp.RouteFamily, 0, len(peer.configuredRFlist()))
				for _, f := range peer.configuredRFlist() {
					if f != bgp.RF_RTC_UC {
						fs = append(fs, f)
					}
				}
				var candidates []*table.Path
				if path.IsWithdraw {
					candidates = peer.adjRibOut.PathList(fs, false)
				} else {
					candidates = rib.GetBestPathList(peer.TableID(), fs)
				}
				paths := make([]*table.Path, 0, len(candidates))
				for _, p := range candidates {
					for _, ext := range p.GetExtCommunities() {
						if ext.String() == rt.String() {
							if path.IsWithdraw {
								p = p.Clone(true)
							}
							paths = append(paths, p)
							break
						}
					}
				}
				if path.IsWithdraw {
					paths = peer.processOutgoingPaths(nil, paths)
				} else {
					paths = peer.processOutgoingPaths(paths, nil)
				}
				msgs = append(msgs, newSenderMsg(peer, paths, nil, false))
			}
		}
		alteredPathList = pathList
		var multi [][]*table.Path
		best, withdrawn, multi = rib.ProcessPaths([]string{table.GLOBAL_RIB_NAME}, pathList)
		if len(best[table.GLOBAL_RIB_NAME]) == 0 {
			return nil, alteredPathList
		}
		server.watchers.notify(WATCHER_EVENT_BESTPATH_CHANGE, &watcherEventBestPathMsg{pathList: best[table.GLOBAL_RIB_NAME], multiPathList: multi})
	}

	for _, targetPeer := range server.neighborMap {
		if (peer == nil && targetPeer.isRouteServerClient()) || (peer != nil && peer.isRouteServerClient() != targetPeer.isRouteServerClient()) {
			continue
		}
		if paths := targetPeer.processOutgoingPaths(best[targetPeer.TableID()], withdrawn); len(paths) > 0 {
			msgs = append(msgs, newSenderMsg(targetPeer, paths, nil, false))
		}
	}
	return msgs, alteredPathList
}

func (server *BgpServer) handleFSMMessage(peer *Peer, e *FsmMsg) []*SenderMsg {
	var msgs []*SenderMsg
	switch e.MsgType {
	case FSM_MSG_STATE_CHANGE:
		nextState := e.MsgData.(bgp.FSMState)
		oldState := bgp.FSMState(peer.fsm.pConf.State.SessionState.ToInt())
		peer.fsm.pConf.State.SessionState = config.IntToSessionStateMap[int(nextState)]
		peer.fsm.StateChange(nextState)

		if oldState == bgp.BGP_FSM_ESTABLISHED {
			t := time.Now()
			if t.Sub(time.Unix(peer.fsm.pConf.Timers.State.Uptime, 0)) < FLOP_THRESHOLD {
				peer.fsm.pConf.State.Flops++
			}
			var drop []bgp.RouteFamily
			if peer.fsm.reason == FSM_GRACEFUL_RESTART {
				peer.fsm.pConf.GracefulRestart.State.PeerRestarting = true
				var p []bgp.RouteFamily
				p, drop = peer.forwardingPreservedFamilies()
				peer.StaleAll(p)
			} else {
				drop = peer.configuredRFlist()
			}
			peer.prefixLimitWarned = make(map[bgp.RouteFamily]bool)
			peer.DropAll(drop)
			msgs = server.dropPeerAllRoutes(peer, drop)
		} else if peer.fsm.pConf.GracefulRestart.State.PeerRestarting && nextState == bgp.BGP_FSM_IDLE {
			// RFC 4724 4.2
			// If the session does not get re-established within the "Restart Time"
			// that the peer advertised previously, the Receiving Speaker MUST
			// delete all the stale routes from the peer that it is retaining.
			peer.fsm.pConf.GracefulRestart.State.PeerRestarting = false
			peer.DropAll(peer.configuredRFlist())
			msgs = server.dropPeerAllRoutes(peer, peer.configuredRFlist())
		}

		close(peer.outgoing)
		peer.outgoing = make(chan *FsmOutgoingMsg, 128)
		if nextState == bgp.BGP_FSM_ESTABLISHED {
			// update for export policy
			laddr, _ := peer.fsm.LocalHostPort()
			peer.fsm.pConf.Transport.State.LocalAddress = laddr
			peer.fsm.peerInfo.LocalAddress = net.ParseIP(laddr)
			deferralExpiredFunc := func(family bgp.RouteFamily) func() {
				return func() {
					req := NewGrpcRequest(REQ_DEFERRAL_TIMER_EXPIRED, peer.ID(), family, nil)
					server.GrpcReqCh <- req
					<-req.ResponseCh
				}
			}
			if !peer.fsm.pConf.GracefulRestart.State.LocalRestarting {
				// When graceful-restart cap (which means intention
				// of sending EOR) and route-target address family are negotiated,
				// send route-target NLRIs first, and wait to send others
				// till receiving EOR of route-target address family.
				// This prevents sending uninterested routes to peers.
				//
				// However, when the peer is graceful restarting, give up
				// waiting sending non-route-target NLRIs since the peer won't send
				// any routes (and EORs) before we send ours (or deferral-timer expires).
				var pathList []*table.Path
				if c := config.GetAfiSafi(peer.fsm.pConf, bgp.RF_RTC_UC); !peer.fsm.pConf.GracefulRestart.State.PeerRestarting && peer.fsm.rfMap[bgp.RF_RTC_UC] && c.RouteTargetMembership.Config.DeferralTime > 0 {
					pathList, _ = peer.getBestFromLocal([]bgp.RouteFamily{bgp.RF_RTC_UC})
					t := c.RouteTargetMembership.Config.DeferralTime
					for _, f := range peer.configuredRFlist() {
						if f != bgp.RF_RTC_UC {
							time.AfterFunc(time.Second*time.Duration(t), deferralExpiredFunc(f))
						}
					}
				} else {
					pathList, _ = peer.getBestFromLocal(peer.configuredRFlist())
				}

				if len(pathList) > 0 {
					peer.adjRibOut.Update(pathList)
					msgs = []*SenderMsg{newSenderMsg(peer, pathList, nil, false)}
				}
			} else {
				// RFC 4724 4.1
				// Once the session between the Restarting Speaker and the Receiving
				// Speaker is re-established, the Restarting Speaker will receive and
				// process BGP messages from its peers.  However, it MUST defer route
				// selection for an address family until it either (a) ...snip...
				// or (b) the Selection_Deferral_Timer referred to below has expired.
				deferral := peer.fsm.pConf.GracefulRestart.Config.DeferralTime
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   peer.ID(),
				}).Debugf("now syncing, suppress sending updates. start deferral timer(%d)", deferral)
				time.AfterFunc(time.Second*time.Duration(deferral), deferralExpiredFunc(bgp.RouteFamily(0)))
			}
		} else {
			if server.shutdown && nextState == bgp.BGP_FSM_IDLE {
				die := true
				for _, p := range server.neighborMap {
					if p.fsm.state != bgp.BGP_FSM_IDLE {
						die = false
						break
					}
				}
				if die {
					os.Exit(0)
				}
			}
			peer.fsm.pConf.Timers.State.Downtime = time.Now().Unix()
		}
		// clear counter
		if peer.fsm.adminState == ADMIN_STATE_DOWN {
			peer.fsm.pConf.State = config.NeighborState{}
			peer.fsm.pConf.Timers.State = config.TimersState{}
		}
		peer.startFSMHandler(server.fsmincomingCh, server.fsmStateCh)
		server.broadcastPeerState(peer, oldState)
	case FSM_MSG_ROUTE_REFRESH:
		if paths := peer.handleRouteRefresh(e); len(paths) > 0 {
			return []*SenderMsg{newSenderMsg(peer, paths, nil, false)}
		}
	case FSM_MSG_BGP_MESSAGE:
		switch m := e.MsgData.(type) {
		case *bgp.MessageError:
			return []*SenderMsg{newSenderMsg(peer, nil, bgp.NewBGPNotificationMessage(m.TypeCode, m.SubTypeCode, m.Data), false)}
		case *bgp.BGPMessage:
			server.roaManager.validate(e.PathList)
			pathList, eor, notification := peer.handleUpdate(e)
			if notification != nil {
				return []*SenderMsg{newSenderMsg(peer, nil, notification, true)}
			}
			if m.Header.Type == bgp.BGP_MSG_UPDATE && server.watchers.watching(WATCHER_EVENT_UPDATE_MSG) {
				_, y := peer.fsm.capMap[bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER]
				l, _ := peer.fsm.LocalHostPort()
				ev := &watcherEventUpdateMsg{
					message:      m,
					peerAS:       peer.fsm.peerInfo.AS,
					localAS:      peer.fsm.peerInfo.LocalAS,
					peerAddress:  peer.fsm.peerInfo.Address,
					localAddress: net.ParseIP(l),
					peerID:       peer.fsm.peerInfo.ID,
					fourBytesAs:  y,
					timestamp:    e.timestamp,
					payload:      e.payload,
					postPolicy:   false,
					pathList:     pathList,
				}
				server.watchers.notify(WATCHER_EVENT_UPDATE_MSG, ev)
			}

			if len(pathList) > 0 {
				var altered []*table.Path
				msgs, altered = server.propagateUpdate(peer, pathList)
				if server.watchers.watching(WATCHER_EVENT_POST_POLICY_UPDATE_MSG) {
					_, y := peer.fsm.capMap[bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER]
					l, _ := peer.fsm.LocalHostPort()
					ev := &watcherEventUpdateMsg{
						peerAS:       peer.fsm.peerInfo.AS,
						localAS:      peer.fsm.peerInfo.LocalAS,
						peerAddress:  peer.fsm.peerInfo.Address,
						localAddress: net.ParseIP(l),
						peerID:       peer.fsm.peerInfo.ID,
						fourBytesAs:  y,
						timestamp:    e.timestamp,
						postPolicy:   true,
						pathList:     altered,
					}
					for _, u := range table.CreateUpdateMsgFromPaths(altered) {
						payload, _ := u.Serialize()
						ev.payload = payload
						server.watchers.notify(WATCHER_EVENT_POST_POLICY_UPDATE_MSG, ev)
					}
				}
			}

			if len(eor) > 0 {
				rtc := false
				for _, f := range eor {
					if f == bgp.RF_RTC_UC {
						rtc = true
					}
					for i, a := range peer.fsm.pConf.AfiSafis {
						if g, _ := bgp.GetRouteFamily(string(a.Config.AfiSafiName)); f == g {
							peer.fsm.pConf.AfiSafis[i].MpGracefulRestart.State.EndOfRibReceived = true
						}
					}
				}

				// RFC 4724 4.1
				// Once the session between the Restarting Speaker and the Receiving
				// Speaker is re-established, ...snip... it MUST defer route
				// selection for an address family until it either (a) receives the
				// End-of-RIB marker from all its peers (excluding the ones with the
				// "Restart State" bit set in the received capability and excluding the
				// ones that do not advertise the graceful restart capability) or ...snip...
				if peer.fsm.pConf.GracefulRestart.State.LocalRestarting {
					allEnd := func() bool {
						for _, p := range server.neighborMap {
							if !p.recvedAllEOR() {
								return false
							}
						}
						return true
					}()
					if allEnd {
						for _, p := range server.neighborMap {
							p.fsm.pConf.GracefulRestart.State.LocalRestarting = false
							if !p.isGracefulRestartEnabled() {
								continue
							}
							paths, _ := p.getBestFromLocal(p.configuredRFlist())
							if len(paths) > 0 {
								p.adjRibOut.Update(paths)
								msgs = append(msgs, newSenderMsg(p, paths, nil, false))
							}
						}
						log.WithFields(log.Fields{
							"Topic": "Server",
						}).Info("sync finished")

					}

					// we don't delay non-route-target NLRIs when local-restarting
					rtc = false
				}
				if peer.fsm.pConf.GracefulRestart.State.PeerRestarting {
					if peer.recvedAllEOR() {
						peer.fsm.pConf.GracefulRestart.State.PeerRestarting = false
						pathList := peer.adjRibIn.DropStale(peer.configuredRFlist())
						log.WithFields(log.Fields{
							"Topic": "Peer",
							"Key":   peer.fsm.pConf.Config.NeighborAddress,
						}).Debugf("withdraw %d stale routes", len(pathList))
						m, _ := server.propagateUpdate(peer, pathList)
						msgs = append(msgs, m...)
					}

					// we don't delay non-route-target NLRIs when peer is restarting
					rtc = false
				}

				// received EOR of route-target address family
				// outbound filter is now ready, let's flash non-route-target NLRIs
				if c := config.GetAfiSafi(peer.fsm.pConf, bgp.RF_RTC_UC); rtc && c != nil && c.RouteTargetMembership.Config.DeferralTime > 0 {
					log.WithFields(log.Fields{
						"Topic": "Peer",
						"Key":   peer.ID(),
					}).Debug("received route-target eor. flash non-route-target NLRIs")
					families := make([]bgp.RouteFamily, 0, len(peer.configuredRFlist()))
					for _, f := range peer.configuredRFlist() {
						if f != bgp.RF_RTC_UC {
							families = append(families, f)
						}
					}
					if paths, _ := peer.getBestFromLocal(families); len(paths) > 0 {
						peer.adjRibOut.Update(paths)
						msgs = append(msgs, newSenderMsg(peer, paths, nil, false))
					}
				}
			}
		default:
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.fsm.pConf.Config.NeighborAddress,
				"Data":  e.MsgData,
			}).Panic("unknown msg type")
		}
	}
	return msgs
}

func (server *BgpServer) SetGlobalType(g config.Global) error {
	ch := make(chan *GrpcResponse)
	server.GrpcReqCh <- &GrpcRequest{
		RequestType: REQ_START_SERVER,
		Data:        &g,
		ResponseCh:  ch,
	}
	if err := (<-ch).Err(); err != nil {
		return err
	}
	return nil
}

func (server *BgpServer) SetCollector(c config.Collector) error {
	if len(c.Config.Url) == 0 {
		return nil
	}
	ch := make(chan *GrpcResponse)
	server.GrpcReqCh <- &GrpcRequest{
		RequestType: REQ_INITIALIZE_COLLECTOR,
		Data:        &c.Config,
		ResponseCh:  ch,
	}
	if err := (<-ch).Err(); err != nil {
		return err
	}
	return nil
}

func (server *BgpServer) SetZebraConfig(z config.Zebra) error {
	if !z.Config.Enabled {
		return nil
	}
	ch := make(chan *GrpcResponse)
	server.GrpcReqCh <- &GrpcRequest{
		RequestType: REQ_INITIALIZE_ZEBRA,
		Data:        &z.Config,
		ResponseCh:  ch,
	}
	if err := (<-ch).Err(); err != nil {
		return err
	}
	return nil
}

func (server *BgpServer) SetRpkiConfig(c []config.RpkiServer) error {
	ch := make(chan *GrpcResponse)
	server.GrpcReqCh <- &GrpcRequest{
		RequestType: REQ_INITIALIZE_RPKI,
		Data:        &server.bgpConfig.Global,
		ResponseCh:  ch,
	}
	if err := (<-ch).Err(); err != nil {
		return err
	}

	for _, s := range c {
		ch := make(chan *GrpcResponse)
		server.GrpcReqCh <- &GrpcRequest{
			RequestType: REQ_ADD_RPKI,
			Data: &api.AddRpkiRequest{
				Address:  s.Config.Address,
				Port:     s.Config.Port,
				Lifetime: s.Config.RecordLifetime,
			},
			ResponseCh: ch,
		}
		if err := (<-ch).Err(); err != nil {
			return err
		}
	}
	return nil
}

func (server *BgpServer) SetBmpConfig(c []config.BmpServer) error {
	for _, s := range c {
		ch := make(chan *GrpcResponse)
		server.GrpcReqCh <- &GrpcRequest{
			RequestType: REQ_ADD_BMP,
			Data:        &s.Config,
			ResponseCh:  ch,
		}
		if err := (<-ch).Err(); err != nil {
			return err
		}
	}
	return nil
}

func (server *BgpServer) SetMrtConfig(c []config.Mrt) error {
	for _, s := range c {
		if s.FileName != "" {
			ch := make(chan *GrpcResponse)
			server.GrpcReqCh <- &GrpcRequest{
				RequestType: REQ_ENABLE_MRT,
				Data: &api.EnableMrtRequest{
					DumpType: int32(s.DumpType.ToInt()),
					Filename: s.FileName,
					Interval: s.Interval,
				},
				ResponseCh: ch,
			}
			if err := (<-ch).Err(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (server *BgpServer) PeerAdd(peer config.Neighbor) error {
	ch := make(chan *GrpcResponse)
	server.GrpcReqCh <- &GrpcRequest{
		RequestType: REQ_ADD_NEIGHBOR,
		Data:        &peer,
		ResponseCh:  ch,
	}
	return (<-ch).Err()
}

func (server *BgpServer) PeerDelete(peer config.Neighbor) error {
	ch := make(chan *GrpcResponse)
	server.GrpcReqCh <- &GrpcRequest{
		RequestType: REQ_DEL_NEIGHBOR,
		Data:        &peer,
		ResponseCh:  ch,
	}
	return (<-ch).Err()
}

func (server *BgpServer) PeerUpdate(peer config.Neighbor) (bool, error) {
	ch := make(chan *GrpcResponse)
	server.GrpcReqCh <- &GrpcRequest{
		RequestType: REQ_UPDATE_NEIGHBOR,
		Data:        &peer,
		ResponseCh:  ch,
	}
	res := <-ch
	return res.Data.(bool), res.Err()
}

func (server *BgpServer) Shutdown() {
	server.shutdown = true
	for _, p := range server.neighborMap {
		p.fsm.adminStateCh <- ADMIN_STATE_DOWN
	}
	// TODO: call fsmincomingCh.Close()
}

func (server *BgpServer) UpdatePolicy(policy config.RoutingPolicy) {
	ch := make(chan *GrpcResponse)
	server.GrpcReqCh <- &GrpcRequest{
		RequestType: REQ_RELOAD_POLICY,
		Data:        policy,
		ResponseCh:  ch,
	}
	<-ch
}

func (server *BgpServer) setPolicyByConfig(id string, c config.ApplyPolicy) {
	for _, dir := range []table.PolicyDirection{table.POLICY_DIRECTION_IN, table.POLICY_DIRECTION_IMPORT, table.POLICY_DIRECTION_EXPORT} {
		ps, def, err := server.policy.GetAssignmentFromConfig(dir, c)
		if err != nil {
			log.WithFields(log.Fields{
				"Topic": "Policy",
				"Dir":   dir,
			}).Errorf("failed to get policy info: %s", err)
			continue
		}
		server.policy.SetDefaultPolicy(id, dir, def)
		server.policy.SetPolicy(id, dir, ps)
	}
}

func (server *BgpServer) SetRoutingPolicy(pl config.RoutingPolicy) error {
	if err := server.policy.Reload(pl); err != nil {
		log.WithFields(log.Fields{
			"Topic": "Policy",
		}).Errorf("failed to create routing policy: %s", err)
		return err
	}
	server.setPolicyByConfig(table.GLOBAL_RIB_NAME, server.bgpConfig.Global.ApplyPolicy)
	return nil
}

func (server *BgpServer) handlePolicy(pl config.RoutingPolicy) error {
	if err := server.SetRoutingPolicy(pl); err != nil {
		log.WithFields(log.Fields{
			"Topic": "Policy",
		}).Errorf("failed to set new policy: %s", err)
		return err
	}
	for _, peer := range server.neighborMap {
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   peer.fsm.pConf.Config.NeighborAddress,
		}).Info("call set policy")
		server.setPolicyByConfig(peer.ID(), peer.fsm.pConf.ApplyPolicy)
	}
	return nil
}

func (server *BgpServer) checkNeighborRequest(grpcReq *GrpcRequest) (*Peer, error) {
	remoteAddr := grpcReq.Name
	peer, found := server.neighborMap[remoteAddr]
	if !found {
		result := &GrpcResponse{}
		result.ResponseErr = fmt.Errorf("Neighbor that has %v doesn't exist.", remoteAddr)
		grpcReq.ResponseCh <- result
		close(grpcReq.ResponseCh)
		return nil, result.ResponseErr
	}
	return peer, nil
}

// EVPN MAC MOBILITY HANDLING
//
// We don't have multihoming function now, so ignore
// ESI comparison.
//
// RFC7432 15. MAC Mobility
//
// A PE detecting a locally attached MAC address for which it had
// previously received a MAC/IP Advertisement route with the same zero
// Ethernet segment identifier (single-homed scenarios) advertises it
// with a MAC Mobility extended community attribute with the sequence
// number set properly.  In the case of single-homed scenarios, there
// is no need for ESI comparison.

func getMacMobilityExtendedCommunity(etag uint32, mac net.HardwareAddr, evpnPaths []*table.Path) *bgp.MacMobilityExtended {
	seqs := make([]struct {
		seq     int
		isLocal bool
	}, 0)

	for _, path := range evpnPaths {
		nlri := path.GetNlri().(*bgp.EVPNNLRI)
		target, ok := nlri.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute)
		if !ok {
			continue
		}
		if target.ETag == etag && bytes.Equal(target.MacAddress, mac) {
			found := false
			for _, ec := range path.GetExtCommunities() {
				if t, st := ec.GetTypes(); t == bgp.EC_TYPE_EVPN && st == bgp.EC_SUBTYPE_MAC_MOBILITY {
					seqs = append(seqs, struct {
						seq     int
						isLocal bool
					}{int(ec.(*bgp.MacMobilityExtended).Sequence), path.IsLocal()})
					found = true
					break
				}
			}

			if !found {
				seqs = append(seqs, struct {
					seq     int
					isLocal bool
				}{-1, path.IsLocal()})
			}
		}
	}

	if len(seqs) > 0 {
		newSeq := -2
		var isLocal bool
		for _, seq := range seqs {
			if seq.seq > newSeq {
				newSeq = seq.seq
				isLocal = seq.isLocal
			}
		}

		if !isLocal {
			newSeq += 1
		}

		if newSeq != -1 {
			return &bgp.MacMobilityExtended{
				Sequence: uint32(newSeq),
			}
		}
	}
	return nil
}

func (server *BgpServer) Api2PathList(resource api.Resource, name string, ApiPathList []*api.Path) ([]*table.Path, error) {
	var nlri bgp.AddrPrefixInterface
	var nexthop string
	var pi *table.PeerInfo

	paths := make([]*table.Path, 0, len(ApiPathList))

	for _, path := range ApiPathList {
		seen := make(map[bgp.BGPAttrType]bool)

		pattr := make([]bgp.PathAttributeInterface, 0)
		extcomms := make([]bgp.ExtendedCommunityInterface, 0)

		if path.SourceAsn != 0 {
			pi = &table.PeerInfo{
				AS:      path.SourceAsn,
				LocalID: net.ParseIP(path.SourceId),
			}
		} else {
			pi = &table.PeerInfo{
				AS:      server.bgpConfig.Global.Config.As,
				LocalID: net.ParseIP(server.bgpConfig.Global.Config.RouterId).To4(),
			}
		}

		if len(path.Nlri) > 0 {
			nlri = &bgp.IPAddrPrefix{}
			err := nlri.DecodeFromBytes(path.Nlri)
			if err != nil {
				return nil, err
			}
		}

		for _, attr := range path.Pattrs {
			p, err := bgp.GetPathAttribute(attr)
			if err != nil {
				return nil, err
			}

			err = p.DecodeFromBytes(attr)
			if err != nil {
				return nil, err
			}

			if _, ok := seen[p.GetType()]; !ok {
				seen[p.GetType()] = true
			} else {
				return nil, fmt.Errorf("the path attribute apears twice. Type : " + strconv.Itoa(int(p.GetType())))
			}
			switch p.GetType() {
			case bgp.BGP_ATTR_TYPE_NEXT_HOP:
				nexthop = p.(*bgp.PathAttributeNextHop).Value.String()
			case bgp.BGP_ATTR_TYPE_EXTENDED_COMMUNITIES:
				value := p.(*bgp.PathAttributeExtendedCommunities).Value
				if len(value) > 0 {
					extcomms = append(extcomms, value...)
				}
			case bgp.BGP_ATTR_TYPE_MP_REACH_NLRI:
				mpreach := p.(*bgp.PathAttributeMpReachNLRI)
				if len(mpreach.Value) != 1 {
					return nil, fmt.Errorf("include only one route in mp_reach_nlri")
				}
				nlri = mpreach.Value[0]
				nexthop = mpreach.Nexthop.String()
			default:
				pattr = append(pattr, p)
			}
		}

		if nlri == nil || nexthop == "" {
			return nil, fmt.Errorf("not found nlri or nexthop")
		}

		rf := bgp.AfiSafiToRouteFamily(nlri.AFI(), nlri.SAFI())

		if resource == api.Resource_VRF {
			label, err := server.globalRib.GetNextLabel(name, nexthop, path.IsWithdraw)
			if err != nil {
				return nil, err
			}
			vrf := server.globalRib.Vrfs[name]
			switch rf {
			case bgp.RF_IPv4_UC:
				n := nlri.(*bgp.IPAddrPrefix)
				nlri = bgp.NewLabeledVPNIPAddrPrefix(n.Length, n.Prefix.String(), *bgp.NewMPLSLabelStack(label), vrf.Rd)
			case bgp.RF_IPv6_UC:
				n := nlri.(*bgp.IPv6AddrPrefix)
				nlri = bgp.NewLabeledVPNIPv6AddrPrefix(n.Length, n.Prefix.String(), *bgp.NewMPLSLabelStack(label), vrf.Rd)
			case bgp.RF_EVPN:
				n := nlri.(*bgp.EVPNNLRI)
				switch n.RouteType {
				case bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT:
					n.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute).RD = vrf.Rd
				case bgp.EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG:
					n.RouteTypeData.(*bgp.EVPNMulticastEthernetTagRoute).RD = vrf.Rd
				}
			default:
				return nil, fmt.Errorf("unsupported route family for vrf: %s", rf)
			}
			extcomms = append(extcomms, vrf.ExportRt...)
		}

		if resource != api.Resource_VRF && rf == bgp.RF_IPv4_UC {
			pattr = append(pattr, bgp.NewPathAttributeNextHop(nexthop))
		} else {
			pattr = append(pattr, bgp.NewPathAttributeMpReachNLRI(nexthop, []bgp.AddrPrefixInterface{nlri}))
		}

		if rf == bgp.RF_EVPN {
			evpnNlri := nlri.(*bgp.EVPNNLRI)
			if evpnNlri.RouteType == bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT {
				macIpAdv := evpnNlri.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute)
				etag := macIpAdv.ETag
				mac := macIpAdv.MacAddress
				paths := server.globalRib.GetBestPathList(table.GLOBAL_RIB_NAME, []bgp.RouteFamily{bgp.RF_EVPN})
				if m := getMacMobilityExtendedCommunity(etag, mac, paths); m != nil {
					extcomms = append(extcomms, m)
				}
			}
		}

		if len(extcomms) > 0 {
			pattr = append(pattr, bgp.NewPathAttributeExtendedCommunities(extcomms))
		}
		newPath := table.NewPath(pi, nlri, path.IsWithdraw, pattr, time.Now(), path.NoImplicitWithdraw)
		newPath.SetIsFromExternal(path.IsFromExternal)
		paths = append(paths, newPath)

	}
	return paths, nil
}

func (server *BgpServer) handleAddPathRequest(grpcReq *GrpcRequest) []*table.Path {
	var err error
	var uuidBytes []byte
	paths := make([]*table.Path, 0, 1)
	arg, ok := grpcReq.Data.(*api.AddPathRequest)
	if !ok {
		err = fmt.Errorf("type assertion failed")
	} else {
		paths, err = server.Api2PathList(arg.Resource, arg.VrfId, []*api.Path{arg.Path})
		if err == nil {
			u := uuid.NewV4()
			uuidBytes = u.Bytes()
			paths[0].SetUUID(uuidBytes)
		}
	}
	grpcReq.ResponseCh <- &GrpcResponse{
		ResponseErr: err,
		Data: &api.AddPathResponse{
			Uuid: uuidBytes,
		},
	}
	close(grpcReq.ResponseCh)
	return paths
}

func (server *BgpServer) handleDeletePathRequest(grpcReq *GrpcRequest) []*table.Path {
	var err error
	paths := make([]*table.Path, 0, 1)
	arg, ok := grpcReq.Data.(*api.DeletePathRequest)
	if !ok {
		err = fmt.Errorf("type assertion failed")
	} else {
		if len(arg.Uuid) > 0 {
			path := func() *table.Path {
				for _, path := range server.globalRib.GetPathList(table.GLOBAL_RIB_NAME, server.globalRib.GetRFlist()) {
					if len(path.UUID()) > 0 && bytes.Equal(path.UUID(), arg.Uuid) {
						return path
					}
				}
				return nil
			}()
			if path != nil {
				paths = append(paths, path.Clone(true))
			} else {
				err = fmt.Errorf("Can't find a specified path")
			}
		} else if arg.Path != nil {
			arg.Path.IsWithdraw = true
			paths, err = server.Api2PathList(arg.Resource, arg.VrfId, []*api.Path{arg.Path})
		} else {
			// delete all paths
			families := server.globalRib.GetRFlist()
			if arg.Family != 0 {
				families = []bgp.RouteFamily{bgp.RouteFamily(arg.Family)}
			}
			for _, path := range server.globalRib.GetPathList(table.GLOBAL_RIB_NAME, families) {
				paths = append(paths, path.Clone(true))
			}
		}
	}
	grpcReq.ResponseCh <- &GrpcResponse{
		ResponseErr: err,
		Data:        &api.DeletePathResponse{},
	}
	close(grpcReq.ResponseCh)
	return paths
}

func (server *BgpServer) handleInjectMrtRequest(grpcReq *GrpcRequest) []*table.Path {
	var err error
	var paths []*table.Path
	arg, ok := grpcReq.Data.(*api.InjectMrtRequest)
	if !ok {
		err = fmt.Errorf("type assertion failed")
	}
	if err == nil {
		paths, err = server.Api2PathList(arg.Resource, arg.VrfId, arg.Paths)
		if err == nil {
			return paths
		}
	}
	result := &GrpcResponse{
		ResponseErr: err,
	}
	grpcReq.ResponseCh <- result
	close(grpcReq.ResponseCh)
	return []*table.Path{}

}

func (server *BgpServer) handleAddVrfRequest(grpcReq *GrpcRequest) ([]*table.Path, error) {
	arg, _ := grpcReq.Data.(*api.AddVrfRequest)
	rib := server.globalRib
	rd := bgp.GetRouteDistinguisher(arg.Vrf.Rd)
	f := func(bufs [][]byte) ([]bgp.ExtendedCommunityInterface, error) {
		ret := make([]bgp.ExtendedCommunityInterface, 0, len(bufs))
		for _, rt := range bufs {
			r, err := bgp.ParseExtended(rt)
			if err != nil {
				return nil, err
			}
			ret = append(ret, r)
		}
		return ret, nil
	}
	importRt, err := f(arg.Vrf.ImportRt)
	if err != nil {
		return nil, err
	}
	exportRt, err := f(arg.Vrf.ExportRt)
	if err != nil {
		return nil, err
	}
	pi := &table.PeerInfo{
		AS:      server.bgpConfig.Global.Config.As,
		LocalID: net.ParseIP(server.bgpConfig.Global.Config.RouterId).To4(),
	}
	return rib.AddVrf(arg.Vrf.Name, rd, importRt, exportRt, pi)
}

func (server *BgpServer) handleDeleteVrfRequest(grpcReq *GrpcRequest) ([]*table.Path, error) {
	arg, _ := grpcReq.Data.(*api.DeleteVrfRequest)
	rib := server.globalRib
	return rib.DeleteVrf(arg.Vrf.Name)
}

func (server *BgpServer) handleVrfRequest(req *GrpcRequest) []*table.Path {
	var msgs []*table.Path
	result := &GrpcResponse{}

	switch req.RequestType {
	case REQ_VRF:
		arg := req.Data.(*api.GetRibRequest)
		name := arg.Table.Name
		rib := server.globalRib
		vrfs := rib.Vrfs
		if _, ok := vrfs[name]; !ok {
			result.ResponseErr = fmt.Errorf("vrf %s not found", name)
			break
		}
		var rf bgp.RouteFamily
		switch bgp.RouteFamily(arg.Table.Family) {
		case bgp.RF_IPv4_UC:
			rf = bgp.RF_IPv4_VPN
		case bgp.RF_IPv6_UC:
			rf = bgp.RF_IPv6_VPN
		case bgp.RF_EVPN:
			rf = bgp.RF_EVPN
		default:
			result.ResponseErr = fmt.Errorf("unsupported route family: %s", bgp.RouteFamily(arg.Table.Family))
			break
		}
		paths := rib.GetPathList(table.GLOBAL_RIB_NAME, []bgp.RouteFamily{rf})
		dsts := make([]*api.Destination, 0, len(paths))
		for _, path := range paths {
			ok := table.CanImportToVrf(vrfs[name], path)
			if !ok {
				continue
			}
			dsts = append(dsts, &api.Destination{
				Prefix: path.GetNlri().String(),
				Paths:  []*api.Path{path.ToApiStruct(table.GLOBAL_RIB_NAME)},
			})
		}
		req.ResponseCh <- &GrpcResponse{
			Data: &api.GetRibResponse{
				Table: &api.Table{
					Type:         arg.Table.Type,
					Family:       arg.Table.Family,
					Destinations: dsts,
				},
			},
		}
		goto END
	case REQ_GET_VRF:
		l := make([]*api.Vrf, 0, len(server.globalRib.Vrfs))
		for _, vrf := range server.globalRib.Vrfs {
			l = append(l, vrf.ToApiStruct())
		}
		result.Data = &api.GetVrfResponse{Vrfs: l}
	case REQ_ADD_VRF:
		msgs, result.ResponseErr = server.handleAddVrfRequest(req)
		result.Data = &api.AddVrfResponse{}
	case REQ_DELETE_VRF:
		msgs, result.ResponseErr = server.handleDeleteVrfRequest(req)
		result.Data = &api.DeleteVrfResponse{}
	default:
		result.ResponseErr = fmt.Errorf("unknown request type: %d", req.RequestType)
	}

	req.ResponseCh <- result
END:
	close(req.ResponseCh)
	return msgs
}

func (server *BgpServer) handleModConfig(grpcReq *GrpcRequest) error {
	var c *config.Global
	switch arg := grpcReq.Data.(type) {
	case *api.StartServerRequest:
		g := arg.Global
		if net.ParseIP(g.RouterId) == nil {
			return fmt.Errorf("invalid router-id format: %s", g.RouterId)
		}
		families := make([]config.AfiSafi, 0, len(g.Families))
		for _, f := range g.Families {
			name := config.AfiSafiType(bgp.RouteFamily(f).String())
			families = append(families, config.AfiSafi{
				Config: config.AfiSafiConfig{
					AfiSafiName: name,
					Enabled:     true,
				},
				State: config.AfiSafiState{
					AfiSafiName: name,
				},
			})
		}
		b := &config.BgpConfigSet{
			Global: config.Global{
				Config: config.GlobalConfig{
					As:               g.As,
					RouterId:         g.RouterId,
					Port:             g.ListenPort,
					LocalAddressList: g.ListenAddresses,
				},
				MplsLabelRange: config.MplsLabelRange{
					MinLabel: g.MplsLabelMin,
					MaxLabel: g.MplsLabelMax,
				},
				AfiSafis: families,
			},
		}
		if err := config.SetDefaultConfigValues(nil, b); err != nil {
			return err
		}
		c = &b.Global
	case *config.Global:
		c = arg
	case *api.StopServerRequest:
		for k, _ := range server.neighborMap {
			_, err := server.handleDeleteNeighborRequest(&GrpcRequest{
				Data: &api.DeleteNeighborRequest{
					Peer: &api.Peer{
						Conf: &api.PeerConf{
							NeighborAddress: k,
						},
					},
				},
			})
			if err != nil {
				return err
			}
		}
		for _, l := range server.listeners {
			l.Close()
		}
		server.bgpConfig.Global = config.Global{}
		return nil
	}

	if server.bgpConfig.Global.Config.As != 0 {
		return fmt.Errorf("gobgp is already started")
	}

	if c.Config.Port > 0 {
		acceptCh := make(chan *net.TCPConn, 4096)
		for _, addr := range c.Config.LocalAddressList {
			l, err := NewTCPListener(addr, uint32(c.Config.Port), acceptCh)
			if err != nil {
				return err
			}
			server.listeners = append(server.listeners, l)
		}
		server.acceptCh = acceptCh
	}

	rfs, _ := config.AfiSafis(c.AfiSafis).ToRfList()
	server.globalRib = table.NewTableManager(rfs, c.MplsLabelRange.MinLabel, c.MplsLabelRange.MaxLabel)

	p := config.RoutingPolicy{}
	if err := server.SetRoutingPolicy(p); err != nil {
		return err
	}
	server.bgpConfig.Global = *c
	// update route selection options
	table.SelectionOptions = c.RouteSelectionOptions.Config
	table.UseMultiplePaths = c.UseMultiplePaths.Config
	return nil
}

func sendMultipleResponses(grpcReq *GrpcRequest, results []*GrpcResponse) {
	defer close(grpcReq.ResponseCh)
	for _, r := range results {
		select {
		case grpcReq.ResponseCh <- r:
		case <-grpcReq.EndCh:
			return
		}
	}
}

func (server *BgpServer) handleGrpc(grpcReq *GrpcRequest) []*SenderMsg {
	var msgs []*SenderMsg

	logOp := func(addr string, action string) {
		log.WithFields(log.Fields{
			"Topic": "Operation",
			"Key":   addr,
		}).Info(action)
	}

	reqToPeers := func(grpcReq *GrpcRequest) ([]*Peer, error) {
		peers := make([]*Peer, 0)
		if grpcReq.Name == "all" {
			for _, p := range server.neighborMap {
				peers = append(peers, p)
			}
			return peers, nil
		}
		peer, err := server.checkNeighborRequest(grpcReq)
		return []*Peer{peer}, err
	}

	if server.bgpConfig.Global.Config.As == 0 && grpcReq.RequestType != REQ_START_SERVER {
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: fmt.Errorf("bgpd main loop is not started yet"),
		}
		close(grpcReq.ResponseCh)
		return nil
	}

	var err error

	switch grpcReq.RequestType {
	case REQ_GET_SERVER:
		g := server.bgpConfig.Global
		result := &GrpcResponse{
			Data: &api.GetServerResponse{
				Global: &api.Global{
					As:              g.Config.As,
					RouterId:        g.Config.RouterId,
					ListenPort:      g.Config.Port,
					ListenAddresses: g.Config.LocalAddressList,
					MplsLabelMin:    g.MplsLabelRange.MinLabel,
					MplsLabelMax:    g.MplsLabelRange.MaxLabel,
				},
			},
		}
		grpcReq.ResponseCh <- result
		close(grpcReq.ResponseCh)
	case REQ_START_SERVER:
		err := server.handleModConfig(grpcReq)
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
			Data:        &api.StartServerResponse{},
		}
		close(grpcReq.ResponseCh)
	case REQ_STOP_SERVER:
		err := server.handleModConfig(grpcReq)
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
			Data:        &api.StopServerResponse{},
		}
		close(grpcReq.ResponseCh)
	case REQ_GLOBAL_RIB, REQ_LOCAL_RIB:
		arg := grpcReq.Data.(*api.GetRibRequest)
		d := &api.Table{
			Type:   arg.Table.Type,
			Family: arg.Table.Family,
		}
		rib := server.globalRib
		id := table.GLOBAL_RIB_NAME
		if grpcReq.RequestType == REQ_LOCAL_RIB {
			peer, ok := server.neighborMap[arg.Table.Name]
			if !ok {
				err = fmt.Errorf("Neighbor that has %v doesn't exist.", arg.Table.Name)
				goto ERROR
			}
			if !peer.isRouteServerClient() {
				err = fmt.Errorf("Neighbor %v doesn't have local rib", arg.Table.Name)
				goto ERROR
			}
			id = peer.ID()
		}
		af := bgp.RouteFamily(arg.Table.Family)
		if _, ok := rib.Tables[af]; !ok {
			err = fmt.Errorf("address family: %s not supported", af)
			goto ERROR
		}

		dsts := make([]*api.Destination, 0, len(rib.Tables[af].GetDestinations()))
		if (af == bgp.RF_IPv4_UC || af == bgp.RF_IPv6_UC) && len(arg.Table.Destinations) > 0 {
			f := func(id, cidr string) (bool, error) {
				_, prefix, err := net.ParseCIDR(cidr)
				if err != nil {
					return false, err
				}
				if dst := rib.Tables[af].GetDestination(prefix.String()); dst != nil {
					if d := dst.ToApiStruct(id); d != nil {
						dsts = append(dsts, d)
					}
					return true, nil
				} else {
					return false, nil
				}
			}
			for _, dst := range arg.Table.Destinations {
				key := dst.Prefix
				if _, err := f(id, key); err != nil {
					if host := net.ParseIP(key); host != nil {
						masklen := 32
						if af == bgp.RF_IPv6_UC {
							masklen = 128
						}
						for i := masklen; i > 0; i-- {
							if y, _ := f(id, fmt.Sprintf("%s/%d", key, i)); y {
								break
							}
						}
					}
				} else if dst.LongerPrefixes {
					_, prefix, _ := net.ParseCIDR(key)
					ones, bits := prefix.Mask.Size()
					for i := ones + 1; i <= bits; i++ {
						prefix.Mask = net.CIDRMask(i, bits)
						f(id, prefix.String())
					}
				}
			}
		} else {
			for _, dst := range rib.Tables[af].GetSortedDestinations() {
				if d := dst.ToApiStruct(id); d != nil {
					dsts = append(dsts, d)
				}
			}
		}
		d.Destinations = dsts
		grpcReq.ResponseCh <- &GrpcResponse{
			Data: &api.GetRibResponse{Table: d},
		}
		close(grpcReq.ResponseCh)
	case REQ_BMP_GLOBAL:
		paths := server.globalRib.GetBestPathList(table.GLOBAL_RIB_NAME, server.globalRib.GetRFlist())
		bmpmsgs := make([]*bmp.BMPMessage, 0, len(paths))
		for _, path := range paths {
			msgs := table.CreateUpdateMsgFromPaths([]*table.Path{path})
			buf, _ := msgs[0].Serialize()
			bmpmsgs = append(bmpmsgs, bmpPeerRoute(bmp.BMP_PEER_TYPE_GLOBAL, true, 0, path.GetSource(), path.GetTimestamp().Unix(), buf))
		}
		grpcReq.ResponseCh <- &GrpcResponse{
			Data: bmpmsgs,
		}
		close(grpcReq.ResponseCh)
	case REQ_ADD_PATH:
		pathList := server.handleAddPathRequest(grpcReq)
		if len(pathList) > 0 {
			msgs, _ = server.propagateUpdate(nil, pathList)
		}
	case REQ_DELETE_PATH:
		pathList := server.handleDeletePathRequest(grpcReq)
		if len(pathList) > 0 {
			msgs, _ = server.propagateUpdate(nil, pathList)
		}
	case REQ_BMP_NEIGHBORS:
		//TODO: merge REQ_NEIGHBORS and REQ_BMP_NEIGHBORS
		msgs := make([]*bmp.BMPMessage, 0, len(server.neighborMap))
		for _, peer := range server.neighborMap {
			if peer.fsm.state != bgp.BGP_FSM_ESTABLISHED {
				continue
			}
			laddr, lport := peer.fsm.LocalHostPort()
			_, rport := peer.fsm.RemoteHostPort()
			sentOpen := buildopen(peer.fsm.gConf, peer.fsm.pConf)
			info := peer.fsm.peerInfo
			timestamp := peer.fsm.pConf.Timers.State.Uptime
			msg := bmpPeerUp(laddr, lport, rport, sentOpen, peer.fsm.recvOpen, bmp.BMP_PEER_TYPE_GLOBAL, false, 0, info, timestamp)
			msgs = append(msgs, msg)
		}
		grpcReq.ResponseCh <- &GrpcResponse{
			Data: msgs,
		}
		close(grpcReq.ResponseCh)
	case REQ_NEIGHBOR:
		l := []*api.Peer{}
		for _, peer := range server.neighborMap {
			l = append(l, peer.ToApiStruct())
		}
		grpcReq.ResponseCh <- &GrpcResponse{
			Data: &api.GetNeighborResponse{
				Peers: l,
			},
		}
		close(grpcReq.ResponseCh)
	case REQ_ADJ_RIB_IN, REQ_ADJ_RIB_OUT:
		arg := grpcReq.Data.(*api.GetRibRequest)
		d := &api.Table{
			Type:   arg.Table.Type,
			Family: arg.Table.Family,
		}

		peer, ok := server.neighborMap[arg.Table.Name]
		if !ok {
			err = fmt.Errorf("Neighbor that has %v doesn't exist.", arg.Table.Name)
			goto ERROR
		}

		rf := bgp.RouteFamily(arg.Table.Family)
		var paths []*table.Path
		if grpcReq.RequestType == REQ_ADJ_RIB_IN {
			paths = peer.adjRibIn.PathList([]bgp.RouteFamily{rf}, false)
			log.Debugf("RouteFamily=%v adj-rib-in found : %d", rf.String(), len(paths))
		} else {
			paths = peer.adjRibOut.PathList([]bgp.RouteFamily{rf}, false)
			log.Debugf("RouteFamily=%v adj-rib-out found : %d", rf.String(), len(paths))
		}

		results := make([]*api.Destination, 0, len(paths))
		switch rf {
		case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
			r := radix.New()
			for _, p := range paths {
				key := p.GetNlri().String()
				found := true
				for _, dst := range arg.Table.Destinations {
					found = false
					if dst.Prefix == key {
						found = true
						break
					}
				}

				if found {
					b, _ := r.Get(table.CidrToRadixkey(key))
					if b == nil {
						r.Insert(table.CidrToRadixkey(key), &api.Destination{
							Prefix: key,
							Paths:  []*api.Path{p.ToApiStruct(peer.TableID())},
						})
					} else {
						d := b.(*api.Destination)
						d.Paths = append(d.Paths, p.ToApiStruct(peer.TableID()))
					}
				}
			}
			r.Walk(func(s string, v interface{}) bool {
				results = append(results, v.(*api.Destination))
				return false
			})
		default:
			for _, p := range paths {
				results = append(results, &api.Destination{
					Prefix: p.GetNlri().String(),
					Paths:  []*api.Path{p.ToApiStruct(peer.TableID())},
				})
			}
		}
		d.Destinations = results
		grpcReq.ResponseCh <- &GrpcResponse{
			Data: &api.GetRibResponse{Table: d},
		}
		close(grpcReq.ResponseCh)
	case REQ_BMP_ADJ_IN:
		bmpmsgs := make([]*bmp.BMPMessage, 0)
		for _, peer := range server.neighborMap {
			if peer.fsm.state != bgp.BGP_FSM_ESTABLISHED {
				continue
			}
			for _, path := range peer.adjRibIn.PathList(peer.configuredRFlist(), false) {
				msgs := table.CreateUpdateMsgFromPaths([]*table.Path{path})
				buf, _ := msgs[0].Serialize()
				bmpmsgs = append(bmpmsgs, bmpPeerRoute(bmp.BMP_PEER_TYPE_GLOBAL, false, 0, peer.fsm.peerInfo, path.GetTimestamp().Unix(), buf))
			}
		}
		grpcReq.ResponseCh <- &GrpcResponse{
			Data: bmpmsgs,
		}
		close(grpcReq.ResponseCh)
	case REQ_NEIGHBOR_SHUTDOWN:
		peers, err := reqToPeers(grpcReq)
		if err != nil {
			break
		}
		logOp(grpcReq.Name, "Neighbor shutdown")
		m := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN, nil)
		for _, peer := range peers {
			msgs = append(msgs, newSenderMsg(peer, nil, m, false))
		}
		grpcReq.ResponseCh <- &GrpcResponse{Data: &api.ShutdownNeighborResponse{}}
		close(grpcReq.ResponseCh)

	case REQ_NEIGHBOR_RESET:
		peers, err := reqToPeers(grpcReq)
		if err != nil {
			break
		}
		logOp(grpcReq.Name, "Neighbor reset")
		m := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET, nil)
		for _, peer := range peers {
			peer.fsm.idleHoldTime = peer.fsm.pConf.Timers.Config.IdleHoldTimeAfterReset
			msgs = append(msgs, newSenderMsg(peer, nil, m, false))
		}
		grpcReq.ResponseCh <- &GrpcResponse{Data: &api.ResetNeighborResponse{}}
		close(grpcReq.ResponseCh)

	case REQ_NEIGHBOR_SOFT_RESET, REQ_NEIGHBOR_SOFT_RESET_IN:
		peers, err := reqToPeers(grpcReq)
		if err != nil {
			break
		}
		if grpcReq.RequestType == REQ_NEIGHBOR_SOFT_RESET {
			logOp(grpcReq.Name, "Neighbor soft reset")
		} else {
			logOp(grpcReq.Name, "Neighbor soft reset in")
		}

		for _, peer := range peers {
			pathList := []*table.Path{}
			families := []bgp.RouteFamily{grpcReq.RouteFamily}
			if families[0] == bgp.RouteFamily(0) {
				families = peer.configuredRFlist()
			}
			for _, path := range peer.adjRibIn.PathList(families, false) {
				exResult := path.Filtered(peer.ID())
				path.Filter(peer.ID(), table.POLICY_DIRECTION_NONE)
				if server.policy.ApplyPolicy(peer.ID(), table.POLICY_DIRECTION_IN, path, nil) != nil {
					pathList = append(pathList, path.Clone(false))
					// this path still in rib's
					// knownPathList. We can't
					// drop
					// table.POLICY_DIRECTION_IMPORT
					// flag here. Otherwise, this
					// path could be the old best
					// path.
					if peer.isRouteServerClient() {
						path.Filter(peer.ID(), table.POLICY_DIRECTION_IMPORT)
					}
				} else {
					path.Filter(peer.ID(), table.POLICY_DIRECTION_IN)
					if exResult != table.POLICY_DIRECTION_IN {
						pathList = append(pathList, path.Clone(true))
					}
				}
			}
			peer.adjRibIn.RefreshAcceptedNumber(families)
			m, _ := server.propagateUpdate(peer, pathList)
			msgs = append(msgs, m...)
		}

		if grpcReq.RequestType == REQ_NEIGHBOR_SOFT_RESET_IN {
			grpcReq.ResponseCh <- &GrpcResponse{Data: &api.SoftResetNeighborResponse{}}
			close(grpcReq.ResponseCh)
			break
		}
		fallthrough
	case REQ_NEIGHBOR_SOFT_RESET_OUT, REQ_DEFERRAL_TIMER_EXPIRED:
		peers, err := reqToPeers(grpcReq)
		if err != nil {
			break
		}
		if grpcReq.RequestType == REQ_NEIGHBOR_SOFT_RESET_OUT {
			logOp(grpcReq.Name, "Neighbor soft reset out")
		}
		for _, peer := range peers {
			if peer.fsm.state != bgp.BGP_FSM_ESTABLISHED {
				continue
			}

			families := []bgp.RouteFamily{grpcReq.RouteFamily}
			if families[0] == bgp.RouteFamily(0) {
				families = peer.configuredRFlist()
			}

			if grpcReq.RequestType == REQ_DEFERRAL_TIMER_EXPIRED {
				if peer.fsm.pConf.GracefulRestart.State.LocalRestarting {
					peer.fsm.pConf.GracefulRestart.State.LocalRestarting = false
					log.WithFields(log.Fields{
						"Topic":    "Peer",
						"Key":      peer.ID(),
						"Families": families,
					}).Debug("deferral timer expired")
				} else if c := config.GetAfiSafi(peer.fsm.pConf, bgp.RF_RTC_UC); peer.fsm.rfMap[bgp.RF_RTC_UC] && !c.MpGracefulRestart.State.EndOfRibReceived {
					log.WithFields(log.Fields{
						"Topic":    "Peer",
						"Key":      peer.ID(),
						"Families": families,
					}).Debug("route-target deferral timer expired")
				} else {
					continue
				}
			}

			sentPathList := peer.adjRibOut.PathList(families, false)
			peer.adjRibOut.Drop(families)
			pathList, filtered := peer.getBestFromLocal(families)
			if len(pathList) > 0 {
				peer.adjRibOut.Update(pathList)
				msgs = append(msgs, newSenderMsg(peer, pathList, nil, false))
			}
			if grpcReq.RequestType != REQ_DEFERRAL_TIMER_EXPIRED && len(filtered) > 0 {
				withdrawnList := make([]*table.Path, 0, len(filtered))
				for _, p := range filtered {
					found := false
					for _, sentPath := range sentPathList {
						if p.GetNlri() == sentPath.GetNlri() {
							found = true
							break
						}
					}
					if found {
						withdrawnList = append(withdrawnList, p.Clone(true))
					}
				}
				msgs = append(msgs, newSenderMsg(peer, withdrawnList, nil, false))
			}
		}
		grpcReq.ResponseCh <- &GrpcResponse{Data: &api.SoftResetNeighborResponse{}}
		close(grpcReq.ResponseCh)

	case REQ_NEIGHBOR_ENABLE, REQ_NEIGHBOR_DISABLE:
		peer, err1 := server.checkNeighborRequest(grpcReq)
		if err1 != nil {
			break
		}
		result := &GrpcResponse{}
		if grpcReq.RequestType == REQ_NEIGHBOR_ENABLE {
			select {
			case peer.fsm.adminStateCh <- ADMIN_STATE_UP:
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   peer.fsm.pConf.Config.NeighborAddress,
				}).Debug("ADMIN_STATE_UP requested")
			default:
				log.Warning("previous request is still remaining. : ", peer.fsm.pConf.Config.NeighborAddress)
				result.ResponseErr = fmt.Errorf("previous request is still remaining %v", peer.fsm.pConf.Config.NeighborAddress)
			}
			result.Data = &api.EnableNeighborResponse{}
		} else {
			select {
			case peer.fsm.adminStateCh <- ADMIN_STATE_DOWN:
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   peer.fsm.pConf.Config.NeighborAddress,
				}).Debug("ADMIN_STATE_DOWN requested")
			default:
				log.Warning("previous request is still remaining. : ", peer.fsm.pConf.Config.NeighborAddress)
				result.ResponseErr = fmt.Errorf("previous request is still remaining %v", peer.fsm.pConf.Config.NeighborAddress)
			}
			result.Data = &api.DisableNeighborResponse{}
		}
		grpcReq.ResponseCh <- result
		close(grpcReq.ResponseCh)
	case REQ_GRPC_ADD_NEIGHBOR:
		_, err := server.handleAddNeighborRequest(grpcReq)
		grpcReq.ResponseCh <- &GrpcResponse{
			Data:        &api.AddNeighborResponse{},
			ResponseErr: err,
		}
		close(grpcReq.ResponseCh)
	case REQ_GRPC_DELETE_NEIGHBOR:
		m, err := server.handleDeleteNeighborRequest(grpcReq)
		grpcReq.ResponseCh <- &GrpcResponse{
			Data:        &api.DeleteNeighborResponse{},
			ResponseErr: err,
		}
		if len(m) > 0 {
			msgs = append(msgs, m...)
		}
		close(grpcReq.ResponseCh)
	case REQ_ADD_NEIGHBOR:
		_, err := server.handleAddNeighbor(grpcReq.Data.(*config.Neighbor))
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
		}
		close(grpcReq.ResponseCh)
	case REQ_DEL_NEIGHBOR:
		m, err := server.handleDelNeighbor(grpcReq.Data.(*config.Neighbor), bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_PEER_DECONFIGURED)
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
		}
		if len(m) > 0 {
			msgs = append(msgs, m...)
		}
		close(grpcReq.ResponseCh)
	case REQ_UPDATE_NEIGHBOR:
		m, policyUpdated, err := server.handleUpdateNeighbor(grpcReq.Data.(*config.Neighbor))
		grpcReq.ResponseCh <- &GrpcResponse{
			Data:        policyUpdated,
			ResponseErr: err,
		}
		if len(m) > 0 {
			msgs = append(msgs, m...)
		}
		close(grpcReq.ResponseCh)
	case REQ_GET_DEFINED_SET:
		rsp, err := server.handleGrpcGetDefinedSet(grpcReq)
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
			Data:        rsp,
		}
		close(grpcReq.ResponseCh)
	case REQ_ADD_DEFINED_SET:
		rsp, err := server.handleGrpcAddDefinedSet(grpcReq)
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
			Data:        rsp,
		}
		close(grpcReq.ResponseCh)
	case REQ_DELETE_DEFINED_SET:
		rsp, err := server.handleGrpcDeleteDefinedSet(grpcReq)
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
			Data:        rsp,
		}
		close(grpcReq.ResponseCh)
	case REQ_REPLACE_DEFINED_SET:
		rsp, err := server.handleGrpcReplaceDefinedSet(grpcReq)
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
			Data:        rsp,
		}
		close(grpcReq.ResponseCh)
	case REQ_GET_STATEMENT:
		rsp, err := server.handleGrpcGetStatement(grpcReq)
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
			Data:        rsp,
		}
		close(grpcReq.ResponseCh)
	case REQ_ADD_STATEMENT:
		data, err := server.handleGrpcAddStatement(grpcReq)
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
			Data:        data,
		}
		close(grpcReq.ResponseCh)
	case REQ_DELETE_STATEMENT:
		data, err := server.handleGrpcDeleteStatement(grpcReq)
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
			Data:        data,
		}
		close(grpcReq.ResponseCh)
	case REQ_REPLACE_STATEMENT:
		data, err := server.handleGrpcReplaceStatement(grpcReq)
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
			Data:        data,
		}
		close(grpcReq.ResponseCh)
	case REQ_GET_POLICY:
		rsp, err := server.handleGrpcGetPolicy(grpcReq)
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
			Data:        rsp,
		}
		close(grpcReq.ResponseCh)
	case REQ_ADD_POLICY:
		data, err := server.handleGrpcAddPolicy(grpcReq)
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
			Data:        data,
		}
		close(grpcReq.ResponseCh)
	case REQ_DELETE_POLICY:
		data, err := server.handleGrpcDeletePolicy(grpcReq)
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
			Data:        data,
		}
		close(grpcReq.ResponseCh)
	case REQ_REPLACE_POLICY:
		data, err := server.handleGrpcReplacePolicy(grpcReq)
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
			Data:        data,
		}
		close(grpcReq.ResponseCh)
	case REQ_GET_POLICY_ASSIGNMENT:
		data, err := server.handleGrpcGetPolicyAssignment(grpcReq)
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
			Data:        data,
		}
		close(grpcReq.ResponseCh)
	case REQ_ADD_POLICY_ASSIGNMENT:
		data, err := server.handleGrpcAddPolicyAssignment(grpcReq)
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
			Data:        data,
		}
		close(grpcReq.ResponseCh)
	case REQ_DELETE_POLICY_ASSIGNMENT:
		data, err := server.handleGrpcDeletePolicyAssignment(grpcReq)
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
			Data:        data,
		}
		close(grpcReq.ResponseCh)
	case REQ_REPLACE_POLICY_ASSIGNMENT:
		data, err := server.handleGrpcReplacePolicyAssignment(grpcReq)
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
			Data:        data,
		}
		close(grpcReq.ResponseCh)
	case REQ_MONITOR_RIB, REQ_MONITOR_NEIGHBOR_PEER_STATE:
		if grpcReq.Name != "" {
			if _, err = server.checkNeighborRequest(grpcReq); err != nil {
				break
			}
		}
		w, y := server.watchers.watcher(WATCHER_GRPC_MONITOR)
		if y {
			go w.(*grpcWatcher).addRequest(grpcReq)
		}
	case REQ_ENABLE_MRT:
		server.handleEnableMrtRequest(grpcReq)
	case REQ_DISABLE_MRT:
		server.handleDisableMrtRequest(grpcReq)
	case REQ_INJECT_MRT:
		pathList := server.handleInjectMrtRequest(grpcReq)
		if len(pathList) > 0 {
			msgs, _ = server.propagateUpdate(nil, pathList)
			grpcReq.ResponseCh <- &GrpcResponse{}
			close(grpcReq.ResponseCh)
		}
	case REQ_ADD_BMP:
		server.handleAddBmp(grpcReq)
	case REQ_DELETE_BMP:
		server.handleDeleteBmp(grpcReq)
	case REQ_VALIDATE_RIB:
		server.handleValidateRib(grpcReq)
	case REQ_INITIALIZE_RPKI:
		g := grpcReq.Data.(*config.Global)
		grpcDone(grpcReq, server.roaManager.SetAS(g.Config.As))
	case REQ_ADD_RPKI, REQ_DELETE_RPKI, REQ_ENABLE_RPKI, REQ_DISABLE_RPKI, REQ_RESET_RPKI, REQ_SOFT_RESET_RPKI:
		server.handleModRpki(grpcReq)
	case REQ_ROA, REQ_GET_RPKI:
		rsp := server.roaManager.handleGRPC(grpcReq)
		grpcReq.ResponseCh <- rsp
		close(grpcReq.ResponseCh)
	case REQ_VRF, REQ_GET_VRF, REQ_ADD_VRF, REQ_DELETE_VRF:
		pathList := server.handleVrfRequest(grpcReq)
		if len(pathList) > 0 {
			msgs, _ = server.propagateUpdate(nil, pathList)
		}
	case REQ_RELOAD_POLICY:
		err := server.handlePolicy(grpcReq.Data.(config.RoutingPolicy))
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
		}
		close(grpcReq.ResponseCh)
	case REQ_INITIALIZE_ZEBRA:
		c := grpcReq.Data.(*config.ZebraConfig)
		protos := make([]string, 0, len(c.RedistributeRouteTypeList))
		for _, p := range c.RedistributeRouteTypeList {
			protos = append(protos, string(p))
		}
		z, err := newZebraWatcher(server.GrpcReqCh, c.Url, protos)
		if err == nil {
			server.watchers.addWatcher(WATCHER_ZEBRA, z)
		}
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
		}
		close(grpcReq.ResponseCh)
	case REQ_INITIALIZE_COLLECTOR:
		c := grpcReq.Data.(*config.CollectorConfig)
		collector, err := NewCollector(server.GrpcReqCh, c.Url, c.DbName, c.TableDumpInterval)
		if err == nil {
			server.watchers.addWatcher(WATCHER_COLLECTOR, collector)
		}
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
		}
		close(grpcReq.ResponseCh)
	case REQ_WATCHER_ADJ_RIB_IN:
		pathList := make([]*table.Path, 0)
		for _, peer := range server.neighborMap {
			pathList = append(pathList, peer.adjRibIn.PathList(peer.configuredRFlist(), false)...)
		}

		grpcReq.ResponseCh <- &GrpcResponse{}
		close(grpcReq.ResponseCh)
		server.watchers.notify(WATCHER_EVENT_ADJ_IN, &watcherEventAdjInMsg{pathList: pathList})
	default:
		err = fmt.Errorf("Unknown request type: %v", grpcReq.RequestType)
		goto ERROR
	}
	return msgs
ERROR:
	grpcReq.ResponseCh <- &GrpcResponse{
		ResponseErr: err,
	}
	close(grpcReq.ResponseCh)
	return msgs
}

func (server *BgpServer) handleGrpcGetDefinedSet(grpcReq *GrpcRequest) (*api.GetDefinedSetResponse, error) {
	arg := grpcReq.Data.(*api.GetDefinedSetRequest)
	typ := table.DefinedType(arg.Type)
	set, ok := server.policy.DefinedSetMap[typ]
	if !ok {
		return &api.GetDefinedSetResponse{}, fmt.Errorf("invalid defined-set type: %d", typ)
	}
	sets := make([]*api.DefinedSet, 0)
	for _, s := range set {
		sets = append(sets, s.ToApiStruct())
	}
	return &api.GetDefinedSetResponse{Sets: sets}, nil
}

func (server *BgpServer) handleAddNeighbor(c *config.Neighbor) ([]*SenderMsg, error) {
	addr := c.Config.NeighborAddress
	if _, y := server.neighborMap[addr]; y {
		return nil, fmt.Errorf("Can't overwrite the exising peer: %s", addr)
	}

	if server.bgpConfig.Global.Config.Port > 0 {
		for _, l := range server.Listeners(addr) {
			SetTcpMD5SigSockopts(l, addr, c.Config.AuthPassword)
		}
	}
	log.Info("Add a peer configuration for ", addr)

	peer := NewPeer(&server.bgpConfig.Global, c, server.globalRib, server.policy)
	server.setPolicyByConfig(peer.ID(), c.ApplyPolicy)
	if peer.isRouteServerClient() {
		pathList := make([]*table.Path, 0)
		rfList := peer.configuredRFlist()
		for _, p := range server.neighborMap {
			if !p.isRouteServerClient() {
				continue
			}
			pathList = append(pathList, p.getAccepted(rfList)...)
		}
		moded := server.RSimportPaths(peer, pathList)
		if len(moded) > 0 {
			server.globalRib.ProcessPaths(nil, moded)
		}
	}
	server.neighborMap[addr] = peer
	peer.startFSMHandler(server.fsmincomingCh, server.fsmStateCh)
	server.broadcastPeerState(peer, bgp.BGP_FSM_IDLE)
	return nil, nil
}

func (server *BgpServer) handleDelNeighbor(c *config.Neighbor, code, subcode uint8) ([]*SenderMsg, error) {
	addr := c.Config.NeighborAddress
	n, y := server.neighborMap[addr]
	if !y {
		return nil, fmt.Errorf("Can't delete a peer configuration for %s", addr)
	}
	for _, l := range server.Listeners(addr) {
		SetTcpMD5SigSockopts(l, addr, "")
	}
	log.Info("Delete a peer configuration for ", addr)

	n.fsm.sendNotification(code, subcode, nil, "")

	go func(addr string) {
		t := time.AfterFunc(time.Minute*5, func() { log.Fatal("failed to free the fsm.h.t for ", addr) })
		n.fsm.h.t.Kill(nil)
		n.fsm.h.t.Wait()
		t.Stop()
		t = time.AfterFunc(time.Minute*5, func() { log.Fatal("failed to free the fsm.h for ", addr) })
		n.fsm.t.Kill(nil)
		n.fsm.t.Wait()
		t.Stop()
	}(addr)
	delete(server.neighborMap, addr)
	m := server.dropPeerAllRoutes(n, n.configuredRFlist())
	return m, nil
}

func (server *BgpServer) handleUpdateNeighbor(c *config.Neighbor) ([]*SenderMsg, bool, error) {
	addr := c.Config.NeighborAddress
	peer := server.neighborMap[addr]
	policyUpdated := false

	if !peer.fsm.pConf.ApplyPolicy.Equal(&c.ApplyPolicy) {
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   addr,
		}).Info("Update ApplyPolicy")
		server.setPolicyByConfig(peer.ID(), c.ApplyPolicy)
		peer.fsm.pConf.ApplyPolicy = c.ApplyPolicy
		policyUpdated = true
	}
	original := peer.fsm.pConf

	if !original.Config.Equal(&c.Config) || !original.Transport.Config.Equal(&c.Transport.Config) || config.CheckAfiSafisChange(original.AfiSafis, c.AfiSafis) {
		sub := uint8(bgp.BGP_ERROR_SUB_OTHER_CONFIGURATION_CHANGE)
		if original.Config.AdminDown != c.Config.AdminDown {
			sub = bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN
			state := "Admin Down"
			if c.Config.AdminDown == false {
				state = "Admin Up"
			}
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.ID(),
				"State": state,
			}).Info("update admin-state configuration")
		} else if original.Config.PeerAs != c.Config.PeerAs {
			sub = bgp.BGP_ERROR_SUB_PEER_DECONFIGURED
		}
		msgs, err := server.handleDelNeighbor(peer.fsm.pConf, bgp.BGP_ERROR_CEASE, sub)
		if err != nil {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   addr,
			}).Error(err)
			return msgs, policyUpdated, err
		}
		msgs2, err := server.handleAddNeighbor(c)
		msgs = append(msgs, msgs2...)
		if err != nil {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   addr,
			}).Error(err)
		}
		return msgs, policyUpdated, err
	}

	if !original.Timers.Config.Equal(&c.Timers.Config) {
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   peer.ID(),
		}).Info("update timer configuration")
		peer.fsm.pConf.Timers.Config = c.Timers.Config
	}

	msgs, err := peer.updatePrefixLimitConfig(c.AfiSafis)
	if err != nil {
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   addr,
		}).Error(err)
		// rollback to original state
		peer.fsm.pConf = original
		return nil, policyUpdated, err
	}
	return msgs, policyUpdated, nil
}

func (server *BgpServer) handleAddNeighborRequest(grpcReq *GrpcRequest) ([]*SenderMsg, error) {
	arg, ok := grpcReq.Data.(*api.AddNeighborRequest)
	if !ok {
		return []*SenderMsg{}, fmt.Errorf("AddNeighborRequest type assertion failed")
	} else {
		apitoConfig := func(a *api.Peer) (*config.Neighbor, error) {
			pconf := &config.Neighbor{}
			if a.Conf != nil {
				pconf.Config.NeighborAddress = a.Conf.NeighborAddress
				pconf.Config.PeerAs = a.Conf.PeerAs
				if a.Conf.LocalAs == 0 {
					pconf.Config.LocalAs = server.bgpConfig.Global.Config.As
				} else {
					pconf.Config.LocalAs = a.Conf.LocalAs
				}
				if pconf.Config.PeerAs != pconf.Config.LocalAs {
					pconf.Config.PeerType = config.PEER_TYPE_EXTERNAL
				} else {
					pconf.Config.PeerType = config.PEER_TYPE_INTERNAL
				}
				pconf.Config.AuthPassword = a.Conf.AuthPassword
				pconf.Config.RemovePrivateAs = config.RemovePrivateAsOption(a.Conf.RemovePrivateAs)
				pconf.Config.RouteFlapDamping = a.Conf.RouteFlapDamping
				pconf.Config.SendCommunity = config.CommunityType(a.Conf.SendCommunity)
				pconf.Config.Description = a.Conf.Description
				pconf.Config.PeerGroup = a.Conf.PeerGroup
				pconf.Config.NeighborAddress = a.Conf.NeighborAddress
			}
			if a.Timers != nil {
				if a.Timers.Config != nil {
					pconf.Timers.Config.ConnectRetry = float64(a.Timers.Config.ConnectRetry)
					pconf.Timers.Config.HoldTime = float64(a.Timers.Config.HoldTime)
					pconf.Timers.Config.KeepaliveInterval = float64(a.Timers.Config.KeepaliveInterval)
					pconf.Timers.Config.MinimumAdvertisementInterval = float64(a.Timers.Config.MinimumAdvertisementInterval)
				}
			} else {
				pconf.Timers.Config.ConnectRetry = float64(config.DEFAULT_CONNECT_RETRY)
				pconf.Timers.Config.HoldTime = float64(config.DEFAULT_HOLDTIME)
				pconf.Timers.Config.KeepaliveInterval = float64(config.DEFAULT_HOLDTIME / 3)
			}
			if a.RouteReflector != nil {
				pconf.RouteReflector.Config.RouteReflectorClusterId = config.RrClusterIdType(a.RouteReflector.RouteReflectorClusterId)
				pconf.RouteReflector.Config.RouteReflectorClient = a.RouteReflector.RouteReflectorClient
			}
			if a.RouteServer != nil {
				pconf.RouteServer.Config.RouteServerClient = a.RouteServer.RouteServerClient
			}
			if a.ApplyPolicy != nil {
				if a.ApplyPolicy.ImportPolicy != nil {
					pconf.ApplyPolicy.Config.DefaultImportPolicy = config.DefaultPolicyType(a.ApplyPolicy.ImportPolicy.Default)
					for _, p := range a.ApplyPolicy.ImportPolicy.Policies {
						pconf.ApplyPolicy.Config.ImportPolicyList = append(pconf.ApplyPolicy.Config.ImportPolicyList, p.Name)
					}
				}
				if a.ApplyPolicy.ExportPolicy != nil {
					pconf.ApplyPolicy.Config.DefaultExportPolicy = config.DefaultPolicyType(a.ApplyPolicy.ExportPolicy.Default)
					for _, p := range a.ApplyPolicy.ExportPolicy.Policies {
						pconf.ApplyPolicy.Config.ExportPolicyList = append(pconf.ApplyPolicy.Config.ExportPolicyList, p.Name)
					}
				}
				if a.ApplyPolicy.InPolicy != nil {
					pconf.ApplyPolicy.Config.DefaultInPolicy = config.DefaultPolicyType(a.ApplyPolicy.InPolicy.Default)
					for _, p := range a.ApplyPolicy.InPolicy.Policies {
						pconf.ApplyPolicy.Config.InPolicyList = append(pconf.ApplyPolicy.Config.InPolicyList, p.Name)
					}
				}
			}
			if a.Families != nil {
				for _, family := range a.Families {
					name, ok := bgp.AddressFamilyNameMap[bgp.RouteFamily(family)]
					if !ok {
						return pconf, fmt.Errorf("invalid address family: %d", family)
					}
					cAfiSafi := config.AfiSafi{
						Config: config.AfiSafiConfig{
							AfiSafiName: config.AfiSafiType(name),
						},
					}
					pconf.AfiSafis = append(pconf.AfiSafis, cAfiSafi)
				}
			} else {
				if net.ParseIP(a.Conf.NeighborAddress).To4() != nil {
					pconf.AfiSafis = []config.AfiSafi{
						config.AfiSafi{
							Config: config.AfiSafiConfig{
								AfiSafiName: "ipv4-unicast",
							},
						},
					}
				} else {
					pconf.AfiSafis = []config.AfiSafi{
						config.AfiSafi{
							Config: config.AfiSafiConfig{
								AfiSafiName: "ipv6-unicast",
							},
						},
					}
				}
			}
			if a.Transport != nil {
				pconf.Transport.Config.LocalAddress = a.Transport.LocalAddress
				pconf.Transport.Config.PassiveMode = a.Transport.PassiveMode
			} else {
				if net.ParseIP(a.Conf.NeighborAddress).To4() != nil {
					pconf.Transport.Config.LocalAddress = "0.0.0.0"
				} else {
					pconf.Transport.Config.LocalAddress = "::"
				}
			}
			if a.EbgpMultihop != nil {
				pconf.EbgpMultihop.Config.Enabled = a.EbgpMultihop.Enabled
				pconf.EbgpMultihop.Config.MultihopTtl = uint8(a.EbgpMultihop.MultihopTtl)
			}
			return pconf, nil
		}
		c, err := apitoConfig(arg.Peer)
		if err != nil {
			return nil, err
		}
		return server.handleAddNeighbor(c)
	}
}

func (server *BgpServer) handleDeleteNeighborRequest(grpcReq *GrpcRequest) ([]*SenderMsg, error) {
	arg := grpcReq.Data.(*api.DeleteNeighborRequest)
	return server.handleDelNeighbor(&config.Neighbor{
		Config: config.NeighborConfig{
			NeighborAddress: arg.Peer.Conf.NeighborAddress,
		},
	}, bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_PEER_DECONFIGURED)
}

func (server *BgpServer) handleGrpcAddDefinedSet(grpcReq *GrpcRequest) (*api.AddDefinedSetResponse, error) {
	arg := grpcReq.Data.(*api.AddDefinedSetRequest)
	set := arg.Set
	typ := table.DefinedType(set.Type)
	name := set.Name
	var err error
	m, ok := server.policy.DefinedSetMap[typ]
	if !ok {
		return nil, fmt.Errorf("invalid defined-set type: %d", typ)
	}
	d, ok := m[name]
	s, err := table.NewDefinedSetFromApiStruct(set)
	if err != nil {
		return nil, err
	}
	if ok {
		err = d.Append(s)
	} else {
		m[name] = s
	}
	return &api.AddDefinedSetResponse{}, err
}

func (server *BgpServer) handleGrpcDeleteDefinedSet(grpcReq *GrpcRequest) (*api.DeleteDefinedSetResponse, error) {
	arg := grpcReq.Data.(*api.DeleteDefinedSetRequest)
	set := arg.Set
	typ := table.DefinedType(set.Type)
	name := set.Name
	var err error
	m, ok := server.policy.DefinedSetMap[typ]
	if !ok {
		return nil, fmt.Errorf("invalid defined-set type: %d", typ)
	}
	d, ok := m[name]
	if !ok {
		return nil, fmt.Errorf("not found defined-set: %s", name)
	}
	s, err := table.NewDefinedSetFromApiStruct(set)
	if err != nil {
		return nil, err
	}
	if arg.All {
		if server.policy.InUse(d) {
			return nil, fmt.Errorf("can't delete. defined-set %s is in use", name)
		}
		delete(m, name)
	} else {
		err = d.Remove(s)
	}
	return &api.DeleteDefinedSetResponse{}, err
}

func (server *BgpServer) handleGrpcReplaceDefinedSet(grpcReq *GrpcRequest) (*api.ReplaceDefinedSetResponse, error) {
	arg := grpcReq.Data.(*api.ReplaceDefinedSetRequest)
	set := arg.Set
	typ := table.DefinedType(set.Type)
	name := set.Name
	var err error
	m, ok := server.policy.DefinedSetMap[typ]
	if !ok {
		return nil, fmt.Errorf("invalid defined-set type: %d", typ)
	}
	d, ok := m[name]
	if !ok {
		return nil, fmt.Errorf("not found defined-set: %s", name)
	}
	s, err := table.NewDefinedSetFromApiStruct(set)
	if err != nil {
		return nil, err
	}
	return &api.ReplaceDefinedSetResponse{}, d.Replace(s)
}

func (server *BgpServer) handleGrpcGetStatement(grpcReq *GrpcRequest) (*api.GetStatementResponse, error) {
	l := make([]*api.Statement, 0)
	for _, s := range server.policy.StatementMap {
		l = append(l, s.ToApiStruct())
	}
	return &api.GetStatementResponse{Statements: l}, nil
}

func (server *BgpServer) handleGrpcAddStatement(grpcReq *GrpcRequest) (*api.AddStatementResponse, error) {
	var err error
	arg := grpcReq.Data.(*api.AddStatementRequest)
	s, err := table.NewStatementFromApiStruct(arg.Statement, server.policy.DefinedSetMap)
	if err != nil {
		return nil, err
	}
	m := server.policy.StatementMap
	name := s.Name
	if d, ok := m[name]; ok {
		err = d.Add(s)
	} else {
		m[name] = s
	}
	return &api.AddStatementResponse{}, err
}

func (server *BgpServer) handleGrpcDeleteStatement(grpcReq *GrpcRequest) (*api.DeleteStatementResponse, error) {
	var err error
	arg := grpcReq.Data.(*api.DeleteStatementRequest)
	s, err := table.NewStatementFromApiStruct(arg.Statement, server.policy.DefinedSetMap)
	if err != nil {
		return nil, err
	}
	m := server.policy.StatementMap
	name := s.Name
	if d, ok := m[name]; ok {
		if arg.All {
			if server.policy.StatementInUse(d) {
				err = fmt.Errorf("can't delete. statement %s is in use", name)
			} else {
				delete(m, name)
			}
		} else {
			err = d.Remove(s)
		}
	} else {
		err = fmt.Errorf("not found statement: %s", name)
	}
	return &api.DeleteStatementResponse{}, err
}

func (server *BgpServer) handleGrpcReplaceStatement(grpcReq *GrpcRequest) (*api.ReplaceStatementResponse, error) {
	var err error
	arg := grpcReq.Data.(*api.ReplaceStatementRequest)
	s, err := table.NewStatementFromApiStruct(arg.Statement, server.policy.DefinedSetMap)
	if err != nil {
		return nil, err
	}
	m := server.policy.StatementMap
	name := s.Name
	if d, ok := m[name]; ok {
		err = d.Replace(s)
	} else {
		err = fmt.Errorf("not found statement: %s", name)
	}
	return &api.ReplaceStatementResponse{}, err
}

func (server *BgpServer) handleGrpcGetPolicy(grpcReq *GrpcRequest) (*api.GetPolicyResponse, error) {
	policies := make([]*api.Policy, 0, len(server.policy.PolicyMap))
	for _, s := range server.policy.PolicyMap {
		policies = append(policies, s.ToApiStruct())
	}
	return &api.GetPolicyResponse{Policies: policies}, nil
}

func (server *BgpServer) policyInUse(x *table.Policy) bool {
	for _, peer := range server.neighborMap {
		for _, dir := range []table.PolicyDirection{table.POLICY_DIRECTION_IN, table.POLICY_DIRECTION_EXPORT, table.POLICY_DIRECTION_EXPORT} {
			for _, y := range server.policy.GetPolicy(peer.ID(), dir) {
				if x.Name() == y.Name() {
					return true
				}
			}
		}
	}
	for _, dir := range []table.PolicyDirection{table.POLICY_DIRECTION_EXPORT, table.POLICY_DIRECTION_EXPORT} {
		for _, y := range server.policy.GetPolicy(table.GLOBAL_RIB_NAME, dir) {
			if x.Name() == y.Name() {
				return true
			}
		}
	}
	return false
}

func (server *BgpServer) handleGrpcAddPolicy(grpcReq *GrpcRequest) (*api.AddPolicyResponse, error) {
	policyMutex.Lock()
	defer policyMutex.Unlock()
	rsp := &api.AddPolicyResponse{}
	arg := grpcReq.Data.(*api.AddPolicyRequest)
	x, err := table.NewPolicyFromApiStruct(arg.Policy, server.policy.DefinedSetMap)
	if err != nil {
		return rsp, err
	}
	pMap := server.policy.PolicyMap
	sMap := server.policy.StatementMap
	name := x.Name()
	y, ok := pMap[name]
	if arg.ReferExistingStatements {
		err = x.FillUp(sMap)
	} else {
		for _, s := range x.Statements {
			if _, ok := sMap[s.Name]; ok {
				return rsp, fmt.Errorf("statement %s already defined", s.Name)
			}
			sMap[s.Name] = s
		}
	}
	if ok {
		err = y.Add(x)
	} else {
		pMap[name] = x
	}
	return &api.AddPolicyResponse{}, err
}

func (server *BgpServer) handleGrpcDeletePolicy(grpcReq *GrpcRequest) (*api.DeletePolicyResponse, error) {
	policyMutex.Lock()
	defer policyMutex.Unlock()
	rsp := &api.DeletePolicyResponse{}
	arg := grpcReq.Data.(*api.DeletePolicyRequest)
	x, err := table.NewPolicyFromApiStruct(arg.Policy, server.policy.DefinedSetMap)
	if err != nil {
		return rsp, err
	}
	pMap := server.policy.PolicyMap
	sMap := server.policy.StatementMap
	name := x.Name()
	y, ok := pMap[name]
	if !ok {
		return rsp, fmt.Errorf("not found policy: %s", name)
	}
	if arg.All {
		if server.policyInUse(y) {
			return rsp, fmt.Errorf("can't delete. policy %s is in use", name)
		}
		log.WithFields(log.Fields{
			"Topic": "Policy",
			"Key":   name,
		}).Debug("delete policy")
		delete(pMap, name)
	} else {
		err = y.Remove(x)
	}
	if err == nil && !arg.PreserveStatements {
		for _, s := range y.Statements {
			if !server.policy.StatementInUse(s) {
				log.WithFields(log.Fields{
					"Topic": "Policy",
					"Key":   s.Name,
				}).Debug("delete unused statement")
				delete(sMap, s.Name)
			}
		}
	}
	return rsp, err
}

func (server *BgpServer) handleGrpcReplacePolicy(grpcReq *GrpcRequest) (*api.ReplacePolicyResponse, error) {
	policyMutex.Lock()
	defer policyMutex.Unlock()
	rsp := &api.ReplacePolicyResponse{}
	arg := grpcReq.Data.(*api.ReplacePolicyRequest)
	x, err := table.NewPolicyFromApiStruct(arg.Policy, server.policy.DefinedSetMap)
	if err != nil {
		return rsp, err
	}
	pMap := server.policy.PolicyMap
	sMap := server.policy.StatementMap
	name := x.Name()
	y, ok := pMap[name]
	if !ok {
		return rsp, fmt.Errorf("not found policy: %s", name)
	}
	if arg.ReferExistingStatements {
		if err = x.FillUp(sMap); err != nil {
			return rsp, err
		}
	} else {
		for _, s := range x.Statements {
			if _, ok := sMap[s.Name]; ok {
				return rsp, fmt.Errorf("statement %s already defined", s.Name)
			}
			sMap[s.Name] = s
		}
	}

	err = y.Replace(x)
	if err == nil && !arg.PreserveStatements {
		for _, s := range y.Statements {
			if !server.policy.StatementInUse(s) {
				log.WithFields(log.Fields{
					"Topic": "Policy",
					"Key":   s.Name,
				}).Debug("delete unused statement")
				delete(sMap, s.Name)
			}
		}
	}
	return rsp, err
}

func (server *BgpServer) getPolicyInfo(a *api.PolicyAssignment) (string, table.PolicyDirection, error) {
	switch a.Resource {
	case api.Resource_GLOBAL:
		switch a.Type {
		case api.PolicyType_IMPORT:
			return table.GLOBAL_RIB_NAME, table.POLICY_DIRECTION_IMPORT, nil
		case api.PolicyType_EXPORT:
			return table.GLOBAL_RIB_NAME, table.POLICY_DIRECTION_EXPORT, nil
		default:
			return "", table.POLICY_DIRECTION_NONE, fmt.Errorf("invalid policy type")
		}
	case api.Resource_LOCAL:
		peer, ok := server.neighborMap[a.Name]
		if !ok {
			return "", table.POLICY_DIRECTION_NONE, fmt.Errorf("not found peer %s", a.Name)
		}
		if !peer.isRouteServerClient() {
			return "", table.POLICY_DIRECTION_NONE, fmt.Errorf("non-rs-client peer %s doesn't have per peer policy", a.Name)
		}
		switch a.Type {
		case api.PolicyType_IN:
			return peer.ID(), table.POLICY_DIRECTION_IN, nil
		case api.PolicyType_IMPORT:
			return peer.ID(), table.POLICY_DIRECTION_IMPORT, nil
		case api.PolicyType_EXPORT:
			return peer.ID(), table.POLICY_DIRECTION_EXPORT, nil
		default:
			return "", table.POLICY_DIRECTION_NONE, fmt.Errorf("invalid policy type")
		}
	default:
		return "", table.POLICY_DIRECTION_NONE, fmt.Errorf("invalid resource type")
	}

}

func (server *BgpServer) handleGrpcGetPolicyAssignment(grpcReq *GrpcRequest) (*api.GetPolicyAssignmentResponse, error) {
	rsp := &api.GetPolicyAssignmentResponse{}
	id, dir, err := server.getPolicyInfo(grpcReq.Data.(*api.GetPolicyAssignmentRequest).Assignment)
	if err != nil {
		return rsp, err
	}
	rsp.Assignment = &api.PolicyAssignment{
		Default: server.policy.GetDefaultPolicy(id, dir).ToApiStruct(),
	}
	ps := server.policy.GetPolicy(id, dir)
	rsp.Assignment.Policies = make([]*api.Policy, 0, len(ps))
	for _, x := range ps {
		rsp.Assignment.Policies = append(rsp.Assignment.Policies, x.ToApiStruct())
	}
	return rsp, nil
}

func (server *BgpServer) handleGrpcAddPolicyAssignment(grpcReq *GrpcRequest) (*api.AddPolicyAssignmentResponse, error) {
	var err error
	var dir table.PolicyDirection
	var id string
	rsp := &api.AddPolicyAssignmentResponse{}
	policyMutex.Lock()
	defer policyMutex.Unlock()
	arg := grpcReq.Data.(*api.AddPolicyAssignmentRequest)
	assignment := arg.Assignment
	id, dir, err = server.getPolicyInfo(assignment)
	if err != nil {
		return rsp, err
	}
	ps := make([]*table.Policy, 0, len(assignment.Policies))
	seen := make(map[string]bool)
	for _, x := range assignment.Policies {
		p, ok := server.policy.PolicyMap[x.Name]
		if !ok {
			return rsp, fmt.Errorf("not found policy %s", x.Name)
		}
		if seen[x.Name] {
			return rsp, fmt.Errorf("duplicated policy %s", x.Name)
		}
		seen[x.Name] = true
		ps = append(ps, p)
	}
	cur := server.policy.GetPolicy(id, dir)
	if cur == nil {
		err = server.policy.SetPolicy(id, dir, ps)
	} else {
		seen = make(map[string]bool)
		ps = append(cur, ps...)
		for _, x := range ps {
			if seen[x.Name()] {
				return rsp, fmt.Errorf("duplicated policy %s", x.Name())
			}
			seen[x.Name()] = true
		}
		err = server.policy.SetPolicy(id, dir, ps)
	}
	if err != nil {
		return rsp, err
	}

	switch assignment.Default {
	case api.RouteAction_ACCEPT:
		err = server.policy.SetDefaultPolicy(id, dir, table.ROUTE_TYPE_ACCEPT)
	case api.RouteAction_REJECT:
		err = server.policy.SetDefaultPolicy(id, dir, table.ROUTE_TYPE_REJECT)
	}
	return rsp, err
}

func (server *BgpServer) handleGrpcDeletePolicyAssignment(grpcReq *GrpcRequest) (*api.DeletePolicyAssignmentResponse, error) {
	var err error
	var dir table.PolicyDirection
	var id string
	policyMutex.Lock()
	defer policyMutex.Unlock()
	rsp := &api.DeletePolicyAssignmentResponse{}
	arg := grpcReq.Data.(*api.DeletePolicyAssignmentRequest)
	assignment := arg.Assignment
	id, dir, err = server.getPolicyInfo(assignment)
	if err != nil {
		return rsp, err
	}
	ps := make([]*table.Policy, 0, len(assignment.Policies))
	seen := make(map[string]bool)
	for _, x := range assignment.Policies {
		p, ok := server.policy.PolicyMap[x.Name]
		if !ok {
			return rsp, fmt.Errorf("not found policy %s", x.Name)
		}
		if seen[x.Name] {
			return rsp, fmt.Errorf("duplicated policy %s", x.Name)
		}
		seen[x.Name] = true
		ps = append(ps, p)
	}
	cur := server.policy.GetPolicy(id, dir)

	if arg.All {
		err = server.policy.SetPolicy(id, dir, nil)
		if err != nil {
			return rsp, err
		}
		err = server.policy.SetDefaultPolicy(id, dir, table.ROUTE_TYPE_NONE)
	} else {
		n := make([]*table.Policy, 0, len(cur)-len(ps))
		for _, y := range cur {
			found := false
			for _, x := range ps {
				if x.Name() == y.Name() {
					found = true
					break
				}
			}
			if !found {
				n = append(n, y)
			}
		}
		err = server.policy.SetPolicy(id, dir, n)
	}
	return rsp, err
}

func (server *BgpServer) handleGrpcReplacePolicyAssignment(grpcReq *GrpcRequest) (*api.ReplacePolicyAssignmentResponse, error) {
	var err error
	var dir table.PolicyDirection
	var id string
	policyMutex.Lock()
	defer policyMutex.Unlock()
	rsp := &api.ReplacePolicyAssignmentResponse{}
	arg := grpcReq.Data.(*api.ReplacePolicyAssignmentRequest)
	assignment := arg.Assignment
	id, dir, err = server.getPolicyInfo(assignment)
	if err != nil {
		return rsp, err
	}
	ps := make([]*table.Policy, 0, len(assignment.Policies))
	seen := make(map[string]bool)
	for _, x := range assignment.Policies {
		p, ok := server.policy.PolicyMap[x.Name]
		if !ok {
			return rsp, fmt.Errorf("not found policy %s", x.Name)
		}
		if seen[x.Name] {
			return rsp, fmt.Errorf("duplicated policy %s", x.Name)
		}
		seen[x.Name] = true
		ps = append(ps, p)
	}
	server.policy.GetPolicy(id, dir)
	err = server.policy.SetPolicy(id, dir, ps)
	if err != nil {
		return rsp, err
	}
	switch assignment.Default {
	case api.RouteAction_ACCEPT:
		err = server.policy.SetDefaultPolicy(id, dir, table.ROUTE_TYPE_ACCEPT)
	case api.RouteAction_REJECT:
		err = server.policy.SetDefaultPolicy(id, dir, table.ROUTE_TYPE_REJECT)
	}
	return rsp, err
}

func grpcDone(grpcReq *GrpcRequest, e error) {
	result := &GrpcResponse{
		ResponseErr: e,
	}
	grpcReq.ResponseCh <- result
	close(grpcReq.ResponseCh)
}

func (server *BgpServer) handleEnableMrtRequest(grpcReq *GrpcRequest) {
	arg := grpcReq.Data.(*api.EnableMrtRequest)
	if _, y := server.watchers.watcher(WATCHER_MRT); y {
		grpcDone(grpcReq, fmt.Errorf("already enabled"))
		return
	}
	if arg.Interval != 0 && arg.Interval < 30 {
		log.Info("minimum mrt dump interval is 30 seconds")
		arg.Interval = 30
	}
	w, err := newMrtWatcher(arg.DumpType, arg.Filename, arg.Interval)
	if err == nil {
		server.watchers.addWatcher(WATCHER_MRT, w)
	}
	grpcReq.ResponseCh <- &GrpcResponse{
		ResponseErr: err,
		Data:        &api.EnableMrtResponse{},
	}
	close(grpcReq.ResponseCh)
}

func (server *BgpServer) handleDisableMrtRequest(grpcReq *GrpcRequest) {
	_, y := server.watchers.watcher(WATCHER_MRT)
	if !y {
		grpcDone(grpcReq, fmt.Errorf("not enabled yet"))
		return
	}
	server.watchers.delWatcher(WATCHER_MRT)
	grpcReq.ResponseCh <- &GrpcResponse{
		Data: &api.DisableMrtResponse{},
	}
	close(grpcReq.ResponseCh)
}

func (server *BgpServer) handleAddBmp(grpcReq *GrpcRequest) {
	var c *config.BmpServerConfig
	switch arg := grpcReq.Data.(type) {
	case *api.AddBmpRequest:
		c = &config.BmpServerConfig{
			Address: arg.Address,
			Port:    arg.Port,
			RouteMonitoringPolicy: config.BmpRouteMonitoringPolicyType(arg.Type),
		}
	case *config.BmpServerConfig:
		c = arg
	}

	w, y := server.watchers.watcher(WATCHER_BMP)
	if !y {
		w, _ = newBmpWatcher(server.GrpcReqCh)
		server.watchers.addWatcher(WATCHER_BMP, w)
	}

	err := w.(*bmpWatcher).addServer(*c)
	grpcReq.ResponseCh <- &GrpcResponse{
		ResponseErr: err,
		Data:        &api.AddBmpResponse{},
	}
	close(grpcReq.ResponseCh)
}

func (server *BgpServer) handleDeleteBmp(grpcReq *GrpcRequest) {
	var c *config.BmpServerConfig
	switch arg := grpcReq.Data.(type) {
	case *api.DeleteBmpRequest:
		c = &config.BmpServerConfig{
			Address: arg.Address,
			Port:    arg.Port,
		}
	case *config.BmpServerConfig:
		c = arg
	}

	if w, y := server.watchers.watcher(WATCHER_BMP); y {
		err := w.(*bmpWatcher).deleteServer(*c)
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
			Data:        &api.DeleteBmpResponse{},
		}
		close(grpcReq.ResponseCh)
	} else {
		grpcDone(grpcReq, fmt.Errorf("bmp not configured"))
	}
}

func (server *BgpServer) handleValidateRib(grpcReq *GrpcRequest) {
	arg := grpcReq.Data.(*api.ValidateRibRequest)
	for _, rf := range server.globalRib.GetRFlist() {
		if t, ok := server.globalRib.Tables[rf]; ok {
			dsts := t.GetDestinations()
			if arg.Prefix != "" {
				_, prefix, _ := net.ParseCIDR(arg.Prefix)
				if dst := t.GetDestination(prefix.String()); dst != nil {
					dsts = map[string]*table.Destination{prefix.String(): dst}
				}
			}
			for _, dst := range dsts {
				server.roaManager.validate(dst.GetAllKnownPathList())
			}
		}
	}
	result := &GrpcResponse{
		Data: &api.ValidateRibResponse{},
	}
	grpcReq.ResponseCh <- result
	close(grpcReq.ResponseCh)
}

func (server *BgpServer) handleModRpki(grpcReq *GrpcRequest) {
	done := func(grpcReq *GrpcRequest, data interface{}, e error) {
		result := &GrpcResponse{
			ResponseErr: e,
			Data:        data,
		}
		grpcReq.ResponseCh <- result
		close(grpcReq.ResponseCh)
	}

	switch arg := grpcReq.Data.(type) {
	case *api.AddRpkiRequest:
		done(grpcReq, &api.AddRpkiResponse{}, server.roaManager.AddServer(net.JoinHostPort(arg.Address, strconv.Itoa(int(arg.Port))), arg.Lifetime))
	case *api.DeleteRpkiRequest:
		done(grpcReq, &api.DeleteRpkiResponse{}, server.roaManager.DeleteServer(arg.Address))
	case *api.EnableRpkiRequest:
		done(grpcReq, &api.EnableRpkiResponse{}, server.roaManager.Enable(arg.Address))
	case *api.DisableRpkiRequest:
		done(grpcReq, &api.DisableRpkiResponse{}, server.roaManager.Disable(arg.Address))
	case *api.ResetRpkiRequest:
		done(grpcReq, &api.ResetRpkiResponse{}, server.roaManager.Reset(arg.Address))
	case *api.SoftResetRpkiRequest:
		done(grpcReq, &api.SoftResetRpkiResponse{}, server.roaManager.SoftReset(arg.Address))
	}
}
