// Copyright (C) 2014-2016 Nippon Telegraph and Telephone Corporation.
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
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/armon/go-radix"
	"github.com/eapache/channels"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/osrg/gobgp/table"
	"github.com/satori/go.uuid"
)

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
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Error": err,
				}).Warn("Failed to AcceptTCP")
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

	mgmtCh      chan func()
	policy      *table.RoutingPolicy
	listeners   []*TCPListener
	neighborMap map[string]*Peer
	globalRib   *table.TableManager
	roaManager  *roaManager
	shutdown    bool
	watcherMap  map[WatchEventType][]*Watcher
	zclient     *zebraClient
	bmpManager  *bmpClientManager
	mrt         *mrtWriter
}

func NewBgpServer() *BgpServer {
	roaManager, _ := NewROAManager(0)
	s := &BgpServer{
		neighborMap: make(map[string]*Peer),
		policy:      table.NewRoutingPolicy(),
		roaManager:  roaManager,
		mgmtCh:      make(chan func(), 1),
		watcherMap:  make(map[WatchEventType][]*Watcher),
	}
	s.bmpManager = newBmpClientManager(s)
	return s
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

func (s *BgpServer) active() error {
	if s.bgpConfig.Global.Config.As == 0 {
		return fmt.Errorf("bgp server hasn't started yet")
	}
	return nil
}

func (server *BgpServer) Serve() {
	server.listeners = make([]*TCPListener, 0, 2)
	server.fsmincomingCh = channels.NewInfiniteChannel()
	server.fsmStateCh = make(chan *FsmMsg, 4096)

	handleFsmMsg := func(e *FsmMsg) {
		peer, found := server.neighborMap[e.MsgSrc]
		if !found {
			log.WithFields(log.Fields{
				"Topic": "Peer",
			}).Warnf("Cant't find the neighbor %s", e.MsgSrc)
			return
		}
		if e.Version != peer.fsm.version {
			log.WithFields(log.Fields{
				"Topic": "Peer",
			}).Debug("FSM version inconsistent")
			return
		}
		server.handleFSMMessage(peer, e)
	}

	for {
		passConn := func(conn *net.TCPConn) {
			host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			ipaddr, _ := net.ResolveIPAddr("ip", host)
			remoteAddr := ipaddr.String()
			peer, found := server.neighborMap[remoteAddr]
			if found {
				if peer.fsm.adminState != ADMIN_STATE_UP {
					log.WithFields(log.Fields{
						"Topic":       "Peer",
						"Remote Addr": remoteAddr,
						"Admin State": peer.fsm.adminState,
					}).Debug("New connection for non admin-state-up peer")
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
				log.WithFields(log.Fields{
					"Topic": "Peer",
				}).Debugf("Accepted a new passive connection from:%s", remoteAddr)
				peer.PassConn(conn)
			} else {
				log.WithFields(log.Fields{
					"Topic": "Peer",
				}).Infof("Can't find configuration for a new passive connection from:%s", remoteAddr)
				conn.Close()
			}
		}

		select {
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
		case f := <-server.mgmtCh:
			f()
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
		}
	}
}

func sendFsmOutgoingMsg(peer *Peer, paths []*table.Path, notification *bgp.BGPMessage, stayIdle bool) {
	peer.outgoing.In() <- &FsmOutgoingMsg{
		Paths:        paths,
		Notification: notification,
		StayIdle:     stayIdle,
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

func filterpath(peer *Peer, path *table.Path, withdrawals []*table.Path) *table.Path {
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
					if rt == nil {
						ignore = false
					} else if ext.String() == rt.String() {
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
		// Say, gobgp was advertising prefix A and peer P also.
		// When gobgp withdraws prefix A, best path calculation chooses
		// the path from P as the best path for prefix A.
		// For peers other than P, this path should be advertised
		// (as implicit withdrawal). However for P, we should advertise
		// the local withdraw path.

		// Note: multiple paths having the same prefix could exist the
		// withdrawals list in the case of Route Server setup with
		// import policies modifying paths. In such case, gobgp sends
		// duplicated update messages; withdraw messages for the same
		// prefix.
		// However, currently we don't support local path for Route
		// Server setup so this is NOT the case.
		for _, w := range withdrawals {
			if w.IsLocal() && path.GetNlri().String() == w.GetNlri().String() {
				return w
			}
		}
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

func clonePathList(pathList []*table.Path) []*table.Path {
	l := make([]*table.Path, 0, len(pathList))
	for _, p := range pathList {
		if p != nil {
			l = append(l, p.Clone(p.IsWithdraw))
		}
	}
	return l
}

func (server *BgpServer) dropPeerAllRoutes(peer *Peer, families []bgp.RouteFamily) {
	ids := make([]string, 0, len(server.neighborMap))
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
			clonedMpath := make([][]*table.Path, len(multipath))
			for i, pathList := range multipath {
				clonedMpath[i] = clonePathList(pathList)
			}
			server.notifyWatcher(WATCH_EVENT_TYPE_BEST_PATH, &WatchEventBestPath{PathList: clonePathList(best[table.GLOBAL_RIB_NAME]), MultiPathList: clonedMpath})
		}

		for _, targetPeer := range server.neighborMap {
			if peer.isRouteServerClient() != targetPeer.isRouteServerClient() || targetPeer == peer {
				continue
			}
			if paths := targetPeer.processOutgoingPaths(best[targetPeer.TableID()], nil); len(paths) > 0 {
				sendFsmOutgoingMsg(targetPeer, paths, nil, false)
			}
		}
	}
}

func createWatchEventPeerState(peer *Peer) *WatchEventPeerState {
	_, rport := peer.fsm.RemoteHostPort()
	laddr, lport := peer.fsm.LocalHostPort()
	sentOpen := buildopen(peer.fsm.gConf, peer.fsm.pConf)
	recvOpen := peer.fsm.recvOpen
	return &WatchEventPeerState{
		PeerAS:       peer.fsm.peerInfo.AS,
		LocalAS:      peer.fsm.peerInfo.LocalAS,
		PeerAddress:  peer.fsm.peerInfo.Address,
		LocalAddress: net.ParseIP(laddr),
		PeerPort:     rport,
		LocalPort:    lport,
		PeerID:       peer.fsm.peerInfo.ID,
		SentOpen:     sentOpen,
		RecvOpen:     recvOpen,
		State:        peer.fsm.state,
		AdminState:   peer.fsm.adminState,
		Timestamp:    time.Now(),
	}
}

func (server *BgpServer) broadcastPeerState(peer *Peer, oldState bgp.FSMState) {
	newState := peer.fsm.state
	if oldState == bgp.BGP_FSM_ESTABLISHED || newState == bgp.BGP_FSM_ESTABLISHED {
		server.notifyWatcher(WATCH_EVENT_TYPE_PEER_STATE, createWatchEventPeerState(peer))
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

func (server *BgpServer) propagateUpdate(peer *Peer, pathList []*table.Path) []*table.Path {
	rib := server.globalRib
	var alteredPathList, withdrawn []*table.Path
	var best map[string][]*table.Path

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
						if rt == nil || ext.String() == rt.String() {
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
				sendFsmOutgoingMsg(peer, paths, nil, false)
			}
		}
		alteredPathList = pathList
		var multipath [][]*table.Path
		best, withdrawn, multipath = rib.ProcessPaths([]string{table.GLOBAL_RIB_NAME}, pathList)
		if len(best[table.GLOBAL_RIB_NAME]) == 0 {
			return alteredPathList
		}
		clonedMpath := make([][]*table.Path, len(multipath))
		for i, pathList := range multipath {
			clonedMpath[i] = clonePathList(pathList)
		}
		server.notifyWatcher(WATCH_EVENT_TYPE_BEST_PATH, &WatchEventBestPath{PathList: clonePathList(best[table.GLOBAL_RIB_NAME]), MultiPathList: clonedMpath})

	}

	for _, targetPeer := range server.neighborMap {
		if (peer == nil && targetPeer.isRouteServerClient()) || (peer != nil && peer.isRouteServerClient() != targetPeer.isRouteServerClient()) {
			continue
		}
		if paths := targetPeer.processOutgoingPaths(best[targetPeer.TableID()], withdrawn); len(paths) > 0 {
			sendFsmOutgoingMsg(targetPeer, paths, nil, false)
		}
	}
	return alteredPathList
}

func (server *BgpServer) handleFSMMessage(peer *Peer, e *FsmMsg) {
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
			server.dropPeerAllRoutes(peer, drop)
		} else if peer.fsm.pConf.GracefulRestart.State.PeerRestarting && nextState == bgp.BGP_FSM_IDLE {
			// RFC 4724 4.2
			// If the session does not get re-established within the "Restart Time"
			// that the peer advertised previously, the Receiving Speaker MUST
			// delete all the stale routes from the peer that it is retaining.
			peer.fsm.pConf.GracefulRestart.State.PeerRestarting = false
			peer.DropAll(peer.configuredRFlist())
			server.dropPeerAllRoutes(peer, peer.configuredRFlist())
		}

		peer.outgoing.Close()
		peer.outgoing = channels.NewInfiniteChannel()
		if nextState == bgp.BGP_FSM_ESTABLISHED {
			// update for export policy
			laddr, _ := peer.fsm.LocalHostPort()
			peer.fsm.pConf.Transport.State.LocalAddress = laddr
			peer.fsm.peerInfo.LocalAddress = net.ParseIP(laddr)
			deferralExpiredFunc := func(family bgp.RouteFamily) func() {
				return func() {
					ch := make(chan struct{})
					defer func() { <-ch }()

					server.mgmtCh <- func() {
						defer close(ch)

						server.softResetOut(peer.fsm.pConf.Config.NeighborAddress, bgp.RouteFamily(0), true)
					}
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
					sendFsmOutgoingMsg(peer, pathList, nil, false)
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
				}).Debugf("Now syncing, suppress sending updates. start deferral timer(%d)", deferral)
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
			sendFsmOutgoingMsg(peer, paths, nil, false)
			return
		}
	case FSM_MSG_BGP_MESSAGE:
		switch m := e.MsgData.(type) {
		case *bgp.MessageError:
			sendFsmOutgoingMsg(peer, nil, bgp.NewBGPNotificationMessage(m.TypeCode, m.SubTypeCode, m.Data), false)
			return
		case *bgp.BGPMessage:
			server.roaManager.validate(e.PathList)
			pathList, eor, notification := peer.handleUpdate(e)
			if notification != nil {
				sendFsmOutgoingMsg(peer, nil, notification, true)
				return
			}
			if m.Header.Type == bgp.BGP_MSG_UPDATE && server.isWatched(WATCH_EVENT_TYPE_PRE_UPDATE) {
				_, y := peer.fsm.capMap[bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER]
				l, _ := peer.fsm.LocalHostPort()
				ev := &WatchEventUpdate{
					Message:      m,
					PeerAS:       peer.fsm.peerInfo.AS,
					LocalAS:      peer.fsm.peerInfo.LocalAS,
					PeerAddress:  peer.fsm.peerInfo.Address,
					LocalAddress: net.ParseIP(l),
					PeerID:       peer.fsm.peerInfo.ID,
					FourBytesAs:  y,
					Timestamp:    e.timestamp,
					Payload:      e.payload,
					PostPolicy:   false,
					PathList:     clonePathList(pathList),
				}
				server.notifyWatcher(WATCH_EVENT_TYPE_PRE_UPDATE, ev)
			}

			if len(pathList) > 0 {
				var altered []*table.Path
				altered = server.propagateUpdate(peer, pathList)
				if server.isWatched(WATCH_EVENT_TYPE_POST_UPDATE) {
					_, y := peer.fsm.capMap[bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER]
					l, _ := peer.fsm.LocalHostPort()
					ev := &WatchEventUpdate{
						PeerAS:       peer.fsm.peerInfo.AS,
						LocalAS:      peer.fsm.peerInfo.LocalAS,
						PeerAddress:  peer.fsm.peerInfo.Address,
						LocalAddress: net.ParseIP(l),
						PeerID:       peer.fsm.peerInfo.ID,
						FourBytesAs:  y,
						Timestamp:    e.timestamp,
						PostPolicy:   true,
						PathList:     clonePathList(altered),
					}
					for _, u := range table.CreateUpdateMsgFromPaths(altered) {
						payload, _ := u.Serialize()
						ev.Payload = payload
						server.notifyWatcher(WATCH_EVENT_TYPE_POST_UPDATE, ev)
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
								sendFsmOutgoingMsg(p, paths, nil, false)
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
						server.propagateUpdate(peer, pathList)
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
						sendFsmOutgoingMsg(peer, paths, nil, false)
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
	return
}

func (s *BgpServer) StartCollector(c *config.CollectorConfig) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)
		_, err = NewCollector(s, c.Url, c.DbName, c.TableDumpInterval)
	}
	return err
}

func (s *BgpServer) StartZebraClient(x *config.Zebra) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		if s.zclient != nil {
			err = fmt.Errorf("already connected to Zebra")
		} else {
			c := x.Config

			protos := make([]string, 0, len(c.RedistributeRouteTypeList))
			for _, p := range c.RedistributeRouteTypeList {
				protos = append(protos, string(p))
			}
			s.zclient, err = newZebraClient(s, c.Url, protos)
		}
	}
	return err
}

func (s *BgpServer) AddBmp(c *config.BmpServerConfig) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		err = s.bmpManager.addServer(c)
	}
	return err
}

func (s *BgpServer) DeleteBmp(c *config.BmpServerConfig) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		err = s.bmpManager.deleteServer(c)
	}
	return err
}

func (s *BgpServer) Shutdown() {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		s.shutdown = true
		for _, p := range s.neighborMap {
			p.fsm.adminStateCh <- ADMIN_STATE_DOWN
		}
		// TODO: call fsmincomingCh.Close()
	}
}

func (s *BgpServer) UpdatePolicy(policy config.RoutingPolicy) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		ap := make(map[string]config.ApplyPolicy, len(s.neighborMap)+1)
		ap[table.GLOBAL_RIB_NAME] = s.bgpConfig.Global.ApplyPolicy
		for _, peer := range s.neighborMap {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.fsm.pConf.Config.NeighborAddress,
			}).Info("call set policy")
			ap[peer.ID()] = peer.fsm.pConf.ApplyPolicy
		}
		err = s.policy.Reset(&policy, ap)
	}
	return err
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

func (server *BgpServer) fixupApiPath(vrfId string, pathList []*table.Path) error {
	pi := &table.PeerInfo{
		AS:      server.bgpConfig.Global.Config.As,
		LocalID: net.ParseIP(server.bgpConfig.Global.Config.RouterId).To4(),
	}

	for _, path := range pathList {
		if path.GetSource() == nil {
			path.SetSource(pi)
		}

		extcomms := make([]bgp.ExtendedCommunityInterface, 0)
		nlri := path.GetNlri()
		rf := bgp.AfiSafiToRouteFamily(nlri.AFI(), nlri.SAFI())

		if vrfId != "" {
			label, err := server.globalRib.GetNextLabel(vrfId, path.GetNexthop().String(), path.IsWithdraw)
			if err != nil {
				return err
			}
			vrf := server.globalRib.Vrfs[vrfId]
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
				return fmt.Errorf("unsupported route family for vrf: %s", rf)
			}
			extcomms = append(extcomms, vrf.ExportRt...)
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
			path.SetExtCommunities(extcomms, false)
		}
	}
	return nil
}

func (s *BgpServer) AddPath(vrfId string, pathList []*table.Path) (uuidBytes []byte, err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		if err = s.active(); err != nil {
			return
		}

		if err = s.fixupApiPath(vrfId, pathList); err == nil {
			if len(pathList) == 1 {
				uuidBytes = uuid.NewV4().Bytes()
				pathList[0].SetUUID(uuidBytes)
			}
			s.propagateUpdate(nil, pathList)
		}
	}
	return uuidBytes, err
}

func (s *BgpServer) DeletePath(uuid []byte, f bgp.RouteFamily, vrfId string, pathList []*table.Path) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		deletePathList := make([]*table.Path, 0)
		if len(uuid) > 0 {
			path := func() *table.Path {
				for _, path := range s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, s.globalRib.GetRFlist()) {
					if len(path.UUID()) > 0 && bytes.Equal(path.UUID(), uuid) {
						return path
					}
				}
				return nil
			}()
			if path != nil {
				deletePathList = append(deletePathList, path.Clone(true))
			} else {
				err = fmt.Errorf("Can't find a specified path")
			}
		} else if len(pathList) == 0 {
			// delete all paths
			families := s.globalRib.GetRFlist()
			if f != 0 {
				families = []bgp.RouteFamily{f}
			}
			for _, path := range s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, families) {
				deletePathList = append(deletePathList, path.Clone(true))
			}
		} else {
			if err = s.fixupApiPath(vrfId, pathList); err != nil {
				return
			}
			deletePathList = pathList
		}
		s.propagateUpdate(nil, deletePathList)
	}
	return err
}

func (s *BgpServer) Start(c *config.Global) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		if s.bgpConfig.Global.Config.As != 0 {
			err = fmt.Errorf("gobgp is already started")
			return
		}

		if err = config.SetDefaultGlobalConfigValues(c); err != nil {
			return
		}

		if c.Config.Port > 0 {
			acceptCh := make(chan *net.TCPConn, 4096)
			for _, addr := range c.Config.LocalAddressList {
				var l *TCPListener
				l, err = NewTCPListener(addr, uint32(c.Config.Port), acceptCh)
				if err != nil {
					return
				}
				s.listeners = append(s.listeners, l)
			}
			s.acceptCh = acceptCh
		}

		rfs, _ := config.AfiSafis(c.AfiSafis).ToRfList()
		s.globalRib = table.NewTableManager(rfs, c.MplsLabelRange.MinLabel, c.MplsLabelRange.MaxLabel)
		if err = s.policy.Reset(&config.RoutingPolicy{}, map[string]config.ApplyPolicy{table.GLOBAL_RIB_NAME: c.ApplyPolicy}); err != nil {
			return
		}
		s.bgpConfig.Global = *c
		// update route selection options
		table.SelectionOptions = c.RouteSelectionOptions.Config
		table.UseMultiplePaths = c.UseMultiplePaths.Config

		s.roaManager.SetAS(s.bgpConfig.Global.Config.As)
	}
	return nil
}

func (s *BgpServer) GetVrf() (l []*table.Vrf) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		l = make([]*table.Vrf, 0, len(s.globalRib.Vrfs))
		for _, vrf := range s.globalRib.Vrfs {
			l = append(l, vrf.Clone())
		}
	}
	return l
}

func (s *BgpServer) AddVrf(name string, rd bgp.RouteDistinguisherInterface, im, ex []bgp.ExtendedCommunityInterface) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		if err = s.active(); err != nil {
			return
		}

		pi := &table.PeerInfo{
			AS:      s.bgpConfig.Global.Config.As,
			LocalID: net.ParseIP(s.bgpConfig.Global.Config.RouterId).To4(),
		}
		if pathList, e := s.globalRib.AddVrf(name, rd, im, ex, pi); e != nil {
			err = e
		} else if len(pathList) > 0 {
			s.propagateUpdate(nil, pathList)
		}
	}
	return err
}

func (s *BgpServer) DeleteVrf(name string) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		pathList, err := s.globalRib.DeleteVrf(name)
		if err == nil && len(pathList) > 0 {
			s.propagateUpdate(nil, pathList)
		}
	}
	return err
}

func (s *BgpServer) Stop() (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		for k, _ := range s.neighborMap {
			if err = s.deleteNeighbor(&config.Neighbor{Config: config.NeighborConfig{
				NeighborAddress: k}}, bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_PEER_DECONFIGURED); err != nil {
				return
			}
		}
		for _, l := range s.listeners {
			l.Close()
		}
		s.bgpConfig.Global = config.Global{}
	}
	return nil
}

func (s *BgpServer) softResetIn(addr string, family bgp.RouteFamily) error {
	peers, err := s.addrToPeers(addr)
	if err != nil {
		return err
	}
	for _, peer := range peers {
		pathList := []*table.Path{}
		families := []bgp.RouteFamily{family}
		if family == bgp.RouteFamily(0) {
			families = peer.configuredRFlist()
		}
		for _, path := range peer.adjRibIn.PathList(families, false) {
			exResult := path.Filtered(peer.ID())
			path.Filter(peer.ID(), table.POLICY_DIRECTION_NONE)
			if s.policy.ApplyPolicy(peer.ID(), table.POLICY_DIRECTION_IN, path, nil) != nil {
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
		s.propagateUpdate(peer, pathList)
	}
	return err
}

func (s *BgpServer) softResetOut(addr string, family bgp.RouteFamily, deferral bool) error {
	peers, err := s.addrToPeers(addr)
	if err != nil {
		return err
	}
	for _, peer := range peers {
		if peer.fsm.state != bgp.BGP_FSM_ESTABLISHED {
			continue
		}

		families := []bgp.RouteFamily{family}
		if family == bgp.RouteFamily(0) {
			families = peer.configuredRFlist()
		}

		if deferral {
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
			sendFsmOutgoingMsg(peer, pathList, nil, false)
		}
		if deferral == false && len(filtered) > 0 {
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
			sendFsmOutgoingMsg(peer, withdrawnList, nil, false)
		}
	}
	return nil
}

func (s *BgpServer) SoftResetIn(addr string, family bgp.RouteFamily) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	log.WithFields(log.Fields{
		"Topic": "Operation",
		"Key":   addr,
	}).Info("Neighbor soft reset in")

	s.mgmtCh <- func() {
		defer close(ch)
		err = s.softResetIn(addr, family)
	}
	return err
}

func (s *BgpServer) SoftResetOut(addr string, family bgp.RouteFamily) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	log.WithFields(log.Fields{
		"Topic": "Operation",
		"Key":   addr,
	}).Info("Neighbor soft reset out")

	s.mgmtCh <- func() {
		defer close(ch)
		err = s.softResetOut(addr, family, false)
	}
	return err
}

func (s *BgpServer) SoftReset(addr string, family bgp.RouteFamily) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	log.WithFields(log.Fields{
		"Topic": "Operation",
		"Key":   addr,
	}).Info("Neighbor soft reset")

	s.mgmtCh <- func() {
		defer close(ch)
		err = s.softResetIn(addr, family)
		err = s.softResetOut(addr, family, false)
	}
	return err
}

type LookupOption uint8

const (
	LOOKUP_EXACT LookupOption = iota
	LOOKUP_LONGER
	LOOKUP_SHORTER
)

type LookupPrefix struct {
	Prefix string
	LookupOption
}

func (s *BgpServer) GetRib(addr string, family bgp.RouteFamily, prefixes []*LookupPrefix) (id string, dsts map[string][]*table.Path, err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		rib := s.globalRib
		id = table.GLOBAL_RIB_NAME
		if len(addr) > 0 {
			peer, ok := s.neighborMap[addr]
			if !ok {
				err = fmt.Errorf("Neighbor that has %v doesn't exist.", addr)
				return
			}
			if !peer.isRouteServerClient() {
				err = fmt.Errorf("Neighbor %v doesn't have local rib", addr)
				return
			}
			id = peer.ID()
		}
		af := bgp.RouteFamily(family)
		if _, ok := rib.Tables[af]; !ok {
			err = fmt.Errorf("address family: %s not supported", af)
			return
		}

		dsts = make(map[string][]*table.Path)
		if (af == bgp.RF_IPv4_UC || af == bgp.RF_IPv6_UC) && len(prefixes) > 0 {
			f := func(id, cidr string) (bool, error) {
				_, prefix, err := net.ParseCIDR(cidr)
				if err != nil {
					return false, err
				}
				if dst := rib.Tables[af].GetDestination(prefix.String()); dst != nil {
					if paths := dst.GetKnownPathList(id); len(paths) > 0 {
						dsts[dst.GetNlri().String()] = clonePathList(paths)
					}
					return true, nil
				} else {
					return false, nil
				}
			}
			for _, p := range prefixes {
				key := p.Prefix
				switch p.LookupOption {
				case LOOKUP_LONGER:
					_, prefix, _ := net.ParseCIDR(key)
					for _, dst := range rib.Tables[af].GetLongerPrefixDestinations(prefix.String()) {
						if paths := dst.GetKnownPathList(id); len(paths) > 0 {
							dsts[dst.GetNlri().String()] = clonePathList(paths)
						}
					}

				case LOOKUP_SHORTER:
					_, prefix, _ := net.ParseCIDR(key)
					ones, bits := prefix.Mask.Size()
					for i := ones; i > 0; i-- {
						prefix.Mask = net.CIDRMask(i, bits)
						f(id, prefix.String())
					}
				default:
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
					}
				}
			}
		} else {
			for _, dst := range rib.Tables[af].GetSortedDestinations() {
				if paths := dst.GetKnownPathList(id); len(paths) > 0 {
					dsts[dst.GetNlri().String()] = clonePathList(paths)
				}
			}
		}
	}
	return id, dsts, err
}

func (s *BgpServer) GetVrfRib(name string, family bgp.RouteFamily, prefixes []*LookupPrefix) (id string, dsts map[string][]*table.Path, err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		rib := s.globalRib
		vrfs := rib.Vrfs
		if _, ok := vrfs[name]; !ok {
			err = fmt.Errorf("vrf %s not found", name)
			return
		}
		var rf bgp.RouteFamily
		switch family {
		case bgp.RF_IPv4_UC:
			rf = bgp.RF_IPv4_VPN
		case bgp.RF_IPv6_UC:
			rf = bgp.RF_IPv6_VPN
		case bgp.RF_EVPN:
			rf = bgp.RF_EVPN
		default:
			err = fmt.Errorf("unsupported route family: %s", family)
			return
		}

		dsts = make(map[string][]*table.Path)
		for _, path := range rib.GetPathList(table.GLOBAL_RIB_NAME, []bgp.RouteFamily{rf}) {
			if ok := table.CanImportToVrf(vrfs[name], path); ok {
				if d, y := dsts[path.GetNlri().String()]; y {
					d = append(d, path.Clone(false))
				} else {
					dsts[path.GetNlri().String()] = []*table.Path{path.Clone(false)}
				}
			}
		}
	}
	return table.GLOBAL_RIB_NAME, dsts, err
}

func (s *BgpServer) GetAdjRib(addr string, family bgp.RouteFamily, in bool, prefixes []*LookupPrefix) (id string, dsts map[string][]*table.Path, err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		peer, ok := s.neighborMap[addr]
		if !ok {
			err = fmt.Errorf("Neighbor that has %v doesn't exist.", addr)
			return
		}
		id = peer.TableID()

		var paths []*table.Path
		if in {
			paths = peer.adjRibIn.PathList([]bgp.RouteFamily{family}, false)
			log.WithFields(log.Fields{
				"Topic": "Peer",
			}).Debugf("RouteFamily=%v adj-rib-in found : %d", family.String(), len(paths))
		} else {
			paths = peer.adjRibOut.PathList([]bgp.RouteFamily{family}, false)
			log.WithFields(log.Fields{
				"Topic": "Peer",
			}).Debugf("RouteFamily=%v adj-rib-out found : %d", family.String(), len(paths))
		}

		for i, p := range paths {
			paths[i] = p.Clone(false)
			paths[i].Filter(id, p.Filtered(id))
		}

		dsts = make(map[string][]*table.Path)
		switch family {
		case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
			r := radix.New()
			for _, p := range paths {
				key := p.GetNlri().String()
				found := true
				for _, p := range prefixes {
					found = false
					if p.Prefix == key {
						found = true
						break
					}
				}

				if found {
					b, _ := r.Get(table.CidrToRadixkey(key))
					if b == nil {
						r.Insert(table.CidrToRadixkey(key), []*table.Path{p})
					} else {
						l := b.([]*table.Path)
						l = append(l, p)
					}
				}
			}
			r.Walk(func(s string, v interface{}) bool {
				dsts[s] = v.([]*table.Path)
				return false
			})
		default:
			for _, p := range paths {
				if d, y := dsts[p.GetNlri().String()]; y {
					d = append(d, p)
				} else {
					dsts[p.GetNlri().String()] = []*table.Path{p}
				}
			}
		}
	}
	return id, dsts, err
}

func (s *BgpServer) GetServer() (c *config.Global) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		g := s.bgpConfig.Global
		c = &g
	}
	return c
}

func (s *BgpServer) GetNeighbor() (l []*config.Neighbor) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		l = make([]*config.Neighbor, 0, len(s.neighborMap))
		for _, peer := range s.neighborMap {
			l = append(l, peer.ToConfig())
		}
	}
	return l
}

func (server *BgpServer) addNeighbor(c *config.Neighbor) error {

	if err := config.SetDefaultNeighborConfigValues(c, server.bgpConfig.Global.Config.As); err != nil {
		return err
	}

	addr := c.Config.NeighborAddress
	if _, y := server.neighborMap[addr]; y {
		return fmt.Errorf("Can't overwrite the exising peer: %s", addr)
	}

	if server.bgpConfig.Global.Config.Port > 0 {
		for _, l := range server.Listeners(addr) {
			SetTcpMD5SigSockopts(l, addr, c.Config.AuthPassword)
		}
	}
	log.WithFields(log.Fields{
		"Topic": "Peer",
	}).Infof("Add a peer configuration for:%s", addr)

	peer := NewPeer(&server.bgpConfig.Global, c, server.globalRib, server.policy)
	server.policy.Reset(nil, map[string]config.ApplyPolicy{peer.ID(): c.ApplyPolicy})
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
	return nil
}

func (s *BgpServer) AddNeighbor(c *config.Neighbor) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		if err = s.active(); err != nil {
			return
		}
		err = s.addNeighbor(c)
	}
	return err
}

func (server *BgpServer) deleteNeighbor(c *config.Neighbor, code, subcode uint8) error {
	addr := c.Config.NeighborAddress
	if intf := c.Config.NeighborInterface; intf != "" {
		var err error
		addr, err = config.GetIPv6LinkLocalNeighborAddress(intf)
		if err != nil {
			return err
		}
	}
	n, y := server.neighborMap[addr]
	if !y {
		return fmt.Errorf("Can't delete a peer configuration for %s", addr)
	}
	for _, l := range server.Listeners(addr) {
		SetTcpMD5SigSockopts(l, addr, "")
	}
	log.WithFields(log.Fields{
		"Topic": "Peer",
	}).Infof("Delete a peer configuration for:%s", addr)

	n.fsm.sendNotification(code, subcode, nil, "")

	go func(addr string) {
		t1 := time.AfterFunc(time.Minute*5, func() {
			log.WithFields(log.Fields{
				"Topic": "Peer",
			}).Warnf("Failed to free the fsm.h.t for %s", addr)
		})
		n.fsm.h.t.Kill(nil)
		n.fsm.h.t.Wait()
		t1.Stop()
		t2 := time.AfterFunc(time.Minute*5, func() {
			log.WithFields(log.Fields{
				"Topic": "Peer",
			}).Warnf("Failed to free the fsm.t for %s", addr)
		})
		n.fsm.t.Kill(nil)
		n.fsm.t.Wait()
		t2.Stop()
	}(addr)
	delete(server.neighborMap, addr)
	server.dropPeerAllRoutes(n, n.configuredRFlist())
	return nil
}

func (s *BgpServer) DeleteNeighbor(c *config.Neighbor) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		err = s.deleteNeighbor(c, bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_PEER_DECONFIGURED)
	}
	return err
}

func (s *BgpServer) UpdateNeighbor(c *config.Neighbor) (policyUpdated bool, err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		addr := c.Config.NeighborAddress
		peer, ok := s.neighborMap[addr]
		if !ok {
			err = fmt.Errorf("Neighbor that has %v doesn't exist.", addr)
			return
		}

		if !peer.fsm.pConf.ApplyPolicy.Equal(&c.ApplyPolicy) {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   addr,
			}).Info("Update ApplyPolicy")
			s.policy.Reset(nil, map[string]config.ApplyPolicy{peer.ID(): c.ApplyPolicy})
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
			if err = s.deleteNeighbor(peer.fsm.pConf, bgp.BGP_ERROR_CEASE, sub); err != nil {
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   addr,
				}).Error(err)
				return
			}
			err = s.addNeighbor(c)
			if err != nil {
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   addr,
				}).Error(err)
			}
			return
		}

		if !original.Timers.Config.Equal(&c.Timers.Config) {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.ID(),
			}).Info("update timer configuration")
			peer.fsm.pConf.Timers.Config = c.Timers.Config
		}

		err = peer.updatePrefixLimitConfig(c.AfiSafis)
		if err != nil {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   addr,
			}).Error(err)
			// rollback to original state
			peer.fsm.pConf = original
		}
	}
	return policyUpdated, err
}

func (s *BgpServer) addrToPeers(addr string) (l []*Peer, err error) {
	if len(addr) == 0 {
		for _, p := range s.neighborMap {
			l = append(l, p)
		}
		return l, nil
	}
	peer, found := s.neighborMap[addr]
	if !found {
		return l, fmt.Errorf("Neighbor that has %v doesn't exist.", addr)
	}
	return []*Peer{peer}, nil
}

func (s *BgpServer) resetNeighbor(op, addr string, subcode uint8) error {
	log.WithFields(log.Fields{
		"Topic": "Operation",
		"Key":   addr,
	}).Info(op)

	peers, err := s.addrToPeers(addr)
	if err == nil {
		m := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, subcode, nil)
		for _, peer := range peers {
			sendFsmOutgoingMsg(peer, nil, m, false)
		}
	}
	return err
}

func (s *BgpServer) ShutdownNeighbor(addr string) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		err = s.resetNeighbor("Neighbor shutdown", addr, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN)
	}
	return err
}

func (s *BgpServer) ResetNeighbor(addr string) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		err = s.resetNeighbor("Neighbor reset", addr, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET)
		if err == nil {
			peers, _ := s.addrToPeers(addr)
			for _, peer := range peers {
				peer.fsm.idleHoldTime = peer.fsm.pConf.Timers.Config.IdleHoldTimeAfterReset
			}

		}
	}
	return err
}

func (s *BgpServer) setAdminState(addr string, enable bool) error {
	peers, err := s.addrToPeers(addr)
	if err == nil {
		for _, peer := range peers {
			f := func(state AdminState, message string) {
				select {
				case peer.fsm.adminStateCh <- state:
					log.WithFields(log.Fields{
						"Topic": "Peer",
						"Key":   peer.fsm.pConf.Config.NeighborAddress,
					}).Debug(message)
				default:
					log.Warning("previous request is still remaining. : ", peer.fsm.pConf.Config.NeighborAddress)
				}
			}
			if enable {
				f(ADMIN_STATE_UP, "ADMIN_STATE_UP requested")
			} else {
				f(ADMIN_STATE_DOWN, "ADMIN_STATE_DOWN requested")
			}
		}
	}
	return err
}

func (s *BgpServer) EnableNeighbor(addr string) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		err = s.setAdminState(addr, true)
	}
	return err
}

func (s *BgpServer) DisableNeighbor(addr string) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		err = s.setAdminState(addr, false)
	}
	return err
}

func (s *BgpServer) GetDefinedSet(typ table.DefinedType) (sets *config.DefinedSets, err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		sets, err = s.policy.GetDefinedSet(typ)
	}
	return sets, err
}

func (s *BgpServer) AddDefinedSet(a table.DefinedSet) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		err = s.policy.AddDefinedSet(a)
	}
	return err
}

func (s *BgpServer) DeleteDefinedSet(a table.DefinedSet, all bool) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		err = s.policy.DeleteDefinedSet(a, all)
	}
	return err
}

func (s *BgpServer) ReplaceDefinedSet(a table.DefinedSet) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		err = s.policy.ReplaceDefinedSet(a)
	}
	return err
}

func (s *BgpServer) GetStatement() (l []*config.Statement) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		l = s.policy.GetStatement()
	}
	return l
}

func (s *BgpServer) AddStatement(st *table.Statement) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		err = s.policy.AddStatement(st)
	}
	return err
}

func (s *BgpServer) DeleteStatement(st *table.Statement, all bool) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		err = s.policy.DeleteStatement(st, all)
	}
	return err
}

func (s *BgpServer) ReplaceStatement(st *table.Statement) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		err = s.policy.ReplaceStatement(st)
	}
	return err
}

func (s *BgpServer) GetPolicy() (l []*config.PolicyDefinition) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		l = s.policy.GetAllPolicy()
	}
	return l
}

func (s *BgpServer) AddPolicy(x *table.Policy, refer bool) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		err = s.policy.AddPolicy(x, refer)
	}
	return err
}

func (s *BgpServer) DeletePolicy(x *table.Policy, all, preserve bool) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		l := make([]string, 0, len(s.neighborMap)+1)
		for _, peer := range s.neighborMap {
			l = append(l, peer.ID())
		}
		l = append(l, table.GLOBAL_RIB_NAME)

		err = s.policy.DeletePolicy(x, all, preserve, l)

	}
	return err
}

func (s *BgpServer) ReplacePolicy(x *table.Policy, refer, preserve bool) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		err = s.policy.ReplacePolicy(x, refer, preserve)
	}
	return err
}

func (server *BgpServer) toPolicyInfo(name string, dir table.PolicyDirection) (string, error) {
	if name == "" {
		switch dir {
		case table.POLICY_DIRECTION_IMPORT, table.POLICY_DIRECTION_EXPORT:
			return table.GLOBAL_RIB_NAME, nil
		}
		return "", fmt.Errorf("invalid policy type")
	} else {
		peer, ok := server.neighborMap[name]
		if !ok {
			return "", fmt.Errorf("not found peer %s", name)
		}
		if !peer.isRouteServerClient() {
			return "", fmt.Errorf("non-rs-client peer %s doesn't have per peer policy", name)
		}
		return peer.ID(), nil
	}
}

func (s *BgpServer) GetPolicyAssignment(name string, dir table.PolicyDirection) (rt table.RouteType, l []*config.PolicyDefinition, err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		var id string
		id, err = s.toPolicyInfo(name, dir)
		if err != nil {
			rt = table.ROUTE_TYPE_NONE
		} else {
			rt, l, err = s.policy.GetPolicyAssignment(id, dir)
		}
	}
	return rt, l, err
}

func (s *BgpServer) AddPolicyAssignment(name string, dir table.PolicyDirection, policies []*config.PolicyDefinition, def table.RouteType) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		var id string
		id, err = s.toPolicyInfo(name, dir)
		if err != nil {
			return
		}
		err = s.policy.AddPolicyAssignment(id, dir, policies, def)
	}
	return err
}

func (s *BgpServer) DeletePolicyAssignment(name string, dir table.PolicyDirection, policies []*config.PolicyDefinition, all bool) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		var id string
		id, err = s.toPolicyInfo(name, dir)
		if err != nil {
			return
		}
		err = s.policy.DeletePolicyAssignment(id, dir, policies, all)
	}
	return err
}

func (s *BgpServer) ReplacePolicyAssignment(name string, dir table.PolicyDirection, policies []*config.PolicyDefinition, def table.RouteType) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		var id string
		id, err = s.toPolicyInfo(name, dir)
		if err != nil {
			return
		}
		err = s.policy.ReplacePolicyAssignment(id, dir, policies, def)
	}
	return err
}

func (s *BgpServer) EnableMrt(c *config.Mrt) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		if s.mrt != nil {
			err = fmt.Errorf("already enabled")
		} else {
			interval := c.Interval

			if interval != 0 && interval < 30 {
				log.Info("minimum mrt dump interval is 30 seconds")
				interval = 30
			}
			s.mrt, err = newMrtWriter(s, c.DumpType.ToInt(), c.FileName, interval)
		}
	}
	return err
}

func (s *BgpServer) DisableMrt() (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		if s.mrt != nil {
			s.mrt.Stop()
		} else {
			err = fmt.Errorf("not enabled")
		}
	}
	return err
}

func (s *BgpServer) ValidateRib(prefix string) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		for _, rf := range s.globalRib.GetRFlist() {
			if t, ok := s.globalRib.Tables[rf]; ok {
				dsts := t.GetDestinations()
				if prefix != "" {
					_, p, _ := net.ParseCIDR(prefix)
					if dst := t.GetDestination(p.String()); dst != nil {
						dsts = map[string]*table.Destination{p.String(): dst}
					}
				}
				for _, dst := range dsts {
					s.roaManager.validate(dst.GetAllKnownPathList())
				}
			}
		}
	}
	return err
}

func (s *BgpServer) GetRpki() (l []*config.RpkiServer, err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		l = s.roaManager.GetServers()
	}
	return l, err
}

func (s *BgpServer) GetRoa(family bgp.RouteFamily) (l []*ROA, err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		l, err = s.roaManager.GetRoa(family)
	}
	return l, err
}

func (s *BgpServer) AddRpki(c *config.RpkiServerConfig) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		err = s.roaManager.AddServer(net.JoinHostPort(c.Address, strconv.Itoa(int(c.Port))), c.RecordLifetime)
	}
	return err
}

func (s *BgpServer) DeleteRpki(c *config.RpkiServerConfig) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		err = s.roaManager.DeleteServer(c.Address)
	}
	return err
}

func (s *BgpServer) EnableRpki(c *config.RpkiServerConfig) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		err = s.roaManager.Enable(c.Address)
	}
	return err
}

func (s *BgpServer) DisableRpki(c *config.RpkiServerConfig) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		err = s.roaManager.Disable(c.Address)
	}
	return err
}

func (s *BgpServer) ResetRpki(c *config.RpkiServerConfig) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		err = s.roaManager.Reset(c.Address)
	}
	return err
}

func (s *BgpServer) SoftResetRpki(c *config.RpkiServerConfig) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		err = s.roaManager.SoftReset(c.Address)
	}
	return err
}

type WatchEventType string

const (
	WATCH_EVENT_TYPE_BEST_PATH   WatchEventType = "bestpath"
	WATCH_EVENT_TYPE_PRE_UPDATE  WatchEventType = "preupdate"
	WATCH_EVENT_TYPE_POST_UPDATE WatchEventType = "postupdate"
	WATCH_EVENT_TYPE_PEER_STATE  WatchEventType = "peerstate"
)

type WatchEvent interface {
}

type WatchEventUpdate struct {
	Message      *bgp.BGPMessage
	PeerAS       uint32
	LocalAS      uint32
	PeerAddress  net.IP
	LocalAddress net.IP
	PeerID       net.IP
	FourBytesAs  bool
	Timestamp    time.Time
	Payload      []byte
	PostPolicy   bool
	PathList     []*table.Path
}

type WatchEventPeerState struct {
	PeerAS       uint32
	LocalAS      uint32
	PeerAddress  net.IP
	LocalAddress net.IP
	PeerPort     uint16
	LocalPort    uint16
	PeerID       net.IP
	SentOpen     *bgp.BGPMessage
	RecvOpen     *bgp.BGPMessage
	State        bgp.FSMState
	AdminState   AdminState
	Timestamp    time.Time
}

type WatchEventAdjIn struct {
	PathList []*table.Path
}

type WatchEventBestPath struct {
	PathList      []*table.Path
	MultiPathList [][]*table.Path
}

type watchOptions struct {
	bestpath       bool
	preUpdate      bool
	postUpdate     bool
	peerState      bool
	initUpdate     bool
	initPostUpdate bool
	initPeerState  bool
}

type WatchOption func(*watchOptions)

func WatchBestPath() WatchOption {
	return func(o *watchOptions) {
		o.bestpath = true
	}
}

func WatchUpdate(current bool) WatchOption {
	return func(o *watchOptions) {
		o.preUpdate = true
		if current {
			o.initUpdate = true
		}
	}
}

func WatchPostUpdate(current bool) WatchOption {
	return func(o *watchOptions) {
		o.postUpdate = true
		if current {
			o.initPostUpdate = true
		}
	}
}

func WatchPeerState(current bool) WatchOption {
	return func(o *watchOptions) {
		o.peerState = true
		if current {
			o.initPeerState = true
		}
	}
}

type Watcher struct {
	opts   watchOptions
	realCh chan WatchEvent
	ch     *channels.InfiniteChannel
	s      *BgpServer
}

func (w *Watcher) Event() <-chan WatchEvent {
	return w.realCh
}

func (w *Watcher) Generate(t WatchEventType) (err error) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	w.s.mgmtCh <- func() {
		defer close(ch)

		switch t {
		case WATCH_EVENT_TYPE_PRE_UPDATE:
		default:
			err = fmt.Errorf("unsupported type ", t)
			return
		}
		pathList := make([]*table.Path, 0)
		for _, peer := range w.s.neighborMap {
			pathList = append(pathList, peer.adjRibIn.PathList(peer.configuredRFlist(), false)...)
		}
		w.notify(&WatchEventAdjIn{PathList: clonePathList(pathList)})
	}
	return err
}

func (w *Watcher) notify(v WatchEvent) {
	w.ch.In() <- v
}

func (w *Watcher) loop() {
	for {
		select {
		case ev, ok := <-w.ch.Out():
			if !ok {
				close(w.realCh)
				return
			}
			w.realCh <- ev.(WatchEvent)
		}
	}
}

func (w *Watcher) Stop() {
	ch := make(chan struct{})
	defer func() { <-ch }()
	w.s.mgmtCh <- func() {
		defer close(ch)
		for k, l := range w.s.watcherMap {
			for i, v := range l {
				if w == v {
					w.s.watcherMap[k] = append(l[:i], l[i+1:]...)
					break
				}
			}
		}

		w.ch.Close()
		// make sure the loop function finishes
		func() {
			for {
				select {
				case <-w.realCh:
				default:
					return
				}
			}
		}()
	}
}

func (s *BgpServer) isWatched(typ WatchEventType) bool {
	return len(s.watcherMap[typ]) != 0
}

func (s *BgpServer) notifyWatcher(typ WatchEventType, ev WatchEvent) {
	for _, w := range s.watcherMap[typ] {
		w.notify(ev)
	}
}

func (s *BgpServer) Watch(opts ...WatchOption) (w *Watcher) {
	ch := make(chan struct{})
	defer func() { <-ch }()

	s.mgmtCh <- func() {
		defer close(ch)

		w = &Watcher{
			s:      s,
			realCh: make(chan WatchEvent, 8),
			ch:     channels.NewInfiniteChannel(),
		}

		for _, opt := range opts {
			opt(&w.opts)
		}

		register := func(t WatchEventType, w *Watcher) {
			s.watcherMap[t] = append(s.watcherMap[t], w)
		}

		if w.opts.bestpath {
			register(WATCH_EVENT_TYPE_BEST_PATH, w)
		}
		if w.opts.preUpdate {
			register(WATCH_EVENT_TYPE_PRE_UPDATE, w)
		}
		if w.opts.postUpdate {
			register(WATCH_EVENT_TYPE_POST_UPDATE, w)
		}
		if w.opts.peerState {
			register(WATCH_EVENT_TYPE_PEER_STATE, w)
		}
		if w.opts.initPeerState {
			for _, peer := range s.neighborMap {
				if peer.fsm.state != bgp.BGP_FSM_ESTABLISHED {
					continue
				}
				w.notify(createWatchEventPeerState(peer))
			}
		}
		if w.opts.initUpdate {
			for _, peer := range s.neighborMap {
				if peer.fsm.state != bgp.BGP_FSM_ESTABLISHED {
					continue
				}
				for _, path := range peer.adjRibIn.PathList(peer.configuredRFlist(), false) {
					msgs := table.CreateUpdateMsgFromPaths([]*table.Path{path})
					buf, _ := msgs[0].Serialize()
					_, y := peer.fsm.capMap[bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER]
					l, _ := peer.fsm.LocalHostPort()
					w.notify(&WatchEventUpdate{
						Message:      msgs[0],
						PeerAS:       peer.fsm.peerInfo.AS,
						LocalAS:      peer.fsm.peerInfo.LocalAS,
						PeerAddress:  peer.fsm.peerInfo.Address,
						LocalAddress: net.ParseIP(l),
						PeerID:       peer.fsm.peerInfo.ID,
						FourBytesAs:  y,
						Timestamp:    path.GetTimestamp(),
						Payload:      buf,
						PostPolicy:   false,
					})
				}
			}
		}
		if w.opts.postUpdate {
			for _, path := range s.globalRib.GetBestPathList(table.GLOBAL_RIB_NAME, s.globalRib.GetRFlist()) {
				msgs := table.CreateUpdateMsgFromPaths([]*table.Path{path})
				buf, _ := msgs[0].Serialize()
				w.notify(&WatchEventUpdate{
					PeerAS:      path.GetSource().AS,
					PeerAddress: path.GetSource().Address,
					PeerID:      path.GetSource().ID,
					Message:     msgs[0],
					Timestamp:   path.GetTimestamp(),
					Payload:     buf,
					PostPolicy:  true,
				})
			}

		}

		go w.loop()
	}
	return w
}
