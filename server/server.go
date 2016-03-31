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
	"github.com/osrg/gobgp/table"
	"github.com/osrg/gobgp/zebra"
	"github.com/satori/go.uuid"
)

var policyMutex sync.RWMutex

type SenderMsg struct {
	messages    []*bgp.BGPMessage
	sendCh      chan *bgp.BGPMessage
	destination string
	twoBytesAs  bool
}

type broadcastMsg interface {
	send()
}

type broadcastGrpcMsg struct {
	req    *GrpcRequest
	result *GrpcResponse
	done   bool
}

func (m *broadcastGrpcMsg) send() {
	m.req.ResponseCh <- m.result
	if m.done == true {
		close(m.req.ResponseCh)
	}
}

type broadcastBGPMsg struct {
	message      *bgp.BGPMessage
	peerAS       uint32
	localAS      uint32
	peerAddress  net.IP
	localAddress net.IP
	fourBytesAs  bool
	ch           chan *broadcastBGPMsg
}

func (m *broadcastBGPMsg) send() {
	m.ch <- m
}

type Watchers map[watcherType]watcher

func (ws Watchers) watching(typ watcherEventType) bool {
	for _, w := range ws {
		for _, ev := range w.watchingEventTypes() {
			if ev == typ {
				return true
			}
		}
	}
	return false
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
	addedPeerCh   chan config.Neighbor
	deletedPeerCh chan config.Neighbor
	updatedPeerCh chan config.Neighbor
	fsmincomingCh *channels.InfiniteChannel
	fsmStateCh    chan *FsmMsg
	rpkiConfigCh  chan []config.RpkiServer
	acceptCh      chan *net.TCPConn
	zapiMsgCh     chan *zebra.Message

	GrpcReqCh      chan *GrpcRequest
	policyUpdateCh chan config.RoutingPolicy
	policy         *table.RoutingPolicy
	broadcastReqs  []*GrpcRequest
	broadcastMsgs  []broadcastMsg
	listeners      []*TCPListener
	neighborMap    map[string]*Peer
	globalRib      *table.TableManager
	zclient        *zebra.Client
	roaManager     *roaManager
	shutdown       bool
	watchers       Watchers
}

func NewBgpServer() *BgpServer {
	b := BgpServer{}
	b.addedPeerCh = make(chan config.Neighbor)
	b.deletedPeerCh = make(chan config.Neighbor)
	b.updatedPeerCh = make(chan config.Neighbor)
	b.rpkiConfigCh = make(chan []config.RpkiServer)
	b.GrpcReqCh = make(chan *GrpcRequest, 1)
	b.policyUpdateCh = make(chan config.RoutingPolicy)
	b.neighborMap = make(map[string]*Peer)
	b.watchers = Watchers(make(map[watcherType]watcher))
	b.roaManager, _ = NewROAManager(0, nil)
	b.policy = table.NewRoutingPolicy()
	return &b
}

func (server *BgpServer) notify2watchers(typ watcherEventType, ev watcherEvent) error {
	for _, watcher := range server.watchers {
		if ch := watcher.notify(typ); ch != nil {
			server.broadcastMsgs = append(server.broadcastMsgs, &broadcastWatcherMsg{
				ch:    ch,
				event: ev,
			})
		}
	}
	return nil
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
	server.roaManager, _ = NewROAManager(0, nil)

	w, _ := newGrpcIncomingWatcher()
	server.watchers[WATCHER_GRPC_INCOMING] = w

	senderCh := make(chan *SenderMsg, 1<<16)
	go func(ch chan *SenderMsg) {
		for {
			// TODO: must be more clever. Slow peer makes other peers slow too.
			m := <-ch
			w := func(c chan *bgp.BGPMessage, msg *bgp.BGPMessage) {
				// nasty but the peer could already become non established state before here.
				defer func() { recover() }()
				c <- msg
			}

			for _, b := range m.messages {
				if m.twoBytesAs == false && b.Header.Type == bgp.BGP_MSG_UPDATE {
					log.WithFields(log.Fields{
						"Topic": "Peer",
						"Key":   m.destination,
						"Data":  b,
					}).Debug("update for 2byte AS peer")
					table.UpdatePathAttrs2ByteAs(b.Body.(*bgp.BGPUpdate))
				}
				w(m.sendCh, b)
			}
		}
	}(senderCh)

	broadcastCh := make(chan broadcastMsg, 8)
	go func(ch chan broadcastMsg) {
		for {
			m := <-ch
			m.send()
		}
	}(broadcastCh)

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
		var firstBroadcastMsg broadcastMsg
		var bCh chan broadcastMsg
		if len(server.broadcastMsgs) > 0 {
			bCh = broadcastCh
			firstBroadcastMsg = server.broadcastMsgs[0]
		}

		passConn := func(conn *net.TCPConn) {
			remoteAddr, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			peer, found := server.neighborMap[remoteAddr]
			if found {
				localAddrValid := func(laddr net.IP) bool {
					if laddr == nil {
						return true
					}
					l := conn.LocalAddr()
					if l == nil {
						// already closed
						return false
					}

					host, _, _ := net.SplitHostPort(l.String())
					if host != laddr.String() {
						log.WithFields(log.Fields{
							"Topic":           "Peer",
							"Key":             remoteAddr,
							"Configured addr": laddr.String(),
							"Addr":            host,
						}).Info("Mismatched local address")
						return false
					}
					return true
				}(net.ParseIP(peer.conf.Transport.Config.LocalAddress))
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
		case c := <-server.rpkiConfigCh:
			server.roaManager, _ = NewROAManager(server.bgpConfig.Global.Config.As, c)
		case rmsg := <-server.roaManager.ReceiveROA():
			server.roaManager.HandleROAEvent(rmsg)
		case zmsg := <-server.zapiMsgCh:
			m := handleZapiMsg(zmsg, server)
			if len(m) > 0 {
				senderMsgs = append(senderMsgs, m...)
			}
		case conn := <-server.acceptCh:
			passConn(conn)
		case config := <-server.addedPeerCh:
			addr := config.Config.NeighborAddress
			_, found := server.neighborMap[addr]
			if found {
				log.Warn("Can't overwrite the exising peer ", addr)
				continue
			}
			if server.bgpConfig.Global.ListenConfig.Port > 0 {
				for _, l := range server.Listeners(addr) {
					SetTcpMD5SigSockopts(l, addr, config.Config.AuthPassword)
				}
			}
			peer := NewPeer(server.bgpConfig.Global, config, server.globalRib, server.policy)
			server.setPolicyByConfig(peer.ID(), config.ApplyPolicy)
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
		case config := <-server.deletedPeerCh:
			addr := config.Config.NeighborAddress
			for _, l := range server.Listeners(addr) {
				SetTcpMD5SigSockopts(l, addr, "")
			}
			peer, found := server.neighborMap[addr]
			if found {
				log.Info("Delete a peer configuration for ", addr)
				go func(addr string) {
					t := time.AfterFunc(time.Minute*5, func() { log.Fatal("failed to free the fsm.h.t for ", addr) })
					peer.fsm.h.t.Kill(nil)
					peer.fsm.h.t.Wait()
					t.Stop()
					t = time.AfterFunc(time.Minute*5, func() { log.Fatal("failed to free the fsm.h for ", addr) })
					peer.fsm.t.Kill(nil)
					peer.fsm.t.Wait()
					t.Stop()
				}(addr)

				m := server.dropPeerAllRoutes(peer, peer.configuredRFlist())
				if len(m) > 0 {
					senderMsgs = append(senderMsgs, m...)
				}
				delete(server.neighborMap, addr)
			} else {
				log.Info("Can't delete a peer configuration for ", addr)
			}
		case config := <-server.updatedPeerCh:
			addr := config.Config.NeighborAddress
			peer := server.neighborMap[addr]
			peer.conf = config
			server.setPolicyByConfig(peer.ID(), config.ApplyPolicy)
		case e, ok := <-server.fsmincomingCh.Out():
			if !ok {
				continue
			}
			handleFsmMsg(e.(*FsmMsg))
		case e := <-server.fsmStateCh:
			handleFsmMsg(e)
		case sCh <- firstMsg:
			senderMsgs = senderMsgs[1:]
		case bCh <- firstBroadcastMsg:
			server.broadcastMsgs = server.broadcastMsgs[1:]
		case grpcReq := <-server.GrpcReqCh:
			m := server.handleGrpc(grpcReq)
			if len(m) > 0 {
				senderMsgs = append(senderMsgs, m...)
			}
		case pl := <-server.policyUpdateCh:
			server.handlePolicy(pl)
		}
	}
}

func newSenderMsg(peer *Peer, messages []*bgp.BGPMessage) *SenderMsg {
	_, y := peer.fsm.capMap[bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER]
	return &SenderMsg{
		messages:    messages,
		sendCh:      peer.outgoing,
		destination: peer.conf.Config.NeighborAddress,
		twoBytesAs:  y,
	}
}

func isASLoop(peer *Peer, path *table.Path) bool {
	for _, as := range path.GetAsList() {
		if as == peer.conf.Config.PeerAs {
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

	remoteAddr := peer.conf.Config.NeighborAddress

	//iBGP handling
	if !path.IsLocal() && peer.isIBGPPeer() {
		ignore := true
		info := path.GetSource()

		//if the path comes from eBGP peer
		if info.AS != peer.conf.Config.PeerAs {
			ignore = false
		}
		// RFC4456 8. Avoiding Routing Information Loops
		// A router that recognizes the ORIGINATOR_ID attribute SHOULD
		// ignore a route received with its BGP Identifier as the ORIGINATOR_ID.
		if id := path.GetOriginatorID(); peer.gConf.Config.RouterId == id.String() {
			log.WithFields(log.Fields{
				"Topic":        "Peer",
				"Key":          remoteAddr,
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
						"Key":       remoteAddr,
						"ClusterID": clusterId,
						"Data":      path,
					}).Debug("cluster list path attribute has local cluster id, ignore")
					return nil
				}
			}
			ignore = false
		}

		if ignore {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   remoteAddr,
				"Data":  path,
			}).Debug("From same AS, ignore.")
			return nil
		}
	}

	if remoteAddr == path.GetSource().Address.String() {
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   remoteAddr,
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
	msgs := make([]*SenderMsg, 0)

	options := &table.PolicyOptions{}
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
		best, withdrawn := server.globalRib.DeletePathsByPeer(ids, peer.fsm.peerInfo, rf)
		server.validatePaths(nil, withdrawn, true)

		if peer.isRouteServerClient() {
			for _, targetPeer := range server.neighborMap {
				if !targetPeer.isRouteServerClient() || targetPeer == peer || targetPeer.fsm.state != bgp.BGP_FSM_ESTABLISHED {
					continue
				}
				if _, ok := targetPeer.fsm.rfMap[rf]; !ok {
					continue
				}
				pathList := make([]*table.Path, 0, len(best[targetPeer.TableID()]))
				options.Neighbor = targetPeer.fsm.peerInfo.Address
				for _, bestPath := range best[targetPeer.TableID()] {
					if path := server.policy.ApplyPolicy(targetPeer.TableID(), table.POLICY_DIRECTION_EXPORT, filterpath(targetPeer, bestPath), options); path != nil {
						pathList = append(pathList, path)
					}
				}
				msgList := table.CreateUpdateMsgFromPaths(pathList)
				msgs = append(msgs, newSenderMsg(targetPeer, msgList))
				targetPeer.adjRibOut.Update(pathList)
			}
		} else {
			sendPathList := make([]*table.Path, 0, len(best[table.GLOBAL_RIB_NAME]))
			for _, path := range best[table.GLOBAL_RIB_NAME] {
				if path != nil {
					sendPathList = append(sendPathList, path)
				}
			}
			if len(sendPathList) == 0 {
				return msgs
			}

			server.broadcastBests(sendPathList)

			for _, targetPeer := range server.neighborMap {
				if targetPeer.isRouteServerClient() || targetPeer.fsm.state != bgp.BGP_FSM_ESTABLISHED {
					continue
				}
				if _, ok := targetPeer.fsm.rfMap[rf]; !ok {
					continue
				}
				pathList := make([]*table.Path, 0, len(sendPathList))
				options.Neighbor = targetPeer.fsm.peerInfo.Address
				for _, path := range sendPathList {
					if path := server.policy.ApplyPolicy(table.GLOBAL_RIB_NAME, table.POLICY_DIRECTION_EXPORT, filterpath(targetPeer, path), options); path != nil {
						pathList = append(pathList, path)
					}
				}
				targetPeer.adjRibOut.Update(pathList)
				msgList := table.CreateUpdateMsgFromPaths(pathList)

				msgs = append(msgs, newSenderMsg(targetPeer, msgList))
			}
		}
	}
	return msgs
}

func (server *BgpServer) broadcastValidationResults(results []*api.ROAResult) {
	for _, result := range results {
		remainReqs := make([]*GrpcRequest, 0, len(server.broadcastReqs))
		for _, req := range server.broadcastReqs {
			select {
			case <-req.EndCh:
				continue
			default:
			}
			if req.RequestType != REQ_MONITOR_ROA_VALIDATION_RESULT {
				remainReqs = append(remainReqs, req)
				continue
			}
			m := &broadcastGrpcMsg{
				req: req,
				result: &GrpcResponse{
					Data: result,
				},
			}
			server.broadcastMsgs = append(server.broadcastMsgs, m)

			remainReqs = append(remainReqs, req)
		}
		server.broadcastReqs = remainReqs
	}
}

func (server *BgpServer) broadcastBests(bests []*table.Path) {
	for _, path := range bests {
		if !path.IsFromExternal() {
			z := newBroadcastZapiBestMsg(server.zclient, path)
			if z != nil {
				server.broadcastMsgs = append(server.broadcastMsgs, z)
				log.WithFields(log.Fields{
					"Topic":   "Server",
					"Client":  z.client,
					"Message": z.msg,
				}).Debug("Default policy applied and rejected.")
			}
		}

		rf := path.GetRouteFamily()

		result := &GrpcResponse{
			Data: &api.Destination{
				Prefix: path.GetNlri().String(),
				Paths:  []*api.Path{path.ToApiStruct(table.GLOBAL_RIB_NAME)},
			},
		}
		remainReqs := make([]*GrpcRequest, 0, len(server.broadcastReqs))
		for _, req := range server.broadcastReqs {
			select {
			case <-req.EndCh:
				continue
			default:
			}
			if req.RequestType != REQ_MONITOR_GLOBAL_BEST_CHANGED {
				remainReqs = append(remainReqs, req)
				continue
			}
			if req.RouteFamily == bgp.RouteFamily(0) || req.RouteFamily == rf {
				m := &broadcastGrpcMsg{
					req:    req,
					result: result,
				}
				server.broadcastMsgs = append(server.broadcastMsgs, m)
			}
			remainReqs = append(remainReqs, req)
		}
		server.broadcastReqs = remainReqs
	}
}

func (server *BgpServer) broadcastPeerState(peer *Peer, oldState bgp.FSMState) {
	result := &GrpcResponse{
		Data: peer.ToApiStruct(),
	}
	remainReqs := make([]*GrpcRequest, 0, len(server.broadcastReqs))
	for _, req := range server.broadcastReqs {
		select {
		case <-req.EndCh:
			continue
		default:
		}
		ignore := req.RequestType != REQ_MONITOR_NEIGHBOR_PEER_STATE
		ignore = ignore || (req.Name != "" && req.Name != peer.conf.Config.NeighborAddress)
		if ignore {
			remainReqs = append(remainReqs, req)
			continue
		}
		m := &broadcastGrpcMsg{
			req:    req,
			result: result,
		}
		server.broadcastMsgs = append(server.broadcastMsgs, m)
		remainReqs = append(remainReqs, req)
	}
	server.broadcastReqs = remainReqs
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
				timestamp:    time.Now(),
			}
			server.notify2watchers(WATCHER_EVENT_STATE_CHANGE, ev)
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

func (server *BgpServer) isRpkiMonitored() bool {
	if len(server.broadcastReqs) > 0 {
		for _, req := range server.broadcastReqs {
			if req.RequestType == REQ_MONITOR_ROA_VALIDATION_RESULT {
				return true
			}
		}
	}
	return false
}

func (server *BgpServer) validatePaths(newly, withdrawn []*table.Path, peerDown bool) {
	isMonitor := server.isRpkiMonitored()
	if isMonitor {
		rrList := make([]*api.ROAResult, 0, len(withdrawn))
		for _, path := range withdrawn {
			if path.Validation() == config.RPKI_VALIDATION_RESULT_TYPE_INVALID {
				reason := api.ROAResult_WITHDRAW
				if peerDown {
					reason = api.ROAResult_PEER_DOWN
				}
				rr := &api.ROAResult{
					Reason:    reason,
					Address:   path.GetSource().Address.String(),
					Timestamp: path.GetTimestamp().Unix(),
					OriginAs:  path.GetSourceAs(),
					Prefix:    path.GetNlri().String(),
					OldResult: api.ROAResult_ValidationResult(path.Validation().ToInt()),
					NewResult: api.ROAResult_ValidationResult(path.Validation().ToInt()),
				}
				if b := path.GetAsPath(); b != nil {
					rr.AspathAttr, _ = b.Serialize()
				}
				rrList = append(rrList, rr)
			}
		}
		server.broadcastValidationResults(rrList)
	}

	if vResults := server.roaManager.validate(newly, isMonitor); isMonitor {
		for i, path := range newly {
			old := func() config.RpkiValidationResultType {
				for _, withdrawn := range withdrawn {
					if path.GetSource().Equal(withdrawn.GetSource()) {
						return withdrawn.Validation()
					}
				}
				return config.RPKI_VALIDATION_RESULT_TYPE_NONE
			}()
			vResults[i].OldResult = api.ROAResult_ValidationResult(old.ToInt())
		}
		rrList := make([]*api.ROAResult, 0, len(vResults))
		for _, rr := range vResults {
			invalid := api.ROAResult_ValidationResult(config.RPKI_VALIDATION_RESULT_TYPE_INVALID.ToInt())
			if rr.NewResult == invalid || rr.OldResult == invalid {
				rrList = append(rrList, rr)
			}
		}
		server.broadcastValidationResults(rrList)
	}
}

func (server *BgpServer) propagateUpdate(peer *Peer, pathList []*table.Path) ([]*SenderMsg, []*table.Path) {
	msgs := make([]*SenderMsg, 0)
	rib := server.globalRib
	var alteredPathList []*table.Path
	options := &table.PolicyOptions{}
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
			if !p.isRouteServerClient() || p.fsm.state != bgp.BGP_FSM_ESTABLISHED || p.fsm.pConf.GracefulRestart.State.LocalRestarting {
				return false
			}
			return true
		}

		ids := make([]string, 0, len(server.neighborMap))
		for _, targetPeer := range server.neighborMap {
			if isTarget(targetPeer) {
				ids = append(ids, targetPeer.TableID())
			}
		}
		best, newly, withdrawn := rib.ProcessPaths(ids, append(pathList, moded...))
		server.validatePaths(newly, withdrawn, false)

		for _, targetPeer := range server.neighborMap {
			if !isTarget(targetPeer) {
				continue
			}
			sendPathList := make([]*table.Path, 0, len(best[targetPeer.TableID()]))
			options.Neighbor = targetPeer.fsm.peerInfo.Address
			for _, bestPath := range best[targetPeer.TableID()] {
				path := server.policy.ApplyPolicy(targetPeer.TableID(), table.POLICY_DIRECTION_EXPORT, filterpath(targetPeer, bestPath), options)
				if path != nil {
					sendPathList = append(sendPathList, path)
				}
			}
			msgList := table.CreateUpdateMsgFromPaths(sendPathList)
			targetPeer.adjRibOut.Update(sendPathList)
			msgs = append(msgs, newSenderMsg(targetPeer, msgList))
		}
	} else {
		for idx, path := range pathList {
			pathList[idx] = server.policy.ApplyPolicy(table.GLOBAL_RIB_NAME, table.POLICY_DIRECTION_IMPORT, path, nil)
		}
		alteredPathList = pathList
		best, newly, withdrawn := rib.ProcessPaths([]string{table.GLOBAL_RIB_NAME}, pathList)
		server.validatePaths(newly, withdrawn, false)
		sendPathList := make([]*table.Path, 0, len(best[table.GLOBAL_RIB_NAME]))
		if server.bgpConfig.Global.Collector.Enabled {
			sendPathList = pathList
		} else {
			for _, path := range best[table.GLOBAL_RIB_NAME] {
				if path != nil {
					sendPathList = append(sendPathList, path)
				}
			}
			if len(sendPathList) == 0 {
				return msgs, alteredPathList
			}
			server.broadcastBests(sendPathList)
		}

		for _, targetPeer := range server.neighborMap {
			if targetPeer.isRouteServerClient() || targetPeer.fsm.state != bgp.BGP_FSM_ESTABLISHED || targetPeer.fsm.pConf.GracefulRestart.State.LocalRestarting {
				if targetPeer.fsm.pConf.GracefulRestart.State.LocalRestarting {
					log.WithFields(log.Fields{
						"Topic": "Peer",
						"Key":   targetPeer.conf.Config.NeighborAddress,
					}).Debug("now syncing, suppress sending updates")
				}
				continue
			}
			pathList := make([]*table.Path, len(sendPathList))
			copy(pathList, sendPathList)
			options.Neighbor = targetPeer.fsm.peerInfo.Address
			for idx, path := range pathList {
				path = server.policy.ApplyPolicy(table.GLOBAL_RIB_NAME, table.POLICY_DIRECTION_EXPORT, filterpath(targetPeer, path), options)
				if path != nil && !server.bgpConfig.Global.Collector.Enabled {
					path = path.Clone(path.IsWithdraw)
					path.UpdatePathAttrs(&server.bgpConfig.Global, &targetPeer.conf)
				}
				pathList[idx] = path
			}
			targetPeer.adjRibOut.Update(pathList)
			msgList := table.CreateUpdateMsgFromPaths(pathList)

			msgs = append(msgs, newSenderMsg(targetPeer, msgList))
		}
	}
	return msgs, alteredPathList
}

func (server *BgpServer) handleFSMMessage(peer *Peer, e *FsmMsg) []*SenderMsg {
	msgs := make([]*SenderMsg, 0)

	switch e.MsgType {
	case FSM_MSG_STATE_CHANGE:
		nextState := e.MsgData.(bgp.FSMState)
		oldState := bgp.FSMState(peer.conf.State.SessionState.ToInt())
		peer.conf.State.SessionState = config.IntToSessionStateMap[int(nextState)]
		peer.fsm.StateChange(nextState)

		if oldState == bgp.BGP_FSM_ESTABLISHED {
			t := time.Now()
			if t.Sub(time.Unix(peer.conf.Timers.State.Uptime, 0)) < FLOP_THRESHOLD {
				peer.conf.State.Flops++
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
			peer.DropAll(drop)
			msgs = append(msgs, server.dropPeerAllRoutes(peer, drop)...)
		} else if peer.fsm.pConf.GracefulRestart.State.PeerRestarting && nextState == bgp.BGP_FSM_IDLE {
			// RFC 4724 4.2
			// If the session does not get re-established within the "Restart Time"
			// that the peer advertised previously, the Receiving Speaker MUST
			// delete all the stale routes from the peer that it is retaining.
			peer.fsm.pConf.GracefulRestart.State.PeerRestarting = false
			peer.DropAll(peer.configuredRFlist())

			msgs = append(msgs, server.dropPeerAllRoutes(peer, peer.configuredRFlist())...)
		}

		close(peer.outgoing)
		peer.outgoing = make(chan *bgp.BGPMessage, 128)
		if nextState == bgp.BGP_FSM_ESTABLISHED {
			// update for export policy
			laddr, _ := peer.fsm.LocalHostPort()
			peer.conf.Transport.Config.LocalAddress = laddr
			if !peer.fsm.pConf.GracefulRestart.State.LocalRestarting {
				pathList, _ := peer.getBestFromLocal(peer.configuredRFlist())
				if len(pathList) > 0 {
					peer.adjRibOut.Update(pathList)
					msgs = append(msgs, newSenderMsg(peer, table.CreateUpdateMsgFromPaths(pathList)))
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
					"Key":   peer.conf.Config.NeighborAddress,
				}).Debugf("now syncing, suppress sending updates. start deferral timer(%d)", deferral)
				time.AfterFunc(time.Second*time.Duration(deferral), func() {
					req := NewGrpcRequest(REQ_DEFERRAL_TIMER_EXPIRED, peer.conf.Config.NeighborAddress, bgp.RouteFamily(0), nil)
					server.GrpcReqCh <- req
					<-req.ResponseCh
				})
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
			peer.conf.Timers.State.Downtime = time.Now().Unix()
		}
		// clear counter
		if peer.fsm.adminState == ADMIN_STATE_DOWN {
			peer.conf.State = config.NeighborState{}
			peer.conf.Timers.State = config.TimersState{}
		}
		peer.startFSMHandler(server.fsmincomingCh, server.fsmStateCh)
		server.broadcastPeerState(peer, oldState)

	case FSM_MSG_BGP_MESSAGE:
		switch m := e.MsgData.(type) {
		case *bgp.MessageError:
			msgs = append(msgs, newSenderMsg(peer, []*bgp.BGPMessage{bgp.NewBGPNotificationMessage(m.TypeCode, m.SubTypeCode, m.Data)}))
		case *bgp.BGPMessage:
			pathList, msgList, eor := peer.handleBGPmessage(e)

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
				server.notify2watchers(WATCHER_EVENT_UPDATE_MSG, ev)
			}

			if len(msgList) > 0 {
				msgs = append(msgs, newSenderMsg(peer, msgList))
			}

			if len(pathList) > 0 {
				m, altered := server.propagateUpdate(peer, pathList)
				msgs = append(msgs, m...)
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
						server.notify2watchers(WATCHER_EVENT_POST_POLICY_UPDATE_MSG, ev)
					}
				}
			}

			if len(eor) > 0 {
				for _, f := range eor {
					for i, a := range peer.fsm.pConf.AfiSafis {
						if g, _ := bgp.GetRouteFamily(string(a.AfiSafiName)); f == g {
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
							pathList, _ := p.getBestFromLocal(p.configuredRFlist())
							if len(pathList) > 0 {
								p.adjRibOut.Update(pathList)
								msgs = append(msgs, newSenderMsg(p, table.CreateUpdateMsgFromPaths(pathList)))
							}
						}
						log.WithFields(log.Fields{
							"Topic": "Server",
						}).Info("sync finished")
					}
				}
				if peer.fsm.pConf.GracefulRestart.State.PeerRestarting {
					if peer.recvedAllEOR() {
						peer.fsm.pConf.GracefulRestart.State.PeerRestarting = false
						pathList := peer.adjRibIn.DropStale(peer.configuredRFlist())
						log.WithFields(log.Fields{
							"Topic": "Peer",
							"Key":   peer.conf.Config.NeighborAddress,
						}).Debugf("withdraw %d stale routes", len(pathList))
						m, _ := server.propagateUpdate(peer, pathList)
						msgs = append(msgs, m...)
					}
				}
			}
		default:
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.conf.Config.NeighborAddress,
				"Data":  e.MsgData,
			}).Panic("unknown msg type")
		}
	}
	return msgs
}

func (server *BgpServer) SetGlobalType(g config.Global) error {
	ch := make(chan *GrpcResponse)
	server.GrpcReqCh <- &GrpcRequest{
		RequestType: REQ_MOD_GLOBAL_CONFIG,
		Data:        &g,
		ResponseCh:  ch,
	}
	if err := (<-ch).Err(); err != nil {
		return err
	}
	if g.Zebra.Enabled {
		cli, err := NewZclient(g.Zebra.Url, g.Zebra.RedistributeRouteTypeList)
		if err != nil {
			return err
		}
		server.zclient = cli
		server.zapiMsgCh = server.zclient.Receive()
	}
	return nil
}

func (server *BgpServer) SetRpkiConfig(c []config.RpkiServer) {
	server.rpkiConfigCh <- c
}

func (server *BgpServer) SetBmpConfig(c []config.BmpServer) error {
	for _, s := range c {
		ch := make(chan *GrpcResponse)
		server.GrpcReqCh <- &GrpcRequest{
			RequestType: REQ_MOD_BMP,
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
				RequestType: REQ_MOD_MRT,
				Data: &api.ModMrtArguments{
					Operation: api.Operation_ADD,
					DumpType:  int32(s.DumpType.ToInt()),
					Filename:  s.FileName,
					Interval:  s.Interval,
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

func (server *BgpServer) PeerAdd(peer config.Neighbor) {
	server.addedPeerCh <- peer
}

func (server *BgpServer) PeerDelete(peer config.Neighbor) {
	server.deletedPeerCh <- peer
}

func (server *BgpServer) PeerUpdate(peer config.Neighbor) {
	server.updatedPeerCh <- peer
}

func (server *BgpServer) Shutdown() {
	server.shutdown = true
	for _, p := range server.neighborMap {
		p.fsm.adminStateCh <- ADMIN_STATE_DOWN
	}
	// TODO: call fsmincomingCh.Close()
}

func (server *BgpServer) UpdatePolicy(policy config.RoutingPolicy) {
	server.policyUpdateCh <- policy
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
			"Key":   peer.conf.Config.NeighborAddress,
		}).Info("call set policy")
		server.setPolicyByConfig(peer.ID(), peer.conf.ApplyPolicy)
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

func (server *BgpServer) handleModPathRequest(grpcReq *GrpcRequest) []*table.Path {
	var err error
	var uuidBytes []byte
	paths := make([]*table.Path, 0, 1)
	arg, ok := grpcReq.Data.(*api.ModPathArguments)
	if !ok {
		err = fmt.Errorf("type assertion failed")
	}

	if err == nil {
		switch arg.Operation {
		case api.Operation_DEL:
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
				break
			}
			arg.Path.IsWithdraw = true
			fallthrough
		case api.Operation_ADD:
			paths, err = server.Api2PathList(arg.Resource, arg.Name, []*api.Path{arg.Path})
			if err == nil {
				u := uuid.NewV4()
				uuidBytes = u.Bytes()
				paths[0].SetUUID(uuidBytes)
			}
		case api.Operation_DEL_ALL:
			families := server.globalRib.GetRFlist()
			if arg.Family != 0 {
				families = []bgp.RouteFamily{bgp.RouteFamily(arg.Family)}
			}
			for _, path := range server.globalRib.GetPathList(table.GLOBAL_RIB_NAME, families) {
				paths = append(paths, path.Clone(true))
			}
		}
	}
	result := &GrpcResponse{
		ResponseErr: err,
		Data: &api.ModPathResponse{
			Uuid: uuidBytes,
		},
	}
	grpcReq.ResponseCh <- result
	close(grpcReq.ResponseCh)
	return paths
}

func (server *BgpServer) handleModPathsRequest(grpcReq *GrpcRequest) []*table.Path {
	var err error
	var paths []*table.Path
	arg, ok := grpcReq.Data.(*api.ModPathsArguments)
	if !ok {
		err = fmt.Errorf("type assertion failed")
	}
	if err == nil {
		paths, err = server.Api2PathList(arg.Resource, arg.Name, arg.Paths)
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

func (server *BgpServer) handleVrfMod(arg *api.ModVrfArguments) ([]*table.Path, error) {
	rib := server.globalRib
	var msgs []*table.Path
	switch arg.Operation {
	case api.Operation_ADD:
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
		msgs, err = rib.AddVrf(arg.Vrf.Name, rd, importRt, exportRt, pi)
		if err != nil {
			return nil, err
		}
	case api.Operation_DEL:
		var err error
		msgs, err = rib.DeleteVrf(arg.Vrf.Name)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown operation: %d", arg.Operation)
	}
	return msgs, nil
}

func (server *BgpServer) handleVrfRequest(req *GrpcRequest) []*table.Path {
	var msgs []*table.Path
	result := &GrpcResponse{}

	switch req.RequestType {
	case REQ_VRF:
		arg := req.Data.(*api.Table)
		name := arg.Name
		rib := server.globalRib
		vrfs := rib.Vrfs
		if _, ok := vrfs[name]; !ok {
			result.ResponseErr = fmt.Errorf("vrf %s not found", name)
			break
		}
		var rf bgp.RouteFamily
		switch bgp.RouteFamily(arg.Family) {
		case bgp.RF_IPv4_UC:
			rf = bgp.RF_IPv4_VPN
		case bgp.RF_IPv6_UC:
			rf = bgp.RF_IPv6_VPN
		case bgp.RF_EVPN:
			rf = bgp.RF_EVPN
		default:
			result.ResponseErr = fmt.Errorf("unsupported route family: %s", bgp.RouteFamily(arg.Family))
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
			Data: &api.Table{
				Type:         arg.Type,
				Family:       arg.Family,
				Destinations: dsts,
			},
		}
		goto END
	case REQ_VRFS:
		vrfs := server.globalRib.Vrfs
		for _, vrf := range vrfs {
			req.ResponseCh <- &GrpcResponse{
				Data: vrf.ToApiStruct(),
			}
		}
		goto END
	case REQ_VRF_MOD:
		arg := req.Data.(*api.ModVrfArguments)
		msgs, result.ResponseErr = server.handleVrfMod(arg)
	default:
		result.ResponseErr = fmt.Errorf("unknown request type: %d", req.RequestType)
	}

	req.ResponseCh <- result
END:
	close(req.ResponseCh)
	return msgs
}

func (server *BgpServer) handleModConfig(grpcReq *GrpcRequest) error {
	var op api.Operation
	var c *config.Global
	switch arg := grpcReq.Data.(type) {
	case *api.ModGlobalConfigArguments:
		op = arg.Operation
		if op == api.Operation_ADD {
			g := arg.Global
			if net.ParseIP(g.RouterId) == nil {
				return fmt.Errorf("invalid router-id format: %s", g.RouterId)
			}
			families := make([]config.AfiSafi, 0, len(g.Families))
			for _, f := range g.Families {
				name := config.AfiSafiType(bgp.RouteFamily(f).String())
				families = append(families, config.AfiSafi{
					AfiSafiName: name,
					Config: config.AfiSafiConfig{
						AfiSafiName: name,
						Enabled:     true,
					},
					State: config.AfiSafiState{
						AfiSafiName: name,
					},
				})
			}
			b := &config.Bgp{
				Global: config.Global{
					Config: config.GlobalConfig{
						As:       g.As,
						RouterId: g.RouterId,
					},
					ListenConfig: config.ListenConfig{
						Port:             g.ListenPort,
						LocalAddressList: g.ListenAddresses,
					},
					MplsLabelRange: config.MplsLabelRange{
						MinLabel: g.MplsLabelMin,
						MaxLabel: g.MplsLabelMax,
					},
					AfiSafis: families,
					Collector: config.Collector{
						Enabled: g.Collector,
					},
				},
			}
			if err := config.SetDefaultConfigValues(nil, b); err != nil {
				return err
			}
			c = &b.Global
		}
	case *config.Global:
		op = api.Operation_ADD
		c = arg
	}

	switch op {
	case api.Operation_ADD:
		if server.bgpConfig.Global.Config.As != 0 {
			return fmt.Errorf("gobgp is already started")
		}

		if c.ListenConfig.Port > 0 {
			acceptCh := make(chan *net.TCPConn, 4096)
			for _, addr := range c.ListenConfig.LocalAddressList {
				l, err := NewTCPListener(addr, uint32(c.ListenConfig.Port), acceptCh)
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
	case api.Operation_DEL_ALL:
		for k, _ := range server.neighborMap {
			_, err := server.handleGrpcModNeighbor(&GrpcRequest{
				Data: &api.ModNeighborArguments{
					Operation: api.Operation_DEL,
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
	}
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

	sortedDsts := func(id string, t *table.Table) []*api.Destination {
		results := make([]*api.Destination, 0, len(t.GetDestinations()))

		r := radix.New()
		for _, dst := range t.GetDestinations() {
			if d := dst.ToApiStruct(id); d != nil {
				r.Insert(dst.RadixKey, d)
			}
		}
		r.Walk(func(s string, v interface{}) bool {
			results = append(results, v.(*api.Destination))
			return false
		})

		return results
	}

	if server.bgpConfig.Global.Config.As == 0 && grpcReq.RequestType != REQ_MOD_GLOBAL_CONFIG {
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: fmt.Errorf("bgpd main loop is not started yet"),
		}
		close(grpcReq.ResponseCh)
		return nil
	}

	var err error

	switch grpcReq.RequestType {
	case REQ_GLOBAL_CONFIG:
		g := server.bgpConfig.Global
		result := &GrpcResponse{
			Data: &api.Global{
				As:              g.Config.As,
				RouterId:        g.Config.RouterId,
				ListenPort:      g.ListenConfig.Port,
				ListenAddresses: g.ListenConfig.LocalAddressList,
				MplsLabelMin:    g.MplsLabelRange.MinLabel,
				MplsLabelMax:    g.MplsLabelRange.MaxLabel,
				Collector:       g.Collector.Enabled,
			},
		}
		grpcReq.ResponseCh <- result
		close(grpcReq.ResponseCh)
	case REQ_MOD_GLOBAL_CONFIG:
		err := server.handleModConfig(grpcReq)
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
		}
		close(grpcReq.ResponseCh)
	case REQ_GLOBAL_RIB, REQ_LOCAL_RIB:
		arg := grpcReq.Data.(*api.Table)
		d := &api.Table{
			Type:   arg.Type,
			Family: arg.Family,
		}
		rib := server.globalRib
		id := table.GLOBAL_RIB_NAME
		if grpcReq.RequestType == REQ_LOCAL_RIB {
			peer, ok := server.neighborMap[arg.Name]
			if !ok {
				err = fmt.Errorf("Neighbor that has %v doesn't exist.", arg.Name)
				goto ERROR
			}
			if !peer.isRouteServerClient() {
				err = fmt.Errorf("Neighbor %v doesn't have local rib", arg.Name)
				goto ERROR
			}
			id = peer.ID()
		}
		af := bgp.RouteFamily(arg.Family)
		if _, ok := rib.Tables[af]; !ok {
			err = fmt.Errorf("address family: %s not supported", af)
			goto ERROR
		}

		switch af {
		case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
			if len(arg.Destinations) > 0 {
				dsts := []*api.Destination{}
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
				for _, dst := range arg.Destinations {
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
				d.Destinations = dsts
			} else {
				d.Destinations = sortedDsts(id, rib.Tables[af])
			}
		default:
			d.Destinations = make([]*api.Destination, 0, len(rib.Tables[af].GetDestinations()))
			for _, dst := range rib.Tables[af].GetDestinations() {
				if s := dst.ToApiStruct(id); s != nil {
					d.Destinations = append(d.Destinations, s)
				}
			}
		}
		grpcReq.ResponseCh <- &GrpcResponse{
			Data: d,
		}
		close(grpcReq.ResponseCh)
	case REQ_BMP_GLOBAL:
		paths := server.globalRib.GetBestPathList(table.GLOBAL_RIB_NAME, server.globalRib.GetRFlist())
		bmpmsgs := make([]*bgp.BMPMessage, 0, len(paths))
		for _, path := range paths {
			msgs := table.CreateUpdateMsgFromPaths([]*table.Path{path})
			buf, _ := msgs[0].Serialize()
			bmpmsgs = append(bmpmsgs, bmpPeerRoute(bgp.BMP_PEER_TYPE_GLOBAL, true, 0, path.GetSource(), path.GetTimestamp().Unix(), buf))
		}
		grpcReq.ResponseCh <- &GrpcResponse{
			Data: bmpmsgs,
		}
		close(grpcReq.ResponseCh)
	case REQ_MOD_PATH:
		pathList := server.handleModPathRequest(grpcReq)
		if len(pathList) > 0 {
			msgs, _ = server.propagateUpdate(nil, pathList)
		}
	case REQ_MOD_PATHS:
		pathList := server.handleModPathsRequest(grpcReq)
		if len(pathList) > 0 {
			msgs, _ = server.propagateUpdate(nil, pathList)
			grpcReq.ResponseCh <- &GrpcResponse{}
			close(grpcReq.ResponseCh)
		}
	case REQ_NEIGHBORS:
		results := make([]*GrpcResponse, len(server.neighborMap))
		i := 0
		for _, peer := range server.neighborMap {
			result := &GrpcResponse{
				Data: peer.ToApiStruct(),
			}
			results[i] = result
			i++
		}
		go sendMultipleResponses(grpcReq, results)
	case REQ_BMP_NEIGHBORS:
		//TODO: merge REQ_NEIGHBORS and REQ_BMP_NEIGHBORS
		msgs := make([]*bgp.BMPMessage, 0, len(server.neighborMap))
		for _, peer := range server.neighborMap {
			if peer.fsm.state != bgp.BGP_FSM_ESTABLISHED {
				continue
			}
			laddr, lport := peer.fsm.LocalHostPort()
			_, rport := peer.fsm.RemoteHostPort()
			sentOpen := buildopen(peer.fsm.gConf, peer.fsm.pConf)
			info := peer.fsm.peerInfo
			timestamp := peer.conf.Timers.State.Uptime
			msg := bmpPeerUp(laddr, lport, rport, sentOpen, peer.fsm.recvOpen, bgp.BMP_PEER_TYPE_GLOBAL, false, 0, info, timestamp)
			msgs = append(msgs, msg)
		}
		grpcReq.ResponseCh <- &GrpcResponse{
			Data: msgs,
		}
		close(grpcReq.ResponseCh)
	case REQ_NEIGHBOR:
		peer, err := server.checkNeighborRequest(grpcReq)
		if err != nil {
			break
		}
		result := &GrpcResponse{
			Data: peer.ToApiStruct(),
		}
		grpcReq.ResponseCh <- result
		close(grpcReq.ResponseCh)

	case REQ_ADJ_RIB_IN, REQ_ADJ_RIB_OUT:
		arg := grpcReq.Data.(*api.Table)
		d := &api.Table{
			Type:   arg.Type,
			Family: arg.Family,
		}

		peer, ok := server.neighborMap[arg.Name]
		if !ok {
			err = fmt.Errorf("Neighbor that has %v doesn't exist.", arg.Name)
			goto ERROR
		}

		rf := bgp.RouteFamily(arg.Family)
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
				for _, dst := range arg.Destinations {
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
			Data: d,
		}
		close(grpcReq.ResponseCh)
	case REQ_BMP_ADJ_IN:
		bmpmsgs := make([]*bgp.BMPMessage, 0)
		for _, peer := range server.neighborMap {
			if peer.fsm.state != bgp.BGP_FSM_ESTABLISHED {
				continue
			}
			for _, path := range peer.adjRibIn.PathList(peer.configuredRFlist(), false) {
				msgs := table.CreateUpdateMsgFromPaths([]*table.Path{path})
				buf, _ := msgs[0].Serialize()
				bmpmsgs = append(bmpmsgs, bmpPeerRoute(bgp.BMP_PEER_TYPE_GLOBAL, false, 0, peer.fsm.peerInfo, path.GetTimestamp().Unix(), buf))
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
			msgs = append(msgs, newSenderMsg(peer, []*bgp.BGPMessage{m}))
		}
		grpcReq.ResponseCh <- &GrpcResponse{}
		close(grpcReq.ResponseCh)

	case REQ_NEIGHBOR_RESET:
		peers, err := reqToPeers(grpcReq)
		if err != nil {
			break
		}
		logOp(grpcReq.Name, "Neighbor reset")
		for _, peer := range peers {
			peer.fsm.idleHoldTime = peer.conf.Timers.Config.IdleHoldTimeAfterReset
			m := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET, nil)
			msgs = append(msgs, newSenderMsg(peer, []*bgp.BGPMessage{m}))
		}
		grpcReq.ResponseCh <- &GrpcResponse{}
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
			grpcReq.ResponseCh <- &GrpcResponse{}
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

			if grpcReq.RequestType == REQ_DEFERRAL_TIMER_EXPIRED {
				if peer.fsm.pConf.GracefulRestart.State.LocalRestarting {
					peer.fsm.pConf.GracefulRestart.State.LocalRestarting = false
					log.WithFields(log.Fields{
						"Topic": "Peer",
						"Key":   peer.conf.Config.NeighborAddress,
					}).Debug("deferral timer expired")
				} else {
					continue
				}
			}

			families := []bgp.RouteFamily{grpcReq.RouteFamily}
			if families[0] == bgp.RouteFamily(0) {
				families = peer.configuredRFlist()
			}
			sentPathList := peer.adjRibOut.PathList(families, false)
			peer.adjRibOut.Drop(families)
			pathList, filtered := peer.getBestFromLocal(families)
			if len(pathList) > 0 {
				peer.adjRibOut.Update(pathList)
				msgs = append(msgs, newSenderMsg(peer, table.CreateUpdateMsgFromPaths(pathList)))
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
				msgs = append(msgs, newSenderMsg(peer, table.CreateUpdateMsgFromPaths(withdrawnList)))
			}
		}
		grpcReq.ResponseCh <- &GrpcResponse{}
		close(grpcReq.ResponseCh)

	case REQ_NEIGHBOR_ENABLE, REQ_NEIGHBOR_DISABLE:
		peer, err1 := server.checkNeighborRequest(grpcReq)
		if err1 != nil {
			break
		}
		var err api.Error
		result := &GrpcResponse{}
		if grpcReq.RequestType == REQ_NEIGHBOR_ENABLE {
			select {
			case peer.fsm.adminStateCh <- ADMIN_STATE_UP:
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   peer.conf.Config.NeighborAddress,
				}).Debug("ADMIN_STATE_UP requested")
				err.Code = api.Error_SUCCESS
				err.Msg = "ADMIN_STATE_UP"
			default:
				log.Warning("previous request is still remaining. : ", peer.conf.Config.NeighborAddress)
				err.Code = api.Error_FAIL
				err.Msg = "previous request is still remaining"
			}
		} else {
			select {
			case peer.fsm.adminStateCh <- ADMIN_STATE_DOWN:
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   peer.conf.Config.NeighborAddress,
				}).Debug("ADMIN_STATE_DOWN requested")
				err.Code = api.Error_SUCCESS
				err.Msg = "ADMIN_STATE_DOWN"
			default:
				log.Warning("previous request is still remaining. : ", peer.conf.Config.NeighborAddress)
				err.Code = api.Error_FAIL
				err.Msg = "previous request is still remaining"
			}
		}
		result.Data = err
		grpcReq.ResponseCh <- result
		close(grpcReq.ResponseCh)
	case REQ_MOD_NEIGHBOR:
		m, err := server.handleGrpcModNeighbor(grpcReq)
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
		}
		if len(m) > 0 {
			msgs = append(msgs, m...)
		}
		close(grpcReq.ResponseCh)
	case REQ_DEFINED_SET:
		if err := server.handleGrpcGetDefinedSet(grpcReq); err != nil {
			grpcReq.ResponseCh <- &GrpcResponse{
				ResponseErr: err,
			}
		}
		close(grpcReq.ResponseCh)
	case REQ_MOD_DEFINED_SET:
		err := server.handleGrpcModDefinedSet(grpcReq)
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
		}
		close(grpcReq.ResponseCh)
	case REQ_STATEMENT:
		if err := server.handleGrpcGetStatement(grpcReq); err != nil {
			grpcReq.ResponseCh <- &GrpcResponse{
				ResponseErr: err,
			}
		}
		close(grpcReq.ResponseCh)
	case REQ_MOD_STATEMENT:
		err := server.handleGrpcModStatement(grpcReq)
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
		}
		close(grpcReq.ResponseCh)
	case REQ_POLICY:
		if err := server.handleGrpcGetPolicy(grpcReq); err != nil {
			grpcReq.ResponseCh <- &GrpcResponse{
				ResponseErr: err,
			}
		}
		close(grpcReq.ResponseCh)
	case REQ_MOD_POLICY:
		err := server.handleGrpcModPolicy(grpcReq)
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
		}
		close(grpcReq.ResponseCh)
	case REQ_POLICY_ASSIGNMENT:
		if err := server.handleGrpcGetPolicyAssignment(grpcReq); err != nil {
			grpcReq.ResponseCh <- &GrpcResponse{
				ResponseErr: err,
			}
		}
		close(grpcReq.ResponseCh)
	case REQ_MOD_POLICY_ASSIGNMENT:
		err := server.handleGrpcModPolicyAssignment(grpcReq)
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: err,
		}
		close(grpcReq.ResponseCh)
	case REQ_MONITOR_GLOBAL_BEST_CHANGED, REQ_MONITOR_NEIGHBOR_PEER_STATE, REQ_MONITOR_ROA_VALIDATION_RESULT:
		server.broadcastReqs = append(server.broadcastReqs, grpcReq)
	case REQ_MONITOR_INCOMING:
		if grpcReq.Name != "" {
			if _, err = server.checkNeighborRequest(grpcReq); err != nil {
				break
			}
		}
		w := server.watchers[WATCHER_GRPC_INCOMING]
		go w.(*grpcIncomingWatcher).addRequest(grpcReq)
	case REQ_MRT_GLOBAL_RIB, REQ_MRT_LOCAL_RIB:
		server.handleMrt(grpcReq)
	case REQ_MOD_MRT:
		server.handleModMrt(grpcReq)
	case REQ_MOD_BMP:
		server.handleModBmp(grpcReq)
	case REQ_MOD_RPKI:
		server.handleModRpki(grpcReq)
	case REQ_ROA, REQ_RPKI:
		server.roaManager.handleGRPC(grpcReq)
	case REQ_VRF, REQ_VRFS, REQ_VRF_MOD:
		pathList := server.handleVrfRequest(grpcReq)
		if len(pathList) > 0 {
			msgs, _ = server.propagateUpdate(nil, pathList)
		}
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

func (server *BgpServer) handleGrpcGetDefinedSet(grpcReq *GrpcRequest) error {
	arg := grpcReq.Data.(*api.DefinedSet)
	typ := table.DefinedType(arg.Type)
	name := arg.Name
	set, ok := server.policy.DefinedSetMap[typ]
	if !ok {
		return fmt.Errorf("invalid defined-set type: %d", typ)
	}
	found := false
	for _, s := range set {
		if name != "" && name != s.Name() {
			continue
		}
		grpcReq.ResponseCh <- &GrpcResponse{
			Data: s.ToApiStruct(),
		}
		found = true
		if name != "" {
			break
		}
	}
	if !found {
		return fmt.Errorf("not found %s", name)
	}
	return nil
}
func (server *BgpServer) handleGrpcModNeighbor(grpcReq *GrpcRequest) (sMsgs []*SenderMsg, err error) {
	arg := grpcReq.Data.(*api.ModNeighborArguments)
	addr := arg.Peer.Conf.NeighborAddress
	n, ok := server.neighborMap[addr]
	if arg.Operation != api.Operation_ADD && !ok {
		return nil, fmt.Errorf("not found neighbor %s", addr)
	}

	switch arg.Operation {
	case api.Operation_ADD:
		if ok {
			return nil, fmt.Errorf("Can't overwrite the exising peer %s", addr)
		} else {
			log.Infof("Peer %s is added", addr)
		}
		if server.bgpConfig.Global.ListenConfig.Port > 0 {
			for _, l := range server.Listeners(addr) {
				SetTcpMD5SigSockopts(l, addr, arg.Peer.Conf.AuthPassword)
			}
		}
		apitoConfig := func(a *api.Peer) (config.Neighbor, error) {
			var pconf config.Neighbor
			if a.Conf != nil {
				pconf.NeighborAddress = a.Conf.NeighborAddress
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
					cAfiSafi := config.AfiSafi{AfiSafiName: config.AfiSafiType(name)}
					pconf.AfiSafis = append(pconf.AfiSafis, cAfiSafi)
				}
			} else {
				if net.ParseIP(a.Conf.NeighborAddress).To4() != nil {
					pconf.AfiSafis = []config.AfiSafi{
						config.AfiSafi{AfiSafiName: "ipv4-unicast"}}
				} else {
					pconf.AfiSafis = []config.AfiSafi{
						config.AfiSafi{AfiSafiName: "ipv6-unicast"}}
				}
			}
			if a.Transport != nil {
				pconf.Transport.Config.LocalAddress = a.Transport.LocalAddress
				pconf.Transport.Config.PassiveMode = a.Transport.PassiveMode
			}
			if a.EbgpMultihop != nil {
				pconf.EbgpMultihop.Config.Enabled = a.EbgpMultihop.Enabled
				pconf.EbgpMultihop.Config.MultihopTtl = uint8(a.EbgpMultihop.MultihopTtl)
			}
			return pconf, nil
		}
		configneigh, err := apitoConfig(arg.Peer)
		if err != nil {
			return nil, err
		}
		peer := NewPeer(server.bgpConfig.Global, configneigh, server.globalRib, server.policy)
		server.setPolicyByConfig(peer.ID(), configneigh.ApplyPolicy)
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
	case api.Operation_DEL:
		for _, l := range server.Listeners(addr) {
			SetTcpMD5SigSockopts(l, addr, "")
		}
		log.Info("Delete a peer configuration for ", addr)
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
		m := server.dropPeerAllRoutes(n, n.configuredRFlist())
		if len(m) > 0 {
			sMsgs = append(sMsgs, m...)
		}
		delete(server.neighborMap, addr)
	}
	return sMsgs, err
}

func (server *BgpServer) handleGrpcModDefinedSet(grpcReq *GrpcRequest) error {
	arg := grpcReq.Data.(*api.ModDefinedSetArguments)
	set := arg.Set
	typ := table.DefinedType(set.Type)
	name := set.Name
	var err error
	m, ok := server.policy.DefinedSetMap[typ]
	if !ok {
		return fmt.Errorf("invalid defined-set type: %d", typ)
	}
	d, ok := m[name]
	if arg.Operation != api.Operation_ADD && !ok {
		return fmt.Errorf("not found defined-set: %s", name)
	}
	s, err := table.NewDefinedSetFromApiStruct(set)
	if err != nil {
		return err
	}
	switch arg.Operation {
	case api.Operation_ADD:
		if ok {
			err = d.Append(s)
		} else {
			m[name] = s
		}
	case api.Operation_DEL:
		err = d.Remove(s)
	case api.Operation_DEL_ALL:
		if server.policy.InUse(d) {
			return fmt.Errorf("can't delete. defined-set %s is in use", name)
		}
		delete(m, name)
	case api.Operation_REPLACE:
		err = d.Replace(s)
	}
	return err
}

func (server *BgpServer) handleGrpcGetStatement(grpcReq *GrpcRequest) error {
	arg := grpcReq.Data.(*api.Statement)
	name := arg.Name
	found := false
	for _, s := range server.policy.StatementMap {
		if name != "" && name != s.Name {
			continue
		}
		grpcReq.ResponseCh <- &GrpcResponse{
			Data: s.ToApiStruct(),
		}
		found = true
		if name != "" {
			break
		}
	}
	if !found {
		return fmt.Errorf("not found %s", name)
	}
	return nil
}

func (server *BgpServer) handleGrpcModStatement(grpcReq *GrpcRequest) error {
	arg := grpcReq.Data.(*api.ModStatementArguments)
	s, err := table.NewStatementFromApiStruct(arg.Statement, server.policy.DefinedSetMap)
	if err != nil {
		return err
	}
	m := server.policy.StatementMap
	name := s.Name
	d, ok := m[name]
	if arg.Operation != api.Operation_ADD && !ok {
		return fmt.Errorf("not found statement: %s", name)
	}
	switch arg.Operation {
	case api.Operation_ADD:
		if ok {
			err = d.Add(s)
		} else {
			m[name] = s
		}
	case api.Operation_DEL:
		err = d.Remove(s)
	case api.Operation_DEL_ALL:
		if server.policy.StatementInUse(d) {
			return fmt.Errorf("can't delete. statement %s is in use", name)
		}
		delete(m, name)
	case api.Operation_REPLACE:
		err = d.Replace(s)
	}
	return err

}

func (server *BgpServer) handleGrpcGetPolicy(grpcReq *GrpcRequest) error {
	arg := grpcReq.Data.(*api.Policy)
	name := arg.Name
	found := false
	for _, s := range server.policy.PolicyMap {
		if name != "" && name != s.Name() {
			continue
		}
		grpcReq.ResponseCh <- &GrpcResponse{
			Data: s.ToApiStruct(),
		}
		found = true
		if name != "" {
			break
		}
	}
	if !found {
		return fmt.Errorf("not found %s", name)
	}
	return nil
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

func (server *BgpServer) handleGrpcModPolicy(grpcReq *GrpcRequest) error {
	policyMutex.Lock()
	defer policyMutex.Unlock()
	arg := grpcReq.Data.(*api.ModPolicyArguments)
	x, err := table.NewPolicyFromApiStruct(arg.Policy, server.policy.DefinedSetMap)
	if err != nil {
		return err
	}
	pMap := server.policy.PolicyMap
	sMap := server.policy.StatementMap
	name := x.Name()
	y, ok := pMap[name]
	if arg.Operation != api.Operation_ADD && !ok {
		return fmt.Errorf("not found policy: %s", name)
	}
	switch arg.Operation {
	case api.Operation_ADD, api.Operation_REPLACE:
		if arg.ReferExistingStatements {
			err = x.FillUp(sMap)
			if err != nil {
				return err
			}
		} else {
			for _, s := range x.Statements {
				if _, ok := sMap[s.Name]; ok {
					return fmt.Errorf("statement %s already defined", s.Name)
				}
				sMap[s.Name] = s
			}
		}
		if arg.Operation == api.Operation_REPLACE {
			err = y.Replace(x)
		} else if ok {
			err = y.Add(x)
		} else {
			pMap[name] = x
		}
	case api.Operation_DEL:
		err = y.Remove(x)
	case api.Operation_DEL_ALL:
		if server.policyInUse(y) {
			return fmt.Errorf("can't delete. policy %s is in use", name)
		}
		log.WithFields(log.Fields{
			"Topic": "Policy",
			"Key":   name,
		}).Debug("delete policy")
		delete(pMap, name)
	}
	if err == nil && arg.Operation != api.Operation_ADD && !arg.PreserveStatements {
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
	return err
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

func (server *BgpServer) handleGrpcGetPolicyAssignment(grpcReq *GrpcRequest) error {
	arg := grpcReq.Data.(*api.PolicyAssignment)
	id, dir, err := server.getPolicyInfo(arg)
	if err != nil {
		return err
	}
	arg.Default = server.policy.GetDefaultPolicy(id, dir).ToApiStruct()
	ps := server.policy.GetPolicy(id, dir)
	arg.Policies = make([]*api.Policy, 0, len(ps))
	for _, x := range ps {
		arg.Policies = append(arg.Policies, x.ToApiStruct())
	}
	grpcReq.ResponseCh <- &GrpcResponse{
		Data: arg,
	}
	return nil
}

func (server *BgpServer) handleGrpcModPolicyAssignment(grpcReq *GrpcRequest) error {
	var err error
	var dir table.PolicyDirection
	var id string
	policyMutex.Lock()
	defer policyMutex.Unlock()
	arg := grpcReq.Data.(*api.ModPolicyAssignmentArguments)
	assignment := arg.Assignment
	id, dir, err = server.getPolicyInfo(assignment)
	if err != nil {
		return err
	}
	ps := make([]*table.Policy, 0, len(assignment.Policies))
	for _, x := range assignment.Policies {
		p, ok := server.policy.PolicyMap[x.Name]
		if !ok {
			return fmt.Errorf("not found policy %s", x.Name)
		}
		ps = append(ps, p)
	}
	cur := server.policy.GetPolicy(id, dir)
	switch arg.Operation {
	case api.Operation_ADD, api.Operation_REPLACE:
		if arg.Operation == api.Operation_REPLACE || cur == nil {
			err = server.policy.SetPolicy(id, dir, ps)
		} else {
			err = server.policy.SetPolicy(id, dir, append(cur, ps...))
		}
		if err != nil {
			return err
		}
		switch assignment.Default {
		case api.RouteAction_ACCEPT:
			err = server.policy.SetDefaultPolicy(id, dir, table.ROUTE_TYPE_ACCEPT)
		case api.RouteAction_REJECT:
			err = server.policy.SetDefaultPolicy(id, dir, table.ROUTE_TYPE_REJECT)
		}
	case api.Operation_DEL:
		n := make([]*table.Policy, 0, len(cur)-len(ps))
		for _, x := range ps {
			found := false
			for _, y := range cur {
				if x.Name() == y.Name() {
					found = true
					break
				}
			}
			if !found {
				n = append(n, x)
			}
		}
		err = server.policy.SetPolicy(id, dir, n)
	case api.Operation_DEL_ALL:
		err = server.policy.SetPolicy(id, dir, nil)
		if err != nil {
			return err
		}
		err = server.policy.SetDefaultPolicy(id, dir, table.ROUTE_TYPE_NONE)
	}
	return err
}

func grpcDone(grpcReq *GrpcRequest, e error) {
	result := &GrpcResponse{
		ResponseErr: e,
	}
	grpcReq.ResponseCh <- result
	close(grpcReq.ResponseCh)
}

func (server *BgpServer) handleModMrt(grpcReq *GrpcRequest) {
	arg := grpcReq.Data.(*api.ModMrtArguments)
	w, y := server.watchers[WATCHER_MRT]
	if arg.Operation == api.Operation_ADD {
		if y {
			grpcDone(grpcReq, fmt.Errorf("already enabled"))
			return
		}
	} else {
		if !y {
			grpcDone(grpcReq, fmt.Errorf("not enabled yet"))
			return
		}
	}
	switch arg.Operation {
	case api.Operation_ADD:
		if arg.Interval != 0 && arg.Interval < 30 {
			log.Info("minimum mrt dump interval is 30 seconds")
			arg.Interval = 30
		}
		w, err := newMrtWatcher(arg.DumpType, arg.Filename, arg.Interval)
		if err == nil {
			server.watchers[WATCHER_MRT] = w
		}
		grpcDone(grpcReq, err)
	case api.Operation_DEL:
		delete(server.watchers, WATCHER_MRT)
		w.stop()
		grpcDone(grpcReq, nil)
	}
}

func (server *BgpServer) handleModBmp(grpcReq *GrpcRequest) {
	var op api.Operation
	var c *config.BmpServerConfig
	switch arg := grpcReq.Data.(type) {
	case *api.ModBmpArguments:
		c = &config.BmpServerConfig{
			Address: arg.Address,
			Port:    arg.Port,
			RouteMonitoringPolicy: config.BmpRouteMonitoringPolicyType(arg.Type),
		}
		op = arg.Operation
	case *config.BmpServerConfig:
		c = arg
		op = api.Operation_ADD
	}

	w, y := server.watchers[WATCHER_BMP]
	if !y {
		if op == api.Operation_ADD {
			w, _ = newBmpWatcher(server.GrpcReqCh)
			server.watchers[WATCHER_BMP] = w
		} else if op == api.Operation_DEL {
			grpcDone(grpcReq, fmt.Errorf("not enabled yet"))
			return
		}
	}

	switch op {
	case api.Operation_ADD:
		err := w.(*bmpWatcher).addServer(*c)
		grpcDone(grpcReq, err)
	case api.Operation_DEL:
		err := w.(*bmpWatcher).deleteServer(*c)
		grpcDone(grpcReq, err)
	default:
		grpcDone(grpcReq, fmt.Errorf("unsupported operation: %s", op))
	}
}

func (server *BgpServer) handleModRpki(grpcReq *GrpcRequest) {
	arg := grpcReq.Data.(*api.ModRpkiArguments)

	switch arg.Operation {
	case api.Operation_ADD:
		r := config.RpkiServer{}
		r.Config.Address = arg.Address
		r.Config.Port = arg.Port
		server.bgpConfig.RpkiServers = append(server.bgpConfig.RpkiServers, r)
		server.roaManager, _ = NewROAManager(server.bgpConfig.Global.Config.As, server.bgpConfig.RpkiServers)
		grpcDone(grpcReq, nil)
		return
	case api.Operation_ENABLE, api.Operation_DISABLE, api.Operation_RESET, api.Operation_SOFTRESET:
		grpcDone(grpcReq, server.roaManager.operate(arg.Operation, arg.Address))
		return
	case api.Operation_REPLACE:
		isMonitored := server.isRpkiMonitored()
		for _, rf := range server.globalRib.GetRFlist() {
			if t, ok := server.globalRib.Tables[rf]; ok {
				for _, dst := range t.GetDestinations() {
					if rr := server.roaManager.validate(dst.GetAllKnownPathList(), isMonitored); isMonitored {
						send := make([]*api.ROAResult, 0, len(rr))
						for _, r := range rr {
							invalid := api.ROAResult_ValidationResult(config.RPKI_VALIDATION_RESULT_TYPE_INVALID.ToInt())

							if r.OldResult != r.NewResult && (r.OldResult == invalid || r.NewResult == invalid) {
								r.Reason = api.ROAResult_REVALIDATE
								send = append(send, r)
							}
						}
						server.broadcastValidationResults(send)
					}
				}
			}
		}
		grpcDone(grpcReq, nil)
		return
	}
	grpcDone(grpcReq, fmt.Errorf("not supported yet"))
}

func (server *BgpServer) handleMrt(grpcReq *GrpcRequest) {
	now := uint32(time.Now().Unix())
	view := ""
	result := &GrpcResponse{}
	var rib *table.TableManager

	switch grpcReq.RequestType {
	case REQ_MRT_GLOBAL_RIB:
		rib = server.globalRib
	case REQ_MRT_LOCAL_RIB:
		peer, err := server.checkNeighborRequest(grpcReq)
		if err != nil {
			return
		}
		rib = peer.localRib
		if rib == nil {
			result.ResponseErr = fmt.Errorf("no local rib for %s", grpcReq.Name)
			grpcReq.ResponseCh <- result
			close(grpcReq.ResponseCh)
			return
		}
		view = grpcReq.Name
	}

	msg, err := server.mkMrtPeerIndexTableMsg(now, view)
	if err != nil {
		result.ResponseErr = fmt.Errorf("failed to make new mrt peer index table message: %s", err)
		grpcReq.ResponseCh <- result
		close(grpcReq.ResponseCh)
		return
	}
	data, err := msg.Serialize()
	if err != nil {
		result.ResponseErr = fmt.Errorf("failed to serialize table: %s", err)
		grpcReq.ResponseCh <- result
		close(grpcReq.ResponseCh)
		return
	}

	tbl, ok := rib.Tables[grpcReq.RouteFamily]
	if !ok {
		result.ResponseErr = fmt.Errorf("unsupported route family: %s", grpcReq.RouteFamily)
		grpcReq.ResponseCh <- result
		close(grpcReq.ResponseCh)
		return
	}

	msgs, err := server.mkMrtRibMsgs(tbl, now)
	if err != nil {
		result.ResponseErr = fmt.Errorf("failed to make new mrt rib message: %s", err)
		grpcReq.ResponseCh <- result
		close(grpcReq.ResponseCh)
		return
	}
	for _, msg := range msgs {
		d, err := msg.Serialize()
		if err != nil {
			result.ResponseErr = fmt.Errorf("failed to serialize rib msg: %s", err)
			grpcReq.ResponseCh <- result
			close(grpcReq.ResponseCh)
			return
		}
		data = append(data, d...)
	}

	result.Data = &api.MrtMessage{
		Data: data,
	}

	select {
	case <-grpcReq.EndCh:
		return
	default:
	}

	m := &broadcastGrpcMsg{
		req:    grpcReq,
		result: result,
	}

	interval := int64(grpcReq.Data.(uint64))
	if interval > 0 {
		go func() {
			t := time.NewTimer(time.Second * time.Duration(interval))
			<-t.C
			server.GrpcReqCh <- grpcReq
		}()
	} else {
		m.done = true
	}
	server.broadcastMsgs = append(server.broadcastMsgs, m)

	return
}

func (server *BgpServer) mkMrtPeerIndexTableMsg(t uint32, view string) (*bgp.MRTMessage, error) {
	peers := make([]*bgp.Peer, 0, len(server.neighborMap))
	for _, peer := range server.neighborMap {
		id := peer.fsm.peerInfo.ID.To4().String()
		ipaddr := peer.conf.Config.NeighborAddress
		asn := peer.conf.Config.PeerAs
		peers = append(peers, bgp.NewPeer(id, ipaddr, asn, true))
	}
	bgpid := server.bgpConfig.Global.Config.RouterId
	table := bgp.NewPeerIndexTable(bgpid, view, peers)
	return bgp.NewMRTMessage(t, bgp.TABLE_DUMPv2, bgp.PEER_INDEX_TABLE, table)
}

func (server *BgpServer) mkMrtRibMsgs(tbl *table.Table, t uint32) ([]*bgp.MRTMessage, error) {
	getPeerIndex := func(info *table.PeerInfo) uint16 {
		var idx uint16
		for _, peer := range server.neighborMap {
			if peer.fsm.peerInfo.Equal(info) {
				return idx
			}
			idx++
		}
		return idx
	}

	var subtype bgp.MRTSubTypeTableDumpv2

	switch tbl.GetRoutefamily() {
	case bgp.RF_IPv4_UC:
		subtype = bgp.RIB_IPV4_UNICAST
	case bgp.RF_IPv4_MC:
		subtype = bgp.RIB_IPV4_MULTICAST
	case bgp.RF_IPv6_UC:
		subtype = bgp.RIB_IPV6_UNICAST
	case bgp.RF_IPv6_MC:
		subtype = bgp.RIB_IPV6_MULTICAST
	default:
		subtype = bgp.RIB_GENERIC
	}

	var seq uint32
	msgs := make([]*bgp.MRTMessage, 0, len(tbl.GetDestinations()))
	for _, dst := range tbl.GetDestinations() {
		l := dst.GetKnownPathList(table.GLOBAL_RIB_NAME)
		entries := make([]*bgp.RibEntry, 0, len(l))
		for _, p := range l {
			// mrt doesn't assume to dump locally generated routes
			if p.IsLocal() {
				continue
			}
			idx := getPeerIndex(p.GetSource())
			e := bgp.NewRibEntry(idx, uint32(p.GetTimestamp().Unix()), p.GetPathAttrs())
			entries = append(entries, e)
		}
		// if dst only contains locally generated routes, ignore it
		if len(entries) == 0 {
			continue
		}
		rib := bgp.NewRib(seq, dst.GetNlri(), entries)
		seq++
		msg, err := bgp.NewMRTMessage(t, bgp.TABLE_DUMPv2, subtype, rib)
		if err != nil {
			return nil, err
		}
		msgs = append(msgs, msg)
	}
	return msgs, nil
}
