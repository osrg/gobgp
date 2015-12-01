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
	"github.com/BurntSushi/toml"
	log "github.com/Sirupsen/logrus"
	"github.com/armon/go-radix"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/table"
	"github.com/osrg/gobgp/zebra"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	GLOBAL_RIB_NAME = "global"
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

type BgpServer struct {
	bgpConfig     config.Bgp
	globalTypeCh  chan config.Global
	addedPeerCh   chan config.Neighbor
	deletedPeerCh chan config.Neighbor
	updatedPeerCh chan config.Neighbor
	fsmincomingCh chan *FsmMsg
	rpkiConfigCh  chan config.RpkiServers
	bmpConfigCh   chan config.BmpServers

	GrpcReqCh      chan *GrpcRequest
	listenPort     int
	policyUpdateCh chan config.RoutingPolicy
	policy         *table.RoutingPolicy
	broadcastReqs  []*GrpcRequest
	broadcastMsgs  []broadcastMsg
	listenerMap    map[string]*net.TCPListener
	neighborMap    map[string]*Peer
	globalRib      *table.TableManager
	zclient        *zebra.Client
	roaClient      *roaClient
	bmpClient      *bmpClient
	bmpConnCh      chan *bmpConn
	shutdown       bool
	watchers       map[watcherType]watcher
}

func NewBgpServer(port int) *BgpServer {
	b := BgpServer{}
	b.globalTypeCh = make(chan config.Global)
	b.addedPeerCh = make(chan config.Neighbor)
	b.deletedPeerCh = make(chan config.Neighbor)
	b.updatedPeerCh = make(chan config.Neighbor)
	b.rpkiConfigCh = make(chan config.RpkiServers)
	b.bmpConfigCh = make(chan config.BmpServers)
	b.bmpConnCh = make(chan *bmpConn)
	b.GrpcReqCh = make(chan *GrpcRequest, 1)
	b.policyUpdateCh = make(chan config.RoutingPolicy)
	b.neighborMap = make(map[string]*Peer)
	b.listenPort = port
	b.watchers = make(map[watcherType]watcher)
	b.roaClient, _ = newROAClient(0, config.RpkiServers{})
	return &b
}

// avoid mapped IPv6 address
func listenAndAccept(proto string, port int, ch chan *net.TCPConn) (*net.TCPListener, error) {
	service := ":" + strconv.Itoa(port)
	addr, _ := net.ResolveTCPAddr(proto, service)

	l, err := net.ListenTCP(proto, addr)
	if err != nil {
		log.Info(err)
		return nil, err
	}
	go func() {
		for {
			conn, err := l.AcceptTCP()
			if err != nil {
				log.Info(err)
				continue
			}
			ch <- conn
		}
	}()

	return l, nil
}

func (server *BgpServer) Serve() {
	var g config.Global
	for {
		select {
		case grpcReq := <-server.GrpcReqCh:
			server.handleGrpc(grpcReq)
		case g = <-server.globalTypeCh:
			server.bgpConfig.Global = g
			server.globalTypeCh = nil
		}
		if server.globalTypeCh == nil {
			break
		}
	}

	if g.Mrt.FileName != "" {
		w, err := newMrtWatcher(g.Mrt.FileName)
		if err != nil {
			log.Warn(err)
		} else {
			server.watchers[WATCHER_MRT] = w
		}
	}

	if g.Zebra.Enabled == true {
		if g.Zebra.Url == "" {
			g.Zebra.Url = "unix:/var/run/quagga/zserv.api"
		}
		redists := make([]string, 0, len(g.Zebra.RedistributeRouteTypeList))
		for _, t := range g.Zebra.RedistributeRouteTypeList {
			redists = append(redists, t.RouteType)
		}
		err := server.NewZclient(g.Zebra.Url, redists)
		if err != nil {
			log.Error(err)
		}
	}

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

	toRFlist := func(l []config.AfiSafi) []bgp.RouteFamily {
		rfList := []bgp.RouteFamily{}
		for _, rf := range l {
			k, _ := bgp.GetRouteFamily(rf.AfiSafiName)
			rfList = append(rfList, k)
		}
		return rfList
	}
	server.globalRib = table.NewTableManager(GLOBAL_RIB_NAME, toRFlist(g.AfiSafis.AfiSafiList), g.MplsLabelRange.MinLabel, g.MplsLabelRange.MaxLabel)
	server.listenerMap = make(map[string]*net.TCPListener)
	acceptCh := make(chan *net.TCPConn)
	l4, err1 := listenAndAccept("tcp4", server.listenPort, acceptCh)
	server.listenerMap["tcp4"] = l4
	l6, err2 := listenAndAccept("tcp6", server.listenPort, acceptCh)
	server.listenerMap["tcp6"] = l6
	if err1 != nil && err2 != nil {
		log.Fatal("can't listen either v4 and v6")
		os.Exit(1)
	}

	listener := func(addr net.IP) *net.TCPListener {
		var l *net.TCPListener
		if addr.To4() != nil {
			l = server.listenerMap["tcp4"]
		} else {
			l = server.listenerMap["tcp6"]
		}
		return l
	}

	server.fsmincomingCh = make(chan *FsmMsg, 4096)
	var senderMsgs []*SenderMsg

	var zapiMsgCh chan *zebra.Message
	if server.zclient != nil {
		zapiMsgCh = server.zclient.Receive()
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
				}(peer.conf.Transport.TransportConfig.LocalAddress)
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
		case conn := <-acceptCh:
			passConn(conn)
		default:
		}

		select {
		case c := <-server.rpkiConfigCh:
			server.roaClient, _ = newROAClient(server.bgpConfig.Global.GlobalConfig.As, c)
		case c := <-server.bmpConfigCh:
			server.bmpClient, _ = newBMPClient(c, server.bmpConnCh)
		case c := <-server.bmpConnCh:
			bmpMsgList := []*bgp.BMPMessage{}
			for _, targetPeer := range server.neighborMap {
				if targetPeer.fsm.state != bgp.BGP_FSM_ESTABLISHED {
					continue
				}
				for _, p := range targetPeer.adjRib.GetInPathList(targetPeer.configuredRFlist()) {
					// avoid to merge for timestamp
					u := table.CreateUpdateMsgFromPaths([]*table.Path{p})
					buf, _ := u[0].Serialize()
					bmpMsgList = append(bmpMsgList, bmpPeerRoute(bgp.BMP_PEER_TYPE_GLOBAL, false, 0, targetPeer.fsm.peerInfo, p.GetTimestamp().Unix(), buf))
				}
			}

			m := &broadcastBMPMsg{
				ch:      server.bmpClient.send(),
				conn:    c.conn,
				addr:    c.addr,
				msgList: bmpMsgList,
			}
			server.broadcastMsgs = append(server.broadcastMsgs, m)
		case rmsg := <-server.roaClient.recieveROA():
			server.roaClient.handleRTRMsg(rmsg)
		case zmsg := <-zapiMsgCh:
			m := handleZapiMsg(zmsg, server)
			if len(m) > 0 {
				senderMsgs = append(senderMsgs, m...)
			}
		case conn := <-acceptCh:
			passConn(conn)
		case config := <-server.addedPeerCh:
			addr := config.NeighborConfig.NeighborAddress.String()
			_, found := server.neighborMap[addr]
			if found {
				log.Warn("Can't overwrite the exising peer ", addr)
				continue
			}

			SetTcpMD5SigSockopts(listener(config.NeighborConfig.NeighborAddress), addr, config.NeighborConfig.AuthPassword)
			var loc *table.TableManager
			if config.RouteServer.RouteServerConfig.RouteServerClient {
				loc = table.NewTableManager(config.NeighborConfig.NeighborAddress.String(), toRFlist(config.AfiSafis.AfiSafiList), g.MplsLabelRange.MinLabel, g.MplsLabelRange.MaxLabel)
			} else {
				loc = server.globalRib
			}
			peer := NewPeer(g, config, loc)

			server.setPolicyByConfig(peer, config.ApplyPolicy)
			if peer.isRouteServerClient() {
				pathList := make([]*table.Path, 0)
				rfList := peer.configuredRFlist()
				for _, p := range server.neighborMap {
					if p.isRouteServerClient() == true {
						pathList = append(pathList, p.getAccepted(rfList)...)
					}
				}
				pathList, _ = peer.ApplyPolicy(table.POLICY_DIRECTION_IMPORT, pathList)
				if len(pathList) > 0 {
					peer.localRib.ProcessPaths(pathList)
				}
			}
			server.neighborMap[addr] = peer
			peer.startFSMHandler(server.fsmincomingCh)
			server.broadcastPeerState(peer)
		case config := <-server.deletedPeerCh:
			addr := config.NeighborConfig.NeighborAddress.String()
			SetTcpMD5SigSockopts(listener(config.NeighborConfig.NeighborAddress), addr, "")
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

				m := server.dropPeerAllRoutes(peer)
				if len(m) > 0 {
					senderMsgs = append(senderMsgs, m...)
				}
				delete(server.neighborMap, addr)
			} else {
				log.Info("Can't delete a peer configuration for ", addr)
			}
		case config := <-server.updatedPeerCh:
			addr := config.NeighborConfig.NeighborAddress.String()
			peer := server.neighborMap[addr]
			peer.conf = config
			server.setPolicyByConfig(peer, config.ApplyPolicy)
		case e := <-server.fsmincomingCh:
			peer, found := server.neighborMap[e.MsgSrc]
			if !found {
				log.Warn("Can't find the neighbor ", e.MsgSrc)
				break
			}
			m := server.handleFSMMessage(peer, e, server.fsmincomingCh)
			if len(m) > 0 {
				senderMsgs = append(senderMsgs, m...)
			}
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
	_, y := peer.capMap[bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER]
	return &SenderMsg{
		messages:    messages,
		sendCh:      peer.outgoing,
		destination: peer.conf.NeighborConfig.NeighborAddress.String(),
		twoBytesAs:  y,
	}
}

func filterpath(peer *Peer, pathList []*table.Path) []*table.Path {
	filtered := make([]*table.Path, 0)

	for _, path := range pathList {
		if _, ok := peer.rfMap[path.GetRouteFamily()]; !ok {
			continue
		}

		remoteAddr := peer.conf.NeighborConfig.NeighborAddress

		//iBGP handling
		if !path.IsLocal() && peer.isIBGPPeer() {
			ignore := true
			info := path.GetSource()

			//if the path comes from eBGP peer
			if info.AS != peer.conf.NeighborConfig.PeerAs {
				ignore = false
			}
			// RFC4456 8. Avoiding Routing Information Loops
			// A router that recognizes the ORIGINATOR_ID attribute SHOULD
			// ignore a route received with its BGP Identifier as the ORIGINATOR_ID.
			if id := path.GetOriginatorID(); peer.gConf.GlobalConfig.RouterId.Equal(id) {
				log.WithFields(log.Fields{
					"Topic":        "Peer",
					"Key":          remoteAddr,
					"OriginatorID": id,
					"Data":         path,
				}).Debug("Originator ID is mine, ignore")
				continue
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
						continue
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
				continue
			}
		}

		if remoteAddr.Equal(path.GetSource().Address) {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   remoteAddr,
				"Data":  path,
			}).Debug("From me, ignore.")
			continue
		}

		send := true
		for _, as := range path.GetAsList() {
			if as == peer.conf.NeighborConfig.PeerAs {
				send = false
				break
			}
		}

		if !send {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   remoteAddr,
				"Data":  path,
			}).Debug("AS PATH loop, ignore.")
			continue
		}
		filtered = append(filtered, path.Clone(remoteAddr, path.IsWithdraw))
	}
	return filtered
}

func (server *BgpServer) dropPeerAllRoutes(peer *Peer) []*SenderMsg {
	msgs := make([]*SenderMsg, 0)

	for _, rf := range peer.configuredRFlist() {
		if peer.isRouteServerClient() {
			for _, targetPeer := range server.neighborMap {
				rib := targetPeer.localRib
				if !targetPeer.isRouteServerClient() || rib.OwnerName() == peer.conf.NeighborConfig.NeighborAddress.String() {
					continue
				}
				pathList, _ := rib.DeletePathsforPeer(peer.fsm.peerInfo, rf)
				if targetPeer.fsm.state != bgp.BGP_FSM_ESTABLISHED || len(pathList) == 0 {
					continue
				}
				msgList := table.CreateUpdateMsgFromPaths(pathList)
				msgs = append(msgs, newSenderMsg(targetPeer, msgList))
				targetPeer.adjRib.UpdateOut(pathList)
			}
		} else {
			rib := server.globalRib
			pathList, _ := rib.DeletePathsforPeer(peer.fsm.peerInfo, rf)
			if len(pathList) == 0 {
				continue
			}

			server.broadcastBests(pathList)

			msgList := table.CreateUpdateMsgFromPaths(pathList)
			for _, targetPeer := range server.neighborMap {
				if targetPeer.isRouteServerClient() || targetPeer.fsm.state != bgp.BGP_FSM_ESTABLISHED {
					continue
				}
				if _, ok := targetPeer.rfMap[rf]; !ok {
					continue
				}
				targetPeer.adjRib.UpdateOut(pathList)
				msgs = append(msgs, newSenderMsg(targetPeer, msgList))
			}
		}
	}
	return msgs
}

func (server *BgpServer) broadcastBests(bests []*table.Path) {
	for _, path := range bests {
		if !path.IsFromZebra {
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
				Paths:  []*api.Path{path.ToApiStruct()},
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

func (server *BgpServer) broadcastPeerState(peer *Peer) {
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
		ignore = ignore || (req.Name != "" && req.Name != peer.conf.NeighborConfig.NeighborAddress.String())
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
}

func (server *BgpServer) propagateUpdate(peer *Peer, pathList []*table.Path) []*SenderMsg {
	msgs := make([]*SenderMsg, 0)
	if peer != nil && peer.isRouteServerClient() {
		for _, targetPeer := range server.neighborMap {
			rib := targetPeer.localRib
			if !targetPeer.isRouteServerClient() || rib.OwnerName() == peer.conf.NeighborConfig.NeighborAddress.String() {
				continue
			}
			sendPathList, _ := targetPeer.ApplyPolicy(table.POLICY_DIRECTION_IMPORT, pathList)
			sendPathList, _ = rib.ProcessPaths(sendPathList)
			if targetPeer.fsm.state != bgp.BGP_FSM_ESTABLISHED || len(sendPathList) == 0 {
				continue
			}
			sendPathList, _ = targetPeer.ApplyPolicy(table.POLICY_DIRECTION_EXPORT, filterpath(targetPeer, sendPathList))
			if len(sendPathList) == 0 {
				continue
			}
			msgList := table.CreateUpdateMsgFromPaths(sendPathList)
			targetPeer.adjRib.UpdateOut(sendPathList)
			msgs = append(msgs, newSenderMsg(targetPeer, msgList))
		}
	} else {
		rib := server.globalRib
		pathList = rib.ApplyPolicy(table.POLICY_DIRECTION_IMPORT, pathList)
		sendPathList, _ := rib.ProcessPaths(pathList)
		if len(sendPathList) == 0 {
			return msgs
		}

		server.broadcastBests(sendPathList)

		for _, targetPeer := range server.neighborMap {
			if targetPeer.isRouteServerClient() || targetPeer.fsm.state != bgp.BGP_FSM_ESTABLISHED {
				continue
			}
			f := rib.ApplyPolicy(table.POLICY_DIRECTION_EXPORT, filterpath(targetPeer, sendPathList))
			if len(f) == 0 {
				continue
			}
			for _, path := range f {
				path.UpdatePathAttrs(&server.bgpConfig.Global, &targetPeer.conf)
			}
			targetPeer.adjRib.UpdateOut(f)
			msgList := table.CreateUpdateMsgFromPaths(f)

			msgs = append(msgs, newSenderMsg(targetPeer, msgList))
		}
	}
	return msgs
}

func (server *BgpServer) handleFSMMessage(peer *Peer, e *FsmMsg, incoming chan *FsmMsg) []*SenderMsg {
	msgs := make([]*SenderMsg, 0)

	switch e.MsgType {
	case FSM_MSG_STATE_CHANGE:
		nextState := e.MsgData.(bgp.FSMState)
		oldState := bgp.FSMState(peer.conf.NeighborState.SessionState)
		peer.conf.NeighborState.SessionState = uint32(nextState)
		peer.fsm.StateChange(nextState)

		if oldState == bgp.BGP_FSM_ESTABLISHED {
			if ch := server.bmpClient.send(); ch != nil {
				m := &broadcastBMPMsg{
					ch:      ch,
					msgList: []*bgp.BMPMessage{bmpPeerDown(bgp.BMP_PEER_DOWN_REASON_UNKNOWN, bgp.BMP_PEER_TYPE_GLOBAL, false, 0, peer.fsm.peerInfo, peer.conf.Timers.TimersState.Downtime)},
				}
				server.broadcastMsgs = append(server.broadcastMsgs, m)
			}
			t := time.Now()
			if t.Sub(time.Unix(peer.conf.Timers.TimersState.Uptime, 0)) < FLOP_THRESHOLD {
				peer.conf.NeighborState.Flops++
			}

			peer.DropAll(peer.configuredRFlist())

			msgs = append(msgs, server.dropPeerAllRoutes(peer)...)
		}

		close(peer.outgoing)
		peer.outgoing = make(chan *bgp.BGPMessage, 128)
		if nextState == bgp.BGP_FSM_ESTABLISHED {
			// update for export policy
			laddr, lport := peer.fsm.LocalHostPort()
			peer.conf.Transport.TransportConfig.LocalAddress = net.ParseIP(laddr)
			if ch := server.bmpClient.send(); ch != nil {
				_, rport := peer.fsm.RemoteHostPort()
				m := &broadcastBMPMsg{
					ch:      ch,
					msgList: []*bgp.BMPMessage{bmpPeerUp(laddr, lport, rport, buildopen(peer.fsm.gConf, peer.fsm.pConf), peer.recvOpen, bgp.BMP_PEER_TYPE_GLOBAL, false, 0, peer.fsm.peerInfo, peer.conf.Timers.TimersState.Uptime)},
				}
				server.broadcastMsgs = append(server.broadcastMsgs, m)
			}
			pathList, _ := peer.getBestFromLocal(peer.configuredRFlist())
			if len(pathList) > 0 {
				peer.adjRib.UpdateOut(pathList)
				msgs = append(msgs, newSenderMsg(peer, table.CreateUpdateMsgFromPaths(pathList)))
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
			peer.conf.Timers.TimersState.Downtime = time.Now().Unix()
		}
		// clear counter
		if peer.fsm.adminState == ADMIN_STATE_DOWN {
			peer.conf.NeighborState = config.NeighborState{}
			peer.conf.Timers.TimersState = config.TimersState{}
		}
		peer.startFSMHandler(incoming)
		server.broadcastPeerState(peer)

	case FSM_MSG_BGP_MESSAGE:
		switch m := e.MsgData.(type) {
		case *bgp.MessageError:
			msgs = append(msgs, newSenderMsg(peer, []*bgp.BGPMessage{bgp.NewBGPNotificationMessage(m.TypeCode, m.SubTypeCode, m.Data)}))
		case *bgp.BGPMessage:
			if m.Header.Type == bgp.BGP_MSG_UPDATE {
				listener := make(map[watcher]chan watcherEvent)
				for _, watcher := range server.watchers {
					if ch := watcher.notify(WATCHER_EVENT_UPDATE_MSG); ch != nil {
						listener[watcher] = ch
					}
				}
				if len(listener) > 0 {
					_, y := peer.capMap[bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER]
					l, _ := peer.fsm.LocalHostPort()
					ev := &watcherEventUpdateMsg{
						message:      m,
						peerAS:       peer.fsm.peerInfo.AS,
						localAS:      peer.fsm.peerInfo.LocalAS,
						peerAddress:  peer.fsm.peerInfo.Address,
						localAddress: net.ParseIP(l),
						fourBytesAs:  y,
						timestamp:    e.timestamp,
						payload:      e.payload,
					}
					for _, ch := range listener {
						bm := &broadcastWatcherMsg{
							ch:    ch,
							event: ev,
						}
						server.broadcastMsgs = append(server.broadcastMsgs, bm)
					}
				}

				if ch := server.bmpClient.send(); ch != nil {
					bm := &broadcastBMPMsg{
						ch:      ch,
						msgList: []*bgp.BMPMessage{bmpPeerRoute(bgp.BMP_PEER_TYPE_GLOBAL, false, 0, peer.fsm.peerInfo, e.timestamp.Unix(), e.payload)},
					}
					server.broadcastMsgs = append(server.broadcastMsgs, bm)
				}
			}

			pathList, update, msgList := peer.handleBGPmessage(e)
			if len(msgList) > 0 {
				msgs = append(msgs, newSenderMsg(peer, msgList))
				break
			}
			if update == false {
				if len(pathList) > 0 {
					msgList := table.CreateUpdateMsgFromPaths(pathList)
					msgs = append(msgs, newSenderMsg(peer, msgList))
				}
				break
			} else {
				if len(pathList) > 0 {
					server.roaClient.validate(pathList)
				}
			}
			// FIXME: refactor peer.handleBGPmessage and this func
			if peer.isRouteServerClient() {
				var accepted []*table.Path
				for _, p := range pathList {
					if p.Filtered == false {
						accepted = append(accepted, p)
					}
				}
				msgs = append(msgs, server.propagateUpdate(peer, accepted)...)
			} else {
				msgs = append(msgs, server.propagateUpdate(peer, pathList)...)
			}
		default:
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.conf.NeighborConfig.NeighborAddress,
				"Data":  e.MsgData,
			}).Panic("unknown msg type")
		}
	}
	return msgs
}

func (server *BgpServer) SetGlobalType(g config.Global) {
	if server.globalTypeCh != nil {
		server.globalTypeCh <- g
	}
}

func (server *BgpServer) SetRpkiConfig(c config.RpkiServers) {
	server.rpkiConfigCh <- c
}

func (server *BgpServer) SetBmpConfig(c config.BmpServers) {
	server.bmpConfigCh <- c
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
}

func (server *BgpServer) UpdatePolicy(policy config.RoutingPolicy) {
	server.policyUpdateCh <- policy
}

func (server *BgpServer) setPolicyByConfig(p policyPoint, c config.ApplyPolicy) {
	for _, dir := range []table.PolicyDirection{table.POLICY_DIRECTION_IN, table.POLICY_DIRECTION_IMPORT, table.POLICY_DIRECTION_EXPORT} {
		ps, def, err := server.policy.GetAssignmentFromConfig(dir, c)
		if err != nil {
			log.WithFields(log.Fields{
				"Topic": "Policy",
				"Dir":   dir,
			}).Errorf("failed to get policy info: %s", err)
			continue
		}
		p.SetDefaultPolicy(dir, def)
		p.SetPolicy(dir, ps)
	}
}

func (server *BgpServer) SetPolicy(pl config.RoutingPolicy) error {
	p, err := table.NewRoutingPolicy(pl)
	if err != nil {
		log.WithFields(log.Fields{
			"Topic": "Policy",
		}).Errorf("failed to create routing policy: %s", err)
		return err
	}
	server.policy = p
	server.setPolicyByConfig(server.globalRib, server.bgpConfig.Global.ApplyPolicy)
	return nil
}

func (server *BgpServer) handlePolicy(pl config.RoutingPolicy) error {
	if err := server.SetPolicy(pl); err != nil {
		log.WithFields(log.Fields{
			"Topic": "Policy",
		}).Errorf("failed to set new policy: %s", err)
		return err
	}
	for _, peer := range server.neighborMap {
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   peer.conf.NeighborConfig.NeighborAddress,
		}).Info("call set policy")
		server.setPolicyByConfig(peer, peer.conf.ApplyPolicy)
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

func (server *BgpServer) handleModPathRequest(grpcReq *GrpcRequest) []*table.Path {
	var nlri bgp.AddrPrefixInterface
	result := &GrpcResponse{}

	var pattr []bgp.PathAttributeInterface
	var extcomms []bgp.ExtendedCommunityInterface
	var nexthop string
	var rf bgp.RouteFamily
	var paths []*table.Path
	var path *api.Path
	var pi *table.PeerInfo
	arg, ok := grpcReq.Data.(*api.ModPathArguments)
	if !ok {
		result.ResponseErr = fmt.Errorf("type assertion failed")
		goto ERR
	}

	paths = make([]*table.Path, 0, len(arg.Paths))

	for _, path = range arg.Paths {
		seen := make(map[bgp.BGPAttrType]bool)

		pattr = make([]bgp.PathAttributeInterface, 0)
		extcomms = make([]bgp.ExtendedCommunityInterface, 0)

		if path.SourceAsn != 0 {
			pi = &table.PeerInfo{
				AS:      path.SourceAsn,
				LocalID: net.ParseIP(path.SourceId),
			}
		} else {
			pi = &table.PeerInfo{
				AS:      server.bgpConfig.Global.GlobalConfig.As,
				LocalID: server.bgpConfig.Global.GlobalConfig.RouterId,
			}
		}

		if len(path.Nlri) > 0 {
			nlri = &bgp.IPAddrPrefix{}
			err := nlri.DecodeFromBytes(path.Nlri)
			if err != nil {
				result.ResponseErr = err
				goto ERR
			}
		}

		for _, attr := range path.Pattrs {
			p, err := bgp.GetPathAttribute(attr)
			if err != nil {
				result.ResponseErr = err
				goto ERR
			}

			err = p.DecodeFromBytes(attr)
			if err != nil {
				result.ResponseErr = err
				goto ERR
			}

			if _, ok := seen[p.GetType()]; !ok {
				seen[p.GetType()] = true
			} else {
				result.ResponseErr = fmt.Errorf("the path attribute apears twice. Type : " + strconv.Itoa(int(p.GetType())))
				goto ERR
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
					result.ResponseErr = fmt.Errorf("include only one route in mp_reach_nlri")
					goto ERR
				}
				nlri = mpreach.Value[0]
				nexthop = mpreach.Nexthop.String()
			default:
				pattr = append(pattr, p)
			}
		}

		if nlri == nil || nexthop == "" {
			result.ResponseErr = fmt.Errorf("not found nlri or nexthop")
			goto ERR
		}

		rf = bgp.AfiSafiToRouteFamily(nlri.AFI(), nlri.SAFI())

		if arg.Resource == api.Resource_VRF {
			label, err := server.globalRib.GetNextLabel(arg.Name, nexthop, path.IsWithdraw)
			if err != nil {
				result.ResponseErr = err
				goto ERR
			}
			vrf := server.globalRib.Vrfs[arg.Name]
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
				result.ResponseErr = fmt.Errorf("unsupported route family for vrf: %s", rf)
				goto ERR
			}
			extcomms = append(extcomms, vrf.ExportRt...)
		}

		if arg.Resource != api.Resource_VRF && rf == bgp.RF_IPv4_UC {
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
				paths := server.globalRib.GetBestPathList([]bgp.RouteFamily{bgp.RF_EVPN})
				if m := getMacMobilityExtendedCommunity(etag, mac, paths); m != nil {
					extcomms = append(extcomms, m)
				}
			}
		}

		if len(extcomms) > 0 {
			pattr = append(pattr, bgp.NewPathAttributeExtendedCommunities(extcomms))
		}

		paths = append(paths, table.NewPath(pi, nlri, path.IsWithdraw, pattr, false, time.Now(), path.NoImplicitWithdraw))

	}

	return paths
ERR:
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
			AS:      server.bgpConfig.Global.GlobalConfig.As,
			LocalID: server.bgpConfig.Global.GlobalConfig.RouterId,
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
		paths := rib.GetPathList(rf)
		dsts := make([]*api.Destination, 0, len(paths))
		for _, path := range paths {
			ok := table.CanImportToVrf(vrfs[name], path)
			if !ok {
				continue
			}
			dsts = append(dsts, &api.Destination{
				Prefix: path.GetNlri().String(),
				Paths:  []*api.Path{path.ToApiStruct()},
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

func (server *BgpServer) handleModGlobalConfig(grpcReq *GrpcRequest) error {
	arg := grpcReq.Data.(*api.ModGlobalConfigArguments)
	if arg.Operation != api.Operation_ADD {
		return fmt.Errorf("invalid operation %s", arg.Operation)
	}
	if server.globalTypeCh == nil {
		return fmt.Errorf("gobgp is already started")
	}
	g := arg.Global
	c := config.Bgp{
		Global: config.Global{
			GlobalConfig: config.GlobalConfig{
				As:       g.As,
				RouterId: net.ParseIP(g.RouterId),
			},
		},
	}
	err := config.SetDefaultConfigValues(toml.MetaData{}, &c)
	if err != nil {
		return err
	}
	go func() {
		server.globalTypeCh <- c.Global
	}()
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

	sortedDsts := func(t *table.Table) []*api.Destination {
		results := make([]*api.Destination, 0, len(t.GetDestinations()))

		r := radix.New()
		for _, dst := range t.GetDestinations() {
			r.Insert(dst.RadixKey, dst.ToApiStruct())
		}
		r.Walk(func(s string, v interface{}) bool {
			results = append(results, v.(*api.Destination))
			return false
		})

		return results
	}

	if server.globalTypeCh != nil && grpcReq.RequestType != REQ_MOD_GLOBAL_CONFIG {
		grpcReq.ResponseCh <- &GrpcResponse{
			ResponseErr: fmt.Errorf("bgpd main loop is not started yet"),
		}
		close(grpcReq.ResponseCh)
		return nil
	}

	var err error

	switch grpcReq.RequestType {
	case REQ_GLOBAL_CONFIG:
		result := &GrpcResponse{
			Data: &api.Global{
				As:       server.bgpConfig.Global.GlobalConfig.As,
				RouterId: server.bgpConfig.Global.GlobalConfig.RouterId.String(),
			},
		}
		grpcReq.ResponseCh <- result
		close(grpcReq.ResponseCh)
	case REQ_MOD_GLOBAL_CONFIG:
		err := server.handleModGlobalConfig(grpcReq)
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
			rib = peer.localRib
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
				for _, dst := range arg.Destinations {
					key := dst.Prefix
					if _, prefix, err := net.ParseCIDR(key); err == nil {
						if dst := rib.Tables[af].GetDestination(prefix.String()); dst != nil {
							dsts = append(dsts, dst.ToApiStruct())
						}
					} else if host := net.ParseIP(key); host != nil {
						masklen := 32
						if af == bgp.RF_IPv6_UC {
							masklen = 128
						}
						for i := masklen; i > 0; i-- {
							if dst := rib.Tables[af].GetDestination(fmt.Sprintf("%s/%d", key, i)); dst != nil {
								dsts = append(dsts, dst.ToApiStruct())
								break
							}
						}
					}
				}
				d.Destinations = dsts
			} else {
				d.Destinations = sortedDsts(rib.Tables[af])
			}
		default:
			d.Destinations = make([]*api.Destination, 0, len(rib.Tables[af].GetDestinations()))
			for _, dst := range rib.Tables[af].GetDestinations() {
				d.Destinations = append(d.Destinations, dst.ToApiStruct())
			}
		}
		grpcReq.ResponseCh <- &GrpcResponse{
			Data: d,
		}
		close(grpcReq.ResponseCh)
	case REQ_MOD_PATH:
		pathList := server.handleModPathRequest(grpcReq)
		if len(pathList) > 0 {
			msgs = server.propagateUpdate(nil, pathList)
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
			paths = peer.adjRib.GetInPathList([]bgp.RouteFamily{rf})
			log.Debugf("RouteFamily=%v adj-rib-in found : %d", rf.String(), len(paths))
		} else {
			paths = peer.adjRib.GetOutPathList([]bgp.RouteFamily{rf})
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
					r.Insert(table.CidrToRadixkey(key), &api.Destination{
						Prefix: key,
						Paths:  []*api.Path{p.ToApiStruct()},
					})
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
					Paths:  []*api.Path{p.ToApiStruct()},
				})
			}
		}
		d.Destinations = results
		grpcReq.ResponseCh <- &GrpcResponse{
			Data: d,
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
			peer.fsm.idleHoldTime = peer.conf.Timers.TimersConfig.IdleHoldTimeAfterReset
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
			pathList := peer.adjRib.GetInPathList([]bgp.RouteFamily{grpcReq.RouteFamily})
			if peer.isRouteServerClient() {
				pathList, _ = peer.ApplyPolicy(table.POLICY_DIRECTION_IN, pathList)
			}
			msgs = append(msgs, server.propagateUpdate(peer, pathList)...)
		}

		if grpcReq.RequestType == REQ_NEIGHBOR_SOFT_RESET_IN {
			grpcReq.ResponseCh <- &GrpcResponse{}
			close(grpcReq.ResponseCh)
			break
		}
		fallthrough
	case REQ_NEIGHBOR_SOFT_RESET_OUT:
		peers, err := reqToPeers(grpcReq)
		if err != nil {
			break
		}
		if grpcReq.RequestType == REQ_NEIGHBOR_SOFT_RESET_OUT {
			logOp(grpcReq.Name, "Neighbor soft reset out")
		}
		for _, peer := range peers {
			rfList := peer.configuredRFlist()
			peer.adjRib.DropOut(rfList)
			pathList, filtered := peer.getBestFromLocal(rfList)
			if len(pathList) > 0 {
				peer.adjRib.UpdateOut(pathList)
				msgs = append(msgs, newSenderMsg(peer, table.CreateUpdateMsgFromPaths(pathList)))
			}
			if len(filtered) > 0 {
				for _, p := range filtered {
					p.IsWithdraw = true
				}
				msgs = append(msgs, newSenderMsg(peer, table.CreateUpdateMsgFromPaths(filtered)))
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
					"Key":   peer.conf.NeighborConfig.NeighborAddress,
				}).Debug("ADMIN_STATE_UP requested")
				err.Code = api.Error_SUCCESS
				err.Msg = "ADMIN_STATE_UP"
			default:
				log.Warning("previous request is still remaining. : ", peer.conf.NeighborConfig.NeighborAddress)
				err.Code = api.Error_FAIL
				err.Msg = "previous request is still remaining"
			}
		} else {
			select {
			case peer.fsm.adminStateCh <- ADMIN_STATE_DOWN:
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   peer.conf.NeighborConfig.NeighborAddress,
				}).Debug("ADMIN_STATE_DOWN requested")
				err.Code = api.Error_SUCCESS
				err.Msg = "ADMIN_STATE_DOWN"
			default:
				log.Warning("previous request is still remaining. : ", peer.conf.NeighborConfig.NeighborAddress)
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
	case REQ_MONITOR_GLOBAL_BEST_CHANGED, REQ_MONITOR_NEIGHBOR_PEER_STATE:
		server.broadcastReqs = append(server.broadcastReqs, grpcReq)
	case REQ_MRT_GLOBAL_RIB, REQ_MRT_LOCAL_RIB:
		server.handleMrt(grpcReq)
	case REQ_MOD_MRT:
		server.handleModMrt(grpcReq)
	case REQ_MOD_RPKI:
		server.handleModRpki(grpcReq)
	case REQ_ROA, REQ_RPKI:
		server.roaClient.handleGRPC(grpcReq)
	case REQ_VRF, REQ_VRFS, REQ_VRF_MOD:
		pathList := server.handleVrfRequest(grpcReq)
		if len(pathList) > 0 {
			msgs = server.propagateUpdate(nil, pathList)
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
	listener := func(addr net.IP) *net.TCPListener {
		var l *net.TCPListener
		if addr.To4() != nil {
			l = server.listenerMap["tcp4"]
		} else {
			l = server.listenerMap["tcp6"]
		}
		return l
	}

	switch arg.Operation {
	case api.Operation_ADD:
		if ok {
			return nil, fmt.Errorf("Can't overwrite the exising peer %s", addr)
		} else {
			log.Infof("Peer %s is added", addr)
		}
		SetTcpMD5SigSockopts(listener(net.ParseIP(addr)), addr, arg.Peer.Conf.AuthPassword)
		var loc *table.TableManager
		if arg.Peer.RouteServer != nil {
			if arg.Peer.RouteServer.RouteServerClient {
				apitoRFlist := func(l []*api.AfiSafi) []bgp.RouteFamily {
					rfList := []bgp.RouteFamily{}
					for _, rf := range l {
						k, _ := bgp.GetRouteFamily(rf.Name)
						rfList = append(rfList, k)
					}
					return rfList
				}
				loc = table.NewTableManager(addr, apitoRFlist(arg.Peer.Afisafis.Afisafi), server.bgpConfig.Global.MplsLabelRange.MinLabel, server.bgpConfig.Global.MplsLabelRange.MaxLabel)
			} else {
				loc = server.globalRib
			}
		} else {
			loc = server.globalRib
		}
		apitoConfig := func(a *api.Peer) config.Neighbor {
			var pconf config.Neighbor
			if a.Conf != nil {
				pconf.NeighborAddress = net.ParseIP(a.Conf.NeighborAddress)
				pconf.NeighborConfig.NeighborAddress = net.ParseIP(a.Conf.NeighborAddress)
				pconf.NeighborConfig.PeerAs = a.Conf.PeerAs
				pconf.NeighborConfig.LocalAs = a.Conf.LocalAs
				if pconf.NeighborConfig.PeerAs != server.bgpConfig.Global.GlobalConfig.As {
					pconf.NeighborConfig.PeerType = config.PEER_TYPE_EXTERNAL
				} else {
					pconf.NeighborConfig.PeerType = config.PEER_TYPE_INTERNAL
				}
				pconf.NeighborConfig.AuthPassword = a.Conf.AuthPassword
				pconf.NeighborConfig.RemovePrivateAs = config.RemovePrivateAsOption(a.Conf.RemovePrivateAs)
				pconf.NeighborConfig.RouteFlapDamping = a.Conf.RouteFlapDamping
				pconf.NeighborConfig.SendCommunity = config.CommunityType(a.Conf.SendCommunity)
				pconf.NeighborConfig.Description = a.Conf.Description
				pconf.NeighborConfig.PeerGroup = a.Conf.PeerGroup
				pconf.NeighborConfig.NeighborAddress = net.ParseIP(a.Conf.NeighborAddress)
			}
			if a.Timers != nil {
				if a.Timers.Config != nil {
					pconf.Timers.TimersConfig.ConnectRetry = float64(a.Timers.Config.ConnectRetry)
					pconf.Timers.TimersConfig.HoldTime = float64(a.Timers.Config.HoldTime)
					pconf.Timers.TimersConfig.KeepaliveInterval = float64(a.Timers.Config.KeepaliveInterval)
					pconf.Timers.TimersConfig.MinimumAdvertisementInterval = float64(a.Timers.Config.MinimumAdvertisementInterval)
				}
			} else {
				pconf.Timers.TimersConfig.ConnectRetry = float64(config.DEFAULT_CONNECT_RETRY)
				pconf.Timers.TimersConfig.HoldTime = float64(config.DEFAULT_HOLDTIME)
				pconf.Timers.TimersConfig.KeepaliveInterval = float64(config.DEFAULT_HOLDTIME / 3)
			}
			if a.RouteReflector != nil {
				pconf.RouteReflector.RouteReflectorConfig.RouteReflectorClusterId = config.RrClusterIdType(a.RouteReflector.RouteReflectorClusterId)
				pconf.RouteReflector.RouteReflectorConfig.RouteReflectorClient = a.RouteReflector.RouteReflectorClient
			}
			if a.RouteServer != nil {
				pconf.RouteServer.RouteServerConfig.RouteServerClient = a.RouteServer.RouteServerClient
			}
			if a.ApplyPolicy != nil {
				if a.ApplyPolicy.ImportPolicy != nil {
					pconf.ApplyPolicy.ApplyPolicyConfig.DefaultImportPolicy = config.DefaultPolicyType(a.ApplyPolicy.ImportPolicy.Default)
					for _, p := range a.ApplyPolicy.ImportPolicy.Policies {
						pconf.ApplyPolicy.ApplyPolicyConfig.ImportPolicy = append(pconf.ApplyPolicy.ApplyPolicyConfig.ImportPolicy, p.Name)
					}
				}
				if a.ApplyPolicy.ExportPolicy != nil {
					pconf.ApplyPolicy.ApplyPolicyConfig.DefaultExportPolicy = config.DefaultPolicyType(a.ApplyPolicy.ExportPolicy.Default)
					for _, p := range a.ApplyPolicy.ExportPolicy.Policies {
						pconf.ApplyPolicy.ApplyPolicyConfig.ExportPolicy = append(pconf.ApplyPolicy.ApplyPolicyConfig.ExportPolicy, p.Name)
					}
				}
				if a.ApplyPolicy.InPolicy != nil {
					pconf.ApplyPolicy.ApplyPolicyConfig.DefaultInPolicy = config.DefaultPolicyType(a.ApplyPolicy.InPolicy.Default)
					for _, p := range a.ApplyPolicy.InPolicy.Policies {
						pconf.ApplyPolicy.ApplyPolicyConfig.InPolicy = append(pconf.ApplyPolicy.ApplyPolicyConfig.InPolicy, p.Name)
					}
				}
			}
			return pconf
		}
		configneigh := apitoConfig(arg.Peer)
		peer := NewPeer(server.bgpConfig.Global, configneigh, loc)
		server.setPolicyByConfig(peer, configneigh.ApplyPolicy)
		if peer.isRouteServerClient() {
			pathList := make([]*table.Path, 0)
			rfList := peer.configuredRFlist()
			for _, p := range server.neighborMap {
				if p.isRouteServerClient() == true {
					pathList = append(pathList, p.getAccepted(rfList)...)
				}
			}
			pathList, _ = peer.ApplyPolicy(table.POLICY_DIRECTION_IMPORT, pathList)
			if len(pathList) > 0 {
				peer.localRib.ProcessPaths(pathList)
			}
		}
		server.neighborMap[addr] = peer
		peer.startFSMHandler(server.fsmincomingCh)
		server.broadcastPeerState(peer)
	case api.Operation_DEL:
		SetTcpMD5SigSockopts(listener(net.ParseIP(addr)), addr, "")
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
		m := server.dropPeerAllRoutes(n)
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
			for _, y := range peer.GetPolicy(dir) {
				if x.Name() == y.Name() {
					return true
				}
			}
		}
	}
	for _, dir := range []table.PolicyDirection{table.POLICY_DIRECTION_EXPORT, table.POLICY_DIRECTION_EXPORT} {
		for _, y := range server.globalRib.GetPolicy(dir) {
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

type policyPoint interface {
	GetDefaultPolicy(table.PolicyDirection) table.RouteType
	GetPolicy(table.PolicyDirection) []*table.Policy
	SetDefaultPolicy(table.PolicyDirection, table.RouteType) error
	SetPolicy(table.PolicyDirection, []*table.Policy) error
}

func (server *BgpServer) getPolicyInfo(a *api.PolicyAssignment) (policyPoint, table.PolicyDirection, error) {
	switch a.Resource {
	case api.Resource_GLOBAL:
		switch a.Type {
		case api.PolicyType_IMPORT:
			return server.globalRib, table.POLICY_DIRECTION_IMPORT, nil
		case api.PolicyType_EXPORT:
			return server.globalRib, table.POLICY_DIRECTION_EXPORT, nil
		default:
			return nil, table.POLICY_DIRECTION_NONE, fmt.Errorf("invalid policy type")
		}
	case api.Resource_LOCAL:
		peer, ok := server.neighborMap[a.Name]
		if !ok {
			return nil, table.POLICY_DIRECTION_NONE, fmt.Errorf("not found peer %s", a.Name)
		}
		switch a.Type {
		case api.PolicyType_IN:
			return peer, table.POLICY_DIRECTION_IN, nil
		case api.PolicyType_IMPORT:
			return peer, table.POLICY_DIRECTION_IMPORT, nil
		case api.PolicyType_EXPORT:
			return peer, table.POLICY_DIRECTION_EXPORT, nil
		default:
			return nil, table.POLICY_DIRECTION_NONE, fmt.Errorf("invalid policy type")
		}
	default:
		return nil, table.POLICY_DIRECTION_NONE, fmt.Errorf("invalid resource type")
	}

}

func (server *BgpServer) handleGrpcGetPolicyAssignment(grpcReq *GrpcRequest) error {
	arg := grpcReq.Data.(*api.PolicyAssignment)
	i, dir, err := server.getPolicyInfo(arg)
	if err != nil {
		return err
	}
	arg.Default = i.GetDefaultPolicy(dir).ToApiStruct()
	ps := i.GetPolicy(dir)
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
	var i policyPoint
	policyMutex.Lock()
	defer policyMutex.Unlock()
	arg := grpcReq.Data.(*api.ModPolicyAssignmentArguments)
	assignment := arg.Assignment
	i, dir, err = server.getPolicyInfo(assignment)
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
	cur := i.GetPolicy(dir)
	switch arg.Operation {
	case api.Operation_ADD, api.Operation_REPLACE:
		if arg.Operation == api.Operation_REPLACE || cur == nil {
			err = i.SetPolicy(dir, ps)
		} else {
			err = i.SetPolicy(dir, append(cur, ps...))
		}
		if err != nil {
			return err
		}
		switch assignment.Default {
		case api.RouteAction_ACCEPT:
			err = i.SetDefaultPolicy(dir, table.ROUTE_TYPE_ACCEPT)
		case api.RouteAction_REJECT:
			err = i.SetDefaultPolicy(dir, table.ROUTE_TYPE_REJECT)
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
		err = i.SetPolicy(dir, n)
	case api.Operation_DEL_ALL:
		err = i.SetPolicy(dir, nil)
		if err != nil {
			return err
		}
		err = i.SetDefaultPolicy(dir, table.ROUTE_TYPE_NONE)
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
		w, err := newMrtWatcher(arg.Filename)
		if err == nil {
			server.watchers[WATCHER_MRT] = w
		}
		grpcDone(grpcReq, err)
	case api.Operation_DEL:
		delete(server.watchers, WATCHER_MRT)
		w.stop()
		grpcDone(grpcReq, nil)
	case api.Operation_REPLACE:
		go func() {
			err := w.restart(arg.Filename)
			grpcDone(grpcReq, err)
		}()
	}
}

func (server *BgpServer) handleModRpki(grpcReq *GrpcRequest) {
	arg := grpcReq.Data.(*api.ModRpkiArguments)
	configured := false
	if len(server.bgpConfig.RpkiServers.RpkiServerList) > 0 {
		configured = true
	}

	if arg.Operation == api.Operation_ADD {
		if configured {
			grpcDone(grpcReq, fmt.Errorf("already enabled"))
			return
		}
	} else {
		if !configured {
			grpcDone(grpcReq, fmt.Errorf("not enabled yet"))
			return
		}
	}
	switch arg.Operation {
	case api.Operation_ADD:
		r := config.RpkiServer{}
		r.RpkiServerConfig.Address = net.ParseIP(arg.Address)
		r.RpkiServerConfig.Port = arg.Port
		server.bgpConfig.RpkiServers.RpkiServerList = append(server.bgpConfig.RpkiServers.RpkiServerList, r)
		server.roaClient, _ = newROAClient(server.bgpConfig.Global.GlobalConfig.As, server.bgpConfig.RpkiServers)
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
		ipaddr := peer.conf.NeighborConfig.NeighborAddress.String()
		asn := peer.conf.NeighborConfig.PeerAs
		peers = append(peers, bgp.NewPeer(id, ipaddr, asn, true))
	}
	bgpid := server.bgpConfig.Global.GlobalConfig.RouterId.To4().String()
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
		l := dst.GetKnownPathList()
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

func (server *BgpServer) NewZclient(url string, redistRouteTypes []string) error {
	l := strings.SplitN(url, ":", 2)
	if len(l) != 2 {
		return fmt.Errorf("unsupported url: %s", url)
	}
	cli, err := zebra.NewClient(l[0], l[1], zebra.ROUTE_BGP)
	if err != nil {
		return err
	}
	cli.SendHello()
	cli.SendRouterIDAdd()
	cli.SendInterfaceAdd()
	for _, typ := range redistRouteTypes {
		t, err := zebra.RouteTypeFromString(typ)
		if err != nil {
			return err
		}
		cli.SendRedistribute(t)
	}
	if e := cli.SendCommand(zebra.REDISTRIBUTE_DEFAULT_ADD, nil); e != nil {
		return e
	}
	server.zclient = cli
	return nil
}
