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
	log "github.com/Sirupsen/logrus"
	"github.com/armon/go-radix"
	"github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/policy"
	"github.com/osrg/gobgp/table"
	"github.com/osrg/gobgp/zebra"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	GLOBAL_RIB_NAME = "global"
)

type Direction string

const (
	POLICY_DIRECTION_IMPORT Direction = "import"
	POLICY_DIRECTION_EXPORT           = "export"
	POLICY_DIRECTION_IN               = "in"
)

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

type BgpServer struct {
	bgpConfig     config.Bgp
	globalTypeCh  chan config.Global
	addedPeerCh   chan config.Neighbor
	deletedPeerCh chan config.Neighbor
	updatedPeerCh chan config.Neighbor
	rpkiConfigCh  chan config.RpkiServers

	GrpcReqCh      chan *GrpcRequest
	listenPort     int
	policyUpdateCh chan config.RoutingPolicy
	policyMap      map[string]*policy.Policy
	routingPolicy  config.RoutingPolicy
	broadcastReqs  []*GrpcRequest
	broadcastMsgs  []broadcastMsg
	neighborMap    map[string]*Peer
	localRibMap    map[string]*LocalRib
	zclient        *zebra.Client
	roaClient      *roaClient
}

func NewBgpServer(port int) *BgpServer {
	b := BgpServer{}
	b.globalTypeCh = make(chan config.Global)
	b.addedPeerCh = make(chan config.Neighbor)
	b.deletedPeerCh = make(chan config.Neighbor)
	b.updatedPeerCh = make(chan config.Neighbor)
	b.rpkiConfigCh = make(chan config.RpkiServers)
	b.GrpcReqCh = make(chan *GrpcRequest, 1)
	b.policyUpdateCh = make(chan config.RoutingPolicy)
	b.localRibMap = make(map[string]*LocalRib)
	b.neighborMap = make(map[string]*Peer)
	b.listenPort = port
	b.roaClient, _ = newROAClient("")
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

func (server *BgpServer) addLocalRib(rib *LocalRib) {
	server.localRibMap[rib.OwnerName()] = rib
}

func (server *BgpServer) Serve() {
	g := <-server.globalTypeCh
	server.bgpConfig.Global = g

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

	// FIXME
	rfList := func(l []config.AfiSafi) []bgp.RouteFamily {
		rfList := []bgp.RouteFamily{}
		for _, rf := range l {
			k, _ := bgp.GetRouteFamily(rf.AfiSafiName)
			rfList = append(rfList, k)
		}
		return rfList
	}(g.AfiSafis.AfiSafiList)

	server.addLocalRib(NewLocalRib(GLOBAL_RIB_NAME, rfList, make(map[string]*policy.Policy)))

	listenerMap := make(map[string]*net.TCPListener)
	acceptCh := make(chan *net.TCPConn)
	l4, err1 := listenAndAccept("tcp4", server.listenPort, acceptCh)
	listenerMap["tcp4"] = l4
	l6, err2 := listenAndAccept("tcp6", server.listenPort, acceptCh)
	listenerMap["tcp6"] = l6
	if err1 != nil && err2 != nil {
		log.Fatal("can't listen either v4 and v6")
		os.Exit(1)
	}

	listener := func(addr net.IP) *net.TCPListener {
		var l *net.TCPListener
		if addr.To4() != nil {
			l = listenerMap["tcp4"]
		} else {
			l = listenerMap["tcp6"]
		}
		return l
	}

	incoming := make(chan *fsmMsg, 4096)
	var senderMsgs []*SenderMsg

	var zapiMsgCh chan *zebra.Message
	if server.zclient != nil {
		zapiMsgCh = server.zclient.Recieve()
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

		select {
		case c := <-server.rpkiConfigCh:
			if len(c.RpkiServerList) > 0 {
				var url string
				if c.RpkiServerList[0].RpkiServerConfig.Address.To16() == nil {
					url = fmt.Sprintf("%s", c.RpkiServerList[0].RpkiServerConfig.Address)
				} else {
					url = fmt.Sprintf("[%s]", c.RpkiServerList[0].RpkiServerConfig.Address)
				}
				url += fmt.Sprintf(":%d", c.RpkiServerList[0].RpkiServerConfig.Port)
				server.roaClient, _ = newROAClient(url)
			}
		case rmsg := <-server.roaClient.recieveROA():
			server.roaClient.handleRTRMsg(rmsg)
		case zmsg := <-zapiMsgCh:
			handleZapiMsg(zmsg)
		case conn := <-acceptCh:
			remoteAddr, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			peer, found := server.neighborMap[remoteAddr]
			if found {
				log.Debug("accepted a new passive connection from ", remoteAddr)
				peer.PassConn(conn)
			} else {
				log.Info("can't find configuration for a new passive connection from ", remoteAddr)
				conn.Close()
			}
		case config := <-server.addedPeerCh:
			addr := config.NeighborConfig.NeighborAddress.String()
			_, found := server.neighborMap[addr]
			if found {
				log.Warn("Can't overwrite the exising peer ", addr)
				continue
			}

			SetTcpMD5SigSockopts(listener(config.NeighborConfig.NeighborAddress), addr, config.NeighborConfig.AuthPassword)

			peer := NewPeer(g, config)
			name := config.NeighborConfig.NeighborAddress.String()

			if config.RouteServer.RouteServerConfig.RouteServerClient {
				loc := NewLocalRib(name, peer.configuredRFlist(), make(map[string]*policy.Policy))
				server.addLocalRib(loc)
				loc.setPolicy(peer, server.policyMap)
				// set in policy
				peer.setPolicy(server.policyMap)

				pathList := make([]*table.Path, 0)
				for _, p := range server.neighborMap {
					if p.isRouteServerClient() == false {
						continue
					}
					for _, rf := range peer.configuredRFlist() {
						pathList = append(pathList, p.adjRib.GetInPathList(rf)...)
					}
				}
				pathList = applyPolicies(peer, loc, POLICY_DIRECTION_IMPORT, pathList)
				if len(pathList) > 0 {
					loc.rib.ProcessPaths(pathList)
				}
			}
			server.neighborMap[name] = peer
			peer.outgoing = make(chan *bgp.BGPMessage, 128)
			peer.startFSMHandler(incoming)
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
				if peer.isRouteServerClient() {
					delete(server.localRibMap, addr)
				}
			} else {
				log.Info("Can't delete a peer configuration for ", addr)
			}
		case config := <-server.updatedPeerCh:
			addr := config.NeighborConfig.NeighborAddress.String()
			peer := server.neighborMap[addr]
			if peer.isRouteServerClient() {
				peer.conf.ApplyPolicy = config.ApplyPolicy
				loc := server.localRibMap[addr]
				loc.setPolicy(peer, server.policyMap)
				peer.setPolicy(server.policyMap)
			}
		case e := <-incoming:
			peer, found := server.neighborMap[e.MsgSrc]
			if !found {
				log.Warn("Can't find the neighbor ", e.MsgSrc)
				break
			}
			m := server.handleFSMMessage(peer, e, incoming)
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

func dropSameAsPath(asnum uint32, p []*table.Path) []*table.Path {
	pathList := []*table.Path{}
	for _, path := range p {
		asList := path.GetAsList()
		send := true
		for _, as := range asList {
			if as == asnum {
				send = false
				break
			}
		}
		if send {
			pathList = append(pathList, path)
		}
	}
	return pathList
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

		selfGenerated := path.GetSource().ID == nil
		fromAS := path.GetSource().AS
		myAS := peer.gConf.GlobalConfig.As
		if !selfGenerated && !peer.isEBGP && myAS == fromAS {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.conf.NeighborConfig.NeighborAddress,
				"Data":  path,
			}).Debug("From same AS, ignore.")
			continue
		}

		if peer.conf.NeighborConfig.NeighborAddress.Equal(path.GetSource().Address) {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.conf.NeighborConfig.NeighborAddress,
				"Data":  path,
			}).Debug("From me, ignore.")
			continue
		}

		if peer.conf.NeighborConfig.PeerAs == path.GetSourceAs() {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.conf.NeighborConfig.NeighborAddress,
				"Data":  path,
			}).Debug("AS PATH loop, ignore.")
			continue
		}
		filtered = append(filtered, path.Clone(path.IsWithdraw))
	}
	return filtered
}

func (server *BgpServer) dropPeerAllRoutes(peer *Peer) []*SenderMsg {
	msgs := make([]*SenderMsg, 0)

	for _, rf := range peer.configuredRFlist() {
		if peer.isRouteServerClient() {
			for _, loc := range server.localRibMap {
				targetPeer := server.neighborMap[loc.OwnerName()]
				if loc.isGlobal() || loc.OwnerName() == peer.conf.NeighborConfig.NeighborAddress.String() {
					continue
				}
				pathList, _ := loc.rib.DeletePathsforPeer(peer.peerInfo, rf)
				pathList = dropSameAsPath(targetPeer.conf.NeighborConfig.PeerAs, pathList)
				if targetPeer.fsm.state != bgp.BGP_FSM_ESTABLISHED || len(pathList) == 0 {
					continue
				}
				msgList := table.CreateUpdateMsgFromPaths(pathList)
				msgs = append(msgs, newSenderMsg(targetPeer, msgList))
				targetPeer.adjRib.UpdateOut(pathList)
			}
		} else {
			loc := server.localRibMap[GLOBAL_RIB_NAME]
			pathList, _ := loc.rib.DeletePathsforPeer(peer.peerInfo, rf)
			if len(pathList) == 0 {
				continue
			}

			server.broadcastBests(pathList)

			msgList := table.CreateUpdateMsgFromPaths(pathList)
			for _, targetPeer := range server.neighborMap {
				if targetPeer.isRouteServerClient() || targetPeer.fsm.state != bgp.BGP_FSM_ESTABLISHED {
					continue
				}
				targetPeer.adjRib.UpdateOut(pathList)
				msgs = append(msgs, newSenderMsg(targetPeer, msgList))
			}
		}
	}
	return msgs
}

func applyPolicies(peer *Peer, loc *LocalRib, d Direction, pathList []*table.Path) []*table.Path {
	var defaultPolicy config.DefaultPolicyType
	ret := make([]*table.Path, 0, len(pathList))

	switch d {
	case POLICY_DIRECTION_EXPORT:
		defaultPolicy = loc.defaultExportPolicy
	case POLICY_DIRECTION_IMPORT:
		defaultPolicy = loc.defaultImportPolicy
	case POLICY_DIRECTION_IN:
		defaultPolicy = peer.defaultInPolicy
	default:
		log.WithFields(log.Fields{
			"Topic": "Server",
			"Key":   peer.conf.NeighborConfig.NeighborAddress,
		}).Error("direction is not specified.")
		return ret
	}

	for _, path := range pathList {
		if !path.IsWithdraw {
			var applied bool = false
			switch d {
			case POLICY_DIRECTION_IN:
				applied, path = peer.applyPolicies(d, path)
			case POLICY_DIRECTION_IMPORT, POLICY_DIRECTION_EXPORT:
				applied, path = loc.applyPolicies(d, path)
			}

			if applied {
				if path == nil {
					log.WithFields(log.Fields{
						"Topic": "Peer",
						"Key":   peer.conf.NeighborConfig.NeighborAddress,
						"Data":  path,
					}).Debug("Policy applied and rejected.")
					continue
				}
			} else if defaultPolicy != config.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE {
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   peer.conf.NeighborConfig.NeighborAddress,
					"Data":  path,
				}).Debug("Default policy applied and rejected.")
				continue
			}
		}
		// FIXME: probably we already clone.
		ret = append(ret, path.Clone(path.IsWithdraw))
	}
	return ret
}

func (server *BgpServer) broadcastBests(bests []*table.Path) {
	for _, path := range bests {
		z := newBroadcastZapiBestMsg(server.zclient, path)
		if z != nil {
			server.broadcastMsgs = append(server.broadcastMsgs, z)
		}

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
			m := &broadcastGrpcMsg{
				req:    req,
				result: result,
			}
			server.broadcastMsgs = append(server.broadcastMsgs, m)
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

func (server *BgpServer) propagateUpdate(neighborAddress string, RouteServerClient bool, pathList []*table.Path) []*SenderMsg {
	msgs := make([]*SenderMsg, 0)

	if RouteServerClient {
		p := server.neighborMap[neighborAddress]
		newPathList := applyPolicies(p, nil, POLICY_DIRECTION_IN, pathList)
		for _, loc := range server.localRibMap {
			targetPeer := server.neighborMap[loc.OwnerName()]
			if loc.isGlobal() || loc.OwnerName() == neighborAddress {
				continue
			}
			sendPathList, _ := loc.rib.ProcessPaths(applyPolicies(targetPeer, loc, POLICY_DIRECTION_IMPORT,
				dropSameAsPath(targetPeer.conf.NeighborConfig.PeerAs, filterpath(targetPeer, newPathList))))
			if targetPeer.fsm.state != bgp.BGP_FSM_ESTABLISHED || len(sendPathList) == 0 {
				continue
			}
			sendPathList = applyPolicies(targetPeer, loc, POLICY_DIRECTION_EXPORT, sendPathList)
			if len(sendPathList) == 0 {
				continue
			}
			msgList := table.CreateUpdateMsgFromPaths(sendPathList)
			targetPeer.adjRib.UpdateOut(sendPathList)
			msgs = append(msgs, newSenderMsg(targetPeer, msgList))
		}
	} else {
		globalLoc := server.localRibMap[GLOBAL_RIB_NAME]
		sendPathList, _ := globalLoc.rib.ProcessPaths(pathList)
		if len(sendPathList) == 0 {
			return msgs
		}

		server.broadcastBests(sendPathList)

		for _, targetPeer := range server.neighborMap {
			if targetPeer.isRouteServerClient() || targetPeer.fsm.state != bgp.BGP_FSM_ESTABLISHED {
				continue
			}
			f := filterpath(targetPeer, sendPathList)
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

func (server *BgpServer) handleFSMMessage(peer *Peer, e *fsmMsg, incoming chan *fsmMsg) []*SenderMsg {
	msgs := make([]*SenderMsg, 0)

	switch e.MsgType {
	case FSM_MSG_STATE_CHANGE:
		nextState := e.MsgData.(bgp.FSMState)
		oldState := bgp.FSMState(peer.conf.NeighborState.SessionState)
		peer.conf.NeighborState.SessionState = uint32(nextState)
		peer.fsm.StateChange(nextState)
		globalRib := server.localRibMap[GLOBAL_RIB_NAME]

		if oldState == bgp.BGP_FSM_ESTABLISHED {
			t := time.Now()
			if t.Sub(time.Unix(peer.conf.Timers.TimersState.Uptime, 0)) < FLOP_THRESHOLD {
				peer.conf.NeighborState.Flops++
			}

			for _, rf := range peer.configuredRFlist() {
				peer.adjRib.DropAll(rf)
			}

			msgs = append(msgs, server.dropPeerAllRoutes(peer)...)
		}

		close(peer.outgoing)
		peer.outgoing = make(chan *bgp.BGPMessage, 128)
		if nextState == bgp.BGP_FSM_ESTABLISHED {
			pathList := make([]*table.Path, 0)
			if peer.isRouteServerClient() {
				loc := server.localRibMap[peer.conf.NeighborConfig.NeighborAddress.String()]
				pathList = applyPolicies(peer, loc, POLICY_DIRECTION_EXPORT, peer.getBests(loc))
			} else {
				peer.conf.Transport.TransportConfig.LocalAddress = peer.fsm.LocalAddr()
				for _, path := range filterpath(peer, peer.getBests(globalRib)) {
					p := path.Clone(path.IsWithdraw)
					p.UpdatePathAttrs(&server.bgpConfig.Global, &peer.conf)
					pathList = append(pathList, p)
				}
			}
			if len(pathList) > 0 {
				peer.adjRib.UpdateOut(pathList)
				msgs = append(msgs, newSenderMsg(peer, table.CreateUpdateMsgFromPaths(pathList)))
			}
		} else {
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
			pathList, update, msgList := peer.handleBGPmessage(m)
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
			msgs = append(msgs, server.propagateUpdate(peer.conf.NeighborConfig.NeighborAddress.String(),
				peer.isRouteServerClient(), pathList)...)
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
	server.globalTypeCh <- g
}

func (server *BgpServer) SetRpkiConfig(c config.RpkiServers) {
	server.rpkiConfigCh <- c
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
	for _, p := range server.neighborMap {
		p.fsm.adminStateCh <- ADMIN_STATE_DOWN
	}
}

func (server *BgpServer) UpdatePolicy(policy config.RoutingPolicy) {
	server.policyUpdateCh <- policy
}

func (server *BgpServer) SetPolicy(pl config.RoutingPolicy) {
	pMap := make(map[string]*policy.Policy)
	df := pl.DefinedSets
	for _, p := range pl.PolicyDefinitions.PolicyDefinitionList {
		pMap[p.Name] = policy.NewPolicy(p, df)
	}
	server.policyMap = pMap
	server.routingPolicy = pl
}

func (server *BgpServer) handlePolicy(pl config.RoutingPolicy) {
	server.SetPolicy(pl)
	for _, loc := range server.localRibMap {
		if loc.isGlobal() {
			continue
		}
		targetPeer := server.neighborMap[loc.OwnerName()]
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   targetPeer.conf.NeighborConfig.NeighborAddress,
		}).Info("call set policy")
		loc.setPolicy(targetPeer, server.policyMap)
		// set distribute policy
		targetPeer.setPolicy(server.policyMap)
	}
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

	pattr := make([]bgp.PathAttributeInterface, 0)
	extcomms := make([]bgp.ExtendedCommunityInterface, 0)
	var nexthop string
	var rf bgp.RouteFamily
	var path *api.Path
	seen := make(map[bgp.BGPAttrType]bool)
	var pi *table.PeerInfo

	arg, ok := grpcReq.Data.(*api.ModPathArguments)
	if !ok {
		result.ResponseErr = fmt.Errorf("type assertion failed")
		goto ERR
	}
	if arg.Asn != 0 {
		pi = &table.PeerInfo{
			AS:      arg.Asn,
			LocalID: net.ParseIP(arg.Id),
		}
	} else {
		pi = &table.PeerInfo{
			AS:      server.bgpConfig.Global.GlobalConfig.As,
			LocalID: server.bgpConfig.Global.GlobalConfig.RouterId,
		}
	}
	path = arg.Path

	if len(path.Nlri) > 0 {
		nlri = &bgp.NLRInfo{}
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
		vrfs := server.localRibMap[GLOBAL_RIB_NAME].rib.Vrfs
		if _, ok := vrfs[arg.Name]; !ok {
			result.ResponseErr = fmt.Errorf("vrf %s not found", arg.Name)
			goto ERR
		}
		vrf := vrfs[arg.Name]

		switch rf {
		case bgp.RF_IPv4_UC:
			n := nlri.(*bgp.NLRInfo)
			nlri = bgp.NewLabeledVPNIPAddrPrefix(n.Length, n.Prefix.String(), *bgp.NewMPLSLabelStack(), vrf.Rd)
		case bgp.RF_IPv6_UC:
			n := nlri.(*bgp.IPv6AddrPrefix)
			nlri = bgp.NewLabeledVPNIPv6AddrPrefix(n.Length, n.Prefix.String(), *bgp.NewMPLSLabelStack(), vrf.Rd)
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
			paths := server.localRibMap[GLOBAL_RIB_NAME].rib.GetBestPathList(bgp.RF_EVPN)
			if m := getMacMobilityExtendedCommunity(etag, mac, paths); m != nil {
				extcomms = append(extcomms, m)
			}
		}
	}

	if len(extcomms) > 0 {
		pattr = append(pattr, bgp.NewPathAttributeExtendedCommunities(extcomms))
	}

	return []*table.Path{table.NewPath(pi, nlri, path.IsWithdraw, pattr, false, time.Now(), path.NoImplicitWithdraw)}
ERR:
	grpcReq.ResponseCh <- result
	close(grpcReq.ResponseCh)
	return []*table.Path{}

}

func (server *BgpServer) handleVrfMod(arg *api.ModVrfArguments) ([]*table.Path, error) {
	manager := server.localRibMap[GLOBAL_RIB_NAME].rib
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
		exportRt, err := f(arg.Vrf.ImportRt)
		if err != nil {
			return nil, err
		}
		pi := &table.PeerInfo{
			AS:      server.bgpConfig.Global.GlobalConfig.As,
			LocalID: server.bgpConfig.Global.GlobalConfig.RouterId,
		}
		msgs, err = manager.AddVrf(arg.Vrf.Name, rd, importRt, exportRt, pi)
		if err != nil {
			return nil, err
		}
	case api.Operation_DEL:
		var err error
		msgs, err = manager.DeleteVrf(arg.Vrf.Name)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown operation:", arg.Operation)
	}
	return msgs, nil
}

func (server *BgpServer) handleVrfRequest(req *GrpcRequest) []*table.Path {
	var msgs []*table.Path
	result := &GrpcResponse{}

	switch req.RequestType {
	case REQ_VRF:
		name := req.Name
		rib := server.localRibMap[GLOBAL_RIB_NAME].rib
		vrfs := rib.Vrfs
		if _, ok := vrfs[name]; !ok {
			result.ResponseErr = fmt.Errorf("vrf %s not found", name)
			break
		}
		var rf bgp.RouteFamily
		switch req.RouteFamily {
		case bgp.RF_IPv4_UC:
			rf = bgp.RF_IPv4_VPN
		case bgp.RF_IPv6_UC:
			rf = bgp.RF_IPv6_VPN
		case bgp.RF_EVPN:
			rf = bgp.RF_EVPN
		default:
			result.ResponseErr = fmt.Errorf("unsupported route family: %s", req.RouteFamily)
			break
		}
		for _, path := range rib.GetPathList(rf) {
			ok := policy.CanImportToVrf(vrfs[name], path)
			if !ok {
				continue
			}
			req.ResponseCh <- &GrpcResponse{
				Data: &api.Destination{
					Prefix: path.GetNlri().String(),
					Paths:  []*api.Path{path.ToApiStruct()},
				},
			}
		}
		goto END
	case REQ_VRFS:
		vrfs := server.localRibMap[GLOBAL_RIB_NAME].rib.Vrfs
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
		result.ResponseErr = fmt.Errorf("unknown request type:", req.RequestType)
	}

	req.ResponseCh <- result
END:
	close(req.ResponseCh)
	return msgs
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

	sortedDsts := func(t *table.Table) []*GrpcResponse {
		results := make([]*GrpcResponse, len(t.GetDestinations()))

		r := radix.New()
		for _, dst := range t.GetDestinations() {
			result := &GrpcResponse{}
			result.Data = dst.ToApiStruct()
			r.Insert(dst.RadixKey, result)
		}
		i := 0
		r.Walk(func(s string, v interface{}) bool {
			r, _ := v.(*GrpcResponse)
			results[i] = r
			i++
			return false
		})

		return results
	}

	switch grpcReq.RequestType {
	case REQ_GLOBAL_RIB:
		if t, ok := server.localRibMap[GLOBAL_RIB_NAME].rib.Tables[grpcReq.RouteFamily]; ok {
			results := make([]*GrpcResponse, len(t.GetDestinations()))
			switch grpcReq.RouteFamily {
			case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
				results = sortedDsts(server.localRibMap[GLOBAL_RIB_NAME].rib.Tables[grpcReq.RouteFamily])
			default:
				i := 0
				for _, dst := range t.GetDestinations() {
					result := &GrpcResponse{}
					result.Data = dst.ToApiStruct()
					results[i] = result
					i++
				}
			}
			go sendMultipleResponses(grpcReq, results)
		}

	case REQ_MOD_PATH:
		pathList := server.handleModPathRequest(grpcReq)
		if len(pathList) > 0 {
			msgs = server.propagateUpdate("", false, pathList)
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

	case REQ_LOCAL_RIB:
		peer, err := server.checkNeighborRequest(grpcReq)
		if err != nil {
			break
		}
		if peer.isRouteServerClient() && peer.fsm.adminState != ADMIN_STATE_DOWN {
			remoteAddr := grpcReq.Name
			if t, ok := server.localRibMap[remoteAddr].rib.Tables[grpcReq.RouteFamily]; ok {
				results := make([]*GrpcResponse, len(t.GetDestinations()))
				switch grpcReq.RouteFamily {
				case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
					results = sortedDsts(server.localRibMap[remoteAddr].rib.Tables[grpcReq.RouteFamily])
				default:
					i := 0
					for _, dst := range t.GetDestinations() {
						result := &GrpcResponse{}
						result.Data = dst.ToApiStruct()
						results[i] = result
						i++
					}
				}
				go sendMultipleResponses(grpcReq, results)
			}
		}

	case REQ_ADJ_RIB_IN, REQ_ADJ_RIB_OUT:
		peer, err := server.checkNeighborRequest(grpcReq)
		if err != nil {
			break
		}
		rf := grpcReq.RouteFamily
		var paths []*table.Path

		if grpcReq.RequestType == REQ_ADJ_RIB_IN {
			paths = peer.adjRib.GetInPathList(rf)
			log.Debugf("RouteFamily=%v adj-rib-in found : %d", rf.String(), len(paths))
		} else {
			paths = peer.adjRib.GetOutPathList(rf)
			log.Debugf("RouteFamily=%v adj-rib-out found : %d", rf.String(), len(paths))
		}

		toResult := func(p *table.Path) *GrpcResponse {
			return &GrpcResponse{
				Data: &api.Destination{
					Prefix: p.GetNlri().String(),
					Paths:  []*api.Path{p.ToApiStruct()},
				},
			}
		}

		results := make([]*GrpcResponse, len(paths))
		switch rf {
		case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
			r := radix.New()
			for _, p := range paths {
				r.Insert(table.CidrToRadixkey(p.GetNlri().String()), toResult(p))
			}
			i := 0
			r.Walk(func(s string, v interface{}) bool {
				r, _ := v.(*GrpcResponse)
				results[i] = r
				i++
				return false
			})
		default:
			for i, p := range paths {
				results[i] = toResult(p)
			}
		}
		go sendMultipleResponses(grpcReq, results)

	case REQ_NEIGHBOR_SHUTDOWN:
		peer, err := server.checkNeighborRequest(grpcReq)
		if err != nil {
			break
		}
		m := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN, nil)
		msgs = []*SenderMsg{newSenderMsg(peer, []*bgp.BGPMessage{m})}
		grpcReq.ResponseCh <- &GrpcResponse{}
		close(grpcReq.ResponseCh)

	case REQ_NEIGHBOR_RESET:
		peer, err := server.checkNeighborRequest(grpcReq)
		if err != nil {
			break
		}
		peer.fsm.idleHoldTime = peer.conf.Timers.TimersConfig.IdleHoldTimeAfterReset
		m := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET, nil)
		msgs = []*SenderMsg{newSenderMsg(peer, []*bgp.BGPMessage{m})}
		grpcReq.ResponseCh <- &GrpcResponse{}
		close(grpcReq.ResponseCh)

	case REQ_NEIGHBOR_SOFT_RESET, REQ_NEIGHBOR_SOFT_RESET_IN:
		peer, err := server.checkNeighborRequest(grpcReq)
		if err != nil {
			break
		}
		pathList := peer.adjRib.GetInPathList(grpcReq.RouteFamily)
		msgs = server.propagateUpdate(peer.conf.NeighborConfig.NeighborAddress.String(), peer.isRouteServerClient(), pathList)

		if grpcReq.RequestType == REQ_NEIGHBOR_SOFT_RESET_IN {
			grpcReq.ResponseCh <- &GrpcResponse{}
			close(grpcReq.ResponseCh)
			break
		}
		fallthrough
	case REQ_NEIGHBOR_SOFT_RESET_OUT:
		peer, err := server.checkNeighborRequest(grpcReq)
		if err != nil {
			break
		}
		pathList := peer.adjRib.GetOutPathList(grpcReq.RouteFamily)
		msgList := table.CreateUpdateMsgFromPaths(pathList)
		msgs = []*SenderMsg{newSenderMsg(peer, msgList)}
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

	case REQ_NEIGHBOR_POLICY:
		peer, err := server.checkNeighborRequest(grpcReq)
		if err != nil {
			break
		}
		loc := server.localRibMap[peer.conf.NeighborConfig.NeighborAddress.String()]
		if loc == nil {
			result := &GrpcResponse{
				ResponseErr: fmt.Errorf("no local rib for %s", peer.conf.NeighborConfig.NeighborAddress.String()),
			}
			grpcReq.ResponseCh <- result
			close(grpcReq.ResponseCh)
			break
		}

		extract := func(policyNames []string) []*api.PolicyDefinition {
			pdList := server.routingPolicy.PolicyDefinitions.PolicyDefinitionList
			df := server.routingPolicy.DefinedSets
			extracted := []*api.PolicyDefinition{}
			for _, policyName := range policyNames {
				match := false
				for _, pd := range pdList {
					if policyName == pd.Name {
						match = true
						extracted = append(extracted, policy.PolicyDefinitionToApiStruct(pd, df))
						break
					}
				}
				if !match {
					extracted = append(extracted, &api.PolicyDefinition{PolicyDefinitionName: policyName})
				}
			}
			return extracted
		}

		// Add importpolies that has been set in the configuration file to the list.
		// However, peer haven't target importpolicy when add PolicyDefinition of name only to the list.
		conImportPolicyNames := peer.conf.ApplyPolicy.ApplyPolicyConfig.ImportPolicy
		resImportPolicies := extract(conImportPolicyNames)

		// Add importpolies that has been set in the configuration file to the list.
		// However, peer haven't target importpolicy when add PolicyDefinition of name only to the list.
		conExportPolicyNames := peer.conf.ApplyPolicy.ApplyPolicyConfig.ExportPolicy
		resExportPolicies := extract(conExportPolicyNames)

		inPolicyNames := peer.conf.ApplyPolicy.ApplyPolicyConfig.InPolicy
		resInPolicies := extract(inPolicyNames)

		defaultImportPolicy := policy.ROUTE_REJECT
		defaultExportPolicy := policy.ROUTE_REJECT
		defaultInPolicy := policy.ROUTE_REJECT
		if loc.defaultImportPolicy == config.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE {
			defaultImportPolicy = policy.ROUTE_ACCEPT
		}
		if loc.defaultExportPolicy == config.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE {
			defaultExportPolicy = policy.ROUTE_ACCEPT
		}
		if peer.defaultInPolicy == config.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE {
			defaultInPolicy = policy.ROUTE_ACCEPT
		}
		result := &GrpcResponse{
			Data: &api.ApplyPolicy{
				DefaultImportPolicy: defaultImportPolicy,
				ImportPolicies:      resImportPolicies,
				DefaultExportPolicy: defaultExportPolicy,
				ExportPolicies:      resExportPolicies,
				DefaultInPolicy:     defaultInPolicy,
				InPolicies:          resInPolicies,
			},
		}
		grpcReq.ResponseCh <- result
		close(grpcReq.ResponseCh)

	case REQ_NEIGHBOR_POLICY_ADD_IMPORT, REQ_NEIGHBOR_POLICY_ADD_EXPORT, REQ_NEIGHBOR_POLICY_ADD_DISTRIBUTE,
		REQ_NEIGHBOR_POLICY_DEL_IMPORT, REQ_NEIGHBOR_POLICY_DEL_EXPORT, REQ_NEIGHBOR_POLICY_DEL_DISTRIBUTE:
		peer, err := server.checkNeighborRequest(grpcReq)
		if err != nil {
			break
		}
		reqApplyPolicy := grpcReq.Data.(*api.ApplyPolicy)
		reqPolicyMap := server.policyMap
		applyPolicy := &peer.conf.ApplyPolicy.ApplyPolicyConfig
		var defInPolicy, defOutPolicy, defDistPolicy config.DefaultPolicyType
		if grpcReq.RequestType == REQ_NEIGHBOR_POLICY_ADD_IMPORT {
			if reqApplyPolicy.DefaultImportPolicy != policy.ROUTE_ACCEPT {
				defInPolicy = config.DEFAULT_POLICY_TYPE_REJECT_ROUTE
			}
			applyPolicy.DefaultImportPolicy = defInPolicy
			applyPolicy.ImportPolicy = policy.PoliciesToString(reqApplyPolicy.ImportPolicies)
		} else if grpcReq.RequestType == REQ_NEIGHBOR_POLICY_ADD_EXPORT {
			if reqApplyPolicy.DefaultExportPolicy != policy.ROUTE_ACCEPT {
				defOutPolicy = config.DEFAULT_POLICY_TYPE_REJECT_ROUTE
			}
			applyPolicy.DefaultExportPolicy = defOutPolicy
			applyPolicy.ExportPolicy = policy.PoliciesToString(reqApplyPolicy.ExportPolicies)
		} else if grpcReq.RequestType == REQ_NEIGHBOR_POLICY_ADD_DISTRIBUTE {
			if reqApplyPolicy.DefaultInPolicy != policy.ROUTE_ACCEPT {
				defDistPolicy = config.DEFAULT_POLICY_TYPE_REJECT_ROUTE
			}
			applyPolicy.DefaultInPolicy = defDistPolicy
			applyPolicy.InPolicy = policy.PoliciesToString(reqApplyPolicy.InPolicies)
		} else if grpcReq.RequestType == REQ_NEIGHBOR_POLICY_DEL_IMPORT {
			applyPolicy.DefaultImportPolicy = config.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE
			applyPolicy.ImportPolicy = make([]string, 0)
		} else if grpcReq.RequestType == REQ_NEIGHBOR_POLICY_DEL_EXPORT {
			applyPolicy.DefaultExportPolicy = config.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE
			applyPolicy.ExportPolicy = make([]string, 0)
		} else if grpcReq.RequestType == REQ_NEIGHBOR_POLICY_DEL_DISTRIBUTE {
			applyPolicy.DefaultInPolicy = config.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE
			applyPolicy.InPolicy = make([]string, 0)
		}

		if grpcReq.RequestType == REQ_NEIGHBOR_POLICY_ADD_DISTRIBUTE ||
			grpcReq.RequestType == REQ_NEIGHBOR_POLICY_DEL_DISTRIBUTE {
			peer.setPolicy(reqPolicyMap)
		} else {
			loc := server.localRibMap[peer.conf.NeighborConfig.NeighborAddress.String()]
			loc.setPolicy(peer, reqPolicyMap)
		}

		grpcReq.ResponseCh <- &GrpcResponse{}
		close(grpcReq.ResponseCh)

	case REQ_POLICY_PREFIXES, REQ_POLICY_NEIGHBORS, REQ_POLICY_ASPATHS,
		REQ_POLICY_COMMUNITIES, REQ_POLICY_EXTCOMMUNITIES, REQ_POLICY_ROUTEPOLICIES:
		server.handleGrpcShowPolicies(grpcReq)
	case REQ_POLICY_PREFIX, REQ_POLICY_NEIGHBOR, REQ_POLICY_ASPATH,
		REQ_POLICY_COMMUNITY, REQ_POLICY_EXTCOMMUNITY, REQ_POLICY_ROUTEPOLICY:
		server.handleGrpcShowPolicy(grpcReq)
	case REQ_POLICY_PREFIX_ADD, REQ_POLICY_NEIGHBOR_ADD, REQ_POLICY_ASPATH_ADD,
		REQ_POLICY_COMMUNITY_ADD, REQ_POLICY_EXTCOMMUNITY_ADD, REQ_POLICY_ROUTEPOLICY_ADD:
		server.handleGrpcAddPolicy(grpcReq)
	case REQ_POLICY_PREFIX_DELETE, REQ_POLICY_NEIGHBOR_DELETE, REQ_POLICY_ASPATH_DELETE,
		REQ_POLICY_COMMUNITY_DELETE, REQ_POLICY_EXTCOMMUNITY_DELETE, REQ_POLICY_ROUTEPOLICY_DELETE:
		server.handleGrpcDelPolicy(grpcReq)
	case REQ_POLICY_PREFIXES_DELETE, REQ_POLICY_NEIGHBORS_DELETE, REQ_POLICY_ASPATHS_DELETE,
		REQ_POLICY_COMMUNITIES_DELETE, REQ_POLICY_EXTCOMMUNITIES_DELETE, REQ_POLICY_ROUTEPOLICIES_DELETE:
		server.handleGrpcDelPolicies(grpcReq)
	case REQ_MONITOR_GLOBAL_BEST_CHANGED, REQ_MONITOR_NEIGHBOR_PEER_STATE:
		server.broadcastReqs = append(server.broadcastReqs, grpcReq)
	case REQ_MRT_GLOBAL_RIB, REQ_MRT_LOCAL_RIB:
		server.handleMrt(grpcReq)
	case REQ_RPKI:
		server.roaClient.handleGRPC(grpcReq)
	case REQ_VRF, REQ_VRFS, REQ_VRF_MOD:
		pathList := server.handleVrfRequest(grpcReq)
		if len(pathList) > 0 {
			msgs = server.propagateUpdate("", false, pathList)
		}
	default:
		errmsg := fmt.Errorf("Unknown request type: %v", grpcReq.RequestType)
		result := &GrpcResponse{
			ResponseErr: errmsg,
		}
		grpcReq.ResponseCh <- result
		close(grpcReq.ResponseCh)
	}
	return msgs
}

func (server *BgpServer) handleGrpcShowPolicies(grpcReq *GrpcRequest) {
	result := &GrpcResponse{}
	switch grpcReq.RequestType {
	case REQ_POLICY_PREFIXES:
		info := server.routingPolicy.DefinedSets.PrefixSets.PrefixSetList
		if len(info) > 0 {
			for _, ps := range info {
				resPrefixSet := policy.PrefixSetToApiStruct(ps)
				pd := &api.PolicyDefinition{}
				pd.StatementList = []*api.Statement{{Conditions: &api.Conditions{MatchPrefixSet: resPrefixSet}}}
				result = &GrpcResponse{
					Data: pd,
				}
				grpcReq.ResponseCh <- result
			}
		} else {
			result.ResponseErr = fmt.Errorf("Policy prefix doesn't exist.")
			grpcReq.ResponseCh <- result
		}
	case REQ_POLICY_NEIGHBORS:
		info := server.routingPolicy.DefinedSets.NeighborSets.NeighborSetList
		if len(info) > 0 {
			for _, ns := range info {
				resNeighborSet := policy.NeighborSetToApiStruct(ns)
				pd := &api.PolicyDefinition{}
				pd.StatementList = []*api.Statement{{Conditions: &api.Conditions{MatchNeighborSet: resNeighborSet}}}
				result = &GrpcResponse{
					Data: pd,
				}
				grpcReq.ResponseCh <- result
			}
		} else {
			result.ResponseErr = fmt.Errorf("Policy neighbor doesn't exist.")
			grpcReq.ResponseCh <- result
		}
	case REQ_POLICY_ASPATHS:
		info := server.routingPolicy.DefinedSets.BgpDefinedSets.AsPathSets.AsPathSetList
		if len(info) > 0 {
			for _, as := range info {
				resAsPathSet := policy.AsPathSetToApiStruct(as)
				pd := &api.PolicyDefinition{}
				pd.StatementList = []*api.Statement{{Conditions: &api.Conditions{MatchAsPathSet: resAsPathSet}}}
				result = &GrpcResponse{
					Data: pd,
				}
				grpcReq.ResponseCh <- result
			}
		} else {
			result.ResponseErr = fmt.Errorf("Policy aspath doesn't exist.")
			grpcReq.ResponseCh <- result
		}
	case REQ_POLICY_COMMUNITIES:
		info := server.routingPolicy.DefinedSets.BgpDefinedSets.CommunitySets.CommunitySetList
		if len(info) > 0 {
			for _, cs := range info {
				resCommunitySet := policy.CommunitySetToApiStruct(cs)
				pd := &api.PolicyDefinition{}
				pd.StatementList = []*api.Statement{{Conditions: &api.Conditions{MatchCommunitySet: resCommunitySet}}}
				result = &GrpcResponse{
					Data: pd,
				}
				grpcReq.ResponseCh <- result
			}
		} else {
			result.ResponseErr = fmt.Errorf("Policy community doesn't exist.")
			grpcReq.ResponseCh <- result
		}
	case REQ_POLICY_EXTCOMMUNITIES:
		info := server.routingPolicy.DefinedSets.BgpDefinedSets.ExtCommunitySets.ExtCommunitySetList
		if len(info) > 0 {
			for _, es := range info {
				resExtcommunitySet := policy.ExtCommunitySetToApiStruct(es)
				pd := &api.PolicyDefinition{}
				pd.StatementList = []*api.Statement{{Conditions: &api.Conditions{MatchExtCommunitySet: resExtcommunitySet}}}
				result = &GrpcResponse{
					Data: pd,
				}
				grpcReq.ResponseCh <- result
			}
		} else {
			result.ResponseErr = fmt.Errorf("Policy extended community doesn't exist.")
			grpcReq.ResponseCh <- result
		}
	case REQ_POLICY_ROUTEPOLICIES:
		info := server.routingPolicy.PolicyDefinitions.PolicyDefinitionList
		df := server.routingPolicy.DefinedSets
		result := &GrpcResponse{}
		if len(info) > 0 {
			for _, pd := range info {
				resPolicyDefinition := policy.PolicyDefinitionToApiStruct(pd, df)
				result = &GrpcResponse{
					Data: resPolicyDefinition,
				}
				grpcReq.ResponseCh <- result
			}
		} else {
			result.ResponseErr = fmt.Errorf("Route Policy doesn't exist.")
			grpcReq.ResponseCh <- result
		}
	}
	close(grpcReq.ResponseCh)
}
func (server *BgpServer) handleGrpcShowPolicy(grpcReq *GrpcRequest) {
	name := grpcReq.Data.(string)
	result := &GrpcResponse{}
	switch grpcReq.RequestType {
	case REQ_POLICY_PREFIX:
		info := server.routingPolicy.DefinedSets.PrefixSets.PrefixSetList
		resPrefixSet := &api.PrefixSet{}
		for _, ps := range info {
			if ps.PrefixSetName == name {
				resPrefixSet = policy.PrefixSetToApiStruct(ps)
				break
			}
		}
		if len(resPrefixSet.PrefixList) > 0 {
			pd := &api.PolicyDefinition{}
			pd.StatementList = []*api.Statement{{Conditions: &api.Conditions{MatchPrefixSet: resPrefixSet}}}
			result = &GrpcResponse{
				Data: pd,
			}
		} else {
			result.ResponseErr = fmt.Errorf("policy prefix that has %v doesn't exist.", name)
		}
	case REQ_POLICY_NEIGHBOR:
		info := server.routingPolicy.DefinedSets.NeighborSets.NeighborSetList
		resNeighborSet := &api.NeighborSet{}
		for _, ns := range info {
			if ns.NeighborSetName == name {
				resNeighborSet = policy.NeighborSetToApiStruct(ns)
				break
			}
		}
		if len(resNeighborSet.NeighborList) > 0 {
			pd := &api.PolicyDefinition{}
			pd.StatementList = []*api.Statement{{Conditions: &api.Conditions{MatchNeighborSet: resNeighborSet}}}
			result = &GrpcResponse{
				Data: pd,
			}
		} else {
			result.ResponseErr = fmt.Errorf("policy neighbor that has %v doesn't exist.", name)
		}
	case REQ_POLICY_ASPATH:
		info := server.routingPolicy.DefinedSets.BgpDefinedSets.AsPathSets.AsPathSetList
		resAsPathSet := &api.AsPathSet{}
		for _, as := range info {
			if as.AsPathSetName == name {
				resAsPathSet = policy.AsPathSetToApiStruct(as)
				break
			}
		}
		if len(resAsPathSet.AsPathMembers) > 0 {
			pd := &api.PolicyDefinition{}
			pd.StatementList = []*api.Statement{{Conditions: &api.Conditions{MatchAsPathSet: resAsPathSet}}}
			result = &GrpcResponse{
				Data: pd,
			}
		} else {
			result.ResponseErr = fmt.Errorf("policy aspath that has %v doesn't exist.", name)
		}
	case REQ_POLICY_COMMUNITY:
		info := server.routingPolicy.DefinedSets.BgpDefinedSets.CommunitySets.CommunitySetList
		resCommunitySet := &api.CommunitySet{}
		for _, cs := range info {
			if cs.CommunitySetName == name {
				resCommunitySet = policy.CommunitySetToApiStruct(cs)
				break
			}
		}
		if len(resCommunitySet.CommunityMembers) > 0 {
			pd := &api.PolicyDefinition{}
			pd.StatementList = []*api.Statement{{Conditions: &api.Conditions{MatchCommunitySet: resCommunitySet}}}
			result = &GrpcResponse{
				Data: pd,
			}
		} else {
			result.ResponseErr = fmt.Errorf("policy community that has %v doesn't exist.", name)
		}
	case REQ_POLICY_EXTCOMMUNITY:
		info := server.routingPolicy.DefinedSets.BgpDefinedSets.ExtCommunitySets.ExtCommunitySetList
		resExtCommunitySet := &api.ExtCommunitySet{}
		for _, es := range info {
			if es.ExtCommunitySetName == name {
				resExtCommunitySet = policy.ExtCommunitySetToApiStruct(es)
				break
			}
		}
		if len(resExtCommunitySet.ExtCommunityMembers) > 0 {
			pd := &api.PolicyDefinition{}
			pd.StatementList = []*api.Statement{{Conditions: &api.Conditions{MatchExtCommunitySet: resExtCommunitySet}}}
			result = &GrpcResponse{
				Data: pd,
			}
		} else {
			result.ResponseErr = fmt.Errorf("policy extended community that has %v doesn't exist.", name)
		}
	case REQ_POLICY_ROUTEPOLICY:
		info := server.routingPolicy.PolicyDefinitions.PolicyDefinitionList
		df := server.routingPolicy.DefinedSets
		resPolicyDefinition := &api.PolicyDefinition{}
		for _, pd := range info {
			if pd.Name == name {
				resPolicyDefinition = policy.PolicyDefinitionToApiStruct(pd, df)
				break
			}
		}
		if len(resPolicyDefinition.StatementList) > 0 {
			result = &GrpcResponse{
				Data: resPolicyDefinition,
			}
		} else {
			result.ResponseErr = fmt.Errorf("Route Policy that has %v doesn't  exist.", name)
		}
	}
	grpcReq.ResponseCh <- result
	close(grpcReq.ResponseCh)
}

func (server *BgpServer) handleGrpcAddPolicy(grpcReq *GrpcRequest) {
	result := &GrpcResponse{}
	switch grpcReq.RequestType {
	case REQ_POLICY_PREFIX_ADD:
		reqPrefixSet := grpcReq.Data.(*api.PolicyDefinition).StatementList[0].Conditions.MatchPrefixSet
		conPrefixSetList := server.routingPolicy.DefinedSets.PrefixSets.PrefixSetList
		isReqPrefixSet, prefixSet := policy.PrefixSetToConfigStruct(reqPrefixSet)
		if !isReqPrefixSet {
			result.ResponseErr = fmt.Errorf("doesn't reqest of policy prefix.")
			grpcReq.ResponseCh <- result
			close(grpcReq.ResponseCh)
		}
		// If the same PrefixSet is not set, add PrefixSet of request to the end.
		// If only name of the PrefixSet is same, overwrite with PrefixSet of request
		idxPrefixSet, idxPrefix := policy.IndexOfPrefixSet(conPrefixSetList, prefixSet)
		if idxPrefixSet == -1 {
			conPrefixSetList = append(conPrefixSetList, prefixSet)
		} else {
			if idxPrefix == -1 {
				conPrefixSetList[idxPrefixSet].PrefixList =
					append(conPrefixSetList[idxPrefixSet].PrefixList, prefixSet.PrefixList[0])
			}
		}
		server.routingPolicy.DefinedSets.PrefixSets.PrefixSetList = conPrefixSetList
	case REQ_POLICY_NEIGHBOR_ADD:
		reqNeighborSet := grpcReq.Data.(*api.PolicyDefinition).StatementList[0].Conditions.MatchNeighborSet
		conNeighborSetList := server.routingPolicy.DefinedSets.NeighborSets.NeighborSetList
		isReqNeighborSet, neighborSet := policy.NeighborSetToConfigStruct(reqNeighborSet)
		if !isReqNeighborSet {
			result.ResponseErr = fmt.Errorf("doesn't reqest of policy neighbor.")
			grpcReq.ResponseCh <- result
			close(grpcReq.ResponseCh)
		}
		// If the same NeighborSet is not set, add NeighborSet of request to the end.
		// If only name of the NeighborSet is same, overwrite with NeighborSet of request
		idxNeighborSet, idxNeighbor := policy.IndexOfNeighborSet(conNeighborSetList, neighborSet)
		if idxNeighborSet == -1 {
			conNeighborSetList = append(conNeighborSetList, neighborSet)
		} else {
			if idxNeighbor == -1 {
				conNeighborSetList[idxNeighborSet].NeighborInfoList =
					append(conNeighborSetList[idxNeighborSet].NeighborInfoList, neighborSet.NeighborInfoList[0])
			}
		}
		server.routingPolicy.DefinedSets.NeighborSets.NeighborSetList = conNeighborSetList
	case REQ_POLICY_ASPATH_ADD:
		reqAsPathSet := grpcReq.Data.(*api.PolicyDefinition).StatementList[0].Conditions.MatchAsPathSet
		conAsPathSetList := server.routingPolicy.DefinedSets.BgpDefinedSets.AsPathSets.AsPathSetList
		isReqAsPathSet, asPathSet := policy.AsPathSetToConfigStruct(reqAsPathSet)
		if !isReqAsPathSet {
			result.ResponseErr = fmt.Errorf("doesn't reqest of policy aspath.")
			grpcReq.ResponseCh <- result
			close(grpcReq.ResponseCh)
		}
		// If the same AsPathSet is not set, add AsPathSet of request to the end.
		// If only name of the AsPathSet is same, overwrite with AsPathSet of request
		idxAsPathSet, idxAsPath := policy.IndexOfAsPathSet(conAsPathSetList, asPathSet)
		if idxAsPathSet == -1 {
			conAsPathSetList = append(conAsPathSetList, asPathSet)
		} else {
			if idxAsPath == -1 {
				conAsPathSetList[idxAsPathSet].AsPathList =
					append(conAsPathSetList[idxAsPathSet].AsPathList, asPathSet.AsPathList[0])
			}
		}
		server.routingPolicy.DefinedSets.BgpDefinedSets.AsPathSets.AsPathSetList = conAsPathSetList
	case REQ_POLICY_COMMUNITY_ADD:
		reqCommunitySet := grpcReq.Data.(*api.PolicyDefinition).StatementList[0].Conditions.MatchCommunitySet
		conCommunitySetList := server.routingPolicy.DefinedSets.BgpDefinedSets.CommunitySets.CommunitySetList
		isReqCommunitySet, communitySet := policy.CommunitySetToConfigStruct(reqCommunitySet)
		if !isReqCommunitySet {
			result.ResponseErr = fmt.Errorf("doesn't reqest of policy community.")
			grpcReq.ResponseCh <- result
			close(grpcReq.ResponseCh)
		}
		// If the same CommunitySet is not set, add CommunitySet of request to the end.
		// If only name of the CommunitySet is same, overwrite with CommunitySet of request
		idxCommunitySet, idxCommunity := policy.IndexOfCommunitySet(conCommunitySetList, communitySet)
		if idxCommunitySet == -1 {
			conCommunitySetList = append(conCommunitySetList, communitySet)
		} else {
			if idxCommunity == -1 {
				conCommunitySetList[idxCommunitySet].CommunityList =
					append(conCommunitySetList[idxCommunitySet].CommunityList, communitySet.CommunityList[0])
			}
		}
		server.routingPolicy.DefinedSets.BgpDefinedSets.CommunitySets.CommunitySetList = conCommunitySetList
	case REQ_POLICY_EXTCOMMUNITY_ADD:
		reqExtCommunitySet := grpcReq.Data.(*api.PolicyDefinition).StatementList[0].Conditions.MatchExtCommunitySet
		conExtCommunitySetList := server.routingPolicy.DefinedSets.BgpDefinedSets.ExtCommunitySets.ExtCommunitySetList
		isReqExtCommunitySet, extCommunitySet := policy.ExtCommunitySetToConfigStruct(reqExtCommunitySet)
		if !isReqExtCommunitySet {
			result.ResponseErr = fmt.Errorf("doesn't reqest of policy extended community.")
			grpcReq.ResponseCh <- result
			close(grpcReq.ResponseCh)
		}
		// If the same ExtCommunitySet is not set, add ExtCommunitySet of request to the end.
		// If only name of the ExtCommunitySet is same, overwrite with ExtCommunitySet of request
		idxExtCommunitySet, idxExtCommunity := policy.IndexOfExtCommunitySet(conExtCommunitySetList, extCommunitySet)
		if idxExtCommunitySet == -1 {
			conExtCommunitySetList = append(conExtCommunitySetList, extCommunitySet)
		} else {
			if idxExtCommunity == -1 {
				conExtCommunitySetList[idxExtCommunitySet].ExtCommunityList =
					append(conExtCommunitySetList[idxExtCommunitySet].ExtCommunityList, extCommunitySet.ExtCommunityList[0])
			}
		}
		server.routingPolicy.DefinedSets.BgpDefinedSets.ExtCommunitySets.ExtCommunitySetList = conExtCommunitySetList
	case REQ_POLICY_ROUTEPOLICY_ADD:
		reqPolicy := grpcReq.Data.(*api.PolicyDefinition)
		reqConditions := reqPolicy.StatementList[0].Conditions
		reqActions := reqPolicy.StatementList[0].Actions
		conPolicyList := server.routingPolicy.PolicyDefinitions.PolicyDefinitionList
		_, policyDef := policy.PolicyDefinitionToConfigStruct(reqPolicy)
		idxPolicy, idxStatement := policy.IndexOfPolicyDefinition(conPolicyList, policyDef)
		if idxPolicy == -1 {
			conPolicyList = append(conPolicyList, policyDef)
		} else {
			statement := policyDef.Statements.StatementList[0]
			if idxStatement == -1 {
				conPolicyList[idxPolicy].Statements.StatementList =
					append(conPolicyList[idxPolicy].Statements.StatementList, statement)
			} else {
				conConditions := &conPolicyList[idxPolicy].Statements.StatementList[idxStatement].Conditions
				conActions := &conPolicyList[idxPolicy].Statements.StatementList[idxStatement].Actions
				if reqConditions.MatchPrefixSet != nil {
					conConditions.MatchPrefixSet = statement.Conditions.MatchPrefixSet
				}
				if reqConditions.MatchNeighborSet != nil {
					conConditions.MatchNeighborSet = statement.Conditions.MatchNeighborSet
				}
				if reqConditions.MatchAsPathSet != nil {
					conConditions.BgpConditions.MatchAsPathSet = statement.Conditions.BgpConditions.MatchAsPathSet
				}
				if reqConditions.MatchCommunitySet != nil {
					conConditions.BgpConditions.MatchCommunitySet = statement.Conditions.BgpConditions.MatchCommunitySet
				}
				if reqConditions.MatchExtCommunitySet != nil {
					conConditions.BgpConditions.MatchExtCommunitySet = statement.Conditions.BgpConditions.MatchExtCommunitySet
				}
				if reqConditions.MatchAsPathLength != nil {
					conConditions.BgpConditions.AsPathLength = statement.Conditions.BgpConditions.AsPathLength
				}
				if reqActions.RouteAction != "" {
					conActions.RouteDisposition.AcceptRoute = statement.Actions.RouteDisposition.AcceptRoute
					conActions.RouteDisposition.RejectRoute = statement.Actions.RouteDisposition.RejectRoute
				}
				if reqActions.Community != nil {
					conActions.BgpActions.SetCommunity = statement.Actions.BgpActions.SetCommunity
				}
				if reqActions.Med != "" {
					conActions.BgpActions.SetMed = statement.Actions.BgpActions.SetMed
				}
				if reqActions.AsPrepend != nil {
					conActions.BgpActions.SetAsPathPrepend = statement.Actions.BgpActions.SetAsPathPrepend
				}
			}
		}
		server.routingPolicy.PolicyDefinitions.PolicyDefinitionList = conPolicyList
	}
	server.handlePolicy(server.routingPolicy)
	grpcReq.ResponseCh <- result
	close(grpcReq.ResponseCh)
}

func (server *BgpServer) handleGrpcDelPolicy(grpcReq *GrpcRequest) {
	result := &GrpcResponse{}
	switch grpcReq.RequestType {
	case REQ_POLICY_PREFIX_DELETE:
		reqPrefixSet := grpcReq.Data.(*api.PolicyDefinition).StatementList[0].Conditions.MatchPrefixSet
		conPrefixSetList := server.routingPolicy.DefinedSets.PrefixSets.PrefixSetList
		isReqPrefixSet, prefixSet := policy.PrefixSetToConfigStruct(reqPrefixSet)
		if isReqPrefixSet {
			// If only name of the PrefixSet is same, delete all of the elements of the PrefixSet.
			// If the same element PrefixSet, delete the it's element from PrefixSet.
			idxPrefixSet, idxPrefix := policy.IndexOfPrefixSet(conPrefixSetList, prefixSet)
			prefix := prefixSet.PrefixList[0]
			if idxPrefixSet == -1 {
				result.ResponseErr = fmt.Errorf("Policy prefix that has %v %v %v doesn't exist.", prefixSet.PrefixSetName,
					prefix.IpPrefix, prefix.MasklengthRange)
			} else {
				if idxPrefix == -1 {
					result.ResponseErr = fmt.Errorf("Policy prefix that has %v %v %v doesn't exist.", prefixSet.PrefixSetName,
						prefix.IpPrefix, prefix.MasklengthRange)
				} else {
					conPrefixSetList[idxPrefixSet].PrefixList =
						append(conPrefixSetList[idxPrefixSet].PrefixList[:idxPrefix], conPrefixSetList[idxPrefixSet].PrefixList[idxPrefix+1:]...)
				}
			}
		} else {
			idxPrefixSet := -1
			for i, conPrefixSet := range conPrefixSetList {
				if conPrefixSet.PrefixSetName == reqPrefixSet.PrefixSetName {
					idxPrefixSet = i
					break
				}
			}
			if idxPrefixSet == -1 {
				result.ResponseErr = fmt.Errorf("Policy prefix that has %v doesn't exist.", prefixSet.PrefixSetName)
			} else {
				conPrefixSetList = append(conPrefixSetList[:idxPrefixSet], conPrefixSetList[idxPrefixSet+1:]...)
			}
		}
		server.routingPolicy.DefinedSets.PrefixSets.PrefixSetList = conPrefixSetList
	case REQ_POLICY_NEIGHBOR_DELETE:
		reqNeighborSet := grpcReq.Data.(*api.PolicyDefinition).StatementList[0].Conditions.MatchNeighborSet
		conNeighborSetList := server.routingPolicy.DefinedSets.NeighborSets.NeighborSetList
		isReqNeighborSet, neighborSet := policy.NeighborSetToConfigStruct(reqNeighborSet)
		if isReqNeighborSet {
			// If only name of the NeighborSet is same, delete all of the elements of the NeighborSet.
			// If the same element NeighborSet, delete the it's element from NeighborSet.
			idxNeighborSet, idxNeighbor := policy.IndexOfNeighborSet(conNeighborSetList, neighborSet)
			if idxNeighborSet == -1 {
				result.ResponseErr = fmt.Errorf("Policy neighbor that has %v %v doesn't exist.", neighborSet.NeighborSetName,
					neighborSet.NeighborInfoList[0].Address)
			} else {
				if idxNeighbor == -1 {
					result.ResponseErr = fmt.Errorf("Policy neighbor that has %v %v doesn't exist.", neighborSet.NeighborSetName,
						neighborSet.NeighborInfoList[0].Address)
				} else {
					conNeighborSetList[idxNeighborSet].NeighborInfoList =
						append(conNeighborSetList[idxNeighborSet].NeighborInfoList[:idxNeighbor],
							conNeighborSetList[idxNeighborSet].NeighborInfoList[idxNeighbor+1:]...)
				}
			}
		} else {
			idxNeighborSet := -1
			for i, conNeighborSet := range conNeighborSetList {
				if conNeighborSet.NeighborSetName == reqNeighborSet.NeighborSetName {
					idxNeighborSet = i
					break
				}
			}
			if idxNeighborSet == -1 {
				result.ResponseErr = fmt.Errorf("Policy neighbor %v doesn't  exist.", neighborSet.NeighborSetName)
			} else {
				conNeighborSetList = append(conNeighborSetList[:idxNeighborSet], conNeighborSetList[idxNeighborSet+1:]...)
			}
		}
		server.routingPolicy.DefinedSets.NeighborSets.NeighborSetList = conNeighborSetList
	case REQ_POLICY_ASPATH_DELETE:
		reqAsPathSet := grpcReq.Data.(*api.PolicyDefinition).StatementList[0].Conditions.MatchAsPathSet
		conAsPathSetList := server.routingPolicy.DefinedSets.BgpDefinedSets.AsPathSets.AsPathSetList
		result := &GrpcResponse{}
		isReqAsPathSet, asPathSet := policy.AsPathSetToConfigStruct(reqAsPathSet)
		// If only name of the AsPathSet is same, delete all of the elements of the AsPathSet.
		// If the same element AsPathSet, delete the it's element from AsPathSet.
		idxAsPathSet, idxAsPath := policy.IndexOfAsPathSet(conAsPathSetList, asPathSet)
		if isReqAsPathSet {
			if idxAsPathSet == -1 {
				result.ResponseErr = fmt.Errorf("Policy aspath that has %v %v doesn't exist.", asPathSet.AsPathSetName,
					asPathSet.AsPathList[0].AsPath)
			} else {
				if idxAsPath == -1 {
					result.ResponseErr = fmt.Errorf("Policy aspath that has %v %v doesn't exist.", asPathSet.AsPathSetName,
						asPathSet.AsPathList[0].AsPath)
				} else {
					conAsPathSetList[idxAsPathSet].AsPathList =
						append(conAsPathSetList[idxAsPathSet].AsPathList[:idxAsPath],
							conAsPathSetList[idxAsPathSet].AsPathList[idxAsPath+1:]...)
				}
			}
		} else {
			if idxAsPathSet == -1 {
				result.ResponseErr = fmt.Errorf("Policy aspath %v doesn't  exist.", asPathSet.AsPathSetName)
			} else {
				conAsPathSetList = append(conAsPathSetList[:idxAsPathSet], conAsPathSetList[idxAsPathSet+1:]...)
			}
		}
		server.routingPolicy.DefinedSets.BgpDefinedSets.AsPathSets.AsPathSetList = conAsPathSetList
	case REQ_POLICY_COMMUNITY_DELETE:
		reqCommunitySet := grpcReq.Data.(*api.PolicyDefinition).StatementList[0].Conditions.MatchCommunitySet
		conCommunitySetList := server.routingPolicy.DefinedSets.BgpDefinedSets.CommunitySets.CommunitySetList
		isReqCommunitySet, CommunitySet := policy.CommunitySetToConfigStruct(reqCommunitySet)
		// If only name of the CommunitySet is same, delete all of the elements of the CommunitySet.
		// If the same element CommunitySet, delete the it's element from CommunitySet.
		idxCommunitySet, idxCommunity := policy.IndexOfCommunitySet(conCommunitySetList, CommunitySet)
		if isReqCommunitySet {
			if idxCommunitySet == -1 {
				result.ResponseErr = fmt.Errorf("Policy community that has %v %v doesn't exist.", CommunitySet.CommunitySetName,
					CommunitySet.CommunityList[0].Community)
			} else {
				if idxCommunity == -1 {
					result.ResponseErr = fmt.Errorf("Policy community that has %v %v doesn't exist.", CommunitySet.CommunitySetName,
						CommunitySet.CommunityList[0].Community)
				} else {
					conCommunitySetList[idxCommunitySet].CommunityList =
						append(conCommunitySetList[idxCommunitySet].CommunityList[:idxCommunity],
							conCommunitySetList[idxCommunitySet].CommunityList[idxCommunity+1:]...)
				}
			}
		} else {
			if idxCommunitySet == -1 {
				result.ResponseErr = fmt.Errorf("Policy community %v doesn't  exist.", CommunitySet.CommunitySetName)
			} else {
				conCommunitySetList = append(conCommunitySetList[:idxCommunitySet], conCommunitySetList[idxCommunitySet+1:]...)
			}
		}
		server.routingPolicy.DefinedSets.BgpDefinedSets.CommunitySets.CommunitySetList = conCommunitySetList
	case REQ_POLICY_EXTCOMMUNITY_DELETE:
		reqExtCommunitySet := grpcReq.Data.(*api.PolicyDefinition).StatementList[0].Conditions.MatchExtCommunitySet
		conExtCommunitySetList := server.routingPolicy.DefinedSets.BgpDefinedSets.ExtCommunitySets.ExtCommunitySetList
		isReqExtCommunitySet, ExtCommunitySet := policy.ExtCommunitySetToConfigStruct(reqExtCommunitySet)
		// If only name of the ExtCommunitySet is same, delete all of the elements of the ExtCommunitySet.
		// If the same element ExtCommunitySet, delete the it's element from ExtCommunitySet.
		idxExtCommunitySet, idxExtCommunity := policy.IndexOfExtCommunitySet(conExtCommunitySetList, ExtCommunitySet)
		if isReqExtCommunitySet {
			if idxExtCommunitySet == -1 {
				result.ResponseErr = fmt.Errorf("Policy extended community that has %v %v doesn't exist.",
					ExtCommunitySet.ExtCommunitySetName, ExtCommunitySet.ExtCommunityList[0].ExtCommunity)
			} else {
				if idxExtCommunity == -1 {
					result.ResponseErr = fmt.Errorf("Policy extended community that has %v %v doesn't exist.",
						ExtCommunitySet.ExtCommunitySetName, ExtCommunitySet.ExtCommunityList[0].ExtCommunity)
				} else {
					conExtCommunitySetList[idxExtCommunitySet].ExtCommunityList =
						append(conExtCommunitySetList[idxExtCommunitySet].ExtCommunityList[:idxExtCommunity],
							conExtCommunitySetList[idxExtCommunitySet].ExtCommunityList[idxExtCommunity+1:]...)
				}
			}
		} else {
			if idxExtCommunitySet == -1 {
				result.ResponseErr = fmt.Errorf("Policy extended community %v doesn't  exist.",
					ExtCommunitySet.ExtCommunitySetName)
			} else {
				conExtCommunitySetList =
					append(conExtCommunitySetList[:idxExtCommunitySet], conExtCommunitySetList[idxExtCommunitySet+1:]...)
			}
		}
		server.routingPolicy.DefinedSets.BgpDefinedSets.ExtCommunitySets.ExtCommunitySetList = conExtCommunitySetList
	case REQ_POLICY_ROUTEPOLICY_DELETE:
		reqPolicy := grpcReq.Data.(*api.PolicyDefinition)
		conPolicyList := server.routingPolicy.PolicyDefinitions.PolicyDefinitionList
		isStatement, policyDef := policy.PolicyDefinitionToConfigStruct(reqPolicy)
		idxPolicy, idxStatement := policy.IndexOfPolicyDefinition(conPolicyList, policyDef)
		if isStatement {
			if idxPolicy == -1 {
				result.ResponseErr = fmt.Errorf("Policy that has %v doesn't exist.", policyDef.Name)
			} else {
				if idxStatement == -1 {
					result.ResponseErr = fmt.Errorf("Policy Statment that has %v doesn't exist.", policyDef.Statements.StatementList[0].Name)
				} else {
					conPolicyList[idxPolicy].Statements.StatementList =
						append(conPolicyList[idxPolicy].Statements.StatementList[:idxStatement], conPolicyList[idxPolicy].Statements.StatementList[idxStatement+1:]...)
				}
			}
		} else {
			idxPolicy := -1
			for i, conPolicy := range conPolicyList {
				if conPolicy.Name == reqPolicy.PolicyDefinitionName {
					idxPolicy = i
					break
				}
			}
			if idxPolicy == -1 {
				result.ResponseErr = fmt.Errorf("Policy that has %v doesn't exist.", policyDef.Name)
			} else {
				conPolicyList = append(conPolicyList[:idxPolicy], conPolicyList[idxPolicy+1:]...)
			}
		}
		server.routingPolicy.PolicyDefinitions.PolicyDefinitionList = conPolicyList
	}
	server.handlePolicy(server.routingPolicy)
	grpcReq.ResponseCh <- result
	close(grpcReq.ResponseCh)
}

func (server *BgpServer) handleGrpcDelPolicies(grpcReq *GrpcRequest) {
	result := &GrpcResponse{}
	definedSets := &server.routingPolicy.DefinedSets
	switch grpcReq.RequestType {
	case REQ_POLICY_PREFIXES_DELETE:
		definedSets.PrefixSets.PrefixSetList = make([]config.PrefixSet, 0)
	case REQ_POLICY_NEIGHBORS_DELETE:
		definedSets.NeighborSets.NeighborSetList = make([]config.NeighborSet, 0)
	case REQ_POLICY_ASPATHS_DELETE:
		definedSets.BgpDefinedSets.AsPathSets.AsPathSetList = make([]config.AsPathSet, 0)
	case REQ_POLICY_COMMUNITIES_DELETE:
		definedSets.BgpDefinedSets.CommunitySets.CommunitySetList = make([]config.CommunitySet, 0)
	case REQ_POLICY_EXTCOMMUNITIES_DELETE:
		definedSets.BgpDefinedSets.ExtCommunitySets.ExtCommunitySetList = make([]config.ExtCommunitySet, 0)
	case REQ_POLICY_ROUTEPOLICIES_DELETE:
		server.routingPolicy.PolicyDefinitions.PolicyDefinitionList = make([]config.PolicyDefinition, 0)
	}
	server.handlePolicy(server.routingPolicy)
	grpcReq.ResponseCh <- result
	close(grpcReq.ResponseCh)
}

func (server *BgpServer) handleMrt(grpcReq *GrpcRequest) {
	now := uint32(time.Now().Unix())
	view := ""
	result := &GrpcResponse{}
	var manager *table.TableManager

	switch grpcReq.RequestType {
	case REQ_MRT_GLOBAL_RIB:
		manager = server.localRibMap[GLOBAL_RIB_NAME].rib
	case REQ_MRT_LOCAL_RIB:
		_, err := server.checkNeighborRequest(grpcReq)
		if err != nil {
			return
		}
		loc, ok := server.localRibMap[grpcReq.Name]
		if !ok {
			result.ResponseErr = fmt.Errorf("no local rib for %s", grpcReq.Name)
			grpcReq.ResponseCh <- result
			close(grpcReq.ResponseCh)
			return
		}
		manager = loc.rib
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

	tbl, ok := manager.Tables[grpcReq.RouteFamily]
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
		id := peer.peerInfo.ID.To4().String()
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
			if peer.peerInfo.Equal(info) {
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

func (server *BgpServer) NewZclient(url string) error {
	l := strings.SplitN(url, ":", 2)
	if len(l) != 2 {
		return fmt.Errorf("unsupported url: %s", url)
	}
	cli, err := zebra.NewClient(l[0], l[1], zebra.ROUTE_BGP)
	if err != nil {
		return err
	}
	cli.SendHello()
	server.zclient = cli
	return nil
}
