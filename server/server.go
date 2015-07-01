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
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/policy"
	"github.com/osrg/gobgp/table"
	"gopkg.in/tomb.v2"
	"net"
	"os"
	"strconv"
	"time"
)

const (
	GLOBAL_RIB_NAME = "global"
)

type Direction string

const (
	POLICY_DIRECTION_IMPORT     Direction = "import"
	POLICY_DIRECTION_EXPORT               = "export"
	POLICY_DIRECTION_DISTRIBUTE           = "distribute"
)

type SenderMsg struct {
	messages    []*bgp.BGPMessage
	sendCh      chan *bgp.BGPMessage
	destination string
	twoBytesAs  bool
}

type BgpServer struct {
	bgpConfig      config.Bgp
	globalTypeCh   chan config.Global
	addedPeerCh    chan config.Neighbor
	deletedPeerCh  chan config.Neighbor
	GrpcReqCh      chan *GrpcRequest
	listenPort     int
	policyUpdateCh chan config.RoutingPolicy
	policyMap      map[string]*policy.Policy
	routingPolicy  config.RoutingPolicy
	broadcastReqs  []*GrpcRequest

	neighborMap map[string]*Peer
	localRibMap map[string]*LocalRib
}

func NewBgpServer(port int) *BgpServer {
	b := BgpServer{}
	b.globalTypeCh = make(chan config.Global)
	b.addedPeerCh = make(chan config.Neighbor)
	b.deletedPeerCh = make(chan config.Neighbor)
	b.GrpcReqCh = make(chan *GrpcRequest, 1)
	b.policyUpdateCh = make(chan config.RoutingPolicy)
	b.localRibMap = make(map[string]*LocalRib)
	b.neighborMap = make(map[string]*Peer)
	b.listenPort = port
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

	// FIXME
	rfList := func(l []config.AfiSafi) []bgp.RouteFamily {
		rfList := []bgp.RouteFamily{}
		for _, rf := range l {
			k, _ := bgp.GetRouteFamily(rf.AfiSafiName)
			rfList = append(rfList, k)
		}
		return rfList
	}(g.AfiSafiList)

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
	for {
		var firstMsg *SenderMsg
		var sCh chan *SenderMsg
		if len(senderMsgs) > 0 {
			sCh = senderCh
			firstMsg = senderMsgs[0]
		}
		select {
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
			addr := config.NeighborAddress.String()
			_, found := server.neighborMap[addr]
			if found {
				log.Warn("Can't overwrite the exising peer ", addr)
				continue
			}

			SetTcpMD5SigSockopts(listener(config.NeighborAddress), addr, config.AuthPassword)

			peer := NewPeer(g, config)
			name := config.NeighborAddress.String()

			if config.RouteServer.RouteServerClient == true {
				loc := NewLocalRib(name, peer.configuredRFlist(), make(map[string]*policy.Policy))
				server.addLocalRib(loc)
				loc.setPolicy(peer, server.policyMap)
				// set distribute policy
				peer.setDistributePolicy(server.policyMap)

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
			addr := config.NeighborAddress.String()
			SetTcpMD5SigSockopts(listener(config.NeighborAddress), addr, "")
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
		destination: peer.config.NeighborAddress.String(),
		twoBytesAs:  y,
	}
}

func filterpath(peer *Peer, pathList []*table.Path) []*table.Path {
	filtered := make([]*table.Path, 0)

	for _, path := range pathList {
		if _, ok := peer.rfMap[path.GetRouteFamily()]; !ok {
			continue
		}

		if peer.config.NeighborAddress.Equal(path.GetSource().Address) {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.config.NeighborAddress,
				"Data":  path,
			}).Debug("From me, ignore.")
			continue
		}

		if peer.config.PeerAs == path.GetSourceAs() {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.config.NeighborAddress,
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
				if loc.isGlobal() || loc.OwnerName() == peer.config.NeighborAddress.String() {
					continue
				}
				pathList, _ := loc.rib.DeletePathsforPeer(peer.peerInfo, rf)
				pathList = dropSameAsPath(targetPeer.config.PeerAs, pathList)
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
	case POLICY_DIRECTION_DISTRIBUTE:
		defaultPolicy = peer.defaultDistributePolicy
	default:
		log.WithFields(log.Fields{
			"Topic": "Server",
			"Key":   peer.config.NeighborAddress,
		}).Error("direction is not specified.")
		return ret
	}

	for _, path := range pathList {
		if !path.IsWithdraw {
			var applied bool = false
			if d == POLICY_DIRECTION_DISTRIBUTE {
				applied, path = peer.applyDistributePolicies(path)
			} else {
				applied, path = loc.applyPolicies(d, path)
			}

			if applied {
				if path == nil {
					log.WithFields(log.Fields{
						"Topic": "Peer",
						"Key":   peer.config.NeighborAddress,
						"Data":  path,
					}).Debug("Policy applied and rejected.")
					continue
				}
			} else if defaultPolicy != config.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE {
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   peer.config.NeighborAddress,
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
		result := &GrpcResponse{
			Data: path.ToApiStruct(),
		}
		remainReqs := make([]*GrpcRequest, 0, len(server.broadcastReqs))
		for _, req := range server.broadcastReqs {
			if req.RequestType != REQ_MONITOR_GLOBAL_BEST_CHANGED {
				remainReqs = append(remainReqs, req)
				continue
			}
			select {
			case <-req.EndCh:
				continue
			case req.ResponseCh <- result:
			default:
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
		ignore := req.RequestType != REQ_MONITOR_NEIGHBOR_PEER_STATE
		ignore = ignore || (req.RemoteAddr != "" && req.RemoteAddr != peer.config.NeighborAddress.String())
		if ignore {
			remainReqs = append(remainReqs, req)
			continue
		}
		select {
		case <-req.EndCh:
			continue
		case req.ResponseCh <- result:
		default:
		}
		remainReqs = append(remainReqs, req)
	}
	server.broadcastReqs = remainReqs
}

func (server *BgpServer) propagateUpdate(neighborAddress string, RouteServerClient bool, pathList []*table.Path) []*SenderMsg {
	msgs := make([]*SenderMsg, 0)

	if RouteServerClient {
		p := server.neighborMap[neighborAddress]
		newPathList := applyPolicies(p, nil, POLICY_DIRECTION_DISTRIBUTE, pathList)
		for _, loc := range server.localRibMap {
			targetPeer := server.neighborMap[loc.OwnerName()]
			if loc.isGlobal() || loc.OwnerName() == neighborAddress {
				continue
			}
			sendPathList, _ := loc.rib.ProcessPaths(applyPolicies(targetPeer, loc, POLICY_DIRECTION_IMPORT, dropSameAsPath(targetPeer.config.PeerAs, filterpath(targetPeer, newPathList))))
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
			for _, path := range f {
				path.SetNexthop(targetPeer.config.LocalAddress)
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
		oldState := bgp.FSMState(peer.config.BgpNeighborCommonState.State)
		go func(t *tomb.Tomb, addr string, oldState, newState bgp.FSMState) {
			e := time.AfterFunc(time.Second*30, func() { log.Fatal("failed to free the fsm.h.t for ", addr, oldState, newState) })
			t.Wait()
			e.Stop()
		}(&peer.fsm.h.t, peer.config.NeighborAddress.String(), oldState, nextState)
		peer.config.BgpNeighborCommonState.State = uint32(nextState)
		peer.fsm.StateChange(nextState)
		globalRib := server.localRibMap[GLOBAL_RIB_NAME]

		if oldState == bgp.BGP_FSM_ESTABLISHED {
			t := time.Now()
			if t.Sub(time.Unix(peer.config.BgpNeighborCommonState.Uptime, 0)) < FLOP_THRESHOLD {
				peer.config.BgpNeighborCommonState.Flops++
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
				loc := server.localRibMap[peer.config.NeighborAddress.String()]
				pathList = applyPolicies(peer, loc, POLICY_DIRECTION_EXPORT, peer.getBests(loc))
			} else {
				peer.config.LocalAddress = peer.fsm.LocalAddr()
				for _, path := range peer.getBests(globalRib) {
					p := path.Clone(path.IsWithdraw)
					p.SetNexthop(peer.config.LocalAddress)
					pathList = append(pathList, p)
				}
			}
			if len(pathList) > 0 {
				peer.adjRib.UpdateOut(pathList)
				msgs = append(msgs, newSenderMsg(peer, table.CreateUpdateMsgFromPaths(pathList)))
			}
		} else {
			peer.config.BgpNeighborCommonState.Downtime = time.Now().Unix()
		}
		// clear counter
		if peer.fsm.adminState == ADMIN_STATE_DOWN {
			peer.config.BgpNeighborCommonState = config.BgpNeighborCommonState{}
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
			}
			msgs = append(msgs, server.propagateUpdate(peer.config.NeighborAddress.String(),
				peer.isRouteServerClient(), pathList)...)
		default:
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.config.NeighborAddress,
				"Data":  e.MsgData,
			}).Panic("unknonw msg type")
		}
	}
	return msgs
}

func (server *BgpServer) SetGlobalType(g config.Global) {
	server.globalTypeCh <- g
}

func (server *BgpServer) PeerAdd(peer config.Neighbor) {
	server.addedPeerCh <- peer
}

func (server *BgpServer) PeerDelete(peer config.Neighbor) {
	server.deletedPeerCh <- peer
}

func (server *BgpServer) UpdatePolicy(policy config.RoutingPolicy) {
	server.policyUpdateCh <- policy
}

func (server *BgpServer) SetPolicy(pl config.RoutingPolicy) {
	pMap := make(map[string]*policy.Policy)
	df := pl.DefinedSets
	for _, p := range pl.PolicyDefinitionList {
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
			"Key":   targetPeer.config.NeighborAddress,
		}).Info("call set policy")
		loc.setPolicy(targetPeer, server.policyMap)
		// set distribute policy
		targetPeer.setDistributePolicy(server.policyMap)
	}
}

func (server *BgpServer) checkNeighborRequest(grpcReq *GrpcRequest) (*Peer, error) {
	remoteAddr := grpcReq.RemoteAddr
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

func handleGlobalRibRequest(grpcReq *GrpcRequest, peerInfo *table.PeerInfo) []*table.Path {
	pathList := []*table.Path{}
	result := &GrpcResponse{}

	rf := grpcReq.RouteFamily
	path, ok := grpcReq.Data.(*api.Path)
	if !ok {
		result.ResponseErr = fmt.Errorf("type assertion failed")
		grpcReq.ResponseCh <- result
		close(grpcReq.ResponseCh)
		return pathList
	}
	var isWithdraw bool
	if grpcReq.RequestType == REQ_GLOBAL_DELETE {
		isWithdraw = true
	}

	var nlri bgp.AddrPrefixInterface
	pattr := make([]bgp.PathAttributeInterface, 0)
	pattr = append(pattr, bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP))
	asparam := bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{peerInfo.AS})
	pattr = append(pattr, bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{asparam}))

	switch rf {
	case bgp.RF_IPv4_UC:
		ip, net, _ := net.ParseCIDR(path.Nlri.Prefix)
		if ip.To4() == nil {
			result.ResponseErr = fmt.Errorf("Invalid ipv4 prefix: %s", path.Nlri.Prefix)
			grpcReq.ResponseCh <- result
			close(grpcReq.ResponseCh)
			return pathList
		}
		ones, _ := net.Mask.Size()
		nlri = &bgp.NLRInfo{
			IPAddrPrefix: *bgp.NewIPAddrPrefix(uint8(ones), ip.String()),
		}

		pattr = append(pattr, bgp.NewPathAttributeNextHop("0.0.0.0"))

	case bgp.RF_IPv6_UC:

		ip, net, _ := net.ParseCIDR(path.Nlri.Prefix)
		if ip.To16() == nil {
			result.ResponseErr = fmt.Errorf("Invalid ipv6 prefix: %s", path.Nlri.Prefix)
			grpcReq.ResponseCh <- result
			close(grpcReq.ResponseCh)
			return pathList
		}
		ones, _ := net.Mask.Size()
		nlri = bgp.NewIPv6AddrPrefix(uint8(ones), ip.String())

		pattr = append(pattr, bgp.NewPathAttributeMpReachNLRI("::", []bgp.AddrPrefixInterface{nlri}))

	case bgp.RF_EVPN:
		mac, err := net.ParseMAC(path.Nlri.EvpnNlri.MacIpAdv.MacAddr)
		if err != nil {
			result.ResponseErr = fmt.Errorf("Invalid mac: %s", path.Nlri.EvpnNlri.MacIpAdv.MacAddr)
			grpcReq.ResponseCh <- result
			close(grpcReq.ResponseCh)
			return pathList
		}
		ip := net.ParseIP(path.Nlri.EvpnNlri.MacIpAdv.IpAddr)
		if ip == nil {
			result.ResponseErr = fmt.Errorf("Invalid ip prefix: %s", path.Nlri.EvpnNlri.MacIpAdv.IpAddr)
			grpcReq.ResponseCh <- result
			close(grpcReq.ResponseCh)
			return pathList
		}
		iplen := net.IPv4len * 8
		if ip.To4() == nil {
			iplen = net.IPv6len * 8
		}

		macIpAdv := &bgp.EVPNMacIPAdvertisementRoute{
			RD: bgp.NewRouteDistinguisherTwoOctetAS(0, 0),
			ESI: bgp.EthernetSegmentIdentifier{
				Type: bgp.ESI_ARBITRARY,
			},
			MacAddressLength: 48,
			MacAddress:       mac,
			IPAddressLength:  uint8(iplen),
			IPAddress:        ip,
			Labels:           []uint32{0},
		}
		nlri = bgp.NewEVPNNLRI(bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT, 0, macIpAdv)
		pattr = append(pattr, bgp.NewPathAttributeMpReachNLRI("0.0.0.0", []bgp.AddrPrefixInterface{nlri}))
	case bgp.RF_ENCAP:
		endpoint := net.ParseIP(path.Nlri.Prefix)
		if endpoint == nil {
			result.ResponseErr = fmt.Errorf("Invalid endpoint ip address: %s", path.Nlri.Prefix)
			grpcReq.ResponseCh <- result
			close(grpcReq.ResponseCh)
			return pathList

		}
		nlri = bgp.NewEncapNLRI(endpoint.String())
		pattr = append(pattr, bgp.NewPathAttributeMpReachNLRI("0.0.0.0", []bgp.AddrPrefixInterface{nlri}))

		iterSubTlvs := func(subTlvs []*api.TunnelEncapSubTLV) {
			for _, subTlv := range subTlvs {
				if subTlv.Type == api.ENCAP_SUBTLV_TYPE_COLOR {
					color := subTlv.Color
					subTlv := &bgp.TunnelEncapSubTLV{
						Type:  bgp.ENCAP_SUBTLV_TYPE_COLOR,
						Value: &bgp.TunnelEncapSubTLVColor{color},
					}
					tlv := &bgp.TunnelEncapTLV{
						Type:  bgp.TUNNEL_TYPE_VXLAN,
						Value: []*bgp.TunnelEncapSubTLV{subTlv},
					}
					attr := bgp.NewPathAttributeTunnelEncap([]*bgp.TunnelEncapTLV{tlv})
					pattr = append(pattr, attr)
					break
				}
			}
		}

		iterTlvs := func(tlvs []*api.TunnelEncapTLV) {
			for _, tlv := range tlvs {
				if tlv.Type == api.TUNNEL_TYPE_VXLAN {
					iterSubTlvs(tlv.SubTlv)
					break
				}
			}
		}

		func(attrs []*api.PathAttr) {
			for _, attr := range attrs {
				if attr.Type == api.BGP_ATTR_TYPE_TUNNEL_ENCAP {
					iterTlvs(attr.TunnelEncap)
					break
				}
			}
		}(path.Attrs)

	case bgp.RF_RTC_UC:
		var ec bgp.ExtendedCommunityInterface
		target := path.Nlri.RtNlri.Target
		ec_type := target.Type
		ec_subtype := target.Subtype
		switch ec_type {
		case api.EXTENDED_COMMUNITIE_TYPE_TWO_OCTET_AS_SPECIFIC:
			if target.Asn == 0 && target.LocalAdmin == 0 {
				break
			}
			ec = &bgp.TwoOctetAsSpecificExtended{
				SubType:      bgp.ExtendedCommunityAttrSubType(ec_subtype),
				AS:           uint16(target.Asn),
				LocalAdmin:   target.LocalAdmin,
				IsTransitive: true,
			}
		default:
			result.ResponseErr = fmt.Errorf("Invalid endpoint ip address: %s", path.Nlri.Prefix)
			grpcReq.ResponseCh <- result
			close(grpcReq.ResponseCh)
			return pathList
		}

		nlri = bgp.NewRouteTargetMembershipNLRI(peerInfo.AS, ec)

		pattr = append(pattr, bgp.NewPathAttributeMpReachNLRI("0.0.0.0", []bgp.AddrPrefixInterface{nlri}))

	default:
		result.ResponseErr = fmt.Errorf("Unsupported address family: %s", rf)
		grpcReq.ResponseCh <- result
		close(grpcReq.ResponseCh)
		return pathList
	}

	p := table.NewPath(peerInfo, nlri, isWithdraw, pattr, false, time.Now())
	return []*table.Path{p}
}

func (server *BgpServer) handleGrpc(grpcReq *GrpcRequest) []*SenderMsg {
	msgs := make([]*SenderMsg, 0)

	switch grpcReq.RequestType {
	case REQ_GLOBAL_RIB:
		if t, ok := server.localRibMap[GLOBAL_RIB_NAME].rib.Tables[grpcReq.RouteFamily]; ok {
			for _, dst := range t.GetDestinations() {
				result := &GrpcResponse{}
				result.Data = dst.ToApiStruct()
				grpcReq.ResponseCh <- result
			}
		}
		close(grpcReq.ResponseCh)

	case REQ_GLOBAL_ADD, REQ_GLOBAL_DELETE:
		pi := &table.PeerInfo{
			AS:      server.bgpConfig.Global.As,
			LocalID: server.bgpConfig.Global.RouterId,
		}
		pathList := handleGlobalRibRequest(grpcReq, pi)
		if len(pathList) > 0 {
			msgs = append(msgs, server.propagateUpdate("", false, pathList)...)
			grpcReq.ResponseCh <- &GrpcResponse{}
			close(grpcReq.ResponseCh)
		}

	case REQ_NEIGHBORS:
		for _, peer := range server.neighborMap {
			result := &GrpcResponse{
				Data: peer.ToApiStruct(),
			}
			grpcReq.ResponseCh <- result
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

	case REQ_LOCAL_RIB:
		peer, err := server.checkNeighborRequest(grpcReq)
		if err != nil {
			break
		}
		if peer.fsm.adminState != ADMIN_STATE_DOWN {
			remoteAddr := grpcReq.RemoteAddr
			if t, ok := server.localRibMap[remoteAddr].rib.Tables[grpcReq.RouteFamily]; ok {
				for _, dst := range t.GetDestinations() {
					result := &GrpcResponse{}
					result.Data = dst.ToApiStruct()
					grpcReq.ResponseCh <- result
				}
			}
		}
		close(grpcReq.ResponseCh)

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

		for _, p := range paths {
			result := &GrpcResponse{}
			result.Data = p.ToApiStruct()
			grpcReq.ResponseCh <- result
		}
		close(grpcReq.ResponseCh)

	case REQ_NEIGHBOR_SHUTDOWN:
		peer, err := server.checkNeighborRequest(grpcReq)
		if err != nil {
			break
		}
		m := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN, nil)
		msgs = append(msgs, newSenderMsg(peer, []*bgp.BGPMessage{m}))
		grpcReq.ResponseCh <- &GrpcResponse{}
		close(grpcReq.ResponseCh)

	case REQ_NEIGHBOR_RESET:
		peer, err := server.checkNeighborRequest(grpcReq)
		if err != nil {
			break
		}
		peer.fsm.idleHoldTime = peer.config.Timers.IdleHoldTimeAfterReset
		m := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET, nil)
		msgs = append(msgs, newSenderMsg(peer, []*bgp.BGPMessage{m}))
		grpcReq.ResponseCh <- &GrpcResponse{}
		close(grpcReq.ResponseCh)

	case REQ_NEIGHBOR_SOFT_RESET, REQ_NEIGHBOR_SOFT_RESET_IN:
		peer, err := server.checkNeighborRequest(grpcReq)
		if err != nil {
			break
		}
		// soft-reconfiguration inbound
		pathList := peer.adjRib.GetInPathList(grpcReq.RouteFamily)
		msgs = append(msgs, server.propagateUpdate(peer.config.NeighborAddress.String(),
			peer.isRouteServerClient(), pathList)...)

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
		msgs = append(msgs, newSenderMsg(peer, msgList))
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
					"Key":   peer.config.NeighborAddress,
				}).Debug("ADMIN_STATE_UP requested")
				err.Code = api.Error_SUCCESS
				err.Msg = "ADMIN_STATE_UP"
			default:
				log.Warning("previous request is still remaining. : ", peer.config.NeighborAddress)
				err.Code = api.Error_FAIL
				err.Msg = "previous request is still remaining"
			}
		} else {
			select {
			case peer.fsm.adminStateCh <- ADMIN_STATE_DOWN:
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   peer.config.NeighborAddress,
				}).Debug("ADMIN_STATE_DOWN requested")
				err.Code = api.Error_SUCCESS
				err.Msg = "ADMIN_STATE_DOWN"
			default:
				log.Warning("previous request is still remaining. : ", peer.config.NeighborAddress)
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
		loc := server.localRibMap[peer.config.NeighborAddress.String()]
		if loc == nil {
			result := &GrpcResponse{
				ResponseErr: fmt.Errorf("no local rib for %s", peer.config.NeighborAddress.String()),
			}
			grpcReq.ResponseCh <- result
			close(grpcReq.ResponseCh)
			break
		}
		resInPolicies := []*api.PolicyDefinition{}
		resOutPolicies := []*api.PolicyDefinition{}
		resDistPolicies := []*api.PolicyDefinition{}
		pdList := server.routingPolicy.PolicyDefinitionList
		df := server.routingPolicy.DefinedSets

		extract := func(policyNames []string) []*api.PolicyDefinition {
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
		conInPolicyNames := peer.config.ApplyPolicy.ImportPolicies
		resInPolicies = extract(conInPolicyNames)

		// Add importpolies that has been set in the configuration file to the list.
		// However, peer haven't target importpolicy when add PolicyDefinition of name only to the list.
		conOutPolicyNames := peer.config.ApplyPolicy.ExportPolicies
		resOutPolicies = extract(conOutPolicyNames)

		distPolicyNames := peer.config.ApplyPolicy.DistributePolicies
		resDistPolicies = extract(distPolicyNames)

		defaultInPolicy := policy.ROUTE_REJECT
		defaultOutPolicy := policy.ROUTE_REJECT
		defaultDistPolicy := policy.ROUTE_REJECT
		if loc.defaultImportPolicy == config.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE {
			defaultInPolicy = policy.ROUTE_ACCEPT
		}
		if loc.defaultExportPolicy == config.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE {
			defaultOutPolicy = policy.ROUTE_ACCEPT
		}
		if peer.defaultDistributePolicy == config.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE {
			defaultDistPolicy = policy.ROUTE_ACCEPT
		}
		result := &GrpcResponse{
			Data: &api.ApplyPolicy{
				DefaultImportPolicy:     defaultInPolicy,
				ImportPolicies:          resInPolicies,
				DefaultExportPolicy:     defaultOutPolicy,
				ExportPolicies:          resOutPolicies,
				DefaultDistributePolicy: defaultDistPolicy,
				DistributePolicies:      resDistPolicies,
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
		applyPolicy := &peer.config.ApplyPolicy
		var defInPolicy, defOutPolicy, defDistPolicy config.DefaultPolicyType
		if grpcReq.RequestType == REQ_NEIGHBOR_POLICY_ADD_IMPORT {
			if reqApplyPolicy.DefaultImportPolicy != policy.ROUTE_ACCEPT {
				defInPolicy = config.DEFAULT_POLICY_TYPE_REJECT_ROUTE
			}
			peer.config.ApplyPolicy.DefaultImportPolicy = defInPolicy
			applyPolicy.ImportPolicies = policy.PoliciesToString(reqApplyPolicy.ImportPolicies)
		} else if grpcReq.RequestType == REQ_NEIGHBOR_POLICY_ADD_EXPORT {
			if reqApplyPolicy.DefaultExportPolicy != policy.ROUTE_ACCEPT {
				defOutPolicy = config.DEFAULT_POLICY_TYPE_REJECT_ROUTE
			}
			peer.config.ApplyPolicy.DefaultExportPolicy = defOutPolicy
			applyPolicy.ExportPolicies = policy.PoliciesToString(reqApplyPolicy.ExportPolicies)
		} else if grpcReq.RequestType == REQ_NEIGHBOR_POLICY_ADD_DISTRIBUTE {
			if reqApplyPolicy.DefaultDistributePolicy != policy.ROUTE_ACCEPT {
				defDistPolicy = config.DEFAULT_POLICY_TYPE_REJECT_ROUTE
			}
			peer.config.ApplyPolicy.DefaultDistributePolicy = defDistPolicy
			applyPolicy.DistributePolicies = policy.PoliciesToString(reqApplyPolicy.DistributePolicies)
		} else if grpcReq.RequestType == REQ_NEIGHBOR_POLICY_DEL_IMPORT {
			peer.config.ApplyPolicy.DefaultImportPolicy = config.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE
			peer.config.ApplyPolicy.ImportPolicies = make([]string, 0)
		} else if grpcReq.RequestType == REQ_NEIGHBOR_POLICY_DEL_EXPORT {
			peer.config.ApplyPolicy.DefaultExportPolicy = config.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE
			peer.config.ApplyPolicy.ExportPolicies = make([]string, 0)
		} else if grpcReq.RequestType == REQ_NEIGHBOR_POLICY_DEL_DISTRIBUTE {
			peer.config.ApplyPolicy.DefaultDistributePolicy = config.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE
			peer.config.ApplyPolicy.DistributePolicies = make([]string, 0)
		}

		if grpcReq.RequestType == REQ_NEIGHBOR_POLICY_ADD_DISTRIBUTE ||
			grpcReq.RequestType == REQ_NEIGHBOR_POLICY_DEL_DISTRIBUTE {
			peer.setDistributePolicy(reqPolicyMap)
		} else {
			loc := server.localRibMap[peer.config.NeighborAddress.String()]
			loc.setPolicy(peer, reqPolicyMap)
		}

		grpcReq.ResponseCh <- &GrpcResponse{}
		close(grpcReq.ResponseCh)

	case REQ_POLICY_PREFIXES, REQ_POLICY_NEIGHBORS, REQ_POLICY_ASPATHS,
		REQ_POLICY_COMMUNITIES, REQ_POLICY_ROUTEPOLICIES:
		server.handleGrpcShowPolicies(grpcReq)
	case REQ_POLICY_PREFIX, REQ_POLICY_NEIGHBOR, REQ_POLICY_ASPATH,
		REQ_POLICY_COMMUNITY, REQ_POLICY_ROUTEPOLICY:
		server.handleGrpcShowPolicy(grpcReq)
	case REQ_POLICY_PREFIX_ADD, REQ_POLICY_NEIGHBOR_ADD, REQ_POLICY_ASPATH_ADD,
		REQ_POLICY_COMMUNITY_ADD, REQ_POLICY_ROUTEPOLICY_ADD:
		server.handleGrpcAddPolicy(grpcReq)
	case REQ_POLICY_PREFIX_DELETE, REQ_POLICY_NEIGHBOR_DELETE, REQ_POLICY_ASPATH_DELETE,
		REQ_POLICY_COMMUNITY_DELETE, REQ_POLICY_ROUTEPOLICY_DELETE:
		server.handleGrpcDelPolicy(grpcReq)
	case REQ_POLICY_PREFIXES_DELETE, REQ_POLICY_NEIGHBORS_DELETE, REQ_POLICY_ASPATHS_DELETE,
		REQ_POLICY_COMMUNITIES_DELETE, REQ_POLICY_ROUTEPOLICIES_DELETE:
		server.handleGrpcDelPolicies(grpcReq)
	case REQ_MONITOR_GLOBAL_BEST_CHANGED, REQ_MONITOR_NEIGHBOR_PEER_STATE:
		server.broadcastReqs = append(server.broadcastReqs, grpcReq)
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
		info := server.routingPolicy.DefinedSets.PrefixSetList
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
		info := server.routingPolicy.DefinedSets.NeighborSetList
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
		info := server.routingPolicy.DefinedSets.BgpDefinedSets.AsPathSetList
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
		info := server.routingPolicy.DefinedSets.BgpDefinedSets.CommunitySetList
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
	case REQ_POLICY_ROUTEPOLICIES:
		info := server.routingPolicy.PolicyDefinitionList
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
		info := server.routingPolicy.DefinedSets.PrefixSetList
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
		info := server.routingPolicy.DefinedSets.NeighborSetList
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
		info := server.routingPolicy.DefinedSets.BgpDefinedSets.AsPathSetList
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
		info := server.routingPolicy.DefinedSets.BgpDefinedSets.CommunitySetList
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
	case REQ_POLICY_ROUTEPOLICY:
		log.Error("IN RoutePolicy")
		info := server.routingPolicy.PolicyDefinitionList
		df := server.routingPolicy.DefinedSets
		resPolicyDefinition := &api.PolicyDefinition{}
		for _, pd := range info {
			if pd.Name == name {
				resPolicyDefinition = policy.PolicyDefinitionToApiStruct(pd, df)
				break
			}
		}
		log.Error("IN RoutePolicy: ", len(resPolicyDefinition.StatementList))
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
		conPrefixSetList := server.routingPolicy.DefinedSets.PrefixSetList
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
		server.routingPolicy.DefinedSets.PrefixSetList = conPrefixSetList
	case REQ_POLICY_NEIGHBOR_ADD:
		reqNeighborSet := grpcReq.Data.(*api.PolicyDefinition).StatementList[0].Conditions.MatchNeighborSet
		conNeighborSetList := server.routingPolicy.DefinedSets.NeighborSetList
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
		server.routingPolicy.DefinedSets.NeighborSetList = conNeighborSetList
	case REQ_POLICY_ASPATH_ADD:
		reqAsPathSet := grpcReq.Data.(*api.PolicyDefinition).StatementList[0].Conditions.MatchAsPathSet
		conAsPathSetList := server.routingPolicy.DefinedSets.BgpDefinedSets.AsPathSetList
		isReqAsPathSet, asPathSet := policy.AsPathSetToConfigStruct(reqAsPathSet)
		if !isReqAsPathSet {
			result.ResponseErr = fmt.Errorf("doesn't reqest of policy aspath.")
			grpcReq.ResponseCh <- result
			close(grpcReq.ResponseCh)
		}
		// If the same NeighborSet is not set, add NeighborSet of request to the end.
		// If only name of the NeighborSet is same, overwrite with NeighborSet of request
		idxAsPathSet, idxAsPath := policy.IndexOfAsPathSet(conAsPathSetList, asPathSet)
		if idxAsPathSet == -1 {
			conAsPathSetList = append(conAsPathSetList, asPathSet)
		} else {
			if idxAsPath == -1 {
				conAsPathSetList[idxAsPathSet].AsPathSetMembers =
					append(conAsPathSetList[idxAsPathSet].AsPathSetMembers, asPathSet.AsPathSetMembers[0])
			}
		}
		server.routingPolicy.DefinedSets.BgpDefinedSets.AsPathSetList = conAsPathSetList
	case REQ_POLICY_COMMUNITY_ADD:
		reqCommunitySet := grpcReq.Data.(*api.PolicyDefinition).StatementList[0].Conditions.MatchCommunitySet
		conCommunitySetList := server.routingPolicy.DefinedSets.BgpDefinedSets.CommunitySetList
		isReqCommunitySet, communitySet := policy.CommunitySetToConfigStruct(reqCommunitySet)
		if !isReqCommunitySet {
			result.ResponseErr = fmt.Errorf("doesn't reqest of policy community.")
			grpcReq.ResponseCh <- result
			close(grpcReq.ResponseCh)
		}
		// If the same NeighborSet is not set, add NeighborSet of request to the end.
		// If only name of the NeighborSet is same, overwrite with NeighborSet of request
		idxCommunitySet, idxCommunity := policy.IndexOfCommunitySet(conCommunitySetList, communitySet)
		if idxCommunitySet == -1 {
			conCommunitySetList = append(conCommunitySetList, communitySet)
		} else {
			if idxCommunity == -1 {
				conCommunitySetList[idxCommunitySet].CommunityMembers =
					append(conCommunitySetList[idxCommunitySet].CommunityMembers, communitySet.CommunityMembers[0])
			}
		}
		server.routingPolicy.DefinedSets.BgpDefinedSets.CommunitySetList = conCommunitySetList
	case REQ_POLICY_ROUTEPOLICY_ADD:
		reqPolicy := grpcReq.Data.(*api.PolicyDefinition)
		reqConditions := reqPolicy.StatementList[0].Conditions
		reqActions := reqPolicy.StatementList[0].Actions
		conPolicyList := server.routingPolicy.PolicyDefinitionList
		_, policyDef := policy.PolicyDefinitionToConfigStruct(reqPolicy)
		idxPolicy, idxStatement := policy.IndexOfPolicyDefinition(conPolicyList, policyDef)
		if idxPolicy == -1 {
			conPolicyList = append(conPolicyList, policyDef)
		} else {
			statement := policyDef.StatementList[0]
			if idxStatement == -1 {
				conPolicyList[idxPolicy].StatementList =
					append(conPolicyList[idxPolicy].StatementList, statement)
			} else {
				conStatement := &conPolicyList[idxPolicy].StatementList[idxStatement]
				if reqConditions.MatchPrefixSet != nil {
					conStatement.Conditions.MatchPrefixSet = statement.Conditions.MatchPrefixSet
				}
				if reqConditions.MatchNeighborSet != nil {
					conStatement.Conditions.MatchNeighborSet = statement.Conditions.MatchNeighborSet
				}
				if reqConditions.MatchSetOptions != "" {
					conStatement.Conditions.MatchSetOptions = statement.Conditions.MatchSetOptions
				}
				if reqConditions.MatchAsPathSet != nil {
					conStatement.Conditions.BgpConditions.MatchAsPathSet = statement.Conditions.BgpConditions.MatchAsPathSet
				}
				if reqConditions.MatchCommunitySet != nil {
					conStatement.Conditions.BgpConditions.MatchCommunitySet = statement.Conditions.BgpConditions.MatchCommunitySet
				}
				if reqConditions.MatchAsPathLength != nil {
					conStatement.Conditions.BgpConditions.AsPathLength = statement.Conditions.BgpConditions.AsPathLength
				}
				if reqActions.RouteAction != "" {
					conStatement.Actions.AcceptRoute = statement.Actions.AcceptRoute
					conStatement.Actions.RejectRoute = statement.Actions.RejectRoute
				}
				if reqActions.Community != nil {
					conStatement.Actions.BgpActions.SetCommunity = statement.Actions.BgpActions.SetCommunity
				}
			}
		}
		server.routingPolicy.PolicyDefinitionList = conPolicyList
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
		conPrefixSetList := server.routingPolicy.DefinedSets.PrefixSetList
		isReqPrefixSet, prefixSet := policy.PrefixSetToConfigStruct(reqPrefixSet)
		if isReqPrefixSet {
			// If only name of the PrefixSet is same, delete all of the elements of the PrefixSet.
			// If the same element PrefixSet, delete the it's element from PrefixSet.
			idxPrefixSet, idxPrefix := policy.IndexOfPrefixSet(conPrefixSetList, prefixSet)
			prefix := prefixSet.PrefixList[0]
			if idxPrefixSet == -1 {
				result.ResponseErr = fmt.Errorf("Policy prefix that has %v %v/%v %v doesn't exist.", prefixSet.PrefixSetName,
					prefix.Address, prefix.Masklength, prefix.MasklengthRange)
			} else {
				if idxPrefix == -1 {
					result.ResponseErr = fmt.Errorf("Policy prefix that has %v %v/%v %v doesn't exist.", prefixSet.PrefixSetName,
						prefix.Address, prefix.Masklength, prefix.MasklengthRange)
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
		server.routingPolicy.DefinedSets.PrefixSetList = conPrefixSetList
	case REQ_POLICY_NEIGHBOR_DELETE:
		reqNeighborSet := grpcReq.Data.(*api.PolicyDefinition).StatementList[0].Conditions.MatchNeighborSet
		conNeighborSetList := server.routingPolicy.DefinedSets.NeighborSetList
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
		server.routingPolicy.DefinedSets.NeighborSetList = conNeighborSetList
	case REQ_POLICY_ASPATH_DELETE:
		reqAsPathSet := grpcReq.Data.(*api.PolicyDefinition).StatementList[0].Conditions.MatchAsPathSet
		conAsPathSetList := server.routingPolicy.DefinedSets.BgpDefinedSets.AsPathSetList
		result := &GrpcResponse{}
		isReqAsPathSet, asPathSet := policy.AsPathSetToConfigStruct(reqAsPathSet)
		// If only name of the NeighborSet is same, delete all of the elements of the NeighborSet.
		// If the same element NeighborSet, delete the it's element from NeighborSet.
		idxAsPathSet, idxAsPath := policy.IndexOfAsPathSet(conAsPathSetList, asPathSet)
		if isReqAsPathSet {
			if idxAsPathSet == -1 {
				result.ResponseErr = fmt.Errorf("Policy aspath that has %v %v doesn't exist.", asPathSet.AsPathSetName,
					asPathSet.AsPathSetMembers[0])
			} else {
				if idxAsPath == -1 {
					result.ResponseErr = fmt.Errorf("Policy aspath that has %v %v doesn't exist.", asPathSet.AsPathSetName,
						asPathSet.AsPathSetMembers[0])
				} else {
					conAsPathSetList[idxAsPathSet].AsPathSetMembers =
						append(conAsPathSetList[idxAsPathSet].AsPathSetMembers[:idxAsPath],
							conAsPathSetList[idxAsPathSet].AsPathSetMembers[idxAsPath+1:]...)
				}
			}
		} else {
			if idxAsPathSet == -1 {
				result.ResponseErr = fmt.Errorf("Policy aspath %v doesn't  exist.", asPathSet.AsPathSetName)
			} else {
				conAsPathSetList = append(conAsPathSetList[:idxAsPathSet], conAsPathSetList[idxAsPathSet+1:]...)
			}
		}
		server.routingPolicy.DefinedSets.BgpDefinedSets.AsPathSetList = conAsPathSetList
	case REQ_POLICY_COMMUNITY_DELETE:
		reqCommunitySet := grpcReq.Data.(*api.PolicyDefinition).StatementList[0].Conditions.MatchCommunitySet
		conCommunitySetList := server.routingPolicy.DefinedSets.BgpDefinedSets.CommunitySetList
		isReqCommunitySet, CommunitySet := policy.CommunitySetToConfigStruct(reqCommunitySet)
		// If only name of the NeighborSet is same, delete all of the elements of the NeighborSet.
		// If the same element NeighborSet, delete the it's element from NeighborSet.
		idxCommunitySet, idxCommunity := policy.IndexOfCommunitySet(conCommunitySetList, CommunitySet)
		if isReqCommunitySet {
			if idxCommunitySet == -1 {
				result.ResponseErr = fmt.Errorf("Policy aspath that has %v %v doesn't exist.", CommunitySet.CommunitySetName,
					CommunitySet.CommunityMembers[0])
			} else {
				if idxCommunity == -1 {
					result.ResponseErr = fmt.Errorf("Policy aspath that has %v %v doesn't exist.", CommunitySet.CommunitySetName,
						CommunitySet.CommunityMembers[0])
				} else {
					conCommunitySetList[idxCommunitySet].CommunityMembers =
						append(conCommunitySetList[idxCommunitySet].CommunityMembers[:idxCommunity],
							conCommunitySetList[idxCommunitySet].CommunityMembers[idxCommunity+1:]...)
				}
			}
		} else {
			if idxCommunitySet == -1 {
				result.ResponseErr = fmt.Errorf("Policy aspath %v doesn't  exist.", CommunitySet.CommunitySetName)
			} else {
				conCommunitySetList = append(conCommunitySetList[:idxCommunitySet], conCommunitySetList[idxCommunitySet+1:]...)
			}
		}
		server.routingPolicy.DefinedSets.BgpDefinedSets.CommunitySetList = conCommunitySetList
	case REQ_POLICY_ROUTEPOLICY_DELETE:
		reqPolicy := grpcReq.Data.(*api.PolicyDefinition)
		conPolicyList := server.routingPolicy.PolicyDefinitionList
		result := &GrpcResponse{}
		isStatement, policyDef := policy.PolicyDefinitionToConfigStruct(reqPolicy)
		idxPolicy, idxStatement := policy.IndexOfPolicyDefinition(conPolicyList, policyDef)
		if isStatement {
			if idxPolicy == -1 {
				result.ResponseErr = fmt.Errorf("Policy that has %v doesn't exist.", policyDef.Name)
			} else {
				if idxStatement == -1 {
					result.ResponseErr = fmt.Errorf("Policy Statment that has %v doesn't exist.", policyDef.StatementList[0].Name)
				} else {
					conPolicyList[idxPolicy].StatementList =
						append(conPolicyList[idxPolicy].StatementList[:idxStatement], conPolicyList[idxPolicy].StatementList[idxStatement+1:]...)
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
		server.routingPolicy.PolicyDefinitionList = conPolicyList
	}
	server.handlePolicy(server.routingPolicy)
	grpcReq.ResponseCh <- result
	close(grpcReq.ResponseCh)
}

func (server *BgpServer) handleGrpcDelPolicies(grpcReq *GrpcRequest) {
	result := &GrpcResponse{}
	switch grpcReq.RequestType {
	case REQ_POLICY_PREFIXES_DELETE:
		server.routingPolicy.DefinedSets.PrefixSetList = make([]config.PrefixSet, 0)
	case REQ_POLICY_NEIGHBORS_DELETE:
		server.routingPolicy.DefinedSets.NeighborSetList = make([]config.NeighborSet, 0)
	case REQ_POLICY_ASPATHS_DELETE:
		server.routingPolicy.DefinedSets.BgpDefinedSets.AsPathSetList = make([]config.AsPathSet, 0)
	case REQ_POLICY_COMMUNITIES_DELETE:
		server.routingPolicy.DefinedSets.BgpDefinedSets.CommunitySetList = make([]config.CommunitySet, 0)
	case REQ_POLICY_ROUTEPOLICIES_DELETE:
		server.routingPolicy.PolicyDefinitionList = make([]config.PolicyDefinition, 0)
	}
	server.handlePolicy(server.routingPolicy)
	grpcReq.ResponseCh <- result
	close(grpcReq.ResponseCh)
}
