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
	"github.com/osrg/gobgp/policy"
	"net"
	"os"
	"reflect"
	"strconv"
)

type serverMsgType int

const (
	_ serverMsgType = iota
	SRV_MSG_PEER_ADDED
	SRV_MSG_PEER_DELETED
	SRV_MSG_API
	SRV_MSG_POLICY_UPDATED
)

type serverMsg struct {
	msgType serverMsgType
	msgData interface{}
}

type serverMsgDataPeer struct {
	peerMsgCh chan *peerMsg
	address   net.IP
	As        uint32
}

type peerMapInfo struct {
	peer                *Peer
	serverMsgCh         chan *serverMsg
	peerMsgCh           chan *peerMsg
	peerMsgData         *serverMsgDataPeer
	isRouteServerClient bool
}

type BgpServer struct {
	bgpConfig      config.Bgp
	globalTypeCh   chan config.Global
	addedPeerCh    chan config.Neighbor
	deletedPeerCh  chan config.Neighbor
	GrpcReqCh      chan *GrpcRequest
	listenPort     int
	peerMap        map[string]peerMapInfo
	globalRib      *Peer
	policyUpdateCh chan config.RoutingPolicy
	policyMap      map[string]*policy.Policy
	routingPolicy  config.RoutingPolicy
}

func NewBgpServer(port int) *BgpServer {
	b := BgpServer{}
	b.globalTypeCh = make(chan config.Global)
	b.addedPeerCh = make(chan config.Neighbor)
	b.deletedPeerCh = make(chan config.Neighbor)
	b.GrpcReqCh = make(chan *GrpcRequest, 1)
	b.policyUpdateCh = make(chan config.RoutingPolicy)
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
			// TODO: check ebgp or not
			ttl := 1
			SetTcpTTLSockopts(conn, ttl)
			ch <- conn
		}
	}()

	return l, nil
}

func (server *BgpServer) Serve() {
	g := <-server.globalTypeCh
	server.bgpConfig.Global = g

	globalSch := make(chan *serverMsg, 8)
	globalPch := make(chan *peerMsg, 4096)
	neighConf := config.Neighbor{
		NeighborAddress: g.RouterId,
		AfiSafiList:     g.AfiSafiList,
		PeerAs:          g.As,
	}
	server.globalRib = NewPeer(g, neighConf, globalSch, globalPch, nil, true, make(map[string]*policy.Policy))

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

	listenFile := func(addr net.IP) *os.File {
		var l *net.TCPListener
		if addr.To4() != nil {
			l = listenerMap["tcp4"]
		} else {
			l = listenerMap["tcp6"]
		}
		f, _ := l.File()
		return f
	}

	server.peerMap = make(map[string]peerMapInfo)
	for {
		select {
		case conn := <-acceptCh:
			remoteAddr, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			info, found := server.peerMap[remoteAddr]
			if found {
				log.Debug("accepted a new passive connection from ", remoteAddr)
				info.peer.PassConn(conn)
			} else {
				log.Info("can't find configuration for a new passive connection from ", remoteAddr)
				conn.Close()
			}
		case peer := <-server.addedPeerCh:
			addr := peer.NeighborAddress.String()
			f := listenFile(peer.NeighborAddress)
			SetTcpMD5SigSockopts(int(f.Fd()), addr, peer.AuthPassword)
			sch := make(chan *serverMsg, 8)
			pch := make(chan *peerMsg, 4096)
			var l []*serverMsgDataPeer
			if peer.RouteServer.RouteServerClient {
				for _, v := range server.peerMap {
					if v.isRouteServerClient {
						l = append(l, v.peerMsgData)
					}
				}
			} else {
				globalRib := &serverMsgDataPeer{
					address:   server.bgpConfig.Global.RouterId,
					peerMsgCh: globalPch,
				}
				l = []*serverMsgDataPeer{globalRib}
			}
			p := NewPeer(server.bgpConfig.Global, peer, sch, pch, l, false, server.policyMap)
			d := &serverMsgDataPeer{
				address:   peer.NeighborAddress,
				peerMsgCh: pch,
				As:        peer.PeerAs,
			}
			msg := &serverMsg{
				msgType: SRV_MSG_PEER_ADDED,
				msgData: d,
			}
			if peer.RouteServer.RouteServerClient {
				sendServerMsgToRSClients(server.peerMap, msg)
			} else {
				globalSch <- msg
			}

			server.peerMap[peer.NeighborAddress.String()] = peerMapInfo{
				peer:                p,
				serverMsgCh:         sch,
				peerMsgData:         d,
				isRouteServerClient: peer.RouteServer.RouteServerClient,
			}
		case peer := <-server.deletedPeerCh:
			addr := peer.NeighborAddress.String()
			f := listenFile(peer.NeighborAddress)
			SetTcpMD5SigSockopts(int(f.Fd()), addr, "")
			info, found := server.peerMap[addr]
			if found {
				log.Info("Delete a peer configuration for ", addr)
				info.peer.Stop()
				delete(server.peerMap, addr)
				msg := &serverMsg{
					msgType: SRV_MSG_PEER_DELETED,
					msgData: info.peer.peerInfo,
				}
				if info.isRouteServerClient {
					sendServerMsgToRSClients(server.peerMap, msg)
				} else {
					globalSch <- msg
				}
			} else {
				log.Info("Can't delete a peer configuration for ", addr)
			}
		case grpcReq := <-server.GrpcReqCh:
			server.handleGrpc(grpcReq)
		case pl := <-server.policyUpdateCh:
			server.handlePolicy(pl)
		}
	}
}

func sendServerMsgToAll(peerMap map[string]peerMapInfo, msg *serverMsg) {
	for _, info := range peerMap {
		info.serverMsgCh <- msg
	}
}

func sendServerMsgToRSClients(peerMap map[string]peerMapInfo, msg *serverMsg) {
	for _, info := range peerMap {
		if info.isRouteServerClient {
			info.serverMsgCh <- msg
		}
	}
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
		pMap[p.Name] = policy.NewPolicy(p.Name, p, df)
	}
	server.policyMap = pMap
	server.routingPolicy = pl
}

func (server *BgpServer) handlePolicy(pl config.RoutingPolicy) {
	server.SetPolicy(pl)
	msg := &serverMsg{
		msgType: SRV_MSG_POLICY_UPDATED,
		msgData: server.policyMap,
	}
	sendServerMsgToAll(server.peerMap, msg)
}

func (server *BgpServer) handleGrpc(grpcReq *GrpcRequest) {
	switch grpcReq.RequestType {
	case REQ_NEIGHBORS:
		for _, info := range server.peerMap {
			result := &GrpcResponse{
				Data: info.peer.ToApiStruct(),
			}
			grpcReq.ResponseCh <- result
		}
		close(grpcReq.ResponseCh)
	case REQ_NEIGHBOR:
		remoteAddr := grpcReq.RemoteAddr
		var result *GrpcResponse
		info, found := server.peerMap[remoteAddr]
		if found {
			result = &GrpcResponse{
				Data: info.peer.ToApiStruct(),
			}
		} else {
			result = &GrpcResponse{
				ResponseErr: fmt.Errorf("Neighbor that has %v does not exist.", remoteAddr),
			}
		}
		grpcReq.ResponseCh <- result
		close(grpcReq.ResponseCh)
	case REQ_GLOBAL_RIB, REQ_GLOBAL_ADD, REQ_GLOBAL_DELETE:
		msg := &serverMsg{
			msgType: SRV_MSG_API,
			msgData: grpcReq,
		}
		server.globalRib.serverMsgCh <- msg
	case REQ_LOCAL_RIB, REQ_NEIGHBOR_SHUTDOWN, REQ_NEIGHBOR_RESET,
		REQ_NEIGHBOR_SOFT_RESET, REQ_NEIGHBOR_SOFT_RESET_IN, REQ_NEIGHBOR_SOFT_RESET_OUT,
		REQ_ADJ_RIB_IN, REQ_ADJ_RIB_OUT,
		REQ_NEIGHBOR_ENABLE, REQ_NEIGHBOR_DISABLE:

		remoteAddr := grpcReq.RemoteAddr
		result := &GrpcResponse{}
		info, found := server.peerMap[remoteAddr]
		if found {
			msg := &serverMsg{
				msgType: SRV_MSG_API,
				msgData: grpcReq,
			}
			info.peer.serverMsgCh <- msg
		} else {
			result.ResponseErr = fmt.Errorf("Neighbor that has %v does not exist.", remoteAddr)
			grpcReq.ResponseCh <- result
			close(grpcReq.ResponseCh)
		}
	case REQ_POLICY_PREFIXES:
		info := server.routingPolicy.DefinedSets.PrefixSetList
		result := &GrpcResponse{}
		if len(info) > 0 {
			for _, ps := range info {
				resPrefixSet := prefixToApiStruct(ps)
				result = &GrpcResponse{
					Data: resPrefixSet,
				}
				grpcReq.ResponseCh <- result
			}
		} else {
			result.ResponseErr = fmt.Errorf("Prefix is not exist.")
			grpcReq.ResponseCh <- result
		}
		close(grpcReq.ResponseCh)
	case REQ_POLICY_PREFIX:
		name := grpcReq.Data.(string)
		info := server.routingPolicy.DefinedSets.PrefixSetList
		result := &GrpcResponse{}
		resPrefixSet := &api.PrefixSet{}
		for _, ps := range info {
			if ps.PrefixSetName == name {
				resPrefixSet = prefixToApiStruct(ps)
				break
			}
		}
		if len(resPrefixSet.PrefixList) > 0 {
			result = &GrpcResponse{
				Data: resPrefixSet,
			}
			grpcReq.ResponseCh <- result
		} else {
			result.ResponseErr = fmt.Errorf("Prefix that has %v does not exist.", name)
			grpcReq.ResponseCh <- result
		}
		close(grpcReq.ResponseCh)
	case REQ_POLICY_PREFIX_ADD:
		reqPrefixSet := grpcReq.Data.(*api.PrefixSet)
		conPrefixSetList := server.routingPolicy.DefinedSets.PrefixSetList
		result := &GrpcResponse{}
		isReqPrefixSet, prefixSet := prefixToConfigStruct(reqPrefixSet)
		if !isReqPrefixSet {
			result.ResponseErr = fmt.Errorf("dose not reqest of policy prefix.")
			grpcReq.ResponseCh <- result
			close(grpcReq.ResponseCh)
		}
		idxPrefixSet, idxPrefix := findPrefixSet(conPrefixSetList, prefixSet)
		if idxPrefixSet == -1 {
			conPrefixSetList = append(conPrefixSetList, prefixSet)
		} else {
			if idxPrefix == -1 {
				conPrefixSetList[idxPrefixSet].PrefixList = append(conPrefixSetList[idxPrefixSet].PrefixList, prefixSet.PrefixList[0])
			}
		}
		server.routingPolicy.DefinedSets.PrefixSetList = conPrefixSetList
		server.handlePolicy(server.routingPolicy)
		grpcReq.ResponseCh <- result
		close(grpcReq.ResponseCh)
	case REQ_POLICY_PREFIX_DELETE:
		reqPrefixSet := grpcReq.Data.(*api.PrefixSet)
		conPrefixSetList := server.routingPolicy.DefinedSets.PrefixSetList
		result := &GrpcResponse{}
		isReqPrefixSet, prefixSet := prefixToConfigStruct(reqPrefixSet)
		if isReqPrefixSet {
			idxPrefixSet, idxPrefix := findPrefixSet(conPrefixSetList, prefixSet)
			if idxPrefixSet == -1 {
				result.ResponseErr = fmt.Errorf("Prefix %v %v/%v %v does not exist.", prefixSet.PrefixSetName,
					prefixSet.PrefixList[0].Address, prefixSet.PrefixList[0].Masklength, prefixSet.PrefixList[0].MasklengthRange)
			} else {
				if idxPrefix == -1 {
					result.ResponseErr = fmt.Errorf("Prefix %v %v/%v %v does not exist.", prefixSet.PrefixSetName,
						prefixSet.PrefixList[0].Address, prefixSet.PrefixList[0].Masklength, prefixSet.PrefixList[0].MasklengthRange)
				} else {
					copy(conPrefixSetList[idxPrefixSet].PrefixList[idxPrefix:], conPrefixSetList[idxPrefixSet].PrefixList[idxPrefix+1:])
					conPrefixSetList[idxPrefixSet].PrefixList = conPrefixSetList[idxPrefixSet].PrefixList[:len(conPrefixSetList[idxPrefixSet].PrefixList)-1]
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
				result.ResponseErr = fmt.Errorf("Prefix %v does not exist.", prefixSet.PrefixSetName)
			} else {
				copy(conPrefixSetList[idxPrefixSet:], conPrefixSetList[idxPrefixSet+1:])
				conPrefixSetList = conPrefixSetList[:len(conPrefixSetList)-1]
			}
		}
		server.routingPolicy.DefinedSets.PrefixSetList = conPrefixSetList
		server.handlePolicy(server.routingPolicy)
		grpcReq.ResponseCh <- result
		close(grpcReq.ResponseCh)
	case REQ_POLICY_PREFIXES_DELETE:
		result := &GrpcResponse{}
		pl := config.RoutingPolicy{}
		server.handlePolicy(pl)
		grpcReq.ResponseCh <- result
		close(grpcReq.ResponseCh)
	case REQ_POLICY_NEIGHBORS:
		info := server.routingPolicy.DefinedSets.NeighborSetList
		result := &GrpcResponse{}
		if len(info) > 0 {
			for _, ns := range info {
				resNeighborSet := neighborToApiStruct(ns)
				result = &GrpcResponse{
					Data: resNeighborSet,
				}
				grpcReq.ResponseCh <- result
			}
		} else {
			result.ResponseErr = fmt.Errorf("Neighbor is not exist.")
			grpcReq.ResponseCh <- result
		}
		close(grpcReq.ResponseCh)
	case REQ_POLICY_NEIGHBOR:
		name := grpcReq.Data.(string)
		info := server.routingPolicy.DefinedSets.NeighborSetList
		result := &GrpcResponse{}
		resNeighborSet := &api.NeighborSet{}
		for _, ns := range info {
			if ns.NeighborSetName == name {
				resNeighborSet = neighborToApiStruct(ns)
				break
			}
		}
		if len(resNeighborSet.NeighborList) > 0 {
			result = &GrpcResponse{
				Data: resNeighborSet,
			}
			grpcReq.ResponseCh <- result
		} else {
			result.ResponseErr = fmt.Errorf("Neighbor that has %v does not exist.", name)
			grpcReq.ResponseCh <- result
		}
		close(grpcReq.ResponseCh)
	case REQ_POLICY_ROUTEPOLICIES:
		info := server.routingPolicy.PolicyDefinitionList
		df := server.routingPolicy.DefinedSets
		result := &GrpcResponse{}
		if len(info) > 0 {
			for _, pd := range info {
				resPolicyDefinition := policyDefinitionToApiStruct(pd, df)
				result = &GrpcResponse{
					Data: resPolicyDefinition,
				}
				grpcReq.ResponseCh <- result
			}
		} else {
			result.ResponseErr = fmt.Errorf("Route Policy is not exist.")
			grpcReq.ResponseCh <- result
		}
		close(grpcReq.ResponseCh)
	case REQ_POLICY_ROUTEPOLICY:
		name := grpcReq.Data.(string)
		info := server.routingPolicy.PolicyDefinitionList
		df := server.routingPolicy.DefinedSets
		result := &GrpcResponse{}
		resPolicyDefinition := &api.PolicyDefinition{}
		for _, pd := range info {
			if pd.Name == name {
				resPolicyDefinition = policyDefinitionToApiStruct(pd, df)
				break
			}
		}
		if len(resPolicyDefinition.StatementList) > 0 {
			result = &GrpcResponse{
				Data: resPolicyDefinition,
			}
			grpcReq.ResponseCh <- result
		} else {
			result.ResponseErr = fmt.Errorf("Route Policy that has %v does not exist.", name)
			grpcReq.ResponseCh <- result
		}
		close(grpcReq.ResponseCh)
	}
}

func findPrefixSet(conPrefixSetList []config.PrefixSet, reqPrefixSet config.PrefixSet) (int, int) {
	idxPrefixSet := -1
	idxPrefix := -1
	for i, conPrefixSet := range conPrefixSetList {
		if conPrefixSet.PrefixSetName == reqPrefixSet.PrefixSetName {
			idxPrefixSet = i
			if reqPrefixSet.PrefixList == nil {
				return idxPrefixSet, idxPrefix
			}
			for j, conPrefix := range conPrefixSet.PrefixList {
				if reflect.DeepEqual(conPrefix.Address, reqPrefixSet.PrefixList[0].Address) && conPrefix.Masklength == reqPrefixSet.PrefixList[0].Masklength &&
					conPrefix.MasklengthRange == reqPrefixSet.PrefixList[0].MasklengthRange {
					idxPrefix = j
					return idxPrefixSet, idxPrefix
				}
			}
		}
	}
	return idxPrefixSet, idxPrefix
}

func findNeighborSet(conNeighborSetList []config.NeighborSet, reqNeighborSet config.NeighborSet) (int, int) {
	idxNeighborSet := -1
	idxNeighbor := -1
	for i, conNeighborSet := range conNeighborSetList {
		if conNeighborSet.NeighborSetName == reqNeighborSet.NeighborSetName {
			idxNeighborSet = i
			if reqNeighborSet.NeighborInfoList == nil {
				return idxNeighborSet, idxNeighbor
			}
			for j, conNeighbor := range conNeighborSet.NeighborInfoList {
				if reflect.DeepEqual(conNeighbor.Address, reqNeighborSet.NeighborInfoList[0].Address) {
					idxNeighbor = j
					return idxNeighborSet, idxNeighbor
				}
			}
		}
	}
	return idxNeighborSet, idxNeighbor
}

func prefixToApiStruct(ps config.PrefixSet) *api.PrefixSet {
	resPrefixList := make([]*api.Prefix, 0)
	for _, p := range ps.PrefixList {
		resPrefix := &api.Prefix{
			Address:         p.Address.String(),
			MaskLength:      uint32(p.Masklength),
			MaskLengthRange: p.MasklengthRange,
		}
		resPrefixList = append(resPrefixList, resPrefix)
	}
	resPrefixSet := &api.PrefixSet{
		PrefixSetName: ps.PrefixSetName,
		PrefixList:    resPrefixList,
	}
	return resPrefixSet
}

func prefixToConfigStruct(reqPrefixSet *api.PrefixSet) (bool, config.PrefixSet) {
	var prefix config.Prefix
	var prefixSet config.PrefixSet
	isReqPrefixSet := true
	if reqPrefixSet.PrefixList != nil {
		prefix = config.Prefix{
			Address:         net.ParseIP(reqPrefixSet.PrefixList[0].Address),
			Masklength:      uint8(reqPrefixSet.PrefixList[0].MaskLength),
			MasklengthRange: reqPrefixSet.PrefixList[0].MaskLengthRange,
		}
		prefixList := []config.Prefix{prefix}

		prefixSet = config.PrefixSet{
			PrefixSetName: reqPrefixSet.PrefixSetName,
			PrefixList:    prefixList,
		}
	} else {
		isReqPrefixSet = false
		prefixSet = config.PrefixSet{
			PrefixSetName: reqPrefixSet.PrefixSetName,
			PrefixList:    nil,
		}
	}
	return isReqPrefixSet, prefixSet
}

func neighborToApiStruct(ns config.NeighborSet) *api.NeighborSet {
	resNeighborList := make([]*api.Neighbor, 0)
	for _, n := range ns.NeighborInfoList {
		resNeighbor := &api.Neighbor{
			Address: n.Address.String(),
		}
		resNeighborList = append(resNeighborList, resNeighbor)
	}
	resNeighborSet := &api.NeighborSet{
		NeighborSetName: ns.NeighborSetName,
		NeighborList:    resNeighborList,
	}
	return resNeighborSet
}

func neighborToConfigStruct(reqNeighborSet *api.NeighborSet) (bool, config.NeighborSet) {
	var neighbor config.NeighborInfo
	var neighborSet config.NeighborSet
	isReqNeighborSet := true
	if reqNeighborSet.NeighborList != nil {
		neighbor = config.NeighborInfo{
			Address: net.ParseIP(reqNeighborSet.NeighborList[0].Address),
		}
		neighborList := []config.NeighborInfo{neighbor}

		neighborSet = config.NeighborSet{
			NeighborSetName:  reqNeighborSet.NeighborSetName,
			NeighborInfoList: neighborList,
		}
	} else {
		isReqNeighborSet = false
		neighborSet = config.NeighborSet{
			NeighborSetName:  reqNeighborSet.NeighborSetName,
			NeighborInfoList: nil,
		}
	}
	return isReqNeighborSet, neighborSet
}

func policyDefinitionToApiStruct(pd config.PolicyDefinition, df config.DefinedSets) *api.PolicyDefinition {
	conPrefixSetList := df.PrefixSetList
	conNeighborSetList := df.NeighborSetList
	resStatementList := make([]*api.Statement, 0)
	for _, st := range pd.StatementList {
		conditions := st.Conditions
		actions := st.Actions

		prefixSet := &api.PrefixSet{
			PrefixSetName: conditions.MatchPrefixSet,
		}
		neighborSet := &api.NeighborSet{
			NeighborSetName: conditions.MatchNeighborSet,
		}
		_, conPrefixSet := prefixToConfigStruct(prefixSet)
		_, conNeighborSet := neighborToConfigStruct(neighborSet)
		idxPrefixSet, _ := findPrefixSet(conPrefixSetList, conPrefixSet)
		idxNeighborSet, _ := findNeighborSet(conNeighborSetList, conNeighborSet)

		if idxPrefixSet != -1 {
			prefixSet = prefixToApiStruct(conPrefixSetList[idxPrefixSet])
		}
		if idxNeighborSet != -1 {
			neighborSet = neighborToApiStruct(conNeighborSetList[idxNeighborSet])
		}

		resConditions := &api.Conditions{
			MatchPrefixSet:   prefixSet,
			MatchNeighborSet: neighborSet,
			MatchSetOptions:  int64(conditions.MatchSetOptions),
		}
		resActions := &api.Actions{
			AcceptRoute: actions.AcceptRoute,
			RejectRoute: actions.RejectRoute,
		}
		resStatement := &api.Statement{
			StatementNeme: st.Name,
			Conditions:    resConditions,
			Actions:       resActions,
		}
		resStatementList = append(resStatementList, resStatement)
	}
	resPolicyDefinition := &api.PolicyDefinition{
		PolicyDefinitionName: pd.Name,
		StatementList:        resStatementList,
	}
	return resPolicyDefinition
}
