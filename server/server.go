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

	listener := func(addr net.IP) *net.TCPListener {
		var l *net.TCPListener
		if addr.To4() != nil {
			l = listenerMap["tcp4"]
		} else {
			l = listenerMap["tcp6"]
		}
		return l
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
			SetTcpMD5SigSockopts(listener(peer.NeighborAddress), addr, peer.AuthPassword)
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
			SetTcpMD5SigSockopts(listener(peer.NeighborAddress), addr, "")
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
		pMap[p.Name] = policy.NewPolicy(p, df)
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
				ResponseErr: fmt.Errorf("Neighbor that has %v doesn't  exist.", remoteAddr),
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
		REQ_NEIGHBOR_ENABLE, REQ_NEIGHBOR_DISABLE,
		REQ_NEIGHBOR_POLICY:
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
			result.ResponseErr = fmt.Errorf("Neighbor that has %v doesn't  exist.", remoteAddr)
			grpcReq.ResponseCh <- result
			close(grpcReq.ResponseCh)
		}
	case REQ_NEIGHBOR_POLICY_ADD_IMPORT, REQ_NEIGHBOR_POLICY_ADD_EXPORT, REQ_NEIGHBOR_POLICY_DEL_IMPORT, REQ_NEIGHBOR_POLICY_DEL_EXPORT:
		remoteAddr := grpcReq.RemoteAddr
		result := &GrpcResponse{}
		info, found := server.peerMap[remoteAddr]
		if found {
			reqApplyPolicy := grpcReq.Data.(*api.ApplyPolicy)
			grpcReq.Data = []interface{}{reqApplyPolicy, server.policyMap}
			msg := &serverMsg{
				msgType: SRV_MSG_API,
				msgData: grpcReq,
			}
			info.peer.serverMsgCh <- msg
		} else {
			result.ResponseErr = fmt.Errorf("Neighbor that has %v doesn't  exist.", remoteAddr)
			grpcReq.ResponseCh <- result
			close(grpcReq.ResponseCh)
		}
	case REQ_POLICY_PREFIXES:
		info := server.routingPolicy.DefinedSets.PrefixSetList
		result := &GrpcResponse{}
		if len(info) > 0 {
			for _, ps := range info {
				resPrefixSet := policy.PrefixSetToApiStruct(ps)
				result = &GrpcResponse{
					Data: resPrefixSet,
				}
				grpcReq.ResponseCh <- result
			}
		} else {
			result.ResponseErr = fmt.Errorf("Policy prefix doesn't exist.")
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
				resPrefixSet = policy.PrefixSetToApiStruct(ps)
				break
			}
		}
		if len(resPrefixSet.PrefixList) > 0 {
			result = &GrpcResponse{
				Data: resPrefixSet,
			}
			grpcReq.ResponseCh <- result
		} else {
			result.ResponseErr = fmt.Errorf("Policy prefix that has %v doesn't exist.", name)
			grpcReq.ResponseCh <- result
		}
		close(grpcReq.ResponseCh)
	case REQ_POLICY_PREFIX_ADD:
		reqPrefixSet := grpcReq.Data.(*api.PrefixSet)
		conPrefixSetList := server.routingPolicy.DefinedSets.PrefixSetList
		result := &GrpcResponse{}
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
		server.handlePolicy(server.routingPolicy)
		grpcReq.ResponseCh <- result
		close(grpcReq.ResponseCh)
	case REQ_POLICY_PREFIXES_DELETE:
		result := &GrpcResponse{}
		server.routingPolicy.DefinedSets.PrefixSetList = make([]config.PrefixSet, 0)
		server.handlePolicy(server.routingPolicy)
		grpcReq.ResponseCh <- result
		close(grpcReq.ResponseCh)
	case REQ_POLICY_NEIGHBORS:
		info := server.routingPolicy.DefinedSets.NeighborSetList
		result := &GrpcResponse{}
		if len(info) > 0 {
			for _, ns := range info {
				resNeighborSet := policy.NeighborSetToApiStruct(ns)
				result = &GrpcResponse{
					Data: resNeighborSet,
				}
				grpcReq.ResponseCh <- result
			}
		} else {
			result.ResponseErr = fmt.Errorf("Policy neighbor doesn't  exist.")
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
				resNeighborSet = policy.NeighborSetToApiStruct(ns)
				break
			}
		}
		if len(resNeighborSet.NeighborList) > 0 {
			result = &GrpcResponse{
				Data: resNeighborSet,
			}
			grpcReq.ResponseCh <- result
		} else {
			result.ResponseErr = fmt.Errorf("Policy neighbor that has %v doesn't exist.", name)
			grpcReq.ResponseCh <- result
		}
		close(grpcReq.ResponseCh)
	case REQ_POLICY_NEIGHBOR_ADD:
		reqNeighborSet := grpcReq.Data.(*api.NeighborSet)
		conNeighborSetList := server.routingPolicy.DefinedSets.NeighborSetList
		result := &GrpcResponse{}
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
		server.handlePolicy(server.routingPolicy)
		grpcReq.ResponseCh <- result
		close(grpcReq.ResponseCh)
	case REQ_POLICY_NEIGHBOR_DELETE:
		reqNeighborSet := grpcReq.Data.(*api.NeighborSet)
		conNeighborSetList := server.routingPolicy.DefinedSets.NeighborSetList
		result := &GrpcResponse{}
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
		server.handlePolicy(server.routingPolicy)
		grpcReq.ResponseCh <- result
		close(grpcReq.ResponseCh)
	case REQ_POLICY_NEIGHBORS_DELETE:
		result := &GrpcResponse{}
		server.routingPolicy.DefinedSets.NeighborSetList = make([]config.NeighborSet, 0)
		server.handlePolicy(server.routingPolicy)
		grpcReq.ResponseCh <- result
		close(grpcReq.ResponseCh)
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
		close(grpcReq.ResponseCh)
	case REQ_POLICY_ROUTEPOLICY:
		name := grpcReq.Data.(string)
		info := server.routingPolicy.PolicyDefinitionList
		df := server.routingPolicy.DefinedSets
		result := &GrpcResponse{}
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
			grpcReq.ResponseCh <- result
		} else {
			result.ResponseErr = fmt.Errorf("Route Policy that has %v doesn't  exist.", name)
			grpcReq.ResponseCh <- result
		}
		close(grpcReq.ResponseCh)
	case REQ_POLICY_ROUTEPOLICY_ADD:
		reqPolicy := grpcReq.Data.(*api.PolicyDefinition)
		reqConditions := reqPolicy.StatementList[0].Conditions
		reqActions := reqPolicy.StatementList[0].Actions
		conPolicyList := server.routingPolicy.PolicyDefinitionList
		result := &GrpcResponse{}
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
				if reqConditions != nil {
					if reqConditions.MatchPrefixSet != nil {
						conStatement.Conditions.MatchPrefixSet = statement.Conditions.MatchPrefixSet
					}
					if reqConditions.MatchNeighborSet != nil {
						conStatement.Conditions.MatchNeighborSet = statement.Conditions.MatchNeighborSet
					}
					if reqConditions.MatchSetOptions != "" {
						conStatement.Conditions.MatchSetOptions = statement.Conditions.MatchSetOptions
					}
					if reqConditions.MatchAsPathLength != nil {
						conStatement.Conditions.BgpConditions.AsPathLength = statement.Conditions.BgpConditions.AsPathLength
					}
				}
				if reqActions != nil {
					conStatement.Actions = statement.Actions
				}
			}
		}
		server.routingPolicy.PolicyDefinitionList = conPolicyList
		server.handlePolicy(server.routingPolicy)
		grpcReq.ResponseCh <- result
		close(grpcReq.ResponseCh)

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
		server.handlePolicy(server.routingPolicy)
		grpcReq.ResponseCh <- result
		close(grpcReq.ResponseCh)

	case REQ_POLICY_ROUTEPOLICIES_DELETE:
		result := &GrpcResponse{}
		server.routingPolicy.PolicyDefinitionList = make([]config.PolicyDefinition, 0)
		server.handlePolicy(server.routingPolicy)
		grpcReq.ResponseCh <- result
		close(grpcReq.ResponseCh)
	}
}
