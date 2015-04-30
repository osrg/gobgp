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
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/policy"
	"github.com/osrg/gobgp/table"
	"gopkg.in/tomb.v2"
	"net"
	"strconv"
	"time"
)

const (
	FSM_CHANNEL_LENGTH = 1024
	FLOP_THRESHOLD     = time.Second * 30
	MIN_CONNECT_RETRY  = 10
)

type peerMsgType int

const (
	_ peerMsgType = iota
	PEER_MSG_PATH
	PEER_MSG_PEER_DOWN
)

type peerMsg struct {
	msgType peerMsgType
	msgData interface{}
}

type Peer struct {
	t            tomb.Tomb
	globalConfig config.Global
	peerConfig   config.Neighbor
	connCh       chan net.Conn
	serverMsgCh  chan *serverMsg
	peerMsgCh    chan *peerMsg
	getActiveCh  chan struct{}
	fsm          *FSM
	adjRib       *table.AdjRib
	// peer and rib are always not one-to-one so should not be
	// here but it's the simplest and works our first target.
	rib                 *table.TableManager
	isGlobalRib         bool
	rfMap               map[bgp.RouteFamily]bool
	capMap              map[bgp.BGPCapabilityCode]bgp.ParameterCapabilityInterface
	peerInfo            *table.PeerInfo
	siblings            map[string]*serverMsgDataPeer
	outgoing            chan *bgp.BGPMessage
	importPolicies      []*policy.Policy
	defaultImportPolicy config.DefaultPolicyType
	exportPolicies      []*policy.Policy
	defaultExportPolicy config.DefaultPolicyType
	broadcaster         Broadcaster
}

func NewPeer(g config.Global, peer config.Neighbor, serverMsgCh chan *serverMsg, peerMsgCh chan *peerMsg, peerList []*serverMsgDataPeer, isGlobalRib bool, policyMap map[string]*policy.Policy) *Peer {
	p := &Peer{
		globalConfig: g,
		peerConfig:   peer,
		connCh:       make(chan net.Conn),
		serverMsgCh:  serverMsgCh,
		peerMsgCh:    peerMsgCh,
		getActiveCh:  make(chan struct{}),
		rfMap:        make(map[bgp.RouteFamily]bool),
		capMap:       make(map[bgp.BGPCapabilityCode]bgp.ParameterCapabilityInterface),
		isGlobalRib:  isGlobalRib,
		broadcaster:  NewBroadcaster(),
	}
	p.siblings = make(map[string]*serverMsgDataPeer)
	for _, s := range peerList {
		p.siblings[s.address.String()] = s
	}
	p.fsm = NewFSM(&g, &peer, p.connCh)
	peer.BgpNeighborCommonState.State = uint32(bgp.BGP_FSM_IDLE)
	peer.BgpNeighborCommonState.Downtime = time.Now().Unix()
	for _, rf := range peer.AfiSafiList {
		k, _ := bgp.GetRouteFamily(rf.AfiSafiName)
		p.rfMap[k] = true
	}
	p.peerInfo = &table.PeerInfo{
		AS:      peer.PeerAs,
		LocalID: g.RouterId,
		Address: peer.NeighborAddress,
	}
	if isGlobalRib {
		p.peerInfo.ID = g.RouterId
	}
	rfList := p.configuredRFlist()
	p.adjRib = table.NewAdjRib(rfList)
	p.rib = table.NewTableManager(p.peerConfig.NeighborAddress.String(), rfList)
	p.setPolicy(policyMap)
	p.t.Go(p.loop)
	if !peer.TransportOptions.PassiveMode && !isGlobalRib {
		p.t.Go(p.connectLoop)
	}
	return p
}

func (peer *Peer) setPolicy(policyMap map[string]*policy.Policy) {
	// configure import policy
	policyConfig := peer.peerConfig.ApplyPolicy
	inPolicies := make([]*policy.Policy, 0)
	for _, policyName := range policyConfig.ImportPolicies {
		log.WithFields(log.Fields{
			"Topic":      "Peer",
			"Key":        peer.peerConfig.NeighborAddress,
			"PolicyName": policyName,
		}).Info("import policy installed")
		if pol, ok := policyMap[policyName]; ok {
			log.Debug("import policy : ", pol)
			inPolicies = append(inPolicies, pol)
		}
	}
	peer.importPolicies = inPolicies

	// configure export policy
	outPolicies := make([]*policy.Policy, 0)
	for _, policyName := range policyConfig.ExportPolicies {
		log.WithFields(log.Fields{
			"Topic":      "Peer",
			"Key":        peer.peerConfig.NeighborAddress,
			"PolicyName": policyName,
		}).Info("export policy installed")
		if pol, ok := policyMap[policyName]; ok {
			log.Debug("export policy : ", pol)
			outPolicies = append(outPolicies, pol)
		}
	}
	peer.exportPolicies = outPolicies
}

func (peer *Peer) configuredRFlist() []bgp.RouteFamily {
	rfList := []bgp.RouteFamily{}
	for _, rf := range peer.peerConfig.AfiSafiList {
		k, _ := bgp.GetRouteFamily(rf.AfiSafiName)
		rfList = append(rfList, k)
	}
	return rfList
}

func (peer *Peer) sendPathsToSiblings(pathList []table.Path) {
	if len(pathList) == 0 {
		return
	}
	pm := &peerMsg{
		msgType: PEER_MSG_PATH,
		msgData: pathList,
	}
	for _, s := range peer.siblings {
		s.peerMsgCh <- pm
	}
}

func (peer *Peer) handleBGPmessage(m *bgp.BGPMessage) {
	log.WithFields(log.Fields{
		"Topic": "Peer",
		"Key":   peer.peerConfig.NeighborAddress,
		"data":  m,
	}).Debug("received")

	switch m.Header.Type {
	case bgp.BGP_MSG_OPEN:
		body := m.Body.(*bgp.BGPOpen)
		peer.peerInfo.ID = m.Body.(*bgp.BGPOpen).ID
		r := make(map[bgp.RouteFamily]bool)
		for _, p := range body.OptParams {
			if paramCap, y := p.(*bgp.OptionParameterCapability); y {
				for _, c := range paramCap.Capability {
					peer.capMap[c.Code()] = c
					if c.Code() == bgp.BGP_CAP_MULTIPROTOCOL {
						m := c.(*bgp.CapMultiProtocol)
						r[bgp.AfiSafiToRouteFamily(m.CapValue.AFI, m.CapValue.SAFI)] = true
					}
				}
			}
		}

		for rf, _ := range peer.rfMap {
			if _, y := r[rf]; !y {
				delete(peer.rfMap, rf)
			}
		}

		for _, rf := range peer.configuredRFlist() {
			if _, ok := r[rf]; ok {
				peer.rfMap[rf] = true
			}
		}

		// calculate HoldTime
		// RFC 4271 P.13
		// a BGP speaker MUST calculate the value of the Hold Timer
		// by using the smaller of its configured Hold Time and the Hold Time
		// received in the OPEN message.
		holdTime := float64(body.HoldTime)
		myHoldTime := peer.fsm.peerConfig.Timers.HoldTime
		if holdTime > myHoldTime {
			peer.fsm.negotiatedHoldTime = myHoldTime
		} else {
			peer.fsm.negotiatedHoldTime = holdTime
		}

	case bgp.BGP_MSG_ROUTE_REFRESH:
		rr := m.Body.(*bgp.BGPRouteRefresh)
		rf := bgp.AfiSafiToRouteFamily(rr.AFI, rr.SAFI)
		if _, ok := peer.rfMap[rf]; !ok {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.peerConfig.NeighborAddress,
				"Data":  rf,
			}).Warn("Route family isn't supported")
			return
		}
		if _, ok := peer.capMap[bgp.BGP_CAP_ROUTE_REFRESH]; ok {
			pathList := peer.adjRib.GetOutPathList(rf)
			peer.sendMessages(table.CreateUpdateMsgFromPaths(pathList))
		} else {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.peerConfig.NeighborAddress,
			}).Warn("ROUTE_REFRESH received but the capability wasn't advertised")
		}
	case bgp.BGP_MSG_UPDATE:
		peer.peerConfig.BgpNeighborCommonState.UpdateRecvTime = time.Now().Unix()
		body := m.Body.(*bgp.BGPUpdate)
		_, err := bgp.ValidateUpdateMsg(body, peer.rfMap)
		if err != nil {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.peerConfig.NeighborAddress,
				"error": err,
			}).Warn("malformed BGP update message")
			m := err.(*bgp.MessageError)
			if m.TypeCode != 0 {
				peer.outgoing <- bgp.NewBGPNotificationMessage(m.TypeCode, m.SubTypeCode, m.Data)
			}
			return
		}
		table.UpdatePathAttrs4ByteAs(body)
		pathList := table.ProcessMessage(m, peer.peerInfo)
		peer.adjRib.UpdateIn(pathList)
		peer.sendPathsToSiblings(pathList)
	}
}

func (peer *Peer) sendMessages(msgs []*bgp.BGPMessage) {
	for _, m := range msgs {
		if peer.peerConfig.BgpNeighborCommonState.State != uint32(bgp.BGP_FSM_ESTABLISHED) {
			continue
		}

		if m.Header.Type != bgp.BGP_MSG_UPDATE {
			log.Fatal("not update message ", m.Header.Type)
		}

		_, y := peer.capMap[bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER]
		if !y {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.peerConfig.NeighborAddress,
				"data":  m,
			}).Debug("update for 2byte AS peer")
			table.UpdatePathAttrs2ByteAs(m.Body.(*bgp.BGPUpdate))
		}

		peer.outgoing <- m
	}
}

func (peer *Peer) handleGrpc(grpcReq *GrpcRequest) {
	result := &GrpcResponse{}
	switch grpcReq.RequestType {
	case REQ_GLOBAL_ADD, REQ_GLOBAL_DELETE:
		rf := grpcReq.RouteFamily
		path, ok := grpcReq.Data.(*api.Path)
		if !ok {
			result.ResponseErr = fmt.Errorf("type assertion failed")
			grpcReq.ResponseCh <- result
			close(grpcReq.ResponseCh)
			return
		}
		var isWithdraw bool
		if grpcReq.RequestType == REQ_GLOBAL_DELETE {
			isWithdraw = true
		}

		var nlri bgp.AddrPrefixInterface
		pattr := make([]bgp.PathAttributeInterface, 0)
		pattr = append(pattr, bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP))
		asparam := bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{peer.peerInfo.AS})
		pattr = append(pattr, bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{asparam}))

		switch rf {
		case bgp.RF_IPv4_UC:
			ip, net, _ := net.ParseCIDR(path.Nlri.Prefix)
			if ip.To4() == nil {
				result.ResponseErr = fmt.Errorf("Invalid ipv4 prefix: %s", path.Nlri.Prefix)
				grpcReq.ResponseCh <- result
				close(grpcReq.ResponseCh)
				return
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
				return
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
				return
			}
			ip := net.ParseIP(path.Nlri.EvpnNlri.MacIpAdv.IpAddr)
			if ip == nil {
				result.ResponseErr = fmt.Errorf("Invalid ip prefix: %s", path.Nlri.EvpnNlri.MacIpAdv.IpAddr)
				grpcReq.ResponseCh <- result
				close(grpcReq.ResponseCh)
				return
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
				Labels:           path.Nlri.EvpnNlri.MacIpAdv.Labels,
			}
			nlri = bgp.NewEVPNNLRI(bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT, 0, macIpAdv)
			pattr = append(pattr, bgp.NewPathAttributeMpReachNLRI("0.0.0.0", []bgp.AddrPrefixInterface{nlri}))
		case bgp.RF_ENCAP:
			endpoint := net.ParseIP(path.Nlri.Prefix)
			if endpoint == nil {
				result.ResponseErr = fmt.Errorf("Invalid endpoint ip address: %s", path.Nlri.Prefix)
				grpcReq.ResponseCh <- result
				close(grpcReq.ResponseCh)
				return

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

		default:
			result.ResponseErr = fmt.Errorf("Unsupported address family: %s", rf)
			grpcReq.ResponseCh <- result
			close(grpcReq.ResponseCh)
			return
		}

		p, err := table.CreatePath(peer.peerInfo, nlri, pattr, isWithdraw, time.Now())
		if err != nil {
			result.ResponseErr = err
			grpcReq.ResponseCh <- result
			close(grpcReq.ResponseCh)
			return
		}

		pm := &peerMsg{
			msgType: PEER_MSG_PATH,
			msgData: []table.Path{p},
		}
		peer.peerMsgCh <- pm

	case REQ_LOCAL_RIB, REQ_GLOBAL_RIB:
		if peer.fsm.adminState == ADMIN_STATE_DOWN {
			close(grpcReq.ResponseCh)
			return
		}
		if t, ok := peer.rib.Tables[grpcReq.RouteFamily]; ok {
			for _, dst := range t.GetDestinations() {
				result := &GrpcResponse{}
				result.Data = dst.ToApiStruct()
				grpcReq.ResponseCh <- result
			}
		}
		close(grpcReq.ResponseCh)
		return
	case REQ_MONITOR_BEST_CHANGED:
		peer.t.Go(func() error {
			r := peer.broadcaster.Listen()
			for {
				select {
				case <-peer.t.Dying():
					break
				case b := <-r.C:
					v := b.v
					r.C <- b
					r.C = b.c
					for _, path := range v.([]table.Path) {
						result := &GrpcResponse{
							Data: path.ToApiStruct(),
						}
						grpcReq.ResponseCh <- result
					}
				}
			}
			close(grpcReq.ResponseCh)
			return nil
		})
		return
	case REQ_NEIGHBOR_SHUTDOWN:
		peer.outgoing <- bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN, nil)
	case REQ_NEIGHBOR_RESET:
		peer.fsm.idleHoldTime = peer.peerConfig.Timers.IdleHoldTimeAfterReset
		peer.outgoing <- bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET, nil)
	case REQ_NEIGHBOR_SOFT_RESET, REQ_NEIGHBOR_SOFT_RESET_IN:
		// soft-reconfiguration inbound
		peer.sendPathsToSiblings(peer.adjRib.GetInPathList(grpcReq.RouteFamily))
		if grpcReq.RequestType == REQ_NEIGHBOR_SOFT_RESET_IN {
			break
		}
		fallthrough
	case REQ_NEIGHBOR_SOFT_RESET_OUT:
		pathList := peer.adjRib.GetOutPathList(grpcReq.RouteFamily)
		peer.sendMessages(table.CreateUpdateMsgFromPaths(pathList))
	case REQ_ADJ_RIB_IN, REQ_ADJ_RIB_OUT:
		rf := grpcReq.RouteFamily
		var paths []table.Path

		if grpcReq.RequestType == REQ_ADJ_RIB_IN {
			paths = peer.adjRib.GetInPathList(rf)
			log.Debugf("RouteFamily=%v adj-rib-in found : %d", rf.String(), len(paths))
		} else {
			paths = peer.adjRib.GetOutPathList(rf)
			log.Debugf("RouteFamily=%v adj-rib-out found : %d", rf.String(), len(paths))
		}

		for _, p := range paths {
			result := &GrpcResponse{}
			path := &api.Path{}
			j, _ := json.Marshal(p)
			err := json.Unmarshal(j, path)
			if err != nil {
				result.ResponseErr = err
			} else {
				result.Data = path
			}
			grpcReq.ResponseCh <- result
		}
		close(grpcReq.ResponseCh)
		return
	case REQ_NEIGHBOR_ENABLE, REQ_NEIGHBOR_DISABLE:
		var err api.Error
		if grpcReq.RequestType == REQ_NEIGHBOR_ENABLE {
			select {
			case peer.fsm.adminStateCh <- ADMIN_STATE_UP:
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   peer.peerConfig.NeighborAddress,
				}).Debug("ADMIN_STATE_UP requested")
				err.Code = api.Error_SUCCESS
				err.Msg = "ADMIN_STATE_UP"
			default:
				log.Warning("previous request is still remaining. : ", peer.peerConfig.NeighborAddress)
				err.Code = api.Error_FAIL
				err.Msg = "previous request is still remaining"
			}
		} else {
			select {
			case peer.fsm.adminStateCh <- ADMIN_STATE_DOWN:
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   peer.peerConfig.NeighborAddress,
				}).Debug("ADMIN_STATE_DOWN requested")
				err.Code = api.Error_SUCCESS
				err.Msg = "ADMIN_STATE_DOWN"
			default:
				log.Warning("previous request is still remaining. : ", peer.peerConfig.NeighborAddress)
				err.Code = api.Error_FAIL
				err.Msg = "previous request is still remaining"
			}
		}
		result.Data = err
	}
	grpcReq.ResponseCh <- result
	close(grpcReq.ResponseCh)
}

func (peer *Peer) sendUpdateMsgFromPaths(pList []table.Path) {
	pList = func(arg []table.Path) []table.Path {
		ret := make([]table.Path, 0, len(arg))
		for _, path := range arg {
			if _, ok := peer.rfMap[path.GetRouteFamily()]; !ok {
				continue
			}
			if peer.peerConfig.NeighborAddress.Equal(path.GetSource().Address) {
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   peer.peerConfig.NeighborAddress,
					"Data":  path,
				}).Debug("From me, ignore.")
				continue
			}

			if peer.peerConfig.PeerAs == path.GetSourceAs() {
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   peer.peerConfig.NeighborAddress,
					"Data":  path,
				}).Debug("AS PATH loop, ignore.")
				continue
			}

			if !path.IsWithdraw() {
				applied, path := peer.applyPolicies(peer.exportPolicies, path)
				if applied && path == nil {
					log.WithFields(log.Fields{
						"Topic": "Peer",
						"Key":   peer.peerConfig.NeighborAddress,
						"Data":  path,
					}).Debug("Export policy applied, reject.")
					continue
				} else if peer.defaultExportPolicy != config.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE {
					log.WithFields(log.Fields{
						"Topic": "Peer",
						"Key":   peer.peerConfig.NeighborAddress,
						"Data":  path,
					}).Debug("Default export policy applied, reject.")
					continue
				}
			}

			ret = append(ret, path.Clone(path.IsWithdraw()))
		}
		return ret
	}(pList)

	peer.adjRib.UpdateOut(pList)

	if bgp.FSMState(peer.peerConfig.BgpNeighborCommonState.State) != bgp.BGP_FSM_ESTABLISHED || len(pList) == 0 {
		return
	}

	pList = func(arg []table.Path) []table.Path {
		ret := make([]table.Path, 0, len(arg))
		for _, path := range pList {
			isLocal := path.GetSource().ID.Equal(peer.peerInfo.LocalID)
			if isLocal {
				path.SetNexthop(peer.peerConfig.LocalAddress)
			} else {
				table.UpdatePathAttrs(path, &peer.globalConfig, &peer.peerConfig)
			}

			ret = append(ret, path)
		}
		return ret
	}(pList)

	peer.sendMessages(table.CreateUpdateMsgFromPaths(pList))
}

// apply policies to the path
// if multiple policies are defined,
// this function applies each policy to the path in the order that
// policies are stored in the array passed to this function.
//
// the way of applying statements inside a single policy
//   - apply statement until the condition in the statement matches.
//     if the condition matches the path, apply the action on the statement and
//     return value that indicates 'applied' to caller of this function
//   - if no statement applied, then process the next policy
//
// if no policy applied, return value that indicates 'not applied' to the caller of this function
//
// return values:
//	bool -- indicates that any of policy applied to the path that is passed to this function
//  table.Path -- indicates new path object that is the result of modification according to
//                policy's action.
//                If the applied policy doesn't have a modification action,
//                then return the path itself that is passed to this function, otherwise return
//                modified path.
//                If action of the policy is 'reject', return nil
//
func (peer *Peer) applyPolicies(policies []*policy.Policy, original table.Path) (bool, table.Path) {

	var applied bool = true

	for _, pol := range policies {
		if result, action, newpath := pol.Apply(original); result {
			log.Debug("newpath: ", newpath)
			if action == policy.ROUTE_TYPE_REJECT {
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   peer.peerConfig.NeighborAddress,
					"NRLI":  original.GetNlri(),
				}).Debug("path was rejected")
				// return applied, nil, this means path was rejected
				return applied, nil
			} else {
				// return applied, new path
				return applied, newpath
			}
		}
	}
	log.Debug("no policy applied.", original)
	// return not applied, original path
	return !applied, original
}

func (peer *Peer) handlePeerMsg(m *peerMsg) {
	switch m.msgType {
	case PEER_MSG_PATH:
		pList := m.msgData.([]table.Path)

		tmp := make([]table.Path, 0, len(pList))
		for _, path := range pList {
			if path.IsWithdraw() {
				tmp = append(tmp, path)
				continue
			}

			applied, path := peer.applyPolicies(peer.importPolicies, path)
			if applied && path == nil {
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   peer.peerConfig.NeighborAddress,
					"Data":  path,
				}).Debug("Import policy applied, reject.")
				continue
			} else if peer.defaultImportPolicy != config.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE {
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   peer.peerConfig.NeighborAddress,
					"Data":  path,
				}).Debug("Default import policy applied, reject.")
				continue
			}

			tmp = append(tmp, path)
		}
		pList = tmp

		if peer.peerConfig.RouteServer.RouteServerClient || peer.isGlobalRib {
			pList, _ = peer.rib.ProcessPaths(pList)
			peer.broadcaster.Write(pList)
		}

		if peer.isGlobalRib {
			peer.sendPathsToSiblings(pList)
		} else {
			peer.sendUpdateMsgFromPaths(pList)
		}

	case PEER_MSG_PEER_DOWN:
		for _, rf := range peer.configuredRFlist() {
			pList, _ := peer.rib.DeletePathsforPeer(m.msgData.(*table.PeerInfo), rf)
			if peer.peerConfig.RouteServer.RouteServerClient {
				peer.sendUpdateMsgFromPaths(pList)
			} else if peer.isGlobalRib {
				peer.sendPathsToSiblings(pList)
			}
		}
	}
}

func (peer *Peer) handleServerMsg(m *serverMsg) {
	switch m.msgType {
	case SRV_MSG_PEER_ADDED:
		d := m.msgData.(*serverMsgDataPeer)
		peer.siblings[d.address.String()] = d
		for _, rf := range peer.configuredRFlist() {
			if peer.peerConfig.RouteServer.RouteServerClient {
				peer.sendPathsToSiblings(peer.adjRib.GetInPathList(rf))
			} else if peer.isGlobalRib {
				peer.sendPathsToSiblings(peer.rib.GetPathList(rf))
			}
		}
	case SRV_MSG_PEER_DELETED:
		d := m.msgData.(*table.PeerInfo)
		if _, ok := peer.siblings[d.Address.String()]; ok {
			delete(peer.siblings, d.Address.String())
			for _, rf := range peer.configuredRFlist() {
				pList, _ := peer.rib.DeletePathsforPeer(d, rf)
				if peer.peerConfig.RouteServer.RouteServerClient {
					peer.sendUpdateMsgFromPaths(pList)
				} else {
					peer.sendPathsToSiblings(pList)
				}
			}
		} else {
			log.Warning("can not find peer: ", d.Address.String())
		}
	case SRV_MSG_API:
		peer.handleGrpc(m.msgData.(*GrpcRequest))
	case SRV_MSG_POLICY_UPDATED:
		log.Debug("policy updated")
		d := m.msgData.(map[string]*policy.Policy)
		peer.setPolicy(d)
	default:
		log.Fatal("unknown server msg type ", m.msgType)
	}
}

func (peer *Peer) connectLoop() error {
	var tick int
	if tick = int(peer.fsm.peerConfig.Timers.ConnectRetry); tick < MIN_CONNECT_RETRY {
		tick = MIN_CONNECT_RETRY
	}

	ticker := time.NewTicker(time.Duration(tick) * time.Second)
	ticker.Stop()

	connect := func() {
		if bgp.FSMState(peer.peerConfig.BgpNeighborCommonState.State) == bgp.BGP_FSM_ACTIVE {
			var host string
			addr := peer.peerConfig.NeighborAddress

			if addr.To4() != nil {
				host = addr.String() + ":" + strconv.Itoa(bgp.BGP_PORT)
			} else {
				host = "[" + addr.String() + "]:" + strconv.Itoa(bgp.BGP_PORT)
			}

			conn, err := net.DialTimeout("tcp", host, time.Duration(MIN_CONNECT_RETRY-1)*time.Second)
			if err == nil {
				peer.connCh <- conn
			} else {
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   peer.peerConfig.NeighborAddress,
				}).Debugf("failed to connect: %s", err)
			}
		}
	}

	for {
		select {
		case <-peer.t.Dying():
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.peerConfig.NeighborAddress,
			}).Debug("stop connect loop")
			ticker.Stop()
			return nil
		case <-ticker.C:
			connect()
		case <-peer.getActiveCh:
			ticker = time.NewTicker(time.Duration(tick) * time.Second)
		}
	}
}

// this goroutine handles routing table operations
func (peer *Peer) loop() error {
	for {
		incoming := make(chan *fsmMsg, FSM_CHANNEL_LENGTH)
		peer.outgoing = make(chan *bgp.BGPMessage, FSM_CHANNEL_LENGTH)

		var h *FSMHandler

		if !peer.isGlobalRib {
			h = NewFSMHandler(peer.fsm, incoming, peer.outgoing)
			switch peer.peerConfig.BgpNeighborCommonState.State {
			case uint32(bgp.BGP_FSM_ESTABLISHED):
				peer.peerConfig.LocalAddress = peer.fsm.LocalAddr()
				for rf, _ := range peer.rfMap {
					pathList := peer.adjRib.GetOutPathList(rf)
					if !peer.peerConfig.RouteServer.RouteServerClient {
						for _, path := range pathList {
							path.SetNexthop(peer.peerConfig.LocalAddress)
						}
					}
					peer.sendMessages(table.CreateUpdateMsgFromPaths(pathList))
				}
				peer.fsm.peerConfig.BgpNeighborCommonState.Uptime = time.Now().Unix()
				peer.fsm.peerConfig.BgpNeighborCommonState.EstablishedCount++
			case uint32(bgp.BGP_FSM_ACTIVE):
				if !peer.peerConfig.TransportOptions.PassiveMode {
					peer.getActiveCh <- struct{}{}
				}
				fallthrough
			default:
				peer.fsm.peerConfig.BgpNeighborCommonState.Downtime = time.Now().Unix()
			}
		}

		sameState := true
		for sameState {
			select {
			case <-peer.t.Dying():
				close(peer.connCh)
				peer.outgoing <- bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_PEER_DECONFIGURED, nil)
				// h.t.Kill(nil) will be called
				// internall so even goroutines in
				// non-established will be killed.
				h.Stop()
				return nil
			case e := <-incoming:
				switch e.MsgType {
				case FSM_MSG_STATE_CHANGE:
					nextState := e.MsgData.(bgp.FSMState)
					// waits for all goroutines created for the current state
					h.Wait()
					oldState := bgp.FSMState(peer.peerConfig.BgpNeighborCommonState.State)
					peer.peerConfig.BgpNeighborCommonState.State = uint32(nextState)
					peer.fsm.StateChange(nextState)
					sameState = false
					if oldState == bgp.BGP_FSM_ESTABLISHED {
						t := time.Now()
						if t.Sub(time.Unix(peer.fsm.peerConfig.BgpNeighborCommonState.Uptime, 0)) < FLOP_THRESHOLD {
							peer.fsm.peerConfig.BgpNeighborCommonState.Flops++
						}

						for _, rf := range peer.configuredRFlist() {
							peer.adjRib.DropAllIn(rf)
						}
						pm := &peerMsg{
							msgType: PEER_MSG_PEER_DOWN,
							msgData: peer.peerInfo,
						}
						for _, s := range peer.siblings {
							s.peerMsgCh <- pm
						}
					}

					// clear counter
					if h.fsm.adminState == ADMIN_STATE_DOWN {
						h.fsm.peerConfig.BgpNeighborCommonState = config.BgpNeighborCommonState{}
					}

				case FSM_MSG_BGP_MESSAGE:
					switch m := e.MsgData.(type) {
					case *bgp.MessageError:
						peer.outgoing <- bgp.NewBGPNotificationMessage(m.TypeCode, m.SubTypeCode, m.Data)
					case *bgp.BGPMessage:
						peer.handleBGPmessage(m)
					default:
						log.WithFields(log.Fields{
							"Topic": "Peer",
							"Key":   peer.peerConfig.NeighborAddress,
							"Data":  e.MsgData,
						}).Panic("unknonw msg type")
					}
				}
			case m := <-peer.serverMsgCh:
				peer.handleServerMsg(m)
			case m := <-peer.peerMsgCh:
				peer.handlePeerMsg(m)
			}
		}
	}
}

func (peer *Peer) Stop() error {
	peer.t.Kill(nil)
	return peer.t.Wait()
}

func (peer *Peer) PassConn(conn *net.TCPConn) {
	peer.connCh <- conn
}

func (peer *Peer) MarshalJSON() ([]byte, error) {
	return json.Marshal(peer.ToApiStruct())
}

func (peer *Peer) ToApiStruct() *api.Peer {

	f := peer.fsm
	c := f.peerConfig

	capList := make([]int32, 0, len(peer.capMap))
	for k, _ := range peer.capMap {
		capList = append(capList, int32(k))
	}

	conf := &api.PeerConf{
		RemoteIp:  c.NeighborAddress.String(),
		Id:        peer.peerInfo.ID.To4().String(),
		RemoteAs:  c.PeerAs,
		RemoteCap: capList,
		LocalCap:  []int32{int32(bgp.BGP_CAP_MULTIPROTOCOL), int32(bgp.BGP_CAP_ROUTE_REFRESH), int32(bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER)},
	}

	s := c.BgpNeighborCommonState

	uptime := int64(0)
	if s.Uptime != 0 {
		uptime = int64(time.Now().Sub(time.Unix(s.Uptime, 0)).Seconds())
	}
	downtime := int64(0)
	if s.Downtime != 0 {
		downtime = int64(time.Now().Sub(time.Unix(s.Downtime, 0)).Seconds())
	}

	advertized := uint32(0)
	received := uint32(0)
	accepted := uint32(0)
	if f.state == bgp.BGP_FSM_ESTABLISHED {
		for _, rf := range peer.configuredRFlist() {
			advertized += uint32(peer.adjRib.GetOutCount(rf))
			received += uint32(peer.adjRib.GetInCount(rf))
			accepted += uint32(peer.adjRib.GetInCount(rf))
		}
	}

	info := &api.PeerInfo{
		BgpState:                  f.state.String(),
		AdminState:                f.adminState.String(),
		FsmEstablishedTransitions: s.EstablishedCount,
		TotalMessageOut:           s.TotalOut,
		TotalMessageIn:            s.TotalIn,
		UpdateMessageOut:          s.UpdateOut,
		UpdateMessageIn:           s.UpdateIn,
		KeepAliveMessageOut:       s.KeepaliveOut,
		KeepAliveMessageIn:        s.KeepaliveIn,
		OpenMessageOut:            s.OpenOut,
		OpenMessageIn:             s.OpenIn,
		NotificationOut:           s.NotifyOut,
		NotificationIn:            s.NotifyIn,
		RefreshMessageOut:         s.RefreshOut,
		RefreshMessageIn:          s.RefreshIn,
		DiscardedOut:              s.DiscardedOut,
		DiscardedIn:               s.DiscardedIn,
		Uptime:                    uptime,
		Downtime:                  downtime,
		Received:                  received,
		Accepted:                  accepted,
		Advertized:                advertized,
		OutQ:                      uint32(len(peer.outgoing)),
		Flops:                     s.Flops,
	}

	return &api.Peer{
		Conf: conf,
		Info: info,
	}
}
