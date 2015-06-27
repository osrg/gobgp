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
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/policy"
	"github.com/osrg/gobgp/table"
	"net"
	"time"
)

const (
	FLOP_THRESHOLD    = time.Second * 30
	MIN_CONNECT_RETRY = 10
)

type Peer struct {
	globalConfig config.Global
	config       config.Neighbor
	fsm          *FSM
	rfMap        map[bgp.RouteFamily]bool
	capMap       map[bgp.BGPCapabilityCode]bgp.ParameterCapabilityInterface
	adjRib       *table.AdjRib
	peerInfo     *table.PeerInfo
	outgoing     chan *bgp.BGPMessage
}

func NewPeer(g config.Global, config config.Neighbor) *Peer {
	peer := &Peer{
		globalConfig: g,
		config:       config,
		rfMap:        make(map[bgp.RouteFamily]bool),
		capMap:       make(map[bgp.BGPCapabilityCode]bgp.ParameterCapabilityInterface),
	}

	config.BgpNeighborCommonState.State = uint32(bgp.BGP_FSM_IDLE)
	config.BgpNeighborCommonState.Downtime = time.Now().Unix()
	for _, rf := range config.AfiSafiList {
		k, _ := bgp.GetRouteFamily(rf.AfiSafiName)
		peer.rfMap[k] = true
	}
	peer.peerInfo = &table.PeerInfo{
		AS:      config.PeerAs,
		LocalID: g.RouterId,
		Address: config.NeighborAddress,
	}
	peer.adjRib = table.NewAdjRib(peer.configuredRFlist())
	peer.fsm = NewFSM(&g, &config)
	return peer
}

func (peer *Peer) isRouteServerClient() bool {
	return peer.config.RouteServer.RouteServerClient
}

func (peer *Peer) configuredRFlist() []bgp.RouteFamily {
	rfList := []bgp.RouteFamily{}
	for _, rf := range peer.config.AfiSafiList {
		k, _ := bgp.GetRouteFamily(rf.AfiSafiName)
		rfList = append(rfList, k)
	}
	return rfList
}

func (peer *Peer) handleBGPmessage(m *bgp.BGPMessage) ([]*table.Path, bool, []*bgp.BGPMessage) {
	bgpMsgList := []*bgp.BGPMessage{}
	pathList := []*table.Path{}
	log.WithFields(log.Fields{
		"Topic": "Peer",
		"Key":   peer.config.NeighborAddress,
		"data":  m,
	}).Debug("received")
	update := false

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
		myHoldTime := peer.config.Timers.HoldTime
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
				"Key":   peer.config.NeighborAddress,
				"Data":  rf,
			}).Warn("Route family isn't supported")
			break
		}
		if _, ok := peer.capMap[bgp.BGP_CAP_ROUTE_REFRESH]; ok {
			pathList = peer.adjRib.GetOutPathList(rf)
		} else {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.config.NeighborAddress,
			}).Warn("ROUTE_REFRESH received but the capability wasn't advertised")
		}

	case bgp.BGP_MSG_UPDATE:
		update = true
		peer.config.BgpNeighborCommonState.UpdateRecvTime = time.Now().Unix()
		body := m.Body.(*bgp.BGPUpdate)
		_, err := bgp.ValidateUpdateMsg(body, peer.rfMap)
		if err != nil {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.config.NeighborAddress,
				"error": err,
			}).Warn("malformed BGP update message")
			m := err.(*bgp.MessageError)
			if m.TypeCode != 0 {
				bgpMsgList = append(bgpMsgList, bgp.NewBGPNotificationMessage(m.TypeCode, m.SubTypeCode, m.Data))
			}
			break
		}
		table.UpdatePathAttrs4ByteAs(body)
		pathList = table.ProcessMessage(m, peer.peerInfo)
		peer.adjRib.UpdateIn(pathList)
	}
	return pathList, update, bgpMsgList
}

func (peer *Peer) getBests(loc *LocalRib) []*table.Path {
	pathList := []*table.Path{}
	for _, rf := range peer.configuredRFlist() {
		for _, paths := range loc.rib.GetPathList(rf) {
			pathList = append(pathList, paths)
		}
	}
	return pathList
}

func (peer *Peer) startFSMHandler(incoming chan *fsmMsg) {
	peer.fsm.h = NewFSMHandler(peer.fsm, incoming, peer.outgoing)
}

func (peer *Peer) PassConn(conn *net.TCPConn) {
	select {
	case peer.fsm.connCh <- conn:
	default:
		conn.Close()
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   peer.config.NeighborAddress,
		}).Warn("accepted conn is closed to avoid be blocked")
	}
}

func (peer *Peer) MarshalJSON() ([]byte, error) {
	return json.Marshal(peer.ToApiStruct())
}

func (peer *Peer) ToApiStruct() *api.Peer {

	f := peer.fsm
	c := f.peerConfig

	remoteCap := make([]*api.Capability, 0, len(peer.capMap))
	for _, c := range peer.capMap {
		remoteCap = append(remoteCap, c.ToApiStruct())
	}

	caps := capabilitiesFromConfig(&peer.globalConfig, &peer.config)
	localCap := make([]*api.Capability, 0, len(caps))
	for _, c := range caps {
		localCap = append(localCap, c.ToApiStruct())
	}

	conf := &api.PeerConf{
		RemoteIp:          c.NeighborAddress.String(),
		Id:                peer.peerInfo.ID.To4().String(),
		RemoteAs:          c.PeerAs,
		RemoteCap:         remoteCap,
		LocalCap:          localCap,
		KeepaliveInterval: uint32(peer.config.Timers.KeepaliveInterval),
		Holdtime:          uint32(peer.config.Timers.HoldTime),
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

	keepalive := uint32(0)
	if f.negotiatedHoldTime != 0 {
		if f.negotiatedHoldTime < c.Timers.HoldTime {
			keepalive = uint32(f.negotiatedHoldTime / 3)
		} else {
			keepalive = uint32(c.Timers.KeepaliveInterval)
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
		NegotiatedHoldtime:        uint32(f.negotiatedHoldTime),
		KeepaliveInterval:         keepalive,
	}

	return &api.Peer{
		Conf: conf,
		Info: info,
	}
}

type LocalRib struct {
	rib                 *table.TableManager
	importPolicies      []*policy.Policy
	defaultImportPolicy config.DefaultPolicyType
	exportPolicies      []*policy.Policy
	defaultExportPolicy config.DefaultPolicyType
}

func NewLocalRib(owner string, rfList []bgp.RouteFamily, policyMap map[string]*policy.Policy) *LocalRib {
	return &LocalRib{
		rib: table.NewTableManager(owner, rfList),
	}
}

func (loc *LocalRib) OwnerName() string {
	return loc.rib.OwnerName()
}

func (loc *LocalRib) isGlobal() bool {
	return loc.OwnerName() == "global"
}

func (loc *LocalRib) setPolicy(peer *Peer, policyMap map[string]*policy.Policy) {
	// configure import policy
	policyConfig := peer.config.ApplyPolicy
	inPolicies := make([]*policy.Policy, 0)
	for _, policyName := range policyConfig.ImportPolicies {
		log.WithFields(log.Fields{
			"Topic":      "Peer",
			"Key":        peer.config.NeighborAddress,
			"PolicyName": policyName,
		}).Info("import policy installed")
		if pol, ok := policyMap[policyName]; ok {
			log.Debug("import policy : ", pol)
			inPolicies = append(inPolicies, pol)
		}
	}
	loc.importPolicies = inPolicies
	loc.defaultImportPolicy = policyConfig.DefaultImportPolicy

	// configure export policy
	outPolicies := make([]*policy.Policy, 0)
	for _, policyName := range policyConfig.ExportPolicies {
		log.WithFields(log.Fields{
			"Topic":      "Peer",
			"Key":        peer.config.NeighborAddress,
			"PolicyName": policyName,
		}).Info("export policy installed")
		if pol, ok := policyMap[policyName]; ok {
			log.Debug("export policy : ", pol)
			outPolicies = append(outPolicies, pol)
		}
	}
	loc.exportPolicies = outPolicies
	loc.defaultExportPolicy = policyConfig.DefaultExportPolicy
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
func (loc *LocalRib) applyPolicies(isExport bool, original *table.Path) (bool, *table.Path) {

	var applied bool = true
	var policies []*policy.Policy
	var direction string
	if isExport == true {
		policies = loc.exportPolicies
		direction = "export"
	} else {
		policies = loc.importPolicies
		direction = "import"
	}

	for _, pol := range policies {
		if result, action, newpath := pol.Apply(original); result {
			log.Debug("newpath: ", newpath)
			if action == policy.ROUTE_TYPE_REJECT {
				log.WithFields(log.Fields{
					"Topic": "Loc",
					"Key":   loc.OwnerName(),
					"NRLI":  original.GetNlri(),
					"Dir":   direction,
				}).Debug("path was rejected")
				// return applied, nil, this means path was rejected
				return applied, nil
			} else {
				// return applied, new path
				return applied, newpath
			}
		}
	}
	log.WithFields(log.Fields{
		"Topic": "Loc",
		"Key":   loc.OwnerName(),
		"Len":   len(policies),
		"NRLI":  original,
		"Dir":   direction,
	}).Debug("no policy applied")
	return !applied, original
}
