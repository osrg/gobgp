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
	gConf                   config.Global
	conf                    config.Neighbor
	fsm                     *FSM
	rfMap                   map[bgp.RouteFamily]bool
	capMap                  map[bgp.BGPCapabilityCode][]bgp.ParameterCapabilityInterface
	adjRib                  *table.AdjRib
	peerInfo                *table.PeerInfo
	outgoing                chan *bgp.BGPMessage
	distPolicies            []*policy.Policy
	defaultDistributePolicy config.DefaultPolicyType
	isConfederationMember   bool
	isEBGP                  bool
}

func NewPeer(g config.Global, conf config.Neighbor) *Peer {
	peer := &Peer{
		gConf:  g,
		conf:   conf,
		rfMap:  make(map[bgp.RouteFamily]bool),
		capMap: make(map[bgp.BGPCapabilityCode][]bgp.ParameterCapabilityInterface),
	}

	conf.NeighborState.SessionState = uint32(bgp.BGP_FSM_IDLE)
	conf.Timers.TimersState.Downtime = time.Now().Unix()
	for _, rf := range conf.AfiSafis.AfiSafiList {
		k, _ := bgp.GetRouteFamily(rf.AfiSafiName)
		peer.rfMap[k] = true
	}
	peer.peerInfo = &table.PeerInfo{
		AS:      conf.NeighborConfig.PeerAs,
		LocalAS: g.GlobalConfig.As,
		LocalID: g.GlobalConfig.RouterId,
		Address: conf.NeighborConfig.NeighborAddress,
	}
	peer.adjRib = table.NewAdjRib(peer.configuredRFlist())
	peer.fsm = NewFSM(&g, &conf)

	if conf.NeighborConfig.PeerAs != g.GlobalConfig.As {
		peer.isEBGP = true
		for _, member := range g.Confederation.ConfederationConfig.MemberAs {
			if member == conf.NeighborConfig.PeerAs {
				peer.isConfederationMember = true
				break
			}
		}
	}

	return peer
}

func (peer *Peer) isRouteServerClient() bool {
	return peer.conf.RouteServer.RouteServerConfig.RouteServerClient
}

func (peer *Peer) configuredRFlist() []bgp.RouteFamily {
	rfList := []bgp.RouteFamily{}
	for _, rf := range peer.conf.AfiSafis.AfiSafiList {
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
		"Key":   peer.conf.NeighborConfig.NeighborAddress,
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
					m, ok := peer.capMap[c.Code()]
					if !ok {
						m = make([]bgp.ParameterCapabilityInterface, 0, 1)
					}
					peer.capMap[c.Code()] = append(m, c)

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
		myHoldTime := peer.conf.Timers.TimersConfig.HoldTime
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
				"Key":   peer.conf.NeighborConfig.NeighborAddress,
				"Data":  rf,
			}).Warn("Route family isn't supported")
			break
		}
		if _, ok := peer.capMap[bgp.BGP_CAP_ROUTE_REFRESH]; ok {
			pathList = peer.adjRib.GetOutPathList(rf)
		} else {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.conf.NeighborConfig.NeighborAddress,
			}).Warn("ROUTE_REFRESH received but the capability wasn't advertised")
		}

	case bgp.BGP_MSG_UPDATE:
		update = true
		peer.conf.Timers.TimersState.UpdateRecvTime = time.Now().Unix()
		body := m.Body.(*bgp.BGPUpdate)
		confedCheckRequired := !peer.isConfederationMember && peer.isEBGP
		_, err := bgp.ValidateUpdateMsg(body, peer.rfMap, confedCheckRequired)
		if err != nil {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.conf.NeighborConfig.NeighborAddress,
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
		for _, paths := range loc.rib.GetBestPathList(rf) {
			pathList = append(pathList, paths)
		}
	}
	return pathList
}

func (peer *Peer) startFSMHandler(incoming chan *fsmMsg) {
	peer.fsm.h = NewFSMHandler(peer.fsm, incoming, peer.outgoing)
}

func (peer *Peer) PassConn(conn *net.TCPConn) {
	isEBGP := peer.gConf.GlobalConfig.As != peer.conf.NeighborConfig.PeerAs
	if isEBGP {
		ttl := 1
		SetTcpTTLSockopts(conn, ttl)
	}
	select {
	case peer.fsm.connCh <- conn:
	default:
		conn.Close()
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   peer.conf.NeighborConfig.NeighborAddress,
		}).Warn("accepted conn is closed to avoid be blocked")
	}
}

func (peer *Peer) MarshalJSON() ([]byte, error) {
	return json.Marshal(peer.ToApiStruct())
}

func (peer *Peer) ToApiStruct() *api.Peer {

	f := peer.fsm
	c := f.pConf

	remoteCap := make([]*api.Capability, 0, len(peer.capMap))
	for _, c := range peer.capMap {
		for _, m := range c {
			remoteCap = append(remoteCap, m.ToApiStruct())
		}
	}

	caps := capabilitiesFromConfig(&peer.gConf, &peer.conf)
	localCap := make([]*api.Capability, 0, len(caps))
	for _, c := range caps {
		localCap = append(localCap, c.ToApiStruct())
	}

	conf := &api.PeerConf{
		RemoteIp:          c.NeighborConfig.NeighborAddress.String(),
		Id:                peer.peerInfo.ID.To4().String(),
		RemoteAs:          c.NeighborConfig.PeerAs,
		RemoteCap:         remoteCap,
		LocalCap:          localCap,
		KeepaliveInterval: uint32(peer.conf.Timers.TimersConfig.KeepaliveInterval),
		Holdtime:          uint32(peer.conf.Timers.TimersConfig.HoldTime),
	}

	s := &c.NeighborState
	timer := &c.Timers

	uptime := int64(0)
	if timer.TimersState.Uptime != 0 {
		uptime = int64(time.Now().Sub(time.Unix(timer.TimersState.Uptime, 0)).Seconds())
	}
	downtime := int64(0)
	if timer.TimersState.Downtime != 0 {
		downtime = int64(time.Now().Sub(time.Unix(timer.TimersState.Downtime, 0)).Seconds())
	}

	advertized := uint32(0)
	received := uint32(0)
	accepted := uint32(0)
	if f.state == bgp.BGP_FSM_ESTABLISHED {
		for _, rf := range peer.configuredRFlist() {
			advertized += uint32(peer.adjRib.GetOutCount(rf))
			received += uint32(peer.adjRib.GetInCount(rf))
			// FIXME: we should store 'accepted' in memory
			for _, p := range peer.adjRib.GetInPathList(rf) {
				applied, path := peer.applyDistributePolicies(p)
				if applied && path == nil || !applied && peer.defaultDistributePolicy != config.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE {
					continue
				}
				accepted += 1
			}
		}
	}

	keepalive := uint32(0)
	if f.negotiatedHoldTime != 0 {
		if f.negotiatedHoldTime < timer.TimersConfig.HoldTime {
			keepalive = uint32(f.negotiatedHoldTime / 3)
		} else {
			keepalive = uint32(timer.TimersConfig.KeepaliveInterval)
		}
	}

	info := &api.PeerInfo{
		BgpState:                  f.state.String(),
		AdminState:                f.adminState.String(),
		FsmEstablishedTransitions: s.EstablishedCount,
		TotalMessageOut:           s.Messages.Sent.Total,
		TotalMessageIn:            s.Messages.Received.Total,
		UpdateMessageOut:          s.Messages.Sent.Update,
		UpdateMessageIn:           s.Messages.Received.Update,
		KeepAliveMessageOut:       s.Messages.Sent.Keepalive,
		KeepAliveMessageIn:        s.Messages.Received.Keepalive,
		OpenMessageOut:            s.Messages.Sent.Open,
		OpenMessageIn:             s.Messages.Received.Open,
		NotificationOut:           s.Messages.Sent.Notification,
		NotificationIn:            s.Messages.Received.Notification,
		RefreshMessageOut:         s.Messages.Sent.Refresh,
		RefreshMessageIn:          s.Messages.Received.Refresh,
		DiscardedOut:              s.Messages.Sent.Discarded,
		DiscardedIn:               s.Messages.Received.Discarded,
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

func (peer *Peer) setDistributePolicy(policyMap map[string]*policy.Policy) {
	// configure distribute policy
	policyConf := peer.conf.ApplyPolicy
	distPolicies := make([]*policy.Policy, 0)
	for _, policyName := range policyConf.ApplyPolicyConfig.InPolicy {
		log.WithFields(log.Fields{
			"Topic":      "Peer",
			"Key":        peer.conf.NeighborConfig.NeighborAddress,
			"PolicyName": policyName,
		}).Info("distribute policy installed")
		if pol, ok := policyMap[policyName]; ok {
			log.Debug("distribute policy : ", pol)
			distPolicies = append(distPolicies, pol)
		}
	}
	peer.distPolicies = distPolicies
	peer.defaultDistributePolicy = policyConf.ApplyPolicyConfig.DefaultInPolicy
}

func (peer *Peer) applyDistributePolicies(original *table.Path) (bool, *table.Path) {
	policies := peer.distPolicies
	var d Direction = POLICY_DIRECTION_DISTRIBUTE

	return applyPolicy("Peer", peer.conf.NeighborConfig.NeighborAddress.String(), d, policies, original)
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
	policyConf := peer.conf.ApplyPolicy
	inPolicies := make([]*policy.Policy, 0)
	for _, policyName := range policyConf.ApplyPolicyConfig.ImportPolicy {
		log.WithFields(log.Fields{
			"Topic":      "Peer",
			"Key":        peer.conf.NeighborConfig.NeighborAddress,
			"PolicyName": policyName,
		}).Info("import policy installed")
		if pol, ok := policyMap[policyName]; ok {
			log.Debug("import policy : ", pol)
			inPolicies = append(inPolicies, pol)
		}
	}
	loc.importPolicies = inPolicies
	loc.defaultImportPolicy = policyConf.ApplyPolicyConfig.DefaultImportPolicy

	// configure export policy
	outPolicies := make([]*policy.Policy, 0)
	for _, policyName := range policyConf.ApplyPolicyConfig.ExportPolicy {
		log.WithFields(log.Fields{
			"Topic":      "Peer",
			"Key":        peer.conf.NeighborConfig.NeighborAddress,
			"PolicyName": policyName,
		}).Info("export policy installed")
		if pol, ok := policyMap[policyName]; ok {
			log.Debug("export policy : ", pol)
			outPolicies = append(outPolicies, pol)
		}
	}
	loc.exportPolicies = outPolicies
	loc.defaultExportPolicy = policyConf.ApplyPolicyConfig.DefaultExportPolicy
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
func (loc *LocalRib) applyPolicies(d Direction, original *table.Path) (bool, *table.Path) {
	var policies []*policy.Policy
	switch d {
	case POLICY_DIRECTION_EXPORT:
		policies = loc.exportPolicies
	case POLICY_DIRECTION_IMPORT:
		policies = loc.importPolicies
	}
	return applyPolicy("Loc", loc.OwnerName(), d, policies, original)
}

func applyPolicy(component, owner string, d Direction, policies []*policy.Policy, original *table.Path) (bool, *table.Path) {
	var applied bool = true
	for _, pol := range policies {
		if result, action, newpath := pol.Apply(original); result {
			log.Debug("newpath: ", newpath)
			if action == policy.ROUTE_TYPE_REJECT {
				log.WithFields(log.Fields{
					"Topic": component,
					"Key":   owner,
					"NLRI":  original.GetNlri(),
					"Dir":   d,
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
		"Topic": component,
		"Key":   owner,
		"Len":   len(policies),
		"NLRI":  original,
		"Dir":   d,
	}).Debug("no policy applied")
	return !applied, original
}
