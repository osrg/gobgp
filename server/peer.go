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
	api "github.com/osrg/gobgp/api"
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
	gConf                 config.Global
	conf                  config.Neighbor
	fsm                   *FSM
	rfMap                 map[bgp.RouteFamily]bool
	capMap                map[bgp.BGPCapabilityCode][]bgp.ParameterCapabilityInterface
	adjRib                *table.AdjRib
	peerInfo              *table.PeerInfo
	outgoing              chan *bgp.BGPMessage
	inPolicies            []*policy.Policy
	defaultInPolicy       config.DefaultPolicyType
	accepted              uint32
	importPolicies        []*policy.Policy
	defaultImportPolicy   config.DefaultPolicyType
	exportPolicies        []*policy.Policy
	defaultExportPolicy   config.DefaultPolicyType
	isConfederationMember bool
	recvOpen              *bgp.BGPMessage
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
	id := net.ParseIP(string(conf.RouteReflector.RouteReflectorConfig.RouteReflectorClusterId)).To4()
	peer.peerInfo = &table.PeerInfo{
		AS:                      conf.NeighborConfig.PeerAs,
		LocalAS:                 g.GlobalConfig.As,
		LocalID:                 g.GlobalConfig.RouterId,
		Address:                 conf.NeighborConfig.NeighborAddress,
		RouteReflectorClient:    peer.isRouteReflectorClient(),
		RouteReflectorClusterID: id,
	}
	peer.adjRib = table.NewAdjRib(peer.configuredRFlist())
	peer.fsm = NewFSM(&g, &conf)

	if conf.NeighborConfig.PeerAs != g.GlobalConfig.As {
		for _, member := range g.Confederation.ConfederationConfig.MemberAs {
			if member == conf.NeighborConfig.PeerAs {
				peer.isConfederationMember = true
				break
			}
		}
	}

	return peer
}

func (peer *Peer) isEBGPPeer() bool {
	return peer.conf.NeighborConfig.PeerAs != peer.gConf.GlobalConfig.As
}

func (peer *Peer) isIBGPPeer() bool {
	return peer.conf.NeighborConfig.PeerAs == peer.gConf.GlobalConfig.As
}

func (peer *Peer) isRouteServerClient() bool {
	return peer.conf.RouteServer.RouteServerConfig.RouteServerClient
}

func (peer *Peer) isRouteReflectorClient() bool {
	return peer.conf.RouteReflector.RouteReflectorConfig.RouteReflectorClient
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
		peer.recvOpen = m
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
						r[m.CapValue] = true
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
		confedCheckRequired := !peer.isConfederationMember && peer.isEBGPPeer()
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

func (peer *Peer) getBests(rib *table.TableManager) []*table.Path {
	pathList := []*table.Path{}
	for _, rf := range peer.configuredRFlist() {
		for _, paths := range rib.GetBestPathList(rf) {
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

	remoteCap := make([][]byte, 0, len(peer.capMap))
	for _, c := range peer.capMap {
		for _, m := range c {
			buf, _ := m.Serialize()
			remoteCap = append(remoteCap, buf)
		}
	}

	caps := capabilitiesFromConfig(&peer.gConf, &peer.conf)
	localCap := make([][]byte, 0, len(caps))
	for _, c := range caps {
		buf, _ := c.Serialize()
		localCap = append(localCap, buf)
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
	if f.state == bgp.BGP_FSM_ESTABLISHED {
		for _, rf := range peer.configuredRFlist() {
			advertized += uint32(peer.adjRib.GetOutCount(rf))
			received += uint32(peer.adjRib.GetInCount(rf))
			// FIXME: we should store 'accepted' in memory
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
		Accepted:                  peer.accepted,
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

func (peer *Peer) setPolicy(policyMap map[string]*policy.Policy) {
	// configure in-policy
	policyConf := peer.conf.ApplyPolicy
	inPolicies := make([]*policy.Policy, 0)
	for _, policyName := range policyConf.ApplyPolicyConfig.InPolicy {
		log.WithFields(log.Fields{
			"Topic":      "Peer",
			"Key":        peer.conf.NeighborConfig.NeighborAddress,
			"PolicyName": policyName,
		}).Info("in-policy installed")
		if pol, ok := policyMap[policyName]; ok {
			log.Debug("in policy : ", pol)
			inPolicies = append(inPolicies, pol)
		}
	}
	peer.inPolicies = inPolicies
	peer.defaultInPolicy = policyConf.ApplyPolicyConfig.DefaultInPolicy

	importPolicies := make([]*policy.Policy, 0)
	for _, policyName := range policyConf.ApplyPolicyConfig.ImportPolicy {
		log.WithFields(log.Fields{
			"Topic":      "Peer",
			"Key":        peer.conf.NeighborConfig.NeighborAddress,
			"PolicyName": policyName,
		}).Info("import policy installed")
		if pol, ok := policyMap[policyName]; ok {
			log.Debug("import policy : ", pol)
			importPolicies = append(importPolicies, pol)
		}
	}
	peer.importPolicies = importPolicies
	peer.defaultImportPolicy = policyConf.ApplyPolicyConfig.DefaultImportPolicy

	// configure export policy
	exportPolicies := make([]*policy.Policy, 0)
	for _, policyName := range policyConf.ApplyPolicyConfig.ExportPolicy {
		log.WithFields(log.Fields{
			"Topic":      "Peer",
			"Key":        peer.conf.NeighborConfig.NeighborAddress,
			"PolicyName": policyName,
		}).Info("export policy installed")
		if pol, ok := policyMap[policyName]; ok {
			log.Debug("export policy : ", pol)
			exportPolicies = append(exportPolicies, pol)
		}
	}
	peer.exportPolicies = exportPolicies
	peer.defaultExportPolicy = policyConf.ApplyPolicyConfig.DefaultExportPolicy
}

func (peer *Peer) GetPolicy(d PolicyDirection) []*policy.Policy {
	switch d {
	case POLICY_DIRECTION_IN:
		return peer.inPolicies
	case POLICY_DIRECTION_IMPORT:
		return peer.importPolicies
	case POLICY_DIRECTION_EXPORT:
		return peer.exportPolicies
	}
	return nil
}

func (peer *Peer) GetDefaultPolicy(d PolicyDirection) policy.RouteType {
	var def config.DefaultPolicyType
	switch d {
	case POLICY_DIRECTION_IN:
		def = peer.defaultInPolicy
	case POLICY_DIRECTION_IMPORT:
		def = peer.defaultImportPolicy
	case POLICY_DIRECTION_EXPORT:
		def = peer.defaultExportPolicy
	}

	if def == config.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE {
		return policy.ROUTE_TYPE_ACCEPT
	}
	return policy.ROUTE_TYPE_REJECT
}

func (peer *Peer) ApplyPolicy(d PolicyDirection, paths []*table.Path) ([]*table.Path, []*table.Path) {
	newpaths := make([]*table.Path, 0, len(paths))
	filteredPaths := make([]*table.Path, 0)
	for _, path := range paths {
		result := policy.ROUTE_TYPE_NONE
		newpath := path
		for _, p := range peer.GetPolicy(d) {
			result, newpath = p.Apply(path)
			if result != policy.ROUTE_TYPE_NONE {
				break
			}
		}

		if result == policy.ROUTE_TYPE_NONE {
			result = peer.GetDefaultPolicy(d)
		}

		switch result {
		case policy.ROUTE_TYPE_ACCEPT:
			newpaths = append(newpaths, newpath)
			if d == POLICY_DIRECTION_IN {
				peer.accepted += 1
			}
		case policy.ROUTE_TYPE_REJECT:
			path.Filtered = true
			filteredPaths = append(filteredPaths, path)
			log.WithFields(log.Fields{
				"Topic":     "Peer",
				"Key":       peer.conf.NeighborConfig.NeighborAddress,
				"Path":      path,
				"Direction": d,
			}).Debug("reject")
		}
	}
	return newpaths, filteredPaths
}

func (peer *Peer) DropAll(rf bgp.RouteFamily) {
	peer.adjRib.DropAll(rf)
	peer.accepted = 0
}
