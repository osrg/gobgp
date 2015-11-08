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
	"github.com/osrg/gobgp/table"
	"net"
	"time"
)

const (
	FLOP_THRESHOLD    = time.Second * 30
	MIN_CONNECT_RETRY = 10
)

type Peer struct {
	gConf           config.Global
	conf            config.Neighbor
	fsm             *FSM
	rfMap           map[bgp.RouteFamily]bool
	capMap          map[bgp.BGPCapabilityCode][]bgp.ParameterCapabilityInterface
	adjRib          *table.AdjRib
	outgoing        chan *bgp.BGPMessage
	inPolicies      []*table.Policy
	defaultInPolicy table.RouteType
	accepted        uint32
	staleAccepted   bool
	recvOpen        *bgp.BGPMessage
	localRib        *table.TableManager
}

func NewPeer(g config.Global, conf config.Neighbor, loc *table.TableManager) *Peer {
	peer := &Peer{
		gConf:    g,
		conf:     conf,
		rfMap:    make(map[bgp.RouteFamily]bool),
		capMap:   make(map[bgp.BGPCapabilityCode][]bgp.ParameterCapabilityInterface),
		outgoing: make(chan *bgp.BGPMessage, 128),
		localRib: loc,
	}
	conf.NeighborState.SessionState = uint32(bgp.BGP_FSM_IDLE)
	conf.Timers.TimersState.Downtime = time.Now().Unix()
	peer.adjRib = table.NewAdjRib(peer.configuredRFlist())
	peer.fsm = NewFSM(&g, &conf, peer)
	return peer
}

func (peer *Peer) Fsm() *FSM {
	return peer.fsm
}

func (peer *Peer) Outgoing() chan *bgp.BGPMessage {
	return peer.outgoing
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
	return peer.localRib.GetRFlist()
}

func (peer *Peer) updateAccepted(accepted uint32) {
	peer.accepted = accepted
	peer.staleAccepted = false
}

func (peer *Peer) getAccepted(rfList []bgp.RouteFamily) []*table.Path {
	var pathList []*table.Path
	for _, path := range peer.adjRib.GetInPathList(rfList) {
		if path.Filtered == false {
			pathList = append(pathList, path)
		}
	}
	return pathList
}

func (peer *Peer) getBestFromLocal(rfList []bgp.RouteFamily) ([]*table.Path, []*table.Path) {
	pathList, filtered := peer.ApplyPolicy(table.POLICY_DIRECTION_EXPORT, filterpath(peer, peer.localRib.GetBestPathList(rfList)))
	if peer.isRouteServerClient() == false {
		for _, path := range pathList {
			path.UpdatePathAttrs(&peer.gConf, &peer.conf)
		}
	}
	return pathList, filtered
}

func open2Cap(open *bgp.BGPOpen, n *config.Neighbor) (map[bgp.BGPCapabilityCode][]bgp.ParameterCapabilityInterface, map[bgp.RouteFamily]bool) {
	capMap := make(map[bgp.BGPCapabilityCode][]bgp.ParameterCapabilityInterface)
	rfMap := config.CreateRfMap(n)
	r := make(map[bgp.RouteFamily]bool)
	for _, p := range open.OptParams {
		if paramCap, y := p.(*bgp.OptionParameterCapability); y {
			for _, c := range paramCap.Capability {
				m, ok := capMap[c.Code()]
				if !ok {
					m = make([]bgp.ParameterCapabilityInterface, 0, 1)
				}
				capMap[c.Code()] = append(m, c)

				if c.Code() == bgp.BGP_CAP_MULTIPROTOCOL {
					m := c.(*bgp.CapMultiProtocol)
					r[m.CapValue] = true
				}
			}
		}
	}

	for rf, _ := range rfMap {
		if _, y := r[rf]; !y {
			delete(rfMap, rf)
		}
	}
	return capMap, rfMap
}

func (peer *Peer) handleBGPmessage(e *FsmMsg) ([]*table.Path, bool, []*bgp.BGPMessage) {
	m := e.MsgData.(*bgp.BGPMessage)
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
		peer.capMap, peer.rfMap = open2Cap(body, &peer.conf)

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
			rfList := []bgp.RouteFamily{rf}
			peer.adjRib.DropOut(rfList)
			accepted, filtered := peer.getBestFromLocal(rfList)
			peer.adjRib.UpdateOut(accepted)
			pathList = append(pathList, accepted...)
			for _, path := range filtered {
				path.IsWithdraw = true
				pathList = append(pathList, path)
			}
		} else {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.conf.NeighborConfig.NeighborAddress,
			}).Warn("ROUTE_REFRESH received but the capability wasn't advertised")
		}

	case bgp.BGP_MSG_UPDATE:
		update = true
		peer.conf.Timers.TimersState.UpdateRecvTime = time.Now().Unix()
		if len(e.PathList) > 0 {
			pathList = e.PathList
			peer.staleAccepted = true
			peer.adjRib.UpdateIn(pathList)
		}
	case bgp.BGP_MSG_NOTIFICATION:
		body := m.Body.(*bgp.BGPNotification)
		log.WithFields(log.Fields{
			"Topic":   "Peer",
			"Key":     peer.conf.NeighborConfig.NeighborAddress,
			"Code":    body.ErrorCode,
			"Subcode": body.ErrorSubcode,
			"Data":    body.Data,
		}).Warn("received notification")
	}
	return pathList, update, bgpMsgList
}

func (peer *Peer) startFSMHandler(incoming chan *FsmMsg) {
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
		NeighborAddress:  c.NeighborConfig.NeighborAddress.String(),
		Id:               peer.fsm.peerInfo.ID.To4().String(),
		PeerAs:           c.NeighborConfig.PeerAs,
		LocalAs:          c.NeighborConfig.LocalAs,
		PeerType:         uint32(c.NeighborConfig.PeerType),
		AuthPassword:     c.NeighborConfig.AuthPassword,
		RemovePrivateAs:  uint32(c.NeighborConfig.RemovePrivateAs),
		RouteFlapDamping: c.NeighborConfig.RouteFlapDamping,
		SendCommunity:    uint32(c.NeighborConfig.SendCommunity),
		Description:      c.NeighborConfig.Description,
		PeerGroup:        c.NeighborConfig.PeerGroup,
		RemoteCap:        remoteCap,
		LocalCap:         localCap,
	}

	timer := &c.Timers
	s := &c.NeighborState

	advertized := uint32(0)
	received := uint32(0)
	accepted := uint32(0)
	if f.state == bgp.BGP_FSM_ESTABLISHED {
		rfList := peer.configuredRFlist()
		advertized = uint32(peer.adjRib.GetOutCount(rfList))
		received = uint32(peer.adjRib.GetInCount(rfList))
		if peer.staleAccepted {
			accepted = uint32(len(peer.getAccepted(rfList)))
			peer.updateAccepted(accepted)
		} else {
			accepted = peer.accepted
		}
	}

	uptime := int64(0)
	if timer.TimersState.Uptime != 0 {
		uptime = int64(time.Now().Sub(time.Unix(timer.TimersState.Uptime, 0)).Seconds())
	}
	downtime := int64(0)
	if timer.TimersState.Downtime != 0 {
		downtime = int64(time.Now().Sub(time.Unix(timer.TimersState.Downtime, 0)).Seconds())
	}

	keepalive := uint32(0)
	if f.negotiatedHoldTime != 0 {
		if f.negotiatedHoldTime < timer.TimersConfig.HoldTime {
			keepalive = uint32(f.negotiatedHoldTime / 3)
		} else {
			keepalive = uint32(timer.TimersConfig.KeepaliveInterval)
		}
	}

	timerconf := &api.TimersConfig{
		ConnectRetry:                 uint64(timer.TimersConfig.ConnectRetry),
		HoldTime:                     uint64(timer.TimersConfig.HoldTime),
		KeepaliveInterval:            uint64(keepalive),
		MinimumAdvertisementInterval: uint64(timer.TimersConfig.MinimumAdvertisementInterval),
	}

	timerstate := &api.TimersState{
		Uptime:   uint64(uptime),
		Downtime: uint64(downtime),
	}

	apitimer := &api.Timers{
		Config: timerconf,
		State:  timerstate,
	}
	msgrcv := &api.Message{
		NOTIFICATION: s.Messages.Received.Notification,
		UPDATE:       s.Messages.Received.Update,
		OPEN:         s.Messages.Received.Open,
		KEEPALIVE:    s.Messages.Received.Keepalive,
		REFRESH:      s.Messages.Received.Refresh,
		DISCARDED:    s.Messages.Received.Discarded,
		TOTAL:        s.Messages.Received.Total,
	}
	msgsnt := &api.Message{
		NOTIFICATION: s.Messages.Sent.Notification,
		UPDATE:       s.Messages.Sent.Update,
		OPEN:         s.Messages.Sent.Open,
		KEEPALIVE:    s.Messages.Sent.Keepalive,
		REFRESH:      s.Messages.Sent.Refresh,
		DISCARDED:    s.Messages.Sent.Discarded,
		TOTAL:        s.Messages.Sent.Total,
	}
	msg := &api.Messages{
		Received: msgrcv,
		Sent:     msgsnt,
	}
	info := &api.PeerState{
		BgpState:   f.state.String(),
		AdminState: f.adminState.String(),
		Messages:   msg,
		Received:   received,
		Accepted:   accepted,
		Advertized: advertized,
	}

	return &api.Peer{
		Conf:   conf,
		Info:   info,
		Timers: apitimer,
	}
}

func (peer *Peer) GetPolicy(d table.PolicyDirection) []*table.Policy {
	switch d {
	case table.POLICY_DIRECTION_IN:
		return peer.inPolicies
	default:
		return peer.localRib.GetPolicy(d)
	}
	return nil
}

func (peer *Peer) SetPolicy(d table.PolicyDirection, policies []*table.Policy) error {
	switch d {
	case table.POLICY_DIRECTION_IN:
		peer.inPolicies = policies
	default:
		return peer.localRib.SetPolicy(d, policies)
	}
	return nil
}

func (peer *Peer) GetDefaultPolicy(d table.PolicyDirection) table.RouteType {
	switch d {
	case table.POLICY_DIRECTION_IN:
		return peer.defaultInPolicy
	default:
		return peer.localRib.GetDefaultPolicy(d)
	}
	return table.ROUTE_TYPE_NONE
}

func (peer *Peer) SetDefaultPolicy(d table.PolicyDirection, typ table.RouteType) error {
	switch d {
	case table.POLICY_DIRECTION_IN:
		peer.defaultInPolicy = typ
	default:
		if peer.isRouteServerClient() {
			return peer.localRib.SetDefaultPolicy(d, typ)
		}
	}
	return nil
}

func (peer *Peer) ApplyPolicy(d table.PolicyDirection, paths []*table.Path) ([]*table.Path, []*table.Path) {
	newpaths := make([]*table.Path, 0, len(paths))
	filteredPaths := make([]*table.Path, 0)
	for _, path := range paths {
		result := table.ROUTE_TYPE_NONE
		newpath := path
		for _, p := range peer.GetPolicy(d) {
			result, newpath = p.Apply(path)
			if result != table.ROUTE_TYPE_NONE {
				break
			}
		}

		if result == table.ROUTE_TYPE_NONE {
			result = peer.GetDefaultPolicy(d)
		}

		switch result {
		case table.ROUTE_TYPE_ACCEPT:
			if d == table.POLICY_DIRECTION_IN {
				path.Filtered = false
			}
			newpaths = append(newpaths, newpath)
		case table.ROUTE_TYPE_REJECT:
			if d == table.POLICY_DIRECTION_IN {
				path.Filtered = true
			}
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

func (peer *Peer) DropAll(rfList []bgp.RouteFamily) {
	peer.adjRib.DropIn(rfList)
	peer.adjRib.DropOut(rfList)
	peer.staleAccepted = false
	peer.accepted = 0
}
