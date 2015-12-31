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
	tableId   string
	gConf     config.Global
	conf      config.Neighbor
	fsm       *FSM
	adjRibIn  *table.AdjRib
	adjRibOut *table.AdjRib
	outgoing  chan *bgp.BGPMessage
	recvOpen  *bgp.BGPMessage
	policy    *table.RoutingPolicy
	localRib  *table.TableManager
}

func NewPeer(g config.Global, conf config.Neighbor, loc *table.TableManager, policy *table.RoutingPolicy) *Peer {
	peer := &Peer{
		gConf:    g,
		conf:     conf,
		outgoing: make(chan *bgp.BGPMessage, 128),
		localRib: loc,
		policy:   policy,
	}
	tableId := table.GLOBAL_RIB_NAME
	if peer.isRouteServerClient() {
		tableId = conf.Config.NeighborAddress
	}
	peer.tableId = tableId
	conf.State.SessionState = uint32(bgp.BGP_FSM_IDLE)
	conf.Timers.State.Downtime = time.Now().Unix()
	rfs, _ := conf.AfiSafis.ToRfList()
	peer.adjRibIn = table.NewAdjRib(peer.ID(), rfs)
	peer.adjRibOut = table.NewAdjRib(peer.ID(), rfs)
	peer.fsm = NewFSM(&g, &conf, policy)
	return peer
}

func (peer *Peer) Fsm() *FSM {
	return peer.fsm
}

func (peer *Peer) Outgoing() chan *bgp.BGPMessage {
	return peer.outgoing
}

func (peer *Peer) ID() string {
	return peer.conf.Config.NeighborAddress
}

func (peer *Peer) TableID() string {
	return peer.tableId
}

func (peer *Peer) isIBGPPeer() bool {
	return peer.conf.Config.PeerAs == peer.gConf.Config.As
}

func (peer *Peer) isRouteServerClient() bool {
	return peer.conf.RouteServer.Config.RouteServerClient
}

func (peer *Peer) isRouteReflectorClient() bool {
	return peer.conf.RouteReflector.Config.RouteReflectorClient
}

func (peer *Peer) configuredRFlist() []bgp.RouteFamily {
	rfs, _ := peer.conf.AfiSafis.ToRfList()
	return rfs
}

func (peer *Peer) getAccepted(rfList []bgp.RouteFamily) []*table.Path {
	return peer.adjRibIn.PathList(rfList, true)
}

func (peer *Peer) getBestFromLocal(rfList []bgp.RouteFamily) ([]*table.Path, []*table.Path) {
	pathList := []*table.Path{}
	filtered := []*table.Path{}
	for _, path := range peer.localRib.GetBestPathList(peer.TableID(), rfList) {
		p := peer.policy.ApplyPolicy(peer.TableID(), table.POLICY_DIRECTION_EXPORT, filterpath(peer, path))
		if p == nil {
			filtered = append(filtered, path)
			continue
		}
		if !peer.isRouteServerClient() {
			p.UpdatePathAttrs(&peer.gConf, &peer.conf)
		}
		pathList = append(pathList, p)
	}
	return pathList, filtered
}

func (peer *Peer) handleBGPmessage(e *FsmMsg) ([]*table.Path, []*bgp.BGPMessage) {
	m := e.MsgData.(*bgp.BGPMessage)
	log.WithFields(log.Fields{
		"Topic": "Peer",
		"Key":   peer.conf.Config.NeighborAddress,
		"data":  m,
	}).Debug("received")

	switch m.Header.Type {
	case bgp.BGP_MSG_ROUTE_REFRESH:
		rr := m.Body.(*bgp.BGPRouteRefresh)
		rf := bgp.AfiSafiToRouteFamily(rr.AFI, rr.SAFI)
		if _, ok := peer.fsm.rfMap[rf]; !ok {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.conf.Config.NeighborAddress,
				"Data":  rf,
			}).Warn("Route family isn't supported")
			break
		}
		if _, ok := peer.fsm.capMap[bgp.BGP_CAP_ROUTE_REFRESH]; ok {
			rfList := []bgp.RouteFamily{rf}
			peer.adjRibOut.Drop(rfList)
			accepted, filtered := peer.getBestFromLocal(rfList)
			peer.adjRibOut.Update(accepted)
			for _, path := range filtered {
				path.IsWithdraw = true
				accepted = append(accepted, path)
			}
			return nil, table.CreateUpdateMsgFromPaths(accepted)
		} else {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.conf.Config.NeighborAddress,
			}).Warn("ROUTE_REFRESH received but the capability wasn't advertised")
		}

	case bgp.BGP_MSG_UPDATE:
		peer.conf.Timers.State.UpdateRecvTime = time.Now().Unix()
		if len(e.PathList) > 0 {
			peer.adjRibIn.Update(e.PathList)
			paths := make([]*table.Path, 0, len(e.PathList))
			for _, path := range e.PathList {
				if path.Filtered(peer.ID()) != table.POLICY_DIRECTION_IN {
					paths = append(paths, path)
				}
			}
			return paths, nil
		}
	case bgp.BGP_MSG_NOTIFICATION:
		body := m.Body.(*bgp.BGPNotification)
		log.WithFields(log.Fields{
			"Topic":   "Peer",
			"Key":     peer.conf.Config.NeighborAddress,
			"Code":    body.ErrorCode,
			"Subcode": body.ErrorSubcode,
			"Data":    body.Data,
		}).Warn("received notification")
	}
	return nil, nil
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
			"Key":   peer.conf.Config.NeighborAddress,
		}).Warn("accepted conn is closed to avoid be blocked")
	}
}

func (peer *Peer) MarshalJSON() ([]byte, error) {
	return json.Marshal(peer.ToApiStruct())
}

func (peer *Peer) ToApiStruct() *api.Peer {

	f := peer.fsm
	c := f.pConf

	remoteCap := make([][]byte, 0, len(peer.fsm.capMap))
	for _, c := range peer.fsm.capMap {
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
		NeighborAddress:  c.Config.NeighborAddress,
		Id:               peer.fsm.peerInfo.ID.To4().String(),
		PeerAs:           c.Config.PeerAs,
		LocalAs:          c.Config.LocalAs,
		PeerType:         uint32(c.Config.PeerType),
		AuthPassword:     c.Config.AuthPassword,
		RemovePrivateAs:  uint32(c.Config.RemovePrivateAs),
		RouteFlapDamping: c.Config.RouteFlapDamping,
		SendCommunity:    uint32(c.Config.SendCommunity),
		Description:      c.Config.Description,
		PeerGroup:        c.Config.PeerGroup,
		RemoteCap:        remoteCap,
		LocalCap:         localCap,
	}

	timer := &c.Timers
	s := &c.State

	advertized := uint32(0)
	received := uint32(0)
	accepted := uint32(0)
	if f.state == bgp.BGP_FSM_ESTABLISHED {
		rfList := peer.configuredRFlist()
		advertized = uint32(peer.adjRibOut.Count(rfList))
		received = uint32(peer.adjRibIn.Count(rfList))
		accepted = uint32(peer.adjRibIn.Accepted(rfList))
	}

	uptime := int64(0)
	if timer.State.Uptime != 0 {
		uptime = int64(time.Now().Sub(time.Unix(timer.State.Uptime, 0)).Seconds())
	}
	downtime := int64(0)
	if timer.State.Downtime != 0 {
		downtime = int64(time.Now().Sub(time.Unix(timer.State.Downtime, 0)).Seconds())
	}

	keepalive := uint32(0)
	if f.negotiatedHoldTime != 0 {
		if f.negotiatedHoldTime < timer.Config.HoldTime {
			keepalive = uint32(f.negotiatedHoldTime / 3)
		} else {
			keepalive = uint32(timer.Config.KeepaliveInterval)
		}
	}

	timerconf := &api.TimersConfig{
		ConnectRetry:                 uint64(timer.Config.ConnectRetry),
		HoldTime:                     uint64(timer.Config.HoldTime),
		KeepaliveInterval:            uint64(keepalive),
		MinimumAdvertisementInterval: uint64(timer.Config.MinimumAdvertisementInterval),
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

func (peer *Peer) DropAll(rfList []bgp.RouteFamily) {
	peer.adjRibIn.Drop(rfList)
	peer.adjRibOut.Drop(rfList)
}
