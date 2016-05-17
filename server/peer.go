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
	"github.com/eapache/channels"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/osrg/gobgp/table"
	"net"
	"time"
)

const (
	FLOP_THRESHOLD    = time.Second * 30
	MIN_CONNECT_RETRY = 10
)

type Peer struct {
	tableId           string
	fsm               *FSM
	adjRibIn          *table.AdjRib
	adjRibOut         *table.AdjRib
	outgoing          chan *FsmOutgoingMsg
	policy            *table.RoutingPolicy
	localRib          *table.TableManager
	prefixLimitWarned map[bgp.RouteFamily]bool
}

func NewPeer(g *config.Global, conf *config.Neighbor, loc *table.TableManager, policy *table.RoutingPolicy) *Peer {
	peer := &Peer{
		outgoing:          make(chan *FsmOutgoingMsg, 128),
		localRib:          loc,
		policy:            policy,
		fsm:               NewFSM(g, conf, policy),
		prefixLimitWarned: make(map[bgp.RouteFamily]bool),
	}
	if peer.isRouteServerClient() {
		peer.tableId = conf.Config.NeighborAddress
	} else {
		peer.tableId = table.GLOBAL_RIB_NAME
	}
	rfs, _ := config.AfiSafis(conf.AfiSafis).ToRfList()
	peer.adjRibIn = table.NewAdjRib(peer.ID(), rfs)
	peer.adjRibOut = table.NewAdjRib(peer.ID(), rfs)
	return peer
}

func (peer *Peer) ID() string {
	return peer.fsm.pConf.Config.NeighborAddress
}

func (peer *Peer) TableID() string {
	return peer.tableId
}

func (peer *Peer) isIBGPPeer() bool {
	return peer.fsm.pConf.Config.PeerAs == peer.fsm.gConf.Config.As
}

func (peer *Peer) isRouteServerClient() bool {
	return peer.fsm.pConf.RouteServer.Config.RouteServerClient
}

func (peer *Peer) isRouteReflectorClient() bool {
	return peer.fsm.pConf.RouteReflector.Config.RouteReflectorClient
}

func (peer *Peer) isGracefulRestartEnabled() bool {
	return peer.fsm.pConf.GracefulRestart.State.Enabled
}

func (peer *Peer) recvedAllEOR() bool {
	for _, a := range peer.fsm.pConf.AfiSafis {
		if s := a.MpGracefulRestart.State; s.Enabled && !s.EndOfRibReceived {
			return false
		}
	}
	return true
}

func (peer *Peer) configuredRFlist() []bgp.RouteFamily {
	rfs, _ := config.AfiSafis(peer.fsm.pConf.AfiSafis).ToRfList()
	return rfs
}

func (peer *Peer) forwardingPreservedFamilies() ([]bgp.RouteFamily, []bgp.RouteFamily) {
	list := []bgp.RouteFamily{}
	for _, a := range peer.fsm.pConf.AfiSafis {
		if s := a.MpGracefulRestart.State; s.Enabled && s.Received {
			f, _ := bgp.GetRouteFamily(string(a.Config.AfiSafiName))
			list = append(list, f)
		}
	}
	preserved := []bgp.RouteFamily{}
	notPreserved := []bgp.RouteFamily{}
	for _, f := range peer.configuredRFlist() {
		p := true
		for _, g := range list {
			if f == g {
				p = false
				preserved = append(preserved, f)
			}
		}
		if p {
			notPreserved = append(notPreserved, f)
		}
	}
	return preserved, notPreserved
}

func (peer *Peer) getAccepted(rfList []bgp.RouteFamily) []*table.Path {
	return peer.adjRibIn.PathList(rfList, true)
}

func (peer *Peer) filterpath(path *table.Path) *table.Path {
	// special handling for RTC nlri
	// see comments in (*Destination).Calculate()
	if path != nil && path.GetRouteFamily() == bgp.RF_RTC_UC && !path.IsWithdraw {
		// if we already sent the same nlri, ignore this
		if peer.adjRibOut.Exists(path) {
			return nil
		}
		dst := peer.localRib.GetDestination(path)
		path = nil
		// we send a path even if it is not a best path
		for _, p := range dst.GetKnownPathList(peer.TableID()) {
			// just take care not to send back it
			if peer.ID() != p.GetSource().Address.String() {
				path = p
				break
			}
		}
	}
	if filterpath(peer, path) == nil {
		return nil
	}
	if !peer.isRouteServerClient() {
		path = path.Clone(path.IsWithdraw)
		path.UpdatePathAttrs(peer.fsm.gConf, peer.fsm.pConf)
	}
	options := &table.PolicyOptions{
		Info: peer.fsm.peerInfo,
	}
	path = peer.policy.ApplyPolicy(peer.TableID(), table.POLICY_DIRECTION_EXPORT, path, options)

	// remove local-pref attribute
	// we should do this after applying export policy since policy may
	// set local-preference
	if path != nil && peer.fsm.pConf.Config.PeerType == config.PEER_TYPE_EXTERNAL {
		path.RemoveLocalPref()
	}
	return path
}

func (peer *Peer) getBestFromLocal(rfList []bgp.RouteFamily) ([]*table.Path, []*table.Path) {
	pathList := []*table.Path{}
	filtered := []*table.Path{}
	for _, path := range peer.localRib.GetBestPathList(peer.TableID(), rfList) {
		if p := peer.filterpath(path); p != nil {
			pathList = append(pathList, p)
		} else {
			filtered = append(filtered, path)
		}

	}
	if peer.isGracefulRestartEnabled() {
		for _, family := range rfList {
			pathList = append(pathList, table.NewEOR(family))
		}
	}
	return pathList, filtered
}

func (peer *Peer) processOutgoingPaths(paths, withdrawals []*table.Path) []*table.Path {
	if peer.fsm.state != bgp.BGP_FSM_ESTABLISHED {
		return nil
	}
	if peer.fsm.pConf.GracefulRestart.State.LocalRestarting {
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   peer.fsm.pConf.Config.NeighborAddress,
		}).Debug("now syncing, suppress sending updates")
		return nil
	}

	outgoing := make([]*table.Path, 0, len(paths))
	// Note: multiple paths having the same prefix could exist the
	// withdrawals list in the case of Route Server setup with
	// import policies modifying paths. In such case, gobgp sends
	// duplicated update messages; withdraw messages for the same
	// prefix.
	// However, currently we don't support local path for Route
	// Server setup so this is NOT the case.
	for _, path := range withdrawals {
		if path.IsLocal() {
			if _, ok := peer.fsm.rfMap[path.GetRouteFamily()]; ok {
				outgoing = append(outgoing, path)
			}
		}
	}

	for _, path := range paths {
		if p := peer.filterpath(path); p != nil {
			outgoing = append(outgoing, p)
		}
	}

	peer.adjRibOut.Update(outgoing)
	return outgoing
}

func (peer *Peer) handleRouteRefresh(e *FsmMsg) []*table.Path {
	m := e.MsgData.(*bgp.BGPMessage)
	rr := m.Body.(*bgp.BGPRouteRefresh)
	rf := bgp.AfiSafiToRouteFamily(rr.AFI, rr.SAFI)
	if _, ok := peer.fsm.rfMap[rf]; !ok {
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   peer.ID(),
			"Data":  rf,
		}).Warn("Route family isn't supported")
		return nil
	}
	if _, ok := peer.fsm.capMap[bgp.BGP_CAP_ROUTE_REFRESH]; !ok {
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   peer.ID(),
		}).Warn("ROUTE_REFRESH received but the capability wasn't advertised")
		return nil
	}
	rfList := []bgp.RouteFamily{rf}
	peer.adjRibOut.Drop(rfList)
	accepted, filtered := peer.getBestFromLocal(rfList)
	peer.adjRibOut.Update(accepted)
	for _, path := range filtered {
		path.IsWithdraw = true
		accepted = append(accepted, path)
	}
	return accepted
}

func (peer *Peer) doPrefixLimit(k bgp.RouteFamily, c *config.PrefixLimitConfig) *bgp.BGPMessage {
	if maxPrefixes := int(c.MaxPrefixes); maxPrefixes > 0 {
		count := peer.adjRibIn.Count([]bgp.RouteFamily{k})
		pct := int(c.ShutdownThresholdPct)
		if pct > 0 && !peer.prefixLimitWarned[k] && count > (maxPrefixes*pct/100) {
			peer.prefixLimitWarned[k] = true
			log.WithFields(log.Fields{
				"Topic":         "Peer",
				"Key":           peer.ID(),
				"AddressFamily": k.String(),
			}).Warnf("prefix limit %d%% reached", pct)
		}
		if count > maxPrefixes {
			log.WithFields(log.Fields{
				"Topic":         "Peer",
				"Key":           peer.ID(),
				"AddressFamily": k.String(),
			}).Warnf("prefix limit reached")
			return bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_MAXIMUM_NUMBER_OF_PREFIXES_REACHED, nil)
		}
	}
	return nil

}

func (peer *Peer) updatePrefixLimitConfig(c []config.AfiSafi) ([]*SenderMsg, error) {
	x := peer.fsm.pConf.AfiSafis
	y := c
	if len(x) != len(y) {
		return nil, fmt.Errorf("changing supported afi-safi is not allowed")
	}
	m := make(map[bgp.RouteFamily]config.PrefixLimitConfig)
	for _, e := range x {
		k, err := bgp.GetRouteFamily(string(e.Config.AfiSafiName))
		if err != nil {
			return nil, err
		}
		m[k] = e.PrefixLimit.Config
	}
	msgs := make([]*SenderMsg, 0, len(y))
	for _, e := range y {
		k, err := bgp.GetRouteFamily(string(e.Config.AfiSafiName))
		if err != nil {
			return nil, err
		}
		if p, ok := m[k]; !ok {
			return nil, fmt.Errorf("changing supported afi-safi is not allowed")
		} else if !p.Equal(&e.PrefixLimit.Config) {
			log.WithFields(log.Fields{
				"Topic":                   "Peer",
				"Key":                     peer.ID(),
				"AddressFamily":           e.Config.AfiSafiName,
				"OldMaxPrefixes":          p.MaxPrefixes,
				"NewMaxPrefixes":          e.PrefixLimit.Config.MaxPrefixes,
				"OldShutdownThresholdPct": p.ShutdownThresholdPct,
				"NewShutdownThresholdPct": e.PrefixLimit.Config.ShutdownThresholdPct,
			}).Warnf("update prefix limit configuration")
			peer.prefixLimitWarned[k] = false
			if msg := peer.doPrefixLimit(k, &e.PrefixLimit.Config); msg != nil {
				msgs = append(msgs, newSenderMsg(peer, nil, msg, true))
			}
		}
	}
	peer.fsm.pConf.AfiSafis = c
	return msgs, nil
}

func (peer *Peer) handleUpdate(e *FsmMsg) ([]*table.Path, []bgp.RouteFamily, *bgp.BGPMessage) {
	m := e.MsgData.(*bgp.BGPMessage)
	update := m.Body.(*bgp.BGPUpdate)
	log.WithFields(log.Fields{
		"Topic":       "Peer",
		"Key":         peer.fsm.pConf.Config.NeighborAddress,
		"nlri":        update.NLRI,
		"withdrawals": update.WithdrawnRoutes,
		"attributes":  update.PathAttributes,
	}).Debug("received update")
	peer.fsm.pConf.Timers.State.UpdateRecvTime = time.Now().Unix()
	if len(e.PathList) > 0 {
		peer.adjRibIn.Update(e.PathList)
		for _, family := range peer.fsm.pConf.AfiSafis {
			k, _ := bgp.GetRouteFamily(string(family.Config.AfiSafiName))
			if msg := peer.doPrefixLimit(k, &family.PrefixLimit.Config); msg != nil {
				return nil, nil, msg
			}
		}
		paths := make([]*table.Path, 0, len(e.PathList))
		eor := []bgp.RouteFamily{}
		for _, path := range e.PathList {
			if path.IsEOR() {
				family := path.GetRouteFamily()
				log.WithFields(log.Fields{
					"Topic":         "Peer",
					"Key":           peer.ID(),
					"AddressFamily": family,
				}).Debug("EOR received")
				eor = append(eor, family)
				continue
			}
			if path.Filtered(peer.ID()) != table.POLICY_DIRECTION_IN {
				paths = append(paths, path)
			}
		}
		return paths, eor, nil
	}
	return nil, nil, nil
}

func (peer *Peer) startFSMHandler(incoming *channels.InfiniteChannel, stateCh chan *FsmMsg) {
	peer.fsm.h = NewFSMHandler(peer.fsm, incoming, stateCh, peer.outgoing)
}

func (peer *Peer) StaleAll(rfList []bgp.RouteFamily) {
	peer.adjRibIn.StaleAll(rfList)
}

func (peer *Peer) PassConn(conn *net.TCPConn) {
	select {
	case peer.fsm.connCh <- conn:
	default:
		conn.Close()
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   peer.ID(),
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

	caps := capabilitiesFromConfig(peer.fsm.pConf)
	localCap := make([][]byte, 0, len(caps))
	for _, c := range caps {
		buf, _ := c.Serialize()
		localCap = append(localCap, buf)
	}

	prefixLimits := make([]*api.PrefixLimit, 0, len(peer.fsm.pConf.AfiSafis))
	for _, family := range peer.fsm.pConf.AfiSafis {
		if c := family.PrefixLimit.Config; c.MaxPrefixes > 0 {
			k, _ := bgp.GetRouteFamily(string(family.Config.AfiSafiName))
			prefixLimits = append(prefixLimits, &api.PrefixLimit{
				Family:               uint32(k),
				MaxPrefixes:          c.MaxPrefixes,
				ShutdownThresholdPct: uint32(c.ShutdownThresholdPct),
			})
		}
	}

	conf := &api.PeerConf{
		NeighborAddress:  c.Config.NeighborAddress,
		Id:               peer.fsm.peerInfo.ID.To4().String(),
		PeerAs:           c.Config.PeerAs,
		LocalAs:          c.Config.LocalAs,
		PeerType:         uint32(c.Config.PeerType.ToInt()),
		AuthPassword:     c.Config.AuthPassword,
		RemovePrivateAs:  uint32(c.Config.RemovePrivateAs.ToInt()),
		RouteFlapDamping: c.Config.RouteFlapDamping,
		SendCommunity:    uint32(c.Config.SendCommunity.ToInt()),
		Description:      c.Config.Description,
		PeerGroup:        c.Config.PeerGroup,
		RemoteCap:        remoteCap,
		LocalCap:         localCap,
		PrefixLimits:     prefixLimits,
	}

	timer := c.Timers
	s := c.State

	advertised := uint32(0)
	received := uint32(0)
	accepted := uint32(0)
	if f.state == bgp.BGP_FSM_ESTABLISHED {
		rfList := peer.configuredRFlist()
		advertised = uint32(peer.adjRibOut.Count(rfList))
		received = uint32(peer.adjRibIn.Count(rfList))
		accepted = uint32(peer.adjRibIn.Accepted(rfList))
	}

	uptime := int64(0)
	if timer.State.Uptime != 0 {
		uptime = timer.State.Uptime
	}
	downtime := int64(0)
	if timer.State.Downtime != 0 {
		downtime = timer.State.Downtime
	}

	timerconf := &api.TimersConfig{
		ConnectRetry:      uint64(timer.Config.ConnectRetry),
		HoldTime:          uint64(timer.Config.HoldTime),
		KeepaliveInterval: uint64(timer.Config.KeepaliveInterval),
	}

	timerstate := &api.TimersState{
		KeepaliveInterval:  uint64(timer.State.KeepaliveInterval),
		NegotiatedHoldTime: uint64(timer.State.NegotiatedHoldTime),
		Uptime:             uint64(uptime),
		Downtime:           uint64(downtime),
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
		Advertised: advertised,
	}
	rr := &api.RouteReflector{
		RouteReflectorClient:    peer.fsm.pConf.RouteReflector.Config.RouteReflectorClient,
		RouteReflectorClusterId: string(peer.fsm.pConf.RouteReflector.Config.RouteReflectorClusterId),
	}
	rs := &api.RouteServer{
		RouteServerClient: peer.fsm.pConf.RouteServer.Config.RouteServerClient,
	}

	return &api.Peer{
		Conf:           conf,
		Info:           info,
		Timers:         apitimer,
		RouteReflector: rr,
		RouteServer:    rs,
	}
}

func (peer *Peer) DropAll(rfList []bgp.RouteFamily) {
	peer.adjRibIn.Drop(rfList)
	peer.adjRibOut.Drop(rfList)
}
