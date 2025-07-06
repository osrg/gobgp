// Copyright (C) 2014-2021 Nippon Telegraph and Telephone Corporation.
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

package peering

import (
	"fmt"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/bgputils"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/utils"
)

const (
	FlopThreshold = time.Second * 30
)

type PeerGroup struct {
	Conf             *oc.PeerGroup
	Members          map[string]oc.Neighbor
	DynamicNeighbors map[string]*oc.DynamicNeighbor
}

func NewPeerGroup(c *oc.PeerGroup) *PeerGroup {
	return &PeerGroup{
		Conf:             c,
		Members:          make(map[string]oc.Neighbor),
		DynamicNeighbors: make(map[string]*oc.DynamicNeighbor),
	}
}

func (pg *PeerGroup) AddMember(c oc.Neighbor) {
	pg.Members[c.State.NeighborAddress] = c
}

func (pg *PeerGroup) DeleteMember(c oc.Neighbor) {
	delete(pg.Members, c.State.NeighborAddress)
}

func (pg *PeerGroup) AddDynamicNeighbor(c *oc.DynamicNeighbor) {
	pg.DynamicNeighbors[c.Config.Prefix] = c
}

func (pg *PeerGroup) DeleteDynamicNeighbor(prefix string) {
	delete(pg.DynamicNeighbors, prefix)
}

func NewDynamicPeer(g *oc.Global, neighborAddress string, pg *oc.PeerGroup, loc *table.TableManager, policy *table.RoutingPolicy, logger log.Logger) *Peer {
	conf := oc.Neighbor{
		Config: oc.NeighborConfig{
			PeerGroup: pg.Config.PeerGroupName,
		},
		State: oc.NeighborState{
			NeighborAddress: neighborAddress,
		},
		Transport: oc.Transport{
			Config: oc.TransportConfig{
				PassiveMode: true,
			},
		},
	}
	if err := oc.OverwriteNeighborConfigWithPeerGroup(&conf, pg); err != nil {
		logger.Debug("Can't overwrite neighbor config",
			log.Fields{
				"Topic": "Peer",
				"Key":   neighborAddress,
				"Error": err,
			})
		return nil
	}
	if err := oc.SetDefaultNeighborConfigValues(&conf, pg, g); err != nil {
		logger.Debug("Can't set default config",
			log.Fields{
				"Topic": "Peer",
				"Key":   neighborAddress,
				"Error": err,
			})
		return nil
	}
	peer := NewPeer(g, &conf, loc, policy, logger)
	peer.FSM.Lock.Lock()
	peer.FSM.State = bgp.BGP_FSM_ACTIVE
	peer.FSM.Lock.Unlock()
	return peer
}

type Peer struct {
	TableId           string
	FSM               *fsm
	AdjRibIn          *table.AdjRib
	Policy            *table.RoutingPolicy
	LocalRib          *table.TableManager
	PrefixLimitWarned map[bgp.Family]bool
	// map of path local identifiers sent for that prefix
	SentPaths           map[table.PathDestLocalKey]map[uint32]struct{}
	SendMaxPathFiltered map[table.PathLocalKey]struct{}
	LLGREndChs          []chan struct{}
}

func NewPeer(g *oc.Global, conf *oc.Neighbor, loc *table.TableManager, policy *table.RoutingPolicy, logger log.Logger) *Peer {
	peer := &Peer{
		LocalRib:            loc,
		Policy:              policy,
		FSM:                 newFSM(g, conf, logger),
		PrefixLimitWarned:   make(map[bgp.Family]bool),
		SentPaths:           make(map[table.PathDestLocalKey]map[uint32]struct{}),
		SendMaxPathFiltered: make(map[table.PathLocalKey]struct{}),
	}
	if peer.IsRouteServerClient() {
		peer.TableId = conf.State.NeighborAddress
	} else {
		peer.TableId = table.GLOBAL_RIB_NAME
	}
	rfs, _ := oc.AfiSafis(conf.AfiSafis).ToRfList()
	peer.AdjRibIn = table.NewAdjRib(peer.FSM.Logger, rfs)
	return peer
}

func (peer *Peer) AS() uint32 {
	peer.FSM.Lock.RLock()
	defer peer.FSM.Lock.RUnlock()
	return peer.FSM.PeerConf.State.PeerAs
}

func (peer *Peer) ID() string {
	peer.FSM.Lock.RLock()
	defer peer.FSM.Lock.RUnlock()
	return peer.FSM.PeerConf.State.NeighborAddress
}

func (peer *Peer) routerID() net.IP {
	peer.FSM.Lock.RLock()
	defer peer.FSM.Lock.RUnlock()
	return peer.FSM.PeerInfo.ID
}

func (peer *Peer) RouterID() string {
	if id := peer.routerID(); id != nil {
		return id.String()
	}
	return ""
}

func (peer *Peer) TableID() string {
	return peer.TableId
}

func (peer *Peer) AllowAsPathLoopLocal() bool {
	peer.FSM.Lock.RLock()
	defer peer.FSM.Lock.RUnlock()
	return peer.FSM.PeerConf.AsPathOptions.Config.AllowAsPathLoopLocal
}

func (peer *Peer) IsIBGPPeer() bool {
	peer.FSM.Lock.RLock()
	defer peer.FSM.Lock.RUnlock()
	return peer.FSM.PeerConf.State.PeerType == oc.PEER_TYPE_INTERNAL
}

func (peer *Peer) IsRouteServerClient() bool {
	peer.FSM.Lock.RLock()
	defer peer.FSM.Lock.RUnlock()
	return peer.FSM.PeerConf.RouteServer.Config.RouteServerClient
}

func (peer *Peer) IsSecondaryRouteEnabled() bool {
	peer.FSM.Lock.RLock()
	defer peer.FSM.Lock.RUnlock()
	return peer.FSM.PeerConf.RouteServer.Config.RouteServerClient && peer.FSM.PeerConf.RouteServer.Config.SecondaryRoute
}

func (peer *Peer) IsRouteReflectorClient() bool {
	peer.FSM.Lock.RLock()
	defer peer.FSM.Lock.RUnlock()
	return peer.FSM.PeerConf.RouteReflector.Config.RouteReflectorClient
}

func (peer *Peer) IsGracefulRestartEnabled() bool {
	peer.FSM.Lock.RLock()
	defer peer.FSM.Lock.RUnlock()
	return peer.FSM.PeerConf.GracefulRestart.State.Enabled
}

func (peer *Peer) GetAddPathMode(family bgp.Family) bgp.BGPAddPathMode {
	peer.FSM.Lock.RLock()
	defer peer.FSM.Lock.RUnlock()
	if mode, y := peer.FSM.RFMap[family]; y {
		return mode
	}
	return bgp.BGP_ADD_PATH_NONE
}

func (peer *Peer) IsAddPathReceiveEnabled(family bgp.Family) bool {
	return peer.GetAddPathMode(family)&bgp.BGP_ADD_PATH_RECEIVE > 0
}

func (peer *Peer) IsAddPathSendEnabled(family bgp.Family) bool {
	return peer.GetAddPathMode(family)&bgp.BGP_ADD_PATH_SEND > 0
}

func (peer *Peer) GetAddPathSendMax(family bgp.Family) uint8 {
	peer.FSM.Lock.RLock()
	defer peer.FSM.Lock.RUnlock()
	for _, a := range peer.FSM.PeerConf.AfiSafis {
		if a.State.Family == family {
			return a.AddPaths.Config.SendMax
		}
	}
	return 0
}

func (peer *Peer) GetRoutesCount(family bgp.Family, dstPrefix string) uint8 {
	destLocalKey := table.NewPathDestLocalKey(family, dstPrefix)
	if identifiers, ok := peer.SentPaths[*destLocalKey]; ok {
		count := len(identifiers)
		// the send-max config is uint8, so we need to check for overflow
		if count > int(^uint8(0)) {
			return ^uint8(0)
		}
		return uint8(count)
	}
	return 0
}

func (peer *Peer) UpdateRoutes(paths ...*table.Path) {
	if len(paths) == 0 {
		return
	}
	for _, path := range paths {
		localKey := path.GetLocalKey()
		destLocalKey := localKey.PathDestLocalKey
		identifiers, destExists := peer.SentPaths[destLocalKey]
		if path.IsWithdraw && destExists {
			delete(identifiers, path.GetNlri().PathLocalIdentifier())
		} else if !path.IsWithdraw {
			if !destExists {
				peer.SentPaths[destLocalKey] = make(map[uint32]struct{})
			}
			identifiers := peer.SentPaths[destLocalKey]
			if len(identifiers) < int(peer.GetAddPathSendMax(destLocalKey.Family)) {
				identifiers[localKey.Id] = struct{}{}
			}
		}
	}
}

func (peer *Peer) IsPathSendMaxFiltered(path *table.Path) bool {
	if path == nil {
		return false
	}
	_, found := peer.SendMaxPathFiltered[path.GetLocalKey()]
	return found
}

func (peer *Peer) UnsetPathSendMaxFiltered(path *table.Path) bool {
	if path == nil {
		return false
	}
	if _, ok := peer.SendMaxPathFiltered[path.GetLocalKey()]; !ok {
		return false
	}
	delete(peer.SendMaxPathFiltered, path.GetLocalKey())
	return true
}

func (peer *Peer) HasPathAlreadyBeenSent(path *table.Path) bool {
	if path == nil {
		return false
	}
	destLocalKey := path.GetDestLocalKey()
	if _, dstExist := peer.SentPaths[destLocalKey]; !dstExist {
		return false
	}
	_, pathExist := peer.SentPaths[destLocalKey][path.GetNlri().PathLocalIdentifier()]
	return pathExist
}

func (peer *Peer) IsDynamicNeighbor() bool {
	peer.FSM.Lock.RLock()
	defer peer.FSM.Lock.RUnlock()
	return peer.FSM.PeerConf.Config.NeighborAddress == "" && peer.FSM.PeerConf.Config.NeighborInterface == ""
}

func (peer *Peer) RecvedAllEOR() bool {
	peer.FSM.Lock.RLock()
	defer peer.FSM.Lock.RUnlock()
	for _, a := range peer.FSM.PeerConf.AfiSafis {
		if s := a.MpGracefulRestart.State; s.Enabled && s.Received && !s.EndOfRibReceived {
			return false
		}
	}
	return true
}

func (peer *Peer) ConfiguredRFlist() []bgp.Family {
	peer.FSM.Lock.RLock()
	defer peer.FSM.Lock.RUnlock()
	rfs, _ := oc.AfiSafis(peer.FSM.PeerConf.AfiSafis).ToRfList()
	return rfs
}

func (peer *Peer) NegotiatedRFList() []bgp.Family {
	peer.FSM.Lock.RLock()
	defer peer.FSM.Lock.RUnlock()
	l := make([]bgp.Family, 0, len(peer.FSM.RFMap))
	for family := range peer.FSM.RFMap {
		l = append(l, family)
	}
	return l
}

func (peer *Peer) ToGlobalFamilies(families []bgp.Family) []bgp.Family {
	id := peer.ID()
	peer.FSM.Lock.RLock()
	defer peer.FSM.Lock.RUnlock()
	if peer.FSM.PeerConf.Config.Vrf != "" {
		fs := make([]bgp.Family, 0, len(families))
		for _, f := range families {
			switch f {
			case bgp.RF_IPv4_UC:
				fs = append(fs, bgp.RF_IPv4_VPN)
			case bgp.RF_IPv6_UC:
				fs = append(fs, bgp.RF_IPv6_VPN)
			case bgp.RF_FS_IPv4_UC:
				fs = append(fs, bgp.RF_FS_IPv4_VPN)
			case bgp.RF_FS_IPv6_UC:
				fs = append(fs, bgp.RF_FS_IPv6_VPN)
			default:
				peer.FSM.Logger.Warn("invalid family configured for neighbor with vrf",
					log.Fields{
						"Topic":  "Peer",
						"Key":    id,
						"Family": f,
						"VRF":    peer.FSM.PeerConf.Config.Vrf,
					})
			}
		}
		families = fs
	}
	return families
}

func (peer *Peer) ForwardingPreservedFamilies() ([]bgp.Family, []bgp.Family) {
	peer.FSM.Lock.RLock()
	list := []bgp.Family{}
	for _, a := range peer.FSM.PeerConf.AfiSafis {
		if s := a.MpGracefulRestart.State; s.Enabled && s.Received {
			list = append(list, a.State.Family)
		}
	}
	peer.FSM.Lock.RUnlock()
	return utils.Classify(peer.ConfiguredRFlist(), list)
}

func (peer *Peer) LLGRFamilies() ([]bgp.Family, []bgp.Family) {
	peer.FSM.Lock.RLock()
	list := []bgp.Family{}
	for _, a := range peer.FSM.PeerConf.AfiSafis {
		if a.LongLivedGracefulRestart.State.Enabled {
			list = append(list, a.State.Family)
		}
	}
	peer.FSM.Lock.RUnlock()
	return utils.Classify(peer.ConfiguredRFlist(), list)
}

func (peer *Peer) IsLLGREnabledFamily(family bgp.Family) bool {
	peer.FSM.Lock.RLock()
	llgrEnabled := peer.FSM.PeerConf.GracefulRestart.Config.LongLivedEnabled
	peer.FSM.Lock.RUnlock()
	if !llgrEnabled {
		return false
	}
	fs, _ := peer.LLGRFamilies()
	return slices.Contains(fs, family)
}

func (peer *Peer) LLGRRestartTime(family bgp.Family) uint32 {
	peer.FSM.Lock.RLock()
	defer peer.FSM.Lock.RUnlock()
	for _, a := range peer.FSM.PeerConf.AfiSafis {
		if a.State.Family == family {
			return a.LongLivedGracefulRestart.State.PeerRestartTime
		}
	}
	return 0
}

func (peer *Peer) LLGRRestartTimerExpired(family bgp.Family) bool {
	peer.FSM.Lock.RLock()
	defer peer.FSM.Lock.RUnlock()
	all := true
	for _, a := range peer.FSM.PeerConf.AfiSafis {
		if a.State.Family == family {
			a.LongLivedGracefulRestart.State.PeerRestartTimerExpired = true
		}
		s := a.LongLivedGracefulRestart.State
		if s.Received && !s.PeerRestartTimerExpired {
			all = false
		}
	}
	return all
}

func (peer *Peer) MarkLLGRStale(fs []bgp.Family) []*table.Path {
	return peer.AdjRibIn.MarkLLGRStaleOrDrop(fs)
}

func (peer *Peer) StopPeerRestarting() {
	peer.FSM.Lock.Lock()
	defer peer.FSM.Lock.Unlock()
	peer.FSM.PeerConf.GracefulRestart.State.PeerRestarting = false
	for _, ch := range peer.LLGREndChs {
		close(ch)
	}
	peer.LLGREndChs = make([]chan struct{}, 0)
	peer.FSM.LongLivedRunning = false
}

func (peer *Peer) FilterPathFromSourcePeer(path, old *table.Path) *table.Path {
	// Consider 3 peers - A, B, C and prefix P originated by C. Parallel eBGP
	// sessions exist between A & B, and both have a single session with C.
	//
	// When A receives the withdraw from C, we enter this func for each peer of
	// A, with the following:
	// peer: [C, B #1, B #2]
	// path: new best for P facing B
	// old: old best for P facing C
	//
	// Our comparison between peer identifier and path source ID must be router
	// ID-based (not neighbor address), otherwise we will return early. If we
	// return early for one of the two sessions facing B
	// (whichever is not the new best path), we fail to send a withdraw towards
	// B, and the route is "stuck".
	// TODO: considerations for RFC6286
	if !peer.routerID().Equal(path.GetSource().ID) {
		return path
	}

	// Note: Multiple paths having the same prefix could exist the withdrawals
	// list in the case of Route Server setup with import policies modifying
	// paths. In such case, gobgp sends duplicated update messages; withdraw
	// messages for the same prefix.
	if !peer.IsRouteServerClient() {
		if peer.IsRouteReflectorClient() && path.GetFamily() == bgp.RF_RTC_UC {
			// When the peer is a Route Reflector client and the given path
			// contains the Route Tartget Membership NLRI, the path should not
			// be withdrawn in order to signal the client to distribute routes
			// with the specific RT to Route Reflector.
			return path
		} else if !path.IsWithdraw && old != nil && old.GetSource().Address.String() != peer.ID() {
			// Say, peer A and B advertized same prefix P, and best path
			// calculation chose a path from B as best. When B withdraws prefix
			// P, best path calculation chooses the path from A as best. For
			// peers other than A, this path should be advertised (as implicit
			// withdrawal). However for A, we should advertise the withdrawal
			// path. Thing is same when peer A and we advertized prefix P (as
			// local route), then, we withdraws the prefix.
			return old.Clone(true)
		}
	}
	if peer.FSM.Logger.GetLevel() >= log.DebugLevel {
		peer.FSM.Logger.Debug("From me, ignore",
			log.Fields{
				"Topic": "Peer",
				"Key":   peer.ID(),
				"Data":  path,
			})
	}
	return nil
}

func (peer *Peer) doPrefixLimit(k bgp.Family, c *oc.PrefixLimitConfig) *bgp.BGPMessage {
	if maxPrefixes := int(c.MaxPrefixes); maxPrefixes > 0 {
		count := peer.AdjRibIn.Count([]bgp.Family{k})
		pct := int(c.ShutdownThresholdPct)
		if pct > 0 && !peer.PrefixLimitWarned[k] && count > maxPrefixes*pct/100 {
			peer.PrefixLimitWarned[k] = true
			peer.FSM.Logger.Warn("prefix limit reached",
				log.Fields{
					"Topic":  "Peer",
					"Key":    peer.ID(),
					"Family": k.String(),
					"Pct":    pct,
				})
		}
		if count > maxPrefixes {
			peer.FSM.Logger.Warn("prefix limit reached",
				log.Fields{
					"Topic":  "Peer",
					"Key":    peer.ID(),
					"Family": k.String(),
				})
			return bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_MAXIMUM_NUMBER_OF_PREFIXES_REACHED, nil)
		}
	}
	return nil
}

func (peer *Peer) SendFSMOutgoingMsg(paths []*table.Path, notification *bgp.BGPMessage, stayIdle bool) {
	peer.FSM.OutgoingCh.In() <- &FSMOutgoingMsg{
		Paths:        paths,
		Notification: notification,
		StayIdle:     stayIdle,
	}
}

func (peer *Peer) UpdatePrefixLimitConfig(c []oc.AfiSafi) error {
	peer.FSM.Lock.RLock()
	x := peer.FSM.PeerConf.AfiSafis
	peer.FSM.Lock.RUnlock()
	y := c
	if len(x) != len(y) {
		return fmt.Errorf("changing supported afi-safi is not allowed")
	}
	m := make(map[bgp.Family]oc.PrefixLimitConfig)
	for _, e := range x {
		m[e.State.Family] = e.PrefixLimit.Config
	}
	for _, e := range y {
		if p, ok := m[e.State.Family]; !ok {
			return fmt.Errorf("changing supported afi-safi is not allowed")
		} else if !p.Equal(&e.PrefixLimit.Config) {
			peer.FSM.Logger.Warn("update prefix limit configuration",
				log.Fields{
					"Topic":                   "Peer",
					"Key":                     peer.ID(),
					"AddressFamily":           e.Config.AfiSafiName,
					"OldMaxPrefixes":          p.MaxPrefixes,
					"NewMaxPrefixes":          e.PrefixLimit.Config.MaxPrefixes,
					"OldShutdownThresholdPct": p.ShutdownThresholdPct,
					"NewShutdownThresholdPct": e.PrefixLimit.Config.ShutdownThresholdPct,
				})
			peer.PrefixLimitWarned[e.State.Family] = false
			if msg := peer.doPrefixLimit(e.State.Family, &e.PrefixLimit.Config); msg != nil {
				peer.SendFSMOutgoingMsg(nil, msg, true)
			}
		}
	}
	peer.FSM.Lock.Lock()
	peer.FSM.PeerConf.AfiSafis = c
	peer.FSM.Lock.Unlock()
	return nil
}

func (peer *Peer) HandleUpdate(e *FSMMsg) ([]*table.Path, []bgp.Family, *bgp.BGPMessage) {
	m := e.MsgData.(*bgp.BGPMessage)
	update := m.Body.(*bgp.BGPUpdate)

	if peer.FSM.Logger.GetLevel() >= log.DebugLevel {
		peer.FSM.Logger.Debug("received update",
			log.Fields{
				"Topic":       "Peer",
				"Key":         peer.FSM.PeerConf.State.NeighborAddress,
				"nlri":        update.NLRI,
				"withdrawals": update.WithdrawnRoutes,
				"attributes":  update.PathAttributes,
			})
	}

	peer.FSM.Lock.Lock()
	peer.FSM.PeerConf.Timers.State.UpdateRecvTime = time.Now().Unix()
	peer.FSM.Lock.Unlock()
	if len(e.PathList) > 0 {
		paths := make([]*table.Path, 0, len(e.PathList))
		eor := []bgp.Family{}
		for _, path := range e.PathList {
			if path.IsEOR() {
				family := path.GetFamily()
				peer.FSM.Logger.Debug("EOR received",
					log.Fields{
						"Topic":         "Peer",
						"Key":           peer.ID(),
						"AddressFamily": family,
					})
				eor = append(eor, family)
				continue
			}
			// RFC4271 9.1.2 Phase 2: Route Selection
			//
			// If the AS_PATH attribute of a BGP route contains an AS loop, the BGP
			// route should be excluded from the Phase 2 decision function.
			if aspath := path.GetAsPath(); aspath != nil {
				peer.FSM.Lock.RLock()
				localAS := peer.FSM.PeerInfo.LocalAS
				allowOwnAS := int(peer.FSM.PeerConf.AsPathOptions.Config.AllowOwnAs)
				peer.FSM.Lock.RUnlock()
				if bgputils.HasOwnASLoop(localAS, allowOwnAS, aspath) {
					path.SetRejected(true)
					continue
				}
			}
			// RFC4456 8. Avoiding Routing Information Loops
			// A router that recognizes the ORIGINATOR_ID attribute SHOULD
			// ignore a route received with its BGP Identifier as the ORIGINATOR_ID.
			isIBGPPeer := peer.IsIBGPPeer()
			peer.FSM.Lock.RLock()
			routerId := peer.FSM.GlobalConf.Config.RouterId
			peer.FSM.Lock.RUnlock()
			if isIBGPPeer {
				if id := path.GetOriginatorID(); routerId == id.String() {
					peer.FSM.Logger.Debug("Originator ID is mine, ignore",
						log.Fields{
							"Topic":        "Peer",
							"Key":          peer.ID(),
							"OriginatorID": id,
							"Data":         path,
						})
					path.SetRejected(true)
					continue
				}
			}
			paths = append(paths, path)
		}
		peer.AdjRibIn.Update(e.PathList)
		peer.FSM.Lock.RLock()
		peerAfiSafis := peer.FSM.PeerConf.AfiSafis
		peer.FSM.Lock.RUnlock()
		for _, af := range peerAfiSafis {
			if msg := peer.doPrefixLimit(af.State.Family, &af.PrefixLimit.Config); msg != nil {
				return nil, nil, msg
			}
		}
		return paths, eor, nil
	}
	return nil, nil, nil
}

func (peer *Peer) StartFSMHandler(wg *sync.WaitGroup, callback FSMCallback) {
	handler := newFSMHandler(peer.FSM, peer.FSM.OutgoingCh, wg, callback)
	peer.FSM.Lock.Lock()
	peer.FSM.Handler = handler
	peer.FSM.Lock.Unlock()
}

func (peer *Peer) StopFSMHandler() {
	peer.FSM.Lock.RLock()
	defer peer.FSM.Lock.RUnlock()
	peer.FSM.Handler.CtxCancel()
}

func (peer *Peer) StaleAll(rfList []bgp.Family) []*table.Path {
	return peer.AdjRibIn.StaleAll(rfList)
}

func (peer *Peer) PassConn(conn net.Conn) {
	select {
	case peer.FSM.ConnCh <- conn:
	default:
		conn.Close()
		peer.FSM.Logger.Warn("accepted conn is closed to avoid be blocked",
			log.Fields{
				"Topic": "Peer",
				"Key":   peer.ID(),
			})
	}
}

func (peer *Peer) DropAll(rfList []bgp.Family) []*table.Path {
	return peer.AdjRibIn.Drop(rfList)
}
