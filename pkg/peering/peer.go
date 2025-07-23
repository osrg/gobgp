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
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/bgputils"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/utils"
)

func NewPeer(g *oc.Global, conf *oc.Neighbor, loc *table.TableManager, policy *table.RoutingPolicy, logger log.Logger) *Peer {
	rfs, _ := oc.AfiSafis(conf.AfiSafis).ToRfList()
	tableID := table.GLOBAL_RIB_NAME
	if conf.RouteServer.Config.RouteServerClient {
		tableID = conf.State.NeighborAddress
	}
	common := &FSMCommon{
		GlobalConf: g,
		PeerConf:   conf,
		RFMap:      make(map[bgp.Family]bgp.BGPAddPathMode),
		CapMap:     make(map[bgp.BGPCapabilityCode][]bgp.ParameterCapabilityInterface),
		PeerInfo:   table.NewPeerInfo(g, conf),
		SentOpen:   bgputils.BuildOpenMessage(g, conf),
	}
	return &Peer{
		Common:              common,
		TableId:             tableID,
		AdjRibIn:            table.NewAdjRib(logger, rfs),
		LocalRib:            loc,
		Policy:              policy,
		PrefixLimitWarned:   make(map[bgp.Family]bool),
		SentPaths:           make(map[table.PathDestLocalKey]map[uint32]struct{}),
		SendMaxPathFiltered: make(map[table.PathLocalKey]struct{}),
		Logger:              logger,
	}
}

func (peer *Peer) AS() uint32 {
	peer.Common.Lock.RLock()
	defer peer.Common.Lock.RUnlock()
	return peer.Common.PeerConf.State.PeerAs
}

func (peer *Peer) ID() string {
	peer.Common.Lock.RLock()
	defer peer.Common.Lock.RUnlock()
	return peer.Common.PeerConf.State.NeighborAddress
}

func (peer *Peer) RouterID() net.IP {
	peer.Common.Lock.RLock()
	defer peer.Common.Lock.RUnlock()
	return peer.Common.PeerInfo.ID
}

func (peer *Peer) TableID() string {
	return peer.TableId
}

func (peer *Peer) AllowAsPathLoopLocal() bool {
	peer.Common.Lock.RLock()
	defer peer.Common.Lock.RUnlock()
	return peer.Common.PeerConf.AsPathOptions.Config.AllowAsPathLoopLocal
}

func (peer *Peer) IsIBGPPeer() bool {
	peer.Common.Lock.RLock()
	defer peer.Common.Lock.RUnlock()
	return peer.Common.PeerConf.State.PeerType == oc.PEER_TYPE_INTERNAL
}

func (peer *Peer) IsRouteServerClient() bool {
	return peer.Common.PeerConf.RouteServer.Config.RouteServerClient
}

func (peer *Peer) IsSecondaryRouteEnabled() bool {
	return peer.Common.PeerConf.RouteServer.Config.RouteServerClient && peer.Common.PeerConf.RouteServer.Config.SecondaryRoute
}

func (peer *Peer) IsRouteReflectorClient() bool {
	return peer.Common.PeerConf.RouteReflector.Config.RouteReflectorClient
}

func (peer *Peer) IsGracefulRestartEnabled() bool {
	peer.Common.Lock.RLock()
	defer peer.Common.Lock.RUnlock()
	return peer.Common.PeerConf.GracefulRestart.State.Enabled
}

func (peer *Peer) GetAddPathMode(family bgp.Family) bgp.BGPAddPathMode {
	peer.Common.Lock.RLock()
	defer peer.Common.Lock.RUnlock()
	if mode, y := peer.Common.RFMap[family]; y {
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
	for _, a := range peer.Common.PeerConf.AfiSafis {
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
	peer.Common.Lock.RLock()
	defer peer.Common.Lock.RUnlock()
	return peer.Common.PeerConf.Config.NeighborAddress == "" && peer.Common.PeerConf.Config.NeighborInterface == ""
}

func (peer *Peer) RecvedAllEOR() bool {
	peer.Common.Lock.RLock()
	defer peer.Common.Lock.RUnlock()
	for _, a := range peer.Common.PeerConf.AfiSafis {
		if s := a.MpGracefulRestart.State; s.Enabled && s.Received && !s.EndOfRibReceived {
			return false
		}
	}
	return true
}

func (peer *Peer) ConfiguredRFlist() []bgp.Family {
	peer.Common.Lock.RLock()
	defer peer.Common.Lock.RUnlock()
	rfs, _ := oc.AfiSafis(peer.Common.PeerConf.AfiSafis).ToRfList()
	return rfs
}

func (peer *Peer) NegotiatedRFList() []bgp.Family {
	peer.Common.Lock.RLock()
	defer peer.Common.Lock.RUnlock()
	l := make([]bgp.Family, 0, len(peer.Common.RFMap))
	for family := range peer.Common.RFMap {
		l = append(l, family)
	}
	return l
}

func (peer *Peer) ToGlobalFamilies(families []bgp.Family) []bgp.Family {
	id := peer.ID()
	vrf := peer.Common.PeerConf.Config.Vrf
	if vrf == "" {
		return families
	}

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
			peer.Logger.Warn("invalid family configured for neighbor with vrf",
				log.Fields{
					"Topic":  "Peer",
					"Key":    id,
					"Family": f,
					"VRF":    vrf,
				})
		}
	}
	return fs
}

func (peer *Peer) ForwardingPreservedFamilies() ([]bgp.Family, []bgp.Family) {
	peer.Common.Lock.RLock()
	list := []bgp.Family{}
	for _, a := range peer.Common.PeerConf.AfiSafis {
		if s := a.MpGracefulRestart.State; s.Enabled && s.Received {
			list = append(list, a.State.Family)
		}
	}
	peer.Common.Lock.RUnlock()
	return utils.Classify(peer.ConfiguredRFlist(), list)
}

func (peer *Peer) LLGRFamilies() ([]bgp.Family, []bgp.Family) {
	peer.Common.Lock.RLock()
	list := []bgp.Family{}
	for _, a := range peer.Common.PeerConf.AfiSafis {
		if a.LongLivedGracefulRestart.State.Enabled {
			list = append(list, a.State.Family)
		}
	}
	peer.Common.Lock.RUnlock()
	return utils.Classify(peer.ConfiguredRFlist(), list)
}

func (peer *Peer) IsLLGREnabledFamily(family bgp.Family) bool {
	llgrEnabled := peer.Common.PeerConf.GracefulRestart.Config.LongLivedEnabled
	if !llgrEnabled {
		return false
	}
	fs, _ := peer.LLGRFamilies()
	return slices.Contains(fs, family)
}

func (peer *Peer) LLGRRestartTime(family bgp.Family) uint32 {
	peer.Common.Lock.RLock()
	defer peer.Common.Lock.RUnlock()
	for _, a := range peer.Common.PeerConf.AfiSafis {
		if a.State.Family == family {
			return a.LongLivedGracefulRestart.State.PeerRestartTime
		}
	}
	return 0
}

func (peer *Peer) LLGRRestartTimerExpired(family bgp.Family) bool {
	peer.Common.Lock.RLock()
	defer peer.Common.Lock.RUnlock()
	all := true
	for _, a := range peer.Common.PeerConf.AfiSafis {
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
	peer.Common.Lock.Lock()
	peer.Common.PeerConf.GracefulRestart.State.PeerRestarting = false
	peer.Common.Lock.Unlock()

	peer.Lock.Lock()
	defer peer.Lock.Unlock()
	for _, ch := range peer.LLGREndChs {
		close(ch)
	}
	peer.LLGREndChs = make([]chan struct{}, 0)
	peer.LongLivedRunning = false
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
	if !peer.RouterID().Equal(path.GetSource().ID) {
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
	if peer.Logger.GetLevel() >= log.DebugLevel {
		peer.Logger.Debug("From me, ignore",
			log.Fields{
				"Topic": "Peer",
				"Key":   peer.ID(),
				"Data":  path,
			})
	}
	return nil
}

func (peer *Peer) doPrefixLimit(k bgp.Family, c *oc.PrefixLimitConfig) bool {
	maxPrefixes := int(c.MaxPrefixes)
	if maxPrefixes <= 0 {
		return false
	}

	count := peer.AdjRibIn.Count([]bgp.Family{k})
	pct := int(c.ShutdownThresholdPct)
	if pct > 0 && !peer.PrefixLimitWarned[k] && count > maxPrefixes*pct/100 {
		peer.PrefixLimitWarned[k] = true
		peer.Logger.Warn("prefix limit reached",
			log.Fields{
				"Topic":  "Peer",
				"Key":    peer.ID(),
				"Family": k.String(),
				"Pct":    pct,
			})
	}

	if count > maxPrefixes {
		peer.SetAdminState(AdminStatePfxCt, "prefix limit reached")
		return true
	}
	return false
}

func (peer *Peer) SendFSMOutgoingMsg(paths []*table.Path) {
	peer.Lock.RLock()
	defer peer.Lock.RUnlock()
	if peer.fsm == nil {
		return
	}
	peer.fsm.outgoingCh.In() <- paths
}

func (peer *Peer) UpdatePrefixLimitConfig(c []oc.AfiSafi) error {
	peer.Common.Lock.RLock()
	x := peer.Common.PeerConf.AfiSafis
	m := make(map[bgp.Family]oc.PrefixLimitConfig)
	for _, e := range x {
		m[e.State.Family] = e.PrefixLimit.Config
	}
	peer.Common.Lock.RUnlock()
	if len(x) != len(c) {
		return fmt.Errorf("changing supported afi-safi is not allowed")
	}
	for _, e := range c {
		p, ok := m[e.State.Family]
		if !ok {
			return fmt.Errorf("changing supported afi-safi is not allowed")
		}
		if !p.Equal(&e.PrefixLimit.Config) {
			peer.Logger.Warn("update prefix limit configuration",
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
			peer.doPrefixLimit(e.State.Family, &e.PrefixLimit.Config)
		}
	}
	peer.Common.Lock.Lock()
	peer.Common.PeerConf.AfiSafis = c
	peer.Common.Lock.Unlock()
	return nil
}

func (peer *Peer) HandleUpdate(e *FSMMsg) ([]*table.Path, []bgp.Family) {
	m := e.Message
	update := m.Body.(*bgp.BGPUpdate)

	peer.Common.Lock.Lock()
	peer.Common.PeerConf.Timers.State.UpdateRecvTime = time.Now().Unix()
	neighborAddress := peer.Common.PeerConf.State.NeighborAddress
	peer.Common.Lock.Unlock()

	if peer.Logger.GetLevel() >= log.DebugLevel {
		peer.Logger.Debug("received update",
			log.Fields{
				"Topic":       "Peer",
				"Key":         neighborAddress,
				"nlri":        update.NLRI,
				"withdrawals": update.WithdrawnRoutes,
				"attributes":  update.PathAttributes,
			})
	}

	if len(e.PathList) > 0 {
		paths := make([]*table.Path, 0, len(e.PathList))
		eor := []bgp.Family{}
		for _, path := range e.PathList {
			if path.IsEOR() {
				family := path.GetFamily()
				peer.Logger.Debug("EOR received",
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
				peer.Common.Lock.RLock()
				localAS := peer.Common.PeerInfo.LocalAS
				allowOwnAS := int(peer.Common.PeerConf.AsPathOptions.Config.AllowOwnAs)
				peer.Common.Lock.RUnlock()
				if bgputils.HasOwnASLoop(localAS, allowOwnAS, aspath) {
					path.SetRejected(true)
					continue
				}
			}
			// RFC4456 8. Avoiding Routing Information Loops
			// A router that recognizes the ORIGINATOR_ID attribute SHOULD
			// ignore a route received with its BGP Identifier as the ORIGINATOR_ID.
			isIBGPPeer := peer.IsIBGPPeer()
			routerId := peer.Common.GlobalConf.Config.RouterId
			if isIBGPPeer {
				if id := path.GetOriginatorID(); routerId == id.String() {
					peer.Logger.Debug("Originator ID is mine, ignore",
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
		peer.Common.Lock.RLock()
		peerAfiSafis := peer.Common.PeerConf.AfiSafis
		peer.Common.Lock.RUnlock()
		for _, af := range peerAfiSafis {
			if peer.doPrefixLimit(af.State.Family, &af.PrefixLimit.Config) {
				return nil, nil
			}
		}
		return paths, eor
	}
	return nil, nil
}

func (peer *Peer) StaleAll(rfList []bgp.Family) []*table.Path {
	return peer.AdjRibIn.StaleAll(rfList)
}

func (peer *Peer) DropAll(rfList []bgp.Family) []*table.Path {
	return peer.AdjRibIn.Drop(rfList)
}

func (peer *Peer) SendEndNotification(n *bgp.BGPMessage) {
	peer.fsm.endNotificationCh <- n
}

func (peer *Peer) NeedConnTTLUpdate() error {
	conn := peer.fsm.conn.Load()
	if conn == nil {
		return nil
	}
	return peer.fsm.common.SetPeerConnTTL(conn)
}
