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

package server

import (
	"fmt"
	"net"
	"slices"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

const (
	flopThreshold = time.Second * 30
)

type peerGroup struct {
	Conf             *oc.PeerGroup
	members          map[string]oc.Neighbor
	dynamicNeighbors map[string]*oc.DynamicNeighbor
}

func newPeerGroup(c *oc.PeerGroup) *peerGroup {
	return &peerGroup{
		Conf:             c,
		members:          make(map[string]oc.Neighbor),
		dynamicNeighbors: make(map[string]*oc.DynamicNeighbor),
	}
}

func (pg *peerGroup) AddMember(c oc.Neighbor) {
	pg.members[c.State.NeighborAddress] = c
}

func (pg *peerGroup) DeleteMember(c oc.Neighbor) {
	delete(pg.members, c.State.NeighborAddress)
}

func (pg *peerGroup) AddDynamicNeighbor(c *oc.DynamicNeighbor) {
	pg.dynamicNeighbors[c.Config.Prefix] = c
}

func (pg *peerGroup) DeleteDynamicNeighbor(prefix string) {
	delete(pg.dynamicNeighbors, prefix)
}

func newDynamicPeer(g *oc.Global, neighborAddress string, pg *oc.PeerGroup, loc *table.TableManager, policy *table.RoutingPolicy, logger log.Logger) *peer {
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
	peer := newPeer(g, &conf, loc, policy, logger)
	peer.fsm.lock.Lock()
	peer.fsm.state = bgp.BGP_FSM_ACTIVE
	peer.fsm.lock.Unlock()
	return peer
}

type peer struct {
	tableId           string
	fsm               *fsm
	adjRibIn          *table.AdjRib
	policy            *table.RoutingPolicy
	localRib          *table.TableManager
	prefixLimitWarned map[bgp.Family]bool
	// map of path local identifiers sent for that prefix
	sentPaths           map[table.PathDestLocalKey]map[uint32]struct{}
	sendMaxPathFiltered map[table.PathLocalKey]struct{}
	llgrEndChs          []chan struct{}
}

func newPeer(g *oc.Global, conf *oc.Neighbor, loc *table.TableManager, policy *table.RoutingPolicy, logger log.Logger) *peer {
	peer := &peer{
		localRib:            loc,
		policy:              policy,
		fsm:                 newFSM(g, conf, logger),
		prefixLimitWarned:   make(map[bgp.Family]bool),
		sentPaths:           make(map[table.PathDestLocalKey]map[uint32]struct{}),
		sendMaxPathFiltered: make(map[table.PathLocalKey]struct{}),
	}
	if peer.isRouteServerClient() {
		peer.tableId = conf.State.NeighborAddress
	} else {
		peer.tableId = table.GLOBAL_RIB_NAME
	}
	rfs, _ := oc.AfiSafis(conf.AfiSafis).ToRfList()
	peer.adjRibIn = table.NewAdjRib(peer.fsm.logger, rfs)
	return peer
}

func (peer *peer) AS() uint32 {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.State.PeerAs
}

func (peer *peer) ID() string {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.State.NeighborAddress
}

func (peer *peer) routerID() net.IP {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.peerInfo.ID
}

func (peer *peer) RouterID() string {
	if id := peer.routerID(); id != nil {
		return id.String()
	}
	return ""
}

func (peer *peer) TableID() string {
	return peer.tableId
}

func (peer *peer) allowAsPathLoopLocal() bool {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.AsPathOptions.Config.AllowAsPathLoopLocal
}

func (peer *peer) isIBGPPeer() bool {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.State.PeerType == oc.PEER_TYPE_INTERNAL
}

func (peer *peer) isRouteServerClient() bool {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.RouteServer.Config.RouteServerClient
}

func (peer *peer) isSecondaryRouteEnabled() bool {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.RouteServer.Config.RouteServerClient && peer.fsm.pConf.RouteServer.Config.SecondaryRoute
}

func (peer *peer) isRouteReflectorClient() bool {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.RouteReflector.Config.RouteReflectorClient
}

func (peer *peer) isGracefulRestartEnabled() bool {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.GracefulRestart.State.Enabled
}

func (peer *peer) getAddPathMode(family bgp.Family) bgp.BGPAddPathMode {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	if mode, y := peer.fsm.rfMap[family]; y {
		return mode
	}
	return bgp.BGP_ADD_PATH_NONE
}

func (peer *peer) isAddPathReceiveEnabled(family bgp.Family) bool {
	return peer.getAddPathMode(family)&bgp.BGP_ADD_PATH_RECEIVE > 0
}

func (peer *peer) isAddPathSendEnabled(family bgp.Family) bool {
	return peer.getAddPathMode(family)&bgp.BGP_ADD_PATH_SEND > 0
}

func (peer *peer) getAddPathSendMax(family bgp.Family) uint8 {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	for _, a := range peer.fsm.pConf.AfiSafis {
		if a.State.Family == family {
			return a.AddPaths.Config.SendMax
		}
	}
	return 0
}

func (peer *peer) getRoutesCount(family bgp.Family, dstPrefix string) uint8 {
	destLocalKey := table.NewPathDestLocalKey(family, dstPrefix)
	if identifiers, ok := peer.sentPaths[*destLocalKey]; ok {
		count := len(identifiers)
		// the send-max config is uint8, so we need to check for overflow
		if count > int(^uint8(0)) {
			return ^uint8(0)
		}
		return uint8(count)
	}
	return 0
}

func (peer *peer) updateRoutes(paths ...*table.Path) {
	if len(paths) == 0 {
		return
	}
	for _, path := range paths {
		localKey := path.GetLocalKey()
		destLocalKey := localKey.PathDestLocalKey
		identifiers, destExists := peer.sentPaths[destLocalKey]
		if path.IsWithdraw && destExists {
			delete(identifiers, path.GetNlri().PathLocalIdentifier())
		} else if !path.IsWithdraw {
			if !destExists {
				peer.sentPaths[destLocalKey] = make(map[uint32]struct{})
			}
			identifiers := peer.sentPaths[destLocalKey]
			if len(identifiers) < int(peer.getAddPathSendMax(destLocalKey.Family)) {
				identifiers[localKey.Id] = struct{}{}
			}
		}
	}
}

func (peer *peer) isPathSendMaxFiltered(path *table.Path) bool {
	if path == nil {
		return false
	}
	_, found := peer.sendMaxPathFiltered[path.GetLocalKey()]
	return found
}

func (peer *peer) unsetPathSendMaxFiltered(path *table.Path) bool {
	if path == nil {
		return false
	}
	if _, ok := peer.sendMaxPathFiltered[path.GetLocalKey()]; !ok {
		return false
	}
	delete(peer.sendMaxPathFiltered, path.GetLocalKey())
	return true
}

func (peer *peer) hasPathAlreadyBeenSent(path *table.Path) bool {
	if path == nil {
		return false
	}
	destLocalKey := path.GetDestLocalKey()
	if _, dstExist := peer.sentPaths[destLocalKey]; !dstExist {
		return false
	}
	_, pathExist := peer.sentPaths[destLocalKey][path.GetNlri().PathLocalIdentifier()]
	return pathExist
}

func (peer *peer) isDynamicNeighbor() bool {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.Config.NeighborAddress == "" && peer.fsm.pConf.Config.NeighborInterface == ""
}

func (peer *peer) recvedAllEOR() bool {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	for _, a := range peer.fsm.pConf.AfiSafis {
		if s := a.MpGracefulRestart.State; s.Enabled && s.Received && !s.EndOfRibReceived {
			return false
		}
	}
	return true
}

func (peer *peer) configuredRFlist() []bgp.Family {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	rfs, _ := oc.AfiSafis(peer.fsm.pConf.AfiSafis).ToRfList()
	return rfs
}

func (peer *peer) negotiatedRFList() []bgp.Family {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	l := make([]bgp.Family, 0, len(peer.fsm.rfMap))
	for family := range peer.fsm.rfMap {
		l = append(l, family)
	}
	return l
}

func (peer *peer) toGlobalFamilies(families []bgp.Family) []bgp.Family {
	id := peer.ID()
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	if peer.fsm.pConf.Config.Vrf != "" {
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
				peer.fsm.logger.Warn("invalid family configured for neighbor with vrf",
					log.Fields{
						"Topic":  "Peer",
						"Key":    id,
						"Family": f,
						"VRF":    peer.fsm.pConf.Config.Vrf,
					})
			}
		}
		families = fs
	}
	return families
}

func classifyFamilies(all, part []bgp.Family) ([]bgp.Family, []bgp.Family) {
	a := []bgp.Family{}
	b := []bgp.Family{}
	for _, f := range all {
		p := true
		if slices.Contains(part, f) {
			p = false
			a = append(a, f)
		}
		if p {
			b = append(b, f)
		}
	}
	return a, b
}

func (peer *peer) forwardingPreservedFamilies() ([]bgp.Family, []bgp.Family) {
	peer.fsm.lock.RLock()
	list := []bgp.Family{}
	for _, a := range peer.fsm.pConf.AfiSafis {
		if s := a.MpGracefulRestart.State; s.Enabled && s.Received {
			list = append(list, a.State.Family)
		}
	}
	peer.fsm.lock.RUnlock()
	return classifyFamilies(peer.configuredRFlist(), list)
}

func (peer *peer) llgrFamilies() ([]bgp.Family, []bgp.Family) {
	peer.fsm.lock.RLock()
	list := []bgp.Family{}
	for _, a := range peer.fsm.pConf.AfiSafis {
		if a.LongLivedGracefulRestart.State.Enabled {
			list = append(list, a.State.Family)
		}
	}
	peer.fsm.lock.RUnlock()
	return classifyFamilies(peer.configuredRFlist(), list)
}

func (peer *peer) isLLGREnabledFamily(family bgp.Family) bool {
	peer.fsm.lock.RLock()
	llgrEnabled := peer.fsm.pConf.GracefulRestart.Config.LongLivedEnabled
	peer.fsm.lock.RUnlock()
	if !llgrEnabled {
		return false
	}
	fs, _ := peer.llgrFamilies()
	return slices.Contains(fs, family)
}

func (peer *peer) llgrRestartTime(family bgp.Family) uint32 {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	for _, a := range peer.fsm.pConf.AfiSafis {
		if a.State.Family == family {
			return a.LongLivedGracefulRestart.State.PeerRestartTime
		}
	}
	return 0
}

func (peer *peer) llgrRestartTimerExpired(family bgp.Family) bool {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	all := true
	for _, a := range peer.fsm.pConf.AfiSafis {
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

func (peer *peer) markLLGRStale(fs []bgp.Family) []*table.Path {
	return peer.adjRibIn.MarkLLGRStaleOrDrop(fs)
}

func (peer *peer) stopPeerRestarting() {
	peer.fsm.lock.Lock()
	defer peer.fsm.lock.Unlock()
	peer.fsm.pConf.GracefulRestart.State.PeerRestarting = false
	for _, ch := range peer.llgrEndChs {
		close(ch)
	}
	peer.llgrEndChs = make([]chan struct{}, 0)
	peer.fsm.longLivedRunning = false
}

func (peer *peer) filterPathFromSourcePeer(path, old *table.Path) *table.Path {
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
	if !peer.isRouteServerClient() {
		if peer.isRouteReflectorClient() && path.GetFamily() == bgp.RF_RTC_UC {
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
	if peer.fsm.logger.GetLevel() >= log.DebugLevel {
		peer.fsm.logger.Debug("From me, ignore",
			log.Fields{
				"Topic": "Peer",
				"Key":   peer.ID(),
				"Data":  path,
			})
	}
	return nil
}

func (peer *peer) doPrefixLimit(k bgp.Family, c *oc.PrefixLimitConfig) *bgp.BGPMessage {
	if maxPrefixes := int(c.MaxPrefixes); maxPrefixes > 0 {
		count := peer.adjRibIn.Count([]bgp.Family{k})
		pct := int(c.ShutdownThresholdPct)
		if pct > 0 && !peer.prefixLimitWarned[k] && count > maxPrefixes*pct/100 {
			peer.prefixLimitWarned[k] = true
			peer.fsm.logger.Warn("prefix limit reached",
				log.Fields{
					"Topic":  "Peer",
					"Key":    peer.ID(),
					"Family": k.String(),
					"Pct":    pct,
				})
		}
		if count > maxPrefixes {
			peer.fsm.logger.Warn("prefix limit reached",
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

func (peer *peer) updatePrefixLimitConfig(c []oc.AfiSafi) error {
	peer.fsm.lock.RLock()
	x := peer.fsm.pConf.AfiSafis
	peer.fsm.lock.RUnlock()
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
			peer.fsm.logger.Warn("update prefix limit configuration",
				log.Fields{
					"Topic":                   "Peer",
					"Key":                     peer.ID(),
					"AddressFamily":           e.Config.AfiSafiName,
					"OldMaxPrefixes":          p.MaxPrefixes,
					"NewMaxPrefixes":          e.PrefixLimit.Config.MaxPrefixes,
					"OldShutdownThresholdPct": p.ShutdownThresholdPct,
					"NewShutdownThresholdPct": e.PrefixLimit.Config.ShutdownThresholdPct,
				})
			peer.prefixLimitWarned[e.State.Family] = false
			if msg := peer.doPrefixLimit(e.State.Family, &e.PrefixLimit.Config); msg != nil {
				sendfsmOutgoingMsg(peer, nil, msg, true)
			}
		}
	}
	peer.fsm.lock.Lock()
	peer.fsm.pConf.AfiSafis = c
	peer.fsm.lock.Unlock()
	return nil
}

func (peer *peer) handleUpdate(e *fsmMsg) ([]*table.Path, []bgp.Family, *bgp.BGPMessage) {
	m := e.MsgData.(*bgp.BGPMessage)
	update := m.Body.(*bgp.BGPUpdate)

	if peer.fsm.logger.GetLevel() >= log.DebugLevel {
		peer.fsm.logger.Debug("received update",
			log.Fields{
				"Topic":       "Peer",
				"Key":         peer.fsm.pConf.State.NeighborAddress,
				"nlri":        update.NLRI,
				"withdrawals": update.WithdrawnRoutes,
				"attributes":  update.PathAttributes,
			})
	}

	peer.fsm.lock.Lock()
	peer.fsm.pConf.Timers.State.UpdateRecvTime = time.Now().Unix()
	peer.fsm.lock.Unlock()
	if len(e.PathList) > 0 {
		paths := make([]*table.Path, 0, len(e.PathList))
		eor := []bgp.Family{}
		for _, path := range e.PathList {
			if path.IsEOR() {
				family := path.GetFamily()
				peer.fsm.logger.Debug("EOR received",
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
				peer.fsm.lock.RLock()
				localAS := peer.fsm.peerInfo.LocalAS
				allowOwnAS := int(peer.fsm.pConf.AsPathOptions.Config.AllowOwnAs)
				peer.fsm.lock.RUnlock()
				if hasOwnASLoop(localAS, allowOwnAS, aspath) {
					path.SetRejected(true)
					continue
				}
			}
			// RFC4456 8. Avoiding Routing Information Loops
			// A router that recognizes the ORIGINATOR_ID attribute SHOULD
			// ignore a route received with its BGP Identifier as the ORIGINATOR_ID.
			isIBGPPeer := peer.isIBGPPeer()
			peer.fsm.lock.RLock()
			routerId := peer.fsm.gConf.Config.RouterId
			peer.fsm.lock.RUnlock()
			if isIBGPPeer {
				if id := path.GetOriginatorID(); routerId == id.String() {
					peer.fsm.logger.Debug("Originator ID is mine, ignore",
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
		peer.adjRibIn.Update(e.PathList)
		peer.fsm.lock.RLock()
		peerAfiSafis := peer.fsm.pConf.AfiSafis
		peer.fsm.lock.RUnlock()
		for _, af := range peerAfiSafis {
			if msg := peer.doPrefixLimit(af.State.Family, &af.PrefixLimit.Config); msg != nil {
				return nil, nil, msg
			}
		}
		return paths, eor, nil
	}
	return nil, nil, nil
}

func (peer *peer) startFSMHandler(callback func(*fsmMsg, bool)) {
	handler := newFSMHandler(peer.fsm, peer.fsm.outgoingCh, callback)
	peer.fsm.lock.Lock()
	peer.fsm.h = handler
	peer.fsm.lock.Unlock()
}

func (peer *peer) StaleAll(rfList []bgp.Family) []*table.Path {
	return peer.adjRibIn.StaleAll(rfList)
}

func (peer *peer) PassConn(conn net.Conn) {
	select {
	case peer.fsm.connCh <- conn:
	default:
		conn.Close()
		peer.fsm.logger.Warn("accepted conn is closed to avoid be blocked",
			log.Fields{
				"Topic": "Peer",
				"Key":   peer.ID(),
			})
	}
}

func (peer *peer) DropAll(rfList []bgp.Family) []*table.Path {
	return peer.adjRibIn.Drop(rfList)
}
