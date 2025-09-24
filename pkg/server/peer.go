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
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

const (
	flopThreshold = time.Second * 30
)

type peerPathLimiterImpl struct {
	afiSafis []oc.AfiSafi

	// map of path local identifiers sent for that prefix
	sentPaths           map[table.PathDestLocalKey]map[uint32]struct{}
	sendMaxPathFiltered map[table.PathLocalKey]struct{}
}

type peerPathLimiter interface {
	getAddPathSendMax(family bgp.Family) uint8
	getRoutesCount(family bgp.Family, dstPrefix string) uint8
	updateRoutes(paths ...*table.Path)
	isPathSendMaxFiltered(path *table.Path) bool
	setPathSendMaxFiltered(path *table.Path)
	unsetPathSendMaxFiltered(path *table.Path) bool
	hasPathAlreadyBeenSent(path *table.Path) bool
}

func (peer *peerPathLimiterImpl) init(afiSafis []oc.AfiSafi) {
	peer.afiSafis = afiSafis

	peer.sentPaths = make(map[table.PathDestLocalKey]map[uint32]struct{})
	peer.sendMaxPathFiltered = make(map[table.PathLocalKey]struct{})
}

func (peer *peerPathLimiterImpl) getAddPathSendMax(family bgp.Family) uint8 {
	for _, a := range peer.afiSafis {
		if a.State.Family == family {
			return a.AddPaths.Config.SendMax
		}
	}
	return 0
}

func (peer *peerPathLimiterImpl) getRoutesCount(family bgp.Family, dstPrefix string) uint8 {
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

func (peer *peerPathLimiterImpl) updateRoutes(paths ...*table.Path) {
	if len(paths) == 0 {
		return
	}
	for _, path := range paths {
		localKey := path.GetLocalKey()
		destLocalKey := localKey.PathDestLocalKey
		identifiers, destExists := peer.sentPaths[destLocalKey]
		if path.IsWithdraw && destExists {
			delete(identifiers, path.LocalID())
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

func (peer *peerPathLimiterImpl) isPathSendMaxFiltered(path *table.Path) bool {
	if path == nil {
		return false
	}
	_, found := peer.sendMaxPathFiltered[path.GetLocalKey()]
	return found
}

func (peer *peerPathLimiterImpl) setPathSendMaxFiltered(path *table.Path) {
	if path == nil {
		return
	}
	peer.sendMaxPathFiltered[path.GetLocalKey()] = struct{}{}
}

func (peer *peerPathLimiterImpl) unsetPathSendMaxFiltered(path *table.Path) bool {
	if path == nil {
		return false
	}
	if _, ok := peer.sendMaxPathFiltered[path.GetLocalKey()]; !ok {
		return false
	}
	delete(peer.sendMaxPathFiltered, path.GetLocalKey())
	return true
}

func (peer *peerPathLimiterImpl) hasPathAlreadyBeenSent(path *table.Path) bool {
	if path == nil {
		return false
	}
	destLocalKey := path.GetDestLocalKey()
	if _, dstExist := peer.sentPaths[destLocalKey]; !dstExist {
		return false
	}
	_, pathExist := peer.sentPaths[destLocalKey][path.LocalID()]
	return pathExist
}

type receiver interface {
	peerPathLimiter

	ID() string
	PeerInfo() *table.PeerInfo

	TableID() string
	AS() uint32

	vrf() string
	routingPolicy() *table.RoutingPolicy
	PolicyID() string
	localRib() *table.TableManager
	configuredRFlist() []bgp.Family

	isIBGPPeer() bool
	isEnabledFamily(rf bgp.Family) bool
	isLLGREnabledFamily(rf bgp.Family) bool
	replacePeerAS() (bool, uint32, uint32)
	isRouteReflectorClient() bool
	isAddPathSendEnabled(family bgp.Family) bool
	isRouteServerClient() bool
	isSecondaryRouteEnabled() bool
	allowAsPathLoopLocal() bool

	isGracefulRestartEnabled() bool
	resetLocalRestarting() bool

	needToAdvertise() bool
	send(paths, old []*table.Path)

	logger() log.Logger
}

type peerGroup struct {
	peerPathLimiterImpl

	l log.Logger

	Conf *oc.PeerGroup
	info *table.PeerInfo

	rfList, llgrRFList []bgp.Family
	loc                *table.TableManager
	policy             *table.RoutingPolicy

	members          map[string]oc.Neighbor
	dynamicNeighbors map[string]*oc.DynamicNeighbor
	neighborMap      map[string]*peer
}

func newPeerGroup(l log.Logger, policy *table.RoutingPolicy, g *oc.Global, c *oc.PeerGroup, loc *table.TableManager) (*peerGroup, error) {
	pg := &peerGroup{
		l: l,

		loc:    loc,
		policy: policy,

		members:          make(map[string]oc.Neighbor),
		dynamicNeighbors: make(map[string]*oc.DynamicNeighbor),
		neighborMap:      make(map[string]*peer),
	}
	if err := pg.Update(g, c); err != nil {
		return nil, err
	}

	// Initializes peerPathLimiterImpl. Using pg.peerPathLimiterImpl.init would be better, but
	// golangci-lint insists overwise, so here we are
	pg.init(c.AfiSafis)
	return pg, nil
}

func (pg *peerGroup) Update(g *oc.Global, c *oc.PeerGroup) error {
	if err := oc.SetPeerGroupStateValues(c, g); err != nil {
		return err
	}

	pg.Conf = c
	pg.info = table.NewPeerGroupInfo(g, c)
	pg.rfList, _ = oc.AfiSafis(pg.Conf.AfiSafis).ToRfList()

	if c.GracefulRestart.Config.LongLivedEnabled {
		pg.llgrRFList = llgrFamilies(c.AfiSafis, false)
	} else {
		pg.llgrRFList = nil
	}

	return nil
}

func (pg *peerGroup) AddMember(c oc.Neighbor, peer *peer) {
	pg.members[c.State.NeighborAddress.String()] = c
	pg.neighborMap[c.State.NeighborAddress.String()] = peer
}

func (pg *peerGroup) DeleteMember(addr string) {
	delete(pg.members, addr)
	delete(pg.neighborMap, addr)
}

func (pg *peerGroup) AddDynamicNeighbor(c *oc.DynamicNeighbor) {
	pg.dynamicNeighbors[c.Config.Prefix.String()] = c
}

func (pg *peerGroup) DeleteDynamicNeighbor(prefix string) {
	delete(pg.dynamicNeighbors, prefix)
}

func (pg *peerGroup) ID() string {
	return oc.NewPeerGroupPolicyAssignmentKeyFromName(pg.Conf.Config.PeerGroupName)
}

func (pg *peerGroup) PeerInfo() *table.PeerInfo {
	return pg.info
}

func (pg *peerGroup) TableID() string {
	return table.GLOBAL_RIB_NAME
}

func (pg *peerGroup) PolicyID() string {
	if pg.Conf.Config.SharedPolicy {
		return pg.ID()
	}

	return table.GLOBAL_RIB_NAME
}

func (pg *peerGroup) AS() uint32 {
	return pg.Conf.Config.PeerAs
}

func (pg *peerGroup) needToAdvertise() bool {
	return true
}

func (pg *peerGroup) vrf() string {
	return ""
}

func (pg *peerGroup) routingPolicy() *table.RoutingPolicy {
	return pg.policy
}

func (pg *peerGroup) localRib() *table.TableManager {
	return pg.loc
}

func (pg *peerGroup) configuredRFlist() []bgp.Family {
	return pg.rfList
}

func (pg *peerGroup) isIBGPPeer() bool {
	return pg.info.PeerType == oc.PEER_TYPE_INTERNAL
}

func (pg *peerGroup) isEnabledFamily(family bgp.Family) bool {
	return slices.Contains(pg.rfList, family)
}

func (pg *peerGroup) isLLGREnabledFamily(family bgp.Family) bool {
	return slices.Contains(pg.llgrRFList, family)
}

func (pg *peerGroup) replacePeerAS() (bool, uint32, uint32) {
	return pg.Conf.AsPathOptions.Config.ReplacePeerAs,
		pg.Conf.Config.PeerAs,
		pg.Conf.Config.LocalAs
}

func (pg *peerGroup) isAddPathSendEnabled(family bgp.Family) bool {
	// Different peers can treat ADD_PATH capability differently. For now
	// we do not support per-peer-group receivers with ADD_PATH-capable peers
	return false
}

func (pg *peerGroup) isRouteReflectorClient() bool {
	return pg.Conf.RouteReflector.Config.RouteReflectorClient
}

func (pg *peerGroup) isRouteServerClient() bool {
	return pg.Conf.RouteServer.Config.RouteServerClient
}

func (pg *peerGroup) isSecondaryRouteEnabled() bool {
	return pg.Conf.RouteServer.Config.SecondaryRoute
}

func (pg *peerGroup) isGracefulRestartEnabled() bool {
	return pg.Conf.GracefulRestart.Config.Enabled
}

func (pg *peerGroup) allowAsPathLoopLocal() bool {
	return pg.Conf.AsPathOptions.Config.AllowAsPathLoopLocal
}

func (pg *peerGroup) resetLocalRestarting() bool {
	var anyPeerLocalRestarting bool
	for _, p := range pg.neighborMap {
		if p.resetLocalRestarting() {
			anyPeerLocalRestarting = true
		}
	}
	return anyPeerLocalRestarting
}

func (pg *peerGroup) send(paths, olds []*table.Path) {
	for _, peer := range pg.neighborMap {
		if !peer.needToAdvertise() {
			continue
		}

		// Perform last checks for filtering paths to avoid sending paths back to the peer
		// that originated it.
		filtered := filterPathsForPeer(peer, paths, olds)
		peer.send(filtered, nil)
	}
}

func filterPathsForPeer(peer *peer, paths, olds []*table.Path) []*table.Path {
	var filtered []*table.Path
	for idx, path := range paths {
		var old *table.Path
		if olds != nil {
			old = olds[idx]
		}

		peerPath := peerFilterpath(peer, path, old)
		if peerPath != nil {
			peerPath = peerPostFilterpath(peer, peerPath)
		}
		if peerPath != nil {
			// All modifications to path are done, compute hash to avoid each peer computing it
			// to avoid data race when each peer goroutine
			_ = path.GetHash()
		}

		if peerPath == path {
			// In most cases no paths will be filtered or _altered_, so we do a lazy filtering
			// and start tracking filtered paths after encontering the first filtered path
			if filtered != nil {
				filtered = append(filtered, peerPath)
			}
			continue
		}

		if filtered == nil {
			filtered = make([]*table.Path, idx, len(paths))
			copy(filtered, paths[:idx])
		}
		if peerPath != nil {
			filtered = append(filtered, peerPath)
		}
	}

	if filtered != nil {
		return filtered
	}
	return paths
}

func (pg *peerGroup) logger() log.Logger {
	return pg.l
}

func newDynamicPeer(g *oc.Global, neighborAddress string, pg *oc.PeerGroup, loc *table.TableManager, policy *table.RoutingPolicy, logger log.Logger) *peer {
	conf := oc.Neighbor{
		Config: oc.NeighborConfig{
			PeerGroup: pg.Config.PeerGroupName,
		},
		State: oc.NeighborState{
			NeighborAddress: netip.MustParseAddr(neighborAddress),
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
	peer := newPeer(g, &conf, pg, loc, policy, logger)
	peer.fsm.lock.Lock()
	peer.fsm.state = bgp.BGP_FSM_ACTIVE
	peer.fsm.lock.Unlock()
	return peer
}

type peer struct {
	peerPathLimiterImpl

	tableId           string
	policyId          string
	fsm               *fsm
	adjRibIn          *table.AdjRib
	policy            *table.RoutingPolicy
	loc               *table.TableManager
	peerInfo          *table.PeerInfo
	prefixLimitWarned map[bgp.Family]bool

	llgrEndChs       []chan struct{}
	longLivedRunning bool
}

func newPeer(g *oc.Global, conf *oc.Neighbor, pg *oc.PeerGroup, loc *table.TableManager, policy *table.RoutingPolicy, logger log.Logger) *peer {
	peer := &peer{
		loc:               loc,
		policy:            policy,
		fsm:               newFSM(g, conf, logger),
		prefixLimitWarned: make(map[bgp.Family]bool),
	}

	if peer.isRouteServerClient() {
		peer.tableId = conf.State.NeighborAddress.String()
	} else {
		peer.tableId = table.GLOBAL_RIB_NAME
	}

	if pg != nil && pg.Config.SharedPolicy {
		peer.policyId = oc.NewPeerGroupPolicyAssignmentKeyFromName(pg.Config.PeerGroupName)
	} else {
		peer.policyId = peer.tableId
	}

	rfs, _ := oc.AfiSafis(conf.AfiSafis).ToRfList()
	peer.init(conf.AfiSafis)
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
	return peer.fsm.pConf.State.NeighborAddress.String()
}

func (peer *peer) PeerGroup() string {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.Config.PeerGroup
}

func (peer *peer) PeerInfo() *table.PeerInfo {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()

	// Return a copy since we're releasing lock here
	peerInfo := *peer.peerInfo
	return &peerInfo
}

func (peer *peer) routerID() netip.Addr {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	if peer.fsm.pConf.State.RemoteRouterId.IsValid() {
		return peer.fsm.pConf.State.RemoteRouterId
	}
	return netip.Addr{}
}

func (peer *peer) TableID() string {
	return peer.tableId
}

func (peer *peer) allowAsPathLoopLocal() bool {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.AsPathOptions.Config.AllowAsPathLoopLocal
}

func (peer *peer) PolicyID() string {
	return peer.policyId
}

func (peer *peer) vrf() string {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.Config.Vrf
}

func (peer *peer) routingPolicy() *table.RoutingPolicy {
	return peer.policy
}

func (peer *peer) localRib() *table.TableManager {
	return peer.loc
}

func (peer *peer) isIBGPPeer() bool {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.State.PeerType == oc.PEER_TYPE_INTERNAL
}

func (peer *peer) replacePeerAS() (bool, uint32, uint32) {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.AsPathOptions.Config.ReplacePeerAs,
		peer.fsm.pConf.Config.LocalAs,
		peer.fsm.pConf.Config.PeerAs
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

func (peer *peer) resetLocalRestarting() bool {
	peer.fsm.lock.Lock()
	defer peer.fsm.lock.Unlock()

	peerLocalRestarting := peer.fsm.pConf.GracefulRestart.State.LocalRestarting
	peer.fsm.pConf.GracefulRestart.State.LocalRestarting = false
	return peerLocalRestarting
}

func (peer *peer) logger() log.Logger {
	return peer.fsm.logger
}

func (peer *peer) needToAdvertise() bool {
	peer.fsm.lock.RLock()
	notEstablished := peer.fsm.state != bgp.BGP_FSM_ESTABLISHED
	localRestarting := peer.fsm.pConf.GracefulRestart.State.LocalRestarting
	peer.fsm.lock.RUnlock()
	if notEstablished {
		return false
	}
	if localRestarting {
		peer.fsm.lock.RLock()
		peer.fsm.logger.Debug("now syncing, suppress sending updates",
			log.Fields{
				"Topic": "Peer",
				"Key":   peer.fsm.pConf.State.NeighborAddress,
			})
		peer.fsm.lock.RUnlock()
		return false
	}
	return true
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

func (peer *peer) isDynamicNeighbor() bool {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return !peer.fsm.pConf.Config.NeighborAddress.IsValid() && peer.fsm.pConf.Config.NeighborInterface == ""
}

func (peer *peer) getRtcEORWait() bool {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	peer.fsm.logger.Debug("Get rtcEORWait",
		log.Fields{
			"Topic": "Peer",
			"Key":   peer.fsm.pConf.State.NeighborAddress,
			"Data":  peer.fsm.rtcEORWait,
		})

	return peer.fsm.rtcEORWait
}

func (peer *peer) setRtcEORWait(waiting bool) {
	peer.fsm.lock.Lock()
	defer peer.fsm.lock.Unlock()
	peer.fsm.rtcEORWait = waiting
	peer.fsm.logger.Debug("Set rtcEORWait",
		log.Fields{
			"Topic": "Peer",
			"Key":   peer.fsm.pConf.State.NeighborAddress,
			"Data":  peer.fsm.rtcEORWait,
		})
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

func toGlobalFamilies(peer receiver, families []bgp.Family) []bgp.Family {
	id := peer.ID()
	if vrf := peer.vrf(); vrf != "" {
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
				peer.logger().Warn("invalid family configured for neighbor with vrf",
					log.Fields{
						"Topic":  "Peer",
						"Key":    id,
						"Family": f,
						"VRF":    vrf,
					})
			}
		}
		families = fs
	}
	return families
}

func llgrFamilies(afiSafis []oc.AfiSafi, checkState bool) []bgp.Family {
	list := make([]bgp.Family, 0, len(afiSafis))
	for _, a := range afiSafis {
		if !a.LongLivedGracefulRestart.Config.Enabled {
			continue
		}
		if checkState && !a.LongLivedGracefulRestart.State.Enabled {
			// NOTE: only peers have state - for peer groups we should check
			// only config when filtering on peer-group level
			continue
		}
		list = append(list, a.State.Family)
	}
	return list
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
	list := llgrFamilies(peer.fsm.pConf.AfiSafis, true)
	peer.fsm.lock.RUnlock()
	return classifyFamilies(peer.configuredRFlist(), list)
}

func (peer *peer) isEnabledFamily(family bgp.Family) bool {
	return slices.Contains(peer.configuredRFlist(), family)
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

func (peer *peer) llgrRestartTimerStarted(family bgp.Family) {
	peer.fsm.lock.Lock()
	defer peer.fsm.lock.Unlock()

	for i, a := range peer.fsm.pConf.AfiSafis {
		if a.State.Family == family {
			peer.fsm.pConf.AfiSafis[i].MpGracefulRestart.State.Running = false
			peer.fsm.pConf.AfiSafis[i].LongLivedGracefulRestart.State.Running = true
		}
	}
}

func (peer *peer) llgrRestartTimerExpired(family bgp.Family) bool {
	peer.fsm.lock.Lock()
	defer peer.fsm.lock.Unlock()
	all := true
	for i, a := range peer.fsm.pConf.AfiSafis {
		if a.State.Family == family {
			peer.fsm.pConf.AfiSafis[i].LongLivedGracefulRestart.State.PeerRestartTimerExpired = true
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
	for i := range peer.fsm.pConf.AfiSafis {
		peer.fsm.pConf.AfiSafis[i].MpGracefulRestart.State.Running = false
		peer.fsm.pConf.AfiSafis[i].LongLivedGracefulRestart.State.Running = false
	}

	for _, ch := range peer.llgrEndChs {
		close(ch)
	}
	peer.llgrEndChs = make([]chan struct{}, 0)
	peer.longLivedRunning = false
}

// Returns true if the peer is interested in this path according to BGP RTC
// (i.e., has advertised the relevant RT).
func (peer *peer) interestedIn(path *table.Path) bool {
	for _, ext := range path.GetExtCommunities() {
		for _, p := range peer.adjRibIn.PathList([]bgp.Family{bgp.RF_RTC_UC}, true) {
			rt := p.GetNlri().(*bgp.RouteTargetMembershipNLRI).RouteTarget
			// Note: nil RT means the default route target
			if rt == nil || ext.String() == rt.String() {
				return true
			}
		}
	}
	return false
}

func (peer *peer) filterPathFromSourcePeer(path, old *table.Path) *table.Path {
	// EOR is originated by us, other peer cannot be source of it
	if path.IsEOR() {
		return path
	}

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
	if peer.routerID() != path.GetSource().ID {
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
	pathExportSkipped(peer, path, "filter-from-source-peer")
	return nil
}

func (peer *peer) sendNotification(msg *bgp.BGPMessage) {
	select {
	case peer.fsm.notification <- msg:
	default:
	}
}

func (peer *peer) isPrefixLimit(k bgp.Family, c *oc.PrefixLimitConfig) bool {
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
			return true
		}
	}
	return false
}

func (peer *peer) updatePrefixLimitConfig(c []oc.AfiSafi) (bool, error) {
	peer.fsm.lock.RLock()
	x := peer.fsm.pConf.AfiSafis
	peer.fsm.lock.RUnlock()
	y := c
	if len(x) != len(y) {
		return false, fmt.Errorf("changing supported afi-safi is not allowed")
	}
	m := make(map[bgp.Family]oc.PrefixLimitConfig)
	for _, e := range x {
		m[e.State.Family] = e.PrefixLimit.Config
	}
	reachLimit := false
	for _, e := range y {
		if p, ok := m[e.State.Family]; !ok {
			return false, fmt.Errorf("changing supported afi-safi is not allowed")
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
			if peer.isPrefixLimit(e.State.Family, &e.PrefixLimit.Config) {
				reachLimit = true
			}
		}
	}
	peer.fsm.lock.Lock()
	peer.fsm.pConf.AfiSafis = c
	peer.fsm.lock.Unlock()
	return reachLimit, nil
}

func (peer *peer) handleUpdate(e *fsmMsg) ([]*table.Path, []bgp.Family, bool) {
	m := e.MsgData.(*bgp.BGPMessage)
	update := m.Body.(*bgp.BGPUpdate)

	treatAsWithdraw := e.handling == bgp.ERROR_HANDLING_TREAT_AS_WITHDRAW

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

	pathList := table.ProcessMessage(m, peer.peerInfo, e.timestamp, treatAsWithdraw)
	if len(pathList) > 0 {
		paths := make([]*table.Path, 0, len(pathList))
		eor := []bgp.Family{}
		for _, path := range pathList {
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
				localAS := peer.fsm.gConf.Config.As
				localASForPeer := peer.peerInfo.LocalAS
				allowOwnAS := int(peer.fsm.pConf.AsPathOptions.Config.AllowOwnAs)
				peer.fsm.lock.RUnlock()

				hasLocalAS := hasOwnASLoop(localAS, allowOwnAS, aspath)
				hasLocalASForPeer := hasOwnASLoop(localASForPeer, allowOwnAS, aspath)
				if hasLocalAS || hasLocalASForPeer {
					// FIXME: in GoBGPv3 only AS specified in a global config was checked
					// so we issue a warning, but still allow a path to be handled
					reject := hasLocalAS
					if reject {
						path.SetRejected(true)
						continue
					}

					peer.fsm.warnOnce(logOnceAllowOwnAs,
						"Got a path with Local AS in AS Path."+
							" Such paths can be accepted for now, but without allow-own-as properly configured might be rejected in future.",
						log.Fields{
							"Topic": "Peer",
							"Key":   peer.fsm.pConf.State.NeighborAddress,
							"nlri":  path.GetNlri().String(),
						})
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
				if path.GetOriginatorID() == routerId {
					peer.fsm.logger.Debug("Originator ID is mine, ignore",
						log.Fields{
							"Topic":        "Peer",
							"Key":          peer.ID(),
							"OriginatorID": routerId,
							"Data":         path,
						})
					path.SetRejected(true)
					continue
				}
			}
			paths = append(paths, path)
		}
		peer.adjRibIn.Update(pathList)
		peer.fsm.lock.RLock()
		peerAfiSafis := peer.fsm.pConf.AfiSafis
		peer.fsm.lock.RUnlock()
		for _, af := range peerAfiSafis {
			if isLimit := peer.isPrefixLimit(af.State.Family, &af.PrefixLimit.Config); isLimit {
				return nil, nil, true
			}
		}
		return paths, eor, false
	}
	return nil, nil, false
}

func (peer *peer) startFSMHandler(wg *sync.WaitGroup, callback fsmCallback) {
	handler := newFSMHandler(peer.fsm, peer.fsm.outgoingCh, wg, callback)
	peer.fsm.lock.Lock()
	peer.fsm.h = handler
	peer.fsm.lock.Unlock()
}

func (peer *peer) stopFSMHandler() {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	peer.fsm.h.ctxCancel()
}

func (peer *peer) send(paths, olds []*table.Path) {
	peer.fsm.outgoingCh.In() <- &fsmOutgoingMsg{
		Paths: paths,
	}
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
