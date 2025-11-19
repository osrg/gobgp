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
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
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
	pg.members[c.State.NeighborAddress.String()] = c
}

func (pg *peerGroup) DeleteMember(c oc.Neighbor) {
	delete(pg.members, c.State.NeighborAddress.String())
}

func (pg *peerGroup) AddDynamicNeighbor(c *oc.DynamicNeighbor) {
	pg.dynamicNeighbors[c.Config.Prefix.String()] = c
}

func (pg *peerGroup) DeleteDynamicNeighbor(prefix string) {
	delete(pg.dynamicNeighbors, prefix)
}

func newDynamicPeer(g *oc.Global, neighborAddress string, pg *oc.PeerGroup, loc *table.TableManager, policy *table.RoutingPolicy, logger *slog.Logger) *peer {
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
			slog.String("Topic", "Peer"),
			slog.String("Key", neighborAddress),
			slog.String("Error", err.Error()))
		return nil
	}
	if err := oc.SetDefaultNeighborConfigValues(&conf, pg, g); err != nil {
		logger.Debug("Can't set default config",
			slog.String("Topic", "Peer"),
			slog.String("Key", neighborAddress),
			slog.String("Error", err.Error()))
		return nil
	}

	return newPeer(g, &conf, bgp.BGP_FSM_ACTIVE, loc, policy, logger)
}

type peer struct {
	tableId           string
	fsm               *fsm
	adjRibIn          *table.AdjRib
	policy            *table.RoutingPolicy
	localRib          *table.TableManager
	peerInfo          *table.PeerInfo
	prefixLimitWarned map[bgp.Family]bool
	// map of path local identifiers sent for that prefix
	sentPaths           map[table.PathDestLocalKey]map[uint32]struct{}
	sendMaxPathFiltered map[table.PathLocalKey]struct{}
	llgrEndChs          []chan struct{}
	longLivedRunning    bool
}

func newPeer(g *oc.Global, conf *oc.Neighbor, state bgp.FSMState, loc *table.TableManager, policy *table.RoutingPolicy, logger *slog.Logger) *peer {
	peer := &peer{
		localRib:            loc,
		policy:              policy,
		fsm:                 newFSM(g, conf, state, logger.With(slog.String("Topic", "Peer"), slog.String("Key", conf.State.NeighborAddress.String()))),
		prefixLimitWarned:   make(map[bgp.Family]bool),
		sentPaths:           make(map[table.PathDestLocalKey]map[uint32]struct{}),
		sendMaxPathFiltered: make(map[table.PathLocalKey]struct{}),
	}
	if peer.isRouteServerClient() {
		peer.tableId = conf.State.NeighborAddress.String()
	} else {
		peer.tableId = table.GLOBAL_RIB_NAME
	}
	rfs, _ := oc.AfiSafis(conf.AfiSafis).ToRfList()
	peer.adjRibIn = table.NewAdjRib(logger, rfs)
	return peer
}

func (peer *peer) AdminState() adminState {
	return peer.fsm.adminState.Load()
}

func (peer *peer) State() bgp.FSMState {
	return peer.fsm.state.Load()
}

func (peer *peer) AS() uint32 {
	peer.fsm.lock.Lock()
	defer peer.fsm.lock.Unlock()
	return peer.fsm.pConf.State.PeerAs
}

func (peer *peer) ID() string {
	peer.fsm.lock.Lock()
	defer peer.fsm.lock.Unlock()
	return peer.fsm.pConf.State.NeighborAddress.String()
}

func (peer *peer) routerID() netip.Addr {
	peer.fsm.lock.Lock()
	defer peer.fsm.lock.Unlock()
	if peer.fsm.pConf.State.RemoteRouterId.IsValid() {
		return peer.fsm.pConf.State.RemoteRouterId
	}
	return netip.Addr{}
}

func (peer *peer) TableID() string {
	return peer.tableId
}

func (peer *peer) allowAsPathLoopLocal() bool {
	peer.fsm.lock.Lock()
	defer peer.fsm.lock.Unlock()
	return peer.fsm.pConf.AsPathOptions.Config.AllowAsPathLoopLocal
}

func (peer *peer) isIBGPPeer() bool {
	peer.fsm.lock.Lock()
	defer peer.fsm.lock.Unlock()
	return peer.fsm.pConf.State.PeerType == oc.PEER_TYPE_INTERNAL
}

func (peer *peer) isRouteServerClient() bool {
	peer.fsm.lock.Lock()
	defer peer.fsm.lock.Unlock()
	return peer.fsm.pConf.RouteServer.Config.RouteServerClient
}

func (peer *peer) isSecondaryRouteEnabled() bool {
	peer.fsm.lock.Lock()
	defer peer.fsm.lock.Unlock()
	return peer.fsm.pConf.RouteServer.Config.RouteServerClient && peer.fsm.pConf.RouteServer.Config.SecondaryRoute
}

func (peer *peer) isRouteReflectorClient() bool {
	peer.fsm.lock.Lock()
	defer peer.fsm.lock.Unlock()
	return peer.fsm.pConf.RouteReflector.Config.RouteReflectorClient
}

func (peer *peer) isGracefulRestartEnabled() bool {
	peer.fsm.lock.Lock()
	defer peer.fsm.lock.Unlock()
	return peer.fsm.pConf.GracefulRestart.State.Enabled
}

func (peer *peer) getAddPathMode(family bgp.Family) (bool, bgp.BGPAddPathMode) {
	if mode, y := peer.fsm.familyMap.Load().(map[bgp.Family]bgp.BGPAddPathMode)[family]; y {
		return true, mode
	}
	return false, 0
}

func (peer *peer) isAddPathReceiveEnabled(family bgp.Family) bool {
	enabled, mode := peer.getAddPathMode(family)
	return enabled && mode&bgp.BGP_ADD_PATH_RECEIVE > 0
}

func (peer *peer) isAddPathSendEnabled(family bgp.Family) bool {
	enabled, mode := peer.getAddPathMode(family)
	return enabled && mode&bgp.BGP_ADD_PATH_SEND > 0
}

func (peer *peer) IsFamilyEnabled(family bgp.Family) bool {
	y, _ := peer.getAddPathMode(family)
	return y
}

func (peer *peer) getAddPathSendMax(family bgp.Family) uint8 {
	peer.fsm.lock.Lock()
	defer peer.fsm.lock.Unlock()
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
	_, pathExist := peer.sentPaths[destLocalKey][path.LocalID()]
	return pathExist
}

func (peer *peer) isDynamicNeighbor() bool {
	peer.fsm.lock.Lock()
	defer peer.fsm.lock.Unlock()
	return !peer.fsm.pConf.Config.NeighborAddress.IsValid() && peer.fsm.pConf.Config.NeighborInterface == ""
}

func (peer *peer) getRtcEORWait() bool {
	v := peer.fsm.rtcEORWait.Load()
	peer.fsm.logger.Debug("Get rtcEORWait", slog.Bool("Data", v))
	return v
}

func (peer *peer) setRtcEORWait(waiting bool) {
	peer.fsm.rtcEORWait.Store(waiting)
	peer.fsm.logger.Debug("Set rtcEORWait", slog.Bool("Data", waiting))
}

func (peer *peer) recvedAllEOR() bool {
	peer.fsm.lock.Lock()
	defer peer.fsm.lock.Unlock()
	for _, a := range peer.fsm.pConf.AfiSafis {
		if s := a.MpGracefulRestart.State; s.Enabled && s.Received && !s.EndOfRibReceived {
			return false
		}
	}
	return true
}

func (peer *peer) configuredRFlist() []bgp.Family {
	peer.fsm.lock.Lock()
	defer peer.fsm.lock.Unlock()
	rfs, _ := oc.AfiSafis(peer.fsm.pConf.AfiSafis).ToRfList()
	return rfs
}

func (peer *peer) negotiatedRFList() []bgp.Family {
	rfmap := peer.fsm.familyMap.Load().(map[bgp.Family]bgp.BGPAddPathMode)

	l := make([]bgp.Family, 0, len(rfmap))
	for family := range rfmap {
		l = append(l, family)
	}
	return l
}

func (peer *peer) toGlobalFamilies(families []bgp.Family) []bgp.Family {
	peer.fsm.lock.Lock()
	defer peer.fsm.lock.Unlock()
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
					slog.String("Family", f.String()),
					slog.String("VRF", peer.fsm.pConf.Config.Vrf))
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
	peer.fsm.lock.Lock()
	list := []bgp.Family{}
	for _, a := range peer.fsm.pConf.AfiSafis {
		if s := a.MpGracefulRestart.State; s.Enabled && s.Received {
			list = append(list, a.State.Family)
		}
	}
	peer.fsm.lock.Unlock()
	return classifyFamilies(peer.configuredRFlist(), list)
}

func (peer *peer) llgrFamilies() ([]bgp.Family, []bgp.Family) {
	peer.fsm.lock.Lock()
	list := []bgp.Family{}
	for _, a := range peer.fsm.pConf.AfiSafis {
		if a.LongLivedGracefulRestart.State.Enabled {
			list = append(list, a.State.Family)
		}
	}
	peer.fsm.lock.Unlock()
	return classifyFamilies(peer.configuredRFlist(), list)
}

func (peer *peer) isLLGREnabledFamily(family bgp.Family) bool {
	peer.fsm.lock.Lock()
	llgrEnabled := peer.fsm.pConf.GracefulRestart.Config.LongLivedEnabled
	peer.fsm.lock.Unlock()
	if !llgrEnabled {
		return false
	}
	fs, _ := peer.llgrFamilies()
	return slices.Contains(fs, family)
}

func (peer *peer) llgrRestartTime(family bgp.Family) uint32 {
	peer.fsm.lock.Lock()
	defer peer.fsm.lock.Unlock()
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
	peer.fsm.logger.Debug("From me, ignore",
		slog.String("Topic", "Peer"),
		slog.String("Key", peer.ID()),
		slog.String("Data", path.String()))
	return nil
}

func (peer *peer) sendNotification(msg *bgp.BGPMessage) {
	nonblockSendChannel(peer.fsm.notification, msg)
}

func (peer *peer) isPrefixLimit(k bgp.Family, c *oc.PrefixLimitConfig) bool {
	if maxPrefixes := int(c.MaxPrefixes); maxPrefixes > 0 {
		count := peer.adjRibIn.Count([]bgp.Family{k})
		pct := int(c.ShutdownThresholdPct)
		if pct > 0 && !peer.prefixLimitWarned[k] && count > maxPrefixes*pct/100 {
			peer.prefixLimitWarned[k] = true
			peer.fsm.logger.Warn("prefix limit reached",
				slog.String("Family", k.String()),
				slog.Int("Pct", pct))
		}
		if count > maxPrefixes {
			peer.fsm.logger.Warn("prefix limit reached", slog.String("Family", k.String()))
			return true
		}
	}
	return false
}

func (peer *peer) updatePrefixLimitConfig(c []oc.AfiSafi) (bool, error) {
	peer.fsm.lock.Lock()
	x := peer.fsm.pConf.AfiSafis
	peer.fsm.lock.Unlock()
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
				slog.String("AddressFamily", string(e.Config.AfiSafiName)),
				slog.Uint64("OldMaxPrefixes", uint64(p.MaxPrefixes)),
				slog.Uint64("NewMaxPrefixes", uint64(e.PrefixLimit.Config.MaxPrefixes)),
				slog.Int("OldShutdownThresholdPct", int(p.ShutdownThresholdPct)),
				slog.Int("NewShutdownThresholdPct", int(e.PrefixLimit.Config.ShutdownThresholdPct)))

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

	peer.fsm.logger.Debug("received update",
		slog.Any("nlri", update.NLRI),
		slog.Any("withdrawals", update.WithdrawnRoutes),
		slog.Any("path_attributes", update.PathAttributes))

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
				peer.fsm.logger.Debug("EOR received", slog.String("AddressFamily", family.String()))
				eor = append(eor, family)
				continue
			}
			// RFC4271 9.1.2 Phase 2: Route Selection
			//
			// If the AS_PATH attribute of a BGP route contains an AS loop, the BGP
			// route should be excluded from the Phase 2 decision function.
			if aspath := path.GetAsPath(); aspath != nil {
				peer.fsm.lock.Lock()
				localAS := peer.fsm.pConf.Config.LocalAs
				allowOwnAS := int(peer.fsm.pConf.AsPathOptions.Config.AllowOwnAs)
				peer.fsm.lock.Unlock()
				if hasOwnASLoop(localAS, allowOwnAS, aspath) {
					path.SetRejected(true)
					continue
				}
			}
			// RFC4456 8. Avoiding Routing Information Loops
			// A router that recognizes the ORIGINATOR_ID attribute SHOULD
			// ignore a route received with its BGP Identifier as the ORIGINATOR_ID.
			isIBGPPeer := peer.isIBGPPeer()
			peer.fsm.lock.Lock()
			routerId := peer.fsm.gConf.Config.RouterId
			peer.fsm.lock.Unlock()
			if isIBGPPeer {
				if path.GetOriginatorID() == routerId {
					peer.fsm.logger.Debug("Originator ID is mine, ignore",
						slog.String("OriginatorID", path.GetOriginatorID().String()),
						slog.String("Data", path.String()))

					path.SetRejected(true)
					continue
				}
			}
			paths = append(paths, path)
		}
		peer.adjRibIn.Update(pathList)
		peer.fsm.lock.Lock()
		peerAfiSafis := peer.fsm.pConf.AfiSafis
		peer.fsm.lock.Unlock()
		for _, af := range peerAfiSafis {
			if isLimit := peer.isPrefixLimit(af.State.Family, &af.PrefixLimit.Config); isLimit {
				return nil, nil, true
			}
		}
		return paths, eor, false
	}
	return nil, nil, false
}

func (peer *peer) startFSM(wg *sync.WaitGroup, callback fsmCallback) {
	peer.fsm.start(wg, callback)
}

func (peer *peer) stopFSM() {
	peer.fsm.stop()
}

func (peer *peer) StaleAll(rfList []bgp.Family) []*table.Path {
	return peer.adjRibIn.StaleAll(rfList)
}

func (peer *peer) PassConn(conn net.Conn) {
	select {
	case peer.fsm.connCh <- conn:
	default:
		conn.Close()
		peer.fsm.logger.Warn("accepted conn is closed to avoid be blocked")
	}
}

func (peer *peer) DropAll(rfList []bgp.Family) []*table.Path {
	return peer.adjRibIn.Drop(rfList)
}
