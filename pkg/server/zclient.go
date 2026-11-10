// Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
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
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/zebra"
)

type nexthopStateKey struct {
	vrfID   uint32
	nexthop netip.Addr
}

// nexthopStateCache keeps independent state for each resolution domain.
// A metric of math.MaxUint32 means that the nexthop is unreachable.
type nexthopStateCache map[nexthopStateKey]uint32

func (m nexthopStateCache) applyToPathList(vrfID uint32, paths []*table.Path) []*table.Path {
	updated := make([]*table.Path, 0, len(paths))
	for _, path := range paths {
		if path == nil || path.IsWithdraw {
			continue
		}
		metric, ok := m[nexthopStateKey{vrfID, path.GetNexthop()}]
		if !ok {
			continue
		}
		isNexthopInvalid := metric == math.MaxUint32
		if isNexthopInvalid && path.IsNexthopInvalid {
			// Path is already correctly marked as invalid; nothing to do.
			continue
		}
		med, err := path.GetMed()
		if !isNexthopInvalid && err == nil && med == metric && !path.IsNexthopInvalid {
			// Path MED already reflects the current nexthop metric; nothing to do.
			continue
		}
		newPath := path.Clone(false)
		if isNexthopInvalid {
			newPath.IsNexthopInvalid = true
		} else {
			newPath.IsNexthopInvalid = false
			if err := newPath.SetMed(int64(metric), true); err != nil {
				continue
			}
		}
		updated = append(updated, newPath)
	}
	return updated
}

func (m nexthopStateCache) updateByNexthopUpdate(vrfID uint32, body *zebra.NexthopUpdateBody) (updated bool) {
	if len(body.Nexthops) == 0 {
		// If NEXTHOP_UPDATE message does not contain any nexthop, the given
		// nexthop is unreachable.
		if _, ok := m[nexthopStateKey{vrfID, body.Prefix.Prefix}]; !ok {
			// Zebra will send an empty NEXTHOP_UPDATE message as the fist
			// response for the NEXTHOP_REGISTER message. Here ignores it.
			return false
		}
		m[nexthopStateKey{vrfID, body.Prefix.Prefix}] = math.MaxUint32 // means unreachable
	} else {
		m[nexthopStateKey{vrfID, body.Prefix.Prefix}] = body.Metric
	}
	return true
}

func (m nexthopStateCache) filterPathToRegister(vrfID uint32, paths []*table.Path) []*table.Path {
	filteredPaths := make([]*table.Path, 0, len(paths))
	for _, path := range paths {
		// Here filters out:
		// - Nil path
		// - Withdrawn path
		// - External path (advertised from Zebra) in order avoid sending back
		// - Unspecified nexthop address
		// - Already registered nexthop
		if path == nil || path.IsWithdraw || path.IsFromExternal() {
			continue
		} else if nexthop := path.GetNexthop(); !nexthop.IsValid() || nexthop.IsUnspecified() {
			continue
		} else if _, ok := m[nexthopStateKey{vrfID, nexthop}]; ok {
			continue
		}
		filteredPaths = append(filteredPaths, path)
	}
	return filteredPaths
}

func filterOutExternalPath(paths []*table.Path) []*table.Path {
	filteredPaths := make([]*table.Path, 0, len(paths))
	for _, path := range paths {
		// Here filters out:
		// - Nil path
		// - External path (advertised from Zebra) in order avoid sending back
		// - Unreachable non-withdraw path because invalidated by Zebra
		if path == nil || path.IsFromExternal() || path.IsNexthopInvalid && !path.IsWithdraw {
			continue
		}
		filteredPaths = append(filteredPaths, path)
	}
	return filteredPaths
}

func addLabelToNexthop(path *table.Path, z *zebraClient, msgFlags *zebra.MessageFlag, nexthop *zebra.Nexthop) {
	rf := path.GetFamily()
	if rf == bgp.RF_IPv4_VPN || rf == bgp.RF_IPv6_VPN {
		z.client.SetLabelFlag(msgFlags, nexthop)
		switch rf {
		case bgp.RF_IPv4_VPN:
			for _, label := range path.GetNlri().(*bgp.LabeledVPNIPAddrPrefix).Labels.Labels {
				nexthop.LabelNum++
				nexthop.MplsLabels = append(nexthop.MplsLabels, label)
			}
		case bgp.RF_IPv6_VPN:
			for _, label := range path.GetNlri().(*bgp.LabeledVPNIPAddrPrefix).Labels.Labels {
				nexthop.LabelNum++
				nexthop.MplsLabels = append(nexthop.MplsLabels, label)
			}
		}
	}
}

func newIPRouteBody(dst []*table.Path, vrfID uint32, z *zebraClient, nexthopVrfs map[*table.Path]uint32) (body *zebra.IPRouteBody, isWithdraw bool) {
	version := z.client.Version
	paths := filterOutExternalPath(dst)
	if len(paths) == 0 {
		return nil, false
	}
	path := paths[0]

	l := strings.SplitN(path.GetPrefix(), "/", 2)
	var prefix netip.Addr
	nexthops := make([]zebra.Nexthop, 0, len(paths))
	msgFlags := zebra.MessageNexthop
	switch path.GetFamily() {
	case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
		prefix = path.GetNlri().(*bgp.IPAddrPrefix).Prefix.Addr()
	case bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN:
		prefix = path.GetNlri().(*bgp.LabeledVPNIPAddrPrefix).Prefix.Addr()
	default:
		return nil, false
	}
	for _, p := range paths {
		nexthop := zebra.Nexthop{Gate: p.GetNexthop(), VrfID: nexthopVrfs[p]}
		// link-local next-hop requires an interface index for kernel route installation
		nexthop.Ifindex = 0
		if nexthop.Gate.Is6() && nexthop.Gate.IsLinkLocalUnicast() {
			if zone := p.GetSource().Address.Zone(); zone != "" {
				if id, err := strconv.ParseUint(zone, 10, 32); err == nil {
					nexthop.Ifindex = uint32(id)
				} else if ifi, err := net.InterfaceByName(zone); err == nil {
					nexthop.Ifindex = uint32(ifi.Index)
				}
			}
		}
		if nexthop.VrfID != vrfID {
			addLabelToNexthop(p, z, &msgFlags, &nexthop)
		}
		nexthops = append(nexthops, nexthop)
	}
	plen, _ := strconv.ParseUint(l[1], 10, 8)
	med, err := path.GetMed()
	if err == nil {
		msgFlags |= zebra.MessageMetric.ToEach(version, z.client.Software)
	}
	var flags zebra.Flag
	if path.IsIBGP() {
		flags = zebra.FlagIBGP.ToEach(z.client.Version, z.client.Software) | zebra.FlagAllowRecursion
	} else if path.GetSource().MultihopTtl > 0 {
		flags = zebra.FlagAllowRecursion // 0x01
	}
	return &zebra.IPRouteBody{
		Type:    zebra.RouteBGP,
		Flags:   flags,
		Safi:    zebra.SafiUnicast,
		Message: msgFlags,
		Prefix: zebra.Prefix{
			Prefix:    prefix,
			PrefixLen: uint8(plen),
		},
		Nexthops: nexthops,
		Metric:   med,
	}, path.IsWithdraw
}

func newNexthopRegisterBody(vrfID uint32, paths []*table.Path, nexthopCache nexthopStateCache) *zebra.NexthopRegisterBody {
	paths = nexthopCache.filterPathToRegister(vrfID, paths)
	if len(paths) == 0 {
		return nil
	}
	nexthops := make([]*zebra.RegisteredNexthop, 0, len(paths))
	for _, p := range paths {
		switch p.GetFamily() {
		case bgp.RF_IPv4_UC, bgp.RF_IPv4_VPN, bgp.RF_IPv6_UC, bgp.RF_IPv6_VPN:
		default:
			continue
		}
		nexthop := p.GetNexthop()
		family := uint16(syscall.AF_INET6)
		if nexthop.Is4() {
			family = syscall.AF_INET
		}
		nexthops = append(nexthops, &zebra.RegisteredNexthop{Family: family, Prefix: nexthop})
	}

	// If no nexthop needs to be registered or unregistered, skips to send
	// message.
	if len(nexthops) == 0 {
		return nil
	}

	return &zebra.NexthopRegisterBody{
		Nexthops: nexthops,
	}
}

func newNexthopUnregisterBody(family uint16, prefix netip.Addr) *zebra.NexthopRegisterBody {
	return &zebra.NexthopRegisterBody{
		Nexthops: []*zebra.RegisteredNexthop{{
			Family: family,
			Prefix: prefix,
		}},
	}
}

func newPathFromIPRouteMessage(logger *slog.Logger, m *zebra.Message, version uint8, software zebra.Software) *table.Path {
	header := m.Header
	body := m.Body.(*zebra.IPRouteBody)
	family := body.Family(logger, version, software)
	isWithdraw := body.IsWithdraw(version, software)

	var nlri bgp.NLRI
	pattr := make([]bgp.PathAttributeInterface, 0)
	origin := bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP)
	pattr = append(pattr, origin)

	logger.Debug("create path from ip route message",
		slog.String("Topic", "Zebra"),
		slog.String("RouteType", body.Type.String()),
		slog.String("Flag", body.Flags.String(version, software)),
		slog.Any("Message", body.Message),
		slog.Int("Family", int(body.Prefix.Family)),
		slog.String("Prefix", body.Prefix.Prefix.String()),
		slog.Int("PrefixLength", int(body.Prefix.PrefixLen)),
		slog.Any("Nexthop", body.Nexthops),
		slog.Uint64("Metric", uint64(body.Metric)),
		slog.Int("Distance", int(body.Distance)),
		slog.Uint64("Mtu", uint64(body.Mtu)),
		slog.String("api", header.Command.String()),
	)

	nlri, _ = bgp.NewIPAddrPrefix(netip.MustParsePrefix(fmt.Sprintf("%s/%d", body.Prefix.Prefix.String(), body.Prefix.PrefixLen)))
	switch family {
	case bgp.RF_IPv4_UC:
		if len(body.Nexthops) > 0 {
			pa, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr(body.Nexthops[0].Gate.String()))
			pattr = append(pattr, pa)
		}
	case bgp.RF_IPv6_UC:
		if len(body.Nexthops) > 0 {
			nexthop, err := netip.ParseAddr(body.Nexthops[0].Gate.String())
			if err == nil {
				attr, _ := bgp.NewPathAttributeMpReachNLRI(family, []bgp.PathNLRI{{NLRI: nlri}}, nexthop)
				pattr = append(pattr, attr)
			}
		}
	default:
		logger.Error("unsupport address family",
			slog.String("Topic", "Zebra"),
			slog.Int("Family", int(family)),
		)
		return nil
	}

	med := bgp.NewPathAttributeMultiExitDisc(body.Metric)
	pattr = append(pattr, med)

	path := table.NewPath(family, nil, bgp.PathNLRI{NLRI: nlri}, isWithdraw, pattr, time.Now(), false)
	path.SetIsFromExternal(true)
	return path
}

type mplsLabelParameter struct {
	rangeSize     uint32
	requested     bool // a GET_LABEL_CHUNK request waits for its response
	maps          map[uint64]*table.Bitmap
	unassignedVrf []*table.Vrf // Vrfs which are not assigned MPLS label
}

// The labels that a label chunk from zebra may hold. RFC 3032 Section 2.1
// gives 0 to 3 special meanings and says "Values 4-15 are reserved.", and
// "This 20-bit field carries the actual value of the Label."
const (
	minUnreservedMplsLabel = 16
	maxMplsLabel           = 1<<20 - 1
)

type zebraClient struct {
	client       *zebra.Client
	server       *BgpServer
	nexthopCache nexthopStateCache
	cacheLock    sync.Mutex
	mplsLabel    mplsLabelParameter
	dead         chan struct{}
}

// globalRibOptions returns the route selection options of the global RIB. A
// zebra client runs in its own goroutine, so it must not read server.globalRib
// directly: StartBgp replaces that table manager. The caller must not hold the
// returned values across a management operation, because that would deadlock
// with the dispatcher.
func (z *zebraClient) globalRibOptions() (oc.RouteSelectionOptionsConfig, oc.UseMultiplePathsConfig) {
	z.server.shared.mu.RLock()
	defer z.server.shared.mu.RUnlock()

	return z.server.globalRib.SelectionOptions(), z.server.globalRib.MultiplePathsOptions()
}

// nexthopVrfID is called with the server state lock held. An imported VPN
// path resolves in its source VRF, not in every VRF that imports its RTs.
func (z *zebraClient) nexthopVrfID(path *table.Path) uint32 {
	if path == nil || path.IsEOR() {
		return zebra.DefaultVrf
	}
	if vrfID, ok := z.server.apiPathVrf[path.RootPath()]; ok {
		return vrfID
	}
	if peer, ok := z.server.neighborMap[path.GetSource().Address]; ok {
		if vrf, ok := z.server.globalRib.GetVrf(peer.fsm.pConf.ReadOnly().Config.Vrf); ok {
			return vrf.Id
		}
	}
	return zebra.DefaultVrf
}

func (z *zebraClient) nexthopVrfMap(paths []*table.Path) map[*table.Path]uint32 {
	vrfs := make(map[*table.Path]uint32, len(paths))
	for _, path := range paths {
		vrfs[path] = z.nexthopVrfID(path)
	}
	return vrfs
}

// getPathListWithNexthopUpdate reads the live RIB under the management lock.
// The lookup and its updates must be one operation: a snapshot updated later
// could otherwise resurrect a path withdrawn or replaced in between.
func (z *zebraClient) getPathListWithNexthopUpdate(vrfID uint32, body *zebra.NexthopUpdateBody) []*table.Path {
	var families []bgp.Family
	switch body.Prefix.Family {
	case syscall.AF_INET, syscall.AF_INET6:
		families = []bgp.Family{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC, bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN}
	default:
		return nil
	}
	paths := z.server.globalRib.GetPathListWithNexthop(table.GLOBAL_RIB_NAME, families, body.Prefix.Prefix)
	filtered := paths[:0]
	for _, path := range paths {
		if z.nexthopVrfID(path) == vrfID {
			filtered = append(filtered, path)
		}
	}
	return filtered
}

func (z *zebraClient) handleNexthopUpdate(vrfID uint32, body *zebra.NexthopUpdateBody) (bool, error) {
	unregister := false
	err := z.server.mgmtOperation(func() error {
		z.cacheLock.Lock()
		updated := z.nexthopCache.updateByNexthopUpdate(vrfID, body)
		z.cacheLock.Unlock()
		if !updated {
			return nil
		}
		paths := z.getPathListWithNexthopUpdate(vrfID, body)
		if len(paths) == 0 {
			z.cacheLock.Lock()
			delete(z.nexthopCache, nexthopStateKey{vrfID, body.Prefix.Prefix})
			z.cacheLock.Unlock()
			unregister = true
			return nil
		}
		z.cacheLock.Lock()
		paths = z.nexthopCache.applyToPathList(vrfID, paths)
		z.cacheLock.Unlock()
		z.server.propagateUpdate(nil, paths)
		return nil
	}, true)
	return unregister, err
}

// Recheck the current paths rather than a watcher's old snapshots. Policy may
// rewrite the nexthop; its metric is applied before global import policy just
// as for a received NHT update, without recreating a withdrawn/replaced path.
func (z *zebraClient) recheckNexthops(nexthops []nexthopStateKey) error {
	return z.server.mgmtOperation(func() error {
		seen := make(map[nexthopStateKey]bool, len(nexthops))
		for _, nexthop := range nexthops {
			if seen[nexthop] || !nexthop.nexthop.IsValid() {
				continue
			}
			seen[nexthop] = true
			family := uint8(syscall.AF_INET6)
			if nexthop.nexthop.Is4() {
				family = syscall.AF_INET
			}
			paths := z.getPathListWithNexthopUpdate(nexthop.vrfID, &zebra.NexthopUpdateBody{
				Prefix: zebra.Prefix{Family: family, Prefix: nexthop.nexthop},
			})
			z.cacheLock.Lock()
			paths = z.nexthopCache.applyToPathList(nexthop.vrfID, paths)
			z.cacheLock.Unlock()
			z.server.propagateUpdate(nil, paths)
		}
		return nil
	}, true)
}

func (z *zebraClient) registerNexthops(paths []*table.Path, vrfs map[*table.Path]uint32) {
	groups := make(map[uint32][]*table.Path)
	for _, path := range paths {
		if path != nil {
			vrfID := vrfs[path]
			groups[vrfID] = append(groups[vrfID], path)
		}
	}
	for vrfID, paths := range groups {
		z.cacheLock.Lock()
		body := newNexthopRegisterBody(vrfID, paths, z.nexthopCache)
		z.cacheLock.Unlock()
		if body != nil {
			if err := z.client.SendNexthopRegister(vrfID, body, false); err != nil {
				z.server.logger.Error("failed to send nexthop register",
					slog.String("Topic", "Zebra"), slog.String("Error", err.Error()))
			}
		}
	}
}

func (z *zebraClient) loop() {
	w, err := z.server.watch([]WatchOption{
		WatchBestPath(true),
		WatchPostUpdate(true, "", ""),
	}...)
	if err != nil {
		// the BGP server has stopped, so there is nothing left to watch.
		z.server.logger.Warn("failed to start zebra watcher",
			slog.String("Topic", "Zebra"),
			slog.String("Error", err.Error()))
		return
	}
	defer w.Stop()

	for {
		select {
		case <-z.dead:
			return
		case msg := <-z.client.Receive():
			if msg == nil {
				break
			}
			switch body := msg.Body.(type) {
			case *zebra.IPRouteBody:
				if path := newPathFromIPRouteMessage(z.server.logger, msg, z.client.Version, z.client.Software); path != nil {
					if err := z.server.addPathStream(context.Background(), "", []*table.Path{path}); err != nil {
						z.server.logger.Error("failed to add path from zebra",
							slog.String("Topic", "Zebra"),
							slog.Any("Path", path),
							slog.String("Error", err.Error()),
						)
					}
				}
			case *zebra.NexthopUpdateBody:
				unregister, err := z.handleNexthopUpdate(msg.Header.VrfID, body)
				if err == nil && unregister {
					err = z.client.SendNexthopRegister(msg.Header.VrfID, newNexthopUnregisterBody(uint16(body.Prefix.Family), body.Prefix.Prefix), true)
				}
				if err != nil {
					z.server.logger.Error("failed to update nexthop reachability",
						slog.String("Topic", "Zebra"), slog.String("Error", err.Error()))
				}
			case *zebra.GetLabelChunkBody:
				z.server.logger.Debug("zebra GetLabelChunkBody is received",
					slog.String("Topic", "Zebra"),
					slog.Int("Start", int(body.Start)),
					slog.Int("End", int(body.End)),
				)
				if err := z.addLabelChunk(body); err != nil {
					z.server.logger.Warn("ignore a label chunk from zebra",
						slog.String("Topic", "Zebra"),
						slog.String("Error", err.Error()))
					continue
				}
				for _, vrf := range z.mplsLabel.unassignedVrf {
					if err := z.assignAndSendVrfMplsLabel(vrf); err != nil {
						z.server.logger.Error("zebra failed to assign and send vrf mpls label",
							slog.String("Topic", "Zebra"),
							slog.String("Vrf", vrf.Name),
							slog.String("Error", err.Error()))
					}
				}
				z.mplsLabel.unassignedVrf = nil
			}
		case ev := <-w.Event():
			switch msg := ev.(type) {
			case *watchEventBestPath:
				_, multiplePathsOptions := z.globalRibOptions()
				pathLists := msg.MultiPathList
				if !multiplePathsOptions.Enabled {
					pathLists = make([][]*table.Path, 0, len(msg.PathList))
					for _, path := range msg.PathList {
						pathLists = append(pathLists, []*table.Path{path})
					}
				}
				for _, paths := range pathLists {
					nexthops := make([]nexthopStateKey, 0, len(paths))
					for _, path := range paths {
						if path != nil && !path.IsWithdraw {
							nexthops = append(nexthops, nexthopStateKey{msg.NexthopVrf[path], path.GetNexthop()})
						}
					}
					if len(nexthops) > 0 {
						if err := z.recheckNexthops(nexthops); err != nil {
							z.server.logger.Error("failed to recheck nexthop reachability",
								slog.String("Topic", "Zebra"), slog.String("Error", err.Error()))
						}
					}
					for vrfID := range msg.Vrf {
						if body, isWithdraw := newIPRouteBody(paths, vrfID, z, msg.NexthopVrf); body != nil {
							if err := z.client.SendIPRoute(vrfID, body, isWithdraw); err != nil {
								z.server.logger.Error("failed to send ip route",
									slog.String("Topic", "Zebra"), slog.String("Error", err.Error()))
							}
						}
					}
					z.registerNexthops(paths, msg.NexthopVrf)
				}
			case *watchEventUpdate:
				z.registerNexthops(msg.PathList, msg.NexthopVrf)
			}
		}
	}
}

func newZebraClient(s *BgpServer, url string, protos []string, version uint8, nhtEnable bool, nhtDelay uint8, mplsLabelRangeSize uint32, software zebra.Software) (*zebraClient, error) {
	l := strings.SplitN(url, ":", 2)
	if len(l) != 2 {
		return nil, fmt.Errorf("unsupported url: %s", url)
	}
	var cli *zebra.Client
	var err error
	var usingVersion uint8
	var zapivers [zebra.MaxZapiVer - zebra.MinZapiVer + 1]uint8
	zapivers[0] = version
	for elem, ver := 1, zebra.MinZapiVer; elem < len(zapivers) && ver <= zebra.MaxZapiVer; elem++ {
		if version == ver && ver < zebra.MaxZapiVer {
			ver++
		}
		zapivers[elem] = ver
		ver++
	}
	for elem, ver := range zapivers {
		cli, err = zebra.NewClient(s.logger, l[0], l[1], zebra.RouteBGP, ver, software, mplsLabelRangeSize)
		if cli != nil && err == nil {
			usingVersion = ver
			break
		}
		// Another version helps when zebra closes the connection on a
		// version it does not support, not when zebra does not answer.
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil, err
		}
		// Retry with another Zebra message version
		s.logger.Warn("cannot connect to Zebra with message version",
			slog.String("Topic", "Zebra"),
			slog.Int("Version", int(ver)))
		if elem < len(zapivers)-1 {
			s.logger.Warn("going to retry another version",
				slog.String("Topic", "Zebra"),
				slog.Int("Version", int(zapivers[elem+1])))
		}
	}
	if cli == nil || err != nil {
		return nil, err
	}
	s.logger.Info("success to connect to Zebra",
		slog.String("Topic", "Zebra"),
		slog.Int("Version", int(usingVersion)),
	)

	// Note: HELLO/ROUTER_ID_ADD messages are automatically sent to negotiate
	// the Zebra message version in zebra.NewClient().
	// cli.SendHello()
	// cli.SendRouterIDAdd()
	cli.SendInterfaceAdd()
	for _, typ := range protos {
		t, err := zebra.RouteTypeFromString(typ, version, software)
		if err != nil {
			return nil, err
		}
		cli.SendRedistribute(t, zebra.DefaultVrf)
	}
	w := &zebraClient{
		client:       cli,
		server:       s,
		nexthopCache: make(nexthopStateCache),
		mplsLabel: mplsLabelParameter{
			rangeSize: mplsLabelRangeSize,
			// Set before the loop starts, as the loop reads it.
			requested: mplsLabelRangeSize > 0 && cli.SupportMpls(),
			maps:      make(map[uint64]*table.Bitmap),
		},
		dead: make(chan struct{}),
	}
	go w.loop()
	if mplsLabelRangeSize > 0 && cli.SupportMpls() {
		if err = cli.SendGetLabelChunk(&zebra.GetLabelChunkBody{ChunkSize: mplsLabelRangeSize}); err != nil {
			return nil, err
		}
	}
	return w, nil
}

// addLabelChunk takes the label chunk that zebra sent in response to our
// GET_LABEL_CHUNK request. gobgpd sends one request only, so a chunk that
// comes without a request is not used. The size of the bitmap comes from the
// chunk, so the chunk must hold only valid labels.
func (z *zebraClient) addLabelChunk(body *zebra.GetLabelChunkBody) error {
	if !z.mplsLabel.requested {
		return fmt.Errorf("label chunk %d-%d was not requested", body.Start, body.End)
	}
	if body.Start > body.End || body.Start < minUnreservedMplsLabel || body.End > maxMplsLabel {
		return fmt.Errorf("invalid label chunk %d-%d", body.Start, body.End)
	}
	z.mplsLabel.requested = false
	startEnd := uint64(body.Start)<<32 | uint64(body.End)
	z.mplsLabel.maps[startEnd] = table.NewBitmap(int(body.End - body.Start + 1))
	return nil
}

func (z *zebraClient) assignMplsLabel() (uint32, error) {
	if z.mplsLabel.maps == nil {
		return 0, nil
	}
	var label uint32
	for startEnd, bitmap := range z.mplsLabel.maps {
		start := uint32(startEnd >> 32)
		end := uint32(startEnd & 0xffffffff)
		l, err := bitmap.FindandSetZeroBit()
		if err == nil && start+uint32(l) <= end {
			label = start + uint32(l)
			break
		}
	}
	if label == 0 {
		return 0, fmt.Errorf("failed to assign new MPLS label")
	}
	return label, nil
}

func (z *zebraClient) assignAndSendVrfMplsLabel(vrf *table.Vrf) error {
	var err error
	if vrf.MplsLabel, err = z.assignMplsLabel(); vrf.MplsLabel > 0 { // success
		if err = z.client.SendVrfLabel(vrf.MplsLabel, vrf.Id); err != nil {
			return err
		}
	} else if vrf.MplsLabel == 0 { // GetLabelChunk is not performed
		z.mplsLabel.unassignedVrf = append(z.mplsLabel.unassignedVrf, vrf)
	}
	return err
}

func (z *zebraClient) releaseMplsLabel(label uint32) {
	if z.mplsLabel.maps == nil {
		return
	}
	for startEnd, bitmap := range z.mplsLabel.maps {
		start := uint32(startEnd >> 32)
		end := uint32(startEnd & 0xffffffff)
		if start <= label && label <= end {
			bitmap.Unflag(uint(label - start))
			return
		}
	}
}
