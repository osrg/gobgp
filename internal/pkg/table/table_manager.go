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

package table

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/dgryski/go-farm"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

const (
	GLOBAL_RIB_NAME = "global"
)

func ProcessMessage(m *bgp.BGPMessage, peerInfo *PeerInfo, timestamp time.Time, treatAsWithdraw bool) []*Path {
	update := m.Body.(*bgp.BGPUpdate)

	if y, f := update.IsEndOfRib(); y {
		// this message has no normal updates or withdrawals.
		return []*Path{NewEOR(f)}
	}

	attrs := make([]bgp.PathAttributeInterface, 0, len(update.PathAttributes))
	var reach *bgp.PathAttributeMpReachNLRI
	var unreach *bgp.PathAttributeMpUnreachNLRI
	for _, attr := range update.PathAttributes {
		switch a := attr.(type) {
		case *bgp.PathAttributeMpReachNLRI:
			reach = a
		case *bgp.PathAttributeMpUnreachNLRI:
			unreach = a
		default:
			// update msg may not contain next_hop (type:3) in attr
			// due to it uses MpReachNLRI and it also has empty update.NLRI
			attrs = append(attrs, attr)
		}
	}

	if treatAsWithdraw {
		attrs = []bgp.PathAttributeInterface{}
	}

	var hash uint64
	if len(attrs) != 0 {
		total := bytes.NewBuffer(make([]byte, 0))
		for _, a := range attrs {
			b, _ := a.Serialize()
			total.Write(b)
		}
		hash = farm.Hash64(total.Bytes())
	}

	listLen := len(update.NLRI) + len(update.WithdrawnRoutes)
	if reach != nil {
		listLen += len(reach.Value)
	}
	if unreach != nil {
		listLen += len(unreach.Value)
	}

	pathList := make([]*Path, 0, listLen)

	for _, nlri := range update.NLRI {
		p := NewPath(bgp.RF_IPv4_UC, peerInfo, bgp.PathNLRI{NLRI: nlri.NLRI}, treatAsWithdraw, attrs, timestamp, false)
		p.remoteID = nlri.ID
		p.SetHash(hash)
		pathList = append(pathList, p)
	}

	if reach != nil {
		nexthop := reach.Nexthop
		family := bgp.NewFamily(reach.AFI, reach.SAFI)

		for _, nlri := range reach.Value {
			// when build path from reach
			// reachAttrs might not contain next_hop if `attrs` does not have one
			// this happens when a MP peer send update to gobgp
			// However nlri is always populated because how we build the path
			// path.info{nlri: nlri}
			// Compute a new attribute array for each path with one NLRI to make serialization
			// of path attrs faster
			reachAttrs := []bgp.PathAttributeInterface{}
			if !treatAsWithdraw {
				nlriAttr, _ := bgp.NewPathAttributeMpReachNLRI(family, []bgp.PathNLRI{nlri}, nexthop)
				reachAttrs = makeAttributeList(attrs, nlriAttr)
			}

			p := NewPath(family, peerInfo, bgp.PathNLRI{NLRI: nlri.NLRI}, treatAsWithdraw, reachAttrs, timestamp, false)
			p.remoteID = nlri.ID
			p.SetHash(hash)
			pathList = append(pathList, p)
		}
	}

	for _, nlri := range update.WithdrawnRoutes {
		p := NewPath(bgp.RF_IPv4_UC, peerInfo, bgp.PathNLRI{NLRI: nlri.NLRI}, true, []bgp.PathAttributeInterface{}, timestamp, false)
		p.remoteID = nlri.ID
		pathList = append(pathList, p)
	}

	if unreach != nil {
		family := bgp.NewFamily(unreach.AFI, unreach.SAFI)

		for _, nlri := range unreach.Value {
			p := NewPath(family, peerInfo, bgp.PathNLRI{NLRI: nlri.NLRI}, true, []bgp.PathAttributeInterface{}, timestamp, false)
			p.remoteID = nlri.ID
			pathList = append(pathList, p)
		}
	}

	return pathList
}

func makeAttributeList(
	attrs []bgp.PathAttributeInterface, reach *bgp.PathAttributeMpReachNLRI,
) []bgp.PathAttributeInterface {
	reachAttrs := make([]bgp.PathAttributeInterface, len(attrs)+1)
	copy(reachAttrs, attrs)
	// we sort attributes when creating a bgp message from paths
	reachAttrs[len(reachAttrs)-1] = reach
	return reachAttrs
}

type TableManager struct {
	Tables map[bgp.Family]*Table
	Vrfs   map[string]*Vrf
	rfList []bgp.Family
	logger *slog.Logger
}

func NewTableManager(logger *slog.Logger, rfList []bgp.Family) *TableManager {
	t := &TableManager{
		Tables: make(map[bgp.Family]*Table),
		Vrfs:   make(map[string]*Vrf),
		rfList: rfList,
		logger: logger,
	}
	for _, rf := range rfList {
		t.Tables[rf] = NewTable(logger, rf)
	}
	return t
}

func (manager *TableManager) GetRFlist() []bgp.Family {
	return manager.rfList
}

func (manager *TableManager) AddVrf(name string, id uint32, rd bgp.RouteDistinguisherInterface, importRt, exportRt []bgp.ExtendedCommunityInterface, info *PeerInfo) ([]*Path, error) {
	if _, ok := manager.Vrfs[name]; ok {
		return nil, fmt.Errorf("vrf %s already exists", name)
	}
	rtMap, err := newRouteTargetMap(importRt)
	if err != nil {
		return nil, err
	}
	manager.logger.Debug("add vrf",
		slog.String("Topic", "Vrf"),
		slog.String("Key", name),
		slog.String("Rd", rd.String()),
		slog.Any("ImportRt", rtMap.ToSlice()),
		slog.Any("ExportRt", exportRt),
	)
	manager.Vrfs[name] = &Vrf{
		Name:     name,
		Id:       id,
		Rd:       rd,
		ImportRt: rtMap,
		ExportRt: exportRt,
	}
	msgs := make([]*Path, 0, len(importRt))
	nexthop := netip.IPv4Unspecified()
	for _, target := range importRt {
		nlri := bgp.NewRouteTargetMembershipNLRI(info.AS, target)
		pattr := make([]bgp.PathAttributeInterface, 0, 2)
		pattr = append(pattr, bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP))
		attr, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_RTC_UC, []bgp.PathNLRI{{NLRI: nlri}}, nexthop)
		pattr = append(pattr, attr)
		msgs = append(msgs, NewPath(bgp.RF_RTC_UC, info, bgp.PathNLRI{NLRI: nlri}, false, pattr, time.Now(), false))
	}
	return msgs, nil
}

func (manager *TableManager) DeleteVrf(name string) ([]*Path, error) {
	if _, ok := manager.Vrfs[name]; !ok {
		return nil, fmt.Errorf("vrf %s not found", name)
	}
	msgs := make([]*Path, 0)
	vrf := manager.Vrfs[name]
	for _, t := range manager.Tables {
		msgs = append(msgs, t.deletePathsByVrf(vrf)...)
	}
	manager.logger.Debug("delete vrf",
		slog.String("Topic", "Vrf"),
		slog.String("Key", vrf.Name),
		slog.String("Rd", vrf.Rd.String()),
		slog.Any("ImportRt", vrf.ImportRt.ToSlice()),
		slog.Any("ExportRt", vrf.ExportRt),
		slog.Any("MplsLabel", vrf.MplsLabel),
	)
	delete(manager.Vrfs, name)
	rtcTable := manager.Tables[bgp.RF_RTC_UC]
	msgs = append(msgs, rtcTable.deleteRTCPathsByVrf(vrf, manager.Vrfs)...)
	return msgs, nil
}

func (manager *TableManager) Update(newPath *Path) []*Update {
	if newPath == nil || newPath.IsEOR() {
		return nil
	}

	// Except for a special case with EVPN, we'll have one destination.
	updates := make([]*Update, 0, 1)
	family := newPath.GetFamily()
	if table, ok := manager.Tables[family]; ok {
		updates = append(updates, table.update(newPath))

		if family == bgp.RF_EVPN {
			for _, p := range manager.handleMacMobility(newPath) {
				updates = append(updates, table.update(p))
			}
		}
	}
	return updates
}

// EVPN MAC MOBILITY HANDLING
//
// RFC7432 15. MAC Mobility
//
// A PE receiving a MAC/IP Advertisement route for a MAC address with a
// different Ethernet segment identifier and a higher sequence number
// than that which it had previously advertised withdraws its MAC/IP
// Advertisement route.
// ......
// If the PE is the originator of the MAC route and it receives the same
// MAC address with the same sequence number that it generated, it will
// compare its own IP address with the IP address of the remote PE and
// will select the lowest IP.  If its own route is not the best one, it
// will withdraw the route.
func (manager *TableManager) handleMacMobility(path *Path) []*Path {
	pathList := make([]*Path, 0)
	nlri := path.GetNlri().(*bgp.EVPNNLRI)
	if path.IsWithdraw || path.IsLocal() || nlri.RouteType != bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT {
		return nil
	}

	f := func(p *Path) (bgp.EthernetSegmentIdentifier, uint32, net.HardwareAddr, int, netip.Addr) {
		nlri := p.GetNlri().(*bgp.EVPNNLRI)
		d := nlri.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute)
		ecs := p.GetExtCommunities()
		seq := -1
		for _, ec := range ecs {
			if t, st := ec.GetTypes(); t == bgp.EC_TYPE_EVPN && st == bgp.EC_SUBTYPE_MAC_MOBILITY {
				seq = int(ec.(*bgp.MacMobilityExtended).Sequence)
				break
			}
		}
		return d.ESI, d.ETag, d.MacAddress, seq, p.GetSource().Address
	}
	e1, et1, m1, s1, i1 := f(path)

	// Extract the route targets to scope the lookup to the MAC-VRF with the MAC address.
	// This will help large EVPN instances where a single MAC is present in a lot of MAC-VRFs (e.g.
	// an anycast router).
	// A route may have multiple route targets, to target multiple MAC-VRFs (e.g. in both an L2VNI
	// and L3VNI in the VXLAN case).
	var paths []*Path
	for _, ec := range path.GetRouteTargets() {
		paths = append(paths, manager.GetPathListWithMac(GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_EVPN}, ec, m1)...)
	}

	for _, path2 := range paths {
		if !path2.IsLocal() || path2.GetNlri().(*bgp.EVPNNLRI).RouteType != bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT {
			continue
		}
		e2, et2, m2, s2, i2 := f(path2)
		if et1 == et2 && bytes.Equal(m1, m2) && !bytes.Equal(e1.Value, e2.Value) {
			if s1 > s2 || s1 == s2 && i1.Compare(i2) < 0 {
				pathList = append(pathList, path2.Clone(true))
			}
		}
	}
	return pathList
}

func (manager *TableManager) tables(list ...bgp.Family) []*Table {
	l := make([]*Table, 0, len(manager.Tables))
	if len(list) == 0 {
		for _, v := range manager.Tables {
			l = append(l, v)
		}
		return l
	}
	for _, f := range list {
		if t, ok := manager.Tables[f]; ok {
			l = append(l, t)
		}
	}
	return l
}

func (manager *TableManager) getDestinationCount(rfList []bgp.Family) int {
	count := 0
	for _, t := range manager.tables(rfList...) {
		count += len(t.GetDestinations())
	}
	return count
}

func (manager *TableManager) GetBestPathList(id string, as uint32, rfList []bgp.Family) []*Path {
	if SelectionOptions.DisableBestPathSelection {
		// Note: If best path selection disabled, there is no best path.
		return nil
	}
	paths := make([]*Path, 0, manager.getDestinationCount(rfList))
	for _, t := range manager.tables(rfList...) {
		paths = append(paths, t.Bests(id, as)...)
	}
	return paths
}

func (manager *TableManager) GetBestMultiPathList(id string, rfList []bgp.Family) [][]*Path {
	if !UseMultiplePaths.Enabled || SelectionOptions.DisableBestPathSelection {
		// Note: If multi path not enabled or best path selection disabled,
		// there is no best multi path.
		return nil
	}
	paths := make([][]*Path, 0, manager.getDestinationCount(rfList))
	for _, t := range manager.tables(rfList...) {
		paths = append(paths, t.MultiBests(id)...)
	}
	return paths
}

func (manager *TableManager) GetPathList(id string, as uint32, rfList []bgp.Family) []*Path {
	paths := make([]*Path, 0, manager.getDestinationCount(rfList))
	for _, t := range manager.tables(rfList...) {
		paths = append(paths, t.GetKnownPathList(id, as)...)
	}
	return paths
}

func (manager *TableManager) GetPathListWithMac(id string, as uint32, rfList []bgp.Family, rt bgp.ExtendedCommunityInterface, mac net.HardwareAddr) []*Path {
	var paths []*Path
	for _, t := range manager.tables(rfList...) {
		paths = append(paths, t.GetKnownPathListWithMac(id, as, rt, mac, false)...)
	}
	return paths
}

func (manager *TableManager) GetPathListWithNexthop(id string, rfList []bgp.Family, nexthop netip.Addr) []*Path {
	paths := make([]*Path, 0, manager.getDestinationCount(rfList))
	for _, rf := range rfList {
		if t, ok := manager.Tables[rf]; ok {
			for _, path := range t.GetKnownPathList(id, 0) {
				if path.GetNexthop() == nexthop {
					paths = append(paths, path)
				}
			}
		}
	}
	return paths
}

func (manager *TableManager) GetPathListWithSource(id string, rfList []bgp.Family, source *PeerInfo) []*Path {
	paths := make([]*Path, 0, manager.getDestinationCount(rfList))
	for _, rf := range rfList {
		if t, ok := manager.Tables[rf]; ok {
			for _, path := range t.GetKnownPathList(id, 0) {
				if path.GetSource().Equal(source) {
					paths = append(paths, path)
				}
			}
		}
	}
	return paths
}

func (manager *TableManager) GetDestination(path *Path) *Destination {
	if path == nil {
		return nil
	}
	family := path.GetFamily()
	t, ok := manager.Tables[family]
	if !ok {
		return nil
	}
	return t.GetDestination(path.GetNlri())
}
