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
	"net"
	"time"

	farm "github.com/dgryski/go-farm"
	log "github.com/sirupsen/logrus"

	"github.com/osrg/gobgp/packet/bgp"
)

const (
	GLOBAL_RIB_NAME = "global"
)

type MplsLabelRangeFullError struct{}

func (e *MplsLabelRangeFullError) Error() string {
	return "could not assign new MPLS label; need to allocate new MPLS label range"
}

func NewMplsLabelRangeFullError() *MplsLabelRangeFullError {
	return &MplsLabelRangeFullError{}
}

func ProcessMessage(m *bgp.BGPMessage, peerInfo *PeerInfo, timestamp time.Time) []*Path {
	update := m.Body.(*bgp.BGPUpdate)

	if y, f := update.IsEndOfRib(); y {
		// this message has no normal updates or withdrawals.
		return []*Path{NewEOR(f)}
	}

	adds := make([]bgp.AddrPrefixInterface, 0, len(update.NLRI))
	for _, nlri := range update.NLRI {
		adds = append(adds, nlri)
	}

	dels := make([]bgp.AddrPrefixInterface, 0, len(update.WithdrawnRoutes))
	for _, nlri := range update.WithdrawnRoutes {
		dels = append(dels, nlri)
	}

	attrs := make([]bgp.PathAttributeInterface, 0, len(update.PathAttributes))
	var reach *bgp.PathAttributeMpReachNLRI
	for _, attr := range update.PathAttributes {
		switch a := attr.(type) {
		case *bgp.PathAttributeMpReachNLRI:
			reach = a
		case *bgp.PathAttributeMpUnreachNLRI:
			l := make([]bgp.AddrPrefixInterface, 0, len(a.Value))
			for _, nlri := range a.Value {
				l = append(l, nlri)
			}
			dels = append(dels, l...)
		default:
			attrs = append(attrs, attr)
		}
	}

	listLen := len(adds) + len(dels)
	if reach != nil {
		listLen += len(reach.Value)
	}

	var hash uint32
	if len(adds) > 0 || reach != nil {
		total := bytes.NewBuffer(make([]byte, 0))
		for _, a := range attrs {
			b, _ := a.Serialize()
			total.Write(b)
		}
		hash = farm.Hash32(total.Bytes())
	}

	pathList := make([]*Path, 0, listLen)
	for _, nlri := range adds {
		p := NewPath(peerInfo, nlri, false, attrs, timestamp, false)
		p.SetHash(hash)
		pathList = append(pathList, p)
	}
	if reach != nil {
		reachAttrs := make([]bgp.PathAttributeInterface, len(attrs)+1)
		copy(reachAttrs, attrs)
		// we sort attributes when creating a bgp message from paths
		reachAttrs[len(reachAttrs)-1] = reach

		for _, nlri := range reach.Value {
			p := NewPath(peerInfo, nlri, false, reachAttrs, timestamp, false)
			p.SetHash(hash)
			pathList = append(pathList, p)
		}
	}
	for _, nlri := range dels {
		p := NewPath(peerInfo, nlri, true, []bgp.PathAttributeInterface{}, timestamp, false)
		pathList = append(pathList, p)
	}
	return pathList
}

type TableManager struct {
	Tables        map[bgp.RouteFamily]*Table
	Vrfs          map[string]*Vrf
	rfList        []bgp.RouteFamily
	mplsLabelMaps map[uint64]*Bitmap
}

func NewTableManager(rfList []bgp.RouteFamily) *TableManager {
	t := &TableManager{
		Tables: make(map[bgp.RouteFamily]*Table),
		Vrfs:   make(map[string]*Vrf),
		rfList: rfList,
	}
	for _, rf := range rfList {
		t.Tables[rf] = NewTable(rf)
	}
	return t
}

func (manager *TableManager) GetRFlist() []bgp.RouteFamily {
	return manager.rfList
}

func (manager *TableManager) EnableMplsLabelAllocation() error {
	if manager.mplsLabelMaps != nil {
		return fmt.Errorf("label allocation already enabled")
	}
	manager.mplsLabelMaps = make(map[uint64]*Bitmap)
	return nil
}

func (manager *TableManager) AllocateMplsLabelRange(start, end uint32) error {
	if manager.mplsLabelMaps == nil {
		return fmt.Errorf("label allocation not yet enabled")
	}
	log.WithFields(log.Fields{
		"Topic": "Vrf",
		"Start": start,
		"End":   end,
	}).Debug("allocate new MPLS label range")
	startEnd := uint64(start)<<32 | uint64(end)
	manager.mplsLabelMaps[startEnd] = NewBitmap(int(end - start + 1))
	return nil
}

func (manager *TableManager) assignMplsLabel() (uint32, error) {
	if manager.mplsLabelMaps == nil {
		return 0, nil
	}
	var label uint32
	for startEnd, bitmap := range manager.mplsLabelMaps {
		start := uint32(startEnd >> 32)
		end := uint32(startEnd & 0xffffffff)
		l, err := bitmap.FindandSetZeroBit()
		if err == nil && start+uint32(l) <= end {
			label = start + uint32(l)
			break
		}
	}
	if label == 0 {
		return 0, NewMplsLabelRangeFullError()
	}
	return label, nil
}

func (manager *TableManager) releaseMplsLabel(label uint32) {
	if manager.mplsLabelMaps == nil {
		return
	}
	for startEnd, bitmap := range manager.mplsLabelMaps {
		start := uint32(startEnd >> 32)
		end := uint32(startEnd & 0xffffffff)
		if start <= label && label <= end {
			bitmap.Unflag(uint(label - start))
			return
		}
	}
	return
}

func (manager *TableManager) AddVrf(name string, id uint32, rd bgp.RouteDistinguisherInterface, importRt, exportRt []bgp.ExtendedCommunityInterface, info *PeerInfo) ([]*Path, error) {
	if _, ok := manager.Vrfs[name]; ok {
		return nil, fmt.Errorf("vrf %s already exists", name)
	}
	mplsLabel, err := manager.assignMplsLabel()
	if err != nil {
		return nil, err
	}
	option := &vrfOption{
		mplsLabel: mplsLabel,
	}
	log.WithFields(log.Fields{
		"Topic":    "Vrf",
		"Key":      name,
		"Rd":       rd,
		"ImportRt": importRt,
		"ExportRt": exportRt,
		"option":   fmt.Sprintf("%+v", option),
	}).Debug("add vrf")
	manager.Vrfs[name] = &Vrf{
		Name:     name,
		Id:       id,
		Rd:       rd,
		ImportRt: importRt,
		ExportRt: exportRt,
		option:   option,
	}
	msgs := make([]*Path, 0, len(importRt))
	nexthop := "0.0.0.0"
	for _, target := range importRt {
		nlri := bgp.NewRouteTargetMembershipNLRI(info.AS, target)
		pattr := make([]bgp.PathAttributeInterface, 0, 2)
		pattr = append(pattr, bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP))
		pattr = append(pattr, bgp.NewPathAttributeMpReachNLRI(nexthop, []bgp.AddrPrefixInterface{nlri}))
		msgs = append(msgs, NewPath(info, nlri, false, pattr, time.Now(), false))
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
	log.WithFields(log.Fields{
		"Topic":    "Vrf",
		"Key":      vrf.Name,
		"Rd":       vrf.Rd,
		"ImportRt": vrf.ImportRt,
		"ExportRt": vrf.ExportRt,
		"option":   fmt.Sprintf("%+v", vrf.option),
	}).Debug("delete vrf")
	manager.releaseMplsLabel(vrf.MplsLabel())
	delete(manager.Vrfs, name)
	rtcTable := manager.Tables[bgp.RF_RTC_UC]
	msgs = append(msgs, rtcTable.deleteRTCPathsByVrf(vrf, manager.Vrfs)...)
	return msgs, nil
}

func (tm *TableManager) update(newPath *Path) *Update {
	t := tm.Tables[newPath.GetRouteFamily()]
	t.validatePath(newPath)
	dst := t.getOrCreateDest(newPath.GetNlri())
	u := dst.Calculate(newPath)
	if len(dst.knownPathList) == 0 {
		t.deleteDest(dst)
	}
	return u
}

func (manager *TableManager) GetPathListByPeer(info *PeerInfo, rf bgp.RouteFamily) []*Path {
	if t, ok := manager.Tables[rf]; ok {
		pathList := make([]*Path, 0, len(t.destinations))
		for _, dst := range t.destinations {
			for _, p := range dst.knownPathList {
				if p.GetSource().Equal(info) {
					pathList = append(pathList, p)
				}
			}
		}
		return pathList
	}
	return nil
}

func (manager *TableManager) Update(newPath *Path) []*Update {
	if newPath == nil || newPath.IsEOR() {
		return nil
	}

	// Except for a special case with EVPN, we'll have one destination.
	updates := make([]*Update, 0, 1)
	family := newPath.GetRouteFamily()
	if _, ok := manager.Tables[family]; ok {
		updates = append(updates, manager.update(newPath))

		if family == bgp.RF_EVPN {
			for _, p := range manager.handleMacMobility(newPath) {
				updates = append(updates, manager.update(p))
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
func (manager *TableManager) handleMacMobility(path *Path) []*Path {
	pathList := make([]*Path, 0)
	nlri := path.GetNlri().(*bgp.EVPNNLRI)
	if path.IsWithdraw || path.IsLocal() || nlri.RouteType != bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT {
		return nil
	}
	for _, path2 := range manager.GetPathList(GLOBAL_RIB_NAME, 0, []bgp.RouteFamily{bgp.RF_EVPN}) {
		if !path2.IsLocal() || path2.GetNlri().(*bgp.EVPNNLRI).RouteType != bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT {
			continue
		}
		f := func(p *Path) (bgp.EthernetSegmentIdentifier, net.HardwareAddr, int) {
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
			return d.ESI, d.MacAddress, seq
		}
		e1, m1, s1 := f(path)
		e2, m2, s2 := f(path2)
		if bytes.Equal(m1, m2) && !bytes.Equal(e1.Value, e2.Value) && s1 > s2 {
			pathList = append(pathList, path2.Clone(true))
		}
	}
	return pathList
}

func (manager *TableManager) tables(list ...bgp.RouteFamily) []*Table {
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

func (manager *TableManager) getDestinationCount(rfList []bgp.RouteFamily) int {
	count := 0
	for _, t := range manager.tables(rfList...) {
		count += len(t.GetDestinations())
	}
	return count
}

func (manager *TableManager) GetBestPathList(id string, as uint32, rfList []bgp.RouteFamily) []*Path {
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

func (manager *TableManager) GetBestMultiPathList(id string, rfList []bgp.RouteFamily) [][]*Path {
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

func (manager *TableManager) GetPathList(id string, as uint32, rfList []bgp.RouteFamily) []*Path {
	paths := make([]*Path, 0, manager.getDestinationCount(rfList))
	for _, t := range manager.tables(rfList...) {
		paths = append(paths, t.GetKnownPathList(id, as)...)
	}
	return paths
}

func (manager *TableManager) GetPathListWithNexthop(id string, rfList []bgp.RouteFamily, nexthop net.IP) []*Path {
	paths := make([]*Path, 0, manager.getDestinationCount(rfList))
	for _, rf := range rfList {
		if t, ok := manager.Tables[rf]; ok {
			for _, path := range t.GetKnownPathList(id, 0) {
				if path.GetNexthop().Equal(nexthop) {
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
	family := path.GetRouteFamily()
	t, ok := manager.Tables[family]
	if !ok {
		return nil
	}
	return t.GetDestination(path.GetNlri())
}

func (manager *TableManager) TableInfo(id string, as uint32, family bgp.RouteFamily) (*TableInfo, error) {
	t, ok := manager.Tables[family]
	if !ok {
		return nil, fmt.Errorf("address family %s is not configured", family)
	}
	return t.Info(id, as), nil
}
