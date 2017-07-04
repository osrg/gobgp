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

	"github.com/osrg/gobgp/packet/bgp"
	log "github.com/sirupsen/logrus"
)

const (
	GLOBAL_RIB_NAME = "global"
)

func nlri2Path(m *bgp.BGPMessage, p *PeerInfo, now time.Time) []*Path {
	updateMsg := m.Body.(*bgp.BGPUpdate)
	pathAttributes := updateMsg.PathAttributes
	pathList := make([]*Path, 0)
	for _, nlri := range updateMsg.NLRI {
		path := NewPath(p, nlri, false, pathAttributes, now, false)
		pathList = append(pathList, path)
	}
	return pathList
}

func withdraw2Path(m *bgp.BGPMessage, p *PeerInfo, now time.Time) []*Path {
	updateMsg := m.Body.(*bgp.BGPUpdate)
	pathAttributes := updateMsg.PathAttributes
	pathList := make([]*Path, 0)
	for _, nlri := range updateMsg.WithdrawnRoutes {
		path := NewPath(p, nlri, true, pathAttributes, now, false)
		pathList = append(pathList, path)
	}
	return pathList
}

func mpreachNlri2Path(m *bgp.BGPMessage, p *PeerInfo, now time.Time) []*Path {
	updateMsg := m.Body.(*bgp.BGPUpdate)
	pathAttributes := updateMsg.PathAttributes
	attrList := []*bgp.PathAttributeMpReachNLRI{}

	for _, attr := range pathAttributes {
		a, ok := attr.(*bgp.PathAttributeMpReachNLRI)
		if ok {
			attrList = append(attrList, a)
			break
		}
	}
	pathList := make([]*Path, 0)

	for _, mp := range attrList {
		nlri_info := mp.Value
		for _, nlri := range nlri_info {
			path := NewPath(p, nlri, false, pathAttributes, now, false)
			pathList = append(pathList, path)
		}
	}
	return pathList
}

func mpunreachNlri2Path(m *bgp.BGPMessage, p *PeerInfo, now time.Time) []*Path {
	updateMsg := m.Body.(*bgp.BGPUpdate)
	pathAttributes := updateMsg.PathAttributes
	attrList := []*bgp.PathAttributeMpUnreachNLRI{}

	for _, attr := range pathAttributes {
		a, ok := attr.(*bgp.PathAttributeMpUnreachNLRI)
		if ok {
			attrList = append(attrList, a)
			break
		}
	}
	pathList := make([]*Path, 0)

	for _, mp := range attrList {
		nlri_info := mp.Value

		for _, nlri := range nlri_info {
			path := NewPath(p, nlri, true, pathAttributes, now, false)
			pathList = append(pathList, path)
		}
	}
	return pathList
}

func ProcessMessage(m *bgp.BGPMessage, peerInfo *PeerInfo, timestamp time.Time) []*Path {
	pathList := make([]*Path, 0)
	pathList = append(pathList, nlri2Path(m, peerInfo, timestamp)...)
	pathList = append(pathList, withdraw2Path(m, peerInfo, timestamp)...)
	pathList = append(pathList, mpreachNlri2Path(m, peerInfo, timestamp)...)
	pathList = append(pathList, mpunreachNlri2Path(m, peerInfo, timestamp)...)
	if y, f := m.Body.(*bgp.BGPUpdate).IsEndOfRib(); y {
		pathList = append(pathList, NewEOR(f))
	}
	return pathList
}

type TableManager struct {
	Tables map[bgp.RouteFamily]*Table
	Vrfs   map[string]*Vrf
	rfList []bgp.RouteFamily
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

func (manager *TableManager) AddVrf(name string, id uint32, rd bgp.RouteDistinguisherInterface, importRt, exportRt []bgp.ExtendedCommunityInterface, info *PeerInfo) ([]*Path, error) {
	if _, ok := manager.Vrfs[name]; ok {
		return nil, fmt.Errorf("vrf %s already exists", name)
	}
	log.WithFields(log.Fields{
		"Topic":    "Vrf",
		"Key":      name,
		"Rd":       rd,
		"ImportRt": importRt,
		"ExportRt": exportRt,
	}).Debugf("add vrf")
	manager.Vrfs[name] = &Vrf{
		Name:     name,
		Id:       id,
		Rd:       rd,
		ImportRt: importRt,
		ExportRt: exportRt,
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
	}).Debugf("delete vrf")
	delete(manager.Vrfs, name)
	rtcTable := manager.Tables[bgp.RF_RTC_UC]
	msgs = append(msgs, rtcTable.deleteRTCPathsByVrf(vrf, manager.Vrfs)...)
	return msgs, nil
}

func (manager *TableManager) calculate(dsts []*Destination) []*Destination {
	emptyDsts := make([]*Destination, 0, len(dsts))
	clonedDsts := make([]*Destination, 0, len(dsts))

	for _, dst := range dsts {
		log.WithFields(log.Fields{
			"Topic": "table",
			"Key":   dst.GetNlri().String(),
		}).Debug("Processing destination")

		clonedDsts = append(clonedDsts, dst.Calculate())

		if len(dst.knownPathList) == 0 {
			emptyDsts = append(emptyDsts, dst)
		}
	}

	for _, dst := range emptyDsts {
		t := manager.Tables[dst.Family()]
		t.deleteDest(dst)
	}
	return clonedDsts
}

func (manager *TableManager) DeletePathsByPeer(info *PeerInfo, rf bgp.RouteFamily) []*Destination {
	if t, ok := manager.Tables[rf]; ok {
		dsts := t.DeleteDestByPeer(info)
		return manager.calculate(dsts)
	}
	return nil
}

func (manager *TableManager) ProcessPaths(pathList []*Path) []*Destination {
	m := make(map[string]bool, len(pathList))
	dsts := make([]*Destination, 0, len(pathList))
	for _, path := range pathList {
		if path == nil || path.IsEOR() {
			continue
		}
		rf := path.GetRouteFamily()
		if t, ok := manager.Tables[rf]; ok {
			dst := t.insert(path)
			key := dst.GetNlri().String()
			if !m[key] {
				m[key] = true
				dsts = append(dsts, dst)
			}
			if rf == bgp.RF_EVPN {
				for _, dst := range manager.handleMacMobility(path) {
					key := dst.GetNlri().String()
					if !m[key] {
						m[key] = true
						dsts = append(dsts, dst)
					}
				}
			}
		}
	}
	return manager.calculate(dsts)
}

// EVPN MAC MOBILITY HANDLING
//
// RFC7432 15. MAC Mobility
//
// A PE receiving a MAC/IP Advertisement route for a MAC address with a
// different Ethernet segment identifier and a higher sequence number
// than that which it had previously advertised withdraws its MAC/IP
// Advertisement route.
func (manager *TableManager) handleMacMobility(path *Path) []*Destination {
	dsts := make([]*Destination, 0)
	nlri := path.GetNlri().(*bgp.EVPNNLRI)
	if path.IsWithdraw || path.IsLocal() || nlri.RouteType != bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT {
		return nil
	}
	for _, path2 := range manager.GetPathList(GLOBAL_RIB_NAME, []bgp.RouteFamily{bgp.RF_EVPN}) {
		if !path2.IsLocal() || path2.GetNlri().(*bgp.EVPNNLRI).RouteType != bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT {
			continue
		}
		f := func(p *Path) (uint32, net.HardwareAddr, int) {
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
			return d.ETag, d.MacAddress, seq
		}
		e1, m1, s1 := f(path)
		e2, m2, s2 := f(path2)
		if e1 == e2 && bytes.Equal(m1, m2) && s1 > s2 {
			path2.IsWithdraw = true
			dsts = append(dsts, manager.Tables[bgp.RF_EVPN].insert(path2))
		}
	}
	return dsts
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

func (manager *TableManager) GetBestPathList(id string, rfList []bgp.RouteFamily) []*Path {
	paths := make([]*Path, 0, manager.getDestinationCount(rfList))
	for _, t := range manager.tables(rfList...) {
		paths = append(paths, t.Bests(id)...)
	}
	return paths
}

func (manager *TableManager) GetBestMultiPathList(id string, rfList []bgp.RouteFamily) [][]*Path {
	if !UseMultiplePaths.Enabled {
		return nil
	}
	paths := make([][]*Path, 0, manager.getDestinationCount(rfList))
	for _, t := range manager.tables(rfList...) {
		paths = append(paths, t.MultiBests(id)...)
	}
	return paths
}

func (manager *TableManager) GetPathList(id string, rfList []bgp.RouteFamily) []*Path {
	paths := make([]*Path, 0, manager.getDestinationCount(rfList))
	for _, t := range manager.tables(rfList...) {
		paths = append(paths, t.GetKnownPathList(id)...)
	}
	return paths
}

func (manager *TableManager) GetPathListWithNexthop(id string, rfList []bgp.RouteFamily, nexthop net.IP) []*Path {
	paths := make([]*Path, 0, manager.getDestinationCount(rfList))
	for _, rf := range rfList {
		if t, ok := manager.Tables[rf]; ok {
			for _, path := range t.GetKnownPathList(id) {
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
	return t.GetDestination(path.getPrefix())
}

func (manager *TableManager) TableInfo(id string, family bgp.RouteFamily) (*TableInfo, error) {
	t, ok := manager.Tables[family]
	if !ok {
		return nil, fmt.Errorf("address family %s is not configured", family)
	}
	return t.Info(id), nil
}
