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
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/packet"
	"net"
	"time"
)

func nlri2Path(m *bgp.BGPMessage, p *PeerInfo, now time.Time) []*Path {
	updateMsg := m.Body.(*bgp.BGPUpdate)
	pathAttributes := updateMsg.PathAttributes
	pathList := make([]*Path, 0)
	for _, nlri := range updateMsg.NLRI {
		path := NewPath(p, nlri, false, pathAttributes, false, now, false)
		pathList = append(pathList, path)
	}
	return pathList
}

func withdraw2Path(m *bgp.BGPMessage, p *PeerInfo, now time.Time) []*Path {
	updateMsg := m.Body.(*bgp.BGPUpdate)
	pathAttributes := updateMsg.PathAttributes
	pathList := make([]*Path, 0)
	for _, nlri := range updateMsg.WithdrawnRoutes {
		path := NewPath(p, nlri, true, pathAttributes, false, now, false)
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
			path := NewPath(p, nlri, false, pathAttributes, false, now, false)
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
			path := NewPath(p, nlri, true, pathAttributes, false, now, false)
			pathList = append(pathList, path)
		}
	}
	return pathList
}

func ProcessMessage(m *bgp.BGPMessage, peerInfo *PeerInfo) []*Path {
	pathList := make([]*Path, 0)
	now := time.Now()
	pathList = append(pathList, nlri2Path(m, peerInfo, now)...)
	pathList = append(pathList, withdraw2Path(m, peerInfo, now)...)
	pathList = append(pathList, mpreachNlri2Path(m, peerInfo, now)...)
	pathList = append(pathList, mpunreachNlri2Path(m, peerInfo, now)...)
	return pathList
}

type TableManager struct {
	Tables    map[bgp.RouteFamily]*Table
	Vrfs      map[string]*Vrf
	owner     string
	minLabel  uint32
	maxLabel  uint32
	nextLabel uint32
}

func NewTableManager(owner string, rfList []bgp.RouteFamily, minLabel, maxLabel uint32) *TableManager {
	t := &TableManager{
		Tables:    make(map[bgp.RouteFamily]*Table),
		Vrfs:      make(map[string]*Vrf),
		owner:     owner,
		minLabel:  minLabel,
		maxLabel:  maxLabel,
		nextLabel: minLabel,
	}
	for _, rf := range rfList {
		t.Tables[rf] = NewTable(rf)
	}
	return t
}

func (manager *TableManager) GetNextLabel(name, nexthop string, isWithdraw bool) (uint32, error) {
	var label uint32
	var err error
	vrf, ok := manager.Vrfs[name]
	if !ok {
		return label, fmt.Errorf("vrf %s not found", name)
	}
	label, ok = vrf.LabelMap[nexthop]
	if !ok {
		label, err = manager.getNextLabel()
		vrf.LabelMap[nexthop] = label
	}
	return label, err

}

func (manager *TableManager) getNextLabel() (uint32, error) {
	if manager.nextLabel > manager.maxLabel {
		return 0, fmt.Errorf("ran out of label resource. max label %d", manager.maxLabel)
	}
	label := manager.nextLabel
	manager.nextLabel += 1
	return label, nil
}

func (manager *TableManager) OwnerName() string {
	return manager.owner
}

func (manager *TableManager) AddVrf(name string, rd bgp.RouteDistinguisherInterface, importRt, exportRt []bgp.ExtendedCommunityInterface, info *PeerInfo) ([]*Path, error) {
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
		Rd:       rd,
		ImportRt: importRt,
		ExportRt: exportRt,
		LabelMap: make(map[string]uint32),
	}
	msgs := make([]*Path, 0, len(importRt))
	nexthop := "0.0.0.0"
	for _, target := range importRt {
		nlri := bgp.NewRouteTargetMembershipNLRI(info.AS, target)
		pattr := make([]bgp.PathAttributeInterface, 0, 2)
		pattr = append(pattr, bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP))
		pattr = append(pattr, bgp.NewPathAttributeMpReachNLRI(nexthop, []bgp.AddrPrefixInterface{nlri}))
		msgs = append(msgs, NewPath(info, nlri, false, pattr, false, time.Now(), false))
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

func (manager *TableManager) calculate(destinationList []*Destination) ([]*Path, error) {
	result := make([]*Path, 0, len(destinationList))
	for _, destination := range destinationList {
		// compute best path

		log.WithFields(log.Fields{
			"Topic": "table",
			"Owner": manager.owner,
			"Key":   destination.GetNlri().String(),
		}).Debug("Processing destination")

		newBestPath, backups, matchedWithdrawals := destination.Calculate()
		currentBestPath := destination.GetBestPath()

		if newBestPath != nil && newBestPath.Equal(currentBestPath) {
			// best path is not changed
			log.WithFields(log.Fields{
				"Topic":    "table",
				"Owner":    manager.owner,
				"Key":      destination.GetNlri().String(),
				"peer":     newBestPath.GetSource().Address,
				"next_hop": newBestPath.GetNexthop().String(),
				"reason":   newBestPath.reason,
			}).Debug("best path is not changed")
			newBestPath = nil
		} else if newBestPath == nil {
			log.WithFields(log.Fields{
				"Topic": "table",
				"Owner": manager.owner,
				"Key":   destination.GetNlri().String(),
			}).Debug("best path is nil")

			if len(destination.GetKnownPathList()) > 0 {
				log.WithFields(log.Fields{
					"Topic": "table",
					"Owner": manager.owner,
					"Key":   destination.GetNlri().String(),
				}).Error("code logic bug: known path list is not empty")
				continue
			}
			if len(backups) > 0 {
				log.WithFields(log.Fields{
					"Topic": "table",
					"Owner": manager.owner,
					"Key":   destination.GetNlri().String(),
				}).Error("code logic bug: buckup list is not empty")
				continue
			}
			if currentBestPath != nil && len(matchedWithdrawals) == 0 {
				log.WithFields(log.Fields{
					"Topic": "table",
					"Owner": manager.owner,
					"Key":   destination.GetNlri().String(),
				}).Error("code logic bug: matchedWithdrawals is empty")
				continue
			}
			if currentBestPath != nil {
				// matchedWithdrawals is sorted.
				// A head route is the route which withdraw a best path.
				newBestPath = matchedWithdrawals[0]
				matchedWithdrawals = matchedWithdrawals[1:]
				log.WithFields(log.Fields{
					"Topic":    "table",
					"Owner":    manager.owner,
					"Key":      destination.GetNlri().String(),
					"peer":     currentBestPath.GetSource().Address,
					"next_hop": currentBestPath.GetNexthop().String(),
				}).Debug("best path is lost")
			}
			destination.setBestPath(nil)
		} else {
			log.WithFields(log.Fields{
				"Topic":    "table",
				"Owner":    manager.owner,
				"Key":      newBestPath.GetNlri().String(),
				"peer":     newBestPath.GetSource().Address,
				"next_hop": newBestPath.GetNexthop(),
				"reason":   newBestPath.reason,
			}).Debug("new best path")
			if len(matchedWithdrawals) > 0 && matchedWithdrawals[0] == currentBestPath {
				// matchedWithdrawals is sorted.
				// A head route is the route which withdraw a best path.
				// new best path is elected. just throw away the head withdraw route.
				matchedWithdrawals = matchedWithdrawals[1:]
			}
			destination.setBestPath(newBestPath)
		}

		if newBestPath != nil {
			result = append(result, newBestPath)
		}
		result = append(result, matchedWithdrawals...)
		result = append(result, backups...)

		if len(destination.GetKnownPathList()) == 0 && destination.GetBestPath() == nil {
			rf := destination.getRouteFamily()
			t := manager.Tables[rf]
			t.deleteDest(destination)
			log.WithFields(log.Fields{
				"Topic":        "table",
				"Owner":        manager.owner,
				"Key":          destination.GetNlri().String(),
				"route_family": rf,
			}).Debug("destination removed")
		}
	}
	return result, nil
}

func (manager *TableManager) DeletePathsforPeer(peerInfo *PeerInfo, rf bgp.RouteFamily) ([]*Path, error) {
	if t, ok := manager.Tables[rf]; ok {
		destinationList := t.DeleteDestByPeer(peerInfo)
		return manager.calculate(destinationList)
	}
	return nil, nil
}

func (manager *TableManager) ProcessPaths(pathList []*Path) ([]*Path, error) {
	destinationList := make([]*Destination, 0, len(pathList))
	for _, path := range pathList {
		rf := path.GetRouteFamily()
		if t, ok := manager.Tables[rf]; ok {
			destinationList = append(destinationList, t.insert(path))
			if rf == bgp.RF_EVPN {
				dsts := manager.handleMacMobility(path)
				if len(dsts) > 0 {
					destinationList = append(destinationList, dsts...)
				}
			}
		}
	}
	return manager.calculate(destinationList)
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
	for _, path2 := range manager.GetPathList(bgp.RF_EVPN) {
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

func (manager *TableManager) GetPathList(rf bgp.RouteFamily) []*Path {
	if _, ok := manager.Tables[rf]; !ok {
		return []*Path{}
	}
	destinations := manager.Tables[rf].GetDestinations()
	paths := make([]*Path, 0, len(destinations))
	for _, dest := range destinations {
		paths = append(paths, dest.knownPathList...)
	}
	return paths
}

func (manager *TableManager) GetBestPathList(rf bgp.RouteFamily) []*Path {
	if _, ok := manager.Tables[rf]; !ok {
		return []*Path{}
	}
	destinations := manager.Tables[rf].GetDestinations()
	paths := make([]*Path, 0, len(destinations))
	for _, dest := range destinations {
		paths = append(paths, dest.GetBestPath())
	}
	return paths
}

// process BGPUpdate message
// this function processes only BGPUpdate
func (manager *TableManager) ProcessUpdate(fromPeer *PeerInfo, message *bgp.BGPMessage) ([]*Path, error) {
	// check msg's type if it's BGPUpdate
	if message.Header.Type != bgp.BGP_MSG_UPDATE {
		log.WithFields(log.Fields{
			"Topic": "table",
			"Owner": manager.owner,
			"key":   fromPeer.Address.String(),
			"Type":  message.Header.Type,
		}).Warn("message is not BGPUpdate")
		return nil, nil
	}

	return manager.ProcessPaths(ProcessMessage(message, fromPeer))
}
