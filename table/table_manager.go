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
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/packet"
	"reflect"
	"time"
)

func nlri2Path(m *bgp.BGPMessage, p *PeerInfo, now time.Time) []Path {
	updateMsg := m.Body.(*bgp.BGPUpdate)
	pathAttributes := updateMsg.PathAttributes
	pathList := make([]Path, 0)
	for _, nlri_info := range updateMsg.NLRI {
		// define local variable to pass nlri's address to CreatePath
		var nlri bgp.NLRInfo = nlri_info
		// create Path object
		path, _ := CreatePath(p, &nlri, pathAttributes, false, now)
		pathList = append(pathList, path)
	}
	return pathList
}

func withdraw2Path(m *bgp.BGPMessage, p *PeerInfo, now time.Time) []Path {
	updateMsg := m.Body.(*bgp.BGPUpdate)
	pathAttributes := updateMsg.PathAttributes
	pathList := make([]Path, 0)
	for _, nlriWithdraw := range updateMsg.WithdrawnRoutes {
		// define local variable to pass nlri's address to CreatePath
		var w bgp.WithdrawnRoute = nlriWithdraw
		// create withdrawn Path object
		path, _ := CreatePath(p, &w, pathAttributes, true, now)
		pathList = append(pathList, path)
	}
	return pathList
}

func mpreachNlri2Path(m *bgp.BGPMessage, p *PeerInfo, now time.Time) []Path {
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
	pathList := make([]Path, 0)

	for _, mp := range attrList {
		nlri_info := mp.Value
		for _, nlri := range nlri_info {
			path, _ := CreatePath(p, nlri, pathAttributes, false, now)
			pathList = append(pathList, path)
		}
	}
	return pathList
}

func mpunreachNlri2Path(m *bgp.BGPMessage, p *PeerInfo, now time.Time) []Path {
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
	pathList := make([]Path, 0)

	for _, mp := range attrList {
		nlri_info := mp.Value

		for _, nlri := range nlri_info {
			path, _ := CreatePath(p, nlri, pathAttributes, true, now)
			pathList = append(pathList, path)
		}
	}
	return pathList
}

func ProcessMessage(m *bgp.BGPMessage, peerInfo *PeerInfo) []Path {
	pathList := make([]Path, 0)
	now := time.Now()
	pathList = append(pathList, nlri2Path(m, peerInfo, now)...)
	pathList = append(pathList, withdraw2Path(m, peerInfo, now)...)
	pathList = append(pathList, mpreachNlri2Path(m, peerInfo, now)...)
	pathList = append(pathList, mpunreachNlri2Path(m, peerInfo, now)...)
	return pathList
}

type TableManager struct {
	Tables   map[bgp.RouteFamily]Table
	localAsn uint32
	owner    string
}

func NewTableManager(owner string, rfList []bgp.RouteFamily) *TableManager {
	t := &TableManager{}
	t.Tables = make(map[bgp.RouteFamily]Table)
	for _, rf := range rfList {
		// FIXME: NewIPTable() should handle all cases.
		switch rf {
		case bgp.RF_IPv4_UC:
			t.Tables[bgp.RF_IPv4_UC] = NewIPv4Table(0)
		case bgp.RF_IPv6_UC:
			t.Tables[bgp.RF_IPv6_UC] = NewIPv6Table(0)
		case bgp.RF_IPv4_VPN:
			t.Tables[bgp.RF_IPv4_VPN] = NewIPv4VPNTable(0)
		case bgp.RF_EVPN:
			t.Tables[bgp.RF_EVPN] = NewEVPNTable(0)
		case bgp.RF_ENCAP:
			t.Tables[bgp.RF_ENCAP] = NewEncapTable()
		case bgp.RF_RTC_UC:
			t.Tables[bgp.RF_RTC_UC] = NewRouteTargetTable()
		}
	}
	t.owner = owner
	return t
}

func (manager *TableManager) calculate(destinationList []Destination) ([]Path, error) {
	newPaths := make([]Path, 0)

	for _, destination := range destinationList {
		// compute best path

		log.WithFields(log.Fields{
			"Topic": "table",
			"Owner": manager.owner,
			"Key":   destination.getNlri().String(),
		}).Debug("Processing destination")

		newBestPath, reason, err := destination.Calculate(manager.localAsn)

		if err != nil {
			log.Error(err)
			continue
		}

		destination.setBestPathReason(reason)
		currentBestPath := destination.getBestPath()

		if newBestPath != nil && currentBestPath == newBestPath {
			// best path is not changed
			log.WithFields(log.Fields{
				"Topic":    "table",
				"Owner":    manager.owner,
				"Key":      destination.getNlri().String(),
				"peer":     newBestPath.GetSource().Address,
				"next_hop": newBestPath.GetNexthop().String(),
				"reason":   reason,
			}).Debug("best path is not changed")
			continue
		}

		if newBestPath == nil {
			log.WithFields(log.Fields{
				"Topic": "table",
				"Owner": manager.owner,
				"Key":   destination.getNlri().String(),
			}).Debug("best path is nil")

			if len(destination.getKnownPathList()) == 0 {
				// create withdraw path
				if currentBestPath != nil {
					log.WithFields(log.Fields{
						"Topic":    "table",
						"Owner":    manager.owner,
						"Key":      destination.getNlri().String(),
						"peer":     currentBestPath.GetSource().Address,
						"next_hop": currentBestPath.GetNexthop().String(),
					}).Debug("best path is lost")

					p := destination.getBestPath()
					newPaths = append(newPaths, p.Clone(true))
				}
				destination.setBestPath(nil)
			} else {

				log.WithFields(log.Fields{
					"Topic": "table",
					"Owner": manager.owner,
					"Key":   destination.getNlri().String(),
				}).Error("known path list is not empty")
			}
		} else {
			log.WithFields(log.Fields{
				"Topic":    "table",
				"Owner":    manager.owner,
				"Key":      newBestPath.GetNlri().String(),
				"peer":     newBestPath.GetSource().Address,
				"next_hop": newBestPath.GetNexthop(),
				"reason":   reason,
			}).Debug("new best path")

			newPaths = append(newPaths, newBestPath)
			destination.setBestPath(newBestPath)
		}

		if len(destination.getKnownPathList()) == 0 && destination.getBestPath() == nil {
			rf := destination.getRouteFamily()
			t := manager.Tables[rf]
			deleteDest(t, destination)
			log.WithFields(log.Fields{
				"Topic":        "table",
				"Owner":        manager.owner,
				"Key":          destination.getNlri().String(),
				"route_family": rf,
			}).Debug("destination removed")
		}
	}
	return newPaths, nil
}

func (manager *TableManager) DeletePathsforPeer(peerInfo *PeerInfo, rf bgp.RouteFamily) ([]Path, error) {
	if _, ok := manager.Tables[rf]; ok {
		destinationList := manager.Tables[rf].DeleteDestByPeer(peerInfo)
		return manager.calculate(destinationList)
	}
	return []Path{}, nil
}

func (manager *TableManager) ProcessPaths(pathList []Path) ([]Path, error) {
	destinationList := make([]Destination, 0)
	for _, path := range pathList {
		rf := path.GetRouteFamily()
		if _, ok := manager.Tables[rf]; ok {
			destination := insert(manager.Tables[rf], path)
			destinationList = append(destinationList, destination)
		}
	}
	return manager.calculate(destinationList)
}

func (manager *TableManager) GetPathList(rf bgp.RouteFamily) []Path {
	if _, ok := manager.Tables[rf]; !ok {
		return []Path{}
	}
	var paths []Path
	for _, dest := range manager.Tables[rf].GetDestinations() {
		paths = append(paths, dest.getBestPath())
	}
	return paths
}

// process BGPUpdate message
// this function processes only BGPUpdate
func (manager *TableManager) ProcessUpdate(fromPeer *PeerInfo, message *bgp.BGPMessage) ([]Path, error) {
	// check msg's type if it's BGPUpdate
	if message.Header.Type != bgp.BGP_MSG_UPDATE {
		log.WithFields(log.Fields{
			"Topic": "table",
			"Owner": manager.owner,
			"key":   fromPeer.Address.String(),
			"Type":  message.Header.Type,
		}).Warn("message is not BGPUpdate")
		return []Path{}, nil
	}

	return manager.ProcessPaths(ProcessMessage(message, fromPeer))
}

type AdjRib struct {
	adjRibIn  map[bgp.RouteFamily]map[string]*ReceivedRoute
	adjRibOut map[bgp.RouteFamily]map[string]*ReceivedRoute
}

func NewAdjRib(rfList []bgp.RouteFamily) *AdjRib {
	r := &AdjRib{
		adjRibIn:  make(map[bgp.RouteFamily]map[string]*ReceivedRoute),
		adjRibOut: make(map[bgp.RouteFamily]map[string]*ReceivedRoute),
	}
	for _, rf := range rfList {
		r.adjRibIn[rf] = make(map[string]*ReceivedRoute)
		r.adjRibOut[rf] = make(map[string]*ReceivedRoute)
	}
	return r
}

func (adj *AdjRib) update(rib map[bgp.RouteFamily]map[string]*ReceivedRoute, pathList []Path) {
	for _, path := range pathList {
		rf := path.GetRouteFamily()
		key := path.getPrefix()
		old, found := rib[rf][key]
		if path.IsWithdraw() {
			if found {
				delete(rib[rf], key)
			}
		} else {
			if found && reflect.DeepEqual(old.path.getPathAttrs(), path.getPathAttrs()) {
				path.setTimestamp(old.path.getTimestamp())
			}
			rib[rf][key] = NewReceivedRoute(path, false)
		}
	}
}

func (adj *AdjRib) UpdateIn(pathList []Path) {
	adj.update(adj.adjRibIn, pathList)
}

func (adj *AdjRib) UpdateOut(pathList []Path) {
	adj.update(adj.adjRibOut, pathList)
}

func (adj *AdjRib) getPathList(rib map[string]*ReceivedRoute) []Path {
	pathList := make([]Path, 0, len(rib))
	for _, rr := range rib {
		pathList = append(pathList, rr.path)
	}
	return pathList
}

func (adj *AdjRib) GetInPathList(rf bgp.RouteFamily) []Path {
	if _, ok := adj.adjRibIn[rf]; !ok {
		return []Path{}
	}
	return adj.getPathList(adj.adjRibIn[rf])
}

func (adj *AdjRib) GetOutPathList(rf bgp.RouteFamily) []Path {
	if _, ok := adj.adjRibOut[rf]; !ok {
		return []Path{}
	}
	return adj.getPathList(adj.adjRibOut[rf])
}

func (adj *AdjRib) GetInCount(rf bgp.RouteFamily) int {
	if _, ok := adj.adjRibIn[rf]; !ok {
		return 0
	}
	return len(adj.adjRibIn[rf])
}

func (adj *AdjRib) GetOutCount(rf bgp.RouteFamily) int {
	if _, ok := adj.adjRibOut[rf]; !ok {
		return 0
	}
	return len(adj.adjRibOut[rf])
}

func (adj *AdjRib) DropAllIn(rf bgp.RouteFamily) {
	if _, ok := adj.adjRibIn[rf]; ok {
		// replace old one
		adj.adjRibIn[rf] = make(map[string]*ReceivedRoute)
	}
}

type ReceivedRoute struct {
	path     Path
	filtered bool
}

func (rr *ReceivedRoute) String() string {
	return rr.path.getPrefix()
}

func NewReceivedRoute(path Path, filtered bool) *ReceivedRoute {

	rroute := &ReceivedRoute{
		path:     path,
		filtered: filtered,
	}
	return rroute
}
