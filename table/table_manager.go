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
	"os"
	"time"
)

var logger *log.Logger = &log.Logger{
	Out:       os.Stderr,
	Formatter: new(log.JSONFormatter),
	Hooks:     make(map[log.Level][]log.Hook),
	Level:     log.InfoLevel,
}

type RouteFamily int

const (
	RF_IPv4_UC   RouteFamily = bgp.RF_IPv4_UC
	RF_IPv6_UC   RouteFamily = bgp.RF_IPv6_UC
	RF_IPv4_VPN  RouteFamily = bgp.RF_IPv4_VPN
	RF_IPv6_VPN  RouteFamily = bgp.RF_IPv6_VPN
	RF_IPv4_MPLS RouteFamily = bgp.RF_IPv4_MPLS
	RF_IPv6_MPLS RouteFamily = bgp.RF_IPv6_MPLS
	RF_RTC_UC    RouteFamily = bgp.RF_RTC_UC
)

func (rf RouteFamily) String() string {
	switch rf {
	case RF_IPv4_UC:
		return "RF_IPv4_UC"
	case RF_IPv6_UC:
		return "RF_IPv6_UC"
	case RF_IPv4_VPN:
		return "RF_IPv4_VPN"
	case RF_IPv6_VPN:
		return "RF_IPv6_VPN"
	case RF_IPv4_MPLS:
		return "RF_IPv4_MPLS"
	case RF_IPv6_MPLS:
		return "RF_IPv6_MPLS"
	case RF_RTC_UC:
		return "RF_RTC_UC"
	default:
		return "Unknown"
	}
}

type AttributeType int

const (
	BGP_ATTR_TYPE_ORIGIN               AttributeType = bgp.BGP_ATTR_TYPE_ORIGIN
	BGP_ATTR_TYPE_AS_PATH              AttributeType = bgp.BGP_ATTR_TYPE_AS_PATH
	BGP_ATTR_TYPE_NEXT_HOP             AttributeType = bgp.BGP_ATTR_TYPE_NEXT_HOP
	BGP_ATTR_TYPE_MULTI_EXIT_DISC      AttributeType = bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC
	BGP_ATTR_TYPE_LOCAL_PREF           AttributeType = bgp.BGP_ATTR_TYPE_LOCAL_PREF
	BGP_ATTR_TYPE_ATOMIC_AGGREGATE     AttributeType = bgp.BGP_ATTR_TYPE_ATOMIC_AGGREGATE
	BGP_ATTR_TYPE_AGGREGATOR           AttributeType = bgp.BGP_ATTR_TYPE_AGGREGATOR
	BGP_ATTR_TYPE_COMMUNITIES          AttributeType = bgp.BGP_ATTR_TYPE_COMMUNITIES
	BGP_ATTR_TYPE_ORIGINATOR_ID        AttributeType = bgp.BGP_ATTR_TYPE_ORIGINATOR_ID
	BGP_ATTR_TYPE_CLUSTER_LIST         AttributeType = bgp.BGP_ATTR_TYPE_CLUSTER_LIST
	BGP_ATTR_TYPE_MP_REACH_NLRI        AttributeType = bgp.BGP_ATTR_TYPE_MP_REACH_NLRI
	BGP_ATTR_TYPE_MP_UNREACH_NLRI      AttributeType = bgp.BGP_ATTR_TYPE_MP_UNREACH_NLRI
	BGP_ATTR_TYPE_EXTENDED_COMMUNITIES AttributeType = bgp.BGP_ATTR_TYPE_EXTENDED_COMMUNITIES
	BGP_ATTR_TYPE_AS4_PATH             AttributeType = bgp.BGP_ATTR_TYPE_AS4_PATH
	BGP_ATTR_TYPE_AS4_AGGREGATOR       AttributeType = bgp.BGP_ATTR_TYPE_AS4_AGGREGATOR
)

func (attr AttributeType) String() string {
	switch attr {
	case BGP_ATTR_TYPE_ORIGIN:
		return "BGP_ATTR_TYPE_ORIGIN"
	case BGP_ATTR_TYPE_AS_PATH:
		return "BGP_ATTR_TYPE_AS_PATH"
	case BGP_ATTR_TYPE_NEXT_HOP:
		return "BGP_ATTR_TYPE_NEXT_HOP"
	case BGP_ATTR_TYPE_MULTI_EXIT_DISC:
		return "BGP_ATTR_TYPE_MULTI_EXIT_DISC"
	case BGP_ATTR_TYPE_LOCAL_PREF:
		return "BGP_ATTR_TYPE_LOCAL_PREF"
	case BGP_ATTR_TYPE_ATOMIC_AGGREGATE:
		return "BGP_ATTR_TYPE_ATOMIC_AGGREGATE"
	case BGP_ATTR_TYPE_AGGREGATOR:
		return "BGP_ATTR_TYPE_AGGREGATOR"
	case BGP_ATTR_TYPE_COMMUNITIES:
		return "BGP_ATTR_TYPE_COMMUNITIES"
	case BGP_ATTR_TYPE_ORIGINATOR_ID:
		return "BGP_ATTR_TYPE_ORIGINATOR_ID"
	case BGP_ATTR_TYPE_CLUSTER_LIST:
		return "BGP_ATTR_TYPE_CLUSTER_LIST"
	case BGP_ATTR_TYPE_MP_REACH_NLRI:
		return "BGP_ATTR_TYPE_MP_REACH_NLRI"
	case BGP_ATTR_TYPE_MP_UNREACH_NLRI:
		return "BGP_ATTR_TYPE_MP_UNREACH_NLRI"
	case BGP_ATTR_TYPE_EXTENDED_COMMUNITIES:
		return "BGP_ATTR_TYPE_EXTENDED_COMMUNITIES"
	case BGP_ATTR_TYPE_AS4_PATH:
		return "BGP_ATTR_TYPE_AS4_PATH"
	case BGP_ATTR_TYPE_AS4_AGGREGATOR:
		return "BGP_ATTR_TYPE_AS4_AGGREGATOR"
	default:
		return "Unknown"
	}
}

type ProcessMessage struct {
	innerMessage *bgp.BGPMessage
	fromPeer     *PeerInfo
}

func NewProcessMessage(m *bgp.BGPMessage, peerInfo *PeerInfo) *ProcessMessage {
	return &ProcessMessage{
		innerMessage: m,
		fromPeer:     peerInfo,
	}
}

func (p *ProcessMessage) nlri2Path() []Path {
	updateMsg := p.innerMessage.Body.(*bgp.BGPUpdate)
	pathAttributes := updateMsg.PathAttributes
	pathList := make([]Path, 0)
	for _, nlri_info := range updateMsg.NLRI {
		// define local variable to pass nlri's address to CreatePath
		var nlri bgp.NLRInfo = nlri_info
		// create Path object
		path := CreatePath(p.fromPeer, &nlri, pathAttributes, false)
		pathList = append(pathList, path)
	}
	return pathList
}

func (p *ProcessMessage) withdraw2Path() []Path {
	updateMsg := p.innerMessage.Body.(*bgp.BGPUpdate)
	pathAttributes := updateMsg.PathAttributes
	pathList := make([]Path, 0)
	for _, nlriWithdraw := range updateMsg.WithdrawnRoutes {
		// define local variable to pass nlri's address to CreatePath
		var w bgp.WithdrawnRoute = nlriWithdraw
		// create withdrawn Path object
		path := CreatePath(p.fromPeer, &w, pathAttributes, true)
		pathList = append(pathList, path)
	}
	return pathList
}

func (p *ProcessMessage) mpreachNlri2Path() []Path {
	updateMsg := p.innerMessage.Body.(*bgp.BGPUpdate)
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
			path := CreatePath(p.fromPeer, nlri, pathAttributes, false)
			pathList = append(pathList, path)
		}
	}
	return pathList
}

func (p *ProcessMessage) mpunreachNlri2Path() []Path {
	updateMsg := p.innerMessage.Body.(*bgp.BGPUpdate)
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
			path := CreatePath(p.fromPeer, nlri, pathAttributes, true)
			pathList = append(pathList, path)
		}
	}
	return pathList
}

func (p *ProcessMessage) ToPathList() []Path {
	pathList := make([]Path, 0)
	pathList = append(pathList, p.nlri2Path()...)
	pathList = append(pathList, p.withdraw2Path()...)
	pathList = append(pathList, p.mpreachNlri2Path()...)
	pathList = append(pathList, p.mpunreachNlri2Path()...)
	return pathList
}

type TableManager struct {
	Tables   map[RouteFamily]Table
	localAsn uint32
}

func NewTableManager() *TableManager {
	t := &TableManager{}
	t.Tables = make(map[RouteFamily]Table)
	t.Tables[RF_IPv4_UC] = NewIPv4Table(0)
	t.Tables[RF_IPv6_UC] = NewIPv6Table(0)
	return t
}

func setLogger(loggerInstance *log.Logger) {
	logger = loggerInstance
}

func (manager *TableManager) ProcessPaths(pathList []Path) ([]Path, []Destination, error) {
	bestPaths := make([]Path, 0)
	lostDest := make([]Destination, 0)

	destinationList := make([]Destination, 0)
	for _, path := range pathList {
		rf := path.getRouteFamily()
		// push Path into table
		destination := insert(manager.Tables[rf], path)
		destinationList = append(destinationList, destination)
	}

	for _, destination := range destinationList {
		// compute best path
		logger.Infof("Processing destination: %v", destination.String())
		newBestPath, reason, err := destination.Calculate(manager.localAsn)

		logger.Debugf("new best path: %v, reason=%v", newBestPath, reason)
		if err != nil {
			logger.Error(err)
			continue
		}

		destination.setBestPathReason(reason)
		currentBestPath := destination.getBestPath()

		if newBestPath != nil && currentBestPath == newBestPath {
			// best path is not changed
			logger.Debug("best path is not changed")
			continue
		}

		if newBestPath == nil {
			logger.Debug("best path is nil")
			if len(destination.getKnownPathList()) == 0 {
				// create withdraw path
				if currentBestPath != nil {
					logger.Debug("best path is lost")
					destination.setOldBestPath(destination.getBestPath())
					lostDest = append(lostDest, destination)
				}
				destination.setBestPath(nil)
			} else {
				logger.Error("known path list is not empty")
			}
		} else {
			logger.Debugf("new best path: NLRI: %v, next_hop=%v, reason=%v",
				newBestPath.getPrefix().String(),
				newBestPath.getNexthop().String(),
				reason)

			bestPaths = append(bestPaths, newBestPath)
			destination.setBestPath(newBestPath)
		}

		if len(destination.getKnownPathList()) == 0 && destination.getBestPath() == nil {
			rf := destination.getRouteFamily()
			t := manager.Tables[rf]
			deleteDest(t, destination)
			logger.Debugf("destination removed route_family=%v, destination=%v", rf, destination)
		}
	}
	return bestPaths, lostDest, nil
}

// process BGPUpdate message
// this function processes only BGPUpdate
func (manager *TableManager) ProcessUpdate(fromPeer *PeerInfo, message *bgp.BGPMessage) ([]Path, []Destination, error) {
	var bestPaths []Path = make([]Path, 0)
	var lostDest []Destination = make([]Destination, 0)

	// check msg's type if it's BGPUpdate
	if message.Header.Type != bgp.BGP_MSG_UPDATE {
		logger.Warn("message is not BGPUpdate")
		return bestPaths, lostDest, nil
	}

	msg := &ProcessMessage{
		innerMessage: message,
		fromPeer:     fromPeer,
	}

	return manager.ProcessPaths(msg.ToPathList())
}

type AdjRib struct {
	adjRibIn  map[RouteFamily]map[string]*ReceivedRoute
	adjRibOut map[RouteFamily]map[string]*ReceivedRoute
}

func NewAdjRib() *AdjRib {
	r := &AdjRib{
		adjRibIn:  make(map[RouteFamily]map[string]*ReceivedRoute),
		adjRibOut: make(map[RouteFamily]map[string]*ReceivedRoute),
	}
	r.adjRibIn[RF_IPv4_UC] = make(map[string]*ReceivedRoute)
	r.adjRibIn[RF_IPv6_UC] = make(map[string]*ReceivedRoute)
	r.adjRibOut[RF_IPv4_UC] = make(map[string]*ReceivedRoute)
	r.adjRibOut[RF_IPv6_UC] = make(map[string]*ReceivedRoute)
	return r
}

func (adj *AdjRib) update(rib map[RouteFamily]map[string]*ReceivedRoute, pathList []Path) {
	for _, path := range pathList {
		rf := path.getRouteFamily()
		key := path.getPrefix().String()
		if path.IsWithdraw() {
			_, found := rib[rf][key]
			if found {
				delete(rib[rf], key)
			}
		} else {
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
	pathList := []Path{}

	for _, rr := range rib {
		pathList = append(pathList, rr.path)
	}
	return pathList
}

func (adj *AdjRib) GetInPathList(rf RouteFamily) []Path {
	return adj.getPathList(adj.adjRibIn[rf])
}

func (adj *AdjRib) GetOutPathList(rf RouteFamily) []Path {
	return adj.getPathList(adj.adjRibOut[rf])
}

type ReceivedRoute struct {
	path      Path
	filtered  bool
	timestamp time.Time
}

func (rr *ReceivedRoute) String() string {
	return rr.path.(*PathDefault).getPrefix().String()
}

func NewReceivedRoute(path Path, filtered bool) *ReceivedRoute {

	rroute := &ReceivedRoute{
		path:      path,
		filtered:  filtered,
		timestamp: time.Now(),
	}
	return rroute
}
