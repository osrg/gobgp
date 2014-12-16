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
	"net"
	"os"
	"time"
)

var logger *log.Logger = &log.Logger{
	Out:       os.Stderr,
	Formatter: new(log.JSONFormatter),
	Hooks:     make(map[log.Level][]log.Hook),
	Level:     log.InfoLevel,
}

type PeerCounterName string

const (
	RECV_PREFIXES        PeerCounterName = "recv_prefixes"
	RECV_UPDATES         PeerCounterName = "recv_updates"
	SENT_UPDATES         PeerCounterName = "sent_updates"
	RECV_NOTIFICATION    PeerCounterName = "recv_notification"
	SENT_NOTIFICATION    PeerCounterName = "sent_notification"
	SENT_REFRESH         PeerCounterName = "sent_refresh"
	RECV_REFRESH         PeerCounterName = "recv_refresh"
	FSM_ESTB_TRANSITIONS PeerCounterName = "fms_established_transitions"
)

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

type TableManager struct {
	Tables        map[RouteFamily]Table
	adjInLocalRib map[string]*ReceivedRoute
	Counter       map[PeerCounterName]int
	localAsn      uint32
}

type ProcessMessage struct {
	innerMessage *bgp.BGPMessage
	fromPeer     *PeerInfo
}

func NewTableManager() *TableManager {
	t := &TableManager{}
	t.Tables = make(map[RouteFamily]Table)
	t.Tables[RF_IPv4_UC] = NewIPv4Table(0)
	t.Tables[RF_IPv6_UC] = NewIPv6Table(0)
	// initialize prefix counter
	t.Counter = make(map[PeerCounterName]int)
	t.Counter[RECV_PREFIXES] = 0

	return t
}

func setLogger(loggerInstance *log.Logger) {
	logger = loggerInstance
}

func (manager *TableManager) incrCounter(name PeerCounterName, step int) {
	val := manager.Counter[name]
	val += step
	manager.Counter[name] = val
}

// create destination list from nlri
func (manager *TableManager) handleNlri(p *ProcessMessage) ([]Destination, error) {

	updateMsg := p.innerMessage.Body.(*bgp.BGPUpdate)
	nlriList := updateMsg.NLRI // NLRI is an array of NLRInfo.
	pathAttributes := updateMsg.PathAttributes

	destList := make([]Destination, 0)
	for _, nlri_info := range nlriList {

		// define local variable to pass nlri's address to CreatePath
		var nlri bgp.NLRInfo = nlri_info
		// create Path object
		path := CreatePath(p.fromPeer, &nlri, pathAttributes, false)
		// TODO process filter

		rf := path.getRouteFamily()
		// push Path into table
		destination := insert(manager.Tables[rf], path)
		destList = append(destList, destination)
		manager.incrCounter(RECV_PREFIXES, len(nlriList))
		// TODO handle adj-in-loc-rib
		//		rr := NewReceivedRoute(path, p.fromPeer, false)
		//		manager.adjInLocalRib[p.fromPeer.String()] = rr
		//		manager.adjInChanged <- rr
	}

	logger.Debugf("destinationList contains %d destinations from nlri_info", len(destList))

	return destList, nil
}

// create destination list from withdrawn routes
func (manager *TableManager) handleWithdraw(p *ProcessMessage) ([]Destination, error) {

	updateMsg := p.innerMessage.Body.(*bgp.BGPUpdate)
	pathAttributes := updateMsg.PathAttributes
	withdrawnRoutes := updateMsg.WithdrawnRoutes

	wDestList := make([]Destination, 0)

	// process withdraw path
	for _, nlriWithdraw := range withdrawnRoutes {
		// define local variable to pass nlri's address to CreatePath
		var w bgp.WithdrawnRoute = nlriWithdraw
		// create withdrawn Path object
		path := CreatePath(p.fromPeer, &w, pathAttributes, true)
		rf := path.getRouteFamily()
		// push Path into table
		destination := insert(manager.Tables[rf], path)
		wDestList = append(wDestList, destination)
	}

	logger.Debugf("destinationList contains %d withdrawn destinations", len(wDestList))
	return wDestList, nil
}

// create destination list from nlri
func (manager *TableManager) handleMPReachNlri(p *ProcessMessage) ([]Destination, error) {

	updateMsg := p.innerMessage.Body.(*bgp.BGPUpdate)
	pathAttributes := updateMsg.PathAttributes
	attrList := []*bgp.PathAttributeMpReachNLRI{}

LOOP:
	for _, attr := range pathAttributes {
		switch a := attr.(type) {
		case *bgp.PathAttributeMpReachNLRI:
			attrList = append(attrList, a)
			break LOOP
		}
	}

	destList := make([]Destination, 0)
	for _, mp := range attrList {
		nlri_info := mp.Value

		for _, nlri := range nlri_info {
			path := CreatePath(p.fromPeer, nlri, pathAttributes, false)
			// TODO process filter

			rf := path.getRouteFamily()
			// push Path into table
			destination := insert(manager.Tables[rf], path)

			destList = append(destList, destination)
			manager.incrCounter(RECV_PREFIXES, len(nlri_info))
			// TODO handle adj-in-loc-rib
			//		rr := NewReceivedRoute(path, p.fromPeer, false)
			//		manager.adjInLocalRib[p.fromPeer.String()] = rr
			//		manager.adjInChanged <- rr
		}
	}
	logger.Debugf("destinationList contains %d destinations from MpReachNLRI", len(destList))

	return destList, nil
}

// create destination list from nlri
func (manager *TableManager) handleMPUNReachNlri(p *ProcessMessage) ([]Destination, error) {

	updateMsg := p.innerMessage.Body.(*bgp.BGPUpdate)
	pathAttributes := updateMsg.PathAttributes
	attrList := []*bgp.PathAttributeMpUnreachNLRI{}

LOOP:
	for _, attr := range pathAttributes {
		switch a := attr.(type) {
		case *bgp.PathAttributeMpUnreachNLRI:
			attrList = append(attrList, a)
			break LOOP
		}
	}

	destList := make([]Destination, 0)
	for _, mp := range attrList {
		nlri_info := mp.Value

		for _, nlri := range nlri_info {
			path := CreatePath(p.fromPeer, nlri, pathAttributes, true)
			// TODO process filter

			rf := path.getRouteFamily()
			// push Path into table
			destination := insert(manager.Tables[rf], path)

			destList = append(destList, destination)
			manager.incrCounter(RECV_PREFIXES, len(nlri_info))
		}
	}
	logger.Debugf("destinationList contains %d destinations from MpUnreachNLRI", len(destList))
	return destList, nil
}

// process BGPUpdate message
// this function processes only BGPUpdate
func (manager *TableManager) ProcessUpdate(fromPeer *PeerInfo, message *bgp.BGPMessage) ([]Path, []Destination, error) {

	var bestPaths []Path = make([]Path, 0)
	var lostDest []Destination = make([]Destination, 0)

	// check msg's type if it's BGPUpdate
	body := message.Body
	switch body.(type) {
	case *bgp.BGPUpdate:

		msg := &ProcessMessage{
			innerMessage: message,
			fromPeer:     fromPeer,
		}

		// get destination list
		destList, err := manager.handleNlri(msg)
		if err != nil {
			logger.Error(err)
			return nil, nil, err
		}

		wDestList, err := manager.handleWithdraw(msg)
		if err != nil {
			logger.Error(err)
			return nil, nil, err
		}

		mpreachDestList, err := manager.handleMPReachNlri(msg)
		if err != nil {
			logger.Error(err)
			return nil, nil, err
		}

		mpunreachDestList, err := manager.handleMPUNReachNlri(msg)
		if err != nil {
			logger.Error(err)
			return nil, nil, err
		}
		// merge destList and wDestList
		destinationList := append(destList, wDestList...)
		destinationList = append(destinationList, mpreachDestList...)
		destinationList = append(destinationList, mpunreachDestList...)

		// check best path changed
		if destinationList != nil {
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
		}
	default:
		logger.Warn("message is not BGPUpdate")
	}

	return bestPaths, lostDest, nil
}

type ReceivedRoute struct {
	path      Path
	fromPeer  *net.IP
	filtered  bool
	timestamp time.Time
}

func (rr *ReceivedRoute) String() string {
	return rr.path.(*PathDefault).getPrefix().String()
}

func NewReceivedRoute(path Path, peer *net.IP, filtered bool) *ReceivedRoute {

	rroute := &ReceivedRoute{
		path:      path,
		fromPeer:  peer,
		filtered:  filtered,
		timestamp: time.Now(),
	}
	return rroute
}
