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
	"fmt"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/utils"
	"net"
)

type Path interface {
	String() string
	getPathAttributeMap() *utils.OrderedMap
	getPathAttribute(int) bgp.PathAttributeInterface
	clone(forWithdrawal bool) Path
	setRouteFamily(ROUTE_FAMILY RouteFamily)
	getRouteFamily() RouteFamily
	setSource(source *Peer)
	getSource() *Peer
	setNexthop(nexthop net.IP)
	getNexthop() net.IP
	setSourceVerNum(sourceVerNum int)
	getSourceVerNum() int
	setWithdraw(withdraw bool)
	isWithdraw() bool
	setNlri(nlri bgp.AddrPrefixInterface)
	getNlri() bgp.AddrPrefixInterface
	getPrefix() net.IP
	setMedSetByTargetNeighbor(medSetByTargetNeighbor bool)
	getMedSetByTargetNeighbor() bool
}

type PathDefault struct {
	ROUTE_FAMILY           RouteFamily
	source                 *Peer
	nexthop                net.IP
	sourceVerNum           int
	withdraw               bool
	nlri                   bgp.AddrPrefixInterface
	pattrMap               *utils.OrderedMap
	medSetByTargetNeighbor bool
}

func NewPathDefault(source *Peer, nlri bgp.AddrPrefixInterface, sourceVerNum int, nexthop net.IP,
	isWithdraw bool, pattr *utils.OrderedMap, medSetByTargetNeighbor bool) *PathDefault {

	if !isWithdraw && (pattr == nil || nexthop == nil) {
		logger.Error("Need to provide nexthop and patattrs for path that is not a withdraw.")
		return nil
	}

	path := &PathDefault{}
	path.ROUTE_FAMILY = RF_IPv4_UC
	path.pattrMap = utils.NewOrderedMap()
	if pattr != nil {
		keyList := pattr.KeyLists()
		for key := keyList.Front(); key != nil; key = key.Next() {
			key := key.Value
			val := pattr.Get(key)
			e := path.pattrMap.Append(key, val)
			if e != nil {
				logger.Error(e)
			}
		}
	}
	path.nlri = nlri
	path.source = source
	path.nexthop = nexthop
	path.sourceVerNum = sourceVerNum
	path.withdraw = isWithdraw
	path.medSetByTargetNeighbor = medSetByTargetNeighbor

	return path
}

func (pd *PathDefault) setRouteFamily(ROUTE_FAMILY RouteFamily) {
	pd.ROUTE_FAMILY = ROUTE_FAMILY
}
func (pd *PathDefault) getRouteFamily() RouteFamily {
	return pd.ROUTE_FAMILY
}

func (pd *PathDefault) setSource(source *Peer) {
	pd.source = source
}
func (pd *PathDefault) getSource() *Peer {
	return pd.source
}

func (pd *PathDefault) setNexthop(nexthop net.IP) {
	pd.nexthop = nexthop
}

func (pd *PathDefault) getNexthop() net.IP {
	return pd.nexthop
}

func (pd *PathDefault) setSourceVerNum(sourceVerNum int) {
	pd.sourceVerNum = sourceVerNum
}

func (pd *PathDefault) getSourceVerNum() int {
	return pd.sourceVerNum
}

func (pd *PathDefault) setWithdraw(withdraw bool) {
	pd.withdraw = withdraw
}

func (pd *PathDefault) isWithdraw() bool {
	return pd.withdraw
}

func (pd *PathDefault) setNlri(nlri bgp.AddrPrefixInterface) {
	pd.nlri = nlri
}

func (pd *PathDefault) getNlri() bgp.AddrPrefixInterface {
	return pd.nlri
}

func (pd *PathDefault) setMedSetByTargetNeighbor(medSetByTargetNeighbor bool) {
	pd.medSetByTargetNeighbor = medSetByTargetNeighbor
}

func (pd *PathDefault) getMedSetByTargetNeighbor() bool {
	return pd.medSetByTargetNeighbor
}

//Copy the entity
func (pd *PathDefault) getPathAttributeMap() *utils.OrderedMap {
	cpPattr := utils.NewOrderedMap()
	keyList := pd.pattrMap.KeyLists()
	for key := keyList.Front(); key != nil; key = key.Next() {
		key := key.Value
		val := pd.pattrMap.Get(key)
		e := cpPattr.Append(key, val)
		if e != nil {
			logger.Error(e)
		}
	}
	return cpPattr
}

func (pd *PathDefault) getPathAttribute(pattrType int) bgp.PathAttributeInterface {
	attr := pd.pattrMap.Get(pattrType)
	if attr == nil {
		logger.Debugf("Attribute Type %s is not found", AttributeType(pattrType))
		return nil
	}
	return attr.(bgp.PathAttributeInterface)
}

func (pi *PathDefault) clone(forWithdrawal bool) Path {
	pathAttrs := utils.NewOrderedMap()
	if !forWithdrawal {
		pathAttrs = pi.getPathAttributeMap()
	}
	def := NewPathDefault(pi.getSource(), pi.getNlri(), pi.getSourceVerNum(),
		pi.getNexthop(), forWithdrawal, pathAttrs, pi.getMedSetByTargetNeighbor())
	switch pi.ROUTE_FAMILY {
	case RF_IPv4_UC:
		return &IPv4Path{PathDefault: def}
	case RF_IPv6_UC:
		return &IPv6Path{PathDefault: def}
	default:
		return def
	}
}

// return Path's string representation
func (pi *PathDefault) String() string {
	str := fmt.Sprintf("IPv4Path Source: %d, ", pi.getSourceVerNum())
	str = str + fmt.Sprintf(" NLRI: %s, ", pi.getPrefix().String())
	str = str + fmt.Sprintf(" nexthop: %s, ", pi.getNexthop().String())
	str = str + fmt.Sprintf(" withdraw: %s, ", pi.isWithdraw())
	str = str + fmt.Sprintf(" path attributes: %s, ", pi.getPathAttributeMap())
	return str
}

func (pi *PathDefault) getPrefix() net.IP {

	switch nlri := pi.nlri.(type) {
	case *bgp.NLRInfo:
		return nlri.Prefix
	case *bgp.WithdrawnRoute:
		return nlri.Prefix
	}
	return nil
}

func createPathAttributeMap(pathAttributes []bgp.PathAttributeInterface) *utils.OrderedMap {

	pathAttrMap := utils.NewOrderedMap()
	for _, attr := range pathAttributes {
		var err error
		switch a := attr.(type) {
		case *bgp.PathAttributeOrigin:
			err = pathAttrMap.Append(bgp.BGP_ATTR_TYPE_ORIGIN, a)
		case *bgp.PathAttributeAsPath:
			err = pathAttrMap.Append(bgp.BGP_ATTR_TYPE_AS_PATH, a)
		case *bgp.PathAttributeNextHop:
			err = pathAttrMap.Append(bgp.BGP_ATTR_TYPE_NEXT_HOP, a)
		case *bgp.PathAttributeMultiExitDisc:
			err = pathAttrMap.Append(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC, a)
		case *bgp.PathAttributeLocalPref:
			err = pathAttrMap.Append(bgp.BGP_ATTR_TYPE_LOCAL_PREF, a)
		case *bgp.PathAttributeAtomicAggregate:
			err = pathAttrMap.Append(bgp.BGP_ATTR_TYPE_ATOMIC_AGGREGATE, a)
		case *bgp.PathAttributeAggregator:
			err = pathAttrMap.Append(bgp.BGP_ATTR_TYPE_AGGREGATOR, a)
		case *bgp.PathAttributeCommunities:
			err = pathAttrMap.Append(bgp.BGP_ATTR_TYPE_COMMUNITIES, a)
		case *bgp.PathAttributeOriginatorId:
			err = pathAttrMap.Append(bgp.BGP_ATTR_TYPE_ORIGINATOR_ID, a)
		case *bgp.PathAttributeClusterList:
			err = pathAttrMap.Append(bgp.BGP_ATTR_TYPE_CLUSTER_LIST, a)
		case *bgp.PathAttributeMpReachNLRI:
			err = pathAttrMap.Append(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI, a)
		case *bgp.PathAttributeMpUnreachNLRI:
			err = pathAttrMap.Append(bgp.BGP_ATTR_TYPE_MP_UNREACH_NLRI, a)
		case *bgp.PathAttributeExtendedCommunities:
			err = pathAttrMap.Append(bgp.BGP_ATTR_TYPE_EXTENDED_COMMUNITIES, a)
		case *bgp.PathAttributeAs4Path:
			err = pathAttrMap.Append(bgp.BGP_ATTR_TYPE_AS4_PATH, a)
		case *bgp.PathAttributeAs4Aggregator:
			err = pathAttrMap.Append(bgp.BGP_ATTR_TYPE_AS4_AGGREGATOR, a)
		}
		if err != nil {
			return nil
		}
	}
	return pathAttrMap
}

// create Path object based on route family
func CreatePath(source *Peer, nlri bgp.AddrPrefixInterface,
	pathAttributes []bgp.PathAttributeInterface, isWithdraw bool) Path {

	rf := RouteFamily(int(nlri.AFI())<<16 | int(nlri.SAFI()))
	logger.Debugf("afi: %d, safi: %d ", int(nlri.AFI()), nlri.SAFI())
	pathAttrMap := createPathAttributeMap(pathAttributes)
	var path Path
	var sourceVerNum int = 1

	if source != nil {
		sourceVerNum = source.VersionNum
	}

	switch rf {
	case RF_IPv4_UC:
		logger.Debugf("RouteFamily : %s", RF_IPv4_UC.String())
		var nexthop net.IP

		if !isWithdraw {
			nexthop_attr := pathAttrMap.Get(bgp.BGP_ATTR_TYPE_NEXT_HOP).(*bgp.PathAttributeNextHop)
			nexthop = nexthop_attr.Value
		} else {
			nexthop = nil
		}

		path = NewIPv4Path(source, nlri, sourceVerNum, nexthop, isWithdraw, pathAttrMap, false)
	case RF_IPv6_UC:
		logger.Debugf("RouteFamily : %s", RF_IPv6_UC.String())
		var nexthop net.IP

		if !isWithdraw {
			mpattr := pathAttrMap.Get(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI).(*bgp.PathAttributeMpReachNLRI)
			nexthop = mpattr.Nexthop
		} else {
			nexthop = nil
		}
		path = NewIPv6Path(source, nlri, sourceVerNum, nexthop, isWithdraw, pathAttrMap, false)
	}
	return path
}

/*
* 	Definition of inherited Path  interface
 */
type IPv4Path struct {
	*PathDefault
}

func NewIPv4Path(source *Peer, nlri bgp.AddrPrefixInterface, sourceVerNum int, nexthop net.IP,
	isWithdraw bool, pattr *utils.OrderedMap, medSetByTargetNeighbor bool) *IPv4Path {
	ipv4Path := &IPv4Path{}
	ipv4Path.PathDefault = NewPathDefault(source, nlri, sourceVerNum, nexthop, isWithdraw, pattr, medSetByTargetNeighbor)
	ipv4Path.PathDefault.ROUTE_FAMILY = RF_IPv4_UC
	return ipv4Path
}

func (ipv4p *IPv4Path) setPathDefault(pd *PathDefault) {
	ipv4p.PathDefault = pd
}
func (ipv4p *IPv4Path) getPathDefault() *PathDefault {
	return ipv4p.PathDefault
}

type IPv6Path struct {
	*PathDefault
}

func NewIPv6Path(source *Peer, nlri bgp.AddrPrefixInterface, sourceVerNum int, nexthop net.IP,
	isWithdraw bool, pattr *utils.OrderedMap, medSetByTargetNeighbor bool) *IPv6Path {
	ipv6Path := &IPv6Path{}
	ipv6Path.PathDefault = NewPathDefault(source, nlri, sourceVerNum, nexthop, isWithdraw, pattr, medSetByTargetNeighbor)
	ipv6Path.PathDefault.ROUTE_FAMILY = RF_IPv6_UC
	return ipv6Path
}

func (ipv6p *IPv6Path) setPathDefault(pd *PathDefault) {
	ipv6p.PathDefault = pd
}

func (ipv6p *IPv6Path) getPathDefault() *PathDefault {
	return ipv6p.PathDefault
}

func (ipv6p *IPv6Path) getPrefix() net.IP {
	addrPrefix := ipv6p.nlri.(*bgp.IPv6AddrPrefix)
	return addrPrefix.Prefix
}

// return IPv6Path's string representation
func (ipv6p *IPv6Path) String() string {
	str := fmt.Sprintf("IPv6Path Source: %d, ", ipv6p.getSourceVerNum())
	str = str + fmt.Sprintf(" NLRI: %s, ", ipv6p.getPrefix().String())
	str = str + fmt.Sprintf(" nexthop: %s, ", ipv6p.getNexthop().String())
	str = str + fmt.Sprintf(" withdraw: %s, ", ipv6p.isWithdraw())
	str = str + fmt.Sprintf(" path attributes: %s, ", ipv6p.getPathAttributeMap())
	return str
}
