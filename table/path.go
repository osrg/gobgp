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
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/packet"
	"net"
	"reflect"
	"time"
)

type Path interface {
	String() string
	getPathAttrs() []bgp.PathAttributeInterface
	getPathAttr(bgp.BGPAttrType) (int, bgp.PathAttributeInterface)
	GetRouteFamily() bgp.RouteFamily
	setSource(source *PeerInfo)
	getSource() *PeerInfo
	setNexthop(nexthop net.IP)
	getNexthop() net.IP
	setWithdraw(withdraw bool)
	IsWithdraw() bool
	getNlri() bgp.AddrPrefixInterface
	getPrefix() string
	setMedSetByTargetNeighbor(medSetByTargetNeighbor bool)
	getMedSetByTargetNeighbor() bool
	clone(IsWithdraw bool) Path
	getTimestamp() time.Time
	setTimestamp(t time.Time)
	MarshalJSON() ([]byte, error)
}

type PathDefault struct {
	routeFamily            bgp.RouteFamily
	source                 *PeerInfo
	nexthop                net.IP
	withdraw               bool
	nlri                   bgp.AddrPrefixInterface
	pathAttrs              []bgp.PathAttributeInterface
	medSetByTargetNeighbor bool
	timestamp              time.Time
}

func NewPathDefault(rf bgp.RouteFamily, source *PeerInfo, nlri bgp.AddrPrefixInterface, nexthop net.IP, isWithdraw bool, pattrs []bgp.PathAttributeInterface, medSetByTargetNeighbor bool, now time.Time) *PathDefault {

	if !isWithdraw && pattrs == nil {
		log.Error("Need to provide nexthop and patattrs for path that is not a withdraw.")
		return nil
	}

	path := &PathDefault{}
	path.routeFamily = rf
	path.pathAttrs = pattrs
	path.nlri = nlri
	path.source = source
	path.nexthop = nexthop
	path.withdraw = isWithdraw
	path.medSetByTargetNeighbor = medSetByTargetNeighbor
	path.timestamp = now
	return path
}

func (pd *PathDefault) getTimestamp() time.Time {
	return pd.timestamp
}

func (pd *PathDefault) setTimestamp(t time.Time) {
	pd.timestamp = t
}

func (pd *PathDefault) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Network string
		Nexthop string
		Attrs   []bgp.PathAttributeInterface
		Age     float64
	}{
		Network: pd.getPrefix(),
		Nexthop: pd.nexthop.String(),
		Attrs:   pd.getPathAttrs(),
		Age:     time.Now().Sub(pd.timestamp).Seconds(),
	})
}

// create new PathAttributes
func (pd *PathDefault) clone(isWithdraw bool) Path {
	nlri := pd.nlri
	if isWithdraw {
		if pd.IsWithdraw() {
			log.Fatal("Withdraw path is not supposed to be cloned")
		} else {
			nlri = &bgp.WithdrawnRoute{pd.nlri.(*bgp.NLRInfo).IPAddrPrefix}
		}
	}
	return CreatePath(pd.source, nlri, pd.pathAttrs, isWithdraw, pd.timestamp)
}

func (pd *PathDefault) GetRouteFamily() bgp.RouteFamily {
	return pd.routeFamily
}

func (pd *PathDefault) setSource(source *PeerInfo) {
	pd.source = source
}
func (pd *PathDefault) getSource() *PeerInfo {
	return pd.source
}

func (pd *PathDefault) setNexthop(nexthop net.IP) {
	pd.nexthop = nexthop
}

func (pd *PathDefault) getNexthop() net.IP {
	return pd.nexthop
}

func (pd *PathDefault) setWithdraw(withdraw bool) {
	pd.withdraw = withdraw
}

func (pd *PathDefault) IsWithdraw() bool {
	return pd.withdraw
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

func (pd *PathDefault) getPathAttrs() []bgp.PathAttributeInterface {
	return pd.pathAttrs
}

func (pd *PathDefault) getPathAttr(pattrType bgp.BGPAttrType) (int, bgp.PathAttributeInterface) {
	attrMap := [bgp.BGP_ATTR_TYPE_AS4_AGGREGATOR + 1]reflect.Type{}
	attrMap[bgp.BGP_ATTR_TYPE_ORIGIN] = reflect.TypeOf(&bgp.PathAttributeOrigin{})
	attrMap[bgp.BGP_ATTR_TYPE_AS_PATH] = reflect.TypeOf(&bgp.PathAttributeAsPath{})
	attrMap[bgp.BGP_ATTR_TYPE_NEXT_HOP] = reflect.TypeOf(&bgp.PathAttributeNextHop{})
	attrMap[bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC] = reflect.TypeOf(&bgp.PathAttributeMultiExitDisc{})
	attrMap[bgp.BGP_ATTR_TYPE_LOCAL_PREF] = reflect.TypeOf(&bgp.PathAttributeLocalPref{})
	attrMap[bgp.BGP_ATTR_TYPE_ATOMIC_AGGREGATE] = reflect.TypeOf(&bgp.PathAttributeAtomicAggregate{})
	attrMap[bgp.BGP_ATTR_TYPE_AGGREGATOR] = reflect.TypeOf(&bgp.PathAttributeAggregator{})
	attrMap[bgp.BGP_ATTR_TYPE_COMMUNITIES] = reflect.TypeOf(&bgp.PathAttributeCommunities{})
	attrMap[bgp.BGP_ATTR_TYPE_ORIGINATOR_ID] = reflect.TypeOf(&bgp.PathAttributeOriginatorId{})
	attrMap[bgp.BGP_ATTR_TYPE_CLUSTER_LIST] = reflect.TypeOf(&bgp.PathAttributeClusterList{})
	attrMap[bgp.BGP_ATTR_TYPE_MP_REACH_NLRI] = reflect.TypeOf(&bgp.PathAttributeMpReachNLRI{})
	attrMap[bgp.BGP_ATTR_TYPE_MP_UNREACH_NLRI] = reflect.TypeOf(&bgp.PathAttributeMpUnreachNLRI{})
	attrMap[bgp.BGP_ATTR_TYPE_EXTENDED_COMMUNITIES] = reflect.TypeOf(&bgp.PathAttributeExtendedCommunities{})
	attrMap[bgp.BGP_ATTR_TYPE_AS4_PATH] = reflect.TypeOf(&bgp.PathAttributeAs4Path{})
	attrMap[bgp.BGP_ATTR_TYPE_AS4_AGGREGATOR] = reflect.TypeOf(&bgp.PathAttributeAs4Aggregator{})

	t := attrMap[pattrType]
	for i, p := range pd.pathAttrs {
		if t == reflect.TypeOf(p) {
			return i, p
		}
	}
	return -1, nil
}

// return Path's string representation
func (pi *PathDefault) String() string {
	str := fmt.Sprintf("IPv4Path Source: %v, ", pi.getSource())
	str = str + fmt.Sprintf(" NLRI: %s, ", pi.getPrefix())
	str = str + fmt.Sprintf(" nexthop: %s, ", pi.getNexthop().String())
	str = str + fmt.Sprintf(" withdraw: %s, ", pi.IsWithdraw())
	//str = str + fmt.Sprintf(" path attributes: %s, ", pi.getPathAttributeMap())
	return str
}

func (pi *PathDefault) getPrefix() string {
	switch nlri := pi.nlri.(type) {
	case *bgp.NLRInfo:
		return nlri.IPAddrPrefix.IPAddrPrefixDefault.String()
	case *bgp.WithdrawnRoute:
		return nlri.IPAddrPrefix.IPAddrPrefixDefault.String()
	}
	log.Fatal()
	return ""
}

// create Path object based on route family
func CreatePath(source *PeerInfo, nlri bgp.AddrPrefixInterface, attrs []bgp.PathAttributeInterface, isWithdraw bool, now time.Time) Path {

	rf := bgp.RouteFamily(int(nlri.AFI())<<16 | int(nlri.SAFI()))
	log.Debugf("afi: %d, safi: %d ", int(nlri.AFI()), nlri.SAFI())
	var path Path

	switch rf {
	case bgp.RF_IPv4_UC:
		log.Debugf("RouteFamily : %s", bgp.RF_IPv4_UC.String())
		path = NewIPv4Path(source, nlri, isWithdraw, attrs, false, now)
	case bgp.RF_IPv6_UC:
		log.Debugf("RouteFamily : %s", bgp.RF_IPv6_UC.String())
		path = NewIPv6Path(source, nlri, isWithdraw, attrs, false, now)
	}
	return path
}

/*
* 	Definition of inherited Path  interface
 */
type IPv4Path struct {
	*PathDefault
}

func NewIPv4Path(source *PeerInfo, nlri bgp.AddrPrefixInterface, isWithdraw bool, attrs []bgp.PathAttributeInterface, medSetByTargetNeighbor bool, now time.Time) *IPv4Path {
	ipv4Path := &IPv4Path{}
	ipv4Path.PathDefault = NewPathDefault(bgp.RF_IPv4_UC, source, nlri, nil, isWithdraw, attrs, medSetByTargetNeighbor, now)
	if !isWithdraw {
		_, nexthop_attr := ipv4Path.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
		ipv4Path.nexthop = nexthop_attr.(*bgp.PathAttributeNextHop).Value
	}
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

func NewIPv6Path(source *PeerInfo, nlri bgp.AddrPrefixInterface, isWithdraw bool, attrs []bgp.PathAttributeInterface, medSetByTargetNeighbor bool, now time.Time) *IPv6Path {
	ipv6Path := &IPv6Path{}
	ipv6Path.PathDefault = NewPathDefault(bgp.RF_IPv6_UC, source, nlri, nil, isWithdraw, attrs, medSetByTargetNeighbor, now)
	if !isWithdraw {
		_, mpattr := ipv6Path.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
		ipv6Path.nexthop = mpattr.(*bgp.PathAttributeMpReachNLRI).Nexthop
	}
	return ipv6Path
}

func (ipv6p *IPv6Path) clone(isWithdraw bool) Path {
	nlri := ipv6p.nlri
	if isWithdraw {
		if ipv6p.IsWithdraw() {
			log.Fatal("Withdraw path is not supposed to be cloned")
		}
	}
	return CreatePath(ipv6p.source, nlri, ipv6p.pathAttrs, isWithdraw, ipv6p.PathDefault.timestamp)
}

func (ipv6p *IPv6Path) setPathDefault(pd *PathDefault) {
	ipv6p.PathDefault = pd
}

func (ipv6p *IPv6Path) getPathDefault() *PathDefault {
	return ipv6p.PathDefault
}

func (ipv6p *IPv6Path) getPrefix() string {
	addrPrefix := ipv6p.nlri.(*bgp.IPv6AddrPrefix)
	return addrPrefix.IPAddrPrefixDefault.String()
}

// return IPv6Path's string representation
func (ipv6p *IPv6Path) String() string {
	str := fmt.Sprintf("IPv6Path Source: %v, ", ipv6p.getSource())
	str = str + fmt.Sprintf(" NLRI: %s, ", ipv6p.getPrefix())
	str = str + fmt.Sprintf(" nexthop: %s, ", ipv6p.getNexthop().String())
	str = str + fmt.Sprintf(" withdraw: %s, ", ipv6p.IsWithdraw())
	//str = str + fmt.Sprintf(" path attributes: %s, ", ipv6p.getPathAttributeMap())
	return str
}

func (ipv6p *IPv6Path) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Network string
		Nexthop string
		Attrs   []bgp.PathAttributeInterface
		Age     float64
	}{
		Network: ipv6p.getPrefix(),
		Nexthop: ipv6p.PathDefault.nexthop.String(),
		Attrs:   ipv6p.PathDefault.getPathAttrs(),
		Age:     time.Now().Sub(ipv6p.PathDefault.timestamp).Seconds(),
	})
}
