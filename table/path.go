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
	"github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"net"
	"reflect"
	"time"
)

type Path interface {
	String() string
	getPathAttrs() []bgp.PathAttributeInterface
	getPathAttr(bgp.BGPAttrType) (int, bgp.PathAttributeInterface)
	updatePathAttrs(global *config.Global, peer *config.Neighbor)
	GetRouteFamily() bgp.RouteFamily
	setSource(source *PeerInfo)
	GetSource() *PeerInfo
	GetSourceAs() uint32
	GetNexthop() net.IP
	SetNexthop(net.IP)
	setWithdraw(withdraw bool)
	IsWithdraw() bool
	GetNlri() bgp.AddrPrefixInterface
	getPrefix() string
	setMedSetByTargetNeighbor(medSetByTargetNeighbor bool)
	getMedSetByTargetNeighbor() bool
	Clone(IsWithdraw bool) Path
	getTimestamp() time.Time
	setTimestamp(t time.Time)
	ToApiStruct() *api.Path
	MarshalJSON() ([]byte, error)
	Equal(p Path) bool
}

type PathDefault struct {
	routeFamily            bgp.RouteFamily
	source                 *PeerInfo
	withdraw               bool
	nlri                   bgp.AddrPrefixInterface
	pathAttrs              []bgp.PathAttributeInterface
	medSetByTargetNeighbor bool
	timestamp              time.Time
}

func NewPathDefault(rf bgp.RouteFamily, source *PeerInfo, nlri bgp.AddrPrefixInterface, isWithdraw bool, pattrs []bgp.PathAttributeInterface, medSetByTargetNeighbor bool, now time.Time) *PathDefault {
	if !isWithdraw && pattrs == nil {
		log.WithFields(log.Fields{
			"Topic": "Table",
			"Key":   nlri.String(),
			"Peer":  source.Address.String(),
		}).Error("Need to provide patattrs for the path that is not withdraw.")
		return nil
	}

	path := &PathDefault{}
	path.routeFamily = rf
	path.pathAttrs = pattrs
	path.nlri = nlri
	path.source = source
	path.withdraw = isWithdraw
	path.medSetByTargetNeighbor = medSetByTargetNeighbor
	path.timestamp = now
	return path
}

func cloneAsPath(asAttr *bgp.PathAttributeAsPath) *bgp.PathAttributeAsPath {
	newASparams := make([]bgp.AsPathParamInterface, len(asAttr.Value))
	for i, param := range asAttr.Value {
		asParam := param.(*bgp.As4PathParam)
		as := make([]uint32, len(asParam.AS))
		copy(as, asParam.AS)
		newASparams[i] = bgp.NewAs4PathParam(asParam.Type, as)
	}
	return bgp.NewPathAttributeAsPath(newASparams)
}

func (pd *PathDefault) updatePathAttrs(global *config.Global, peer *config.Neighbor) {

	if peer.RouteServer.RouteServerClient {
		return
	}

	if peer.PeerType == config.PEER_TYPE_EXTERNAL {
		// NEXTHOP handling
		pd.SetNexthop(peer.LocalAddress)

		// AS_PATH handling
		//
		//  When a given BGP speaker advertises the route to an external
		//  peer, the advertising speaker updates the AS_PATH attribute
		//  as follows:
		//  1) if the first path segment of the AS_PATH is of type
		//     AS_SEQUENCE, the local system prepends its own AS num as
		//     the last element of the sequence (put it in the left-most
		//     position with respect to the position of  octets in the
		//     protocol message).  If the act of prepending will cause an
		//     overflow in the AS_PATH segment (i.e.,  more than 255
		//     ASes), it SHOULD prepend a new segment of type AS_SEQUENCE
		//     and prepend its own AS number to this new segment.
		//
		//  2) if the first path segment of the AS_PATH is of type AS_SET
		//     , the local system prepends a new path segment of type
		//     AS_SEQUENCE to the AS_PATH, including its own AS number in
		//     that segment.
		//
		//  3) if the AS_PATH is empty, the local system creates a path
		//     segment of type AS_SEQUENCE, places its own AS into that
		//     segment, and places that segment into the AS_PATH.
		idx, originalAsPath := pd.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
		if idx < 0 {
			log.Fatal("missing AS_PATH mandatory attribute")
		}
		asPath := cloneAsPath(originalAsPath.(*bgp.PathAttributeAsPath))
		pd.pathAttrs[idx] = asPath
		fst := asPath.Value[0].(*bgp.As4PathParam)
		if len(asPath.Value) > 0 && fst.Type == bgp.BGP_ASPATH_ATTR_TYPE_SEQ &&
			fst.ASLen() < 255 {
			fst.AS = append([]uint32{global.As}, fst.AS...)
			fst.Num += 1
		} else {
			p := bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{global.As})
			asPath.Value = append([]bgp.AsPathParamInterface{p}, asPath.Value...)
		}

		// MED Handling
		idx, _ = pd.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
		if idx >= 0 {
			pd.pathAttrs = append(pd.pathAttrs[:idx], pd.pathAttrs[idx+1:]...)
		}
	} else if peer.PeerType == config.PEER_TYPE_INTERNAL {
		// For iBGP peers we are required to send local-pref attribute
		// for connected or local prefixes.
		// We set default local-pref 100.
		p := bgp.NewPathAttributeLocalPref(100)
		idx, _ := pd.getPathAttr(bgp.BGP_ATTR_TYPE_LOCAL_PREF)
		if idx < 0 {
			pd.pathAttrs = append(pd.pathAttrs, p)
		} else {
			pd.pathAttrs[idx] = p
		}
	} else {
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   peer.NeighborAddress,
		}).Warnf("invalid peer type: %d", peer.PeerType)
	}
}

func (pd *PathDefault) getTimestamp() time.Time {
	return pd.timestamp
}

func (pd *PathDefault) setTimestamp(t time.Time) {
	pd.timestamp = t
}

func (pd *PathDefault) ToApiStruct() *api.Path {
	pathAttrs := func(arg []bgp.PathAttributeInterface) []*api.PathAttr {
		ret := make([]*api.PathAttr, 0, len(arg))
		for _, a := range arg {
			ret = append(ret, a.ToApiStruct())
		}
		return ret
	}(pd.getPathAttrs())
	return &api.Path{
		Nlri:       pd.GetNlri().ToApiStruct(),
		Nexthop:    pd.GetNexthop().String(),
		Attrs:      pathAttrs,
		Age:        int64(time.Now().Sub(pd.timestamp).Seconds()),
		IsWithdraw: pd.IsWithdraw(),
	}
}

func (pd *PathDefault) MarshalJSON() ([]byte, error) {
	return json.Marshal(pd.ToApiStruct())
}

// create new PathAttributes
func (pd *PathDefault) Clone(isWithdraw bool) Path {
	nlri := pd.nlri
	if pd.GetRouteFamily() == bgp.RF_IPv4_UC && isWithdraw {
		if pd.IsWithdraw() {
			nlri = pd.nlri
		} else {
			nlri = &bgp.WithdrawnRoute{pd.nlri.(*bgp.NLRInfo).IPAddrPrefix}
		}
	}

	newPathAttrs := make([]bgp.PathAttributeInterface, len(pd.pathAttrs))
	for i, v := range pd.pathAttrs {
		newPathAttrs[i] = v
	}

	path, _ := CreatePath(pd.source, nlri, newPathAttrs, isWithdraw, pd.timestamp)
	return path
}

func (pd *PathDefault) GetRouteFamily() bgp.RouteFamily {
	return pd.routeFamily
}

func (pd *PathDefault) setSource(source *PeerInfo) {
	pd.source = source
}
func (pd *PathDefault) GetSource() *PeerInfo {
	return pd.source
}

func (pd *PathDefault) GetSourceAs() uint32 {
	_, attr := pd.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	if attr != nil {
		asPathParam := attr.(*bgp.PathAttributeAsPath).Value
		if len(asPathParam) == 0 {
			return 0
		}
		asPath := asPathParam[len(asPathParam)-1].(*bgp.As4PathParam)
		if asPath.Num == 0 {
			return 0
		}
		return asPath.AS[asPath.Num-1]
	}
	return 0
}

func (pd *PathDefault) GetNexthop() net.IP {
	_, attr := pd.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	if attr != nil {
		return attr.(*bgp.PathAttributeNextHop).Value
	}
	_, attr = pd.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
	if attr != nil {
		return attr.(*bgp.PathAttributeMpReachNLRI).Nexthop
	}
	return net.IP{}
}

func (pd *PathDefault) SetNexthop(nexthop net.IP) {
	idx, attr := pd.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	if attr != nil {
		newNexthop := bgp.NewPathAttributeNextHop(nexthop.String())
		pd.pathAttrs[idx] = newNexthop
	}
	idx, attr = pd.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
	if attr != nil {
		oldNlri := attr.(*bgp.PathAttributeMpReachNLRI)
		newNlri := bgp.NewPathAttributeMpReachNLRI(nexthop.String(), oldNlri.Value)
		pd.pathAttrs[idx] = newNlri
	}
}

func (pd *PathDefault) setWithdraw(withdraw bool) {
	pd.withdraw = withdraw
}

func (pd *PathDefault) IsWithdraw() bool {
	return pd.withdraw
}

func (pd *PathDefault) GetNlri() bgp.AddrPrefixInterface {
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
func (pd *PathDefault) String() string {
	str := fmt.Sprintf("IPv4Path Source: %v, ", pd.GetSource())
	str = str + fmt.Sprintf(" NLRI: %s, ", pd.getPrefix())
	str = str + fmt.Sprintf(" nexthop: %s, ", pd.GetNexthop().String())
	str = str + fmt.Sprintf(" withdraw: %s, ", pd.IsWithdraw())
	//str = str + fmt.Sprintf(" path attributes: %s, ", pi.getPathAttributeMap())
	return str
}

func (pd *PathDefault) getPrefix() string {
	return pd.nlri.String()
}

func (pd *PathDefault) Equal(p Path) bool {
	if p == nil {
		return false
	} else if pd == p {
		return true
	}
	serialize := func(p Path) string {
		a := p.ToApiStruct()
		a.Age = 0
		a.Best = false
		j, _ := json.Marshal(a)
		return string(j)
	}
	return serialize(pd) == serialize(p)
}

// create Path object based on route family
func CreatePath(source *PeerInfo, nlri bgp.AddrPrefixInterface, attrs []bgp.PathAttributeInterface, isWithdraw bool, now time.Time) (Path, error) {

	rf := bgp.RouteFamily(int(nlri.AFI())<<16 | int(nlri.SAFI()))
	log.Debugf("CreatePath afi: %d, safi: %d ", int(nlri.AFI()), nlri.SAFI())
	var path Path

	switch rf {
	case bgp.RF_IPv4_UC:
		log.Debugf("CreatePath RouteFamily : %s", bgp.RF_IPv4_UC.String())
		path = NewIPv4Path(source, nlri, isWithdraw, attrs, false, now)
	case bgp.RF_IPv6_UC:
		log.Debugf("CreatePath RouteFamily : %s", bgp.RF_IPv6_UC.String())
		path = NewIPv6Path(source, nlri, isWithdraw, attrs, false, now)
	case bgp.RF_IPv4_VPN:
		log.Debugf("CreatePath RouteFamily : %s", bgp.RF_IPv4_VPN.String())
		path = NewIPv4VPNPath(source, nlri, isWithdraw, attrs, false, now)
	case bgp.RF_EVPN:
		log.Debugf("CreatePath RouteFamily : %s", bgp.RF_EVPN.String())
		path = NewEVPNPath(source, nlri, isWithdraw, attrs, false, now)
	case bgp.RF_ENCAP:
		log.Debugf("CreatePath RouteFamily : %s", bgp.RF_ENCAP.String())
		path = NewEncapPath(source, nlri, isWithdraw, attrs, false, now)
	default:
		return path, fmt.Errorf("Unsupported RouteFamily: %s", rf)
	}
	return path, nil
}

/*
* 	Definition of inherited Path  interface
 */
type IPv4Path struct {
	*PathDefault
}

func NewIPv4Path(source *PeerInfo, nlri bgp.AddrPrefixInterface, isWithdraw bool, attrs []bgp.PathAttributeInterface, medSetByTargetNeighbor bool, now time.Time) *IPv4Path {
	ipv4Path := &IPv4Path{}
	ipv4Path.PathDefault = NewPathDefault(bgp.RF_IPv4_UC, source, nlri, isWithdraw, attrs, medSetByTargetNeighbor, now)
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
	ipv6Path.PathDefault = NewPathDefault(bgp.RF_IPv6_UC, source, nlri, isWithdraw, attrs, medSetByTargetNeighbor, now)
	return ipv6Path
}

func (ipv6p *IPv6Path) setPathDefault(pd *PathDefault) {
	ipv6p.PathDefault = pd
}

func (ipv6p *IPv6Path) getPathDefault() *PathDefault {
	return ipv6p.PathDefault
}

// return IPv6Path's string representation
func (ipv6p *IPv6Path) String() string {
	str := fmt.Sprintf("IPv6Path Source: %v, ", ipv6p.GetSource())
	str = str + fmt.Sprintf(" NLRI: %s, ", ipv6p.getPrefix())
	str = str + fmt.Sprintf(" nexthop: %s, ", ipv6p.GetNexthop().String())
	str = str + fmt.Sprintf(" withdraw: %s, ", ipv6p.IsWithdraw())
	//str = str + fmt.Sprintf(" path attributes: %s, ", ipv6p.getPathAttributeMap())
	return str
}

type IPv4VPNPath struct {
	*PathDefault
}

func NewIPv4VPNPath(source *PeerInfo, nlri bgp.AddrPrefixInterface, isWithdraw bool, attrs []bgp.PathAttributeInterface, medSetByTargetNeighbor bool, now time.Time) *IPv4VPNPath {
	ipv4VPNPath := &IPv4VPNPath{}
	ipv4VPNPath.PathDefault = NewPathDefault(bgp.RF_IPv4_VPN, source, nlri, isWithdraw, attrs, medSetByTargetNeighbor, now)
	return ipv4VPNPath
}

func (ipv4vpnp *IPv4VPNPath) setPathDefault(pd *PathDefault) {
	ipv4vpnp.PathDefault = pd
}

func (ipv4vpnp *IPv4VPNPath) getPathDefault() *PathDefault {
	return ipv4vpnp.PathDefault
}

// return IPv4VPNPath's string representation
func (ipv4vpnp *IPv4VPNPath) String() string {
	str := fmt.Sprintf("IPv4VPNPath Source: %v, ", ipv4vpnp.GetSource())
	str = str + fmt.Sprintf(" NLRI: %s, ", ipv4vpnp.getPrefix())
	str = str + fmt.Sprintf(" nexthop: %s, ", ipv4vpnp.GetNexthop().String())
	str = str + fmt.Sprintf(" withdraw: %s, ", ipv4vpnp.IsWithdraw())
	//str = str + fmt.Sprintf(" path attributes: %s, ", ipv4vpnp.getPathAttributeMap())
	return str
}

func (ipv4vpnp *IPv4VPNPath) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Network string
		Nexthop string
		Attrs   []bgp.PathAttributeInterface
		Age     int64
	}{
		Network: ipv4vpnp.getPrefix(),
		Nexthop: ipv4vpnp.PathDefault.GetNexthop().String(),
		Attrs:   ipv4vpnp.PathDefault.getPathAttrs(),
		Age:     int64(time.Now().Sub(ipv4vpnp.PathDefault.timestamp).Seconds()),
	})
}

type EVPNPath struct {
	*PathDefault
}

func NewEVPNPath(source *PeerInfo, nlri bgp.AddrPrefixInterface, isWithdraw bool, attrs []bgp.PathAttributeInterface, medSetByTargetNeighbor bool, now time.Time) *EVPNPath {
	EVPNPath := &EVPNPath{}
	EVPNPath.PathDefault = NewPathDefault(bgp.RF_EVPN, source, nlri, isWithdraw, attrs, medSetByTargetNeighbor, now)
	return EVPNPath
}

func (evpnp *EVPNPath) setPathDefault(pd *PathDefault) {
	evpnp.PathDefault = pd
}

func (evpnp *EVPNPath) getPathDefault() *PathDefault {
	return evpnp.PathDefault
}

// return EVPNPath's string representation
func (evpnp *EVPNPath) String() string {
	str := fmt.Sprintf("EVPNPath Source: %v, ", evpnp.GetSource())
	str = str + fmt.Sprintf(" NLRI: %s, ", evpnp.getPrefix())
	str = str + fmt.Sprintf(" nexthop: %s, ", evpnp.GetNexthop().String())
	str = str + fmt.Sprintf(" withdraw: %s, ", evpnp.IsWithdraw())
	//str = str + fmt.Sprintf(" path attributes: %s, ", evpnp.getPathAttributeMap())
	return str
}

func (evpnp *EVPNPath) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Network string
		Nexthop string
		Attrs   []bgp.PathAttributeInterface
		Age     int64
	}{
		Network: evpnp.getPrefix(),
		Nexthop: evpnp.PathDefault.GetNexthop().String(),
		Attrs:   evpnp.PathDefault.getPathAttrs(),
		Age:     int64(time.Now().Sub(evpnp.PathDefault.timestamp).Seconds()),
	})
}

type EncapPath struct {
	*PathDefault
}

func NewEncapPath(source *PeerInfo, nlri bgp.AddrPrefixInterface, isWithdraw bool, attrs []bgp.PathAttributeInterface, medSetByTargetNeighbor bool, now time.Time) *EncapPath {
	return &EncapPath{
		PathDefault: NewPathDefault(bgp.RF_ENCAP, source, nlri, isWithdraw, attrs, medSetByTargetNeighbor, now),
	}
}

func (p *EncapPath) setPathDefault(pd *PathDefault) {
	p.PathDefault = pd
}
func (p *EncapPath) getPathDefault() *PathDefault {
	return p.PathDefault
}
