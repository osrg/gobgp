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
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"net"
	"time"
)

type Path struct {
	source                 *PeerInfo
	IsWithdraw             bool
	nlri                   bgp.AddrPrefixInterface
	pathAttrs              []bgp.PathAttributeInterface
	medSetByTargetNeighbor bool
	timestamp              time.Time
}

func NewPath(source *PeerInfo, nlri bgp.AddrPrefixInterface, isWithdraw bool, pattrs []bgp.PathAttributeInterface, medSetByTargetNeighbor bool, timestamp time.Time) *Path {
	if !isWithdraw && pattrs == nil {
		log.WithFields(log.Fields{
			"Topic": "Table",
			"Key":   nlri.String(),
			"Peer":  source.Address.String(),
		}).Error("Need to provide patattrs for the path that is not withdraw.")
		return nil
	}

	return &Path{
		source:                 source,
		IsWithdraw:             isWithdraw,
		nlri:                   nlri,
		pathAttrs:              pattrs,
		medSetByTargetNeighbor: medSetByTargetNeighbor,
		timestamp:              timestamp,
	}
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

func (path *Path) updatePathAttrs(global *config.Global, peer *config.Neighbor) {

	if peer.RouteServer.RouteServerClient {
		return
	}

	if peer.PeerType == config.PEER_TYPE_EXTERNAL {
		// NEXTHOP handling
		path.SetNexthop(peer.LocalAddress)

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
		idx, originalAsPath := path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
		if idx < 0 {
			log.Fatal("missing AS_PATH mandatory attribute")
		}
		asPath := cloneAsPath(originalAsPath.(*bgp.PathAttributeAsPath))
		path.pathAttrs[idx] = asPath
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
		idx, _ = path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
		if idx >= 0 {
			path.pathAttrs = append(path.pathAttrs[:idx], path.pathAttrs[idx+1:]...)
		}
	} else if peer.PeerType == config.PEER_TYPE_INTERNAL {
		// For iBGP peers we are required to send local-pref attribute
		// for connected or local prefixes.
		// We set default local-pref 100.
		p := bgp.NewPathAttributeLocalPref(100)
		idx, _ := path.getPathAttr(bgp.BGP_ATTR_TYPE_LOCAL_PREF)
		if idx < 0 {
			path.pathAttrs = append(path.pathAttrs, p)
		} else {
			path.pathAttrs[idx] = p
		}
	} else {
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   peer.NeighborAddress,
		}).Warnf("invalid peer type: %d", peer.PeerType)
	}
}

func (path *Path) getTimestamp() time.Time {
	return path.timestamp
}

func (path *Path) setTimestamp(t time.Time) {
	path.timestamp = t
}

func (path *Path) isLocal() bool {
	var ret bool
	if path.source.Address == nil {
		ret = true
	}
	return ret
}

func (path *Path) ToApiStruct() *api.Path {
	pathAttrs := func(arg []bgp.PathAttributeInterface) []*api.PathAttr {
		ret := make([]*api.PathAttr, 0, len(arg))
		for _, a := range arg {
			ret = append(ret, a.ToApiStruct())
		}
		return ret
	}(path.getPathAttrs())
	return &api.Path{
		Nlri:       path.GetNlri().ToApiStruct(),
		Nexthop:    path.GetNexthop().String(),
		Attrs:      pathAttrs,
		Age:        int64(time.Now().Sub(path.timestamp).Seconds()),
		IsWithdraw: path.IsWithdraw,
	}
}

// create new PathAttributes
func (path *Path) Clone(isWithdraw bool) *Path {
	nlri := path.nlri
	if path.GetRouteFamily() == bgp.RF_IPv4_UC && isWithdraw {
		if path.IsWithdraw {
			nlri = path.nlri
		} else {
			nlri = &bgp.WithdrawnRoute{path.nlri.(*bgp.NLRInfo).IPAddrPrefix}
		}
	}

	newPathAttrs := make([]bgp.PathAttributeInterface, len(path.pathAttrs))
	for i, v := range path.pathAttrs {
		newPathAttrs[i] = v
	}

	return NewPath(path.source, nlri, isWithdraw, newPathAttrs, false, path.timestamp)
}

func (path *Path) GetRouteFamily() bgp.RouteFamily {
	return bgp.AfiSafiToRouteFamily(path.nlri.AFI(), path.nlri.SAFI())
}

func (path *Path) setSource(source *PeerInfo) {
	path.source = source
}
func (path *Path) GetSource() *PeerInfo {
	return path.source
}

func (path *Path) GetSourceAs() uint32 {
	_, attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
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

func (path *Path) GetNexthop() net.IP {
	_, attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	if attr != nil {
		return attr.(*bgp.PathAttributeNextHop).Value
	}
	_, attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
	if attr != nil {
		return attr.(*bgp.PathAttributeMpReachNLRI).Nexthop
	}
	return net.IP{}
}

func (path *Path) SetNexthop(nexthop net.IP) {
	idx, attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	if attr != nil {
		newNexthop := bgp.NewPathAttributeNextHop(nexthop.String())
		path.pathAttrs[idx] = newNexthop
	}
	idx, attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
	if attr != nil {
		oldNlri := attr.(*bgp.PathAttributeMpReachNLRI)
		newNlri := bgp.NewPathAttributeMpReachNLRI(nexthop.String(), oldNlri.Value)
		path.pathAttrs[idx] = newNlri
	}
}

func (path *Path) GetNlri() bgp.AddrPrefixInterface {
	return path.nlri
}

func (path *Path) setMedSetByTargetNeighbor(medSetByTargetNeighbor bool) {
	path.medSetByTargetNeighbor = medSetByTargetNeighbor
}

func (path *Path) getMedSetByTargetNeighbor() bool {
	return path.medSetByTargetNeighbor
}

func (path *Path) getPathAttrs() []bgp.PathAttributeInterface {
	return path.pathAttrs
}

func (path *Path) getPathAttr(pattrType bgp.BGPAttrType) (int, bgp.PathAttributeInterface) {
	for i, p := range path.pathAttrs {
		if p.GetType() == pattrType {
			return i, p
		}
	}
	return -1, nil
}

// return Path's string representation
func (path *Path) String() string {
	str := fmt.Sprintf("Source: %v, ", path.GetSource())
	str += fmt.Sprintf(" NLRI: %s, ", path.getPrefix())
	str += fmt.Sprintf(" nexthop: %s, ", path.GetNexthop())
	str += fmt.Sprintf(" withdraw: %s, ", path.IsWithdraw)
	return str
}

func (path *Path) getPrefix() string {
	return path.nlri.String()
}

// GetAsPathLen returns the number of AS_PATH
func (path *Path) GetAsPathLen() int {

	var length int = 0
	if _, attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH); attr != nil {
		aspath := attr.(*bgp.PathAttributeAsPath)
		for _, paramIf := range aspath.Value {
			segment := paramIf.(*bgp.As4PathParam)
			length += segment.ASLen()
		}
	}
	return length
}

func (path *Path) GetAsList() []uint32 {
	return path.getAsListofSpecificType(true, true)

}

func (path *Path) GetAsSeqList() []uint32 {
	return path.getAsListofSpecificType(true, false)

}

func (path *Path) getAsListofSpecificType(getAsSeq, getAsSet bool) []uint32 {
	asList := []uint32{}
	if _, attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH); attr != nil {
		aspath := attr.(*bgp.PathAttributeAsPath)
		for _, paramIf := range aspath.Value {
			segment := paramIf.(*bgp.As4PathParam)
			if getAsSeq && segment.Type == bgp.BGP_ASPATH_ATTR_TYPE_SEQ {
				asList = append(asList, segment.AS...)
				continue
			}
			if getAsSet && segment.Type == bgp.BGP_ASPATH_ATTR_TYPE_SET {
				asList = append(asList, segment.AS...)
			}
		}
	}
	return asList
}

func (path *Path) GetCommunities() []uint32 {
	communityList := []uint32{}
	if _, attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_COMMUNITIES); attr != nil {
		communities := attr.(*bgp.PathAttributeCommunities)
		communityList = append(communityList, communities.Value...)
	}
	return communityList
}

// SetCommunities adds or replaces communities with new ones.
// If the length of communites is 0, it does nothing.
func (path *Path) SetCommunities(communities []uint32, doReplace bool) {

	if len(communities) == 0 {
		// do nothing
		return
	}

	newList := make([]uint32, 0)
	idx, attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_COMMUNITIES)
	if attr != nil {
		c := attr.(*bgp.PathAttributeCommunities)
		if doReplace {
			newList = append(newList, communities...)
		} else {
			newList = append(newList, c.Value...)
			newList = append(newList, communities...)
		}
		newCommunities := bgp.NewPathAttributeCommunities(newList)
		path.pathAttrs[idx] = newCommunities
	} else {
		newList = append(newList, communities...)
		newCommunities := bgp.NewPathAttributeCommunities(newList)
		path.pathAttrs = append(path.pathAttrs, newCommunities)
	}

}

// RemoveCommunities removes specific communities.
// If the length of communites is 0, it does nothing.
// If all communities are removed, it removes Communities path attribute itself.
func (path *Path) RemoveCommunities(communities []uint32) int {

	if len(communities) == 0 {
		// do nothing
		return 0
	}

	find := func(val uint32) bool {
		for _, com := range communities {
			if com == val {
				return true
			}
		}
		return false
	}

	count := 0
	idx, attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_COMMUNITIES)
	if attr != nil {
		newList := make([]uint32, 0)
		c := attr.(*bgp.PathAttributeCommunities)

		for _, value := range c.Value {
			if find(value) {
				count += 1
			} else {
				newList = append(newList, value)
			}
		}

		if len(newList) != 0 {
			newCommunities := bgp.NewPathAttributeCommunities(newList)
			path.pathAttrs[idx] = newCommunities
		} else {
			path.pathAttrs = append(path.pathAttrs[:idx], path.pathAttrs[idx+1:]...)
		}
	}
	return count
}

// ClearCommunities removes Communities path attribute.
func (path *Path) ClearCommunities() {
	idx, _ := path.getPathAttr(bgp.BGP_ATTR_TYPE_COMMUNITIES)
	if idx >= 0 {
		path.pathAttrs = append(path.pathAttrs[:idx], path.pathAttrs[idx+1:]...)
	}
}

func (lhs *Path) Equal(rhs *Path) bool {
	if rhs == nil {
		return false
	} else if lhs == rhs {
		return true
	}
	isSamePathAttrs := func() bool {
		if len(lhs.pathAttrs) != len(rhs.getPathAttrs()) {
			return false
		}
		for i, v := range rhs.getPathAttrs() {
			if !v.Equal(lhs.pathAttrs[i]) {
				return false
			}
		}
		return true
	}
	return lhs.IsWithdraw == rhs.IsWithdraw && lhs.nlri.Equal(rhs.GetNlri()) && isSamePathAttrs()
}
