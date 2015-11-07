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
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"math"
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
	NoImplicitWithdraw     bool
	Validation             config.RpkiValidationResultType
	IsFromZebra            bool
	Filtered               bool
	Owner                  net.IP
}

func NewPath(source *PeerInfo, nlri bgp.AddrPrefixInterface, isWithdraw bool, pattrs []bgp.PathAttributeInterface, medSetByTargetNeighbor bool, timestamp time.Time, noImplicitWithdraw bool) *Path {
	if !isWithdraw && pattrs == nil {
		log.WithFields(log.Fields{
			"Topic": "Table",
			"Key":   nlri.String(),
			"Peer":  source.Address.String(),
		}).Error("Need to provide patattrs for the path that is not withdraw.")
		return nil
	}

	var owner net.IP
	if source != nil {
		owner = source.Address
	}

	return &Path{
		source:                 source,
		IsWithdraw:             isWithdraw,
		nlri:                   nlri,
		pathAttrs:              pattrs,
		medSetByTargetNeighbor: medSetByTargetNeighbor,
		timestamp:              timestamp,
		NoImplicitWithdraw:     noImplicitWithdraw,
		Owner:                  owner,
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

func (path *Path) UpdatePathAttrs(global *config.Global, peer *config.Neighbor) {

	if peer.RouteServer.RouteServerConfig.RouteServerClient {
		return
	}

	localAddress := peer.Transport.TransportConfig.LocalAddress
	if peer.NeighborConfig.PeerType == config.PEER_TYPE_EXTERNAL {
		// NEXTHOP handling
		path.SetNexthop(localAddress)

		// AS_PATH handling
		path.PrependAsn(global.GlobalConfig.As, 1)

		// MED Handling
		idx, _ := path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
		if idx >= 0 && !path.IsLocal() {
			path.pathAttrs = append(path.pathAttrs[:idx], path.pathAttrs[idx+1:]...)
		}

		// remove local-pref attribute
		idx, _ = path.getPathAttr(bgp.BGP_ATTR_TYPE_LOCAL_PREF)
		if idx >= 0 && !config.IsConfederationMember(global, peer) {
			path.pathAttrs = append(path.pathAttrs[:idx], path.pathAttrs[idx+1:]...)
		}

	} else if peer.NeighborConfig.PeerType == config.PEER_TYPE_INTERNAL {
		// NEXTHOP handling for iBGP
		// if the path generated locally set local address as nexthop.
		// if not, don't modify it.
		// TODO: NEXT-HOP-SELF support
		nexthop := path.GetNexthop()
		if path.IsLocal() && (nexthop.Equal(net.ParseIP("0.0.0.0")) || nexthop.Equal(net.ParseIP("::"))) {
			path.SetNexthop(localAddress)
		}

		// AS_PATH handling for iBGP
		// if the path has AS_PATH path attribute, don't modify it.
		// if not, attach *empty* AS_PATH path attribute.
		idx, _ := path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
		if idx < 0 {
			path.PrependAsn(0, 0)
		}

		// For iBGP peers we are required to send local-pref attribute
		// for connected or local prefixes.
		// We set default local-pref 100.
		p := bgp.NewPathAttributeLocalPref(100)
		idx, _ = path.getPathAttr(bgp.BGP_ATTR_TYPE_LOCAL_PREF)
		if idx < 0 {
			path.pathAttrs = append(path.pathAttrs, p)
		} else if !path.IsLocal() {
			path.pathAttrs[idx] = p
		}

		// RFC4456: BGP Route Reflection
		// 8. Avoiding Routing Information Loops
		info := path.source
		if peer.RouteReflector.RouteReflectorConfig.RouteReflectorClient {
			// This attribute will carry the BGP Identifier of the originator of the route in the local AS.
			// A BGP speaker SHOULD NOT create an ORIGINATOR_ID attribute if one already exists.
			idx, _ = path.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGINATOR_ID)
			if idx < 0 {
				p := bgp.NewPathAttributeOriginatorId(info.ID.String())
				path.pathAttrs = append(path.pathAttrs, p)
			}
			// When an RR reflects a route, it MUST prepend the local CLUSTER_ID to the CLUSTER_LIST.
			// If the CLUSTER_LIST is empty, it MUST create a new one.
			idx, _ = path.getPathAttr(bgp.BGP_ATTR_TYPE_CLUSTER_LIST)
			id := string(peer.RouteReflector.RouteReflectorConfig.RouteReflectorClusterId)
			if idx < 0 {
				p := bgp.NewPathAttributeClusterList([]string{id})
				path.pathAttrs = append(path.pathAttrs, p)
			} else {
				p := path.pathAttrs[idx].(*bgp.PathAttributeClusterList)
				newClusterList := make([]string, 0, len(p.Value))
				for _, ip := range p.Value {
					newClusterList = append(newClusterList, ip.String())
				}
				path.pathAttrs[idx] = bgp.NewPathAttributeClusterList(append([]string{id}, newClusterList...))
			}
		}

	} else {
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   peer.NeighborConfig.NeighborAddress,
		}).Warnf("invalid peer type: %d", peer.NeighborConfig.PeerType)
	}
}

func (path *Path) GetTimestamp() time.Time {
	return path.timestamp
}

func (path *Path) setTimestamp(t time.Time) {
	path.timestamp = t
}

func (path *Path) IsLocal() bool {
	return path.source.Address == nil
}

func (path *Path) IsIBGP() bool {
	return path.source.AS == path.source.LocalAS
}

func (path *Path) ToApiStruct() *api.Path {
	nlri := path.GetNlri()
	n, _ := nlri.Serialize()
	rf := uint32(bgp.AfiSafiToRouteFamily(nlri.AFI(), nlri.SAFI()))
	pattrs := func(arg []bgp.PathAttributeInterface) [][]byte {
		ret := make([][]byte, 0, len(arg))
		for _, a := range arg {
			aa, _ := a.Serialize()
			ret = append(ret, aa)
		}
		return ret
	}(path.GetPathAttrs())
	return &api.Path{
		Nlri:       n,
		Pattrs:     pattrs,
		Age:        int64(time.Now().Sub(path.timestamp).Seconds()),
		IsWithdraw: path.IsWithdraw,
		Validation: int32(path.Validation),
		Filtered:   path.Filtered,
		Rf:         rf,
	}
}

func (path *Path) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Source     *PeerInfo                    `json:"source"`
		IsWithdraw bool                         `json:"is_withdraw"`
		Nlri       bgp.AddrPrefixInterface      `json:"nlri"`
		Pathattrs  []bgp.PathAttributeInterface `json:"pattrs"`
		Filtered   bool                         `json:"filtered"`
	}{
		Source:     path.source,
		IsWithdraw: path.IsWithdraw,
		Nlri:       path.nlri,
		Pathattrs:  path.pathAttrs,
		Filtered:   path.Filtered,
	})
}

// create new PathAttributes
func (path *Path) Clone(owner net.IP, isWithdraw bool) *Path {
	newPathAttrs := make([]bgp.PathAttributeInterface, len(path.pathAttrs))
	for i, v := range path.pathAttrs {
		newPathAttrs[i] = v
	}

	p := NewPath(path.source, path.nlri, isWithdraw, newPathAttrs, false, path.timestamp, path.NoImplicitWithdraw)
	p.Validation = path.Validation
	p.Owner = owner
	return p
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

func (path *Path) GetPathAttrs() []bgp.PathAttributeInterface {
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
	s := bytes.NewBuffer(make([]byte, 0, 64))
	s.WriteString(fmt.Sprintf("{ %s | ", path.getPrefix()))
	s.WriteString(fmt.Sprintf("src: %s", path.GetSource()))
	s.WriteString(fmt.Sprintf(", nh: %s", path.GetNexthop()))
	if path.IsWithdraw {
		s.WriteString(", withdraw")
	}
	s.WriteString(" }")
	return s.String()
}

func (path *Path) getPrefix() string {
	return path.nlri.String()
}

func (path *Path) GetAsPath() *bgp.PathAttributeAsPath {
	_, attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	if attr != nil {
		return attr.(*bgp.PathAttributeAsPath)
	}
	return nil
}

// GetAsPathLen returns the number of AS_PATH
func (path *Path) GetAsPathLen() int {

	var length int = 0
	if _, attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH); attr != nil {
		aspath := attr.(*bgp.PathAttributeAsPath)
		for _, as := range aspath.Value {
			length += as.ASLen()
		}
	}
	return length
}

func (path *Path) GetAsString() string {
	s := bytes.NewBuffer(make([]byte, 0, 64))
	if _, attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH); attr != nil {
		aspath := attr.(*bgp.PathAttributeAsPath)
		for i, paramIf := range aspath.Value {
			segment := paramIf.(*bgp.As4PathParam)
			if i != 0 {
				s.WriteString(" ")
			}

			sep := " "
			switch segment.Type {
			case bgp.BGP_ASPATH_ATTR_TYPE_SET, bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET:
				s.WriteString("{")
				sep = ","
			}
			for j, as := range segment.AS {
				s.WriteString(fmt.Sprintf("%d", as))
				if j != len(segment.AS)-1 {
					s.WriteString(sep)
				}
			}
			switch segment.Type {
			case bgp.BGP_ASPATH_ATTR_TYPE_SET, bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET:
				s.WriteString("}")
			}
		}
	}
	return s.String()
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
			} else {
				asList = append(asList, 0)
			}
		}
	}
	return asList
}

// PrependAsn prepends AS number.
// This function updates the AS_PATH attribute as follows.
//  1) if the first path segment of the AS_PATH is of type
//     AS_SEQUENCE, the local system prepends the specified AS num as
//     the last element of the sequence (put it in the left-most
//     position with respect to the position of  octets in the
//     protocol message) the specified number of times.
//     If the act of prepending will cause an overflow in the AS_PATH
//     segment (i.e.,  more than 255 ASes),
//     it SHOULD prepend a new segment of type AS_SEQUENCE
//     and prepend its own AS number to this new segment.
//
//  2) if the first path segment of the AS_PATH is of other than type
//     AS_SEQUENCE, the local system prepends a new path segment of type
//     AS_SEQUENCE to the AS_PATH, including the specified AS number in
//     that segment.
//
//  3) if the AS_PATH is empty, the local system creates a path
//     segment of type AS_SEQUENCE, places the specified AS number
//     into that segment, and places that segment into the AS_PATH.
func (path *Path) PrependAsn(asn uint32, repeat uint8) {

	idx, original := path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)

	asns := make([]uint32, repeat)
	for i, _ := range asns {
		asns[i] = asn
	}

	var asPath *bgp.PathAttributeAsPath
	if idx < 0 {
		asPath = bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{})
		path.pathAttrs = append(path.pathAttrs, asPath)
	} else {
		asPath = cloneAsPath(original.(*bgp.PathAttributeAsPath))
		path.pathAttrs[idx] = asPath
	}

	if len(asPath.Value) > 0 {
		fst := asPath.Value[0].(*bgp.As4PathParam)
		if fst.Type == bgp.BGP_ASPATH_ATTR_TYPE_SEQ {
			if len(fst.AS)+int(repeat) > 255 {
				repeat = uint8(255 - len(fst.AS))
			}
			fst.AS = append(asns[:int(repeat)], fst.AS...)
			fst.Num += repeat
			asns = asns[int(repeat):]
		}
	}

	if len(asns) > 0 {
		p := bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, asns)
		asPath.Value = append([]bgp.AsPathParamInterface{p}, asPath.Value...)
	}
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
// If the length of communities is 0 and doReplace is true, it clears communities.
func (path *Path) SetCommunities(communities []uint32, doReplace bool) {

	if len(communities) == 0 && doReplace {
		// clear communities
		path.ClearCommunities()
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

func (path *Path) GetExtCommunities() []bgp.ExtendedCommunityInterface {
	eCommunityList := make([]bgp.ExtendedCommunityInterface, 0)
	if _, attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_EXTENDED_COMMUNITIES); attr != nil {
		eCommunities := attr.(*bgp.PathAttributeExtendedCommunities).Value
		for _, eCommunity := range eCommunities {
			eCommunityList = append(eCommunityList, eCommunity)
		}
	}
	return eCommunityList
}

func (path *Path) SetExtCommunities(exts []bgp.ExtendedCommunityInterface, doReplace bool) {
	idx, attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_EXTENDED_COMMUNITIES)
	if attr != nil {
		l := attr.(*bgp.PathAttributeExtendedCommunities).Value
		if doReplace {
			l = exts
		} else {
			l = append(l, exts...)
		}
		path.pathAttrs[idx] = bgp.NewPathAttributeExtendedCommunities(l)
	} else {
		path.pathAttrs = append(path.pathAttrs, bgp.NewPathAttributeExtendedCommunities(exts))
	}
}

func (path *Path) GetMed() (uint32, error) {
	_, attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	if attr == nil {
		return 0, fmt.Errorf("no med path attr")
	}
	return attr.(*bgp.PathAttributeMultiExitDisc).Value, nil
}

// SetMed replace, add or subtraction med with new ones.
func (path *Path) SetMed(med int64, doReplace bool) error {

	parseMed := func(orgMed uint32, med int64, doReplace bool) (*bgp.PathAttributeMultiExitDisc, error) {
		newMed := &bgp.PathAttributeMultiExitDisc{}
		if doReplace {
			newMed = bgp.NewPathAttributeMultiExitDisc(uint32(med))
		} else {
			if int64(orgMed)+med < 0 {
				return nil, fmt.Errorf("med value invalid. it's underflow threshold.")
			} else if int64(orgMed)+med > int64(math.MaxUint32) {
				return nil, fmt.Errorf("med value invalid. it's overflow threshold.")
			}
			newMed = bgp.NewPathAttributeMultiExitDisc(uint32(int64(orgMed) + med))
		}
		return newMed, nil
	}

	idx, attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	if attr != nil {
		m := attr.(*bgp.PathAttributeMultiExitDisc)
		newMed, err := parseMed(m.Value, med, doReplace)
		if err != nil {
			return err
		}
		path.pathAttrs[idx] = newMed
	} else {
		m := 0
		newMed, err := parseMed(uint32(m), med, doReplace)
		if err != nil {
			return err
		}
		path.pathAttrs = append(path.pathAttrs, newMed)
	}
	return nil
}

func (path *Path) GetOriginatorID() net.IP {
	if _, attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGINATOR_ID); attr != nil {
		return attr.(*bgp.PathAttributeOriginatorId).Value
	}
	return nil
}

func (path *Path) GetClusterList() []net.IP {
	if _, attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_CLUSTER_LIST); attr != nil {
		return attr.(*bgp.PathAttributeClusterList).Value
	}
	return nil
}

func (lhs *Path) Equal(rhs *Path) bool {
	if rhs == nil {
		return false
	} else if lhs == rhs {
		return true
	}
	f := func(p *Path) []byte {
		s := p.ToApiStruct()
		s.Age = 0
		buf, _ := json.Marshal(s)
		return buf
	}
	return bytes.Equal(f(lhs), f(rhs))
}
