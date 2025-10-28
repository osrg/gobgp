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
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"slices"
	"sort"
	"time"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/segmentio/fasthash/fnv1a"
)

const (
	DEFAULT_LOCAL_PREF = 100
)

var ErrNoMedPathAttr error = errors.New("no med path attr")

type Bitmap struct {
	bitmap []uint64
}

func (b *Bitmap) Flag(i uint) {
	b.bitmap[i/64] |= 1 << (i % 64)
}

func (b *Bitmap) Unflag(i uint) {
	b.bitmap[i/64] &^= 1 << (i % 64)
}

func (b *Bitmap) GetFlag(i uint) bool {
	return b.bitmap[i/64]&(1<<(i%64)) > 0
}

func (b *Bitmap) FindandSetZeroBit() (uint, error) {
	for i := range len(b.bitmap) {
		if b.bitmap[i] == math.MaxUint64 {
			continue
		}
		// replace this with TrailingZero64() when gobgp drops go 1.8 support.
		for j := range 64 {
			v := ^b.bitmap[i]
			if v&(1<<uint64(j)) > 0 {
				r := i*64 + j
				b.Flag(uint(r))
				return uint(r), nil
			}
		}
	}
	return 0, fmt.Errorf("no space")
}

func (b *Bitmap) Expand() {
	b.bitmap = append(b.bitmap, uint64(0))
}

func NewBitmap(size int) *Bitmap {
	b := &Bitmap{}
	if size != 0 {
		b.bitmap = make([]uint64, (size+64-1)/64)
	}
	return b
}

type originInfo struct {
	nlri               bgp.NLRI
	source             *PeerInfo
	timestamp          int64
	noImplicitWithdraw bool
	isFromExternal     bool
	eor                bool
	stale              bool
}

type RpkiValidationReasonType string

const (
	RPKI_VALIDATION_REASON_TYPE_NONE   RpkiValidationReasonType = "none"
	RPKI_VALIDATION_REASON_TYPE_AS     RpkiValidationReasonType = "as"
	RPKI_VALIDATION_REASON_TYPE_LENGTH RpkiValidationReasonType = "length"
)

var RpkiValidationReasonTypeToIntMap = map[RpkiValidationReasonType]int{
	RPKI_VALIDATION_REASON_TYPE_NONE:   0,
	RPKI_VALIDATION_REASON_TYPE_AS:     1,
	RPKI_VALIDATION_REASON_TYPE_LENGTH: 2,
}

func (v RpkiValidationReasonType) ToInt() int {
	i, ok := RpkiValidationReasonTypeToIntMap[v]
	if !ok {
		return -1
	}
	return i
}

var IntToRpkiValidationReasonTypeMap = map[int]RpkiValidationReasonType{
	0: RPKI_VALIDATION_REASON_TYPE_NONE,
	1: RPKI_VALIDATION_REASON_TYPE_AS,
	2: RPKI_VALIDATION_REASON_TYPE_LENGTH,
}

type Validation struct {
	Status          oc.RpkiValidationResultType
	Reason          RpkiValidationReasonType
	Matched         []*ROA
	UnmatchedAs     []*ROA
	UnmatchedLength []*ROA
}

type Path struct {
	info      *originInfo
	parent    *Path
	pathAttrs []bgp.PathAttributeInterface
	dels      []bgp.BGPAttrType
	attrsHash uint64
	localID   uint32
	remoteID  uint32
	family    bgp.Family
	rejected  bool
	// doesn't exist in the adj
	dropped bool

	// For BGP Nexthop Tracking, this field shows if nexthop is invalidated by IGP.
	IsNexthopInvalid bool
	IsWithdraw       bool
}

type FilteredType uint8

const (
	NotFiltered FilteredType = 1 << iota
	PolicyFiltered
	SendMaxFiltered
)

type PathDestLocalKey struct {
	Family bgp.Family
	Prefix string
}
type PathLocalKey struct {
	PathDestLocalKey
	Id uint32
}

func NewPathDestLocalKey(f bgp.Family, destPrefix string) *PathDestLocalKey {
	return &PathDestLocalKey{
		Family: f,
		Prefix: destPrefix,
	}
}

var localSource = &PeerInfo{}

func NewPath(family bgp.Family, source *PeerInfo, pathnlri bgp.PathNLRI, isWithdraw bool, pattrs []bgp.PathAttributeInterface, timestamp time.Time, noImplicitWithdraw bool) *Path {
	if source == nil {
		source = localSource
	}
	if !isWithdraw && pattrs == nil {
		return nil
	}
	return &Path{
		info: &originInfo{
			nlri:               pathnlri.NLRI,
			source:             source,
			timestamp:          timestamp.Unix(),
			noImplicitWithdraw: noImplicitWithdraw,
		},
		family:     family,
		IsWithdraw: isWithdraw,
		pathAttrs:  pattrs,
		remoteID:   pathnlri.ID,
	}
}

func NewEOR(family bgp.Family) *Path {
	return &Path{
		family: family,
		info: &originInfo{
			eor: true,
		},
	}
}

func (path *Path) IsEOR() bool {
	if path.info != nil && path.info.eor {
		return true
	}
	return false
}

func cloneAsPath(asAttr *bgp.PathAttributeAsPath) *bgp.PathAttributeAsPath {
	newASparams := make([]bgp.AsPathParamInterface, len(asAttr.Value))
	for i, param := range asAttr.Value {
		asList := param.GetAS()
		as := make([]uint32, len(asList))
		copy(as, asList)
		newASparams[i] = bgp.NewAs4PathParam(param.GetType(), as)
	}
	return bgp.NewPathAttributeAsPath(newASparams)
}

func UpdatePathAttrs(logger *slog.Logger, global *oc.Global, peer *oc.Neighbor, info *PeerInfo, original *Path) *Path {
	if peer.RouteServer.Config.RouteServerClient {
		return original
	}
	path := original.Clone(original.IsWithdraw)

	for _, a := range path.GetPathAttrs() {
		if _, y := bgp.PathAttrFlags[a.GetType()]; !y {
			if a.GetFlags()&bgp.BGP_ATTR_FLAG_TRANSITIVE == 0 {
				path.delPathAttr(a.GetType())
			}
		} else {
			switch a.GetType() {
			case bgp.BGP_ATTR_TYPE_CLUSTER_LIST, bgp.BGP_ATTR_TYPE_ORIGINATOR_ID:
				if peer.State.PeerType != oc.PEER_TYPE_INTERNAL || !peer.RouteReflector.Config.RouteReflectorClient {
					// send these attributes to only rr clients
					path.delPathAttr(a.GetType())
				}
			}
		}
	}

	localAddress := info.LocalAddress
	nexthop := path.GetNexthop()
	switch peer.State.PeerType {
	case oc.PEER_TYPE_EXTERNAL:
		// NEXTHOP handling
		if !path.IsLocal() || nexthop.IsUnspecified() {
			path.SetNexthop(localAddress.AsSlice())
		}

		// remove-private-as handling
		path.RemovePrivateAS(peer.Config.LocalAs, peer.State.RemovePrivateAs)

		// AS_PATH handling
		confed := peer.IsConfederationMember(global)
		path.PrependAsn(peer.Config.LocalAs, 1, confed)
		if !confed {
			path.removeConfedAs()
		}

		// MED Handling
		if med := path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC); med != nil && !path.IsLocal() {
			path.delPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
		}
	case oc.PEER_TYPE_INTERNAL:
		// NEXTHOP handling for iBGP
		// if the path generated locally set local address as nexthop.
		// if not, don't modify it.
		// TODO: NEXT-HOP-SELF support
		if path.IsLocal() && nexthop.IsUnspecified() {
			path.SetNexthop(localAddress.AsSlice())
		}

		// AS_PATH handling for iBGP
		// if the path has AS_PATH path attribute, don't modify it.
		// if not, attach *empty* AS_PATH path attribute.
		if nh := path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH); nh == nil {
			path.PrependAsn(0, 0, false)
		}

		// For iBGP peers we are required to send local-pref attribute
		// for connected or local prefixes.
		// We set default local-pref 100.
		if pref := path.getPathAttr(bgp.BGP_ATTR_TYPE_LOCAL_PREF); pref == nil {
			path.setPathAttr(bgp.NewPathAttributeLocalPref(DEFAULT_LOCAL_PREF))
		}

		// RFC4456: BGP Route Reflection
		// 8. Avoiding Routing Information Loops
		info := path.GetSource()
		if peer.RouteReflector.Config.RouteReflectorClient {
			// This attribute will carry the BGP Identifier of the originator of the route in the local AS.
			// A BGP speaker SHOULD NOT create an ORIGINATOR_ID attribute if one already exists.
			//
			// RFC4684 3.2 Intra-AS VPN Route Distribution
			// When advertising RT membership NLRI to a route-reflector client,
			// the Originator attribute shall be set to the router-id of the
			// advertiser, and the Next-hop attribute shall be set of the local
			// address for that session.
			if path.GetFamily() == bgp.RF_RTC_UC {
				path.SetNexthop(localAddress.AsSlice())
				attr, _ := bgp.NewPathAttributeOriginatorId(info.LocalID)
				path.setPathAttr(attr)
			} else if path.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGINATOR_ID) == nil {
				if path.IsLocal() {
					attr, _ := bgp.NewPathAttributeOriginatorId(global.Config.RouterId)
					path.setPathAttr(attr)
				} else {
					attr, _ := bgp.NewPathAttributeOriginatorId(info.ID)
					path.setPathAttr(attr)
				}
			}
			// When an RR reflects a route, it MUST prepend the local CLUSTER_ID to the CLUSTER_LIST.
			// If the CLUSTER_LIST is empty, it MUST create a new one.
			// TODO: needs to validated earlier.
			clusterID := peer.RouteReflector.State.RouteReflectorClusterId
			if p := path.getPathAttr(bgp.BGP_ATTR_TYPE_CLUSTER_LIST); p == nil {
				pa, _ := bgp.NewPathAttributeClusterList([]netip.Addr{clusterID})
				path.setPathAttr(pa)
			} else {
				clusterList := p.(*bgp.PathAttributeClusterList)
				pa, _ := bgp.NewPathAttributeClusterList(append([]netip.Addr{clusterID}, clusterList.Value...))
				path.setPathAttr(pa)
			}
		}
	default:
		logger.Warn("invalid peer type",
			slog.String("Topic", "Peer"),
			slog.String("Key", peer.State.NeighborAddress.String()),
			slog.Any("Type", peer.State.PeerType))
	}
	return path
}

func (path *Path) GetTimestamp() time.Time {
	return time.Unix(path.OriginInfo().timestamp, 0)
}

func (path *Path) setTimestamp(t time.Time) {
	path.OriginInfo().timestamp = t.Unix()
}

func (path *Path) IsLocal() bool {
	return !path.GetSource().Address.IsValid()
}

func (path *Path) IsIBGP() bool {
	as := path.GetSource().AS
	return as == path.GetSource().LocalAS && as != 0
}

// create new PathAttributes
func (path *Path) Clone(isWithdraw bool) *Path {
	return &Path{
		parent:           path,
		family:           path.family,
		IsWithdraw:       isWithdraw,
		IsNexthopInvalid: path.IsNexthopInvalid,
		attrsHash:        path.attrsHash,
		localID:          path.localID,
		remoteID:         path.remoteID,
	}
}

func (path *Path) root() *Path {
	p := path
	for p.parent != nil {
		p = p.parent
	}
	return p
}

func (path *Path) OriginInfo() *originInfo {
	return path.root().info
}

func (path *Path) NoImplicitWithdraw() bool {
	return path.OriginInfo().noImplicitWithdraw
}

func (path *Path) IsFromExternal() bool {
	return path.OriginInfo().isFromExternal
}

func (path *Path) SetIsFromExternal(y bool) {
	path.OriginInfo().isFromExternal = y
}

func (path *Path) GetFamily() bgp.Family {
	return path.family
}

func (path *Path) GetSource() *PeerInfo {
	return path.OriginInfo().source
}

func (path *Path) MarkStale(s bool) {
	path.OriginInfo().stale = s
}

func (path *Path) IsStale() bool {
	return path.OriginInfo().stale
}

func (path *Path) IsRejected() bool {
	return path.rejected
}

func (path *Path) SetRejected(y bool) {
	path.rejected = y
}

func (path *Path) IsDropped() bool {
	return path.dropped
}

func (path *Path) SetDropped(y bool) {
	path.dropped = y
}

func (path *Path) HasNoLLGR() bool {
	return slices.Contains(path.GetCommunities(), uint32(bgp.COMMUNITY_NO_LLGR))
}

func (path *Path) IsLLGRStale() bool {
	return slices.Contains(path.GetCommunities(), uint32(bgp.COMMUNITY_LLGR_STALE))
}

func (path *Path) GetSourceAs() uint32 {
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	if attr != nil {
		asPathParam := attr.(*bgp.PathAttributeAsPath).Value
		if len(asPathParam) == 0 {
			return 0
		}
		asList := asPathParam[len(asPathParam)-1].GetAS()
		if len(asList) == 0 {
			return 0
		}
		return asList[len(asList)-1]
	}
	return 0
}

func (path *Path) GetNexthop() netip.Addr {
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	if attr != nil {
		return attr.(*bgp.PathAttributeNextHop).Value
	}
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
	if attr != nil {
		return attr.(*bgp.PathAttributeMpReachNLRI).Nexthop
	}
	return netip.Addr{}
}

func (path *Path) SetNexthop(nexthop net.IP) {
	if path.GetFamily() == bgp.RF_IPv4_UC && nexthop.To4() == nil {
		path.delPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
		mpreach, _ := bgp.NewPathAttributeMpReachNLRI(path.GetFamily(), []bgp.PathNLRI{{NLRI: path.GetNlri(), ID: path.localID}}, netip.MustParseAddr(nexthop.String()))
		path.setPathAttr(mpreach)
		return
	}
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	if attr != nil {
		pa, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr(nexthop.String()))
		path.setPathAttr(pa)
	}
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
	if attr != nil {
		oldNlri := attr.(*bgp.PathAttributeMpReachNLRI)
		mpreach, _ := bgp.NewPathAttributeMpReachNLRI(path.GetFamily(), oldNlri.Value, netip.MustParseAddr(nexthop.String()))
		path.setPathAttr(mpreach)
	}
}

func (path *Path) GetNlri() bgp.NLRI {
	return path.OriginInfo().nlri
}

type PathAttrs []bgp.PathAttributeInterface

func (a PathAttrs) Len() int {
	return len(a)
}

func (a PathAttrs) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a PathAttrs) Less(i, j int) bool {
	return a[i].GetType() < a[j].GetType()
}

func (path *Path) GetPathAttrs() []bgp.PathAttributeInterface {
	deleted := NewBitmap(math.MaxUint8)
	modified := make(map[uint]bgp.PathAttributeInterface)
	p := path
	for {
		for _, t := range p.dels {
			deleted.Flag(uint(t))
		}
		if p.parent == nil {
			list := PathAttrs(make([]bgp.PathAttributeInterface, 0, len(p.pathAttrs)))
			// we assume that the original pathAttrs are
			// in order, that is, other bgp speakers send
			// attributes in order.
			for _, a := range p.pathAttrs {
				typ := uint(a.GetType())
				if m, ok := modified[typ]; ok {
					list = append(list, m)
					delete(modified, typ)
				} else if !deleted.GetFlag(typ) {
					list = append(list, a)
				}
			}
			if len(modified) > 0 {
				// Huh, some attributes were newly
				// added. So we need to sort...
				for _, m := range modified {
					list = append(list, m)
				}
				sort.Sort(list)
			}
			return list
		} else {
			for _, a := range p.pathAttrs {
				typ := uint(a.GetType())
				if _, ok := modified[typ]; !deleted.GetFlag(typ) && !ok {
					modified[typ] = a
				}
			}
		}
		p = p.parent
	}
}

func (path *Path) getPathAttr(typ bgp.BGPAttrType) bgp.PathAttributeInterface {
	p := path
	for {
		if slices.Contains(p.dels, typ) {
			return nil
		}
		for _, a := range p.pathAttrs {
			if a.GetType() == typ {
				return a
			}
		}
		if p.parent == nil {
			return nil
		}
		p = p.parent
	}
}

func (path *Path) setPathAttr(a bgp.PathAttributeInterface) {
	path.attrsHash = 0
	if len(path.pathAttrs) == 0 {
		path.pathAttrs = []bgp.PathAttributeInterface{a}
	} else {
		for i, b := range path.pathAttrs {
			if a.GetType() == b.GetType() {
				path.pathAttrs[i] = a
				return
			}
		}
		path.pathAttrs = append(path.pathAttrs, a)
	}
}

func (path *Path) delPathAttr(typ bgp.BGPAttrType) {
	path.attrsHash = 0
	if len(path.dels) == 0 {
		path.dels = []bgp.BGPAttrType{typ}
	} else {
		path.dels = append(path.dels, typ)
	}
}

// return Path's string representation
func (path *Path) String() string {
	s := bytes.NewBuffer(make([]byte, 0, 64))
	if path.IsEOR() {
		fmt.Fprintf(s, "{ %s EOR | src: %s }", path.GetFamily(), path.GetSource())
		return s.String()
	}
	fmt.Fprintf(s, "{ %s | ", path.GetPrefix())
	fmt.Fprintf(s, "src: %s", path.GetSource())
	fmt.Fprintf(s, ", nh: %s", path.GetNexthop())
	if path.IsNexthopInvalid {
		s.WriteString(" (not reachable)")
	}
	if path.IsWithdraw {
		s.WriteString(", withdraw")
	}
	s.WriteString(" }")
	return s.String()
}

// GetLocalKey identifies the path in the local BGP server.
func (path *Path) GetLocalKey() PathLocalKey {
	return PathLocalKey{
		PathDestLocalKey: path.GetDestLocalKey(),
		Id:               path.localID,
	}
}

// GetDestLocalKey identifies the path destination in the local BGP server.
func (path *Path) GetDestLocalKey() PathDestLocalKey {
	return PathDestLocalKey{
		Family: path.GetFamily(),
		Prefix: path.GetNlri().String(),
	}
}

func (path *Path) GetPrefix() string {
	return path.GetNlri().String()
}

func (path *Path) GetAsPath() *bgp.PathAttributeAsPath {
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	if attr != nil {
		return attr.(*bgp.PathAttributeAsPath)
	}
	return nil
}

// GetAsPathLen returns the number of AS_PATH
func (path *Path) GetAsPathLen() int {
	length := 0
	if aspath := path.GetAsPath(); aspath != nil {
		for _, as := range aspath.Value {
			length += as.ASLen()
		}
	}
	return length
}

func (path *Path) GetAsString() string {
	s := bytes.NewBuffer(make([]byte, 0, 64))
	if aspath := path.GetAsPath(); aspath != nil {
		return bgp.AsPathString(aspath)
	}
	return s.String()
}

func (path *Path) GetAsList() []uint32 {
	return path.getAsListOfSpecificType(true, true)
}

func (path *Path) GetAsSeqList() []uint32 {
	return path.getAsListOfSpecificType(true, false)
}

func (path *Path) getAsListOfSpecificType(getAsSeq, getAsSet bool) []uint32 {
	asList := []uint32{}
	if aspath := path.GetAsPath(); aspath != nil {
		for _, param := range aspath.Value {
			segType := param.GetType()
			if getAsSeq && segType == bgp.BGP_ASPATH_ATTR_TYPE_SEQ {
				asList = append(asList, param.GetAS()...)
				continue
			}
			if getAsSet && segType == bgp.BGP_ASPATH_ATTR_TYPE_SET {
				asList = append(asList, param.GetAS()...)
			} else {
				asList = append(asList, 0)
			}
		}
	}
	return asList
}

func (path *Path) GetLabelString() string {
	return bgp.LabelString(path.GetNlri())
}

// PrependAsn prepends AS number.
// This function updates the AS_PATH attribute as follows.
// (If the peer is in the confederation member AS,
//
//	replace AS_SEQUENCE in the following sentence with AS_CONFED_SEQUENCE.)
//	1) if the first path segment of the AS_PATH is of type
//	   AS_SEQUENCE, the local system prepends the specified AS num as
//	   the last element of the sequence (put it in the left-most
//	   position with respect to the position of  octets in the
//	   protocol message) the specified number of times.
//	   If the act of prepending will cause an overflow in the AS_PATH
//	   segment (i.e.,  more than 255 ASes),
//	   it SHOULD prepend a new segment of type AS_SEQUENCE
//	   and prepend its own AS number to this new segment.
//
//	2) if the first path segment of the AS_PATH is of other than type
//	   AS_SEQUENCE, the local system prepends a new path segment of type
//	   AS_SEQUENCE to the AS_PATH, including the specified AS number in
//	   that segment.
//
//	3) if the AS_PATH is empty, the local system creates a path
//	   segment of type AS_SEQUENCE, places the specified AS number
//	   into that segment, and places that segment into the AS_PATH.
func (path *Path) PrependAsn(asn uint32, repeat uint8, confed bool) {
	var segType uint8
	if confed {
		segType = bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ
	} else {
		segType = bgp.BGP_ASPATH_ATTR_TYPE_SEQ
	}

	original := path.GetAsPath()

	asns := make([]uint32, repeat)
	for i := range asns {
		asns[i] = asn
	}

	var asPath *bgp.PathAttributeAsPath
	if original == nil {
		asPath = bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{})
	} else {
		asPath = cloneAsPath(original)
	}

	if len(asPath.Value) > 0 {
		param := asPath.Value[0]
		asList := param.GetAS()
		if param.GetType() == segType {
			if int(repeat)+len(asList) > 255 {
				repeat = uint8(255 - len(asList))
			}
			newAsList := append(asns[:int(repeat)], asList...)
			asPath.Value[0] = bgp.NewAs4PathParam(segType, newAsList)
			asns = asns[int(repeat):]
		}
	}

	if len(asns) > 0 {
		p := bgp.NewAs4PathParam(segType, asns)
		asPath.Value = append([]bgp.AsPathParamInterface{p}, asPath.Value...)
	}
	path.setPathAttr(asPath)
}

func isPrivateAS(as uint32) bool {
	return 64512 <= as && as <= 65534 || 4200000000 <= as && as <= 4294967294
}

func (path *Path) RemovePrivateAS(localAS uint32, option oc.RemovePrivateAsOption) {
	original := path.GetAsPath()
	if original == nil {
		return
	}
	switch option {
	case oc.REMOVE_PRIVATE_AS_OPTION_ALL, oc.REMOVE_PRIVATE_AS_OPTION_REPLACE:
		newASParams := make([]bgp.AsPathParamInterface, 0, len(original.Value))
		for _, param := range original.Value {
			asList := param.GetAS()
			newASParam := make([]uint32, 0, len(asList))
			for _, as := range asList {
				if isPrivateAS(as) {
					if option == oc.REMOVE_PRIVATE_AS_OPTION_REPLACE {
						newASParam = append(newASParam, localAS)
					}
				} else {
					newASParam = append(newASParam, as)
				}
			}
			if len(newASParam) > 0 {
				newASParams = append(newASParams, bgp.NewAs4PathParam(param.GetType(), newASParam))
			}
		}
		path.setPathAttr(bgp.NewPathAttributeAsPath(newASParams))
	}
}

func (path *Path) removeConfedAs() {
	original := path.GetAsPath()
	if original == nil {
		return
	}
	newAsParams := make([]bgp.AsPathParamInterface, 0, len(original.Value))
	for _, param := range original.Value {
		switch param.GetType() {
		case bgp.BGP_ASPATH_ATTR_TYPE_SEQ, bgp.BGP_ASPATH_ATTR_TYPE_SET:
			newAsParams = append(newAsParams, param)
		}
	}
	path.setPathAttr(bgp.NewPathAttributeAsPath(newAsParams))
}

func (path *Path) ReplaceAS(localAS, peerAS uint32) *Path {
	original := path.GetAsPath()
	if original == nil {
		return path
	}
	newASParams := make([]bgp.AsPathParamInterface, 0, len(original.Value))
	changed := false
	for _, param := range original.Value {
		segType := param.GetType()
		asList := param.GetAS()
		newASParam := make([]uint32, 0, len(asList))
		for _, as := range asList {
			if as == peerAS {
				as = localAS
				changed = true
			}
			newASParam = append(newASParam, as)
		}
		newASParams = append(newASParams, bgp.NewAs4PathParam(segType, newASParam))
	}
	if changed {
		path = path.Clone(path.IsWithdraw)
		path.setPathAttr(bgp.NewPathAttributeAsPath(newASParams))
	}
	return path
}

func (path *Path) GetCommunities() []uint32 {
	communityList := []uint32{}
	if attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_COMMUNITIES); attr != nil {
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
		path.delPathAttr(bgp.BGP_ATTR_TYPE_COMMUNITIES)
		return
	}

	newList := make([]uint32, 0)
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_COMMUNITIES)
	if attr != nil {
		c := attr.(*bgp.PathAttributeCommunities)
		if doReplace {
			newList = append(newList, communities...)
		} else {
			newList = append(newList, c.Value...)
			newList = append(newList, communities...)
		}
	} else {
		newList = append(newList, communities...)
	}
	path.setPathAttr(bgp.NewPathAttributeCommunities(newList))
}

// RemoveCommunities removes specific communities.
// If the length of communities is 0, it does nothing.
// If all communities are removed, it removes Communities path attribute itself.
func (path *Path) RemoveCommunities(communities []uint32) int {
	if len(communities) == 0 {
		// do nothing
		return 0
	}

	find := func(val uint32) bool {
		return slices.Contains(communities, val)
	}

	count := 0
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_COMMUNITIES)
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
			path.setPathAttr(bgp.NewPathAttributeCommunities(newList))
		} else {
			path.delPathAttr(bgp.BGP_ATTR_TYPE_COMMUNITIES)
		}
	}
	return count
}

func (path *Path) GetExtCommunities() []bgp.ExtendedCommunityInterface {
	eCommunityList := make([]bgp.ExtendedCommunityInterface, 0)
	if attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_EXTENDED_COMMUNITIES); attr != nil {
		eCommunities := attr.(*bgp.PathAttributeExtendedCommunities).Value
		eCommunityList = append(eCommunityList, eCommunities...)
	}
	return eCommunityList
}

func (path *Path) SetExtCommunities(exts []bgp.ExtendedCommunityInterface, doReplace bool) {
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_EXTENDED_COMMUNITIES)
	if attr != nil {
		l := attr.(*bgp.PathAttributeExtendedCommunities).Value
		if doReplace {
			l = exts
		} else {
			l = append(l, exts...)
		}
		path.setPathAttr(bgp.NewPathAttributeExtendedCommunities(l))
	} else {
		path.setPathAttr(bgp.NewPathAttributeExtendedCommunities(exts))
	}
}

func (path *Path) GetRouteTargets() []bgp.ExtendedCommunityInterface {
	rts := make([]bgp.ExtendedCommunityInterface, 0)
	for _, ec := range path.GetExtCommunities() {
		if t, st := ec.GetTypes(); t <= bgp.EC_TYPE_TRANSITIVE_FOUR_OCTET_AS_SPECIFIC && st == bgp.EC_SUBTYPE_ROUTE_TARGET {
			rts = append(rts, ec)
		}
	}
	return rts
}

func (path *Path) GetLargeCommunities() []*bgp.LargeCommunity {
	if a := path.getPathAttr(bgp.BGP_ATTR_TYPE_LARGE_COMMUNITY); a != nil {
		v := a.(*bgp.PathAttributeLargeCommunities).Values
		ret := make([]*bgp.LargeCommunity, 0, len(v))
		ret = append(ret, v...)
		return ret
	}
	return nil
}

func (path *Path) SetLargeCommunities(cs []*bgp.LargeCommunity, doReplace bool) {
	if len(cs) == 0 && doReplace {
		// clear large communities
		path.delPathAttr(bgp.BGP_ATTR_TYPE_LARGE_COMMUNITY)
		return
	}

	a := path.getPathAttr(bgp.BGP_ATTR_TYPE_LARGE_COMMUNITY)
	if a == nil || doReplace {
		path.setPathAttr(bgp.NewPathAttributeLargeCommunities(cs))
	} else {
		l := a.(*bgp.PathAttributeLargeCommunities).Values
		path.setPathAttr(bgp.NewPathAttributeLargeCommunities(append(l, cs...)))
	}
}

func (path *Path) GetMed() (uint32, error) {
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	if attr == nil {
		return 0, ErrNoMedPathAttr
	}
	return attr.(*bgp.PathAttributeMultiExitDisc).Value, nil
}

// SetMed replace, add or subtraction med with new ones.
func (path *Path) SetMed(med int64, doReplace bool) error {
	parseMed := func(orgMed uint32, med int64, doReplace bool) (*bgp.PathAttributeMultiExitDisc, error) {
		if doReplace {
			return bgp.NewPathAttributeMultiExitDisc(uint32(med)), nil
		}

		medVal := int64(orgMed) + med
		if medVal < 0 {
			return nil, fmt.Errorf("med value invalid. it's underflow threshold: %v", medVal)
		} else if medVal > int64(math.MaxUint32) {
			return nil, fmt.Errorf("med value invalid. it's overflow threshold: %v", medVal)
		}

		return bgp.NewPathAttributeMultiExitDisc(uint32(int64(orgMed) + med)), nil
	}

	m := uint32(0)
	if attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC); attr != nil {
		m = attr.(*bgp.PathAttributeMultiExitDisc).Value
	}
	newMed, err := parseMed(m, med, doReplace)
	if err != nil {
		return err
	}
	path.setPathAttr(newMed)
	return nil
}

func (path *Path) RemoveLocalPref() {
	if path.getPathAttr(bgp.BGP_ATTR_TYPE_LOCAL_PREF) != nil {
		path.delPathAttr(bgp.BGP_ATTR_TYPE_LOCAL_PREF)
	}
}

func (path *Path) GetOriginatorID() netip.Addr {
	if attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGINATOR_ID); attr != nil {
		return attr.(*bgp.PathAttributeOriginatorId).Value
	}
	return netip.Addr{}
}

func (path *Path) GetClusterList() []netip.Addr {
	if attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_CLUSTER_LIST); attr != nil {
		return attr.(*bgp.PathAttributeClusterList).Value
	}
	return nil
}

func (path *Path) GetOrigin() (uint8, error) {
	if attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN); attr != nil {
		return attr.(*bgp.PathAttributeOrigin).Value, nil
	}
	return 0, fmt.Errorf("no origin path attr")
}

func (path *Path) GetLocalPref() (uint32, error) {
	lp := uint32(DEFAULT_LOCAL_PREF)
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_LOCAL_PREF)
	if attr != nil {
		lp = attr.(*bgp.PathAttributeLocalPref).Value
	}
	return lp, nil
}

func (lhs *Path) EqualBySourceAndPathID(rhs *Path) bool {
	if rhs == nil {
		return false
	}
	if lhs == rhs {
		return true
	}

	if !lhs.GetSource().Equal(rhs.GetSource()) {
		return false
	}

	return lhs.remoteID == rhs.remoteID
}

func (lhs *Path) Equal(rhs *Path) bool {
	if rhs == nil {
		return false
	}
	if lhs == rhs {
		return true
	}

	lhsPathAttrs := lhs.GetPathAttrs()
	rhsPathAttrs := rhs.GetPathAttrs()
	// comparing by length first as it's quite fast (with golang slice)
	// and easy to know if paths are different
	if len(lhsPathAttrs) == 0 && len(rhsPathAttrs) == 0 {
		return lhs.EqualBySourceAndPathID(rhs)
	}

	if len(lhsPathAttrs) != len(rhsPathAttrs) {
		return false
	}

	if !lhs.GetSource().Equal(rhs.GetSource()) {
		return false
	}
	// The idea here is to calculate the hash of the attributes on demand
	if lhs.attrsHash > 0 && rhs.attrsHash > 0 { // direct access to the hash to avoid unnecessary hash calculation
		return lhs.attrsHash == rhs.attrsHash
	}
	// slow path comparison, could happen as attributes flags is not part of the hash
	for t, a := range lhsPathAttrs {
		b := rhsPathAttrs[t]
		if a.GetType() != b.GetType() {
			return false
		}
		if a.Len() != b.Len() {
			return false
		}
		if a.GetFlags() != b.GetFlags() {
			return false
		}
	}
	// really slow path comparison, if hash not been calculated yet
	if lhs.GetHash() != rhs.GetHash() {
		return false
	}

	return true
}

func (path *Path) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Nlri       bgp.NLRI                     `json:"nlri"`
		PathAttrs  []bgp.PathAttributeInterface `json:"attrs"`
		Age        int64                        `json:"age"`
		Withdrawal bool                         `json:"withdrawal,omitempty"`
		Validation string                       `json:"validation,omitempty"`
		SourceID   net.IP                       `json:"source-id,omitempty"`
		NeighborIP net.IP                       `json:"neighbor-ip,omitempty"`
		Stale      bool                         `json:"stale,omitempty"`
		UUID       string                       `json:"uuid,omitempty"`
		ID         uint32                       `json:"id,omitempty"`
	}{
		Nlri:       path.GetNlri(),
		PathAttrs:  path.GetPathAttrs(),
		Age:        path.GetTimestamp().Unix(),
		Withdrawal: path.IsWithdraw,
		SourceID:   path.GetSource().ID.AsSlice(),
		NeighborIP: path.GetSource().Address.AsSlice(),
		Stale:      path.IsStale(),
		ID:         path.remoteID,
	})
}

// Return > 0 if lhs is preferred over the rhs
// Return 0 if they are equal
// Return < 0 if rhs is preferred over the lhs
func (lhs *Path) Compare(rhs *Path) int {
	if lhs.IsLocal() && !rhs.IsLocal() {
		return 1
	} else if !lhs.IsLocal() && rhs.IsLocal() {
		return -1
	}

	if !lhs.IsIBGP() && rhs.IsIBGP() {
		return 1
	} else if lhs.IsIBGP() && !rhs.IsIBGP() {
		return -1
	}

	lp1, _ := lhs.GetLocalPref()
	lp2, _ := rhs.GetLocalPref()
	if lp1 != lp2 {
		return int(lp1) - int(lp2)
	}

	l1 := lhs.GetAsPathLen()
	l2 := rhs.GetAsPathLen()
	if l1 != l2 {
		return l2 - l1
	}

	o1, _ := lhs.GetOrigin()
	o2, _ := rhs.GetOrigin()
	if o1 != o2 {
		return int(o2) - int(o1)
	}

	m1, _ := lhs.GetMed()
	m2, _ := rhs.GetMed()
	return int(m2) - int(m1)
}

func (v *Vrf) ToGlobalPath(path *Path) error {
	nlri := path.GetNlri()
	nh := path.GetNexthop()

	switch rf := path.GetFamily(); rf {
	case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
		n := nlri.(*bgp.IPAddrPrefix)
		path.OriginInfo().nlri, _ = bgp.NewLabeledVPNIPAddrPrefix(n.Prefix, *bgp.NewMPLSLabelStack(v.MplsLabel), v.Rd)
		if rf == bgp.RF_IPv4_UC {
			path.family = bgp.RF_IPv4_VPN
		} else {
			path.family = bgp.RF_IPv6_VPN
		}
	case bgp.RF_FS_IPv4_UC, bgp.RF_FS_IPv6_UC:
		n := nlri.(*bgp.FlowSpecNLRI)
		if rf == bgp.RF_FS_IPv4_UC {
			path.family = bgp.RF_FS_IPv4_VPN
		} else {
			path.family = bgp.RF_FS_IPv6_VPN
		}
		path.OriginInfo().nlri, _ = bgp.NewFlowSpecVPN(path.family, v.Rd, n.Value)
	case bgp.RF_EVPN:
		n := nlri.(*bgp.EVPNNLRI)
		switch n.RouteType {
		case bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT:
			n.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute).RD = v.Rd
		case bgp.EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG:
			n.RouteTypeData.(*bgp.EVPNMulticastEthernetTagRoute).RD = v.Rd
		}
	case bgp.RF_MUP_IPv4, bgp.RF_MUP_IPv6:
		n := nlri.(*bgp.MUPNLRI)
		switch n.RouteType {
		case bgp.MUP_ROUTE_TYPE_INTERWORK_SEGMENT_DISCOVERY:
			n.RouteTypeData.(*bgp.MUPInterworkSegmentDiscoveryRoute).RD = v.Rd
		case bgp.MUP_ROUTE_TYPE_DIRECT_SEGMENT_DISCOVERY:
			n.RouteTypeData.(*bgp.MUPDirectSegmentDiscoveryRoute).RD = v.Rd
		case bgp.MUP_ROUTE_TYPE_TYPE_1_SESSION_TRANSFORMED:
			n.RouteTypeData.(*bgp.MUPType1SessionTransformedRoute).RD = v.Rd
		case bgp.MUP_ROUTE_TYPE_TYPE_2_SESSION_TRANSFORMED:
			n.RouteTypeData.(*bgp.MUPType2SessionTransformedRoute).RD = v.Rd
		}
	default:
		return fmt.Errorf("unsupported route family for vrf: %s", rf)
	}
	path.SetExtCommunities(v.ExportRt, false)
	// FIXME: we should not need to keep mp reach in Path.
	path.delPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	mpreach, _ := bgp.NewPathAttributeMpReachNLRI(path.family, []bgp.PathNLRI{{NLRI: path.OriginInfo().nlri, ID: path.localID}}, nh)
	path.setPathAttr(mpreach)
	return nil
}

func (p *Path) ToGlobal(vrf *Vrf) *Path {
	nlri := p.GetNlri()
	nh := p.GetNexthop()
	var newFamily bgp.Family
	switch rf := p.GetFamily(); rf {
	case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
		n := nlri.(*bgp.IPAddrPrefix)
		nlri, _ = bgp.NewLabeledVPNIPAddrPrefix(n.Prefix, *bgp.NewMPLSLabelStack(vrf.MplsLabel), vrf.Rd)
		if rf == bgp.RF_IPv4_UC {
			newFamily = bgp.RF_IPv4_VPN
		} else {
			newFamily = bgp.RF_IPv6_VPN
		}
	case bgp.RF_EVPN:
		n := nlri.(*bgp.EVPNNLRI)
		switch n.RouteType {
		case bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT:
			old := n.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute)
			new := &bgp.EVPNMacIPAdvertisementRoute{
				RD:               vrf.Rd,
				ESI:              old.ESI,
				ETag:             old.ETag,
				MacAddressLength: old.MacAddressLength,
				MacAddress:       old.MacAddress,
				IPAddressLength:  old.IPAddressLength,
				IPAddress:        old.IPAddress,
				Labels:           old.Labels,
			}
			nlri = bgp.NewEVPNNLRI(n.RouteType, new)
		case bgp.EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG:
			old := n.RouteTypeData.(*bgp.EVPNMulticastEthernetTagRoute)
			new := &bgp.EVPNMulticastEthernetTagRoute{
				RD:              vrf.Rd,
				ETag:            old.ETag,
				IPAddressLength: old.IPAddressLength,
				IPAddress:       old.IPAddress,
			}
			nlri = bgp.NewEVPNNLRI(n.RouteType, new)
		}
		newFamily = rf
	case bgp.RF_MUP_IPv4, bgp.RF_MUP_IPv6:
		n := nlri.(*bgp.MUPNLRI)
		switch n.RouteType {
		case bgp.MUP_ROUTE_TYPE_INTERWORK_SEGMENT_DISCOVERY:
			old := n.RouteTypeData.(*bgp.MUPInterworkSegmentDiscoveryRoute)
			nlri = bgp.NewMUPInterworkSegmentDiscoveryRoute(vrf.Rd, old.Prefix)
		case bgp.MUP_ROUTE_TYPE_DIRECT_SEGMENT_DISCOVERY:
			old := n.RouteTypeData.(*bgp.MUPDirectSegmentDiscoveryRoute)
			nlri = bgp.NewMUPDirectSegmentDiscoveryRoute(vrf.Rd, old.Address)
		case bgp.MUP_ROUTE_TYPE_TYPE_1_SESSION_TRANSFORMED:
			old := n.RouteTypeData.(*bgp.MUPType1SessionTransformedRoute)
			nlri = bgp.NewMUPType1SessionTransformedRoute(vrf.Rd, old.Prefix, old.TEID, old.QFI, old.EndpointAddress, old.SourceAddress)
		case bgp.MUP_ROUTE_TYPE_TYPE_2_SESSION_TRANSFORMED:
			old := n.RouteTypeData.(*bgp.MUPType2SessionTransformedRoute)
			nlri = bgp.NewMUPType2SessionTransformedRoute(vrf.Rd, old.EndpointAddressLength, old.EndpointAddress, old.TEID)
		}
		newFamily = rf
	default:
		return p
	}
	path := NewPath(newFamily, p.OriginInfo().source, bgp.PathNLRI{NLRI: nlri}, p.IsWithdraw, p.GetPathAttrs(), p.GetTimestamp(), false)
	path.SetExtCommunities(vrf.ExportRt, false)
	path.delPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	attr, _ := bgp.NewPathAttributeMpReachNLRI(newFamily, []bgp.PathNLRI{{NLRI: nlri, ID: p.localID}}, nh)
	path.setPathAttr(attr)
	path.localID = p.localID
	path.remoteID = p.remoteID
	return path
}

func (p *Path) ToLocal() *Path {
	var newFamily bgp.Family
	nlri := p.GetNlri()
	f := p.GetFamily()
	switch f {
	case bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN:
		n := nlri.(*bgp.LabeledVPNIPAddrPrefix)
		nlri, _ = bgp.NewIPAddrPrefix(n.Prefix)
		if f == bgp.RF_IPv4_VPN {
			newFamily = bgp.RF_IPv4_UC
		} else {
			newFamily = bgp.RF_IPv6_UC
		}
	case bgp.RF_FS_IPv4_VPN, bgp.RF_FS_IPv6_VPN:
		n := nlri.(*bgp.FlowSpecNLRI)
		newFamily = bgp.RF_FS_IPv4_UC
		if f == bgp.RF_FS_IPv6_VPN {
			newFamily = bgp.RF_FS_IPv6_UC
		}
		nlri, _ = bgp.NewFlowSpecUnicast(newFamily, n.Value)
	default:
		return p
	}
	path := NewPath(newFamily, p.OriginInfo().source, bgp.PathNLRI{NLRI: nlri}, p.IsWithdraw, p.GetPathAttrs(), p.GetTimestamp(), false)
	switch f {
	case bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN:
		path.delPathAttr(bgp.BGP_ATTR_TYPE_EXTENDED_COMMUNITIES)
	case bgp.RF_FS_IPv4_VPN, bgp.RF_FS_IPv6_VPN:
		extcomms := path.GetExtCommunities()
		newExtComms := make([]bgp.ExtendedCommunityInterface, 0, len(extcomms))
		for _, extComm := range extcomms {
			_, subType := extComm.GetTypes()
			if subType == bgp.EC_SUBTYPE_ROUTE_TARGET {
				continue
			}
			newExtComms = append(newExtComms, extComm)
		}
		path.SetExtCommunities(newExtComms, true)
	}

	if f == bgp.RF_IPv4_VPN {
		nh := path.GetNexthop()
		path.delPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
		pa, _ := bgp.NewPathAttributeNextHop(nh)
		path.setPathAttr(pa)
	}
	path.IsNexthopInvalid = p.IsNexthopInvalid
	path.localID = p.localID
	path.remoteID = p.remoteID
	return path
}

func (p *Path) updateHash() {
	p.attrsHash = fnv1a.Init64
	for _, a := range p.GetPathAttrs() {
		d, _ := a.Serialize()
		p.attrsHash = fnv1a.AddBytes64(p.attrsHash, d)
	}
}

func (p *Path) SetHash(v uint64) {
	p.attrsHash = v
}

// GetHash returns the hash value of the path attributes.
func (p *Path) GetHash() uint64 {
	if p.attrsHash == 0 {
		p.updateHash()
	}
	return p.attrsHash
}

func (p *Path) SetSource(peerInfo *PeerInfo) {
	if p.info != nil {
		p.info.source = peerInfo
	}
}

func (p *Path) LocalID() uint32 {
	return p.localID
}

func (p *Path) RemoteID() uint32 {
	return p.remoteID
}

func nlriToIPNet(nlri bgp.NLRI) *net.IPNet {
	switch T := nlri.(type) {
	case *bgp.IPAddrPrefix:
		return &net.IPNet{
			IP:   T.Prefix.Addr().AsSlice(),
			Mask: net.CIDRMask(T.Prefix.Bits(), T.Prefix.Addr().BitLen()),
		}
	case *bgp.LabeledIPAddrPrefix:
		return &net.IPNet{
			IP:   T.Prefix.Masked().Addr().AsSlice(),
			Mask: net.CIDRMask(T.Prefix.Bits(), T.Prefix.Addr().BitLen()),
		}
	case *bgp.LabeledVPNIPAddrPrefix:
		return &net.IPNet{
			IP:   T.Prefix.Addr().AsSlice(),
			Mask: net.CIDRMask(T.Prefix.Bits(), T.Prefix.Addr().BitLen()),
		}
	}
	return nil
}

func bestPathListForRT(id string, as uint32, withdraw bool, inPaths map[*Path]struct{}, outPaths []*Path) []*Path {
	for p := range inPaths {
		if p.IsNexthopInvalid || rsFilter(id, as, p) {
			continue
		}
		if !p.IsWithdraw && withdraw {
			p = p.Clone(true)
		}
		outPaths = append(outPaths, p)
	}
	return outPaths
}

func (t *Table) HasRT(key uint64) bool {
	if t.rtc == nil {
		return false
	}
	if rtPaths, ok := t.rtc.(*routeFamilyRTCMap); ok {
		num, found := rtPaths.rts[key]
		return found && num > 0
	}
	return false
}

func (t *Table) bestPathListForRTMaxLen(rt uint64) int {
	if t.rtc == nil {
		return 0
	}
	if vpnPaths, ok := t.rtc.(*vpnFamilyRTCMap); ok {
		if rtTable, found := vpnPaths.rts[rt]; found {
			return len(rtTable.paths)
		}
	}
	return 0
}

func (t *Table) getBestsForDetachedRTFromPeer(rt uint64, peerId string, tableId string, as uint32, paths []*Path) []*Path {
	if t.rtc == nil {
		// Note: "return paths" means "no new paths are returned".
		return paths
	}
	if vpnPaths, ok := t.rtc.(*vpnFamilyRTCMap); ok {
		if rtTable, found := vpnPaths.rts[rt]; found {
			if _, foundId := rtTable.peers[peerId]; foundId {
				delete(rtTable.peers, peerId)
				if !rtTable.empty() {
					return bestPathListForRT(tableId, as, true, rtTable.paths, paths)
				}
				delete(vpnPaths.rts, rt)
			}
		}
	}
	return paths
}

func (t *Table) getBestsForNewlyAttachedRTtoPeer(rt uint64, peerId string, tableId string, as uint32, paths []*Path) []*Path {
	if t.rtc == nil {
		// Note: "return paths" means "no new paths are returned".
		return paths
	}
	if vpnPaths, ok := t.rtc.(*vpnFamilyRTCMap); ok {
		if rtTable, found := vpnPaths.rts[rt]; !found {
			rtTable = newVpnFamilyRT()
			vpnPaths.rts[rt] = rtTable
			rtTable.peers[peerId] = struct{}{}
		} else {
			if _, foundId := rtTable.peers[peerId]; !foundId {
				rtTable.peers[peerId] = struct{}{}
				return bestPathListForRT(tableId, as, false, rtTable.paths, paths)
			}
		}
	}
	return paths
}
