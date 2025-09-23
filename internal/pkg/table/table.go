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
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math/bits"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/k-sone/critbitgo"
	"github.com/segmentio/fasthash/fnv1a"

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func addrPrefixOnlySerialize(nlri bgp.NLRI) []byte {
	switch T := nlri.(type) {
	case *bgp.IPAddrPrefix:
		byteLen := T.Prefix.Addr().BitLen() / 8
		b := make([]byte, byteLen+1)
		copy(b, T.Prefix.Addr().AsSlice())
		b[byteLen] = uint8(T.Prefix.Bits())
		return b
	case *bgp.LabeledVPNIPAddrPrefix:
		byteLen := T.Prefix.Addr().BitLen() / 8
		// RD and length
		b := make([]byte, byteLen+9)
		serializedRD, _ := T.RD.Serialize()
		copy(b, serializedRD)
		copy(b[8:], T.Prefix.Addr().AsSlice())
		b[8+byteLen] = uint8(T.Prefix.Bits())
		return b
	}
	return []byte(nlri.String())
}

func AddrPrefixOnlyCompare(a, b bgp.NLRI) int {
	return bytes.Compare(addrPrefixOnlySerialize(a), addrPrefixOnlySerialize(b))
}

// used internally, should not be aliassed
type (
	addrPrefixKey uint64
	macKey        uint64
)

type TableSelectOption struct {
	ID             string
	AS             uint32
	LookupPrefixes []*apiutil.LookupPrefix
	VRF            *Vrf
	adj            bool
	Best           bool
	MultiPath      bool
}

func tableKey(nlri bgp.NLRI) addrPrefixKey {
	h := fnv1a.Init64
	switch T := nlri.(type) {
	case *bgp.IPAddrPrefix:
		h = fnv1a.AddBytes64(h, T.Prefix.Addr().AsSlice())
		h = fnv1a.AddBytes64(h, []byte{uint8(T.Prefix.Bits())})
	case *bgp.LabeledVPNIPAddrPrefix:
		serializedRD, _ := T.RD.Serialize()
		h = fnv1a.AddBytes64(h, serializedRD)
		h = fnv1a.AddBytes64(h, T.Prefix.Addr().AsSlice())
		h = fnv1a.AddBytes64(h, []byte{uint8(T.Prefix.Bits())})
	default:
		h = fnv1a.AddString64(h, nlri.String())
	}
	return addrPrefixKey(h)
}

type Destinations map[addrPrefixKey][]*Destination

func (d Destinations) getDestinationList(nlri bgp.NLRI) []*Destination {
	dest, ok := d[tableKey(nlri)]
	if !ok {
		return nil
	}
	return dest
}

func (d Destinations) Get(nlri bgp.NLRI) *Destination {
	for _, d := range d.getDestinationList(nlri) {
		if AddrPrefixOnlyCompare(d.nlri, nlri) == 0 {
			return d
		}
	}
	return nil
}

func (d Destinations) InsertUpdate(dest *Destination) (collision bool) {
	nlri := dest.nlri
	key := tableKey(nlri)
	new := false
	if _, ok := d[key]; !ok {
		d[key] = make([]*Destination, 0)
		new = true
	}
	for i, v := range d[key] {
		if AddrPrefixOnlyCompare(v.nlri, nlri) == 0 {
			d[key][i] = dest
			return collision
		}
	}
	if !new {
		// we have collision
		collision = true
	}
	d[key] = append(d[key], dest)
	return collision
}

func (d Destinations) Remove(nlri bgp.NLRI) {
	key := tableKey(nlri)
	if _, ok := d[key]; !ok {
		return
	}
	for i, v := range d[key] {
		if AddrPrefixOnlyCompare(v.nlri, nlri) == 0 {
			d[key] = append(d[key][:i], d[key][i+1:]...)
			if len(d[key]) == 0 {
				delete(d, key)
			}
			return
		}
	}
}

func macKeyHash(rt bgp.ExtendedCommunityInterface, mac net.HardwareAddr) macKey {
	b, _ := rt.Serialize()
	b = append(b, mac...)
	return macKey(fnv1a.HashBytes64(b))
}

type EVPNMacNLRIs map[macKey]map[*Destination]struct{}

func (e EVPNMacNLRIs) Get(rt bgp.ExtendedCommunityInterface, mac net.HardwareAddr) (d []*Destination) {
	if dests, ok := e[macKeyHash(rt, mac)]; ok {
		d = make([]*Destination, len(dests))
		i := 0
		for dest := range dests {
			d[i] = dest
			i++
		}
	}
	return d
}

func (e EVPNMacNLRIs) Insert(rt bgp.ExtendedCommunityInterface, mac net.HardwareAddr, dest *Destination) {
	macKey := macKeyHash(rt, mac)
	if _, ok := e[macKey]; !ok {
		e[macKey] = make(map[*Destination]struct{})
	}
	e[macKey][dest] = struct{}{}
}

func (e EVPNMacNLRIs) Remove(rt bgp.ExtendedCommunityInterface, mac net.HardwareAddr, dest *Destination) {
	macKey := macKeyHash(rt, mac)
	if dests, ok := e[macKey]; ok {
		delete(dests, dest)
		if len(dests) == 0 {
			delete(e, macKey)
		}
	}
}

type Table struct {
	Family       bgp.Family
	destinations Destinations
	logger       *slog.Logger
	// index of evpn prefixes with paths to a specific MAC in a MAC-VRF
	// this is a map[rt, MAC address]map[addrPrefixKey][]nlri
	// this holds a map for a set of prefixes.
	macIndex EVPNMacNLRIs
}

func NewTable(logger *slog.Logger, rf bgp.Family, dsts ...*Destination) *Table {
	t := &Table{
		Family:       rf,
		destinations: make(Destinations),
		logger:       logger,
		macIndex:     make(EVPNMacNLRIs),
	}
	for _, dst := range dsts {
		t.setDestination(dst)
	}
	return t
}

func (t *Table) GetFamily() bgp.Family {
	return t.Family
}

func (t *Table) deletePathsByVrf(vrf *Vrf) []*Path {
	pathList := make([]*Path, 0)
	for _, dests := range t.destinations {
		for _, dest := range dests {
			for _, p := range dest.knownPathList {
				var rd bgp.RouteDistinguisherInterface
				nlri := p.GetNlri()
				switch v := nlri.(type) {
				case *bgp.LabeledVPNIPAddrPrefix:
					rd = v.RD
				case *bgp.EVPNNLRI:
					rd = v.RD()
				case *bgp.MUPNLRI:
					rd = v.RD()
				default:
					return pathList
				}
				if p.IsLocal() && vrf.Rd.String() == rd.String() {
					pathList = append(pathList, p.Clone(true))
					break
				}
			}
		}
	}
	return pathList
}

func (t *Table) deleteRTCPathsByVrf(vrf *Vrf, vrfs map[string]*Vrf) []*Path {
	pathList := make([]*Path, 0)
	if t.Family != bgp.RF_RTC_UC {
		return pathList
	}
	for lhs := range vrf.ImportRt {
		for _, dests := range t.destinations {
			for _, dest := range dests {
				nlri := dest.GetNlri().(*bgp.RouteTargetMembershipNLRI)
				rhs, _ := extCommRouteTargetKey(nlri.RouteTarget)
				if lhs == rhs && isLastTargetUser(vrfs, lhs) {
					for _, p := range dest.knownPathList {
						if p.IsLocal() {
							pathList = append(pathList, p.Clone(true))
							break
						}
					}
				}
			}
		}
	}
	return pathList
}

func (t *Table) deleteDest(dest *Destination) {
	count := 0
	for _, v := range dest.localIdMap.bitmap {
		count += bits.OnesCount64(v)
	}
	if len(dest.localIdMap.bitmap) != 0 && count != 1 {
		return
	}
	t.destinations.Remove(dest.GetNlri())

	if nlri, ok := dest.nlri.(*bgp.EVPNNLRI); ok {
		if macadv, ok := nlri.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute); ok {
			for _, path := range dest.knownPathList {
				for _, ec := range path.GetRouteTargets() {
					t.macIndex.Remove(ec, macadv.MacAddress, dest)
				}
			}
		}
	}
}

func (t *Table) validatePath(path *Path) {
	if path == nil {
		t.logger.Error("path is nil",
			slog.String("Topic", "Table"),
			slog.String("Key", t.Family.String()),
		)
	}
	if path.GetFamily() != t.Family {
		t.logger.Error("Invalid path. Family mismatch",
			slog.String("Topic", "Table"),
			slog.String("Key", t.Family.String()),
			slog.Any("Prefix", path.GetPrefix()),
			slog.String("ReceivedRf", path.GetFamily().String()),
		)
	}
	if attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH); attr != nil {
		pathParam := attr.(*bgp.PathAttributeAsPath).Value
		for _, as := range pathParam {
			_, y := as.(*bgp.As4PathParam)
			if !y {
				t.logger.Error("AsPathParam must be converted to As4PathParam",
					slog.String("Topic", "Table"),
					slog.String("Key", t.Family.String()),
					slog.Any("As", as),
				)
			}
		}
	}
	if attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_AS4_PATH); attr != nil {
		t.logger.Error("AS4_PATH must be converted to AS_PATH",
			slog.String("Topic", "Table"),
			slog.String("Key", t.Family.String()),
		)
	}
	if path.GetNlri() == nil {
		t.logger.Error("path's nlri is nil",
			slog.String("Topic", "Table"),
			slog.String("Key", t.Family.String()),
		)
	}
}

func (t *Table) getOrCreateDest(nlri bgp.NLRI, size int) *Destination {
	dest := t.GetDestination(nlri)
	// If destination for given prefix does not exist we create it.
	if dest == nil {
		t.logger.Debug("create Destination",
			slog.String("Topic", "Table"),
			slog.Any("Nlri", nlri),
		)
		dest = NewDestination(nlri, size)
		t.setDestination(dest)
	}
	return dest
}

func (t *Table) update(newPath *Path) *Update {
	t.validatePath(newPath)
	dst := t.getOrCreateDest(newPath.GetNlri(), 64)
	u := dst.Calculate(t.logger, newPath)

	if len(dst.knownPathList) == 0 {
		t.deleteDest(dst)
		return u
	}

	if nlri, ok := newPath.GetNlri().(*bgp.EVPNNLRI); ok {
		if macadv, ok := nlri.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute); ok {
			for _, ec := range newPath.GetRouteTargets() {
				t.macIndex.Insert(ec, macadv.MacAddress, dst)
			}
		}
	}

	return u
}

func (t *Table) GetDestinations() []*Destination {
	d := make([]*Destination, 0, len(t.destinations))
	for _, dests := range t.destinations {
		d = append(d, dests...)
	}
	return d
}

func (t *Table) GetDestination(nlri bgp.NLRI) *Destination {
	return t.destinations.Get(nlri)
}

func (t *Table) GetLongerPrefixDestinations(key string) ([]*Destination, error) {
	results := make([]*Destination, 0, len(t.GetDestinations()))
	switch t.Family {
	case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC, bgp.RF_IPv4_MPLS, bgp.RF_IPv6_MPLS:
		_, prefix, err := net.ParseCIDR(key)
		if err != nil {
			return nil, fmt.Errorf("error parsing cidr %s: %v", key, err)
		}
		ones, bits := prefix.Mask.Size()

		r := critbitgo.NewNet()
		for _, dst := range t.GetDestinations() {
			_ = r.Add(nlriToIPNet(dst.nlri), dst)
		}
		p := &net.IPNet{
			IP:   prefix.IP,
			Mask: net.CIDRMask(ones>>3<<3, bits),
		}
		mask := 0
		div := 0
		if ones%8 != 0 {
			mask = 8 - ones&0x7
			div = ones >> 3
		}
		r.WalkPrefix(p, func(n *net.IPNet, v any) bool {
			if mask != 0 && n.IP[div]>>mask != p.IP[div]>>mask {
				return true
			}
			l, _ := n.Mask.Size()

			if ones > l {
				return true
			}
			results = append(results, v.(*Destination))
			return true
		})
	case bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN:
		prefixRd, prefix, err := bgp.ParseVPNPrefix(key)
		if err != nil {
			return nil, err
		}
		ones := prefix.Bits()
		bits := prefix.Addr().BitLen()

		r := critbitgo.NewNet()
		for _, dst := range t.GetDestinations() {
			dstRD := dst.nlri.(*bgp.LabeledVPNIPAddrPrefix).RD
			if prefixRd.String() != dstRD.String() {
				continue
			}

			_ = r.Add(nlriToIPNet(dst.nlri), dst)
		}

		p := &net.IPNet{
			IP:   prefix.Addr().AsSlice(),
			Mask: net.CIDRMask(ones>>3<<3, bits),
		}

		mask := 0
		div := 0
		if ones%8 != 0 {
			mask = 8 - ones&0x7
			div = ones >> 3
		}

		r.WalkPrefix(p, func(n *net.IPNet, v any) bool {
			if mask != 0 && n.IP[div]>>mask != p.IP[div]>>mask {
				return true
			}
			l, _ := n.Mask.Size()

			if ones > l {
				return true
			}
			results = append(results, v.(*Destination))
			return true
		})
	default:
		results = append(results, t.GetDestinations()...)
	}
	return results, nil
}

func (t *Table) GetEvpnDestinationsWithRouteType(typ string) ([]*Destination, error) {
	var routeType uint8
	switch strings.ToLower(typ) {
	case "a-d":
		routeType = bgp.EVPN_ROUTE_TYPE_ETHERNET_AUTO_DISCOVERY
	case "macadv":
		routeType = bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT
	case "multicast":
		routeType = bgp.EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG
	case "esi":
		routeType = bgp.EVPN_ETHERNET_SEGMENT_ROUTE
	case "prefix":
		routeType = bgp.EVPN_IP_PREFIX
	default:
		return nil, fmt.Errorf("unsupported evpn route type: %s", typ)
	}
	destinations := t.GetDestinations()
	results := make([]*Destination, 0, len(destinations))
	switch t.Family {
	case bgp.RF_EVPN:
		for _, dst := range destinations {
			if nlri, ok := dst.nlri.(*bgp.EVPNNLRI); !ok {
				return nil, fmt.Errorf("invalid evpn nlri type detected: %T", dst.nlri)
			} else if nlri.RouteType == routeType {
				results = append(results, dst)
			}
		}
	default:
		results = append(results, destinations...)
	}
	return results, nil
}

func (t *Table) GetMUPDestinationsWithRouteType(p string) ([]*Destination, error) {
	var routeType uint16
	switch strings.ToLower(p) {
	case "isd":
		routeType = bgp.MUP_ROUTE_TYPE_INTERWORK_SEGMENT_DISCOVERY
	case "dsd":
		routeType = bgp.MUP_ROUTE_TYPE_DIRECT_SEGMENT_DISCOVERY
	case "t1st":
		routeType = bgp.MUP_ROUTE_TYPE_TYPE_1_SESSION_TRANSFORMED
	case "t2st":
		routeType = bgp.MUP_ROUTE_TYPE_TYPE_2_SESSION_TRANSFORMED
	default:
		// use prefix as route key
	}
	destinations := t.GetDestinations()
	results := make([]*Destination, 0, len(destinations))
	switch t.Family {
	case bgp.RF_MUP_IPv4, bgp.RF_MUP_IPv6:
		for _, dst := range destinations {
			if nlri, ok := dst.nlri.(*bgp.MUPNLRI); !ok {
				return nil, fmt.Errorf("invalid mup nlri type detected: %T", dst.nlri)
			} else if nlri.RouteType == routeType {
				results = append(results, dst)
			} else if nlri.String() == p {
				results = append(results, dst)
			}
		}
	default:
		results = append(results, destinations...)
	}
	return results, nil
}

func (t *Table) setDestination(dst *Destination) {
	if collision := t.destinations.InsertUpdate(dst); collision {
		t.logger.Warn("insert collision detected",
			slog.String("Topic", "Table"),
			slog.String("Key", t.Family.String()),
			slog.String("1stPrefix", t.destinations.getDestinationList(dst.GetNlri())[0].GetNlri().String()),
			slog.String("Prefix", dst.GetNlri().String()),
		)
	}

	if nlri, ok := dst.nlri.(*bgp.EVPNNLRI); ok {
		if macadv, ok := nlri.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute); ok {
			for _, path := range dst.knownPathList {
				for _, ec := range path.GetRouteTargets() {
					t.macIndex.Insert(ec, macadv.MacAddress, dst)
				}
			}
		}
	}
}

func (t *Table) Bests(id string, as uint32) []*Path {
	paths := make([]*Path, 0, len(t.destinations))
	for _, dst := range t.GetDestinations() {
		path := dst.GetBestPath(id, as)
		if path != nil {
			paths = append(paths, path)
		}
	}
	return paths
}

func (t *Table) MultiBests(id string) [][]*Path {
	paths := make([][]*Path, 0, len(t.destinations))
	for _, dst := range t.GetDestinations() {
		path := dst.GetMultiBestPath(id)
		if path != nil {
			paths = append(paths, path)
		}
	}
	return paths
}

func (t *Table) GetKnownPathList(id string, as uint32) []*Path {
	paths := make([]*Path, 0, len(t.destinations))
	for _, dst := range t.GetDestinations() {
		paths = append(paths, dst.GetKnownPathList(id, as)...)
	}
	return paths
}

func (t *Table) GetKnownPathListWithMac(id string, as uint32, rt bgp.ExtendedCommunityInterface, mac net.HardwareAddr, onlyBest bool) []*Path {
	var paths []*Path
	for _, dst := range t.macIndex.Get(rt, mac) {
		if onlyBest {
			paths = append(paths, dst.GetBestPath(id, as))
		} else {
			paths = append(paths, dst.GetKnownPathList(id, as)...)
		}
	}
	return paths
}

// ContainsCIDR checks if one IPNet is a subnet of another.
func containsCIDR(n1, n2 *net.IPNet) bool {
	ones1, _ := n1.Mask.Size()
	ones2, _ := n2.Mask.Size()
	return ones1 <= ones2 && n1.Contains(n2.IP)
}

func (t *Table) Select(option ...TableSelectOption) (*Table, error) {
	id := GLOBAL_RIB_NAME
	var vrf *Vrf
	adj := false
	prefixes := make([]*apiutil.LookupPrefix, 0, len(option))
	best := false
	mp := false
	as := uint32(0)
	for _, o := range option {
		if o.ID != "" {
			id = o.ID
		}
		if o.VRF != nil {
			vrf = o.VRF
		}
		adj = o.adj
		prefixes = append(prefixes, o.LookupPrefixes...)
		best = o.Best
		mp = o.MultiPath
		as = o.AS
	}
	dOption := DestinationSelectOption{ID: id, AS: as, VRF: vrf, adj: adj, Best: best, MultiPath: mp}
	r := NewTable(nil, t.Family)

	if len(prefixes) != 0 {
		switch t.Family {
		case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
			f := func(prefixStr string) (bool, error) {
				prefix, err := netip.ParsePrefix(prefixStr)
				if err != nil {
					return false, err
				}
				nlri, err := bgp.NewIPAddrPrefix(prefix)
				if err != nil {
					return false, err
				}
				if dst := t.GetDestination(nlri); dst != nil {
					if d := dst.Select(dOption); d != nil {
						r.setDestination(d)
						return true, nil
					}
				}
				return false, nil
			}

			for _, p := range prefixes {
				key := p.Prefix
				switch p.LookupOption {
				case apiutil.LOOKUP_LONGER:
					ds, err := t.GetLongerPrefixDestinations(key)
					if err != nil {
						return nil, err
					}
					for _, dst := range ds {
						if d := dst.Select(dOption); d != nil {
							r.setDestination(d)
						}
					}
				case apiutil.LOOKUP_SHORTER:
					addr, prefix, err := net.ParseCIDR(key)
					if err != nil {
						return nil, err
					}
					ones, _ := prefix.Mask.Size()
					for i := ones; i >= 0; i-- {
						_, prefix, _ := net.ParseCIDR(fmt.Sprintf("%s/%d", addr.String(), i))
						ret, err := f(prefix.String())
						if err != nil {
							return nil, err
						}
						if ret {
							break
						}
					}
				default:
					if host := net.ParseIP(key); host != nil {
						masklen := 32
						if t.Family == bgp.RF_IPv6_UC {
							masklen = 128
						}
						for i := masklen; i >= 0; i-- {
							_, prefix, err := net.ParseCIDR(fmt.Sprintf("%s/%d", key, i))
							if err != nil {
								return nil, err
							}
							ret, err := f(prefix.String())
							if err != nil {
								return nil, err
							}
							if ret {
								break
							}
						}
					} else if _, err := f(key); err != nil {
						return nil, err
					}
				}
			}
		case bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN:
			f := func(prefixStr string) error {
				rd, p, err := bgp.ParseVPNPrefix(prefixStr)
				if err != nil {
					return err
				}

				nlri, _ := bgp.NewLabeledVPNIPAddrPrefix(p, *bgp.NewMPLSLabelStack(), rd)
				if dst := t.GetDestination(nlri); dst != nil {
					if d := dst.Select(dOption); d != nil {
						r.setDestination(d)
					}
				}
				return nil
			}

			for _, p := range prefixes {
				switch p.LookupOption {
				case apiutil.LOOKUP_LONGER:
					_, prefix, err := net.ParseCIDR(p.Prefix)
					if err != nil {
						return nil, err
					}

					if p.RD == "" {
						for _, dst := range t.GetDestinations() {
							tablePrefix := nlriToIPNet(dst.nlri)

							if containsCIDR(prefix, tablePrefix) {
								r.setDestination(dst)
							}
						}

						return r, nil
					}

					ds, err := t.GetLongerPrefixDestinations(p.RD + ":" + p.Prefix)
					if err != nil {
						return nil, err
					}

					for _, dst := range ds {
						if d := dst.Select(dOption); d != nil {
							r.setDestination(d)
						}
					}
				case apiutil.LOOKUP_SHORTER:
					addr, prefix, err := net.ParseCIDR(p.Prefix)
					if err != nil {
						return nil, err
					}

					if p.RD == "" {
						for _, dst := range t.GetDestinations() {
							tablePrefix := nlriToIPNet(dst.nlri)

							if containsCIDR(tablePrefix, prefix) {
								r.setDestination(dst)
							}
						}

						return r, nil
					}

					rd, err := bgp.ParseRouteDistinguisher(p.RD)
					if err != nil {
						return nil, err
					}

					ones, _ := prefix.Mask.Size()
					for i := ones; i >= 0; i-- {
						_, prefix, _ := net.ParseCIDR(addr.String() + "/" + strconv.Itoa(i))

						err := f(rd.String() + ":" + prefix.String())
						if err != nil {
							return nil, err
						}
					}
				default:
					if p.RD == "" {
						for _, dst := range t.GetDestinations() {
							net := nlriToIPNet(dst.nlri)
							if net.String() == p.Prefix {
								r.setDestination(dst)
							}
						}

						return r, nil
					}

					err := f(p.RD + ":" + p.Prefix)
					if err != nil {
						return nil, err
					}
				}
			}
		case bgp.RF_EVPN:
			for _, p := range prefixes {
				// Uses LookupPrefix.Prefix as EVPN Route Type string
				ds, err := t.GetEvpnDestinationsWithRouteType(p.Prefix)
				if err != nil {
					return nil, err
				}
				for _, dst := range ds {
					if d := dst.Select(dOption); d != nil {
						r.setDestination(d)
					}
				}
			}
		case bgp.RF_MUP_IPv4, bgp.RF_MUP_IPv6:
			for _, p := range prefixes {
				ds, err := t.GetMUPDestinationsWithRouteType(p.Prefix)
				if err != nil {
					return nil, err
				}
				for _, dst := range ds {
					if d := dst.Select(dOption); d != nil {
						r.setDestination(d)
					}
				}
			}
		default:
			return nil, fmt.Errorf("route filtering is not supported for this family")
		}
	} else {
		for _, dst := range t.GetDestinations() {
			if d := dst.Select(dOption); d != nil {
				r.setDestination(d)
			}
		}
	}
	return r, nil
}

type TableInfo struct {
	NumDestination int
	NumPath        int
	NumAccepted    int
	NumCollision   int
}

type TableInfoOptions struct {
	ID  string
	AS  uint32
	VRF *Vrf
}

func (t *Table) Info(option ...TableInfoOptions) *TableInfo {
	var numD, numP, numC int

	id := GLOBAL_RIB_NAME
	var vrf *Vrf
	as := uint32(0)

	for _, o := range option {
		if o.ID != "" {
			id = o.ID
		}
		if o.VRF != nil {
			vrf = o.VRF
		}
		as = o.AS
	}

	for _, dests := range t.destinations {
		if len(dests) > 1 {
			numC += len(dests) - 1
		}
		for _, d := range dests {
			paths := d.GetKnownPathList(id, as)
			n := len(paths)

			if vrf != nil {
				ps := make([]*Path, 0, len(paths))
				for _, p := range paths {
					if CanImportToVrf(vrf, p) {
						ps = append(ps, p.ToLocal())
					}
				}
				n = len(ps)
			}
			if n != 0 {
				numD++
				numP += n
			}
		}
	}
	return &TableInfo{
		NumDestination: numD,
		NumPath:        numP,
		NumCollision:   numC,
	}
}

var (
	ErrInvalidRouteTarget error = errors.New("ExtendedCommunity is not RouteTarget")
	ErrNilCommunity       error = errors.New("RouteTarget could not be nil")
)

func extCommRouteTargetKey(routeTarget bgp.ExtendedCommunityInterface) (uint64, error) {
	if routeTarget == nil {
		return 0, ErrNilCommunity
	}
	switch rt := routeTarget.(type) {
	case *bgp.TwoOctetAsSpecificExtended, *bgp.IPv4AddressSpecificExtended, *bgp.FourOctetAsSpecificExtended:
		bytes, err := rt.Serialize()
		if err != nil {
			return 0, err
		}
		return binary.BigEndian.Uint64(bytes[:]), nil
	default:
		return 0, ErrInvalidRouteTarget
	}
}

type routeTargetMap map[uint64]bgp.ExtendedCommunityInterface

func (rtm routeTargetMap) ToSlice() []bgp.ExtendedCommunityInterface {
	s := make([]bgp.ExtendedCommunityInterface, 0, len(rtm))
	for _, rt := range rtm {
		s = append(s, rt)
	}
	return s
}

func (rtm routeTargetMap) Clone() routeTargetMap {
	rts := make(routeTargetMap, len(rtm))
	for key, rt := range rtm {
		rts[key] = rt
	}
	return rts
}

func newRouteTargetMap(s []bgp.ExtendedCommunityInterface) (routeTargetMap, error) {
	m := make(routeTargetMap, len(s))
	for _, rt := range s {
		key, err := extCommRouteTargetKey(rt)
		if err != nil {
			return nil, err
		}
		m[key] = rt
	}
	return m, nil
}
