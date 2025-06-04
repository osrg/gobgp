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
	"maps"
	"math/bits"
	"net"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"github.com/k-sone/critbitgo"

	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

type LookupOption uint8

const (
	LOOKUP_EXACT LookupOption = iota
	LOOKUP_LONGER
	LOOKUP_SHORTER
)

type LookupPrefix struct {
	Prefix string
	RD     string
	LookupOption
}

type TableSelectOption struct {
	ID             string
	AS             uint32
	LookupPrefixes []*LookupPrefix
	VRF            *Vrf
	adj            bool
	Best           bool
	MultiPath      bool
}

type Table struct {
	mu sync.RWMutex

	family       bgp.Family
	destinations map[string]*Destination
	logger       log.Logger
	// index of evpn prefixes with paths to a specific MAC in a MAC-VRF
	// this is a map[rt, MAC address]map[prefix]struct{}
	// this holds a map for a set of prefixes.
	macIndex map[string]map[string]struct{}
}

func tableKey(nlri bgp.AddrPrefixInterface) string {
	switch T := nlri.(type) {
	case *bgp.IPAddrPrefix:
		b := make([]byte, 5)
		copy(b, T.Prefix.To4())
		b[4] = T.Length
		return *(*string)(unsafe.Pointer(&b))
	case *bgp.IPv6AddrPrefix:
		b := make([]byte, 17)
		copy(b, T.Prefix.To16())
		b[16] = T.Length
		return *(*string)(unsafe.Pointer(&b))
	case *bgp.LabeledVPNIPAddrPrefix:
		b := make([]byte, 13)
		serializedRD, _ := T.RD.Serialize()
		copy(b, serializedRD)
		copy(b[8:12], T.Prefix.To4())
		b[12] = T.Length
		return *(*string)(unsafe.Pointer(&b))
	case *bgp.LabeledVPNIPv6AddrPrefix:
		b := make([]byte, 25)
		serializedRD, _ := T.RD.Serialize()
		copy(b, serializedRD)
		copy(b[8:24], T.Prefix.To16())
		b[24] = T.Length
		return *(*string)(unsafe.Pointer(&b))
	}
	return nlri.String()
}

func macKey(rt bgp.ExtendedCommunityInterface, mac net.HardwareAddr) string {
	b, _ := rt.Serialize()
	b = append(b, mac...)
	return *(*string)(unsafe.Pointer(&b))
}

func NewTable(logger log.Logger, rf bgp.Family, dsts ...*Destination) *Table {
	t := &Table{
		mu:           sync.RWMutex{},
		family:       rf,
		destinations: make(map[string]*Destination),
		logger:       logger,
		macIndex:     make(map[string]map[string]struct{}),
	}
	for _, dst := range dsts {
		t.setDestination(dst)
	}
	return t
}

func (t *Table) GetFamily() bgp.Family {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.family
}

func (t *Table) deletePathsByVrf(vrf *Vrf) []*Path {
	pathList := []*Path{}
	for _, dest := range t.destinations {
		for _, p := range dest.knownPathList {
			var rd bgp.RouteDistinguisherInterface
			nlri := p.GetNlri()
			switch v := nlri.(type) {
			case *bgp.LabeledVPNIPAddrPrefix:
				rd = v.RD
			case *bgp.LabeledVPNIPv6AddrPrefix:
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
	return pathList
}

func (t *Table) deleteRTCPathsByVrf(vrf *Vrf, vrfs map[string]*Vrf) []*Path {
	pathList := []*Path{}
	if t.family != bgp.RF_RTC_UC {
		return pathList
	}

	for _, target := range vrf.ImportRt {
		lhs := target.String()
		for _, dest := range t.destinations {
			nlri := dest.GetNlri().(*bgp.RouteTargetMembershipNLRI)
			rhs := nlri.RouteTarget.String()
			if lhs != rhs || !isLastTargetUser(vrfs, target) {
				continue
			}
			for _, p := range dest.knownPathList {
				if p.IsLocal() {
					pathList = append(pathList, p.Clone(true))
					break
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

	delete(t.destinations, tableKey(dest.GetNlri()))

	nlri, ok := dest.nlri.(*bgp.EVPNNLRI)
	if !ok {
		return
	}
	macadv, ok := nlri.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute)
	if !ok {
		return
	}

	for _, path := range dest.knownPathList {
		for _, ec := range path.GetRouteTargets() {
			macKey := macKey(ec, macadv.MacAddress)
			if keys, ok := t.macIndex[macKey]; ok {
				delete(keys, tableKey(nlri))
				if len(keys) == 0 {
					delete(t.macIndex, macKey)
				}
			}
		}
	}
}

func (t *Table) DeleteDest(dest *Destination) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.deleteDest(dest)
}

func (t *Table) validatePath(path *Path) {
	if path == nil {
		t.logger.Error("path is nil",
			log.Fields{
				"Topic": "Table",
				"Key":   t.family,
			})
	}
	if path.GetFamily() != t.family {
		t.logger.Error("Invalid path. RouteFamily mismatch",
			log.Fields{
				"Topic":      "Table",
				"Key":        t.family,
				"Prefix":     path.GetPrefix(),
				"ReceivedRf": path.GetFamily().String(),
			})
	}
	if attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH); attr != nil {
		pathParam := attr.(*bgp.PathAttributeAsPath).Value
		for _, as := range pathParam {
			_, y := as.(*bgp.As4PathParam)
			if !y {
				t.logger.Fatal("AsPathParam must be converted to As4PathParam",
					log.Fields{
						"Topic": "Table",
						"Key":   t.family,
						"As":    as,
					})
			}
		}
	}
	if attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_AS4_PATH); attr != nil {
		t.logger.Fatal("AS4_PATH must be converted to AS_PATH",
			log.Fields{
				"Topic": "Table",
				"Key":   t.family,
			})
	}
	if path.GetNlri() == nil {
		t.logger.Fatal("path's nlri is nil",
			log.Fields{
				"Topic": "Table",
				"Key":   t.family,
			})
	}
}

func (t *Table) getOrCreateDest(nlri bgp.AddrPrefixInterface, size int) *Destination {
	dest := t.destinations[tableKey(nlri)]
	if dest != nil {
		return dest
	}

	// If destination for given prefix does not exist we create it.
	t.logger.Debug("create Destination",
		log.Fields{
			"Topic": "Table",
			"Nlri":  nlri,
		})
	dest = NewDestination(nlri, size)
	t.setDestination(dest)
	return dest
}

func (t *Table) GetOrCreateDest(nlri bgp.AddrPrefixInterface, size int) *Destination {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.getOrCreateDest(nlri, size)
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
			tableKey := tableKey(nlri)
			for _, ec := range newPath.GetRouteTargets() {
				macKey := macKey(ec, macadv.MacAddress)
				if _, ok := t.macIndex[macKey]; !ok {
					t.macIndex[macKey] = make(map[string]struct{})
				}
				t.macIndex[macKey][tableKey] = struct{}{}
			}
		}
	}

	return u
}

func (t *Table) Update(newPath *Path) *Update {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.update(newPath)
}

func (t *Table) WalkDestinations(f func(*Destination) bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, dst := range t.destinations {
		if f(dst) {
			return
		}
	}
}

func (t *Table) GetDestinations() map[string]*Destination {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return maps.Clone(t.destinations)
}

func (t *Table) getDestination(nlri bgp.AddrPrefixInterface) *Destination {
	return t.destinations[tableKey(nlri)]
}

func (t *Table) GetDestination(nlri bgp.AddrPrefixInterface) *Destination {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.getDestination(nlri)
}

func (t *Table) GetDestinationsCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.destinations)
}

func (t *Table) getLongerPrefixDestinations(key string) ([]*Destination, error) {
	results := make([]*Destination, 0, len(t.destinations))
	switch t.family {
	case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC, bgp.RF_IPv4_MPLS, bgp.RF_IPv6_MPLS:
		_, prefix, err := net.ParseCIDR(key)
		if err != nil {
			return nil, fmt.Errorf("error parsing cidr %s: %v", key, err)
		}
		ones, bits := prefix.Mask.Size()

		r := critbitgo.NewNet()
		for _, dst := range t.destinations {
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
		prefixRd, _, network, err := bgp.ParseVPNPrefix(key)
		if err != nil {
			return nil, err
		}
		ones, bits := network.Mask.Size()

		r := critbitgo.NewNet()
		for _, dst := range t.destinations {
			var dstRD bgp.RouteDistinguisherInterface
			switch t.family {
			case bgp.RF_IPv4_VPN:
				dstRD = dst.nlri.(*bgp.LabeledVPNIPAddrPrefix).RD
			case bgp.RF_IPv6_VPN:
				dstRD = dst.nlri.(*bgp.LabeledVPNIPv6AddrPrefix).RD
			}

			if prefixRd.String() != dstRD.String() {
				continue
			}

			_ = r.Add(nlriToIPNet(dst.nlri), dst)
		}

		p := &net.IPNet{
			IP:   network.IP,
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
		for _, dst := range t.destinations {
			results = append(results, dst)
		}
	}
	return results, nil
}

func (t *Table) GetLongerPrefixDestinations(key string) ([]*Destination, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.getLongerPrefixDestinations(key)
}

func (t *Table) getEvpnDestinationsWithRouteType(typ string) ([]*Destination, error) {
	routeType := uint8(0)
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

	results := make([]*Destination, 0, len(t.destinations))
	switch t.family {
	case bgp.RF_EVPN:
		for _, dst := range t.destinations {
			if nlri, ok := dst.nlri.(*bgp.EVPNNLRI); !ok {
				return nil, fmt.Errorf("invalid evpn nlri type detected: %T", dst.nlri)
			} else if nlri.RouteType == routeType {
				results = append(results, dst)
			}
		}
	default:
		for _, dst := range t.destinations {
			results = append(results, dst)
		}
	}
	return results, nil
}

func (t *Table) GetEvpnDestinationsWithRouteType(typ string) ([]*Destination, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.getEvpnDestinationsWithRouteType(typ)
}

func (t *Table) getMUPDestinationsWithRouteType(p string) ([]*Destination, error) {
	routeType := uint16(0)
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

	results := make([]*Destination, 0, len(t.destinations))
	switch t.family {
	case bgp.RF_MUP_IPv4, bgp.RF_MUP_IPv6:
		for _, dst := range t.destinations {
			if nlri, ok := dst.nlri.(*bgp.MUPNLRI); !ok {
				return nil, fmt.Errorf("invalid mup nlri type detected: %T", dst.nlri)
			} else if nlri.RouteType == routeType {
				results = append(results, dst)
			} else if nlri.String() == p {
				results = append(results, dst)
			}
		}
	default:
		for _, dst := range t.destinations {
			results = append(results, dst)
		}
	}
	return results, nil
}

func (t *Table) GetMUPDestinationsWithRouteType(p string) ([]*Destination, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.getMUPDestinationsWithRouteType(p)
}

func (t *Table) setDestination(dst *Destination) {
	tableKey := tableKey(dst.nlri)
	t.destinations[tableKey] = dst

	nlri, ok := dst.nlri.(*bgp.EVPNNLRI)
	if !ok {
		return
	}
	macadv, ok := nlri.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute)
	if !ok {
		return
	}
	for _, path := range dst.knownPathList {
		for _, ec := range path.GetRouteTargets() {
			macKey := macKey(ec, macadv.MacAddress)
			if _, ok := t.macIndex[macKey]; !ok {
				t.macIndex[macKey] = make(map[string]struct{})
			}
			t.macIndex[macKey][tableKey] = struct{}{}
		}
	}
}

func (t *Table) Bests(id string, as uint32) []*Path {
	t.mu.RLock()
	defer t.mu.RUnlock()

	paths := make([]*Path, 0, len(t.destinations))
	for _, dst := range t.destinations {
		path := dst.GetBestPath(id, as)
		if path != nil {
			paths = append(paths, path)
		}
	}
	return paths
}

func (t *Table) MultiBests(id string) [][]*Path {
	t.mu.RLock()
	defer t.mu.RUnlock()

	paths := make([][]*Path, 0, len(t.destinations))
	for _, dst := range t.destinations {
		path := dst.GetMultiBestPath(id)
		if path != nil {
			paths = append(paths, path)
		}
	}
	return paths
}

func (t *Table) GetKnownPathList(id string, as uint32) []*Path {
	t.mu.RLock()
	defer t.mu.RUnlock()

	paths := make([]*Path, 0, len(t.destinations))
	for _, dst := range t.destinations {
		paths = append(paths, dst.GetKnownPathList(id, as)...)
	}
	return paths
}

func (t *Table) GetKnownPathListWithMac(id string, as uint32, rt bgp.ExtendedCommunityInterface, mac net.HardwareAddr, onlyBest bool) []*Path {
	t.mu.RLock()
	defer t.mu.RUnlock()

	paths := []*Path{}
	if prefixes, ok := t.macIndex[macKey(rt, mac)]; ok {
		for prefix := range prefixes {
			if dst, ok := t.destinations[prefix]; ok {
				if onlyBest {
					paths = append(paths, dst.GetBestPath(id, as))
				} else {
					paths = append(paths, dst.GetKnownPathList(id, as)...)
				}
			}
		}
	}
	return paths
}

func (t *Table) Select(option ...TableSelectOption) (*Table, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	dOption := DestinationSelectOption{
		ID: GLOBAL_RIB_NAME,
	}
	prefixes := make([]*LookupPrefix, 0, len(option))
	for _, o := range option {
		if o.ID != "" {
			dOption.ID = o.ID
		}
		if o.VRF != nil {
			dOption.VRF = o.VRF
		}
		dOption.adj = o.adj
		dOption.Best = o.Best
		dOption.MultiPath = o.MultiPath
		dOption.AS = o.AS
		prefixes = append(prefixes, o.LookupPrefixes...)
	}

	r := NewTable(nil, t.family)
	// no need to lock r since it is a new table
	// only accessible here

	if len(prefixes) == 0 {
		for _, dst := range t.destinations {
			if d := dst.Select(dOption); d != nil {
				r.setDestination(d)
			}
		}
		return r, nil
	}

	switch t.family {
	case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
		f := func(prefixStr string) (bool, error) {
			var nlri bgp.AddrPrefixInterface
			var err error
			if t.family == bgp.RF_IPv4_UC {
				nlri, err = bgp.NewPrefixFromFamily(bgp.AFI_IP, bgp.SAFI_UNICAST, prefixStr)
			} else {
				nlri, err = bgp.NewPrefixFromFamily(bgp.AFI_IP6, bgp.SAFI_UNICAST, prefixStr)
			}
			if err != nil {
				return false, err
			}
			if dst := t.getDestination(nlri); dst != nil {
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
			case LOOKUP_LONGER:
				ds, err := t.getLongerPrefixDestinations(key)
				if err != nil {
					return nil, err
				}
				for _, dst := range ds {
					if d := dst.Select(dOption); d != nil {
						r.setDestination(d)
					}
				}
			case LOOKUP_SHORTER:
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
					if t.family == bgp.RF_IPv6_UC {
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
			var nlri bgp.AddrPrefixInterface
			var err error

			if t.family == bgp.RF_IPv4_VPN {
				nlri, err = bgp.NewPrefixFromFamily(bgp.AFI_IP, bgp.SAFI_MPLS_VPN, prefixStr)
			} else {
				nlri, err = bgp.NewPrefixFromFamily(bgp.AFI_IP6, bgp.SAFI_MPLS_VPN, prefixStr)
			}
			if err != nil {
				return fmt.Errorf("failed to create prefix: %w", err)
			}

			if dst := t.getDestination(nlri); dst != nil {
				if d := dst.Select(dOption); d != nil {
					r.setDestination(d)
				}
			}
			return nil
		}

		for _, p := range prefixes {
			switch p.LookupOption {
			case LOOKUP_LONGER:
				_, prefix, err := net.ParseCIDR(p.Prefix)
				if err != nil {
					return nil, err
				}

				if p.RD == "" {
					for _, dst := range t.destinations {
						tablePrefix := nlriToIPNet(dst.nlri)

						if bgp.ContainsCIDR(prefix, tablePrefix) {
							r.setDestination(dst)
						}
					}

					return r, nil
				}

				ds, err := t.getLongerPrefixDestinations(p.RD + ":" + p.Prefix)
				if err != nil {
					return nil, err
				}

				for _, dst := range ds {
					if d := dst.Select(dOption); d != nil {
						r.setDestination(d)
					}
				}
			case LOOKUP_SHORTER:
				addr, prefix, err := net.ParseCIDR(p.Prefix)
				if err != nil {
					return nil, err
				}

				if p.RD == "" {
					for _, dst := range t.destinations {
						tablePrefix := nlriToIPNet(dst.nlri)

						if bgp.ContainsCIDR(tablePrefix, prefix) {
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
					for _, dst := range t.destinations {
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
			ds, err := t.getEvpnDestinationsWithRouteType(p.Prefix)
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
			ds, err := t.getMUPDestinationsWithRouteType(p.Prefix)
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
	return r, nil
}

type TableInfo struct {
	NumDestination int
	NumPath        int
	NumAccepted    int
}

type TableInfoOptions struct {
	ID  string
	AS  uint32
	VRF *Vrf
}

func (t *Table) Info(option ...TableInfoOptions) *TableInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()

	tOptions := TableSelectOption{
		ID: GLOBAL_RIB_NAME,
	}
	for _, o := range option {
		if o.ID != "" {
			tOptions.ID = o.ID
		}
		if o.VRF != nil {
			tOptions.VRF = o.VRF
		}
		tOptions.AS = o.AS
	}

	tInfo := &TableInfo{}
	for _, d := range t.destinations {
		paths := d.GetKnownPathList(tOptions.ID, tOptions.AS)
		n := len(paths)

		if vrf := tOptions.VRF; vrf != nil {
			ps := make([]*Path, 0, len(paths))
			for _, p := range paths {
				if CanImportToVrf(vrf, p) {
					ps = append(ps, p.ToLocal())
				}
			}
			n = len(ps)
		}
		if n != 0 {
			tInfo.NumDestination++
			tInfo.NumPath += n
		}
	}
	return tInfo
}
