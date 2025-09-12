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
	crand "crypto/rand"
	"encoding/binary"
	"math/rand"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
)

func TestLookupLonger(t *testing.T) {
	tbl := NewTable(logger, bgp.RF_IPv4_UC)

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("11.0.0.0/23"))
	tbl.setDestination(NewDestination(nlri, 0))
	nlri, _ = bgp.NewIPAddrPrefix(netip.MustParsePrefix("11.0.0.0/24"))
	tbl.setDestination(NewDestination(nlri, 0))
	nlri, _ = bgp.NewIPAddrPrefix(netip.MustParsePrefix("11.0.0.4/32"))
	tbl.setDestination(NewDestination(nlri, 0))
	nlri, _ = bgp.NewIPAddrPrefix(netip.MustParsePrefix("11.0.0.129/32"))
	tbl.setDestination(NewDestination(nlri, 0))
	nlri, _ = bgp.NewIPAddrPrefix(netip.MustParsePrefix("11.0.0.144/28"))
	tbl.setDestination(NewDestination(nlri, 0))
	nlri, _ = bgp.NewIPAddrPrefix(netip.MustParsePrefix("11.0.0.144/29"))
	tbl.setDestination(NewDestination(nlri, 0))
	nlri, _ = bgp.NewIPAddrPrefix(netip.MustParsePrefix("11.0.0.145/32"))
	tbl.setDestination(NewDestination(nlri, 0))

	r, _ := tbl.GetLongerPrefixDestinations("11.0.0.128/25")
	assert.Equal(t, len(r), 4)
	r, _ = tbl.GetLongerPrefixDestinations("11.0.0.0/24")
	assert.Equal(t, len(r), 6)
}

func TestTableDeleteDest(t *testing.T) {
	peerT := TableCreatePeer()
	pathT := TableCreatePath(peerT)
	ipv4t := NewTable(logger, bgp.RF_IPv4_UC)
	for _, path := range pathT {
		dest := NewDestination(path.GetNlri(), 0)
		ipv4t.setDestination(dest)
	}
	dest := NewDestination(pathT[0].GetNlri(), 0)
	ipv4t.setDestination(dest)
	ipv4t.deleteDest(dest)
	gdest := ipv4t.GetDestination(pathT[0].GetNlri())
	assert.Nil(t, gdest)
}

func TestTableGetFamily(t *testing.T) {
	ipv4t := NewTable(logger, bgp.RF_IPv4_UC)
	rf := ipv4t.GetFamily()
	assert.Equal(t, rf, bgp.RF_IPv4_UC)
}

func TestTableDestinationsCollision(t *testing.T) {
	peerT := TableCreatePeer()
	pathT := TableCreatePath(peerT)
	ipv4t := NewTable(logger, bgp.RF_IPv4_UC)

	k := tableKey(pathT[0].GetNlri())
	// fake an entry
	ipv4t.destinations[k] = []*Destination{{nlri: pathT[1].GetNlri()}}
	for _, path := range pathT {
		dest := NewDestination(path.GetNlri(), 0)
		ipv4t.setDestination(dest)
	}
	assert.Equal(t, 1, ipv4t.Info().NumCollision)
}

func TestTableSetDestinations(t *testing.T) {
	peerT := TableCreatePeer()
	pathT := TableCreatePath(peerT)
	ipv4t := NewTable(logger, bgp.RF_IPv4_UC)
	destinations := make([]*Destination, 0)
	for _, path := range pathT {
		dest := NewDestination(path.GetNlri(), 0)
		destinations = append(destinations, dest)
		ipv4t.setDestination(dest)
	}
	// make them comparable
	slices.SortFunc(destinations, func(a, b *Destination) int {
		return AddrPrefixOnlyCompare(a.GetNlri(), b.GetNlri())
	})
	ds := ipv4t.GetDestinations()
	slices.SortFunc(ds, func(a, b *Destination) int {
		return AddrPrefixOnlyCompare(a.GetNlri(), b.GetNlri())
	})
	assert.Equal(t, ds, destinations)
}

func TestTableGetDestinations(t *testing.T) {
	peerT := DestCreatePeer()
	pathT := DestCreatePath(peerT)
	ipv4t := NewTable(logger, bgp.RF_IPv4_UC)
	destinations := make([]*Destination, 0)
	for _, path := range pathT {
		dest := NewDestination(path.GetNlri(), 0)
		destinations = append(destinations, dest)
		ipv4t.setDestination(dest)
	}
	// make them comparable
	slices.SortFunc(destinations, func(a, b *Destination) int {
		return AddrPrefixOnlyCompare(a.GetNlri(), b.GetNlri())
	})
	ds := ipv4t.GetDestinations()
	slices.SortFunc(ds, func(a, b *Destination) int {
		return AddrPrefixOnlyCompare(a.GetNlri(), b.GetNlri())
	})
	assert.Equal(t, ds, destinations)
}

func TestTableKey(t *testing.T) {
	tb := NewTable(logger, bgp.RF_IPv4_UC)
	n1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("0.0.0.0/0"))
	d1 := NewDestination(n1, 0)
	n2, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("0.0.0.0/1"))
	d2 := NewDestination(n2, 0)

	assert.NotEqual(t, tableKey(d1.GetNlri()), tableKey(d2.GetNlri()))
	tb.setDestination(d1)
	tb.setDestination(d2)
	assert.Equal(t, len(tb.GetDestinations()), 2)
}

func BenchmarkTableKey(b *testing.B) {
	rd := bgp.NewRouteDistinguisherTwoOctetAS(1, 2)
	esi, _ := bgp.ParseEthernetSegmentIdentifier([]string{"lacp", "aa:bb:cc:dd:ee:ff", "100"})
	nlri1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("192.168.1.0/24"))
	nlri2, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:db8::/64"))
	nlri3, _ := bgp.NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix("192.168.1.0/24"), *bgp.NewMPLSLabelStack(100, 200, 300), rd)
	nlri4, _ := bgp.NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix("2001:db8::/64"), *bgp.NewMPLSLabelStack(100, 200, 300), rd)
	prefix := []bgp.NLRI{
		nlri1,
		nlri2,
		nlri3,
		nlri4,
	}

	b.Run("TableKey known types", func(b *testing.B) {
		b.ResetTimer()
		for range b.N {
			for _, p := range prefix {
				_ = tableKey(p)
			}
		}
	})

	prefix = append(prefix, bgp.NewEVPNEthernetAutoDiscoveryRoute(rd, esi, 1, 2))
	b.Run("TableKey with unknown type", func(b *testing.B) {
		b.ResetTimer()
		for range b.N {
			for _, p := range prefix {
				_ = tableKey(p)
			}
		}
	})
}

func TestTableSelectMalformedIPv4UCPrefixes(t *testing.T) {
	table := NewTable(logger, bgp.RF_IPv4_UC)
	assert.Equal(t, 0, len(table.GetDestinations()))

	tests := []struct {
		name   string
		prefix string
		option apiutil.LookupOption
		found  int
	}{
		{
			name:   "Malformed IPv4 Address",
			prefix: "2.2.2.2.2",
			option: apiutil.LOOKUP_EXACT,
			found:  0,
		},
		{
			name:   "exact match with RD and prefix that does not exist",
			prefix: "foo",
			option: apiutil.LOOKUP_EXACT,
			found:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := table.Select(
				TableSelectOption{
					LookupPrefixes: []*apiutil.LookupPrefix{{
						Prefix:       tt.prefix,
						LookupOption: tt.option,
					}},
				},
			)
			assert.Error(t, err)
		})
	}
}

func TestTableSelectMalformedIPv6UCPrefixes(t *testing.T) {
	table := NewTable(logger, bgp.RF_IPv6_UC)
	assert.Equal(t, 0, len(table.GetDestinations()))

	tests := []struct {
		name   string
		prefix string
		option apiutil.LookupOption
		found  int
	}{
		{
			name:   "Malformed IPv6 Address: 3343:faba:3903:128::::/63",
			prefix: "3343:faba:3903:128::::/63",
			option: apiutil.LOOKUP_EXACT,
			found:  0,
		},
		{
			name:   "Malformed IPv6 Address: foo",
			prefix: "foo",
			option: apiutil.LOOKUP_EXACT,
			found:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := table.Select(
				TableSelectOption{
					LookupPrefixes: []*apiutil.LookupPrefix{{
						Prefix:       tt.prefix,
						LookupOption: tt.option,
					}},
				},
			)
			assert.Error(t, err)
		})
	}
}

func TestTableSelectVPNv4(t *testing.T) {
	prefixes := []string{
		"100:100:2.2.2.0/25",
		"100:100:2.2.2.2/32",
		"200:100:2.2.2.2/32",
		"300:100:2.2.2.2/32",
		"100:100:2.2.2.3/32",
		"100:100:2.2.2.4/32",
		"1.1.1.1:1:2.2.2.5/32",
		"8732:1:2.2.2.5/32",
		"8732:1:3.3.3.3/32",
	}

	table := NewTable(logger, bgp.RF_IPv4_VPN)
	for _, prefix := range prefixes {
		rd, p, _ := bgp.ParseVPNPrefix(prefix)
		nlri, _ := bgp.NewLabeledVPNIPAddrPrefix(p, *bgp.NewMPLSLabelStack(), rd)

		destination := NewDestination(nlri, 0, NewPath(bgp.RF_IPv4_VPN, nil, bgp.PathNLRI{NLRI: nlri}, false, nil, time.Now(), false))
		table.setDestination(destination)
	}
	assert.Equal(t, 9, len(table.GetDestinations()))

	tests := []struct {
		name   string
		prefix string
		RD     string
		option apiutil.LookupOption
		found  int
	}{
		{
			name:   "exact match with RD that does not exist",
			prefix: "2.2.2.2/32",
			RD:     "500:500",
			option: apiutil.LOOKUP_EXACT,
			found:  0,
		},
		{
			name:   "exact match with RD and prefix that does not exist",
			prefix: "4.4.4.4/32",
			RD:     "100:100",
			option: apiutil.LOOKUP_EXACT,
			found:  0,
		},
		{
			name:   "exact match with RD",
			prefix: "2.2.2.0/25",
			RD:     "100:100",
			option: apiutil.LOOKUP_EXACT,
			found:  1,
		},
		{
			name:   "longer match with RD",
			prefix: "2.2.2.0/25",
			RD:     "100:100",
			option: apiutil.LOOKUP_LONGER,
			found:  4,
		},
		{
			name:   "shorter match with RD",
			prefix: "2.2.2.2/32",
			RD:     "100:100",
			option: apiutil.LOOKUP_SHORTER,
			found:  2,
		},
		{
			name:   "exact match without RD for prefix that does not exist",
			prefix: "4.4.4.4/32",
			option: apiutil.LOOKUP_EXACT,
			found:  0,
		},
		{
			name:   "exact match without RD",
			prefix: "2.2.2.2/32",
			option: apiutil.LOOKUP_EXACT,
			found:  3,
		},
		{
			name:   "longer match without RD",
			prefix: "2.2.2.0/24",
			option: apiutil.LOOKUP_LONGER,
			found:  8,
		},
		{
			name:   "shorter match without RD",
			prefix: "2.2.2.2/32",
			option: apiutil.LOOKUP_SHORTER,
			found:  4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filteredTable, err := table.Select(
				TableSelectOption{
					LookupPrefixes: []*apiutil.LookupPrefix{{
						Prefix:       tt.prefix,
						RD:           tt.RD,
						LookupOption: tt.option,
					}},
				},
			)
			assert.NoError(t, err)
			assert.Equal(t, tt.found, len(filteredTable.GetDestinations()))
		})
	}
}

func TestTableSelectVPNv6(t *testing.T) {
	prefixes := []string{
		"100:100:100::/32",
		"100:100:100::/64",
		"100:100:100:1::/64",
		"100:100:100:2::/64",
		"200:100:100:2::/64",
		"300:100:100:2::/64",
		"100:100:100:3:1::/48",
		"100:100:100:3:1:2::/64",
		"100:100:100:2:3:4:5:6::/96",
	}

	table := NewTable(logger, bgp.RF_IPv6_VPN)
	for _, prefix := range prefixes {
		rd, p, _ := bgp.ParseVPNPrefix(prefix)
		nlri, _ := bgp.NewLabeledVPNIPAddrPrefix(p, *bgp.NewMPLSLabelStack(), rd)
		destination := NewDestination(nlri, 0, NewPath(bgp.RF_IPv6_VPN, nil, bgp.PathNLRI{NLRI: nlri}, false, nil, time.Now(), false))
		table.setDestination(destination)
	}
	assert.Equal(t, 9, len(table.GetDestinations()))

	tests := []struct {
		name   string
		prefix string
		RD     string
		option apiutil.LookupOption
		found  int
	}{
		{
			name:   "exact match with RD that does not exist",
			prefix: "100::/32",
			RD:     "500:500",
			option: apiutil.LOOKUP_EXACT,
			found:  0,
		},
		{
			name:   "exact match with RD and prefix that does not exist",
			prefix: "200::/32",
			RD:     "100:100",
			option: apiutil.LOOKUP_EXACT,
			found:  0,
		},
		{
			name:   "exact match with RD",
			prefix: "100:2::/64",
			RD:     "100:100",
			option: apiutil.LOOKUP_EXACT,
			found:  1,
		},
		{
			name:   "longer match with RD",
			prefix: "100::/16",
			RD:     "100:100",
			option: apiutil.LOOKUP_LONGER,
			found:  7,
		},
		{
			name:   "shorter match with RD",
			prefix: "100::/96",
			RD:     "100:100",
			option: apiutil.LOOKUP_SHORTER,
			found:  2,
		},
		{
			name:   "exact match without RD for prefix that does not exist",
			prefix: "100:5::/64",
			option: apiutil.LOOKUP_EXACT,
			found:  0,
		},
		{
			name:   "exact match without RD",
			prefix: "100:2::/64",
			option: apiutil.LOOKUP_EXACT,
			found:  3,
		},
		{
			name:   "longer match without RD",
			prefix: "100:3::/32",
			option: apiutil.LOOKUP_LONGER,
			found:  2,
		},
		{
			name:   "shorter match without RD",
			prefix: "100:2::/96",
			option: apiutil.LOOKUP_SHORTER,
			found:  3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filteredTable, err := table.Select(
				TableSelectOption{
					LookupPrefixes: []*apiutil.LookupPrefix{{
						Prefix:       tt.prefix,
						RD:           tt.RD,
						LookupOption: tt.option,
					}},
				},
			)
			assert.NoError(t, err)
			assert.Equal(t, tt.found, len(filteredTable.GetDestinations()))
		})
	}
}

func TableCreatePeer() []*PeerInfo {
	peerT1 := &PeerInfo{AS: 65000}
	peerT2 := &PeerInfo{AS: 65001}
	peerT3 := &PeerInfo{AS: 65002}
	peerT := []*PeerInfo{peerT1, peerT2, peerT3}
	return peerT
}

func TableCreatePath(peerT []*PeerInfo) []*Path {
	bgpMsgT1 := updateMsgT1()
	bgpMsgT2 := updateMsgT2()
	bgpMsgT3 := updateMsgT3()
	pathT := make([]*Path, 3)
	for i, msg := range []*bgp.BGPMessage{bgpMsgT1, bgpMsgT2, bgpMsgT3} {
		updateMsgT := msg.Body.(*bgp.BGPUpdate)
		nlriList := updateMsgT.NLRI
		pathAttributes := updateMsgT.PathAttributes
		nlri_info := nlriList[0]
		pathT[i] = NewPath(bgp.RF_IPv4_UC, peerT[i], bgp.PathNLRI{NLRI: nlri_info.NLRI}, false, pathAttributes, time.Now(), false)
	}
	return pathT
}

func updateMsgT1() *bgp.BGPMessage {
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65000})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.50.1"))
	med := bgp.NewPathAttributeMultiExitDisc(0)

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med,
	}

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	return bgp.NewBGPUpdateMessage(nil, pathAttributes, []bgp.PathNLRI{{NLRI: nlri}})
}

func updateMsgT2() *bgp.BGPMessage {
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65100})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.100.1"))
	med := bgp.NewPathAttributeMultiExitDisc(100)

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med,
	}

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("20.20.20.0/24"))
	return bgp.NewBGPUpdateMessage(nil, pathAttributes, []bgp.PathNLRI{{NLRI: nlri}})
}

func updateMsgT3() *bgp.BGPMessage {
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65100})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.150.1"))
	med := bgp.NewPathAttributeMultiExitDisc(100)

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med,
	}

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("30.30.30.0/24"))
	w1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("40.40.40.0/23"))
	withdrawnRoutes := []bgp.PathNLRI{{NLRI: w1}}
	return bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, []bgp.PathNLRI{{NLRI: nlri}})
}

//nolint:errcheck
func createRandomAddrPrefix() []bgp.NLRI {
	label := *bgp.NewMPLSLabelStack(1, 2, 3)
	rd := bgp.NewRouteDistinguisherTwoOctetAS(256, 10000)

	b := make([]byte, 4)
	crand.Read(b)
	addrv4, _ := netip.AddrFromSlice(b)
	lengthv4 := uint8(rand.Intn(32)) + 1
	prefixv4 := netip.PrefixFrom(addrv4, int(lengthv4))

	b = make([]byte, 16)
	crand.Read(b)
	addrv6, _ := netip.AddrFromSlice(b)
	prefixv6 := netip.PrefixFrom(addrv6, rand.Intn(128)+1)

	nlri1, _ := bgp.NewIPAddrPrefix(prefixv4)
	nlri2, _ := bgp.NewLabeledVPNIPAddrPrefix(prefixv4, label, rd)
	nlri3, _ := bgp.NewLabeledIPAddrPrefix(prefixv4, label)
	nlri4, _ := bgp.NewIPAddrPrefix(prefixv6)
	nlri5, _ := bgp.NewLabeledVPNIPAddrPrefix(prefixv6, label, rd)
	nlri6, _ := bgp.NewLabeledIPAddrPrefix(prefixv6, label)
	prefixes := []bgp.NLRI{nlri1, nlri2, nlri3, nlri4, nlri5, nlri6}

	return prefixes
}

//nolint:errcheck
func createAddrPrefixBaseIndex(index int) []bgp.NLRI {
	label := *bgp.NewMPLSLabelStack(1, 2, 3)
	rd := bgp.NewRouteDistinguisherTwoOctetAS(256, 10000)

	b := []byte{192, 168, 1, 0}
	v := binary.BigEndian.Uint32(b)
	v += uint32(index) << 8
	binary.BigEndian.PutUint32(b, v)
	addrv4, _ := netip.AddrFromSlice(b)
	prefixv4 := netip.PrefixFrom(addrv4, 28)

	b = make([]byte, 16)
	crand.Read(b)
	v = binary.BigEndian.Uint32(b)
	v += uint32(index) << 8
	binary.BigEndian.PutUint32(b, v)
	addrv6, _ := netip.AddrFromSlice(b)
	prefixv6 := netip.PrefixFrom(addrv6, 96)

	nlri1, _ := bgp.NewIPAddrPrefix(prefixv4)
	nlri2, _ := bgp.NewLabeledVPNIPAddrPrefix(prefixv4, label, rd)
	nlri3, _ := bgp.NewLabeledIPAddrPrefix(prefixv4, label)
	nlri4, _ := bgp.NewIPAddrPrefix(prefixv6)
	nlri5, _ := bgp.NewLabeledVPNIPAddrPrefix(prefixv6, label, rd)
	nlri6, _ := bgp.NewLabeledIPAddrPrefix(prefixv6, label)
	prefixes := []bgp.NLRI{nlri1, nlri2, nlri3, nlri4, nlri5, nlri6}

	return prefixes
}

func TestTableDestinationsCollisionAttack(t *testing.T) {
	t.Skip()
	if !strings.Contains(runtime.GOARCH, "64") {
		t.Skip("This test is only for 64bit architecture")
	}

	ipv4t := NewTable(logger, bgp.RF_IPv4_UC)

	i := 0
	for {
		// filled until 1GB
		mem := SystemMemoryAvailableMiB()
		if mem < 1024 {
			break
		}

		for _, p := range createAddrPrefixBaseIndex(i) {
			dest := NewDestination(p, 0)
			ipv4t.setDestination(dest)
		}

		for _, p := range createRandomAddrPrefix() {
			dest := NewDestination(p, 0)
			ipv4t.setDestination(dest)
		}

		i++
	}

	assert.Equal(t, 0, ipv4t.Info().NumCollision)

	dests := ipv4t.GetDestinations()
	rand.Shuffle(len(dests), func(i, j int) {
		dests[i], dests[j] = dests[j], dests[i]
	})
	for i := range min(len(dests), 10) {
		t.Log(dests[i].GetNlri().String())
	}
}

func buildPrefixesWithLabels() []bgp.NLRI {
	label1 := *bgp.NewMPLSLabelStack(1, 2, 3)
	label2 := *bgp.NewMPLSLabelStack(4, 5, 6)
	label3 := *bgp.NewMPLSLabelStack(7, 8)
	rd1 := bgp.NewRouteDistinguisherTwoOctetAS(256, 10000)
	rd2 := bgp.NewRouteDistinguisherTwoOctetAS(128, 12300)

	index := 125
	b := []byte{192, 168, 1, 0}
	v := binary.BigEndian.Uint32(b)
	v += uint32(index) << 8
	binary.BigEndian.PutUint32(b, v)
	addrv4, _ := netip.AddrFromSlice(b)
	prefixv4 := netip.PrefixFrom(addrv4, 28)

	b = make([]byte, 16)
	_, _ = crand.Read(b)
	v = binary.BigEndian.Uint32(b)
	v += uint32(index) << 8
	binary.BigEndian.PutUint32(b, v)
	addrv6, _ := netip.AddrFromSlice(b)
	prefixv6 := netip.PrefixFrom(addrv6, 96)

	nlri1, _ := bgp.NewIPAddrPrefix(prefixv4)
	nlri2, _ := bgp.NewIPAddrPrefix(prefixv6)
	prefixes := []bgp.NLRI{nlri1, nlri2}

	for _, l := range []bgp.MPLSLabelStack{label1, label2, label3} {
		for _, rd := range []bgp.RouteDistinguisherInterface{rd1, rd2} {
			vpn, _ := bgp.NewLabeledVPNIPAddrPrefix(prefixv4, l, rd)
			prefixes = append(prefixes, vpn)
			mpls, _ := bgp.NewLabeledIPAddrPrefix(prefixv4, l)
			prefixes = append(prefixes, mpls)
			vpn, _ = bgp.NewLabeledVPNIPAddrPrefix(prefixv6, l, rd)
			prefixes = append(prefixes, vpn)
			mpls, _ = bgp.NewLabeledIPAddrPrefix(prefixv6, l)
			prefixes = append(prefixes, mpls)
		}
	}
	return prefixes
}

func TestTableKeyWithLabels(t *testing.T) {
	ipv4t := NewTable(logger, bgp.RF_IPv4_UC)
	for _, p := range buildPrefixesWithLabels() {
		dest := NewDestination(p, 0)
		ipv4t.setDestination(dest)
	}

	assert.Equal(t, 0, ipv4t.Info().NumCollision)
	// 8 here as labels are not counted in the destination key
	// 1 IPv4 prefix
	// 1 IPv6 prefix
	// 1 LabeledVPNIPv4 prefix with 3 labels, 2 RDs  (sum = 2)
	// 1 LabeledIPv4 prefix with 3 labels            (sum = 1) the 2nd replace the 1st one (update)
	// 1 LabeledVPNIPv6 prefix with 3 labels,2 RDs   (sum = 2)
	// 1 LabeledIPv6 prefix with 3 labels            (sum = 1) the 2nd replace the 1st one (update)
	assert.Equal(t, 8, len(ipv4t.GetDestinations()))
}

func BenchmarkTableKeyWithLabels(b *testing.B) {
	prefixes := buildPrefixesWithLabels()
	for range b.N {
		for _, p := range prefixes {
			tableKey(p)
		}
	}
}

func Test_RouteTargetKey(t *testing.T) {
	assert := assert.New(t)

	// TwoOctetAsSpecificExtended
	buf := make([]byte, 13)
	buf[0] = 96 // in bit length
	binary.BigEndian.PutUint32(buf[1:5], 65546)
	buf[5] = byte(bgp.EC_TYPE_TRANSITIVE_TWO_OCTET_AS_SPECIFIC) // typehigh
	buf[6] = byte(bgp.EC_SUBTYPE_ROUTE_TARGET)                  // subtype
	binary.BigEndian.PutUint16(buf[7:9], 0x1314)
	binary.BigEndian.PutUint32(buf[9:], 0x15161718)
	r, err := bgp.NLRIFromSlice(bgp.RF_RTC_UC, buf)
	assert.NoError(err)
	key, err := extCommRouteTargetKey(r.(*bgp.RouteTargetMembershipNLRI).RouteTarget)
	assert.NoError(err)
	assert.Equal(uint64(0x0002131415161718), key)

	// IPv4AddressSpecificExtended
	buf = make([]byte, 13)
	buf[0] = 96 // in bit length
	binary.BigEndian.PutUint32(buf[1:5], 65546)
	buf[5] = byte(bgp.EC_TYPE_TRANSITIVE_IP4_SPECIFIC) // typehigh
	buf[6] = byte(bgp.EC_SUBTYPE_ROUTE_TARGET)         // subtype
	ip := net.ParseIP("10.1.2.3").To4()
	copy(buf[7:11], []byte(ip))
	binary.BigEndian.PutUint16(buf[11:], 0x1314)
	r, err = bgp.NLRIFromSlice(bgp.RF_RTC_UC, buf)
	assert.NoError(err)
	key, err = extCommRouteTargetKey(r.(*bgp.RouteTargetMembershipNLRI).RouteTarget)
	assert.NoError(err)
	assert.Equal(uint64(0x01020a0102031314), key)

	// FourOctetAsSpecificExtended
	buf = make([]byte, 13)
	buf[0] = 96 // in bit length
	binary.BigEndian.PutUint32(buf[1:5], 65546)
	buf[5] = byte(bgp.EC_TYPE_TRANSITIVE_FOUR_OCTET_AS_SPECIFIC) // typehigh
	buf[6] = byte(bgp.EC_SUBTYPE_ROUTE_TARGET)                   // subtype
	binary.BigEndian.PutUint32(buf[7:], 0x15161718)
	binary.BigEndian.PutUint16(buf[11:], 0x1314)
	r, err = bgp.NLRIFromSlice(bgp.RF_RTC_UC, buf)
	assert.NoError(err)
	key, err = extCommRouteTargetKey(r.(*bgp.RouteTargetMembershipNLRI).RouteTarget)
	assert.NoError(err)
	assert.Equal(uint64(0x0202151617181314), key)

	// OpaqueExtended, wrong RouteTarget
	buf = make([]byte, 13)
	buf[0] = 96 // in bit length
	binary.BigEndian.PutUint32(buf[1:5], 65546)
	buf[5] = byte(bgp.EC_TYPE_TRANSITIVE_OPAQUE) // typehigh
	binary.BigEndian.PutUint32(buf[9:], 1000000)
	r, err = bgp.NLRIFromSlice(bgp.RF_RTC_UC, buf)
	assert.NoError(err)
	_, err = extCommRouteTargetKey(r.(*bgp.RouteTargetMembershipNLRI).RouteTarget)
	assert.NotNil(err)
}

func TestContainsCIDR(t *testing.T) {
	tests := []struct {
		name    string
		prefix1 string
		prefix2 string
		result  bool
	}{
		{
			name:    "v4 prefix2 is a subnet of prefix1",
			prefix1: "172.17.0.0/16",
			prefix2: "172.17.192.0/18",
			result:  true,
		},
		{
			name:    "v4 prefix2 is a supernet of prefix1",
			prefix1: "172.17.191.0/18",
			prefix2: "172.17.0.0/16",
			result:  false,
		},
		{
			name:    "v4 prefix2 is not a subnet of prefix1",
			prefix1: "10.10.20.0/30",
			prefix2: "10.10.30.3/32",
			result:  false,
		},
		{
			name:    "v4 prefix2 is equal to prefix1",
			prefix1: "10.10.20.0/30",
			prefix2: "10.10.20.0/30",
			result:  true,
		},
		{
			name:    "v6 prefix2 is not a subnet of prefix1",
			prefix1: "1::/64",
			prefix2: "2::/72",
			result:  false,
		},
		{
			name:    "v6 prefix2 is a supernet of prefix1",
			prefix1: "1::/64",
			prefix2: "1::/32",
			result:  false,
		},
		{
			name:    "v6 prefix2 is a subnet of prefix1",
			prefix1: "1::/64",
			prefix2: "1::/112",
			result:  true,
		},
		{
			name:    "v6 prefix2 is equal to prefix1",
			prefix1: "100:100::/64",
			prefix2: "100:100::/64",
			result:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, prefixNet1, _ := net.ParseCIDR(tt.prefix1)
			_, prefixNet2, _ := net.ParseCIDR(tt.prefix2)

			result := containsCIDR(prefixNet1, prefixNet2)
			assert.Equal(t, tt.result, result)
		})
	}
}
