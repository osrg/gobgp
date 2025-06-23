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
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
)

func TestLookupLonger(t *testing.T) {
	tbl := NewTable(logger, bgp.RF_IPv4_UC)

	tbl.setDestination(NewDestination(bgp.NewIPAddrPrefix(23, "11.0.0.0"), 0))
	tbl.setDestination(NewDestination(bgp.NewIPAddrPrefix(24, "11.0.0.0"), 0))
	tbl.setDestination(NewDestination(bgp.NewIPAddrPrefix(32, "11.0.0.4"), 0))
	tbl.setDestination(NewDestination(bgp.NewIPAddrPrefix(32, "11.0.0.129"), 0))
	tbl.setDestination(NewDestination(bgp.NewIPAddrPrefix(28, "11.0.0.144"), 0))
	tbl.setDestination(NewDestination(bgp.NewIPAddrPrefix(29, "11.0.0.144"), 0))
	tbl.setDestination(NewDestination(bgp.NewIPAddrPrefix(32, "11.0.0.145"), 0))

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
		return bgp.AddrPrefixOnlyCompare(a.GetNlri(), b.GetNlri())
	})
	ds := ipv4t.GetDestinations()
	slices.SortFunc(ds, func(a, b *Destination) int {
		return bgp.AddrPrefixOnlyCompare(a.GetNlri(), b.GetNlri())
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
		return bgp.AddrPrefixOnlyCompare(a.GetNlri(), b.GetNlri())
	})
	ds := ipv4t.GetDestinations()
	slices.SortFunc(ds, func(a, b *Destination) int {
		return bgp.AddrPrefixOnlyCompare(a.GetNlri(), b.GetNlri())
	})
	assert.Equal(t, ds, destinations)
}

func TestTableKey(t *testing.T) {
	tb := NewTable(logger, bgp.RF_IPv4_UC)
	n1, _ := bgp.NewPrefixFromFamily(bgp.AFI_IP, bgp.SAFI_UNICAST, "0.0.0.0/0")
	d1 := NewDestination(n1, 0)
	n2, _ := bgp.NewPrefixFromFamily(bgp.AFI_IP, bgp.SAFI_UNICAST, "0.0.0.0/1")
	d2 := NewDestination(n2, 0)

	assert.NotEqual(t, tableKey(d1.GetNlri()), tableKey(d2.GetNlri()))
	tb.setDestination(d1)
	tb.setDestination(d2)
	assert.Equal(t, len(tb.GetDestinations()), 2)
}

func BenchmarkTableKey(b *testing.B) {
	rd := bgp.NewRouteDistinguisherTwoOctetAS(1, 2)
	esi, _ := bgp.ParseEthernetSegmentIdentifier([]string{"lacp", "aa:bb:cc:dd:ee:ff", "100"})
	prefix := []bgp.AddrPrefixInterface{
		bgp.NewIPAddrPrefix(24, "192.168.1.0"),
		bgp.NewIPv6AddrPrefix(64, "2001:db8::"),
		bgp.NewLabeledVPNIPAddrPrefix(24, "192.168.1.0", *bgp.NewMPLSLabelStack(100, 200, 300), rd),
		bgp.NewLabeledVPNIPv6AddrPrefix(64, "2001:db8::", *bgp.NewMPLSLabelStack(100, 200, 300), rd),
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
		option LookupOption
		found  int
	}{
		{
			name:   "Malformed IPv4 Address",
			prefix: "2.2.2.2.2",
			option: LOOKUP_EXACT,
			found:  0,
		},
		{
			name:   "exact match with RD and prefix that does not exist",
			prefix: "foo",
			option: LOOKUP_EXACT,
			found:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := table.Select(
				TableSelectOption{
					LookupPrefixes: []*LookupPrefix{{
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
		option LookupOption
		found  int
	}{
		{
			name:   "Malformed IPv6 Address: 3343:faba:3903:128::::/63",
			prefix: "3343:faba:3903:128::::/63",
			option: LOOKUP_EXACT,
			found:  0,
		},
		{
			name:   "Malformed IPv6 Address: foo",
			prefix: "foo",
			option: LOOKUP_EXACT,
			found:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := table.Select(
				TableSelectOption{
					LookupPrefixes: []*LookupPrefix{{
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
		nlri, _ := bgp.NewPrefixFromFamily(bgp.AFI_IP, bgp.SAFI_MPLS_VPN, prefix)

		destination := NewDestination(nlri, 0, NewPath(nil, nlri, false, nil, time.Now(), false))
		table.setDestination(destination)
	}
	assert.Equal(t, 9, len(table.GetDestinations()))

	tests := []struct {
		name   string
		prefix string
		RD     string
		option LookupOption
		found  int
	}{
		{
			name:   "exact match with RD that does not exist",
			prefix: "2.2.2.2/32",
			RD:     "500:500",
			option: LOOKUP_EXACT,
			found:  0,
		},
		{
			name:   "exact match with RD and prefix that does not exist",
			prefix: "4.4.4.4/32",
			RD:     "100:100",
			option: LOOKUP_EXACT,
			found:  0,
		},
		{
			name:   "exact match with RD",
			prefix: "2.2.2.0/25",
			RD:     "100:100",
			option: LOOKUP_EXACT,
			found:  1,
		},
		{
			name:   "longer match with RD",
			prefix: "2.2.2.0/25",
			RD:     "100:100",
			option: LOOKUP_LONGER,
			found:  4,
		},
		{
			name:   "shorter match with RD",
			prefix: "2.2.2.2/32",
			RD:     "100:100",
			option: LOOKUP_SHORTER,
			found:  2,
		},
		{
			name:   "exact match without RD for prefix that does not exist",
			prefix: "4.4.4.4/32",
			option: LOOKUP_EXACT,
			found:  0,
		},
		{
			name:   "exact match without RD",
			prefix: "2.2.2.2/32",
			option: LOOKUP_EXACT,
			found:  3,
		},
		{
			name:   "longer match without RD",
			prefix: "2.2.2.0/24",
			option: LOOKUP_LONGER,
			found:  8,
		},
		{
			name:   "shorter match without RD",
			prefix: "2.2.2.2/32",
			option: LOOKUP_SHORTER,
			found:  4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filteredTable, err := table.Select(
				TableSelectOption{
					LookupPrefixes: []*LookupPrefix{{
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
		nlri, _ := bgp.NewPrefixFromFamily(bgp.AFI_IP6, bgp.SAFI_MPLS_VPN, prefix)

		destination := NewDestination(nlri, 0, NewPath(nil, nlri, false, nil, time.Now(), false))
		table.setDestination(destination)
	}
	assert.Equal(t, 9, len(table.GetDestinations()))

	tests := []struct {
		name   string
		prefix string
		RD     string
		option LookupOption
		found  int
	}{
		{
			name:   "exact match with RD that does not exist",
			prefix: "100::/32",
			RD:     "500:500",
			option: LOOKUP_EXACT,
			found:  0,
		},
		{
			name:   "exact match with RD and prefix that does not exist",
			prefix: "200::/32",
			RD:     "100:100",
			option: LOOKUP_EXACT,
			found:  0,
		},
		{
			name:   "exact match with RD",
			prefix: "100:2::/64",
			RD:     "100:100",
			option: LOOKUP_EXACT,
			found:  1,
		},
		{
			name:   "longer match with RD",
			prefix: "100::/16",
			RD:     "100:100",
			option: LOOKUP_LONGER,
			found:  7,
		},
		{
			name:   "shorter match with RD",
			prefix: "100::/96",
			RD:     "100:100",
			option: LOOKUP_SHORTER,
			found:  2,
		},
		{
			name:   "exact match without RD for prefix that does not exist",
			prefix: "100:5::/64",
			option: LOOKUP_EXACT,
			found:  0,
		},
		{
			name:   "exact match without RD",
			prefix: "100:2::/64",
			option: LOOKUP_EXACT,
			found:  3,
		},
		{
			name:   "longer match without RD",
			prefix: "100:3::/32",
			option: LOOKUP_LONGER,
			found:  2,
		},
		{
			name:   "shorter match without RD",
			prefix: "100:2::/96",
			option: LOOKUP_SHORTER,
			found:  3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filteredTable, err := table.Select(
				TableSelectOption{
					LookupPrefixes: []*LookupPrefix{{
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
		pathT[i] = NewPath(peerT[i], nlri_info, false, pathAttributes, time.Now(), false)
	}
	return pathT
}

func updateMsgT1() *bgp.BGPMessage {
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65000})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("192.168.50.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med,
	}

	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.10.0")}
	return bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
}

func updateMsgT2() *bgp.BGPMessage {
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65100})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("192.168.100.1")
	med := bgp.NewPathAttributeMultiExitDisc(100)

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med,
	}

	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "20.20.20.0")}
	return bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
}

func updateMsgT3() *bgp.BGPMessage {
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65100})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("192.168.150.1")
	med := bgp.NewPathAttributeMultiExitDisc(100)

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med,
	}

	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "30.30.30.0")}
	w1 := bgp.NewIPAddrPrefix(23, "40.40.40.0")
	withdrawnRoutes := []*bgp.IPAddrPrefix{w1}
	return bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
}

//nolint:errcheck
func createRandomAddrPrefix() []bgp.AddrPrefixInterface {
	label := *bgp.NewMPLSLabelStack(1, 2, 3)
	rd := bgp.NewRouteDistinguisherTwoOctetAS(256, 10000)

	b := make([]byte, 4)
	crand.Read(b)
	addrv4, _ := netip.AddrFromSlice(b)
	prefixv4 := addrv4.String()
	lengthv4 := uint8(rand.Intn(32)) + 1

	b = make([]byte, 16)
	crand.Read(b)
	addrv6, _ := netip.AddrFromSlice(b)
	prefixv6 := addrv6.String()
	lengthv6 := uint8(rand.Intn(128)) + 1

	prefixes := []bgp.AddrPrefixInterface{
		bgp.NewIPAddrPrefix(lengthv4, prefixv4),
		bgp.NewLabeledVPNIPAddrPrefix(lengthv4, prefixv4, label, rd),
		bgp.NewLabeledIPAddrPrefix(lengthv4, prefixv4, label),
		bgp.NewIPv6AddrPrefix(lengthv6, prefixv6),
		bgp.NewLabeledVPNIPv6AddrPrefix(lengthv6, prefixv6, label, rd),
		bgp.NewLabeledIPv6AddrPrefix(lengthv6, prefixv6, label),
	}

	return prefixes
}

//nolint:errcheck
func createAddrPrefixBaseIndex(index int) []bgp.AddrPrefixInterface {
	label := *bgp.NewMPLSLabelStack(1, 2, 3)
	rd := bgp.NewRouteDistinguisherTwoOctetAS(256, 10000)

	b := []byte{192, 168, 1, 0}
	v := binary.BigEndian.Uint32(b)
	v += uint32(index) << 8
	binary.BigEndian.PutUint32(b, v)
	addrv4, _ := netip.AddrFromSlice(b)
	prefixv4 := addrv4.String()
	lengthv4 := uint8(28)

	b = make([]byte, 16)
	crand.Read(b)
	v = binary.BigEndian.Uint32(b)
	v += uint32(index) << 8
	binary.BigEndian.PutUint32(b, v)
	addrv6, _ := netip.AddrFromSlice(b)
	prefixv6 := addrv6.String()
	lengthv6 := uint8(96)

	prefixes := []bgp.AddrPrefixInterface{
		bgp.NewIPAddrPrefix(lengthv4, prefixv4),
		bgp.NewLabeledVPNIPAddrPrefix(lengthv4, prefixv4, label, rd),
		bgp.NewLabeledIPAddrPrefix(lengthv4, prefixv4, label),
		bgp.NewIPv6AddrPrefix(lengthv6, prefixv6),
		bgp.NewLabeledVPNIPv6AddrPrefix(lengthv6, prefixv6, label, rd),
		bgp.NewLabeledIPv6AddrPrefix(lengthv6, prefixv6, label),
	}

	return prefixes
}

func TestTableDestinationsCollisionAttack(t *testing.T) {
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
