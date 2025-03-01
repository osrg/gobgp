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
	"testing"
	"time"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
)

func TestCreateTable(t *testing.T) {
	table := NewTable(logger, bgp.RF_FS_IPv4_VPN)
	assert.NotNil(t, table.rtc)
	_, checkType := table.rtc.(*vpnFamilyRTCMap)
	assert.True(t, checkType)

	table = NewTable(logger, bgp.RF_RTC_UC)
	assert.Nil(t, table.rtc)

	table = NewTable(logger, bgp.RF_IPv4_MPLS)
	assert.Nil(t, table.rtc)

	assert.Panics(t, func() {
		table = NewTable(logger, 0)
	})
}

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

func TestTableGetRouteFamily(t *testing.T) {
	ipv4t := NewTable(logger, bgp.RF_IPv4_UC)
	rf := ipv4t.GetRoutefamily()
	assert.Equal(t, rf, bgp.RF_IPv4_UC)
}

func TestTableSetDestinations(t *testing.T) {
	peerT := TableCreatePeer()
	pathT := TableCreatePath(peerT)
	ipv4t := NewTable(logger, bgp.RF_IPv4_UC)
	destinations := make(map[string]*Destination)
	for _, path := range pathT {
		tableKey := ipv4t.tableKey(path.GetNlri())
		dest := NewDestination(path.GetNlri(), 0)
		destinations[tableKey] = dest
	}
	ipv4t.setDestinations(destinations)
	ds := ipv4t.GetDestinations()
	assert.Equal(t, ds, destinations)
}
func TestTableGetDestinations(t *testing.T) {
	peerT := DestCreatePeer()
	pathT := DestCreatePath(peerT)
	ipv4t := NewTable(logger, bgp.RF_IPv4_UC)
	destinations := make(map[string]*Destination)
	for _, path := range pathT {
		tableKey := ipv4t.tableKey(path.GetNlri())
		dest := NewDestination(path.GetNlri(), 0)
		destinations[tableKey] = dest
	}
	ipv4t.setDestinations(destinations)
	ds := ipv4t.GetDestinations()
	assert.Equal(t, ds, destinations)
}

func TestTableKey(t *testing.T) {
	tb := NewTable(logger, bgp.RF_IPv4_UC)
	n1, _ := bgp.NewPrefixFromRouteFamily(bgp.AFI_IP, bgp.SAFI_UNICAST, "0.0.0.0/0")
	d1 := NewDestination(n1, 0)
	n2, _ := bgp.NewPrefixFromRouteFamily(bgp.AFI_IP, bgp.SAFI_UNICAST, "0.0.0.0/1")
	d2 := NewDestination(n2, 0)
	assert.Equal(t, len(tb.tableKey(d1.GetNlri())), 5)
	tb.setDestination(d1)
	tb.setDestination(d2)
	assert.Equal(t, len(tb.GetDestinations()), 2)
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
			filteredTable, _ := table.Select(
				TableSelectOption{
					LookupPrefixes: []*LookupPrefix{{
						Prefix:       tt.prefix,
						LookupOption: tt.option,
					}},
				},
			)
			assert.Equal(t, tt.found, len(filteredTable.GetDestinations()))
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
			filteredTable, _ := table.Select(
				TableSelectOption{
					LookupPrefixes: []*LookupPrefix{{
						Prefix:       tt.prefix,
						LookupOption: tt.option,
					}},
				},
			)
			assert.Equal(t, tt.found, len(filteredTable.GetDestinations()))
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
		nlri, _ := bgp.NewPrefixFromRouteFamily(bgp.AFI_IP, bgp.SAFI_MPLS_VPN, prefix)

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
			filteredTable, _ := table.Select(
				TableSelectOption{
					LookupPrefixes: []*LookupPrefix{{
						Prefix:       tt.prefix,
						RD:           tt.RD,
						LookupOption: tt.option,
					}},
				},
			)
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
		nlri, _ := bgp.NewPrefixFromRouteFamily(bgp.AFI_IP6, bgp.SAFI_MPLS_VPN, prefix)

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
			filteredTable, _ := table.Select(
				TableSelectOption{
					LookupPrefixes: []*LookupPrefix{{
						Prefix:       tt.prefix,
						RD:           tt.RD,
						LookupOption: tt.option,
					}},
				},
			)
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

type testPathWithRTs struct {
	prefix string
	rts    []bgp.ExtendedCommunityInterface
}

func TestTableRTC(t *testing.T) {
	rtStrings := []string{"100:100", "100:200", "100:300"}
	rts := make([]bgp.ExtendedCommunityInterface, 0)
	for _, strRT := range rtStrings {
		rt, err := bgp.ParseRouteTarget(strRT)
		assert.Nil(t, err)
		rts = append(rts, rt)
	}
	assert.Equal(t, 3, len(rts))

	declarations := []testPathWithRTs{
		{
			prefix: "100:100:10.10.10.10/32",
			rts:    []bgp.ExtendedCommunityInterface{rts[0]},
		},
		{
			prefix: "101:100:10.10.10.11/32",
			rts:    []bgp.ExtendedCommunityInterface{rts[0], rts[1]},
		},
		{
			prefix: "100:200:10.10.10.12/32",
			rts:    []bgp.ExtendedCommunityInterface{rts[1]},
		},
		{
			prefix: "100:300:10.10.10.13/32",
			rts:    []bgp.ExtendedCommunityInterface{rts[2]},
		},
	}
	table, paths := makeTableWithRT(t, nil, declarations, bgp.RF_IPv4_VPN)
	assert.Equal(t, 4, len(table.GetDestinations()))

	hash0, err := bgp.ExtCommRouteTargetKey(rts[0])
	assert.Nil(t, err)
	pathsRT := table.getBestsForNewlyAttachedRTtoPeer(hash0, "127.0.0.1:1", "global", 0, nil)
	assert.Equal(t, 2, len(pathsRT))
	assert.True(t, equalPaths(pathsRT, []*Path{paths[0], paths[1]}))

	hash1, err := bgp.ExtCommRouteTargetKey(rts[1])
	assert.Nil(t, err)

	pathsRT = table.getBestsForNewlyAttachedRTtoPeer(hash1, "127.0.0.1:1", "global", 0, nil)
	assert.Equal(t, 2, len(pathsRT))
	assert.True(t, equalPaths(pathsRT, []*Path{paths[1], paths[2]}))

	hash2, err := bgp.ExtCommRouteTargetKey(rts[2])
	assert.Nil(t, err)

	pathsRT = table.getBestsForNewlyAttachedRTtoPeer(hash2, "127.0.0.1:1", "global", 0, pathsRT)
	assert.Equal(t, 3, len(pathsRT))
	assert.True(t, equalPaths(pathsRT, []*Path{paths[1], paths[2], paths[3]}))

	pathsRT = table.getBestsForNewlyAttachedRTtoPeer(hash1, "127.0.0.1:1", "global", 0, nil)
	assert.Equal(t, 0, len(pathsRT))

	pathsRT = table.getBestsForNewlyAttachedRTtoPeer(hash2, "127.0.0.1:1", "global", 0, nil)
	assert.Equal(t, 0, len(pathsRT))

	pathsRT = table.getBestsForNewlyAttachedRTtoPeer(hash0, "127.0.0.1:2", "global", 0, nil)
	assert.Equal(t, 2, len(pathsRT))
	assert.True(t, equalPaths(pathsRT, []*Path{paths[0], paths[1]}))

	pathsRT = table.getBestsForNewlyAttachedRTtoPeer(hash1, "127.0.0.1:2", "global", 0, nil)
	assert.Equal(t, 2, len(pathsRT))
	assert.True(t, equalPaths(pathsRT, []*Path{paths[1], paths[2]}))

	update := table.update(paths[2].Clone(true))
	assert.Equal(t, 0, len(update.KnownPathList))
	assert.Equal(t, 1, len(update.OldKnownPathList))
	assert.True(t, update.OldKnownPathList[0].Equal(paths[2]))

	update = table.update(paths[1].Clone(false))
	assert.Equal(t, 1, len(update.KnownPathList))
	assert.Equal(t, 1, len(update.OldKnownPathList))
	assert.True(t, update.KnownPathList[0].Equal(paths[1]))
	assert.True(t, update.OldKnownPathList[0].Equal(paths[1]))

	pathsRT = table.getBestsForNewlyAttachedRTtoPeer(hash0, "127.0.0.1:1", "global", 0, nil)
	assert.Equal(t, 0, len(pathsRT))

	pathsRT = table.getBestsForNewlyAttachedRTtoPeer(hash1, "127.0.0.1:1", "global", 0, nil)
	assert.Equal(t, 0, len(pathsRT))

	pathsRT = table.getBestsForNewlyAttachedRTtoPeer(hash2, "127.0.0.1:1", "global", 0, nil)
	assert.Equal(t, 0, len(pathsRT))

	pathsRT = table.getBestsForDetachedRTFromPeer(hash0, "127.0.0.1:1", "global", 0, nil)
	assert.Equal(t, 2, len(pathsRT))
	assert.True(t, equalPaths(pathsRT, []*Path{paths[0], paths[1]}))

	pathsRT = table.getBestsForDetachedRTFromPeer(hash2, "127.0.0.1:1", "global", 0, pathsRT)
	assert.Equal(t, 3, len(pathsRT))
	assert.True(t, equalPaths(pathsRT, []*Path{paths[0], paths[1], paths[3]}))

	pathsRT = table.getBestsForDetachedRTFromPeer(hash1, "127.0.0.1:1", "global", 0, nil)
	assert.Equal(t, 1, len(pathsRT))
	assert.True(t, equalPaths(pathsRT, []*Path{paths[1]}))

	pathsRT = table.getBestsForDetachedRTFromPeer(hash1, "127.0.0.1:1", "global", 0, nil)
	assert.Equal(t, 0, len(pathsRT))

	pathsRT = table.getBestsForNewlyAttachedRTtoPeer(hash1, "127.0.0.1:1", "global", 0, nil)
	assert.Equal(t, 1, len(pathsRT))
	assert.True(t, equalPaths(pathsRT, []*Path{paths[1]}))
}

func equalPaths(paths1, paths2 []*Path) bool {
	if len(paths1) != len(paths2) {
		return false
	}
	cp2 := paths2[:]
	for _, p1 := range paths1 {
		found := false
		for i2, p2 := range cp2 {
			if p1.Equal(p2) {
				found = true
				cp2 = append(cp2[:i2], cp2[i2+1:]...)
				break
			}
		}
		if !found {
			return false
		}
	}
	return len(cp2) == 0
}

func makeTableWithRT(t *testing.T, table *Table, declarations []testPathWithRTs, rf bgp.RouteFamily) (*Table, []*Path) {
	if table == nil {
		table = NewTable(logger, rf)
	}
	afi, safi := bgp.RouteFamilyToAfiSafi(rf)
	paths := make([]*Path, 0)
	for _, item := range declarations {
		nlri, _ := bgp.NewPrefixFromRouteFamily(afi, safi, item.prefix)
		var pattr *bgp.PathAttributeExtendedCommunities
		if len(item.rts) > 0 {
			pattr = bgp.NewPathAttributeExtendedCommunities(item.rts)
		}
		path := NewPath(nil, nlri, false, []bgp.PathAttributeInterface{pattr}, time.Now(), false)

		update := table.update(path)
		assert.Equal(t, 1, len(update.KnownPathList))
		assert.Equal(t, 0, len(update.OldKnownPathList))
		assert.True(t, update.KnownPathList[0].Equal(path))
		paths = append(paths, path)
	}
	return table, paths
}
