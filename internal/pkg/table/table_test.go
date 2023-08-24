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

func TestTableSelect(t *testing.T) {
	// Test VPNv4 table
	existingVpnv4Prefix1 := "100:100:10.1.1.0/27"
	existingVpnv4Prefix2 := "100:100:10.1.1.0/28"

	vpnv4Prefix1, _ := bgp.NewPrefixFromRouteFamily(bgp.AFI_IP, bgp.SAFI_MPLS_VPN, existingVpnv4Prefix1)
	vpnv4Prefix2, _ := bgp.NewPrefixFromRouteFamily(bgp.AFI_IP, bgp.SAFI_MPLS_VPN, existingVpnv4Prefix2)
	vpnv4Destination1 := NewDestination(vpnv4Prefix1, 0, NewPath(nil, vpnv4Prefix1, false, nil, time.Now(), false))
	vpnv4Destination2 := NewDestination(vpnv4Prefix2, 0, NewPath(nil, vpnv4Prefix2, false, nil, time.Now(), false))

	vpnv4Table := NewTable(logger, bgp.RF_IPv4_VPN)
	assert.Equal(t, 13, len(vpnv4Table.tableKey(vpnv4Destination1.GetNlri())))

	vpnv4Table.setDestination(vpnv4Destination1)
	vpnv4Table.setDestination(vpnv4Destination2)
	assert.Equal(t, 2, len(vpnv4Table.GetDestinations()))

	// exact match
	filteredVpnv4Table, _ := vpnv4Table.Select(
		TableSelectOption{
			LookupPrefixes: []*LookupPrefix{{Prefix: existingVpnv4Prefix1}},
		},
	)
	assert.Equal(t, 1, len(filteredVpnv4Table.GetDestinations()))

	// longer match
	shorterVpnv4Prefix := "100:100:10.1.1.0/24"
	filteredVpnv4TableLonger, _ := vpnv4Table.Select(
		TableSelectOption{
			LookupPrefixes: []*LookupPrefix{{Prefix: shorterVpnv4Prefix, LookupOption: LOOKUP_LONGER}},
		},
	)
	assert.Equal(t, 2, len(filteredVpnv4TableLonger.GetDestinations()))

	// shorter match
	longerVpnv4Prefix := "100:100:10.1.1.0/32"
	filteredVpnv4TableShorter, _ := vpnv4Table.Select(
		TableSelectOption{
			LookupPrefixes: []*LookupPrefix{{Prefix: longerVpnv4Prefix, LookupOption: LOOKUP_SHORTER}},
		},
	)
	assert.Equal(t, 2, len(filteredVpnv4TableShorter.GetDestinations()))

	// does not exist
	nonExistingVpnv4Prefix := "100:100:20.0.0.0/24"

	emptyVpnv4Table, _ := vpnv4Table.Select(
		TableSelectOption{
			LookupPrefixes: []*LookupPrefix{{Prefix: nonExistingVpnv4Prefix}},
		},
	)
	assert.Equal(t, 0, len(emptyVpnv4Table.GetDestinations()))

	// invalid
	invalidVpnv4Prefix := "30.0.0.0/24"
	noVpnv4Prefix, _ := bgp.NewPrefixFromRouteFamily(bgp.AFI_IP, bgp.SAFI_MPLS_VPN, invalidVpnv4Prefix)
	assert.Nil(t, noVpnv4Prefix)

	// Test VPNv6 table
	existingVpnv6Prefix1 := "1.1.1.1:1:100:1::/64"
	existingVpnv6Prefix2 := "1.1.1.1:1:100:2::/64"

	vpnv6Prefix1, _ := bgp.NewPrefixFromRouteFamily(bgp.AFI_IP6, bgp.SAFI_MPLS_VPN, existingVpnv6Prefix1)
	vpnv6Prefix2, _ := bgp.NewPrefixFromRouteFamily(bgp.AFI_IP6, bgp.SAFI_MPLS_VPN, existingVpnv6Prefix2)
	vpnv6Destination1 := NewDestination(vpnv6Prefix1, 0, NewPath(nil, vpnv6Prefix1, false, nil, time.Now(), false))
	vpnv6Destination2 := NewDestination(vpnv6Prefix2, 0, NewPath(nil, vpnv6Prefix2, false, nil, time.Now(), false))

	vpnv6Table := NewTable(logger, bgp.RF_IPv6_VPN)
	assert.Equal(t, 25, len(vpnv6Table.tableKey(vpnv6Destination1.GetNlri())))

	vpnv6Table.setDestination(vpnv6Destination1)
	vpnv6Table.setDestination(vpnv6Destination2)
	assert.Equal(t, 2, len(vpnv6Table.GetDestinations()))

	// exact match
	filteredVpnv6Table, _ := vpnv6Table.Select(
		TableSelectOption{
			LookupPrefixes: []*LookupPrefix{{Prefix: existingVpnv6Prefix1}},
		},
	)
	assert.Equal(t, 1, len(filteredVpnv6Table.GetDestinations()))

	// longer match
	shorterVpnv6Prefix := "1.1.1.1:1:100::/16"
	filteredVpnv6TableLonger, _ := vpnv6Table.Select(
		TableSelectOption{
			LookupPrefixes: []*LookupPrefix{{Prefix: shorterVpnv6Prefix, LookupOption: LOOKUP_LONGER}},
		},
	)
	assert.Equal(t, 2, len(filteredVpnv6TableLonger.GetDestinations()))

	filteredVpnv6TableLongerNoMatch, _ := vpnv6Table.Select(
		TableSelectOption{
			LookupPrefixes: []*LookupPrefix{{Prefix: shorterVpnv6Prefix, LookupOption: LOOKUP_SHORTER}},
		},
	)
	assert.Equal(t, 0, len(filteredVpnv6TableLongerNoMatch.GetDestinations()))

	// shorter match
	longerVpnv6Prefix := "1.1.1.1:1:100:1::/96"
	filteredVpnv6TableShorter, _ := vpnv6Table.Select(
		TableSelectOption{
			LookupPrefixes: []*LookupPrefix{{Prefix: longerVpnv6Prefix, LookupOption: LOOKUP_SHORTER}},
		},
	)
	assert.Equal(t, 1, len(filteredVpnv6TableShorter.GetDestinations()))

	filteredVpnv6TableShorterNoMatch, _ := vpnv6Table.Select(
		TableSelectOption{
			LookupPrefixes: []*LookupPrefix{{Prefix: longerVpnv6Prefix, LookupOption: LOOKUP_LONGER}},
		},
	)
	assert.Equal(t, 0, len(filteredVpnv6TableShorterNoMatch.GetDestinations()))

	// does not exist
	nonExistingVpnv6Prefix := "1.1.1.1:1:200:1::/64"

	emptyVpnv6Table, _ := vpnv6Table.Select(
		TableSelectOption{
			LookupPrefixes: []*LookupPrefix{{Prefix: nonExistingVpnv6Prefix}},
		},
	)
	assert.Equal(t, 0, len(emptyVpnv6Table.GetDestinations()))

	// invalid
	invalidVpnv6Prefix := "300:1::/64"
	noVpnv6Prefix, _ := bgp.NewPrefixFromRouteFamily(bgp.AFI_IP, bgp.SAFI_MPLS_VPN, invalidVpnv6Prefix)
	assert.Nil(t, noVpnv6Prefix)
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
