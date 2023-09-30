// Copyright (C) 2014,2015 Nippon Telegraph and Telephone Corporation.
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
	"math"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/osrg/gobgp/v3/pkg/config/oc"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetStatement(t *testing.T) {
	r := NewRoutingPolicy(logger)
	r.statementMap["statement1"] = &Statement{Name: "statement1"}
	r.statementMap["statement2"] = &Statement{Name: "statement2"}
	assert.Equal(t, len(r.GetStatement("")), 2)
	assert.Equal(t, len(r.GetStatement("statement1")), 1)
	assert.Equal(t, len(r.GetStatement("unknown")), 0)
}

func TestGetPolicy(t *testing.T) {
	r := NewRoutingPolicy(logger)
	r.policyMap["p1"] = &Policy{Name: "p1"}
	r.policyMap["p2"] = &Policy{Name: "p2"}
	assert.Equal(t, len(r.GetPolicy("")), 2)
	assert.Equal(t, len(r.GetPolicy("p1")), 1)
	assert.Equal(t, len(r.GetPolicy("unknown")), 0)
}
func TestPrefixCalcurateNoRange(t *testing.T) {
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.0")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := ProcessMessage(updateMsg, peer, time.Now())[0]
	// test
	pl1, _ := NewPrefix(oc.Prefix{IpPrefix: "10.10.0.0/24", MasklengthRange: ""})
	match1 := pl1.Match(path)
	assert.Equal(t, true, match1)
	pl2, _ := NewPrefix(oc.Prefix{IpPrefix: "10.10.0.0/23", MasklengthRange: ""})
	match2 := pl2.Match(path)
	assert.Equal(t, false, match2)
	pl3, _ := NewPrefix(oc.Prefix{IpPrefix: "10.10.0.0/16", MasklengthRange: "21..24"})
	match3 := pl3.Match(path)
	assert.Equal(t, true, match3)
}

func TestPrefixCalcurateAddress(t *testing.T) {
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := ProcessMessage(updateMsg, peer, time.Now())[0]
	// test
	pl1, _ := NewPrefix(oc.Prefix{IpPrefix: "10.11.0.0/16", MasklengthRange: "21..24"})
	match1 := pl1.Match(path)
	assert.Equal(t, false, match1)
	pl2, _ := NewPrefix(oc.Prefix{IpPrefix: "10.10.0.0/16", MasklengthRange: "21..24"})
	match2 := pl2.Match(path)
	assert.Equal(t, true, match2)
}

func TestPrefixCalcurateLength(t *testing.T) {
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := ProcessMessage(updateMsg, peer, time.Now())[0]
	// test
	pl1, _ := NewPrefix(oc.Prefix{IpPrefix: "10.10.64.0/24", MasklengthRange: "21..24"})
	match1 := pl1.Match(path)
	assert.Equal(t, false, match1)
	pl2, _ := NewPrefix(oc.Prefix{IpPrefix: "10.10.64.0/16", MasklengthRange: "21..24"})
	match2 := pl2.Match(path)
	assert.Equal(t, true, match2)
}

func TestPrefixCalcurateLengthRange(t *testing.T) {
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := ProcessMessage(updateMsg, peer, time.Now())[0]
	// test
	pl1, _ := NewPrefix(oc.Prefix{IpPrefix: "10.10.0.0/16", MasklengthRange: "21..23"})
	match1 := pl1.Match(path)
	assert.Equal(t, false, match1)
	pl2, _ := NewPrefix(oc.Prefix{IpPrefix: "10.10.0.0/16", MasklengthRange: "25..26"})
	match2 := pl2.Match(path)
	assert.Equal(t, false, match2)
	pl3, _ := NewPrefix(oc.Prefix{IpPrefix: "10.10.0.0/16", MasklengthRange: "21..24"})
	match3 := pl3.Match(path)
	assert.Equal(t, true, match3)
}

func TestPrefixCalcurateNoRangeIPv6(t *testing.T) {
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("2001::192:168:50:1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	mpnlri := []bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")}
	mpreach := bgp.NewPathAttributeMpReachNLRI("2001::192:168:50:1", mpnlri)
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{mpreach, origin, aspath, med}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nil)
	path := ProcessMessage(updateMsg, peer, time.Now())[0]
	// test
	pl1, _ := NewPrefix(oc.Prefix{IpPrefix: "2001:123:123::/48", MasklengthRange: ""})
	match1 := pl1.Match(path)
	assert.Equal(t, false, match1)
	pl2, _ := NewPrefix(oc.Prefix{IpPrefix: "2001:123:123:1::/64", MasklengthRange: ""})
	match2 := pl2.Match(path)
	assert.Equal(t, true, match2)
	pl3, _ := NewPrefix(oc.Prefix{IpPrefix: "2001:123:123::/48", MasklengthRange: "64..80"})
	match3 := pl3.Match(path)
	assert.Equal(t, true, match3)
}

func TestPrefixCalcurateAddressIPv6(t *testing.T) {
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("2001::192:168:50:1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	mpnlri := []bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")}
	mpreach := bgp.NewPathAttributeMpReachNLRI("2001::192:168:50:1", mpnlri)
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{mpreach, origin, aspath, med}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nil)
	path := ProcessMessage(updateMsg, peer, time.Now())[0]
	// test
	pl1, _ := NewPrefix(oc.Prefix{IpPrefix: "2001:123:128::/48", MasklengthRange: "64..80"})
	match1 := pl1.Match(path)
	assert.Equal(t, false, match1)
	pl2, _ := NewPrefix(oc.Prefix{IpPrefix: "2001:123:123::/48", MasklengthRange: "64..80"})
	match2 := pl2.Match(path)
	assert.Equal(t, true, match2)
}

func TestPrefixCalcurateLengthIPv6(t *testing.T) {
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("2001::192:168:50:1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	mpnlri := []bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")}
	mpreach := bgp.NewPathAttributeMpReachNLRI("2001::192:168:50:1", mpnlri)
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{mpreach, origin, aspath, med}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nil)
	path := ProcessMessage(updateMsg, peer, time.Now())[0]
	// test
	pl1, _ := NewPrefix(oc.Prefix{IpPrefix: "2001:123:123:64::/64", MasklengthRange: "64..80"})
	match1 := pl1.Match(path)
	assert.Equal(t, false, match1)
	pl2, _ := NewPrefix(oc.Prefix{IpPrefix: "2001:123:123:64::/48", MasklengthRange: "64..80"})
	match2 := pl2.Match(path)
	assert.Equal(t, true, match2)
}

func TestPrefixCalcurateLengthRangeIPv6(t *testing.T) {
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("2001::192:168:50:1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	mpnlri := []bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")}
	mpreach := bgp.NewPathAttributeMpReachNLRI("2001::192:168:50:1", mpnlri)
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{mpreach, origin, aspath, med}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nil)
	path := ProcessMessage(updateMsg, peer, time.Now())[0]
	// test
	pl1, _ := NewPrefix(oc.Prefix{IpPrefix: "2001:123:123::/48", MasklengthRange: "62..63"})
	match1 := pl1.Match(path)
	assert.Equal(t, false, match1)
	pl2, _ := NewPrefix(oc.Prefix{IpPrefix: "2001:123:123::/48", MasklengthRange: "65..66"})
	match2 := pl2.Match(path)
	assert.Equal(t, false, match2)
	pl3, _ := NewPrefix(oc.Prefix{IpPrefix: "2001:123:123::/48", MasklengthRange: "63..65"})
	match3 := pl3.Match(path)
	assert.Equal(t, true, match3)
}

func TestPolicyNotMatch(t *testing.T) {
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := ProcessMessage(updateMsg, peer, time.Now())[0]

	// create policy
	ps := createPrefixSet("ps1", "10.3.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")
	ds := oc.DefinedSets{}
	ds.PrefixSets = []oc.PrefixSet{ps}
	ds.NeighborSets = []oc.NeighborSet{ns}
	s := createStatement("statement1", "ps1", "ns1", false)
	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	r := NewRoutingPolicy(logger)
	err := r.reload(pl)
	assert.Nil(t, err)
	pType, newPath := r.policyMap["pd1"].Apply(logger, path, nil)
	assert.Equal(t, ROUTE_TYPE_NONE, pType)
	assert.Equal(t, newPath, path)
}

func TestPolicyMatchAndReject(t *testing.T) {
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := ProcessMessage(updateMsg, peer, time.Now())[0]
	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")
	ds := oc.DefinedSets{}
	ds.PrefixSets = []oc.PrefixSet{ps}
	ds.NeighborSets = []oc.NeighborSet{ns}

	s := createStatement("statement1", "ps1", "ns1", false)
	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	r := NewRoutingPolicy(logger)
	err := r.reload(pl)
	assert.Nil(t, err)
	pType, newPath := r.policyMap["pd1"].Apply(logger, path, nil)
	assert.Equal(t, ROUTE_TYPE_REJECT, pType)
	assert.Equal(t, newPath, path)
}

func TestPolicyMatchAndAccept(t *testing.T) {
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := ProcessMessage(updateMsg, peer, time.Now())[0]
	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")
	ds := oc.DefinedSets{}
	ds.PrefixSets = []oc.PrefixSet{ps}
	ds.NeighborSets = []oc.NeighborSet{ns}

	s := createStatement("statement1", "ps1", "ns1", true)
	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	//test
	r := NewRoutingPolicy(logger)
	err := r.reload(pl)
	assert.Nil(t, err)
	pType, newPath := r.policyMap["pd1"].Apply(logger, path, nil)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.Equal(t, path, newPath)
}

func TestPolicyRejectOnlyPrefixSet(t *testing.T) {
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.1.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.1.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.1.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path1 := ProcessMessage(updateMsg, peer, time.Now())[0]

	peer = &PeerInfo{AS: 65002, Address: net.ParseIP("10.0.2.2")}
	origin = bgp.NewPathAttributeOrigin(0)
	aspathParam = []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65002})}
	aspath = bgp.NewPathAttributeAsPath(aspathParam)
	nexthop = bgp.NewPathAttributeNextHop("10.0.2.2")
	med = bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes = []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri = []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.9.2.102")}
	updateMsg = bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path2 := ProcessMessage(updateMsg, peer, time.Now())[0]

	// create policy
	ps := createPrefixSet("ps1", "10.10.1.0/16", "21..24")
	ds := oc.DefinedSets{}
	ds.PrefixSets = []oc.PrefixSet{ps}

	s := createStatement("statement1", "ps1", "", false)
	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	//test
	r := NewRoutingPolicy(logger)
	err := r.reload(pl)
	assert.Nil(t, err)
	p := r.policyMap["pd1"]
	pType, newPath := p.Apply(logger, path1, nil)
	assert.Equal(t, ROUTE_TYPE_REJECT, pType)
	assert.Equal(t, newPath, path1)

	pType2, newPath2 := p.Apply(logger, path2, nil)
	assert.Equal(t, ROUTE_TYPE_NONE, pType2)
	assert.Equal(t, newPath2, path2)
}

func TestPolicyRejectOnlyNeighborSet(t *testing.T) {
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.1.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.1.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.1.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path1 := ProcessMessage(updateMsg, peer, time.Now())[0]

	peer = &PeerInfo{AS: 65002, Address: net.ParseIP("10.0.2.2")}
	origin = bgp.NewPathAttributeOrigin(0)
	aspathParam = []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65002})}
	aspath = bgp.NewPathAttributeAsPath(aspathParam)
	nexthop = bgp.NewPathAttributeNextHop("10.0.2.2")
	med = bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes = []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri = []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.2.102")}
	updateMsg = bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path2 := ProcessMessage(updateMsg, peer, time.Now())[0]

	// create policy
	ns := createNeighborSet("ns1", "10.0.1.1")
	ds := oc.DefinedSets{}
	ds.NeighborSets = []oc.NeighborSet{ns}

	s := createStatement("statement1", "", "ns1", false)
	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	//test
	r := NewRoutingPolicy(logger)
	err := r.reload(pl)
	assert.Nil(t, err)
	pType, newPath := r.policyMap["pd1"].Apply(logger, path1, nil)
	assert.Equal(t, ROUTE_TYPE_REJECT, pType)
	assert.Equal(t, newPath, path1)

	pType2, newPath2 := r.policyMap["pd1"].Apply(logger, path2, nil)
	assert.Equal(t, ROUTE_TYPE_NONE, pType2)
	assert.Equal(t, newPath2, path2)
}

func TestPolicyDifferentRoutefamilyOfPathAndPolicy(t *testing.T) {
	// create path ipv4
	peerIPv4 := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	originIPv4 := bgp.NewPathAttributeOrigin(0)
	aspathParamIPv4 := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspathIPv4 := bgp.NewPathAttributeAsPath(aspathParamIPv4)
	nexthopIPv4 := bgp.NewPathAttributeNextHop("10.0.0.1")
	medIPv4 := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributesIPv4 := []bgp.PathAttributeInterface{originIPv4, aspathIPv4, nexthopIPv4, medIPv4}
	nlriIPv4 := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsgIPv4 := bgp.NewBGPUpdateMessage(nil, pathAttributesIPv4, nlriIPv4)
	pathIPv4 := ProcessMessage(updateMsgIPv4, peerIPv4, time.Now())[0]
	// create path ipv6
	peerIPv6 := &PeerInfo{AS: 65001, Address: net.ParseIP("2001::192:168:50:1")}
	originIPv6 := bgp.NewPathAttributeOrigin(0)
	aspathParamIPv6 := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspathIPv6 := bgp.NewPathAttributeAsPath(aspathParamIPv6)
	mpnlriIPv6 := []bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")}
	mpreachIPv6 := bgp.NewPathAttributeMpReachNLRI("2001::192:168:50:1", mpnlriIPv6)
	medIPv6 := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributesIPv6 := []bgp.PathAttributeInterface{mpreachIPv6, originIPv6, aspathIPv6, medIPv6}
	updateMsgIPv6 := bgp.NewBGPUpdateMessage(nil, pathAttributesIPv6, nil)
	pathIPv6 := ProcessMessage(updateMsgIPv6, peerIPv6, time.Now())[0]
	// create policy
	psIPv4 := createPrefixSet("psIPv4", "10.10.0.0/16", "21..24")
	nsIPv4 := createNeighborSet("nsIPv4", "10.0.0.1")

	psIPv6 := createPrefixSet("psIPv6", "2001:123:123::/48", "64..80")
	nsIPv6 := createNeighborSet("nsIPv6", "2001::192:168:50:1")

	ds := oc.DefinedSets{}
	ds.PrefixSets = []oc.PrefixSet{psIPv4, psIPv6}
	ds.NeighborSets = []oc.NeighborSet{nsIPv4, nsIPv6}

	stIPv4 := createStatement("statement1", "psIPv4", "nsIPv4", false)
	stIPv6 := createStatement("statement2", "psIPv6", "nsIPv6", false)

	pd := createPolicyDefinition("pd1", stIPv4, stIPv6)
	pl := createRoutingPolicy(ds, pd)

	//test
	r := NewRoutingPolicy(logger)
	err := r.reload(pl)
	assert.Nil(t, err)
	p := r.policyMap["pd1"]
	pType1, newPath1 := p.Apply(logger, pathIPv4, nil)
	assert.Equal(t, ROUTE_TYPE_REJECT, pType1)
	assert.Equal(t, newPath1, pathIPv4)

	pType2, newPath2 := p.Apply(logger, pathIPv6, nil)
	assert.Equal(t, ROUTE_TYPE_REJECT, pType2)
	assert.Equal(t, newPath2, pathIPv6)
}

func TestAsPathLengthConditionEvaluate(t *testing.T) {
	// setup
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(2, []uint16{65001, 65000, 65004, 65005}),
		bgp.NewAsPathParam(1, []uint16{65001, 65000, 65004, 65005}),
	}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	UpdatePathAttrs4ByteAs(logger, updateMsg.Body.(*bgp.BGPUpdate))
	path := ProcessMessage(updateMsg, peer, time.Now())[0]

	// create match condition
	asPathLength := oc.AsPathLength{
		Operator: "eq",
		Value:    5,
	}
	c, _ := NewAsPathLengthCondition(asPathLength)

	// test
	assert.Equal(t, true, c.Evaluate(path, nil))

	// create match condition
	asPathLength = oc.AsPathLength{
		Operator: "ge",
		Value:    3,
	}
	c, _ = NewAsPathLengthCondition(asPathLength)

	// test
	assert.Equal(t, true, c.Evaluate(path, nil))

	// create match condition
	asPathLength = oc.AsPathLength{
		Operator: "le",
		Value:    3,
	}
	c, _ = NewAsPathLengthCondition(asPathLength)

	// test
	assert.Equal(t, false, c.Evaluate(path, nil))
}

func TestPolicyMatchAndAcceptNextHop(t *testing.T) {
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := ProcessMessage(updateMsg, peer, time.Now())[0]

	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")
	ds := oc.DefinedSets{}
	ds.PrefixSets = []oc.PrefixSet{ps}
	ds.NeighborSets = []oc.NeighborSet{ns}
	s := createStatement("statement1", "ps1", "ns1", true)
	s.Conditions.BgpConditions.NextHopInList = []string{"10.0.0.1/32"}
	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	r := NewRoutingPolicy(logger)
	err := r.reload(pl)
	assert.Nil(t, err)
	pType, newPath := r.policyMap["pd1"].Apply(logger, path, nil)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.Equal(t, newPath, path)
}

func TestPolicyMatchAndRejectNextHop(t *testing.T) {
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := ProcessMessage(updateMsg, peer, time.Now())[0]

	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")
	ds := oc.DefinedSets{}
	ds.PrefixSets = []oc.PrefixSet{ps}
	ds.NeighborSets = []oc.NeighborSet{ns}
	s := createStatement("statement1", "ps1", "ns1", true)
	s.Conditions.BgpConditions.NextHopInList = []string{"10.0.0.12"}
	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	r := NewRoutingPolicy(logger)
	err := r.reload(pl)
	assert.Nil(t, err)
	pType, newPath := r.policyMap["pd1"].Apply(logger, path, nil)
	assert.Equal(t, ROUTE_TYPE_NONE, pType)
	assert.Equal(t, newPath, path)
}

func TestAsPathLengthConditionWithOtherCondition(t *testing.T) {
	// setup
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(2, []uint16{65001, 65000, 65004, 65004, 65005}),
		bgp.NewAsPathParam(1, []uint16{65001, 65000, 65004, 65005}),
	}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	UpdatePathAttrs4ByteAs(logger, updateMsg.Body.(*bgp.BGPUpdate))
	path := ProcessMessage(updateMsg, peer, time.Now())[0]

	// create policy
	ps := createPrefixSet("ps1", "10.10.1.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := oc.DefinedSets{}
	ds.PrefixSets = []oc.PrefixSet{ps}
	ds.NeighborSets = []oc.NeighborSet{ns}

	// create match condition
	asPathLength := oc.AsPathLength{
		Operator: "le",
		Value:    10,
	}

	s := createStatement("statement1", "ps1", "ns1", false)
	s.Conditions.BgpConditions.AsPathLength = asPathLength
	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	//test
	r := NewRoutingPolicy(logger)
	err := r.reload(pl)
	assert.Nil(t, err)
	p := r.policyMap["pd1"]
	pType, newPath := p.Apply(logger, path, nil)
	assert.Equal(t, ROUTE_TYPE_REJECT, pType)
	assert.Equal(t, newPath, path)

}

func TestAs4PathLengthConditionEvaluate(t *testing.T) {
	// setup
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{
		bgp.NewAs4PathParam(2, []uint32{
			createAs4Value("65001.1"),
			createAs4Value("65000.1"),
			createAs4Value("65004.1"),
			createAs4Value("65005.1"),
		}),
		bgp.NewAs4PathParam(1, []uint32{
			createAs4Value("65001.1"),
			createAs4Value("65000.1"),
			createAs4Value("65004.1"),
			createAs4Value("65005.1"),
		}),
	}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	UpdatePathAttrs4ByteAs(logger, updateMsg.Body.(*bgp.BGPUpdate))
	path := ProcessMessage(updateMsg, peer, time.Now())[0]

	// create match condition
	asPathLength := oc.AsPathLength{
		Operator: "eq",
		Value:    5,
	}
	c, _ := NewAsPathLengthCondition(asPathLength)

	// test
	assert.Equal(t, true, c.Evaluate(path, nil))

	// create match condition
	asPathLength = oc.AsPathLength{
		Operator: "ge",
		Value:    3,
	}
	c, _ = NewAsPathLengthCondition(asPathLength)

	// test
	assert.Equal(t, true, c.Evaluate(path, nil))

	// create match condition
	asPathLength = oc.AsPathLength{
		Operator: "le",
		Value:    3,
	}
	c, _ = NewAsPathLengthCondition(asPathLength)

	// test
	assert.Equal(t, false, c.Evaluate(path, nil))
}

func addPolicy(r *RoutingPolicy, x *Policy) {
	for _, s := range x.Statements {
		for _, c := range s.Conditions {
			r.validateCondition(c)
		}
	}
}

func TestAs4PathLengthConditionWithOtherCondition(t *testing.T) {
	// setup
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{
		bgp.NewAs4PathParam(2, []uint32{
			createAs4Value("65001.1"),
			createAs4Value("65000.1"),
			createAs4Value("65004.1"),
			createAs4Value("65004.1"),
			createAs4Value("65005.1"),
		}),
		bgp.NewAs4PathParam(1, []uint32{
			createAs4Value("65001.1"),
			createAs4Value("65000.1"),
			createAs4Value("65004.1"),
			createAs4Value("65005.1"),
		}),
	}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	UpdatePathAttrs4ByteAs(logger, updateMsg.Body.(*bgp.BGPUpdate))
	path := ProcessMessage(updateMsg, peer, time.Now())[0]

	// create policy
	ps := createPrefixSet("ps1", "10.10.1.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := oc.DefinedSets{}
	ds.PrefixSets = []oc.PrefixSet{ps}
	ds.NeighborSets = []oc.NeighborSet{ns}

	// create match condition
	asPathLength := oc.AsPathLength{
		Operator: "le",
		Value:    10,
	}

	s := createStatement("statement1", "ps1", "ns1", false)
	s.Conditions.BgpConditions.AsPathLength = asPathLength
	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	//test
	r := NewRoutingPolicy(logger)
	r.reload(pl)
	p, _ := NewPolicy(pl.PolicyDefinitions[0])
	addPolicy(r, p)
	pType, newPath := p.Apply(logger, path, nil)
	assert.Equal(t, ROUTE_TYPE_REJECT, pType)
	assert.Equal(t, newPath, path)

}

func TestAsPathConditionEvaluate(t *testing.T) {

	// setup
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam1 := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(2, []uint16{65001, 65000, 65010, 65004, 65005}),
	}
	aspath := bgp.NewPathAttributeAsPath(aspathParam1)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg1 := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	UpdatePathAttrs4ByteAs(logger, updateMsg1.Body.(*bgp.BGPUpdate))
	path1 := ProcessMessage(updateMsg1, peer, time.Now())[0]

	aspathParam2 := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(2, []uint16{65010}),
	}
	aspath2 := bgp.NewPathAttributeAsPath(aspathParam2)
	pathAttributes = []bgp.PathAttributeInterface{origin, aspath2, nexthop, med}
	updateMsg2 := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	UpdatePathAttrs4ByteAs(logger, updateMsg2.Body.(*bgp.BGPUpdate))
	path2 := ProcessMessage(updateMsg2, peer, time.Now())[0]

	// create match condition
	asPathSet1 := oc.AsPathSet{
		AsPathSetName: "asset1",
		AsPathList:    []string{"^65001"},
	}

	asPathSet2 := oc.AsPathSet{
		AsPathSetName: "asset2",
		AsPathList:    []string{"65005$"},
	}

	asPathSet3 := oc.AsPathSet{
		AsPathSetName: "asset3",
		AsPathList:    []string{"65004", "65005$"},
	}

	asPathSet4 := oc.AsPathSet{
		AsPathSetName: "asset4",
		AsPathList:    []string{"65000$"},
	}

	asPathSet5 := oc.AsPathSet{
		AsPathSetName: "asset5",
		AsPathList:    []string{"65010"},
	}

	asPathSet6 := oc.AsPathSet{
		AsPathSetName: "asset6",
		AsPathList:    []string{"^65010$"},
	}

	m := make(map[string]DefinedSet)
	for _, s := range []oc.AsPathSet{asPathSet1, asPathSet2, asPathSet3,
		asPathSet4, asPathSet5, asPathSet6} {
		a, _ := NewAsPathSet(s)
		m[s.AsPathSetName] = a
	}

	createAspathC := func(name string, option oc.MatchSetOptionsType) *AsPathCondition {
		matchSet := oc.MatchAsPathSet{}
		matchSet.AsPathSet = name
		matchSet.MatchSetOptions = option
		p, _ := NewAsPathCondition(matchSet)
		if v, ok := m[name]; ok {
			p.set = v.(*AsPathSet)
		}
		return p
	}

	p1 := createAspathC("asset1", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p2 := createAspathC("asset2", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p3 := createAspathC("asset3", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p4 := createAspathC("asset4", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p5 := createAspathC("asset5", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p6 := createAspathC("asset6", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p7 := createAspathC("asset3", oc.MATCH_SET_OPTIONS_TYPE_ALL)
	p8 := createAspathC("asset3", oc.MATCH_SET_OPTIONS_TYPE_INVERT)

	// test
	assert.Equal(t, true, p1.Evaluate(path1, nil))
	assert.Equal(t, true, p2.Evaluate(path1, nil))
	assert.Equal(t, true, p3.Evaluate(path1, nil))
	assert.Equal(t, false, p4.Evaluate(path1, nil))
	assert.Equal(t, true, p5.Evaluate(path1, nil))
	assert.Equal(t, false, p6.Evaluate(path1, nil))
	assert.Equal(t, true, p6.Evaluate(path2, nil))
	assert.Equal(t, true, p7.Evaluate(path1, nil))
	assert.Equal(t, true, p8.Evaluate(path2, nil))
}

func TestMultipleAsPathConditionEvaluate(t *testing.T) {

	// setup
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam1 := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(2, []uint16{65001, 65000, 54000, 65004, 65005}),
	}
	aspath := bgp.NewPathAttributeAsPath(aspathParam1)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg1 := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	UpdatePathAttrs4ByteAs(logger, updateMsg1.Body.(*bgp.BGPUpdate))
	path1 := ProcessMessage(updateMsg1, peer, time.Now())[0]

	// create match condition
	asPathSet1 := oc.AsPathSet{
		AsPathSetName: "asset1",
		AsPathList:    []string{"^65001_65000"},
	}

	asPathSet2 := oc.AsPathSet{
		AsPathSetName: "asset2",
		AsPathList:    []string{"65004_65005$"},
	}

	asPathSet3 := oc.AsPathSet{
		AsPathSetName: "asset3",
		AsPathList:    []string{"65001_65000_54000"},
	}

	asPathSet4 := oc.AsPathSet{
		AsPathSetName: "asset4",
		AsPathList:    []string{"54000_65004_65005"},
	}

	asPathSet5 := oc.AsPathSet{
		AsPathSetName: "asset5",
		AsPathList:    []string{"^65001 65000 54000 65004 65005$"},
	}

	asPathSet6 := oc.AsPathSet{
		AsPathSetName: "asset6",
		AsPathList:    []string{".*_[0-9]+_65005"},
	}

	asPathSet7 := oc.AsPathSet{
		AsPathSetName: "asset7",
		AsPathList:    []string{".*_5[0-9]+_[0-9]+"},
	}

	asPathSet8 := oc.AsPathSet{
		AsPathSetName: "asset8",
		AsPathList:    []string{"6[0-9]+_6[0-9]+_5[0-9]+"},
	}

	asPathSet9 := oc.AsPathSet{
		AsPathSetName: "asset9",
		AsPathList:    []string{"6[0-9]+__6[0-9]+"},
	}

	m := make(map[string]DefinedSet)
	for _, s := range []oc.AsPathSet{asPathSet1, asPathSet2, asPathSet3,
		asPathSet4, asPathSet5, asPathSet6, asPathSet7, asPathSet8, asPathSet9} {
		a, _ := NewAsPathSet(s)
		m[s.AsPathSetName] = a
	}

	createAspathC := func(name string, option oc.MatchSetOptionsType) *AsPathCondition {
		matchSet := oc.MatchAsPathSet{}
		matchSet.AsPathSet = name
		matchSet.MatchSetOptions = option
		p, _ := NewAsPathCondition(matchSet)
		if v, ok := m[name]; ok {
			p.set = v.(*AsPathSet)
		}
		return p
	}

	p1 := createAspathC("asset1", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p2 := createAspathC("asset2", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p3 := createAspathC("asset3", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p4 := createAspathC("asset4", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p5 := createAspathC("asset5", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p6 := createAspathC("asset6", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p7 := createAspathC("asset7", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p8 := createAspathC("asset8", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p9 := createAspathC("asset9", oc.MATCH_SET_OPTIONS_TYPE_ANY)

	// test
	assert.Equal(t, true, p1.Evaluate(path1, nil))
	assert.Equal(t, true, p2.Evaluate(path1, nil))
	assert.Equal(t, true, p3.Evaluate(path1, nil))
	assert.Equal(t, true, p4.Evaluate(path1, nil))
	assert.Equal(t, true, p5.Evaluate(path1, nil))
	assert.Equal(t, true, p6.Evaluate(path1, nil))
	assert.Equal(t, true, p7.Evaluate(path1, nil))
	assert.Equal(t, true, p8.Evaluate(path1, nil))
	assert.Equal(t, false, p9.Evaluate(path1, nil))
}

func TestAsPathCondition(t *testing.T) {
	type astest struct {
		path   *Path
		result bool
	}

	makeTest := func(asPathAttrType uint8, ases []uint32, result bool) astest {
		aspathParam := []bgp.AsPathParamInterface{
			bgp.NewAs4PathParam(asPathAttrType, ases),
		}
		pathAttributes := []bgp.PathAttributeInterface{bgp.NewPathAttributeAsPath(aspathParam)}
		p := NewPath(nil, nil, false, pathAttributes, time.Time{}, false)
		return astest{
			path:   p,
			result: result,
		}
	}

	tests := make(map[string][]astest)

	tests["^(100_)+(200_)+$"] = []astest{
		makeTest(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{100, 200}, true),
		makeTest(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{100, 100, 200}, true),
		makeTest(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{100, 100, 200, 200}, true),
		makeTest(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{100, 100, 200, 200, 300}, false),
	}

	aslen255 := func() []uint32 {
		r := make([]uint32, 255)
		for i := 0; i < 255; i++ {
			r[i] = 1
		}
		return r
	}()
	tests["^([0-9]+_){0,255}$"] = []astest{
		makeTest(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, aslen255, true),
		makeTest(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, append(aslen255, 1), false),
	}

	tests["(_7521)$"] = []astest{
		makeTest(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{7521}, true),
		makeTest(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{1000, 7521}, true),
		makeTest(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{7521, 1000}, false),
		makeTest(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{1000, 7521, 100}, false),
	}

	tests["^65001( |_.*_)65535$"] = []astest{
		makeTest(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001, 65535}, true),
		makeTest(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001, 65001, 65535}, true),
		makeTest(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001, 65002, 65003, 65535}, true),
		makeTest(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001, 65534}, false),
		makeTest(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65002, 65535}, false),
		makeTest(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65002, 65001, 65535}, false),
		makeTest(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001, 65535, 65002}, false),
		makeTest(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{650019, 65535}, false),
		makeTest(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001, 165535}, false),
	}

	for k, v := range tests {
		s, _ := NewAsPathSet(oc.AsPathSet{
			AsPathSetName: k,
			AsPathList:    []string{k},
		})
		c, _ := NewAsPathCondition(oc.MatchAsPathSet{
			AsPathSet:       k,
			MatchSetOptions: oc.MATCH_SET_OPTIONS_TYPE_ANY,
		})
		c.set = s
		for _, a := range v {
			result := c.Evaluate(a.path, nil)
			if a.result != result {
				t.Logf("failed: EXP: %v, ASSTR: %v, Expected: %v, Result: %v",
					k,
					a.path.GetAsString(),
					a.result,
					result)
			}
		}
	}
}

func TestAsPathConditionWithOtherCondition(t *testing.T) {

	// setup
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(1, []uint16{65001, 65000, 65004, 65005}),
		bgp.NewAsPathParam(2, []uint16{65001, 65000, 65004, 65004, 65005}),
	}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	UpdatePathAttrs4ByteAs(logger, updateMsg.Body.(*bgp.BGPUpdate))
	path := ProcessMessage(updateMsg, peer, time.Now())[0]

	// create policy
	asPathSet := oc.AsPathSet{
		AsPathSetName: "asset1",
		AsPathList:    []string{"65005$"},
	}

	ps := createPrefixSet("ps1", "10.10.1.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := oc.DefinedSets{}
	ds.PrefixSets = []oc.PrefixSet{ps}
	ds.NeighborSets = []oc.NeighborSet{ns}
	ds.BgpDefinedSets.AsPathSets = []oc.AsPathSet{asPathSet}

	s := createStatement("statement1", "ps1", "ns1", false)
	s.Conditions.BgpConditions.MatchAsPathSet.AsPathSet = "asset1"

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	//test
	r := NewRoutingPolicy(logger)
	err := r.reload(pl)
	assert.Nil(t, err)
	p := r.policyMap["pd1"]
	pType, newPath := p.Apply(logger, path, nil)
	assert.Equal(t, ROUTE_TYPE_REJECT, pType)
	assert.Equal(t, newPath, path)

}

func TestAs4PathConditionEvaluate(t *testing.T) {

	// setup
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam1 := []bgp.AsPathParamInterface{
		bgp.NewAs4PathParam(2, []uint32{
			createAs4Value("65001.1"),
			createAs4Value("65000.1"),
			createAs4Value("65010.1"),
			createAs4Value("65004.1"),
			createAs4Value("65005.1"),
		})}

	aspath := bgp.NewPathAttributeAsPath(aspathParam1)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg1 := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	UpdatePathAttrs4ByteAs(logger, updateMsg1.Body.(*bgp.BGPUpdate))
	path1 := ProcessMessage(updateMsg1, peer, time.Now())[0]

	aspathParam2 := []bgp.AsPathParamInterface{
		bgp.NewAs4PathParam(2, []uint32{
			createAs4Value("65010.1"),
		}),
	}
	aspath2 := bgp.NewPathAttributeAsPath(aspathParam2)
	pathAttributes = []bgp.PathAttributeInterface{origin, aspath2, nexthop, med}
	updateMsg2 := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	UpdatePathAttrs4ByteAs(logger, updateMsg2.Body.(*bgp.BGPUpdate))
	path2 := ProcessMessage(updateMsg2, peer, time.Now())[0]

	// create match condition
	asPathSet1 := oc.AsPathSet{
		AsPathSetName: "asset1",
		AsPathList:    []string{fmt.Sprintf("^%d", createAs4Value("65001.1"))},
	}

	asPathSet2 := oc.AsPathSet{
		AsPathSetName: "asset2",
		AsPathList:    []string{fmt.Sprintf("%d$", createAs4Value("65005.1"))},
	}

	asPathSet3 := oc.AsPathSet{
		AsPathSetName: "asset3",
		AsPathList: []string{
			fmt.Sprintf("%d", createAs4Value("65004.1")),
			fmt.Sprintf("%d$", createAs4Value("65005.1")),
		},
	}

	asPathSet4 := oc.AsPathSet{
		AsPathSetName: "asset4",
		AsPathList: []string{
			fmt.Sprintf("%d$", createAs4Value("65000.1")),
		},
	}

	asPathSet5 := oc.AsPathSet{
		AsPathSetName: "asset5",
		AsPathList: []string{
			fmt.Sprintf("%d", createAs4Value("65010.1")),
		},
	}

	asPathSet6 := oc.AsPathSet{
		AsPathSetName: "asset6",
		AsPathList: []string{
			fmt.Sprintf("%d$", createAs4Value("65010.1")),
		},
	}

	m := make(map[string]DefinedSet)
	for _, s := range []oc.AsPathSet{asPathSet1, asPathSet2, asPathSet3,
		asPathSet4, asPathSet5, asPathSet6} {
		a, _ := NewAsPathSet(s)
		m[s.AsPathSetName] = a
	}

	createAspathC := func(name string, option oc.MatchSetOptionsType) *AsPathCondition {
		matchSet := oc.MatchAsPathSet{}
		matchSet.AsPathSet = name
		matchSet.MatchSetOptions = option
		p, _ := NewAsPathCondition(matchSet)
		if v, ok := m[name]; ok {
			p.set = v.(*AsPathSet)
		}
		return p
	}

	p1 := createAspathC("asset1", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p2 := createAspathC("asset2", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p3 := createAspathC("asset3", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p4 := createAspathC("asset4", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p5 := createAspathC("asset5", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p6 := createAspathC("asset6", oc.MATCH_SET_OPTIONS_TYPE_ANY)

	p7 := createAspathC("asset3", oc.MATCH_SET_OPTIONS_TYPE_ALL)
	p8 := createAspathC("asset3", oc.MATCH_SET_OPTIONS_TYPE_INVERT)

	// test
	assert.Equal(t, true, p1.Evaluate(path1, nil))
	assert.Equal(t, true, p2.Evaluate(path1, nil))
	assert.Equal(t, true, p3.Evaluate(path1, nil))
	assert.Equal(t, false, p4.Evaluate(path1, nil))
	assert.Equal(t, true, p5.Evaluate(path1, nil))
	assert.Equal(t, false, p6.Evaluate(path1, nil))
	assert.Equal(t, true, p6.Evaluate(path2, nil))

	assert.Equal(t, true, p7.Evaluate(path1, nil))
	assert.Equal(t, true, p8.Evaluate(path2, nil))
}

func TestMultipleAs4PathConditionEvaluate(t *testing.T) {

	// setup
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam1 := []bgp.AsPathParamInterface{
		bgp.NewAs4PathParam(2, []uint32{
			createAs4Value("65001.1"),
			createAs4Value("65000.1"),
			createAs4Value("54000.1"),
			createAs4Value("65004.1"),
			createAs4Value("65005.1"),
		}),
	}

	aspath := bgp.NewPathAttributeAsPath(aspathParam1)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg1 := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	UpdatePathAttrs4ByteAs(logger, updateMsg1.Body.(*bgp.BGPUpdate))
	path1 := ProcessMessage(updateMsg1, peer, time.Now())[0]

	// create match condition
	asPathSet1 := oc.AsPathSet{
		AsPathSetName: "asset1",
		AsPathList: []string{
			fmt.Sprintf("^%d_%d", createAs4Value("65001.1"), createAs4Value("65000.1")),
		},
	}

	asPathSet2 := oc.AsPathSet{
		AsPathSetName: "asset2",
		AsPathList: []string{
			fmt.Sprintf("%d_%d$", createAs4Value("65004.1"), createAs4Value("65005.1")),
		},
	}

	asPathSet3 := oc.AsPathSet{
		AsPathSetName: "asset3",
		AsPathList: []string{
			fmt.Sprintf("%d_%d_%d", createAs4Value("65001.1"), createAs4Value("65000.1"), createAs4Value("54000.1")),
		},
	}

	asPathSet4 := oc.AsPathSet{
		AsPathSetName: "asset4",
		AsPathList: []string{
			fmt.Sprintf("%d_%d_%d", createAs4Value("54000.1"), createAs4Value("65004.1"), createAs4Value("65005.1")),
		},
	}

	asPathSet5 := oc.AsPathSet{
		AsPathSetName: "asset5",
		AsPathList: []string{
			fmt.Sprintf("^%d %d %d %d %d$", createAs4Value("65001.1"), createAs4Value("65000.1"), createAs4Value("54000.1"), createAs4Value("65004.1"), createAs4Value("65005.1")),
		},
	}

	asPathSet6 := oc.AsPathSet{
		AsPathSetName: "asset6",
		AsPathList: []string{
			fmt.Sprintf(".*_[0-9]+_%d", createAs4Value("65005.1")),
		},
	}

	asPathSet7 := oc.AsPathSet{
		AsPathSetName: "asset7",
		AsPathList:    []string{".*_3[0-9]+_[0-9]+"},
	}

	asPathSet8 := oc.AsPathSet{
		AsPathSetName: "asset8",
		AsPathList:    []string{"4[0-9]+_4[0-9]+_3[0-9]+"},
	}

	asPathSet9 := oc.AsPathSet{
		AsPathSetName: "asset9",
		AsPathList:    []string{"4[0-9]+__4[0-9]+"},
	}

	m := make(map[string]DefinedSet)
	for _, s := range []oc.AsPathSet{asPathSet1, asPathSet2, asPathSet3,
		asPathSet4, asPathSet5, asPathSet6, asPathSet7, asPathSet8, asPathSet9} {
		a, _ := NewAsPathSet(s)
		m[s.AsPathSetName] = a
	}

	createAspathC := func(name string, option oc.MatchSetOptionsType) *AsPathCondition {
		matchSet := oc.MatchAsPathSet{}
		matchSet.AsPathSet = name
		matchSet.MatchSetOptions = option
		p, _ := NewAsPathCondition(matchSet)
		if v, ok := m[name]; ok {
			p.set = v.(*AsPathSet)
		}
		return p
	}

	p1 := createAspathC("asset1", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p2 := createAspathC("asset2", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p3 := createAspathC("asset3", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p4 := createAspathC("asset4", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p5 := createAspathC("asset5", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p6 := createAspathC("asset6", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p7 := createAspathC("asset7", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p8 := createAspathC("asset8", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p9 := createAspathC("asset9", oc.MATCH_SET_OPTIONS_TYPE_ANY)

	// test
	assert.Equal(t, true, p1.Evaluate(path1, nil))
	assert.Equal(t, true, p2.Evaluate(path1, nil))
	assert.Equal(t, true, p3.Evaluate(path1, nil))
	assert.Equal(t, true, p4.Evaluate(path1, nil))
	assert.Equal(t, true, p5.Evaluate(path1, nil))
	assert.Equal(t, true, p6.Evaluate(path1, nil))
	assert.Equal(t, true, p7.Evaluate(path1, nil))
	assert.Equal(t, true, p8.Evaluate(path1, nil))
	assert.Equal(t, false, p9.Evaluate(path1, nil))
}

func TestAs4PathConditionWithOtherCondition(t *testing.T) {

	// setup
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{
		bgp.NewAs4PathParam(1, []uint32{
			createAs4Value("65001.1"),
			createAs4Value("65000.1"),
			createAs4Value("65004.1"),
			createAs4Value("65005.1"),
		}),
		bgp.NewAs4PathParam(2, []uint32{
			createAs4Value("65001.1"),
			createAs4Value("65000.1"),
			createAs4Value("65004.1"),
			createAs4Value("65004.1"),
			createAs4Value("65005.1"),
		}),
	}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	UpdatePathAttrs4ByteAs(logger, updateMsg.Body.(*bgp.BGPUpdate))
	path := ProcessMessage(updateMsg, peer, time.Now())[0]

	// create policy
	asPathSet := oc.AsPathSet{
		AsPathSetName: "asset1",
		AsPathList:    []string{fmt.Sprintf("%d$", createAs4Value("65005.1"))},
	}

	ps := createPrefixSet("ps1", "10.10.1.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := oc.DefinedSets{}
	ds.PrefixSets = []oc.PrefixSet{ps}
	ds.NeighborSets = []oc.NeighborSet{ns}
	ds.BgpDefinedSets.AsPathSets = []oc.AsPathSet{asPathSet}

	s := createStatement("statement1", "ps1", "ns1", false)
	s.Conditions.BgpConditions.MatchAsPathSet.AsPathSet = "asset1"

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	//test
	r := NewRoutingPolicy(logger)
	r.reload(pl)
	p, _ := NewPolicy(pl.PolicyDefinitions[0])
	addPolicy(r, p)
	pType, newPath := p.Apply(logger, path, nil)
	assert.Equal(t, ROUTE_TYPE_REJECT, pType)
	assert.Equal(t, newPath, path)

}

func TestAs4PathConditionEvaluateMixedWith2byteAS(t *testing.T) {

	// setup
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam1 := []bgp.AsPathParamInterface{
		bgp.NewAs4PathParam(2, []uint32{
			createAs4Value("65001.1"),
			createAs4Value("65000.1"),
			createAs4Value("54000.1"),
			100,
			5000,
			createAs4Value("65004.1"),
			createAs4Value("65005.1"),
			4000,
		}),
	}

	aspath := bgp.NewPathAttributeAsPath(aspathParam1)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg1 := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	UpdatePathAttrs4ByteAs(logger, updateMsg1.Body.(*bgp.BGPUpdate))
	path1 := ProcessMessage(updateMsg1, peer, time.Now())[0]

	// create match condition
	asPathSet1 := oc.AsPathSet{
		AsPathSetName: "asset1",
		AsPathList:    []string{fmt.Sprintf("^%d", createAs4Value("65001.1"))},
	}

	asPathSet2 := oc.AsPathSet{
		AsPathSetName: "asset2",
		AsPathList:    []string{"4000$"},
	}

	asPathSet3 := oc.AsPathSet{
		AsPathSetName: "asset3",
		AsPathList:    []string{fmt.Sprintf("%d", createAs4Value("65004.1")), "4000$"},
	}

	asPathSet4 := oc.AsPathSet{
		AsPathSetName: "asset4",
		AsPathList:    []string{fmt.Sprintf("%d_%d_%d", createAs4Value("54000.1"), 100, 5000)},
	}

	asPathSet5 := oc.AsPathSet{
		AsPathSetName: "asset5",
		AsPathList:    []string{".*_[0-9]+_100"},
	}

	asPathSet6 := oc.AsPathSet{
		AsPathSetName: "asset6",
		AsPathList:    []string{".*_3[0-9]+_[0]+"},
	}

	asPathSet7 := oc.AsPathSet{
		AsPathSetName: "asset7",
		AsPathList:    []string{".*_3[0-9]+_[1]+"},
	}

	m := make(map[string]DefinedSet)
	for _, s := range []oc.AsPathSet{asPathSet1, asPathSet2, asPathSet3,
		asPathSet4, asPathSet5, asPathSet6, asPathSet7} {
		a, _ := NewAsPathSet(s)
		m[s.AsPathSetName] = a
	}

	createAspathC := func(name string, option oc.MatchSetOptionsType) *AsPathCondition {
		matchSet := oc.MatchAsPathSet{}
		matchSet.AsPathSet = name
		matchSet.MatchSetOptions = option
		p, _ := NewAsPathCondition(matchSet)
		if v, ok := m[name]; ok {
			p.set = v.(*AsPathSet)
		}
		return p
	}

	p1 := createAspathC("asset1", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p2 := createAspathC("asset2", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p3 := createAspathC("asset3", oc.MATCH_SET_OPTIONS_TYPE_ALL)
	p4 := createAspathC("asset4", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p5 := createAspathC("asset5", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p6 := createAspathC("asset6", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p7 := createAspathC("asset7", oc.MATCH_SET_OPTIONS_TYPE_ANY)

	// test
	assert.Equal(t, true, p1.Evaluate(path1, nil))
	assert.Equal(t, true, p2.Evaluate(path1, nil))
	assert.Equal(t, true, p3.Evaluate(path1, nil))
	assert.Equal(t, true, p4.Evaluate(path1, nil))
	assert.Equal(t, true, p5.Evaluate(path1, nil))
	assert.Equal(t, false, p6.Evaluate(path1, nil))
	assert.Equal(t, true, p7.Evaluate(path1, nil))

}

func TestCommunityConditionEvaluate(t *testing.T) {

	// setup
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam1 := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(2, []uint16{65001, 65000, 65004, 65005}),
		bgp.NewAsPathParam(1, []uint16{65001, 65010, 65004, 65005}),
	}
	aspath := bgp.NewPathAttributeAsPath(aspathParam1)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	communities := bgp.NewPathAttributeCommunities([]uint32{
		stringToCommunityValue("65001:100"),
		stringToCommunityValue("65001:200"),
		stringToCommunityValue("65001:300"),
		stringToCommunityValue("65001:400"),
		0x00000000,
		0xFFFFFF01,
		0xFFFFFF02,
		0xFFFFFF03})

	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med, communities}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg1 := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	UpdatePathAttrs4ByteAs(logger, updateMsg1.Body.(*bgp.BGPUpdate))
	path1 := ProcessMessage(updateMsg1, peer, time.Now())[0]

	communities2 := bgp.NewPathAttributeCommunities([]uint32{
		stringToCommunityValue("65001:100"),
		stringToCommunityValue("65001:200"),
		stringToCommunityValue("65001:300"),
		stringToCommunityValue("65001:400")})

	pathAttributes2 := []bgp.PathAttributeInterface{origin, aspath, nexthop, med, communities2}
	updateMsg2 := bgp.NewBGPUpdateMessage(nil, pathAttributes2, nlri)
	UpdatePathAttrs4ByteAs(logger, updateMsg2.Body.(*bgp.BGPUpdate))
	path2 := ProcessMessage(updateMsg2, peer, time.Now())[0]

	// create match condition
	comSet1 := oc.CommunitySet{
		CommunitySetName: "comset1",
		CommunityList:    []string{"65001:10", "65001:50", "65001:100"},
	}

	comSet2 := oc.CommunitySet{
		CommunitySetName: "comset2",
		CommunityList:    []string{"65001:200"},
	}

	comSet3 := oc.CommunitySet{
		CommunitySetName: "comset3",
		CommunityList:    []string{"4259905936"},
	}

	comSet4 := oc.CommunitySet{
		CommunitySetName: "comset4",
		CommunityList:    []string{"^[0-9]*:300$"},
	}

	comSet5 := oc.CommunitySet{
		CommunitySetName: "comset5",
		CommunityList:    []string{"INTERNET"},
	}

	comSet6 := oc.CommunitySet{
		CommunitySetName: "comset6",
		CommunityList:    []string{"NO_EXPORT"},
	}

	comSet7 := oc.CommunitySet{
		CommunitySetName: "comset7",
		CommunityList:    []string{"NO_ADVERTISE"},
	}

	comSet8 := oc.CommunitySet{
		CommunitySetName: "comset8",
		CommunityList:    []string{"NO_EXPORT_SUBCONFED"},
	}

	comSet9 := oc.CommunitySet{
		CommunitySetName: "comset9",
		CommunityList: []string{
			"65001:\\d+",
			"\\d+:\\d00",
		},
	}

	comSet10 := oc.CommunitySet{
		CommunitySetName: "comset10",
		CommunityList: []string{
			"65001:1",
			"65001:2",
			"65001:3",
		},
	}

	m := make(map[string]DefinedSet)

	for _, c := range []oc.CommunitySet{comSet1, comSet2, comSet3,
		comSet4, comSet5, comSet6, comSet7, comSet8, comSet9, comSet10} {
		s, _ := NewCommunitySet(c)
		m[c.CommunitySetName] = s
	}

	createCommunityC := func(name string, option oc.MatchSetOptionsType) *CommunityCondition {
		matchSet := oc.MatchCommunitySet{}
		matchSet.CommunitySet = name
		matchSet.MatchSetOptions = option
		c, _ := NewCommunityCondition(matchSet)
		if v, ok := m[name]; ok {
			c.set = v.(*CommunitySet)
		}
		return c
	}

	// ANY case
	p1 := createCommunityC("comset1", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p2 := createCommunityC("comset2", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p3 := createCommunityC("comset3", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p4 := createCommunityC("comset4", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p5 := createCommunityC("comset5", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p6 := createCommunityC("comset6", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p7 := createCommunityC("comset7", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p8 := createCommunityC("comset8", oc.MATCH_SET_OPTIONS_TYPE_ANY)

	// ALL case
	p9 := createCommunityC("comset9", oc.MATCH_SET_OPTIONS_TYPE_ALL)

	// INVERT case
	p10 := createCommunityC("comset10", oc.MATCH_SET_OPTIONS_TYPE_INVERT)

	// test
	assert.Equal(t, true, p1.Evaluate(path1, nil))
	assert.Equal(t, true, p2.Evaluate(path1, nil))
	assert.Equal(t, true, p3.Evaluate(path1, nil))
	assert.Equal(t, true, p4.Evaluate(path1, nil))
	assert.Equal(t, true, p5.Evaluate(path1, nil))
	assert.Equal(t, true, p6.Evaluate(path1, nil))
	assert.Equal(t, true, p7.Evaluate(path1, nil))
	assert.Equal(t, true, p8.Evaluate(path1, nil))
	assert.Equal(t, true, p9.Evaluate(path2, nil))
	assert.Equal(t, true, p10.Evaluate(path1, nil))

}

func TestCommunityConditionEvaluateWithOtherCondition(t *testing.T) {

	// setup
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(1, []uint16{65001, 65000, 65004, 65005}),
		bgp.NewAsPathParam(2, []uint16{65001, 65000, 65004, 65004, 65005}),
	}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	communities := bgp.NewPathAttributeCommunities([]uint32{
		stringToCommunityValue("65001:100"),
		stringToCommunityValue("65001:200"),
		stringToCommunityValue("65001:300"),
		stringToCommunityValue("65001:400"),
		0x00000000,
		0xFFFFFF01,
		0xFFFFFF02,
		0xFFFFFF03})
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med, communities}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	UpdatePathAttrs4ByteAs(logger, updateMsg.Body.(*bgp.BGPUpdate))
	path := ProcessMessage(updateMsg, peer, time.Now())[0]

	// create policy
	asPathSet := oc.AsPathSet{
		AsPathSetName: "asset1",
		AsPathList:    []string{"65005$"},
	}

	comSet1 := oc.CommunitySet{
		CommunitySetName: "comset1",
		CommunityList:    []string{"65001:100", "65001:200", "65001:300"},
	}

	comSet2 := oc.CommunitySet{
		CommunitySetName: "comset2",
		CommunityList:    []string{"65050:\\d+"},
	}

	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := oc.DefinedSets{}
	ds.PrefixSets = []oc.PrefixSet{ps}
	ds.NeighborSets = []oc.NeighborSet{ns}
	ds.BgpDefinedSets.AsPathSets = []oc.AsPathSet{asPathSet}
	ds.BgpDefinedSets.CommunitySets = []oc.CommunitySet{comSet1, comSet2}

	s1 := createStatement("statement1", "ps1", "ns1", false)
	s1.Conditions.BgpConditions.MatchAsPathSet.AsPathSet = "asset1"
	s1.Conditions.BgpConditions.MatchCommunitySet.CommunitySet = "comset1"

	s2 := createStatement("statement2", "ps1", "ns1", false)
	s2.Conditions.BgpConditions.MatchAsPathSet.AsPathSet = "asset1"
	s2.Conditions.BgpConditions.MatchCommunitySet.CommunitySet = "comset2"

	pd1 := createPolicyDefinition("pd1", s1)
	pd2 := createPolicyDefinition("pd2", s2)
	pl := createRoutingPolicy(ds, pd1, pd2)

	//test
	r := NewRoutingPolicy(logger)
	err := r.reload(pl)
	assert.Nil(t, err)
	p := r.policyMap["pd1"]
	pType, newPath := p.Apply(logger, path, nil)
	assert.Equal(t, ROUTE_TYPE_REJECT, pType)
	assert.Equal(t, newPath, path)

	p = r.policyMap["pd2"]
	pType, newPath = p.Apply(logger, path, nil)
	assert.Equal(t, ROUTE_TYPE_NONE, pType)
	assert.Equal(t, newPath, path)

}

func TestPolicyMatchAndAddCommunities(t *testing.T) {

	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := ProcessMessage(updateMsg, peer, time.Now())[0]
	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := oc.DefinedSets{}
	ds.PrefixSets = []oc.PrefixSet{ps}
	ds.NeighborSets = []oc.NeighborSet{ns}

	community := "65000:100"

	s := createStatement("statement1", "ps1", "ns1", true)
	s.Actions.BgpActions.SetCommunity = createSetCommunity("ADD", community)

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	//test
	r := NewRoutingPolicy(logger)
	err := r.reload(pl)
	assert.Nil(t, err)
	p := r.policyMap["pd1"]

	pType, newPath := p.Apply(logger, path, nil)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)
	assert.Equal(t, []uint32{stringToCommunityValue(community)}, newPath.GetCommunities())
}

func TestPolicyMatchAndReplaceCommunities(t *testing.T) {

	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	communities := bgp.NewPathAttributeCommunities([]uint32{
		stringToCommunityValue("65001:200"),
	})
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med, communities}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := ProcessMessage(updateMsg, peer, time.Now())[0]
	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := oc.DefinedSets{}
	ds.PrefixSets = []oc.PrefixSet{ps}
	ds.NeighborSets = []oc.NeighborSet{ns}

	community := "65000:100"

	s := createStatement("statement1", "ps1", "ns1", true)
	s.Actions.BgpActions.SetCommunity = createSetCommunity("REPLACE", community)

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	//test
	r := NewRoutingPolicy(logger)
	err := r.reload(pl)
	assert.Nil(t, err)
	p := r.policyMap["pd1"]

	pType, newPath := p.Apply(logger, path, nil)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)
	assert.Equal(t, []uint32{stringToCommunityValue(community)}, newPath.GetCommunities())
}

func TestPolicyMatchAndRemoveCommunities(t *testing.T) {

	// create path
	community1 := "65000:100"
	community2 := "65000:200"
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	communities := bgp.NewPathAttributeCommunities([]uint32{
		stringToCommunityValue(community1),
		stringToCommunityValue(community2),
	})
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med, communities}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := ProcessMessage(updateMsg, peer, time.Now())[0]
	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := oc.DefinedSets{}
	ds.PrefixSets = []oc.PrefixSet{ps}
	ds.NeighborSets = []oc.NeighborSet{ns}

	s := createStatement("statement1", "ps1", "ns1", true)
	s.Actions.BgpActions.SetCommunity = createSetCommunity("REMOVE", community1)

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	//test
	r := NewRoutingPolicy(logger)
	err := r.reload(pl)
	assert.Nil(t, err)
	p := r.policyMap["pd1"]
	pType, newPath := p.Apply(logger, path, nil)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)
	assert.Equal(t, []uint32{stringToCommunityValue(community2)}, newPath.GetCommunities())
}

func TestPolicyMatchAndRemoveCommunitiesRegexp(t *testing.T) {

	// create path
	community1 := "65000:100"
	community2 := "65000:200"
	community3 := "65100:100"
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	communities := bgp.NewPathAttributeCommunities([]uint32{
		stringToCommunityValue(community1),
		stringToCommunityValue(community2),
		stringToCommunityValue(community3),
	})
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med, communities}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := ProcessMessage(updateMsg, peer, time.Now())[0]
	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := oc.DefinedSets{}
	ds.PrefixSets = []oc.PrefixSet{ps}
	ds.NeighborSets = []oc.NeighborSet{ns}

	s := createStatement("statement1", "ps1", "ns1", true)
	s.Actions.BgpActions.SetCommunity = createSetCommunity("REMOVE", ".*:100")

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	//test
	r := NewRoutingPolicy(logger)
	err := r.reload(pl)
	assert.Nil(t, err)
	p := r.policyMap["pd1"]
	pType, newPath := p.Apply(logger, path, nil)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)
	assert.Equal(t, []uint32{stringToCommunityValue(community2)}, newPath.GetCommunities())
}

func TestPolicyMatchAndRemoveCommunitiesRegexp2(t *testing.T) {

	// create path
	community1 := "0:1"
	community2 := "10:1"
	community3 := "45686:2"
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	communities := bgp.NewPathAttributeCommunities([]uint32{
		stringToCommunityValue(community1),
		stringToCommunityValue(community2),
		stringToCommunityValue(community3),
	})
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med, communities}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := ProcessMessage(updateMsg, peer, time.Now())[0]
	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := oc.DefinedSets{}
	ds.PrefixSets = []oc.PrefixSet{ps}
	ds.NeighborSets = []oc.NeighborSet{ns}

	s := createStatement("statement1", "ps1", "ns1", true)
	s.Actions.BgpActions.SetCommunity = createSetCommunity("REMOVE", "^(0|45686):[0-9]+")

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	//test
	r := NewRoutingPolicy(logger)
	err := r.reload(pl)
	assert.Nil(t, err)
	p := r.policyMap["pd1"]
	pType, newPath := p.Apply(logger, path, nil)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)
	assert.Equal(t, []uint32{stringToCommunityValue(community2)}, newPath.GetCommunities())
}

func TestPolicyMatchAndClearCommunities(t *testing.T) {

	// create path
	community1 := "65000:100"
	community2 := "65000:200"
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	communities := bgp.NewPathAttributeCommunities([]uint32{
		stringToCommunityValue(community1),
		stringToCommunityValue(community2),
	})
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med, communities}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := ProcessMessage(updateMsg, peer, time.Now())[0]
	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := oc.DefinedSets{}
	ds.PrefixSets = []oc.PrefixSet{ps}
	ds.NeighborSets = []oc.NeighborSet{ns}

	s := createStatement("statement1", "ps1", "ns1", true)
	// action NULL is obsolate
	s.Actions.BgpActions.SetCommunity.Options = "REPLACE"
	s.Actions.BgpActions.SetCommunity.SetCommunityMethod.CommunitiesList = nil

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	//test
	r := NewRoutingPolicy(logger)
	err := r.reload(pl)
	assert.Nil(t, err)
	p := r.policyMap["pd1"]

	pType, newPath := p.Apply(logger, path, nil)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)
	//assert.Equal(t, []uint32{}, newPath.GetCommunities())
}

func TestExtCommunityConditionEvaluate(t *testing.T) {

	// setup
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam1 := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(2, []uint16{65001, 65000, 65004, 65005}),
		bgp.NewAsPathParam(1, []uint16{65001, 65010, 65004, 65005}),
	}
	aspath := bgp.NewPathAttributeAsPath(aspathParam1)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	eComAsSpecific1 := &bgp.TwoOctetAsSpecificExtended{
		SubType:      bgp.ExtendedCommunityAttrSubType(bgp.EC_SUBTYPE_ROUTE_TARGET),
		AS:           65001,
		LocalAdmin:   200,
		IsTransitive: true,
	}
	eComIpPrefix1 := &bgp.IPv4AddressSpecificExtended{
		SubType:      bgp.ExtendedCommunityAttrSubType(bgp.EC_SUBTYPE_ROUTE_TARGET),
		IPv4:         net.ParseIP("10.0.0.1"),
		LocalAdmin:   300,
		IsTransitive: true,
	}
	eComAs4Specific1 := &bgp.FourOctetAsSpecificExtended{
		SubType:      bgp.ExtendedCommunityAttrSubType(bgp.EC_SUBTYPE_ROUTE_TARGET),
		AS:           65030000,
		LocalAdmin:   200,
		IsTransitive: true,
	}
	eComAsSpecific2 := &bgp.TwoOctetAsSpecificExtended{
		SubType:      bgp.ExtendedCommunityAttrSubType(bgp.EC_SUBTYPE_ROUTE_TARGET),
		AS:           65002,
		LocalAdmin:   200,
		IsTransitive: false,
	}
	eComIpPrefix2 := &bgp.IPv4AddressSpecificExtended{
		SubType:      bgp.ExtendedCommunityAttrSubType(bgp.EC_SUBTYPE_ROUTE_TARGET),
		IPv4:         net.ParseIP("10.0.0.2"),
		LocalAdmin:   300,
		IsTransitive: false,
	}
	eComAs4Specific2 := &bgp.FourOctetAsSpecificExtended{
		SubType:      bgp.ExtendedCommunityAttrSubType(bgp.EC_SUBTYPE_ROUTE_TARGET),
		AS:           65030001,
		LocalAdmin:   200,
		IsTransitive: false,
	}
	eComAsSpecific3 := &bgp.TwoOctetAsSpecificExtended{
		SubType:      bgp.ExtendedCommunityAttrSubType(bgp.EC_SUBTYPE_ROUTE_ORIGIN),
		AS:           65010,
		LocalAdmin:   300,
		IsTransitive: true,
	}
	eComIpPrefix3 := &bgp.IPv4AddressSpecificExtended{
		SubType:      bgp.ExtendedCommunityAttrSubType(bgp.EC_SUBTYPE_ROUTE_ORIGIN),
		IPv4:         net.ParseIP("10.0.10.10"),
		LocalAdmin:   400,
		IsTransitive: true,
	}
	eComAs4Specific3 := &bgp.FourOctetAsSpecificExtended{
		SubType:      bgp.ExtendedCommunityAttrSubType(bgp.EC_SUBTYPE_ROUTE_TARGET),
		AS:           65030002,
		LocalAdmin:   500,
		IsTransitive: true,
	}
	ec := []bgp.ExtendedCommunityInterface{eComAsSpecific1, eComIpPrefix1, eComAs4Specific1, eComAsSpecific2,
		eComIpPrefix2, eComAs4Specific2, eComAsSpecific3, eComIpPrefix3, eComAs4Specific3}
	extCommunities := bgp.NewPathAttributeExtendedCommunities(ec)

	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med, extCommunities}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg1 := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	UpdatePathAttrs4ByteAs(logger, updateMsg1.Body.(*bgp.BGPUpdate))
	path1 := ProcessMessage(updateMsg1, peer, time.Now())[0]

	convUintStr := func(as uint32) string {
		upper := strconv.FormatUint(uint64(as&0xFFFF0000>>16), 10)
		lower := strconv.FormatUint(uint64(as&0x0000FFFF), 10)
		str := fmt.Sprintf("%s.%s", upper, lower)
		return str
	}

	// create match condition
	ecomSet1 := oc.ExtCommunitySet{
		ExtCommunitySetName: "ecomSet1",
		ExtCommunityList:    []string{"RT:65001:200"},
	}
	ecomSet2 := oc.ExtCommunitySet{
		ExtCommunitySetName: "ecomSet2",
		ExtCommunityList:    []string{"RT:10.0.0.1:300"},
	}
	ecomSet3 := oc.ExtCommunitySet{
		ExtCommunitySetName: "ecomSet3",
		ExtCommunityList:    []string{fmt.Sprintf("RT:%s:200", convUintStr(65030000))},
	}
	ecomSet4 := oc.ExtCommunitySet{
		ExtCommunitySetName: "ecomSet4",
		ExtCommunityList:    []string{"RT:65002:200"},
	}
	ecomSet5 := oc.ExtCommunitySet{
		ExtCommunitySetName: "ecomSet5",
		ExtCommunityList:    []string{"RT:10.0.0.2:300"},
	}
	ecomSet6 := oc.ExtCommunitySet{
		ExtCommunitySetName: "ecomSet6",
		ExtCommunityList:    []string{fmt.Sprintf("RT:%s:200", convUintStr(65030001))},
	}
	ecomSet7 := oc.ExtCommunitySet{
		ExtCommunitySetName: "ecomSet7",
		ExtCommunityList:    []string{"SoO:65010:300"},
	}
	ecomSet8 := oc.ExtCommunitySet{
		ExtCommunitySetName: "ecomSet8",
		ExtCommunityList:    []string{"SoO:10.0.10.10:[0-9]+"},
	}
	ecomSet9 := oc.ExtCommunitySet{
		ExtCommunitySetName: "ecomSet9",
		ExtCommunityList:    []string{"RT:[0-9]+:[0-9]+"},
	}
	ecomSet10 := oc.ExtCommunitySet{
		ExtCommunitySetName: "ecomSet10",
		ExtCommunityList:    []string{"RT:.+:\\d00", "SoO:.+:\\d00"},
	}
	ecomSet11 := oc.ExtCommunitySet{
		ExtCommunitySetName: "ecomSet11",
		ExtCommunityList:    []string{"RT:65001:2", "SoO:11.0.10.10:[0-9]+"},
	}
	ecomSet12 := oc.ExtCommunitySet{
		ExtCommunitySetName: "ecomSet12",
		ExtCommunityList:    []string{"LB:65001:125000"},
	}

	m := make(map[string]DefinedSet)
	for _, c := range []oc.ExtCommunitySet{ecomSet1, ecomSet2, ecomSet3, ecomSet4, ecomSet5, ecomSet6, ecomSet7,
		ecomSet8, ecomSet9, ecomSet10, ecomSet11, ecomSet12} {
		s, _ := NewExtCommunitySet(c)
		m[s.Name()] = s
	}

	createExtCommunityC := func(name string, option oc.MatchSetOptionsType) *ExtCommunityCondition {
		matchSet := oc.MatchExtCommunitySet{}
		matchSet.ExtCommunitySet = name
		matchSet.MatchSetOptions = option
		c, _ := NewExtCommunityCondition(matchSet)
		if v, ok := m[name]; ok {
			c.set = v.(*ExtCommunitySet)
		}

		return c
	}

	p1 := createExtCommunityC("ecomSet1", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p2 := createExtCommunityC("ecomSet2", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p3 := createExtCommunityC("ecomSet3", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p4 := createExtCommunityC("ecomSet4", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p5 := createExtCommunityC("ecomSet5", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p6 := createExtCommunityC("ecomSet6", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p7 := createExtCommunityC("ecomSet7", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p8 := createExtCommunityC("ecomSet8", oc.MATCH_SET_OPTIONS_TYPE_ANY)
	p9 := createExtCommunityC("ecomSet9", oc.MATCH_SET_OPTIONS_TYPE_ANY)

	// ALL case
	p10 := createExtCommunityC("ecomSet10", oc.MATCH_SET_OPTIONS_TYPE_ALL)

	// INVERT case
	p11 := createExtCommunityC("ecomSet11", oc.MATCH_SET_OPTIONS_TYPE_INVERT)

	// test
	assert.Equal(t, true, p1.Evaluate(path1, nil))
	assert.Equal(t, true, p2.Evaluate(path1, nil))
	assert.Equal(t, true, p3.Evaluate(path1, nil))
	assert.Equal(t, false, p4.Evaluate(path1, nil))
	assert.Equal(t, false, p5.Evaluate(path1, nil))
	assert.Equal(t, false, p6.Evaluate(path1, nil))
	assert.Equal(t, true, p7.Evaluate(path1, nil))
	assert.Equal(t, true, p8.Evaluate(path1, nil))
	assert.Equal(t, true, p9.Evaluate(path1, nil))
	assert.Equal(t, true, p10.Evaluate(path1, nil))
	assert.Equal(t, true, p11.Evaluate(path1, nil))

}

func TestExtCommunityConditionEvaluateWithOtherCondition(t *testing.T) {

	// setup
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.2.1.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(1, []uint16{65001, 65000, 65004, 65005}),
		bgp.NewAsPathParam(2, []uint16{65001, 65000, 65004, 65004, 65005}),
	}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.2.1.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	eComAsSpecific1 := &bgp.TwoOctetAsSpecificExtended{
		SubType:      bgp.ExtendedCommunityAttrSubType(bgp.EC_SUBTYPE_ROUTE_TARGET),
		AS:           65001,
		LocalAdmin:   200,
		IsTransitive: true,
	}
	eComIpPrefix1 := &bgp.IPv4AddressSpecificExtended{
		SubType:      bgp.ExtendedCommunityAttrSubType(bgp.EC_SUBTYPE_ROUTE_TARGET),
		IPv4:         net.ParseIP("10.0.0.1"),
		LocalAdmin:   300,
		IsTransitive: true,
	}
	eComAs4Specific1 := &bgp.FourOctetAsSpecificExtended{
		SubType:      bgp.ExtendedCommunityAttrSubType(bgp.EC_SUBTYPE_ROUTE_TARGET),
		AS:           65030000,
		LocalAdmin:   200,
		IsTransitive: true,
	}
	eComAsSpecific2 := &bgp.TwoOctetAsSpecificExtended{
		SubType:      bgp.ExtendedCommunityAttrSubType(bgp.EC_SUBTYPE_ROUTE_TARGET),
		AS:           65002,
		LocalAdmin:   200,
		IsTransitive: false,
	}
	eComIpPrefix2 := &bgp.IPv4AddressSpecificExtended{
		SubType:      bgp.ExtendedCommunityAttrSubType(bgp.EC_SUBTYPE_ROUTE_TARGET),
		IPv4:         net.ParseIP("10.0.0.2"),
		LocalAdmin:   300,
		IsTransitive: false,
	}
	eComAs4Specific2 := &bgp.FourOctetAsSpecificExtended{
		SubType:      bgp.ExtendedCommunityAttrSubType(bgp.EC_SUBTYPE_ROUTE_TARGET),
		AS:           65030001,
		LocalAdmin:   200,
		IsTransitive: false,
	}
	eComAsSpecific3 := &bgp.TwoOctetAsSpecificExtended{
		SubType:      bgp.ExtendedCommunityAttrSubType(bgp.EC_SUBTYPE_ROUTE_ORIGIN),
		AS:           65010,
		LocalAdmin:   300,
		IsTransitive: true,
	}
	eComIpPrefix3 := &bgp.IPv4AddressSpecificExtended{
		SubType:      bgp.ExtendedCommunityAttrSubType(bgp.EC_SUBTYPE_ROUTE_ORIGIN),
		IPv4:         net.ParseIP("10.0.10.10"),
		LocalAdmin:   400,
		IsTransitive: true,
	}
	eComAs4Specific3 := &bgp.FourOctetAsSpecificExtended{
		SubType:      bgp.ExtendedCommunityAttrSubType(bgp.EC_SUBTYPE_ROUTE_TARGET),
		AS:           65030002,
		LocalAdmin:   500,
		IsTransitive: true,
	}
	ec := []bgp.ExtendedCommunityInterface{eComAsSpecific1, eComIpPrefix1, eComAs4Specific1, eComAsSpecific2,
		eComIpPrefix2, eComAs4Specific2, eComAsSpecific3, eComIpPrefix3, eComAs4Specific3}
	extCommunities := bgp.NewPathAttributeExtendedCommunities(ec)

	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med, extCommunities}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	UpdatePathAttrs4ByteAs(logger, updateMsg.Body.(*bgp.BGPUpdate))
	path := ProcessMessage(updateMsg, peer, time.Now())[0]

	// create policy
	asPathSet := oc.AsPathSet{
		AsPathSetName: "asset1",
		AsPathList:    []string{"65005$"},
	}

	ecomSet1 := oc.ExtCommunitySet{
		ExtCommunitySetName: "ecomSet1",
		ExtCommunityList:    []string{"RT:65001:201"},
	}
	ecomSet2 := oc.ExtCommunitySet{
		ExtCommunitySetName: "ecomSet2",
		ExtCommunityList:    []string{"RT:[0-9]+:[0-9]+"},
	}

	ps := createPrefixSet("ps1", "10.10.1.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.2.1.1")

	ds := oc.DefinedSets{}
	ds.PrefixSets = []oc.PrefixSet{ps}
	ds.NeighborSets = []oc.NeighborSet{ns}
	ds.BgpDefinedSets.AsPathSets = []oc.AsPathSet{asPathSet}
	ds.BgpDefinedSets.ExtCommunitySets = []oc.ExtCommunitySet{ecomSet1, ecomSet2}

	s1 := createStatement("statement1", "ps1", "ns1", false)
	s1.Conditions.BgpConditions.MatchAsPathSet.AsPathSet = "asset1"
	s1.Conditions.BgpConditions.MatchExtCommunitySet.ExtCommunitySet = "ecomSet1"

	s2 := createStatement("statement2", "ps1", "ns1", false)
	s2.Conditions.BgpConditions.MatchAsPathSet.AsPathSet = "asset1"
	s2.Conditions.BgpConditions.MatchExtCommunitySet.ExtCommunitySet = "ecomSet2"

	pd1 := createPolicyDefinition("pd1", s1)
	pd2 := createPolicyDefinition("pd2", s2)
	pl := createRoutingPolicy(ds, pd1, pd2)
	//test
	r := NewRoutingPolicy(logger)
	err := r.reload(pl)
	assert.Nil(t, err)
	p := r.policyMap["pd1"]
	pType, newPath := p.Apply(logger, path, nil)
	assert.Equal(t, ROUTE_TYPE_NONE, pType)
	assert.Equal(t, newPath, path)

	p = r.policyMap["pd2"]
	pType, newPath = p.Apply(logger, path, nil)
	assert.Equal(t, ROUTE_TYPE_REJECT, pType)
	assert.Equal(t, newPath, path)

}

func TestPolicyMatchAndReplaceMed(t *testing.T) {

	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(100)

	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := ProcessMessage(updateMsg, peer, time.Now())[0]
	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := oc.DefinedSets{}
	ds.PrefixSets = []oc.PrefixSet{ps}
	ds.NeighborSets = []oc.NeighborSet{ns}

	m := "200"
	s := createStatement("statement1", "ps1", "ns1", true)
	s.Actions.BgpActions.SetMed = oc.BgpSetMedType(m)

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	//test
	r := NewRoutingPolicy(logger)
	err := r.reload(pl)
	assert.Nil(t, err)
	p := r.policyMap["pd1"]

	pType, newPath := p.Apply(logger, path, nil)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)
	v, err := newPath.GetMed()
	assert.Nil(t, err)
	newMed := fmt.Sprintf("%d", v)
	assert.Equal(t, m, newMed)
}

func TestPolicyMatchAndAddingMed(t *testing.T) {

	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(100)

	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := ProcessMessage(updateMsg, peer, time.Now())[0]
	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := oc.DefinedSets{}
	ds.PrefixSets = []oc.PrefixSet{ps}
	ds.NeighborSets = []oc.NeighborSet{ns}

	m := "+200"
	ma := "300"
	s := createStatement("statement1", "ps1", "ns1", true)
	s.Actions.BgpActions.SetMed = oc.BgpSetMedType(m)

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)
	//test
	r := NewRoutingPolicy(logger)
	err := r.reload(pl)
	assert.Nil(t, err)
	p := r.policyMap["pd1"]
	pType, newPath := p.Apply(logger, path, nil)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)

	v, err := newPath.GetMed()
	assert.Nil(t, err)
	newMed := fmt.Sprintf("%d", v)
	assert.Equal(t, ma, newMed)
}

func TestPolicyMatchAndAddingMedOverFlow(t *testing.T) {

	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(1)

	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := ProcessMessage(updateMsg, peer, time.Now())[0]
	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := oc.DefinedSets{}
	ds.PrefixSets = []oc.PrefixSet{ps}
	ds.NeighborSets = []oc.NeighborSet{ns}

	m := fmt.Sprintf("+%d", uint32(math.MaxUint32))
	ma := "1"

	s := createStatement("statement1", "ps1", "ns1", true)
	s.Actions.BgpActions.SetMed = oc.BgpSetMedType(m)

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)
	//test
	r := NewRoutingPolicy(logger)
	err := r.reload(pl)
	assert.Nil(t, err)
	p := r.policyMap["pd1"]

	pType, newPath := p.Apply(logger, path, nil)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)

	v, err := newPath.GetMed()
	assert.Nil(t, err)
	newMed := fmt.Sprintf("%d", v)
	assert.Equal(t, ma, newMed)
}

func TestPolicyMatchAndSubtractMed(t *testing.T) {

	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(100)

	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := ProcessMessage(updateMsg, peer, time.Now())[0]
	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := oc.DefinedSets{}
	ds.PrefixSets = []oc.PrefixSet{ps}
	ds.NeighborSets = []oc.NeighborSet{ns}

	m := "-50"
	ma := "50"

	s := createStatement("statement1", "ps1", "ns1", true)
	s.Actions.BgpActions.SetMed = oc.BgpSetMedType(m)

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)
	//test
	r := NewRoutingPolicy(logger)
	err := r.reload(pl)
	assert.Nil(t, err)
	p := r.policyMap["pd1"]

	pType, newPath := p.Apply(logger, path, nil)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)

	v, err := newPath.GetMed()
	assert.Nil(t, err)
	newMed := fmt.Sprintf("%d", v)
	assert.Equal(t, ma, newMed)
}

func TestPolicyMatchAndSubtractMedUnderFlow(t *testing.T) {

	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(100)

	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := ProcessMessage(updateMsg, peer, time.Now())[0]
	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := oc.DefinedSets{}
	ds.PrefixSets = []oc.PrefixSet{ps}
	ds.NeighborSets = []oc.NeighborSet{ns}

	m := "-101"
	ma := "100"

	s := createStatement("statement1", "ps1", "ns1", true)
	s.Actions.BgpActions.SetMed = oc.BgpSetMedType(m)

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)
	//test
	r := NewRoutingPolicy(logger)
	err := r.reload(pl)
	assert.Nil(t, err)
	p := r.policyMap["pd1"]

	pType, newPath := p.Apply(logger, path, nil)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)

	v, err := newPath.GetMed()
	assert.Nil(t, err)
	newMed := fmt.Sprintf("%d", v)
	assert.Equal(t, ma, newMed)
}

func TestPolicyMatchWhenPathHaveNotMed(t *testing.T) {

	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")

	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := ProcessMessage(updateMsg, peer, time.Now())[0]
	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := oc.DefinedSets{}
	ds.PrefixSets = []oc.PrefixSet{ps}
	ds.NeighborSets = []oc.NeighborSet{ns}

	m := "-50"
	s := createStatement("statement1", "ps1", "ns1", true)
	s.Actions.BgpActions.SetMed = oc.BgpSetMedType(m)

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)
	//test
	r := NewRoutingPolicy(logger)
	err := r.reload(pl)
	assert.Nil(t, err)
	p := r.policyMap["pd1"]

	pType, newPath := p.Apply(logger, path, nil)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)

	_, err = newPath.GetMed()
	assert.NotNil(t, err)
}

func TestPolicyAsPathPrepend(t *testing.T) {

	assert := assert.New(t)

	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001, 65000})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)

	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)

	body := updateMsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(logger, body)
	path := ProcessMessage(updateMsg, peer, time.Now())[0]

	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := oc.DefinedSets{}
	ds.PrefixSets = []oc.PrefixSet{ps}
	ds.NeighborSets = []oc.NeighborSet{ns}

	s := createStatement("statement1", "ps1", "ns1", true)
	s.Actions.BgpActions.SetAsPathPrepend.As = "65002"
	s.Actions.BgpActions.SetAsPathPrepend.RepeatN = 10

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)
	//test
	r := NewRoutingPolicy(logger)
	r.reload(pl)
	p := r.policyMap["pd1"]

	pType, newPath := p.Apply(logger, path, nil)
	assert.Equal(ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(nil, newPath)
	assert.Equal([]uint32{65002, 65002, 65002, 65002, 65002, 65002, 65002, 65002, 65002, 65002, 65001, 65000}, newPath.GetAsSeqList())
}

func TestPolicyAsPathPrependLastAs(t *testing.T) {

	assert := assert.New(t)
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65002, 65001, 65000})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)

	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)

	body := updateMsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(logger, body)
	path := ProcessMessage(updateMsg, peer, time.Now())[0]

	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := oc.DefinedSets{}
	ds.PrefixSets = []oc.PrefixSet{ps}
	ds.NeighborSets = []oc.NeighborSet{ns}

	s := createStatement("statement1", "ps1", "ns1", true)
	s.Actions.BgpActions.SetAsPathPrepend.As = "last-as"
	s.Actions.BgpActions.SetAsPathPrepend.RepeatN = 5

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)
	//test
	r := NewRoutingPolicy(logger)
	r.reload(pl)
	p := r.policyMap["pd1"]

	pType, newPath := p.Apply(logger, path, nil)
	assert.Equal(ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(nil, newPath)
	assert.Equal([]uint32{65002, 65002, 65002, 65002, 65002, 65002, 65001, 65000}, newPath.GetAsSeqList())
}

func TestPolicyAs4PathPrepend(t *testing.T) {

	assert := assert.New(t)

	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{
		bgp.NewAs4PathParam(2, []uint32{
			createAs4Value("65001.1"),
			createAs4Value("65000.1"),
		}),
	}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)

	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)

	body := updateMsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(logger, body)
	path := ProcessMessage(updateMsg, peer, time.Now())[0]

	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := oc.DefinedSets{}
	ds.PrefixSets = []oc.PrefixSet{ps}
	ds.NeighborSets = []oc.NeighborSet{ns}

	s := createStatement("statement1", "ps1", "ns1", true)
	s.Actions.BgpActions.SetAsPathPrepend.As = fmt.Sprintf("%d", createAs4Value("65002.1"))
	s.Actions.BgpActions.SetAsPathPrepend.RepeatN = 10

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)
	//test
	r := NewRoutingPolicy(logger)
	r.reload(pl)
	p, err := NewPolicy(pl.PolicyDefinitions[0])
	assert.Nil(err)
	addPolicy(r, p)

	pType, newPath := p.Apply(logger, path, nil)
	assert.Equal(ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(nil, newPath)
	asn := createAs4Value("65002.1")
	assert.Equal([]uint32{
		asn, asn, asn, asn, asn, asn, asn, asn, asn, asn,
		createAs4Value("65001.1"),
		createAs4Value("65000.1"),
	}, newPath.GetAsSeqList())
}

func TestPolicyAs4PathPrependLastAs(t *testing.T) {

	assert := assert.New(t)
	// create path
	peer := &PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{
		bgp.NewAs4PathParam(2, []uint32{
			createAs4Value("65002.1"),
			createAs4Value("65001.1"),
			createAs4Value("65000.1"),
		}),
	}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)

	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)

	body := updateMsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(logger, body)
	path := ProcessMessage(updateMsg, peer, time.Now())[0]

	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := oc.DefinedSets{}
	ds.PrefixSets = []oc.PrefixSet{ps}
	ds.NeighborSets = []oc.NeighborSet{ns}

	s := createStatement("statement1", "ps1", "ns1", true)
	s.Actions.BgpActions.SetAsPathPrepend.As = "last-as"
	s.Actions.BgpActions.SetAsPathPrepend.RepeatN = 5

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)
	//test
	r := NewRoutingPolicy(logger)
	r.reload(pl)
	p, _ := NewPolicy(pl.PolicyDefinitions[0])
	addPolicy(r, p)

	pType, newPath := p.Apply(logger, path, nil)
	assert.Equal(ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(nil, newPath)
	asn := createAs4Value("65002.1")
	assert.Equal([]uint32{
		asn, asn, asn, asn, asn,
		createAs4Value("65002.1"),
		createAs4Value("65001.1"),
		createAs4Value("65000.1"),
	}, newPath.GetAsSeqList())
}

func TestParseCommunityRegexp(t *testing.T) {
	exp, err := ParseCommunityRegexp("65000:1")
	assert.Equal(t, nil, err)
	assert.Equal(t, true, exp.MatchString("65000:1"))
	assert.Equal(t, false, exp.MatchString("65000:100"))

	// test if the parseCommunityRegexp function behaves as expected

	l1 := "6830:24370$"
	r1, _ := ParseCommunityRegexp("6830:24370$")

	l2 := "^6830:24370$"
	r2, _ := ParseCommunityRegexp("^6830:24370$")

	l3 := "^65001:100$"
	r3, _ := ParseCommunityRegexp("65001:100")

	l4 := "^65001:400$"
	r4, _ := ParseCommunityRegexp("4259905936")

	l5 := "^[0-9]*:300$"
	r5, _ := ParseCommunityRegexp("^[0-9]*:300$")

	l6 := "^" + strconv.Itoa(int(bgp.COMMUNITY_INTERNET)) + ":" + strconv.Itoa(int(bgp.COMMUNITY_INTERNET)) + "$"
	r6, _ := ParseCommunityRegexp("INTERNET")

	fmt.Printf("%v %v", l2, r2)

	assert.Equal(t, l1, r1.String())
	assert.Equal(t, l2, r2.String())
	assert.Equal(t, l3, r3.String())
	assert.Equal(t, l4, r4.String())
	assert.Equal(t, l5, r5.String())
	assert.Equal(t, l6, r6.String())
}

func TestLocalPrefAction(t *testing.T) {
	action, err := NewLocalPrefAction(10)
	assert.Nil(t, err)

	nlri := bgp.NewIPAddrPrefix(24, "10.0.0.0")

	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{
		bgp.NewAs4PathParam(2, []uint32{
			createAs4Value("65002.1"),
			createAs4Value("65001.1"),
			createAs4Value("65000.1"),
		}),
	}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)

	attrs := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}

	path := NewPath(nil, nlri, false, attrs, time.Now(), false)
	p, _ := action.Apply(path, nil)
	assert.NotNil(t, p)

	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_LOCAL_PREF)
	assert.NotNil(t, attr)
	lp := attr.(*bgp.PathAttributeLocalPref)
	assert.Equal(t, int(lp.Value), int(10))
}

func createStatement(name, psname, nsname string, accept bool) oc.Statement {
	c := oc.Conditions{
		MatchPrefixSet: oc.MatchPrefixSet{
			PrefixSet: psname,
		},
		MatchNeighborSet: oc.MatchNeighborSet{
			NeighborSet: nsname,
		},
	}
	rd := oc.ROUTE_DISPOSITION_REJECT_ROUTE
	if accept {
		rd = oc.ROUTE_DISPOSITION_ACCEPT_ROUTE
	}
	a := oc.Actions{
		RouteDisposition: rd,
	}
	s := oc.Statement{
		Name:       name,
		Conditions: c,
		Actions:    a,
	}
	return s
}

func createSetCommunity(operation string, community ...string) oc.SetCommunity {

	s := oc.SetCommunity{
		SetCommunityMethod: oc.SetCommunityMethod{
			CommunitiesList: community,
		},
		Options: operation,
	}
	return s
}

func stringToCommunityValue(comStr string) uint32 {
	elem := strings.Split(comStr, ":")
	asn, _ := strconv.ParseUint(elem[0], 10, 16)
	val, _ := strconv.ParseUint(elem[1], 10, 16)
	return uint32(asn<<16 | val)
}

func createPolicyDefinition(defName string, stmt ...oc.Statement) oc.PolicyDefinition {
	pd := oc.PolicyDefinition{
		Name:       defName,
		Statements: []oc.Statement(stmt),
	}
	return pd
}

func createRoutingPolicy(ds oc.DefinedSets, pd ...oc.PolicyDefinition) oc.RoutingPolicy {
	pl := oc.RoutingPolicy{
		DefinedSets:       ds,
		PolicyDefinitions: []oc.PolicyDefinition(pd),
	}
	return pl
}

func createPrefixSet(name string, prefix string, maskLength string) oc.PrefixSet {
	ps := oc.PrefixSet{
		PrefixSetName: name,
		PrefixList: []oc.Prefix{
			{
				IpPrefix:        prefix,
				MasklengthRange: maskLength,
			}},
	}
	return ps
}

func createNeighborSet(name string, addr string) oc.NeighborSet {
	ns := oc.NeighborSet{
		NeighborSetName:  name,
		NeighborInfoList: []string{addr},
	}
	return ns
}

func createAs4Value(s string) uint32 {
	v := strings.Split(s, ".")
	upper, _ := strconv.ParseUint(v[0], 10, 16)
	lower, _ := strconv.ParseUint(v[1], 10, 16)
	return uint32(upper<<16 | lower)
}

func TestPrefixSetOperation(t *testing.T) {
	// tryp to create prefixset with multiple families
	p1 := oc.Prefix{
		IpPrefix:        "0.0.0.0/0",
		MasklengthRange: "0..7",
	}
	p2 := oc.Prefix{
		IpPrefix:        "0::/25",
		MasklengthRange: "25..128",
	}
	_, err := NewPrefixSet(oc.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList:    []oc.Prefix{p1, p2},
	})
	assert.NotNil(t, err)
	m1, _ := NewPrefixSet(oc.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList:    []oc.Prefix{p1},
	})
	m2, err := NewPrefixSet(oc.PrefixSet{PrefixSetName: "ps2"})
	assert.Nil(t, err)
	err = m1.Append(m2)
	assert.Nil(t, err)
	err = m2.Append(m1)
	assert.Nil(t, err)
	assert.Equal(t, bgp.RF_IPv4_UC, m2.family)
	p3, _ := NewPrefix(oc.Prefix{IpPrefix: "10.10.0.0/24", MasklengthRange: ""})
	p4, _ := NewPrefix(oc.Prefix{IpPrefix: "0::/25", MasklengthRange: ""})
	_, err = NewPrefixSetFromApiStruct("ps3", []*Prefix{p3, p4})
	assert.NotNil(t, err)
}

func TestPrefixSetMatch(t *testing.T) {
	p1 := oc.Prefix{
		IpPrefix:        "0.0.0.0/0",
		MasklengthRange: "0..7",
	}
	p2 := oc.Prefix{
		IpPrefix:        "0.0.0.0/0",
		MasklengthRange: "25..32",
	}
	ps, err := NewPrefixSet(oc.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList:    []oc.Prefix{p1, p2},
	})
	assert.Nil(t, err)
	m := &PrefixCondition{
		set: ps,
	}

	path := NewPath(nil, bgp.NewIPAddrPrefix(6, "0.0.0.0"), false, []bgp.PathAttributeInterface{}, time.Now(), false)
	assert.True(t, m.Evaluate(path, nil))

	path = NewPath(nil, bgp.NewIPAddrPrefix(10, "0.0.0.0"), false, []bgp.PathAttributeInterface{}, time.Now(), false)
	assert.False(t, m.Evaluate(path, nil))

	path = NewPath(nil, bgp.NewIPAddrPrefix(25, "0.0.0.0"), false, []bgp.PathAttributeInterface{}, time.Now(), false)
	assert.True(t, m.Evaluate(path, nil))

	path = NewPath(nil, bgp.NewIPAddrPrefix(30, "0.0.0.0"), false, []bgp.PathAttributeInterface{}, time.Now(), false)
	assert.True(t, m.Evaluate(path, nil))

	p3 := oc.Prefix{
		IpPrefix:        "0.0.0.0/0",
		MasklengthRange: "9..10",
	}
	ps2, err := NewPrefixSet(oc.PrefixSet{
		PrefixSetName: "ps2",
		PrefixList:    []oc.Prefix{p3},
	})
	assert.Nil(t, err)
	err = ps.Append(ps2)
	assert.Nil(t, err)

	path = NewPath(nil, bgp.NewIPAddrPrefix(10, "0.0.0.0"), false, []bgp.PathAttributeInterface{}, time.Now(), false)
	assert.True(t, m.Evaluate(path, nil))

	ps3, err := NewPrefixSet(oc.PrefixSet{
		PrefixSetName: "ps3",
		PrefixList:    []oc.Prefix{p1},
	})
	assert.Nil(t, err)
	err = ps.Remove(ps3)
	assert.Nil(t, err)

	path = NewPath(nil, bgp.NewIPAddrPrefix(6, "0.0.0.0"), false, []bgp.PathAttributeInterface{}, time.Now(), false)
	assert.False(t, m.Evaluate(path, nil))
}

func TestPrefixSetMatchV4withV6Prefix(t *testing.T) {
	p1 := oc.Prefix{
		IpPrefix:        "c000::/3",
		MasklengthRange: "3..128",
	}
	ps, err := NewPrefixSet(oc.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList:    []oc.Prefix{p1},
	})
	assert.Nil(t, err)
	m := &PrefixCondition{
		set: ps,
	}

	path := NewPath(nil, bgp.NewIPAddrPrefix(6, "192.0.0.0"), false, []bgp.PathAttributeInterface{}, time.Now(), false)
	assert.False(t, m.Evaluate(path, nil))
}

func TestPrefixSetMatchV6LabeledwithV6Prefix(t *testing.T) {
	p1 := oc.Prefix{
		IpPrefix:        "2806:106e:19::/48",
		MasklengthRange: "48..48",
	}
	ps, err := NewPrefixSet(oc.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList:    []oc.Prefix{p1},
	})
	assert.Nil(t, err)
	m := &PrefixCondition{
		set: ps,
	}

	labels := bgp.NewMPLSLabelStack(100, 200)
	n1 := bgp.NewLabeledIPv6AddrPrefix(48, "2806:106e:19::", *labels)
	path := NewPath(nil, n1, false, []bgp.PathAttributeInterface{}, time.Now(), false)
	assert.True(t, m.Evaluate(path, nil))

	labels = bgp.NewMPLSLabelStack(100, 200)
	n2 := bgp.NewLabeledIPv6AddrPrefix(48, "1806:106e:19::", *labels)
	path = NewPath(nil, n2, false, []bgp.PathAttributeInterface{}, time.Now(), false)
	assert.False(t, m.Evaluate(path, nil))
}

func TestPrefixSetMatchVPNV4Prefix(t *testing.T) {
	p1 := oc.Prefix{
		IpPrefix:        "10.10.10.0/24",
		MasklengthRange: "24..32",
	}
	ps, err := NewPrefixSet(oc.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList:    []oc.Prefix{p1},
	})
	assert.Nil(t, err)
	m := &PrefixCondition{
		set: ps,
	}

	labels := bgp.NewMPLSLabelStack(100, 200)
	rd, _ := bgp.ParseRouteDistinguisher("100:100")

	n1 := bgp.NewLabeledVPNIPAddrPrefix(32, "10.10.10.10", *labels, rd)
	path := NewPath(nil, n1, false, []bgp.PathAttributeInterface{}, time.Now(), false)
	assert.True(t, m.Evaluate(path, nil))

	n2 := bgp.NewLabeledVPNIPAddrPrefix(32, "10.20.20.20", *labels, rd)
	path = NewPath(nil, n2, false, []bgp.PathAttributeInterface{}, time.Now(), false)
	assert.False(t, m.Evaluate(path, nil))

	n3 := bgp.NewLabeledVPNIPAddrPrefix(16, "10.10.0.0", *labels, rd)
	path = NewPath(nil, n3, false, []bgp.PathAttributeInterface{}, time.Now(), false)
	assert.False(t, m.Evaluate(path, nil))
}

func TestPrefixSetMatchVPNV6Prefix(t *testing.T) {
	p1 := oc.Prefix{
		IpPrefix:        "2001:123:123:1::/64",
		MasklengthRange: "64..128",
	}
	ps, err := NewPrefixSet(oc.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList:    []oc.Prefix{p1},
	})
	assert.Nil(t, err)
	m := &PrefixCondition{
		set: ps,
	}

	labels := bgp.NewMPLSLabelStack(100, 200)
	rd, _ := bgp.ParseRouteDistinguisher("100:100")

	n1 := bgp.NewLabeledVPNIPv6AddrPrefix(128, "2001:123:123:1::", *labels, rd)
	path := NewPath(nil, n1, false, []bgp.PathAttributeInterface{}, time.Now(), false)
	assert.True(t, m.Evaluate(path, nil))

	n2 := bgp.NewLabeledVPNIPv6AddrPrefix(128, "2001:124:123:1::", *labels, rd)
	path = NewPath(nil, n2, false, []bgp.PathAttributeInterface{}, time.Now(), false)
	assert.False(t, m.Evaluate(path, nil))

	n3 := bgp.NewLabeledVPNIPv6AddrPrefix(48, "2001:124:123::", *labels, rd)
	path = NewPath(nil, n3, false, []bgp.PathAttributeInterface{}, time.Now(), false)
	assert.False(t, m.Evaluate(path, nil))
}

func TestLargeCommunityMatchAction(t *testing.T) {
	coms := []*bgp.LargeCommunity{
		{ASN: 100, LocalData1: 100, LocalData2: 100},
		{ASN: 100, LocalData1: 200, LocalData2: 200},
	}
	p := NewPath(nil, nil, false, []bgp.PathAttributeInterface{bgp.NewPathAttributeLargeCommunities(coms)}, time.Time{}, false)

	c := oc.LargeCommunitySet{
		LargeCommunitySetName: "l0",
		LargeCommunityList: []string{
			"100:100:100",
			"100:300:100",
		},
	}

	set, err := NewLargeCommunitySet(c)
	assert.Equal(t, err, nil)

	m, err := NewLargeCommunityCondition(oc.MatchLargeCommunitySet{
		LargeCommunitySet: "l0",
	})
	assert.Equal(t, err, nil)
	m.set = set

	assert.Equal(t, m.Evaluate(p, nil), true)

	a, err := NewLargeCommunityAction(oc.SetLargeCommunity{
		SetLargeCommunityMethod: oc.SetLargeCommunityMethod{
			CommunitiesList: []string{"100:100:100"},
		},
		Options: oc.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE,
	})
	assert.Equal(t, err, nil)
	p, _ = a.Apply(p, nil)

	assert.Equal(t, m.Evaluate(p, nil), false)

	a, err = NewLargeCommunityAction(oc.SetLargeCommunity{
		SetLargeCommunityMethod: oc.SetLargeCommunityMethod{
			CommunitiesList: []string{
				"100:300:100",
				"200:100:100",
			},
		},
		Options: oc.BGP_SET_COMMUNITY_OPTION_TYPE_ADD,
	})
	assert.Equal(t, err, nil)
	p, _ = a.Apply(p, nil)

	assert.Equal(t, m.Evaluate(p, nil), true)

	a, err = NewLargeCommunityAction(oc.SetLargeCommunity{
		SetLargeCommunityMethod: oc.SetLargeCommunityMethod{
			CommunitiesList: []string{"^100:"},
		},
		Options: oc.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE,
	})
	assert.Equal(t, err, nil)
	p, _ = a.Apply(p, nil)

	assert.Equal(t, m.Evaluate(p, nil), false)

	c = oc.LargeCommunitySet{
		LargeCommunitySetName: "l1",
		LargeCommunityList: []string{
			"200:",
		},
	}

	set, err = NewLargeCommunitySet(c)
	assert.Equal(t, err, nil)

	m, err = NewLargeCommunityCondition(oc.MatchLargeCommunitySet{
		LargeCommunitySet: "l1",
	})
	assert.Equal(t, err, nil)
	m.set = set

	assert.Equal(t, m.Evaluate(p, nil), true)
}

func TestLargeCommunitiesMatchClearAction(t *testing.T) {
	coms := []*bgp.LargeCommunity{
		{ASN: 100, LocalData1: 100, LocalData2: 100},
		{ASN: 100, LocalData1: 200, LocalData2: 200},
	}
	p := NewPath(nil, nil, false, []bgp.PathAttributeInterface{bgp.NewPathAttributeLargeCommunities(coms)}, time.Time{}, false)

	a, err := NewLargeCommunityAction(oc.SetLargeCommunity{
		SetLargeCommunityMethod: oc.SetLargeCommunityMethod{
			CommunitiesList: []string{
				"100:100:100",
				"100:200:200",
			},
		},
		Options: oc.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE,
	})

	assert.Equal(t, err, nil)
	p, _ = a.Apply(p, nil)

	var lc []*bgp.LargeCommunity
	assert.Equal(t, lc, p.GetLargeCommunities())
}

func TestAfiSafiInMatchPath(t *testing.T) {
	condition, err := NewAfiSafiInCondition([]oc.AfiSafiType{oc.AFI_SAFI_TYPE_L3VPN_IPV4_UNICAST, oc.AFI_SAFI_TYPE_L3VPN_IPV6_UNICAST})
	require.NoError(t, err)

	rtExtCom, err := bgp.ParseExtendedCommunity(bgp.EC_SUBTYPE_ROUTE_TARGET, "100:100")
	assert.NoError(t, err)

	prefixVPNv4 := bgp.NewLabeledVPNIPAddrPrefix(0, "1.1.1.0/24", *bgp.NewMPLSLabelStack(), bgp.NewRouteDistinguisherTwoOctetAS(100, 100))
	prefixVPNv6 := bgp.NewLabeledVPNIPv6AddrPrefix(0, "2001:0db8:85a3:0000:0000:8a2e:0370:7334", *bgp.NewMPLSLabelStack(), bgp.NewRouteDistinguisherTwoOctetAS(200, 200))
	prefixRTC := bgp.NewRouteTargetMembershipNLRI(100, nil)
	prefixv4 := bgp.NewIPAddrPrefix(0, "1.1.1.0/24")
	prefixv6 := bgp.NewIPv6AddrPrefix(0, "2001:0db8:85a3:0000:0000:8a2e:0370:7334")

	pathVPNv4 := NewPath(nil, prefixVPNv4, false, []bgp.PathAttributeInterface{bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{rtExtCom})}, time.Time{}, false)
	pathVPNv6 := NewPath(nil, prefixVPNv6, false, []bgp.PathAttributeInterface{bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{rtExtCom})}, time.Time{}, false)
	pathv4 := NewPath(nil, prefixv4, false, []bgp.PathAttributeInterface{}, time.Time{}, false)
	pathv6 := NewPath(nil, prefixv6, false, []bgp.PathAttributeInterface{}, time.Time{}, false)
	pathRTC := NewPath(nil, prefixRTC, false, []bgp.PathAttributeInterface{}, time.Time{}, false)

	type Entry struct {
		path        *Path
		shouldMatch bool
	}

	for _, entry := range []Entry{
		{pathVPNv4, true},
		{pathVPNv6, true},
		{pathv4, false},
		{pathv6, false},
		{pathRTC, false},
	} {
		assert.Equal(t, condition.Evaluate(entry.path, nil), entry.shouldMatch)
	}
}

func TestMultipleStatementPolicy(t *testing.T) {
	r := NewRoutingPolicy(logger)
	rp := oc.RoutingPolicy{
		PolicyDefinitions: []oc.PolicyDefinition{{
			Name: "p1",
			Statements: []oc.Statement{
				{
					Actions: oc.Actions{
						BgpActions: oc.BgpActions{
							SetMed: "+100",
						},
					},
				},
				{
					Actions: oc.Actions{
						BgpActions: oc.BgpActions{
							SetLocalPref: 100,
						},
					},
				},
			},
		},
		},
	}
	err := r.reload(rp)
	assert.Nil(t, err)

	nlri := bgp.NewIPAddrPrefix(24, "10.10.0.0")

	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	pattrs := []bgp.PathAttributeInterface{origin, aspath, nexthop}

	path := NewPath(nil, nlri, false, pattrs, time.Now(), false)

	pType, newPath := r.policyMap["p1"].Apply(logger, path, nil)
	assert.Equal(t, ROUTE_TYPE_NONE, pType)
	med, _ := newPath.GetMed()
	assert.Equal(t, med, uint32(100))
	localPref, _ := newPath.GetLocalPref()
	assert.Equal(t, localPref, uint32(100))
}

func TestNewSingleAsPathMatch(t *testing.T) {
	r := NewSingleAsPathMatch("^65100_")
	assert.Equal(t, r.mode, LEFT_MOST)
	r = NewSingleAsPathMatch("_65100$")
	assert.Equal(t, r.mode, ORIGIN)
	r = NewSingleAsPathMatch("_65100_")
	assert.Equal(t, r.mode, INCLUDE)
	r = NewSingleAsPathMatch("^65100$")
	assert.Equal(t, r.mode, ONLY)
}
