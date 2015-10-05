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

package policy

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/table"
	"github.com/stretchr/testify/assert"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func init() {
	log.SetLevel(log.DebugLevel)
}

func TestPrefixCalcurateNoRange(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.0")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// test
	pl1, _ := NewPrefix("10.10.0.0/24", "")
	match1 := ipPrefixCalculate(path, pl1)
	assert.Equal(t, true, match1)
	pl2, _ := NewPrefix("10.10.0.0/23", "")
	match2 := ipPrefixCalculate(path, pl2)
	assert.Equal(t, false, match2)
	pl3, _ := NewPrefix("10.10.0.0/16", "21..24")
	match3 := ipPrefixCalculate(path, pl3)
	assert.Equal(t, true, match3)
}

func TestPrefixCalcurateAddress(t *testing.T) {
	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// test
	pl1, _ := NewPrefix("10.11.0.0/16", "21..24")
	match1 := ipPrefixCalculate(path, pl1)
	assert.Equal(t, false, match1)
	pl2, _ := NewPrefix("10.10.0.0/16", "21..24")
	match2 := ipPrefixCalculate(path, pl2)
	assert.Equal(t, true, match2)
}

func TestPrefixCalcurateLength(t *testing.T) {
	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// test
	pl1, _ := NewPrefix("10.10.64.0/24", "21..24")
	match1 := ipPrefixCalculate(path, pl1)
	assert.Equal(t, false, match1)
	pl2, _ := NewPrefix("10.10.64.0/16", "21..24")
	match2 := ipPrefixCalculate(path, pl2)
	assert.Equal(t, true, match2)
}

func TestPrefixCalcurateLengthRange(t *testing.T) {
	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// test
	pl1, _ := NewPrefix("10.10.0.0/16", "21..23")
	match1 := ipPrefixCalculate(path, pl1)
	assert.Equal(t, false, match1)
	pl2, _ := NewPrefix("10.10.0.0/16", "25..26")
	match2 := ipPrefixCalculate(path, pl2)
	assert.Equal(t, false, match2)
	pl3, _ := NewPrefix("10.10.0.0/16", "21..24")
	match3 := ipPrefixCalculate(path, pl3)
	assert.Equal(t, true, match3)
}

func TestPrefixCalcurateNoRangeIPv6(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("2001::192:168:50:1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	mpnlri := []bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")}
	mpreach := bgp.NewPathAttributeMpReachNLRI("2001::192:168:50:1", mpnlri)
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{mpreach, origin, aspath, med}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nil)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// test
	pl1, _ := NewPrefix("2001:123:123::/48", "")
	match1 := ipPrefixCalculate(path, pl1)
	assert.Equal(t, false, match1)
	pl2, _ := NewPrefix("2001:123:123:1::/64", "")
	match2 := ipPrefixCalculate(path, pl2)
	assert.Equal(t, true, match2)
	pl3, _ := NewPrefix("2001:123:123::/48", "64..80")
	match3 := ipPrefixCalculate(path, pl3)
	assert.Equal(t, true, match3)
}

func TestPrefixCalcurateAddressIPv6(t *testing.T) {
	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("2001::192:168:50:1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	mpnlri := []bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")}
	mpreach := bgp.NewPathAttributeMpReachNLRI("2001::192:168:50:1", mpnlri)
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{mpreach, origin, aspath, med}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nil)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// test
	pl1, _ := NewPrefix("2001:123:128::/48", "64..80")
	match1 := ipPrefixCalculate(path, pl1)
	assert.Equal(t, false, match1)
	pl2, _ := NewPrefix("2001:123:123::/48", "64..80")
	match2 := ipPrefixCalculate(path, pl2)
	assert.Equal(t, true, match2)
}

func TestPrefixCalcurateLengthIPv6(t *testing.T) {
	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("2001::192:168:50:1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	mpnlri := []bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")}
	mpreach := bgp.NewPathAttributeMpReachNLRI("2001::192:168:50:1", mpnlri)
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{mpreach, origin, aspath, med}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nil)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// test
	pl1, _ := NewPrefix("2001:123:123:64::/64", "64..80")
	match1 := ipPrefixCalculate(path, pl1)
	assert.Equal(t, false, match1)
	pl2, _ := NewPrefix("2001:123:123:64::/48", "64..80")
	match2 := ipPrefixCalculate(path, pl2)
	assert.Equal(t, true, match2)
}

func TestPrefixCalcurateLengthRangeIPv6(t *testing.T) {
	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("2001::192:168:50:1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	mpnlri := []bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")}
	mpreach := bgp.NewPathAttributeMpReachNLRI("2001::192:168:50:1", mpnlri)
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{mpreach, origin, aspath, med}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nil)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// test
	pl1, _ := NewPrefix("2001:123:123::/48", "62..63")
	match1 := ipPrefixCalculate(path, pl1)
	assert.Equal(t, false, match1)
	pl2, _ := NewPrefix("2001:123:123::/48", "65..66")
	match2 := ipPrefixCalculate(path, pl2)
	assert.Equal(t, false, match2)
	pl3, _ := NewPrefix("2001:123:123::/48", "63..65")
	match3 := ipPrefixCalculate(path, pl3)
	assert.Equal(t, true, match3)
}

func TestPolicyNotMatch(t *testing.T) {
	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]

	// create policy
	ps := createPrefixSet("ps1", "10.3.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")
	ds := config.DefinedSets{}
	ds.PrefixSets.PrefixSetList = []config.PrefixSet{ps}
	ds.NeighborSets.NeighborSetList = []config.NeighborSet{ns}
	s := createStatement("statement1", "ps1", "ns1", false)
	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitions.PolicyDefinitionList[0], df)
	pType, newPath := p.Apply(path)
	assert.Equal(t, ROUTE_TYPE_NONE, pType)
	assert.Equal(t, newPath, path)
}

func TestPolicyMatchAndReject(t *testing.T) {
	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")
	ds := config.DefinedSets{}
	ds.PrefixSets.PrefixSetList = []config.PrefixSet{ps}
	ds.NeighborSets.NeighborSetList = []config.NeighborSet{ns}

	s := createStatement("statement1", "ps1", "ns1", false)
	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitions.PolicyDefinitionList[0], df)
	pType, newPath := p.Apply(path)
	assert.Equal(t, ROUTE_TYPE_REJECT, pType)
	assert.Equal(t, newPath, path)
}

func TestPolicyMatchAndAccept(t *testing.T) {
	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")
	ds := config.DefinedSets{}
	ds.PrefixSets.PrefixSetList = []config.PrefixSet{ps}
	ds.NeighborSets.NeighborSetList = []config.NeighborSet{ns}

	s := createStatement("statement1", "ps1", "ns1", true)
	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitions.PolicyDefinitionList[0], df)
	pType, newPath := p.Apply(path)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.Equal(t, path, newPath)
}

func TestPolicyRejectOnlyPrefixSet(t *testing.T) {
	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.1.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.1.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.1.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path1 := table.ProcessMessage(updateMsg, peer)[0]

	peer = &table.PeerInfo{AS: 65002, Address: net.ParseIP("10.0.2.2")}
	origin = bgp.NewPathAttributeOrigin(0)
	aspathParam = []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65002})}
	aspath = bgp.NewPathAttributeAsPath(aspathParam)
	nexthop = bgp.NewPathAttributeNextHop("10.0.2.2")
	med = bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes = []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri = []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.9.2.102")}
	updateMsg = bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path2 := table.ProcessMessage(updateMsg, peer)[0]

	// create policy
	ps := createPrefixSet("ps1", "10.10.1.0/16", "21..24")
	ds := config.DefinedSets{}
	ds.PrefixSets.PrefixSetList = []config.PrefixSet{ps}

	s := createStatement("statement1", "ps1", "ns1", false)
	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitions.PolicyDefinitionList[0], df)
	pType, newPath := p.Apply(path1)
	assert.Equal(t, ROUTE_TYPE_REJECT, pType)
	assert.Equal(t, newPath, path1)

	pType2, newPath2 := p.Apply(path2)
	assert.Equal(t, ROUTE_TYPE_NONE, pType2)
	assert.Equal(t, newPath2, path2)
}

func TestPolicyRejectOnlyNeighborSet(t *testing.T) {
	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.1.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.1.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.1.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path1 := table.ProcessMessage(updateMsg, peer)[0]

	peer = &table.PeerInfo{AS: 65002, Address: net.ParseIP("10.0.2.2")}
	origin = bgp.NewPathAttributeOrigin(0)
	aspathParam = []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65002})}
	aspath = bgp.NewPathAttributeAsPath(aspathParam)
	nexthop = bgp.NewPathAttributeNextHop("10.0.2.2")
	med = bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes = []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri = []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.2.102")}
	updateMsg = bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path2 := table.ProcessMessage(updateMsg, peer)[0]

	// create policy
	ns := createNeighborSet("ns1", "10.0.1.1")
	ds := config.DefinedSets{}
	ds.NeighborSets.NeighborSetList = []config.NeighborSet{ns}

	s := createStatement("statement1", "ps1", "ns1", false)
	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitions.PolicyDefinitionList[0], df)
	pType, newPath := p.Apply(path1)
	assert.Equal(t, ROUTE_TYPE_REJECT, pType)
	assert.Equal(t, newPath, path1)

	pType2, newPath2 := p.Apply(path2)
	assert.Equal(t, ROUTE_TYPE_NONE, pType2)
	assert.Equal(t, newPath2, path2)
}

func TestPolicyDifferentRoutefamilyOfPathAndPolicy(t *testing.T) {
	// create path ipv4
	peerIPv4 := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	originIPv4 := bgp.NewPathAttributeOrigin(0)
	aspathParamIPv4 := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspathIPv4 := bgp.NewPathAttributeAsPath(aspathParamIPv4)
	nexthopIPv4 := bgp.NewPathAttributeNextHop("10.0.0.1")
	medIPv4 := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributesIPv4 := []bgp.PathAttributeInterface{originIPv4, aspathIPv4, nexthopIPv4, medIPv4}
	nlriIPv4 := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsgIPv4 := bgp.NewBGPUpdateMessage(nil, pathAttributesIPv4, nlriIPv4)
	pathIPv4 := table.ProcessMessage(updateMsgIPv4, peerIPv4)[0]
	// create path ipv6
	peerIPv6 := &table.PeerInfo{AS: 65001, Address: net.ParseIP("2001::192:168:50:1")}
	originIPv6 := bgp.NewPathAttributeOrigin(0)
	aspathParamIPv6 := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspathIPv6 := bgp.NewPathAttributeAsPath(aspathParamIPv6)
	mpnlriIPv6 := []bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")}
	mpreachIPv6 := bgp.NewPathAttributeMpReachNLRI("2001::192:168:50:1", mpnlriIPv6)
	medIPv6 := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributesIPv6 := []bgp.PathAttributeInterface{mpreachIPv6, originIPv6, aspathIPv6, medIPv6}
	updateMsgIPv6 := bgp.NewBGPUpdateMessage(nil, pathAttributesIPv6, nil)
	pathIPv6 := table.ProcessMessage(updateMsgIPv6, peerIPv6)[0]
	// create policy
	psIPv4 := createPrefixSet("psIPv4", "10.10.0.0/16", "21..24")
	nsIPv4 := createNeighborSet("nsIPv4", "10.0.0.1")

	psIPv6 := createPrefixSet("psIPv6", "2001:123:123::/48", "64..80")
	nsIPv6 := createNeighborSet("nsIPv6", "2001::192:168:50:1")

	ds := config.DefinedSets{}
	ds.PrefixSets.PrefixSetList = []config.PrefixSet{psIPv4, psIPv6}
	ds.NeighborSets.NeighborSetList = []config.NeighborSet{nsIPv4, nsIPv6}

	stIPv4 := createStatement("statement1", "psIPv4", "nsIPv4", false)
	stIPv6 := createStatement("statement2", "psIPv6", "nsIPv6", false)

	pd := createPolicyDefinition("pd1", stIPv4, stIPv6)
	pl := createRoutingPolicy(ds, pd)

	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitions.PolicyDefinitionList[0], df)
	pType1, newPath1 := p.Apply(pathIPv4)
	assert.Equal(t, ROUTE_TYPE_REJECT, pType1)
	assert.Equal(t, newPath1, pathIPv4)

	pType2, newPath2 := p.Apply(pathIPv6)
	assert.Equal(t, ROUTE_TYPE_REJECT, pType2)
	assert.Equal(t, newPath2, pathIPv6)
}

func TestAsPathLengthConditionEvaluate(t *testing.T) {
	// setup
	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
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
	table.UpdatePathAttrs4ByteAs(updateMsg.Body.(*bgp.BGPUpdate))
	path := table.ProcessMessage(updateMsg, peer)[0]

	// create match condition
	asPathLength := config.AsPathLength{
		Operator: "eq",
		Value:    5,
	}
	c := NewAsPathLengthCondition(asPathLength)

	// test
	assert.Equal(t, true, c.evaluate(path))

	// create match condition
	asPathLength = config.AsPathLength{
		Operator: "ge",
		Value:    3,
	}
	c = NewAsPathLengthCondition(asPathLength)

	// test
	assert.Equal(t, true, c.evaluate(path))

	// create match condition
	asPathLength = config.AsPathLength{
		Operator: "le",
		Value:    3,
	}
	c = NewAsPathLengthCondition(asPathLength)

	// test
	assert.Equal(t, false, c.evaluate(path))
}

func TestAsPathLengthConditionWithOtherCondition(t *testing.T) {
	// setup
	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
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
	table.UpdatePathAttrs4ByteAs(updateMsg.Body.(*bgp.BGPUpdate))
	path := table.ProcessMessage(updateMsg, peer)[0]

	// create policy
	ps := createPrefixSet("ps1", "10.10.1.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := config.DefinedSets{}
	ds.PrefixSets.PrefixSetList = []config.PrefixSet{ps}
	ds.NeighborSets.NeighborSetList = []config.NeighborSet{ns}

	// create match condition
	asPathLength := config.AsPathLength{
		Operator: "le",
		Value:    10,
	}

	s := createStatement("statement1", "ps1", "ns1", false)
	s.Conditions.BgpConditions.AsPathLength = asPathLength
	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitions.PolicyDefinitionList[0], df)
	pType, newPath := p.Apply(path)
	assert.Equal(t, ROUTE_TYPE_REJECT, pType)
	assert.Equal(t, newPath, path)

}

func TestAsPathConditionEvaluate(t *testing.T) {

	// setup
	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
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
	table.UpdatePathAttrs4ByteAs(updateMsg1.Body.(*bgp.BGPUpdate))
	path1 := table.ProcessMessage(updateMsg1, peer)[0]

	aspathParam2 := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(2, []uint16{65010}),
	}
	aspath2 := bgp.NewPathAttributeAsPath(aspathParam2)
	pathAttributes = []bgp.PathAttributeInterface{origin, aspath2, nexthop, med}
	updateMsg2 := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	table.UpdatePathAttrs4ByteAs(updateMsg2.Body.(*bgp.BGPUpdate))
	path2 := table.ProcessMessage(updateMsg2, peer)[0]

	// create match condition
	asPathSet1 := config.AsPathSet{
		AsPathSetName: "asset1",
		AsPathList: []config.AsPath{
			config.AsPath{AsPath: "^65001"},
		},
	}

	asPathSet2 := config.AsPathSet{
		AsPathSetName: "asset2",
		AsPathList: []config.AsPath{
			config.AsPath{AsPath: "65005$"},
		},
	}

	asPathSet3 := config.AsPathSet{
		AsPathSetName: "asset3",
		AsPathList: []config.AsPath{
			config.AsPath{AsPath: "65004"},
			config.AsPath{AsPath: "65005$"},
		},
	}

	asPathSet4 := config.AsPathSet{
		AsPathSetName: "asset4",
		AsPathList: []config.AsPath{
			config.AsPath{AsPath: "65000$"},
		},
	}

	asPathSet5 := config.AsPathSet{
		AsPathSetName: "asset5",
		AsPathList: []config.AsPath{
			config.AsPath{AsPath: "65010"},
		},
	}

	asPathSet6 := config.AsPathSet{
		AsPathSetName: "asset6",
		AsPathList: []config.AsPath{
			config.AsPath{AsPath: "^65010$"},
		},
	}

	asPathSetList := []config.AsPathSet{asPathSet1, asPathSet2, asPathSet3,
		asPathSet4, asPathSet5, asPathSet6}

	createAspathC := func(name string, option config.MatchSetOptionsType) *AsPathCondition {
		matchSet := config.MatchAsPathSet{}
		matchSet.AsPathSet = name
		matchSet.MatchSetOptions = option
		p := NewAsPathCondition(matchSet, asPathSetList)
		return p
	}

	p1 := createAspathC("asset1", config.MATCH_SET_OPTIONS_TYPE_ANY)
	p2 := createAspathC("asset2", config.MATCH_SET_OPTIONS_TYPE_ANY)
	p3 := createAspathC("asset3", config.MATCH_SET_OPTIONS_TYPE_ANY)
	p4 := createAspathC("asset4", config.MATCH_SET_OPTIONS_TYPE_ANY)
	p5 := createAspathC("asset5", config.MATCH_SET_OPTIONS_TYPE_ANY)
	p6 := createAspathC("asset6", config.MATCH_SET_OPTIONS_TYPE_ANY)

	//TODO: add ALL and INVERT cases.
	p7 := createAspathC("asset3", config.MATCH_SET_OPTIONS_TYPE_ALL)
	p8 := createAspathC("asset3", config.MATCH_SET_OPTIONS_TYPE_INVERT)

	// test
	assert.Equal(t, true, p1.evaluate(path1))
	assert.Equal(t, true, p2.evaluate(path1))
	assert.Equal(t, true, p3.evaluate(path1))
	assert.Equal(t, false, p4.evaluate(path1))
	assert.Equal(t, true, p5.evaluate(path1))
	assert.Equal(t, false, p6.evaluate(path1))
	assert.Equal(t, true, p6.evaluate(path2))

	assert.Equal(t, true, p7.evaluate(path1))
	assert.Equal(t, true, p8.evaluate(path2))
}

func TestMultipleAsPathConditionEvaluate(t *testing.T) {

	// setup
	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
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
	table.UpdatePathAttrs4ByteAs(updateMsg1.Body.(*bgp.BGPUpdate))
	path1 := table.ProcessMessage(updateMsg1, peer)[0]

	// create match condition
	asPathSet1 := config.AsPathSet{
		AsPathSetName: "asset1",
		AsPathList: []config.AsPath{
			config.AsPath{AsPath: "^65001_65000"},
		},
	}

	asPathSet2 := config.AsPathSet{
		AsPathSetName: "asset2",
		AsPathList: []config.AsPath{
			config.AsPath{AsPath: "65004_65005$"},
		},
	}

	asPathSet3 := config.AsPathSet{
		AsPathSetName: "asset3",
		AsPathList: []config.AsPath{
			config.AsPath{AsPath: "65001_65000_54000"},
		},
	}

	asPathSet4 := config.AsPathSet{
		AsPathSetName: "asset4",
		AsPathList: []config.AsPath{
			config.AsPath{AsPath: "54000_65004_65005"},
		},
	}

	asPathSet5 := config.AsPathSet{
		AsPathSetName: "asset5",
		AsPathList: []config.AsPath{
			config.AsPath{AsPath: "^65001 65000 54000 65004 65005$"},
		},
	}

	asPathSet6 := config.AsPathSet{
		AsPathSetName: "asset6",
		AsPathList: []config.AsPath{
			config.AsPath{AsPath: ".*_[0-9]+_65005"},
		},
	}

	asPathSet7 := config.AsPathSet{
		AsPathSetName: "asset7",
		AsPathList: []config.AsPath{
			config.AsPath{AsPath: ".*_5[0-9]+_[0-9]+"},
		},
	}

	asPathSet8 := config.AsPathSet{
		AsPathSetName: "asset8",
		AsPathList: []config.AsPath{
			config.AsPath{AsPath: "6[0-9]+_6[0-9]+_5[0-9]+"},
		},
	}

	asPathSet9 := config.AsPathSet{
		AsPathSetName: "asset9",
		AsPathList: []config.AsPath{
			config.AsPath{AsPath: "6[0-9]+__6[0-9]+"},
		},
	}

	asPathSetList := []config.AsPathSet{asPathSet1, asPathSet2, asPathSet3,
		asPathSet4, asPathSet5, asPathSet6, asPathSet7, asPathSet8, asPathSet9}

	createAspathC := func(name string, option config.MatchSetOptionsType) *AsPathCondition {
		matchSet := config.MatchAsPathSet{}
		matchSet.AsPathSet = name
		matchSet.MatchSetOptions = option
		p := NewAsPathCondition(matchSet, asPathSetList)
		return p
	}

	p1 := createAspathC("asset1", config.MATCH_SET_OPTIONS_TYPE_ANY)
	p2 := createAspathC("asset2", config.MATCH_SET_OPTIONS_TYPE_ANY)
	p3 := createAspathC("asset3", config.MATCH_SET_OPTIONS_TYPE_ANY)
	p4 := createAspathC("asset4", config.MATCH_SET_OPTIONS_TYPE_ANY)
	p5 := createAspathC("asset5", config.MATCH_SET_OPTIONS_TYPE_ANY)
	p6 := createAspathC("asset6", config.MATCH_SET_OPTIONS_TYPE_ANY)
	p7 := createAspathC("asset7", config.MATCH_SET_OPTIONS_TYPE_ANY)
	p8 := createAspathC("asset8", config.MATCH_SET_OPTIONS_TYPE_ANY)
	p9 := createAspathC("asset9", config.MATCH_SET_OPTIONS_TYPE_ANY)

	// test
	assert.Equal(t, true, p1.evaluate(path1))
	assert.Equal(t, true, p2.evaluate(path1))
	assert.Equal(t, true, p3.evaluate(path1))
	assert.Equal(t, true, p4.evaluate(path1))
	assert.Equal(t, true, p5.evaluate(path1))
	assert.Equal(t, true, p6.evaluate(path1))
	assert.Equal(t, true, p7.evaluate(path1))
	assert.Equal(t, true, p8.evaluate(path1))
	assert.Equal(t, false, p9.evaluate(path1))
}

func TestAsPathCondition(t *testing.T) {
	type astest struct {
		path   *table.Path
		result bool
	}

	makeTest := func(asPathAttrType uint8, ases []uint32, result bool) astest {
		aspathParam := []bgp.AsPathParamInterface{
			bgp.NewAs4PathParam(asPathAttrType, ases),
		}
		pathAttributes := []bgp.PathAttributeInterface{bgp.NewPathAttributeAsPath(aspathParam)}
		p := table.NewPath(nil, nil, false, pathAttributes, false, time.Time{}, false)
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

	for k, v := range tests {
		r, _ := regexp.Compile(strings.Replace(k, "_", ASPATH_REGEXP_MAGIC, -1))
		c := &AsPathCondition{
			AsRegExpList: []*regexp.Regexp{r},
			MatchOption:  config.MATCH_SET_OPTIONS_TYPE_ANY,
		}
		for _, a := range v {
			result := c.evaluate(a.path)
			if a.result != result {
				log.WithFields(log.Fields{
					"EXP":      k,
					"ASN":      r,
					"ASSTR":    a.path.GetAsString(),
					"Expected": a.result,
					"Result":   result,
				}).Fatal("failed")
			}
		}
	}
}

func TestAsPathConditionWithOtherCondition(t *testing.T) {

	// setup
	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
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
	table.UpdatePathAttrs4ByteAs(updateMsg.Body.(*bgp.BGPUpdate))
	path := table.ProcessMessage(updateMsg, peer)[0]

	// create policy
	asPathSet := config.AsPathSet{
		AsPathSetName: "asset1",
		AsPathList:    []config.AsPath{config.AsPath{"65005$"}},
	}

	ps := createPrefixSet("ps1", "10.10.1.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := config.DefinedSets{}
	ds.PrefixSets.PrefixSetList = []config.PrefixSet{ps}
	ds.NeighborSets.NeighborSetList = []config.NeighborSet{ns}
	ds.BgpDefinedSets.AsPathSets.AsPathSetList = []config.AsPathSet{asPathSet}

	s := createStatement("statement1", "ps1", "ns1", false)
	s.Conditions.BgpConditions.MatchAsPathSet.AsPathSet = "asset1"

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitions.PolicyDefinitionList[0], df)
	pType, newPath := p.Apply(path)
	assert.Equal(t, ROUTE_TYPE_REJECT, pType)
	assert.Equal(t, newPath, path)

}

func TestCommunityConditionEvaluate(t *testing.T) {

	log.SetLevel(log.DebugLevel)

	// setup
	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
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
	table.UpdatePathAttrs4ByteAs(updateMsg1.Body.(*bgp.BGPUpdate))
	path1 := table.ProcessMessage(updateMsg1, peer)[0]

	// create match condition
	comSet1 := config.CommunitySet{
		CommunitySetName: "comset1",
		CommunityList: []config.Community{
			config.Community{"65001:10"},
			config.Community{"65001:50"},
			config.Community{"65001:100"},
		},
	}

	comSet2 := config.CommunitySet{
		CommunitySetName: "comset2",
		CommunityList: []config.Community{
			config.Community{"65001:200"},
		},
	}

	comSet3 := config.CommunitySet{
		CommunitySetName: "comset3",
		CommunityList: []config.Community{
			config.Community{"4259905936"},
		},
	}

	comSet4 := config.CommunitySet{
		CommunitySetName: "comset4",
		CommunityList: []config.Community{
			config.Community{"^[0-9]*:300$"},
		},
	}

	comSet5 := config.CommunitySet{
		CommunitySetName: "comset5",
		CommunityList: []config.Community{
			config.Community{"INTERNET"},
		},
	}

	comSet6 := config.CommunitySet{
		CommunitySetName: "comset6",
		CommunityList: []config.Community{
			config.Community{"NO_EXPORT"},
		},
	}

	comSet7 := config.CommunitySet{
		CommunitySetName: "comset7",
		CommunityList: []config.Community{
			config.Community{"NO_ADVERTISE"},
		},
	}

	comSet8 := config.CommunitySet{
		CommunitySetName: "comset8",
		CommunityList: []config.Community{
			config.Community{"NO_EXPORT_SUBCONFED"},
		},
	}

	comSet9 := config.CommunitySet{
		CommunitySetName: "comset9",
		CommunityList: []config.Community{
			config.Community{"65001:100"},
			config.Community{"65001:200"},
			config.Community{"65001:300"},
		},
	}

	comSet10 := config.CommunitySet{
		CommunitySetName: "comset10",
		CommunityList: []config.Community{
			config.Community{"65001:1"},
			config.Community{"65001:2"},
			config.Community{"65001:3"},
		},
	}

	comSetList := []config.CommunitySet{comSet1, comSet2, comSet3,
		comSet4, comSet5, comSet6, comSet7, comSet8, comSet9, comSet10}

	createCommunityC := func(name string, option config.MatchSetOptionsType) *CommunityCondition {
		matchSet := config.MatchCommunitySet{}
		matchSet.CommunitySet = name
		matchSet.MatchSetOptions = option
		c := NewCommunityCondition(matchSet, comSetList)
		return c
	}

	// ANY case
	p1 := createCommunityC("comset1", config.MATCH_SET_OPTIONS_TYPE_ANY)
	p2 := createCommunityC("comset2", config.MATCH_SET_OPTIONS_TYPE_ANY)
	p3 := createCommunityC("comset3", config.MATCH_SET_OPTIONS_TYPE_ANY)
	p4 := createCommunityC("comset4", config.MATCH_SET_OPTIONS_TYPE_ANY)
	p5 := createCommunityC("comset5", config.MATCH_SET_OPTIONS_TYPE_ANY)
	p6 := createCommunityC("comset6", config.MATCH_SET_OPTIONS_TYPE_ANY)
	p7 := createCommunityC("comset7", config.MATCH_SET_OPTIONS_TYPE_ANY)
	p8 := createCommunityC("comset8", config.MATCH_SET_OPTIONS_TYPE_ANY)

	// ALL case
	p9 := createCommunityC("comset9", config.MATCH_SET_OPTIONS_TYPE_ALL)

	// INVERT case
	p10 := createCommunityC("comset10", config.MATCH_SET_OPTIONS_TYPE_INVERT)

	// test
	assert.Equal(t, true, p1.evaluate(path1))
	assert.Equal(t, true, p2.evaluate(path1))
	assert.Equal(t, true, p3.evaluate(path1))
	assert.Equal(t, true, p4.evaluate(path1))
	assert.Equal(t, true, p5.evaluate(path1))
	assert.Equal(t, true, p6.evaluate(path1))
	assert.Equal(t, true, p7.evaluate(path1))
	assert.Equal(t, true, p8.evaluate(path1))
	assert.Equal(t, true, p9.evaluate(path1))
	assert.Equal(t, true, p10.evaluate(path1))

}

func TestCommunityConditionEvaluateWithOtherCondition(t *testing.T) {

	// setup
	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
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
	table.UpdatePathAttrs4ByteAs(updateMsg.Body.(*bgp.BGPUpdate))
	path := table.ProcessMessage(updateMsg, peer)[0]

	// create policy
	asPathSet := config.AsPathSet{
		AsPathSetName: "asset1",
		AsPathList: []config.AsPath{
			config.AsPath{"65005$"},
		},
	}

	comSet1 := config.CommunitySet{
		CommunitySetName: "comset1",
		CommunityList: []config.Community{
			config.Community{"65001:100"},
			config.Community{"65001:200"},
			config.Community{"65001:300"},
		},
	}

	comSet2 := config.CommunitySet{
		CommunitySetName: "comset2",
		CommunityList: []config.Community{
			config.Community{"65050:\\d+"},
		},
	}

	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := config.DefinedSets{}
	ds.PrefixSets.PrefixSetList = []config.PrefixSet{ps}
	ds.NeighborSets.NeighborSetList = []config.NeighborSet{ns}
	ds.BgpDefinedSets.AsPathSets.AsPathSetList = []config.AsPathSet{asPathSet}
	ds.BgpDefinedSets.CommunitySets.CommunitySetList = []config.CommunitySet{comSet1, comSet2}

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
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitions.PolicyDefinitionList[0], df)
	pType, newPath := p.Apply(path)
	assert.Equal(t, ROUTE_TYPE_REJECT, pType)
	assert.Equal(t, newPath, path)

	df = pl.DefinedSets
	p = NewPolicy(pl.PolicyDefinitions.PolicyDefinitionList[1], df)
	pType, newPath = p.Apply(path)
	assert.Equal(t, ROUTE_TYPE_NONE, pType)
	assert.Equal(t, newPath, path)

}

func TestPolicyMatchAndAddCommunities(t *testing.T) {

	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := config.DefinedSets{}
	ds.PrefixSets.PrefixSetList = []config.PrefixSet{ps}
	ds.NeighborSets.NeighborSetList = []config.NeighborSet{ns}

	community := "65000:100"

	s := createStatement("statement1", "ps1", "ns1", true)
	s.Actions.BgpActions.SetCommunity = createSetCommunity("ADD", community)

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitions.PolicyDefinitionList[0], df)

	pType, newPath := p.Apply(path)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)
	log.Debug(newPath)
	assert.Equal(t, []uint32{stringToCommunityValue(community)}, newPath.GetCommunities())
}

func TestPolicyMatchAndReplaceCommunities(t *testing.T) {

	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
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
	path := table.ProcessMessage(updateMsg, peer)[0]
	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := config.DefinedSets{}
	ds.PrefixSets.PrefixSetList = []config.PrefixSet{ps}
	ds.NeighborSets.NeighborSetList = []config.NeighborSet{ns}

	community := "65000:100"

	s := createStatement("statement1", "ps1", "ns1", true)
	s.Actions.BgpActions.SetCommunity = createSetCommunity("REPLACE", community)

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitions.PolicyDefinitionList[0], df)

	pType, newPath := p.Apply(path)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)
	assert.Equal(t, []uint32{stringToCommunityValue(community)}, newPath.GetCommunities())
}

func TestPolicyMatchAndRemoveCommunities(t *testing.T) {

	// create path
	community1 := "65000:100"
	community2 := "65000:200"
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
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
	path := table.ProcessMessage(updateMsg, peer)[0]
	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := config.DefinedSets{}
	ds.PrefixSets.PrefixSetList = []config.PrefixSet{ps}
	ds.NeighborSets.NeighborSetList = []config.NeighborSet{ns}

	s := createStatement("statement1", "ps1", "ns1", true)
	s.Actions.BgpActions.SetCommunity = createSetCommunity("REMOVE", community1)

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitions.PolicyDefinitionList[0], df)
	pType, newPath := p.Apply(path)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)
	assert.Equal(t, []uint32{stringToCommunityValue(community2)}, newPath.GetCommunities())
}

func TestPolicyMatchAndRemoveCommunitiesRegexp(t *testing.T) {

	// create path
	community1 := "65000:100"
	community2 := "65000:200"
	community3 := "65100:100"
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
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
	path := table.ProcessMessage(updateMsg, peer)[0]
	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := config.DefinedSets{}
	ds.PrefixSets.PrefixSetList = []config.PrefixSet{ps}
	ds.NeighborSets.NeighborSetList = []config.NeighborSet{ns}

	s := createStatement("statement1", "ps1", "ns1", true)
	s.Actions.BgpActions.SetCommunity = createSetCommunity("REMOVE", ".*:100")

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitions.PolicyDefinitionList[0], df)
	pType, newPath := p.Apply(path)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)
	assert.Equal(t, []uint32{stringToCommunityValue(community2)}, newPath.GetCommunities())
}

func TestPolicyMatchAndRemoveCommunitiesRegexp2(t *testing.T) {

	// create path
	community1 := "0:1"
	community2 := "10:1"
	community3 := "45686:2"
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
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
	path := table.ProcessMessage(updateMsg, peer)[0]
	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := config.DefinedSets{}
	ds.PrefixSets.PrefixSetList = []config.PrefixSet{ps}
	ds.NeighborSets.NeighborSetList = []config.NeighborSet{ns}

	s := createStatement("statement1", "ps1", "ns1", true)
	s.Actions.BgpActions.SetCommunity = createSetCommunity("REMOVE", "^(0|45686):[0-9]+")

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitions.PolicyDefinitionList[0], df)
	pType, newPath := p.Apply(path)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)
	assert.Equal(t, []uint32{stringToCommunityValue(community2)}, newPath.GetCommunities())
}

func TestPolicyMatchAndClearCommunities(t *testing.T) {

	// create path
	community1 := "65000:100"
	community2 := "65000:200"
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
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
	path := table.ProcessMessage(updateMsg, peer)[0]
	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := config.DefinedSets{}
	ds.PrefixSets.PrefixSetList = []config.PrefixSet{ps}
	ds.NeighborSets.NeighborSetList = []config.NeighborSet{ns}

	s := createStatement("statement1", "ps1", "ns1", true)
	// action NULL is obsolate
	s.Actions.BgpActions.SetCommunity.Options = "REPLACE"
	s.Actions.BgpActions.SetCommunity.SetCommunityMethod.Communities = nil

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitions.PolicyDefinitionList[0], df)

	pType, newPath := p.Apply(path)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)
	//assert.Equal(t, []uint32{}, newPath.GetCommunities())
}

func TestExtCommunityConditionEvaluate(t *testing.T) {

	log.SetLevel(log.DebugLevel)

	// setup
	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
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
	table.UpdatePathAttrs4ByteAs(updateMsg1.Body.(*bgp.BGPUpdate))
	path1 := table.ProcessMessage(updateMsg1, peer)[0]

	convUintStr := func(as uint32) string {
		upper := strconv.FormatUint(uint64(as&0xFFFF0000>>16), 10)
		lower := strconv.FormatUint(uint64(as&0x0000FFFF), 10)
		str := fmt.Sprintf("%s.%s", upper, lower)
		return str
	}

	// create match condition
	ecomSet1 := config.ExtCommunitySet{
		ExtCommunitySetName: "ecomSet1",
		ExtCommunityList: []config.ExtCommunity{
			config.ExtCommunity{"RT:65001:200"},
		},
	}
	ecomSet2 := config.ExtCommunitySet{
		ExtCommunitySetName: "ecomSet2",
		ExtCommunityList: []config.ExtCommunity{
			config.ExtCommunity{"RT:10.0.0.1:300"},
		},
	}
	ecomSet3 := config.ExtCommunitySet{
		ExtCommunitySetName: "ecomSet3",
		ExtCommunityList: []config.ExtCommunity{
			config.ExtCommunity{fmt.Sprintf("RT:%s:200", convUintStr(65030000))},
		},
	}
	ecomSet4 := config.ExtCommunitySet{
		ExtCommunitySetName: "ecomSet4",
		ExtCommunityList: []config.ExtCommunity{
			config.ExtCommunity{"RT:65002:200"},
		},
	}
	ecomSet5 := config.ExtCommunitySet{
		ExtCommunitySetName: "ecomSet5",
		ExtCommunityList: []config.ExtCommunity{
			config.ExtCommunity{"RT:10.0.0.2:300"},
		},
	}
	ecomSet6 := config.ExtCommunitySet{
		ExtCommunitySetName: "ecomSet6",
		ExtCommunityList: []config.ExtCommunity{
			config.ExtCommunity{fmt.Sprintf("RT:%s:200", convUintStr(65030001))},
		},
	}
	ecomSet7 := config.ExtCommunitySet{
		ExtCommunitySetName: "ecomSet7",
		ExtCommunityList: []config.ExtCommunity{
			config.ExtCommunity{"SoO:65010:300"},
		},
	}
	ecomSet8 := config.ExtCommunitySet{
		ExtCommunitySetName: "ecomSet8",
		ExtCommunityList: []config.ExtCommunity{
			config.ExtCommunity{"SoO:10.0.10.10:[0-9]+"},
		},
	}
	ecomSet9 := config.ExtCommunitySet{
		ExtCommunitySetName: "ecomSet9",
		ExtCommunityList: []config.ExtCommunity{
			config.ExtCommunity{"RT:[0-9]+:[0-9]+"},
		},
	}
	ecomSet10 := config.ExtCommunitySet{
		ExtCommunitySetName: "ecomSet10",
		ExtCommunityList: []config.ExtCommunity{
			config.ExtCommunity{"RT:65001:200"},
			config.ExtCommunity{"RT:10.0.0.1:300"},
			config.ExtCommunity{"SoO:10.0.10.10:[0-9]+"},
		},
	}

	ecomSet11 := config.ExtCommunitySet{
		ExtCommunitySetName: "ecomSet11",
		ExtCommunityList: []config.ExtCommunity{
			config.ExtCommunity{"RT:65001:2"},
			config.ExtCommunity{"RT:10.0.0.1:3"},
			config.ExtCommunity{"SoO:11.0.10.10:[0-9]+"},
		},
	}

	comSetList := []config.ExtCommunitySet{ecomSet1, ecomSet2, ecomSet3, ecomSet4, ecomSet5, ecomSet6, ecomSet7,
		ecomSet8, ecomSet9, ecomSet10, ecomSet11}

	createExtCommunityC := func(name string, option config.MatchSetOptionsType) *ExtCommunityCondition {
		matchSet := config.MatchExtCommunitySet{}
		matchSet.ExtCommunitySet = name
		matchSet.MatchSetOptions = option
		c := NewExtCommunityCondition(matchSet, comSetList)
		return c
	}

	p1 := createExtCommunityC("ecomSet1", config.MATCH_SET_OPTIONS_TYPE_ANY)
	p2 := createExtCommunityC("ecomSet2", config.MATCH_SET_OPTIONS_TYPE_ANY)
	p3 := createExtCommunityC("ecomSet3", config.MATCH_SET_OPTIONS_TYPE_ANY)
	p4 := createExtCommunityC("ecomSet4", config.MATCH_SET_OPTIONS_TYPE_ANY)
	p5 := createExtCommunityC("ecomSet5", config.MATCH_SET_OPTIONS_TYPE_ANY)
	p6 := createExtCommunityC("ecomSet6", config.MATCH_SET_OPTIONS_TYPE_ANY)
	p7 := createExtCommunityC("ecomSet7", config.MATCH_SET_OPTIONS_TYPE_ANY)
	p8 := createExtCommunityC("ecomSet8", config.MATCH_SET_OPTIONS_TYPE_ANY)
	p9 := createExtCommunityC("ecomSet9", config.MATCH_SET_OPTIONS_TYPE_ANY)

	// ALL case
	p10 := createExtCommunityC("ecomSet10", config.MATCH_SET_OPTIONS_TYPE_ALL)

	// INVERT case
	p11 := createExtCommunityC("ecomSet11", config.MATCH_SET_OPTIONS_TYPE_INVERT)

	// test
	assert.Equal(t, true, p1.evaluate(path1))
	assert.Equal(t, true, p2.evaluate(path1))
	assert.Equal(t, true, p3.evaluate(path1))
	assert.Equal(t, false, p4.evaluate(path1))
	assert.Equal(t, false, p5.evaluate(path1))
	assert.Equal(t, false, p6.evaluate(path1))
	assert.Equal(t, true, p7.evaluate(path1))
	assert.Equal(t, true, p8.evaluate(path1))
	assert.Equal(t, true, p9.evaluate(path1))
	assert.Equal(t, true, p10.evaluate(path1))
	assert.Equal(t, true, p11.evaluate(path1))

}

func TestExtCommunityConditionEvaluateWithOtherCondition(t *testing.T) {

	log.SetLevel(log.DebugLevel)

	// setup
	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.2.1.1")}
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
	table.UpdatePathAttrs4ByteAs(updateMsg.Body.(*bgp.BGPUpdate))
	path := table.ProcessMessage(updateMsg, peer)[0]

	// create policy
	asPathSet := config.AsPathSet{
		AsPathSetName: "asset1",
		AsPathList: []config.AsPath{
			config.AsPath{"65005$"},
		},
	}

	ecomSet1 := config.ExtCommunitySet{
		ExtCommunitySetName: "ecomSet1",
		ExtCommunityList: []config.ExtCommunity{
			config.ExtCommunity{"RT:65001:201"},
		},
	}
	ecomSet2 := config.ExtCommunitySet{
		ExtCommunitySetName: "ecomSet2",
		ExtCommunityList: []config.ExtCommunity{
			config.ExtCommunity{"RT:[0-9]+:[0-9]+"},
		},
	}

	ps := createPrefixSet("ps1", "10.10.1.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.2.1.1")

	ds := config.DefinedSets{}
	ds.PrefixSets.PrefixSetList = []config.PrefixSet{ps}
	ds.NeighborSets.NeighborSetList = []config.NeighborSet{ns}
	ds.BgpDefinedSets.AsPathSets.AsPathSetList = []config.AsPathSet{asPathSet}
	ds.BgpDefinedSets.ExtCommunitySets.ExtCommunitySetList = []config.ExtCommunitySet{ecomSet1, ecomSet2}

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
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitions.PolicyDefinitionList[0], df)
	pType, newPath := p.Apply(path)
	assert.Equal(t, ROUTE_TYPE_NONE, pType)
	assert.Equal(t, newPath, path)

	p = NewPolicy(pl.PolicyDefinitions.PolicyDefinitionList[1], df)
	pType, newPath = p.Apply(path)
	assert.Equal(t, ROUTE_TYPE_REJECT, pType)
	assert.Equal(t, newPath, path)

}

func TestPolicyMatchAndReplaceMed(t *testing.T) {

	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(100)

	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := config.DefinedSets{}
	ds.PrefixSets.PrefixSetList = []config.PrefixSet{ps}
	ds.NeighborSets.NeighborSetList = []config.NeighborSet{ns}

	m := "200"
	s := createStatement("statement1", "ps1", "ns1", true)
	s.Actions.BgpActions.SetMed = config.BgpSetMedType(m)

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)

	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitions.PolicyDefinitionList[0], df)

	pType, newPath := p.Apply(path)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)
	v, err := newPath.GetMed()
	assert.Nil(t, err)
	newMed := fmt.Sprintf("%d", v)
	assert.Equal(t, m, newMed)
}

func TestPolicyMatchAndAddingMed(t *testing.T) {

	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(100)

	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := config.DefinedSets{}
	ds.PrefixSets.PrefixSetList = []config.PrefixSet{ps}
	ds.NeighborSets.NeighborSetList = []config.NeighborSet{ns}

	m := "+200"
	ma := "300"
	s := createStatement("statement1", "ps1", "ns1", true)
	s.Actions.BgpActions.SetMed = config.BgpSetMedType(m)

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)
	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitions.PolicyDefinitionList[0], df)
	pType, newPath := p.Apply(path)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)

	v, err := newPath.GetMed()
	assert.Nil(t, err)
	newMed := fmt.Sprintf("%d", v)
	assert.Equal(t, ma, newMed)
}

func TestPolicyMatchAndAddingMedOverFlow(t *testing.T) {

	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(1)

	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := config.DefinedSets{}
	ds.PrefixSets.PrefixSetList = []config.PrefixSet{ps}
	ds.NeighborSets.NeighborSetList = []config.NeighborSet{ns}

	m := fmt.Sprintf("+%d", math.MaxUint32)
	ma := "1"

	s := createStatement("statement1", "ps1", "ns1", true)
	s.Actions.BgpActions.SetMed = config.BgpSetMedType(m)

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)
	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitions.PolicyDefinitionList[0], df)

	pType, newPath := p.Apply(path)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)

	v, err := newPath.GetMed()
	assert.Nil(t, err)
	newMed := fmt.Sprintf("%d", v)
	assert.Equal(t, ma, newMed)
}

func TestPolicyMatchAndSubtractMed(t *testing.T) {

	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(100)

	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := config.DefinedSets{}
	ds.PrefixSets.PrefixSetList = []config.PrefixSet{ps}
	ds.NeighborSets.NeighborSetList = []config.NeighborSet{ns}

	m := "-50"
	ma := "50"

	s := createStatement("statement1", "ps1", "ns1", true)
	s.Actions.BgpActions.SetMed = config.BgpSetMedType(m)

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)
	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitions.PolicyDefinitionList[0], df)

	pType, newPath := p.Apply(path)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)

	v, err := newPath.GetMed()
	assert.Nil(t, err)
	newMed := fmt.Sprintf("%d", v)
	assert.Equal(t, ma, newMed)
}

func TestPolicyMatchAndSubtractMedUnderFlow(t *testing.T) {

	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(100)

	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := config.DefinedSets{}
	ds.PrefixSets.PrefixSetList = []config.PrefixSet{ps}
	ds.NeighborSets.NeighborSetList = []config.NeighborSet{ns}

	m := "-101"
	ma := "100"

	s := createStatement("statement1", "ps1", "ns1", true)
	s.Actions.BgpActions.SetMed = config.BgpSetMedType(m)

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)
	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitions.PolicyDefinitionList[0], df)

	pType, newPath := p.Apply(path)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)

	v, err := newPath.GetMed()
	assert.Nil(t, err)
	newMed := fmt.Sprintf("%d", v)
	assert.Equal(t, ma, newMed)
}

func TestPolicyMatchWhenPathHaveNotMed(t *testing.T) {

	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")

	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := config.DefinedSets{}
	ds.PrefixSets.PrefixSetList = []config.PrefixSet{ps}
	ds.NeighborSets.NeighborSetList = []config.NeighborSet{ns}

	m := "-50"
	s := createStatement("statement1", "ps1", "ns1", true)
	s.Actions.BgpActions.SetMed = config.BgpSetMedType(m)

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)
	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitions.PolicyDefinitionList[0], df)

	pType, newPath := p.Apply(path)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)

	_, err := newPath.GetMed()
	assert.NotNil(t, err)
}

func TestPolicyAsPathPrepend(t *testing.T) {

	assert := assert.New(t)

	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001, 65000})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)

	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)

	body := updateMsg.Body.(*bgp.BGPUpdate)
	table.UpdatePathAttrs4ByteAs(body)
	path := table.ProcessMessage(updateMsg, peer)[0]

	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := config.DefinedSets{}
	ds.PrefixSets.PrefixSetList = []config.PrefixSet{ps}
	ds.NeighborSets.NeighborSetList = []config.NeighborSet{ns}

	s := createStatement("statement1", "ps1", "ns1", true)
	s.Actions.BgpActions.SetAsPathPrepend.As = "65002"
	s.Actions.BgpActions.SetAsPathPrepend.RepeatN = 10

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)
	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitions.PolicyDefinitionList[0], df)

	pType, newPath := p.Apply(path)
	assert.Equal(ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(nil, newPath)
	assert.Equal([]uint32{65002, 65002, 65002, 65002, 65002, 65002, 65002, 65002, 65002, 65002, 65001, 65000}, newPath.GetAsSeqList())
}

func TestPolicyAsPathPrependLastAs(t *testing.T) {

	assert := assert.New(t)
	// create path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65002, 65001, 65000})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)

	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.0.101")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)

	body := updateMsg.Body.(*bgp.BGPUpdate)
	table.UpdatePathAttrs4ByteAs(body)
	path := table.ProcessMessage(updateMsg, peer)[0]

	// create policy
	ps := createPrefixSet("ps1", "10.10.0.0/16", "21..24")
	ns := createNeighborSet("ns1", "10.0.0.1")

	ds := config.DefinedSets{}
	ds.PrefixSets.PrefixSetList = []config.PrefixSet{ps}
	ds.NeighborSets.NeighborSetList = []config.NeighborSet{ns}

	s := createStatement("statement1", "ps1", "ns1", true)
	s.Actions.BgpActions.SetAsPathPrepend.As = "last-as"
	s.Actions.BgpActions.SetAsPathPrepend.RepeatN = 5

	pd := createPolicyDefinition("pd1", s)
	pl := createRoutingPolicy(ds, pd)
	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitions.PolicyDefinitionList[0], df)

	pType, newPath := p.Apply(path)
	assert.Equal(ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(nil, newPath)
	assert.Equal([]uint32{65002, 65002, 65002, 65002, 65002, 65002, 65001, 65000}, newPath.GetAsSeqList())
}

func createStatement(name, psname, nsname string, accept bool) config.Statement {

	c := config.Conditions{
		MatchPrefixSet: config.MatchPrefixSet{
			PrefixSet: psname,
		},
		MatchNeighborSet: config.MatchNeighborSet{
			NeighborSet: nsname,
		},
	}
	a := config.Actions{
		RouteDisposition: config.RouteDisposition{
			AcceptRoute: accept,
			RejectRoute: !accept,
		},
	}
	s := config.Statement{
		Name:       name,
		Conditions: c,
		Actions:    a,
	}
	return s
}

func createSetCommunity(operation string, community ...string) config.SetCommunity {

	s := config.SetCommunity{
		SetCommunityMethod: config.SetCommunityMethod{
			Communities: community,
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

func createPolicyDefinition(defName string, stmt ...config.Statement) config.PolicyDefinition {
	pd := config.PolicyDefinition{
		Name: defName,
		Statements: config.Statements{
			StatementList: stmt,
		},
	}
	return pd
}

func createRoutingPolicy(ds config.DefinedSets, pd ...config.PolicyDefinition) config.RoutingPolicy {
	pl := config.RoutingPolicy{
		DefinedSets: ds,
		PolicyDefinitions: config.PolicyDefinitions{
			PolicyDefinitionList: pd,
		},
	}
	return pl
}

func createPrefixSet(name string, prefix string, maskLength string) config.PrefixSet {
	ps := config.PrefixSet{
		PrefixSetName: name,
		PrefixList: []config.Prefix{
			config.Prefix{
				IpPrefix:        prefix,
				MasklengthRange: maskLength,
			}},
	}
	return ps
}

func createNeighborSet(name string, addr string) config.NeighborSet {
	ns := config.NeighborSet{
		NeighborSetName: name,
		NeighborInfoList: []config.NeighborInfo{
			config.NeighborInfo{
				Address: net.ParseIP(addr),
			}},
	}
	return ns
}
