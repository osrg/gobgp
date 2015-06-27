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
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/table"
	"github.com/stretchr/testify/assert"
	"net"
	"strconv"
	"strings"
	"testing"
	"fmt"
	"math"
)

func TestPrefixCalcurateNoRange(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	// creatae path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.0.101")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	updateMsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// test
	pl1, _ := NewPrefix(net.ParseIP("10.10.0.0"), 24, "")
	match1 := ipPrefixCalculate(path, pl1)
	assert.Equal(t, false, match1)
	pl2, _ := NewPrefix(net.ParseIP("10.10.0.101"), 24, "")
	match2 := ipPrefixCalculate(path, pl2)
	assert.Equal(t, true, match2)
	pl3, _ := NewPrefix(net.ParseIP("10.10.0.0"), 16, "21..24")
	match3 := ipPrefixCalculate(path, pl3)
	assert.Equal(t, true, match3)
}

func TestPrefixCalcurateAddress(t *testing.T) {
	// creatae path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.0.101")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	updateMsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// test
	pl1, _ := NewPrefix(net.ParseIP("10.11.0.0"), 16, "21..24")
	match1 := ipPrefixCalculate(path, pl1)
	assert.Equal(t, false, match1)
	pl2, _ := NewPrefix(net.ParseIP("10.10.0.0"), 16, "21..24")
	match2 := ipPrefixCalculate(path, pl2)
	assert.Equal(t, true, match2)
}

func TestPrefixCalcurateLength(t *testing.T) {
	// creatae path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.0.101")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	updateMsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// test
	pl1, _ := NewPrefix(net.ParseIP("10.10.64.0"), 24, "21..24")
	match1 := ipPrefixCalculate(path, pl1)
	assert.Equal(t, false, match1)
	pl2, _ := NewPrefix(net.ParseIP("10.10.64.0"), 16, "21..24")
	match2 := ipPrefixCalculate(path, pl2)
	assert.Equal(t, true, match2)
}

func TestPrefixCalcurateLengthRange(t *testing.T) {
	// creatae path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.0.101")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	updateMsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// test
	pl1, _ := NewPrefix(net.ParseIP("10.10.0.0"), 16, "21..23")
	match1 := ipPrefixCalculate(path, pl1)
	assert.Equal(t, false, match1)
	pl2, _ := NewPrefix(net.ParseIP("10.10.0.0"), 16, "25..26")
	match2 := ipPrefixCalculate(path, pl2)
	assert.Equal(t, false, match2)
	pl3, _ := NewPrefix(net.ParseIP("10.10.0.0"), 16, "21..24")
	match3 := ipPrefixCalculate(path, pl3)
	assert.Equal(t, true, match3)
}

func TestPrefixCalcurateNoRangeIPv6(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	// creatae path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("2001::192:168:50:1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	mpnlri := []bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")}
	mpreach := bgp.NewPathAttributeMpReachNLRI("2001::192:168:50:1", mpnlri)
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{mpreach, origin, aspath, med}
	nlri := []bgp.NLRInfo{}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	updateMsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// test
	pl1, _ := NewPrefix(net.ParseIP("2001:123:123::"), 48, "")
	match1 := ipPrefixCalculate(path, pl1)
	assert.Equal(t, false, match1)
	pl2, _ := NewPrefix(net.ParseIP("2001:123:123:1::"), 64, "")
	match2 := ipPrefixCalculate(path, pl2)
	assert.Equal(t, true, match2)
	pl3, _ := NewPrefix(net.ParseIP("2001:123:123::"), 48, "64..80")
	match3 := ipPrefixCalculate(path, pl3)
	assert.Equal(t, true, match3)
}

func TestPrefixCalcurateAddressIPv6(t *testing.T) {
	// creatae path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("2001::192:168:50:1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	mpnlri := []bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")}
	mpreach := bgp.NewPathAttributeMpReachNLRI("2001::192:168:50:1", mpnlri)
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{mpreach, origin, aspath, med}
	nlri := []bgp.NLRInfo{}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	updateMsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// test
	pl1, _ := NewPrefix(net.ParseIP("2001:123:128::"), 48, "64..80")
	match1 := ipPrefixCalculate(path, pl1)
	assert.Equal(t, false, match1)
	pl2, _ := NewPrefix(net.ParseIP("2001:123:123::"), 48, "64..80")
	match2 := ipPrefixCalculate(path, pl2)
	assert.Equal(t, true, match2)
}

func TestPrefixCalcurateLengthIPv6(t *testing.T) {
	// creatae path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("2001::192:168:50:1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	mpnlri := []bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")}
	mpreach := bgp.NewPathAttributeMpReachNLRI("2001::192:168:50:1", mpnlri)
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{mpreach, origin, aspath, med}
	nlri := []bgp.NLRInfo{}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	updateMsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// test
	pl1, _ := NewPrefix(net.ParseIP("2001:123:123:64::"), 64, "64..80")
	match1 := ipPrefixCalculate(path, pl1)
	assert.Equal(t, false, match1)
	pl2, _ := NewPrefix(net.ParseIP("2001:123:123:64::"), 48, "64..80")
	match2 := ipPrefixCalculate(path, pl2)
	assert.Equal(t, true, match2)
}

func TestPrefixCalcurateLengthRangeIPv6(t *testing.T) {
	// creatae path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("2001::192:168:50:1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	mpnlri := []bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")}
	mpreach := bgp.NewPathAttributeMpReachNLRI("2001::192:168:50:1", mpnlri)
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{mpreach, origin, aspath, med}
	nlri := []bgp.NLRInfo{}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	updateMsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// test
	pl1, _ := NewPrefix(net.ParseIP("2001:123:123::"), 48, "62..63")
	match1 := ipPrefixCalculate(path, pl1)
	assert.Equal(t, false, match1)
	pl2, _ := NewPrefix(net.ParseIP("2001:123:123::"), 48, "65..66")
	match2 := ipPrefixCalculate(path, pl2)
	assert.Equal(t, false, match2)
	pl3, _ := NewPrefix(net.ParseIP("2001:123:123::"), 48, "63..65")
	match3 := ipPrefixCalculate(path, pl3)
	assert.Equal(t, true, match3)
}

func TestPolicyNotMatch(t *testing.T) {
	// creatae path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.0.101")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	updateMsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// create policy
	ps := config.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList: []config.Prefix{
			config.Prefix{
				Address:         net.ParseIP("10.3.0.0"),
				Masklength:      16,
				MasklengthRange: "21..24",
			}},
	}
	ns := config.NeighborSet{
		NeighborSetName: "ns1",
		NeighborInfoList: []config.NeighborInfo{
			config.NeighborInfo{
				Address: net.ParseIP("10.0.0.1"),
			}},
	}
	ds := config.DefinedSets{
		PrefixSetList:   []config.PrefixSet{ps},
		NeighborSetList: []config.NeighborSet{ns},
	}
	s := config.Statement{
		Name: "statement1",
		Conditions: config.Conditions{
			MatchPrefixSet:   "ps1",
			MatchNeighborSet: "ns1",
			MatchSetOptions:  config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: false,
			RejectRoute: true,
		},
	}
	pd := config.PolicyDefinition{"pd1", []config.Statement{s}}
	pl := config.RoutingPolicy{ds, []config.PolicyDefinition{pd}}
	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitionList[0], df)
	match, pType, newPath := p.Apply(path)
	assert.Equal(t, false, match)
	assert.Equal(t, ROUTE_TYPE_NONE, pType)
	assert.Nil(t, newPath)
}

func TestPolicyMatchAndReject(t *testing.T) {
	// creatae path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.0.101")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	updateMsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// create policy
	ps := config.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList: []config.Prefix{
			config.Prefix{
				Address:         net.ParseIP("10.10.0.0"),
				Masklength:      16,
				MasklengthRange: "21..24",
			}},
	}
	ns := config.NeighborSet{
		NeighborSetName: "ns1",
		NeighborInfoList: []config.NeighborInfo{
			config.NeighborInfo{
				Address: net.ParseIP("10.0.0.1"),
			}},
	}
	ds := config.DefinedSets{
		PrefixSetList:   []config.PrefixSet{ps},
		NeighborSetList: []config.NeighborSet{ns},
	}
	s := config.Statement{
		Name: "statement1",
		Conditions: config.Conditions{
			MatchPrefixSet:   "ps1",
			MatchNeighborSet: "ns1",
			MatchSetOptions:  config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: false,
			RejectRoute: true,
		},
	}
	pd := config.PolicyDefinition{"pd1", []config.Statement{s}}
	pl := config.RoutingPolicy{ds, []config.PolicyDefinition{pd}}
	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitionList[0], df)
	match, pType, newPath := p.Apply(path)
	assert.Equal(t, true, match)
	assert.Equal(t, ROUTE_TYPE_REJECT, pType)
	assert.Nil(t, newPath)
}

func TestPolicyMatchAndAccept(t *testing.T) {
	// creatae path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.0.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.0.101")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	updateMsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// create policy
	ps := config.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList: []config.Prefix{
			config.Prefix{
				Address:         net.ParseIP("10.10.0.0"),
				Masklength:      16,
				MasklengthRange: "21..24",
			}},
	}
	ns := config.NeighborSet{
		NeighborSetName: "ns1",
		NeighborInfoList: []config.NeighborInfo{
			config.NeighborInfo{
				Address: net.ParseIP("10.0.0.1"),
			}},
	}
	ds := config.DefinedSets{
		PrefixSetList:   []config.PrefixSet{ps},
		NeighborSetList: []config.NeighborSet{ns},
	}
	s := config.Statement{
		Name: "statement1",
		Conditions: config.Conditions{
			MatchPrefixSet:   "ps1",
			MatchNeighborSet: "ns1",
			MatchSetOptions:  config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: true,
			RejectRoute: false,
		},
	}
	pd := config.PolicyDefinition{"pd1", []config.Statement{s}}
	pl := config.RoutingPolicy{ds, []config.PolicyDefinition{pd}}
	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitionList[0], df)
	match, pType, newPath := p.Apply(path)
	assert.Equal(t, true, match)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.Equal(t, path, newPath)
}

func TestPolicyRejectOnlyPrefixSet(t *testing.T) {
	// creatae path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.1.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.1.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.1.101")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	updateMsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	path1 := table.ProcessMessage(updateMsg, peer)[0]

	peer = &table.PeerInfo{AS: 65002, Address: net.ParseIP("10.0.2.2")}
	origin = bgp.NewPathAttributeOrigin(0)
	aspathParam = []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65002})}
	aspath = bgp.NewPathAttributeAsPath(aspathParam)
	nexthop = bgp.NewPathAttributeNextHop("10.0.2.2")
	med = bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes = []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri = []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.9.2.102")}
	withdrawnRoutes = []bgp.WithdrawnRoute{}
	updateMsg = bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	path2 := table.ProcessMessage(updateMsg, peer)[0]

	// create policy
	ps := config.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList: []config.Prefix{
			config.Prefix{
				Address:         net.ParseIP("10.10.1.0"),
				Masklength:      16,
				MasklengthRange: "21..24",
			}},
	}
	ds := config.DefinedSets{
		PrefixSetList:   []config.PrefixSet{ps},
		NeighborSetList: []config.NeighborSet{},
	}
	s := config.Statement{
		Name: "statement1",
		Conditions: config.Conditions{
			MatchPrefixSet:   "ps1",
			MatchNeighborSet: "ns1",
			MatchSetOptions:  config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: false,
			RejectRoute: true,
		},
	}
	pd := config.PolicyDefinition{"pd1", []config.Statement{s}}
	pl := config.RoutingPolicy{ds, []config.PolicyDefinition{pd}}
	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitionList[0], df)
	match, pType, newPath := p.Apply(path1)
	assert.Equal(t, true, match)
	assert.Equal(t, ROUTE_TYPE_REJECT, pType)
	assert.Nil(t, newPath)

	match2, pType2, newPath2 := p.Apply(path2)
	assert.Equal(t, false, match2)
	assert.Equal(t, ROUTE_TYPE_NONE, pType2)
	assert.Nil(t, newPath2)
}

func TestPolicyRejectOnlyNeighborSet(t *testing.T) {
	// creatae path
	peer := &table.PeerInfo{AS: 65001, Address: net.ParseIP("10.0.1.1")}
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.1.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.1.101")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	updateMsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	path1 := table.ProcessMessage(updateMsg, peer)[0]

	peer = &table.PeerInfo{AS: 65002, Address: net.ParseIP("10.0.2.2")}
	origin = bgp.NewPathAttributeOrigin(0)
	aspathParam = []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65002})}
	aspath = bgp.NewPathAttributeAsPath(aspathParam)
	nexthop = bgp.NewPathAttributeNextHop("10.0.2.2")
	med = bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes = []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri = []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.2.102")}
	withdrawnRoutes = []bgp.WithdrawnRoute{}
	updateMsg = bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	path2 := table.ProcessMessage(updateMsg, peer)[0]

	// create policy
	ns := config.NeighborSet{
		NeighborSetName: "ns1",
		NeighborInfoList: []config.NeighborInfo{
			config.NeighborInfo{
				Address: net.ParseIP("10.0.1.1"),
			}},
	}
	ds := config.DefinedSets{
		PrefixSetList:   []config.PrefixSet{},
		NeighborSetList: []config.NeighborSet{ns},
	}
	s := config.Statement{
		Name: "statement1",
		Conditions: config.Conditions{
			MatchPrefixSet:   "ps1",
			MatchNeighborSet: "ns1",
			MatchSetOptions:  config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: false,
			RejectRoute: true,
		},
	}
	pd := config.PolicyDefinition{"pd1", []config.Statement{s}}
	pl := config.RoutingPolicy{ds, []config.PolicyDefinition{pd}}
	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitionList[0], df)
	match, pType, newPath := p.Apply(path1)
	assert.Equal(t, true, match)
	assert.Equal(t, ROUTE_TYPE_REJECT, pType)
	assert.Nil(t, newPath)

	match2, pType2, newPath2 := p.Apply(path2)
	assert.Equal(t, false, match2)
	assert.Equal(t, ROUTE_TYPE_NONE, pType2)
	assert.Nil(t, newPath2)
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
	nlriIPv4 := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.0.101")}
	withdrawnRoutesIPv4 := []bgp.WithdrawnRoute{}
	updateMsgIPv4 := bgp.NewBGPUpdateMessage(withdrawnRoutesIPv4, pathAttributesIPv4, nlriIPv4)
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
	nlriIPv6 := []bgp.NLRInfo{}
	withdrawnRoutesIPv6 := []bgp.WithdrawnRoute{}
	updateMsgIPv6 := bgp.NewBGPUpdateMessage(withdrawnRoutesIPv6, pathAttributesIPv6, nlriIPv6)
	pathIPv6 := table.ProcessMessage(updateMsgIPv6, peerIPv6)[0]
	// create policy
	psIPv4 := config.PrefixSet{
		PrefixSetName: "psIPv4",
		PrefixList: []config.Prefix{
			config.Prefix{
				Address:         net.ParseIP("10.10.0.0"),
				Masklength:      16,
				MasklengthRange: "21..24",
			}},
	}
	nsIPv4 := config.NeighborSet{
		NeighborSetName: "nsIPv4",
		NeighborInfoList: []config.NeighborInfo{
			config.NeighborInfo{
				Address: net.ParseIP("10.0.0.1"),
			}},
	}
	psIPv6 := config.PrefixSet{
		PrefixSetName: "psIPv6",
		PrefixList: []config.Prefix{
			config.Prefix{
				Address:         net.ParseIP("2001:123:123::"),
				Masklength:      48,
				MasklengthRange: "64..80",
			}},
	}
	nsIPv6 := config.NeighborSet{
		NeighborSetName: "nsIPv6",
		NeighborInfoList: []config.NeighborInfo{
			config.NeighborInfo{
				Address: net.ParseIP("2001::192:168:50:1"),
			}},
	}
	ds := config.DefinedSets{
		PrefixSetList:   []config.PrefixSet{psIPv4, psIPv6},
		NeighborSetList: []config.NeighborSet{nsIPv4, nsIPv6},
	}
	stIPv4 := config.Statement{
		Name: "statement1",
		Conditions: config.Conditions{
			MatchPrefixSet:   "psIPv4",
			MatchNeighborSet: "nsIPv4",
			MatchSetOptions:  config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: false,
			RejectRoute: true,
		},
	}
	stIPv6 := config.Statement{
		Name: "statement2",
		Conditions: config.Conditions{
			MatchPrefixSet:   "psIPv6",
			MatchNeighborSet: "nsIPv6",
			MatchSetOptions:  config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: false,
			RejectRoute: true,
		},
	}
	pd := config.PolicyDefinition{"pd1", []config.Statement{stIPv4, stIPv6}}
	pl := config.RoutingPolicy{ds, []config.PolicyDefinition{pd}}
	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitionList[0], df)
	match1, pType1, newPath1 := p.Apply(pathIPv4)
	assert.Equal(t, true, match1)
	assert.Equal(t, ROUTE_TYPE_REJECT, pType1)
	assert.Nil(t, newPath1)

	match2, pType2, newPath2 := p.Apply(pathIPv6)
	assert.Equal(t, true, match2)
	assert.Equal(t, ROUTE_TYPE_REJECT, pType2)
	assert.Nil(t, newPath2)
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
	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.0.101")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	updateMsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
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
	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.0.101")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	updateMsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	table.UpdatePathAttrs4ByteAs(updateMsg.Body.(*bgp.BGPUpdate))
	path := table.ProcessMessage(updateMsg, peer)[0]

	// create policy
	ps := config.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList: []config.Prefix{
			config.Prefix{
				Address:         net.ParseIP("10.10.1.0"),
				Masklength:      16,
				MasklengthRange: "21..24",
			}},
	}
	ns := config.NeighborSet{
		NeighborSetName: "ns1",
		NeighborInfoList: []config.NeighborInfo{
			config.NeighborInfo{
				Address: net.ParseIP("10.0.1.1"),
			}},
	}

	ds := config.DefinedSets{
		PrefixSetList:   []config.PrefixSet{ps},
		NeighborSetList: []config.NeighborSet{ns},
	}

	// create match condition
	asPathLength := config.AsPathLength{
		Operator: "le",
		Value:    10,
	}

	bgpCondition := config.BgpConditions{
		AsPathLength: asPathLength,
	}

	s := config.Statement{
		Name: "statement1",
		Conditions: config.Conditions{
			MatchPrefixSet:   "ps1",
			MatchNeighborSet: "ns1",
			MatchSetOptions:  config.MATCH_SET_OPTIONS_TYPE_ANY,
			BgpConditions:    bgpCondition,
		},
		Actions: config.Actions{
			RejectRoute: true,
		},
	}
	pd := config.PolicyDefinition{"pd1", []config.Statement{s}}
	pl := config.RoutingPolicy{ds, []config.PolicyDefinition{pd}}

	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitionList[0], df)
	match, pType, newPath := p.Apply(path)
	assert.Equal(t, true, match)
	assert.Equal(t, ROUTE_TYPE_REJECT, pType)
	assert.Nil(t, newPath)

}

func TestAsPathConditionEvaluate(t *testing.T) {

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
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.0.101")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	updateMsg1 := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	table.UpdatePathAttrs4ByteAs(updateMsg1.Body.(*bgp.BGPUpdate))
	path1 := table.ProcessMessage(updateMsg1, peer)[0]

	aspathParam2 := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(2, []uint16{65010}),
		bgp.NewAsPathParam(1, []uint16{65010}),
	}
	aspath2 := bgp.NewPathAttributeAsPath(aspathParam2)
	pathAttributes = []bgp.PathAttributeInterface{origin, aspath2, nexthop, med}
	updateMsg2 := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	table.UpdatePathAttrs4ByteAs(updateMsg2.Body.(*bgp.BGPUpdate))
	path2 := table.ProcessMessage(updateMsg2, peer)[0]

	// create match condition
	asPathSet1 := config.AsPathSet{
		AsPathSetName:    "asset1",
		AsPathSetMembers: []string{"^65001"},
	}

	asPathSet2 := config.AsPathSet{
		AsPathSetName:    "asset2",
		AsPathSetMembers: []string{"65005$"},
	}

	asPathSet3 := config.AsPathSet{
		AsPathSetName:    "asset3",
		AsPathSetMembers: []string{"65004", "65005$"},
	}

	asPathSet4 := config.AsPathSet{
		AsPathSetName:    "asset4",
		AsPathSetMembers: []string{"65000$"},
	}

	asPathSet5 := config.AsPathSet{
		AsPathSetName:    "asset5",
		AsPathSetMembers: []string{"65010"},
	}

	asPathSet6 := config.AsPathSet{
		AsPathSetName:    "asset6",
		AsPathSetMembers: []string{"^65010$"},
	}

	asPathSetList := []config.AsPathSet{asPathSet1, asPathSet2, asPathSet3,
		asPathSet4, asPathSet5, asPathSet6}

	p1 := NewAsPathCondition("asset1", asPathSetList)
	p2 := NewAsPathCondition("asset2", asPathSetList)
	p3 := NewAsPathCondition("asset3", asPathSetList)
	p4 := NewAsPathCondition("asset4", asPathSetList)
	p5 := NewAsPathCondition("asset5", asPathSetList)
	p6 := NewAsPathCondition("asset6", asPathSetList)

	// test
	assert.Equal(t, true, p1.evaluate(path1))
	assert.Equal(t, true, p2.evaluate(path1))
	assert.Equal(t, true, p3.evaluate(path1))
	assert.Equal(t, false, p4.evaluate(path1))
	assert.Equal(t, false, p5.evaluate(path1))
	assert.Equal(t, false, p6.evaluate(path1))
	assert.Equal(t, true, p6.evaluate(path2))

}

func TestAsPathConditionWithOtherCondition(t *testing.T) {

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
	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.0.101")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	updateMsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	table.UpdatePathAttrs4ByteAs(updateMsg.Body.(*bgp.BGPUpdate))
	path := table.ProcessMessage(updateMsg, peer)[0]

	// create policy
	asPathSet := config.AsPathSet{
		AsPathSetName:    "asset1",
		AsPathSetMembers: []string{"65005$"},
	}

	prefixSet := config.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList: []config.Prefix{
			config.Prefix{
				Address:         net.ParseIP("10.11.1.0"),
				Masklength:      16,
				MasklengthRange: "21..24",
			}},
	}

	neighborSet := config.NeighborSet{
		NeighborSetName: "ns1",
		NeighborInfoList: []config.NeighborInfo{
			config.NeighborInfo{
				Address: net.ParseIP("10.2.1.1"),
			}},
	}

	ds := config.DefinedSets{
		PrefixSetList:   []config.PrefixSet{prefixSet},
		NeighborSetList: []config.NeighborSet{neighborSet},
		BgpDefinedSets: config.BgpDefinedSets{
			AsPathSetList: []config.AsPathSet{asPathSet},
		},
	}

	s := config.Statement{
		Name: "statement1",
		Conditions: config.Conditions{
			MatchPrefixSet:   "ps1",
			MatchNeighborSet: "ns1",
			BgpConditions: config.BgpConditions{
				MatchAsPathSet: "asset1",
			},
			MatchSetOptions: config.MATCH_SET_OPTIONS_TYPE_ANY,
		},
		Actions: config.Actions{
			AcceptRoute: false,
			RejectRoute: true,
		},
	}

	pd := config.PolicyDefinition{"pd1", []config.Statement{s}}
	pl := config.RoutingPolicy{
		DefinedSets:          ds,
		PolicyDefinitionList: []config.PolicyDefinition{pd},
	}

	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitionList[0], df)
	match, pType, newPath := p.Apply(path)
	assert.Equal(t, true, match)
	assert.Equal(t, ROUTE_TYPE_REJECT, pType)
	assert.Nil(t, newPath)

}

func TestConditionConditionEvaluate(t *testing.T) {

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
	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.0.101")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	updateMsg1 := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	table.UpdatePathAttrs4ByteAs(updateMsg1.Body.(*bgp.BGPUpdate))
	path1 := table.ProcessMessage(updateMsg1, peer)[0]

	// create match condition
	comSet1 := config.CommunitySet{
		CommunitySetName: "comset1",
		CommunityMembers: []string{"65001:10", "65001:50", "65001:100"},
	}

	comSet2 := config.CommunitySet{
		CommunitySetName: "comset2",
		CommunityMembers: []string{"65001:200"},
	}

	comSet3 := config.CommunitySet{
		CommunitySetName: "comset3",
		CommunityMembers: []string{"4259905936"},
	}

	comSet4 := config.CommunitySet{
		CommunitySetName: "comset4",
		CommunityMembers: []string{"^[0-9]*:300$"},
	}

	comSet5 := config.CommunitySet{
		CommunitySetName: "comset5",
		CommunityMembers: []string{"INTERNET"},
	}

	comSet6 := config.CommunitySet{
		CommunitySetName: "comset6",
		CommunityMembers: []string{"NO_EXPORT"},
	}

	comSet7 := config.CommunitySet{
		CommunitySetName: "comset7",
		CommunityMembers: []string{"NO_ADVERTISE"},
	}

	comSet8 := config.CommunitySet{
		CommunitySetName: "comset8",
		CommunityMembers: []string{"NO_EXPORT_SUBCONFED"},
	}

	comSetList := []config.CommunitySet{comSet1, comSet2, comSet3,
		comSet4, comSet5, comSet6, comSet7, comSet8}
	p1 := NewCommunityCondition("comset1", comSetList)
	p2 := NewCommunityCondition("comset2", comSetList)
	p3 := NewCommunityCondition("comset3", comSetList)
	p4 := NewCommunityCondition("comset4", comSetList)
	p5 := NewCommunityCondition("comset5", comSetList)
	p6 := NewCommunityCondition("comset6", comSetList)
	p7 := NewCommunityCondition("comset7", comSetList)
	p8 := NewCommunityCondition("comset8", comSetList)

	// test
	assert.Equal(t, true, p1.evaluate(path1))
	assert.Equal(t, true, p2.evaluate(path1))
	assert.Equal(t, true, p3.evaluate(path1))
	assert.Equal(t, true, p4.evaluate(path1))
	assert.Equal(t, true, p5.evaluate(path1))
	assert.Equal(t, true, p6.evaluate(path1))
	assert.Equal(t, true, p7.evaluate(path1))
	assert.Equal(t, true, p8.evaluate(path1))

}

func TestConditionConditionEvaluateWithOtherCondition(t *testing.T) {

	log.SetLevel(log.DebugLevel)

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
	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.0.101")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	updateMsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	table.UpdatePathAttrs4ByteAs(updateMsg.Body.(*bgp.BGPUpdate))
	path := table.ProcessMessage(updateMsg, peer)[0]

	// create policy
	asPathSet := config.AsPathSet{
		AsPathSetName:    "asset1",
		AsPathSetMembers: []string{"65004$"},
	}

	comSet1 := config.CommunitySet{
		CommunitySetName: "comset1",
		CommunityMembers: []string{"65001:10", "65001:50", "65001:100"},
	}

	comSet2 := config.CommunitySet{
		CommunitySetName: "comset2",
		CommunityMembers: []string{"65050:\\d+"},
	}

	prefixSet := config.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList: []config.Prefix{
			config.Prefix{
				Address:         net.ParseIP("10.11.1.0"),
				Masklength:      16,
				MasklengthRange: "21..24",
			}},
	}

	neighborSet := config.NeighborSet{
		NeighborSetName: "ns1",
		NeighborInfoList: []config.NeighborInfo{
			config.NeighborInfo{
				Address: net.ParseIP("10.2.1.1"),
			}},
	}

	ds := config.DefinedSets{
		PrefixSetList:   []config.PrefixSet{prefixSet},
		NeighborSetList: []config.NeighborSet{neighborSet},
		BgpDefinedSets: config.BgpDefinedSets{
			AsPathSetList:    []config.AsPathSet{asPathSet},
			CommunitySetList: []config.CommunitySet{comSet1, comSet2},
		},
	}

	s1 := config.Statement{
		Name: "statement1",
		Conditions: config.Conditions{
			MatchPrefixSet:   "ps1",
			MatchNeighborSet: "ns1",
			BgpConditions: config.BgpConditions{
				MatchAsPathSet:    "asset1",
				MatchCommunitySet: "comset1",
			},
			MatchSetOptions: config.MATCH_SET_OPTIONS_TYPE_ANY,
		},
		Actions: config.Actions{
			AcceptRoute: false,
			RejectRoute: true,
		},
	}

	s2 := config.Statement{
		Name: "statement1",
		Conditions: config.Conditions{
			MatchPrefixSet:   "ps1",
			MatchNeighborSet: "ns1",
			BgpConditions: config.BgpConditions{
				MatchAsPathSet:    "asset1",
				MatchCommunitySet: "comset2",
			},
			MatchSetOptions: config.MATCH_SET_OPTIONS_TYPE_ANY,
		},
		Actions: config.Actions{
			AcceptRoute: false,
			RejectRoute: true,
		},
	}

	pd1 := config.PolicyDefinition{"pd1", []config.Statement{s1}}
	pd2 := config.PolicyDefinition{"pd2", []config.Statement{s2}}
	pl := config.RoutingPolicy{
		DefinedSets:          ds,
		PolicyDefinitionList: []config.PolicyDefinition{pd1, pd2},
	}

	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitionList[0], df)
	match, pType, newPath := p.Apply(path)
	assert.Equal(t, true, match)
	assert.Equal(t, ROUTE_TYPE_REJECT, pType)
	assert.Nil(t, newPath)

	df = pl.DefinedSets
	p = NewPolicy(pl.PolicyDefinitionList[1], df)
	match, pType, newPath = p.Apply(path)
	assert.Equal(t, false, match)
	assert.Equal(t, ROUTE_TYPE_NONE, pType)
	assert.Nil(t, newPath)

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
	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.0.101")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	updateMsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// create policy
	ps := config.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList: []config.Prefix{
			config.Prefix{
				Address:         net.ParseIP("10.10.0.0"),
				Masklength:      16,
				MasklengthRange: "21..24",
			}},
	}
	ns := config.NeighborSet{
		NeighborSetName: "ns1",
		NeighborInfoList: []config.NeighborInfo{
			config.NeighborInfo{
				Address: net.ParseIP("10.0.0.1"),
			}},
	}
	ds := config.DefinedSets{
		PrefixSetList:   []config.PrefixSet{ps},
		NeighborSetList: []config.NeighborSet{ns},
	}

	community := "65000:100"

	s := config.Statement{
		Name: "statement1",
		Conditions: config.Conditions{
			MatchPrefixSet:   "ps1",
			MatchNeighborSet: "ns1",
			MatchSetOptions:  config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: true,
			BgpActions: config.BgpActions{
				SetCommunity: config.SetCommunity{
					Communities: []string{community},
					Options:     "ADD",
				},
			},
		},
	}

	pd := config.PolicyDefinition{"pd1", []config.Statement{s}}
	pl := config.RoutingPolicy{ds, []config.PolicyDefinition{pd}}
	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitionList[0], df)
	match, pType, newPath := p.Apply(path)
	assert.Equal(t, true, match)
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
	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.0.101")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	updateMsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// create policy
	ps := config.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList: []config.Prefix{
			config.Prefix{
				Address:         net.ParseIP("10.10.0.0"),
				Masklength:      16,
				MasklengthRange: "21..24",
			}},
	}
	ns := config.NeighborSet{
		NeighborSetName: "ns1",
		NeighborInfoList: []config.NeighborInfo{
			config.NeighborInfo{
				Address: net.ParseIP("10.0.0.1"),
			}},
	}
	ds := config.DefinedSets{
		PrefixSetList:   []config.PrefixSet{ps},
		NeighborSetList: []config.NeighborSet{ns},
	}

	community := "65000:100"

	s := config.Statement{
		Name: "statement1",
		Conditions: config.Conditions{
			MatchPrefixSet:   "ps1",
			MatchNeighborSet: "ns1",
			MatchSetOptions:  config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: true,
			BgpActions: config.BgpActions{
				SetCommunity: config.SetCommunity{
					Communities: []string{community},
					Options:     "REPLACE",
				},
			},
		},
	}

	pd := config.PolicyDefinition{"pd1", []config.Statement{s}}
	pl := config.RoutingPolicy{ds, []config.PolicyDefinition{pd}}
	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitionList[0], df)
	match, pType, newPath := p.Apply(path)
	assert.Equal(t, true, match)
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
	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.0.101")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	updateMsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// create policy
	ps := config.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList: []config.Prefix{
			config.Prefix{
				Address:         net.ParseIP("10.10.0.0"),
				Masklength:      16,
				MasklengthRange: "21..24",
			}},
	}
	ns := config.NeighborSet{
		NeighborSetName: "ns1",
		NeighborInfoList: []config.NeighborInfo{
			config.NeighborInfo{
				Address: net.ParseIP("10.0.0.1"),
			}},
	}
	ds := config.DefinedSets{
		PrefixSetList:   []config.PrefixSet{ps},
		NeighborSetList: []config.NeighborSet{ns},
	}

	s := config.Statement{
		Name: "statement1",
		Conditions: config.Conditions{
			MatchPrefixSet:   "ps1",
			MatchNeighborSet: "ns1",
			MatchSetOptions:  config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: true,
			BgpActions: config.BgpActions{
				SetCommunity: config.SetCommunity{
					Communities: []string{community1},
					Options:     "REMOVE",
				},
			},
		},
	}

	pd := config.PolicyDefinition{"pd1", []config.Statement{s}}
	pl := config.RoutingPolicy{ds, []config.PolicyDefinition{pd}}
	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitionList[0], df)
	match, pType, newPath := p.Apply(path)
	assert.Equal(t, true, match)
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
	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.0.101")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	updateMsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// create policy
	ps := config.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList: []config.Prefix{
			config.Prefix{
				Address:         net.ParseIP("10.10.0.0"),
				Masklength:      16,
				MasklengthRange: "21..24",
			}},
	}
	ns := config.NeighborSet{
		NeighborSetName: "ns1",
		NeighborInfoList: []config.NeighborInfo{
			config.NeighborInfo{
				Address: net.ParseIP("10.0.0.1"),
			}},
	}
	ds := config.DefinedSets{
		PrefixSetList:   []config.PrefixSet{ps},
		NeighborSetList: []config.NeighborSet{ns},
	}

	s := config.Statement{
		Name: "statement1",
		Conditions: config.Conditions{
			MatchPrefixSet:   "ps1",
			MatchNeighborSet: "ns1",
			MatchSetOptions:  config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: true,
			BgpActions: config.BgpActions{
				SetCommunity: config.SetCommunity{
					Communities: []string{community1},
					Options:     "NULL",
				},
			},
		},
	}

	pd := config.PolicyDefinition{"pd1", []config.Statement{s}}
	pl := config.RoutingPolicy{ds, []config.PolicyDefinition{pd}}
	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitionList[0], df)
	match, pType, newPath := p.Apply(path)
	assert.Equal(t, true, match)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)
	assert.Equal(t, []uint32{}, newPath.GetCommunities())
}

func stringToCommunityValue(comStr string) uint32 {
	elem := strings.Split(comStr, ":")
	asn, _ := strconv.ParseUint(elem[0], 10, 16)
	val, _ := strconv.ParseUint(elem[1], 10, 16)
	return uint32(asn<<16 | val)
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
	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.0.101")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	updateMsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// create policy
	ps := config.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList: []config.Prefix{
			config.Prefix{
				Address:         net.ParseIP("10.10.0.0"),
				Masklength:      16,
				MasklengthRange: "21..24",
			}},
	}
	ns := config.NeighborSet{
		NeighborSetName: "ns1",
		NeighborInfoList: []config.NeighborInfo{
			config.NeighborInfo{
				Address: net.ParseIP("10.0.0.1"),
			}},
	}
	ds := config.DefinedSets{
		PrefixSetList:   []config.PrefixSet{ps},
		NeighborSetList: []config.NeighborSet{ns},
	}

	m := "200"
	s := config.Statement{
		Name: "statement1",
		Conditions: config.Conditions{
			MatchPrefixSet:   "ps1",
			MatchNeighborSet: "ns1",
			MatchSetOptions:  config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: true,
			BgpActions: config.BgpActions{
				SetMed: config.BgpSetMedType(m),
			},
		},
	}

	pd := config.PolicyDefinition{"pd1", []config.Statement{s}}
	pl := config.RoutingPolicy{ds, []config.PolicyDefinition{pd}}
	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitionList[0], df)
	match, pType, newPath := p.Apply(path)
	assert.Equal(t, true, match)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)

	newMed := fmt.Sprintf("%d", newPath.GetMed())
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
	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.0.101")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	updateMsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// create policy
	ps := config.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList: []config.Prefix{
			config.Prefix{
				Address:         net.ParseIP("10.10.0.0"),
				Masklength:      16,
				MasklengthRange: "21..24",
			}},
	}
	ns := config.NeighborSet{
		NeighborSetName: "ns1",
		NeighborInfoList: []config.NeighborInfo{
			config.NeighborInfo{
				Address: net.ParseIP("10.0.0.1"),
			}},
	}
	ds := config.DefinedSets{
		PrefixSetList:   []config.PrefixSet{ps},
		NeighborSetList: []config.NeighborSet{ns},
	}

	m := "+200"
	ma := "300"
	s := config.Statement{
		Name: "statement1",
		Conditions: config.Conditions{
			MatchPrefixSet:   "ps1",
			MatchNeighborSet: "ns1",
			MatchSetOptions:  config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: true,
			BgpActions: config.BgpActions{
				SetMed: config.BgpSetMedType(m),
			},
		},
	}

	pd := config.PolicyDefinition{"pd1", []config.Statement{s}}
	pl := config.RoutingPolicy{ds, []config.PolicyDefinition{pd}}
	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitionList[0], df)
	match, pType, newPath := p.Apply(path)
	assert.Equal(t, true, match)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)

	newMed := fmt.Sprintf("%d", newPath.GetMed())
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
	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.0.101")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	updateMsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// create policy
	ps := config.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList: []config.Prefix{
			config.Prefix{
				Address:         net.ParseIP("10.10.0.0"),
				Masklength:      16,
				MasklengthRange: "21..24",
			}},
	}
	ns := config.NeighborSet{
		NeighborSetName: "ns1",
		NeighborInfoList: []config.NeighborInfo{
			config.NeighborInfo{
				Address: net.ParseIP("10.0.0.1"),
			}},
	}
	ds := config.DefinedSets{
		PrefixSetList:   []config.PrefixSet{ps},
		NeighborSetList: []config.NeighborSet{ns},
	}

	m := fmt.Sprintf("+%d",math.MaxUint32)
	ma := "1"
	s := config.Statement{
		Name: "statement1",
		Conditions: config.Conditions{
			MatchPrefixSet:   "ps1",
			MatchNeighborSet: "ns1",
			MatchSetOptions:  config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: true,
			BgpActions: config.BgpActions{
				SetMed: config.BgpSetMedType(m),
			},
		},
	}

	pd := config.PolicyDefinition{"pd1", []config.Statement{s}}
	pl := config.RoutingPolicy{ds, []config.PolicyDefinition{pd}}
	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitionList[0], df)
	match, pType, newPath := p.Apply(path)
	assert.Equal(t, true, match)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)

	newMed := fmt.Sprintf("%d", newPath.GetMed())
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
	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.0.101")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	updateMsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// create policy
	ps := config.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList: []config.Prefix{
			config.Prefix{
				Address:         net.ParseIP("10.10.0.0"),
				Masklength:      16,
				MasklengthRange: "21..24",
			}},
	}
	ns := config.NeighborSet{
		NeighborSetName: "ns1",
		NeighborInfoList: []config.NeighborInfo{
			config.NeighborInfo{
				Address: net.ParseIP("10.0.0.1"),
			}},
	}
	ds := config.DefinedSets{
		PrefixSetList:   []config.PrefixSet{ps},
		NeighborSetList: []config.NeighborSet{ns},
	}

	m := "-50"
	ma := "50"
	s := config.Statement{
		Name: "statement1",
		Conditions: config.Conditions{
			MatchPrefixSet:   "ps1",
			MatchNeighborSet: "ns1",
			MatchSetOptions:  config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: true,
			BgpActions: config.BgpActions{
				SetMed: config.BgpSetMedType(m),
			},
		},
	}

	pd := config.PolicyDefinition{"pd1", []config.Statement{s}}
	pl := config.RoutingPolicy{ds, []config.PolicyDefinition{pd}}
	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitionList[0], df)
	match, pType, newPath := p.Apply(path)
	assert.Equal(t, true, match)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)

	newMed := fmt.Sprintf("%d", newPath.GetMed())
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
	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.0.101")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	updateMsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// create policy
	ps := config.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList: []config.Prefix{
			config.Prefix{
				Address:         net.ParseIP("10.10.0.0"),
				Masklength:      16,
				MasklengthRange: "21..24",
			}},
	}
	ns := config.NeighborSet{
		NeighborSetName: "ns1",
		NeighborInfoList: []config.NeighborInfo{
			config.NeighborInfo{
				Address: net.ParseIP("10.0.0.1"),
			}},
	}
	ds := config.DefinedSets{
		PrefixSetList:   []config.PrefixSet{ps},
		NeighborSetList: []config.NeighborSet{ns},
	}

	m := "-101"
	ma := "100"
	s := config.Statement{
		Name: "statement1",
		Conditions: config.Conditions{
			MatchPrefixSet:   "ps1",
			MatchNeighborSet: "ns1",
			MatchSetOptions:  config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: true,
			BgpActions: config.BgpActions{
				SetMed: config.BgpSetMedType(m),
			},
		},
	}

	pd := config.PolicyDefinition{"pd1", []config.Statement{s}}
	pl := config.RoutingPolicy{ds, []config.PolicyDefinition{pd}}
	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitionList[0], df)
	match, pType, newPath := p.Apply(path)
	assert.Equal(t, true, match)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)

	newMed := fmt.Sprintf("%d", newPath.GetMed())
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
	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.0.101")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	updateMsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	path := table.ProcessMessage(updateMsg, peer)[0]
	// create policy
	ps := config.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList: []config.Prefix{
			config.Prefix{
				Address:         net.ParseIP("10.10.0.0"),
				Masklength:      16,
				MasklengthRange: "21..24",
			}},
	}
	ns := config.NeighborSet{
		NeighborSetName: "ns1",
		NeighborInfoList: []config.NeighborInfo{
			config.NeighborInfo{
				Address: net.ParseIP("10.0.0.1"),
			}},
	}
	ds := config.DefinedSets{
		PrefixSetList:   []config.PrefixSet{ps},
		NeighborSetList: []config.NeighborSet{ns},
	}

	m := "-50"
	s := config.Statement{
		Name: "statement1",
		Conditions: config.Conditions{
			MatchPrefixSet:   "ps1",
			MatchNeighborSet: "ns1",
			MatchSetOptions:  config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: true,
			BgpActions: config.BgpActions{
				SetMed: config.BgpSetMedType(m),
			},
		},
	}

	pd := config.PolicyDefinition{"pd1", []config.Statement{s}}
	pl := config.RoutingPolicy{ds, []config.PolicyDefinition{pd}}
	//test
	df := pl.DefinedSets
	p := NewPolicy(pl.PolicyDefinitionList[0], df)
	match, pType, newPath := p.Apply(path)
	assert.Equal(t, true, match)
	assert.Equal(t, ROUTE_TYPE_ACCEPT, pType)
	assert.NotEqual(t, nil, newPath)

	newMed := fmt.Sprintf("%d", newPath.GetMed())
	assert.Equal(t, "0", newMed)
}
