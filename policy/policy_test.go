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
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/table"
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func TestPrefixCalcurateNoRange(t *testing.T) {
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
	msg := table.NewProcessMessage(updateMsg, peer)
	path := msg.ToPathList()[0]
	// test
	pl1 := NewPrefix(net.ParseIP("10.10.0.0"), 24, "")
	match1 := IpPrefixCalcurate(path, pl1)
	assert.Equal(t, match1, false)
	pl2 := NewPrefix(net.ParseIP("10.10.0.101"), 24, "")
	match2 := IpPrefixCalcurate(path, pl2)
	assert.Equal(t, match2, true)
	pl3 := NewPrefix(net.ParseIP("10.10.0.0"), 16, "21..24")
	match3 := IpPrefixCalcurate(path, pl3)
	assert.Equal(t, match3, true)
}

func TestPrefixCalcurateInAddress(t *testing.T) {
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
	msg := table.NewProcessMessage(updateMsg, peer)
	path := msg.ToPathList()[0]
	// test
	pl1 := NewPrefix(net.ParseIP("10.11.0.0"), 16, "21..24")
	match1 := IpPrefixCalcurate(path, pl1)
	assert.Equal(t, match1, false)
	pl2 := NewPrefix(net.ParseIP("10.10.0.0"), 16, "21..24")
	match2 := IpPrefixCalcurate(path, pl2)
	assert.Equal(t, match2, true)
}

func TestPrefixCalcurateInLength(t *testing.T) {
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
	msg := table.NewProcessMessage(updateMsg, peer)
	path := msg.ToPathList()[0]
	// test
	pl1 := NewPrefix(net.ParseIP("10.10.64.0"), 24, "21..24")
	match1 := IpPrefixCalcurate(path, pl1)
	assert.Equal(t, match1, false)
	pl2 := NewPrefix(net.ParseIP("10.10.64.0"), 16, "21..24")
	match2 := IpPrefixCalcurate(path, pl2)
	assert.Equal(t, match2, true)
}

func TestPrefixCalcurateInLengthRange(t *testing.T) {
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
	msg := table.NewProcessMessage(updateMsg, peer)
	path := msg.ToPathList()[0]
	// test
	pl1 := NewPrefix(net.ParseIP("10.10.0.0"), 16, "21..23")
	match1 := IpPrefixCalcurate(path, pl1)
	assert.Equal(t, match1, false)
	pl2 := NewPrefix(net.ParseIP("10.10.0.0"), 16, "25..26")
	match2 := IpPrefixCalcurate(path, pl2)
	assert.Equal(t, match2, false)
	pl3 := NewPrefix(net.ParseIP("10.10.0.0"), 16, "21..24")
	match3 := IpPrefixCalcurate(path, pl3)
	assert.Equal(t, match3, true)
}

func TestPolicyNotMatchL(t *testing.T) {
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
	msg := table.NewProcessMessage(updateMsg, peer)
	path := msg.ToPathList()[0]
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
		},
		Actions: config.Actions{
			AcceptRoute: false,
			RejectRoute: true,
		},
	}
	pd := config.PolicyDefinition{"pd1", []config.Statement{s}}
	pl := config.RoutingPolicy{ds, []config.PolicyDefinition{pd}}
	//test
	pName := "pd1"
	df := pl.DefinedSets
	p := NewPolicy(pName, pl.PolicyDefinitionList[0], df)
	match, pType, newPath := p.Apply(path)
	assert.Equal(t, match, false)
	assert.Equal(t, pType, ROUTE_TYPE_NONE)
	assert.Equal(t, newPath, nil)
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
	msg := table.NewProcessMessage(updateMsg, peer)
	path := msg.ToPathList()[0]
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
		},
		Actions: config.Actions{
			AcceptRoute: false,
			RejectRoute: true,
		},
	}
	pd := config.PolicyDefinition{"pd1", []config.Statement{s}}
	pl := config.RoutingPolicy{ds, []config.PolicyDefinition{pd}}
	//test
	pName := "pd1"
	df := pl.DefinedSets
	p := NewPolicy(pName, pl.PolicyDefinitionList[0], df)
	match, pType, newPath := p.Apply(path)
	assert.Equal(t, match, true)
	assert.Equal(t, pType, ROUTE_TYPE_REJECT)
	assert.Equal(t, newPath, nil)
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
	msg := table.NewProcessMessage(updateMsg, peer)
	path := msg.ToPathList()[0]
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
		},
		Actions: config.Actions{
			AcceptRoute: true,
			RejectRoute: false,
		},
	}
	pd := config.PolicyDefinition{"pd1", []config.Statement{s}}
	pl := config.RoutingPolicy{ds, []config.PolicyDefinition{pd}}
	//test
	pName := "pd1"
	df := pl.DefinedSets
	p := NewPolicy(pName, pl.PolicyDefinitionList[0], df)
	match, pType, newPath := p.Apply(path)
	assert.Equal(t, match, true)
	assert.Equal(t, pType, ROUTE_TYPE_ACCEPT)
	assert.Equal(t, newPath, path)
}

func TestPolicyRejectOnlyPrefixList(t *testing.T) {
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
	msg := table.NewProcessMessage(updateMsg, peer)
	path1 := msg.ToPathList()[0]

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
	msg = table.NewProcessMessage(updateMsg, peer)
	path2 := msg.ToPathList()[0]

	// create policy
	ps := config.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList: []config.Prefix{
			config.Prefix{
				Address:         net.ParseIP("10.10.1.0"),
				Masklength:      24,
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
		},
		Actions: config.Actions{
			AcceptRoute: false,
			RejectRoute: true,
		},
	}
	pd := config.PolicyDefinition{"pd1", []config.Statement{s}}
	pl := config.RoutingPolicy{ds, []config.PolicyDefinition{pd}}
	//test
	pName := "pd1"
	df := pl.DefinedSets
	p := NewPolicy(pName, pl.PolicyDefinitionList[0], df)
	match, pType, newPath := p.Apply(path1)
	assert.Equal(t, match, true)
	assert.Equal(t, pType, ROUTE_TYPE_REJECT)
	assert.Equal(t, newPath, nil)

	match2, pType2, newPath2 := p.Apply(path2)
	assert.Equal(t, match2, false)
	assert.Equal(t, pType2, ROUTE_TYPE_NONE)
	assert.Equal(t, newPath2, nil)
}

func TestPolicyRejectOnlyNeighborList(t *testing.T) {
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
	msg := table.NewProcessMessage(updateMsg, peer)
	path1 := msg.ToPathList()[0]

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
	msg = table.NewProcessMessage(updateMsg, peer)
	path2 := msg.ToPathList()[0]

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
		},
		Actions: config.Actions{
			AcceptRoute: false,
			RejectRoute: true,
		},
	}
	pd := config.PolicyDefinition{"pd1", []config.Statement{s}}
	pl := config.RoutingPolicy{ds, []config.PolicyDefinition{pd}}
	//test
	pName := "pd1"
	df := pl.DefinedSets
	p := NewPolicy(pName, pl.PolicyDefinitionList[0], df)
	match, pType, newPath := p.Apply(path1)
	assert.Equal(t, match, true)
	assert.Equal(t, pType, ROUTE_TYPE_REJECT)
	assert.Equal(t, newPath, nil)

	match2, pType2, newPath2 := p.Apply(path2)
	assert.Equal(t, match2, false)
	assert.Equal(t, pType2, ROUTE_TYPE_NONE)
	assert.Equal(t, newPath2, nil)
}
