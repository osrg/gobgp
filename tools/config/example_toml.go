package main

import (
	"bytes"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/osrg/gobgp/config"
	"net"
)

func main() {
	b := config.Bgp{
		Global: config.Global{
			As:       12332,
			RouterId: net.ParseIP("10.0.0.1"),
		},
		NeighborList: []config.Neighbor{
			config.Neighbor{
				PeerAs:          12333,
				NeighborAddress: net.ParseIP("192.168.177.32"),
				AuthPassword:    "apple",
				AfiSafiList:     []config.AfiSafi{config.AfiSafi{AfiSafiName: "ipv4-unicast"}, config.AfiSafi{AfiSafiName: "ipv6-unicast"}},
				ApplyPolicy: config.ApplyPolicy{
					ImportPolicies:      []string{"pd1"},
					DefaultImportPolicy: config.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE,
				},
			},
			config.Neighbor{
				PeerAs:          12334,
				NeighborAddress: net.ParseIP("192.168.177.33"),
				AuthPassword:    "orange",
			},
			config.Neighbor{
				PeerAs:          12335,
				NeighborAddress: net.ParseIP("192.168.177.34"),
				AuthPassword:    "grape",
			},
		},
	}

	var buffer bytes.Buffer
	encoder := toml.NewEncoder(&buffer)
	err := encoder.Encode(b)
	if err != nil {
		panic(err)
	}

	err = encoder.Encode(policy())
	if err != nil {
		panic(err)
	}
	fmt.Printf("%v\n", buffer.String())
}

func policy() config.RoutingPolicy {

	ps := config.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList: []config.Prefix{
			config.Prefix{
				Address:         net.ParseIP("10.3.192.0"),
				Masklength:      21,
				MasklengthRange: "21..24",
			}},
	}

	ns := config.NeighborSet{
		NeighborSetName: "ns1",
		NeighborInfoList: []config.NeighborInfo{
			config.NeighborInfo{
				Address: net.ParseIP("10.0.0.2"),
			}},
	}

	cs := config.CommunitySet{
		CommunitySetName: "community1",
		CommunityMembers: []string{"65100:10"},
	}

	ecs := config.ExtCommunitySet{
		ExtCommunitySetName: "ecommunity1",
		ExtCommunityMembers: []string{"RT:65001:200"},
	}

	as := config.AsPathSet{
		AsPathSetName: "aspath1",
		AsPathSetMembers: []string{"^65100"},
	}

	bds := config.BgpDefinedSets{
		CommunitySetList: []config.CommunitySet{cs},
		ExtCommunitySetList: []config.ExtCommunitySet{ecs},
		AsPathSetList:	[]config.AsPathSet{as},
	}

	ds := config.DefinedSets{
		PrefixSetList:   []config.PrefixSet{ps},
		NeighborSetList: []config.NeighborSet{ns},
		BgpDefinedSets: bds,
	}

	al := config.AsPathLength{
		Operator: "eq",
		Value: 2,
	}

	s := config.Statement{
		Name: "statement1",
		Conditions: config.Conditions{
			MatchPrefixSet:   "ps1",
			MatchNeighborSet: "ns1",
			MatchSetOptions:  config.MATCH_SET_OPTIONS_TYPE_ALL,
			BgpConditions: config.BgpConditions{
				MatchCommunitySet: "community1",
				MatchExtCommunitySet: "ecommunity1",
				MatchAsPathSet: "aspath1",
				AsPathLength: al,
			},
		},
		Actions: config.Actions{
			AcceptRoute: false,
			RejectRoute: true,
			BgpActions: config.BgpActions{
				SetCommunity: config.SetCommunity{
					Communities: []string{"65100:20"},
					Options: "ADD",
				},
				SetMed: "-200",
			},
		},
	}

	pd := config.PolicyDefinition{
		Name:          "pd1",
		StatementList: []config.Statement{s},
	}

	p := config.RoutingPolicy{
		DefinedSets:          ds,
		PolicyDefinitionList: []config.PolicyDefinition{pd},
	}

	return p
}
