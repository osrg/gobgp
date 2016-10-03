package main

import (
	"bytes"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/osrg/gobgp/config"
)

func main() {
	b := config.BGP{
		Global: config.Global{
			AS:       12332,
			RouterID: "10.0.0.1",
		},
		Neighbors: []config.Neighbor{
			config.Neighbor{
				PeerAS:          12333,
				AuthPassword:    "apple",
				NeighborAddress: "192.168.177.33",
				AfiSafis: []config.AfiSafi{
					config.AfiSafi{
						AfiSafiName: "ipv4-unicast",
					},
					config.AfiSafi{
						AfiSafiName: "ipv6-unicast",
					},
				},
				ApplyPolicy: config.ApplyPolicy{
					ImportPolicyList:    []string{"pd1"},
					DefaultImportPolicy: config.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE,
				},
			},

			config.Neighbor{
				PeerAS:          12334,
				AuthPassword:    "orange",
				NeighborAddress: "192.168.177.32",
			},

			config.Neighbor{
				PeerAS:          12335,
				AuthPassword:    "grape",
				NeighborAddress: "192.168.177.34",
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
		Prefixes: []config.Prefix{
			config.Prefix{
				IPPrefix:        "10.3.192.0/21",
				MasklengthRange: "21..24",
			}},
	}

	ns := config.NeighborSet{
		NeighborSetName: "ns1",
		AddressList:     []string{"10.0.0.2"},
	}

	cs := config.CommunitySet{
		CommunitySetName:    "community1",
		CommunityMemberList: []string{"65100:10"},
	}

	ecs := config.ExtCommunitySet{
		ExtCommunitySetName:    "ecommunity1",
		ExtCommunityMemberList: []string{"RT:65001:200"},
	}

	as := config.ASPathSet{
		ASPathSetName:       "aspath1",
		ASPathSetMemberList: []string{"^65100"},
	}

	bds := config.BGPDefinedSets{
		CommunitySets:    []config.CommunitySet{cs},
		ExtCommunitySets: []config.ExtCommunitySet{ecs},
		ASPathSets:       []config.ASPathSet{as},
	}

	ds := config.DefinedSets{
		PrefixSets:     []config.PrefixSet{ps},
		NeighborSets:   []config.NeighborSet{ns},
		BGPDefinedSets: bds,
	}

	al := config.ASPathLength{
		Operator: "eq",
		Value:    2,
	}

	s := config.Statement{
		Name: "statement1",
		Conditions: config.Conditions{

			MatchPrefixSet: config.MatchPrefixSet{
				PrefixSet:       "ps1",
				MatchSetOptions: config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
			},

			MatchNeighborSet: config.MatchNeighborSet{
				NeighborSet:     "ns1",
				MatchSetOptions: config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
			},

			BGPConditions: config.BGPConditions{
				MatchCommunitySet: config.MatchCommunitySet{
					CommunitySet:    "community1",
					MatchSetOptions: config.MATCH_SET_OPTIONS_TYPE_ANY,
				},

				MatchExtCommunitySet: config.MatchExtCommunitySet{
					ExtCommunitySet: "ecommunity1",
					MatchSetOptions: config.MATCH_SET_OPTIONS_TYPE_ANY,
				},

				MatchASPathSet: config.MatchASPathSet{
					ASPathSet:       "aspath1",
					MatchSetOptions: config.MATCH_SET_OPTIONS_TYPE_ANY,
				},
				ASPathLength: al,
			},
		},
		Actions: config.Actions{
			RouteDisposition: config.RouteDisposition{
				AcceptRoute: false,
				RejectRoute: true,
			},
			BGPActions: config.BGPActions{
				SetCommunity: config.SetCommunity{
					Options: "ADD",
					Inline: config.Inline{
						CommunitiesList: []string{"65100:20"},
					},
				},
				SetMED: "-200",
			},
		},
	}

	pd := config.PolicyDefinition{
		Name:       "pd1",
		Statements: []config.Statement{s},
	}

	p := config.RoutingPolicy{
		DefinedSets:       ds,
		PolicyDefinitions: []config.PolicyDefinition{pd},
	}

	return p
}
