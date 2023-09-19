package main

import (
	"bytes"
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/osrg/gobgp/v3/pkg/config/gobgp"
)

func main() {
	b := gobgp.Bgp{
		Global: gobgp.Global{
			Config: gobgp.GlobalConfig{
				As:       12332,
				RouterId: "10.0.0.1",
			},
		},
		Neighbors: []gobgp.Neighbor{
			{
				Config: gobgp.NeighborConfig{
					PeerAs:          12333,
					AuthPassword:    "apple",
					NeighborAddress: "192.168.177.33",
				},
				AfiSafis: []gobgp.AfiSafi{
					{
						Config: gobgp.AfiSafiConfig{
							AfiSafiName: "ipv4-unicast",
						},
					},
					{
						Config: gobgp.AfiSafiConfig{
							AfiSafiName: "ipv6-unicast",
						},
					},
				},
				ApplyPolicy: gobgp.ApplyPolicy{

					Config: gobgp.ApplyPolicyConfig{
						ImportPolicyList:    []string{"pd1"},
						DefaultImportPolicy: gobgp.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE,
					},
				},
			},

			{
				Config: gobgp.NeighborConfig{
					PeerAs:          12334,
					AuthPassword:    "orange",
					NeighborAddress: "192.168.177.32",
				},
			},

			{
				Config: gobgp.NeighborConfig{
					PeerAs:          12335,
					AuthPassword:    "grape",
					NeighborAddress: "192.168.177.34",
				},
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

func policy() gobgp.RoutingPolicy {

	ps := gobgp.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList: []gobgp.Prefix{
			{
				IpPrefix:        "10.3.192.0/21",
				MasklengthRange: "21..24",
			}},
	}

	ns := gobgp.NeighborSet{
		NeighborSetName:  "ns1",
		NeighborInfoList: []string{"10.0.0.2"},
	}

	cs := gobgp.CommunitySet{
		CommunitySetName: "community1",
		CommunityList:    []string{"65100:10"},
	}

	ecs := gobgp.ExtCommunitySet{
		ExtCommunitySetName: "ecommunity1",
		ExtCommunityList:    []string{"RT:65001:200"},
	}

	as := gobgp.AsPathSet{
		AsPathSetName: "aspath1",
		AsPathList:    []string{"^65100"},
	}

	bds := gobgp.BgpDefinedSets{
		CommunitySets:    []gobgp.CommunitySet{cs},
		ExtCommunitySets: []gobgp.ExtCommunitySet{ecs},
		AsPathSets:       []gobgp.AsPathSet{as},
	}

	ds := gobgp.DefinedSets{
		PrefixSets:     []gobgp.PrefixSet{ps},
		NeighborSets:   []gobgp.NeighborSet{ns},
		BgpDefinedSets: bds,
	}

	al := gobgp.AsPathLength{
		Operator: "eq",
		Value:    2,
	}

	s := gobgp.Statement{
		Name: "statement1",
		Conditions: gobgp.Conditions{

			MatchPrefixSet: gobgp.MatchPrefixSet{
				PrefixSet:       "ps1",
				MatchSetOptions: gobgp.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
			},

			MatchNeighborSet: gobgp.MatchNeighborSet{
				NeighborSet:     "ns1",
				MatchSetOptions: gobgp.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
			},

			BgpConditions: gobgp.BgpConditions{
				MatchCommunitySet: gobgp.MatchCommunitySet{
					CommunitySet:    "community1",
					MatchSetOptions: gobgp.MATCH_SET_OPTIONS_TYPE_ANY,
				},

				MatchExtCommunitySet: gobgp.MatchExtCommunitySet{
					ExtCommunitySet: "ecommunity1",
					MatchSetOptions: gobgp.MATCH_SET_OPTIONS_TYPE_ANY,
				},

				MatchAsPathSet: gobgp.MatchAsPathSet{
					AsPathSet:       "aspath1",
					MatchSetOptions: gobgp.MATCH_SET_OPTIONS_TYPE_ANY,
				},
				AsPathLength: al,
			},
		},
		Actions: gobgp.Actions{
			RouteDisposition: "reject-route",
			BgpActions: gobgp.BgpActions{
				SetCommunity: gobgp.SetCommunity{
					SetCommunityMethod: gobgp.SetCommunityMethod{
						CommunitiesList: []string{"65100:20"},
					},
					Options: "ADD",
				},
				SetMed: "-200",
			},
		},
	}

	pd := gobgp.PolicyDefinition{
		Name:       "pd1",
		Statements: []gobgp.Statement{s},
	}

	p := gobgp.RoutingPolicy{
		DefinedSets:       ds,
		PolicyDefinitions: []gobgp.PolicyDefinition{pd},
	}

	return p
}
