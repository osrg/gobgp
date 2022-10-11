package main

import (
	"bytes"
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/osrg/gobgp/v3/pkg/bgpconfig"
)

func main() {
	b := bgpconfig.Bgp{
		Global: bgpconfig.Global{
			Config: bgpconfig.GlobalConfig{
				As:       12332,
				RouterId: "10.0.0.1",
			},
		},
		Neighbors: []bgpconfig.Neighbor{
			{
				Config: bgpconfig.NeighborConfig{
					PeerAs:          12333,
					AuthPassword:    "apple",
					NeighborAddress: "192.168.177.33",
				},
				AfiSafis: []bgpconfig.AfiSafi{
					{
						Config: bgpconfig.AfiSafiConfig{
							AfiSafiName: "ipv4-unicast",
						},
					},
					{
						Config: bgpconfig.AfiSafiConfig{
							AfiSafiName: "ipv6-unicast",
						},
					},
				},
				ApplyPolicy: bgpconfig.ApplyPolicy{

					Config: bgpconfig.ApplyPolicyConfig{
						ImportPolicyList:    []string{"pd1"},
						DefaultImportPolicy: bgpconfig.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE,
					},
				},
			},

			{
				Config: bgpconfig.NeighborConfig{
					PeerAs:          12334,
					AuthPassword:    "orange",
					NeighborAddress: "192.168.177.32",
				},
			},

			{
				Config: bgpconfig.NeighborConfig{
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

func policy() bgpconfig.RoutingPolicy {

	ps := bgpconfig.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList: []bgpconfig.Prefix{
			{
				IpPrefix:        "10.3.192.0/21",
				MasklengthRange: "21..24",
			}},
	}

	ns := bgpconfig.NeighborSet{
		NeighborSetName:  "ns1",
		NeighborInfoList: []string{"10.0.0.2"},
	}

	cs := bgpconfig.CommunitySet{
		CommunitySetName: "community1",
		CommunityList:    []string{"65100:10"},
	}

	ecs := bgpconfig.ExtCommunitySet{
		ExtCommunitySetName: "ecommunity1",
		ExtCommunityList:    []string{"RT:65001:200"},
	}

	as := bgpconfig.AsPathSet{
		AsPathSetName: "aspath1",
		AsPathList:    []string{"^65100"},
	}

	bds := bgpconfig.BgpDefinedSets{
		CommunitySets:    []bgpconfig.CommunitySet{cs},
		ExtCommunitySets: []bgpconfig.ExtCommunitySet{ecs},
		AsPathSets:       []bgpconfig.AsPathSet{as},
	}

	ds := bgpconfig.DefinedSets{
		PrefixSets:     []bgpconfig.PrefixSet{ps},
		NeighborSets:   []bgpconfig.NeighborSet{ns},
		BgpDefinedSets: bds,
	}

	al := bgpconfig.AsPathLength{
		Operator: "eq",
		Value:    2,
	}

	s := bgpconfig.Statement{
		Name: "statement1",
		Conditions: bgpconfig.Conditions{

			MatchPrefixSet: bgpconfig.MatchPrefixSet{
				PrefixSet:       "ps1",
				MatchSetOptions: bgpconfig.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
			},

			MatchNeighborSet: bgpconfig.MatchNeighborSet{
				NeighborSet:     "ns1",
				MatchSetOptions: bgpconfig.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
			},

			BgpConditions: bgpconfig.BgpConditions{
				MatchCommunitySet: bgpconfig.MatchCommunitySet{
					CommunitySet:    "community1",
					MatchSetOptions: bgpconfig.MATCH_SET_OPTIONS_TYPE_ANY,
				},

				MatchExtCommunitySet: bgpconfig.MatchExtCommunitySet{
					ExtCommunitySet: "ecommunity1",
					MatchSetOptions: bgpconfig.MATCH_SET_OPTIONS_TYPE_ANY,
				},

				MatchAsPathSet: bgpconfig.MatchAsPathSet{
					AsPathSet:       "aspath1",
					MatchSetOptions: bgpconfig.MATCH_SET_OPTIONS_TYPE_ANY,
				},
				AsPathLength: al,
			},
		},
		Actions: bgpconfig.Actions{
			RouteDisposition: "reject-route",
			BgpActions: bgpconfig.BgpActions{
				SetCommunity: bgpconfig.SetCommunity{
					SetCommunityMethod: bgpconfig.SetCommunityMethod{
						CommunitiesList: []string{"65100:20"},
					},
					Options: "ADD",
				},
				SetMed: "-200",
			},
		},
	}

	pd := bgpconfig.PolicyDefinition{
		Name:       "pd1",
		Statements: []bgpconfig.Statement{s},
	}

	p := bgpconfig.RoutingPolicy{
		DefinedSets:       ds,
		PolicyDefinitions: []bgpconfig.PolicyDefinition{pd},
	}

	return p
}
