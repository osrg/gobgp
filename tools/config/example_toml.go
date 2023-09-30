package main

import (
	"bytes"
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/osrg/gobgp/v3/pkg/config/oc"
)

func main() {
	b := oc.Bgp{
		Global: oc.Global{
			Config: oc.GlobalConfig{
				As:       12332,
				RouterId: "10.0.0.1",
			},
		},
		Neighbors: []oc.Neighbor{
			{
				Config: oc.NeighborConfig{
					PeerAs:          12333,
					AuthPassword:    "apple",
					NeighborAddress: "192.168.177.33",
				},
				AfiSafis: []oc.AfiSafi{
					{
						Config: oc.AfiSafiConfig{
							AfiSafiName: "ipv4-unicast",
						},
					},
					{
						Config: oc.AfiSafiConfig{
							AfiSafiName: "ipv6-unicast",
						},
					},
				},
				ApplyPolicy: oc.ApplyPolicy{

					Config: oc.ApplyPolicyConfig{
						ImportPolicyList:    []string{"pd1"},
						DefaultImportPolicy: oc.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE,
					},
				},
			},

			{
				Config: oc.NeighborConfig{
					PeerAs:          12334,
					AuthPassword:    "orange",
					NeighborAddress: "192.168.177.32",
				},
			},

			{
				Config: oc.NeighborConfig{
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

func policy() oc.RoutingPolicy {

	ps := oc.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList: []oc.Prefix{
			{
				IpPrefix:        "10.3.192.0/21",
				MasklengthRange: "21..24",
			}},
	}

	ns := oc.NeighborSet{
		NeighborSetName:  "ns1",
		NeighborInfoList: []string{"10.0.0.2"},
	}

	cs := oc.CommunitySet{
		CommunitySetName: "community1",
		CommunityList:    []string{"65100:10"},
	}

	ecs := oc.ExtCommunitySet{
		ExtCommunitySetName: "ecommunity1",
		ExtCommunityList:    []string{"RT:65001:200"},
	}

	as := oc.AsPathSet{
		AsPathSetName: "aspath1",
		AsPathList:    []string{"^65100"},
	}

	bds := oc.BgpDefinedSets{
		CommunitySets:    []oc.CommunitySet{cs},
		ExtCommunitySets: []oc.ExtCommunitySet{ecs},
		AsPathSets:       []oc.AsPathSet{as},
	}

	ds := oc.DefinedSets{
		PrefixSets:     []oc.PrefixSet{ps},
		NeighborSets:   []oc.NeighborSet{ns},
		BgpDefinedSets: bds,
	}

	al := oc.AsPathLength{
		Operator: "eq",
		Value:    2,
	}

	s := oc.Statement{
		Name: "statement1",
		Conditions: oc.Conditions{

			MatchPrefixSet: oc.MatchPrefixSet{
				PrefixSet:       "ps1",
				MatchSetOptions: oc.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
			},

			MatchNeighborSet: oc.MatchNeighborSet{
				NeighborSet:     "ns1",
				MatchSetOptions: oc.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
			},

			BgpConditions: oc.BgpConditions{
				MatchCommunitySet: oc.MatchCommunitySet{
					CommunitySet:    "community1",
					MatchSetOptions: oc.MATCH_SET_OPTIONS_TYPE_ANY,
				},

				MatchExtCommunitySet: oc.MatchExtCommunitySet{
					ExtCommunitySet: "ecommunity1",
					MatchSetOptions: oc.MATCH_SET_OPTIONS_TYPE_ANY,
				},

				MatchAsPathSet: oc.MatchAsPathSet{
					AsPathSet:       "aspath1",
					MatchSetOptions: oc.MATCH_SET_OPTIONS_TYPE_ANY,
				},
				AsPathLength: al,
			},
		},
		Actions: oc.Actions{
			RouteDisposition: "reject-route",
			BgpActions: oc.BgpActions{
				SetCommunity: oc.SetCommunity{
					SetCommunityMethod: oc.SetCommunityMethod{
						CommunitiesList: []string{"65100:20"},
					},
					Options: "ADD",
				},
				SetMed: "-200",
			},
		},
	}

	pd := oc.PolicyDefinition{
		Name:       "pd1",
		Statements: []oc.Statement{s},
	}

	p := oc.RoutingPolicy{
		DefinedSets:       ds,
		PolicyDefinitions: []oc.PolicyDefinition{pd},
	}

	return p
}
