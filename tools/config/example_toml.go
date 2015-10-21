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
			GlobalConfig: config.GlobalConfig{
				As:       12332,
				RouterId: net.ParseIP("10.0.0.1"),
			},
		},
		Neighbors: config.Neighbors{
			NeighborList: []config.Neighbor{
				config.Neighbor{
					NeighborConfig: config.NeighborConfig{
						PeerAs:          12333,
						AuthPassword:    "apple",
						NeighborAddress: net.ParseIP("192.168.177.33"),
					},
					AfiSafis: config.AfiSafis{

						AfiSafiList: []config.AfiSafi{
							config.AfiSafi{AfiSafiName: "ipv4-unicast"},
							config.AfiSafi{AfiSafiName: "ipv6-unicast"},
						},
					},
					ApplyPolicy: config.ApplyPolicy{

						ApplyPolicyConfig: config.ApplyPolicyConfig{
							ImportPolicy:        []string{"pd1"},
							DefaultImportPolicy: config.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE,
						},
					},
				},

				config.Neighbor{
					NeighborConfig: config.NeighborConfig{
						PeerAs:          12334,
						AuthPassword:    "orange",
						NeighborAddress: net.ParseIP("192.168.177.32"),
					},
				},

				config.Neighbor{
					NeighborConfig: config.NeighborConfig{
						PeerAs:          12335,
						AuthPassword:    "grape",
						NeighborAddress: net.ParseIP("192.168.177.34"),
					},
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

func policy() config.RoutingPolicy {

	ps := config.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList: []config.Prefix{
			config.Prefix{
				IpPrefix:        "10.3.192.0/21",
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
		CommunityList: []config.Community{
			config.Community{Community: "65100:10"},
		},
	}

	ecs := config.ExtCommunitySet{
		ExtCommunitySetName: "ecommunity1",
		ExtCommunityList: []config.ExtCommunity{
			config.ExtCommunity{ExtCommunity: "RT:65001:200"},
		},
	}

	as := config.AsPathSet{
		AsPathSetName: "aspath1",
		AsPathList: []config.AsPath{
			config.AsPath{AsPath: "^65100"},
		},
	}

	bds := config.BgpDefinedSets{

		CommunitySets: config.CommunitySets{
			CommunitySetList: []config.CommunitySet{cs},
		},

		ExtCommunitySets: config.ExtCommunitySets{
			ExtCommunitySetList: []config.ExtCommunitySet{ecs},
		},

		AsPathSets: config.AsPathSets{
			AsPathSetList: []config.AsPathSet{as},
		},
	}

	ds := config.DefinedSets{

		PrefixSets: config.PrefixSets{
			PrefixSetList: []config.PrefixSet{ps},
		},

		NeighborSets: config.NeighborSets{
			NeighborSetList: []config.NeighborSet{ns},
		},

		BgpDefinedSets: bds,
	}

	al := config.AsPathLength{
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

			BgpConditions: config.BgpConditions{
				MatchCommunitySet: config.MatchCommunitySet{
					CommunitySet:    "community1",
					MatchSetOptions: config.MATCH_SET_OPTIONS_TYPE_ANY,
				},

				MatchExtCommunitySet: config.MatchExtCommunitySet{
					ExtCommunitySet: "ecommunity1",
					MatchSetOptions: config.MATCH_SET_OPTIONS_TYPE_ANY,
				},

				MatchAsPathSet: config.MatchAsPathSet{
					AsPathSet:       "aspath1",
					MatchSetOptions: config.MATCH_SET_OPTIONS_TYPE_ANY,
				},
				AsPathLength: al,
			},
		},
		Actions: config.Actions{
			RouteDisposition: config.RouteDisposition{
				AcceptRoute: false,
				RejectRoute: true,
			},
			BgpActions: config.BgpActions{
				SetCommunity: config.SetCommunity{
					SetCommunityMethod: config.SetCommunityMethod{
						Communities: []string{"65100:20"},
					},
					Options: "ADD",
				},
				SetMed: "-200",
			},
		},
	}

	pd := config.PolicyDefinition{
		Name: "pd1",
		Statements: config.Statements{
			StatementList: []config.Statement{s},
		},
	}

	p := config.RoutingPolicy{
		DefinedSets: ds,
		PolicyDefinitions: config.PolicyDefinitions{
			PolicyDefinitionList: []config.PolicyDefinition{pd},
		},
	}

	return p
}
