package main

import (
	"bytes"
	"fmt"
	"net/netip"

	"github.com/BurntSushi/toml"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
)

func main() {
	b := oc.Bgp{
		Global: oc.Global{
			Config: oc.GlobalConfig{
				As:       12332,
				RouterId: netip.MustParseAddr("10.0.0.1"),
			},
		},
		Neighbors: []oc.Neighbor{
			{
				Config: oc.NeighborConfig{
					PeerAs:          12333,
					AuthPassword:    "apple",
					NeighborAddress: netip.MustParseAddr("192.168.177.33"),
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
					NeighborAddress: netip.MustParseAddr("192.168.177.32"),
				},
			},

			{
				Config: oc.NeighborConfig{
					PeerAs:          12335,
					AuthPassword:    "grape",
					NeighborAddress: netip.MustParseAddr("192.168.177.34"),
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
				IpPrefix:        netip.MustParsePrefix("10.3.192.0/21"),
				MasklengthRange: "21..24",
			},
		},
	}

	rps := oc.PrefixSet{
		PrefixSetName: "rtc1",
		PrefixList: []oc.Prefix{
			// /96: full NLRI (origin-AS + Route Target).
			{
				RtcPrefix:       "65000:65000:100/96",
				MasklengthRange: "96..96",
			},
			// /32: origin-AS only; Route Target is outside the prefix, use 0.
			{
				RtcPrefix:       "65000:0:0/32",
				MasklengthRange: "32..96",
			},
			// /64: origin-AS + 2-octet-AS Route Target AS (local-admin ignored).
			{
				RtcPrefix:       "65000:65000:0/64",
				MasklengthRange: "64..96",
			},
			// /80: + 4-octet/IPv4 Route Target AS (local-admin ignored).
			{
				RtcPrefix:       "65000:100.1000:0/80",
				MasklengthRange: "80..96",
			},
		},
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
		PrefixSets:     []oc.PrefixSet{ps, rps},
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
