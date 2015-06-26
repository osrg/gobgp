package main

import (
	"bytes"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/jessevdk/go-flags"
	"github.com/osrg/gobgp/config"
	"io/ioutil"
	"log"
	"net"
	"os"
)

func bindPolicy(outputDir, peer, target, policyName string, isReplace bool, defaultReject bool) {

	newConf := config.Bgp{}
	_, d_err := toml.DecodeFile(fmt.Sprintf("%s/gobgpd.conf", outputDir), &newConf)
	if d_err != nil {
		log.Fatal(d_err)
	}

	for idx, neighbor := range newConf.NeighborList {
		ip := net.ParseIP(peer)

		if ip.String() == neighbor.NeighborAddress.String() {
			ap := &neighbor.ApplyPolicy
			switch target {
			case "import":
				if isReplace {
					ap.ImportPolicies = []string{policyName}
				} else {
					ap.ImportPolicies = append(ap.ImportPolicies, policyName)
				}
				if defaultReject {
					ap.DefaultImportPolicy = 1
				}
			case "export":
				if isReplace {
					ap.ExportPolicies = []string{policyName}
				} else {
					ap.ExportPolicies = append(ap.ExportPolicies, policyName)
				}
				if defaultReject {
					ap.DefaultExportPolicy = 1
				}
			case "distribute":
				if isReplace {
					ap.DistributePolicies = []string{policyName}
				} else {
					ap.DistributePolicies = append(ap.DistributePolicies, policyName)
				}
				if defaultReject {
					ap.DefaultDistributePolicy = 1
				}
			}
			newConf.NeighborList[idx] = neighbor
		}
	}

	policyConf := createPolicyConfig()
	var buffer bytes.Buffer
	encoder := toml.NewEncoder(&buffer)
	encoder.Encode(newConf)
	encoder.Encode(policyConf)

	e_err := ioutil.WriteFile(fmt.Sprintf("%s/gobgpd.conf", outputDir), buffer.Bytes(), 0644)
	if e_err != nil {
		log.Fatal(e_err)
	}
}

func createPolicyConfig() *config.RoutingPolicy {

	ps0 := config.PrefixSet{
		PrefixSetName: "ps0",
		PrefixList: []config.Prefix{
			config.Prefix{
				Address:         net.ParseIP("192.168.0.0"),
				Masklength:      16,
				MasklengthRange: "16..24",
			}},
	}

	ps1 := config.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList: []config.Prefix{
			config.Prefix{
				Address:    net.ParseIP("192.168.20.0"),
				Masklength: 24,
			}, config.Prefix{
				Address:    net.ParseIP("192.168.200.0"),
				Masklength: 24,
			}},
	}

	ps2 := config.PrefixSet{
		PrefixSetName: "ps2",
		PrefixList: []config.Prefix{
			config.Prefix{
				Address:    net.ParseIP("192.168.20.0"),
				Masklength: 24,
			}},
	}

	ps3 := config.PrefixSet{
		PrefixSetName: "ps3",
		PrefixList: []config.Prefix{
			config.Prefix{
				Address:         net.ParseIP("2001:0:10:2::"),
				Masklength:      64,
				MasklengthRange: "64..128",
			}},
	}

	ps4 := config.PrefixSet{
		PrefixSetName: "ps4",
		PrefixList: []config.Prefix{
			config.Prefix{
				Address:    net.ParseIP("2001:0:10:20::"),
				Masklength: 64,
			}, config.Prefix{
				Address:    net.ParseIP("2001:0:10:200::"),
				Masklength: 64,
			}},
	}

	ps5 := config.PrefixSet{
		PrefixSetName: "ps5",
		PrefixList: []config.Prefix{
			config.Prefix{
				Address:    net.ParseIP("2001:0:10:20::"),
				Masklength: 64,
			}},
	}

	ps6 := config.PrefixSet{
		PrefixSetName: "ps6",
		PrefixList: []config.Prefix{
			config.Prefix{
				Address:    net.ParseIP("192.168.10.0"),
				Masklength: 24,
			}},
	}

	nsPeer2 := config.NeighborSet{
		NeighborSetName: "nsPeer2",
		NeighborInfoList: []config.NeighborInfo{
			config.NeighborInfo{
				Address: net.ParseIP("10.0.0.2"),
			}},
	}

	nsPeer2V6 := config.NeighborSet{
		NeighborSetName: "nsPeer2V6",
		NeighborInfoList: []config.NeighborInfo{
			config.NeighborInfo{
				Address: net.ParseIP("2001::0:192:168:0:2"),
			}},
	}

	nsExabgp := config.NeighborSet{
		NeighborSetName: "nsExabgp",
		NeighborInfoList: []config.NeighborInfo{
			config.NeighborInfo{
				Address: net.ParseIP("10.0.0.100"),
			}},
	}

	psExabgp := config.PrefixSet{
		PrefixSetName: "psExabgp",
		PrefixList: []config.Prefix{
			config.Prefix{
				Address:         net.ParseIP("192.168.100.0"),
				Masklength:      24,
				MasklengthRange: "16..24",
			}},
	}

	aspathFrom := config.AsPathSet{
		AsPathSetName:    "aspathFrom",
		AsPathSetMembers: []string{"^65100"},
	}

	aspathAny := config.AsPathSet{
		AsPathSetName:    "aspAny",
		AsPathSetMembers: []string{"65098"},
	}

	aspathOrigin := config.AsPathSet{
		AsPathSetName:    "aspOrigin",
		AsPathSetMembers: []string{"65091$"},
	}

	aspathOnly := config.AsPathSet{
		AsPathSetName:    "aspOnly",
		AsPathSetMembers: []string{"^65100$"},
	}

	comStr := config.CommunitySet{
		CommunitySetName: "comStr",
		CommunityMembers: []string{"65100:10"},
	}

	comRegExp := config.CommunitySet{
		CommunitySetName: "comRegExp",
		CommunityMembers: []string{"6[0-9]+:[0-9]+"},
	}

	st0 := config.Statement{
		Name: "st0",
		Conditions: config.Conditions{
			MatchPrefixSet:   "ps0",
			MatchNeighborSet: "nsPeer2",
			MatchSetOptions:  config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: false,
		},
	}

	st1 := config.Statement{
		Name: "st1",
		Conditions: config.Conditions{
			MatchPrefixSet:   "ps1",
			MatchNeighborSet: "nsPeer2",
			MatchSetOptions:  config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: false,
		},
	}

	st2 := config.Statement{
		Name: "st2",
		Conditions: config.Conditions{
			MatchPrefixSet:   "ps2",
			MatchNeighborSet: "nsPeer2",
			MatchSetOptions:  config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: false,
			RejectRoute: true,
		},
	}

	st3 := config.Statement{
		Name: "st3",
		Conditions: config.Conditions{
			MatchPrefixSet:   "ps3",
			MatchNeighborSet: "nsPeer2V6",
			MatchSetOptions:  config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: false,
		},
	}

	st4 := config.Statement{
		Name: "st4",
		Conditions: config.Conditions{
			MatchPrefixSet:   "ps4",
			MatchNeighborSet: "nsPeer2V6",
			MatchSetOptions:  config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: false,
		},
	}

	st5 := config.Statement{
		Name: "st5",
		Conditions: config.Conditions{
			MatchPrefixSet:   "ps5",
			MatchNeighborSet: "nsPeer2V6",
			MatchSetOptions:  config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: false,
			RejectRoute: true,
		},
	}

	st_aspathlen := config.Statement{
		Name: "st_aspathlen",
		Conditions: config.Conditions{
			MatchPrefixSet:   "psExabgp",
			MatchNeighborSet: "nsExabgp",
			BgpConditions: config.BgpConditions{
				AsPathLength: config.AsPathLength{
					Operator: "ge",
					Value:    10,
				},
			},
			MatchSetOptions: config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: false,
		},
	}

	st_aspathFrom := config.Statement{
		Name: "st_aspathlen",
		Conditions: config.Conditions{
			MatchPrefixSet:   "psExabgp",
			MatchNeighborSet: "nsExabgp",
			BgpConditions: config.BgpConditions{
				MatchAsPathSet: "aspathFrom",
			},
			MatchSetOptions: config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: false,
		},
	}

	st_aspathAny := config.Statement{
		Name: "st_aspathlen",
		Conditions: config.Conditions{
			MatchPrefixSet:   "psExabgp",
			MatchNeighborSet: "nsExabgp",
			BgpConditions: config.BgpConditions{
				MatchAsPathSet: "aspAny",
			},
			MatchSetOptions: config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: false,
		},
	}

	st_aspathOrigin := config.Statement{
		Name: "st_aspathlen",
		Conditions: config.Conditions{
			MatchPrefixSet:   "psExabgp",
			MatchNeighborSet: "nsExabgp",
			BgpConditions: config.BgpConditions{
				MatchAsPathSet: "aspOrigin",
			},
			MatchSetOptions: config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: false,
		},
	}

	st_aspathOnly := config.Statement{
		Name: "st_aspathlen",
		Conditions: config.Conditions{
			MatchPrefixSet:   "psExabgp",
			MatchNeighborSet: "nsExabgp",
			BgpConditions: config.BgpConditions{
				MatchAsPathSet: "aspOnly",
			},
			MatchSetOptions: config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: false,
		},
	}

	st_comStr := config.Statement{
		Name: "st_community",
		Conditions: config.Conditions{
			MatchPrefixSet:   "psExabgp",
			MatchNeighborSet: "nsExabgp",
			BgpConditions: config.BgpConditions{
				MatchCommunitySet: "comStr",
			},
			MatchSetOptions: config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: false,
		},
	}

	st_comRegExp := config.Statement{
		Name: "st_community_regexp",
		Conditions: config.Conditions{
			MatchPrefixSet:   "psExabgp",
			MatchNeighborSet: "nsExabgp",
			BgpConditions: config.BgpConditions{
				MatchCommunitySet: "comRegExp",
			},
			MatchSetOptions: config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: false,
		},
	}

	st_comAdd := config.Statement{
		Name: "st_community_regexp",
		Conditions: config.Conditions{
			MatchPrefixSet:   "psExabgp",
			MatchNeighborSet: "nsExabgp",
			BgpConditions: config.BgpConditions{
				MatchCommunitySet: "comStr",
			},
			MatchSetOptions: config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: true,
			BgpActions: config.BgpActions{
				SetCommunity: config.SetCommunity{
					Communities: []string{"65100:20"},
					Options:     "ADD",
				},
			},
		},
	}

	st_comReplace := config.Statement{
		Name: "st_community_regexp",
		Conditions: config.Conditions{
			MatchPrefixSet:   "psExabgp",
			MatchNeighborSet: "nsExabgp",
			BgpConditions: config.BgpConditions{
				MatchCommunitySet: "comStr",
			},
			MatchSetOptions: config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: true,
			BgpActions: config.BgpActions{
				SetCommunity: config.SetCommunity{
					Communities: []string{"65100:20", "65100:30"},
					Options:     "REPLACE",
				},
			},
		},
	}

	st_comRemove := config.Statement{
		Name: "st_community_regexp",
		Conditions: config.Conditions{
			MatchPrefixSet:   "psExabgp",
			MatchNeighborSet: "nsExabgp",
			BgpConditions: config.BgpConditions{
				MatchCommunitySet: "comStr",
			},
			MatchSetOptions: config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: true,
			BgpActions: config.BgpActions{
				SetCommunity: config.SetCommunity{
					Communities: []string{"65100:20", "65100:30"},
					Options:     "REMOVE",
				},
			},
		},
	}

	st_comNull := config.Statement{
		Name: "st_community_regexp",
		Conditions: config.Conditions{
			MatchPrefixSet:   "psExabgp",
			MatchNeighborSet: "nsExabgp",
			BgpConditions: config.BgpConditions{
				MatchCommunitySet: "comStr",
			},
			MatchSetOptions: config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: true,
			BgpActions: config.BgpActions{
				SetCommunity: config.SetCommunity{
					Communities: []string{},
					Options:     "NULL",
				},
			},
		},
	}

	st_distribute_reject := config.Statement{
		Name: "st_community_distriibute",
		Conditions: config.Conditions{
			BgpConditions: config.BgpConditions{
				MatchCommunitySet: "comStr",
			},
			MatchSetOptions: config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: false,
		},
	}

	st_distribute_accept := config.Statement{
		Name: "st_distriibute_accept",
		Conditions: config.Conditions{
			MatchPrefixSet:  "ps6",
			MatchSetOptions: config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: true,
		},
	}

	st_distribute_comm_add := config.Statement{
		Name: "st_distribute_comm_add",
		Conditions: config.Conditions{
			BgpConditions: config.BgpConditions{
				MatchCommunitySet: "comStr",
			},
			MatchSetOptions: config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: true,
			BgpActions: config.BgpActions{
				SetCommunity: config.SetCommunity{
					Communities: []string{"65100:20"},
					Options:     "ADD",
				},
			},
		},
	}

	test_01_import_policy_initial := config.PolicyDefinition{
		Name:          "test_01_import_policy_initial",
		StatementList: []config.Statement{st0},
	}

	test_02_export_policy_initial := config.PolicyDefinition{
		Name:          "test_02_export_policy_initial",
		StatementList: []config.Statement{st0},
	}

	test_03_import_policy_update := config.PolicyDefinition{
		Name:          "test_03_import_policy_update",
		StatementList: []config.Statement{st1},
	}

	test_03_import_policy_update_softreset := config.PolicyDefinition{
		Name:          "test_03_import_policy_update_softreset",
		StatementList: []config.Statement{st2},
	}

	test_04_export_policy_update := config.PolicyDefinition{
		Name:          "test_04_export_policy_update",
		StatementList: []config.Statement{st1},
	}

	test_04_export_policy_update_softreset := config.PolicyDefinition{
		Name:          "test_04_export_policy_update_softreset",
		StatementList: []config.Statement{st2},
	}

	test_05_import_policy_initial_ipv6 := config.PolicyDefinition{
		Name:          "test_05_import_policy_initial_ipv6",
		StatementList: []config.Statement{st3},
	}

	test_06_export_policy_initial_ipv6 := config.PolicyDefinition{
		Name:          "test_06_export_policy_initial_ipv6",
		StatementList: []config.Statement{st3},
	}

	test_07_import_policy_update := config.PolicyDefinition{
		Name:          "test_07_import_policy_update",
		StatementList: []config.Statement{st4},
	}

	test_07_import_policy_update_softreset := config.PolicyDefinition{
		Name:          "test_07_import_policy_update_softreset",
		StatementList: []config.Statement{st5},
	}

	test_08_export_policy_update := config.PolicyDefinition{
		Name:          "test_08_export_policy_update",
		StatementList: []config.Statement{st4},
	}

	test_08_export_policy_update_softreset := config.PolicyDefinition{
		Name:          "test_08_export_policy_update_softreset",
		StatementList: []config.Statement{st5},
	}

	test_09_aspath_length_condition_import := config.PolicyDefinition{
		Name:          "test_09_aspath_length_condition_import",
		StatementList: []config.Statement{st_aspathlen},
	}

	test_10_aspath_from_condition_import := config.PolicyDefinition{
		Name:          "test_10_aspath_from_condition_import",
		StatementList: []config.Statement{st_aspathFrom},
	}

	test_11_aspath_any_condition_import := config.PolicyDefinition{
		Name:          "test_11_aspath_any_condition_import",
		StatementList: []config.Statement{st_aspathAny},
	}

	test_12_aspath_origin_condition_import := config.PolicyDefinition{
		Name:          "test_12_aspath_origin_condition_import",
		StatementList: []config.Statement{st_aspathOrigin},
	}

	test_13_aspath_only_condition_import := config.PolicyDefinition{
		Name:          "test_13_aspath_only_condition_import",
		StatementList: []config.Statement{st_aspathOnly},
	}

	test_14_aspath_only_condition_import := config.PolicyDefinition{
		Name:          "test_14_aspath_only_condition_import",
		StatementList: []config.Statement{st_comStr},
	}

	test_15_community_condition_import := config.PolicyDefinition{
		Name:          "test_15_community_condition_import",
		StatementList: []config.Statement{st_comStr},
	}

	test_16_community_condition_regexp_import := config.PolicyDefinition{
		Name:          "test_16_community_condition_regexp_import",
		StatementList: []config.Statement{st_comRegExp},
	}

	test_17_community_add_action_import := config.PolicyDefinition{
		Name:          "test_17_community_add_action_import",
		StatementList: []config.Statement{st_comAdd},
	}

	test_18_community_replace_action_import := config.PolicyDefinition{
		Name:          "test_18_community_replace_action_import",
		StatementList: []config.Statement{st_comReplace},
	}

	test_19_community_remove_action_import := config.PolicyDefinition{
		Name:          "test_19_community_remove_action_import",
		StatementList: []config.Statement{st_comRemove},
	}

	test_20_community_null_action_import := config.PolicyDefinition{
		Name:          "test_20_community_null_action_import",
		StatementList: []config.Statement{st_comNull},
	}

	test_21_community_add_action_export := config.PolicyDefinition{
		Name:          "test_21_community_add_action_export",
		StatementList: []config.Statement{st_comAdd},
	}

	test_22_community_replace_action_export := config.PolicyDefinition{
		Name:          "test_22_community_replace_action_export",
		StatementList: []config.Statement{st_comReplace},
	}

	test_23_community_remove_action_export := config.PolicyDefinition{
		Name:          "test_23_community_remove_action_export",
		StatementList: []config.Statement{st_comRemove},
	}

	test_24_community_null_action_export := config.PolicyDefinition{
		Name:          "test_24_community_null_action_export",
		StatementList: []config.Statement{st_comNull},
	}

	test_25_distribute_reject := config.PolicyDefinition{
		Name:          "test_25_distribute_reject",
		StatementList: []config.Statement{st_distribute_reject},
	}

	test_26_distribute_accept := config.PolicyDefinition{
		Name:          "test_26_distribute_accept",
		StatementList: []config.Statement{st_distribute_accept},
	}

	test_27_distribute_set_community_action := config.PolicyDefinition{
		Name:          "test_27_distribute_set_community_action",
		StatementList: []config.Statement{st_distribute_comm_add},
	}

	ds := config.DefinedSets{
		PrefixSetList:   []config.PrefixSet{ps0, ps1, ps2, ps3, ps4, ps5, ps6, psExabgp},
		NeighborSetList: []config.NeighborSet{nsPeer2, nsPeer2V6, nsExabgp},
		BgpDefinedSets: config.BgpDefinedSets{
			AsPathSetList:    []config.AsPathSet{aspathFrom, aspathAny, aspathOrigin, aspathOnly},
			CommunitySetList: []config.CommunitySet{comStr, comRegExp},
		},
	}

	p := &config.RoutingPolicy{
		DefinedSets: ds,
		PolicyDefinitionList: []config.PolicyDefinition{
			test_01_import_policy_initial,
			test_02_export_policy_initial,
			test_03_import_policy_update,
			test_03_import_policy_update_softreset,
			test_04_export_policy_update,
			test_04_export_policy_update_softreset,
			test_05_import_policy_initial_ipv6,
			test_06_export_policy_initial_ipv6,
			test_07_import_policy_update,
			test_07_import_policy_update_softreset,
			test_08_export_policy_update,
			test_08_export_policy_update_softreset,
			test_09_aspath_length_condition_import,
			test_10_aspath_from_condition_import,
			test_11_aspath_any_condition_import,
			test_12_aspath_origin_condition_import,
			test_13_aspath_only_condition_import,
			test_14_aspath_only_condition_import,
			test_15_community_condition_import,
			test_16_community_condition_regexp_import,
			test_17_community_add_action_import,
			test_18_community_replace_action_import,
			test_19_community_remove_action_import,
			test_20_community_null_action_import,
			test_21_community_add_action_export,
			test_22_community_replace_action_export,
			test_23_community_remove_action_export,
			test_24_community_null_action_export,
			test_25_distribute_reject,
			test_26_distribute_accept,
			test_27_distribute_set_community_action,
		},
	}
	return p
}

func main() {
	var opts struct {
		OutputDir  string `short:"d" long:"output" description:"specifing the output directory"`
		Neighbor   string `short:"n" long:"neighbor" description:"neighbor ip adress to which add policy config"`
		Target     string `short:"t" long:"target" description:"target such as export or import to which add policy"`
		PolicyName string `short:"p" long:"policy" description:"policy name bound to peer"`
		Replace    bool   `short:"r" long:"replace" description:"Replace existing policy with new one" default:"false"`
		Reject     bool   `short:"j" long:"reject" description:"Set default policy reject" default:"false"`
	}

	parser := flags.NewParser(&opts, flags.Default)
	_, err := parser.Parse()
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	}

	if _, err := os.Stat(opts.OutputDir + "/gobgpd.conf"); os.IsNotExist(err) {
		log.Fatal(err)
	}

	bindPolicy(opts.OutputDir, opts.Neighbor, opts.Target, opts.PolicyName, opts.Replace, opts.Reject)
}
