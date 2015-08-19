package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/jessevdk/go-flags"
	"github.com/osrg/gobgp/config"
)

func bindPolicy(outputDir, peer, target, policyName string, isReplace bool, defaultReject bool) {

	newConf := config.Bgp{}
	_, d_err := toml.DecodeFile(fmt.Sprintf("%s/gobgpd.conf", outputDir), &newConf)
	if d_err != nil {
		log.Fatal(d_err)
	}

	for idx, neighbor := range newConf.Neighbors.NeighborList {
		ip := net.ParseIP(peer)

		if ip.String() == neighbor.NeighborConfig.NeighborAddress.String() {
			ap := &neighbor.ApplyPolicy.ApplyPolicyConfig
			switch target {
			case "import":
				if isReplace {
					ap.ImportPolicy = []string{policyName}
				} else {
					ap.ImportPolicy = append(ap.ImportPolicy, policyName)
				}
				if defaultReject {
					ap.DefaultImportPolicy = 1
				}
			case "export":
				if isReplace {
					ap.ExportPolicy = []string{policyName}
				} else {
					ap.ExportPolicy = append(ap.ExportPolicy, policyName)
				}
				if defaultReject {
					ap.DefaultExportPolicy = 1
				}
			case "distribute":
				if isReplace {
					ap.InPolicy = []string{policyName}
				} else {
					ap.InPolicy = append(ap.InPolicy, policyName)
				}
				if defaultReject {
					ap.DefaultInPolicy = 1
				}
			}
			newConf.Neighbors.NeighborList[idx] = neighbor
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
				IpPrefix:        "192.168.0.0/16",
				MasklengthRange: "16..24",
			}},
	}

	ps1 := config.PrefixSet{
		PrefixSetName: "ps1",
		PrefixList: []config.Prefix{
			config.Prefix{
				IpPrefix: "192.168.20.0/24",
			}, config.Prefix{
				IpPrefix: "192.168.200.0/24",
			}},
	}

	ps2 := config.PrefixSet{
		PrefixSetName: "ps2",
		PrefixList: []config.Prefix{
			config.Prefix{
				IpPrefix: "192.168.20.0/24",
			}},
	}

	ps3 := config.PrefixSet{
		PrefixSetName: "ps3",
		PrefixList: []config.Prefix{
			config.Prefix{
				IpPrefix:        "2001:0:10:2::/64",
				MasklengthRange: "64..128",
			}},
	}

	ps4 := config.PrefixSet{
		PrefixSetName: "ps4",
		PrefixList: []config.Prefix{
			config.Prefix{
				IpPrefix: "2001:0:10:20::/64",
			}, config.Prefix{
				IpPrefix: "2001:0:10:200::/64",
			}},
	}

	ps5 := config.PrefixSet{
		PrefixSetName: "ps5",
		PrefixList: []config.Prefix{
			config.Prefix{
				IpPrefix: "2001:0:10:20::/64",
			}},
	}

	ps6 := config.PrefixSet{
		PrefixSetName: "ps6",
		PrefixList: []config.Prefix{
			config.Prefix{
				IpPrefix: "192.168.10.0/24",
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
				IpPrefix:        "192.168.100.0/24",
				MasklengthRange: "16..24",
			}},
	}

	aspathFrom := config.AsPathSet{
		AsPathSetName: "aspathFrom",
		AsPathList: []config.AsPath{
			config.AsPath{"^65100"},
		},
	}

	aspathAny := config.AsPathSet{
		AsPathSetName: "aspAny",
		AsPathList: []config.AsPath{
			config.AsPath{"65098"},
		},
	}

	aspathOrigin := config.AsPathSet{
		AsPathSetName: "aspOrigin",
		AsPathList: []config.AsPath{
			config.AsPath{"65091$"},
		},
	}

	aspathOnly := config.AsPathSet{
		AsPathSetName: "aspOnly",
		AsPathList: []config.AsPath{
			config.AsPath{"^65100$"},
		},
	}

	comStr := config.CommunitySet{
		CommunitySetName: "comStr",
		CommunityList: []config.Community{
			config.Community{"65100:10"},
		},
	}

	comRegExp := config.CommunitySet{
		CommunitySetName: "comRegExp",
		CommunityList: []config.Community{
			config.Community{"6[0-9]+:[0-9]+"},
		},
	}
	eComOrigin := config.ExtCommunitySet{
		ExtCommunitySetName: "eComOrigin",
		ExtCommunityList: []config.ExtCommunity{
			config.ExtCommunity{"SoO:65001.65100:200"},
		},
	}
	eComTarget := config.ExtCommunitySet{
		ExtCommunitySetName: "eComTarget",
		ExtCommunityList: []config.ExtCommunity{
			config.ExtCommunity{"RT:6[0-9]+:3[0-9]+"},
		},
	}

	createStatement := func(name string, ps, ns string, accept bool) config.Statement {
		st := config.Statement{}
		st.Name = name
		st.Actions.RouteDisposition.AcceptRoute = accept

		if ps != "" {
			st.Conditions.MatchPrefixSet.PrefixSet = ps
		}

		if ns != "" {
			st.Conditions.MatchNeighborSet.NeighborSet = ns
		}

		return st
	}

	st0 := createStatement("st0", "ps0", "nsPeer2", false)
	st1 := createStatement("st1", "ps1", "nsPeer2", false)
	st2 := createStatement("st2", "ps2", "nsPeer2", false)
	st3 := createStatement("st3", "ps3", "nsPeer2V6", false)
	st4 := createStatement("st4", "ps4", "nsPeer2V6", false)
	st5 := createStatement("st5", "ps5", "nsPeer2V6", false)

	st_aspathlen := createStatement("st_aspathlen", "psExabgp", "nsExabgp", false)
	st_aspathlen.Conditions.BgpConditions.AsPathLength.Operator = "ge"
	st_aspathlen.Conditions.BgpConditions.AsPathLength.Value = 10

	st_aspathFrom := createStatement("st_aspathFrom", "psExabgp", "nsExabgp", false)
	st_aspathFrom.Conditions.BgpConditions.MatchAsPathSet.AsPathSet = "aspathFrom"

	st_aspathAny := createStatement("st_aspathAny", "psExabgp", "nsExabgp", false)
	st_aspathAny.Conditions.BgpConditions.MatchAsPathSet.AsPathSet = "aspAny"

	st_aspathOrigin := createStatement("st_aspathOrigin", "psExabgp", "nsExabgp", false)
	st_aspathOrigin.Conditions.BgpConditions.MatchAsPathSet.AsPathSet = "aspOrigin"

	st_aspathOnly := createStatement("st_aspathOnly", "psExabgp", "nsExabgp", false)
	st_aspathOnly.Conditions.BgpConditions.MatchAsPathSet.AsPathSet = "aspOnly"

	st_comStr := createStatement("st_community", "psExabgp", "nsExabgp", false)
	st_comStr.Conditions.BgpConditions.MatchCommunitySet.CommunitySet = "comStr"

	st_comRegExp := createStatement("st_community_regexp", "psExabgp", "nsExabgp", false)
	st_comRegExp.Conditions.BgpConditions.MatchCommunitySet.CommunitySet = "comRegExp"

	st_comAdd := createStatement("st_community_regexp", "psExabgp", "nsExabgp", true)
	st_comAdd.Conditions.BgpConditions.MatchCommunitySet.CommunitySet = "comStr"
	st_comAdd.Actions.BgpActions.SetCommunity.SetCommunityMethod.Communities = []string{"65100:20"}
	st_comAdd.Actions.BgpActions.SetCommunity.Options = "ADD"

	st_comReplace := createStatement("st_community_regexp", "psExabgp", "nsExabgp", true)
	st_comReplace.Conditions.BgpConditions.MatchCommunitySet.CommunitySet = "comStr"
	st_comReplace.Actions.BgpActions.SetCommunity.SetCommunityMethod.Communities = []string{"65100:20", "65100:30"}
	st_comReplace.Actions.BgpActions.SetCommunity.Options = "REPLACE"

	st_comRemove := createStatement("st_community_regexp", "psExabgp", "nsExabgp", true)
	st_comRemove.Conditions.BgpConditions.MatchCommunitySet.CommunitySet = "comStr"
	st_comRemove.Actions.BgpActions.SetCommunity.SetCommunityMethod.Communities = []string{"65100:20", "65100:30"}
	st_comRemove.Actions.BgpActions.SetCommunity.Options = "REMOVE"

	st_comNull := createStatement("st_community_regexp", "psExabgp", "nsExabgp", true)
	st_comNull.Conditions.BgpConditions.MatchCommunitySet.CommunitySet = "comStr"
	st_comNull.Actions.BgpActions.SetCommunity.SetCommunityMethod.Communities = []string{}
	//use REPLACE instead of NULL
	st_comNull.Actions.BgpActions.SetCommunity.Options = "REPLACE"

	st_medReplace := createStatement("st_medReplace", "psExabgp", "nsExabgp", true)
	st_medReplace.Actions.BgpActions.SetMed = "100"

	st_medAdd := createStatement("st_medAdd", "psExabgp", "nsExabgp", true)
	st_medAdd.Actions.BgpActions.SetMed = "+100"

	st_medSub := createStatement("st_medSub", "psExabgp", "nsExabgp", true)
	st_medSub.Actions.BgpActions.SetMed = "-100"

	st_distribute_reject := createStatement("st_community_distriibute", "", "", false)
	st_distribute_reject.Conditions.BgpConditions.MatchCommunitySet.CommunitySet = "comStr"

	st_distribute_accept := createStatement("st_distriibute_accept", "ps6", "", true)

	st_distribute_comm_add := createStatement("st_distribute_comm_add", "", "", true)
	st_distribute_comm_add.Conditions.BgpConditions.MatchCommunitySet.CommunitySet = "comStr"
	st_distribute_comm_add.Actions.BgpActions.SetCommunity.SetCommunityMethod.Communities = []string{"65100:20"}
	st_distribute_comm_add.Actions.BgpActions.SetCommunity.Options = "ADD"

	st_distribute_med_add := createStatement("st_distribute_med_add", "psExabgp", "nsExabgp", true)
	st_distribute_med_add.Actions.BgpActions.SetMed = "+100"

	st_asprepend := createStatement("st_asprepend", "psExabgp", "nsExabgp", true)
	st_asprepend.Actions.BgpActions.SetAsPathPrepend.As = "65005"
	st_asprepend.Actions.BgpActions.SetAsPathPrepend.RepeatN = 5

	st_asprepend_lastas := createStatement("st_asprepend_lastas", "psExabgp", "nsExabgp", true)
	st_asprepend_lastas.Actions.BgpActions.SetAsPathPrepend.As = "last-as"
	st_asprepend_lastas.Actions.BgpActions.SetAsPathPrepend.RepeatN = 5

	st_eComOrigin := createStatement("st_eComAS4", "psExabgp", "nsExabgp", false)
	st_eComOrigin.Conditions.BgpConditions.MatchExtCommunitySet.ExtCommunitySet = "eComOrigin"

	st_eComTarget := createStatement("st_eComRegExp", "psExabgp", "nsExabgp", false)
	st_eComTarget.Conditions.BgpConditions.MatchExtCommunitySet.ExtCommunitySet = "eComTarget"

	st_only_prefix_condition_accept := createStatement("st_only_prefix_condition_accept", "psExabgp", "", true)

	st_extcomAdd := createStatement("st_extcommunity_add", "psExabgp", "nsExabgp", true)
	st_extcomAdd.Actions.BgpActions.SetExtCommunity.SetExtCommunityMethod.Communities = []string{"0:2:0xfd:0xe8:0:0:0:1"}
	st_extcomAdd.Actions.BgpActions.SetExtCommunity.Options = "ADD"

	st_extcomAdd_append := createStatement("st_extcommunity_add_append", "psExabgp", "nsExabgp", true)
	st_extcomAdd_append.Actions.BgpActions.SetExtCommunity.SetExtCommunityMethod.Communities = []string{"0:2:0xfe:0x4c:0:0:0:0x64"}
	st_extcomAdd_append.Actions.BgpActions.SetExtCommunity.Options = "ADD"

	st_extcomAdd_multiple := createStatement("st_extcommunity_add_multiple", "psExabgp", "nsExabgp", true)
	st_extcomAdd_multiple.Actions.BgpActions.SetExtCommunity.SetExtCommunityMethod.Communities = []string{"0:2:0xfe:0x4c:0:0:0:0x64", "0:2:0:0x64:0:0:0:0x64"}
	st_extcomAdd_multiple.Actions.BgpActions.SetExtCommunity.Options = "ADD"

	test_01_import_policy_initial := config.PolicyDefinition{
		Name: "test_01_import_policy_initial",
		Statements: config.Statements{
			StatementList: []config.Statement{st0},
		},
	}

	test_02_export_policy_initial := config.PolicyDefinition{
		Name: "test_02_export_policy_initial",
		Statements: config.Statements{
			StatementList: []config.Statement{st0},
		},
	}

	test_03_import_policy_update := config.PolicyDefinition{
		Name: "test_03_import_policy_update",
		Statements: config.Statements{
			StatementList: []config.Statement{st1},
		},
	}

	test_03_import_policy_update_softreset := config.PolicyDefinition{
		Name: "test_03_import_policy_update_softreset",
		Statements: config.Statements{
			StatementList: []config.Statement{st2},
		},
	}

	test_04_export_policy_update := config.PolicyDefinition{
		Name: "test_04_export_policy_update",
		Statements: config.Statements{
			StatementList: []config.Statement{st1},
		},
	}

	test_04_export_policy_update_softreset := config.PolicyDefinition{
		Name: "test_04_export_policy_update_softreset",
		Statements: config.Statements{
			StatementList: []config.Statement{st2},
		},
	}

	test_05_import_policy_initial_ipv6 := config.PolicyDefinition{
		Name: "test_05_import_policy_initial_ipv6",
		Statements: config.Statements{
			StatementList: []config.Statement{st3},
		},
	}

	test_06_export_policy_initial_ipv6 := config.PolicyDefinition{
		Name: "test_06_export_policy_initial_ipv6",
		Statements: config.Statements{
			StatementList: []config.Statement{st3},
		},
	}

	test_07_import_policy_update := config.PolicyDefinition{
		Name: "test_07_import_policy_update",
		Statements: config.Statements{
			StatementList: []config.Statement{st4},
		},
	}

	test_07_import_policy_update_softreset := config.PolicyDefinition{
		Name: "test_07_import_policy_update_softreset",
		Statements: config.Statements{
			StatementList: []config.Statement{st5},
		},
	}

	test_08_export_policy_update := config.PolicyDefinition{
		Name: "test_08_export_policy_update",
		Statements: config.Statements{
			StatementList: []config.Statement{st4},
		},
	}

	test_08_export_policy_update_softreset := config.PolicyDefinition{
		Name: "test_08_export_policy_update_softreset",
		Statements: config.Statements{
			StatementList: []config.Statement{st5},
		},
	}

	test_09_aspath_length_condition_import := config.PolicyDefinition{
		Name: "test_09_aspath_length_condition_import",
		Statements: config.Statements{
			StatementList: []config.Statement{st_aspathlen},
		},
	}

	test_10_aspath_from_condition_import := config.PolicyDefinition{
		Name: "test_10_aspath_from_condition_import",
		Statements: config.Statements{
			StatementList: []config.Statement{st_aspathFrom},
		},
	}

	test_11_aspath_any_condition_import := config.PolicyDefinition{
		Name: "test_11_aspath_any_condition_import",
		Statements: config.Statements{
			StatementList: []config.Statement{st_aspathAny},
		},
	}

	test_12_aspath_origin_condition_import := config.PolicyDefinition{
		Name: "test_12_aspath_origin_condition_import",
		Statements: config.Statements{
			StatementList: []config.Statement{st_aspathOrigin},
		},
	}

	test_13_aspath_only_condition_import := config.PolicyDefinition{
		Name: "test_13_aspath_only_condition_import",
		Statements: config.Statements{
			StatementList: []config.Statement{st_aspathOnly},
		},
	}

	test_14_aspath_only_condition_import := config.PolicyDefinition{
		Name: "test_14_aspath_only_condition_import",
		Statements: config.Statements{
			StatementList: []config.Statement{st_comStr},
		},
	}

	test_15_community_condition_import := config.PolicyDefinition{
		Name: "test_15_community_condition_import",
		Statements: config.Statements{
			StatementList: []config.Statement{st_comStr},
		},
	}

	test_16_community_condition_regexp_import := config.PolicyDefinition{
		Name: "test_16_community_condition_regexp_import",
		Statements: config.Statements{
			StatementList: []config.Statement{st_comRegExp},
		},
	}

	test_17_community_add_action_import := config.PolicyDefinition{
		Name: "test_17_community_add_action_import",
		Statements: config.Statements{
			StatementList: []config.Statement{st_comAdd},
		},
	}

	test_18_community_replace_action_import := config.PolicyDefinition{
		Name: "test_18_community_replace_action_import",
		Statements: config.Statements{
			StatementList: []config.Statement{st_comReplace},
		},
	}

	test_19_community_remove_action_import := config.PolicyDefinition{
		Name: "test_19_community_remove_action_import",
		Statements: config.Statements{
			StatementList: []config.Statement{st_comRemove},
		},
	}

	test_20_community_null_action_import := config.PolicyDefinition{
		Name: "test_20_community_null_action_import",
		Statements: config.Statements{
			StatementList: []config.Statement{st_comNull},
		},
	}

	test_21_community_add_action_export := config.PolicyDefinition{
		Name: "test_21_community_add_action_export",
		Statements: config.Statements{
			StatementList: []config.Statement{st_comAdd},
		},
	}

	test_22_community_replace_action_export := config.PolicyDefinition{
		Name: "test_22_community_replace_action_export",
		Statements: config.Statements{
			StatementList: []config.Statement{st_comReplace},
		},
	}

	test_23_community_remove_action_export := config.PolicyDefinition{
		Name: "test_23_community_remove_action_export",
		Statements: config.Statements{
			StatementList: []config.Statement{st_comRemove},
		},
	}

	test_24_community_null_action_export := config.PolicyDefinition{
		Name: "test_24_community_null_action_export",
		Statements: config.Statements{
			StatementList: []config.Statement{st_comNull},
		},
	}

	test_25_med_replace_action_import := config.PolicyDefinition{
		Name: "test_25_med_replace_action_import",
		Statements: config.Statements{
			StatementList: []config.Statement{st_medReplace},
		},
	}

	test_26_med_add_action_import := config.PolicyDefinition{
		Name: "test_26_med_add_action_import",
		Statements: config.Statements{
			StatementList: []config.Statement{st_medAdd},
		},
	}

	test_27_med_subtract_action_import := config.PolicyDefinition{
		Name: "test_27_med_subtract_action_import",
		Statements: config.Statements{
			StatementList: []config.Statement{st_medSub},
		},
	}

	test_28_med_replace_action_export := config.PolicyDefinition{
		Name: "test_28_med_replace_action_export",
		Statements: config.Statements{
			StatementList: []config.Statement{st_medReplace},
		},
	}

	test_29_med_add_action_export := config.PolicyDefinition{
		Name: "test_29_med_add_action_export",
		Statements: config.Statements{
			StatementList: []config.Statement{st_medAdd},
		},
	}

	test_30_med_subtract_action_export := config.PolicyDefinition{
		Name: "test_30_med_subtract_action_export",
		Statements: config.Statements{
			StatementList: []config.Statement{st_medSub},
		},
	}

	test_31_distribute_reject := config.PolicyDefinition{
		Name: "test_31_distribute_reject",
		Statements: config.Statements{
			StatementList: []config.Statement{st_distribute_reject},
		},
	}

	test_32_distribute_accept := config.PolicyDefinition{
		Name: "test_32_distribute_accept",
		Statements: config.Statements{
			StatementList: []config.Statement{st_distribute_accept},
		},
	}

	test_33_distribute_set_community_action := config.PolicyDefinition{
		Name: "test_33_distribute_set_community_action",
		Statements: config.Statements{
			StatementList: []config.Statement{st_distribute_comm_add},
		},
	}

	test_34_distribute_set_med_action := config.PolicyDefinition{
		Name: "test_34_distribute_set_med_action",
		Statements: config.Statements{
			StatementList: []config.Statement{st_distribute_med_add},
		},
	}

	test_35_distribute_policy_update := config.PolicyDefinition{
		Name: "test_35_distribute_policy_update",
		Statements: config.Statements{
			StatementList: []config.Statement{st1},
		},
	}

	test_35_distribute_policy_update_softreset := config.PolicyDefinition{
		Name: "test_35_distribute_policy_update_softreset",
		Statements: config.Statements{
			StatementList: []config.Statement{st2},
		},
	}

	test_36_aspath_prepend_action_import := config.PolicyDefinition{
		Name: "test_36_aspath_prepend_action_import",
		Statements: config.Statements{
			StatementList: []config.Statement{st_asprepend},
		},
	}

	test_37_aspath_prepend_action_export := config.PolicyDefinition{
		Name: "test_37_aspath_prepend_action_export",
		Statements: config.Statements{
			StatementList: []config.Statement{st_asprepend},
		},
	}

	test_38_aspath_prepend_action_lastas_import := config.PolicyDefinition{
		Name: "test_38_aspath_prepend_action_lastas_import",
		Statements: config.Statements{
			StatementList: []config.Statement{st_asprepend_lastas},
		},
	}

	test_39_aspath_prepend_action_lastas_export := config.PolicyDefinition{
		Name: "test_39_aspath_prepend_action_lastas_export",
		Statements: config.Statements{
			StatementList: []config.Statement{st_asprepend_lastas},
		},
	}

	test_40_ecommunity_origin_condition_import := config.PolicyDefinition{
		Name: "test_40_ecommunity_origin_condition_import",
		Statements: config.Statements{
			StatementList: []config.Statement{st_eComOrigin},
		},
	}

	test_41_ecommunity_target_condition_export := config.PolicyDefinition{
		Name: "test_41_ecommunity_target_condition_export",
		Statements: config.Statements{
			StatementList: []config.Statement{st_eComTarget},
		},
	}

	test_42_only_prefix_condition_accept := config.PolicyDefinition{
		Name: "test_42_only_prefix_condition_accept",
		Statements: config.Statements{
			StatementList: []config.Statement{st_only_prefix_condition_accept},
		},
	}

	test_43_extcommunity_add_action_import := config.PolicyDefinition{
		Name: "test_43_extcommunity_add_action_import",
		Statements: config.Statements{
			StatementList: []config.Statement{st_extcomAdd},
		},
	}

	test_44_extcommunity_add_action_append_import := config.PolicyDefinition{
		Name: "test_44_extcommunity_add_action_append_import",
		Statements: config.Statements{
			StatementList: []config.Statement{st_extcomAdd_append},
		},
	}

	test_45_extcommunity_add_action_multiple_import := config.PolicyDefinition{
		Name: "test_45_extcommunity_add_action_multiple_import",
		Statements: config.Statements{
			StatementList: []config.Statement{st_extcomAdd_multiple},
		},
	}

	test_46_extcommunity_add_action_export := config.PolicyDefinition{
		Name: "test_46_extcommunity_add_action_export",
		Statements: config.Statements{
			StatementList: []config.Statement{st_extcomAdd},
		},
	}


	ds := config.DefinedSets{}
	ds.PrefixSets.PrefixSetList = []config.PrefixSet{ps0, ps1, ps2, ps3, ps4, ps5, ps6, psExabgp}
	ds.NeighborSets.NeighborSetList = []config.NeighborSet{nsPeer2, nsPeer2V6, nsExabgp}
	ds.BgpDefinedSets.AsPathSets.AsPathSetList = []config.AsPathSet{aspathFrom, aspathAny, aspathOrigin, aspathOnly}
	ds.BgpDefinedSets.CommunitySets.CommunitySetList = []config.CommunitySet{comStr, comRegExp}
	ds.BgpDefinedSets.ExtCommunitySets.ExtCommunitySetList = []config.ExtCommunitySet{eComOrigin, eComTarget}

	p := &config.RoutingPolicy{
		DefinedSets: ds,
		PolicyDefinitions: config.PolicyDefinitions{
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
				test_25_med_replace_action_import,
				test_26_med_add_action_import,
				test_27_med_subtract_action_import,
				test_28_med_replace_action_export,
				test_29_med_add_action_export,
				test_30_med_subtract_action_export,
				test_31_distribute_reject,
				test_32_distribute_accept,
				test_33_distribute_set_community_action,
				test_34_distribute_set_med_action,
				test_35_distribute_policy_update,
				test_35_distribute_policy_update_softreset,
				test_36_aspath_prepend_action_import,
				test_37_aspath_prepend_action_export,
				test_38_aspath_prepend_action_lastas_import,
				test_39_aspath_prepend_action_lastas_export,
				test_40_ecommunity_origin_condition_import,
				test_41_ecommunity_target_condition_export,
				test_42_only_prefix_condition_accept,
				test_43_extcommunity_add_action_import,
				test_44_extcommunity_add_action_append_import,
				test_45_extcommunity_add_action_multiple_import,
				test_46_extcommunity_add_action_export,
			},
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
