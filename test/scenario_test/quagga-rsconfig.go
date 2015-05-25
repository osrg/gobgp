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
	"path/filepath"
)

var serverAddress = make(map[string]string)
var baseNeighborAddress = make(map[string]string)
var baseNeighborNetwork = make(map[string]string)
var baseNeighborNetMask = make(map[string]string)

const (
	IPv4 = "ipv4"
	IPv6 = "ipv6"
)

type QuaggaConfig struct {
	id          int
	config      *config.Neighbor
	gobgpConfig *config.Global
	serverIP    net.IP
}

func NewQuaggaConfig(id int, gConfig *config.Global, myConfig *config.Neighbor, server net.IP) *QuaggaConfig {
	return &QuaggaConfig{
		id:          id,
		config:      myConfig,
		gobgpConfig: gConfig,
		serverIP:    server,
	}
}

func (qt *QuaggaConfig) IPv4Config() *bytes.Buffer {
	buf := bytes.NewBuffer(nil)
	buf.WriteString(fmt.Sprintf("! my address %s\n", qt.config.NeighborAddress))
	buf.WriteString(fmt.Sprintf("! my ip_version %s\n", IPv4))
	buf.WriteString("hostname bgpd\n")
	buf.WriteString("password zebra\n")
	buf.WriteString(fmt.Sprintf("router bgp %d\n", qt.config.PeerAs))
	buf.WriteString(fmt.Sprintf("bgp router-id 192.168.0.%d\n", qt.id))
	buf.WriteString(fmt.Sprintf("network %s%d%s\n", baseNeighborNetwork[IPv4], qt.id, baseNeighborNetMask[IPv4]))
	buf.WriteString(fmt.Sprintf("neighbor %s remote-as %d\n", qt.serverIP, qt.gobgpConfig.As))
	buf.WriteString(fmt.Sprintf("neighbor %s password %s\n", qt.serverIP, qt.config.AuthPassword))
	buf.WriteString("debug bgp as4\n")
	buf.WriteString("debug bgp fsm\n")
	buf.WriteString("debug bgp updates\n")
	buf.WriteString("debug bgp events\n")
	buf.WriteString("log file /var/log/quagga/bgpd.log\n")

	return buf
}

func (qt *QuaggaConfig) IPv6Config() *bytes.Buffer {
	buf := bytes.NewBuffer(nil)
	buf.WriteString(fmt.Sprintf("! my address %s\n", qt.config.NeighborAddress))
	buf.WriteString(fmt.Sprintf("! my ip_version %s\n", IPv6))
	buf.WriteString("hostname bgpd\n")
	buf.WriteString("password zebra\n")
	buf.WriteString(fmt.Sprintf("router bgp %d\n", qt.config.PeerAs))
	buf.WriteString(fmt.Sprintf("bgp router-id 192.168.0.%d\n", qt.id))
	buf.WriteString("no bgp default ipv4-unicast\n")
	buf.WriteString(fmt.Sprintf("neighbor %s remote-as %d\n", qt.serverIP, qt.gobgpConfig.As))
	buf.WriteString(fmt.Sprintf("neighbor %s password %s\n", qt.serverIP, qt.config.AuthPassword))
	buf.WriteString("address-family ipv6\n")
	buf.WriteString(fmt.Sprintf("network %s%d%s\n", baseNeighborNetwork[IPv6], qt.id, baseNeighborNetMask[IPv6]))
	buf.WriteString(fmt.Sprintf("neighbor %s activate\n", qt.serverIP))
	buf.WriteString(fmt.Sprintf("neighbor %s route-map IPV6-OUT out\n", qt.serverIP))
	buf.WriteString("exit-address-family\n")
	buf.WriteString("ipv6 prefix-list pl-ipv6 seq 10 permit any\n")
	buf.WriteString("route-map IPV6-OUT permit 10\n")
	buf.WriteString("match ipv6 address prefix-list pl-ipv6\n")
	buf.WriteString(fmt.Sprintf("set ipv6 next-hop global %s\n", qt.config.NeighborAddress))
	buf.WriteString("debug bgp as4\n")
	buf.WriteString("debug bgp fsm\n")
	buf.WriteString("debug bgp updates\n")
	buf.WriteString("debug bgp events\n")
	buf.WriteString("log file /var/log/quagga/bgpd.log\n")

	return buf
}

func create_config_files(nr int, outputDir string, IPVersion string, nonePeer bool, normalBGP bool, policyPattern string) {
	quaggaConfigList := make([]*QuaggaConfig, 0)

	gobgpConf := config.Bgp{
		Global: config.Global{
			As:       65000,
			RouterId: net.ParseIP("192.168.255.1"),
		},
	}

	var policyConf *config.RoutingPolicy

	for i := 1; i < nr+1; i++ {
		c := config.Neighbor{
			PeerAs:           65000 + uint32(i),
			NeighborAddress:  net.ParseIP(fmt.Sprintf("%s%d", baseNeighborAddress[IPVersion], i)),
			AuthPassword:     fmt.Sprintf("hoge%d", i),
			TransportOptions: config.TransportOptions{PassiveMode: true},
			RouteServer:      config.RouteServer{RouteServerClient: !normalBGP},
			Timers:           config.Timers{HoldTime: 30, KeepaliveInterval: 10, IdleHoldTimeAfterReset: 10},
			PeerType:         config.PEER_TYPE_EXTERNAL,
		}

		policyConf = bindPolicy(&c, policyPattern)

		gobgpConf.NeighborList = append(gobgpConf.NeighborList, c)
		if !nonePeer {
			q := NewQuaggaConfig(i, &gobgpConf.Global, &c, net.ParseIP(serverAddress[IPVersion]))
			quaggaConfigList = append(quaggaConfigList, q)
			os.Mkdir(fmt.Sprintf("%s/q%d", outputDir, i), 0755)
			var err error
			if IPVersion == IPv6 {
				err = ioutil.WriteFile(fmt.Sprintf("%s/q%d/bgpd.conf", outputDir, i), q.IPv6Config().Bytes(), 0644)
			} else {
				err = ioutil.WriteFile(fmt.Sprintf("%s/q%d/bgpd.conf", outputDir, i), q.IPv4Config().Bytes(), 0644)
			}
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	var buffer bytes.Buffer
	encoder := toml.NewEncoder(&buffer)
	encoder.Encode(gobgpConf)
	if policyConf != nil {
		encoder.Encode(policyConf)
	}

	err := ioutil.WriteFile(fmt.Sprintf("%s/gobgpd.conf", outputDir), buffer.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func append_config_files(ar int, outputDir string, IPVersion string, noQuagga bool, normalBGP bool, policyPattern string) {

	gobgpConf := config.Bgp{
		Global: config.Global{
			As:       65000,
			RouterId: net.ParseIP("192.168.255.1"),
		},
	}
	c := config.Neighbor{
		PeerAs:           65000 + uint32(ar),
		NeighborAddress:  net.ParseIP(fmt.Sprintf("%s%d", baseNeighborAddress[IPVersion], ar)),
		AuthPassword:     fmt.Sprintf("hoge%d", ar),
		RouteServer:      config.RouteServer{RouteServerClient: !normalBGP},
		TransportOptions: config.TransportOptions{PassiveMode: true},
		Timers:           config.Timers{HoldTime: 30, KeepaliveInterval: 10, IdleHoldTimeAfterReset: 10},
		PeerType:         config.PEER_TYPE_EXTERNAL,
	}

	bindPolicy(&c, policyPattern)

	if !noQuagga {
		q := NewQuaggaConfig(ar, &gobgpConf.Global, &c, net.ParseIP(serverAddress[IPVersion]))
		os.Mkdir(fmt.Sprintf("%s/q%d", outputDir, ar), 0755)
		var err error
		if IPVersion == IPv6 {
			err = ioutil.WriteFile(fmt.Sprintf("%s/q%d/bgpd.conf", outputDir, ar), q.IPv6Config().Bytes(), 0644)
		} else {
			err = ioutil.WriteFile(fmt.Sprintf("%s/q%d/bgpd.conf", outputDir, ar), q.IPv4Config().Bytes(), 0644)
		}
		if err != nil {
			log.Fatal(err)
		}
	}
	newConf := config.Bgp{}
	_, d_err := toml.DecodeFile(fmt.Sprintf("%s/gobgpd.conf", outputDir), &newConf)
	if d_err != nil {
		log.Fatal(d_err)
	}
	newConf.NeighborList = append(newConf.NeighborList, c)
	var buffer bytes.Buffer
	encoder := toml.NewEncoder(&buffer)
	encoder.Encode(newConf)

	policyConf := &config.RoutingPolicy{}
	_, p_err := toml.DecodeFile(fmt.Sprintf("%s/gobgpd.conf", outputDir), policyConf)
	if p_err != nil {
		log.Fatal(p_err)
	}

	if policyConf != nil && len(policyConf.PolicyDefinitionList) != 0 {
		encoder.Encode(policyConf)
	}

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

	pdImportV4 := config.PolicyDefinition{
		Name:          "policy_use_ps0",
		StatementList: []config.Statement{st0},
	}

	pdExportV4 := config.PolicyDefinition{
		Name:          "policy_use_ps1",
		StatementList: []config.Statement{st1},
	}

	pdImportV6 := config.PolicyDefinition{
		Name:          "policy_use_ps3",
		StatementList: []config.Statement{st3},
	}

	pdExportV6 := config.PolicyDefinition{
		Name:          "policy_use_ps4",
		StatementList: []config.Statement{st4},
	}

	pdAspathlen := config.PolicyDefinition{
		Name:          "policy_aspathlen",
		StatementList: []config.Statement{st_aspathlen},
	}

	pdaspathFrom := config.PolicyDefinition{
		Name:          "policy_aspathFrom",
		StatementList: []config.Statement{st_aspathFrom},
	}

	pdaspathAny := config.PolicyDefinition{
		Name:          "policy_aspathAny",
		StatementList: []config.Statement{st_aspathAny},
	}

	pdaspathOrigin := config.PolicyDefinition{
		Name:          "policy_aspathOrigin",
		StatementList: []config.Statement{st_aspathOrigin},
	}

	pdaspathOnly := config.PolicyDefinition{
		Name:          "policy_aspathOnly",
		StatementList: []config.Statement{st_aspathOnly},
	}

	pdCommunity := config.PolicyDefinition{
		Name:          "policy_community",
		StatementList: []config.Statement{st_comStr},
	}

	pdCommunityRegExp := config.PolicyDefinition{
		Name:          "policy_community_regexp",
		StatementList: []config.Statement{st_comRegExp},
	}

	pdCommunityAdd := config.PolicyDefinition{
		Name:          "policy_community_add",
		StatementList: []config.Statement{st_comAdd},
	}

	pdCommunityReplace := config.PolicyDefinition{
		Name:          "policy_community_replace",
		StatementList: []config.Statement{st_comReplace},
	}

	pdCommunityRemove := config.PolicyDefinition{
		Name:          "policy_community_remove",
		StatementList: []config.Statement{st_comRemove},
	}

	pdCommunityNull := config.PolicyDefinition{
		Name:          "policy_community_null",
		StatementList: []config.Statement{st_comNull},
	}

	ds := config.DefinedSets{
		PrefixSetList:   []config.PrefixSet{ps0, ps1, ps2, ps3, ps4, ps5, psExabgp},
		NeighborSetList: []config.NeighborSet{nsPeer2, nsPeer2V6, nsExabgp},
		BgpDefinedSets: config.BgpDefinedSets{
			AsPathSetList:    []config.AsPathSet{aspathFrom, aspathAny, aspathOrigin, aspathOnly},
			CommunitySetList: []config.CommunitySet{comStr, comRegExp},
		},
	}

	p := &config.RoutingPolicy{
		DefinedSets: ds,
		PolicyDefinitionList: []config.PolicyDefinition{pdImportV4, pdExportV4, pdImportV6, pdExportV6,
			pdAspathlen, pdaspathFrom, pdaspathAny, pdaspathOrigin, pdaspathOnly,
			pdCommunity, pdCommunityRegExp, pdCommunityAdd, pdCommunityReplace, pdCommunityRemove, pdCommunityNull},
	}

	return p
}

func updatePolicyConfig(outputDir string, pattern string) {

	newConf := config.Bgp{}
	policyConf := config.RoutingPolicy{}

	_, d_err := toml.DecodeFile(fmt.Sprintf("%s/gobgpd.conf", outputDir), &newConf)
	if d_err != nil {
		log.Fatal(d_err)
	}
	_, d_err = toml.DecodeFile(fmt.Sprintf("%s/gobgpd.conf", outputDir), &policyConf)
	if d_err != nil {
		log.Fatal(d_err)
	}

	fmt.Println(policyConf)

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

	if pattern == "test_03_import_policy_update" || pattern == "test_04_export_policy_update" {
		policyConf.PolicyDefinitionList[1].StatementList = []config.Statement{st2}
	}

	if pattern == "test_07_import_policy_update" || pattern == "test_08_export_policy_update" {
		policyConf.PolicyDefinitionList[3].StatementList = []config.Statement{st5}
	}

	var buffer bytes.Buffer
	encoder := toml.NewEncoder(&buffer)
	encoder.Encode(newConf)
	encoder.Encode(policyConf)
	e_err := ioutil.WriteFile(fmt.Sprintf("%s/gobgpd.conf", outputDir), buffer.Bytes(), 0644)
	if e_err != nil {
		log.Fatal(e_err)
	}

	return
}

type PolicyBinding struct {
	NeighborAddress   string
	Policy            *config.RoutingPolicy
	ImportPolicyNames []string
	ExportPolicyNames []string
}

func getPolicyBinding(pattern string) *PolicyBinding {

	var pb *PolicyBinding = &PolicyBinding{Policy: createPolicyConfig()}

	switch pattern {
	case "test_01_import_policy_initial":
		pb.NeighborAddress = "10.0.0.3"
		pb.ImportPolicyNames = []string{"policy_use_ps0"}
		pb.ExportPolicyNames = nil

	case "test_02_export_policy_initial":
		pb.NeighborAddress = "10.0.0.3"
		pb.ImportPolicyNames = nil
		pb.ExportPolicyNames = []string{"policy_use_ps0"}

	case "test_03_import_policy_update":
		pb.NeighborAddress = "10.0.0.3"
		pb.ImportPolicyNames = []string{"policy_use_ps1"}
		pb.ExportPolicyNames = nil

	case "test_04_export_policy_update":
		pb.NeighborAddress = "10.0.0.3"
		pb.ImportPolicyNames = nil
		pb.ExportPolicyNames = []string{"policy_use_ps1"}

	case "test_05_import_policy_initial_ipv6":
		pb.NeighborAddress = "2001::0:192:168:0:3"
		pb.ImportPolicyNames = []string{"policy_use_ps3"}
		pb.ExportPolicyNames = nil

	case "test_06_export_policy_initial_ipv6":
		pb.NeighborAddress = "2001::0:192:168:0:3"
		pb.ImportPolicyNames = nil
		pb.ExportPolicyNames = []string{"policy_use_ps3"}

	case "test_07_import_policy_update":
		pb.NeighborAddress = "2001::0:192:168:0:3"
		pb.ImportPolicyNames = []string{"policy_use_ps4"}
		pb.ExportPolicyNames = nil

	case "test_08_export_policy_update":
		pb.NeighborAddress = "2001::0:192:168:0:3"
		pb.ImportPolicyNames = nil
		pb.ExportPolicyNames = []string{"policy_use_ps4"}

	case "test_09_aspath_length_condition_import":
		pb.NeighborAddress = "10.0.0.2"
		pb.ImportPolicyNames = []string{"policy_aspathlen"}
		pb.ExportPolicyNames = nil

	case "test_10_aspath_from_condition_import":
		pb.NeighborAddress = "10.0.0.2"
		pb.ImportPolicyNames = []string{"policy_aspathFrom"}
		pb.ExportPolicyNames = nil

	case "test_11_aspath_any_condition_import":
		pb.NeighborAddress = "10.0.0.2"
		pb.ImportPolicyNames = []string{"policy_aspathAny"}
		pb.ExportPolicyNames = nil

	case "test_12_aspath_origin_condition_import":
		pb.NeighborAddress = "10.0.0.2"
		pb.ImportPolicyNames = []string{"policy_aspathOrigin"}
		pb.ExportPolicyNames = nil

	case "test_13_aspath_only_condition_import":
		pb.NeighborAddress = "10.0.0.2"
		pb.ImportPolicyNames = []string{"policy_aspathOnly"}
		pb.ExportPolicyNames = nil

	case "test_14_aspath_only_condition_import":
		pb.NeighborAddress = "10.0.0.2"
		pb.ImportPolicyNames = []string{"policy_aspathOnly"}
		pb.ExportPolicyNames = nil

	case "test_15_community_condition_import":
		pb.NeighborAddress = "10.0.0.2"
		pb.ImportPolicyNames = []string{"policy_community"}
		pb.ExportPolicyNames = nil

	case "test_16_community_condition_regexp_import":
		pb.NeighborAddress = "10.0.0.2"
		pb.ImportPolicyNames = []string{"policy_community_regexp"}
		pb.ExportPolicyNames = nil

	case "test_17_community_add_action_import":
		pb.NeighborAddress = "10.0.0.2"
		pb.ImportPolicyNames = []string{"policy_community_add"}
		pb.ExportPolicyNames = nil

	case "test_18_community_replace_action_import":
		pb.NeighborAddress = "10.0.0.2"
		pb.ImportPolicyNames = []string{"policy_community_replace"}
		pb.ExportPolicyNames = nil

	case "test_19_community_remove_action_import":
		pb.NeighborAddress = "10.0.0.2"
		pb.ImportPolicyNames = []string{"policy_community_remove"}
		pb.ExportPolicyNames = nil

	case "test_20_community_null_action_import":
		pb.NeighborAddress = "10.0.0.2"
		pb.ImportPolicyNames = []string{"policy_community_null"}
		pb.ExportPolicyNames = nil

	case "test_21_community_add_action_export":
		pb.NeighborAddress = "10.0.0.2"
		pb.ImportPolicyNames = nil
		pb.ExportPolicyNames = []string{"policy_community_add"}

	case "test_22_community_replace_action_export":
		pb.NeighborAddress = "10.0.0.2"
		pb.ImportPolicyNames = nil
		pb.ExportPolicyNames = []string{"policy_community_replace"}

	case "test_23_community_remove_action_export":
		pb.NeighborAddress = "10.0.0.2"
		pb.ImportPolicyNames = nil
		pb.ExportPolicyNames = []string{"policy_community_remove"}

	case "test_24_community_null_action_export":
		pb.NeighborAddress = "10.0.0.2"
		pb.ImportPolicyNames = nil
		pb.ExportPolicyNames = []string{"policy_community_null"}
	default:
		pb = nil
	}

	return pb

}

func bindPolicy(c *config.Neighbor, policyPattern string) *config.RoutingPolicy {
	var binding *PolicyBinding
	if policyPattern != "" {
		binding = getPolicyBinding(policyPattern)
	}

	if binding != nil {
		ip := net.ParseIP(binding.NeighborAddress)
		if ip.String() == c.NeighborAddress.String() {
			ap := config.ApplyPolicy{
				ImportPolicies: binding.ImportPolicyNames,
				ExportPolicies: binding.ExportPolicyNames,
			}
			c.ApplyPolicy = ap
			return binding.Policy
		}
	}
	return nil
}

func main() {
	var opts struct {
		ClientNumber  int    `short:"n" long:"client-number" description:"specfying the number of clients" default:"8"`
		OutputDir     string `short:"c" long:"output" description:"specifing the output directory"`
		AppendClient  int    `short:"a" long:"append" description:"specifing the add client number" default:"0"`
		IPVersion     string `short:"v" long:"ip-version" description:"specifing the use ip version" default:"IPv4"`
		NetIdentifier int    `short:"i" long:"net-identifer" description:"specifing the use network identifier" default:"0"`
		NonePeer      bool   `long:"none-peer" description:"disable make quagga config"`
		NormalBGP     bool   `long:"normal-bgp" description:"generate normal bgp server configuration"`
		PolicyPattern string `short:"p" long:"policy-pattern" description:"specify policy pattern" default:""`
		UpdatePolicy  bool   `long:"update-policy" description:"update exsisting policy config" default:"false"`
	}
	parser := flags.NewParser(&opts, flags.Default)
	_, err := parser.Parse()
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	}
	if opts.OutputDir == "" {
		opts.OutputDir, _ = filepath.Abs(".")
	} else {
		if _, err := os.Stat(opts.OutputDir); os.IsNotExist(err) {
			os.Mkdir(opts.OutputDir, 0755)
		}
	}

	if opts.IPVersion == IPv6 {
		serverAddress[IPv6] = fmt.Sprintf("2001::%d:192:168:255:1", opts.NetIdentifier)
		baseNeighborAddress[IPv6] = fmt.Sprintf("2001::%d:192:168:0:", opts.NetIdentifier)
		baseNeighborNetwork[IPv6] = "2001:0:10:"
		baseNeighborNetMask[IPv6] = "::/64"
	} else {
		opts.IPVersion = IPv4
		serverAddress[IPv4] = fmt.Sprintf("1%d.0.255.1", opts.NetIdentifier)
		baseNeighborAddress[IPv4] = fmt.Sprintf("1%d.0.0.", opts.NetIdentifier)
		baseNeighborNetwork[IPv4] = "192.168."
		baseNeighborNetMask[IPv4] = ".0/24"
	}

	isCreateMode := opts.AppendClient == 0 && !opts.UpdatePolicy

	if isCreateMode {
		create_config_files(opts.ClientNumber, opts.OutputDir, opts.IPVersion, opts.NonePeer, opts.NormalBGP, opts.PolicyPattern)
	} else {
		if _, err := os.Stat(fmt.Sprintf("%s/gobgpd.conf", opts.OutputDir)); os.IsNotExist(err) {
			log.Fatal(err)
		}
		if opts.UpdatePolicy {
			updatePolicyConfig(opts.OutputDir, opts.PolicyPattern)
		} else {
			append_config_files(opts.AppendClient, opts.OutputDir, opts.IPVersion, opts.NonePeer, opts.NormalBGP, opts.PolicyPattern)
		}
	}
}
