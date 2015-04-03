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

	var binding *PolicyBinding
	if policyPattern != "" {
		binding = bindPolicy(policyPattern)
	}

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

		if binding != nil {
            ip := net.ParseIP(binding.NeighborAddress)
			if ip.String() == c.NeighborAddress.String() {
				ap := config.ApplyPolicy{
					ImportPolicies: binding.ImportPolicyNames,
					ExportPolicies: binding.ExportPolicyNames,
				}
				c.ApplyPolicy = ap
			}

		}

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
	if binding != nil {
		encoder.Encode(binding.Policy)
	}

	err := ioutil.WriteFile(fmt.Sprintf("%s/gobgpd.conf", outputDir), buffer.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func append_config_files(ar int, outputDir string, IPVersion string, nonePeer bool, normalBGP bool) {

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
	if !nonePeer {
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

	ns0 := config.NeighborSet{
		NeighborSetName: "ns0",
		NeighborInfoList: []config.NeighborInfo{
			config.NeighborInfo{
				Address: net.ParseIP("10.0.0.2"),
			}},
	}

	ns1 := config.NeighborSet{
		NeighborSetName: "ns1",
		NeighborInfoList: []config.NeighborInfo{
			config.NeighborInfo{
				Address: net.ParseIP("2001::0:192:168:0:2"),
			}},
	}

	st0 := config.Statement{
		Name: "st0",
		Conditions: config.Conditions{
			MatchPrefixSet:   "ps0",
			MatchNeighborSet: "ns0",
			MatchSetOptions:  config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: false,
			RejectRoute: true,
		},
	}

	st1 := config.Statement{
		Name: "st1",
		Conditions: config.Conditions{
			MatchPrefixSet:   "ps1",
			MatchNeighborSet: "ns0",
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
			MatchNeighborSet: "ns1",
			MatchSetOptions:  config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: false,
			RejectRoute: true,
		},
	}

	st4 := config.Statement{
		Name: "st4",
		Conditions: config.Conditions{
			MatchPrefixSet:   "ps4",
			MatchNeighborSet: "ns1",
			MatchSetOptions:  config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: false,
			RejectRoute: true,
		},
	}

	pd0 := config.PolicyDefinition{
		Name:          "policy0",
		StatementList: []config.Statement{st0},
	}

	pd1 := config.PolicyDefinition{
		Name:          "policy1",
		StatementList: []config.Statement{st1},
	}

	pd2 := config.PolicyDefinition{
		Name:          "policy2",
		StatementList: []config.Statement{st3},
	}

	pd3 := config.PolicyDefinition{
		Name:          "policy3",
		StatementList: []config.Statement{st4},
	}

	ds := config.DefinedSets{
		PrefixSetList:   []config.PrefixSet{ps0, ps1, ps2, ps3, ps4, ps5},
		NeighborSetList: []config.NeighborSet{ns0, ns1},
	}

	p := &config.RoutingPolicy{
		DefinedSets:          ds,
		PolicyDefinitionList: []config.PolicyDefinition{pd0, pd1, pd2, pd3},
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
			MatchNeighborSet: "ns0",
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
			MatchNeighborSet: "ns1",
			MatchSetOptions:  config.MATCH_SET_OPTIONS_TYPE_ALL,
		},
		Actions: config.Actions{
			AcceptRoute: false,
			RejectRoute: true,
		},
	}

	if pattern == "p3" || pattern == "p4" {
		policyConf.PolicyDefinitionList[1].StatementList = []config.Statement{st2}
	}

	if pattern == "p7" || pattern == "p8" {
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

func bindPolicy(pattern string) *PolicyBinding {

	var pb *PolicyBinding = &PolicyBinding{Policy: createPolicyConfig()}

	switch pattern {
	case "p1":
		pb.NeighborAddress = "10.0.0.3"
		pb.ImportPolicyNames = []string{"policy0"}
		pb.ExportPolicyNames = nil

	case "p2":
		pb.NeighborAddress = "10.0.0.3"
		pb.ImportPolicyNames = nil
		pb.ExportPolicyNames = []string{"policy0"}

	case "p3":
		pb.NeighborAddress = "10.0.0.3"
		pb.ImportPolicyNames = []string{"policy1"}
		pb.ExportPolicyNames = nil

	case "p4":
		pb.NeighborAddress = "10.0.0.3"
		pb.ImportPolicyNames = nil
		pb.ExportPolicyNames = []string{"policy1"}

	case "p5":
		pb.NeighborAddress = "2001::0:192:168:0:3"
		pb.ImportPolicyNames = []string{"policy2"}
		pb.ExportPolicyNames = nil

	case "p6":
		pb.NeighborAddress = "2001::0:192:168:0:3"
		pb.ImportPolicyNames = nil
		pb.ExportPolicyNames = []string{"policy2"}

	case "p7":
		pb.NeighborAddress = "2001::0:192:168:0:3"
		pb.ImportPolicyNames = []string{"policy3"}
		pb.ExportPolicyNames = nil

	case "p8":
		pb.NeighborAddress = "2001::0:192:168:0:3"
		pb.ImportPolicyNames = nil
		pb.ExportPolicyNames = []string{"policy3"}

	default:
		pb = nil
	}

	return pb

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
			append_config_files(opts.AppendClient, opts.OutputDir, opts.IPVersion, opts.NonePeer, opts.NormalBGP)
		}
	}
}
