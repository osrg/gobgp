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
	IPv4 = "IPv4"
	IPv6 = "IPv6"
)

type QuaggaConfig struct {
	id          int
	config      *config.NeighborType
	gobgpConfig *config.GlobalType
	serverIP    net.IP
}

func NewQuaggaConfig(id int, gConfig *config.GlobalType, myConfig *config.NeighborType, server net.IP) *QuaggaConfig {
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
	buf.WriteString("! my ip_version IPv4\n")
	buf.WriteString("hostname bgpd\n")
	buf.WriteString("password zebra\n")
	buf.WriteString(fmt.Sprintf("router bgp %d\n", qt.config.PeerAs))
	buf.WriteString(fmt.Sprintf("bgp router-id 192.168.0.%d\n", qt.id))
	buf.WriteString(fmt.Sprintf("network %s%d%s\n", baseNeighborNetwork["IPv4"], qt.id, baseNeighborNetMask["IPv4"]))
	buf.WriteString(fmt.Sprintf("neighbor %s remote-as %d\n", qt.serverIP, qt.gobgpConfig.As))
	buf.WriteString(fmt.Sprintf("neighbor %s password %s\n", qt.serverIP, qt.config.AuthPassword))
	buf.WriteString("log file /var/log/quagga/bgpd.log\n")

	return buf
}

func (qt *QuaggaConfig) IPv6Config() *bytes.Buffer {
	buf := bytes.NewBuffer(nil)
	buf.WriteString(fmt.Sprintf("! my address %s\n", qt.config.NeighborAddress))
	buf.WriteString("! my ip_version IPv6\n")
	buf.WriteString("hostname bgpd\n")
	buf.WriteString("password zebra\n")
	buf.WriteString(fmt.Sprintf("router bgp %d\n", qt.config.PeerAs))
	buf.WriteString(fmt.Sprintf("bgp router-id 192.168.0.%d\n", qt.id))
	buf.WriteString("no bgp default ipv4-unicast\n")
	buf.WriteString(fmt.Sprintf("neighbor %s remote-as %d\n", qt.serverIP, qt.gobgpConfig.As))
	buf.WriteString(fmt.Sprintf("neighbor %s password %s\n", qt.serverIP, qt.config.AuthPassword))
	buf.WriteString("address-family ipv6\n")
	buf.WriteString(fmt.Sprintf("network %s%d%s\n", baseNeighborNetwork["IPv6"], qt.id, baseNeighborNetMask["IPv6"]))
	buf.WriteString(fmt.Sprintf("neighbor %s activate\n", qt.serverIP))
	buf.WriteString(fmt.Sprintf("neighbor %s route-map IPV6-OUT out\n", qt.serverIP))
	buf.WriteString("exit-address-family\n")
	buf.WriteString("ipv6 prefix-list pl-ipv6 seq 10 permit any\n")
	buf.WriteString("route-map IPV6-OUT permit 10\n")
	buf.WriteString("match ipv6 address prefix-list pl-ipv6\n")
	buf.WriteString(fmt.Sprintf("set ipv6 next-hop global %s\n", qt.config.NeighborAddress))
	buf.WriteString("log file /var/log/quagga/bgpd.log\n")

	return buf
}

func create_config_files(nr int, outputDir string, IPVersion string) {
	quaggaConfigList := make([]*QuaggaConfig, 0)

	gobgpConf := config.BgpType{
		Global: config.GlobalType{
			As:       65000,
			RouterId: net.ParseIP("192.168.255.1"),
		},
	}

	for i := 1; i < nr+1; i++ {
		c := config.NeighborType{
			PeerAs:          65000 + uint32(i),
			NeighborAddress: net.ParseIP(fmt.Sprintf("%s%d", baseNeighborAddress[IPVersion], i)),
			AuthPassword:    fmt.Sprintf("hoge%d", i),
		}
		gobgpConf.NeighborList = append(gobgpConf.NeighborList, c)
		q := NewQuaggaConfig(i, &gobgpConf.Global, &c, net.ParseIP(serverAddress[IPVersion]))
		quaggaConfigList = append(quaggaConfigList, q)
		os.Mkdir(fmt.Sprintf("%s/q%d", outputDir, i), 0755)
		var err error
		if IPVersion == "IPv6" {
			err = ioutil.WriteFile(fmt.Sprintf("%s/q%d/bgpd.conf", outputDir, i), q.IPv6Config().Bytes(), 0644)
		} else {
			err = ioutil.WriteFile(fmt.Sprintf("%s/q%d/bgpd.conf", outputDir, i), q.IPv4Config().Bytes(), 0644)
		}
		if err != nil {
			log.Fatal(err)
		}
	}

	var buffer bytes.Buffer
	encoder := toml.NewEncoder(&buffer)
	encoder.Encode(gobgpConf)

	err := ioutil.WriteFile(fmt.Sprintf("%s/gobgpd.conf", outputDir), buffer.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func append_config_files(ar int, outputDir string, IPVersion string) {

	gobgpConf := config.BgpType{
		Global: config.GlobalType{
			As:       65000,
			RouterId: net.ParseIP("192.168.255.1"),
		},
	}
	c := config.NeighborType{
		PeerAs:          65000 + uint32(ar),
		NeighborAddress: net.ParseIP(fmt.Sprintf("%s%d", baseNeighborAddress[IPVersion], ar)),
		AuthPassword:    fmt.Sprintf("hoge%d", ar),
	}
	q := NewQuaggaConfig(ar, &gobgpConf.Global, &c, net.ParseIP(serverAddress[IPVersion]))
	os.Mkdir(fmt.Sprintf("%s/q%d", outputDir, ar), 0755)
	var err error
	if IPVersion == "IPv6" {
		err = ioutil.WriteFile(fmt.Sprintf("%s/q%d/bgpd.conf", outputDir, ar), q.IPv6Config().Bytes(), 0644)
	} else {
		err = ioutil.WriteFile(fmt.Sprintf("%s/q%d/bgpd.conf", outputDir, ar), q.IPv4Config().Bytes(), 0644)
	}
	if err != nil {
		log.Fatal(err)
	}
	newConf := config.BgpType{}
	_, d_err := toml.DecodeFile(fmt.Sprintf("%s/gobgpd.conf", outputDir), &newConf)
	if d_err != nil {
		log.Fatal(err)
	}
	newConf.NeighborList = append(newConf.NeighborList, c)
	var buffer bytes.Buffer
	encoder := toml.NewEncoder(&buffer)
	encoder.Encode(newConf)
	e_err := ioutil.WriteFile(fmt.Sprintf("%s/gobgpd.conf", outputDir), buffer.Bytes(), 0644)
	if e_err != nil {
		log.Fatal(err)
	}
}

func main() {
	var opts struct {
		ClientNumber  int    `short:"n" long:"client-number" description:"specfying the number of clients" default:"8"`
		OutputDir     string `short:"c" long:"output" description:"specifing the output directory"`
		AppendClient  int    `short:"a" long:"append" description:"specifing the add client number" default:"0"`
		IPVersion     string `short:"v" long:"ip-version" description:"specifing the use ip version" default:"IPv4"`
		NetIdentifier int    `short:"i" long:"net-identifer" description:"specifing the use network identifier" default:"0"`
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

	if opts.AppendClient == 0 {
		create_config_files(opts.ClientNumber, opts.OutputDir, opts.IPVersion)
	} else {
		if _, err := os.Stat(fmt.Sprintf("%s/gobgpd.conf", opts.OutputDir)); os.IsNotExist(err) {
			log.Fatal(err)
		}
		append_config_files(opts.AppendClient, opts.OutputDir, opts.IPVersion)
	}
}
