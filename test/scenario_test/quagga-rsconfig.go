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

func (qt *QuaggaConfig) Config() *bytes.Buffer {
	buf := bytes.NewBuffer(nil)

	buf.WriteString("hostname bgpd\n")
	buf.WriteString("password zebra\n")
	buf.WriteString(fmt.Sprintf("router bgp %d\n", qt.config.PeerAs))
	buf.WriteString(fmt.Sprintf("bgp router-id 192.168.0.%d\n", qt.id))
	buf.WriteString(fmt.Sprintf("network 192.168.%d.0/24\n", qt.id))
	buf.WriteString(fmt.Sprintf("neighbor %s remote-as %d\n", qt.serverIP, qt.gobgpConfig.As))
	buf.WriteString(fmt.Sprintf("neighbor %s password %s\n", qt.serverIP, qt.config.AuthPassword))
	buf.WriteString("log file /var/log/quagga/bgpd.log")
	return buf
}

func create_config_files(nr int, outputDir string) {
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
			NeighborAddress: net.ParseIP(fmt.Sprintf("10.0.0.%d", i)),
			AuthPassword:    fmt.Sprintf("hoge%d", i),
		}
		gobgpConf.NeighborList = append(gobgpConf.NeighborList, c)
		q := NewQuaggaConfig(i, &gobgpConf.Global, &c, net.ParseIP("10.0.255.1"))
		quaggaConfigList = append(quaggaConfigList, q)
		os.Mkdir(fmt.Sprintf("%s/q%d", outputDir, i), 0755)
		err := ioutil.WriteFile(fmt.Sprintf("%s/q%d/bgpd.conf", outputDir, i), q.Config().Bytes(), 0644)
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

func append_config_files(ar int, outputDir string) {
	gobgpConf := config.BgpType{
		Global: config.GlobalType{
			As:       65000,
			RouterId: net.ParseIP("192.168.255.1"),
		},
	}
	c := config.NeighborType{
		PeerAs: 65000 + uint32(ar),

		NeighborAddress: net.ParseIP(fmt.Sprintf("10.0.0.%d", ar)),
		AuthPassword:    fmt.Sprintf("hoge%d", ar),
	}
	q := NewQuaggaConfig(ar, &gobgpConf.Global, &c, net.ParseIP("10.0.255.1"))
	os.Mkdir(fmt.Sprintf("%s/q%d", outputDir, ar), 0755)
	err := ioutil.WriteFile(fmt.Sprintf("%s/q%d/bgpd.conf", outputDir, ar), q.Config().Bytes(), 0644)
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
		ClientNumber int    `short:"n" long:"client-number" description:"specfying the number of clients" default:"8"`
		OutputDir    string `short:"c" long:"output" description:"specifing the output directory"`
		AppendClient int    `short:"a" long:"append" description:"specifing the add client number" default:"0"`
	}
	parser := flags.NewParser(&opts, flags.Default)

	_, err := parser.Parse()
	if err != nil {
		os.Exit(1)
	}

	if opts.OutputDir == "" {
		opts.OutputDir, _ = filepath.Abs(".")
	} else {
		if _, err := os.Stat(opts.OutputDir); os.IsNotExist(err) {
			os.Mkdir(opts.OutputDir, 0755)
		}
	}

	if opts.AppendClient == 0 {
		create_config_files(opts.ClientNumber, opts.OutputDir)
	} else {
		if _, err := os.Stat(fmt.Sprintf("%s/gobgpd.conf", opts.OutputDir)); os.IsNotExist(err) {
			log.Fatal(err)
		}
		append_config_files(opts.AppendClient, opts.OutputDir)
	}
}
