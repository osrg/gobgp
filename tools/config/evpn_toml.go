package main

import (
	"bytes"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/osrg/gobgp/config"
	"net"
	"os"
	"io/ioutil"
)

func main() {
	b := config.Bgp{
		Global: config.Global{
			As:       64512,
			RouterId: net.ParseIP("192.168.99.17"),
		},
		NeighborList: []config.Neighbor{
			config.Neighbor{
				PeerAs:          64512,
				NeighborAddress: net.ParseIP("192.168.99.23"),
				// AuthPassword:    "apple",
				AfiSafiList:     []config.AfiSafi{
					// config.AfiSafi{
					// 	AfiSafiName: "ipv4-unicast",
					// },
					config.AfiSafi{
						AfiSafiName: "l2vpn-evpn",
						L2vpnEvpn: config.L2vpnEvpn{
							Enabled: true,
							ApplyPolicy: config.ApplyPolicy{
								ImportPolicies: []string{"64512:79"},
								ExportPolicies: []string{"64512:79"},
							},
						},
					},
				},
				Timers:			 config.Timers{
					ConnectRetry:		100,
					HoldTime:			180,
					KeepaliveInterval:	10,
				},
			},
			config.Neighbor{
				PeerAs:          64512,
				NeighborAddress: net.ParseIP("12.11.11.1"),
				AfiSafiList:     []config.AfiSafi{
					config.AfiSafi{
						AfiSafiName: "ipv4-unicast",
					},
					config.AfiSafi{
						AfiSafiName: "l2vpn-evpn",
						L2vpnEvpn: config.L2vpnEvpn{
							Enabled: true,
							ApplyPolicy: config.ApplyPolicy{
								ImportPolicies: []string{"64512:79"},
								ExportPolicies: []string{"64512:79"},
							},
						},
					},
				},
				Timers:			 config.Timers{
					ConnectRetry:		100,
					HoldTime:			180,
					KeepaliveInterval:	10,
				},
			},
			// config.Neighbor{
			// 	PeerAs:          12335,
			// 	NeighborAddress: net.ParseIP("192.168.177.34"),
			// 	AuthPassword:    "grape",
			// },
		},
	}

	var buffer bytes.Buffer
	encoder := toml.NewEncoder(&buffer)
	err := encoder.Encode(b)
	if err != nil {
		panic(err)
	}

	content := []byte(buffer.String())
	ioutil.WriteFile("gobgpd.conf", content, os.ModePerm)

	fmt.Printf("%v\n", buffer.String())
}
