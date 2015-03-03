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
			As:       12332,
			RouterId: net.ParseIP("10.0.0.1"),
		},
		NeighborList: []config.Neighbor{
			config.Neighbor{
				PeerAs:          12333,
				NeighborAddress: net.ParseIP("192.168.177.32"),
				AuthPassword:    "apple",
			},
			config.Neighbor{
				PeerAs:          12334,
				NeighborAddress: net.ParseIP("192.168.177.33"),
				AuthPassword:    "orange",
			},
			config.Neighbor{
				PeerAs:          12335,
				NeighborAddress: net.ParseIP("192.168.177.34"),
				AuthPassword:    "grape",
			},
		},
	}

	var buffer bytes.Buffer
	encoder := toml.NewEncoder(&buffer)
	err := encoder.Encode(b)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%v\n", buffer.String())
}
