// Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"net"
	"os"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/jessevdk/go-flags"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/server"
	"github.com/osrg/gobgp/table"
)

func newPeer(g config.Global, p config.Neighbor, incoming chan *server.FsmMsg, id uint32) *server.Peer {
	tbl := table.NewTableManager([]bgp.RouteFamily{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC}, 0, 0)
	peer := server.NewPeer(g, p, tbl, id, table.NewRoutingPolicy())
	server.NewFSMHandler(peer.Fsm(), incoming, peer.Outgoing())
	return peer
}

func main() {
	var opts struct {
		NumPeer int `short:"n" long:"num-peer" description:"num of peers"`
	}
	args, err := flags.Parse(&opts)
	if err != nil {
		os.Exit(1)
	}
	if len(args) != 1 || args[0] != "T1" {
		log.Errorf("Usage: performance_test -n <num-peer> T1")
		os.Exit(1)
	}

	peerMap := make(map[string]*server.Peer)
	incoming := make(chan *server.FsmMsg, 1024)
	num := opts.NumPeer
	start := time.Now()
	for i := 0; i < num; i++ {
		localAddr := fmt.Sprintf("10.10.%d.%d", (i+2)/255, (i+2)%255)
		g := config.Global{
			GlobalConfig: config.GlobalConfig{
				As:       uint32(1001 + i),
				RouterId: net.ParseIP(localAddr),
			},
		}
		p := config.Neighbor{
			NeighborConfig: config.NeighborConfig{
				PeerAs:          1000,
				NeighborAddress: net.ParseIP("10.10.0.1"),
			},
			Transport: config.Transport{
				TransportConfig: config.TransportConfig{
					LocalAddress: net.ParseIP(localAddr),
				},
			},
		}
		peer := newPeer(g, p, incoming, uint32(i+1))
		peerMap[p.Transport.TransportConfig.LocalAddress.String()] = peer
	}
	established := 0
	ticker := time.NewTicker(time.Second * 5)
	for {
		select {
		case msg := <-incoming:
			peer := peerMap[msg.MsgDst]
			switch msg.MsgType {
			case server.FSM_MSG_STATE_CHANGE:
				nextState := msg.MsgData.(bgp.FSMState)
				fsm := peer.Fsm()
				fsm.StateChange(nextState)
				server.NewFSMHandler(fsm, incoming, peer.Outgoing())
				if nextState == bgp.BGP_FSM_ESTABLISHED {
					established++
				}
				if num == established {
					goto END
				}
			}
		case <-ticker.C:
			now := time.Now()
			log.Infof("[%s] # of established: %d", now.Sub(start), established)
		}
	}
END:
	end := time.Now()
	log.Infof("all established. elapsed time: %s", end.Sub(start))
	if args[0] == "T1" {
		return
	}
	for {
		select {
		case msg := <-incoming:
			fmt.Println(msg)
		}
	}
}
