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
	"os"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/jessevdk/go-flags"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/server"
)

func newServer() *server.BgpServer {
	s := server.NewBgpServer()
	go s.Serve()
	return s
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

	num := opts.NumPeer
	serverMap := make(map[string]*server.BgpServer)
	estabCh := make(chan struct{}, 8)
	start := time.Now()

	for i := 0; i < num; i++ {
		s := newServer()
		localAddr := fmt.Sprintf("10.10.%d.%d", (i+2)/255, (i+2)%255)
		serverMap[localAddr] = s
		req := server.NewGrpcRequest(server.REQ_MOD_GLOBAL_CONFIG, "", bgp.RouteFamily(0), &api.ModGlobalConfigArguments{
			Operation: api.Operation_ADD,
			Global: &api.Global{
				As:       uint32(1001 + i),
				RouterId: localAddr,
				Deaf:     true,
			},
		})
		s.GrpcReqCh <- req
		res := <-req.ResponseCh
		if err := res.Err(); err != nil {
			log.Fatalf("%s", err)
		}

		req = server.NewGrpcRequest(server.REQ_MONITOR_NEIGHBOR_PEER_STATE, "", bgp.RouteFamily(0), nil)
		s.GrpcReqCh <- req
		go func(r *server.GrpcRequest) {
			for {
				select {
				case msg := <-r.ResponseCh:
					if msg.Data.(*api.Peer).Info.BgpState == api.PeerState_ESTABLISHED {
						estabCh <- struct{}{}
						return
					}
				}
			}
		}(req)

		req = server.NewGrpcRequest(server.REQ_MOD_NEIGHBOR, "", bgp.RouteFamily(0), &api.ModNeighborArguments{
			Operation: api.Operation_ADD,
			Peer: &api.Peer{
				Conf: &api.PeerConf{
					NeighborAddress: "10.10.0.1",
					PeerAs:          1000,
				},
				Transport: &api.Transport{
					LocalAddress: localAddr,
				},
				Timers: &api.Timers{
					Config: &api.TimersConfig{
						ConnectRetry:      1,
						HoldTime:          config.DEFAULT_HOLDTIME,
						KeepaliveInterval: config.DEFAULT_HOLDTIME / 3,
					},
				},
			},
		})
		s.GrpcReqCh <- req
		res = <-req.ResponseCh
		if err := res.Err(); err != nil {
			log.Fatalf("%s", err)
		}
	}
	established := 0
	ticker := time.NewTicker(time.Second * 5)
	for {
		select {
		case <-estabCh:
			established++
			if num == established {
				goto END
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
}
