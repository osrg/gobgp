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
	"time"

	log "github.com/Sirupsen/logrus"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/gobgp/cmd"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/server"
)

func T2(opt Option, m map[string]*server.BgpServer) {

	log.Info("start T2")

	start := time.Now()
	i := 1
	for _, s := range m {
		if i%255 == 224 {
			i += 16 // 239 - 224 + 1
		}
		if opt.Unique {
			i = 100
		}
		paths := make([]*api.Path, 0, opt.NumPrefix)
		for j := 100; j < opt.NumPrefix+100; j++ {
			path, _ := cmd.ParsePath(bgp.RF_IPv4_UC, []string{fmt.Sprintf("%d.%d.%d.%d/32", i%255, i/255, j%255, j/255)})
			paths = append(paths, path)
		}

		arg := &api.ModPathArguments{
			Resource: api.Resource_GLOBAL,
			Paths:    paths,
		}

		req := server.NewGrpcRequest(server.REQ_MOD_PATH, arg.Name, bgp.RouteFamily(0), arg)
		s.GrpcReqCh <- req
		res := <-req.ResponseCh
		if err := res.Err(); err != nil {
			log.Fatalf(err.Error())
		}
		i++
	}

	ticker := time.NewTicker(time.Second * 1)
	for {
		select {
		case <-ticker.C:
			i := 0
			j := 0
			for _, s := range m {
				req := server.NewGrpcRequest(server.REQ_NEIGHBORS, "", bgp.RouteFamily(0), nil)
				s.GrpcReqCh <- req
				for peer := range req.ResponseCh {
					i += int(peer.Data.(*api.Peer).Info.Received)
					j += int(peer.Data.(*api.Peer).Info.Accepted)
				}
			}
			now := time.Now()
			log.Infof("[%s] total received: %d, accepted: %d ", now.Sub(start), i, j)
		}
	}
}
