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

package server

import (
	"bufio"
	"fmt"
	"github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/packet"
	"net"
)

type roa struct {
	AS        uint32
	PrefixLen uint8
	MaxLen    uint8
	Prefix    net.IP
}

func (r *roa) key() string {
	return fmt.Sprintf("%s/%d", r.Prefix.String(), r.PrefixLen)
}

func (r *roa) toApiStruct() *api.ROA {
	return &api.ROA{
		As:        r.AS,
		Prefixlen: uint32(r.PrefixLen),
		Maxlen:    uint32(r.MaxLen),
		Prefix:    r.Prefix.String(),
	}
}

type roaClient struct {
	roas     map[bgp.RouteFamily]map[string]*roa
	outgoing chan *roa
}

func (c *roaClient) recieveROA() chan *roa {
	return c.outgoing
}

func (c *roaClient) handleRTRMsg(r *roa) {
	if r.Prefix.To4() != nil {
		c.roas[bgp.RF_IPv4_UC][r.key()] = r
	} else {
		c.roas[bgp.RF_IPv6_UC][r.key()] = r
	}
}

func (c *roaClient) handleGRPC(grpcReq *GrpcRequest) {
	if roas, ok := c.roas[grpcReq.RouteFamily]; ok {
		for _, r := range roas {
			result := &GrpcResponse{}
			result.Data = r.toApiStruct()
			grpcReq.ResponseCh <- result
		}
	}
	close(grpcReq.ResponseCh)
}

func newROAClient(url string) (*roaClient, error) {
	c := &roaClient{
		roas: make(map[bgp.RouteFamily]map[string]*roa),
	}
	c.roas[bgp.RF_IPv4_UC] = make(map[string]*roa)
	c.roas[bgp.RF_IPv6_UC] = make(map[string]*roa)

	if url == "" {
		return c, nil
	}

	conn, err := net.Dial("tcp", url)
	if err != nil {
		return c, err
	}

	r := bgp.NewRTRResetQuery()
	data, _ := r.Serialize()
	conn.Write(data)
	reader := bufio.NewReader(conn)
	scanner := bufio.NewScanner(reader)
	scanner.Split(bgp.SplitRTR)

	ch := make(chan *roa)
	c.outgoing = ch

	go func(ch chan *roa) {
		for scanner.Scan() {
			m, _ := bgp.ParseRTR(scanner.Bytes())
			if m != nil {
				switch msg := m.(type) {
				case *bgp.RTRIPPrefix:
					p := make([]byte, len(msg.Prefix))
					copy(p, msg.Prefix)
					ch <- &roa{
						AS:        msg.AS,
						PrefixLen: msg.PrefixLen,
						MaxLen:    msg.MaxLen,
						Prefix:    p,
					}
				}

			}
		}
	}(ch)

	return c, nil
}
