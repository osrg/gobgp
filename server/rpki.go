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
	"bytes"
	"fmt"
	"github.com/armon/go-radix"
	"github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/table"
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
	url      string
	roas     map[bgp.RouteFamily]*radix.Tree
	outgoing chan *roa
}

func (c *roaClient) recieveROA() chan *roa {
	return c.outgoing
}

func roa2key(r *roa) string {
	var buffer bytes.Buffer
	for i := 0; i < len(r.Prefix) && i < int(r.PrefixLen); i++ {
		buffer.WriteString(fmt.Sprintf("%08b", r.Prefix[i]))
	}
	return buffer.String()[:r.PrefixLen]
}

func (c *roaClient) handleRTRMsg(r *roa) {
	if r.Prefix.To4() != nil {
		c.roas[bgp.RF_IPv4_UC].Insert(roa2key(r), r)
	} else {
		c.roas[bgp.RF_IPv6_UC].Insert(roa2key(r), r)
	}
}

func (c *roaClient) handleGRPC(grpcReq *GrpcRequest) {
	if tree, ok := c.roas[grpcReq.RouteFamily]; ok {
		tree.Walk(func(s string, v interface{}) bool {
			r, _ := v.(*roa)
			result := &GrpcResponse{}
			result.Data = r.toApiStruct()
			grpcReq.ResponseCh <- result
			return false
		})
	}
	close(grpcReq.ResponseCh)
}

func (c *roaClient) validate(pathList []*table.Path) {
	if c.url == "" {
		return
	}

	for _, path := range pathList {
		if tree, ok := c.roas[path.GetRouteFamily()]; ok {
			_, n, _ := net.ParseCIDR(path.GetNlri().String())
			ones, _ := n.Mask.Size()
			var buffer bytes.Buffer
			for i := 0; i < len(n.IP) && i < ones; i++ {
				buffer.WriteString(fmt.Sprintf("%08b", n.IP[i]))
			}
			_, r, _ := tree.LongestPrefix(buffer.String()[:ones])
			if r == nil {
				path.Validation = config.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND
			} else {
				roa, _ := r.(*roa)
				if roa.AS == path.GetSourceAs() {
					path.Validation = config.RPKI_VALIDATION_RESULT_TYPE_VALID
				} else {
					path.Validation = config.RPKI_VALIDATION_RESULT_TYPE_INVALID
				}
			}
		}
	}
}

func newROAClient(url string) (*roaClient, error) {
	c := &roaClient{
		url:  url,
		roas: make(map[bgp.RouteFamily]*radix.Tree),
	}
	c.roas[bgp.RF_IPv4_UC] = radix.New()
	c.roas[bgp.RF_IPv6_UC] = radix.New()

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
