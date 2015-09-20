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
	log "github.com/Sirupsen/logrus"
	"github.com/armon/go-radix"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/table"
	"net"
	"strconv"
	"time"
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
	roas     map[bgp.RouteFamily]*radix.Tree
	outgoing chan []byte
	config   config.RpkiServers
}

func (c *roaClient) recieveROA() chan []byte {
	return c.outgoing
}

func roa2key(r *roa) string {
	var buffer bytes.Buffer
	for i := 0; i < len(r.Prefix) && i < int(r.PrefixLen); i++ {
		buffer.WriteString(fmt.Sprintf("%08b", r.Prefix[i]))
	}
	return buffer.String()[:r.PrefixLen]
}

func (c *roaClient) handleRTRMsg(buf []byte) {
	received := &c.config.RpkiServerList[0].RpkiServerState.RpkiMessages.RpkiReceived

	m, _ := bgp.ParseRTR(buf)
	if m != nil {
		switch msg := m.(type) {
		case *bgp.RTRSerialNotify:
			received.SerialNotify++
		case *bgp.RTRSerialQuery:
		case *bgp.RTRResetQuery:
		case *bgp.RTRCacheResponse:
			received.CacheResponse++
		case *bgp.RTRIPPrefix:
			p := make([]byte, len(msg.Prefix))
			copy(p, msg.Prefix)
			r := &roa{
				AS:        msg.AS,
				PrefixLen: msg.PrefixLen,
				MaxLen:    msg.MaxLen,
				Prefix:    p,
			}
			if r.Prefix.To4() != nil {
				received.Ipv4Prefix++
				c.roas[bgp.RF_IPv4_UC].Insert(roa2key(r), r)
			} else {
				received.Ipv6Prefix++
				c.roas[bgp.RF_IPv6_UC].Insert(roa2key(r), r)
			}
		case *bgp.RTREndOfData:
			received.EndOfData++
		case *bgp.RTRCacheReset:
			received.CacheReset++
		case *bgp.RTRErrorReport:
		}
	} else {
		received.Error++
	}
}

func (c *roaClient) handleGRPC(grpcReq *GrpcRequest) {
	switch grpcReq.RequestType {
	case REQ_RPKI:
		results := make([]*GrpcResponse, 0)
		for _, s := range c.config.RpkiServerList {
			state := &s.RpkiServerState
			rpki := &api.RPKI{
				Conf: &api.RPKIConf{
					Address: s.RpkiServerConfig.Address.String(),
				},
				State: &api.RPKIState{
					Uptime:       state.Uptime,
					ReceivedIpv4: int32(c.roas[bgp.RF_IPv4_UC].Len()),
					ReceivedIpv6: int32(c.roas[bgp.RF_IPv6_UC].Len()),
				},
			}
			result := &GrpcResponse{}
			result.Data = rpki
			results = append(results, result)
		}
		go sendMultipleResponses(grpcReq, results)

	case REQ_ROA:
		if len(c.config.RpkiServerList) == 0 || c.config.RpkiServerList[0].RpkiServerConfig.Address.String() != grpcReq.Name {
			result := &GrpcResponse{}
			result.ResponseErr = fmt.Errorf("RPKI server that has %v doesn't exist.", grpcReq.Name)

			grpcReq.ResponseCh <- result
			break
		}

		results := make([]*GrpcResponse, 0)
		if tree, ok := c.roas[grpcReq.RouteFamily]; ok {
			tree.Walk(func(s string, v interface{}) bool {
				r, _ := v.(*roa)
				result := &GrpcResponse{}
				result.Data = r.toApiStruct()
				results = append(results, result)
				return false
			})
		}
		go sendMultipleResponses(grpcReq, results)
	}
}

func (c *roaClient) validate(pathList []*table.Path) {
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

func newROAClient(conf config.RpkiServers) (*roaClient, error) {
	var url string

	c := &roaClient{
		roas:   make(map[bgp.RouteFamily]*radix.Tree),
		config: conf,
	}
	c.roas[bgp.RF_IPv4_UC] = radix.New()
	c.roas[bgp.RF_IPv6_UC] = radix.New()

	if len(conf.RpkiServerList) == 0 {
		return c, nil
	} else {
		if len(conf.RpkiServerList) > 1 {
			log.Warn("currently only one RPKI server is supposed")
		}
		c := conf.RpkiServerList[0].RpkiServerConfig
		url = net.JoinHostPort(c.Address.String(), strconv.Itoa(int(c.Port)))
	}

	conn, err := net.Dial("tcp", url)
	if err != nil {
		return c, err
	}

	state := &conf.RpkiServerList[0].RpkiServerState
	state.Uptime = time.Now().Unix()
	r := bgp.NewRTRResetQuery()
	data, _ := r.Serialize()
	conn.Write(data)
	state.RpkiMessages.RpkiSent.ResetQuery++
	reader := bufio.NewReader(conn)
	scanner := bufio.NewScanner(reader)
	scanner.Split(bgp.SplitRTR)

	ch := make(chan []byte)
	c.outgoing = ch

	go func(ch chan []byte) {
		for scanner.Scan() {
			ch <- scanner.Bytes()
		}
	}(ch)

	return c, nil
}
