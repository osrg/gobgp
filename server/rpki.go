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

type roaBucket struct {
	Prefix    net.IP
	PrefixLen uint8
	entries   []*roa
}

type roa struct {
	MaxLen uint8
	AS     []uint32
}

type roaClient struct {
	AS       uint32
	roas     map[bgp.RouteFamily]*radix.Tree
	outgoing chan []byte
	config   config.RpkiServers
}

func (c *roaClient) recieveROA() chan []byte {
	return c.outgoing
}

func addROA(tree *radix.Tree, as uint32, prefix []byte, prefixLen, maxLen uint8) {
	key := table.IpToRadixkey(prefix, prefixLen)
	b, _ := tree.Get(key)
	if b == nil {
		p := make([]byte, len(prefix))
		copy(p, prefix)

		r := &roa{
			AS:     []uint32{as},
			MaxLen: maxLen,
		}

		b := &roaBucket{
			PrefixLen: prefixLen,
			Prefix:    p,
			entries:   []*roa{r},
		}

		tree.Insert(key, b)
	} else {
		bucket := b.(*roaBucket)
		found := false
		for _, r := range bucket.entries {
			if r.MaxLen == maxLen {
				found = true
				r.AS = append(r.AS, as)
			}
		}
		if found == false {
			r := &roa{
				MaxLen: maxLen,
				AS:     []uint32{as},
			}
			bucket.entries = append(bucket.entries, r)
		}
	}
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
			var tree *radix.Tree
			if msg.Type == bgp.RTR_IPV4_PREFIX {
				received.Ipv4Prefix++
				tree = c.roas[bgp.RF_IPv4_UC]
			} else {
				received.Ipv6Prefix++
				tree = c.roas[bgp.RF_IPv6_UC]
			}
			addROA(tree, msg.AS, msg.Prefix, msg.PrefixLen, msg.MaxLen)
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
				b, _ := v.(*roaBucket)
				for _, r := range b.entries {
					for _, as := range r.AS {
						result := &GrpcResponse{}
						result.Data = &api.ROA{
							As:        as,
							Maxlen:    uint32(r.MaxLen),
							Prefixlen: uint32(b.PrefixLen),
							Prefix:    b.Prefix.String(),
						}
						results = append(results, result)
					}
				}
				return false
			})
		}
		go sendMultipleResponses(grpcReq, results)
	}
}

func validatePath(ownAs uint32, tree *radix.Tree, cidr string, asPath *bgp.PathAttributeAsPath) config.RpkiValidationResultType {
	var as uint32
	if asPath == nil || len(asPath.Value) == 0 {
		return config.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND
	}
	asParam := asPath.Value[len(asPath.Value)-1].(*bgp.As4PathParam)
	switch asParam.Type {
	case bgp.BGP_ASPATH_ATTR_TYPE_SEQ:
		if len(asParam.AS) == 0 {
			return config.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND
		}
		as = asParam.AS[len(asParam.AS)-1]
	case bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET, bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ:
		as = ownAs
	default:
		return config.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND
	}
	_, n, _ := net.ParseCIDR(cidr)
	ones, _ := n.Mask.Size()
	prefixLen := uint8(ones)
	_, b, _ := tree.LongestPrefix(table.IpToRadixkey(n.IP, prefixLen))
	if b == nil {
		return config.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND
	} else {
		result := config.RPKI_VALIDATION_RESULT_TYPE_INVALID
		bucket, _ := b.(*roaBucket)
		for _, r := range bucket.entries {
			if prefixLen > r.MaxLen {
				continue
			}

			y := func(x uint32, asList []uint32) bool {
				for _, as := range asList {
					if x == as {
						return true
					}
				}
				return false
			}(as, r.AS)

			if y {
				result = config.RPKI_VALIDATION_RESULT_TYPE_VALID
				break
			}
		}
		return result
	}
}

func (c *roaClient) validate(pathList []*table.Path) {
	if c.roas[bgp.RF_IPv4_UC].Len() == 0 && c.roas[bgp.RF_IPv6_UC].Len() == 0 {
		return
	}
	for _, path := range pathList {
		if tree, ok := c.roas[path.GetRouteFamily()]; ok {
			path.Validation = validatePath(c.AS, tree, path.GetNlri().String(), path.GetAsPath())
		}
	}
}

func newROAClient(as uint32, conf config.RpkiServers) (*roaClient, error) {
	var url string

	c := &roaClient{
		AS:     as,
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
