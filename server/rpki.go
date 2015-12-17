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
	"gopkg.in/tomb.v2"
	"net"
	"strconv"
	"strings"
	"time"
)

type roaBucket struct {
	Prefix    net.IP
	PrefixLen uint8
	entries   []*roa
}

type roa struct {
	Src    string
	MaxLen uint8
	AS     []uint32
}

const (
	CONNECTED uint8 = iota
	DISCONNECTED
	RTR
)

type roaClientEvent struct {
	eventType uint8
	src       string
	conn      *net.TCPConn
	data      []byte
}

type roaManager struct {
	AS        uint32
	roas      map[bgp.RouteFamily]*radix.Tree
	config    config.RpkiServers
	eventCh   chan *roaClientEvent
	clientMap map[string]*roaClient
}

func (c *roaManager) recieveROA() chan *roaClientEvent {
	return c.eventCh
}

func (m *roaManager) handleROAEvent(ev *roaClientEvent) {
	client, y := m.clientMap[ev.src]
	if !y {
		if ev.eventType == CONNECTED {
			ev.conn.Close()
		}
		log.Error("can't find %s roa server configuration", ev.src)
		return
	}
	switch ev.eventType {
	case DISCONNECTED:
		log.Info("roa server is disconnected, ", ev.src)
		client.state.Downtime = time.Now().Unix()
		// clear state
		client.state.RpkiMessages = config.RpkiMessages{}
		client.conn.Close()
		client.conn = nil
		client.t = tomb.Tomb{}
		client.t.Go(client.tryConnect)
	case CONNECTED:
		log.Info("roa server is connected, ", ev.src)
		client.conn = ev.conn
		client.state.Uptime = time.Now().Unix()
		client.t = tomb.Tomb{}
		client.t.Go(client.established)
	case RTR:
		m.handleRTRMsg(ev.src, client.state, ev.data)
	}
}

func addROA(host string, tree *radix.Tree, as uint32, prefix []byte, prefixLen, maxLen uint8) {
	key := table.IpToRadixkey(prefix, prefixLen)
	b, _ := tree.Get(key)
	if b == nil {
		p := make([]byte, len(prefix))
		copy(p, prefix)

		r := &roa{
			AS:     []uint32{as},
			MaxLen: maxLen,
			Src:    host,
		}

		b := &roaBucket{
			PrefixLen: prefixLen,
			Prefix:    p,
			entries:   []*roa{r},
		}

		tree.Insert(key, b)
	} else {
		bucket := b.(*roaBucket)
		for _, r := range bucket.entries {
			if r.MaxLen == maxLen && r.Src == host {
				// we already have?
				for _, a := range r.AS {
					if a == as {
						return
					}
				}
				r.AS = append(r.AS, as)
				return
			}
		}
		r := &roa{
			MaxLen: maxLen,
			AS:     []uint32{as},
			Src:    host,
		}
		bucket.entries = append(bucket.entries, r)
	}
}

func (c *roaManager) handleRTRMsg(host string, state *config.RpkiServerState, buf []byte) {
	received := &state.RpkiMessages.RpkiReceived

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
			addROA(host, tree, msg.AS, msg.Prefix, msg.PrefixLen, msg.MaxLen)
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

func splitHostPort(network string) (host string, port int) {
	if strings.HasPrefix(network, "[") {
		l := strings.Split(network, "]:")
		port, _ := strconv.Atoi(l[1])
		return l[0][1:], port
	} else {
		l := strings.Split(network, ":")
		port, _ := strconv.Atoi(l[1])
		return l[0], port
	}
}

func (c *roaManager) handleGRPC(grpcReq *GrpcRequest) {
	switch grpcReq.RequestType {
	case REQ_RPKI:
		results := make([]*GrpcResponse, 0)
		for _, client := range c.clientMap {
			state := client.state
			received := &state.RpkiMessages.RpkiReceived
			rpki := &api.RPKI{
				Conf: &api.RPKIConf{
					Address: client.addr,
				},
				State: &api.RPKIState{
					Uptime:       state.Uptime,
					ReceivedIpv4: received.Ipv4Prefix,
					ReceivedIpv6: received.Ipv6Prefix,
				},
			}
			result := &GrpcResponse{}
			result.Data = rpki
			results = append(results, result)
		}
		go sendMultipleResponses(grpcReq, results)

	case REQ_ROA:
		if len(c.clientMap) == 0 {
			result := &GrpcResponse{}
			result.ResponseErr = fmt.Errorf("RPKI server isn't configured.")
			grpcReq.ResponseCh <- result
			break
		}
		results := make([]*GrpcResponse, 0)
		var rfList []bgp.RouteFamily
		switch grpcReq.RouteFamily {
		case bgp.RF_IPv4_UC:
			rfList = []bgp.RouteFamily{bgp.RF_IPv4_UC}
		case bgp.RF_IPv6_UC:
			rfList = []bgp.RouteFamily{bgp.RF_IPv6_UC}
		default:
			rfList = []bgp.RouteFamily{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC}
		}
		for _, rf := range rfList {
			if tree, ok := c.roas[rf]; ok {
				tree.Walk(func(s string, v interface{}) bool {
					b, _ := v.(*roaBucket)
					for _, r := range b.entries {
						for _, as := range r.AS {
							result := &GrpcResponse{}
							host, port := splitHostPort(r.Src)
							result.Data = &api.ROA{
								As:        as,
								Maxlen:    uint32(r.MaxLen),
								Prefixlen: uint32(b.PrefixLen),
								Prefix:    b.Prefix.String(),
								Conf: &api.RPKIConf{
									Address:    host,
									RemotePort: uint32(port),
								},
							}
							results = append(results, result)
						}
					}
					return false
				})
			}
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

func (c *roaManager) validate(pathList []*table.Path) {
	if c.roas[bgp.RF_IPv4_UC].Len() == 0 && c.roas[bgp.RF_IPv6_UC].Len() == 0 {
		return
	}
	for _, path := range pathList {
		if tree, ok := c.roas[path.GetRouteFamily()]; ok {
			path.Validation = validatePath(c.AS, tree, path.GetNlri().String(), path.GetAsPath())
		}
	}
}

type roaClient struct {
	t       tomb.Tomb
	host    string
	addr    string
	conn    *net.TCPConn
	state   *config.RpkiServerState
	eventCh chan *roaClientEvent
}

func (c *roaClient) kill() {
	c.t.Kill(nil)
	if c.conn != nil {
		c.conn.Close()
	}
}

func (c *roaClient) tryConnect() error {
	for c.t.Alive() {
		conn, err := net.Dial("tcp", c.host)
		if err != nil {
			time.Sleep(30 * time.Second)
		} else {
			c.eventCh <- &roaClientEvent{
				eventType: CONNECTED,
				src:       c.host,
				conn:      conn.(*net.TCPConn),
			}
			return nil
		}
	}
	return nil
}

func (c *roaClient) established() error {
	defer c.conn.Close()

	disconnected := func() {
		c.eventCh <- &roaClientEvent{
			eventType: DISCONNECTED,
			src:       c.host,
		}
	}

	r := bgp.NewRTRResetQuery()
	data, _ := r.Serialize()
	_, err := c.conn.Write(data)
	if err != nil {
		disconnected()
		return nil
	}

	c.state.RpkiMessages.RpkiSent.ResetQuery++

	reader := bufio.NewReader(c.conn)
	scanner := bufio.NewScanner(reader)
	scanner.Split(bgp.SplitRTR)

	for scanner.Scan() {
		c.eventCh <- &roaClientEvent{
			eventType: RTR,
			src:       c.host,
			data:      scanner.Bytes(),
		}
	}
	disconnected()
	return nil
}

func newROAManager(as uint32, conf config.RpkiServers) (*roaManager, error) {
	m := &roaManager{
		AS:     as,
		roas:   make(map[bgp.RouteFamily]*radix.Tree),
		config: conf,
	}
	m.roas[bgp.RF_IPv4_UC] = radix.New()
	m.roas[bgp.RF_IPv6_UC] = radix.New()
	m.eventCh = make(chan *roaClientEvent)
	m.clientMap = make(map[string]*roaClient)

	for _, entry := range conf.RpkiServerList {
		c := entry.RpkiServerConfig
		client := &roaClient{
			host:    net.JoinHostPort(c.Address.String(), strconv.Itoa(int(c.Port))),
			addr:    c.Address.String(),
			eventCh: m.eventCh,
			state:   &entry.RpkiServerState,
		}
		m.clientMap[client.host] = client
		client.t.Go(client.tryConnect)
	}

	return m, nil
}
