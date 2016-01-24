// Copyright (C) 2015,2016 Nippon Telegraph and Telephone Corporation.
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
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/armon/go-radix"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/table"
	"gopkg.in/tomb.v2"
)

type roaBucket struct {
	Prefix    net.IP
	PrefixLen uint8
	entries   []*roa
}

type roa struct {
	bucket *roaBucket
	Src    string
	MaxLen uint8
	AS     []uint32
}

func (r *roa) toApiStruct() []*api.ROA {
	l := make([]*api.ROA, 0, len(r.AS))
	for _, as := range r.AS {
		host, port := splitHostPort(r.Src)
		a := &api.ROA{
			As:        as,
			Maxlen:    uint32(r.MaxLen),
			Prefixlen: uint32(r.bucket.PrefixLen),
			Prefix:    r.bucket.Prefix.String(),
			Conf: &api.RPKIConf{
				Address:    host,
				RemotePort: uint32(port),
			},
		}
		l = append(l, a)
	}
	return l
}

type roas []*api.ROA

func (r roas) Len() int {
	return len(r)
}

func (r roas) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}

func (r roas) Less(i, j int) bool {
	r1 := r[i]
	r2 := r[j]

	if r1.Maxlen < r1.Maxlen {
		return true
	} else if r1.Maxlen > r1.Maxlen {
		return false
	}

	if r1.As < r2.As {
		return true
	}
	return false
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
	config    []config.RpkiServer
	eventCh   chan *roaClientEvent
	clientMap map[string]*roaClient
}

func newROAManager(as uint32, servers []config.RpkiServer) (*roaManager, error) {
	m := &roaManager{
		AS:     as,
		roas:   make(map[bgp.RouteFamily]*radix.Tree),
		config: servers,
	}
	m.roas[bgp.RF_IPv4_UC] = radix.New()
	m.roas[bgp.RF_IPv6_UC] = radix.New()
	m.eventCh = make(chan *roaClientEvent)
	m.clientMap = make(map[string]*roaClient)

	for _, entry := range servers {
		c := entry.Config
		client := &roaClient{
			host:     net.JoinHostPort(c.Address, strconv.Itoa(int(c.Port))),
			eventCh:  m.eventCh,
			records:  make(map[int]uint32),
			prefixes: make(map[int]uint32),
		}
		m.clientMap[client.host] = client
		client.t.Go(client.tryConnect)
	}

	return m, nil
}

func (m *roaManager) deleteAllROA(network string) {
	for _, tree := range m.roas {
		deleteKeys := make([]string, 0, tree.Len())
		tree.Walk(func(s string, v interface{}) bool {
			b, _ := v.(*roaBucket)
			newEntries := make([]*roa, 0, len(b.entries))
			for _, r := range b.entries {
				if r.Src != network {
					newEntries = append(newEntries, r)
				}
			}
			if len(newEntries) > 0 {
				b.entries = newEntries
			} else {
				deleteKeys = append(deleteKeys, s)
			}
			return false
		})
		for _, key := range deleteKeys {
			tree.Delete(key)
		}
	}
}

func (m *roaManager) operate(op api.Operation, address string) error {
	for network, client := range m.clientMap {
		add, _ := splitHostPort(network)
		if add == address {
			switch op {
			case api.Operation_ENABLE:
				client.enable(client.serialNumber)
			case api.Operation_DISABLE:
			case api.Operation_RESET:
				client.reset()
			case api.Operation_SOFTRESET:
				client.softReset()
				m.deleteAllROA(network)
			}
			return nil
		}
	}
	return fmt.Errorf("roa server not found %s", address)
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
		m.handleRTRMsg(client, &client.state, ev.data)
	}
}

func deleteROA(client *roaClient, family int, tree *radix.Tree, as uint32, prefix []byte, prefixLen, maxLen uint8) {
	host := client.host
	key := table.IpToRadixkey(prefix, prefixLen)
	b, _ := tree.Get(key)
	isDeleted := func() bool {
		if b != nil {
			bucket := b.(*roaBucket)
			for _, r := range bucket.entries {
				if r.MaxLen == maxLen && r.Src == host {
					for idx, a := range r.AS {
						if a == as {
							r.AS = append(r.AS[:idx], r.AS[idx+1:]...)
							if len(bucket.entries) == 0 {
								tree.Delete(key)
							}
							return true
						}
					}
				}
			}
		}
		return false
	}()
	if isDeleted {
		client.records[family]--
		isNoPrefix := func() bool {
			if b, _ := tree.Get(key); b != nil {
				bucket := b.(*roaBucket)
				for _, r := range bucket.entries {
					if r.Src == host {
						return false
					}
				}
				return true
			} else {
				return true
			}
		}()
		if isNoPrefix {
			client.prefixes[family]--
		}
	} else {
		log.Info("can't withdraw a roa", net.IP(prefix).String(), as, prefixLen, maxLen)
	}
}

func addROA(client *roaClient, family int, tree *radix.Tree, as uint32, prefix []byte, prefixLen, maxLen uint8) {
	host := client.host
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
		r.bucket = b

		tree.Insert(key, b)
		client.prefixes[family]++
		client.records[family]++
	} else {
		bucket := b.(*roaBucket)
		isNewPrefix := func() bool {
			for _, r := range bucket.entries {
				if r.Src == host {
					return false
				}
			}
			return true
		}()
		if isNewPrefix {
			client.prefixes[family]++
		}

		for _, r := range bucket.entries {
			if r.MaxLen == maxLen && r.Src == host {
				// we already have?
				for _, a := range r.AS {
					if a == as {
						return
					}
				}
				r.AS = append(r.AS, as)
				client.records[family]++
				return
			}
		}
		r := &roa{
			bucket: bucket,
			MaxLen: maxLen,
			AS:     []uint32{as},
			Src:    host,
		}
		bucket.entries = append(bucket.entries, r)
		client.records[family]++
	}
}

func (c *roaManager) handleRTRMsg(client *roaClient, state *config.RpkiServerState, buf []byte) {
	received := &state.RpkiMessages.RpkiReceived

	m, err := bgp.ParseRTR(buf)
	if err == nil {
		switch msg := m.(type) {
		case *bgp.RTRSerialNotify:
			if client.serialNumber < msg.RTRCommon.SerialNumber {
				client.enable(client.serialNumber)
			} else if client.serialNumber > msg.RTRCommon.SerialNumber {
				// should not happen. try to get the whole ROAs.
				client.softReset()
			}
			received.SerialNotify++
		case *bgp.RTRSerialQuery:
		case *bgp.RTRResetQuery:
		case *bgp.RTRCacheResponse:
			received.CacheResponse++
		case *bgp.RTRIPPrefix:
			var tree *radix.Tree
			family := bgp.AFI_IP
			if msg.Type == bgp.RTR_IPV4_PREFIX {
				received.Ipv4Prefix++
				tree = c.roas[bgp.RF_IPv4_UC]
			} else {
				family = bgp.AFI_IP6
				received.Ipv6Prefix++
				tree = c.roas[bgp.RF_IPv6_UC]
			}
			if (msg.Flags & 1) == 1 {
				addROA(client, family, tree, msg.AS, msg.Prefix, msg.PrefixLen, msg.MaxLen)
			} else {
				deleteROA(client, family, tree, msg.AS, msg.Prefix, msg.PrefixLen, msg.MaxLen)
			}
		case *bgp.RTREndOfData:
			received.EndOfData++
			client.sessionID = msg.RTRCommon.SessionID
			client.serialNumber = msg.RTRCommon.SerialNumber
		case *bgp.RTRCacheReset:
			client.softReset()
			received.CacheReset++
		case *bgp.RTRErrorReport:
			received.Error++
		}
	} else {
		log.Info("failed to parse a RTR message", client.host)
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
			addr, port := splitHostPort(client.host)
			received := &state.RpkiMessages.RpkiReceived
			sent := client.state.RpkiMessages.RpkiSent
			up := true
			if client.conn == nil {
				up = false
			}
			rpki := &api.RPKI{
				Conf: &api.RPKIConf{
					Address:    addr,
					RemotePort: uint32(port),
				},
				State: &api.RPKIState{
					Uptime:        state.Uptime,
					Downtime:      state.Downtime,
					Up:            up,
					RecordIpv4:    client.records[bgp.AFI_IP],
					RecordIpv6:    client.records[bgp.AFI_IP6],
					PrefixIpv4:    client.prefixes[bgp.AFI_IP],
					PrefixIpv6:    client.prefixes[bgp.AFI_IP6],
					Serial:        client.serialNumber,
					ReceivedIpv4:  received.Ipv4Prefix,
					ReceivedIpv6:  received.Ipv6Prefix,
					SerialNotify:  received.SerialNotify,
					CacheReset:    received.CacheReset,
					CacheResponse: received.CacheResponse,
					EndOfData:     received.EndOfData,
					Error:         received.Error,
					SerialQuery:   sent.SerialQuery,
					ResetQuery:    sent.ResetQuery,
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
					var roaList roas
					for _, r := range b.entries {
						for _, as := range r.AS {
							host, port := splitHostPort(r.Src)
							roa := &api.ROA{
								As:        as,
								Maxlen:    uint32(r.MaxLen),
								Prefixlen: uint32(b.PrefixLen),
								Prefix:    b.Prefix.String(),
								Conf: &api.RPKIConf{
									Address:    host,
									RemotePort: uint32(port),
								},
							}
							roaList = append(roaList, roa)
						}
					}
					sort.Sort(roaList)
					for _, roa := range roaList {
						result := &GrpcResponse{
							Data: roa,
						}
						results = append(results, result)
					}
					return false
				})
			}
		}
		go sendMultipleResponses(grpcReq, results)
	}
}

func validatePath(ownAs uint32, tree *radix.Tree, cidr string, asPath *bgp.PathAttributeAsPath) (config.RpkiValidationResultType, []*roa) {
	var as uint32
	if asPath == nil || len(asPath.Value) == 0 {
		return config.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND, []*roa{}
	}
	asParam := asPath.Value[len(asPath.Value)-1].(*bgp.As4PathParam)
	switch asParam.Type {
	case bgp.BGP_ASPATH_ATTR_TYPE_SEQ:
		if len(asParam.AS) == 0 {
			return config.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND, []*roa{}
		}
		as = asParam.AS[len(asParam.AS)-1]
	case bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET, bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ:
		as = ownAs
	default:
		return config.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND, []*roa{}
	}
	_, n, _ := net.ParseCIDR(cidr)
	ones, _ := n.Mask.Size()
	prefixLen := uint8(ones)
	_, b, _ := tree.LongestPrefix(table.IpToRadixkey(n.IP, prefixLen))
	if b == nil {
		return config.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND, []*roa{}
	}

	roaList := make([]*roa, 0)

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
			return config.RPKI_VALIDATION_RESULT_TYPE_VALID, []*roa{r}
		}
		roaList = append(roaList, r)
	}
	return result, roaList
}

func (c *roaManager) validate(pathList []*table.Path, isMonitor bool) []*api.ROAResult {
	results := make([]*api.ROAResult, 0)
	if len(c.clientMap) == 0 {
		return results
	}
	for _, path := range pathList {
		if path.IsWithdraw {
			continue
		}
		if tree, ok := c.roas[path.GetRouteFamily()]; ok {
			r, roaList := validatePath(c.AS, tree, path.GetNlri().String(), path.GetAsPath())
			if isMonitor && path.Validation() != config.RpkiValidationResultType(r) {
				apiRoaList := func() []*api.ROA {
					apiRoaList := make([]*api.ROA, 0)
					for _, r := range roaList {
						apiRoaList = append(apiRoaList, r.toApiStruct()...)
					}
					return apiRoaList
				}()
				rr := &api.ROAResult{
					Address:   path.GetSource().Address.String(),
					Timestamp: path.GetTimestamp().Unix(),
					OriginAs:  path.GetSourceAs(),
					Prefix:    path.GetNlri().String(),
					OldResult: api.ROAResult_ValidationResult(path.Validation().ToInt()),
					NewResult: api.ROAResult_ValidationResult(r.ToInt()),
					Roas:      apiRoaList,
				}
				if b := path.GetAsPath(); b != nil {
					rr.AspathAttr, _ = b.Serialize()
				}
				results = append(results, rr)
			}
			path.SetValidation(config.RpkiValidationResultType(r))
		}
	}
	return results
}

type roaClient struct {
	t            tomb.Tomb
	host         string
	conn         *net.TCPConn
	state        config.RpkiServerState
	eventCh      chan *roaClientEvent
	sessionID    uint16
	serialNumber uint32
	prefixes     map[int]uint32
	records      map[int]uint32
}

func (c *roaClient) enable(serial uint32) error {
	if c.conn != nil {
		r := bgp.NewRTRSerialQuery(c.sessionID, serial)
		data, _ := r.Serialize()
		_, err := c.conn.Write(data)
		if err != nil {
			return err
		}
		c.state.RpkiMessages.RpkiSent.SerialQuery++
	}
	return nil
}

func (c *roaClient) softReset() error {
	if c.conn != nil {
		r := bgp.NewRTRResetQuery()
		data, _ := r.Serialize()
		_, err := c.conn.Write(data)
		if err != nil {
			return err
		}
		c.state.RpkiMessages.RpkiSent.ResetQuery++
	}
	return nil
}

func (c *roaClient) reset() {
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

	err := c.softReset()
	if err != nil {
		disconnected()
		return nil
	}

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
