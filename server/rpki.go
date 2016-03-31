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
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/armon/go-radix"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/osrg/gobgp/table"
	"gopkg.in/tomb.v2"
)

func before(a, b uint32) bool {
	return int32(a-b) < 0
}

type ipPrefix struct {
	Prefix net.IP
	Length uint8
}

type roaBucket struct {
	Prefix  *ipPrefix
	entries []*ROA
}

type ROA struct {
	Family int
	Prefix *ipPrefix
	MaxLen uint8
	AS     uint32
	Src    string
}

func NewROA(family int, prefixByte []byte, prefixLen uint8, maxLen uint8, as uint32, src string) *ROA {
	p := make([]byte, len(prefixByte))
	copy(p, prefixByte)
	return &ROA{
		Family: family,
		Prefix: &ipPrefix{
			Prefix: p,
			Length: prefixLen,
		},
		MaxLen: maxLen,
		AS:     as,
		Src:    src,
	}
}

func (r *ROA) Equal(roa *ROA) bool {
	if r.MaxLen == roa.MaxLen && r.Src == roa.Src && r.AS == roa.AS {
		return true
	}
	return false
}

func (r *ROA) toApiStruct() *api.ROA {
	host, port, _ := net.SplitHostPort(r.Src)
	return &api.ROA{
		As:        r.AS,
		Maxlen:    uint32(r.MaxLen),
		Prefixlen: uint32(r.Prefix.Length),
		Prefix:    r.Prefix.Prefix.String(),
		Conf: &api.RPKIConf{
			Address:    host,
			RemotePort: port,
		},
	}
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
	LIFETIMEOUT
)

type roaClientEvent struct {
	eventType uint8
	src       string
	conn      *net.TCPConn
	data      []byte
}

type roaManager struct {
	AS        uint32
	Roas      map[bgp.RouteFamily]*radix.Tree
	config    []config.RpkiServer
	eventCh   chan *roaClientEvent
	clientMap map[string]*roaClient
}

func NewROAManager(as uint32, servers []config.RpkiServer) (*roaManager, error) {
	m := &roaManager{
		AS:     as,
		Roas:   make(map[bgp.RouteFamily]*radix.Tree),
		config: servers,
	}
	m.Roas[bgp.RF_IPv4_UC] = radix.New()
	m.Roas[bgp.RF_IPv6_UC] = radix.New()
	m.eventCh = make(chan *roaClientEvent)
	m.clientMap = make(map[string]*roaClient)

	for _, entry := range servers {
		c := entry.Config
		// should be set somewhere else
		if c.RecordLifetime == 0 {
			c.RecordLifetime = 3600
		}
		client := NewRoaClient(c.Address, strconv.Itoa(int(c.Port)), m.eventCh, c.RecordLifetime)
		m.clientMap[client.host] = client
		client.t.Go(client.tryConnect)
	}

	return m, nil
}

func (m *roaManager) deleteAllROA(network string) {
	for _, tree := range m.Roas {
		deleteKeys := make([]string, 0, tree.Len())
		tree.Walk(func(s string, v interface{}) bool {
			b, _ := v.(*roaBucket)
			newEntries := make([]*ROA, 0, len(b.entries))
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
		add, _, _ := net.SplitHostPort(network)
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

func (c *roaManager) ReceiveROA() chan *roaClientEvent {
	return c.eventCh
}

func (c *roaClient) lifetimeout() {
	c.eventCh <- &roaClientEvent{
		eventType: LIFETIMEOUT,
		src:       c.host,
	}
}

func (m *roaManager) HandleROAEvent(ev *roaClientEvent) {
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
		client.endOfData = false
		client.pendingROAs = make([]*ROA, 0)
		client.state.RpkiMessages = config.RpkiMessages{}
		client.conn = nil
		client.t = tomb.Tomb{}
		client.t.Go(client.tryConnect)
		client.timer = time.AfterFunc(time.Duration(client.lifetime)*time.Second, client.lifetimeout)
		client.oldSessionID = client.sessionID
	case CONNECTED:
		log.Info("roa server is connected, ", ev.src)
		client.conn = ev.conn
		client.state.Uptime = time.Now().Unix()
		client.t = tomb.Tomb{}
		client.t.Go(client.established)
	case RTR:
		m.handleRTRMsg(client, &client.state, ev.data)
	case LIFETIMEOUT:
		// a) already reconnected but hasn't received
		// EndOfData -> needs to delete stale ROAs
		// b) not reconnected -> needs to delete stale ROAs
		//
		// c) already reconnected and received EndOfData so
		// all stale ROAs were deleted -> timer was cancelled
		// so should not be here.
		if client.oldSessionID != client.sessionID {
			log.Info("reconnected so ignore timeout", client.host)
		} else {
			log.Info("delete all due to timeout", client.host)
			m.deleteAllROA(client.host)
		}
	}
}

func (m *roaManager) roa2tree(roa *ROA) (*radix.Tree, string) {
	tree := m.Roas[bgp.RF_IPv4_UC]
	if roa.Family == bgp.AFI_IP6 {
		tree = m.Roas[bgp.RF_IPv6_UC]
	}
	return tree, table.IpToRadixkey(roa.Prefix.Prefix, roa.Prefix.Length)
}

func (m *roaManager) deleteROA(roa *ROA) {
	tree, key := m.roa2tree(roa)
	b, _ := tree.Get(key)
	if b != nil {
		bucket := b.(*roaBucket)
		newEntries := make([]*ROA, 0, len(bucket.entries))
		for _, r := range bucket.entries {
			if !r.Equal(roa) {
				newEntries = append(newEntries, r)
			}
		}
		if len(newEntries) != len(bucket.entries) {
			bucket.entries = newEntries
			if len(newEntries) == 0 {
				tree.Delete(key)
			}
			return
		}
	}
	log.Info("can't withdraw a roa", roa.Prefix.Prefix.String(), roa.Prefix.Length, roa.AS, roa.MaxLen)
}

func (m *roaManager) addROA(roa *ROA) {
	tree, key := m.roa2tree(roa)
	b, _ := tree.Get(key)
	var bucket *roaBucket
	if b == nil {
		bucket = &roaBucket{
			Prefix:  roa.Prefix,
			entries: make([]*ROA, 0),
		}
		tree.Insert(key, bucket)
	} else {
		bucket = b.(*roaBucket)
		for _, r := range bucket.entries {
			if r.Equal(roa) {
				// we already have the same one
				return
			}
		}
	}
	bucket.entries = append(bucket.entries, roa)
}

func (c *roaManager) handleRTRMsg(client *roaClient, state *config.RpkiServerState, buf []byte) {
	received := &state.RpkiMessages.RpkiReceived

	m, err := bgp.ParseRTR(buf)
	if err == nil {
		switch msg := m.(type) {
		case *bgp.RTRSerialNotify:
			if before(client.serialNumber, msg.RTRCommon.SerialNumber) {
				client.enable(client.serialNumber)
			} else if client.serialNumber == msg.RTRCommon.SerialNumber {
				// nothing
			} else {
				// should not happen. try to get the whole ROAs.
				client.softReset()
			}
			received.SerialNotify++
		case *bgp.RTRSerialQuery:
		case *bgp.RTRResetQuery:
		case *bgp.RTRCacheResponse:
			received.CacheResponse++
			client.endOfData = false
		case *bgp.RTRIPPrefix:
			family := bgp.AFI_IP
			if msg.Type == bgp.RTR_IPV4_PREFIX {
				received.Ipv4Prefix++
			} else {
				family = bgp.AFI_IP6
				received.Ipv6Prefix++
			}
			roa := NewROA(family, msg.Prefix, msg.PrefixLen, msg.MaxLen, msg.AS, client.host)
			if (msg.Flags & 1) == 1 {
				if client.endOfData {
					c.addROA(roa)
				} else {
					client.pendingROAs = append(client.pendingROAs, roa)
				}
			} else {
				c.deleteROA(roa)
			}
		case *bgp.RTREndOfData:
			received.EndOfData++
			if client.sessionID != msg.RTRCommon.SessionID {
				// remove all ROAs related with the
				// previous session
				c.deleteAllROA(client.host)
			}
			client.sessionID = msg.RTRCommon.SessionID
			client.serialNumber = msg.RTRCommon.SerialNumber
			client.endOfData = true
			if client.timer != nil {
				client.timer.Stop()
				client.timer = nil
			}
			for _, roa := range client.pendingROAs {
				c.addROA(roa)
			}
			client.pendingROAs = make([]*ROA, 0)
		case *bgp.RTRCacheReset:
			client.softReset()
			received.CacheReset++
		case *bgp.RTRErrorReport:
			received.Error++
		}
	} else {
		log.Info("failed to parse a RTR message ", client.host, err)
	}
}

func (c *roaManager) handleGRPC(grpcReq *GrpcRequest) {
	switch grpcReq.RequestType {
	case REQ_RPKI:
		results := make([]*GrpcResponse, 0)

		f := func(tree *radix.Tree) (map[string]uint32, map[string]uint32) {
			records := make(map[string]uint32)
			prefixes := make(map[string]uint32)

			tree.Walk(func(s string, v interface{}) bool {
				b, _ := v.(*roaBucket)
				tmpRecords := make(map[string]uint32)
				for _, roa := range b.entries {
					tmpRecords[roa.Src]++
				}

				for src, r := range tmpRecords {
					if r > 0 {
						records[src] += r
						prefixes[src]++
					}
				}
				return false
			})
			return records, prefixes
		}

		recordsV4, prefixesV4 := f(c.Roas[bgp.RF_IPv4_UC])
		recordsV6, prefixesV6 := f(c.Roas[bgp.RF_IPv6_UC])

		for _, client := range c.clientMap {
			state := client.state
			addr, port, _ := net.SplitHostPort(client.host)
			received := &state.RpkiMessages.RpkiReceived
			sent := client.state.RpkiMessages.RpkiSent
			up := true
			if client.conn == nil {
				up = false
			}

			f := func(m map[string]uint32, key string) uint32 {
				if r, ok := m[key]; ok {
					return r
				}
				return 0
			}

			rpki := &api.RPKI{
				Conf: &api.RPKIConf{
					Address:    addr,
					RemotePort: port,
				},
				State: &api.RPKIState{
					Uptime:        state.Uptime,
					Downtime:      state.Downtime,
					Up:            up,
					RecordIpv4:    f(recordsV4, client.host),
					RecordIpv6:    f(recordsV6, client.host),
					PrefixIpv4:    f(prefixesV4, client.host),
					PrefixIpv6:    f(prefixesV6, client.host),
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
			if tree, ok := c.Roas[rf]; ok {
				tree.Walk(func(s string, v interface{}) bool {
					b, _ := v.(*roaBucket)
					var roaList roas
					for _, r := range b.entries {
						roaList = append(roaList, r.toApiStruct())
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

func validatePath(ownAs uint32, tree *radix.Tree, cidr string, asPath *bgp.PathAttributeAsPath) (config.RpkiValidationResultType, []*ROA) {
	var as uint32
	if asPath == nil || len(asPath.Value) == 0 {
		return config.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND, []*ROA{}
	}
	asParam := asPath.Value[len(asPath.Value)-1].(*bgp.As4PathParam)
	switch asParam.Type {
	case bgp.BGP_ASPATH_ATTR_TYPE_SEQ:
		if len(asParam.AS) == 0 {
			return config.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND, []*ROA{}
		}
		as = asParam.AS[len(asParam.AS)-1]
	case bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET, bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ:
		as = ownAs
	default:
		return config.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND, []*ROA{}
	}
	_, n, _ := net.ParseCIDR(cidr)
	ones, _ := n.Mask.Size()
	prefixLen := uint8(ones)
	_, b, _ := tree.LongestPrefix(table.IpToRadixkey(n.IP, prefixLen))
	if b == nil {
		return config.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND, []*ROA{}
	}

	roaList := make([]*ROA, 0)

	result := config.RPKI_VALIDATION_RESULT_TYPE_INVALID
	bucket, _ := b.(*roaBucket)
	for _, r := range bucket.entries {
		if prefixLen > r.MaxLen {
			continue
		}
		if r.AS == as {
			result = config.RPKI_VALIDATION_RESULT_TYPE_VALID
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
		if tree, ok := c.Roas[path.GetRouteFamily()]; ok {
			r, roaList := validatePath(c.AS, tree, path.GetNlri().String(), path.GetAsPath())
			if isMonitor && path.Validation() != config.RpkiValidationResultType(r) {
				apiRoaList := func() []*api.ROA {
					apiRoaList := make([]*api.ROA, 0)
					for _, r := range roaList {
						apiRoaList = append(apiRoaList, r.toApiStruct())
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
	oldSessionID uint16
	serialNumber uint32
	timer        *time.Timer
	lifetime     int64
	endOfData    bool
	pendingROAs  []*ROA
}

func NewRoaClient(address, port string, ch chan *roaClientEvent, lifetime int64) *roaClient {
	return &roaClient{
		host:        net.JoinHostPort(address, port),
		eventCh:     ch,
		lifetime:    lifetime,
		pendingROAs: make([]*ROA, 0),
	}
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
		c.endOfData = false
		c.pendingROAs = make([]*ROA, 0)
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

	for {
		header := make([]byte, bgp.RTR_MIN_LEN)
		_, err := io.ReadFull(c.conn, header)
		if err != nil {
			break
		}
		totalLen := binary.BigEndian.Uint32(header[4:8])
		if totalLen < bgp.RTR_MIN_LEN {
			break
		}

		body := make([]byte, totalLen-bgp.RTR_MIN_LEN)
		_, err = io.ReadFull(c.conn, body)
		if err != nil {
			break
		}

		c.eventCh <- &roaClientEvent{
			eventType: RTR,
			src:       c.host,
			data:      append(header, body...),
		}

	}
	disconnected()
	return nil
}
