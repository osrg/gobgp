// Copyright (C) 2014, 2015 Nippon Telegraph and Telephone Corporation.
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

package zebra

import (
	"encoding/binary"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"io"
	"net"
	"strings"
	"syscall"
)

const (
	HEADER_SIZE      = 6
	HEADER_MARKER    = 255
	VERSION          = 2
	INTERFACE_NAMSIZ = 20
)

type INTERFACE_STATUS uint8

const (
	INTERFACE_ACTIVE        = 0x01
	INTERFACE_SUB           = 0x02
	INTERFACE_LINKDETECTION = 0x04
)

func (t INTERFACE_STATUS) String() string {
	ss := make([]string, 0, 3)
	if t&INTERFACE_ACTIVE > 0 {
		ss = append(ss, "ACTIVE")
	}
	if t&INTERFACE_SUB > 0 {
		ss = append(ss, "SUB")
	}
	if t&INTERFACE_LINKDETECTION > 0 {
		ss = append(ss, "LINKDETECTION")
	}
	return strings.Join(ss, "|")
}

// Subsequent Address Family Identifier.
type SAFI uint8

const (
	_ SAFI = iota
	SAFI_UNICAST
	SAFI_MULTICAST
	SAFI_RESERVED_3
	SAFI_MPLS_VPN
	SAFI_MAX
)

// API Types.
type API_TYPE uint16

const (
	_ API_TYPE = iota
	INTERFACE_ADD
	INTERFACE_DELETE
	INTERFACE_ADDRESS_ADD
	INTERFACE_ADDRESS_DELETE
	INTERFACE_UP
	INTERFACE_DOWN
	IPV4_ROUTE_ADD
	IPV4_ROUTE_DELETE
	IPV6_ROUTE_ADD
	IPV6_ROUTE_DELETE
	REDISTRIBUTE_ADD
	REDISTRIBUTE_DELETE
	REDISTRIBUTE_DEFAULT_ADD
	REDISTRIBUTE_DEFAULT_DELETE
	IPV4_NEXTHOP_LOOKUP
	IPV6_NEXTHOP_LOOKUP
	IPV4_IMPORT_LOOKUP
	IPV6_IMPORT_LOOKUP
	INTERFACE_RENAME
	ROUTER_ID_ADD
	ROUTER_ID_DELETE
	ROUTER_ID_UPDATE
	HELLO
	MESSAGE_MAX
)

// Route Types.
type ROUTE_TYPE uint8

const (
	ROUTE_SYSTEM ROUTE_TYPE = iota
	ROUTE_KERNEL
	ROUTE_CONNECT
	ROUTE_STATIC
	ROUTE_RIP
	ROUTE_RIPNG
	ROUTE_OSPF
	ROUTE_OSPF6
	ROUTE_ISIS
	ROUTE_BGP
	ROUTE_HSLS
	ROUTE_OLSR
	ROUTE_BABEL
	ROUTE_MAX
)

var routeTypeValueMap = map[string]ROUTE_TYPE{
	"system":  ROUTE_SYSTEM,
	"kernel":  ROUTE_KERNEL,
	"connect": ROUTE_CONNECT,
	"static":  ROUTE_STATIC,
	"rip":     ROUTE_RIP,
	"ripng":   ROUTE_RIPNG,
	"ospf":    ROUTE_OSPF,
	"ospf3":   ROUTE_OSPF6,
	"isis":    ROUTE_ISIS,
	"bgp":     ROUTE_BGP,
	"hsls":    ROUTE_HSLS,
	"olsr":    ROUTE_OLSR,
	"babel":   ROUTE_BABEL,
}

func RouteTypeFromString(typ string) (ROUTE_TYPE, error) {
	t, ok := routeTypeValueMap[typ]
	if ok {
		return t, nil
	}
	return t, fmt.Errorf("unknown route type: %s", typ)
}

const (
	MESSAGE_NEXTHOP  = 0x01
	MESSAGE_IFINDEX  = 0x02
	MESSAGE_DISTANCE = 0x04
	MESSAGE_METRIC   = 0x08
)

// Message Flags
type FLAG uint64

const (
	FLAG_INTERNAL  FLAG = 0x01
	FLAG_SELFROUTE FLAG = 0x02
	FLAG_BLACKHOLE FLAG = 0x04
	FLAG_IBGP      FLAG = 0x08
	FLAG_SELECTED  FLAG = 0x10
	FLAG_CHANGED   FLAG = 0x20
	FLAG_STATIC    FLAG = 0x40
	FLAG_REJECT    FLAG = 0x80
)

func (t FLAG) String() string {
	var ss []string
	if t&FLAG_INTERNAL > 0 {
		ss = append(ss, "FLAG_INTERNAL")
	}
	if t&FLAG_SELFROUTE > 0 {
		ss = append(ss, "FLAG_SELFROUTE")
	}
	if t&FLAG_BLACKHOLE > 0 {
		ss = append(ss, "FLAG_BLACKHOLE")
	}
	if t&FLAG_IBGP > 0 {
		ss = append(ss, "FLAG_IBGP")
	}
	if t&FLAG_SELECTED > 0 {
		ss = append(ss, "FLAG_SELECTED")
	}
	if t&FLAG_CHANGED > 0 {
		ss = append(ss, "FLAG_CHANGED")
	}
	if t&FLAG_STATIC > 0 {
		ss = append(ss, "FLAG_STATIC")
	}
	if t&FLAG_REJECT > 0 {
		ss = append(ss, "FLAG_REJECT")
	}
	return strings.Join(ss, "|")
}

// Nexthop Flags.
type NEXTHOP_FLAG uint8

const (
	_ NEXTHOP_FLAG = iota
	NEXTHOP_IFINDEX
	NEXTHOP_IFNAME
	NEXTHOP_IPV4
	NEXTHOP_IPV4_IFINDEX
	NEXTHOP_IPV4_IFNAME
	NEXTHOP_IPV6
	NEXTHOP_IPV6_IFINDEX
	NEXTHOP_IPV6_IFNAME
	NEXTHOP_BLACKHOLE
)

type Client struct {
	outgoing      chan *Message
	incoming      chan *Message
	redistDefault ROUTE_TYPE
	conn          net.Conn
}

func NewClient(network, address string, typ ROUTE_TYPE) (*Client, error) {
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	outgoing := make(chan *Message)
	incoming := make(chan *Message, 64)

	c := &Client{
		outgoing:      outgoing,
		incoming:      incoming,
		redistDefault: typ,
		conn:          conn,
	}

	go func() {
		for {
			m, more := <-outgoing
			if more {
				b, err := m.Serialize()
				if err != nil {
					log.Warnf("failed to serialize: %s", m)
					continue
				}

				_, err = conn.Write(b)
				if err != nil {
					log.Errorf("failed to write: %s", err)
					close(outgoing)
				}
			} else {
				log.Debug("finish outgoing loop")
				return
			}
		}
	}()

	go func() {
		for {
			headerBuf, err := readAll(conn, HEADER_SIZE)
			if err != nil {
				log.Error("failed to read header: ", err)
				return
			}
			log.Debugf("read header from zebra: %v", headerBuf)
			hd := &Header{}
			err = hd.DecodeFromBytes(headerBuf)
			if err != nil {
				log.Error("failed to decode header: ", err)
				return
			}

			bodyBuf, err := readAll(conn, int(hd.Len-HEADER_SIZE))
			if err != nil {
				log.Error("failed to read body: ", err)
				return
			}
			log.Debugf("read body from zebra: %v", bodyBuf)
			m, err := ParseMessage(hd, bodyBuf)
			if err != nil {
				log.Warn("failed to parse message: ", err)
				continue
			}

			incoming <- m
		}
	}()

	return c, nil
}

func readAll(conn net.Conn, length int) ([]byte, error) {
	buf := make([]byte, length)
	_, err := io.ReadFull(conn, buf)
	return buf, err
}

func (c *Client) Receive() chan *Message {
	return c.incoming
}

func (c *Client) Send(m *Message) {
	defer func() {
		if err := recover(); err != nil {
			log.Debugf("recovered: %s", err)
		}
	}()
	log.WithFields(log.Fields{
		"Topic":  "Zebra",
		"Header": m.Header,
		"Body":   m.Body,
	}).Debug("send command to zebra")
	c.outgoing <- m
}

func (c *Client) SendCommand(command API_TYPE, body Body) error {
	m := &Message{
		Header: Header{
			Len:     HEADER_SIZE,
			Marker:  HEADER_MARKER,
			Version: VERSION,
			Command: command,
		},
		Body: body,
	}
	c.Send(m)
	return nil
}

func (c *Client) SendHello() error {
	if c.redistDefault > 0 {
		body := &HelloBody{
			RedistDefault: c.redistDefault,
		}
		return c.SendCommand(HELLO, body)
	}
	return nil
}

func (c *Client) SendRouterIDAdd() error {
	return c.SendCommand(ROUTER_ID_ADD, nil)
}

func (c *Client) SendInterfaceAdd() error {
	return c.SendCommand(INTERFACE_ADD, nil)
}

func (c *Client) SendRedistribute(t ROUTE_TYPE) error {
	if c.redistDefault != t {
		body := &RedistributeBody{
			Redist: t,
		}
		if e := c.SendCommand(REDISTRIBUTE_ADD, body); e != nil {
			return e
		}
	}

	return nil
}

func (c *Client) SendRedistributeDelete(t ROUTE_TYPE) error {

	if t < ROUTE_MAX {
		body := &RedistributeBody{
			Redist: t,
		}
		if e := c.SendCommand(REDISTRIBUTE_DELETE, body); e != nil {
			return e
		}
	} else {
		return fmt.Errorf("unknown route type: %d", t)
	}
	return nil
}

func (c *Client) Close() error {
	close(c.outgoing)
	return c.conn.Close()
}

type Header struct {
	Len     uint16
	Marker  uint8
	Version uint8
	Command API_TYPE
}

func (h *Header) Serialize() ([]byte, error) {
	buf := make([]byte, HEADER_SIZE)
	binary.BigEndian.PutUint16(buf[0:], h.Len)
	buf[2] = h.Marker
	buf[3] = h.Version
	binary.BigEndian.PutUint16(buf[4:], uint16(h.Command))
	return buf, nil
}

func (h *Header) DecodeFromBytes(data []byte) error {
	if uint16(len(data)) < HEADER_SIZE {
		return fmt.Errorf("Not all ZAPI message header")
	}
	h.Len = binary.BigEndian.Uint16(data[0:2])
	h.Marker = data[2]
	h.Version = data[3]
	h.Command = API_TYPE(binary.BigEndian.Uint16(data[4:6]))
	return nil
}

type Body interface {
	DecodeFromBytes([]byte) error
	Serialize() ([]byte, error)
}

type HelloBody struct {
	RedistDefault ROUTE_TYPE
}

func (b *HelloBody) DecodeFromBytes(data []byte) error {
	b.RedistDefault = ROUTE_TYPE(data[0])
	return nil
}

func (b *HelloBody) Serialize() ([]byte, error) {
	return []byte{uint8(b.RedistDefault)}, nil
}

type RedistributeBody struct {
	Redist ROUTE_TYPE
}

func (b *RedistributeBody) DecodeFromBytes(data []byte) error {
	b.Redist = ROUTE_TYPE(data[0])
	return nil
}

func (b *RedistributeBody) Serialize() ([]byte, error) {
	return []byte{uint8(b.Redist)}, nil
}

type InterfaceUpdateBody struct {
	Name         string
	Index        uint32
	Status       INTERFACE_STATUS
	Flags        uint64
	Metric       uint32
	MTU          uint32
	MTU6         uint32
	Bandwidth    uint32
	HardwareAddr net.HardwareAddr
}

func (b *InterfaceUpdateBody) DecodeFromBytes(data []byte) error {
	if len(data) < INTERFACE_NAMSIZ+29 {
		return fmt.Errorf("lack of bytes. need %d but %d", INTERFACE_NAMSIZ+29, len(data))
	}

	b.Name = string(data[:INTERFACE_NAMSIZ])
	data = data[INTERFACE_NAMSIZ:]
	b.Index = binary.BigEndian.Uint32(data[:4])
	b.Status = INTERFACE_STATUS(data[4])
	b.Flags = binary.BigEndian.Uint64(data[5:13])
	b.Metric = binary.BigEndian.Uint32(data[13:17])
	b.MTU = binary.BigEndian.Uint32(data[17:21])
	b.MTU6 = binary.BigEndian.Uint32(data[21:25])
	b.Bandwidth = binary.BigEndian.Uint32(data[25:29])
	l := binary.BigEndian.Uint32(data[29:33])
	if l > 0 {
		b.HardwareAddr = data[33 : 33+l]
	}
	return nil
}

func (b *InterfaceUpdateBody) Serialize() ([]byte, error) {
	return []byte{}, nil
}

func (b *InterfaceUpdateBody) String() string {
	s := fmt.Sprintf("name: %s, idx: %d, status: %s, flags: %s, metric: %d, mtu: %d, mtu6: %d, bandwith: %d", b.Name, b.Index, b.Status, intfflag2string(b.Flags), b.Metric, b.MTU, b.MTU6, b.Bandwidth)
	if len(b.HardwareAddr) > 0 {
		return s + fmt.Sprintf(", mac: %s", b.HardwareAddr)
	}
	return s
}

type InterfaceAddressUpdateBody struct {
	Index  uint32
	Flags  uint8
	Prefix net.IP
	Length uint8
}

func (b *InterfaceAddressUpdateBody) DecodeFromBytes(data []byte) error {
	b.Index = binary.BigEndian.Uint32(data[:4])
	b.Flags = data[4]
	family := data[5]
	var addrlen int8
	switch family {
	case syscall.AF_INET:
		addrlen = net.IPv4len
	case syscall.AF_INET6:
		addrlen = net.IPv6len
	default:
		return fmt.Errorf("unknown address family: %d", family)
	}
	b.Prefix = data[6 : 6+addrlen]
	b.Length = data[6+addrlen]
	return nil
}

func (b *InterfaceAddressUpdateBody) Serialize() ([]byte, error) {
	return []byte{}, nil
}

func (b *InterfaceAddressUpdateBody) String() string {
	return fmt.Sprintf("idx: %d, flags: %d, addr: %s/%d", b.Index, b.Flags, b.Prefix, b.Length)
}

type RouterIDUpdateBody struct {
	Length uint8
	Prefix net.IP
}

func (b *RouterIDUpdateBody) DecodeFromBytes(data []byte) error {
	family := data[0]
	var addrlen int8
	switch family {
	case syscall.AF_INET:
		addrlen = net.IPv4len
	case syscall.AF_INET6:
		addrlen = net.IPv6len
	default:
		return fmt.Errorf("unknown address family: %d", family)
	}
	b.Prefix = data[1 : 1+addrlen]
	b.Length = data[1+addrlen]
	return nil
}

func (b *RouterIDUpdateBody) Serialize() ([]byte, error) {
	return []byte{}, nil
}

func (b *RouterIDUpdateBody) String() string {
	return fmt.Sprintf("id: %s/%d", b.Prefix, b.Length)
}

type IPRouteBody struct {
	Type         ROUTE_TYPE
	Flags        FLAG
	Message      uint8
	SAFI         SAFI
	Prefix       net.IP
	PrefixLength uint8
	Nexthops     []net.IP
	Ifindexs     []uint32
	Distance     uint8
	Metric       uint32
	Api          API_TYPE
}

func (b *IPRouteBody) Serialize() ([]byte, error) {
	buf := make([]byte, 5)
	buf[0] = uint8(b.Type)
	buf[1] = uint8(b.Flags)
	buf[2] = b.Message
	binary.BigEndian.PutUint16(buf[3:], uint16(b.SAFI))
	bitlen := b.PrefixLength
	bytelen := (int(b.PrefixLength) + 7) / 8
	bbuf := make([]byte, bytelen)
	copy(bbuf, b.Prefix)
	if bitlen%8 != 0 {
		mask := 0xff00 >> (bitlen % 8)
		last_byte_value := bbuf[bytelen-1] & byte(mask)
		bbuf[bytelen-1] = last_byte_value
	}
	buf = append(buf, bitlen)
	buf = append(buf, bbuf...)

	if b.Message&MESSAGE_NEXTHOP > 0 {
		if b.Flags&FLAG_BLACKHOLE > 0 {
			buf = append(buf, []byte{1, uint8(NEXTHOP_BLACKHOLE)}...)
		} else {
			buf = append(buf, uint8(len(b.Nexthops)+len(b.Ifindexs)))
		}

		for _, v := range b.Nexthops {
			if v.To4() != nil {
				buf = append(buf, uint8(NEXTHOP_IPV4))
				buf = append(buf, v.To4()...)
			} else {
				buf = append(buf, uint8(NEXTHOP_IPV6))
				buf = append(buf, v.To16()...)
			}
		}

		for _, v := range b.Ifindexs {
			buf = append(buf, uint8(NEXTHOP_IFINDEX))
			bbuf := make([]byte, 4)
			binary.BigEndian.PutUint32(bbuf, v)
			buf = append(buf, bbuf...)
		}
	}

	if b.Message&MESSAGE_DISTANCE > 0 {
		buf = append(buf, b.Distance)
	}
	if b.Message&MESSAGE_METRIC > 0 {
		bbuf := make([]byte, 4)
		binary.BigEndian.PutUint32(bbuf, b.Metric)
		buf = append(buf, bbuf...)
	}
	return buf, nil
}

func (b *IPRouteBody) DecodeFromBytes(data []byte) error {

	isV4 := b.Api == IPV4_ROUTE_ADD || b.Api == IPV4_ROUTE_DELETE
	var addrLen uint8 = net.IPv4len
	if !isV4 {
		addrLen = net.IPv6len
	}

	b.Type = ROUTE_TYPE(data[0])
	b.Flags = FLAG(data[1])
	b.Message = data[2]
	b.PrefixLength = data[3]
	b.SAFI = SAFI(SAFI_UNICAST)

	if b.PrefixLength > addrLen*8 {
		return fmt.Errorf("prefix length is greater than %d", addrLen*8)
	}

	byteLen := int((b.PrefixLength + 7) / 8)

	pos := 4
	buf := make([]byte, addrLen)
	copy(buf, data[pos:pos+byteLen])

	if isV4 {
		b.Prefix = net.IP(buf).To4()
	} else {
		b.Prefix = net.IP(buf).To16()
	}

	pos += byteLen

	rest := 0
	var numNexthop int
	if b.Message&MESSAGE_NEXTHOP > 0 {
		numNexthop = int(data[pos])
		// rest = numNexthop(1) + (nexthop(4 or 16) + placeholder(1) + ifindex(4)) * numNexthop
		rest += 1 + numNexthop*(int(addrLen)+5)
	}

	if b.Message&MESSAGE_DISTANCE > 0 {
		// distance(1)
		rest += 1
	}

	if b.Message&MESSAGE_METRIC > 0 {
		// metric(4)
		rest += 4
	}

	if len(data[pos:]) != rest {
		return fmt.Errorf("message length invalid")
	}

	b.Nexthops = []net.IP{}
	b.Ifindexs = []uint32{}

	if b.Message&MESSAGE_NEXTHOP > 0 {
		pos += 1
		for i := 0; i < numNexthop; i++ {
			addr := data[pos : pos+int(addrLen)]
			var nexthop net.IP
			if isV4 {
				nexthop = net.IP(addr).To4()
			} else {
				nexthop = net.IP(addr).To16()
			}
			b.Nexthops = append(b.Nexthops, nexthop)

			// skip nexthop and 1byte place holder
			pos += int(addrLen + 1)
			ifidx := binary.BigEndian.Uint32(data[pos : pos+4])
			b.Ifindexs = append(b.Ifindexs, ifidx)
			pos += 4
		}
	}

	if b.Message&MESSAGE_DISTANCE > 0 {
		b.Distance = data[pos]
	}
	if b.Message&MESSAGE_METRIC > 0 {
		pos += 1
		b.Metric = binary.BigEndian.Uint32(data[pos : pos+4])
	}

	return nil
}

func (b *IPRouteBody) String() string {
	s := fmt.Sprintf("type: %s, flags: %s, message: %d, prefix: %s, length: %d, nexthop: %s, distance: %d, metric: %d",
		b.Type.String(), b.Flags.String(), b.Message, b.Prefix.String(), b.PrefixLength, b.Nexthops[0].String(), b.Distance, b.Metric)
	return s
}

type NexthopLookupBody struct {
	Api      API_TYPE
	Addr     net.IP
	Metric   uint32
	Nexthops []*Nexthop
}

type Nexthop struct {
	Ifname  string
	Ifindex uint32
	Type    NEXTHOP_FLAG
	Addr    net.IP
}

func (n *Nexthop) String() string {
	s := fmt.Sprintf("type: %s, addr: %s, ifindex: %d, ifname: %s", n.Type.String(), n.Addr.String(), n.Ifindex, n.Ifname)
	return s
}

func (b *NexthopLookupBody) Serialize() ([]byte, error) {

	isV4 := b.Api == IPV4_NEXTHOP_LOOKUP
	buf := make([]byte, 0)

	if isV4 {
		buf = append(buf, b.Addr.To4()...)
	} else {
		buf = append(buf, b.Addr.To16()...)
	}
	return buf, nil
}

func (b *NexthopLookupBody) DecodeFromBytes(data []byte) error {

	isV4 := b.Api == IPV4_NEXTHOP_LOOKUP
	var addrLen uint8 = net.IPv4len
	if !isV4 {
		addrLen = net.IPv6len
	}

	if len(data) < int(addrLen) {
		return fmt.Errorf("message length invalid")
	}

	buf := make([]byte, addrLen)
	copy(buf, data[0:addrLen])
	pos := addrLen

	if isV4 {
		b.Addr = net.IP(buf).To4()
	} else {
		b.Addr = net.IP(buf).To16()
	}

	if len(data[pos:]) > int(1+addrLen) {
		b.Metric = binary.BigEndian.Uint32(data[pos : pos+4])
		pos += 4
		nexthopNum := int(data[pos])
		b.Nexthops = []*Nexthop{}

		if nexthopNum > 0 {
			pos += 1
			for i := 0; i < nexthopNum; i++ {
				nh := &Nexthop{}
				nh.Type = NEXTHOP_FLAG(data[pos])
				pos += 1

				switch nh.Type {
				case NEXTHOP_IPV4, NEXTHOP_IPV6:
					b := make([]byte, addrLen)
					copy(b, data[pos:pos+addrLen])
					if isV4 {
						nh.Addr = net.IP(b).To4()
					} else {
						nh.Addr = net.IP(b).To16()
					}
					pos += addrLen

				case NEXTHOP_IPV4_IFINDEX, NEXTHOP_IPV6_IFINDEX, NEXTHOP_IPV6_IFNAME:
					b := make([]byte, addrLen)
					copy(b, data[pos:pos+addrLen])
					if isV4 {
						nh.Addr = net.IP(b).To4()
					} else {
						nh.Addr = net.IP(b).To16()
					}
					pos += addrLen
					nh.Ifindex = binary.BigEndian.Uint32(data[pos : pos+4])
					pos += 4

				case NEXTHOP_IFINDEX, NEXTHOP_IFNAME:
					nh.Ifindex = binary.BigEndian.Uint32(data[pos : pos+4])
					pos += 4
				}
				b.Nexthops = append(b.Nexthops, nh)
			}
		}
	}

	return nil
}

func (b *NexthopLookupBody) String() string {
	s := fmt.Sprintf("addr: %s, metric: %d", b.Addr, b.Metric)
	if len(b.Nexthops) > 0 {
		for _, nh := range b.Nexthops {
			s = s + fmt.Sprintf(", nexthop:{%s}", nh.String())
		}
	}
	return s
}

type ImportLookupBody struct {
	Api          API_TYPE
	PrefixLength uint8
	Prefix       net.IP
	Addr         net.IP
	Metric       uint32
	Nexthops     []*Nexthop
}

func (b *ImportLookupBody) Serialize() ([]byte, error) {
	buf := make([]byte, 1)
	buf[0] = b.PrefixLength
	buf = append(buf, b.Addr.To4()...)
	return buf, nil
}

func (b *ImportLookupBody) DecodeFromBytes(data []byte) error {

	var addrLen uint8 = net.IPv4len

	if len(data) < int(addrLen) {
		return fmt.Errorf("message length invalid")
	}

	buf := make([]byte, addrLen)
	copy(buf, data[0:addrLen])
	pos := addrLen

	b.Addr = net.IP(buf).To4()

	if len(data[pos:]) > int(1+addrLen) {
		b.Metric = binary.BigEndian.Uint32(data[pos : pos+4])
		pos += 4
		nexthopNum := int(data[pos])
		b.Nexthops = []*Nexthop{}
		if nexthopNum > 0 {
			pos += 1
			for i := 0; i < nexthopNum; i++ {
				nh := &Nexthop{}
				nh.Type = NEXTHOP_FLAG(data[pos])
				pos += 1

				switch nh.Type {
				case NEXTHOP_IPV4:
					b := make([]byte, addrLen)
					copy(b, data[pos:pos+addrLen])
					nh.Addr = net.IP(b).To4()
					pos += addrLen

				case NEXTHOP_IPV4_IFINDEX:
					b := make([]byte, addrLen)
					copy(b, data[pos:pos+addrLen])
					nh.Addr = net.IP(b).To4()
					pos += addrLen
					nh.Ifindex = binary.BigEndian.Uint32(data[pos : pos+4])
					pos += 4

				case NEXTHOP_IFINDEX, NEXTHOP_IFNAME:
					nh.Ifindex = binary.BigEndian.Uint32(data[pos : pos+4])
					pos += 4
				}
				b.Nexthops = append(b.Nexthops, nh)
			}
		}
	}

	return nil
}

func (b *ImportLookupBody) String() string {
	s := fmt.Sprintf("addr: %s, metric: %d", b.Addr, b.Metric)
	if len(b.Nexthops) > 0 {
		for _, nh := range b.Nexthops {
			s = s + fmt.Sprintf(", nexthop:{%s}", nh.String())
		}
	}
	return s
}

type Message struct {
	Header Header
	Body   Body
}

func (m *Message) Serialize() ([]byte, error) {
	var body []byte
	if m.Body != nil {
		var err error
		body, err = m.Body.Serialize()
		if err != nil {
			return nil, err
		}
	}
	m.Header.Len = uint16(len(body)) + HEADER_SIZE
	hdr, err := m.Header.Serialize()
	if err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}

func ParseMessage(hdr *Header, data []byte) (*Message, error) {
	m := &Message{Header: *hdr}

	switch m.Header.Command {
	case INTERFACE_ADD, INTERFACE_DELETE, INTERFACE_UP, INTERFACE_DOWN:
		m.Body = &InterfaceUpdateBody{}
	case INTERFACE_ADDRESS_ADD, INTERFACE_ADDRESS_DELETE:
		m.Body = &InterfaceAddressUpdateBody{}
	case ROUTER_ID_UPDATE:
		m.Body = &RouterIDUpdateBody{}
	case IPV4_ROUTE_ADD, IPV6_ROUTE_ADD, IPV4_ROUTE_DELETE, IPV6_ROUTE_DELETE:
		m.Body = &IPRouteBody{Api: m.Header.Command}
		log.Debugf("ipv4/v6 route add/delete message received: %v", data)
	case IPV4_NEXTHOP_LOOKUP, IPV6_NEXTHOP_LOOKUP:
		m.Body = &NexthopLookupBody{Api: m.Header.Command}
		log.Debugf("ipv4/v6 nexthop lookup received: %v", data)
	case IPV4_IMPORT_LOOKUP:
		m.Body = &ImportLookupBody{Api: m.Header.Command}
		log.Debugf("ipv4 import lookup message received: %v", data)
	default:
		return nil, fmt.Errorf("Unknown zapi command: %d", m.Header.Command)
	}
	err := m.Body.DecodeFromBytes(data)
	if err != nil {
		return nil, err
	}
	return m, nil
}
