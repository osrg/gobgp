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
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

func Test_Header(t *testing.T) {
	assert := assert.New(t)

	command := map[uint8]API_TYPE{
		2: IPV4_ROUTE_ADD,
		3: IPV4_ROUTE_ADD,
		4: FRR_IPV4_ROUTE_ADD,
		5: FRR_ZAPI5_IPV4_ROUTE_ADD,
		6: FRR_ZAPI6_ROUTE_ADD,
	}
	for v := MinZapiVer; v <= MaxZapiVer; v++ {
		//DecodeFromBytes
		buf := make([]byte, HeaderSize(v))
		binary.BigEndian.PutUint16(buf[0:], HeaderSize(v))
		buf[2] = HEADER_MARKER
		if v >= 4 {
			buf[2] = FRR_HEADER_MARKER
		}
		buf[3] = v
		switch v {
		case 2:
			binary.BigEndian.PutUint16(buf[4:], uint16(command[v]))
		case 3, 4:
			binary.BigEndian.PutUint16(buf[4:], uint16(0)) // vrf id
			binary.BigEndian.PutUint16(buf[6:], uint16(command[v]))
		case 5, 6:
			binary.BigEndian.PutUint32(buf[4:], uint32(0)) // vrf id
			binary.BigEndian.PutUint16(buf[8:], uint16(command[v]))
		}
		h := &Header{}
		err := h.DecodeFromBytes(buf)
		assert.Equal(nil, err)

		//Serialize
		buf, err = h.Serialize()
		assert.Equal(nil, err)
		h2 := &Header{}
		err = h2.DecodeFromBytes(buf)
		assert.Equal(nil, err)
		assert.Equal(h, h2)

		// header_size mismatch
		buf = make([]byte, HeaderSize(v)-1) // mismatch value
		binary.BigEndian.PutUint16(buf[0:], HeaderSize(v))
		buf[2] = HEADER_MARKER
		if v >= 4 {
			buf[2] = FRR_HEADER_MARKER
		}
		buf[3] = v
		h3 := &Header{}
		err = h3.DecodeFromBytes(buf)
		assert.NotEqual(nil, err, "err should be nil")
	}
}

func Test_InterfaceUpdateBody(t *testing.T) {
	assert := assert.New(t)

	addSize := map[uint8]uint8{2: 39, 3: 44, 4: 50, 5: 50, 6: 50}
	for v := MinZapiVer; v <= MaxZapiVer; v++ {
		//DecodeFromBytes
		buf := make([]byte, INTERFACE_NAMSIZ+addSize[v])
		pos := INTERFACE_NAMSIZ
		binary.BigEndian.PutUint32(buf[pos:], 1) //Index
		pos += 4
		buf[pos] = byte(INTERFACE_ACTIVE) //Status
		pos += 1
		binary.BigEndian.PutUint64(buf[pos:], 1)
		pos += 8 // flags
		if v > 3 {
			buf[pos] = byte(PTM_ENABLE_OFF) // ptm enable
			pos += 1
			buf[pos] = byte(PTM_STATUS_UNKNOWN) // ptm status
			pos += 1
		}
		binary.BigEndian.PutUint32(buf[pos:], 1)
		pos += 4 // metric
		if v > 3 {
			binary.BigEndian.PutUint32(buf[pos:], 10000)
			pos += 4 // speed
		}
		binary.BigEndian.PutUint32(buf[pos:], 1500)
		pos += 4 // MTU
		binary.BigEndian.PutUint32(buf[pos:], 1500)
		pos += 4 // MTU6
		binary.BigEndian.PutUint32(buf[pos:], 200)
		pos += 4 // bandwidth
		if v > 2 {
			binary.BigEndian.PutUint32(buf[pos:], uint32(LINK_TYPE_ETHER))
			pos += 4 // Linktype
		}
		binary.BigEndian.PutUint32(buf[pos:], 6)
		pos += 4 // hwaddr_len
		mac, _ := net.ParseMAC("01:23:45:67:89:ab")
		copy(buf[pos:pos+6], []byte(mac))
		pos += 6
		if v > 2 {
			buf[pos] = byte(0) // link param
			pos += 1
		}
		b := &InterfaceUpdateBody{}
		err := b.DecodeFromBytes(buf, v, "")
		assert.Equal(nil, err)
		assert.Equal("01:23:45:67:89:ab", b.HardwareAddr.String())
		buf = make([]byte, INTERFACE_NAMSIZ+32) //size mismatch
		b = &InterfaceUpdateBody{}
		err = b.DecodeFromBytes(buf, v, "")
		assert.NotEqual(nil, err)
	}
}

func Test_InterfaceAddressUpdateBody(t *testing.T) {
	assert := assert.New(t)

	for v := MinZapiVer; v <= MaxZapiVer; v++ {
		//DecodeFromBytes
		buf := make([]byte, 15)
		pos := 0
		binary.BigEndian.PutUint32(buf[pos:], 0) // index
		pos += 4
		buf[pos] = 0x01 // flags
		pos += 1
		buf[pos] = 0x2 // family
		pos += 1
		ip := net.ParseIP("192.168.100.1").To4() // prefix
		copy(buf[pos:pos+4], []byte(ip))
		pos += 4
		buf[pos] = byte(24) // prefix len
		pos += 1
		dst := net.ParseIP("192.168.100.255").To4() // destination
		copy(buf[pos:pos+4], []byte(dst))

		b := &InterfaceAddressUpdateBody{}
		err := b.DecodeFromBytes(buf, v, "")
		require.NoError(t, err)

		assert.Equal(uint32(0), b.Index)
		assert.Equal(INTERFACE_ADDRESS_FLAG(1), b.Flags)
		assert.Equal("192.168.100.1", b.Prefix.String())
		assert.Equal(uint8(24), b.Length)
		assert.Equal("192.168.100.255", b.Destination.String())

		// af invalid
		buf[5] = 0x4
		pos += 1
		b = &InterfaceAddressUpdateBody{}
		err = b.DecodeFromBytes(buf, v, "")
		assert.NotEqual(nil, err)
	}
}

func Test_RouterIDUpdateBody(t *testing.T) {
	assert := assert.New(t)

	for v := MinZapiVer; v <= MaxZapiVer; v++ {
		//DecodeFromBytes
		buf := make([]byte, 6)
		pos := 0
		buf[pos] = 0x2
		pos += 1
		ip := net.ParseIP("192.168.100.1").To4()
		copy(buf[pos:pos+4], []byte(ip))
		pos += 4
		buf[pos] = byte(32)

		b := &RouterIDUpdateBody{}
		err := b.DecodeFromBytes(buf, v, "")
		assert.Equal(nil, err)
		assert.Equal("192.168.100.1", b.Prefix.String())
		assert.Equal(uint8(32), b.Length)

		// af invalid
		buf[0] = 0x4
		pos += 1
		b = &RouterIDUpdateBody{}
		err = b.DecodeFromBytes(buf, v, "")
		assert.NotEqual(nil, err)
	}
}

func Test_IPRouteBody_IPv4(t *testing.T) {
	assert := assert.New(t)

	size := map[uint8]uint8{2: 26, 3: 26, 4: 31, 5: 38, 6: 38}
	command := map[uint8]API_TYPE{
		2: IPV4_ROUTE_ADD,
		3: IPV4_ROUTE_ADD,
		4: FRR_IPV4_ROUTE_ADD,
		5: FRR_ZAPI5_IPV4_ROUTE_ADD,
		6: FRR_ZAPI6_ROUTE_ADD,
	}
	routeType := map[uint8]ROUTE_TYPE{
		2: ROUTE_CONNECT,
		3: ROUTE_CONNECT,
		4: FRR_ROUTE_CONNECT,
		5: FRR_ZAPI5_ROUTE_CONNECT,
		6: FRR_ZAPI6_ROUTE_CONNECT,
	}
	message := map[uint8]MESSAGE_FLAG{
		2: MESSAGE_NEXTHOP | MESSAGE_IFINDEX | MESSAGE_DISTANCE | MESSAGE_METRIC | MESSAGE_MTU,
		3: MESSAGE_NEXTHOP | MESSAGE_IFINDEX | MESSAGE_DISTANCE | MESSAGE_METRIC | MESSAGE_MTU,
		4: FRR_MESSAGE_NEXTHOP | FRR_MESSAGE_IFINDEX | FRR_MESSAGE_DISTANCE | FRR_MESSAGE_METRIC | FRR_MESSAGE_MTU,
		5: FRR_ZAPI5_MESSAGE_NEXTHOP | FRR_ZAPI5_MESSAGE_DISTANCE | FRR_ZAPI5_MESSAGE_METRIC | FRR_ZAPI5_MESSAGE_MTU,
		6: FRR_ZAPI5_MESSAGE_NEXTHOP | FRR_ZAPI5_MESSAGE_DISTANCE | FRR_ZAPI5_MESSAGE_METRIC | FRR_ZAPI5_MESSAGE_MTU,
	}
	messageWithoutNexthop := map[uint8]MESSAGE_FLAG{
		2: MESSAGE_DISTANCE | MESSAGE_METRIC,
		3: MESSAGE_DISTANCE | MESSAGE_METRIC,
		4: FRR_MESSAGE_DISTANCE | FRR_MESSAGE_METRIC,
		5: FRR_ZAPI5_MESSAGE_DISTANCE | FRR_ZAPI5_MESSAGE_METRIC,
		6: FRR_ZAPI5_MESSAGE_DISTANCE | FRR_ZAPI5_MESSAGE_METRIC,
	}
	for v := MinZapiVer; v <= MaxZapiVer; v++ {
		//DecodeFromBytes IPV4_ROUTE
		buf := make([]byte, size[v])
		buf[0] = byte(routeType[v])
		pos := 1
		switch v {
		case 2, 3:
			buf[pos] = byte(FLAG_SELECTED)
			pos += 1
		case 4, 5, 6:
			binary.BigEndian.PutUint16(buf[pos:], 0) //Instance
			pos += 2
			binary.BigEndian.PutUint32(buf[pos:], uint32(FLAG_SELECTED))
			pos += 4
		}
		buf[pos] = byte(message[v])
		pos += 1
		if v > 4 {
			buf[pos] = byte(FRR_ZAPI5_SAFI_UNICAST) //SAFI
			pos += 1
			buf[pos] = byte(syscall.AF_INET) //Family
			pos += 1
		}
		buf[pos] = 24 // PrefixLen
		pos += 1
		ip := net.ParseIP("192.168.100.0").To4()
		copy(buf[pos:pos+3], []byte(ip))
		pos += 3
		switch v {
		case 2, 3, 4:
			buf[pos] = byte(1) // Number of Nexthops
			pos += 1
		case 5, 6:
			binary.BigEndian.PutUint16(buf[pos:], 1) // Number of Nexthops
			pos += 2
			binary.BigEndian.PutUint32(buf[pos:], 0) // vrfid
			pos += 4
			buf[pos] = byte(FRR_NEXTHOP_TYPE_IPV4_IFINDEX)
			pos += 1
		}
		nexthop := net.ParseIP("0.0.0.0").To4()
		copy(buf[pos:pos+4], []byte(nexthop))
		pos += 4
		if v < 5 {
			buf[pos] = 1 // Number of ifindex
			pos += 1
		}
		binary.BigEndian.PutUint32(buf[pos:], 1) // ifindex
		pos += 4
		buf[pos] = 0 // distance
		pos += 1
		binary.BigEndian.PutUint32(buf[pos:], 1) // metric
		pos += 4
		binary.BigEndian.PutUint32(buf[pos:], 1) // mtu
		pos += 4
		r := &IPRouteBody{Api: command[v]}
		err := r.DecodeFromBytes(buf, v, "")
		assert.Equal(nil, err)
		assert.Equal("192.168.100.0", r.Prefix.Prefix.String())
		assert.Equal(uint8(0x18), r.Prefix.PrefixLen)
		assert.Equal(message[v], r.Message)
		assert.Equal("0.0.0.0", r.Nexthops[0].Gate.String())
		switch v {
		case 2, 3, 4:
			assert.Equal(uint32(1), r.Nexthops[1].Ifindex)
		case 5, 6:
			assert.Equal(uint32(1), r.Nexthops[0].Ifindex)
		}
		assert.Equal(uint8(0), r.Distance)
		assert.Equal(uint32(1), r.Metric)
		assert.Equal(uint32(1), r.Mtu)

		//Serialize
		buf, err = r.Serialize(v, "")
		assert.Equal(nil, err)
		switch v {
		case 2, 3:
			assert.Equal([]byte{0x2, 0x10, byte(message[v])}, buf[0:3])
			pos = 3
		case 4, 5, 6:
			assert.Equal([]byte{0x2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, byte(message[v])}, buf[0:8])
			pos = 8
		}
		switch v {
		case 2, 3, 4:
			assert.Equal([]byte{0x0, 0x1}, buf[pos:pos+2]) // SAFI
			pos += 2
		case 5, 6:
			assert.Equal(byte(0x1), buf[pos]) // SAFI
			pos += 1
			assert.Equal(byte(0x2), buf[pos]) // Family
			pos += 1

		}
		assert.Equal(byte(24), buf[pos])
		pos += 1
		ip = net.ParseIP("192.168.100.0").To4()
		assert.Equal([]byte(ip)[0:3], buf[pos:pos+3])
		pos += 3
		switch v {
		case 2, 3, 4:
			assert.Equal(byte(2), buf[pos]) // number of nexthop
			pos += 1
		case 5, 6:
			assert.Equal([]byte{0x0, 0x1}, buf[pos:pos+2]) // number of nexthop
			pos += 2
			assert.Equal([]byte{0x0, 0x0, 0x0, 0x0}, buf[pos:pos+4]) // vrfid
			pos += 4
		}
		switch v {
		case 2, 3:
			assert.Equal(byte(NEXTHOP_TYPE_IPV4), buf[pos])
			assert.Equal(byte(NEXTHOP_TYPE_IFINDEX), buf[pos+5])
			pos += 10
		case 4:
			assert.Equal(byte(FRR_NEXTHOP_TYPE_IPV4), buf[pos])
			assert.Equal(byte(FRR_NEXTHOP_TYPE_IFINDEX), buf[pos+5])
			pos += 10
		case 5, 6:
			assert.Equal(byte(FRR_NEXTHOP_TYPE_IPV4_IFINDEX), buf[pos])
			pos += 9
		}
		assert.Equal(byte(0x0), buf[pos]) // distance
		bi := make([]byte, 4)
		binary.BigEndian.PutUint32(bi, 1)
		assert.Equal(bi, buf[pos+1:pos+5]) //metric
		assert.Equal(bi, buf[pos+5:pos+9]) //mtu

		// length invalid
		buf = make([]byte, size[v]-8)
		buf[0] = byte(routeType[v])
		pos = 1
		switch v {
		case 2, 3:
			buf[pos] = byte(FLAG_SELECTED)
			pos += 1
		case 4, 5, 6:
			binary.BigEndian.PutUint16(buf[pos:], 0) //Instance
			pos += 2
			binary.BigEndian.PutUint32(buf[pos:], uint32(FLAG_SELECTED))
			pos += 4
		}
		buf[pos] = byte(message[v])
		pos += 1
		if v > 4 {
			buf[pos] = byte(FRR_ZAPI5_SAFI_UNICAST) //SAFI
			pos += 1
			buf[pos] = byte(syscall.AF_INET) //Family
			pos += 1
		}
		buf[pos] = 24 // PrefixLen
		pos += 1
		ip = net.ParseIP("192.168.100.0").To4()
		copy(buf[pos:pos+3], []byte(ip))
		pos += 3
		switch v {
		case 2, 3, 4:
			buf[pos] = byte(1) // Number of Nexthops
			pos += 1
		case 5, 6:
			binary.BigEndian.PutUint16(buf[pos:], 1) // Number of Nexthops
			pos += 2
			binary.BigEndian.PutUint32(buf[pos:], 0) // vrfid
			pos += 4
			buf[pos] = byte(FRR_NEXTHOP_TYPE_IPV4_IFINDEX)
			pos += 1
		}
		nexthop = net.ParseIP("0.0.0.0").To4()
		copy(buf[pos:pos+4], []byte(nexthop))
		pos += 4
		if v < 5 {
			buf[pos] = 1 // Number of ifindex
			pos += 1
		}
		binary.BigEndian.PutUint32(buf[pos:], 1) // ifindex
		pos += 4

		r = &IPRouteBody{Api: command[v]}
		err = r.DecodeFromBytes(buf, v, "")
		switch v {
		case 2, 3, 4:
			assert.Equal("MESSAGE_METRIC message length invalid pos:14 rest:14", err.Error())
		case 5, 6:
			assert.Equal("MESSAGE_METRIC message length invalid pos:19 rest:19", err.Error())
		}

		// no nexthop
		switch v {
		case 2, 3, 4:
			buf = make([]byte, size[v]-14)
		case 5, 6:
			buf = make([]byte, size[v]-19)
		}
		buf[0] = byte(routeType[v])
		pos = 1
		switch v {
		case 2, 3:
			buf[pos] = byte(FLAG_SELECTED)
			pos += 1
		case 4, 5, 6:
			binary.BigEndian.PutUint16(buf[pos:], 0) //Instance
			pos += 2
			binary.BigEndian.PutUint32(buf[pos:], uint32(FLAG_SELECTED))
			pos += 4
		}
		buf[pos] = byte(messageWithoutNexthop[v])
		pos += 1
		if v > 4 {
			buf[pos] = byte(FRR_ZAPI5_SAFI_UNICAST) //SAFI
			pos += 1
			buf[pos] = byte(syscall.AF_INET) //Family
			pos += 1
		}
		buf[pos] = 24 // PrefixLen
		pos += 1
		ip = net.ParseIP("192.168.100.0").To4()
		copy(buf[pos:pos+3], []byte(ip))
		pos += 3
		buf[pos] = 1 // distance
		pos += 1
		binary.BigEndian.PutUint32(buf[pos:], 0) //metric
		pos += 4
		r = &IPRouteBody{Api: command[v]}
		err = r.DecodeFromBytes(buf, v, "")
		assert.Equal(nil, err)
	}
}

func Test_IPRouteBody_IPv6(t *testing.T) {
	assert := assert.New(t)
	size := map[uint8]uint8{2: 43, 3: 43, 4: 48, 5: 55, 6: 55}
	command := map[uint8]API_TYPE{
		2: IPV6_ROUTE_ADD,
		3: IPV6_ROUTE_ADD,
		4: FRR_IPV6_ROUTE_ADD,
		5: FRR_ZAPI5_IPV6_ROUTE_ADD,
		6: FRR_ZAPI6_ROUTE_ADD,
	}
	routeType := map[uint8]ROUTE_TYPE{
		2: ROUTE_CONNECT,
		3: ROUTE_CONNECT,
		4: FRR_ROUTE_CONNECT,
		5: FRR_ZAPI5_ROUTE_CONNECT,
		6: FRR_ZAPI6_ROUTE_CONNECT,
	}
	message := map[uint8]MESSAGE_FLAG{
		2: MESSAGE_NEXTHOP | MESSAGE_IFINDEX | MESSAGE_DISTANCE | MESSAGE_METRIC | MESSAGE_MTU,
		3: MESSAGE_NEXTHOP | MESSAGE_IFINDEX | MESSAGE_DISTANCE | MESSAGE_METRIC | MESSAGE_MTU,
		4: FRR_MESSAGE_NEXTHOP | FRR_MESSAGE_IFINDEX | FRR_MESSAGE_DISTANCE | FRR_MESSAGE_METRIC | FRR_MESSAGE_MTU,
		5: FRR_ZAPI5_MESSAGE_NEXTHOP | FRR_ZAPI5_MESSAGE_DISTANCE | FRR_ZAPI5_MESSAGE_METRIC | FRR_ZAPI5_MESSAGE_MTU,
		6: FRR_ZAPI5_MESSAGE_NEXTHOP | FRR_ZAPI5_MESSAGE_DISTANCE | FRR_ZAPI5_MESSAGE_METRIC | FRR_ZAPI5_MESSAGE_MTU,
	}
	nexthopType := map[uint8]NEXTHOP_TYPE{
		2: NEXTHOP_TYPE_IPV6,
		3: NEXTHOP_TYPE_IPV6,
		4: FRR_NEXTHOP_TYPE_IPV6,
		5: FRR_NEXTHOP_TYPE_IPV6_IFINDEX,
		6: FRR_NEXTHOP_TYPE_IPV6_IFINDEX,
	}
	messageWithoutNexthop := map[uint8]MESSAGE_FLAG{
		2: MESSAGE_DISTANCE | MESSAGE_METRIC,
		3: MESSAGE_DISTANCE | MESSAGE_METRIC,
		4: FRR_MESSAGE_DISTANCE | FRR_MESSAGE_METRIC,
		5: FRR_ZAPI5_MESSAGE_DISTANCE | FRR_ZAPI5_MESSAGE_METRIC,
		6: FRR_ZAPI5_MESSAGE_DISTANCE | FRR_ZAPI5_MESSAGE_METRIC,
	}
	for v := MinZapiVer; v <= MaxZapiVer; v++ {
		//DecodeFromBytes IPV6_ROUTE
		buf := make([]byte, size[v])
		buf[0] = byte(routeType[v])
		pos := 1
		switch v {
		case 2, 3:
			buf[pos] = byte(FLAG_SELECTED)
			pos += 1
		case 4, 5, 6:
			binary.BigEndian.PutUint16(buf[pos:], 0) //Instance
			pos += 2
			binary.BigEndian.PutUint32(buf[pos:], uint32(FLAG_SELECTED))
			pos += 4
		}
		buf[pos] = byte(message[v])
		pos += 1
		if v > 4 {
			buf[pos] = byte(FRR_ZAPI5_SAFI_UNICAST) //SAFI
			pos += 1
			buf[pos] = byte(syscall.AF_INET6) //Family
			pos += 1
		}
		buf[pos] = 64 // prefixLen
		pos += 1
		ip := net.ParseIP("2001:db8:0:f101::").To16()
		copy(buf[pos:pos+8], []byte(ip))
		pos += 8
		switch v {
		case 2, 3, 4:
			buf[pos] = byte(1) // Number of Nexthops
			pos += 1
		case 5, 6:
			binary.BigEndian.PutUint16(buf[pos:], 1) // Number of Nexthops
			pos += 2
			binary.BigEndian.PutUint32(buf[pos:], 0) // vrfid
			pos += 4
			buf[pos] = byte(FRR_NEXTHOP_TYPE_IPV6_IFINDEX)
			pos += 1
		}
		nexthop := net.ParseIP("::").To16()
		copy(buf[pos:pos+16], []byte(nexthop))
		pos += 16
		if v < 5 {
			buf[pos] = 1 // Number of ifindex
			pos += 1
		}
		binary.BigEndian.PutUint32(buf[pos:], 1) // ifindex
		pos += 4
		buf[pos] = 0 // distance
		pos += 1
		binary.BigEndian.PutUint32(buf[pos:], 1) // metric
		pos += 4
		binary.BigEndian.PutUint32(buf[pos:], 1) // mtu
		pos += 4
		r := &IPRouteBody{Api: command[v]}
		err := r.DecodeFromBytes(buf, v, "")
		assert.Equal(nil, err)
		assert.Equal("2001:db8:0:f101::", r.Prefix.Prefix.String())
		assert.Equal(uint8(64), r.Prefix.PrefixLen)
		assert.Equal(message[v], r.Message)
		assert.Equal("::", r.Nexthops[0].Gate.String())
		switch v {
		case 2, 3, 4:
			assert.Equal(uint32(1), r.Nexthops[1].Ifindex)
		case 5, 6:
			assert.Equal(uint32(1), r.Nexthops[0].Ifindex)
		}
		assert.Equal(uint8(0), r.Distance)
		assert.Equal(uint32(1), r.Metric)
		assert.Equal(uint32(1), r.Mtu)

		//Serialize
		buf, err = r.Serialize(v, "")
		assert.Equal(nil, err)
		switch v {
		case 2, 3:
			assert.Equal([]byte{0x2, 0x10, byte(message[v])}, buf[0:3])
			pos = 3
		case 4, 5, 6:
			assert.Equal([]byte{0x2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, byte(message[v])}, buf[0:8])
			pos = 8
		}
		switch v {
		case 2, 3, 4:
			assert.Equal([]byte{0x0, 0x1}, buf[pos:pos+2]) // SAFI
			pos += 2
		case 5, 6:
			assert.Equal(byte(0x1), buf[pos]) // SAFI
			pos += 1
			assert.Equal(byte(syscall.AF_INET6), buf[pos]) // Family
			pos += 1
		}
		assert.Equal(byte(64), buf[pos])
		pos += 1
		ip = net.ParseIP("2001:db8:0:f101::").To16()
		assert.Equal([]byte(ip)[0:8], buf[pos:pos+8])
		pos += 8
		switch v {
		case 2, 3, 4:
			assert.Equal(byte(2), buf[pos]) // number of nexthop
			pos += 1
		case 5, 6:
			assert.Equal([]byte{0x0, 0x1}, buf[pos:pos+2]) // number of nexthop
			pos += 2
			assert.Equal([]byte{0x0, 0x0, 0x0, 0x0}, buf[pos:pos+4]) // vrfid
			pos += 4
		}
		assert.Equal(byte(nexthopType[v]), buf[pos])
		pos += 1
		ip = net.ParseIP("::").To16()
		assert.Equal([]byte(ip), buf[pos:pos+16])
		pos += 16
		switch v { // Only Quagga (ZAPI version 2,3) and FRR 3.x (ZAPI version 4)
		case 2, 3:
			assert.Equal(byte(NEXTHOP_TYPE_IFINDEX), buf[pos])
			pos += 1
		case 4:
			assert.Equal(byte(FRR_NEXTHOP_TYPE_IFINDEX), buf[pos])
			pos += 1
		}
		bi := make([]byte, 4)
		binary.BigEndian.PutUint32(bi, 1)
		assert.Equal(bi, buf[pos:pos+4]) // ifindex
		pos += 4
		assert.Equal(byte(0x0), buf[pos])  // distance
		assert.Equal(bi, buf[pos+1:pos+5]) //metric
		assert.Equal(bi, buf[pos+5:pos+9]) //mtu

		// length invalid
		buf = make([]byte, size[v]+7)
		buf[0] = byte(routeType[v])
		pos = 1
		switch v {
		case 2, 3:
			buf[pos] = byte(FLAG_SELECTED)
			pos += 1
		case 4, 5, 6:
			binary.BigEndian.PutUint16(buf[pos:], 0) //Instance
			pos += 2
			binary.BigEndian.PutUint32(buf[pos:], uint32(FLAG_SELECTED))
			pos += 4
		}
		buf[pos] = byte(message[v])
		pos += 1
		if v > 4 {
			buf[pos] = byte(FRR_ZAPI5_SAFI_UNICAST) //SAFI
			pos += 1
			buf[pos] = byte(syscall.AF_INET6) //Family
			pos += 1
		}
		buf[pos] = 64 // prefixLen
		pos += 1
		ip = net.ParseIP("2001:db8:0:f101::").To16()
		copy(buf[pos:pos+8], []byte(ip))
		pos += 8
		switch v {
		case 2, 3, 4:
			buf[pos] = byte(1) // Number of Nexthops
			pos += 1
		case 5, 6:
			binary.BigEndian.PutUint16(buf[pos:], 1) // Number of Nexthops
			pos += 2
			binary.BigEndian.PutUint32(buf[pos:], 0) // vrfid
			pos += 4
			buf[pos] = byte(FRR_NEXTHOP_TYPE_IPV6_IFINDEX)
			pos += 1
		}
		nexthop = net.ParseIP("::").To16()
		copy(buf[pos:pos+16], []byte(nexthop))
		pos += 16
		if v < 5 {
			buf[pos] = 1 // Number of ifindex
			pos += 1
		}
		binary.BigEndian.PutUint32(buf[pos:], 1) // ifindex
		pos += 4

		r = &IPRouteBody{Api: command[v]}
		err = r.DecodeFromBytes(buf, v, "")
		switch v {
		case 2, 3, 4:
			assert.Equal("message length invalid pos:39 rest:46", err.Error())
		case 5, 6:
			assert.Equal("message length invalid pos:44 rest:51", err.Error())
		}

		// no nexthop
		switch v {
		case 2, 3, 4:
			buf = make([]byte, size[v]-32)
		case 5, 6:
			buf = make([]byte, size[v]-37)
		}
		buf[0] = byte(routeType[v])
		pos = 1
		switch v {
		case 2, 3:
			buf[pos] = byte(FLAG_SELECTED)
			pos += 1
		case 4, 5, 6:
			binary.BigEndian.PutUint16(buf[pos:], 0) //Instance
			pos += 2
			binary.BigEndian.PutUint32(buf[pos:], uint32(FLAG_SELECTED))
			pos += 4
		}
		buf[pos] = byte(messageWithoutNexthop[v])
		pos += 1
		if v > 4 {
			buf[pos] = byte(FRR_ZAPI5_SAFI_UNICAST) //SAFI
			pos += 1
			buf[pos] = byte(syscall.AF_INET) //Family
			pos += 1
		}
		buf[pos] = 16 // PrefixLen
		pos += 1
		ip = net.ParseIP("2501::").To16()
		copy(buf[pos:pos+2], []byte(ip))
		pos += 2
		buf[pos] = 1                             //distance
		binary.BigEndian.PutUint32(buf[pos:], 0) //metic
		r = &IPRouteBody{Api: command[v]}
		err = r.DecodeFromBytes(buf, v, "")
		assert.Equal(nil, err)
	}
}

// NexthopLookup exists in only quagga (zebra API version 2 and 3)
func Test_NexthopLookupBody(t *testing.T) {
	assert := assert.New(t)

	//ipv4
	//DecodeFromBytes
	pos := 0
	buf := make([]byte, 18)
	ip := net.ParseIP("192.168.50.0").To4()
	copy(buf[0:4], []byte(ip))
	pos += 4
	binary.BigEndian.PutUint32(buf[pos:], 10)
	pos += 4
	buf[pos] = byte(1)
	pos += 1
	buf[pos] = byte(4)
	pos += 1
	ip = net.ParseIP("172.16.1.101").To4()
	copy(buf[pos:pos+4], []byte(ip))
	pos += 4
	binary.BigEndian.PutUint32(buf[pos:], 3)

	b := &NexthopLookupBody{Api: IPV4_NEXTHOP_LOOKUP}
	err := b.DecodeFromBytes(buf, 2, "")
	assert.Equal(nil, err)
	assert.Equal("192.168.50.0", b.Addr.String())
	assert.Equal(uint32(10), b.Metric)
	assert.Equal(uint32(3), b.Nexthops[0].Ifindex)
	assert.Equal(NEXTHOP_TYPE(4), b.Nexthops[0].Type)
	assert.Equal("172.16.1.101", b.Nexthops[0].Gate.String())

	//Serialize
	buf, err = b.Serialize(2, "")
	ip = net.ParseIP("192.168.50.0").To4()
	assert.Equal(nil, err)
	assert.Equal([]byte(ip)[0:4], buf[0:4])

	// length invalid
	buf = make([]byte, 3)
	b = &NexthopLookupBody{Api: IPV4_NEXTHOP_LOOKUP}
	err = b.DecodeFromBytes(buf, 2, "")
	assert.NotEqual(nil, err)

	//ipv6
	//DecodeFromBytes
	pos = 0
	buf = make([]byte, 46)
	ip = net.ParseIP("2001:db8:0:f101::").To16()
	copy(buf[0:16], []byte(ip))
	pos += 16
	binary.BigEndian.PutUint32(buf[pos:], 10)
	pos += 4
	buf[pos] = byte(1)
	pos += 1
	buf[pos] = byte(7)
	pos += 1
	ip = net.ParseIP("2001:db8:0:1111::1").To16()
	copy(buf[pos:pos+16], []byte(ip))
	pos += 16
	binary.BigEndian.PutUint32(buf[pos:], 3)

	b = &NexthopLookupBody{Api: IPV6_NEXTHOP_LOOKUP}
	err = b.DecodeFromBytes(buf, 2, "")
	assert.Equal(nil, err)
	assert.Equal("2001:db8:0:f101::", b.Addr.String())
	assert.Equal(uint32(10), b.Metric)
	assert.Equal(uint32(3), b.Nexthops[0].Ifindex)
	assert.Equal(NEXTHOP_TYPE(7), b.Nexthops[0].Type)
	assert.Equal("2001:db8:0:1111::1", b.Nexthops[0].Gate.String())

	//Serialize
	buf, err = b.Serialize(2, "")
	ip = net.ParseIP("2001:db8:0:f101::").To16()
	assert.Equal(nil, err)
	assert.Equal([]byte(ip)[0:16], buf[0:16])

	// length invalid
	buf = make([]byte, 15)
	b = &NexthopLookupBody{Api: IPV6_NEXTHOP_LOOKUP}
	err = b.DecodeFromBytes(buf, 2, "")
	assert.NotEqual(nil, err)
}

// ImportLookup exists in only quagga (zebra API version 2 and 3)
func Test_ImportLookupBody(t *testing.T) {
	assert := assert.New(t)

	//DecodeFromBytes
	pos := 0
	buf := make([]byte, 18)
	ip := net.ParseIP("192.168.50.0").To4()
	copy(buf[0:4], []byte(ip))
	pos += 4
	binary.BigEndian.PutUint32(buf[pos:], 10)
	pos += 4
	buf[pos] = byte(1)
	pos += 1
	buf[pos] = byte(4)
	pos += 1
	ip = net.ParseIP("172.16.1.101").To4()
	copy(buf[pos:pos+4], []byte(ip))
	pos += 4
	binary.BigEndian.PutUint32(buf[pos:], 3)

	b := &ImportLookupBody{Api: IPV4_IMPORT_LOOKUP}
	err := b.DecodeFromBytes(buf, 2, "")
	assert.Equal(nil, err)
	assert.Equal("192.168.50.0", b.Addr.String())
	assert.Equal(uint32(10), b.Metric)
	assert.Equal(uint32(3), b.Nexthops[0].Ifindex)
	assert.Equal(NEXTHOP_TYPE(4), b.Nexthops[0].Type)
	assert.Equal("172.16.1.101", b.Nexthops[0].Gate.String())

	//Serialize
	b.PrefixLength = uint8(24)
	buf, err = b.Serialize(2, "")
	ip = net.ParseIP("192.168.50.0").To4()
	assert.Equal(nil, err)
	assert.Equal(uint8(24), buf[0])
	assert.Equal([]byte(ip)[0:4], buf[1:5])

	// length invalid
	buf = make([]byte, 3)
	b = &ImportLookupBody{Api: IPV4_IMPORT_LOOKUP}
	err = b.DecodeFromBytes(buf, 2, "")
	assert.NotEqual(nil, err)
}

func Test_NexthopRegisterBody(t *testing.T) {
	assert := assert.New(t)

	// Input binary
	bufIn := []byte{
		0x01, uint8(syscall.AF_INET >> 8), uint8(syscall.AF_INET & 0xff), 0x20, // connected(1 byte)=1, afi(2 bytes)=AF_INET, prefix_len(1 byte)=32
		0xc0, 0xa8, 0x01, 0x01, // prefix(4 bytes)="192.168.1.1"
		0x00, uint8(syscall.AF_INET6 >> 8), uint8(syscall.AF_INET6 & 0xff), 0x80, // connected(1 byte)=0, afi(2 bytes)=AF_INET6, prefix_len(1 byte)=128
		0x20, 0x01, 0x0d, 0xb8, // prefix(16 bytes)="2001:db8:1:1::1"
		0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
	}
	command := map[uint8]API_TYPE{
		2: NEXTHOP_REGISTER,
		3: NEXTHOP_REGISTER,
		4: FRR_NEXTHOP_REGISTER,
		5: FRR_ZAPI5_NEXTHOP_REGISTER,
		6: FRR_ZAPI6_NEXTHOP_REGISTER,
	}
	for v := MinZapiVer; v <= MaxZapiVer; v++ {
		// Test DecodeFromBytes()
		b := &NexthopRegisterBody{Api: command[v]}
		err := b.DecodeFromBytes(bufIn, v, "")
		assert.Nil(err)

		// Test decoded values
		assert.Equal(uint8(1), b.Nexthops[0].Connected)
		assert.Equal(uint16(syscall.AF_INET), b.Nexthops[0].Family)
		assert.Equal(net.ParseIP("192.168.1.1").To4(), b.Nexthops[0].Prefix)
		assert.Equal(uint8(0), b.Nexthops[1].Connected)
		assert.Equal(uint16(syscall.AF_INET6), b.Nexthops[1].Family)
		assert.Equal(net.ParseIP("2001:db8:1:1::1").To16(), b.Nexthops[1].Prefix)

		// Test Serialize()
		bufOut, err := b.Serialize(v, "")
		assert.Nil(err)

		// Test serialised value
		assert.Equal(bufIn, bufOut)
	}
}

func Test_NexthopUpdateBody(t *testing.T) {
	assert := assert.New(t)

	size := map[uint8]uint8{2: 21, 3: 21, 4: 22, 5: 26, 6: 26}
	command := map[uint8]API_TYPE{
		2: NEXTHOP_UPDATE,
		3: NEXTHOP_UPDATE,
		4: FRR_NEXTHOP_UPDATE,
		5: FRR_ZAPI5_NEXTHOP_UPDATE,
		6: FRR_ZAPI6_NEXTHOP_UPDATE,
	}
	nexthopType := map[uint8]NEXTHOP_TYPE{
		2: NEXTHOP_TYPE_IPV4_IFINDEX,
		3: NEXTHOP_TYPE_IPV4_IFINDEX,
		4: FRR_NEXTHOP_TYPE_IPV4_IFINDEX,
		5: FRR_NEXTHOP_TYPE_IPV4_IFINDEX,
		6: FRR_NEXTHOP_TYPE_IPV4_IFINDEX,
	}

	for v := MinZapiVer; v <= MaxZapiVer; v++ {
		// Input binary
		bufIn := make([]byte, size[v])
		// afi(2 bytes)=AF_INET, prefix_len(1 byte)=32, prefix(4 bytes)="192.168.1.1"
		copy(bufIn[0:7], []byte{0x00, 0x02, 0x20, 0xc0, 0xa8, 0x01, 0x01})
		pos := 7
		if v > 4 { // Type(1byte), Instance(2byte)
			copy(bufIn[pos:pos+3], []byte{byte(FRR_ZAPI5_ROUTE_CONNECT), 0x00, 0x00})
			pos += 3
		}
		if v > 3 { // Distance
			bufIn[pos] = 0
			pos += 1
		}
		// metric(4 bytes)=1, number of nexthops(1 byte)=1
		copy(bufIn[pos:pos+5], []byte{0x00, 0x00, 0x00, 0x01, 0x01})
		pos += 5
		bufIn[pos] = byte(nexthopType[v])
		pos += 1
		// nexthop_ip(4 bytes)="192.168.0.1", nexthop_ifindex(4 byte)=2
		copy(bufIn[pos:pos+8], []byte{0xc0, 0xa8, 0x01, 0x01, 0x00, 0x00, 0x00, 0x02})
		pos += 8
		if v > 4 {
			bufIn[pos] = byte(0) // label num
			pos += 1
		}

		// Test DecodeFromBytes()
		b := &NexthopUpdateBody{Api: command[v]}
		err := b.DecodeFromBytes(bufIn, v, "")
		assert.Nil(err)

		// Test decoded values
		assert.Equal(uint8(syscall.AF_INET), b.Prefix.Family)
		assert.Equal(net.ParseIP("192.168.1.1").To4(), b.Prefix.Prefix)
		assert.Equal(uint32(1), b.Metric)
		nexthop := Nexthop{
			Type:    nexthopType[v],
			Gate:    net.ParseIP("192.168.1.1").To4(),
			Ifindex: uint32(2),
		}
		assert.Equal(1, len(b.Nexthops))
		assert.Equal(nexthop, b.Nexthops[0])
	}
}

func Test_GetLabelChunkBody(t *testing.T) {
	assert := assert.New(t)

	// Test only with ZAPI version 5 and 6
	routeType := map[uint8]ROUTE_TYPE{5: FRR_ZAPI5_ROUTE_BGP, 6: FRR_ZAPI6_ROUTE_BGP}
	for v := uint8(5); v <= MaxZapiVer; v++ {
		//DecodeFromBytes
		buf := make([]byte, 12)
		buf[0] = byte(routeType[v])             // Route Type
		binary.BigEndian.PutUint16(buf[1:], 0)  //Instance
		buf[3] = 0                              //Keep
		binary.BigEndian.PutUint32(buf[4:], 80) //Start
		binary.BigEndian.PutUint32(buf[8:], 89) //End

		b := &GetLabelChunkBody{}
		err := b.DecodeFromBytes(buf, v, "")
		assert.Equal(nil, err)

		//Serialize
		b.ChunkSize = 10
		buf, err = b.Serialize(v, "")
		assert.Equal(nil, err)
		assert.Equal(byte(routeType[v]), buf[0])
		bi := make([]byte, 4)
		binary.BigEndian.PutUint32(bi, 10)
		assert.Equal(bi, buf[4:8]) // Chunksize
	}
}

func Test_VrfLabelBody(t *testing.T) {
	assert := assert.New(t)
	// Test only with ZAPI version 5 and 6
	for v := uint8(5); v <= MaxZapiVer; v++ {
		//DecodeFromBytes
		bufIn := make([]byte, 6)
		binary.BigEndian.PutUint32(bufIn[0:], 80) //label
		bufIn[4] = byte(AFI_IP)
		bufIn[5] = byte(LSP_BGP)
		b := &VrfLabelBody{}
		err := b.DecodeFromBytes(bufIn, v, "")
		assert.Equal(nil, err)
		//Serialize
		var bufOut []byte
		bufOut, err = b.Serialize(v, "")
		assert.Equal(nil, err)
		assert.Equal(bufIn, bufOut)
	}
}
