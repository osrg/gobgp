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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Header(t *testing.T) {
	assert := assert.New(t)

	command := map[uint8]APIType{
		2: zapi3IPv4RouteAdd,
		3: zapi3IPv4RouteAdd,
		4: zapi4IPv4RouteAdd,
		5: zapi6Frr7RouteAdd,
		6: zapi6Frr7RouteAdd,
	}
	for v := MinZapiVer; v <= MaxZapiVer; v++ {
		//decodeFromBytes
		buf := make([]byte, HeaderSize(v))
		binary.BigEndian.PutUint16(buf[0:], HeaderSize(v))
		buf[2] = headerMarker
		if v >= 4 {
			buf[2] = frrHeaderMarker
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
		err := h.decodeFromBytes(buf)
		assert.Equal(nil, err)

		//serialize
		buf, err = h.serialize()
		assert.Equal(nil, err)
		h2 := &Header{}
		err = h2.decodeFromBytes(buf)
		assert.Equal(nil, err)
		assert.Equal(h, h2)

		// header_size mismatch
		buf = make([]byte, HeaderSize(v)-1) // mismatch value
		binary.BigEndian.PutUint16(buf[0:], HeaderSize(v))
		buf[2] = headerMarker
		if v >= 4 {
			buf[2] = frrHeaderMarker
		}
		buf[3] = v
		h3 := &Header{}
		err = h3.decodeFromBytes(buf)
		assert.NotEqual(nil, err, "err should be nil")
	}
}

func Test_interfaceUpdateBody(t *testing.T) {
	assert := assert.New(t)

	addSize := map[uint8]uint8{2: 39, 3: 44, 4: 50, 5: 50, 6: 54}
	for v := MinZapiVer; v <= MaxZapiVer; v++ {
		//decodeFromBytes
		buf := make([]byte, interfaceNameSize+addSize[v])
		pos := interfaceNameSize
		binary.BigEndian.PutUint32(buf[pos:], 1) //Index
		pos += 4
		buf[pos] = byte(interfaceActive) //Status
		pos++
		binary.BigEndian.PutUint64(buf[pos:], 1)
		pos += 8 // flags
		if v > 3 {
			buf[pos] = byte(ptmEnableOff) // ptm enable
			pos++
			buf[pos] = byte(ptmStatusUnknown) // ptm status
			pos++
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
		pos += 4    // bandwidth
		if v == 6 { // "frr7.2", ""
			binary.BigEndian.PutUint32(buf[pos:], 1)
			pos += 4 // link Ifindex
		}
		if v > 2 {
			binary.BigEndian.PutUint32(buf[pos:], uint32(linkTypeEther))
			pos += 4 // Linktype
		}
		binary.BigEndian.PutUint32(buf[pos:], 6)
		pos += 4 // hwaddr_len
		mac, _ := net.ParseMAC("01:23:45:67:89:ab")
		copy(buf[pos:pos+6], []byte(mac))
		pos += 6
		if v > 2 {
			buf[pos] = byte(0) // link param
			pos++
		}
		b := &interfaceUpdateBody{}
		software := NewSoftware(v, "")
		err := b.decodeFromBytes(buf, v, software)
		assert.Equal(nil, err)
		assert.Equal("01:23:45:67:89:ab", b.hardwareAddr.String())
		buf = make([]byte, interfaceNameSize+32) //size mismatch
		b = &interfaceUpdateBody{}
		err = b.decodeFromBytes(buf, v, software)
		assert.NotEqual(nil, err)
	}
}

func Test_interfaceAddressUpdateBody(t *testing.T) {
	assert := assert.New(t)

	for v := MinZapiVer; v <= MaxZapiVer; v++ {
		//decodeFromBytes
		buf := make([]byte, 15)
		pos := 0
		binary.BigEndian.PutUint32(buf[pos:], 0) // index
		pos += 4
		buf[pos] = 0x01 // flags
		pos++
		buf[pos] = 0x2 // family
		pos++
		ip := net.ParseIP("192.168.100.1").To4() // prefix
		copy(buf[pos:pos+4], []byte(ip))
		pos += 4
		buf[pos] = byte(24) // prefix len
		pos++
		dst := net.ParseIP("192.168.100.255").To4() // destination
		copy(buf[pos:pos+4], []byte(dst))

		b := &interfaceAddressUpdateBody{}
		software := NewSoftware(v, "")
		err := b.decodeFromBytes(buf, v, software)
		require.NoError(t, err)

		assert.Equal(uint32(0), b.index)
		assert.Equal(interfaceAddressFlag(1), b.flags)
		assert.Equal("192.168.100.1", b.prefix.String())
		assert.Equal(uint8(24), b.length)
		assert.Equal("192.168.100.255", b.destination.String())

		// af invalid
		buf[5] = 0x4
		pos++
		b = &interfaceAddressUpdateBody{}
		err = b.decodeFromBytes(buf, v, software)
		assert.NotEqual(nil, err)
	}
}

func Test_routerIDUpdateBody(t *testing.T) {
	assert := assert.New(t)

	for v := MinZapiVer; v <= MaxZapiVer; v++ {
		//decodeFromBytes
		buf := make([]byte, 6)
		pos := 0
		buf[pos] = 0x2
		pos++
		ip := net.ParseIP("192.168.100.1").To4()
		copy(buf[pos:pos+4], []byte(ip))
		pos += 4
		buf[pos] = byte(32)

		b := &routerIDUpdateBody{}
		software := NewSoftware(v, "")
		err := b.decodeFromBytes(buf, v, software)
		assert.Equal(nil, err)
		assert.Equal("192.168.100.1", b.prefix.String())
		assert.Equal(uint8(32), b.length)

		// af invalid
		buf[0] = 0x4
		pos++
		b = &routerIDUpdateBody{}
		err = b.decodeFromBytes(buf, v, software)
		assert.NotEqual(nil, err)
	}
}

func Test_IPRouteBody_IPv4(t *testing.T) {
	assert := assert.New(t)

	size := map[uint8]uint8{2: 26, 3: 26, 4: 31, 5: 38, 6: 42}
	command := map[uint8]APIType{
		2: zapi3IPv4RouteAdd,
		3: zapi3IPv4RouteAdd,
		4: zapi4IPv4RouteAdd,
		5: zapi6Frr7RouteAdd,
		6: RouteAdd,
	}
	routeType := routeConnect
	message := map[uint8]MessageFlag{
		2: MessageNexthop | messageIFIndex | zapi4MessageDistance | zapi4MessageMetric | zapi3MessageMTU,
		3: MessageNexthop | messageIFIndex | zapi4MessageDistance | zapi4MessageMetric | zapi3MessageMTU,
		4: MessageNexthop | messageIFIndex | zapi4MessageDistance | zapi4MessageMetric | zapi4MessageMTU,
		5: MessageNexthop | MessageDistance | MessageMetric | MessageMTU,
		6: MessageNexthop | MessageDistance | MessageMetric | MessageMTU,
	}
	messageWithoutNexthop := map[uint8]MessageFlag{
		2: zapi4MessageDistance | zapi4MessageMetric,
		3: zapi4MessageDistance | zapi4MessageMetric,
		4: zapi4MessageDistance | zapi4MessageMetric,
		5: MessageDistance | MessageMetric,
		6: MessageDistance | MessageMetric,
	}
	for v := MinZapiVer; v <= MaxZapiVer; v++ {
		//decodeFromBytes IPV4_ROUTE
		buf := make([]byte, size[v])
		buf[0] = byte(routeType)
		pos := 1
		software := NewSoftware(v, "")
		switch v {
		case 2, 3:
			buf[pos] = byte(FlagSelected.ToEach(v, software))
			pos++
		case 4, 5, 6:
			binary.BigEndian.PutUint16(buf[pos:], 0) //Instance
			pos += 2
			binary.BigEndian.PutUint32(buf[pos:], uint32(FlagSelected.ToEach(v, software)))
			pos += 4
		}
		if v == 6 {
			binary.BigEndian.PutUint32(buf[pos:], uint32(message[v])) // frr7.5: 32bit
			pos += 4
		} else {
			buf[pos] = uint8(message[v]) // before frr7.4: 8bit
			pos++
		}
		if v > 4 {
			buf[pos] = byte(SafiUnicast) //SAFI
			pos++
			buf[pos] = byte(syscall.AF_INET) //Family
			pos++
		}
		buf[pos] = 24 // PrefixLen
		pos++
		ip := net.ParseIP("192.168.100.0").To4()
		copy(buf[pos:pos+3], []byte(ip))
		pos += 3
		switch v {
		case 2, 3, 4:
			buf[pos] = byte(1) // Number of Nexthops
			pos++
		case 5, 6:
			binary.BigEndian.PutUint16(buf[pos:], 1) // Number of Nexthops
			pos += 2
			binary.BigEndian.PutUint32(buf[pos:], 0) // vrfid
			pos += 4
			buf[pos] = byte(nexthopTypeIPv4IFIndex)
			pos++
		}
		if v == 6 { //onlink (frr7,1, 7.2, 7.3, 7.4)
			buf[pos] = 1
			pos++
		}
		nexthop := net.ParseIP("0.0.0.0").To4()
		copy(buf[pos:pos+4], []byte(nexthop))
		pos += 4
		if v < 5 {
			buf[pos] = 1 // Number of Ifindex
			pos++
		}
		binary.BigEndian.PutUint32(buf[pos:], 1) // Ifindex
		pos += 4
		buf[pos] = 0 // distance
		pos++
		binary.BigEndian.PutUint32(buf[pos:], 1) // metric
		pos += 4
		binary.BigEndian.PutUint32(buf[pos:], 1) // mtu
		pos += 4
		r := &IPRouteBody{API: command[v]}
		err := r.decodeFromBytes(buf, v, software)
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

		//serialize
		buf, err = r.serialize(v, software)
		assert.Equal(nil, err)
		switch v {
		case 2, 3:
			assert.Equal([]byte{0x2, 0x10, byte(message[v])}, buf[0:3])
			pos = 3
		case 4, 5:
			tmpFlag := byte(0xff & FlagSelected.ToEach(v, software))
			assert.Equal([]byte{0x2, 0x00, 0x00, 0x00, 0x00, 0x00, tmpFlag, byte(message[v])}, buf[0:8])
			pos = 8
		case 6: // frr 7.5: MessageFlag: 32bit
			tmpFlag := byte(0xff & FlagSelected.ToEach(v, software))
			assert.Equal([]byte{0x2, 0x00, 0x00, 0x00, 0x00, 0x00, tmpFlag, 0x00, 0x00, 0x00, byte(message[v])}, buf[0:11])
			pos = 11
		}
		switch v {
		case 2, 3, 4:
			assert.Equal([]byte{0x0, 0x1}, buf[pos:pos+2]) // SAFI
			pos += 2
		case 5, 6:
			assert.Equal(byte(0x1), buf[pos]) // SAFI
			pos++
			assert.Equal(byte(0x2), buf[pos]) // Family
			pos++

		}

		assert.Equal(byte(24), buf[pos])
		pos++
		ip = net.ParseIP("192.168.100.0").To4()
		assert.Equal([]byte(ip)[0:3], buf[pos:pos+3])
		pos += 3
		switch v {
		case 2, 3, 4:
			assert.Equal(byte(2), buf[pos]) // number of nexthop
			pos++
		case 5, 6:
			assert.Equal([]byte{0x0, 0x1}, buf[pos:pos+2]) // number of nexthop
			pos += 2
			assert.Equal([]byte{0x0, 0x0, 0x0, 0x0}, buf[pos:pos+4]) // vrfid
			pos += 4
		}
		switch v {
		case 2, 3:
			assert.Equal(byte(backwardNexthopTypeIPv4), buf[pos])
			assert.Equal(byte(nexthopTypeIFIndex), buf[pos+5])
			pos += 10
		case 4:
			assert.Equal(byte(nexthopTypeIPv4), buf[pos])
			assert.Equal(byte(nexthopTypeIFIndex), buf[pos+5])
			pos += 10
		case 5, 6:
			assert.Equal(byte(nexthopTypeIPv4IFIndex), buf[pos])
			pos += 9
		}
		if v == 6 { //onlink (frr7,1, 7.2, 7.3, 7.4)
			assert.Equal(byte(0x1), buf[pos])
			pos++
		}
		assert.Equal(byte(0x0), buf[pos]) // distance
		bi := make([]byte, 4)
		binary.BigEndian.PutUint32(bi, 1)
		assert.Equal(bi, buf[pos+1:pos+5]) //metric
		assert.Equal(bi, buf[pos+5:pos+9]) //mtu

		// length invalid
		buf = make([]byte, size[v]-8)
		buf[0] = byte(routeConnect)
		pos = 1
		switch v {
		case 2, 3:
			buf[pos] = byte(FlagSelected.ToEach(v, software))
			pos++
		case 4, 5, 6:
			binary.BigEndian.PutUint16(buf[pos:], 0) //Instance
			pos += 2
			binary.BigEndian.PutUint32(buf[pos:], uint32(FlagSelected.ToEach(v, software)))
			pos += 4
		}
		if v == 6 {
			binary.BigEndian.PutUint32(buf[pos:], uint32(message[v])) // frr7.5: 32bit
			pos += 4
		} else {
			buf[pos] = uint8(message[v]) // before frr7.4: 8bit
			pos++
		}

		if v > 4 {
			buf[pos] = byte(SafiUnicast) //SAFI
			pos++
			buf[pos] = byte(syscall.AF_INET) //Family
			pos++
		}
		buf[pos] = 24 // PrefixLen
		pos++
		ip = net.ParseIP("192.168.100.0").To4()
		copy(buf[pos:pos+3], []byte(ip))
		pos += 3
		switch v {
		case 2, 3, 4:
			buf[pos] = byte(1) // Number of Nexthops
			pos++
		case 5, 6:
			binary.BigEndian.PutUint16(buf[pos:], 1) // Number of Nexthops
			pos += 2
			binary.BigEndian.PutUint32(buf[pos:], 0) // vrfid
			pos += 4
			buf[pos] = byte(nexthopTypeIPv4IFIndex)
			pos++
		}
		if v == 6 { //onlink (frr7,1, 7.2, 7.3, 7.4)
			buf[pos] = 1
			pos++
		}
		nexthop = net.ParseIP("0.0.0.0").To4()
		copy(buf[pos:pos+4], []byte(nexthop))
		pos += 4
		if v < 5 {
			buf[pos] = 1 // Number of Ifindex
			pos++
		}
		binary.BigEndian.PutUint32(buf[pos:], 1) // Ifindex
		pos += 4

		r = &IPRouteBody{API: command[v]}
		err = r.decodeFromBytes(buf, v, software)
		switch v {
		case 2, 3, 4:
			assert.Equal("MessageMetric message length invalid pos:14 rest:14", err.Error())
		case 5:
			assert.Equal("MessageMetric message length invalid pos:19 rest:19", err.Error())
		case 6:
			assert.Equal("MessageMetric message length invalid pos:20 rest:20", err.Error())
		}

		// no nexthop
		switch v {
		case 2, 3, 4:
			buf = make([]byte, size[v]-14)
		case 5:
			buf = make([]byte, size[v]-19)
		case 6:
			buf = make([]byte, size[v]-20)
		}
		buf[0] = byte(routeType)
		pos = 1
		switch v {
		case 2, 3:
			buf[pos] = byte(FlagSelected.ToEach(v, software))
			pos++
		case 4, 5, 6:
			binary.BigEndian.PutUint16(buf[pos:], 0) //Instance
			pos += 2
			binary.BigEndian.PutUint32(buf[pos:], uint32(FlagSelected.ToEach(v, software)))
			pos += 4
		}

		if v == 6 {
			binary.BigEndian.PutUint32(buf[pos:], uint32(messageWithoutNexthop[v])) // frr7.5: 32bit
			pos += 4
		} else {
			buf[pos] = byte(messageWithoutNexthop[v]) // before frr7.4: 8bit
			pos++
		}

		if v > 4 {
			buf[pos] = byte(SafiUnicast) //SAFI
			pos++
			buf[pos] = byte(syscall.AF_INET) //Family
			pos++
		}
		buf[pos] = 24 // PrefixLen
		pos++
		ip = net.ParseIP("192.168.100.0").To4()
		copy(buf[pos:pos+3], []byte(ip))
		pos += 3
		buf[pos] = 1 // distance
		pos++
		binary.BigEndian.PutUint32(buf[pos:], 0) //metric
		pos += 4
		r = &IPRouteBody{API: command[v]}
		err = r.decodeFromBytes(buf, v, software)
		assert.Equal(nil, err)
	}
}

func Test_IPRouteBody_IPv6(t *testing.T) {
	assert := assert.New(t)
	size := map[uint8]uint8{2: 43, 3: 43, 4: 48, 5: 55, 6: 59}
	command := map[uint8]APIType{
		2: zapi3IPv6RouteAdd,
		3: zapi3IPv6RouteAdd,
		4: zapi4IPv6RouteAdd,
		5: zapi6Frr7RouteAdd,
		6: zapi6Frr7RouteAdd,
	}
	routeType := routeConnect
	message := map[uint8]MessageFlag{
		2: MessageNexthop | messageIFIndex | zapi4MessageDistance | zapi4MessageMetric | zapi3MessageMTU,
		3: MessageNexthop | messageIFIndex | zapi4MessageDistance | zapi4MessageMetric | zapi3MessageMTU,
		4: MessageNexthop | messageIFIndex | zapi4MessageDistance | zapi4MessageMetric | zapi4MessageMTU,
		5: MessageNexthop | MessageDistance | MessageMetric | MessageMTU,
		6: MessageNexthop | MessageDistance | MessageMetric | MessageMTU,
	}
	nexthopType := map[uint8]nexthopType{
		2: backwardNexthopTypeIPv6,
		3: backwardNexthopTypeIPv6,
		4: nexthopTypeIPv6,
		5: nexthopTypeIPv6IFIndex,
		6: nexthopTypeIPv6IFIndex,
	}
	messageWithoutNexthop := map[uint8]MessageFlag{
		2: zapi4MessageDistance | zapi4MessageMetric,
		3: zapi4MessageDistance | zapi4MessageMetric,
		4: zapi4MessageDistance | zapi4MessageMetric,
		5: MessageDistance | MessageMetric,
		6: MessageDistance | MessageMetric,
	}
	for v := MinZapiVer; v <= MaxZapiVer; v++ {
		//decodeFromBytes IPV6_ROUTE
		buf := make([]byte, size[v])
		buf[0] = byte(routeType)
		pos := 1
		software := NewSoftware(v, "")
		switch v {
		case 2, 3:
			buf[pos] = byte(FlagSelected.ToEach(v, software))
			pos++
		case 4, 5, 6:
			binary.BigEndian.PutUint16(buf[pos:], 0) //Instance
			pos += 2
			binary.BigEndian.PutUint32(buf[pos:], uint32(FlagSelected.ToEach(v, software)))
			pos += 4
		}

		if v == 6 {
			binary.BigEndian.PutUint32(buf[pos:], uint32(message[v])) // frr7.5: 32bit
			pos += 4
		} else {
			buf[pos] = uint8(message[v]) // before frr7.4: 8bit
			pos++
		}

		if v > 4 {
			buf[pos] = byte(SafiUnicast) //SAFI
			pos++
			buf[pos] = byte(syscall.AF_INET6) //Family
			pos++
		}
		buf[pos] = 64 // prefixLen
		pos++
		ip := net.ParseIP("2001:db8:0:f101::").To16()
		copy(buf[pos:pos+8], []byte(ip))
		pos += 8
		switch v {
		case 2, 3, 4:
			buf[pos] = byte(1) // Number of Nexthops
			pos++
		case 5, 6:
			binary.BigEndian.PutUint16(buf[pos:], 1) // Number of Nexthops
			pos += 2
			binary.BigEndian.PutUint32(buf[pos:], 0) // vrfid
			pos += 4
			buf[pos] = byte(nexthopTypeIPv6IFIndex)
			pos++
		}
		if v == 6 { //onlink (frr7,1, 7.2, 7.3, 7.4)
			buf[pos] = 1
			pos++
		}
		nexthop := net.ParseIP("::").To16()
		copy(buf[pos:pos+16], []byte(nexthop))
		pos += 16
		if v < 5 {
			buf[pos] = 1 // Number of Ifindex
			pos++
		}
		binary.BigEndian.PutUint32(buf[pos:], 1) // Ifindex
		pos += 4
		buf[pos] = 0 // distance
		pos++
		binary.BigEndian.PutUint32(buf[pos:], 1) // metric
		pos += 4
		binary.BigEndian.PutUint32(buf[pos:], 1) // mtu
		pos += 4
		r := &IPRouteBody{API: command[v]}
		err := r.decodeFromBytes(buf, v, software)
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

		//serialize
		buf, err = r.serialize(v, software)
		assert.Equal(nil, err)
		switch v {
		case 2, 3:
			assert.Equal([]byte{0x2, 0x10, byte(message[v])}, buf[0:3])
			pos = 3
		case 4, 5:
			tmpFlag := byte(0xff & FlagSelected.ToEach(v, software))
			assert.Equal([]byte{0x2, 0x00, 0x00, 0x00, 0x00, 0x00, tmpFlag, byte(message[v])}, buf[0:8])
			pos = 8
		case 6: // frr 7.5: MessageFlag: 32bit
			tmpFlag := byte(0xff & FlagSelected.ToEach(v, software))
			assert.Equal([]byte{0x2, 0x00, 0x00, 0x00, 0x00, 0x00, tmpFlag, 0x00, 0x00, 0x00, byte(message[v])}, buf[0:11])
			pos = 11
		}
		switch v {
		case 2, 3, 4:
			assert.Equal([]byte{0x0, 0x1}, buf[pos:pos+2]) // SAFI
			pos += 2
		case 5, 6:
			assert.Equal(byte(0x1), buf[pos]) // SAFI
			pos++
			assert.Equal(byte(syscall.AF_INET6), buf[pos]) // Family
			pos++
		}
		assert.Equal(byte(64), buf[pos])
		pos++
		ip = net.ParseIP("2001:db8:0:f101::").To16()
		assert.Equal([]byte(ip)[0:8], buf[pos:pos+8])
		pos += 8
		switch v {
		case 2, 3, 4:
			assert.Equal(byte(2), buf[pos]) // number of nexthop
			pos++
		case 5, 6:
			assert.Equal([]byte{0x0, 0x1}, buf[pos:pos+2]) // number of nexthop
			pos += 2
			assert.Equal([]byte{0x0, 0x0, 0x0, 0x0}, buf[pos:pos+4]) // vrfid
			pos += 4
		}
		assert.Equal(byte(nexthopType[v]), buf[pos])
		pos++
		if v == 6 { //onlink (frr7,1, 7.2, 7.3, 7.4)
			assert.Equal(byte(0x1), buf[pos])
			pos++
		}
		ip = net.ParseIP("::").To16()
		assert.Equal([]byte(ip), buf[pos:pos+16])
		pos += 16
		switch v { // Only Quagga (ZAPI version 2,3) and FRR 3.x (ZAPI version 4)
		case 2, 3:
			assert.Equal(byte(nexthopTypeIFIndex), buf[pos])
			pos++
		case 4:
			assert.Equal(byte(nexthopTypeIFIndex), buf[pos])
			pos++
		}
		bi := make([]byte, 4)
		binary.BigEndian.PutUint32(bi, 1)
		assert.Equal(bi, buf[pos:pos+4]) // Ifindex
		pos += 4
		assert.Equal(byte(0x0), buf[pos])  // distance
		assert.Equal(bi, buf[pos+1:pos+5]) //metric
		assert.Equal(bi, buf[pos+5:pos+9]) //mtu

		// length invalid
		buf = make([]byte, size[v]+7)
		buf[0] = byte(routeType)
		pos = 1
		switch v {
		case 2, 3:
			buf[pos] = byte(FlagSelected.ToEach(v, software))
			pos++
		case 4, 5, 6:
			binary.BigEndian.PutUint16(buf[pos:], 0) //Instance
			pos += 2
			binary.BigEndian.PutUint32(buf[pos:], uint32(FlagSelected.ToEach(v, software)))
			pos += 4
		}

		if v == 6 {
			binary.BigEndian.PutUint32(buf[pos:], uint32(message[v])) // frr7.5: 32bit
			pos += 4
		} else {
			buf[pos] = uint8(message[v]) // before frr7.4: 8bit
			pos++
		}

		if v > 4 {
			buf[pos] = byte(SafiUnicast) //SAFI
			pos++
			buf[pos] = byte(syscall.AF_INET6) //Family
			pos++
		}
		buf[pos] = 64 // prefixLen
		pos++
		ip = net.ParseIP("2001:db8:0:f101::").To16()
		copy(buf[pos:pos+8], []byte(ip))
		pos += 8
		switch v {
		case 2, 3, 4:
			buf[pos] = byte(1) // Number of Nexthops
			pos++
		case 5, 6:
			binary.BigEndian.PutUint16(buf[pos:], 1) // Number of Nexthops
			pos += 2
			binary.BigEndian.PutUint32(buf[pos:], 0) // vrfid
			pos += 4
			buf[pos] = byte(nexthopTypeIPv6IFIndex)
			pos++
		}
		if v == 6 { //onlink (frr7,1, 7.2, 7.3, 7.4)
			buf[pos] = 1
			pos++
		}
		nexthop = net.ParseIP("::").To16()
		copy(buf[pos:pos+16], []byte(nexthop))
		pos += 16
		if v < 5 {
			buf[pos] = 1 // Number of Ifindex
			pos++
		}
		binary.BigEndian.PutUint32(buf[pos:], 1) // Ifindex
		pos += 4

		r = &IPRouteBody{API: command[v]}
		err = r.decodeFromBytes(buf, v, software)
		switch v {
		case 2, 3:
			assert.Equal("message length invalid (last) pos:39 rest:46, message:0x1f", err.Error())
		case 4:
			assert.Equal("message length invalid (last) pos:39 rest:46, message:0x2f", err.Error())
		case 5:
			assert.Equal("message length invalid (last) pos:44 rest:51, message:0x17", err.Error())
		case 6:
			assert.Equal("message length invalid (last) pos:45 rest:52, message:0x17", err.Error())
		}

		// no nexthop
		switch v {
		case 2, 3, 4:
			buf = make([]byte, size[v]-32)
		case 5:
			buf = make([]byte, size[v]-37)
		case 6:
			buf = make([]byte, size[v]-38)
		}
		buf[0] = byte(routeType)
		pos = 1
		switch v {
		case 2, 3:
			buf[pos] = byte(FlagSelected.ToEach(v, software))
			pos++
		case 4, 5, 6:
			binary.BigEndian.PutUint16(buf[pos:], 0) //Instance
			pos += 2
			binary.BigEndian.PutUint32(buf[pos:], uint32(FlagSelected.ToEach(v, software)))
			pos += 4
		}

		if v == 6 {
			binary.BigEndian.PutUint32(buf[pos:], uint32(messageWithoutNexthop[v])) // frr7.5: 32bit
			pos += 4
		} else {
			buf[pos] = byte(messageWithoutNexthop[v]) // before frr7.4: 8bit
			pos++
		}

		if v > 4 {
			buf[pos] = byte(SafiUnicast) //SAFI
			pos++
			buf[pos] = byte(syscall.AF_INET) //Family
			pos++
		}
		buf[pos] = 16 // PrefixLen
		pos++
		ip = net.ParseIP("2501::").To16()
		copy(buf[pos:pos+2], []byte(ip))
		pos += 2
		buf[pos] = 1                             //distance
		binary.BigEndian.PutUint32(buf[pos:], 0) //metic
		r = &IPRouteBody{API: command[v]}
		err = r.decodeFromBytes(buf, v, software)
		assert.Equal(nil, err)
	}
}

// NexthopLookup exists in only quagga (zebra API version 2 and 3)
func Test_nexthopLookupBody(t *testing.T) {
	assert := assert.New(t)

	//ipv4
	//decodeFromBytes
	pos := 0
	buf := make([]byte, 18)
	ip := net.ParseIP("192.168.50.0").To4()
	copy(buf[0:4], []byte(ip)) // addr
	pos += 4
	binary.BigEndian.PutUint32(buf[pos:], 10) // metric
	pos += 4
	buf[pos] = byte(1) // numNexthop
	pos++
	buf[pos] = byte(4)
	pos++
	ip = net.ParseIP("172.16.1.101").To4()
	copy(buf[pos:pos+4], []byte(ip))
	pos += 4
	binary.BigEndian.PutUint32(buf[pos:], 3)

	//b := &nexthopLookupBody{api: zapi3IPv4NexthopLookup}
	b := &lookupBody{api: zapi3IPv4NexthopLookup}
	v := uint8(2)
	software := NewSoftware(v, "")
	err := b.decodeFromBytes(buf, v, software)
	assert.Equal(nil, err)
	assert.Equal("192.168.50.0", b.addr.String())
	assert.Equal(uint32(10), b.metric)
	assert.Equal(uint32(3), b.nexthops[0].Ifindex)
	assert.Equal(nexthopType(4), b.nexthops[0].Type)
	assert.Equal("172.16.1.101", b.nexthops[0].Gate.String())

	//serialize
	buf, err = b.serialize(v, software)
	ip = net.ParseIP("192.168.50.0").To4()
	assert.Equal(nil, err)
	assert.Equal([]byte(ip)[0:4], buf[0:4])

	// length invalid
	buf = make([]byte, 3)
	//b = &nexthopLookupBody{api: zapi3IPv4NexthopLookup}
	b = &lookupBody{api: zapi3IPv4NexthopLookup}
	err = b.decodeFromBytes(buf, v, software)
	assert.NotEqual(nil, err)

	//ipv6
	//decodeFromBytes
	pos = 0
	buf = make([]byte, 46)
	ip = net.ParseIP("2001:db8:0:f101::").To16()
	copy(buf[0:16], []byte(ip))
	pos += 16
	binary.BigEndian.PutUint32(buf[pos:], 10)
	pos += 4
	buf[pos] = byte(1)
	pos++
	buf[pos] = byte(7)
	pos++
	ip = net.ParseIP("2001:db8:0:1111::1").To16()
	copy(buf[pos:pos+16], []byte(ip))
	pos += 16
	binary.BigEndian.PutUint32(buf[pos:], 3)

	b = &lookupBody{api: zapi3IPv6NexthopLookup}
	err = b.decodeFromBytes(buf, v, software)
	assert.Equal(nil, err)
	assert.Equal("2001:db8:0:f101::", b.addr.String())
	assert.Equal(uint32(10), b.metric)
	assert.Equal(uint32(3), b.nexthops[0].Ifindex)
	assert.Equal(nexthopType(7), b.nexthops[0].Type)
	assert.Equal("2001:db8:0:1111::1", b.nexthops[0].Gate.String())

	//serialize
	buf, err = b.serialize(v, software)
	ip = net.ParseIP("2001:db8:0:f101::").To16()
	assert.Equal(nil, err)
	assert.Equal([]byte(ip)[0:16], buf[0:16])

	// length invalid
	buf = make([]byte, 15)
	b = &lookupBody{api: zapi3IPv6NexthopLookup}
	err = b.decodeFromBytes(buf, v, software)
	assert.NotEqual(nil, err)
}

// ImportLookup exists in only quagga (zebra API version 2 and 3)
func Test_importLookupBody(t *testing.T) {
	assert := assert.New(t)

	//decodeFromBytes
	pos := 0
	buf := make([]byte, 18)
	ip := net.ParseIP("192.168.50.0").To4()
	copy(buf[0:4], []byte(ip))
	pos += 4
	binary.BigEndian.PutUint32(buf[pos:], 10)
	pos += 4
	buf[pos] = byte(1)
	pos++
	buf[pos] = byte(4)
	pos++
	ip = net.ParseIP("172.16.1.101").To4()
	copy(buf[pos:pos+4], []byte(ip))
	pos += 4
	binary.BigEndian.PutUint32(buf[pos:], 3)

	b := &lookupBody{api: zapi3IPv4ImportLookup}
	v := uint8(2)
	software := NewSoftware(v, "")
	err := b.decodeFromBytes(buf, v, software)
	assert.Equal(nil, err)
	assert.Equal("192.168.50.0", b.addr.String())
	assert.Equal(uint32(10), b.metric)
	assert.Equal(uint32(3), b.nexthops[0].Ifindex)
	assert.Equal(nexthopType(4), b.nexthops[0].Type)
	assert.Equal("172.16.1.101", b.nexthops[0].Gate.String())

	//serialize
	b.prefixLength = uint8(24)
	buf, err = b.serialize(v, software)
	ip = net.ParseIP("192.168.50.0").To4()
	assert.Equal(nil, err)
	assert.Equal(uint8(24), buf[0])
	assert.Equal([]byte(ip)[0:4], buf[1:5])

	// length invalid
	buf = make([]byte, 3)
	b = &lookupBody{api: zapi3IPv4ImportLookup}
	err = b.decodeFromBytes(buf, v, software)
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
	command := map[uint8]APIType{
		2: zapi3NexthopRegister,
		3: zapi3NexthopRegister,
		4: zapi4NexthopRegister,
		5: zapi5Frr5NexthopRegister,
		6: nexthopRegister,
	}
	for v := MinZapiVer; v <= MaxZapiVer; v++ {
		// Test decodeFromBytes()
		software := NewSoftware(v, "")
		b := &NexthopRegisterBody{api: command[v].toCommon(v, software)}
		err := b.decodeFromBytes(bufIn, v, software)
		assert.Nil(err)

		// Test decoded values
		assert.Equal(uint8(1), b.Nexthops[0].connected)
		assert.Equal(uint16(syscall.AF_INET), b.Nexthops[0].Family)
		assert.Equal(net.ParseIP("192.168.1.1").To4(), b.Nexthops[0].Prefix)
		assert.Equal(uint8(0), b.Nexthops[1].connected)
		assert.Equal(uint16(syscall.AF_INET6), b.Nexthops[1].Family)
		assert.Equal(net.ParseIP("2001:db8:1:1::1").To16(), b.Nexthops[1].Prefix)

		// Test serialize()
		bufOut, err := b.serialize(v, software)
		assert.Nil(err)

		// Test serialised value
		assert.Equal(bufIn, bufOut)
	}
}

func Test_NexthopUpdateBody(t *testing.T) {
	assert := assert.New(t)

	size := map[uint8]uint8{2: 21, 3: 21, 4: 22, 5: 26, 6: 34}
	command := map[uint8]APIType{
		2: zapi3NexthopUpdate,
		3: zapi3NexthopUpdate,
		4: zapi4NexthopUpdate,
		5: zapi5Frr5NexthopUpdate,
		6: nexthopUpdate,
	}
	nexthopType := map[uint8]nexthopType{
		2: backwardNexthopTypeIPv4IFIndex,
		3: backwardNexthopTypeIPv4IFIndex,
		4: nexthopTypeIPv4IFIndex,
		5: nexthopTypeIPv4IFIndex,
		6: nexthopTypeIPv4IFIndex,
	}

	for v := MinZapiVer; v <= MaxZapiVer; v++ {
		// Input binary
		bufIn := make([]byte, size[v])
		pos := 0
		if v == 6 { // frr7.5
			// message flag
			copy(bufIn[pos:pos+4], []byte{0x00, 0x00, 0x00, 0x00})
			pos += 4
		}
		// afi(2 bytes)=AF_INET, prefix_len(1 byte)=32, prefix(4 bytes)="192.168.1.1"
		copy(bufIn[pos:pos+7], []byte{0x00, 0x02, 0x20, 0xc0, 0xa8, 0x01, 0x01})
		pos += 7

		if v > 4 { // Type(1byte), Instance(2byte)
			copy(bufIn[pos:pos+3], []byte{byte(routeConnect), 0x00, 0x00})
			pos += 3
		}
		if v > 3 { // Distance
			bufIn[pos] = 0
			pos++
		}
		// metric(4 bytes)=1, number of nexthops(1 byte)=1
		copy(bufIn[pos:pos+5], []byte{0x00, 0x00, 0x00, 0x01, 0x01})
		pos += 5
		if v == 6 { // version == 6 and not frr6
			binary.BigEndian.PutUint32(bufIn[pos:], 0) //vrfid
			pos += 4
		}
		bufIn[pos] = byte(nexthopType[v])
		pos++
		if v == 6 { // frr7.3 and later
			bufIn[pos] = byte(0) // nexthop flag
			pos++
		}
		// nexthop_ip(4 bytes)="192.168.0.1", nexthop_Ifindex(4 byte)=2
		copy(bufIn[pos:pos+8], []byte{0xc0, 0xa8, 0x01, 0x01, 0x00, 0x00, 0x00, 0x02})
		pos += 8
		if v == 5 { // frr7.3&7.4 (latest software of zapi v6) depends on nexthop flag
			bufIn[pos] = byte(0) // label num
			pos++
		}

		// Test decodeFromBytes()
		software := NewSoftware(v, "")
		b := &NexthopUpdateBody{API: command[v].toCommon(v, software)}
		err := b.decodeFromBytes(bufIn, v, software)
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
	routeType := RouteBGP
	for v := uint8(5); v <= MaxZapiVer; v++ {
		//decodeFromBytes
		buf := make([]byte, 12)
		buf[0] = byte(routeType)                // Route Type
		binary.BigEndian.PutUint16(buf[1:], 0)  //Instance
		buf[3] = 0                              //Keep
		binary.BigEndian.PutUint32(buf[4:], 80) //Start
		binary.BigEndian.PutUint32(buf[8:], 89) //End

		b := &GetLabelChunkBody{}
		software := NewSoftware(v, "")
		err := b.decodeFromBytes(buf, v, software)
		assert.Equal(nil, err)

		//serialize
		b.ChunkSize = 10
		buf, err = b.serialize(v, software)
		assert.Equal(nil, err)
		assert.Equal(byte(routeType), buf[0])
		bi := make([]byte, 4)
		binary.BigEndian.PutUint32(bi, 10)
		assert.Equal(bi, buf[4:8]) // Chunksize
	}
}

func Test_vrfLabelBody(t *testing.T) {
	assert := assert.New(t)
	// Test only with ZAPI version 5 and 6
	for v := uint8(5); v <= MaxZapiVer; v++ {
		//decodeFromBytes
		bufIn := make([]byte, 6)
		binary.BigEndian.PutUint32(bufIn[0:], 80) //label
		bufIn[4] = byte(afiIP)
		bufIn[5] = byte(lspBGP)
		b := &vrfLabelBody{}
		software := NewSoftware(v, "")
		err := b.decodeFromBytes(bufIn, v, software)
		assert.Equal(nil, err)
		//serialize
		var bufOut []byte
		bufOut, err = b.serialize(v, software)
		assert.Equal(nil, err)
		assert.Equal(bufIn, bufOut)
	}
}

func FuzzZapi(f *testing.F) {

	f.Fuzz(func(t *testing.T, data []byte) {

		if len(data) < 16 {
			return
		}

		for v := MinZapiVer; v <= MaxZapiVer; v++ {

			ZAPIHeaderSize := int(HeaderSize(v))

			hd := &Header{}
			err := hd.decodeFromBytes(data[:ZAPIHeaderSize])

			if err != nil {
				return
			}

			software := NewSoftware(v, "")
			parseMessage(hd, data[:ZAPIHeaderSize], software)
		}
	})
}
