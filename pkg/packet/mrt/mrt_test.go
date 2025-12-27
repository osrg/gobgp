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

package mrt

import (
	"bufio"
	"bytes"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
)

func TestMrtHdr(t *testing.T) {
	h1, err := NewMRTHeader(time.Unix(10, 0), TABLE_DUMPv2, RIB_IPV4_MULTICAST, 20)
	if err != nil {
		t.Fatal(err)
	}
	b1, err := h1.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	h2, err := ParseHeader(b1)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, reflect.DeepEqual(h1, h2), true)
}

func TestMrtHdrTime(t *testing.T) {
	ttime1 := time.Unix(10, 0)
	h1, err := NewMRTHeader(ttime1, TABLE_DUMPv2, RIB_IPV4_MULTICAST, 20)
	if err != nil {
		t.Fatal(err)
	}
	h1time := h1.GetTime()
	t.Logf("this timestamp should be 10s after epoch:%v", h1time)
	assert.Equal(t, h1time, ttime1)

	ttime2 := time.Unix(20, 123000)
	h2, err := NewMRTHeader(ttime2, BGP4MP_ET, STATE_CHANGE, 20)
	if err != nil {
		t.Fatal(err)
	}
	h2time := h2.GetTime()
	t.Logf("this timestamp should be 20s and 123ms after epoch:%v", h2time)
	assert.Equal(t, h2time, ttime2)
}

func testPeer(t *testing.T, p1 *Peer) {
	b1, err := p1.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	p2 := &Peer{}
	rest, err := p2.decodeFromBytes(b1)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, len(rest), 0)
	assert.Equal(t, reflect.DeepEqual(p1, p2), true)
}

func TestMrtPeer(t *testing.T) {
	p := NewPeer(netip.MustParseAddr("192.168.0.1"), netip.MustParseAddr("10.0.0.1"), 65000, false)
	testPeer(t, p)
}

func TestMrtPeerv6(t *testing.T) {
	p := NewPeer(netip.MustParseAddr("192.168.0.1"), netip.MustParseAddr("2001::1"), 65000, false)
	testPeer(t, p)
}

func TestMrtPeerAS4(t *testing.T) {
	p := NewPeer(netip.MustParseAddr("192.168.0.1"), netip.MustParseAddr("2001::1"), 135500, true)
	testPeer(t, p)
}

func TestMrtPeerIndexTable(t *testing.T) {
	p1 := NewPeer(netip.MustParseAddr("192.168.0.1"), netip.MustParseAddr("10.0.0.1"), 65000, false)
	p2 := NewPeer(netip.MustParseAddr("192.168.0.1"), netip.MustParseAddr("2001::1"), 65000, false)
	p3 := NewPeer(netip.MustParseAddr("192.168.0.1"), netip.MustParseAddr("2001::1"), 135500, true)
	pt1 := NewPeerIndexTable(netip.MustParseAddr("192.168.0.1"), "test", []*Peer{p1, p2, p3})
	b1, err := pt1.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	pt2, err := parsePeerIndexTable(b1)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, reflect.DeepEqual(pt1, pt2), true)
}

func TestParsePeerIndexTable_LargeViewNameDoesNotPanic(t *testing.T) {
	// Regression: viewLen is uint16 in the wire format. Using uint16 arithmetic
	// in slice indices can wrap (e.g., 6+0xffff == 5), causing a panic even when
	// the buffer is large enough.
	viewLen := 0xffff

	data := make([]byte, 0, 4+2+viewLen+2)
	data = append(data, 192, 0, 2, 1) // CollectorBgpId
	data = append(data, 0xff, 0xff)   // ViewName length
	data = append(data, bytes.Repeat([]byte{'a'}, viewLen)...)
	data = append(data, 0x00, 0x00) // PeerNum

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("parsePeerIndexTable must not panic: %v", r)
		}
	}()

	tbl, err := parsePeerIndexTable(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tbl.ViewName) != viewLen {
		t.Fatalf("unexpected view name length: got %d want %d", len(tbl.ViewName), viewLen)
	}
}

func TestMrtRibEntry(t *testing.T) {
	aspath1 := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(2, []uint16{1000}),
		bgp.NewAsPathParam(1, []uint16{1001, 1002}),
		bgp.NewAsPathParam(2, []uint16{1003, 1004}),
	}
	panh, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("129.1.1.2"))
	p := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(3),
		bgp.NewPathAttributeAsPath(aspath1),
		panh,
		bgp.NewPathAttributeMultiExitDisc(1 << 20),
		bgp.NewPathAttributeLocalPref(1 << 22),
	}

	e1 := NewRibEntry(1, uint32(time.Now().Unix()), 0, p, false)
	b1, err := e1.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	e2, rest, err := parseRibEntry(b1, bgp.RF_IPv4_UC, false)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, len(rest), 0)
	assert.Equal(t, reflect.DeepEqual(e1, e2), true)
}

func TestMrtRibEntryWithAddPath(t *testing.T) {
	aspath1 := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(2, []uint16{1000}),
		bgp.NewAsPathParam(1, []uint16{1001, 1002}),
		bgp.NewAsPathParam(2, []uint16{1003, 1004}),
	}
	panh, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("129.1.1.2"))
	p := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(3),
		bgp.NewPathAttributeAsPath(aspath1),
		panh,
		bgp.NewPathAttributeMultiExitDisc(1 << 20),
		bgp.NewPathAttributeLocalPref(1 << 22),
	}
	e1 := NewRibEntry(1, uint32(time.Now().Unix()), 200, p, true)
	b1, err := e1.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	e2, rest2, err := parseRibEntry(b1, bgp.RF_IPv4_UC, true)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, len(rest2), 0)
	assert.Equal(t, reflect.DeepEqual(e1, e2), true)
}

func TestMrtRib(t *testing.T) {
	aspath1 := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(2, []uint16{1000}),
		bgp.NewAsPathParam(1, []uint16{1001, 1002}),
		bgp.NewAsPathParam(2, []uint16{1003, 1004}),
	}
	panh, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("129.1.1.2"))
	p := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(3),
		bgp.NewPathAttributeAsPath(aspath1),
		panh,
		bgp.NewPathAttributeMultiExitDisc(1 << 20),
		bgp.NewPathAttributeLocalPref(1 << 22),
	}

	e1 := NewRibEntry(1, uint32(time.Now().Unix()), 0, p, false)
	e2 := NewRibEntry(2, uint32(time.Now().Unix()), 0, p, false)
	e3 := NewRibEntry(3, uint32(time.Now().Unix()), 0, p, false)
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("192.168.0.0/24"))
	r1 := NewRib(1, bgp.RF_IPv4_UC, nlri, []*RibEntry{e1, e2, e3})
	b1, err := r1.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	r2, err := parseRib(b1, bgp.RF_IPv4_UC, false)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, reflect.DeepEqual(r1, r2), true)
}

func TestMrtRibWithAddPath(t *testing.T) {
	aspath1 := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(2, []uint16{1000}),
		bgp.NewAsPathParam(1, []uint16{1001, 1002}),
		bgp.NewAsPathParam(2, []uint16{1003, 1004}),
	}
	panh, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("129.1.1.2"))
	p := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(3),
		bgp.NewPathAttributeAsPath(aspath1),
		panh,
		bgp.NewPathAttributeMultiExitDisc(1 << 20),
		bgp.NewPathAttributeLocalPref(1 << 22),
	}

	e1 := NewRibEntry(1, uint32(time.Now().Unix()), 100, p, true)
	e2 := NewRibEntry(2, uint32(time.Now().Unix()), 200, p, true)
	e3 := NewRibEntry(3, uint32(time.Now().Unix()), 300, p, true)

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("192.168.0.0/24"))
	r1 := NewRib(1, bgp.RF_IPv4_UC, nlri, []*RibEntry{e1, e2, e3})
	b1, err := r1.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	r2, err := parseRib(b1, bgp.RF_IPv4_UC, true)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, reflect.DeepEqual(r1, r2), true)
}

func TestMrtGeoPeerTable(t *testing.T) {
	p1, _ := NewGeoPeer(netip.MustParseAddr("192.168.0.1"), 28.031157, 86.899684)
	p2, _ := NewGeoPeer(netip.MustParseAddr("192.168.0.1"), 35.360556, 138.727778)
	pt1, _ := NewGeoPeerTable(netip.MustParseAddr("192.168.0.1"), 12.345678, 98.765432, []*GeoPeer{p1, p2})
	b1, err := pt1.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	pt2, err := parseGeoPeerTable(b1)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, reflect.DeepEqual(pt1, pt2), true)
}

func TestMrtBgp4mpStateChange(t *testing.T) {
	c1, _ := NewBGP4MPStateChange(65000, 65001, 1, netip.MustParseAddr("192.168.0.1"), netip.MustParseAddr("192.168.0.2"), false, ACTIVE, ESTABLISHED)
	b1, err := c1.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	c2, err := parseBGP4MPStateChange(&BGP4MPHeader{}, b1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c2.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, reflect.DeepEqual(c1, c2), true)
}

func TestMrtBgp4mpMessage(t *testing.T) {
	msg := bgp.NewBGPKeepAliveMessage()
	m1, _ := NewBGP4MPMessage(65000, 65001, 1, netip.MustParseAddr("192.168.0.1"), netip.MustParseAddr("192.168.0.2"), false, msg)
	b1, err := m1.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	m2, err := parseBGP4MPMessage(&BGP4MPHeader{}, false, false, b1)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, reflect.DeepEqual(m1, m2), true)
}

func TestMrtSplit(t *testing.T) {
	var b bytes.Buffer
	numwrite, numread := 10, 0
	for range numwrite {
		msg := bgp.NewBGPKeepAliveMessage()
		m1, _ := NewBGP4MPMessage(65000, 65001, 1, netip.MustParseAddr("192.168.0.1"), netip.MustParseAddr("192.168.0.2"), false, msg)
		mm, _ := NewMRTMessage(time.Unix(1234, 0), BGP4MP, MESSAGE, m1)
		b1, err := mm.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		b.Write(b1)
	}
	t.Logf("wrote %d serialized MRT keepalives in the buffer", numwrite)
	r := bytes.NewReader(b.Bytes())
	scanner := bufio.NewScanner(r)
	scanner.Split(SplitMrt)
	for scanner.Scan() {
		numread += 1
	}
	t.Logf("scanner scanned %d serialized keepalives from the buffer", numread)
	assert.Equal(t, numwrite, numread)
}

//nolint:errcheck
func FuzzMRT(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < MRT_COMMON_HEADER_LEN {
			return
		}

		hdr, err := ParseHeader(data[:MRT_COMMON_HEADER_LEN])
		if err != nil {
			return
		}

		ParseBody(data[MRT_COMMON_HEADER_LEN:], hdr)
	})
}

//nolint:errcheck
func FuzzDecodeFromBytes(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ParseHeader(data)
		parsePeerIndexTable(data)
		parseRibEntry(data, bgp.RF_IPv4_UC, false)
		parseRibEntry(data, bgp.RF_IPv4_UC, true)
		parseRib(data, bgp.RF_IPv4_UC, false)
		parseRib(data, bgp.RF_IPv4_UC, true)
		parseGeoPeerTable(data)
		(&GeoPeer{}).decodeFromBytes(data)
		(&Peer{}).decodeFromBytes(data)
		if len(data) > 12 {
			h := &BGP4MPHeader{isAS4: true}
			_, err := h.decodeFromBytes(data[:12])
			if err != nil {
				return
			}
			parseBGP4MPStateChange(h, data[12:])
			parseBGP4MPMessage(h, true, true, data[12:])
			parseBGP4MPMessage(h, true, false, data[12:])
			parseBGP4MPMessage(h, false, true, data[12:])
			parseBGP4MPMessage(h, false, false, data[12:])
		}
		if len(data) > 8 {
			h := &BGP4MPHeader{isAS4: false}
			_, err := h.decodeFromBytes(data[:8])
			if err != nil {
				return
			}
			parseBGP4MPStateChange(h, data[8:])
			parseBGP4MPMessage(h, true, true, data[8:])
			parseBGP4MPMessage(h, true, false, data[8:])
			parseBGP4MPMessage(h, false, true, data[8:])
			parseBGP4MPMessage(h, false, false, data[8:])
		}
	})
}
