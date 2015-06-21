package mrt

import (
	"bytes"
	"github.com/osrg/gobgp/packet"
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
	"time"
)

func TestMrtHdr(t *testing.T) {
	h1, err := NewHeader(10, TABLE_DUMPv2, RIB_IPV4_MULTICAST, 20)
	if err != nil {
		t.Fatal(err)
	}
	b1, err := h1.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	h2 := &Header{}
	err = h2.DecodeFromBytes(b1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := h2.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, bytes.Equal(b1, b2), true)
}

func testPeer(t *testing.T, p1 *Peer) {
	b1, err := p1.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	p2 := &Peer{}
	rest, err := p2.DecodeFromBytes(b1)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, len(rest), 0)
	b2, err := p2.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, bytes.Equal(b1, b2), true)
}

func TestMrtPeer(t *testing.T) {
	p := NewPeer(net.ParseIP("192.168.0.1"), net.ParseIP("10.0.0.1"), 65000, false)
	testPeer(t, p)
}

func TestMrtPeerv6(t *testing.T) {
	p := NewPeer(net.ParseIP("192.168.0.1"), net.ParseIP("2001::1"), 65000, false)
	testPeer(t, p)
}

func TestMrtPeerAS4(t *testing.T) {
	p := NewPeer(net.ParseIP("192.168.0.1"), net.ParseIP("2001::1"), 135500, true)
	testPeer(t, p)
}

func TestMrtPeerIndexTable(t *testing.T) {
	p1 := NewPeer(net.ParseIP("192.168.0.1"), net.ParseIP("10.0.0.1"), 65000, false)
	p2 := NewPeer(net.ParseIP("192.168.0.1"), net.ParseIP("2001::1"), 65000, false)
	p3 := NewPeer(net.ParseIP("192.168.0.1"), net.ParseIP("2001::1"), 135500, true)
	pt1 := NewPeerIndexTable(net.ParseIP("192.168.0.1"), "test", []*Peer{p1, p2, p3})
	b1, err := pt1.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	pt2 := &PeerIndexTable{}
	err = pt2.DecodeFromBytes(b1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := pt2.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, bytes.Equal(b1, b2), true)
}

func TestMrtRibEntry(t *testing.T) {
	aspath1 := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(2, []uint16{1000}),
		bgp.NewAsPathParam(1, []uint16{1001, 1002}),
		bgp.NewAsPathParam(2, []uint16{1003, 1004}),
	}

	p := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(3),
		bgp.NewPathAttributeAsPath(aspath1),
		bgp.NewPathAttributeNextHop("129.1.1.2"),
		bgp.NewPathAttributeMultiExitDisc(1 << 20),
		bgp.NewPathAttributeLocalPref(1 << 22),
	}

	e1 := NewRibEntry(1, uint32(time.Now().Unix()), p)
	b1, err := e1.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	e2 := &RibEntry{}
	rest, err := e2.DecodeFromBytes(b1)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, len(rest), 0)
	b2, err := e2.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, bytes.Equal(b1, b2), true)
}

func TestMrtRib(t *testing.T) {
	aspath1 := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(2, []uint16{1000}),
		bgp.NewAsPathParam(1, []uint16{1001, 1002}),
		bgp.NewAsPathParam(2, []uint16{1003, 1004}),
	}

	p := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(3),
		bgp.NewPathAttributeAsPath(aspath1),
		bgp.NewPathAttributeNextHop("129.1.1.2"),
		bgp.NewPathAttributeMultiExitDisc(1 << 20),
		bgp.NewPathAttributeLocalPref(1 << 22),
	}

	e1 := NewRibEntry(1, uint32(time.Now().Unix()), p)
	e2 := NewRibEntry(2, uint32(time.Now().Unix()), p)
	e3 := NewRibEntry(3, uint32(time.Now().Unix()), p)

	r1 := NewRib(1, bgp.NewIPAddrPrefix(24, "192.168.0.0"), []*RibEntry{e1, e2, e3})
	b1, err := r1.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	r2 := &Rib{
		RouteFamily: bgp.RF_IPv4_UC,
	}
	err = r2.DecodeFromBytes(b1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := r2.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, bytes.Equal(b1, b2), true)
}

func TestMrtBgp4mpStateChange(t *testing.T) {
	c1 := NewBGP4MPStateChange(65000, 650001, 1, net.ParseIP("192.168.0.1"), net.ParseIP("192.168.0.2"), false, ACTIVE, ESTABLISHED)
	b1, err := c1.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	c2 := &BGP4MPStateChange{BGP4MPHeader: &BGP4MPHeader{}}
	err = c2.DecodeFromBytes(b1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := c2.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, bytes.Equal(b1, b2), true)
}

func TestMrtBgp4mpMessage(t *testing.T) {
	msg := bgp.NewBGPKeepAliveMessage()
	m1 := NewBGP4MPMessage(65000, 650001, 1, net.ParseIP("192.168.0.1"), net.ParseIP("192.168.0.2"), false, msg)
	b1, err := m1.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	m2 := &BGP4MPMessage{BGP4MPHeader: &BGP4MPHeader{}}
	err = m2.DecodeFromBytes(b1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := m2.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, bytes.Equal(b1, b2), true)
}

func TestMrtBgp4mpMessageLocal(t *testing.T) {
	msg := bgp.NewBGPKeepAliveMessage()
	m1 := NewBGP4MPMessageLocal(65000, 650001, 1, net.ParseIP("192.168.0.1"), net.ParseIP("192.168.0.2"), false, msg)
	b1, err := m1.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	m2 := &BGP4MPMessage{BGP4MPHeader: &BGP4MPHeader{}}
	err = m2.DecodeFromBytes(b1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := m2.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, bytes.Equal(b1, b2), true)
}
