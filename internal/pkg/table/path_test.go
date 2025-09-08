// path_test.go
package table

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
)

func TestPathNewIPv4(t *testing.T) {
	peerP := PathCreatePeer()
	pathP := PathCreatePath(peerP)
	ipv4p := NewPath(bgp.RF_IPv4_UC, pathP[0].GetSource(), bgp.PathNLRI{NLRI: pathP[0].GetNlri()}, true, pathP[0].GetPathAttrs(), time.Now(), false)
	assert.NotNil(t, ipv4p)
}

func TestPathNewIPv6(t *testing.T) {
	peerP := PathCreatePeer()
	pathP := PathCreatePath(peerP)
	ipv6p := NewPath(bgp.RF_IPv4_UC, pathP[0].GetSource(), bgp.PathNLRI{NLRI: pathP[0].GetNlri()}, true, pathP[0].GetPathAttrs(), time.Now(), false)
	assert.NotNil(t, ipv6p)
}

func TestPathGetNlri(t *testing.T) {
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("13.2.3.2/24"))
	pd := &Path{
		info: &originInfo{
			nlri: nlri,
		},
	}
	r_nlri := pd.GetNlri()
	assert.Equal(t, r_nlri, nlri)
}

func TestPathCreatePath(t *testing.T) {
	peerP := PathCreatePeer()
	msg := updateMsgP1()
	updateMsgP := msg.Body.(*bgp.BGPUpdate)
	nlriList := updateMsgP.NLRI
	pathAttributes := updateMsgP.PathAttributes
	nlri_info := nlriList[0]
	path := NewPath(bgp.RF_IPv4_UC, peerP[0], bgp.PathNLRI{NLRI: nlri_info.NLRI}, false, pathAttributes, time.Now(), false)
	assert.NotNil(t, path)
}

func TestPathGetPrefix(t *testing.T) {
	peerP := PathCreatePeer()
	pathP := PathCreatePath(peerP)
	prefix := "10.10.10.0/24"
	r_prefix := pathP[0].GetPrefix()
	assert.Equal(t, r_prefix, prefix)
}

func TestPathGetAttribute(t *testing.T) {
	peerP := PathCreatePeer()
	pathP := PathCreatePath(peerP)
	nh := "192.168.50.1"
	pa := pathP[0].getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	r_nh := pa.(*bgp.PathAttributeNextHop).Value.String()
	assert.Equal(t, r_nh, nh)
}

func TestASPathLen(t *testing.T) {
	assert := assert.New(t)
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint16{65001, 65002, 65003, 65004, 65004, 65004, 65004, 65004, 65005}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SET, []uint16{65001, 65002, 65003, 65004, 65005}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ, []uint16{65100, 65101, 65102}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET, []uint16{65100, 65101}),
	}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.50.1"))
	med := bgp.NewPathAttributeMultiExitDisc(0)

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med,
	}

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	bgpmsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, []bgp.PathNLRI{{NLRI: nlri}})
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(logger, update)
	peer := PathCreatePeer()
	p := NewPath(bgp.RF_IPv4_UC, peer[0], bgp.PathNLRI{NLRI: update.NLRI[0].NLRI}, false, update.PathAttributes, time.Now(), false)
	assert.Equal(10, p.GetAsPathLen())
}

func TestPathPrependAsnToExistingSeqAttr(t *testing.T) {
	assert := assert.New(t)
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint16{65001, 65002, 65003, 65004, 65005}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SET, []uint16{65001, 65002, 65003, 65004, 65005}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ, []uint16{65100, 65101, 65102}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET, []uint16{65100, 65101}),
	}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.50.1"))

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
	}

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	bgpmsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, []bgp.PathNLRI{{NLRI: nlri}})
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(logger, update)
	peer := PathCreatePeer()
	p := NewPath(bgp.RF_IPv4_UC, peer[0], bgp.PathNLRI{NLRI: update.NLRI[0].NLRI}, false, update.PathAttributes, time.Now(), false)

	p.PrependAsn(65000, 1, false)
	assert.Equal([]uint32{65000, 65001, 65002, 65003, 65004, 65005, 0, 0, 0}, p.GetAsSeqList())
}

func TestPathPrependAsnToNewAsPathAttr(t *testing.T) {
	assert := assert.New(t)
	origin := bgp.NewPathAttributeOrigin(0)
	nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.50.1"))

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		nexthop,
	}

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	bgpmsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, []bgp.PathNLRI{{NLRI: nlri}})
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(logger, update)
	peer := PathCreatePeer()
	p := NewPath(bgp.RF_IPv4_UC, peer[0], bgp.PathNLRI{NLRI: update.NLRI[0].NLRI}, false, update.PathAttributes, time.Now(), false)

	asn := uint32(65000)
	p.PrependAsn(asn, 1, false)
	assert.Equal([]uint32{asn}, p.GetAsSeqList())
}

func TestPathPrependAsnToNewAsPathSeq(t *testing.T) {
	assert := assert.New(t)
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SET, []uint16{65001, 65002, 65003, 65004, 65005}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ, []uint16{65100, 65101, 65102}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET, []uint16{65100, 65101}),
	}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.50.1"))

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
	}

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	bgpmsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, []bgp.PathNLRI{{NLRI: nlri}})
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(logger, update)
	peer := PathCreatePeer()
	p := NewPath(bgp.RF_IPv4_UC, peer[0], bgp.PathNLRI{NLRI: update.NLRI[0].NLRI}, false, update.PathAttributes, time.Now(), false)

	asn := uint32(65000)
	p.PrependAsn(asn, 1, false)
	assert.Equal([]uint32{asn, 0, 0, 0}, p.GetAsSeqList())
}

func TestPathPrependAsnToEmptyAsPathAttr(t *testing.T) {
	assert := assert.New(t)
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint16{}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SET, []uint16{65001, 65002, 65003, 65004, 65005}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ, []uint16{65100, 65101, 65102}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET, []uint16{65100, 65101}),
	}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.50.1"))

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
	}

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	bgpmsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, []bgp.PathNLRI{{NLRI: nlri}})
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(logger, update)
	peer := PathCreatePeer()
	p := NewPath(bgp.RF_IPv4_UC, peer[0], bgp.PathNLRI{NLRI: update.NLRI[0].NLRI}, false, update.PathAttributes, time.Now(), false)

	asn := uint32(65000)
	p.PrependAsn(asn, 1, false)
	assert.Equal([]uint32{asn, 0, 0, 0}, p.GetAsSeqList())
}

func TestPathPrependAsnToFullPathAttr(t *testing.T) {
	assert := assert.New(t)
	origin := bgp.NewPathAttributeOrigin(0)

	asns := make([]uint16, 255)
	for i := range asns {
		asns[i] = 65000 + uint16(i)
	}

	aspathParam := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, asns),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SET, []uint16{65001, 65002, 65003, 65004, 65005}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ, []uint16{65100, 65101, 65102}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET, []uint16{65100, 65101}),
	}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.50.1"))

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
	}

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	bgpmsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, []bgp.PathNLRI{{NLRI: nlri}})
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(logger, update)
	peer := PathCreatePeer()
	p := NewPath(bgp.RF_IPv4_UC, peer[0], bgp.PathNLRI{NLRI: update.NLRI[0].NLRI}, false, update.PathAttributes, time.Now(), false)

	expected := []uint32{65000, 65000}
	for _, v := range asns {
		expected = append(expected, uint32(v))
	}
	p.PrependAsn(65000, 2, false)
	assert.Equal(append(expected, []uint32{0, 0, 0}...), p.GetAsSeqList())
}

func TestGetPathAttrs(t *testing.T) {
	paths := PathCreatePath(PathCreatePeer())
	path0 := paths[0]
	path1 := path0.Clone(false)
	path1.delPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	path2 := path1.Clone(false)
	nexthopAttr, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.50.1"))
	path2.setPathAttr(nexthopAttr)
	assert.NotNil(t, path2.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP))
}

/*
func TestGetTransversalPathAttrs(t *testing.T) {
	checkTransversalPathAttrs := func(t *testing.T, path *Path, expectedAttr bgp.BGPAttrType, checkIsNotExist ...bool) {
		for _, attr := range path.GetTransversalPathAttrs() {
			assert.NotNil(t, attr)
		}
		if len(checkIsNotExist) > 0 && checkIsNotExist[0] {
			assert.Nil(t, path.GetTransversalPathAttrs()[expectedAttr])
		} else {
			assert.NotNil(t, path.GetTransversalPathAttrs()[expectedAttr])
		}
	}
	paths := PathCreatePath(PathCreatePeer())
	path0 := paths[0]
	checkTransversalPathAttrs(t, path0, bgp.BGP_ATTR_TYPE_ORIGIN)
	nextHop := path0.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	assert.NotNil(t, nextHop)
	assert.Equal(t, nextHop.(*bgp.PathAttributeNextHop).Value.String(), "192.168.50.1")

	path1 := path0.Clone(false)
	path1.setPathAttr(bgp.NewPathAttributeNextHop("192.168.98.1"))
	nextHop = path1.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	assert.NotNil(t, nextHop)
	assert.Equal(t, nextHop.(*bgp.PathAttributeNextHop).Value.String(), "192.168.98.1")
	path1.delPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	assert.NotNil(t, path1.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN))
	checkTransversalPathAttrs(t, path1, bgp.BGP_ATTR_TYPE_ORIGIN)
	checkTransversalPathAttrs(t, path1, bgp.BGP_ATTR_TYPE_NEXT_HOP, true)

	path2 := path1.Clone(false)
	assert.NotNil(t, path2.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN))
	path2.delPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	// adding an attribute that has been deleted previously by underlayer, is not allowed
	path2.setPathAttr(bgp.NewPathAttributeNextHop("192.168.99.1"))
	checkTransversalPathAttrs(t, path2, bgp.BGP_ATTR_TYPE_ORIGIN, true)
	checkTransversalPathAttrs(t, path2, bgp.BGP_ATTR_TYPE_NEXT_HOP, true)

	nextHop = path2.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	assert.NotNil(t, nextHop)
	assert.Equal(t, nextHop.(*bgp.PathAttributeNextHop).Value.String(), "192.168.99.1")
}
*/

func PathCreatePeer() []*PeerInfo {
	peerP1 := &PeerInfo{AS: 65000}
	peerP2 := &PeerInfo{AS: 65001}
	peerP3 := &PeerInfo{AS: 65002}
	peerP := []*PeerInfo{peerP1, peerP2, peerP3}
	return peerP
}

func PathCreatePath(peerP []*PeerInfo) []*Path {
	bgpMsgP1 := updateMsgP1()
	bgpMsgP2 := updateMsgP2()
	bgpMsgP3 := updateMsgP3()
	pathP := make([]*Path, 3)
	for i, msg := range []*bgp.BGPMessage{bgpMsgP1, bgpMsgP2, bgpMsgP3} {
		updateMsgP := msg.Body.(*bgp.BGPUpdate)
		nlriList := updateMsgP.NLRI
		pathAttributes := updateMsgP.PathAttributes
		nlri_info := nlriList[0]
		pathP[i] = NewPath(bgp.RF_IPv4_UC, peerP[i], bgp.PathNLRI{NLRI: nlri_info.NLRI}, false, pathAttributes, time.Now(), false)
	}
	return pathP
}

func updateMsgP1() *bgp.BGPMessage {
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65000})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.50.1"))
	med := bgp.NewPathAttributeMultiExitDisc(0)

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med,
	}

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	return bgp.NewBGPUpdateMessage(nil, pathAttributes, []bgp.PathNLRI{{NLRI: nlri}})
}

func updateMsgP2() *bgp.BGPMessage {
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65100})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.100.1"))
	med := bgp.NewPathAttributeMultiExitDisc(100)

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med,
	}

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("20.20.20.0/24"))
	return bgp.NewBGPUpdateMessage(nil, pathAttributes, []bgp.PathNLRI{{NLRI: nlri}})
}

func updateMsgP3() *bgp.BGPMessage {
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65100})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.150.1"))
	med := bgp.NewPathAttributeMultiExitDisc(100)

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med,
	}

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("30.30.30.0/24"))
	w1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("40.40.40.0/23"))
	withdrawnRoutes := []bgp.PathNLRI{{NLRI: w1}}
	return bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, []bgp.PathNLRI{{NLRI: nlri}})
}

func TestRemovePrivateAS(t *testing.T) {
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{64512, 64513, 1, 2})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("30.30.30.0/24"))
	path := NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, []bgp.PathAttributeInterface{aspath}, time.Now(), false)
	path.RemovePrivateAS(10, oc.REMOVE_PRIVATE_AS_OPTION_ALL)
	list := path.GetAsList()
	assert.Equal(t, len(list), 2)
	assert.Equal(t, list[0], uint32(1))
	assert.Equal(t, list[1], uint32(2))

	path = NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, []bgp.PathAttributeInterface{aspath}, time.Now(), false)
	path.RemovePrivateAS(10, oc.REMOVE_PRIVATE_AS_OPTION_REPLACE)
	list = path.GetAsList()
	assert.Equal(t, len(list), 4)
	assert.Equal(t, list[0], uint32(10))
	assert.Equal(t, list[1], uint32(10))
	assert.Equal(t, list[2], uint32(1))
	assert.Equal(t, list[3], uint32(2))
}

func TestReplaceAS(t *testing.T) {
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{64512, 64513, 1, 2})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("30.30.30.0/24"))
	path := NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, []bgp.PathAttributeInterface{aspath}, time.Now(), false)
	path = path.ReplaceAS(10, 1)
	list := path.GetAsList()
	assert.Equal(t, len(list), 4)
	assert.Equal(t, list[0], uint32(64512))
	assert.Equal(t, list[1], uint32(64513))
	assert.Equal(t, list[2], uint32(10))
	assert.Equal(t, list[3], uint32(2))
}

func TestNLRIToIPNet(t *testing.T) {
	_, n1, _ := net.ParseCIDR("30.30.30.0/24")
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("30.30.30.0/24"))
	ipNet := nlriToIPNet(nlri)
	assert.Equal(t, n1, ipNet)

	_, n2, _ := net.ParseCIDR("2806:106e:19::/48")
	nlri, _ = bgp.NewIPAddrPrefix(netip.MustParsePrefix("2806:106e:19::/48"))
	ipNet = nlriToIPNet(nlri)
	assert.Equal(t, n2, ipNet)

	labels := bgp.NewMPLSLabelStack(100, 200)
	_, n3, _ := net.ParseCIDR("30.30.30.0/24")
	mpls, _ := bgp.NewLabeledIPAddrPrefix(netip.MustParsePrefix("30.30.30.0/24"), *labels)
	ipNet = nlriToIPNet(mpls)
	assert.Equal(t, n3, ipNet)

	_, n4, _ := net.ParseCIDR("2806:106e:19::/48")
	mpls, _ = bgp.NewLabeledIPAddrPrefix(netip.MustParsePrefix("2806:106e:19::/48"), *labels)
	ipNet = nlriToIPNet(mpls)
	assert.Equal(t, n4, ipNet)

	rd, _ := bgp.ParseRouteDistinguisher("100:100")
	_, n5, _ := net.ParseCIDR("40.40.40.0/24")
	vpnv4, _ := bgp.NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix("40.40.40.0/24"), *labels, rd)
	ipNet = nlriToIPNet(vpnv4)
	assert.Equal(t, n5, ipNet)

	_, n6, _ := net.ParseCIDR("2001:db8:53::/64")
	vpnv6, _ := bgp.NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix("2001:db8:53::/64"), *labels, rd)
	ipNet = nlriToIPNet(vpnv6)
	assert.Equal(t, n6, ipNet)
}

func TestUnknownPathAttributes(t *testing.T) {
	peerP := PathCreatePeer()
	pathP := PathCreatePath(peerP)

	type255 := bgp.BGPAttrType(255)
	unknownAttr := bgp.NewPathAttributeUnknown(bgp.BGPAttrFlag(0), type255, []byte{0x01, 0x02, 0x03})
	pathP[0].setPathAttr(unknownAttr)

	// Check if the unknown attribute is present
	assert.NotNil(t, pathP[0].getPathAttr(type255))

	found255 := false
	var last bgp.BGPAttrType
	for _, attr := range pathP[0].GetPathAttrs() {
		assert.NotNil(t, attr)
		if last >= attr.GetType() {
			t.Errorf("Path attributes are not sorted: %v >= %v", last, attr.GetType())
		}
		last = attr.GetType()
		if attr.GetType() == type255 {
			found255 = true
		}
	}
	assert.True(t, found255, "Unknown attribute of type 255 should be present in the path attributes list")
}
