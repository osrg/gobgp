// path_test.go
package table

import (
	"bytes"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/dgryski/go-farm"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	assert.Equal(t, nh, pathP[0].GetNexthop().String())
	// The next hop is kept out of the path attributes.
	assert.Nil(t, pathP[0].getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP))
	pa := pathP[0].getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	require.NotNil(t, pa)
	assert.Equal(t, bgp.BGP_ORIGIN_ATTR_TYPE_IGP, pa.(*bgp.PathAttributeOrigin).Value)
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
	path1.delPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	assert.Nil(t, path1.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC))
	path2 := path1.Clone(false)
	path2.setPathAttr(bgp.NewPathAttributeMultiExitDisc(100))
	assert.NotNil(t, path2.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC))
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

func TestUpdatePathAttrsRTCOriginatorIDWithLocalID(t *testing.T) {
	global := &oc.Global{Config: oc.GlobalConfig{As: 65000, RouterId: netip.MustParseAddr("10.0.0.1")}}
	clusterID := netip.MustParseAddr("10.0.0.100")
	info := &PeerInfo{
		AS:                      65000,
		LocalAS:                 65000,
		LocalAddress:            netip.MustParseAddr("192.168.0.1"),
		RouteReflectorClient:    true,
		RouteReflectorClusterID: clusterID,
		PeerType:                oc.PEER_TYPE_INTERNAL,
	}

	// Case 1: Source with Address (not local) set - should use LocalID as Originator ID
	sourceWithLocalID := &PeerInfo{
		AS:      65000,
		LocalAS: 65000,
		ID:      netip.MustParseAddr("10.0.0.2"),
		LocalID: netip.MustParseAddr("10.0.0.100"), // Different from global RouterId
		Address: netip.MustParseAddr("10.0.0.2"),   // Not local path (IsLocal() == false)
	}
	nlri := bgp.PathNLRI{NLRI: bgp.NewRouteTargetMembershipNLRI(0, nil)}
	nlriAttr, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_RTC_UC, []bgp.PathNLRI{nlri})
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
		nlriAttr,
	}
	pathWithLocalID := NewPath(bgp.RF_RTC_UC, sourceWithLocalID, nlri, false, attrs, time.Now(), false)
	updatedPath1 := UpdatePathAttrs(logger, global, info, pathWithLocalID)

	attr1 := updatedPath1.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGINATOR_ID)
	originatorID1 := attr1.(*bgp.PathAttributeOriginatorId).Value
	assert.True(t, originatorID1.IsValid(), "Originator ID attribute should be set for RTC route")
	assert.Equal(t, "10.0.0.100", originatorID1.String(),
		"Originator ID should be src.LocalID when path is not local")

	// Case 2: Source with LocalID nil - should fall back to global.Config.RouterId
	sourceWithoutLocalID := &PeerInfo{
		AS:      65000,
		LocalAS: 65000,
		ID:      netip.MustParseAddr("10.0.0.2"),
	}
	pathWithoutLocalID := NewPath(bgp.RF_RTC_UC, sourceWithoutLocalID, nlri, false, attrs, time.Now(), false)
	updatedPath2 := UpdatePathAttrs(logger, global, info, pathWithoutLocalID)

	attr2 := updatedPath2.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGINATOR_ID)
	originatorID2 := attr2.(*bgp.PathAttributeOriginatorId).Value
	assert.True(t, originatorID2.IsValid(), "Originator ID attribute should be set for RTC route")
	assert.Equal(t, "10.0.0.1", originatorID2.String(),
		"Originator ID should be global.Config.RouterId when path is local")
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

// attrsHashLikeEagerSites mirrors the eager hash computation used for
// paths originating from ProcessMessage: farm.Hash64 over the serialized
// path attributes excluding MP_REACH_NLRI.
func attrsHashLikeEagerSites(p *Path) uint64 {
	total := bytes.NewBuffer(make([]byte, 0))
	for _, a := range p.GetPathAttrs() {
		if a.GetType() == bgp.BGP_ATTR_TYPE_MP_REACH_NLRI {
			continue
		}
		b, _ := a.Serialize()
		total.Write(b)
	}
	return farm.Hash64(total.Bytes())
}

func mupT1stPath(t *testing.T, teid netip.Addr, nexthop netip.Addr) *Path {
	t.Helper()
	rd := bgp.NewRouteDistinguisherTwoOctetAS(65000, 100)
	nlri := bgp.NewMUPType1SessionTransformedRoute(rd, netip.MustParsePrefix("10.10.10.1/32"), teid, 9, netip.MustParseAddr("10.10.10.1"), nil)
	mpreach, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_MUP_IPv4, []bgp.PathNLRI{{NLRI: nlri}}, nexthop)
	assert.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE),
		mpreach,
	}
	return NewPath(bgp.RF_MUP_IPv4, nil, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
}

func ipv4Path(t *testing.T, nexthop netip.Addr) *Path {
	t.Helper()
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.20.30.0/24"))
	nh, err := bgp.NewPathAttributeNextHop(nexthop)
	assert.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE),
		nh,
	}
	return NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
}

func TestPathEqual(t *testing.T) {
	teid1 := netip.MustParseAddr("0.0.0.100")
	teid2 := netip.MustParseAddr("0.0.0.200")
	nh1 := netip.MustParseAddr("10.0.0.1")
	nh2 := netip.MustParseAddr("10.0.0.2")

	t.Run("same pointer", func(t *testing.T) {
		p := ipv4Path(t, nh1)
		assert.True(t, p.Equal(p))
	})

	t.Run("clone", func(t *testing.T) {
		p := ipv4Path(t, nh1)
		assert.True(t, p.Equal(p.Clone(false)))
	})

	t.Run("identical, independently built", func(t *testing.T) {
		assert.True(t, ipv4Path(t, nh1).Equal(ipv4Path(t, nh1)))
		assert.True(t, mupT1stPath(t, teid1, nh1).Equal(mupT1stPath(t, teid1, nh1)))
	})

	t.Run("NEXT_HOP attribute differs", func(t *testing.T) {
		assert.False(t, ipv4Path(t, nh1).Equal(ipv4Path(t, nh2)))
	})

	t.Run("MP_REACH nexthop differs", func(t *testing.T) {
		lhs := mupT1stPath(t, teid1, nh1)
		rhs := mupT1stPath(t, teid1, nh2)
		// eager hashes collide because MP_REACH_NLRI is excluded from them
		lhs.SetHash(attrsHashLikeEagerSites(lhs))
		rhs.SetHash(attrsHashLikeEagerSites(rhs))
		assert.Equal(t, lhs.GetHash(), rhs.GetHash())
		assert.False(t, lhs.Equal(rhs))
	})

	t.Run("MP_REACH nexthop differs with NEXT_HOP present", func(t *testing.T) {
		// an UPDATE carrying both IPv4 NLRI and MP_REACH_NLRI is valid; the MP
		// paths built from it then hold a NEXT_HOP attribute alongside MP_REACH
		newMixedPath := func(mpNexthop string) *Path {
			nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:db8:10::/64"))
			panh, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
			mpreach, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri}},
				netip.MustParseAddr(mpNexthop))
			assert.NoError(t, err)
			attrs := []bgp.PathAttributeInterface{
				bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE),
				panh,
				mpreach,
			}
			p := NewPath(bgp.RF_IPv6_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
			p.SetHash(attrsHashLikeEagerSites(p))
			return p
		}
		lhs := newMixedPath("2001:db8::1")
		rhs := newMixedPath("2001:db8::2")
		assert.Equal(t, lhs.GetHash(), rhs.GetHash())
		assert.False(t, lhs.Equal(rhs))
	})

	t.Run("MP_REACH link-local nexthop differs", func(t *testing.T) {
		newV6Path := func(ll string) *Path {
			nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:db8:10::/64"))
			mpreach, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri}},
				netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr(ll))
			assert.NoError(t, err)
			attrs := []bgp.PathAttributeInterface{
				bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE),
				mpreach,
			}
			p := NewPath(bgp.RF_IPv6_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
			p.SetHash(attrsHashLikeEagerSites(p))
			return p
		}
		lhs := newV6Path("fe80::1")
		rhs := newV6Path("fe80::2")
		assert.Equal(t, lhs.GetHash(), rhs.GetHash())
		assert.Equal(t, lhs.GetNexthop(), rhs.GetNexthop())
		assert.False(t, lhs.Equal(rhs))
	})

	t.Run("NLRI payload outside the route key differs", func(t *testing.T) {
		lhs := mupT1stPath(t, teid1, nh1)
		rhs := mupT1stPath(t, teid2, nh1)
		// same route key (TEID is not part of it), same eager hash
		assert.Equal(t, lhs.GetNlri().String(), rhs.GetNlri().String())
		lhs.SetHash(attrsHashLikeEagerSites(lhs))
		rhs.SetHash(attrsHashLikeEagerSites(rhs))
		assert.Equal(t, lhs.GetHash(), rhs.GetHash())
		assert.False(t, lhs.Equal(rhs))
	})
}

// A path hashed eagerly in ProcessMessage and an identical one hashed
// lazily via updateHash must produce the same value, or Equal reports a
// spurious difference.
func TestPathAttrsHashConsistency(t *testing.T) {
	teid := netip.MustParseAddr("0.0.0.100")
	nh := netip.MustParseAddr("10.0.0.1")

	eager := mupT1stPath(t, teid, nh)
	eager.SetHash(attrsHashLikeEagerSites(eager))
	lazy := mupT1stPath(t, teid, nh)

	assert.Equal(t, eager.GetHash(), lazy.GetHash())
	assert.True(t, eager.Equal(lazy))
}

func linkLocalNexthopPath(t *testing.T, source *PeerInfo, nexthops ...netip.Addr) *Path {
	t.Helper()

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:db8:1::/64"))
	pathnlri := bgp.PathNLRI{NLRI: nlri}
	mpreach, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{pathnlri}, nexthops...)
	assert.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
		bgp.NewPathAttributeAsPath(nil),
		bgp.NewPathAttributeLocalPref(DEFAULT_LOCAL_PREF),
		mpreach,
	}
	return NewPath(bgp.RF_IPv6_UC, source, pathnlri, false, attrs, time.Now(), false)
}

func TestUpdatePathAttrsLinkLocalNexthop(t *testing.T) {
	global := &oc.Global{Config: oc.GlobalConfig{As: 65000, RouterId: netip.MustParseAddr("10.0.0.1")}}

	unspecified := netip.MustParseAddr("::")
	globalNexthop := netip.MustParseAddr("2001:db8::1")
	linkLocal := netip.MustParseAddr("fe80::ade0")

	// The peer the path was learned from, reachable over eth0.
	onLink := &PeerInfo{
		AS:      65000,
		LocalAS: 65000,
		ID:      netip.MustParseAddr("10.0.0.2"),
		Address: netip.MustParseAddr("fe80::ade0%eth0"),
	}
	// A peer on the same link as onLink.
	sameLink := &PeerInfo{
		AS:           65000,
		LocalAS:      65000,
		PeerType:     oc.PEER_TYPE_INTERNAL,
		Address:      netip.MustParseAddr("fe80::ade2%eth0"),
		LocalAddress: netip.MustParseAddr("fe80::ade1%eth0"),
	}
	// A peer on another link.
	otherLink := &PeerInfo{
		AS:           65000,
		LocalAS:      65000,
		PeerType:     oc.PEER_TYPE_INTERNAL,
		Address:      netip.MustParseAddr("fe80::beef%eth1"),
		LocalAddress: netip.MustParseAddr("fe80::cafe%eth1"),
	}
	// A peer reachable over a global address, so gobgp does not know its link.
	globalPeer := &PeerInfo{
		AS:           65000,
		LocalAS:      65000,
		PeerType:     oc.PEER_TYPE_INTERNAL,
		Address:      netip.MustParseAddr("2001:db8::2"),
		LocalAddress: netip.MustParseAddr("2001:db8::3"),
	}

	for _, tt := range []struct {
		name          string
		source        *PeerInfo
		info          *PeerInfo
		nexthops      []netip.Addr
		wantNexthop   netip.Addr
		wantLinkLocal netip.Addr
	}{
		{
			name:          "unspecified global kept on the same link",
			source:        onLink,
			info:          sameLink,
			nexthops:      []netip.Addr{unspecified, linkLocal},
			wantNexthop:   unspecified,
			wantLinkLocal: linkLocal,
		},
		{
			name:        "unspecified global replaced on another link",
			source:      onLink,
			info:        otherLink,
			nexthops:    []netip.Addr{unspecified, linkLocal},
			wantNexthop: netip.MustParseAddr("fe80::cafe"),
		},
		{
			name:        "unspecified global replaced for a peer on an unknown link",
			source:      onLink,
			info:        globalPeer,
			nexthops:    []netip.Addr{unspecified, linkLocal},
			wantNexthop: netip.MustParseAddr("2001:db8::3"),
		},
		{
			name:          "link-local in the global part kept on the same link",
			source:        onLink,
			info:          sameLink,
			nexthops:      []netip.Addr{linkLocal, linkLocal},
			wantNexthop:   linkLocal,
			wantLinkLocal: linkLocal,
		},
		{
			name:        "link-local in the global part replaced on another link",
			source:      onLink,
			info:        otherLink,
			nexthops:    []netip.Addr{linkLocal, linkLocal},
			wantNexthop: netip.MustParseAddr("fe80::cafe"),
		},
		{
			name:        "link-local alone replaced on another link",
			source:      onLink,
			info:        otherLink,
			nexthops:    []netip.Addr{linkLocal},
			wantNexthop: netip.MustParseAddr("fe80::cafe"),
		},
		{
			name:        "link-local alone kept on the same link",
			source:      onLink,
			info:        sameLink,
			nexthops:    []netip.Addr{linkLocal},
			wantNexthop: linkLocal,
		},
		{
			name:        "link-local alone set by the operator is kept",
			source:      nil,
			info:        otherLink,
			nexthops:    []netip.Addr{linkLocal},
			wantNexthop: linkLocal,
		},
		{
			name:          "global and link-local kept on the same link",
			source:        onLink,
			info:          sameLink,
			nexthops:      []netip.Addr{globalNexthop, linkLocal},
			wantNexthop:   globalNexthop,
			wantLinkLocal: linkLocal,
		},
		{
			name:        "link-local dropped on another link",
			source:      onLink,
			info:        otherLink,
			nexthops:    []netip.Addr{globalNexthop, linkLocal},
			wantNexthop: globalNexthop,
		},
		{
			name:          "link-local set by the operator is kept",
			source:        nil,
			info:          otherLink,
			nexthops:      []netip.Addr{globalNexthop, linkLocal},
			wantNexthop:   globalNexthop,
			wantLinkLocal: linkLocal,
		},
		{
			name:        "unspecified global of a local path is replaced",
			source:      nil,
			info:        otherLink,
			nexthops:    []netip.Addr{unspecified, linkLocal},
			wantNexthop: netip.MustParseAddr("fe80::cafe"),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := linkLocalNexthopPath(t, tt.source, tt.nexthops...)
			updated := UpdatePathAttrs(logger, global, tt.info, path)

			assert.Equal(t, Nexthops{global: tt.wantNexthop, linkLocal: tt.wantLinkLocal}, updated.nexthops())
		})
	}
}

// AdjRib.StaleAll marks a clone stale, and MarkStale writes through
// Path.root(). The watcher goroutines read the same field with IsStale() on
// their own clone of that root, and no lock covers both sides. Check that the
// two do not race.
func TestMarkStaleIsRaceFree(t *testing.T) {
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}
	root := NewPath(bgp.RF_IPv4_UC, &PeerInfo{}, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)

	// What clonePathList() hands to a watcher.
	watched := root.Clone(false)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 1000 {
			// What AdjRib.StaleAll() does.
			n := root.Clone(false)
			n.MarkStale(true)
		}
	}()
	go func() {
		defer wg.Done()
		for range 1000 {
			// What toPathApiUtil() does in the watcher goroutine.
			_ = watched.IsStale()
		}
	}()
	wg.Wait()

	assert.True(t, watched.IsStale())
}

func TestNlriToPrefix(t *testing.T) {
	rd, _ := bgp.ParseRouteDistinguisher("100:100")
	evpn := func(prefix string, bits uint8) bgp.NLRI {
		n, _ := bgp.NewEVPNIPPrefixRoute(rd, bgp.EthernetSegmentIdentifier{}, 0, bits, netip.MustParseAddr(prefix), netip.IPv4Unspecified(), 100)
		return n
	}
	labels := bgp.NewMPLSLabelStack(100, 200)
	ip, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("30.30.30.0/24"))
	mpls, _ := bgp.NewLabeledIPAddrPrefix(netip.MustParsePrefix("30.30.30.0/24"), *labels)
	vpn, _ := bgp.NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix("30.30.30.0/24"), *labels, rd)
	macIP, _ := bgp.NewEVPNMacIPAdvertisementRoute(rd, bgp.EthernetSegmentIdentifier{}, 0, "00:11:22:33:44:55", netip.MustParseAddr("30.30.30.1"), nil)
	macIPv6, _ := bgp.NewEVPNMacIPAdvertisementRoute(rd, bgp.EthernetSegmentIdentifier{}, 0, "00:11:22:33:44:55", netip.MustParseAddr("2001:db8::1"), nil)
	macOnly, _ := bgp.NewEVPNMacIPAdvertisementRoute(rd, bgp.EthernetSegmentIdentifier{}, 0, "00:11:22:33:44:55", netip.Addr{}, nil)

	tests := []struct {
		name string
		nlri bgp.NLRI
		want netip.Prefix
	}{
		{"ipv4", ip, netip.MustParsePrefix("30.30.30.0/24")},
		{"labeled", mpls, netip.MustParsePrefix("30.30.30.0/24")},
		{"labeled vpn", vpn, netip.MustParsePrefix("30.30.30.0/24")},
		{"evpn type 5 v4", evpn("30.30.30.0", 24), netip.MustParsePrefix("30.30.30.0/24")},
		{"evpn type 5 v6", evpn("2806:106e:19::", 48), netip.MustParsePrefix("2806:106e:19::/48")},
		{"evpn type 2 v4", macIP, netip.MustParsePrefix("30.30.30.1/32")},
		{"evpn type 2 v6", macIPv6, netip.MustParsePrefix("2001:db8::1/128")},
		{"evpn type 2 mac only", macOnly, netip.Prefix{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nlriToPrefix(tt.nlri)
			assert.Equal(t, tt.want.IsValid(), got.IsValid())
			if tt.want.IsValid() {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

// Two VRFs with the same prefix give two VPN routes that differ only in the
// RD. After ToGlobalPath, their destination keys have to differ too.
// Otherwise one hides the other wherever the key is used, for example when
// an UPDATE is built from both.
func TestToGlobalPathKeepsRDInKey(t *testing.T) {
	rt, _ := bgp.ParseRouteTarget("100:100")
	newGlobal := func(rd string) *Path {
		r, err := bgp.ParseRouteDistinguisher(rd)
		assert.NoError(t, err)
		v := &Vrf{Name: rd, Rd: r, ExportRt: []bgp.ExtendedCommunityInterface{rt}}
		nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("20.0.0.0/24"))
		nh, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.0.2.1"))
		p := NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false,
			[]bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh}, time.Now(), false)
		assert.NoError(t, v.ToGlobalPath(p))
		return p
	}
	p1 := newGlobal("100:100")
	p2 := newGlobal("300:300")

	assert.Equal(t, "100:100:20.0.0.0/24", p1.GetDestLocalKey().Prefix)
	assert.Equal(t, "300:300:20.0.0.0/24", p2.GetDestLocalKey().Prefix)
	assert.NotEqual(t, p1.GetLocalKey(), p2.GetLocalKey())

	n := 0
	for _, msg := range CreateUpdateMsgFromPaths([]*Path{p1, p2}) {
		for _, a := range msg.Body.(*bgp.BGPUpdate).PathAttributes {
			if mp, ok := a.(*bgp.PathAttributeMpReachNLRI); ok {
				n += len(mp.Value)
			}
		}
	}
	assert.Equal(t, 2, n, "both routes must be in the UPDATE")
}

// RFC 7311 3.3 disables AIGP by default on an eBGP session that is not a
// confederation one, and gobgp has no knob to enable it, so the attribute
// is neither sent on nor passed along from such a session.
func TestUpdatePathAttrsAigp(t *testing.T) {
	global := &oc.Global{
		Config:        oc.GlobalConfig{As: 65000, RouterId: netip.MustParseAddr("10.0.0.1")},
		Confederation: oc.Confederation{Config: oc.ConfederationConfig{MemberAsList: []uint32{65001}}},
	}

	internal := &PeerInfo{
		AS:       65000,
		LocalAS:  65000,
		PeerType: oc.PEER_TYPE_INTERNAL,
		ID:       netip.MustParseAddr("10.0.0.2"),
		Address:  netip.MustParseAddr("10.0.0.2"),
	}
	confed := &PeerInfo{
		AS:            65001,
		LocalAS:       65000,
		PeerType:      oc.PEER_TYPE_EXTERNAL,
		Confederation: true,
		ID:            netip.MustParseAddr("10.0.0.3"),
		Address:       netip.MustParseAddr("10.0.0.3"),
	}
	external := &PeerInfo{
		AS:       65100,
		LocalAS:  65000,
		PeerType: oc.PEER_TYPE_EXTERNAL,
		ID:       netip.MustParseAddr("10.0.0.4"),
		Address:  netip.MustParseAddr("10.0.0.4"),
	}
	local := &PeerInfo{}

	for _, tt := range []struct {
		name   string
		source *PeerInfo
		info   *PeerInfo
		want   bool
	}{
		{"local to internal", local, internal, true},
		{"local to confederation", local, confed, true},
		{"local to external", local, external, false},
		{"internal to internal", internal, internal, true},
		{"internal to confederation", internal, confed, true},
		{"internal to external", internal, external, false},
		{"confederation to internal", confed, internal, true},
		{"external to internal", external, internal, false},
		{"external to confederation", external, confed, false},
		{"external to external", external, external, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.0.0/24"))
			nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.0.2.1"))
			attrs := []bgp.PathAttributeInterface{
				bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
				bgp.NewPathAttributeAsPath(nil),
				nexthop,
				bgp.NewPathAttributeAigp([]bgp.AigpTLVInterface{bgp.NewAigpTLVIgpMetric(0)}),
			}
			path := NewPath(bgp.RF_IPv4_UC, tt.source, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
			updated := UpdatePathAttrs(logger, global, tt.info, path)

			assert.Equal(t, tt.want, updated.getPathAttr(bgp.BGP_ATTR_TYPE_AIGP) != nil)
		})
	}
}

func TestUpdatePathAttrsReflectToNonClient(t *testing.T) {
	global := &oc.Global{Config: oc.GlobalConfig{As: 65000, RouterId: netip.MustParseAddr("10.0.0.1")}}
	clusterID := netip.MustParseAddr("10.0.0.100")

	client := &PeerInfo{
		AS:                      65000,
		LocalAS:                 65000,
		PeerType:                oc.PEER_TYPE_INTERNAL,
		ID:                      netip.MustParseAddr("10.0.0.2"),
		Address:                 netip.MustParseAddr("10.0.0.2"),
		RouteReflectorClient:    true,
		RouteReflectorClusterID: clusterID,
	}
	nonClient := &PeerInfo{
		AS:       65000,
		LocalAS:  65000,
		PeerType: oc.PEER_TYPE_INTERNAL,
		ID:       netip.MustParseAddr("10.0.0.3"),
		Address:  netip.MustParseAddr("10.0.0.3"),
	}
	external := &PeerInfo{
		AS:       65100,
		LocalAS:  65000,
		PeerType: oc.PEER_TYPE_EXTERNAL,
		ID:       netip.MustParseAddr("10.0.0.4"),
		Address:  netip.MustParseAddr("10.0.0.4"),
	}

	newPath := func(source *PeerInfo, extra ...bgp.PathAttributeInterface) *Path {
		nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.0.0/24"))
		nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.0.2.1"))
		attrs := append([]bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
			bgp.NewPathAttributeAsPath(nil),
			nexthop,
		}, extra...)
		return NewPath(bgp.RF_IPv4_UC, source, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
	}

	t.Run("from a client", func(t *testing.T) {
		updated := UpdatePathAttrs(logger, global, nonClient, newPath(client))
		assert.Equal(t, client.ID, updated.GetOriginatorID())
		assert.Equal(t, []netip.Addr{clusterID}, updated.GetClusterList())
	})

	t.Run("from a client that reflected it", func(t *testing.T) {
		originator, _ := bgp.NewPathAttributeOriginatorId(netip.MustParseAddr("10.0.0.5"))
		list, _ := bgp.NewPathAttributeClusterList([]netip.Addr{netip.MustParseAddr("10.0.0.200")})
		updated := UpdatePathAttrs(logger, global, nonClient, newPath(client, originator, list))
		assert.Equal(t, netip.MustParseAddr("10.0.0.5"), updated.GetOriginatorID())
		assert.Equal(t, []netip.Addr{clusterID, netip.MustParseAddr("10.0.0.200")}, updated.GetClusterList())
	})

	t.Run("from an external peer", func(t *testing.T) {
		updated := UpdatePathAttrs(logger, global, nonClient, newPath(external))
		assert.False(t, updated.GetOriginatorID().IsValid())
		assert.Empty(t, updated.GetClusterList())
	})
}
