// path_test.go
package table

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/osrg/gobgp/v3/pkg/config/oc"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
)

func TestPathNewIPv4(t *testing.T) {
	peerP := PathCreatePeer()
	pathP := PathCreatePath(peerP)
	ipv4p := NewPath(pathP[0].GetSource(), pathP[0].GetNlri(), true, pathP[0].GetPathAttrs(), time.Now(), false)
	assert.NotNil(t, ipv4p)
}

func TestPathNewIPv6(t *testing.T) {
	peerP := PathCreatePeer()
	pathP := PathCreatePath(peerP)
	ipv6p := NewPath(pathP[0].GetSource(), pathP[0].GetNlri(), true, pathP[0].GetPathAttrs(), time.Now(), false)
	assert.NotNil(t, ipv6p)
}

func TestPathGetNlri(t *testing.T) {
	nlri := bgp.NewIPAddrPrefix(24, "13.2.3.2")
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
	path := NewPath(peerP[0], nlri_info, false, pathAttributes, time.Now(), false)
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
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET, []uint16{65100, 65101})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("192.168.50.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med,
	}

	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.10.0")}
	bgpmsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(logger, update)
	peer := PathCreatePeer()
	p := NewPath(peer[0], update.NLRI[0], false, update.PathAttributes, time.Now(), false)
	assert.Equal(10, p.GetAsPathLen())
}

func TestPathPrependAsnToExistingSeqAttr(t *testing.T) {
	assert := assert.New(t)
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint16{65001, 65002, 65003, 65004, 65005}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SET, []uint16{65001, 65002, 65003, 65004, 65005}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ, []uint16{65100, 65101, 65102}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET, []uint16{65100, 65101})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("192.168.50.1")

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
	}

	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.10.0")}
	bgpmsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(logger, update)
	peer := PathCreatePeer()
	p := NewPath(peer[0], update.NLRI[0], false, update.PathAttributes, time.Now(), false)

	p.PrependAsn(65000, 1, false)
	assert.Equal([]uint32{65000, 65001, 65002, 65003, 65004, 65005, 0, 0, 0}, p.GetAsSeqList())
}

func TestPathPrependAsnToNewAsPathAttr(t *testing.T) {
	assert := assert.New(t)
	origin := bgp.NewPathAttributeOrigin(0)
	nexthop := bgp.NewPathAttributeNextHop("192.168.50.1")

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		nexthop,
	}

	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.10.0")}
	bgpmsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(logger, update)
	peer := PathCreatePeer()
	p := NewPath(peer[0], update.NLRI[0], false, update.PathAttributes, time.Now(), false)

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
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET, []uint16{65100, 65101})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("192.168.50.1")

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
	}

	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.10.0")}
	bgpmsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(logger, update)
	peer := PathCreatePeer()
	p := NewPath(peer[0], update.NLRI[0], false, update.PathAttributes, time.Now(), false)

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
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET, []uint16{65100, 65101})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("192.168.50.1")

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
	}

	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.10.0")}
	bgpmsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(logger, update)
	peer := PathCreatePeer()
	p := NewPath(peer[0], update.NLRI[0], false, update.PathAttributes, time.Now(), false)

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
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET, []uint16{65100, 65101})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("192.168.50.1")

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
	}

	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.10.0")}
	bgpmsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(logger, update)
	peer := PathCreatePeer()
	p := NewPath(peer[0], update.NLRI[0], false, update.PathAttributes, time.Now(), false)

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
	path2.setPathAttr(bgp.NewPathAttributeNextHop("192.168.50.1"))
	assert.NotNil(t, path2.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP))
}

func Test_ToGlobalPath_IPv4(t *testing.T) {
	vrf := &Vrf{
		Rd:                        bgp.NewRouteDistinguisherTwoOctetAS(100, 100),
		ImportToGlobalAsEvpnType5: false,
		MplsLabel:                 100,
	}

	prefix := "192.168.1.0/24"
	_, network, _ := net.ParseCIDR(prefix)
	prefixLen, _ := network.Mask.Size()

	path := NewPath(nil, bgp.NewIPAddrPrefix(uint8(prefixLen), network.IP.String()), false, []bgp.PathAttributeInterface{}, time.Now(), false)

	err := vrf.ToGlobalPath(path)
	assert.NoError(t, err)

	nlri := path.GetNlri()
	family := path.GetRouteFamily()
	assert.Equal(t, bgp.RF_IPv4_VPN, family)
	vpnNlri := nlri.(*bgp.LabeledVPNIPAddrPrefix)
	assert.Equal(t, prefix, vpnNlri.IPPrefix())
	assert.Equal(t, vrf.Rd, vpnNlri.RD)
}

func Test_ToGlobalPath_IPv4_EVPN(t *testing.T) {
	vrf := &Vrf{
		Rd:                        bgp.NewRouteDistinguisherTwoOctetAS(100, 100),
		ImportToGlobalAsEvpnType5: true,
		EthernetTag:               100,
	}

	prefix := "192.168.1.0/24"
	_, network, _ := net.ParseCIDR(prefix)
	prefixLen, _ := network.Mask.Size()

	path := NewPath(nil, bgp.NewIPAddrPrefix(uint8(prefixLen), network.IP.String()), false, []bgp.PathAttributeInterface{}, time.Now(), false)

	err := vrf.ToGlobalPath(path)
	assert.NoError(t, err)

	family := path.GetRouteFamily()
	assert.Equal(t, bgp.RF_EVPN, family)
	nlri := path.GetNlri()
	evpnNlri := nlri.(*bgp.EVPNNLRI)
	assert.Equal(t, bgp.EVPN_IP_PREFIX, int(evpnNlri.RouteType))
	ipPrefix := evpnNlri.RouteTypeData.(*bgp.EVPNIPPrefixRoute)
	assert.Equal(t, vrf.Rd, ipPrefix.RD)
	assert.Equal(t, vrf.EthernetTag, ipPrefix.ETag)
}

func Test_ToGlobal_IPv4(t *testing.T) {
	vrf := &Vrf{
		Rd:                        bgp.NewRouteDistinguisherTwoOctetAS(100, 100),
		ImportToGlobalAsEvpnType5: false,
		MplsLabel:                 100,
	}

	prefix := "192.168.1.0/24"
	_, network, _ := net.ParseCIDR(prefix)
	prefixLen, _ := network.Mask.Size()

	original := NewPath(nil, bgp.NewIPAddrPrefix(uint8(prefixLen), network.IP.String()), false, []bgp.PathAttributeInterface{}, time.Now(), false)
	path := original.ToGlobal(vrf)

	nlri := path.GetNlri()
	family := path.GetRouteFamily()
	assert.Equal(t, bgp.RF_IPv4_VPN, family)
	vpnNlri := nlri.(*bgp.LabeledVPNIPAddrPrefix)
	assert.Equal(t, prefix, vpnNlri.IPPrefix())
	assert.Equal(t, vrf.Rd, vpnNlri.RD)
}

func Test_ToLocal_IPv4VPN(t *testing.T) {
	rd := bgp.NewRouteDistinguisherTwoOctetAS(100, 100)
	prefix := "192.168.1.0/24"
	_, network, _ := net.ParseCIDR(prefix)
	prefixLen, _ := network.Mask.Size()

	labels := []uint32{100}
	mpls := bgp.NewMPLSLabelStack(labels...)
	original := NewPath(nil, bgp.NewLabeledVPNIPAddrPrefix(uint8(prefixLen), network.IP.String(), *mpls, rd), false, []bgp.PathAttributeInterface{}, time.Now(), false)

	path := original.ToLocal()
	nlri := path.GetNlri()
	family := path.GetRouteFamily()
	assert.Equal(t, bgp.RF_IPv4_UC, family)
	ipNlri := nlri.(*bgp.IPAddrPrefix)
	assert.Equal(t, prefix, ipNlri.String())
}

func Test_ToLocal_EVPN_IPPrefix(t *testing.T) {
	rd := bgp.NewRouteDistinguisherTwoOctetAS(100, 100)
	esi, _ := bgp.ParseEthernetSegmentIdentifier([]string{"single-homed"})
	prefix := "192.168.1.0"
	prefixLen := uint8(24)
	tag := uint32(100)

	original := NewPath(nil, bgp.NewEVPNIPPrefixRoute(rd, esi, tag, prefixLen, prefix, "0.0.0.0", 0), false, []bgp.PathAttributeInterface{}, time.Now(), false)

	path := original.ToLocal()
	nlri := path.GetNlri()
	family := path.GetRouteFamily()
	assert.Equal(t, bgp.RF_IPv4_UC, family)
	ipNlri := nlri.(*bgp.IPAddrPrefix)
	assert.Equal(t, fmt.Sprintf("%s/%d", prefix, prefixLen), ipNlri.String())
}

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
		pathP[i] = NewPath(peerP[i], nlri_info, false, pathAttributes, time.Now(), false)
	}
	return pathP
}

func updateMsgP1() *bgp.BGPMessage {

	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65000})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("192.168.50.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med,
	}

	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.10.0")}
	return bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
}

func updateMsgP2() *bgp.BGPMessage {

	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65100})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("192.168.100.1")
	med := bgp.NewPathAttributeMultiExitDisc(100)

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med,
	}

	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "20.20.20.0")}
	return bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
}

func updateMsgP3() *bgp.BGPMessage {
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65100})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("192.168.150.1")
	med := bgp.NewPathAttributeMultiExitDisc(100)

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med,
	}

	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "30.30.30.0")}
	w1 := bgp.NewIPAddrPrefix(23, "40.40.40.0")
	withdrawnRoutes := []*bgp.IPAddrPrefix{w1}
	return bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
}

func TestRemovePrivateAS(t *testing.T) {
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{64512, 64513, 1, 2})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nlri := bgp.NewIPAddrPrefix(24, "30.30.30.0")
	path := NewPath(nil, nlri, false, []bgp.PathAttributeInterface{aspath}, time.Now(), false)
	path.RemovePrivateAS(10, oc.REMOVE_PRIVATE_AS_OPTION_ALL)
	list := path.GetAsList()
	assert.Equal(t, len(list), 2)
	assert.Equal(t, list[0], uint32(1))
	assert.Equal(t, list[1], uint32(2))

	path = NewPath(nil, nlri, false, []bgp.PathAttributeInterface{aspath}, time.Now(), false)
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
	nlri := bgp.NewIPAddrPrefix(24, "30.30.30.0")
	path := NewPath(nil, nlri, false, []bgp.PathAttributeInterface{aspath}, time.Now(), false)
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
	ipNet := nlriToIPNet(bgp.NewIPAddrPrefix(24, "30.30.30.0"))
	assert.Equal(t, n1, ipNet)

	_, n2, _ := net.ParseCIDR("2806:106e:19::/48")
	ipNet = nlriToIPNet(bgp.NewIPv6AddrPrefix(48, "2806:106e:19::"))
	assert.Equal(t, n2, ipNet)

	labels := bgp.NewMPLSLabelStack(100, 200)
	_, n3, _ := net.ParseCIDR("30.30.30.0/24")
	ipNet = nlriToIPNet(bgp.NewLabeledIPAddrPrefix(24, "30.30.30.0", *labels))
	assert.Equal(t, n3, ipNet)

	_, n4, _ := net.ParseCIDR("2806:106e:19::/48")
	ipNet = nlriToIPNet(bgp.NewLabeledIPv6AddrPrefix(48, "2806:106e:19::", *labels))
	assert.Equal(t, n4, ipNet)

	rd, _ := bgp.ParseRouteDistinguisher("100:100")
	_, n5, _ := net.ParseCIDR("40.40.40.0/24")
	ipNet = nlriToIPNet(bgp.NewLabeledVPNIPAddrPrefix(24, "40.40.40.0", *labels, rd))
	assert.Equal(t, n5, ipNet)

	_, n6, _ := net.ParseCIDR("2001:db8:53::/64")
	ipNet = nlriToIPNet(bgp.NewLabeledVPNIPv6AddrPrefix(64, "2001:db8:53::", *labels, rd))
	assert.Equal(t, n6, ipNet)
}
