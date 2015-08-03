// path_test.go
package table

import (
	//"fmt"
	"fmt"
	"testing"
	"time"

	"github.com/osrg/gobgp/packet"
	"github.com/stretchr/testify/assert"
)

func TestPathNewIPv4(t *testing.T) {
	peerP := PathCreatePeer()
	pathP := PathCreatePath(peerP)
	ipv4p := NewPath(pathP[0].GetSource(), pathP[0].GetNlri(), true, pathP[0].GetPathAttrs(), pathP[0].getMedSetByTargetNeighbor(), time.Now(), false)
	assert.NotNil(t, ipv4p)
}
func TestPathNewIPv6(t *testing.T) {
	peerP := PathCreatePeer()
	pathP := PathCreatePath(peerP)
	ipv6p := NewPath(pathP[0].GetSource(), pathP[0].GetNlri(), true, pathP[0].GetPathAttrs(), pathP[0].getMedSetByTargetNeighbor(), time.Now(), false)
	assert.NotNil(t, ipv6p)
}

func TestPathSetSource(t *testing.T) {
	pd := &Path{}
	pr := &PeerInfo{AS: 65000}
	pd.setSource(pr)
	r_pr := pd.GetSource()
	assert.Equal(t, r_pr, pr)
}

func TestPathGetSource(t *testing.T) {
	pd := &Path{}
	pr := &PeerInfo{AS: 65001}
	pd.setSource(pr)
	r_pr := pd.GetSource()
	assert.Equal(t, r_pr, pr)
}

func TestPathGetNlri(t *testing.T) {
	nlri := bgp.NewNLRInfo(24, "13.2.3.2")
	pd := &Path{
		nlri: nlri,
	}
	r_nlri := pd.GetNlri()
	assert.Equal(t, r_nlri, nlri)
}

func TestPathSetMedSetByTargetNeighbor(t *testing.T) {
	pd := &Path{}
	msbt := true
	pd.setMedSetByTargetNeighbor(msbt)
	r_msbt := pd.getMedSetByTargetNeighbor()
	assert.Equal(t, r_msbt, msbt)
}

func TestPathGetMedSetByTargetNeighbor(t *testing.T) {
	pd := &Path{}
	msbt := true
	pd.setMedSetByTargetNeighbor(msbt)
	r_msbt := pd.getMedSetByTargetNeighbor()
	assert.Equal(t, r_msbt, msbt)
}

func TestPathCreatePath(t *testing.T) {
	peerP := PathCreatePeer()
	msg := updateMsgP1()
	updateMsgP := msg.Body.(*bgp.BGPUpdate)
	nlriList := updateMsgP.NLRI
	pathAttributes := updateMsgP.PathAttributes
	nlri_info := nlriList[0]
	path := NewPath(peerP[0], &nlri_info, false, pathAttributes, false, time.Now(), false)
	assert.NotNil(t, path)

}

func TestPathGetPrefix(t *testing.T) {
	peerP := PathCreatePeer()
	pathP := PathCreatePath(peerP)
	prefix := "10.10.10.0/24"
	r_prefix := pathP[0].getPrefix()
	assert.Equal(t, r_prefix, prefix)
}
func TestPathGetAttribute(t *testing.T) {
	peerP := PathCreatePeer()
	pathP := PathCreatePath(peerP)
	nh := "192.168.50.1"
	_, pa := pathP[0].getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
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

	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.10.0")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	bgpmsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(update)
	peer := PathCreatePeer()
	p := NewPath(peer[0], &update.NLRI[0], false, update.PathAttributes, false, time.Now(), false)
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

	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.10.0")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	bgpmsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(update)
	peer := PathCreatePeer()
	p := NewPath(peer[0], &update.NLRI[0], false, update.PathAttributes, false, time.Now(), false)

	p.PrependAsn(65000, 1)
	assert.Equal([]uint32{65000, 65001, 65002, 65003, 65004, 65005}, p.GetAsSeqList())
	fmt.Printf("asns: %v", p.GetAsSeqList())
}

func TestPathPrependAsnToNewAsPathAttr(t *testing.T) {
	assert := assert.New(t)
	origin := bgp.NewPathAttributeOrigin(0)
	nexthop := bgp.NewPathAttributeNextHop("192.168.50.1")

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		nexthop,
	}

	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.10.0")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	bgpmsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(update)
	peer := PathCreatePeer()
	p := NewPath(peer[0], &update.NLRI[0], false, update.PathAttributes, false, time.Now(), false)

	asn := uint32(65000)
	p.PrependAsn(asn, 1)
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

	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.10.0")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	bgpmsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(update)
	peer := PathCreatePeer()
	p := NewPath(peer[0], &update.NLRI[0], false, update.PathAttributes, false, time.Now(), false)

	asn := uint32(65000)
	p.PrependAsn(asn, 1)
	assert.Equal([]uint32{asn}, p.GetAsSeqList())
	fmt.Printf("asns: %v", p.GetAsSeqList())
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

	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.10.0")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	bgpmsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(update)
	peer := PathCreatePeer()
	p := NewPath(peer[0], &update.NLRI[0], false, update.PathAttributes, false, time.Now(), false)

	asn := uint32(65000)
	p.PrependAsn(asn, 1)
	assert.Equal([]uint32{asn}, p.GetAsSeqList())
	fmt.Printf("asns: %v", p.GetAsSeqList())
}

func TestPathPrependAsnToFullPathAttr(t *testing.T) {
	assert := assert.New(t)
	origin := bgp.NewPathAttributeOrigin(0)

	asns := make([]uint16, 255)
	for i, _ := range asns {
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

	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.10.0")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	bgpmsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(update)
	peer := PathCreatePeer()
	p := NewPath(peer[0], &update.NLRI[0], false, update.PathAttributes, false, time.Now(), false)

	expected := []uint32{65000, 65000}
	for _, v := range asns {
		expected = append(expected, uint32(v))
	}
	p.PrependAsn(65000, 2)
	assert.Equal(expected, p.GetAsSeqList())
	fmt.Printf("asns: %v", p.GetAsSeqList())
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
		pathP[i] = NewPath(peerP[i], &nlri_info, false, pathAttributes, false, time.Now(), false)
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

	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.10.0")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	return bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
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

	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "20.20.20.0")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	return bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
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

	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "30.30.30.0")}
	w1 := bgp.WithdrawnRoute{*bgp.NewIPAddrPrefix(23, "40.40.40.0")}
	withdrawnRoutes := []bgp.WithdrawnRoute{w1}
	return bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
}
