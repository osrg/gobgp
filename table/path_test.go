// path_test.go
package table

import (
	//"fmt"
	"github.com/osrg/gobgp/packet"
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func TestPathNewIPv4(t *testing.T) {
	peerP := PathCreatePeer()
	msgP := PathCreateMSG(peerP)
	pathP := PathCreatePath(msgP)
	ipv4p := NewIPv4Path(pathP[0].getSource(), pathP[0].getNlri(), true, pathP[0].getPathAttrs(), pathP[0].getMedSetByTargetNeighbor())
	assert.NotNil(t, ipv4p)
}
func TestPathNewIPv6(t *testing.T) {
	peerP := PathCreatePeer()
	msgP := PathCreateMSG(peerP)
	pathP := PathCreatePath(msgP)
	ipv6p := NewIPv6Path(pathP[0].getSource(), pathP[0].getNlri(), true, pathP[0].getPathAttrs(), pathP[0].getMedSetByTargetNeighbor())
	assert.NotNil(t, ipv6p)
}

func TestPathIPv4SetDefault(t *testing.T) {
	pd := &PathDefault{withdraw: true}
	ipv4p := &IPv4Path{}
	ipv4p.setPathDefault(pd)
	r_pd := ipv4p.getPathDefault()
	assert.Equal(t, r_pd, pd)
}

func TestPathIPv4GetDefault(t *testing.T) {
	pd := &PathDefault{withdraw: false}
	ipv4p := &IPv4Path{}
	ipv4p.setPathDefault(pd)
	r_pd := ipv4p.getPathDefault()
	assert.Equal(t, r_pd, pd)
}

func TestPathIPv6SetDefault(t *testing.T) {
	pd := &PathDefault{}
	ipv6p := &IPv6Path{}
	ipv6p.setPathDefault(pd)
	r_pd := ipv6p.getPathDefault()
	assert.Equal(t, r_pd, pd)
}

func TestPathIPv6GetDefault(t *testing.T) {
	pd := &PathDefault{}
	ipv6p := &IPv6Path{}
	ipv6p.setPathDefault(pd)
	r_pd := ipv6p.getPathDefault()
	assert.Equal(t, r_pd, pd)
}

func TestPathGetRouteFamily(t *testing.T) {
	pd := &PathDefault{routeFamily: bgp.RF_IPv6_UC}
	rf := pd.GetRouteFamily()
	assert.Equal(t, rf, bgp.RF_IPv6_UC)
}

func TestPathSetSource(t *testing.T) {
	pd := &PathDefault{}
	pr := &PeerInfo{AS: 65000}
	pd.setSource(pr)
	r_pr := pd.getSource()
	assert.Equal(t, r_pr, pr)
}

func TestPathGetSource(t *testing.T) {
	pd := &PathDefault{}
	pr := &PeerInfo{AS: 65001}
	pd.setSource(pr)
	r_pr := pd.getSource()
	assert.Equal(t, r_pr, pr)
}

func TestPathSetNexthop(t *testing.T) {
	pd := &PathDefault{}
	ip := net.ParseIP("192.168.0.1")
	pd.setNexthop(ip)
	nh := pd.getNexthop()
	assert.Equal(t, nh, ip)
}

func TestPathgetNexthop(t *testing.T) {
	pd := &PathDefault{}
	ip := net.ParseIP("192.168.0.2")
	pd.setNexthop(ip)
	nh := pd.getNexthop()
	assert.Equal(t, nh, ip)
}

func TestPathSetWithdraw(t *testing.T) {
	pd := &PathDefault{}
	wd := true
	pd.setWithdraw(wd)
	r_wd := pd.IsWithdraw()
	assert.Equal(t, r_wd, wd)
}

func TestPathGetWithdaw(t *testing.T) {
	pd := &PathDefault{}
	wd := false
	pd.setWithdraw(wd)
	r_wd := pd.IsWithdraw()
	assert.Equal(t, r_wd, wd)
}

func TestPathGetNlri(t *testing.T) {
	nlri := bgp.NewNLRInfo(24, "13.2.3.2")
	pd := &PathDefault{
		nlri: nlri,
	}
	r_nlri := pd.getNlri()
	assert.Equal(t, r_nlri, nlri)
}

func TestPathSetMedSetByTargetNeighbor(t *testing.T) {
	pd := &PathDefault{}
	msbt := true
	pd.setMedSetByTargetNeighbor(msbt)
	r_msbt := pd.getMedSetByTargetNeighbor()
	assert.Equal(t, r_msbt, msbt)
}

func TestPathGetMedSetByTargetNeighbor(t *testing.T) {
	pd := &PathDefault{}
	msbt := true
	pd.setMedSetByTargetNeighbor(msbt)
	r_msbt := pd.getMedSetByTargetNeighbor()
	assert.Equal(t, r_msbt, msbt)
}

func TestPathCreatePath(t *testing.T) {
	peerP := PathCreatePeer()
	msgP := PathCreateMSG(peerP)
	updateMsgP := msgP[0].innerMessage.Body.(*bgp.BGPUpdate)
	nlriList := updateMsgP.NLRI
	pathAttributes := updateMsgP.PathAttributes
	nlri_info := nlriList[0]
	path := CreatePath(msgP[0].fromPeer, &nlri_info, pathAttributes, false)
	assert.NotNil(t, path)

}

func TestPathGetPrefix(t *testing.T) {
	peerP := PathCreatePeer()
	msgP := PathCreateMSG(peerP)
	pathP := PathCreatePath(msgP)
	prefix := "10.10.10.0/24"
	r_prefix := pathP[0].getPrefix()
	assert.Equal(t, r_prefix, prefix)
}
func TestPathGetAttribute(t *testing.T) {
	peerP := PathCreatePeer()
	msgP := PathCreateMSG(peerP)
	pathP := PathCreatePath(msgP)
	nh := "192.168.50.1"
	_, pa := pathP[0].getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	r_nh := pa.(*bgp.PathAttributeNextHop).Value.String()
	assert.Equal(t, r_nh, nh)
}

func PathCreatePeer() []*PeerInfo {
	peerP1 := &PeerInfo{AS: 65000}
	peerP2 := &PeerInfo{AS: 65001}
	peerP3 := &PeerInfo{AS: 65002}
	peerP := []*PeerInfo{peerP1, peerP2, peerP3}
	return peerP
}
func PathCreateMSG(peerP []*PeerInfo) []*ProcessMessage {
	bgpMsgP1 := updateMsgP1()
	bgpMsgP2 := updateMsgP2()
	bgpMsgP3 := updateMsgP3()
	msgP1 := &ProcessMessage{innerMessage: bgpMsgP1, fromPeer: peerP[0]}
	msgP2 := &ProcessMessage{innerMessage: bgpMsgP2, fromPeer: peerP[1]}
	msgP3 := &ProcessMessage{innerMessage: bgpMsgP3, fromPeer: peerP[2]}
	msgP := []*ProcessMessage{msgP1, msgP2, msgP3}
	return msgP
}
func PathCreatePath(msgs []*ProcessMessage) []Path {
	pathP := make([]Path, 3)
	for i, msg := range msgs {
		updateMsgP := msg.innerMessage.Body.(*bgp.BGPUpdate)
		nlriList := updateMsgP.NLRI
		pathAttributes := updateMsgP.PathAttributes
		nlri_info := nlriList[0]
		pathP[i] = CreatePath(msg.fromPeer, &nlri_info, pathAttributes, false)
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
