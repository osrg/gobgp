// Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
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

package table

import (
	//"fmt"
	"github.com/osrg/gobgp/packet"
	"github.com/stretchr/testify/assert"
	//"net"
	"testing"
)

func TestDestinationNewIPv4(t *testing.T) {
	peerD := DestCreatePeer()
	msgD := DestCreateMSG(peerD)
	pathD := DestCreatePath(msgD)
	ipv4d := NewIPv4Destination(pathD[0].getNlri())
	assert.NotNil(t, ipv4d)
}
func TestDestinationNewIPv6(t *testing.T) {
	peerD := DestCreatePeer()
	msgD := DestCreateMSG(peerD)
	pathD := DestCreatePath(msgD)
	ipv6d := NewIPv6Destination(pathD[0].getNlri())
	assert.NotNil(t, ipv6d)
}

func TestDestinationSetRouteFamily(t *testing.T) {
	dd := &DestinationDefault{}
	dd.setRouteFamily(RF_IPv4_UC)
	rf := dd.getRouteFamily()
	assert.Equal(t, rf, RF_IPv4_UC)
}
func TestDestinationGetRouteFamily(t *testing.T) {
	dd := &DestinationDefault{}
	dd.setRouteFamily(RF_IPv6_UC)
	rf := dd.getRouteFamily()
	assert.Equal(t, rf, RF_IPv6_UC)
}
func TestDestinationSetNlri(t *testing.T) {
	dd := &DestinationDefault{}
	nlri := bgp.NewNLRInfo(24, "13.2.3.1")
	dd.setNlri(nlri)
	r_nlri := dd.getNlri()
	assert.Equal(t, r_nlri, nlri)
}
func TestDestinationGetNlri(t *testing.T) {
	dd := &DestinationDefault{}
	nlri := bgp.NewNLRInfo(24, "10.110.123.1")
	dd.setNlri(nlri)
	r_nlri := dd.getNlri()
	assert.Equal(t, r_nlri, nlri)
}
func TestDestinationSetBestPathReason(t *testing.T) {
	dd := &DestinationDefault{}
	reason := "reason1"
	dd.setBestPathReason(reason)
	r_reason := dd.getBestPathReason()
	assert.Equal(t, r_reason, reason)
}
func TestDestinationGetBestPathReason(t *testing.T) {
	dd := &DestinationDefault{}
	reason := "reason2"
	dd.setBestPathReason(reason)
	r_reason := dd.getBestPathReason()
	assert.Equal(t, r_reason, reason)
}
func TestDestinationSetBestPath(t *testing.T) {
	peerD := DestCreatePeer()
	msgD := DestCreateMSG(peerD)
	pathD := DestCreatePath(msgD)
	ipv4d := NewIPv4Destination(pathD[0].getNlri())
	ipv4d.setBestPath(pathD[0])
	r_pathD := ipv4d.getBestPath()
	assert.Equal(t, r_pathD, pathD[0])
}
func TestDestinationGetBestPath(t *testing.T) {
	peerD := DestCreatePeer()
	msgD := DestCreateMSG(peerD)
	pathD := DestCreatePath(msgD)
	ipv4d := NewIPv4Destination(pathD[0].getNlri())
	ipv4d.setBestPath(pathD[0])
	r_pathD := ipv4d.getBestPath()
	assert.Equal(t, r_pathD, pathD[0])
}
func TestDestinationCalculate(t *testing.T) {
	peerD := DestCreatePeer()
	msgD := DestCreateMSG(peerD)
	pathD := DestCreatePath(msgD)
	ipv4d := NewIPv4Destination(pathD[0].getNlri())
	//best path selection
	ipv4d.addNewPath(pathD[0])
	ipv4d.addNewPath(pathD[1])
	ipv4d.addNewPath(pathD[2])
	ipv4d.addWithdraw(pathD[2])
	_, _, e := ipv4d.Calculate(uint32(100))
	assert.Nil(t, e)
}

func DestCreatePeer() []*PeerInfo {
	peerD1 := &PeerInfo{VersionNum: 4, AS: 65000}
	peerD2 := &PeerInfo{VersionNum: 4, AS: 65001}
	peerD3 := &PeerInfo{VersionNum: 4, AS: 65002}
	peerD := []*PeerInfo{peerD1, peerD2, peerD3}
	return peerD
}
func DestCreateMSG(peerD []*PeerInfo) []*ProcessMessage {
	bgpMsgD1 := updateMsgD1()
	bgpMsgD2 := updateMsgD2()
	bgpMsgD3 := updateMsgD3()
	msgD1 := &ProcessMessage{innerMessage: bgpMsgD1, fromPeer: peerD[0]}
	msgD2 := &ProcessMessage{innerMessage: bgpMsgD2, fromPeer: peerD[1]}
	msgD3 := &ProcessMessage{innerMessage: bgpMsgD3, fromPeer: peerD[2]}
	msgD := []*ProcessMessage{msgD1, msgD2, msgD3}
	return msgD
}
func DestCreatePath(msgs []*ProcessMessage) []Path {
	pathD := make([]Path, 3)
	for i, msg := range msgs {
		updateMsgD := msg.innerMessage.Body.(*bgp.BGPUpdate)
		nlriList := updateMsgD.NLRI
		pathAttributes := updateMsgD.PathAttributes
		nlri_info := nlriList[0]
		pathD[i] = CreatePath(msg.fromPeer, &nlri_info, pathAttributes, false)
	}
	return pathD
}

func updateMsgD1() *bgp.BGPMessage {

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

func updateMsgD2() *bgp.BGPMessage {

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
func updateMsgD3() *bgp.BGPMessage {
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
