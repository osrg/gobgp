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
	"net"
	"testing"
	"time"
)

func TestDestinationNewIPv4(t *testing.T) {
	peerD := DestCreatePeer()
	pathD := DestCreatePath(peerD)
	ipv4d := NewDestination(pathD[0].GetNlri())
	assert.NotNil(t, ipv4d)
}
func TestDestinationNewIPv6(t *testing.T) {
	peerD := DestCreatePeer()
	pathD := DestCreatePath(peerD)
	ipv6d := NewDestination(pathD[0].GetNlri())
	assert.NotNil(t, ipv6d)
}

func TestDestinationSetRouteFamily(t *testing.T) {
	dd := &Destination{}
	dd.setRouteFamily(bgp.RF_IPv4_UC)
	rf := dd.Family()
	assert.Equal(t, rf, bgp.RF_IPv4_UC)
}
func TestDestinationGetRouteFamily(t *testing.T) {
	dd := &Destination{}
	dd.setRouteFamily(bgp.RF_IPv6_UC)
	rf := dd.Family()
	assert.Equal(t, rf, bgp.RF_IPv6_UC)
}
func TestDestinationSetNlri(t *testing.T) {
	dd := &Destination{}
	nlri := bgp.NewIPAddrPrefix(24, "13.2.3.1")
	dd.setNlri(nlri)
	r_nlri := dd.GetNlri()
	assert.Equal(t, r_nlri, nlri)
}
func TestDestinationGetNlri(t *testing.T) {
	dd := &Destination{}
	nlri := bgp.NewIPAddrPrefix(24, "10.110.123.1")
	dd.setNlri(nlri)
	r_nlri := dd.GetNlri()
	assert.Equal(t, r_nlri, nlri)
}
func DestCreatePeer() []*PeerInfo {
	peerD1 := &PeerInfo{AS: 65000}
	peerD2 := &PeerInfo{AS: 65001}
	peerD3 := &PeerInfo{AS: 65002}
	peerD := []*PeerInfo{peerD1, peerD2, peerD3}
	return peerD
}

func DestCreatePath(peerD []*PeerInfo) []*Path {
	bgpMsgD1 := updateMsgD1()
	bgpMsgD2 := updateMsgD2()
	bgpMsgD3 := updateMsgD3()
	pathD := make([]*Path, 3)
	for i, msg := range []*bgp.BGPMessage{bgpMsgD1, bgpMsgD2, bgpMsgD3} {
		updateMsgD := msg.Body.(*bgp.BGPUpdate)
		nlriList := updateMsgD.NLRI
		pathAttributes := updateMsgD.PathAttributes
		nlri_info := nlriList[0]
		pathD[i] = NewPath(peerD[i], nlri_info, false, pathAttributes, time.Now(), false)
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

	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.10.0")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	UpdatePathAttrs4ByteAs(updateMsg.Body.(*bgp.BGPUpdate))
	return updateMsg
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

	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "20.20.20.0")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	UpdatePathAttrs4ByteAs(updateMsg.Body.(*bgp.BGPUpdate))
	return updateMsg
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

	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "30.30.30.0")}
	w1 := bgp.NewIPAddrPrefix(23, "40.40.40.0")
	withdrawnRoutes := []*bgp.IPAddrPrefix{w1}
	updateMsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	UpdatePathAttrs4ByteAs(updateMsg.Body.(*bgp.BGPUpdate))
	return updateMsg
}

func TestRadixkey(t *testing.T) {
	assert.Equal(t, "000010100000001100100000", CidrToRadixkey("10.3.32.0/24"))
	assert.Equal(t, "000010100000001100100000", IpToRadixkey(net.ParseIP("10.3.32.0").To4(), 24))
	assert.Equal(t, "000010100000001100100000", IpToRadixkey(net.ParseIP("10.3.32.0").To4(), 24))
}
