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
	"github.com/osrg/gobgp/packet"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestTableCreateDestDefault(t *testing.T) {
	td := NewTableDefault(0)
	nlri := bgp.NewNLRInfo(24, "13.2.3.1")
	cd := td.createDest(nlri)
	assert.Nil(t, cd)
}

func TestTableTableKeyDefault(t *testing.T) {
	td := NewTableDefault(0)
	nlri := bgp.NewNLRInfo(24, "13.2.3.1")
	tk := td.tableKey(nlri)
	assert.Equal(t, tk, "")
}

func TestTableDeleteDestByNlri(t *testing.T) {
	peerT := TableCreatePeer()
	msgT := TableCreateMSG(peerT)
	pathT := TableCreatePath(msgT)
	ipv4t := NewIPv4Table(0)
	for _, path := range pathT {
		tableKey := ipv4t.tableKey(path.getNlri())
		dest := ipv4t.createDest(path.getNlri())
		ipv4t.setDestination(tableKey, dest)
	}
	tableKey := ipv4t.tableKey(pathT[0].getNlri())
	gdest := ipv4t.getDestination(tableKey)
	rdest := deleteDestByNlri(ipv4t, pathT[0].getNlri())
	assert.Equal(t, rdest, gdest)
}

func TestTableDeleteDest(t *testing.T) {
	peerT := TableCreatePeer()
	msgT := TableCreateMSG(peerT)
	pathT := TableCreatePath(msgT)
	ipv4t := NewIPv4Table(0)
	for _, path := range pathT {
		tableKey := ipv4t.tableKey(path.getNlri())
		dest := ipv4t.createDest(path.getNlri())
		ipv4t.setDestination(tableKey, dest)
	}
	tableKey := ipv4t.tableKey(pathT[0].getNlri())
	dest := ipv4t.createDest(pathT[0].getNlri())
	ipv4t.setDestination(tableKey, dest)
	deleteDest(ipv4t, dest)
	gdest := ipv4t.getDestination(tableKey)
	assert.Nil(t, gdest)
}

func TestTableGetRouteFamily(t *testing.T) {
	ipv4t := NewIPv4Table(0)
	rf := ipv4t.GetRoutefamily()
	assert.Equal(t, rf, bgp.RF_IPv4_UC)
}

func TestTableSetDestinations(t *testing.T) {
	peerT := TableCreatePeer()
	msgT := TableCreateMSG(peerT)
	pathT := TableCreatePath(msgT)
	ipv4t := NewIPv4Table(0)
	destinations := make(map[string]Destination)
	for _, path := range pathT {
		tableKey := ipv4t.tableKey(path.getNlri())
		dest := ipv4t.createDest(path.getNlri())
		destinations[tableKey] = dest
	}
	ipv4t.setDestinations(destinations)
	ds := ipv4t.getDestinations()
	assert.Equal(t, ds, destinations)
}
func TestTableGetDestinations(t *testing.T) {
	peerT := DestCreatePeer()
	msgT := DestCreateMSG(peerT)
	pathT := DestCreatePath(msgT)
	ipv4t := NewIPv4Table(0)
	destinations := make(map[string]Destination)
	for _, path := range pathT {
		tableKey := ipv4t.tableKey(path.getNlri())
		dest := ipv4t.createDest(path.getNlri())
		destinations[tableKey] = dest
	}
	ipv4t.setDestinations(destinations)
	ds := ipv4t.getDestinations()
	assert.Equal(t, ds, destinations)
}

func TableCreatePeer() []*PeerInfo {
	peerT1 := &PeerInfo{AS: 65000}
	peerT2 := &PeerInfo{AS: 65001}
	peerT3 := &PeerInfo{AS: 65002}
	peerT := []*PeerInfo{peerT1, peerT2, peerT3}
	return peerT
}
func TableCreateMSG(peerT []*PeerInfo) []*ProcessMessage {
	bgpMsgT1 := updateMsgT1()
	bgpMsgT2 := updateMsgT2()
	bgpMsgT3 := updateMsgT3()
	msgT1 := &ProcessMessage{innerMessage: bgpMsgT1, fromPeer: peerT[0]}
	msgT2 := &ProcessMessage{innerMessage: bgpMsgT2, fromPeer: peerT[1]}
	msgT3 := &ProcessMessage{innerMessage: bgpMsgT3, fromPeer: peerT[2]}
	msgT := []*ProcessMessage{msgT1, msgT2, msgT3}
	return msgT
}
func TableCreatePath(msgs []*ProcessMessage) []Path {
	pathT := make([]Path, 3)
	for i, msg := range msgs {
		updateMsgT := msg.innerMessage.Body.(*bgp.BGPUpdate)
		nlriList := updateMsgT.NLRI
		pathAttributes := updateMsgT.PathAttributes
		nlri_info := nlriList[0]
		pathT[i] = CreatePath(msg.fromPeer, &nlri_info, pathAttributes, false)
	}
	return pathT
}

func updateMsgT1() *bgp.BGPMessage {

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

func updateMsgT2() *bgp.BGPMessage {

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
func updateMsgT3() *bgp.BGPMessage {
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
