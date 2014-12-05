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
func createDestinationCheck(t *testing.T, path Path) (Destination, string) {
	dest := NewIPv4Destination(path.getNlri())
	ar := assert.NotNil(t, dest)
	if !ar {
		return nil, "NG"
	}
	return dest, "OK"
}

func routeCheck(t *testing.T, dest Destination) string {
	bgpMsg1 := updateMsgD1()
	bgpMsg2 := updateMsgD2()
	bgpMsg3 := updateMsgD3()
	pr1 := &Peer{VersionNum: 2, RemoteAs: 65000}
	pr2 := &Peer{VersionNum: 4, RemoteAs: 65001}
	pr3 := &Peer{VersionNum: 4, RemoteAs: 65002}
	msg1 := &ProcessMessage{innerMessage: bgpMsg1, fromPeer: pr1}
	msg2 := &ProcessMessage{innerMessage: bgpMsg2, fromPeer: pr1}
	msg3 := &ProcessMessage{innerMessage: bgpMsg3, fromPeer: pr2}
	path1, _ := createPathCheck(t, msg1)
	path2, _ := createPathCheck(t, msg2)
	path3, _ := createPathCheck(t, msg3)

	//best path selection
	dest.addNewPath(path1)
	dest.addNewPath(path2)
	dest.addNewPath(path3)
	dest.addWithdraw(path3)

	_, _, e := dest.Calculate(uint32(100))
	//bpath, str, e := dest.Calculate()
	//t.Log(bpath)
	//t.Log(str)
	ar := assert.Nil(t, e)
	if !ar {
		return "NG"
	}

	//sent route and remove sent route
	sroute1 := &SentRoute{path: path1, peer: pr1}
	sroute2 := &SentRoute{path: path2, peer: pr1}
	sroute3 := &SentRoute{path: path3, peer: pr2}
	dest.addSentRoute(sroute1)
	dest.addSentRoute(sroute2)
	dest.addSentRoute(sroute3)
	result := dest.removeSentRoute(pr3)
	ar = assert.Equal(t, result, false)
	if !ar {
		return "NG"
	}
	result = dest.removeSentRoute(pr2)
	ar = assert.Equal(t, result, true)
	if !ar {
		return "NG"
	}

	//remote old path
	rpath := dest.removeOldPathsFromSource(pr1)
	t.Log(rpath)
	//t.Log(dest.getKnownPathList())
	return "OK"
}

/*
func getKnownPathListCheck(t *testing.T, dest Destination) string {
	paths := dest.getKnownPathList()
	t.Log(paths)
	return "OK"
}
*/

//getter&setter test
func dgsTerCheck(t *testing.T, path Path) string {
	dd := &DestinationDefault{}
	//check Route Family
	dd.setRouteFamily(RF_IPv4_UC)
	rf := dd.getRouteFamily()
	ar := assert.Equal(t, rf, RF_IPv4_UC)
	if !ar {
		return "NG"
	}
	//check nlri
	nlri := bgp.NewNLRInfo(24, "13.2.3.1")
	dd.setNlri(nlri)
	r_nlri := dd.getNlri()
	ar = assert.Equal(t, r_nlri, nlri)
	if !ar {
		return "NG"
	}
	// check best path reason
	reason := "reason"
	dd.setBestPathReason(reason)
	r_reason := dd.getBestPathReason()
	ar = assert.Equal(t, r_reason, reason)
	if !ar {
		return "NG"
	}
	//check best path
	dd.setBestPath(path)
	r_path := dd.getBestPath()
	ar = assert.Equal(t, r_path, path)
	if !ar {
		return "NG"
	}
	return "OK"
}
func TestDestination(t *testing.T) {
	bgpMsg1 := updateMsgD1()
	pr1 := &Peer{VersionNum: 2, RemoteAs: 65000}
	msg := &ProcessMessage{innerMessage: bgpMsg1, fromPeer: pr1}
	path, _ := createPathCheck(t, msg)
	t.Log("# CREATE PATH CHECK")
	dest, result := createDestinationCheck(t, path)
	t.Log("# CHECK END -> [ ", result, " ]")
	t.Log("")
	t.Log("# ROUTE CHECK")
	result = routeCheck(t, dest)
	t.Log("# CHECK END -> [ ", result, " ]")
	t.Log("")
	t.Log("# GETTER SETTER CHECK")
	result = dgsTerCheck(t, path)
	t.Log("# CHECK END -> [ ", result, " ]")
	t.Log("")
}
