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
	_ "fmt"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
)

var logger = slog.Default()

// process BGPUpdate message
// this function processes only BGPUpdate
func (manager *TableManager) ProcessUpdate(fromPeer *PeerInfo, message *bgp.BGPMessage) ([]*Path, error) {
	pathList := make([]*Path, 0)
	dsts := make([]*Update, 0)
	for _, path := range ProcessMessage(message, fromPeer, time.Now(), false) {
		dsts = append(dsts, manager.Update(path)...)
	}
	for _, d := range dsts {
		b, _, _ := d.GetChanges(GLOBAL_RIB_NAME, 0, false)
		pathList = append(pathList, b)
	}
	return pathList, nil
}

func peerR1() *PeerInfo {
	peer := &PeerInfo{
		AS:      65000,
		LocalAS: 65000,
		ID:      netip.MustParseAddr("10.0.0.3"),
		LocalID: netip.MustParseAddr("10.0.0.1"),
		Address: netip.MustParseAddr("10.0.0.1"),
	}
	return peer
}

func peerR2() *PeerInfo {
	peer := &PeerInfo{
		AS:      65100,
		LocalAS: 65000,
		Address: netip.MustParseAddr("10.0.0.2"),
	}
	return peer
}

func peerR3() *PeerInfo {
	peer := &PeerInfo{
		AS:      65000,
		LocalAS: 65000,
		ID:      netip.MustParseAddr("10.0.0.2"),
		LocalID: netip.MustParseAddr("10.0.0.1"),
		Address: netip.MustParseAddr("10.0.0.3"),
	}
	return peer
}

func TestTreatAsWithdraw(t *testing.T) {
	msg := update_fromR2_ipv6()
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("1.1.1.0/24"))
	msg.Body.(*bgp.BGPUpdate).NLRI = append(msg.Body.(*bgp.BGPUpdate).NLRI, bgp.PathNLRI{NLRI: nlri})

	paths := ProcessMessage(msg, peerR2(), time.Now(), true)

	assert.Equal(t, paths[0].IsWithdraw, true)
	assert.Equal(t, paths[1].IsWithdraw, true)
}

// test best path calculation and check the result path is from R1
func TestProcessBGPUpdate_0_select_onlypath_ipv4(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})

	bgpMessage := update_fromR1()
	peer := peerR1()
	pList, err := tm.ProcessUpdate(peer, bgpMessage)
	assert.Equal(t, len(pList), 1)
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	// check type
	path := pList[0]
	assert.Equal(t, path.GetFamily(), bgp.RF_IPv4_UC)

	// check PathAttribute
	pathAttributes := bgpMessage.Body.(*bgp.BGPUpdate).PathAttributes
	expectedOrigin := pathAttributes[0]
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[1]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedNexthopAttr := pathAttributes[2]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	pathNexthop := attr.(*bgp.PathAttributeNextHop)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedMed := pathAttributes[3]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, 4, len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "10.10.10.0/24"
	assert.Equal(t, expectedPrefix, path.GetPrefix())
	// check nexthop
	expectedNexthop := "192.168.50.1"
	assert.Equal(t, expectedNexthop, path.GetNexthop().String())
}

// test best path calculation and check the result path is from R1
func TestProcessBGPUpdate_0_select_onlypath_ipv6(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv6_UC})

	bgpMessage := update_fromR1_ipv6()
	peer := peerR1()
	pList, err := tm.ProcessUpdate(peer, bgpMessage)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	// check type
	path := pList[0]
	assert.Equal(t, path.GetFamily(), bgp.RF_IPv6_UC)

	// check PathAttribute
	pathAttributes := bgpMessage.Body.(*bgp.BGPUpdate).PathAttributes

	expectedNexthopAttr := pathAttributes[0]
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
	pathNexthop := attr.(*bgp.PathAttributeMpReachNLRI)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedOrigin := pathAttributes[1]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[2]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedMed := pathAttributes[3]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, 4, len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "2001:123:123:1::/64"
	assert.Equal(t, expectedPrefix, path.GetPrefix())
	// check nexthop
	expectedNexthop := "2001::192:168:50:1"
	assert.Equal(t, expectedNexthop, path.GetNexthop().String())
}

// test: compare localpref
func TestProcessBGPUpdate_1_select_high_localpref_ipv4(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})

	// low localpref message
	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint32{65000})
	nexthop1, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.50.1"))
	med1 := bgp.NewPathAttributeMultiExitDisc(0)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		origin1, aspath1, nexthop1, med1, localpref1,
	}
	nlri1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	bgpMessage1 := bgp.NewBGPUpdateMessage(nil, pathAttributes1, []bgp.PathNLRI{{NLRI: nlri1}})

	// high localpref message
	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint32{65100, 65000})
	nexthop2, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.50.1"))
	med2 := bgp.NewPathAttributeMultiExitDisc(100)
	localpref2 := bgp.NewPathAttributeLocalPref(200)

	pathAttributes2 := []bgp.PathAttributeInterface{
		origin2, aspath2, nexthop2, med2, localpref2,
	}
	nlri2, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	bgpMessage2 := bgp.NewBGPUpdateMessage(nil, pathAttributes2, []bgp.PathNLRI{{NLRI: nlri2}})

	peer1 := peerR1()
	pList, err := tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	peer2 := peerR2()
	pList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	// check type
	path := pList[0]
	assert.Equal(t, path.GetFamily(), bgp.RF_IPv4_UC)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes
	expectedOrigin := pathAttributes[0]
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[1]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedNexthopAttr := pathAttributes[2]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	pathNexthop := attr.(*bgp.PathAttributeNextHop)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedMed := pathAttributes[3]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, len(pathAttributes2), len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "10.10.10.0/24"
	assert.Equal(t, expectedPrefix, path.GetPrefix())
	// check nexthop
	expectedNexthop := "192.168.50.1"
	assert.Equal(t, expectedNexthop, path.GetNexthop().String())
}

func TestProcessBGPUpdate_1_select_high_localpref_ipv6(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv6_UC})

	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint32{65000})
	nlri1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:123:1::/64"))
	mpReach1, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri1}}, netip.MustParseAddr("2001::192:168:50:1"))
	med1 := bgp.NewPathAttributeMultiExitDisc(100)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		mpReach1, origin1, aspath1, med1, localpref1,
	}

	bgpMessage1 := bgp.NewBGPUpdateMessage(nil, pathAttributes1, nil)

	origin2 := bgp.NewPathAttributeOrigin(0)
	nlri2, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:123:1::/64"))
	aspath2 := createAsPathAttribute([]uint32{65100, 65000})
	mpReach2, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri2}}, netip.MustParseAddr("2001::192:168:100:1"))
	med2 := bgp.NewPathAttributeMultiExitDisc(100)
	localpref2 := bgp.NewPathAttributeLocalPref(200)

	pathAttributes2 := []bgp.PathAttributeInterface{
		mpReach2, origin2, aspath2, med2, localpref2,
	}

	bgpMessage2 := bgp.NewBGPUpdateMessage(nil, pathAttributes2, nil)

	peer1 := peerR1()
	pList, err := tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	peer2 := peerR2()
	pList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	// check type
	path := pList[0]
	assert.Equal(t, path.GetFamily(), bgp.RF_IPv6_UC)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes

	expectedNexthopAttr := pathAttributes[0]
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
	pathNexthop := attr.(*bgp.PathAttributeMpReachNLRI)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedOrigin := pathAttributes[1]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[2]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedMed := pathAttributes[3]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, 5, len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "2001:123:123:1::/64"
	assert.Equal(t, expectedPrefix, path.GetPrefix())
	// check nexthop
	expectedNexthop := "2001::192:168:100:1"
	assert.Equal(t, expectedNexthop, path.GetNexthop().String())
}

// test: compare localOrigin
func TestProcessBGPUpdate_2_select_local_origin_ipv4(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})

	// low localpref message
	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint32{65000})
	nexthop1, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.50.1"))
	med1 := bgp.NewPathAttributeMultiExitDisc(0)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		origin1, aspath1, nexthop1, med1, localpref1,
	}
	nlri1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	bgpMessage1 := bgp.NewBGPUpdateMessage(nil, pathAttributes1, []bgp.PathNLRI{{NLRI: nlri1}})

	// high localpref message
	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint32{})
	nexthop2, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("0.0.0.0"))
	med2 := bgp.NewPathAttributeMultiExitDisc(100)
	localpref2 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes2 := []bgp.PathAttributeInterface{
		origin2, aspath2, nexthop2, med2, localpref2,
	}
	nlri2, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	bgpMessage2 := bgp.NewBGPUpdateMessage(nil, pathAttributes2, []bgp.PathNLRI{{NLRI: nlri2}})

	peer1 := peerR1()
	pList, err := tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	peer2 := &PeerInfo{
		Address: netip.MustParseAddr("0.0.0.0"),
	}
	pList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	// check type
	path := pList[0]
	assert.Equal(t, path.GetFamily(), bgp.RF_IPv4_UC)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes
	expectedOrigin := pathAttributes[0]
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[1]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedNexthopAttr := pathAttributes[2]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	pathNexthop := attr.(*bgp.PathAttributeNextHop)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedMed := pathAttributes[3]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, len(pathAttributes2), len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "10.10.10.0/24"
	assert.Equal(t, expectedPrefix, path.GetPrefix())
	// check nexthop
	expectedNexthop := "0.0.0.0"
	assert.Equal(t, expectedNexthop, path.GetNexthop().String())
}

func TestProcessBGPUpdate_2_select_local_origin_ipv6(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv6_UC})

	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint32{65000})
	nlri1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:123:1::/64"))
	mpReach1, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri1}}, netip.MustParseAddr("2001::192:168:50:1"))
	med1 := bgp.NewPathAttributeMultiExitDisc(100)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		mpReach1, origin1, aspath1, med1, localpref1,
	}

	bgpMessage1 := bgp.NewBGPUpdateMessage(nil, pathAttributes1, nil)

	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint32{})
	nlri2, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:123:1::/64"))
	mpReach2, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri2}}, netip.MustParseAddr("::"))
	med2 := bgp.NewPathAttributeMultiExitDisc(100)
	localpref2 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes2 := []bgp.PathAttributeInterface{
		mpReach2, origin2, aspath2, med2, localpref2,
	}

	bgpMessage2 := bgp.NewBGPUpdateMessage(nil, pathAttributes2, nil)

	peer1 := peerR1()
	pList, err := tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	peer2 := &PeerInfo{
		Address: netip.MustParseAddr("0.0.0.0"),
	}

	pList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	// check type
	path := pList[0]
	assert.Equal(t, path.GetFamily(), bgp.RF_IPv6_UC)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes

	expectedNexthopAttr := pathAttributes[0]
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
	pathNexthop := attr.(*bgp.PathAttributeMpReachNLRI)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedOrigin := pathAttributes[1]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[2]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedMed := pathAttributes[3]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, 5, len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "2001:123:123:1::/64"
	assert.Equal(t, expectedPrefix, path.GetPrefix())
	// check nexthop
	expectedNexthop := "::"
	assert.Equal(t, expectedNexthop, path.GetNexthop().String())
}

// test: compare AS_PATH
func TestProcessBGPUpdate_3_select_aspath_ipv4(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})

	bgpMessage1 := update_fromR2viaR1()
	peer1 := peerR1()
	pList, err := tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)
	bgpMessage2 := update_fromR2()
	peer2 := peerR2()
	pList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	// check type
	path := pList[0]
	assert.Equal(t, path.GetFamily(), bgp.RF_IPv4_UC)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes
	expectedOrigin := pathAttributes[0]
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[1]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedNexthopAttr := pathAttributes[2]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	pathNexthop := attr.(*bgp.PathAttributeNextHop)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedMed := pathAttributes[3]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, 4, len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "20.20.20.0/24"
	assert.Equal(t, expectedPrefix, path.GetPrefix())
	// check nexthop
	expectedNexthop := "192.168.100.1"
	assert.Equal(t, expectedNexthop, path.GetNexthop().String())
}

func TestProcessBGPUpdate_3_select_aspath_ipv6(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv6_UC})

	bgpMessage1 := update_fromR2viaR1_ipv6()
	peer1 := peerR1()
	pList, err := tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)
	bgpMessage2 := update_fromR2_ipv6()
	peer2 := peerR2()
	pList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	// check type
	path := pList[0]
	assert.Equal(t, path.GetFamily(), bgp.RF_IPv6_UC)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes

	expectedNexthopAttr := pathAttributes[0]
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
	pathNexthop := attr.(*bgp.PathAttributeMpReachNLRI)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedOrigin := pathAttributes[1]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[2]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedMed := pathAttributes[3]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, 4, len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "2002:223:123:1::/64"
	assert.Equal(t, expectedPrefix, path.GetPrefix())
	// check nexthop
	expectedNexthop := "2001::192:168:100:1"
	assert.Equal(t, expectedNexthop, path.GetNexthop().String())
}

// test: compare Origin
func TestProcessBGPUpdate_4_select_low_origin_ipv4(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})

	// low origin message
	origin1 := bgp.NewPathAttributeOrigin(1)
	aspath1 := createAsPathAttribute([]uint32{65200, 65000})
	nexthop1, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.50.1"))
	med1 := bgp.NewPathAttributeMultiExitDisc(100)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		origin1, aspath1, nexthop1, med1, localpref1,
	}
	nlri1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	bgpMessage1 := bgp.NewBGPUpdateMessage(nil, pathAttributes1, []bgp.PathNLRI{{NLRI: nlri1}})

	// high origin message
	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint32{65100, 65000})
	nexthop2, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.100.1"))
	med2 := bgp.NewPathAttributeMultiExitDisc(100)
	localpref2 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes2 := []bgp.PathAttributeInterface{
		origin2, aspath2, nexthop2, med2, localpref2,
	}
	nlri2, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	bgpMessage2 := bgp.NewBGPUpdateMessage(nil, pathAttributes2, []bgp.PathNLRI{{NLRI: nlri2}})

	peer1 := peerR1()
	pList, err := tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	peer2 := peerR2()
	pList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	// check type
	path := pList[0]
	assert.Equal(t, path.GetFamily(), bgp.RF_IPv4_UC)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes
	expectedOrigin := pathAttributes[0]
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[1]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedNexthopAttr := pathAttributes[2]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	pathNexthop := attr.(*bgp.PathAttributeNextHop)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedMed := pathAttributes[3]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, len(pathAttributes2), len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "10.10.10.0/24"
	assert.Equal(t, expectedPrefix, path.GetPrefix())
	// check nexthop
	expectedNexthop := "192.168.100.1"
	assert.Equal(t, expectedNexthop, path.GetNexthop().String())
}

func TestProcessBGPUpdate_4_select_low_origin_ipv6(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv6_UC})

	origin1 := bgp.NewPathAttributeOrigin(1)
	aspath1 := createAsPathAttribute([]uint32{65200, 65000})
	nlri1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:123:1::/64"))
	mpReach1, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri1}}, netip.MustParseAddr("2001::192:168:50:1"))
	med1 := bgp.NewPathAttributeMultiExitDisc(100)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		mpReach1, origin1, aspath1, med1, localpref1,
	}

	bgpMessage1 := bgp.NewBGPUpdateMessage(nil, pathAttributes1, nil)

	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint32{65100, 65000})
	nlri2, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:123:1::/64"))
	mpReach2, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri2}}, netip.MustParseAddr("2001::192:168:100:1"))
	med2 := bgp.NewPathAttributeMultiExitDisc(100)
	localpref2 := bgp.NewPathAttributeLocalPref(200)

	pathAttributes2 := []bgp.PathAttributeInterface{
		mpReach2, origin2, aspath2, med2, localpref2,
	}

	bgpMessage2 := bgp.NewBGPUpdateMessage(nil, pathAttributes2, nil)

	peer1 := peerR1()
	pList, err := tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	peer2 := peerR2()
	pList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	// check type
	path := pList[0]
	assert.Equal(t, path.GetFamily(), bgp.RF_IPv6_UC)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes

	expectedNexthopAttr := pathAttributes[0]
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
	pathNexthop := attr.(*bgp.PathAttributeMpReachNLRI)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedOrigin := pathAttributes[1]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[2]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedMed := pathAttributes[3]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, 5, len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "2001:123:123:1::/64"
	assert.Equal(t, expectedPrefix, path.GetPrefix())
	// check nexthop
	expectedNexthop := "2001::192:168:100:1"
	assert.Equal(t, expectedNexthop, path.GetNexthop().String())
}

// test: compare MED
func TestProcessBGPUpdate_5_select_low_med_ipv4(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})

	// low origin message
	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint32{65200, 65000})
	nexthop1, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.50.1"))
	med1 := bgp.NewPathAttributeMultiExitDisc(500)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		origin1, aspath1, nexthop1, med1, localpref1,
	}
	nlri1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	bgpMessage1 := bgp.NewBGPUpdateMessage(nil, pathAttributes1, []bgp.PathNLRI{{NLRI: nlri1}})

	// high origin message
	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint32{65100, 65000})
	nexthop2, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.100.1"))
	med2 := bgp.NewPathAttributeMultiExitDisc(100)
	localpref2 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes2 := []bgp.PathAttributeInterface{
		origin2, aspath2, nexthop2, med2, localpref2,
	}
	nlri2, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	bgpMessage2 := bgp.NewBGPUpdateMessage(nil, pathAttributes2, []bgp.PathNLRI{{NLRI: nlri2}})

	peer1 := peerR1()
	pList, err := tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	peer2 := peerR2()
	pList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	// check type
	path := pList[0]
	assert.Equal(t, path.GetFamily(), bgp.RF_IPv4_UC)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes
	expectedOrigin := pathAttributes[0]
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[1]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedNexthopAttr := pathAttributes[2]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	pathNexthop := attr.(*bgp.PathAttributeNextHop)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedMed := pathAttributes[3]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, len(pathAttributes2), len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "10.10.10.0/24"
	assert.Equal(t, expectedPrefix, path.GetPrefix())
	// check nexthop
	expectedNexthop := "192.168.100.1"
	assert.Equal(t, expectedNexthop, path.GetNexthop().String())
}

func TestProcessBGPUpdate_5_select_low_med_ipv6(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv6_UC})

	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint32{65200, 65000})
	nlri1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:123:1::/64"))
	mpReach1, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri1}}, netip.MustParseAddr("2001::192:168:50:1"))
	med1 := bgp.NewPathAttributeMultiExitDisc(500)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		mpReach1, origin1, aspath1, med1, localpref1,
	}

	bgpMessage1 := bgp.NewBGPUpdateMessage(nil, pathAttributes1, nil)

	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint32{65100, 65000})
	nlri2, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:123:1::/64"))
	mpReach2, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri2}}, netip.MustParseAddr("2001::192:168:100:1"))
	med2 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref2 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes2 := []bgp.PathAttributeInterface{
		mpReach2, origin2, aspath2, med2, localpref2,
	}

	bgpMessage2 := bgp.NewBGPUpdateMessage(nil, pathAttributes2, nil)

	peer1 := peerR1()
	pList, err := tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	peer2 := peerR2()
	pList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	// check type
	path := pList[0]
	assert.Equal(t, path.GetFamily(), bgp.RF_IPv6_UC)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes

	expectedNexthopAttr := pathAttributes[0]
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
	pathNexthop := attr.(*bgp.PathAttributeMpReachNLRI)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedOrigin := pathAttributes[1]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[2]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedMed := pathAttributes[3]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, 5, len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "2001:123:123:1::/64"
	assert.Equal(t, expectedPrefix, path.GetPrefix())
	// check nexthop
	expectedNexthop := "2001::192:168:100:1"
	assert.Equal(t, expectedNexthop, path.GetNexthop().String())
}

// test: compare AS_NUMBER(prefer eBGP path)
func TestProcessBGPUpdate_6_select_ebgp_path_ipv4(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})

	// low origin message
	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint32{65000, 65200})
	nexthop1, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.50.1"))
	med1 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		origin1, aspath1, nexthop1, med1, localpref1,
	}
	nlri1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	bgpMessage1 := bgp.NewBGPUpdateMessage(nil, pathAttributes1, []bgp.PathNLRI{{NLRI: nlri1}})

	// high origin message
	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint32{65100, 65000})
	nexthop2, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.100.1"))
	med2 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref2 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes2 := []bgp.PathAttributeInterface{
		origin2, aspath2, nexthop2, med2, localpref2,
	}
	nlri2, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	bgpMessage2 := bgp.NewBGPUpdateMessage(nil, pathAttributes2, []bgp.PathNLRI{{NLRI: nlri2}})

	peer1 := peerR1()
	pList, err := tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	peer2 := peerR2()
	pList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	// check type
	path := pList[0]
	assert.Equal(t, path.GetFamily(), bgp.RF_IPv4_UC)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes
	expectedOrigin := pathAttributes[0]
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[1]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedNexthopAttr := pathAttributes[2]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	pathNexthop := attr.(*bgp.PathAttributeNextHop)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedMed := pathAttributes[3]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, len(pathAttributes2), len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "10.10.10.0/24"
	assert.Equal(t, expectedPrefix, path.GetPrefix())
	// check nexthop
	expectedNexthop := "192.168.100.1"
	assert.Equal(t, expectedNexthop, path.GetNexthop().String())
}

func TestProcessBGPUpdate_6_select_ebgp_path_ipv6(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv6_UC})

	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint32{65000, 65200})
	nlri1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:123:1::/64"))
	mpReach1, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri1}}, netip.MustParseAddr("2001::192:168:50:1"))
	med1 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		mpReach1, origin1, aspath1, med1, localpref1,
	}

	bgpMessage1 := bgp.NewBGPUpdateMessage(nil, pathAttributes1, nil)

	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint32{65100, 65200})
	nlri2, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:123:1::/64"))
	mpReach2, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri2}}, netip.MustParseAddr("2001::192:168:100:1"))
	med2 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref2 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes2 := []bgp.PathAttributeInterface{
		mpReach2, origin2, aspath2, med2, localpref2,
	}

	bgpMessage2 := bgp.NewBGPUpdateMessage(nil, pathAttributes2, nil)

	peer1 := peerR1()
	pList, err := tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	peer2 := peerR2()
	pList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	// check type
	path := pList[0]
	assert.Equal(t, path.GetFamily(), bgp.RF_IPv6_UC)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes

	expectedNexthopAttr := pathAttributes[0]
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
	pathNexthop := attr.(*bgp.PathAttributeMpReachNLRI)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedOrigin := pathAttributes[1]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[2]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedMed := pathAttributes[3]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, 5, len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "2001:123:123:1::/64"
	assert.Equal(t, expectedPrefix, path.GetPrefix())
	// check nexthop
	expectedNexthop := "2001::192:168:100:1"
	assert.Equal(t, expectedNexthop, path.GetNexthop().String())
}

// test: compare IGP cost -> N/A

// test: compare Router ID
func TestProcessBGPUpdate_7_select_low_routerid_path_ipv4(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})
	SelectionOptions.ExternalCompareRouterId = true

	// low origin message
	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint32{65000, 65200})
	nexthop1, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.50.1"))
	med1 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		origin1, aspath1, nexthop1, med1, localpref1,
	}
	nlri1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	bgpMessage1 := bgp.NewBGPUpdateMessage(nil, pathAttributes1, []bgp.PathNLRI{{NLRI: nlri1}})

	// high origin message
	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint32{65000, 65100})
	nexthop2, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.100.1"))
	med2 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref2 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes2 := []bgp.PathAttributeInterface{
		origin2, aspath2, nexthop2, med2, localpref2,
	}
	nlri2, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	bgpMessage2 := bgp.NewBGPUpdateMessage(nil, pathAttributes2, []bgp.PathNLRI{{NLRI: nlri2}})

	peer1 := peerR1()
	pList, err := tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	peer3 := peerR3()
	pList, err = tm.ProcessUpdate(peer3, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	// check type
	path := pList[0]
	assert.Equal(t, path.GetFamily(), bgp.RF_IPv4_UC)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes
	expectedOrigin := pathAttributes[0]
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[1]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedNexthopAttr := pathAttributes[2]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	pathNexthop := attr.(*bgp.PathAttributeNextHop)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedMed := pathAttributes[3]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, len(pathAttributes2), len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "10.10.10.0/24"
	assert.Equal(t, expectedPrefix, path.GetPrefix())
	// check nexthop
	expectedNexthop := "192.168.100.1"
	assert.Equal(t, expectedNexthop, path.GetNexthop().String())
}

func TestProcessBGPUpdate_7_select_low_routerid_path_ipv6(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv6_UC})

	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint32{65000, 65200})
	nlri1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:123:1::/64"))
	mpReach1, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri1}}, netip.MustParseAddr("2001::192:168:50:1"))
	med1 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		mpReach1, origin1, aspath1, med1, localpref1,
	}

	bgpMessage1 := bgp.NewBGPUpdateMessage(nil, pathAttributes1, nil)

	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint32{65100, 65200})
	nlri2, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:123:1::/64"))
	mpReach2, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri2}}, netip.MustParseAddr("2001::192:168:100:1"))
	med2 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref2 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes2 := []bgp.PathAttributeInterface{
		mpReach2, origin2, aspath2, med2, localpref2,
	}

	bgpMessage2 := bgp.NewBGPUpdateMessage(nil, pathAttributes2, nil)

	peer1 := peerR1()
	pList, err := tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	peer3 := peerR3()
	pList, err = tm.ProcessUpdate(peer3, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	// check type
	path := pList[0]
	assert.Equal(t, path.GetFamily(), bgp.RF_IPv6_UC)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes

	expectedNexthopAttr := pathAttributes[0]
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
	pathNexthop := attr.(*bgp.PathAttributeMpReachNLRI)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedOrigin := pathAttributes[1]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[2]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedMed := pathAttributes[3]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, 5, len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "2001:123:123:1::/64"
	assert.Equal(t, expectedPrefix, path.GetPrefix())
	// check nexthop
	expectedNexthop := "2001::192:168:100:1"
	assert.Equal(t, expectedNexthop, path.GetNexthop().String())
}

// test: withdraw and mpunreach path
func TestProcessBGPUpdate_8_withdraw_path_ipv4(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})

	// path1
	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint32{65000})
	nexthop1, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.50.1"))
	med1 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		origin1, aspath1, nexthop1, med1, localpref1,
	}
	nlri1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	bgpMessage1 := bgp.NewBGPUpdateMessage(nil, pathAttributes1, []bgp.PathNLRI{{NLRI: nlri1}})

	// path 2
	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint32{65100, 65000})
	nexthop2, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.100.1"))
	med2 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref2 := bgp.NewPathAttributeLocalPref(200)

	pathAttributes2 := []bgp.PathAttributeInterface{
		origin2, aspath2, nexthop2, med2, localpref2,
	}
	nlri2, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	bgpMessage2 := bgp.NewBGPUpdateMessage(nil, pathAttributes2, []bgp.PathNLRI{{NLRI: nlri2}})

	peer1 := peerR1()
	pList, err := tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	peer2 := peerR2()
	pList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	// check type
	path := pList[0]
	assert.Equal(t, path.GetFamily(), bgp.RF_IPv4_UC)

	// check PathAttribute
	checkPattr := func(expected *bgp.BGPMessage, actual *Path) {
		pathAttributes := expected.Body.(*bgp.BGPUpdate).PathAttributes
		expectedOrigin := pathAttributes[0]
		attr := actual.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
		pathOrigin := attr.(*bgp.PathAttributeOrigin)
		assert.Equal(t, expectedOrigin, pathOrigin)

		expectedAsPath := pathAttributes[1]
		attr = actual.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
		pathAspath := attr.(*bgp.PathAttributeAsPath)
		assert.Equal(t, expectedAsPath, pathAspath)

		expectedNexthopAttr := pathAttributes[2]
		attr = actual.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
		pathNexthop := attr.(*bgp.PathAttributeNextHop)
		assert.Equal(t, expectedNexthopAttr, pathNexthop)

		expectedMed := pathAttributes[3]
		attr = actual.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
		pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
		assert.Equal(t, expectedMed, pathMed)

		// check PathAttribute length
		assert.Equal(t, len(pathAttributes), len(path.GetPathAttrs()))
	}
	checkPattr(bgpMessage2, path)
	// check destination
	expectedPrefix := "10.10.10.0/24"
	assert.Equal(t, expectedPrefix, path.GetPrefix())
	// check nexthop
	expectedNexthop := "192.168.100.1"
	assert.Equal(t, expectedNexthop, path.GetNexthop().String())

	// withdraw path
	w1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	w := []bgp.PathNLRI{{NLRI: w1}}
	bgpMessage3 := bgp.NewBGPUpdateMessage(w, nil, nil)

	pList, err = tm.ProcessUpdate(peer2, bgpMessage3)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	path = pList[0]
	assert.Equal(t, path.GetFamily(), bgp.RF_IPv4_UC)

	checkPattr(bgpMessage1, path)
	// check destination
	expectedPrefix = "10.10.10.0/24"
	assert.Equal(t, expectedPrefix, path.GetPrefix())
	// check nexthop
	expectedNexthop = "192.168.50.1"
	assert.Equal(t, expectedNexthop, path.GetNexthop().String())
}

// TODO MP_UNREACH
func TestProcessBGPUpdate_8_mpunreach_path_ipv6(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv6_UC})

	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint32{65000})
	nlri1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:123:1::/64"))
	mpReach1, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri1}}, netip.MustParseAddr("2001::192:168:50:1"))
	med1 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		mpReach1, origin1, aspath1, med1, localpref1,
	}

	bgpMessage1 := bgp.NewBGPUpdateMessage(nil, pathAttributes1, nil)

	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint32{65100, 65000})
	nlri2, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:123:1::/64"))
	mpReach2, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri2}}, netip.MustParseAddr("2001::192:168:100:1"))
	med2 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref2 := bgp.NewPathAttributeLocalPref(200)

	pathAttributes2 := []bgp.PathAttributeInterface{
		mpReach2, origin2, aspath2, med2, localpref2,
	}

	bgpMessage2 := bgp.NewBGPUpdateMessage(nil, pathAttributes2, nil)

	peer1 := peerR1()
	pList, err := tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	peer2 := peerR2()
	pList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	// check type
	path := pList[0]
	assert.Equal(t, path.GetFamily(), bgp.RF_IPv6_UC)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes

	expectedNexthopAttr := pathAttributes[0]
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
	pathNexthop := attr.(*bgp.PathAttributeMpReachNLRI)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedOrigin := pathAttributes[1]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[2]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedMed := pathAttributes[3]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute
	checkPattr := func(expected *bgp.BGPMessage, actual *Path) {
		pathAttributes := expected.Body.(*bgp.BGPUpdate).PathAttributes

		expectedNexthopAttr := pathAttributes[0]
		attr = actual.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
		pathNexthop := attr.(*bgp.PathAttributeMpReachNLRI)
		assert.Equal(t, expectedNexthopAttr, pathNexthop)

		expectedOrigin := pathAttributes[1]
		attr = actual.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
		pathOrigin := attr.(*bgp.PathAttributeOrigin)
		assert.Equal(t, expectedOrigin, pathOrigin)

		expectedAsPath := pathAttributes[2]
		attr = actual.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
		pathAspath := attr.(*bgp.PathAttributeAsPath)
		assert.Equal(t, expectedAsPath, pathAspath)

		expectedMed := pathAttributes[3]
		attr = actual.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
		pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
		assert.Equal(t, expectedMed, pathMed)
		// check PathAttribute length
		assert.Equal(t, len(pathAttributes), len(path.GetPathAttrs()))
	}

	checkPattr(bgpMessage2, path)

	// check destination
	expectedPrefix := "2001:123:123:1::/64"
	assert.Equal(t, expectedPrefix, path.GetPrefix())
	// check nexthop
	expectedNexthop := "2001::192:168:100:1"
	assert.Equal(t, expectedNexthop, path.GetNexthop().String())

	// mpunreach path
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:123:1::/64"))
	mpUnreach, _ := bgp.NewPathAttributeMpUnreachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri}})
	bgpMessage3 := bgp.NewBGPUpdateMessage(nil, []bgp.PathAttributeInterface{mpUnreach}, nil)

	pList, err = tm.ProcessUpdate(peer2, bgpMessage3)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	path = pList[0]
	assert.Equal(t, path.GetFamily(), bgp.RF_IPv6_UC)

	checkPattr(bgpMessage1, path)
	// check destination
	expectedPrefix = "2001:123:123:1::/64"
	assert.Equal(t, expectedPrefix, path.GetPrefix())
	// check nexthop
	expectedNexthop = "2001::192:168:50:1"
	assert.Equal(t, expectedNexthop, path.GetNexthop().String())
}

// handle bestpath lost
func TestProcessBGPUpdate_bestpath_lost_ipv4(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})

	// path1
	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint32{65000})
	nexthop1, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.50.1"))
	med1 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		origin1, aspath1, nexthop1, med1, localpref1,
	}
	nlri1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	bgpMessage1 := bgp.NewBGPUpdateMessage(nil, pathAttributes1, []bgp.PathNLRI{{NLRI: nlri1}})

	// path 1 withdraw
	w1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	w := []bgp.PathNLRI{{NLRI: w1}}
	bgpMessage1_w := bgp.NewBGPUpdateMessage(w, nil, nil)

	peer1 := peerR1()
	pList, err := tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	pList, err = tm.ProcessUpdate(peer1, bgpMessage1_w)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, true)
	assert.NoError(t, err)

	// check old best path
	path := pList[0]
	assert.Equal(t, path.GetFamily(), bgp.RF_IPv4_UC)

	// check PathAttribute
	checkPattr := func(expected *bgp.BGPMessage, actual *Path) {
		pathAttributes := expected.Body.(*bgp.BGPUpdate).PathAttributes
		expectedOrigin := pathAttributes[0]
		attr := actual.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
		pathOrigin := attr.(*bgp.PathAttributeOrigin)
		assert.Equal(t, expectedOrigin, pathOrigin)

		expectedAsPath := pathAttributes[1]
		attr = actual.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
		pathAspath := attr.(*bgp.PathAttributeAsPath)
		assert.Equal(t, expectedAsPath, pathAspath)

		expectedNexthopAttr := pathAttributes[2]
		attr = actual.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
		pathNexthop := attr.(*bgp.PathAttributeNextHop)
		assert.Equal(t, expectedNexthopAttr, pathNexthop)

		expectedMed := pathAttributes[3]
		attr = actual.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
		pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
		assert.Equal(t, expectedMed, pathMed)

		// check PathAttribute length
		assert.Equal(t, len(pathAttributes), len(path.GetPathAttrs()))
	}

	checkPattr(bgpMessage1, path)
	// check destination
	expectedPrefix := "10.10.10.0/24"
	assert.Equal(t, expectedPrefix, path.GetPrefix())
}

func TestProcessBGPUpdate_bestpath_lost_ipv6(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv6_UC})

	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint32{65000})
	nlri1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:123:1::/64"))
	mpReach1, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri1}}, netip.MustParseAddr("2001::192:168:50:1"))
	med1 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		mpReach1, origin1, aspath1, med1, localpref1,
	}

	bgpMessage1 := bgp.NewBGPUpdateMessage(nil, pathAttributes1, nil)

	peer1 := peerR1()
	pList, err := tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	// path1 mpunreach
	nlri2, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:123:1::/64"))
	mpUnreach, _ := bgp.NewPathAttributeMpUnreachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri2}})
	bgpMessage1_w := bgp.NewBGPUpdateMessage(nil, []bgp.PathAttributeInterface{mpUnreach}, nil)

	pList, err = tm.ProcessUpdate(peer1, bgpMessage1_w)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, true)
	assert.NoError(t, err)

	// check old best path
	path := pList[0]
	assert.Equal(t, path.GetFamily(), bgp.RF_IPv6_UC)

	// check PathAttribute
	checkPattr := func(expected *bgp.BGPMessage, actual *Path) {
		pathAttributes := expected.Body.(*bgp.BGPUpdate).PathAttributes

		expectedNexthopAttr := pathAttributes[0]
		attr := actual.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
		pathNexthop := attr.(*bgp.PathAttributeMpReachNLRI)
		assert.Equal(t, expectedNexthopAttr, pathNexthop)

		expectedOrigin := pathAttributes[1]
		attr = actual.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
		pathOrigin := attr.(*bgp.PathAttributeOrigin)
		assert.Equal(t, expectedOrigin, pathOrigin)

		expectedAsPath := pathAttributes[2]
		attr = actual.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
		pathAspath := attr.(*bgp.PathAttributeAsPath)
		assert.Equal(t, expectedAsPath, pathAspath)

		expectedMed := pathAttributes[3]
		attr = actual.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
		pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
		assert.Equal(t, expectedMed, pathMed)
		// check PathAttribute length
		assert.Equal(t, len(pathAttributes), len(path.GetPathAttrs()))
	}

	checkPattr(bgpMessage1, path)

	// check destination
	expectedPrefix := "2001:123:123:1::/64"
	assert.Equal(t, expectedPrefix, path.GetPrefix())
}

// test: implicit withdrawal case
func TestProcessBGPUpdate_implicit_withdrwal_ipv4(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})

	// path1
	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint32{65000, 65100, 65200})
	nexthop1, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.50.1"))
	med1 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		origin1, aspath1, nexthop1, med1, localpref1,
	}
	nlri1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	bgpMessage1 := bgp.NewBGPUpdateMessage(nil, pathAttributes1, []bgp.PathNLRI{{NLRI: nlri1}})

	// path 1 from same peer but short AS_PATH
	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint32{65000, 65100})
	nexthop2, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.50.1"))
	med2 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref2 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes2 := []bgp.PathAttributeInterface{
		origin2, aspath2, nexthop2, med2, localpref2,
	}
	nlri2, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	bgpMessage2 := bgp.NewBGPUpdateMessage(nil, pathAttributes2, []bgp.PathNLRI{{NLRI: nlri2}})

	peer1 := peerR1()
	pList, err := tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	pList, err = tm.ProcessUpdate(peer1, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	// check type
	path := pList[0]
	assert.Equal(t, path.GetFamily(), bgp.RF_IPv4_UC)

	// check PathAttribute
	checkPattr := func(expected *bgp.BGPMessage, actual *Path) {
		pathAttributes := expected.Body.(*bgp.BGPUpdate).PathAttributes
		expectedOrigin := pathAttributes[0]
		attr := actual.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
		pathOrigin := attr.(*bgp.PathAttributeOrigin)
		assert.Equal(t, expectedOrigin, pathOrigin)

		expectedAsPath := pathAttributes[1]
		attr = actual.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
		pathAspath := attr.(*bgp.PathAttributeAsPath)
		assert.Equal(t, expectedAsPath, pathAspath)

		expectedNexthopAttr := pathAttributes[2]
		attr = actual.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
		pathNexthop := attr.(*bgp.PathAttributeNextHop)
		assert.Equal(t, expectedNexthopAttr, pathNexthop)

		expectedMed := pathAttributes[3]
		attr = actual.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
		pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
		assert.Equal(t, expectedMed, pathMed)

		// check PathAttribute length
		assert.Equal(t, len(pathAttributes), len(path.GetPathAttrs()))
	}
	checkPattr(bgpMessage2, path)
	// check destination
	expectedPrefix := "10.10.10.0/24"
	assert.Equal(t, expectedPrefix, path.GetPrefix())
	// check nexthop
	expectedNexthop := "192.168.50.1"
	assert.Equal(t, expectedNexthop, path.GetNexthop().String())
}

func TestProcessBGPUpdate_implicit_withdrwal_ipv6(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv6_UC})

	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint32{65000, 65100, 65200})
	nlri1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:123:1::/64"))
	mpReach1, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri1}}, netip.MustParseAddr("2001::192:168:50:1"))
	med1 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref1 := bgp.NewPathAttributeLocalPref(200)

	pathAttributes1 := []bgp.PathAttributeInterface{
		mpReach1, origin1, aspath1, med1, localpref1,
	}

	bgpMessage1 := bgp.NewBGPUpdateMessage(nil, pathAttributes1, nil)

	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint32{65000, 65100})
	nlri2, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:123:1::/64"))
	mpReach2, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri2}}, netip.MustParseAddr("2001::192:168:50:1"))
	med2 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref2 := bgp.NewPathAttributeLocalPref(200)

	pathAttributes2 := []bgp.PathAttributeInterface{
		mpReach2, origin2, aspath2, med2, localpref2,
	}

	bgpMessage2 := bgp.NewBGPUpdateMessage(nil, pathAttributes2, nil)

	peer1 := peerR1()
	pList, err := tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	pList, err = tm.ProcessUpdate(peer1, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	// check type
	path := pList[0]
	assert.Equal(t, path.GetFamily(), bgp.RF_IPv6_UC)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes

	expectedNexthopAttr := pathAttributes[0]
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
	pathNexthop := attr.(*bgp.PathAttributeMpReachNLRI)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedOrigin := pathAttributes[1]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[2]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedMed := pathAttributes[3]
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute
	checkPattr := func(expected *bgp.BGPMessage, actual *Path) {
		pathAttributes := expected.Body.(*bgp.BGPUpdate).PathAttributes

		expectedNexthopAttr := pathAttributes[0]
		attr := actual.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
		pathNexthop := attr.(*bgp.PathAttributeMpReachNLRI)
		assert.Equal(t, expectedNexthopAttr, pathNexthop)

		expectedOrigin := pathAttributes[1]
		attr = actual.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
		pathOrigin := attr.(*bgp.PathAttributeOrigin)
		assert.Equal(t, expectedOrigin, pathOrigin)

		expectedAsPath := pathAttributes[2]
		attr = actual.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
		pathAspath := attr.(*bgp.PathAttributeAsPath)
		assert.Equal(t, expectedAsPath, pathAspath)

		expectedMed := pathAttributes[3]
		attr = actual.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
		pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
		assert.Equal(t, expectedMed, pathMed)
		// check PathAttribute length
		assert.Equal(t, len(pathAttributes), len(path.GetPathAttrs()))
	}

	checkPattr(bgpMessage2, path)

	// check destination
	expectedPrefix := "2001:123:123:1::/64"
	assert.Equal(t, expectedPrefix, path.GetPrefix())
	// check nexthop
	expectedNexthop := "2001::192:168:50:1"
	assert.Equal(t, expectedNexthop, path.GetNexthop().String())
}

// check multiple paths
func TestProcessBGPUpdate_multiple_nlri_ipv4(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})

	createPathAttr := func(aspaths []uint32, nh string) []bgp.PathAttributeInterface {
		origin := bgp.NewPathAttributeOrigin(0)
		aspath := createAsPathAttribute(aspaths)
		nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr(nh))
		med := bgp.NewPathAttributeMultiExitDisc(200)
		localpref := bgp.NewPathAttributeLocalPref(100)
		pathAttr := []bgp.PathAttributeInterface{
			origin, aspath, nexthop, med, localpref,
		}
		return pathAttr
	}

	// check PathAttribute
	checkPattr := func(expected *bgp.BGPMessage, actual *Path) {
		pathAttributes := expected.Body.(*bgp.BGPUpdate).PathAttributes
		expectedOrigin := pathAttributes[0]
		attr := actual.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
		pathOrigin := attr.(*bgp.PathAttributeOrigin)
		assert.Equal(t, expectedOrigin, pathOrigin)

		expectedAsPath := pathAttributes[1]
		attr = actual.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
		pathAspath := attr.(*bgp.PathAttributeAsPath)
		assert.Equal(t, expectedAsPath, pathAspath)

		expectedNexthopAttr := pathAttributes[2]
		attr = actual.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
		pathNexthop := attr.(*bgp.PathAttributeNextHop)
		assert.Equal(t, expectedNexthopAttr, pathNexthop)

		expectedMed := pathAttributes[3]
		attr = actual.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
		pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
		assert.Equal(t, expectedMed, pathMed)

		// check PathAttribute length
		assert.Equal(t, len(pathAttributes), len(actual.GetPathAttrs()))
	}

	checkBestPathResult := func(rf bgp.Family, prefix, nexthop string, p *Path, m *bgp.BGPMessage) {
		assert.Equal(t, p.GetFamily(), rf)
		checkPattr(m, p)
		// check destination
		assert.Equal(t, prefix, p.GetPrefix())
		// check nexthop
		assert.Equal(t, nexthop, p.GetNexthop().String())
	}

	// path1
	pathAttributes1 := createPathAttr([]uint32{65000, 65100, 65200}, "192.168.50.1")
	nlri1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	nlri2, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("20.20.20.0/24"))
	nlri3, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("30.30.30.0/24"))
	nlri4, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("40.40.40.0/24"))
	nlri5, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("50.50.50.0/24"))
	nlri := []bgp.PathNLRI{{NLRI: nlri1}, {NLRI: nlri2}, {NLRI: nlri3}, {NLRI: nlri4}, {NLRI: nlri5}}
	bgpMessage1 := bgp.NewBGPUpdateMessage(nil, pathAttributes1, nlri)

	// path2
	pathAttributes2 := createPathAttr([]uint32{65000, 65100, 65300}, "192.168.50.1")
	nlri1, _ = bgp.NewIPAddrPrefix(netip.MustParsePrefix("11.11.11.0/24"))
	nlri2, _ = bgp.NewIPAddrPrefix(netip.MustParsePrefix("22.22.22.0/24"))
	nlri3, _ = bgp.NewIPAddrPrefix(netip.MustParsePrefix("33.33.33.0/24"))
	nlri4, _ = bgp.NewIPAddrPrefix(netip.MustParsePrefix("44.44.44.0/24"))
	nlri5, _ = bgp.NewIPAddrPrefix(netip.MustParsePrefix("55.55.55.0/24"))
	nlri = []bgp.PathNLRI{{NLRI: nlri1}, {NLRI: nlri2}, {NLRI: nlri3}, {NLRI: nlri4}, {NLRI: nlri5}}
	bgpMessage2 := bgp.NewBGPUpdateMessage(nil, pathAttributes2, nlri)

	// path3
	pathAttributes3 := createPathAttr([]uint32{65000, 65100, 65400}, "192.168.50.1")
	nlri1, _ = bgp.NewIPAddrPrefix(netip.MustParsePrefix("77.77.77.0/24"))
	nlri2, _ = bgp.NewIPAddrPrefix(netip.MustParsePrefix("88.88.88.0/24"))
	nlri = []bgp.PathNLRI{{NLRI: nlri1}, {NLRI: nlri2}}
	bgpMessage3 := bgp.NewBGPUpdateMessage(nil, pathAttributes3, nlri)

	// path4
	pathAttributes4 := createPathAttr([]uint32{65000, 65100, 65500}, "192.168.50.1")
	nlri1, _ = bgp.NewIPAddrPrefix(netip.MustParsePrefix("99.99.99.0/24"))
	nlri = []bgp.PathNLRI{{NLRI: nlri1}}
	bgpMessage4 := bgp.NewBGPUpdateMessage(nil, pathAttributes4, nlri)

	peer1 := peerR1()
	pList, err := tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 5, len(pList))
	for _, p := range pList {
		assert.Equal(t, p.IsWithdraw, false)
	}
	assert.NoError(t, err)

	checkBestPathResult(bgp.RF_IPv4_UC, "10.10.10.0/24", "192.168.50.1", pList[0], bgpMessage1)
	checkBestPathResult(bgp.RF_IPv4_UC, "20.20.20.0/24", "192.168.50.1", pList[1], bgpMessage1)
	checkBestPathResult(bgp.RF_IPv4_UC, "30.30.30.0/24", "192.168.50.1", pList[2], bgpMessage1)
	checkBestPathResult(bgp.RF_IPv4_UC, "40.40.40.0/24", "192.168.50.1", pList[3], bgpMessage1)
	checkBestPathResult(bgp.RF_IPv4_UC, "50.50.50.0/24", "192.168.50.1", pList[4], bgpMessage1)

	pList, err = tm.ProcessUpdate(peer1, bgpMessage2)
	assert.Equal(t, 5, len(pList))
	for _, p := range pList {
		assert.Equal(t, p.IsWithdraw, false)
	}
	assert.NoError(t, err)

	checkBestPathResult(bgp.RF_IPv4_UC, "11.11.11.0/24", "192.168.50.1", pList[0], bgpMessage2)
	checkBestPathResult(bgp.RF_IPv4_UC, "22.22.22.0/24", "192.168.50.1", pList[1], bgpMessage2)
	checkBestPathResult(bgp.RF_IPv4_UC, "33.33.33.0/24", "192.168.50.1", pList[2], bgpMessage2)
	checkBestPathResult(bgp.RF_IPv4_UC, "44.44.44.0/24", "192.168.50.1", pList[3], bgpMessage2)
	checkBestPathResult(bgp.RF_IPv4_UC, "55.55.55.0/24", "192.168.50.1", pList[4], bgpMessage2)

	pList, err = tm.ProcessUpdate(peer1, bgpMessage3)
	assert.Equal(t, 2, len(pList))
	for _, p := range pList {
		assert.Equal(t, p.IsWithdraw, false)
	}
	assert.NoError(t, err)

	pList, err = tm.ProcessUpdate(peer1, bgpMessage4)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	// check table
	table := tm.Tables[bgp.RF_IPv4_UC]
	assert.Equal(t, 13, len(table.GetDestinations()))
}

// check multiple paths
func TestProcessBGPUpdate_multiple_nlri_ipv6(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv6_UC})

	createPathAttr := func(aspaths []uint32) []bgp.PathAttributeInterface {
		origin := bgp.NewPathAttributeOrigin(0)
		aspath := createAsPathAttribute(aspaths)
		med := bgp.NewPathAttributeMultiExitDisc(100)
		localpref := bgp.NewPathAttributeLocalPref(100)
		pathAttr := []bgp.PathAttributeInterface{
			origin, aspath, med, localpref,
		}
		return pathAttr
	}

	// check PathAttribute
	checkPattr := func(expected *bgp.BGPMessage, actual *Path) {
		bgpPathAttributes := expected.Body.(*bgp.BGPUpdate).PathAttributes
		bgpUpdateNexthop := bgpPathAttributes[4]
		nexthopStr := bgpUpdateNexthop.(*bgp.PathAttributeMpReachNLRI).Nexthop.String()
		expectedNexthopAttr, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC,
			[]bgp.PathNLRI{{NLRI: actual.GetNlri()}},
			netip.MustParseAddr(nexthopStr))
		attr := actual.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
		pathNexthop := attr.(*bgp.PathAttributeMpReachNLRI)
		assert.Equal(t, expectedNexthopAttr, pathNexthop)

		expectedOrigin := bgpPathAttributes[0]
		attr = actual.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
		pathOrigin := attr.(*bgp.PathAttributeOrigin)
		assert.Equal(t, expectedOrigin, pathOrigin)

		expectedAsPath := bgpPathAttributes[1]
		attr = actual.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
		pathAspath := attr.(*bgp.PathAttributeAsPath)
		assert.Equal(t, expectedAsPath, pathAspath)

		expectedMed := bgpPathAttributes[2]
		attr = actual.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
		pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
		assert.Equal(t, expectedMed, pathMed)

		expectedLocalpref := bgpPathAttributes[3]
		attr = actual.getPathAttr(bgp.BGP_ATTR_TYPE_LOCAL_PREF)
		localpref := attr.(*bgp.PathAttributeLocalPref)
		assert.Equal(t, expectedLocalpref, localpref)

		// check PathAttribute length
		assert.Equal(t, len(bgpPathAttributes), len(actual.GetPathAttrs()))
	}

	checkBestPathResult := func(rf bgp.Family, prefix, nexthop string, p *Path, m *bgp.BGPMessage) {
		assert.Equal(t, p.GetFamily(), rf)
		checkPattr(m, p)
		// check destination
		assert.Equal(t, prefix, p.GetPrefix())
		// check nexthop
		assert.Equal(t, nexthop, p.GetNexthop().String())
	}

	// path1
	pathAttributes1 := createPathAttr([]uint32{65000, 65100, 65200})
	nlri1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:1210:11::/64"))
	nlri2, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:1220:11::/64"))
	nlri3, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:1230:11::/64"))
	nlri4, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:1240:11::/64"))
	nlri5, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:1250:11::/64"))
	mpreach1, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC,
		[]bgp.PathNLRI{{NLRI: nlri1}, {NLRI: nlri2}, {NLRI: nlri3}, {NLRI: nlri4}, {NLRI: nlri5}},
		netip.MustParseAddr("2001::192:168:50:1"))

	pathAttributes1 = append(pathAttributes1, mpreach1)
	bgpMessage1 := bgp.NewBGPUpdateMessage(nil, pathAttributes1, nil)

	// path2
	pathAttributes2 := createPathAttr([]uint32{65000, 65100, 65300})
	nlri1, _ = bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:1211:11::/64"))
	nlri2, _ = bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:1222:11::/64"))
	nlri3, _ = bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:1233:11::/64"))
	nlri4, _ = bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:1244:11::/64"))
	nlri5, _ = bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:1255:11::/64"))
	mpreach2, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC,
		[]bgp.PathNLRI{{NLRI: nlri1}, {NLRI: nlri2}, {NLRI: nlri3}, {NLRI: nlri4}, {NLRI: nlri5}},
		netip.MustParseAddr("2001::192:168:50:1"))

	pathAttributes2 = append(pathAttributes2, mpreach2)
	bgpMessage2 := bgp.NewBGPUpdateMessage(nil, pathAttributes2, nil)

	// path3
	pathAttributes3 := createPathAttr([]uint32{65000, 65100, 65400})
	nlri1, _ = bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:1277:11::/64"))
	nlri2, _ = bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:1288:11::/64"))
	mpreach3, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC,
		[]bgp.PathNLRI{{NLRI: nlri1}, {NLRI: nlri2}},
		netip.MustParseAddr("2001::192:168:50:1"))
	pathAttributes3 = append(pathAttributes3, mpreach3)
	bgpMessage3 := bgp.NewBGPUpdateMessage(nil, pathAttributes3, nil)

	// path4
	pathAttributes4 := createPathAttr([]uint32{65000, 65100, 65500})
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:1299:11::/64"))
	mpreach4, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri}}, netip.MustParseAddr("2001::192:168:50:1"))
	pathAttributes4 = append(pathAttributes4, mpreach4)
	bgpMessage4 := bgp.NewBGPUpdateMessage(nil, pathAttributes4, nil)

	peer1 := peerR1()
	pList, err := tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 5, len(pList))
	for _, p := range pList {
		assert.Equal(t, p.IsWithdraw, false)
	}
	assert.NoError(t, err)

	checkBestPathResult(bgp.RF_IPv6_UC, "2001:123:1210:11::/64", "2001::192:168:50:1", pList[0], bgpMessage1)
	checkBestPathResult(bgp.RF_IPv6_UC, "2001:123:1220:11::/64", "2001::192:168:50:1", pList[1], bgpMessage1)
	checkBestPathResult(bgp.RF_IPv6_UC, "2001:123:1230:11::/64", "2001::192:168:50:1", pList[2], bgpMessage1)
	checkBestPathResult(bgp.RF_IPv6_UC, "2001:123:1240:11::/64", "2001::192:168:50:1", pList[3], bgpMessage1)
	checkBestPathResult(bgp.RF_IPv6_UC, "2001:123:1250:11::/64", "2001::192:168:50:1", pList[4], bgpMessage1)

	pList, err = tm.ProcessUpdate(peer1, bgpMessage2)
	assert.Equal(t, 5, len(pList))
	for _, p := range pList {
		assert.Equal(t, p.IsWithdraw, false)
	}
	assert.NoError(t, err)

	checkBestPathResult(bgp.RF_IPv6_UC, "2001:123:1211:11::/64", "2001::192:168:50:1", pList[0], bgpMessage2)
	checkBestPathResult(bgp.RF_IPv6_UC, "2001:123:1222:11::/64", "2001::192:168:50:1", pList[1], bgpMessage2)
	checkBestPathResult(bgp.RF_IPv6_UC, "2001:123:1233:11::/64", "2001::192:168:50:1", pList[2], bgpMessage2)
	checkBestPathResult(bgp.RF_IPv6_UC, "2001:123:1244:11::/64", "2001::192:168:50:1", pList[3], bgpMessage2)
	checkBestPathResult(bgp.RF_IPv6_UC, "2001:123:1255:11::/64", "2001::192:168:50:1", pList[4], bgpMessage2)

	pList, err = tm.ProcessUpdate(peer1, bgpMessage3)
	assert.Equal(t, 2, len(pList))
	for _, p := range pList {
		assert.Equal(t, p.IsWithdraw, false)
	}
	assert.NoError(t, err)

	pList, err = tm.ProcessUpdate(peer1, bgpMessage4)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, pList[0].IsWithdraw, false)
	assert.NoError(t, err)

	// check table
	table := tm.Tables[bgp.RF_IPv6_UC]
	assert.Equal(t, 13, len(table.GetDestinations()))
}

func TestProcessBGPUpdate_multiple_nlri_ipv4_split(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})

	origin := bgp.NewPathAttributeOrigin(0)
	aspath := createAsPathAttribute([]uint32{65000, 65100, 65200})
	n1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.1/32"))
	n2, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.2/32"))
	n3, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.3/32"))
	mpReach, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv4_UC,
		[]bgp.PathNLRI{{NLRI: n1}, {NLRI: n2}, {NLRI: n3}},
		netip.MustParseAddr("10.50.60.70"))
	med := bgp.NewPathAttributeMultiExitDisc(200)
	localpref := bgp.NewPathAttributeLocalPref(200)
	pathAttributes := []bgp.PathAttributeInterface{
		mpReach, origin, aspath, med, localpref,
	}
	bgpMessage := bgp.NewBGPUpdateMessage(nil, pathAttributes, nil)

	peer1 := peerR1()
	pList, err := tm.ProcessUpdate(peer1, bgpMessage)
	assert.Equal(t, len(mpReach.Value), len(pList))
	for i, p := range pList {
		attr := p.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI).(*bgp.PathAttributeMpReachNLRI)
		assert.Equal(t, mpReach.Nexthop, attr.Nexthop)
		assert.Equal(t, []bgp.PathNLRI{{NLRI: mpReach.Value[i].NLRI}}, attr.Value)
	}
	assert.NoError(t, err)
}

func TestProcessBGPUpdate_Timestamp(t *testing.T) {
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{65000})}
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

	adjRib := NewAdjRib(logger, []bgp.Family{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC})
	m1 := bgp.NewBGPUpdateMessage(nil, pathAttributes, []bgp.PathNLRI{{NLRI: nlri}})
	peer := peerR1()
	pList1 := ProcessMessage(m1, peer, time.Now(), false)
	path1 := pList1[0]
	t1 := path1.GetTimestamp()
	adjRib.Update(pList1)

	m2 := bgp.NewBGPUpdateMessage(nil, pathAttributes, []bgp.PathNLRI{{NLRI: nlri}})
	pList2 := ProcessMessage(m2, peer, time.Now(), false)
	// path2 := pList2[0].(*IPv4Path)
	// t2 = path2.timestamp
	adjRib.Update(pList2)

	inList := adjRib.PathList([]bgp.Family{bgp.RF_IPv4_UC}, false)
	assert.Equal(t, len(inList), 1)
	assert.Equal(t, inList[0].GetTimestamp(), t1)

	med2 := bgp.NewPathAttributeMultiExitDisc(1)
	pathAttributes2 := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med2,
	}

	m3 := bgp.NewBGPUpdateMessage(nil, pathAttributes2, []bgp.PathNLRI{{NLRI: nlri}})
	pList3 := ProcessMessage(m3, peer, time.Now(), false)
	t3 := pList3[0].GetTimestamp()
	adjRib.Update(pList3)

	inList = adjRib.PathList([]bgp.Family{bgp.RF_IPv4_UC}, false)
	assert.Equal(t, len(inList), 1)
	assert.Equal(t, inList[0].GetTimestamp(), t3)
}

func update_fromR1() *bgp.BGPMessage {
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{65000})}
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

func update_fromR1_ipv6() *bgp.BGPMessage {
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{65000})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)

	mp_nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:123:123:1::/64"))
	mpReach, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: mp_nlri}}, netip.MustParseAddr("2001::192:168:50:1"))
	med := bgp.NewPathAttributeMultiExitDisc(0)

	pathAttributes := []bgp.PathAttributeInterface{
		mpReach,
		origin,
		aspath,
		med,
	}
	return bgp.NewBGPUpdateMessage(nil, pathAttributes, nil)
}

func update_fromR2() *bgp.BGPMessage {
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{65100})}
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

func update_fromR2_ipv6() *bgp.BGPMessage {
	origin := bgp.NewPathAttributeOrigin(0)
	aspath := createAsPathAttribute([]uint32{65100})
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2002:223:123:1::/64"))
	mpReach, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri}}, netip.MustParseAddr("2001::192:168:100:1"))
	med := bgp.NewPathAttributeMultiExitDisc(100)

	pathAttributes := []bgp.PathAttributeInterface{
		mpReach,
		origin,
		aspath,
		med,
	}
	return bgp.NewBGPUpdateMessage(nil, pathAttributes, nil)
}

func createAsPathAttribute(ases []uint32) *bgp.PathAttributeAsPath {
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, ases)}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	return aspath
}

func update_fromR2viaR1() *bgp.BGPMessage {
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{65000, 65100})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.50.1"))

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
	}

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("20.20.20.0/24"))
	return bgp.NewBGPUpdateMessage(nil, pathAttributes, []bgp.PathNLRI{{NLRI: nlri}})
}

func update_fromR2viaR1_ipv6() *bgp.BGPMessage {
	origin := bgp.NewPathAttributeOrigin(0)
	aspath := createAsPathAttribute([]uint32{65000, 65100})
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2002:223:123:1::/64"))
	mpReach, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri}}, netip.MustParseAddr("2001::192:168:50:1"))
	med := bgp.NewPathAttributeMultiExitDisc(100)

	pathAttributes := []bgp.PathAttributeInterface{
		mpReach,
		origin,
		aspath,
		med,
	}
	return bgp.NewBGPUpdateMessage(nil, pathAttributes, nil)
}

func parseRDRT(rdStr string) (bgp.RouteDistinguisherInterface, bgp.ExtendedCommunityInterface, error) {
	rd, err := bgp.ParseRouteDistinguisher(rdStr)
	if err != nil {
		return nil, nil, err
	}

	rt, err := bgp.ParseExtendedCommunity(bgp.EC_SUBTYPE_ROUTE_TARGET, rdStr)
	if err != nil {
		return nil, nil, err
	}
	return rd, rt, nil
}

func createPeerInfo(as uint32, localId string) *PeerInfo {
	return &PeerInfo{
		AS:      as,
		LocalID: netip.MustParseAddr(localId),
	}
}

func makeVpn4Path(t *testing.T, peerInfo *PeerInfo, address string, nh string, rdStr string, importRtsStr []string) *Path {
	rts := make([]bgp.ExtendedCommunityInterface, 0, len(importRtsStr))
	for _, rtStr := range importRtsStr {
		_, rt, err := parseRDRT(rtStr)
		if err != nil {
			t.Fatal(err)
		}
		rts = append(rts, rt)
	}

	panh, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr(nh))
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		panh,
		bgp.NewPathAttributeExtendedCommunities(rts),
	}
	rd, _ := bgp.ParseRouteDistinguisher(rdStr)
	labels := bgp.NewMPLSLabelStack(100, 200)
	prefix, _ := bgp.NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix(address+"/24"), *labels, rd)
	return NewPath(bgp.RF_IPv4_VPN, peerInfo, bgp.PathNLRI{NLRI: prefix}, false, attrs, time.Now(), false)
}

func makeRtcPath(t *testing.T, peerInfo *PeerInfo, rtStr string, withdraw bool) *Path {
	panh, _ := bgp.NewPathAttributeNextHop(netip.IPv4Unspecified())
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		panh,
	}

	_, rt, err := parseRDRT(rtStr)
	if err != nil {
		t.Fatal(err)
	}

	prefix := bgp.NewRouteTargetMembershipNLRI(peerInfo.AS, rt)

	return NewPath(bgp.RF_RTC_UC, peerInfo, bgp.PathNLRI{NLRI: prefix}, withdraw, attrs, time.Now(), false)
}

func addVrf(t *testing.T, tm *TableManager, peerInfo *PeerInfo, vrfName, rdStr string, importRtsStr []string, exportRtsStr []string, id uint32) *Vrf {
	rd, _, err := parseRDRT(rdStr)
	if err != nil {
		t.Fatal(err)
	}

	importRts := make([]bgp.ExtendedCommunityInterface, 0, len(importRtsStr))
	rtPaths := make([]string, 0, len(importRtsStr))
	for _, importRtStr := range importRtsStr {
		_, rt, err := parseRDRT(importRtStr)
		if err != nil {
			t.Fatal(err)
		}
		importRts = append(importRts, rt)

		rtPath := makeRtcPath(t, peerInfo, importRtStr, false)
		rtPaths = append(rtPaths, rtPath.String())
	}

	exportRts := make([]bgp.ExtendedCommunityInterface, 0, len(exportRtsStr))
	for _, exportRtStr := range exportRtsStr {
		_, rt, err := parseRDRT(exportRtStr)
		if err != nil {
			t.Fatal(err)
		}
		exportRts = append(exportRts, rt)
	}

	outputRts, err := tm.AddVrf(vrfName, id, rd, importRts, exportRts, peerInfo)
	assert.NoError(t, err)
	assert.Equal(t, len(importRtsStr), len(outputRts))
	for _, outputRt := range outputRts {
		assert.Contains(t, rtPaths, outputRt.String())
		tm.Update(outputRt)
	}

	return tm.Vrfs[vrfName]
}

func TestVRF(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv6_VPN, bgp.RF_IPv4_VPN, bgp.RF_RTC_UC})
	peerInfo := createPeerInfo(64511, "127.0.0.11")
	uniqueImportRTs := []string{"111:111", "111:222", "111:333"}
	sharedImportRTs := []string{"111:444", "111:555"}
	firstVrfName := "firstVrf"
	secondVrfName := "secondVrf"
	vrf := addVrf(t, tm, peerInfo, firstVrfName, "111:100", append(uniqueImportRTs, sharedImportRTs...), []string{"222:111", "222:222"}, 1)
	assert.NotNil(t, vrf)

	vrf2 := addVrf(t, tm, peerInfo, secondVrfName, "222:100", sharedImportRTs, []string{"222:111", "222:222"}, 1)
	assert.NotNil(t, vrf2)

	pathCanImport := makeVpn4Path(t, peerInfo, "10.20.30.0", "8.8.8.8", "111:100", []string{"555:444", "111:222", "555:555"})
	assert.True(t, CanImportToVrf(vrf, pathCanImport))

	pathCantImport := makeVpn4Path(t, peerInfo, "10.20.30.0", "8.8.8.8", "111:100", []string{"555:444", "555:555", "222:222"})
	assert.False(t, CanImportToVrf(vrf, pathCantImport))

	// firstDeletedRTs must contain unique rts only.
	firstDeletedRTs, err := tm.DeleteVrf(firstVrfName)
	assert.NoError(t, err)
	assert.Equal(t, len(uniqueImportRTs), len(firstDeletedRTs))
	deletedRTsStr := make([]string, 0, len(firstDeletedRTs))
	for _, deletedRT := range firstDeletedRTs {
		deletedRTsStr = append(deletedRTsStr, deletedRT.String())
	}
	for _, importRT := range uniqueImportRTs {
		importRTStr := makeRtcPath(t, peerInfo, importRT, true).String()
		assert.Contains(t, deletedRTsStr, importRTStr)
	}

	// secondDeletedRTs must contain all the remaining rts.
	secondDeletedRTs, err := tm.DeleteVrf(secondVrfName)
	assert.NoError(t, err)
	assert.Equal(t, len(sharedImportRTs), len(secondDeletedRTs))
	deletedRTsStr = make([]string, 0, len(secondDeletedRTs))
	for _, deletedRT := range secondDeletedRTs {
		deletedRTsStr = append(deletedRTsStr, deletedRT.String())
	}
	for _, importRT := range sharedImportRTs {
		importRTStr := makeRtcPath(t, peerInfo, importRT, true).String()
		assert.Contains(t, deletedRTsStr, importRTStr)
	}
}

func TestTableManagerRTC(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv6_VPN, bgp.RF_IPv4_VPN, bgp.RF_IPv4_UC})

	rtStrings := []string{"100:100", "100:200", "100:300", "100:400"}
	rts := make([]bgp.ExtendedCommunityInterface, 0)
	for _, strRT := range rtStrings {
		rt, err := bgp.ParseRouteTarget(strRT)
		assert.NoError(t, err)
		rts = append(rts, rt)
	}
	assert.Equal(t, 4, len(rts))

	declarations6 := []testPathWithRTs{
		{
			rd:     "100:100",
			prefix: "100:1::/64",
			rts:    []bgp.ExtendedCommunityInterface{rts[3]},
		},
		{
			rd:     "101:100",
			prefix: "100:3:1::/48",
			rts:    []bgp.ExtendedCommunityInterface{rts[3], rts[1]},
		},
		{
			rd:     "100:300",
			prefix: "10.10.10.13/32",
			rts:    []bgp.ExtendedCommunityInterface{rts[2]},
		},
	}
	var paths6 []*Path
	tm.Tables[bgp.RF_IPv6_VPN], paths6 = makeTableWithRT(t, tm.Tables[bgp.RF_IPv6_VPN], declarations6, bgp.RF_IPv6_VPN)

	declarations4 := []testPathWithRTs{
		{
			rd:     "100:100",
			prefix: "10.10.10.10/32",
			rts:    []bgp.ExtendedCommunityInterface{rts[0]},
		},
		{
			rd:     "101:100",
			prefix: "10.10.10.11/32",
			rts:    []bgp.ExtendedCommunityInterface{rts[0], rts[1]},
		},
		{
			rd:     "100:200",
			prefix: "10.10.10.12/32",
			rts:    []bgp.ExtendedCommunityInterface{rts[1]},
		},
		{
			rd:     "100:300",
			prefix: "10.10.10.13/32",
			rts:    []bgp.ExtendedCommunityInterface{rts[2]},
		},
	}
	var paths4 []*Path
	tm.Tables[bgp.RF_IPv4_VPN], paths4 = makeTableWithRT(t, tm.Tables[bgp.RF_IPv4_VPN], declarations4, bgp.RF_IPv4_VPN)

	hash0, err := ExtCommRouteTargetKey(rts[0])
	assert.NoError(t, err)
	pathsRT := tm.GetBestPathListForAddedRT(hash0, "127.0.0.1:1", "global", 0,
		[]bgp.Family{bgp.RF_IPv6_VPN, bgp.RF_IPv4_VPN, bgp.RF_IPv4_UC})
	assert.Equal(t, 2, len(pathsRT))
	assert.True(t, equalPaths(pathsRT, []*Path{paths4[0], paths4[1]}))

	hash1, err := ExtCommRouteTargetKey(rts[1])
	assert.NoError(t, err)

	pathsRT = tm.GetBestPathListForAddedRT(hash1, "127.0.0.1:1", "global", 0,
		[]bgp.Family{bgp.RF_IPv6_VPN, bgp.RF_IPv4_VPN, bgp.RF_IPv4_UC})
	assert.Equal(t, 3, len(pathsRT))
	assert.True(t, equalPaths(pathsRT, []*Path{paths4[1], paths4[2], paths6[1]}))

	hash2, err := ExtCommRouteTargetKey(rts[2])
	assert.NoError(t, err)

	pathsRT = tm.GetBestPathListForAddedRT(hash2, "127.0.0.1:1", "global", 0,
		[]bgp.Family{bgp.RF_IPv6_VPN, bgp.RF_IPv4_VPN, bgp.RF_IPv4_UC})
	assert.Equal(t, 2, len(pathsRT))
	assert.True(t, equalPaths(pathsRT, []*Path{paths4[3], paths6[2]}))

	pathsRT = tm.GetBestPathListForAddedRT(hash1, "127.0.0.1:1", "global", 0,
		[]bgp.Family{bgp.RF_IPv6_VPN, bgp.RF_IPv4_VPN, bgp.RF_IPv4_UC})
	assert.Equal(t, 0, len(pathsRT))

	pathsRT = tm.GetBestPathListForAddedRT(hash0, "127.0.0.1:2", "global", 0,
		[]bgp.Family{bgp.RF_IPv6_VPN, bgp.RF_IPv4_VPN, bgp.RF_IPv4_UC})
	assert.Equal(t, 2, len(pathsRT))
	assert.True(t, equalPaths(pathsRT, []*Path{paths4[0], paths4[1]}))

	pathsRT = tm.GetBestPathListForAddedRT(hash1, "127.0.0.1:2", "global", 0,
		[]bgp.Family{bgp.RF_IPv6_VPN, bgp.RF_IPv4_VPN, bgp.RF_IPv4_UC})
	assert.Equal(t, 3, len(pathsRT))
	assert.True(t, equalPaths(pathsRT, []*Path{paths4[1], paths4[2], paths6[1]}))

	hash3, err := ExtCommRouteTargetKey(rts[3])
	assert.NoError(t, err)
	pathsRT = tm.GetBestPathListForAddedRT(hash3, "127.0.0.1:2", "global", 0,
		[]bgp.Family{bgp.RF_IPv6_VPN, bgp.RF_IPv4_VPN, bgp.RF_IPv4_UC})
	assert.Equal(t, 2, len(pathsRT))
	assert.True(t, equalPaths(pathsRT, []*Path{paths6[0], paths6[1]}))

	update := tm.Tables[bgp.RF_IPv4_VPN].update(paths4[2].Clone(true))
	assert.Equal(t, 0, len(update.KnownPathList))
	assert.Equal(t, 1, len(update.OldKnownPathList))
	assert.True(t, update.OldKnownPathList[0].Equal(paths4[2]))

	update = tm.Tables[bgp.RF_IPv4_VPN].update(paths4[1].Clone(false))
	assert.Equal(t, 1, len(update.KnownPathList))
	assert.Equal(t, 1, len(update.OldKnownPathList))
	assert.True(t, update.KnownPathList[0].Equal(paths4[1]))
	assert.True(t, update.OldKnownPathList[0].Equal(paths4[1]))

	update = tm.Tables[bgp.RF_IPv6_VPN].update(paths6[1].Clone(true))
	assert.Equal(t, 0, len(update.KnownPathList))
	assert.Equal(t, 1, len(update.OldKnownPathList))
	assert.True(t, update.OldKnownPathList[0].Equal(paths6[1]))

	rf := []bgp.Family{bgp.RF_IPv6_VPN, bgp.RF_IPv4_VPN, bgp.RF_IPv4_UC}

	pathsRT = tm.GetBestPathListForAddedRT(hash0, "127.0.0.1:1", "global", 0, rf)
	assert.Equal(t, 0, len(pathsRT))

	pathsRT = tm.GetBestPathListForAddedRT(hash1, "127.0.0.1:1", "global", 0, rf)
	assert.Equal(t, 0, len(pathsRT))

	pathsRT = tm.GetBestPathListForAddedRT(hash2, "127.0.0.1:1", "global", 0, rf)
	assert.Equal(t, 0, len(pathsRT))

	pathsRT = tm.GetBestPathListForWithdrawnRT(tm.BestPathListForRTMaxLen(hash0, rf), hash0, "127.0.0.1:1", "global", 0, rf)
	assert.Equal(t, 2, len(pathsRT))
	assert.True(t, equalPaths(pathsRT, []*Path{paths4[0], paths4[1]}))

	pathsRT = tm.GetBestPathListForWithdrawnRT(0, hash1, "127.0.0.1:1", "global", 0, rf)
	assert.Equal(t, 1, len(pathsRT))
	assert.True(t, equalPaths(pathsRT, []*Path{paths4[1]}))

	pathsRT = tm.GetBestPathListForAddedRT(hash1, "127.0.0.1:1", "global", 0, rf)
	assert.Equal(t, 1, len(pathsRT))
	assert.True(t, equalPaths(pathsRT, []*Path{paths4[1]}))

	pathsRT = tm.GetBestPathListForAddedRT(hash2, "127.0.0.1:3", "global", 0, rf)
	assert.Equal(t, 2, len(pathsRT))
	assert.True(t, equalPaths(pathsRT, []*Path{paths4[3], paths6[2]}))

	pathsRT = tm.GetBestPathListForAddedRT(hash2, "127.0.0.1:3", "global", 0, rf)
	assert.Equal(t, 0, len(pathsRT))

	pathsRT = tm.GetBestPathListForWithdrawnRT(30, hash2, "127.0.0.1:3", "global", 0, rf)
	assert.Equal(t, 2, len(pathsRT))
	assert.True(t, equalPaths(pathsRT, []*Path{paths4[3], paths6[2]}))
}
