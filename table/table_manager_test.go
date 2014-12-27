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
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/packet"
	"github.com/stretchr/testify/assert"
	"net"
	"os"
	"reflect"
	"testing"
)

func getLogger(lv log.Level) *log.Logger {
	var l *log.Logger = &log.Logger{
		Out:       os.Stderr,
		Formatter: new(log.JSONFormatter),
		Hooks:     make(map[log.Level][]log.Hook),
		Level:     lv,
	}
	return l
}

func peerR1() *PeerInfo {
	peer := &PeerInfo{
		VersionNum: 4,
		AS:         65000,
		ID:         net.ParseIP("10.0.0.3").To4(),
		LocalID:    net.ParseIP("10.0.0.1").To4(),
	}
	return peer
}

func peerR2() *PeerInfo {
	peer := &PeerInfo{
		VersionNum: 4,
		AS:         65100,
	}
	return peer
}

func peerR3() *PeerInfo {
	peer := &PeerInfo{
		VersionNum: 4,
		AS:         65000,
		ID:         net.ParseIP("10.0.0.2").To4(),
		LocalID:    net.ParseIP("10.0.0.1").To4(),
	}
	return peer
}

// test best path calculation and check the result path is from R1
func TestProcessBGPUpdate_0_select_onlypath_ipv4(t *testing.T) {

	tm := NewTableManager()

	bgpMessage := update_fromR1()
	peer := peerR1()
	pList, wList, err := tm.ProcessUpdate(peer, bgpMessage)
	assert.Equal(t, len(pList), 1)
	assert.Equal(t, len(wList), 0)
	assert.NoError(t, err)

	// check type
	path := pList[0]
	expectedType := "*table.IPv4Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType)

	// check PathAttribute
	pathAttributes := bgpMessage.Body.(*bgp.BGPUpdate).PathAttributes
	expectedOrigin := pathAttributes[0]
	_, attr := path.GetPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[1]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedNexthopAttr := pathAttributes[2]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	pathNexthop := attr.(*bgp.PathAttributeNextHop)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedMed := pathAttributes[3]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, 4, len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "10.10.10.0"
	assert.Equal(t, expectedPrefix, path.getPrefix().String())
	// check nexthop
	expectedNexthop := "192.168.50.1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String())

}

// test best path calculation and check the result path is from R1
func TestProcessBGPUpdate_0_select_onlypath_ipv6(t *testing.T) {

	tm := NewTableManager()

	bgpMessage := update_fromR1_ipv6()
	peer := peerR1()
	pList, wList, err := tm.ProcessUpdate(peer, bgpMessage)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	// check type
	path := pList[0]
	expectedType := "*table.IPv6Path"
	assert.Equal(t, expectedType, reflect.TypeOf(path).String())

	// check PathAttribute
	pathAttributes := bgpMessage.Body.(*bgp.BGPUpdate).PathAttributes

	expectedNexthopAttr := pathAttributes[0]
	_, attr := path.GetPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
	pathNexthop := attr.(*bgp.PathAttributeMpReachNLRI)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedOrigin := pathAttributes[1]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[2]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedMed := pathAttributes[3]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, 4, len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "2001:123:123:1::"
	assert.Equal(t, expectedPrefix, path.getPrefix().String())
	// check nexthop
	expectedNexthop := "2001::192:168:50:1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String())

}

// test: compare localpref
func TestProcessBGPUpdate_1_select_high_localpref_ipv4(t *testing.T) {

	tm := NewTableManager()
	var pList []Path
	var wList []Destination
	var err error

	// low localpref message
	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint16{65000})
	nexthop1 := bgp.NewPathAttributeNextHop("192.168.50.1")
	med1 := bgp.NewPathAttributeMultiExitDisc(0)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		origin1, aspath1, nexthop1, med1, localpref1,
	}
	nlri1 := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.10.0")}
	withdrawnRoutes1 := []bgp.WithdrawnRoute{}
	bgpMessage1 := bgp.NewBGPUpdateMessage(withdrawnRoutes1, pathAttributes1, nlri1)

	// high localpref message
	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint16{65100, 65000})
	nexthop2 := bgp.NewPathAttributeNextHop("192.168.50.1")
	med2 := bgp.NewPathAttributeMultiExitDisc(100)
	localpref2 := bgp.NewPathAttributeLocalPref(200)

	pathAttributes2 := []bgp.PathAttributeInterface{
		origin2, aspath2, nexthop2, med2, localpref2,
	}
	nlri2 := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.10.0")}
	withdrawnRoutes2 := []bgp.WithdrawnRoute{}
	bgpMessage2 := bgp.NewBGPUpdateMessage(withdrawnRoutes2, pathAttributes2, nlri2)

	peer1 := peerR1()
	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	peer2 := peerR2()
	pList, wList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	// check type
	path := pList[0]
	expectedType := "*table.IPv4Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes
	expectedOrigin := pathAttributes[0]
	_, attr := path.GetPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[1]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedNexthopAttr := pathAttributes[2]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	pathNexthop := attr.(*bgp.PathAttributeNextHop)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedMed := pathAttributes[3]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, len(pathAttributes2), len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "10.10.10.0"
	assert.Equal(t, expectedPrefix, path.getPrefix().String())
	// check nexthop
	expectedNexthop := "192.168.50.1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String())

}

func TestProcessBGPUpdate_1_select_high_localpref_ipv6(t *testing.T) {

	tm := NewTableManager()
	var pList []Path
	var wList []Destination
	var err error

	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint16{65000})
	mp_reach1 := createMpReach("2001::192:168:50:1",
		[]bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")})
	med1 := bgp.NewPathAttributeMultiExitDisc(100)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		mp_reach1, origin1, aspath1, med1, localpref1,
	}

	nlri1 := []bgp.NLRInfo{}
	withdrawnRoutes1 := []bgp.WithdrawnRoute{}
	bgpMessage1 := bgp.NewBGPUpdateMessage(withdrawnRoutes1, pathAttributes1, nlri1)

	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint16{65100, 65000})
	mp_reach2 := createMpReach("2001::192:168:100:1",
		[]bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")})
	med2 := bgp.NewPathAttributeMultiExitDisc(100)
	localpref2 := bgp.NewPathAttributeLocalPref(200)

	pathAttributes2 := []bgp.PathAttributeInterface{
		mp_reach2, origin2, aspath2, med2, localpref2,
	}

	nlri2 := []bgp.NLRInfo{}
	withdrawnRoutes2 := []bgp.WithdrawnRoute{}
	bgpMessage2 := bgp.NewBGPUpdateMessage(withdrawnRoutes2, pathAttributes2, nlri2)

	peer1 := peerR1()
	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	peer2 := peerR2()
	pList, wList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	// check type
	path := pList[0]
	expectedType := "*table.IPv6Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes

	expectedNexthopAttr := pathAttributes[0]
	_, attr := path.GetPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
	pathNexthop := attr.(*bgp.PathAttributeMpReachNLRI)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedOrigin := pathAttributes[1]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[2]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedMed := pathAttributes[3]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, 5, len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "2001:123:123:1::"
	assert.Equal(t, expectedPrefix, path.getPrefix().String())
	// check nexthop
	expectedNexthop := "2001::192:168:100:1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String())

}

// test: compare localOrigin
func TestProcessBGPUpdate_2_select_local_origin_ipv4(t *testing.T) {

	tm := NewTableManager()
	var pList []Path
	var wList []Destination
	var err error

	// low localpref message
	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint16{65000})
	nexthop1 := bgp.NewPathAttributeNextHop("192.168.50.1")
	med1 := bgp.NewPathAttributeMultiExitDisc(0)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		origin1, aspath1, nexthop1, med1, localpref1,
	}
	nlri1 := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.10.0")}
	withdrawnRoutes1 := []bgp.WithdrawnRoute{}
	bgpMessage1 := bgp.NewBGPUpdateMessage(withdrawnRoutes1, pathAttributes1, nlri1)

	// high localpref message
	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint16{})
	nexthop2 := bgp.NewPathAttributeNextHop("0.0.0.0")
	med2 := bgp.NewPathAttributeMultiExitDisc(100)
	localpref2 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes2 := []bgp.PathAttributeInterface{
		origin2, aspath2, nexthop2, med2, localpref2,
	}
	nlri2 := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.10.0")}
	withdrawnRoutes2 := []bgp.WithdrawnRoute{}
	bgpMessage2 := bgp.NewBGPUpdateMessage(withdrawnRoutes2, pathAttributes2, nlri2)

	peer1 := peerR1()
	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	var peer2 *PeerInfo = nil
	pList, wList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	// check type
	path := pList[0]
	expectedType := "*table.IPv4Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes
	expectedOrigin := pathAttributes[0]
	_, attr := path.GetPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[1]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedNexthopAttr := pathAttributes[2]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	pathNexthop := attr.(*bgp.PathAttributeNextHop)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedMed := pathAttributes[3]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, len(pathAttributes2), len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "10.10.10.0"
	assert.Equal(t, expectedPrefix, path.getPrefix().String())
	// check nexthop
	expectedNexthop := "0.0.0.0"
	assert.Equal(t, expectedNexthop, path.getNexthop().String())

}

func TestProcessBGPUpdate_2_select_local_origin_ipv6(t *testing.T) {

	tm := NewTableManager()
	var pList []Path
	var wList []Destination
	var err error

	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint16{65000})
	mp_reach1 := createMpReach("2001::192:168:50:1",
		[]bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")})
	med1 := bgp.NewPathAttributeMultiExitDisc(100)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		mp_reach1, origin1, aspath1, med1, localpref1,
	}

	nlri1 := []bgp.NLRInfo{}
	withdrawnRoutes1 := []bgp.WithdrawnRoute{}
	bgpMessage1 := bgp.NewBGPUpdateMessage(withdrawnRoutes1, pathAttributes1, nlri1)

	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint16{})
	mp_reach2 := createMpReach("::",
		[]bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")})
	med2 := bgp.NewPathAttributeMultiExitDisc(100)
	localpref2 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes2 := []bgp.PathAttributeInterface{
		mp_reach2, origin2, aspath2, med2, localpref2,
	}

	nlri2 := []bgp.NLRInfo{}
	withdrawnRoutes2 := []bgp.WithdrawnRoute{}
	bgpMessage2 := bgp.NewBGPUpdateMessage(withdrawnRoutes2, pathAttributes2, nlri2)

	peer1 := peerR1()
	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	var peer2 *PeerInfo = nil
	pList, wList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	// check type
	path := pList[0]
	expectedType := "*table.IPv6Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes

	expectedNexthopAttr := pathAttributes[0]
	_, attr := path.GetPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
	pathNexthop := attr.(*bgp.PathAttributeMpReachNLRI)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedOrigin := pathAttributes[1]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[2]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedMed := pathAttributes[3]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, 5, len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "2001:123:123:1::"
	assert.Equal(t, expectedPrefix, path.getPrefix().String())
	// check nexthop
	expectedNexthop := "::"
	assert.Equal(t, expectedNexthop, path.getNexthop().String())

}

// test: compare AS_PATH
func TestProcessBGPUpdate_3_select_aspath_ipv4(t *testing.T) {

	tm := NewTableManager()
	var pList []Path
	var wList []Destination
	var err error

	bgpMessage1 := update_fromR2viaR1()
	peer1 := peerR1()
	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)
	bgpMessage2 := update_fromR2()
	peer2 := peerR2()
	pList, wList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	// check type
	path := pList[0]
	expectedType := "*table.IPv4Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes
	expectedOrigin := pathAttributes[0]
	_, attr := path.GetPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[1]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedNexthopAttr := pathAttributes[2]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	pathNexthop := attr.(*bgp.PathAttributeNextHop)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedMed := pathAttributes[3]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, 4, len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "20.20.20.0"
	assert.Equal(t, expectedPrefix, path.getPrefix().String())
	// check nexthop
	expectedNexthop := "192.168.100.1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String())

}

func TestProcessBGPUpdate_3_select_aspath_ipv6(t *testing.T) {

	tm := NewTableManager()
	var pList []Path
	var wList []Destination
	var err error

	bgpMessage1 := update_fromR2viaR1_ipv6()
	peer1 := peerR1()
	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)
	bgpMessage2 := update_fromR2_ipv6()
	peer2 := peerR2()
	pList, wList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	// check type
	path := pList[0]
	expectedType := "*table.IPv6Path"
	assert.Equal(t, expectedType, reflect.TypeOf(path).String())

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes

	expectedNexthopAttr := pathAttributes[0]
	_, attr := path.GetPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
	pathNexthop := attr.(*bgp.PathAttributeMpReachNLRI)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedOrigin := pathAttributes[1]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[2]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedMed := pathAttributes[3]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, 4, len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "2002:223:123:1::"
	assert.Equal(t, expectedPrefix, path.getPrefix().String())
	// check nexthop
	expectedNexthop := "2001::192:168:100:1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String())

}

// test: compare Origin
func TestProcessBGPUpdate_4_select_low_origin_ipv4(t *testing.T) {

	tm := NewTableManager()
	var pList []Path
	var wList []Destination
	var err error

	// low origin message
	origin1 := bgp.NewPathAttributeOrigin(1)
	aspath1 := createAsPathAttribute([]uint16{65200, 65000})
	nexthop1 := bgp.NewPathAttributeNextHop("192.168.50.1")
	med1 := bgp.NewPathAttributeMultiExitDisc(100)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		origin1, aspath1, nexthop1, med1, localpref1,
	}
	nlri1 := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.10.0")}
	withdrawnRoutes1 := []bgp.WithdrawnRoute{}
	bgpMessage1 := bgp.NewBGPUpdateMessage(withdrawnRoutes1, pathAttributes1, nlri1)

	// high origin message
	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint16{65100, 65000})
	nexthop2 := bgp.NewPathAttributeNextHop("192.168.100.1")
	med2 := bgp.NewPathAttributeMultiExitDisc(100)
	localpref2 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes2 := []bgp.PathAttributeInterface{
		origin2, aspath2, nexthop2, med2, localpref2,
	}
	nlri2 := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.10.0")}
	withdrawnRoutes2 := []bgp.WithdrawnRoute{}
	bgpMessage2 := bgp.NewBGPUpdateMessage(withdrawnRoutes2, pathAttributes2, nlri2)

	peer1 := peerR1()
	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	peer2 := peerR2()
	pList, wList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	// check type
	path := pList[0]
	expectedType := "*table.IPv4Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes
	expectedOrigin := pathAttributes[0]
	_, attr := path.GetPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[1]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedNexthopAttr := pathAttributes[2]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	pathNexthop := attr.(*bgp.PathAttributeNextHop)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedMed := pathAttributes[3]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, len(pathAttributes2), len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "10.10.10.0"
	assert.Equal(t, expectedPrefix, path.getPrefix().String())
	// check nexthop
	expectedNexthop := "192.168.100.1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String())

}

func TestProcessBGPUpdate_4_select_low_origin_ipv6(t *testing.T) {

	tm := NewTableManager()
	var pList []Path
	var wList []Destination
	var err error

	origin1 := bgp.NewPathAttributeOrigin(1)
	aspath1 := createAsPathAttribute([]uint16{65200, 65000})
	mp_reach1 := createMpReach("2001::192:168:50:1",
		[]bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")})
	med1 := bgp.NewPathAttributeMultiExitDisc(100)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		mp_reach1, origin1, aspath1, med1, localpref1,
	}

	nlri1 := []bgp.NLRInfo{}
	withdrawnRoutes1 := []bgp.WithdrawnRoute{}
	bgpMessage1 := bgp.NewBGPUpdateMessage(withdrawnRoutes1, pathAttributes1, nlri1)

	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint16{65100, 65000})
	mp_reach2 := createMpReach("2001::192:168:100:1",
		[]bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")})
	med2 := bgp.NewPathAttributeMultiExitDisc(100)
	localpref2 := bgp.NewPathAttributeLocalPref(200)

	pathAttributes2 := []bgp.PathAttributeInterface{
		mp_reach2, origin2, aspath2, med2, localpref2,
	}

	nlri2 := []bgp.NLRInfo{}
	withdrawnRoutes2 := []bgp.WithdrawnRoute{}
	bgpMessage2 := bgp.NewBGPUpdateMessage(withdrawnRoutes2, pathAttributes2, nlri2)

	peer1 := peerR1()
	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	peer2 := peerR2()
	pList, wList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	// check type
	path := pList[0]
	expectedType := "*table.IPv6Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes

	expectedNexthopAttr := pathAttributes[0]
	_, attr := path.GetPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
	pathNexthop := attr.(*bgp.PathAttributeMpReachNLRI)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedOrigin := pathAttributes[1]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[2]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedMed := pathAttributes[3]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, 5, len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "2001:123:123:1::"
	assert.Equal(t, expectedPrefix, path.getPrefix().String())
	// check nexthop
	expectedNexthop := "2001::192:168:100:1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String())

}

// test: compare MED
func TestProcessBGPUpdate_5_select_low_med_ipv4(t *testing.T) {

	tm := NewTableManager()
	var pList []Path
	var wList []Destination
	var err error

	// low origin message
	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint16{65200, 65000})
	nexthop1 := bgp.NewPathAttributeNextHop("192.168.50.1")
	med1 := bgp.NewPathAttributeMultiExitDisc(500)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		origin1, aspath1, nexthop1, med1, localpref1,
	}
	nlri1 := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.10.0")}
	withdrawnRoutes1 := []bgp.WithdrawnRoute{}
	bgpMessage1 := bgp.NewBGPUpdateMessage(withdrawnRoutes1, pathAttributes1, nlri1)

	// high origin message
	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint16{65100, 65000})
	nexthop2 := bgp.NewPathAttributeNextHop("192.168.100.1")
	med2 := bgp.NewPathAttributeMultiExitDisc(100)
	localpref2 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes2 := []bgp.PathAttributeInterface{
		origin2, aspath2, nexthop2, med2, localpref2,
	}
	nlri2 := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.10.0")}
	withdrawnRoutes2 := []bgp.WithdrawnRoute{}
	bgpMessage2 := bgp.NewBGPUpdateMessage(withdrawnRoutes2, pathAttributes2, nlri2)

	peer1 := peerR1()
	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	peer2 := peerR2()
	pList, wList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	// check type
	path := pList[0]
	expectedType := "*table.IPv4Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes
	expectedOrigin := pathAttributes[0]
	_, attr := path.GetPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[1]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedNexthopAttr := pathAttributes[2]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	pathNexthop := attr.(*bgp.PathAttributeNextHop)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedMed := pathAttributes[3]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, len(pathAttributes2), len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "10.10.10.0"
	assert.Equal(t, expectedPrefix, path.getPrefix().String())
	// check nexthop
	expectedNexthop := "192.168.100.1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String())

}

func TestProcessBGPUpdate_5_select_low_med_ipv6(t *testing.T) {

	tm := NewTableManager()
	var pList []Path
	var wList []Destination
	var err error

	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint16{65200, 65000})
	mp_reach1 := createMpReach("2001::192:168:50:1",
		[]bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")})
	med1 := bgp.NewPathAttributeMultiExitDisc(500)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		mp_reach1, origin1, aspath1, med1, localpref1,
	}

	nlri1 := []bgp.NLRInfo{}
	withdrawnRoutes1 := []bgp.WithdrawnRoute{}
	bgpMessage1 := bgp.NewBGPUpdateMessage(withdrawnRoutes1, pathAttributes1, nlri1)

	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint16{65100, 65000})
	mp_reach2 := createMpReach("2001::192:168:100:1",
		[]bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")})
	med2 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref2 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes2 := []bgp.PathAttributeInterface{
		mp_reach2, origin2, aspath2, med2, localpref2,
	}

	nlri2 := []bgp.NLRInfo{}
	withdrawnRoutes2 := []bgp.WithdrawnRoute{}
	bgpMessage2 := bgp.NewBGPUpdateMessage(withdrawnRoutes2, pathAttributes2, nlri2)

	peer1 := peerR1()
	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	peer2 := peerR2()
	pList, wList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	// check type
	path := pList[0]
	expectedType := "*table.IPv6Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes

	expectedNexthopAttr := pathAttributes[0]
	_, attr := path.GetPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
	pathNexthop := attr.(*bgp.PathAttributeMpReachNLRI)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedOrigin := pathAttributes[1]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[2]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedMed := pathAttributes[3]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, 5, len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "2001:123:123:1::"
	assert.Equal(t, expectedPrefix, path.getPrefix().String())
	// check nexthop
	expectedNexthop := "2001::192:168:100:1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String())

}

// test: compare AS_NUMBER(prefer eBGP path)
func TestProcessBGPUpdate_6_select_ebgp_path_ipv4(t *testing.T) {

	tm := NewTableManager()
	tm.localAsn = uint32(65000)

	var pList []Path
	var wList []Destination
	var err error

	// low origin message
	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint16{65000, 65200})
	nexthop1 := bgp.NewPathAttributeNextHop("192.168.50.1")
	med1 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		origin1, aspath1, nexthop1, med1, localpref1,
	}
	nlri1 := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.10.0")}
	withdrawnRoutes1 := []bgp.WithdrawnRoute{}
	bgpMessage1 := bgp.NewBGPUpdateMessage(withdrawnRoutes1, pathAttributes1, nlri1)

	// high origin message
	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint16{65100, 65000})
	nexthop2 := bgp.NewPathAttributeNextHop("192.168.100.1")
	med2 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref2 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes2 := []bgp.PathAttributeInterface{
		origin2, aspath2, nexthop2, med2, localpref2,
	}
	nlri2 := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.10.0")}
	withdrawnRoutes2 := []bgp.WithdrawnRoute{}
	bgpMessage2 := bgp.NewBGPUpdateMessage(withdrawnRoutes2, pathAttributes2, nlri2)

	peer1 := peerR1()
	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	peer2 := peerR2()
	pList, wList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	// check type
	path := pList[0]
	expectedType := "*table.IPv4Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes
	expectedOrigin := pathAttributes[0]
	_, attr := path.GetPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[1]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedNexthopAttr := pathAttributes[2]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	pathNexthop := attr.(*bgp.PathAttributeNextHop)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedMed := pathAttributes[3]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, len(pathAttributes2), len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "10.10.10.0"
	assert.Equal(t, expectedPrefix, path.getPrefix().String())
	// check nexthop
	expectedNexthop := "192.168.100.1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String())

}

func TestProcessBGPUpdate_6_select_ebgp_path_ipv6(t *testing.T) {

	tm := NewTableManager()
	tm.localAsn = uint32(65000)
	var pList []Path
	var wList []Destination
	var err error

	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint16{65000, 65200})
	mp_reach1 := createMpReach("2001::192:168:50:1",
		[]bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")})
	med1 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		mp_reach1, origin1, aspath1, med1, localpref1,
	}

	nlri1 := []bgp.NLRInfo{}
	withdrawnRoutes1 := []bgp.WithdrawnRoute{}
	bgpMessage1 := bgp.NewBGPUpdateMessage(withdrawnRoutes1, pathAttributes1, nlri1)

	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint16{65100, 65200})
	mp_reach2 := createMpReach("2001::192:168:100:1",
		[]bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")})
	med2 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref2 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes2 := []bgp.PathAttributeInterface{
		mp_reach2, origin2, aspath2, med2, localpref2,
	}

	nlri2 := []bgp.NLRInfo{}
	withdrawnRoutes2 := []bgp.WithdrawnRoute{}
	bgpMessage2 := bgp.NewBGPUpdateMessage(withdrawnRoutes2, pathAttributes2, nlri2)

	peer1 := peerR1()
	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	peer2 := peerR2()
	pList, wList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	// check type
	path := pList[0]
	expectedType := "*table.IPv6Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes

	expectedNexthopAttr := pathAttributes[0]
	_, attr := path.GetPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
	pathNexthop := attr.(*bgp.PathAttributeMpReachNLRI)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedOrigin := pathAttributes[1]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[2]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedMed := pathAttributes[3]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, 5, len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "2001:123:123:1::"
	assert.Equal(t, expectedPrefix, path.getPrefix().String())
	// check nexthop
	expectedNexthop := "2001::192:168:100:1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String())

}

// test: compare IGP cost -> N/A

// test: compare Router ID
func TestProcessBGPUpdate_7_select_low_routerid_path_ipv4(t *testing.T) {

	tm := NewTableManager()
	tm.localAsn = uint32(65000)

	var pList []Path
	var wList []Destination
	var err error

	// low origin message
	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint16{65000, 65200})
	nexthop1 := bgp.NewPathAttributeNextHop("192.168.50.1")
	med1 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		origin1, aspath1, nexthop1, med1, localpref1,
	}
	nlri1 := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.10.0")}
	withdrawnRoutes1 := []bgp.WithdrawnRoute{}
	bgpMessage1 := bgp.NewBGPUpdateMessage(withdrawnRoutes1, pathAttributes1, nlri1)

	// high origin message
	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint16{65000, 65100})
	nexthop2 := bgp.NewPathAttributeNextHop("192.168.100.1")
	med2 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref2 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes2 := []bgp.PathAttributeInterface{
		origin2, aspath2, nexthop2, med2, localpref2,
	}
	nlri2 := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.10.0")}
	withdrawnRoutes2 := []bgp.WithdrawnRoute{}
	bgpMessage2 := bgp.NewBGPUpdateMessage(withdrawnRoutes2, pathAttributes2, nlri2)

	peer1 := peerR1()
	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	peer3 := peerR3()
	pList, wList, err = tm.ProcessUpdate(peer3, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	// check type
	path := pList[0]
	expectedType := "*table.IPv4Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes
	expectedOrigin := pathAttributes[0]
	_, attr := path.GetPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[1]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedNexthopAttr := pathAttributes[2]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	pathNexthop := attr.(*bgp.PathAttributeNextHop)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedMed := pathAttributes[3]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, len(pathAttributes2), len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "10.10.10.0"
	assert.Equal(t, expectedPrefix, path.getPrefix().String())
	// check nexthop
	expectedNexthop := "192.168.100.1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String())

}

func TestProcessBGPUpdate_7_select_low_routerid_path_ipv6(t *testing.T) {

	tm := NewTableManager()
	tm.localAsn = uint32(65000)
	var pList []Path
	var wList []Destination
	var err error

	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint16{65000, 65200})
	mp_reach1 := createMpReach("2001::192:168:50:1",
		[]bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")})
	med1 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		mp_reach1, origin1, aspath1, med1, localpref1,
	}

	nlri1 := []bgp.NLRInfo{}
	withdrawnRoutes1 := []bgp.WithdrawnRoute{}
	bgpMessage1 := bgp.NewBGPUpdateMessage(withdrawnRoutes1, pathAttributes1, nlri1)

	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint16{65100, 65200})
	mp_reach2 := createMpReach("2001::192:168:100:1",
		[]bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")})
	med2 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref2 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes2 := []bgp.PathAttributeInterface{
		mp_reach2, origin2, aspath2, med2, localpref2,
	}

	nlri2 := []bgp.NLRInfo{}
	withdrawnRoutes2 := []bgp.WithdrawnRoute{}
	bgpMessage2 := bgp.NewBGPUpdateMessage(withdrawnRoutes2, pathAttributes2, nlri2)

	peer1 := peerR1()
	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	peer3 := peerR3()
	pList, wList, err = tm.ProcessUpdate(peer3, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	// check type
	path := pList[0]
	expectedType := "*table.IPv6Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes

	expectedNexthopAttr := pathAttributes[0]
	_, attr := path.GetPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
	pathNexthop := attr.(*bgp.PathAttributeMpReachNLRI)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedOrigin := pathAttributes[1]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[2]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedMed := pathAttributes[3]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, 5, len(path.GetPathAttrs()))

	// check destination
	expectedPrefix := "2001:123:123:1::"
	assert.Equal(t, expectedPrefix, path.getPrefix().String())
	// check nexthop
	expectedNexthop := "2001::192:168:100:1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String())

}

// test: withdraw and mpunreach path
func TestProcessBGPUpdate_8_withdraw_path_ipv4(t *testing.T) {

	tm := NewTableManager()
	//setLogger(getLogger(log.DebugLevel))
	var pList []Path
	var wList []Destination
	var err error

	// path1
	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint16{65000})
	nexthop1 := bgp.NewPathAttributeNextHop("192.168.50.1")
	med1 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		origin1, aspath1, nexthop1, med1, localpref1,
	}
	nlri1 := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.10.0")}
	withdrawnRoutes1 := []bgp.WithdrawnRoute{}
	bgpMessage1 := bgp.NewBGPUpdateMessage(withdrawnRoutes1, pathAttributes1, nlri1)

	// path 2
	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint16{65100, 65000})
	nexthop2 := bgp.NewPathAttributeNextHop("192.168.100.1")
	med2 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref2 := bgp.NewPathAttributeLocalPref(200)

	pathAttributes2 := []bgp.PathAttributeInterface{
		origin2, aspath2, nexthop2, med2, localpref2,
	}
	nlri2 := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.10.0")}
	withdrawnRoutes2 := []bgp.WithdrawnRoute{}
	bgpMessage2 := bgp.NewBGPUpdateMessage(withdrawnRoutes2, pathAttributes2, nlri2)

	peer1 := peerR1()
	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	peer2 := peerR2()
	pList, wList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	// check type
	path := pList[0]
	expectedType := "*table.IPv4Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType)

	// check PathAttribute
	checkPattr := func(expected *bgp.BGPMessage, actual Path) {
		pathAttributes := expected.Body.(*bgp.BGPUpdate).PathAttributes
		expectedOrigin := pathAttributes[0]
		_, attr := actual.GetPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
		pathOrigin := attr.(*bgp.PathAttributeOrigin)
		assert.Equal(t, expectedOrigin, pathOrigin)

		expectedAsPath := pathAttributes[1]
		_, attr = actual.GetPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
		pathAspath := attr.(*bgp.PathAttributeAsPath)
		assert.Equal(t, expectedAsPath, pathAspath)

		expectedNexthopAttr := pathAttributes[2]
		_, attr = actual.GetPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
		pathNexthop := attr.(*bgp.PathAttributeNextHop)
		assert.Equal(t, expectedNexthopAttr, pathNexthop)

		expectedMed := pathAttributes[3]
		_, attr = actual.GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
		pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
		assert.Equal(t, expectedMed, pathMed)

		// check PathAttribute length
		assert.Equal(t, len(pathAttributes), len(path.GetPathAttrs()))
	}
	checkPattr(bgpMessage2, path)
	// check destination
	expectedPrefix := "10.10.10.0"
	assert.Equal(t, expectedPrefix, path.getPrefix().String())
	// check nexthop
	expectedNexthop := "192.168.100.1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String())

	//withdraw path
	w1 := bgp.WithdrawnRoute{*bgp.NewIPAddrPrefix(24, "10.10.10.0")}
	w := []bgp.WithdrawnRoute{w1}
	bgpMessage3 := bgp.NewBGPUpdateMessage(w, []bgp.PathAttributeInterface{}, []bgp.NLRInfo{})

	pList, wList, err = tm.ProcessUpdate(peer2, bgpMessage3)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	path = pList[0]
	expectedType = "*table.IPv4Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType)

	checkPattr(bgpMessage1, path)
	// check destination
	expectedPrefix = "10.10.10.0"
	assert.Equal(t, expectedPrefix, path.getPrefix().String())
	// check nexthop
	expectedNexthop = "192.168.50.1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String())
}

// TODO MP_UNREACH
func TestProcessBGPUpdate_8_mpunreach_path_ipv6(t *testing.T) {

	tm := NewTableManager()
	var pList []Path
	var wList []Destination
	var err error

	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint16{65000})
	mp_reach1 := createMpReach("2001::192:168:50:1",
		[]bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")})
	med1 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		mp_reach1, origin1, aspath1, med1, localpref1,
	}

	nlri1 := []bgp.NLRInfo{}
	withdrawnRoutes1 := []bgp.WithdrawnRoute{}
	bgpMessage1 := bgp.NewBGPUpdateMessage(withdrawnRoutes1, pathAttributes1, nlri1)

	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint16{65100, 65000})
	mp_reach2 := createMpReach("2001::192:168:100:1",
		[]bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")})
	med2 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref2 := bgp.NewPathAttributeLocalPref(200)

	pathAttributes2 := []bgp.PathAttributeInterface{
		mp_reach2, origin2, aspath2, med2, localpref2,
	}

	nlri2 := []bgp.NLRInfo{}
	withdrawnRoutes2 := []bgp.WithdrawnRoute{}
	bgpMessage2 := bgp.NewBGPUpdateMessage(withdrawnRoutes2, pathAttributes2, nlri2)

	peer1 := peerR1()
	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	peer2 := peerR2()
	pList, wList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	// check type
	path := pList[0]
	expectedType := "*table.IPv6Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes

	expectedNexthopAttr := pathAttributes[0]
	_, attr := path.GetPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
	pathNexthop := attr.(*bgp.PathAttributeMpReachNLRI)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedOrigin := pathAttributes[1]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[2]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedMed := pathAttributes[3]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute
	checkPattr := func(expected *bgp.BGPMessage, actual Path) {
		pathAttributes := expected.Body.(*bgp.BGPUpdate).PathAttributes

		expectedNexthopAttr := pathAttributes[0]
		_, attr = actual.GetPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
		pathNexthop := attr.(*bgp.PathAttributeMpReachNLRI)
		assert.Equal(t, expectedNexthopAttr, pathNexthop)

		expectedOrigin := pathAttributes[1]
		_, attr = actual.GetPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
		pathOrigin := attr.(*bgp.PathAttributeOrigin)
		assert.Equal(t, expectedOrigin, pathOrigin)

		expectedAsPath := pathAttributes[2]
		_, attr = actual.GetPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
		pathAspath := attr.(*bgp.PathAttributeAsPath)
		assert.Equal(t, expectedAsPath, pathAspath)

		expectedMed := pathAttributes[3]
		_, attr = actual.GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
		pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
		assert.Equal(t, expectedMed, pathMed)
		// check PathAttribute length
		assert.Equal(t, len(pathAttributes), len(path.GetPathAttrs()))
	}

	checkPattr(bgpMessage2, path)

	// check destination
	expectedPrefix := "2001:123:123:1::"
	assert.Equal(t, expectedPrefix, path.getPrefix().String())
	// check nexthop
	expectedNexthop := "2001::192:168:100:1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String())

	//mpunreach path
	mp_unreach := createMpUNReach("2001:123:123:1::", 64)
	bgpMessage3 := bgp.NewBGPUpdateMessage([]bgp.WithdrawnRoute{},
		[]bgp.PathAttributeInterface{mp_unreach}, []bgp.NLRInfo{})

	pList, wList, err = tm.ProcessUpdate(peer2, bgpMessage3)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	path = pList[0]
	expectedType = "*table.IPv6Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType)

	checkPattr(bgpMessage1, path)
	// check destination
	expectedPrefix = "2001:123:123:1::"
	assert.Equal(t, expectedPrefix, path.getPrefix().String())
	// check nexthop
	expectedNexthop = "2001::192:168:50:1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String())

}

// handle bestpath lost
func TestProcessBGPUpdate_bestpath_lost_ipv4(t *testing.T) {

	tm := NewTableManager()
	//setLogger(getLogger(log.DebugLevel))
	var pList []Path
	var wList []Destination
	var err error

	// path1
	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint16{65000})
	nexthop1 := bgp.NewPathAttributeNextHop("192.168.50.1")
	med1 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		origin1, aspath1, nexthop1, med1, localpref1,
	}
	nlri1 := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.10.0")}
	bgpMessage1 := bgp.NewBGPUpdateMessage([]bgp.WithdrawnRoute{}, pathAttributes1, nlri1)

	// path 1 withdraw
	w1 := bgp.WithdrawnRoute{*bgp.NewIPAddrPrefix(24, "10.10.10.0")}
	w := []bgp.WithdrawnRoute{w1}
	bgpMessage1_w := bgp.NewBGPUpdateMessage(w, []bgp.PathAttributeInterface{}, []bgp.NLRInfo{})

	peer1 := peerR1()
	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage1_w)
	assert.Equal(t, 0, len(pList))
	assert.Equal(t, 1, len(wList))
	assert.NoError(t, err)

	// check old best path
	path := wList[0].GetOldBestPath()
	expectedType := "*table.IPv4Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType)

	// check PathAttribute
	checkPattr := func(expected *bgp.BGPMessage, actual Path) {
		pathAttributes := expected.Body.(*bgp.BGPUpdate).PathAttributes
		expectedOrigin := pathAttributes[0]
		_, attr := actual.GetPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
		pathOrigin := attr.(*bgp.PathAttributeOrigin)
		assert.Equal(t, expectedOrigin, pathOrigin)

		expectedAsPath := pathAttributes[1]
		_, attr = actual.GetPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
		pathAspath := attr.(*bgp.PathAttributeAsPath)
		assert.Equal(t, expectedAsPath, pathAspath)

		expectedNexthopAttr := pathAttributes[2]
		_, attr = actual.GetPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
		pathNexthop := attr.(*bgp.PathAttributeNextHop)
		assert.Equal(t, expectedNexthopAttr, pathNexthop)

		expectedMed := pathAttributes[3]
		_, attr = actual.GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
		pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
		assert.Equal(t, expectedMed, pathMed)

		// check PathAttribute length
		assert.Equal(t, len(pathAttributes), len(path.GetPathAttrs()))
	}

	checkPattr(bgpMessage1, path)
	// check destination
	expectedPrefix := "10.10.10.0"
	assert.Equal(t, expectedPrefix, path.getPrefix().String())
	// check nexthop
	expectedNexthop := "192.168.50.1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String())

}

func TestProcessBGPUpdate_bestpath_lost_ipv6(t *testing.T) {

	tm := NewTableManager()
	var pList []Path
	var wList []Destination
	var err error

	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint16{65000})
	mp_reach1 := createMpReach("2001::192:168:50:1",
		[]bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")})
	med1 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		mp_reach1, origin1, aspath1, med1, localpref1,
	}

	nlri1 := []bgp.NLRInfo{}
	withdrawnRoutes1 := []bgp.WithdrawnRoute{}
	bgpMessage1 := bgp.NewBGPUpdateMessage(withdrawnRoutes1, pathAttributes1, nlri1)

	peer1 := peerR1()
	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	// path1 mpunreach
	mp_unreach := createMpUNReach("2001:123:123:1::", 64)
	bgpMessage1_w := bgp.NewBGPUpdateMessage([]bgp.WithdrawnRoute{},
		[]bgp.PathAttributeInterface{mp_unreach}, []bgp.NLRInfo{})

	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage1_w)
	assert.Equal(t, 0, len(pList))
	assert.Equal(t, 1, len(wList))
	assert.NoError(t, err)

	// check old best path
	path := wList[0].GetOldBestPath()
	expectedType := "*table.IPv6Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType)

	// check PathAttribute
	checkPattr := func(expected *bgp.BGPMessage, actual Path) {
		pathAttributes := expected.Body.(*bgp.BGPUpdate).PathAttributes

		expectedNexthopAttr := pathAttributes[0]
		_, attr := actual.GetPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
		pathNexthop := attr.(*bgp.PathAttributeMpReachNLRI)
		assert.Equal(t, expectedNexthopAttr, pathNexthop)

		expectedOrigin := pathAttributes[1]
		_, attr = actual.GetPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
		pathOrigin := attr.(*bgp.PathAttributeOrigin)
		assert.Equal(t, expectedOrigin, pathOrigin)

		expectedAsPath := pathAttributes[2]
		_, attr = actual.GetPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
		pathAspath := attr.(*bgp.PathAttributeAsPath)
		assert.Equal(t, expectedAsPath, pathAspath)

		expectedMed := pathAttributes[3]
		_, attr = actual.GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
		pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
		assert.Equal(t, expectedMed, pathMed)
		// check PathAttribute length
		assert.Equal(t, len(pathAttributes), len(path.GetPathAttrs()))
	}

	checkPattr(bgpMessage1, path)

	// check destination
	expectedPrefix := "2001:123:123:1::"
	assert.Equal(t, expectedPrefix, path.getPrefix().String())
	// check nexthop
	expectedNexthop := "2001::192:168:50:1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String())

}

// test: implicit withdrawal case
func TestProcessBGPUpdate_implicit_withdrwal_ipv4(t *testing.T) {

	tm := NewTableManager()
	//setLogger(getLogger(log.DebugLevel))
	var pList []Path
	var wList []Destination
	var err error

	// path1
	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint16{65000, 65100, 65200})
	nexthop1 := bgp.NewPathAttributeNextHop("192.168.50.1")
	med1 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref1 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes1 := []bgp.PathAttributeInterface{
		origin1, aspath1, nexthop1, med1, localpref1,
	}
	nlri1 := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.10.0")}
	withdrawnRoutes1 := []bgp.WithdrawnRoute{}
	bgpMessage1 := bgp.NewBGPUpdateMessage(withdrawnRoutes1, pathAttributes1, nlri1)

	// path 1 from same peer but short AS_PATH
	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint16{65000, 65100})
	nexthop2 := bgp.NewPathAttributeNextHop("192.168.50.1")
	med2 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref2 := bgp.NewPathAttributeLocalPref(100)

	pathAttributes2 := []bgp.PathAttributeInterface{
		origin2, aspath2, nexthop2, med2, localpref2,
	}
	nlri2 := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.10.0")}
	withdrawnRoutes2 := []bgp.WithdrawnRoute{}
	bgpMessage2 := bgp.NewBGPUpdateMessage(withdrawnRoutes2, pathAttributes2, nlri2)

	peer1 := peerR1()
	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	// check type
	path := pList[0]
	expectedType := "*table.IPv4Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType)

	// check PathAttribute
	checkPattr := func(expected *bgp.BGPMessage, actual Path) {
		pathAttributes := expected.Body.(*bgp.BGPUpdate).PathAttributes
		expectedOrigin := pathAttributes[0]
		_, attr := actual.GetPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
		pathOrigin := attr.(*bgp.PathAttributeOrigin)
		assert.Equal(t, expectedOrigin, pathOrigin)

		expectedAsPath := pathAttributes[1]
		_, attr = actual.GetPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
		pathAspath := attr.(*bgp.PathAttributeAsPath)
		assert.Equal(t, expectedAsPath, pathAspath)

		expectedNexthopAttr := pathAttributes[2]
		_, attr = actual.GetPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
		pathNexthop := attr.(*bgp.PathAttributeNextHop)
		assert.Equal(t, expectedNexthopAttr, pathNexthop)

		expectedMed := pathAttributes[3]
		_, attr = actual.GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
		pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
		assert.Equal(t, expectedMed, pathMed)

		// check PathAttribute length
		assert.Equal(t, len(pathAttributes), len(path.GetPathAttrs()))
	}
	checkPattr(bgpMessage2, path)
	// check destination
	expectedPrefix := "10.10.10.0"
	assert.Equal(t, expectedPrefix, path.getPrefix().String())
	// check nexthop
	expectedNexthop := "192.168.50.1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String())

}

func TestProcessBGPUpdate_implicit_withdrwal_ipv6(t *testing.T) {

	tm := NewTableManager()
	var pList []Path
	var wList []Destination
	var err error

	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint16{65000, 65100, 65200})
	mp_reach1 := createMpReach("2001::192:168:50:1",
		[]bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")})
	med1 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref1 := bgp.NewPathAttributeLocalPref(200)

	pathAttributes1 := []bgp.PathAttributeInterface{
		mp_reach1, origin1, aspath1, med1, localpref1,
	}

	nlri1 := []bgp.NLRInfo{}
	withdrawnRoutes1 := []bgp.WithdrawnRoute{}
	bgpMessage1 := bgp.NewBGPUpdateMessage(withdrawnRoutes1, pathAttributes1, nlri1)

	origin2 := bgp.NewPathAttributeOrigin(0)
	aspath2 := createAsPathAttribute([]uint16{65000, 65100})
	mp_reach2 := createMpReach("2001::192:168:50:1",
		[]bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")})
	med2 := bgp.NewPathAttributeMultiExitDisc(200)
	localpref2 := bgp.NewPathAttributeLocalPref(200)

	pathAttributes2 := []bgp.PathAttributeInterface{
		mp_reach2, origin2, aspath2, med2, localpref2,
	}

	nlri2 := []bgp.NLRInfo{}
	withdrawnRoutes2 := []bgp.WithdrawnRoute{}
	bgpMessage2 := bgp.NewBGPUpdateMessage(withdrawnRoutes2, pathAttributes2, nlri2)

	peer1 := peerR1()
	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	// check type
	path := pList[0]
	expectedType := "*table.IPv6Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes

	expectedNexthopAttr := pathAttributes[0]
	_, attr := path.GetPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
	pathNexthop := attr.(*bgp.PathAttributeMpReachNLRI)
	assert.Equal(t, expectedNexthopAttr, pathNexthop)

	expectedOrigin := pathAttributes[1]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	pathOrigin := attr.(*bgp.PathAttributeOrigin)
	assert.Equal(t, expectedOrigin, pathOrigin)

	expectedAsPath := pathAttributes[2]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	pathAspath := attr.(*bgp.PathAttributeAsPath)
	assert.Equal(t, expectedAsPath, pathAspath)

	expectedMed := pathAttributes[3]
	_, attr = path.GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute
	checkPattr := func(expected *bgp.BGPMessage, actual Path) {
		pathAttributes := expected.Body.(*bgp.BGPUpdate).PathAttributes

		expectedNexthopAttr := pathAttributes[0]
		_, attr := actual.GetPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
		pathNexthop := attr.(*bgp.PathAttributeMpReachNLRI)
		assert.Equal(t, expectedNexthopAttr, pathNexthop)

		expectedOrigin := pathAttributes[1]
		_, attr = actual.GetPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
		pathOrigin := attr.(*bgp.PathAttributeOrigin)
		assert.Equal(t, expectedOrigin, pathOrigin)

		expectedAsPath := pathAttributes[2]
		_, attr = actual.GetPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
		pathAspath := attr.(*bgp.PathAttributeAsPath)
		assert.Equal(t, expectedAsPath, pathAspath)

		expectedMed := pathAttributes[3]
		_, attr = actual.GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
		pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
		assert.Equal(t, expectedMed, pathMed)
		// check PathAttribute length
		assert.Equal(t, len(pathAttributes), len(path.GetPathAttrs()))
	}

	checkPattr(bgpMessage2, path)

	// check destination
	expectedPrefix := "2001:123:123:1::"
	assert.Equal(t, expectedPrefix, path.getPrefix().String())
	// check nexthop
	expectedNexthop := "2001::192:168:50:1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String())

}

// check multiple paths
func TestProcessBGPUpdate_multiple_nlri_ipv4(t *testing.T) {

	tm := NewTableManager()
	//setLogger(getLogger(log.DebugLevel))
	var pList []Path
	var wList []Destination
	var err error

	createPathAttr := func(aspaths []uint16, nh string) []bgp.PathAttributeInterface {
		origin := bgp.NewPathAttributeOrigin(0)
		aspath := createAsPathAttribute(aspaths)
		nexthop := bgp.NewPathAttributeNextHop(nh)
		med := bgp.NewPathAttributeMultiExitDisc(200)
		localpref := bgp.NewPathAttributeLocalPref(100)
		pathAttr := []bgp.PathAttributeInterface{
			origin, aspath, nexthop, med, localpref,
		}
		return pathAttr
	}

	// check PathAttribute
	checkPattr := func(expected *bgp.BGPMessage, actual Path) {
		pathAttributes := expected.Body.(*bgp.BGPUpdate).PathAttributes
		expectedOrigin := pathAttributes[0]
		_, attr := actual.GetPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
		pathOrigin := attr.(*bgp.PathAttributeOrigin)
		assert.Equal(t, expectedOrigin, pathOrigin)

		expectedAsPath := pathAttributes[1]
		_, attr = actual.GetPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
		pathAspath := attr.(*bgp.PathAttributeAsPath)
		assert.Equal(t, expectedAsPath, pathAspath)

		expectedNexthopAttr := pathAttributes[2]
		_, attr = actual.GetPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
		pathNexthop := attr.(*bgp.PathAttributeNextHop)
		assert.Equal(t, expectedNexthopAttr, pathNexthop)

		expectedMed := pathAttributes[3]
		_, attr = actual.GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
		pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
		assert.Equal(t, expectedMed, pathMed)

		// check PathAttribute length
		assert.Equal(t, len(pathAttributes), len(actual.GetPathAttrs()))
	}

	checkBestPathResult := func(pType, prefix, nexthop string, p Path, m *bgp.BGPMessage) {
		expectedType := pType
		assert.Equal(t, reflect.TypeOf(p).String(), expectedType)
		checkPattr(m, p)
		// check destination
		assert.Equal(t, prefix, p.getPrefix().String())
		// check nexthop
		assert.Equal(t, nexthop, p.getNexthop().String())
	}

	// path1
	pathAttributes1 := createPathAttr([]uint16{65000, 65100, 65200}, "192.168.50.1")
	nlri1 := []bgp.NLRInfo{
		*bgp.NewNLRInfo(24, "10.10.10.0"),
		*bgp.NewNLRInfo(24, "20.20.20.0"),
		*bgp.NewNLRInfo(24, "30.30.30.0"),
		*bgp.NewNLRInfo(24, "40.40.40.0"),
		*bgp.NewNLRInfo(24, "50.50.50.0")}
	bgpMessage1 := bgp.NewBGPUpdateMessage([]bgp.WithdrawnRoute{}, pathAttributes1, nlri1)

	// path2
	pathAttributes2 := createPathAttr([]uint16{65000, 65100, 65300}, "192.168.50.1")
	nlri2 := []bgp.NLRInfo{
		*bgp.NewNLRInfo(24, "11.11.11.0"),
		*bgp.NewNLRInfo(24, "22.22.22.0"),
		*bgp.NewNLRInfo(24, "33.33.33.0"),
		*bgp.NewNLRInfo(24, "44.44.44.0"),
		*bgp.NewNLRInfo(24, "55.55.55.0")}
	bgpMessage2 := bgp.NewBGPUpdateMessage([]bgp.WithdrawnRoute{}, pathAttributes2, nlri2)

	// path3
	pathAttributes3 := createPathAttr([]uint16{65000, 65100, 65400}, "192.168.50.1")
	nlri3 := []bgp.NLRInfo{
		*bgp.NewNLRInfo(24, "77.77.77.0"),
		*bgp.NewNLRInfo(24, "88.88.88.0"),
	}
	bgpMessage3 := bgp.NewBGPUpdateMessage([]bgp.WithdrawnRoute{}, pathAttributes3, nlri3)

	// path4
	pathAttributes4 := createPathAttr([]uint16{65000, 65100, 65500}, "192.168.50.1")
	nlri4 := []bgp.NLRInfo{
		*bgp.NewNLRInfo(24, "99.99.99.0"),
	}
	bgpMessage4 := bgp.NewBGPUpdateMessage([]bgp.WithdrawnRoute{}, pathAttributes4, nlri4)

	peer1 := peerR1()
	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 5, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	checkBestPathResult("*table.IPv4Path", "10.10.10.0", "192.168.50.1", pList[0], bgpMessage1)
	checkBestPathResult("*table.IPv4Path", "20.20.20.0", "192.168.50.1", pList[1], bgpMessage1)
	checkBestPathResult("*table.IPv4Path", "30.30.30.0", "192.168.50.1", pList[2], bgpMessage1)
	checkBestPathResult("*table.IPv4Path", "40.40.40.0", "192.168.50.1", pList[3], bgpMessage1)
	checkBestPathResult("*table.IPv4Path", "50.50.50.0", "192.168.50.1", pList[4], bgpMessage1)

	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage2)
	assert.Equal(t, 5, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	checkBestPathResult("*table.IPv4Path", "11.11.11.0", "192.168.50.1", pList[0], bgpMessage2)
	checkBestPathResult("*table.IPv4Path", "22.22.22.0", "192.168.50.1", pList[1], bgpMessage2)
	checkBestPathResult("*table.IPv4Path", "33.33.33.0", "192.168.50.1", pList[2], bgpMessage2)
	checkBestPathResult("*table.IPv4Path", "44.44.44.0", "192.168.50.1", pList[3], bgpMessage2)
	checkBestPathResult("*table.IPv4Path", "55.55.55.0", "192.168.50.1", pList[4], bgpMessage2)

	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage3)
	assert.Equal(t, 2, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage4)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	// check table
	table := tm.Tables[bgp.RF_IPv4_UC]
	assert.Equal(t, 13, len(table.getDestinations()))

}

// check multiple paths
func TestProcessBGPUpdate_multiple_nlri_ipv6(t *testing.T) {

	tm := NewTableManager()
	//setLogger(getLogger(log.DebugLevel))
	var pList []Path
	var wList []Destination
	var err error

	createPathAttr := func(aspaths []uint16) []bgp.PathAttributeInterface {
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
	checkPattr := func(expected *bgp.BGPMessage, actual Path) {
		pathAttributes := expected.Body.(*bgp.BGPUpdate).PathAttributes
		pathNexthop := pathAttributes[4]
		_, attr := actual.GetPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
		expectedNexthopAttr := attr.(*bgp.PathAttributeMpReachNLRI)
		assert.Equal(t, expectedNexthopAttr, pathNexthop)

		expectedOrigin := pathAttributes[0]
		_, attr = actual.GetPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
		pathOrigin := attr.(*bgp.PathAttributeOrigin)
		assert.Equal(t, expectedOrigin, pathOrigin)

		expectedAsPath := pathAttributes[1]
		_, attr = actual.GetPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
		pathAspath := attr.(*bgp.PathAttributeAsPath)
		assert.Equal(t, expectedAsPath, pathAspath)

		expectedMed := pathAttributes[2]
		_, attr = actual.GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
		pathMed := attr.(*bgp.PathAttributeMultiExitDisc)
		assert.Equal(t, expectedMed, pathMed)

		expectedLocalpref := pathAttributes[3]
		_, attr = actual.GetPathAttr(bgp.BGP_ATTR_TYPE_LOCAL_PREF)
		localpref := attr.(*bgp.PathAttributeLocalPref)
		assert.Equal(t, expectedLocalpref, localpref)

		// check PathAttribute length
		assert.Equal(t, len(pathAttributes), len(actual.GetPathAttrs()))

	}

	checkBestPathResult := func(pType, prefix, nexthop string, p Path, m *bgp.BGPMessage) {
		expectedType := pType
		assert.Equal(t, reflect.TypeOf(p).String(), expectedType)
		checkPattr(m, p)
		// check destination
		assert.Equal(t, prefix, p.getPrefix().String())
		// check nexthop
		assert.Equal(t, nexthop, p.getNexthop().String())
	}

	// path1
	pathAttributes1 := createPathAttr([]uint16{65000, 65100, 65200})
	mpreach1 := createMpReach("2001::192:168:50:1", []bgp.AddrPrefixInterface{
		bgp.NewIPv6AddrPrefix(64, "2001:123:1210:11::"),
		bgp.NewIPv6AddrPrefix(64, "2001:123:1220:11::"),
		bgp.NewIPv6AddrPrefix(64, "2001:123:1230:11::"),
		bgp.NewIPv6AddrPrefix(64, "2001:123:1240:11::"),
		bgp.NewIPv6AddrPrefix(64, "2001:123:1250:11::"),
	})
	pathAttributes1 = append(pathAttributes1, mpreach1)
	bgpMessage1 := bgp.NewBGPUpdateMessage([]bgp.WithdrawnRoute{}, pathAttributes1, []bgp.NLRInfo{})

	// path2
	pathAttributes2 := createPathAttr([]uint16{65000, 65100, 65300})
	mpreach2 := createMpReach("2001::192:168:50:1", []bgp.AddrPrefixInterface{
		bgp.NewIPv6AddrPrefix(64, "2001:123:1211:11::"),
		bgp.NewIPv6AddrPrefix(64, "2001:123:1222:11::"),
		bgp.NewIPv6AddrPrefix(64, "2001:123:1233:11::"),
		bgp.NewIPv6AddrPrefix(64, "2001:123:1244:11::"),
		bgp.NewIPv6AddrPrefix(64, "2001:123:1255:11::"),
	})
	pathAttributes2 = append(pathAttributes2, mpreach2)
	bgpMessage2 := bgp.NewBGPUpdateMessage([]bgp.WithdrawnRoute{}, pathAttributes2, []bgp.NLRInfo{})

	// path3
	pathAttributes3 := createPathAttr([]uint16{65000, 65100, 65400})
	mpreach3 := createMpReach("2001::192:168:50:1", []bgp.AddrPrefixInterface{
		bgp.NewIPv6AddrPrefix(64, "2001:123:1277:11::"),
		bgp.NewIPv6AddrPrefix(64, "2001:123:1288:11::"),
	})
	pathAttributes3 = append(pathAttributes3, mpreach3)
	bgpMessage3 := bgp.NewBGPUpdateMessage([]bgp.WithdrawnRoute{}, pathAttributes3, []bgp.NLRInfo{})

	// path4
	pathAttributes4 := createPathAttr([]uint16{65000, 65100, 65500})
	mpreach4 := createMpReach("2001::192:168:50:1", []bgp.AddrPrefixInterface{
		bgp.NewIPv6AddrPrefix(64, "2001:123:1299:11::"),
	})
	pathAttributes4 = append(pathAttributes4, mpreach4)
	bgpMessage4 := bgp.NewBGPUpdateMessage([]bgp.WithdrawnRoute{}, pathAttributes4, []bgp.NLRInfo{})

	peer1 := peerR1()
	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 5, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	checkBestPathResult("*table.IPv6Path", "2001:123:1210:11::", "2001::192:168:50:1", pList[0], bgpMessage1)
	checkBestPathResult("*table.IPv6Path", "2001:123:1220:11::", "2001::192:168:50:1", pList[1], bgpMessage1)
	checkBestPathResult("*table.IPv6Path", "2001:123:1230:11::", "2001::192:168:50:1", pList[2], bgpMessage1)
	checkBestPathResult("*table.IPv6Path", "2001:123:1240:11::", "2001::192:168:50:1", pList[3], bgpMessage1)
	checkBestPathResult("*table.IPv6Path", "2001:123:1250:11::", "2001::192:168:50:1", pList[4], bgpMessage1)

	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage2)
	assert.Equal(t, 5, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	checkBestPathResult("*table.IPv6Path", "2001:123:1211:11::", "2001::192:168:50:1", pList[0], bgpMessage2)
	checkBestPathResult("*table.IPv6Path", "2001:123:1222:11::", "2001::192:168:50:1", pList[1], bgpMessage2)
	checkBestPathResult("*table.IPv6Path", "2001:123:1233:11::", "2001::192:168:50:1", pList[2], bgpMessage2)
	checkBestPathResult("*table.IPv6Path", "2001:123:1244:11::", "2001::192:168:50:1", pList[3], bgpMessage2)
	checkBestPathResult("*table.IPv6Path", "2001:123:1255:11::", "2001::192:168:50:1", pList[4], bgpMessage2)

	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage3)
	assert.Equal(t, 2, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage4)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	// check table
	table := tm.Tables[bgp.RF_IPv6_UC]
	assert.Equal(t, 13, len(table.getDestinations()))

}

func TestModifyPathAttribute(t *testing.T) {
	tm := NewTableManager()

	bgpMessage := update_fromR1()
	peer := peerR1()
	pList, wList, err := tm.ProcessUpdate(peer, bgpMessage)
	assert.Equal(t, len(pList), 1)
	assert.Equal(t, len(wList), 0)
	assert.NoError(t, err)

	path0 := pList[0]
	path1 := path0.Clone(false)

	_, attr1 := path1.GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	mx1 := attr1.(*bgp.PathAttributeMultiExitDisc)
	original := mx1.Value
	mx1.Value++

	table := tm.Tables[bgp.RF_IPv4_UC]
	dest := table.getDestination(table.tableKey(path0.GetNlri()).String()).(*IPv4Destination)
	path2 := dest.getKnownPathList()
	_, attr2 := path2[0].GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	mx2 := attr2.(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, original, mx2.Value)

	path3 := path0
	_, attr3 := path3.GetPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	mx3 := attr3.(*bgp.PathAttributeMultiExitDisc)
	mx3.Value++
	assert.Equal(t, mx2.Value, mx3.Value)
}

func update_fromR1() *bgp.BGPMessage {

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

func update_fromR1_ipv6() *bgp.BGPMessage {

	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65000})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)

	mp_nlri := []bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2001:123:123:1::")}
	mp_reach := bgp.NewPathAttributeMpReachNLRI("2001::192:168:50:1", mp_nlri)
	med := bgp.NewPathAttributeMultiExitDisc(0)

	pathAttributes := []bgp.PathAttributeInterface{
		mp_reach,
		origin,
		aspath,
		med,
	}
	nlri := []bgp.NLRInfo{}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	return bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
}

func update_fromR2() *bgp.BGPMessage {

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

func update_fromR2_ipv6() *bgp.BGPMessage {

	origin := bgp.NewPathAttributeOrigin(0)
	aspath := createAsPathAttribute([]uint16{65100})
	mp_reach := createMpReach("2001::192:168:100:1",
		[]bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2002:223:123:1::")})
	med := bgp.NewPathAttributeMultiExitDisc(100)

	pathAttributes := []bgp.PathAttributeInterface{
		mp_reach,
		origin,
		aspath,
		med,
	}
	nlri := []bgp.NLRInfo{}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	return bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
}

func createAsPathAttribute(ases []uint16) *bgp.PathAttributeAsPath {
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, ases)}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	return aspath
}

func createMpReach(nexthop string, prefix []bgp.AddrPrefixInterface) *bgp.PathAttributeMpReachNLRI {
	mp_reach := bgp.NewPathAttributeMpReachNLRI(nexthop, prefix)
	return mp_reach
}

func createMpUNReach(nlri string, len uint8) *bgp.PathAttributeMpUnreachNLRI {
	mp_nlri := []bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(len, nlri)}
	mp_unreach := bgp.NewPathAttributeMpUnreachNLRI(mp_nlri)
	return mp_unreach
}

func update_fromR2viaR1() *bgp.BGPMessage {

	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65000, 65100})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("192.168.50.1")

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
	}

	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "20.20.20.0")}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	return bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
}

func update_fromR2viaR1_ipv6() *bgp.BGPMessage {

	origin := bgp.NewPathAttributeOrigin(0)
	aspath := createAsPathAttribute([]uint16{65000, 65100})
	mp_reach := createMpReach("2001::192:168:50:1",
		[]bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "2002:223:123:1::")})
	med := bgp.NewPathAttributeMultiExitDisc(100)

	pathAttributes := []bgp.PathAttributeInterface{
		mp_reach,
		origin,
		aspath,
		med,
	}
	nlri := []bgp.NLRInfo{}
	withdrawnRoutes := []bgp.WithdrawnRoute{}
	return bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)

}
