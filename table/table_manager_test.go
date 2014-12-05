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

func getLogger() *log.Logger {
	var l *log.Logger = &log.Logger{
		Out:       os.Stderr,
		Formatter: new(log.JSONFormatter),
		Hooks:     make(map[log.Level][]log.Hook),
		Level:     log.InfoLevel,
	}
	return l
}

func peerR1() *Peer {
	proto := &BgpProtocol{}
	proto.sentOpenMsg = bgp.NewBGPOpenMessage(65000, 300, "10.0.0.1", nil).Body.(*bgp.BGPOpen)
	proto.recvOpenMsg = bgp.NewBGPOpenMessage(65000, 300, "10.0.0.3", nil).Body.(*bgp.BGPOpen)

	peer := &Peer{
		VersionNum: 4,
		RemoteAs:   65000,
		protocol:   proto,
	}
	return peer
}

func peerR2() *Peer {
	peer := &Peer{
		VersionNum: 4,
		RemoteAs:   65100,
	}
	return peer
}

func peerR3() *Peer {
	proto := &BgpProtocol{}
	proto.sentOpenMsg = bgp.NewBGPOpenMessage(65000, 300, "10.0.0.1", nil).Body.(*bgp.BGPOpen)
	proto.recvOpenMsg = bgp.NewBGPOpenMessage(65000, 300, "10.0.0.2", nil).Body.(*bgp.BGPOpen)

	peer := &Peer{
		VersionNum: 4,
		RemoteAs:   65000,
		protocol:   proto,
	}
	return peer
}

// test best path calculation and check the result path is from R1
func TestProcessBGPUpdate_0_select_onlypath_ipv4(t *testing.T) {

	tm := NewTableManager()
	setLogger(getLogger())

	bgpMessage := update_fromR1()
	peer := peerR1()
	pList, wList, err := tm.ProcessUpdate(peer, bgpMessage)
	assert.Equal(t, len(pList), 1, "pList length should be 1")
	assert.Equal(t, len(wList), 0, "wList length should be 0")
	assert.NoError(t, err, "err should be nil")

	// check type
	path := pList[0]
	expectedType := "*table.IPv4Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType, "best path should be *table.IPv4Path")

	// check PathAttribute
	pathAttributes := bgpMessage.Body.(*bgp.BGPUpdate).PathAttributes
	expectedOrigin := pathAttributes[0]
	pathOrigin := path.getPathAttribute(bgp.BGP_ATTR_TYPE_ORIGIN).(*bgp.PathAttributeOrigin)
	assert.Equal(t, pathOrigin, expectedOrigin, "PathAttributeOrigin should be ", expectedOrigin)

	expectedAsPath := pathAttributes[1]
	pathAspath := path.getPathAttribute(bgp.BGP_ATTR_TYPE_AS_PATH).(*bgp.PathAttributeAsPath)
	assert.Equal(t, pathAspath, expectedAsPath, "PathAttributeAsPath should be ", expectedAsPath)

	expectedNexthopAttr := pathAttributes[2]
	pathNexthop := path.getPathAttribute(bgp.BGP_ATTR_TYPE_NEXT_HOP).(*bgp.PathAttributeNextHop)
	assert.Equal(t, pathNexthop, expectedNexthopAttr, "PathAttributeNextHop should be ", expectedNexthopAttr)

	expectedMed := pathAttributes[3]
	pathMed := path.getPathAttribute(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC).(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed, "PathAttributeMed should be ", expectedMed)

	// check PathAttribute length
	assert.Equal(t, 4, path.getPathAttributeMap().Len(), "PathAttribute length should be ", 4)

	// check destination
	expectedPrefix := "10.10.10.0"
	assert.Equal(t, expectedPrefix, path.getPrefix().String(), "prefix should be ", expectedPrefix)
	// check nexthop
	expectedNexthop := "192.168.50.1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String(), "nexthop should be ", expectedNexthop)

}

// test best path calculation and check the result path is from R1
func TestProcessBGPUpdate_0_select_onlypath_ipv6(t *testing.T) {

	tm := NewTableManager()
	setLogger(getLogger())

	bgpMessage := update_fromR1_ipv6()
	peer := peerR1()
	pList, wList, err := tm.ProcessUpdate(peer, bgpMessage)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err)

	// check type
	path := pList[0]
	expectedType := "*table.IPv6Path"
	assert.Equal(t, expectedType, reflect.TypeOf(path).String(), "best path should be *table.IPv6Path")

	// check PathAttribute
	pathAttributes := bgpMessage.Body.(*bgp.BGPUpdate).PathAttributes

	expectedNexthopAttr := pathAttributes[0]
	pathNexthop := path.getPathAttribute(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI).(*bgp.PathAttributeMpReachNLRI)
	assert.Equal(t, pathNexthop, expectedNexthopAttr, "PathAttributeNextHop should be ", expectedNexthopAttr)

	expectedOrigin := pathAttributes[1]
	pathOrigin := path.getPathAttribute(bgp.BGP_ATTR_TYPE_ORIGIN).(*bgp.PathAttributeOrigin)
	assert.Equal(t, pathOrigin, expectedOrigin, "PathAttributeOrigin should be ", expectedOrigin)

	expectedAsPath := pathAttributes[2]
	pathAspath := path.getPathAttribute(bgp.BGP_ATTR_TYPE_AS_PATH).(*bgp.PathAttributeAsPath)
	assert.Equal(t, pathAspath, expectedAsPath, "PathAttributeAsPath should be ", expectedAsPath)

	expectedMed := pathAttributes[3]
	pathMed := path.getPathAttribute(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC).(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed, "PathAttributeMed should be ", expectedMed)

	// check PathAttribute length
	assert.Equal(t, 4, path.getPathAttributeMap().Len(), "PathAttribute length should be ", 4)

	// check destination
	expectedPrefix := "2001:123:123:1::"
	assert.Equal(t, expectedPrefix, path.getPrefix().String(), "prefix should be ", expectedPrefix)
	// check nexthop
	expectedNexthop := "2001::192:168:50:1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String(), "nexthop should be ", expectedNexthop)

}

// test: compare localpref
func TestProcessBGPUpdate_1_select_high_localpref_ipv4(t *testing.T) {

	tm := NewTableManager()
	var pList, wList []Path
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
	assert.Equal(t, 1, len(pList), "pList length should be 1")
	assert.Equal(t, 0, len(wList), "wList length should be 0")
	assert.NoError(t, err, "err should be nil")

	peer2 := peerR2()
	pList, wList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList), "pList length should be 1")
	assert.Equal(t, 0, len(wList), "wList length should be 0")
	assert.NoError(t, err, "err should be nil")

	// check type
	path := pList[0]
	expectedType := "*table.IPv4Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType, "best path should be *table.IPv4Path")

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes
	expectedOrigin := pathAttributes[0]
	pathOrigin := path.getPathAttribute(bgp.BGP_ATTR_TYPE_ORIGIN).(*bgp.PathAttributeOrigin)
	assert.Equal(t, pathOrigin, expectedOrigin, "PathAttributeOrigin should be ", expectedOrigin)

	expectedAsPath := pathAttributes[1]
	pathAspath := path.getPathAttribute(bgp.BGP_ATTR_TYPE_AS_PATH).(*bgp.PathAttributeAsPath)
	assert.Equal(t, pathAspath, expectedAsPath, "PathAttributeAsPath should be ", expectedAsPath)

	expectedNexthopAttr := pathAttributes[2]
	pathNexthop := path.getPathAttribute(bgp.BGP_ATTR_TYPE_NEXT_HOP).(*bgp.PathAttributeNextHop)
	assert.Equal(t, pathNexthop, expectedNexthopAttr, "PathAttributeNextHop should be ", expectedNexthopAttr)

	expectedMed := pathAttributes[3]
	pathMed := path.getPathAttribute(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC).(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed, "PathAttributeMed should be ", expectedMed)

	// check PathAttribute length
	assert.Equal(t, len(pathAttributes2), path.getPathAttributeMap().Len(), "PathAttribute length should be ", 4)

	// check destination
	expectedPrefix := "10.10.10.0"
	assert.Equal(t, expectedPrefix, path.getPrefix().String(), "prefix should be ", expectedPrefix)
	// check nexthop
	expectedNexthop := "192.168.50.1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String(), "nexthop should be ", expectedNexthop)

}

func TestProcessBGPUpdate_1_select_high_localpref_ipv6(t *testing.T) {

	tm := NewTableManager()
	var pList, wList []Path
	var err error

	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint16{65000})
	mp_reach1 := createMpReach("2001::192:168:50:1", "2001:123:123:1::", 64)
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
	mp_reach2 := createMpReach("2001::192:168:100:1", "2001:123:123:1::", 64)
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
	assert.NoError(t, err, "err should be nil")

	peer2 := peerR2()
	pList, wList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err, "err should be nil")

	// check type
	path := pList[0]
	expectedType := "*table.IPv6Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes

	expectedNexthopAttr := pathAttributes[0]
	pathNexthop := path.getPathAttribute(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI).(*bgp.PathAttributeMpReachNLRI)
	assert.Equal(t, pathNexthop, expectedNexthopAttr)

	expectedOrigin := pathAttributes[1]
	pathOrigin := path.getPathAttribute(bgp.BGP_ATTR_TYPE_ORIGIN).(*bgp.PathAttributeOrigin)
	assert.Equal(t, pathOrigin, expectedOrigin)

	expectedAsPath := pathAttributes[2]
	pathAspath := path.getPathAttribute(bgp.BGP_ATTR_TYPE_AS_PATH).(*bgp.PathAttributeAsPath)
	assert.Equal(t, pathAspath, expectedAsPath)

	expectedMed := pathAttributes[3]
	pathMed := path.getPathAttribute(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC).(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, 5, path.getPathAttributeMap().Len())

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
	var pList, wList []Path
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

	var peer2 *Peer = nil
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
	pathOrigin := path.getPathAttribute(bgp.BGP_ATTR_TYPE_ORIGIN).(*bgp.PathAttributeOrigin)
	assert.Equal(t, pathOrigin, expectedOrigin)

	expectedAsPath := pathAttributes[1]
	pathAspath := path.getPathAttribute(bgp.BGP_ATTR_TYPE_AS_PATH).(*bgp.PathAttributeAsPath)
	assert.Equal(t, pathAspath, expectedAsPath)

	expectedNexthopAttr := pathAttributes[2]
	pathNexthop := path.getPathAttribute(bgp.BGP_ATTR_TYPE_NEXT_HOP).(*bgp.PathAttributeNextHop)
	assert.Equal(t, pathNexthop, expectedNexthopAttr)

	expectedMed := pathAttributes[3]
	pathMed := path.getPathAttribute(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC).(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, len(pathAttributes2), path.getPathAttributeMap().Len())

	// check destination
	expectedPrefix := "10.10.10.0"
	assert.Equal(t, expectedPrefix, path.getPrefix().String())
	// check nexthop
	expectedNexthop := "0.0.0.0"
	assert.Equal(t, expectedNexthop, path.getNexthop().String())

}

func TestProcessBGPUpdate_2_select_local_origin_ipv6(t *testing.T) {

	tm := NewTableManager()
	var pList, wList []Path
	var err error

	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint16{65000})
	mp_reach1 := createMpReach("2001::192:168:50:1", "2001:123:123:1::", 64)
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
	mp_reach2 := createMpReach("::", "2001:123:123:1::", 64)
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
	assert.NoError(t, err, "err should be nil")

	var peer2 *Peer = nil
	pList, wList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err, "err should be nil")

	// check type
	path := pList[0]
	expectedType := "*table.IPv6Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes

	expectedNexthopAttr := pathAttributes[0]
	pathNexthop := path.getPathAttribute(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI).(*bgp.PathAttributeMpReachNLRI)
	assert.Equal(t, pathNexthop, expectedNexthopAttr)

	expectedOrigin := pathAttributes[1]
	pathOrigin := path.getPathAttribute(bgp.BGP_ATTR_TYPE_ORIGIN).(*bgp.PathAttributeOrigin)
	assert.Equal(t, pathOrigin, expectedOrigin)

	expectedAsPath := pathAttributes[2]
	pathAspath := path.getPathAttribute(bgp.BGP_ATTR_TYPE_AS_PATH).(*bgp.PathAttributeAsPath)
	assert.Equal(t, pathAspath, expectedAsPath)

	expectedMed := pathAttributes[3]
	pathMed := path.getPathAttribute(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC).(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, 5, path.getPathAttributeMap().Len())

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
	var pList, wList []Path
	var err error

	bgpMessage1 := update_fromR2viaR1()
	peer1 := peerR1()
	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList), "pList length should be 1")
	assert.Equal(t, 0, len(wList), "wList length should be 0")
	assert.NoError(t, err, "err should be nil")
	bgpMessage2 := update_fromR2()
	peer2 := peerR2()
	pList, wList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList), "pList length should be 1")
	assert.Equal(t, 0, len(wList), "wList length should be 0")
	assert.NoError(t, err, "err should be nil")

	// check type
	path := pList[0]
	expectedType := "*table.IPv4Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType, "best path should be *table.IPv4Path")

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes
	expectedOrigin := pathAttributes[0]
	pathOrigin := path.getPathAttribute(bgp.BGP_ATTR_TYPE_ORIGIN).(*bgp.PathAttributeOrigin)
	assert.Equal(t, pathOrigin, expectedOrigin, "PathAttributeOrigin should be ", expectedOrigin)

	expectedAsPath := pathAttributes[1]
	pathAspath := path.getPathAttribute(bgp.BGP_ATTR_TYPE_AS_PATH).(*bgp.PathAttributeAsPath)
	assert.Equal(t, pathAspath, expectedAsPath, "PathAttributeAsPath should be ", expectedAsPath)

	expectedNexthopAttr := pathAttributes[2]
	pathNexthop := path.getPathAttribute(bgp.BGP_ATTR_TYPE_NEXT_HOP).(*bgp.PathAttributeNextHop)
	assert.Equal(t, pathNexthop, expectedNexthopAttr, "PathAttributeNextHop should be ", expectedNexthopAttr)

	expectedMed := pathAttributes[3]
	pathMed := path.getPathAttribute(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC).(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed, "PathAttributeMed should be ", expectedMed)

	// check PathAttribute length
	assert.Equal(t, 4, path.getPathAttributeMap().Len(), "PathAttribute length should be ", 4)

	// check destination
	expectedPrefix := "20.20.20.0"
	assert.Equal(t, expectedPrefix, path.getPrefix().String(), "prefix should be ", expectedPrefix)
	// check nexthop
	expectedNexthop := "192.168.100.1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String(), "nexthop should be ", expectedNexthop)

}

func TestProcessBGPUpdate_3_select_aspath_ipv6(t *testing.T) {

	tm := NewTableManager()
	var pList, wList []Path
	var err error

	bgpMessage1 := update_fromR2viaR1_ipv6()
	peer1 := peerR1()
	pList, wList, err = tm.ProcessUpdate(peer1, bgpMessage1)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err, "err should be nil")
	bgpMessage2 := update_fromR2_ipv6()
	peer2 := peerR2()
	pList, wList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err, "err should be nil")

	// check type
	path := pList[0]
	expectedType := "*table.IPv6Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType, "best path should be *table.IPv6Path")

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes

	expectedNexthopAttr := pathAttributes[0]
	pathNexthop := path.getPathAttribute(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI).(*bgp.PathAttributeMpReachNLRI)
	assert.Equal(t, pathNexthop, expectedNexthopAttr, "PathAttributeNextHop should be ", expectedNexthopAttr)

	expectedOrigin := pathAttributes[1]
	pathOrigin := path.getPathAttribute(bgp.BGP_ATTR_TYPE_ORIGIN).(*bgp.PathAttributeOrigin)
	assert.Equal(t, pathOrigin, expectedOrigin, "PathAttributeOrigin should be ", expectedOrigin)

	expectedAsPath := pathAttributes[2]
	pathAspath := path.getPathAttribute(bgp.BGP_ATTR_TYPE_AS_PATH).(*bgp.PathAttributeAsPath)
	assert.Equal(t, pathAspath, expectedAsPath, "PathAttributeAsPath should be ", expectedAsPath)

	expectedMed := pathAttributes[3]
	pathMed := path.getPathAttribute(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC).(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed, "PathAttributeMed should be ", expectedMed)

	// check PathAttribute length
	assert.Equal(t, 4, path.getPathAttributeMap().Len(), "PathAttribute length should be ", 4)

	// check destination
	expectedPrefix := "2002:223:123:1::"
	assert.Equal(t, expectedPrefix, path.getPrefix().String(), "prefix should be ", expectedPrefix)
	// check nexthop
	expectedNexthop := "2001::192:168:100:1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String(), "nexthop should be ", expectedNexthop)

}

// test: compare Origin
func TestProcessBGPUpdate_4_select_low_origin_ipv4(t *testing.T) {

	tm := NewTableManager()
	var pList, wList []Path
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
	pathOrigin := path.getPathAttribute(bgp.BGP_ATTR_TYPE_ORIGIN).(*bgp.PathAttributeOrigin)
	assert.Equal(t, pathOrigin, expectedOrigin)

	expectedAsPath := pathAttributes[1]
	pathAspath := path.getPathAttribute(bgp.BGP_ATTR_TYPE_AS_PATH).(*bgp.PathAttributeAsPath)
	assert.Equal(t, pathAspath, expectedAsPath)

	expectedNexthopAttr := pathAttributes[2]
	pathNexthop := path.getPathAttribute(bgp.BGP_ATTR_TYPE_NEXT_HOP).(*bgp.PathAttributeNextHop)
	assert.Equal(t, pathNexthop, expectedNexthopAttr)

	expectedMed := pathAttributes[3]
	pathMed := path.getPathAttribute(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC).(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, len(pathAttributes2), path.getPathAttributeMap().Len())

	// check destination
	expectedPrefix := "10.10.10.0"
	assert.Equal(t, expectedPrefix, path.getPrefix().String())
	// check nexthop
	expectedNexthop := "192.168.100.1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String())

}

func TestProcessBGPUpdate_4_select_low_origin_ipv6(t *testing.T) {

	tm := NewTableManager()
	var pList, wList []Path
	var err error

	origin1 := bgp.NewPathAttributeOrigin(1)
	aspath1 := createAsPathAttribute([]uint16{65200, 65000})
	mp_reach1 := createMpReach("2001::192:168:50:1", "2001:123:123:1::", 64)
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
	mp_reach2 := createMpReach("2001::192:168:100:1", "2001:123:123:1::", 64)
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
	assert.NoError(t, err, "err should be nil")

	peer2 := peerR2()
	pList, wList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err, "err should be nil")

	// check type
	path := pList[0]
	expectedType := "*table.IPv6Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes

	expectedNexthopAttr := pathAttributes[0]
	pathNexthop := path.getPathAttribute(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI).(*bgp.PathAttributeMpReachNLRI)
	assert.Equal(t, pathNexthop, expectedNexthopAttr)

	expectedOrigin := pathAttributes[1]
	pathOrigin := path.getPathAttribute(bgp.BGP_ATTR_TYPE_ORIGIN).(*bgp.PathAttributeOrigin)
	assert.Equal(t, pathOrigin, expectedOrigin)

	expectedAsPath := pathAttributes[2]
	pathAspath := path.getPathAttribute(bgp.BGP_ATTR_TYPE_AS_PATH).(*bgp.PathAttributeAsPath)
	assert.Equal(t, pathAspath, expectedAsPath)

	expectedMed := pathAttributes[3]
	pathMed := path.getPathAttribute(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC).(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, 5, path.getPathAttributeMap().Len())

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
	var pList, wList []Path
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
	pathOrigin := path.getPathAttribute(bgp.BGP_ATTR_TYPE_ORIGIN).(*bgp.PathAttributeOrigin)
	assert.Equal(t, pathOrigin, expectedOrigin)

	expectedAsPath := pathAttributes[1]
	pathAspath := path.getPathAttribute(bgp.BGP_ATTR_TYPE_AS_PATH).(*bgp.PathAttributeAsPath)
	assert.Equal(t, pathAspath, expectedAsPath)

	expectedNexthopAttr := pathAttributes[2]
	pathNexthop := path.getPathAttribute(bgp.BGP_ATTR_TYPE_NEXT_HOP).(*bgp.PathAttributeNextHop)
	assert.Equal(t, pathNexthop, expectedNexthopAttr)

	expectedMed := pathAttributes[3]
	pathMed := path.getPathAttribute(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC).(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, len(pathAttributes2), path.getPathAttributeMap().Len())

	// check destination
	expectedPrefix := "10.10.10.0"
	assert.Equal(t, expectedPrefix, path.getPrefix().String())
	// check nexthop
	expectedNexthop := "192.168.100.1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String())

}

func TestProcessBGPUpdate_5_select_low_med_ipv6(t *testing.T) {

	tm := NewTableManager()
	var pList, wList []Path
	var err error

	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint16{65200, 65000})
	mp_reach1 := createMpReach("2001::192:168:50:1", "2001:123:123:1::", 64)
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
	mp_reach2 := createMpReach("2001::192:168:100:1", "2001:123:123:1::", 64)
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
	assert.NoError(t, err, "err should be nil")

	peer2 := peerR2()
	pList, wList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err, "err should be nil")

	// check type
	path := pList[0]
	expectedType := "*table.IPv6Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes

	expectedNexthopAttr := pathAttributes[0]
	pathNexthop := path.getPathAttribute(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI).(*bgp.PathAttributeMpReachNLRI)
	assert.Equal(t, pathNexthop, expectedNexthopAttr)

	expectedOrigin := pathAttributes[1]
	pathOrigin := path.getPathAttribute(bgp.BGP_ATTR_TYPE_ORIGIN).(*bgp.PathAttributeOrigin)
	assert.Equal(t, pathOrigin, expectedOrigin)

	expectedAsPath := pathAttributes[2]
	pathAspath := path.getPathAttribute(bgp.BGP_ATTR_TYPE_AS_PATH).(*bgp.PathAttributeAsPath)
	assert.Equal(t, pathAspath, expectedAsPath)

	expectedMed := pathAttributes[3]
	pathMed := path.getPathAttribute(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC).(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, 5, path.getPathAttributeMap().Len())

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

	var pList, wList []Path
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
	pathOrigin := path.getPathAttribute(bgp.BGP_ATTR_TYPE_ORIGIN).(*bgp.PathAttributeOrigin)
	assert.Equal(t, pathOrigin, expectedOrigin)

	expectedAsPath := pathAttributes[1]
	pathAspath := path.getPathAttribute(bgp.BGP_ATTR_TYPE_AS_PATH).(*bgp.PathAttributeAsPath)
	assert.Equal(t, pathAspath, expectedAsPath)

	expectedNexthopAttr := pathAttributes[2]
	pathNexthop := path.getPathAttribute(bgp.BGP_ATTR_TYPE_NEXT_HOP).(*bgp.PathAttributeNextHop)
	assert.Equal(t, pathNexthop, expectedNexthopAttr)

	expectedMed := pathAttributes[3]
	pathMed := path.getPathAttribute(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC).(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, len(pathAttributes2), path.getPathAttributeMap().Len())

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
	var pList, wList []Path
	var err error

	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint16{65000, 65200})
	mp_reach1 := createMpReach("2001::192:168:50:1", "2001:123:123:1::", 64)
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
	mp_reach2 := createMpReach("2001::192:168:100:1", "2001:123:123:1::", 64)
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
	assert.NoError(t, err, "err should be nil")

	peer2 := peerR2()
	pList, wList, err = tm.ProcessUpdate(peer2, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err, "err should be nil")

	// check type
	path := pList[0]
	expectedType := "*table.IPv6Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes

	expectedNexthopAttr := pathAttributes[0]
	pathNexthop := path.getPathAttribute(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI).(*bgp.PathAttributeMpReachNLRI)
	assert.Equal(t, pathNexthop, expectedNexthopAttr)

	expectedOrigin := pathAttributes[1]
	pathOrigin := path.getPathAttribute(bgp.BGP_ATTR_TYPE_ORIGIN).(*bgp.PathAttributeOrigin)
	assert.Equal(t, pathOrigin, expectedOrigin)

	expectedAsPath := pathAttributes[2]
	pathAspath := path.getPathAttribute(bgp.BGP_ATTR_TYPE_AS_PATH).(*bgp.PathAttributeAsPath)
	assert.Equal(t, pathAspath, expectedAsPath)

	expectedMed := pathAttributes[3]
	pathMed := path.getPathAttribute(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC).(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, 5, path.getPathAttributeMap().Len())

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

	var pList, wList []Path
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
	pathOrigin := path.getPathAttribute(bgp.BGP_ATTR_TYPE_ORIGIN).(*bgp.PathAttributeOrigin)
	assert.Equal(t, pathOrigin, expectedOrigin)

	expectedAsPath := pathAttributes[1]
	pathAspath := path.getPathAttribute(bgp.BGP_ATTR_TYPE_AS_PATH).(*bgp.PathAttributeAsPath)
	assert.Equal(t, pathAspath, expectedAsPath)

	expectedNexthopAttr := pathAttributes[2]
	pathNexthop := path.getPathAttribute(bgp.BGP_ATTR_TYPE_NEXT_HOP).(*bgp.PathAttributeNextHop)
	assert.Equal(t, pathNexthop, expectedNexthopAttr)

	expectedMed := pathAttributes[3]
	pathMed := path.getPathAttribute(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC).(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, len(pathAttributes2), path.getPathAttributeMap().Len())

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
	var pList, wList []Path
	var err error

	origin1 := bgp.NewPathAttributeOrigin(0)
	aspath1 := createAsPathAttribute([]uint16{65000, 65200})
	mp_reach1 := createMpReach("2001::192:168:50:1", "2001:123:123:1::", 64)
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
	mp_reach2 := createMpReach("2001::192:168:100:1", "2001:123:123:1::", 64)
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
	assert.NoError(t, err, "err should be nil")

	peer3 := peerR3()
	pList, wList, err = tm.ProcessUpdate(peer3, bgpMessage2)
	assert.Equal(t, 1, len(pList))
	assert.Equal(t, 0, len(wList))
	assert.NoError(t, err, "err should be nil")

	// check type
	path := pList[0]
	expectedType := "*table.IPv6Path"
	assert.Equal(t, reflect.TypeOf(path).String(), expectedType)

	// check PathAttribute
	pathAttributes := bgpMessage2.Body.(*bgp.BGPUpdate).PathAttributes

	expectedNexthopAttr := pathAttributes[0]
	pathNexthop := path.getPathAttribute(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI).(*bgp.PathAttributeMpReachNLRI)
	assert.Equal(t, pathNexthop, expectedNexthopAttr)

	expectedOrigin := pathAttributes[1]
	pathOrigin := path.getPathAttribute(bgp.BGP_ATTR_TYPE_ORIGIN).(*bgp.PathAttributeOrigin)
	assert.Equal(t, pathOrigin, expectedOrigin)

	expectedAsPath := pathAttributes[2]
	pathAspath := path.getPathAttribute(bgp.BGP_ATTR_TYPE_AS_PATH).(*bgp.PathAttributeAsPath)
	assert.Equal(t, pathAspath, expectedAsPath)

	expectedMed := pathAttributes[3]
	pathMed := path.getPathAttribute(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC).(*bgp.PathAttributeMultiExitDisc)
	assert.Equal(t, expectedMed, pathMed)

	// check PathAttribute length
	assert.Equal(t, 5, path.getPathAttributeMap().Len())

	// check destination
	expectedPrefix := "2001:123:123:1::"
	assert.Equal(t, expectedPrefix, path.getPrefix().String())
	// check nexthop
	expectedNexthop := "2001::192:168:100:1"
	assert.Equal(t, expectedNexthop, path.getNexthop().String())

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
	mp_reach := createMpReach("2001::192:168:100:1", "2002:223:123:1::", 64)
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

func createMpReach(nexthop, nlri string, len uint8) *bgp.PathAttributeMpReachNLRI {
	mp_nlri := []bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(len, nlri)}
	mp_reach := bgp.NewPathAttributeMpReachNLRI(nexthop, mp_nlri)
	return mp_reach
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
	mp_reach := createMpReach("2001::192:168:50:1", "2002:223:123:1::", 64)
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

func update() *bgp.BGPMessage {
	w1 := bgp.WithdrawnRoute{*bgp.NewIPAddrPrefix(23, "121.1.3.2")}
	w2 := bgp.WithdrawnRoute{*bgp.NewIPAddrPrefix(17, "100.33.3.0")}
	w := []bgp.WithdrawnRoute{w1, w2}
	//w := []WithdrawnRoute{}

	aspath1 := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(2, []uint16{1000}),
		bgp.NewAsPathParam(1, []uint16{1001, 1002}),
		bgp.NewAsPathParam(2, []uint16{1003, 1004}),
	}

	aspath2 := []bgp.AsPathParamInterface{
		bgp.NewAs4PathParam(2, []uint32{1000000}),
		bgp.NewAs4PathParam(1, []uint32{1000001, 1002}),
		bgp.NewAs4PathParam(2, []uint32{1003, 100004}),
	}

	aspath3 := []*bgp.As4PathParam{
		bgp.NewAs4PathParam(2, []uint32{1000000}),
		bgp.NewAs4PathParam(1, []uint32{1000001, 1002}),
		bgp.NewAs4PathParam(2, []uint32{1003, 100004}),
	}

	ecommunities := []bgp.ExtendedCommunityInterface{
		&bgp.TwoOctetAsSpecificExtended{SubType: 1, AS: 10003, LocalAdmin: 3 << 20},
		&bgp.FourOctetAsSpecificExtended{SubType: 2, AS: 1 << 20, LocalAdmin: 300},
		&bgp.IPv4AddressSpecificExtended{SubType: 3, IPv4: net.ParseIP("192.2.1.2").To4(), LocalAdmin: 3000},
		&bgp.OpaqueExtended{Value: []byte{0, 1, 2, 3, 4, 5, 6, 7}},
		&bgp.UnknownExtended{Type: 99, Value: []byte{0, 1, 2, 3, 4, 5, 6, 7}},
	}

	mp_nlri := []bgp.AddrPrefixInterface{
		bgp.NewLabelledVPNIPAddrPrefix(20, "192.0.9.0", *bgp.NewLabel(1, 2, 3),
			bgp.NewRouteDistinguisherTwoOctetAS(256, 10000)),
		bgp.NewLabelledVPNIPAddrPrefix(26, "192.10.8.192", *bgp.NewLabel(5, 6, 7, 8),
			bgp.NewRouteDistinguisherIPAddressAS("10.0.1.1", 10001)),
	}

	mp_nlri2 := []bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(100,
		"fe80:1234:1234:5667:8967:af12:8912:1023")}

	mp_nlri3 := []bgp.AddrPrefixInterface{bgp.NewLabelledVPNIPv6AddrPrefix(100,
		"fe80:1234:1234:5667:8967:af12:1203:33a1", *bgp.NewLabel(5, 6),
		bgp.NewRouteDistinguisherFourOctetAS(5, 6))}

	mp_nlri4 := []bgp.AddrPrefixInterface{bgp.NewLabelledIPAddrPrefix(25, "192.168.0.0",
		*bgp.NewLabel(5, 6, 7))}

	p := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(3),
		bgp.NewPathAttributeAsPath(aspath1),
		bgp.NewPathAttributeAsPath(aspath2),
		bgp.NewPathAttributeNextHop("129.1.1.2"),
		bgp.NewPathAttributeMultiExitDisc(1 << 20),
		bgp.NewPathAttributeLocalPref(1 << 22),
		bgp.NewPathAttributeAtomicAggregate(),
		bgp.NewPathAttributeAggregator(uint16(30002), "129.0.2.99"),
		bgp.NewPathAttributeAggregator(uint32(30002), "129.0.2.99"),
		bgp.NewPathAttributeAggregator(uint32(300020), "129.0.2.99"),
		bgp.NewPathAttributeCommunities([]uint32{1, 3}),
		bgp.NewPathAttributeOriginatorId("10.10.0.1"),
		bgp.NewPathAttributeClusterList([]string{"10.10.0.2", "10.10.0.3"}),
		bgp.NewPathAttributeExtendedCommunities(ecommunities),
		bgp.NewPathAttributeAs4Path(aspath3),
		bgp.NewPathAttributeAs4Aggregator(10000, "112.22.2.1"),
		bgp.NewPathAttributeMpReachNLRI("112.22.2.0", mp_nlri),
		bgp.NewPathAttributeMpReachNLRI("1023::", mp_nlri2),
		bgp.NewPathAttributeMpReachNLRI("fe80::", mp_nlri3),
		bgp.NewPathAttributeMpReachNLRI("129.1.1.1", mp_nlri4),
		bgp.NewPathAttributeMpUnreachNLRI(mp_nlri),
		&bgp.PathAttributeUnknown{
			PathAttribute: bgp.PathAttribute{
				Flags: 1,
				Type:  100,
				Value: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
			},
		},
	}
	n := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "13.2.3.1")}
	return bgp.NewBGPUpdateMessage(w, p, n)
}
