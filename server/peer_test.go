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

package server

import (
	"fmt"
	//"encoding/json"
	"encoding/json"
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/table"
	"github.com/stretchr/testify/assert"
	"net"
	"reflect"
	"testing"
	"time"
)

func peerRC3() *table.PeerInfo {
	peer := &table.PeerInfo{
		AS:      66003,
		ID:      net.ParseIP("10.0.255.3").To4(),
		LocalID: net.ParseIP("10.0.255.1").To4(),
	}
	return peer
}

func createAsPathAttribute(ases []uint32) *bgp.PathAttributeAsPath {
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, ases)}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	return aspath
}

func createMpReach(nexthop string, prefix []bgp.AddrPrefixInterface) *bgp.PathAttributeMpReachNLRI {
	mp_reach := bgp.NewPathAttributeMpReachNLRI(nexthop, prefix)
	return mp_reach
}

func update_fromRC3() *bgp.BGPMessage {
	pathAttributes := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(1),
		createAsPathAttribute([]uint32{66003, 4000, 70000}),
		createMpReach("2001:db8::3",
			[]bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "38:38:38:38::")}),
	}
	return bgp.NewBGPUpdateMessage([]bgp.WithdrawnRoute{}, pathAttributes, []bgp.NLRInfo{})
}

func TestProcessBGPUpdate_fourbyteAS(t *testing.T) {
	rib1 := table.NewTableManager("peer_test", []bgp.RouteFamily{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC})

	m := update_fromRC3()
	peerInfo := peerRC3()
	msg := table.NewProcessMessage(m, peerInfo)
	pathList := msg.ToPathList()

	pList, _ := rib1.ProcessPaths(pathList)
	assert.Equal(t, len(pList), 1)
	assert.Equal(t, pList[0].IsWithdraw(), false)
	fmt.Println(pList)
	sendMsg := table.CreateUpdateMsgFromPaths(pList)
	assert.Equal(t, len(sendMsg), 1)
	table.UpdatePathAttrs2ByteAs(sendMsg[0].Body.(*bgp.BGPUpdate))
	update := sendMsg[0].Body.(*bgp.BGPUpdate)
	assert.Equal(t, len(update.PathAttributes), 4)
	assert.Equal(t, reflect.TypeOf(update.PathAttributes[3]).String(), "*bgp.PathAttributeAs4Path")
	attr := update.PathAttributes[3].(*bgp.PathAttributeAs4Path)
	assert.Equal(t, len(attr.Value), 1)
	assert.Equal(t, attr.Value[0].AS, []uint32{66003, 70000})
	attrAS := update.PathAttributes[1].(*bgp.PathAttributeAsPath)
	assert.Equal(t, len(attrAS.Value), 1)
	assert.Equal(t, attrAS.Value[0].(*bgp.AsPathParam).AS, []uint16{bgp.AS_TRANS, 4000, bgp.AS_TRANS})

	rib2 := table.NewTableManager("peer_test", []bgp.RouteFamily{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC})
	pList2, _ := rib2.ProcessPaths(pathList)
	assert.Equal(t, len(pList2), 1)
	assert.Equal(t, pList[0].IsWithdraw(), false)
	sendMsg2 := table.CreateUpdateMsgFromPaths(pList2)
	assert.Equal(t, len(sendMsg2), 1)
	update2 := sendMsg2[0].Body.(*bgp.BGPUpdate)
	assert.Equal(t, len(update2.PathAttributes), 3)
	attrAS2 := update2.PathAttributes[1].(*bgp.PathAttributeAsPath)
	assert.Equal(t, len(attrAS2.Value), 1)
	assert.Equal(t, attrAS2.Value[0].(*bgp.As4PathParam).AS, []uint32{66003, 4000, 70000})
}

func TestPeerAdminShutdownWhileEstablished(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	assert := assert.New(t)
	m := NewMockConnection()
	globalConfig := config.Global{}
	peerConfig := config.Neighbor{}
	peerConfig.PeerAs = 100000
	peerConfig.Timers.KeepaliveInterval = 5
	peer := makePeer(globalConfig, peerConfig)
	peer.fsm.opensentHoldTime = 10

	peer.t.Go(peer.loop)
	pushPackets := func() {
		o, _ := open().Serialize()
		m.setData(o)
		k, _ := keepalive().Serialize()
		m.setData(k)
	}
	go pushPackets()

	waitUntil(assert, bgp.BGP_FSM_ACTIVE, peer, 1000)
	peer.acceptedConnCh <- m
	waitUntil(assert, bgp.BGP_FSM_ESTABLISHED, peer, 1000)

	restReq := api.NewRestRequest(api.REQ_NEIGHBOR_DISABLE, "0.0.0.0", bgp.RF_IPv4_UC)
	msg := &serverMsg{
		msgType: SRV_MSG_API,
		msgData: restReq,
	}

	peer.serverMsgCh <- msg
	result := <-restReq.ResponseCh
	res := make(map[string]string)
	json.Unmarshal(result.Data, &res)
	assert.Equal("ADMIN_STATE_DOWN", res["result"])

	waitUntil(assert, bgp.BGP_FSM_IDLE, peer, 1000)

	assert.Equal(bgp.BGP_FSM_IDLE, peer.fsm.state)
	assert.Equal(ADMIN_STATE_DOWN, peer.fsm.adminState)
	lastMsg := m.sendBuf[len(m.sendBuf)-1]
	sent, _ := bgp.ParseBGPMessage(lastMsg)
	assert.Equal(uint8(bgp.BGP_MSG_NOTIFICATION), sent.Header.Type)
	assert.Equal(uint8(bgp.BGP_ERROR_CEASE), sent.Body.(*bgp.BGPNotification).ErrorCode)
	assert.Equal(uint8(bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN), sent.Body.(*bgp.BGPNotification).ErrorSubcode)
	assert.True(m.isClosed)

	// check counter
	counter := peer.fsm.peerConfig.BgpNeighborCommonState
	assertCounter(assert, counter)
}

func TestPeerAdminShutdownWhileIdle(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	assert := assert.New(t)

	globalConfig := config.Global{}
	peerConfig := config.Neighbor{}
	peerConfig.PeerAs = 100000
	peerConfig.Timers.KeepaliveInterval = 5
	peer := makePeer(globalConfig, peerConfig)
	peer.fsm.opensentHoldTime = 10
	peer.fsm.idleHoldTime = 5
	peer.t.Go(peer.loop)

	waitUntil(assert, bgp.BGP_FSM_IDLE, peer, 1000)

	restReq := api.NewRestRequest(api.REQ_NEIGHBOR_DISABLE, "0.0.0.0", bgp.RF_IPv4_UC)
	msg := &serverMsg{
		msgType: SRV_MSG_API,
		msgData: restReq,
	}

	peer.serverMsgCh <- msg
	result := <-restReq.ResponseCh
	res := make(map[string]string)
	json.Unmarshal(result.Data, &res)
	assert.Equal("ADMIN_STATE_DOWN", res["result"])

	waitUntil(assert, bgp.BGP_FSM_IDLE, peer, 100)
	assert.Equal(bgp.BGP_FSM_IDLE, peer.fsm.state)
	assert.Equal(ADMIN_STATE_DOWN, peer.fsm.adminState)

	// check counter
	counter := peer.fsm.peerConfig.BgpNeighborCommonState
	assertCounter(assert, counter)
}

func TestPeerAdminShutdownWhileActive(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	assert := assert.New(t)

	globalConfig := config.Global{}
	peerConfig := config.Neighbor{}
	peerConfig.PeerAs = 100000
	peerConfig.Timers.KeepaliveInterval = 5
	peer := makePeer(globalConfig, peerConfig)
	peer.fsm.opensentHoldTime = 10
	peer.t.Go(peer.loop)

	waitUntil(assert, bgp.BGP_FSM_ACTIVE, peer, 1000)

	restReq := api.NewRestRequest(api.REQ_NEIGHBOR_DISABLE, "0.0.0.0", bgp.RF_IPv4_UC)
	msg := &serverMsg{
		msgType: SRV_MSG_API,
		msgData: restReq,
	}

	peer.serverMsgCh <- msg
	result := <-restReq.ResponseCh
	res := make(map[string]string)
	json.Unmarshal(result.Data, &res)
	assert.Equal("ADMIN_STATE_DOWN", res["result"])

	waitUntil(assert, bgp.BGP_FSM_IDLE, peer, 100)
	assert.Equal(bgp.BGP_FSM_IDLE, peer.fsm.state)
	assert.Equal(ADMIN_STATE_DOWN, peer.fsm.adminState)

	// check counter
	counter := peer.fsm.peerConfig.BgpNeighborCommonState
	assertCounter(assert, counter)
}

func TestPeerAdminShutdownWhileOpensent(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	assert := assert.New(t)
	m := NewMockConnection()
	globalConfig := config.Global{}
	peerConfig := config.Neighbor{}
	peerConfig.PeerAs = 100000
	peerConfig.Timers.KeepaliveInterval = 5
	peer := makePeer(globalConfig, peerConfig)
	peer.fsm.opensentHoldTime = 1
	peer.t.Go(peer.loop)

	waitUntil(assert, bgp.BGP_FSM_ACTIVE, peer, 1000)
	peer.acceptedConnCh <- m
	waitUntil(assert, bgp.BGP_FSM_OPENSENT, peer, 1000)

	restReq := api.NewRestRequest(api.REQ_NEIGHBOR_DISABLE, "0.0.0.0", bgp.RF_IPv4_UC)
	msg := &serverMsg{
		msgType: SRV_MSG_API,
		msgData: restReq,
	}

	peer.serverMsgCh <- msg
	result := <-restReq.ResponseCh
	res := make(map[string]string)
	json.Unmarshal(result.Data, &res)
	assert.Equal("ADMIN_STATE_DOWN", res["result"])

	waitUntil(assert, bgp.BGP_FSM_IDLE, peer, 100)
	assert.Equal(bgp.BGP_FSM_IDLE, peer.fsm.state)
	assert.Equal(ADMIN_STATE_DOWN, peer.fsm.adminState)
	lastMsg := m.sendBuf[len(m.sendBuf)-1]
	sent, _ := bgp.ParseBGPMessage(lastMsg)
	assert.NotEqual(bgp.BGP_MSG_NOTIFICATION, sent.Header.Type)
	assert.True(m.isClosed)

	// check counter
	counter := peer.fsm.peerConfig.BgpNeighborCommonState
	assertCounter(assert, counter)
}

func TestPeerAdminShutdownWhileOpenconfirm(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	assert := assert.New(t)
	m := NewMockConnection()
	globalConfig := config.Global{}
	peerConfig := config.Neighbor{}
	peerConfig.PeerAs = 100000
	peerConfig.Timers.KeepaliveInterval = 5
	peer := makePeer(globalConfig, peerConfig)
	peer.fsm.opensentHoldTime = 10
	peer.t.Go(peer.loop)
	pushPackets := func() {
		o, _ := open().Serialize()
		m.setData(o)
	}
	go pushPackets()
	waitUntil(assert, bgp.BGP_FSM_ACTIVE, peer, 1000)
	peer.acceptedConnCh <- m
	waitUntil(assert, bgp.BGP_FSM_OPENCONFIRM, peer, 1000)

	restReq := api.NewRestRequest(api.REQ_NEIGHBOR_DISABLE, "0.0.0.0", bgp.RF_IPv4_UC)
	msg := &serverMsg{
		msgType: SRV_MSG_API,
		msgData: restReq,
	}

	peer.serverMsgCh <- msg
	result := <-restReq.ResponseCh
	res := make(map[string]string)
	json.Unmarshal(result.Data, &res)
	assert.Equal("ADMIN_STATE_DOWN", res["result"])

	waitUntil(assert, bgp.BGP_FSM_IDLE, peer, 1000)
	assert.Equal(bgp.BGP_FSM_IDLE, peer.fsm.state)
	assert.Equal(ADMIN_STATE_DOWN, peer.fsm.adminState)
	lastMsg := m.sendBuf[len(m.sendBuf)-1]
	sent, _ := bgp.ParseBGPMessage(lastMsg)
	assert.NotEqual(bgp.BGP_MSG_NOTIFICATION, sent.Header.Type)
	assert.True(m.isClosed)

	// check counter
	counter := peer.fsm.peerConfig.BgpNeighborCommonState
	assertCounter(assert, counter)

}

func TestPeerAdminEnable(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	assert := assert.New(t)
	m := NewMockConnection()
	globalConfig := config.Global{}
	peerConfig := config.Neighbor{}
	peerConfig.PeerAs = 100000
	peerConfig.Timers.KeepaliveInterval = 5
	peer := makePeer(globalConfig, peerConfig)

	peer.fsm.opensentHoldTime = 5
	peer.t.Go(peer.loop)
	pushPackets := func() {
		o, _ := open().Serialize()
		m.setData(o)
		k, _ := keepalive().Serialize()
		m.setData(k)
	}
	go pushPackets()

	waitUntil(assert, bgp.BGP_FSM_ACTIVE, peer, 1000)
	peer.acceptedConnCh <- m
	waitUntil(assert, bgp.BGP_FSM_ESTABLISHED, peer, 1000)

	// shutdown peer at first
	restReq := api.NewRestRequest(api.REQ_NEIGHBOR_DISABLE, "0.0.0.0", bgp.RF_IPv4_UC)
	msg := &serverMsg{
		msgType: SRV_MSG_API,
		msgData: restReq,
	}
	peer.serverMsgCh <- msg
	result := <-restReq.ResponseCh
	res := make(map[string]string)
	json.Unmarshal(result.Data, &res)
	assert.Equal("ADMIN_STATE_DOWN", res["result"])

	waitUntil(assert, bgp.BGP_FSM_IDLE, peer, 100)
	assert.Equal(bgp.BGP_FSM_IDLE, peer.fsm.state)
	assert.Equal(ADMIN_STATE_DOWN, peer.fsm.adminState)

	// enable peer
	restReq = api.NewRestRequest(api.REQ_NEIGHBOR_ENABLE, "0.0.0.0", bgp.RF_IPv4_UC)
	msg = &serverMsg{
		msgType: SRV_MSG_API,
		msgData: restReq,
	}
	peer.serverMsgCh <- msg
	result = <-restReq.ResponseCh
	res = make(map[string]string)
	json.Unmarshal(result.Data, &res)
	assert.Equal("ADMIN_STATE_UP", res["result"])

	waitUntil(assert, bgp.BGP_FSM_ACTIVE, peer, 1000)
	assert.Equal(bgp.BGP_FSM_ACTIVE, peer.fsm.state)

	m2 := NewMockConnection()
	pushPackets = func() {
		o, _ := open().Serialize()
		m2.setData(o)
		k, _ := keepalive().Serialize()
		m2.setData(k)
	}
	go pushPackets()

	peer.acceptedConnCh <- m2

	waitUntil(assert, bgp.BGP_FSM_ESTABLISHED, peer, 1000)
	assert.Equal(bgp.BGP_FSM_ESTABLISHED, peer.fsm.state)
}

func TestPeerAdminShutdownReject(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	assert := assert.New(t)
	m := NewMockConnection()
	m.wait = 500

	globalConfig := config.Global{}
	peerConfig := config.Neighbor{}
	peerConfig.PeerAs = 100000
	peerConfig.Timers.KeepaliveInterval = 5
	peer := makePeer(globalConfig, peerConfig)
	peer.fsm.opensentHoldTime = 1
	peer.t.Go(peer.loop)

	waitUntil(assert, bgp.BGP_FSM_ACTIVE, peer, 1000)
	peer.acceptedConnCh <- m
	waitUntil(assert, bgp.BGP_FSM_OPENSENT, peer, 1000)

	restReq := api.NewRestRequest(api.REQ_NEIGHBOR_DISABLE, "0.0.0.0", bgp.RF_IPv4_UC)
	msg := &serverMsg{
		msgType: SRV_MSG_API,
		msgData: restReq,
	}

	peer.fsm.adminStateCh <- ADMIN_STATE_DOWN

	peer.serverMsgCh <- msg
	result := <-restReq.ResponseCh
	res := make(map[string]string)
	json.Unmarshal(result.Data, &res)
	assert.Equal("previous request is still remaining", res["result"])

	restReq = api.NewRestRequest(api.REQ_NEIGHBOR_ENABLE, "0.0.0.0", bgp.RF_IPv4_UC)
	msg = &serverMsg{
		msgType: SRV_MSG_API,
		msgData: restReq,
	}

	peer.serverMsgCh <- msg
	result = <-restReq.ResponseCh
	res = make(map[string]string)
	json.Unmarshal(result.Data, &res)
	assert.Equal("previous request is still remaining", res["result"])

	waitUntil(assert, bgp.BGP_FSM_IDLE, peer, 1000)
	assert.Equal(bgp.BGP_FSM_IDLE, peer.fsm.state)
	assert.Equal(ADMIN_STATE_DOWN, peer.fsm.adminState)

}

func TestPeerSelectSmallerHoldtime(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	assert := assert.New(t)
	m := NewMockConnection()

	globalConfig := config.Global{}
	peerConfig := config.Neighbor{}
	peerConfig.PeerAs = 65001
	peerConfig.Timers.KeepaliveInterval = 5
	peer := makePeer(globalConfig, peerConfig)
	peer.fsm.opensentHoldTime = 1
	peerConfig.Timers.HoldTime = 5
	peer.t.Go(peer.loop)

	pushPackets := func() {
		opn := bgp.NewBGPOpenMessage(65001, 0, "10.0.0.1", []bgp.OptionParameterInterface{})
		o, _ := opn.Serialize()
		m.setData(o)
	}
	go pushPackets()

	waitUntil(assert, bgp.BGP_FSM_ACTIVE, peer, 1000)
	peer.acceptedConnCh <- m
	waitUntil(assert, bgp.BGP_FSM_OPENCONFIRM, peer, 1000)

	assert.Equal(float64(0), peer.fsm.negotiatedHoldTime)
}

func assertCounter(assert *assert.Assertions, counter config.BgpNeighborCommonState) {
	assert.Equal(uint32(0), counter.OpenIn)
	assert.Equal(uint32(0), counter.OpenOut)
	assert.Equal(uint32(0), counter.UpdateIn)
	assert.Equal(uint32(0), counter.UpdateOut)
	assert.Equal(uint32(0), counter.KeepaliveIn)
	assert.Equal(uint32(0), counter.KeepaliveOut)
	assert.Equal(uint32(0), counter.NotifyIn)
	assert.Equal(uint32(0), counter.NotifyOut)
	assert.Equal(uint32(0), counter.EstablishedCount)
	assert.Equal(uint32(0), counter.TotalIn)
	assert.Equal(uint32(0), counter.TotalOut)
	assert.Equal(uint32(0), counter.RefreshIn)
	assert.Equal(uint32(0), counter.RefreshOut)
	assert.Equal(uint32(0), counter.DynamicCapIn)
	assert.Equal(uint32(0), counter.DynamicCapOut)
	assert.Equal(uint32(0), counter.EstablishedCount)
	assert.Equal(uint32(0), counter.Flops)
}

func waitUntil(assert *assert.Assertions, state bgp.FSMState, peer *Peer, timeout int64) {
	isTimeout := false
	expire := func() {
		isTimeout = true
	}
	time.AfterFunc((time.Duration)(timeout)*time.Millisecond, expire)

	for {
		time.Sleep(1 * time.Millisecond)

		if peer.fsm.state == state || isTimeout {
			assert.Equal(state, peer.fsm.state, "timeout")
			break
		}
	}
}

func makePeer(globalConfig config.Global, peerConfig config.Neighbor) *Peer {

	sch := make(chan *serverMsg, 8)
	pch := make(chan *peerMsg, 4096)

	p := &Peer{
		globalConfig:   globalConfig,
		peerConfig:     peerConfig,
		acceptedConnCh: make(chan net.Conn),
		serverMsgCh:    sch,
		peerMsgCh:      pch,
		rfMap:          make(map[bgp.RouteFamily]bool),
		capMap:         make(map[bgp.BGPCapabilityCode]bgp.ParameterCapabilityInterface),
	}
	p.siblings = make(map[string]*serverMsgDataPeer)

	p.fsm = NewFSM(&globalConfig, &peerConfig, p.acceptedConnCh)
	peerConfig.BgpNeighborCommonState.State = uint32(bgp.BGP_FSM_IDLE)
	peerConfig.BgpNeighborCommonState.Downtime = time.Now().Unix()
	if peerConfig.NeighborAddress.To4() != nil {
		p.rfMap[bgp.RF_IPv4_UC] = true
	} else {
		p.rfMap[bgp.RF_IPv6_UC] = true
	}

	p.peerInfo = &table.PeerInfo{
		AS:      peerConfig.PeerAs,
		LocalID: globalConfig.RouterId,
		Address: peerConfig.NeighborAddress,
	}
	rfList := []bgp.RouteFamily{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC}
	p.adjRib = table.NewAdjRib(rfList)
	p.rib = table.NewTableManager(p.peerConfig.NeighborAddress.String(), rfList)

	return p
}
