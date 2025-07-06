// Copyright (C) 2014-2021 Nippon Telegraph and Telephone Corporation.
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

package peering

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/eapache/channels"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/osrg/gobgp/v4/pkg/bgputils"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockConnection struct {
	net.Conn
	recvCh    chan chan byte
	sendBuf   [][]byte
	currentCh chan byte
	isClosed  bool
	wait      int
	mtx       sync.Mutex
}

func NewMockConnection() *MockConnection {
	m := &MockConnection{
		recvCh:   make(chan chan byte, 128),
		sendBuf:  make([][]byte, 0),
		isClosed: false,
	}
	return m
}

func (m *MockConnection) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *MockConnection) SetWriteDeadline(t time.Time) error {
	return nil
}

func (m *MockConnection) setData(data []byte) int {
	dataChan := make(chan byte, 4096)
	for _, b := range data {
		dataChan <- b
	}
	m.recvCh <- dataChan
	return len(dataChan)
}

func (m *MockConnection) Read(buf []byte) (int, error) {
	m.mtx.Lock()
	closed := m.isClosed
	m.mtx.Unlock()
	if closed {
		return 0, errors.New("already closed")
	}

	if m.currentCh == nil {
		m.currentCh = <-m.recvCh
	}

	length := 0
	rest := len(buf)
	for i := range rest {
		if len(m.currentCh) > 0 {
			val := <-m.currentCh
			buf[i] = val
			length++
		} else {
			m.currentCh = nil
			break
		}
	}

	return length, nil
}

func (m *MockConnection) Write(buf []byte) (int, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	time.Sleep(time.Duration(m.wait) * time.Millisecond)
	m.sendBuf = append(m.sendBuf, buf)
	_, err := bgp.ParseBGPMessage(buf)
	return len(buf), err
}

func (m *MockConnection) GetLastestBuf() []byte {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	if len(m.sendBuf) == 0 {
		return nil
	}
	return m.sendBuf[len(m.sendBuf)-1]
}

func (m *MockConnection) GetBufCount() int {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	return len(m.sendBuf)
}

func (m *MockConnection) Close() error {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	if !m.isClosed {
		close(m.recvCh)
		m.isClosed = true
	}
	return nil
}

func (m *MockConnection) LocalAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.ParseIP("10.10.10.10"),
		Port: bgp.BGP_PORT,
	}
}

func TestReadAll(t *testing.T) {
	assert := assert.New(t)
	m := NewMockConnection()
	msg := open()
	expected1, _ := msg.Header.Serialize()
	expected2, _ := msg.Body.Serialize()

	pushBytes := func() {
		t.Log("push 5 bytes")
		m.setData(expected1[:5])
		t.Log("push rest")
		m.setData(expected1[5:])
		t.Log("push bytes at once")
		m.setData(expected2)
	}

	go pushBytes()

	var actual1 []byte
	actual1, _ = netutils.ReadAll(m, bgp.BGP_HEADER_LENGTH)
	assert.Equal(expected1, actual1)

	var actual2 []byte
	actual2, _ = netutils.ReadAll(m, len(expected2))
	assert.Equal(expected2, actual2)
}

func TestFSMHandlerOpensent_HoldTimerExpired(t *testing.T) {
	assert := assert.New(t)

	m := NewMockConnection()
	p, h := makePeerAndHandler(m)
	defer cleanPeerAndHandler(p, h)

	// set keepalive ticker
	p.FSM.PeerConf.Timers.State.KeepaliveInterval = 3

	// set holdtime
	p.FSM.OpenSentHoldTime = 2

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	state, _ := h.opensent(ctx)

	assert.Equal(bgp.BGP_FSM_IDLE, state)
	lastMsg := m.GetLastestBuf()
	sent, _ := bgp.ParseBGPMessage(lastMsg)
	assert.Equal(uint8(bgp.BGP_MSG_NOTIFICATION), sent.Header.Type)
	assert.Equal(uint8(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED), sent.Body.(*bgp.BGPNotification).ErrorCode)
}

func TestFSMHandlerOpenconfirm_HoldTimerExpired(t *testing.T) {
	assert := assert.New(t)

	m := NewMockConnection()
	p, h := makePeerAndHandler(m)
	defer cleanPeerAndHandler(p, h)

	// set up keepalive ticker
	p.FSM.PeerConf.Timers.Config.KeepaliveInterval = 1

	// set holdtime
	p.FSM.PeerConf.Timers.State.NegotiatedHoldTime = 2

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	state, _ := h.openconfirm(ctx)

	assert.Equal(bgp.BGP_FSM_IDLE, state)
	lastMsg := m.GetLastestBuf()
	sent, _ := bgp.ParseBGPMessage(lastMsg)
	assert.Equal(uint8(bgp.BGP_MSG_NOTIFICATION), sent.Header.Type)
	assert.Equal(uint8(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED), sent.Body.(*bgp.BGPNotification).ErrorCode)
}

func TestFSMHandlerEstablish_HoldTimerExpired(t *testing.T) {
	assert := assert.New(t)

	m := NewMockConnection()
	p, h := makePeerAndHandler(m)
	defer cleanPeerAndHandler(p, h)

	// set keepalive ticker
	p.FSM.PeerConf.Timers.State.KeepaliveInterval = 3

	msg := keepalive()
	header, _ := msg.Header.Serialize()
	body, _ := msg.Body.Serialize()

	pushPackets := func() {
		// first keepalive from peer
		m.setData(header)
		m.setData(body)
	}

	// set holdtime
	p.FSM.PeerConf.Timers.Config.HoldTime = 2
	p.FSM.PeerConf.Timers.State.NegotiatedHoldTime = 2

	go pushPackets()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	state, fsmStateReason := h.established(ctx)
	assert.Equal(bgp.BGP_FSM_IDLE, state)
	assert.Equal(FSMHoldTimerExpired, fsmStateReason.Type)
	time.Sleep(time.Second * 1)
	lastMsg := m.GetLastestBuf()
	require.NotNil(t, lastMsg)
	sent, _ := bgp.ParseBGPMessage(lastMsg)
	assert.Equal(uint8(bgp.BGP_MSG_NOTIFICATION), sent.Header.Type)
	assert.Equal(uint8(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED), sent.Body.(*bgp.BGPNotification).ErrorCode)
}

func TestFSMHandlerEstablish_HoldTimerExpired_GR_Enabled(t *testing.T) {
	assert := assert.New(t)

	m := NewMockConnection()
	p, h := makePeerAndHandler(m)
	defer cleanPeerAndHandler(p, h)

	// set keepalive ticker
	p.FSM.PeerConf.Timers.State.KeepaliveInterval = 3

	msg := keepalive()
	header, _ := msg.Header.Serialize()
	body, _ := msg.Body.Serialize()

	pushPackets := func() {
		// first keepalive from peer
		m.setData(header)
		m.setData(body)
	}

	// set holdtime
	p.FSM.PeerConf.Timers.Config.HoldTime = 2
	p.FSM.PeerConf.Timers.State.NegotiatedHoldTime = 2

	// Enable graceful restart
	p.FSM.PeerConf.GracefulRestart.State.Enabled = true

	go pushPackets()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	state, fsmStateReason := h.established(ctx)
	assert.Equal(bgp.BGP_FSM_IDLE, state)
	assert.Equal(FSMGracefulRestart, fsmStateReason.Type)
	time.Sleep(time.Second * 1)
	lastMsg := m.GetLastestBuf()
	require.NotNil(t, lastMsg)
	sent, _ := bgp.ParseBGPMessage(lastMsg)
	assert.Equal(uint8(bgp.BGP_MSG_NOTIFICATION), sent.Header.Type)
	assert.Equal(uint8(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED), sent.Body.(*bgp.BGPNotification).ErrorCode)
}

func TestFSMHandlerOpenconfirm_HoldtimeZero(t *testing.T) {
	assert := assert.New(t)

	m := NewMockConnection()
	p, h := makePeerAndHandler(m)
	defer cleanPeerAndHandler(p, h)

	// set up keepalive ticker
	p.FSM.PeerConf.Timers.Config.KeepaliveInterval = 1
	// set holdtime
	p.FSM.PeerConf.Timers.State.NegotiatedHoldTime = 0

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go h.openconfirm(ctx)

	time.Sleep(100 * time.Millisecond)

	assert.Equal(0, m.GetBufCount())
}

func TestFSMHandlerEstablished_HoldtimeZero(t *testing.T) {
	assert := assert.New(t)

	m := NewMockConnection()
	p, h := makePeerAndHandler(m)
	defer cleanPeerAndHandler(p, h)

	// set holdtime
	p.FSM.PeerConf.Timers.State.NegotiatedHoldTime = 0

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go h.established(ctx)

	time.Sleep(100 * time.Millisecond)

	assert.Equal(0, m.GetBufCount())
}

func TestCheckOwnASLoop(t *testing.T) {
	assert := assert.New(t)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{65100})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	assert.False(bgputils.HasOwnASLoop(65100, 10, aspath))
	assert.True(bgputils.HasOwnASLoop(65100, 0, aspath))
	assert.False(bgputils.HasOwnASLoop(65200, 0, aspath))
}

func TestBadBGPIdentifier(t *testing.T) {
	assert := assert.New(t)
	msg1 := openWithBadBGPIdentifier_Zero()
	msg2 := openWithBadBGPIdentifier_Same()
	body1 := msg1.Body.(*bgp.BGPOpen)
	body2 := msg2.Body.(*bgp.BGPOpen)

	// Test if Bad BGP Identifier notification is sent if remote router-id is 0.0.0.0.
	peerAs, err := bgp.ValidateOpenMsg(body1, 65000, 65001, net.ParseIP("192.168.1.1"))
	assert.Equal(int(peerAs), 0)
	assert.Equal(uint8(bgp.BGP_ERROR_SUB_BAD_BGP_IDENTIFIER), err.(*bgp.MessageError).SubTypeCode)

	// Test if Bad BGP Identifier notification is sent if remote router-id is the same for iBGP.
	peerAs, err = bgp.ValidateOpenMsg(body2, 65000, 65000, net.ParseIP("192.168.1.1"))
	assert.Equal(int(peerAs), 0)
	assert.Equal(uint8(bgp.BGP_ERROR_SUB_BAD_BGP_IDENTIFIER), err.(*bgp.MessageError).SubTypeCode)
}

func makePeerAndHandler(m net.Conn) (*Peer, *FSMHandler) {
	fsm := newFSM(&oc.Global{}, &oc.Neighbor{}, log.NewDefaultLogger())
	fsm.Conn = m

	p := &Peer{FSM: fsm}

	h := &FSMHandler{
		FSM:           fsm,
		StateReasonCh: make(chan FSMStateReason, 2),
		Outgoing:      channels.NewInfiniteChannel(),
		Callback:      func(*FSMMsg) {},
	}

	fsm.Handler = h
	return p, h
}

func cleanPeerAndHandler(p *Peer, h *FSMHandler) {
	h.Outgoing.Close()
	p.FSM.OutgoingCh.Close()
	p.FSM.Conn.Close()
}

func open() *bgp.BGPMessage {
	p1 := bgp.NewOptionParameterCapability(
		[]bgp.ParameterCapabilityInterface{bgp.NewCapRouteRefresh()})
	p2 := bgp.NewOptionParameterCapability(
		[]bgp.ParameterCapabilityInterface{bgp.NewCapMultiProtocol(bgp.RF_IPv4_UC)})
	g := &bgp.CapGracefulRestartTuple{AFI: 4, SAFI: 2, Flags: 3}
	p3 := bgp.NewOptionParameterCapability(
		[]bgp.ParameterCapabilityInterface{bgp.NewCapGracefulRestart(true, true, 100,
			[]*bgp.CapGracefulRestartTuple{g})})
	p4 := bgp.NewOptionParameterCapability(
		[]bgp.ParameterCapabilityInterface{bgp.NewCapFourOctetASNumber(100000)})
	return bgp.NewBGPOpenMessage(11033, 303, "100.4.10.3",
		[]bgp.OptionParameterInterface{p1, p2, p3, p4})
}

func openWithBadBGPIdentifier_Zero() *bgp.BGPMessage {
	return bgp.NewBGPOpenMessage(65000, 303, "0.0.0.0",
		[]bgp.OptionParameterInterface{})
}

func openWithBadBGPIdentifier_Same() *bgp.BGPMessage {
	return bgp.NewBGPOpenMessage(65000, 303, "192.168.1.1",
		[]bgp.OptionParameterInterface{})
}

func keepalive() *bgp.BGPMessage {
	return bgp.NewBGPKeepAliveMessage()
}
