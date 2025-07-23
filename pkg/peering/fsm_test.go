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
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/osrg/gobgp/v4/pkg/bgputils"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/utils"

	"github.com/stretchr/testify/assert"
)

type MockConnection struct {
	net.Conn
	remote net.Conn

	lock     sync.Mutex
	bufReady *utils.NotificationChannel
	lastBuf  []byte
	lastErr  error
}

func NewMockConnection() *MockConnection {
	l, r := net.Pipe()
	m := &MockConnection{
		Conn:     l,
		remote:   r,
		bufReady: utils.NewNotificationChannel(),
		lastBuf:  make([]byte, bgp.BGP_MAX_MESSAGE_LENGTH),
	}

	go func() {
		buf := make([]byte, bgp.BGP_MAX_MESSAGE_LENGTH)
		for {
			n, err := m.remote.Read(buf)
			if n == 0 && errors.Is(err, io.EOF) {
				return
			}
			m.lock.Lock()
			copy(m.lastBuf, buf[:n])
			m.lastBuf = m.lastBuf[:n]
			m.lastErr = err
			m.lock.Unlock()
			m.bufReady.Notify()
			if err != nil {
				break
			}
		}
	}()

	return m
}

func (m *MockConnection) GetLastestBuf() ([]byte, error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	buf := make([]byte, len(m.lastBuf))
	err := m.lastErr
	copy(buf, m.lastBuf)
	return buf, err
}

func TestReadAll(t *testing.T) {
	assert := assert.New(t)
	m := NewMockConnection()
	msg := open()
	expected1, _ := msg.Header.Serialize()
	expected2, _ := msg.Body.Serialize()

	pushBytes := func() {
		t.Log("push 5 bytes")
		m.remote.Write(expected1[:5])
		t.Log("push rest")
		m.remote.Write(expected1[5:])
		t.Log("push bytes at once")
		m.remote.Write(expected2)
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
	p := makePeer(bgp.BGP_FSM_OPENSENT)
	t.Cleanup(func() { cleanPeer(p) })

	// set opensent holdtime
	OpenSentHoldTime = 2 * time.Second

	// simulate the connection being accepted and the open message being sent
	err := p.fsm.acceptConn(m)
	assert.NoError(err)

	transition := p.fsm.step(t.Context())
	assert.Equal(bgp.BGP_FSM_IDLE, transition.NewState)

	<-m.bufReady.C

	// hold timer expired, so a notification message should be sent
	lastMsg, err := m.GetLastestBuf()
	assert.True(err == nil || errors.Is(err, io.EOF))

	sent, err := bgp.ParseBGPMessage(lastMsg)
	assert.NoError(err)
	assert.Equal(uint8(bgp.BGP_MSG_NOTIFICATION), sent.Header.Type)
	assert.Equal(uint8(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED), sent.Body.(*bgp.BGPNotification).ErrorCode)
}

func TestFSMHandlerOpenconfirm_HoldTimerExpired(t *testing.T) {
	assert := assert.New(t)

	m := NewMockConnection()
	p := makePeer(bgp.BGP_FSM_OPENCONFIRM)
	t.Cleanup(func() { cleanPeer(p) })

	// simulate the connection being accepted and the open message being received
	conn := p.fsm.newFSMTrackedConn(m)
	p.fsm.conn.Store(conn)

	// set up keepalive ticker
	conn.keepAliveInterval = 3 * time.Second

	// set holdtime
	conn.holdTime = 2 * time.Second

	transition := p.fsm.step(t.Context())
	assert.Equal(bgp.BGP_FSM_IDLE, transition.NewState)

	lastMsg, err := m.GetLastestBuf()
	assert.True(err == nil || errors.Is(err, io.EOF))

	sent, err := bgp.ParseBGPMessage(lastMsg)
	assert.NoError(err)
	assert.Equal(uint8(bgp.BGP_MSG_NOTIFICATION), sent.Header.Type)
	assert.Equal(uint8(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED), sent.Body.(*bgp.BGPNotification).ErrorCode)
}

func TestFSMHandlerEstablish_HoldTimerExpired(t *testing.T) {
	assert := assert.New(t)

	m := NewMockConnection()
	p := makePeer(bgp.BGP_FSM_ESTABLISHED)
	t.Cleanup(func() { cleanPeer(p) })

	// simulate the connection being accepted and the open message being received
	conn := p.fsm.newFSMTrackedConn(m)
	p.fsm.conn.Store(conn)

	// set keepalive ticker
	p.fsm.timers.keepAliveInterval = 3 * time.Second

	// set holdtime
	p.fsm.timers.holdTime = 2 * time.Second

	transition := p.fsm.step(t.Context())
	assert.Equal(bgp.BGP_FSM_IDLE, transition.NewState)
	assert.Equal(FSMHoldTimerExpired, transition.Reason)

	lastMsg, err := m.GetLastestBuf()
	assert.True(err == nil || errors.Is(err, io.EOF))

	sent, err := bgp.ParseBGPMessage(lastMsg)
	assert.NoError(err)
	assert.Equal(uint8(bgp.BGP_MSG_NOTIFICATION), sent.Header.Type)
	assert.Equal(uint8(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED), sent.Body.(*bgp.BGPNotification).ErrorCode)
}

func TestFSMHandlerEstablish_HoldTimerExpired_GR_Enabled(t *testing.T) {
	assert := assert.New(t)

	m := NewMockConnection()
	p := makePeer(bgp.BGP_FSM_ESTABLISHED)
	t.Cleanup(func() { cleanPeer(p) })

	// simulate the connection being accepted and the open message being received
	conn := p.fsm.newFSMTrackedConn(m)
	p.fsm.conn.Store(conn)

	// set keepalive ticker
	p.fsm.timers.keepAliveInterval = 3 * time.Second

	// set holdtime
	p.fsm.timers.holdTime = 2 * time.Second

	// Enable graceful restart
	p.Common.PeerConf.GracefulRestart.State.Enabled = true

	transition := p.fsm.step(t.Context())
	assert.Equal(bgp.BGP_FSM_IDLE, transition.NewState)
	assert.Equal(FSMGracefulRestart, transition.Reason)

	lastMsg, err := m.GetLastestBuf()
	assert.True(err == nil || errors.Is(err, io.EOF))

	sent, err := bgp.ParseBGPMessage(lastMsg)
	assert.NoError(err)
	assert.Equal(uint8(bgp.BGP_MSG_NOTIFICATION), sent.Header.Type)
	assert.Equal(uint8(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED), sent.Body.(*bgp.BGPNotification).ErrorCode)
}

func TestFSMHandlerOpenconfirm_HoldtimeZero(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)

	m := NewMockConnection()
	p := makePeer(bgp.BGP_FSM_OPENCONFIRM)
	t.Cleanup(func() {
		wg.Wait()
		cleanPeer(p)
	})

	// set keepalive ticker
	p.fsm.timers.keepAliveInterval = 0 * time.Second

	// set holdtime
	p.fsm.timers.holdTime = 0 * time.Second

	// simulate the connection being accepted and the open message being received
	conn := p.fsm.newFSMTrackedConn(m)
	p.fsm.conn.Store(conn)
	go func() {
		p.fsm.step(t.Context())
		wg.Done()
	}()

	select {
	case <-time.After(100 * time.Millisecond):
	case <-m.bufReady.C:
		lastMsg, err := m.GetLastestBuf()
		assert.NoError(t, err)
		sent, err := bgp.ParseBGPMessage(lastMsg)
		assert.NoError(t, err)
		t.Fatalf("Expected no messages to be sent, but got one: %v", sent.Body)
	}
}

func TestFSMHandlerEstablished_HoldtimeZero(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)

	m := NewMockConnection()
	p := makePeer(bgp.BGP_FSM_ESTABLISHED)
	t.Cleanup(func() {
		wg.Wait()
		cleanPeer(p)
	})

	// set keepalive ticker
	p.fsm.timers.keepAliveInterval = 0 * time.Second

	// set holdtime
	p.fsm.timers.holdTime = 0 * time.Second

	// simulate the connection being accepted and the open message being received
	conn := p.fsm.newFSMTrackedConn(m)
	p.fsm.conn.Store(conn)
	go func() {
		p.fsm.step(t.Context())
		wg.Done()
	}()

	select {
	case <-time.After(100 * time.Millisecond):
	case <-m.bufReady.C:
		lastMsg, err := m.GetLastestBuf()
		assert.NoError(t, err)
		sent, err := bgp.ParseBGPMessage(lastMsg)
		assert.NoError(t, err)
		t.Fatalf("Expected no messages to be sent, but got one: %v", sent.Body)
	}
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

func makePeer(state bgp.FSMState) *Peer {
	logger := log.NewDefaultLogger()
	p := NewPeer(&oc.Global{}, &oc.Neighbor{}, nil, nil, logger)
	p.fsm = newFSM(p.Common, nil, nil, logger)
	p.fsm.state.Store(state)
	return p
}

func cleanPeer(p *Peer) {
	p.fsm.outgoingCh.Close()
	conn := p.fsm.conn.Load()
	if conn != nil {
		conn.Close()
	}
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
