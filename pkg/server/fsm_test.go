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

package server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eapache/channels"
	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/packet/bmp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type NotificationChannel struct {
	C chan any
}

func NewNotificationChannel() *NotificationChannel {
	return &NotificationChannel{
		C: make(chan any, 1),
	}
}

func (nc *NotificationChannel) Notify() {
	select {
	case nc.C <- struct{}{}:
	default:
	}
}

func (nc *NotificationChannel) Clear() {
	select {
	case <-nc.C:
	default:
	}
}

type MockConnection struct {
	net.Conn
	remote net.Conn

	lock        sync.Mutex
	bufReady    *NotificationChannel
	lastBuf     []byte
	lastErr     error
	allMessages [][]byte
	remoteAddr  net.Addr
	localAddr   net.Addr
}

func NewMockConnection() *MockConnection {
	l, r := net.Pipe()
	m := &MockConnection{
		Conn:        l,
		remote:      r,
		bufReady:    NewNotificationChannel(),
		lastBuf:     make([]byte, bgp.BGP_MAX_MESSAGE_LENGTH),
		allMessages: make([][]byte, 0),
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
			msg := make([]byte, n)
			copy(msg, buf[:n])
			m.allMessages = append(m.allMessages, msg)
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

// Additional MockConnection helpers used by server_test.go:
//   - SetRemoteAddr configures deterministic local/remote TCP addresses so tests
//     can validate BGP server behavior that depends on peer addressing.
//   - RemoteAddr and LocalAddr honor any test-specified addresses while
//     falling back to the underlying net.Conn when none are set.
func (m *MockConnection) SetRemoteAddr(addr string) {
	ip := netip.MustParseAddr(addr)
	m.lock.Lock()
	m.remoteAddr = net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip, 10179))
	m.localAddr = &net.TCPAddr{IP: net.ParseIP("127.0.0.201"), Port: 10179}
	m.lock.Unlock()
}

func (m *MockConnection) RemoteAddr() net.Addr {
	m.lock.Lock()
	defer m.lock.Unlock()
	if m.remoteAddr != nil {
		return m.remoteAddr
	}
	return m.Conn.RemoteAddr()
}

func (m *MockConnection) LocalAddr() net.Addr {
	m.lock.Lock()
	defer m.lock.Unlock()
	if m.localAddr != nil {
		return m.localAddr
	}
	return m.Conn.LocalAddr()
}

func (m *MockConnection) PushBgpMessage(msg *bgp.BGPMessage) {
	buf, _ := msg.Serialize()
	m.remote.Write(buf)
}

func (m *MockConnection) GetSentMessages() [][]byte {
	m.lock.Lock()
	defer m.lock.Unlock()
	// Return collected messages
	result := make([][]byte, len(m.allMessages))
	copy(result, m.allMessages)
	return result
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
	actual1, _ = readAll(m, bgp.BGP_HEADER_LENGTH)
	assert.Equal(expected1, actual1)

	var actual2 []byte
	actual2, _ = readAll(m, len(expected2))
	assert.Equal(expected2, actual2)
}

func TestFSMHandlerOpensent_HoldTimerExpired(t *testing.T) {
	assert := assert.New(t)

	m := NewMockConnection()
	p, h := makePeerAndHandler(m)
	t.Cleanup(func() { cleanPeerAndHandler(p, h) })

	// set holdtime
	p.fsm.opensentHoldTime = 2
	p.fsm.gConf.Config.RouterId = netip.MustParseAddr("1.1.1.1")

	state, reason := h.opensent(t.Context())

	assert.Equal(bgp.BGP_FSM_IDLE, state)
	assert.Equal(fsmHoldTimerExpired, reason.Type)

	<-m.bufReady.C

	// hold timer expired, so a notification message should be sent
	lastMsg, err := m.GetLastestBuf()
	assert.True(err == nil || errors.Is(err, io.EOF))

	sent, _ := bgp.ParseBGPMessage(lastMsg)
	assert.Equal(uint8(bgp.BGP_MSG_NOTIFICATION), sent.Header.Type)
	assert.Equal(uint8(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED), sent.Body.(*bgp.BGPNotification).ErrorCode)
}

// RFC 4271 8.2.2: in OpenSent, a NOTIFICATION with a version error
// (Event 24) gets no answer, and any other NOTIFICATION (Event 25) gets
// a Finite State Machine Error.
func TestFSMHandlerOpensent_NotificationReceived(t *testing.T) {
	tests := []struct {
		name       string
		code       uint8
		subcode    uint8
		wantReason fsmStateReasonType
		wantAnswer bool
	}{
		{"version error", bgp.BGP_ERROR_OPEN_MESSAGE_ERROR, bgp.BGP_ERROR_SUB_UNSUPPORTED_VERSION_NUMBER, fsmNotificationRecv, false},
		{"other open error", bgp.BGP_ERROR_OPEN_MESSAGE_ERROR, bgp.BGP_ERROR_SUB_BAD_PEER_AS, fsmInvalidMsg, true},
		{"cease", bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_CONNECTION_COLLISION_RESOLUTION, fsmInvalidMsg, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMockConnection()
			p, h := makePeerAndHandler(m)
			t.Cleanup(func() { cleanPeerAndHandler(p, h) })
			p.fsm.opensentHoldTime = 10

			// net.Pipe writes block until the message is read.
			go m.PushBgpMessage(bgp.NewBGPNotificationMessage(tt.code, tt.subcode, nil))

			state, reason := h.opensent(t.Context())
			require.Equal(t, bgp.BGP_FSM_IDLE, state)
			require.Equal(t, tt.wantReason, reason.Type)

			if !tt.wantAnswer {
				require.Equal(t, tt.code, reason.BGPNotification.ErrorCode)
				require.Equal(t, tt.subcode, reason.BGPNotification.ErrorSubcode)
				require.Never(t, func() bool { return len(m.GetSentMessages()) > 0 },
					100*time.Millisecond, 10*time.Millisecond)
				return
			}
			require.Eventually(t, func() bool { return len(m.GetSentMessages()) > 0 },
				time.Second, 10*time.Millisecond)
			sent, err := bgp.ParseBGPMessage(m.GetSentMessages()[0])
			require.NoError(t, err)
			require.Equal(t, uint8(bgp.BGP_MSG_NOTIFICATION), sent.Header.Type)
			n := sent.Body.(*bgp.BGPNotification)
			require.Equal(t, uint8(bgp.BGP_ERROR_FSM_ERROR), n.ErrorCode)
			require.Equal(t, uint8(1), n.ErrorSubcode)
		})
	}
}

func TestFSMHandlerOpenconfirm_HoldTimerExpired(t *testing.T) {
	assert := assert.New(t)

	m := NewMockConnection()
	p, h := makePeerAndHandler(m)
	t.Cleanup(func() { cleanPeerAndHandler(p, h) })

	// set keepalive ticker
	p.fsm.lock.Lock()
	conf := p.fsm.pConf.ReadCopy()
	conf.Timers.State.KeepaliveInterval = 3

	// set holdtime
	conf.Timers.State.NegotiatedHoldTime = 2
	p.fsm.pConf.Update(&conf)
	p.fsm.lock.Unlock()

	state, reason := h.openconfirm(t.Context())

	assert.Equal(bgp.BGP_FSM_IDLE, state)
	assert.Equal(fsmHoldTimerExpired, reason.Type)

	<-m.bufReady.C

	lastMsg, err := m.GetLastestBuf()
	assert.True(err == nil || errors.Is(err, io.EOF))

	sent, _ := bgp.ParseBGPMessage(lastMsg)
	assert.Equal(uint8(bgp.BGP_MSG_NOTIFICATION), sent.Header.Type)
	assert.Equal(uint8(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED), sent.Body.(*bgp.BGPNotification).ErrorCode)
}

// RFC 4271 8.2.2: in OpenConfirm, a NOTIFICATION (Event 24 or 25) gets no
// answer. The reason carries the received NOTIFICATION.
func TestFSMHandlerOpenconfirm_NotificationReceived(t *testing.T) {
	tests := []struct {
		name    string
		code    uint8
		subcode uint8
	}{
		{"version error", bgp.BGP_ERROR_OPEN_MESSAGE_ERROR, bgp.BGP_ERROR_SUB_UNSUPPORTED_VERSION_NUMBER},
		{"cease", bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMockConnection()
			p, h := makePeerAndHandler(m)
			t.Cleanup(func() { cleanPeerAndHandler(p, h) })

			p.fsm.lock.Lock()
			conf := p.fsm.pConf.ReadCopy()
			conf.Timers.State.KeepaliveInterval = 30
			conf.Timers.State.NegotiatedHoldTime = 90
			p.fsm.pConf.Update(&conf)
			p.fsm.lock.Unlock()

			// net.Pipe writes block until the message is read.
			go m.PushBgpMessage(bgp.NewBGPNotificationMessage(tt.code, tt.subcode, nil))

			state, reason := h.openconfirm(t.Context())
			require.Equal(t, bgp.BGP_FSM_IDLE, state)
			require.Equal(t, fsmNotificationRecv, reason.Type)
			require.Equal(t, tt.code, reason.BGPNotification.ErrorCode)
			require.Equal(t, tt.subcode, reason.BGPNotification.ErrorSubcode)
			require.Never(t, func() bool { return len(m.GetSentMessages()) > 0 },
				100*time.Millisecond, 10*time.Millisecond)
		})
	}
}

func TestFSMHandlerEstablish_HoldTimerExpired(t *testing.T) {
	assert := assert.New(t)

	m := NewMockConnection()
	p, h := makePeerAndHandler(m)
	t.Cleanup(func() { cleanPeerAndHandler(p, h) })

	p.fsm.lock.Lock()
	conf := p.fsm.pConf.ReadCopy()
	// set keepalive ticker
	conf.Timers.State.KeepaliveInterval = 3

	// set holdtime
	conf.Timers.State.NegotiatedHoldTime = 2
	p.fsm.pConf.Update(&conf)
	p.fsm.lock.Unlock()

	state, reason := h.established(t.Context())
	assert.Equal(bgp.BGP_FSM_IDLE, state)
	assert.Equal(fsmHoldTimerExpired, reason.Type)

	// force send pending messages
	<-m.bufReady.C

	lastMsg, err := m.GetLastestBuf()
	assert.True(err == nil || errors.Is(err, io.EOF))

	sent, _ := bgp.ParseBGPMessage(lastMsg)
	assert.Equal(uint8(bgp.BGP_MSG_NOTIFICATION), sent.Header.Type)
	assert.Equal(uint8(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED), sent.Body.(*bgp.BGPNotification).ErrorCode)
}

func TestFSMHandlerEstablish_HoldTimerExpired_GR_Enabled(t *testing.T) {
	assert := assert.New(t)

	m := NewMockConnection()
	p, h := makePeerAndHandler(m)
	t.Cleanup(func() { cleanPeerAndHandler(p, h) })

	p.fsm.lock.Lock()
	conf := p.fsm.pConf.ReadCopy()
	// set keepalive ticker
	conf.Timers.State.KeepaliveInterval = 3

	// set holdtime
	conf.Timers.State.NegotiatedHoldTime = 2

	// Enable graceful restart
	conf.GracefulRestart.State.Enabled = true
	p.fsm.pConf.Update(&conf)
	p.fsm.lock.Unlock()

	// The server decides whether the session ends gracefully. The FSM
	// reports the real reason.
	state, reason := h.established(t.Context())
	assert.Equal(bgp.BGP_FSM_IDLE, state)
	assert.Equal(fsmHoldTimerExpired, reason.Type)
	assert.Equal(uint8(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED), reason.BGPNotification.ErrorCode)

	<-m.bufReady.C

	lastMsg, err := m.GetLastestBuf()
	assert.True(err == nil || errors.Is(err, io.EOF))

	sent, _ := bgp.ParseBGPMessage(lastMsg)
	assert.Equal(uint8(bgp.BGP_MSG_NOTIFICATION), sent.Header.Type)
	assert.Equal(uint8(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED), sent.Body.(*bgp.BGPNotification).ErrorCode)
}

// writeFailConn is a connection on which every write fails.
type writeFailConn struct {
	*MockConnection
}

func (c writeFailConn) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

// When the hold timer expires and the NOTIFICATION cannot be sent, the
// session ends with a write failure, which the server handles as a graceful
// restart.
func TestFSMHandlerEstablish_HoldTimerExpired_GR_Enabled_WriteFailed(t *testing.T) {
	m := writeFailConn{NewMockConnection()}
	p, h := makePeerAndHandler(m)
	t.Cleanup(func() { cleanPeerAndHandler(p, h) })

	p.fsm.lock.Lock()
	conf := p.fsm.pConf.ReadCopy()
	// The hold timer expires before the first KEEPALIVE is sent.
	conf.Timers.State.KeepaliveInterval = 3
	conf.Timers.State.NegotiatedHoldTime = 2
	conf.GracefulRestart.State.Enabled = true
	p.fsm.pConf.Update(&conf)
	p.fsm.lock.Unlock()

	state, reason := h.established(t.Context())
	assert.Equal(t, bgp.BGP_FSM_IDLE, state)
	assert.Equal(t, fsmWriteFailed, reason.Type)
}

// While the server processes a message from the peer, the recv goroutine
// does not read the next messages. The hold timer does not end the session
// then. It expires after the server is done, if nothing else comes.
func TestFSMHandlerEstablished_HoldTimerWhileProcessing(t *testing.T) {
	m := NewMockConnection()
	p, h := makePeerAndHandler(m)
	t.Cleanup(func() { cleanPeerAndHandler(p, h) })

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	h.callback = func(*fsmMsg) {
		once.Do(func() {
			close(entered)
			<-release
		})
	}

	p.fsm.lock.Lock()
	conf := p.fsm.pConf.ReadCopy()
	conf.Timers.State.KeepaliveInterval = 3
	conf.Timers.State.NegotiatedHoldTime = 1
	p.fsm.pConf.Update(&conf)
	p.fsm.lock.Unlock()

	type result struct {
		state  bgp.FSMState
		reason *fsmStateReason
	}
	ch := make(chan result, 1)
	go func() {
		state, reason := h.established(t.Context())
		ch <- result{state, reason}
	}()
	go m.PushBgpMessage(bgp.NewEndOfRib(bgp.RF_IPv4_UC))

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the UPDATE was not passed to the server")
	}
	// The hold timer expires twice while the server processes the UPDATE.
	// No NOTIFICATION is sent. established() itself cannot return before
	// the recv goroutine does, so the NOTIFICATION is what shows it.
	notificationSent := func() bool {
		for _, b := range m.GetSentMessages() {
			msg, err := bgp.ParseBGPMessage(b)
			if err == nil && msg.Header.Type == bgp.BGP_MSG_NOTIFICATION {
				return true
			}
		}
		return false
	}
	require.Never(t, notificationSent, 2500*time.Millisecond, 50*time.Millisecond)

	close(release)
	select {
	case r := <-ch:
		assert.Equal(t, bgp.BGP_FSM_IDLE, r.state)
		assert.Equal(t, fsmHoldTimerExpired, r.reason.Type)
	case <-time.After(5 * time.Second):
		t.Fatal("the hold timer did not expire after the server was done")
	}
	assert.True(t, notificationSent())
}

// A received Hard Reset is reported as fsmHardReset even when the "N" bit
// was not exchanged.
func TestFSMHandlerEstablish_HardResetReceived(t *testing.T) {
	m := NewMockConnection()
	p, h := makePeerAndHandler(m)
	t.Cleanup(func() { cleanPeerAndHandler(p, h) })

	go m.PushBgpMessage(bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_HARD_RESET, nil))

	state, reason := h.established(t.Context())
	assert.Equal(t, bgp.BGP_FSM_IDLE, state)
	assert.Equal(t, fsmHardReset, reason.Type)
}

func TestFSMHandlerOpenconfirm_HoldtimeZero(t *testing.T) {
	assert := assert.New(t)

	m := NewMockConnection()
	p, h := makePeerAndHandler(m)
	t.Cleanup(func() { cleanPeerAndHandler(p, h) })

	p.fsm.lock.Lock()
	conf := p.fsm.pConf.ReadCopy()
	// set up keepalive ticker
	conf.Timers.Config.KeepaliveInterval = 1
	// set holdtime
	conf.Timers.State.NegotiatedHoldTime = 0
	p.fsm.pConf.Update(&conf)
	p.fsm.lock.Unlock()

	go h.openconfirm(t.Context())

	select {
	case <-time.After(100 * time.Millisecond):
	case <-m.bufReady.C:
		lastMsg, err := m.GetLastestBuf()
		assert.NoError(err)
		sent, err := bgp.ParseBGPMessage(lastMsg)
		assert.NoError(err)
		t.Fatalf("Expected no messages to be sent, but got one: %v", sent.Body)
	}
}

func TestFSMHandlerEstablished_HoldtimeZero(t *testing.T) {
	assert := assert.New(t)

	m := NewMockConnection()
	p, h := makePeerAndHandler(m)
	t.Cleanup(func() { cleanPeerAndHandler(p, h) })

	p.fsm.lock.Lock()
	conf := p.fsm.pConf.ReadCopy()
	// set holdtime
	conf.Timers.State.NegotiatedHoldTime = 0
	p.fsm.pConf.Update(&conf)
	p.fsm.lock.Unlock()

	go h.established(t.Context())

	select {
	case <-time.After(100 * time.Millisecond):
	case <-m.bufReady.C:
		lastMsg, err := m.GetLastestBuf()
		assert.NoError(err)
		sent, err := bgp.ParseBGPMessage(lastMsg)
		assert.NoError(err)
		t.Fatalf("Expected no messages to be sent, but got one: %v", sent.Body)
	}
}

func TestCheckOwnASLoop(t *testing.T) {
	assert := assert.New(t)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{65100})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)

	// Test without confederation (existing tests)
	assert.False(hasOwnASLoop(65100, 10, aspath, 0, false))
	assert.True(hasOwnASLoop(65100, 0, aspath, 0, false))
	assert.False(hasOwnASLoop(65200, 0, aspath, 0, false))
}

// Test for issue #3311: Confederation ID loop detection (RFC 5065 Section 4)
func TestCheckOwnASLoopWithConfederation(t *testing.T) {
	assert := assert.New(t)

	// Test case 1: AS_PATH contains Confederation ID
	// AS_PATH: [65100, 65250]
	// Local AS: 65100
	// Confederation ID: 65250
	aspathParam1 := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{65100, 65250})}
	aspath1 := bgp.NewPathAttributeAsPath(aspathParam1)

	// Should detect loop when Confederation ID (65250) is in AS_PATH
	assert.True(hasOwnASLoop(65100, 0, aspath1, 65250, true),
		"Should detect AS loop when Confederation ID is in AS_PATH")

	// Should detect loop with allowOwnAs=1 (ownAS appears once + confedID appears once = 2 > limit 1)
	assert.True(hasOwnASLoop(65100, 1, aspath1, 65250, true),
		"Should detect AS loop when total count exceeds limit")

	// Should allow with allowOwnAs=2 (ownAS appears once + confedID appears once = 2 <= limit 2)
	assert.False(hasOwnASLoop(65100, 2, aspath1, 65250, true),
		"Should allow when count equals limit")

	// Should not detect loop when confederation is disabled
	assert.True(hasOwnASLoop(65100, 0, aspath1, 65250, false),
		"Should still detect ownAS loop even when confederation disabled")

	// Test case 2: AS_PATH contains only Confederation ID
	// AS_PATH: [65200, 65250]
	// Local AS: 65100
	// Confederation ID: 65250
	aspathParam2 := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{65200, 65250})}
	aspath2 := bgp.NewPathAttributeAsPath(aspathParam2)

	// Should detect loop when only Confederation ID is in AS_PATH (not ownAS)
	assert.True(hasOwnASLoop(65100, 0, aspath2, 65250, true),
		"Should detect AS loop when only Confederation ID is in AS_PATH")

	// Should not detect loop when confederation is disabled
	assert.False(hasOwnASLoop(65100, 0, aspath2, 65250, false),
		"Should not detect loop when confederation is disabled")

	// Test case 3: AS_PATH contains multiple occurrences of Confederation ID
	// AS_PATH: [65250, 65200, 65250]
	// Local AS: 65100
	// Confederation ID: 65250
	aspathParam3 := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{65250, 65200, 65250})}
	aspath3 := bgp.NewPathAttributeAsPath(aspathParam3)

	// Should detect loop (2 occurrences > limit 0)
	assert.True(hasOwnASLoop(65100, 0, aspath3, 65250, true),
		"Should detect AS loop with multiple Confederation ID occurrences")

	// Should detect loop (2 occurrences > limit 1)
	assert.True(hasOwnASLoop(65100, 1, aspath3, 65250, true),
		"Should detect AS loop when count exceeds limit")

	// Should allow with limit 2
	assert.False(hasOwnASLoop(65100, 2, aspath3, 65250, true),
		"Should allow when count equals limit")

	// Test case 4: Confederation ID same as own AS
	// AS_PATH: [65250]
	// Local AS: 65250
	// Confederation ID: 65250
	aspathParam4 := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{65250})}
	aspath4 := bgp.NewPathAttributeAsPath(aspathParam4)

	// Should count only once (not double count when confedID == ownAS)
	assert.True(hasOwnASLoop(65250, 0, aspath4, 65250, true),
		"Should detect AS loop when ownAS == Confederation ID")

	// Test case 5: No loop - different AS
	// AS_PATH: [65200, 65300]
	// Local AS: 65100
	// Confederation ID: 65250
	aspathParam5 := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{65200, 65300})}
	aspath5 := bgp.NewPathAttributeAsPath(aspathParam5)

	// Should not detect loop
	assert.False(hasOwnASLoop(65100, 0, aspath5, 65250, true),
		"Should not detect loop when neither ownAS nor Confederation ID is in AS_PATH")
}

func TestBadBGPIdentifier(t *testing.T) {
	assert := assert.New(t)
	msg1 := openWithBadBGPIdentifierZero()
	msg2 := openWithBadBGPIdentifierSame()
	body1 := msg1.Body.(*bgp.BGPOpen)
	body2 := msg2.Body.(*bgp.BGPOpen)

	// Test if Bad BGP Identifier notification is sent if remote router-id is 0.0.0.0.
	peerAs, err := bgp.ValidateOpenMsg(body1, 65000, 65001, netip.MustParseAddr("192.168.1.1"))
	assert.Equal(int(peerAs), 0)
	assert.Equal(uint8(bgp.BGP_ERROR_SUB_BAD_BGP_IDENTIFIER), err.(*bgp.MessageError).SubTypeCode)

	// Test if Bad BGP Identifier notification is sent if remote router-id is the same for iBGP.
	peerAs, err = bgp.ValidateOpenMsg(body2, 65000, 65000, netip.MustParseAddr("192.168.1.1"))
	assert.Equal(int(peerAs), 0)
	assert.Equal(uint8(bgp.BGP_ERROR_SUB_BAD_BGP_IDENTIFIER), err.(*bgp.MessageError).SubTypeCode)
}

func makePeerAndHandler(m net.Conn) (*peer, *fsmHandler) {
	fsm := newFSM(&oc.Global{}, &oc.Neighbor{}, bgp.BGP_FSM_IDLE, slog.Default())
	fsm.conn = m

	p := &peer{fsm: fsm}

	h := &fsmHandler{
		fsm:      fsm,
		outgoing: channels.NewInfiniteChannel(),
		callback: func(*fsmMsg) {},
	}

	fsm.h = h
	return p, h
}

func cleanPeerAndHandler(p *peer, h *fsmHandler) {
	h.outgoing.Close()

	p.fsm.outgoingCh.Close()

	p.fsm.conn.Close()
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
	msg, _ := bgp.NewBGPOpenMessage(11033, 303, netip.MustParseAddr("100.4.10.3"),
		[]bgp.OptionParameterInterface{p1, p2, p3, p4})
	return msg
}

func openWithBadBGPIdentifierZero() *bgp.BGPMessage {
	msg, _ := bgp.NewBGPOpenMessage(65000, 303, netip.MustParseAddr("0.0.0.0"),
		[]bgp.OptionParameterInterface{})
	return msg
}

func openWithBadBGPIdentifierSame() *bgp.BGPMessage {
	msg, _ := bgp.NewBGPOpenMessage(65000, 303, netip.MustParseAddr("192.168.1.1"),
		[]bgp.OptionParameterInterface{})
	return msg
}

func TestFsmPeerConfigAccess(t *testing.T) {
	a := oc.Neighbor{
		Config: oc.NeighborConfig{
			NeighborAddress: netip.MustParseAddr("10.0.0.1"),
			PeerAs:          65001,
		},
		AfiSafis: []oc.AfiSafi{
			{
				Config: oc.AfiSafiConfig{
					AfiSafiName: oc.AFI_SAFI_TYPE_RTC,
					Enabled:     true,
				},
			},
		},
	}

	peer := newPeer(nil, &a, bgp.BGP_FSM_ESTABLISHED, nil, nil, nil, slog.Default())
	b := peer.fsm.pConf.ReadCopy()

	assert.True(t, a.Equal(&b))
	b.Config.NeighborAddress = netip.MustParseAddr("10.0.0.2")
	assert.False(t, a.Equal(&b))
	a.Config.NeighborAddress = netip.MustParseAddr("10.0.0.2")
	assert.True(t, a.Equal(&b))

	a.AfiSafis[0].Config.Enabled = false
	peer.fsm.pConf.Update(&a)
	assert.False(t, a.Equal(&b))
	b.AfiSafis[0].Config.Enabled = false
	assert.True(t, a.Equal(&b))
}

// TestRace_UpdatePrefixLimitConfig tests that updatePrefixLimitConfig is race-free
// when called concurrently with capabilitiesFromConfig (which writes to AfiSafis).
//
// The implementation uses pConf.Load() for deep copy protection.
// The race detector detects races at struct element level, not field level,
// so any concurrent access to the same AfiSafi element is a race even if
// reading/writing different fields.
//
// Run with: go test -race -count=1 ./pkg/server/... -run TestRace_UpdatePrefixLimitConfig
func TestRace_UpdatePrefixLimitConfig(t *testing.T) {
	s, _, peerAddrIP := newTestBgpServerWithPeer(t)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	var testPeer *peer
	err := s.mgmtOperation(func() error {
		testPeer = s.neighborMap[peerAddrIP]
		return nil
	}, true)
	if err != nil {
		t.Fatalf("mgmtOperation failed: %v", err)
	}

	if testPeer == nil {
		t.Fatal("Could not get internal peer object")
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Writer goroutine: repeatedly call newWatchEventPeer which triggers
	// capabilitiesFromConfig -> writes to AfiSafis[i].MpGracefulRestart.State.Advertised
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = newWatchEventPeer(testPeer, nil, bgp.BGP_FSM_IDLE, bgp.BGP_FSM_IDLE, apiutil.PEER_EVENT_STATE)
			}
		}
	}()

	// Reader goroutine: repeatedly call updatePrefixLimitConfig.
	// In production, this receives a fresh config from API each time.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				// Get fresh config like production API calls would provide.
				testPeer.fsm.lock.Lock()
				conf := testPeer.fsm.pConf.ReadCopy()
				freshConfig := conf.AfiSafis
				_, _ = testPeer.updatePrefixLimitConfig(&conf, freshConfig)
				testPeer.fsm.pConf.Update(&conf)
				testPeer.fsm.lock.Unlock()
			}
		}
	}()

	// Run for 2 seconds
	time.Sleep(2 * time.Second)
	close(stop)
	wg.Wait()
}

// TestRace_HandleUpdatePrefixLimit tests that the handleUpdate function's
// prefix limit checking loop is race-free when using pConf.Load().
//
// Run with: go test -race -count=1 ./pkg/server/... -run TestRace_HandleUpdatePrefixLimit
func TestRace_HandleUpdatePrefixLimit(t *testing.T) {
	s, _, peerAddrIP := newTestBgpServerWithPeer(t)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	var testPeer *peer
	err := s.mgmtOperation(func() error {
		testPeer = s.neighborMap[peerAddrIP]
		return nil
	}, true)
	if err != nil {
		t.Fatalf("mgmtOperation failed: %v", err)
	}

	if testPeer == nil {
		t.Fatal("Could not get internal peer object")
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Writer goroutine: repeatedly call newWatchEventPeer
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = newWatchEventPeer(testPeer, nil, bgp.BGP_FSM_IDLE, bgp.BGP_FSM_IDLE, apiutil.PEER_EVENT_STATE)
			}
		}
	}()

	// Reader goroutine: simulate reading AfiSafis like handleUpdate does.
	// Uses pConf.Load() for deep copy - should be race-free.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				// This is the pattern used in handleUpdate - deep copy via pConf.Load().
				afiSafis := testPeer.fsm.pConf.ReadOnly().AfiSafis
				// Iterate and read from elements - safe because we have a deep copy
				for _, af := range afiSafis {
					_ = af.State.Family
					_ = af.PrefixLimit.Config
				}
			}
		}
	}()

	// Run for 2 seconds
	time.Sleep(2 * time.Second)
	close(stop)
	wg.Wait()
}

// TestRace_HandleFSMMessageEOR tests that handleFSMMessage's EOR processing
// is race-free when using pConf.Load().
//
// Run with: go test -race -count=1 ./pkg/server/... -run TestRace_HandleFSMMessageEOR
func TestRace_HandleFSMMessageEOR(t *testing.T) {
	s, _, peerAddrIP := newTestBgpServerWithPeer(t)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	var testPeer *peer
	err := s.mgmtOperation(func() error {
		testPeer = s.neighborMap[peerAddrIP]
		return nil
	}, true)
	if err != nil {
		t.Fatalf("mgmtOperation failed: %v", err)
	}

	if testPeer == nil {
		t.Fatal("Could not get internal peer object")
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Writer goroutine: repeatedly call newWatchEventPeer
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = newWatchEventPeer(testPeer, nil, bgp.BGP_FSM_IDLE, bgp.BGP_FSM_IDLE, apiutil.PEER_EVENT_STATE)
			}
		}
	}()

	// Reader goroutine: simulate the EOR processing pattern in handleFSMMessage.
	// Uses pConf.Load() for deep copy - should be race-free.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				// This is the pattern used in handleFSMMessage EOR processing - deep copy.
				peerAfiSafis := testPeer.fsm.pConf.ReadOnly().AfiSafis

				// Iterate over AfiSafis looking for matching families - safe with deep copy
				for i, a := range peerAfiSafis {
					_ = a.State.Family
					_ = i
				}
			}
		}
	}()

	// Run for 2 seconds
	time.Sleep(2 * time.Second)
	close(stop)
	wg.Wait()
}

// newTestBgpServerWithPeer creates a minimal BgpServer with one peer added.
// Returns the server and peer address (both as string for API use and netip.Addr for internal map access).
func newTestBgpServerWithPeer(t *testing.T) (*BgpServer, string, netip.Addr) {
	t.Helper()

	s := NewBgpServer()
	go s.Serve()

	// Start BGP with minimal config: no TCP listener (ListenPort: -1)
	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	if err != nil {
		t.Fatalf("StartBgp failed: %v", err)
	}

	// Add a peer with GracefulRestart enabled to exercise the race condition.
	// The race involves capabilitiesFromConfig writing to:
	//   pConf.Load().AfiSafis[i].MpGracefulRestart.State.Advertised
	peerAddr := "2.2.2.2"
	peer := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: peerAddr,
			PeerAsn:         65002,
		},
		GracefulRestart: &api.GracefulRestart{
			Enabled:     true,
			RestartTime: 120,
		},
		AfiSafis: []*api.AfiSafi{
			{
				Config: &api.AfiSafiConfig{
					Family: &api.Family{
						Afi:  api.Family_AFI_IP,
						Safi: api.Family_SAFI_UNICAST,
					},
				},
				MpGracefulRestart: &api.MpGracefulRestart{
					Config: &api.MpGracefulRestartConfig{
						Enabled: true,
					},
				},
			},
		},
	}

	err = s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: peer})
	if err != nil {
		t.Fatalf("AddPeer failed: %v", err)
	}

	return s, peerAddr, netip.MustParseAddr(peerAddr)
}

// TestRace_SoftResetPeerAndWatch reproduces a data race reported by the Go race detector
// in production, involving concurrent access to peer configuration data.
//
// Race details from production logs:
//
// Write goroutine stack:
//
//	capabilitiesFromConfig()        <- pkg/server/fsm.go:788
//	  (writes pConf.Load().AfiSafis[i].MpGracefulRestart.State.Advertised = true)
//	buildopen()                     <- pkg/server/fsm.go:826
//	newWatchEventPeer()             <- pkg/server/server.go:957
//	broadcastPeerState()            <- pkg/server/server.go:992
//
// The race occurs in toConfig() (server.go:837-870) which:
//  1. Acquires RLock (line 839)
//  2. Copies AfiSafis slice header: peerAfiSafis := peer.fsm.pConf.Load().AfiSafis (line 841)
//  3. Releases RLock (line 843)
//  4. Iterates over peerAfiSafis (line 846): for i, af := range peerAfiSafis
//     This reads from the original slice elements WITHOUT holding any lock!
//  5. Later acquires Lock (line 868) and calls capabilitiesFromConfig
//     which WRITES to AfiSafis[i].MpGracefulRestart.State.Advertised
//
// The bug is that step 4 reads from shared memory after releasing the lock,
// while another goroutine (in step 5) can be writing to the same memory.
//
// To run this test:
//
//	go test -race -count=1 ./pkg/server/... -run TestRace_SoftResetPeerAndWatch
//
// This test was originally added to reproduce a data race in the unfixed code,
// which caused "race detected during execution of test" when run with -race.
// With the race fixed, this test is now expected to PASS (even under -race) and
// serves as a regression test to ensure the race does not reappear.
func TestRace_SoftResetPeerAndWatch(t *testing.T) {
	s, peerAddr, peerAddrIP := newTestBgpServerWithPeer(t)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	// Get the internal peer object for direct access to internal functions
	var testPeer *peer
	err := s.mgmtOperation(func() error {
		testPeer = s.neighborMap[peerAddrIP]
		return nil
	}, true)
	if err != nil {
		t.Fatalf("mgmtOperation failed: %v", err)
	}

	if testPeer == nil {
		t.Fatal("Could not get internal peer object")
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Writer goroutine: repeatedly call newWatchEventPeer
	// This triggers: buildopen -> capabilitiesFromConfig which WRITES to
	// pConf.Load().AfiSafis[i].MpGracefulRestart.State.Advertised while holding Lock
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				// This is the write path from the production stack trace:
				// newWatchEventPeer -> buildopen -> capabilitiesFromConfig
				_ = newWatchEventPeer(testPeer, nil, bgp.BGP_FSM_IDLE, bgp.BGP_FSM_IDLE, apiutil.PEER_EVENT_STATE)
			}
		}
	}()

	// Reader goroutine: repeatedly call toConfig directly
	// toConfig reads from pConf.Load().AfiSafis after releasing RLock (the race!)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				// toConfig: the buggy pattern is:
				// 1. Copy slice header under lock
				// 2. Release lock
				// 3. Iterate over slice elements WITHOUT lock (race!)
				_ = s.toConfig(testPeer, true)
			}
		}
	}()

	// Additional goroutine: trigger peer state changes via API
	// This exercises the broadcastPeerState -> newWatchEventPeer path
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx := context.Background()
		for {
			select {
			case <-stop:
				return
			default:
				_ = s.DisablePeer(ctx, &api.DisablePeerRequest{Address: peerAddr})
				_ = s.EnablePeer(ctx, &api.EnablePeerRequest{Address: peerAddr})
			}
		}
	}()

	// Additional goroutine: ListPeer API which calls toConfig internally
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx := context.Background()
		for {
			select {
			case <-stop:
				return
			default:
				_ = s.ListPeer(ctx, &api.ListPeerRequest{
					Address:          peerAddr,
					EnableAdvertised: true, // Triggers capabilitiesFromConfig call
				}, func(*api.Peer) {})
			}
		}
	}()

	// Let the goroutines run to trigger the race
	time.Sleep(2 * time.Second)

	close(stop)
	wg.Wait()
}

// TestAtomicMessageCounters verifies that atomic message counters exposed via toConfig
// accurately match the messages processed through bgpMessageStateUpdate.
func TestAtomicMessageCounters(t *testing.T) {
	assert := assert.New(t)

	m := NewMockConnection()
	p, h := makePeerAndHandler(m)
	t.Cleanup(func() { cleanPeerAndHandler(p, h) })

	// Create a mock server to use toConfig
	s := NewBgpServer()

	// Simulate processing various BGP messages
	testCases := []struct {
		msgType uint8
		isIn    bool
		count   int
	}{
		{bgp.BGP_MSG_OPEN, true, 1},
		{bgp.BGP_MSG_OPEN, false, 1},
		{bgp.BGP_MSG_KEEPALIVE, true, 5},
		{bgp.BGP_MSG_KEEPALIVE, false, 5},
		{bgp.BGP_MSG_UPDATE, true, 10},
		{bgp.BGP_MSG_UPDATE, false, 8},
		{bgp.BGP_MSG_NOTIFICATION, true, 2},
		{bgp.BGP_MSG_NOTIFICATION, false, 1},
		{bgp.BGP_MSG_ROUTE_REFRESH, true, 3},
		{bgp.BGP_MSG_ROUTE_REFRESH, false, 2},
	}

	// Track expected counts
	expectedReceived := make(map[uint8]uint64)
	expectedSent := make(map[uint8]uint64)
	var expectedReceivedTotal, expectedSentTotal uint64

	// Process messages and track expectations
	for _, tc := range testCases {
		for range tc.count {
			p.fsm.bgpMessageStateUpdate(tc.msgType, tc.isIn)
			if tc.isIn {
				expectedReceived[tc.msgType]++
				expectedReceivedTotal++
			} else {
				expectedSent[tc.msgType]++
				expectedSentTotal++
			}
		}
	}

	// Get config using toConfig
	config := s.toConfig(p, false)

	// Verify received message counts match
	assert.Equal(expectedReceivedTotal, config.State.Messages.Received.Total,
		"Received total count should match")
	assert.Equal(expectedReceived[bgp.BGP_MSG_OPEN], config.State.Messages.Received.Open,
		"Received OPEN count should match")
	assert.Equal(expectedReceived[bgp.BGP_MSG_KEEPALIVE], config.State.Messages.Received.Keepalive,
		"Received KEEPALIVE count should match")
	assert.Equal(expectedReceived[bgp.BGP_MSG_UPDATE], config.State.Messages.Received.Update,
		"Received UPDATE count should match")
	assert.Equal(expectedReceived[bgp.BGP_MSG_NOTIFICATION], config.State.Messages.Received.Notification,
		"Received NOTIFICATION count should match")
	assert.Equal(expectedReceived[bgp.BGP_MSG_ROUTE_REFRESH], config.State.Messages.Received.Refresh,
		"Received ROUTE_REFRESH count should match")

	// Verify sent message counts match
	assert.Equal(expectedSentTotal, config.State.Messages.Sent.Total,
		"Sent total count should match")
	assert.Equal(expectedSent[bgp.BGP_MSG_OPEN], config.State.Messages.Sent.Open,
		"Sent OPEN count should match")
	assert.Equal(expectedSent[bgp.BGP_MSG_KEEPALIVE], config.State.Messages.Sent.Keepalive,
		"Sent KEEPALIVE count should match")
	assert.Equal(expectedSent[bgp.BGP_MSG_UPDATE], config.State.Messages.Sent.Update,
		"Sent UPDATE count should match")
	assert.Equal(expectedSent[bgp.BGP_MSG_NOTIFICATION], config.State.Messages.Sent.Notification,
		"Sent NOTIFICATION count should match")
	assert.Equal(expectedSent[bgp.BGP_MSG_ROUTE_REFRESH], config.State.Messages.Sent.Refresh,
		"Sent ROUTE_REFRESH count should match")
}

// TestAtomicTimerState verifies that UpdateRecvTime is correctly updated when
// UPDATE messages are received and exposed via toConfig.
func TestAtomicTimerState(t *testing.T) {
	assert := assert.New(t)

	m := NewMockConnection()
	p, h := makePeerAndHandler(m)
	t.Cleanup(func() { cleanPeerAndHandler(p, h) })

	s := NewBgpServer()

	// Initially, UpdateRecvTime should be 0
	config := s.toConfig(p, false)
	assert.Equal(int64(0), config.Timers.State.UpdateRecvTime,
		"UpdateRecvTime should be 0 initially")

	// Record time before sending UPDATE
	timeBefore := time.Now().Unix()

	// Process an UPDATE message (received)
	p.fsm.bgpMessageStateUpdate(bgp.BGP_MSG_UPDATE, true)

	// Record time after sending UPDATE
	timeAfter := time.Now().Unix()

	// Get config and verify UpdateRecvTime is set
	config = s.toConfig(p, false)
	updateTime := config.Timers.State.UpdateRecvTime

	assert.True(updateTime >= timeBefore && updateTime <= timeAfter,
		"UpdateRecvTime should be set to current time when UPDATE received")

	// Sleep briefly to ensure time difference
	time.Sleep(10 * time.Millisecond)

	// Process another UPDATE message
	timeBeforeSecond := time.Now().Unix()
	p.fsm.bgpMessageStateUpdate(bgp.BGP_MSG_UPDATE, true)
	timeAfterSecond := time.Now().Unix()

	// Verify UpdateRecvTime is updated
	config = s.toConfig(p, false)
	updateTimeSecond := config.Timers.State.UpdateRecvTime

	assert.True(updateTimeSecond >= timeBeforeSecond && updateTimeSecond <= timeAfterSecond,
		"UpdateRecvTime should be updated on subsequent UPDATE")
	assert.True(updateTimeSecond >= updateTime,
		"UpdateRecvTime should not go backwards")

	// Verify that sending UPDATE (not receiving) does NOT update UpdateRecvTime
	p.fsm.bgpMessageStateUpdate(bgp.BGP_MSG_UPDATE, false)
	config = s.toConfig(p, false)
	assert.Equal(updateTimeSecond, config.Timers.State.UpdateRecvTime,
		"UpdateRecvTime should not change when UPDATE is sent (only when received)")

	// Verify other message types do NOT update UpdateRecvTime
	p.fsm.bgpMessageStateUpdate(bgp.BGP_MSG_KEEPALIVE, true)
	config = s.toConfig(p, false)
	assert.Equal(updateTimeSecond, config.Timers.State.UpdateRecvTime,
		"UpdateRecvTime should not change for non-UPDATE messages")
}

// TestAtomicCounterReset verifies that message counters and timer state
// are correctly reset to zero when bgpMessageResetStats is called.
func TestAtomicCounterReset(t *testing.T) {
	assert := assert.New(t)

	m := NewMockConnection()
	p, h := makePeerAndHandler(m)
	t.Cleanup(func() { cleanPeerAndHandler(p, h) })

	s := NewBgpServer()

	// Process various messages to populate counters
	p.fsm.bgpMessageStateUpdate(bgp.BGP_MSG_OPEN, true)
	p.fsm.bgpMessageStateUpdate(bgp.BGP_MSG_OPEN, false)
	p.fsm.bgpMessageStateUpdate(bgp.BGP_MSG_KEEPALIVE, true)
	p.fsm.bgpMessageStateUpdate(bgp.BGP_MSG_KEEPALIVE, false)
	p.fsm.bgpMessageStateUpdate(bgp.BGP_MSG_UPDATE, true)
	p.fsm.bgpMessageStateUpdate(bgp.BGP_MSG_UPDATE, false)
	p.fsm.bgpMessageStateUpdate(bgp.BGP_MSG_NOTIFICATION, true)
	p.fsm.bgpMessageStateUpdate(bgp.BGP_MSG_ROUTE_REFRESH, true)

	// Verify counters are non-zero
	config := s.toConfig(p, false)
	assert.Greater(config.State.Messages.Received.Total, uint64(0),
		"Received total should be non-zero before reset")
	assert.Greater(config.State.Messages.Sent.Total, uint64(0),
		"Sent total should be non-zero before reset")
	assert.Greater(config.Timers.State.UpdateRecvTime, int64(0),
		"UpdateRecvTime should be non-zero before reset")

	// Reset stats
	p.fsm.bgpMessageResetStats()

	// Verify all counters are zero after reset
	config = s.toConfig(p, false)

	// Check received counters
	assert.Equal(uint64(0), config.State.Messages.Received.Total,
		"Received total should be 0 after reset")
	assert.Equal(uint64(0), config.State.Messages.Received.Open,
		"Received OPEN should be 0 after reset")
	assert.Equal(uint64(0), config.State.Messages.Received.Keepalive,
		"Received KEEPALIVE should be 0 after reset")
	assert.Equal(uint64(0), config.State.Messages.Received.Update,
		"Received UPDATE should be 0 after reset")
	assert.Equal(uint64(0), config.State.Messages.Received.Notification,
		"Received NOTIFICATION should be 0 after reset")
	assert.Equal(uint64(0), config.State.Messages.Received.Refresh,
		"Received REFRESH should be 0 after reset")
	assert.Equal(uint32(0), config.State.Messages.Received.WithdrawUpdate,
		"Received WithdrawUpdate should be 0 after reset")
	assert.Equal(uint32(0), config.State.Messages.Received.WithdrawPrefix,
		"Received WithdrawPrefix should be 0 after reset")
	assert.Equal(uint64(0), config.State.Messages.Received.Discarded,
		"Received Discarded should be 0 after reset")

	// Check sent counters
	assert.Equal(uint64(0), config.State.Messages.Sent.Total,
		"Sent total should be 0 after reset")
	assert.Equal(uint64(0), config.State.Messages.Sent.Open,
		"Sent OPEN should be 0 after reset")
	assert.Equal(uint64(0), config.State.Messages.Sent.Keepalive,
		"Sent KEEPALIVE should be 0 after reset")
	assert.Equal(uint64(0), config.State.Messages.Sent.Update,
		"Sent UPDATE should be 0 after reset")
	assert.Equal(uint64(0), config.State.Messages.Sent.Notification,
		"Sent NOTIFICATION should be 0 after reset")
	assert.Equal(uint64(0), config.State.Messages.Sent.Refresh,
		"Sent REFRESH should be 0 after reset")
	assert.Equal(uint32(0), config.State.Messages.Sent.WithdrawUpdate,
		"Sent WithdrawUpdate should be 0 after reset")
	assert.Equal(uint32(0), config.State.Messages.Sent.WithdrawPrefix,
		"Sent WithdrawPrefix should be 0 after reset")
	assert.Equal(uint64(0), config.State.Messages.Sent.Discarded,
		"Sent Discarded should be 0 after reset")

	// Check timer state
	assert.Equal(int64(0), config.Timers.State.UpdateRecvTime,
		"UpdateRecvTime should be 0 after reset")
}

// TestAtomicCountersConcurrentAccess verifies that atomic counters can be
// safely updated and read concurrently from multiple goroutines.
func TestAtomicCountersConcurrentAccess(t *testing.T) {
	assert := assert.New(t)

	m := NewMockConnection()
	p, h := makePeerAndHandler(m)
	t.Cleanup(func() { cleanPeerAndHandler(p, h) })

	s := NewBgpServer()

	const numGoroutines = 10
	const updatesPerGoroutine = 100

	var wg sync.WaitGroup

	// Launch multiple goroutines to update counters concurrently
	for range numGoroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range updatesPerGoroutine {
				p.fsm.bgpMessageStateUpdate(bgp.BGP_MSG_UPDATE, true)
				p.fsm.bgpMessageStateUpdate(bgp.BGP_MSG_KEEPALIVE, false)
			}
		}()
	}

	// Launch goroutines to read counters concurrently via toConfig
	readDone := make(chan struct{})
	var readWg sync.WaitGroup
	for range numGoroutines {
		readWg.Add(1)
		go func() {
			defer readWg.Done()
			for {
				select {
				case <-readDone:
					return
				default:
					// Read config without causing panic or race
					_ = s.toConfig(p, false)
				}
			}
		}()
	}

	// Wait for all writers to complete
	wg.Wait()
	close(readDone)
	readWg.Wait()

	// Verify final counts
	config := s.toConfig(p, false)
	expectedUpdates := uint64(numGoroutines * updatesPerGoroutine)
	expectedKeepalives := uint64(numGoroutines * updatesPerGoroutine)

	assert.Equal(expectedUpdates, config.State.Messages.Received.Update,
		"Concurrent UPDATE counter updates should be accurate")
	assert.Equal(expectedKeepalives, config.State.Messages.Sent.Keepalive,
		"Concurrent KEEPALIVE counter updates should be accurate")
	assert.Equal(expectedUpdates+expectedKeepalives, config.State.Messages.Received.Total+config.State.Messages.Sent.Total,
		"Total message count should be sum of all messages")
}

// TestRecvMessageWithError_MalformedNextHop verifies that recvMessageWithError
// handles a malformed NEXT_HOP attribute (length < 4) without panicking.
// This is a regression test for https://github.com/osrg/gobgp/issues/3305.
func TestRecvMessageWithError_MalformedNextHop(t *testing.T) {
	// Malformed BGP UPDATE from issue #3305:
	// NEXT_HOP attribute with length 2 instead of 4.
	raw := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // marker
		0x00, 0x28, // length: 40
		0x02,       // type: UPDATE
		0x00, 0x00, // withdrawn routes length: 0
		0x00, 0x0d, // total path attribute length: 13
		0x40, 0x01, 0x01, 0x02, // ORIGIN: INCOMPLETE
		0x40, 0x02, 0x00, // AS_PATH: empty
		0x40, 0x03, 0x02, 0x01, 0x02, // NEXT_HOP: length 2 (invalid, should be 4)
		0x01, 0x18, 0xc0, 0xa8, 0x01, // NLRI: 192.168.1.0/24 (truncated but enough to trigger the bug)
	}

	t.Run("TreatAsWithdraw", func(t *testing.T) {
		assert := assert.New(t)

		m := NewMockConnection()
		_, h := makePeerAndHandler(m)
		t.Cleanup(func() {
			h.outgoing.Close()
			h.fsm.outgoingCh.Close()
			h.fsm.conn.Close()
		})

		// Enable RFC 7606 revised error handling (treat-as-withdraw).
		// Without this, malformed attributes cause SESSION_RESET which is
		// handled inside recvMessageWithError. The panic only occurs when
		// treat-as-withdraw is enabled and the malformed attribute survives
		// into ValidateUpdateMsg.
		h.fsm.isTreatAsWithdraw = true

		go m.remote.Write(raw)

		stateReasonCh := make(chan fsmStateReason, 2)
		fmsg, err := h.recvMessageWithError(m.Conn, stateReasonCh)

		assert.NoError(err)
		assert.NotNil(fmsg)
		assert.Equal(bgp.ERROR_HANDLING_TREAT_AS_WITHDRAW, fmsg.handling)
	})

	t.Run("SessionReset", func(t *testing.T) {
		assert := assert.New(t)

		m := NewMockConnection()
		_, h := makePeerAndHandler(m)
		t.Cleanup(func() {
			h.outgoing.Close()
			h.fsm.outgoingCh.Close()
			h.fsm.conn.Close()
		})

		// Without RFC 7606, the error should cause a session reset.
		h.fsm.isTreatAsWithdraw = false

		go m.remote.Write(raw)

		stateReasonCh := make(chan fsmStateReason, 2)
		fmsg, err := h.recvMessageWithError(m.Conn, stateReasonCh)

		assert.Error(err)
		assert.NotNil(fmsg)
		assert.Equal(bgp.ERROR_HANDLING_SESSION_RESET, fmsg.handling)
	})
}

// TestRecvMessageWithError_UnknownMessageType verifies that recvMessageWithError
// handles an unknown BGP message type without panicking on nil dereference.
// This is a regression test for https://github.com/osrg/gobgp/issues/3325.
func TestRecvMessageWithError_UnknownMessageType(t *testing.T) {
	assert := assert.New(t)

	m := NewMockConnection()
	_, h := makePeerAndHandler(m)
	t.Cleanup(func() {
		h.outgoing.Close()
		h.fsm.outgoingCh.Close()
		h.fsm.conn.Close()
	})

	// BGP message with unknown type 0xFF.
	// ParseBGPBody returns (nil, error) for unknown types.
	raw := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // marker
		0x00, 0x13, // length: 19 (header only, no body)
		0xff, // type: unknown
	}

	go m.remote.Write(raw)

	stateReasonCh := make(chan fsmStateReason, 2)
	fmsg, err := h.recvMessageWithError(m.Conn, stateReasonCh)

	assert.Error(err)
	assert.NotNil(fmsg)
	assert.Equal(bgp.ERROR_HANDLING_SESSION_RESET, fmsg.handling)
}

// TestRecvMessageWithError_TooLongMessage checks the NOTIFICATION that
// recvMessageWithError builds for a message longer than the peer may send.
// RFC 4271 section 6.1 requires the Data field to carry the erroneous Length
// field; it used to be empty.
//
// The cap is per message type once RFC 8654 extended messages are negotiated:
// section 6 keeps OPEN and KEEPALIVE at 4096 while the rest may reach 65535.
func TestRecvMessageWithError_TooLongMessage(t *testing.T) {
	tests := []struct {
		name            string
		extendedMessage bool
		msgType         uint8
		declaredLen     uint16
		wantData        []byte
	}{
		{
			name:        "over the standard cap",
			msgType:     bgp.BGP_MSG_UPDATE,
			declaredLen: bgp.BGP_MAX_MESSAGE_LENGTH + 1,
			wantData:    []byte{0x10, 0x01},
		},
		{
			name:            "extended message keeps KEEPALIVE at the standard cap",
			extendedMessage: true,
			msgType:         bgp.BGP_MSG_KEEPALIVE,
			declaredLen:     5000,
			wantData:        []byte{0x13, 0x88},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)

			m := NewMockConnection()
			p, h := makePeerAndHandler(m)
			t.Cleanup(func() { cleanPeerAndHandler(p, h) })
			h.fsm.extendedMessage.Store(tt.extendedMessage)

			raw := make([]byte, bgp.BGP_HEADER_LENGTH)
			for i := range raw[:16] {
				raw[i] = 0xff
			}
			binary.BigEndian.PutUint16(raw[16:18], tt.declaredLen)
			raw[18] = tt.msgType

			go m.remote.Write(raw)

			stateReasonCh := make(chan fsmStateReason, 2)
			fmsg, err := h.recvMessageWithError(m.Conn, stateReasonCh)
			assert.Error(err)
			assert.NotNil(fmsg)

			me, ok := fmsg.MsgData.(*bgp.MessageError)
			assert.True(ok)
			assert.Equal(uint8(bgp.BGP_ERROR_MESSAGE_HEADER_ERROR), me.TypeCode)
			assert.Equal(uint8(bgp.BGP_ERROR_SUB_BAD_MESSAGE_LENGTH), me.SubTypeCode)
			assert.Equal(tt.wantData, me.Data)
		})
	}
}

// TestBMPStatsUpdate verifies that BMP stats are correctly updated via
// atomic operations and exposed via toConfig.
func TestBMPStatsUpdate(t *testing.T) {
	assert := assert.New(t)

	m := NewMockConnection()
	p, h := makePeerAndHandler(m)
	t.Cleanup(func() { cleanPeerAndHandler(p, h) })

	s := NewBgpServer()

	// Update BMP withdraw stats
	p.fsm.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_UPDATE, 5)
	p.fsm.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_PREFIX, 10)

	// Get config and verify BMP stats
	config := s.toConfig(p, false)
	assert.Equal(uint32(5), config.State.Messages.Received.WithdrawUpdate,
		"WithdrawUpdate count should match BMP stats")
	assert.Equal(uint32(10), config.State.Messages.Received.WithdrawPrefix,
		"WithdrawPrefix count should match BMP stats")

	// Update again with different increments
	p.fsm.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_UPDATE, 3)
	p.fsm.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_PREFIX, 7)

	config = s.toConfig(p, false)
	assert.Equal(uint32(8), config.State.Messages.Received.WithdrawUpdate,
		"WithdrawUpdate should accumulate correctly")
	assert.Equal(uint32(17), config.State.Messages.Received.WithdrawPrefix,
		"WithdrawPrefix should accumulate correctly")

	// Verify reset clears BMP stats
	p.fsm.bgpMessageResetStats()
	config = s.toConfig(p, false)
	assert.Equal(uint32(0), config.State.Messages.Received.WithdrawUpdate,
		"WithdrawUpdate should be 0 after reset")
	assert.Equal(uint32(0), config.State.Messages.Received.WithdrawPrefix,
		"WithdrawPrefix should be 0 after reset")
}

// makePath creates a table.Path with the given IPv4 prefix, nexthop, and
// community.  All three attributes influence whether paths can be packed into
// the same UPDATE by CreateUpdateMsgFromPaths.
func makePath(t testing.TB, prefix string, nexthop string, community uint32) *table.Path {
	t.Helper()
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	if err != nil {
		t.Fatal(err)
	}
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr(nexthop))
	if err != nil {
		t.Fatal(err)
	}
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
			bgp.NewAs4PathParam(2, []uint32{65001}),
		}),
		nh,
	}
	if community != 0 {
		attrs = append(attrs, bgp.NewPathAttributeCommunities([]uint32{community}))
	}
	return table.NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
}

// parseBGPUpdates deserializes raw bytes captured by MockConnection into
// individual BGP messages.
func parseBGPUpdates(t *testing.T, raw [][]byte) []*bgp.BGPMessage {
	t.Helper()
	msgs := make([]*bgp.BGPMessage, 0, len(raw))
	for _, buf := range raw {
		for len(buf) > 0 {
			msg, err := bgp.ParseBGPMessage(buf)
			if err != nil {
				t.Fatalf("ParseBGPMessage: %v (buflen=%d)", err, len(buf))
			}
			msgs = append(msgs, msg)
			n := int(msg.Header.Len)
			if n <= 0 || n > len(buf) {
				t.Fatalf("invalid message length %d (buflen=%d)", n, len(buf))
			}
			buf = buf[n:]
		}
	}
	return msgs
}

func countNLRIs(msgs []*bgp.BGPMessage) int {
	total := 0
	for _, msg := range msgs {
		if msg.Header.Type != bgp.BGP_MSG_UPDATE {
			continue
		}
		u := msg.Body.(*bgp.BGPUpdate)
		total += len(u.NLRI)
		for _, attr := range u.PathAttributes {
			if mp, ok := attr.(*bgp.PathAttributeMpReachNLRI); ok {
				total += len(mp.Value)
			}
			if mp, ok := attr.(*bgp.PathAttributeMpUnreachNLRI); ok {
				total += len(mp.Value)
			}
		}
	}
	return total
}

// TestSendMessageloop_SingleMessage verifies that a single queued message
// passes through sendMessageloop without artificial delay.
func TestSendMessageloop_SingleMessage(t *testing.T) {
	assert := assert.New(t)

	m := NewMockConnection()
	_, h := makePeerAndHandler(m)
	t.Cleanup(func() { h.outgoing.Close(); m.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	stateReasonCh := make(chan fsmStateReason, 3)
	wg := &sync.WaitGroup{}
	wg.Add(1)

	go h.sendMessageloop(ctx, m, stateReasonCh, wg)

	// Enqueue a single path.
	path := makePath(t, "10.0.0.0/24", "192.168.1.1", 0)
	h.outgoing.In() <- &fsmOutgoingMsg{Paths: []*table.Path{path}}

	// Wait for the message to arrive at the mock connection.
	select {
	case <-m.bufReady.C:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for message")
	}

	cancel()
	wg.Wait()

	msgs := parseBGPUpdates(t, m.GetSentMessages())
	updates := 0
	nlris := 0
	for _, msg := range msgs {
		if msg.Header.Type == bgp.BGP_MSG_UPDATE {
			updates++
			nlris += len(msg.Body.(*bgp.BGPUpdate).NLRI)
		}
	}
	assert.Equal(1, updates, "single path should produce exactly one UPDATE")
	assert.Equal(1, nlris, "single path should carry exactly one NLRI")
}

// TestSendMessageloop_CoalesceMultipleMessages verifies that multiple queued
// fsmOutgoingMsg are all delivered -- every NLRI injected into the outgoing
// channel appears in the wire output. The coalescing drain is opportunistic
// (it depends on goroutine scheduling), so this test validates correctness
// rather than asserting a specific UPDATE count.
func TestSendMessageloop_CoalesceMultipleMessages(t *testing.T) {
	assert := assert.New(t)

	m := NewMockConnection()
	_, h := makePeerAndHandler(m)
	t.Cleanup(func() { h.outgoing.Close(); m.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	stateReasonCh := make(chan fsmStateReason, 3)
	wg := &sync.WaitGroup{}
	wg.Add(1)

	const numPaths = 200
	for i := range numPaths {
		path := makePath(t, fmt.Sprintf("10.%d.%d.0/24", i/256, i%256), "192.168.1.1", 0)
		h.outgoing.In() <- &fsmOutgoingMsg{Paths: []*table.Path{path}}
	}

	go h.sendMessageloop(ctx, m, stateReasonCh, wg)

	assert.Eventually(func() bool {
		return countNLRIs(parseBGPUpdates(t, m.GetSentMessages())) >= numPaths
	}, 5*time.Second, 10*time.Millisecond, "timed out waiting for all NLRIs")

	cancel()
	wg.Wait()

	msgs := parseBGPUpdates(t, m.GetSentMessages())
	nlris := countNLRIs(msgs)
	updates := 0
	for _, msg := range msgs {
		if msg.Header.Type == bgp.BGP_MSG_UPDATE {
			updates++
		}
	}

	assert.Equal(numPaths, nlris, "all NLRIs must be present")
	t.Logf("coalesced %d paths into %d UPDATEs (%.1fx)", numPaths, updates, float64(numPaths)/float64(updates))
}

// TestSendMessageloop_CoalesceMultipleAttributeGroups verifies that paths
// with different attribute sets are correctly separated into different
// UPDATEs, while all NLRIs are preserved.
func TestSendMessageloop_CoalesceMultipleAttributeGroups(t *testing.T) {
	assert := assert.New(t)

	m := NewMockConnection()
	_, h := makePeerAndHandler(m)
	t.Cleanup(func() { h.outgoing.Close(); m.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	stateReasonCh := make(chan fsmStateReason, 3)
	wg := &sync.WaitGroup{}
	wg.Add(1)

	// Create 3 groups of 30 paths, each with a different community.
	const groupSize = 30
	const numGroups = 3
	for g := range numGroups {
		for i := range groupSize {
			prefix := fmt.Sprintf("10.%d.%d.0/24", g, i)
			community := uint32((g + 1) * 1000)
			path := makePath(t, prefix, "192.168.1.1", community)
			h.outgoing.In() <- &fsmOutgoingMsg{Paths: []*table.Path{path}}
		}
	}

	go h.sendMessageloop(ctx, m, stateReasonCh, wg)

	total := groupSize * numGroups
	assert.Eventually(func() bool {
		return countNLRIs(parseBGPUpdates(t, m.GetSentMessages())) >= total
	}, 5*time.Second, 10*time.Millisecond, "timed out waiting for all NLRIs")

	cancel()
	wg.Wait()

	msgs := parseBGPUpdates(t, m.GetSentMessages())
	nlris := countNLRIs(msgs)
	updates := 0
	for _, msg := range msgs {
		if msg.Header.Type == bgp.BGP_MSG_UPDATE {
			updates++
		}
	}

	assert.Equal(total, nlris, "all NLRIs must be present")
	t.Logf("coalesced %d paths (%d groups) into %d UPDATEs", total, numGroups, updates)
}

// TestSendMessageloop_KillSignal verifies that a non-path message causes
// sendMessageloop to exit promptly. This test checks timely termination,
// not preservation or forwarding of the non-path payload.
func TestSendMessageloop_KillSignal(t *testing.T) {
	m := NewMockConnection()
	_, h := makePeerAndHandler(m)
	t.Cleanup(func() { h.outgoing.Close(); m.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stateReasonCh := make(chan fsmStateReason, 3)
	wg := &sync.WaitGroup{}
	wg.Add(1)

	// Enqueue some paths followed by a non-path message (fsmStateReason).
	for i := range 5 {
		path := makePath(t, fmt.Sprintf("10.0.%d.0/24", i), "192.168.1.1", 0)
		h.outgoing.In() <- &fsmOutgoingMsg{Paths: []*table.Path{path}}
	}
	// A non-fsmOutgoingMsg acts as a kill signal and should cause the loop
	// to return promptly.
	h.outgoing.In() <- *newfsmStateReason(fsmAdminDown, nil, nil)

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.sendMessageloop(ctx, m, stateReasonCh, wg)
	}()

	// sendMessageloop should return (not hang) when it encounters the
	// non-path message during drain or on the next outer select iteration.
	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("sendMessageloop did not exit after non-path message")
	}
}

// TestRace_NewWatchEventPeerRecvOpen tests that newWatchEventPeer is race-free
// when called concurrently with an FSM connection transition, which writes
// fsm.recvOpen under fsm.lock.
//
// newWatchEventPeer reads fsm.recvOpen after releasing fsm.lock, so the read is
// unsynchronised with respect to those writes. WatchEvent reaches it for every
// peer in neighborMap when a watcher registers, and broadcastPeerState reaches
// it on each state transition.
//
// Run with: go test -race -count=1 ./pkg/server/... -run TestRace_NewWatchEventPeerRecvOpen
func TestRace_NewWatchEventPeerRecvOpen(t *testing.T) {
	s, _, peerAddrIP := newTestBgpServerWithPeer(t)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	var testPeer *peer
	err := s.mgmtOperation(func() error {
		testPeer = s.neighborMap[peerAddrIP]
		return nil
	}, true)
	if err != nil {
		t.Fatalf("mgmtOperation failed: %v", err)
	}

	if testPeer == nil {
		t.Fatal("Could not get internal peer object")
	}

	open, err := bgp.NewBGPOpenMessage(65002, 90, netip.MustParseAddr("2.2.2.2"), nil)
	if err != nil {
		t.Fatalf("NewBGPOpenMessage failed: %v", err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Writer goroutine: assign fsm.recvOpen under fsm.lock, as the FSM does when
	// a connection reaches OPENCONFIRM.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				testPeer.fsm.lock.Lock()
				testPeer.fsm.recvOpen = open
				testPeer.fsm.lock.Unlock()
			}
		}
	}()

	// Reader goroutine: build watch events, which reads fsm.recvOpen.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = newWatchEventPeer(testPeer, nil, bgp.BGP_FSM_IDLE, bgp.BGP_FSM_IDLE, apiutil.PEER_EVENT_STATE)
			}
		}
	}()

	time.Sleep(2 * time.Second)
	close(stop)
	wg.Wait()
}

// buildUpdate returns a raw UPDATE message with no withdrawn routes and the
// given path attributes and NLRI.
func buildUpdate(attrs, nlri []byte) []byte {
	body := []byte{0x00, 0x00, byte(len(attrs) >> 8), byte(len(attrs))}
	body = append(append(body, attrs...), nlri...)
	l := bgp.BGP_HEADER_LENGTH + len(body)
	msg := make([]byte, 16, l) // marker
	for i := range msg {
		msg[i] = 0xff
	}
	msg = append(msg, byte(l>>8), byte(l), bgp.BGP_MSG_UPDATE)
	return append(msg, body...)
}

// recvUpdate feeds raw to recvMessageloop on a treat-as-withdraw IPv4 unicast
// session and returns either the message passed to the callback or the
// NOTIFICATION that was sent.
func recvUpdate(t *testing.T, raw []byte) (*fsmMsg, *bgp.BGPMessage) {
	t.Helper()
	m := NewMockConnection()
	p, h := makePeerAndHandler(m)
	t.Cleanup(func() { cleanPeerAndHandler(p, h) })

	h.fsm.isTreatAsWithdraw = true
	h.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_NONE})

	received := make(chan *fsmMsg, 1)
	h.callback = func(msg *fsmMsg) { received <- msg }

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go h.recvMessageloop(ctx, m.Conn, make(chan struct{}, 2), make(chan fsmStateReason, 3), &atomic.Bool{}, wg)
	go m.remote.Write(raw)

	select {
	case fmsg := <-received:
		return fmsg, nil
	case n := <-h.fsm.notification:
		return nil, n
	case <-time.After(5 * time.Second):
		t.Fatal("neither a callback nor a notification within 5s")
		return nil, nil
	}
}

// TestRecvMessageloop_ValidatesUpdateAfterAttributeDiscard verifies that an
// UPDATE whose decoder already discarded one malformed attribute still goes
// through ValidateUpdateMsg, so the semantic checks on the remaining
// attributes are not skipped.
func TestRecvMessageloop_ValidatesUpdateAfterAttributeDiscard(t *testing.T) {
	// UPDATE for 192.168.1.0/24 carrying an ATOMIC_AGGREGATE with a one
	// byte value. RFC 7606 Section 7.6 discards that attribute, which is
	// enough for the decoder to report ERROR_HANDLING_ATTRIBUTE_DISCARD.
	// The tail is filled in by the subtests.
	head := []byte{
		0x40, 0x01, 0x01, 0x00, // ORIGIN: IGP
		0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xe9, // AS_PATH: 65001
		0x40, 0x03, 0x04, 0x0a, 0x00, 0x00, 0x01, // NEXT_HOP: 10.0.0.1
		0x40, 0x06, 0x01, 0x00, // ATOMIC_AGGREGATE with a value: discarded
	}
	nlri := []byte{0x18, 0xc0, 0xa8, 0x01} // 192.168.1.0/24

	build := func(extra []byte) []byte {
		return buildUpdate(append(append([]byte{}, head...), extra...), nlri)
	}

	t.Run("InvalidOrigin", func(t *testing.T) {
		assert := assert.New(t)

		raw := build(nil)
		raw[bgp.BGP_HEADER_LENGTH+7] = 0x09 // ORIGIN value out of range

		fmsg, n := recvUpdate(t, raw)
		assert.Nil(n)
		if assert.NotNil(fmsg) {
			assert.Equal(bgp.ERROR_HANDLING_TREAT_AS_WITHDRAW, fmsg.handling)
		}
	})

	t.Run("UnrecognizedWellKnownAttribute", func(t *testing.T) {
		assert := assert.New(t)

		// type 200 with only the transitive flag set is a well-known
		// attribute this implementation does not recognize.
		raw := build([]byte{0x40, 0xc8, 0x01, 0x00})

		fmsg, n := recvUpdate(t, raw)
		assert.Nil(n)
		if assert.NotNil(fmsg) {
			assert.Equal(bgp.ERROR_HANDLING_TREAT_AS_WITHDRAW, fmsg.handling)
		}
	})
}

// TestRecvMessageloop_RepeatedMpUnreachAfterTreatAsWithdraw verifies that a
// repeated MP_UNREACH_NLRI resets the session even when another attribute
// already made the UPDATE treat-as-withdraw (RFC 7606 Section 3 g).
func TestRecvMessageloop_RepeatedMpUnreachAfterTreatAsWithdraw(t *testing.T) {
	assert := assert.New(t)

	raw := buildUpdate([]byte{
		0x40, 0x01, 0x02, 0x00, 0x00, // ORIGIN with a bad length: treat-as-withdraw
		0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xe9, // AS_PATH: 65001
		0x80, 0x0f, 0x07, 0x00, 0x01, 0x01, 0x18, 0x0a, 0x01, 0x01, // MP_UNREACH: 10.1.1.0/24
		0x80, 0x0f, 0x07, 0x00, 0x01, 0x01, 0x18, 0x0a, 0x02, 0x02, // MP_UNREACH: 10.2.2.0/24
	}, nil)

	fmsg, n := recvUpdate(t, raw)
	assert.Nil(fmsg)
	if assert.NotNil(n) {
		body := n.Body.(*bgp.BGPNotification)
		assert.Equal(uint8(bgp.BGP_ERROR_UPDATE_MESSAGE_ERROR), body.ErrorCode)
		assert.Equal(uint8(bgp.BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST), body.ErrorSubcode)
	}
}

// The Extended Nexthop capability lists only the IPv4 families of RFC 8950
// Section 4, not L2VPN EVPN or the IPv6 families.
func TestCapabilitiesExtendedNexthopIPv4Only(t *testing.T) {
	var afs []oc.AfiSafi
	for _, f := range []bgp.Family{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC, bgp.RF_EVPN, bgp.RF_IPv4_MC, bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN, bgp.RF_IPv4_MPLS, bgp.RF_IPv4_VPN_MC, bgp.RF_FS_IPv4_UC} {
		afs = append(afs, oc.AfiSafi{State: oc.AfiSafiState{Family: f}})
	}
	var got []bgp.Family
	for _, c := range capabilitiesFromConfig(&oc.Neighbor{AfiSafis: afs}) {
		if e, ok := c.(*bgp.CapExtendedNexthop); ok {
			for _, tu := range e.Tuples {
				require.Equal(t, uint16(bgp.AFI_IP6), tu.NexthopAFI)
				got = append(got, bgp.NewFamily(tu.NLRIAFI, uint8(tu.NLRISAFI)))
			}
		}
	}
	require.Equal(t, []bgp.Family{bgp.RF_IPv4_UC, bgp.RF_IPv4_MC, bgp.RF_IPv4_VPN, bgp.RF_IPv4_MPLS, bgp.RF_IPv4_VPN_MC}, got)

	// Without an IPv4 family there is no capability.
	for _, c := range capabilitiesFromConfig(&oc.Neighbor{AfiSafis: []oc.AfiSafi{{State: oc.AfiSafiState{Family: bgp.RF_EVPN}}}}) {
		_, ok := c.(*bgp.CapExtendedNexthop)
		require.False(t, ok, "extended nexthop for L2VPN EVPN only")
	}
}

func TestNextIdleHoldTime(t *testing.T) {
	cease := func(subcode uint8) *bgp.BGPNotification {
		return &bgp.BGPNotification{ErrorCode: bgp.BGP_ERROR_CEASE, ErrorSubcode: subcode}
	}
	holdTimerExpired := &bgp.BGPNotification{ErrorCode: bgp.BGP_ERROR_HOLD_TIMER_EXPIRED}
	fsmError := &bgp.BGPNotification{ErrorCode: bgp.BGP_ERROR_FSM_ERROR, ErrorSubcode: 1}
	updateError := &bgp.BGPNotification{ErrorCode: bgp.BGP_ERROR_UPDATE_MESSAGE_ERROR, ErrorSubcode: bgp.BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST}

	const afterReset = 30

	tests := []struct {
		name        string
		backoff     float64
		reason      *fsmStateReason
		wantHold    float64
		wantBackoff float64
	}{
		{"notification sent doubles", 1, newfsmStateReason(fsmNotificationSent, cease(bgp.BGP_ERROR_SUB_BFD_DOWN), nil), 2, 2},
		{"notification received doubles", 2, newfsmStateReason(fsmNotificationRecv, cease(bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET), nil), 4, 4},
		{"hard reset received doubles", 1, newfsmStateReason(fsmHardReset, cease(bgp.BGP_ERROR_SUB_HARD_RESET), nil), 2, 2},
		{"hold timer expired goes back to the initial value", 4, newfsmStateReason(fsmHoldTimerExpired, holdTimerExpired, nil), idleHoldTimeInitial, idleHoldTimeInitial},
		{"FSM error for an unexpected message goes back to the initial value", 8, newfsmStateReason(fsmInvalidMsg, fsmError, nil), idleHoldTimeInitial, idleHoldTimeInitial},
		{"message error doubles", 8, newfsmStateReason(fsmInvalidMsg, updateError, nil), 16, 16},
		{"invalid message doubles", 8, newfsmStateReason(fsmInvalidMsg, nil, nil), 16, 16},
		{"bad peer AS doubles", 16, newfsmStateReason(fsmBadPeerAS, nil, nil), 32, 32},
		{"doubling stops at the maximum", 64, newfsmStateReason(fsmNotificationRecv, cease(bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN), nil), idleHoldTimeMax, idleHoldTimeMax},
		{"maximum stays", idleHoldTimeMax, newfsmStateReason(fsmNotificationSent, holdTimerExpired, nil), idleHoldTimeMax, idleHoldTimeMax},
		{"reset uses idle-hold-time-after-reset", 16, newfsmStateReason(fsmAdminReset, cease(bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET), nil), afterReset, idleHoldTimeInitial},
		{"reset sent as hard reset uses idle-hold-time-after-reset", 16, newfsmStateReason(fsmAdminReset, cease(bgp.BGP_ERROR_SUB_HARD_RESET), nil), afterReset, idleHoldTimeInitial},
		{"reset without a session uses idle-hold-time-after-reset", 16, newfsmStateReason(fsmAdminReset, nil, nil), afterReset, idleHoldTimeInitial},
		{"admin down goes back to the initial value", 16, newfsmStateReason(fsmAdminDown, nil, nil), idleHoldTimeInitial, idleHoldTimeInitial},
		{"read failure keeps the value", 4, newfsmStateReason(fsmReadFailed, nil, nil), 4, 4},
		{"write failure keeps the value", 4, newfsmStateReason(fsmWriteFailed, nil, nil), 4, 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hold, backoff := nextIdleHoldTime(tt.backoff, afterReset, tt.reason)
			assert.Equal(t, tt.wantHold, hold)
			assert.Equal(t, tt.wantBackoff, backoff)
		})
	}
}

// The connection that loses a collision is closed with Cease/Connection
// Collision Resolution (RFC 4271 Section 6.8), and the other one gets
// nothing.
func TestResolveCollision(t *testing.T) {
	tests := []struct {
		name         string
		localID      string
		remoteID     string
		wantOutgoing bool
	}{
		{"local ID is higher", "10.0.0.9", "10.0.0.1", true},
		{"remote ID is higher", "10.0.0.1", "10.0.0.9", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			incoming := NewMockConnection()
			outgoing := NewMockConnection()
			p, h := makePeerAndHandler(incoming)
			t.Cleanup(func() {
				cleanPeerAndHandler(p, h)
				outgoing.Close()
			})
			p.fsm.gConf.Config.RouterId = netip.MustParseAddr(tt.localID)

			open, err := bgp.NewBGPOpenMessage(65002, 90, netip.MustParseAddr(tt.remoteID), nil)
			require.NoError(t, err)

			keepOutgoing := p.fsm.resolveCollision(open.Body.(*bgp.BGPOpen), incoming, outgoing)
			require.Equal(t, tt.wantOutgoing, keepOutgoing)

			loser, winner := outgoing, incoming
			if tt.wantOutgoing {
				loser, winner = incoming, outgoing
			}
			require.Eventually(t, func() bool { return len(loser.GetSentMessages()) > 0 },
				time.Second, 10*time.Millisecond)
			sent, err := bgp.ParseBGPMessage(loser.GetSentMessages()[0])
			require.NoError(t, err)
			require.Equal(t, uint8(bgp.BGP_MSG_NOTIFICATION), sent.Header.Type)
			n := sent.Body.(*bgp.BGPNotification)
			require.Equal(t, uint8(bgp.BGP_ERROR_CEASE), n.ErrorCode)
			require.Equal(t, uint8(bgp.BGP_ERROR_SUB_CONNECTION_COLLISION_RESOLUTION), n.ErrorSubcode)
			require.Empty(t, winner.GetSentMessages())
		})
	}
}

// sentMessage waits for the n-th message sent on m and returns it.
func sentMessage(t *testing.T, m *MockConnection, n int) *bgp.BGPMessage {
	t.Helper()
	require.Eventually(t, func() bool { return len(m.GetSentMessages()) > n },
		time.Second, 10*time.Millisecond)
	msg, err := bgp.ParseBGPMessage(m.GetSentMessages()[n])
	require.NoError(t, err)
	return msg
}

func requireCollisionCease(t *testing.T, msg *bgp.BGPMessage) {
	t.Helper()
	require.Equal(t, uint8(bgp.BGP_MSG_NOTIFICATION), msg.Header.Type)
	n := msg.Body.(*bgp.BGPNotification)
	require.Equal(t, uint8(bgp.BGP_ERROR_CEASE), n.ErrorCode)
	require.Equal(t, uint8(bgp.BGP_ERROR_SUB_CONNECTION_COLLISION_RESOLUTION), n.ErrorSubcode)
}

// In OpenConfirm on the incoming connection, the peer's OPEN arrives on our
// own connection. RFC 4271 Section 6.8 requires the collision to be
// resolved then. openconfirm() used to ignore the outgoing connection, so
// the session went to Idle when the peer closed the incoming one.
// https://github.com/osrg/gobgp/issues/3741
func TestFSMHandlerOpenconfirm_Collision(t *testing.T) {
	tests := []struct {
		name         string
		localID      string
		remoteID     string
		wantOutgoing bool
	}{
		{"local ID is higher", "10.0.0.9", "10.0.0.1", true},
		{"remote ID is higher", "10.0.0.1", "10.0.0.9", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			incoming := NewMockConnection()
			outgoing := NewMockConnection()
			p, h := makePeerAndHandler(incoming)
			t.Cleanup(func() {
				cleanPeerAndHandler(p, h)
				incoming.Close()
				outgoing.Close()
			})
			p.fsm.gConf.Config.RouterId = netip.MustParseAddr(tt.localID)

			open, err := bgp.NewBGPOpenMessage(65002, 90, netip.MustParseAddr(tt.remoteID), nil)
			require.NoError(t, err)
			p.fsm.outgoingConnCh <- outgoingConn{conn: outgoing, open: open}

			type result struct {
				state  bgp.FSMState
				reason *fsmStateReason
			}
			done := make(chan result, 1)
			go func() {
				state, reason := h.openconfirm(t.Context())
				done <- result{state, reason}
			}()

			loser, winner := outgoing, incoming
			if tt.wantOutgoing {
				loser, winner = incoming, outgoing
			}
			requireCollisionCease(t, sentMessage(t, loser, 0))
			if tt.wantOutgoing {
				// openconfirm() answers the OPEN on our connection.
				msg := sentMessage(t, winner, 0)
				require.Equal(t, uint8(bgp.BGP_MSG_KEEPALIVE), msg.Header.Type)
			}

			go winner.PushBgpMessage(bgp.NewBGPKeepAliveMessage())
			select {
			case r := <-done:
				require.Equal(t, bgp.BGP_FSM_ESTABLISHED, r.state)
			case <-time.After(5 * time.Second):
				t.Fatal("the FSM state function did not return")
			}
			require.Same(t, winner, p.fsm.conn)
			if tt.wantOutgoing {
				require.Same(t, open, p.fsm.recvOpen)
			}
		})
	}
}

// active() can start a new outgoing connection manager and then take the
// connection that the previous manager left. The new manager must not keep
// running: it would open another connection to the peer.
func TestFSMHandlerActive_StopsManagerWithOutgoingConn(t *testing.T) {
	m := NewMockConnection()
	p, h := makePeerAndHandler(m)
	t.Cleanup(func() { cleanPeerAndHandler(p, h) })

	outgoing := NewMockConnection()
	t.Cleanup(func() { outgoing.Close() })
	open, err := bgp.NewBGPOpenMessage(65002, 90, netip.MustParseAddr("10.0.0.1"), nil)
	require.NoError(t, err)
	p.fsm.outgoingConnCh <- outgoingConn{conn: outgoing, open: open}

	state, _ := h.active(t.Context())
	require.Equal(t, bgp.BGP_FSM_OPENCONFIRM, state)
	require.Same(t, outgoing, p.fsm.conn)
	require.NotNil(t, p.fsm.outgoingConnMgr)
	require.Error(t, p.fsm.outgoingConnMgr.ctx.Err())
}

// In OpenSent on the incoming connection, the peer's OPEN arrives on our own
// connection before the one on the incoming connection. opensent() used to
// switch to our connection without resolving the collision: the incoming
// connection was neither closed nor used, and opensent() did not return
// until the peer sent something on it.
// https://github.com/osrg/gobgp/issues/3751
func TestFSMHandlerOpensent_OutgoingOpenFirst(t *testing.T) {
	tests := []struct {
		name         string
		localID      string
		remoteID     string
		wantOutgoing bool
	}{
		{"local ID is higher", "10.0.0.9", "10.0.0.1", true},
		{"remote ID is higher", "10.0.0.1", "10.0.0.9", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			incoming := NewMockConnection()
			outgoing := NewMockConnection()
			p, h := makePeerAndHandler(incoming)
			t.Cleanup(func() {
				cleanPeerAndHandler(p, h)
				incoming.Close()
				outgoing.Close()
			})
			p.fsm.opensentHoldTime = 10
			p.fsm.gConf.Config.RouterId = netip.MustParseAddr(tt.localID)
			// The manager that sent the connection has returned.
			p.fsm.outgoingConnMgr = &outgoingConnManager{fsm: p.fsm}
			p.fsm.outgoingConnMgr.state.Store(bgp.BGP_FSM_OPENSENT)

			open, err := bgp.NewBGPOpenMessage(65002, 90, netip.MustParseAddr(tt.remoteID), nil)
			require.NoError(t, err)
			p.fsm.outgoingConnCh <- outgoingConn{conn: outgoing, open: open}

			type result struct {
				state  bgp.FSMState
				reason *fsmStateReason
			}
			done := make(chan result, 1)
			go func() {
				state, reason := h.opensent(t.Context())
				done <- result{state, reason}
			}()

			if tt.wantOutgoing {
				requireCollisionCease(t, sentMessage(t, incoming, 0))
				msg := sentMessage(t, outgoing, 0)
				require.Equal(t, uint8(bgp.BGP_MSG_KEEPALIVE), msg.Header.Type)
			} else {
				requireCollisionCease(t, sentMessage(t, outgoing, 0))
				// Still in OpenSent: the OPEN on the incoming
				// connection moves it to OpenConfirm.
				go incoming.PushBgpMessage(open)
				msg := sentMessage(t, incoming, 0)
				require.Equal(t, uint8(bgp.BGP_MSG_KEEPALIVE), msg.Header.Type)
			}

			select {
			case r := <-done:
				require.Equal(t, bgp.BGP_FSM_OPENCONFIRM, r.state)
			case <-time.After(5 * time.Second):
				t.Fatal("the FSM state function did not return")
			}
			if tt.wantOutgoing {
				require.Same(t, outgoing, p.fsm.conn)
				require.Same(t, open, p.fsm.recvOpen)
			} else {
				require.Same(t, incoming, p.fsm.conn)
			}
		})
	}
}

// startManagerToListener starts an outgoing connection manager that
// connects to a local listener after delay, and returns both.
func startManagerToListener(t *testing.T, delay time.Duration) (*outgoingConnManager, net.Listener) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })

	m := NewMockConnection()
	p, h := makePeerAndHandler(m)
	t.Cleanup(func() { cleanPeerAndHandler(p, h) })
	p.fsm.gConf.Config.RouterId = netip.MustParseAddr("10.0.0.9")
	conf := p.fsm.pConf.ReadCopy()
	conf.Config.LocalAs = 65001
	conf.Timers.Config.HoldTime = 90
	conf.State.NeighborAddress = netip.MustParseAddr("127.0.0.1")
	conf.Transport.Config.RemotePort = uint16(l.Addr().(*net.TCPAddr).Port)
	conf.Transport.Config.LocalAddress = netip.MustParseAddr("127.0.0.1")
	p.fsm.pConf.Update(&conf)

	ocm := newOutGoingConnManager(t.Context(), p.fsm, delay)
	t.Cleanup(func() { ocm.stop(nil) })
	return ocm, l
}

// The manager moves to OpenSent before its OPEN goes out. opensent() used
// to read the state as Connect between the OPEN and the state change, and
// stopped the manager, which closed a connection that the peer may keep.
// https://github.com/osrg/gobgp/issues/3751
func TestOutgoingConnManager_OpenSentBeforeOpen(t *testing.T) {
	ocm, l := startManagerToListener(t, 0)

	conn, err := l.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	msg, err := readAll(conn, bgp.BGP_HEADER_LENGTH)
	require.NoError(t, err)
	require.Equal(t, uint8(bgp.BGP_MSG_OPEN), msg[18])

	require.Equal(t, bgp.BGP_FSM_OPENSENT, ocm.state.Load())
	require.False(t, ocm.state.CompareAndSwap(bgp.BGP_FSM_CONNECT, bgp.BGP_FSM_IDLE))
}

// When opensent() takes the manager over while it is connecting, the
// manager closes the new connection without sending its OPEN.
func TestOutgoingConnManager_StoppedBeforeOpen(t *testing.T) {
	ocm, l := startManagerToListener(t, 2*time.Second)

	// connectLoop() waits 2 seconds before it connects. Take the manager
	// over while it waits there, so that it connects after that. Taken
	// over before connectLoop(), it returns without connecting.
	time.Sleep(500 * time.Millisecond)
	require.True(t, ocm.state.CompareAndSwap(bgp.BGP_FSM_CONNECT, bgp.BGP_FSM_IDLE))

	require.NoError(t, l.(*net.TCPListener).SetDeadline(time.Now().Add(5*time.Second)))
	conn, err := l.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, bgp.BGP_HEADER_LENGTH)
	n, err := conn.Read(buf)
	require.Equal(t, 0, n)
	require.ErrorIs(t, err, io.EOF)

	ocm.wg.Wait()
}

// The delay given to the manager is used only for its first connection.
// When that connection fails, the manager waits the retry delay before it
// connects again.
func TestOutgoingConnManager_RetryDelay(t *testing.T) {
	_, l := startManagerToListener(t, 0)

	require.NoError(t, l.(*net.TCPListener).SetDeadline(time.Now().Add(5*time.Second)))
	conn, err := l.Accept()
	require.NoError(t, err)
	require.Equal(t, uint8(bgp.BGP_MSG_OPEN), readMessage(t, conn).Header.Type)

	start := time.Now()
	conn.Close()

	conn, err = l.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	// connectRetryDelay(minConnectRetryInterval) is at least 0.75 * 2s.
	require.GreaterOrEqual(t, time.Since(start), 1500*time.Millisecond)
}

// readMessage reads one BGP message from conn.
func readMessage(t *testing.T, conn net.Conn) *bgp.BGPMessage {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	hdr, err := readAll(conn, bgp.BGP_HEADER_LENGTH)
	require.NoError(t, err)
	body, err := readAll(conn, int(binary.BigEndian.Uint16(hdr[16:18]))-bgp.BGP_HEADER_LENGTH)
	require.NoError(t, err)
	msg, err := bgp.ParseBGPMessage(append(hdr, body...))
	require.NoError(t, err)
	return msg
}

// A manager stopped with a NOTIFICATION sends it on the connection on which
// it sent its OPEN, and on a connection that it left in outgoingConnCh.
func TestOutgoingConnManager_StopWithNotification(t *testing.T) {
	ocm, l := startManagerToListener(t, 0)

	conn, err := l.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	require.Equal(t, uint8(bgp.BGP_MSG_OPEN), readMessage(t, conn).Header.Type)

	left := NewMockConnection()
	t.Cleanup(func() { left.Close() })
	open, err := bgp.NewBGPOpenMessage(65002, 90, netip.MustParseAddr("10.0.0.1"), nil)
	require.NoError(t, err)
	ocm.fsm.outgoingConnCh <- outgoingConn{conn: left, open: open}

	ocm.stop(bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_CONNECTION_COLLISION_RESOLUTION, nil))

	requireCollisionCease(t, readMessage(t, conn))
	requireCollisionCease(t, sentMessage(t, left, 0))
}

// When the session goes to Idle, a manager that is still connecting is
// stopped: in Idle we make no connection to the peer.
func TestOutgoingConnManager_KeepForIdle_Connecting(t *testing.T) {
	ocm, _ := startManagerToListener(t, time.Minute)

	require.False(t, ocm.keepForIdle())
	require.Error(t, ocm.ctx.Err())
}

// A manager that sent its OPEN is kept when the session goes to Idle.
func TestOutgoingConnManager_KeepForIdle_OpenSent(t *testing.T) {
	ocm, l := startManagerToListener(t, 0)

	conn, err := l.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	require.Equal(t, uint8(bgp.BGP_MSG_OPEN), readMessage(t, conn).Header.Type)

	require.True(t, ocm.keepForIdle())
	require.NoError(t, ocm.ctx.Err())
}

// A connection that the manager left in outgoingConnCh is kept when the
// session goes to Idle.
func TestOutgoingConnManager_KeepForIdle_ConnInChannel(t *testing.T) {
	m := NewMockConnection()
	p, h := makePeerAndHandler(m)
	t.Cleanup(func() { cleanPeerAndHandler(p, h) })

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // the manager has returned
	ocm := &outgoingConnManager{ctx: ctx, cancel: cancel, fsm: p.fsm}

	outgoing := NewMockConnection()
	t.Cleanup(func() { outgoing.Close() })
	open, err := bgp.NewBGPOpenMessage(65002, 90, netip.MustParseAddr("10.0.0.1"), nil)
	require.NoError(t, err)
	p.fsm.outgoingConnCh <- outgoingConn{conn: outgoing, open: open}

	require.True(t, ocm.keepForIdle())
}

// TestRecvMessageloop_DiscardsAs4AttrsFromNewSpeaker verifies that AS4_PATH
// and AS4_AGGREGATOR received on a session where both sides use four-octet AS
// numbers are discarded instead of being merged into AS_PATH and AGGREGATOR
// (RFC 6793 Section 4.1).
func TestRecvMessageloop_DiscardsAs4AttrsFromNewSpeaker(t *testing.T) {
	assert := assert.New(t)

	raw := buildUpdate([]byte{
		0x40, 0x01, 0x01, 0x00, // ORIGIN: IGP
		0x40, 0x02, 0x0a, 0x02, 0x02, 0x00, 0x00, 0xfd, 0xe9, 0x00, 0x00, 0xfd, 0xea, // AS_PATH: 65001 65002
		0x40, 0x03, 0x04, 0x0a, 0x00, 0x00, 0x01, // NEXT_HOP: 10.0.0.1
		0xc0, 0x07, 0x08, 0x00, 0x00, 0xfd, 0xe9, 0x0a, 0x00, 0x00, 0x01, // AGGREGATOR: 65001 10.0.0.1
		0xc0, 0x11, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xeb, // AS4_PATH: 65003
		0xc0, 0x12, 0x08, 0x00, 0x00, 0xfd, 0xed, 0x0a, 0x00, 0x00, 0x02, // AS4_AGGREGATOR: 65005 10.0.0.2
	}, []byte{0x18, 0xc0, 0xa8, 0x01}) // 192.168.1.0/24

	fmsg, n := recvUpdate(t, raw)
	assert.Nil(n)
	if !assert.NotNil(fmsg) {
		return
	}
	assert.Equal(bgp.ERROR_HANDLING_NONE, fmsg.handling)
	body := fmsg.MsgData.(*bgp.BGPMessage).Body.(*bgp.BGPUpdate)
	var asPath *bgp.PathAttributeAsPath
	var aggregator *bgp.PathAttributeAggregator
	for _, a := range body.PathAttributes {
		switch a := a.(type) {
		case *bgp.PathAttributeAsPath:
			asPath = a
		case *bgp.PathAttributeAggregator:
			aggregator = a
		case *bgp.PathAttributeAs4Path, *bgp.PathAttributeAs4Aggregator:
			t.Errorf("%s was not discarded", a.GetType())
		}
	}
	if assert.NotNil(asPath) && assert.Len(asPath.Value, 1) {
		assert.Equal([]uint32{65001, 65002}, asPath.Value[0].GetAS())
	}
	if assert.NotNil(aggregator) {
		assert.Equal(uint32(65001), aggregator.Value.AS)
		assert.Equal(netip.MustParseAddr("10.0.0.1"), aggregator.Value.Address)
	}
}

func requireAdminResetCease(t *testing.T, msg *bgp.BGPMessage) {
	t.Helper()
	require.Equal(t, uint8(bgp.BGP_MSG_NOTIFICATION), msg.Header.Type)
	n := msg.Body.(*bgp.BGPNotification)
	require.Equal(t, uint8(bgp.BGP_ERROR_CEASE), n.ErrorCode)
	require.Equal(t, uint8(bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET), n.ErrorSubcode)
}

// ResetPeer in Idle shortens the idle hold timer to
// idle-hold-time-after-reset and resets the backoff.
// https://github.com/osrg/gobgp/issues/3740
func TestFSMHandlerIdle_Reset(t *testing.T) {
	m := NewMockConnection()
	p, h := makePeerAndHandler(m)
	t.Cleanup(func() { cleanPeerAndHandler(p, h) })

	conf := p.fsm.pConf.ReadCopy()
	conf.Timers.Config.IdleHoldTimeAfterReset = 1
	p.fsm.pConf.Update(&conf)
	p.fsm.idleHoldTime = 64
	p.fsm.idleHoldBackoff = 64

	p.reset(nil)
	start := time.Now()
	state, reason := h.idle(t.Context())
	require.Equal(t, bgp.BGP_FSM_ACTIVE, state)
	require.Equal(t, fsmIdleTimerExpired, reason.Type)
	require.Less(t, time.Since(start), 5*time.Second)
	require.Equal(t, float64(1), p.fsm.idleHoldTime)
	require.Equal(t, float64(idleHoldTimeInitial), p.fsm.idleHoldBackoff)
}

// ResetPeer in Idle never makes the remaining wait longer, like FRR
// peer_clear, which re-arms the start timer with 1 second.
// https://github.com/osrg/gobgp/issues/3860
func TestFSMHandlerIdle_ResetDoesNotLengthenWait(t *testing.T) {
	m := NewMockConnection()
	p, h := makePeerAndHandler(m)
	t.Cleanup(func() { cleanPeerAndHandler(p, h) })

	conf := p.fsm.pConf.ReadCopy()
	conf.Timers.Config.IdleHoldTimeAfterReset = 30
	p.fsm.pConf.Update(&conf)
	p.fsm.idleHoldTime = 1
	p.fsm.idleHoldBackoff = 4

	p.reset(nil)
	start := time.Now()
	state, reason := h.idle(t.Context())
	require.Equal(t, bgp.BGP_FSM_ACTIVE, state)
	require.Equal(t, fsmIdleTimerExpired, reason.Type)
	require.Less(t, time.Since(start), 5*time.Second)
	require.Equal(t, float64(idleHoldTimeInitial), p.fsm.idleHoldBackoff)
}

// DisablePeer of a peer in Idle sets the idle hold time and the backoff
// back to 1 second, so that EnablePeer starts it after 1 second, like
// "no neighbor shutdown" in FRR.
// https://github.com/osrg/gobgp/issues/3860
func TestFSMHandlerIdle_AdminDownResetsBackoff(t *testing.T) {
	m := NewMockConnection()
	p, h := makePeerAndHandler(m)
	t.Cleanup(func() { cleanPeerAndHandler(p, h) })

	p.fsm.idleHoldTime = 64
	p.fsm.idleHoldBackoff = 64

	p.fsm.adminStateCh <- adminStateOperation{adminStateDown, nil}
	p.fsm.adminStateCh <- adminStateOperation{adminStateUp, nil}
	start := time.Now()
	state, reason := h.idle(t.Context())
	require.Equal(t, bgp.BGP_FSM_ACTIVE, state)
	require.Equal(t, fsmIdleTimerExpired, reason.Type)
	require.Less(t, time.Since(start), 5*time.Second)
	require.Equal(t, float64(idleHoldTimeInitial), p.fsm.idleHoldTime)
	require.Equal(t, float64(idleHoldTimeInitial), p.fsm.idleHoldBackoff)
}

// ResetPeer in Idle is ignored while the peer is administratively down.
func TestFSMHandlerIdle_ResetWhileAdminDown(t *testing.T) {
	m := NewMockConnection()
	p, h := makePeerAndHandler(m)
	t.Cleanup(func() { cleanPeerAndHandler(p, h) })

	conf := p.fsm.pConf.ReadCopy()
	conf.Timers.Config.IdleHoldTimeAfterReset = 30
	p.fsm.pConf.Update(&conf)
	p.fsm.adminState.Store(adminStateDown)
	p.fsm.idleHoldTime = 1
	p.fsm.idleHoldBackoff = 1

	p.reset(nil)
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	state, _ := h.idle(ctx)
	require.Equal(t, bgp.FSMState(-1), state)
	require.Empty(t, p.fsm.resetCh)
	require.Equal(t, float64(1), p.fsm.idleHoldTime)
}

// changeadminState rejects a request for the current admin state, and
// State.AdminDown follows the admin state.
// https://github.com/osrg/gobgp/issues/3788
func TestChangeAdminState(t *testing.T) {
	m := NewMockConnection()
	p, h := makePeerAndHandler(m)
	t.Cleanup(func() { cleanPeerAndHandler(p, h) })

	require.Error(t, h.changeadminState(adminStateUp))
	require.False(t, p.fsm.pConf.ReadOnly().State.AdminDown)

	for _, s := range []adminState{adminStatePfxCt, adminStateDown, adminStateUp, adminStateDown} {
		require.NoError(t, h.changeadminState(s))
		require.Equal(t, s, p.fsm.adminState.Load())
		require.Equal(t, s != adminStateUp, p.fsm.pConf.ReadOnly().State.AdminDown)
		require.Error(t, h.changeadminState(s))
		require.Equal(t, s != adminStateUp, p.fsm.pConf.ReadOnly().State.AdminDown)
	}
}

// EnablePeer of an enabled peer in Idle does not restart the idle hold
// timer.
// https://github.com/osrg/gobgp/issues/3788
func TestFSMHandlerIdle_AdminStateUpWhileUp(t *testing.T) {
	m := NewMockConnection()
	p, h := makePeerAndHandler(m)
	t.Cleanup(func() { cleanPeerAndHandler(p, h) })

	p.fsm.idleHoldTime = 1
	start := time.Now()
	go func() {
		time.Sleep(500 * time.Millisecond)
		p.fsm.adminStateCh <- adminStateOperation{adminStateUp, nil}
	}()
	state, _ := h.idle(t.Context())
	require.Equal(t, bgp.BGP_FSM_ACTIVE, state)
	require.Less(t, time.Since(start), 1400*time.Millisecond)
}

// ResetPeer in Active goes to Idle. The connection of the manager, on which
// the OPEN was sent, is closed with Cease/Administrative Reset.
func TestFSMHandlerActive_Reset(t *testing.T) {
	ocm, l := startManagerToListener(t, 0)
	fsm := ocm.fsm
	fsm.outgoingConnMgr = ocm

	conn, err := l.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	require.Equal(t, uint8(bgp.BGP_MSG_OPEN), readMessage(t, conn).Header.Type)
	require.Eventually(t, func() bool { return ocm.state.Load() == bgp.BGP_FSM_OPENSENT },
		time.Second, 10*time.Millisecond)

	fsm.resetCh <- nil
	state, reason := fsm.h.active(t.Context())
	require.Equal(t, bgp.BGP_FSM_IDLE, state)
	require.Equal(t, fsmAdminReset, reason.Type)
	require.Nil(t, reason.BGPNotification)
	require.Error(t, ocm.ctx.Err())
	requireAdminResetCease(t, readMessage(t, conn))
}

// ResetPeer in OpenSent and OpenConfirm sends Cease/Administrative Reset
// and goes to Idle.
func TestFSMHandler_ResetBeforeEstablished(t *testing.T) {
	tests := []struct {
		name  string
		state func(*fsmHandler, context.Context) (bgp.FSMState, *fsmStateReason)
	}{
		{"opensent", (*fsmHandler).opensent},
		{"openconfirm", (*fsmHandler).openconfirm},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMockConnection()
			p, h := makePeerAndHandler(m)
			t.Cleanup(func() { cleanPeerAndHandler(p, h) })
			p.fsm.opensentHoldTime = 10
			conf := p.fsm.pConf.ReadCopy()
			conf.Timers.Config.KeepaliveInterval = 10
			p.fsm.pConf.Update(&conf)

			p.reset(nil)
			state, reason := tt.state(h, t.Context())
			require.Equal(t, bgp.BGP_FSM_IDLE, state)
			require.Equal(t, fsmAdminReset, reason.Type)
			require.Equal(t, uint8(bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET), reason.BGPNotification.ErrorSubcode)
			requireAdminResetCease(t, sentMessage(t, m, 0))
		})
	}
}

// grAfiSafi returns an AfiSafi with graceful restart and long-lived graceful
// restart configured.
func grAfiSafi(name oc.AfiSafiType, family bgp.Family) oc.AfiSafi {
	var a oc.AfiSafi
	a.Config.AfiSafiName = name
	a.Config.Enabled = true
	a.State.Family = family
	a.MpGracefulRestart.Config.Enabled = true
	a.LongLivedGracefulRestart.Config.Enabled = true
	a.LongLivedGracefulRestart.Config.RestartTime = 3600
	return a
}

// grOpen returns an OPEN for ipv4-unicast and ipv6-unicast with caps.
func grOpen(t *testing.T, caps ...bgp.ParameterCapabilityInterface) *bgp.BGPMessage {
	t.Helper()
	caps = append(caps,
		bgp.NewCapMultiProtocol(bgp.RF_IPv4_UC),
		bgp.NewCapMultiProtocol(bgp.RF_IPv6_UC),
		bgp.NewCapFourOctetASNumber(65001))
	m, err := bgp.NewBGPOpenMessage(65001, 90, netip.MustParseAddr("10.0.0.1"),
		[]bgp.OptionParameterInterface{bgp.NewOptionParameterCapability(caps)})
	require.NoError(t, err)
	return m
}

// grFirstSession sets up a peer whose first session negotiated graceful
// restart with the N bit and long-lived graceful restart, for ipv4-unicast
// and ipv6-unicast. The session has ended, and the FSM is in Idle.
func grFirstSession(t *testing.T) (*peer, *fsmHandler, *MockConnection) {
	t.Helper()
	m := NewMockConnection()
	m.SetRemoteAddr("10.0.0.1")
	p, h := makePeerAndHandler(m)
	t.Cleanup(func() { cleanPeerAndHandler(p, h) })

	conf := p.fsm.pConf.ReadCopy()
	conf.Config.PeerAs = 65001
	conf.Config.LocalAs = 65000
	conf.Timers.Config.HoldTime = 90
	conf.GracefulRestart.Config.Enabled = true
	conf.GracefulRestart.Config.NotificationEnabled = true
	conf.GracefulRestart.Config.LongLivedEnabled = true
	conf.AfiSafis = []oc.AfiSafi{
		grAfiSafi(oc.AFI_SAFI_TYPE_IPV4_UNICAST, bgp.RF_IPv4_UC),
		grAfiSafi(oc.AFI_SAFI_TYPE_IPV6_UNICAST, bgp.RF_IPv6_UC),
	}
	p.fsm.pConf.Update(&conf)

	p.fsm.recvOpen = grOpen(t,
		bgp.NewCapGracefulRestart(false, true, 120, []*bgp.CapGracefulRestartTuple{
			bgp.NewCapGracefulRestartTuple(bgp.RF_IPv4_UC, true),
			bgp.NewCapGracefulRestartTuple(bgp.RF_IPv6_UC, true),
		}),
		bgp.NewCapLongLivedGracefulRestart([]*bgp.CapLongLivedGracefulRestartTuple{
			bgp.NewCapLongLivedGracefulRestartTuple(bgp.RF_IPv4_UC, true, 3600),
			bgp.NewCapLongLivedGracefulRestartTuple(bgp.RF_IPv6_UC, true, 3600),
		}))
	p.fsm.stateChange(bgp.BGP_FSM_ESTABLISHED, newfsmStateReason(fsmOpenMsgNegotiated, nil, nil))

	s := p.fsm.pConf.ReadOnly()
	require.True(t, s.GracefulRestart.State.Enabled)
	require.True(t, s.GracefulRestart.State.NotificationEnabled)
	require.True(t, s.GracefulRestart.State.LongLivedEnabled)
	for _, a := range s.AfiSafis {
		require.True(t, a.MpGracefulRestart.State.Received)
		require.True(t, a.LongLivedGracefulRestart.State.Received)
	}

	p.fsm.stateChange(bgp.BGP_FSM_IDLE, newfsmStateReason(fsmReadFailed, nil, nil))
	return p, h, m
}

// The next session has no graceful restart capability. Nothing of the
// negotiated graceful restart State of the first session is kept.
func TestFSMStateChange_GracefulRestartCapabilityRemoved(t *testing.T) {
	p, _, _ := grFirstSession(t)

	p.fsm.recvOpen = grOpen(t)
	p.fsm.stateChange(bgp.BGP_FSM_ESTABLISHED, newfsmStateReason(fsmOpenMsgNegotiated, nil, nil))

	s := p.fsm.pConf.ReadOnly()
	assert.False(t, s.GracefulRestart.State.Enabled)
	assert.Zero(t, s.GracefulRestart.State.PeerRestartTime)
	assert.False(t, s.GracefulRestart.State.NotificationEnabled)
	assert.False(t, s.GracefulRestart.State.LongLivedEnabled)
	for _, a := range s.AfiSafis {
		assert.False(t, a.MpGracefulRestart.State.Enabled, a.State.Family)
		assert.False(t, a.MpGracefulRestart.State.Received, a.State.Family)
		assert.False(t, a.LongLivedGracefulRestart.State.Enabled, a.State.Family)
		assert.False(t, a.LongLivedGracefulRestart.State.Received, a.State.Family)
		assert.Zero(t, a.LongLivedGracefulRestart.State.PeerRestartTime, a.State.Family)
	}
	n := p.grNegotiated()
	assert.Nil(t, n.GR)
	assert.Nil(t, n.LLGR)
}

// The next session has graceful restart for ipv4-unicast only, without the
// N bit and without long-lived graceful restart.
func TestFSMStateChange_GracefulRestartFamilyRemoved(t *testing.T) {
	p, _, _ := grFirstSession(t)

	p.fsm.recvOpen = grOpen(t,
		bgp.NewCapGracefulRestart(false, false, 60, []*bgp.CapGracefulRestartTuple{
			bgp.NewCapGracefulRestartTuple(bgp.RF_IPv4_UC, true),
		}))
	p.fsm.stateChange(bgp.BGP_FSM_ESTABLISHED, newfsmStateReason(fsmOpenMsgNegotiated, nil, nil))

	s := p.fsm.pConf.ReadOnly()
	assert.True(t, s.GracefulRestart.State.Enabled)
	assert.Equal(t, uint16(60), s.GracefulRestart.State.PeerRestartTime)
	assert.False(t, s.GracefulRestart.State.NotificationEnabled)
	assert.False(t, s.GracefulRestart.State.LongLivedEnabled)
	assert.True(t, s.GetAfiSafi(bgp.RF_IPv4_UC).MpGracefulRestart.State.Received)
	assert.False(t, s.GetAfiSafi(bgp.RF_IPv6_UC).MpGracefulRestart.State.Received)
	for _, a := range s.AfiSafis {
		assert.False(t, a.LongLivedGracefulRestart.State.Received, a.State.Family)
	}
	n := p.grNegotiated()
	require.NotNil(t, n.GR)
	assert.Equal(t, uint16(60), n.GR.Time)
	assert.Nil(t, n.LLGR)
}

// When the TCP connection of a session without graceful restart fails, the
// session does not end as a graceful restart, even if the previous session
// negotiated it.
func TestFSMHandlerEstablished_NoGracefulRestartAfterCapabilityRemoved(t *testing.T) {
	p, h, m := grFirstSession(t)

	p.fsm.recvOpen = grOpen(t)
	p.fsm.stateChange(bgp.BGP_FSM_ESTABLISHED, newfsmStateReason(fsmOpenMsgNegotiated, nil, nil))

	type result struct {
		state  bgp.FSMState
		reason *fsmStateReason
	}
	ch := make(chan result, 1)
	go func() {
		state, reason := h.established(t.Context())
		ch <- result{state, reason}
	}()
	m.remote.Close()

	select {
	case r := <-ch:
		require.Equal(t, bgp.BGP_FSM_IDLE, r.state)
		require.Equal(t, fsmReadFailed, r.reason.Type)
	case <-time.After(5 * time.Second):
		t.Fatal("established() did not return")
	}
}

// A new connection from the peer while the session is established ends the
// session when the peer advertised graceful restart or long-lived graceful
// restart for one or more families (RFC 4724 Section 4.2). The old
// connection is closed without a NOTIFICATION, and active() takes the new
// one. Otherwise the new connection is closed.
func TestFSMHandlerEstablished_NewConnection(t *testing.T) {
	tests := []struct {
		name string
		caps []bgp.ParameterCapabilityInterface
		ends bool
	}{
		{"graceful restart", []bgp.ParameterCapabilityInterface{
			bgp.NewCapGracefulRestart(false, false, 120, []*bgp.CapGracefulRestartTuple{
				bgp.NewCapGracefulRestartTuple(bgp.RF_IPv4_UC, true),
			}),
		}, true},
		{"long-lived graceful restart only", []bgp.ParameterCapabilityInterface{
			bgp.NewCapGracefulRestart(false, false, 0, nil),
			bgp.NewCapLongLivedGracefulRestart([]*bgp.CapLongLivedGracefulRestartTuple{
				bgp.NewCapLongLivedGracefulRestartTuple(bgp.RF_IPv4_UC, true, 3600),
			}),
		}, true},
		{"no family in the capability", []bgp.ParameterCapabilityInterface{
			bgp.NewCapGracefulRestart(false, false, 120, nil),
		}, false},
		{"no graceful restart", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, h, m := grFirstSession(t)
			p.fsm.recvOpen = grOpen(t, tt.caps...)
			p.fsm.stateChange(bgp.BGP_FSM_ESTABLISHED, newfsmStateReason(fsmOpenMsgNegotiated, nil, nil))

			type result struct {
				state  bgp.FSMState
				reason *fsmStateReason
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			ch := make(chan result, 1)
			go func() {
				state, reason := h.established(ctx)
				ch <- result{state, reason}
			}()

			conn, remote := net.Pipe()
			t.Cleanup(func() { remote.Close() })
			p.fsm.connCh <- conn

			if !tt.ends {
				// The new connection is closed, and the session stays.
				remote.SetReadDeadline(time.Now().Add(5 * time.Second))
				_, err := remote.Read(make([]byte, 1))
				require.ErrorIs(t, err, io.EOF)
				require.Never(t, func() bool { return len(ch) > 0 }, 100*time.Millisecond, 10*time.Millisecond)
				cancel()
				<-ch
				return
			}

			var r result
			select {
			case r = <-ch:
			case <-time.After(5 * time.Second):
				t.Fatal("established() did not return")
			}
			assert.Equal(t, bgp.BGP_FSM_ACTIVE, r.state)
			assert.Equal(t, fsmNewConnection, r.reason.Type)
			// active() takes the new connection.
			select {
			case c := <-p.fsm.connCh:
				assert.Equal(t, conn, c)
			default:
				t.Fatal("the new connection is not passed to active()")
			}
			// The old connection is closed without a NOTIFICATION.
			_, err := m.Write([]byte{0})
			assert.ErrorIs(t, err, io.ErrClosedPipe)
			for _, b := range m.GetSentMessages() {
				msg, err := bgp.ParseBGPMessage(b)
				require.NoError(t, err)
				assert.NotEqual(t, uint8(bgp.BGP_MSG_NOTIFICATION), msg.Header.Type)
			}
		})
	}
}

// A NOTIFICATION that Established sends for an operation or an admin state
// change. When the N bit was exchanged, the NOTIFICATION is a Hard Reset
// (RFC 8538 Section 5.1), and its data is the original NOTIFICATION:
// ErrCode, Subcode and Data (RFC 8538 Section 3.1).
func TestFSMHandlerEstablished_SentNotification(t *testing.T) {
	communication := newAdministrativeCommunication("maintenance")
	adminDown := func(f *fsm) { f.adminStateCh <- adminStateOperation{adminStateDown, communication} }
	prefixLimit := func(f *fsm) { f.adminStateCh <- adminStateOperation{adminStatePfxCt, nil} }
	reset := func(f *fsm) { f.resetCh <- communication }
	bfdDown := func(f *fsm) {
		f.notification <- bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_BFD_DOWN, nil)
	}
	tests := []struct {
		name         string
		send         func(*fsm)
		reason       fsmStateReasonType
		notification bool
		sentSubcode  uint8
		sentData     []byte
	}{
		{"admin down", adminDown, fsmAdminDown, false, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN, communication},
		{"prefix limit", prefixLimit, fsmAdminDown, false, bgp.BGP_ERROR_SUB_MAXIMUM_NUMBER_OF_PREFIXES_REACHED, nil},
		{"reset", reset, fsmAdminReset, false, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET, communication},
		{"bfd down", bfdDown, fsmNotificationSent, false, bgp.BGP_ERROR_SUB_BFD_DOWN, nil},
		{
			"admin down with N bit", adminDown, fsmAdminDown,
			true, bgp.BGP_ERROR_SUB_HARD_RESET,
			append([]byte{bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN}, communication...),
		},
		{
			"prefix limit with N bit", prefixLimit, fsmAdminDown,
			true, bgp.BGP_ERROR_SUB_HARD_RESET,
			[]byte{bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_MAXIMUM_NUMBER_OF_PREFIXES_REACHED},
		},
		{
			"reset with N bit", reset, fsmAdminReset,
			true, bgp.BGP_ERROR_SUB_HARD_RESET,
			append([]byte{bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET}, communication...),
		},
		{
			"bfd down with N bit", bfdDown, fsmNotificationSent,
			true, bgp.BGP_ERROR_SUB_HARD_RESET,
			[]byte{bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_BFD_DOWN},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, h, m := grFirstSession(t)
			p.fsm.recvOpen = grOpen(t,
				bgp.NewCapGracefulRestart(false, tt.notification, 120, []*bgp.CapGracefulRestartTuple{
					bgp.NewCapGracefulRestartTuple(bgp.RF_IPv4_UC, true),
				}))
			p.fsm.stateChange(bgp.BGP_FSM_ESTABLISHED, newfsmStateReason(fsmOpenMsgNegotiated, nil, nil))

			type result struct {
				state  bgp.FSMState
				reason *fsmStateReason
			}
			ch := make(chan result, 1)
			go func() {
				state, reason := h.established(t.Context())
				ch <- result{state, reason}
			}()
			tt.send(p.fsm)

			var r result
			select {
			case r = <-ch:
			case <-time.After(5 * time.Second):
				t.Fatal("established() did not return")
			}
			assert.Equal(t, bgp.BGP_FSM_IDLE, r.state)
			assert.Equal(t, tt.reason, r.reason.Type)
			require.NotNil(t, r.reason.BGPNotification)
			assert.Equal(t, uint8(bgp.BGP_ERROR_CEASE), r.reason.BGPNotification.ErrorCode)
			assert.Equal(t, tt.sentSubcode, r.reason.BGPNotification.ErrorSubcode)

			msg := sentMessage(t, m, 0)
			require.Equal(t, uint8(bgp.BGP_MSG_NOTIFICATION), msg.Header.Type)
			body := msg.Body.(*bgp.BGPNotification)
			assert.Equal(t, uint8(bgp.BGP_ERROR_CEASE), body.ErrorCode)
			assert.Equal(t, tt.sentSubcode, body.ErrorSubcode)
			assert.Equal(t, tt.sentData, body.Data)
		})
	}
}
