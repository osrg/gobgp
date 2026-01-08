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
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/eapache/channels"
	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
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

	state, reason := h.established(t.Context())
	assert.Equal(bgp.BGP_FSM_IDLE, state)
	assert.Equal(fsmGracefulRestart, reason.Type)

	<-m.bufReady.C

	lastMsg, err := m.GetLastestBuf()
	assert.True(err == nil || errors.Is(err, io.EOF))

	sent, _ := bgp.ParseBGPMessage(lastMsg)
	assert.Equal(uint8(bgp.BGP_MSG_NOTIFICATION), sent.Header.Type)
	assert.Equal(uint8(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED), sent.Body.(*bgp.BGPNotification).ErrorCode)
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
	assert.False(hasOwnASLoop(65100, 10, aspath))
	assert.True(hasOwnASLoop(65100, 0, aspath))
	assert.False(hasOwnASLoop(65200, 0, aspath))
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

	peer := newPeer(nil, &a, bgp.BGP_FSM_ESTABLISHED, nil, nil, slog.Default())
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
				conf := testPeer.fsm.pConf.ReadCopy()
				freshConfig := conf.AfiSafis
				_, _ = testPeer.updatePrefixLimitConfig(&conf, freshConfig)
				testPeer.fsm.pConf.Update(&conf)
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
