package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bfd"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func eventually(timeout time.Duration, what func() error) error {
	var err error
	deadline := time.After(timeout)
	for {
		select {
		case <-deadline:
			if err != nil {
				return err
			}
			return what()
		default:
			err = what()
			if err == nil {
				return nil
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func eventuallyCheckState(timeout time.Duration, s *bfdServer, peerAddress netip.Addr, expected api.BfdSessionState) error {
	return eventually(timeout, func() error {
		state, err := s.GetPeerState(peerAddress)
		if err != nil {
			return err
		}
		if state.state.SessionState != expected {
			return fmt.Errorf("must be: peerState == %s", expected)
		}
		return nil
	})
}

// eventuallyReceivesAfter waits until s has received more packets from peerAddress than
// the given count. The far end restores its configured Desired Min TX Interval only on
// reaching Up, and s learns the new value, and with it the shorter detection time (RFC
// 5880 Section 6.8.4), only from the first packet sent in that state. Since the Up
// packet is paced rather than sent off-schedule, a test that stops the far end the
// instant it reports Up can leave s with the 5 x 1s not-Up detection time. Snapshot
// the count once the far end is Up and wait here for one more packet.
func eventuallyReceivesAfter(timeout time.Duration, s *bfdServer, peerAddress netip.Addr, count uint64) error {
	return eventually(timeout, func() error {
		state, err := s.GetPeerState(peerAddress)
		if err != nil {
			return err
		}
		if state.state.BfdAsync.ReceivedPackets <= count {
			return fmt.Errorf("must be: receivedPackets > %d", count)
		}
		return nil
	})
}

type mockPeerState struct {
	bfdDownCount int64
}

// bfdDown implements peerState.
func (m *mockPeerState) bfdDown(ctx context.Context, addr netip.Addr) error {
	atomic.AddInt64(&m.bfdDownCount, 1)
	return nil
}

func Test_StartStop(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	s1 := NewBfdServer(ps, slog.Default())
	assert.NotNil(s1)

	s1.Start(context.Background(), oc.BfdConfig{ //nolint:errcheck
		Port: 13784,
	})
	defer s1.Stop()
}

func Test_BfdServerStopIdempotentAndPublicMethodsAfterStop(t *testing.T) {
	assert := assert.New(t)

	ps := &mockPeerState{}
	s := NewBfdServer(ps, slog.Default())
	s.Stop()
	s.Stop()

	assert.Error(s.Start(context.Background(), oc.BfdConfig{Port: 13784}))
	assert.Error(s.AddPeer(context.Background(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:    23784,
		Enabled: true,
	}, ""))
	assert.Error(s.DeletePeer(context.Background(), netip.MustParseAddr("127.0.0.1")))
}

func Test_ApiBfdSessionStateToOC(t *testing.T) {
	assert := assert.New(t)

	assert.Equal(oc.BFD_SESSION_STATE_UP, apiBfdSessionStateToOC(api.BfdSessionState_BFD_SESSION_STATE_UP))
	assert.Equal(oc.BFD_SESSION_STATE_DOWN, apiBfdSessionStateToOC(api.BfdSessionState_BFD_SESSION_STATE_DOWN))
	assert.Equal(oc.BFD_SESSION_STATE_ADMIN_DOWN, apiBfdSessionStateToOC(api.BfdSessionState_BFD_SESSION_STATE_ADMIN_DOWN))
	assert.Equal(oc.BFD_SESSION_STATE_INIT, apiBfdSessionStateToOC(api.BfdSessionState_BFD_SESSION_STATE_INIT))
}

func Test_NewBfdConfigFromAPIStructRejectsOverflow(t *testing.T) {
	assert := assert.New(t)

	_, err := newBfdConfigFromAPIStruct(&api.BfdPeerConfig{Port: 1 << 16})
	assert.Error(err)

	_, err = newBfdConfigFromAPIStruct(&api.BfdPeerConfig{DetectionMultiplier: 1 << 8})
	assert.Error(err)

	config, err := newBfdConfigFromAPIStruct(&api.BfdPeerConfig{
		Enabled:             true,
		Port:                BfdServerPort,
		DetectionMultiplier: 3,
	})
	assert.NoError(err)
	assert.True(config.Enabled)
	assert.Equal(uint16(BfdServerPort), config.Port)
	assert.Equal(uint8(3), config.DetectionMultiplier)
}

func newServer(port uint16) *bfdServer {
	ps := &mockPeerState{}
	s := NewBfdServer(ps, slog.Default())
	s.Start(context.Background(), oc.BfdConfig{ //nolint:errcheck
		Port: port,
	})
	return s
}

func newServerWithMock(port uint16) (*bfdServer, *mockPeerState) {
	ps := &mockPeerState{}
	s := NewBfdServer(ps, slog.Default())
	s.Start(context.Background(), oc.BfdConfig{ //nolint:errcheck
		Port: port,
	})
	return s, ps
}

func addPeer(s *bfdServer, port uint16) error {
	return s.AddPeer(context.Background(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     port,
		Enabled:                  true,
		DetectionMultiplier:      5,
		RequiredMinimumReceive:   200000,
		DesiredMinimumTxInterval: 200000,
	}, "")
}

func Test_AddPeerLocalAddressAndBindInterface(t *testing.T) {
	s := newServer(0)
	defer s.Stop()

	peerAddress := netip.MustParseAddr("127.0.0.1")
	localAddress := netip.MustParseAddr("127.0.0.2")
	err := s.addPeer(context.Background(), peerAddress, oc.BfdConfig{Enabled: true}, localAddress, "lo")
	assert.NoError(t, err)

	err = eventually(time.Second, func() error {
		s.peersMutex.RLock()
		defer s.peersMutex.RUnlock()

		peer := s.peers[peerAddress]
		if peer == nil {
			return fmt.Errorf("BFD peer not created")
		}

		if peer.localAddress != localAddress || peer.bindInterface != "lo" {
			return fmt.Errorf("unexpected BFD source configuration: address=%s interface=%q", peer.localAddress, peer.bindInterface)
		}

		return nil
	})
	assert.NoError(t, err)
}

func Test_BgpUpdatePeerLocalAddress(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()
	defer s.Stop()
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 1, RouterId: "1.1.1.1", ListenPort: -1},
	}))

	peerAddress := netip.MustParseAddr("127.0.0.2")
	p := &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: peerAddress.String(), PeerAsn: 2},
		Transport: &api.Transport{LocalAddress: "127.0.0.1", PassiveMode: true},
		Bfd:       &api.BfdPeerConfig{Enabled: true},
	}
	require.NoError(t, s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: p}))

	checkPeer := func(previous *bfdPeer) *bfdPeer {
		t.Helper()
		var current *bfdPeer
		require.NoError(t, eventually(time.Second, func() error {
			s.bfdServer.peersMutex.RLock()
			defer s.bfdServer.peersMutex.RUnlock()
			current = s.bfdServer.peers[peerAddress]
			if current == nil || current == previous || current.localAddress.String() != p.Transport.LocalAddress {
				return fmt.Errorf("BFD peer was not recreated with local address %s", p.Transport.LocalAddress)
			}
			return nil
		}))
		return current
	}
	oldPeer := checkPeer(nil)
	var oldNeighbor *peer
	require.NoError(t, s.mgmtOperation(func() error {
		oldNeighbor = s.neighborMap[peerAddress]
		return nil
	}, true))

	// Transport changes recreate the neighbor, including its BFD session.
	p.Transport.LocalAddress = "127.0.0.3"
	_, err := s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: p})
	require.NoError(t, err)
	oldPeer = checkPeer(oldPeer)
	require.NoError(t, s.mgmtOperation(func() error {
		assert.NotSame(t, oldNeighbor, s.neighborMap[peerAddress])
		oldNeighbor = s.neighborMap[peerAddress]
		return nil
	}, true))

	// BFD-only changes retain the neighbor and preserve the source address.
	p.Bfd.DetectionMultiplier = 7
	_, err = s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: p})
	require.NoError(t, err)
	unchangedPeer := checkPeer(oldPeer)
	require.NoError(t, s.mgmtOperation(func() error {
		assert.Same(t, oldNeighbor, s.neighborMap[peerAddress])
		return nil
	}, true))

	_, err = s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: p})
	require.NoError(t, err)
	s.bfdServer.peersMutex.RLock()
	assert.Same(t, unchangedPeer, s.bfdServer.peers[peerAddress])
	s.bfdServer.peersMutex.RUnlock()
}

type bfdLocalAddrConn struct {
	*net.TCPConn
	localAddr *net.TCPAddr
}

func (c *bfdLocalAddrConn) LocalAddr() net.Addr {
	return c.localAddr
}

func Test_DynamicNeighborBfdLocalAddress(t *testing.T) {
	for _, tt := range []struct {
		name, network, address, prefix, localAddress, zone string
	}{
		{"IPv4 unset", "tcp4", "127.0.0.1:0", "127.0.0.0/8", "", ""},
		{"IPv4 wildcard", "tcp4", "127.0.0.1:0", "127.0.0.0/8", "0.0.0.0", ""},
		{"IPv6 unset", "tcp6", "[::1]:0", "::1/128", "", ""},
		{"IPv6 wildcard", "tcp6", "[::1]:0", "::1/128", "::", ""},
		{"IPv6 zone", "tcp6", "[::1]:0", "::1/128", "::", "test-zone"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := NewBgpServer()
			go s.Serve()
			defer s.Stop()
			require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
				Global: &api.Global{Asn: 1, RouterId: "1.1.1.1", ListenPort: -1},
			}))
			require.NoError(t, s.AddPeerGroup(context.Background(), &api.AddPeerGroupRequest{
				PeerGroup: &api.PeerGroup{
					Conf:      &api.PeerGroupConf{PeerGroupName: "dynamic", PeerAsn: 2},
					Transport: &api.Transport{LocalAddress: tt.localAddress},
					Bfd:       &api.BfdPeerConfig{Enabled: true},
				},
			}))
			require.NoError(t, s.AddDynamicNeighbor(context.Background(), &api.AddDynamicNeighborRequest{
				DynamicNeighbor: &api.DynamicNeighbor{Prefix: tt.prefix, PeerGroup: "dynamic"},
			}))

			listener, err := net.Listen(tt.network, tt.address)
			require.NoError(t, err)
			defer listener.Close()
			client, err := net.DialTimeout(tt.network, listener.Addr().String(), time.Second)
			require.NoError(t, err)
			defer client.Close()
			conn, err := listener.Accept()
			require.NoError(t, err)
			defer conn.Close()
			if tt.zone != "" {
				// Loopback sockets have no zone; supply one to check scope preservation
				// without requiring a configured link-local interface on the test host.
				localAddr := *conn.LocalAddr().(*net.TCPAddr)
				localAddr.Zone = tt.zone
				conn = &bfdLocalAddrConn{TCPConn: conn.(*net.TCPConn), localAddr: &localAddr}
			}
			localAddress := conn.LocalAddr().(*net.TCPAddr).AddrPort().Addr()
			peerAddress := conn.RemoteAddr().(*net.TCPAddr).AddrPort().Addr()

			require.NoError(t, s.mgmtOperation(func() error {
				s.passConnToPeer(conn)
				return nil
			}, true))
			s.bfdServer.peersMutex.RLock()
			initial := s.bfdServer.peers[peerAddress]
			s.bfdServer.peersMutex.RUnlock()
			require.Nil(t, initial, "BFD with an inferred source waits for TCP Established")
			open, err := bgp.NewBGPOpenMessage(2, 90, netip.MustParseAddr("2.2.2.2"), nil)
			require.NoError(t, err)
			for _, msg := range []*bgp.BGPMessage{open, bgp.NewBGPKeepAliveMessage()} {
				wire, err := msg.Serialize()
				require.NoError(t, err)
				_, err = client.Write(wire)
				require.NoError(t, err)
			}
			require.NoError(t, eventually(time.Second, func() error {
				s.bfdServer.peersMutex.RLock()
				defer s.bfdServer.peersMutex.RUnlock()
				p := s.bfdServer.peers[peerAddress]
				if p == nil {
					return fmt.Errorf("BFD peer not created")
				}
				if p.localAddress != localAddress {
					return fmt.Errorf("BFD source %s does not match accepted socket address %s", p.localAddress, localAddress)
				}
				return nil
			}))
		})
	}
}

func Test_AddDeletePeer(t *testing.T) {
	assert := assert.New(t)

	s1 := newServer(13784)
	defer s1.Stop()

	// Add peer
	err := addPeer(s1, 23784)
	assert.NoError(err)

	// Wait bfdServer.loop() thread
	time.Sleep(time.Second * 2)

	// Get state
	state, err := s1.GetPeerState(netip.MustParseAddr("127.0.0.1"))
	assert.NotNil(state)
	assert.NoError(err)

	assert.Equal(state.peerAddress, netip.MustParseAddr("127.0.0.1"))

	// Delete peer
	err = s1.DeletePeer(context.Background(), netip.MustParseAddr("127.0.0.1"))
	assert.NoError(err)

	// Wait bfdServer.loop() thread
	time.Sleep(time.Second * 2)

	// Get state
	state, err = s1.GetPeerState(netip.MustParseAddr("127.0.0.1"))
	assert.Nil(state)
	assert.Error(err)
}

func Test_StateUpDown(t *testing.T) {
	assert := assert.New(t)

	s1 := newServer(13784)
	defer s1.Stop()

	s2 := newServer(23784)

	// Add peer
	err := addPeer(s1, 23784)
	assert.NoError(err)

	// Add peer
	err = addPeer(s2, 13784)
	assert.NoError(err)

	// Establishment is now paced at up to one second per handshake step (RFC 5880
	// Section 6.8.3's not-Up floor: Down and Init both transmit at no faster than 1s),
	// so reaching Up on both sides can take ~3s rather than being near-instant.
	err = eventuallyCheckState(6*time.Second, s1, netip.MustParseAddr("127.0.0.1"), api.BfdSessionState_BFD_SESSION_STATE_UP)
	assert.NoError(err)
	err = eventuallyCheckState(6*time.Second, s2, netip.MustParseAddr("127.0.0.1"), api.BfdSessionState_BFD_SESSION_STATE_UP)
	assert.NoError(err)

	// Get state
	state, err := s1.GetPeerState(netip.MustParseAddr("127.0.0.1"))
	assert.NotNil(state)
	assert.NoError(err)
	assert.Equal(state.state.SessionState, api.BfdSessionState_BFD_SESSION_STATE_UP)
	assert.NotEqual(state.state.BfdAsync.ReceivedPackets, uint64(0))
	assert.NotEqual(state.state.BfdAsync.TransmittedPackets, uint64(0))

	// Get state
	state, err = s2.GetPeerState(netip.MustParseAddr("127.0.0.1"))
	assert.NotNil(state)
	assert.NoError(err)
	assert.Equal(state.state.SessionState, api.BfdSessionState_BFD_SESSION_STATE_UP)
	assert.NotEqual(state.state.BfdAsync.ReceivedPackets, uint64(0))
	assert.NotEqual(state.state.BfdAsync.TransmittedPackets, uint64(0))

	// s2 restored its 200ms interval on reaching Up, but s1 only learns that from
	// s2's first Up packet, which is paced (up to 200ms away). Wait for it, or s1's
	// detection time is still the not-Up 5 x 1s and the 2s wait below fails.
	received := state.state.BfdAsync.ReceivedPackets
	err = eventuallyReceivesAfter(2*time.Second, s1, netip.MustParseAddr("127.0.0.1"), received)
	assert.NoError(err)

	// Stop s2
	s2.Stop()

	// Check state
	err = eventuallyCheckState(2*time.Second, s1, netip.MustParseAddr("127.0.0.1"), api.BfdSessionState_BFD_SESSION_STATE_DOWN)
	assert.NoError(err)
}

func Test_StateUpDownIPv6(t *testing.T) {
	if !canListenUDP("udp6", "[::1]:0") {
		t.Skip("IPv6 loopback is not available")
	}

	assert := assert.New(t)
	peerAddress := netip.MustParseAddr("::1")
	config := func(port uint16) oc.BfdConfig {
		return oc.BfdConfig{
			Port:                     port,
			Enabled:                  true,
			DetectionMultiplier:      5,
			RequiredMinimumReceive:   200000,
			DesiredMinimumTxInterval: 200000,
		}
	}

	s1 := newServer(13786)
	defer s1.Stop()
	s2 := newServer(23786)
	defer s2.Stop()

	assert.NoError(s1.AddPeer(context.Background(), peerAddress, config(23786), ""))
	assert.NoError(s2.AddPeer(context.Background(), peerAddress, config(13786), ""))

	assert.NoError(eventuallyCheckState(6*time.Second, s1, peerAddress, api.BfdSessionState_BFD_SESSION_STATE_UP))
	assert.NoError(eventuallyCheckState(6*time.Second, s2, peerAddress, api.BfdSessionState_BFD_SESSION_STATE_UP))
}

func canListenUDP(network, address string) bool {
	conn, err := net.ListenPacket(network, address)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func Test_BfdServerRxInfo(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ancillary data checked on Linux only")
	}
	lo, err := net.InterfaceByName("lo")
	require.NoError(t, err)

	for _, tt := range []struct {
		name    string
		network string
		address string
	}{
		{"IPv4", "udp4", "127.0.0.1"},
		{"IPv6", "udp6", "::1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := net.ListenUDP(tt.network, &net.UDPAddr{IP: net.ParseIP(tt.address)})
			if err != nil {
				t.Skipf("can't listen on %s: %v", tt.address, err)
			}
			defer conn.Close()

			s := &bfdServer{logger: slog.Default()}
			read := s.ipv4Reader(conn)
			if tt.network == "udp6" {
				read = s.ipv6Reader(conn)
			}

			sender, err := net.DialUDP(tt.network, nil, conn.LocalAddr().(*net.UDPAddr))
			require.NoError(t, err)
			defer sender.Close()
			require.NoError(t, netutils.SetUDPTTLSockopt(sender, 200))
			_, err = sender.Write([]byte{1})
			require.NoError(t, err)

			require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
			n, info, err := read(make([]byte, 64))
			require.NoError(t, err)

			assert.Equal(t, 1, n)
			assert.Equal(t, sender.LocalAddr().(*net.UDPAddr).AddrPort(), info.src)
			assert.Equal(t, netip.MustParseAddr(tt.address), info.dst)
			assert.Equal(t, lo.Index, info.ifIndex)
			assert.Equal(t, 200, info.ttl)
			assert.False(t, info.mhop)
		})
	}
}

// Test_BfdServerListenerFailureIsIndependent checks that a receive socket
// that can't be opened does not keep the other one closed, and that the
// next start() opens it once the port is free.
func Test_BfdServerListenerFailureIsIndependent(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("relies on Linux SO_REUSEADDR semantics for a bind conflict")
	}

	// Without SO_REUSEADDR, this socket makes the server's IPv6 bind fail.
	occupier, err := net.ListenPacket("udp6", "[::]:0")
	if err != nil {
		t.Skipf("IPv6 is not available: %v", err)
	}
	port := occupier.LocalAddr().(*net.UDPAddr).Port

	// Build the server directly, without the loop goroutine, so start()
	// and stop() run only when the test calls them.
	s := &bfdServer{
		logger:    slog.Default(),
		peers:     make(map[netip.Addr]*bfdPeer),
		listeners: newBfdListeners(),
		config:    &oc.BfdConfig{Port: uint16(port)},
	}
	udp4, udp6 := s.listeners[0], s.listeners[1]

	assert.False(t, s.start())
	assert.NotNil(t, udp4.conn)
	assert.Nil(t, udp6.conn)
	assert.True(t, udp6.failed)

	require.NoError(t, occupier.Close())
	assert.True(t, s.start())
	assert.NotNil(t, udp4.conn)
	assert.NotNil(t, udp6.conn)
	assert.False(t, udp6.failed)

	s.stop()
	assert.Nil(t, udp4.conn)
	assert.Nil(t, udp6.conn)
}

func Test_BfdServerNewDiscriminatorSkipsUsed(t *testing.T) {
	values := []uint32{5, 5, 7}
	s := &bfdServer{
		discrs: map[uint32]*bfdPeer{5: {}},
		randomDiscriminator: func() uint32 {
			v := values[0]
			values = values[1:]
			return v
		},
	}

	assert.Equal(t, uint32(7), s.newDiscriminator())
	assert.Empty(t, values)
}

func Test_BfdServerLookupPeer(t *testing.T) {
	v4 := &bfdPeer{
		peerAddress:     netip.MustParseAddr("192.0.2.2"),
		localAddress:    netip.MustParseAddr("192.0.2.1"),
		myDiscriminator: 100,
	}
	ll := &bfdPeer{
		peerAddress:     netip.MustParseAddr("fe80::2%eth0"),
		localAddress:    netip.MustParseAddr("fe80::1%eth0"),
		myDiscriminator: 200,
	}
	noLocal := &bfdPeer{
		peerAddress:     netip.MustParseAddr("192.0.2.3"),
		localAddress:    netip.IPv4Unspecified(),
		myDiscriminator: 300,
	}
	s := &bfdServer{
		peers:  map[netip.Addr]*bfdPeer{},
		discrs: map[uint32]*bfdPeer{},
	}
	for _, p := range []*bfdPeer{v4, ll, noLocal} {
		s.peers[p.peerAddress] = p
		s.discrs[p.myDiscriminator] = p
	}

	rx := func(src, dst string) bfdRxInfo {
		info := bfdRxInfo{
			src: netip.AddrPortFrom(netip.MustParseAddr(src), 49152),
			ttl: 255,
		}
		if dst != "" {
			info.dst = netip.MustParseAddr(dst)
		}
		return info
	}

	for _, tt := range []struct {
		name string
		info bfdRxInfo
		your uint32
		want *bfdPeer
	}{
		{"discriminator", rx("192.0.2.2", "192.0.2.1"), 100, v4},
		{"discriminator from another source", rx("198.51.100.1", "192.0.2.1"), 100, v4},
		{"discriminator to another destination", rx("192.0.2.2", "192.0.2.9"), 100, v4},
		{"unknown discriminator", rx("192.0.2.2", "192.0.2.1"), 999, nil},
		{"zero, address match", rx("192.0.2.2", "192.0.2.1"), 0, v4},
		{"zero, unknown source", rx("198.51.100.1", "192.0.2.1"), 0, nil},
		{"zero, other destination", rx("192.0.2.2", "192.0.2.9"), 0, nil},
		{"zero, destination unknown", rx("192.0.2.2", ""), 0, v4},
		{"zero, local address unspecified", rx("192.0.2.3", "192.0.2.9"), 0, noLocal},
		{"zero, link-local", rx("fe80::2%eth0", "fe80::1"), 0, ll},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := s.lookupPeer(tt.info, &bfd.BFDHeader{YourDiscriminator: tt.your})
			assert.Same(t, tt.want, got)
		})
	}
}

func Test_BfdServerRxPacketUnknownDiscriminator(t *testing.T) {
	s := newServer(13787)
	defer s.Stop()
	require.NoError(t, addPeer(s, 23787))

	s.peersMutex.RLock()
	peer := s.peers[netip.MustParseAddr("127.0.0.1")]
	s.peersMutex.RUnlock()
	require.NotNil(t, peer)
	unknown := peer.myDiscriminator + 1
	if unknown == 0 {
		unknown = 1
	}

	s.rxPacket(bfdRxInfo{
		src: netip.MustParseAddrPort("127.0.0.1:49152"),
		ttl: 255,
	}, &bfd.BFDHeader{
		State:                bfd.StateUp,
		DetectTimeMultiplier: 3,
		MyDiscriminator:      1,
		YourDiscriminator:    unknown,
	})
	assert.Equal(t, uint64(1), s.stats.unknownPeer.Load())
	assert.Equal(t, uint64(0), s.stats.rxPacket.Load())
}

func Test_BfdServerRxPacketTTL(t *testing.T) {
	s := newServer(13788)
	defer s.Stop()
	require.NoError(t, addPeer(s, 23788))

	s.peersMutex.RLock()
	peer := s.peers[netip.MustParseAddr("127.0.0.1")]
	s.peersMutex.RUnlock()
	require.NotNil(t, peer)

	delivered := func() uint64 {
		return s.stats.rxPacket.Load() + s.stats.rxDrop.Load()
	}
	for _, tt := range []struct {
		ttl       int
		discarded bool
	}{
		{254, true},
		{64, true},
		{0, true}, // the socket reports the TTL, but the packet came without it
		{255, false},
		{-1, false}, // the socket can't report the TTL
	} {
		t.Run(fmt.Sprintf("TTL %d", tt.ttl), func(t *testing.T) {
			invalid, ok := peer.stats.invalidTTL.Load(), delivered()
			s.rxPacket(bfdRxInfo{
				src: netip.MustParseAddrPort("127.0.0.1:49152"),
				ttl: tt.ttl,
			}, &bfd.BFDHeader{
				State:                bfd.StateDown,
				DetectTimeMultiplier: 3,
				MyDiscriminator:      1,
				YourDiscriminator:    peer.myDiscriminator,
			})
			if tt.discarded {
				assert.Equal(t, invalid+1, peer.stats.invalidTTL.Load())
				assert.Equal(t, ok, delivered())
			} else {
				assert.Equal(t, invalid, peer.stats.invalidTTL.Load())
				assert.Equal(t, ok+1, delivered())
			}
		})
	}
}

// Test_BfdServerDiscardsWrongTTL sends real packets, as in issue #3738:
// a packet with TTL 64 must not reach the session, one with 255 must.
func Test_BfdServerDiscardsWrongTTL(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("TTL checked on Linux only")
	}

	for _, tt := range []struct {
		name    string
		network string
		address string
		port    uint16
	}{
		{"IPv4", "udp4", "127.0.0.1", 13789},
		{"IPv6", "udp6", "::1", 13790},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if !canListenUDP(tt.network, net.JoinHostPort(tt.address, "0")) {
				t.Skipf("%s is not available", tt.address)
			}
			peerAddress := netip.MustParseAddr(tt.address)

			s := newServer(tt.port)
			defer s.Stop()
			require.NoError(t, s.AddPeer(context.Background(), peerAddress, oc.BfdConfig{
				Port:                     tt.port + 10000,
				Enabled:                  true,
				DetectionMultiplier:      5,
				RequiredMinimumReceive:   200000,
				DesiredMinimumTxInterval: 200000,
			}, ""))
			s.peersMutex.RLock()
			peer := s.peers[peerAddress]
			s.peersMutex.RUnlock()
			require.NotNil(t, peer)

			send := func(ttl int) {
				t.Helper()
				conn, err := net.DialUDP(tt.network, nil, &net.UDPAddr{IP: peerAddress.AsSlice(), Port: int(tt.port)})
				require.NoError(t, err)
				defer conn.Close()
				require.NoError(t, netutils.SetUDPTTLSockopt(conn, ttl))
				b, err := (&bfd.BFDHeader{
					Version:               1,
					State:                 bfd.StateDown,
					DetectTimeMultiplier:  3,
					MyDiscriminator:       1,
					DesiredMinTxInterval:  1000000,
					RequiredMinRxInterval: 1000000,
				}).MarshalBinary()
				require.NoError(t, err)
				_, err = conn.Write(b)
				require.NoError(t, err)
			}

			// The listeners open on the next tick of the server loop, so
			// send until the packet is seen.
			require.NoError(t, eventually(3*time.Second, func() error {
				send(64)
				if peer.stats.invalidTTL.Load() == 0 {
					return fmt.Errorf("TTL 64 packet not discarded yet")
				}
				return nil
			}))
			assert.Equal(t, uint64(0), s.stats.rxPacket.Load()+s.stats.rxDrop.Load())

			require.NoError(t, eventually(3*time.Second, func() error {
				send(255)
				if s.stats.rxPacket.Load()+s.stats.rxDrop.Load() == 0 {
					return fmt.Errorf("TTL 255 packet not received yet")
				}
				return nil
			}))
		})
	}
}

func Test_BfdDown(t *testing.T) {
	assert := assert.New(t)

	s1, m1 := newServerWithMock(13784)

	s2 := newServer(23784)

	// Add peer
	err := addPeer(s1, 23784)
	assert.NoError(err)

	// Add peer
	err = addPeer(s2, 13784)
	assert.NoError(err)

	// Establishment is now paced at up to one second per handshake step (RFC 5880
	// Section 6.8.3's not-Up floor), so wait for Up instead of assuming a fixed sleep
	// covers it. Reaching Up also matters for the wait below: while not yet Up, both
	// sides advertise the floored (slow) interval, which inflates the detection time
	// (Section 6.8.4) that governs how long the peer below takes to notice s2 is gone.
	err = eventuallyCheckState(6*time.Second, s1, netip.MustParseAddr("127.0.0.1"), api.BfdSessionState_BFD_SESSION_STATE_UP)
	assert.NoError(err)
	err = eventuallyCheckState(6*time.Second, s2, netip.MustParseAddr("127.0.0.1"), api.BfdSessionState_BFD_SESSION_STATE_UP)
	assert.NoError(err)

	// s1 learns s2's restored 200ms interval only from s2's first Up packet, which is
	// paced (up to 200ms away). Wait for it so the detection time below is the Up
	// 5 x 200ms, not the not-Up 5 x 1s.
	state, err := s1.GetPeerState(netip.MustParseAddr("127.0.0.1"))
	assert.NoError(err)
	err = eventuallyReceivesAfter(2*time.Second, s1, netip.MustParseAddr("127.0.0.1"), state.state.BfdAsync.ReceivedPackets)
	assert.NoError(err)

	// Stop s2
	s2.Stop()

	// Wait for BFD peer down to close s1's BGP session.
	err = eventually(6*time.Second, func() error {
		if atomic.LoadInt64(&m1.bfdDownCount) == 1 {
			return nil
		}
		return fmt.Errorf("must be: bfdDownCount == 1")
	})
	assert.NoError(err)

	s1.Stop()

	assert.Equal(int64(1), atomic.LoadInt64(&m1.bfdDownCount))
}

func Test_BgpAddDeletePeer(t *testing.T) {
	assert := assert.New(t)

	s := NewBgpServer()
	go s.Serve()
	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        1,
			RouterId:   "1.1.1.1",
			ListenPort: 10179,
		},
	})
	assert.NoError(err)
	defer s.Stop()

	localAddress := netip.MustParseAddr("127.0.0.10")
	nConf1 := &oc.Neighbor{
		Config: oc.NeighborConfig{
			NeighborAddress: netip.MustParseAddr("127.0.0.1"),
			PeerGroup:       "group_on",
		},
	}
	nConf2 := &oc.Neighbor{
		Config: oc.NeighborConfig{
			NeighborAddress: netip.MustParseAddr("127.0.0.2"),
			PeerGroup:       "group_on",
		},
	}
	pgConf := &oc.PeerGroup{
		Config: oc.PeerGroupConfig{
			PeerGroupName: "group_on",
		},
		Transport: oc.Transport{
			Config: oc.TransportConfig{
				LocalAddress: localAddress,
			},
		},
		Bfd: oc.Bfd{
			Config: oc.BfdConfig{
				Enabled:                  true,
				DetectionMultiplier:      7,
				RequiredMinimumReceive:   123000,
				DesiredMinimumTxInterval: 456000,
			},
		},
	}
	gConf := &oc.Global{}

	err = oc.SetDefaultNeighborConfigValues(nConf1, pgConf, gConf)
	assert.NoError(err)
	err = oc.SetDefaultNeighborConfigValues(nConf2, pgConf, gConf)
	assert.NoError(err)

	// Add 'group_on' with enabled BFD
	err = s.AddPeerGroup(context.Background(), &api.AddPeerGroupRequest{
		PeerGroup: oc.NewPeerGroupFromConfigStruct(pgConf),
	})
	assert.NoError(err)

	var count int

	// Add 1 peer
	err = s.AddPeer(context.Background(), &api.AddPeerRequest{
		Peer: oc.NewPeerFromConfigStruct(nConf1),
	})
	assert.NoError(err)
	time.Sleep(time.Second)

	count = 0
	s.ListBfdPeer(context.Background(), func(peerAddress string, state *api.BfdPeerState) {
		count++
	})
	assert.Equal(count, 1)

	s.bfdServer.peersMutex.RLock()
	assert.Equal(localAddress, s.bfdServer.peers[nConf1.Config.NeighborAddress].localAddress)
	s.bfdServer.peersMutex.RUnlock()

	// Delete 1 peer
	err = s.DeletePeer(context.Background(), &api.DeletePeerRequest{
		Address: "127.0.0.1",
	})
	assert.NoError(err)
	time.Sleep(time.Second)

	count = 0
	s.ListBfdPeer(context.Background(), func(peerAddress string, state *api.BfdPeerState) {
		count++
	})
	assert.Equal(count, 0)

	// Add 2 peer
	err = s.AddPeer(context.Background(), &api.AddPeerRequest{
		Peer: oc.NewPeerFromConfigStruct(nConf1),
	})
	assert.NoError(err)
	err = s.AddPeer(context.Background(), &api.AddPeerRequest{
		Peer: oc.NewPeerFromConfigStruct(nConf2),
	})
	assert.NoError(err)
	time.Sleep(time.Second)

	count = 0
	s.ListBfdPeer(context.Background(), func(peerAddress string, state *api.BfdPeerState) {
		count++
	})
	assert.Equal(count, 2)

	// Delete 1 peer
	err = s.DeletePeer(context.Background(), &api.DeletePeerRequest{
		Address: "127.0.0.1",
	})
	assert.NoError(err)
	time.Sleep(time.Second)

	count = 0
	s.ListBfdPeer(context.Background(), func(peerAddress string, state *api.BfdPeerState) {
		count++
	})
	assert.Equal(count, 1)

	// Delete 1 peer
	err = s.DeletePeer(context.Background(), &api.DeletePeerRequest{
		Address: "127.0.0.2",
	})
	assert.NoError(err)
	time.Sleep(time.Second)

	count = 0
	s.ListBfdPeer(context.Background(), func(peerAddress string, state *api.BfdPeerState) {
		count++
	})
	assert.Equal(count, 0)
}

func Test_BgpAddDeletePeerWithDisabledBfd(t *testing.T) {
	assert := assert.New(t)

	s := NewBgpServer()
	go s.Serve()
	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        1,
			RouterId:   "1.1.1.1",
			ListenPort: 10179,
		},
	})
	assert.NoError(err)
	defer s.Stop()

	nConf1 := &oc.Neighbor{
		Config: oc.NeighborConfig{
			NeighborAddress: netip.MustParseAddr("127.0.0.1"),
			PeerGroup:       "group_off",
		},
	}
	nConf2 := &oc.Neighbor{
		Config: oc.NeighborConfig{
			NeighborAddress: netip.MustParseAddr("127.0.0.2"),
			PeerGroup:       "group_on",
		},
	}
	pgConf1 := &oc.PeerGroup{
		Config: oc.PeerGroupConfig{
			PeerGroupName: "group_off",
		},
	}
	pgConf2 := &oc.PeerGroup{
		Config: oc.PeerGroupConfig{
			PeerGroupName: "group_on",
		},
		// Explicit sources can start BFD before TCP establishes.
		Transport: oc.Transport{Config: oc.TransportConfig{LocalAddress: netip.MustParseAddr("127.0.0.1")}},
		Bfd: oc.Bfd{
			Config: oc.BfdConfig{
				Enabled:                  true,
				DetectionMultiplier:      7,
				RequiredMinimumReceive:   123000,
				DesiredMinimumTxInterval: 456000,
			},
		},
	}
	gConf := &oc.Global{}

	err = oc.SetDefaultNeighborConfigValues(nConf1, pgConf1, gConf)
	assert.NoError(err)
	err = oc.SetDefaultNeighborConfigValues(nConf2, pgConf2, gConf)
	assert.NoError(err)

	// Add 'group_on' with enabled BFD
	err = s.AddPeerGroup(context.Background(), &api.AddPeerGroupRequest{
		PeerGroup: oc.NewPeerGroupFromConfigStruct(pgConf1),
	})
	assert.NoError(err)

	// Add 'group_off' without BFD
	err = s.AddPeerGroup(context.Background(), &api.AddPeerGroupRequest{
		PeerGroup: oc.NewPeerGroupFromConfigStruct(pgConf2),
	})
	assert.NoError(err)

	var count int

	// Add 1 peer (group_off)
	err = s.AddPeer(context.Background(), &api.AddPeerRequest{
		Peer: oc.NewPeerFromConfigStruct(nConf1),
	})
	assert.NoError(err)
	time.Sleep(time.Second)

	count = 0
	s.ListBfdPeer(context.Background(), func(peerAddress string, state *api.BfdPeerState) {
		count++
	})
	assert.Equal(count, 0)

	// Add 1 peer (group_on)
	err = s.AddPeer(context.Background(), &api.AddPeerRequest{
		Peer: oc.NewPeerFromConfigStruct(nConf2),
	})
	assert.NoError(err)
	time.Sleep(time.Second)

	count = 0
	s.ListBfdPeer(context.Background(), func(peerAddress string, state *api.BfdPeerState) {
		count++
	})
	assert.Equal(count, 1)

	// Delete 1 peer (group_on)
	err = s.DeletePeer(context.Background(), &api.DeletePeerRequest{
		Address: "127.0.0.2",
	})
	assert.NoError(err)
	time.Sleep(time.Second)

	count = 0
	s.ListBfdPeer(context.Background(), func(peerAddress string, state *api.BfdPeerState) {
		count++
	})
	assert.Equal(count, 0)

	// Delete 1 peer (group_off)
	err = s.DeletePeer(context.Background(), &api.DeletePeerRequest{
		Address: "127.0.0.1",
	})
	assert.NoError(err)
	time.Sleep(time.Second)

	count = 0
	s.ListBfdPeer(context.Background(), func(peerAddress string, state *api.BfdPeerState) {
		count++
	})
	assert.Equal(count, 0)
}

func Test_BgpUpdatePeerBfdConfig(t *testing.T) {
	assert := assert.New(t)

	s := NewBgpServer()
	go s.Serve()
	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        1,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	assert.NoError(err)
	defer s.Stop()

	peer := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "127.0.0.3",
			PeerAsn:         1,
		},
		Transport: &api.Transport{LocalAddress: "127.0.0.1"},
		Bfd:       &api.BfdPeerConfig{Enabled: false},
	}

	err = s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: peer})
	assert.NoError(err)

	countBfdPeers := func() int {
		count := 0
		s.ListBfdPeer(context.Background(), func(peerAddress string, state *api.BfdPeerState) {
			count++
		})
		return count
	}

	assert.Equal(0, countBfdPeers())

	peer.Bfd = &api.BfdPeerConfig{
		Enabled:                  true,
		Port:                     BfdServerPort,
		DetectionMultiplier:      3,
		RequiredMinimumReceive:   1000000,
		DesiredMinimumTxInterval: 1000000,
	}
	_, err = s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: peer})
	assert.NoError(err)

	err = eventually(time.Second, func() error {
		if countBfdPeers() == 1 {
			return nil
		}
		return fmt.Errorf("must be: bfd peer count == 1")
	})
	assert.NoError(err)

	peer.Bfd.Enabled = false
	_, err = s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: peer})
	assert.NoError(err)

	err = eventually(time.Second, func() error {
		if countBfdPeers() == 0 {
			return nil
		}
		return fmt.Errorf("must be: bfd peer count == 0")
	})
	assert.NoError(err)
}

func Test_BfdServer_NoGoroutineLeakAfterStop(t *testing.T) {
	defer goleak.VerifyNone(t)

	assert := assert.New(t)
	ps := &mockPeerState{}
	s := NewBfdServer(ps, slog.Default())
	err := s.Start(context.Background(), oc.BfdConfig{
		Port: 33884,
	})
	assert.NoError(err)

	err = s.AddPeer(context.Background(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
		Port:                     44884,
		Enabled:                  true,
		DetectionMultiplier:      5,
		RequiredMinimumReceive:   200000,
		DesiredMinimumTxInterval: 200000,
	}, "")
	assert.NoError(err)

	time.Sleep(500 * time.Millisecond)
	s.Stop()
}

func Test_BfdServer_RepeatedLifecycleNoGoroutineLeak(t *testing.T) {
	defer goleak.VerifyNone(t)

	assert := assert.New(t)
	for i := range 8 {
		ps := &mockPeerState{}
		s := NewBfdServer(ps, slog.Default())
		port := uint16(35000 + i)
		err := s.Start(context.Background(), oc.BfdConfig{Port: port})
		assert.NoError(err)
		err = s.AddPeer(context.Background(), netip.MustParseAddr("127.0.0.1"), oc.BfdConfig{
			Port:                     port + 2000,
			Enabled:                  true,
			DetectionMultiplier:      5,
			RequiredMinimumReceive:   200000,
			DesiredMinimumTxInterval: 200000,
		}, "")
		assert.NoError(err)
		time.Sleep(80 * time.Millisecond)
		s.Stop()
		runtime.GC()
		time.Sleep(80 * time.Millisecond)
	}
}

func Test_BfdServer_ConcurrentPublicMethods(t *testing.T) {
	defer goleak.VerifyNone(t)

	assert := assert.New(t)
	ps := &mockPeerState{}
	s := NewBfdServer(ps, slog.Default())
	err := s.Start(context.Background(), oc.BfdConfig{
		Port: 35884,
	})
	assert.NoError(err)

	cfg := oc.BfdConfig{
		Enabled:                  true,
		DetectionMultiplier:      3,
		RequiredMinimumReceive:   100000,
		DesiredMinimumTxInterval: 100000,
	}

	const workers = 48
	const rounds = 40
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error
	addErr := func(err error) {
		if err != nil {
			mu.Lock()
			errs = append(errs, err)
			mu.Unlock()
		}
	}

	wg.Add(workers)
	for w := range workers {
		go func(id int) {
			defer wg.Done()
			peerAddr := netip.MustParseAddr(fmt.Sprintf("127.0.0.%d", id%254+1))
			remotePort := uint16(46000 + id)
			for range rounds {
				addErr(s.Start(context.Background(), oc.BfdConfig{Port: 35884}))
				addErr(s.AddPeer(context.Background(), peerAddr, oc.BfdConfig{
					Port:                     remotePort,
					Enabled:                  cfg.Enabled,
					DetectionMultiplier:      cfg.DetectionMultiplier,
					RequiredMinimumReceive:   cfg.RequiredMinimumReceive,
					DesiredMinimumTxInterval: cfg.DesiredMinimumTxInterval,
				}, ""))
				_, _ = s.GetPeerState(peerAddr)
				list := s.GetPeerStateList()
				_ = list
				st := s.GetServerStats()
				_ = st
				addErr(s.DeletePeer(context.Background(), peerAddr))
			}
		}(w)
	}
	wg.Wait()
	assert.Empty(errs, "concurrent public API calls: %v", errs)
	s.Stop()
}
