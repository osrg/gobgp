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
	"github.com/osrg/gobgp/v4/pkg/config/oc"
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
	resetPeerCount int64
}

// ResetPeer implements peerState.
func (m *mockPeerState) ResetPeer(ctx context.Context, r *api.ResetPeerRequest) error {
	atomic.AddInt64(&m.resetPeerCount, 1)
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

func Test_ResetPeer(t *testing.T) {
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

	// Wait for BFD peer down to reset s1's BGP peer.
	err = eventually(6*time.Second, func() error {
		if atomic.LoadInt64(&m1.resetPeerCount) == 1 {
			return nil
		}
		return fmt.Errorf("must be: resetPeerCount == 1")
	})
	assert.NoError(err)

	s1.Stop()

	assert.Equal(int64(1), atomic.LoadInt64(&m1.resetPeerCount))
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
