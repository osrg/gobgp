package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	oc "github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bfd"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/require"
)

func newBFDSourceServer(t *testing.T, dynamic bool) *BgpServer {
	t.Helper()
	s := NewBgpServer()
	go s.Serve()
	t.Cleanup(s.Stop)
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 65001, RouterId: "1.1.1.1", ListenPort: -1},
	}))
	if dynamic {
		require.NoError(t, s.AddPeerGroup(context.Background(), &api.AddPeerGroupRequest{PeerGroup: &api.PeerGroup{
			Conf: &api.PeerGroupConf{PeerGroupName: "dynamic", PeerAsn: 65002},
			Bfd:  &api.BfdPeerConfig{Enabled: true, Port: 13785},
		}}))
		require.NoError(t, s.AddDynamicNeighbor(context.Background(), &api.AddDynamicNeighborRequest{
			DynamicNeighbor: &api.DynamicNeighbor{Prefix: "127.0.0.0/8", PeerGroup: "dynamic"},
		}))
	} else {
		require.NoError(t, s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: &api.Peer{
			Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 65002},
			Transport: &api.Transport{PassiveMode: true},
			Timers:    &api.Timers{Config: &api.TimersConfig{IdleHoldTimeAfterReset: 1}},
			Bfd:       &api.BfdPeerConfig{Enabled: true, Port: 13785},
		}}))
		waitPeerState(t, s, api.PeerState_SESSION_STATE_ACTIVE, 5*time.Second)
	}
	return s
}

func bfdSourcePeer(s *BgpServer) *bfdPeer {
	s.bfdServer.peersMutex.RLock()
	defer s.bfdServer.peersMutex.RUnlock()
	return s.bfdServer.peers[netip.MustParseAddr("127.0.0.1")]
}

// The accepted and outgoing cases both use real TCP sockets and the same
// OPEN/KEEPALIVE exchange. Only connection admission differs.
func establishBFDSourceTCP(t *testing.T, s *BgpServer, outgoing bool, localOverride string) (net.Conn, netip.Addr) {
	t.Helper()
	listenIP := net.ParseIP("127.0.0.1")
	if localOverride != "" && runtime.GOOS == "linux" {
		listenIP = net.ParseIP(localOverride)
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: listenIP})
	require.NoError(t, err)
	defer listener.Close()
	client, err := net.DialTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}, listener.Addr().(*net.TCPAddr))
	require.NoError(t, err)
	accepted, err := listener.AcceptTCP()
	require.NoError(t, err)
	var local net.Conn = accepted
	var remote net.Conn = client
	if outgoing {
		local, remote = client, accepted
	}
	t.Cleanup(func() { local.Close(); remote.Close() })
	if localOverride != "" && runtime.GOOS != "linux" {
		// Linux uses real 127/8 addresses above. Other hosts may not have those
		// aliases; exercise reconnect identity without changing host interfaces.
		local = &bfdLocalAddrConn{TCPConn: local.(*net.TCPConn), localAddr: &net.TCPAddr{IP: net.ParseIP(localOverride)}}
	}
	source := local.LocalAddr().(*net.TCPAddr).AddrPort().Addr().Unmap()
	require.NoError(t, s.mgmtOperation(func() error {
		if outgoing {
			s.neighborMap[netip.MustParseAddr("127.0.0.1")].PassConn(local)
		} else {
			s.passConnToPeer(local)
		}
		return nil
	}, true))
	require.NoError(t, remote.SetDeadline(time.Now().Add(5*time.Second)))
	open, err := bgp.NewBGPOpenMessage(65002, 90, netip.MustParseAddr("2.2.2.2"), nil)
	require.NoError(t, err)
	for _, msg := range []*bgp.BGPMessage{open, bgp.NewBGPKeepAliveMessage()} {
		wire, err := msg.Serialize()
		require.NoError(t, err)
		_, err = remote.Write(wire)
		require.NoError(t, err)
	}
	// Drain OPEN/KEEPALIVE so notification and shutdown writes cannot stall.
	go io.Copy(io.Discard, remote)
	waitPeerState(t, s, api.PeerState_SESSION_STATE_ESTABLISHED, 5*time.Second)
	require.Eventually(t, func() bool { return bfdSourcePeer(s) != nil }, time.Second, time.Millisecond)
	return remote, source
}

// Reproduce the production lock cycle, not just a blocking mock ResetPeer:
// BFD expiry requests management while the lifecycle caller owns shared.mu.
func TestBFDProductionResetRetirement(t *testing.T) {
	s := newBFDSourceServer(t, false)
	address := netip.MustParseAddr("127.0.0.1")
	config := oc.BfdConfig{Enabled: true, Port: 13785}
	require.NoError(t, s.bfdServer.addPeer(context.Background(), address, config, address, ""))
	require.Eventually(t, func() bool { return bfdSourcePeer(s) != nil }, time.Second, time.Millisecond)
	p := bfdSourcePeer(s)
	func() {
		s.shared.mu.Lock()
		defer s.shared.mu.Unlock()
		require.True(t, p.Rx(&bfd.BFDHeader{State: bfd.StateDown, MyDiscriminator: 1, DetectTimeMultiplier: 1, DesiredMinTxInterval: 1000}))
		require.Eventually(t, func() bool { return p.stats.expired.Load() != 0 }, 3*time.Second, time.Millisecond)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		require.NoError(t, s.bfdServer.DeletePeer(ctx, address))
		require.NoError(t, s.bfdServer.addPeer(ctx, address, config, address, ""))
		require.NoError(t, s.bfdServer.DeletePeer(ctx, address))
	}()
	// Flush management after releasing the lock. The canceled reset must not
	// enqueue a notification against this (or any replacement) BGP session.
	require.NoError(t, s.mgmtOperation(func() error {
		if len(s.neighborMap[address].fsm.notification) != 0 {
			return fmt.Errorf("retired BFD session reset the replacement BGP session")
		}
		return nil
	}, true))
}

// Interface binding stays per path: a static neighbor uses only its own
// bind-interface, a dynamic neighbor only the global bind-to-device.
func TestBFDBindInterfacePerNeighborKind(t *testing.T) {
	s := NewBgpServer()
	s.bgpConfig.Global.Config.BindToDevice = "global0"
	static := &oc.Neighbor{}
	static.Config.NeighborAddress = netip.MustParseAddr("127.0.0.1")
	require.Equal(t, "", s.bfdBindInterface(static), "static neighbor must not fall back to bind-to-device")
	static.Transport.Config.BindInterface = "static0"
	require.Equal(t, "static0", s.bfdBindInterface(static))
	dynamic := &oc.Neighbor{}
	dynamic.State.NeighborAddress = netip.MustParseAddr("127.0.0.1")
	dynamic.Transport.Config.BindInterface = "group0"
	require.Equal(t, "global0", s.bfdBindInterface(dynamic), "dynamic neighbor must keep the global bind-to-device")
}

func TestBFDUnspecifiedSourceWaitsForConnection(t *testing.T) {
	s := newBFDSourceServer(t, false)
	require.True(t, bfdSourcePeer(s) == nil, "an unset source must not create a wildcard BFD session before TCP establishes")
}

func TestBFDEstablishedTCPSource(t *testing.T) {
	for _, tt := range []struct {
		name              string
		dynamic, outgoing bool
	}{
		{"accepted-static", false, false}, {"outgoing-static", false, true}, {"accepted-dynamic", true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := newBFDSourceServer(t, tt.dynamic)
			_, source := establishBFDSourceTCP(t, s, tt.outgoing, "")
			require.NoError(t, eventually(time.Second, func() error {
				p := bfdSourcePeer(s)
				if p == nil || p.localAddress.Unmap() != source {
					return fmt.Errorf("BFD source does not match established TCP source %s", source)
				}
				return nil
			}))
		})
	}
}

func TestBFDExplicitSourceSurvivesEstablishment(t *testing.T) {
	s := newBFDSourceServer(t, false)
	config := &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 65002},
		Transport: &api.Transport{PassiveMode: true, LocalAddress: "127.0.0.1"},
		Bfd:       &api.BfdPeerConfig{Enabled: true, Port: 13785},
	}
	_, err := s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: config})
	require.NoError(t, err)
	waitPeerState(t, s, api.PeerState_SESSION_STATE_ACTIVE, 5*time.Second)
	require.Eventually(t, func() bool { return bfdSourcePeer(s) != nil }, time.Second, time.Millisecond)
	previous := bfdSourcePeer(s)
	_, source := establishBFDSourceTCP(t, s, false, "")
	require.True(t, previous == bfdSourcePeer(s), "establishment must not reset an explicitly sourced BFD session")
	require.Equal(t, source, previous.localAddress.Unmap())
}

// An explicit source is authoritative: losing the BGP session must not retire
// (or recreate) the BFD session, exactly as before establishment.
func TestBFDExplicitSourceSurvivesPeerDown(t *testing.T) {
	s := newBFDSourceServer(t, false)
	_, err := s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 65002},
		Transport: &api.Transport{PassiveMode: true, LocalAddress: "127.0.0.1"},
		Timers:    &api.Timers{Config: &api.TimersConfig{IdleHoldTimeAfterReset: 1}},
		Bfd:       &api.BfdPeerConfig{Enabled: true, Port: 13785},
	}})
	require.NoError(t, err)
	waitPeerState(t, s, api.PeerState_SESSION_STATE_ACTIVE, 5*time.Second)
	require.Eventually(t, func() bool { return bfdSourcePeer(s) != nil }, time.Second, time.Millisecond)
	previous := bfdSourcePeer(s)
	remote, _ := establishBFDSourceTCP(t, s, false, "")
	require.NoError(t, remote.Close())
	waitPeerState(t, s, api.PeerState_SESSION_STATE_ACTIVE, 10*time.Second)
	require.True(t, previous == bfdSourcePeer(s), "peer down retired an explicitly sourced BFD session")
	require.False(t, previous.stopped.Load())
}

// An inferred source is kept across a reconnect that yields the same socket
// source; only a changed source replaces the session.
func TestBFDInferredSourceSurvivesSameSourceReconnect(t *testing.T) {
	s := newBFDSourceServer(t, false)
	remote, source := establishBFDSourceTCP(t, s, false, "")
	previous := bfdSourcePeer(s)
	require.NoError(t, remote.Close())
	waitPeerState(t, s, api.PeerState_SESSION_STATE_ACTIVE, 10*time.Second)
	_, again := establishBFDSourceTCP(t, s, false, "")
	require.Equal(t, source, again)
	require.True(t, previous == bfdSourcePeer(s), "same-source reconnect replaced the BFD session")
	require.False(t, previous.stopped.Load())
}

func TestBFDObsoleteFSMCannotDeleteReplacement(t *testing.T) {
	s := newBFDSourceServer(t, false)
	address := netip.MustParseAddr("127.0.0.1")
	var old *peer
	require.NoError(t, s.mgmtOperation(func() error {
		old = s.neighborMap[address]
		return nil
	}, true))
	config := &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: address.String(), PeerAsn: 65002},
		Transport: &api.Transport{PassiveMode: true, LocalAddress: "127.0.0.1"},
		Bfd:       &api.BfdPeerConfig{Enabled: true, Port: 13785},
	}
	_, err := s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: config})
	require.NoError(t, err)
	require.Eventually(t, func() bool { return bfdSourcePeer(s) != nil }, time.Second, time.Millisecond)
	replacement := bfdSourcePeer(s)
	require.NoError(t, s.mgmtOperation(func() error {
		if s.neighborMap[address] == old {
			return fmt.Errorf("transport update did not replace the neighbor")
		}
		s.stopNeighbor(old, bgp.BGP_FSM_ACTIVE, nil)
		return nil
	}, true))
	require.True(t, replacement == bfdSourcePeer(s), "obsolete FSM deleted replacement BFD session")
	require.False(t, replacement.stopped.Load())
}

func TestBFDInferredSourceConfigUpdates(t *testing.T) {
	s := newBFDSourceServer(t, false)
	config := &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 65002},
		Transport: &api.Transport{PassiveMode: true},
		Bfd:       &api.BfdPeerConfig{Enabled: true, Port: 13785, DetectionMultiplier: 7},
	}
	_, err := s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: config})
	require.NoError(t, err)
	require.True(t, bfdSourcePeer(s) == nil, "BFD config update before establishment must still defer source selection")
	_, source := establishBFDSourceTCP(t, s, false, "")
	previous := bfdSourcePeer(s)
	config.Bfd.DetectionMultiplier = 9
	_, err = s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: config})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		p := bfdSourcePeer(s)
		return p != nil && p != previous && p.localAddress.Unmap() == source
	}, time.Second, time.Millisecond)
	require.True(t, previous.stopped.Load())
	config.Bfd.Enabled = false
	_, err = s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: config})
	require.NoError(t, err)
	require.True(t, bfdSourcePeer(s) == nil)
	config.Bfd.Enabled = true
	_, err = s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: config})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		p := bfdSourcePeer(s)
		return p != nil && p.localAddress.Unmap() == source
	}, time.Second, time.Millisecond)
}

// UpdatePeer can reach an accepted dynamic neighbor directly: the request
// carries State.NeighborAddress and no Conf.NeighborAddress, so the neighbor
// keeps its dynamic identity and only the BFD session is replaced. That
// replacement must keep the global bind-to-device and the established source.
func TestBFDDynamicUpdateKeepsGlobalBindToDevice(t *testing.T) {
	const device = "bfd0"
	s := NewBgpServer()
	go s.Serve()
	t.Cleanup(s.Stop)
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 65001, RouterId: "1.1.1.1", ListenPort: -1, BindToDevice: device},
	}))
	require.NoError(t, s.AddPeerGroup(context.Background(), &api.AddPeerGroupRequest{PeerGroup: &api.PeerGroup{
		Conf: &api.PeerGroupConf{PeerGroupName: "dynamic", PeerAsn: 65002},
		Bfd:  &api.BfdPeerConfig{Enabled: true, Port: 13785},
	}}))
	require.NoError(t, s.AddDynamicNeighbor(context.Background(), &api.AddDynamicNeighborRequest{
		DynamicNeighbor: &api.DynamicNeighbor{Prefix: "127.0.0.0/8", PeerGroup: "dynamic"},
	}))
	_, source := establishBFDSourceTCP(t, s, false, "")
	address := netip.MustParseAddr("127.0.0.1")
	var before *peer
	require.NoError(t, s.mgmtOperation(func() error {
		before = s.neighborMap[address]
		return nil
	}, true))
	require.True(t, before.isDynamicNeighbor())
	previous := bfdSourcePeer(s)
	require.Equal(t, device, previous.bindInterface)

	_, err := s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{PeerAsn: 65002, PeerGroup: "dynamic"},
		State:     &api.PeerState{NeighborAddress: address.String()},
		Transport: &api.Transport{PassiveMode: true},
		Bfd:       &api.BfdPeerConfig{Enabled: true, Port: 13785, DetectionMultiplier: 5},
	}})
	require.NoError(t, err)
	require.NoError(t, s.mgmtOperation(func() error {
		if s.neighborMap[address] != before {
			return fmt.Errorf("BFD-only update must not recreate the dynamic neighbor")
		}
		return nil
	}, true))
	require.True(t, before.isDynamicNeighbor(), "BFD-only update must keep the dynamic identity")
	require.Eventually(t, func() bool {
		p := bfdSourcePeer(s)
		return p != nil && p != previous && p.multiplier == 5
	}, time.Second, time.Millisecond)
	require.True(t, previous.stopped.Load())
	current := bfdSourcePeer(s)
	require.Equal(t, device, current.bindInterface, "dynamic neighbor must keep the global bind-to-device across a BFD update")
	require.Equal(t, source, current.localAddress.Unmap(), "BFD update must keep the established source")
}

func TestBFDDynamicConnectionCleanup(t *testing.T) {
	s := newBFDSourceServer(t, true)
	remote, _ := establishBFDSourceTCP(t, s, false, "")
	previous := bfdSourcePeer(s)
	require.NoError(t, remote.Close())
	require.Eventually(t, func() bool { return bfdSourcePeer(s) == nil }, time.Second, time.Millisecond)
	require.True(t, previous.stopped.Load())
	require.Eventually(t, func() bool {
		s.shared.mu.RLock()
		defer s.shared.mu.RUnlock()
		return s.neighborMap[netip.MustParseAddr("127.0.0.1")] == nil
	}, time.Second, time.Millisecond)
}

func TestBFDFailureRetiresSession(t *testing.T) {
	s := newBFDSourceServer(t, false)
	_, _ = establishBFDSourceTCP(t, s, false, "")
	previous := bfdSourcePeer(s)
	require.True(t, previous.Rx(&bfd.BFDHeader{State: bfd.StateDown, MyDiscriminator: 1, DetectTimeMultiplier: 1, DesiredMinTxInterval: 1000}))
	waitPeerState(t, s, api.PeerState_SESSION_STATE_ACTIVE, 10*time.Second)
	require.True(t, previous.stats.expired.Load() != 0)
	// The session stays registered while BGP is down; a reconnect from a
	// different source replaces it and retires the old one.
	require.True(t, previous == bfdSourcePeer(s))
	_, source := establishBFDSourceTCP(t, s, false, "127.0.0.2")
	require.Eventually(t, func() bool {
		current := bfdSourcePeer(s)
		return current != nil && current != previous && current.localAddress.Unmap() == source
	}, time.Second, time.Millisecond)
	require.True(t, previous.stopped.Load())
}

func TestBFDReconnectChangesSourceAndCleansUp(t *testing.T) {
	s := newBFDSourceServer(t, false)
	remote, _ := establishBFDSourceTCP(t, s, false, "")
	previous := bfdSourcePeer(s)
	require.NotNil(t, previous)
	require.NoError(t, remote.Close())
	waitPeerState(t, s, api.PeerState_SESSION_STATE_ACTIVE, 10*time.Second)
	_, source := establishBFDSourceTCP(t, s, false, "127.0.0.2")
	require.Eventually(t, func() bool {
		current := bfdSourcePeer(s)
		return current != nil && current != previous && current.localAddress.Unmap() == source
	}, time.Second, time.Millisecond, "reconnect from a different source must replace the inferred BFD session")
	require.True(t, previous.stopped.Load())
	require.NoError(t, s.DeletePeer(context.Background(), &api.DeletePeerRequest{Address: "127.0.0.1"}))
	require.True(t, bfdSourcePeer(s) == nil)
}
