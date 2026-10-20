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
	flushPeerUpdates := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		// Send no-op deletions on the same FIFO as peer updates. Sending more
		// than its capacity requires the loop to receive a marker, which can
		// only happen after it has finished every earlier update. This works
		// even when DeletePeer returns before its own event is processed.
		for range cap(s.bfdServer.eventPeerUpdate) + 1 {
			if err := s.bfdServer.DeletePeer(ctx, netip.Addr{}); err != nil {
				return err
			}
		}
		return nil
	}
	require.NoError(t, flushPeerUpdates())
	replacement := bfdSourcePeer(s)
	require.NotNil(t, replacement)
	require.NoError(t, s.mgmtOperation(func() error {
		if s.neighborMap[address] == old {
			return fmt.Errorf("transport update did not replace the neighbor")
		}
		s.stopNeighbor(old, bgp.BGP_FSM_ACTIVE, nil)
		return flushPeerUpdates()
	}, true))
	require.True(t, replacement == bfdSourcePeer(s), "obsolete FSM deleted replacement BFD session")
	require.False(t, replacement.stopped.Load())
}

func TestBFDBindInterfacePerNeighborKind(t *testing.T) {
	s := NewBgpServer()
	t.Cleanup(s.bfdServer.Stop)
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
	_, _ = establishBFDSourceTCP(t, s, false, "")
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
}
