package server

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
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
