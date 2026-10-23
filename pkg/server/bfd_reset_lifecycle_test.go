package server

import (
	"context"
	"net/netip"
	"testing"
	"time"

	oc "github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bfd"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/require"
)

// Receive the real bfdDown management operation before retiring the session.
// The dispatcher uses the same shared lock and handler as Serve, but exposes the
// queue boundary so this test never relies on expiry counters or scheduler luck.
func TestBFDQueuedDownRetirement(t *testing.T) {
	for _, action := range []string{"delete", "replace", "stop"} {
		t.Run(action, func(t *testing.T) {
			s := NewBgpServer()
			t.Cleanup(s.bfdServer.Stop)
			s.bgpConfig.Global.Config.As = 65001
			address := netip.MustParseAddr("127.0.0.1")
			config := oc.BfdConfig{Enabled: true, Port: 13785}
			require.NoError(t, s.bfdServer.addPeer(context.Background(), address, config, address, "", 1))
			s.bfdServer.peersMutex.RLock()
			p := s.bfdServer.peers[address]
			s.bfdServer.peersMutex.RUnlock()
			require.NotNil(t, p, "addPeer must wait for installation")

			s.shared.mu.Lock()
			locked := true
			defer func() {
				if locked {
					s.shared.mu.Unlock()
				}
			}()
			require.True(t, p.Rx(&bfd.BFDHeader{State: bfd.StateDown, MyDiscriminator: 1, DetectTimeMultiplier: 1, DesiredMinTxInterval: 1000}))
			// Bring the session Up: only an Up session that expires resets BGP.
			rxOffer(t, p, &bfd.BFDHeader{State: bfd.StateInit, MyDiscriminator: 1, YourDiscriminator: p.myDiscriminator, DetectTimeMultiplier: 1, DesiredMinTxInterval: 1000})
			var op *mgmtOp
			select {
			case op = <-s.mgmtCh:
			case <-time.After(3 * time.Second):
				t.Fatal("BFD expiry did not queue bfdDown")
			}
			dispatched := make(chan struct{})
			go func() {
				s.shared.mu.Lock()
				s.handleMGMTOp(op)
				s.shared.mu.Unlock()
				close(dispatched)
			}()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			switch action {
			case "delete":
				require.NoError(t, s.bfdServer.DeletePeer(ctx, address))
			case "replace":
				require.NoError(t, s.bfdServer.addPeer(ctx, address, config, netip.MustParseAddr("127.0.0.2"), "", 1))
			case "stop":
				stopped := make(chan struct{})
				go func() { p.Stop(); close(stopped) }()
				select {
				case <-stopped:
				case <-ctx.Done():
					t.Fatal("Stop waited for bfdDown while the caller held shared.mu")
				}
			}
			require.ErrorIs(t, p.resetCtx.Err(), context.Canceled)
			// A replacement at the same address must not receive the old BFD-down notification.
			notifications := make(chan *bgp.BGPMessage, 1)
			s.neighborMap[address] = &peer{fsm: &fsm{notification: notifications}}
			s.shared.mu.Unlock()
			locked = false
			select {
			case <-dispatched:
			case <-time.After(time.Second):
				t.Fatal("canceled management operation blocked the dispatcher")
			}
			require.Empty(t, notifications)
		})
	}
}

func TestBfdDownCanceledBeforeQueue(t *testing.T) {
	s := NewBgpServer()
	defer s.bfdServer.Stop()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, s.bfdDown(ctx, netip.MustParseAddr("127.0.0.1")), context.Canceled)
}

// Gate retirement inside the real BFD event loop. Once retirement is entered,
// the add event has necessarily been accepted, but cannot yet be acknowledged.
// Canceling the caller at that boundary must return cancellation, not success.
// This distinguishes enqueue-only AddPeer deterministically without a sleep or
// an assertion that races the event loop's installation/cancellation work.
func TestBFDAddAcknowledgesRetirement(t *testing.T) {
	s := NewBgpServer()
	t.Cleanup(s.bfdServer.Stop)
	s.bgpConfig.Global.Config.As = 65001
	address := netip.MustParseAddr("127.0.0.1")
	config := oc.BfdConfig{Enabled: true, Port: 13785}
	// Install directly so the setup does not itself depend on add acknowledgement.
	s.bfdServer.addBfdPeer(address, config, address, "", 1)
	s.bfdServer.peersMutex.RLock()
	p := s.bfdServer.peers[address]
	s.bfdServer.peersMutex.RUnlock()
	retiring, release := make(chan struct{}), make(chan struct{})
	cancelReset := p.cancelReset
	p.cancelReset = func() {
		close(retiring)
		<-release
		cancelReset()
	}
	s.shared.mu.Lock()
	defer func() {
		close(release)
		cancelReset()
		s.shared.mu.Unlock()
	}()
	require.True(t, p.Rx(&bfd.BFDHeader{State: bfd.StateDown, MyDiscriminator: 1, DetectTimeMultiplier: 1, DesiredMinTxInterval: 1000}))
	// Bring the session Up: only an Up session that expires resets BGP.
	rxOffer(t, p, &bfd.BFDHeader{State: bfd.StateInit, MyDiscriminator: 1, YourDiscriminator: p.myDiscriminator, DetectTimeMultiplier: 1, DesiredMinTxInterval: 1000})
	var op *mgmtOp
	select {
	case op = <-s.mgmtCh:
	case <-time.After(3 * time.Second):
		t.Fatal("BFD expiry did not queue bfdDown")
	}
	// Dispatch under the actual shared lock, as Serve does. Retirement must
	// complete without needing this dispatcher to acquire the lock first.
	dispatched := make(chan struct{})
	go func() {
		s.shared.mu.Lock()
		s.handleMGMTOp(op)
		s.shared.mu.Unlock()
		close(dispatched)
	}()
	t.Cleanup(func() {
		select {
		case <-dispatched:
		case <-time.After(time.Second):
			t.Error("queued BFD-down operation did not finish")
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- s.bfdServer.addPeer(ctx, address, config, netip.MustParseAddr("127.0.0.2"), "", 1)
	}()
	select {
	case <-retiring:
	case <-time.After(time.Second):
		t.Fatal("replacement did not enter retirement")
	}
	cancel()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled, "addPeer returned success before retirement completed")
	case <-time.After(time.Second):
		t.Fatal("addPeer ignored cancellation while waiting for the done channel")
	}
}
