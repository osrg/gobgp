package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/stretchr/testify/assert"
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
	})
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

	// Wait bfdServer.loop() thread
	time.Sleep(time.Second * 2)

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

	time.Sleep(time.Second * 2)

	// Stop s2
	s2.Stop()

	// Wait BFD peer down
	time.Sleep(time.Second * 2)

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
	})
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
		})
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
				}))
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
