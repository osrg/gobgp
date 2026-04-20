package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/stretchr/testify/assert"
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

func eventuallyCheckState(timeout time.Duration, s *bfdServer, peerAddress string, expected bool) error {
	return eventually(timeout, func() error {
		state, err := s.GetPeerState(context.Background(), peerAddress)
		if err != nil {
			return err
		}
		if state.state.State != expected {
			return fmt.Errorf("must be: peerState == %t", expected)
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

	s1.Start(oc.BfdConfig{
		Port: 13784,
	})
	defer s1.Stop()
}

func newBfdServer(port uint16) *bfdServer {
	ps := &mockPeerState{}
	s := NewBfdServer(ps, slog.Default())
	s.Start(oc.BfdConfig{
		Port: port,
	})
	return s
}

func newBfdServerWithMock(port uint16) (*bfdServer, *mockPeerState) {
	ps := &mockPeerState{}
	s := NewBfdServer(ps, slog.Default())
	s.Start(oc.BfdConfig{
		Port: port,
	})
	return s, ps
}

func addBfdPeer(s *bfdServer, port uint16) error {
	return s.AddPeer("127.0.0.1", oc.BfdConfig{
		Port:       port,
		Enabled:    true,
		Multiplier: 5,
		RxInterval: 200,
		TxInterval: 200,
	})
}

func Test_AddDeletePeer(t *testing.T) {
	assert := assert.New(t)

	s1 := newBfdServer(13784)
	defer s1.Stop()

	// Add peer
	err := addBfdPeer(s1, 23784)
	assert.NoError(err)

	// Wait bfdServer.loop() thread
	time.Sleep(time.Second * 2)

	// Get state
	state, err := s1.GetPeerState(context.Background(), "127.0.0.1")
	assert.NotNil(state)
	assert.NoError(err)

	assert.Equal(state.peerAddress, "127.0.0.1")

	// Delete peer
	err = s1.DeletePeer("127.0.0.1")
	assert.NoError(err)

	// Wait bfdServer.loop() thread
	time.Sleep(time.Second * 2)

	// Get state
	state, err = s1.GetPeerState(context.Background(), "127.0.0.1")
	assert.Nil(state)
	assert.Error(err)
}

func Test_StateUpDown(t *testing.T) {
	assert := assert.New(t)

	s1 := newBfdServer(13784)
	defer s1.Stop()

	s2 := newBfdServer(23784)

	// Add peer
	err := addBfdPeer(s1, 23784)
	assert.NoError(err)

	// Add peer
	err = addBfdPeer(s2, 13784)
	assert.NoError(err)

	// Wait bfdServer.loop() thread
	time.Sleep(time.Second * 2)

	// Get state
	state, err := s1.GetPeerState(context.Background(), "127.0.0.1")
	assert.NotNil(state)
	assert.NoError(err)
	assert.Equal(state.state.State, true)
	assert.NotEqual(state.state.ReceivedPacket, uint64(0))
	assert.NotEqual(state.state.SentPacket, uint64(0))

	// Get state
	state, err = s2.GetPeerState(context.Background(), "127.0.0.1")
	assert.NotNil(state)
	assert.NoError(err)
	assert.Equal(state.state.State, true)
	assert.NotEqual(state.state.ReceivedPacket, uint64(0))
	assert.NotEqual(state.state.SentPacket, uint64(0))

	// Stop s2
	s2.Stop()

	// Check state
	err = eventuallyCheckState(2*time.Second, s1, "127.0.0.1", false)
	assert.NoError(err)
}

func Test_ResetPeer(t *testing.T) {
	assert := assert.New(t)

	s1, m1 := newBfdServerWithMock(13784)

	s2 := newBfdServer(23784)

	// Add peer
	err := addBfdPeer(s1, 23784)
	assert.NoError(err)

	// Add peer
	err = addBfdPeer(s2, 13784)
	assert.NoError(err)

	time.Sleep(time.Second * 2)

	// Stop s2
	s2.Stop()

	// Wait BFD peer down
	time.Sleep(time.Second * 2)

	s1.Stop()

	assert.Equal(atomic.LoadInt64(&m1.resetPeerCount), int64(1))
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
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

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
				Enabled:    true,
				Multiplier: 7,
				RxInterval: 123,
				TxInterval: 456,
			},
		},
	}
	gConf := &oc.Global{}

	assert.NoError(oc.SetDefaultNeighborConfigValues(nConf1, pgConf, gConf))
	assert.NoError(oc.SetDefaultNeighborConfigValues(nConf2, pgConf, gConf))

	// Add 'group_on' with enabled BFD
	assert.NoError(s.AddPeerGroup(context.Background(), &api.AddPeerGroupRequest{
		PeerGroup: oc.NewPeerGroupFromConfigStruct(pgConf),
	}))

	var count int

	// Add 1 peer
	assert.NoError(s.AddPeer(context.Background(), &api.AddPeerRequest{
		Peer: oc.NewPeerFromConfigStruct(nConf1),
	}))
	time.Sleep(time.Second)

	count = 0
	s.ListBfdPeer(context.Background(), func(peerAddress string, state *api.BfdPeerState) {
		count++
	})
	assert.Equal(count, 1)

	// Delete 1 peer
	assert.NoError(s.DeletePeer(context.Background(), &api.DeletePeerRequest{
		Address: "127.0.0.1",
	}))
	time.Sleep(time.Second)

	count = 0
	s.ListBfdPeer(context.Background(), func(peerAddress string, state *api.BfdPeerState) {
		count++
	})
	assert.Equal(count, 0)

	// Add 2 peer
	assert.NoError(s.AddPeer(context.Background(), &api.AddPeerRequest{
		Peer: oc.NewPeerFromConfigStruct(nConf1),
	}))
	assert.NoError(s.AddPeer(context.Background(), &api.AddPeerRequest{
		Peer: oc.NewPeerFromConfigStruct(nConf2),
	}))
	time.Sleep(time.Second)

	count = 0
	s.ListBfdPeer(context.Background(), func(peerAddress string, state *api.BfdPeerState) {
		count++
	})
	assert.Equal(count, 2)

	// Delete 1 peer
	assert.NoError(s.DeletePeer(context.Background(), &api.DeletePeerRequest{
		Address: "127.0.0.1",
	}))
	time.Sleep(time.Second)

	count = 0
	s.ListBfdPeer(context.Background(), func(peerAddress string, state *api.BfdPeerState) {
		count++
	})
	assert.Equal(count, 1)

	// Delete 1 peer
	assert.NoError(s.DeletePeer(context.Background(), &api.DeletePeerRequest{
		Address: "127.0.0.2",
	}))
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
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

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
				Enabled:    true,
				Multiplier: 7,
				RxInterval: 123,
				TxInterval: 456,
			},
		},
	}
	gConf := &oc.Global{}

	assert.NoError(oc.SetDefaultNeighborConfigValues(nConf1, pgConf1, gConf))
	assert.NoError(oc.SetDefaultNeighborConfigValues(nConf2, pgConf2, gConf))

	// Add 'group_off' without BFD
	assert.NoError(s.AddPeerGroup(context.Background(), &api.AddPeerGroupRequest{
		PeerGroup: oc.NewPeerGroupFromConfigStruct(pgConf1),
	}))

	// Add 'group_on' with enabled BFD
	assert.NoError(s.AddPeerGroup(context.Background(), &api.AddPeerGroupRequest{
		PeerGroup: oc.NewPeerGroupFromConfigStruct(pgConf2),
	}))

	var count int

	// Add 1 peer (group_off)
	assert.NoError(s.AddPeer(context.Background(), &api.AddPeerRequest{
		Peer: oc.NewPeerFromConfigStruct(nConf1),
	}))
	time.Sleep(time.Second)

	count = 0
	s.ListBfdPeer(context.Background(), func(peerAddress string, state *api.BfdPeerState) {
		count++
	})
	assert.Equal(count, 0)

	// Add 1 peer (group_on)
	assert.NoError(s.AddPeer(context.Background(), &api.AddPeerRequest{
		Peer: oc.NewPeerFromConfigStruct(nConf2),
	}))
	time.Sleep(time.Second)

	count = 0
	s.ListBfdPeer(context.Background(), func(peerAddress string, state *api.BfdPeerState) {
		count++
	})
	assert.Equal(count, 1)

	// Delete 1 peer (group_on)
	assert.NoError(s.DeletePeer(context.Background(), &api.DeletePeerRequest{
		Address: "127.0.0.2",
	}))
	time.Sleep(time.Second)

	count = 0
	s.ListBfdPeer(context.Background(), func(peerAddress string, state *api.BfdPeerState) {
		count++
	})
	assert.Equal(count, 0)

	// Delete 1 peer (group_off)
	assert.NoError(s.DeletePeer(context.Background(), &api.DeletePeerRequest{
		Address: "127.0.0.1",
	}))
	time.Sleep(time.Second)

	count = 0
	s.ListBfdPeer(context.Background(), func(peerAddress string, state *api.BfdPeerState) {
		count++
	})
	assert.Equal(count, 0)
}
