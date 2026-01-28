// Copyright (C) 2026 Nippon Telegraph and Telephone Corporation.
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
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// TestHandleFSMMessage_Parallel_StateChanges tests various state change scenarios in parallel
func TestHandleFSMMessage_Parallel_StateChanges(t *testing.T) {
	numPeers := 80

	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	// Create multiple peers
	peers := make([]*peer, numPeers)
	for i := range numPeers {
		peerAddr := netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})
		err = s.AddPeer(context.Background(), &api.AddPeerRequest{
			Peer: &api.Peer{
				Conf: &api.PeerConf{
					NeighborAddress: peerAddr.String(),
					PeerAsn:         uint32(65002 + i),
					AdminDown:       true, // Keep peer admin down to prevent actual connections
				},
				AfiSafis: []*api.AfiSafi{
					{
						Config: &api.AfiSafiConfig{
							Family: &api.Family{
								Afi:  api.Family_AFI_IP,
								Safi: api.Family_SAFI_UNICAST,
							},
							Enabled: true,
						},
					},
				},
			},
		})
		require.NoError(t, err)

		err = s.mgmtOperation(func() error {
			peers[i] = s.neighborMap[peerAddr]
			return nil
		}, true)
		require.NoError(t, err)
		require.NotNil(t, peers[i])
	}

	// Run handleFSMMessage for all peers concurrently with state changes
	var wg sync.WaitGroup
	for i := range numPeers {
		wg.Add(1)
		go func(peerIdx int) {
			defer wg.Done()
			p := peers[peerIdx]

			// Test state change from IDLE to ACTIVE
			msg1 := &fsmMsg{
				MsgType:     fsmMsgStateChange,
				MsgData:     bgp.BGP_FSM_ACTIVE,
				StateReason: newfsmStateReason(fsmIdleTimerExpired, nil, nil),
				timestamp:   time.Now(),
			}
			s.handleFSMMessage(p, msg1)

			// Small delay
			time.Sleep(10 * time.Millisecond)

			// Test state change from ACTIVE to IDLE
			msg2 := &fsmMsg{
				MsgType:     fsmMsgStateChange,
				MsgData:     bgp.BGP_FSM_IDLE,
				StateReason: newfsmStateReason(fsmAdminDown, nil, nil),
				timestamp:   time.Now(),
			}
			s.handleFSMMessage(p, msg2)
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Verify all peers are still in the neighbor map
	err = s.mgmtOperation(func() error {
		assert.Equal(t, numPeers, len(s.neighborMap))
		return nil
	}, true)
	require.NoError(t, err)
}

// TestHandleFSMMessage_StateChange_AdminDown tests admin down state changes
func TestHandleFSMMessage_StateChange_AdminDown(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	peerAddr := "2.2.2.2"
	err = s.AddPeer(context.Background(), &api.AddPeerRequest{
		Peer: &api.Peer{
			Conf: &api.PeerConf{
				NeighborAddress: peerAddr,
				PeerAsn:         65002,
				AdminDown:       true,
			},
			AfiSafis: []*api.AfiSafi{
				{
					Config: &api.AfiSafiConfig{
						Family: &api.Family{
							Afi:  api.Family_AFI_IP,
							Safi: api.Family_SAFI_UNICAST,
						},
						Enabled: true,
					},
				},
			},
		},
	})
	require.NoError(t, err)

	var p *peer
	err = s.mgmtOperation(func() error {
		p = s.neighborMap[netip.MustParseAddr(peerAddr)]
		return nil
	}, true)
	require.NoError(t, err)
	require.NotNil(t, p)

	// Set peer admin down state
	p.fsm.adminState.Store(adminStateDown)

	// Send state change to IDLE with admin down
	msg := &fsmMsg{
		MsgType:     fsmMsgStateChange,
		MsgData:     bgp.BGP_FSM_IDLE,
		StateReason: newfsmStateReason(fsmAdminDown, nil, nil),
		timestamp:   time.Now(),
	}

	s.handleFSMMessage(p, msg)

	// Verify counters were cleared (admin down clears counters)
	conf := *p.fsm.pConf.ReadOnly()
	assert.Equal(t, int64(0), conf.Timers.State.Uptime)
	assert.Equal(t, int64(0), conf.Timers.State.Downtime)
}

// TestHandleFSMMessage_StateChange_IdleToActive tests state transition from IDLE to ACTIVE
func TestHandleFSMMessage_StateChange_IdleToActive(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	peerAddr := "2.2.2.2"
	err = s.AddPeer(context.Background(), &api.AddPeerRequest{
		Peer: &api.Peer{
			Conf: &api.PeerConf{
				NeighborAddress: peerAddr,
				PeerAsn:         65002,
				AdminDown:       true,
			},
			AfiSafis: []*api.AfiSafi{
				{
					Config: &api.AfiSafiConfig{
						Family: &api.Family{
							Afi:  api.Family_AFI_IP,
							Safi: api.Family_SAFI_UNICAST,
						},
						Enabled: true,
					},
				},
			},
		},
	})
	require.NoError(t, err)

	var p *peer
	err = s.mgmtOperation(func() error {
		p = s.neighborMap[netip.MustParseAddr(peerAddr)]
		return nil
	}, true)
	require.NoError(t, err)
	require.NotNil(t, p)

	// Send state change from IDLE to ACTIVE
	msg := &fsmMsg{
		MsgType:     fsmMsgStateChange,
		MsgData:     bgp.BGP_FSM_ACTIVE,
		StateReason: newfsmStateReason(fsmIdleTimerExpired, nil, nil),
		timestamp:   time.Now(),
	}

	initialState := p.State()
	s.handleFSMMessage(p, msg)

	// Verify state change was processed (state changed from initial)
	conf := *p.fsm.pConf.ReadOnly()
	assert.NotEqual(t, int(initialState), conf.State.SessionState.ToInt())
}

// TestHandleFSMMessage_ConcurrentAccess tests concurrent access to handleFSMMessage
func TestHandleFSMMessage_ConcurrentAccess(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	// Create three peers
	numPeers := 80
	peers := make([]*peer, numPeers)

	for i := range numPeers {
		peerAddr := netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})
		err = s.AddPeer(context.Background(), &api.AddPeerRequest{
			Peer: &api.Peer{
				Conf: &api.PeerConf{
					NeighborAddress: peerAddr.String(),
					PeerAsn:         uint32(65002 + i),
					AdminDown:       true,
				},
				AfiSafis: []*api.AfiSafi{
					{
						Config: &api.AfiSafiConfig{
							Family: &api.Family{
								Afi:  api.Family_AFI_IP,
								Safi: api.Family_SAFI_UNICAST,
							},
							Enabled: true,
						},
					},
				},
			},
		})
		require.NoError(t, err)

		err = s.mgmtOperation(func() error {
			peers[i] = s.neighborMap[peerAddr]
			return nil
		}, true)
		require.NoError(t, err)
		require.NotNil(t, peers[i])
	}

	// Send multiple state change messages concurrently to all peers
	var wg sync.WaitGroup
	iterations := 300

	for i := range numPeers {
		for j := range iterations {
			wg.Add(1)
			go func(peerIdx, iter int) {
				defer wg.Done()
				p := peers[peerIdx]

				// Alternate between IDLE and ACTIVE
				var targetState bgp.FSMState
				var reason fsmStateReasonType
				if iter%2 == 0 {
					targetState = bgp.BGP_FSM_ACTIVE
					reason = fsmIdleTimerExpired
				} else {
					targetState = bgp.BGP_FSM_IDLE
					reason = fsmAdminDown
				}

				msg := &fsmMsg{
					MsgType:     fsmMsgStateChange,
					MsgData:     targetState,
					StateReason: newfsmStateReason(reason, nil, nil),
					timestamp:   time.Now(),
				}

				s.handleFSMMessage(p, msg)
			}(i, j)
		}
	}

	wg.Wait()

	// Verify all peers are still in the neighbor map
	err = s.mgmtOperation(func() error {
		assert.Equal(t, numPeers, len(s.neighborMap))
		for _, p := range peers {
			assert.NotNil(t, p)
		}
		return nil
	}, true)
	require.NoError(t, err)
}

// TestHandleFSMMessage_WithGracefulRestart tests graceful restart scenarios
func TestHandleFSMMessage_WithGracefulRestart(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	peerAddr := "2.2.2.2"
	err = s.AddPeer(context.Background(), &api.AddPeerRequest{
		Peer: &api.Peer{
			Conf: &api.PeerConf{
				NeighborAddress: peerAddr,
				PeerAsn:         65002,
				AdminDown:       true,
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
						Enabled: true,
					},
					MpGracefulRestart: &api.MpGracefulRestart{
						Config: &api.MpGracefulRestartConfig{
							Enabled: true,
						},
					},
				},
			},
		},
	})
	require.NoError(t, err)

	var p *peer
	err = s.mgmtOperation(func() error {
		p = s.neighborMap[netip.MustParseAddr(peerAddr)]
		return nil
	}, true)
	require.NoError(t, err)
	require.NotNil(t, p)

	// Verify graceful restart config is set
	conf := *p.fsm.pConf.ReadOnly()
	assert.True(t, conf.GracefulRestart.Config.Enabled, "GR should be enabled in config")

	// Send state change message
	msg := &fsmMsg{
		MsgType:     fsmMsgStateChange,
		MsgData:     bgp.BGP_FSM_IDLE,
		StateReason: newfsmStateReason(fsmGracefulRestart, nil, nil),
		timestamp:   time.Now(),
	}

	s.handleFSMMessage(p, msg)

	// Wait a bit for processing
	time.Sleep(50 * time.Millisecond)

	// Verify message was processed without panic
	assert.NotNil(t, p)
}

// TestHandleFSMMessage_DynamicNeighborRace tests the race condition in stopNeighbor with dynamic neighbors
func TestHandleFSMMessage_DynamicNeighborRace(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	// Add a peer group for dynamic neighbors
	err = s.AddPeerGroup(context.Background(), &api.AddPeerGroupRequest{
		PeerGroup: &api.PeerGroup{
			Conf: &api.PeerGroupConf{
				PeerGroupName: "dynamic-group",
				PeerAsn:       65002,
			},
			AfiSafis: []*api.AfiSafi{
				{
					Config: &api.AfiSafiConfig{
						Family: &api.Family{
							Afi:  api.Family_AFI_IP,
							Safi: api.Family_SAFI_UNICAST,
						},
						Enabled: true,
					},
				},
			},
		},
	})
	require.NoError(t, err)

	// Add dynamic neighbor configuration
	err = s.AddDynamicNeighbor(context.Background(), &api.AddDynamicNeighborRequest{
		DynamicNeighbor: &api.DynamicNeighbor{
			Prefix:    "10.0.0.0/24",
			PeerGroup: "dynamic-group",
		},
	})
	require.NoError(t, err)

	numPeers := 80
	peers := make([]*peer, numPeers)

	// Manually create dynamic peers by adding them directly
	// Dynamic peers have invalid NeighborAddress
	for i := range numPeers {
		peerAddr := netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})

		err = s.mgmtOperation(func() error {
			// Get peer group
			pg, ok := s.peerGroupMap["dynamic-group"]
			if !ok {
				return nil
			}

			// Create a dynamic peer using the internal function
			peer := newDynamicPeer(&s.bgpConfig.Global, peerAddr.String(), pg.Conf, s.globalRib, s.policy, s.logger)
			if peer != nil {
				s.neighborMap[peerAddr] = peer
				peers[i] = peer

				// Start the peer's FSM
				peer.fsm.start(s.shutdownWG, func(msg *fsmMsg) {
					s.handleFSMMessage(peer, msg)
				})
			}
			return nil
		}, true)
		require.NoError(t, err)
	}

	// Wait a bit for FSMs to start
	time.Sleep(50 * time.Millisecond)

	// Now trigger ESTABLISHED -> IDLE transitions in parallel for dynamic peers
	// This should trigger stopNeighbor which modifies s.neighborMap
	var wg sync.WaitGroup
	for i := range numPeers {
		if peers[i] == nil {
			continue
		}
		wg.Add(1)
		go func(peerIdx int) {
			defer wg.Done()
			p := peers[peerIdx]

			// Verify it's a dynamic neighbor
			if !p.isDynamicNeighbor() {
				t.Errorf("Peer %d is not dynamic - cannot trigger stopNeighbor race", peerIdx)
				return
			}

			t.Logf("Peer %d is dynamic, triggering stopNeighbor", peerIdx)

			// Set peer to ESTABLISHED first
			p.fsm.lock.Lock()
			conf := p.fsm.pConf.ReadCopy()
			conf.State.SessionState = "established"
			conf.Timers.State.Uptime = time.Now().Add(-1 * time.Minute).Unix()
			p.fsm.pConf.Update(&conf)
			p.fsm.lock.Unlock()

			// Send state change from ESTABLISHED to IDLE (non-graceful)
			// This should trigger stopNeighbor which deletes from s.neighborMap
			msg := &fsmMsg{
				MsgType:     fsmMsgStateChange,
				MsgData:     bgp.BGP_FSM_IDLE,
				StateReason: newfsmStateReason(fsmAdminDown, nil, nil), // non-graceful
				timestamp:   time.Now(),
			}

			s.handleFSMMessage(p, msg)
		}(i)
	}

	wg.Wait()
}

// TestHandleFSMMessage_NeighborMapIterationRace tests race when iterating neighborMap during EOR processing
func TestHandleFSMMessage_NeighborMapIterationRace(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	numPeers := 80
	peers := make([]*peer, numPeers)

	// Create peers with graceful restart enabled
	for i := range numPeers {
		peerAddr := netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})
		err = s.AddPeer(context.Background(), &api.AddPeerRequest{
			Peer: &api.Peer{
				Conf: &api.PeerConf{
					NeighborAddress: peerAddr.String(),
					PeerAsn:         uint32(65002 + i),
					AdminDown:       true,
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
							Enabled: true,
						},
						MpGracefulRestart: &api.MpGracefulRestart{
							Config: &api.MpGracefulRestartConfig{
								Enabled: true,
							},
						},
					},
				},
			},
		})
		require.NoError(t, err)

		err = s.mgmtOperation(func() error {
			peers[i] = s.neighborMap[peerAddr]
			return nil
		}, true)
		require.NoError(t, err)
		require.NotNil(t, peers[i])
	}

	// Run parallel operations that trigger neighborMap iteration
	var wg sync.WaitGroup

	// Goroutine 1: Trigger state transitions that cause EOR processing
	// This will iterate over s.neighborMap at lines 1568, 1576, 1684, 1692
	for i := range numPeers / 2 {
		wg.Add(1)
		go func(peerIdx int) {
			defer wg.Done()
			p := peers[peerIdx]

			// Set to ESTABLISHED to enable EOR processing path
			p.fsm.lock.Lock()
			conf := p.fsm.pConf.ReadCopy()
			conf.State.SessionState = "established"
			conf.Timers.State.Uptime = time.Now().Add(-1 * time.Minute).Unix()
			conf.GracefulRestart.State.LocalRestarting = true
			p.fsm.pConf.Update(&conf)
			p.fsm.lock.Unlock()

			// Send BGP UPDATE with EOR to trigger the neighborMap iteration
			eorMsg := bgp.NewBGPUpdateMessage(nil, nil, nil)
			msg := &fsmMsg{
				MsgType:     fsmMsgBGPMessage,
				MsgData:     eorMsg,
				StateReason: nil,
				timestamp:   time.Now(),
			}

			s.handleFSMMessage(p, msg)
		}(i)
	}

	// Goroutine 2: Add/remove dynamic neighbors to cause concurrent map modifications
	// This simulates the race between iteration and modification
	for i := numPeers / 2; i < numPeers; i++ {
		wg.Add(1)
		go func(peerIdx int) {
			defer wg.Done()
			p := peers[peerIdx]

			// Rapidly change states to stress the system
			for range 300 {
				msg := &fsmMsg{
					MsgType:     fsmMsgStateChange,
					MsgData:     bgp.BGP_FSM_ACTIVE,
					StateReason: newfsmStateReason(fsmIdleTimerExpired, nil, nil),
					timestamp:   time.Now(),
				}
				s.handleFSMMessage(p, msg)
				time.Sleep(5 * time.Millisecond)

				msg = &fsmMsg{
					MsgType:     fsmMsgStateChange,
					MsgData:     bgp.BGP_FSM_IDLE,
					StateReason: newfsmStateReason(fsmAdminDown, nil, nil),
					timestamp:   time.Now(),
				}
				s.handleFSMMessage(p, msg)
				time.Sleep(5 * time.Millisecond)
			}
		}(i)
	}

	wg.Wait()
}

// TestHandleFSMMessage_PropagateUpdateRace tests race in propagateUpdate's neighborMap iteration
func TestHandleFSMMessage_PropagateUpdateRace(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	// Add peer group for dynamic neighbors
	err = s.AddPeerGroup(context.Background(), &api.AddPeerGroupRequest{
		PeerGroup: &api.PeerGroup{
			Conf: &api.PeerGroupConf{
				PeerGroupName: "test-group",
				PeerAsn:       65002,
			},
			AfiSafis: []*api.AfiSafi{
				{
					Config: &api.AfiSafiConfig{
						Family: &api.Family{
							Afi:  api.Family_AFI_IP,
							Safi: api.Family_SAFI_UNICAST,
						},
						Enabled: true,
					},
				},
			},
		},
	})
	require.NoError(t, err)

	err = s.AddDynamicNeighbor(context.Background(), &api.AddDynamicNeighborRequest{
		DynamicNeighbor: &api.DynamicNeighbor{
			Prefix:    "10.0.0.0/24",
			PeerGroup: "test-group",
		},
	})
	require.NoError(t, err)

	numPeers := 80
	peers := make([]*peer, numPeers)
	dynamicPeers := make([]bool, numPeers)

	// Create mix of regular and dynamic peers
	for i := range numPeers {
		peerAddr := netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})
		isDynamic := i < numPeers/2 // half of the peers are dynamic

		if isDynamic {
			// Create dynamic peer
			err = s.mgmtOperation(func() error {
				pg, ok := s.peerGroupMap["test-group"]
				if !ok {
					return nil
				}
				peer := newDynamicPeer(&s.bgpConfig.Global, peerAddr.String(), pg.Conf, s.globalRib, s.policy, s.logger)
				if peer != nil {
					s.neighborMap[peerAddr] = peer
					peers[i] = peer
					dynamicPeers[i] = true
					peer.fsm.start(s.shutdownWG, func(msg *fsmMsg) {
						s.handleFSMMessage(peer, msg)
					})
				}
				return nil
			}, true)
		} else {
			// Create regular peer
			err = s.AddPeer(context.Background(), &api.AddPeerRequest{
				Peer: &api.Peer{
					Conf: &api.PeerConf{
						NeighborAddress: peerAddr.String(),
						PeerAsn:         uint32(65002 + i),
						AdminDown:       true,
					},
					AfiSafis: []*api.AfiSafi{
						{
							Config: &api.AfiSafiConfig{
								Family: &api.Family{
									Afi:  api.Family_AFI_IP,
									Safi: api.Family_SAFI_UNICAST,
								},
								Enabled: true,
							},
						},
					},
				},
			})
			require.NoError(t, err)

			err = s.mgmtOperation(func() error {
				peers[i] = s.neighborMap[peerAddr]
				return nil
			}, true)
		}
		require.NoError(t, err)
	}

	time.Sleep(50 * time.Millisecond)

	var wg sync.WaitGroup

	// Goroutines that trigger propagateUpdate (which iterates neighborMap at line 1209)
	for i := numPeers / 2; i < numPeers; i++ {
		if peers[i] == nil {
			continue
		}
		wg.Add(1)
		go func(peerIdx int) {
			defer wg.Done()
			p := peers[peerIdx]

			// Set to ESTABLISHED
			p.fsm.lock.Lock()
			conf := p.fsm.pConf.ReadCopy()
			conf.State.SessionState = "established"
			conf.Timers.State.Uptime = time.Now().Add(-1 * time.Minute).Unix()
			p.fsm.pConf.Update(&conf)
			p.fsm.lock.Unlock()

			// Trigger state change that calls propagateUpdate
			msg := &fsmMsg{
				MsgType:     fsmMsgStateChange,
				MsgData:     bgp.BGP_FSM_IDLE,
				StateReason: newfsmStateReason(fsmHoldTimerExpired, nil, nil),
				timestamp:   time.Now(),
			}

			s.handleFSMMessage(p, msg)
		}(i)
	}

	// Concurrently delete dynamic neighbors (triggers stopNeighbor)
	for i := range numPeers / 2 {
		if peers[i] == nil || !dynamicPeers[i] {
			continue
		}
		wg.Add(1)
		go func(peerIdx int) {
			defer wg.Done()
			p := peers[peerIdx]

			if !p.isDynamicNeighbor() {
				return
			}

			// Set to ESTABLISHED then trigger peer down (non-graceful)
			p.fsm.lock.Lock()
			conf := p.fsm.pConf.ReadCopy()
			conf.State.SessionState = "established"
			conf.Timers.State.Uptime = time.Now().Add(-1 * time.Minute).Unix()
			p.fsm.pConf.Update(&conf)
			p.fsm.lock.Unlock()

			// This will call stopNeighbor which deletes from neighborMap
			// While other goroutines are iterating over it
			msg := &fsmMsg{
				MsgType:     fsmMsgStateChange,
				MsgData:     bgp.BGP_FSM_IDLE,
				StateReason: newfsmStateReason(fsmAdminDown, nil, nil), // non-graceful
				timestamp:   time.Now(),
			}

			s.handleFSMMessage(p, msg)
		}(i)
	}

	wg.Wait()
}

// TestHandleFSMMessage_ParallelDifferentPeers tests handleFSMMessage with different peers in parallel
func TestHandleFSMMessage_ParallelDifferentPeers(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	numPeers := 80
	peers := make([]*peer, numPeers)

	// Create peers with different configurations
	for i := range numPeers {
		peerAddr := netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})
		enableGR := i%2 == 0 // Enable GR for even numbered peers

		peerConfig := &api.Peer{
			Conf: &api.PeerConf{
				NeighborAddress: peerAddr.String(),
				PeerAsn:         uint32(65002 + i),
				AdminDown:       true,
			},
			AfiSafis: []*api.AfiSafi{
				{
					Config: &api.AfiSafiConfig{
						Family: &api.Family{
							Afi:  api.Family_AFI_IP,
							Safi: api.Family_SAFI_UNICAST,
						},
						Enabled: true,
					},
				},
			},
		}

		if enableGR {
			peerConfig.GracefulRestart = &api.GracefulRestart{
				Enabled:     true,
				RestartTime: 120,
			}
			peerConfig.AfiSafis[0].MpGracefulRestart = &api.MpGracefulRestart{
				Config: &api.MpGracefulRestartConfig{
					Enabled: true,
				},
			}
		}

		err = s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: peerConfig})
		require.NoError(t, err)

		err = s.mgmtOperation(func() error {
			peers[i] = s.neighborMap[peerAddr]
			return nil
		}, true)
		require.NoError(t, err)
		require.NotNil(t, peers[i])
	}

	// Process messages for all peers in parallel
	var wg sync.WaitGroup
	for i := range numPeers {
		wg.Add(1)
		go func(peerIdx int) {
			defer wg.Done()
			p := peers[peerIdx]

			// Send multiple state changes
			states := []bgp.FSMState{
				bgp.BGP_FSM_ACTIVE,
				bgp.BGP_FSM_IDLE,
				bgp.BGP_FSM_ACTIVE,
				bgp.BGP_FSM_IDLE,
			}

			for _, state := range states {
				reason := fsmIdleTimerExpired
				if state == bgp.BGP_FSM_IDLE {
					reason = fsmAdminDown
				}

				msg := &fsmMsg{
					MsgType:     fsmMsgStateChange,
					MsgData:     state,
					StateReason: newfsmStateReason(reason, nil, nil),
					timestamp:   time.Now(),
				}

				s.handleFSMMessage(p, msg)
				time.Sleep(5 * time.Millisecond)
			}
		}(i)
	}

	wg.Wait()

	// Verify all peers are still present and functional
	err = s.mgmtOperation(func() error {
		assert.Equal(t, numPeers, len(s.neighborMap))
		for i, p := range peers {
			assert.NotNil(t, p, "peer %d should not be nil", i)
			// Verify GR config settings are still correct
			conf := *p.fsm.pConf.ReadOnly()
			if i%2 == 0 {
				assert.True(t, conf.GracefulRestart.Config.Enabled, "peer %d should have GR enabled in config", i)
			} else {
				assert.False(t, conf.GracefulRestart.Config.Enabled, "peer %d should not have GR enabled in config", i)
			}
		}
		return nil
	}, true)
	require.NoError(t, err)
}

// TestHandleFSMMessage_PrefixLimitWarnedRace tests concurrent access to prefixLimitWarned map
func TestHandleFSMMessage_PrefixLimitWarnedRace(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	numPeers := 20
	peers := make([]*peer, numPeers)

	// Create peers with prefix limit config
	for i := range numPeers {
		peerAddr := netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})
		err = s.AddPeer(context.Background(), &api.AddPeerRequest{
			Peer: &api.Peer{
				Conf: &api.PeerConf{
					NeighborAddress: peerAddr.String(),
					PeerAsn:         uint32(65002 + i),
					AdminDown:       true,
				},
				AfiSafis: []*api.AfiSafi{
					{
						Config: &api.AfiSafiConfig{
							Family: &api.Family{
								Afi:  api.Family_AFI_IP,
								Safi: api.Family_SAFI_UNICAST,
							},
							Enabled: true,
						},
						PrefixLimits: &api.PrefixLimit{
							MaxPrefixes:          100,
							ShutdownThresholdPct: 80,
						},
					},
				},
			},
		})
		require.NoError(t, err)

		err = s.mgmtOperation(func() error {
			peers[i] = s.neighborMap[peerAddr]
			return nil
		}, true)
		require.NoError(t, err)
		require.NotNil(t, peers[i])
	}

	// Test concurrent reset and read/write of prefixLimitWarned
	var wg sync.WaitGroup

	// Goroutines that reset the map (simulating PeerDown)
	for i := range numPeers / 2 {
		wg.Add(1)
		go func(peerIdx int) {
			defer wg.Done()
			p := peers[peerIdx]

			for range 100 {
				// Set to ESTABLISHED first
				p.fsm.lock.Lock()
				conf := p.fsm.pConf.ReadCopy()
				conf.State.SessionState = "established"
				conf.Timers.State.Uptime = time.Now().Add(-1 * time.Minute).Unix()
				p.fsm.pConf.Update(&conf)
				p.fsm.lock.Unlock()

				// Trigger PeerDown which resets prefixLimitWarned
				msg := &fsmMsg{
					MsgType:     fsmMsgStateChange,
					MsgData:     bgp.BGP_FSM_IDLE,
					StateReason: newfsmStateReason(fsmHoldTimerExpired, nil, nil),
					timestamp:   time.Now(),
				}
				s.handleFSMMessage(p, msg)
				time.Sleep(1 * time.Millisecond)
			}
		}(i)
	}

	// Goroutines that read/write the map (simulating isPrefixLimit)
	for i := numPeers / 2; i < numPeers; i++ {
		wg.Add(1)
		go func(peerIdx int) {
			defer wg.Done()
			p := peers[peerIdx]

			for range 100 {
				// Access prefixLimitWarned through isPrefixLimit
				p.fsm.lock.Lock()
				conf := p.fsm.pConf.ReadCopy()
				p.fsm.lock.Unlock()

				for _, af := range conf.AfiSafis {
					p.isPrefixLimit(af.State.Family, &af.PrefixLimit.Config)
				}
				time.Sleep(1 * time.Millisecond)
			}
		}(i)
	}

	wg.Wait()
}

// TestHandleFSMMessage_LLGREndChsRace tests concurrent append and reset of llgrEndChs slice
func TestHandleFSMMessage_LLGREndChsRace(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	numPeers := 20
	peers := make([]*peer, numPeers)

	// Create peers with LLGR enabled
	for i := range numPeers {
		peerAddr := netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})
		err = s.AddPeer(context.Background(), &api.AddPeerRequest{
			Peer: &api.Peer{
				Conf: &api.PeerConf{
					NeighborAddress: peerAddr.String(),
					PeerAsn:         uint32(65002 + i),
					AdminDown:       true,
				},
				GracefulRestart: &api.GracefulRestart{
					Enabled:          true,
					RestartTime:      120,
					LonglivedEnabled: true,
				},
				AfiSafis: []*api.AfiSafi{
					{
						Config: &api.AfiSafiConfig{
							Family: &api.Family{
								Afi:  api.Family_AFI_IP,
								Safi: api.Family_SAFI_UNICAST,
							},
							Enabled: true,
						},
						MpGracefulRestart: &api.MpGracefulRestart{
							Config: &api.MpGracefulRestartConfig{
								Enabled: true,
							},
						},
						LongLivedGracefulRestart: &api.LongLivedGracefulRestart{
							Config: &api.LongLivedGracefulRestartConfig{
								Enabled:     true,
								RestartTime: 1, // 1 second for faster test
							},
						},
					},
				},
			},
		})
		require.NoError(t, err)

		err = s.mgmtOperation(func() error {
			peers[i] = s.neighborMap[peerAddr]
			return nil
		}, true)
		require.NoError(t, err)
		require.NotNil(t, peers[i])
	}

	// Test concurrent append and reset of llgrEndChs
	var wg sync.WaitGroup

	// Goroutines that append to llgrEndChs (simulating LLGR timer start)
	for i := range numPeers / 2 {
		wg.Add(1)
		go func(peerIdx int) {
			defer wg.Done()
			p := peers[peerIdx]

			for range 50 {
				// Set to ESTABLISHED first
				p.fsm.lock.Lock()
				conf := p.fsm.pConf.ReadCopy()
				conf.State.SessionState = "established"
				conf.Timers.State.Uptime = time.Now().Add(-1 * time.Minute).Unix()
				conf.GracefulRestart.State.PeerRestarting = true
				p.fsm.pConf.Update(&conf)
				p.fsm.lock.Unlock()

				// Trigger LLGR path which appends to llgrEndChs
				msg := &fsmMsg{
					MsgType:     fsmMsgStateChange,
					MsgData:     bgp.BGP_FSM_IDLE,
					StateReason: newfsmStateReason(fsmGracefulRestart, nil, nil),
					timestamp:   time.Now(),
				}
				s.handleFSMMessage(p, msg)
				time.Sleep(2 * time.Millisecond)
			}
		}(i)
	}

	// Goroutines that reset llgrEndChs (simulating stopPeerRestarting)
	for i := numPeers / 2; i < numPeers; i++ {
		wg.Add(1)
		go func(peerIdx int) {
			defer wg.Done()
			p := peers[peerIdx]

			for range 50 {
				// Directly call stopPeerRestarting which resets llgrEndChs
				p.stopPeerRestarting()
				time.Sleep(2 * time.Millisecond)
			}
		}(i)
	}

	wg.Wait()
}
