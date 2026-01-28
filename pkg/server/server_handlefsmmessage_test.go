// Copyright (C) 2026 Cisco Systems, Inc.
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

	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

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

				for _, af := range conf.AfiSafis {
					p.isPrefixLimit(af.State.Family, &af.PrefixLimit.Config)
				}
				p.fsm.lock.Unlock()

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
