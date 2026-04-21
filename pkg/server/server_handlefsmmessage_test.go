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
	"github.com/osrg/gobgp/v4/internal/pkg/table"
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

func TestSoftResetOutSerializesNormalReset(t *testing.T) {
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

	peerAddr := netip.MustParseAddr("10.0.0.1")
	p := newPeerandInfo(t, 65001, 65002, peerAddr.String(), s.globalRib)
	p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
	err = s.mgmtOperation(func() error {
		s.neighborMap[peerAddr] = p
		return nil
	}, true)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := s.mgmtOperation(func() error {
			delete(s.neighborMap, peerAddr)
			return nil
		}, false)
		require.NoError(t, err)
		require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
	})

	p.routeRefreshInProgress.RLock()
	locked := true
	defer func() {
		if locked {
			p.routeRefreshInProgress.RUnlock()
		}
	}()

	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		done <- s.softResetOut(peerAddr.String(), bgp.RF_IPv4_UC, false)
	}()
	<-started

	select {
	case err := <-done:
		p.routeRefreshInProgress.RUnlock()
		locked = false
		require.NoError(t, err)
		t.Fatal("normal soft reset out completed while live propagation held the route-refresh read lock")
	case <-time.After(200 * time.Millisecond):
	}

	p.routeRefreshInProgress.RUnlock()
	locked = false

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("normal soft reset out did not complete after the route-refresh read lock was released")
	}
}

func TestRTCMembershipSerializesTriggeredVPNUpdates(t *testing.T) {
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

	peerAddr := netip.MustParseAddr("10.0.0.1")
	p := newPeerandInfo(t, 65001, 65002, peerAddr.String(), s.globalRib)
	p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
	p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{
		bgp.RF_RTC_UC:      bgp.BGP_ADD_PATH_NONE,
		bgp.RF_IPv4_VPN:    bgp.BGP_ADD_PATH_NONE,
		bgp.RF_IPv6_VPN:    bgp.BGP_ADD_PATH_NONE,
		bgp.RF_FS_IPv4_VPN: bgp.BGP_ADD_PATH_NONE,
		bgp.RF_FS_IPv6_VPN: bgp.BGP_ADD_PATH_NONE,
	})
	t.Cleanup(func() {
		cleanInfiniteChannel(p.fsm.outgoingCh)
		require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
	})

	_, rt, err := parseRDRT("65001:100")
	require.NoError(t, err)
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.0.2.254"))
	require.NoError(t, err)
	rtcPath := table.NewPath(bgp.RF_RTC_UC, p.peerInfo.Load(), bgp.PathNLRI{
		NLRI: bgp.NewRouteTargetMembershipNLRI(65001, rt),
	}, false, []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		nh,
	}, time.Now(), false)
	require.NotNil(t, rtcPath)

	p.routeRefreshInProgress.Lock()
	locked := true
	defer func() {
		if locked {
			p.routeRefreshInProgress.Unlock()
		}
	}()

	done := make(chan struct{})
	go func() {
		s.processRTCMembership(p, rtcPath)
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("RTC-triggered VPN update completed while route refresh was in progress")
	case <-time.After(200 * time.Millisecond):
	}

	p.routeRefreshInProgress.Unlock()
	locked = false

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RTC-triggered VPN update did not complete after route refresh finished")
	}
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
