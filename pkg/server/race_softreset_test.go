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

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// newTestBgpServerWithPeer creates a minimal BgpServer with one peer added.
// Returns the server and peer address (both as string for API use and netip.Addr for internal map access).
func newTestBgpServerWithPeer(t *testing.T) (*BgpServer, string, netip.Addr) {
	t.Helper()

	s := NewBgpServer()
	go s.Serve()

	// Start BGP with minimal config: no TCP listener (ListenPort: -1)
	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	if err != nil {
		t.Fatalf("StartBgp failed: %v", err)
	}

	// Add a peer with GracefulRestart enabled to exercise the race condition.
	// The race involves capabilitiesFromConfig writing to:
	//   pConf.AfiSafis[i].MpGracefulRestart.State.Advertised
	peerAddr := "2.2.2.2"
	peer := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: peerAddr,
			PeerAsn:         65002,
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
				},
				MpGracefulRestart: &api.MpGracefulRestart{
					Config: &api.MpGracefulRestartConfig{
						Enabled: true,
					},
				},
			},
		},
	}

	err = s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: peer})
	if err != nil {
		t.Fatalf("AddPeer failed: %v", err)
	}

	return s, peerAddr, netip.MustParseAddr(peerAddr)
}

// TestRace_SoftResetPeerAndWatch reproduces a data race reported by the Go race detector
// in production, involving concurrent access to peer configuration data.
//
// Race details from production logs:
//
// Write goroutine stack:
//
//	capabilitiesFromConfig()        <- pkg/server/fsm.go:788
//	  (writes pConf.AfiSafis[i].MpGracefulRestart.State.Advertised = true)
//	buildopen()                     <- pkg/server/fsm.go:826
//	newWatchEventPeer()             <- pkg/server/server.go:957
//	broadcastPeerState()            <- pkg/server/server.go:992
//
// The race occurs in toConfig() (server.go:837-870) which:
//  1. Acquires RLock (line 839)
//  2. Copies AfiSafis slice header: peerAfiSafis := peer.fsm.pConf.AfiSafis (line 841)
//  3. Releases RLock (line 843)
//  4. Iterates over peerAfiSafis (line 846): for i, af := range peerAfiSafis
//     This reads from the original slice elements WITHOUT holding any lock!
//  5. Later acquires Lock (line 868) and calls capabilitiesFromConfig
//     which WRITES to AfiSafis[i].MpGracefulRestart.State.Advertised
//
// The bug is that step 4 reads from shared memory after releasing the lock,
// while another goroutine (in step 5) can be writing to the same memory.
//
// To run this test:
//
//	go test -race -count=1 ./pkg/server/... -run TestRace_SoftResetPeerAndWatch
//
// This test was originally added to reproduce a data race in the unfixed code,
// which caused "race detected during execution of test" when run with -race.
// With the race fixed, this test is now expected to PASS (even under -race) and
// serves as a regression test to ensure the race does not reappear.
func TestRace_SoftResetPeerAndWatch(t *testing.T) {
	s, peerAddr, peerAddrIP := newTestBgpServerWithPeer(t)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	// Get the internal peer object for direct access to internal functions
	var testPeer *peer
	err := s.mgmtOperation(func() error {
		testPeer = s.neighborMap[peerAddrIP]
		return nil
	}, true)
	if err != nil {
		t.Fatalf("mgmtOperation failed: %v", err)
	}

	if testPeer == nil {
		t.Fatal("Could not get internal peer object")
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Writer goroutine: repeatedly call newWatchEventPeer
	// This triggers: buildopen -> capabilitiesFromConfig which WRITES to
	// pConf.AfiSafis[i].MpGracefulRestart.State.Advertised while holding Lock
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				// This is the write path from the production stack trace:
				// newWatchEventPeer -> buildopen -> capabilitiesFromConfig
				_ = newWatchEventPeer(testPeer, nil, bgp.BGP_FSM_IDLE, bgp.BGP_FSM_IDLE, apiutil.PEER_EVENT_STATE)
			}
		}
	}()

	// Reader goroutine: repeatedly call toConfig directly
	// toConfig reads from pConf.AfiSafis after releasing RLock (the race!)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				// toConfig: the buggy pattern is:
				// 1. Copy slice header under lock
				// 2. Release lock
				// 3. Iterate over slice elements WITHOUT lock (race!)
				_ = s.toConfig(testPeer, true)
			}
		}
	}()

	// Additional goroutine: trigger peer state changes via API
	// This exercises the broadcastPeerState -> newWatchEventPeer path
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx := context.Background()
		for {
			select {
			case <-stop:
				return
			default:
				_ = s.DisablePeer(ctx, &api.DisablePeerRequest{Address: peerAddr})
				_ = s.EnablePeer(ctx, &api.EnablePeerRequest{Address: peerAddr})
			}
		}
	}()

	// Additional goroutine: ListPeer API which calls toConfig internally
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx := context.Background()
		for {
			select {
			case <-stop:
				return
			default:
				_ = s.ListPeer(ctx, &api.ListPeerRequest{
					Address:          peerAddr,
					EnableAdvertised: true, // Triggers capabilitiesFromConfig call
				}, func(*api.Peer) {})
			}
		}
	}()

	// Let the goroutines run to trigger the race
	time.Sleep(2 * time.Second)

	close(stop)
	wg.Wait()

	// This test is expected to FAIL with -race due to data race detection.
	// Once the race is fixed in the production code, this test should PASS.
}
