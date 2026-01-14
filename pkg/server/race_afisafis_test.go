package server

import (
	"context"
	"sync"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// TestRace_UpdatePrefixLimitConfig tests that updatePrefixLimitConfig is race-free
// when called concurrently with capabilitiesFromConfig (which writes to AfiSafis).
//
// The implementation uses copyAfiSafis() for deep copy protection.
// The race detector detects races at struct element level, not field level,
// so any concurrent access to the same AfiSafi element is a race even if
// reading/writing different fields.
//
// Run with: go test -race -count=1 ./pkg/server/... -run TestRace_UpdatePrefixLimitConfig
func TestRace_UpdatePrefixLimitConfig(t *testing.T) {
	s, _, peerAddrIP := newTestBgpServerWithPeer(t)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

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

	// Writer goroutine: repeatedly call newWatchEventPeer which triggers
	// capabilitiesFromConfig -> writes to AfiSafis[i].MpGracefulRestart.State.Advertised
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = newWatchEventPeer(testPeer, nil, bgp.BGP_FSM_IDLE, bgp.BGP_FSM_IDLE, apiutil.PEER_EVENT_STATE)
			}
		}
	}()

	// Reader goroutine: repeatedly call updatePrefixLimitConfig
	// In production, this receives a fresh config from API each time
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				// Get fresh config like production API calls would provide
				testPeer.fsm.lock.Lock()
				freshConfig := testPeer.copyAfiSafis()
				testPeer.fsm.lock.Unlock()
				_, _ = testPeer.updatePrefixLimitConfig(freshConfig)
			}
		}
	}()

	// Run for 2 seconds
	time.Sleep(2 * time.Second)
	close(stop)
	wg.Wait()
}

// TestRace_HandleUpdatePrefixLimit tests that the handleUpdate function's
// prefix limit checking loop is race-free when using copyAfiSafis.
//
// Run with: go test -race -count=1 ./pkg/server/... -run TestRace_HandleUpdatePrefixLimit
func TestRace_HandleUpdatePrefixLimit(t *testing.T) {
	s, _, peerAddrIP := newTestBgpServerWithPeer(t)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

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
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = newWatchEventPeer(testPeer, nil, bgp.BGP_FSM_IDLE, bgp.BGP_FSM_IDLE, apiutil.PEER_EVENT_STATE)
			}
		}
	}()

	// Reader goroutine: simulate reading AfiSafis like handleUpdate does
	// Uses copyAfiSafis for deep copy - should be race-free
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				// This is the pattern used in handleUpdate - deep copy via copyAfiSafis
				testPeer.fsm.lock.Lock()
				afiSafis := testPeer.copyAfiSafis()
				testPeer.fsm.lock.Unlock()
				// Iterate and read from elements - safe because we have a deep copy
				for _, af := range afiSafis {
					_ = af.State.Family
					_ = af.PrefixLimit.Config
				}
			}
		}
	}()

	// Run for 2 seconds
	time.Sleep(2 * time.Second)
	close(stop)
	wg.Wait()
}

// TestRace_HandleFSMMessageEOR tests that handleFSMMessage's EOR processing
// is race-free when using copyAfiSafis.
//
// Run with: go test -race -count=1 ./pkg/server/... -run TestRace_HandleFSMMessageEOR
func TestRace_HandleFSMMessageEOR(t *testing.T) {
	s, _, peerAddrIP := newTestBgpServerWithPeer(t)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

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
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = newWatchEventPeer(testPeer, nil, bgp.BGP_FSM_IDLE, bgp.BGP_FSM_IDLE, apiutil.PEER_EVENT_STATE)
			}
		}
	}()

	// Reader goroutine: simulate the EOR processing pattern in handleFSMMessage
	// Uses copyAfiSafis for deep copy - should be race-free
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				// This is the pattern used in handleFSMMessage EOR processing - deep copy
				testPeer.fsm.lock.Lock()
				peerAfiSafis := testPeer.copyAfiSafis()
				testPeer.fsm.lock.Unlock()

				// Iterate over AfiSafis looking for matching families - safe with deep copy
				for i, a := range peerAfiSafis {
					_ = a.State.Family
					_ = i
				}
			}
		}
	}()

	// Run for 2 seconds
	time.Sleep(2 * time.Second)
	close(stop)
	wg.Wait()
}
