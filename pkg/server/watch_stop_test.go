package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	api "github.com/osrg/gobgp/v4/api"
)

// TestWatcherStopDoesNotHoldTheServerLock checks that stopping a watcher with
// a long queue does not hold the server lock while the queue is drained:
// handleFSMMessage takes that lock for every message a peer sends, so a
// drain under it stops every session's receive loop.
func TestWatcherStopDoesNotHoldTheServerLock(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	// What a receive loop does for each message it reads, tried when the
	// drain starts.
	var readable bool
	w, err := s.watch(WatchPeer(), func(o *watchOptions) {
		o.stopDrainHook = func() {
			if s.shared.mu.TryRLock() {
				readable = true
				s.shared.mu.RUnlock()
			}
		}
	})
	require.NoError(t, err)
	for range 100_000 {
		w.notify(&watchEventPeer{})
	}
	w.Stop()
	require.True(t, readable, "the server lock was held while the watcher drained")
}
