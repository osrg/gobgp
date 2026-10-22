package server

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// lsNodeNLRI is a BGP-LS node NLRI of the OSPF protocol whose descriptor
// carries the given area. NLRI.String does not show the area.
func lsNodeNLRI(t *testing.T, area byte) bgp.NLRI {
	t.Helper()
	nlri, err := bgp.NLRIFromSlice(bgp.RF_LS, []byte{
		0x00, 0x01, 0x00, 0x25, // Node NLRI
		0x03,                                           // Protocol OSPFv2
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ID
		0x01, 0x00, 0x00, 0x18, // Local Node Desc
		0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xfd, 0xe8, // TLV ASN: 65000
		0x02, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, area, // TLV OSPF Area ID
		0x02, 0x03, 0x00, 0x04, 0x0a, 0x00, 0x00, 0x01, // TLV IGP Router ID: 10.0.0.1
	})
	require.NoError(t, err)
	return nlri
}

// TestWatchPolicyBgpLsNodesOfTwoAreas checks that two BGP-LS nodes whose
// String is the same, since it omits the OSPF area, are two destinations for
// the watcher, as they are for the RIB: withdrawing one withdraws that one.
func TestWatchPolicyBgpLsNodesOfTwoAreas(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	addWatchPolicy(t, s, "tagged")
	w, err := s.watch(WatchBestPath(false), WatchBestPathPolicy("tagged"))
	require.NoError(t, err)
	defer w.Stop()

	a, b := lsNodeNLRI(t, 1), lsNodeNLRI(t, 2)
	require.Equal(t, a.String(), b.String())
	p := func(n bgp.NLRI, withdraw bool) *table.Path {
		return tablePath(t, bgp.RF_LS, n, "192.0.2.1", 0, true, withdraw)
	}

	serialized := func(ev watchEvent) (out [][]byte) {
		for _, path := range ev.(*watchEventBestPath).PathList {
			ser, err := path.GetNlri().Serialize()
			require.NoError(t, err)
			out = append(out, ser)
		}
		return out
	}
	next := func() watchEvent {
		select {
		case ev := <-w.Event():
			return ev
		case <-time.After(10 * time.Second):
			t.Fatal("no best path event")
			return nil
		}
	}
	serA, err := a.Serialize()
	require.NoError(t, err)
	serB, err := b.Serialize()
	require.NoError(t, err)

	notifyBest(s, p(a, false), p(b, false))
	assert.Equal(t, [][]byte{serA, serB}, serialized(next()))
	notifyBest(s, p(a, true))
	assert.Equal(t, [][]byte{serA}, serialized(next()), "the withdrawal of a node named another")
	notifyBest(s, p(b, true))
	assert.Equal(t, [][]byte{serB}, serialized(next()))
}

// TestWatchPolicyInitialTableTracksOnlyItsOwnDestinations checks that, while
// the initial table waits for its client, churn on destinations the table
// does not hold leaves nothing recorded for them: what is tracked never
// exceeds the table, however long the initial send is blocked.
func TestWatchPolicyInitialTableTracksOnlyItsOwnDestinations(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	addWatchPolicy(t, s, "tagged")
	_, err := s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{
		watchPolicyPath(t, "10.0.1.0/24", true),
		watchPolicyPath(t, "10.0.2.0/24", true),
		watchPolicyPath(t, "10.0.3.0/24", true),
	}})
	require.NoError(t, err)

	entered, release := make(chan struct{}), make(chan struct{})
	var first atomic.Bool
	hook := func(o *watchOptions) {
		o.initChunkHook = func() {
			if first.CompareAndSwap(false, true) {
				close(entered)
				<-release
			}
		}
	}
	r := &bestPathRecorder{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, s.WatchEvent(ctx, WatchEventMessageCallbacks{OnBestPath: r.onBestPath},
		WatchBestPath(true), WatchBestPathPolicy("tagged"), hook))
	<-entered
	w := findBestWatcher(t, s)

	for i := range 300 {
		prefix := fmt.Sprintf("10.%d.%d.0/24", 100+i/250, i%250)
		_, err = s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{watchPolicyPath(t, prefix, true)}})
		require.NoError(t, err)
		require.NoError(t, s.DeletePath(apiutil.DeletePathRequest{Paths: []*apiutil.Path{watchPolicyPath(t, prefix, true)}}))
	}
	w.mu.Lock()
	pending := w.pending.Len()
	w.mu.Unlock()
	assert.Equal(t, 3, pending, "destinations tracked while the initial table is blocked")

	close(release)
	assert.Equal(t, map[string]bool{"10.0.1.0/24": false, "10.0.2.0/24": false, "10.0.3.0/24": false}, r.next(t, 0), "initial table")
	w.mu.Lock()
	assert.Nil(t, w.pending)
	w.mu.Unlock()
}

// TestWatchPolicyInitialTableBetweenChunks pauses the initial table between
// its first and second chunk and changes destinations of the table: one
// already evaluated and sent, one not evaluated yet. The watcher ends up
// holding exactly the accepted paths: the one sent is withdrawn, the one not
// evaluated is left to its own event, which rejects it.
func TestWatchPolicyInitialTableBetweenChunks(t *testing.T) {
	const total = watchInitChunk + 76
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	addWatchPolicy(t, s, "tagged")
	var paths []*apiutil.Path
	want := map[string]bool{}
	for i := range total {
		prefix := fmt.Sprintf("10.%d.%d.0/24", i/250, i%250)
		paths = append(paths, watchPolicyPath(t, prefix, true))
		want[prefix] = true
	}
	_, err := s.AddPath(apiutil.AddPathRequest{Paths: paths})
	require.NoError(t, err)

	paused, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	hook := func(o *watchOptions) {
		o.initChunkHook = func() {
			if calls.Add(1) == 2 {
				close(paused)
				<-release
			}
		}
	}
	r := &bestPathRecorder{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, s.WatchEvent(ctx, WatchEventMessageCallbacks{OnBestPath: r.onBestPath},
		WatchBestPath(true), WatchBestPathPolicy("tagged"), hook))
	<-paused
	w := findBestWatcher(t, s)

	// Between the chunks: the first one is announced, the second is not.
	var sent, notYet string
	w.mu.Lock()
	require.Equal(t, watchInitChunk, w.announced.Len())
	for a := range w.announced.Values() {
		sent = a.GetNlri().String()
		break
	}
	require.Equal(t, total-watchInitChunk, w.pending.Len())
	for p := range want {
		if sent == p {
			continue
		}
		found := false
		for a := range w.announced.Values() {
			if a.GetNlri().String() == p {
				found = true
				break
			}
		}
		if !found {
			notYet = p
			break
		}
	}
	w.mu.Unlock()
	require.NotEmpty(t, notYet)

	_, err = s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{
		watchPolicyPath(t, sent, false), watchPolicyPath(t, notYet, false),
	}})
	require.NoError(t, err)
	close(release)

	// The table carries what was accepted before the pause and after it,
	// less the destination changed before its chunk; the change of the
	// destination sent withdraws it.
	state := map[string]bool{}
	for n := range 2 {
		for p, withdrawn := range r.next(t, n) {
			if withdrawn {
				delete(state, p)
			} else {
				state[p] = true
			}
		}
	}
	delete(want, sent)
	delete(want, notYet)
	assert.Equal(t, want, state)
}

// TestWatchFailedWatcherLeavesNoState checks that a watcher that failed does
// not evaluate its policy nor change what it remembers, and that, while its
// callback is blocked and never returns, it is deregistered and its policy
// reference released.
func TestWatchFailedWatcherLeavesNoState(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	addWatchPolicy(t, s, "tagged")
	_, err := s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{watchPolicyPath(t, "10.0.1.0/24", true)}})
	require.NoError(t, err)

	inCallback := make(chan struct{})
	var once sync.Once
	block := make(chan struct{})
	defer close(block)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, s.WatchEvent(ctx, WatchEventMessageCallbacks{
		OnBestPath: func([]*apiutil.Path, time.Time) {
			once.Do(func() { close(inCallback) })
			<-block
		},
	}, WatchBestPath(true), WatchBestPathPolicy("tagged")))
	select {
	case <-inCallback:
	case <-time.After(10 * time.Second):
		t.Fatal("the callback was not called")
	}
	w := findBestWatcher(t, s)

	w.fail(errors.New("forced"))

	// The callback has not returned, yet the watcher is gone and the policy
	// is free.
	require.Eventually(t, func() bool { return !s.isWatched(watchEventTypeBestPath) }, 10*time.Second, 10*time.Millisecond,
		"the failed watcher is still registered while its callback is blocked")
	del := &api.DeletePolicyRequest{Policy: &api.Policy{Name: "tagged"}, All: true}
	require.Eventually(t, func() bool { return s.DeletePolicy(context.Background(), del) == nil }, 10*time.Second, 10*time.Millisecond,
		"the failed watcher still holds its policy")

	// A notification that still reaches the failed watcher changes nothing.
	w.mu.Lock()
	before := w.announced.Len()
	w.mu.Unlock()
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.9.0/24"))
	require.NoError(t, err)
	assert.Nil(t, s.filterBestPath(w, []*table.Path{tablePath(t, bgp.RF_IPv4_UC, nlri, "192.0.2.1", 0, true, false)}, time.Now()))
	w.mu.Lock()
	assert.Equal(t, before, w.announced.Len())
	w.mu.Unlock()
}

// TestWatchFailAndStopRace checks that the failure of a watcher, which stops
// it from a goroutine of its own, and the stops of the callback goroutine and
// of the client are safe together: the watcher is removed, drained and its
// policy released once, whatever the order.
func TestWatchFailAndStopRace(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	addWatchPolicy(t, s, "tagged")
	for range 50 {
		w, err := s.watch(WatchBestPath(false), WatchBestPathPolicy("tagged"))
		require.NoError(t, err)
		var wg sync.WaitGroup
		for _, f := range []func(){
			func() { w.fail(errors.New("a")) },
			func() { w.fail(errors.New("b")) },
			w.Stop,
			w.Stop,
		} {
			wg.Add(1)
			go func() { defer wg.Done(); f() }()
		}
		wg.Wait()
		w.Stop()
		require.Eventually(t, func() bool { return !s.isWatched(watchEventTypeBestPath) }, 10*time.Second, time.Millisecond)
	}
	// One release per watcher: the policy has no reference left.
	del := &api.DeletePolicyRequest{Policy: &api.Policy{Name: "tagged"}, All: true}
	require.Eventually(t, func() bool { return s.DeletePolicy(context.Background(), del) == nil }, 10*time.Second, 10*time.Millisecond)
}

// TestWatchFailureRefusesTheAdmissionOfQueuedEvents checks that no callback
// is admitted after the watcher failed, even when an event is already
// waiting: with the callback goroutine held inside its first callback, an
// event is queued, the watcher fails and the callback returns; the goroutine
// finds the event and the failure both ready and must not deliver the event.
// The test waits for the goroutine to end, not for a time to pass.
func TestWatchFailureRefusesTheAdmissionOfQueuedEvents(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	addWatchPolicy(t, s, "tagged")
	_, err := s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{watchPolicyPath(t, "10.0.1.0/24", true)}})
	require.NoError(t, err)

	inCallback, release := make(chan struct{}), make(chan struct{})
	holdStop := make(chan struct{})
	defer close(holdStop)
	exited := make(chan struct{})
	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, s.WatchEvent(ctx, WatchEventMessageCallbacks{
		OnBestPath: func([]*apiutil.Path, time.Time) {
			if calls.Add(1) == 1 {
				close(inCallback)
				<-release
			}
		},
	}, WatchBestPath(true), WatchBestPathPolicy("tagged"), func(o *watchOptions) {
		// Keep Stop from draining the event the test queued.
		o.stopDrainHook = func() { <-holdStop }
		o.callbacksDoneHook = func() { close(exited) }
	}))
	<-inCallback
	w := findBestWatcher(t, s)

	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.2.0/24"))
	require.NoError(t, err)
	notifyBest(s, tablePath(t, bgp.RF_IPv4_UC, nlri, "192.0.2.1", 0, true, false))
	require.Eventually(t, func() bool { return len(w.Event()) == 1 }, 10*time.Second, time.Millisecond, "the event did not reach the goroutine's channel")
	w.fail(errors.New("forced"))
	close(release)

	// The goroutine finds the event and the failure ready, delivers nothing
	// and ends.
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("the callback goroutine did not end")
	}
	assert.Equal(t, int32(1), calls.Load(), "a callback was admitted after the watcher failed")
}

// TestWatchInitialTableStopsWithinAChunk checks that the initial table stops
// at the path being evaluated when the watcher fails, not at the end of its
// chunk, and sends nothing.
func TestWatchInitialTableStopsWithinAChunk(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	addWatchPolicy(t, s, "tagged")
	var paths []*apiutil.Path
	for i := range 100 {
		paths = append(paths, watchPolicyPath(t, fmt.Sprintf("10.0.%d.0/24", i), true))
	}
	_, err := s.AddPath(apiutil.AddPathRequest{Paths: paths})
	require.NoError(t, err)

	var evaluated atomic.Int32
	var watched atomic.Pointer[watcher]
	ready := make(chan struct{})
	exited := make(chan struct{})
	r := &bestPathRecorder{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, s.WatchEvent(ctx, WatchEventMessageCallbacks{OnBestPath: r.onBestPath},
		WatchBestPath(true), WatchBestPathPolicy("tagged"), func(o *watchOptions) {
			// The chunk waits until the test has the watcher.
			o.initChunkHook = func() { <-ready }
			o.callbacksDoneHook = func() { close(exited) }
			o.initPathHook = func() {
				if evaluated.Add(1) == 3 {
					// Fail from inside the chunk: the next path is not evaluated.
					watched.Load().fail(errors.New("forced"))
				}
			}
		}))
	watched.Store(findBestWatcher(t, s))
	close(ready)
	// The goroutine that evaluates the table ends at the failure.
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("the initial table did not stop")
	}
	assert.Equal(t, int32(3), evaluated.Load(), "paths evaluated after the failure")
	r.mu.Lock()
	assert.Empty(t, r.events)
	r.mu.Unlock()
}

// TestWatchStopReleasesWhatTheWatcherHolds checks that a stopped watcher whose
// callback is blocked holds no destination of its policy and is not kept
// reachable by the watchers list.
func TestWatchStopReleasesWhatTheWatcherHolds(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	addWatchPolicy(t, s, "tagged")
	_, err := s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{
		watchPolicyPath(t, "10.0.1.0/24", true), watchPolicyPath(t, "10.0.2.0/24", true),
	}})
	require.NoError(t, err)

	inCallback := make(chan struct{})
	var once sync.Once
	block := make(chan struct{})
	defer close(block)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, s.WatchEvent(ctx, WatchEventMessageCallbacks{
		OnBestPath: func([]*apiutil.Path, time.Time) {
			once.Do(func() { close(inCallback) })
			<-block
		},
	}, WatchBestPath(true), WatchBestPathPolicy("tagged")))
	<-inCallback
	w := findBestWatcher(t, s)
	w.mu.Lock()
	require.Equal(t, 2, w.announced.Len())
	w.mu.Unlock()
	s.watcherMu.RLock()
	list := s.watcherMap[watchEventTypeBestPath]
	s.watcherMu.RUnlock()

	w.Stop()

	w.mu.Lock()
	assert.Nil(t, w.announced)
	assert.Nil(t, w.pending)
	w.mu.Unlock()
	assert.Nil(t, list[0], "the watchers list still references the stopped watcher")
}

// vpnPath is a path of 10.30.2.0/24 under one route distinguisher and the
// given label.
func vpnPath(t *testing.T, label uint32, tagged, withdraw bool) *table.Path {
	t.Helper()
	d, err := bgp.ParseRouteDistinguisher("100:100")
	require.NoError(t, err)
	n, err := bgp.NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix("10.30.2.0/24"), *bgp.NewMPLSLabelStack(label), d)
	require.NoError(t, err)
	return tablePath(t, bgp.RF_IPv4_VPN, n, "192.0.2.1", 0, tagged, withdraw)
}

// TestWatchPolicyVpnLabelChange checks that a destination is the same under
// another label, as in the RIB: a path accepted with one label and replaced
// by a rejected one with another is withdrawn, and label churn leaves one
// destination tracked.
func TestWatchPolicyVpnLabelChange(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	addWatchPolicy(t, s, "tagged")
	w, err := s.watch(WatchBestPath(false), WatchBestPathPolicy("tagged"))
	require.NoError(t, err)
	defer w.Stop()

	notifyBest(s, vpnPath(t, 100, true, false))
	require.Len(t, nextBest(t, w), 1)
	notifyBest(s, vpnPath(t, 200, false, false))
	got := nextBest(t, w)
	require.Len(t, got, 1)
	assert.True(t, got[0].withdraw, "the path accepted with the old label was not withdrawn")

	for label := uint32(300); label < 400; label++ {
		notifyBest(s, vpnPath(t, label, true, false))
		nextBest(t, w)
	}
	w.mu.Lock()
	assert.Equal(t, 1, w.announced.Len(), "label churn grew what is tracked")
	w.mu.Unlock()
}

// TestWatchFailsWhenADestinationCannotBeIdentified checks that a best path
// whose destination cannot be identified (a BGP-LS NLRI that cannot be
// serialized) fails the watch with ErrWatchDestination, never colliding
// with another destination through its string form.
func TestWatchFailsWhenADestinationCannotBeIdentified(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	addWatchPolicy(t, s, "tagged")
	w, err := s.watch(WatchBestPath(false), WatchBestPathPolicy("tagged"))
	require.NoError(t, err)
	defer w.Stop()

	// A node whose descriptor carries a sub-TLV the decoder does not know:
	// it decodes, keeps its length, and cannot be serialized.
	bad, err := bgp.NLRIFromSlice(bgp.RF_LS, []byte{
		0x00, 0x01, 0x00, 0x2d,
		0x03,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x20,
		0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xfd, 0xe8,
		0x02, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01,
		0x02, 0x03, 0x00, 0x04, 0x0a, 0x00, 0x00, 0x01,
		0x02, 0x99, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01,
	})
	require.NoError(t, err)
	_, err = bad.Serialize()
	require.Error(t, err)
	notifyBest(s, tablePath(t, bgp.RF_LS, bad, "192.0.2.1", 0, true, false))
	select {
	case <-w.Done():
		require.ErrorIs(t, w.Err(), ErrWatchDestination)
	case <-time.After(10 * time.Second):
		t.Fatal("the watch did not fail")
	}
	require.Eventually(t, func() bool { return !s.isWatched(watchEventTypeBestPath) }, 10*time.Second, time.Millisecond)
}

// TestWatchNoCallbackIsAdmittedAfterFailure checks the admission contract of
// failure at the points where a callback is about to be admitted: the watcher
// fails while what the callback receives is converted, and between the
// batches of an event; the callback in flight goes on and no further one is
// admitted.
func TestWatchNoCallbackIsAdmittedAfterFailure(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	addWatchPolicy(t, s, "tagged")
	var paths []*apiutil.Path
	for i := range 10 {
		paths = append(paths, watchPolicyPath(t, fmt.Sprintf("10.0.%d.0/24", i), true))
	}
	_, err := s.AddPath(apiutil.AddPathRequest{Paths: paths})
	require.NoError(t, err)

	t.Run("during conversion", func(t *testing.T) {
		var calls atomic.Int32
		failed := make(chan error, 1)
		var watched atomic.Pointer[watcher]
		ready := make(chan struct{})
		exited := make(chan struct{})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		require.NoError(t, s.WatchEvent(ctx, WatchEventMessageCallbacks{
			OnBestPath: func([]*apiutil.Path, time.Time) { calls.Add(1) },
			OnError:    func(err error) { failed <- err },
		}, WatchBestPath(true), WatchBestPathPolicy("tagged"), func(o *watchOptions) {
			o.initChunkHook = func() { <-ready }
			o.beforeDeliverHook = func() { watched.Load().fail(errors.New("forced")) }
			o.callbacksDoneHook = func() { close(exited) }
		}))
		watched.Store(findBestWatcher(t, s))
		close(ready)
		select {
		case err := <-failed:
			require.Error(t, err)
		case <-time.After(10 * time.Second):
			t.Fatal("OnError was not called")
		}
		select {
		case <-exited:
		case <-time.After(10 * time.Second):
			t.Fatal("the callback goroutine did not end")
		}
		assert.Equal(t, int32(0), calls.Load(), "a callback was admitted after the watcher failed")
		require.Eventually(t, func() bool { return !s.isWatched(watchEventTypeBestPath) }, 10*time.Second, time.Millisecond)
	})

	t.Run("between batches", func(t *testing.T) {
		var calls atomic.Int32
		var watched atomic.Pointer[watcher]
		ready := make(chan struct{})
		done := make(chan struct{})
		exited := make(chan struct{})
		var once sync.Once
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		require.NoError(t, s.WatchEvent(ctx, WatchEventMessageCallbacks{
			BestPathBatchSize: 2,
			OnBestPathBatch: func([]*apiutil.Path, time.Time, bool) {
				calls.Add(1)
				// In flight: the failure lands while this callback runs.
				watched.Load().fail(errors.New("forced"))
			},
			OnError: func(error) { once.Do(func() { close(done) }) },
		}, WatchBestPath(true), WatchBestPathPolicy("tagged"), func(o *watchOptions) {
			o.initChunkHook = func() { <-ready }
			o.callbacksDoneHook = func() { close(exited) }
		}))
		watched.Store(findBestWatcher(t, s))
		close(ready)
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("OnError was not called")
		}
		select {
		case <-exited:
		case <-time.After(10 * time.Second):
			t.Fatal("the callback goroutine did not end")
		}
		assert.Equal(t, int32(1), calls.Load(), "a batch was admitted after the watcher failed")
	})
}

// TestWatchAdmittedDeliveryMayFollowFailure checks the contract of failure at
// its linearization point: a delivery admitted before the watcher failed may
// run after fail and after OnError, and OnError does not wait for it; every
// delivery after the failure is refused. The delivery is held between its
// admission and its callback while the watcher fails and OnError is called.
func TestWatchAdmittedDeliveryMayFollowFailure(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	addWatchPolicy(t, s, "tagged")
	_, err := s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{watchPolicyPath(t, "10.0.1.0/24", true)}})
	require.NoError(t, err)

	admitted, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var calls atomic.Int32
	ran := make(chan struct{}, 4)
	onError := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, s.WatchEvent(ctx, WatchEventMessageCallbacks{
		OnBestPath: func([]*apiutil.Path, time.Time) {
			calls.Add(1)
			ran <- struct{}{}
		},
		OnError: func(err error) { onError <- err },
	}, WatchBestPath(true), WatchBestPathPolicy("tagged"), func(o *watchOptions) {
		o.admittedHook = func() {
			once.Do(func() {
				close(admitted)
				<-resume
			})
		}
	}))
	<-admitted
	w := findBestWatcher(t, s)
	w.fail(errors.New("forced"))
	select {
	case err := <-onError:
		require.Error(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("OnError waited for the admitted delivery")
	}
	assert.Equal(t, int32(0), calls.Load(), "the admitted callback ran before it was released")

	close(resume)
	select {
	case <-ran:
	case <-time.After(10 * time.Second):
		t.Fatal("the admitted delivery did not run")
	}
	assert.False(t, w.deliver(func() { calls.Add(1) }), "a delivery after the failure was admitted")
	assert.Equal(t, int32(1), calls.Load(), "exactly the admitted callback runs")
}
