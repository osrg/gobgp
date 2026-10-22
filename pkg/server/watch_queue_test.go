package server

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eapache/channels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// addPrefixes adds n local paths, one best path event each, carrying
// communities so that every event is of a meaningful size.
func addPrefixes(t *testing.T, s *BgpServer, first, n, communities int) {
	t.Helper()
	comms := make([]uint32, communities)
	for i := range comms {
		comms[i] = 65000<<16 | uint32(i)
	}
	addPrefixesWith(t, s, first, n, comms)
}

// addPrefixesWith adds n local paths carrying comms, one best path event
// each.
func addPrefixesWith(t *testing.T, s *BgpServer, first, n int, comms []uint32) {
	t.Helper()
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	require.NoError(t, err)
	const batch = 1000
	for start := first; start < first+n; start += batch {
		paths := make([]*apiutil.Path, 0, batch)
		for i := start; i < start+batch && i < first+n; i++ {
			nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)))
			require.NoError(t, err)
			attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh, bgp.NewPathAttributeCommunities(comms)}
			p, err := apiutil.NewPath(bgp.RF_IPv4_UC, nlri, false, attrs, time.Now())
			require.NoError(t, err)
			paths = append(paths, mustApi2apiutilPath(p))
		}
		_, err := s.AddPath(apiutil.AddPathRequest{Paths: paths})
		require.NoError(t, err)
	}
}

// findBestWatcher returns the one watcher of the server that takes best path
// events.
func findBestWatcher(t *testing.T, s *BgpServer) *watcher {
	t.Helper()
	s.watcherMu.RLock()
	defer s.watcherMu.RUnlock()
	require.Len(t, s.watcherMap[watchEventTypeBestPath], 1)
	return s.watcherMap[watchEventTypeBestPath][0]
}

// newDetachedWatcher returns a watcher that is not registered with the
// server and has no goroutine moving its events to its consumer: what it
// queues stays queued, so that its queue can be inspected. Its Stop frees the
// queue.
func newDetachedWatcher(s *BgpServer, limit int) *watcher {
	w := &watcher{
		s:       s,
		filters: make(map[watchEventType]func(w watchEvent) bool),
		done:    make(chan struct{}),
		realCh:  make(chan watchEvent, 8),
		ch:      channels.NewInfiniteChannel(),
	}
	// Nothing moves events to the consumer: Stop has nothing to wait for.
	close(w.realCh)
	w.opts.queueLimit = limit
	return w
}

// TestWatchQueueLimitBoundsAStalledWatcher checks that a watcher whose
// client never reads stops queueing at its limit and fails, while a watcher
// without a limit queues every event.
func TestWatchQueueLimitBoundsAStalledWatcher(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	const limit = 100
	bounded, err := s.watch(WatchBestPath(false), WatchQueueLimit(limit))
	require.NoError(t, err)
	defer bounded.Stop()
	unbounded, err := s.watch(WatchBestPath(false))
	require.NoError(t, err)
	defer unbounded.Stop()

	addPrefixes(t, s, 0, 5000, 1)

	select {
	case <-bounded.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the bounded watcher did not fail")
	}
	require.ErrorIs(t, bounded.Err(), ErrWatchQueueFull)
	// Nothing reads the watcher: the queue held the limit, and its
	// consumer's buffer what it handed over before the failure.
	assert.GreaterOrEqual(t, bounded.admitted.Load(), int64(limit))
	assert.LessOrEqual(t, bounded.admitted.Load(), int64(limit+cap(bounded.realCh)), "the bounded watcher queued past its limit")
	// The unbounded watcher holds them all.
	assert.Eventually(t, func() bool { return unbounded.admitted.Load() >= 5000 }, 10*time.Second, 10*time.Millisecond)

	// A failed watcher admits nothing more: measured at its admissions, not
	// at the queue, which the stop of the failed watcher drains.
	before := bounded.admitted.Load()
	for range 100 {
		bounded.notify(&watchEventPeer{})
	}
	assert.Equal(t, before, bounded.admitted.Load())
}

// TestWatchQueueLimitIsStrict checks that the limit holds when several
// notifiers reach a watcher at once, with the queue one event short of it:
// the check and the enqueue of an event are one step, so exactly one of them
// is admitted, never two.
func TestWatchQueueLimitIsStrict(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	const (
		limit     = 4
		notifiers = 16
	)
	for round := range 200 {
		w := newDetachedWatcher(s, limit)
		for range limit - 1 {
			w.notify(&watchEventPeer{})
		}
		require.False(t, w.failed.Load())

		start := make(chan struct{})
		var wg sync.WaitGroup
		for range notifiers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				w.notify(&watchEventPeer{})
			}()
		}
		close(start)
		wg.Wait()

		require.Equal(t, int64(limit), w.admitted.Load(), "round %d: the limit was not strict", round)
		require.True(t, w.failed.Load(), "round %d: the watcher did not fail at its limit", round)
		require.ErrorIs(t, w.Err(), ErrWatchQueueFull)
		w.Stop()
	}
}

// TestWatchQueueLimitCountsEveryNotifier checks the limit with notifiers
// that all start well short of it: the events admitted are exactly the
// limit, whatever the interleaving.
func TestWatchQueueLimitCountsEveryNotifier(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	const (
		limit     = 50
		notifiers = 8
		each      = 40
	)
	w := newDetachedWatcher(s, limit)
	defer w.Stop()
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range notifiers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range each {
				w.notify(&watchEventPeer{})
			}
		}()
	}
	close(start)
	wg.Wait()
	assert.Equal(t, int64(limit), w.admitted.Load())
	assert.ErrorIs(t, w.Err(), ErrWatchQueueFull)
}

// TestWatchQueueLimitValues checks the limits WatchQueueLimit and the gRPC
// field max_queued_events accept: zero is no limit, one is the smallest, the
// largest an int holds is accepted, and what is not representable or is
// negative is refused (InvalidArgument over gRPC, ErrWatchInvalid
// natively).
func TestWatchQueueLimitValues(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	t.Run("native", func(t *testing.T) {
		for _, tc := range []struct {
			limit int
			ok    bool
		}{
			{0, true}, {1, true}, {math.MaxInt, true}, {-1, false}, {math.MinInt, false},
		} {
			w, err := s.watch(WatchPeer(), WatchQueueLimit(tc.limit))
			if tc.ok {
				require.NoError(t, err, "limit %d", tc.limit)
				assert.Equal(t, tc.limit, w.opts.queueLimit)
				w.Stop()
				continue
			}
			require.ErrorIs(t, err, ErrWatchInvalid, "limit %d", tc.limit)
		}
		require.False(t, s.isWatched(watchEventTypePeerState), "a refused watch stayed registered")
	})

	t.Run("conversion", func(t *testing.T) {
		// The conversion with the largest int of a 64-bit and of a 32-bit
		// platform, whatever the platform of the test.
		for _, maxInt := range []int64{math.MaxInt64, math.MaxInt32} {
			for _, tc := range []struct {
				v  uint32
				ok bool
			}{
				{0, true},
				{1, true},
				{math.MaxInt32, true},
				{math.MaxInt32 + 1, maxInt > math.MaxInt32},
				{math.MaxUint32, maxInt > math.MaxInt32},
			} {
				got, err := watchQueueLimit(tc.v, maxInt)
				if tc.ok {
					require.NoError(t, err, "limit %d, max %d", tc.v, maxInt)
					if int64(tc.v) <= math.MaxInt { // the platform's int holds it
						assert.Equal(t, int(tc.v), got)
					}
					continue
				}
				require.Equal(t, codes.InvalidArgument, status.Code(err), "limit %d, max %d: %v", tc.v, maxInt, err)
			}
		}
	})

	t.Run("request", func(t *testing.T) {
		srv := &server{bgpServer: s}
		// The largest max_queued_events this platform's int holds, and the
		// value above it when there is one (a 32-bit platform).
		largest, maxInt := uint32(math.MaxUint32), math.MaxInt
		if uint64(maxInt) < uint64(largest) {
			largest = uint32(maxInt)
		}
		type request struct {
			v    uint32
			want int
			ok   bool
		}
		requests := []request{{0, 0, true}, {1, 1, true}, {largest, int(largest), true}}
		if largest < math.MaxUint32 {
			requests = append(requests, request{largest + 1, 0, false})
		}
		for _, tc := range requests {
			ctx, cancel := context.WithCancel(context.Background())
			err := srv.watchEvent(ctx, &api.WatchEventRequest{
				Peer:            &api.WatchEventRequest_Peer{},
				MaxQueuedEvents: tc.v,
			}, func(*api.WatchEventResponse, time.Time) {}, func(error) {})
			if tc.ok {
				require.NoError(t, err, "max_queued_events %d", tc.v)
				s.watcherMu.RLock()
				require.Len(t, s.watcherMap[watchEventTypePeerState], 1)
				assert.Equal(t, tc.want, s.watcherMap[watchEventTypePeerState][0].opts.queueLimit)
				s.watcherMu.RUnlock()
			} else {
				require.Equal(t, codes.InvalidArgument, status.Code(err), "max_queued_events %d: %v", tc.v, err)
			}
			cancel()
			require.Eventually(t, func() bool { return !s.isWatched(watchEventTypePeerState) }, 10*time.Second, time.Millisecond)
		}
	})
}

// TestWatchQueueLimitFailsABlockedClient checks that a watcher whose client
// is blocked in its callback still fails at its queue limit: the failure is
// reported while the callback has not returned. The queue is filled only
// once the callback is known to be entered, so that it is what holds the
// goroutine that would otherwise take the events.
func TestWatchQueueLimitFailsABlockedClient(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	entered, block := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { close(block) })
	failed := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, s.WatchEvent(ctx, WatchEventMessageCallbacks{
		OnBestPath: func([]*apiutil.Path, time.Time) {
			once.Do(func() { close(entered) })
			<-block
		},
		OnError: func(err error) { failed <- err },
	}, WatchBestPath(false), WatchQueueLimit(20)))

	// One event, and the callback it reaches is entered and blocked.
	addPrefixes(t, s, 0, 1, 1)
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the callback was not entered")
	}
	// The queue fills behind it, past its limit.
	addPrefixes(t, s, 1, 500, 1)
	select {
	case err := <-failed:
		require.ErrorIs(t, err, ErrWatchQueueFull)
	case <-time.After(10 * time.Second):
		t.Fatal("OnError was not called while the client was blocked")
	}
}

// gatedSend holds the Send of every message of the WatchEvent streams of a
// server until its gate is opened, and tells when the first one is entered:
// the proof that the goroutine that sends is blocked in Send, with nothing
// left to chance.
type gatedSend struct {
	entered chan struct{}
	gate    chan struct{}
	once    sync.Once
	sent    atomic.Int64
}

func newGatedSend() *gatedSend {
	return &gatedSend{entered: make(chan struct{}), gate: make(chan struct{})}
}

func (g *gatedSend) open() {
	select {
	case <-g.gate:
	default:
		close(g.gate)
	}
}

type gatedStream struct {
	grpc.ServerStream
	g *gatedSend
}

func (s *gatedStream) SendMsg(m any) error {
	s.g.once.Do(func() { close(s.g.entered) })
	<-s.g.gate
	err := s.ServerStream.SendMsg(m)
	s.g.sent.Add(1)
	return err
}

func (g *gatedSend) intercept(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if !strings.HasSuffix(info.FullMethod, "/WatchEvent") {
		return handler(srv, ss)
	}
	return handler(srv, &gatedStream{ServerStream: ss, g: g})
}

// startGrpcServer starts a server with gRPC on a unix socket and returns it
// with a client of it. The server and the connection are closed with the
// test.
func startGrpcServer(t *testing.T, serverOpts []ServerOption, dialOpts ...grpc.DialOption) (*BgpServer, api.GoBgpServiceClient) {
	t.Helper()
	dir, err := os.MkdirTemp("", "gobgp-grpc-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	addr := "unix://" + dir + "/gobgp.sock"

	s := NewBgpServer(append([]ServerOption{GrpcListenAddress(addr)}, serverOpts...)...)
	go s.Serve()
	t.Cleanup(s.Stop)
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 1, RouterId: "1.1.1.1", ListenPort: -1},
	}))
	conn, err := grpc.NewClient(addr, append([]grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}, dialOpts...)...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return s, api.NewGoBgpServiceClient(conn)
}

// openWatch opens a WatchEvent stream, retrying until the server listens.
func openWatch(t *testing.T, ctx context.Context, client api.GoBgpServiceClient, r *api.WatchEventRequest) api.GoBgpService_WatchEventClient {
	t.Helper()
	var stream api.GoBgpService_WatchEventClient
	require.Eventually(t, func() bool {
		var err error
		stream, err = client.WatchEvent(ctx, r)
		return err == nil
	}, 10*time.Second, 50*time.Millisecond)
	return stream
}

// receiveUntilEnd reads the stream until it ends and returns the code it
// ended with.
func receiveUntilEnd(stream api.GoBgpService_WatchEventClient) codes.Code {
	for {
		if _, err := stream.Recv(); err != nil {
			return status.Code(err)
		}
	}
}

// TestWatchEventQueueLimitEndsABlockedStream checks that a gRPC watch whose
// goroutine is blocked in Send still ends at max_queued_events: the
// watcher is unregistered while the Send is still blocked, before the client
// reads, and the client then gets RESOURCE_EXHAUSTED. The Send is held by a
// gate and known to be entered before the queue is filled.
func TestWatchEventQueueLimitEndsABlockedStream(t *testing.T) {
	g := newGatedSend()
	t.Cleanup(g.open)
	s, client := startGrpcServer(t, []ServerOption{GrpcOption([]grpc.ServerOption{grpc.StreamInterceptor(g.intercept)})})

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	stream := openWatch(t, ctx, client, &api.WatchEventRequest{
		Table: &api.WatchEventRequest_Table{Filters: []*api.WatchEventRequest_Table_Filter{
			{Type: api.WatchEventRequest_Table_Filter_TYPE_BEST},
		}},
		MaxQueuedEvents: 50,
	})
	require.Eventually(t, func() bool { return s.isWatched(watchEventTypeBestPath) }, 10*time.Second, 10*time.Millisecond)

	// One event, whose Send is entered and held; then a burst that overflows
	// the queue behind it.
	addPrefixes(t, s, 0, 1, 1)
	select {
	case <-g.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the Send was not entered")
	}
	addPrefixes(t, s, 1, 2000, 1)
	require.Eventually(t, func() bool { return !s.isWatched(watchEventTypeBestPath) }, 20*time.Second, 10*time.Millisecond,
		"the failed watcher is still registered while its client is blocked")
	assert.Equal(t, int64(0), g.sent.Load(), "the Send was not blocked when the watcher failed")

	// The client reads now, and the watch ends with the status.
	g.open()
	require.Equal(t, codes.ResourceExhausted, receiveUntilEnd(stream))
}

// TestWatchEventQueueLimitEndsAStalledStream checks the same over real flow
// control: a client that reads nothing at all, with a small fixed window,
// still has its watch ended at max_queued_events, with RESOURCE_EXHAUSTED,
// and its watcher is gone before it reads. Unlike the test above, nothing
// holds the Send but the client: the events are large enough that the window
// fills and the Send blocks.
func TestWatchEventQueueLimitEndsAStalledStream(t *testing.T) {
	// A fixed 64 KiB window: the server's Send blocks once about 30 events
	// (2 KiB each) are unread.
	s, client := startGrpcServer(t, nil, grpc.WithInitialWindowSize(1<<16), grpc.WithInitialConnWindowSize(1<<16))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	stream := openWatch(t, ctx, client, &api.WatchEventRequest{
		Table: &api.WatchEventRequest_Table{Filters: []*api.WatchEventRequest_Table_Filter{
			{Type: api.WatchEventRequest_Table_Filter_TYPE_BEST},
		}},
		MaxQueuedEvents: 50,
	})
	require.Eventually(t, func() bool { return s.isWatched(watchEventTypeBestPath) }, 10*time.Second, 10*time.Millisecond)

	// The events are far more than the window and the queue hold.
	addPrefixes(t, s, 0, 4000, 500)
	require.Eventually(t, func() bool { return !s.isWatched(watchEventTypeBestPath) }, 20*time.Second, 10*time.Millisecond,
		"the failed watcher is still registered while its client is stalled")
	require.Equal(t, codes.ResourceExhausted, receiveUntilEnd(stream))
}

// TestWatchCancelReleasesWhileACallbackIsBlocked checks that cancelling the
// context of a watch whose callback is blocked deregisters the watcher at
// once, without waiting for the callback, and that the callback goroutine ends
// without admitting another callback once the callback returns.
func TestWatchCancelReleasesWhileACallbackIsBlocked(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	entered, block, exited := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	var calls atomic.Int32
	var errs atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, s.WatchEvent(ctx, WatchEventMessageCallbacks{
		OnBestPath: func([]*apiutil.Path, time.Time) {
			calls.Add(1)
			once.Do(func() { close(entered) })
			<-block
		},
		OnError: func(error) { errs.Add(1) },
	}, WatchBestPath(false), func(o *watchOptions) {
		o.callbacksDoneHook = func() { close(exited) }
	}))
	w := findBestWatcher(t, s)

	addPrefixes(t, s, 0, 1, 1)
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the callback was not entered")
	}
	// Events queue behind the blocked callback.
	addPrefixes(t, s, 1, 10, 1)

	cancel()
	// The watcher is deregistered while the callback is blocked, with
	// its queue: the barrier is still closed.
	require.Eventually(t, func() bool { return !s.isWatched(watchEventTypeBestPath) }, 10*time.Second, time.Millisecond,
		"the cancelled watcher is still registered while its callback is blocked")
	<-w.Done()
	select {
	case <-exited:
		t.Fatal("the callback goroutine ended while its callback was blocked")
	default:
	}

	// The callback returns; the goroutine ends and delivers nothing more.
	close(block)
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("the callback goroutine did not end")
	}
	assert.Equal(t, int32(1), calls.Load(), "a callback was admitted after the watch was cancelled")
	assert.Equal(t, int32(0), errs.Load(), "a cancellation was reported as a failure")
}
