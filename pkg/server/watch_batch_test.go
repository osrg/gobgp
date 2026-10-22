package server

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

type batchCall struct {
	n    int
	last bool
}

// TestWatchEventBestPathBatches checks that OnBestPathBatch gets the initial
// table in batches, the final one marked, and an empty table as one empty
// final call. A table that is an exact multiple of the batch size ends with a
// full batch marked final, not with an empty call, and a size that is not
// set, or is not positive, is DefaultBestPathBatchSize.
func TestWatchEventBestPathBatches(t *testing.T) {
	for _, tc := range []struct {
		size  int
		paths int
		want  []batchCall
	}{
		{3, 0, []batchCall{{0, true}}},
		{3, 1, []batchCall{{1, true}}},
		{3, 2, []batchCall{{2, true}}},
		{3, 3, []batchCall{{3, true}}},
		{3, 6, []batchCall{{3, false}, {3, true}}},
		{3, 9, []batchCall{{3, false}, {3, false}, {3, true}}},
		{3, 10, []batchCall{{3, false}, {3, false}, {3, false}, {1, true}}},
		{0, DefaultBestPathBatchSize, []batchCall{{DefaultBestPathBatchSize, true}}},
		{0, DefaultBestPathBatchSize + 1, []batchCall{{DefaultBestPathBatchSize, false}, {1, true}}},
		{-5, DefaultBestPathBatchSize + 1, []batchCall{{DefaultBestPathBatchSize, false}, {1, true}}},
	} {
		t.Run(fmt.Sprintf("size %d, %d paths", tc.size, tc.paths), func(t *testing.T) {
			s := runNewServer(t, 1, "1.1.1.1", -1)
			defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
			if tc.paths > 0 {
				addPrefixes(t, s, 0, tc.paths, 1)
			}
			var mu sync.Mutex
			var calls []batchCall
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			require.NoError(t, s.WatchEvent(ctx, WatchEventMessageCallbacks{
				BestPathBatchSize: tc.size,
				OnBestPathBatch: func(paths []*apiutil.Path, _ time.Time, last bool) {
					mu.Lock()
					defer mu.Unlock()
					calls = append(calls, batchCall{len(paths), last})
				},
			}, WatchBestPath(true)))
			assert.Eventually(t, func() bool {
				mu.Lock()
				defer mu.Unlock()
				return len(calls) > 0 && calls[len(calls)-1].last
			}, 10*time.Second, 10*time.Millisecond)
			mu.Lock()
			assert.Equal(t, tc.want, calls)
			mu.Unlock()
		})
	}
}

// TestWatchEventBestPathBatchOrderAndPrecedence checks that the paths of one
// event reach OnBestPathBatch in the order of the event, across batches, and
// that OnBestPathBatch takes precedence over OnBestPath, which is not
// called when both are set.
func TestWatchEventBestPathBatchOrderAndPrecedence(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	var mu sync.Mutex
	var order []string
	var calls []batchCall
	var whole atomic.Int32
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, s.WatchEvent(ctx, WatchEventMessageCallbacks{
		BestPathBatchSize: 2,
		OnBestPath:        func([]*apiutil.Path, time.Time) { whole.Add(1) },
		OnBestPathBatch: func(paths []*apiutil.Path, _ time.Time, last bool) {
			mu.Lock()
			defer mu.Unlock()
			for _, p := range paths {
				order = append(order, p.Nlri.String())
			}
			calls = append(calls, batchCall{len(paths), last})
			if last {
				close(done)
			}
		},
	}, WatchBestPath(false)))

	// One event of five destinations, in a known order.
	var best []*table.Path
	var want []string
	for i := range 5 {
		prefix := fmt.Sprintf("10.80.%d.0/24", 4-i)
		nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
		require.NoError(t, err)
		best = append(best, consumerTablePath(t, nlri, "192.0.2.1", false))
		want = append(want, prefix)
	}
	notifyBestLists(s, best, nil, nil, nil)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("no event")
	}
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, want, order, "the paths of the event were reordered")
	assert.Equal(t, []batchCall{{2, false}, {2, false}, {1, true}}, calls)
	assert.Equal(t, int32(0), whole.Load(), "OnBestPath was called next to OnBestPathBatch")
}

// TestWatchEventBestPathBatchesStopOnCancel checks that a cancelled watch
// stops converting the initial table between batches.
func TestWatchEventBestPathBatchesStopOnCancel(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	addPrefixes(t, s, 0, 100, 1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	exited := make(chan struct{})
	require.NoError(t, s.WatchEvent(ctx, WatchEventMessageCallbacks{
		BestPathBatchSize: 10,
		OnBestPathBatch: func([]*apiutil.Path, time.Time, bool) {
			calls.Add(1)
			cancel()
		},
	}, WatchBestPath(true), func(o *watchOptions) {
		o.callbacksDoneHook = func() { close(exited) }
	}))
	// The goroutine ends once the cancellation reaches it: no call follows.
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("the callback goroutine did not end")
	}
	assert.Equal(t, int32(1), calls.Load(), "the conversion went on after the watch was cancelled")
}

// TestGRPCWatchEventBatchesTimestampAndNoEmptyEvents checks, over gRPC, that
// the messages of the initial table are cut by batch_size exactly as before
// (batch_size + 1 paths each, the rest in the last), that every table message
// carries its event's time, and that a change that alters no best path sends
// nothing.
func TestGRPCWatchEventBatchesTimestampAndNoEmptyEvents(t *testing.T) {
	dir, err := os.MkdirTemp("", "gobgp-grpc-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	addr := "unix://" + dir + "/gobgp.sock"

	s := NewBgpServer(GrpcListenAddress(addr))
	go s.Serve()
	defer s.Stop()
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 1, RouterId: "1.1.1.1", ListenPort: -1},
	}))
	const n, b = 2003, 7 // 250 x (b+1) + 3
	addPrefixes(t, s, 0, n, 1)

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()
	client := api.NewGoBgpServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	before := time.Now()
	var stream api.GoBgpService_WatchEventClient
	require.Eventually(t, func() bool {
		stream, err = client.WatchEvent(ctx, &api.WatchEventRequest{
			Table: &api.WatchEventRequest_Table{Filters: []*api.WatchEventRequest_Table_Filter{
				{Type: api.WatchEventRequest_Table_Filter_TYPE_BEST, Init: true},
			}},
			BatchSize: b,
		})
		return err == nil
	}, 10*time.Second, 50*time.Millisecond)

	var lens []int
	var stamp time.Time
	for total := 0; ; {
		m, err := stream.Recv()
		require.NoError(t, err)
		ev := m.GetTable()
		require.NotNil(t, ev.GetTimestamp(), "a table message without its event's time")
		ts := ev.GetTimestamp().AsTime()
		if stamp.IsZero() {
			stamp = ts
		}
		assert.Equal(t, stamp, ts, "the messages of one event carry different times")
		lens = append(lens, len(ev.GetPaths()))
		total += len(ev.GetPaths())
		if len(ev.GetPaths()) <= b {
			require.Equal(t, n, total)
			break
		}
		require.Equal(t, b+1, len(ev.GetPaths()), "message %d", len(lens))
	}
	assert.Equal(t, n/(b+1)+1, len(lens))
	assert.True(t, !stamp.Before(before.Add(-time.Second)), "event time %s before the watch began %s", stamp, before)

	// Adding an identical path changes no best path: nothing is sent. The
	// next message is the new destination.
	addPrefixes(t, s, 0, 1, 1)
	addPrefixes(t, s, n, 1, 1)
	m, err := stream.Recv()
	require.NoError(t, err)
	require.Len(t, m.GetTable().GetPaths(), 1)
	got := m.GetTable().GetPaths()[0].GetNlri().GetPrefix()
	assert.Equal(t, uint32(24), got.GetPrefixLen())
	assert.Equal(t, "10.7.211.0", got.GetPrefix(), "an empty event or the unchanged path was sent first")
}

// TestGRPCWatchEventBatchExactLimits checks the messages of the initial
// table over gRPC at the limits of batch_size. A message is sent when it
// holds more than batch_size paths, so the messages carry batch_size + 1
// paths and the last one the rest: a table that is an exact multiple of
// batch_size + 1 ends with an empty message, which is part of the framing, a
// table of up to batch_size paths is one message, an empty table is one empty
// message, and with batch_size 0 the table is one message.
func TestGRPCWatchEventBatchExactLimits(t *testing.T) {
	s, client := startGrpcServer(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// messages is what the stream carries for the initial table: the lengths
	// up to and including the first message that holds no more than
	// batch_size paths, which ends the event (with batch_size 0 the first).
	messages := func(batchSize uint32) []int {
		sctx, scancel := context.WithCancel(ctx)
		defer scancel()
		stream := openWatch(t, sctx, client, &api.WatchEventRequest{
			Table: &api.WatchEventRequest_Table{Filters: []*api.WatchEventRequest_Table_Filter{
				{Type: api.WatchEventRequest_Table_Filter_TYPE_BEST, Init: true},
			}},
			BatchSize: batchSize,
		})
		var lens []int
		for {
			m, err := stream.Recv()
			require.NoError(t, err)
			n := len(m.GetTable().GetPaths())
			lens = append(lens, n)
			if batchSize == 0 || n <= int(batchSize) {
				return lens
			}
		}
	}
	expected := func(total int, batchSize int) []int {
		if batchSize == 0 {
			return []int{total}
		}
		var lens []int
		for ; total > batchSize; total -= batchSize + 1 {
			lens = append(lens, batchSize+1)
		}
		return append(lens, total)
	}

	added := 0
	for _, total := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9} {
		if total > added {
			addPrefixes(t, s, added, total-added, 1)
			added = total
		}
		for _, batchSize := range []int{0, 1, 3} {
			assert.Equal(t, expected(total, batchSize), messages(uint32(batchSize)), "%d paths, batch_size %d", total, batchSize)
		}
	}
	// The cases that matter, spelled out.
	assert.Equal(t, []int{2, 2, 2, 2, 1}, expected(9, 1))
	assert.Equal(t, []int{4, 4, 1}, expected(9, 3))
	assert.Equal(t, []int{4, 4, 0}, expected(8, 3), "an exact multiple ends with an empty message")
	assert.Equal(t, []int{0}, expected(0, 3))
}
