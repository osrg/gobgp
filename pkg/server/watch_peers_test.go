package server

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// The tests of this file run a server (the watched one) with two real
// producers: servers that peer with it over TCP and announce the same
// prefixes. The second producer is at 127.0.0.2, which every Linux host
// routes to the loopback interface.

const (
	producer1Address = "127.0.0.1"
	producer2Address = "127.0.0.2"
)

func requireLoopbackAlias(t *testing.T) {
	t.Helper()
	l, err := net.Listen("tcp", producer2Address+":0")
	if err != nil {
		t.Skipf("%s is not a local address: %v", producer2Address, err)
	}
	_ = l.Close()
}

// producers starts a watched server and two producers peered with it, and
// waits for both sessions.
type producers struct {
	watched    *BgpServer
	p1, p2     *BgpServer
	producerAS map[string]uint32
}

func startProducers(t *testing.T, ports [2]int32) *producers {
	t.Helper()
	requireLoopbackAlias(t)
	pr := &producers{
		watched:    runNewServer(t, 1, "1.1.1.1", -1),
		p1:         runNewServer(t, 2, "2.2.2.2", ports[0]),
		p2:         runNewServer(t, 3, "3.3.3.3", ports[1]),
		producerAS: map[string]uint32{producer1Address: 2, producer2Address: 3},
	}
	t.Cleanup(func() {
		for _, s := range []*BgpServer{pr.watched, pr.p1, pr.p2} {
			_ = s.StopBgp(context.Background(), &api.StopBgpRequest{})
		}
	})
	ctx := context.Background()
	for _, p := range []*BgpServer{pr.p1, pr.p2} {
		require.NoError(t, p.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
			Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 1},
			Transport: &api.Transport{PassiveMode: true},
		}}))
	}
	for i, addr := range []string{producer1Address, producer2Address} {
		require.NoError(t, pr.watched.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
			Conf:      &api.PeerConf{NeighborAddress: addr, PeerAsn: pr.producerAS[addr]},
			Transport: &api.Transport{RemotePort: uint32(ports[i])},
			Timers:    &api.Timers{Config: &api.TimersConfig{ConnectRetry: 1, IdleHoldTimeAfterReset: 1}},
		}}))
	}
	require.Eventually(t, func() bool {
		n := 0
		_ = pr.watched.ListPeer(ctx, &api.ListPeerRequest{}, func(p *api.Peer) {
			if p.State.SessionState == api.PeerState_SESSION_STATE_ESTABLISHED {
				n++
			}
		})
		return n == 2
	}, 30*time.Second, 50*time.Millisecond, "the sessions did not establish")
	return pr
}

// producerPath is a path of a producer: tagged with the watch policy's
// community or not, with padding extra AS numbers in its AS path so that a
// path with less padding wins the best path selection of the watched server.
func producerPath(t testing.TB, prefix string, tagged bool, padding int) *apiutil.Path {
	t.Helper()
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh}
	if padding > 0 {
		asns := make([]uint32, padding)
		for i := range asns {
			asns[i] = 64512 + uint32(i)
		}
		attrs = append(attrs, bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, asns)}))
	}
	if tagged {
		attrs = append(attrs, bgp.NewPathAttributeCommunities([]uint32{watchPolicyCommunity}))
	}
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	require.NoError(t, err)
	p, err := apiutil.NewPath(bgp.RF_IPv4_UC, nlri, false, attrs, time.Now())
	require.NoError(t, err)
	return mustApi2apiutilPath(p)
}

// reconstruction rebuilds, as a consumer does, the table of a best path
// watch from its events: an announcement sets the destination, a withdrawal
// removes it. It remembers the events too.
type reconstruction struct {
	mu     sync.Mutex
	state  map[string]string // prefix -> address of the peer the path came from
	events []string
}

func newReconstruction() *reconstruction {
	return &reconstruction{state: map[string]string{}}
}

func (r *reconstruction) onBestPath(paths []*apiutil.Path, _ time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range paths {
		key := p.Nlri.String()
		if p.Withdrawal {
			delete(r.state, key)
			r.events = append(r.events, "withdraw "+key+" "+p.PeerAddress.String())
			continue
		}
		r.state[key] = p.PeerAddress.String()
		r.events = append(r.events, "announce "+key+" "+p.PeerAddress.String())
	}
}

func (r *reconstruction) snapshot() (map[string]string, []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := make(map[string]string, len(r.state))
	for k, v := range r.state {
		state[k] = v
	}
	return state, append([]string(nil), r.events...)
}

// expectedFromRib is the table a consumer of the policy ought to hold: the
// best paths of the RIB the policy accepts, evaluated by the policy itself.
// The policy and the RIB do not change while the test compares.
func expectedFromRib(t *testing.T, s *BgpServer, policy string) map[string]string {
	t.Helper()
	p, ok := s.policy.AcquireWatchPolicy(policy)
	require.True(t, ok)
	defer s.policy.ReleaseWatchPolicy(p)
	out := map[string]string{}
	require.NoError(t, s.mgmtOperation(func() error {
		for _, path := range s.globalRib.GetBestPathList(table.GLOBAL_RIB_NAME, 0, nil) {
			if match, _ := s.policy.MatchWatchPolicy(p, path, &table.PolicyOptions{Validate: s.roaTable.Validate}); match {
				out[path.GetNlri().String()] = path.GetSource().Address.String()
			}
		}
		return nil
	}, true))
	return out
}

// bestSource is the address of the peer the best path of the prefix of the
// watched server came from, empty when it has none.
func bestSource(t *testing.T, s *BgpServer, prefix string) string {
	t.Helper()
	var src string
	require.NoError(t, s.mgmtOperation(func() error {
		for _, path := range s.globalRib.GetBestPathList(table.GLOBAL_RIB_NAME, 0, nil) {
			if path.GetNlri().String() == prefix {
				src = path.GetSource().Address.String()
			}
		}
		return nil
	}, true))
	return src
}

// TestWatchPolicyTwoProducersChangesStayOrdered checks the order of the
// changes of one prefix announced by two real producers. The notification of
// the first producer's path is held under the destination's propagation lock
// while the second producer, whose path wins the selection and is rejected
// by the policy, announces the prefix: its update reaches the server and
// must wait for the first one. The watcher then gets the announcement and
// the withdrawal in that order, and the withdrawal of the winning path, which
// the watcher was never sent, adds nothing.
func TestWatchPolicyTwoProducersChangesStayOrdered(t *testing.T) {
	pr := startProducers(t, [2]int32{11179, 21179})
	addWatchPolicy(t, pr.watched, "tagged")

	// A probe of the updates the server receives, before any policy.
	arrived := make(chan netip.Addr, 16)
	probeCtx, probeCancel := context.WithCancel(context.Background())
	defer probeCancel()
	require.NoError(t, pr.watched.WatchEvent(probeCtx, WatchEventMessageCallbacks{
		OnPathUpdate: func(paths []*apiutil.Path, _ time.Time) {
			for _, p := range paths {
				if !p.Withdrawal {
					arrived <- p.PeerAddress
				}
			}
		},
	}, WatchUpdate(false, "", "")))

	entered, release := make(chan struct{}), make(chan struct{})
	var held, released sync.Once
	releaseHeld := func() { released.Do(func() { close(release) }) }
	t.Cleanup(releaseHeld)
	r := newReconstruction()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, pr.watched.WatchEvent(ctx, WatchEventMessageCallbacks{OnBestPath: r.onBestPath},
		WatchBestPath(true), WatchBestPathPolicy("tagged"), func(o *watchOptions) {
			o.notifyBestHook = func() {
				held.Do(func() {
					close(entered)
					<-release
				})
			}
		}))

	const prefix = "10.9.0.0/24"
	// The first producer's path, tagged and with a long AS path: its
	// notification is held.
	_, err := pr.p1.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{producerPath(t, prefix, true, 3)}})
	require.NoError(t, err)
	select {
	case <-entered:
	case <-time.After(30 * time.Second):
		t.Fatal("the first change did not reach the watcher")
	}
	// The second producer's path, untagged and shorter: it arrives while
	// the first notification is held.
	_, err = pr.p2.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{producerPath(t, prefix, false, 0)}})
	require.NoError(t, err)
	// The probe saw the first producer's update earlier, which it skips.
	for seen := false; !seen; {
		select {
		case from := <-arrived:
			seen = from.String() == producer2Address
		case <-time.After(30 * time.Second):
			t.Fatal("the second producer's update did not reach the server")
		}
	}
	releaseHeld()

	require.Eventually(t, func() bool {
		_, events := r.snapshot()
		return len(events) >= 2
	}, 30*time.Second, 10*time.Millisecond)
	// The best path is now the rejected one: the watcher holds nothing.
	require.Equal(t, producer2Address, bestSource(t, pr.watched, prefix))
	state, events := r.snapshot()
	assert.Equal(t, []string{
		"announce " + prefix + " " + producer1Address,
		"withdraw " + prefix + " " + producer1Address,
	}, events)
	assert.Empty(t, state)

	// The second producer withdraws: the first path is the best again, and
	// the watcher is told.
	require.NoError(t, pr.p2.DeletePath(apiutil.DeletePathRequest{Paths: []*apiutil.Path{producerPath(t, prefix, false, 0)}}))
	require.Eventually(t, func() bool {
		state, _ := r.snapshot()
		return state[prefix] == producer1Address
	}, 30*time.Second, 10*time.Millisecond)
	assert.Equal(t, expectedFromRib(t, pr.watched, "tagged"), func() map[string]string { s, _ := r.snapshot(); return s }())
}

// TestWatchPolicyTwoProducersDuringTheInitialTable checks the initial table
// of a policy watcher while two real producers change the same prefixes: the
// table is held between its chunks, the producers announce and withdraw
// what it holds, and what the consumer rebuilds from the table and the
// events that follow it is the RIB the policy accepts.
func TestWatchPolicyTwoProducersDuringTheInitialTable(t *testing.T) {
	pr := startProducers(t, [2]int32{11279, 21279})
	addWatchPolicy(t, pr.watched, "tagged")
	const n = 20
	prefix := func(i int) string { return fmt.Sprintf("10.40.%d.0/24", i) }

	// The first producer announces them tagged, the second the odd ones
	// untagged and shorter.
	var first []*apiutil.Path
	for i := range n {
		first = append(first, producerPath(t, prefix(i), true, 3))
	}
	_, err := pr.p1.AddPath(apiutil.AddPathRequest{Paths: first})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return len(expectedFromRib(t, pr.watched, "tagged")) == n
	}, 30*time.Second, 20*time.Millisecond)

	entered, release := make(chan struct{}), make(chan struct{})
	var held, released sync.Once
	releaseHeld := func() { released.Do(func() { close(release) }) }
	t.Cleanup(releaseHeld)
	r := newReconstruction()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, pr.watched.WatchEvent(ctx, WatchEventMessageCallbacks{OnBestPath: r.onBestPath},
		WatchBestPath(true), WatchBestPathPolicy("tagged"), func(o *watchOptions) {
			o.initChunkHook = func() {
				held.Do(func() {
					close(entered)
					<-release
				})
			}
		}))
	select {
	case <-entered:
	case <-time.After(30 * time.Second):
		t.Fatal("the initial table was not taken")
	}

	// While the table is held: the second producer takes the odd prefixes
	// over with a rejected path, and the first withdraws the multiples of
	// four.
	var second, withdrawn []*apiutil.Path
	for i := 1; i < n; i += 2 {
		second = append(second, producerPath(t, prefix(i), false, 0))
	}
	for i := 0; i < n; i += 4 {
		withdrawn = append(withdrawn, producerPath(t, prefix(i), true, 3))
	}
	_, err = pr.p2.AddPath(apiutil.AddPathRequest{Paths: second})
	require.NoError(t, err)
	require.NoError(t, pr.p1.DeletePath(apiutil.DeletePathRequest{Paths: withdrawn}))
	require.Eventually(t, func() bool {
		return bestSource(t, pr.watched, prefix(1)) == producer2Address && bestSource(t, pr.watched, prefix(4)) == ""
	}, 30*time.Second, 20*time.Millisecond)
	releaseHeld()

	require.Eventually(t, func() bool {
		state, _ := r.snapshot()
		return assert.ObjectsAreEqual(expectedFromRib(t, pr.watched, "tagged"), state)
	}, 30*time.Second, 20*time.Millisecond, "the consumer's table is not the RIB the policy accepts")
}

// TestWatchPolicyTwoProducersReconstruct checks, with two real producers
// changing the same prefixes at once (announcements tagged and untagged,
// with more and less padding, and withdrawals), that the table a consumer
// rebuilds from the events of a policy watcher, under a policy that does not
// change, is the RIB the policy accepts once the changes have been
// propagated.
func TestWatchPolicyTwoProducersReconstruct(t *testing.T) {
	pr := startProducers(t, [2]int32{11379, 21379})
	addWatchPolicy(t, pr.watched, "tagged")
	const prefixes = 12
	prefix := func(i int) string { return fmt.Sprintf("10.50.%d.0/24", i) }

	r := newReconstruction()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, pr.watched.WatchEvent(ctx, WatchEventMessageCallbacks{OnBestPath: r.onBestPath},
		WatchBestPath(true), WatchBestPathPolicy("tagged")))

	// Each producer's changes, made up front: an announcement of a prefix,
	// tagged or not and with some padding, or the withdrawal of what it
	// announced.
	type step struct {
		path     *apiutil.Path
		withdraw bool
	}
	plans := make([][]step, 2)
	for seed := range plans {
		rng := rand.New(rand.NewSource(int64(seed + 1)))
		announced := map[int]*apiutil.Path{}
		for range 150 {
			i := rng.Intn(prefixes)
			if old, ok := announced[i]; ok && rng.Intn(3) == 0 {
				plans[seed] = append(plans[seed], step{path: old, withdraw: true})
				delete(announced, i)
				continue
			}
			path := producerPath(t, prefix(i), rng.Intn(2) == 0, rng.Intn(3))
			plans[seed] = append(plans[seed], step{path: path})
			announced[i] = path
		}
	}
	var wg sync.WaitGroup
	for i, p := range []*BgpServer{pr.p1, pr.p2} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, st := range plans[i] {
				var err error
				if st.withdraw {
					err = p.DeletePath(apiutil.DeletePathRequest{Paths: []*apiutil.Path{st.path}})
				} else {
					_, err = p.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{st.path}})
				}
				if err != nil {
					t.Errorf("producer %d: %v", i+1, err)
					return
				}
			}
		}()
	}
	wg.Wait()

	var last map[string]string
	ok := assert.Eventually(t, func() bool {
		want := expectedFromRib(t, pr.watched, "tagged")
		got, _ := r.snapshot()
		last = want
		return assert.ObjectsAreEqual(want, got)
	}, 60*time.Second, 50*time.Millisecond, "the consumer's table is not the RIB the policy accepts")
	if !ok {
		got, events := r.snapshot()
		keys := func(m map[string]string) []string {
			var out []string
			for k, v := range m {
				out = append(out, k+" via "+v)
			}
			sort.Strings(out)
			return out
		}
		t.Logf("RIB and policy: %v\nconsumer:       %v\n%d events", keys(last), keys(got), len(events))
	}
}
