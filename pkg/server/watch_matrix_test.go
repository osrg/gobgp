package server

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func deleteTaggedPolicy(s *BgpServer) error {
	return s.DeletePolicy(context.Background(), &api.DeletePolicyRequest{Policy: &api.Policy{Name: "tagged"}, All: true})
}

// TestWatchPolicyTwoWatchersOnePolicy checks that a policy used by two
// watchers stays protected from deletion until the last of them stops, however
// each one ends.
func TestWatchPolicyTwoWatchersOnePolicy(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	addWatchPolicy(t, s, "tagged")

	first, err := s.watch(WatchBestPath(false), WatchBestPathPolicy("tagged"))
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, s.WatchEvent(ctx, WatchEventMessageCallbacks{OnBestPath: func([]*apiutil.Path, time.Time) {}},
		WatchBestPath(false), WatchBestPathPolicy("tagged")))
	require.Error(t, deleteTaggedPolicy(s))

	first.Stop()
	require.Error(t, deleteTaggedPolicy(s), "stopping one watcher unprotected the policy for the other")
	// A failure of the stopped watcher, which stops it again, releases
	// nothing more.
	first.fail(errors.New("late"))
	first.Stop()
	require.Error(t, deleteTaggedPolicy(s), "a second stop released the other watcher's reference")

	cancel()
	require.Eventually(t, func() bool { return deleteTaggedPolicy(s) == nil }, 10*time.Second, 10*time.Millisecond,
		"the cancelled watcher still holds the policy")
}

// TestWatchPolicyReloadWithOldAndNewWatchers checks a reload that defines the
// policy again under the same name while a watcher uses it: the old watcher
// fails, a new watcher takes the new policy, and the old one's release, which
// may come after, does not disturb the new one.
func TestWatchPolicyReloadWithOldAndNewWatchers(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	addWatchPolicy(t, s, "tagged")

	failed := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, s.WatchEvent(ctx, WatchEventMessageCallbacks{
		OnBestPath: func([]*apiutil.Path, time.Time) {},
		OnError:    func(err error) { failed <- err },
	}, WatchBestPath(false), WatchBestPathPolicy("tagged")))
	old := findBestWatcher(t, s)

	// The reload defines the policy again under its name.
	require.NoError(t, s.SetPolicies(context.Background(), &api.SetPoliciesRequest{
		DefinedSets: []*api.DefinedSet{{
			DefinedType: api.DefinedType_DEFINED_TYPE_COMMUNITY, Name: "tagged-communities", List: []string{"65000:100"},
		}},
		Policies: []*api.Policy{{
			Name: "tagged",
			Statements: []*api.Statement{{
				Name:       "tagged-tagged",
				Conditions: &api.Conditions{CommunitySet: &api.MatchSet{Type: api.MatchSet_TYPE_ANY, Name: "tagged-communities"}},
				Actions:    &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_ACCEPT},
			}},
		}},
	}))
	// A new watcher takes the new policy, whether or not the old one has
	// been stopped yet.
	fresh, err := s.watch(WatchBestPath(false), WatchBestPathPolicy("tagged"))
	require.NoError(t, err)
	defer fresh.Stop()
	require.NotSame(t, old.policy, fresh.policy)

	select {
	case err := <-failed:
		require.ErrorIs(t, err, ErrWatchPolicyRemoved)
	case <-time.After(10 * time.Second):
		t.Fatal("the old watcher did not fail")
	}
	// The old watcher is stopped and has released its reference.
	require.Eventually(t, func() bool {
		s.watcherMu.RLock()
		defer s.watcherMu.RUnlock()
		return len(s.watcherMap[watchEventTypeBestPath]) == 1
	}, 10*time.Second, time.Millisecond)

	require.Error(t, deleteTaggedPolicy(s), "the new watcher's policy is not protected")
	fresh.Stop()
	require.NoError(t, deleteTaggedPolicy(s), "the new policy is still held after its only watcher stopped")
}

// TestWatchCancelReleasesThePolicyWhileACallbackIsBlocked checks that the
// cancellation of a watch whose callback is blocked releases its policy and
// what it remembered at once, without the callback returning.
func TestWatchCancelReleasesThePolicyWhileACallbackIsBlocked(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	addWatchPolicy(t, s, "tagged")
	_, err := s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{watchPolicyPath(t, "10.0.1.0/24", true)}})
	require.NoError(t, err)

	entered, block, exited := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, s.WatchEvent(ctx, WatchEventMessageCallbacks{
		OnBestPath: func([]*apiutil.Path, time.Time) {
			once.Do(func() { close(entered) })
			<-block
		},
	}, WatchBestPath(true), WatchBestPathPolicy("tagged"), func(o *watchOptions) {
		o.callbacksDoneHook = func() { close(exited) }
	}))
	t.Cleanup(func() {
		select {
		case <-block:
		default:
			close(block)
		}
	})
	<-entered
	w := findBestWatcher(t, s)

	cancel()
	require.Eventually(t, func() bool { return !s.isWatched(watchEventTypeBestPath) }, 10*time.Second, time.Millisecond,
		"the cancelled watcher is still registered while its callback is blocked")
	require.Eventually(t, func() bool { return deleteTaggedPolicy(s) == nil }, 10*time.Second, 10*time.Millisecond,
		"the cancelled watcher still holds its policy")
	require.Eventually(t, func() bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.announced == nil && w.pending == nil
	}, 10*time.Second, time.Millisecond, "the cancelled watcher still holds what it remembered")
	select {
	case <-exited:
		t.Fatal("the callback goroutine ended while its callback was blocked")
	default:
	}
	close(block)
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("the callback goroutine did not end")
	}
}

// TestWatchPolicyEvaluationContext checks the context a policy is evaluated
// in, which is the Loc-RIB's and has no export peer: a neighbor condition
// matches the peer the path was received from, a local path matches none, and
// the actions that read the peer the path is sent to change nothing, so that
// a later statement sees the path as it is.
func TestWatchPolicyEvaluationContext(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	ctx := context.Background()
	require.NoError(t, s.AddDefinedSet(ctx, &api.AddDefinedSetRequest{DefinedSet: &api.DefinedSet{
		DefinedType: api.DefinedType_DEFINED_TYPE_NEIGHBOR, Name: "from-one", List: []string{"192.0.2.1/32"},
	}}))
	require.NoError(t, s.AddDefinedSet(ctx, &api.AddDefinedSetRequest{DefinedSet: &api.DefinedSet{
		DefinedType: api.DefinedType_DEFINED_TYPE_PREFIX, Name: "steered",
		Prefixes: []*api.Prefix{{IpPrefix: "10.60.0.0/16", MaskLengthMin: 24, MaskLengthMax: 24}},
	}}))
	require.NoError(t, s.AddPolicy(ctx, &api.AddPolicyRequest{Policy: &api.Policy{
		Name: "from-neighbor",
		Statements: []*api.Statement{{
			Name:       "from-neighbor-one",
			Conditions: &api.Conditions{NeighborSet: &api.MatchSet{Type: api.MatchSet_TYPE_ANY, Name: "from-one"}},
			Actions:    &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_ACCEPT},
		}},
	}}))
	require.NoError(t, s.AddPolicy(ctx, &api.AddPolicyRequest{Policy: &api.Policy{
		Name: "not-from-neighbor",
		Statements: []*api.Statement{{
			Name:       "not-from-neighbor-one",
			Conditions: &api.Conditions{NeighborSet: &api.MatchSet{Type: api.MatchSet_TYPE_INVERT, Name: "from-one"}},
			Actions:    &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_ACCEPT},
		}},
	}}))
	// next-hop self and next-hop peer-address read the peer the path is sent
	// to, and prepend with a confederation the session: with no export
	// context they leave the path, which the next statement matches by
	// its original next hop.
	for _, action := range []*api.NexthopAction{{Self: true}, {PeerAddress: true}, {Unchanged: true}} {
		name := "steer-" + action.String()
		require.NoError(t, s.AddPolicy(ctx, &api.AddPolicyRequest{Policy: &api.Policy{
			Name: name,
			Statements: []*api.Statement{
				{
					Name:       name + "-set",
					Conditions: &api.Conditions{PrefixSet: &api.MatchSet{Type: api.MatchSet_TYPE_ANY, Name: "steered"}},
					Actions:    &api.Actions{Nexthop: action},
				},
				{
					Name:       name + "-accept",
					Conditions: &api.Conditions{NextHopInList: []string{"10.0.0.1/32"}},
					Actions:    &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_ACCEPT},
				},
			},
		}}))
	}

	nlri := func(prefix string) bgp.NLRI {
		n, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
		require.NoError(t, err)
		return n
	}

	t.Run("neighbor condition", func(t *testing.T) {
		for _, tc := range []struct {
			policy string
			source string
			want   bool
		}{
			{"from-neighbor", "192.0.2.1", true},
			{"from-neighbor", "192.0.2.2", false},
			{"not-from-neighbor", "192.0.2.1", false},
			{"not-from-neighbor", "192.0.2.2", true},
		} {
			w, err := s.watch(WatchBestPath(false), WatchBestPathPolicy(tc.policy))
			require.NoError(t, err)
			notifyBest(s, tablePath(t, bgp.RF_IPv4_UC, nlri("10.60.1.0/24"), tc.source, 0, false, false))
			// A path no policy accepts queues nothing: tell it apart by a
			// path that is accepted either way.
			if tc.want {
				assert.Equal(t, []gotPath{{"10.60.1.0/24", false, tc.source, 0}}, nextBest(t, w), "%s from %s", tc.policy, tc.source)
			} else {
				assert.Equal(t, int64(0), w.admitted.Load(), "%s from %s", tc.policy, tc.source)
			}
			w.Stop()
		}
	})

	t.Run("local path", func(t *testing.T) {
		// A path the server originates has no source address: no neighbor
		// condition matches it, an inverted one included. A notification is
		// made before AddPath returns, so what the watcher admitted is
		// settled by then.
		for _, policy := range []string{"from-neighbor", "not-from-neighbor"} {
			w, err := s.watch(WatchBestPath(true), WatchBestPathPolicy(policy))
			require.NoError(t, err)
			initial := w.admitted.Load()
			_, err = s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{watchPolicyPath(t, "10.61.0.0/24", false)}})
			require.NoError(t, err)
			require.NoError(t, s.DeletePath(apiutil.DeletePathRequest{Paths: []*apiutil.Path{watchPolicyPath(t, "10.61.0.0/24", false)}}))
			assert.Equal(t, initial, w.admitted.Load(), "a local path matched the neighbor condition of %s", policy)
			w.Stop()
		}
	})

	t.Run("actions that need the peer", func(t *testing.T) {
		for _, action := range []*api.NexthopAction{{Self: true}, {PeerAddress: true}, {Unchanged: true}} {
			w, err := s.watch(WatchBestPath(false), WatchBestPathPolicy("steer-"+action.String()))
			require.NoError(t, err)
			notifyBest(s, tablePath(t, bgp.RF_IPv4_UC, nlri("10.60.2.0/24"), "192.0.2.1", 0, false, false))
			select {
			case ev := <-w.Event():
				paths := ev.(*watchEventBestPath).PathList
				require.Len(t, paths, 1, "%s", action)
				assert.Equal(t, netip.MustParseAddr("10.0.0.1"), paths[0].GetNexthop(), "%s changed the path delivered", action)
			case <-time.After(10 * time.Second):
				t.Fatalf("%s: the path whose next hop the action could not change was not delivered", action)
			}
			w.Stop()
		}
	})
}

// TestWatchRegistrationStatus checks the status each way a watch is refused
// maps to, and the status each terminal error ends an established stream
// with.
func TestWatchRegistrationStatus(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want codes.Code
	}{
		{"invalid options", ErrWatchInvalid, codes.InvalidArgument},
		{"invalid options, wrapped", errors.Join(errors.New("context"), ErrWatchInvalid), codes.InvalidArgument},
		{"nonexistent policy", ErrWatchPolicyNotFound, codes.NotFound},
		{"incompatible configuration", ErrWatchIncompatible, codes.FailedPrecondition},
		{"anything else is a server that is stopped", errors.New("server stopped"), codes.Unavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, status.Code(watchRegistrationStatus(tc.err)))
		})
	}
	for _, tc := range []struct {
		name string
		err  error
		want codes.Code
	}{
		{"overflow", ErrWatchQueueFull, codes.ResourceExhausted},
		{"policy replaced", ErrWatchPolicyRemoved, codes.Aborted},
		{"destination", ErrWatchDestination, codes.Aborted},
		{"destination, wrapped", errors.Join(errors.New("context"), ErrWatchDestination), codes.Aborted},
	} {
		t.Run("terminal "+tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, status.Code(watchTerminalStatus(tc.err)))
		})
	}
}

// TestWatchEventStatusCodes checks, over gRPC, the status of each way a
// watch is refused or ended: InvalidArgument for options that are invalid or
// cannot be combined, NotFound for a policy that does not exist,
// FailedPrecondition for a configuration that cannot support the watch
// (multiple paths), ResourceExhausted for an overflow and Aborted when the
// policy of an active subscription is removed.
func TestWatchEventStatusCodes(t *testing.T) {
	s, client := startGrpcServer(t, nil)
	addWatchPolicy(t, s, "tagged")

	filter := func(typ api.WatchEventRequest_Table_Filter_Type, policy string) *api.WatchEventRequest_Table_Filter {
		return &api.WatchEventRequest_Table_Filter{Type: typ, Policy: policy}
	}
	const (
		best   = api.WatchEventRequest_Table_Filter_TYPE_BEST
		adjIn  = api.WatchEventRequest_Table_Filter_TYPE_ADJIN
		post   = api.WatchEventRequest_Table_Filter_TYPE_POST_POLICY
		eor    = api.WatchEventRequest_Table_Filter_TYPE_EOR
		reject = codes.InvalidArgument
	)
	table := func(filters ...*api.WatchEventRequest_Table_Filter) *api.WatchEventRequest {
		return &api.WatchEventRequest{Table: &api.WatchEventRequest_Table{Filters: filters}}
	}
	refused := []struct {
		name string
		req  *api.WatchEventRequest
		want codes.Code
	}{
		{"nothing to watch", &api.WatchEventRequest{}, reject},
		{"two best filters and a policy", table(filter(best, "tagged"), filter(best, "")), reject},
		{"a policy on the adj-in", table(filter(adjIn, "tagged")), reject},
		{"a policy on the post-policy", table(filter(post, "tagged")), reject},
		{"a policy on the end-of-rib", table(filter(eor, "tagged")), reject},
		{"a policy that does not exist", table(filter(best, "missing")), codes.NotFound},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			stream := openWatch(t, ctx, client, tc.req)
			_, err := stream.Recv()
			require.Equal(t, tc.want, status.Code(err), "%v", err)
		})
	}
	require.False(t, s.isWatched(watchEventTypeBestPath), "a refused watch stayed registered")
	require.NoError(t, deleteTaggedPolicy(s) /* nothing holds the policy */)
	addWatchPolicy(t, s, "tagged")

	t.Run("multiple paths", func(t *testing.T) {
		multi := NewBgpServer()
		go multi.Serve()
		defer multi.Stop()
		require.NoError(t, multi.StartBgp(context.Background(), &api.StartBgpRequest{
			Global: &api.Global{Asn: 1, RouterId: "1.1.1.1", ListenPort: -1, UseMultiplePaths: true},
		}))
		addWatchPolicy(t, multi, "tagged")
		err := (&server{bgpServer: multi}).watchEvent(context.Background(), table(filter(best, "tagged")),
			func(*api.WatchEventResponse, time.Time) {}, func(error) {})
		require.Equal(t, codes.FailedPrecondition, status.Code(err), "%v", err)
		require.False(t, multi.isWatched(watchEventTypeBestPath))
		// Without a policy the same configuration is fine.
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		require.NoError(t, (&server{bgpServer: multi}).watchEvent(ctx, table(filter(best, "")),
			func(*api.WatchEventResponse, time.Time) {}, func(error) {}))
	})

	t.Run("the policy of an active subscription is removed", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		stream := openWatch(t, ctx, client, table(filter(best, "tagged")))
		require.Eventually(t, func() bool { return s.isWatched(watchEventTypeBestPath) }, 10*time.Second, 10*time.Millisecond)
		require.NoError(t, s.SetPolicies(context.Background(), &api.SetPoliciesRequest{}))
		require.Equal(t, codes.Aborted, receiveUntilEnd(stream))
	})
}

// TestWatchPolicyRefusalsLeaveNothingBehind checks that every watch refused
// for its options or for the configuration of the server starts no goroutine,
// holds no policy and stays registered nowhere: multiple paths, a policy
// without the best path events, a policy that does not exist, a negative
// queue limit.
func TestWatchPolicyRefusalsLeaveNothingBehind(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	addWatchPolicy(t, s, "tagged")

	multi := NewBgpServer()
	go multi.Serve()
	defer multi.Stop()
	require.NoError(t, multi.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 1, RouterId: "1.1.1.1", ListenPort: -1, UseMultiplePaths: true},
	}))
	addWatchPolicy(t, multi, "tagged")

	baseline := goleak.IgnoreCurrent()
	for range 20 {
		_, err := multi.watch(WatchBestPath(true), WatchBestPathPolicy("tagged"))
		require.ErrorIs(t, err, ErrWatchIncompatible)
		for _, opt := range []WatchOption{WatchPeer(), WatchUpdate(false, "", ""), WatchPostUpdate(false, "", ""), WatchEor(false)} {
			_, err = s.watch(opt, WatchBestPathPolicy("tagged"))
			require.ErrorIs(t, err, ErrWatchInvalid)
		}
		_, err = s.watch(WatchBestPath(true), WatchBestPathPolicy("missing"))
		require.ErrorIs(t, err, ErrWatchPolicyNotFound)
		_, err = s.watch(WatchBestPath(true), WatchBestPathPolicy("tagged"), WatchQueueLimit(-1))
		require.ErrorIs(t, err, ErrWatchInvalid)
		err = s.WatchEvent(context.Background(), WatchEventMessageCallbacks{})
		require.ErrorIs(t, err, ErrWatchInvalid)
	}
	goleak.VerifyNone(t, baseline)
	for _, srv := range []*BgpServer{s, multi} {
		require.False(t, srv.isWatched(watchEventTypeBestPath))
		require.NoError(t, deleteTaggedPolicy(srv), "a refused watch holds the policy")
	}
}

// matrixPath is a path of the matrix tests, with the given community and
// MED, so that the same prefix can be announced with different attributes.
func matrixPath(t *testing.T, prefix string, community, med uint32) *apiutil.Path {
	t.Helper()
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh, bgp.NewPathAttributeMultiExitDisc(med)}
	if community != 0 {
		attrs = append(attrs, bgp.NewPathAttributeCommunities([]uint32{community}))
	}
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	require.NoError(t, err)
	p, err := apiutil.NewPath(bgp.RF_IPv4_UC, nlri, false, attrs, time.Now())
	require.NoError(t, err)
	return mustApi2apiutilPath(p)
}

func medOf(p *apiutil.Path) uint32 {
	for _, a := range p.Attrs {
		if m, ok := a.(*bgp.PathAttributeMultiExitDisc); ok {
			return m.Value
		}
	}
	return 0
}

// eventsOf returns the paths of event n of the recorder: prefix, withdrawn
// and MED of each.
func (r *bestPathRecorder) eventAt(t *testing.T, n int) []string {
	t.Helper()
	r.next(t, n)
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, p := range r.events[n] {
		verb := "announce"
		if p.Withdrawal {
			verb = "withdraw"
		}
		out = append(out, fmt.Sprintf("%s %s med %d", verb, p.Nlri, medOf(p)))
	}
	return out
}

const (
	community100 = 65000<<16 | 100
	community200 = 65000<<16 | 200
)

// TestWatchPolicyChainAcceptRejectWithdraw checks the chain of one
// destination: accept, accept again, reject, withdraw. The second acceptance
// replaces the first; the rejection withdraws the path the watcher was sent
// (the second one, not what the RIB held before); the destination going away
// after that sends nothing, as nothing is left to withdraw.
func TestWatchPolicyChainAcceptRejectWithdraw(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	addWatchPolicy(t, s, "tagged")
	r := &bestPathRecorder{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, s.WatchEvent(ctx, WatchEventMessageCallbacks{OnBestPath: r.onBestPath},
		WatchBestPath(true), WatchBestPathPolicy("tagged")))
	r.next(t, 0) // the empty initial table

	const prefix = "10.71.0.0/24"
	add := func(community, med uint32) {
		_, err := s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{matrixPath(t, prefix, community, med)}})
		require.NoError(t, err)
	}
	add(community100, 1)
	assert.Equal(t, []string{"announce 10.71.0.0/24 med 1"}, r.eventAt(t, 1))
	add(community100, 2)
	assert.Equal(t, []string{"announce 10.71.0.0/24 med 2"}, r.eventAt(t, 2))
	add(0, 3)
	assert.Equal(t, []string{"withdraw 10.71.0.0/24 med 2"}, r.eventAt(t, 3), "the path sent is the one withdrawn")
	require.NoError(t, s.DeletePath(apiutil.DeletePathRequest{Paths: []*apiutil.Path{matrixPath(t, prefix, 0, 3)}}))
	// A marker: nothing came of the withdrawal, the next event is its own.
	_, err := s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{matrixPath(t, "10.71.1.0/24", community100, 9)}})
	require.NoError(t, err)
	assert.Equal(t, []string{"announce 10.71.1.0/24 med 9"}, r.eventAt(t, 4), "a withdrawal of a destination that was not sent reached the watcher")

	// And the shorter chain: accept, accept, then the destination goes.
	add(community100, 4)
	assert.Equal(t, []string{"announce 10.71.0.0/24 med 4"}, r.eventAt(t, 5))
	add(community100, 5)
	assert.Equal(t, []string{"announce 10.71.0.0/24 med 5"}, r.eventAt(t, 6))
	require.NoError(t, s.DeletePath(apiutil.DeletePathRequest{Paths: []*apiutil.Path{matrixPath(t, prefix, community100, 5)}}))
	assert.Equal(t, []string{"withdraw 10.71.0.0/24 med 5"}, r.eventAt(t, 7))
}

// TestWatchPolicyIncrementalChanges checks changes to what a policy reads,
// made while it is watched: a defined set that grows, a statement removed and
// a statement added. Each applies to the destinations whose best path
// changes after it; a destination that does not change keeps its verdict.
func TestWatchPolicyIncrementalChanges(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	ctx := context.Background()
	addWatchPolicy(t, s, "tagged") // accepts 65000:100
	add := func(prefix string, community, med uint32) {
		_, err := s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{matrixPath(t, prefix, community, med)}})
		require.NoError(t, err)
	}
	add("10.72.1.0/24", community100, 1) // accepted
	add("10.72.2.0/24", community200, 1) // not accepted yet

	r := &bestPathRecorder{}
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	require.NoError(t, s.WatchEvent(wctx, WatchEventMessageCallbacks{OnBestPath: r.onBestPath},
		WatchBestPath(true), WatchBestPathPolicy("tagged")))
	assert.Equal(t, []string{"announce 10.72.1.0/24 med 1"}, r.eventAt(t, 0), "initial table")

	// The defined set grows to take 65000:200. The destination that carries
	// it has not changed: it keeps its verdict, and a marker shows nothing
	// came of the change.
	require.NoError(t, s.AddDefinedSet(ctx, &api.AddDefinedSetRequest{DefinedSet: &api.DefinedSet{
		DefinedType: api.DefinedType_DEFINED_TYPE_COMMUNITY, Name: "tagged-communities", List: []string{"65000:200"},
	}}))
	add("10.72.9.0/24", community100, 1)
	assert.Equal(t, []string{"announce 10.72.9.0/24 med 1"}, r.eventAt(t, 1), "the grown set was applied to a destination that did not change")
	// Its best path changes: the new set applies.
	add("10.72.2.0/24", community200, 2)
	assert.Equal(t, []string{"announce 10.72.2.0/24 med 2"}, r.eventAt(t, 2))

	// The statement that accepts is removed. Nothing is re-evaluated...
	require.NoError(t, s.DeletePolicy(ctx, &api.DeletePolicyRequest{
		Policy: &api.Policy{Name: "tagged", Statements: []*api.Statement{{Name: "tagged-tagged"}}},
	}))
	// ... until a destination changes: 10.72.1.0/24 is now rejected, and
	// what was sent for it is withdrawn.
	add("10.72.1.0/24", community100, 3)
	assert.Equal(t, []string{"withdraw 10.72.1.0/24 med 1"}, r.eventAt(t, 3))

	// A statement is added to the policy, accepting 65000:200 only.
	require.NoError(t, s.AddDefinedSet(ctx, &api.AddDefinedSetRequest{DefinedSet: &api.DefinedSet{
		DefinedType: api.DefinedType_DEFINED_TYPE_COMMUNITY, Name: "only-200", List: []string{"65000:200"},
	}}))
	require.NoError(t, s.AddPolicy(ctx, &api.AddPolicyRequest{Policy: &api.Policy{
		Name: "tagged",
		Statements: []*api.Statement{{
			Name:       "tagged-only-200",
			Conditions: &api.Conditions{CommunitySet: &api.MatchSet{Type: api.MatchSet_TYPE_ANY, Name: "only-200"}},
			Actions:    &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_ACCEPT},
		}},
	}}))
	add("10.72.1.0/24", community100, 4) // not accepted by the new statement
	add("10.72.2.0/24", community200, 5)
	assert.Equal(t, []string{"announce 10.72.2.0/24 med 5"}, r.eventAt(t, 4), "the added statement was not applied, or 10.72.1.0/24 was sent")
}

// TestWatchPolicyReconstructsTheRib checks that the table a consumer rebuilds
// from the events of a policy watcher is the RIB the policy accepts, under a
// policy that does not change, after a run of changes of local paths: an
// announcement with and without the community, with different attributes,
// and withdrawals.
func TestWatchPolicyReconstructsTheRib(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	addWatchPolicy(t, s, "tagged")
	const prefixes = 30
	prefix := func(i int) string { return fmt.Sprintf("10.73.%d.0/24", i) }
	// Some are there before the watch, so that the initial table is part of
	// what is rebuilt.
	for i := 0; i < prefixes; i += 3 {
		_, err := s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{matrixPath(t, prefix(i), community100, 0)}})
		require.NoError(t, err)
	}
	r := newReconstruction()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, s.WatchEvent(ctx, WatchEventMessageCallbacks{OnBestPath: r.onBestPath},
		WatchBestPath(true), WatchBestPathPolicy("tagged")))

	// A fixed sequence, so that a failure is reproduced: the prefix and
	// the step decide whether the path is tagged and whether it goes.
	live := map[int]*apiutil.Path{}
	for step := range 400 {
		i := step * 7 % prefixes
		if old, ok := live[i]; ok && step%5 == 0 {
			require.NoError(t, s.DeletePath(apiutil.DeletePathRequest{Paths: []*apiutil.Path{old}}))
			delete(live, i)
			continue
		}
		community := uint32(0)
		if step/3%2 == 0 {
			community = community100
		}
		path := matrixPath(t, prefix(i), community, uint32(step))
		_, err := s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{path}})
		require.NoError(t, err)
		live[i] = path
	}
	require.Eventually(t, func() bool {
		got, _ := r.snapshot()
		return assert.ObjectsAreEqual(expectedFromRib(t, s, "tagged"), got)
	}, 30*time.Second, 20*time.Millisecond, "the consumer's table is not the RIB the policy accepts")
	got, _ := r.snapshot()
	assert.NotEmpty(t, got)
}

// TestWatchEventPolicyQueueLimitEndsABlockedStream checks the same for a
// watch with a policy: while the Send is blocked, held by a gate that is
// known to be entered, the watcher is unregistered and its policy released
// before the client reads, and the client then gets RESOURCE_EXHAUSTED.
func TestWatchEventPolicyQueueLimitEndsABlockedStream(t *testing.T) {
	g := newGatedSend()
	t.Cleanup(g.open)
	s, client := startGrpcServer(t, []ServerOption{GrpcOption([]grpc.ServerOption{grpc.StreamInterceptor(g.intercept)})})
	addWatchPolicy(t, s, "tagged")

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	stream := openWatch(t, ctx, client, &api.WatchEventRequest{
		Table: &api.WatchEventRequest_Table{Filters: []*api.WatchEventRequest_Table_Filter{
			{Type: api.WatchEventRequest_Table_Filter_TYPE_BEST, Policy: "tagged"},
		}},
		MaxQueuedEvents: 50,
	})
	require.Eventually(t, func() bool { return s.isWatched(watchEventTypeBestPath) }, 10*time.Second, 10*time.Millisecond)
	require.Error(t, deleteTaggedPolicy(s), "the watcher does not hold its policy")

	// Every path is tagged, so every event reaches the watcher and the
	// client. One event, whose Send is entered and held; then a burst that
	// overflows the queue behind it.
	tagged := []uint32{watchPolicyCommunity, 65001 << 16}
	addPrefixesWith(t, s, 0, 1, tagged)
	select {
	case <-g.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the Send was not entered")
	}
	addPrefixesWith(t, s, 1, 2000, tagged)
	require.Eventually(t, func() bool { return !s.isWatched(watchEventTypeBestPath) }, 20*time.Second, 10*time.Millisecond,
		"the failed watcher is still registered while its client is blocked")
	require.Eventually(t, func() bool { return deleteTaggedPolicy(s) == nil }, 10*time.Second, 10*time.Millisecond,
		"the failed watcher still holds its policy")
	assert.Equal(t, int64(0), g.sent.Load(), "the Send was not blocked when the watcher failed")

	// The client reads now, and the watch ends with the status.
	g.open()
	require.Equal(t, codes.ResourceExhausted, receiveUntilEnd(stream))
}
