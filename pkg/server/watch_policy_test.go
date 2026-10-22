package server

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

const watchPolicyCommunity = 65000<<16 | 100

// addWatchPolicy defines a policy that accepts the paths carrying
// 65000:100.
func addWatchPolicy(t *testing.T, s *BgpServer, name string) {
	t.Helper()
	require.NoError(t, s.AddDefinedSet(context.Background(), &api.AddDefinedSetRequest{
		DefinedSet: &api.DefinedSet{
			DefinedType: api.DefinedType_DEFINED_TYPE_COMMUNITY,
			Name:        name + "-communities",
			List:        []string{"65000:100"},
		},
	}))
	require.NoError(t, s.AddPolicy(context.Background(), &api.AddPolicyRequest{
		Policy: &api.Policy{
			Name: name,
			Statements: []*api.Statement{{
				Name: name + "-tagged",
				Conditions: &api.Conditions{
					CommunitySet: &api.MatchSet{Type: api.MatchSet_TYPE_ANY, Name: name + "-communities"},
				},
				Actions: &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_ACCEPT},
			}},
		},
	}))
}

func watchPolicyPath(t *testing.T, prefix string, tagged bool) *apiutil.Path {
	t.Helper()
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh}
	if tagged {
		attrs = append(attrs, bgp.NewPathAttributeCommunities([]uint32{watchPolicyCommunity}))
	}
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	require.NoError(t, err)
	p, err := apiutil.NewPath(bgp.RF_IPv4_UC, nlri, false, attrs, time.Now())
	require.NoError(t, err)
	return mustApi2apiutilPath(p)
}

type bestPathRecorder struct {
	mu     sync.Mutex
	events [][]*apiutil.Path
}

func (r *bestPathRecorder) onBestPath(paths []*apiutil.Path, _ time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, paths)
}

// next waits for the next event and returns its paths as prefix -> withdrawn.
func (r *bestPathRecorder) next(t *testing.T, n int) map[string]bool {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		if len(r.events) > n {
			out := map[string]bool{}
			for _, p := range r.events[n] {
				out[p.Nlri.String()] = p.Withdrawal
			}
			r.mu.Unlock()
			return out
		}
		r.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for best path event %d", n)
	return nil
}

// TestWatchBestPathPolicy checks a watcher that filters its best paths with
// a policy: the initial table and the changes carry only the paths the
// policy accepts, and a best path it accepted that is replaced by one it does
// not accept, or withdrawn, reaches the watcher as a withdrawal.
func TestWatchBestPathPolicy(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	addWatchPolicy(t, s, "tagged")

	_, err := s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{
		watchPolicyPath(t, "10.0.1.0/24", true),
		watchPolicyPath(t, "10.0.2.0/24", false),
	}})
	require.NoError(t, err)

	r := &bestPathRecorder{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, s.WatchEvent(ctx, WatchEventMessageCallbacks{OnBestPath: r.onBestPath},
		WatchBestPath(true), WatchBestPathPolicy("tagged")))

	// The initial table: the tagged path only.
	assert.Equal(t, map[string]bool{"10.0.1.0/24": false}, r.next(t, 0))

	// A tagged path is sent; an untagged one is not.
	_, err = s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{watchPolicyPath(t, "10.0.3.0/24", false)}})
	require.NoError(t, err)
	_, err = s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{watchPolicyPath(t, "10.0.4.0/24", true)}})
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"10.0.4.0/24": false}, r.next(t, 1))

	// The tagged best path is replaced by an untagged one: a withdrawal.
	_, err = s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{watchPolicyPath(t, "10.0.1.0/24", false)}})
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"10.0.1.0/24": true}, r.next(t, 2))

	// An untagged best path becomes tagged: an announcement.
	_, err = s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{watchPolicyPath(t, "10.0.2.0/24", true)}})
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"10.0.2.0/24": false}, r.next(t, 3))

	// The destination of a tagged path goes away: a withdrawal; of an
	// untagged one: nothing.
	require.NoError(t, s.DeletePath(apiutil.DeletePathRequest{Paths: []*apiutil.Path{watchPolicyPath(t, "10.0.3.0/24", false)}}))
	require.NoError(t, s.DeletePath(apiutil.DeletePathRequest{Paths: []*apiutil.Path{watchPolicyPath(t, "10.0.4.0/24", true)}}))
	assert.Equal(t, map[string]bool{"10.0.4.0/24": true}, r.next(t, 4))
	// Nothing came of the untagged one: the next event is the next tagged
	// path.
	_, err = s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{watchPolicyPath(t, "10.0.8.0/24", true)}})
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"10.0.8.0/24": false}, r.next(t, 5), "an untagged path reached the watcher")
}

// TestWatchBestPathPolicyLifetime checks that a watcher needs an existing
// policy, holds it while it runs and releases it when it stops.
func TestWatchBestPathPolicyLifetime(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	_, err := s.watch(WatchBestPath(true), WatchBestPathPolicy("missing"))
	require.Error(t, err)
	_, err = s.watch(WatchPeer(), WatchBestPathPolicy("missing"))
	require.Error(t, err)

	addWatchPolicy(t, s, "tagged")
	w, err := s.watch(WatchBestPath(false), WatchBestPathPolicy("tagged"))
	require.NoError(t, err)

	del := &api.DeletePolicyRequest{Policy: &api.Policy{Name: "tagged"}, All: true}
	require.Error(t, s.DeletePolicy(context.Background(), del), "a policy in use by a watcher was deleted")
	w.Stop()
	require.NoError(t, s.DeletePolicy(context.Background(), del))
}

// TestWatchBestPathPolicyUnfilteredWatchersUnchanged checks that a watcher
// without a policy still gets every best path change next to a filtered one.
func TestWatchBestPathPolicyUnfilteredWatchersUnchanged(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	addWatchPolicy(t, s, "tagged")

	all, err := s.watch(WatchBestPath(false))
	require.NoError(t, err)
	defer all.Stop()
	filtered, err := s.watch(WatchBestPath(false), WatchBestPathPolicy("tagged"))
	require.NoError(t, err)
	defer filtered.Stop()

	_, err = s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{watchPolicyPath(t, "10.0.5.0/24", false)}})
	require.NoError(t, err)
	_, err = s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{watchPolicyPath(t, "10.0.6.0/24", true)}})
	require.NoError(t, err)

	got := func(w *watcher, n int) []string {
		t.Helper()
		var out []string
		for len(out) < n {
			select {
			case ev := <-w.Event():
				for _, p := range ev.(*watchEventBestPath).PathList {
					out = append(out, p.GetNlri().String())
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("timed out after %v", out)
			}
		}
		return out
	}
	assert.Equal(t, []string{"10.0.5.0/24", "10.0.6.0/24"}, got(all, 2))
	assert.Equal(t, []string{"10.0.6.0/24"}, got(filtered, 1))
}

// TestWatchPolicyRemovedFailsTheWatcher checks that a reload that removes
// a watcher's policy, or defines it again under the same name, fails the
// watcher when the reload completes, with no event needed to notice it.
func TestWatchPolicyRemovedFailsTheWatcher(t *testing.T) {
	for _, recreate := range []bool{false, true} {
		s := runNewServer(t, 1, "1.1.1.1", -1)
		addWatchPolicy(t, s, "tagged")

		failed := make(chan error, 1)
		ctx, cancel := context.WithCancel(context.Background())
		require.NoError(t, s.WatchEvent(ctx, WatchEventMessageCallbacks{
			OnBestPath: func([]*apiutil.Path, time.Time) {},
			OnError:    func(err error) { failed <- err },
		}, WatchBestPath(false), WatchBestPathPolicy("tagged")))

		req := &api.SetPoliciesRequest{}
		if recreate {
			req.DefinedSets = []*api.DefinedSet{{
				DefinedType: api.DefinedType_DEFINED_TYPE_COMMUNITY, Name: "tagged-communities", List: []string{"65000:100"},
			}}
			req.Policies = []*api.Policy{{
				Name: "tagged",
				Statements: []*api.Statement{{
					Name:       "tagged-tagged",
					Conditions: &api.Conditions{CommunitySet: &api.MatchSet{Type: api.MatchSet_TYPE_ANY, Name: "tagged-communities"}},
					Actions:    &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_ACCEPT},
				}},
			}}
		}
		require.NoError(t, s.SetPolicies(context.Background(), req))
		select {
		case err := <-failed:
			assert.True(t, errors.Is(err, ErrWatchPolicyRemoved), "got %v", err)
		case <-time.After(10 * time.Second):
			t.Fatalf("the watcher did not fail (recreate %v)", recreate)
		}
		cancel()
		require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
	}
}
