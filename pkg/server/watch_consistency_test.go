package server

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// addRpkiWatchPolicy defines a policy that accepts the paths whose RPKI
// validation is valid.
func addRpkiWatchPolicy(t *testing.T, s *BgpServer, name string) {
	t.Helper()
	require.NoError(t, s.AddPolicy(context.Background(), &api.AddPolicyRequest{
		Policy: &api.Policy{
			Name: name,
			Statements: []*api.Statement{{
				Name:       name + "-valid",
				Conditions: &api.Conditions{RpkiResult: api.ValidationState_VALIDATION_STATE_VALID},
				Actions:    &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_ACCEPT},
			}},
		},
	}))
}

// rpkiOrigin is the origin AS of rpkiPath's paths.
const rpkiOrigin = 65010

// rpkiPath is a path originated by rpkiOrigin.
func rpkiPath(t *testing.T, prefix string, tagged bool) *apiutil.Path {
	t.Helper()
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0), nh,
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{rpkiOrigin})}),
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

// setRoa adds or deletes a ROA for 10.0.0.0/8 up to /24 and the given AS,
// the way the dispatcher changes the ROA table: under the server lock.
func setRoa(s *BgpServer, add bool, as uint32) {
	r := table.NewROA(bgp.AFI_IP, net.ParseIP("10.0.0.0").To4(), 8, 24, as, "test")
	s.shared.mu.Lock()
	defer s.shared.mu.Unlock()
	if add {
		s.roaTable.Add(r)
	} else {
		s.roaTable.Delete(r)
	}
}

// TestWatchPolicyInitialTableAndRoaChanges checks that the initial table of a
// watcher whose policy reads the ROA table is evaluated while the ROA table
// changes, as the dispatcher changes it, without a data race (run with
// -race).
func TestWatchPolicyInitialTableAndRoaChanges(t *testing.T) {
	for _, batch := range []bool{true, false} {
		s := runNewServer(t, 1, "1.1.1.1", -1)
		addRpkiWatchPolicy(t, s, "valid")
		addPrefixes(t, s, 0, 20000, 1)

		stop := make(chan struct{})
		changed := make(chan struct{})
		go func() {
			defer close(changed)
			for i := uint32(0); ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				setRoa(s, i%2 == 0, 64512+i%1000)
			}
		}()

		got := make(chan struct{})
		var once atomic.Bool
		ctx, cancel := context.WithCancel(context.Background())
		cb := WatchEventMessageCallbacks{}
		if batch {
			cb.OnBestPathBatch = func(_ []*apiutil.Path, _ time.Time, last bool) {
				if last && once.CompareAndSwap(false, true) {
					close(got)
				}
			}
		} else {
			cb.OnBestPath = func([]*apiutil.Path, time.Time) {
				if once.CompareAndSwap(false, true) {
					close(got)
				}
			}
		}
		require.NoError(t, s.WatchEvent(ctx, cb, WatchBestPath(true), WatchBestPathPolicy("valid")))
		select {
		case <-got:
		case <-time.After(30 * time.Second):
			t.Fatal("no initial table")
		}
		close(stop)
		<-changed
		cancel()
		require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
	}
}

// TestWatchPolicyWithdrawsWhatItAnnounced checks that a path the watcher
// was sent is withdrawn when it goes away even if the policy would no longer
// accept it by then: here its ROA was removed in between.
func TestWatchPolicyWithdrawsWhatItAnnounced(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	addRpkiWatchPolicy(t, s, "valid")
	setRoa(s, true, rpkiOrigin)

	r := &bestPathRecorder{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, s.WatchEvent(ctx, WatchEventMessageCallbacks{OnBestPath: r.onBestPath},
		WatchBestPath(true), WatchBestPathPolicy("valid")))
	assert.Equal(t, map[string]bool{}, r.next(t, 0), "initial table")

	// Announced while its ROA validates it.
	_, err := s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{rpkiPath(t, "10.0.1.0/24", false)}})
	require.NoError(t, err)
	_, err = s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{rpkiPath(t, "10.0.2.0/24", false)}})
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"10.0.1.0/24": false}, r.next(t, 1))
	assert.Equal(t, map[string]bool{"10.0.2.0/24": false}, r.next(t, 2))

	setRoa(s, false, rpkiOrigin)

	// Withdrawn, and replaced by a path the policy does not accept: both
	// reach the watcher as withdrawals.
	require.NoError(t, s.DeletePath(apiutil.DeletePathRequest{Paths: []*apiutil.Path{rpkiPath(t, "10.0.1.0/24", false)}}))
	assert.Equal(t, map[string]bool{"10.0.1.0/24": true}, r.next(t, 3))
	_, err = s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{rpkiPath(t, "10.0.2.0/24", true)}})
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"10.0.2.0/24": true}, r.next(t, 4))
}

// TestWatchRefusedLeavesNothingRunning checks that a refused watch starts
// no goroutine and holds no policy.
func TestWatchRefusedLeavesNothingRunning(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	addWatchPolicy(t, s, "tagged")

	baseline := goleak.IgnoreCurrent()
	for range 50 {
		_, err := s.watch(WatchPeer(), WatchBestPathPolicy("tagged"))
		require.Error(t, err)
		_, err = s.watch(WatchBestPath(true), WatchBestPathPolicy("missing"))
		require.Error(t, err)
	}
	goleak.VerifyNone(t, baseline)
	require.NoError(t, s.DeletePolicy(context.Background(), &api.DeletePolicyRequest{Policy: &api.Policy{Name: "tagged"}, All: true}))
}

// TestWatchEventOnePolicyPerWatch checks that a policy cannot be combined
// with another TYPE_BEST filter, which would leave one of them unapplied.
func TestWatchEventOnePolicyPerWatch(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	addWatchPolicy(t, s, "tagged")
	addWatchPolicy(t, s, "other")
	srv := &server{bgpServer: s}

	best := func(policy string) *api.WatchEventRequest_Table_Filter {
		return &api.WatchEventRequest_Table_Filter{Type: api.WatchEventRequest_Table_Filter_TYPE_BEST, Policy: policy}
	}
	for _, filters := range [][]*api.WatchEventRequest_Table_Filter{
		{best("tagged"), best("other")},
		{best("tagged"), best("")},
		{best(""), best("tagged")},
	} {
		err := srv.watchEvent(context.Background(), &api.WatchEventRequest{Table: &api.WatchEventRequest_Table{Filters: filters}},
			func(*api.WatchEventResponse, time.Time) {}, func(error) {})
		require.Equal(t, codes.InvalidArgument, status.Code(err), "filters %v: %v", filters, err)
	}
	require.False(t, s.isWatched(watchEventTypeBestPath))
}

// TestWatchPolicyInitialTableLeavesChangedDestinations checks the initial
// table of a policy watcher against the changes made while it is being
// evaluated: a destination changed meanwhile is told by the change's own
// event, never by the table taken before it, so nothing the watcher holds
// at the end is stale.
func TestWatchPolicyInitialTableLeavesChangedDestinations(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	addWatchPolicy(t, s, "tagged")
	_, err := s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{
		watchPolicyPath(t, "10.0.1.0/24", true), // replaced by an untagged path during the table
		watchPolicyPath(t, "10.0.2.0/24", true), // withdrawn during the table
		watchPolicyPath(t, "10.0.3.0/24", true), // left alone
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
	_, err = s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{watchPolicyPath(t, "10.0.1.0/24", false)}})
	require.NoError(t, err)
	require.NoError(t, s.DeletePath(apiutil.DeletePathRequest{Paths: []*apiutil.Path{watchPolicyPath(t, "10.0.2.0/24", true)}}))
	_, err = s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{watchPolicyPath(t, "10.0.4.0/24", true)}})
	require.NoError(t, err)
	close(release)

	assert.Equal(t, map[string]bool{"10.0.3.0/24": false}, r.next(t, 0), "initial table")
	assert.Equal(t, map[string]bool{"10.0.4.0/24": false}, r.next(t, 1))
	_, err = s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{watchPolicyPath(t, "10.0.5.0/24", true)}})
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"10.0.5.0/24": false}, r.next(t, 2), "an event about 10.0.1.0/24 or 10.0.2.0/24 came first")
}

// notifyBest notifies a best path change as propagateUpdateToNeighbors
// does: under the server lock.
func notifyBest(s *BgpServer, best ...*table.Path) {
	s.shared.mu.RLock()
	defer s.shared.mu.RUnlock()
	s.notifyBestWatcher(best, nil, nil, nil)
}

type gotPath struct {
	prefix   string
	withdraw bool
	source   string
	id       uint32
}

func nextBest(t *testing.T, w *watcher) []gotPath {
	t.Helper()
	select {
	case ev := <-w.Event():
		var out []gotPath
		for _, p := range ev.(*watchEventBestPath).PathList {
			out = append(out, gotPath{p.GetNlri().String(), p.IsWithdraw, p.GetSource().Address.String(), p.RemoteID()})
		}
		return out
	case <-time.After(10 * time.Second):
		t.Fatal("no best path event")
		return nil
	}
}

func tablePath(t *testing.T, family bgp.Family, nlri bgp.NLRI, source string, id uint32, tagged, withdraw bool) *table.Path {
	t.Helper()
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh}
	if tagged {
		attrs = append(attrs, bgp.NewPathAttributeCommunities([]uint32{watchPolicyCommunity}))
	}
	src := &table.PeerInfo{AS: 65001, Address: netip.MustParseAddr(source), ID: netip.MustParseAddr(source)}
	p := table.NewPath(family, src, bgp.PathNLRI{NLRI: nlri, ID: id}, withdraw, attrs, time.Now(), false)
	return p
}

// TestWatchPolicyAddPathSources checks a destination whose best path moves
// between paths of several sources and ADD-PATH identifiers: the watcher
// tracks the destination, so the withdrawal it gets is of the path it was
// sent, whichever path replaced it.
func TestWatchPolicyAddPathSources(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	addWatchPolicy(t, s, "tagged")
	w, err := s.watch(WatchBestPath(false), WatchBestPathPolicy("tagged"))
	require.NoError(t, err)
	defer w.Stop()

	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.9.0/24"))
	require.NoError(t, err)
	p := func(source string, id uint32, tagged, withdraw bool) *table.Path {
		return tablePath(t, bgp.RF_IPv4_UC, nlri, source, id, tagged, withdraw)
	}
	notifyBest(s, p("192.0.2.1", 1, true, false))
	assert.Equal(t, []gotPath{{"10.0.9.0/24", false, "192.0.2.1", 1}}, nextBest(t, w))
	// Another identifier of the same source, tagged: it replaces the first.
	notifyBest(s, p("192.0.2.1", 2, true, false))
	assert.Equal(t, []gotPath{{"10.0.9.0/24", false, "192.0.2.1", 2}}, nextBest(t, w))
	// Another source, untagged: the path sent (identifier 2) is withdrawn.
	notifyBest(s, p("192.0.2.2", 7, false, false))
	assert.Equal(t, []gotPath{{"10.0.9.0/24", true, "192.0.2.1", 2}}, nextBest(t, w))
	// The destination goes: nothing is left to withdraw.
	notifyBest(s, p("192.0.2.2", 7, false, true))
	notifyBest(s, p("192.0.2.2", 9, true, false))
	assert.Equal(t, []gotPath{{"10.0.9.0/24", false, "192.0.2.2", 9}}, nextBest(t, w))
	notifyBest(s, p("192.0.2.2", 9, true, true))
	assert.Equal(t, []gotPath{{"10.0.9.0/24", true, "192.0.2.2", 9}}, nextBest(t, w))
}

// TestWatchPolicyVpnDestinations checks that the same prefix under two
// route distinguishers is two destinations for the watcher.
func TestWatchPolicyVpnDestinations(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	addWatchPolicy(t, s, "tagged")
	w, err := s.watch(WatchBestPath(false), WatchBestPathPolicy("tagged"))
	require.NoError(t, err)
	defer w.Stop()

	vpn := func(rd string) bgp.NLRI {
		d, err := bgp.ParseRouteDistinguisher(rd)
		require.NoError(t, err)
		n, err := bgp.NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix("10.30.2.0/24"), *bgp.NewMPLSLabelStack(100), d)
		require.NoError(t, err)
		return n
	}
	a, b := vpn("100:100"), vpn("100:200")
	notifyBest(s, tablePath(t, bgp.RF_IPv4_VPN, a, "192.0.2.1", 0, true, false))
	notifyBest(s, tablePath(t, bgp.RF_IPv4_VPN, b, "192.0.2.1", 0, true, false))
	assert.Equal(t, []gotPath{{a.String(), false, "192.0.2.1", 0}}, nextBest(t, w))
	assert.Equal(t, []gotPath{{b.String(), false, "192.0.2.1", 0}}, nextBest(t, w))
	notifyBest(s, tablePath(t, bgp.RF_IPv4_VPN, a, "192.0.2.1", 0, false, false))
	assert.Equal(t, []gotPath{{a.String(), true, "192.0.2.1", 0}}, nextBest(t, w))
	notifyBest(s, tablePath(t, bgp.RF_IPv4_VPN, b, "192.0.2.1", 0, true, true))
	assert.Equal(t, []gotPath{{b.String(), true, "192.0.2.1", 0}}, nextBest(t, w))
}

// TestWatchPolicyChainedActions checks a policy whose verdict depends on an
// earlier statement's modification: the modification is evaluated, and the
// path delivered is left as it was.
func TestWatchPolicyChainedActions(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	ctx := context.Background()
	require.NoError(t, s.AddDefinedSet(ctx, &api.AddDefinedSetRequest{DefinedSet: &api.DefinedSet{
		DefinedType: api.DefinedType_DEFINED_TYPE_PREFIX, Name: "mark",
		Prefixes: []*api.Prefix{{IpPrefix: "10.0.20.0/24", MaskLengthMin: 24, MaskLengthMax: 24}},
	}}))
	require.NoError(t, s.AddDefinedSet(ctx, &api.AddDefinedSetRequest{DefinedSet: &api.DefinedSet{
		DefinedType: api.DefinedType_DEFINED_TYPE_COMMUNITY, Name: "marked", List: []string{"65000:100"},
	}}))
	require.NoError(t, s.AddPolicy(ctx, &api.AddPolicyRequest{Policy: &api.Policy{
		Name: "chained",
		Statements: []*api.Statement{
			{
				Name:       "chained-mark",
				Conditions: &api.Conditions{PrefixSet: &api.MatchSet{Type: api.MatchSet_TYPE_ANY, Name: "mark"}},
				Actions: &api.Actions{Community: &api.CommunityAction{
					Type: api.CommunityAction_TYPE_ADD, Communities: []string{"65000:100"},
				}},
			},
			{
				Name:       "chained-accept",
				Conditions: &api.Conditions{CommunitySet: &api.MatchSet{Type: api.MatchSet_TYPE_ANY, Name: "marked"}},
				Actions:    &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_ACCEPT},
			},
		},
	}}))

	r := &bestPathRecorder{}
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	require.NoError(t, s.WatchEvent(wctx, WatchEventMessageCallbacks{OnBestPath: r.onBestPath},
		WatchBestPath(true), WatchBestPathPolicy("chained")))
	assert.Equal(t, map[string]bool{}, r.next(t, 0))
	_, err := s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{watchPolicyPath(t, "10.0.21.0/24", false)}})
	require.NoError(t, err)
	_, err = s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{watchPolicyPath(t, "10.0.20.0/24", false)}})
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"10.0.20.0/24": false}, r.next(t, 1))
	r.mu.Lock()
	for _, a := range r.events[1][0].Attrs {
		_, isCommunities := a.(*bgp.PathAttributeCommunities)
		assert.False(t, isCommunities, "the delivered path was modified")
	}
	r.mu.Unlock()
}
