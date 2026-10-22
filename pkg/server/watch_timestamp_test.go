package server

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// TestWatchEventTimestamps checks that every table message carries the time
// of its event: the initial tables of every filter type, a change and the
// End-of-RIB.
func TestWatchEventTimestamps(t *testing.T) {
	ctx := context.Background()
	s1 := runNewServer(t, 1, "1.1.1.1", 10179)
	defer s1.StopBgp(context.Background(), &api.StopBgpRequest{})
	s2 := runNewServer(t, 1, "2.2.2.2", 20179)
	defer s2.StopBgp(context.Background(), &api.StopBgpRequest{})
	watch := func(typ api.WatchEventRequest_Table_Filter_Type) (chan *api.WatchEventResponse_TableEvent, context.CancelFunc) {
		got := make(chan *api.WatchEventResponse_TableEvent, 1000)
		wctx, cancel := context.WithCancel(ctx)
		err := (&server{bgpServer: s1}).watchEvent(wctx, &api.WatchEventRequest{
			Table: &api.WatchEventRequest_Table{Filters: []*api.WatchEventRequest_Table_Filter{{Type: typ, Init: true}}},
		}, func(r *api.WatchEventResponse, _ time.Time) {
			if te := r.GetTable(); te != nil {
				got <- te
			}
		}, func(error) {})
		require.NoError(t, err)
		return got, cancel
	}
	stamped := func(what string, te *api.WatchEventResponse_TableEvent) {
		t.Helper()
		require.NotNil(t, te.Timestamp, "%s: no timestamp", what)
		assert.WithinDuration(t, time.Now(), te.Timestamp.AsTime(), time.Minute, "%s", what)
	}

	// The End-of-RIB the peer sends once established.
	eors, stopEor := watch(api.WatchEventRequest_Table_Filter_TYPE_EOR)
	defer stopEor()
	established := newPeerStateWaiter(s1, api.PeerState_SESSION_STATE_ESTABLISHED)
	// With graceful restart, so that the peers send End-of-RIB.
	gr := func(_ *BgpServer, _ *oc.Global, n *oc.Neighbor) {
		n.GracefulRestart.Config.Enabled = true
		n.GracefulRestart.Config.RestartTime = 120
	}
	require.NoError(t, peerServers(t, ctx, []*BgpServer{s1, s2}, []oc.AfiSafiType{oc.AFI_SAFI_TYPE_IPV4_UNICAST}, gr))
	established.Wait(t, 10*time.Second)
	select {
	case te := <-eors:
		stamped("End-of-RIB", te)
	case <-time.After(10 * time.Second):
		t.Fatal("no End-of-RIB")
	}

	_, err := s2.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{consumerLocalPath(t, "10.10.0.0/24")}})
	require.NoError(t, err)
	_, err = s1.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{consumerLocalPath(t, "10.11.0.0/24")}})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		n := 0
		_ = s1.mgmtOperation(func() error {
			for _, p := range s1.neighborMap {
				n += p.adjRibIn.Count([]bgp.Family{bgp.RF_IPv4_UC})
			}
			return nil
		}, true)
		return n > 0
	}, 10*time.Second, 50*time.Millisecond)

	for _, typ := range []api.WatchEventRequest_Table_Filter_Type{
		api.WatchEventRequest_Table_Filter_TYPE_BEST,
		api.WatchEventRequest_Table_Filter_TYPE_ADJIN,
		api.WatchEventRequest_Table_Filter_TYPE_POST_POLICY,
	} {
		got, cancel := watch(typ)
		select {
		case te := <-got:
			stamped(typ.String()+" initial table", te)
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: no table event", typ)
		}
		if typ == api.WatchEventRequest_Table_Filter_TYPE_BEST {
			_, err = s1.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{consumerLocalPath(t, "10.12.0.0/24")}})
			require.NoError(t, err)
			for te := range got {
				if len(te.Paths) > 0 && prefixOf(t, te.Paths[0]) == "10.12.0.0/24" {
					stamped("a change", te)
					break
				}
			}
		}
		cancel()
	}
}

func prefixOf(t *testing.T, p *api.Path) string {
	t.Helper()
	n, err := apiutil.UnmarshalNLRI(bgp.RF_IPv4_UC, p.GetNlri())
	require.NoError(t, err)
	return n.String()
}

// TestWatchPostPolicyUpdateTimestampIsEventTime checks the time of a
// post-policy event: an announcement keeps the time the path was received,
// at the resolution the path keeps it, one second, which is what lag is
// measured against, while the withdrawal gobgp makes when a peer goes down
// gets the time of the event, not the age of the path it replaces.
func TestWatchPostPolicyUpdateTimestampIsEventTime(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	require.NoError(t, s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.2", PeerAsn: 2},
		Transport: &api.Transport{PassiveMode: true},
	}}))
	w, err := s.watch(WatchPostUpdate(false, "", ""))
	require.NoError(t, err)
	defer w.Stop()

	var p *peer
	s.shared.mu.RLock()
	for _, n := range s.neighborMap {
		p = n
	}
	s.shared.mu.RUnlock()
	require.NotNil(t, p)

	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
	require.NoError(t, err)
	src := &table.PeerInfo{AS: 2, Address: netip.MustParseAddr("127.0.0.2"), ID: netip.MustParseAddr("2.2.2.2")}
	old := time.Unix(time.Now().Add(-6*time.Hour).Unix(), 0) // paths keep seconds
	received := old.Add(123456789 * time.Nanosecond)
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh}
	stamp := func(withdraw bool) time.Time {
		path := table.NewPath(bgp.RF_IPv4_UC, src, bgp.PathNLRI{NLRI: nlri}, withdraw, attrs, received, false)
		s.notifyPostPolicyUpdateWatcher(p, []*table.Path{path})
		select {
		case ev := <-w.Event():
			return ev.(*watchEventUpdate).Timestamp
		case <-time.After(10 * time.Second):
			t.Fatal("no post-policy event")
			return time.Time{}
		}
	}
	announced := stamp(false)
	assert.True(t, old.Equal(announced), "an announcement lost the time it was received")
	assert.Zero(t, announced.Nanosecond(), "an announcement carries more than the one second the path keeps")
	assert.WithinDuration(t, time.Now(), stamp(true), time.Minute, "a withdrawal carries the age of the path")
}
