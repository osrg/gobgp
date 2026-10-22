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
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/packet/bmp"
	"github.com/osrg/gobgp/v4/pkg/zebra"
)

// The tests of this file describe what the consumers of the best path events
// that read them from the watcher itself, BMP's Loc-RIB monitoring
// (bmpLocRIBRouteMonitoring) and the Zebra client (it reads PathList,
// MultiPathList and Vrf), receive. They use no option of the watch that
// filters or bounds, and must pass unchanged on a server without them.

// consumerLocalPath is a path of the server itself.
func consumerLocalPath(t *testing.T, prefix string) *apiutil.Path {
	t.Helper()
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh}
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	require.NoError(t, err)
	p, err := apiutil.NewPath(bgp.RF_IPv4_UC, nlri, false, attrs, time.Now())
	require.NoError(t, err)
	return mustApi2apiutilPath(p)
}

// consumerTablePath is a path of a peer.
func consumerTablePath(t *testing.T, nlri bgp.NLRI, source string, withdraw bool) *table.Path {
	t.Helper()
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh}
	src := &table.PeerInfo{AS: 65001, Address: netip.MustParseAddr(source), ID: netip.MustParseAddr(source)}
	return table.NewPath(bgp.RF_IPv4_UC, src, bgp.PathNLRI{NLRI: nlri}, withdraw, attrs, time.Now(), false)
}

func notifyBestLists(s *BgpServer, best []*table.Path, multipath [][]*table.Path, update, withdraw []*table.Path) {
	s.shared.mu.RLock()
	defer s.shared.mu.RUnlock()
	s.notifyBestWatcher(best, multipath, update, withdraw)
}

func nextBestEvent(t *testing.T, w *watcher) *watchEventBestPath {
	t.Helper()
	select {
	case ev := <-w.Event():
		return ev.(*watchEventBestPath)
	case <-time.After(10 * time.Second):
		t.Fatal("no best path event")
		return nil
	}
}

// locRibMessages are the messages BMP writes for an event.
func locRibMessages(s *BgpServer, ev *watchEventBestPath) []*bmp.BMPMessage {
	info := &table.PeerInfo{Address: netip.IPv4Unspecified(), AS: 1, ID: netip.MustParseAddr("1.1.1.1")}
	return bmpLocRIBRouteMonitoring(ev, info, s.logger)
}

// updateOf returns the BGP update of a Loc-RIB route monitoring message.
func updateOf(t *testing.T, m *bmp.BMPMessage) *bgp.BGPUpdate {
	t.Helper()
	require.Equal(t, uint8(bmp.BMP_MSG_ROUTE_MONITORING), m.Header.Type)
	require.Equal(t, bmp.BMP_PEER_TYPE_LOCAL_RIB, m.PeerHeader.PeerType)
	msg, err := bgp.ParseBGPMessage(m.Body.(*bmp.BMPRouteMonitoring).BGPUpdatePayload, bmpAddPathMarshallingOption(bgp.RF_IPv4_UC)...)
	require.NoError(t, err)
	u, ok := msg.Body.(*bgp.BGPUpdate)
	require.True(t, ok)
	return u
}

func TestBestPathWatcherEmptyInitialTable(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	w, err := s.watch(WatchBestPath(true))
	require.NoError(t, err)
	defer w.Stop()

	// The empty table is one event with no path: BMP has nothing to write for it, and nothing else follows.
	ev := nextBestEvent(t, w)
	assert.Empty(t, ev.PathList)
	assert.Empty(t, ev.MultiPathList)
	assert.Empty(t, locRIBPathsForBMP(ev))
	assert.Empty(t, locRibMessages(s, ev))
	assert.Empty(t, w.Event(), "an event followed the empty initial table")
}

func TestBestPathWatcherAnnouncementsAndWithdrawals(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	w, err := s.watch(WatchBestPath(false))
	require.NoError(t, err)
	defer w.Stop()

	p := consumerLocalPath(t, "10.90.0.0/24")
	_, err = s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{p}})
	require.NoError(t, err)
	ev := nextBestEvent(t, w)
	require.Len(t, ev.PathList, 1)
	assert.False(t, ev.PathList[0].IsWithdraw)
	assert.Equal(t, "10.90.0.0/24", ev.PathList[0].GetNlri().String())
	assert.Equal(t, map[uint32]bool{zebra.DefaultVrf: true}, ev.Vrf, "Zebra's VRFs of a global path")
	assert.False(t, ev.Timestamp.IsZero())
	msgs := locRibMessages(s, ev)
	require.Len(t, msgs, 1)
	require.Len(t, updateOf(t, msgs[0]).NLRI, 1)

	require.NoError(t, s.DeletePath(apiutil.DeletePathRequest{Paths: []*apiutil.Path{p}}))
	ev = nextBestEvent(t, w)
	require.Len(t, ev.PathList, 1)
	assert.True(t, ev.PathList[0].IsWithdraw)
	msgs = locRibMessages(s, ev)
	require.Len(t, msgs, 1)
	assert.Len(t, updateOf(t, msgs[0]).WithdrawnRoutes, 1)
	assert.Empty(t, w.Event())
}

// TestBestPathWatcherMultipathAndDeltas checks the event of a server with
// multiple paths: the sets of paths, and the deltas, which BMP prefers, as
// the watcher passes them on.
func TestBestPathWatcherMultipathAndDeltas(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 1, RouterId: "1.1.1.1", ListenPort: -1, UseMultiplePaths: true},
	}))
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	w, err := s.watch(WatchBestPath(false))
	require.NoError(t, err)
	defer w.Stop()

	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.91.0.0/24"))
	require.NoError(t, err)
	a := consumerTablePath(t, nlri, "192.0.2.1", false)
	b := consumerTablePath(t, nlri, "192.0.2.2", false)
	gone := consumerTablePath(t, nlri, "192.0.2.3", true)

	// A multipath set and no delta: BMP writes the set.
	notifyBestLists(s, []*table.Path{a}, [][]*table.Path{{a, b}}, nil, nil)
	ev := nextBestEvent(t, w)
	require.Len(t, ev.PathList, 1)
	require.Len(t, ev.MultiPathList, 1)
	require.Len(t, ev.MultiPathList[0], 2)
	assert.Empty(t, ev.UpdatePathList)
	assert.Empty(t, ev.WithdrawPathList)
	assert.Len(t, locRIBPathsForBMP(ev), 2)
	assert.Len(t, locRibMessages(s, ev), 2)
	assert.Equal(t, map[uint32]bool{zebra.DefaultVrf: true}, ev.Vrf)

	// With deltas, BMP writes the withdrawals and then the updates, not the set.
	notifyBestLists(s, []*table.Path{a}, [][]*table.Path{{a}}, []*table.Path{a}, []*table.Path{gone})
	ev = nextBestEvent(t, w)
	paths := locRIBPathsForBMP(ev)
	require.Len(t, paths, 2)
	assert.True(t, paths[0].IsWithdraw, "the withdrawals come first")
	assert.False(t, paths[1].IsWithdraw)
	assert.Len(t, locRibMessages(s, ev), 2)
	assert.Empty(t, w.Event())
}

// TestBestPathWatcherVrfs checks the VRFs a VPN best path is imported into,
// which the Zebra client sends the route for.
func TestBestPathWatcherVrfs(t *testing.T) {
	s := runNewServer(t, 1, "1.1.1.1", -1)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
	addVrf(t, s, "red", "100:100", []string{"100:100"}, []string{"100:100"}, 5)
	addVrf(t, s, "blue", "200:200", []string{"200:200"}, []string{"200:200"}, 6)
	w, err := s.watch(WatchBestPath(false))
	require.NoError(t, err)
	defer w.Stop()

	rd, err := bgp.ParseRouteDistinguisher("100:100")
	require.NoError(t, err)
	nlri, err := bgp.NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix("10.92.0.0/24"), *bgp.NewMPLSLabelStack(100), rd)
	require.NoError(t, err)
	rt, err := bgp.ParseExtendedCommunity(bgp.EC_SUBTYPE_ROUTE_TARGET, "100:100")
	require.NoError(t, err)
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh, bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{rt})}
	src := &table.PeerInfo{AS: 65001, Address: netip.MustParseAddr("192.0.2.1"), ID: netip.MustParseAddr("192.0.2.1")}
	path := table.NewPath(bgp.RF_IPv4_VPN, src, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)

	notifyBestLists(s, []*table.Path{path}, nil, nil, nil)
	ev := nextBestEvent(t, w)
	assert.Equal(t, map[uint32]bool{5: true}, ev.Vrf, "the VRF the path imports into")
	require.Len(t, ev.PathList, 1)
}
