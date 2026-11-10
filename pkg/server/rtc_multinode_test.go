package server

import (
	"context"
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	oc "github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// An RR client must learn another client's interest when its own membership is
// global best, rather than receiving only its own reflected cluster.
func TestRTCClientReceivesOtherClientMembership(t *testing.T) {
	s, _, target := newRTCPropagationTestServer(t)
	configureRTCClientTestPeer(target)
	other := newRTCClientTestPeer(t, s, "10.0.0.3")
	own := rtcClientTestPath(t, target, 0, "4.96.1.7", "4.96.1.0")
	remote := rtcClientTestPath(t, other, 100, "4.96.2.7", "4.96.2.0")
	s.globalRib.Update(own)
	s.propagateUpdate(other, []*table.Path{remote})
	requireRTCClientTestPath(t, target, "10.0.0.3", 100, "4.96.2.0")
	// Export attribute rewriting must not mutate the retained subscriber path.
	require.Equal(t, netip.MustParseAddr("4.96.2.7"), remote.GetOriginatorID())
	require.Equal(t, netip.MustParseAddr("10.0.0.3"), remote.GetNexthop())
	require.Equal(t, []netip.Addr{netip.MustParseAddr("4.96.2.0")}, remote.GetClusterList())
}

// A looping first alternative must not hide the later exportable subscriber.
func TestRTCClientSkipsIneligibleRemoteMembership(t *testing.T) {
	s, _, target := newRTCPropagationTestServer(t)
	configureRTCClientTestPeer(target)
	first := newRTCClientTestPeer(t, s, "10.0.0.3")
	later := newRTCClientTestPeer(t, s, "10.0.0.4")
	looping := rtcClientTestPath(t, first, 100, "4.96.2.7", "0.0.35.0")
	usable := rtcClientTestPath(t, later, 200, "4.96.3.7", "4.96.3.0")
	s.globalRib.Update(looping)
	require.Nil(t, s.filterpath(target, looping, nil), "the first alternative must fail reflection eligibility")
	s.propagateUpdate(later, []*table.Path{usable})
	requireRTCClientTestPath(t, target, "10.0.0.4", 200, "4.96.3.0")
}

// Policy sees the source's original next hop, before RFC 4684 rewrites it for
// this session; rejecting that source must leave the later subscriber usable.
func TestRTCClientSkipsExportPolicyRejectedMembership(t *testing.T) {
	s, _, target := newRTCPropagationTestServer(t)
	configureRTCClientTestPeer(target)
	first := newRTCClientTestPeer(t, s, "10.0.0.3")
	later := newRTCClientTestPeer(t, s, "10.0.0.4")
	setRTCClientTestExportPolicy(t, s, target, "10.0.0.3")
	rejected := rtcClientTestPath(t, first, 100, "4.96.2.7", "4.96.2.0")
	usable := rtcClientTestPath(t, later, 200, "4.96.3.7", "4.96.3.0")
	s.globalRib.Update(rejected)
	require.Nil(t, s.filterpath(target, rejected, nil), "the first alternative must fail source-specific export policy")
	// The accepting action also adds MED. Exactly one application is required.
	s.propagateUpdate(later, []*table.Path{usable})
	requireRTCClientTestPath(t, target, "10.0.0.4", 207, "4.96.3.0")
}

func TestRTCClientSelectionFallback(t *testing.T) {
	for _, scenario := range []string{"own membership only", "looping alternative", "policy rejected alternative", "different tenant alternative", "unreachable alternative"} {
		t.Run(scenario, func(t *testing.T) {
			s, _, target := newRTCPropagationTestServer(t)
			configureRTCClientTestPeer(target)
			own := rtcClientTestPath(t, target, 0, "4.96.1.7", "4.96.1.0")
			wantMed := uint32(0)
			if scenario != "own membership only" {
				other := newRTCClientTestPeer(t, s, "10.0.0.3")
				cluster := "4.96.2.0"
				if scenario == "looping alternative" {
					cluster = "0.0.35.0"
				}
				remote := rtcClientTestPath(t, other, 100, "4.96.2.7", cluster)
				if scenario == "policy rejected alternative" {
					setRTCClientTestExportPolicy(t, s, target, "10.0.0.3")
					wantMed = 7
				}
				if scenario == "different tenant alternative" {
					remote = table.NewPath(bgp.RF_RTC_UC, other.peerInfo.Load(), bgp.PathNLRI{NLRI: bgp.NewRouteTargetMembershipNLRI(25046,
						bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 32106, 200, true))}, false,
						remote.GetPathAttrs(), time.Now(), false)
				}
				if scenario == "unreachable alternative" {
					cache := nexthopStateCache{netip.MustParseAddr("10.0.0.3"): math.MaxUint32}
					invalid := cache.applyToPathList([]*table.Path{remote})
					require.Len(t, invalid, 1)
					remote = invalid[0]
				}
				s.globalRib.Update(remote)
			}
			s.propagateUpdate(nil, []*table.Path{own})
			requireRTCClientTestPath(t, target, "10.0.0.2", wantMed, "4.96.1.0")
		})
	}
}

// Negotiated RTC ADD-PATH SEND must keep exporting the individual input path.
func TestRTCClientAddPathKeepsPerPathExport(t *testing.T) {
	s, _, target := newRTCPropagationTestServer(t)
	configureRTCClientTestPeer(target)
	c := target.fsm.pConf.ReadCopy()
	c.AfiSafis = append(c.AfiSafis, oc.AfiSafi{
		State:    oc.AfiSafiState{Family: bgp.RF_RTC_UC},
		AddPaths: oc.AddPaths{Config: oc.AddPathsConfig{SendMax: 3}},
	})
	target.fsm.pConf.Update(&c)
	target.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_RTC_UC: bgp.BGP_ADD_PATH_SEND})
	first := newRTCClientTestPeer(t, s, "10.0.0.3")
	later := newRTCClientTestPeer(t, s, "10.0.0.4")
	s.globalRib.Update(rtcClientTestPath(t, first, 100, "4.96.2.7", "4.96.2.0"))
	s.propagateUpdate(later, []*table.Path{rtcClientTestPath(t, later, 200, "4.96.3.7", "4.96.3.0")})
	requireRTCClientTestPath(t, target, "10.0.0.4", 200, "4.96.3.0")
}

func TestRTCClientSelectionWithoutRetainedDestination(t *testing.T) {
	s, _, target := newRTCPropagationTestServer(t)
	configureRTCClientTestPeer(target)
	other := newRTCClientTestPeer(t, s, "10.0.0.3")
	p := rtcClientTestPath(t, other, 100, "4.96.2.7", "4.96.2.0")
	require.Nil(t, s.globalRib.GetDestination(p))
	paths := s.processOutgoingPaths(target, []*table.Path{p}, nil)
	require.Len(t, paths, 1)
	require.Equal(t, "25046:32106:100/96", paths[0].GetNlri().String())
	require.Equal(t, netip.MustParseAddr("10.0.0.3"), paths[0].GetSource().Address)
	require.False(t, paths[0].IsWithdraw)
	require.Equal(t, netip.MustParseAddr("0.0.35.1"), paths[0].GetOriginatorID())
	require.Equal(t, netip.MustParseAddr("1.1.1.1"), paths[0].GetNexthop())
	require.Equal(t, []netip.Addr{netip.MustParseAddr("0.0.35.0"), netip.MustParseAddr("4.96.2.0")}, paths[0].GetClusterList())
}

func configureRTCClientTestPeer(p *peer) {
	c := p.fsm.pConf.ReadCopy()
	c.RouteReflector.Config.RouteReflectorClient = true
	c.RouteReflector.State.RouteReflectorClient = true
	c.RouteReflector.State.RouteReflectorClusterId = netip.MustParseAddr("0.0.35.0")
	p.fsm.pConf.Update(&c)
	info := *p.peerInfo.Load()
	info.RouteReflectorClient = true
	info.RouteReflectorClusterID = netip.MustParseAddr("0.0.35.0")
	info.LocalID = netip.MustParseAddr("0.0.35.1")
	info.PeerType = oc.PEER_TYPE_INTERNAL
	p.peerInfo.Store(&info)
}

func newRTCClientTestPeer(t *testing.T, s *BgpServer, address string) *peer {
	t.Helper()
	p := newPeerandInfo(t, 25046, 25046, address, s.globalRib)
	t.Cleanup(func() { cleanInfiniteChannel(p.fsm.outgoingCh) })
	p.policy = s.policy
	configureRTCClientTestPeer(p)
	return p
}

func rtcClientTestPath(t *testing.T, source *peer, med uint32, origin, cluster string) *table.Path {
	t.Helper()
	p := rtcPropagationTestPath(t, source, med)
	id, err := bgp.NewPathAttributeOriginatorId(netip.MustParseAddr(origin))
	require.NoError(t, err)
	cl, err := bgp.NewPathAttributeClusterList([]netip.Addr{netip.MustParseAddr(cluster)})
	require.NoError(t, err)
	nh, err := bgp.NewPathAttributeNextHop(source.peerInfo.Load().Address)
	require.NoError(t, err)
	attrs := append(p.GetPathAttrs(), nh, id, cl)
	return table.NewPath(bgp.RF_RTC_UC, source.peerInfo.Load(), bgp.PathNLRI{NLRI: p.GetNlri()}, false, attrs, time.Now(), false)
}

func setRTCClientTestExportPolicy(t *testing.T, s *BgpServer, target *peer, rejectedSources ...string) {
	t.Helper()
	rejected := make([]netip.Addr, 0, len(rejectedSources))
	for _, source := range rejectedSources {
		rejected = append(rejected, netip.MustParseAddr(source))
	}
	require.NoError(t, s.policy.Reset(&oc.RoutingPolicy{PolicyDefinitions: []oc.PolicyDefinition{{
		Name: "rtc-source-export",
		Statements: []oc.Statement{{
			Name: "reject-source",
			Conditions: oc.Conditions{BgpConditions: oc.BgpConditions{
				NextHopInList: rejected,
			}},
			Actions: oc.Actions{RouteDisposition: oc.ROUTE_DISPOSITION_REJECT_ROUTE},
		}, {
			Name: "accept-once",
			Actions: oc.Actions{
				RouteDisposition: oc.ROUTE_DISPOSITION_ACCEPT_ROUTE,
				BgpActions:       oc.BgpActions{SetMed: "+7"},
			},
		}},
	}}}, nil))
	require.NoError(t, s.policy.SetPeerPolicy(target.exportPolicyID, oc.ApplyPolicy{Config: oc.ApplyPolicyConfig{
		ExportPolicyList: []string{"rtc-source-export"},
	}}))
}

func requireRTCClientTestPath(t *testing.T, target *peer, source string, med uint32, cluster string) {
	t.Helper()
	p := requireRTCPropagationTestPath(t, target, bgp.RF_RTC_UC, "25046:32106:100/96", source, med, false)
	require.Equal(t, netip.MustParseAddr("0.0.35.1"), p.GetOriginatorID())
	require.Equal(t, netip.MustParseAddr("1.1.1.1"), p.GetNexthop())
	require.Equal(t, []netip.Addr{netip.MustParseAddr("0.0.35.0"), netip.MustParseAddr(cluster)}, p.GetClusterList())
}

// Replaying a learned membership must not enqueue another reflected UPDATE.
func TestRTCRepeatedLearnedMembershipDoesNotReflect(t *testing.T) {
	s, source, target := newRTCPropagationTestServer(t)
	p := rtcPropagationTestPath(t, source, 0)
	s.propagateUpdate(source, []*table.Path{p})
	requireRTCPropagationTestPath(t, target, bgp.RF_RTC_UC, "25046:32106:100/96", "10.0.0.1", 0, false)

	s.propagateUpdate(source, []*table.Path{p.Clone(false)})
	requireNoRTCPropagationTestMessage(t, target)
}

// A cached next-hop update changes reachability without changing attributes.
// The internal update boundary must reflect the resulting selection and recovery.
func TestRTCCachedNexthopChangesPropagate(t *testing.T) {
	s, source, target := newRTCPropagationTestServer(t)
	p := rtcPropagationTestPath(t, source, 0)
	s.propagateUpdate(source, []*table.Path{p})
	requireRTCPropagationTestPath(t, target, bgp.RF_RTC_UC, "25046:32106:100/96", "10.0.0.1", 0, false)

	other := newPeerandInfo(t, 25046, 65001, "10.0.0.3", s.globalRib)
	t.Cleanup(func() { cleanInfiniteChannel(other.fsm.outgoingCh) })
	other.policy = s.policy
	s.propagateUpdate(other, []*table.Path{rtcPropagationTestPath(t, other, 100)})
	requireRTCPropagationTestPath(t, target, bgp.RF_RTC_UC, "25046:32106:100/96", "10.0.0.1", 0, false)

	cache := nexthopStateCache{netip.MustParseAddr("10.0.0.1"): math.MaxUint32}
	invalid := cache.applyToPathList([]*table.Path{p})
	require.Len(t, invalid, 1)
	require.NoError(t, s.updatePath("", invalid))
	best := s.globalRib.GetDestination(p).GetBestPath(table.GLOBAL_RIB_NAME, 0)
	require.NotNil(t, best)
	require.Equal(t, netip.MustParseAddr("10.0.0.3"), best.GetSource().Address)
	requireRTCPropagationTestPath(t, target, bgp.RF_RTC_UC, "25046:32106:100/96", "10.0.0.3", 100, false)

	cache[netip.MustParseAddr("10.0.0.1")] = 0
	recovered := cache.applyToPathList(invalid)
	require.Len(t, recovered, 1)
	require.NoError(t, s.updatePath("", recovered))
	best = s.globalRib.GetDestination(p).GetBestPath(table.GLOBAL_RIB_NAME, 0)
	require.NotNil(t, best)
	require.Equal(t, netip.MustParseAddr("10.0.0.1"), best.GetSource().Address)
	requireRTCPropagationTestPath(t, target, bgp.RF_RTC_UC, "25046:32106:100/96", "10.0.0.1", 0, false)
}

func TestRTCRealMembershipChangesPropagate(t *testing.T) {
	t.Run("new source with unchanged best", func(t *testing.T) {
		s, source, target := newRTCPropagationTestServer(t)
		p := rtcPropagationTestPath(t, source, 0)
		s.propagateUpdate(source, []*table.Path{p})
		requireRTCPropagationTestPath(t, target, bgp.RF_RTC_UC, "25046:32106:100/96", "10.0.0.1", 0, false)

		other := newPeerandInfo(t, 25046, 65001, "10.0.0.3", s.globalRib)
		t.Cleanup(func() { cleanInfiniteChannel(other.fsm.outgoingCh) })
		other.policy = s.policy
		s.propagateUpdate(other, []*table.Path{rtcPropagationTestPath(t, other, 100)})
		// RTC considers every source even when the selected best is unchanged.
		requireRTCPropagationTestPath(t, target, bgp.RF_RTC_UC, "25046:32106:100/96", "10.0.0.1", 0, false)
		known := s.globalRib.GetDestination(p).GetKnownPathList(table.GLOBAL_RIB_NAME, 0)
		require.Len(t, known, 2)
		require.Equal(t, netip.MustParseAddr("10.0.0.3"), known[1].GetSource().Address)
	})

	t.Run("attribute replacement", func(t *testing.T) {
		s, source, target := newRTCPropagationTestServer(t)
		s.propagateUpdate(source, []*table.Path{rtcPropagationTestPath(t, source, 0)})
		requireRTCPropagationTestPath(t, target, bgp.RF_RTC_UC, "25046:32106:100/96", "10.0.0.1", 0, false)

		s.propagateUpdate(source, []*table.Path{rtcPropagationTestPath(t, source, 100)})
		requireRTCPropagationTestPath(t, target, bgp.RF_RTC_UC, "25046:32106:100/96", "10.0.0.1", 100, false)
	})

	t.Run("matched withdrawal", func(t *testing.T) {
		s, source, target := newRTCPropagationTestServer(t)
		p := rtcPropagationTestPath(t, source, 0)
		s.propagateUpdate(source, []*table.Path{p})
		requireRTCPropagationTestPath(t, target, bgp.RF_RTC_UC, "25046:32106:100/96", "10.0.0.1", 0, false)

		s.propagateUpdate(source, []*table.Path{p.Clone(true)})
		requireRTCPropagationTestPath(t, target, bgp.RF_RTC_UC, "25046:32106:100/96", "10.0.0.1", 0, true)
		require.Empty(t, s.globalRib.GetDestination(p).GetKnownPathList(table.GLOBAL_RIB_NAME, 0))
	})
}

// An RTC-only guard must preserve the existing IPv4 ADD-PATH replay behavior.
func TestNonRTCUpdatesStillPropagate(t *testing.T) {
	s, source, target := newRTCPropagationTestServer(t)
	c := target.fsm.pConf.ReadCopy()
	for i := range c.AfiSafis {
		if c.AfiSafis[i].State.Family == bgp.RF_IPv4_UC {
			c.AfiSafis[i].AddPaths.Config.SendMax = 2
		}
	}
	target.fsm.pConf.Update(&c)
	target.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_SEND})
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("192.0.2.0/24"))
	require.NoError(t, err)
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	require.NoError(t, err)
	p := table.NewPath(bgp.RF_IPv4_UC, source.peerInfo.Load(), bgp.PathNLRI{NLRI: nlri}, false,
		[]bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh, bgp.NewPathAttributeMultiExitDisc(0)}, time.Now(), false)
	s.propagateUpdate(source, []*table.Path{p})
	requireRTCPropagationTestPath(t, target, bgp.RF_IPv4_UC, "192.0.2.0/24", "10.0.0.1", 0, false)
	s.propagateUpdate(source, []*table.Path{p.Clone(false)})
	requireRTCPropagationTestPath(t, target, bgp.RF_IPv4_UC, "192.0.2.0/24", "10.0.0.1", 0, false)
	s.propagateUpdate(source, []*table.Path{p.Clone(true)})
	requireRTCPropagationTestPath(t, target, bgp.RF_IPv4_UC, "192.0.2.0/24", "10.0.0.1", 0, true)
}

func newRTCPropagationTestServer(t *testing.T) (*BgpServer, *peer, *peer) {
	t.Helper()
	s := NewBgpServer()
	go s.Serve()
	t.Cleanup(s.Stop)
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 25046, RouterId: "0.0.35.1", ListenPort: -1},
	}))
	source := newPeerandInfo(t, 25046, 65001, "10.0.0.1", s.globalRib)
	t.Cleanup(func() { cleanInfiniteChannel(source.fsm.outgoingCh) })
	target := newPeerandInfo(t, 25046, 25046, "10.0.0.2", s.globalRib)
	t.Cleanup(func() { cleanInfiniteChannel(target.fsm.outgoingCh) })
	source.policy = s.policy
	target.policy = s.policy
	c := target.fsm.pConf.ReadCopy()
	c.RouteReflector.Config.RouteReflectorClient = true
	c.RouteReflector.State.RouteReflectorClient = true
	c.RouteReflector.State.RouteReflectorClusterId = netip.MustParseAddr("0.0.35.0")
	target.fsm.pConf.Update(&c)
	info := *target.peerInfo.Load()
	info.RouteReflectorClient = true
	info.RouteReflectorClusterID = netip.MustParseAddr("0.0.35.0")
	target.peerInfo.Store(&info)
	target.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
	target.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_RTC_UC: bgp.BGP_ADD_PATH_NONE})
	require.NoError(t, s.mgmtOperation(func() error {
		s.neighborMap[target.peerInfo.Load().Address] = target
		return nil
	}, true))
	t.Cleanup(func() {
		require.NoError(t, s.mgmtOperation(func() error {
			delete(s.neighborMap, target.peerInfo.Load().Address)
			return nil
		}, false))
	})
	return s, source, target
}

func rtcPropagationTestPath(t *testing.T, source *peer, med uint32) *table.Path {
	t.Helper()
	rt := bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 32106, 100, true)
	nh, err := bgp.NewPathAttributeNextHop(source.peerInfo.Load().Address)
	require.NoError(t, err)
	return table.NewPath(bgp.RF_RTC_UC, source.peerInfo.Load(),
		bgp.PathNLRI{NLRI: bgp.NewRouteTargetMembershipNLRI(25046, rt)}, false,
		[]bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh, bgp.NewPathAttributeMultiExitDisc(med)}, time.Now(), false)
}

func requireRTCPropagationTestPath(t *testing.T, target *peer, family bgp.Family, nlri, source string, med uint32, withdraw bool) *table.Path {
	t.Helper()
	select {
	case outgoing := <-target.fsm.outgoingCh.Out():
		msg, ok := outgoing.(*fsmOutgoingMsg)
		require.True(t, ok, "expected a reflected path message, got %T", outgoing)
		require.Len(t, msg.Paths, 1)
		p := msg.Paths[0]
		require.Equal(t, family, p.GetFamily())
		require.Equal(t, nlri, p.GetNlri().String())
		require.Equal(t, netip.MustParseAddr(source), p.GetSource().Address)
		require.Equal(t, withdraw, p.IsWithdraw)
		gotMed, err := p.GetMed()
		require.NoError(t, err)
		require.Equal(t, med, gotMed)
		return p
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the propagated path")
	}
	return nil
}

func requireNoRTCPropagationTestMessage(t *testing.T, target *peer) {
	t.Helper()
	select {
	case outgoing := <-target.fsm.outgoingCh.Out():
		t.Fatalf("unchanged learned membership was reflected again: %#v", outgoing)
	case <-time.After(200 * time.Millisecond):
	}
}

// The global best may remain a non-client while a client is the actual export.
// Losing that client must withdraw its session export, not silently filter best.
func TestRTCWithdrawAdvertisedClientWhenOnlyNonClientRemains(t *testing.T) {
	s, _, target := newRTCPropagationTestServer(t)
	configureRTCNonClientTestPeer(target)
	client := newRTCClientTestPeer(t, s, "10.0.0.3")
	nonClient := newRTCClientTestPeer(t, s, "10.0.0.4")
	configureRTCNonClientTestPeer(nonClient)
	advertised := rtcClientTestPath(t, client, 100, "4.96.2.7", "4.96.2.0")
	remaining := rtcClientTestPath(t, nonClient, 0, "4.96.3.7", "4.96.3.0")
	s.propagateUpdate(client, []*table.Path{advertised})
	requireRTCPropagationTestPath(t, target, bgp.RF_RTC_UC, "25046:32106:100/96", "10.0.0.3", 100, false)
	s.propagateUpdate(nonClient, []*table.Path{remaining})
	sent := requireRTCPropagationTestPath(t, target, bgp.RF_RTC_UC, "25046:32106:100/96", "10.0.0.3", 100, false)
	require.Equal(t, 1, target.advertisedRoutes([]bgp.Family{bgp.RF_RTC_UC}))
	s.propagateUpdate(client, []*table.Path{advertised.Clone(true)})
	withdrawn := requireRTCPropagationTestPath(t, target, bgp.RF_RTC_UC, "25046:32106:100/96", "10.0.0.3", 100, true)
	require.Equal(t, sent.GetOriginatorID(), withdrawn.GetOriginatorID())
	require.Equal(t, sent.GetClusterList(), withdrawn.GetClusterList())
	require.Equal(t, 0, target.advertisedRoutes([]bgp.Family{bgp.RF_RTC_UC}))
	s.propagateUpdate(nonClient, []*table.Path{rtcClientTestPath(t, nonClient, 50, "4.96.3.7", "4.96.3.0")})
	requireNoRTCPropagationTestMessage(t, target)
}

// A rejected old global best cannot stand in for the accepted session export.
func TestRTCExportPolicyRejectWithdrawsPreviouslySentMembership(t *testing.T) {
	s, _, target := newRTCPropagationTestServer(t)
	configureRTCClientTestPeer(target)
	other := newRTCClientTestPeer(t, s, "10.0.0.3")
	own := rtcClientTestPath(t, target, 0, "4.96.1.7", "4.96.1.0")
	remote := rtcClientTestPath(t, other, 100, "4.96.2.7", "4.96.2.0")
	s.globalRib.Update(own)
	setRTCClientTestExportPolicy(t, s, target, "10.0.0.99")
	s.propagateUpdate(other, []*table.Path{remote})
	requireRTCClientTestPath(t, target, "10.0.0.3", 107, "4.96.2.0")
	setRTCClientTestExportPolicy(t, s, target, "10.0.0.2", "10.0.0.3")
	require.Nil(t, s.filterpathWithPolicy(target, own, nil), "unrelated old global best must also be rejected")
	require.Nil(t, s.filterpathWithPolicy(target, remote, nil), "previously sent source must now be rejected")
	s.propagateUpdate(other, []*table.Path{rtcClientTestPath(t, other, 200, "4.96.2.7", "4.96.2.0")})
	withdrawn := requireRTCPropagationTestPath(t, target, bgp.RF_RTC_UC, "25046:32106:100/96", "10.0.0.3", 107, true)
	require.Equal(t, netip.MustParseAddr("0.0.35.1"), withdrawn.GetOriginatorID())
	require.Equal(t, netip.MustParseAddr("1.1.1.1"), withdrawn.GetNexthop())
	requireRTCWireTestPathID(t, target, withdrawn, 0)
	require.Equal(t, 0, target.advertisedRoutes([]bgp.Family{bgp.RF_RTC_UC}))
	s.propagateUpdate(other, []*table.Path{rtcClientTestPath(t, other, 300, "4.96.2.7", "4.96.2.0")})
	requireNoRTCPropagationTestMessage(t, target)
}

// Reset must remove old-session exports; soft reset replay must record the
// current, once-transformed export so a subsequent rejection withdraws it.
func TestRTCResetClearsAdvertisedMembership(t *testing.T) {
	s, _, target := newRTCPropagationTestServer(t)
	configureRTCClientTestPeer(target)
	other := newRTCClientTestPeer(t, s, "10.0.0.3")
	initial := rtcClientTestPath(t, other, 100, "4.96.2.7", "4.96.2.0")
	s.propagateUpdate(other, []*table.Path{initial})
	requireRTCClientTestPath(t, target, "10.0.0.3", 100, "4.96.2.0")
	target.fsm.state.Store(bgp.BGP_FSM_ACTIVE)
	s.resetAdvertisedRoutes(target)
	require.Equal(t, 0, target.advertisedRoutes([]bgp.Family{bgp.RF_RTC_UC}))
	setRTCClientTestExportPolicy(t, s, target, "10.0.0.3")
	current := rtcClientTestPath(t, other, 200, "4.96.3.7", "4.96.3.0")
	s.propagateUpdate(other, []*table.Path{current})
	target.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
	s.propagateUpdate(other, []*table.Path{rtcClientTestPath(t, other, 201, "4.96.3.7", "4.96.3.0")})
	requireNoRTCPropagationTestMessage(t, target)
	setRTCClientTestExportPolicy(t, s, target, "10.0.0.99")
	s.softResetOutPeer(target, bgp.RF_RTC_UC, false)
	// RTC replay includes its EOR in the same actual outgoing message.
	select {
	case outgoing := <-target.fsm.outgoingCh.Out():
		msg, ok := outgoing.(*fsmOutgoingMsg)
		require.True(t, ok)
		require.Len(t, msg.Paths, 2)
		replay := msg.Paths[0]
		require.False(t, replay.IsWithdraw)
		require.Equal(t, netip.MustParseAddr("10.0.0.3"), replay.GetSource().Address)
		med, err := replay.GetMed()
		require.NoError(t, err)
		require.Equal(t, uint32(208), med)
		require.Equal(t, []netip.Addr{netip.MustParseAddr("0.0.35.0"), netip.MustParseAddr("4.96.3.0")}, replay.GetClusterList())
		require.True(t, msg.Paths[1].IsEOR())
		requireRTCWireTestPathID(t, target, replay, 0)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for RTC replay")
	}
	require.Equal(t, 1, target.advertisedRoutes([]bgp.Family{bgp.RF_RTC_UC}))
	setRTCClientTestExportPolicy(t, s, target, "10.0.0.3")
	s.propagateUpdate(other, []*table.Path{rtcClientTestPath(t, other, 202, "4.96.3.7", "4.96.3.0")})
	withdrawn := requireRTCPropagationTestPath(t, target, bgp.RF_RTC_UC, "25046:32106:100/96", "10.0.0.3", 208, true)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("0.0.35.0"), netip.MustParseAddr("4.96.3.0")}, withdrawn.GetClusterList())
	require.Equal(t, 0, target.advertisedRoutes([]bgp.Family{bgp.RF_RTC_UC}))
}

// RECEIVE-only still exports one path. Distinct received path IDs from the
// same source must reselect and finally withdraw the actual replacement.
func TestRTCReceiveOnlyAddPathReselectsAdvertisedMembership(t *testing.T) {
	s, _, target := newRTCPropagationTestServer(t)
	configureRTCClientTestPeer(target)
	target.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_RTC_UC: bgp.BGP_ADD_PATH_RECEIVE})
	loopingSource := newRTCClientTestPeer(t, s, "10.0.0.3")
	source := newRTCClientTestPeer(t, s, "10.0.0.4")
	looping := rtcClientTestPath(t, loopingSource, 0, "4.96.2.7", "0.0.35.0")
	s.globalRib.Update(looping)
	first := rtcClientTestPathWithID(t, source, 100, "4.96.3.7", "4.96.3.0", 11)
	second := rtcClientTestPathWithID(t, source, 200, "4.96.4.7", "4.96.4.0", 22)
	s.propagateUpdate(source, []*table.Path{first})
	sentFirst := requireRTCPropagationTestPath(t, target, bgp.RF_RTC_UC, "25046:32106:100/96", "10.0.0.4", 100, false)
	require.Equal(t, uint32(11), sentFirst.RemoteID())
	requireRTCWireTestPathID(t, target, sentFirst, 0)
	s.propagateUpdate(source, []*table.Path{second})
	requireRTCPropagationTestPath(t, target, bgp.RF_RTC_UC, "25046:32106:100/96", "10.0.0.4", 100, false)
	s.propagateUpdate(source, []*table.Path{first.Clone(true)})
	replacement := requireRTCPropagationTestPath(t, target, bgp.RF_RTC_UC, "25046:32106:100/96", "10.0.0.4", 200, false)
	require.Equal(t, uint32(22), replacement.RemoteID())
	require.NotEqual(t, sentFirst.LocalID(), replacement.LocalID())
	requireRTCWireTestPathID(t, target, replacement, 0)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("0.0.35.0"), netip.MustParseAddr("4.96.4.0")}, replacement.GetClusterList())
	require.Equal(t, 1, target.advertisedRoutes([]bgp.Family{bgp.RF_RTC_UC}))
	// Replace attributes on the same received path ID before its withdrawal.
	changed := rtcClientTestPathWithID(t, source, 250, "4.96.5.7", "4.96.5.0", 22)
	s.propagateUpdate(source, []*table.Path{changed})
	updated := requireRTCPropagationTestPath(t, target, bgp.RF_RTC_UC, "25046:32106:100/96", "10.0.0.4", 250, false)
	require.Equal(t, replacement.LocalID(), updated.LocalID())
	require.Equal(t, uint32(22), updated.RemoteID())
	s.propagateUpdate(source, []*table.Path{changed.Clone(true)})
	withdrawn := requireRTCPropagationTestPath(t, target, bgp.RF_RTC_UC, "25046:32106:100/96", "10.0.0.4", 250, true)
	require.Equal(t, updated.LocalID(), withdrawn.LocalID())
	require.Equal(t, uint32(22), withdrawn.RemoteID())
	require.Equal(t, []netip.Addr{netip.MustParseAddr("0.0.35.0"), netip.MustParseAddr("4.96.5.0")}, withdrawn.GetClusterList())
	requireRTCWireTestPathID(t, target, withdrawn, 0)
	require.Equal(t, 0, target.advertisedRoutes([]bgp.Family{bgp.RF_RTC_UC}))
}

// SEND ADD-PATH must retain two independent exports and withdraw only the
// matching path, preserving the remaining path's attributes and wire ID.
func TestRTCAddPathDoesNotUseSinglePathBookkeeping(t *testing.T) {
	s, _, target := newRTCPropagationTestServer(t)
	configureRTCClientTestPeer(target)
	c := target.fsm.pConf.ReadCopy()
	c.AfiSafis = append(c.AfiSafis, oc.AfiSafi{
		State:    oc.AfiSafiState{Family: bgp.RF_RTC_UC},
		AddPaths: oc.AddPaths{Config: oc.AddPathsConfig{SendMax: 3}},
	})
	target.fsm.pConf.Update(&c)
	target.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_RTC_UC: bgp.BGP_ADD_PATH_SEND})
	source := newRTCClientTestPeer(t, s, "10.0.0.3")
	first := rtcClientTestPathWithID(t, source, 100, "4.96.2.7", "4.96.2.0", 11)
	second := rtcClientTestPathWithID(t, source, 200, "4.96.3.7", "4.96.3.0", 22)
	s.propagateUpdate(source, []*table.Path{first})
	sentFirst := requireRTCPropagationTestPath(t, target, bgp.RF_RTC_UC, "25046:32106:100/96", "10.0.0.3", 100, false)
	s.propagateUpdate(source, []*table.Path{second})
	sentSecond := requireRTCPropagationTestPath(t, target, bgp.RF_RTC_UC, "25046:32106:100/96", "10.0.0.3", 200, false)
	require.NotZero(t, sentFirst.LocalID())
	require.NotZero(t, sentSecond.LocalID())
	require.NotEqual(t, sentFirst.LocalID(), sentSecond.LocalID())
	requireRTCWireTestPathID(t, target, sentFirst, sentFirst.LocalID())
	requireRTCWireTestPathID(t, target, sentSecond, sentSecond.LocalID())
	require.Equal(t, 2, target.advertisedRoutes([]bgp.Family{bgp.RF_RTC_UC}))
	s.propagateUpdate(source, []*table.Path{first.Clone(true)})
	withdrawn := requireRTCPropagationTestPath(t, target, bgp.RF_RTC_UC, "25046:32106:100/96", "10.0.0.3", 100, true)
	require.Equal(t, sentFirst.LocalID(), withdrawn.LocalID())
	require.Equal(t, uint32(11), withdrawn.RemoteID())
	requireRTCWireTestPathID(t, target, withdrawn, sentFirst.LocalID())
	require.Equal(t, 1, target.advertisedRoutes([]bgp.Family{bgp.RF_RTC_UC}))
	s.propagateUpdate(source, []*table.Path{rtcClientTestPathWithID(t, source, 250, "4.96.4.7", "4.96.4.0", 22)})
	updated := requireRTCPropagationTestPath(t, target, bgp.RF_RTC_UC, "25046:32106:100/96", "10.0.0.3", 250, false)
	require.Equal(t, sentSecond.LocalID(), updated.LocalID())
	require.Equal(t, uint32(22), updated.RemoteID())
	requireRTCWireTestPathID(t, target, updated, sentSecond.LocalID())
	require.Equal(t, []netip.Addr{netip.MustParseAddr("0.0.35.0"), netip.MustParseAddr("4.96.4.0")}, updated.GetClusterList())
}

func configureRTCNonClientTestPeer(p *peer) {
	c := p.fsm.pConf.ReadCopy()
	c.RouteReflector.Config.RouteReflectorClient = false
	c.RouteReflector.State.RouteReflectorClient = false
	p.fsm.pConf.Update(&c)
	info := *p.peerInfo.Load()
	info.RouteReflectorClient = false
	p.peerInfo.Store(&info)
}

func rtcClientTestPathWithID(t *testing.T, source *peer, med uint32, origin, cluster string, id uint32) *table.Path {
	t.Helper()
	p := rtcClientTestPath(t, source, med, origin, cluster)
	nh, err := bgp.NewPathAttributeNextHop(source.peerInfo.Load().Address)
	require.NoError(t, err)
	return table.NewPath(bgp.RF_RTC_UC, source.peerInfo.Load(), bgp.PathNLRI{NLRI: p.GetNlri(), ID: id}, false,
		append(p.GetPathAttrs(), nh), time.Now(), false)
}

// Exercise the same pack/serialize boundary as fsm.send with the negotiated
// outbound mode, then decode as the receiving session would see it.
func requireRTCWireTestPathID(t *testing.T, target *peer, path *table.Path, wantID uint32) {
	t.Helper()
	options := &bgp.MarshallingOption{AddPath: target.fsm.familyMap.Load().(map[bgp.Family]bgp.BGPAddPathMode)}
	msgs := table.CreateUpdateMsgFromPaths([]*table.Path{path}, options)
	require.Len(t, msgs, 1)
	data, err := msgs[0].Serialize(options)
	require.NoError(t, err)
	receiveMode := bgp.BGP_ADD_PATH_NONE
	if target.isAddPathSendEnabled(bgp.RF_RTC_UC) {
		receiveMode = bgp.BGP_ADD_PATH_RECEIVE
	}
	decoded, err := bgp.ParseBGPMessage(data, &bgp.MarshallingOption{AddPath: map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_RTC_UC: receiveMode}})
	require.NoError(t, err)
	var nlris []bgp.PathNLRI
	for _, attr := range decoded.Body.(*bgp.BGPUpdate).PathAttributes {
		switch a := attr.(type) {
		case *bgp.PathAttributeMpReachNLRI:
			require.False(t, path.IsWithdraw)
			nlris = a.Value
		case *bgp.PathAttributeMpUnreachNLRI:
			require.True(t, path.IsWithdraw)
			nlris = a.Value
		}
	}
	require.Len(t, nlris, 1)
	require.Equal(t, "25046:32106:100/96", nlris[0].NLRI.String())
	require.Equal(t, wantID, nlris[0].ID)
}
