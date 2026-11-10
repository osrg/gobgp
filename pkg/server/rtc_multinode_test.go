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

func setRTCClientTestExportPolicy(t *testing.T, s *BgpServer, target *peer, rejectedSource string) {
	t.Helper()
	require.NoError(t, s.policy.Reset(&oc.RoutingPolicy{PolicyDefinitions: []oc.PolicyDefinition{{
		Name: "rtc-source-export",
		Statements: []oc.Statement{{
			Name: "reject-source",
			Conditions: oc.Conditions{BgpConditions: oc.BgpConditions{
				NextHopInList: []netip.Addr{netip.MustParseAddr(rejectedSource)},
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
