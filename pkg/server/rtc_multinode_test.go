package server

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// Replaying a learned membership must not enqueue another reflected UPDATE.
func TestRTCRepeatedLearnedMembershipDoesNotReflect(t *testing.T) {
	s, source, target := newRTCPropagationTestServer(t)
	p := rtcPropagationTestPath(t, source, 0)
	s.propagateUpdate(source, []*table.Path{p})
	requireRTCPropagationTestPath(t, target, bgp.RF_RTC_UC, "25046:32106:100/96", "10.0.0.1", 0, false)

	s.propagateUpdate(source, []*table.Path{p.Clone(false)})
	requireNoRTCPropagationTestMessage(t, target)
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

func requireRTCPropagationTestPath(t *testing.T, target *peer, family bgp.Family, nlri, source string, med uint32, withdraw bool) {
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
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the propagated path")
	}
}

func requireNoRTCPropagationTestMessage(t *testing.T, target *peer) {
	t.Helper()
	select {
	case outgoing := <-target.fsm.outgoingCh.Out():
		t.Fatalf("unchanged learned membership was reflected again: %#v", outgoing)
	case <-time.After(200 * time.Millisecond):
	}
}
