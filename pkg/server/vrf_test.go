package server

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func vrfRT(v int) bgp.ExtendedCommunityInterface {
	return bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 65000, uint32(v), true)
}

func newVPNPathForTest(tb testing.TB, prefix netip.Prefix, rd bgp.RouteDistinguisherInterface, rts ...bgp.ExtendedCommunityInterface) *table.Path {
	tb.Helper()
	family, nexthop := bgp.RF_IPv4_VPN, netip.MustParseAddr("10.0.0.254")
	if prefix.Addr().Is6() {
		family, nexthop = bgp.RF_IPv6_VPN, netip.MustParseAddr("2001:db8:ff::254")
	}
	nlri, err := bgp.NewLabeledVPNIPAddrPrefix(prefix, *bgp.NewMPLSLabelStack(100), rd)
	require.NoError(tb, err)
	mpReach, err := bgp.NewPathAttributeMpReachNLRI(family, []bgp.PathNLRI{{NLRI: nlri}}, nexthop)
	require.NoError(tb, err)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		mpReach,
		bgp.NewPathAttributeExtendedCommunities(rts),
	}
	return table.NewPath(family, nil, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
}

// newVrfNeighbors returns a server with nVrf VRFs of routesPerVrf routes each
// (VRF v uses RD and RT 65000:v), and an established neighbor in each of the
// first nPeer VRFs.
func newVrfNeighbors(tb testing.TB, nVrf, nPeer, routesPerVrf int) (*BgpServer, []*peer) {
	tb.Helper()
	s := NewBgpServer()
	go s.Serve()
	require.NoError(tb, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 65001, RouterId: "1.1.1.1", ListenPort: -1},
	}))
	peers := make([]*peer, 0, nPeer)
	for v := range nVrf {
		name := fmt.Sprintf("vrf%d", v)
		rd := bgp.NewRouteDistinguisherTwoOctetAS(65000, uint32(v))
		rts := []bgp.ExtendedCommunityInterface{vrfRT(v)}
		require.NoError(tb, s.mgmtOperation(func() error {
			_, err := s.globalRib.AddVrf(name, uint32(v+1), rd, rts, rts, &table.PeerInfo{})
			return err
		}, true))
		if v >= nPeer {
			continue
		}
		addr := netip.AddrFrom4([4]byte{10, 0, byte(v >> 8), byte(v)})
		p := newPeerandInfo(tb, 65001, 65002, addr.String(), s.globalRib)
		p.policy = s.policy
		p.fsm.pConf.ReadOnly().Config.Vrf = name
		p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
		p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_NONE, bgp.RF_IPv6_UC: bgp.BGP_ADD_PATH_NONE})
		require.NoError(tb, s.mgmtOperation(func() error {
			s.neighborMap[addr] = p
			return nil
		}, true))
		peers = append(peers, p)
	}
	tb.Cleanup(func() {
		_ = s.mgmtOperation(func() error {
			clear(s.neighborMap)
			return nil
		}, false)
		for _, p := range peers {
			cleanInfiniteChannel(p.fsm.outgoingCh)
		}
		_ = s.StopBgp(context.Background(), &api.StopBgpRequest{})
	})

	paths := make([]*table.Path, 0, nVrf*routesPerVrf)
	for v := range nVrf {
		rd := bgp.NewRouteDistinguisherTwoOctetAS(65000, uint32(v))
		for i := range routesPerVrf {
			prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{20, byte(i >> 16), byte(i >> 8), byte(i)}), 32)
			paths = append(paths, newVPNPathForTest(tb, prefix, rd, vrfRT(v)))
		}
	}
	s.propagateUpdate(nil, paths)
	return s, peers
}

// An injected path reaches exactly the VRF neighbors whose VRF imports it.
func TestVrfNeighborsInject(t *testing.T) {
	s, peers := newVrfNeighbors(t, 3, 3, 0)
	rd := bgp.NewRouteDistinguisherTwoOctetAS(65000, 99)
	sent := func(p *table.Path) []bool {
		l := make([]bool, len(peers))
		for i, peer := range peers {
			l[i] = peer.hasPathAlreadyBeenSent(p.ToLocal())
		}
		return l
	}
	x := newVPNPathForTest(t, netip.MustParsePrefix("30.0.0.1/32"), rd, vrfRT(0))
	y := newVPNPathForTest(t, netip.MustParsePrefix("30.0.0.2/32"), rd, vrfRT(0), vrfRT(2))
	z := newVPNPathForTest(t, netip.MustParsePrefix("30.0.0.3/32"), rd, vrfRT(42))
	s.propagateUpdate(nil, []*table.Path{x, y, z})
	require.Equal(t, []bool{true, false, false}, sent(x))
	require.Equal(t, []bool{true, false, true}, sent(y))
	require.Equal(t, []bool{false, false, false}, sent(z))

	s.propagateUpdate(nil, []*table.Path{y.Clone(true)})
	require.Equal(t, []bool{false, false, false}, sent(y))
	require.Equal(t, []bool{true, false, false}, sent(x))
}

// A VRF neighbor with ADD-PATH send is not skipped: it still gets a path its
// VRF imports when that path is not the best one of its prefix.
func TestVrfNeighborsInjectAddPath(t *testing.T) {
	s, peers := newVrfNeighbors(t, 2, 1, 0)
	for i := range peers[0].fsm.pConf.ReadOnly().AfiSafis {
		peers[0].fsm.pConf.ReadOnly().AfiSafis[i].AddPaths.Config.SendMax = 8
	}
	peers[0].fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_SEND})
	rd := bgp.NewRouteDistinguisherTwoOctetAS(65000, 99)
	prefix := netip.MustParsePrefix("30.0.0.1/32")
	path := func(id uint32, rt bgp.ExtendedCommunityInterface) *table.Path {
		p := newVPNPathForTest(t, prefix, rd, rt)
		src := netip.AddrFrom4([4]byte{9, 9, 9, byte(id)})
		return table.NewPath(p.GetFamily(), &table.PeerInfo{Address: src, ID: src}, bgp.PathNLRI{NLRI: p.GetNlri(), ID: id}, false, p.GetPathAttrs(), p.GetTimestamp(), false)
	}
	best := path(1, vrfRT(1)) // best: lowest router ID, not imported by vrf0
	imported := path(2, vrfRT(0))
	s.propagateUpdate(nil, []*table.Path{best})
	s.propagateUpdate(nil, []*table.Path{imported})
	require.True(t, peers[0].hasPathAlreadyBeenSent(imported.ToLocal()))
}

func vrfDump(s *BgpServer, p *peer, fullScan bool) (paths, filtered []*table.Path) {
	return vrfDumpFamily(s, p, bgp.RF_IPv4_UC, fullScan)
}

func vrfDumpFamily(s *BgpServer, p *peer, family bgp.Family, fullScan bool) (paths, filtered []*table.Path) {
	p.routeRefreshInProgress.RLock()
	defer p.routeRefreshInProgress.RUnlock()
	s.getBestFromLocalCallbackLocked(p, []bgp.Family{family}, false, fullScan, func(a, r []*table.Path) {
		paths, filtered = a, r
	})
	return paths, filtered
}

func pathStrings(paths []*table.Path) []string {
	l := make([]string, 0, len(paths))
	for _, p := range paths {
		l = append(l, p.String())
	}
	return l
}

// The paths advertised to a VRF neighbor are the same with the Route Target
// lookup as with a walk of the whole table:
//   - 30.0.0.1 carries the RT of vrf0 and of vrf1;
//   - 30.0.0.2 carries other RTs;
//   - 30.0.0.3 has a best path without the RT of vrf0 and another path with
//     it: vrf0 does not get it, since only best paths are advertised;
//   - 30.0.0.4 has a best path received with ADD-PATH.
func TestVrfNeighborDumpMatchesFullScan(t *testing.T) {
	const nVrf, routesPerVrf = 5, 50
	s, peers := newVrfNeighbors(t, nVrf, 1, routesPerVrf)
	rd := bgp.NewRouteDistinguisherTwoOctetAS(65000, 99)
	withSource := func(p *table.Path, src string, id uint32) *table.Path {
		a := netip.MustParseAddr(src)
		return table.NewPath(p.GetFamily(), &table.PeerInfo{Address: a, ID: a}, bgp.PathNLRI{NLRI: p.GetNlri(), ID: id}, false, p.GetPathAttrs(), p.GetTimestamp(), false)
	}
	s.propagateUpdate(nil, []*table.Path{
		newVPNPathForTest(t, netip.MustParsePrefix("30.0.0.1/32"), rd, vrfRT(1), vrfRT(0)),
		newVPNPathForTest(t, netip.MustParsePrefix("30.0.0.2/32"), rd, vrfRT(2), vrfRT(3)),
		withSource(newVPNPathForTest(t, netip.MustParsePrefix("30.0.0.3/32"), rd, vrfRT(1)), "9.9.9.1", 0),
		withSource(newVPNPathForTest(t, netip.MustParsePrefix("30.0.0.3/32"), rd, vrfRT(0)), "9.9.9.2", 0),
		withSource(newVPNPathForTest(t, netip.MustParsePrefix("30.0.0.4/32"), rd, vrfRT(0)), "9.9.9.1", 1),
	})
	indexed, _ := vrfDump(s, peers[0], false)
	full, _ := vrfDump(s, peers[0], true)
	require.Len(t, indexed, routesPerVrf+2)
	require.ElementsMatch(t, pathStrings(full), pathStrings(indexed))
}

// Soft reset out keeps the full scan: a path that lost the RT of the VRF must
// be withdrawn.
func TestVrfNeighborSoftResetOutWithdrawsLostRT(t *testing.T) {
	s, peers := newVrfNeighbors(t, 2, 1, 3)
	p := peers[0]
	paths, _ := vrfDump(s, p, false)
	require.Len(t, paths, 3)
	p.updateRoutes(paths...)

	moved := newVPNPathForTest(t, netip.MustParsePrefix("20.0.0.0/32"), bgp.NewRouteDistinguisherTwoOctetAS(65000, 0), vrfRT(1))
	s.propagateUpdate(nil, []*table.Path{moved})
	require.True(t, p.hasPathAlreadyBeenSent(moved.ToLocal()))

	s.softResetOutPeer(p, bgp.RF_IPv4_UC, false)
	require.False(t, p.hasPathAlreadyBeenSent(moved.ToLocal()))
}

// The graceful restart release advertises to a VRF neighbor the paths of its
// VRF only.
func TestVrfNeighborRestartReleased(t *testing.T) {
	s, peers := newVrfNeighbors(t, 3, 1, 5)
	// As if the families had been deferred: nothing advertised yet.
	peers[0].resetAdvertisedRoutes()
	require.Zero(t, peers[0].advertisedRoutes([]bgp.Family{bgp.RF_IPv4_UC}))
	require.NoError(t, s.mgmtOperation(func() error {
		s.restartReleased([]bgp.Family{bgp.RF_IPv4_UC})
		return nil
	}, true))
	require.Equal(t, 5, peers[0].advertisedRoutes([]bgp.Family{bgp.RF_IPv4_UC}))
}

// When the best path of a prefix, received with ADD-PATH, is withdrawn, the
// new best path, received without ADD-PATH, is advertised to the VRF neighbor.
func TestVrfNeighborDumpAfterAddPathWithdraw(t *testing.T) {
	s, peers := newVrfNeighbors(t, 1, 1, 0)
	rd := bgp.NewRouteDistinguisherTwoOctetAS(65000, 99)
	prefix := netip.MustParsePrefix("30.0.0.1/32")
	withSource := func(src string, id uint32) *table.Path {
		p := newVPNPathForTest(t, prefix, rd, vrfRT(0))
		a := netip.MustParseAddr(src)
		return table.NewPath(p.GetFamily(), &table.PeerInfo{Address: a, ID: a}, bgp.PathNLRI{NLRI: p.GetNlri(), ID: id}, false, p.GetPathAttrs(), p.GetTimestamp(), false)
	}
	withAddPath := withSource("9.9.9.1", 1) // best: lower router ID
	withoutAddPath := withSource("9.9.9.2", 0)
	s.propagateUpdate(nil, []*table.Path{withAddPath, withoutAddPath})
	s.propagateUpdate(nil, []*table.Path{withAddPath.Clone(true)})

	paths, _ := vrfDump(s, peers[0], false)
	require.Len(t, paths, 1)
	require.Equal(t, "9.9.9.2", paths[0].GetSource().Address.String())
}
