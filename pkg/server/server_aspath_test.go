package server

import (
	"context"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func newASPathTestPeer(t *testing.T, localAS, remoteAS uint32) (*BgpServer, *peer) {
	t.Helper()
	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{Global: &api.Global{
		Asn: localAS, RouterId: "192.0.2.254", ListenPort: -1,
	}}))
	p := newPeerandInfo(t, localAS, remoteAS, "192.0.2.1", s.globalRib)
	p.policy = s.policy
	p.fsm.gConf.Config.RouterId = netip.MustParseAddr("192.0.2.254")
	require.NoError(t, s.mgmtOperation(func() error {
		s.neighborMap[netip.MustParseAddr(p.ID())] = p
		return nil
	}, true))
	t.Cleanup(func() {
		require.NoError(t, s.mgmtOperation(func() error {
			delete(s.neighborMap, netip.MustParseAddr(p.ID()))
			return nil
		}, false))
		cleanInfiniteChannel(p.fsm.outgoingCh)
		s.Stop()
	})
	return s, p
}

func asPathTestPath(t *testing.T, p *peer, prefix string, id uint32, asns ...uint32) *table.Path {
	t.Helper()
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	require.NoError(t, err)
	family := bgp.RF_IPv4_UC
	nextHop := netip.MustParseAddr("192.0.2.1")
	if nlri.Prefix.Addr().Is6() {
		family = bgp.RF_IPv6_UC
		nextHop = netip.MustParseAddr("2001:db8::1")
	}
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, asns)}),
	}
	if family == bgp.RF_IPv4_UC {
		nh, err := bgp.NewPathAttributeNextHop(nextHop)
		require.NoError(t, err)
		attrs = append(attrs, nh)
	} else {
		mp, err := bgp.NewPathAttributeMpReachNLRI(family, []bgp.PathNLRI{{NLRI: nlri, ID: id}}, nextHop)
		require.NoError(t, err)
		attrs = append(attrs, mp)
	}
	return table.NewPath(family, p.peerInfo.Load(), bgp.PathNLRI{NLRI: nlri, ID: id}, false, attrs, time.Now(), false)
}

func asPathTestUpdate(t *testing.T, path *table.Path) *bgp.BGPMessage {
	t.Helper()
	nlri := []bgp.PathNLRI{{NLRI: path.GetNlri(), ID: path.RemoteID()}}
	if path.GetFamily() == bgp.RF_IPv4_UC {
		if path.IsWithdraw {
			return bgp.NewBGPUpdateMessage(nlri, nil, nil)
		}
		return bgp.NewBGPUpdateMessage(nil, path.GetPathAttrs(), nlri)
	}
	if path.IsWithdraw {
		mp, err := bgp.NewPathAttributeMpUnreachNLRI(path.GetFamily(), nlri)
		require.NoError(t, err)
		return bgp.NewBGPUpdateMessage(nil, []bgp.PathAttributeInterface{mp}, nil)
	}
	return bgp.NewBGPUpdateMessage(nil, path.GetPathAttrs(), nil)
}

func TestSoftResetInReevaluatesASPathOptions(t *testing.T) {
	for _, prefix := range []string{"10.0.0.0/24", "2001:db8:1::/48"} {
		t.Run(prefix, func(t *testing.T) {
			s, p := newASPathTestPeer(t, 65000, 65001)
			loop := asPathTestPath(t, p, prefix, 11, 65001, 65000)
			valid := asPathTestPath(t, p, prefix, 22, 65001)
			family := loop.GetFamily()
			p.adjRibIn = table.NewAdjRib(logger, []bgp.Family{family})
			p.fsm.lock.Lock()
			conf := p.fsm.pConf.ReadCopy()
			conf.AfiSafis = []oc.AfiSafi{{State: oc.AfiSafiState{Family: family}}}
			p.fsm.pConf.Update(&conf)
			p.fsm.lock.Unlock()
			require.NoError(t, s.mgmtOperation(func() error {
				for _, path := range []*table.Path{loop, valid} {
					accepted, _, limit := p.handleUpdate(&fsmMsg{MsgData: asPathTestUpdate(t, path), timestamp: time.Now()})
					assert.False(t, limit)
					s.propagateUpdate(p, accepted)
				}
				return nil
			}, true))
			check := func(want int) {
				t.Helper()
				require.NoError(t, s.mgmtOperation(func() error {
					assert.Equal(t, 2, p.adjRibIn.Count([]bgp.Family{family}))
					assert.Equal(t, want, p.adjRibIn.Accepted([]bgp.Family{family}))
					assert.Len(t, s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{family}), want)
					return nil
				}, true))
			}
			check(1)
			for _, allow := range []uint8{1, 1, 0, 0, 255, 0} {
				p.fsm.lock.Lock()
				conf := p.fsm.pConf.ReadCopy()
				conf.AsPathOptions.Config.AllowOwnAs = allow
				p.fsm.pConf.Update(&conf)
				p.fsm.lock.Unlock()
				require.NoError(t, s.ResetPeer(context.Background(), &api.ResetPeerRequest{
					Address: p.ID(), Soft: true, Direction: api.ResetPeerRequest_DIRECTION_IN,
				}))
				want := 1
				if allow > 0 {
					want = 2
				}
				check(want)
			}
			// Removing one Add-Path route must leave the other path intact.
			require.NoError(t, s.mgmtOperation(func() error {
				paths, _, _ := p.handleUpdate(&fsmMsg{MsgData: asPathTestUpdate(t, valid.Clone(true)), timestamp: time.Now()})
				if !assert.Len(t, paths, 1) {
					return nil
				}
				assert.True(t, paths[0].IsWithdraw)
				s.propagateUpdate(p, paths)
				remaining := p.adjRibIn.PathList([]bgp.Family{family}, false)
				if !assert.Len(t, remaining, 1) {
					return nil
				}
				assert.Equal(t, uint32(11), remaining[0].RemoteID())
				assert.True(t, remaining[0].IsRejected())
				assert.Empty(t, s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{family}))
				return nil
			}, true))
		})
	}
}

func TestSoftResetInPreservesLoopChecksAndImportPolicy(t *testing.T) {
	s, p := newASPathTestPeer(t, 65000, 65000)
	p.fsm.gConf.Confederation.Config.Enabled = true
	p.fsm.gConf.Confederation.Config.Identifier = 65100
	originator, err := bgp.NewPathAttributeOriginatorId(p.fsm.gConf.Config.RouterId)
	require.NoError(t, err)
	paths := []*table.Path{
		asPathTestPath(t, p, "10.0.0.0/24", 0, 65000),
		asPathTestPath(t, p, "10.0.1.0/24", 0, 65100, 65100),
		asPathTestPath(t, p, "10.0.2.0/24", 0, 65000),
		asPathTestPath(t, p, "10.0.3.0/24", 0, 65001),
	}
	for _, i := range []int{2, 3} {
		paths[i] = table.NewPath(paths[i].GetFamily(), p.peerInfo.Load(), bgp.PathNLRI{NLRI: paths[i].GetNlri()}, false, append(paths[i].GetPathAttrs(), originator), time.Now(), false)
	}
	require.NoError(t, s.mgmtOperation(func() error {
		for _, path := range paths {
			accepted, _, _ := p.handleUpdate(&fsmMsg{MsgData: asPathTestUpdate(t, path), timestamp: time.Now()})
			assert.Empty(t, accepted)
		}
		return nil
	}, true))
	setImport := func(action api.RouteAction) {
		t.Helper()
		require.NoError(t, s.SetPolicyAssignment(context.Background(), &api.SetPolicyAssignmentRequest{
			Assignment: &api.PolicyAssignment{Name: table.GLOBAL_RIB_NAME, Direction: api.PolicyDirection_POLICY_DIRECTION_IMPORT, DefaultAction: action},
		}))
	}
	setImport(api.RouteAction_ROUTE_ACTION_REJECT)
	p.fsm.lock.Lock()
	conf := p.fsm.pConf.ReadCopy()
	conf.AsPathOptions.Config.AllowOwnAs = 1
	p.fsm.pConf.Update(&conf)
	p.fsm.lock.Unlock()
	reset := func() {
		t.Helper()
		require.NoError(t, s.ResetPeer(context.Background(), &api.ResetPeerRequest{Address: p.ID(), Soft: true, Direction: api.ResetPeerRequest_DIRECTION_IN}))
	}
	reset()
	require.NoError(t, s.mgmtOperation(func() error {
		assert.Equal(t, 1, p.adjRibIn.Accepted([]bgp.Family{bgp.RF_IPv4_UC}))
		assert.Empty(t, s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_UC}))
		return nil
	}, true))
	setImport(api.RouteAction_ROUTE_ACTION_ACCEPT)
	reset()
	require.NoError(t, s.mgmtOperation(func() error {
		installed := s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_UC})
		if !assert.Len(t, installed, 1) {
			return nil
		}
		assert.Equal(t, "10.0.0.0/24", installed[0].GetPrefix())
		// Treat-as-withdraw retains attributes; loop checks must not consume it.
		withdrawals, _, _ := p.handleUpdate(&fsmMsg{MsgData: asPathTestUpdate(t, paths[2]), timestamp: time.Now(), handling: bgp.ERROR_HANDLING_TREAT_AS_WITHDRAW})
		if !assert.Len(t, withdrawals, 1) {
			return nil
		}
		assert.True(t, withdrawals[0].IsWithdraw)
		return nil
	}, true))
}

func TestSoftResetInWithdrawsASLoopFromDownstream(t *testing.T) {
	s, p := newASPathTestPeer(t, 65000, 65001)
	downstream := newPeerandInfo(t, 65000, 65002, "192.0.2.2", s.globalRib)
	downstream.policy = s.policy
	downstream.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
	downstream.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_NONE})
	path := asPathTestPath(t, p, "10.0.0.0/24", 0, 65001, 65000)
	path.SetRejected(true)
	require.NoError(t, s.mgmtOperation(func() error {
		s.neighborMap[netip.MustParseAddr(downstream.ID())] = downstream
		p.adjRibIn.Update([]*table.Path{path})
		return nil
	}, true))
	t.Cleanup(func() {
		require.NoError(t, s.mgmtOperation(func() error {
			delete(s.neighborMap, netip.MustParseAddr(downstream.ID()))
			return nil
		}, false))
		cleanInfiniteChannel(downstream.fsm.outgoingCh)
	})
	for _, allow := range []uint8{1, 0} {
		p.fsm.lock.Lock()
		conf := p.fsm.pConf.ReadCopy()
		conf.AsPathOptions.Config.AllowOwnAs = allow
		p.fsm.pConf.Update(&conf)
		p.fsm.lock.Unlock()
		require.NoError(t, s.ResetPeer(context.Background(), &api.ResetPeerRequest{
			Address: p.ID(), Soft: true, Direction: api.ResetPeerRequest_DIRECTION_IN,
		}))
		select {
		case outgoing := <-downstream.fsm.outgoingCh.Out():
			msg := outgoing.(*fsmOutgoingMsg)
			require.Len(t, msg.Paths, 1)
			assert.Equal(t, path.GetPrefix(), msg.Paths[0].GetPrefix())
			assert.Equal(t, allow == 0, msg.Paths[0].IsWithdraw)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for downstream AS path update")
		}
	}
}

func TestUpdatePeerASPathOptions(t *testing.T) {
	ctx := context.Background()
	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{Asn: 65000, RouterId: "192.0.2.254", ListenPort: -1}}))
	t.Cleanup(s.Stop)
	p := &api.Peer{Conf: &api.PeerConf{NeighborAddress: "192.0.2.1", PeerAsn: 65001, AdminDown: true}}
	require.NoError(t, s.AddPeer(ctx, &api.AddPeerRequest{Peer: p}))
	var original *peer
	require.NoError(t, s.mgmtOperation(func() error {
		original = s.neighborMap[netip.MustParseAddr(p.Conf.NeighborAddress)]
		return nil
	}, true))
	for _, options := range []oc.AsPathOptionsConfig{
		{AllowOwnAs: 1},
		{AllowOwnAs: 1, ReplacePeerAs: true},
		{AllowOwnAs: 1, ReplacePeerAs: true, AllowAsPathLoopLocal: true},
		{},
		{},
	} {
		previousAllow := p.Conf.AllowOwnAsn
		p.Conf.AllowOwnAsn = uint32(options.AllowOwnAs)
		p.Conf.ReplacePeerAsn = options.ReplacePeerAs
		p.Conf.AllowAspathLoopLocal = options.AllowAsPathLoopLocal
		rsp, err := s.UpdatePeer(ctx, &api.UpdatePeerRequest{Peer: p})
		require.NoError(t, err)
		assert.Equal(t, previousAllow != uint32(options.AllowOwnAs), rsp.NeedsSoftResetIn)
		require.NoError(t, s.ListPeer(ctx, &api.ListPeerRequest{Address: p.Conf.NeighborAddress}, func(got *api.Peer) {
			assert.Equal(t, p.Conf.AllowOwnAsn, got.Conf.AllowOwnAsn)
			assert.Equal(t, p.Conf.ReplacePeerAsn, got.Conf.ReplacePeerAsn)
			assert.Equal(t, p.Conf.AllowAspathLoopLocal, got.Conf.AllowAspathLoopLocal)
		}))
		require.NoError(t, s.mgmtOperation(func() error {
			current := s.neighborMap[netip.MustParseAddr(p.Conf.NeighborAddress)]
			assert.Same(t, original, current, "AS path options must not recreate the peer")
			c := current.fsm.pConf.ReadOnly()
			assert.Equal(t, options, c.AsPathOptions.Config)
			assert.Equal(t, oc.AsPathOptionsState(options), c.AsPathOptions.State)
			return nil
		}, true))
	}
}

func TestUpdatePeerGroupASPathOptions(t *testing.T) {
	ctx := context.Background()
	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{Asn: 65000, RouterId: "192.0.2.254", ListenPort: -1}}))
	t.Cleanup(s.Stop)
	group := &api.PeerGroup{Conf: &api.PeerGroupConf{PeerGroupName: "as-options", PeerAsn: 65001}, Transport: &api.Transport{PassiveMode: true}}
	require.NoError(t, s.AddPeerGroup(ctx, &api.AddPeerGroupRequest{PeerGroup: group}))
	const addr = "192.0.2.19"
	require.NoError(t, s.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{Conf: &api.PeerConf{NeighborAddress: addr, PeerGroup: group.Conf.PeerGroupName}}}))
	const overrideAddr = "192.0.2.20"
	// The config-file API records explicit fields for peer-group inheritance.
	oc.RegisterConfiguredFields(overrideAddr, map[string]any{
		"config": map[string]any{"local-as": 65010},
		"as-path-options": map[string]any{"config": map[string]any{
			"allow-own-as": 1, "replace-peer-as": false, "allow-as-path-loop-local": false,
		}},
		"timers": map[string]any{"config": map[string]any{"hold-time": 45, "keepalive-interval": 15}},
	})
	t.Cleanup(func() { oc.RegisterConfiguredFields(overrideAddr, nil) })
	require.NoError(t, s.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf:   &api.PeerConf{NeighborAddress: overrideAddr, PeerGroup: group.Conf.PeerGroupName, LocalAsn: 65010, AllowOwnAsn: 1},
		Timers: &api.Timers{Config: &api.TimersConfig{HoldTime: 45, KeepaliveInterval: 15}},
	}}))
	var original *peer
	require.NoError(t, s.mgmtOperation(func() error {
		original = s.neighborMap[netip.MustParseAddr(addr)]
		return nil
	}, true))
	for _, enabled := range []bool{true, false} {
		group.Conf.AllowOwnAsn = 0
		if enabled {
			group.Conf.AllowOwnAsn = 2
		}
		group.Conf.ReplacePeerAsn = enabled
		group.Conf.AllowAspathLoopLocal = enabled
		rsp, err := s.UpdatePeerGroup(ctx, &api.UpdatePeerGroupRequest{PeerGroup: group})
		require.NoError(t, err)
		assert.True(t, rsp.NeedsSoftResetIn)
		require.NoError(t, s.ListPeer(ctx, &api.ListPeerRequest{Address: addr}, func(got *api.Peer) {
			assert.Equal(t, group.Conf.AllowOwnAsn, got.Conf.AllowOwnAsn)
			assert.Equal(t, enabled, got.Conf.ReplacePeerAsn)
			assert.Equal(t, enabled, got.Conf.AllowAspathLoopLocal)
		}))
		require.NoError(t, s.ListPeer(ctx, &api.ListPeerRequest{Address: overrideAddr}, func(got *api.Peer) {
			assert.Equal(t, uint32(1), got.Conf.AllowOwnAsn)
			assert.False(t, got.Conf.ReplacePeerAsn)
			assert.False(t, got.Conf.AllowAspathLoopLocal)
			assert.Equal(t, uint32(65010), got.Conf.LocalAsn)
			assert.Equal(t, uint32(65001), got.Conf.PeerAsn)
			assert.Equal(t, uint64(45), got.Timers.Config.HoldTime)
			assert.Equal(t, uint64(15), got.Timers.Config.KeepaliveInterval)
		}))
		require.NoError(t, s.mgmtOperation(func() error {
			current := s.neighborMap[netip.MustParseAddr(addr)]
			assert.Same(t, original, current)
			options := current.fsm.pConf.ReadOnly().AsPathOptions
			assert.Equal(t, oc.AsPathOptionsState(options.Config), options.State)
			return nil
		}, true))
	}
}

func TestSoftResetInAfterRepeatedASLoopUpdate(t *testing.T) {
	for _, addPath := range []bool{false, true} {
		name := "single-path"
		if addPath {
			name = "add-path"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s := NewBgpServer()
			go s.Serve()
			require.NoError(t, s.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{Asn: 65000, RouterId: "192.0.2.254", ListenPort: -1}}))
			t.Cleanup(s.Stop)
			input := &api.Peer{Conf: &api.PeerConf{NeighborAddress: "192.0.2.81", PeerAsn: 65001, AdminDown: true, AllowOwnAsn: 1}}
			require.NoError(t, s.AddPeer(ctx, &api.AddPeerRequest{Peer: input}))
			var p *peer
			require.NoError(t, s.mgmtOperation(func() error {
				p = s.neighborMap[netip.MustParseAddr(input.Conf.NeighborAddress)]
				return nil
			}, true))
			loop := asPathTestPath(t, p, "10.81.0.0/24", 11, 65001, 65000)
			deliver := func(path *table.Path) {
				t.Helper()
				require.NoError(t, s.mgmtOperation(func() error {
					accepted, _, limit := p.handleUpdate(&fsmMsg{MsgData: asPathTestUpdate(t, path), timestamp: time.Now()})
					assert.False(t, limit)
					s.propagateUpdate(p, accepted)
					return nil
				}, true))
			}
			globalIDs := func() []uint32 {
				t.Helper()
				var ids []uint32
				require.NoError(t, s.ListPath(apiutil.ListPathRequest{TableType: api.TableType_TABLE_TYPE_GLOBAL, Family: bgp.RF_IPv4_UC}, func(_ bgp.NLRI, paths []*apiutil.Path) {
					for _, path := range paths {
						ids = append(ids, path.RemoteID)
					}
				}))
				return ids
			}
			deliver(loop)
			want := []uint32{}
			if addPath {
				deliver(asPathTestPath(t, p, "10.81.0.0/24", 22, 65001))
				want = append(want, 22)
			}
			require.Len(t, globalIDs(), 1+len(want))
			input.Conf.AllowOwnAsn = 0
			response, err := s.UpdatePeer(ctx, &api.UpdatePeerRequest{Peer: input})
			require.NoError(t, err)
			require.True(t, response.NeedsSoftResetIn)
			// A repeated UPDATE can mark the cache rejected before the caller resets IN.
			deliver(loop)
			for range 2 {
				require.NoError(t, s.ResetPeer(ctx, &api.ResetPeerRequest{Address: input.Conf.NeighborAddress, Soft: true, Direction: api.ResetPeerRequest_DIRECTION_IN}))
				assert.ElementsMatch(t, want, globalIDs())
				require.NoError(t, s.mgmtOperation(func() error {
					assert.Same(t, p, s.neighborMap[netip.MustParseAddr(input.Conf.NeighborAddress)])
					families := []bgp.Family{bgp.RF_IPv4_UC}
					assert.Equal(t, 1+len(want), p.adjRibIn.Count(families))
					assert.Equal(t, len(want), p.adjRibIn.Accepted(families))
					return nil
				}, true))
			}
		})
	}
}

func TestUpdatePeerGroupPreservesCurrentASPathOverride(t *testing.T) {
	ctx := context.Background()
	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{Asn: 65000, RouterId: "192.0.2.254", ListenPort: -1}}))
	t.Cleanup(s.Stop)
	const addr = "192.0.2.82"
	group := &api.PeerGroup{Conf: &api.PeerGroupConf{PeerGroupName: "current-member", PeerAsn: 65001}, Transport: &api.Transport{PassiveMode: true}}
	require.NoError(t, s.AddPeerGroup(ctx, &api.AddPeerGroupRequest{PeerGroup: group}))
	oc.RegisterConfiguredFields(addr, map[string]any{
		"config":          map[string]any{"admin-down": true},
		"as-path-options": map[string]any{"config": map[string]any{"allow-own-as": 1}},
	})
	t.Cleanup(func() { oc.RegisterConfiguredFields(addr, nil) })
	input := &api.Peer{Conf: &api.PeerConf{NeighborAddress: addr, PeerGroup: group.Conf.PeerGroupName, AllowOwnAsn: 1, AdminDown: true}}
	require.NoError(t, s.AddPeer(ctx, &api.AddPeerRequest{Peer: input}))
	input.Conf.AllowOwnAsn = 2
	response, err := s.UpdatePeer(ctx, &api.UpdatePeerRequest{Peer: input})
	require.NoError(t, err)
	require.True(t, response.NeedsSoftResetIn)
	for _, replace := range []bool{true, false} {
		group.Conf.ReplacePeerAsn = replace
		response, err := s.UpdatePeerGroup(ctx, &api.UpdatePeerGroupRequest{PeerGroup: group})
		require.NoError(t, err)
		assert.False(t, response.NeedsSoftResetIn)
		require.NoError(t, s.ListPeer(ctx, &api.ListPeerRequest{Address: addr}, func(got *api.Peer) {
			assert.Equal(t, uint32(2), got.Conf.AllowOwnAsn)
			assert.Equal(t, replace, got.Conf.ReplacePeerAsn)
		}))
	}
}

func TestSoftResetInASPathCacheHistoryIsBounded(t *testing.T) {
	s, p := newASPathTestPeer(t, 65000, 65001)
	path := asPathTestPath(t, p, "10.83.0.0/24", 0, 65001, 65000)
	path.SetRejected(true)
	require.NoError(t, s.mgmtOperation(func() error {
		p.adjRibIn.Update([]*table.Path{path})
		return nil
	}, true))
	depths := []int{0}
	for step := range 8 {
		allow := uint8((step + 1) % 2)
		p.fsm.lock.Lock()
		conf := p.fsm.pConf.ReadCopy()
		conf.AsPathOptions.Config.AllowOwnAs = allow
		p.fsm.pConf.Update(&conf)
		p.fsm.lock.Unlock()
		require.NoError(t, s.ResetPeer(context.Background(), &api.ResetPeerRequest{Address: p.ID(), Soft: true, Direction: api.ResetPeerRequest_DIRECTION_IN}))
		require.NoError(t, s.mgmtOperation(func() error {
			cached := p.adjRibIn.PathList([]bgp.Family{bgp.RF_IPv4_UC}, false)
			if !assert.Len(t, cached, 1) {
				return nil
			}
			assert.Equal(t, int(allow), p.adjRibIn.Accepted([]bgp.Family{bgp.RF_IPv4_UC}))
			// Inspect private ancestry without adding a public API for this test.
			depth := 0
			for v := reflect.ValueOf(cached[0]).Elem().FieldByName("parent"); !v.IsNil() && depth < 16; v = v.Elem().FieldByName("parent") {
				depth++
			}
			depths = append(depths, depth)
			assert.Zero(t, depth, "admission changes must not retain old cached paths")
			return nil
		}, true))
	}
	t.Logf("parent depth after 0..8 admission changes: %v", depths)
}
