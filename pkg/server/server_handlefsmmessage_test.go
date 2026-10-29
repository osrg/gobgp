// Copyright (C) 2026 Cisco Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/gr"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/packet/bmp"
)

// TestHandleFSMMessage_PrefixLimitWarnedRace tests concurrent access to prefixLimitWarned map
func TestHandleFSMMessage_PrefixLimitWarnedRace(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	numPeers := 20
	peers := make([]*peer, numPeers)

	// Create peers with prefix limit config
	for i := range numPeers {
		peerAddr := netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})
		err = s.AddPeer(context.Background(), &api.AddPeerRequest{
			Peer: &api.Peer{
				Conf: &api.PeerConf{
					NeighborAddress: peerAddr.String(),
					PeerAsn:         uint32(65002 + i),
					AdminDown:       true,
				},
				AfiSafis: []*api.AfiSafi{
					{
						Config: &api.AfiSafiConfig{
							Family: &api.Family{
								Afi:  api.Family_AFI_IP,
								Safi: api.Family_SAFI_UNICAST,
							},
							Enabled: true,
						},
						PrefixLimits: &api.PrefixLimit{
							MaxPrefixes:          100,
							ShutdownThresholdPct: 80,
						},
					},
				},
			},
		})
		require.NoError(t, err)

		err = s.mgmtOperation(func() error {
			peers[i] = s.neighborMap[peerAddr]
			return nil
		}, true)
		require.NoError(t, err)
		require.NotNil(t, peers[i])
	}

	// Test concurrent reset and read/write of prefixLimitWarned
	var wg sync.WaitGroup

	// Goroutines that reset the map (simulating PeerDown)
	for i := range numPeers / 2 {
		wg.Add(1)
		go func(peerIdx int) {
			defer wg.Done()
			p := peers[peerIdx]

			for range 100 {
				passEstablished(t, s, p)

				// Trigger PeerDown which resets prefixLimitWarned
				msg := &fsmMsg{
					MsgType:     fsmMsgStateChange,
					MsgData:     bgp.BGP_FSM_IDLE,
					StateReason: newfsmStateReason(fsmHoldTimerExpired, nil, nil),
					timestamp:   time.Now(),
				}
				s.handleFSMMessage(p, msg)
				time.Sleep(1 * time.Millisecond)
			}
		}(i)
	}

	// Goroutines that read/write the map (simulating isPrefixLimit)
	for i := numPeers / 2; i < numPeers; i++ {
		wg.Add(1)
		go func(peerIdx int) {
			defer wg.Done()
			p := peers[peerIdx]

			for range 100 {
				// Access prefixLimitWarned through isPrefixLimit
				p.fsm.lock.Lock()
				conf := p.fsm.pConf.ReadCopy()

				for _, af := range conf.AfiSafis {
					p.isPrefixLimit(af.State.Family, &af.PrefixLimit.Config)
				}
				p.fsm.lock.Unlock()

				time.Sleep(1 * time.Millisecond)
			}
		}(i)
	}

	wg.Wait()
}

func TestSoftResetOutSerializesNormalReset(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)

	peerAddr := netip.MustParseAddr("10.0.0.1")
	p := newPeerandInfo(t, 65001, 65002, peerAddr.String(), s.globalRib)
	p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
	err = s.mgmtOperation(func() error {
		s.neighborMap[peerAddr] = p
		return nil
	}, true)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := s.mgmtOperation(func() error {
			delete(s.neighborMap, peerAddr)
			return nil
		}, false)
		require.NoError(t, err)
		require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
	})

	p.routeRefreshInProgress.RLock()
	locked := true
	defer func() {
		if locked {
			p.routeRefreshInProgress.RUnlock()
		}
	}()

	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		done <- s.softResetOut(peerAddr.String(), bgp.RF_IPv4_UC, false)
	}()
	<-started

	select {
	case err := <-done:
		p.routeRefreshInProgress.RUnlock()
		locked = false
		require.NoError(t, err)
		t.Fatal("normal soft reset out completed while live propagation held the route-refresh read lock")
	case <-time.After(200 * time.Millisecond):
	}

	p.routeRefreshInProgress.RUnlock()
	locked = false

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("normal soft reset out did not complete after the route-refresh read lock was released")
	}
}

func TestSoftResetOutRefreshesExportPolicyFilteredRoutes(t *testing.T) {
	ctx := context.Background()
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(ctx, &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)

	peerAddr := netip.MustParseAddr("10.0.0.1")
	p := newPeerandInfo(t, 65001, 65002, peerAddr.String(), s.globalRib)
	p.policy = s.policy
	p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
	p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{
		bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_NONE,
	})
	err = s.mgmtOperation(func() error {
		s.neighborMap[peerAddr] = p
		return nil
	}, true)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := s.mgmtOperation(func() error {
			delete(s.neighborMap, peerAddr)
			return nil
		}, false)
		require.NoError(t, err)
		cleanInfiniteChannel(p.fsm.outgoingCh)
		require.NoError(t, s.StopBgp(ctx, &api.StopBgpRequest{}))
	})

	setExportDefault := func(action api.RouteAction) {
		t.Helper()
		err := s.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{
			Assignment: &api.PolicyAssignment{
				Name:          table.GLOBAL_RIB_NAME,
				Direction:     api.PolicyDirection_POLICY_DIRECTION_EXPORT,
				DefaultAction: action,
			},
		})
		require.NoError(t, err)
	}
	requireNoOutgoing := func() {
		t.Helper()
		select {
		case o := <-p.fsm.outgoingCh.Out():
			t.Fatalf("unexpected outbound paths: %#v", o)
		case <-time.After(100 * time.Millisecond):
		}
	}
	requireOutgoing := func() []*table.Path {
		t.Helper()
		select {
		case o := <-p.fsm.outgoingCh.Out():
			msg, ok := o.(*fsmOutgoingMsg)
			require.True(t, ok)
			paths := make([]*table.Path, 0, len(msg.Paths))
			for _, path := range msg.Paths {
				if path != nil && !path.IsEOR() {
					paths = append(paths, path)
				}
			}
			return paths
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for outbound soft-reset paths")
			return nil
		}
	}
	requirePaths := func(paths []*table.Path, withdraw bool, prefixes ...string) {
		t.Helper()
		require.Len(t, paths, len(prefixes))
		seen := make(map[string]struct{}, len(paths))
		for _, path := range paths {
			require.Equal(t, withdraw, path.IsWithdraw)
			seen[path.GetPrefix()] = struct{}{}
		}
		for _, prefix := range prefixes {
			require.Contains(t, seen, prefix)
		}
	}

	advertised := makePath(t, "192.0.2.0/32", "192.0.2.254", 0)
	neverAdvertised := makePath(t, "192.0.2.1/32", "192.0.2.254", 0)

	setExportDefault(api.RouteAction_ROUTE_ACTION_ACCEPT)
	s.propagateUpdate(nil, []*table.Path{advertised})
	requirePaths(requireOutgoing(), false, "192.0.2.0/32")

	setExportDefault(api.RouteAction_ROUTE_ACTION_REJECT)
	s.propagateUpdate(nil, []*table.Path{neverAdvertised})
	requireNoOutgoing()

	require.NoError(t, s.softResetOut(peerAddr.String(), bgp.RF_IPv4_UC, false))
	requirePaths(requireOutgoing(), true, "192.0.2.0/32")

	require.NoError(t, s.softResetOut(peerAddr.String(), bgp.RF_IPv4_UC, false))
	requireNoOutgoing()

	setExportDefault(api.RouteAction_ROUTE_ACTION_ACCEPT)
	require.NoError(t, s.softResetOut(peerAddr.String(), bgp.RF_IPv4_UC, false))
	requirePaths(requireOutgoing(), false, "192.0.2.0/32", "192.0.2.1/32")

	setExportDefault(api.RouteAction_ROUTE_ACTION_REJECT)
	require.NoError(t, s.softResetOut(peerAddr.String(), bgp.RF_IPv4_UC, false))
	requirePaths(requireOutgoing(), true, "192.0.2.0/32", "192.0.2.1/32")
}

func TestSoftResetOutSecondaryRouteWithdrawsAdvertisedFallback(t *testing.T) {
	ctx := context.Background()
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(ctx, &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)

	makeRouteServerPeer := func(address string, asn uint32, secondary bool) *peer {
		t.Helper()
		p := newPeerandInfo(t, 65001, asn, address, s.rsRib)
		p.fsm.lock.Lock()
		conf := p.fsm.pConf.ReadCopy()
		conf.RouteServer.Config.RouteServerClient = true
		conf.RouteServer.Config.SecondaryRoute = secondary
		p.fsm.pConf.Update(&conf)
		p.fsm.lock.Unlock()
		p.tableId = p.ID()
		return p
	}

	peerAddr := netip.MustParseAddr("10.0.0.1")
	target := makeRouteServerPeer(peerAddr.String(), 65002, true)
	target.policy = s.policy
	target.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
	target.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{
		bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_NONE,
	})
	primarySource := makeRouteServerPeer("10.0.0.2", 65003, false)
	fallbackSource := makeRouteServerPeer("10.0.0.3", 65004, false)
	for _, source := range []*peer{primarySource, fallbackSource} {
		require.NoError(t, s.policy.SetPolicyAssignment(
			source.TableID(),
			table.POLICY_DIRECTION_IMPORT,
			nil,
			table.ROUTE_TYPE_ACCEPT,
		))
	}

	err = s.mgmtOperation(func() error {
		s.neighborMap[peerAddr] = target
		return nil
	}, true)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := s.mgmtOperation(func() error {
			delete(s.neighborMap, peerAddr)
			return nil
		}, false)
		require.NoError(t, err)
		cleanInfiniteChannel(target.fsm.outgoingCh)
		require.NoError(t, s.StopBgp(ctx, &api.StopBgpRequest{}))
	})

	const primaryCommunity = uint32(65000)<<16 | 1
	definedSet := &api.DefinedSet{
		DefinedType: api.DefinedType_DEFINED_TYPE_COMMUNITY,
		Name:        "reject-primary",
		List:        []string{"65000:1"},
	}
	rejectPrimary := &api.Policy{
		Name: "reject-primary",
		Statements: []*api.Statement{{
			Name: "reject-primary",
			Conditions: &api.Conditions{
				CommunitySet: &api.MatchSet{
					Name: "reject-primary",
					Type: api.MatchSet_TYPE_ANY,
				},
			},
			Actions: &api.Actions{
				RouteAction: api.RouteAction_ROUTE_ACTION_REJECT,
			},
		}},
	}
	require.NoError(t, s.AddDefinedSet(ctx, &api.AddDefinedSetRequest{DefinedSet: definedSet}))
	require.NoError(t, s.AddPolicy(ctx, &api.AddPolicyRequest{Policy: rejectPrimary}))
	require.NoError(t, s.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{
		Assignment: &api.PolicyAssignment{
			Name:          target.TableID(),
			Direction:     api.PolicyDirection_POLICY_DIRECTION_EXPORT,
			Policies:      []*api.Policy{rejectPrimary},
			DefaultAction: api.RouteAction_ROUTE_ACTION_ACCEPT,
		},
	}))

	makeSourcePath := func(source *peer, localPref uint32, community uint32) *table.Path {
		t.Helper()
		nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("192.0.2.0/32"))
		require.NoError(t, err)
		nextHop, err := bgp.NewPathAttributeNextHop(source.peerInfo.Load().Address)
		require.NoError(t, err)
		attrs := []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
			bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
				bgp.NewAs4PathParam(2, []uint32{source.AS()}),
			}),
			nextHop,
			bgp.NewPathAttributeLocalPref(localPref),
			bgp.NewPathAttributeCommunities([]uint32{community}),
		}
		return table.NewPath(
			bgp.RF_IPv4_UC,
			source.peerInfo.Load(),
			bgp.PathNLRI{NLRI: nlri},
			false,
			attrs,
			time.Now(),
			false,
		)
	}
	requireNoOutgoing := func() {
		t.Helper()
		select {
		case o := <-target.fsm.outgoingCh.Out():
			t.Fatalf("unexpected outbound paths: %#v", o)
		case <-time.After(100 * time.Millisecond):
		}
	}
	requireOutgoing := func() []*table.Path {
		t.Helper()
		select {
		case o := <-target.fsm.outgoingCh.Out():
			msg, ok := o.(*fsmOutgoingMsg)
			require.True(t, ok)
			paths := make([]*table.Path, 0, len(msg.Paths))
			for _, path := range msg.Paths {
				if path != nil && !path.IsEOR() {
					paths = append(paths, path)
				}
			}
			return paths
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for outbound secondary-route soft-reset paths")
			return nil
		}
	}

	primary := makeSourcePath(primarySource, 200, primaryCommunity)
	fallback := makeSourcePath(fallbackSource, 100, 0)

	s.propagateUpdate(primarySource, []*table.Path{primary})
	requireNoOutgoing()

	s.propagateUpdate(fallbackSource, []*table.Path{fallback})
	tbl, ok := s.rsRib.GetTable(bgp.RF_IPv4_UC)
	require.True(t, ok)
	destinations := tbl.GetDestinations()
	require.Len(t, destinations, 1)
	knownPaths := destinations[0].GetAllKnownPathList()
	require.Len(t, knownPaths, 2)
	require.Equal(t, primary.GetSource().Address, knownPaths[0].GetSource().Address)
	paths := requireOutgoing()
	require.Len(t, paths, 1)
	require.False(t, paths[0].IsWithdraw)
	require.Equal(t, fallback.GetSource().Address, paths[0].GetSource().Address)

	require.NoError(t, s.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{
		Assignment: &api.PolicyAssignment{
			Name:          target.TableID(),
			Direction:     api.PolicyDirection_POLICY_DIRECTION_EXPORT,
			DefaultAction: api.RouteAction_ROUTE_ACTION_REJECT,
		},
	}))
	require.NoError(t, s.softResetOut(peerAddr.String(), bgp.RF_IPv4_UC, false))
	paths = requireOutgoing()
	require.Len(t, paths, 1)
	require.True(t, paths[0].IsWithdraw)
	require.Equal(t, "192.0.2.0/32", paths[0].GetPrefix())

	require.NoError(t, s.softResetOut(peerAddr.String(), bgp.RF_IPv4_UC, false))
	requireNoOutgoing()
}

func TestSoftResetOutVRFWithdrawsExportPolicyFilteredRoutes(t *testing.T) {
	ctx := context.Background()
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(ctx, &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	addVrf(t, s, "vrf1", "65001:100", []string{"65001:100"}, []string{"65001:100"}, 1)

	peerAddr := netip.MustParseAddr("10.0.0.1")
	p := newPeerandInfo(t, 65001, 65002, peerAddr.String(), s.globalRib)
	p.policy = s.policy
	p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
	p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{
		bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_NONE,
	})
	p.fsm.lock.Lock()
	conf := p.fsm.pConf.ReadCopy()
	conf.Config.Vrf = "vrf1"
	conf.State.Vrf = "vrf1"
	p.fsm.pConf.Update(&conf)
	p.fsm.lock.Unlock()
	err = s.mgmtOperation(func() error {
		s.neighborMap[peerAddr] = p
		return nil
	}, true)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := s.mgmtOperation(func() error {
			delete(s.neighborMap, peerAddr)
			return nil
		}, false)
		require.NoError(t, err)
		cleanInfiniteChannel(p.fsm.outgoingCh)
		require.NoError(t, s.StopBgp(ctx, &api.StopBgpRequest{}))
	})

	setExportDefault := func(action api.RouteAction) {
		t.Helper()
		err := s.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{
			Assignment: &api.PolicyAssignment{
				Name:          table.GLOBAL_RIB_NAME,
				Direction:     api.PolicyDirection_POLICY_DIRECTION_EXPORT,
				DefaultAction: action,
			},
		})
		require.NoError(t, err)
	}
	requireNoOutgoing := func() {
		t.Helper()
		select {
		case o := <-p.fsm.outgoingCh.Out():
			t.Fatalf("unexpected outbound paths: %#v", o)
		case <-time.After(100 * time.Millisecond):
		}
	}
	requireOutgoing := func() []*table.Path {
		t.Helper()
		select {
		case o := <-p.fsm.outgoingCh.Out():
			msg, ok := o.(*fsmOutgoingMsg)
			require.True(t, ok)
			paths := make([]*table.Path, 0, len(msg.Paths))
			for _, path := range msg.Paths {
				if path != nil && !path.IsEOR() {
					paths = append(paths, path)
				}
			}
			return paths
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for outbound VRF soft-reset paths")
			return nil
		}
	}
	makeVPNPath := func(prefix string) *table.Path {
		t.Helper()
		rd, rt, err := parseRDRT("65001:100")
		require.NoError(t, err)
		labels := bgp.NewMPLSLabelStack(100)
		nlri, err := bgp.NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix(prefix), *labels, rd)
		require.NoError(t, err)
		nextHop, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.0.2.254"))
		require.NoError(t, err)
		return table.NewPath(bgp.RF_IPv4_VPN, nil, bgp.PathNLRI{NLRI: nlri}, false, []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
			bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
				bgp.NewAs4PathParam(2, []uint32{65010}),
			}),
			nextHop,
			bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{rt}),
		}, time.Now(), false)
	}

	advertised := makeVPNPath("192.0.2.0/32")

	setExportDefault(api.RouteAction_ROUTE_ACTION_ACCEPT)
	s.propagateUpdate(nil, []*table.Path{advertised})
	paths := requireOutgoing()
	require.Len(t, paths, 1)
	require.False(t, paths[0].IsWithdraw)
	require.Equal(t, bgp.RF_IPv4_UC, paths[0].GetFamily())
	require.Equal(t, "192.0.2.0/32", paths[0].GetPrefix())

	setExportDefault(api.RouteAction_ROUTE_ACTION_REJECT)
	require.NoError(t, s.softResetOut(peerAddr.String(), bgp.RF_IPv4_UC, false))
	paths = requireOutgoing()
	require.Len(t, paths, 1)
	require.True(t, paths[0].IsWithdraw)
	require.Equal(t, bgp.RF_IPv4_UC, paths[0].GetFamily())
	require.Equal(t, "192.0.2.0/32", paths[0].GetPrefix())

	require.NoError(t, s.softResetOut(peerAddr.String(), bgp.RF_IPv4_UC, false))
	requireNoOutgoing()
}

func TestSoftResetOutAddPathWithdrawsOnlyAdvertisedFilteredRoutes(t *testing.T) {
	ctx := context.Background()
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(ctx, &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)

	peerAddr := netip.MustParseAddr("10.0.0.1")
	p := newPeerandInfo(t, 65001, 65002, peerAddr.String(), s.globalRib)
	p.policy = s.policy
	p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
	p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{
		bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_SEND,
	})
	p.fsm.lock.Lock()
	conf := p.fsm.pConf.ReadCopy()
	foundFamily := false
	for i := range conf.AfiSafis {
		if conf.AfiSafis[i].State.Family != bgp.RF_IPv4_UC {
			continue
		}
		conf.AfiSafis[i].AddPaths.Config.SendMax = 1
		conf.AfiSafis[i].AddPaths.State.SendMax = 1
		foundFamily = true
	}
	p.fsm.pConf.Update(&conf)
	p.fsm.lock.Unlock()
	require.True(t, foundFamily)

	err = s.mgmtOperation(func() error {
		s.neighborMap[peerAddr] = p
		return nil
	}, true)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := s.mgmtOperation(func() error {
			delete(s.neighborMap, peerAddr)
			return nil
		}, false)
		require.NoError(t, err)
		cleanInfiniteChannel(p.fsm.outgoingCh)
		require.NoError(t, s.StopBgp(ctx, &api.StopBgpRequest{}))
	})

	makeSourcePath := func(source string) *table.Path {
		t.Helper()
		nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("192.0.2.0/32"))
		require.NoError(t, err)
		nextHop, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.0.2.254"))
		require.NoError(t, err)
		sourceAddr := netip.MustParseAddr(source)
		return table.NewPath(bgp.RF_IPv4_UC, &table.PeerInfo{
			AS:           65010,
			ID:           sourceAddr,
			Address:      sourceAddr,
			LocalAS:      65001,
			LocalID:      netip.MustParseAddr("1.1.1.1"),
			LocalAddress: netip.MustParseAddr("1.1.1.1"),
		}, bgp.PathNLRI{NLRI: nlri}, false, []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
			bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
				bgp.NewAs4PathParam(2, []uint32{65010}),
			}),
			nextHop,
		}, time.Now(), false)
	}
	requireNoOutgoing := func() {
		t.Helper()
		select {
		case o := <-p.fsm.outgoingCh.Out():
			t.Fatalf("unexpected outbound paths: %#v", o)
		case <-time.After(100 * time.Millisecond):
		}
	}
	requireOutgoing := func() []*table.Path {
		t.Helper()
		select {
		case o := <-p.fsm.outgoingCh.Out():
			msg, ok := o.(*fsmOutgoingMsg)
			require.True(t, ok)
			paths := make([]*table.Path, 0, len(msg.Paths))
			for _, path := range msg.Paths {
				if path != nil && !path.IsEOR() {
					paths = append(paths, path)
				}
			}
			return paths
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for outbound add-path soft-reset paths")
			return nil
		}
	}
	setExportDefault := func(action api.RouteAction) {
		t.Helper()
		err := s.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{
			Assignment: &api.PolicyAssignment{
				Name:          table.GLOBAL_RIB_NAME,
				Direction:     api.PolicyDirection_POLICY_DIRECTION_EXPORT,
				DefaultAction: action,
			},
		})
		require.NoError(t, err)
	}

	advertised := makeSourcePath("10.0.0.2")
	neverAdvertised := makeSourcePath("10.0.0.3")

	setExportDefault(api.RouteAction_ROUTE_ACTION_ACCEPT)
	s.propagateUpdate(nil, []*table.Path{advertised})
	paths := requireOutgoing()
	require.Len(t, paths, 1)
	require.False(t, paths[0].IsWithdraw)
	require.Equal(t, advertised.LocalID(), paths[0].LocalID())

	s.propagateUpdate(nil, []*table.Path{neverAdvertised})
	require.NotEqual(t, advertised.LocalID(), neverAdvertised.LocalID())
	requireNoOutgoing()

	setExportDefault(api.RouteAction_ROUTE_ACTION_REJECT)
	require.NoError(t, s.softResetOut(peerAddr.String(), bgp.RF_IPv4_UC, false))
	paths = requireOutgoing()
	require.Len(t, paths, 1)
	require.True(t, paths[0].IsWithdraw)
	require.Equal(t, "192.0.2.0/32", paths[0].GetPrefix())
	require.Equal(t, advertised.LocalID(), paths[0].LocalID())
	require.NotEqual(t, neverAdvertised.LocalID(), paths[0].LocalID())

	require.NoError(t, s.softResetOut(peerAddr.String(), bgp.RF_IPv4_UC, false))
	requireNoOutgoing()
}

func TestRTCMembershipSerializesTriggeredVPNUpdates(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)

	peerAddr := netip.MustParseAddr("10.0.0.1")
	p := newPeerandInfo(t, 65001, 65002, peerAddr.String(), s.globalRib)
	p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
	p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{
		bgp.RF_RTC_UC:      bgp.BGP_ADD_PATH_NONE,
		bgp.RF_IPv4_VPN:    bgp.BGP_ADD_PATH_NONE,
		bgp.RF_IPv6_VPN:    bgp.BGP_ADD_PATH_NONE,
		bgp.RF_FS_IPv4_VPN: bgp.BGP_ADD_PATH_NONE,
		bgp.RF_FS_IPv6_VPN: bgp.BGP_ADD_PATH_NONE,
	})
	t.Cleanup(func() {
		cleanInfiniteChannel(p.fsm.outgoingCh)
		require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
	})

	_, rt, err := parseRDRT("65001:100")
	require.NoError(t, err)
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.0.2.254"))
	require.NoError(t, err)
	rtcPath := table.NewPath(bgp.RF_RTC_UC, p.peerInfo.Load(), bgp.PathNLRI{
		NLRI: bgp.NewRouteTargetMembershipNLRI(65001, rt),
	}, false, []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		nh,
	}, time.Now(), false)
	require.NotNil(t, rtcPath)

	p.routeRefreshInProgress.Lock()
	locked := true
	defer func() {
		if locked {
			p.routeRefreshInProgress.Unlock()
		}
	}()

	done := make(chan struct{})
	go func() {
		s.processRTCMembership(p, rtcPath)
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("RTC-triggered VPN update completed while route refresh was in progress")
	case <-time.After(200 * time.Millisecond):
	}

	p.routeRefreshInProgress.Unlock()
	locked = false

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RTC-triggered VPN update did not complete after route refresh finished")
	}
}

func TestRTCMembershipDuplicateUpdatesAreNoop(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)

	peerAddr := netip.MustParseAddr("10.0.0.1")
	p := newPeerandInfo(t, 65001, 65002, peerAddr.String(), s.globalRib)
	p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
	p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{
		bgp.RF_RTC_UC:   bgp.BGP_ADD_PATH_NONE,
		bgp.RF_IPv4_VPN: bgp.BGP_ADD_PATH_NONE,
	})
	t.Cleanup(func() {
		cleanInfiniteChannel(p.fsm.outgoingCh)
		require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
	})

	rd, rt, err := parseRDRT("65001:100")
	require.NoError(t, err)
	labels := bgp.NewMPLSLabelStack(100)
	vpnNlri, err := bgp.NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix("192.0.2.0/24"), *labels, rd)
	require.NoError(t, err)
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.0.2.254"))
	require.NoError(t, err)
	vpnPath := table.NewPath(bgp.RF_IPv4_VPN, nil, bgp.PathNLRI{NLRI: vpnNlri}, false, []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		nh,
		bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{rt}),
	}, time.Now(), false)
	require.NotNil(t, vpnPath)
	require.NotEmpty(t, s.globalRib.Update(vpnPath))

	rtcPath := table.NewPath(bgp.RF_RTC_UC, p.peerInfo.Load(), bgp.PathNLRI{
		NLRI: bgp.NewRouteTargetMembershipNLRI(65001, rt),
	}, false, []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		nh,
	}, time.Now(), false)
	require.NotNil(t, rtcPath)

	// The helpers take t so that a failure inside a subtest is reported
	// against that subtest. Capturing the outer t would call FailNow on the
	// parent from the subtest goroutine, which testing rejects.
	requireOutgoing := func(t *testing.T, withdraw bool) {
		t.Helper()
		select {
		case o := <-p.fsm.outgoingCh.Out():
			msg, ok := o.(*fsmOutgoingMsg)
			require.True(t, ok)
			require.Len(t, msg.Paths, 1)
			require.Equal(t, withdraw, msg.Paths[0].IsWithdraw)
			require.Equal(t, "65001:100:192.0.2.0/24", msg.Paths[0].GetPrefix())
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for RTC-triggered VPN paths")
		}
	}
	requireNoOutgoing := func(t *testing.T) {
		t.Helper()
		select {
		case o := <-p.fsm.outgoingCh.Out():
			t.Fatalf("unexpected outbound paths after duplicate RTC update: %#v", o)
		case <-time.After(100 * time.Millisecond):
		}
	}

	t.Run("duplicate withdraw is noop", func(t *testing.T) {
		s.processRTCMembership(p, rtcPath)
		requireOutgoing(t, false)

		withdraw := rtcPath.Clone(true)
		s.processRTCMembership(p, withdraw)
		requireOutgoing(t, true)

		s.processRTCMembership(p, withdraw)
		requireNoOutgoing(t)
	})

	t.Run("duplicate announce is noop", func(t *testing.T) {
		s.processRTCMembership(p, rtcPath)
		requireOutgoing(t, false)

		s.processRTCMembership(p, rtcPath)
		requireNoOutgoing(t)
	})
}

// A withdraw of the default RT membership must withdraw the VPN paths that the
// peer was sent and can no longer receive. It must not withdraw a path that is
// still covered by another RT, and it must not touch a path that was never sent.
func TestRTCMembershipDefaultWithdraw(t *testing.T) {
	ctx := context.Background()

	rd, rt100, err := parseRDRT("65001:100")
	require.NoError(t, err)
	_, rt200, err := parseRDRT("65001:200")
	require.NoError(t, err)
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.0.2.254"))
	require.NoError(t, err)

	setup := func(t *testing.T) (*BgpServer, *peer) {
		t.Helper()
		s := NewBgpServer()
		go s.Serve()
		err := s.StartBgp(ctx, &api.StartBgpRequest{
			Global: &api.Global{
				Asn:        65001,
				RouterId:   "1.1.1.1",
				ListenPort: -1,
			},
		})
		require.NoError(t, err)

		p := newPeerandInfo(t, 65001, 65002, "10.0.0.1", s.globalRib)
		p.policy = s.policy
		p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
		p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{
			bgp.RF_RTC_UC:   bgp.BGP_ADD_PATH_NONE,
			bgp.RF_IPv4_VPN: bgp.BGP_ADD_PATH_NONE,
		})
		t.Cleanup(func() {
			cleanInfiniteChannel(p.fsm.outgoingCh)
			require.NoError(t, s.StopBgp(ctx, &api.StopBgpRequest{}))
		})

		for _, v := range []struct {
			prefix string
			rt     bgp.ExtendedCommunityInterface
		}{
			{"192.0.2.0/24", rt100},
			{"198.51.100.0/24", rt200},
		} {
			nlri, err := bgp.NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix(v.prefix), *bgp.NewMPLSLabelStack(100), rd)
			require.NoError(t, err)
			path := table.NewPath(bgp.RF_IPv4_VPN, nil, bgp.PathNLRI{NLRI: nlri}, false, []bgp.PathAttributeInterface{
				bgp.NewPathAttributeOrigin(0),
				nh,
				bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{v.rt}),
			}, time.Now(), false)
			require.NotEmpty(t, s.globalRib.Update(path))
		}
		return s, p
	}

	rtcPath := func(p *peer, rt bgp.ExtendedCommunityInterface) *table.Path {
		as := uint32(65002)
		if rt == nil {
			as = 0
		}
		return table.NewPath(bgp.RF_RTC_UC, p.peerInfo.Load(), bgp.PathNLRI{
			NLRI: bgp.NewRouteTargetMembershipNLRI(as, rt),
		}, false, []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
			nh,
		}, time.Now(), false)
	}

	// collect returns the paths queued for the peer, as "prefix" for an
	// advertisement and "-prefix" for a withdrawal.
	collect := func(t *testing.T, p *peer) []string {
		t.Helper()
		var got []string
		for {
			select {
			case o := <-p.fsm.outgoingCh.Out():
				msg, ok := o.(*fsmOutgoingMsg)
				require.True(t, ok)
				for _, path := range msg.Paths {
					if path.IsWithdraw {
						got = append(got, "-"+path.GetPrefix())
					} else {
						got = append(got, path.GetPrefix())
					}
				}
			case <-time.After(200 * time.Millisecond):
				slices.Sort(got)
				return got
			}
		}
	}

	t.Run("withdraws what was sent", func(t *testing.T) {
		s, p := setup(t)
		def := rtcPath(p, nil)

		s.processRTCMembership(p, def)
		require.Equal(t, []string{"65001:100:192.0.2.0/24", "65001:100:198.51.100.0/24"}, collect(t, p))

		s.processRTCMembership(p, def.Clone(true))
		require.Equal(t, []string{"-65001:100:192.0.2.0/24", "-65001:100:198.51.100.0/24"}, collect(t, p))
	})

	t.Run("keeps a path covered by another RT", func(t *testing.T) {
		s, p := setup(t)
		def := rtcPath(p, nil)

		s.processRTCMembership(p, rtcPath(p, rt100))
		require.Equal(t, []string{"65001:100:192.0.2.0/24"}, collect(t, p))
		s.processRTCMembership(p, def)
		collect(t, p)

		s.processRTCMembership(p, def.Clone(true))
		require.Equal(t, []string{"-65001:100:198.51.100.0/24"}, collect(t, p))
	})

	t.Run("does not touch a path that was never sent", func(t *testing.T) {
		s, p := setup(t)
		def := rtcPath(p, nil)

		err := s.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{
			Assignment: &api.PolicyAssignment{
				Name:          table.GLOBAL_RIB_NAME,
				Direction:     api.PolicyDirection_POLICY_DIRECTION_EXPORT,
				DefaultAction: api.RouteAction_ROUTE_ACTION_REJECT,
			},
		})
		require.NoError(t, err)

		s.processRTCMembership(p, def)
		require.Empty(t, collect(t, p))

		s.processRTCMembership(p, def.Clone(true))
		require.Empty(t, collect(t, p))
	})
}

// An RT membership shorter than /96 is a prefix of the Route Target. When it
// is advertised, the peer must get the VPN paths that the prefix contains,
// and when it is withdrawn, the peer must lose the ones it got through it,
// including the ones that were sent after the membership arrived.
func TestRTCMembershipPrefix(t *testing.T) {
	ctx := context.Background()
	peerAddr := netip.MustParseAddr("10.0.0.1")
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.0.2.254"))
	require.NoError(t, err)
	rd, err := bgp.ParseRouteDistinguisher("65001:1")
	require.NoError(t, err)

	setup := func(t *testing.T) (*BgpServer, *peer) {
		t.Helper()
		s := NewBgpServer()
		go s.Serve()
		err := s.StartBgp(ctx, &api.StartBgpRequest{
			Global: &api.Global{
				Asn:        65001,
				RouterId:   "1.1.1.1",
				ListenPort: -1,
			},
		})
		require.NoError(t, err)

		p := newPeerandInfo(t, 65001, 65002, peerAddr.String(), s.globalRib)
		p.policy = s.policy
		p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
		p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{
			bgp.RF_RTC_UC:   bgp.BGP_ADD_PATH_NONE,
			bgp.RF_IPv4_VPN: bgp.BGP_ADD_PATH_NONE,
		})
		err = s.mgmtOperation(func() error {
			s.neighborMap[peerAddr] = p
			return nil
		}, true)
		require.NoError(t, err)
		t.Cleanup(func() {
			err := s.mgmtOperation(func() error {
				delete(s.neighborMap, peerAddr)
				return nil
			}, false)
			require.NoError(t, err)
			cleanInfiniteChannel(p.fsm.outgoingCh)
			require.NoError(t, s.StopBgp(ctx, &api.StopBgpRequest{}))
		})
		return s, p
	}

	vpnPath := func(t *testing.T, prefix, rt string) *table.Path {
		t.Helper()
		ec, err := bgp.ParseRouteTarget(rt)
		require.NoError(t, err)
		nlri, err := bgp.NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix(prefix), *bgp.NewMPLSLabelStack(100), rd)
		require.NoError(t, err)
		return table.NewPath(bgp.RF_IPv4_VPN, nil, bgp.PathNLRI{NLRI: nlri}, false, []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
			nh,
			bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{ec}),
		}, time.Now(), false)
	}
	rtcPath := func(t *testing.T, p *peer, s string) *table.Path {
		t.Helper()
		nlri, err := bgp.ParseRouteTargetMembershipNLRI(s)
		require.NoError(t, err)
		return table.NewPath(bgp.RF_RTC_UC, p.peerInfo.Load(), bgp.PathNLRI{NLRI: nlri}, false, []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
			nh,
		}, time.Now(), false)
	}
	// collect returns the VPN prefixes queued for the peer, with "-" in
	// front of a withdrawal.
	collect := func(t *testing.T, p *peer) []string {
		t.Helper()
		var got []string
		for {
			select {
			case o := <-p.fsm.outgoingCh.Out():
				msg, ok := o.(*fsmOutgoingMsg)
				require.True(t, ok)
				for _, path := range msg.Paths {
					if path.IsEOR() || path.GetFamily() != bgp.RF_IPv4_VPN {
						continue
					}
					prefix := path.GetNlri().(*bgp.LabeledVPNIPAddrPrefix).Prefix.String()
					if path.IsWithdraw {
						prefix = "-" + prefix
					}
					got = append(got, prefix)
				}
			case <-time.After(200 * time.Millisecond):
				slices.Sort(got)
				return got
			}
		}
	}
	// The RIB holds two paths with a Route Target of AS 65000 and one of
	// AS 65003.
	addRIB := func(t *testing.T, s *BgpServer) {
		t.Helper()
		for _, path := range []*table.Path{
			vpnPath(t, "10.0.1.0/24", "65000:100"),
			vpnPath(t, "10.0.2.0/24", "65000:200"),
			vpnPath(t, "10.0.3.0/24", "65003:100"),
		} {
			require.NotEmpty(t, s.globalRib.Update(path))
		}
	}

	t.Run("announce and withdraw", func(t *testing.T) {
		s, p := setup(t)
		addRIB(t, s)
		as65000 := rtcPath(t, p, "65002:65000:0/64")

		s.processRTCMembership(p, as65000)
		require.Equal(t, []string{"10.0.1.0/24", "10.0.2.0/24"}, collect(t, p))

		// A path that arrives later is sent through the same membership.
		s.propagateUpdate(nil, []*table.Path{vpnPath(t, "10.0.4.0/24", "65000:300")})
		require.Equal(t, []string{"10.0.4.0/24"}, collect(t, p))

		s.processRTCMembership(p, as65000.Clone(true))
		require.Equal(t, []string{"-10.0.1.0/24", "-10.0.2.0/24", "-10.0.4.0/24"}, collect(t, p))
	})

	t.Run("a prefix that is already covered changes nothing", func(t *testing.T) {
		s, p := setup(t)
		addRIB(t, s)
		s.processRTCMembership(p, rtcPath(t, p, "65002:65000:0/64"))
		collect(t, p)

		rt100 := rtcPath(t, p, "65002:65000:100")
		s.processRTCMembership(p, rt100)
		require.Empty(t, collect(t, p))
		s.processRTCMembership(p, rt100.Clone(true))
		require.Empty(t, collect(t, p))
	})

	t.Run("a shorter prefix over a longer one", func(t *testing.T) {
		s, p := setup(t)
		addRIB(t, s)
		s.processRTCMembership(p, rtcPath(t, p, "65002:65000:100"))
		require.Equal(t, []string{"10.0.1.0/24"}, collect(t, p))

		// 10.0.1.0/24 was sent already, so only the other path goes out,
		// and it is the only one that goes away with the /64.
		as65000 := rtcPath(t, p, "65002:65000:0/64")
		s.processRTCMembership(p, as65000)
		require.Equal(t, []string{"10.0.2.0/24"}, collect(t, p))
		s.processRTCMembership(p, as65000.Clone(true))
		require.Equal(t, []string{"-10.0.2.0/24"}, collect(t, p))
	})
}

func TestPropagateUpdateUsesPrefixBuckets(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	blockedPath := makePath(t, "192.0.2.0/32", "192.0.2.254", 0)
	blockedBucket := s.shared.propagateBucket(blockedPath)
	var differentBucketPath *table.Path
	for i := 1; i < 255; i++ {
		prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), 32).String()
		path := makePath(t, prefix, "192.0.2.254", 0)
		if s.shared.propagateBucket(path) != blockedBucket {
			differentBucketPath = path
			break
		}
	}
	require.NotNil(t, differentBucketPath)

	blockedBucket.Lock()
	locked := true
	defer func() {
		if locked {
			blockedBucket.Unlock()
		}
	}()

	samePrefixDone := make(chan struct{})
	go func() {
		s.propagateUpdate(nil, []*table.Path{blockedPath})
		close(samePrefixDone)
	}()

	select {
	case <-samePrefixDone:
		t.Fatal("same-prefix propagation completed while its bucket was held")
	case <-time.After(200 * time.Millisecond):
	}

	differentPrefixDone := make(chan struct{})
	go func() {
		s.propagateUpdate(nil, []*table.Path{differentBucketPath})
		close(differentPrefixDone)
	}()

	select {
	case <-differentPrefixDone:
	case <-time.After(time.Second):
		t.Fatal("different-prefix propagation did not complete while another bucket was held")
	}

	blockedBucket.Unlock()
	locked = false

	select {
	case <-samePrefixDone:
	case <-time.After(time.Second):
		t.Fatal("same-prefix propagation did not complete after its bucket was released")
	}
}

func TestPropagateUpdateSerializesConcurrentLiveDeltas(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)

	peerAddr := netip.MustParseAddr("10.0.0.1")
	target := newPeerandInfo(t, 65001, 65002, peerAddr.String(), s.globalRib)
	target.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
	target.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{
		bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_SEND,
	})

	const pathCount = 64
	target.fsm.lock.Lock()
	conf := target.fsm.pConf.ReadCopy()
	foundFamily := false
	for i := range conf.AfiSafis {
		if conf.AfiSafis[i].State.Family != bgp.RF_IPv4_UC {
			continue
		}
		conf.AfiSafis[i].AddPaths.Config.SendMax = pathCount
		conf.AfiSafis[i].AddPaths.State.SendMax = pathCount
		foundFamily = true
	}
	target.fsm.pConf.Update(&conf)
	target.fsm.lock.Unlock()
	require.True(t, foundFamily)

	err = s.mgmtOperation(func() error {
		s.neighborMap[peerAddr] = target
		return nil
	}, true)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := s.mgmtOperation(func() error {
			delete(s.neighborMap, peerAddr)
			return nil
		}, false)
		require.NoError(t, err)
		cleanInfiniteChannel(target.fsm.outgoingCh)
		require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
	})

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range pathCount {
		prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), 32).String()
		path := makePath(t, prefix, "192.0.2.254", 0)
		wg.Add(1)
		go func(path *table.Path) {
			defer wg.Done()
			<-start
			s.propagateUpdate(nil, []*table.Path{path})
		}(path)
	}
	close(start)
	wg.Wait()

	sentPathCount := 0
	target.sentPaths.Range(func(_, _ any) bool {
		sentPathCount++
		return true
	})
	require.Equal(t, pathCount, sentPathCount)
}

// passEstablished passes the Established state change of the session of p
// to the server, as the FSM does before the session can end. handleFSMMessage
// takes the old state from pConf. Supply an OPEN too, so concurrent API
// readers can inspect the Established session.
//
// The peers of these tests are admin down, and the server clears the session
// state of an admin down peer at the end of each state change. It is put
// back, so that the next state change is handled as the end of the session.
func passEstablished(t *testing.T, s *BgpServer, p *peer) {
	t.Helper()
	p.fsm.lock.Lock()
	if p.fsm.recvOpen == nil {
		p.fsm.recvOpen = grOpen(t)
	}
	p.fsm.lock.Unlock()
	s.handleFSMMessage(p, &fsmMsg{
		MsgType:     fsmMsgStateChange,
		MsgData:     bgp.BGP_FSM_ESTABLISHED,
		StateReason: newfsmStateReason(fsmOpenMsgNegotiated, nil, nil),
		timestamp:   time.Now(),
	})
	p.fsm.lock.Lock()
	conf := p.fsm.pConf.ReadCopy()
	conf.State.SessionState = oc.SESSION_STATE_ESTABLISHED
	p.fsm.pConf.Update(&conf)
	p.fsm.lock.Unlock()
}

// TestHandleFSMMessage_GRStateRace tests concurrent access to the graceful
// restart state and timers of the peers: sessions that end as a graceful
// restart, the timers that are stopped, and the state that is read for the
// API.
func TestHandleFSMMessage_GRStateRace(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	numPeers := 20
	peers := make([]*peer, numPeers)

	// Create peers with LLGR enabled
	for i := range numPeers {
		peerAddr := netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})
		err = s.AddPeer(context.Background(), &api.AddPeerRequest{
			Peer: &api.Peer{
				Conf: &api.PeerConf{
					NeighborAddress: peerAddr.String(),
					PeerAsn:         uint32(65002 + i),
					AdminDown:       true,
				},
				GracefulRestart: &api.GracefulRestart{
					Enabled:          true,
					RestartTime:      120,
					LonglivedEnabled: true,
				},
				AfiSafis: []*api.AfiSafi{
					{
						Config: &api.AfiSafiConfig{
							Family: &api.Family{
								Afi:  api.Family_AFI_IP,
								Safi: api.Family_SAFI_UNICAST,
							},
							Enabled: true,
						},
						MpGracefulRestart: &api.MpGracefulRestart{
							Config: &api.MpGracefulRestartConfig{
								Enabled: true,
							},
						},
						LongLivedGracefulRestart: &api.LongLivedGracefulRestart{
							Config: &api.LongLivedGracefulRestartConfig{
								Enabled:     true,
								RestartTime: 1, // 1 second for faster test
							},
						},
					},
				},
			},
		})
		require.NoError(t, err)

		err = s.mgmtOperation(func() error {
			peers[i] = s.neighborMap[peerAddr]
			return nil
		}, true)
		require.NoError(t, err)
		require.NotNil(t, peers[i])
	}

	// The sessions negotiated graceful restart with a Restart Time of zero,
	// so the timers start and expire while the test runs.
	for _, p := range peers {
		p.fsm.lock.Lock()
		conf := p.fsm.pConf.ReadCopy()
		conf.GracefulRestart.State.Enabled = true
		conf.GracefulRestart.State.LongLivedEnabled = true
		p.fsm.pConf.Update(&conf)
		p.fsm.capMap = map[bgp.BGPCapabilityCode][]bgp.ParameterCapabilityInterface{
			bgp.BGP_CAP_GRACEFUL_RESTART: {bgp.NewCapGracefulRestart(false, false, 0, []*bgp.CapGracefulRestartTuple{
				bgp.NewCapGracefulRestartTuple(bgp.RF_IPv4_UC, true),
			})},
			bgp.BGP_CAP_LONG_LIVED_GRACEFUL_RESTART: {bgp.NewCapLongLivedGracefulRestart([]*bgp.CapLongLivedGracefulRestartTuple{
				bgp.NewCapLongLivedGracefulRestartTuple(bgp.RF_IPv4_UC, true, 1),
			})},
		}
		p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_NONE})
		p.fsm.lock.Unlock()
	}

	var wg sync.WaitGroup

	// Goroutines that end sessions as a graceful restart
	for i := range numPeers / 2 {
		wg.Add(1)
		go func(peerIdx int) {
			defer wg.Done()
			p := peers[peerIdx]

			for range 50 {
				// Establish the session, then end it as a graceful
				// restart.
				passEstablished(t, s, p)
				s.handleFSMMessage(p, &fsmMsg{
					MsgType:     fsmMsgStateChange,
					MsgData:     bgp.BGP_FSM_IDLE,
					StateReason: newfsmStateReason(fsmReadFailed, nil, nil),
					timestamp:   time.Now(),
				})
				time.Sleep(2 * time.Millisecond)
			}
		}(i)
	}

	// Goroutines that stop the timers and read the state of the same peers
	for i := range numPeers / 2 {
		wg.Add(1)
		go func(peerIdx int) {
			defer wg.Done()
			p := peers[peerIdx]

			for range 50 {
				p.stopGRTimers()
				_ = s.toConfig(p, false)
				time.Sleep(2 * time.Millisecond)
			}
		}(i)
	}

	wg.Wait()
}

// TestHandleFSMMessage_Parallel_StateChanges tests various state change scenarios in parallel
func TestHandleFSMMessage_Parallel_StateChanges(t *testing.T) {
	numPeers := 80

	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	// Create multiple peers
	peers := make([]*peer, numPeers)
	for i := range numPeers {
		peerAddr := netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})
		err = s.AddPeer(context.Background(), &api.AddPeerRequest{
			Peer: &api.Peer{
				Conf: &api.PeerConf{
					NeighborAddress: peerAddr.String(),
					PeerAsn:         uint32(65002 + i),
					AdminDown:       true, // Keep peer admin down to prevent actual connections
				},
				AfiSafis: []*api.AfiSafi{
					{
						Config: &api.AfiSafiConfig{
							Family: &api.Family{
								Afi:  api.Family_AFI_IP,
								Safi: api.Family_SAFI_UNICAST,
							},
							Enabled: true,
						},
					},
				},
			},
		})
		require.NoError(t, err)

		err = s.mgmtOperation(func() error {
			peers[i] = s.neighborMap[peerAddr]
			return nil
		}, true)
		require.NoError(t, err)
		require.NotNil(t, peers[i])
	}

	// Run handleFSMMessage for all peers concurrently with state changes
	var wg sync.WaitGroup
	for i := range numPeers {
		wg.Add(1)
		go func(peerIdx int) {
			defer wg.Done()
			p := peers[peerIdx]

			// Test state change from IDLE to ACTIVE
			msg1 := &fsmMsg{
				MsgType:     fsmMsgStateChange,
				MsgData:     bgp.BGP_FSM_ACTIVE,
				StateReason: newfsmStateReason(fsmIdleTimerExpired, nil, nil),
				timestamp:   time.Now(),
			}
			s.handleFSMMessage(p, msg1)

			// Small delay
			time.Sleep(10 * time.Millisecond)

			// Test state change from ACTIVE to IDLE
			msg2 := &fsmMsg{
				MsgType:     fsmMsgStateChange,
				MsgData:     bgp.BGP_FSM_IDLE,
				StateReason: newfsmStateReason(fsmAdminDown, nil, nil),
				timestamp:   time.Now(),
			}
			s.handleFSMMessage(p, msg2)
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Verify all peers are still in the neighbor map
	err = s.mgmtOperation(func() error {
		assert.Equal(t, numPeers, len(s.neighborMap))
		return nil
	}, true)
	require.NoError(t, err)
}

// TestHandleFSMMessage_StateChange_AdminDown tests admin down state changes
func TestHandleFSMMessage_StateChange_AdminDown(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	peerAddr := "2.2.2.2"
	err = s.AddPeer(context.Background(), &api.AddPeerRequest{
		Peer: &api.Peer{
			Conf: &api.PeerConf{
				NeighborAddress: peerAddr,
				PeerAsn:         65002,
				AdminDown:       true,
			},
			AfiSafis: []*api.AfiSafi{
				{
					Config: &api.AfiSafiConfig{
						Family: &api.Family{
							Afi:  api.Family_AFI_IP,
							Safi: api.Family_SAFI_UNICAST,
						},
						Enabled: true,
					},
				},
			},
		},
	})
	require.NoError(t, err)

	var p *peer
	err = s.mgmtOperation(func() error {
		p = s.neighborMap[netip.MustParseAddr(peerAddr)]
		return nil
	}, true)
	require.NoError(t, err)
	require.NotNil(t, p)

	// Set peer admin down state
	p.fsm.adminState.Store(adminStateDown)

	// Send state change to IDLE with admin down
	msg := &fsmMsg{
		MsgType:     fsmMsgStateChange,
		MsgData:     bgp.BGP_FSM_IDLE,
		StateReason: newfsmStateReason(fsmAdminDown, nil, nil),
		timestamp:   time.Now(),
	}

	s.handleFSMMessage(p, msg)

	// Verify counters were cleared (admin down clears counters)
	conf := *p.fsm.pConf.ReadOnly()
	assert.Equal(t, int64(0), conf.Timers.State.Uptime)
	assert.Equal(t, int64(0), conf.Timers.State.Downtime)
}

// TestHandleFSMMessage_StateChange_IdleToActive tests state transition from IDLE to ACTIVE
func TestHandleFSMMessage_StateChange_IdleToActive(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	peerAddr := "2.2.2.2"
	err = s.AddPeer(context.Background(), &api.AddPeerRequest{
		Peer: &api.Peer{
			Conf: &api.PeerConf{
				NeighborAddress: peerAddr,
				PeerAsn:         65002,
				AdminDown:       true,
			},
			AfiSafis: []*api.AfiSafi{
				{
					Config: &api.AfiSafiConfig{
						Family: &api.Family{
							Afi:  api.Family_AFI_IP,
							Safi: api.Family_SAFI_UNICAST,
						},
						Enabled: true,
					},
				},
			},
		},
	})
	require.NoError(t, err)

	var p *peer
	err = s.mgmtOperation(func() error {
		p = s.neighborMap[netip.MustParseAddr(peerAddr)]
		return nil
	}, true)
	require.NoError(t, err)
	require.NotNil(t, p)

	// Send state change from IDLE to ACTIVE
	msg := &fsmMsg{
		MsgType:     fsmMsgStateChange,
		MsgData:     bgp.BGP_FSM_ACTIVE,
		StateReason: newfsmStateReason(fsmIdleTimerExpired, nil, nil),
		timestamp:   time.Now(),
	}

	initialState := p.State()
	s.handleFSMMessage(p, msg)

	// Verify state change was processed (state changed from initial)
	conf := *p.fsm.pConf.ReadOnly()
	assert.NotEqual(t, int(initialState), conf.State.SessionState.ToInt())
}

// TestHandleFSMMessage_PeerDownDropsQueuedOutgoing tests that the messages
// the last session did not send are dropped, so that the next session does
// not send them.
func TestHandleFSMMessage_PeerDownDropsQueuedOutgoing(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	peerAddr := "2.2.2.2"
	err = s.AddPeer(context.Background(), &api.AddPeerRequest{
		Peer: &api.Peer{
			Conf: &api.PeerConf{
				NeighborAddress: peerAddr,
				PeerAsn:         65002,
				AdminDown:       true,
			},
			AfiSafis: []*api.AfiSafi{
				{
					Config: &api.AfiSafiConfig{
						Family: &api.Family{
							Afi:  api.Family_AFI_IP,
							Safi: api.Family_SAFI_UNICAST,
						},
						Enabled: true,
					},
				},
			},
		},
	})
	require.NoError(t, err)

	var p *peer
	err = s.mgmtOperation(func() error {
		p = s.neighborMap[netip.MustParseAddr(peerAddr)]
		return nil
	}, true)
	require.NoError(t, err)
	require.NotNil(t, p)

	// The session was established and it goes down with messages still
	// queued.
	passEstablished(t, s, p)
	for range 100 {
		p.fsm.outgoingCh.In() <- &fsmOutgoingMsg{}
	}

	msg := &fsmMsg{
		MsgType:     fsmMsgStateChange,
		MsgData:     bgp.BGP_FSM_IDLE,
		StateReason: newfsmStateReason(fsmHoldTimerExpired, nil, nil),
		timestamp:   time.Now(),
	}
	s.handleFSMMessage(p, msg)

	assert.Equal(t, 0, p.fsm.outgoingCh.Len())
}

// TestHandleFSMMessage_ConcurrentAccess tests concurrent access to handleFSMMessage
func TestHandleFSMMessage_ConcurrentAccess(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	// Create three peers
	numPeers := 80
	peers := make([]*peer, numPeers)

	for i := range numPeers {
		peerAddr := netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})
		err = s.AddPeer(context.Background(), &api.AddPeerRequest{
			Peer: &api.Peer{
				Conf: &api.PeerConf{
					NeighborAddress: peerAddr.String(),
					PeerAsn:         uint32(65002 + i),
					AdminDown:       true,
				},
				AfiSafis: []*api.AfiSafi{
					{
						Config: &api.AfiSafiConfig{
							Family: &api.Family{
								Afi:  api.Family_AFI_IP,
								Safi: api.Family_SAFI_UNICAST,
							},
							Enabled: true,
						},
					},
				},
			},
		})
		require.NoError(t, err)

		err = s.mgmtOperation(func() error {
			peers[i] = s.neighborMap[peerAddr]
			return nil
		}, true)
		require.NoError(t, err)
		require.NotNil(t, peers[i])
	}

	// Send multiple state change messages concurrently to all peers
	var wg sync.WaitGroup
	iterations := 300

	for i := range numPeers {
		for j := range iterations {
			wg.Add(1)
			go func(peerIdx, iter int) {
				defer wg.Done()
				p := peers[peerIdx]

				// Alternate between IDLE and ACTIVE
				var targetState bgp.FSMState
				var reason fsmStateReasonType
				if iter%2 == 0 {
					targetState = bgp.BGP_FSM_ACTIVE
					reason = fsmIdleTimerExpired
				} else {
					targetState = bgp.BGP_FSM_IDLE
					reason = fsmAdminDown
				}

				msg := &fsmMsg{
					MsgType:     fsmMsgStateChange,
					MsgData:     targetState,
					StateReason: newfsmStateReason(reason, nil, nil),
					timestamp:   time.Now(),
				}

				s.handleFSMMessage(p, msg)
			}(i, j)
		}
	}

	wg.Wait()

	// Verify all peers are still in the neighbor map
	err = s.mgmtOperation(func() error {
		assert.Equal(t, numPeers, len(s.neighborMap))
		for _, p := range peers {
			assert.NotNil(t, p)
		}
		return nil
	}, true)
	require.NoError(t, err)
}

// TestHandleFSMMessage_WithGracefulRestart tests graceful restart scenarios
func TestHandleFSMMessage_WithGracefulRestart(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	peerAddr := "2.2.2.2"
	err = s.AddPeer(context.Background(), &api.AddPeerRequest{
		Peer: &api.Peer{
			Conf: &api.PeerConf{
				NeighborAddress: peerAddr,
				PeerAsn:         65002,
				AdminDown:       true,
			},
			GracefulRestart: &api.GracefulRestart{
				Enabled:     true,
				RestartTime: 120,
			},
			AfiSafis: []*api.AfiSafi{
				{
					Config: &api.AfiSafiConfig{
						Family: &api.Family{
							Afi:  api.Family_AFI_IP,
							Safi: api.Family_SAFI_UNICAST,
						},
						Enabled: true,
					},
					MpGracefulRestart: &api.MpGracefulRestart{
						Config: &api.MpGracefulRestartConfig{
							Enabled: true,
						},
					},
				},
			},
		},
	})
	require.NoError(t, err)

	var p *peer
	err = s.mgmtOperation(func() error {
		p = s.neighborMap[netip.MustParseAddr(peerAddr)]
		return nil
	}, true)
	require.NoError(t, err)
	require.NotNil(t, p)

	// Verify graceful restart config is set
	conf := *p.fsm.pConf.ReadOnly()
	assert.True(t, conf.GracefulRestart.Config.Enabled, "GR should be enabled in config")

	// Send state change message
	msg := &fsmMsg{
		MsgType:     fsmMsgStateChange,
		MsgData:     bgp.BGP_FSM_IDLE,
		StateReason: newfsmStateReason(fsmReadFailed, nil, nil),
		timestamp:   time.Now(),
	}

	s.handleFSMMessage(p, msg)

	// Wait a bit for processing
	time.Sleep(50 * time.Millisecond)

	// Verify message was processed without panic
	assert.NotNil(t, p)
}

// TestHandleFSMMessage_DynamicNeighborRace tests the race condition in stopNeighbor with dynamic neighbors
func TestHandleFSMMessage_DynamicNeighborRace(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	// Add a peer group for dynamic neighbors
	err = s.AddPeerGroup(context.Background(), &api.AddPeerGroupRequest{
		PeerGroup: &api.PeerGroup{
			Conf: &api.PeerGroupConf{
				PeerGroupName: "dynamic-group",
				PeerAsn:       65002,
			},
			AfiSafis: []*api.AfiSafi{
				{
					Config: &api.AfiSafiConfig{
						Family: &api.Family{
							Afi:  api.Family_AFI_IP,
							Safi: api.Family_SAFI_UNICAST,
						},
						Enabled: true,
					},
				},
			},
		},
	})
	require.NoError(t, err)

	// Add dynamic neighbor configuration
	err = s.AddDynamicNeighbor(context.Background(), &api.AddDynamicNeighborRequest{
		DynamicNeighbor: &api.DynamicNeighbor{
			Prefix:    "10.0.0.0/24",
			PeerGroup: "dynamic-group",
		},
	})
	require.NoError(t, err)

	numPeers := 80
	peers := make([]*peer, numPeers)

	// Manually create dynamic peers by adding them directly
	// Dynamic peers have invalid NeighborAddress
	for i := range numPeers {
		peerAddr := netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})

		err = s.mgmtOperation(func() error {
			// Get peer group
			pg, ok := s.peerGroupMap["dynamic-group"]
			if !ok {
				return nil
			}

			// Create a dynamic peer using the internal function
			peer := newDynamicPeer(&s.bgpConfig.Global, peerAddr.String(), pg.Conf, s.globalRib, s.policy, s.logger)
			if peer != nil {
				s.neighborMap[peerAddr] = peer
				peers[i] = peer

				// Start the peer's FSM
				peer.fsm.start(s.shutdownWG, func(msg *fsmMsg) {
					s.handleFSMMessage(peer, msg)
				})
			}
			return nil
		}, true)
		require.NoError(t, err)
	}

	// Wait a bit for FSMs to start
	time.Sleep(50 * time.Millisecond)

	// Now trigger ESTABLISHED -> IDLE transitions in parallel for dynamic peers
	// This should trigger stopNeighbor which modifies s.neighborMap
	var wg sync.WaitGroup
	for i := range numPeers {
		if peers[i] == nil {
			continue
		}
		wg.Add(1)
		go func(peerIdx int) {
			defer wg.Done()
			p := peers[peerIdx]

			// Verify it's a dynamic neighbor
			if !p.isDynamicNeighbor() {
				t.Errorf("Peer %d is not dynamic - cannot trigger stopNeighbor race", peerIdx)
				return
			}

			t.Logf("Peer %d is dynamic, triggering stopNeighbor", peerIdx)

			passEstablished(t, s, p)

			// Send state change from ESTABLISHED to IDLE (non-graceful)
			// This should trigger stopNeighbor which deletes from s.neighborMap
			msg := &fsmMsg{
				MsgType:     fsmMsgStateChange,
				MsgData:     bgp.BGP_FSM_IDLE,
				StateReason: newfsmStateReason(fsmAdminDown, nil, nil), // non-graceful
				timestamp:   time.Now(),
			}

			s.handleFSMMessage(p, msg)
		}(i)
	}

	wg.Wait()
}

// TestHandleFSMMessage_NeighborMapIterationRace tests race when iterating neighborMap during EOR processing
func TestHandleFSMMessage_NeighborMapIterationRace(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	numPeers := 80
	peers := make([]*peer, numPeers)

	// Create peers with graceful restart enabled
	for i := range numPeers {
		peerAddr := netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})
		err = s.AddPeer(context.Background(), &api.AddPeerRequest{
			Peer: &api.Peer{
				Conf: &api.PeerConf{
					NeighborAddress: peerAddr.String(),
					PeerAsn:         uint32(65002 + i),
					AdminDown:       true,
				},
				GracefulRestart: &api.GracefulRestart{
					Enabled:     true,
					RestartTime: 120,
				},
				AfiSafis: []*api.AfiSafi{
					{
						Config: &api.AfiSafiConfig{
							Family: &api.Family{
								Afi:  api.Family_AFI_IP,
								Safi: api.Family_SAFI_UNICAST,
							},
							Enabled: true,
						},
						MpGracefulRestart: &api.MpGracefulRestart{
							Config: &api.MpGracefulRestartConfig{
								Enabled: true,
							},
						},
					},
				},
			},
		})
		require.NoError(t, err)

		err = s.mgmtOperation(func() error {
			peers[i] = s.neighborMap[peerAddr]
			return nil
		}, true)
		require.NoError(t, err)
		require.NotNil(t, peers[i])
	}

	// Run parallel operations that trigger neighborMap iteration
	var wg sync.WaitGroup

	// Goroutine 1: Trigger state transitions that cause EOR processing
	// This will iterate over s.neighborMap at lines 1568, 1576, 1684, 1692
	for i := range numPeers / 2 {
		wg.Add(1)
		go func(peerIdx int) {
			defer wg.Done()
			p := peers[peerIdx]

			// Set to ESTABLISHED to enable EOR processing path
			p.fsm.lock.Lock()
			conf := p.fsm.pConf.ReadCopy()
			conf.State.SessionState = "established"
			conf.Timers.State.Uptime = time.Now().Add(-1 * time.Minute).Unix()
			conf.GracefulRestart.State.LocalRestarting = true
			p.fsm.pConf.Update(&conf)
			p.fsm.lock.Unlock()

			// Send BGP UPDATE with EOR to trigger the neighborMap iteration
			eorMsg := bgp.NewBGPUpdateMessage(nil, nil, nil)
			msg := &fsmMsg{
				MsgType:     fsmMsgBGPMessage,
				MsgData:     eorMsg,
				StateReason: nil,
				timestamp:   time.Now(),
			}

			s.handleFSMMessage(p, msg)
		}(i)
	}

	// Goroutine 2: Add/remove dynamic neighbors to cause concurrent map modifications
	// This simulates the race between iteration and modification
	for i := numPeers / 2; i < numPeers; i++ {
		wg.Add(1)
		go func(peerIdx int) {
			defer wg.Done()
			p := peers[peerIdx]

			// Rapidly change states to stress the system
			for range 300 {
				msg := &fsmMsg{
					MsgType:     fsmMsgStateChange,
					MsgData:     bgp.BGP_FSM_ACTIVE,
					StateReason: newfsmStateReason(fsmIdleTimerExpired, nil, nil),
					timestamp:   time.Now(),
				}
				s.handleFSMMessage(p, msg)
				time.Sleep(5 * time.Millisecond)

				msg = &fsmMsg{
					MsgType:     fsmMsgStateChange,
					MsgData:     bgp.BGP_FSM_IDLE,
					StateReason: newfsmStateReason(fsmAdminDown, nil, nil),
					timestamp:   time.Now(),
				}
				s.handleFSMMessage(p, msg)
				time.Sleep(5 * time.Millisecond)
			}
		}(i)
	}

	wg.Wait()
}

// TestHandleFSMMessage_PropagateUpdateRace tests race in propagateUpdate's neighborMap iteration
func TestHandleFSMMessage_PropagateUpdateRace(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	// Add peer group for dynamic neighbors
	err = s.AddPeerGroup(context.Background(), &api.AddPeerGroupRequest{
		PeerGroup: &api.PeerGroup{
			Conf: &api.PeerGroupConf{
				PeerGroupName: "test-group",
				PeerAsn:       65002,
			},
			AfiSafis: []*api.AfiSafi{
				{
					Config: &api.AfiSafiConfig{
						Family: &api.Family{
							Afi:  api.Family_AFI_IP,
							Safi: api.Family_SAFI_UNICAST,
						},
						Enabled: true,
					},
				},
			},
		},
	})
	require.NoError(t, err)

	err = s.AddDynamicNeighbor(context.Background(), &api.AddDynamicNeighborRequest{
		DynamicNeighbor: &api.DynamicNeighbor{
			Prefix:    "10.0.0.0/24",
			PeerGroup: "test-group",
		},
	})
	require.NoError(t, err)

	numPeers := 80
	peers := make([]*peer, numPeers)
	dynamicPeers := make([]bool, numPeers)

	// Create mix of regular and dynamic peers
	for i := range numPeers {
		peerAddr := netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})
		isDynamic := i < numPeers/2 // half of the peers are dynamic

		if isDynamic {
			// Create dynamic peer
			err = s.mgmtOperation(func() error {
				pg, ok := s.peerGroupMap["test-group"]
				if !ok {
					return nil
				}
				peer := newDynamicPeer(&s.bgpConfig.Global, peerAddr.String(), pg.Conf, s.globalRib, s.policy, s.logger)
				if peer != nil {
					s.neighborMap[peerAddr] = peer
					peers[i] = peer
					dynamicPeers[i] = true
					peer.fsm.start(s.shutdownWG, func(msg *fsmMsg) {
						s.handleFSMMessage(peer, msg)
					})
				}
				return nil
			}, true)
		} else {
			// Create regular peer
			err = s.AddPeer(context.Background(), &api.AddPeerRequest{
				Peer: &api.Peer{
					Conf: &api.PeerConf{
						NeighborAddress: peerAddr.String(),
						PeerAsn:         uint32(65002 + i),
						AdminDown:       true,
					},
					AfiSafis: []*api.AfiSafi{
						{
							Config: &api.AfiSafiConfig{
								Family: &api.Family{
									Afi:  api.Family_AFI_IP,
									Safi: api.Family_SAFI_UNICAST,
								},
								Enabled: true,
							},
						},
					},
				},
			})
			require.NoError(t, err)

			err = s.mgmtOperation(func() error {
				peers[i] = s.neighborMap[peerAddr]
				return nil
			}, true)
		}
		require.NoError(t, err)
	}

	time.Sleep(50 * time.Millisecond)

	var wg sync.WaitGroup

	// Goroutines that trigger propagateUpdate (which iterates neighborMap at line 1209)
	for i := numPeers / 2; i < numPeers; i++ {
		if peers[i] == nil {
			continue
		}
		wg.Add(1)
		go func(peerIdx int) {
			defer wg.Done()
			p := peers[peerIdx]

			passEstablished(t, s, p)

			// Trigger state change that calls propagateUpdate
			msg := &fsmMsg{
				MsgType:     fsmMsgStateChange,
				MsgData:     bgp.BGP_FSM_IDLE,
				StateReason: newfsmStateReason(fsmHoldTimerExpired, nil, nil),
				timestamp:   time.Now(),
			}

			s.handleFSMMessage(p, msg)
		}(i)
	}

	// Concurrently delete dynamic neighbors (triggers stopNeighbor)
	for i := range numPeers / 2 {
		if peers[i] == nil || !dynamicPeers[i] {
			continue
		}
		wg.Add(1)
		go func(peerIdx int) {
			defer wg.Done()
			p := peers[peerIdx]

			if !p.isDynamicNeighbor() {
				return
			}

			passEstablished(t, s, p)

			// This will call stopNeighbor which deletes from neighborMap
			// While other goroutines are iterating over it
			msg := &fsmMsg{
				MsgType:     fsmMsgStateChange,
				MsgData:     bgp.BGP_FSM_IDLE,
				StateReason: newfsmStateReason(fsmAdminDown, nil, nil), // non-graceful
				timestamp:   time.Now(),
			}

			s.handleFSMMessage(p, msg)
		}(i)
	}

	wg.Wait()
}

// TestHandleFSMMessage_ParallelDifferentPeers tests handleFSMMessage with different peers in parallel
func TestHandleFSMMessage_ParallelDifferentPeers(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)
	defer s.StopBgp(context.Background(), &api.StopBgpRequest{})

	numPeers := 80
	peers := make([]*peer, numPeers)

	// Create peers with different configurations
	for i := range numPeers {
		peerAddr := netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})
		enableGR := i%2 == 0 // Enable GR for even numbered peers

		peerConfig := &api.Peer{
			Conf: &api.PeerConf{
				NeighborAddress: peerAddr.String(),
				PeerAsn:         uint32(65002 + i),
				AdminDown:       true,
			},
			AfiSafis: []*api.AfiSafi{
				{
					Config: &api.AfiSafiConfig{
						Family: &api.Family{
							Afi:  api.Family_AFI_IP,
							Safi: api.Family_SAFI_UNICAST,
						},
						Enabled: true,
					},
				},
			},
		}

		if enableGR {
			peerConfig.GracefulRestart = &api.GracefulRestart{
				Enabled:     true,
				RestartTime: 120,
			}
			peerConfig.AfiSafis[0].MpGracefulRestart = &api.MpGracefulRestart{
				Config: &api.MpGracefulRestartConfig{
					Enabled: true,
				},
			}
		}

		err = s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: peerConfig})
		require.NoError(t, err)

		err = s.mgmtOperation(func() error {
			peers[i] = s.neighborMap[peerAddr]
			return nil
		}, true)
		require.NoError(t, err)
		require.NotNil(t, peers[i])
	}

	// Process messages for all peers in parallel
	var wg sync.WaitGroup
	for i := range numPeers {
		wg.Add(1)
		go func(peerIdx int) {
			defer wg.Done()
			p := peers[peerIdx]

			// Send multiple state changes
			states := []bgp.FSMState{
				bgp.BGP_FSM_ACTIVE,
				bgp.BGP_FSM_IDLE,
				bgp.BGP_FSM_ACTIVE,
				bgp.BGP_FSM_IDLE,
			}

			for _, state := range states {
				reason := fsmIdleTimerExpired
				if state == bgp.BGP_FSM_IDLE {
					reason = fsmAdminDown
				}

				msg := &fsmMsg{
					MsgType:     fsmMsgStateChange,
					MsgData:     state,
					StateReason: newfsmStateReason(reason, nil, nil),
					timestamp:   time.Now(),
				}

				s.handleFSMMessage(p, msg)
				time.Sleep(5 * time.Millisecond)
			}
		}(i)
	}

	wg.Wait()

	// Verify all peers are still present and functional
	err = s.mgmtOperation(func() error {
		assert.Equal(t, numPeers, len(s.neighborMap))
		for i, p := range peers {
			assert.NotNil(t, p, "peer %d should not be nil", i)
			// Verify GR config settings are still correct
			conf := *p.fsm.pConf.ReadOnly()
			if i%2 == 0 {
				assert.True(t, conf.GracefulRestart.Config.Enabled, "peer %d should have GR enabled in config", i)
			} else {
				assert.False(t, conf.GracefulRestart.Config.Enabled, "peer %d should not have GR enabled in config", i)
			}
		}
		return nil
	}, true)
	require.NoError(t, err)
}

// grTestPeer sets up a peer whose session negotiated graceful restart with
// the OPEN open from the peer, for ipv4-unicast and ipv6-unicast, with one
// route in each family. Long-lived graceful restart is configured too, so it
// is negotiated if open has the capability.
func grTestPeer(t *testing.T, open *bgp.BGPMessage) (*BgpServer, *peer) {
	t.Helper()
	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 65000, RouterId: "1.1.1.1", ListenPort: -1},
	}))

	// Build the peer without its FSM goroutine, like the tests above.
	peerAddr := netip.MustParseAddr("10.0.0.1")
	p := newPeerandInfo(t, 65000, 65001, peerAddr.String(), s.globalRib)
	require.NoError(t, s.mgmtOperation(func() error {
		s.neighborMap[peerAddr] = p
		return nil
	}, true))
	t.Cleanup(func() {
		require.NoError(t, s.mgmtOperation(func() error {
			if s.neighborMap[peerAddr] == p {
				delete(s.neighborMap, peerAddr)
			}
			return nil
		}, false))
		p.stopGRTimers()
		require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
	})

	m := NewMockConnection()
	m.SetRemoteAddr(peerAddr.String())
	t.Cleanup(func() { m.Close() })
	p.fsm.conn = m

	p.fsm.lock.Lock()
	conf := p.fsm.pConf.ReadCopy()
	conf.Config.LocalAs = 65000
	conf.GracefulRestart.Config.Enabled = true
	conf.GracefulRestart.Config.LongLivedEnabled = true
	conf.AfiSafis = []oc.AfiSafi{
		grAfiSafi(oc.AFI_SAFI_TYPE_IPV4_UNICAST, bgp.RF_IPv4_UC),
		grAfiSafi(oc.AFI_SAFI_TYPE_IPV6_UNICAST, bgp.RF_IPv6_UC),
	}
	p.fsm.pConf.Update(&conf)
	p.fsm.lock.Unlock()
	p.adjRibIn = table.NewAdjRib(logger, []bgp.Family{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC})

	grEstablish(t, s, p, open)
	grAddRoute(t, s, p, "10.10.10.0/24")
	grAddRoute(t, s, p, "2001:db8:10::/64")
	return s, p
}

// grAddRoute adds a route from the peer to its Adj-RIB-In, in the server
// loop because the graceful restart timers change it there too.
func grAddRoute(t *testing.T, s *BgpServer, p *peer, prefix string) {
	t.Helper()
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	require.NoError(t, err)
	family := bgp.RF_IPv4_UC
	if netip.MustParsePrefix(prefix).Addr().Is6() {
		family = bgp.RF_IPv6_UC
	}
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{65001})}),
	}
	require.NoError(t, s.mgmtOperation(func() error {
		p.adjRibIn.Update([]*table.Path{
			table.NewPath(family, p.peerInfo.Load(), bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false),
		})
		return nil
	}, false))
}

// grEstablish establishes the session of p with the OPEN open from the peer.
func grEstablish(t *testing.T, s *BgpServer, p *peer, open *bgp.BGPMessage) {
	t.Helper()
	p.fsm.recvOpen = open
	reason := newfsmStateReason(fsmOpenMsgNegotiated, nil, nil)
	p.fsm.stateChange(bgp.BGP_FSM_ESTABLISHED, reason)
	s.handleFSMMessage(p, &fsmMsg{
		MsgType:     fsmMsgStateChange,
		MsgData:     bgp.BGP_FSM_ESTABLISHED,
		StateReason: reason,
		timestamp:   time.Now(),
	})
	p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
}

// grStateChange passes a state change of the session of p to the server.
func grStateChange(t *testing.T, s *BgpServer, p *peer, next bgp.FSMState, reason *fsmStateReason) {
	t.Helper()
	p.fsm.stateChange(next, reason)
	p.fsm.state.Store(next)
	s.handleFSMMessage(p, &fsmMsg{
		MsgType:     fsmMsgStateChange,
		MsgData:     next,
		StateReason: reason,
		timestamp:   time.Now(),
	})
}

// grDown ends the session of p as a graceful restart.
func grDown(t *testing.T, s *BgpServer, p *peer) {
	t.Helper()
	grStateChange(t, s, p, bgp.BGP_FSM_IDLE, newfsmStateReason(fsmReadFailed, nil, nil))
}

func grEOR(s *BgpServer, p *peer, f bgp.Family) {
	s.handleFSMMessage(p, &fsmMsg{MsgType: fsmMsgBGPMessage, MsgData: bgp.NewEndOfRib(f), timestamp: time.Now()})
}

// grCount returns the number of routes of family f from the peer.
func grCount(s *BgpServer, p *peer, f bgp.Family) int {
	n := 0
	_ = s.mgmtOperation(func() error {
		n = p.adjRibIn.Count([]bgp.Family{f})
		return nil
	}, false)
	return n
}

// grStale returns the number of stale routes of family f from the peer.
func grStale(s *BgpServer, p *peer, f bgp.Family) int {
	n := 0
	_ = s.mgmtOperation(func() error {
		for _, path := range p.adjRibIn.PathList([]bgp.Family{f}, false) {
			if path.IsStale() {
				n++
			}
		}
		return nil
	}, false)
	return n
}

// grBoth is a Graceful Restart Capability for ipv4 and ipv6 with the F bit,
// and the given Restart Time.
func grBoth(restartTime uint16) bgp.ParameterCapabilityInterface {
	return bgp.NewCapGracefulRestart(false, false, restartTime, []*bgp.CapGracefulRestartTuple{
		bgp.NewCapGracefulRestartTuple(bgp.RF_IPv4_UC, true),
		bgp.NewCapGracefulRestartTuple(bgp.RF_IPv6_UC, true),
	})
}

// grLLGRv4 is a Long-Lived Graceful Restart Capability for ipv4 with the F
// bit and the given LLST.
func grLLGRv4(llst uint32) bgp.ParameterCapabilityInterface {
	return bgp.NewCapLongLivedGracefulRestart([]*bgp.CapLongLivedGracefulRestartTuple{
		bgp.NewCapLongLivedGracefulRestartTuple(bgp.RF_IPv4_UC, true, llst),
	})
}

// When the session ends as a graceful restart, the routes of the families in
// the Graceful Restart Capability are kept as stale. The End-of-RIB marker of
// a family removes the stale routes of that family only (RFC 4724 Section
// 4.2), and the restart ends with the last marker.
func TestHandleFSMMessage_EORDropsStalePerFamily(t *testing.T) {
	s, p := grTestPeer(t, grOpen(t, grBoth(120)))
	grDown(t, s, p)
	require.True(t, p.grRestarting())
	require.Equal(t, 1, grStale(s, p, bgp.RF_IPv4_UC))
	require.Equal(t, 1, grStale(s, p, bgp.RF_IPv6_UC))

	grEstablish(t, s, p, grOpen(t, grBoth(120)))
	grEOR(s, p, bgp.RF_IPv4_UC)
	assert.Equal(t, 0, grCount(s, p, bgp.RF_IPv4_UC))
	assert.Equal(t, 1, grCount(s, p, bgp.RF_IPv6_UC))
	assert.True(t, p.grRestarting())

	grEOR(s, p, bgp.RF_IPv6_UC)
	assert.Equal(t, 0, grCount(s, p, bgp.RF_IPv6_UC))
	assert.False(t, p.grRestarting())
}

// When the session is established again after a graceful restart, the
// stale routes of a family that the peer did not preserve are removed at
// once (RFC 4724 Section 4.2). The restart is over when no stale routes are
// kept.
func TestHandleFSMMessage_ReestablishDropsNotPreservedStale(t *testing.T) {
	gr := func(tuples ...*bgp.CapGracefulRestartTuple) bgp.ParameterCapabilityInterface {
		return bgp.NewCapGracefulRestart(true, false, 120, tuples)
	}
	tests := []struct {
		name           string
		caps           []bgp.ParameterCapabilityInterface
		wantV4, wantV6 int
		wantRestarting bool
	}{
		{"both preserved", []bgp.ParameterCapabilityInterface{gr(
			bgp.NewCapGracefulRestartTuple(bgp.RF_IPv4_UC, true),
			bgp.NewCapGracefulRestartTuple(bgp.RF_IPv6_UC, true),
		)}, 1, 1, true},
		{"F bit clear for ipv4", []bgp.ParameterCapabilityInterface{gr(
			bgp.NewCapGracefulRestartTuple(bgp.RF_IPv4_UC, false),
			bgp.NewCapGracefulRestartTuple(bgp.RF_IPv6_UC, true),
		)}, 0, 1, true},
		{"ipv4 not in the capability", []bgp.ParameterCapabilityInterface{gr(
			bgp.NewCapGracefulRestartTuple(bgp.RF_IPv6_UC, true),
		)}, 0, 1, true},
		{"F bit clear for both", []bgp.ParameterCapabilityInterface{gr(
			bgp.NewCapGracefulRestartTuple(bgp.RF_IPv4_UC, false),
			bgp.NewCapGracefulRestartTuple(bgp.RF_IPv6_UC, false),
		)}, 0, 0, false},
		{"no capability", nil, 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, p := grTestPeer(t, grOpen(t, grBoth(120)))
			grDown(t, s, p)

			grEstablish(t, s, p, grOpen(t, tt.caps...))

			assert.Equal(t, tt.wantV4, grCount(s, p, bgp.RF_IPv4_UC))
			assert.Equal(t, tt.wantV6, grCount(s, p, bgp.RF_IPv6_UC))
			assert.Equal(t, tt.wantRestarting, p.grRestarting())
		})
	}
}

// grLLGRStarted sets up a peer whose ipv4 routes are in the long-lived stale
// period: the session negotiated a Restart Time of zero and LLGR for ipv4
// with the given LLST, and ended as a graceful restart. The ipv6 routes are
// removed when the Restart Time expires.
func grLLGRStarted(t *testing.T, llst uint32) (*BgpServer, *peer) {
	t.Helper()
	s, p := grTestPeer(t, grOpen(t, grBoth(0), grLLGRv4(llst)))
	grDown(t, s, p)
	require.Eventually(t, func() bool {
		var phase gr.Phase
		_ = s.mgmtOperation(func() error {
			p.grMu.Lock()
			phase = p.grHelper.Phase(bgp.RF_IPv4_UC)
			p.grMu.Unlock()
			return nil
		}, false)
		return phase == gr.LLGRStale
	}, 5*time.Second, 10*time.Millisecond)
	require.Equal(t, 1, grStale(s, p, bgp.RF_IPv4_UC))
	var llgrStale bool
	require.NoError(t, s.mgmtOperation(func() error {
		llgrStale = p.adjRibIn.PathList([]bgp.Family{bgp.RF_IPv4_UC}, false)[0].IsLLGRStale()
		return nil
	}, false))
	require.True(t, llgrStale)
	require.Equal(t, 0, grCount(s, p, bgp.RF_IPv6_UC))
	return s, p
}

// A family in the long-lived stale period stays in it when the session is
// established again and the Long-Lived Graceful Restart Capability preserves
// it, even if it is not in the Graceful Restart Capability. The End-of-RIB
// marker of another family does not end it. Its own marker does.
func TestHandleFSMMessage_ReestablishLongLivedStale(t *testing.T) {
	s, p := grLLGRStarted(t, 3600)

	grEstablish(t, s, p, grOpen(t,
		bgp.NewCapGracefulRestart(true, false, 120, []*bgp.CapGracefulRestartTuple{
			bgp.NewCapGracefulRestartTuple(bgp.RF_IPv6_UC, true),
		}),
		grLLGRv4(3600)))
	assert.Equal(t, 1, grStale(s, p, bgp.RF_IPv4_UC))
	assert.True(t, p.grRestarting())

	grEOR(s, p, bgp.RF_IPv6_UC)
	assert.Equal(t, 1, grStale(s, p, bgp.RF_IPv4_UC))
	assert.True(t, p.grRestarting())

	grEOR(s, p, bgp.RF_IPv4_UC)
	assert.Equal(t, 0, grStale(s, p, bgp.RF_IPv4_UC))
	assert.False(t, p.grRestarting())
}

// A family in the long-lived stale period is removed when the session is
// established again without the Long-Lived Graceful Restart Capability
// (RFC 9494 Section 4.2).
func TestHandleFSMMessage_ReestablishDropsNotPreservedLongLivedStale(t *testing.T) {
	s, p := grLLGRStarted(t, 3600)

	grEstablish(t, s, p, grOpen(t, grBoth(120)))
	assert.Equal(t, 0, grCount(s, p, bgp.RF_IPv4_UC))
	assert.False(t, p.grRestarting())
}

// When the LLST expires after the session is established again, only the
// stale routes are removed. The routes of the new session stay.
func TestHandleFSMMessage_LLSTExpiryKeepsNewRoutes(t *testing.T) {
	s, p := grLLGRStarted(t, 1)

	grEstablish(t, s, p, grOpen(t, grBoth(120), grLLGRv4(1)))
	grAddRoute(t, s, p, "10.10.20.0/24")
	require.Equal(t, 2, grCount(s, p, bgp.RF_IPv4_UC))

	require.Eventually(t, func() bool {
		return grStale(s, p, bgp.RF_IPv4_UC) == 0
	}, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, 1, grCount(s, p, bgp.RF_IPv4_UC))
}

// A change to Idle during the Restart Time, for example when a connection of
// the returning peer fails in OpenSent, does not end the restart.
func TestHandleFSMMessage_IdleDuringRestartKeepsStale(t *testing.T) {
	s, p := grTestPeer(t, grOpen(t, grBoth(120)))
	grDown(t, s, p)

	grStateChange(t, s, p, bgp.BGP_FSM_ACTIVE, newfsmStateReason(fsmIdleTimerExpired, nil, nil))
	grStateChange(t, s, p, bgp.BGP_FSM_OPENSENT, newfsmStateReason(fsmNewConnection, nil, nil))
	grStateChange(t, s, p, bgp.BGP_FSM_IDLE, newfsmStateReason(fsmReadFailed, nil, nil))

	assert.True(t, p.grRestarting())
	assert.Equal(t, 1, grStale(s, p, bgp.RF_IPv4_UC))
	assert.Equal(t, 1, grStale(s, p, bgp.RF_IPv6_UC))
}

// When the peer is disabled during the Restart Time, the restart is given up
// and the routes of the peer are removed.
func TestHandleFSMMessage_DisableDuringRestart(t *testing.T) {
	s, p := grTestPeer(t, grOpen(t, grBoth(120)))
	grDown(t, s, p)

	require.NoError(t, s.DisablePeer(context.Background(), &api.DisablePeerRequest{Address: "10.0.0.1"}))
	assert.False(t, p.grRestarting())
	assert.Equal(t, 0, grCount(s, p, bgp.RF_IPv4_UC))
	assert.Equal(t, 0, grCount(s, p, bgp.RF_IPv6_UC))
	p.grMu.Lock()
	assert.Nil(t, p.grRestartTimer)
	p.grMu.Unlock()
}

// A dynamic neighbor is deleted when its graceful restart ends with no
// session: at the Restart Time without LLGR, or when the last LLST expires.
func TestHandleFSMMessage_DynamicNeighborAfterRestart(t *testing.T) {
	tests := []struct {
		name string
		open []bgp.ParameterCapabilityInterface
	}{
		{"Restart Time", []bgp.ParameterCapabilityInterface{grBoth(0)}},
		{"LLST", []bgp.ParameterCapabilityInterface{grBoth(0), grLLGRv4(1)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, p := grTestPeer(t, grOpen(t, tt.open...))
			p.fsm.lock.Lock()
			conf := p.fsm.pConf.ReadCopy()
			conf.Config.NeighborAddress = netip.Addr{}
			p.fsm.pConf.Update(&conf)
			p.fsm.lock.Unlock()
			require.True(t, p.isDynamicNeighbor())
			// stopNeighbor() stops the FSM. The FSM of the test peer does
			// not run, so give it only what stopping needs.
			ctx, cancel := context.WithCancel(t.Context())
			p.fsm.h = &fsmHandler{fsm: p.fsm, ctx: ctx, ctxCancel: cancel}

			grDown(t, s, p)
			require.Eventually(t, func() bool {
				var found bool
				_ = s.mgmtOperation(func() error {
					found = s.neighborMap[netip.MustParseAddr("10.0.0.1")] == p
					return nil
				}, false)
				return !found
			}, 5*time.Second, 10*time.Millisecond)
			assert.False(t, p.grRestarting())
			assert.Equal(t, 0, grCount(s, p, bgp.RF_IPv4_UC))
		})
	}
}

// The initial dump of a route server client is built in the Established
// handler, before the FSM stores the Established state. A secondary-route
// client gets its routes and the End-of-RIB marker like any other client, and
// nothing is sent to it by route propagation before it is established.
func TestGetBestFromLocalSecondaryRouteBeforeEstablished(t *testing.T) {
	for _, secondary := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal", true: "secondary"}[secondary], func(t *testing.T) {
			ctx := context.Background()
			s := NewBgpServer()
			go s.Serve()
			require.NoError(t, s.StartBgp(ctx, &api.StartBgpRequest{
				Global: &api.Global{Asn: 65001, RouterId: "1.1.1.1", ListenPort: -1},
			}))

			newClient := func(address string, asn uint32, secondary bool) *peer {
				p := newPeerandInfo(t, 65001, asn, address, s.rsRib)
				p.fsm.lock.Lock()
				conf := p.fsm.pConf.ReadCopy()
				conf.RouteServer.Config.RouteServerClient = true
				conf.RouteServer.Config.SecondaryRoute = secondary
				conf.GracefulRestart.State.Enabled = true
				p.fsm.pConf.Update(&conf)
				p.fsm.lock.Unlock()
				p.tableId = p.ID()
				p.policy = s.policy
				p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_NONE})
				return p
			}
			targetAddr := netip.MustParseAddr("10.0.0.1")
			sourceAddr := netip.MustParseAddr("10.0.0.2")
			target := newClient(targetAddr.String(), 65002, secondary)
			// As in the Established handler: the state is stored after it.
			target.fsm.state.Store(bgp.BGP_FSM_OPENCONFIRM)
			source := newClient(sourceAddr.String(), 65003, false)
			source.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
			require.NoError(t, s.policy.SetPolicyAssignment(source.TableID(), table.POLICY_DIRECTION_IMPORT, nil, table.ROUTE_TYPE_ACCEPT))
			require.NoError(t, s.policy.SetPolicyAssignment(target.TableID(), table.POLICY_DIRECTION_EXPORT, nil, table.ROUTE_TYPE_ACCEPT))
			require.NoError(t, s.mgmtOperation(func() error {
				s.neighborMap[targetAddr] = target
				s.neighborMap[sourceAddr] = source
				return nil
			}, true))
			t.Cleanup(func() {
				require.NoError(t, s.mgmtOperation(func() error {
					delete(s.neighborMap, targetAddr)
					delete(s.neighborMap, sourceAddr)
					return nil
				}, false))
				cleanInfiniteChannel(target.fsm.outgoingCh)
				cleanInfiniteChannel(source.fsm.outgoingCh)
				require.NoError(t, s.StopBgp(ctx, &api.StopBgpRequest{}))
			})

			nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("192.0.2.0/24"))
			require.NoError(t, err)
			nextHop, err := bgp.NewPathAttributeNextHop(source.peerInfo.Load().Address)
			require.NoError(t, err)
			attrs := []bgp.PathAttributeInterface{
				bgp.NewPathAttributeOrigin(0),
				bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{65003})}),
				nextHop,
			}
			path := table.NewPath(bgp.RF_IPv4_UC, source.peerInfo.Load(), bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
			require.NoError(t, s.mgmtOperation(func() error {
				s.propagateUpdate(source, []*table.Path{path})
				return nil
			}, true))
			// Not established: nothing is sent by propagation.
			assert.Equal(t, 0, target.fsm.outgoingCh.Len())

			var got []*table.Path
			require.NoError(t, s.mgmtOperation(func() error {
				s.getBestFromLocalCallback(target, []bgp.Family{bgp.RF_IPv4_UC}, true, true, func(paths, _ []*table.Path) {
					got = paths
				})
				return nil
			}, true))
			require.Len(t, got, 2)
			assert.Equal(t, "192.0.2.0/24", got[0].GetNlri().String())
			assert.False(t, got[0].IsEOR())
			assert.True(t, got[1].IsEOR())
		})
	}
}

// localRestartPeer adds a peer that takes part in our own graceful restart,
// like a peer of the configuration file when gobgpd is started with -r. The
// peer has no FSM goroutine. It is configured for ipv4-unicast and
// ipv6-unicast with graceful restart, and a deferral time of deferral.
func localRestartPeer(t *testing.T, s *BgpServer, address string, deferral uint16) *peer {
	t.Helper()
	addr := netip.MustParseAddr(address)
	p := newPeerandInfo(t, 65000, 65001, address, s.globalRib)
	m := NewMockConnection()
	m.SetRemoteAddr(address)
	t.Cleanup(func() { m.Close() })
	p.fsm.conn = m

	p.fsm.lock.Lock()
	conf := p.fsm.pConf.ReadCopy()
	conf.Config.LocalAs = 65000
	conf.GracefulRestart.Config.Enabled = true
	conf.GracefulRestart.Config.DeferralTime = deferral
	conf.GracefulRestart.State.LocalRestarting = true
	conf.AfiSafis = []oc.AfiSafi{
		grAfiSafi(oc.AFI_SAFI_TYPE_IPV4_UNICAST, bgp.RF_IPv4_UC),
		grAfiSafi(oc.AFI_SAFI_TYPE_IPV6_UNICAST, bgp.RF_IPv6_UC),
	}
	p.fsm.pConf.Update(&conf)
	p.fsm.lock.Unlock()
	p.adjRibIn = table.NewAdjRib(s.logger, []bgp.Family{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC})

	require.NoError(t, s.mgmtOperation(func() error {
		s.neighborMap[addr] = p
		s.restartPeerAdded(p, &conf)
		return nil
	}, true))
	t.Cleanup(func() {
		require.NoError(t, s.mgmtOperation(func() error {
			if s.neighborMap[addr] == p {
				delete(s.neighborMap, addr)
				s.restartEvent(func(r *gr.Restart) gr.RestartActions { return r.PeerRemoved(p.ID()) })
			}
			return nil
		}, false))
		cleanInfiniteChannel(p.fsm.outgoingCh)
	})
	return p
}

// localRestartServer starts a server for the tests of our own graceful
// restart.
func localRestartServer(t *testing.T) *BgpServer {
	t.Helper()
	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 65000, RouterId: "1.1.1.1", ListenPort: -1},
	}))
	t.Cleanup(func() {
		require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
	})
	return s
}

// sentEORs returns the families whose End-of-RIB marker was queued for the
// peer, and drains the queue.
func sentEORs(p *peer) []bgp.Family {
	var eors []bgp.Family
	for {
		select {
		case o := <-p.fsm.outgoingCh.Out():
			for _, path := range o.(*fsmOutgoingMsg).Paths {
				if path != nil && path.IsEOR() {
					eors = append(eors, path.GetFamily())
				}
			}
		case <-time.After(50 * time.Millisecond):
			return eors
		}
	}
}

func localRestarting(p *peer) bool {
	return p.fsm.pConf.ReadOnly().GracefulRestart.State.LocalRestarting
}

// After gobgpd is started with -r, a family is advertised, with the
// End-of-RIB marker, when the marker of the family is received from every
// peer (RFC 4724 Section 4.1). The families are independent.
func TestHandleFSMMessage_LocalRestart(t *testing.T) {
	s := localRestartServer(t)
	a := localRestartPeer(t, s, "10.0.0.1", 360)
	b := localRestartPeer(t, s, "10.0.0.2", 360)
	require.True(t, s.deferred(bgp.RF_IPv4_UC))
	require.True(t, s.deferred(bgp.RF_IPv6_UC))

	grEstablish(t, s, a, grOpen(t, grBoth(120)))
	grEstablish(t, s, b, grOpen(t, grBoth(120)))
	// Nothing is advertised while the families are deferred.
	assert.Empty(t, sentEORs(a))
	assert.Empty(t, sentEORs(b))

	grEOR(s, a, bgp.RF_IPv4_UC)
	assert.True(t, s.deferred(bgp.RF_IPv4_UC))
	assert.Empty(t, sentEORs(a))
	assert.Empty(t, sentEORs(b))

	grEOR(s, b, bgp.RF_IPv4_UC)
	assert.False(t, s.deferred(bgp.RF_IPv4_UC))
	assert.True(t, s.deferred(bgp.RF_IPv6_UC))
	assert.Equal(t, []bgp.Family{bgp.RF_IPv4_UC}, sentEORs(a))
	assert.Equal(t, []bgp.Family{bgp.RF_IPv4_UC}, sentEORs(b))
	assert.True(t, localRestarting(a))
	assert.True(t, localRestarting(b))

	grEOR(s, a, bgp.RF_IPv6_UC)
	grEOR(s, b, bgp.RF_IPv6_UC)
	assert.False(t, s.deferred(bgp.RF_IPv6_UC))
	assert.Equal(t, []bgp.Family{bgp.RF_IPv6_UC}, sentEORs(a))
	assert.Equal(t, []bgp.Family{bgp.RF_IPv6_UC}, sentEORs(b))
	assert.False(t, localRestarting(a))
	assert.False(t, localRestarting(b))
	assert.False(t, s.restart.Restarting())
}

// A peer with the Restart State bit, and a peer without the Graceful Restart
// Capability, are not waited for (RFC 4724 Section 4.1). They get the
// advertisement when the family is released.
func TestHandleFSMMessage_LocalRestartExcludedPeers(t *testing.T) {
	restarted := bgp.NewCapGracefulRestart(true, false, 120, []*bgp.CapGracefulRestartTuple{
		bgp.NewCapGracefulRestartTuple(bgp.RF_IPv4_UC, true),
		bgp.NewCapGracefulRestartTuple(bgp.RF_IPv6_UC, true),
	})
	s := localRestartServer(t)
	a := localRestartPeer(t, s, "10.0.0.1", 360)
	b := localRestartPeer(t, s, "10.0.0.2", 360)
	c := localRestartPeer(t, s, "10.0.0.3", 360)

	grEstablish(t, s, b, grOpen(t, restarted))
	grEstablish(t, s, c, grOpen(t))
	assert.True(t, s.deferred(bgp.RF_IPv4_UC))
	assert.Empty(t, sentEORs(b))
	assert.Empty(t, sentEORs(c))

	grEstablish(t, s, a, grOpen(t, grBoth(120)))
	grEOR(s, a, bgp.RF_IPv4_UC)
	assert.False(t, s.deferred(bgp.RF_IPv4_UC))
	assert.True(t, s.deferred(bgp.RF_IPv6_UC))
	assert.Equal(t, []bgp.Family{bgp.RF_IPv4_UC}, sentEORs(a))
	assert.Equal(t, []bgp.Family{bgp.RF_IPv4_UC}, sentEORs(b))
	// A peer without graceful restart gets no marker.
	assert.Empty(t, sentEORs(c))
}

// A deferral timer releases the peer from the family. The family is
// released when every peer is.
func TestHandleFSMMessage_LocalRestartDeferralTimer(t *testing.T) {
	s := localRestartServer(t)
	a := localRestartPeer(t, s, "10.0.0.1", 1)
	b := localRestartPeer(t, s, "10.0.0.2", 360)
	grEstablish(t, s, a, grOpen(t, grBoth(120)))
	grEstablish(t, s, b, grOpen(t, grBoth(120)))

	// The timers of a expire, but b is waited for.
	require.Eventually(t, func() bool {
		s.restartMu.Lock()
		defer s.restartMu.Unlock()
		_, ok := s.restartTimers[gr.DeferralTimer{Peer: a.ID(), Family: bgp.RF_IPv4_UC}]
		return !ok
	}, 3*time.Second, 50*time.Millisecond)
	assert.True(t, s.deferred(bgp.RF_IPv4_UC))
	grEOR(s, b, bgp.RF_IPv4_UC)
	assert.False(t, s.deferred(bgp.RF_IPv4_UC))
	assert.Equal(t, []bgp.Family{bgp.RF_IPv4_UC}, sentEORs(a))
	assert.Equal(t, []bgp.Family{bgp.RF_IPv4_UC}, sentEORs(b))
}

// A peer whose session ends is not waited for any more.
func TestHandleFSMMessage_LocalRestartPeerDown(t *testing.T) {
	s := localRestartServer(t)
	a := localRestartPeer(t, s, "10.0.0.1", 360)
	b := localRestartPeer(t, s, "10.0.0.2", 360)
	grEstablish(t, s, a, grOpen(t, grBoth(120)))
	grEstablish(t, s, b, grOpen(t, grBoth(120)))
	grEOR(s, a, bgp.RF_IPv4_UC)
	grEOR(s, a, bgp.RF_IPv6_UC)
	require.True(t, s.deferred(bgp.RF_IPv4_UC))

	grStateChange(t, s, b, bgp.BGP_FSM_IDLE, newfsmStateReason(fsmReadFailed, nil, nil))
	assert.False(t, s.deferred(bgp.RF_IPv4_UC))
	assert.False(t, s.deferred(bgp.RF_IPv6_UC))
	assert.ElementsMatch(t, []bgp.Family{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC}, sentEORs(a))
	assert.False(t, localRestarting(a))
}

// The server decides from the reason of the session end and the negotiated
// state whether the session ends as a graceful restart. The peer event
// reports a graceful restart to the API, and BMP gets the real reason.
func TestHandleFSMMessage_GracefulSessionEnd(t *testing.T) {
	notification := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_UPDATE_MESSAGE_ERROR, bgp.BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil)
	hardReset := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_HARD_RESET, nil)
	holdTimer := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED, 0, nil)
	tests := []struct {
		name         string
		reason       *fsmStateReason
		notification bool
		graceful     bool
		wantAPI      api.PeerState_DisconnectReason
		wantBMP      uint8
	}{
		{
			"read failed", newfsmStateReason(fsmReadFailed, nil, nil), false, true,
			api.PeerState_DISCONNECT_REASON_GRACEFUL_RESTART, bmp.BMP_PEER_DOWN_REASON_REMOTE_NO_NOTIFICATION,
		},
		{
			"write failed", newfsmStateReason(fsmWriteFailed, nil, nil), false, true,
			api.PeerState_DISCONNECT_REASON_GRACEFUL_RESTART, bmp.BMP_PEER_DOWN_REASON_REMOTE_NO_NOTIFICATION,
		},
		{
			"hold timer expired", newfsmStateReason(fsmHoldTimerExpired, notificationBody(holdTimer), nil), false, true,
			api.PeerState_DISCONNECT_REASON_GRACEFUL_RESTART, bmp.BMP_PEER_DOWN_REASON_LOCAL_BGP_NOTIFICATION,
		},
		{
			"notification received without N", newfsmStateReason(fsmNotificationRecv, notificationBody(notification), nil), false, false,
			api.PeerState_DISCONNECT_REASON_NOTIFICATION_RECEIVED, bmp.BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION,
		},
		{
			"notification received with N", newfsmStateReason(fsmNotificationRecv, notificationBody(notification), nil), true, true,
			api.PeerState_DISCONNECT_REASON_GRACEFUL_RESTART, bmp.BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION,
		},
		{
			"hard reset received with N", newfsmStateReason(fsmHardReset, notificationBody(hardReset), nil), true, false,
			api.PeerState_DISCONNECT_REASON_HARD_RESET, bmp.BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION,
		},
		{
			"admin down", newfsmStateReason(fsmAdminDown, nil, nil), true, false,
			api.PeerState_DISCONNECT_REASON_ADMIN_DOWN, bmp.BMP_PEER_DOWN_REASON_LOCAL_NO_NOTIFICATION,
		},
		{
			"new connection", newfsmStateReason(fsmNewConnection, nil, nil), false, true,
			api.PeerState_DISCONNECT_REASON_GRACEFUL_RESTART, bmp.BMP_PEER_DOWN_REASON_LOCAL_NO_NOTIFICATION,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, p := grTestPeer(t, grOpen(t, grBoth(120)))
			p.fsm.lock.Lock()
			conf := p.fsm.pConf.ReadCopy()
			require.True(t, conf.GracefulRestart.State.Enabled)
			conf.GracefulRestart.State.NotificationEnabled = tt.notification
			p.fsm.pConf.Update(&conf)
			p.fsm.lock.Unlock()

			// After a new connection, the FSM goes to Active to take it.
			next := bgp.BGP_FSM_IDLE
			if tt.reason.Type == fsmNewConnection {
				next = bgp.BGP_FSM_ACTIVE
			}
			grStateChange(t, s, p, next, tt.reason)

			assert.Equal(t, tt.graceful, p.grRestarting())
			p.grMu.Lock()
			restartTimer := p.grRestartTimer != nil
			p.grMu.Unlock()
			assert.Equal(t, tt.graceful, restartTimer)
			if tt.graceful {
				assert.Equal(t, 1, grStale(s, p, bgp.RF_IPv4_UC))
			} else {
				assert.Equal(t, 0, grCount(s, p, bgp.RF_IPv4_UC))
			}

			e := newWatchEventPeer(p, &fsmMsg{StateReason: tt.reason}, next, bgp.BGP_FSM_ESTABLISHED, apiutil.PEER_EVENT_STATE)
			assert.Equal(t, tt.graceful, e.Graceful)
			reason, message := convertFSMStateReasonToAPI(e.StateReason, e.Graceful)
			assert.Equal(t, tt.wantAPI, reason)
			if tt.graceful {
				assert.Equal(t, "graceful-restart", message)
			}

			m := bmpPeerDown(e, bmp.BMP_PEER_TYPE_GLOBAL, false, 0)
			body := m.Body.(*bmp.BMPPeerDownNotification)
			assert.Equal(t, tt.wantBMP, body.Reason)
			if n := tt.reason.notificationMessage(); n != nil {
				assert.Equal(t, n, body.BGPNotification)
			}
			if tt.reason.Type == fsmNewConnection {
				// FSM Event 17, TcpConnectionConfirmed.
				assert.Equal(t, []byte{0, 17}, body.Data)
			}
		})
	}
}

// A family that is only in the Long-Lived Graceful Restart Capability has a
// Restart Time of zero (RFC 9494 Section 4.2). Its routes get LLGR_STALE and
// its LLST timer starts when the session ends. A family in the Graceful
// Restart Capability waits for the Restart Time.
func TestHandleFSMMessage_LLGROnlyFamily(t *testing.T) {
	s, p := grTestPeer(t, grOpen(t,
		bgp.NewCapGracefulRestart(false, false, 120, []*bgp.CapGracefulRestartTuple{
			bgp.NewCapGracefulRestartTuple(bgp.RF_IPv6_UC, true),
		}),
		grLLGRv4(3600)))
	grDown(t, s, p)

	assert.Equal(t, 1, grStale(s, p, bgp.RF_IPv4_UC))
	assert.Equal(t, 1, grStale(s, p, bgp.RF_IPv6_UC))
	var v4LLGRStale, v6LLGRStale bool
	require.NoError(t, s.mgmtOperation(func() error {
		v4LLGRStale = p.adjRibIn.PathList([]bgp.Family{bgp.RF_IPv4_UC}, false)[0].IsLLGRStale()
		v6LLGRStale = p.adjRibIn.PathList([]bgp.Family{bgp.RF_IPv6_UC}, false)[0].IsLLGRStale()
		return nil
	}, false))
	assert.True(t, v4LLGRStale)
	assert.False(t, v6LLGRStale)

	p.grMu.Lock()
	_, llgrTimer := p.grLLGRTimers[bgp.RF_IPv4_UC]
	restartTimer := p.grRestartTimer != nil
	p.grMu.Unlock()
	assert.True(t, llgrTimer)
	assert.True(t, restartTimer)
}

func TestHandleFSMMessage_InitialUpdateBeforeFSMStore(t *testing.T) {
	for _, tc := range []struct {
		name         string
		localRestart bool
		policyChange bool
	}{
		{"plain_withdrawal", false, false},
		{"plain_policy_change", false, true},
		{"local_restart_withdrawal", true, false},
		{"local_restart_policy_change", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := localRestartServer(t)
			var target *peer
			if tc.localRestart {
				target = localRestartPeer(t, s, "10.0.0.1", 360)
			} else {
				target = initialUpdatePeer(t, s, "10.0.0.1")
			}
			receiver := newPeerandInfo(t, 65001, 65000, "10.0.0.254", s.globalRib)
			t.Cleanup(func() { cleanInfiniteChannel(receiver.fsm.outgoingCh) })
			remoteInfo := *receiver.peerInfo.Load()
			remoteInfo.LocalAddress = netip.MustParseAddr("198.51.100.1")
			receiver.peerInfo.Store(&remoteInfo)

			nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("203.0.113.0/24"))
			require.NoError(t, err)
			nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.0.2.254"))
			require.NoError(t, err)
			path := table.NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh}, time.Now(), false)
			require.NoError(t, s.mgmtOperation(func() error { s.propagateUpdate(nil, []*table.Path{path}); return nil }, true))

			sawRoute := false
			deliver := func() {
				for target.fsm.outgoingCh.Len() > 0 {
					outgoing := (<-target.fsm.outgoingCh.Out()).(*fsmOutgoingMsg)
					for _, update := range table.CreateUpdateMsgFromPaths(outgoing.Paths) {
						wire, err := update.Serialize()
						require.NoError(t, err)
						received, err := bgp.ParseBGPMessage(wire)
						require.NoError(t, err)
						receiver.handleUpdate(&fsmMsg{MsgType: fsmMsgBGPMessage, MsgData: received, timestamp: time.Now()}, nil)
						sawRoute = sawRoute || receiver.adjRibIn.Accepted([]bgp.Family{bgp.RF_IPv4_UC}) > 0
					}
				}
			}
			// In the local-restart cases, the remote R-bit releases the wait.
			target.fsm.state.Store(bgp.BGP_FSM_OPENCONFIRM)
			target.fsm.recvOpen = grOpen(t, bgp.NewCapGracefulRestart(true, false, 120, nil))
			reason := newfsmStateReason(fsmOpenMsgNegotiated, nil, nil)
			target.fsm.stateChange(bgp.BGP_FSM_ESTABLISHED, reason)
			s.handleFSMMessage(target, &fsmMsg{MsgType: fsmMsgStateChange, MsgData: bgp.BGP_FSM_ESTABLISHED, StateReason: reason})

			// Pause the FSM at its callback return, before its state.Store. Another
			// peer's UPDATE processing is allowed to run at this exact boundary.
			require.NoError(t, s.mgmtOperation(func() error {
				if tc.policyChange {
					if err := target.policy.SetPolicyAssignment(target.exportPolicyID, table.POLICY_DIRECTION_EXPORT, nil, table.ROUTE_TYPE_REJECT); err != nil {
						return err
					}
					s.softResetOutPeer(target, bgp.RF_IPv4_UC, false)
				} else {
					s.propagateUpdate(nil, []*table.Path{path.Clone(true)})
				}
				return nil
			}, true))
			target.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
			deliver()
			require.True(t, sawRoute, "initial dump must actually advertise the route")
			expectedLocal := 0
			if tc.policyChange {
				expectedLocal = 1
			}
			require.Len(t, s.globalRib.GetBestPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_UC}), expectedLocal)
			require.Zero(t, receiver.adjRibIn.Accepted([]bgp.Family{bgp.RF_IPv4_UC}), "remote Adj-RIB-In retained a withdrawn route after the initial dump")
		})
	}
}

func initialUpdatePeer(t *testing.T, s *BgpServer, address string) *peer {
	t.Helper()
	p := newPeerandInfo(t, 65000, 65001, address, s.globalRib)
	conn := NewMockConnection()
	conn.SetRemoteAddr(address)
	p.fsm.conn = conn
	addr := netip.MustParseAddr(address)
	require.NoError(t, s.mgmtOperation(func() error {
		s.neighborMap[addr] = p
		return nil
	}, true))
	t.Cleanup(func() {
		require.NoError(t, s.mgmtOperation(func() error {
			delete(s.neighborMap, addr)
			return nil
		}, false))
		conn.Close()
		cleanInfiniteChannel(p.fsm.outgoingCh)
	})
	return p
}
