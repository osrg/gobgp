// Copyright (C) 2026 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
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

func newAddPathRefreshPeer(t *testing.T, limits map[bgp.Family]uint8) (*BgpServer, *peer) {
	t.Helper()
	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{Global: &api.Global{Asn: 65000, RouterId: "1.1.1.1", ListenPort: -1}}))
	target := newPeerandInfo(t, 65000, 65002, "192.0.2.1", s.globalRib)
	target.policy = s.policy
	target.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
	modes := make(map[bgp.Family]bgp.BGPAddPathMode)
	target.fsm.lock.Lock()
	conf := target.fsm.pConf.ReadCopy()
	conf.AfiSafis = nil
	for family, limit := range limits {
		modes[family] = bgp.BGP_ADD_PATH_NONE
		if limit > 0 {
			modes[family] = bgp.BGP_ADD_PATH_SEND
		}
		afi := oc.AfiSafi{State: oc.AfiSafiState{Family: family}}
		afi.AddPaths.Config.SendMax, afi.AddPaths.State.SendMax = limit, limit
		conf.AfiSafis = append(conf.AfiSafis, afi)
	}
	target.fsm.pConf.Update(&conf)
	target.fsm.capMap[bgp.BGP_CAP_ROUTE_REFRESH] = []bgp.ParameterCapabilityInterface{bgp.NewCapRouteRefresh()}
	target.fsm.lock.Unlock()
	target.fsm.familyMap.Store(modes)
	targetAddr := netip.MustParseAddr(target.ID())
	require.NoError(t, s.mgmtOperation(func() error { s.neighborMap[targetAddr] = target; return nil }, true))
	t.Cleanup(func() {
		require.NoError(t, s.mgmtOperation(func() error { delete(s.neighborMap, targetAddr); return nil }, false))
		cleanInfiniteChannel(target.fsm.outgoingCh)
		require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
	})
	return s, target
}

func addPathRefreshPath(t *testing.T, prefix, address string, asns ...uint32) *table.Path {
	t.Helper()
	source := netip.MustParseAddr(address)
	p := makePath(t, "10.231.0.0/24", "192.0.2.254", 0)
	attrs := p.GetFullPathAttrs()
	for i, attr := range attrs {
		if _, ok := attr.(*bgp.PathAttributeAsPath); ok {
			attrs[i] = bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, asns)})
		}
	}
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	require.NoError(t, err)
	family := bgp.RF_IPv4_UC
	if nlri.Prefix.Addr().Is6() {
		family = bgp.RF_IPv6_UC
		mp, err := bgp.NewPathAttributeMpReachNLRI(family, []bgp.PathNLRI{{NLRI: nlri}}, netip.MustParseAddr("2001:db8::254"))
		require.NoError(t, err)
		attrs = append(attrs[:2], mp)
	}
	return table.NewPath(family, &table.PeerInfo{PeerType: oc.PEER_TYPE_EXTERNAL, AS: asns[0], ID: source, Address: source, LocalAS: 65000, LocalID: netip.MustParseAddr("1.1.1.1"), LocalAddress: netip.MustParseAddr("1.1.1.1")}, bgp.PathNLRI{NLRI: nlri, ID: uint32(source.As4()[3])}, false, attrs, time.Now(), false)
}

type addPathWireState map[table.PathLocalKey]bool

// receive uses the production UPDATE packer and serializer, then applies the
// decoded (family, prefix, wire Path-ID) actions as an independent receiver.
func (wire addPathWireState) receive(t *testing.T, target *peer) []*table.Path {
	t.Helper()
	sendModes := target.fsm.familyMap.Load().(map[bgp.Family]bgp.BGPAddPathMode)
	recvModes := make(map[bgp.Family]bgp.BGPAddPathMode)
	for family, mode := range sendModes {
		if mode&bgp.BGP_ADD_PATH_SEND != 0 {
			recvModes[family] = bgp.BGP_ADD_PATH_RECEIVE
		}
	}
	record := func(family bgp.Family, paths []bgp.PathNLRI, withdraw bool) {
		for _, path := range paths {
			key := table.PathLocalKey{PathDestLocalKey: *table.NewPathDestLocalKey(family, path.NLRI.String()), Id: path.ID}
			if withdraw {
				delete(wire, key)
			} else {
				wire[key] = true
			}
		}
	}
	var paths []*table.Path
	for {
		select {
		case outgoing := <-target.fsm.outgoingCh.Out():
			batch := outgoing.(*fsmOutgoingMsg).Paths
			paths = append(paths, batch...)
			opts := &bgp.MarshallingOption{AddPath: sendModes}
			for _, update := range table.CreateUpdateMsgFromPaths(batch, opts) {
				serialized, err := update.Serialize(opts)
				require.NoError(t, err)
				parsed, err := bgp.ParseBGPMessage(serialized, &bgp.MarshallingOption{AddPath: recvModes})
				require.NoError(t, err)
				body := parsed.Body.(*bgp.BGPUpdate)
				record(bgp.RF_IPv4_UC, body.WithdrawnRoutes, true)
				record(bgp.RF_IPv4_UC, body.NLRI, false)
				for _, attr := range body.PathAttributes {
					switch mp := attr.(type) {
					case *bgp.PathAttributeMpReachNLRI:
						record(bgp.NewFamily(mp.AFI, mp.SAFI), mp.Value, false)
					case *bgp.PathAttributeMpUnreachNLRI:
						record(bgp.NewFamily(mp.AFI, mp.SAFI), mp.Value, true)
					}
				}
			}
		case <-time.After(50 * time.Millisecond):
			return paths
		}
	}
}

func addPathRefresh(t *testing.T, s *BgpServer, target *peer, family bgp.Family) {
	t.Helper()
	wire, err := bgp.NewBGPRouteRefreshMessage(family.Afi(), 0, family.Safi()).Serialize()
	require.NoError(t, err)
	refresh, err := bgp.ParseBGPMessage(wire)
	require.NoError(t, err)
	s.handleRouteRefresh(target, &fsmMsg{MsgData: refresh})
}

func TestAddPathRefreshSendMaxWire(t *testing.T) {
	for _, sendMax := range []uint8{1, 2} {
		for _, preferredFirst := range []bool{false, true} {
			for _, vrfPeer := range []bool{false, true} {
				t.Run(fmt.Sprintf("send-max=%d/preferred-withdrawn-first=%v/vrf=%v", sendMax, preferredFirst, vrfPeer), func(t *testing.T) {
					s, target := newAddPathRefreshPeer(t, map[bgp.Family]uint8{bgp.RF_IPv4_UC: sendMax})
					preferred := addPathRefreshPath(t, "10.231.0.0/24", "192.0.2.10", 65001)
					fallback := addPathRefreshPath(t, "10.231.0.0/24", "192.0.2.20", 65003, 65004)
					if vrfPeer {
						addVrf(t, s, "vrf1", "65000:100", []string{"65000:100"}, []string{"65000:100"}, 1)
						target.fsm.lock.Lock()
						conf := target.fsm.pConf.ReadCopy()
						conf.Config.Vrf = "vrf1"
						target.fsm.pConf.Update(&conf)
						target.fsm.lock.Unlock()
						vrf, ok := s.globalRib.GetVrf("vrf1")
						require.True(t, ok)
						preferred, fallback = preferred.ToGlobal(vrf), fallback.ToGlobal(vrf)
					}
					key := func(path *table.Path) table.PathLocalKey {
						if vrfPeer {
							path = path.ToLocal()
						}
						return path.GetLocalKey()
					}
					wire := make(addPathWireState)
					s.propagateUpdate(nil, []*table.Path{preferred})
					wire.receive(t, target)
					assert.Equal(t, addPathWireState{key(preferred): true}, wire, "preferred first")
					s.propagateUpdate(nil, []*table.Path{fallback})
					wire.receive(t, target)
					expected := addPathWireState{key(preferred): true}
					if sendMax == 2 {
						expected[key(fallback)] = true
					}
					assert.Equal(t, expected, wire, "before refresh")
					addPathRefresh(t, s, target, bgp.RF_IPv4_UC)
					wire.receive(t, target)
					assert.Equal(t, expected, wire, "legal basic refresh obeys send-max")
					first, last := fallback, preferred
					if preferredFirst {
						first, last = preferred, fallback
					}
					s.propagateUpdate(nil, []*table.Path{first.Clone(true)})
					wire.receive(t, target)
					assert.Equal(t, addPathWireState{key(last): true}, wire, "source withdrawal and replacement")
					s.propagateUpdate(nil, []*table.Path{last.Clone(true)})
					wire.receive(t, target)
					assert.Empty(t, s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{preferred.GetFamily()}))
					assert.Empty(t, wire, "both source withdrawals leave an empty receiver")
				})
			}
		}
	}
}

func TestAddPathInitialDumpAndReadOnlyQueries(t *testing.T) {
	for _, sendMax := range []uint8{0, 1, 2} {
		t.Run(fmt.Sprint(sendMax), func(t *testing.T) {
			s, target := newAddPathRefreshPeer(t, map[bgp.Family]uint8{bgp.RF_IPv4_UC: sendMax, bgp.RF_IPv6_UC: sendMax})
			// Both wire families share the test peer's IPv4 transport.
			var candidates []*table.Path
			expected := make(addPathWireState)
			for _, prefix := range []string{"10.231.0.0/24", "10.231.1.0/24", "2001:db8:231::/48"} {
				for i, address := range []string{"192.0.2.10", "192.0.2.20"} {
					path := addPathRefreshPath(t, prefix, address, uint32(65010+i))
					require.NotEmpty(t, s.globalRib.Update(path))
					candidates = append(candidates, path)
					key := path.GetLocalKey()
					if sendMax == 0 {
						key.Id = 0
					}
					if i == 0 || sendMax == 2 {
						expected[key] = true
					}
				}
			}
			target.fsm.state.Store(bgp.BGP_FSM_OPENCONFIRM)
			target.fsm.lock.Lock()
			conf := target.fsm.pConf.ReadCopy()
			conf.GracefulRestart.State.Enabled = true
			target.fsm.pConf.Update(&conf)
			target.fsm.lock.Unlock()
			s.getBestFromLocalCallback(target, []bgp.Family{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC}, true, true, func(paths, _ []*table.Path) { target.updateRoutes(paths...); sendfsmOutgoingMsg(target, paths) })
			wire := make(addPathWireState)
			emitted := wire.receive(t, target)
			assert.Equal(t, expected, wire, "initial dump before Established respects every prefix/family")
			eors := 0
			for _, path := range emitted {
				if path.IsEOR() {
					eors++
				}
			}
			assert.Equal(t, 2, eors)
			count := target.advertisedRoutes([]bgp.Family{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC})
			for _, family := range []bgp.Family{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC} {
				seen := 0
				require.NoError(t, s.ListPath(apiutil.ListPathRequest{TableType: api.TableType_TABLE_TYPE_ADJ_OUT, Name: target.ID(), Family: family}, func(_ bgp.NLRI, paths []*apiutil.Path) {
					seen += len(paths)
					if sendMax == 1 {
						require.True(t, paths[1].SendMaxFiltered)
					}
				}))
				want := 2
				if family == bgp.RF_IPv4_UC {
					want = 4
				}
				if sendMax == 0 {
					want /= 2
				}
				assert.Equal(t, want, seen, "read-only query keeps suppressed candidates")
			}
			assert.Equal(t, count, target.advertisedRoutes([]bgp.Family{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC}))
			assert.Empty(t, wire.receive(t, target), "queries do not queue output")
			target.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
			for _, path := range candidates {
				s.propagateUpdate(nil, []*table.Path{path.Clone(true)})
			}
			wire.receive(t, target)
			assert.Empty(t, wire)
		})
	}
}

func TestAddPathVRFInitialDumpWire(t *testing.T) {
	for _, sendMax := range []uint8{1, 2} {
		t.Run(fmt.Sprint(sendMax), func(t *testing.T) {
			s, target := newAddPathRefreshPeer(t, map[bgp.Family]uint8{bgp.RF_IPv4_UC: sendMax})
			addVrf(t, s, "vrf1", "65000:100", []string{"65000:100"}, []string{"65000:100"}, 1)
			target.fsm.lock.Lock()
			conf := target.fsm.pConf.ReadCopy()
			conf.Config.Vrf = "vrf1"
			target.fsm.pConf.Update(&conf)
			target.fsm.lock.Unlock()
			vrf, ok := s.globalRib.GetVrf("vrf1")
			require.True(t, ok)
			first := addPathRefreshPath(t, "10.231.0.0/24", "192.0.2.10", 65001).ToGlobal(vrf)
			second := addPathRefreshPath(t, "10.231.0.0/24", "192.0.2.20", 65003, 65004).ToGlobal(vrf)
			require.NotEmpty(t, s.globalRib.Update(first))
			require.NotEmpty(t, s.globalRib.Update(second))
			s.getBestFromLocalCallback(target, []bgp.Family{bgp.RF_IPv4_UC}, true, true, func(paths, _ []*table.Path) {
				target.updateRoutes(paths...)
				sendfsmOutgoingMsg(target, paths)
			})
			wire := make(addPathWireState)
			wire.receive(t, target)
			expected := addPathWireState{first.ToLocal().GetLocalKey(): true}
			if sendMax == 2 {
				expected[second.ToLocal().GetLocalKey()] = true
			}
			assert.Equal(t, expected, wire, "the local wire family controls candidate collection from the VPN RIB")
			assert.Equal(t, int(sendMax), target.advertisedRoutes([]bgp.Family{bgp.RF_IPv4_UC}))
		})
	}
}

func TestAddPathRefreshPolicyReplacement(t *testing.T) {
	for _, refresh := range []bool{false, true} {
		t.Run(fmt.Sprintf("route-refresh=%v", refresh), func(t *testing.T) {
			s, target := newAddPathRefreshPeer(t, map[bgp.Family]uint8{bgp.RF_IPv4_UC: 1})
			incumbent := addPathRefreshPath(t, "10.231.0.0/24", "192.0.2.10", 65001, 65004)
			incumbent.SetCommunities([]uint32{uint32(65000)<<16 | 1}, false)
			better := addPathRefreshPath(t, "10.231.0.0/24", "192.0.2.20", 65003)
			wire := make(addPathWireState)
			s.propagateUpdate(nil, []*table.Path{incumbent, better})
			wire.receive(t, target)
			addPathRefresh(t, s, target, bgp.RF_IPv4_UC)
			wire.receive(t, target)
			assert.Equal(t, addPathWireState{incumbent.GetLocalKey(): true}, wire, "refresh retains the previously sent eligible ID despite a better RIB candidate")
			ctx := context.Background()
			require.NoError(t, s.AddDefinedSet(ctx, &api.AddDefinedSetRequest{DefinedSet: &api.DefinedSet{DefinedType: api.DefinedType_DEFINED_TYPE_COMMUNITY, Name: "reject-incumbent", List: []string{"65000:1"}}}))
			policy := &api.Policy{Name: "reject-incumbent", Statements: []*api.Statement{{Name: "reject-incumbent", Conditions: &api.Conditions{CommunitySet: &api.MatchSet{Name: "reject-incumbent", Type: api.MatchSet_TYPE_ANY}}, Actions: &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_REJECT}}}}
			require.NoError(t, s.AddPolicy(ctx, &api.AddPolicyRequest{Policy: policy}))
			require.NoError(t, s.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{Assignment: &api.PolicyAssignment{Name: target.exportPolicyID, Direction: api.PolicyDirection_POLICY_DIRECTION_EXPORT, Policies: []*api.Policy{policy}, DefaultAction: api.RouteAction_ROUTE_ACTION_ACCEPT}}))
			if refresh {
				addPathRefresh(t, s, target, bgp.RF_IPv4_UC)
			} else {
				s.softResetOutPeer(target, bgp.RF_IPv4_UC, false)
			}
			emitted := wire.receive(t, target)
			require.Len(t, emitted, 2, "one withdrawal and one replacement, with no duplicate withdrawal")
			assert.Equal(t, addPathWireState{better.GetLocalKey(): true}, wire)
			assert.False(t, target.isPathSendMaxFiltered(better), "a sent replacement cannot retain the filtered marker")
			require.NoError(t, s.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{Assignment: &api.PolicyAssignment{Name: target.exportPolicyID, Direction: api.PolicyDirection_POLICY_DIRECTION_EXPORT, DefaultAction: api.RouteAction_ROUTE_ACTION_ACCEPT}}))
			s.softResetOutPeer(target, bgp.RF_IPv4_UC, false)
			wire.receive(t, target)
			assert.Equal(t, addPathWireState{better.GetLocalKey(): true}, wire)
			s.propagateUpdate(nil, []*table.Path{better.Clone(true)})
			wire.receive(t, target)
			assert.Equal(t, addPathWireState{incumbent.GetLocalKey(): true}, wire)
			s.propagateUpdate(nil, []*table.Path{incumbent.Clone(true)})
			wire.receive(t, target)
			assert.Empty(t, wire)
		})
	}
}

func TestAddPathRefreshClearsRejectedSendMaxMarkers(t *testing.T) {
	for _, refresh := range []bool{false, true} {
		t.Run(fmt.Sprintf("route-refresh=%v", refresh), func(t *testing.T) {
			s, target := newAddPathRefreshPeer(t, map[bgp.Family]uint8{bgp.RF_IPv4_UC: 1})
			first := addPathRefreshPath(t, "10.231.0.0/24", "192.0.2.10", 65001)
			fallback := addPathRefreshPath(t, "10.231.0.0/24", "192.0.2.20", 65003, 65004)
			fallback.SetCommunities([]uint32{uint32(65000)<<16 | 1}, false)
			s.propagateUpdate(nil, []*table.Path{first, fallback})
			wire := make(addPathWireState)
			wire.receive(t, target)
			require.True(t, target.isPathSendMaxFiltered(fallback))
			ctx := context.Background()
			require.NoError(t, s.AddDefinedSet(ctx, &api.AddDefinedSetRequest{DefinedSet: &api.DefinedSet{DefinedType: api.DefinedType_DEFINED_TYPE_COMMUNITY, Name: "reject-suppressed", List: []string{"65000:1"}}}))
			policy := &api.Policy{Name: "reject-suppressed", Statements: []*api.Statement{{Name: "reject-suppressed", Conditions: &api.Conditions{CommunitySet: &api.MatchSet{Name: "reject-suppressed", Type: api.MatchSet_TYPE_ANY}}, Actions: &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_REJECT}}}}
			require.NoError(t, s.AddPolicy(ctx, &api.AddPolicyRequest{Policy: policy}))
			require.NoError(t, s.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{Assignment: &api.PolicyAssignment{Name: target.exportPolicyID, Direction: api.PolicyDirection_POLICY_DIRECTION_EXPORT, Policies: []*api.Policy{policy}, DefaultAction: api.RouteAction_ROUTE_ACTION_ACCEPT}}))
			require.NoError(t, s.ListPath(apiutil.ListPathRequest{TableType: api.TableType_TABLE_TYPE_ADJ_OUT, Name: target.ID(), Family: bgp.RF_IPv4_UC, EnableFiltered: true}, func(_ bgp.NLRI, _ []*apiutil.Path) {}))
			assert.True(t, target.isPathSendMaxFiltered(fallback), "a read-only query must not commit the reevaluation")
			if refresh {
				addPathRefresh(t, s, target, bgp.RF_IPv4_UC)
			} else {
				s.softResetOutPeer(target, bgp.RF_IPv4_UC, false)
			}
			wire.receive(t, target)
			assert.Equal(t, addPathWireState{first.GetLocalKey(): true}, wire)
			assert.False(t, target.isPathSendMaxFiltered(fallback), "a rejected path is no longer suppressed by send-max")
		})
	}
}

func TestAddPathLiveRejectRetiresSendMaxMarker(t *testing.T) {
	for _, vrfPeer := range []bool{false, true} {
		for _, tt := range []struct {
			name      string
			community uint32
			sendMax   uint8
		}{
			{name: "policy-reject-suppressed", community: uint32(65000)<<16 | 1, sendMax: 1},
			{name: "post-filter-withdraw-suppressed", community: uint32(bgp.COMMUNITY_LLGR_STALE), sendMax: 1},
			{name: "post-filter-withdraw-advertised", community: uint32(bgp.COMMUNITY_LLGR_STALE), sendMax: 2},
		} {
			t.Run(fmt.Sprintf("vrf=%v/%s", vrfPeer, tt.name), func(t *testing.T) {
				s, target := newAddPathRefreshPeer(t, map[bgp.Family]uint8{bgp.RF_IPv4_UC: tt.sendMax})
				ctx := context.Background()
				require.NoError(t, s.AddDefinedSet(ctx, &api.AddDefinedSetRequest{DefinedSet: &api.DefinedSet{DefinedType: api.DefinedType_DEFINED_TYPE_COMMUNITY, Name: "reject-live", List: []string{"65000:1"}}}))
				policy := &api.Policy{Name: "reject-live", Statements: []*api.Statement{{Name: "reject-live", Conditions: &api.Conditions{CommunitySet: &api.MatchSet{Name: "reject-live", Type: api.MatchSet_TYPE_ANY}}, Actions: &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_REJECT}}}}
				require.NoError(t, s.AddPolicy(ctx, &api.AddPolicyRequest{Policy: policy}))
				require.NoError(t, s.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{Assignment: &api.PolicyAssignment{Name: target.exportPolicyID, Direction: api.PolicyDirection_POLICY_DIRECTION_EXPORT, Policies: []*api.Policy{policy}, DefaultAction: api.RouteAction_ROUTE_ACTION_ACCEPT}}))
				first := addPathRefreshPath(t, "10.231.0.0/24", "192.0.2.10", 65001)
				fallback := addPathRefreshPath(t, "10.231.0.0/24", "192.0.2.20", 65003, 65004)
				if vrfPeer {
					addVrf(t, s, "vrf1", "65000:100", []string{"65000:100"}, []string{"65000:100"}, 1)
					target.fsm.lock.Lock()
					conf := target.fsm.pConf.ReadCopy()
					conf.Config.Vrf = "vrf1"
					target.fsm.pConf.Update(&conf)
					target.fsm.lock.Unlock()
					vrf, ok := s.globalRib.GetVrf("vrf1")
					require.True(t, ok)
					first, fallback = first.ToGlobal(vrf), fallback.ToGlobal(vrf)
				}
				s.propagateUpdate(nil, []*table.Path{first, fallback})
				wire := make(addPathWireState)
				wire.receive(t, target)
				localFirst := filteredPathForPeer(target, first)
				localFallback := filteredPathForPeer(target, fallback)
				before := addPathWireState{localFirst.GetLocalKey(): true}
				if tt.sendMax == 2 {
					before[localFallback.GetLocalKey()] = true
				}
				require.Equal(t, before, wire)
				require.Equal(t, tt.sendMax == 1, target.isPathSendMaxFiltered(localFallback))

				changed := fallback.Clone(false)
				changed.SetCommunities([]uint32{tt.community}, false)
				s.propagateUpdate(nil, []*table.Path{changed})
				emitted := wire.receive(t, target)
				assert.Equal(t, addPathWireState{localFirst.GetLocalKey(): true}, wire)
				assert.False(t, target.isPathSendMaxFiltered(localFallback), "a rejected live update retires its former send-max reason")
				if tt.sendMax == 1 {
					assert.Empty(t, emitted, "a never-advertised ID needs no withdrawal")
				} else {
					require.Len(t, emitted, 1)
					assert.True(t, emitted[0].IsWithdraw)
					assert.Equal(t, localFallback.GetLocalKey(), emitted[0].GetLocalKey())
				}
				assert.Equal(t, 1, target.advertisedRoutes([]bgp.Family{bgp.RF_IPv4_UC}))
			})
		}
	}
}

func TestAddPathRTCWithdrawalClearsSuppressedSendMaxMarkers(t *testing.T) {
	s, target := newAddPathRefreshPeer(t, map[bgp.Family]uint8{bgp.RF_IPv4_VPN: 1, bgp.RF_RTC_UC: 0})
	rd, rt, err := parseRDRT("65000:100")
	require.NoError(t, err)
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	membership := table.NewPath(bgp.RF_RTC_UC, target.peerInfo.Load(), bgp.PathNLRI{NLRI: bgp.NewRouteTargetMembershipNLRI(65002, rt)}, false, []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh}, time.Now(), false)
	s.processRTCMembership(target, membership)
	vrf := &table.Vrf{Rd: rd, ExportRt: []bgp.ExtendedCommunityInterface{rt}}
	first := addPathRefreshPath(t, "10.231.0.0/24", "192.0.2.10", 65001).ToGlobal(vrf)
	fallback := addPathRefreshPath(t, "10.231.0.0/24", "192.0.2.20", 65003, 65004).ToGlobal(vrf)
	s.propagateUpdate(nil, []*table.Path{first, fallback})
	wire := make(addPathWireState)
	wire.receive(t, target)
	require.True(t, target.isPathSendMaxFiltered(fallback))
	s.processRTCMembership(target, membership.Clone(true))
	wire.receive(t, target)
	assert.Empty(t, wire)
	assert.False(t, target.isPathSendMaxFiltered(fallback), "RTC-rejected paths are no longer suppressed by send-max")
	s.propagateUpdate(nil, []*table.Path{first.Clone(true), fallback.Clone(true)})
	assert.Empty(t, wire.receive(t, target), "source withdrawals cannot recreate rejected output")
	assert.False(t, target.isPathSendMaxFiltered(fallback))
}

func TestAddPathRTCMembershipSendMax(t *testing.T) {
	for _, sendMax := range []uint8{1, 2} {
		for _, membershipKind := range []string{"exact", "default", "prefix"} {
			t.Run(fmt.Sprintf("send-max=%d/membership=%s", sendMax, membershipKind), func(t *testing.T) {
				s, target := newAddPathRefreshPeer(t, map[bgp.Family]uint8{bgp.RF_IPv4_VPN: sendMax, bgp.RF_RTC_UC: 0})
				rd, rt, err := parseRDRT("65000:100")
				require.NoError(t, err)
				vrf := &table.Vrf{Rd: rd, ExportRt: []bgp.ExtendedCommunityInterface{rt}}
				first := addPathRefreshPath(t, "10.231.0.0/24", "192.0.2.10", 65001).ToGlobal(vrf)
				second := addPathRefreshPath(t, "10.231.0.0/24", "192.0.2.20", 65003, 65004).ToGlobal(vrf)
				require.NotEmpty(t, s.globalRib.Update(first))
				require.NotEmpty(t, s.globalRib.Update(second))
				rtm := bgp.NewRouteTargetMembershipNLRI(65002, rt)
				switch membershipKind {
				case "default":
					rtm = bgp.NewRouteTargetMembershipNLRI(0, nil)
				case "prefix":
					rtm, err = bgp.ParseRouteTargetMembershipNLRI("65002:65000:0/64")
					require.NoError(t, err)
				}
				nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.0.2.1"))
				require.NoError(t, err)
				membership := table.NewPath(bgp.RF_RTC_UC, target.peerInfo.Load(), bgp.PathNLRI{NLRI: rtm}, false, []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh}, time.Now(), false)
				s.processRTCMembership(target, membership)
				wire := make(addPathWireState)
				wire.receive(t, target)
				assert.Len(t, wire, int(sendMax), "RTC announces must share the outbound ceiling")
				assert.True(t, wire[first.GetLocalKey()])
				s.propagateUpdate(nil, []*table.Path{first.Clone(true)})
				wire.receive(t, target)
				assert.Equal(t, addPathWireState{second.GetLocalKey(): true}, wire, "RTC-dumped fallback remains eligible for promotion")
				s.processRTCMembership(target, membership.Clone(true))
				wire.receive(t, target)
				assert.Empty(t, wire, "RTC membership withdrawal removes every sent ID")
			})
		}
	}
}

func TestAddPathRTCWithdrawalRefillsThroughRemainingMembership(t *testing.T) {
	tests := []struct {
		name          string
		sendMax       uint8
		firstCount    int
		fallbackCount int
		overlap       bool
		rejectFirst   bool
	}{
		{name: "promote suppressed fallback", sendMax: 1, firstCount: 1, fallbackCount: 1},
		{name: "keep advertised fallback", sendMax: 2, firstCount: 1, fallbackCount: 1},
		{name: "overlapping route targets", sendMax: 1, firstCount: 1, fallbackCount: 1, overlap: true},
		{name: "multiple freed slots", sendMax: 2, firstCount: 2, fallbackCount: 3},
		{name: "reject preferred fallback", sendMax: 1, firstCount: 1, fallbackCount: 2, rejectFirst: true},
		{name: "no eligible fallback", sendMax: 1, firstCount: 1, fallbackCount: 1, rejectFirst: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, target := newAddPathRefreshPeer(t, map[bgp.Family]uint8{bgp.RF_IPv4_VPN: tt.sendMax, bgp.RF_RTC_UC: 0})
			rd, rtA, err := parseRDRT("65000:100")
			require.NoError(t, err)
			_, rtB, err := parseRDRT("65000:200")
			require.NoError(t, err)
			makeVPNPath := func(index int, rts []bgp.ExtendedCommunityInterface) *table.Path {
				asns := []uint32{uint32(65010 + index)}
				for range index {
					asns = append(asns, 65050)
				}
				return addPathRefreshPath(t, "10.231.0.0/24", fmt.Sprintf("192.0.2.%d", 10+index), asns...).ToGlobal(&table.Vrf{Rd: rd, ExportRt: rts})
			}
			var first, fallbacks []*table.Path
			for i := range tt.firstCount {
				rts := []bgp.ExtendedCommunityInterface{rtA}
				if tt.overlap {
					rts = append(rts, rtB)
				}
				p := makeVPNPath(i, rts)
				require.NotEmpty(t, s.globalRib.Update(p))
				first = append(first, p)
			}
			for i := range tt.fallbackCount {
				p := makeVPNPath(tt.firstCount+i, []bgp.ExtendedCommunityInterface{rtB})
				if tt.rejectFirst && i == 0 {
					p.SetCommunities([]uint32{uint32(65000)<<16 | 1}, false)
				}
				require.NotEmpty(t, s.globalRib.Update(p))
				fallbacks = append(fallbacks, p)
			}
			if tt.rejectFirst {
				ctx := context.Background()
				require.NoError(t, s.AddDefinedSet(ctx, &api.AddDefinedSetRequest{DefinedSet: &api.DefinedSet{DefinedType: api.DefinedType_DEFINED_TYPE_COMMUNITY, Name: "reject-fallback", List: []string{"65000:1"}}}))
				policy := &api.Policy{Name: "reject-fallback", Statements: []*api.Statement{{Name: "reject-fallback", Conditions: &api.Conditions{CommunitySet: &api.MatchSet{Name: "reject-fallback", Type: api.MatchSet_TYPE_ANY}}, Actions: &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_REJECT}}}}
				require.NoError(t, s.AddPolicy(ctx, &api.AddPolicyRequest{Policy: policy}))
				require.NoError(t, s.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{Assignment: &api.PolicyAssignment{Name: target.exportPolicyID, Direction: api.PolicyDirection_POLICY_DIRECTION_EXPORT, Policies: []*api.Policy{policy}, DefaultAction: api.RouteAction_ROUTE_ACTION_ACCEPT}}))
			}
			nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.0.2.1"))
			require.NoError(t, err)
			membership := func(rt bgp.ExtendedCommunityInterface) *table.Path {
				return table.NewPath(bgp.RF_RTC_UC, target.peerInfo.Load(), bgp.PathNLRI{NLRI: bgp.NewRouteTargetMembershipNLRI(65002, rt)}, false, []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh}, time.Now(), false)
			}
			mA, mB := membership(rtA), membership(rtB)
			wire := make(addPathWireState)
			s.processRTCMembership(target, mA)
			wire.receive(t, target)
			before := make(addPathWireState)
			for _, p := range first {
				before[p.GetLocalKey()] = true
			}
			require.Equal(t, before, wire)
			s.processRTCMembership(target, mB)
			wire.receive(t, target)
			for i, p := range fallbacks {
				if len(before) < int(tt.sendMax) && (!tt.rejectFirst || i != 0) {
					before[p.GetLocalKey()] = true
				}
			}
			require.Equal(t, before, wire, "second membership respects send-max")
			s.processRTCMembership(target, mA.Clone(true))
			emitted := wire.receive(t, target)
			after := make(addPathWireState)
			wantEmitted := tt.firstCount
			if tt.overlap {
				after = before
				wantEmitted = 0
			} else {
				for i, p := range fallbacks {
					if len(after) >= int(tt.sendMax) || tt.rejectFirst && i == 0 {
						continue
					}
					after[p.GetLocalKey()] = true
					if !before[p.GetLocalKey()] {
						wantEmitted++
					}
				}
			}
			assert.Equal(t, after, wire, "withdrawal refills only the released slots from the remaining RT")
			assert.Len(t, emitted, wantEmitted, "existing advertisements need no duplicate update")
			assert.Equal(t, len(after), target.advertisedRoutes([]bgp.Family{bgp.RF_IPv4_VPN}))
			for i, p := range fallbacks {
				if tt.rejectFirst && i == 0 {
					assert.False(t, wire[p.GetLocalKey()], "replenishment must apply export policy")
				} else {
					assert.Equal(t, !after[p.GetLocalKey()], target.isPathSendMaxFiltered(p))
				}
			}
			s.processRTCMembership(target, mA.Clone(true))
			assert.Empty(t, wire.receive(t, target), "duplicate RTC withdrawal stays a no-op")
			s.processRTCMembership(target, mB.Clone(true))
			wire.receive(t, target)
			assert.Empty(t, wire)
			assert.Zero(t, target.advertisedRoutes([]bgp.Family{bgp.RF_IPv4_VPN}))
		})
	}
}

func TestAddPathRTCDeferralRetainsAdvertisedWithdrawals(t *testing.T) {
	for _, sendMax := range []uint8{0, 1} {
		t.Run(fmt.Sprint(sendMax), func(t *testing.T) {
			s, target := newAddPathRefreshPeer(t, map[bgp.Family]uint8{bgp.RF_IPv4_VPN: sendMax, bgp.RF_RTC_UC: 0})
			target.setRtcEORWait(true)
			target.fsm.lock.Lock()
			conf := target.fsm.pConf.ReadCopy()
			for i := range conf.AfiSafis {
				conf.AfiSafis[i].Config.AfiSafiName = oc.AfiSafiType(conf.AfiSafis[i].State.Family.String())
			}
			target.fsm.pConf.Update(&conf)
			target.fsm.lock.Unlock()
			rd, rt, err := parseRDRT("65000:100")
			require.NoError(t, err)
			vrf := &table.Vrf{Rd: rd, ExportRt: []bgp.ExtendedCommunityInterface{rt}}
			first := addPathRefreshPath(t, "10.231.0.0/24", "192.0.2.10", 65001).ToGlobal(vrf)
			first.SetCommunities([]uint32{uint32(65000)<<16 | 1}, false)
			second := addPathRefreshPath(t, "10.231.0.0/24", "192.0.2.20", 65003, 65004).ToGlobal(vrf)
			require.NotEmpty(t, s.globalRib.Update(first))
			require.NotEmpty(t, s.globalRib.Update(second))
			nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.0.2.1"))
			require.NoError(t, err)
			membership := table.NewPath(bgp.RF_RTC_UC, target.peerInfo.Load(), bgp.PathNLRI{NLRI: bgp.NewRouteTargetMembershipNLRI(65002, rt)}, false, []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh}, time.Now(), false)
			s.processRTCMembership(target, membership)
			wire := make(addPathWireState)
			require.Empty(t, wire.receive(t, target), "RTC EOR defers the normal initial VPN output")
			// A legal refresh can establish an advertisement before RTC EOR.
			addPathRefresh(t, s, target, bgp.RF_IPv4_VPN)
			wire.receive(t, target)
			firstKey := first.GetLocalKey()
			if sendMax == 0 {
				firstKey.Id = 0
			}
			require.Equal(t, addPathWireState{firstKey: true}, wire)
			ctx := context.Background()
			require.NoError(t, s.AddDefinedSet(ctx, &api.AddDefinedSetRequest{DefinedSet: &api.DefinedSet{DefinedType: api.DefinedType_DEFINED_TYPE_COMMUNITY, Name: "reject-first", List: []string{"65000:1"}}}))
			policy := &api.Policy{Name: "reject-first", Statements: []*api.Statement{{Name: "reject-first", Conditions: &api.Conditions{CommunitySet: &api.MatchSet{Name: "reject-first", Type: api.MatchSet_TYPE_ANY}}, Actions: &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_REJECT}}}}
			require.NoError(t, s.AddPolicy(ctx, &api.AddPolicyRequest{Policy: policy}))
			require.NoError(t, s.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{Assignment: &api.PolicyAssignment{Name: target.exportPolicyID, Direction: api.PolicyDirection_POLICY_DIRECTION_EXPORT, Policies: []*api.Policy{policy}, DefaultAction: api.RouteAction_ROUTE_ACTION_ACCEPT}}))
			s.softResetOutPeer(target, bgp.Family(0), true)
			emitted := wire.receive(t, target)
			if sendMax == 0 {
				assert.Empty(t, emitted, "ordinary BGP keeps its existing deferral behavior")
				assert.Equal(t, addPathWireState{firstKey: true}, wire)
			} else {
				require.Len(t, emitted, 2, "replacement and the withdrawal that releases its slot")
				assert.Equal(t, addPathWireState{second.GetLocalKey(): true}, wire)
				assert.False(t, target.hasPathAlreadyBeenSent(first))
			}
			assert.Equal(t, 1, target.advertisedRoutes([]bgp.Family{bgp.RF_IPv4_VPN}))
		})
	}
}

func TestAddPathRefreshRetainsPostFilterWithdrawal(t *testing.T) {
	s, target := newAddPathRefreshPeer(t, map[bgp.Family]uint8{bgp.RF_IPv4_UC: 1})
	incumbent := addPathRefreshPath(t, "10.231.0.0/24", "192.0.2.10", 65001)
	fallback := addPathRefreshPath(t, "10.231.0.0/24", "192.0.2.20", 65003, 65004)
	s.propagateUpdate(nil, []*table.Path{incumbent, fallback})
	wire := make(addPathWireState)
	wire.receive(t, target)
	// A peer without LLGR support must receive a withdrawal for the stale ID.
	changed := incumbent.Clone(false)
	changed.SetCommunities([]uint32{uint32(bgp.COMMUNITY_LLGR_STALE)}, false)
	require.NotEmpty(t, s.globalRib.Update(changed))
	addPathRefresh(t, s, target, bgp.RF_IPv4_UC)
	wire.receive(t, target)
	assert.Equal(t, addPathWireState{fallback.GetLocalKey(): true}, wire, "postFilterpath's withdrawal releases the incumbent's slot")
}

func TestAddPathSourceWithdrawalAfterConcurrentRTCWithdrawal(t *testing.T) {
	s, target := newAddPathRefreshPeer(t, map[bgp.Family]uint8{bgp.RF_IPv4_VPN: 1, bgp.RF_RTC_UC: 0})
	source := newPeerandInfo(t, 65000, 65001, "192.0.2.10", s.globalRib)
	source.policy = s.policy
	t.Cleanup(func() { cleanInfiniteChannel(source.fsm.outgoingCh) })
	rd, rt, err := parseRDRT("65000:100")
	require.NoError(t, err)
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	membership := table.NewPath(bgp.RF_RTC_UC, target.peerInfo.Load(), bgp.PathNLRI{NLRI: bgp.NewRouteTargetMembershipNLRI(65002, rt)}, false, []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh}, time.Now(), false)
	s.processRTCMembership(target, membership)
	path := addPathRefreshPath(t, "10.231.0.0/24", "192.0.2.10", 65001).ToGlobal(&table.Vrf{Rd: rd, ExportRt: []bgp.ExtendedCommunityInterface{rt}})
	s.propagateUpdate(source, []*table.Path{path})
	wire := make(addPathWireState)
	wire.receive(t, target)
	require.Equal(t, addPathWireState{path.GetLocalKey(): true}, wire)

	// Pause the source withdrawal after RIB.Update removed the route, before
	// the neighbor's advertisement bookkeeping receives that withdrawal.
	inFilter := make(chan struct{})
	release := make(chan struct{})
	var once, releaseOnce sync.Once
	w, err := s.watch(func(o *watchOptions) {
		o.postUpdate = true
		o.postUpdateFilter = func(watchEvent) bool {
			once.Do(func() {
				close(inFilter)
				<-release
			})
			return true
		}
	})
	require.NoError(t, err)
	t.Cleanup(w.Stop)
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.propagateUpdate(source, []*table.Path{path.Clone(true)})
	}()
	select {
	case <-inFilter:
	case <-time.After(time.Second):
		t.Fatal("source withdrawal did not reach the post-policy watcher")
	}
	require.Empty(t, s.globalRib.GetPathsByRT(rt, []bgp.Family{bgp.RF_IPv4_VPN}))
	// RTC cannot find the route in its index now. The pending source
	// withdrawal still has to remove its advertised ID after RTC rejects it.
	s.processRTCMembership(target, membership.Clone(true))
	unblock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("source withdrawal did not finish")
	}
	wire.receive(t, target)
	assert.Empty(t, wire, "an advertised ID requires its withdrawal even after RTC eligibility changes")
	assert.Zero(t, target.advertisedRoutes([]bgp.Family{bgp.RF_IPv4_VPN}))
}

func TestAddPathRefreshConcurrentWithdrawal(t *testing.T) {
	s, target := newAddPathRefreshPeer(t, map[bgp.Family]uint8{bgp.RF_IPv4_UC: 1})
	first := addPathRefreshPath(t, "10.231.0.0/24", "192.0.2.10", 65001)
	second := addPathRefreshPath(t, "10.231.0.0/24", "192.0.2.20", 65003, 65004)
	s.propagateUpdate(nil, []*table.Path{first, second})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 20 {
			addPathRefresh(t, s, target, bgp.RF_IPv4_UC)
		}
	}()
	go func() {
		defer wg.Done()
		for range 20 {
			s.propagateUpdate(nil, []*table.Path{second.Clone(true), second.Clone(false)})
		}
	}()
	wg.Wait()
	s.propagateUpdate(nil, []*table.Path{first.Clone(true), second.Clone(true)})
	wire := make(addPathWireState)
	wire.receive(t, target)
	assert.Empty(t, wire)
	assert.Zero(t, target.advertisedRoutes([]bgp.Family{bgp.RF_IPv4_UC}))
}
