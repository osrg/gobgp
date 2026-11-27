// Copyright (C) 2026 The GoBGP Authors.
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
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/require"
)

func exportTestPeers(t testing.TB, count int, opts ...ServerOption) (*BgpServer, []*peer) {
	t.Helper()
	s := NewBgpServer(opts...)
	s.bgpConfig.Global = oc.Global{Config: oc.GlobalConfig{As: 65000, RouterId: netip.MustParseAddr("192.0.2.254")}}
	s.globalRib = table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC, bgp.RF_IPv4_VPN, bgp.RF_RTC_UC}, oc.RouteSelectionOptionsConfig{}, oc.UseMultiplePathsConfig{})
	require.NoError(t, s.policy.Initialize())
	require.NoError(t, s.policy.SetPeerPolicy(table.GLOBAL_RIB_NAME, oc.ApplyPolicy{Config: oc.ApplyPolicyConfig{DefaultExportPolicy: oc.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE}}))
	peers := make([]*peer, count)
	for i := range peers {
		addr := netip.MustParseAddr(fmt.Sprintf("192.0.2.%d", i+1))
		conf := &oc.Neighbor{Config: oc.NeighborConfig{PeerAs: 65200, NeighborAddress: addr}}
		require.NoError(t, oc.SetDefaultNeighborConfigValues(conf, nil, &s.bgpConfig.Global))
		conf.State.RemoteRouterId = addr
		p := newPeer(&s.bgpConfig.Global, conf, bgp.BGP_FSM_ESTABLISHED, s.globalRib, s.policy, nil, logger)
		p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: 0, bgp.RF_IPv6_UC: 0, bgp.RF_IPv4_VPN: 0})
		p.peerInfo.Store(table.NewPeerInfo(&s.bgpConfig.Global, conf, 65200, 65000, addr,
			s.bgpConfig.Global.Config.RouterId, addr, s.bgpConfig.Global.Config.RouterId))
		// The fixture starts Established without running the FSM handshake.
		s.grSessionEstablished(p, p.grNegotiated())
		peers[i] = p
		s.neighborMap[addr] = p
		t.Cleanup(func() {
			p.fsm.outgoingCh.Close()
			for range p.fsm.outgoingCh.Out() {
			}
		})
	}
	return s, peers
}

func exportTestPolicy(t testing.TB, s *BgpServer, statements []oc.Statement) {
	t.Helper()
	require.NoError(t, s.policy.Reset(&oc.RoutingPolicy{PolicyDefinitions: []oc.PolicyDefinition{{Name: "export", Statements: statements}}}, map[string]oc.ApplyPolicy{
		table.GLOBAL_RIB_NAME: {Config: oc.ApplyPolicyConfig{ExportPolicyList: []string{"export"}, DefaultExportPolicy: oc.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE}},
	}))
}

func exportAttributePolicy() []oc.Statement {
	return []oc.Statement{{Name: "attributes", Actions: oc.Actions{BgpActions: oc.BgpActions{SetMed: "123", SetLocalPref: 234}}}}
}

func updateGroupPeers(group *updateGroup) []*peer {
	peers := make([]*peer, 0, len(group.receivers))
	for _, receiver := range group.receivers {
		peers = append(peers, receiver.peer)
	}
	return peers
}

// queuedGroupPaths uses a marker to drain each fixture queue through all
// preceding messages without waiting for a quiet period. No FSM consumes it.
func queuedGroupPaths(t testing.TB, peers []*peer) map[*peer][]*table.Path {
	t.Helper()
	out := make(map[*peer][]*table.Path)
	for _, p := range peers {
		marker := &fsmOutgoingMsg{}
		p.fsm.outgoingCh.In() <- marker
		timer := time.NewTimer(time.Second)
	drain:
		for {
			select {
			case item := <-p.fsm.outgoingCh.Out():
				msg := item.(*fsmOutgoingMsg)
				if msg == marker {
					break drain
				}
				if len(msg.Paths) != 0 {
					out[p] = append(out[p], msg.Paths...)
				}
			case <-timer.C:
				t.Fatalf("timed out draining outgoing paths for %s", p.ID())
			}
		}
		timer.Stop()
	}
	return out
}

func updateGroupOutputs(t testing.TB, s *BgpServer, paths, olds []*table.Path) map[*peer][]*table.Path {
	t.Helper()
	out := make(map[*peer][]*table.Path)
	entry := s.updateGroups.getTargets(paths[0].GetFamily(), s.policy, s.neighborMap)
	for _, p := range entry.individual {
		out[p] = s.processOutgoingPaths(p, paths, olds)
	}
	for _, group := range entry.groups {
		s.processOutgoingPathsForGroup(group, paths, olds)
		for p, outgoing := range queuedGroupPaths(t, updateGroupPeers(group)) {
			out[p] = outgoing
		}
	}
	return out
}

func requireUpdateGroupParity(t *testing.T, s *BgpServer, peers []*peer, paths, olds []*table.Path) map[*peer][]*table.Path {
	t.Helper()
	out := updateGroupOutputs(t, s, paths, olds)
	for _, p := range peers {
		want := s.processOutgoingPaths(p, paths, olds)
		require.Len(t, out[p], len(want), p.ID())
		for i, path := range want {
			require.True(t, path.Equal(out[p][i]), p.ID())
		}
	}
	return out
}

type updateGroupCountAction struct {
	table.Action
	calls *atomic.Int64
}

func (a *updateGroupCountAction) Apply(path *table.Path, options *table.PolicyOptions) (*table.Path, error) {
	a.calls.Add(1)
	return a.Action.Apply(path, options)
}

func TestUpdateGroupSharedEvaluation(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(fmt.Sprintf("reject=%v", reject), func(t *testing.T) {
			s, peers := exportTestPeers(t, 10)
			st, err := table.NewStatement(exportAttributePolicy()[0])
			require.NoError(t, err)
			st.RouteAction = &table.RoutingAction{AcceptRoute: !reject}
			require.NoError(t, s.policy.AddPolicy(&table.Policy{Name: "counted", Statements: []*table.Statement{st}}, false))
			require.NoError(t, s.policy.SetPolicyAssignment(table.GLOBAL_RIB_NAME, table.POLICY_DIRECTION_EXPORT,
				[]*oc.PolicyDefinition{{Name: "counted"}}, table.ROUTE_TYPE_ACCEPT))
			groups := s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups
			require.Len(t, groups, 1)
			require.Len(t, updateGroupPeers(groups[0]), 10)
			// Instrument the action after building the group.
			var calls atomic.Int64
			st.ModActions[0] = &updateGroupCountAction{Action: st.ModActions[0], calls: &calls}
			input := newPolicyTestPath(t, &table.PeerInfo{AS: 65100})
			out := updateGroupOutputs(t, s, []*table.Path{input}, nil)
			require.EqualValues(t, 1, calls.Load())
			updateGroupOutputs(t, s, []*table.Path{input}, nil)
			require.EqualValues(t, 2, calls.Load(), "results do not survive fanout")
			for _, p := range peers {
				if reject {
					require.Empty(t, out[p])
					continue
				}
				require.Len(t, out[p], 1)
				require.True(t, s.filterpath(p, input, nil).Equal(out[p][0]))
			}
			if !reject {
				out[peers[0]][0].SetNexthop(netip.MustParseAddr("203.0.113.99"))
				require.NotEqual(t, out[peers[0]][0].GetNexthop(), out[peers[1]][0].GetNexthop())
				require.Equal(t, netip.MustParseAddr("192.0.2.1"), input.GetNexthop())
			}
		})
	}
}

func TestUpdateGroupOldPathEvaluation(t *testing.T) {
	for _, rejectOld := range []bool{false, true} {
		t.Run(fmt.Sprintf("reject-old=%v", rejectOld), func(t *testing.T) {
			s, peers := exportTestPeers(t, 10)
			set, err := table.NewCommunitySet(oc.CommunitySet{CommunitySetName: "old", CommunityList: []string{"65000:1"}})
			require.NoError(t, err)
			require.NoError(t, s.policy.AddDefinedSet(set, false))
			st, err := table.NewStatement(oc.Statement{Name: "old", Conditions: oc.Conditions{BgpConditions: oc.BgpConditions{
				MatchCommunitySet: oc.MatchCommunitySet{CommunitySet: "old", MatchSetOptions: oc.MATCH_SET_OPTIONS_TYPE_ANY},
			}}, Actions: oc.Actions{RouteDisposition: oc.ROUTE_DISPOSITION_ACCEPT_ROUTE}})
			require.NoError(t, err)
			st.RouteAction = &table.RoutingAction{AcceptRoute: !rejectOld}
			reject := &table.Statement{Name: "reject", RouteAction: &table.RoutingAction{AcceptRoute: false}}
			require.NoError(t, s.policy.AddPolicy(&table.Policy{Name: "export", Statements: []*table.Statement{st, reject}}, false))
			require.NoError(t, s.policy.SetPolicyAssignment(table.GLOBAL_RIB_NAME, table.POLICY_DIRECTION_EXPORT, []*oc.PolicyDefinition{{Name: "export"}}, table.ROUTE_TYPE_REJECT))
			require.Len(t, s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups, 1)
			var oldCalls, newCalls atomic.Int64
			st.RouteAction = &updateGroupCountAction{Action: st.RouteAction, calls: &oldCalls}
			reject.RouteAction = &updateGroupCountAction{Action: reject.RouteAction, calls: &newCalls}
			old := newPolicyTestPath(t, &table.PeerInfo{AS: 65100})
			old.SetCommunities([]uint32{65000<<16 | 1}, true)
			input := old.Clone(false)
			input.SetCommunities(nil, true)
			// Two distinct new candidates sharing one old path/context.
			input2 := input.Clone(false)
			paths, olds := []*table.Path{input, input2}, []*table.Path{old, old}
			out := updateGroupOutputs(t, s, paths, olds)
			require.EqualValues(t, 2, newCalls.Load())
			require.EqualValues(t, 1, oldCalls.Load())
			for _, p := range peers {
				want := s.processOutgoingPaths(p, paths, olds)
				require.Len(t, out[p], len(want))
				for i, path := range want {
					require.True(t, path.Equal(out[p][i]))
					require.True(t, out[p][i].IsWithdraw)
				}
			}
			oldCalls.Store(0)
			newCalls.Store(0)
			updateGroupOutputs(t, s, paths, olds)
			require.EqualValues(t, 1, oldCalls.Load(), "old cache lives only within fanout")
			require.EqualValues(t, 2, newCalls.Load())
			oldCalls.Store(0)
			newCalls.Store(0)
			input2.SetNexthop(netip.MustParseAddr("192.0.2.2"))
			updateGroupOutputs(t, s, paths, olds)
			require.EqualValues(t, 2, oldCalls.Load(), "old checks with different next-hop contexts stay separate")
			require.EqualValues(t, 2, newCalls.Load())
		})
	}
}

func TestUpdateGroupRegistryLifecycle(t *testing.T) {
	s, peers := exportTestPeers(t, 2)
	first := s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups
	require.Len(t, first, 1)
	require.Same(t, first[0], s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups[0])
	exportTestPolicy(t, s, exportAttributePolicy())
	second := s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups
	require.NotSame(t, first[0], second[0])
	require.Same(t, second[0], s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups[0])
	// Unsupported policy changes split existing groups, without a session reset.
	exportTestPolicy(t, s, []oc.Statement{{Name: "peer-address", Actions: oc.Actions{BgpActions: oc.BgpActions{SetNextHop: "peer-address"}}}})
	require.Empty(t, s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups)
	require.Len(t, s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).individual, 2)
	exportTestPolicy(t, s, exportAttributePolicy())
	require.Len(t, s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups, 1)
	// Configuration invalidation drops the cache without changing published snapshots.
	before := s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups
	s.updateGroups.invalidate()
	require.Empty(t, s.updateGroups.entries)
	require.NotSame(t, before[0], s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups[0])
	s.updateGroups.invalidate()
	conf := peers[0].fsm.pConf.ReadCopy()
	conf.AsPathOptions.State.ReplacePeerAs = true
	peers[0].fsm.pConf.Update(&conf)
	require.Empty(t, s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups)
	require.Len(t, s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).individual, 2)
}

func TestUpdateGroupAssignments(t *testing.T) {
	s, peers := exportTestPeers(t, 2)
	exportTestPolicy(t, s, exportAttributePolicy())
	require.Len(t, s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups, 1)
	require.NoError(t, s.policy.SetPolicyAssignment(peers[0].ID(), table.POLICY_DIRECTION_EXPORT, []*oc.PolicyDefinition{{Name: "export"}}, table.ROUTE_TYPE_ACCEPT))
	peers[0].updatePolicyIDs()
	require.Len(t, s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups, 1, "assignment source does not enter key")
	require.NoError(t, s.policy.SetPolicyAssignment(peers[0].ID(), table.POLICY_DIRECTION_EXPORT, nil, table.ROUTE_TYPE_REJECT))
	peers[0].updatePolicyIDs()
	require.Empty(t, s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups)
	require.Len(t, s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).individual, 2)
	require.NoError(t, s.policy.DeletePolicyAssignment(peers[0].ID(), table.POLICY_DIRECTION_EXPORT, nil, true))
	peers[0].updatePolicyIDs()
	require.Len(t, s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups, 1)
}

func TestUpdateGroupFallback(t *testing.T) {
	cases := []struct {
		name   string
		family bgp.Family
		change func(*peer)
	}{
		{"add-path", bgp.RF_IPv4_UC, func(p *peer) {
			p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_SEND})
		}},
		{"vrf", bgp.RF_IPv4_UC, func(p *peer) { c := p.fsm.pConf.ReadCopy(); c.Config.Vrf = "vrf"; p.fsm.pConf.Update(&c) }},
		{"replace-as", bgp.RF_IPv4_UC, func(p *peer) {
			c := p.fsm.pConf.ReadCopy()
			c.AsPathOptions.State.ReplacePeerAs = true
			p.fsm.pConf.Update(&c)
		}},
		{"disabled-family", bgp.RF_IPv4_UC, func(p *peer) { p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{}) }},
		{"down", bgp.RF_IPv4_UC, func(p *peer) {
			c := p.fsm.pConf.ReadCopy()
			p.fsm.state.Store(bgp.BGP_FSM_IDLE)
			c.State.SessionState = oc.SESSION_STATE_IDLE
			p.fsm.pConf.Update(&c)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, peers := exportTestPeers(t, 2)
			if tc.change != nil {
				for _, p := range peers {
					tc.change(p)
				}
			}
			groups := s.updateGroups.getTargets(tc.family, s.policy, s.neighborMap).groups
			if tc.name == "down" {
				require.Empty(t, s.updateGroups.getTargets(tc.family, s.policy, s.neighborMap).individual)
				require.Empty(t, groups)
				return
			}
			require.Empty(t, groups)
			require.ElementsMatch(t, peers, s.updateGroups.getTargets(tc.family, s.policy, s.neighborMap).individual)
		})
	}
}

func TestUpdateGroupRecipientChecks(t *testing.T) {
	s, peers := exportTestPeers(t, 3)
	input := newPolicyTestPath(t, &table.PeerInfo{AS: 65100, Address: netip.MustParseAddr(peers[0].ID())})
	requireUpdateGroupParity(t, s, peers, []*table.Path{input}, nil)
	old := input.Clone(false)
	input = input.Clone(false)
	input.SetCommunities([]uint32{uint32(bgp.COMMUNITY_NO_ADVERTISE)}, true)
	requireUpdateGroupParity(t, s, peers, []*table.Path{input}, []*table.Path{old})
	input = old.Clone(true)
	requireUpdateGroupParity(t, s, peers, []*table.Path{input}, nil)
}

func TestUpdateGroupParallelFanout(t *testing.T) {
	s, peers := exportTestPeers(t, 10)
	exportTestPolicy(t, s, exportAttributePolicy())
	var wg sync.WaitGroup
	for i := range 8 {
		input := updateGroupFamilyPath(t, bgp.RF_IPv4_UC, i+1)
		wg.Go(func() {
			for range 25 {
				s.shared.mu.RLock()
				targets := s.updateGroups.getTargets(input.GetFamily(), s.policy, s.neighborMap)
				s.propagateUpdateToGroups(targets.groups, input.GetFamily(), []*table.Path{input}, nil)
				s.shared.mu.RUnlock()
			}
		})
	}
	wg.Go(func() {
		for range 25 {
			s.shared.mu.Lock()
			err := s.policy.SetPolicyAssignment(table.GLOBAL_RIB_NAME, table.POLICY_DIRECTION_EXPORT, nil, table.ROUTE_TYPE_ACCEPT)
			s.updateGroups.invalidate()
			s.shared.mu.Unlock()
			if err != nil {
				t.Error(err)
			}
		}
	})
	wg.Wait()
	out := queuedGroupPaths(t, peers)
	for _, p := range peers {
		require.Len(t, out[p], 8*25, p.ID())
	}
}

func TestUpdateGroupFanoutDelivery(t *testing.T) {
	s, peers := exportTestPeers(t, 10)
	exportTestPolicy(t, s, exportAttributePolicy())
	input := newPolicyTestPath(t, &table.PeerInfo{AS: 65100, Address: netip.MustParseAddr("198.51.100.1")})
	s.propagateUpdate(nil, []*table.Path{input})
	for _, p := range peers {
		select {
		case msg := <-p.fsm.outgoingCh.Out():
			paths := msg.(*fsmOutgoingMsg).Paths
			require.Len(t, paths, 1)
			med, err := paths[0].GetMed()
			require.NoError(t, err)
			require.Equal(t, uint32(123), med)
			require.True(t, p.hasPathAlreadyBeenSent(paths[0]))
		case <-time.After(time.Second):
			t.Fatal("the UPDATE was not passed to the output queue")
		}
	}
}

func TestUpdateGroupKeySeparatesOutboundSettings(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*table.PeerInfo, *oc.Neighbor)
	}{
		{"local-as", func(i *table.PeerInfo, c *oc.Neighbor) { i.LocalAS++ }},
		{"peer-type", func(i *table.PeerInfo, c *oc.Neighbor) { i.PeerType = oc.PEER_TYPE_INTERNAL }},
		{"remove-private-as", func(i *table.PeerInfo, c *oc.Neighbor) { i.RemovePrivateAs = oc.REMOVE_PRIVATE_AS_OPTION_ALL }},
		{"local-address", func(i *table.PeerInfo, c *oc.Neighbor) { i.LocalAddress = netip.MustParseAddr("192.0.2.250") }},
		{"cluster-id", func(i *table.PeerInfo, c *oc.Neighbor) {
			i.RouteReflectorClusterID = netip.MustParseAddr("192.0.2.250")
		}},
		{"rr-client", func(i *table.PeerInfo, c *oc.Neighbor) { i.RouteReflectorClient = true }},
		{"confederation", func(i *table.PeerInfo, c *oc.Neighbor) { i.Confederation = true }},
		{"zone", func(i *table.PeerInfo, c *oc.Neighbor) { i.Address = netip.MustParseAddr("fe80::1%eth0") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, peers := exportTestPeers(t, 2)
			i, c := *peers[0].peerInfo.Load(), peers[0].fsm.pConf.ReadCopy()
			tc.change(&i, &c)
			peers[0].peerInfo.Store(&i)
			peers[0].fsm.pConf.Update(&c)
			require.Empty(t, s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups)
			require.Len(t, s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).individual, 2)
		})
	}
}

func TestUpdateGroupIPv6RouteReflection(t *testing.T) {
	for _, local := range []bool{false, true} {
		t.Run(fmt.Sprintf("local=%v", local), func(t *testing.T) {
			s, peers := exportTestPeers(t, 3)
			for _, p := range peers {
				c := p.fsm.pConf.ReadCopy()
				c.Config.PeerAs = 65000
				c.State.PeerAs = 65000
				c.State.PeerType = oc.PEER_TYPE_INTERNAL
				c.RouteReflector.Config.RouteReflectorClient = true
				c.RouteReflector.State.RouteReflectorClusterId = s.bgpConfig.Global.Config.RouterId
				p.fsm.pConf.Update(&c)
				info := *p.peerInfo.Load()
				info.PeerType = oc.PEER_TYPE_INTERNAL
				info.AS = 65000
				info.RouteReflectorClient = true
				info.RouteReflectorClusterID = s.bgpConfig.Global.Config.RouterId
				info.LocalAddress = netip.MustParseAddr("2001:db8::1")
				p.peerInfo.Store(&info)
			}
			nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:db8:100::/64"))
			require.NoError(t, err)
			source := &table.PeerInfo{AS: 65000, Address: netip.MustParseAddr("2001:db8::10"), ID: netip.MustParseAddr("192.0.2.10")}
			if local {
				source = &table.PeerInfo{AS: 65000}
			}
			reach, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri}}, netip.MustParseAddr("::"))
			require.NoError(t, err)
			input := table.NewPath(bgp.RF_IPv6_UC, source, bgp.PathNLRI{NLRI: nlri}, false, []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), reach}, time.Now(), false)
			input.SetNexthop(netip.MustParseAddr("::"))
			require.Len(t, s.updateGroups.getTargets(bgp.RF_IPv6_UC, s.policy, s.neighborMap).groups, 1)
			out := requireUpdateGroupParity(t, s, peers, []*table.Path{input}, nil)
			for _, p := range peers {
				require.Len(t, out[p], 1)
				require.Equal(t, netip.MustParseAddr("2001:db8::1"), out[p][0].GetNexthop())
				require.Equal(t, []netip.Addr{s.bgpConfig.Global.Config.RouterId}, out[p][0].GetClusterList())
			}
		})
	}
}

func TestUpdateGroupRejectedConfigKeepsRegistry(t *testing.T) {
	s, peers := exportTestPeers(t, 2)
	groups := s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups
	require.Len(t, groups, 1)

	c := peers[0].fsm.pConf.ReadCopy()
	c.Config.PeerGroup = "missing-group"
	require.Error(t, s.addNeighbor(&c))
	require.Same(t, groups[0], s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups[0])

	_, err := s.updateNeighbor(&c)
	require.Error(t, err)
	require.Same(t, groups[0], s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups[0])

	_, err = s.updatePeerGroup(&oc.PeerGroup{Config: oc.PeerGroupConfig{PeerGroupName: "missing-group"}})
	require.Error(t, err)
	require.Same(t, groups[0], s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups[0])
}

func TestUpdateGroupConfigAndRemoval(t *testing.T) {
	s, peers := exportTestPeers(t, 2)
	require.Len(t, s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups, 1)
	c := peers[0].fsm.pConf.ReadCopy()
	c.AsPathOptions.Config.ReplacePeerAs = true
	c.AsPathOptions.State.ReplacePeerAs = true
	_, err := s.updateNeighbor(&c)
	require.NoError(t, err)
	require.Empty(t, s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups)
	require.Len(t, s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).individual, 2)
	// This fixture has no running FSM goroutine; exercise real removal with a
	// no-op cancellation hook, leaving channel cleanup to the fixture.
	peers[0].fsm.h = &fsmHandler{ctxCancel: func() {}}
	require.NoError(t, s.deleteNeighbor(&c, 0, 0, false))
	for _, entry := range s.updateGroups.entries {
		for _, group := range entry.groups {
			require.NotContains(t, updateGroupPeers(group), peers[0])
		}
	}
	groups := s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups
	require.Empty(t, groups)
	require.Equal(t, []*peer{peers[1]}, s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).individual)
}

func TestUpdateGroupSessionLifecycle(t *testing.T) {
	s, peers := exportTestPeers(t, 2)
	require.Len(t, s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups, 1)
	p := peers[0]
	s.handleFSMMessage(p, &fsmMsg{MsgType: fsmMsgStateChange, MsgData: bgp.BGP_FSM_IDLE, StateReason: newfsmStateReason(fsmAdminDown, nil, nil)})
	require.NotContains(t, s.updateGroups.entries, bgp.RF_IPv4_UC)
	input := newPolicyTestPath(t, &table.PeerInfo{AS: 65100})
	updateGroupOutputs(t, s, []*table.Path{input}, nil)
	groups := s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups
	require.Empty(t, groups)
	require.Equal(t, []*peer{peers[1]}, s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).individual)
	c := p.fsm.pConf.ReadCopy()
	c.Transport.State.LocalAddress = s.bgpConfig.Global.Config.RouterId
	c.Transport.State.RemoteAddress = c.Config.NeighborAddress
	p.fsm.pConf.Update(&c)
	done := make(chan struct{})
	t.Cleanup(func() { <-done })
	func() {
		s.updateGroups.mu.Lock()
		defer s.updateGroups.mu.Unlock()
		go func() {
			defer close(done)
			s.handleFSMMessage(p, &fsmMsg{MsgType: fsmMsgStateChange, MsgData: bgp.BGP_FSM_ESTABLISHED, StateReason: newfsmStateReason(fsmAdminDown, nil, nil)})
		}()
		require.Eventually(t, func() bool { return p.State() == bgp.BGP_FSM_ESTABLISHED }, 5*time.Second, time.Millisecond,
			"Established must be published before group invalidation")
	}()
	<-done
	require.Equal(t, bgp.BGP_FSM_ESTABLISHED, p.State())
	groups = s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups
	require.Len(t, groups, 1)
	require.ElementsMatch(t, peers, updateGroupPeers(groups[0]))
	require.Same(t, groups[0], s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups[0])
}

type updateGroupCountCondition struct {
	table.Condition
	calls *atomic.Int64
}

func (c *updateGroupCountCondition) Evaluate(path *table.Path, options *table.PolicyOptions) bool {
	c.calls.Add(1)
	return c.Condition.Evaluate(path, options)
}

func TestUpdateGroupNextHopCondition(t *testing.T) {
	s, peers := exportTestPeers(t, 10)
	original := netip.MustParseAddr("192.0.2.1")
	st, err := table.NewStatement(oc.Statement{Name: "next-hop", Conditions: oc.Conditions{
		BgpConditions: oc.BgpConditions{NextHopInList: []netip.Addr{original}},
	}, Actions: oc.Actions{RouteDisposition: oc.ROUTE_DISPOSITION_ACCEPT_ROUTE}})
	require.NoError(t, err)
	require.NoError(t, s.policy.AddPolicy(&table.Policy{Name: "export", Statements: []*table.Statement{st}}, false))
	require.NoError(t, s.policy.SetPolicyAssignment(table.GLOBAL_RIB_NAME, table.POLICY_DIRECTION_EXPORT,
		[]*oc.PolicyDefinition{{Name: "export"}}, table.ROUTE_TYPE_REJECT))
	require.Len(t, s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups, 1)
	var calls atomic.Int64
	st.Conditions[0] = &updateGroupCountCondition{Condition: st.Conditions[0], calls: &calls}
	accepted := newPolicyTestPath(t, &table.PeerInfo{AS: 65100, Address: netip.MustParseAddr("198.51.100.1")})
	rejected := accepted.Clone(false)
	rejected.SetNexthop(netip.MustParseAddr("192.0.2.2"))
	otherRejected := accepted.Clone(false)
	otherRejected.SetNexthop(netip.MustParseAddr("192.0.2.3"))
	paths := []*table.Path{accepted, rejected, otherRejected}
	olds := []*table.Path{nil, accepted, accepted}
	out := updateGroupOutputs(t, s, paths, olds)
	require.EqualValues(t, 5, calls.Load(), "three current candidates and two old-path next-hop contexts, once per group")
	for _, p := range peers {
		require.Len(t, out[p], 1)
		require.False(t, out[p][0].IsWithdraw)
		// eBGP rewrites the next hop before policy evaluation. The condition
		// still matches the original next hop through PolicyOptions.OldNextHop.
		require.Equal(t, p.peerInfo.Load().LocalAddress, out[p][0].GetNexthop())
		require.NotEqual(t, original, out[p][0].GetNexthop())
		require.Equal(t, updateGroupWire(t, s.processOutgoingPaths(p, paths, olds)), updateGroupWire(t, out[p]))
	}
}

func TestUpdateGroupNextHopActions(t *testing.T) {
	for _, action := range []string{"self", "unchanged", "peer-address"} {
		for _, local := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/local=%v", action, local), func(t *testing.T) {
				s, peers := exportTestPeers(t, 3)
				st, err := table.NewStatement(oc.Statement{Name: "next-hop", Actions: oc.Actions{
					RouteDisposition: oc.ROUTE_DISPOSITION_ACCEPT_ROUTE,
					BgpActions:       oc.BgpActions{SetNextHop: oc.BgpNextHopType(action)},
				}})
				require.NoError(t, err)
				require.NoError(t, s.policy.AddPolicy(&table.Policy{Name: "export", Statements: []*table.Statement{st}}, false))
				require.NoError(t, s.policy.SetPolicyAssignment(table.GLOBAL_RIB_NAME, table.POLICY_DIRECTION_EXPORT,
					[]*oc.PolicyDefinition{{Name: "export"}}, table.ROUTE_TYPE_REJECT))
				evaluations := 1
				if action == "peer-address" {
					evaluations = len(peers)
				}
				entry := s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap)
				if action == "peer-address" {
					require.Empty(t, entry.groups)
					require.ElementsMatch(t, peers, entry.individual)
				} else {
					require.Len(t, entry.groups, 1)
					require.Empty(t, entry.individual)
				}
				var calls atomic.Int64
				st.ModActions[0] = &updateGroupCountAction{Action: st.ModActions[0], calls: &calls}
				source := &table.PeerInfo{AS: 65100, Address: netip.MustParseAddr("198.51.100.1")}
				if local {
					source.Address = netip.Addr{}
				}
				input := newPolicyTestPath(t, source)
				if local {
					input.SetNexthop(netip.IPv4Unspecified())
				}
				original := input.GetNexthop()
				out := updateGroupOutputs(t, s, []*table.Path{input}, nil)
				require.EqualValues(t, evaluations, calls.Load())
				for _, p := range peers {
					require.Len(t, out[p], 1)
					want := p.peerInfo.Load().LocalAddress
					if action == "peer-address" {
						want = p.peerInfo.Load().Address
					} else if action == "unchanged" && !local {
						want = original
					}
					require.Equal(t, want, out[p][0].GetNexthop())
					require.True(t, s.filterpath(p, input, nil).Equal(out[p][0]))
				}
				require.Equal(t, original, input.GetNexthop())
			})
		}
	}
}

func TestUpdateGroupSessionDownInvalidatesSnapshot(t *testing.T) {
	s, peers := exportTestPeers(t, 3)
	original := s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups[0]
	inactive := peers[0]
	s.handleFSMMessage(inactive, &fsmMsg{MsgType: fsmMsgStateChange, MsgData: bgp.BGP_FSM_IDLE, StateReason: newfsmStateReason(fsmAdminDown, nil, nil)})
	require.NotContains(t, s.updateGroups.entries, bgp.RF_IPv4_UC,
		"session down must invalidate the cache before another fanout")
	conf := inactive.fsm.pConf.ReadCopy()
	input := newPolicyTestPath(t, &table.PeerInfo{AS: 65100})

	var wg sync.WaitGroup
	for i := range 4 {
		candidate := updateGroupFamilyPath(t, bgp.RF_IPv4_UC, i+1)
		wg.Go(func() {
			s.processOutgoingPathsForGroup(original, []*table.Path{candidate}, nil)
		})
	}
	wg.Wait()
	out := queuedGroupPaths(t, peers)
	require.NotContains(t, out, inactive, "sent to inactive peer")
	for _, p := range peers[1:] {
		require.Len(t, out[p], 4, p.ID())
	}
	groups := s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups
	require.Len(t, groups, 1)
	require.ElementsMatch(t, peers[1:], updateGroupPeers(groups[0]))
	require.ElementsMatch(t, peers, updateGroupPeers(original), "published membership must remain immutable")

	conf.State.SessionState = oc.SESSION_STATE_ESTABLISHED
	inactive.fsm.pConf.Update(&conf)
	s.updateGroups.invalidate()
	require.NotContains(t, updateGroupPeers(s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups[0]), inactive,
		"a session still being prepared must not join a group")
	inactive.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
	s.updateGroups.invalidate()
	rejoined := s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups[0]
	s.processOutgoingPathsForGroup(rejoined, []*table.Path{input}, nil)
	rebuilt := s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups[0]
	require.Same(t, rejoined, rebuilt)
	require.Contains(t, updateGroupPeers(rebuilt), inactive)
}

func TestUpdateGroupInvalidationRebuildsSnapshot(t *testing.T) {
	s, peers := exportTestPeers(t, 4)
	info := *peers[0].peerInfo.Load()
	info.LocalAS++
	peers[0].peerInfo.Store(&info)
	before := s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap)
	require.Len(t, before.groups, 1)
	require.Equal(t, []*peer{peers[0]}, before.individual)
	require.Same(t, before, s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap))

	s.updateGroups.invalidate()
	require.Empty(t, s.updateGroups.entries)
	after := s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap)
	require.NotSame(t, before, after)
	require.NotSame(t, before.groups[0], after.groups[0])
	require.ElementsMatch(t, updateGroupPeers(before.groups[0]), updateGroupPeers(after.groups[0]))

	// Removing an individual recipient also invalidates the cached snapshot.
	delete(s.neighborMap, netip.MustParseAddr(peers[0].ID()))
	s.updateGroups.invalidate()
	require.Empty(t, s.updateGroups.entries)
	rebuilt := s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap)
	require.Empty(t, rebuilt.individual)
	require.ElementsMatch(t, peers[1:], updateGroupPeers(rebuilt.groups[0]))
	require.Equal(t, []*peer{peers[0]}, before.individual)
	require.ElementsMatch(t, peers[1:], updateGroupPeers(before.groups[0]))
}

func TestUpdateGroupOldSessionIsSkippedAfterInitialUpdate(t *testing.T) {
	s, peers := exportTestPeers(t, 3)
	input := newPolicyTestPath(t, &table.PeerInfo{AS: 65100, Address: netip.MustParseAddr("198.51.100.1")})
	// Production updates the RIB before obtaining a group snapshot.
	s.globalRib.Update(input)
	group := s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups[0]
	neighbor := peers[0]
	s.handleFSMMessage(neighbor, &fsmMsg{MsgType: fsmMsgStateChange, MsgData: bgp.BGP_FSM_IDLE, StateReason: newfsmStateReason(fsmAdminDown, nil, nil)})
	conf := neighbor.fsm.pConf.ReadCopy()
	newAddress := netip.MustParseAddr("192.0.2.253")
	conf.Transport.State.LocalAddress = newAddress
	conf.Transport.State.RemoteAddress = conf.Config.NeighborAddress
	neighbor.fsm.pConf.Update(&conf)
	s.handleFSMMessage(neighbor, &fsmMsg{MsgType: fsmMsgStateChange, MsgData: bgp.BGP_FSM_ESTABLISHED, StateReason: newfsmStateReason(fsmAdminDown, nil, nil)})

	select {
	case msg := <-neighbor.fsm.outgoingCh.Out():
		paths := msg.(*fsmOutgoingMsg).Paths
		require.Len(t, paths, 1)
		require.Equal(t, input.GetPrefix(), paths[0].GetPrefix())
		require.Equal(t, newAddress, paths[0].GetNexthop())
	case <-time.After(time.Second):
		t.Fatal("new session did not receive the current RIB")
	}

	s.processOutgoingPathsForGroup(group, []*table.Path{input}, nil)
	out := queuedGroupPaths(t, peers)
	require.NotContains(t, out, neighbor, "old snapshot must not send into the new session")
	require.Len(t, out, 2)
	for _, p := range peers[1:] {
		expected := s.processOutgoingPaths(p, []*table.Path{input}, nil)
		require.Equal(t, updateGroupWire(t, expected), updateGroupWire(t, out[p]))
	}
}

func TestUpdateGroupFanoutDuringSessionChanges(t *testing.T) {
	s, peers := exportTestPeers(t, 3)
	neighbor := peers[0]
	conf := neighbor.fsm.pConf.ReadCopy()
	conf.Transport.State.LocalAddress = s.bgpConfig.Global.Config.RouterId
	conf.Transport.State.RemoteAddress = conf.Config.NeighborAddress
	neighbor.fsm.pConf.Update(&conf)
	var wg sync.WaitGroup
	for i := range 4 {
		input := updateGroupFamilyPath(t, bgp.RF_IPv4_UC, i+1)
		wg.Go(func() {
			for range 50 {
				s.shared.mu.RLock()
				targets := s.updateGroups.getTargets(input.GetFamily(), s.policy, s.neighborMap)
				s.propagateUpdateToGroups(targets.groups, input.GetFamily(), []*table.Path{input}, nil)
				for _, p := range targets.individual {
					p.routeRefreshInProgress.RLock()
					if outgoing := s.processOutgoingPaths(p, []*table.Path{input}, nil); len(outgoing) != 0 {
						sendOutgoingPaths(p, outgoing)
					}
					p.routeRefreshInProgress.RUnlock()
				}
				s.shared.mu.RUnlock()
			}
		})
	}
	wg.Go(func() {
		for range 20 {
			for _, state := range []bgp.FSMState{bgp.BGP_FSM_IDLE, bgp.BGP_FSM_ESTABLISHED} {
				s.handleFSMMessage(neighbor, &fsmMsg{MsgType: fsmMsgStateChange, MsgData: state, StateReason: newfsmStateReason(fsmAdminDown, nil, nil)})
				neighbor.fsm.state.Store(state)
			}
		}
	})
	wg.Wait()
	groups := s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups
	require.Len(t, groups, 1)
	require.ElementsMatch(t, peers, updateGroupPeers(groups[0]))
}

func TestUpdateGroupPerPeerCapabilities(t *testing.T) {
	for _, name := range []string{"llgr", "extended-next-hop", "encoding-and-timer"} {
		t.Run(name, func(t *testing.T) {
			s, peers := exportTestPeers(t, 2)
			conf := peers[0].fsm.pConf.ReadCopy()
			input := newPolicyTestPath(t, &table.PeerInfo{AS: 65100, Address: netip.MustParseAddr("198.51.100.1")})
			switch name {
			case "llgr":
				conf.GracefulRestart.Config.LongLivedEnabled = true
				for i := range conf.AfiSafis {
					if conf.AfiSafis[i].State.Family == bgp.RF_IPv4_UC {
						conf.AfiSafis[i].LongLivedGracefulRestart.State.Enabled = true
					}
				}
				input.SetCommunities([]uint32{uint32(bgp.COMMUNITY_LLGR_STALE)}, true)
			case "extended-next-hop":
				peers[0].fsm.capMap = map[bgp.BGPCapabilityCode][]bgp.ParameterCapabilityInterface{
					bgp.BGP_CAP_EXTENDED_NEXTHOP: {bgp.NewCapExtendedNexthop([]*bgp.CapExtendedNexthopTuple{
						bgp.NewCapExtendedNexthopTuple(bgp.RF_IPv4_UC, bgp.AFI_IP6),
					})},
				}
				exportTestPolicy(t, s, []oc.Statement{{Name: "v6-next-hop", Actions: oc.Actions{BgpActions: oc.BgpActions{SetNextHop: "2001:db8::1"}}}})
			case "encoding-and-timer":
				conf.State.RemoteCapabilityList = []bgp.ParameterCapabilityInterface{bgp.NewCapFourOctetASNumber(65200)}
				conf.Timers.Config.MinimumAdvertisementInterval++
			}
			peers[0].fsm.pConf.Update(&conf)
			require.Len(t, s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups, 1)
			out := requireUpdateGroupParity(t, s, peers, []*table.Path{input}, nil)
			require.False(t, out[peers[0]][0].IsWithdraw)
			require.Equal(t, name != "encoding-and-timer", out[peers[1]][0].IsWithdraw)
		})
	}
}

func TestUpdateGroupIgnoresPerPeerSessionSettings(t *testing.T) {
	s, peers := exportTestPeers(t, 2)
	neighbor := peers[0]
	conf := neighbor.fsm.pConf.ReadCopy()
	conf.Config.NeighborInterface = "eth1"
	conf.Config.PeerGroup = "another-group"
	conf.EbgpMultihop.Config.MultihopTtl = 20
	neighbor.fsm.pConf.Update(&conf)
	info := *neighbor.peerInfo.Load()
	info.LocalID = netip.MustParseAddr("192.0.2.200")
	info.PeerGroup = conf.Config.PeerGroup
	info.MultihopTtl = conf.EbgpMultihop.Config.MultihopTtl
	neighbor.peerInfo.Store(&info)
	neighbor.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_RECEIVE})
	require.Len(t, s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups, 1)
	input := newPolicyTestPath(t, &table.PeerInfo{AS: 65100, Address: netip.MustParseAddr("198.51.100.1")})
	out := requireUpdateGroupParity(t, s, peers, []*table.Path{input}, nil)
	for _, p := range peers {
		require.Len(t, out[p], 1)
	}
}

func TestUpdateGroupDifferentPeerAS(t *testing.T) {
	for _, tc := range []struct {
		name          string
		peerAS        [2]uint32
		members       []uint32
		groups        int
		firstFiltered bool
	}{
		{"external", [2]uint32{65200, 65300}, nil, 1, false},
		{"as-loop", [2]uint32{65100, 65200}, nil, 1, true},
		{"confederation-members", [2]uint32{65200, 65300}, []uint32{65200, 65300}, 1, false},
		{"confederation-boundary", [2]uint32{65200, 65300}, []uint32{65200}, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, peers := exportTestPeers(t, 2)
			s.bgpConfig.Global.Confederation.Config.MemberAsList = tc.members
			for i, neighbor := range peers {
				conf := neighbor.fsm.pConf.ReadCopy()
				conf.Config.PeerAs = tc.peerAS[i]
				conf.State.PeerAs = tc.peerAS[i]
				neighbor.fsm.pConf.Update(&conf)
				old := neighbor.peerInfo.Load()
				neighbor.peerInfo.Store(table.NewPeerInfo(&s.bgpConfig.Global, &conf, tc.peerAS[i], old.LocalAS,
					old.ID, old.LocalID, old.Address, old.LocalAddress))
			}
			entry := s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap)
			if tc.groups == 2 {
				require.Empty(t, entry.groups)
				require.ElementsMatch(t, peers, entry.individual)
			} else {
				require.Len(t, entry.groups, 1)
				require.Empty(t, entry.individual)
			}
			input := newPolicyTestPath(t, &table.PeerInfo{AS: 65100, Address: netip.MustParseAddr("198.51.100.1")})
			out := requireUpdateGroupParity(t, s, peers, []*table.Path{input}, nil)
			if tc.firstFiltered {
				require.Empty(t, out[peers[0]])
			} else {
				require.Len(t, out[peers[0]], 1)
			}
			require.Len(t, out[peers[1]], 1)
		})
	}
}

func TestUpdateGroupTimerUpdateKeepsRegistry(t *testing.T) {
	s, peers := exportTestPeers(t, 2)
	before := s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups
	conf := peers[0].fsm.pConf.ReadCopy()
	conf.Timers.Config.MinimumAdvertisementInterval++
	_, err := s.updateNeighbor(&conf)
	require.NoError(t, err)
	require.NotNil(t, s.updateGroups.entries[bgp.RF_IPv4_UC])
	require.Same(t, before[0], s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups[0])
}

func updateGroupFamilyPeers(t testing.TB, count int, families ...bgp.Family) (*BgpServer, []*peer) {
	t.Helper()
	s, peers := exportTestPeers(t, count)
	s.globalRib = table.NewTableManager(logger, families, oc.RouteSelectionOptionsConfig{}, oc.UseMultiplePathsConfig{})
	for _, p := range peers {
		p.localRib = s.globalRib
		modes := make(map[bgp.Family]bgp.BGPAddPathMode)
		for _, family := range families {
			modes[family] = 0
		}
		p.fsm.familyMap.Store(modes)
	}
	return s, peers
}

func updateGroupFamilyPath(t testing.TB, family bgp.Family, index int) *table.Path {
	t.Helper()
	rd := bgp.NewRouteDistinguisherTwoOctetAS(65000, 100)
	prefix := netip.MustParsePrefix(fmt.Sprintf("203.0.%d.0/24", index))
	nextHop := netip.MustParseAddr("198.51.100.1")
	if family.Afi() == bgp.AFI_IP6 {
		prefix = netip.MustParsePrefix(fmt.Sprintf("2001:db8:%x::/64", index))
		nextHop = netip.MustParseAddr("2001:db8::1")
	}
	var nlri bgp.NLRI
	var err error
	switch family {
	case bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN:
		nlri, err = bgp.NewLabeledVPNIPAddrPrefix(prefix, *bgp.NewMPLSLabelStack(100), rd)
	case bgp.RF_IPv4_MPLS, bgp.RF_IPv6_MPLS:
		nlri, err = bgp.NewLabeledIPAddrPrefix(prefix, *bgp.NewMPLSLabelStack(100))
	case bgp.RF_EVPN:
		nlri, err = bgp.NewEVPNMacIPAdvertisementRoute(rd, bgp.EthernetSegmentIdentifier{}, 0,
			fmt.Sprintf("00:11:22:33:44:%02x", index), prefix.Addr(), []uint32{100})
	case bgp.RF_FS_IPv4_UC:
		var destination *bgp.IPAddrPrefix
		destination, err = bgp.NewIPAddrPrefix(prefix)
		require.NoError(t, err)
		nlri, err = bgp.NewFlowSpecUnicast(family, []bgp.FlowSpecComponentInterface{bgp.NewFlowSpecDestinationPrefix(destination)})
	case bgp.RF_RTC_UC:
		nlri = bgp.NewRouteTargetMembershipNLRI(65000,
			bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 65000, uint32(index), true))
	default:
		nlri, err = bgp.NewIPAddrPrefix(prefix)
	}
	require.NoError(t, err)
	nextHops := []netip.Addr{nextHop}
	if family == bgp.RF_FS_IPv4_UC {
		nextHops = nil
	}
	mp, err := bgp.NewPathAttributeMpReachNLRI(family, []bgp.PathNLRI{{NLRI: nlri}}, nextHops...)
	require.NoError(t, err)
	return table.NewPath(family, &table.PeerInfo{
		AS: 65100, LocalAS: 65000,
		Address: netip.MustParseAddr("198.51.100.1"), ID: netip.MustParseAddr("198.51.100.1"),
	},
		bgp.PathNLRI{NLRI: nlri}, false, []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0), mp,
			bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{65100})}),
		}, time.Now(), false)
}

// Count real policy calls after building the group.
func countUpdateGroupPolicy(t testing.TB, s *BgpServer, family bgp.Family, reject bool) *atomic.Int64 {
	t.Helper()
	st, err := table.NewStatement(exportAttributePolicy()[0])
	require.NoError(t, err)
	st.RouteAction = &table.RoutingAction{AcceptRoute: !reject}
	require.NoError(t, s.policy.AddPolicy(&table.Policy{Name: "counted", Statements: []*table.Statement{st}}, false))
	require.NoError(t, s.policy.SetPolicyAssignment(table.GLOBAL_RIB_NAME, table.POLICY_DIRECTION_EXPORT,
		[]*oc.PolicyDefinition{{Name: "counted"}}, table.ROUTE_TYPE_ACCEPT))
	require.Len(t, s.updateGroups.getTargets(family, s.policy, s.neighborMap).groups, 1)
	calls := &atomic.Int64{}
	st.ModActions[0] = &updateGroupCountAction{Action: st.ModActions[0], calls: calls}
	return calls
}

func updateGroupWire(t testing.TB, paths []*table.Path) [][]byte {
	t.Helper()
	var result [][]byte
	for _, msg := range table.CreateUpdateMsgFromPaths(paths) {
		data, err := msg.Serialize()
		require.NoError(t, err)
		result = append(result, data)
	}
	return result
}

func TestUpdateGroupAddressFamilies(t *testing.T) {
	for _, family := range []bgp.Family{
		bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN, bgp.RF_EVPN,
		bgp.RF_IPv4_MPLS, bgp.RF_IPv6_MPLS, bgp.RF_IPv4_MC, bgp.RF_IPv6_MC, bgp.RF_FS_IPv4_UC,
	} {
		t.Run(family.String(), func(t *testing.T) {
			s, peers := updateGroupFamilyPeers(t, 10, family)
			calls := countUpdateGroupPolicy(t, s, family, false)
			inputs := []*table.Path{updateGroupFamilyPath(t, family, 1), updateGroupFamilyPath(t, family, 2)}
			// Multiple destinations remain in the same order in one output per peer.
			out := updateGroupOutputs(t, s, inputs, nil)
			require.EqualValues(t, 2, calls.Load(), "one evaluation per candidate, not per recipient")
			for _, p := range peers {
				require.Len(t, out[p], 2)
				want := s.processOutgoingPaths(p, inputs, nil)
				require.Equal(t, updateGroupWire(t, want), updateGroupWire(t, out[p]))
			}
			require.NotSame(t, out[peers[0]][0], out[peers[1]][0])
			out[peers[0]][0].SetCommunities([]uint32{123}, true)
			require.Empty(t, out[peers[1]][0].GetCommunities())
			require.Empty(t, inputs[0].GetCommunities())
			withdrawals := []*table.Path{inputs[0].Clone(true), inputs[1].Clone(true)}
			requireUpdateGroupParity(t, s, peers, withdrawals, inputs)
		})
	}
}

func TestUpdateGroupVPNRTCInterest(t *testing.T) {
	for _, family := range []bgp.Family{bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN} {
		t.Run(family.String(), func(t *testing.T) {
			s, peers := updateGroupFamilyPeers(t, 4, family, bgp.RF_RTC_UC)
			exportTestPolicy(t, s, []oc.Statement{{Name: "rt-rewrite", Actions: oc.Actions{BgpActions: oc.BgpActions{
				SetExtCommunity: oc.SetExtCommunity{Options: "replace", SetExtCommunityMethod: oc.SetExtCommunityMethod{CommunitiesList: []string{"RT:65000:2"}}},
			}}}})
			rtA := bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 65000, 1, true)
			rtB := bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 65000, 2, true)
			input := updateGroupFamilyPath(t, family, 1)
			input.SetExtCommunities([]bgp.ExtendedCommunityInterface{rtA}, true)
			for i, p := range peers {
				// Two interested peers, one interested in the other RT, one with none.
				if i == 3 {
					continue
				}
				rt := rtA
				if i == 0 {
					rt = rtB
				}
				membership := table.NewPath(bgp.RF_RTC_UC, &table.PeerInfo{},
					bgp.PathNLRI{NLRI: bgp.NewRouteTargetMembershipNLRI(65000, rt)}, false, []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}, time.Now(), false)
				p.rtmHandler.SyncAfterImport(membership)
			}
			groups := s.updateGroups.getTargets(family, s.policy, s.neighborMap).groups
			require.Len(t, groups, 1, "RTC interest is a per-peer check, not group identity")
			out := requireUpdateGroupParity(t, s, peers, []*table.Path{input}, nil)
			require.Empty(t, out[peers[0]], "policy-added RT must not bypass RTC")
			require.Empty(t, out[peers[3]])
			for _, p := range peers[1:3] {
				require.Len(t, out[p], 1)
				require.Equal(t, rtB.String(), out[p][0].GetExtCommunities()[0].String())
			}
			replacement := input.Clone(false)
			replacement.SetExtCommunities([]bgp.ExtendedCommunityInterface{rtB}, true)
			out = requireUpdateGroupParity(t, s, peers, []*table.Path{replacement}, []*table.Path{input})
			require.Len(t, out[peers[0]], 1)
			require.False(t, out[peers[0]][0].IsWithdraw)
			for _, p := range peers[1:3] {
				require.Len(t, out[p], 1)
				require.True(t, out[p][0].IsWithdraw)
			}
			require.Empty(t, out[peers[3]])
			// UpdatePathAttrs creates a new AS_PATH for these eBGP peers.
			// Sharing that attribute proves synthesized withdrawals reuse it,
			// while each recipient still receives its own mutable path.
			require.Same(t, out[peers[1]][0].GetAsPath(), out[peers[2]][0].GetAsPath())
			require.NotSame(t, out[peers[1]][0], out[peers[2]][0])
			out[peers[1]][0].SetNexthop(netip.MustParseAddr("203.0.113.99"))
			require.NotEqual(t, out[peers[1]][0].GetNexthop(), out[peers[2]][0].GetNexthop())
			require.Equal(t, rtA.String(), out[peers[2]][0].GetExtCommunities()[0].String(), "withdrawals bypass export policy")

			// One batch can both announce and withdraw the same source path.
			out = requireUpdateGroupParity(t, s, peers, []*table.Path{input, replacement}, []*table.Path{nil, input})
			for _, p := range peers[1:3] {
				require.Len(t, out[p], 2)
				require.False(t, out[p][0].IsWithdraw)
				require.True(t, out[p][1].IsWithdraw)
			}

			out = requireUpdateGroupParity(t, s, peers, []*table.Path{input.Clone(true)}, nil)
			require.Same(t, out[peers[1]][0].GetAsPath(), out[peers[2]][0].GetAsPath(), "explicit withdrawals also share preparation")
		})
	}
}

func TestUpdateGroupRTCSelectedCandidates(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(fmt.Sprintf("reject=%v", reject), func(t *testing.T) {
			s, peers := updateGroupFamilyPeers(t, 4, bgp.RF_RTC_UC)
			calls := countUpdateGroupPolicy(t, s, bgp.RF_RTC_UC, reject)
			preferred := updateGroupFamilyPath(t, bgp.RF_RTC_UC, 1)
			// Each path gets its own source record from the fixture.
			preferred.GetSource().Address = netip.MustParseAddr(peers[0].ID())
			preferred.GetSource().ID = peers[0].routerID()
			preferred.GetSource().RouteReflectorClient = true
			preferred.SetCommunities([]uint32{1}, true)
			alternative := updateGroupFamilyPath(t, bgp.RF_RTC_UC, 1)
			alternative.SetCommunities([]uint32{2}, true)
			s.globalRib.Update(preferred)
			s.globalRib.Update(alternative)
			// The propagation input is neither of the actual selected candidates.
			input := updateGroupFamilyPath(t, bgp.RF_RTC_UC, 1)
			for i, p := range peers {
				selected, _, stop := s.peerFilterpath(p, input, nil)
				require.False(t, stop)
				if i == 0 {
					require.Same(t, alternative, selected)
				} else {
					require.Same(t, preferred, selected)
				}
			}
			out := updateGroupOutputs(t, s, []*table.Path{input}, nil)
			require.EqualValues(t, 2, calls.Load(), "each selected candidate evaluated once, including reject")
			for _, p := range peers {
				want := s.processOutgoingPaths(p, []*table.Path{input}, nil)
				require.Equal(t, updateGroupWire(t, want), updateGroupWire(t, out[p]))
			}
			calls.Store(0)
			updateGroupOutputs(t, s, []*table.Path{input}, nil)
			require.EqualValues(t, 2, calls.Load())
		})
	}
}

func updateGroupRTCPath(t testing.TB, source *table.PeerInfo) *table.Path {
	t.Helper()
	rt := bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 65000, 1, true)
	nlri := bgp.PathNLRI{NLRI: bgp.NewRouteTargetMembershipNLRI(65000, rt)}
	mp, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_RTC_UC, []bgp.PathNLRI{nlri}, netip.MustParseAddr("198.51.100.1"))
	require.NoError(t, err)
	return table.NewPath(bgp.RF_RTC_UC, source, nlri, false,
		[]bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), mp}, time.Now(), false)
}

func TestUpdateGroupRTCRRClients(t *testing.T) {
	s, peers := exportTestPeers(t, 3)
	for _, p := range peers {
		conf := p.fsm.pConf.ReadCopy()
		conf.Config.PeerAs, conf.State.PeerAs = 65000, 65000
		conf.Config.PeerType, conf.State.PeerType = oc.PEER_TYPE_INTERNAL, oc.PEER_TYPE_INTERNAL
		conf.RouteReflector.Config.RouteReflectorClient, conf.RouteReflector.State.RouteReflectorClient = true, true
		conf.RouteReflector.Config.RouteReflectorClusterId = s.bgpConfig.Global.Config.RouterId
		conf.RouteReflector.State.RouteReflectorClusterId = s.bgpConfig.Global.Config.RouterId
		p.fsm.pConf.Update(&conf)
		p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_RTC_UC: 0})
		addr := netip.MustParseAddr(p.ID())
		p.peerInfo.Store(table.NewPeerInfo(&s.bgpConfig.Global, &conf, 65000, 65000, addr,
			s.bgpConfig.Global.Config.RouterId, addr, s.bgpConfig.Global.Config.RouterId))
	}
	exportTestPolicy(t, s, exportAttributePolicy())
	require.Len(t, s.updateGroups.getTargets(bgp.RF_RTC_UC, s.policy, s.neighborMap).groups, 1)
	input := updateGroupRTCPath(t, peers[0].peerInfo.Load())
	out := requireUpdateGroupParity(t, s, peers, []*table.Path{input}, nil)
	for _, p := range peers {
		// RTC must also be announced back to its originating RR client.
		require.Len(t, out[p], 1)
		require.False(t, out[p][0].IsWithdraw)
	}
}

func TestUpdateGroupRTCLocalLoopAndWithdrawal(t *testing.T) {
	s, peers := exportTestPeers(t, 3)
	for _, p := range peers {
		p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_RTC_UC: 0})
	}
	input := updateGroupRTCPath(t, &table.PeerInfo{})
	// A new local candidate uses the existing old-local branch. An identical
	// repeat must still be suppressed before consulting shared results.
	old := input.Clone(false)
	old.SetNexthop(netip.MustParseAddr("198.51.100.2"))
	out := requireUpdateGroupParity(t, s, peers, []*table.Path{input}, []*table.Path{old})
	for _, p := range peers {
		require.Len(t, out[p], 1)
	}
	out = requireUpdateGroupParity(t, s, peers, []*table.Path{input}, []*table.Path{input})
	require.Empty(t, out)

	// Explicit withdrawals bypass RTC candidate selection even after the RIB
	// entry disappears, and must not be suppressed as duplicate local updates.
	withdraw := input.Clone(true)
	out = requireUpdateGroupParity(t, s, peers, []*table.Path{withdraw}, []*table.Path{input})
	for _, p := range peers {
		require.Len(t, out[p], 1)
		require.True(t, out[p][0].IsWithdraw)
	}
}

func TestUpdateGroupRTCFanoutDelivery(t *testing.T) {
	s, peers := exportTestPeers(t, 3)
	for _, p := range peers {
		p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_RTC_UC: 0})
	}
	exportTestPolicy(t, s, exportAttributePolicy())
	input := updateGroupRTCPath(t, &table.PeerInfo{})
	for _, withdraw := range []bool{false, true} {
		path := input
		if withdraw {
			path = input.Clone(true)
		}
		s.propagateUpdate(nil, []*table.Path{path})
		for _, p := range peers {
			select {
			case msg := <-p.fsm.outgoingCh.Out():
				paths := msg.(*fsmOutgoingMsg).Paths
				require.Len(t, paths, 1)
				require.Equal(t, withdraw, paths[0].IsWithdraw)
				require.Equal(t, withdraw, !p.hasPathAlreadyBeenSent(input))
			case <-time.After(time.Second):
				t.Fatalf("RTC update (withdraw=%t) was not delivered to %s", withdraw, p.ID())
			}
		}
	}
}

func TestUpdateGroupEVPNMacMobility(t *testing.T) {
	s, peers := updateGroupFamilyPeers(t, 3, bgp.RF_EVPN)
	exportTestPolicy(t, s, exportAttributePolicy())
	local := updateGroupFamilyPath(t, bgp.RF_EVPN, 1)
	localSource := *local.GetSource()
	localSource.Address = netip.Addr{}
	local.SetSource(&localSource)
	rt := bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 65000, 1, true)
	local.SetExtCommunities([]bgp.ExtendedCommunityInterface{rt, &bgp.MacMobilityExtended{Sequence: 0}}, true)
	s.propagateUpdate(nil, []*table.Path{local})
	receive := func(p *peer) []*table.Path {
		t.Helper()
		select {
		case msg := <-p.fsm.outgoingCh.Out():
			return msg.(*fsmOutgoingMsg).Paths
		case <-time.After(time.Second):
			t.Fatal("the EVPN UPDATE was not passed to the output queue")
			return nil
		}
	}
	for _, p := range peers {
		require.Len(t, receive(p), 1)
		require.True(t, p.hasPathAlreadyBeenSent(local))
	}
	incoming := updateGroupFamilyPath(t, bgp.RF_EVPN, 1)
	esi := bgp.EthernetSegmentIdentifier{Value: []byte{0, 0, 0, 0, 0, 0, 0, 0, 1}}
	nlri, err := bgp.NewEVPNMacIPAdvertisementRoute(bgp.NewRouteDistinguisherTwoOctetAS(65000, 200), esi, 0,
		"00:11:22:33:44:01", netip.MustParseAddr("203.0.1.0"), []uint32{200})
	require.NoError(t, err)
	nextHop := incoming.GetNexthop()
	incoming = table.NewPath(bgp.RF_EVPN, incoming.GetSource(), bgp.PathNLRI{NLRI: nlri}, false, incoming.GetPathAttrs(), time.Now(), false)
	incoming.SetNexthop(nextHop)
	incoming.SetExtCommunities([]bgp.ExtendedCommunityInterface{rt, &bgp.MacMobilityExtended{Sequence: 1}}, true)
	s.propagateUpdate(nil, []*table.Path{incoming})
	for _, p := range peers {
		paths := receive(p)
		require.Len(t, paths, 1, "the incoming destination is propagated first")
		paths = append(paths, receive(p)...)
		require.Len(t, paths, 2, "MAC mobility propagates the local withdrawal separately")
		require.Equal(t, incoming.GetPrefix(), paths[0].GetPrefix())
		require.False(t, paths[0].IsWithdraw)
		require.Equal(t, local.GetPrefix(), paths[1].GetPrefix())
		require.True(t, paths[1].IsWithdraw)
		require.True(t, p.hasPathAlreadyBeenSent(incoming))
		require.False(t, p.hasPathAlreadyBeenSent(local))
		want := s.processOutgoingPaths(p, []*table.Path{incoming, local.Clone(true)}, nil)
		require.Equal(t, updateGroupWire(t, want), updateGroupWire(t, paths))
	}
}

func TestUpdateGroupFamilyModes(t *testing.T) {
	for _, family := range []bgp.Family{bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN, bgp.RF_EVPN, bgp.RF_RTC_UC} {
		for _, mode := range []string{"add-path", "vrf", "route-server", "replace-as"} {
			t.Run(family.String()+"/"+mode, func(t *testing.T) {
				s, peers := updateGroupFamilyPeers(t, 2, family)
				for _, p := range peers {
					conf := p.fsm.pConf.ReadCopy()
					switch mode {
					case "add-path":
						p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{family: bgp.BGP_ADD_PATH_SEND})
					case "vrf":
						conf.Config.Vrf = "vrf"
					case "route-server":
						conf.RouteServer.Config.RouteServerClient = true
					case "replace-as":
						conf.AsPathOptions.State.ReplacePeerAs = true
					}
					p.fsm.pConf.Update(&conf)
				}
				groups := s.updateGroups.getTargets(family, s.policy, s.neighborMap).groups
				if mode == "route-server" {
					require.Empty(t, s.updateGroups.getTargets(family, s.policy, s.neighborMap).individual)
					require.Empty(t, groups)
					return
				}
				require.Empty(t, groups)
				require.ElementsMatch(t, peers, s.updateGroups.getTargets(family, s.policy, s.neighborMap).individual)
			})
		}
	}
}

func TestUpdateGroupWaitsForEstablished(t *testing.T) {
	s, peers := exportTestPeers(t, 2)
	peers[0].fsm.state.Store(bgp.BGP_FSM_OPENCONFIRM)
	require.Equal(t, oc.SESSION_STATE_ESTABLISHED, peers[0].fsm.pConf.ReadOnly().State.SessionState)
	assignment := s.policy.GetExportPolicyGroupInfo(peers[0].exportPolicyID)
	_, eligible := updateGroupKeyForPeer(peers[0], peers[0].peerInfo.Load(), bgp.RF_IPv4_UC, assignment)
	require.False(t, eligible)

	groups := s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).groups
	require.Empty(t, groups)
	require.Equal(t, []*peer{peers[1]}, s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap).individual)
}

func TestUpdateGroupLocalRestartDeferral(t *testing.T) {
	s, peers := exportTestPeers(t, 3)
	s.restart.PeerAdded(peers[0].ID(), []bgp.Family{bgp.RF_IPv4_UC})
	input := newPolicyTestPath(t, &table.PeerInfo{AS: 65100})
	s.propagateUpdate(nil, []*table.Path{input})
	for _, p := range peers {
		require.Zero(t, p.fsm.outgoingCh.Len(), "deferred routes must not be queued")
		require.False(t, p.hasPathAlreadyBeenSent(input))
	}
	s.runRestartActions(s.restart.PeerRemoved(peers[0].ID()), 0)
	for _, p := range peers {
		require.True(t, p.hasPathAlreadyBeenSent(input), "released routes must be advertised")
	}
}

func TestUpdateGroupsDefault(t *testing.T) {
	s, peers := exportTestPeers(t, 3)
	statement, err := table.NewStatement(exportAttributePolicy()[0])
	require.NoError(t, err)
	var calls atomic.Int64
	statement.ModActions[0] = &updateGroupCountAction{Action: statement.ModActions[0], calls: &calls}
	require.NoError(t, s.policy.AddPolicy(&table.Policy{Name: "counted", Statements: []*table.Statement{statement}}, false))
	require.NoError(t, s.policy.SetPolicyAssignment(table.GLOBAL_RIB_NAME, table.POLICY_DIRECTION_EXPORT,
		[]*oc.PolicyDefinition{{Name: "counted"}}, table.ROUTE_TYPE_ACCEPT))
	input := newPolicyTestPath(t, &table.PeerInfo{AS: 65100, Address: netip.MustParseAddr("198.51.100.1")})
	s.propagateUpdate(nil, []*table.Path{input})
	require.EqualValues(t, 1, calls.Load())
	require.NotEmpty(t, s.updateGroups.entries)
	for _, neighbor := range peers {
		select {
		case msg := <-neighbor.fsm.outgoingCh.Out():
			paths := msg.(*fsmOutgoingMsg).Paths
			require.Len(t, paths, 1)
			require.True(t, s.filterpath(neighbor, input, nil).Equal(paths[0]))
		case <-time.After(time.Second):
			t.Fatal("the UPDATE was not passed to the output queue")
		}
	}
}
