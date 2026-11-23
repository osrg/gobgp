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
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/require"
)

func BenchmarkUpdateGroupFanout(b *testing.B) {
	for _, policy := range []string{"none", "attributes", "regex", "self", "peer-address"} {
		for _, count := range []int{1, 10, 100} {
			for _, shared := range []bool{false, true} {
				b.Run(fmt.Sprintf("%s/peers=%d/shared=%v", policy, count, shared), func(b *testing.B) {
					s, peers := exportTestPeers(b, count)
					switch policy {
					case "attributes":
						exportTestPolicy(b, s, exportAttributePolicy())
					case "self", "peer-address":
						exportTestPolicy(b, s, []oc.Statement{{Name: "next-hop", Actions: oc.Actions{BgpActions: oc.BgpActions{SetNextHop: oc.BgpNextHopType(policy)}}}})
					case "regex":
						patterns := make([]string, 16)
						for i := range patterns {
							patterns[i] = fmt.Sprintf("^65000 (64512|64513)( [0-9]+)+ 42%02d$", i)
						}
						statements := append([]oc.Statement{{Name: "as-path", Conditions: oc.Conditions{BgpConditions: oc.BgpConditions{
							MatchAsPathSet: oc.MatchAsPathSet{AsPathSet: "expensive", MatchSetOptions: oc.MATCH_SET_OPTIONS_TYPE_ANY},
						}}, Actions: oc.Actions{RouteDisposition: oc.ROUTE_DISPOSITION_REJECT_ROUTE}}}, exportAttributePolicy()...)
						require.NoError(b, s.policy.Reset(&oc.RoutingPolicy{
							DefinedSets:       oc.DefinedSets{BgpDefinedSets: oc.BgpDefinedSets{AsPathSets: []oc.AsPathSet{{AsPathSetName: "expensive", AsPathList: patterns}}}},
							PolicyDefinitions: []oc.PolicyDefinition{{Name: "export", Statements: statements}},
						}, map[string]oc.ApplyPolicy{table.GLOBAL_RIB_NAME: {Config: oc.ApplyPolicyConfig{ExportPolicyList: []string{"export"}, DefaultExportPolicy: oc.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE}}}))
					}
					nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("203.0.113.0/24"))
					require.NoError(b, err)
					input := table.NewPath(bgp.RF_IPv4_UC, &table.PeerInfo{AS: 65100}, bgp.PathNLRI{NLRI: nlri}, false, []bgp.PathAttributeInterface{
						bgp.NewPathAttributeOrigin(0), bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{64512, 64496, 65100, 64513, 64497, 65101, 64514, 64498})}),
					}, time.Now(), false)
					paths := []*table.Path{input}
					s.updateGroups.getTargets(input.GetFamily(), s.policy, s.neighborMap)
					b.ReportAllocs()
					b.ResetTimer()
					for range b.N {
						benchmarkUpdateGroupFanout(s, peers, paths, shared)
					}
				})
			}
		}
	}
}

func BenchmarkUpdateGroupRegistry(b *testing.B) {
	for _, rebuild := range []bool{false, true} {
		b.Run(fmt.Sprintf("rebuild=%v", rebuild), func(b *testing.B) {
			s, _ := exportTestPeers(b, 100)
			exportTestPolicy(b, s, exportAttributePolicy())
			s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if rebuild {
					s.updateGroups.invalidate()
				}
				s.updateGroups.getTargets(bgp.RF_IPv4_UC, s.policy, s.neighborMap)
			}
		})
	}
}

// benchmarkGroupPaths measures shared filtering without route bookkeeping or
// outgoing queues. Production delivery is exercised through the FSM in tests.
func benchmarkGroupPaths(s *BgpServer, group *updateGroup, paths, olds []*table.Path, emit func(*peer, []*table.Path)) {
	cache := exportCache{filteredPaths: make(map[exportPathKey]*table.Path, len(paths))}
	if olds != nil {
		cache.sentOlds = make(map[oldPathPolicyKey]bool, len(olds))
	}
	for _, receiver := range group.receivers {
		func() {
			receiver.peer.routeRefreshInProgress.RLock()
			defer receiver.peer.routeRefreshInProgress.RUnlock()
			if !needToAdvertise(receiver.peer) {
				return
			}
			if outgoing := s.filterGroupPaths(receiver, paths, olds, &cache); len(outgoing) != 0 {
				emit(receiver.peer, outgoing)
			}
		}()
	}
}

func benchmarkUpdateGroupFanout(s *BgpServer, peers []*peer, paths []*table.Path, shared bool) {
	if shared {
		entry := s.updateGroups.getTargets(paths[0].GetFamily(), s.policy, s.neighborMap)
		for _, g := range entry.groups {
			benchmarkGroupPaths(s, g, paths, nil, func(*peer, []*table.Path) {})
		}
		for _, p := range entry.individual {
			p.routeRefreshInProgress.RLock()
			s.processOutgoingPaths(p, paths, nil)
			p.routeRefreshInProgress.RUnlock()
		}
	} else {
		for _, p := range peers {
			p.routeRefreshInProgress.RLock()
			s.processOutgoingPaths(p, paths, nil)
			p.routeRefreshInProgress.RUnlock()
		}
	}
}

func BenchmarkUpdateGroupFamilies(b *testing.B) {
	for _, family := range []bgp.Family{bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN, bgp.RF_EVPN, bgp.RF_RTC_UC} {
		for _, count := range []int{1, 10, 100} {
			for _, shared := range []bool{false, true} {
				b.Run(fmt.Sprintf("%s/peers=%d/shared=%v", family, count, shared), func(b *testing.B) {
					s, peers := updateGroupFamilyPeers(b, count, family)
					exportTestPolicy(b, s, exportAttributePolicy())
					input := updateGroupFamilyPath(b, family, 1)
					s.globalRib.Update(input) // RTC selects a candidate from the RIB per peer.
					paths := []*table.Path{input}
					s.updateGroups.getTargets(family, s.policy, s.neighborMap)
					b.ReportAllocs()
					b.ResetTimer()
					for range b.N {
						benchmarkUpdateGroupFanout(s, peers, paths, shared)
					}
				})
			}
		}
	}
}
