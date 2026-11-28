// Copyright (C) 2026 Nippon Telegraph and Telephone Corporation.
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
	"encoding/binary"
	"io"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/zebra"
)

func newNHTServer(t *testing.T) *BgpServer {
	t.Helper()
	s := NewBgpServer(LoggerOption(slog.New(slog.NewJSONHandler(io.Discard, nil)), nil))
	go s.Serve()
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 65000, RouterId: "192.0.2.1", ListenPort: -1},
	}))
	t.Cleanup(s.Stop)
	// Both VRFs import both RTs: the import domain must not be used as the
	// next-hop resolution domain.
	addVrf(t, s, "red", "65000:11", []string{"65000:11", "65000:22"}, []string{"65000:11"}, 11)
	addVrf(t, s, "blue", "65000:22", []string{"65000:11", "65000:22"}, []string{"65000:22"}, 22)
	return s
}

func nhtPath(t *testing.T, prefix string, nexthop netip.Addr, source *table.PeerInfo) *table.Path {
	t.Helper()
	p := netip.MustParsePrefix(prefix)
	nlri, err := bgp.NewIPAddrPrefix(p)
	require.NoError(t, err)
	nh, err := bgp.NewPathAttributeNextHop(nexthop)
	require.NoError(t, err)
	family := bgp.RF_IPv4_UC
	if p.Addr().Is6() {
		family = bgp.RF_IPv6_UC
	}
	return table.NewPath(family, source, bgp.PathNLRI{NLRI: nlri}, false,
		[]bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh}, time.Now(), false)
}

// Decode an FRR 8.1 ZAPI-v6 frame through the real stream decoder, retaining
// its header VRF. The NHT serializer does not yet encode reachable nexthops,
// so use the protocol fixture: one interface nexthop (type 1), with no flags.
func nhtMessage(t *testing.T, vrfID uint32, nexthop netip.Addr, metric uint32, reachable bool) *zebra.Message {
	t.Helper()
	family := uint16(syscall.AF_INET)
	if nexthop.Is6() {
		family = syscall.AF_INET6
	}
	body := binary.BigEndian.AppendUint32(nil, 0) // message flags
	body = binary.BigEndian.AppendUint16(body, family)
	body = append(body, byte(nexthop.BitLen()))
	body = append(body, nexthop.AsSlice()...)
	body = append(body, byte(zebra.RouteStatic), 0, 0, 0) // type, instance, distance
	body = binary.BigEndian.AppendUint32(body, metric)
	body = append(body, 0)
	if reachable {
		body[len(body)-1] = 1
		body = binary.BigEndian.AppendUint32(body, vrfID)
		body = append(body, 1, 0) // interface nexthop type, flags
		body = binary.BigEndian.AppendUint32(body, 2)
	}
	frame := binary.BigEndian.AppendUint16(nil, uint16(10+len(body)))
	frame = append(frame, zebra.HeaderMarker(6), 6)
	frame = binary.BigEndian.AppendUint32(frame, vrfID)
	frame = binary.BigEndian.AppendUint16(frame, 22) // FRR 8.1 ZEBRA_NEXTHOP_UPDATE
	frame = append(frame, body...)
	reader, writer := net.Pipe()
	defer reader.Close()
	defer writer.Close()
	done := make(chan error, 1)
	go func() {
		_, err := writer.Write(frame)
		done <- err
	}()
	msg, err := zebra.ReceiveSingleMsg(slog.New(slog.NewJSONHandler(io.Discard, nil)), reader,
		6, zebra.NewSoftware(6, "frr8.1"), "test")
	require.NoError(t, err)
	require.NoError(t, <-done)
	require.NotNil(t, msg)
	require.Equal(t, vrfID, msg.Header.VrfID)
	require.Len(t, msg.Body.(*zebra.NexthopUpdateBody).Nexthops, map[bool]int{false: 0, true: 1}[reachable])
	return msg
}

func applyNHTMessage(t *testing.T, z *zebraClient, msg *zebra.Message) bool {
	t.Helper()
	unregister, err := z.handleNexthopUpdate(msg.Header.VrfID, msg.Body.(*zebra.NexthopUpdateBody))
	require.NoError(t, err)
	return unregister
}

func TestZebraNHTVRFIsolation(t *testing.T) {
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, origin := range []string{"api", "peer"} {
			for _, sameNexthop := range []bool{true, false} {
				name := family + "/" + origin + "/" + map[bool]string{true: "same_nexthop", false: "distinct_control"}[sameNexthop]
				t.Run(name, func(t *testing.T) {
					s := newNHTServer(t)
					nh := netip.MustParseAddr("10.0.0.1")
					otherNH := netip.MustParseAddr("10.0.0.2")
					prefix, newPrefix, remotePrefix := "203.0.113.0/24", "203.0.114.0/24", "203.0.115.0/24"
					if family == "ipv6" {
						nh, otherNH = netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")
						prefix, newPrefix, remotePrefix = "2001:db8:113::/64", "2001:db8:114::/64", "2001:db8:115::/64"
					}
					blueNH := nh
					if !sameNexthop {
						blueNH = otherNH
					}
					peers := make(map[string]*peer)
					if origin == "peer" {
						for i, vrf := range []string{"red", "blue"} {
							p := newPeerandInfo(t, 65000, uint32(65100+i), []string{"192.0.2.11", "192.0.2.22"}[i], s.globalRib)
							p.policy = s.policy
							conf := p.fsm.pConf.ReadCopy()
							conf.Config.Vrf = vrf
							p.fsm.lock.Lock()
							p.fsm.pConf.Update(&conf)
							p.fsm.lock.Unlock()
							peers[vrf] = p
							require.NoError(t, s.mgmtOperation(func() error {
								s.neighborMap[p.peerInfo.Load().Address] = p
								return nil
							}, true))
						}
						t.Cleanup(func() {
							require.NoError(t, s.mgmtOperation(func() error {
								for _, p := range peers {
									delete(s.neighborMap, p.peerInfo.Load().Address)
									cleanInfiniteChannel(p.fsm.outgoingCh)
								}
								return nil
							}, false))
						})
					}
					var z *zebraClient
					add := func(vrf, destination string, nextHop netip.Addr) {
						t.Helper()
						if p := peers[vrf]; p != nil {
							path := nhtPath(t, destination, nextHop, p.peerInfo.Load())
							require.NoError(t, s.mgmtOperation(func() error {
								s.propagateUpdate(p, []*table.Path{path})
								return nil
							}, true))
							if z != nil {
								require.NoError(t, z.recheckNexthops([]nexthopStateKey{{map[string]uint32{"red": 11, "blue": 22}[vrf], nextHop}}))
							}
						} else {
							require.NoError(t, s.addPathStream(vrf, []*table.Path{nhtPath(t, destination, nextHop, nil)}))
						}
					}
					// Admission before Zebra is enabled must retain API origin scope.
					add("red", prefix, nh)
					add("blue", prefix, blueNH)
					add("", prefix, nh)
					// A remote VPN route deliberately carries red's RD and RT. Its
					// resolution domain is nevertheless the default VRF.
					remote := nhtPath(t, remotePrefix, nh, &table.PeerInfo{Address: netip.MustParseAddr("192.0.2.250")})
					red, _ := s.globalRib.GetVrf("red")
					remote = remote.ToGlobal(red)
					require.NoError(t, s.addPathStream("", []*table.Path{remote}))
					z = &zebraClient{server: s, nexthopCache: make(nexthopStateCache)}
					require.NoError(t, s.mgmtOperation(func() error { s.zclient = z; return nil }, true))
					for _, state := range []struct {
						vrf    uint32
						nh     netip.Addr
						metric uint32
					}{{11, nh, 20}, {22, blueNH, 40}, {0, nh, 60}} {
						require.False(t, applyNHTMessage(t, z, nhtMessage(t, state.vrf, state.nh, state.metric, true)))
					}
					pathCount := 4
					check := func(redInvalid, defaultInvalid bool, redMetric uint32) {
						t.Helper()
						require.NoError(t, s.mgmtOperation(func() error {
							paths := s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC, bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN})
							assert.Len(t, paths, pathCount)
							for _, path := range paths {
								var vrfID uint32
								if vpn, ok := path.GetNlri().(*bgp.LabeledVPNIPAddrPrefix); ok && vpn.Prefix.String() != remotePrefix {
									vrfID = map[string]uint32{"65000:11": 11, "65000:22": 22}[vpn.RD.String()]
								}
								assert.Equal(t, vrfID, z.nexthopVrfID(path), "origin scope of %s", path.GetPrefix())
								wantInvalid := map[uint32]bool{11: redInvalid, 22: false, 0: defaultInvalid}[vrfID]
								assert.Equal(t, wantInvalid, path.IsNexthopInvalid, "scope=%d path=%s", vrfID, path.GetPrefix())
								if !wantInvalid {
									med, err := path.GetMed()
									assert.NoError(t, err)
									assert.Equal(t, map[uint32]uint32{11: redMetric, 22: 40, 0: 60}[vrfID], med)
								}
							}
							return nil
						}, true))
					}
					check(false, false, 20)
					require.False(t, applyNHTMessage(t, z, nhtMessage(t, 11, nh, 0, false)))
					check(true, false, 20)
					add("red", newPrefix, nh)
					add("blue", newPrefix, blueNH)
					add("", newPrefix, nh)
					pathCount = 7
					check(true, false, 20)
					require.False(t, applyNHTMessage(t, z, nhtMessage(t, 11, nh, 31, true)))
					check(false, false, 31)
					require.False(t, applyNHTMessage(t, z, nhtMessage(t, 0, nh, 0, false)))
					check(false, true, 31)
					require.False(t, applyNHTMessage(t, z, nhtMessage(t, 0, nh, 60, true)))
					check(false, false, 31)
				})
			}
		}
	}
}

func TestZebraNHTOriginLifecycle(t *testing.T) {
	s := newNHTServer(t)
	nh := netip.MustParseAddr("10.0.0.1")
	path := nhtPath(t, "203.0.113.0/24", nh, nil)
	require.NoError(t, s.addPathStream("red", []*table.Path{path}))
	z := &zebraClient{server: s, nexthopCache: make(nexthopStateCache)}
	require.NoError(t, s.mgmtOperation(func() error {
		s.zclient = z
		assert.Len(t, s.apiPathVrf, 1)
		clone := path.Clone(false)
		assert.NoError(t, clone.SetMed(99, true))
		assert.Equal(t, uint32(11), z.nexthopVrfID(clone))
		return nil
	}, true))
	w, err := s.watch(WatchBestPath(false))
	require.NoError(t, err)
	t.Cleanup(w.Stop)
	require.NoError(t, s.addPathStream("", []*table.Path{path.Clone(true)}))
	select {
	case ev := <-w.Event():
		best := ev.(*watchEventBestPath)
		require.Len(t, best.PathList, 1)
		withdrawal := best.PathList[0]
		require.True(t, withdrawal.IsWithdraw)
		require.Equal(t, uint32(11), best.NexthopVrf[withdrawal], "queued withdrawal retains its origin scope")
	case <-time.After(5 * time.Second):
		t.Fatal("missing withdrawal event")
	}
	require.Empty(t, s.apiPathVrf)
	// Replacing a VRF API route with a global VPN route of the same identity
	// must reset its origin instead of retaining a stale VRF association.
	replacement := nhtPath(t, "203.0.113.0/24", nh, nil)
	red, _ := s.globalRib.GetVrf("red")
	replacement = replacement.ToGlobal(red)
	require.NoError(t, s.addPathStream("red", []*table.Path{nhtPath(t, "203.0.113.0/24", nh, nil)}))
	require.NoError(t, s.addPathStream("", []*table.Path{replacement}))
	require.NoError(t, s.mgmtOperation(func() error {
		assert.Empty(t, s.apiPathVrf)
		assert.Equal(t, uint32(zebra.DefaultVrf), z.nexthopVrfID(replacement))
		z.nexthopCache[nexthopStateKey{11, nh}] = math.MaxUint32
		z.nexthopCache[nexthopStateKey{22, nh}] = 40
		return nil
	}, true))
	require.NoError(t, s.DeleteVrf(context.Background(), &api.DeleteVrfRequest{Name: "red"}))
	require.NotContains(t, z.nexthopCache, nexthopStateKey{11, nh})
	require.Equal(t, uint32(40), z.nexthopCache[nexthopStateKey{22, nh}])
	addVrf(t, s, "new-red", "65000:111", []string{"65000:111"}, []string{"65000:111"}, 11)
	newPath := nhtPath(t, "203.0.114.0/24", nh, nil)
	require.NoError(t, s.addPathStream("new-red", []*table.Path{newPath}))
	require.NoError(t, s.mgmtOperation(func() error {
		paths := z.getPathListWithNexthopUpdate(11, &zebra.NexthopUpdateBody{Prefix: zebra.Prefix{Family: syscall.AF_INET, Prefix: nh}})
		if assert.Len(t, paths, 1) {
			assert.False(t, paths[0].IsNexthopInvalid, "reused VRF ID must not inherit unreachable cache state")
		}
		return nil
	}, true))
}

func TestZebraNHTSerializedWithRouteChanges(t *testing.T) {
	for _, withdraw := range []bool{true, false} {
		t.Run(map[bool]string{true: "withdraw", false: "replace"}[withdraw], func(t *testing.T) {
			s := newNHTServer(t)
			nh := netip.MustParseAddr("10.0.0.1")
			otherNH := netip.MustParseAddr("10.0.0.2")
			path := nhtPath(t, "203.0.113.0/24", nh, nil)
			require.NoError(t, s.addPathStream("red", []*table.Path{path}))
			z := &zebraClient{server: s, nexthopCache: nexthopStateCache{nexthopStateKey{11, nh}: 20}}
			require.NoError(t, s.mgmtOperation(func() error { s.zclient = z; return nil }, true))
			// Pause NHT while it owns the management lock. A route change
			// queued here must run after the live lookup and propagation,
			// rather than slipping between a snapshot and its later update.
			z.cacheLock.Lock()
			locked := true
			defer func() {
				if locked {
					z.cacheLock.Unlock()
				}
			}()
			nhtDone := make(chan error, 1)
			go func() {
				_, err := z.handleNexthopUpdate(11, &zebra.NexthopUpdateBody{Prefix: zebra.Prefix{Family: syscall.AF_INET, Prefix: nh}})
				nhtDone <- err
			}()
			require.Eventually(t, func() bool {
				if s.shared.mu.TryRLock() {
					s.shared.mu.RUnlock()
					return false
				}
				return true
			}, 5*time.Second, time.Millisecond)
			replacement := nhtPath(t, "203.0.113.0/24", otherNH, nil)
			changeDone := make(chan error, 1)
			go func() {
				if withdraw {
					changeDone <- s.updatePath("", []*table.Path{path.Clone(true)})
				} else {
					changeDone <- s.addPathStream("red", []*table.Path{replacement})
				}
			}()
			z.cacheLock.Unlock()
			locked = false
			require.NoError(t, <-nhtDone)
			require.NoError(t, <-changeDone)
			// A delayed best-path event carries only its old resolution key;
			// its recheck must observe the route change that has completed.
			require.NoError(t, z.recheckNexthops([]nexthopStateKey{{11, nh}}))
			require.Equal(t, uint32(math.MaxUint32), z.nexthopCache[nexthopStateKey{11, nh}], "watcher rechecks do not synthesize NHT cache state")
			paths := s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_VPN})
			if withdraw {
				require.Empty(t, paths, "NHT must not resurrect the withdrawn route")
			} else {
				require.Len(t, paths, 1)
				require.Equal(t, otherNH, paths[0].GetNexthop())
				require.False(t, paths[0].IsNexthopInvalid)
			}
			// With no live path using this scoped nexthop, unregister only
			// that VRF's entry, leaving the same address in blue untouched.
			z.nexthopCache[nexthopStateKey{22, nh}] = 40
			require.True(t, applyNHTMessage(t, z, nhtMessage(t, 11, nh, 20, true)))
			require.NotContains(t, z.nexthopCache, nexthopStateKey{11, nh})
			require.Equal(t, uint32(40), z.nexthopCache[nexthopStateKey{22, nh}])
		})
	}
}

func TestZebraNHTRegistrationScope(t *testing.T) {
	nh := netip.MustParseAddr("10.0.0.1")
	path := nhtPath(t, "203.0.113.0/24", nh, nil)
	cache := nexthopStateCache{nexthopStateKey{22, nh}: 40}
	require.NotNil(t, newNexthopRegisterBody(11, []*table.Path{path}, cache), "another VRF's cache must not suppress registration")
	require.Nil(t, newNexthopRegisterBody(22, []*table.Path{path}, cache))
	cache[nexthopStateKey{11, nh}] = math.MaxUint32
	require.Nil(t, newNexthopRegisterBody(11, []*table.Path{path}, cache))
	// The current first-empty-response behavior is intentionally preserved,
	// and must be independent in each VRF even if another VRF is reachable.
	require.False(t, cache.updateByNexthopUpdate(33, &zebra.NexthopUpdateBody{Prefix: zebra.Prefix{Prefix: nh}}))
	require.NotContains(t, cache, nexthopStateKey{33, nh})
}

func TestZebraMultipathResolutionScopes(t *testing.T) {
	z := &zebraClient{client: &zebra.Client{Version: 6, Software: zebra.NewSoftware(6, "frr8.1")}}
	paths := make([]*table.Path, 0, 3)
	vrfs := make(map[*table.Path]uint32)
	for i, vrfID := range []uint32{11, 0, 22} {
		prefix := netip.MustParsePrefix("203.0.113.0/24")
		nlri, err := bgp.NewLabeledVPNIPAddrPrefix(prefix, *bgp.NewMPLSLabelStack(uint32(100 + i)), bgp.NewRouteDistinguisherTwoOctetAS(65000, 11))
		require.NoError(t, err)
		nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
		require.NoError(t, err)
		path := table.NewPath(bgp.RF_IPv4_VPN, nil, bgp.PathNLRI{NLRI: nlri}, false,
			[]bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh}, time.Now(), false)
		paths = append(paths, path)
		vrfs[path] = vrfID
	}
	body, withdrawn := newIPRouteBody(paths, 11, z, vrfs)
	require.NotNil(t, body)
	require.False(t, withdrawn)
	require.Len(t, body.Nexthops, 3)
	for i, nextHop := range body.Nexthops {
		require.Equal(t, vrfs[paths[i]], nextHop.VrfID)
		if i == 0 {
			require.Zero(t, nextHop.LabelNum)
			require.Empty(t, nextHop.MplsLabels)
		} else {
			require.Equal(t, uint8(1), nextHop.LabelNum)
			require.Equal(t, []uint32{uint32(100 + i)}, nextHop.MplsLabels)
		}
	}
}

func TestZebraNHTImportPolicyPriority(t *testing.T) {
	for _, tt := range []struct {
		name, med string
		rewrite   bool
		metric    uint32
		invalid   bool
		wantMED   uint32
	}{
		{"metric_control", "", false, 30, false, 20},
		{"policy_med", "100", false, 30, false, 100},
		{"policy_med_rewrite", "100", true, 30, false, 100},
		{"rewrite_metric", "", true, 30, false, 30},
		{"rewrite_unreachable", "100", true, math.MaxUint32, true, 100},
		{"policy_med_equal_to_input", "20", true, 30, false, 20},
		{"policy_med_relative", "+100", true, 30, false, 130},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := newNHTServer(t)
			nh, rewrittenNH := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
			config := oc.PolicyDefinition{Name: "nht-import", Statements: []oc.Statement{{
				Name: "nht-import", Actions: oc.Actions{
					RouteDisposition: oc.ROUTE_DISPOSITION_ACCEPT_ROUTE,
					BgpActions:       oc.BgpActions{SetMed: oc.BgpSetMedType(tt.med)},
				},
			}}}
			if tt.rewrite {
				config.Statements[0].Actions.BgpActions.SetNextHop = oc.BgpNextHopType(rewrittenNH.String())
			}
			policy, err := table.NewPolicy(config)
			require.NoError(t, err)
			require.NoError(t, s.AddPolicy(context.Background(), &api.AddPolicyRequest{Policy: table.NewAPIPolicyFromTableStruct(policy)}))
			require.NoError(t, s.AddPolicyAssignment(context.Background(), &api.AddPolicyAssignmentRequest{Assignment: &api.PolicyAssignment{
				Name: table.GLOBAL_RIB_NAME, Direction: api.PolicyDirection_POLICY_DIRECTION_IMPORT,
				Policies: []*api.Policy{{Name: "nht-import"}}, DefaultAction: api.RouteAction_ROUTE_ACTION_ACCEPT,
			}}))
			z := &zebraClient{server: s, nexthopCache: nexthopStateCache{
				nexthopStateKey{0, nh}: 20, nexthopStateKey{0, rewrittenNH}: tt.metric,
			}}
			require.NoError(t, s.mgmtOperation(func() error { s.zclient = z; return nil }, true))
			require.NoError(t, s.addPathStream("", []*table.Path{nhtPath(t, "203.0.113.0/24", nh, nil)}))
			paths := s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_UC})
			require.Len(t, paths, 1)
			require.Equal(t, tt.invalid, paths[0].IsNexthopInvalid, "final nexthop reachability must be correct before the watcher recheck")
			if tt.med == "100" {
				med, err := paths[0].GetMed()
				require.NoError(t, err)
				require.Equal(t, uint32(100), med, "cached metric must not override import policy")
			}
			// Run the same live recheck as the Zebra best-path watcher. It
			// reapplies global import policy after the final nexthop metric.
			require.NoError(t, z.recheckNexthops([]nexthopStateKey{{0, paths[0].GetNexthop()}}))
			paths = s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_UC})
			require.Len(t, paths, 1)
			med, err := paths[0].GetMed()
			require.NoError(t, err)
			require.Equal(t, tt.wantMED, med)
			require.Equal(t, tt.invalid, paths[0].IsNexthopInvalid)
			wantNH := nh
			if tt.rewrite {
				wantNH = rewrittenNH
			}
			require.Equal(t, wantNH, paths[0].GetNexthop())
		})
	}
}

func TestZebraNHTAPIOriginFamilies(t *testing.T) {
	s := newNHTServer(t)
	nh := netip.MustParseAddr("10.0.0.1")
	evpn, err := bgp.NewEVPNMulticastEthernetTagRoute(nil, 0, netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	prefix, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("203.0.113.0/24"))
	require.NoError(t, err)
	flow, err := bgp.NewFlowSpecUnicast(bgp.RF_FS_IPv4_UC, []bgp.FlowSpecComponentInterface{bgp.NewFlowSpecDestinationPrefix(prefix)})
	require.NoError(t, err)
	for _, tt := range []struct {
		family bgp.Family
		nlri   bgp.NLRI
	}{
		{bgp.RF_EVPN, evpn},
		{bgp.RF_FS_IPv4_UC, flow},
	} {
		nextHop, err := bgp.NewPathAttributeNextHop(nh)
		require.NoError(t, err)
		path := table.NewPath(tt.family, nil, bgp.PathNLRI{NLRI: tt.nlri}, false,
			[]bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nextHop}, time.Now(), false)
		require.NoError(t, s.addPathStream("red", []*table.Path{path}))
		require.Len(t, s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{path.GetFamily()}), 1)
		require.Empty(t, s.apiPathVrf, "non-NHT VRF families must not retain origin associations")
	}
}

func TestZebraNHTAPIOriginRetirement(t *testing.T) {
	s := newNHTServer(t)
	first := nhtPath(t, "203.0.113.0/24", netip.MustParseAddr("10.0.0.1"), nil)
	require.NoError(t, s.addPathStream("red", []*table.Path{first}))
	second := nhtPath(t, "203.0.113.0/24", netip.MustParseAddr("10.0.0.2"), nil)
	require.NoError(t, s.addPathStream("red", []*table.Path{second}))
	require.Len(t, s.apiPathVrf, 1)
	require.NotContains(t, s.apiPathVrf, first.RootPath())
	require.Equal(t, uint32(11), s.apiPathVrf[second.RootPath()])
	require.Equal(t, first.LocalID(), second.LocalID())
	policy, err := table.NewPolicy(oc.PolicyDefinition{Name: "reject-api", Statements: []oc.Statement{{
		Name: "reject-api", Actions: oc.Actions{RouteDisposition: oc.ROUTE_DISPOSITION_REJECT_ROUTE},
	}}})
	require.NoError(t, err)
	require.NoError(t, s.AddPolicy(context.Background(), &api.AddPolicyRequest{Policy: table.NewAPIPolicyFromTableStruct(policy)}))
	require.NoError(t, s.AddPolicyAssignment(context.Background(), &api.AddPolicyAssignmentRequest{Assignment: &api.PolicyAssignment{
		Name: table.GLOBAL_RIB_NAME, Direction: api.PolicyDirection_POLICY_DIRECTION_IMPORT,
		Policies: []*api.Policy{{Name: "reject-api"}}, DefaultAction: api.RouteAction_ROUTE_ACTION_ACCEPT,
	}}))
	rejected := nhtPath(t, "203.0.114.0/24", netip.MustParseAddr("10.0.0.1"), nil)
	require.NoError(t, s.addPathStream("red", []*table.Path{rejected}))
	require.Len(t, s.apiPathVrf, 1, "rejected admission must release its origin without affecting retained paths")
	require.NotContains(t, s.apiPathVrf, rejected.RootPath())
	require.Len(t, s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_VPN}), 1)
}

func TestZebraNHTPeerImportMEDCondition(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "reachable", true: "unreachable"}[invalid], func(t *testing.T) {
			s := newNHTServer(t)
			p := newPeerandInfo(t, 65000, 65001, "192.0.2.11", s.globalRib)
			p.policy = s.policy
			t.Cleanup(func() {
				require.NoError(t, s.mgmtOperation(func() error {
					delete(s.neighborMap, p.peerInfo.Load().Address)
					cleanInfiniteChannel(p.fsm.outgoingCh)
					return nil
				}, false))
			})
			policy, err := table.NewPolicy(oc.PolicyDefinition{Name: "peer-reject-20", Statements: []oc.Statement{{
				Name: "peer-reject-20", Conditions: oc.Conditions{BgpConditions: oc.BgpConditions{MedEq: 20}},
				Actions: oc.Actions{RouteDisposition: oc.ROUTE_DISPOSITION_REJECT_ROUTE},
			}}})
			require.NoError(t, err)
			require.NoError(t, s.AddPolicy(context.Background(), &api.AddPolicyRequest{Policy: table.NewAPIPolicyFromTableStruct(policy)}))
			require.NoError(t, s.policy.AddPolicyAssignment(p.ID(), table.POLICY_DIRECTION_IMPORT,
				[]*oc.PolicyDefinition{{Name: "peer-reject-20"}}, table.ROUTE_TYPE_ACCEPT))
			nh := netip.MustParseAddr("10.0.0.1")
			metric := uint32(20)
			if invalid {
				metric = math.MaxUint32
			}
			z := &zebraClient{server: s, nexthopCache: nexthopStateCache{nexthopStateKey{0, nh}: metric}}
			path := nhtPath(t, "203.0.113.0/24", nh, p.peerInfo.Load())
			require.NoError(t, path.SetMed(10, true))
			require.NoError(t, s.mgmtOperation(func() error {
				s.zclient = z
				p.updatePolicyIDs()
				s.neighborMap[p.peerInfo.Load().Address] = p
				s.propagateUpdate(p, []*table.Path{path})
				return nil
			}, true))
			paths := s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_UC})
			require.Len(t, paths, 1, "peer import must see received MED 10")
			med, err := paths[0].GetMed()
			require.NoError(t, err)
			require.Equal(t, uint32(10), med)
			require.Equal(t, invalid, paths[0].IsNexthopInvalid, "cache validity is applied before watcher recheck")
			require.NoError(t, z.recheckNexthops([]nexthopStateKey{{0, nh}}))
			paths = s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_UC})
			require.Len(t, paths, 1)
			med, err = paths[0].GetMed()
			require.NoError(t, err)
			if invalid {
				require.Equal(t, uint32(10), med)
			} else {
				require.Equal(t, uint32(20), med)
			}
			require.Equal(t, invalid, paths[0].IsNexthopInvalid)
		})
	}
}

func TestZebraNHTNoImplicitOriginIsolation(t *testing.T) {
	for _, redFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "red_first", false: "default_first"}[redFirst], func(t *testing.T) {
			s := newNHTServer(t)
			nh := netip.MustParseAddr("10.0.0.1")
			raw := nhtPath(t, "203.0.113.0/24", nh, nil)
			redPath := table.NewPath(raw.GetFamily(), raw.GetSource(), bgp.PathNLRI{NLRI: raw.GetNlri()},
				false, raw.GetFullPathAttrs(), time.Now(), true)
			redMED, defaultMED := uint32(10), uint32(40)
			if !redFirst {
				redMED, defaultMED = defaultMED, redMED
			}
			require.NoError(t, redPath.SetMed(int64(redMED), true))
			require.NoError(t, s.addPathStream("red", []*table.Path{redPath}))
			red, _ := s.globalRib.GetVrf("red")
			defaultPath := nhtPath(t, "203.0.113.0/24", nh, nil).ToGlobal(red)
			require.NoError(t, defaultPath.SetMed(int64(defaultMED), true))
			require.NoError(t, s.addPathStream("", []*table.Path{defaultPath}))
			ids := map[*table.Path]uint32{redPath.RootPath(): redPath.LocalID(), defaultPath.RootPath(): defaultPath.LocalID()}
			require.NotEqual(t, redPath.LocalID(), defaultPath.LocalID(), "new origin admission gets a separate Path-ID")
			z := &zebraClient{server: s, nexthopCache: nexthopStateCache{
				nexthopStateKey{11, nh}: redMED, nexthopStateKey{0, nh}: defaultMED,
			}}
			require.NoError(t, s.mgmtOperation(func() error { s.zclient = z; return nil }, true))
			check := func(redInvalid bool) {
				t.Helper()
				paths := s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_VPN})
				require.Len(t, paths, 2)
				counts := make(map[*table.Path]int)
				for _, path := range paths {
					root := path.RootPath()
					counts[root]++
					require.Equal(t, ids[root], path.LocalID(), "NHT update preserves Path-ID")
					if root == redPath.RootPath() {
						require.Equal(t, redInvalid, path.IsNexthopInvalid)
					} else {
						require.Equal(t, defaultPath.RootPath(), root)
						require.False(t, path.IsNexthopInvalid)
						med, err := path.GetMed()
						require.NoError(t, err)
						require.Equal(t, defaultMED, med)
					}
				}
				require.Equal(t, map[*table.Path]int{redPath.RootPath(): 1, defaultPath.RootPath(): 1}, counts)
				require.Len(t, s.apiPathVrf, 1)
				require.Equal(t, uint32(11), s.apiPathVrf[redPath.RootPath()])
			}
			check(false)
			require.False(t, applyNHTMessage(t, z, nhtMessage(t, 11, nh, 0, false)))
			check(true)
			require.False(t, applyNHTMessage(t, z, nhtMessage(t, 11, nh, 25, true)))
			check(false)
			require.NoError(t, s.addPathStream("", []*table.Path{redPath.Clone(true)}))
			paths := s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_VPN})
			require.Len(t, paths, 1, "clone withdrawal removes only its own origin")
			require.Equal(t, defaultPath.RootPath(), paths[0].RootPath())
			require.Equal(t, ids[defaultPath.RootPath()], paths[0].LocalID())
			require.Empty(t, s.apiPathVrf)
			// A fresh withdrawal has no shared lineage and retains the usual
			// source/RemoteID matching behavior.
			detached := nhtPath(t, "203.0.113.0/24", nh, nil).ToGlobal(red).Clone(true)
			require.NoError(t, s.addPathStream("", []*table.Path{detached}))
			require.Empty(t, s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_VPN}))
		})
	}
}

func TestZebraNHTGlobalAPISourceAlias(t *testing.T) {
	for _, family := range []bgp.Family{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC, bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN} {
		t.Run(family.String(), func(t *testing.T) {
			s := newNHTServer(t)
			p := newPeerandInfo(t, 65000, 65001, "192.0.2.11", s.globalRib)
			p.policy = s.policy
			conf := p.fsm.pConf.ReadCopy()
			conf.Config.Vrf = "red"
			p.fsm.pConf.Update(&conf)
			require.NoError(t, s.mgmtOperation(func() error {
				p.updatePolicyIDs()
				s.neighborMap[p.peerInfo.Load().Address] = p
				return nil
			}, true))
			t.Cleanup(func() {
				require.NoError(t, s.mgmtOperation(func() error {
					delete(s.neighborMap, p.peerInfo.Load().Address)
					cleanInfiniteChannel(p.fsm.outgoingCh)
					return nil
				}, false))
			})
			prefix := "203.0.113.0/24"
			if family == bgp.RF_IPv6_UC || family == bgp.RF_IPv6_VPN {
				prefix = "2001:db8:113::/64"
			}
			nh := netip.MustParseAddr("10.0.0.1")
			input := nhtPath(t, prefix, nh, nil)
			if family == bgp.RF_IPv4_VPN || family == bgp.RF_IPv6_VPN {
				red, _ := s.globalRib.GetVrf("red")
				input = input.ToGlobal(red)
			}
			request := apiutil.AddPathRequest{Paths: []*apiutil.Path{{
				Family: family, Nlri: input.GetNlri(), Attrs: input.GetFullPathAttrs(),
				PeerASN: p.AS(), PeerAddress: p.peerInfo.Load().Address, PeerID: p.peerInfo.Load().ID,
			}}}
			// Admission must record default scope even before Zebra is enabled.
			_, err := s.AddPath(request)
			require.NoError(t, err)
			paths := s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{family})
			require.Len(t, paths, 1)
			apiPath := paths[0]
			require.False(t, apiPath.GetSource().LocalID.IsValid())
			require.True(t, p.peerInfo.Load().LocalID.IsValid())
			require.False(t, apiPath.EqualBySourceAndPathID(nhtPath(t, prefix, nh, p.peerInfo.Load())),
				"API source metadata cannot equal a live peer source with its local router ID")
			z := &zebraClient{server: s, nexthopCache: make(nexthopStateCache)}
			require.NoError(t, s.mgmtOperation(func() error {
				s.zclient = z
				scope, present := s.apiPathVrf[apiPath.RootPath()]
				require.True(t, present, "a source alias needs explicit default scope")
				require.Zero(t, scope)
				require.Zero(t, z.nexthopVrfID(apiPath))
				return nil
			}, true))
			require.False(t, applyNHTMessage(t, z, nhtMessage(t, 0, nh, 20, true)))
			// No path belongs to red merely because its API metadata names red's peer.
			require.True(t, applyNHTMessage(t, z, nhtMessage(t, 11, nh, 40, true)))
			require.False(t, applyNHTMessage(t, z, nhtMessage(t, 0, nh, 0, false)))
			paths = s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{family})
			require.Len(t, paths, 1)
			require.True(t, paths[0].IsNexthopInvalid)
			// Public API-to-API replacement retires the first origin association.
			_, err = s.AddPath(request)
			require.NoError(t, err)
			require.NoError(t, s.mgmtOperation(func() error {
				require.Len(t, s.apiPathVrf, 1)
				require.NotContains(t, s.apiPathVrf, apiPath.RootPath())
				return nil
			}, true))
			require.NoError(t, s.DeletePath(apiutil.DeletePathRequest{Paths: request.Paths}))
			require.Empty(t, s.apiPathVrf)
		})
	}
}
