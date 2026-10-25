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
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// TestIngressLoopCheckWithdrawsInstalledPath covers the three ingress loop
// checks in handleUpdate. A re-advertisement that trips one of them must take
// the path the peer had installed out of the Loc-RIB, the same way BGP
// replaces a route when the same NLRI is advertised again.
func TestIngressLoopCheckWithdrawsInstalledPath(t *testing.T) {
	const (
		localAS   = uint32(65000)
		prefix    = "10.0.0.0/24"
		routerID  = "192.0.2.254"
		peerAddr  = "192.0.2.1"
		clusterID = "255.0.0.1"
	)
	family := bgp.RF_IPv4_UC
	families := []bgp.Family{family}

	for _, tc := range []struct {
		name string
		// peerAS is the neighbor AS; equal to localAS makes the peer iBGP.
		peerAS uint32
		// looping returns the attributes that must trip the check.
		looping func(t *testing.T) []bgp.PathAttributeInterface
		// clusterIDs is what the server reports as its local cluster IDs.
		clusterIDs []string
	}{
		{
			name:   "as-path",
			peerAS: 65001,
			looping: func(t *testing.T) []bgp.PathAttributeInterface {
				t.Helper()
				return []bgp.PathAttributeInterface{
					bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
						bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001, localAS}),
					}),
				}
			},
		},
		{
			name:   "originator-id",
			peerAS: localAS,
			looping: func(t *testing.T) []bgp.PathAttributeInterface {
				t.Helper()
				originator, err := bgp.NewPathAttributeOriginatorId(netip.MustParseAddr(routerID))
				require.NoError(t, err)
				return []bgp.PathAttributeInterface{originator}
			},
		},
		{
			name:       "cluster-list",
			peerAS:     localAS,
			clusterIDs: []string{clusterID},
			looping: func(t *testing.T) []bgp.PathAttributeInterface {
				t.Helper()
				list, err := bgp.NewPathAttributeClusterList([]netip.Addr{netip.MustParseAddr(clusterID)})
				require.NoError(t, err)
				return []bgp.PathAttributeInterface{list}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s := NewBgpServer()
			go s.Serve()
			require.NoError(t, s.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
				Asn: localAS, RouterId: routerID, ListenPort: -1,
			}}))
			t.Cleanup(s.Stop)

			p := newPeerandInfo(t, localAS, tc.peerAS, peerAddr, s.globalRib)
			p.policy = s.policy
			p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
			require.NoError(t, s.mgmtOperation(func() error {
				p.fsm.gConf.Config.RouterId = netip.MustParseAddr(routerID)
				s.neighborMap[netip.MustParseAddr(p.ID())] = p
				s.rrClusterIDs = make(map[netip.Addr]struct{}, len(tc.clusterIDs))
				for _, id := range tc.clusterIDs {
					s.rrClusterIDs[netip.MustParseAddr(id)] = struct{}{}
				}
				return nil
			}, true))
			t.Cleanup(func() {
				require.NoError(t, s.mgmtOperation(func() error {
					delete(s.neighborMap, netip.MustParseAddr(p.ID()))
					return nil
				}, false))
				cleanInfiniteChannel(p.fsm.outgoingCh)
			})

			nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
			require.NoError(t, err)
			nexthop, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr(peerAddr))
			require.NoError(t, err)
			advertise := func(extra ...bgp.PathAttributeInterface) {
				t.Helper()
				attrs := append([]bgp.PathAttributeInterface{
					bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
					nexthop,
				}, extra...)
				s.handleFSMMessage(p, &fsmMsg{
					MsgType:   fsmMsgBGPMessage,
					MsgData:   bgp.NewBGPUpdateMessage(nil, attrs, []bgp.PathNLRI{{NLRI: nlri}}),
					timestamp: time.Now(),
				})
			}

			// A plain advertisement the loop checks accept.
			advertise(bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
				bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001}),
			}))
			require.NoError(t, s.mgmtOperation(func() error {
				require.Len(t, s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, families), 1)
				assert.Equal(t, 1, p.adjRibIn.Accepted(families))
				return nil
			}, true))

			// The same NLRI again, now tripping the check.
			advertise(tc.looping(t)...)
			require.NoError(t, s.mgmtOperation(func() error {
				assert.Empty(t, s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, families),
					"the previously installed path must be withdrawn")
				assert.Equal(t, 0, p.adjRibIn.Accepted(families))
				cached := p.adjRibIn.PathList(families, false)
				require.Len(t, cached, 1, "the rejected path stays in the Adj-RIB-In")
				assert.True(t, cached[0].IsRejected())
				assert.Zero(t, cached[0].LocalID(),
					"a rejected path must not hold a local path ID")
				return nil
			}, true))

			// Advertising something acceptable again brings the path back.
			advertise(bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
				bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001}),
			}))
			require.NoError(t, s.mgmtOperation(func() error {
				assert.Len(t, s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, families), 1)
				assert.Equal(t, 1, p.adjRibIn.Accepted(families))
				return nil
			}, true))
		})
	}
}

// TestOwnNexthopWithdrawsInstalledPath covers RFC 4271 5.1.3: a route with
// the local address of the session as its next hop is rejected. It stays in
// the Adj-RIB-In, the path the peer had installed is withdrawn, and a soft
// reset in keeps it rejected.
func TestOwnNexthopWithdrawsInstalledPath(t *testing.T) {
	const (
		localAS  = uint32(65000)
		prefix   = "10.0.0.0/24"
		routerID = "192.0.2.254"
		peerAddr = "192.0.2.1"
		ownAddr  = "192.0.2.2"
	)
	families := []bgp.Family{bgp.RF_IPv4_UC}

	for _, tc := range []struct {
		name string
		// localAddr is the local address of the session as the FSM records it.
		localAddr string
	}{
		{name: "ipv4", localAddr: ownAddr},
		// An IPv4 session accepted on an IPv6 socket.
		{name: "ipv4-mapped", localAddr: "::ffff:" + ownAddr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s := NewBgpServer()
			go s.Serve()
			require.NoError(t, s.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
				Asn: localAS, RouterId: routerID, ListenPort: -1,
			}}))
			t.Cleanup(s.Stop)

			p := newPeerandInfo(t, localAS, 65001, peerAddr, s.globalRib)
			p.policy = s.policy
			p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
			info := *p.peerInfo.Load()
			info.LocalAddress = netip.MustParseAddr(tc.localAddr)
			p.peerInfo.Store(&info)
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
			})

			nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
			require.NoError(t, err)
			advertise := func(nexthop string) {
				t.Helper()
				nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr(nexthop))
				require.NoError(t, err)
				attrs := []bgp.PathAttributeInterface{
					bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
					bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
						bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001}),
					}),
					nh,
				}
				s.handleFSMMessage(p, &fsmMsg{
					MsgType:   fsmMsgBGPMessage,
					MsgData:   bgp.NewBGPUpdateMessage(nil, attrs, []bgp.PathNLRI{{NLRI: nlri}}),
					timestamp: time.Now(),
				})
			}
			assertRejected := func() {
				t.Helper()
				require.NoError(t, s.mgmtOperation(func() error {
					assert.Empty(t, s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, families),
						"the previously installed path must be withdrawn")
					assert.Equal(t, 0, p.adjRibIn.Accepted(families))
					cached := p.adjRibIn.PathList(families, false)
					require.Len(t, cached, 1, "the rejected path stays in the Adj-RIB-In")
					assert.True(t, cached[0].IsRejected())
					return nil
				}, true))
			}

			advertise(peerAddr)
			require.NoError(t, s.mgmtOperation(func() error {
				require.Len(t, s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, families), 1)
				assert.Equal(t, 1, p.adjRibIn.Accepted(families))
				return nil
			}, true))

			// The same NLRI again, now with our own address as the next hop.
			advertise(ownAddr)
			assertRejected()

			require.NoError(t, s.mgmtOperation(func() error {
				return s.softResetIn(peerAddr, bgp.RF_IPv4_UC)
			}, true))
			assertRejected()

			// A next hop that is not ours brings the path back.
			advertise(peerAddr)
			require.NoError(t, s.mgmtOperation(func() error {
				assert.Len(t, s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, families), 1)
				assert.Equal(t, 1, p.adjRibIn.Accepted(families))
				return nil
			}, true))
		})
	}
}

// TestHasOwnNexthop covers which next hops hasOwnNexthop takes as ours.
func TestHasOwnNexthop(t *testing.T) {
	p := newPeerandInfo(t, 65000, 65001, "192.0.2.1", table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC}, oc.RouteSelectionOptionsConfig{}, oc.UseMultiplePathsConfig{}))

	path := func(t *testing.T, nexthop string) *table.Path {
		t.Helper()
		nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
		require.NoError(t, err)
		nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr(nexthop))
		require.NoError(t, err)
		return table.NewPath(bgp.RF_IPv4_UC, p.peerInfo.Load(), bgp.PathNLRI{NLRI: nlri}, false,
			[]bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP), nh},
			time.Now(), false)
	}

	for _, tc := range []struct {
		name      string
		remote    string
		local     string
		nexthop   string
		wantOwned bool
	}{
		{name: "own", remote: "192.0.2.1", local: "192.0.2.2", nexthop: "192.0.2.2", wantOwned: true},
		{name: "peer", remote: "192.0.2.1", local: "192.0.2.2", nexthop: "192.0.2.1"},
		{name: "third-party", remote: "192.0.2.1", local: "192.0.2.2", nexthop: "192.0.2.3"},
		// Two instances on one host that differ only in the port.
		{name: "same-address", remote: "127.0.0.1", local: "127.0.0.1", nexthop: "127.0.0.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := *p.peerInfo.Load()
			info.Address = netip.MustParseAddr(tc.remote)
			info.LocalAddress = netip.MustParseAddr(tc.local)
			assert.Equal(t, tc.wantOwned, p.hasOwnNexthop(path(t, tc.nexthop), &info))
		})
	}
}

// TestExternalPeerReflectionAttrsDiscarded covers RFC 7606 7.9 and 7.10: an
// ORIGINATOR_ID or a CLUSTER_LIST received from an external peer is discarded.
// Both exist to stop loops inside our AS, so an external peer has no say in
// them. Left on the path, the CLUSTER_LIST holds the route back from every
// route reflector client and the ORIGINATOR_ID is passed on to them.
func TestExternalPeerReflectionAttrsDiscarded(t *testing.T) {
	const (
		localAS      = uint32(65000)
		prefix       = "10.0.0.0/24"
		routerID     = "192.0.2.254"
		externalAddr = "192.0.2.1"
		clientAddr   = "192.0.2.2"
	)

	for _, tc := range []struct {
		name string
		attr func(t *testing.T) bgp.PathAttributeInterface
	}{
		{
			// The cluster ID defaults to the router ID, which the peer
			// reads from our OPEN.
			name: "cluster-list",
			attr: func(t *testing.T) bgp.PathAttributeInterface {
				t.Helper()
				list, err := bgp.NewPathAttributeClusterList([]netip.Addr{netip.MustParseAddr(routerID)})
				require.NoError(t, err)
				return list
			},
		},
		{
			// The router ID of the client, which then ignores the route.
			name: "originator-id",
			attr: func(t *testing.T) bgp.PathAttributeInterface {
				t.Helper()
				originator, err := bgp.NewPathAttributeOriginatorId(netip.MustParseAddr(clientAddr))
				require.NoError(t, err)
				return originator
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s := NewBgpServer()
			go s.Serve()
			require.NoError(t, s.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
				Asn: localAS, RouterId: routerID, ListenPort: -1,
			}}))
			t.Cleanup(s.Stop)

			external := newPeerandInfo(t, localAS, 65001, externalAddr, s.globalRib)
			client := newPeerandInfo(t, localAS, localAS, clientAddr, s.globalRib)
			conf := client.fsm.pConf.ReadCopy()
			conf.RouteReflector.Config.RouteReflectorClient = true
			conf.RouteReflector.State.RouteReflectorClusterId = netip.MustParseAddr(routerID)
			client.fsm.pConf.Update(&conf)
			info := *client.peerInfo.Load()
			info.RouteReflectorClient = true
			info.RouteReflectorClusterID = netip.MustParseAddr(routerID)
			client.peerInfo.Store(&info)
			// Without RTC, which would hold back a route with no route target.
			client.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_NONE})

			peers := []*peer{external, client}
			require.NoError(t, s.mgmtOperation(func() error {
				for _, p := range peers {
					p.policy = s.policy
					p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
					s.neighborMap[netip.MustParseAddr(p.ID())] = p
				}
				return nil
			}, true))
			t.Cleanup(func() {
				require.NoError(t, s.mgmtOperation(func() error {
					for _, p := range peers {
						delete(s.neighborMap, netip.MustParseAddr(p.ID()))
					}
					return nil
				}, false))
				for _, p := range peers {
					cleanInfiniteChannel(p.fsm.outgoingCh)
				}
			})

			nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
			require.NoError(t, err)
			nexthop, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr(externalAddr))
			require.NoError(t, err)

			// A pre-policy watcher reads the path in its own goroutine while
			// the route is processed, so the path must not change after it
			// is handed over. toConfig serializes the OPEN the peer sent.
			open, err := bgp.NewBGPOpenMessage(65001, 90, netip.MustParseAddr(externalAddr), nil)
			require.NoError(t, err)
			external.fsm.recvOpen = open
			w, err := s.watch(WatchUpdate(false, "", ""))
			require.NoError(t, err)
			t.Cleanup(w.Stop)
			preAttrs := make(chan []bgp.PathAttributeInterface, 1)
			go func() {
				for ev := range w.Event() {
					if u, ok := ev.(*watchEventUpdate); ok && len(u.PathList) > 0 {
						preAttrs <- u.PathList[0].GetPathAttrs()
						return
					}
				}
			}()

			s.handleFSMMessage(external, &fsmMsg{
				MsgType: fsmMsgBGPMessage,
				MsgData: bgp.NewBGPUpdateMessage(nil, []bgp.PathAttributeInterface{
					bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
					bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
						bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001}),
					}),
					nexthop,
					tc.attr(t),
				}, []bgp.PathNLRI{{NLRI: nlri}}),
				timestamp: time.Now(),
			})

			// The route is accepted either way.
			require.NoError(t, s.mgmtOperation(func() error {
				require.Len(t, s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_UC}), 1)
				return nil
			}, true))

			// The attribute is discarded on receipt, so neither the
			// Adj-RIB-In nor the pre-policy watcher has it.
			adjIn := external.adjRibIn.PathList([]bgp.Family{bgp.RF_IPv4_UC}, false)
			require.Len(t, adjIn, 1)
			typ := tc.attr(t).GetType()
			for _, a := range adjIn[0].GetPathAttrs() {
				assert.NotEqual(t, typ, a.GetType())
			}
			select {
			case attrs := <-preAttrs:
				for _, a := range attrs {
					assert.NotEqual(t, typ, a.GetType())
				}
			case <-time.After(time.Second):
				t.Fatal("the pre-policy watcher got no update")
			}

			select {
			case o := <-client.fsm.outgoingCh.Out():
				paths := o.(*fsmOutgoingMsg).Paths
				require.Len(t, paths, 1)
				assert.False(t, paths[0].IsWithdraw)
				assert.Equal(t, prefix, paths[0].GetPrefix())
				// What the client gets is what we set as a reflector.
				assert.Equal(t, netip.MustParseAddr(externalAddr), paths[0].GetOriginatorID())
				assert.Equal(t, []netip.Addr{netip.MustParseAddr(routerID)}, paths[0].GetClusterList())
			case <-time.After(time.Second):
				t.Fatal("the route was not sent to the route reflector client")
			}
		})
	}
}

func TestExternalPeerOriginValidationStateDiscarded(t *testing.T) {
	const (
		localAS  = uint32(65000)
		prefix   = "10.0.0.0/24"
		routerID = "192.0.2.254"
	)

	rt := bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 65001, 100, true)
	for _, tc := range []struct {
		name string
		as   uint32
		want []bgp.ExtendedCommunityInterface
	}{
		// RFC 8097 2: dropped by default when received from an EBGP peer.
		{name: "external", as: 65001, want: []bgp.ExtendedCommunityInterface{rt}},
		{name: "internal", as: localAS, want: []bgp.ExtendedCommunityInterface{bgp.NewValidationExtended(bgp.VALIDATION_STATE_VALID), rt}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s := NewBgpServer()
			go s.Serve()
			require.NoError(t, s.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
				Asn: localAS, RouterId: routerID, ListenPort: -1,
			}}))
			t.Cleanup(s.Stop)

			p := newPeerandInfo(t, localAS, tc.as, "192.0.2.1", s.globalRib)
			// Without it, the missing ORIGINATOR_ID of the route matches.
			p.fsm.gConf.Config.RouterId = netip.MustParseAddr(routerID)
			require.NoError(t, s.mgmtOperation(func() error {
				p.policy = s.policy
				p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
				s.neighborMap[netip.MustParseAddr(p.ID())] = p
				return nil
			}, true))
			t.Cleanup(func() {
				require.NoError(t, s.mgmtOperation(func() error {
					delete(s.neighborMap, netip.MustParseAddr(p.ID()))
					return nil
				}, false))
				cleanInfiniteChannel(p.fsm.outgoingCh)
			})

			nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
			require.NoError(t, err)
			nexthop, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.0.2.1"))
			require.NoError(t, err)
			var asPath []bgp.AsPathParamInterface
			if tc.as != localAS {
				asPath = []bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{tc.as})}
			}
			s.handleFSMMessage(p, &fsmMsg{
				MsgType: fsmMsgBGPMessage,
				MsgData: bgp.NewBGPUpdateMessage(nil, []bgp.PathAttributeInterface{
					bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
					bgp.NewPathAttributeAsPath(asPath),
					nexthop,
					bgp.NewPathAttributeLocalPref(100),
					bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{
						bgp.NewValidationExtended(bgp.VALIDATION_STATE_VALID), rt,
					}),
				}, []bgp.PathNLRI{{NLRI: nlri}}),
				timestamp: time.Now(),
			})

			var paths []*table.Path
			require.NoError(t, s.mgmtOperation(func() error {
				paths = s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_UC})
				return nil
			}, true))
			require.Len(t, paths, 1)
			assert.Equal(t, tc.want, paths[0].GetExtCommunities())
		})
	}
}
