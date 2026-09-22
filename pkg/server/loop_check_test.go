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
