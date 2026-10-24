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

	"github.com/stretchr/testify/require"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func addPathEVPNMacPath(t *testing.T, source *table.PeerInfo, rdAdmin uint16, esiByte byte, seq uint32) *table.Path {
	t.Helper()
	esi := bgp.EthernetSegmentIdentifier{Type: bgp.ESI_ARBITRARY, Value: []byte{esiByte, esiByte, esiByte, esiByte, esiByte, esiByte, esiByte, esiByte, esiByte}}
	nlri, err := bgp.NewEVPNMacIPAdvertisementRoute(bgp.NewRouteDistinguisherTwoOctetAS(rdAdmin, 1), esi, 0, "00:11:22:33:44:55", netip.Addr{}, []uint32{100})
	require.NoError(t, err)
	mp, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_EVPN, []bgp.PathNLRI{{NLRI: nlri}}, netip.MustParseAddr("10.0.0.1"))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		mp,
		bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{
			bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 65000, 1, true),
			bgp.NewMacMobilityExtended(seq, false),
		}),
	}
	return table.NewPath(bgp.RF_EVPN, source, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
}

// drainOutgoing returns the paths queued for the peer until the queue stays
// quiet for a moment.
func drainOutgoing(p *peer) []*table.Path {
	var paths []*table.Path
	for {
		select {
		case m := <-p.fsm.outgoingCh.Out():
			paths = append(paths, m.(*fsmOutgoingMsg).Paths...)
		case <-time.After(200 * time.Millisecond):
			return paths
		}
	}
}

// newEVPNMobilityServer starts a server with a source peer and a target peer
// that are both established. The target has ADD-PATH send enabled for EVPN if
// addPath is set.
func newEVPNMobilityServer(t *testing.T, addPath bool) (*BgpServer, *peer, *peer) {
	t.Helper()
	ctx := context.Background()
	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(ctx, &api.StartBgpRequest{
		Global: &api.Global{Asn: 1111, RouterId: "1.1.1.1", ListenPort: -1},
	}))

	source := newPeerandInfo(t, 1111, 1112, "10.1.142.66", s.globalRib)
	target := newPeerandInfo(t, 1111, 1113, "10.1.142.65", s.globalRib)
	for _, p := range []*peer{source, target} {
		p.policy = s.policy
		p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
	}
	target.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_EVPN: bgp.BGP_ADD_PATH_NONE})
	if addPath {
		target.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_EVPN: bgp.BGP_ADD_PATH_SEND})
		target.fsm.lock.Lock()
		conf := target.fsm.pConf.ReadCopy()
		evpn := oc.AfiSafi{State: oc.AfiSafiState{Family: bgp.RF_EVPN}}
		evpn.AddPaths.Config.SendMax = 4
		evpn.AddPaths.State.SendMax = 4
		conf.AfiSafis = append(conf.AfiSafis, evpn)
		target.fsm.pConf.Update(&conf)
		target.fsm.lock.Unlock()
	}

	targetAddress := netip.MustParseAddr("10.1.142.65")
	require.NoError(t, s.mgmtOperation(func() error {
		s.neighborMap[targetAddress] = target
		return nil
	}, true))
	t.Cleanup(func() {
		require.NoError(t, s.mgmtOperation(func() error {
			delete(s.neighborMap, targetAddress)
			return nil
		}, false))
		cleanInfiniteChannel(target.fsm.outgoingCh)
		require.NoError(t, s.StopBgp(ctx, &api.StopBgpRequest{}))
	})
	return s, source, target
}

// EVPN MAC mobility withdraws the local MAC/IP paths that carry the MAC of the
// received path. The target peer has to learn that the local path is gone, with
// and without ADD-PATH, and when the local path and the new path have different
// RDs (two destinations) or the same RD (one destination, the ESI is not part
// of the route key).
func TestEVPNMacMobilityWithdrawal(t *testing.T) {
	tests := []struct {
		name     string
		addPath  bool
		rdMoved  uint16
		sameDest bool
	}{
		{name: "add-path, different RD", addPath: true, rdMoved: 2},
		{name: "no add-path, different RD", addPath: false, rdMoved: 2},
		{name: "add-path, same RD", addPath: true, rdMoved: 1, sameDest: true},
		{name: "no add-path, same RD", addPath: false, rdMoved: 1, sameDest: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, source, target := newEVPNMobilityServer(t, tt.addPath)

			local := addPathEVPNMacPath(t, nil, 1, 1, 0)
			s.propagateUpdate(nil, []*table.Path{local})
			sent := drainOutgoing(target)
			require.Len(t, sent, 1, "the peer gets the local path")
			require.False(t, sent[0].IsWithdraw)

			// The MAC moves: same MAC, another ESI, higher sequence number.
			moved := addPathEVPNMacPath(t, source.peerInfo.Load(), tt.rdMoved, 2, 1)
			require.Equal(t, tt.sameDest, local.GetNlri().String() == moved.GetNlri().String())
			s.propagateUpdate(source, []*table.Path{moved})

			// The new path comes first, the withdrawal of the local path
			// after it. A peer without ADD-PATH gets no withdrawal when both
			// paths are in one destination: the new path replaces the local
			// one in its UPDATE, and a withdrawal would remove the new best.
			got := drainOutgoing(target)
			require.False(t, got[0].IsWithdraw)
			require.Equal(t, moved.GetNlri().String(), got[0].GetNlri().String())
			require.Equal(t, moved.GetSource(), got[0].GetSource())
			if tt.sameDest && !tt.addPath {
				require.Len(t, got, 1)
				return
			}
			require.Len(t, got, 2)
			require.True(t, got[1].IsWithdraw)
			require.Equal(t, local.GetNlri().String(), got[1].GetNlri().String())
			require.True(t, got[1].IsLocal(), "the withdrawal is the one of the local path")

			if tt.addPath {
				require.False(t, target.hasPathAlreadyBeenSent(local), "the local path is no longer recorded as sent")
				require.True(t, target.hasPathAlreadyBeenSent(moved))
			}
		})
	}
}
