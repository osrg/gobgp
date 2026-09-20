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
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/packet/mrt"
)

func newMrtTestServer(t *testing.T) *BgpServer {
	t.Helper()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	s := &BgpServer{
		shared:      newSharedData(),
		neighborMap: make(map[netip.Addr]*peer),
		globalRib:   table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC}, oc.RouteSelectionOptionsConfig{}, oc.UseMultiplePathsConfig{}),
		logger:      logger,
	}
	s.bgpConfig.Global.Config.RouterId = netip.MustParseAddr("10.0.0.1")
	return s
}

// newMrtTestPath builds an IPv4 unicast path. A nil src makes it a locally
// generated path.
func newMrtTestPath(t *testing.T, src *table.PeerInfo, prefix, nexthop string) *table.Path {
	t.Helper()

	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	require.NoError(t, err)
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr(nexthop))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		nh,
	}
	return table.NewPath(bgp.RF_IPv4_UC, src, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
}

func TestMrtDumpTablePeerIndexTable(t *testing.T) {
	s := newMrtTestServer(t)

	src := &table.PeerInfo{
		AS:      65001,
		ID:      netip.MustParseAddr("172.16.0.1"),
		Address: netip.MustParseAddr("192.168.0.1"),
	}
	s.globalRib.Update(newMrtTestPath(t, src, "10.10.10.0/24", "192.168.0.1"))

	m := &mrtWriter{s: s, c: &oc.MrtConfig{}}
	msgs := m.dumpTable()
	require.NotEmpty(t, msgs)

	pit, ok := msgs[0].Body.(*mrt.PeerIndexTable)
	require.True(t, ok, "the first message must be the PEER_INDEX_TABLE")
	require.Len(t, pit.Peers, 1)
	assert.Equal(t, netip.MustParseAddr("192.168.0.1"), pit.Peers[0].IpAddress)
	assert.Equal(t, netip.MustParseAddr("172.16.0.1"), pit.Peers[0].BgpId)
	assert.Equal(t, uint32(65001), pit.Peers[0].AS)
}

// A locally generated path has no source peer, so its address, ID and AS are
// unset. The peer index table must still record a usable address for it. An
// unset address serializes to nothing, which truncates the peer entry and
// shifts every entry after it.
func TestMrtDumpTableLocalPathPeerIndexTable(t *testing.T) {
	s := newMrtTestServer(t)

	// Two local paths, to check that they share one peer record.
	s.globalRib.Update(newMrtTestPath(t, nil, "10.10.10.0/24", "192.168.0.1"))
	s.globalRib.Update(newMrtTestPath(t, nil, "10.10.20.0/24", "192.168.0.1"))
	src := &table.PeerInfo{
		AS:      65001,
		ID:      netip.MustParseAddr("172.16.0.1"),
		Address: netip.MustParseAddr("192.168.0.2"),
	}
	s.globalRib.Update(newMrtTestPath(t, src, "10.10.30.0/24", "192.168.0.2"))

	m := &mrtWriter{s: s, c: &oc.MrtConfig{}}
	msgs := m.dumpTable()
	require.NotEmpty(t, msgs)

	pit, ok := msgs[0].Body.(*mrt.PeerIndexTable)
	require.True(t, ok, "the first message must be the PEER_INDEX_TABLE")
	require.Len(t, pit.Peers, 2)

	unspec := netip.IPv4Unspecified()
	local := mrt.NewPeer(unspec, unspec, 0, true)
	remote := mrt.NewPeer(netip.MustParseAddr("172.16.0.1"), netip.MustParseAddr("192.168.0.2"), 65001, true)
	assert.ElementsMatch(t, []*mrt.Peer{local, remote}, pit.Peers)

	// Every RIB entry must point at the peer the path came from.
	want := map[string]*mrt.Peer{
		"10.10.10.0/24": local,
		"10.10.20.0/24": local,
		"10.10.30.0/24": remote,
	}
	seen := 0
	for _, msg := range msgs[1:] {
		rib, ok := msg.Body.(*mrt.Rib)
		require.True(t, ok)
		for _, e := range rib.Entries {
			require.Less(t, int(e.PeerIndex), len(pit.Peers))
			assert.Equal(t, want[rib.Prefix.String()], pit.Peers[e.PeerIndex], "prefix %s", rib.Prefix)
			seen++
		}
	}
	assert.Equal(t, len(want), seen)

	// The peer index table must survive a round trip through the wire
	// format. A truncated peer entry is only visible once it is decoded
	// again.
	buf, err := msgs[0].Serialize()
	require.NoError(t, err)
	require.Greater(t, len(buf), mrt.MRT_COMMON_HEADER_LEN)
	hdr, err := mrt.ParseHeader(buf[:mrt.MRT_COMMON_HEADER_LEN])
	require.NoError(t, err)
	decoded, err := mrt.ParseBody(buf[mrt.MRT_COMMON_HEADER_LEN:], hdr)
	require.NoError(t, err)
	decodedPit, ok := decoded.Body.(*mrt.PeerIndexTable)
	require.True(t, ok)
	assert.Equal(t, pit.Peers, decodedPit.Peers)
}
