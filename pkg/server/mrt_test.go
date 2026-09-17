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

func TestMrtDumpTablePeerIndexTable(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	s := &BgpServer{
		shared:      newSharedData(),
		neighborMap: make(map[netip.Addr]*peer),
		globalRib:   table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC}),
		logger:      logger,
	}
	s.bgpConfig.Global.Config.RouterId = netip.MustParseAddr("10.0.0.1")

	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	require.NoError(t, err)
	nexthop, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.168.0.1"))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		nexthop,
	}
	src := &table.PeerInfo{
		AS:      65001,
		ID:      netip.MustParseAddr("172.16.0.1"),
		Address: netip.MustParseAddr("192.168.0.1"),
	}
	s.globalRib.Update(table.NewPath(bgp.RF_IPv4_UC, src, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false))

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
