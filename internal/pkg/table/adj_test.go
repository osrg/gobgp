// Copyright (C) 2018 Nippon Telegraph and Telephone Corporation.
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

package table

import (
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateAdjTable(t *testing.T) {
	table := NewTable(logger, bgp.RF_RTC_UC)
	assert.Equal(t, bgp.RF_RTC_UC, table.GetFamily())

	table = NewTable(logger, bgp.RF_FS_IPv4_VPN)
	assert.Equal(t, bgp.RF_FS_IPv4_VPN, table.GetFamily())
}

func TestAddPath(t *testing.T) {
	pi := &PeerInfo{}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}

	nlri1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("20.20.20.0/24"))
	p1 := NewPath(bgp.RF_IPv4_UC, pi, bgp.PathNLRI{NLRI: nlri1}, false, attrs, time.Now(), false)
	p1.remoteID = 1
	nlri2, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("20.20.20.0/24"))
	p2 := NewPath(bgp.RF_IPv4_UC, pi, bgp.PathNLRI{NLRI: nlri2}, false, attrs, time.Now(), false)
	p2.remoteID = 2
	family := p1.GetFamily()
	families := []bgp.Family{family}

	adj := NewAdjRib(slog.Default(), families)
	adj.Update([]*Path{p1, p2})
	assert.Equal(t, len(adj.table[family].GetDestinations()), 1)
	assert.Equal(t, adj.Count([]bgp.Family{family}), 2)

	p3 := NewPath(bgp.RF_IPv4_UC, pi, bgp.PathNLRI{NLRI: nlri2}, false, attrs, time.Now(), false)
	p3.remoteID = 2
	adj.Update([]*Path{p3})

	var found *Path
	for _, d := range adj.table[family].GetDestinations() {
		for _, p := range d.knownPathList {
			if p.remoteID == 2 {
				found = p
				break
			}
		}
	}
	assert.Equal(t, found, p3)
	adj.Update([]*Path{p3.Clone(true)})
	assert.Equal(t, adj.Count([]bgp.Family{family}), 1)
	adj.Update([]*Path{p1.Clone(true)})
	assert.Equal(t, 0, len(adj.table[family].GetDestinations()))
}

func TestUpdateReportsAcceptedToRejected(t *testing.T) {
	pi := &PeerInfo{Address: netip.MustParseAddr("192.0.2.1"), AS: 65001}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}
	family := bgp.RF_IPv4_UC
	families := []bgp.Family{family}

	newPath := func(rejected bool) *Path {
		nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
		require.NoError(t, err)
		p := NewPath(family, pi, bgp.PathNLRI{NLRI: nlri, ID: 7}, false, attrs, time.Now(), false)
		p.SetRejected(rejected)
		return p
	}

	adj := NewAdjRib(logger, families)

	accepted := newPath(false)
	require.Empty(t, adj.Update([]*Path{accepted}), "a first advertisement withdraws nothing")
	require.Equal(t, 1, adj.Accepted(families))

	// The table assigns a local path ID once the path is installed.
	accepted.localID = 5

	rejected := newPath(true)
	withdrawals := adj.Update([]*Path{rejected})
	require.Len(t, withdrawals, 1, "accepted to rejected must withdraw the installed path")
	w := withdrawals[0]
	assert.True(t, w.IsWithdraw)
	assert.True(t, w.IsDropped(), "the table must release the local path ID")
	assert.Equal(t, uint32(5), w.LocalID(), "the withdrawal carries the ID that was advertised")
	assert.Equal(t, uint32(7), w.RemoteID())
	assert.True(t, w.EqualBySourceAndPathID(accepted))
	assert.Zero(t, rejected.LocalID(), "a rejected cache entry must not hold a local path ID")
	assert.Equal(t, 0, adj.Accepted(families))
	assert.Equal(t, 1, adj.Count(families))

	// Staying rejected is not a transition, so there is nothing left to remove.
	require.Empty(t, adj.Update([]*Path{newPath(true)}))
	assert.Equal(t, 0, adj.Accepted(families))

	// Coming back is handled by the implicit withdraw in the table.
	back := newPath(false)
	require.Empty(t, adj.Update([]*Path{back}))
	assert.Equal(t, 1, adj.Accepted(families))

	// A real withdrawal is returned to the caller by handleUpdate already.
	require.Empty(t, adj.Update([]*Path{back.Clone(true)}))
	assert.Equal(t, 0, adj.Count(families))
}

func TestAddPathAdjOut(t *testing.T) {
	pi := &PeerInfo{}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}

	nlri1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("20.20.20.0/24"))
	p1 := NewPath(bgp.RF_IPv4_UC, pi, bgp.PathNLRI{NLRI: nlri1}, false, attrs, time.Now(), false)
	p1.localID = 1
	p1.remoteID = 1
	nlri2, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("20.20.20.0/24"))
	p2 := NewPath(bgp.RF_IPv4_UC, pi, bgp.PathNLRI{NLRI: nlri2}, false, attrs, time.Now(), false)
	p2.localID = 2
	p2.remoteID = 1
	nlri3, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("20.20.20.0/24"))
	p3 := NewPath(bgp.RF_IPv4_UC, pi, bgp.PathNLRI{NLRI: nlri3}, false, attrs, time.Now(), false)
	p3.localID = 3
	p3.remoteID = 2
	nlri4, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("20.20.20.0/24"))
	p4 := NewPath(bgp.RF_IPv4_UC, pi, bgp.PathNLRI{NLRI: nlri4}, false, attrs, time.Now(), false)
	p4.localID = 4
	p4.remoteID = 3
	family := p1.GetFamily()
	families := []bgp.Family{family}

	adj := NewAdjRib(slog.Default(), families)
	adj.UpdateAdjRibOut([]*Path{p1, p2, p3, p4})
	assert.Equal(t, len(adj.table[family].GetDestinations()), 1)
	assert.Equal(t, adj.Count([]bgp.Family{family}), 4)
}

func TestStale(t *testing.T) {
	pi := &PeerInfo{}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}

	nlri1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("20.20.10.0/24"))
	p1 := NewPath(bgp.RF_IPv4_UC, pi, bgp.PathNLRI{NLRI: nlri1}, false, attrs, time.Now(), false)
	nlri2, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("20.20.20.0/24"))
	p2 := NewPath(bgp.RF_IPv4_UC, pi, bgp.PathNLRI{NLRI: nlri2}, false, attrs, time.Now(), false)
	p2.SetRejected(true)

	family := p1.GetFamily()
	families := []bgp.Family{family}

	adj := NewAdjRib(slog.Default(), families)
	adj.Update([]*Path{p1, p2})
	assert.Equal(t, adj.Count([]bgp.Family{family}), 2)
	assert.Equal(t, adj.Accepted([]bgp.Family{family}), 1)

	stalePathList := adj.StaleAll(families)
	// As looped path should not be returned
	assert.Equal(t, 1, len(stalePathList))

	for _, p := range adj.PathList([]bgp.Family{family}, false) {
		assert.True(t, p.IsStale())
	}

	nlri3, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("20.20.30.0/24"))
	p3 := NewPath(bgp.RF_IPv4_UC, pi, bgp.PathNLRI{NLRI: nlri3}, false, attrs, time.Now(), false)
	adj.Update([]*Path{p1, p3})

	droppedPathList := adj.DropStale(families)
	assert.Equal(t, 2, len(droppedPathList))
	assert.Equal(t, adj.Count([]bgp.Family{family}), 1)
	assert.Equal(t, 1, len(adj.table[family].GetDestinations()))
}

func TestDropSkipsRejected(t *testing.T) {
	pi := &PeerInfo{}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}

	nlri1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("20.20.10.0/24"))
	p1 := NewPath(bgp.RF_IPv4_UC, pi, bgp.PathNLRI{NLRI: nlri1}, false, attrs, time.Now(), false)
	nlri2, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("20.20.20.0/24"))
	p2 := NewPath(bgp.RF_IPv4_UC, pi, bgp.PathNLRI{NLRI: nlri2}, false, attrs, time.Now(), false)
	p2.SetRejected(true)

	family := p1.GetFamily()
	families := []bgp.Family{family}

	adj := NewAdjRib(slog.Default(), families)
	adj.Update([]*Path{p1, p2})
	assert.Equal(t, 2, adj.Count(families))
	assert.Equal(t, 1, adj.Accepted(families))

	// Drop must not emit withdrawals for rejected paths that never entered the RIB.
	dropped := adj.Drop(families)
	assert.Equal(t, 1, len(dropped))
	// Clone() does not copy the rejected flag, so check which prefix survived.
	assert.Equal(t, "20.20.10.0/24", dropped[0].GetNlri().String())
	assert.Equal(t, 0, adj.Count(families))
	assert.Equal(t, 0, adj.Accepted(families))
}

func TestLLGRStale(t *testing.T) {
	pi := &PeerInfo{}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}

	nlri1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("20.20.10.0/24"))
	p1 := NewPath(bgp.RF_IPv4_UC, pi, bgp.PathNLRI{NLRI: nlri1}, false, attrs, time.Now(), false)

	nlri2, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("20.20.20.0/24"))
	p2 := NewPath(bgp.RF_IPv4_UC, pi, bgp.PathNLRI{NLRI: nlri2}, false, attrs, time.Now(), false)
	p2.SetRejected(true) // Not accepted

	nlri3, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("20.20.30.0/24"))
	p3 := NewPath(bgp.RF_IPv4_UC, pi, bgp.PathNLRI{NLRI: nlri3}, false, attrs, time.Now(), false)
	p3.SetRejected(true)
	// Not accepted and then dropped on MarkLLGRStaleOrDrop
	p3.SetCommunities([]uint32{uint32(bgp.COMMUNITY_NO_LLGR)}, false)

	nlri4, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("20.20.40.0/24"))
	p4 := NewPath(bgp.RF_IPv4_UC, pi, bgp.PathNLRI{NLRI: nlri4}, false, attrs, time.Now(), false)
	// dropped on MarkLLGRStaleOrDrop
	p4.SetCommunities([]uint32{uint32(bgp.COMMUNITY_NO_LLGR)}, false)

	family := p1.GetFamily()
	families := []bgp.Family{family}

	adj := NewAdjRib(slog.Default(), families)
	adj.Update([]*Path{p1, p2, p3, p4})
	assert.Equal(t, adj.Count([]bgp.Family{family}), 4)
	assert.Equal(t, adj.Accepted([]bgp.Family{family}), 2)

	pathList := adj.MarkLLGRStaleOrDrop(families)
	assert.Equal(t, 3, len(pathList)) // Does not return aslooped path that is retained in adjrib
	assert.Equal(t, adj.Count([]bgp.Family{family}), 2)
	assert.Equal(t, adj.Accepted([]bgp.Family{family}), 1)
	assert.Equal(t, 2, len(adj.table[family].GetDestinations()))

	retained := adj.PathList([]bgp.Family{family}, false)
	require.Len(t, retained, 2)
	var retainedRejected *Path
	for _, p := range retained {
		if p.IsRejected() {
			retainedRejected = p
			break
		}
	}
	require.NotNil(t, retainedRejected)
	assert.Contains(t, retainedRejected.GetCommunities(), uint32(bgp.COMMUNITY_LLGR_STALE))
}

func TestUpdateUnknownFamily(t *testing.T) {
	// A path whose address family is not registered in adj.table must be
	// silently skipped -- not panic -- in both Update and UpdateAdjRibOut.
	// This covers the treat-as-withdraw path triggered by a malformed BGP
	// UPDATE (RFC 7606): the peer may send NLRI for a family the local side
	// never negotiated, causing a nil table lookup.
	pi := &PeerInfo{}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}

	nlri1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
	p4 := NewPath(bgp.RF_IPv4_UC, pi, bgp.PathNLRI{NLRI: nlri1}, false, attrs, time.Now(), false)
	// AdjRib only knows about IPv6; IPv4 path is unconfigured.
	adj := NewAdjRib(slog.Default(), []bgp.Family{bgp.RF_IPv6_UC})
	assert.NotPanics(t, func() { adj.Update([]*Path{p4}) })
	assert.NotPanics(t, func() { adj.UpdateAdjRibOut([]*Path{p4}) })
}

func TestWithdrawUnknownPath(t *testing.T) {
	pi := &PeerInfo{}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}

	nlri1, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("20.20.20.0/24"))
	p1 := NewPath(bgp.RF_IPv4_UC, pi, bgp.PathNLRI{NLRI: nlri1}, true, attrs, time.Now(), false)
	family := p1.GetFamily()
	families := []bgp.Family{family}

	adj := NewAdjRib(logger, families)
	adj.Update([]*Path{p1})
	// Check that the table is empty (no destinations across all shards)
	dests := adj.table[family].GetDestinations()
	assert.Equal(t, 0, len(dests))
}
