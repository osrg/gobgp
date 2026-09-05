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

func TestAdjRibSetRejectedPreservesPath(t *testing.T) {
	for _, modified := range []bool{false, true} {
		name := "received"
		if modified {
			name = "modified"
		}
		t.Run(name, func(t *testing.T) {
			family := bgp.RF_IPv4_UC
			families := []bgp.Family{family}
			adj := NewAdjRib(logger, families)
			nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.83.0.0/24"))
			require.NoError(t, err)
			source := &PeerInfo{Address: netip.MustParseAddr("192.0.2.1"), AS: 65001}
			path := NewPath(family, source, bgp.PathNLRI{NLRI: nlri, ID: 11}, false, []bgp.PathAttributeInterface{
				bgp.NewPathAttributeOrigin(0), bgp.NewPathAttributeMultiExitDisc(50), bgp.NewPathAttributeLocalPref(100),
			}, time.Now(), true)
			path.localID = 22
			path.IsNexthopInvalid = true
			path.MarkStale(true)
			path.SetIsFromExternal(true)
			if modified {
				path = path.Clone(false)
				require.NoError(t, path.SetMed(60, true))
				path.RemoveLocalPref()
			}
			adj.Update([]*Path{path})
			initial, parent := path, path.parent
			attrs, hash := path.GetPathAttrs(), path.GetHash()
			for range 8 {
				previous := path
				rejected := !previous.IsRejected()
				path = adj.SetRejected(previous, rejected)
				assert.NotSame(t, previous, path)
				assert.Equal(t, !rejected, previous.IsRejected())
				assert.True(t, path.parent == parent, "cached ancestry must not grow")
				assert.Equal(t, attrs, path.GetPathAttrs())
				assert.Equal(t, hash, path.GetHash())
				assert.Same(t, source, path.GetSource())
				assert.Equal(t, initial.GetTimestamp(), path.GetTimestamp())
				assert.Equal(t, uint32(11), path.RemoteID())
				assert.Equal(t, uint32(22), path.LocalID())
				assert.True(t, path.IsStale())
				assert.True(t, path.IsFromExternal())
				assert.True(t, path.NoImplicitWithdraw())
				assert.True(t, path.IsNexthopInvalid)
				assert.False(t, path.IsWithdraw)
				assert.Equal(t, 1, adj.Count(families))
				accepted := 1
				if rejected {
					accepted = 0
				}
				assert.Equal(t, accepted, adj.Accepted(families))
				assert.Same(t, path, adj.SetRejected(path, rejected))
			}
			// An attribute edit on the replacement must not mutate retained old views.
			require.NoError(t, path.SetMed(99, true))
			assert.Equal(t, attrs, initial.GetPathAttrs())
		})
	}
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
	// silently skipped — not panic — in both Update and UpdateAdjRibOut.
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
