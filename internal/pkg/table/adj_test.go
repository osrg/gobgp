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
	"sync"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateAdjTable(t *testing.T) {
	table := NewAdjTable(logger, bgp.RF_RTC_UC)
	assert.NotNil(t, table.adjRts)

	table = NewAdjTable(logger, bgp.RF_FS_IPv4_VPN)
	assert.Nil(t, table.adjRts)
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

func TestAdjRTC(t *testing.T) {
	pi := &PeerInfo{}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}

	rt1, _ := bgp.ParseRouteTarget("65520:1000000")
	_, err := extCommRouteTargetKey(rt1)
	assert.NoError(t, err)
	nlri1 := bgp.NewRouteTargetMembershipNLRI(65000, rt1)
	p1 := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlri1}, false, attrs, time.Now(), false)
	p1.remoteID = 1

	rt2, _ := bgp.ParseRouteTarget("65520:1000001")
	nlri2 := bgp.NewRouteTargetMembershipNLRI(65000, rt2)
	p2 := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlri2}, false, attrs, time.Now(), false)
	p2.remoteID = 2

	nlri3 := bgp.NewRouteTargetMembershipNLRI(0, nil)
	p3 := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlri3}, false, attrs, time.Now(), false)
	p3.remoteID = 3

	family := p1.GetFamily()
	assert.Equal(t, family, bgp.RF_RTC_UC)
	families := []bgp.Family{family}
	adj := NewAdjRib(logger, families)

	adj.Update([]*Path{p1, p2, p3})
	assert.Equal(t, adj.Count([]bgp.Family{family}), 3)

	assert.True(t, adj.HasDefaultRT())
	assert.True(t, adj.HasRTinRtcTable(rt1))
	assert.True(t, adj.HasRTinRtcTable(rt2))

	adj.Update([]*Path{p1.Clone(true)})
	assert.Equal(t, adj.Count([]bgp.Family{family}), 2)
	assert.True(t, adj.HasDefaultRT())
	assert.True(t, !adj.HasRTinRtcTable(rt1))
	assert.True(t, adj.HasRTinRtcTable(rt2))

	adj.Update([]*Path{p3.Clone(true)})
	assert.Equal(t, adj.Count([]bgp.Family{family}), 1)
	assert.False(t, adj.HasDefaultRT())
	assert.True(t, adj.HasRTinRtcTable(rt2))

	adj.Update([]*Path{p2.Clone(true)})
	assert.Equal(t, adj.Count([]bgp.Family{family}), 0)
	assert.True(t, !adj.HasRTinRtcTable(rt2))
}

func TestAdjRTCSameRT(t *testing.T) {
	pi := &PeerInfo{}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}

	rt1, _ := bgp.ParseRouteTarget("65520:1000000")
	nlri1a := bgp.NewRouteTargetMembershipNLRI(65000, rt1)
	nlri1b := bgp.NewRouteTargetMembershipNLRI(65001, rt1) // same RT, different AS

	// Two ADD-PATH paths for the same (AS=65000, RT=rt1) NLRI, different path IDs.
	p1 := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlri1a, ID: 1}, false, attrs, time.Now(), false)
	p2 := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlri1a, ID: 2}, false, attrs, time.Now(), false)
	// Different AS, same RT.
	p3 := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlri1b, ID: 1}, false, attrs, time.Now(), false)

	family := bgp.RF_RTC_UC
	adj := NewAdjRib(logger, []bgp.Family{family})

	adj.Update([]*Path{p1, p2, p3})
	assert.Equal(t, 3, adj.Count([]bgp.Family{family}))
	assert.True(t, adj.HasRTinRtcTable(rt1))

	// Withdraw p1 — p2 and p3 still hold rt1 interest.
	adj.Update([]*Path{p1.Clone(true)})
	assert.Equal(t, 2, adj.Count([]bgp.Family{family}))
	assert.True(t, adj.HasRTinRtcTable(rt1), "peer still has rt1 via p2 and p3")

	// Withdraw p3 — p2 still holds rt1 interest.
	adj.Update([]*Path{p3.Clone(true)})
	assert.Equal(t, 1, adj.Count([]bgp.Family{family}))
	assert.True(t, adj.HasRTinRtcTable(rt1), "peer still has rt1 via p2")

	// Spurious withdraw: same NLRI as p2 but unknown pathID — must be a no-op.
	pSpurious := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlri1a, ID: 99}, true, attrs, time.Now(), false)
	adj.Update([]*Path{pSpurious})
	assert.True(t, adj.HasRTinRtcTable(rt1), "spurious withdraw must not remove rt1 interest")

	// Withdraw p2 — no more rt1 interest.
	adj.Update([]*Path{p2.Clone(true)})
	assert.Equal(t, 0, adj.Count([]bgp.Family{family}))
	assert.False(t, adj.HasRTinRtcTable(rt1))
}

func TestAdjRTSetConcurrent(t *testing.T) {
	pi := &PeerInfo{}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}

	rt, _ := bgp.ParseRouteTarget("65520:1000000")
	nlri := bgp.NewRouteTargetMembershipNLRI(65000, rt)
	rtHash, err := nlriRouteTargetKey(nlri)
	assert.NoError(t, err)

	s := newAdjRTSet()

	const goroutines = 20
	const iters = 500

	var wg sync.WaitGroup

	// Writers: concurrent add and sub.
	for i := range goroutines {
		wg.Add(1)
		go func(id uint32) {
			defer wg.Done()
			path := NewPath(bgp.RF_RTC_UC, pi, bgp.PathNLRI{NLRI: nlri, ID: id}, false, attrs, time.Now(), false)
			withdraw := path.Clone(true)
			for range iters {
				s.add(path)
				s.sub(withdraw)
			}
		}(uint32(i))
	}

	// Readers: concurrent has, running throughout the writes.
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iters {
				_ = s.has(rtHash)
				_ = s.has(DefaultRT)
			}
		}()
	}

	wg.Wait()
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
