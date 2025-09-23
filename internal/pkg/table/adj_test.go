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
)

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
}
