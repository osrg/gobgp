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
	"testing"
	"time"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
)

func TestAddPath(t *testing.T) {
	pi := &PeerInfo{}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}

	nlri1 := bgp.NewIPAddrPrefix(24, "20.20.20.0")
	nlri1.SetPathIdentifier(1)
	p1 := NewPath(pi, nlri1, false, attrs, time.Now(), false)
	nlri2 := bgp.NewIPAddrPrefix(24, "20.20.20.0")
	nlri2.SetPathIdentifier(2)
	p2 := NewPath(pi, nlri2, false, attrs, time.Now(), false)
	family := p1.GetRouteFamily()
	families := []bgp.RouteFamily{family}

	adj := NewAdjRib(logger, families)
	adj.Update([]*Path{p1, p2})
	assert.Equal(t, len(adj.table[family].destinations), 1)
	assert.Equal(t, adj.Count([]bgp.RouteFamily{family}), 2)

	p3 := NewPath(pi, nlri2, false, attrs, time.Now(), false)
	adj.Update([]*Path{p3})

	var found *Path
	for _, d := range adj.table[family].destinations {
		for _, p := range d.knownPathList {
			if p.GetNlri().PathIdentifier() == nlri2.PathIdentifier() {
				found = p
				break
			}
		}
	}
	assert.Equal(t, found, p3)
	adj.Update([]*Path{p3.Clone(true)})
	assert.Equal(t, adj.Count([]bgp.RouteFamily{family}), 1)
	adj.Update([]*Path{p1.Clone(true)})
	assert.Equal(t, 0, len(adj.table[family].destinations))
}

func TestAddPathAdjOut(t *testing.T) {
	pi := &PeerInfo{}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}

	nlri1 := bgp.NewIPAddrPrefix(24, "20.20.20.0")
	nlri1.SetPathIdentifier(1)
	nlri1.SetPathLocalIdentifier(1)
	p1 := NewPath(pi, nlri1, false, attrs, time.Now(), false)
	nlri2 := bgp.NewIPAddrPrefix(24, "20.20.20.0")
	nlri2.SetPathIdentifier(1)
	nlri2.SetPathLocalIdentifier(2)
	p2 := NewPath(pi, nlri2, false, attrs, time.Now(), false)
	nlri3 := bgp.NewIPAddrPrefix(24, "20.20.20.0")
	nlri3.SetPathIdentifier(2)
	nlri3.SetPathLocalIdentifier(3)
	p3 := NewPath(pi, nlri3, false, attrs, time.Now(), false)
	nlri4 := bgp.NewIPAddrPrefix(24, "20.20.20.0")
	nlri4.SetPathIdentifier(3)
	nlri4.SetPathLocalIdentifier(4)
	p4 := NewPath(pi, nlri4, false, attrs, time.Now(), false)
	family := p1.GetRouteFamily()
	families := []bgp.RouteFamily{family}

	adj := NewAdjRib(logger, families)
	adj.UpdateAdjRibOut([]*Path{p1, p2, p3, p4})
	assert.Equal(t, len(adj.table[family].destinations), 1)
	assert.Equal(t, adj.Count([]bgp.RouteFamily{family}), 4)
}

func TestStale(t *testing.T) {
	pi := &PeerInfo{}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}

	nlri1 := bgp.NewIPAddrPrefix(24, "20.20.10.0")
	p1 := NewPath(pi, nlri1, false, attrs, time.Now(), false)
	nlri2 := bgp.NewIPAddrPrefix(24, "20.20.20.0")
	p2 := NewPath(pi, nlri2, false, attrs, time.Now(), false)
	p2.SetRejected(true)

	family := p1.GetRouteFamily()
	families := []bgp.RouteFamily{family}

	adj := NewAdjRib(logger, families)
	adj.Update([]*Path{p1, p2})
	assert.Equal(t, adj.Count([]bgp.RouteFamily{family}), 2)
	assert.Equal(t, adj.Accepted([]bgp.RouteFamily{family}), 1)

	stalePathList := adj.StaleAll(families)
	// As looped path should not be returned
	assert.Equal(t, 1, len(stalePathList))

	for _, p := range adj.PathList([]bgp.RouteFamily{family}, false) {
		assert.True(t, p.IsStale())
	}

	nlri3 := bgp.NewIPAddrPrefix(24, "20.20.30.0")
	p3 := NewPath(pi, nlri3, false, attrs, time.Now(), false)
	adj.Update([]*Path{p1, p3})

	droppedPathList := adj.DropStale(families)
	assert.Equal(t, 2, len(droppedPathList))
	assert.Equal(t, adj.Count([]bgp.RouteFamily{family}), 1)
	assert.Equal(t, 1, len(adj.table[family].destinations))
}

func TestLLGRStale(t *testing.T) {
	pi := &PeerInfo{}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}

	nlri1 := bgp.NewIPAddrPrefix(24, "20.20.10.0")
	p1 := NewPath(pi, nlri1, false, attrs, time.Now(), false)

	nlri2 := bgp.NewIPAddrPrefix(24, "20.20.20.0")
	p2 := NewPath(pi, nlri2, false, attrs, time.Now(), false)
	p2.SetRejected(true) // Not accepted

	nlri3 := bgp.NewIPAddrPrefix(24, "20.20.30.0")
	p3 := NewPath(pi, nlri3, false, attrs, time.Now(), false)
	p3.SetRejected(true)
	// Not accepted and then dropped on MarkLLGRStaleOrDrop
	p3.SetCommunities([]uint32{uint32(bgp.COMMUNITY_NO_LLGR)}, false)

	nlri4 := bgp.NewIPAddrPrefix(24, "20.20.40.0")
	p4 := NewPath(pi, nlri4, false, attrs, time.Now(), false)
	// dropped on MarkLLGRStaleOrDrop
	p4.SetCommunities([]uint32{uint32(bgp.COMMUNITY_NO_LLGR)}, false)

	family := p1.GetRouteFamily()
	families := []bgp.RouteFamily{family}

	adj := NewAdjRib(logger, families)
	adj.Update([]*Path{p1, p2, p3, p4})
	assert.Equal(t, adj.Count([]bgp.RouteFamily{family}), 4)
	assert.Equal(t, adj.Accepted([]bgp.RouteFamily{family}), 2)

	pathList := adj.MarkLLGRStaleOrDrop(families)
	assert.Equal(t, 3, len(pathList)) // Does not return aslooped path that is retained in adjrib
	assert.Equal(t, adj.Count([]bgp.RouteFamily{family}), 2)
	assert.Equal(t, adj.Accepted([]bgp.RouteFamily{family}), 1)
	assert.Equal(t, 2, len(adj.table[family].destinations))
}
