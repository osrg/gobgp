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

	"github.com/osrg/gobgp/pkg/packet/bgp"

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

	adj := NewAdjRib(families)
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

func TestStale(t *testing.T) {
	pi := &PeerInfo{}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}

	nlri1 := bgp.NewIPAddrPrefix(24, "20.20.10.0")
	p1 := NewPath(pi, nlri1, false, attrs, time.Now(), false)
	nlri2 := bgp.NewIPAddrPrefix(24, "20.20.20.0")
	p2 := NewPath(pi, nlri2, false, attrs, time.Now(), false)
	family := p1.GetRouteFamily()
	families := []bgp.RouteFamily{family}

	adj := NewAdjRib(families)
	adj.Update([]*Path{p1, p2})
	assert.Equal(t, adj.Count([]bgp.RouteFamily{family}), 2)

	adj.StaleAll(families)

	for _, p := range adj.PathList([]bgp.RouteFamily{family}, false) {
		assert.True(t, p.IsStale())
	}

	nlri3 := bgp.NewIPAddrPrefix(24, "20.20.30.0")
	p3 := NewPath(pi, nlri3, false, attrs, time.Now(), false)
	adj.Update([]*Path{p1, p3})

	adj.DropStale(families)
	assert.Equal(t, adj.Count([]bgp.RouteFamily{family}), 1)
	assert.Equal(t, 1, len(adj.table[family].destinations))
}
