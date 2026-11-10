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

package gr

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

var (
	v4 = bgp.RF_IPv4_UC
	v6 = bgp.RF_IPv6_UC

	both = map[bgp.Family]bool{v4: true, v6: true}
)

func grCap(restartTime uint16, tuples ...*bgp.CapGracefulRestartTuple) *bgp.CapGracefulRestart {
	return bgp.NewCapGracefulRestart(false, false, restartTime, tuples)
}

func grTuple(f bgp.Family, forward bool) *bgp.CapGracefulRestartTuple {
	return bgp.NewCapGracefulRestartTuple(f, forward)
}

func llgrCap(tuples ...*bgp.CapLongLivedGracefulRestartTuple) *bgp.CapLongLivedGracefulRestart {
	return bgp.NewCapLongLivedGracefulRestart(tuples)
}

func llgrTuple(f bgp.Family, forward bool, llst uint32) *bgp.CapLongLivedGracefulRestartTuple {
	return bgp.NewCapLongLivedGracefulRestartTuple(f, forward, llst)
}

// grNegotiated is what a session negotiated: graceful restart for ipv4 and
// ipv6, and long-lived graceful restart for ipv4 with an LLST of 60 seconds.
func grNegotiated() Negotiated {
	return Negotiated{
		Families: both,
		GR:       grCap(120, grTuple(v4, true), grTuple(v6, true)),
		LLGR:     llgrCap(llgrTuple(v4, true, 60)),
	}
}

func TestNegotiated_HasFamilies(t *testing.T) {
	v4only := map[bgp.Family]bool{v4: true}
	tests := []struct {
		name string
		n    Negotiated
		want bool
	}{
		{"nothing", Negotiated{Families: both}, false},
		{"graceful restart", Negotiated{Families: both, GR: grCap(120, grTuple(v4, false))}, true},
		{"no family in the capability", Negotiated{Families: both, GR: grCap(120)}, false},
		{"family not negotiated", Negotiated{Families: v4only, GR: grCap(120, grTuple(v6, true))}, false},
		{"long-lived graceful restart only", Negotiated{Families: both, GR: grCap(0), LLGR: llgrCap(llgrTuple(v4, true, 60))}, true},
		{"long-lived without graceful restart", Negotiated{Families: both, LLGR: llgrCap(llgrTuple(v4, true, 60))}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.n.HasFamilies())
		})
	}
}
