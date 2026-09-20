// Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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

package main

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func Test_ExtractReserved(t *testing.T) {
	assert := assert.New(t)
	args := strings.Split("10 rt 100:100 med 10 nexthop 10.0.0.1 aigp metric 10 local-pref 100", " ")
	keys := map[string]int{
		"rt":         paramList,
		"med":        paramSingle,
		"nexthop":    paramSingle,
		"aigp":       paramList,
		"local-pref": paramSingle,
	}
	m, _ := extractReserved(args, keys)
	assert.True(len(m["rt"]) == 1)
	assert.True(len(m["med"]) == 1)
	assert.True(len(m["nexthop"]) == 1)
	assert.True(len(m["aigp"]) == 2)
	assert.True(len(m["local-pref"]) == 1)
}

func Test_getNextHopFromPathAttributes(t *testing.T) {
	globalNexthop := netip.MustParseAddr("2001:db8::1")
	linkLocalNexthop := netip.MustParseAddr("fe80::ade0")
	unspecified := netip.MustParseAddr("::")

	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:db8:1::/64"))

	for _, tt := range []struct {
		name     string
		nexthops []netip.Addr
		want     netip.Addr
	}{
		{
			name:     "global and link-local",
			nexthops: []netip.Addr{globalNexthop, linkLocalNexthop},
			want:     globalNexthop,
		},
		{
			// BIRD sends this when it has no global address on the link.
			name:     "unspecified global and link-local",
			nexthops: []netip.Addr{unspecified, linkLocalNexthop},
			want:     linkLocalNexthop,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mpReach, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri}}, tt.nexthops...)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, getNextHopFromPathAttributes([]bgp.PathAttributeInterface{mpReach}))
		})
	}
}
