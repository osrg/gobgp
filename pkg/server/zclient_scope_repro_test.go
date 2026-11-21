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
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func TestZebraNHTRegistrationAddressFamily(t *testing.T) {
	for _, tc := range []struct {
		name    string
		family  bgp.Family
		nexthop string
		wantAF  uint16
	}{
		{"ipv4_control", bgp.RF_IPv4_UC, "192.0.2.1", syscall.AF_INET},
		{"ipv6_control", bgp.RF_IPv6_UC, "2001:db8::1", syscall.AF_INET6},
		{"ipv4_extended_nexthop", bgp.RF_IPv4_UC, "2001:db8::1", syscall.AF_INET6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prefix := netip.MustParsePrefix("203.0.113.0/24")
			if tc.family == bgp.RF_IPv6_UC {
				prefix = netip.MustParsePrefix("2001:db8:113::/64")
			}
			nlri, err := bgp.NewIPAddrPrefix(prefix)
			require.NoError(t, err)
			nh, err := bgp.NewPathAttributeMpReachNLRI(tc.family,
				[]bgp.PathNLRI{{NLRI: nlri}}, netip.MustParseAddr(tc.nexthop))
			require.NoError(t, err)
			path := table.NewPath(tc.family, nil, bgp.PathNLRI{NLRI: nlri}, false,
				[]bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh}, time.Now(), false)
			body := newNexthopRegisterBody(0, []*table.Path{path}, nexthopStateCache{})
			require.NotNil(t, body)
			require.Len(t, body.Nexthops, 1)
			require.Equal(t, tc.wantAF, body.Nexthops[0].Family,
				"registration family describes the next-hop address, independently of NLRI family")
			if tc.name == "ipv4_extended_nexthop" {
				s := newNHTServer(t)
				require.NoError(t, s.addPathStream("red", []*table.Path{path}))
				z := &zebraClient{server: s, nexthopCache: make(nexthopStateCache)}
				require.NoError(t, s.mgmtOperation(func() error { s.zclient = z; return nil }, true))
				require.False(t, applyNHTMessage(t, z, nhtMessage(t, 11, path.GetNexthop(), 20, true)))
				require.False(t, applyNHTMessage(t, z, nhtMessage(t, 11, path.GetNexthop(), 0, false)))
				paths := s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_VPN})
				require.Len(t, paths, 1)
				require.True(t, paths[0].IsNexthopInvalid,
					"IPv6 NHT must find an IPv4 VPN path carrying that next hop")
			}
		})
	}
}
