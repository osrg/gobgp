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

package table

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func TestNoImplicitWithdrawCloneLineage(t *testing.T) {
	for _, withdraw := range []bool{false, true} {
		t.Run(map[bool]string{false: "update", true: "withdraw"}[withdraw], func(t *testing.T) {
			logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
			rib := NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC},
				oc.RouteSelectionOptionsConfig{}, oc.UseMultiplePathsConfig{})
			makePath := func(med uint32) *Path {
				nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("203.0.113.0/24"))
				require.NoError(t, err)
				nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
				require.NoError(t, err)
				return NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false,
					[]bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh, bgp.NewPathAttributeMultiExitDisc(med)},
					time.Now(), true)
			}
			first, second := makePath(10), makePath(40)
			rib.Update(first)
			rib.Update(second)
			require.NotEqual(t, first.LocalID(), second.LocalID())
			updated := first.Clone(withdraw)
			if !withdraw {
				require.NoError(t, updated.SetMed(20, true))
			}
			rib.Update(updated)
			paths := rib.GetPathList(GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_UC})
			if withdraw {
				require.Len(t, paths, 1)
				require.True(t, paths[0].OriginInfo() == second.OriginInfo(),
					"a clone withdrawal must remove its own retained lineage")
				return
			}
			require.Len(t, paths, 2, "a clone update must replace its retained lineage instead of adding a third path")
			counts := make(map[*Path]int)
			for _, path := range paths {
				if path.OriginInfo() == first.OriginInfo() {
					counts[first]++
					require.Equal(t, first.LocalID(), path.LocalID())
					med, err := path.GetMed()
					require.NoError(t, err)
					require.Equal(t, uint32(20), med)
				} else {
					counts[second]++
				}
			}
			require.Equal(t, map[*Path]int{first: 1, second: 1}, counts)
		})
	}
}
