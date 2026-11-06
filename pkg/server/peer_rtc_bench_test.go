package server

import (
	"fmt"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func BenchmarkInterestedIn(b *testing.B) {
	for _, count := range []int{1, 8, 32} {
		for _, match := range []string{"first", "last", "none", "empty"} {
			b.Run(fmt.Sprintf("rt=%d/%s", count, match), func(b *testing.B) {
				exts := make([]bgp.ExtendedCommunityInterface, count)
				for i := range exts {
					exts[i] = bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 65000, uint32(i), true)
				}
				path := table.NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{}, false,
					[]bgp.PathAttributeInterface{bgp.NewPathAttributeExtendedCommunities(exts)}, time.Time{}, false)
				p := &peer{rtmHandler: table.NewRouteTargetMembershipHandler()}
				index := 0
				if match == "last" {
					index = count - 1
				}
				if match != "empty" {
					rt := exts[index]
					if match == "none" {
						rt = bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 65001, 0, true)
					}
					nlri := bgp.NewRouteTargetMembershipNLRI(65001, rt)
					p.rtmHandler.SyncAfterImport(table.NewPath(bgp.RF_RTC_UC, nil, bgp.PathNLRI{NLRI: nlri}, false,
						[]bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}, time.Time{}, false))
				}
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					if got := p.interestedIn(path); got != (match == "first" || match == "last") {
						b.Fatal("unexpected membership result")
					}
				}
			})
		}
	}
}
