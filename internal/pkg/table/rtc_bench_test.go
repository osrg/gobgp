package table

import (
	"fmt"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func BenchmarkRTCPathOperations(b *testing.B) {
	for _, count := range []int{1, 8, 32} {
		exts := make([]bgp.ExtendedCommunityInterface, count)
		for i := range exts {
			exts[i] = bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 65000, uint32(i), true)
		}
		path := rtcInterestPath(exts...)
		b.Run(fmt.Sprintf("rt=%d", count), func(b *testing.B) {
			b.Run("RegisterExisting", func(b *testing.B) {
				idx := NewVPNPathIndex()
				idx.RegisterPath(path)
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					idx.RegisterPath(path)
				}
			})
			b.Run("RegisterUnregister", func(b *testing.B) {
				idx := NewVPNPathIndex()
				// Keep the RT buckets alive so this measures path churn,
				// independently of allocating and deleting bucket maps.
				idx.RegisterPath(rtcInterestPath(exts...))
				idx.RegisterPath(path)
				idx.UnregisterPath(path)
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					idx.RegisterPath(path)
					idx.UnregisterPath(path)
				}
			})
			for _, match := range []string{"first", "last", "none"} {
				b.Run("Contains/"+match, func(b *testing.B) {
					rt := exts[0]
					switch match {
					case "last":
						rt = exts[count-1]
					case "none":
						rt = bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 65001, 0, true)
					}
					nlri := bgp.NewRouteTargetMembershipNLRI(65001, rt)
					b.ReportAllocs()
					b.ResetTimer()
					for range b.N {
						if got := RouteTargetMembershipContains(nlri, path); got != (match != "none") {
							b.Fatal("unexpected membership result")
						}
					}
				})
			}
		})
	}
}

func BenchmarkInterestedIn(b *testing.B) {
	for _, count := range []int{1, 8, 32} {
		for _, match := range []string{"first", "last", "none", "empty"} {
			b.Run(fmt.Sprintf("rt=%d/%s", count, match), func(b *testing.B) {
				exts := make([]bgp.ExtendedCommunityInterface, count)
				for i := range exts {
					exts[i] = bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 65000, uint32(i), true)
				}
				path := NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{}, false,
					[]bgp.PathAttributeInterface{bgp.NewPathAttributeExtendedCommunities(exts)}, time.Time{}, false)
				handler := NewRouteTargetMembershipHandler()
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
					handler.SyncAfterImport(NewPath(bgp.RF_RTC_UC, nil, bgp.PathNLRI{NLRI: nlri}, false,
						[]bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}, time.Time{}, false))
				}
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					if got := handler.InterestedIn(path); got != (match == "first" || match == "last") {
						b.Fatal("unexpected membership result")
					}
				}
			})
		}
	}
}
