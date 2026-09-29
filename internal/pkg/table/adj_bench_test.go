package table

import (
	"fmt"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func newBenchAdjRib(b *testing.B, prefixes int) *AdjRib {
	b.Helper()
	pi := &PeerInfo{Address: netip.MustParseAddr("192.0.2.1"), AS: 65001}
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}
	adj := NewAdjRib(slog.Default(), []bgp.Family{bgp.RF_IPv4_UC})
	paths := make([]*Path, 0, prefixes)
	for i := range prefixes {
		addr := netip.AddrFrom4([4]byte{byte(i >> 16), byte(i >> 8), byte(i), 0})
		nlri, err := bgp.NewIPAddrPrefix(netip.PrefixFrom(addr, 24))
		if err != nil {
			b.Fatal(err)
		}
		paths = append(paths, NewPath(bgp.RF_IPv4_UC, pi, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false))
	}
	adj.Update(paths)
	return adj
}

// walkCount is the pre-cache implementation of Count.
func (adj *AdjRib) walkCount(rfList []bgp.Family) int {
	count := 0
	adj.walk(rfList, func(d *destination) bool {
		count += len(d.knownPathList)
		return false
	})
	return count
}

func BenchmarkAdjRibCount(b *testing.B) {
	rf := []bgp.Family{bgp.RF_IPv4_UC}
	for _, n := range []int{1_000, 100_000, 1_000_000} {
		adj := newBenchAdjRib(b, n)
		if got, want := adj.Count(rf), adj.walkCount(rf); got != want || got != n {
			b.Fatalf("count mismatch: cached=%d walk=%d want=%d", got, want, n)
		}
		b.Run(fmt.Sprintf("walk/%d", n), func(b *testing.B) {
			for range b.N {
				_ = adj.walkCount(rf)
			}
		})
		b.Run(fmt.Sprintf("cached/%d", n), func(b *testing.B) {
			for range b.N {
				_ = adj.Count(rf)
			}
		})
	}
}
