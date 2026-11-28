package server

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// Cost of injecting one VPN path with one VRF neighbor per VRF.
func BenchmarkVrfNeighborsInject(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("vrf-neighbors=%d", n), func(b *testing.B) {
			s, _ := newVrfNeighbors(b, n, n, 0)
			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				v := i % n
				rd := bgp.NewRouteDistinguisherTwoOctetAS(65000, uint32(v))
				prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{20, byte(i >> 16), byte(i >> 8), byte(i)}), 32)
				s.propagateUpdate(nil, []*table.Path{newVPNPathForTest(b, prefix, rd, vrfRT(v))})
			}
		})
	}
}

// Cost of advertising its VRF to one neighbor (session up, graceful restart
// release, route refresh): 100 VRFs of 10000 routes.
func BenchmarkVrfNeighborDump(b *testing.B) {
	s, peers := newVrfNeighbors(b, 100, 1, 10000)
	for _, mode := range []struct {
		name     string
		fullScan bool
	}{{"full-scan", true}, {"rt-index", false}} {
		b.Run(mode.name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				if paths, _ := vrfDump(s, peers[0], mode.fullScan); len(paths) != 10000 {
					b.Fatalf("got %d paths", len(paths))
				}
			}
		})
	}
}
