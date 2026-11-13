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
