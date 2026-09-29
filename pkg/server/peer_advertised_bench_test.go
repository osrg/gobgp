package server

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// BenchmarkAdvertisedCount compares the ListPeer "advertised" figure computed
// by recomputing the export set (old) with the per-peer counter (new).
func BenchmarkAdvertisedCount(b *testing.B) {
	v4 := []bgp.Family{bgp.RF_IPv4_UC}
	for _, n := range []int{1_000, 10_000, 100_000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			s := NewBgpServer()
			go s.Serve()
			require.NoError(b, s.StartBgp(context.Background(), &api.StartBgpRequest{
				Global: &api.Global{Asn: 65001, RouterId: "1.1.1.1", ListenPort: -1},
			}))

			addr := netip.MustParseAddr("10.0.0.1")
			p := newPeerandInfo(b, 65001, 65002, addr.String(), s.globalRib)
			p.policy = s.policy
			p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
			p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_NONE})
			require.NoError(b, s.mgmtOperation(func() error {
				s.neighborMap[addr] = p
				return nil
			}, true))
			b.Cleanup(func() {
				_ = s.mgmtOperation(func() error {
					delete(s.neighborMap, addr)
					return nil
				}, false)
				cleanInfiniteChannel(p.fsm.outgoingCh)
				_ = s.StopBgp(context.Background(), &api.StopBgpRequest{})
			})

			paths := make([]*table.Path, 0, n)
			for i := range n {
				prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{20, byte(i >> 16), byte(i >> 8), byte(i)}), 32)
				paths = append(paths, makePath(b, prefix.String(), "10.0.0.254", 0))
			}
			s.propagateUpdate(nil, paths)

			old := func() int {
				got := 0
				s.getBestFromLocalCallback(p, v4, false, false, func(paths []*table.Path, _ []*table.Path) {
					got = len(paths)
				})
				return got
			}
			if want, got := old(), p.advertisedRoutes(v4); want != n || got != n {
				b.Fatalf("mismatch: recompute=%d counter=%d want=%d", want, got, n)
			}

			b.Run("recompute", func(b *testing.B) {
				b.ReportAllocs()
				for range b.N {
					_ = old()
				}
			})
			b.Run("counter", func(b *testing.B) {
				b.ReportAllocs()
				for range b.N {
					_ = p.advertisedRoutes(v4)
				}
			})
		})
	}
}
