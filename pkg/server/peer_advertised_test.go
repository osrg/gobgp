package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func TestPeerAdvertisedRoutesMatchesSentPaths(t *testing.T) {
	rib := table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC}, oc.RouteSelectionOptionsConfig{}, oc.UseMultiplePathsConfig{})
	p := newPeerandInfo(t, 65001, 65002, "192.0.2.1", rib)
	v4 := []bgp.Family{bgp.RF_IPv4_UC}

	inSentPaths := func() int {
		n := 0
		p.sentPaths.Range(func(_, v any) bool {
			n += len(v.(pathIDSet))
			return true
		})
		return n
	}
	check := func(step string, want int) {
		t.Helper()
		require.Equal(t, want, p.advertisedRoutes(v4), "%s: counter", step)
		require.Equal(t, inSentPaths(), p.advertisedRoutes(v4), "%s: counter vs sentPaths", step)
	}
	withdraw := func(path *table.Path) *table.Path { return path.Clone(true) }

	a := makePath(t, "10.0.0.0/24", "192.0.2.254", 0)
	b := makePath(t, "10.0.1.0/24", "192.0.2.254", 0)

	check("empty", 0)
	p.updateRoutes(a, b)
	check("two adds", 2)
	p.updateRoutes(a)
	check("re-add same path", 2)
	p.updateRoutes(withdraw(a))
	check("withdraw", 1)
	p.updateRoutes(withdraw(a))
	check("withdraw again", 1)
	p.updateRoutes(withdraw(makePath(t, "10.9.9.0/24", "192.0.2.254", 0)))
	check("withdraw unknown", 1)
	require.Zero(t, p.advertisedRoutes([]bgp.Family{bgp.RF_IPv6_UC}))

	p.resetAdvertisedRoutes()
	check("reset", 0)
}
