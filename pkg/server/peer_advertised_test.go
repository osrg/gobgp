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
			n += v.(*pathIDSet).len()
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

func TestPeerAdvertisedRoutesVrf(t *testing.T) {
	rib := table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC}, oc.RouteSelectionOptionsConfig{}, oc.UseMultiplePathsConfig{})
	p := newPeerandInfo(t, 65001, 65002, "192.0.2.1", rib)
	p.fsm.pConf.ReadOnly().Config.Vrf = "vrf1"

	// updateRoutes sees paths already converted by ToLocal(), so the
	// counter is keyed by the local family.
	p.updateRoutes(makePath(t, "10.0.0.0/24", "192.0.2.254", 0))

	require.Equal(t, 1, p.advertisedRoutes([]bgp.Family{bgp.RF_IPv4_UC}))
	require.Zero(t, p.advertisedRoutes(p.toGlobalFamilies([]bgp.Family{bgp.RF_IPv4_UC})))
}

func TestPeerSentPathIDTransitions(t *testing.T) {
	rib := table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC}, oc.RouteSelectionOptionsConfig{}, oc.UseMultiplePathsConfig{})
	p := newPeerandInfo(t, 65001, 65002, "192.0.2.1", rib)
	key := *table.NewPathDestLocalKey(bgp.RF_IPv4_UC, "10.0.0.0/24")

	// value returns the stored set. present is false if key is not stored.
	value := func() (s *pathIDSet, present bool) {
		v, ok := p.sentPaths.Load(key)
		if !ok {
			return nil, false
		}
		return v.(*pathIDSet), true
	}
	requireAbsent := func(step string) {
		t.Helper()
		_, ok := value()
		require.False(t, ok, step)
	}
	requireNil := func(step string) {
		t.Helper()
		s, ok := value()
		require.True(t, ok, step)
		require.Nil(t, s, step)
	}
	requireSet := func(step string, ids ...uint32) *pathIDSet {
		t.Helper()
		s, ok := value()
		require.True(t, ok, step)
		require.NotNil(t, s, step)
		require.Equal(t, len(ids), s.len(), step)
		for _, id := range ids {
			require.True(t, s.has(id), "%s: id %d", step, id)
		}
		return s
	}

	// A non-zero ID for a key with a nil value happens only when sentPaths
	// was not cleared between sessions. Those cases log an error, but the
	// set must still be right.
	t.Run("id 0 only", func(t *testing.T) {
		require.True(t, p.addSentPathID(key, 0))
		requireNil("add 0")
		require.False(t, p.addSentPathID(key, 0))
		requireNil("add 0 again")
		require.False(t, p.deleteSentPathID(key, 1))
		requireNil("delete absent id")
		require.True(t, p.deleteSentPathID(key, 0))
		requireAbsent("delete 0")
		require.False(t, p.deleteSentPathID(key, 0))
		requireAbsent("delete 0 again")
	})

	t.Run("nil to set", func(t *testing.T) {
		require.True(t, p.addSentPathID(key, 0))
		requireNil("add 0")
		require.True(t, p.addSentPathID(key, 1))
		s := requireSet("add 1", 0, 1)
		require.True(t, p.deleteSentPathID(key, 1))
		// The set is not changed back to nil.
		require.Same(t, s, requireSet("delete 1", 0))
		require.True(t, p.deleteSentPathID(key, 0))
		requireAbsent("delete 0")

		// An ID that does not fit in the bits.
		require.True(t, p.addSentPathID(key, 0))
		require.True(t, p.addSentPathID(key, 64))
		requireSet("add 64", 0, 64)
		require.True(t, p.deleteSentPathID(key, 64))
		require.True(t, p.deleteSentPathID(key, 0))
		requireAbsent("delete 64 and 0")
	})

	t.Run("set first", func(t *testing.T) {
		require.True(t, p.addSentPathID(key, 1))
		s := requireSet("add 1", 1)
		require.False(t, p.addSentPathID(key, 1))
		require.True(t, p.addSentPathID(key, 2))
		require.True(t, p.addSentPathID(key, 0))
		require.False(t, p.addSentPathID(key, 0))
		// Changes after the first Store are done in place.
		require.Same(t, s, requireSet("add 2 and 0", 0, 1, 2))
		require.False(t, p.deleteSentPathID(key, 3))
		require.True(t, p.deleteSentPathID(key, 1))
		requireSet("delete 1", 0, 2)
		require.True(t, p.deleteSentPathID(key, 0))
		require.False(t, p.deleteSentPathID(key, 0))
		requireSet("delete 0", 2)
		require.True(t, p.deleteSentPathID(key, 2))
		requireAbsent("delete 2")
	})
}

func TestPathIDSet(t *testing.T) {
	var s *pathIDSet
	require.Equal(t, 1, s.len())
	require.True(t, s.has(0))
	require.False(t, s.has(1))

	s = newPathIDSet()
	require.Zero(t, s.len())
	require.False(t, s.has(0))
	for _, id := range []uint32{0, 1, 63, 64, 65, 1000} {
		require.True(t, s.add(id), "add %d", id)
		require.False(t, s.add(id), "add %d again", id)
	}
	require.Equal(t, 6, s.len())
	require.Equal(t, uint64(1|1<<1|1<<63), s.bits)
	require.ElementsMatch(t, []uint32{64, 65, 1000}, s.ids)
	require.False(t, s.has(2))
	require.False(t, s.has(66))

	require.False(t, s.remove(2))
	require.False(t, s.remove(66))
	require.True(t, s.remove(63))
	require.False(t, s.has(63))
	require.True(t, s.remove(64))
	require.False(t, s.has(64))
	require.ElementsMatch(t, []uint32{65, 1000}, s.ids)
	require.Equal(t, 4, s.len())
	for _, id := range []uint32{0, 1, 65, 1000} {
		require.True(t, s.remove(id), "remove %d", id)
	}
	require.Zero(t, s.len())
	require.Zero(t, s.bits)
	require.Empty(t, s.ids)
}
