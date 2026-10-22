package table

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func destMapPath(t *testing.T, f bgp.Family, n bgp.NLRI, id uint32) *Path {
	t.Helper()
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh}
	src := &PeerInfo{AS: 65001, Address: netip.MustParseAddr("192.0.2.1"), ID: netip.MustParseAddr("192.0.2.1")}
	return NewPath(f, src, bgp.PathNLRI{NLRI: n, ID: id}, false, attrs, time.Now(), false)
}

// TestDestMapIdentity checks that DestMap identifies destinations as the RIB
// does: labels and ADD-PATH identifiers are not part of it, the route
// distinguisher is, and BGP-LS nodes that differ only in a field String omits
// are two destinations.
func TestDestMapIdentity(t *testing.T) {
	m := NewDestMap[int](0)
	pfx := netip.MustParsePrefix("20.0.0.0/24")
	rd1, _ := bgp.ParseRouteDistinguisher("100:100")
	rd2, _ := bgp.ParseRouteDistinguisher("300:300")
	vpn := func(label uint32, rd bgp.RouteDistinguisherInterface, id uint32) *Path {
		n, err := bgp.NewLabeledVPNIPAddrPrefix(pfx, *bgp.NewMPLSLabelStack(label), rd)
		require.NoError(t, err)
		return destMapPath(t, bgp.RF_IPv4_VPN, n, id)
	}
	require.NoError(t, m.Set(vpn(100, rd1, 1), 1))
	v, ok, err := m.Get(vpn(200, rd1, 2))
	require.NoError(t, err)
	assert.True(t, ok, "a new label is another destination")
	assert.Equal(t, 1, v)
	require.NoError(t, m.Set(vpn(200, rd1, 2), 2))
	assert.Equal(t, 1, m.Len(), "label churn grew the map")
	_, ok, err = m.Get(vpn(100, rd2, 1))
	require.NoError(t, err)
	assert.False(t, ok, "another route distinguisher found the destination")

	a, b := lsNodeOfArea(t, 1), lsNodeOfArea(t, 2)
	require.Equal(t, a.String(), b.String())
	require.NoError(t, m.Set(destMapPath(t, bgp.RF_LS, a, 0), 10))
	require.NoError(t, m.Set(destMapPath(t, bgp.RF_LS, b, 0), 20))
	assert.Equal(t, 3, m.Len())
	require.NoError(t, m.Delete(destMapPath(t, bgp.RF_LS, a, 0)))
	_, ok, _ = m.Get(destMapPath(t, bgp.RF_LS, a, 0))
	assert.False(t, ok)
	v, ok, _ = m.Get(destMapPath(t, bgp.RF_LS, b, 0))
	assert.True(t, ok)
	assert.Equal(t, 20, v)
}

// TestDestMapCollisions checks that destinations whose keys collide are told
// apart as the RIB tells them apart.
func TestDestMapCollisions(t *testing.T) {
	m := NewDestMap[int](0)
	m.hash = func(bgp.NLRI) addrPrefixKey { return 1 }
	var paths []*Path
	for i := range 5 {
		n, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0." + string(rune('0'+i)) + ".0/24"))
		require.NoError(t, err)
		paths = append(paths, destMapPath(t, bgp.RF_IPv4_UC, n, 0))
		require.NoError(t, m.Set(paths[i], i))
	}
	require.Equal(t, 5, m.Len())
	require.Len(t, m.m, 1, "the keys did not collide")
	for i, p := range paths {
		v, ok, err := m.Get(p)
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, i, v)
	}
	require.NoError(t, m.Delete(paths[2]))
	_, ok, _ := m.Get(paths[2])
	assert.False(t, ok)
	assert.Equal(t, 4, m.Len())
	n := 0
	for range m.Values() {
		n++
	}
	assert.Equal(t, 4, n)
}

// TestDestMapUnidentifiable checks that a destination that cannot be
// serialized is an error, never a fallback to its string form.
func TestDestMapUnidentifiable(t *testing.T) {
	m := NewDestMap[int](0)
	bad := &bgp.LsAddrPrefix{Type: bgp.LS_NLRI_TYPE_NODE, NLRI: &bgp.LsNodeNLRI{}}
	p := destMapPath(t, bgp.RF_LS, bad, 0)
	assert.Error(t, m.Set(p, 1))
	_, _, err := m.Get(p)
	assert.Error(t, err)
	assert.Error(t, m.Delete(p))
	assert.Equal(t, 0, m.Len())
}

// TestDestMapDeleteClearsTheVacatedCell checks that deleting a destination
// from a bucket of colliding ones leaves the discarded tail of the bucket
// holding neither the NLRI nor the value, which would stay reachable through
// the bucket's backing array.
func TestDestMapDeleteClearsTheVacatedCell(t *testing.T) {
	m := NewDestMap[*int](0)
	m.hash = func(bgp.NLRI) addrPrefixKey { return 1 }
	var paths []*Path
	for i := range 3 {
		n, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(fmt.Sprintf("10.0.%d.0/24", i)))
		require.NoError(t, err)
		paths = append(paths, destMapPath(t, bgp.RF_IPv4_UC, n, 0))
		require.NoError(t, m.Set(paths[i], &i))
	}
	var key destMapKey
	for k := range m.m {
		key = k
	}
	// The bucket before the delete: its backing array is the one the bucket
	// after the delete shrinks over.
	before := m.m[key]
	require.Len(t, before, 3)

	// Deleting from the middle moves the last entry down, which leaves the
	// last cell of the backing array to be cleared; deleting the new last
	// entry then leaves another.
	require.NoError(t, m.Delete(paths[0]))
	assert.Nil(t, before[2].nlri, "the discarded tail kept an NLRI")
	assert.Nil(t, before[2].v, "the discarded tail kept a value")
	require.NoError(t, m.Delete(paths[2]))
	assert.Nil(t, before[1].nlri, "the discarded tail kept an NLRI")
	assert.Nil(t, before[1].v, "the discarded tail kept a value")

	v, ok, err := m.Get(paths[1])
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, 1, *v)
	require.NoError(t, m.Delete(paths[1]))
	assert.Nil(t, before[0].nlri)
	assert.Nil(t, before[0].v)
	assert.Equal(t, 0, m.Len())
	assert.Empty(t, m.m, "an empty bucket stayed in the map")
}
