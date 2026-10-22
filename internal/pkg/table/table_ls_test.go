package table

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// lsNodeOfArea is a BGP-LS node NLRI of the OSPF protocol whose descriptor
// carries the given area, which NLRI.String omits.
func lsNodeOfArea(t *testing.T, area byte) bgp.NLRI {
	t.Helper()
	nlri, err := bgp.NLRIFromSlice(bgp.RF_LS, []byte{
		0x00, 0x01, 0x00, 0x25,
		0x03,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x18,
		0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xfd, 0xe8,
		0x02, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, area,
		0x02, 0x03, 0x00, 0x04, 0x0a, 0x00, 0x00, 0x01,
	})
	require.NoError(t, err)
	return nlri
}

// TestTableKeepsBgpLsNodesOfTwoAreasApart forces two BGP-LS nodes that differ
// only in their OSPF area into one hash bucket and checks that the RIB, which
// then tells destinations apart by AddrPrefixOnlyCompare, keeps them as two.
func TestTableKeepsBgpLsNodesOfTwoAreasApart(t *testing.T) {
	orig := tableKey
	tableKey = func(bgp.NLRI) addrPrefixKey { return 1 }
	defer func() { tableKey = orig }()

	a, b := lsNodeOfArea(t, 1), lsNodeOfArea(t, 2)
	require.Equal(t, a.String(), b.String())
	assert.NotZero(t, AddrPrefixOnlyCompare(a, b))

	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh}
	src := &PeerInfo{AS: 65001, Address: netip.MustParseAddr("192.0.2.1"), ID: netip.MustParseAddr("192.0.2.1")}
	tbl := NewTable(logger, bgp.RF_LS)
	for _, n := range []bgp.NLRI{a, b} {
		path := NewPath(bgp.RF_LS, src, bgp.PathNLRI{NLRI: n}, false, attrs, time.Now(), false)
		require.NotNil(t, tbl.update(path, oc.RouteSelectionOptionsConfig{}))
	}
	assert.Len(t, tbl.GetDestinations(), 2, "two nodes of different areas became one destination")
	da, db := tbl.GetDestination(a), tbl.GetDestination(b)
	require.NotNil(t, da)
	require.NotNil(t, db)
	assert.NotSame(t, da, db)
}
