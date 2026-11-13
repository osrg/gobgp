package table

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// GetImportingVrfs must return the VRFs for which CanImportToVrf is true,
// also after VRFs sharing Route Targets are deleted.
func TestGetImportingVrfs(t *testing.T) {
	rt := func(s string) bgp.ExtendedCommunityInterface {
		r, err := bgp.ParseRouteTarget(s)
		require.NoError(t, err)
		return r
	}
	rd, err := bgp.ParseRouteDistinguisher("100:1")
	require.NoError(t, err)
	rts := []bgp.ExtendedCommunityInterface{rt("100:0"), rt("100:1"), rt("100:2")}
	m := NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_VPN, bgp.RF_RTC_UC}, oc.RouteSelectionOptionsConfig{}, oc.UseMultiplePathsConfig{})
	pi := &PeerInfo{}
	for name, imp := range map[string][]bgp.ExtendedCommunityInterface{
		"a": {rts[0]}, "b": {rts[0], rts[1]}, "c": {rts[2]}, "d": nil,
	} {
		_, err := m.AddVrf(name, 0, rd, imp, nil, pi)
		require.NoError(t, err)
	}
	path := func(prefix string, ecs ...bgp.ExtendedCommunityInterface) *Path {
		nlri, err := bgp.NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix(prefix), *bgp.NewMPLSLabelStack(), rd)
		require.NoError(t, err)
		attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), bgp.NewPathAttributeExtendedCommunities(ecs)}
		return NewPath(bgp.RF_IPv4_VPN, pi, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
	}
	paths := []*Path{
		path("10.0.0.0/24", rts[0]),
		path("10.0.1.0/24", rts[1], rts[2]),
		path("10.0.2.0/24", rt("999:9")),
		path("10.0.3.0/24", bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 100, 0, false)),
	}
	check := func() {
		t.Helper()
		for _, p := range paths {
			want := map[string]*Vrf{}
			for name, vrf := range m.GetAllVrfsMap() {
				if CanImportToVrf(vrf, p) {
					want[name] = vrf
				}
			}
			got := m.GetImportingVrfs(p)
			if got == nil {
				got = map[string]*Vrf{}
			}
			require.Equal(t, want, got, p.GetNlri().String())
		}
	}
	check()
	_, err = m.DeleteVrf("b")
	require.NoError(t, err)
	check()
	_, err = m.DeleteVrf("a")
	require.NoError(t, err)
	check()
	require.Nil(t, m.GetImportingVrfs(nil))
}
