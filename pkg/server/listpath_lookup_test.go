// Copyright (C) 2026 Pau Nadeu.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func lookupPath(t testing.TB, family bgp.Family, prefix string, labels ...uint32) *api.Path {
	t.Helper()
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	require.NoError(t, err)
	var nlri bgp.NLRI
	switch family {
	case bgp.RF_IPv4_UC:
		nlri, err = bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	case bgp.RF_IPv4_MPLS:
		nlri, err = bgp.NewLabeledIPAddrPrefix(netip.MustParsePrefix(prefix), *bgp.NewMPLSLabelStack(labels...))
	}
	require.NoError(t, err)
	p, err := apiutil.NewPath(family, nlri, false, []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh}, time.Now())
	require.NoError(t, err)
	return p
}

func apiFamilyOf(f bgp.Family) *api.Family {
	return &api.Family{Afi: api.Family_Afi(f.Afi()), Safi: api.Family_Safi(f.Safi())}
}

// listKeys runs a gRPC ListPath and returns the destinations it streamed.
func listKeys(t *testing.T, g *server, family bgp.Family, tableType api.TableType, keys ...*api.TableLookupPrefix) ([]string, error) {
	t.Helper()
	var out []string
	err := g.listPath(context.Background(), &api.ListPathRequest{TableType: tableType, Family: apiFamilyOf(family), Prefixes: keys}, func(d *api.Destination) {
		out = append(out, d.Prefix)
	})
	return out, err
}

// An exact lookup by NLRI works for labeled unicast, which a prefix string
// could not filter before, and never fall back to a longest-prefix match.
func TestListPathLookupByNLRI(t *testing.T) {
	s := startContextServer(t)
	g := &server{bgpServer: s, shared: s.shared}
	ctx := context.Background()
	for _, p := range []*api.Path{
		lookupPath(t, bgp.RF_IPv4_UC, "10.20.0.0/16"),
		lookupPath(t, bgp.RF_IPv4_UC, "10.20.1.0/24"),
		lookupPath(t, bgp.RF_IPv4_MPLS, "10.20.1.0/24", 100),
	} {
		_, err := g.AddPath(ctx, &api.AddPathRequest{TableType: api.TableType_TABLE_TYPE_GLOBAL, Path: p})
		require.NoError(t, err)
	}
	global := api.TableType_TABLE_TYPE_GLOBAL

	got, err := listKeys(t, g, bgp.RF_IPv4_MPLS, global, &api.TableLookupPrefix{Nlri: lookupPath(t, bgp.RF_IPv4_MPLS, "10.20.1.0/24", 999).Nlri})
	require.NoError(t, err)
	require.Equal(t, []string{"10.20.1.0/24"}, got, "the label is not part of the key")

	got, err = listKeys(t, g, bgp.RF_IPv4_UC, global,
		&api.TableLookupPrefix{Nlri: lookupPath(t, bgp.RF_IPv4_UC, "10.20.1.0/24").Nlri, Type: api.TableLookupPrefix_TYPE_EXACT},
		&api.TableLookupPrefix{Nlri: lookupPath(t, bgp.RF_IPv4_UC, "10.20.1.7/32").Nlri},
		&api.TableLookupPrefix{Nlri: lookupPath(t, bgp.RF_IPv4_UC, "192.0.2.0/24").Nlri})
	require.NoError(t, err)
	require.Equal(t, []string{"10.20.1.0/24"}, got, "a /32 key does not match the covering /24, and a missing key is absent")

	// The legacy unspecified-type string lookup is unchanged: an address is
	// a longest-prefix match.
	got, err = listKeys(t, g, bgp.RF_IPv4_UC, global, &api.TableLookupPrefix{Prefix: "10.20.1.7"})
	require.NoError(t, err)
	require.Equal(t, []string{"10.20.1.0/24"}, got)

	// Labeled unicast takes prefix strings now.
	got, err = listKeys(t, g, bgp.RF_IPv4_MPLS, global, &api.TableLookupPrefix{Prefix: "10.20.0.0/16", Type: api.TableLookupPrefix_TYPE_LONGER})
	require.NoError(t, err)
	require.Equal(t, []string{"10.20.1.0/24"}, got)

	// The native call.
	var native []string
	require.NoError(t, s.ListPath(apiutil.ListPathRequest{
		TableType: global, Family: bgp.RF_IPv4_UC,
		Prefixes: []*apiutil.LookupPrefix{{NLRI: mustNLRI(t, lookupPath(t, bgp.RF_IPv4_UC, "10.20.0.0/16"))}},
	}, func(prefix bgp.NLRI, _ []*apiutil.Path) { native = append(native, prefix.String()) }))
	require.Equal(t, []string{"10.20.0.0/16"}, native)
}

func mustNLRI(t *testing.T, p *api.Path) bgp.NLRI {
	t.Helper()
	nlri, err := apiutil.GetNativeNlri(p)
	require.NoError(t, err)
	return nlri
}

// Every invalid combination is refused with INVALID_ARGUMENT before the
// table is read.
func TestListPathLookupByNLRIRefusals(t *testing.T) {
	s := startContextServer(t)
	g := &server{bgpServer: s, shared: s.shared}
	uc := lookupPath(t, bgp.RF_IPv4_UC, "10.0.0.0/8").Nlri
	lu := lookupPath(t, bgp.RF_IPv4_MPLS, "10.0.0.0/8", 1).Nlri
	evpn := &api.NLRI{Nlri: &api.NLRI_EvpnEthernetSegment{EvpnEthernetSegment: &api.EVPNEthernetSegmentRoute{Rd: nil, IpAddress: "10.0.0.1"}}}
	encap4 := &api.NLRI{Nlri: &api.NLRI_Encapsulation{Encapsulation: &api.EncapsulationNLRI{Address: "192.0.2.1"}}}
	global := api.TableType_TABLE_TYPE_GLOBAL
	for name, tc := range map[string]struct {
		family bgp.Family
		table  api.TableType
		key    *api.TableLookupPrefix
	}{
		"prefix with an NLRI":      {bgp.RF_IPv4_UC, global, &api.TableLookupPrefix{Nlri: uc, Prefix: "10.0.0.0/8"}},
		"rd with an NLRI":          {bgp.RF_IPv4_UC, global, &api.TableLookupPrefix{Nlri: uc, Rd: "65000:1"}},
		"longer with an NLRI":      {bgp.RF_IPv4_UC, global, &api.TableLookupPrefix{Nlri: uc, Type: api.TableLookupPrefix_TYPE_LONGER}},
		"shorter with an NLRI":     {bgp.RF_IPv4_UC, global, &api.TableLookupPrefix{Nlri: uc, Type: api.TableLookupPrefix_TYPE_SHORTER}},
		"labeled on unicast":       {bgp.RF_IPv4_UC, global, &api.TableLookupPrefix{Nlri: lu}},
		"unicast on labeled":       {bgp.RF_IPv4_MPLS, global, &api.TableLookupPrefix{Nlri: uc}},
		"EVPN NLRI on unicast":     {bgp.RF_IPv4_UC, global, &api.TableLookupPrefix{Nlri: evpn}},
		"an NLRI on a VRF table":   {bgp.RF_IPv4_UC, api.TableType_TABLE_TYPE_VRF, &api.TableLookupPrefix{Nlri: uc}},
		"IPv4 encap on IPv6 encap": {bgp.RF_IPv6_ENCAP, global, &api.TableLookupPrefix{Nlri: encap4}},
		"IPv4 encap on unicast":    {bgp.RF_IPv4_UC, global, &api.TableLookupPrefix{Nlri: encap4}},
	} {
		_, err := listKeys(t, g, tc.family, tc.table, tc.key)
		require.Equal(t, codes.InvalidArgument, status.Code(err), "%s: %v", name, err)
	}
	// The native call refuses the same way.
	err := s.ListPath(apiutil.ListPathRequest{
		TableType: global,
		Family:    bgp.RF_IPv4_UC,
		Prefixes:  []*apiutil.LookupPrefix{{NLRI: mustNLRI(t, lookupPath(t, bgp.RF_IPv4_MPLS, "10.0.0.0/8", 1))}},
	}, func(bgp.NLRI, []*apiutil.Path) {})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	nativeEncap, err := bgp.NewEncapNLRI(netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	for _, family := range []bgp.Family{bgp.RF_IPv6_ENCAP, bgp.RF_IPv4_UC} {
		err = s.ListPath(apiutil.ListPathRequest{
			TableType: global,
			Family:    family,
			Prefixes:  []*apiutil.LookupPrefix{{NLRI: nativeEncap}},
		}, func(bgp.NLRI, []*apiutil.Path) {})
		require.Equal(t, codes.InvalidArgument, status.Code(err), "%s", family)
	}
}

// On a large table, 1,000 keys cost less than one walk of the table.
func TestListPathLookupByNLRILargeTable(t *testing.T) {
	if testing.Short() {
		t.Skip("large table")
	}
	s := startContextServer(t)
	g := &server{bgpServer: s, shared: s.shared}
	const n = 200000
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh}
	for i := 0; i < n; i += 10000 {
		batch := make([]*table.Path, 0, 10000)
		for j := i; j < i+10000; j++ {
			nlri := ucNLRIAt(j)
			batch = append(batch, table.NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false))
		}
		require.NoError(t, s.addPathStream(context.Background(), "", batch))
	}
	keys := make([]*api.TableLookupPrefix, 1000)
	for i := range keys {
		an, err := apiutil.MarshalNLRI(ucNLRIAt(i * 7))
		require.NoError(t, err)
		keys[i] = &api.TableLookupPrefix{Nlri: an}
	}
	start := time.Now()
	all, err := listKeys(t, g, bgp.RF_IPv4_UC, api.TableType_TABLE_TYPE_GLOBAL)
	require.NoError(t, err)
	walk := time.Since(start)
	require.Len(t, all, n)
	start = time.Now()
	got, err := listKeys(t, g, bgp.RF_IPv4_UC, api.TableType_TABLE_TYPE_GLOBAL, keys...)
	require.NoError(t, err)
	lookup := time.Since(start)
	t.Logf("%d paths: listing the table %v, a lookup of %d keys %v", n, walk, len(keys), lookup)
	require.Len(t, got, len(keys))
	require.Less(t, lookup, walk)
}

func ucNLRIAt(i int) *bgp.IPAddrPrefix {
	a := netip.AddrFrom4([4]byte{20, byte(i >> 16), byte(i >> 8), byte(i)})
	nlri, err := bgp.NewIPAddrPrefix(netip.PrefixFrom(a, 32))
	if err != nil {
		panic(err)
	}
	return nlri
}
