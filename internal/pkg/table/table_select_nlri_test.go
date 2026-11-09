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

package table

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func selectTable(t *testing.T, family bgp.Family, nlris ...bgp.NLRI) *Table {
	t.Helper()
	tbl := NewTable(logger, family)
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}
	for _, nlri := range nlris {
		p := NewPath(family, &PeerInfo{}, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
		tbl.setDestination(newDestination(nlri, 0, p))
	}
	return tbl
}

func selected(t *testing.T, tbl *Table, keys ...*apiutil.LookupPrefix) []string {
	t.Helper()
	r, err := tbl.Select(TableSelectOption{LookupPrefixes: keys})
	require.NoError(t, err)
	var out []string
	for _, d := range r.GetDestinations() {
		out = append(out, d.GetNlri().String())
	}
	return out
}

func ucNLRI(s string) *bgp.IPAddrPrefix {
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(s))
	if err != nil {
		panic(err)
	}
	return nlri
}

func luNLRI(s string, labels ...uint32) *bgp.LabeledIPAddrPrefix {
	nlri, err := bgp.NewLabeledIPAddrPrefix(netip.MustParsePrefix(s), *bgp.NewMPLSLabelStack(labels...))
	if err != nil {
		panic(err)
	}
	return nlri
}

// A lookup by NLRI reads the one destination it names. It is exact even
// with the unspecified lookup type: no longest-prefix match.
func TestSelectByNLRIUnicast(t *testing.T) {
	tbl := selectTable(t, bgp.RF_IPv4_UC, ucNLRI("10.0.0.0/8"), ucNLRI("10.1.0.0/16"))
	require.Equal(t, []string{"10.1.0.0/16"}, selected(t, tbl, &apiutil.LookupPrefix{NLRI: ucNLRI("10.1.0.0/16")}))
	require.Empty(t, selected(t, tbl, &apiutil.LookupPrefix{NLRI: ucNLRI("10.1.2.0/24")}))
	require.Empty(t, selected(t, tbl, &apiutil.LookupPrefix{NLRI: ucNLRI("10.1.2.3/32")}))
	// Several keys, and a key with no destination: the answer has only
	// the destinations found, and the table is not walked.
	require.ElementsMatch(t, []string{"10.0.0.0/8", "10.1.0.0/16"}, selected(t, tbl,
		&apiutil.LookupPrefix{NLRI: ucNLRI("10.1.0.0/16")},
		&apiutil.LookupPrefix{NLRI: ucNLRI("192.0.2.0/24")},
		&apiutil.LookupPrefix{NLRI: ucNLRI("10.0.0.0/8")}))
	// An NLRI key and a prefix string in one request.
	require.ElementsMatch(t, []string{"10.0.0.0/8", "10.1.0.0/16"}, selected(t, tbl,
		&apiutil.LookupPrefix{NLRI: ucNLRI("10.0.0.0/8")},
		&apiutil.LookupPrefix{Prefix: "10.1.2.3"}))
}

// A labeled-unicast destination is keyed by its prefix: the label of the
// key does not matter.
func TestSelectByNLRILabeledUnicast(t *testing.T) {
	tbl := selectTable(t, bgp.RF_IPv4_MPLS, luNLRI("10.0.0.0/24", 100), luNLRI("10.0.0.0/16", 200))
	require.Equal(t, []string{"10.0.0.0/24"}, selected(t, tbl, &apiutil.LookupPrefix{NLRI: luNLRI("10.0.0.0/24", 100)}))
	require.Equal(t, []string{"10.0.0.0/24"}, selected(t, tbl, &apiutil.LookupPrefix{NLRI: luNLRI("10.0.0.0/24", 300)}))
	require.Equal(t, []string{"10.0.0.0/24"}, selected(t, tbl, &apiutil.LookupPrefix{NLRI: luNLRI("10.0.0.0/24")}))
	require.Empty(t, selected(t, tbl, &apiutil.LookupPrefix{NLRI: luNLRI("10.0.0.0/25", 100)}))
}

// Labeled unicast takes the prefix strings of unicast, with the same
// lookup types.
func TestSelectLabeledUnicastPrefixStrings(t *testing.T) {
	tbl := selectTable(t, bgp.RF_IPv4_MPLS, luNLRI("10.0.0.0/8", 1), luNLRI("10.1.0.0/16", 2), luNLRI("10.1.1.0/24", 3))
	require.Equal(t, []string{"10.1.0.0/16"}, selected(t, tbl, &apiutil.LookupPrefix{Prefix: "10.1.0.0/16"}))
	require.Equal(t, []string{"10.1.0.0/16"}, selected(t, tbl, &apiutil.LookupPrefix{Prefix: "10.1.0.0/16", LookupOption: apiutil.LOOKUP_EXACT}))
	require.Equal(t, []string{"10.1.1.0/24"}, selected(t, tbl, &apiutil.LookupPrefix{Prefix: "10.1.1.7"}), "an address is a longest-prefix match, as for unicast")
	require.ElementsMatch(t, []string{"10.1.0.0/16", "10.1.1.0/24"}, selected(t, tbl, &apiutil.LookupPrefix{Prefix: "10.1.0.0/16", LookupOption: apiutil.LOOKUP_LONGER}))
	require.ElementsMatch(t, []string{"10.0.0.0/8", "10.1.0.0/16"}, selected(t, tbl, &apiutil.LookupPrefix{Prefix: "10.1.0.0/16", LookupOption: apiutil.LOOKUP_SHORTER}))
	_, err := tbl.Select(TableSelectOption{LookupPrefixes: []*apiutil.LookupPrefix{{Prefix: "2001:db8::/32"}}})
	require.Error(t, err, "an IPv6 key on an IPv4 table")

	tbl6 := selectTable(t, bgp.RF_IPv6_MPLS, luNLRI("2001:db8::/32", 1))
	require.Equal(t, []string{"2001:db8::/32"}, selected(t, tbl6, &apiutil.LookupPrefix{Prefix: "2001:db8::1"}))
}

// Families that take no prefix string are read by NLRI.
func TestSelectByNLRIOtherFamilies(t *testing.T) {
	fs := func(prefix string) bgp.NLRI {
		nlri, err := bgp.NewFlowSpecUnicast(bgp.RF_FS_IPv4_UC, []bgp.FlowSpecComponentInterface{bgp.NewFlowSpecDestinationPrefix(ucNLRI(prefix))})
		require.NoError(t, err)
		return nlri
	}
	tbl := selectTable(t, bgp.RF_FS_IPv4_UC, fs("10.0.0.0/24"), fs("10.0.1.0/24"))
	require.Len(t, selected(t, tbl, &apiutil.LookupPrefix{NLRI: fs("10.0.1.0/24")}), 1)
	require.Empty(t, selected(t, tbl, &apiutil.LookupPrefix{NLRI: fs("10.0.2.0/24")}))
	_, err := tbl.Select(TableSelectOption{LookupPrefixes: []*apiutil.LookupPrefix{{Prefix: "10.0.1.0/24"}}})
	require.Error(t, err, "a prefix string is still refused for flowspec")

	rd := bgp.NewRouteDistinguisherTwoOctetAS(65000, 1)
	esi := bgp.EthernetSegmentIdentifier{Type: bgp.ESI_ARBITRARY, Value: []byte{1, 1, 1, 1, 1, 1, 1, 1, 1}}
	mac := func(m string) bgp.NLRI {
		nlri, err := bgp.NewEVPNMacIPAdvertisementRoute(rd, esi, 0, m, netip.Addr{}, []uint32{10})
		require.NoError(t, err)
		return nlri
	}
	evpn := selectTable(t, bgp.RF_EVPN, mac("aa:bb:cc:00:00:01"), mac("aa:bb:cc:00:00:02"))
	got := selected(t, evpn, &apiutil.LookupPrefix{NLRI: mac("aa:bb:cc:00:00:02")})
	require.Len(t, got, 1)
	require.Contains(t, got[0], "aa:bb:cc:00:00:02")
}

func TestSelectByNLRIRefusals(t *testing.T) {
	tbl := selectTable(t, bgp.RF_IPv4_UC, ucNLRI("10.0.0.0/8"))
	for name, key := range map[string]*apiutil.LookupPrefix{
		"with a prefix string":       {NLRI: ucNLRI("10.0.0.0/8"), Prefix: "10.0.0.0/8"},
		"with a route distinguisher": {NLRI: ucNLRI("10.0.0.0/8"), RD: "65000:1"},
		"longer":                     {NLRI: ucNLRI("10.0.0.0/8"), LookupOption: apiutil.LOOKUP_LONGER},
		"shorter":                    {NLRI: ucNLRI("10.0.0.0/8"), LookupOption: apiutil.LOOKUP_SHORTER},
		"IPv6 on IPv4":               {NLRI: ucNLRI("2001:db8::/32")},
		"labeled on unicast":         {NLRI: luNLRI("10.0.0.0/8", 1)},
	} {
		_, err := tbl.Select(TableSelectOption{LookupPrefixes: []*apiutil.LookupPrefix{key}})
		require.Error(t, err, name)
	}
}

func TestCheckNLRIFamily(t *testing.T) {
	require.NoError(t, CheckNLRIFamily(bgp.RF_IPv4_UC, ucNLRI("10.0.0.0/8")))
	require.NoError(t, CheckNLRIFamily(bgp.RF_IPv6_UC, ucNLRI("2001:db8::/32")))
	require.NoError(t, CheckNLRIFamily(bgp.RF_IPv4_MPLS, luNLRI("10.0.0.0/8")))
	require.Error(t, CheckNLRIFamily(bgp.RF_IPv6_MPLS, luNLRI("10.0.0.0/8")))
	require.Error(t, CheckNLRIFamily(bgp.RF_IPv4_MPLS, ucNLRI("10.0.0.0/8")))
	fs, err := bgp.NewFlowSpecUnicast(bgp.RF_FS_IPv4_UC, []bgp.FlowSpecComponentInterface{bgp.NewFlowSpecDestinationPrefix(ucNLRI("10.0.0.0/24"))})
	require.NoError(t, err)
	require.NoError(t, CheckNLRIFamily(bgp.RF_FS_IPv4_UC, fs))
	require.Error(t, CheckNLRIFamily(bgp.RF_IPv4_UC, fs))
	require.Error(t, CheckNLRIFamily(bgp.RF_FS_IPv6_UC, fs))

	// An IPv4 encapsulation endpoint serializes like an IPv4 host prefix
	// and like an IPv6 endpoint; only its type and address decide.
	encap4, err := bgp.NewEncapNLRI(netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	require.NoError(t, CheckNLRIFamily(bgp.RF_IPv4_ENCAP, encap4))
	require.Error(t, CheckNLRIFamily(bgp.RF_IPv6_ENCAP, encap4))
	require.Error(t, CheckNLRIFamily(bgp.RF_IPv4_UC, encap4))
	encap6, err := bgp.NewEncapNLRI(netip.MustParseAddr("2001:db8::1"))
	require.NoError(t, err)
	require.NoError(t, CheckNLRIFamily(bgp.RF_IPv6_ENCAP, encap6))
	require.Error(t, CheckNLRIFamily(bgp.RF_IPv4_ENCAP, encap6))

	// A unicast host prefix is not an encapsulation endpoint.
	require.Error(t, CheckNLRIFamily(bgp.RF_IPv4_ENCAP, ucNLRI("192.0.2.1/32")))

	tbl := selectTable(t, bgp.RF_IPv6_ENCAP)
	_, err = tbl.Select(TableSelectOption{LookupPrefixes: []*apiutil.LookupPrefix{{NLRI: encap4}}})
	require.Error(t, err, "Select refuses an IPv4 endpoint on the IPv6 table")
}
