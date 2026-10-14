package server

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// The tests in this file pin the next hop of a path in the API: in the
// paths that the API shows, and in the paths that AddPath and
// AddPathStream add. The order of the attributes is not checked.

// apiNexthop is the next hop part of the attributes of an api.Path.
type apiNexthop struct {
	// nextHop is the NEXT_HOP attribute, "" when there is none.
	nextHop string
	// mpFamily, mpNextHops and mpNLRIs are from MP_REACH_NLRI.
	// mpFamily is 0 when there is no MP_REACH_NLRI.
	mpFamily   bgp.Family
	mpNextHops []string
	mpNLRIs    []string
}

func apiNexthopOf(t *testing.T, attrs []*api.Attribute) apiNexthop {
	t.Helper()
	var n apiNexthop
	for _, a := range attrs {
		switch a := a.Attr.(type) {
		case *api.Attribute_NextHop:
			n.nextHop = a.NextHop.NextHop
		case *api.Attribute_MpReach:
			n.mpFamily = apiutil.ToFamily(a.MpReach.Family)
			n.mpNextHops = a.MpReach.NextHops
			nlris, err := apiutil.UnmarshalNLRIs(n.mpFamily, a.MpReach.Nlris)
			require.NoError(t, err)
			for _, nlri := range nlris {
				n.mpNLRIs = append(n.mpNLRIs, nlri.String())
			}
		}
	}
	return n
}

// apiNexthopOfPath returns the next hop of an api.Path made by toPathApi.
// It also checks that the binary form of the attributes gives the same
// next hop.
func apiNexthopOfPath(t *testing.T, path *apiutil.Path) apiNexthop {
	t.Helper()
	n := apiNexthopOf(t, toPathApi(path, false, false, false).Pattrs)

	native, err := apiutil.GetNativePathAttributes(toPathApi(path, true, false, false))
	require.NoError(t, err)
	attrs, err := apiutil.MarshalPathAttributes(native)
	require.NoError(t, err)
	assert.Equal(t, n, apiNexthopOf(t, attrs), "binary attributes")
	return n
}

func nexthopTestPrefix(t *testing.T, s string) bgp.NLRI {
	t.Helper()
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(s))
	require.NoError(t, err)
	return nlri
}

func nexthopTestVPNPrefix(t *testing.T, s string) bgp.NLRI {
	t.Helper()
	rd := bgp.NewRouteDistinguisherTwoOctetAS(65000, 100)
	nlri, err := bgp.NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix(s), *bgp.NewMPLSLabelStack(100), rd)
	require.NoError(t, err)
	return nlri
}

func nexthopTestFlowSpec(t *testing.T, s string) bgp.NLRI {
	t.Helper()
	nlri, err := bgp.NewFlowSpecUnicast(bgp.RF_FS_IPv4_UC, []bgp.FlowSpecComponentInterface{
		bgp.NewFlowSpecDestinationPrefix(nexthopTestPrefix(t, s).(*bgp.IPAddrPrefix)),
	})
	require.NoError(t, err)
	return nlri
}

func nexthopTestAttrs() []bgp.PathAttributeInterface {
	return []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65100})}),
	}
}

// A received path shows the next hops it was received with. A path from
// MP_REACH_NLRI shows an MP_REACH_NLRI with its own NLRI only.
func TestNexthopReceivedPathInAPI(t *testing.T) {
	peer := &table.PeerInfo{
		AS:      65100,
		LocalAS: 65000,
		ID:      netip.MustParseAddr("10.0.0.2"),
		Address: netip.MustParseAddr("10.0.0.2"),
	}

	v4 := []bgp.NLRI{nexthopTestPrefix(t, "10.1.0.0/24"), nexthopTestPrefix(t, "10.2.0.0/24")}
	v6 := []bgp.NLRI{nexthopTestPrefix(t, "2001:db8:1::/64"), nexthopTestPrefix(t, "2001:db8:2::/64")}
	vpn4 := []bgp.NLRI{nexthopTestVPNPrefix(t, "10.1.0.0/24"), nexthopTestVPNPrefix(t, "10.2.0.0/24")}
	fs4 := []bgp.NLRI{nexthopTestFlowSpec(t, "10.1.0.0/24")}

	for _, tt := range []struct {
		name     string
		family   bgp.Family
		nlris    []bgp.NLRI
		nexthops []string // in MP_REACH_NLRI, or NEXT_HOP when inField
		inField  bool     // the NLRIs are in the NLRI field
		want     apiNexthop
	}{
		{
			name:     "IPv4 unicast in the NLRI field",
			family:   bgp.RF_IPv4_UC,
			nlris:    v4,
			nexthops: []string{"192.0.2.1"},
			inField:  true,
			want:     apiNexthop{nextHop: "192.0.2.1"},
		},
		{
			name:     "IPv4 unicast in MP_REACH_NLRI with an IPv4 next hop",
			family:   bgp.RF_IPv4_UC,
			nlris:    v4,
			nexthops: []string{"192.0.2.1"},
			want:     apiNexthop{mpFamily: bgp.RF_IPv4_UC, mpNextHops: []string{"192.0.2.1"}},
		},
		{
			name:     "IPv4 unicast with an IPv6 global and link-local next hop (RFC 5549)",
			family:   bgp.RF_IPv4_UC,
			nlris:    v4,
			nexthops: []string{"2001:db8::1", "fe80::1"},
			want:     apiNexthop{mpFamily: bgp.RF_IPv4_UC, mpNextHops: []string{"2001:db8::1", "fe80::1"}},
		},
		{
			name:     "IPv6 unicast with a global next hop",
			family:   bgp.RF_IPv6_UC,
			nlris:    v6,
			nexthops: []string{"2001:db8::1"},
			want:     apiNexthop{mpFamily: bgp.RF_IPv6_UC, mpNextHops: []string{"2001:db8::1"}},
		},
		{
			name:     "IPv6 unicast with a global and link-local next hop",
			family:   bgp.RF_IPv6_UC,
			nlris:    v6,
			nexthops: []string{"2001:db8::1", "fe80::1"},
			want:     apiNexthop{mpFamily: bgp.RF_IPv6_UC, mpNextHops: []string{"2001:db8::1", "fe80::1"}},
		},
		{
			name:     "IPv6 unicast with an unspecified global and a link-local next hop",
			family:   bgp.RF_IPv6_UC,
			nlris:    v6,
			nexthops: []string{"::", "fe80::1"},
			want:     apiNexthop{mpFamily: bgp.RF_IPv6_UC, mpNextHops: []string{"::", "fe80::1"}},
		},
		{
			name:     "IPv6 unicast with a link-local next hop alone",
			family:   bgp.RF_IPv6_UC,
			nlris:    v6,
			nexthops: []string{"fe80::1"},
			want:     apiNexthop{mpFamily: bgp.RF_IPv6_UC, mpNextHops: []string{"fe80::1"}},
		},
		{
			name:     "IPv6 unicast with an IPv4 next hop",
			family:   bgp.RF_IPv6_UC,
			nlris:    v6,
			nexthops: []string{"192.0.2.1"},
			want:     apiNexthop{mpFamily: bgp.RF_IPv6_UC, mpNextHops: []string{"192.0.2.1"}},
		},
		{
			name:     "IPv4 VPN",
			family:   bgp.RF_IPv4_VPN,
			nlris:    vpn4,
			nexthops: []string{"192.0.2.1"},
			want:     apiNexthop{mpFamily: bgp.RF_IPv4_VPN, mpNextHops: []string{"192.0.2.1"}},
		},
		{
			name:   "IPv4 FlowSpec without a next hop",
			family: bgp.RF_FS_IPv4_UC,
			nlris:  fs4,
			want:   apiNexthop{mpFamily: bgp.RF_FS_IPv4_UC},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			nexthops := make([]netip.Addr, 0, len(tt.nexthops))
			for _, s := range tt.nexthops {
				nexthops = append(nexthops, netip.MustParseAddr(s))
			}
			pathNLRIs := make([]bgp.PathNLRI, 0, len(tt.nlris))
			for _, nlri := range tt.nlris {
				pathNLRIs = append(pathNLRIs, bgp.PathNLRI{NLRI: nlri})
			}

			attrs := nexthopTestAttrs()
			var msg *bgp.BGPMessage
			if tt.inField {
				nh, err := bgp.NewPathAttributeNextHop(nexthops[0])
				require.NoError(t, err)
				msg = bgp.NewBGPUpdateMessage(nil, append(attrs, nh), pathNLRIs)
			} else {
				reach, err := bgp.NewPathAttributeMpReachNLRI(tt.family, pathNLRIs, nexthops...)
				require.NoError(t, err)
				msg = bgp.NewBGPUpdateMessage(nil, append(attrs, reach), nil)
			}
			b, err := msg.Serialize()
			require.NoError(t, err)
			msg, err = bgp.ParseBGPMessage(b)
			require.NoError(t, err)

			paths := table.ProcessMessage(msg, peer, time.Now(), false)
			require.Len(t, paths, len(tt.nlris))
			for _, p := range paths {
				want := tt.want
				if want.mpFamily != 0 {
					want.mpNLRIs = []string{p.GetNlri().String()}
				}
				assert.Equal(t, want, apiNexthopOfPath(t, toPathApiUtil(p)), "%s", p.GetNlri())
			}
		})
	}
}

// AddPath and AddPathStream put the same next hop on a path. They use two
// functions to convert the path, apiutil2Path and api2Path.
func TestNexthopAddPath(t *testing.T) {
	const vrfName = "vrf1"

	mpReach := func(family bgp.Family, nlri bgp.NLRI, nexthops ...string) *api.Attribute {
		f := apiutil.ToApiFamily(family.Afi(), family.Safi())
		n, err := apiutil.MarshalNLRI(nlri)
		require.NoError(t, err)
		return &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: &api.MpReachNLRIAttribute{
			Family:   f,
			NextHops: nexthops,
			Nlris:    []*api.NLRI{n},
		}}}
	}
	nextHop := func(s string) *api.Attribute {
		return &api.Attribute{Attr: &api.Attribute_NextHop{NextHop: &api.NextHopAttribute{NextHop: s}}}
	}

	v4 := nexthopTestPrefix(t, "10.1.0.0/24")
	v6 := nexthopTestPrefix(t, "2001:db8:1::/64")
	fs4 := nexthopTestFlowSpec(t, "10.1.0.0/24")
	rd := bgp.NewRouteDistinguisherTwoOctetAS(65000, 100)
	vpn4, err := bgp.NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix("10.1.0.0/24"), *bgp.NewMPLSLabelStack(), rd)
	require.NoError(t, err)
	vpn6, err := bgp.NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix("2001:db8:1::/64"), *bgp.NewMPLSLabelStack(), rd)
	require.NoError(t, err)

	for _, tt := range []struct {
		name    string
		family  bgp.Family
		nlri    bgp.NLRI
		nexthop *api.Attribute // nil for none
		vrf     bool
		wantErr bool
		// want is the path in the global table.
		want apiNexthop
		// wantVrf is the path in the VRF table. It is not checked when
		// it is nil.
		wantVrf *apiNexthop
	}{
		{
			name:    "IPv4 unicast with NEXT_HOP",
			family:  bgp.RF_IPv4_UC,
			nlri:    v4,
			nexthop: nextHop("192.0.2.1"),
			want:    apiNexthop{nextHop: "192.0.2.1"},
		},
		{
			// It is stored as NEXT_HOP.
			name:    "IPv4 unicast with MP_REACH_NLRI and an IPv4 next hop",
			family:  bgp.RF_IPv4_UC,
			nlri:    v4,
			nexthop: mpReach(bgp.RF_IPv4_UC, v4, "192.0.2.1"),
			want:    apiNexthop{nextHop: "192.0.2.1"},
		},
		{
			name:    "IPv4 unicast with an IPv6 next hop (RFC 5549)",
			family:  bgp.RF_IPv4_UC,
			nlri:    v4,
			nexthop: mpReach(bgp.RF_IPv4_UC, v4, "2001:db8::1"),
			want:    apiNexthop{mpFamily: bgp.RF_IPv4_UC, mpNextHops: []string{"2001:db8::1"}, mpNLRIs: []string{v4.String()}},
		},
		{
			name:    "IPv6 unicast with a global next hop",
			family:  bgp.RF_IPv6_UC,
			nlri:    v6,
			nexthop: mpReach(bgp.RF_IPv6_UC, v6, "2001:db8::1"),
			want:    apiNexthop{mpFamily: bgp.RF_IPv6_UC, mpNextHops: []string{"2001:db8::1"}, mpNLRIs: []string{v6.String()}},
		},
		{
			// The link-local next hop is dropped.
			name:    "IPv6 unicast with a global and link-local next hop",
			family:  bgp.RF_IPv6_UC,
			nlri:    v6,
			nexthop: mpReach(bgp.RF_IPv6_UC, v6, "2001:db8::1", "fe80::1"),
			want:    apiNexthop{mpFamily: bgp.RF_IPv6_UC, mpNextHops: []string{"2001:db8::1"}, mpNLRIs: []string{v6.String()}},
		},
		{
			name:    "IPv4 FlowSpec without a next hop",
			family:  bgp.RF_FS_IPv4_UC,
			nlri:    fs4,
			nexthop: mpReach(bgp.RF_FS_IPv4_UC, fs4),
			want:    apiNexthop{mpFamily: bgp.RF_FS_IPv4_UC, mpNLRIs: []string{fs4.String()}},
		},
		{
			name:    "IPv4 unicast without a next hop",
			family:  bgp.RF_IPv4_UC,
			nlri:    v4,
			wantErr: true,
		},
		{
			name:    "IPv4 unicast in a VRF",
			family:  bgp.RF_IPv4_UC,
			nlri:    v4,
			nexthop: nextHop("192.0.2.1"),
			vrf:     true,
			want:    apiNexthop{mpFamily: bgp.RF_IPv4_VPN, mpNextHops: []string{"192.0.2.1"}, mpNLRIs: []string{vpn4.String()}},
			wantVrf: &apiNexthop{nextHop: "192.0.2.1"},
		},
		{
			// The VRF table is not checked. ToLocal keeps the
			// MP_REACH_NLRI of the IPv6 VPN path, so the API shows
			// the VPN family and NLRI for an IPv6 unicast path.
			name:    "IPv6 unicast in a VRF",
			family:  bgp.RF_IPv6_UC,
			nlri:    v6,
			nexthop: mpReach(bgp.RF_IPv6_UC, v6, "2001:db8::1"),
			vrf:     true,
			want:    apiNexthop{mpFamily: bgp.RF_IPv6_VPN, mpNextHops: []string{"2001:db8::1"}, mpNLRIs: []string{vpn6.String()}},
		},
	} {
		n, err := apiutil.MarshalNLRI(tt.nlri)
		require.NoError(t, err)
		pattrs, err := apiutil.MarshalPathAttributes(nexthopTestAttrs())
		require.NoError(t, err)
		if tt.nexthop != nil {
			pattrs = append(pattrs, tt.nexthop)
		}
		path := &api.Path{
			Family: apiutil.ToApiFamily(tt.family.Afi(), tt.family.Safi()),
			Nlri:   n,
			Pattrs: pattrs,
		}
		vrfID := ""
		tableType := api.TableType_TABLE_TYPE_GLOBAL
		if tt.vrf {
			vrfID = vrfName
			tableType = api.TableType_TABLE_TYPE_VRF
		}

		for _, add := range []struct {
			name string
			fn   func(s *BgpServer) error
		}{
			{
				name: "AddPath",
				fn: func(s *BgpServer) error {
					p, err := api2apiutilPath(path)
					require.NoError(t, err)
					_, err = s.AddPath(apiutil.AddPathRequest{VRFID: vrfID, Paths: []*apiutil.Path{p}})
					return err
				},
			},
			{
				name: "AddPathStream",
				fn: func(s *BgpServer) error {
					p, err := api2Path(tableType, path, false)
					if err != nil {
						return err
					}
					return s.addPathStream(vrfID, []*table.Path{p})
				},
			},
		} {
			t.Run(tt.name+"/"+add.name, func(t *testing.T) {
				s := runNewServer(t, 65000, "10.0.0.1", -1)
				defer s.StopBgp(context.Background(), &api.StopBgpRequest{})
				if tt.vrf {
					addVrf(t, s, vrfName, "65000:100", []string{"65000:200"}, []string{"65000:200"}, 1)
				}

				err := add.fn(s)
				if tt.wantErr {
					assert.Error(t, err)
					return
				}
				require.NoError(t, err)

				list := func(tableType api.TableType, name string, family bgp.Family) []apiNexthop {
					var l []apiNexthop
					err := s.ListPath(apiutil.ListPathRequest{
						TableType: tableType,
						Name:      name,
						Family:    family,
					}, func(_ bgp.NLRI, paths []*apiutil.Path) {
						for _, p := range paths {
							l = append(l, apiNexthopOfPath(t, p))
						}
					})
					require.NoError(t, err)
					return l
				}

				globalFamily := tt.family
				if tt.vrf {
					globalFamily = tt.want.mpFamily
				}
				assert.Equal(t, []apiNexthop{tt.want}, list(api.TableType_TABLE_TYPE_GLOBAL, "", globalFamily))
				if tt.wantVrf != nil {
					assert.Equal(t, []apiNexthop{*tt.wantVrf}, list(api.TableType_TABLE_TYPE_VRF, vrfName, tt.family))
				}
			})
		}
	}
}
