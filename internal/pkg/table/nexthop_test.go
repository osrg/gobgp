package table

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests in this file pin the next hop of a path at each point where
// it enters or leaves the table. They build paths with ProcessMessage and
// check only GetNexthop and the encoded UPDATE, never the attribute list
// of the Path, so they do not depend on how the Path stores the next hop.
// The order of the attributes in an UPDATE is not checked.

// sentRoute is how one NLRI was advertised.
type sentRoute struct {
	family bgp.Family
	// viaMP is true when the NLRI is in MP_REACH_NLRI, and false when
	// it is in the NLRI field with a NEXT_HOP attribute.
	viaMP     bool
	nexthop   netip.Addr
	linkLocal netip.Addr
}

func wireRoundTrip(t *testing.T, msg *bgp.BGPMessage, options ...*bgp.MarshallingOption) *bgp.BGPMessage {
	t.Helper()
	b, err := msg.Serialize(options...)
	require.NoError(t, err)
	m, err := bgp.ParseBGPMessage(b, options...)
	require.NoError(t, err)
	return m
}

// receive returns the paths that the table makes from an UPDATE with
// nlris in the NLRI field and attrs. The UPDATE goes through the wire
// format first, like a received one. A nil source makes local paths.
func receive(t *testing.T, source *PeerInfo, nlris []bgp.PathNLRI, attrs []bgp.PathAttributeInterface, options ...*bgp.MarshallingOption) []*Path {
	t.Helper()
	msg := wireRoundTrip(t, bgp.NewBGPUpdateMessage(nil, attrs, nlris), options...)
	paths := ProcessMessage(msg, source, time.Now(), false)
	require.NotEmpty(t, paths)
	return paths
}

// sentRoutes decodes msgs from the wire format and returns the announced
// NLRIs, keyed by the NLRI string and the path ID.
func sentRoutes(t *testing.T, msgs []*bgp.BGPMessage, options ...*bgp.MarshallingOption) map[string]sentRoute {
	t.Helper()
	routes := make(map[string]sentRoute)
	add := func(nlri bgp.PathNLRI, r sentRoute) {
		k := routeKey(nlri.NLRI, nlri.ID)
		_, dup := routes[k]
		assert.False(t, dup, "%s is announced twice", k)
		routes[k] = r
	}
	for _, msg := range msgs {
		u := wireRoundTrip(t, msg, options...).Body.(*bgp.BGPUpdate)
		var nexthop *bgp.PathAttributeNextHop
		var reach *bgp.PathAttributeMpReachNLRI
		for _, a := range u.PathAttributes {
			switch a := a.(type) {
			case *bgp.PathAttributeNextHop:
				nexthop = a
			case *bgp.PathAttributeMpReachNLRI:
				reach = a
			}
		}
		if len(u.NLRI) > 0 {
			require.NotNil(t, nexthop, "NLRI field without NEXT_HOP")
			for _, nlri := range u.NLRI {
				add(nlri, sentRoute{family: bgp.RF_IPv4_UC, nexthop: nexthop.Value})
			}
		} else {
			assert.Nil(t, nexthop, "NEXT_HOP without NLRI in the NLRI field")
		}
		if reach != nil {
			family := bgp.NewFamily(reach.AFI, reach.SAFI)
			for _, nlri := range reach.Value {
				add(nlri, sentRoute{
					family:    family,
					viaMP:     true,
					nexthop:   reach.Nexthop,
					linkLocal: reach.LinkLocalNexthop,
				})
			}
		}
	}
	return routes
}

func routeKey(nlri bgp.NLRI, id uint32) string {
	return fmt.Sprintf("%s id %d", nlri, id)
}

// wantRoutes returns what sentRoutes returns when every path in paths is
// advertised as r.
func wantRoutes(paths []*Path, r sentRoute) map[string]sentRoute {
	m := make(map[string]sentRoute, len(paths))
	for _, p := range paths {
		m[routeKey(p.GetNlri(), 0)] = r
	}
	return m
}

func nexthopTestAttrs() []bgp.PathAttributeInterface {
	return []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
		createAsPathAttribute([]uint32{65100}),
	}
}

func withNextHop(t *testing.T, nexthop string) []bgp.PathAttributeInterface {
	t.Helper()
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr(nexthop))
	require.NoError(t, err)
	return append(nexthopTestAttrs(), nh)
}

func withMpReach(t *testing.T, family bgp.Family, nlris []bgp.PathNLRI, nexthops ...string) []bgp.PathAttributeInterface {
	t.Helper()
	addrs := make([]netip.Addr, 0, len(nexthops))
	for _, nh := range nexthops {
		addrs = append(addrs, netip.MustParseAddr(nh))
	}
	reach, err := bgp.NewPathAttributeMpReachNLRI(family, nlris, addrs...)
	require.NoError(t, err)
	return append(nexthopTestAttrs(), reach)
}

func prefixNLRIs(t *testing.T, prefixes ...string) []bgp.PathNLRI {
	t.Helper()
	l := make([]bgp.PathNLRI, 0, len(prefixes))
	for _, s := range prefixes {
		nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(s))
		require.NoError(t, err)
		l = append(l, bgp.PathNLRI{NLRI: nlri})
	}
	return l
}

func vpnNLRIs(t *testing.T, prefixes ...string) []bgp.PathNLRI {
	t.Helper()
	rd := bgp.NewRouteDistinguisherTwoOctetAS(65000, 100)
	l := make([]bgp.PathNLRI, 0, len(prefixes))
	for _, s := range prefixes {
		nlri, err := bgp.NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix(s), *bgp.NewMPLSLabelStack(100), rd)
		require.NoError(t, err)
		l = append(l, bgp.PathNLRI{NLRI: nlri})
	}
	return l
}

func flowSpecNLRIs(t *testing.T, prefix string) []bgp.PathNLRI {
	t.Helper()
	dst, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	require.NoError(t, err)
	nlri, err := bgp.NewFlowSpecUnicast(bgp.RF_FS_IPv4_UC, []bgp.FlowSpecComponentInterface{bgp.NewFlowSpecDestinationPrefix(dst)})
	require.NoError(t, err)
	return []bgp.PathNLRI{{NLRI: nlri}}
}

func flowSpecVPNNLRIs(t *testing.T, prefix string) []bgp.PathNLRI {
	t.Helper()
	dst, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	require.NoError(t, err)
	nlri, err := bgp.NewFlowSpecVPN(bgp.RF_FS_IPv4_VPN, bgp.NewRouteDistinguisherTwoOctetAS(65000, 100), []bgp.FlowSpecComponentInterface{bgp.NewFlowSpecDestinationPrefix(dst)})
	require.NoError(t, err)
	return []bgp.PathNLRI{{NLRI: nlri}}
}

// A received path is advertised with the next hops it was received with
// when nothing rewrites them.
func TestNexthopReceiveAndSend(t *testing.T) {
	v4 := prefixNLRIs(t, "10.1.0.0/24", "10.2.0.0/24")
	v6 := prefixNLRIs(t, "2001:db8:1::/64", "2001:db8:2::/64")
	vpn4 := vpnNLRIs(t, "10.1.0.0/24", "10.2.0.0/24")
	vpn6 := vpnNLRIs(t, "2001:db8:1::/64", "2001:db8:2::/64")
	fs4 := flowSpecNLRIs(t, "10.1.0.0/24")

	for _, tt := range []struct {
		name        string
		nlris       []bgp.PathNLRI // the NLRI field
		attrs       []bgp.PathAttributeInterface
		wantNexthop string // GetNexthop, "" for an invalid address
		want        sentRoute
	}{
		{
			name:        "IPv4 unicast in the NLRI field",
			nlris:       v4,
			attrs:       withNextHop(t, "192.0.2.1"),
			wantNexthop: "192.0.2.1",
			want:        sentRoute{family: bgp.RF_IPv4_UC, nexthop: netip.MustParseAddr("192.0.2.1")},
		},
		{
			// It goes out in the NLRI field with NEXT_HOP.
			name:        "IPv4 unicast in MP_REACH_NLRI with an IPv4 next hop",
			attrs:       withMpReach(t, bgp.RF_IPv4_UC, v4, "192.0.2.1"),
			wantNexthop: "192.0.2.1",
			want:        sentRoute{family: bgp.RF_IPv4_UC, nexthop: netip.MustParseAddr("192.0.2.1")},
		},
		{
			name:        "IPv4 unicast with an IPv6 next hop (RFC 5549)",
			attrs:       withMpReach(t, bgp.RF_IPv4_UC, v4, "2001:db8::1"),
			wantNexthop: "2001:db8::1",
			want:        sentRoute{family: bgp.RF_IPv4_UC, viaMP: true, nexthop: netip.MustParseAddr("2001:db8::1")},
		},
		{
			name:        "IPv4 unicast with an IPv6 global and link-local next hop (RFC 5549)",
			attrs:       withMpReach(t, bgp.RF_IPv4_UC, v4, "2001:db8::1", "fe80::1"),
			wantNexthop: "2001:db8::1",
			want: sentRoute{
				family:    bgp.RF_IPv4_UC,
				viaMP:     true,
				nexthop:   netip.MustParseAddr("2001:db8::1"),
				linkLocal: netip.MustParseAddr("fe80::1"),
			},
		},
		{
			name:        "IPv6 unicast with a global next hop",
			attrs:       withMpReach(t, bgp.RF_IPv6_UC, v6, "2001:db8::1"),
			wantNexthop: "2001:db8::1",
			want:        sentRoute{family: bgp.RF_IPv6_UC, viaMP: true, nexthop: netip.MustParseAddr("2001:db8::1")},
		},
		{
			name:        "IPv6 unicast with a global and link-local next hop",
			attrs:       withMpReach(t, bgp.RF_IPv6_UC, v6, "2001:db8::1", "fe80::1"),
			wantNexthop: "2001:db8::1",
			want: sentRoute{
				family:    bgp.RF_IPv6_UC,
				viaMP:     true,
				nexthop:   netip.MustParseAddr("2001:db8::1"),
				linkLocal: netip.MustParseAddr("fe80::1"),
			},
		},
		{
			// GetNexthop returns the link-local address, the only one
			// that can be used. The received form is sent as it is.
			name:        "IPv6 unicast with an unspecified global and a link-local next hop",
			attrs:       withMpReach(t, bgp.RF_IPv6_UC, v6, "::", "fe80::1"),
			wantNexthop: "fe80::1",
			want: sentRoute{
				family:    bgp.RF_IPv6_UC,
				viaMP:     true,
				nexthop:   netip.MustParseAddr("::"),
				linkLocal: netip.MustParseAddr("fe80::1"),
			},
		},
		{
			name:        "IPv6 unicast with a link-local next hop alone",
			attrs:       withMpReach(t, bgp.RF_IPv6_UC, v6, "fe80::1"),
			wantNexthop: "fe80::1",
			want:        sentRoute{family: bgp.RF_IPv6_UC, viaMP: true, nexthop: netip.MustParseAddr("fe80::1")},
		},
		{
			// The IPv4 address goes on the wire in the IPv4-mapped
			// form and is unmapped when it is decoded.
			name:        "IPv6 unicast with an IPv4 next hop",
			attrs:       withMpReach(t, bgp.RF_IPv6_UC, v6, "192.0.2.1"),
			wantNexthop: "192.0.2.1",
			want:        sentRoute{family: bgp.RF_IPv6_UC, viaMP: true, nexthop: netip.MustParseAddr("192.0.2.1")},
		},
		{
			name:        "IPv4 VPN",
			attrs:       withMpReach(t, bgp.RF_IPv4_VPN, vpn4, "192.0.2.1"),
			wantNexthop: "192.0.2.1",
			want:        sentRoute{family: bgp.RF_IPv4_VPN, viaMP: true, nexthop: netip.MustParseAddr("192.0.2.1")},
		},
		{
			name:        "IPv6 VPN",
			attrs:       withMpReach(t, bgp.RF_IPv6_VPN, vpn6, "2001:db8::1"),
			wantNexthop: "2001:db8::1",
			want:        sentRoute{family: bgp.RF_IPv6_VPN, viaMP: true, nexthop: netip.MustParseAddr("2001:db8::1")},
		},
		{
			name:  "IPv4 FlowSpec without a next hop",
			attrs: withMpReach(t, bgp.RF_FS_IPv4_UC, fs4),
			want:  sentRoute{family: bgp.RF_FS_IPv4_UC, viaMP: true},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			paths := receive(t, peerR1(), tt.nlris, tt.attrs)

			var wantNexthop netip.Addr
			if tt.wantNexthop != "" {
				wantNexthop = netip.MustParseAddr(tt.wantNexthop)
			}
			for _, p := range paths {
				assert.Equal(t, wantNexthop, p.GetNexthop(), "%s", p.GetNlri())
			}
			assert.Equal(t, wantRoutes(paths, tt.want), sentRoutes(t, CreateUpdateMsgFromPaths(paths)))
		})
	}
}

// With ADD-PATH the path IDs go out with the next hops of their paths.
func TestNexthopReceiveAndSendAddPath(t *testing.T) {
	opt := &bgp.MarshallingOption{AddPath: map[bgp.Family]bgp.BGPAddPathMode{
		bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_BOTH,
		bgp.RF_IPv6_UC: bgp.BGP_ADD_PATH_BOTH,
	}}

	withID := func(l []bgp.PathNLRI, id uint32) []bgp.PathNLRI {
		for i := range l {
			l[i].ID = id
		}
		return l
	}

	var paths []*Path
	paths = append(paths, receive(t, peerR1(), withID(prefixNLRIs(t, "10.1.0.0/24"), 1), withNextHop(t, "192.0.2.1"), opt)...)
	paths = append(paths, receive(t, peerR1(), withID(prefixNLRIs(t, "10.1.0.0/24"), 2), withNextHop(t, "192.0.2.2"), opt)...)
	paths = append(paths, receive(t, peerR1(), nil, withMpReach(t, bgp.RF_IPv6_UC, withID(prefixNLRIs(t, "2001:db8:1::/64"), 1), "2001:db8::1", "fe80::1"), opt)...)
	paths = append(paths, receive(t, peerR1(), nil, withMpReach(t, bgp.RF_IPv6_UC, withID(prefixNLRIs(t, "2001:db8:1::/64"), 2), "2001:db8::2"), opt)...)

	v4, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.1.0.0/24"))
	v6, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:db8:1::/64"))
	want := map[string]sentRoute{
		routeKey(v4, 1): {family: bgp.RF_IPv4_UC, nexthop: netip.MustParseAddr("192.0.2.1")},
		routeKey(v4, 2): {family: bgp.RF_IPv4_UC, nexthop: netip.MustParseAddr("192.0.2.2")},
		routeKey(v6, 1): {
			family:    bgp.RF_IPv6_UC,
			viaMP:     true,
			nexthop:   netip.MustParseAddr("2001:db8::1"),
			linkLocal: netip.MustParseAddr("fe80::1"),
		},
		routeKey(v6, 2): {family: bgp.RF_IPv6_UC, viaMP: true, nexthop: netip.MustParseAddr("2001:db8::2")},
	}
	assert.Equal(t, want, sentRoutes(t, CreateUpdateMsgFromAdjRIBInPaths(paths, opt), opt))
}

// The next hop that UpdatePathAttrs puts on a path for the peer it is
// advertised to.
func TestNexthopUpdatePathAttrs(t *testing.T) {
	global := &oc.Global{Config: oc.GlobalConfig{As: 65000, RouterId: netip.MustParseAddr("10.0.0.1")}}

	ebgp4 := &PeerInfo{
		AS:           65200,
		LocalAS:      65000,
		PeerType:     oc.PEER_TYPE_EXTERNAL,
		Address:      netip.MustParseAddr("10.0.0.2"),
		LocalAddress: netip.MustParseAddr("10.0.0.1"),
	}
	ebgp6 := &PeerInfo{
		AS:           65200,
		LocalAS:      65000,
		PeerType:     oc.PEER_TYPE_EXTERNAL,
		Address:      netip.MustParseAddr("2001:db8::fe"),
		LocalAddress: netip.MustParseAddr("2001:db8::ff"),
	}
	ibgp4 := &PeerInfo{
		AS:           65000,
		LocalAS:      65000,
		PeerType:     oc.PEER_TYPE_INTERNAL,
		Address:      netip.MustParseAddr("10.0.0.2"),
		LocalAddress: netip.MustParseAddr("10.0.0.1"),
	}
	ibgp6 := &PeerInfo{
		AS:           65000,
		LocalAS:      65000,
		PeerType:     oc.PEER_TYPE_INTERNAL,
		Address:      netip.MustParseAddr("2001:db8::fe"),
		LocalAddress: netip.MustParseAddr("2001:db8::ff"),
	}

	v4 := prefixNLRIs(t, "10.1.0.0/24")
	v6 := prefixNLRIs(t, "2001:db8:1::/64")

	for _, tt := range []struct {
		name   string
		source *PeerInfo // nil for a local path
		nlris  []bgp.PathNLRI
		attrs  []bgp.PathAttributeInterface
		info   *PeerInfo
		want   sentRoute
	}{
		{
			name:   "IPv4 to an eBGP peer",
			source: peerR1(),
			nlris:  v4,
			attrs:  withNextHop(t, "192.0.2.1"),
			info:   ebgp4,
			want:   sentRoute{family: bgp.RF_IPv4_UC, nexthop: netip.MustParseAddr("10.0.0.1")},
		},
		{
			// The IPv6 local address makes it an RFC 5549 route.
			name:   "IPv4 to an eBGP peer over IPv6",
			source: peerR1(),
			nlris:  v4,
			attrs:  withNextHop(t, "192.0.2.1"),
			info:   ebgp6,
			want:   sentRoute{family: bgp.RF_IPv4_UC, viaMP: true, nexthop: netip.MustParseAddr("2001:db8::ff")},
		},
		{
			name:   "IPv6 with a link-local next hop to an eBGP peer",
			source: peerR1(),
			attrs:  withMpReach(t, bgp.RF_IPv6_UC, v6, "2001:db8::1", "fe80::1"),
			info:   ebgp6,
			want:   sentRoute{family: bgp.RF_IPv6_UC, viaMP: true, nexthop: netip.MustParseAddr("2001:db8::ff")},
		},
		{
			name:   "IPv4 to an iBGP peer",
			source: peerR1(),
			nlris:  v4,
			attrs:  withNextHop(t, "192.0.2.1"),
			info:   ibgp4,
			want:   sentRoute{family: bgp.RF_IPv4_UC, nexthop: netip.MustParseAddr("192.0.2.1")},
		},
		{
			// The peer is not on the link of fe80::1, so the
			// link-local part is dropped (RFC 2545 3).
			name:   "IPv6 with a link-local next hop to an iBGP peer",
			source: peerR1(),
			attrs:  withMpReach(t, bgp.RF_IPv6_UC, v6, "2001:db8::1", "fe80::1"),
			info:   ibgp6,
			want:   sentRoute{family: bgp.RF_IPv6_UC, viaMP: true, nexthop: netip.MustParseAddr("2001:db8::1")},
		},
		{
			name:  "local IPv4 path with an unspecified next hop to an iBGP peer",
			nlris: v4,
			attrs: withNextHop(t, "0.0.0.0"),
			info:  ibgp4,
			want:  sentRoute{family: bgp.RF_IPv4_UC, nexthop: netip.MustParseAddr("10.0.0.1")},
		},
		{
			name:  "local IPv6 path with an unspecified next hop to an iBGP peer",
			attrs: withMpReach(t, bgp.RF_IPv6_UC, v6, "::"),
			info:  ibgp6,
			want:  sentRoute{family: bgp.RF_IPv6_UC, viaMP: true, nexthop: netip.MustParseAddr("2001:db8::ff")},
		},
		{
			name:  "local IPv4 path with a next hop to an eBGP peer",
			nlris: v4,
			attrs: withNextHop(t, "192.0.2.1"),
			info:  ebgp4,
			want:  sentRoute{family: bgp.RF_IPv4_UC, nexthop: netip.MustParseAddr("192.0.2.1")},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			paths := receive(t, tt.source, tt.nlris, tt.attrs)
			sent := make([]*Path, 0, len(paths))
			for _, p := range paths {
				sent = append(sent, UpdatePathAttrs(logger, global, tt.info, p))
			}
			assert.Equal(t, wantRoutes(sent, tt.want), sentRoutes(t, CreateUpdateMsgFromPaths(sent)))
			for _, p := range sent {
				assert.Equal(t, tt.want.nexthop, p.GetNexthop(), "%s", p.GetNlri())
			}
		})
	}
}

// Clone keeps the next hop, and a withdrawal made by Clone carries none.
func TestNexthopClone(t *testing.T) {
	paths := receive(t, peerR1(), nil, withMpReach(t, bgp.RF_IPv6_UC, prefixNLRIs(t, "2001:db8:1::/64"), "2001:db8::1", "fe80::1"))
	require.Len(t, paths, 1)

	c := paths[0].Clone(false)
	assert.Equal(t, netip.MustParseAddr("2001:db8::1"), c.GetNexthop())
	assert.Equal(t, wantRoutes(paths, sentRoute{
		family:    bgp.RF_IPv6_UC,
		viaMP:     true,
		nexthop:   netip.MustParseAddr("2001:db8::1"),
		linkLocal: netip.MustParseAddr("fe80::1"),
	}), sentRoutes(t, CreateUpdateMsgFromPaths([]*Path{c})))

	w := paths[0].Clone(true)
	assert.Empty(t, sentRoutes(t, CreateUpdateMsgFromPaths([]*Path{w})))
}

func nexthopTestVrf(t *testing.T) *Vrf {
	t.Helper()
	rd, err := bgp.ParseRouteDistinguisher("65000:100")
	require.NoError(t, err)
	_, rt, err := parseRDRT("65000:200")
	require.NoError(t, err)
	return &Vrf{Name: "vrf1", Rd: rd, ExportRt: []bgp.ExtendedCommunityInterface{rt}, MplsLabel: 100}
}

// A path that a VRF peer sends is put in the global table by ToGlobal
// with its next hop.
func TestNexthopToGlobal(t *testing.T) {
	vrf := nexthopTestVrf(t)

	for _, tt := range []struct {
		name  string
		nlris []bgp.PathNLRI
		attrs []bgp.PathAttributeInterface
		want  sentRoute
	}{
		{
			name:  "IPv4 unicast",
			nlris: prefixNLRIs(t, "10.1.0.0/24"),
			attrs: withNextHop(t, "192.0.2.1"),
			want:  sentRoute{family: bgp.RF_IPv4_VPN, viaMP: true, nexthop: netip.MustParseAddr("192.0.2.1")},
		},
		{
			// The link-local part is dropped.
			name:  "IPv6 unicast",
			attrs: withMpReach(t, bgp.RF_IPv6_UC, prefixNLRIs(t, "2001:db8:1::/64"), "2001:db8::1", "fe80::1"),
			want:  sentRoute{family: bgp.RF_IPv6_VPN, viaMP: true, nexthop: netip.MustParseAddr("2001:db8::1")},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			paths := receive(t, peerR1(), tt.nlris, tt.attrs)
			global := make([]*Path, 0, len(paths))
			for _, p := range paths {
				g := p.ToGlobal(vrf)
				assert.Equal(t, tt.want.nexthop, g.GetNexthop())
				global = append(global, g)
			}
			assert.Equal(t, wantRoutes(global, tt.want), sentRoutes(t, CreateUpdateMsgFromPaths(global)))
		})
	}
}

// A local path added to a VRF is put in the global table by ToGlobalPath
// with its next hop.
func TestNexthopVrfToGlobalPath(t *testing.T) {
	vrf := nexthopTestVrf(t)

	for _, tt := range []struct {
		name  string
		attrs []bgp.PathAttributeInterface
		want  sentRoute
	}{
		{
			name:  "IPv4 unicast",
			attrs: withMpReach(t, bgp.RF_IPv4_UC, prefixNLRIs(t, "10.1.0.0/24"), "192.0.2.1"),
			want:  sentRoute{family: bgp.RF_IPv4_VPN, viaMP: true, nexthop: netip.MustParseAddr("192.0.2.1")},
		},
		{
			name:  "IPv6 unicast",
			attrs: withMpReach(t, bgp.RF_IPv6_UC, prefixNLRIs(t, "2001:db8:1::/64"), "2001:db8::1"),
			want:  sentRoute{family: bgp.RF_IPv6_VPN, viaMP: true, nexthop: netip.MustParseAddr("2001:db8::1")},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			paths := receive(t, nil, nil, tt.attrs)
			for _, p := range paths {
				require.NoError(t, vrf.ToGlobalPath(p))
				assert.Equal(t, tt.want.nexthop, p.GetNexthop())
			}
			assert.Equal(t, wantRoutes(paths, tt.want), sentRoutes(t, CreateUpdateMsgFromPaths(paths)))
		})
	}
}

// ToLocal turns a VPN path into a unicast path with the same next hop.
func TestNexthopToLocal(t *testing.T) {
	for _, tt := range []struct {
		name  string
		attrs []bgp.PathAttributeInterface
		want  sentRoute
	}{
		{
			// It goes out in the NLRI field with NEXT_HOP.
			name:  "IPv4 VPN",
			attrs: withMpReach(t, bgp.RF_IPv4_VPN, vpnNLRIs(t, "10.1.0.0/24"), "192.0.2.1"),
			want:  sentRoute{family: bgp.RF_IPv4_UC, nexthop: netip.MustParseAddr("192.0.2.1")},
		},
		{
			// It goes out in MP_REACH_NLRI without NEXT_HOP.
			name:  "IPv4 VPN with an IPv6 next hop",
			attrs: withMpReach(t, bgp.RF_IPv4_VPN, vpnNLRIs(t, "10.1.0.0/24"), "2001:db8::1"),
			want:  sentRoute{family: bgp.RF_IPv4_UC, viaMP: true, nexthop: netip.MustParseAddr("2001:db8::1")},
		},
		{
			name:  "IPv6 VPN",
			attrs: withMpReach(t, bgp.RF_IPv6_VPN, vpnNLRIs(t, "2001:db8:1::/64"), "2001:db8::1"),
			want:  sentRoute{family: bgp.RF_IPv6_UC, viaMP: true, nexthop: netip.MustParseAddr("2001:db8::1")},
		},
		{
			name:  "IPv6 VPN with a link-local next hop",
			attrs: withMpReach(t, bgp.RF_IPv6_VPN, vpnNLRIs(t, "2001:db8:1::/64"), "2001:db8::1", "fe80::1"),
			want: sentRoute{
				family:    bgp.RF_IPv6_UC,
				viaMP:     true,
				nexthop:   netip.MustParseAddr("2001:db8::1"),
				linkLocal: netip.MustParseAddr("fe80::1"),
			},
		},
		{
			name:  "IPv4 FlowSpec VPN",
			attrs: withMpReach(t, bgp.RF_FS_IPv4_VPN, flowSpecVPNNLRIs(t, "10.1.0.0/24")),
			want:  sentRoute{family: bgp.RF_FS_IPv4_UC, viaMP: true},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			paths := receive(t, peerR1(), nil, tt.attrs)
			local := make([]*Path, 0, len(paths))
			for _, p := range paths {
				l := p.ToLocal()
				assert.Equal(t, tt.want.nexthop, l.GetNexthop())
				local = append(local, l)
			}
			assert.Equal(t, wantRoutes(local, tt.want), sentRoutes(t, CreateUpdateMsgFromPaths(local)))
		})
	}
}

// The RTC paths that AddVrf makes for the import Route Targets have the
// next hop 0.0.0.0.
func TestNexthopAddVrfRtcPaths(t *testing.T) {
	tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_VPN, bgp.RF_RTC_UC}, oc.RouteSelectionOptionsConfig{}, oc.UseMultiplePathsConfig{})
	rd, err := bgp.ParseRouteDistinguisher("65000:100")
	require.NoError(t, err)
	_, rt, err := parseRDRT("65000:200")
	require.NoError(t, err)

	paths, err := tm.AddVrf("vrf1", 1, rd, []bgp.ExtendedCommunityInterface{rt}, nil, peerR1())
	require.NoError(t, err)
	require.Len(t, paths, 1)
	assert.Equal(t, netip.IPv4Unspecified(), paths[0].GetNexthop())
	assert.Equal(t, wantRoutes(paths, sentRoute{family: bgp.RF_RTC_UC, viaMP: true, nexthop: netip.IPv4Unspecified()}),
		sentRoutes(t, CreateUpdateMsgFromPaths(paths)))
}
