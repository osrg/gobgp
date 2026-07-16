package bgp

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_MUPExtended(t *testing.T) {
	assert := assert.New(t)
	exts := make([]ExtendedCommunityInterface, 0)
	exts = append(exts, NewMUPExtended(100, 10000))
	m1 := NewPathAttributeExtendedCommunities(exts)
	buf1, err := m1.Serialize()
	require.NoError(t, err)

	m2 := NewPathAttributeExtendedCommunities(nil)
	err = m2.DecodeFromBytes(buf1)
	require.NoError(t, err)

	_, err = m2.Serialize()
	require.NoError(t, err)

	assert.Equal(m1, m2)
}

func Test_MUPInterworkSegmentDiscoveryRouteIPv4(t *testing.T) {
	assert := assert.New(t)
	rd, _ := ParseRouteDistinguisher("100:100")
	r := &MUPInterworkSegmentDiscoveryRoute{
		RD:     rd,
		Prefix: netip.MustParsePrefix("10.10.10.0/24"),
	}
	n1 := NewMUPNLRI(AFI_IP, MUP_ARCH_TYPE_3GPP_5G, MUP_ROUTE_TYPE_INTERWORK_SEGMENT_DISCOVERY, r)
	buf1, err := n1.Serialize()
	assert.NoError(err)
	n2, err := NLRIFromSlice(RF_MUP_IPv4, buf1)
	assert.NoError(err)

	t.Logf("%s", n1)
	t.Logf("%s", n2)

	assert.Equal(n1, n2)
}

func Test_MUPInterworkSegmentDiscoveryRouteIPv6(t *testing.T) {
	assert := assert.New(t)
	rd, _ := ParseRouteDistinguisher("100:100")
	r := &MUPInterworkSegmentDiscoveryRoute{
		RD:     rd,
		Prefix: netip.MustParsePrefix("2001::/64"),
	}
	n1 := NewMUPNLRI(AFI_IP6, MUP_ARCH_TYPE_3GPP_5G, MUP_ROUTE_TYPE_INTERWORK_SEGMENT_DISCOVERY, r)
	buf1, err := n1.Serialize()
	assert.NoError(err)
	n2, err := NLRIFromSlice(RF_MUP_IPv6, buf1)
	assert.NoError(err)

	t.Logf("%s", n1)
	t.Logf("%s", n2)

	assert.Equal(n1, n2)
}

func Test_MUPDirectSegmentDiscoveryRouteIPv4(t *testing.T) {
	assert := assert.New(t)
	rd, _ := ParseRouteDistinguisher("100:100")
	r := &MUPDirectSegmentDiscoveryRoute{
		RD:      rd,
		Address: netip.MustParseAddr("10.10.10.1"),
	}
	n1 := NewMUPNLRI(AFI_IP, MUP_ARCH_TYPE_3GPP_5G, MUP_ROUTE_TYPE_DIRECT_SEGMENT_DISCOVERY, r)
	buf1, err := n1.Serialize()
	assert.NoError(err)
	n2, err := NLRIFromSlice(RF_MUP_IPv4, buf1)
	assert.NoError(err)

	t.Logf("%s", n1)
	t.Logf("%s", n2)

	assert.Equal(n1, n2)
}

func Test_MUPDirectSegmentDiscoveryRouteIPv6(t *testing.T) {
	assert := assert.New(t)
	rd, _ := ParseRouteDistinguisher("100:100")
	r := &MUPDirectSegmentDiscoveryRoute{
		RD:      rd,
		Address: netip.MustParseAddr("2001::1"),
	}
	n1 := NewMUPNLRI(AFI_IP6, MUP_ARCH_TYPE_3GPP_5G, MUP_ROUTE_TYPE_DIRECT_SEGMENT_DISCOVERY, r)
	buf1, err := n1.Serialize()
	assert.NoError(err)
	n2, err := NLRIFromSlice(RF_MUP_IPv6, buf1)
	assert.NoError(err)

	t.Logf("%s", n1)
	t.Logf("%s", n2)

	assert.Equal(n1, n2)
}

func Test_MUPType1SessionTransformedRoute(t *testing.T) {
	assert := assert.New(t)
	rd, _ := ParseRouteDistinguisher("100:100")
	ipv4SA := netip.MustParseAddr("10.10.10.2")
	ipv6SA := netip.MustParseAddr("2001::2")
	tests := []struct {
		name string
		in   *MUPType1SessionTransformedRoute
		afi  uint16
		rf   Family
	}{
		{
			name: "IPv4",
			in: &MUPType1SessionTransformedRoute{
				RD:                    rd,
				Prefix:                netip.MustParsePrefix("192.100.0.0/24"),
				TEID:                  netip.MustParseAddr("0.0.0.100"),
				QFI:                   9,
				EndpointAddressLength: 32,
				EndpointAddress:       netip.MustParseAddr("10.10.10.1"),
			},
			afi: AFI_IP,
			rf:  RF_MUP_IPv4,
		},
		{
			name: "IPv4_with_SourceAddress",
			in: &MUPType1SessionTransformedRoute{
				RD:                    rd,
				Prefix:                netip.MustParsePrefix("192.100.0.0/24"),
				TEID:                  netip.MustParseAddr("0.0.0.100"),
				QFI:                   9,
				EndpointAddressLength: 32,
				EndpointAddress:       netip.MustParseAddr("10.10.10.1"),
				SourceAddressLength:   32,
				SourceAddress:         &ipv4SA,
			},
			afi: AFI_IP,
			rf:  RF_MUP_IPv4,
		},
		{
			name: "IPv6",
			in: &MUPType1SessionTransformedRoute{
				RD:                    rd,
				Prefix:                netip.MustParsePrefix("2001:db8:1::/48"),
				TEID:                  netip.MustParseAddr("0.0.0.100"),
				QFI:                   9,
				EndpointAddressLength: 128,
				EndpointAddress:       netip.MustParseAddr("2001::1"),
			},
			afi: AFI_IP6,
			rf:  RF_MUP_IPv6,
		},
		{
			name: "IPv6_with_SourceAddress",
			in: &MUPType1SessionTransformedRoute{
				RD:                    rd,
				Prefix:                netip.MustParsePrefix("2001:db8:1::/48"),
				TEID:                  netip.MustParseAddr("0.0.0.100"),
				QFI:                   9,
				EndpointAddressLength: 128,
				EndpointAddress:       netip.MustParseAddr("2001::1"),
				SourceAddressLength:   128,
				SourceAddress:         &ipv6SA,
			},
			afi: AFI_IP6,
			rf:  RF_MUP_IPv6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n1 := NewMUPNLRI(tt.afi, MUP_ARCH_TYPE_3GPP_5G, MUP_ROUTE_TYPE_TYPE_1_SESSION_TRANSFORMED, tt.in)
			buf1, err := n1.Serialize()
			assert.NoError(err)
			n2, err := NLRIFromSlice(tt.rf, buf1)
			assert.NoError(err)

			t.Logf("%s", n1)
			t.Logf("%s", n2)

			assert.Equal(n1, n2)
		})
	}
}

func Test_MUPType2SessionTransformedRouteIPv4(t *testing.T) {
	assert := assert.New(t)
	rd, _ := ParseRouteDistinguisher("100:100")
	tests := []struct {
		name string
		in   *MUPType2SessionTransformedRoute
	}{
		{
			name: "teid length = 32",
			in: &MUPType2SessionTransformedRoute{
				RD:                    rd,
				EndpointAddressLength: 64,
				EndpointAddress:       netip.MustParseAddr("10.10.10.1"),
				TEID:                  netip.MustParseAddr("0.0.0.100"),
			},
		},
		{
			name: "teid length = 10",
			in: &MUPType2SessionTransformedRoute{
				RD:                    rd,
				EndpointAddressLength: 42,
				EndpointAddress:       netip.MustParseAddr("10.10.10.1"),
				TEID:                  netip.MustParseAddr("100.64.0.0"), // /10
			},
		},
		{
			name: "teid length = 0",
			in: &MUPType2SessionTransformedRoute{
				RD:                    rd,
				EndpointAddressLength: 32,
				EndpointAddress:       netip.MustParseAddr("10.10.10.1"),
				TEID:                  netip.MustParseAddr("0.0.0.0"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n1 := NewMUPNLRI(AFI_IP, MUP_ARCH_TYPE_3GPP_5G, MUP_ROUTE_TYPE_TYPE_2_SESSION_TRANSFORMED, tt.in)
			buf1, err := n1.Serialize()
			assert.NoError(err)
			n2, err := NLRIFromSlice(RF_MUP_IPv4, buf1)
			assert.NoError(err)

			t.Logf("%s", n1)
			t.Logf("%s", n2)

			assert.Equal(n1, n2)
		})
	}
}

func Test_MUPType2SessionTransformedRouteIPv6(t *testing.T) {
	assert := assert.New(t)
	rd, _ := ParseRouteDistinguisher("100:100")
	tests := []struct {
		name string
		in   *MUPType2SessionTransformedRoute
	}{
		{
			name: "teid length = 32",
			in: &MUPType2SessionTransformedRoute{
				RD:                    rd,
				EndpointAddressLength: 160,
				EndpointAddress:       netip.MustParseAddr("2001::1"),
				TEID:                  netip.MustParseAddr("0.0.0.100"),
			},
		},
		{
			name: "teid length = 10",
			in: &MUPType2SessionTransformedRoute{
				RD:                    rd,
				EndpointAddressLength: 138,
				EndpointAddress:       netip.MustParseAddr("2001::1"),
				TEID:                  netip.MustParseAddr("100.64.0.0"), // /10
			},
		},
		{
			name: "teid length = 0",
			in: &MUPType2SessionTransformedRoute{
				RD:                    rd,
				EndpointAddressLength: 128,
				EndpointAddress:       netip.MustParseAddr("2001::1"),
				TEID:                  netip.MustParseAddr("0.0.0.0"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n1 := NewMUPNLRI(AFI_IP6, MUP_ARCH_TYPE_3GPP_5G, MUP_ROUTE_TYPE_TYPE_2_SESSION_TRANSFORMED, tt.in)
			buf1, err := n1.Serialize()
			assert.NoError(err)
			n2, err := NLRIFromSlice(RF_MUP_IPv6, buf1)
			assert.NoError(err)

			t.Logf("%s", n1)
			t.Logf("%s", n2)

			assert.Equal(n1, n2)
		})
	}
}

func Test_MUPType1SessionTransformedRouteTLVs(t *testing.T) {
	assert := assert.New(t)
	rd, _ := ParseRouteDistinguisher("100:100")
	tests := []struct {
		name string
		in   *MUPType1SessionTransformedRoute
	}{
		{
			// No TLV is applicable to Type 1 ST routes, but received TLVs
			// must be kept and propagated unchanged.
			name: "session parameters",
			in: &MUPType1SessionTransformedRoute{
				RD:                    rd,
				Prefix:                netip.MustParsePrefix("192.100.0.0/24"),
				TEID:                  netip.MustParseAddr("0.0.0.100"),
				QFI:                   9,
				EndpointAddressLength: 32,
				EndpointAddress:       netip.MustParseAddr("10.10.10.1"),
				TLVs: []MUPTLVInterface{
					NewMUPSessionParametersTLV(netip.MustParseAddr("0.0.0.200"), 11),
				},
			},
		},
		{
			name: "unknown TLV",
			in: &MUPType1SessionTransformedRoute{
				RD:                    rd,
				Prefix:                netip.MustParsePrefix("192.100.0.0/24"),
				TEID:                  netip.MustParseAddr("0.0.0.100"),
				QFI:                   9,
				EndpointAddressLength: 32,
				EndpointAddress:       netip.MustParseAddr("10.10.10.1"),
				TLVs: []MUPTLVInterface{
					NewMUPUnknownTLV(200, []byte{0xde, 0xad, 0xbe, 0xef}),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n1 := NewMUPNLRI(AFI_IP, MUP_ARCH_TYPE_3GPP_5G, MUP_ROUTE_TYPE_TYPE_1_SESSION_TRANSFORMED, tt.in)
			buf1, err := n1.Serialize()
			assert.NoError(err)
			n2, err := NLRIFromSlice(RF_MUP_IPv4, buf1)
			assert.NoError(err)

			t.Logf("%s", n1)
			t.Logf("%s", n2)

			assert.Equal(n1, n2)
		})
	}
}

func Test_MUPType2SessionTransformedRouteTLVs(t *testing.T) {
	assert := assert.New(t)
	rd, _ := ParseRouteDistinguisher("100:100")
	tests := []struct {
		name string
		in   *MUPType2SessionTransformedRoute
		afi  uint16
		rf   Family
	}{
		{
			name: "session parameters",
			in: &MUPType2SessionTransformedRoute{
				RD:                    rd,
				EndpointAddressLength: 64,
				EndpointAddress:       netip.MustParseAddr("10.10.10.1"),
				TEID:                  netip.MustParseAddr("0.0.0.100"),
				TLVs: []MUPTLVInterface{
					NewMUPSessionParametersTLV(netip.MustParseAddr("0.0.0.200"), 9),
				},
			},
			afi: AFI_IP,
			rf:  RF_MUP_IPv4,
		},
		{
			name: "interwork endpoint IPv4",
			in: &MUPType2SessionTransformedRoute{
				RD:                    rd,
				EndpointAddressLength: 64,
				EndpointAddress:       netip.MustParseAddr("10.10.10.1"),
				TEID:                  netip.MustParseAddr("0.0.0.100"),
				TLVs: []MUPTLVInterface{
					NewMUPInterworkEndpointTLV(netip.MustParseAddr("10.20.30.40")),
				},
			},
			afi: AFI_IP,
			rf:  RF_MUP_IPv4,
		},
		{
			name: "interwork endpoint IPv6",
			in: &MUPType2SessionTransformedRoute{
				RD:                    rd,
				EndpointAddressLength: 160,
				EndpointAddress:       netip.MustParseAddr("2001::1"),
				TEID:                  netip.MustParseAddr("0.0.0.100"),
				TLVs: []MUPTLVInterface{
					NewMUPInterworkEndpointTLV(netip.MustParseAddr("2001::100")),
				},
			},
			afi: AFI_IP6,
			rf:  RF_MUP_IPv6,
		},
		{
			name: "source address",
			in: &MUPType2SessionTransformedRoute{
				RD:                    rd,
				EndpointAddressLength: 64,
				EndpointAddress:       netip.MustParseAddr("10.10.10.1"),
				TEID:                  netip.MustParseAddr("0.0.0.100"),
				TLVs: []MUPTLVInterface{
					NewMUPSourceAddressTLV(netip.MustParseAddr("10.0.0.1")),
				},
			},
			afi: AFI_IP,
			rf:  RF_MUP_IPv4,
		},
		{
			name: "multiple TLVs",
			in: &MUPType2SessionTransformedRoute{
				RD:                    rd,
				EndpointAddressLength: 64,
				EndpointAddress:       netip.MustParseAddr("10.10.10.1"),
				TEID:                  netip.MustParseAddr("0.0.0.100"),
				TLVs: []MUPTLVInterface{
					NewMUPSessionParametersTLV(netip.MustParseAddr("0.0.0.200"), 9),
					NewMUPInterworkEndpointTLV(netip.MustParseAddr("10.20.30.40")),
					NewMUPSourceAddressTLV(netip.MustParseAddr("2001::100")),
					NewMUPUnknownTLV(200, []byte{0xde, 0xad, 0xbe, 0xef}),
				},
			},
			afi: AFI_IP,
			rf:  RF_MUP_IPv4,
		},
		{
			name: "TLV after zero length TEID",
			in: &MUPType2SessionTransformedRoute{
				RD:                    rd,
				EndpointAddressLength: 32,
				EndpointAddress:       netip.MustParseAddr("10.10.10.1"),
				TEID:                  netip.MustParseAddr("0.0.0.0"),
				TLVs: []MUPTLVInterface{
					NewMUPSessionParametersTLV(netip.MustParseAddr("0.0.0.200"), 9),
				},
			},
			afi: AFI_IP,
			rf:  RF_MUP_IPv4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n1 := NewMUPNLRI(tt.afi, MUP_ARCH_TYPE_3GPP_5G, MUP_ROUTE_TYPE_TYPE_2_SESSION_TRANSFORMED, tt.in)
			buf1, err := n1.Serialize()
			assert.NoError(err)
			n2, err := NLRIFromSlice(tt.rf, buf1)
			assert.NoError(err)

			t.Logf("%s", n1)
			t.Logf("%s", n2)

			assert.Equal(n1, n2)
		})
	}
}

func Test_MUPTLVsNotPartOfRouteKey(t *testing.T) {
	assert := assert.New(t)
	rd, _ := ParseRouteDistinguisher("100:100")
	ea := netip.MustParseAddr("10.10.10.1")
	teid := netip.MustParseAddr("0.0.0.100")
	without := NewMUPType2SessionTransformedRoute(rd, 64, ea, teid)
	with := NewMUPType2SessionTransformedRoute(rd, 64, ea, teid,
		NewMUPSessionParametersTLV(netip.MustParseAddr("0.0.0.200"), 9),
		NewMUPInterworkEndpointTLV(netip.MustParseAddr("10.20.30.40")),
	)
	assert.Equal(without.String(), with.String())

	prefix := netip.MustParsePrefix("192.100.0.0/24")
	t1without := NewMUPType1SessionTransformedRoute(rd, prefix, teid, 9, ea, nil)
	t1with := NewMUPType1SessionTransformedRoute(rd, prefix, teid, 9, ea, nil,
		NewMUPUnknownTLV(200, []byte{0xde, 0xad}))
	assert.Equal(t1without.String(), t1with.String())
}

func Test_MUPTLVsMalformed(t *testing.T) {
	assert := assert.New(t)
	rd, _ := ParseRouteDistinguisher("100:100")
	base := NewMUPType2SessionTransformedRoute(rd, 64, netip.MustParseAddr("10.10.10.1"), netip.MustParseAddr("0.0.0.100"))
	tests := []struct {
		name string
		tail []byte // appended after the mandatory fields, added to the NLRI Length
	}{
		{
			// a single remaining octet cannot hold a TLV header
			name: "remaining 1 octet",
			tail: []byte{0x01},
		},
		{
			name: "declared length exceeds remaining octets",
			tail: []byte{0x01, 0x05, 0x00},
		},
		{
			name: "session parameters TLV with invalid length",
			tail: []byte{0x01, 0x04, 0x00, 0x00, 0x00, 0x64},
		},
		{
			name: "interwork endpoint TLV with invalid length",
			tail: []byte{0x02, 0x05, 0x0a, 0x14, 0x1e, 0x28, 0x00},
		},
		{
			name: "source address TLV with invalid length",
			tail: []byte{0x03, 0x05, 0x0a, 0x14, 0x1e, 0x28, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf, err := base.Serialize()
			assert.NoError(err)
			buf = append(buf, tt.tail...)
			buf[3] += uint8(len(tt.tail))
			_, err = NLRIFromSlice(RF_MUP_IPv4, buf)
			assert.Error(err)
		})
	}

	t.Run("NLRI length shorter than mandatory fields", func(t *testing.T) {
		buf, err := base.Serialize()
		assert.NoError(err)
		buf[3] -= 1
		_, err = NLRIFromSlice(RF_MUP_IPv4, buf)
		assert.Error(err)
	})
}

func Test_MUPNLRILengthOverflow(t *testing.T) {
	assert := assert.New(t)
	rd, _ := ParseRouteDistinguisher("100:100")
	tlvs := make([]MUPTLVInterface, 3)
	for i := range tlvs {
		tlvs[i] = NewMUPUnknownTLV(200, make([]byte, 100))
	}
	n := NewMUPType2SessionTransformedRoute(rd, 64, netip.MustParseAddr("10.10.10.1"), netip.MustParseAddr("0.0.0.100"), tlvs...)
	_, err := n.Serialize()
	assert.ErrorContains(err, "length mismatch")
}
