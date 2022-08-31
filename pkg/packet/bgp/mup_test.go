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
		RD:           rd,
		PrefixLength: 24,
		Prefix:       netip.MustParsePrefix("10.10.10.0/24"),
	}
	n1 := NewMUPNLRI(MUP_ARCH_TYPE_3GPP_5G, MUP_ROUTE_TYPE_INTERWORK_SEGMENT_DISCOVERY, r)
	buf1, err := n1.Serialize()
	assert.Nil(err)
	n2, err := NewPrefixFromRouteFamily(RouteFamilyToAfiSafi(RF_MUP_IPv4))
	assert.Nil(err)
	err = n2.DecodeFromBytes(buf1)
	assert.Nil(err)

	t.Logf("%s", n1)
	t.Logf("%s", n2)

	assert.Equal(n1, n2)
}

func Test_MUPInterworkSegmentDiscoveryRouteIPv6(t *testing.T) {
	assert := assert.New(t)
	rd, _ := ParseRouteDistinguisher("100:100")
	r := &MUPInterworkSegmentDiscoveryRoute{
		RD:           rd,
		PrefixLength: 64,
		Prefix:       netip.MustParsePrefix("2001::/64"),
	}
	n1 := NewMUPNLRI(MUP_ARCH_TYPE_3GPP_5G, MUP_ROUTE_TYPE_INTERWORK_SEGMENT_DISCOVERY, r)
	buf1, err := n1.Serialize()
	assert.Nil(err)
	n2, err := NewPrefixFromRouteFamily(RouteFamilyToAfiSafi(RF_MUP_IPv6))
	assert.Nil(err)
	err = n2.DecodeFromBytes(buf1)
	assert.Nil(err)

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
	n1 := NewMUPNLRI(MUP_ARCH_TYPE_3GPP_5G, MUP_ROUTE_TYPE_DIRECT_SEGMENT_DISCOVERY, r)
	buf1, err := n1.Serialize()
	assert.Nil(err)
	n2, err := NewPrefixFromRouteFamily(RouteFamilyToAfiSafi(RF_MUP_IPv4))
	assert.Nil(err)
	err = n2.DecodeFromBytes(buf1)
	assert.Nil(err)

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
	n1 := NewMUPNLRI(MUP_ARCH_TYPE_3GPP_5G, MUP_ROUTE_TYPE_DIRECT_SEGMENT_DISCOVERY, r)
	buf1, err := n1.Serialize()
	assert.Nil(err)
	n2, err := NewPrefixFromRouteFamily(RouteFamilyToAfiSafi(RF_MUP_IPv6))
	assert.Nil(err)
	err = n2.DecodeFromBytes(buf1)
	assert.Nil(err)

	t.Logf("%s", n1)
	t.Logf("%s", n2)

	assert.Equal(n1, n2)
}

func Test_MUPType1SessionTransformedRouteIPv4(t *testing.T) {
	assert := assert.New(t)
	rd, _ := ParseRouteDistinguisher("100:100")
	r := &MUPType1SessionTransformedRoute{
		RD:                    rd,
		PrefixLength:          32,
		Prefix:                netip.MustParseAddr("192.100.0.1"),
		TEID:                  100,
		QFI:                   9,
		EndpointAddressLength: 32,
		EndpointAddress:       netip.MustParseAddr("10.10.10.1"),
	}
	n1 := NewMUPNLRI(MUP_ARCH_TYPE_3GPP_5G, MUP_ROUTE_TYPE_TYPE_1_SESSION_TRANSFORMED, r)
	buf1, err := n1.Serialize()
	assert.Nil(err)
	n2, err := NewPrefixFromRouteFamily(RouteFamilyToAfiSafi(RF_MUP_IPv4))
	assert.Nil(err)
	err = n2.DecodeFromBytes(buf1)
	assert.Nil(err)

	t.Logf("%s", n1)
	t.Logf("%s", n2)

	assert.Equal(n1, n2)
}

func Test_MUPType1SessionTransformedRouteIPv6(t *testing.T) {
	assert := assert.New(t)
	rd, _ := ParseRouteDistinguisher("100:100")
	r := &MUPType1SessionTransformedRoute{
		RD:                    rd,
		PrefixLength:          128,
		Prefix:                netip.MustParseAddr("2001:db8:1:1::1"),
		TEID:                  100,
		QFI:                   9,
		EndpointAddressLength: 128,
		EndpointAddress:       netip.MustParseAddr("2001::1"),
	}
	n1 := NewMUPNLRI(MUP_ARCH_TYPE_3GPP_5G, MUP_ROUTE_TYPE_TYPE_1_SESSION_TRANSFORMED, r)
	buf1, err := n1.Serialize()
	assert.Nil(err)
	n2, err := NewPrefixFromRouteFamily(RouteFamilyToAfiSafi(RF_MUP_IPv6))
	assert.Nil(err)
	err = n2.DecodeFromBytes(buf1)
	assert.Nil(err)

	t.Logf("%s", n1)
	t.Logf("%s", n2)

	assert.Equal(n1, n2)
}

func Test_MUPType2SessionTransformedRouteIPv4(t *testing.T) {
	assert := assert.New(t)
	rd, _ := ParseRouteDistinguisher("100:100")
	r := &MUPType2SessionTransformedRoute{
		RD:                    rd,
		EndpointAddressLength: 64,
		EndpointAddress:       netip.MustParseAddr("10.10.10.1"),
		TEID:                  100,
	}
	n1 := NewMUPNLRI(MUP_ARCH_TYPE_3GPP_5G, MUP_ROUTE_TYPE_TYPE_2_SESSION_TRANSFORMED, r)
	buf1, err := n1.Serialize()
	assert.Nil(err)
	n2, err := NewPrefixFromRouteFamily(RouteFamilyToAfiSafi(RF_MUP_IPv4))
	assert.Nil(err)
	err = n2.DecodeFromBytes(buf1)
	assert.Nil(err)

	t.Logf("%s", n1)
	t.Logf("%s", n2)

	assert.Equal(n1, n2)
}

func Test_MUPType2SessionTransformedRouteIPv6(t *testing.T) {
	assert := assert.New(t)
	rd, _ := ParseRouteDistinguisher("100:100")
	r := &MUPType2SessionTransformedRoute{
		RD:                    rd,
		EndpointAddressLength: 160,
		EndpointAddress:       netip.MustParseAddr("2001::1"),
		TEID:                  100,
	}
	n1 := NewMUPNLRI(MUP_ARCH_TYPE_3GPP_5G, MUP_ROUTE_TYPE_TYPE_2_SESSION_TRANSFORMED, r)
	buf1, err := n1.Serialize()
	assert.Nil(err)
	n2, err := NewPrefixFromRouteFamily(RouteFamilyToAfiSafi(RF_MUP_IPv6))
	assert.Nil(err)
	err = n2.DecodeFromBytes(buf1)
	assert.Nil(err)

	t.Logf("%s", n1)
	t.Logf("%s", n2)

	assert.Equal(n1, n2)
}
