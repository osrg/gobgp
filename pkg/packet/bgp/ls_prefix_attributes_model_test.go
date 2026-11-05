package bgp_test

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLSPrefixAttributesModelRoundTrip(t *testing.T) {
	t.Parallel()
	model := &bgp.LsAttribute{Prefix: bgp.LsAttributePrefix{
		IGPRouteTags:      []uint32{0, 1, 1, 0xffffffff},
		ExtendedRouteTags: []uint64{0, 1, 1, 0xffffffffffffffff},
		OSPFForwardingAddresses: []netip.Addr{
			netip.IPv4Unspecified(), netip.IPv6Unspecified(),
			netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1"),
			netip.MustParseAddr("::ffff:192.0.2.1"),
		},
	}}
	attribute := &bgp.PathAttributeLs{
		PathAttribute: bgp.PathAttribute{Flags: bgp.BGP_ATTR_FLAG_OPTIONAL, Type: bgp.BGP_ATTR_TYPE_LS},
		TLVs:          bgp.NewLsAttributeTLVs(model),
	}
	require.Len(t, attribute.TLVs, 7)
	wire, err := attribute.Serialize()
	require.NoError(t, err)
	var decoded bgp.PathAttributeLs
	require.NoError(t, decoded.DecodeFromBytes(wire))
	assert.Equal(t, model, decoded.Extract())

	data, err := decoded.MarshalJSON()
	require.NoError(t, err)
	var document bgp.LsAttribute
	require.NoError(t, json.Unmarshal(data, &document))
	assert.Equal(t, model.Prefix, document.Prefix)
}

func TestLSPrefixAttributesModelPreservesRepeatedTLVs(t *testing.T) {
	t.Parallel()
	firstAddress := netip.MustParseAddr("192.0.2.1")
	secondAddress := netip.MustParseAddr("2001:db8::1")
	firstTags := bgp.NewLsTLVIGPRouteTag([]uint32{0, 42})
	firstExtendedTags := bgp.NewLsTLVExtendedRouteTag([]uint64{0, 42})
	firstForwarding := bgp.NewLsTLVOSPFForwardingAddress(firstAddress)
	attribute := &bgp.PathAttributeLs{TLVs: []bgp.LsTLVInterface{
		firstTags, firstExtendedTags, firstForwarding,
		bgp.NewLsTLVIGPRouteTag([]uint32{42, 0xffffffff}),
		bgp.NewLsTLVExtendedRouteTag([]uint64{42, 0xffffffffffffffff}),
		bgp.NewLsTLVOSPFForwardingAddress(secondAddress),
	}}
	want := bgp.LsAttributePrefix{
		IGPRouteTags:            []uint32{0, 42, 42, 0xffffffff},
		ExtendedRouteTags:       []uint64{0, 42, 42, 0xffffffffffffffff},
		OSPFForwardingAddresses: []netip.Addr{firstAddress, secondAddress},
	}
	model := attribute.Extract()
	assert.Equal(t, want, model.Prefix)
	firstTags.Tags[0] = 123
	firstExtendedTags.Tags[0] = 123
	firstForwarding.Address = netip.IPv4Unspecified()
	assert.Equal(t, want, model.Prefix, "extracted lists must not alias the original TLVs")
}

func TestLSPrefixAttributesModelOmitsAbsentFields(t *testing.T) {
	t.Parallel()
	model := &bgp.LsAttribute{}
	attribute := &bgp.PathAttributeLs{TLVs: bgp.NewLsAttributeTLVs(model)}
	assert.Empty(t, attribute.TLVs)
	data, err := attribute.MarshalJSON()
	require.NoError(t, err)
	assert.NotContains(t, string(data), "igp_route_tags")
	assert.NotContains(t, string(data), "extended_route_tags")
	assert.NotContains(t, string(data), "ospf_forwarding_addresses")
}
