package apiutil

import (
	"net/netip"
	"testing"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestLsPrefixAttributesAPIRoundTrip(t *testing.T) {
	t.Parallel()
	for _, withFlags := range []bool{false, true} {
		name := "without IGP flags"
		if withFlags {
			name = "with IGP flags"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			input := &api.LsAttribute{
				Prefix: &api.LsAttributePrefix{
					IgpRouteTags:      []uint32{0, 42, 42, 0xffffffff},
					ExtendedRouteTags: []uint64{0, 1 << 40, 1 << 40, 0xffffffffffffffff},
					OspfForwardingAddresses: []string{
						"0.0.0.0", "::", "192.0.2.1", "2001:db8::1", "::ffff:192.0.2.1", "192.0.2.1",
					},
				},
			}
			if withFlags {
				input.Prefix.IgpFlags = &api.LsIGPFlags{Down: true}
			}
			encoded, err := proto.Marshal(input)
			require.NoError(t, err)
			var transported api.LsAttribute
			require.NoError(t, proto.Unmarshal(encoded, &transported))
			native, err := UnmarshalLsAttribute(&transported)
			require.NoError(t, err)
			assert.Equal(t, input.Prefix.IgpRouteTags, native.Prefix.IGPRouteTags)
			assert.Equal(t, input.Prefix.ExtendedRouteTags, native.Prefix.ExtendedRouteTags)
			for i, address := range input.Prefix.OspfForwardingAddresses {
				require.Len(t, native.Prefix.OSPFForwardingAddresses, len(input.Prefix.OspfForwardingAddresses))
				assert.Equal(t, netip.MustParseAddr(address), native.Prefix.OSPFForwardingAddresses[i])
			}
			attribute := &bgp.PathAttributeLs{
				PathAttribute: bgp.PathAttribute{Flags: bgp.BGP_ATTR_FLAG_OPTIONAL, Type: bgp.BGP_ATTR_TYPE_LS},
				TLVs:          bgp.NewLsAttributeTLVs(native),
			}
			wire, err := attribute.Serialize()
			require.NoError(t, err)
			var decoded bgp.PathAttributeLs
			require.NoError(t, decoded.DecodeFromBytes(wire))
			output, err := NewLsAttributeFromNative(&decoded)
			require.NoError(t, err)
			require.NotNil(t, output.Prefix)
			assert.Equal(t, input.Prefix.IgpRouteTags, output.Prefix.IgpRouteTags)
			assert.Equal(t, input.Prefix.ExtendedRouteTags, output.Prefix.ExtendedRouteTags)
			assert.Equal(t, input.Prefix.OspfForwardingAddresses, output.Prefix.OspfForwardingAddresses)
			assert.True(t, proto.Equal(input.Prefix.IgpFlags, output.Prefix.IgpFlags))
		})
	}
}

func TestLsPrefixAttributesAPIWithoutOtherAttributes(t *testing.T) {
	t.Parallel()
	for _, input := range []*api.LsAttributePrefix{
		{IgpRouteTags: []uint32{0}},
		{ExtendedRouteTags: []uint64{0}},
		{OspfForwardingAddresses: []string{"0.0.0.0"}},
	} {
		native, err := UnmarshalLsAttribute(&api.LsAttribute{Prefix: input})
		require.NoError(t, err)
		attribute := &bgp.PathAttributeLs{TLVs: bgp.NewLsAttributeTLVs(native)}
		require.Len(t, attribute.TLVs, 1)
		output, err := NewLsAttributeFromNative(attribute)
		require.NoError(t, err)
		assert.True(t, proto.Equal(input, output.Prefix))
	}
}

func TestLsPrefixAttributesAPIAbsent(t *testing.T) {
	t.Parallel()
	for _, input := range []*api.LsAttribute{
		{},
		{Prefix: &api.LsAttributePrefix{}},
	} {
		native, err := UnmarshalLsAttribute(input)
		require.NoError(t, err)
		assert.Empty(t, bgp.NewLsAttributeTLVs(native))
		output, err := NewLsAttributeFromNative(&bgp.PathAttributeLs{})
		require.NoError(t, err)
		assert.Empty(t, output.Prefix.IgpRouteTags)
		assert.Empty(t, output.Prefix.ExtendedRouteTags)
		assert.Empty(t, output.Prefix.OspfForwardingAddresses)
	}
}

func TestLsPrefixAttributesAPIRejectInvalidValues(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		attr *api.LsAttribute
	}{
		{"empty address", &api.LsAttribute{Prefix: &api.LsAttributePrefix{OspfForwardingAddresses: []string{""}}}},
		{"invalid address", &api.LsAttribute{Prefix: &api.LsAttributePrefix{OspfForwardingAddresses: []string{"invalid"}}}},
		{"address with zone", &api.LsAttribute{Prefix: &api.LsAttributePrefix{OspfForwardingAddresses: []string{"fe80::1%eth0"}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := UnmarshalLsAttribute(test.attr)
			require.Error(t, err)
		})
	}
}

func TestLsForwardingAddressAPIRejectInvalidNativeValues(t *testing.T) {
	t.Parallel()
	for _, address := range []netip.Addr{{}, netip.MustParseAddr("fe80::1%eth0")} {
		_, err := NewLsAttributeFromNative(&bgp.PathAttributeLs{TLVs: []bgp.LsTLVInterface{
			bgp.NewLsTLVOSPFForwardingAddress(address),
		}})
		require.Error(t, err)
	}
}
