package bgp

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLsPrefixAttributesWireRoundTrip(t *testing.T) {
	t.Parallel()
	body := tlvBytes(uint16(LS_TLV_IGP_ROUTE_TAG), []byte{0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0})
	body = append(body, tlvBytes(uint16(LS_TLV_EXTENDED_ROUTE_TAG), []byte{0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255})...)
	body = append(body, tlvBytes(uint16(LS_TLV_OSPF_FORWARDING_ADDR), []byte{0, 0, 0, 0})...)
	body = append(body, tlvBytes(uint16(LS_TLV_OSPF_FORWARDING_ADDR), netip.MustParseAddr("2001:db8::1").AsSlice())...)
	body = append(body, tlvBytes(uint16(LS_TLV_IGP_ROUTE_TAG), []byte{0, 0, 0, 7})...)
	wire := lsAttrBytes(body)
	var attribute PathAttributeLs
	require.NoError(t, attribute.DecodeFromBytes(wire))
	require.Len(t, attribute.TLVs, 5)
	igp, ok := attribute.TLVs[0].(*LsTLVIGPRouteTag)
	require.True(t, ok)
	assert.Equal(t, []uint32{0, 0xffffffff, 0}, igp.Tags)
	extended, ok := attribute.TLVs[1].(*LsTLVExtendedRouteTag)
	require.True(t, ok)
	assert.Equal(t, []uint64{0, 0xffffffffffffffff}, extended.Tags)
	ipv4, ok := attribute.TLVs[2].(*LsTLVOSPFForwardingAddress)
	require.True(t, ok)
	assert.Equal(t, netip.IPv4Unspecified(), ipv4.Address)
	ipv6, ok := attribute.TLVs[3].(*LsTLVOSPFForwardingAddress)
	require.True(t, ok)
	assert.Equal(t, netip.MustParseAddr("2001:db8::1"), ipv6.Address)
	repeated, ok := attribute.TLVs[4].(*LsTLVIGPRouteTag)
	require.True(t, ok)
	assert.Equal(t, []uint32{7}, repeated.Tags)
	encoded, err := attribute.Serialize()
	require.NoError(t, err)
	assert.Equal(t, wire, encoded)
	clear(wire)
	owned, err := attribute.Serialize()
	require.NoError(t, err)
	assert.Equal(t, encoded, owned, "decoded native values must survive wire buffer reuse")
}

func TestLsPrefixAttributeDecoderValidation(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name           string
		typ            LsTLVType
		new            func() LsTLVInterface
		valid          []byte
		invalidLengths []int
	}{
		{"IGP tags", LS_TLV_IGP_ROUTE_TAG, func() LsTLVInterface { return &LsTLVIGPRouteTag{} }, []byte{0, 0, 0, 0}, []int{0, 1, 3, 5}},
		{"extended tags", LS_TLV_EXTENDED_ROUTE_TAG, func() LsTLVInterface { return &LsTLVExtendedRouteTag{} }, make([]byte, 8), []int{0, 1, 4, 7, 9}},
		{"forwarding address", LS_TLV_OSPF_FORWARDING_ADDR, func() LsTLVInterface { return &LsTLVOSPFForwardingAddress{} }, []byte{192, 0, 2, 1}, []int{0, 1, 3, 5, 15, 17}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			valid := tlvBytes(uint16(test.typ), test.valid)
			decoder := test.new()
			require.NoError(t, decoder.DecodeFromBytes(valid))
			invalid := [][]byte{nil, valid[:3], valid[:len(valid)-1], tlvBytes(uint16(LS_TLV_NODE_NAME), test.valid)}
			for _, length := range test.invalidLengths {
				invalid = append(invalid, tlvBytes(uint16(test.typ), make([]byte, length)))
			}
			for _, wire := range invalid {
				require.Error(t, decoder.DecodeFromBytes(wire))
				encoded, err := decoder.Serialize()
				require.NoError(t, err)
				assert.Equal(t, valid, encoded, "failed decode must preserve the previous value")
			}
			for _, length := range test.invalidLengths {
				var attribute PathAttributeLs
				require.Error(t, attribute.DecodeFromBytes(lsAttrBytes(tlvBytes(uint16(test.typ), make([]byte, length)))))
			}
		})
	}
}

func TestLsRouteTagSerializationBounds(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		width int
		new   func(int) LsTLVInterface
	}{
		{"IGP tags", 4, func(count int) LsTLVInterface { return NewLsTLVIGPRouteTag(make([]uint32, count)) }},
		{"extended tags", 8, func(count int) LsTLVInterface { return NewLsTLVExtendedRouteTag(make([]uint64, count)) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			for _, count := range []int{0, 65535/test.width + 1} {
				_, err := test.new(count).Serialize()
				require.Error(t, err)
			}
			maximum := test.new(65535 / test.width)
			wire, err := maximum.Serialize()
			require.NoError(t, err)
			assert.Equal(t, test.width*(65535/test.width)+4, len(wire))
			require.NoError(t, maximum.DecodeFromBytes(wire))
			roundTrip, err := maximum.Serialize()
			require.NoError(t, err)
			assert.Equal(t, wire, roundTrip)
		})
	}
	_, err := (&LsTLVIGPRouteTag{LsTLV: LsTLV{Type: LS_TLV_IGP_ROUTE_TAG, Length: 8}, Tags: []uint32{1}}).Serialize()
	require.Error(t, err, "declared length must match the tag list")
	_, err = (&LsTLVExtendedRouteTag{LsTLV: LsTLV{Type: LS_TLV_IGP_ROUTE_TAG, Length: 8}, Tags: []uint64{1}}).Serialize()
	require.Error(t, err, "header must match the concrete TLV type")
}

func TestLsOSPFForwardingAddressPreservesFamily(t *testing.T) {
	t.Parallel()
	for _, input := range []string{"0.0.0.0", "192.0.2.1", "::", "2001:db8::1", "::ffff:192.0.2.1"} {
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			address := netip.MustParseAddr(input)
			tlv := NewLsTLVOSPFForwardingAddress(address)
			wire, err := tlv.Serialize()
			require.NoError(t, err)
			assert.Equal(t, tlvBytes(uint16(LS_TLV_OSPF_FORWARDING_ADDR), address.AsSlice()), wire)
			var decoded LsTLVOSPFForwardingAddress
			require.NoError(t, decoded.DecodeFromBytes(wire))
			assert.Equal(t, address, decoded.Address)
			data, err := decoded.MarshalJSON()
			require.NoError(t, err)
			var model struct {
				Type    LsTLVType  `json:"type"`
				Address netip.Addr `json:"ospf_forwarding_address"`
			}
			require.NoError(t, json.Unmarshal(data, &model))
			assert.Equal(t, LsTLVType(LS_TLV_OSPF_FORWARDING_ADDR), model.Type)
			assert.Equal(t, address, model.Address)
		})
	}
	for _, address := range []netip.Addr{{}, netip.MustParseAddr("fe80::1%eth0")} {
		_, err := NewLsTLVOSPFForwardingAddress(address).Serialize()
		require.Error(t, err)
	}
	wrongLength := NewLsTLVOSPFForwardingAddress(netip.IPv4Unspecified())
	wrongLength.Length = 16
	_, err := wrongLength.Serialize()
	require.Error(t, err)
}
