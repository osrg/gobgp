package bgp

import (
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func msdWire(typ LsTLVType, value ...byte) []byte {
	wire := binary.BigEndian.AppendUint16(nil, uint16(typ))
	wire = binary.BigEndian.AppendUint16(wire, uint16(len(value)))
	return append(wire, value...)
}

func msdAttributeWire(value []byte) []byte {
	wire := []byte{byte(BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_EXTENDED_LENGTH), byte(BGP_ATTR_TYPE_LS)}
	wire = binary.BigEndian.AppendUint16(wire, uint16(len(value)))
	return append(wire, value...)
}

func TestLsMSDAttributeRoundTrip(t *testing.T) {
	t.Parallel()
	body := msdWire(LS_TLV_NODE_MSD, 1, 0, 1, 255, 255, 42)
	body = append(body, msdWire(LS_TLV_LINK_MSD, 0, 0, 1, 255)...)
	body = append(body, msdWire(LS_TLV_NODE_MSD, 1, 9)...)
	wire := msdAttributeWire(body)
	var attribute PathAttributeLs
	require.NoError(t, attribute.DecodeFromBytes(wire))
	require.Len(t, attribute.TLVs, 3)
	node, ok := attribute.TLVs[0].(*LsTLVNodeMSD)
	require.True(t, ok)
	assert.Equal(t, []LsMSDEntry{{Type: 1, Value: 0}, {Type: 1, Value: 255}, {Type: 255, Value: 42}}, node.Entries)
	link, ok := attribute.TLVs[1].(*LsTLVLinkMSD)
	require.True(t, ok)
	assert.Equal(t, []LsMSDEntry{{Type: 0, Value: 0}, {Type: 1, Value: 255}}, link.Entries)
	repeated, ok := attribute.TLVs[2].(*LsTLVNodeMSD)
	require.True(t, ok)
	assert.Equal(t, []LsMSDEntry{{Type: 1, Value: 9}}, repeated.Entries)
	encoded, err := attribute.Serialize()
	require.NoError(t, err)
	assert.Equal(t, wire, encoded)
	// Decoded entries own their storage, including when the original BGP
	// message buffer is subsequently reused by its reader.
	clear(wire)
	owned, err := attribute.Serialize()
	require.NoError(t, err)
	assert.Equal(t, encoded, owned)
}

func TestLsMSDDecoderValidationAndReuse(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		typ  LsTLVType
		new  func() LsTLVInterface
	}{
		{name: "node", typ: LS_TLV_NODE_MSD, new: func() LsTLVInterface { return &LsTLVNodeMSD{} }},
		{name: "link", typ: LS_TLV_LINK_MSD, new: func() LsTLVInterface { return &LsTLVLinkMSD{} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			decoder := test.new()
			valid := msdWire(test.typ, 1, 0, 1, 255)
			require.NoError(t, decoder.DecodeFromBytes(valid))
			for _, invalid := range [][]byte{
				nil,
				valid[:3],
				valid[:len(valid)-1],
				msdWire(test.typ),
				msdWire(test.typ, 1),
				msdWire(test.typ, 1, 2, 3),
				msdWire(LS_TLV_NODE_NAME, 1, 2),
			} {
				require.Error(t, decoder.DecodeFromBytes(invalid))
				encoded, err := decoder.Serialize()
				require.NoError(t, err)
				assert.Equal(t, valid, encoded, "failed decode must leave prior state intact")
			}
			shorter := msdWire(test.typ, 255, 0)
			require.NoError(t, decoder.DecodeFromBytes(shorter))
			encoded, err := decoder.Serialize()
			require.NoError(t, err)
			assert.Equal(t, shorter, encoded, "successful reuse replaces old entries")
			data, err := decoder.MarshalJSON()
			require.NoError(t, err)
			var model struct {
				Type    LsTLVType    `json:"type"`
				Entries []LsMSDEntry `json:"entries"`
			}
			require.NoError(t, json.Unmarshal(data, &model))
			assert.Equal(t, test.typ, model.Type)
			assert.Equal(t, []LsMSDEntry{{Type: 255, Value: 0}}, model.Entries)
			assert.NotEmpty(t, decoder.String())
		})
	}
}

func TestLsMSDRejectsMalformedAttribute(t *testing.T) {
	t.Parallel()
	for _, typ := range []LsTLVType{LS_TLV_NODE_MSD, LS_TLV_LINK_MSD} {
		for _, value := range [][]byte{nil, {1}, {1, 2, 3}} {
			var attribute PathAttributeLs
			require.Error(t, attribute.DecodeFromBytes(msdAttributeWire(msdWire(typ, value...))))
		}
	}
}

func TestLsMSDSerializationBounds(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		new  func([]LsMSDEntry) LsTLVInterface
	}{
		{name: "node", new: func(entries []LsMSDEntry) LsTLVInterface { return NewLsTLVNodeMSD(entries) }},
		{name: "link", new: func(entries []LsMSDEntry) LsTLVInterface { return NewLsTLVLinkMSD(entries) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			for _, count := range []int{0, 32768} {
				_, err := test.new(make([]LsMSDEntry, count)).Serialize()
				require.Error(t, err)
			}
			entries := make([]LsMSDEntry, 32767)
			entries[0], entries[len(entries)-1] = LsMSDEntry{Type: 255, Value: 0}, LsMSDEntry{Type: 1, Value: 255}
			tlv := test.new(entries)
			wire, err := tlv.Serialize()
			require.NoError(t, err)
			assert.Equal(t, 65534+4, len(wire))
			assert.Equal(t, 65534+4, tlv.Len())
			require.NoError(t, tlv.DecodeFromBytes(wire))
			roundTrip, err := tlv.Serialize()
			require.NoError(t, err)
			assert.Equal(t, wire, roundTrip)
		})
	}
	_, err := (&LsTLVNodeMSD{LsTLV: LsTLV{Type: LS_TLV_NODE_MSD, Length: 4}, Entries: []LsMSDEntry{{Type: 1, Value: 2}}}).Serialize()
	require.Error(t, err, "declared length must match entries")
	_, err = (&LsTLVLinkMSD{LsTLV: LsTLV{Type: LS_TLV_NODE_MSD, Length: 2}, Entries: []LsMSDEntry{{Type: 1, Value: 2}}}).Serialize()
	require.Error(t, err, "header must use the concrete TLV type")
}
