package bgp_test

import (
	"encoding/json"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLsMSDAttributeModelRoundTrip(t *testing.T) {
	t.Parallel()
	want := &bgp.LsAttribute{
		Node: bgp.LsAttributeNode{MSDs: []bgp.LsMSDEntry{{Type: 1, Value: 0}, {Type: 1, Value: 255}, {Type: 255, Value: 42}}},
		Link: bgp.LsAttributeLink{MSDs: []bgp.LsMSDEntry{{Type: 0, Value: 0}, {Type: 1, Value: 255}}},
	}
	attribute := &bgp.PathAttributeLs{
		PathAttribute: bgp.PathAttribute{Flags: bgp.BGP_ATTR_FLAG_OPTIONAL, Type: bgp.BGP_ATTR_TYPE_LS},
		TLVs:          bgp.NewLsAttributeTLVs(want),
	}
	require.Len(t, attribute.TLVs, 2)
	assert.IsType(t, &bgp.LsTLVNodeMSD{}, attribute.TLVs[0])
	assert.IsType(t, &bgp.LsTLVLinkMSD{}, attribute.TLVs[1])
	wire, err := attribute.Serialize()
	require.NoError(t, err)
	var decoded bgp.PathAttributeLs
	require.NoError(t, decoded.DecodeFromBytes(wire))
	assert.Equal(t, want, decoded.Extract())
}

func TestLsMSDAttributeModelRetainsRepeatedTLVsAndJSON(t *testing.T) {
	t.Parallel()
	attribute := &bgp.PathAttributeLs{TLVs: []bgp.LsTLVInterface{
		bgp.NewLsTLVNodeMSD([]bgp.LsMSDEntry{{Type: 1, Value: 0}, {Type: 1, Value: 255}}),
		bgp.NewLsTLVLinkMSD([]bgp.LsMSDEntry{{Type: 0, Value: 0}}),
		bgp.NewLsTLVNodeMSD([]bgp.LsMSDEntry{{Type: 255, Value: 42}}),
		bgp.NewLsTLVLinkMSD([]bgp.LsMSDEntry{{Type: 1, Value: 255}}),
	}}
	wantNode := []bgp.LsMSDEntry{{Type: 1, Value: 0}, {Type: 1, Value: 255}, {Type: 255, Value: 42}}
	wantLink := []bgp.LsMSDEntry{{Type: 0, Value: 0}, {Type: 1, Value: 255}}
	model := attribute.Extract()
	assert.Equal(t, wantNode, model.Node.MSDs)
	assert.Equal(t, wantLink, model.Link.MSDs)
	data, err := attribute.MarshalJSON()
	require.NoError(t, err)
	var document struct {
		Node struct {
			MSDs []bgp.LsMSDEntry `json:"msds"`
		} `json:"node"`
		Link struct {
			MSDs []bgp.LsMSDEntry `json:"msds"`
		} `json:"link"`
	}
	require.NoError(t, json.Unmarshal(data, &document))
	assert.Equal(t, wantNode, document.Node.MSDs)
	assert.Equal(t, wantLink, document.Link.MSDs)

	// Aggregation does not alias the original TLV entries.
	attribute.TLVs[0].(*bgp.LsTLVNodeMSD).Entries[0].Value = 99
	attribute.TLVs[1].(*bgp.LsTLVLinkMSD).Entries[0].Value = 99
	assert.Equal(t, wantNode, model.Node.MSDs)
	assert.Equal(t, wantLink, model.Link.MSDs)
}

func TestLsMSDAttributeModelOmitsAbsentValues(t *testing.T) {
	t.Parallel()
	for _, model := range []*bgp.LsAttribute{
		{},
		{Node: bgp.LsAttributeNode{MSDs: []bgp.LsMSDEntry{}}, Link: bgp.LsAttributeLink{MSDs: []bgp.LsMSDEntry{}}},
	} {
		attribute := &bgp.PathAttributeLs{TLVs: bgp.NewLsAttributeTLVs(model)}
		assert.Empty(t, attribute.TLVs)
		data, err := attribute.MarshalJSON()
		require.NoError(t, err)
		assert.NotContains(t, string(data), "msds")
	}
}
