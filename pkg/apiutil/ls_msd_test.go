package apiutil

import (
	"testing"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestLsMSDAPIRoundTrip(t *testing.T) {
	t.Parallel()
	input := &api.LsAttribute{
		Node: &api.LsAttributeNode{Msds: []*api.LsMSDEntry{
			{Type: 1, Value: 12}, {Type: 255, Value: 0}, {Type: 1, Value: 255},
		}},
		Link: &api.LsAttributeLink{Msds: []*api.LsMSDEntry{
			{Type: 0, Value: 0}, {Type: 1, Value: 8}, {Type: 1, Value: 8},
		}},
	}
	encoded, err := proto.Marshal(input)
	require.NoError(t, err)
	var transported api.LsAttribute
	require.NoError(t, proto.Unmarshal(encoded, &transported))
	native, err := UnmarshalLsAttribute(&transported)
	require.NoError(t, err)
	assert.Equal(t, []bgp.LsMSDEntry{{Type: 1, Value: 12}, {Type: 255, Value: 0}, {Type: 1, Value: 255}}, native.Node.MSDs)
	assert.Equal(t, []bgp.LsMSDEntry{{Type: 0, Value: 0}, {Type: 1, Value: 8}, {Type: 1, Value: 8}}, native.Link.MSDs)
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
	require.NotNil(t, output.Node)
	require.NotNil(t, output.Link)
	assert.True(t, proto.Equal(input.Node, output.Node))
	assert.True(t, proto.Equal(input.Link, output.Link))
}

func TestLsMSDAPIAbsent(t *testing.T) {
	t.Parallel()
	for _, input := range []*api.LsAttribute{
		{},
		{Node: &api.LsAttributeNode{}, Link: &api.LsAttributeLink{}},
	} {
		native, err := UnmarshalLsAttribute(input)
		require.NoError(t, err)
		assert.Empty(t, bgp.NewLsAttributeTLVs(native))
		output, err := NewLsAttributeFromNative(&bgp.PathAttributeLs{})
		require.NoError(t, err)
		assert.Empty(t, output.Node.Msds)
		assert.Empty(t, output.Link.Msds)
	}
}

func TestLsMSDAPIRejectInvalidValues(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		attr *api.LsAttribute
	}{
		{"nil node MSD", &api.LsAttribute{Node: &api.LsAttributeNode{Msds: []*api.LsMSDEntry{nil}}}},
		{"nil link MSD", &api.LsAttribute{Link: &api.LsAttributeLink{Msds: []*api.LsMSDEntry{nil}}}},
		{"node MSD type overflow", &api.LsAttribute{Node: &api.LsAttributeNode{Msds: []*api.LsMSDEntry{{Type: 256}}}}},
		{"node MSD value overflow", &api.LsAttribute{Node: &api.LsAttributeNode{Msds: []*api.LsMSDEntry{{Value: 256}}}}},
		{"link MSD type overflow", &api.LsAttribute{Link: &api.LsAttributeLink{Msds: []*api.LsMSDEntry{{Type: 256}}}}},
		{"link MSD value overflow", &api.LsAttribute{Link: &api.LsAttributeLink{Msds: []*api.LsMSDEntry{{Value: 256}}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := UnmarshalLsAttribute(test.attr)
			require.Error(t, err)
		})
	}
}
