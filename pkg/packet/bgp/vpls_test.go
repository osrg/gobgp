package bgp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_VPLSExtended(t *testing.T) {
	assert := assert.New(t)
	exts := make([]ExtendedCommunityInterface, 0)
	exts = append(exts, NewVPLSExtended(100, 1500))
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

func Test_VPLSExtended_decoding(t *testing.T) {
	assert := assert.New(t)
	buf := []byte{
		0xc0, 0x10, 0x10, 0x00, 0x02, 0xfd, 0xf9, 0x00, 0x00, 0x00,
		0x68, 0x80, 0x0a, 0x13, 0x00, 0x05, 0xdc, 0x00, 0x64,
	}
	m1 := NewPathAttributeExtendedCommunities(nil)
	err := m1.DecodeFromBytes(buf)
	require.NoError(t, err)

	exts := make([]ExtendedCommunityInterface, 0)
	exts = append(exts, NewTwoOctetAsSpecificExtended(EC_SUBTYPE_ROUTE_TARGET, 65017, 104, true), NewVPLSExtended(0, 1500))
	m2 := NewPathAttributeExtendedCommunities(exts)

	assert.Equal(m1, m2)
}

func Test_VPLSNLRI(t *testing.T) {
	assert := assert.New(t)
	n1 := NewVPLSNLRI(NewRouteDistinguisherTwoOctetAS(65500, 10), 1, 3, 8, 100)
	buf1, err := n1.Serialize()
	assert.Nil(err)
	n2 := &VPLSNLRI{}
	err = n2.DecodeFromBytes(buf1)
	assert.Nil(err)

	t.Logf("%s", n1)
	t.Logf("%s", n2)

	assert.Equal(n1, n1)
}

func Test_VPLSNLRI_decoding(t *testing.T) {
	assert := assert.New(t)
	buf := []byte{
		0x90, 0x0e, 0x00, 0x1c, 0x00, 0x19, 0x41, 0x04, 0xc0, 0x00, 0x02,
		0x07, 0x00, 0x00, 0x11, 0x00, 0x00, 0xfd, 0xf9, 0x00, 0x00, 0x00,
		0x68, 0x00, 0x01, 0x00, 0x01, 0x00, 0x08, 0xc3, 0x50, 0x01,
	}
	m1 := NewPathAttributeMpReachNLRI("", nil)
	err := m1.DecodeFromBytes(buf)
	require.NoError(t, err)

	ns := make([]AddrPrefixInterface, 0)
	ns = append(ns, NewVPLSNLRI(NewRouteDistinguisherTwoOctetAS(65017, 104), 1, 1, 8, 800000))
	m2 := NewPathAttributeMpReachNLRI("192.0.2.7", ns)
	m2.PathAttribute.Flags |= BGP_ATTR_FLAG_EXTENDED_LENGTH

	assert.Equal(m1, m2)
}
