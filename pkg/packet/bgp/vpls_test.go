package bgp

import (
	"net/netip"
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
	assert.NoError(err)
	n2 := &VPLSNLRI{}
	err = n2.decodeFromBytes(buf1)
	assert.NoError(err)

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
	m1 := &PathAttributeMpReachNLRI{}
	err := m1.DecodeFromBytes(buf)
	require.NoError(t, err)

	rd := NewRouteDistinguisherTwoOctetAS(65017, 104)
	nlri := NewVPLSNLRI(rd, 1, 1, 8, 800000)
	m2, _ := NewPathAttributeMpReachNLRI(RF_VPLS, []PathNLRI{{NLRI: nlri}}, netip.MustParseAddr("192.0.2.7"))
	m2.Flags |= BGP_ATTR_FLAG_EXTENDED_LENGTH

	assert.Equal(m1, m2)
}
