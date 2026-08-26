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

	assert.Equal(n1, n2)
}

func Test_VPLSNLRI_decodeRejectsUnsupportedLength(t *testing.T) {
	// Len() reports a fixed 19 bytes to the MP_(UN)REACH framing loop, so a
	// VPLS NLRI whose length field is not 17 must be rejected. Before the fix
	// the 12-byte BGP-AD form decoded successfully into a VPLSNLRI with a nil
	// RD, which both mis-framed the following NLRI and panicked on re-serialize.
	adNLRI := &VPLSNLRI{}
	// length = 12 (BGP-AD) followed by a 12-byte body.
	err := adNLRI.decodeFromBytes([]byte{0x00, 0x0c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	require.Error(t, err)
	assert.Nil(t, adNLRI.rd)

	// length = 32 (oversized) with a body long enough to get past the
	// len(data) >= length+2 check.
	longNLRI := &VPLSNLRI{}
	buf := make([]byte, 2+32)
	buf[1] = 0x20
	err = longNLRI.decodeFromBytes(buf)
	require.Error(t, err)
}

func Test_VPLSNLRI_mpReachRejectsBGPADNLRI(t *testing.T) {
	// A 12-byte RFC 6074 BGP-AD NLRI plus 5 trailing bytes is exactly the 19
	// bytes that VPLSNLRI.Len() reports, so the MP_REACH framing loop consumed
	// it without complaint. Before the fix, DecodeFromBytes returned no error
	// and left one VPLS route with a nil RD, which panicked on re-serialize.
	buf := []byte{
		0x90, 0x0e, 0x00, 0x1c, // MP_REACH_NLRI, extended length, 28 bytes
		0x00, 0x19, 0x41, // AFI 25 (L2VPN), SAFI 65 (VPLS)
		0x04, 0xc0, 0x00, 0x02, 0x07, // next hop 192.0.2.7
		0x00,       // SNPA count
		0x00, 0x0c, // NLRI length = 12 (BGP-AD)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // RD
		0x01, 0x02, 0x03, 0x04, // VSI-ID
		0x00, 0x00, 0x00, 0x00, 0x00, // padding up to Len()
	}
	m := &PathAttributeMpReachNLRI{}
	err := m.DecodeFromBytes(buf)
	require.Error(t, err)
	require.Empty(t, m.Value)
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
