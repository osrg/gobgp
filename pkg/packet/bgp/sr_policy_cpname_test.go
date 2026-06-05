package bgp

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_TunnelEncapSubTLVSRCandidatePathName_RoundTrip verifies the
// packet-layer Serialize → DecodeFromBytes round-trip for the SR
// Candidate Path Name sub-TLV (RFC 9012 Section 2.4.4, IANA SR
// Policy Tunnel Encapsulation Sub-TLVs type 129).
//
// Prior to the fix, DecodeFromBytes used value[1:t.Len()] for the
// name slice. value carries the body only (length t.Length); t.Len()
// adds the 3-byte sub-TLV header on top, so the upper bound
// over-reads three bytes past the body. When the sub-TLV was the
// next-to-last entry inside a Tunnel-Encap attribute, the over-read
// consumed the next sub-TLV's header bytes, corrupted its parse, and
// the entire PathAttributeTunnelEncap was silently dropped at the
// receive layer.
func Test_TunnelEncapSubTLVSRCandidatePathName_RoundTrip(t *testing.T) {
	assert := assert.New(t)

	for _, name := range []string{"", "a", "cp-bisect", "candidate-path-with-a-very-long-name-1234567890"} {
		orig := NewTunnelEncapSubTLVSRCandidatePathName(name)
		raw, err := orig.Serialize()
		assert.NoError(err)
		assert.NotEmpty(raw)

		// Append trailing bytes that look like the start of another
		// sub-TLV. The decoder must not reach into them.
		trailer := []byte{0x80, 0x00, 0x06, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		combined := append(append([]byte{}, raw...), trailer...)

		got := &TunnelEncapSubTLVSRCandidatePathName{}
		assert.NoError(got.DecodeFromBytes(combined))
		assert.Equal(name, got.CandidatePathName,
			"Candidate Path Name must round-trip without over-reading the next sub-TLV")
		assert.True(bytes.Equal(combined[len(raw):], trailer),
			"trailer must remain intact in the underlying buffer")
	}
}

// Test_TunnelEncapSubTLVSRCandidatePathName_RejectsZeroLength locks
// in the malformed-attribute guard. The Reserved byte is mandatory,
// so a body of length zero is invalid.
func Test_TunnelEncapSubTLVSRCandidatePathName_RejectsZeroLength(t *testing.T) {
	// Build a wire-form sub-TLV with Length=0 manually: type 0x81,
	// 2-byte length 0x0000, no body.
	raw := []byte{0x81, 0x00, 0x00}
	got := &TunnelEncapSubTLVSRCandidatePathName{}
	err := got.DecodeFromBytes(raw)
	if err == nil {
		t.Fatalf("zero-length body must be rejected")
	}
}
