package bgp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Two SRv6 Information sub-TLVs (RFC 9252) packed into one SRv6 L3
// Service TLV. Each carries exactly one SID Structure sub-sub-TLV. The
// decoder must attribute each sub-sub-TLV to its own parent and must not
// read past the first sub-TLV's declared Length into the second.
func TestSRv6InformationSubTLV_DoesNotOverreadSibling(t *testing.T) {
	assert := assert.New(t)

	info := func(lastSIDByte, subSubFirst byte) []byte {
		return []byte{
			0x01, 0x00, 0x1e, // Type=1 (Information), Length=30
			0x00,                                                                                                  // Reserved
			0x20, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, lastSIDByte, // SID (16)
			0x00,       // Flags
			0x00, 0x13, // Endpoint Behavior
			0x00,                                                        // Reserved
			0x01, 0x00, 0x06, subSubFirst, 0x18, 0x10, 0x00, 0x10, 0x40, // SID Structure sub-sub-TLV
		}
	}

	body := append(info(0x01, 0x28), info(0x02, 0x30)...)
	// SRv6 L3 Service TLV: Type + Length + Reserved + two Information sub-TLVs
	raw := append([]byte{0x05, 0x00, byte(1 + len(body)), 0x00}, body...)

	s := &SRv6ServiceTLV{}
	assert.NoError(s.DecodeFromBytes(raw))
	assert.Equal(2, len(s.SubTLVs))

	first := s.SubTLVs[0].(*SRv6InformationSubTLV)
	second := s.SubTLVs[1].(*SRv6InformationSubTLV)
	assert.Equal(1, len(first.SubSubTLVs),
		"first Information sub-TLV must not absorb the sibling's bytes as its own sub-sub-TLVs")
	assert.Equal(1, len(second.SubSubTLVs))
}
