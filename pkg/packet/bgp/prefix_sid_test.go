package bgp

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRoundTripSubSubTLV(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "SRv6SIDStructureSubSubTLV",
			input: []byte{0x01, 0x00, 0x06, 0x28, 0x18, 0x10, 0x00, 0x10, 0x40},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sstlv := &SRv6SIDStructureSubSubTLV{}
			if err := sstlv.DecodeFromBytes(tt.input); err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			recovered, err := sstlv.Serialize()
			if err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			if !bytes.Equal(tt.input, recovered) {
				t.Fatalf("round trip conversion test failed as expected prefix sid attribute %+v does not match actual: %+v", tt.input, recovered)
			}
		})
	}
}

func TestRoundTripSubTLV(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "SRv6InformationSubTLV",
			input: []byte{0x01, 0x00, 0x1e, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x01, 0x00, 0x06, 0x28, 0x18, 0x10, 0x00, 0x10, 0x40},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stlv := &SRv6InformationSubTLV{}
			if err := stlv.DecodeFromBytes(tt.input); err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			recovered, err := stlv.Serialize()
			if err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			if !bytes.Equal(tt.input, recovered) {
				t.Fatalf("round trip conversion test failed as expected prefix sid attribute %+v does not match actual: %+v", tt.input, recovered)
			}
		})
	}
}

func TestRoundTripPrefixSID(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "srv6 prefix sid",
			input: []byte{0xc0, 0x28, 0x25, 0x05, 0x00, 0x22, 0x00, 0x01, 0x00, 0x1e, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x01, 0x00, 0x06, 0x28, 0x18, 0x10, 0x00, 0x10, 0x40},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attribute, err := GetPathAttribute(tt.input)
			if err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			if err := attribute.DecodeFromBytes(tt.input); err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			recovered, err := attribute.Serialize()
			if err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			if !bytes.Equal(tt.input, recovered) {
				t.Fatalf("round trip conversion test failed as expected prefix sid attribute %+v does not match actual: %+v", tt.input, recovered)
			}
		})
	}
}

func TestNewPathAttributePrefixSID(t *testing.T) {
	prefix := netip.MustParsePrefix("2001:0:5:3::/64")
	tests := []struct {
		name string
		psid *PathAttributePrefixSID
		want []byte
	}{
		{
			name: "srv6 prefix sid",
			psid: NewPathAttributePrefixSID(
				NewSRv6ServiceTLV(
					TLVTypeSRv6L3Service,
					NewSRv6InformationSubTLV(
						prefix.Addr(),
						END_DT4,
						NewSRv6SIDStructureSubSubTLV(uint8(prefix.Bits()), 24, 16, 0, 16, 64),
					),
				),
			),
			want: []byte{0xc0, 0x28, 0x25, 0x05, 0x00, 0x22, 0x00, 0x01, 0x00, 0x1e, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x01, 0x00, 0x06, 0x40, 0x18, 0x10, 0x00, 0x10, 0x40},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.psid.Serialize()
			if err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Logf("psid: %s", tt.psid)
				t.Fatalf("got %x want %x", got, tt.want)
			}
		})
	}
}

func TestSRv6L3ServiceUnknownSubTLV(t *testing.T) {
	// SRv6L3ServiceAttribute with an unknown sub-TLV type (0xff).
	// Previously, the default branch advanced the wrong variable (data
	// instead of stlvs), causing an infinite loop.
	input := []byte{
		0x05,       // Type: TLVTypeSRv6L3Service
		0x00, 0x07, // Length: 7 (1 reserved + 6 sub-TLV)
		0x00, // Reserved
		// Unknown sub-TLV: Type=0xff, Length=3, Value=0x01,0x02,0x03
		0xff, 0x00, 0x03, 0x01, 0x02, 0x03,
	}
	s := &SRv6L3ServiceAttribute{}
	err := s.DecodeFromBytes(input)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(s.SubTLVs))
}

func TestSRv6ServiceTLVUnknownSubTLV(t *testing.T) {
	// SRv6ServiceTLV with an unknown sub-TLV type (0xff).
	// Same bug as SRv6L3ServiceAttribute.
	input := []byte{
		0x05,       // Type: TLVTypeSRv6L3Service
		0x00, 0x07, // Length: 7 (1 reserved + 6 sub-TLV)
		0x00, // Reserved
		// Unknown sub-TLV: Type=0xff, Length=3, Value=0x01,0x02,0x03
		0xff, 0x00, 0x03, 0x01, 0x02, 0x03,
	}
	s := &SRv6ServiceTLV{}
	err := s.DecodeFromBytes(input)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(s.SubTLVs))
}

func TestSRv6SIDStructureSubSubTLVLength(t *testing.T) {
	// RFC 9252 Section 3.2.1 fixes the SRv6 SID Structure Sub-Sub-TLV
	// Length at 6 octets. A shorter one used to be accepted while the
	// decoder still consumed the six structure bytes, and Serialize then
	// wrote those six bytes into a buffer sized from Length.
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "length 1",
			input: []byte{0x01, 0x00, 0x01, 0x28, 0x18, 0x10, 0x00, 0x10, 0x40},
		},
		{
			name:  "length 5",
			input: []byte{0x01, 0x00, 0x05, 0x28, 0x18, 0x10, 0x00, 0x10, 0x40},
		},
		{
			name:  "length 7",
			input: []byte{0x01, 0x00, 0x07, 0x28, 0x18, 0x10, 0x00, 0x10, 0x40, 0x00},
		},
		{
			name:  "truncated value",
			input: []byte{0x01, 0x00, 0x06, 0x28, 0x18, 0x10, 0x00, 0x10},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sstlv := &SRv6SIDStructureSubSubTLV{}
			assert.Error(t, sstlv.DecodeFromBytes(tt.input))
		})
	}
}

func TestSRv6InformationSubTLVLength(t *testing.T) {
	// RFC 9252 Section 7: the SRv6 SID Information Sub-TLV is malformed
	// when "The Sub-TLV Length is less than 21". A shorter one used to be
	// accepted while the decoder still consumed the 24 fixed bytes, and
	// Serialize then wrote them into a buffer sized from Length.
	sid := []byte{
		0x20, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x03,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	for _, length := range []uint16{0, 1, 16, 20} {
		t.Run(fmt.Sprintf("length %d", length), func(t *testing.T) {
			input := []byte{0x01, byte(length >> 8), byte(length), 0x00}
			input = append(input, sid...)
			input = append(input, 0x00, 0x00, 0x13, 0x00)

			stlv := &SRv6InformationSubTLV{}
			assert.Error(t, stlv.DecodeFromBytes(input))
		})
	}
}

func TestPathAttributePrefixSIDMalformedLength(t *testing.T) {
	// Both TLVs are reached through a full Prefix-SID attribute here: a
	// malformed length must be rejected at decode time, because the
	// attribute is re-serialized on the receive path (the attrs hash in
	// table.ProcessMessage) and any panic there takes down the daemon.
	tests := []struct {
		name  string
		input []byte
	}{
		{
			// SRv6 SID Structure Sub-Sub-TLV Length = 5.
			name:  "sub-sub-tlv length 5",
			input: []byte{0xc0, 0x28, 0x25, 0x05, 0x00, 0x22, 0x00, 0x01, 0x00, 0x1e, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x01, 0x00, 0x05, 0x28, 0x18, 0x10, 0x00, 0x10, 0x40},
		},
		{
			// SRv6 SID Information Sub-TLV Length = 16.
			name:  "sub-tlv length 16",
			input: []byte{0xc0, 0x28, 0x1c, 0x05, 0x00, 0x19, 0x00, 0x01, 0x00, 0x10, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attribute, err := GetPathAttribute(tt.input)
			assert.NoError(t, err)
			assert.Error(t, attribute.DecodeFromBytes(tt.input))

			// Serializing the partially decoded attribute must not
			// panic either. Whether it errors is not interesting; the
			// malformed TLV was never appended, so it may well succeed.
			assert.NotPanics(t, func() {
				_, _ = attribute.Serialize()
			})
		})
	}
}

func TestBGPUpdatePrefixSIDMalformedSubSubTLVLength(t *testing.T) {
	// A full UPDATE carrying an SRv6 SID Structure Sub-Sub-TLV that
	// declares Length = 5 while carrying the six structure bytes.
	raw, err := hex.DecodeString("ffffffffffffffffffffffffffffffff0073020000005c4001010040020602010000fdea800e2400015504c00002fe0001000317000000640000006418c000020000006409200a00000100c028250500220001001e002001000000050003000000000000000000001300010005281810001040")
	assert.NoError(t, err)

	msg, err := ParseBGPMessage(raw)
	assert.Error(t, err)
	if msg == nil {
		return
	}
	assert.NotPanics(t, func() {
		_, _ = msg.Serialize()
	})
}

// to make label with bottom of stack
type prefixSidLabel struct {
	Label uint32
	IPAddrPrefixDefault
}

func (l *prefixSidLabel) Serialize(options ...*MarshallingOption) ([]byte, error) {
	bits := 8*3 + l.Prefix.Bits()
	buf := []byte{byte(bits)}
	label := l.Label << 4
	lbuf := []byte{byte(label >> 16 & 0xff), byte(label >> 8 & 0xff), byte(label & 0xff)}
	buf = append(buf, lbuf...)
	buf = append(buf, l.serializePrefix()...)
	return buf, nil
}

func (l *prefixSidLabel) Flat() map[string]string {
	return map[string]string{}
}

func (l *prefixSidLabel) MarshalJSON() ([]byte, error) {
	return []byte{}, nil
}

func (l *prefixSidLabel) Len(options ...*MarshallingOption) int {
	return 0
}

func (l *prefixSidLabel) String() string {
	return ""
}

func TestLabelBottomWorkaround(t *testing.T) {
	assert := assert.New(t)
	label := uint32(16000)
	prefix := &prefixSidLabel{Label: label, IPAddrPrefixDefault: IPAddrPrefixDefault{Prefix: netip.MustParsePrefix("200.10.10.0/24")}}
	mpreach, _ := NewPathAttributeMpReachNLRI(RF_IPv4_MPLS, []PathNLRI{{NLRI: prefix}}, netip.MustParseAddr("4.4.4.4"))

	sid := NewPathAttributePrefixSID()

	binary, err := NewBGPUpdateMessage(nil, []PathAttributeInterface{mpreach, sid}, nil).Serialize()
	assert.NoError(err)

	msg, err := ParseBGPMessage(binary)
	assert.NoError(err)

	mpreach = msg.Body.(*BGPUpdate).PathAttributes[0].(*PathAttributeMpReachNLRI)
	assert.Equal(1, len(mpreach.Value))
	p := mpreach.Value[0].NLRI.(*LabeledIPAddrPrefix)
	assert.Equal(label, p.Labels.Labels[0])
}
