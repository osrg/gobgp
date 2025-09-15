package bgp

import (
	"bytes"
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
