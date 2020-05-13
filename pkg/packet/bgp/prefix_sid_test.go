package bgp

import (
	"bytes"
	"testing"

	"github.com/golang/protobuf/ptypes/any"
	api "github.com/osrg/gobgp/api"
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
	tests := []struct {
		name  string
		input *api.PrefixSID
	}{
		{
			name: "path attribute srv6 prefix sid",
			input: &api.PrefixSID{
				Tlvs: []*any.Any{
					{
						TypeUrl: "type.googleapis.com/gobgpapi.SRv6L3ServiceTLV",
						Value:   []byte{10, 157, 1, 8, 1, 18, 152, 1, 10, 149, 1, 10, 50, 116, 121, 112, 101, 46, 103, 111, 111, 103, 108, 101, 97, 112, 105, 115, 46, 99, 111, 109, 47, 103, 111, 98, 103, 112, 97, 112, 105, 46, 83, 82, 118, 54, 73, 110, 102, 111, 114, 109, 97, 116, 105, 111, 110, 83, 117, 98, 84, 76, 86, 18, 95, 10, 16, 32, 1, 0, 0, 0, 5, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 18, 0, 24, 17, 34, 71, 8, 1, 18, 67, 10, 65, 10, 51, 116, 121, 112, 101, 46, 103, 111, 111, 103, 108, 101, 97, 112, 105, 115, 46, 99, 111, 109, 47, 103, 111, 98, 103, 112, 97, 112, 105, 46, 83, 82, 118, 54, 83, 116, 114, 117, 99, 116, 117, 114, 101, 83, 117, 98, 83, 117, 98, 84, 76, 86, 18, 10, 8, 40, 16, 24, 24, 16, 40, 16, 48, 64},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewPathAttributePrefixSID(tt.input)
			if err != nil {
				t.Fatalf("failed with error: %+v", err)
			}
			t.Logf("resulting prefix sid: %s", p.String())
			b, _ := p.Serialize()
			t.Logf("serialized prefix sid: %s", string(b))

		})
	}
}
