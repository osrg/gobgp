package bgp

import (
	"bytes"
	"testing"
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
			if bytes.Compare(tt.input, recovered) != 0 {
				t.Fatalf("round trip conversion test failed as expected prefix sid attribute %+v does not match actual: %+v", tt.input, recovered)
			}
		})
	}
}
