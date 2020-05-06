package bgp

import (
	"reflect"
	"testing"
)

func TestUnmarshalUnicastNLRI(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *PathAttributePrefixSID
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetPathAttribute(tt.input)
			if err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			if !reflect.DeepEqual(tt.expect, got) {
				t.Fatalf("test failed as expected nlri %+v does not match actual nlri %+v", tt.expect, got)
			}
		})
	}
}
