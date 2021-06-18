package bgp

import (
	"encoding/binary"
	"net"
	"reflect"
	"testing"

	"github.com/go-test/deep"
)

func TestBindingSIDRoundTrip(t *testing.T) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, 24321)
	bsid, _ := NewBSID(b)
	tests := []struct {
		name  string
		input *TunnelEncapSubTLVSRBSID
		fail  bool
	}{
		{
			name: "no bsid",
			input: &TunnelEncapSubTLVSRBSID{
				TunnelEncapSubTLV: TunnelEncapSubTLV{
					Type:   1,
					Length: 2,
				},
				Flags: 0x0,
				BSID:  nil,
			},
			fail: false,
		},
		{
			name: "v4 bsid",
			input: &TunnelEncapSubTLVSRBSID{
				TunnelEncapSubTLV: TunnelEncapSubTLV{
					Type:   1,
					Length: 6,
				},
				Flags: 0x0,
				BSID:  bsid,
			},
			fail: false,
		},
		{
			name: "srv6 bsid",
			input: &TunnelEncapSubTLVSRBSID{
				TunnelEncapSubTLV: TunnelEncapSubTLV{
					Type:   1,
					Length: 18,
				},
				Flags: 0x0,
				BSID: &BSID{
					Value: net.ParseIP("2001:1::1").To16(),
				},
			},
			fail: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := tt.input.Serialize()
			if err != nil && !tt.fail {
				t.Fatalf("expected to succeed but failed with error: %+v", err)
			}
			if err == nil && tt.fail {
				t.Fatal("Expected to fail but succeeded")
			}
			if err != nil {
				return
			}
			result := &TunnelEncapSubTLVSRBSID{}
			err = result.DecodeFromBytes(b)
			if err != nil && !tt.fail {
				t.Fatalf("expected to succeed but failed with error: %+v", err)
			}
			if err == nil && tt.fail {
				t.Fatal("Expected to fail but succeeded")
			}
			if err != nil {
				return
			}
			if !reflect.DeepEqual(tt.input, result) {
				t.Logf("Diffs: %+v", deep.Equal(tt.input, result))
				t.Fatalf("expected: %+v does not match result: %+v", tt.input, result)
			}
		})
	}
}

func TestSegmentListRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		input *TunnelEncapSubTLVSRSegmentList
		fail  bool
	}{
		{
			name: "empty Segment List Sub TLV",
			input: &TunnelEncapSubTLVSRSegmentList{
				TunnelEncapSubTLV: TunnelEncapSubTLV{
					Type:   ENCAP_SUBTLV_TYPE_SRSEGMENT_LIST,
					Length: 6, // Weight (6 bytes) + Length of each segment + 2
				},
			},
			fail: false,
		},
		{
			name: "only empty weight",
			input: &TunnelEncapSubTLVSRSegmentList{
				TunnelEncapSubTLV: TunnelEncapSubTLV{
					Type:   ENCAP_SUBTLV_TYPE_SRSEGMENT_LIST,
					Length: 6, // Weight (6 bytes) + Length of each segment + 2
				},
				Weight: &SegmentListWeight{
					TunnelEncapSubTLV: TunnelEncapSubTLV{
						Type:   9,
						Length: 6,
					},
					Flags:  0,
					Weight: 100,
				},
			},
			fail: false,
		},
		{
			name: "weight and 1 type A segment",
			input: &TunnelEncapSubTLVSRSegmentList{
				TunnelEncapSubTLV: TunnelEncapSubTLV{
					Type:   ENCAP_SUBTLV_TYPE_SRSEGMENT_LIST,
					Length: 6, // Weight (6 bytes) + Length of each segment + 2
				},
				Weight: &SegmentListWeight{
					TunnelEncapSubTLV: TunnelEncapSubTLV{
						Type:   SegmentListSubTLVWeight,
						Length: 6,
					},
					Flags:  0,
					Weight: 100,
				},
				Segments: []TunnelEncapSubTLVInterface{
					&SegmentTypeA{
						TunnelEncapSubTLV: TunnelEncapSubTLV{
							Type:   EncapSubTLVType(TypeA),
							Length: 6,
						},
						Flags: 0,
						Label: (21431 << 12),
					},
				},
			},
			fail: false,
		},
		{
			name: "weight and 2 type A segment",
			input: &TunnelEncapSubTLVSRSegmentList{
				TunnelEncapSubTLV: TunnelEncapSubTLV{
					Type:   ENCAP_SUBTLV_TYPE_SRSEGMENT_LIST,
					Length: 6, // Weight (6 bytes) + Length of each segment + 2
				},
				Weight: &SegmentListWeight{
					TunnelEncapSubTLV: TunnelEncapSubTLV{
						Type:   SegmentListSubTLVWeight,
						Length: 6,
					},
					Flags:  0,
					Weight: 100,
				},
				Segments: []TunnelEncapSubTLVInterface{
					&SegmentTypeA{
						TunnelEncapSubTLV: TunnelEncapSubTLV{
							Type:   EncapSubTLVType(TypeA),
							Length: 6,
						},
						Flags: 0,
						Label: (21431 << 12),
					},
					&SegmentTypeA{
						TunnelEncapSubTLV: TunnelEncapSubTLV{
							Type:   EncapSubTLVType(TypeA),
							Length: 6,
						},
						Flags: 0,
						Label: (100001 << 12),
					},
				},
			},
			fail: false,
		},
		{
			name: "weight and 2 type B segment without SRv6 Endpoint Behavior and Structure",
			input: &TunnelEncapSubTLVSRSegmentList{
				TunnelEncapSubTLV: TunnelEncapSubTLV{
					Type:   ENCAP_SUBTLV_TYPE_SRSEGMENT_LIST,
					Length: 6, // Weight (6 bytes) + Length of each segment + 2
				},
				Weight: &SegmentListWeight{
					TunnelEncapSubTLV: TunnelEncapSubTLV{
						Type:   SegmentListSubTLVWeight,
						Length: 6,
					},
					Flags:  0,
					Weight: 100,
				},
				Segments: []TunnelEncapSubTLVInterface{
					&SegmentTypeB{
						TunnelEncapSubTLV: TunnelEncapSubTLV{Type: EncapSubTLVType(TypeB), Length: 6},
						Flags:             0,
						SID:               net.ParseIP("2001:1::1").To16(),
					},
					&SegmentTypeB{
						TunnelEncapSubTLV: TunnelEncapSubTLV{Type: EncapSubTLVType(TypeB), Length: 6},
						Flags:             0,
						SID:               net.ParseIP("2001:1::2").To16(),
					},
				},
			},
			fail: false,
		},
		{
			name: "weight and 2 type B segment with SR Endpoint Behavior and Structure",
			input: &TunnelEncapSubTLVSRSegmentList{
				TunnelEncapSubTLV: TunnelEncapSubTLV{
					Type:   ENCAP_SUBTLV_TYPE_SRSEGMENT_LIST,
					Length: 6, // Weight (6 bytes) + Length of each segment + 2
				},
				Weight: &SegmentListWeight{
					TunnelEncapSubTLV: TunnelEncapSubTLV{
						Type:   SegmentListSubTLVWeight,
						Length: 6,
					},
					Flags:  0,
					Weight: 100,
				},
				Segments: []TunnelEncapSubTLVInterface{
					&SegmentTypeB{
						TunnelEncapSubTLV: TunnelEncapSubTLV{Type: EncapSubTLVType(TypeB), Length: 6},
						Flags:             0,
						SID:               net.ParseIP("2001:1::1").To16(),
						SRv6EBS: &SRv6EndpointBehaviorStructure{
							Behavior: 39,
							BlockLen: 5,
							NodeLen:  6,
							FuncLen:  7,
							ArgLen:   8,
						},
					},
					&SegmentTypeB{
						TunnelEncapSubTLV: TunnelEncapSubTLV{Type: EncapSubTLVType(TypeB), Length: 6},
						Flags:             0,
						SID:               net.ParseIP("2001:1::2").To16(),
					},
				},
			},
			fail: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := tt.input.Serialize()
			if err != nil && !tt.fail {
				t.Fatalf("expected to succeed but failed with error: %+v", err)
			}
			if err == nil && tt.fail {
				t.Fatal("Expected to fail but succeeded")
			}
			if err != nil {
				return
			}
			result := &TunnelEncapSubTLVSRSegmentList{}
			err = result.DecodeFromBytes(b)
			if err != nil && !tt.fail {
				t.Fatalf("expected to succeed but failed with error: %+v", err)
			}
			if err == nil && tt.fail {
				t.Fatal("Expected to fail but succeeded")
			}
			if err != nil {
				return
			}
			if !reflect.DeepEqual(tt.input, result) {
				t.Logf("Diffs: %+v", deep.Equal(tt.input, result))
				t.Fatalf("expected: %+v does not match result: %+v", tt.input, result)
			}
		})
	}
}
