package bgp

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"reflect"
	"strings"
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
				BSID:  &BSID{Value: make([]byte, 0)},
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

func TestSRBSIDNoBSIDRendering(t *testing.T) {
	// A length-2 SR Binding SID sub-TLV has flags and reserved byte but no
	// BSID value. String() and MarshalJSON() must not panic when BSID is absent.
	tlv := &TunnelEncapSubTLVSRBSID{
		TunnelEncapSubTLV: TunnelEncapSubTLV{Type: 1, Length: 2},
		Flags:             0x80,
	}
	b, err := tlv.Serialize()
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}
	result := &TunnelEncapSubTLVSRBSID{}
	if err := result.DecodeFromBytes(b); err != nil {
		t.Fatalf("DecodeFromBytes failed: %v", err)
	}

	s := result.String()
	if !strings.Contains(s, "n/a") {
		t.Errorf("String() should contain \"n/a\" for absent BSID, got: %s", s)
	}

	if _, err := json.Marshal(result); err != nil {
		t.Errorf("MarshalJSON() returned error: %v", err)
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
						Label: 21431 << 12,
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
						Label: 21431 << 12,
					},
					&SegmentTypeA{
						TunnelEncapSubTLV: TunnelEncapSubTLV{
							Type:   EncapSubTLVType(TypeA),
							Length: 6,
						},
						Flags: 0,
						Label: 100001 << 12,
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

func Test_SRPolicyNLRIEndpointClampedToLength(t *testing.T) {
	// Two SR Policy IPv4 NLRIs packed in one MP_REACH buffer. Each NLRI is
	// 13 bytes: length(1) + distinguisher(4) + color(4) + endpoint(4).
	mkV4 := func(ep [4]byte) []byte {
		b := []byte{SRPolicyIPv4NLRILen, 0, 0, 0, 1, 0, 0, 0, 2}
		return append(b, ep[:]...)
	}
	buf := append(mkV4([4]byte{10, 0, 0, 1}), mkV4([4]byte{10, 0, 0, 2})...)

	n, err := NLRIFromSlice(RF_SR_POLICY_IPv4, buf)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	s := n.(*SRPolicyNLRI)
	if len(s.Endpoint) != 4 {
		t.Fatalf("endpoint absorbed sibling NLRI bytes: got %d bytes (%x), want 4", len(s.Endpoint), s.Endpoint)
	}
	if got := net.IP(s.Endpoint).To4().String(); got != "10.0.0.1" {
		t.Fatalf("endpoint mismatch: got %s, want 10.0.0.1", got)
	}

	// IPv6 endpoint is 16 bytes.
	v6 := []byte{SRPolicyIPv6NLRILen, 0, 0, 0, 1, 0, 0, 0, 2}
	v6 = append(v6, net.ParseIP("2001:db8::1").To16()...)
	v6 = append(v6, 0xde, 0xad) // trailing bytes from a following NLRI
	n, err = NLRIFromSlice(RF_SR_POLICY_IPv6, v6)
	if err != nil {
		t.Fatalf("decode v6 failed: %v", err)
	}
	if got := len(n.(*SRPolicyNLRI).Endpoint); got != 16 {
		t.Fatalf("v6 endpoint absorbed trailing bytes: got %d bytes, want 16", got)
	}
}
