// Copyright (C) 2026 The GoBGP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package apiutil

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func Test_LsSrPolicyCandidatePathNLRIRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		in   *api.LsSrPolicyCandidatePathNLRI
		str  string
	}{
		{
			"ipv4",
			&api.LsSrPolicyCandidatePathNLRI{
				LocalNode: &api.LsNodeDescriptor{Asn: 65001, BgpRouterId: "1.1.1.1", LocalRouterIdIpv4: "10.0.0.1"},
				CandidatePathDescriptor: &api.LsSrPolicyCandidatePathDescriptor{
					ProtocolOrigin:    20,
					Endpoint:          "10.0.0.2",
					Color:             100,
					OriginatorAsn:     65001,
					OriginatorAddress: "1.1.1.1",
					Discriminator:     1,
				},
			},
			"NLRI { SRPOLICY_CP { LOCAL_NODE: {ASN: 65001, BGP LS ID: 0, BGP ROUTER ID: 1.1.1.1, IPv4 ROUTER ID: 10.0.0.1} ENDPOINT: 10.0.0.2 COLOR: 100 ORIGIN: 20 ORIGINATOR: 65001/1.1.1.1 DISCRIMINATOR: 1 SR:7 } }",
		},
		{
			"ipv6",
			&api.LsSrPolicyCandidatePathNLRI{
				LocalNode: &api.LsNodeDescriptor{Asn: 65001, IgpRouterId: "0000.0000.0001", LocalRouterIdIpv6: "2001:db8::1"},
				CandidatePathDescriptor: &api.LsSrPolicyCandidatePathDescriptor{
					ProtocolOrigin:    10,
					Endpoint:          "2001:db8::2",
					Color:             200,
					OriginatorAsn:     65002,
					OriginatorAddress: "2001:db8::1",
					Discriminator:     2,
				},
			},
			"NLRI { SRPOLICY_CP { LOCAL_NODE: {ASN: 65001, BGP LS ID: 0, IGP ROUTER ID: 0000.0000.0001, IPv6 ROUTER ID: 2001:db8::1} ENDPOINT: 2001:db8::2 COLOR: 200 ORIGIN: 10 ORIGINATOR: 65002/2001:db8::1 DISCRIMINATOR: 2 SR:7 } }",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert := assert.New(t)
			input := &api.NLRI{Nlri: &api.NLRI_LsAddrPrefix{LsAddrPrefix: &api.LsAddrPrefix{
				Type:       api.LsNLRIType_LS_NLRI_TYPE_SR_POLICY_CANDIDATE_PATH,
				Nlri:       &api.LsAddrPrefix_LsNLRI{Nlri: &api.LsAddrPrefix_LsNLRI_SrPolicyCandidatePath{SrPolicyCandidatePath: test.in}},
				ProtocolId: api.LsProtocolID_LS_PROTOCOL_ID_SEGMENT_ROUTING,
				Identifier: 7,
			}}}

			native, err := UnmarshalNLRI(bgp.RF_LS, input)
			require.NoError(t, err)
			assert.Equal(test.str, native.String())

			// The wire encoding decodes back to the same NLRI.
			wire, err := native.Serialize()
			require.NoError(t, err)
			decoded, err := bgp.NLRIFromSlice(bgp.RF_LS, wire)
			require.NoError(t, err)
			assert.Equal(test.str, decoded.String())

			output, err := MarshalNLRI(decoded)
			assert.NoError(err)
			// Length is computed by the unmarshaller and filled in on output.
			input.GetLsAddrPrefix().Length = output.GetLsAddrPrefix().Length
			assert.True(proto.Equal(input, output), "got %v", output)
		})
	}
}

func Test_LsSrPolicyCandidatePathNLRIUnmarshalErrors(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		name string
		in   *api.LsSrPolicyCandidatePathNLRI
	}{
		{"missing descriptor", &api.LsSrPolicyCandidatePathNLRI{LocalNode: &api.LsNodeDescriptor{Asn: 1, BgpRouterId: "1.1.1.1"}}},
		{"bad endpoint", &api.LsSrPolicyCandidatePathNLRI{
			LocalNode:               &api.LsNodeDescriptor{Asn: 1, BgpRouterId: "1.1.1.1"},
			CandidatePathDescriptor: &api.LsSrPolicyCandidatePathDescriptor{Endpoint: "nope", OriginatorAddress: "1.1.1.1"},
		}},
		{"bad originator", &api.LsSrPolicyCandidatePathNLRI{
			LocalNode:               &api.LsNodeDescriptor{Asn: 1, BgpRouterId: "1.1.1.1"},
			CandidatePathDescriptor: &api.LsSrPolicyCandidatePathDescriptor{Endpoint: "10.0.0.1", OriginatorAddress: ""},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := UnmarshalLsSrPolicyCandidatePathNLRI(test.in, bgp.LS_PROTOCOL_SEGMENT_ROUTING, 0)
			assert.Error(err)
		})
	}
}

func Test_LsAttributeSrPolicyRoundTrip(t *testing.T) {
	assert := assert.New(t)

	input := &api.LsAttribute{
		SrPolicy: &api.LsAttributeSrPolicy{
			BindingSid: &api.LsSrBindingSID{
				Flags: &api.LsSrBindingSIDFlags{Allocated: true, FromSrlb: true},
				Label: 24001,
			},
			Srv6BindingSids: []*api.LsSrv6BindingSID{{
				Flags:            &api.LsSrv6BindingSIDFlags{Allocated: true, Fallback: true},
				Sid:              "fc00:0:1::1",
				SpecifiedSid:     "fc00:0:1::2",
				EndpointBehavior: &api.LsSrv6EndpointBehavior{EndpointBehavior: 48},
				SidStructure:     &api.LsSrv6SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16, LocalArg: 64},
			}, {
				Flags:            &api.LsSrv6BindingSIDFlags{Allocated: true},
				Sid:              "fc00:0:1::3",
				SpecifiedSid:     "::",
				EndpointBehavior: &api.LsSrv6EndpointBehavior{EndpointBehavior: 49},
			}},
			State: &api.LsSrCandidatePathState{
				Priority:   10,
				Flags:      &api.LsSrCandidatePathStateFlags{Active: true, Evaluated: true, ValidSidList: true, Delegated: true},
				Preference: 200,
			},
			CandidatePathName: proto.String("cp1"),
			PolicyName:        proto.String("blue"),
			Constraints: &api.LsSrCandidatePathConstraints{
				Flags:     &api.LsSrCandidatePathConstraintsFlags{Srv6: true, ProtectedOnly: true, Strict: true, HopByHop: true},
				Mtid:      3,
				Algorithm: 128,
				Affinity:  &api.LsSrAffinityConstraint{ExcludeAny: []uint32{0xff}, IncludeAll: []uint32{1, 0x80000000}},
				Srlgs:     []uint32{10, 20},
				Bandwidth: &api.LsSrBandwidthConstraint{Bandwidth: 5e8},
				DisjointGroup: &api.LsSrDisjointGroupConstraint{
					RequestFlags: &api.LsSrDisjointGroupRequestFlags{Srlg: true, Link: true, Fallback: true},
					StatusFlags:  &api.LsSrDisjointGroupStatusFlags{Link: true, Fallback: true},
					GroupId:      7,
				},
				BidirectionalGroup: &api.LsSrBidirectionalGroupConstraint{
					Flags:           &api.LsSrBidirectionalGroupFlags{Reverse: true},
					PcepAssociation: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
				},
				Metrics: []*api.LsSrMetricConstraint{
					{MetricType: 1, Flags: &api.LsSrMetricConstraintFlags{Optimization: true}},
					{MetricType: 2, Flags: &api.LsSrMetricConstraintFlags{Margin: true, Bound: true}, Margin: 10, Bound: 500},
				},
			},
			SegmentLists: []*api.LsSrSegmentList{
				{
					Flags:  &api.LsSrSegmentListFlags{Explicit: true, Verified: true},
					Weight: 1,
					Segments: []*api.LsSrSegment{
						{SegmentType: api.LsSrSegmentType_LS_SR_SEGMENT_TYPE_A_MPLS_LABEL, Flags: &api.LsSrSegmentFlags{SidPresent: true, Explicit: true}, Label: 16001},
						{SegmentType: api.LsSrSegmentType_LS_SR_SEGMENT_TYPE_C_IPV4_NODE, Flags: &api.LsSrSegmentFlags{SidPresent: true, Explicit: true}, Label: 16002, LocalAddress: "10.0.0.3", Algorithm: 128},
						{SegmentType: api.LsSrSegmentType_LS_SR_SEGMENT_TYPE_F_IPV4_ADJACENCY, Flags: &api.LsSrSegmentFlags{SidPresent: true, Explicit: true}, Label: 24006, LocalAddress: "10.0.0.6", RemoteAddress: "10.0.0.7"},
						{SegmentType: api.LsSrSegmentType_LS_SR_SEGMENT_TYPE_G_IPV6_NODE_INTERFACE_MPLS, Flags: &api.LsSrSegmentFlags{SidPresent: true}, Label: 24007, LocalAddress: "2001:db8::7", LocalInterfaceId: 70, RemoteAddress: "2001:db8::8", RemoteInterfaceId: 80},
					},
					Metrics: []*api.LsSrSegmentListMetric{
						{MetricType: 1, Flags: &api.LsSrSegmentListMetricFlags{Value: true}, Value: 30},
						{MetricType: 2, Flags: &api.LsSrSegmentListMetricFlags{Bound: true, Margin: true, Absolute: true}, Bound: 100, Margin: 5},
					},
					Bandwidth:  &api.LsSrSegmentListBandwidth{Bandwidth: 1e9},
					Identifier: &api.LsSrSegmentListIdentifier{Identifier: 7},
				},
				{
					Flags:  &api.LsSrSegmentListFlags{Srv6: true, Explicit: true},
					Weight: 2,
					Mtid:   3,
					Segments: []*api.LsSrSegment{
						{
							SegmentType:      api.LsSrSegmentType_LS_SR_SEGMENT_TYPE_B_SRV6_SID,
							Flags:            &api.LsSrSegmentFlags{SidPresent: true, Explicit: true},
							Sid:              "fc00:0:2::1",
							EndpointBehavior: &api.LsSrv6EndpointBehavior{EndpointBehavior: 48},
							SidStructure:     &api.LsSrv6SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16, LocalArg: 64},
						},
						{SegmentType: api.LsSrSegmentType_LS_SR_SEGMENT_TYPE_J_IPV6_NODE_INTERFACE_SRV6, Flags: &api.LsSrSegmentFlags{SidPresent: true, Explicit: true}, Sid: "fc00:0:4::1", LocalAddress: "2001:db8::4", LocalInterfaceId: 1, RemoteAddress: "2001:db8::5", RemoteInterfaceId: 2},
					},
				},
			},
		},
	}

	native, err := UnmarshalLsAttribute(input)
	assert.NoError(err)
	if assert.NotNil(native.SrPolicy.BindingSID) {
		assert.EqualValues(24001, native.SrPolicy.BindingSID.Label)
		assert.True(native.SrPolicy.BindingSID.Flags.FromSRLB)
	}
	if assert.NotNil(native.SrPolicy.State) {
		assert.True(native.SrPolicy.State.Flags.Active)
		assert.EqualValues(200, native.SrPolicy.State.Preference)
	}
	assert.Len(native.SrPolicy.SegmentLists, 2)
	if assert.NotNil(native.SrPolicy.Constraints) {
		assert.True(native.SrPolicy.Constraints.Flags.HopByHop)
		assert.Equal([]uint32{10, 20}, native.SrPolicy.Constraints.SRLGs)
		assert.Equal([]byte{0, 1, 2, 3, 4, 5}, native.SrPolicy.Constraints.BidirectionalGroup.PcepAssociation)
	}

	// Encode to the wire and decode again, as gobgpd does between peers.
	built := &bgp.PathAttributeLs{
		PathAttribute: bgp.PathAttribute{Flags: bgp.BGP_ATTR_FLAG_OPTIONAL, Type: bgp.BGP_ATTR_TYPE_LS},
		TLVs:          bgp.NewLsAttributeTLVs(native),
	}
	wire, err := built.Serialize()
	assert.NoError(err)
	decoded := &bgp.PathAttributeLs{}
	assert.NoError(decoded.DecodeFromBytes(wire))

	output, err := NewLsAttributeFromNative(decoded)
	assert.NoError(err)
	assert.True(proto.Equal(input.SrPolicy, output.SrPolicy), "got %v", output.SrPolicy)

	// An attribute without SR Policy TLVs yields an empty SR Policy message.
	empty, err := NewLsAttributeFromNative(&bgp.PathAttributeLs{})
	assert.NoError(err)
	assert.True(proto.Equal(&api.LsAttributeSrPolicy{}, empty.SrPolicy))
}

func Test_LsAttributeSrPolicyUnmarshalErrors(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		name string
		in   *api.LsAttributeSrPolicy
	}{
		{"bad binding sid", &api.LsAttributeSrPolicy{BindingSid: &api.LsSrBindingSID{Sid: "x"}}},
		{"bad srv6 binding sid", &api.LsAttributeSrPolicy{Srv6BindingSids: []*api.LsSrv6BindingSID{{Sid: "x"}}}},
		{"priority out of range", &api.LsAttributeSrPolicy{State: &api.LsSrCandidatePathState{Priority: 256}}},
		{"bad segment address", &api.LsAttributeSrPolicy{SegmentLists: []*api.LsSrSegmentList{{Segments: []*api.LsSrSegment{{LocalAddress: "x"}}}}}},
		{"segment type out of range", &api.LsAttributeSrPolicy{SegmentLists: []*api.LsSrSegmentList{{Segments: []*api.LsSrSegment{{SegmentType: 300}}}}}},
		{"mtid out of range", &api.LsAttributeSrPolicy{SegmentLists: []*api.LsSrSegmentList{{Mtid: 70000}}}},
		{"constraints mtid out of range", &api.LsAttributeSrPolicy{Constraints: &api.LsSrCandidatePathConstraints{Mtid: 70000}}},
		{"constraints algorithm out of range", &api.LsAttributeSrPolicy{Constraints: &api.LsSrCandidatePathConstraints{Algorithm: 256}}},
		{"affinity too long", &api.LsAttributeSrPolicy{Constraints: &api.LsSrCandidatePathConstraints{Affinity: &api.LsSrAffinityConstraint{IncludeAny: make([]uint32, 256)}}}},
		{"constraint bandwidth negative", &api.LsAttributeSrPolicy{Constraints: &api.LsSrCandidatePathConstraints{Bandwidth: &api.LsSrBandwidthConstraint{Bandwidth: -1}}}},
		{"short pcep association", &api.LsAttributeSrPolicy{Constraints: &api.LsSrCandidatePathConstraints{DisjointGroup: &api.LsSrDisjointGroupConstraint{PcepAssociation: []byte{1, 2, 3}}}}},
		{"metric constraint type out of range", &api.LsAttributeSrPolicy{Constraints: &api.LsSrCandidatePathConstraints{Metrics: []*api.LsSrMetricConstraint{{MetricType: 256}}}}},
		{"constraints exceed the TLV size", &api.LsAttributeSrPolicy{Constraints: &api.LsSrCandidatePathConstraints{BidirectionalGroup: &api.LsSrBidirectionalGroupConstraint{PcepAssociation: make([]byte, 0x10000)}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := UnmarshalLsAttributeSrPolicy(test.in)
			assert.Error(err)
		})
	}
}

func TestLsSrPolicyHeadendValidation(t *testing.T) {
	valid := &api.LsSrPolicyCandidatePathNLRI{
		LocalNode:               &api.LsNodeDescriptor{Asn: 65001, BgpRouterId: "1.1.1.1", LocalRouterIdIpv4: "10.0.0.1"},
		CandidatePathDescriptor: &api.LsSrPolicyCandidatePathDescriptor{ProtocolOrigin: 3, Endpoint: "10.0.0.2", OriginatorAddress: "1.1.1.1"},
	}
	for _, tt := range []struct {
		name     string
		change   func(*api.LsSrPolicyCandidatePathNLRI)
		protocol bgp.LsProtocolID
		wantErr  bool
	}{
		{"headend", func(n *api.LsSrPolicyCandidatePathNLRI) {}, 9, false},
		// The conversion is no stricter than the wire decoder (RFC 9552
		// section 8.2.2): a nonconforming route learned from a peer must
		// convert back, so an odd Protocol-ID or a headend without a
		// Router-ID or ASN is accepted. Only what cannot be encoded at
		// all is refused.
		{"wrong protocol", func(n *api.LsSrPolicyCandidatePathNLRI) {}, 2, false},
		{"missing Router-ID", func(n *api.LsSrPolicyCandidatePathNLRI) { n.LocalNode.LocalRouterIdIpv4 = "" }, 9, false},
		{"headend missing ASN", func(n *api.LsSrPolicyCandidatePathNLRI) { n.LocalNode.Asn = 0 }, 9, false},
		{"IPv6 in IPv4 Router-ID", func(n *api.LsSrPolicyCandidatePathNLRI) { n.LocalNode.LocalRouterIdIpv4 = "2001:db8::1" }, 9, true},
		{"IPv4 in IPv6 Router-ID", func(n *api.LsSrPolicyCandidatePathNLRI) { n.LocalNode.LocalRouterIdIpv6 = "10.0.0.1" }, 9, true},
		{"zoned Router-ID", func(n *api.LsSrPolicyCandidatePathNLRI) { n.LocalNode.LocalRouterIdIpv6 = "fe80::1%eth0" }, 9, true},
		{"IPv6 BGP Router-ID", func(n *api.LsSrPolicyCandidatePathNLRI) { n.LocalNode.BgpRouterId = "2001:db8::1" }, 9, true},
		{"PCE with only headend address", func(n *api.LsSrPolicyCandidatePathNLRI) {
			n.LocalNode = &api.LsNodeDescriptor{LocalRouterIdIpv6: "2001:db8::1"}
			n.CandidatePathDescriptor.ProtocolOrigin = 30
		}, 9, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			input := proto.Clone(valid).(*api.LsSrPolicyCandidatePathNLRI)
			tt.change(input)
			nlri, err := UnmarshalLsSrPolicyCandidatePathNLRI(input, tt.protocol, 0)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			wire, err := nlri.Serialize()
			require.NoError(t, err)
			decoded, err := bgp.NLRIFromSlice(bgp.RF_LS, wire)
			require.NoError(t, err)
			output, err := MarshalNLRI(decoded)
			require.NoError(t, err)
			require.True(t, proto.Equal(input, output.GetLsAddrPrefix().GetNlri().GetSrPolicyCandidatePath()))
		})
	}
}

func TestLsSrSegmentValidation(t *testing.T) {
	for _, tt := range []struct {
		name    string
		segment *api.LsSrSegment
	}{
		{"negative type", &api.LsSrSegment{SegmentType: -1}},
		{"unknown type", &api.LsSrSegment{SegmentType: 12}},
		{"missing descriptor", &api.LsSrSegment{SegmentType: 3}},
		{"IPv6 in IPv4 node", &api.LsSrSegment{SegmentType: 3, LocalAddress: "2001:db8::1"}},
		{"IPv6 in IPv4 interface", &api.LsSrSegment{SegmentType: 5, LocalAddress: "2001:db8::1"}},
		{"IPv6 in IPv4 adjacency", &api.LsSrSegment{SegmentType: 6, LocalAddress: "10.0.0.1", RemoteAddress: "2001:db8::2"}},
		{"IPv4 in IPv6 node", &api.LsSrSegment{SegmentType: 4, LocalAddress: "10.0.0.1"}},
		{"IPv4 in IPv6 adjacency", &api.LsSrSegment{SegmentType: 8, LocalAddress: "2001:db8::1", RemoteAddress: "10.0.0.2"}},
		{"IPv4 SID", &api.LsSrSegment{SegmentType: 2, Sid: "10.0.0.1"}},
		{"zoned SID", &api.LsSrSegment{SegmentType: 2, Sid: "fe80::1%eth0"}},
		{"SID on MPLS", &api.LsSrSegment{SegmentType: 1, Sid: "2001:db8::1"}},
		{"label on SRv6", &api.LsSrSegment{SegmentType: 2, Label: 16000}},
		{"label overflow", &api.LsSrSegment{SegmentType: 1, Label: 1 << 20}},
		{"behavior overflow", &api.LsSrSegment{SegmentType: 2, EndpointBehavior: &api.LsSrv6EndpointBehavior{EndpointBehavior: 1 << 16}}},
		{"structure overflow", &api.LsSrSegment{SegmentType: 2, SidStructure: &api.LsSrv6SIDStructure{LocalBlock: 256}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalLsSrSegment(tt.segment)
			require.Error(t, err)
		})
	}
	seg, err := UnmarshalLsSrSegment(&api.LsSrSegment{SegmentType: 1, Label: 1<<20 - 1})
	require.NoError(t, err)
	_, err = bgp.NewLsTLVSrSegment(seg).Serialize()
	require.NoError(t, err)

	// A 16-octet SID is wire-legal whatever it reads as, so a segment a
	// peer sent with an IPv4-mapped SID must convert back through the API.
	seg, err = UnmarshalLsSrSegment(&api.LsSrSegment{SegmentType: 2, Sid: "::ffff:10.0.0.1"})
	require.NoError(t, err)
	_, err = bgp.NewLsTLVSrSegment(seg).Serialize()
	require.NoError(t, err)
}

func TestLsSrBindingSIDValidation(t *testing.T) {
	for _, sid := range []string{"192.0.2.1", "fe80::1%eth0"} {
		t.Run(sid, func(t *testing.T) {
			_, err := UnmarshalLsSrv6BindingSID(&api.LsSrv6BindingSID{Sid: sid})
			require.Error(t, err)
			_, err = UnmarshalLsSrBindingSID(&api.LsSrBindingSID{Flags: &api.LsSrBindingSIDFlags{Srv6: true}, SpecifiedSid: sid})
			require.Error(t, err)
		})
	}
	// A 16-octet SID from a peer can decode to an IPv4-mapped address, so
	// the conversion accepts one.
	_, err := UnmarshalLsSrv6BindingSID(&api.LsSrv6BindingSID{Sid: "::ffff:192.0.2.1"})
	require.NoError(t, err)
	_, err = UnmarshalLsSrBindingSID(&api.LsSrBindingSID{Label: 1 << 20})
	require.Error(t, err)
	_, err = UnmarshalLsSrBindingSID(&api.LsSrBindingSID{SpecifiedLabel: 1 << 20})
	require.Error(t, err)
	for _, bw := range []float32{-1, float32(math.Inf(1)), float32(math.NaN())} {
		_, err := UnmarshalLsSrSegmentList(&api.LsSrSegmentList{Bandwidth: &api.LsSrSegmentListBandwidth{Bandwidth: bw}})
		require.Error(t, err)
	}
}

// A zero-length name TLV is valid (RFC 9857 sections 5.4 and 5.5) and
// distinct from an absent one, so presence must survive the API round trip.
func TestLsSrPolicyNamePresenceRoundTrip(t *testing.T) {
	empty := ""
	in := &bgp.LsAttributeSrPolicy{PolicyName: &empty}
	out, err := UnmarshalLsAttributeSrPolicy(MarshalLsAttributeSrPolicy(in))
	require.NoError(t, err)
	if assert.NotNil(t, out.PolicyName) {
		assert.Equal(t, "", *out.PolicyName)
	}
	assert.Nil(t, out.CandidatePathName)
}
