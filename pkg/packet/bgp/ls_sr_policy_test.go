package bgp

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tlvBytes frames value as a BGP-LS TLV of the given type.
func tlvBytes(typ uint16, value ...[]byte) []byte {
	body := []byte{}
	for _, v := range value {
		body = append(body, v...)
	}
	buf := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint16(buf[:2], typ)
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(body)))
	return append(buf, body...)
}

// lsNLRIBytes frames a type-5 BGP-LS NLRI: NLRI type, length, Protocol-ID,
// Identifier and the TLVs.
func lsNLRIBytes(nlriType uint16, protocolID byte, identifier uint64, tlvs ...[]byte) []byte {
	body := []byte{protocolID}
	body = binary.BigEndian.AppendUint64(body, identifier)
	for _, t := range tlvs {
		body = append(body, t...)
	}
	buf := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint16(buf[:2], nlriType)
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(body)))
	return append(buf, body...)
}

// lsAttrBytes frames TLVs as a BGP-LS path attribute.
func lsAttrBytes(tlvs ...[]byte) []byte {
	body := []byte{}
	for _, t := range tlvs {
		body = append(body, t...)
	}
	if len(body) > 255 {
		buf := []byte{0x90, 0x1d, 0, 0}
		binary.BigEndian.PutUint16(buf[2:4], uint16(len(body)))
		return append(buf, body...)
	}
	return append([]byte{0x80, 0x1d, byte(len(body))}, body...)
}

func ip4(s string) []byte {
	a := netip.MustParseAddr(s).As4()
	return a[:]
}

func ip6(s string) []byte {
	a := netip.MustParseAddr(s).As16()
	return a[:]
}

func be32(v uint32) []byte {
	return binary.BigEndian.AppendUint32(nil, v)
}

func labelField(label uint32) []byte {
	return be32(label << 12)
}

// Headend node descriptor: ASN 65001, BGP-LS ID 0, BGP Router-ID 1.1.1.1.
var srPolicyHeadendTLV = tlvBytes(256,
	tlvBytes(512, be32(65001)),
	tlvBytes(513, be32(0)),
	tlvBytes(516, ip4("1.1.1.1")),
	tlvBytes(1028, ip4("10.0.0.1")),
)

const srPolicyHeadendStr = "{ASN: 65001, BGP LS ID: 0, BGP ROUTER ID: 1.1.1.1, IPv4 ROUTER ID: 10.0.0.1}"

func srPolicyCPDescTLV(flags byte, endpoint, originator []byte) []byte {
	return tlvBytes(554,
		[]byte{20, flags, 0, 0}, // Protocol-Origin BGP, Flags, Reserved
		endpoint,
		be32(100),   // Color
		be32(65001), // Originator ASN
		originator,
		be32(1), // Discriminator
	)
}

func Test_LsSrPolicyCandidatePathNLRI(t *testing.T) {
	assert := assert.New(t)

	dupDesc := srPolicyCPDescTLV(0x00, ip4("10.0.0.9"), ip4("9.9.9.9"))

	tests := []struct {
		name      string
		in        []byte
		str       string
		err       bool
		serialize bool
	}{
		{
			"ipv4 endpoint and originator",
			lsNLRIBytes(5, 9, 0, srPolicyHeadendTLV, srPolicyCPDescTLV(0x00, ip4("10.0.0.2"), ip4("1.1.1.1"))),
			"NLRI { SRPOLICY_CP { LOCAL_NODE: " + srPolicyHeadendStr + " ENDPOINT: 10.0.0.2 COLOR: 100 ORIGIN: 20 ORIGINATOR: 65001/1.1.1.1 DISCRIMINATOR: 1 SR:0 } }",
			false, true,
		},
		{
			"ipv6 endpoint and originator",
			lsNLRIBytes(5, 9, 7, srPolicyHeadendTLV, srPolicyCPDescTLV(0xc0, ip6("2001:db8::2"), ip6("2001:db8::1"))),
			"NLRI { SRPOLICY_CP { LOCAL_NODE: " + srPolicyHeadendStr + " ENDPOINT: 2001:db8::2 COLOR: 100 ORIGIN: 20 ORIGINATOR: 65001/2001:db8::1 DISCRIMINATOR: 1 SR:7 } }",
			false, true,
		},
		{
			"ipv6 endpoint, ipv4 originator",
			lsNLRIBytes(5, 9, 0, srPolicyHeadendTLV, srPolicyCPDescTLV(0x80, ip6("2001:db8::2"), ip4("1.1.1.1"))),
			"NLRI { SRPOLICY_CP { LOCAL_NODE: " + srPolicyHeadendStr + " ENDPOINT: 2001:db8::2 COLOR: 100 ORIGIN: 20 ORIGINATOR: 65001/1.1.1.1 DISCRIMINATOR: 1 SR:0 } }",
			false, true,
		},
		{
			"reserved flag bits set are preserved",
			lsNLRIBytes(5, 9, 0, srPolicyHeadendTLV, srPolicyCPDescTLV(0x3f, ip4("10.0.0.2"), ip4("1.1.1.1"))),
			"NLRI { SRPOLICY_CP { LOCAL_NODE: " + srPolicyHeadendStr + " ENDPOINT: 10.0.0.2 COLOR: 100 ORIGIN: 20 ORIGINATOR: 65001/1.1.1.1 DISCRIMINATOR: 1 SR:0 } }",
			false, true,
		},
		{
			"unknown protocol id is tolerated",
			lsNLRIBytes(5, 2, 0, srPolicyHeadendTLV, srPolicyCPDescTLV(0x00, ip4("10.0.0.2"), ip4("1.1.1.1"))),
			"NLRI { SRPOLICY_CP { LOCAL_NODE: " + srPolicyHeadendStr + " ENDPOINT: 10.0.0.2 COLOR: 100 ORIGIN: 20 ORIGINATOR: 65001/1.1.1.1 DISCRIMINATOR: 1 ISIS-L2:0 } }",
			false, true,
		},
		{
			"unknown TLV before the descriptor is preserved",
			lsNLRIBytes(5, 9, 0, srPolicyHeadendTLV, tlvBytes(999, []byte{0xff}), srPolicyCPDescTLV(0x00, ip4("10.0.0.2"), ip4("1.1.1.1"))),
			"NLRI { SRPOLICY_CP { LOCAL_NODE: " + srPolicyHeadendStr + " ENDPOINT: 10.0.0.2 COLOR: 100 ORIGIN: 20 ORIGINATOR: 65001/1.1.1.1 DISCRIMINATOR: 1 TLV 999: ff SR:0 } }",
			false, true,
		},
		{
			"duplicate descriptor: first one wins, second is preserved",
			lsNLRIBytes(5, 9, 0, srPolicyHeadendTLV,
				srPolicyCPDescTLV(0x00, ip4("10.0.0.2"), ip4("1.1.1.1")),
				dupDesc),
			"NLRI { SRPOLICY_CP { LOCAL_NODE: " + srPolicyHeadendStr + " ENDPOINT: 10.0.0.2 COLOR: 100 ORIGIN: 20 ORIGINATOR: 65001/1.1.1.1 DISCRIMINATOR: 1" +
				fmt.Sprintf(" TLV 554: %x", dupDesc[tlvHdrLen:]) + " SR:0 } }",
			false, true,
		},
		{
			"descriptor too short",
			lsNLRIBytes(5, 9, 0, srPolicyHeadendTLV, tlvBytes(554, []byte{20, 0, 0, 0}, ip4("10.0.0.2"), be32(100), be32(65001), ip4("1.1.1.1"), []byte{0, 0, 1})),
			"", true, false,
		},
		{
			"E flag set but IPv4-sized endpoint",
			lsNLRIBytes(5, 9, 0, srPolicyHeadendTLV, srPolicyCPDescTLV(0x80, ip4("10.0.0.2"), ip4("1.1.1.1"))),
			"", true, false,
		},
		{
			"descriptor missing",
			lsNLRIBytes(5, 9, 0, srPolicyHeadendTLV),
			"", true, false,
		},
		{
			"headend missing",
			lsNLRIBytes(5, 9, 0, srPolicyCPDescTLV(0x00, ip4("10.0.0.2"), ip4("1.1.1.1"))),
			"", true, false,
		},
		{
			// RFC 9552 Section 8.2.2: the NLRI is not malformed based on
			// which sub-TLVs the headend descriptor carries.
			"headend without router id",
			lsNLRIBytes(5, 9, 0, tlvBytes(256, tlvBytes(512, be32(65001))), srPolicyCPDescTLV(0x00, ip4("10.0.0.2"), ip4("1.1.1.1"))),
			"NLRI { SRPOLICY_CP { LOCAL_NODE: {ASN: 65001} ENDPOINT: 10.0.0.2 COLOR: 100 ORIGIN: 20 ORIGINATOR: 65001/1.1.1.1 DISCRIMINATOR: 1 SR:0 } }",
			false, true,
		},
		{
			"truncated header",
			[]byte{0x00, 0x05, 0x00, 0x05, 0x09, 0x00, 0x00, 0x00, 0x00},
			"", true, false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			nlri := LsAddrPrefix{}
			if test.err {
				assert.Error(nlri.decodeFromBytes(test.in))
				return
			}
			assert.NoError(nlri.decodeFromBytes(test.in))
			assert.Equal(LS_NLRI_TYPE_SR_POLICY_CANDIDATE_PATH, nlri.Type)
			assert.Equal(test.str, nlri.String())
			if test.serialize {
				got, err := nlri.Serialize()
				assert.NoError(err)
				assert.Equal(test.in, got)
			}
		})
	}
}

func Test_LsSrPolicyCandidatePathNLRIConstructAndJSON(t *testing.T) {
	assert := assert.New(t)

	nd := &LsNodeDescriptor{Asn: 65001, BGPRouterID: netip.MustParseAddr("1.1.1.1"), LocalRouterID: netip.MustParseAddr("10.0.0.1")}
	ndTLV := NewLsTLVNodeDescriptor(nd, LS_TLV_LOCAL_NODE_DESC)
	desc := &LsSrPolicyCandidatePathDescriptor{
		ProtocolOrigin:    20,
		Endpoint:          netip.MustParseAddr("2001:db8::2"),
		Color:             100,
		OriginatorASN:     65001,
		OriginatorAddress: netip.MustParseAddr("1.1.1.1"),
		Discriminator:     1,
	}
	descTLV := NewLsTLVSrPolicyCandidatePathDescriptor(desc)
	assert.EqualValues(LS_TLV_SR_POLICY_CP_DESC, descTLV.Type)
	assert.EqualValues(36, descTLV.Length)

	nlri := &LsAddrPrefix{
		Type: LS_NLRI_TYPE_SR_POLICY_CANDIDATE_PATH,
		NLRI: &LsSrPolicyCandidatePathNLRI{
			LsNLRI: LsNLRI{
				NLRIType:   LS_NLRI_TYPE_SR_POLICY_CANDIDATE_PATH,
				ProtocolID: LS_PROTOCOL_SEGMENT_ROUTING,
				Identifier: 0,
				Length:     uint16(9 + ndTLV.Len() + descTLV.Len()),
			},
			LocalNodeDesc:     &ndTLV,
			CandidatePathDesc: descTLV,
		},
	}

	want := lsNLRIBytes(5, 9, 0, srPolicyHeadendTLV, srPolicyCPDescTLV(0x80, ip6("2001:db8::2"), ip4("1.1.1.1")))
	got, err := nlri.Serialize()
	assert.NoError(err)
	assert.Equal(want, got)

	decoded := LsAddrPrefix{}
	assert.NoError(decoded.decodeFromBytes(got))
	assert.Equal(desc, decoded.NLRI.(*LsSrPolicyCandidatePathNLRI).CandidatePathDesc.(*LsTLVSrPolicyCandidatePathDescriptor).Extract())

	j, err := json.Marshal(decoded.NLRI)
	assert.NoError(err)
	assert.JSONEq(`{
		"type": 5,
		"local_node_desc": {"asn":65001,"bgp_ls_id":0,"ospf_area_id":0,"pseudo_node":false,"igp_router_id":"","bgp_router_id":"1.1.1.1","bgp_confederation_member":0,"local_router_id_ipv4":"10.0.0.1"},
		"candidate_path_desc": {"protocol_origin":20,"endpoint":"2001:db8::2","color":100,"originator_asn":65001,"originator_address":"1.1.1.1","discriminator":1}
	}`, string(j))

	// Serialize/String/JSON on an empty NLRI must not panic.
	empty := &LsSrPolicyCandidatePathNLRI{}
	_, err = empty.Serialize()
	assert.Error(err)
	assert.Equal("SRPOLICY_CP { EMPTY }", empty.String())
	_, err = empty.MarshalJSON()
	assert.Error(err)
}

// srPolicySegmentTLV frames an SR Segment sub-TLV: type, reserved, flags,
// SID field and descriptor.
func srPolicySegmentTLV(segType byte, flags uint16, sid []byte, desc ...[]byte) []byte {
	hdr := []byte{segType, 0}
	hdr = binary.BigEndian.AppendUint16(hdr, flags)
	body := [][]byte{hdr, sid}
	body = append(body, desc...)
	return tlvBytes(1206, body...)
}

func srPolicySegmentListTLV(flags uint16, weight uint32, subTLVs ...[]byte) []byte {
	hdr := binary.BigEndian.AppendUint16(nil, flags)
	hdr = append(hdr, 0, 0) // reserved
	hdr = append(hdr, 0, 0) // MTID
	hdr = append(hdr, 0, 0) // algorithm, reserved
	hdr = binary.BigEndian.AppendUint32(hdr, weight)
	body := [][]byte{hdr}
	body = append(body, subTLVs...)
	return tlvBytes(1205, body...)
}

var (
	srv6EndpointBehaviorTLV = tlvBytes(1250, []byte{0x00, 0x30, 0x00, 0x00}) // End.B6.Encaps (48), flags 0, algo 0
	srv6SIDStructureTLV     = tlvBytes(1252, []byte{32, 16, 16, 64})
)

// srPolicyBaseAttrBytes carries the single-instance TLVs of a candidate path
// and no segment list.
func srPolicyBaseAttrBytes() []byte {
	return lsAttrBytes(
		// SR Binding SID: B + L flags, label 24001, no specified BSID.
		tlvBytes(1201, []byte{0x50, 0x00, 0x00, 0x00}, labelField(24001), be32(0)),
		// SRv6 Binding SID: B flag, SID, specified SID and endpoint behavior.
		tlvBytes(1212, []byte{0x80, 0x00, 0x00, 0x00}, ip6("fc00:0:1::1"), ip6("fc00:0:1::2"), srv6EndpointBehaviorTLV, srv6SIDStructureTLV),
		// CP State: priority 10, flags A+E+V, preference 200.
		tlvBytes(1202, []byte{10, 0, 0x58, 0x00}, be32(200)),
		tlvBytes(1203, []byte("cp1")),
		tlvBytes(1213, []byte("pol-blue")),
	)
}

func srPolicyBaseAttrModel() LsAttributeSrPolicy {
	cpName := "cp1"
	policyName := "pol-blue"
	return LsAttributeSrPolicy{
		BindingSID: &LsSrBindingSID{Flags: LsSrBindingSIDFlags{Allocated: true, FromSRLB: true}, Label: 24001},
		Srv6BindingSIDs: []LsSrv6BindingSID{{
			Flags:            LsSrv6BindingSIDFlags{Allocated: true},
			SID:              netip.MustParseAddr("fc00:0:1::1"),
			SpecifiedSID:     netip.MustParseAddr("fc00:0:1::2"),
			EndpointBehavior: &LsSrv6EndpointBehavior{EndpointBehavior: 48},
			SIDStructure:     &LsSrv6SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16, LocalArg: 64},
		}},
		State: &LsSrCandidatePathState{
			Priority:   10,
			Flags:      LsSrCandidatePathStateFlags{Active: true, Evaluated: true, ValidSIDList: true},
			Preference: 200,
		},
		CandidatePathName: &cpName,
		PolicyName:        &policyName,
	}
}

func srPolicyMplsAttrBytes() []byte {
	return lsAttrBytes(
		// SR Binding SID: B + L flags, label 24001, no specified BSID.
		tlvBytes(1201, []byte{0x50, 0x00, 0x00, 0x00}, labelField(24001), be32(0)),
		// CP State: priority 10, flags A+E+V, preference 200.
		tlvBytes(1202, []byte{10, 0, 0x58, 0x00}, be32(200)),
		tlvBytes(1203, []byte("cp1")),
		tlvBytes(1213, []byte("pol-blue")),
		srPolicySegmentListTLV(0x5000, 1, // flags E+V, weight 1
			srPolicySegmentTLV(1, 0xc000, labelField(16001), []byte{0}),
			srPolicySegmentTLV(3, 0xc000, labelField(16002), []byte{0}, ip4("10.0.0.3")),
			srPolicySegmentTLV(5, 0xc000, labelField(24005), ip4("10.0.0.5"), be32(7)),
			srPolicySegmentTLV(6, 0xc000, labelField(24006), ip4("10.0.0.6"), ip4("10.0.0.7")),
			tlvBytes(1207, []byte{1, 0x10, 0, 0}, be32(0), be32(0), be32(30)), // metric type 1, V flag, value 30
			tlvBytes(1216, []byte{0x4e, 0x6e, 0x6b, 0x28}),                    // float32(1e9)
			tlvBytes(1217, be32(7)),
		),
		srPolicySegmentListTLV(0x4000, 2, // flags E, weight 2
			srPolicySegmentTLV(1, 0xc000, labelField(16003), []byte{0}),
		),
	)
}

func srPolicyMplsAttrModel() LsAttributeSrPolicy {
	cpName := "cp1"
	policyName := "pol-blue"
	bw := float32(1e9)
	id := uint32(7)
	return LsAttributeSrPolicy{
		BindingSID: &LsSrBindingSID{Flags: LsSrBindingSIDFlags{Allocated: true, FromSRLB: true}, Label: 24001},
		State: &LsSrCandidatePathState{
			Priority:   10,
			Flags:      LsSrCandidatePathStateFlags{Active: true, Evaluated: true, ValidSIDList: true},
			Preference: 200,
		},
		CandidatePathName: &cpName,
		PolicyName:        &policyName,
		SegmentLists: []LsSrSegmentList{
			{
				Flags:  LsSrSegmentListFlags{Explicit: true, Verified: true},
				Weight: 1,
				Segments: []LsSrSegment{
					{SegmentType: LS_SR_SEGMENT_TYPE_A_MPLS_LABEL, Flags: LsSrSegmentFlags{SIDPresent: true, Explicit: true}, Label: 16001},
					{SegmentType: LS_SR_SEGMENT_TYPE_C_IPV4_NODE, Flags: LsSrSegmentFlags{SIDPresent: true, Explicit: true}, Label: 16002, LocalAddress: netip.MustParseAddr("10.0.0.3")},
					{SegmentType: LS_SR_SEGMENT_TYPE_E_IPV4_NODE_INTERFACE, Flags: LsSrSegmentFlags{SIDPresent: true, Explicit: true}, Label: 24005, LocalAddress: netip.MustParseAddr("10.0.0.5"), LocalInterfaceID: 7},
					{SegmentType: LS_SR_SEGMENT_TYPE_F_IPV4_ADJACENCY, Flags: LsSrSegmentFlags{SIDPresent: true, Explicit: true}, Label: 24006, LocalAddress: netip.MustParseAddr("10.0.0.6"), RemoteAddress: netip.MustParseAddr("10.0.0.7")},
				},
				Metrics:    []LsSrSegmentListMetric{{MetricType: 1, Flags: LsSrSegmentListMetricFlags{Value: true}, Value: 30}},
				Bandwidth:  &bw,
				Identifier: &id,
			},
			{
				Flags:  LsSrSegmentListFlags{Explicit: true},
				Weight: 2,
				Segments: []LsSrSegment{
					{SegmentType: LS_SR_SEGMENT_TYPE_A_MPLS_LABEL, Flags: LsSrSegmentFlags{SIDPresent: true, Explicit: true}, Label: 16003},
				},
			},
		},
	}
}

func srPolicySrv6AttrBytes() []byte {
	return lsAttrBytes(
		tlvBytes(1212, []byte{0x80, 0x00, 0x00, 0x00}, ip6("fc00:0:1::1"), ip6("::"), srv6EndpointBehaviorTLV, srv6SIDStructureTLV),
		srPolicySegmentListTLV(0xc000, 1, // flags D+E
			srPolicySegmentTLV(2, 0xc000, ip6("fc00:0:2::1"), []byte{0}, srv6EndpointBehaviorTLV, srv6SIDStructureTLV),
			srPolicySegmentTLV(9, 0xc000, ip6("fc00:0:3::1"), []byte{0}, ip6("2001:db8::3")),
			srPolicySegmentTLV(10, 0xc000, ip6("fc00:0:4::1"), ip6("2001:db8::4"), be32(1), ip6("2001:db8::5"), be32(2)),
			srPolicySegmentTLV(11, 0xc000, ip6("fc00:0:6::1"), ip6("2001:db8::6"), ip6("2001:db8::7")),
		),
	)
}

func srPolicySrv6AttrModel() LsAttributeSrPolicy {
	eb := &LsSrv6EndpointBehavior{EndpointBehavior: 48}
	ss := &LsSrv6SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16, LocalArg: 64}
	explicit := LsSrSegmentFlags{SIDPresent: true, Explicit: true}
	return LsAttributeSrPolicy{
		Srv6BindingSIDs: []LsSrv6BindingSID{{
			Flags:            LsSrv6BindingSIDFlags{Allocated: true},
			SID:              netip.MustParseAddr("fc00:0:1::1"),
			SpecifiedSID:     netip.MustParseAddr("::"),
			EndpointBehavior: eb,
			SIDStructure:     ss,
		}},
		SegmentLists: []LsSrSegmentList{
			{
				Flags:  LsSrSegmentListFlags{SRv6: true, Explicit: true},
				Weight: 1,
				Segments: []LsSrSegment{
					{SegmentType: LS_SR_SEGMENT_TYPE_B_SRV6_SID, Flags: explicit, SID: netip.MustParseAddr("fc00:0:2::1"), EndpointBehavior: eb, SIDStructure: ss},
					{SegmentType: LS_SR_SEGMENT_TYPE_I_IPV6_NODE_SRV6, Flags: explicit, SID: netip.MustParseAddr("fc00:0:3::1"), LocalAddress: netip.MustParseAddr("2001:db8::3")},
					{SegmentType: LS_SR_SEGMENT_TYPE_J_IPV6_NODE_INTERFACE_SRV6, Flags: explicit, SID: netip.MustParseAddr("fc00:0:4::1"), LocalAddress: netip.MustParseAddr("2001:db8::4"), LocalInterfaceID: 1, RemoteAddress: netip.MustParseAddr("2001:db8::5"), RemoteInterfaceID: 2},
					{SegmentType: LS_SR_SEGMENT_TYPE_K_IPV6_ADJACENCY_SRV6, Flags: explicit, SID: netip.MustParseAddr("fc00:0:6::1"), LocalAddress: netip.MustParseAddr("2001:db8::6"), RemoteAddress: netip.MustParseAddr("2001:db8::7")},
				},
			},
		},
	}
}

func srPolicyMplsV6AttrBytes() []byte {
	return lsAttrBytes(
		// SR Binding SID with D flag: SRv6 BSID and specified BSID.
		tlvBytes(1201, []byte{0xc0, 0x00, 0x00, 0x00}, ip6("fc00:0:1::1"), ip6("fc00:0:1::2")),
		srPolicySegmentListTLV(0x0000, 0,
			srPolicySegmentTLV(4, 0x8000, labelField(16004), []byte{128}, ip6("2001:db8::4")),
			srPolicySegmentTLV(7, 0x8000, labelField(24007), ip6("2001:db8::7"), be32(70), ip6("2001:db8::8"), be32(80)),
			srPolicySegmentTLV(8, 0x8000, labelField(24008), ip6("2001:db8::8"), ip6("2001:db8::9")),
		),
	)
}

func srPolicyMplsV6AttrModel() LsAttributeSrPolicy {
	present := LsSrSegmentFlags{SIDPresent: true}
	return LsAttributeSrPolicy{
		BindingSID: &LsSrBindingSID{
			Flags:        LsSrBindingSIDFlags{SRv6: true, Allocated: true},
			SID:          netip.MustParseAddr("fc00:0:1::1"),
			SpecifiedSID: netip.MustParseAddr("fc00:0:1::2"),
		},
		SegmentLists: []LsSrSegmentList{
			{
				Segments: []LsSrSegment{
					{SegmentType: LS_SR_SEGMENT_TYPE_D_IPV6_NODE_MPLS, Flags: present, Label: 16004, Algorithm: 128, LocalAddress: netip.MustParseAddr("2001:db8::4")},
					{SegmentType: LS_SR_SEGMENT_TYPE_G_IPV6_NODE_INTERFACE_MPLS, Flags: present, Label: 24007, LocalAddress: netip.MustParseAddr("2001:db8::7"), LocalInterfaceID: 70, RemoteAddress: netip.MustParseAddr("2001:db8::8"), RemoteInterfaceID: 80},
					{SegmentType: LS_SR_SEGMENT_TYPE_H_IPV6_ADJACENCY_MPLS, Flags: present, Label: 24008, LocalAddress: netip.MustParseAddr("2001:db8::8"), RemoteAddress: netip.MustParseAddr("2001:db8::9")},
				},
			},
		},
	}
}

func Test_PathAttributeLsSrPolicy(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		name string
		in   []byte
		str  string
		want LsAttributeSrPolicy
	}{
		{
			"binding sids, state and names",
			srPolicyBaseAttrBytes(),
			"{LsAttributes: {SR Binding SID: 24001 Specified: 0 Flags: BL} {SRv6 Binding SID: fc00:0:1::1 Specified: fc00:0:1::2 Flags: B} {SR CP State: Priority:10 Preference:200 Flags:AEV} {SR CP Name: cp1} {SR Policy Name: pol-blue} }",
			srPolicyBaseAttrModel(),
		},
		{
			"sr-mpls candidate path",
			srPolicyMplsAttrBytes(),
			"{LsAttributes: {SR Binding SID: 24001 Specified: 0 Flags: BL} {SR CP State: Priority:10 Preference:200 Flags:AEV} {SR CP Name: cp1} {SR Policy Name: pol-blue} " +
				"{SR Segment List: Weight:1 MTID:0 Algo:0 Flags:EV {Segment: Type:A Label:16001 Algo:0 Flags:SE} {Segment: Type:C Label:16002 Node:10.0.0.3 Algo:0 Flags:SE} {Segment: Type:E Label:24005 Node:10.0.0.5 IfID:7 Flags:SE} {Segment: Type:F Label:24006 Local:10.0.0.6 Remote:10.0.0.7 Flags:SE} {Metric: Type:1 Margin:0 Bound:0 Value:30 Flags:V} {Bandwidth: 1e+09} {Identifier: 7}} " +
				"{SR Segment List: Weight:2 MTID:0 Algo:0 Flags:E {Segment: Type:A Label:16003 Algo:0 Flags:SE}} }",
			srPolicyMplsAttrModel(),
		},
		{
			"srv6 candidate path",
			srPolicySrv6AttrBytes(),
			"{LsAttributes: {SRv6 Binding SID: fc00:0:1::1 Specified: :: Flags: B} " +
				"{SR Segment List: Weight:1 MTID:0 Algo:0 Flags:DE {Segment: Type:B SID:fc00:0:2::1 Algo:0 Flags:SE} {Segment: Type:I SID:fc00:0:3::1 Node:2001:db8::3 Algo:0 Flags:SE} {Segment: Type:J SID:fc00:0:4::1 Local:2001:db8::4/1 Remote:2001:db8::5/2 Flags:SE} {Segment: Type:K SID:fc00:0:6::1 Local:2001:db8::6 Remote:2001:db8::7 Flags:SE}} }",
			srPolicySrv6AttrModel(),
		},
		{
			"srv6 binding sid in SR BSID TLV and ipv6 sr-mpls segments",
			srPolicyMplsV6AttrBytes(),
			"{LsAttributes: {SR Binding SID: fc00:0:1::1 Specified: fc00:0:1::2 Flags: DB} " +
				"{SR Segment List: Weight:0 MTID:0 Algo:0 Flags:- {Segment: Type:D Label:16004 Node:2001:db8::4 Algo:128 Flags:S} {Segment: Type:G Label:24007 Local:2001:db8::7/70 Remote:2001:db8::8/80 Flags:S} {Segment: Type:H Label:24008 Local:2001:db8::8 Remote:2001:db8::9 Flags:S}} }",
			srPolicyMplsV6AttrModel(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Wire -> native.
			attr := PathAttributeLs{}
			assert.NoError(attr.DecodeFromBytes(test.in))
			assert.Equal(test.str, attr.String())
			assert.Equal(test.want, attr.Extract().SrPolicy)

			// Byte-exact round trip.
			got, err := attr.Serialize()
			assert.NoError(err)
			assert.Equal(test.in, got)

			// The JSON "sr_policy" object matches the extracted model.
			j, err := attr.MarshalJSON()
			assert.NoError(err)
			var m map[string]json.RawMessage
			assert.NoError(json.Unmarshal(j, &m))
			wantJSON, err := json.Marshal(test.want)
			assert.NoError(err)
			assert.JSONEq(string(wantJSON), string(m["sr_policy"]))

			// Native model -> wire through the constructors.
			built := PathAttributeLs{
				PathAttribute: PathAttribute{Flags: attr.Flags, Type: BGP_ATTR_TYPE_LS},
				TLVs:          NewLsAttributeTLVs(&LsAttribute{SrPolicy: test.want}),
			}
			got, err = built.Serialize()
			assert.NoError(err)
			assert.Equal(test.in, got)
		})
	}
}

func Test_PathAttributeLsSrPolicyTolerance(t *testing.T) {
	assert := assert.New(t)

	t.Run("constraints TLV is decoded and forwarded", func(t *testing.T) {
		in := lsAttrBytes(
			tlvBytes(1202, []byte{10, 0, 0x40, 0x00}, be32(200)),
			tlvBytes(1204, []byte{0x80, 0x00, 0, 0, 0, 0, 0, 0},
				tlvBytes(1208, []byte{1, 0, 0, 0}, be32(0xff)),
				tlvBytes(1210, be32(1)),
				tlvBytes(1215, []byte{1, 0x80, 0, 0}, be32(1), be32(2)),
			),
			srPolicySegmentListTLV(0x4000, 1, srPolicySegmentTLV(1, 0xc000, labelField(16001), []byte{0})),
		)
		attr := PathAttributeLs{}
		assert.NoError(attr.DecodeFromBytes(in))
		sp := attr.Extract().SrPolicy
		if assert.NotNil(sp.State) {
			assert.True(sp.State.Flags.Active)
		}
		if assert.NotNil(sp.Constraints) {
			assert.True(sp.Constraints.Flags.SRv6)
			if assert.NotNil(sp.Constraints.Affinity) {
				assert.Equal([]uint32{0xff}, sp.Constraints.Affinity.ExcludeAny)
			}
			if assert.Len(sp.Constraints.Metrics, 1) {
				assert.True(sp.Constraints.Metrics[0].Flags.Optimization)
			}
		}
		assert.Len(sp.SegmentLists, 1)
		assert.Len(attr.TLVs, 3)
		wire, err := attr.Serialize()
		require.NoError(t, err)
		assert.Equal(in, wire)
	})

	t.Run("invalid bandwidth constraint is forwarded but kept out of the model", func(t *testing.T) {
		// RFC 9552 section 8.2.2: TLV contents do not make the attribute
		// malformed. A negative bandwidth is re-serialized as received.
		in := lsAttrBytes(srPolicyConstraintsTLVWith(tlvBytes(1210, []byte{0xbf, 0x80, 0, 0})))
		attr := PathAttributeLs{}
		assert.NoError(attr.DecodeFromBytes(in))
		if c := attr.Extract().SrPolicy.Constraints; assert.NotNil(c) {
			assert.Nil(c.Bandwidth)
		}
		_, err := attr.MarshalJSON()
		assert.NoError(err)
		got, err := attr.Serialize()
		assert.NoError(err)
		assert.Equal(in, got)
	})

	t.Run("unknown segment type is forwarded, siblings decoded", func(t *testing.T) {
		in := lsAttrBytes(
			srPolicySegmentListTLV(0x4000, 1,
				srPolicySegmentTLV(12, 0xc000, be32(0), []byte{1, 2, 3}),
				srPolicySegmentTLV(1, 0xc000, labelField(16001), []byte{0}),
				tlvBytes(0xdead, []byte{0xff}),
			),
		)
		attr := PathAttributeLs{}
		assert.NoError(attr.DecodeFromBytes(in))
		sp := attr.Extract().SrPolicy
		if assert.Len(sp.SegmentLists, 1) && assert.Len(sp.SegmentLists[0].Segments, 1) {
			assert.EqualValues(16001, sp.SegmentLists[0].Segments[0].Label)
		}
		wire, err := attr.Serialize()
		require.NoError(t, err)
		assert.Equal(in, wire)
	})

	t.Run("segment without S flag exposes no SID", func(t *testing.T) {
		in := lsAttrBytes(
			srPolicySegmentListTLV(0x4000, 1,
				srPolicySegmentTLV(3, 0x4000, labelField(16002), []byte{0}, ip4("10.0.0.3")),
			),
		)
		attr := PathAttributeLs{}
		assert.NoError(attr.DecodeFromBytes(in))
		seg := attr.Extract().SrPolicy.SegmentLists[0].Segments[0]
		assert.False(seg.Flags.SIDPresent)
		assert.EqualValues(0, seg.Label)
		assert.Equal(netip.MustParseAddr("10.0.0.3"), seg.LocalAddress)
		// The raw label is still re-serialized.
		got, err := attr.Serialize()
		assert.NoError(err)
		assert.Equal(in, got)
	})

	t.Run("invalid bandwidth is forwarded but kept out of the model", func(t *testing.T) {
		// RFC 9552 section 8.2.2: TLV contents do not make the attribute
		// malformed. A NaN or negative bandwidth is re-serialized as
		// received; the model takes the first valid instance.
		in := lsAttrBytes(
			srPolicySegmentListTLV(0, 1,
				tlvBytes(1216, []byte{0xff, 0xc0, 0, 0}), // NaN
				tlvBytes(1216, []byte{0xbf, 0x80, 0, 0}), // -1.0
				tlvBytes(1216, []byte{0x3f, 0x80, 0, 0}), // 1.0
			),
		)
		attr := PathAttributeLs{}
		assert.NoError(attr.DecodeFromBytes(in))
		if bw := attr.Extract().SrPolicy.SegmentLists[0].Bandwidth; assert.NotNil(bw) {
			assert.EqualValues(1.0, *bw)
		}
		_, err := attr.MarshalJSON()
		assert.NoError(err)
		got, err := attr.Serialize()
		assert.NoError(err)
		assert.Equal(in, got)
	})

	t.Run("duplicate single-instance TLVs: first wins", func(t *testing.T) {
		in := lsAttrBytes(
			tlvBytes(1202, []byte{1, 0, 0x40, 0x00}, be32(100)),
			tlvBytes(1202, []byte{2, 0, 0x00, 0x00}, be32(200)),
			tlvBytes(1213, []byte("first")),
			tlvBytes(1213, []byte("second")),
			tlvBytes(1201, []byte{0x40, 0x00, 0x00, 0x00}, labelField(1), be32(0)),
			tlvBytes(1201, []byte{0x40, 0x00, 0x00, 0x00}, labelField(2), be32(0)),
			srPolicySegmentListTLV(0, 1,
				tlvBytes(1217, be32(1)),
				tlvBytes(1217, be32(2)),
				tlvBytes(1216, []byte{0x3f, 0x80, 0x00, 0x00}),
				tlvBytes(1216, []byte{0x40, 0x00, 0x00, 0x00}),
			),
		)
		attr := PathAttributeLs{}
		assert.NoError(attr.DecodeFromBytes(in))
		sp := attr.Extract().SrPolicy
		assert.EqualValues(100, sp.State.Preference)
		assert.Equal("first", *sp.PolicyName)
		assert.EqualValues(1, sp.BindingSID.Label)
		assert.EqualValues(1, *sp.SegmentLists[0].Identifier)
		assert.EqualValues(1.0, *sp.SegmentLists[0].Bandwidth)
		// All instances are kept for faithful re-serialization.
		got, err := attr.Serialize()
		assert.NoError(err)
		assert.Equal(in, got)
	})
}

func Test_PathAttributeLsSrPolicyMalformed(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		name string
		in   []byte
	}{
		{"binding sid too short", lsAttrBytes(tlvBytes(1201, []byte{0, 0, 0, 0}, labelField(1), []byte{0, 0, 0}))},
		{"binding sid D flag with mpls length", lsAttrBytes(tlvBytes(1201, []byte{0x80, 0, 0, 0}, labelField(1), be32(0)))},
		{"binding sid mpls flag with srv6 length", lsAttrBytes(tlvBytes(1201, []byte{0, 0, 0, 0}, ip6("::1"), ip6("::")))},
		{"srv6 binding sid too short", lsAttrBytes(tlvBytes(1212, []byte{0, 0, 0, 0}, ip6("::1"), []byte{0}))},
		{"cp state too short", lsAttrBytes(tlvBytes(1202, []byte{1, 0, 0, 0}, []byte{0, 0, 1}))},
		{"cp state too long", lsAttrBytes(tlvBytes(1202, []byte{1, 0, 0, 0}, be32(1), []byte{0}))},
		{"segment list too short", lsAttrBytes(tlvBytes(1205, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}))},
		{"metric too short", lsAttrBytes(srPolicySegmentListTLV(0, 1, tlvBytes(1207, []byte{1, 0, 0, 0}, be32(0), be32(0), []byte{0, 0, 0})))},
		{"bandwidth wrong length", lsAttrBytes(srPolicySegmentListTLV(0, 1, tlvBytes(1216, []byte{0, 0, 0})))},
		{"identifier wrong length", lsAttrBytes(srPolicySegmentListTLV(0, 1, tlvBytes(1217, []byte{0, 0, 0, 0, 0})))},
		{"segment header too short", lsAttrBytes(srPolicySegmentListTLV(0, 1, tlvBytes(1206, []byte{1, 0, 0})))},
		{"segment type C truncated descriptor", lsAttrBytes(srPolicySegmentListTLV(0, 1, srPolicySegmentTLV(3, 0x8000, labelField(1), []byte{0}, []byte{10, 0, 0})))},
		{"segment type B truncated sid", lsAttrBytes(srPolicySegmentListTLV(0, 1, srPolicySegmentTLV(2, 0x8000, ip4("1.1.1.1"), []byte{0})))},
		{"truncated sub-TLV inside segment list", lsAttrBytes(srPolicySegmentListTLV(0, 1, []byte{0x04, 0xb6, 0x00, 0x10, 0x01, 0x00}))},
		{"truncated sub-TLV inside srv6 binding sid", lsAttrBytes(tlvBytes(1212, []byte{0, 0, 0, 0}, ip6("::1"), ip6("::"), []byte{0x04, 0xe2, 0x00, 0x04, 0x00}))},
		{"constraints too short", lsAttrBytes(tlvBytes(1204, []byte{0, 0, 0, 0, 0, 0, 0}))},
		{"affinity size mismatch", lsAttrBytes(srPolicyConstraintsTLVWith(tlvBytes(1208, []byte{1, 0, 0, 0})))},
		{"affinity too short", lsAttrBytes(srPolicyConstraintsTLVWith(tlvBytes(1208, []byte{0, 0, 0})))},
		{"srlg empty", lsAttrBytes(srPolicyConstraintsTLVWith(tlvBytes(1209)))},
		{"srlg not a multiple of 4", lsAttrBytes(srPolicyConstraintsTLVWith(tlvBytes(1209, []byte{0, 0, 0, 1, 0})))},
		{"bandwidth constraint wrong length", lsAttrBytes(srPolicyConstraintsTLVWith(tlvBytes(1210, []byte{0, 0, 0})))},
		{"disjoint group too short", lsAttrBytes(srPolicyConstraintsTLVWith(tlvBytes(1211, []byte{0, 0, 0, 0, 1, 2, 3})))},
		{"bidirectional group too short", lsAttrBytes(srPolicyConstraintsTLVWith(tlvBytes(1214, []byte{0, 0, 0, 0, 1, 2, 3})))},
		{"metric constraint wrong length", lsAttrBytes(srPolicyConstraintsTLVWith(tlvBytes(1215, []byte{1, 0, 0, 0}, be32(0), be32(0), be32(0))))},
		{"truncated sub-TLV inside constraints", lsAttrBytes(srPolicyConstraintsTLVWith([]byte{0x04, 0xb8, 0x00, 0x10, 0x01}))},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attr := PathAttributeLs{}
			assert.Error(attr.DecodeFromBytes(test.in))
		})
	}
}

// srPolicyConstraintsTLVWith wraps sub-TLVs in a Constraints TLV whose
// fixed fields are all zero.
func srPolicyConstraintsTLVWith(subTLVs ...[]byte) []byte {
	return tlvBytes(1204, append([][]byte{{0, 0, 0, 0, 0, 0, 0, 0}}, subTLVs...)...)
}

func srPolicyConstraintsTLV() []byte {
	return tlvBytes(1204, []byte{0xd0, 0x00, 0, 0, 0x00, 0x02, 128, 0},
		tlvBytes(1208, []byte{1, 2, 0, 0}, be32(0xff), be32(1), be32(0x80000000)),
		tlvBytes(1209, be32(10), be32(20)),
		tlvBytes(1210, []byte{0x4e, 0x6e, 0x6b, 0x28}),
		tlvBytes(1211, []byte{0xa0, 0x20, 0, 0}, be32(7)),
		tlvBytes(1214, []byte{0x40, 0x00, 0, 0}, be32(9)),
		tlvBytes(1215, []byte{0, 0x80, 0, 0}, be32(0), be32(0)),
		tlvBytes(1215, []byte{1, 0x70, 0, 0}, be32(5), be32(100)),
	)
}

func srPolicyConstraintsModel() LsSrCandidatePathConstraints {
	bw := float32(1e9)
	return LsSrCandidatePathConstraints{
		Flags:     LsSrCandidatePathConstraintsFlags{SRv6: true, ProtectedOnly: true, AlgorithmOnly: true},
		MTID:      2,
		Algorithm: 128,
		Affinity:  &LsSrAffinityConstraint{ExcludeAny: []uint32{0xff}, IncludeAny: []uint32{1, 0x80000000}},
		SRLGs:     []uint32{10, 20},
		Bandwidth: &bw,
		DisjointGroup: &LsSrDisjointGroupConstraint{
			RequestFlags: LsSrDisjointGroupRequestFlags{SRLG: true, Link: true},
			StatusFlags:  LsSrDisjointGroupStatusFlags{Link: true},
			GroupID:      7,
		},
		BidirectionalGroup: &LsSrBidirectionalGroupConstraint{Flags: LsSrBidirectionalGroupFlags{CoRouted: true}, GroupID: 9},
		Metrics: []LsSrMetricConstraint{
			{MetricType: 0, Flags: LsSrMetricConstraintFlags{Optimization: true}},
			{MetricType: 1, Flags: LsSrMetricConstraintFlags{Margin: true, Absolute: true, Bound: true}, Margin: 5, Bound: 100},
		},
	}
}

func Test_PathAttributeLsSrPolicyConstraints(t *testing.T) {
	assert := assert.New(t)

	in := lsAttrBytes(srPolicyConstraintsTLV())
	want := srPolicyConstraintsModel()

	// Wire -> native.
	attr := PathAttributeLs{}
	require.NoError(t, attr.DecodeFromBytes(in))
	assert.Equal("{LsAttributes: {SR CP Constraints: MTID:2 Algo:128 Flags:DPA "+
		"{Affinity: ExclAny:0x000000ff InclAny:0x00000001,0x80000000 InclAll:-} {SRLG: [10 20]} {Bandwidth: 1e+09} "+
		"{Disjoint Group: ID:7 Request:SL Status:L} {Bidirectional Group: ID:9 Flags:C} "+
		"{Metric Constraint: Type:0 Margin:0 Bound:0 Flags:O} {Metric Constraint: Type:1 Margin:5 Bound:100 Flags:MAB}} }",
		attr.String())
	sp := attr.Extract().SrPolicy
	if assert.NotNil(sp.Constraints) {
		assert.Equal(want, *sp.Constraints)
	}

	// Byte-exact round trip.
	got, err := attr.Serialize()
	require.NoError(t, err)
	assert.Equal(in, got)

	// The JSON "sr_policy" object matches the extracted model.
	j, err := attr.MarshalJSON()
	require.NoError(t, err)
	var m map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(j, &m))
	wantJSON, err := json.Marshal(LsAttributeSrPolicy{Constraints: &want})
	require.NoError(t, err)
	assert.JSONEq(string(wantJSON), string(m["sr_policy"]))

	// Native model -> wire through the constructors.
	built := PathAttributeLs{
		PathAttribute: PathAttribute{Flags: attr.Flags, Type: BGP_ATTR_TYPE_LS},
		TLVs:          NewLsAttributeTLVs(&LsAttribute{SrPolicy: LsAttributeSrPolicy{Constraints: &want}}),
	}
	got, err = built.Serialize()
	require.NoError(t, err)
	assert.Equal(in, got)

	t.Run("pcep association, duplicates and unknown sub-TLVs", func(t *testing.T) {
		association := []byte{1, 2, 3, 4, 5, 6, 7, 8}
		in := lsAttrBytes(srPolicyConstraintsTLVWith(
			tlvBytes(1211, []byte{0x40, 0, 0, 0}, association),
			tlvBytes(1214, []byte{0x80, 0, 0, 0}, association),
			tlvBytes(1209, be32(1)),
			tlvBytes(1209, be32(2)),
			tlvBytes(1210, []byte{0x3f, 0x80, 0, 0}),
			tlvBytes(1210, []byte{0x40, 0x00, 0, 0}),
			tlvBytes(65000, []byte{0xaa}),
		))
		attr := PathAttributeLs{}
		require.NoError(t, attr.DecodeFromBytes(in))
		c := attr.Extract().SrPolicy.Constraints
		require.NotNil(t, c)
		if assert.NotNil(c.DisjointGroup) {
			assert.True(c.DisjointGroup.RequestFlags.Node)
			assert.EqualValues(0, c.DisjointGroup.GroupID)
			assert.Equal(association, c.DisjointGroup.PcepAssociation)
		}
		if assert.NotNil(c.BidirectionalGroup) {
			assert.True(c.BidirectionalGroup.Flags.Reverse)
			assert.Equal(association, c.BidirectionalGroup.PcepAssociation)
		}
		assert.Equal([]uint32{1}, c.SRLGs)
		if assert.NotNil(c.Bandwidth) {
			assert.EqualValues(1.0, *c.Bandwidth)
		}
		assert.Contains(attr.String(), "{Disjoint Group: ID:0102030405060708 Request:N Status:-}")

		// All instances and the unknown sub-TLV are kept for forwarding.
		got, err := attr.Serialize()
		require.NoError(t, err)
		assert.Equal(in, got)

		// The model rebuilds the association object as received.
		built := PathAttributeLs{
			PathAttribute: PathAttribute{Flags: attr.Flags, Type: BGP_ATTR_TYPE_LS},
			TLVs:          NewLsAttributeTLVs(&LsAttribute{SrPolicy: LsAttributeSrPolicy{Constraints: c}}),
		}
		wire, err := built.Serialize()
		require.NoError(t, err)
		decoded := PathAttributeLs{}
		require.NoError(t, decoded.DecodeFromBytes(wire))
		assert.Equal(c, decoded.Extract().SrPolicy.Constraints)
	})

	t.Run("duplicate constraints TLV: first wins", func(t *testing.T) {
		in := lsAttrBytes(
			srPolicyConstraintsTLVWith(tlvBytes(1209, be32(1))),
			srPolicyConstraintsTLVWith(tlvBytes(1209, be32(2))),
		)
		attr := PathAttributeLs{}
		require.NoError(t, attr.DecodeFromBytes(in))
		assert.Equal([]uint32{1}, attr.Extract().SrPolicy.Constraints.SRLGs)
		assert.Len(attr.TLVs, 2)
	})
}

func Test_LsSrConstraintConstructorsUseLsTLVTypes(t *testing.T) {
	assert := assert.New(t)

	c := NewLsTLVSrCandidatePathConstraints(&LsSrCandidatePathConstraints{})
	assert.EqualValues(LS_TLV_SR_CP_CONSTRAINTS, c.Type)
	assert.EqualValues(8, c.Length)

	full := NewLsTLVSrCandidatePathConstraints(&LsSrCandidatePathConstraints{
		Affinity:           &LsSrAffinityConstraint{IncludeAll: []uint32{1, 2}},
		SRLGs:              []uint32{1},
		Bandwidth:          new(float32),
		DisjointGroup:      &LsSrDisjointGroupConstraint{GroupID: 1},
		BidirectionalGroup: &LsSrBidirectionalGroupConstraint{PcepAssociation: []byte{1, 2, 3, 4, 5, 6}},
		Metrics:            []LsSrMetricConstraint{{MetricType: 1}},
	})
	// 8 + (4+12) + (4+4) + (4+4) + (4+8) + (4+10) + (4+12)
	assert.EqualValues(8+16+8+8+12+14+16, full.Length)
	types := []LsTLVType{}
	for _, sub := range full.SubTLVs {
		types = append(types, sub.GetLsTLV().Type)
	}
	assert.Equal([]LsTLVType{
		LS_TLV_SR_AFFINITY_CONSTRAINT, LS_TLV_SR_SRLG_CONSTRAINT, LS_TLV_SR_BANDWIDTH_CONSTRAINT,
		LS_TLV_SR_DISJOINT_GROUP_CONSTRAINT, LS_TLV_SR_BIDIR_GROUP_CONSTRAINT, LS_TLV_SR_METRIC_CONSTRAINT,
	}, types)
	wire, err := full.Serialize()
	require.NoError(t, err)
	assert.Len(wire, int(full.Length)+4)

	// An EAG longer than the 1-octet size field allows cannot be encoded.
	tooLong := NewLsTLVSrAffinityConstraint(&LsSrAffinityConstraint{ExcludeAny: make([]uint32, 256)})
	_, err = tooLong.Serialize()
	assert.Error(err)
	_, err = NewLsTLVSrSRLGConstraint(nil).Serialize()
	assert.Error(err)
}

func Test_LsSrPolicyConstructorsUseLsTLVTypes(t *testing.T) {
	assert := assert.New(t)

	desc := NewLsTLVSrPolicyCandidatePathDescriptor(&LsSrPolicyCandidatePathDescriptor{
		Endpoint:          netip.MustParseAddr("10.0.0.1"),
		OriginatorAddress: netip.MustParseAddr("10.0.0.2"),
	})
	assert.EqualValues(LS_TLV_SR_POLICY_CP_DESC, desc.Type)
	assert.EqualValues(24, desc.Length)

	assert.EqualValues(LS_TLV_SR_BINDING_SID, NewLsTLVSrBindingSID(&LsSrBindingSID{}).Type)
	assert.EqualValues(12, NewLsTLVSrBindingSID(&LsSrBindingSID{}).Length)
	assert.EqualValues(36, NewLsTLVSrBindingSID(&LsSrBindingSID{Flags: LsSrBindingSIDFlags{SRv6: true}}).Length)

	// A label wider than the 20-bit field must be refused, not truncated.
	_, err := NewLsTLVSrBindingSID(&LsSrBindingSID{Label: 1 << 20}).Serialize()
	assert.Error(err)
	_, err = NewLsTLVSrBindingSID(&LsSrBindingSID{SpecifiedLabel: 1 << 20}).Serialize()
	assert.Error(err)

	srv6BSID := NewLsTLVSrv6BindingSID(&LsSrv6BindingSID{
		SID:              netip.MustParseAddr("fc00::1"),
		EndpointBehavior: &LsSrv6EndpointBehavior{EndpointBehavior: 48},
		SIDStructure:     &LsSrv6SIDStructure{LocalBlock: 32, LocalNode: 16, LocalFunc: 16},
	})
	assert.EqualValues(LS_TLV_SRV6_BINDING_SID, srv6BSID.Type)
	assert.EqualValues(36+8+8, srv6BSID.Length)
	if assert.Len(srv6BSID.SubTLVs, 2) {
		assert.EqualValues(LS_TLV_SRV6_ENDPOINT_BEHAVIOR, srv6BSID.SubTLVs[0].GetLsTLV().Type)
		assert.EqualValues(LS_TLV_SRV6_SID_STRUCTURE, srv6BSID.SubTLVs[1].GetLsTLV().Type)
	}

	assert.EqualValues(LS_TLV_SR_CP_STATE, NewLsTLVSrCandidatePathState(&LsSrCandidatePathState{}).Type)

	name := "name"
	assert.EqualValues(LS_TLV_SR_CP_NAME, NewLsTLVSrCandidatePathName(&name).Type)
	assert.EqualValues(LS_TLV_SR_POLICY_NAME, NewLsTLVSrPolicyName(&name).Type)

	assert.EqualValues(LS_TLV_SR_SEGMENT_LIST_METRIC, NewLsTLVSrSegmentListMetric(&LsSrSegmentListMetric{}).Type)
	bw := float32(1)
	assert.EqualValues(LS_TLV_SR_SEGMENT_LIST_BANDWIDTH, NewLsTLVSrSegmentListBandwidth(&bw).Type)
	id := uint32(1)
	assert.EqualValues(LS_TLV_SR_SEGMENT_LIST_IDENTIFIER, NewLsTLVSrSegmentListIdentifier(&id).Type)

	segLens := map[LsSrSegmentType]uint16{
		LS_SR_SEGMENT_TYPE_A_MPLS_LABEL:               4 + 4 + 1,
		LS_SR_SEGMENT_TYPE_B_SRV6_SID:                 4 + 16 + 1,
		LS_SR_SEGMENT_TYPE_C_IPV4_NODE:                4 + 4 + 5,
		LS_SR_SEGMENT_TYPE_D_IPV6_NODE_MPLS:           4 + 4 + 17,
		LS_SR_SEGMENT_TYPE_E_IPV4_NODE_INTERFACE:      4 + 4 + 8,
		LS_SR_SEGMENT_TYPE_F_IPV4_ADJACENCY:           4 + 4 + 8,
		LS_SR_SEGMENT_TYPE_G_IPV6_NODE_INTERFACE_MPLS: 4 + 4 + 40,
		LS_SR_SEGMENT_TYPE_H_IPV6_ADJACENCY_MPLS:      4 + 4 + 32,
		LS_SR_SEGMENT_TYPE_I_IPV6_NODE_SRV6:           4 + 16 + 17,
		LS_SR_SEGMENT_TYPE_J_IPV6_NODE_INTERFACE_SRV6: 4 + 16 + 40,
		LS_SR_SEGMENT_TYPE_K_IPV6_ADJACENCY_SRV6:      4 + 16 + 32,
	}
	for segType, want := range segLens {
		local, remote := netip.IPv6Unspecified(), netip.IPv6Unspecified()
		if segType == LS_SR_SEGMENT_TYPE_C_IPV4_NODE || segType == LS_SR_SEGMENT_TYPE_E_IPV4_NODE_INTERFACE || segType == LS_SR_SEGMENT_TYPE_F_IPV4_ADJACENCY {
			local, remote = netip.IPv4Unspecified(), netip.IPv4Unspecified()
		}
		seg := NewLsTLVSrSegment(&LsSrSegment{SegmentType: segType, LocalAddress: local, RemoteAddress: remote})
		assert.EqualValues(LS_TLV_SR_SEGMENT, seg.Type)
		assert.Equal(want, seg.Length, segType.String())
		// Serialized length must agree with the declared length.
		ser, err := seg.Serialize()
		assert.NoError(err, segType.String())
		assert.Len(ser, int(want)+4, segType.String())
	}

	// Unknown segment types cannot be serialized.
	_, err = NewLsTLVSrSegment(&LsSrSegment{SegmentType: 42}).Serialize()
	assert.Error(err)

	sl := NewLsTLVSrSegmentList(&LsSrSegmentList{
		Segments:   []LsSrSegment{{SegmentType: LS_SR_SEGMENT_TYPE_A_MPLS_LABEL}},
		Metrics:    []LsSrSegmentListMetric{{}},
		Bandwidth:  &bw,
		Identifier: &id,
	})
	assert.EqualValues(LS_TLV_SR_SEGMENT_LIST, sl.Type)
	assert.EqualValues(12+(4+9)+(4+16)+(4+4)+(4+4), sl.Length)
	if assert.Len(sl.SubTLVs, 4) {
		assert.EqualValues(LS_TLV_SR_SEGMENT, sl.SubTLVs[0].GetLsTLV().Type)
		assert.EqualValues(LS_TLV_SR_SEGMENT_LIST_METRIC, sl.SubTLVs[1].GetLsTLV().Type)
		assert.EqualValues(LS_TLV_SR_SEGMENT_LIST_BANDWIDTH, sl.SubTLVs[2].GetLsTLV().Type)
		assert.EqualValues(LS_TLV_SR_SEGMENT_LIST_IDENTIFIER, sl.SubTLVs[3].GetLsTLV().Type)
	}

	// An empty SR Policy category produces no TLVs.
	assert.Empty(NewLsAttributeSrPolicyTLVs(&LsAttributeSrPolicy{}))
}

func Test_LsSrPolicyCandidatePathDescriptorSerializeRequiresAddresses(t *testing.T) {
	assert := assert.New(t)

	tlv := &LsTLVSrPolicyCandidatePathDescriptor{LsTLV: LsTLV{Type: LS_TLV_SR_POLICY_CP_DESC, Length: 24}}
	_, err := tlv.Serialize()
	assert.Error(err)

	// Serialize derives the E/O flags from the address families even when
	// the flags field was left at zero.
	tlv.Endpoint = netip.MustParseAddr("2001:db8::1")
	tlv.OriginatorAddress = netip.MustParseAddr("10.0.0.1")
	tlv.Length = 36
	ser, err := tlv.Serialize()
	assert.NoError(err)
	assert.Equal(byte(0x80), ser[5])
	assert.Len(ser, 40)
}

// A headend advertisement carries TLV 1028 inside the Local Node
// Descriptors, and its address can differ from the BGP Router-ID. The
// MP_REACH_NLRI attribute must decode and re-serialize unchanged: the
// descriptor length covers the sub-TLV, so dropping it would corrupt the
// forwarded UPDATE.
func TestLsSrPolicyHeadendMPReach(t *testing.T) {
	headend := tlvBytes(256,
		tlvBytes(512, be32(65001)),
		tlvBytes(513, be32(0)),
		tlvBytes(516, ip4("192.0.2.1")),
		tlvBytes(1028, ip4("198.51.100.1")),
	)
	nlri := lsNLRIBytes(5, 9, 0, headend,
		tlvBytes(554, []byte{3, 0, 0, 0}, ip4("192.0.2.100"), be32(10), be32(0), ip4("0.0.0.0"), be32(100)))
	// AFI 16388 (BGP-LS), SAFI 71, next hop, reserved octet, then the NLRI.
	body := append([]byte{0x40, 0x04, 0x47, 4, 192, 0, 2, 1, 0}, nlri...)
	wire := append([]byte{0x90, 0x0e, byte(len(body) >> 8), byte(len(body))}, body...)

	attr := &PathAttributeMpReachNLRI{}
	require.NoError(t, attr.DecodeFromBytes(wire))
	require.Len(t, attr.Value, 1)
	cp := attr.Value[0].NLRI.(*LsAddrPrefix).NLRI.(*LsSrPolicyCandidatePathNLRI)
	desc := cp.LocalNodeDesc.(*LsTLVNodeDescriptor).Extract()
	require.Equal(t, netip.MustParseAddr("198.51.100.1"), desc.LocalRouterID)
	require.Equal(t, netip.MustParseAddr("192.0.2.1"), desc.BGPRouterID)
	got, err := attr.Serialize()
	require.NoError(t, err)
	require.Equal(t, wire, got)
}

func TestLsSrPolicyPCEHeadend(t *testing.T) {
	for _, tt := range []struct {
		name    string
		headend []byte
	}{
		{"IPv4", tlvBytes(256, tlvBytes(1028, ip4("10.0.0.1")))},
		{"IPv6", tlvBytes(256, tlvBytes(1029, ip6("2001:db8::1")))},
		{"both", tlvBytes(256, tlvBytes(1028, ip4("10.0.0.1")), tlvBytes(1029, ip6("2001:db8::1")))},
		{"unknown descriptor", tlvBytes(256, tlvBytes(1028, ip4("10.0.0.1")), tlvBytes(65000, []byte{1, 2, 3, 4}))},
	} {
		t.Run(tt.name, func(t *testing.T) {
			wire := lsNLRIBytes(5, 9, 0, tt.headend, srPolicyCPDescTLV(0, ip4("10.0.0.2"), ip4("1.1.1.1")))
			nlri := &LsAddrPrefix{}
			require.NoError(t, nlri.decodeFromBytes(wire))
			got, err := nlri.Serialize()
			require.NoError(t, err)
			require.Equal(t, wire, got)
		})
	}
}

// RFC 9552 does not list the IPv4 and IPv6 Router-ID TLVs among the node
// descriptor sub-TLVs; only RFC 9857 section 3 does, for the headend of an
// SR Policy. A node descriptor of any other NLRI keeps skipping them.
func TestLsSrPolicyHeadendRouterIDOnlyForSrPolicy(t *testing.T) {
	desc := tlvBytes(256, tlvBytes(512, be32(65001)), tlvBytes(513, be32(0)), tlvBytes(516, ip4("1.1.1.1")), tlvBytes(1028, ip4("10.0.0.1")))

	generic := LsTLVNodeDescriptor{}
	require.NoError(t, generic.DecodeFromBytes(desc))
	assert.False(t, generic.Extract().LocalRouterID.IsValid())
	assert.Len(t, generic.SubTLVs, 3)

	headend := LsTLVNodeDescriptor{}
	require.NoError(t, headend.decodeFromBytes(desc, true))
	assert.Equal(t, netip.MustParseAddr("10.0.0.1"), headend.Extract().LocalRouterID)
	got, err := headend.Serialize()
	require.NoError(t, err)
	assert.Equal(t, desc, got)

	// The constructor rebuilds the headend from the model, and the JSON of
	// a descriptor without Router-IDs does not mention them.
	rebuilt := NewLsTLVNodeDescriptor(headend.Extract(), LS_TLV_LOCAL_NODE_DESC)
	got, err = rebuilt.Serialize()
	require.NoError(t, err)
	assert.Equal(t, desc, got)
}

func TestLsSrPolicyHeadendDestinationKey(t *testing.T) {
	headend := LsNodeDescriptor{Asn: 65001, BGPRouterID: netip.MustParseAddr("1.1.1.1"), LocalRouterID: netip.MustParseAddr("10.0.0.1")}
	key := func(nd LsNodeDescriptor) string {
		tlv := NewLsTLVNodeDescriptor(&nd, LS_TLV_LOCAL_NODE_DESC)
		nlri := &LsSrPolicyCandidatePathNLRI{
			LsNLRI:            LsNLRI{ProtocolID: LS_PROTOCOL_SEGMENT_ROUTING},
			LocalNodeDesc:     &tlv,
			CandidatePathDesc: NewLsTLVSrPolicyCandidatePathDescriptor(&LsSrPolicyCandidatePathDescriptor{Endpoint: netip.MustParseAddr("10.0.0.2"), OriginatorAddress: netip.MustParseAddr("1.1.1.1")}),
		}
		return nlri.String()
	}
	for _, tt := range []struct {
		name   string
		change func(*LsNodeDescriptor)
	}{
		{"headend", func(nd *LsNodeDescriptor) { nd.LocalRouterID = netip.MustParseAddr("10.0.0.3") }},
		{"IPv6 headend", func(nd *LsNodeDescriptor) { nd.LocalRouterIDv6 = netip.MustParseAddr("2001:db8::1") }},
		{"IGP ID with BGP ID", func(nd *LsNodeDescriptor) { nd.IGPRouterID = "0000.0000.0001" }},
		{"confederation", func(nd *LsNodeDescriptor) { nd.BGPConfederationMember = 65002 }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			other := headend
			tt.change(&other)
			require.NotEqual(t, key(headend), key(other))
		})
	}
}

func TestLsSrPolicyNestedUnknownTLVs(t *testing.T) {
	unknown := tlvBytes(65000, []byte{1, 2, 3, 4})
	wire := lsAttrBytes(
		tlvBytes(1212, []byte{0x80, 0, 0, 0}, ip6("fc00::1"), ip6("::"), unknown),
		srPolicySegmentListTLV(0xc000, 1, srPolicySegmentTLV(2, 0xc000, ip6("fc00::2"), []byte{0}, unknown)),
	)
	attr := &PathAttributeLs{}
	require.NoError(t, attr.DecodeFromBytes(wire))
	got, err := attr.Serialize()
	require.NoError(t, err)
	require.Equal(t, wire, got)
}

func TestLsSrSegmentSerializeInvalidAddress(t *testing.T) {
	seg := NewLsTLVSrSegment(&LsSrSegment{SegmentType: LS_SR_SEGMENT_TYPE_C_IPV4_NODE, LocalAddress: netip.MustParseAddr("2001:db8::1")})
	_, err := seg.Serialize()
	require.Error(t, err)
}

// Any 16-octet SID is wire-legal, so a decoded segment must re-serialize
// even when the SID reads as an IPv4-mapped address.
func TestLsSrSegmentDecodedAlwaysReserializes(t *testing.T) {
	wire := lsAttrBytes(
		srPolicySegmentListTLV(0xc000, 1, srPolicySegmentTLV(2, 0xc000, ip6("::ffff:1.2.3.4"), []byte{0})),
	)
	attr := &PathAttributeLs{}
	require.NoError(t, attr.DecodeFromBytes(wire))
	got, err := attr.Serialize()
	require.NoError(t, err)
	require.Equal(t, wire, got)
}
