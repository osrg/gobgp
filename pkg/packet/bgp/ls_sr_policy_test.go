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

	// An empty SR Policy category produces no TLVs.
	assert.Empty(NewLsAttributeSrPolicyTLVs(&LsAttributeSrPolicy{}))
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
		{"truncated sub-TLV inside srv6 binding sid", lsAttrBytes(tlvBytes(1212, []byte{0, 0, 0, 0}, ip6("::1"), ip6("::"), []byte{0x04, 0xe2, 0x00, 0x04, 0x00}))},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attr := PathAttributeLs{}
			assert.Error(attr.DecodeFromBytes(test.in))
		})
	}
}

func Test_PathAttributeLsSrPolicyTolerance(t *testing.T) {
	assert := assert.New(t)

	t.Run("duplicate single-instance TLVs: first wins", func(t *testing.T) {
		in := lsAttrBytes(
			tlvBytes(1202, []byte{1, 0, 0x40, 0x00}, be32(100)),
			tlvBytes(1202, []byte{2, 0, 0x00, 0x00}, be32(200)),
			tlvBytes(1213, []byte("first")),
			tlvBytes(1213, []byte("second")),
			tlvBytes(1201, []byte{0x40, 0x00, 0x00, 0x00}, labelField(1), be32(0)),
			tlvBytes(1201, []byte{0x40, 0x00, 0x00, 0x00}, labelField(2), be32(0)),
		)
		attr := PathAttributeLs{}
		assert.NoError(attr.DecodeFromBytes(in))
		sp := attr.Extract().SrPolicy
		assert.EqualValues(100, sp.State.Preference)
		assert.Equal("first", *sp.PolicyName)
		assert.EqualValues(1, sp.BindingSID.Label)
		// All instances are kept for faithful re-serialization.
		got, err := attr.Serialize()
		assert.NoError(err)
		assert.Equal(in, got)
	})

	t.Run("unknown sub-TLV inside the SRv6 binding SID is forwarded", func(t *testing.T) {
		in := lsAttrBytes(tlvBytes(1212, []byte{0x80, 0, 0, 0}, ip6("fc00::1"), ip6("::"), tlvBytes(65000, []byte{1, 2, 3, 4})))
		attr := PathAttributeLs{}
		require.NoError(t, attr.DecodeFromBytes(in))
		if assert.Len(attr.Extract().SrPolicy.Srv6BindingSIDs, 1) {
			assert.Equal(netip.MustParseAddr("fc00::1"), attr.Extract().SrPolicy.Srv6BindingSIDs[0].SID)
		}
		got, err := attr.Serialize()
		require.NoError(t, err)
		assert.Equal(in, got)
	})
}
