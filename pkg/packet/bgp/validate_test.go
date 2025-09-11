package bgp

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func bgpupdate() *BGPMessage {
	aspath := []AsPathParamInterface{
		NewAsPathParam(2, []uint16{65001}),
	}

	panh, _ := NewPathAttributeNextHop(netip.MustParseAddr("192.168.1.1"))
	p := []PathAttributeInterface{
		NewPathAttributeOrigin(1),
		NewPathAttributeAsPath(aspath),
		panh,
	}

	prefix, _ := NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	n := []*IPAddrPrefix{prefix}
	return NewBGPUpdateMessage(nil, p, []PathNLRI{{NLRI: n[0]}})
}

func bgpupdateV6() *BGPMessage {
	aspath := []AsPathParamInterface{
		NewAsPathParam(2, []uint16{65001}),
	}

	nlri, _ := NewIPAddrPrefix(netip.MustParsePrefix("fe80:1234:1234:5667:8967:af12:8912:1023/100"))
	prefixes := []NLRI{nlri}

	p := []PathAttributeInterface{
		NewPathAttributeOrigin(1),
		NewPathAttributeAsPath(aspath),
	}
	mpreach, _ := NewPathAttributeMpReachNLRI(RF_IPv6_UC, []PathNLRI{{NLRI: prefixes[0]}}, netip.MustParseAddr("1023::"))
	p = append(p, mpreach)
	return NewBGPUpdateMessage(nil, p, nil)
}

func Test_Validate_CapV4(t *testing.T) {
	assert := assert.New(t)
	message := bgpupdate().Body.(*BGPUpdate)
	res, err := ValidateUpdateMsg(message, map[Family]BGPAddPathMode{RF_IPv6_UC: BGP_ADD_PATH_BOTH}, false, false, false)
	assert.Equal(false, res)
	assert.Error(err)

	res, err = ValidateUpdateMsg(message, map[Family]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, false, false, false)
	require.NoError(t, err)
	assert.Equal(true, res)
}

func Test_Validate_CapV6(t *testing.T) {
	assert := assert.New(t)
	message := bgpupdateV6().Body.(*BGPUpdate)
	res, err := ValidateUpdateMsg(message, map[Family]BGPAddPathMode{RF_IPv6_UC: BGP_ADD_PATH_BOTH}, false, false, false)
	assert.NoError(err)
	assert.True(res)

	res, err = ValidateUpdateMsg(message, map[Family]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, false, false, false)
	assert.Error(err)
	assert.False(res)
}

func Test_Validate_OK(t *testing.T) {
	assert := assert.New(t)
	message := bgpupdate().Body.(*BGPUpdate)
	res, err := ValidateUpdateMsg(message, map[Family]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, false, false, false)
	assert.Equal(true, res)
	assert.NoError(err)
}

// func Test_Validate_wellknown_but_nontransitive(t *testing.T) {
// 	assert := assert.New(t)
// 	message := bgpupdate().Body.(*BGPUpdate)

// 	originBytes := []byte{0, 1, 1, 1} // 0 means Flags
// 	origin := &PathAttributeOrigin{}
// 	origin.DecodeFromBytes(originBytes)
// 	message.PathAttributes[0] = origin

// 	res, err := ValidateUpdateMsg(message, []Family{RF_IPv4_UC,})
// 	assert.Equal(false, res)
// 	assert.Error(err)
// 	e := err.(*MessageError)
// 	assert.Equal(BGP_ERROR_UPDATE_MESSAGE_ERROR, e.TypeCode)
// 	assert.Equal(BGP_ERROR_SUB_ATTRIBUTE_FLAGS_ERROR, e.SubTypeCode)
// 	assert.Equal(originBytes, e.Data)
// }

// func Test_Validate_wellknown_but_partial(t *testing.T) {
// 	assert := assert.New(t)
// 	message := bgpupdate().Body.(*BGPUpdate)

// 	originBytes := []byte{BGP_ATTR_FLAG_PARTIAL, 1, 1, 1}
// 	origin := &PathAttributeOrigin{}
// 	origin.DecodeFromBytes(originBytes)
// 	message.PathAttributes[0] = origin

// 	res, err := ValidateUpdateMsg(message, []Family{RF_IPv4_UC,})
// 	assert.Equal(false, res)
// 	assert.Error(err)
// 	e := err.(*MessageError)
// 	assert.Equal(BGP_ERROR_UPDATE_MESSAGE_ERROR, e.TypeCode)
// 	assert.Equal(BGP_ERROR_SUB_ATTRIBUTE_FLAGS_ERROR, e.SubTypeCode)
// 	assert.Equal(originBytes, e.Data)
// }

// func Test_Validate_optional_nontransitive_but_partial(t *testing.T) {
// 	assert := assert.New(t)
// 	message := bgpupdate().Body.(*BGPUpdate)
// 	f := BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_PARTIAL
// 	originBytes := []byte{byte(f), 1, 1, 1}
// 	origin := &PathAttributeOrigin{}
// 	origin.DecodeFromBytes(originBytes)
// 	message.PathAttributes[0] = origin

// 	res, err := ValidateUpdateMsg(message, []Family{RF_IPv4_UC,})
// 	assert.Equal(false, res)
// 	assert.Error(err)
// 	e := err.(*MessageError)
// 	assert.Equal(BGP_ERROR_UPDATE_MESSAGE_ERROR, e.TypeCode)
// 	assert.Equal(BGP_ERROR_SUB_ATTRIBUTE_FLAGS_ERROR, e.SubTypeCode)
// 	assert.Equal(originBytes, e.Data)
// }

// func Test_Validate_flag_mismatch(t *testing.T) {
// 	assert := assert.New(t)
// 	message := bgpupdate().Body.(*BGPUpdate)
// 	f := BGP_ATTR_FLAG_OPTIONAL
// 	// origin needs to be well-known
// 	originBytes := []byte{byte(f), 1, 1, 1}
// 	origin := &PathAttributeOrigin{}
// 	origin.DecodeFromBytes(originBytes)
// 	message.PathAttributes[0] = origin

// 	res, err := ValidateUpdateMsg(message, []Family{RF_IPv4_UC,})
// 	assert.Equal(false, res)
// 	assert.Error(err)
// 	e := err.(*MessageError)
// 	assert.Equal(BGP_ERROR_UPDATE_MESSAGE_ERROR, e.TypeCode)
// 	assert.Equal(BGP_ERROR_SUB_ATTRIBUTE_FLAGS_ERROR, e.SubTypeCode)
// 	assert.Equal(originBytes, e.Data)
// }

func Test_Validate_duplicate_attribute(t *testing.T) {
	assert := assert.New(t)
	message := bgpupdate().Body.(*BGPUpdate)
	// duplicate origin path attribute
	originBytes := []byte{byte(PathAttrFlags[BGP_ATTR_TYPE_ORIGIN]), 1, 1, 1}
	origin := &PathAttributeOrigin{}
	assert.NoError(origin.DecodeFromBytes(originBytes))
	message.PathAttributes = append(message.PathAttributes, origin)

	res, err := ValidateUpdateMsg(message, map[Family]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, false, false, false)
	assert.Equal(false, res)
	assert.Error(err)
	e := err.(*MessageError)
	assert.Equal(uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR), e.TypeCode)
	assert.Equal(uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST), e.SubTypeCode)
	assert.Equal(ERROR_HANDLING_ATTRIBUTE_DISCARD, e.ErrorHandling)
	assert.Nil(e.Data)
}

func Test_Validate_mandatory_missing(t *testing.T) {
	assert := assert.New(t)
	message := bgpupdate().Body.(*BGPUpdate)
	message.PathAttributes = message.PathAttributes[1:]
	res, err := ValidateUpdateMsg(message, map[Family]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, false, false, false)
	assert.Equal(false, res)
	assert.Error(err)
	e := err.(*MessageError)
	assert.Equal(uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR), e.TypeCode)
	assert.Equal(uint8(BGP_ERROR_SUB_MISSING_WELL_KNOWN_ATTRIBUTE), e.SubTypeCode)
	assert.Equal(ERROR_HANDLING_TREAT_AS_WITHDRAW, e.ErrorHandling)
	missing, _ := binary.Uvarint(e.Data)
	assert.Equal(uint64(1), missing)
}

func Test_Validate_mandatory_missing_nocheck(t *testing.T) {
	assert := assert.New(t)
	message := bgpupdate().Body.(*BGPUpdate)
	message.PathAttributes = message.PathAttributes[1:]
	message.NLRI = nil

	res, err := ValidateUpdateMsg(message, map[Family]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, false, false, false)
	assert.NoError(err)
	assert.Equal(true, res)
}

func Test_Validate_invalid_origin(t *testing.T) {
	assert := assert.New(t)
	message := bgpupdate().Body.(*BGPUpdate)
	// origin needs to be well-known
	originBytes := []byte{byte(PathAttrFlags[BGP_ATTR_TYPE_ORIGIN]), 1, 1, 5}
	origin := &PathAttributeOrigin{}
	assert.NoError(origin.DecodeFromBytes(originBytes))
	message.PathAttributes[0] = origin

	res, err := ValidateUpdateMsg(message, map[Family]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, false, false, false)
	assert.Error(err)
	assert.Equal(false, res)
	e := err.(*MessageError)
	assert.Equal(uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR), e.TypeCode)
	assert.Equal(uint8(BGP_ERROR_SUB_INVALID_ORIGIN_ATTRIBUTE), e.SubTypeCode)
	assert.Equal(ERROR_HANDLING_TREAT_AS_WITHDRAW, e.ErrorHandling)
	assert.Equal(originBytes, e.Data)
}

func Test_Validate_invalid_nexthop_zero(t *testing.T) {
	assert := assert.New(t)
	message := bgpupdate().Body.(*BGPUpdate)

	// invalid nexthop
	addr := net.ParseIP("0.0.0.1").To4()
	nexthopBytes := []byte{byte(PathAttrFlags[BGP_ATTR_TYPE_NEXT_HOP]), 3, 4}
	nexthopBytes = append(nexthopBytes, addr...)
	nexthop := &PathAttributeNextHop{}
	assert.NoError(nexthop.DecodeFromBytes(nexthopBytes))
	message.PathAttributes[2] = nexthop

	res, err := ValidateUpdateMsg(message, map[Family]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, false, false, false)
	assert.Error(err)
	assert.Equal(false, res)
	e := err.(*MessageError)
	assert.Equal(uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR), e.TypeCode)
	assert.Equal(uint8(BGP_ERROR_SUB_INVALID_NEXT_HOP_ATTRIBUTE), e.SubTypeCode)
	assert.Equal(ERROR_HANDLING_TREAT_AS_WITHDRAW, e.ErrorHandling)
	assert.Equal(nexthopBytes, e.Data)
}

func Test_Validate_invalid_nexthop_lo(t *testing.T) {
	tests := []struct {
		desc              string
		inLoopbackAllowed bool
		wantErr           bool
	}{{
		desc:              "loopback-disallowed",
		inLoopbackAllowed: false,
		wantErr:           true,
	}, {
		desc:              "loopback-allowed",
		inLoopbackAllowed: true,
		wantErr:           false,
	}}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			assert := assert.New(t)
			message := bgpupdate().Body.(*BGPUpdate)

			// invalid nexthop
			addr := net.ParseIP("127.0.0.1").To4()
			nexthopBytes := []byte{byte(PathAttrFlags[BGP_ATTR_TYPE_NEXT_HOP]), 3, 4}
			nexthopBytes = append(nexthopBytes, addr...)
			nexthop := &PathAttributeNextHop{}
			assert.NoError(nexthop.DecodeFromBytes(nexthopBytes))
			message.PathAttributes[2] = nexthop

			res, err := ValidateUpdateMsg(message, map[Family]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, false, false, tt.inLoopbackAllowed)
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(false, res)
				e := err.(*MessageError)
				assert.Equal(uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR), e.TypeCode)
				assert.Equal(uint8(BGP_ERROR_SUB_INVALID_NEXT_HOP_ATTRIBUTE), e.SubTypeCode)
				assert.Equal(ERROR_HANDLING_TREAT_AS_WITHDRAW, e.ErrorHandling)
				assert.Equal(nexthopBytes, e.Data)
			} else {
				assert.NoError(err)
				assert.Equal(true, res)
			}
		})
	}
}

func Test_Validate_invalid_nexthop_de(t *testing.T) {
	assert := assert.New(t)
	message := bgpupdate().Body.(*BGPUpdate)

	// invalid nexthop
	addr := net.ParseIP("224.0.0.1").To4()
	nexthopBytes := []byte{byte(PathAttrFlags[BGP_ATTR_TYPE_NEXT_HOP]), 3, 4}
	nexthopBytes = append(nexthopBytes, addr...)
	nexthop := &PathAttributeNextHop{}
	assert.NoError(nexthop.DecodeFromBytes(nexthopBytes))
	message.PathAttributes[2] = nexthop

	res, err := ValidateUpdateMsg(message, map[Family]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, false, false, false)
	assert.Equal(false, res)
	assert.Error(err)
	e := err.(*MessageError)
	assert.Equal(uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR), e.TypeCode)
	assert.Equal(uint8(BGP_ERROR_SUB_INVALID_NEXT_HOP_ATTRIBUTE), e.SubTypeCode)
	assert.Equal(ERROR_HANDLING_TREAT_AS_WITHDRAW, e.ErrorHandling)
	assert.Equal(nexthopBytes, e.Data)
}

func Test_Validate_unrecognized_well_known(t *testing.T) {
	assert := assert.New(t)
	message := bgpupdate().Body.(*BGPUpdate)
	f := BGP_ATTR_FLAG_TRANSITIVE
	unknownBytes := []byte{byte(f), 30, 1, 1}
	unknown := &PathAttributeUnknown{}
	assert.NoError(unknown.DecodeFromBytes(unknownBytes))
	message.PathAttributes = append(message.PathAttributes, unknown)

	res, err := ValidateUpdateMsg(message, map[Family]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, false, false, false)
	assert.Equal(false, res)
	assert.Error(err)
	e := err.(*MessageError)
	assert.Equal(uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR), e.TypeCode)
	assert.Equal(uint8(BGP_ERROR_SUB_UNRECOGNIZED_WELL_KNOWN_ATTRIBUTE), e.SubTypeCode)
	assert.Equal(ERROR_HANDLING_SESSION_RESET, e.ErrorHandling)
	assert.Equal(unknownBytes, e.Data)
}

func Test_Validate_aspath(t *testing.T) {
	assert := assert.New(t)
	message := bgpupdate().Body.(*BGPUpdate)

	// VALID AS_PATH
	res, err := ValidateUpdateMsg(message, map[Family]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, true, false, false)
	require.NoError(t, err)
	assert.Equal(true, res)

	// CONFED_SET
	newAttrs := make([]PathAttributeInterface, 0)
	attrs := message.PathAttributes
	for _, attr := range attrs {
		if _, y := attr.(*PathAttributeAsPath); y {
			aspath := []AsPathParamInterface{
				NewAsPathParam(BGP_ASPATH_ATTR_TYPE_CONFED_SET, []uint16{65001}),
			}
			newAttrs = append(newAttrs, NewPathAttributeAsPath(aspath))
		} else {
			newAttrs = append(newAttrs, attr)
		}
	}

	message.PathAttributes = newAttrs
	res, err = ValidateUpdateMsg(message, map[Family]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, true, false, false)
	assert.Equal(false, res)
	assert.Error(err)
	e := err.(*MessageError)
	assert.Equal(uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR), e.TypeCode)
	assert.Equal(uint8(BGP_ERROR_SUB_MALFORMED_AS_PATH), e.SubTypeCode)
	assert.Equal(ERROR_HANDLING_TREAT_AS_WITHDRAW, e.ErrorHandling)
	assert.Nil(e.Data)

	res, err = ValidateUpdateMsg(message, map[Family]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, true, true, false)
	assert.Equal(false, res)
	assert.Error(err)
	e = err.(*MessageError)
	assert.Equal(uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR), e.TypeCode)
	assert.Equal(uint8(BGP_ERROR_SUB_MALFORMED_AS_PATH), e.SubTypeCode)
	assert.Nil(e.Data)

	// CONFED_SEQ
	newAttrs = make([]PathAttributeInterface, 0)
	attrs = message.PathAttributes
	for _, attr := range attrs {
		if _, y := attr.(*PathAttributeAsPath); y {
			aspath := []AsPathParamInterface{
				NewAsPathParam(BGP_ASPATH_ATTR_TYPE_CONFED_SEQ, []uint16{65001}),
			}
			newAttrs = append(newAttrs, NewPathAttributeAsPath(aspath))
		} else {
			newAttrs = append(newAttrs, attr)
		}
	}

	message.PathAttributes = newAttrs
	res, err = ValidateUpdateMsg(message, map[Family]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, true, false, false)
	assert.Equal(false, res)
	assert.Error(err)
	e = err.(*MessageError)
	assert.Equal(uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR), e.TypeCode)
	assert.Equal(uint8(BGP_ERROR_SUB_MALFORMED_AS_PATH), e.SubTypeCode)
	assert.Equal(ERROR_HANDLING_TREAT_AS_WITHDRAW, e.ErrorHandling)
	assert.Nil(e.Data)

	res, err = ValidateUpdateMsg(message, map[Family]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, true, true, false)
	require.NoError(t, err)
	assert.Equal(true, res)
}

func Test_Validate_flowspec(t *testing.T) {
	assert := assert.New(t)
	cmp := make([]FlowSpecComponentInterface, 0)
	destPrefix, _ := NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
	cmp = append(cmp, NewFlowSpecDestinationPrefix(destPrefix))
	srcPrefix, _ := NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
	cmp = append(cmp, NewFlowSpecSourcePrefix(srcPrefix))
	item1 := NewFlowSpecComponentItem(DEC_NUM_OP_EQ, TCP)
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_IP_PROTO, []*FlowSpecComponentItem{item1}))
	item2 := NewFlowSpecComponentItem(DEC_NUM_OP_GT_EQ, 20)
	item3 := NewFlowSpecComponentItem(DEC_NUM_OP_AND|DEC_NUM_OP_LT_EQ, 30)
	item4 := NewFlowSpecComponentItem(DEC_NUM_OP_EQ, 10)
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_PORT, []*FlowSpecComponentItem{item2, item3, item4}))
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_DST_PORT, []*FlowSpecComponentItem{item2, item3, item4}))
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_SRC_PORT, []*FlowSpecComponentItem{item2, item3, item4}))
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_ICMP_TYPE, []*FlowSpecComponentItem{item2, item3, item4}))
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_ICMP_CODE, []*FlowSpecComponentItem{item2, item3, item4}))
	item5 := NewFlowSpecComponentItem(0, TCP_FLAG_ACK)
	item6 := NewFlowSpecComponentItem(BITMASK_FLAG_OP_AND|BITMASK_FLAG_OP_NOT, TCP_FLAG_URGENT)
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_TCP_FLAG, []*FlowSpecComponentItem{item5, item6}))
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_PKT_LEN, []*FlowSpecComponentItem{item2, item3, item4}))
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_DSCP, []*FlowSpecComponentItem{item2, item3, item4}))
	isFragment := uint64(0x02)
	item7 := NewFlowSpecComponentItem(BITMASK_FLAG_OP_MATCH, isFragment)
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_FRAGMENT, []*FlowSpecComponentItem{item7}))
	n1, _ := NewFlowSpecUnicast(RF_FS_IPv4_UC, cmp)
	a, _ := NewPathAttributeMpReachNLRI(RF_FS_IPv4_UC, []PathNLRI{{NLRI: n1}}, netip.IPv4Unspecified())
	m := map[Family]BGPAddPathMode{RF_FS_IPv4_UC: BGP_ADD_PATH_NONE}
	_, err := ValidateAttribute(a, m, false, false, false)
	assert.NoError(err)

	cmp = make([]FlowSpecComponentInterface, 0)
	srcPrefix2, _ := NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
	cmp = append(cmp, NewFlowSpecSourcePrefix(srcPrefix2))
	destPrefix2, _ := NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
	cmp = append(cmp, NewFlowSpecDestinationPrefix(destPrefix2))
	n1, _ = NewFlowSpecUnicast(RF_FS_IPv4_UC, cmp)
	a, _ = NewPathAttributeMpReachNLRI(RF_FS_IPv4_UC, []PathNLRI{{NLRI: n1}}, netip.IPv4Unspecified())
	// Swaps components order to reproduce the rules order violation.
	n1.Value[0], n1.Value[1] = n1.Value[1], n1.Value[0]
	_, err = ValidateAttribute(a, m, false, false, false)
	assert.NotNil(err)
}

func TestValidateLargeCommunities(t *testing.T) {
	assert := assert.New(t)
	c1, err := ParseLargeCommunity("10:10:10")
	assert.NoError(err)
	c2, err := ParseLargeCommunity("10:10:10")
	assert.NoError(err)
	c3, err := ParseLargeCommunity("10:10:20")
	assert.NoError(err)
	a := NewPathAttributeLargeCommunities([]*LargeCommunity{c1, c2, c3})
	assert.True(len(a.Values) == 3)
	_, err = ValidateAttribute(a, nil, false, false, false)
	assert.NoError(err)
	assert.True(len(a.Values) == 2)
}

//nolint:errcheck
func FuzzParseLargeCommunity(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string) {
		ParseLargeCommunity(data)
	})
}
