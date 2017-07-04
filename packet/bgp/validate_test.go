package bgp

import (
	"encoding/binary"
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func bgpupdate() *BGPMessage {
	aspath := []AsPathParamInterface{
		NewAsPathParam(2, []uint16{65001}),
	}

	p := []PathAttributeInterface{
		NewPathAttributeOrigin(1),
		NewPathAttributeAsPath(aspath),
		NewPathAttributeNextHop("192.168.1.1"),
	}

	n := []*IPAddrPrefix{NewIPAddrPrefix(24, "10.10.10.0")}
	return NewBGPUpdateMessage(nil, p, n)
}

func bgpupdateV6() *BGPMessage {
	aspath := []AsPathParamInterface{
		NewAsPathParam(2, []uint16{65001}),
	}

	mp_nlri := []AddrPrefixInterface{NewIPv6AddrPrefix(100,
		"fe80:1234:1234:5667:8967:af12:8912:1023")}

	p := []PathAttributeInterface{
		NewPathAttributeOrigin(1),
		NewPathAttributeAsPath(aspath),
		NewPathAttributeMpReachNLRI("1023::", mp_nlri),
	}
	return NewBGPUpdateMessage(nil, p, nil)
}

func Test_Validate_CapV4(t *testing.T) {
	assert := assert.New(t)
	message := bgpupdate().Body.(*BGPUpdate)
	res, err := ValidateUpdateMsg(message, map[RouteFamily]BGPAddPathMode{RF_IPv6_UC: BGP_ADD_PATH_BOTH}, false)
	assert.Equal(false, res)
	assert.Error(err)

	res, err = ValidateUpdateMsg(message, map[RouteFamily]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, false)
	assert.Equal(true, res)
}

func Test_Validate_CapV6(t *testing.T) {
	assert := assert.New(t)
	message := bgpupdateV6().Body.(*BGPUpdate)
	res, err := ValidateUpdateMsg(message, map[RouteFamily]BGPAddPathMode{RF_IPv6_UC: BGP_ADD_PATH_BOTH}, false)
	assert.Equal(true, res)
	assert.NoError(err)

	res, err = ValidateUpdateMsg(message, map[RouteFamily]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, false)
	assert.Equal(false, res)
}

func Test_Validate_OK(t *testing.T) {
	assert := assert.New(t)
	message := bgpupdate().Body.(*BGPUpdate)
	res, err := ValidateUpdateMsg(message, map[RouteFamily]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, false)
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

// 	res, err := ValidateUpdateMsg(message, []RouteFamily{RF_IPv4_UC,})
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

// 	res, err := ValidateUpdateMsg(message, []RouteFamily{RF_IPv4_UC,})
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

// 	res, err := ValidateUpdateMsg(message, []RouteFamily{RF_IPv4_UC,})
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

// 	res, err := ValidateUpdateMsg(message, []RouteFamily{RF_IPv4_UC,})
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
	origin.DecodeFromBytes(originBytes)
	message.PathAttributes = append(message.PathAttributes, origin)

	res, err := ValidateUpdateMsg(message, map[RouteFamily]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, false)
	assert.Equal(false, res)
	assert.Error(err)
	e := err.(*MessageError)
	assert.Equal(uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR), e.TypeCode)
	assert.Equal(uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST), e.SubTypeCode)
	assert.Nil(e.Data)
}

func Test_Validate_mandatory_missing(t *testing.T) {
	assert := assert.New(t)
	message := bgpupdate().Body.(*BGPUpdate)
	message.PathAttributes = message.PathAttributes[1:]
	res, err := ValidateUpdateMsg(message, map[RouteFamily]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, false)
	assert.Equal(false, res)
	assert.Error(err)
	e := err.(*MessageError)
	assert.Equal(uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR), e.TypeCode)
	assert.Equal(uint8(BGP_ERROR_SUB_MISSING_WELL_KNOWN_ATTRIBUTE), e.SubTypeCode)
	missing, _ := binary.Uvarint(e.Data)
	assert.Equal(uint64(1), missing)
}

func Test_Validate_mandatory_missing_nocheck(t *testing.T) {
	assert := assert.New(t)
	message := bgpupdate().Body.(*BGPUpdate)
	message.PathAttributes = message.PathAttributes[1:]
	message.NLRI = nil

	res, err := ValidateUpdateMsg(message, map[RouteFamily]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, false)
	assert.Equal(true, res)
	assert.NoError(err)
}

func Test_Validate_invalid_origin(t *testing.T) {
	assert := assert.New(t)
	message := bgpupdate().Body.(*BGPUpdate)
	// origin needs to be well-known
	originBytes := []byte{byte(PathAttrFlags[BGP_ATTR_TYPE_ORIGIN]), 1, 1, 5}
	origin := &PathAttributeOrigin{}
	origin.DecodeFromBytes(originBytes)
	message.PathAttributes[0] = origin

	res, err := ValidateUpdateMsg(message, map[RouteFamily]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, false)
	assert.Equal(false, res)
	assert.Error(err)
	e := err.(*MessageError)
	assert.Equal(uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR), e.TypeCode)
	assert.Equal(uint8(BGP_ERROR_SUB_INVALID_ORIGIN_ATTRIBUTE), e.SubTypeCode)
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
	nexthop.DecodeFromBytes(nexthopBytes)
	message.PathAttributes[2] = nexthop

	res, err := ValidateUpdateMsg(message, map[RouteFamily]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, false)
	assert.Equal(false, res)
	assert.Error(err)
	e := err.(*MessageError)
	assert.Equal(uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR), e.TypeCode)
	assert.Equal(uint8(BGP_ERROR_SUB_INVALID_NEXT_HOP_ATTRIBUTE), e.SubTypeCode)
	assert.Equal(nexthopBytes, e.Data)
}

func Test_Validate_invalid_nexthop_lo(t *testing.T) {
	assert := assert.New(t)
	message := bgpupdate().Body.(*BGPUpdate)

	// invalid nexthop
	addr := net.ParseIP("127.0.0.1").To4()
	nexthopBytes := []byte{byte(PathAttrFlags[BGP_ATTR_TYPE_NEXT_HOP]), 3, 4}
	nexthopBytes = append(nexthopBytes, addr...)
	nexthop := &PathAttributeNextHop{}
	nexthop.DecodeFromBytes(nexthopBytes)
	message.PathAttributes[2] = nexthop

	res, err := ValidateUpdateMsg(message, map[RouteFamily]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, false)
	assert.Equal(false, res)
	assert.Error(err)
	e := err.(*MessageError)
	assert.Equal(uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR), e.TypeCode)
	assert.Equal(uint8(BGP_ERROR_SUB_INVALID_NEXT_HOP_ATTRIBUTE), e.SubTypeCode)
	assert.Equal(nexthopBytes, e.Data)
}

func Test_Validate_invalid_nexthop_de(t *testing.T) {
	assert := assert.New(t)
	message := bgpupdate().Body.(*BGPUpdate)

	// invalid nexthop
	addr := net.ParseIP("224.0.0.1").To4()
	nexthopBytes := []byte{byte(PathAttrFlags[BGP_ATTR_TYPE_NEXT_HOP]), 3, 4}
	nexthopBytes = append(nexthopBytes, addr...)
	nexthop := &PathAttributeNextHop{}
	nexthop.DecodeFromBytes(nexthopBytes)
	message.PathAttributes[2] = nexthop

	res, err := ValidateUpdateMsg(message, map[RouteFamily]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, false)
	assert.Equal(false, res)
	assert.Error(err)
	e := err.(*MessageError)
	assert.Equal(uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR), e.TypeCode)
	assert.Equal(uint8(BGP_ERROR_SUB_INVALID_NEXT_HOP_ATTRIBUTE), e.SubTypeCode)
	assert.Equal(nexthopBytes, e.Data)

}

func Test_Validate_unrecognized_well_known(t *testing.T) {

	assert := assert.New(t)
	message := bgpupdate().Body.(*BGPUpdate)
	f := BGP_ATTR_FLAG_TRANSITIVE
	unknownBytes := []byte{byte(f), 30, 1, 1}
	unknown := &PathAttributeUnknown{}
	unknown.DecodeFromBytes(unknownBytes)
	message.PathAttributes = append(message.PathAttributes, unknown)

	res, err := ValidateUpdateMsg(message, map[RouteFamily]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, false)
	assert.Equal(false, res)
	assert.Error(err)
	e := err.(*MessageError)
	assert.Equal(uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR), e.TypeCode)
	assert.Equal(uint8(BGP_ERROR_SUB_UNRECOGNIZED_WELL_KNOWN_ATTRIBUTE), e.SubTypeCode)
	assert.Equal(unknownBytes, e.Data)
}

func Test_Validate_aspath(t *testing.T) {

	assert := assert.New(t)
	message := bgpupdate().Body.(*BGPUpdate)

	// VALID AS_PATH
	res, err := ValidateUpdateMsg(message, map[RouteFamily]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, true)
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
	res, err = ValidateUpdateMsg(message, map[RouteFamily]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, true)
	assert.Equal(false, res)
	assert.Error(err)
	e := err.(*MessageError)
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
	res, err = ValidateUpdateMsg(message, map[RouteFamily]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, true)
	assert.Equal(false, res)
	assert.Error(err)
	e = err.(*MessageError)
	assert.Equal(uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR), e.TypeCode)
	assert.Equal(uint8(BGP_ERROR_SUB_MALFORMED_AS_PATH), e.SubTypeCode)
	assert.Nil(e.Data)
}

func Test_Validate_flowspec(t *testing.T) {
	assert := assert.New(t)
	cmp := make([]FlowSpecComponentInterface, 0)
	cmp = append(cmp, NewFlowSpecDestinationPrefix(NewIPAddrPrefix(24, "10.0.0.0")))
	cmp = append(cmp, NewFlowSpecSourcePrefix(NewIPAddrPrefix(24, "10.0.0.0")))
	eq := 0x1
	gt := 0x2
	lt := 0x4
	and := 0x40
	not := 0x2
	item1 := NewFlowSpecComponentItem(eq, TCP)
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_IP_PROTO, []*FlowSpecComponentItem{item1}))
	item2 := NewFlowSpecComponentItem(gt|eq, 20)
	item3 := NewFlowSpecComponentItem(and|lt|eq, 30)
	item4 := NewFlowSpecComponentItem(eq, 10)
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_PORT, []*FlowSpecComponentItem{item2, item3, item4}))
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_DST_PORT, []*FlowSpecComponentItem{item2, item3, item4}))
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_SRC_PORT, []*FlowSpecComponentItem{item2, item3, item4}))
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_ICMP_TYPE, []*FlowSpecComponentItem{item2, item3, item4}))
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_ICMP_CODE, []*FlowSpecComponentItem{item2, item3, item4}))
	item5 := NewFlowSpecComponentItem(0, TCP_FLAG_ACK)
	item6 := NewFlowSpecComponentItem(and|not, TCP_FLAG_URGENT)
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_TCP_FLAG, []*FlowSpecComponentItem{item5, item6}))
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_PKT_LEN, []*FlowSpecComponentItem{item2, item3, item4}))
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_DSCP, []*FlowSpecComponentItem{item2, item3, item4}))
	isFlagment := 0x02
	item7 := NewFlowSpecComponentItem(isFlagment, 0)
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_FRAGMENT, []*FlowSpecComponentItem{item7}))
	n1 := NewFlowSpecIPv4Unicast(cmp)
	a := NewPathAttributeMpReachNLRI("", []AddrPrefixInterface{n1})
	m := map[RouteFamily]BGPAddPathMode{RF_FS_IPv4_UC: BGP_ADD_PATH_NONE}
	_, err := ValidateAttribute(a, m, false)
	assert.Nil(err)

	cmp = make([]FlowSpecComponentInterface, 0)
	cmp = append(cmp, NewFlowSpecSourcePrefix(NewIPAddrPrefix(24, "10.0.0.0")))
	cmp = append(cmp, NewFlowSpecDestinationPrefix(NewIPAddrPrefix(24, "10.0.0.0")))
	n1 = NewFlowSpecIPv4Unicast(cmp)
	a = NewPathAttributeMpReachNLRI("", []AddrPrefixInterface{n1})
	_, err = ValidateAttribute(a, m, false)
	assert.NotNil(err)
}

func TestValidateLargeCommunities(t *testing.T) {
	assert := assert.New(t)
	c1, err := ParseLargeCommunity("10:10:10")
	assert.Nil(err)
	c2, err := ParseLargeCommunity("10:10:10")
	assert.Nil(err)
	c3, err := ParseLargeCommunity("10:10:20")
	assert.Nil(err)
	a := NewPathAttributeLargeCommunities([]*LargeCommunity{c1, c2, c3})
	assert.True(len(a.Values) == 3)
	_, err = ValidateAttribute(a, nil, false)
	assert.Nil(err)
	assert.True(len(a.Values) == 2)
}
