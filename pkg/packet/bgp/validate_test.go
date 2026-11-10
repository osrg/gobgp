package bgp

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
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

// The value of NEXT_HOP is checked only when the UPDATE has NLRIs in the
// NLRI field. An UPDATE with NLRIs only in MP_REACH_NLRI does not use it.
func Test_Validate_nexthop_without_nlri(t *testing.T) {
	invalid, err := NewPathAttributeNextHop(netip.MustParseAddr("0.0.0.1"))
	require.NoError(t, err)
	rfs := map[Family]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_NONE, RF_IPv6_UC: BGP_ADD_PATH_NONE}

	t.Run("MP_REACH_NLRI only", func(t *testing.T) {
		message := bgpupdateV6().Body.(*BGPUpdate)
		message.PathAttributes = append(message.PathAttributes, invalid)
		res, err := ValidateUpdateMsg(message, rfs, false, false, false)
		assert.NoError(t, err)
		assert.True(t, res)
	})

	t.Run("withdrawn routes only", func(t *testing.T) {
		prefix, err := NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
		require.NoError(t, err)
		message := NewBGPUpdateMessage([]PathNLRI{{NLRI: prefix}}, []PathAttributeInterface{invalid}, nil).Body.(*BGPUpdate)
		res, err := ValidateUpdateMsg(message, rfs, false, false, false)
		assert.NoError(t, err)
		assert.True(t, res)
	})

	t.Run("NLRI field and MP_REACH_NLRI", func(t *testing.T) {
		message := bgpupdate().Body.(*BGPUpdate)
		message.PathAttributes[2] = invalid
		v6 := bgpupdateV6().Body.(*BGPUpdate)
		message.PathAttributes = append(message.PathAttributes, v6.PathAttributes[2])
		res, err := ValidateUpdateMsg(message, rfs, false, false, false)
		require.Error(t, err)
		assert.False(t, res)
		e := err.(*MessageError)
		assert.Equal(t, uint8(BGP_ERROR_SUB_INVALID_NEXT_HOP_ATTRIBUTE), e.SubTypeCode)
		assert.Equal(t, ERROR_HANDLING_TREAT_AS_WITHDRAW, e.ErrorHandling)
	})

	t.Run("NEXT_HOP twice without NLRI", func(t *testing.T) {
		message := bgpupdateV6().Body.(*BGPUpdate)
		message.PathAttributes = append(message.PathAttributes, invalid, invalid)
		res, err := ValidateUpdateMsg(message, rfs, false, false, false)
		require.Error(t, err)
		assert.False(t, res)
		e := err.(*MessageError)
		assert.Equal(t, uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST), e.SubTypeCode)
		assert.Equal(t, ERROR_HANDLING_ATTRIBUTE_DISCARD, e.ErrorHandling)
	})
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

// The next hop in MP_REACH_NLRI gets the same host address check as
// NEXT_HOP. The FlowSpec families carry no next hop, and an unspecified IPv6
// next hop is accepted only with a link-local one.
func Test_Validate_invalid_mpreach_nexthop(t *testing.T) {
	v4, err := NewIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"))
	require.NoError(t, err)
	v6, err := NewIPAddrPrefix(netip.MustParsePrefix("2001:db8::/32"))
	require.NoError(t, err)
	vpn, err := NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix("10.10.10.0/24"), *NewMPLSLabelStack(100), NewRouteDistinguisherTwoOctetAS(65001, 1))
	require.NoError(t, err)
	rfs := map[Family]BGPAddPathMode{
		RF_IPv4_UC:  BGP_ADD_PATH_NONE,
		RF_IPv6_UC:  BGP_ADD_PATH_NONE,
		RF_IPv4_VPN: BGP_ADD_PATH_NONE,
	}

	tests := []struct {
		desc            string
		family          Family
		nlri            NLRI
		nexthop         string
		linkLocal       string
		loopbackAllowed bool
		wantErr         bool
	}{
		{desc: "zero", family: RF_IPv4_UC, nlri: v4, nexthop: "0.0.0.0", wantErr: true},
		{desc: "loopback", family: RF_IPv4_UC, nlri: v4, nexthop: "127.0.0.1", wantErr: true},
		{desc: "loopback allowed", family: RF_IPv4_UC, nlri: v4, nexthop: "127.0.0.1", loopbackAllowed: true},
		{desc: "class D", family: RF_IPv4_UC, nlri: v4, nexthop: "224.0.0.1", wantErr: true},
		{desc: "class E", family: RF_IPv4_UC, nlri: v4, nexthop: "240.0.0.1", wantErr: true},
		{desc: "host address", family: RF_IPv4_UC, nlri: v4, nexthop: "192.168.1.1"},
		{desc: "VPN zero", family: RF_IPv4_VPN, nlri: vpn, nexthop: "0.0.0.0", wantErr: true},
		{desc: "IPv6 loopback", family: RF_IPv6_UC, nlri: v6, nexthop: "::1", wantErr: true},
		{desc: "IPv6 loopback allowed", family: RF_IPv6_UC, nlri: v6, nexthop: "::1", loopbackAllowed: true},
		{desc: "IPv6 multicast", family: RF_IPv6_UC, nlri: v6, nexthop: "ff02::1", wantErr: true},
		{desc: "IPv6 unspecified", family: RF_IPv6_UC, nlri: v6, nexthop: "::", wantErr: true},
		{desc: "IPv6 unspecified with link-local", family: RF_IPv6_UC, nlri: v6, nexthop: "::", linkLocal: "fe80::1"},
		{desc: "IPv6 unspecified with non link-local", family: RF_IPv6_UC, nlri: v6, nexthop: "::", linkLocal: "2001:db8::2", wantErr: true},
		{desc: "IPv6 host address", family: RF_IPv6_UC, nlri: v6, nexthop: "2001:db8::1"},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			nexthops := []netip.Addr{netip.MustParseAddr(tt.nexthop)}
			placeholder := netip.MustParseAddr("fe80::1")
			if tt.linkLocal != "" {
				nexthops = append(nexthops, placeholder)
			}
			reach, err := NewPathAttributeMpReachNLRI(tt.family, []PathNLRI{{NLRI: tt.nlri}}, nexthops...)
			require.NoError(t, err)
			attrs := []PathAttributeInterface{
				NewPathAttributeOrigin(1),
				NewPathAttributeAsPath([]AsPathParamInterface{NewAs4PathParam(2, []uint32{65001})}),
				reach,
			}
			// Go through the wire so that the next hop is the decoded one.
			buf, err := NewBGPUpdateMessage(nil, attrs, nil).Serialize()
			require.NoError(t, err)
			if tt.linkLocal != "" {
				// The constructor drops a second address that is not
				// link-local, so write the one under test on the wire.
				from, to := placeholder.As16(), netip.MustParseAddr(tt.linkLocal).As16()
				buf = bytes.Replace(buf, from[:], to[:], 1)
			}
			m, err := ParseBGPMessage(buf)
			require.NoError(t, err)
			message := m.Body.(*BGPUpdate)

			res, err := ValidateUpdateMsg(message, rfs, true, false, tt.loopbackAllowed)
			if !tt.wantErr {
				assert.NoError(t, err)
				assert.True(t, res)
				return
			}
			require.Error(t, err)
			assert.False(t, res)
			e := err.(*MessageError)
			assert.Equal(t, uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR), e.TypeCode)
			assert.Equal(t, uint8(BGP_ERROR_SUB_OPTIONAL_ATTRIBUTE_ERROR), e.SubTypeCode)
			assert.Equal(t, ERROR_HANDLING_TREAT_AS_WITHDRAW, e.ErrorHandling)
		})
	}

	t.Run("flowspec", func(t *testing.T) {
		// RFC 8955 4: the next hop field MUST be ignored. The constructor
		// writes a zero length next hop for FlowSpec, so build the
		// attribute by hand.
		prefix, err := NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
		require.NoError(t, err)
		nlri, err := NewFlowSpecUnicast(RF_FS_IPv4_UC, []FlowSpecComponentInterface{NewFlowSpecDestinationPrefix(prefix)})
		require.NoError(t, err)
		reach := &PathAttributeMpReachNLRI{
			PathAttribute: PathAttribute{Flags: PathAttrFlags[BGP_ATTR_TYPE_MP_REACH_NLRI], Type: BGP_ATTR_TYPE_MP_REACH_NLRI},
			AFI:           AFI_IP,
			SAFI:          SAFI_FLOW_SPEC_UNICAST,
			Nexthop:       netip.MustParseAddr("0.0.0.0"),
			Value:         []PathNLRI{{NLRI: nlri}},
		}
		res, err := ValidateAttribute(reach, map[Family]BGPAddPathMode{RF_FS_IPv4_UC: BGP_ADD_PATH_NONE}, true, false, false)
		assert.NoError(t, err)
		assert.True(t, res)
	})
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
	assert.Equal(ERROR_HANDLING_TREAT_AS_WITHDRAW, e.ErrorHandling)
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

	// empty AS_PATH for confederation eBGP
	newAttrs = make([]PathAttributeInterface, 0)
	attrs = message.PathAttributes
	for _, attr := range attrs {
		if _, y := attr.(*PathAttributeAsPath); y {
			newAttrs = append(newAttrs, NewPathAttributeAsPath([]AsPathParamInterface{}))
		} else {
			newAttrs = append(newAttrs, attr)
		}
	}

	message.PathAttributes = newAttrs
	res, err = ValidateUpdateMsg(message, map[Family]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, true, true, false)
	assert.Equal(false, res)
	assert.Error(err)
	e = err.(*MessageError)
	assert.Equal(uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR), e.TypeCode)
	assert.Equal(uint8(BGP_ERROR_SUB_MALFORMED_AS_PATH), e.SubTypeCode)
	assert.Equal(ERROR_HANDLING_SESSION_RESET, e.ErrorHandling)
	assert.Nil(e.Data)
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

// rfc7607 2. An OPEN message that carries AS 0 must be rejected with
// "Bad Peer AS". AS 0 used to pass the check for a neighbor configured
// without a peer AS, which accepts any AS number.
func Test_Validate_OpenMsg_zero_as(t *testing.T) {
	assert := assert.New(t)
	routerId := netip.MustParseAddr("192.168.1.2")
	myId := netip.MustParseAddr("192.168.1.1")

	as4Cap := func(asnum uint32) []OptionParameterInterface {
		return []OptionParameterInterface{
			NewOptionParameterCapability([]ParameterCapabilityInterface{
				NewCapFourOctetASNumber(asnum),
			}),
		}
	}

	// The two-octet My Autonomous System field is zero.
	m, err := NewBGPOpenMessage(0, 90, routerId, nil)
	require.NoError(t, err)
	as, err := ValidateOpenMsg(m.Body.(*BGPOpen), 0, 65001, myId)
	assert.Equal(uint32(0), as)
	require.Error(t, err)
	assert.Equal(uint8(BGP_ERROR_SUB_BAD_PEER_AS), err.(*MessageError).SubTypeCode)

	// The four-octet AS capability is zero.
	m, err = NewBGPOpenMessage(AS_TRANS, 90, routerId, as4Cap(0))
	require.NoError(t, err)
	as, err = ValidateOpenMsg(m.Body.(*BGPOpen), 0, 65001, myId)
	assert.Equal(uint32(0), as)
	require.Error(t, err)
	assert.Equal(uint8(BGP_ERROR_SUB_BAD_PEER_AS), err.(*MessageError).SubTypeCode)

	// A neighbor configured without a peer AS still takes any other one.
	m, err = NewBGPOpenMessage(65002, 90, routerId, nil)
	require.NoError(t, err)
	as, err = ValidateOpenMsg(m.Body.(*BGPOpen), 0, 65001, myId)
	assert.NoError(err)
	assert.Equal(uint32(65002), as)

	m, err = NewBGPOpenMessage(AS_TRANS, 90, routerId, as4Cap(65536))
	require.NoError(t, err)
	as, err = ValidateOpenMsg(m.Body.(*BGPOpen), 65536, 65001, myId)
	assert.NoError(err)
	assert.Equal(uint32(65536), as)
}

// rfc7607 2. An UPDATE that carries AS 0 in the AS_PATH, AS4_PATH,
// AGGREGATOR, or AS4_AGGREGATOR attribute must be treated as malformed. The
// receive side used to accept and re-propagate such a route.
func Test_Validate_zero_as(t *testing.T) {
	agg := func(as uint32) *PathAttributeAggregator {
		a, err := NewPathAttributeAggregator(as, netip.MustParseAddr("192.168.1.1"))
		require.NoError(t, err)
		return a
	}
	as4agg := func(as uint32) *PathAttributeAs4Aggregator {
		a, err := NewPathAttributeAs4Aggregator(as, netip.MustParseAddr("192.168.1.1"))
		require.NoError(t, err)
		return a
	}

	tests := []struct {
		name     string
		attr     PathAttributeInterface
		replace  bool // replace the AS_PATH attribute instead of appending
		subCode  uint8
		handling ErrorHandling
	}{
		{
			name:     "AS_PATH",
			attr:     NewPathAttributeAsPath([]AsPathParamInterface{NewAsPathParam(BGP_ASPATH_ATTR_TYPE_SEQ, []uint16{65001, 0})}),
			replace:  true,
			subCode:  BGP_ERROR_SUB_MALFORMED_AS_PATH,
			handling: ERROR_HANDLING_TREAT_AS_WITHDRAW,
		},
		{
			name:     "AS4_PATH",
			attr:     NewPathAttributeAs4Path([]*As4PathParam{NewAs4PathParam(BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65536, 0})}),
			subCode:  BGP_ERROR_SUB_MALFORMED_AS_PATH,
			handling: ERROR_HANDLING_ATTRIBUTE_DISCARD,
		},
		{
			name:     "AGGREGATOR",
			attr:     agg(0),
			subCode:  BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST,
			handling: ERROR_HANDLING_ATTRIBUTE_DISCARD,
		},
		{
			name:     "AS4_AGGREGATOR",
			attr:     as4agg(0),
			subCode:  BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST,
			handling: ERROR_HANDLING_ATTRIBUTE_DISCARD,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			message := bgpupdate().Body.(*BGPUpdate)
			if tt.replace {
				message.PathAttributes[1] = tt.attr
			} else {
				message.PathAttributes = append(message.PathAttributes, tt.attr)
			}

			res, err := ValidateUpdateMsg(message, map[Family]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, false, false, false)
			assert.Equal(false, res)
			require.Error(t, err)
			e := err.(*MessageError)
			assert.Equal(uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR), e.TypeCode)
			assert.Equal(tt.subCode, e.SubTypeCode)
			assert.Equal(tt.handling, e.ErrorHandling)

			// attribute-discard must leave the malformed attribute out
			// of the message; treat-as-withdraw keeps it since the
			// whole route is withdrawn.
			present := slices.ContainsFunc(message.PathAttributes, func(x PathAttributeInterface) bool {
				return x.GetType() == tt.attr.GetType()
			})
			if tt.handling == ERROR_HANDLING_ATTRIBUTE_DISCARD {
				assert.False(present, "discarded attribute should be removed")
			} else {
				assert.True(present)
			}
		})
	}
}

// rfc7606 2. Discarding an AGGREGATOR with AS 0 must not leave an
// AS4_AGGREGATOR behind, which would otherwise reset the session when the
// FSM merges the two.
func Test_Validate_zero_as_aggregator_with_as4_aggregator(t *testing.T) {
	assert := assert.New(t)
	agg, err := NewPathAttributeAggregator(uint32(0), netip.MustParseAddr("192.168.1.1"))
	require.NoError(t, err)
	as4agg, err := NewPathAttributeAs4Aggregator(65536, netip.MustParseAddr("192.168.1.1"))
	require.NoError(t, err)
	message := bgpupdate().Body.(*BGPUpdate)
	message.PathAttributes = append(message.PathAttributes, agg, as4agg)

	res, err := ValidateUpdateMsg(message, map[Family]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}, false, false, false)
	assert.Equal(false, res)
	require.Error(t, err)
	assert.Equal(ERROR_HANDLING_ATTRIBUTE_DISCARD, err.(*MessageError).ErrorHandling)
	for _, a := range message.PathAttributes {
		assert.NotEqual(BGP_ATTR_TYPE_AGGREGATOR, a.GetType())
		assert.NotEqual(BGP_ATTR_TYPE_AS4_AGGREGATOR, a.GetType())
	}
	assert.Len(message.NLRI, 1)
}
