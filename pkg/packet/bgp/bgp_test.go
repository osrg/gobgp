// Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bgp

import (
	"bytes"
	"encoding/binary"
	"math"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func keepalive() *BGPMessage {
	return NewBGPKeepAliveMessage()
}

func notification() *BGPMessage {
	return NewBGPNotificationMessage(1, 2, nil)
}

func refresh() *BGPMessage {
	return NewBGPRouteRefreshMessage(1, 2, 10)
}

var result []string

func BenchmarkNormalizeFlowSpecOpValues(b *testing.B) {
	var r []string
	for n := 0; n < b.N; n++ {
		r = normalizeFlowSpecOpValues([]string{"&<=80"})
	}
	result = r
}

func Test_Message(t *testing.T) {
	l := []*BGPMessage{keepalive(), notification(), refresh(), NewTestBGPOpenMessage(), NewTestBGPUpdateMessage()}

	for _, m1 := range l {
		buf1, err := m1.Serialize()
		assert.NoError(t, err)

		t.Log("LEN =", len(buf1))
		m2, err := ParseBGPMessage(buf1)
		assert.NoError(t, err)

		// FIXME: shouldn't but workaround for some structs.
		_, err = m2.Serialize()
		assert.NoError(t, err)

		assert.True(t, reflect.DeepEqual(m1, m2))
	}
}

func Test_IPAddrPrefixString(t *testing.T) {
	ipv4 := NewIPAddrPrefix(24, "129.6.10.0")
	assert.Equal(t, "129.6.10.0/24", ipv4.String())
	ipv4 = NewIPAddrPrefix(24, "129.6.10.1")
	assert.Equal(t, "129.6.10.0/24", ipv4.String())
	ipv4 = NewIPAddrPrefix(22, "129.6.129.0")
	assert.Equal(t, "129.6.128.0/22", ipv4.String())

	ipv6 := NewIPv6AddrPrefix(64, "3343:faba:3903::0")
	assert.Equal(t, "3343:faba:3903::/64", ipv6.String())
	ipv6 = NewIPv6AddrPrefix(64, "3343:faba:3903::1")
	assert.Equal(t, "3343:faba:3903::/64", ipv6.String())
	ipv6 = NewIPv6AddrPrefix(63, "3343:faba:3903:129::0")
	assert.Equal(t, "3343:faba:3903:128::/63", ipv6.String())
}

func Test_MalformedPrefixLookup(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		inPrefix    string
		routeFamily RouteFamily
		want        AddrPrefixInterface
		err         bool
	}{
		{"129.6.128/22", RF_IPv4_UC, nil, true},
		{"foo", RF_IPv4_UC, nil, true},
		{"3343:faba:3903:128::::/63", RF_IPv6_UC, nil, true},
		{"foo", RF_IPv6_UC, nil, true},
	}

	for _, test := range tests {
		afi, safi := RouteFamilyToAfiSafi(RF_IPv4_UC)
		p, err := NewPrefixFromRouteFamily(afi, safi, test.inPrefix)
		if test.err {
			assert.Error(err)
		} else {
			assert.Equal(test.want, p)
		}
	}

}

func Test_IPAddrDecode(t *testing.T) {
	r := IPAddrPrefixDefault{}
	b := make([]byte, 16)
	r.decodePrefix(b, 33, 4)
}

func Test_RouteTargetMembershipNLRIString(t *testing.T) {
	assert := assert.New(t)

	// TwoOctetAsSpecificExtended
	buf := make([]byte, 13)
	buf[0] = 96 // in bit length
	binary.BigEndian.PutUint32(buf[1:5], 65546)
	buf[5] = byte(EC_TYPE_TRANSITIVE_TWO_OCTET_AS_SPECIFIC) // typehigh
	binary.BigEndian.PutUint16(buf[7:9], 65000)
	binary.BigEndian.PutUint32(buf[9:], 65546)
	r := &RouteTargetMembershipNLRI{}
	err := r.DecodeFromBytes(buf)
	assert.Equal(nil, err)
	assert.Equal("65546:65000:65546", r.String())
	buf, err = r.Serialize()
	assert.Equal(nil, err)
	err = r.DecodeFromBytes(buf)
	assert.Equal(nil, err)
	assert.Equal("65546:65000:65546", r.String())

	// IPv4AddressSpecificExtended
	buf = make([]byte, 13)
	buf[0] = 96 // in bit length
	binary.BigEndian.PutUint32(buf[1:5], 65546)
	buf[5] = byte(EC_TYPE_TRANSITIVE_IP4_SPECIFIC) // typehigh
	ip := net.ParseIP("10.0.0.1").To4()
	copy(buf[7:11], []byte(ip))
	binary.BigEndian.PutUint16(buf[11:], 65000)
	r = &RouteTargetMembershipNLRI{}
	err = r.DecodeFromBytes(buf)
	assert.Equal(nil, err)
	assert.Equal("65546:10.0.0.1:65000", r.String())
	buf, err = r.Serialize()
	assert.Equal(nil, err)
	err = r.DecodeFromBytes(buf)
	assert.Equal(nil, err)
	assert.Equal("65546:10.0.0.1:65000", r.String())

	// FourOctetAsSpecificExtended
	buf = make([]byte, 13)
	buf[0] = 96 // in bit length
	binary.BigEndian.PutUint32(buf[1:5], 65546)
	buf[5] = byte(EC_TYPE_TRANSITIVE_FOUR_OCTET_AS_SPECIFIC) // typehigh
	buf[6] = byte(EC_SUBTYPE_ROUTE_TARGET)                   // subtype
	binary.BigEndian.PutUint32(buf[7:], 65546)
	binary.BigEndian.PutUint16(buf[11:], 65000)
	r = &RouteTargetMembershipNLRI{}
	err = r.DecodeFromBytes(buf)
	assert.Equal(nil, err)
	assert.Equal("65546:1.10:65000", r.String())
	buf, err = r.Serialize()
	assert.Equal(nil, err)
	err = r.DecodeFromBytes(buf)
	assert.Equal(nil, err)
	assert.Equal("65546:1.10:65000", r.String())

	// OpaqueExtended
	buf = make([]byte, 13)
	buf[0] = 96 // in bit length
	binary.BigEndian.PutUint32(buf[1:5], 65546)
	buf[5] = byte(EC_TYPE_TRANSITIVE_OPAQUE) // typehigh
	binary.BigEndian.PutUint32(buf[9:], 1000000)
	r = &RouteTargetMembershipNLRI{}
	err = r.DecodeFromBytes(buf)
	assert.Equal(nil, err)
	assert.Equal("65546:1000000", r.String())
	buf, err = r.Serialize()
	assert.Equal(nil, err)
	err = r.DecodeFromBytes(buf)
	assert.Equal(nil, err)
	assert.Equal("65546:1000000", r.String())

	// Unknown
	buf = make([]byte, 13)
	buf[0] = 96 // in bit length
	binary.BigEndian.PutUint32(buf[1:5], 65546)
	buf[5] = 0x04 // typehigh
	binary.BigEndian.PutUint32(buf[9:], 1000000)
	r = &RouteTargetMembershipNLRI{}
	err = r.DecodeFromBytes(buf)
	assert.Equal(nil, err)
	assert.Equal("65546:1000000", r.String())
	buf, err = r.Serialize()
	assert.Equal(nil, err)
	err = r.DecodeFromBytes(buf)
	assert.Equal(nil, err)
	assert.Equal("65546:1000000", r.String())

}

func Test_MalformedUpdateMsg(t *testing.T) {
	assert := assert.New(t)
	var bufin []byte
	var u *BGPUpdate
	var err error

	// Invalid AS_PATH
	bufin = []byte{
		0x00, 0x00, // Withdraws(0)
		0x00, 0x16, // Attrs Len(22)
		0x40, 0x01, 0x01, 0x00, // Attr(ORIGIN)
		0x40, 0x03, 0x04, 0xc0, // Attr(NEXT_HOP)
		0xa8, 0x01, 0x64,
		0x40, 0x02, 0x17, // Attr(AS_PATH) - invalid length
		0x02, 0x03, 0xfd, 0xe8,
		0xfd, 0xe8, 0xfd, 0xe8,
		0x08, 0x0a, // NLRI
	}

	u = &BGPUpdate{}
	err = u.DecodeFromBytes(bufin)
	assert.Error(err)
	assert.Equal(ERROR_HANDLING_TREAT_AS_WITHDRAW, err.(*MessageError).ErrorHandling)

	// Invalid AGGREGATOR
	bufin = []byte{
		0x00, 0x00, // Withdraws(0)
		0x00, 0x16, // Attrs Len(22)
		0xc0, 0x07, 0x05, // Flag, Type(7), Length(5)
		0x00, 0x00, 0x00, 0x64, // aggregator - invalid length
		0x00,
		0x40, 0x01, 0x01, 0x00, // Attr(ORIGIN)
		0x40, 0x03, 0x04, 0xc0, // Attr(NEXT_HOP)
		0xa8, 0x01, 0x64,
		0x40, 0x02, 0x00, // Attr(AS_PATH)
	}

	u = &BGPUpdate{}
	err = u.DecodeFromBytes(bufin)
	assert.Error(err)
	assert.Equal(ERROR_HANDLING_ATTRIBUTE_DISCARD, err.(*MessageError).ErrorHandling)

	// Invalid MP_REACH_NLRI
	bufin = []byte{
		0x00, 0x00, // Withdraws(0)
		0x00, 0x27, // Attrs Len(39)
		0x80, 0x0e, 0x1d, // Flag, Type(14), Length(29)
		0x00, 0x02, 0x01, // afi(2), safi(1)
		0x0f, 0x00, 0x00, 0x00, // nexthop - invalid nexthop length
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0xff,
		0xff, 0x0a, 0x00, 0x00,
		0x00,                   // SNPA(0)
		0x40, 0x20, 0x01, 0x0d, // NLRI
		0xb8, 0x00, 0x01, 0x00,
		0x00,
		0x40, 0x01, 0x01, 0x00, // Attr(ORIGIN)
		0x40, 0x02, 0x00, // Attr(AS_PATH)
	}

	err = u.DecodeFromBytes(bufin)
	assert.Error(err)
	assert.Equal(ERROR_HANDLING_AFISAFI_DISABLE, err.(*MessageError).ErrorHandling)

	// Invalid flag
	bufin = []byte{
		0x00, 0x00, // Withdraws(0)
		0x00, 0x0e, // Attrs Len(14)
		0xc0, 0x01, 0x01, 0x00, // Attr(ORIGIN) - invalid flag
		0x40, 0x03, 0x04, 0xc0, // Attr(NEXT_HOP)
		0xa8, 0x01, 0x64,
		0x40, 0x02, 0x00, // Attr(AS_PATH)
	}

	err = u.DecodeFromBytes(bufin)
	assert.Error(err)
	assert.Equal(ERROR_HANDLING_TREAT_AS_WITHDRAW, err.(*MessageError).ErrorHandling)

	// Invalid AGGREGATOR and MULTI_EXIT_DESC
	bufin = []byte{
		0x00, 0x00, // Withdraws(0)
		0x00, 0x1e, // Attrs Len(30)
		0xc0, 0x07, 0x05, 0x00, // Attr(AGGREGATOR) - invalid length
		0x00, 0x00, 0x64, 0x00,
		0x80, 0x04, 0x05, 0x00, // Attr(MULTI_EXIT_DESC)  - invalid length
		0x00, 0x00, 0x00, 0x64,
		0x40, 0x01, 0x01, 0x00, // Attr(ORIGIN)
		0x40, 0x02, 0x00, // Attr(AS_PATH)
		0x40, 0x03, 0x04, 0xc0, // Attr(NEXT_HOP)
		0xa8, 0x01, 0x64,
		0x20, 0xc8, 0xc8, 0xc8, // NLRI
		0xc8,
	}

	err = u.DecodeFromBytes(bufin)
	assert.Error(err)
	assert.Equal(ERROR_HANDLING_TREAT_AS_WITHDRAW, err.(*MessageError).ErrorHandling)
}

func Test_RFC5512(t *testing.T) {
	assert := assert.New(t)

	buf := make([]byte, 8)
	buf[0] = byte(EC_TYPE_TRANSITIVE_OPAQUE)
	buf[1] = byte(EC_SUBTYPE_COLOR)
	binary.BigEndian.PutUint32(buf[4:], 1000000)
	ec, err := ParseExtended(buf)
	assert.Equal(nil, err)
	assert.Equal("1000000", ec.String())
	buf, err = ec.Serialize()
	assert.Equal(nil, err)
	assert.Equal([]byte{0x3, 0xb, 0x0, 0x0, 0x0, 0xf, 0x42, 0x40}, buf)

	buf = make([]byte, 8)
	buf[0] = byte(EC_TYPE_TRANSITIVE_OPAQUE)
	buf[1] = byte(EC_SUBTYPE_ENCAPSULATION)
	binary.BigEndian.PutUint16(buf[6:], uint16(TUNNEL_TYPE_VXLAN))
	ec, err = ParseExtended(buf)
	assert.Equal(nil, err)
	assert.Equal("VXLAN", ec.String())
	buf, err = ec.Serialize()
	assert.Equal(nil, err)
	assert.Equal([]byte{0x3, 0xc, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8}, buf)

	tlv := NewTunnelEncapTLV(TUNNEL_TYPE_VXLAN, []TunnelEncapSubTLVInterface{NewTunnelEncapSubTLVColor(10)})
	attr := NewPathAttributeTunnelEncap([]*TunnelEncapTLV{tlv})

	buf1, err := attr.Serialize()
	assert.Equal(nil, err)

	p, err := GetPathAttribute(buf1)
	assert.Equal(nil, err)

	err = p.DecodeFromBytes(buf1)
	assert.Equal(nil, err)

	buf2, err := p.Serialize()
	assert.Equal(nil, err)
	assert.Equal(buf1, buf2)

	n1 := NewEncapNLRI("10.0.0.1")
	buf1, err = n1.Serialize()
	assert.Equal(nil, err)

	n2 := NewEncapNLRI("")
	err = n2.DecodeFromBytes(buf1)
	assert.Equal(nil, err)
	assert.Equal("10.0.0.1", n2.String())

	n3 := NewEncapv6NLRI("2001::1")
	buf1, err = n3.Serialize()
	assert.Equal(nil, err)

	n4 := NewEncapv6NLRI("")
	err = n4.DecodeFromBytes(buf1)
	assert.Equal(nil, err)
	assert.Equal("2001::1", n4.String())
}

func Test_ASLen(t *testing.T) {
	assert := assert.New(t)

	aspath := AsPathParam{
		Num: 2,
		AS:  []uint16{65000, 65001},
	}
	aspath.Type = BGP_ASPATH_ATTR_TYPE_SEQ
	assert.Equal(2, aspath.ASLen())

	aspath.Type = BGP_ASPATH_ATTR_TYPE_SET
	assert.Equal(1, aspath.ASLen())

	aspath.Type = BGP_ASPATH_ATTR_TYPE_CONFED_SEQ
	assert.Equal(0, aspath.ASLen())

	aspath.Type = BGP_ASPATH_ATTR_TYPE_CONFED_SET
	assert.Equal(0, aspath.ASLen())

	as4path := As4PathParam{
		Num: 2,
		AS:  []uint32{65000, 65001},
	}
	as4path.Type = BGP_ASPATH_ATTR_TYPE_SEQ
	assert.Equal(2, as4path.ASLen())

	as4path.Type = BGP_ASPATH_ATTR_TYPE_SET
	assert.Equal(1, as4path.ASLen())

	as4path.Type = BGP_ASPATH_ATTR_TYPE_CONFED_SEQ
	assert.Equal(0, as4path.ASLen())

	as4path.Type = BGP_ASPATH_ATTR_TYPE_CONFED_SET
	assert.Equal(0, as4path.ASLen())

}

func Test_MPLSLabelStack(t *testing.T) {
	assert := assert.New(t)
	mpls := NewMPLSLabelStack()
	buf, err := mpls.Serialize()
	assert.Nil(err)
	assert.Equal(true, bytes.Equal(buf, []byte{0, 0, 1}))

	mpls = &MPLSLabelStack{}
	assert.Nil(mpls.DecodeFromBytes(buf))
	assert.Equal(1, len(mpls.Labels))
	assert.Equal(uint32(0), mpls.Labels[0])

	mpls = NewMPLSLabelStack(WITHDRAW_LABEL)
	buf, err = mpls.Serialize()
	assert.Nil(err)
	assert.Equal(true, bytes.Equal(buf, []byte{128, 0, 0}))

	mpls = &MPLSLabelStack{}
	assert.Nil(mpls.DecodeFromBytes(buf))
	assert.Equal(1, len(mpls.Labels))
	assert.Equal(WITHDRAW_LABEL, mpls.Labels[0])
}

func Test_FlowSpecNlri(t *testing.T) {
	assert := assert.New(t)
	cmp := make([]FlowSpecComponentInterface, 0)
	cmp = append(cmp, NewFlowSpecDestinationPrefix(NewIPAddrPrefix(24, "10.0.0.0")))
	cmp = append(cmp, NewFlowSpecSourcePrefix(NewIPAddrPrefix(24, "10.0.0.0")))
	item1 := NewFlowSpecComponentItem(DEC_NUM_OP_EQ, TCP)
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_IP_PROTO, []*FlowSpecComponentItem{item1}))
	item2 := NewFlowSpecComponentItem(DEC_NUM_OP_GT_EQ, 20)
	item3 := NewFlowSpecComponentItem(DEC_NUM_OP_AND|DEC_NUM_OP_LT_EQ, 30)
	item4 := NewFlowSpecComponentItem(DEC_NUM_OP_GT_EQ, 10)
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_PORT, []*FlowSpecComponentItem{item2, item3, item4}))
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_DST_PORT, []*FlowSpecComponentItem{item2, item3, item4}))
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_SRC_PORT, []*FlowSpecComponentItem{item2, item3, item4}))
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_ICMP_TYPE, []*FlowSpecComponentItem{item2, item3, item4}))
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_ICMP_CODE, []*FlowSpecComponentItem{item2, item3, item4}))
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_PKT_LEN, []*FlowSpecComponentItem{item2, item3, item4}))
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_DSCP, []*FlowSpecComponentItem{item2, item3, item4}))
	isFragment := uint64(0x02)
	lastFragment := uint64(0x08)
	item5 := NewFlowSpecComponentItem(BITMASK_FLAG_OP_MATCH, isFragment)
	item6 := NewFlowSpecComponentItem(BITMASK_FLAG_OP_AND, lastFragment)

	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_FRAGMENT, []*FlowSpecComponentItem{item5, item6}))
	item7 := NewFlowSpecComponentItem(0, TCP_FLAG_ACK)
	item8 := NewFlowSpecComponentItem(BITMASK_FLAG_OP_AND|BITMASK_FLAG_OP_NOT, TCP_FLAG_URGENT)

	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_TCP_FLAG, []*FlowSpecComponentItem{item7, item8}))
	n1 := NewFlowSpecIPv4Unicast(cmp)

	buf1, err := n1.Serialize()
	assert.Nil(err)

	n2, err := NewPrefixFromRouteFamily(RouteFamilyToAfiSafi(RF_FS_IPv4_UC))
	assert.Nil(err)

	err = n2.DecodeFromBytes(buf1)
	assert.Nil(err)
	// should be equal
	assert.Equal(n1, n2)
}

func Test_NewFlowSpecComponentItemLength(t *testing.T) {
	item := NewFlowSpecComponentItem(0, 0)
	assert.Equal(t, 1, item.Len())
	item = NewFlowSpecComponentItem(0, math.MaxUint8)
	assert.Equal(t, 1, item.Len())

	item = NewFlowSpecComponentItem(0, math.MaxUint8+1)
	assert.Equal(t, 2, item.Len())
	item = NewFlowSpecComponentItem(0, math.MaxUint16)
	assert.Equal(t, 2, item.Len())

	item = NewFlowSpecComponentItem(0, math.MaxUint16+1)
	assert.Equal(t, 4, item.Len())
	item = NewFlowSpecComponentItem(0, math.MaxUint32)
	assert.Equal(t, 4, item.Len())

	item = NewFlowSpecComponentItem(0, math.MaxUint32+1)
	assert.Equal(t, 8, item.Len())
	item = NewFlowSpecComponentItem(0, math.MaxUint64)
	assert.Equal(t, 8, item.Len())
}

func Test_LinkBandwidthExtended(t *testing.T) {
	assert := assert.New(t)
	exts := make([]ExtendedCommunityInterface, 0)
	exts = append(exts, NewLinkBandwidthExtended(65001, 125000.0))
	m1 := NewPathAttributeExtendedCommunities(exts)
	buf1, err := m1.Serialize()
	require.NoError(t, err)

	m2 := NewPathAttributeExtendedCommunities(nil)
	err = m2.DecodeFromBytes(buf1)
	require.NoError(t, err)

	_, err = m2.Serialize()
	require.NoError(t, err)

	assert.Equal(m1, m2)
}

func Test_FlowSpecExtended(t *testing.T) {
	assert := assert.New(t)
	exts := make([]ExtendedCommunityInterface, 0)
	exts = append(exts, NewTrafficRateExtended(100, 9600.0))
	exts = append(exts, NewTrafficActionExtended(true, false))
	exts = append(exts, NewRedirectTwoOctetAsSpecificExtended(1000, 1000))
	exts = append(exts, NewRedirectIPv4AddressSpecificExtended("10.0.0.1", 1000))
	exts = append(exts, NewRedirectFourOctetAsSpecificExtended(10000000, 1000))
	exts = append(exts, NewTrafficRemarkExtended(10))
	m1 := NewPathAttributeExtendedCommunities(exts)
	buf1, err := m1.Serialize()
	require.NoError(t, err)

	m2 := NewPathAttributeExtendedCommunities(nil)
	err = m2.DecodeFromBytes(buf1)
	require.NoError(t, err)

	_, err = m2.Serialize()
	require.NoError(t, err)

	assert.Equal(m1, m2)
}

func Test_IP6FlowSpecExtended(t *testing.T) {
	exts := make([]ExtendedCommunityInterface, 0)
	exts = append(exts, NewRedirectIPv6AddressSpecificExtended("2001:db8::68", 1000))
	m1 := NewPathAttributeIP6ExtendedCommunities(exts)
	buf1, err := m1.Serialize()
	require.NoError(t, err)

	m2 := NewPathAttributeIP6ExtendedCommunities(nil)
	err = m2.DecodeFromBytes(buf1)
	require.NoError(t, err)

	_, err = m2.Serialize()
	require.NoError(t, err)

	assert.Equal(t, m1, m2)
}

func Test_FlowSpecNlriv6(t *testing.T) {
	cmp := make([]FlowSpecComponentInterface, 0)
	cmp = append(cmp, NewFlowSpecDestinationPrefix6(NewIPv6AddrPrefix(64, "2001::"), 12))
	cmp = append(cmp, NewFlowSpecSourcePrefix6(NewIPv6AddrPrefix(64, "2001::"), 12))
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
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_PKT_LEN, []*FlowSpecComponentItem{item2, item3, item4}))
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_DSCP, []*FlowSpecComponentItem{item2, item3, item4}))
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_LABEL, []*FlowSpecComponentItem{item2, item3, item4}))
	isFragment := uint64(0x02)
	item5 := NewFlowSpecComponentItem(BITMASK_FLAG_OP_MATCH, isFragment)
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_FRAGMENT, []*FlowSpecComponentItem{item5}))
	item6 := NewFlowSpecComponentItem(0, TCP_FLAG_ACK)
	item7 := NewFlowSpecComponentItem(BITMASK_FLAG_OP_AND|BITMASK_FLAG_OP_NOT, TCP_FLAG_URGENT)
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_TCP_FLAG, []*FlowSpecComponentItem{item6, item7}))
	n1 := NewFlowSpecIPv6Unicast(cmp)
	buf1, err := n1.Serialize()
	require.NoError(t, err)

	n2, err := NewPrefixFromRouteFamily(RouteFamilyToAfiSafi(RF_FS_IPv6_UC))
	require.NoError(t, err)

	err = n2.DecodeFromBytes(buf1)
	require.NoError(t, err)

	_, err = n2.Serialize()
	require.NoError(t, err)

	assert.Equal(t, n1, n2)
}

func Test_Aigp(t *testing.T) {
	assert := assert.New(t)
	m := NewAigpTLVIgpMetric(1000)
	a1 := NewPathAttributeAigp([]AigpTLVInterface{m})
	buf1, err := a1.Serialize()
	require.NoError(t, err)

	a2 := NewPathAttributeAigp(nil)
	err = a2.DecodeFromBytes(buf1)
	require.NoError(t, err)

	assert.Equal(a1, a2)
}

func Test_FlowSpecNlriL2(t *testing.T) {
	assert := assert.New(t)
	mac, _ := net.ParseMAC("01:23:45:67:89:ab")
	cmp := make([]FlowSpecComponentInterface, 0)
	cmp = append(cmp, NewFlowSpecDestinationMac(mac))
	cmp = append(cmp, NewFlowSpecSourceMac(mac))
	item1 := NewFlowSpecComponentItem(DEC_NUM_OP_EQ, uint64(IPv4))
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_ETHERNET_TYPE, []*FlowSpecComponentItem{item1}))
	rd, _ := ParseRouteDistinguisher("100:100")
	n1 := NewFlowSpecL2VPN(rd, cmp)
	buf1, err := n1.Serialize()
	assert.Nil(err)
	n2, err := NewPrefixFromRouteFamily(RouteFamilyToAfiSafi(RF_FS_L2_VPN))
	assert.Nil(err)
	err = n2.DecodeFromBytes(buf1)
	assert.Nil(err)

	assert.Equal(n1, n2)
}

func Test_NotificationErrorCode(t *testing.T) {
	// boundary check
	t.Log(NewNotificationErrorCode(BGP_ERROR_MESSAGE_HEADER_ERROR, BGP_ERROR_SUB_BAD_MESSAGE_TYPE).String())
	t.Log(NewNotificationErrorCode(BGP_ERROR_MESSAGE_HEADER_ERROR, BGP_ERROR_SUB_BAD_MESSAGE_TYPE+1).String())
	t.Log(NewNotificationErrorCode(BGP_ERROR_MESSAGE_HEADER_ERROR, 0).String())
	t.Log(NewNotificationErrorCode(0, BGP_ERROR_SUB_BAD_MESSAGE_TYPE).String())
	t.Log(NewNotificationErrorCode(BGP_ERROR_ROUTE_REFRESH_MESSAGE_ERROR+1, 0).String())
}

func Test_FlowSpecNlriVPN(t *testing.T) {
	assert := assert.New(t)
	cmp := make([]FlowSpecComponentInterface, 0)
	cmp = append(cmp, NewFlowSpecDestinationPrefix(NewIPAddrPrefix(24, "10.0.0.0")))
	cmp = append(cmp, NewFlowSpecSourcePrefix(NewIPAddrPrefix(24, "10.0.0.0")))
	rd, _ := ParseRouteDistinguisher("100:100")
	n1 := NewFlowSpecIPv4VPN(rd, cmp)
	buf1, err := n1.Serialize()
	assert.Nil(err)
	n2, err := NewPrefixFromRouteFamily(RouteFamilyToAfiSafi(RF_FS_IPv4_VPN))
	assert.Nil(err)
	err = n2.DecodeFromBytes(buf1)
	require.NoError(t, err)

	assert.Equal(n1, n2)
}

func Test_EVPNIPPrefixRoute(t *testing.T) {
	assert := assert.New(t)
	rd, _ := ParseRouteDistinguisher("100:100")
	r := &EVPNIPPrefixRoute{
		RD: rd,
		ESI: EthernetSegmentIdentifier{
			Type:  ESI_ARBITRARY,
			Value: make([]byte, 9),
		},
		ETag:           10,
		IPPrefixLength: 24,
		IPPrefix:       net.IP{10, 10, 10, 0},
		GWIPAddress:    net.IP{10, 10, 10, 10},
		Label:          1000,
	}
	n1 := NewEVPNNLRI(EVPN_IP_PREFIX, r)
	buf1, err := n1.Serialize()
	assert.Nil(err)
	n2, err := NewPrefixFromRouteFamily(RouteFamilyToAfiSafi(RF_EVPN))
	assert.Nil(err)
	err = n2.DecodeFromBytes(buf1)
	assert.Nil(err)

	assert.Equal(n1, n2)
}

func Test_CapExtendedNexthop(t *testing.T) {
	assert := assert.New(t)
	tuple := NewCapExtendedNexthopTuple(RF_IPv4_UC, AFI_IP6)
	n1 := NewCapExtendedNexthop([]*CapExtendedNexthopTuple{tuple})
	buf1, err := n1.Serialize()
	assert.Nil(err)
	n2, err := DecodeCapability(buf1)
	assert.Nil(err)

	assert.Equal(n1, n2)
}

func Test_AddPath(t *testing.T) {
	assert := assert.New(t)
	opt := &MarshallingOption{AddPath: map[RouteFamily]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH}}
	{
		n1 := NewIPAddrPrefix(24, "10.10.10.0")
		assert.Equal(n1.PathIdentifier(), uint32(0))
		n1.SetPathLocalIdentifier(10)
		assert.Equal(n1.PathLocalIdentifier(), uint32(10))
		bits, err := n1.Serialize(opt)
		assert.Nil(err)
		n2 := &IPAddrPrefix{}
		err = n2.DecodeFromBytes(bits, opt)
		assert.Nil(err)
		assert.Equal(n2.PathIdentifier(), uint32(10))
	}
	{
		n1 := NewIPv6AddrPrefix(64, "2001::")
		n1.SetPathIdentifier(10)
		bits, err := n1.Serialize(opt)
		assert.Nil(err)
		n2 := NewIPv6AddrPrefix(0, "")
		err = n2.DecodeFromBytes(bits, opt)
		assert.Nil(err)
		assert.Equal(n2.PathIdentifier(), uint32(0))
	}
	opt = &MarshallingOption{AddPath: map[RouteFamily]BGPAddPathMode{RF_IPv4_UC: BGP_ADD_PATH_BOTH, RF_IPv6_UC: BGP_ADD_PATH_BOTH}}
	{
		n1 := NewIPv6AddrPrefix(64, "2001::")
		n1.SetPathLocalIdentifier(10)
		bits, err := n1.Serialize(opt)
		assert.Nil(err)
		n2 := NewIPv6AddrPrefix(0, "")
		err = n2.DecodeFromBytes(bits, opt)
		assert.Nil(err)
		assert.Equal(n2.PathIdentifier(), uint32(10))
	}
	opt = &MarshallingOption{AddPath: map[RouteFamily]BGPAddPathMode{RF_IPv4_VPN: BGP_ADD_PATH_BOTH, RF_IPv6_VPN: BGP_ADD_PATH_BOTH}}
	{
		rd, _ := ParseRouteDistinguisher("100:100")
		labels := NewMPLSLabelStack(100, 200)
		n1 := NewLabeledVPNIPAddrPrefix(24, "10.10.10.0", *labels, rd)
		n1.SetPathLocalIdentifier(20)
		bits, err := n1.Serialize(opt)
		assert.Nil(err)
		n2 := NewLabeledVPNIPAddrPrefix(0, "", MPLSLabelStack{}, nil)
		err = n2.DecodeFromBytes(bits, opt)
		assert.Nil(err)
		assert.Equal(n2.PathIdentifier(), uint32(20))
	}
	{
		rd, _ := ParseRouteDistinguisher("100:100")
		labels := NewMPLSLabelStack(100, 200)
		n1 := NewLabeledVPNIPv6AddrPrefix(64, "2001::", *labels, rd)
		n1.SetPathLocalIdentifier(20)
		bits, err := n1.Serialize(opt)
		assert.Nil(err)
		n2 := NewLabeledVPNIPv6AddrPrefix(0, "", MPLSLabelStack{}, nil)
		err = n2.DecodeFromBytes(bits, opt)
		assert.Nil(err)
		assert.Equal(n2.PathIdentifier(), uint32(20))
	}
	opt = &MarshallingOption{AddPath: map[RouteFamily]BGPAddPathMode{RF_IPv4_MPLS: BGP_ADD_PATH_BOTH, RF_IPv6_MPLS: BGP_ADD_PATH_BOTH}}
	{
		labels := NewMPLSLabelStack(100, 200)
		n1 := NewLabeledIPAddrPrefix(24, "10.10.10.0", *labels)
		n1.SetPathLocalIdentifier(20)
		bits, err := n1.Serialize(opt)
		assert.Nil(err)
		n2 := NewLabeledIPAddrPrefix(0, "", MPLSLabelStack{})
		err = n2.DecodeFromBytes(bits, opt)
		assert.Nil(err)
		assert.Equal(n2.PathIdentifier(), uint32(20))
	}
	{
		labels := NewMPLSLabelStack(100, 200)
		n1 := NewLabeledIPv6AddrPrefix(64, "2001::", *labels)
		n1.SetPathLocalIdentifier(20)
		bits, err := n1.Serialize(opt)
		assert.Nil(err)
		n2 := NewLabeledIPv6AddrPrefix(0, "", MPLSLabelStack{})
		err = n2.DecodeFromBytes(bits, opt)
		assert.Nil(err)
		assert.Equal(n2.PathIdentifier(), uint32(20))
	}
	opt = &MarshallingOption{AddPath: map[RouteFamily]BGPAddPathMode{RF_RTC_UC: BGP_ADD_PATH_BOTH}}
	{
		rt, _ := ParseRouteTarget("100:100")
		n1 := NewRouteTargetMembershipNLRI(65000, rt)
		n1.SetPathLocalIdentifier(30)
		bits, err := n1.Serialize(opt)
		assert.Nil(err)
		n2 := NewRouteTargetMembershipNLRI(0, nil)
		err = n2.DecodeFromBytes(bits, opt)
		assert.Nil(err)
		assert.Equal(n2.PathIdentifier(), uint32(30))
	}
	opt = &MarshallingOption{AddPath: map[RouteFamily]BGPAddPathMode{RF_EVPN: BGP_ADD_PATH_BOTH}}
	{
		n1 := NewEVPNNLRI(EVPN_ROUTE_TYPE_ETHERNET_AUTO_DISCOVERY,
			&EVPNEthernetAutoDiscoveryRoute{NewRouteDistinguisherFourOctetAS(5, 6),
				EthernetSegmentIdentifier{ESI_ARBITRARY, make([]byte, 9)}, 2, 2})
		n1.SetPathLocalIdentifier(40)
		bits, err := n1.Serialize(opt)
		assert.Nil(err)
		n2 := NewEVPNNLRI(0, nil)
		err = n2.DecodeFromBytes(bits, opt)
		assert.Nil(err)
		assert.Equal(n2.PathIdentifier(), uint32(40))
	}
	opt = &MarshallingOption{AddPath: map[RouteFamily]BGPAddPathMode{RF_IPv4_ENCAP: BGP_ADD_PATH_BOTH}}
	{
		n1 := NewEncapNLRI("10.10.10.0")
		n1.SetPathLocalIdentifier(50)
		bits, err := n1.Serialize(opt)
		assert.Nil(err)
		n2 := NewEncapNLRI("")
		err = n2.DecodeFromBytes(bits, opt)
		assert.Nil(err)
		assert.Equal(n2.PathIdentifier(), uint32(50))
	}
	opt = &MarshallingOption{AddPath: map[RouteFamily]BGPAddPathMode{RF_FS_IPv4_UC: BGP_ADD_PATH_BOTH}}
	{
		n1 := NewFlowSpecIPv4Unicast([]FlowSpecComponentInterface{NewFlowSpecDestinationPrefix(NewIPAddrPrefix(24, "10.0.0.0"))})
		n1.SetPathLocalIdentifier(60)
		bits, err := n1.Serialize(opt)
		assert.Nil(err)
		n2 := NewFlowSpecIPv4Unicast(nil)
		err = n2.DecodeFromBytes(bits, opt)
		assert.Nil(err)
		assert.Equal(n2.PathIdentifier(), uint32(60))
	}
	opt = &MarshallingOption{AddPath: map[RouteFamily]BGPAddPathMode{RF_OPAQUE: BGP_ADD_PATH_BOTH}}
	{
		n1 := NewOpaqueNLRI([]byte("key"), []byte("value"))
		n1.SetPathLocalIdentifier(70)
		bits, err := n1.Serialize(opt)
		assert.Nil(err)
		n2 := &OpaqueNLRI{}
		err = n2.DecodeFromBytes(bits, opt)
		assert.Nil(err)
		assert.Equal(n2.PathIdentifier(), uint32(70))
	}

}

func Test_CompareFlowSpecNLRI(t *testing.T) {
	assert := assert.New(t)
	cmp, err := ParseFlowSpecComponents(RF_FS_IPv4_UC, "destination 10.0.0.2/32 source 10.0.0.1/32 destination-port ==3128 protocol tcp")
	assert.Nil(err)
	// Note: Use NewFlowSpecIPv4Unicast() for the consistent ordered rules.
	n1 := &NewFlowSpecIPv4Unicast(cmp).FlowSpecNLRI
	cmp, err = ParseFlowSpecComponents(RF_FS_IPv4_UC, "source 10.0.0.0/24 destination-port ==3128 protocol tcp")
	assert.Nil(err)
	n2 := &NewFlowSpecIPv4Unicast(cmp).FlowSpecNLRI
	r, err := CompareFlowSpecNLRI(n1, n2)
	assert.Nil(err)
	assert.True(r > 0)
	cmp, err = ParseFlowSpecComponents(RF_FS_IPv4_UC, "source 10.0.0.9/32 port ==80 ==8080 destination-port >8080&<8080 ==3128 source-port >1024 protocol ==udp ==tcp")
	n3 := &NewFlowSpecIPv4Unicast(cmp).FlowSpecNLRI
	assert.Nil(err)
	cmp, err = ParseFlowSpecComponents(RF_FS_IPv4_UC, "destination 192.168.0.2/32")
	n4 := &NewFlowSpecIPv4Unicast(cmp).FlowSpecNLRI
	assert.Nil(err)
	r, err = CompareFlowSpecNLRI(n3, n4)
	assert.Nil(err)
	assert.True(r < 0)
}

func Test_MpReachNLRIWithIPv4MappedIPv6Prefix(t *testing.T) {
	assert := assert.New(t)
	n1 := NewIPv6AddrPrefix(120, "::ffff:10.0.0.0")
	buf1, err := n1.Serialize()
	assert.Nil(err)
	n2, err := NewPrefixFromRouteFamily(RouteFamilyToAfiSafi(RF_IPv6_UC))
	assert.Nil(err)
	err = n2.DecodeFromBytes(buf1)
	assert.Nil(err)

	assert.Equal(n1, n2)

	label := NewMPLSLabelStack(2)

	n3 := NewLabeledIPv6AddrPrefix(120, "::ffff:10.0.0.0", *label)
	buf1, err = n3.Serialize()
	assert.Nil(err)
	n4, err := NewPrefixFromRouteFamily(RouteFamilyToAfiSafi(RF_IPv6_MPLS))
	assert.Nil(err)
	err = n4.DecodeFromBytes(buf1)
	assert.Nil(err)

	assert.Equal(n3, n4)
}

func Test_MpReachNLRIWithIPv6PrefixWithIPv4Peering(t *testing.T) {
	assert := assert.New(t)
	bufin := []byte{
		0x80, 0x0e, 0x1e, // flags(1), type(1), length(1)
		0x00, 0x02, 0x01, 0x10, // afi(2), safi(1), nexthoplen(1)
		0x00, 0x00, 0x00, 0x00, // nexthop(16)
		0x00, 0x00, 0x00, 0x00, // = "::ffff:172.20.0.1"
		0x00, 0x00, 0xff, 0xff,
		0xac, 0x14, 0x00, 0x01,
		0x00,                   // reserved(1)
		0x40, 0x20, 0x01, 0x0d, // nlri(9)
		0xb8, 0x00, 0x01, 0x00, // = "2001:db8:1:1::/64"
		0x01,
	}
	// Test DecodeFromBytes()
	p := &PathAttributeMpReachNLRI{}
	err := p.DecodeFromBytes(bufin)
	assert.Nil(err)
	// Test decoded values
	assert.Equal(BGPAttrFlag(0x80), p.Flags)
	assert.Equal(BGPAttrType(0xe), p.Type)
	assert.Equal(uint16(0x1e), p.Length)
	assert.Equal(uint16(AFI_IP6), p.AFI)
	assert.Equal(uint8(SAFI_UNICAST), p.SAFI)
	assert.Equal(net.ParseIP("::ffff:172.20.0.1"), p.Nexthop)
	assert.Equal(net.ParseIP(""), p.LinkLocalNexthop)
	value := []AddrPrefixInterface{
		NewIPv6AddrPrefix(64, "2001:db8:1:1::"),
	}
	assert.Equal(value, p.Value)
	// Set NextHop as IPv4 address (because IPv4 peering)
	p.Nexthop = net.ParseIP("172.20.0.1")
	// Test Serialize()
	bufout, err := p.Serialize()
	assert.Nil(err)
	// Test serialised value
	assert.Equal(bufin, bufout)
}

func Test_MpReachNLRIWithIPv6(t *testing.T) {
	assert := assert.New(t)
	bufin := []byte{
		0x90, 0x0e, 0x00, 0x1e, // flags(1), type(1), length(2),
		0x00, 0x02, 0x01, 0x10, // afi(2), safi(1), nexthoplen(1)
		0x20, 0x01, 0x0d, 0xb8, // nexthop(16)
		0x00, 0x01, 0x00, 0x00, // = "2001:db8:1::1"
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		0x00,                   // reserved(1)
		0x40, 0x20, 0x01, 0x0d, // nlri(9)
		0xb8, 0x00, 0x53, 0x00, // = "2001:db8:53::/64"
		0x00,
	}
	// Test DecodeFromBytes()
	p := &PathAttributeMpReachNLRI{}
	err := p.DecodeFromBytes(bufin)
	assert.Nil(err)
	// Test decoded values
	assert.Equal(BGPAttrFlag(0x90), p.Flags)
	assert.Equal(BGPAttrType(0xe), p.Type)
	assert.Equal(uint16(0x1e), p.Length)
	assert.Equal(uint16(AFI_IP6), p.AFI)
	assert.Equal(uint8(SAFI_UNICAST), p.SAFI)
	assert.Equal(net.ParseIP("2001:db8:1::1"), p.Nexthop)
	value := []AddrPrefixInterface{
		NewIPv6AddrPrefix(64, "2001:db8:53::"),
	}
	assert.Equal(value, p.Value)
}

func Test_MpUnreachNLRIWithIPv6(t *testing.T) {
	assert := assert.New(t)
	bufin := []byte{
		0x90, 0x0f, 0x00, 0x0c, // flags(1), type(1), length(2),
		0x00, 0x02, 0x01, // afi(2), safi(1),
		0x40, 0x20, 0x01, 0x0d, // nlri(9)
		0xb8, 0x00, 0x53, 0x00, // = "2001:db8:53::/64"
		0x00,
	}
	// Test DecodeFromBytes()
	p := &PathAttributeMpUnreachNLRI{}
	err := p.DecodeFromBytes(bufin)
	assert.Nil(err)
	// Test decoded values
	assert.Equal(BGPAttrFlag(0x90), p.Flags)
	assert.Equal(BGPAttrType(0xf), p.Type)
	assert.Equal(uint16(0x0c), p.Length)
	assert.Equal(uint16(AFI_IP6), p.AFI)
	assert.Equal(uint8(SAFI_UNICAST), p.SAFI)
	value := []AddrPrefixInterface{
		NewIPv6AddrPrefix(64, "2001:db8:53::"),
	}
	assert.Equal(value, p.Value)
}

func Test_MpReachNLRIWithIPv6PrefixWithLinkLocalNexthop(t *testing.T) {
	assert := assert.New(t)
	bufin := []byte{
		0x80, 0x0e, 0x2c, // flags(1), type(1), length(1)
		0x00, 0x02, 0x01, 0x20, // afi(2), safi(1), nexthoplen(1)
		0x20, 0x01, 0x0d, 0xb8, // nexthop(32)
		0x00, 0x01, 0x00, 0x00, // = "2001:db8:1::1"
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		0xfe, 0x80, 0x00, 0x00, // + "fe80::1" (link local)
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		0x00,                   // reserved(1)
		0x30, 0x20, 0x10, 0x0a, // nlri(7)
		0xb8, 0x00, 0x01, // = "2010:ab8:1::/48"
	}
	// Test DecodeFromBytes()
	p := &PathAttributeMpReachNLRI{}
	err := p.DecodeFromBytes(bufin)
	assert.Nil(err)
	// Test decoded values
	assert.Equal(BGPAttrFlag(0x80), p.Flags)
	assert.Equal(BGPAttrType(0xe), p.Type)
	assert.Equal(uint16(0x2c), p.Length)
	assert.Equal(uint16(AFI_IP6), p.AFI)
	assert.Equal(uint8(SAFI_UNICAST), p.SAFI)
	assert.Equal(net.ParseIP("2001:db8:1::1"), p.Nexthop)
	assert.Equal(net.ParseIP("fe80::1"), p.LinkLocalNexthop)
	value := []AddrPrefixInterface{
		NewIPv6AddrPrefix(48, "2010:ab8:1::"),
	}
	assert.Equal(value, p.Value)
	// Test Serialize()
	bufout, err := p.Serialize()
	assert.Nil(err)
	// Test serialised value
	assert.Equal(bufin, bufout)
}

func Test_MpReachNLRIWithVPNv4Prefix(t *testing.T) {
	assert := assert.New(t)
	bufin := []byte{
		0x80, 0x0e, 0x20, // flags(1), type(1), length(1)
		0x00, 0x01, 0x80, 0x0c, // afi(2), safi(1), nexthoplen(1)
		0x00, 0x00, 0x00, 0x00, // nexthop(12)
		0x00, 0x00, 0x00, 0x00, // = (rd:"0:0",) "172.20.0.1"
		0xac, 0x14, 0x00, 0x01,
		0x00,                   // reserved(1)
		0x70, 0x00, 0x01, 0x01, // nlri(15)
		0x00, 0x00, 0xfd, 0xe8, // = label:16, rd:"65000:100", prefix:"10.1.1.0/24"
		0x00, 0x00, 0x00, 0x64,
		0x0a, 0x01, 0x01,
	}
	// Test DecodeFromBytes()
	p := &PathAttributeMpReachNLRI{}
	err := p.DecodeFromBytes(bufin)
	assert.Nil(err)
	// Test decoded values
	assert.Equal(BGPAttrFlag(0x80), p.Flags)
	assert.Equal(BGPAttrType(0xe), p.Type)
	assert.Equal(uint16(0x20), p.Length)
	assert.Equal(uint16(AFI_IP), p.AFI)
	assert.Equal(uint8(SAFI_MPLS_VPN), p.SAFI)
	assert.Equal(net.ParseIP("172.20.0.1").To4(), p.Nexthop)
	assert.Equal(net.ParseIP(""), p.LinkLocalNexthop)
	value := []AddrPrefixInterface{
		NewLabeledVPNIPAddrPrefix(24, "10.1.1.0", *NewMPLSLabelStack(16),
			NewRouteDistinguisherTwoOctetAS(65000, 100)),
	}
	assert.Equal(value, p.Value)
	// Test Serialize()
	bufout, err := p.Serialize()
	assert.Nil(err)
	// Test serialised value
	assert.Equal(bufin, bufout)
}

func Test_MpReachNLRIWithVPNv6Prefix(t *testing.T) {
	assert := assert.New(t)
	bufin := []byte{
		0x80, 0x0e, 0x39, // flags(1), type(1), length(1)
		0x00, 0x02, 0x80, 0x18, // afi(2), safi(1), nexthoplen(1)
		0x00, 0x00, 0x00, 0x00, // nexthop(24)
		0x00, 0x00, 0x00, 0x00, // = (rd:"0:0",) "2001:db8:1::1"
		0x20, 0x01, 0x0d, 0xb8,
		0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		0x00,                   // reserved(1)
		0xd4, 0x00, 0x01, 0x01, // nlri(28)
		0x00, 0x00, 0xfd, 0xe8, // = label:16, rd:"65000:100", prefix:"2001:1::/124"
		0x00, 0x00, 0x00, 0x64,
		0x20, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	// Test DecodeFromBytes()
	p := &PathAttributeMpReachNLRI{}
	err := p.DecodeFromBytes(bufin)
	assert.Nil(err)
	// Test decoded values
	assert.Equal(BGPAttrFlag(0x80), p.Flags)
	assert.Equal(BGPAttrType(0xe), p.Type)
	assert.Equal(uint16(0x39), p.Length)
	assert.Equal(uint16(AFI_IP6), p.AFI)
	assert.Equal(uint8(SAFI_MPLS_VPN), p.SAFI)
	assert.Equal(net.ParseIP("2001:db8:1::1"), p.Nexthop)
	assert.Equal(net.ParseIP(""), p.LinkLocalNexthop)
	value := []AddrPrefixInterface{
		NewLabeledVPNIPv6AddrPrefix(124, "2001:1::", *NewMPLSLabelStack(16),
			NewRouteDistinguisherTwoOctetAS(65000, 100)),
	}
	assert.Equal(value, p.Value)
	// Test Serialize()
	bufout, err := p.Serialize()
	assert.Nil(err)
	// Test serialised value
	assert.Equal(bufin, bufout)
}

func Test_MpReachNLRIWithIPv4PrefixWithIPv6Nexthop(t *testing.T) {
	assert := assert.New(t)
	bufin := []byte{
		0x80, 0x0e, 0x19, // flags(1), type(1), length(1)
		0x00, 0x01, 0x01, 0x10, // afi(1), safi(1), nexthoplen(1)
		0x20, 0x01, 0x0d, 0xb8, // nexthop(32)
		0x00, 0x01, 0x00, 0x00, // = "2001:db8:1::1"
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		0x00,                   // reserved(1)
		0x18, 0xc0, 0xa8, 0x0a, // nlri(7)
	}
	// Test DecodeFromBytes()
	p := &PathAttributeMpReachNLRI{}
	err := p.DecodeFromBytes(bufin)
	assert.Nil(err)
	// Test decoded values
	assert.Equal(BGPAttrFlag(0x80), p.Flags)
	assert.Equal(BGPAttrType(0xe), p.Type)
	assert.Equal(uint16(0x19), p.Length)
	assert.Equal(uint16(AFI_IP), p.AFI)
	assert.Equal(uint8(SAFI_UNICAST), p.SAFI)
	assert.Equal(net.ParseIP("2001:db8:1::1"), p.Nexthop)
	value := []AddrPrefixInterface{
		NewIPAddrPrefix(24, "192.168.10.0"),
	}
	assert.Equal(value, p.Value)
	// Test Serialize()
	bufout, err := p.Serialize()
	assert.Nil(err)
	// Test serialised value
	assert.Equal(bufin, bufout)
}

func Test_MpReachNLRIWithImplicitPrefix(t *testing.T) {
	assert := assert.New(t)
	bufin := []byte{
		0x80, 0x0e, 0x11, // flags(1), type(1), length(1)
		0x10,                   // nexthoplen(1)
		0x20, 0x01, 0x0d, 0xb8, // nexthop(32)
		0x00, 0x01, 0x00, 0x00, // = "2001:db8:1::1"
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
	}
	prefix := NewIPAddrPrefix(24, "192.168.10.0")
	// Test DecodeFromBytes()
	p := &PathAttributeMpReachNLRI{}
	option := &MarshallingOption{ImplicitPrefix: prefix}
	err := p.DecodeFromBytes(bufin, option)
	assert.Nil(err)
	// Test decoded values
	assert.Equal(BGPAttrFlag(0x80), p.Flags)
	assert.Equal(BGPAttrType(0xe), p.Type)
	assert.Equal(uint16(0x11), p.Length)
	assert.Equal(prefix.AFI(), p.AFI)
	assert.Equal(prefix.SAFI(), p.SAFI)
	assert.Equal(net.ParseIP("2001:db8:1::1"), p.Nexthop)
	value := []AddrPrefixInterface{prefix}
	assert.Equal(value, p.Value)
	// Test Serialize()
	bufout, err := p.Serialize(option)
	assert.Nil(err)
	// Test serialised value
	assert.Equal(bufin, bufout)
}

func Test_ParseRouteDistinguisher(t *testing.T) {
	assert := assert.New(t)

	rd, _ := ParseRouteDistinguisher("100:1000")
	rdType0, ok := rd.(*RouteDistinguisherTwoOctetAS)
	if !ok {
		t.Fatal("Type of RD interface is not RouteDistinguisherTwoOctetAS")
	}

	assert.Equal(uint16(100), rdType0.Admin)
	assert.Equal(uint32(1000), rdType0.Assigned)

	rd, _ = ParseRouteDistinguisher("10.0.0.0:100")
	rdType1, ok := rd.(*RouteDistinguisherIPAddressAS)
	if !ok {
		t.Fatal("Type of RD interface is not RouteDistinguisherIPAddressAS")
	}

	assert.Equal("10.0.0.0", rdType1.Admin.String())
	assert.Equal(uint16(100), rdType1.Assigned)

	rd, _ = ParseRouteDistinguisher("100.1000:10000")
	rdType2, ok := rd.(*RouteDistinguisherFourOctetAS)
	if !ok {
		t.Fatal("Type of RD interface is not RouteDistinguisherFourOctetAS")
	}

	assert.Equal(uint32((100<<16)|1000), rdType2.Admin)
	assert.Equal(uint16(10000), rdType2.Assigned)
}

func TestParseVPNPrefix(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		valid    bool
		rd       RouteDistinguisherInterface
		ipPrefix string
	}{
		{
			name:     "test valid RD type 0 VPNv4 prefix",
			prefix:   "100:100:10.0.0.1/32",
			valid:    true,
			rd:       NewRouteDistinguisherTwoOctetAS(uint16(100), uint32(100)),
			ipPrefix: "10.0.0.1/32",
		},
		{
			name:     "test valid RD type 1 VPNv4 prefix",
			prefix:   "1.1.1.1:100:10.0.0.1/32",
			valid:    true,
			rd:       NewRouteDistinguisherIPAddressAS("1.1.1.1", uint16(100)),
			ipPrefix: "10.0.0.1/32",
		},
		{
			name:     "test valid RD type 2 VPNv4 prefix",
			prefix:   "0.54233:100:10.0.0.1/32",
			valid:    true,
			rd:       NewRouteDistinguisherFourOctetAS(uint32(54233), uint16(100)),
			ipPrefix: "10.0.0.1/32",
		},
		{
			name:     "test invalid VPNv4 prefix",
			prefix:   "100:10.0.0.1/32",
			valid:    false,
			rd:       nil,
			ipPrefix: "",
		},
		{
			name:     "test valid RD type 0 VPNv6 prefix",
			prefix:   "100:100:100:1::/64",
			valid:    true,
			rd:       NewRouteDistinguisherTwoOctetAS(uint16(100), uint32(100)),
			ipPrefix: "100:1::/64",
		},
		{
			name:     "test valid RD type 1 VPNv6 prefix",
			prefix:   "1.1.1.1:100:100:1::/64",
			valid:    true,
			rd:       NewRouteDistinguisherIPAddressAS("1.1.1.1", uint16(100)),
			ipPrefix: "100:1::/64",
		},
		{
			name:     "test valid RD type 2 VPNv6 prefix",
			prefix:   "0.54233:100:100:1::/64",
			valid:    true,
			rd:       NewRouteDistinguisherFourOctetAS(uint32(54233), uint16(100)),
			ipPrefix: "100:1::/64",
		},
		{
			name:     "test invalid VPNv6 prefix",
			prefix:   "100:1::/64",
			valid:    false,
			rd:       nil,
			ipPrefix: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rd, _, network, err := ParseVPNPrefix(tt.prefix)
			if !tt.valid {
				assert.NotNil(t, err)
				return
			}

			assert.Nil(t, err)
			assert.Equal(t, tt.rd, rd)
			assert.Equal(t, tt.ipPrefix, network.String())
		})
	}
}

func TestContainsCIDR(t *testing.T) {
	tests := []struct {
		name    string
		prefix1 string
		prefix2 string
		result  bool
	}{
		{
			name:    "v4 prefix2 is a subnet of prefix1",
			prefix1: "172.17.0.0/16",
			prefix2: "172.17.192.0/18",
			result:  true,
		},
		{
			name:    "v4 prefix2 is a supernet of prefix1",
			prefix1: "172.17.191.0/18",
			prefix2: "172.17.0.0/16",
			result:  false,
		},
		{
			name:    "v4 prefix2 is not a subnet of prefix1",
			prefix1: "10.10.20.0/30",
			prefix2: "10.10.30.3/32",
			result:  false,
		},
		{
			name:    "v4 prefix2 is equal to prefix1",
			prefix1: "10.10.20.0/30",
			prefix2: "10.10.20.0/30",
			result:  true,
		},
		{
			name:    "v6 prefix2 is not a subnet of prefix1",
			prefix1: "1::/64",
			prefix2: "2::/72",
			result:  false,
		},
		{
			name:    "v6 prefix2 is a supernet of prefix1",
			prefix1: "1::/64",
			prefix2: "1::/32",
			result:  false,
		},
		{
			name:    "v6 prefix2 is a subnet of prefix1",
			prefix1: "1::/64",
			prefix2: "1::/112",
			result:  true,
		},
		{
			name:    "v6 prefix2 is equal to prefix1",
			prefix1: "100:100::/64",
			prefix2: "100:100::/64",
			result:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, prefixNet1, _ := net.ParseCIDR(tt.prefix1)
			_, prefixNet2, _ := net.ParseCIDR(tt.prefix2)

			result := ContainsCIDR(prefixNet1, prefixNet2)
			assert.Equal(t, tt.result, result)
		})
	}
}

func Test_ParseEthernetSegmentIdentifier(t *testing.T) {
	assert := assert.New(t)

	// "single-homed"
	esiZero := EthernetSegmentIdentifier{}
	args := make([]string, 0)
	esi, err := ParseEthernetSegmentIdentifier(args)
	assert.Nil(err)
	assert.Equal(esiZero, esi)
	args = []string{"single-homed"}
	esi, err = ParseEthernetSegmentIdentifier(args)
	assert.Nil(err)
	assert.Equal(esiZero, esi)

	// ESI_ARBITRARY
	args = []string{"ARBITRARY", "11:22:33:44:55:66:77:88:99"} // omit "ESI_"
	esi, err = ParseEthernetSegmentIdentifier(args)
	assert.Nil(err)
	assert.Equal(EthernetSegmentIdentifier{
		Type:  ESI_ARBITRARY,
		Value: []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99},
	}, esi)

	// ESI_LACP
	args = []string{"lacp", "aa:bb:cc:dd:ee:ff", strconv.FormatInt(0x1122, 10)} // lower case
	esi, err = ParseEthernetSegmentIdentifier(args)
	assert.Nil(err)
	assert.Equal(EthernetSegmentIdentifier{
		Type:  ESI_LACP,
		Value: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x00},
	}, esi)

	// ESI_MSTP
	args = []string{"esi_mstp", "aa:bb:cc:dd:ee:ff", strconv.FormatInt(0x1122, 10)} // omit "ESI_" + lower case
	esi, err = ParseEthernetSegmentIdentifier(args)
	assert.Nil(err)
	assert.Equal(EthernetSegmentIdentifier{
		Type:  ESI_MSTP,
		Value: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x00},
	}, esi)

	// ESI_MAC
	args = []string{"ESI_MAC", "aa:bb:cc:dd:ee:ff", strconv.FormatInt(0x112233, 10)}
	esi, err = ParseEthernetSegmentIdentifier(args)
	assert.Nil(err)
	assert.Equal(EthernetSegmentIdentifier{
		Type:  ESI_MAC,
		Value: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33},
	}, esi)

	// ESI_ROUTERID
	args = []string{"ESI_ROUTERID", "1.1.1.1", strconv.FormatInt(0x11223344, 10)}
	esi, err = ParseEthernetSegmentIdentifier(args)
	assert.Nil(err)
	assert.Equal(EthernetSegmentIdentifier{
		Type:  ESI_ROUTERID,
		Value: []byte{0x01, 0x01, 0x01, 0x01, 0x11, 0x22, 0x33, 0x44, 0x00},
	}, esi)

	// ESI_AS
	args = []string{"ESI_AS", strconv.FormatInt(0xaabbccdd, 10), strconv.FormatInt(0x11223344, 10)}
	esi, err = ParseEthernetSegmentIdentifier(args)
	assert.Nil(err)
	assert.Equal(EthernetSegmentIdentifier{
		Type:  ESI_AS,
		Value: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44, 0x00},
	}, esi)

	// Other
	args = []string{"99", "11:22:33:44:55:66:77:88:99"}
	esi, err = ParseEthernetSegmentIdentifier(args)
	assert.Nil(err)
	assert.Equal(EthernetSegmentIdentifier{
		Type:  ESIType(99),
		Value: []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99},
	}, esi)
}

func TestParseBogusShortData(t *testing.T) {
	var bodies = []BGPBody{
		&BGPOpen{},
		&BGPUpdate{},
		&BGPNotification{},
		&BGPKeepAlive{},
		&BGPRouteRefresh{},
	}

	for _, b := range bodies {
		b.DecodeFromBytes([]byte{0})
	}
}

func TestFuzzCrashers(t *testing.T) {
	var crashers = []string{
		"000000000000000000\x01",
	}

	for _, f := range crashers {
		ParseBGPMessage([]byte(f))
	}
}

func TestParseMessageWithBadLength(t *testing.T) {
	type testCase struct {
		fname string
		data  []byte
	}

	var cases []testCase
	root := filepath.Join("testdata", "bad-len")
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if path == root {
				return nil
			}
			return filepath.SkipDir
		}
		fname := filepath.Base(path)
		if strings.ContainsRune(fname, '.') {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		cases = append(cases, testCase{
			fname: fname,
			data:  data,
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range cases {
		t.Run(tt.fname, func(t *testing.T) {
			msg, err := ParseBGPMessage(tt.data)
			if err == nil {
				_, err = msg.Serialize()
				if err != nil {
					t.Fatal("failed to serialize:", err)
				}
				return
			}

			switch e := err.(type) {
			case *MessageError:
				switch e.TypeCode {
				case BGP_ERROR_MESSAGE_HEADER_ERROR:
					if e.SubTypeCode != BGP_ERROR_SUB_BAD_MESSAGE_LENGTH {
						t.Fatalf("got unexpected message type and data: %v", e)
					}
				}
			default:
				t.Fatalf("got unexpected error type %T: %v", err, err)
			}

		})
	}
}

func TestNormalizeFlowSpecOpValues(t *testing.T) {
	tests := []struct {
		msg  string
		args []string
		want []string
	}{
		{
			msg:  "valid match",
			args: []string{"  &  <=80", " tcp  != udp ", " =!   SA   & =U!  F", " =  is-fragment+last-fragment"},
			want: []string{"<=80", "tcp", "!=udp", "=!SA", "&=U", "!F", "=is-fragment+last-fragment"},
		},
		{
			msg:  "RFC5575 trims & prefix",
			args: []string{"&<=80"},
			want: []string{"<=80"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.msg, func(t *testing.T) {
			got := normalizeFlowSpecOpValues(tt.args)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_PathAttributeNextHop(t *testing.T) {
	f := func(addr string) {
		b, _ := NewPathAttributeNextHop(addr).Serialize()
		p := PathAttributeNextHop{}
		p.DecodeFromBytes(b)
		assert.Equal(t, addr, p.Value.String())
	}
	f("192.0.2.1")
	f("2001:db8::68")
}

func Test_LsTLVDecode(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in  []byte
		t   LsTLVType
		l   uint16
		v   []byte
		err bool
	}{
		{[]byte{0x01, 0x09, 0x00, 0x1, 0xef}, LS_TLV_IP_REACH_INFO, 5, []byte{0xef}, false},
		{[]byte{0x01, 0x09, 0x00, 0x0}, LS_TLV_IP_REACH_INFO, 4, []byte{}, false},
		{[]byte{0x01, 0x09, 0x01, 0xff}, LS_TLV_IP_REACH_INFO, 0, []byte{}, true},
		{[]byte{0x01, 0x09, 0x01}, LS_TLV_L2_BUNDLE_MEMBER_TLV, 1, []byte{}, true},
	}

	for _, test := range tests {
		tlv := &LsTLV{}

		got, err := tlv.DecodeFromBytes(test.in)
		if test.err {
			assert.Error(err)
			continue
		} else {
			assert.NoError(err)
		}
		assert.Equal(tlv.Len(), int(test.l))
		assert.Equal(got, test.v)
	}
}

func Test_LsTLVSerialize(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		tlv  LsTLV
		val  []byte
		want []byte
		err  bool
	}{
		{LsTLV{Type: LS_TLV_SID_LABEL_TLV, Length: 2}, []byte{0x11, 0x22}, []byte{0x04, 0x89, 0x00, 0x02, 0x11, 0x22}, false},
		{LsTLV{Type: LS_TLV_SID_LABEL_TLV, Length: 2}, []byte{0x11}, nil, true},
		{LsTLV{Type: LS_TLV_IGP_FLAGS, Length: 0}, []byte{}, []byte{0x04, 0x80, 0x00, 0x00}, false},
	}

	for _, test := range tests {
		got, err := test.tlv.Serialize(test.val)
		if test.err {
			assert.Error(err)
		} else {
			assert.NoError(err)
		}

		assert.Equal(got, test.want)
	}
}

func Test_LsTLVLinkID(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in        []byte
		want      string
		serialize bool
		err       bool
	}{
		{[]byte{0x01, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02}, `{"type":258,"local_link_id":1,"remote_link_id":2}`, true, false},
		{[]byte{0x01, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0xFF}, `{"type":258,"local_link_id":1,"remote_link_id":2}`, false, false},
		{[]byte{0x01, 0x02, 0x00, 0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}, "", false, true},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", false, true},
	}

	for _, test := range tests {
		tlv := LsTLVLinkID{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))

		if test.serialize {
			s, err := tlv.Serialize()
			assert.NoError(err)
			assert.Equal(test.in, s)
		}
	}
}

func Test_LsTLVIPv4InterfaceAddr(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in        []byte
		want      string
		serialize bool
		err       bool
	}{
		{[]byte{0x01, 0x03, 0x00, 0x04, 0x01, 0x01, 0x01, 0x01}, `{"type":259,"ipv4_interface_address":"1.1.1.1"}`, true, false},
		{[]byte{0x01, 0x03, 0x00, 0x04, 0x0a, 0x0a, 0x0a, 0x0a, 0x12}, `{"type":259,"ipv4_interface_address":"10.10.10.10"}`, false, false},
		{[]byte{0x01, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00}, "", false, true},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", false, true},
	}

	for _, test := range tests {
		tlv := LsTLVIPv4InterfaceAddr{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))

		if test.serialize {
			s, err := tlv.Serialize()
			assert.NoError(err)
			assert.Equal(test.in, s)
		}
	}
}

func Test_LsTLVIPv4NeighborAddr(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in        []byte
		want      string
		serialize bool
		err       bool
	}{
		{[]byte{0x01, 0x04, 0x00, 0x04, 0x01, 0x01, 0x01, 0x01}, `{"type":260,"ipv4_neighbor_address":"1.1.1.1"}`, true, false},
		{[]byte{0x01, 0x04, 0x00, 0x04, 0x0a, 0x0a, 0x0a, 0x0a, 0x12}, `{"type":260,"ipv4_neighbor_address":"10.10.10.10"}`, false, false},
		{[]byte{0x01, 0x04, 0x00, 0x03, 0x00, 0x00, 0x00}, "", false, true},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", false, true},
	}

	for _, test := range tests {
		tlv := LsTLVIPv4NeighborAddr{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))

		if test.serialize {
			s, err := tlv.Serialize()
			assert.NoError(err)
			assert.Equal(test.in, s)
		}
	}
}

func Test_LsTLVIPv6InterfaceAddr(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in        []byte
		want      string
		serialize bool
		err       bool
	}{
		{[]byte{0x01, 0x05, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xEF}, `{"type":261,"ipv6_interface_address":"2001:db8::beef"}`, true, false},
		{[]byte{0x01, 0x05, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xEF, 0xFF}, `{"type":261,"ipv6_interface_address":"2001:db8::beef"}`, false, false},
		{[]byte{0x01, 0x05, 0x00, 0x10, 0xfe, 0x80, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xEF}, "", false, true},
		{[]byte{0x01, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00}, "", false, true},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", false, true},
	}

	for _, test := range tests {
		tlv := LsTLVIPv6InterfaceAddr{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))

		if test.serialize {
			s, err := tlv.Serialize()
			assert.NoError(err)
			assert.Equal(test.in, s)
		}
	}
}

func Test_LsTLVIPv6NeighborAddr(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in        []byte
		want      string
		serialize bool
		err       bool
	}{
		{[]byte{0x01, 0x06, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xEF}, `{"type":262,"ipv6_neighbor_address":"2001:db8::beef"}`, true, false},
		{[]byte{0x01, 0x06, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xEF, 0xFF}, `{"type":262,"ipv6_neighbor_address":"2001:db8::beef"}`, false, false},
		{[]byte{0x01, 0x06, 0x00, 0x10, 0xfe, 0x81, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xEF}, "", false, true},
		{[]byte{0x01, 0x06, 0x00, 0x03, 0x00, 0x00, 0x00}, "", false, true},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", false, true},
	}

	for _, test := range tests {
		tlv := LsTLVIPv6NeighborAddr{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))

		if test.serialize {
			s, err := tlv.Serialize()
			assert.NoError(err)
			assert.Equal(test.in, s)
		}
	}
}

func Test_LsTLVNodeFlagBits(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in   []byte
		want string
		err  bool
	}{
		{[]byte{0x04, 0x00, 0x00, 0x01, 0xFF}, `{"type":1024,"node_flags":"{Node Flags: XXVRBETO}"}`, false},
		{[]byte{0x04, 0x00, 0x00, 0x01, 0x80}, `{"type":1024,"node_flags":"{Node Flags: *******O}"}`, false},
		{[]byte{0x04, 0x00, 0x00, 0x01, 0x80, 0xAA}, `{"type":1024,"node_flags":"{Node Flags: *******O}"}`, false},
		{[]byte{0x04, 0x00, 0x00, 0x02, 0x80, 0x44}, "", true},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", true},
	}

	for _, test := range tests {
		tlv := LsTLVNodeFlagBits{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))
	}
}

func Test_LsTLVNodeName(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in   []byte
		want string
		err  bool
	}{
		{[]byte{0x04, 0x02, 0x00, 0x03, 0x72, 0x74, 0x72}, `{"type":1026,"node_name":"rtr"}`, false},
		{[]byte{0x04, 0x02, 0x00, 0x03, 0x72, 0x74, 0x72, 0x00}, `{"type":1026,"node_name":"rtr"}`, false},
		{[]byte{0x04, 0x02, 0x00, 0x00}, "", true},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", true},
	}

	for _, test := range tests {
		tlv := LsTLVNodeName{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))
	}
}

func Test_LsTLVIsisArea(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in   []byte
		want string
		err  bool
	}{
		{[]byte{0x04, 0x03, 0x00, 0x03, 0x72, 0x74, 0x72}, `{"type":1027,"isis_area_id":"[114 116 114]"}`, false},
		{[]byte{0x04, 0x03, 0x00, 0x03, 0x72, 0x74, 0x72, 0x44}, `{"type":1027,"isis_area_id":"[114 116 114]"}`, false},
		{[]byte{0x04, 0x03, 0x00, 0x00}, "", true},
		{[]byte{0x04, 0x03, 0x00, 0x0E, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}, "", true},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", true},
	}

	for _, test := range tests {
		tlv := LsTLVIsisArea{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))
	}
}

func Test_LsTLVLocalIPv4RouterID(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in   []byte
		want string
		err  bool
	}{
		{[]byte{0x04, 0x04, 0x00, 0x04, 0x01, 0x01, 0x01, 0x01}, `{"type":1028,"node_local_router_id_ipv4":"1.1.1.1"}`, false},
		{[]byte{0x04, 0x04, 0x00, 0x04, 0x01, 0x01, 0x01, 0x01, 0x12}, `{"type":1028,"node_local_router_id_ipv4":"1.1.1.1"}`, false},
		{[]byte{0x04, 0x04, 0x00, 0x03, 0x00, 0x00, 0x00}, "", true},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", true},
	}

	for _, test := range tests {
		tlv := LsTLVLocalIPv4RouterID{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))
	}
}

func Test_LsTLVRemoteIPv4RouterID(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in   []byte
		want string
		err  bool
	}{
		{[]byte{0x04, 0x06, 0x00, 0x04, 0x02, 0x02, 0x02, 0x02}, `{"type":1030,"node_remote_router_id_ipv4":"2.2.2.2"}`, false},
		{[]byte{0x04, 0x06, 0x00, 0x04, 0x02, 0x02, 0x02, 0x02, 0x44}, `{"type":1030,"node_remote_router_id_ipv4":"2.2.2.2"}`, false},
		{[]byte{0x04, 0x06, 0x00, 0x03, 0x00, 0x00, 0x00}, "", true},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", true},
	}

	for _, test := range tests {
		tlv := LsTLVRemoteIPv4RouterID{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))
	}
}

func Test_LsTLVLocalIPv6RouterID(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in   []byte
		want string
		err  bool
	}{
		{[]byte{0x04, 0x05, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xEF}, `{"type":1029,"node_local_router_id_ipv6":"2001:db8::beef"}`, false},
		{[]byte{0x04, 0x05, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xEF, 0xFF}, `{"type":1029,"node_local_router_id_ipv6":"2001:db8::beef"}`, false},
		{[]byte{0x04, 0x05, 0x00, 0x01, 0x00}, "", true},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", true},
	}

	for _, test := range tests {
		tlv := LsTLVLocalIPv6RouterID{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))
	}
}

func Test_LsTLVRemoteIPv6RouterID(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in   []byte
		want string
		err  bool
	}{
		{[]byte{0x04, 0x07, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xEF}, `{"type":1031,"node_remote_router_id_ipv6":"2001:db8::beef"}`, false},
		{[]byte{0x04, 0x07, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xEF, 0xFF}, `{"type":1031,"node_remote_router_id_ipv6":"2001:db8::beef"}`, false},
		{[]byte{0x04, 0x07, 0x00, 0x01, 0x00}, "", true},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", true},
	}

	for _, test := range tests {
		tlv := LsTLVRemoteIPv6RouterID{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))
	}
}

func Test_LsTLVOpaqueNodeAttr(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in   []byte
		want string
		err  bool
	}{
		{[]byte{0x04, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03}, `{"type":1025,"node_opaque_attribute":"[1 2 3]"}`, false},
		{[]byte{0x04, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03, 0x04}, `{"type":1025,"node_opaque_attribute":"[1 2 3]"}`, false},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", true},
	}

	for _, test := range tests {
		tlv := LsTLVOpaqueNodeAttr{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))
	}
}

func Test_LsTLVAutonomousSystem(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in   []byte
		want string
		err  bool
	}{
		{[]byte{0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07}, `{"type":512,"asn":117901063}`, false},
		{[]byte{0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, 0xFF}, `{"type":512,"asn":117901063}`, false},
		{[]byte{0x02, 0x00, 0x00, 0x03, 0x07, 0x07, 0x07}, "", true},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", true},
	}

	for _, test := range tests {
		tlv := LsTLVAutonomousSystem{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))
	}
}

func Test_LsTLVBgpLsID(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in   []byte
		want string
		err  bool
	}{
		{[]byte{0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07}, `{"type":513,"bgp_ls_id":117901063}`, false},
		{[]byte{0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, 0xFF}, `{"type":513,"bgp_ls_id":117901063}`, false},
		{[]byte{0x02, 0x01, 0x00, 0x03, 0x07, 0x07, 0x07}, "", true},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", true},
	}

	for _, test := range tests {
		tlv := LsTLVBgpLsID{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))
	}
}

func Test_LsTLVIgpRouterID(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in   []byte
		want string
		err  bool
	}{
		{[]byte{0x02, 0x03, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04}, `{"type":515,"igp_router_id":"[1 2 3 4]"}`, false},
		{[]byte{0x02, 0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, `{"type":515,"igp_router_id":"[1 2 3 4 5 6]"}`, false},
		{[]byte{0x02, 0x03, 0x00, 0x07, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, `{"type":515,"igp_router_id":"[1 2 3 4 5 6 7]"}`, false},
		{[]byte{0x02, 0x03, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, `{"type":515,"igp_router_id":"[1 2 3 4 5 6 7 8]"}`, false},
		{[]byte{0x02, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}, "", true},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", true},
	}

	for _, test := range tests {
		tlv := LsTLVIgpRouterID{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))
	}
}

func Test_LsTLVBgpRouterID(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in   []byte
		want string
		err  bool
	}{
		{[]byte{0x02, 0x04, 0x00, 0x04, 0x0a, 0xff, 0x00, 0x01}, `{"type":516,"bgp_router_id":"10.255.0.1"}`, false},
		{[]byte{0x02, 0x04, 0x00, 0x05, 0x0a, 0xff, 0x00, 0x01, 0x02}, "", true},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", true},
	}

	for _, test := range tests {
		tlv := LsTLVBgpRouterID{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))
	}
}

func Test_LsTLVBgpConfederationMember(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in   []byte
		want string
		err  bool
	}{
		{[]byte{0x02, 0x05, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07}, `{"type":517,"bgp_confederation_member":117901063}`, false},
		{[]byte{0x02, 0x05, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, 0xFF}, `{"type":517,"bgp_confederation_member":117901063}`, false},
		{[]byte{0x02, 0x05, 0x00, 0x03, 0x07, 0x07, 0x07}, "", true},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", true},
	}

	for _, test := range tests {
		tlv := LsTLVBgpConfederationMember{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))
	}
}

func Test_LsTLVOspfAreaID(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in   []byte
		want string
		err  bool
	}{
		{[]byte{0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07}, `{"type":514,"ospf_area_id":117901063}`, false},
		{[]byte{0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, 0xFF}, `{"type":514,"ospf_area_id":117901063}`, false},
		{[]byte{0x02, 0x02, 0x00, 0x03, 0x07, 0x07, 0x07}, "", true},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", true},
	}

	for _, test := range tests {
		tlv := LsTLVOspfAreaID{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))
	}
}

func Test_LsTLVOspfRouteType(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in   []byte
		want string
		err  bool
	}{
		{[]byte{0x01, 0x08, 0x00, 0x01, 0x06}, `{"type":264,"ospf_route_type":"NSSA2"}`, false},
		{[]byte{0x01, 0x08, 0x00, 0x01, 0x01, 0xFF}, `{"type":264,"ospf_route_type":"INTRA-AREA"}`, false},
		{[]byte{0x01, 0x08, 0x00, 0x02, 0x01, 0x01}, "", true},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", true},
	}

	for _, test := range tests {
		tlv := LsTLVOspfRouteType{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))
	}
}

func Test_LsTLVIPReachability(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in        []byte
		want      string
		serialize bool
		err       bool
	}{
		{[]byte{0x01, 0x09, 0x00, 0x02, 0x08, 0x0a}, `{"type":265,"prefix_length":8,"prefix":"[10]"}`, true, false},
		{[]byte{0x01, 0x09, 0x00, 0x03, 0x10, 0x0a, 0x0b, 0xFF}, `{"type":265,"prefix_length":16,"prefix":"[10 11]"}`, false, false},
		{[]byte{0x01, 0x09, 0x00, 0x02, 0x08}, ``, false, true},
		{[]byte{0x01, 0x09, 0x00, 0x01, 0x01}, "", false, true},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", false, true},
	}

	for _, test := range tests {
		tlv := LsTLVIPReachability{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))
	}
}

func Test_LsTLVIPReachabilityToIPNet(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		tlv  LsTLVIPReachability
		ipv6 bool
		want net.IPNet
	}{
		{
			tlv: LsTLVIPReachability{
				PrefixLength: 8,
				Prefix:       []byte{0x0a},
			},
			ipv6: false,
			want: net.IPNet{
				IP:   net.IPv4(10, 0, 0, 0),
				Mask: net.CIDRMask(8, 32),
			},
		},
		{
			tlv: LsTLVIPReachability{
				PrefixLength: 4,
				Prefix:       []byte{0xaa},
			},
			ipv6: false,
			want: net.IPNet{
				IP:   net.IPv4(160, 0, 0, 0),
				Mask: net.CIDRMask(4, 32),
			},
		},
		{
			tlv: LsTLVIPReachability{
				PrefixLength: 31,
				Prefix:       []byte{0x0a, 0x0a, 0x0a, 0xfe},
			},
			ipv6: false,
			want: net.IPNet{
				IP:   net.IPv4(10, 10, 10, 254),
				Mask: net.CIDRMask(31, 32),
			},
		},
		{
			tlv: LsTLVIPReachability{
				PrefixLength: 16,
				Prefix:       []byte{0x20, 0x01},
			},
			ipv6: true,
			want: net.IPNet{
				IP:   net.ParseIP("2001::"),
				Mask: net.CIDRMask(16, 128),
			},
		},
		{
			tlv: LsTLVIPReachability{
				PrefixLength: 24,
				Prefix:       []byte{0x20, 0x01, 0x0d},
			},
			ipv6: true,
			want: net.IPNet{
				IP:   net.ParseIP("2001:d00::"),
				Mask: net.CIDRMask(24, 128),
			},
		},
	}

	for _, test := range tests {
		got := test.tlv.ToIPNet(test.ipv6)
		assert.Equal(test.want.IP.String(), got.IP.String())
		assert.Equal(test.want.Mask.String(), got.Mask.String())
	}
}

func Test_LsTLVAdminGroup(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in   []byte
		want string
		err  bool
	}{
		{[]byte{0x04, 0x40, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07}, `{"type":1088,"admin_group":"07070707"}`, false},
		{[]byte{0x04, 0x40, 0x00, 0x04, 0xAE, 0xAE, 0xAE, 0xAE, 0xFF}, `{"type":1088,"admin_group":"aeaeaeae"}`, false},
		{[]byte{0x04, 0x40, 0x00, 0x03, 0x07, 0x07, 0x07}, "", true},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", true},
	}

	for _, test := range tests {
		tlv := LsTLVAdminGroup{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))
	}
}

func Test_LsTLVMaxLinkBw(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in   []byte
		want string
		err  bool
	}{
		{[]byte{0x04, 0x41, 0x00, 0x04, 0x43, 0xA4, 0xB2, 0x00}, `{"type":1089,"max_link_bw":329.39062}`, false},
		{[]byte{0x04, 0x41, 0x00, 0x04, 0x43, 0xA4, 0xB2, 0x00, 0xFF}, `{"type":1089,"max_link_bw":329.39062}`, false},
		{[]byte{0x04, 0x41, 0x00, 0x03, 0x07, 0x07, 0x07}, "", true},
		{[]byte{0x04, 0x41, 0x00, 0x04, 0x7f, 0x80, 0x00, 0x00}, "", true}, // +Inf
		{[]byte{0x04, 0x41, 0x00, 0x04, 0xff, 0x80, 0x00, 0x00}, "", true}, // -Inf
		{[]byte{0x04, 0x41, 0x00, 0x04, 0xff, 0xbf, 0xff, 0xff}, "", true}, // NaN
		{[]byte{0x04, 0x41, 0x00, 0x04, 0xc2, 0xc8, 0x00, 0x00}, "", true}, // -100
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", true},
	}

	for _, test := range tests {
		tlv := LsTLVMaxLinkBw{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))
	}
}

func Test_LsTLVMaxReservableLinkBw(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in   []byte
		want string
		err  bool
	}{
		{[]byte{0x04, 0x42, 0x00, 0x04, 0x43, 0xA4, 0xB2, 0x00}, `{"type":1090,"max_reservable_link_bw":329.39062}`, false},
		{[]byte{0x04, 0x42, 0x00, 0x04, 0x43, 0xA4, 0xB2, 0x00, 0xFF}, `{"type":1090,"max_reservable_link_bw":329.39062}`, false},
		{[]byte{0x04, 0x42, 0x00, 0x03, 0x07, 0x07, 0x07}, "", true},
		{[]byte{0x04, 0x42, 0x00, 0x04, 0x7f, 0x80, 0x00, 0x00}, "", true}, // +Inf
		{[]byte{0x04, 0x42, 0x00, 0x04, 0xff, 0x80, 0x00, 0x00}, "", true}, // -Inf
		{[]byte{0x04, 0x42, 0x00, 0x04, 0xff, 0xbf, 0xff, 0xff}, "", true}, // NaN
		{[]byte{0x04, 0x42, 0x00, 0x04, 0xc2, 0xc8, 0x00, 0x00}, "", true}, // -100
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", true},
	}

	for _, test := range tests {
		tlv := LsTLVMaxReservableLinkBw{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))
	}
}

func Test_LsTLVUnreservedBw(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in   []byte
		want string
		err  bool
	}{
		{[]byte{0x04, 0x43, 0x00, 0x20,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB3, 0x00},
			`{"type":1091,"unreserved_bw":[329.39062,329.39062,329.39062,329.39062,329.39062,329.39062,329.39062,329.39844]}`, false},
		{[]byte{0x04, 0x43, 0x00, 0x20,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB2, 0x00, 0xff},
			`{"type":1091,"unreserved_bw":[329.39062,329.39062,329.39062,329.39062,329.39062,329.39062,329.39062,329.39062]}`, false},
		{[]byte{0x04, 0x43, 0x00, 0x20,
			0x7f, 0x80, 0x00, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB3, 0x00},
			"", true},
		{[]byte{0x04, 0x43, 0x00, 0x20,
			0xff, 0x80, 0x00, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB3, 0x00},
			"", true},
		{[]byte{0x04, 0x43, 0x00, 0x20,
			0x43, 0xA4, 0xB3, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0xff, 0xbf, 0xff, 0xff,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB3, 0x00},
			"", true},
		{[]byte{0x04, 0x43, 0x00, 0x20,
			0x43, 0xA4, 0xB3, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB3, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0x43, 0xA4, 0xB2, 0x00,
			0xc2, 0xc8, 0x00, 0x00},
			"", true},
		{[]byte{0x04, 0x43, 0x00, 0x03, 0x07, 0x07, 0x07}, "", true},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", true},
	}

	for _, test := range tests {
		tlv := LsTLVUnreservedBw{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))
	}
}

func Test_LsTLVTEDefaultMetric(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in        []byte
		want      string
		serialize bool
		err       bool
	}{
		{[]byte{0x04, 0x44, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07}, `{"type":1092,"te_default_metric":117901063}`, true, false},
		{[]byte{0x04, 0x44, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, 0xFF}, `{"type":1092,"te_default_metric":117901063}`, false, false},
		{[]byte{0x04, 0x44, 0x00, 0x03, 0x07, 0x07, 0x07}, "", false, true},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", false, true},
	}

	for _, test := range tests {
		tlv := LsTLVTEDefaultMetric{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))

		if test.serialize {
			got, err := tlv.Serialize()
			assert.NoError(err)
			assert.Equal(test.in, got)
		}
	}
}

func Test_LsTLVIGPMetric(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in        []byte
		want      string
		serialize bool
		err       bool
	}{
		{[]byte{0x04, 0x47, 0x00, 0x01, 0x01}, `{"type":1095,"igp_metric":1}`, true, false},
		{[]byte{0x04, 0x47, 0x00, 0x01, 0x3F}, `{"type":1095,"igp_metric":63}`, true, false},
		{[]byte{0x04, 0x47, 0x00, 0x01, 0xFF}, `{"type":1095,"igp_metric":63}`, false, false},
		{[]byte{0x04, 0x47, 0x00, 0x02, 0x00, 0x01}, `{"type":1095,"igp_metric":1}`, true, false},
		{[]byte{0x04, 0x47, 0x00, 0x02, 0xff, 0xff}, `{"type":1095,"igp_metric":65535}`, true, false},
		{[]byte{0x04, 0x47, 0x00, 0x03, 0x00, 0x00, 0x01}, `{"type":1095,"igp_metric":1}`, true, false},
		{[]byte{0x04, 0x47, 0x00, 0x03, 0xff, 0xff, 0xff}, `{"type":1095,"igp_metric":16777215}`, true, false},
		{[]byte{0x04, 0x47, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07}, "", false, true},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", false, true},
	}

	for _, test := range tests {
		tlv := LsTLVIGPMetric{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))

		if test.serialize {
			got, err := tlv.Serialize()
			assert.NoError(err)
			assert.Equal(test.in, got)
		}
	}
}

func Test_LsTLVNLinkName(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in   []byte
		want string
		err  bool
	}{
		{[]byte{0x04, 0x4a, 0x00, 0x03, 0x72, 0x74, 0x72}, `{"type":1098,"link_name":"rtr"}`, false},
		{[]byte{0x04, 0x4a, 0x00, 0x03, 0x72, 0x74, 0x72, 0x00}, `{"type":1098,"link_name":"rtr"}`, false},
		{[]byte{0x04, 0x4a, 0x00, 0x00}, "", true},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", true},
	}

	for _, test := range tests {
		tlv := LsTLVLinkName{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))
	}
}

func Test_LsTLVSrAlgorithm(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in   []byte
		want string
		err  bool
	}{
		{[]byte{0x04, 0x0b, 0x00, 0x03, 0x01, 0x02, 0x03}, `{"type":1035,"sr_algorithm":"[1 2 3]"}`, false},
		{[]byte{0x04, 0x0b, 0x00, 0x03, 0x01, 0x02, 0x03, 0x04}, `{"type":1035,"sr_algorithm":"[1 2 3]"}`, false},
		{[]byte{0x04, 0x0b, 0x00, 0x00}, "", true},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", true},
	}

	for _, test := range tests {
		tlv := LsTLVSrAlgorithm{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))
	}
}

func Test_LsTLVSrCapabilities(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in        []byte
		want      string
		serialize bool
		err       bool
	}{
		{
			[]byte{
				0x04, 0x0a, 0x00, 0x0c, // type 1034, length 12
				0x00, 0x00, // flags and reserved
				0x00, 0x88, 0xb8, // range: 35000
				0x04, 0x89, 0x00, 0x03, 0x01, 0x88, 0x94, // SID/Label TLV, SID: 100500
			},
			`{"type":1034,"flags":0,"ranges":[{"Range":35000,"FirstLabel":{"type":1161,"sid_label":100500}}]}`,
			true,
			false,
		},
		{
			[]byte{
				0x04, 0x0a, 0x00, 0x0d, // type 1034, length 13
				0x00, 0x00, // flags and reserved
				0x00, 0x88, 0xb8, // range: 35000
				0x04, 0x89, 0x00, 0x04, 0x04, 0x3B, 0x73, 0x49, // SID/Label TLV, SID: 71005001
			},
			`{"type":1034,"flags":0,"ranges":[{"Range":35000,"FirstLabel":{"type":1161,"sid_label":71005001}}]}`,
			true,
			false,
		},
		{
			[]byte{
				0x04, 0x0a, 0x00, 0x17, // type 1034, length 23
				0x00, 0x00, // flags and reserved
				0x00, 0x88, 0xb8, // range: 35000
				0x04, 0x89, 0x00, 0x04, 0x04, 0x3B, 0x73, 0x49, // SID/Label TLV, SID: 71005001
				0x0f, 0x42, 0x40, // range: 1000000
				0x04, 0x89, 0x00, 0x03, 0x01, 0x88, 0x94, // SID/Label TLV, SID: 100500
			},
			`{"type":1034,"flags":0,"ranges":[{"Range":35000,"FirstLabel":{"type":1161,"sid_label":71005001}},{"Range":1000000,"FirstLabel":{"type":1161,"sid_label":100500}}]}`,
			true,
			false,
		},
		{
			[]byte{
				0x04, 0x0a, 0x00, 0x17, // type 1034, length 23
				0x00, 0x00, // flags and reserved
				0x00, 0x88, 0xb8, // range: 35000
				0x04, 0x89, 0x00, 0x04, 0x04, 0x3B, 0x73, 0x49, // SID/Label TLV, SID: 71005001
				0x0f, 0x42, 0x40, // range: 1000000
				0x04, 0x89, 0x00, 0x03, 0x01, 0x88, 0x94, // SID/Label TLV, SID: 100500
				0xff, 0xff, 0xff, // some random bytes - should be ignored
			},
			`{"type":1034,"flags":0,"ranges":[{"Range":35000,"FirstLabel":{"type":1161,"sid_label":71005001}},{"Range":1000000,"FirstLabel":{"type":1161,"sid_label":100500}}]}`,
			false,
			false,
		},
		{
			[]byte{
				0x04, 0x0a, 0x00, 0xcc, // type 1034, length 204 (corrupted)
				0x00, 0x00, // flags and reserved
				0x00, 0x88, 0xb8, // range: 35000
				0x04, 0x89, 0x00, 0x03, 0x01, 0x88, 0x94, // SID/Label TLV, SID: 100500
			},
			"",
			false,
			true,
		},
		{
			[]byte{
				0x04, 0x0a, 0x00, 0x11, // type 1034, length 23
				0x00, 0x00, // flags and reserved
				0x00, 0x88, 0xb8, // range: 35000
				0x04, 0x89, 0x00, 0x04, 0x04, 0x3B, 0x73, 0x49, // SID/Label TLV, SID: 71005001
				0x0f, 0x42, 0x40, // range: 1000000
				0x04, // No SID/Label sub-TLV
			},
			"",
			false,
			true,
		},
	}

	for _, test := range tests {
		tlv := LsTLVSrCapabilities{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))

		if test.serialize {
			s, err := tlv.Serialize()
			assert.NoError(err)
			assert.Equal(test.in, s)
		}
	}
}

func Test_LsTLVLocalBlock(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in        []byte
		want      string
		serialize bool
		err       bool
	}{
		{
			[]byte{
				0x04, 0x0c, 0x00, 0x0c, // type 1036, length 12
				0x00, 0x00, // flags and reserved
				0x00, 0x88, 0xb8, // range: 35000
				0x04, 0x89, 0x00, 0x03, 0x01, 0x88, 0x94, // SID/Label TLV, SID: 100500
			},
			`{"type":1036,"flags":0,"ranges":[{"Range":35000,"FirstLabel":{"type":1161,"sid_label":100500}}]}`,
			true,
			false,
		},
		{
			[]byte{
				0x04, 0x0c, 0x00, 0x0d, // type 1036, length 13
				0x00, 0x00, // flags and reserved
				0x00, 0x88, 0xb8, // range: 35000
				0x04, 0x89, 0x00, 0x04, 0x04, 0x3B, 0x73, 0x49, // SID/Label TLV, SID: 71005001
			},
			`{"type":1036,"flags":0,"ranges":[{"Range":35000,"FirstLabel":{"type":1161,"sid_label":71005001}}]}`,
			true,
			false,
		},
		{
			[]byte{
				0x04, 0x0c, 0x00, 0x17, // type 1036, length 23
				0x00, 0x00, // flags and reserved
				0x00, 0x88, 0xb8, // range: 35000
				0x04, 0x89, 0x00, 0x04, 0x04, 0x3B, 0x73, 0x49, // SID/Label TLV, SID: 71005001
				0x0f, 0x42, 0x40, // range: 1000000
				0x04, 0x89, 0x00, 0x03, 0x01, 0x88, 0x94, // SID/Label TLV, SID: 100500
			},
			`{"type":1036,"flags":0,"ranges":[{"Range":35000,"FirstLabel":{"type":1161,"sid_label":71005001}},{"Range":1000000,"FirstLabel":{"type":1161,"sid_label":100500}}]}`,
			true,
			false,
		},
		{
			[]byte{
				0x04, 0x0c, 0x00, 0x17, // type 1036, length 23
				0x00, 0x00, // flags and reserved
				0x00, 0x88, 0xb8, // range: 35000
				0x04, 0x89, 0x00, 0x04, 0x04, 0x3B, 0x73, 0x49, // SID/Label TLV, SID: 71005001
				0x0f, 0x42, 0x40, // range: 1000000
				0x04, 0x89, 0x00, 0x03, 0x01, 0x88, 0x94, // SID/Label TLV, SID: 100500
				0xff, 0xff, 0xff, // some random bytes - should be ignored
			},
			`{"type":1036,"flags":0,"ranges":[{"Range":35000,"FirstLabel":{"type":1161,"sid_label":71005001}},{"Range":1000000,"FirstLabel":{"type":1161,"sid_label":100500}}]}`,
			false,
			false,
		},
		{
			[]byte{
				0x04, 0x0c, 0x00, 0xcc, // type 1036, length 204 (corrupted)
				0x00, 0x00, // flags and reserved
				0x00, 0x88, 0xb8, // range: 35000
				0x04, 0x89, 0x00, 0x03, 0x01, 0x88, 0x94, // SID/Label TLV, SID: 100500
			},
			"",
			false,
			true,
		},
		{
			[]byte{
				0x04, 0x0c, 0x00, 0x11, // type 1036, length 23
				0x00, 0x00, // flags and reserved
				0x00, 0x88, 0xb8, // range: 35000
				0x04, 0x89, 0x00, 0x04, 0x04, 0x3B, 0x73, 0x49, // SID/Label TLV, SID: 71005001
				0x0f, 0x42, 0x40, // range: 1000000
				0x04, // No SID/Label sub-TLV
			},
			"",
			false,
			true,
		},
	}

	for _, test := range tests {
		tlv := LsTLVSrLocalBlock{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))

		if test.serialize {
			s, err := tlv.Serialize()
			assert.NoError(err)
			assert.Equal(test.in, s)
		}
	}
}

func Test_LsTLVAdjacencySID(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in        []byte
		want      string
		serialize bool
		err       bool
	}{
		{[]byte{0x04, 0x4b, 0x00, 0x07, 0x01, 0x01, 0x00, 0x00, 0x01, 0x88, 0x94}, `{"type":1099,"adjacency_sid":100500}`, true, false},
		{[]byte{0x04, 0x4b, 0x00, 0x07, 0x01, 0x01, 0x00, 0x00, 0xff, 0xff, 0xff}, `{"type":1099,"adjacency_sid":1048575}`, false, false},
		{[]byte{0x04, 0x4b, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x04, 0x3B, 0x73, 0x49}, `{"type":1099,"adjacency_sid":71005001}`, true, false},
		{[]byte{0x04, 0x4b, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x11}, "", false, true},
		{[]byte{0xfe, 0xfe, 0x00, 0x07, 0x04, 0x3B, 0x73, 0x49, 0x05, 0x06, 0x07}, "", false, true},
	}

	for _, test := range tests {
		tlv := LsTLVAdjacencySID{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))

		if test.serialize {
			s, err := tlv.Serialize()
			assert.NoError(err)
			assert.Equal(test.in, s)
		}
	}
}

func Test_LsTLVSIDLabel(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in        []byte
		want      string
		serialize bool
		err       bool
	}{
		{[]byte{0x04, 0x89, 0x00, 0x03, 0x01, 0x88, 0x94}, `{"type":1161,"sid_label":100500}`, true, false},
		{[]byte{0x04, 0x89, 0x00, 0x03, 0x0f, 0xff, 0xff}, `{"type":1161,"sid_label":1048575}`, true, false},
		{[]byte{0x04, 0x89, 0x00, 0x03, 0xff, 0xff, 0xff}, `{"type":1161,"sid_label":1048575}`, false, false},
		{[]byte{0x04, 0x89, 0x00, 0x04, 0x04, 0x3B, 0x73, 0x49}, `{"type":1161,"sid_label":71005001}`, false, false},
		{[]byte{0x04, 0x89, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}, "", false, true},
		{[]byte{0xfe, 0xfe, 0x00, 0x04, 0x04, 0x3B, 0x73, 0x49}, "", false, true},
	}

	for _, test := range tests {
		tlv := LsTLVSIDLabel{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))

		if test.serialize {
			s, err := tlv.Serialize()
			assert.NoError(err)
			assert.Equal(test.in, s)
		}
	}
}

func Test_LsTLVPrefixSID(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in        []byte
		want      string
		serialize bool
		err       bool
	}{
		{[]byte{0x04, 0x86, 0x00, 0x07, 0x01, 0x01, 0x00, 0x00, 0x01, 0x88, 0x94}, `{"type":1158,"prefix_sid":100500}`, true, false},
		{[]byte{0x04, 0x86, 0x00, 0x07, 0x01, 0x01, 0x00, 0x00, 0xff, 0xff, 0xff}, `{"type":1158,"prefix_sid":1048575}`, false, false},
		{[]byte{0x04, 0x86, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x04, 0x3B, 0x73, 0x49}, `{"type":1158,"prefix_sid":71005001}`, true, false},
		{[]byte{0x04, 0x86, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x11}, "", false, true},
		{[]byte{0xfe, 0xfe, 0x00, 0x07, 0x04, 0x3B, 0x73, 0x49, 0x05, 0x06, 0x07}, "", false, true},
	}

	for _, test := range tests {
		tlv := LsTLVPrefixSID{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))

		if test.serialize {
			s, err := tlv.Serialize()
			assert.NoError(err)
			assert.Equal(test.in, s)
		}
	}
}

func Test_LsTLVPeerNodeSID(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in        []byte
		want      string
		serialize bool
		err       bool
	}{
		{[]byte{0x04, 0x4d, 0x00, 0x07, 0xc0, 0x00, 0x00, 0x00, 0x01, 0x88, 0x94}, `{"type":1101,"peer_node_sid":100500}`, true, false},
		{[]byte{0x04, 0x4d, 0x00, 0x07, 0xc0, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff}, `{"type":1101,"peer_node_sid":1048575}`, false, false},
		{[]byte{0x04, 0x4d, 0x00, 0x08, 0xc0, 0x00, 0x00, 0x00, 0x04, 0x3B, 0x73, 0x49}, `{"type":1101,"peer_node_sid":71005001}`, true, false},
		{[]byte{0x04, 0x4d, 0x00, 0x06, 0xc0, 0x02, 0x03, 0x04, 0x05, 0x11}, "", false, true},
		{[]byte{0xfe, 0xfe, 0x00, 0x07, 0x04, 0x3B, 0x73, 0x49, 0x05, 0x06, 0x07}, "", false, true},
	}

	for _, test := range tests {
		tlv := LsTLVPeerNodeSID{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))

		if test.serialize {
			s, err := tlv.Serialize()
			assert.NoError(err)
			assert.Equal(test.in, s)
		}
	}
}

func Test_LsTLVPeerAdjacencySID(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in        []byte
		want      string
		serialize bool
		err       bool
	}{
		{[]byte{0x04, 0x4e, 0x00, 0x07, 0xc0, 0x00, 0x00, 0x00, 0x01, 0x88, 0x94}, `{"type":1102,"peer_adjacency_sid":100500}`, true, false},
		{[]byte{0x04, 0x4e, 0x00, 0x07, 0xc0, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff}, `{"type":1102,"peer_adjacency_sid":1048575}`, false, false},
		{[]byte{0x04, 0x4e, 0x00, 0x08, 0xc0, 0x00, 0x00, 0x00, 0x04, 0x3B, 0x73, 0x49}, `{"type":1102,"peer_adjacency_sid":71005001}`, true, false},
		{[]byte{0x04, 0x4e, 0x00, 0x06, 0xc0, 0x02, 0x03, 0x04, 0x05, 0x11}, "", false, true},
		{[]byte{0xfe, 0xfe, 0x00, 0x07, 0x04, 0x3B, 0x73, 0x49, 0x05, 0x06, 0x07}, "", false, true},
	}

	for _, test := range tests {
		tlv := LsTLVPeerAdjacencySID{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))

		if test.serialize {
			s, err := tlv.Serialize()
			assert.NoError(err)
			assert.Equal(test.in, s)
		}
	}
}

func Test_LsTLVPeerSetSID(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in        []byte
		want      string
		serialize bool
		err       bool
	}{
		{[]byte{0x04, 0x4f, 0x00, 0x07, 0xc0, 0x00, 0x00, 0x00, 0x01, 0x88, 0x94}, `{"type":1103,"peer_set_sid":100500}`, true, false},
		{[]byte{0x04, 0x4f, 0x00, 0x07, 0xc0, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff}, `{"type":1103,"peer_set_sid":1048575}`, false, false},
		{[]byte{0x04, 0x4f, 0x00, 0x08, 0xc0, 0x00, 0x00, 0x00, 0x04, 0x3B, 0x73, 0x49}, `{"type":1103,"peer_set_sid":71005001}`, true, false},
		{[]byte{0x04, 0x4f, 0x00, 0x06, 0xc0, 0x02, 0x03, 0x04, 0x05, 0x11}, "", false, true},
		{[]byte{0xfe, 0xfe, 0x00, 0x07, 0x04, 0x3B, 0x73, 0x49, 0x05, 0x06, 0x07}, "", false, true},
	}

	for _, test := range tests {
		tlv := LsTLVPeerSetSID{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))

		if test.serialize {
			s, err := tlv.Serialize()
			assert.NoError(err)
			assert.Equal(test.in, s)
		}
	}
}

func Test_LsTLVSourceRouterID(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in   []byte
		want string
		err  bool
	}{
		{[]byte{0x04, 0x93, 0x00, 0x04, 0x0a, 0x0a, 0x0a, 0x0a}, `{"type":1171,"source_router_id":"10.10.10.10"}`, false},
		{[]byte{0x04, 0x93, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xEF}, `{"type":1171,"source_router_id":"2001:db8::beef"}`, false},
		{[]byte{0x04, 0x93, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xEF, 0xFF}, `{"type":1171,"source_router_id":"2001:db8::beef"}`, false},
		{[]byte{0x04, 0x93, 0x00, 0x01, 0x00}, "", true},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", true},
	}

	for _, test := range tests {
		tlv := LsTLVSourceRouterID{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))
	}
}

func Test_LsTLVOpaqueLinkAttr(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in   []byte
		want string
		err  bool
	}{
		{[]byte{0x04, 0x49, 0x00, 0x03, 0x01, 0x02, 0x03}, `{"type":1097,"link_opaque_attribute":"[1 2 3]"}`, false},
		{[]byte{0x04, 0x49, 0x00, 0x03, 0x01, 0x02, 0x03, 0x04}, `{"type":1097,"link_opaque_attribute":"[1 2 3]"}`, false},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", true},
	}

	for _, test := range tests {
		tlv := LsTLVOpaqueLinkAttr{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))
	}
}

func Test_LsTLVIGPFlags(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in        []byte
		want      string
		serialize bool
		err       bool
	}{
		{[]byte{0x04, 0x80, 0x00, 0x01, 0xFF}, `{"type":1152,"igp_flags":"{IGP Flags: XXXXPLND}"}`, true, false},
		{[]byte{0x04, 0x80, 0x00, 0x01, 0x80}, `{"type":1152,"igp_flags":"{IGP Flags: *******D}"}`, true, false},
		{[]byte{0x04, 0x80, 0x00, 0x01, 0x80, 0xAA}, `{"type":1152,"igp_flags":"{IGP Flags: *******D}"}`, false, false},
		{[]byte{0x04, 0x80, 0x00, 0x02, 0x80, 0x44}, "", false, true},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", false, true},
	}

	for _, test := range tests {
		tlv := LsTLVIGPFlags{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
			got, err := tlv.MarshalJSON()
			assert.NoError(err)
			assert.Equal(got, []byte(test.want))
			if test.serialize {
				got, err := tlv.Serialize()
				assert.NoError(err)
				assert.Equal(test.in, got)
			}
		}
	}
}

func Test_LsTLVOpaquePrefixAttr(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in   []byte
		want string
		err  bool
	}{
		{[]byte{0x04, 0x85, 0x00, 0x03, 0x01, 0x02, 0x03}, `{"type":1157,"prefix_opaque_attribute":"[1 2 3]"}`, false},
		{[]byte{0x04, 0x85, 0x00, 0x03, 0x01, 0x02, 0x03, 0x04}, `{"type":1157,"prefix_opaque_attribute":"[1 2 3]"}`, false},
		{[]byte{0xfe, 0xfe, 0x00, 0x00}, "", true},
	}

	for _, test := range tests {
		tlv := LsTLVOpaquePrefixAttr{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
			continue
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
		}

		got, err := tlv.MarshalJSON()
		assert.NoError(err)
		assert.Equal(got, []byte(test.want))
	}
}

func Test_parseIGPRouterID(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in     []byte
		str    string
		pseudo bool
	}{
		{[]byte{1, 2, 3, 4}, "1.2.3.4", false},
		{[]byte{1, 2, 3, 4, 5, 255}, "0102.0304.05ff", false},
		{[]byte{1, 2, 3, 4, 5, 255, 0}, "0102.0304.05ff-00", true},
		{[]byte{1, 2, 3, 4, 5, 6, 7, 8}, "1.2.3.4:5.6.7.8", true},
	}

	for _, test := range tests {
		str, pseudo := parseIGPRouterID(test.in)
		assert.Equal(test.str, str)
		assert.Equal(test.pseudo, pseudo)
	}
}

func Test_LsNodeDescriptor(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in        []byte
		str       string
		err       bool
		serialize bool
	}{
		{[]byte{
			0x01, 0x00, 0x00, 0x22, // Local Node Desc
			0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV ASN: 117901063
			0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV BGP LS ID: 117901063
			0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV OSPF Area ID: 117901063
			0x02, 0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // TLV IGP Router ID: 0102.0304.0506
		}, "{ASN: 117901063, BGP LS ID: 117901063, OSPF AREA: 117901063, IGP ROUTER ID: 0102.0304.0506}",
			false, true},
		{[]byte{
			0x01, 0x01, 0x00, 0x22, // Remote Node Desc
			0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV ASN: 117901063
			0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV BGP LS ID: 117901063
			0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV OSPF Area ID: 117901063
			0x02, 0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // TLV IGP Router ID: 0102.0304.0506
		}, "{ASN: 117901063, BGP LS ID: 117901063, OSPF AREA: 117901063, IGP ROUTER ID: 0102.0304.0506}",
			false, true},
		{[]byte{
			0x01, 0x00, 0x00, 0x21, // Truncated Length
			0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV ASN: 117901063
			0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV BGP LS ID: 117901063
			0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV OSPF Area ID: 117901063
			0x02, 0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // TLV IGP Router ID: 0102.0304.0506
		}, "", true, false},
		{[]byte{
			0x01, 0x00, 0x00, 0x22, // Missing mandatory TLV
			0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV ASN: 117901063
			0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV BGP LS ID: 117901063
			0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV OSPF Area ID: 117901063
		}, "", true, false},
		{[]byte{
			0x01, 0x00, 0x00, 0x22, // Incorrect TLV order
			0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV ASN: 117901063
			0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV OSPF Area ID: 117901063
			0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV BGP LS ID: 117901063
			0x02, 0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // TLV IGP Router ID: 0102.0304.0506
		}, "", true, false},
		{[]byte{
			0x01, 0x00, 0x00, 0x26, // Unexpected TLV
			0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV ASN: 117901063
			0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV BGP LS ID: 117901063
			0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV OSPF Area ID: 117901063
			0x02, 0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // TLV IGP Router ID: 0102.0304.0506
			0xfe, 0x01, 0x00, 0x00, // Unsupported
		}, "{ASN: 117901063, BGP LS ID: 117901063, OSPF AREA: 117901063, IGP ROUTER ID: 0102.0304.0506}",
			false, false},
		{[]byte{
			0x01, 0x00, 0x00, 0x0a, // Missing optional TLVs
			0x02, 0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // TLV IGP Router ID: 0102.0304.0506
		}, "{ASN: 0, BGP LS ID: 0, OSPF AREA: 0, IGP ROUTER ID: 0102.0304.0506}", false, true},
		{[]byte{
			0x01, 0x01, 0x00, 0x20, // Remote Node Desc
			0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV ASN: 117901063
			0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV BGP LS ID: 117901063
			0x02, 0x04, 0x00, 0x04, 0x0a, 0xff, 0x00, 0x01, // TLV BGP ROUTER ID: "10.255.0.1"
			0x02, 0x05, 0x00, 0x04, 0x07, 0x07, 0x07, 0x08, // TLV BGP CONFEDERATION MEMBER: 117901064
		}, "{ASN: 117901063, BGP LS ID: 117901063, BGP ROUTER ID: 10.255.0.1}",
			false, true},
	}

	for _, test := range tests {
		tlv := LsTLVNodeDescriptor{}
		if test.err {
			assert.Error(tlv.DecodeFromBytes(test.in))
		} else {
			assert.NoError(tlv.DecodeFromBytes(test.in))
			assert.Equal(test.str, tlv.String())
			if test.serialize {
				got, err := tlv.Serialize()
				assert.NoError(err)
				assert.Equal(test.in, got)
			}
		}
	}
}

func Test_LsAddrPrefix(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in        []byte
		str       string
		err       bool
		serialize bool
	}{
		{[]byte{
			0x00, 0x01, 0x00, 0x2f, // Node NLRI, correct length
			0x02,                                           // Protocol ISIS Level 2
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ID
			0x01, 0x00, 0x00, 0x22, // Local Node Desc
			0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV ASN: 117901063
			0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV BGP LS ID: 117901063
			0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV OSPF Area ID: 117901063
			0x02, 0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // TLV IGP Router ID: 0102.0304.0506
		}, "NLRI { NODE { AS:117901063 BGP-LS ID:117901063 0102.0304.0506 ISIS-L2:0 } }", false, true},
		{[]byte{
			0x00, 0x01, 0x00, 0x2e, // Node NLRI, truncated length
			0x02,                                           // Protocol ISIS Level 2
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ID
			0x01, 0x00, 0x00, 0x22, // Local Node Desc
			0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV ASN: 117901063
			0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV BGP LS ID: 117901063
			0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV OSPF Area ID: 117901063
			0x02, 0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, // TLV IGP Router ID: 0102.0304.05
		}, "", true, false},
		{[]byte{
			0x00, 0x01, 0x00, 0x2f, // Node NLRI, correct length
			0x02,                                           // Protocol ISIS Level 2
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ID
			0x01, 0x01, 0x00, 0x22, // Remote Node Desc (unexpected)
			0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV ASN: 117901063
			0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV BGP LS ID: 117901063
			0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV OSPF Area ID: 117901063
			0x02, 0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // TLV IGP Router ID: 0102.0304.0506
		}, "", true, false},
		{[]byte{
			0x00, 0x01, 0x00, 0x2d, // Node NLRI, correct length
			0x02,                                           // Protocol ISIS Level 2
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ID
			// Mandatory TLV missing
		}, "", true, false},
		{[]byte{
			0x00, 0x02, 0x00, 0x65, // Link NLRI, correct length
			0x02,                                           // Protocol ISIS Level 2
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ID
			0x01, 0x00, 0x00, 0x22, // Local Node Desc
			0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV ASN: 117901063
			0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV BGP LS ID: 117901063
			0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV OSPF Area ID: 117901063
			0x02, 0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // TLV IGP Router ID: 0102.0304.0506
			0x01, 0x01, 0x00, 0x22, // Remote Node Desc
			0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV ASN: 117901063
			0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV BGP LS ID: 117901063
			0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV OSPF Area ID: 117901063
			0x02, 0x03, 0x00, 0x06, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // TLV IGP Router ID: 0605.0403.0201
			0x01, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, // LinkID TLV, Local: 1, Remote: 2
		}, "NLRI { LINK { LOCAL_NODE: 0102.0304.0506 REMOTE_NODE: 0605.0403.0201 LINK: 1->2} }", false, true},
		{[]byte{
			0x00, 0x02, 0x00, 0x69, // Link NLRI, correct length
			0x02,                                           // Protocol ISIS Level 2
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ID
			0x01, 0x00, 0x00, 0x22, // Local Node Desc
			0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV ASN: 117901063
			0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV BGP LS ID: 117901063
			0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV OSPF Area ID: 117901063
			0x02, 0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // TLV IGP Router ID: 0102.0304.0506
			0x01, 0x01, 0x00, 0x22, // Remote Node Desc
			0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV ASN: 117901063
			0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV BGP LS ID: 117901063
			0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV OSPF Area ID: 117901063
			0x02, 0x03, 0x00, 0x06, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // TLV IGP Router ID: 0605.0403.0201
			0x01, 0x03, 0x00, 0x04, 0x01, 0x01, 0x01, 0x01, // IPv4 Interface Addr TLV: 1.1.1.1
			0x01, 0x04, 0x00, 0x04, 0x02, 0x02, 0x02, 0x02, // IPv4 Neighbor Addr TLV: 2.2.2.2
		}, "NLRI { LINK { LOCAL_NODE: 0102.0304.0506 REMOTE_NODE: 0605.0403.0201 LINK: 1.1.1.1->2.2.2.2} }", false, true},
		{[]byte{
			0x00, 0x02, 0x00, 0x81, // Link NLRI, correct length
			0x02,                                           // Protocol ISIS Level 2
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ID
			0x01, 0x00, 0x00, 0x22, // Local Node Desc
			0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV ASN: 117901063
			0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV BGP LS ID: 117901063
			0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV OSPF Area ID: 117901063
			0x02, 0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // TLV IGP Router ID: 0102.0304.0506
			0x01, 0x01, 0x00, 0x22, // Remote Node Desc
			0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV ASN: 117901063
			0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV BGP LS ID: 117901063
			0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV OSPF Area ID: 117901063
			0x02, 0x03, 0x00, 0x06, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // TLV IGP Router ID: 0605.0403.0201
			0x01, 0x05, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xEF, // IPv6 Interface Addr TLV: 2001:db8::beef
			0x01, 0x06, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, // IPv6 Interface Addr TLV: 2001:db8::dead
		}, "NLRI { LINK { LOCAL_NODE: 0102.0304.0506 REMOTE_NODE: 0605.0403.0201 LINK: 2001:db8::beef->2001:db8::dead} }", false, true},
		{[]byte{
			0x00, 0x02, 0x00, 0x59, // Link NLRI, correct length
			0x02,                                           // Protocol ISIS Level 2
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ID
			0x01, 0x00, 0x00, 0x22, // Local Node Desc
			0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV ASN: 117901063
			0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV BGP LS ID: 117901063
			0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV OSPF Area ID: 117901063
			0x02, 0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // TLV IGP Router ID: 0102.0304.0506
			0x01, 0x01, 0x00, 0x22, // Remote Node Desc
			0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV ASN: 117901063
			0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV BGP LS ID: 117901063
			0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV OSPF Area ID: 117901063
			0x02, 0x03, 0x00, 0x06, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // TLV IGP Router ID: 0605.0403.0201
		}, "NLRI { LINK { LOCAL_NODE: 0102.0304.0506 REMOTE_NODE: 0605.0403.0201 LINK: UNKNOWN} }", false, true},
		{[]byte{
			0x00, 0x02, 0x00, 0x33, // Link NLRI, correct length
			0x02,                                           // Protocol ISIS Level 2
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ID
			0x01, 0x00, 0x00, 0x22, // Local Node Desc
			0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV ASN: 117901063
			0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV BGP LS ID: 117901063
			0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV OSPF Area ID: 117901063
			0x02, 0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // TLV IGP Router ID: 0102.0304.0506
			// Missing mandatory TLV
		}, "", true, false},
		{[]byte{
			0x00, 0x03, 0x00, 0x35, // Prefix IPv4 NLRI, correct length
			0x02,                                           // Protocol ISIS Level 2
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ID
			0x01, 0x00, 0x00, 0x22, // Local Node Desc
			0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV ASN: 117901063
			0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV BGP LS ID: 117901063
			0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV OSPF Area ID: 117901063
			0x02, 0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // TLV IGP Router ID: 0102.0304.0506
			0x01, 0x09, 0x00, 0x02, 0x08, 0x0a, // IP ReachabilityInfo TLV, 10.0.0.0/8
		}, "NLRI { PREFIXv4 { LOCAL_NODE: 0102.0304.0506 PREFIX: [10.0.0.0/8] } }", false, true},
		{[]byte{
			0x00, 0x03, 0x00, 0x43, // Prefix IPv4 NLRI, correct length
			0x02,                                           // Protocol ISIS Level 2
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ID
			0x01, 0x00, 0x00, 0x22, // Local Node Desc
			0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV ASN: 117901063
			0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV BGP LS ID: 117901063
			0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV OSPF Area ID: 117901063
			0x02, 0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // TLV IGP Router ID: 0102.0304.0506
			0x01, 0x09, 0x00, 0x02, 0x08, 0x0a, // IP ReachabilityInfo TLV, 10.0.0.0/8
			0x01, 0x09, 0x00, 0x05, 0x1f, 0xc0, 0xa8, 0x07, 0xfe, // IP ReachabilityInfo TLV, 192.168.7.254/31
			0x01, 0x08, 0x00, 0x01, 0x06, // OSPF Route Type TLV (NSSA2)
		}, "NLRI { PREFIXv4 { LOCAL_NODE: 0102.0304.0506 PREFIX: [10.0.0.0/8 192.168.7.254/31] OSPF_ROUTE_TYPE:NSSA2 } }", false, true},
		{[]byte{
			0x00, 0x03, 0x00, 0x35, // Prefix IPv4 NLRI, correct length
			0x02,                                           // Protocol ISIS Level 2
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ID
			0x01, 0x00, 0x00, 0x22, // Local Node Desc
			0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV ASN: 117901063
			0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV BGP LS ID: 117901063
			0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV OSPF Area ID: 117901063
			0x02, 0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // TLV IGP Router ID: 0102.0304.0506
			0x01, 0x09, 0x00, 0x02, 0x08, 0x0a, // IP ReachabilityInfo TLV, 10.0.0.0/8
		}, "NLRI { PREFIXv4 { LOCAL_NODE: 0102.0304.0506 PREFIX: [10.0.0.0/8] } }", false, true},
		{[]byte{
			0x00, 0x03, 0x00, 0x2f, // Prefix IPv4 NLRI, correct length
			0x02,                                           // Protocol ISIS Level 2
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ID
			0x01, 0x00, 0x00, 0x22, // Local Node Desc
			0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV ASN: 117901063
			0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV BGP LS ID: 117901063
			0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV OSPF Area ID: 117901063
			0x02, 0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // TLV IGP Router ID: 0102.0304.0506
			// Missing mandatory TLV (IP Reachability info)
		}, "", true, false},
		{[]byte{
			0x00, 0x03, 0x00, 0x39, // Prefix IPv4 NLRI, correct length
			0x02,                                           // Protocol ISIS Level 2
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ID
			0x01, 0x00, 0x00, 0x22, // Local Node Desc
			0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV ASN: 117901063
			0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV BGP LS ID: 117901063
			0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV OSPF Area ID: 117901063
			0x02, 0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // TLV IGP Router ID: 0102.0304.0506
			// IPv6 IP Reachability info in v4 prefix
			0x01, 0x09, 0x00, 0x06, 0x40, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
		}, "", true, false},
		{[]byte{
			0x00, 0x04, 0x00, 0x35, // Prefix IPv6 NLRI, correct length
			0x02,                                           // Protocol ISIS Level 2
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ID
			0x01, 0x00, 0x00, 0x22, // Local Node Desc
			0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV ASN: 117901063
			0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV BGP LS ID: 117901063
			0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV OSPF Area ID: 117901063
			0x02, 0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // TLV IGP Router ID: 0102.0304.0506
			0x01, 0x09, 0x00, 0x02, 0x08, 0x0a, // IP ReachabilityInfo TLV, 10.0.0.0/8
		}, "NLRI { PREFIXv6 { LOCAL_NODE: 0102.0304.0506 PREFIX: [a00::/8] } }", false, true},
		{[]byte{
			0x00, 0x04, 0x00, 0x43, // Prefix IPv6 NLRI, correct length
			0x02,                                           // Protocol ISIS Level 2
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ID
			0x01, 0x00, 0x00, 0x22, // Local Node Desc
			0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV ASN: 117901063
			0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV BGP LS ID: 117901063
			0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV OSPF Area ID: 117901063
			0x02, 0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // TLV IGP Router ID: 0102.0304.0506
			0x01, 0x09, 0x00, 0x02, 0x08, 0x0a, // IP ReachabilityInfo TLV, 10.0.0.0/8
			0x01, 0x09, 0x00, 0x05, 0x1f, 0xc0, 0xa8, 0x07, 0xfe, // IP ReachabilityInfo TLV, 192.168.7.254/31
			0x01, 0x08, 0x00, 0x01, 0x06, // OSPF Route Type TLV (NSSA2)
		}, "NLRI { PREFIXv6 { LOCAL_NODE: 0102.0304.0506 PREFIX: [a00::/8 c0a8:7fe::/31] OSPF_ROUTE_TYPE:NSSA2 } }", false, true},
		{[]byte{
			0x00, 0x04, 0x00, 0x35, // Prefix IPv6 NLRI, correct length
			0x02,                                           // Protocol ISIS Level 2
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ID
			0x01, 0x00, 0x00, 0x22, // Local Node Desc
			0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV ASN: 117901063
			0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV BGP LS ID: 117901063
			0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV OSPF Area ID: 117901063
			0x02, 0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // TLV IGP Router ID: 0102.0304.0506
			0x01, 0x09, 0x00, 0x02, 0x08, 0x0a, // IP ReachabilityInfo TLV, 10.0.0.0/8
		}, "NLRI { PREFIXv6 { LOCAL_NODE: 0102.0304.0506 PREFIX: [a00::/8] } }", false, true},
		{[]byte{
			0x00, 0x04, 0x00, 0x2f, // Prefix IPv6 NLRI, correct length
			0x02,                                           // Protocol ISIS Level 2
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ID
			0x01, 0x00, 0x00, 0x22, // Local Node Desc
			0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV ASN: 117901063
			0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV BGP LS ID: 117901063
			0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV OSPF Area ID: 117901063
			0x02, 0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // TLV IGP Router ID: 0102.0304.0506
			// Missing mandatory TLV (IP Reachability info)
		}, "", true, false},
		{[]byte{
			0x00, 0x04, 0x00, 0x39, // Prefix IPv6 NLRI, correct length
			0x02,                                           // Protocol ISIS Level 2
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ID
			0x01, 0x00, 0x00, 0x22, // Local Node Desc
			0x02, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV ASN: 117901063
			0x02, 0x01, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV BGP LS ID: 117901063
			0x02, 0x02, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TLV OSPF Area ID: 117901063
			0x02, 0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // TLV IGP Router ID: 0102.0304.0506
			// IPv6 IP Reachability info in v4 prefix
			0x01, 0x09, 0x00, 0x06, 0x40, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
		}, "", true, false},
	}

	for _, test := range tests {
		nlri := LsAddrPrefix{}
		if test.err {
			assert.Error(nlri.DecodeFromBytes(test.in))
		} else {
			assert.NoError(nlri.DecodeFromBytes(test.in))
			assert.Equal(test.str, nlri.String())
			if test.serialize {
				got, err := nlri.Serialize()
				assert.NoError(err)
				assert.Equal(test.in, got)
			}
		}
	}
}

func Test_PathAttributeLs(t *testing.T) {
	assert := assert.New(t)

	var tests = []struct {
		in        []byte
		str       string
		json      string
		serialize bool
		err       bool
	}{
		{[]byte{
			// LS Attribute with all Node-related TLVs.
			0x80, 0x29, 0x62, // Optional attribute, BGP_ATTR_TYPE_LS, correct length
			0x04, 0x00, 0x00, 0x01, 0xFF, // Node flags (all set)
			0x04, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03, // Opaque Node Attr [1 2 3]
			0x04, 0x02, 0x00, 0x03, 0x72, 0x74, 0x72, // Node name: "rtr"
			0x04, 0x03, 0x00, 0x03, 0x72, 0x74, 0x72, // ISIS area: [114 116 114]
			0x04, 0x04, 0x00, 0x04, 0x01, 0x01, 0x01, 0x01, // Local RouterID 1.1.1.1
			0x04, 0x05, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xEF, // Local Router ID 2001:db8::beef
			0x04, 0x0a, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x88, 0xb8, 0x04, 0x89, 0x00, 0x03, 0x01, 0x88, 0x94, // Capabilities: Range 35000, first label: 100500
			0x04, 0x0b, 0x00, 0x03, 0x01, 0x02, 0x03, // SR ALgorithm [1 2 3]
			0x04, 0x0c, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x88, 0xb8, 0x04, 0x89, 0x00, 0x03, 0x01, 0x88, 0x94, // Local block: Range 35000, first label: 100500
			0xde, 0xad, 0x00, 0x01, 0xFF, // Unknown TLV
		},
			"{LsAttributes: {Node Flags: XXVRBETO} {Opaque attribute: [1 2 3]} {Node Name: rtr} {ISIS Area ID: [114 116 114]} {Local RouterID IPv4: 1.1.1.1} {Local RouterID IPv6: 2001:db8::beef} {SR Capabilities: Flags:0 SRGB Ranges: 100500:135500 } {SR Algorithms: [1 2 3]} {SR LocalBlock: Flags:0 SRGB Ranges: 100500:135500 } }",
			`{"type":41,"flags":128,"node":{"flags":{"overload":true,"attached":true,"external":true,"abr":true,"router":true,"v6":true},"opaque":"AQID","name":"rtr","isis_area":"cnRy","local_router_id_ipv4":"1.1.1.1","local_router_id_ipv6":"2001:db8::beef","sr_capabilities":{"ipv4_supported":false,"ipv6_supported":false,"ranges":[{"begin":100500,"end":135500}]},"sr_algorithms":"AQID","sr_local_block":{"ranges":[{"begin":100500,"end":135500}]}},"link":{"local_router_id_ipv4":"1.1.1.1","local_router_id_ipv6":"2001:db8::beef"},"prefix":{},"bgp_peer_segment":{}}`,
			false, false},
		{[]byte{
			// LS Attribute with all Node-related TLVs.
			0x80, 0x29, 0x5d, // Optional attribute, BGP_ATTR_TYPE_LS, correct length
			0x04, 0x00, 0x00, 0x01, 0xFF, // Node flags (all set)
			0x04, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03, // Opaque Node Attr [1 2 3]
			0x04, 0x02, 0x00, 0x03, 0x72, 0x74, 0x72, // Node name: "rtr"
			0x04, 0x03, 0x00, 0x03, 0x72, 0x74, 0x72, // ISIS area: [114 116 114]
			0x04, 0x04, 0x00, 0x04, 0x01, 0x01, 0x01, 0x01, // Local RouterID 1.1.1.1
			0x04, 0x05, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xEF, // Local Router ID 2001:db8::beef
			0x04, 0x0a, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x88, 0xb8, 0x04, 0x89, 0x00, 0x03, 0x01, 0x88, 0x94, // Capabilities: Range 35000, first label: 100500
			0x04, 0x0b, 0x00, 0x03, 0x01, 0x02, 0x03, // SR Algorithm [1 2 3]
			0x04, 0x0c, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x88, 0xb8, 0x04, 0x89, 0x00, 0x03, 0x01, 0x88, 0x94, // Local block: Range 35000, first label: 100500
		},
			"{LsAttributes: {Node Flags: XXVRBETO} {Opaque attribute: [1 2 3]} {Node Name: rtr} {ISIS Area ID: [114 116 114]} {Local RouterID IPv4: 1.1.1.1} {Local RouterID IPv6: 2001:db8::beef} {SR Capabilities: Flags:0 SRGB Ranges: 100500:135500 } {SR Algorithms: [1 2 3]} {SR LocalBlock: Flags:0 SRGB Ranges: 100500:135500 } }",
			`{"type":41,"flags":128,"node":{"flags":{"overload":true,"attached":true,"external":true,"abr":true,"router":true,"v6":true},"opaque":"AQID","name":"rtr","isis_area":"cnRy","local_router_id_ipv4":"1.1.1.1","local_router_id_ipv6":"2001:db8::beef","sr_capabilities":{"ipv4_supported":false,"ipv6_supported":false,"ranges":[{"begin":100500,"end":135500}]},"sr_algorithms":"AQID","sr_local_block":{"ranges":[{"begin":100500,"end":135500}]}},"link":{"local_router_id_ipv4":"1.1.1.1","local_router_id_ipv6":"2001:db8::beef"},"prefix":{},"bgp_peer_segment":{}}`,
			true, false},
		{[]byte{
			// LS Attribute with truncated length
			0x80, 0x29, 0x04, // Optional attribute, BGP_ATTR_TYPE_LS, truncated length
			0x04, 0x00, 0x00, 0x01, 0xFF, // Node flags (all set)
		}, "", "", false, true},
		{[]byte{
			// LS Attribute with all Link-related TLVs.
			0x80, 0x29, 0x9a, // Optional attribute, BGP_ATTR_TYPE_LS, correct length
			0x04, 0x04, 0x00, 0x04, 0x01, 0x01, 0x01, 0x01, // Local RouterID 1.1.1.1
			0x04, 0x05, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xEF, // Local Router ID 2001:db8::beef
			0x04, 0x06, 0x00, 0x04, 0x02, 0x02, 0x02, 0x02, // Local RouterID 2.2.2.2
			0x04, 0x07, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, // Local Router ID 2001:db8::dead
			0x04, 0x40, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // Admin Group 0x07070707
			0x04, 0x41, 0x00, 0x04, 0x43, 0xA4, 0xB2, 0x00, // Max Link Bandwidth 329.39062
			0x04, 0x42, 0x00, 0x04, 0x43, 0xA4, 0xB2, 0x00, // Max Reservable Bandwidth 329.39062
			0x04, 0x43, 0x00, 0x20, 0x43, 0xA4, 0xB2, 0x00, 0x43, 0xA4, 0xB2, 0x00, 0x43, 0xA4, 0xB2, 0x00, 0x43, 0xA4, 0xB2, 0x00, 0x43, 0xA4, 0xB2, 0x00, 0x43, 0xA4, 0xB2, 0x00, 0x43, 0xA4, 0xB2, 0x00, 0x43, 0xA4, 0xB2, 0x00, // Unreserved Bandwidth 329.39062
			0x04, 0x44, 0x00, 0x04, 0x07, 0x07, 0x07, 0x07, // TE Default Metric: 117901063
			0x04, 0x47, 0x00, 0x01, 0x01, // IGP Metric 1
			0x04, 0x49, 0x00, 0x03, 0x01, 0x02, 0x03, // Opaque Link Attr: [1 2 3]
			0x04, 0x4a, 0x00, 0x03, 0x72, 0x74, 0x72, // Link Name: "rtr"
			0x04, 0x4b, 0x00, 0x07, 0x01, 0x01, 0x00, 0x00, 0x01, 0x88, 0x94, // Adjacency SID: 100500
		},
			"{LsAttributes: {Local RouterID IPv4: 1.1.1.1} {Local RouterID IPv6: 2001:db8::beef} {Remote RouterID IPv4: 2.2.2.2} {Remote RouterID IPv6: 2001:db8::dead} {Admin Group: 07070707} {Max Link BW: 329.39062} {Max Reservable Link BW: 329.39062} {Unreserved BW: [329.39062 329.39062 329.39062 329.39062 329.39062 329.39062 329.39062 329.39062]} {TE Default metric: 117901063} {IGP metric: 1} {Opaque link attribute: [1 2 3]} {Link Name: rtr} {Adjacency SID: 100500} }",
			`{"type":41,"flags":128,"node":{"local_router_id_ipv4":"1.1.1.1","local_router_id_ipv6":"2001:db8::beef"},"link":{"name":"rtr","local_router_id_ipv4":"1.1.1.1","local_router_id_ipv6":"2001:db8::beef","remote_router_id_ipv4":"2.2.2.2","remote_router_id_ipv6":"2001:db8::dead","admin_group":117901063,"default_te_metric":117901063,"igp_metric":1,"opaque":"AQID","bandwidth":329.39062,"reservable_bandwidth":329.39062,"unreserved_bandwidth":[329.39062,329.39062,329.39062,329.39062,329.39062,329.39062,329.39062,329.39062],"adjacency_sid":100500},"prefix":{},"bgp_peer_segment":{}}`,
			true, false},
		{[]byte{
			// LS Attribute with all Link-related TLVs.
			0x80, 0x29, 0x17, // Optional attribute, BGP_ATTR_TYPE_LS, correct length
			0x04, 0x80, 0x00, 0x01, 0xFF, // IGP Flags: PLND
			0x04, 0x85, 0x00, 0x03, 0x01, 0x02, 0x03, // Opaque prefix: [1 2 3]
			0x04, 0x86, 0x00, 0x07, 0x01, 0x01, 0x00, 0x00, 0x01, 0x88, 0x94, // Prefix SID: 100500
		},
			"{LsAttributes: {IGP Flags: XXXXPLND} {Prefix opaque attribute: [1 2 3]} {Prefix SID: 100500} }",
			`{"type":41,"flags":128,"node":{},"link":{},"prefix":{"igp_flags":{"down":true,"no_unicast":true,"local_address":true,"propagate_nssa":true},"opaque":"AQID","sr_prefix_sid":100500},"bgp_peer_segment":{}}`,
			true, false},
	}

	for _, test := range tests {
		attr := PathAttributeLs{}
		if test.err {
			assert.Error(attr.DecodeFromBytes(test.in))
		} else {
			assert.NoError(attr.DecodeFromBytes(test.in))
			got, err := attr.MarshalJSON()
			assert.NoError(err)
			assert.Equal(test.json, string(got))
			assert.Equal(test.str, attr.String())

			if test.serialize {
				got, err := attr.Serialize()
				assert.NoError(err)
				assert.Equal(test.in, got)
			}
		}
	}
}

func Test_BGPOpenDecodeCapabilities(t *testing.T) {
	// BGP OPEN message with add-path and long-lived-graceful-restart capabilities,
	// in that order.
	openBytes := []byte{
		0x04,       // version: 4
		0xfa, 0x7b, // my as: 64123
		0x00, 0xf0, // hold time: 240 seconds
		0x7f, 0x00, 0x00, 0x02, // BGP identifier: 127.0.0.2
		0x19, // optional parameters length: 25
		0x02, // parameter type: capability
		0x17, // parameter length: 23

		0x05,       // capability type: extended next hop
		0x06,       // caability length: 6
		0x00, 0x01, // AFI: IPv4
		0x00, 0x01, // SAFI: unicast
		0x00, 0x02, // next hop AFI: IPv6

		0x45,       // capability type: ADD-PATH
		0x04,       // capability length: 4
		0x00, 0x01, // AFI: IPv4
		0x01, // SAFI: unicast
		0x02, // Send/Receive: Send

		0x47, // capability type: Long-lived-graceful-restart
		0x07, // capability length: 7
		0x00, 0x01, 0x01, 0x00, 0x00, 0x0e, 0x10,
	}

	open := &BGPOpen{}
	err := open.DecodeFromBytes(openBytes)
	assert.NoError(t, err)

	capMap := make(map[BGPCapabilityCode][]ParameterCapabilityInterface)
	for _, p := range open.OptParams {
		if paramCap, y := p.(*OptionParameterCapability); y {
			t.Logf("parameter capability: %+v", paramCap)
			for _, c := range paramCap.Capability {
				m, ok := capMap[c.Code()]
				if !ok {
					m = make([]ParameterCapabilityInterface, 0, 1)
				}
				capMap[c.Code()] = append(m, c)
			}
		}
	}

	assert.Len(t, capMap[BGP_CAP_EXTENDED_NEXTHOP], 1)
	nexthopTuples := capMap[BGP_CAP_EXTENDED_NEXTHOP][0].(*CapExtendedNexthop).Tuples
	assert.Len(t, nexthopTuples, 1)
	assert.Equal(t, nexthopTuples[0].NLRIAFI, uint16(AFI_IP))
	assert.Equal(t, nexthopTuples[0].NLRISAFI, uint16(SAFI_UNICAST))
	assert.Equal(t, nexthopTuples[0].NexthopAFI, uint16(AFI_IP6))

	assert.Len(t, capMap[BGP_CAP_ADD_PATH], 1)
	tuples := capMap[BGP_CAP_ADD_PATH][0].(*CapAddPath).Tuples
	assert.Len(t, tuples, 1)
	assert.Equal(t, tuples[0].RouteFamily, RF_IPv4_UC)
	assert.Equal(t, tuples[0].Mode, BGP_ADD_PATH_SEND)
}

func FuzzParseBGPMessage(f *testing.F) {

	f.Fuzz(func(t *testing.T, data []byte) {
		ParseBGPMessage(data)
	})
}

func FuzzParseFlowSpecComponents(f *testing.F) {

	f.Fuzz(func(t *testing.T, data string) {
		ParseFlowSpecComponents(RF_FS_IPv4_UC, data)
	})
}
