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
	"github.com/stretchr/testify/assert"
	"net"
	"reflect"
	"testing"
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

func Test_Message(t *testing.T) {
	l := []*BGPMessage{keepalive(), notification(), refresh(), NewTestBGPOpenMessage(), NewTestBGPUpdateMessage()}
	for _, m1 := range l {
		buf1, _ := m1.Serialize()
		t.Log("LEN =", len(buf1))
		m2, err := ParseBGPMessage(buf1)
		if err != nil {
			t.Error(err)
		}
		// FIXME: shouldn't but workaround for some structs.
		buf2, _ := m2.Serialize()

		if reflect.DeepEqual(m1, m2) == true {
			t.Log("OK")
		} else {
			t.Error("Something wrong")
			t.Error(len(buf1), m1, buf1)
			t.Error(len(buf2), m2, buf2)
		}
	}
}

func Test_IPAddrPrefixString(t *testing.T) {
	ipv4 := NewIPAddrPrefix(24, "129.6.10.0")
	assert.Equal(t, "129.6.10.0/24", ipv4.String())
	ipv6 := NewIPv6AddrPrefix(18, "3343:faba:3903::1")
	assert.Equal(t, "3343:faba:3903::1/18", ipv6.String())
	ipv6 = NewIPv6AddrPrefix(18, "3343:faba:3903::0")
	assert.Equal(t, "3343:faba:3903::/18", ipv6.String())
}

func Test_RouteTargetMembershipNLRIString(t *testing.T) {
	assert := assert.New(t)

	// TwoOctetAsSpecificExtended
	buf := make([]byte, 13)
	buf[0] = 12
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

	subTlv := &TunnelEncapSubTLV{
		Type:  ENCAP_SUBTLV_TYPE_COLOR,
		Value: &TunnelEncapSubTLVColor{10},
	}

	tlv := &TunnelEncapTLV{
		Type:  TUNNEL_TYPE_VXLAN,
		Value: []*TunnelEncapSubTLV{subTlv},
	}

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
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_PKT_LEN, []*FlowSpecComponentItem{item2, item3, item4}))
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_DSCP, []*FlowSpecComponentItem{item2, item3, item4}))
	isFlagment := 0x02
	item5 := NewFlowSpecComponentItem(isFlagment, 0)
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_FRAGMENT, []*FlowSpecComponentItem{item5}))
	item6 := NewFlowSpecComponentItem(0, TCP_FLAG_ACK)
	item7 := NewFlowSpecComponentItem(and|not, TCP_FLAG_URGENT)
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_TCP_FLAG, []*FlowSpecComponentItem{item6, item7}))
	n1 := NewFlowSpecIPv4Unicast(cmp)
	buf1, err := n1.Serialize()
	assert.Nil(err)
	n2, err := NewPrefixFromRouteFamily(RouteFamilyToAfiSafi(RF_FS_IPv4_UC))
	assert.Nil(err)
	err = n2.DecodeFromBytes(buf1)
	assert.Nil(err)
	buf2, _ := n2.Serialize()
	if reflect.DeepEqual(n1, n2) == true {
		t.Log("OK")
	} else {
		t.Error("Something wrong")
		t.Error(len(buf1), n1, buf1)
		t.Error(len(buf2), n2, buf2)
		t.Log(bytes.Equal(buf1, buf2))
	}
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
	assert.Nil(err)
	m2 := NewPathAttributeExtendedCommunities(nil)
	err = m2.DecodeFromBytes(buf1)
	assert.Nil(err)
	buf2, _ := m2.Serialize()
	if reflect.DeepEqual(m1, m2) == true {
		t.Log("OK")
	} else {
		t.Error("Something wrong")
		t.Error(len(buf1), m1, buf1)
		t.Error(len(buf2), m2, buf2)
	}
}

func Test_FlowSpecNlriv6(t *testing.T) {
	assert := assert.New(t)
	cmp := make([]FlowSpecComponentInterface, 0)
	cmp = append(cmp, NewFlowSpecDestinationPrefix6(NewIPv6AddrPrefix(64, "2001::"), 12))
	cmp = append(cmp, NewFlowSpecSourcePrefix6(NewIPv6AddrPrefix(64, "2001::"), 12))
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
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_PKT_LEN, []*FlowSpecComponentItem{item2, item3, item4}))
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_DSCP, []*FlowSpecComponentItem{item2, item3, item4}))
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_LABEL, []*FlowSpecComponentItem{item2, item3, item4}))
	isFlagment := 0x02
	item5 := NewFlowSpecComponentItem(isFlagment, 0)
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_FRAGMENT, []*FlowSpecComponentItem{item5}))
	item6 := NewFlowSpecComponentItem(0, TCP_FLAG_ACK)
	item7 := NewFlowSpecComponentItem(and|not, TCP_FLAG_URGENT)
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_TCP_FLAG, []*FlowSpecComponentItem{item6, item7}))
	n1 := NewFlowSpecIPv6Unicast(cmp)
	buf1, err := n1.Serialize()
	assert.Nil(err)
	n2, err := NewPrefixFromRouteFamily(RouteFamilyToAfiSafi(RF_FS_IPv6_UC))
	assert.Nil(err)
	err = n2.DecodeFromBytes(buf1)
	assert.Nil(err)
	buf2, _ := n2.Serialize()
	if reflect.DeepEqual(n1, n2) == true {
		t.Log("OK")
	} else {
		t.Error("Something wrong")
		t.Error(len(buf1), n1, buf1)
		t.Error(len(buf2), n2, buf2)
		t.Log(bytes.Equal(buf1, buf2))
	}
}

func Test_Aigp(t *testing.T) {
	assert := assert.New(t)
	m := NewAigpTLVIgpMetric(1000)
	a1 := NewPathAttributeAigp([]AigpTLV{m})
	buf1, err := a1.Serialize()
	assert.Nil(err)
	a2 := NewPathAttributeAigp(nil)
	err = a2.DecodeFromBytes(buf1)
	assert.Nil(err)
	buf2, _ := a2.Serialize()
	if reflect.DeepEqual(a1, a2) == true {
		t.Log("OK")
	} else {
		t.Error("Something wrong")
		t.Error(len(buf1), a1, buf1)
		t.Error(len(buf2), a2, buf2)
		t.Log(bytes.Equal(buf1, buf2))
	}
}

func Test_FlowSpecNlriL2(t *testing.T) {
	assert := assert.New(t)
	mac, _ := net.ParseMAC("01:23:45:67:89:ab")
	cmp := make([]FlowSpecComponentInterface, 0)
	cmp = append(cmp, NewFlowSpecDestinationMac(mac))
	cmp = append(cmp, NewFlowSpecSourceMac(mac))
	eq := 0x1
	item1 := NewFlowSpecComponentItem(eq, int(IPv4))
	cmp = append(cmp, NewFlowSpecComponent(FLOW_SPEC_TYPE_ETHERNET_TYPE, []*FlowSpecComponentItem{item1}))
	n1 := NewFlowSpecL2VPN(cmp)
	buf1, err := n1.Serialize()
	assert.Nil(err)
	n2, err := NewPrefixFromRouteFamily(RouteFamilyToAfiSafi(RF_FS_L2_VPN))
	assert.Nil(err)
	err = n2.DecodeFromBytes(buf1)
	assert.Nil(err)
	buf2, _ := n2.Serialize()
	if reflect.DeepEqual(n1, n2) == true {
		t.Log("OK")
	} else {
		t.Error("Something wrong")
		t.Error(len(buf1), n1, buf1)
		t.Error(len(buf2), n2, buf2)
		t.Log(bytes.Equal(buf1, buf2))
	}
}
