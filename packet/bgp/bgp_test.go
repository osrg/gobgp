package bgp

import (
	"bytes"
	"encoding/binary"
	"fmt"
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

func open() *BGPMessage {
	p1 := NewOptionParameterCapability(
		[]ParameterCapabilityInterface{NewCapRouteRefresh()})
	p2 := NewOptionParameterCapability(
		[]ParameterCapabilityInterface{NewCapMultiProtocol(RF_IPv4_UC)})
	g := &CapGracefulRestartTuple{4, 2, 3}
	p3 := NewOptionParameterCapability(
		[]ParameterCapabilityInterface{NewCapGracefulRestart(false, 100,
			[]*CapGracefulRestartTuple{g})})
	p4 := NewOptionParameterCapability(
		[]ParameterCapabilityInterface{NewCapFourOctetASNumber(100000)})
	p5 := NewOptionParameterCapability(
		[]ParameterCapabilityInterface{NewCapAddPath(RF_IPv4_UC, BGP_ADD_PATH_BOTH)})
	return NewBGPOpenMessage(11033, 303, "100.4.10.3",
		[]OptionParameterInterface{p1, p2, p3, p4, p5})
}

func update() *BGPMessage {
	w1 := NewIPAddrPrefix(23, "121.1.3.2")
	w2 := NewIPAddrPrefix(17, "100.33.3.0")
	w := []*IPAddrPrefix{w1, w2}

	aspath1 := []AsPathParamInterface{
		NewAsPathParam(2, []uint16{1000}),
		NewAsPathParam(1, []uint16{1001, 1002}),
		NewAsPathParam(2, []uint16{1003, 1004}),
	}

	aspath2 := []AsPathParamInterface{
		NewAs4PathParam(2, []uint32{1000000}),
		NewAs4PathParam(1, []uint32{1000001, 1002}),
		NewAs4PathParam(2, []uint32{1003, 100004}),
	}

	aspath3 := []*As4PathParam{
		NewAs4PathParam(2, []uint32{1000000}),
		NewAs4PathParam(1, []uint32{1000001, 1002}),
		NewAs4PathParam(2, []uint32{1003, 100004}),
	}

	isTransitive := true

	ecommunities := []ExtendedCommunityInterface{
		NewTwoOctetAsSpecificExtended(EC_SUBTYPE_ROUTE_TARGET, 10003, 3<<20, isTransitive),
		NewFourOctetAsSpecificExtended(EC_SUBTYPE_ROUTE_TARGET, 1<<20, 300, isTransitive),
		NewIPv4AddressSpecificExtended(EC_SUBTYPE_ROUTE_TARGET, "192.2.1.2", 3000, isTransitive),
		&OpaqueExtended{
			Value: &DefaultOpaqueExtendedValue{[]byte{255, 1, 2, 3, 4, 5, 6, 7}},
		},
		&OpaqueExtended{
			Value: &ValidationExtended{Value: VALIDATION_STATE_INVALID},
		},
		&UnknownExtended{Type: 99, Value: []byte{0, 1, 2, 3, 4, 5, 6, 7}},
		NewESILabelExtended(1000, true),
		NewESImportRouteTarget("11:22:33:44:55:66"),
		NewMacMobilityExtended(123, false),
	}

	mp_nlri := []AddrPrefixInterface{
		NewLabeledVPNIPAddrPrefix(20, "192.0.9.0", *NewMPLSLabelStack(1, 2, 3),
			NewRouteDistinguisherTwoOctetAS(256, 10000)),
		NewLabeledVPNIPAddrPrefix(26, "192.10.8.192", *NewMPLSLabelStack(5, 6, 7, 8),
			NewRouteDistinguisherIPAddressAS("10.0.1.1", 10001)),
	}

	mp_nlri2 := []AddrPrefixInterface{NewIPv6AddrPrefix(100,
		"fe80:1234:1234:5667:8967:af12:8912:1023")}

	mp_nlri3 := []AddrPrefixInterface{NewLabeledVPNIPv6AddrPrefix(100,
		"fe80:1234:1234:5667:8967:af12:1203:33a1", *NewMPLSLabelStack(5, 6),
		NewRouteDistinguisherFourOctetAS(5, 6))}

	mp_nlri4 := []AddrPrefixInterface{NewLabeledIPAddrPrefix(25, "192.168.0.0",
		*NewMPLSLabelStack(5, 6, 7))}

	mac, _ := net.ParseMAC("01:23:45:67:89:ab")
	mp_nlri5 := []AddrPrefixInterface{
		NewEVPNNLRI(EVPN_ROUTE_TYPE_ETHERNET_AUTO_DISCOVERY, 0,
			&EVPNEthernetAutoDiscoveryRoute{NewRouteDistinguisherFourOctetAS(5, 6),
				EthernetSegmentIdentifier{ESI_ARBITRARY, make([]byte, 9)}, 2, 2}),
		NewEVPNNLRI(EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT, 0,
			&EVPNMacIPAdvertisementRoute{NewRouteDistinguisherFourOctetAS(5, 6),
				EthernetSegmentIdentifier{ESI_ARBITRARY, make([]byte, 9)}, 3, 48,
				mac, 32, net.ParseIP("192.2.1.2"),
				[]uint32{3, 4}}),
		NewEVPNNLRI(EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG, 0,
			&EVPNMulticastEthernetTagRoute{NewRouteDistinguisherFourOctetAS(5, 6), 3, 32, net.ParseIP("192.2.1.2")}),
		NewEVPNNLRI(EVPN_ETHERNET_SEGMENT_ROUTE, 0,
			&EVPNEthernetSegmentRoute{NewRouteDistinguisherFourOctetAS(5, 6),
				EthernetSegmentIdentifier{ESI_ARBITRARY, make([]byte, 9)},
				32, net.ParseIP("192.2.1.1")}),
	}

	p := []PathAttributeInterface{
		NewPathAttributeOrigin(3),
		NewPathAttributeAsPath(aspath1),
		NewPathAttributeAsPath(aspath2),
		NewPathAttributeNextHop("129.1.1.2"),
		NewPathAttributeMultiExitDisc(1 << 20),
		NewPathAttributeLocalPref(1 << 22),
		NewPathAttributeAtomicAggregate(),
		NewPathAttributeAggregator(uint16(30002), "129.0.2.99"),
		NewPathAttributeAggregator(uint32(30002), "129.0.2.99"),
		NewPathAttributeAggregator(uint32(300020), "129.0.2.99"),
		NewPathAttributeCommunities([]uint32{1, 3}),
		NewPathAttributeOriginatorId("10.10.0.1"),
		NewPathAttributeClusterList([]string{"10.10.0.2", "10.10.0.3"}),
		NewPathAttributeExtendedCommunities(ecommunities),
		NewPathAttributeAs4Path(aspath3),
		NewPathAttributeAs4Aggregator(10000, "112.22.2.1"),
		NewPathAttributeMpReachNLRI("112.22.2.0", mp_nlri),
		NewPathAttributeMpReachNLRI("1023::", mp_nlri2),
		NewPathAttributeMpReachNLRI("fe80::", mp_nlri3),
		NewPathAttributeMpReachNLRI("129.1.1.1", mp_nlri4),
		NewPathAttributeMpReachNLRI("129.1.1.1", mp_nlri5),
		NewPathAttributeMpUnreachNLRI(mp_nlri),
		//NewPathAttributeMpReachNLRI("112.22.2.0", []AddrPrefixInterface{}),
		//NewPathAttributeMpUnreachNLRI([]AddrPrefixInterface{}),
		&PathAttributeUnknown{
			PathAttribute: PathAttribute{
				Flags: BGP_ATTR_FLAG_TRANSITIVE,
				Type:  100,
				Value: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
			},
		},
	}
	n := []*IPAddrPrefix{NewIPAddrPrefix(24, "13.2.3.1")}
	return NewBGPUpdateMessage(w, p, n)
}

func Test_Message(t *testing.T) {
	l := []*BGPMessage{keepalive(), notification(), refresh(), open(), update()}
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

	n1 = NewEncapNLRI("2001::1")
	buf1, err = n1.Serialize()
	assert.Equal(nil, err)

	n2 = NewEncapNLRI("")
	err = n2.DecodeFromBytes(buf1)
	assert.Equal(nil, err)
	assert.Equal("2001::1", n2.String())
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
	fmt.Println(n1, n2)
}
