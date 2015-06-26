package bgp

import (
	"bytes"
	"encoding/binary"
	"github.com/stretchr/testify/assert"
	"net"
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
		[]ParameterCapabilityInterface{NewCapMultiProtocol(3, 4)})
	g := CapGracefulRestartTuples{4, 2, 3}
	p3 := NewOptionParameterCapability(
		[]ParameterCapabilityInterface{NewCapGracefulRestart(2, 100,
			[]CapGracefulRestartTuples{g})})
	p4 := NewOptionParameterCapability(
		[]ParameterCapabilityInterface{NewCapFourOctetASNumber(100000)})
	return NewBGPOpenMessage(11033, 303, "100.4.10.3",
		[]OptionParameterInterface{p1, p2, p3, p4})
}

func update() *BGPMessage {
	w1 := WithdrawnRoute{*NewIPAddrPrefix(23, "121.1.3.2")}
	w2 := WithdrawnRoute{*NewIPAddrPrefix(17, "100.33.3.0")}
	w := []WithdrawnRoute{w1, w2}

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

	ecommunities := []ExtendedCommunityInterface{
		&TwoOctetAsSpecificExtended{SubType: 1, AS: 10003, LocalAdmin: 3 << 20},
		&FourOctetAsSpecificExtended{SubType: 2, AS: 1 << 20, LocalAdmin: 300},
		&IPv4AddressSpecificExtended{SubType: 3, IPv4: net.ParseIP("192.2.1.2").To4(), LocalAdmin: 3000},
		&OpaqueExtended{
			Value: &DefaultOpaqueExtendedValue{[]byte{0, 1, 2, 3, 4, 5, 6, 7}},
		},
		&UnknownExtended{Type: 99, Value: []byte{0, 1, 2, 3, 4, 5, 6, 7}},
	}

	mp_nlri := []AddrPrefixInterface{
		NewLabelledVPNIPAddrPrefix(20, "192.0.9.0", *NewMPLSLabelStack(1, 2, 3),
			NewRouteDistinguisherTwoOctetAS(256, 10000)),
		NewLabelledVPNIPAddrPrefix(26, "192.10.8.192", *NewMPLSLabelStack(5, 6, 7, 8),
			NewRouteDistinguisherIPAddressAS("10.0.1.1", 10001)),
	}

	mp_nlri2 := []AddrPrefixInterface{NewIPv6AddrPrefix(100,
		"fe80:1234:1234:5667:8967:af12:8912:1023")}

	mp_nlri3 := []AddrPrefixInterface{NewLabelledVPNIPv6AddrPrefix(100,
		"fe80:1234:1234:5667:8967:af12:1203:33a1", *NewMPLSLabelStack(5, 6),
		NewRouteDistinguisherFourOctetAS(5, 6))}

	mp_nlri4 := []AddrPrefixInterface{NewLabelledIPAddrPrefix(25, "192.168.0.0",
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
	n := []NLRInfo{*NewNLRInfo(24, "13.2.3.1")}
	return NewBGPUpdateMessage(w, p, n)
}

func Test_Message(t *testing.T) {
	l := []*BGPMessage{keepalive(), notification(), refresh(), open(), update()}
	for _, m := range l {
		buf1, _ := m.Serialize()
		t.Log("LEN =", len(buf1))
		msg, err := ParseBGPMessage(buf1)
		if err != nil {
			t.Error(err)
		}
		buf2, _ := msg.Serialize()
		if bytes.Compare(buf1, buf2) == 0 {
			t.Log("OK")
		} else {
			t.Error("Something wrong")
			t.Error(len(buf1), &m, buf1)
			t.Error(len(buf2), &msg, buf2)
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
	ec, err := parseExtended(buf)
	assert.Equal(nil, err)
	assert.Equal("1000000", ec.String())
	buf, err = ec.Serialize()
	assert.Equal(nil, err)
	assert.Equal([]byte{0x3, 0xb, 0x0, 0x0, 0x0, 0xf, 0x42, 0x40}, buf)

	buf = make([]byte, 8)
	buf[0] = byte(EC_TYPE_TRANSITIVE_OPAQUE)
	buf[1] = byte(EC_SUBTYPE_ENCAPSULATION)
	binary.BigEndian.PutUint16(buf[6:], uint16(TUNNEL_TYPE_VXLAN))
	ec, err = parseExtended(buf)
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

func Test_NLRIEqual(t *testing.T) {
	assert := assert.New(t)
	p1 := NewIPAddrPrefix(24, "192.168.10.0")
	p2 := NewIPAddrPrefix(24, "192.168.10.0")
	p3 := NewIPAddrPrefix(25, "192.168.10.0")
	assert.Equal(true, p1.Equal(p2))
	assert.Equal(false, p1.Equal(p3))

	p4 := NewIPv6AddrPrefix(128, "2001::")
	p5 := NewIPv6AddrPrefix(128, "2001::")
	p6 := NewIPv6AddrPrefix(129, "2001::")
	assert.Equal(true, p4.Equal(p5))
	assert.Equal(false, p4.Equal(p6))

	rd1 := NewRouteDistinguisherTwoOctetAS(1000, 1000)
	rd2 := NewRouteDistinguisherTwoOctetAS(1000, 1000)
	rd3 := NewRouteDistinguisherTwoOctetAS(1000, 2000)
	assert.Equal(true, rd1.Equal(rd2))
	assert.Equal(false, rd1.Equal(rd3))

	rd4 := NewRouteDistinguisherIPAddressAS("10.0.0.1", 1000)
	rd5 := NewRouteDistinguisherIPAddressAS("10.0.0.1", 1000)
	rd6 := NewRouteDistinguisherIPAddressAS("10.0.0.10", 1000)
	assert.Equal(true, rd4.Equal(rd5))
	assert.Equal(false, rd4.Equal(rd6))

	rd7 := NewRouteDistinguisherFourOctetAS(70000, 1000)
	rd8 := NewRouteDistinguisherFourOctetAS(70000, 1000)
	rd9 := NewRouteDistinguisherFourOctetAS(70000, 2000)
	assert.Equal(true, rd7.Equal(rd8))
	assert.Equal(false, rd7.Equal(rd9))

	ls1 := NewMPLSLabelStack(1, 2, 3, 4)
	ls2 := NewMPLSLabelStack(1, 2, 3, 4)
	ls3 := NewMPLSLabelStack(5, 6, 7, 8)
	assert.Equal(true, ls1.Equal(ls2))
	assert.Equal(false, ls1.Equal(ls3))

	p7 := NewLabelledVPNIPAddrPrefix(24, "192.168.0.0", *ls1, rd1)
	p8 := NewLabelledVPNIPAddrPrefix(24, "192.168.0.0", *ls1, rd1)
	p9 := NewLabelledVPNIPAddrPrefix(25, "192.168.0.0", *ls1, rd1)
	assert.Equal(true, p7.Equal(p8))
	assert.Equal(false, p7.Equal(p9))

	p10 := NewLabelledVPNIPv6AddrPrefix(128, "2001::", *ls1, rd1)
	p11 := NewLabelledVPNIPv6AddrPrefix(128, "2001::", *ls1, rd1)
	p12 := NewLabelledVPNIPv6AddrPrefix(129, "2001::", *ls1, rd1)
	assert.Equal(true, p10.Equal(p11))
	assert.Equal(false, p10.Equal(p12))

	p13 := NewLabelledIPAddrPrefix(24, "192.168.0.0", *ls2)
	p14 := NewLabelledIPAddrPrefix(24, "192.168.0.0", *ls2)
	p15 := NewLabelledIPAddrPrefix(24, "192.168.10.0", *ls3)
	assert.Equal(true, p13.Equal(p14))
	assert.Equal(false, p13.Equal(p15))

	p16 := NewLabelledIPv6AddrPrefix(128, "2001::", *ls2)
	p17 := NewLabelledIPv6AddrPrefix(128, "2001::", *ls2)
	p18 := NewLabelledIPv6AddrPrefix(129, "2001::", *ls3)
	assert.Equal(true, p16.Equal(p17))
	assert.Equal(false, p16.Equal(p18))

	rt1 := &TwoOctetAsSpecificExtended{
		AS:         65000,
		LocalAdmin: 10000,
	}
	rt2 := &TwoOctetAsSpecificExtended{
		AS:         65000,
		LocalAdmin: 10000,
	}
	rt3 := &TwoOctetAsSpecificExtended{
		AS:         65000,
		LocalAdmin: 20000,
	}
	assert.Equal(true, rt1.Equal(rt2))
	assert.Equal(false, rt1.Equal(rt3))

	p19 := NewRouteTargetMembershipNLRI(20000, rt1)
	p20 := NewRouteTargetMembershipNLRI(20000, rt2)
	p21 := NewRouteTargetMembershipNLRI(20001, rt3)
	assert.Equal(true, p19.Equal(p20))
	assert.Equal(false, p19.Equal(p21))

	esi1 := &EthernetSegmentIdentifier{
		Type:  ESI_ARBITRARY,
		Value: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
	}
	esi2 := &EthernetSegmentIdentifier{
		Type:  ESI_ARBITRARY,
		Value: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
	}
	esi3 := &EthernetSegmentIdentifier{
		Type:  ESI_ARBITRARY,
		Value: []byte{1, 2, 3, 4, 5, 6, 7, 8, 10},
	}
	assert.Equal(true, esi1.Equal(esi2))
	assert.Equal(false, esi1.Equal(esi3))

	ad1 := &EVPNEthernetAutoDiscoveryRoute{
		RD:    rd1,
		ESI:   *esi1,
		ETag:  1000,
		Label: 1000,
	}
	ad2 := &EVPNEthernetAutoDiscoveryRoute{
		RD:    rd1,
		ESI:   *esi1,
		ETag:  1000,
		Label: 1000,
	}
	ad3 := &EVPNEthernetAutoDiscoveryRoute{
		RD:    rd1,
		ESI:   *esi1,
		ETag:  1010,
		Label: 1000,
	}
	assert.Equal(true, ad1.Equal(ad2))
	assert.Equal(false, ad1.Equal(ad3))

	evpn1 := &EVPNNLRI{
		RouteType:     EVPN_ROUTE_TYPE_ETHERNET_AUTO_DISCOVERY,
		Length:        24,
		RouteTypeData: ad1,
	}
	evpn2 := &EVPNNLRI{
		RouteType:     EVPN_ROUTE_TYPE_ETHERNET_AUTO_DISCOVERY,
		Length:        24,
		RouteTypeData: ad2,
	}
	evpn3 := &EVPNNLRI{
		RouteType:     EVPN_ROUTE_TYPE_ETHERNET_AUTO_DISCOVERY,
		Length:        25,
		RouteTypeData: ad2,
	}
	assert.Equal(true, evpn1.Equal(evpn2))
	assert.Equal(false, evpn1.Equal(evpn3))

	encap1 := &EncapNLRI{
		IPAddrPrefixDefault: IPAddrPrefixDefault{
			Length: 24,
			Prefix: net.ParseIP("192.168.0.0"),
		},
	}
	encap2 := &EncapNLRI{
		IPAddrPrefixDefault: IPAddrPrefixDefault{
			Length: 24,
			Prefix: net.ParseIP("192.168.0.0"),
		},
	}
	encap3 := &EncapNLRI{
		IPAddrPrefixDefault: IPAddrPrefixDefault{
			Length: 24,
			Prefix: net.ParseIP("192.168.10.0"),
		},
	}
	assert.Equal(true, encap1.Equal(encap2))
	assert.Equal(false, encap1.Equal(encap3))
}

func Test_PathAttrEqual(t *testing.T) {
	assert := assert.New(t)
	o1 := NewPathAttributeOrigin(0)
	o2 := NewPathAttributeOrigin(0)
	o3 := NewPathAttributeOrigin(1)
	assert.Equal(true, o1.Equal(o2))
	assert.Equal(false, o1.Equal(o3))

	asp1 := NewAsPathParam(BGP_ASPATH_ATTR_TYPE_SEQ, []uint16{65000})
	asp2 := NewAsPathParam(BGP_ASPATH_ATTR_TYPE_SEQ, []uint16{65000})
	asp3 := NewAsPathParam(BGP_ASPATH_ATTR_TYPE_SEQ, []uint16{65000, 65001})
	assert.Equal(true, asp1.Equal(asp2))
	assert.Equal(false, asp1.Equal(asp3))

	aspath1 := NewPathAttributeAsPath([]AsPathParamInterface{asp1, asp2, asp3})
	aspath2 := NewPathAttributeAsPath([]AsPathParamInterface{asp1, asp2, asp3})
	aspath3 := NewPathAttributeAsPath([]AsPathParamInterface{asp1, asp2})
	assert.Equal(true, aspath1.Equal(aspath2))
	assert.Equal(false, aspath1.Equal(aspath3))

	nh1 := NewPathAttributeNextHop("192.168.0.1")
	nh2 := NewPathAttributeNextHop("192.168.0.1")
	nh3 := NewPathAttributeNextHop("192.168.0.2")
	assert.Equal(true, nh1.Equal(nh2))
	assert.Equal(false, nh1.Equal(nh3))

	med1 := NewPathAttributeMultiExitDisc(100)
	med2 := NewPathAttributeMultiExitDisc(100)
	med3 := NewPathAttributeMultiExitDisc(200)
	assert.Equal(true, med1.Equal(med2))
	assert.Equal(false, med1.Equal(med3))

	lp1 := NewPathAttributeLocalPref(100)
	lp2 := NewPathAttributeLocalPref(100)
	lp3 := NewPathAttributeLocalPref(200)
	assert.Equal(true, lp1.Equal(lp2))
	assert.Equal(false, lp1.Equal(lp3))

	aa1 := NewPathAttributeAtomicAggregate()
	aa2 := NewPathAttributeAtomicAggregate()
	assert.Equal(true, aa1.Equal(aa2))

	ag1 := NewPathAttributeAggregator(uint16(30002), "129.0.2.99")
	ag2 := NewPathAttributeAggregator(uint16(30002), "129.0.2.99")
	ag3 := NewPathAttributeAggregator(uint16(30002), "129.0.2.100")
	assert.Equal(true, ag1.Equal(ag2))
	assert.Equal(false, ag1.Equal(ag3))

	c1 := NewPathAttributeCommunities([]uint32{1, 3})
	c2 := NewPathAttributeCommunities([]uint32{1, 3})
	c3 := NewPathAttributeCommunities([]uint32{1, 10})
	assert.Equal(true, c1.Equal(c2))
	assert.Equal(false, c1.Equal(c3))

	oid1 := NewPathAttributeOriginatorId("10.10.0.1")
	oid2 := NewPathAttributeOriginatorId("10.10.0.1")
	oid3 := NewPathAttributeOriginatorId("10.10.0.2")
	assert.Equal(true, oid1.Equal(oid2))
	assert.Equal(false, oid1.Equal(oid3))

	cli1 := NewPathAttributeClusterList([]string{"10.10.0.2", "10.10.0.3"})
	cli2 := NewPathAttributeClusterList([]string{"10.10.0.2", "10.10.0.3"})
	cli3 := NewPathAttributeClusterList([]string{"10.10.0.2", "10.10.0.4"})
	assert.Equal(true, cli1.Equal(cli2))
	assert.Equal(false, cli1.Equal(cli3))

	ps1 := []AddrPrefixInterface{
		NewLabelledVPNIPAddrPrefix(20, "192.0.9.0", *NewMPLSLabelStack(1, 2, 3),
			NewRouteDistinguisherTwoOctetAS(256, 10000)),
	}
	ps2 := []AddrPrefixInterface{
		NewLabelledVPNIPAddrPrefix(20, "192.0.9.1", *NewMPLSLabelStack(1, 2, 3),
			NewRouteDistinguisherTwoOctetAS(256, 10000)),
	}

	nlri1 := NewPathAttributeMpReachNLRI("112.22.2.0", ps1)
	nlri2 := NewPathAttributeMpReachNLRI("112.22.2.0", ps1)
	nlri3 := NewPathAttributeMpReachNLRI("112.22.2.0", ps2)
	assert.Equal(true, nlri1.Equal(nlri2))
	assert.Equal(false, nlri1.Equal(nlri3))

	nlri4 := NewPathAttributeMpUnreachNLRI(ps1)
	nlri5 := NewPathAttributeMpUnreachNLRI(ps1)
	nlri6 := NewPathAttributeMpUnreachNLRI(ps2)
	assert.Equal(true, nlri4.Equal(nlri5))
	assert.Equal(false, nlri4.Equal(nlri6))

	e1 := []ExtendedCommunityInterface{
		&TwoOctetAsSpecificExtended{SubType: 1, AS: 10003, LocalAdmin: 3 << 20},
	}
	e2 := []ExtendedCommunityInterface{
		&FourOctetAsSpecificExtended{SubType: 2, AS: 1 << 20, LocalAdmin: 300},
	}

	ec1 := NewPathAttributeExtendedCommunities(e1)
	ec2 := NewPathAttributeExtendedCommunities(e1)
	ec3 := NewPathAttributeExtendedCommunities(e2)
	assert.Equal(true, ec1.Equal(ec2))
	assert.Equal(false, ec1.Equal(ec3))

	asp4 := NewAs4PathParam(BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{650000})
	asp5 := NewAs4PathParam(BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{650000})
	asp6 := NewAs4PathParam(BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{650000, 650001})
	assert.Equal(true, asp4.Equal(asp5))
	assert.Equal(false, asp4.Equal(asp6))

	aspath4 := NewPathAttributeAs4Path([]*As4PathParam{asp4, asp5, asp6})
	aspath5 := NewPathAttributeAs4Path([]*As4PathParam{asp4, asp5, asp6})
	aspath6 := NewPathAttributeAs4Path([]*As4PathParam{asp4, asp5})
	assert.Equal(true, aspath4.Equal(aspath5))
	assert.Equal(false, aspath4.Equal(aspath6))

	ag4 := NewPathAttributeAs4Aggregator(10000, "112.22.2.1")
	ag5 := NewPathAttributeAs4Aggregator(10000, "112.22.2.1")
	ag6 := NewPathAttributeAs4Aggregator(10000, "112.22.2.2")
	assert.Equal(true, ag4.Equal(ag5))
	assert.Equal(false, ag4.Equal(ag6))

	subTlv1 := &TunnelEncapSubTLV{
		Type:  ENCAP_SUBTLV_TYPE_COLOR,
		Value: &TunnelEncapSubTLVColor{10},
	}
	subTlv2 := &TunnelEncapSubTLV{
		Type:  ENCAP_SUBTLV_TYPE_COLOR,
		Value: &TunnelEncapSubTLVColor{10},
	}
	subTlv3 := &TunnelEncapSubTLV{
		Type:  ENCAP_SUBTLV_TYPE_COLOR,
		Value: &TunnelEncapSubTLVColor{20},
	}
	assert.Equal(true, subTlv1.Equal(subTlv2))
	assert.Equal(false, subTlv1.Equal(subTlv3))

	tlv1 := &TunnelEncapTLV{
		Type:  TUNNEL_TYPE_VXLAN,
		Value: []*TunnelEncapSubTLV{subTlv1},
	}
	tlv2 := &TunnelEncapTLV{
		Type:  TUNNEL_TYPE_VXLAN,
		Value: []*TunnelEncapSubTLV{subTlv2},
	}
	tlv3 := &TunnelEncapTLV{
		Type:  TUNNEL_TYPE_VXLAN,
		Value: []*TunnelEncapSubTLV{subTlv3},
	}
	assert.Equal(true, tlv1.Equal(tlv2))
	assert.Equal(false, tlv1.Equal(tlv3))

	encap1 := NewPathAttributeTunnelEncap([]*TunnelEncapTLV{tlv1})
	encap2 := NewPathAttributeTunnelEncap([]*TunnelEncapTLV{tlv2})
	encap3 := NewPathAttributeTunnelEncap([]*TunnelEncapTLV{tlv3})
	assert.Equal(true, encap1.Equal(encap2))
	assert.Equal(false, encap1.Equal(encap3))

	unknown1 := &PathAttributeUnknown{
		PathAttribute: PathAttribute{
			Flags: BGP_ATTR_FLAG_TRANSITIVE,
			Type:  100,
			Value: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		},
	}
	unknown2 := &PathAttributeUnknown{
		PathAttribute: PathAttribute{
			Flags: BGP_ATTR_FLAG_TRANSITIVE,
			Type:  100,
			Value: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		},
	}
	unknown3 := &PathAttributeUnknown{
		PathAttribute: PathAttribute{
			Flags: BGP_ATTR_FLAG_TRANSITIVE,
			Type:  100,
			Value: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		},
	}
	assert.Equal(true, unknown1.Equal(unknown2))
	assert.Equal(false, unknown1.Equal(unknown3))
}
