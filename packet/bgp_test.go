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
		&OpaqueExtended{Value: []byte{0, 1, 2, 3, 4, 5, 6, 7}},
		&UnknownExtended{Type: 99, Value: []byte{0, 1, 2, 3, 4, 5, 6, 7}},
	}

	mp_nlri := []AddrPrefixInterface{
		NewLabelledVPNIPAddrPrefix(20, "192.0.9.0", *NewLabel(1, 2, 3),
			NewRouteDistinguisherTwoOctetAS(256, 10000)),
		NewLabelledVPNIPAddrPrefix(26, "192.10.8.192", *NewLabel(5, 6, 7, 8),
			NewRouteDistinguisherIPAddressAS("10.0.1.1", 10001)),
	}

	mp_nlri2 := []AddrPrefixInterface{NewIPv6AddrPrefix(100,
		"fe80:1234:1234:5667:8967:af12:8912:1023")}

	mp_nlri3 := []AddrPrefixInterface{NewLabelledVPNIPv6AddrPrefix(100,
		"fe80:1234:1234:5667:8967:af12:1203:33a1", *NewLabel(5, 6),
		NewRouteDistinguisherFourOctetAS(5, 6))}

	mp_nlri4 := []AddrPrefixInterface{NewLabelledIPAddrPrefix(25, "192.168.0.0",
		*NewLabel(5, 6, 7))}

	mp_nlri5 := []AddrPrefixInterface{NewEVPNNLRI(EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG, 0,
		&EVPNMulticastEthernetTagRoute{NewRouteDistinguisherFourOctetAS(5, 6), 3, 32, net.ParseIP("192.2.1.2")})}

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
	r := &RouteTargetMembershipNLRI{}

	assert := assert.New(t)

	// TwoOctetAsSpecificExtended
	buf := make([]byte, 12)
	binary.BigEndian.PutUint32(buf[:4], 65546)
	buf[4] = 0x00 // typehigh
	binary.BigEndian.PutUint16(buf[6:8], 65000)
	binary.BigEndian.PutUint32(buf[8:], 65546)
	r.DecodeFromBytes(buf)
	assert.Equal("65546:65000:65546/96", r.String())

	// IPv4AddressSpecificExtended
	binary.BigEndian.PutUint32(buf[:4], 65546)
	buf[4] = 0x01 // typehigh
	ip := net.ParseIP("10.0.0.1").To4()
	copy(buf[6:10], []byte(ip))
	binary.BigEndian.PutUint16(buf[10:], 65000)
	r.DecodeFromBytes(buf)
	assert.Equal("65546:10.0.0.1:65000/96", r.String())

	// FourOctetAsSpecificExtended
	binary.BigEndian.PutUint32(buf[:4], 65546)
	buf[4] = 0x02 // typehigh
	buf[5] = 0x01 // subtype
	binary.BigEndian.PutUint32(buf[6:], 65546)
	binary.BigEndian.PutUint16(buf[10:], 65000)
	r.DecodeFromBytes(buf)
	assert.Equal("65546:1.10:65000/96", r.String())

	// OpaqueExtended
	binary.BigEndian.PutUint32(buf[:4], 65546)
	buf[4] = 0x03 // typehigh
	binary.BigEndian.PutUint32(buf[8:], 1000000)
	r.DecodeFromBytes(buf)
	assert.Equal("65546:281479272677952/96", r.String())

	// Unknown
	binary.BigEndian.PutUint32(buf[:4], 65546)
	buf[4] = 0x04 // typehigh
	binary.BigEndian.PutUint32(buf[8:], 1000000)
	r.DecodeFromBytes(buf)
	assert.Equal("65546:281479272677952/96", r.String())

}
