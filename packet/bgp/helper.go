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
	"net"
)

func NewTestBGPOpenMessage() *BGPMessage {
	p1 := NewOptionParameterCapability(
		[]ParameterCapabilityInterface{NewCapRouteRefresh()})
	p2 := NewOptionParameterCapability(
		[]ParameterCapabilityInterface{NewCapMultiProtocol(RF_IPv4_UC)})
	g := &CapGracefulRestartTuple{4, 2, 3}
	p3 := NewOptionParameterCapability(
		[]ParameterCapabilityInterface{NewCapGracefulRestart(false, true, 100,
			[]*CapGracefulRestartTuple{g})})
	p4 := NewOptionParameterCapability(
		[]ParameterCapabilityInterface{NewCapFourOctetASNumber(100000)})
	p5 := NewOptionParameterCapability(
		[]ParameterCapabilityInterface{NewCapAddPath(RF_IPv4_UC, BGP_ADD_PATH_BOTH)})
	return NewBGPOpenMessage(11033, 303, "100.4.10.3",
		[]OptionParameterInterface{p1, p2, p3, p4, p5})
}

func NewTestBGPUpdateMessage() *BGPMessage {
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
				EthernetSegmentIdentifier{ESI_ARBITRARY, make([]byte, 9)}, 2, *NewMPLSLabelStack(uint32(2))}),
		NewEVPNNLRI(EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT, 0,
			&EVPNMacIPAdvertisementRoute{NewRouteDistinguisherFourOctetAS(5, 6),
				EthernetSegmentIdentifier{ESI_ARBITRARY, make([]byte, 9)}, 3, 48,
				mac, 32, net.ParseIP("192.2.1.2"),
				*NewMPLSLabelStack(uint32(3), uint32(4))}),
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
