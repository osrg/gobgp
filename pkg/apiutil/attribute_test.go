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

package apiutil

import (
	"bytes"
	"net/netip"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
)

func Test_OriginAttribute(t *testing.T) {
	assert := assert.New(t)

	input := &api.OriginAttribute{
		Origin: 0, // IGP
	}
	a := &api.Attribute{Attr: &api.Attribute_Origin{Origin: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewOriginAttributeFromNative(n.(*bgp.PathAttributeOrigin))
	assert.Equal(input.Origin, output.Origin)
}

func Test_AsPathAttribute(t *testing.T) {
	assert := assert.New(t)

	input := &api.AsPathAttribute{
		Segments: []*api.AsSegment{
			{
				Type:    1, // SET
				Numbers: []uint32{100, 200},
			},
			{
				Type:    2, // SEQ
				Numbers: []uint32{300, 400},
			},
		},
	}

	a := &api.Attribute{Attr: &api.Attribute_AsPath{AsPath: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewAsPathAttributeFromNative(n.(*bgp.PathAttributeAsPath))
	assert.True(proto.Equal(input, output))
}

func Test_NextHopAttribute(t *testing.T) {
	assert := assert.New(t)

	input := &api.NextHopAttribute{
		NextHop: "192.168.0.1",
	}

	a := &api.Attribute{Attr: &api.Attribute_NextHop{NextHop: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewNextHopAttributeFromNative(n.(*bgp.PathAttributeNextHop))
	assert.True(proto.Equal(input, output))
}

func Test_MultiExitDiscAttribute(t *testing.T) {
	assert := assert.New(t)

	input := &api.MultiExitDiscAttribute{
		Med: 100,
	}

	a := &api.Attribute{Attr: &api.Attribute_MultiExitDisc{MultiExitDisc: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewMultiExitDiscAttributeFromNative(n.(*bgp.PathAttributeMultiExitDisc))
	assert.True(proto.Equal(input, output))
}

func Test_LocalPrefAttribute(t *testing.T) {
	assert := assert.New(t)

	input := &api.LocalPrefAttribute{
		LocalPref: 100,
	}

	a := &api.Attribute{Attr: &api.Attribute_LocalPref{LocalPref: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewLocalPrefAttributeFromNative(n.(*bgp.PathAttributeLocalPref))
	assert.True(proto.Equal(input, output))
}

func Test_AtomicAggregateAttribute(t *testing.T) {
	assert := assert.New(t)

	input := &api.AtomicAggregateAttribute{}

	a := &api.Attribute{Attr: &api.Attribute_AtomicAggregate{AtomicAggregate: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewAtomicAggregateAttributeFromNative(n.(*bgp.PathAttributeAtomicAggregate))
	// AtomicAggregateAttribute has no value
	assert.NotNil(output)
}

func Test_AggregatorAttribute(t *testing.T) {
	assert := assert.New(t)

	input := &api.AggregatorAttribute{
		Asn:     65000,
		Address: "1.1.1.1",
	}

	a := &api.Attribute{Attr: &api.Attribute_Aggregator{Aggregator: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewAggregatorAttributeFromNative(n.(*bgp.PathAttributeAggregator))
	assert.True(proto.Equal(input, output))
}

func Test_CommunitiesAttribute(t *testing.T) {
	assert := assert.New(t)

	input := &api.CommunitiesAttribute{
		Communities: []uint32{100, 200},
	}

	a := &api.Attribute{Attr: &api.Attribute_Communities{Communities: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewCommunitiesAttributeFromNative(n.(*bgp.PathAttributeCommunities))
	assert.True(proto.Equal(input, output))
}

func Test_OriginatorIdAttribute(t *testing.T) {
	assert := assert.New(t)

	input := &api.OriginatorIdAttribute{
		Id: "1.1.1.1",
	}

	a := &api.Attribute{Attr: &api.Attribute_OriginatorId{OriginatorId: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewOriginatorIdAttributeFromNative(n.(*bgp.PathAttributeOriginatorId))
	assert.True(proto.Equal(input, output))
}

func Test_ClusterListAttribute(t *testing.T) {
	assert := assert.New(t)

	input := &api.ClusterListAttribute{
		Ids: []string{"1.1.1.1", "2.2.2.2"},
	}

	a := &api.Attribute{Attr: &api.Attribute_ClusterList{ClusterList: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewClusterListAttributeFromNative(n.(*bgp.PathAttributeClusterList))
	assert.True(proto.Equal(input, output))
}

func Test_MpReachNLRIAttribute_IPv4_UC(t *testing.T) {
	assert := assert.New(t)

	nlris := []*api.NLRI{
		{Nlri: &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{
			PrefixLen: 24,
			Prefix:    "192.168.101.0",
		}}},
		{Nlri: &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{
			PrefixLen: 24,
			Prefix:    "192.168.201.0",
		}}},
	}
	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_UNICAST,
		},
		NextHops: []string{"192.168.1.1"},
		Nlris:    nlris,
	}

	a := &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.True(proto.Equal(input, output))
}

func Test_MpReachNLRIAttribute_IPv6_UC(t *testing.T) {
	assert := assert.New(t)

	nlris := []*api.NLRI{
		{Nlri: &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{
			PrefixLen: 64,
			Prefix:    "2001:db8:1::",
		}}},
		{Nlri: &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{
			PrefixLen: 64,
			Prefix:    "2001:db8:2::",
		}}},
	}
	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP6,
			Safi: api.Family_SAFI_UNICAST,
		},
		NextHops: []string{"2001:db8::1", "fe80::1"},
		Nlris:    nlris,
	}

	a := &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.True(proto.Equal(input, output))
}

func Test_MpReachNLRIAttribute_IPv4_MPLS(t *testing.T) {
	assert := assert.New(t)

	nlris := []*api.NLRI{
		{Nlri: &api.NLRI_LabeledPrefix{LabeledPrefix: &api.LabeledIPAddressPrefix{
			Labels:    []uint32{100},
			PrefixLen: 24,
			Prefix:    "192.168.101.0",
		}}},
		{Nlri: &api.NLRI_LabeledPrefix{LabeledPrefix: &api.LabeledIPAddressPrefix{
			Labels:    []uint32{200},
			PrefixLen: 24,
			Prefix:    "192.168.201.0",
		}}},
	}
	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_MPLS_LABEL,
		},
		NextHops: []string{"192.168.1.1"},
		Nlris:    nlris,
	}

	a := &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.True(proto.Equal(input, output))
}

func Test_MpReachNLRIAttribute_IPv6_MPLS(t *testing.T) {
	assert := assert.New(t)

	nlris := []*api.NLRI{
		{Nlri: &api.NLRI_LabeledPrefix{LabeledPrefix: &api.LabeledIPAddressPrefix{
			Labels:    []uint32{100},
			PrefixLen: 64,
			Prefix:    "2001:db8:1::",
		}}},
		{Nlri: &api.NLRI_LabeledPrefix{LabeledPrefix: &api.LabeledIPAddressPrefix{
			Labels:    []uint32{200},
			PrefixLen: 64,
			Prefix:    "2001:db8:2::",
		}}},
	}
	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP6,
			Safi: api.Family_SAFI_MPLS_LABEL,
		},
		NextHops: []string{"2001:db8::1"},
		Nlris:    nlris,
	}

	a := &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.True(proto.Equal(input, output))
}

func Test_MpReachNLRIAttribute_IPv4_ENCAP(t *testing.T) {
	assert := assert.New(t)

	nlris := []*api.NLRI{
		{Nlri: &api.NLRI_Encapsulation{Encapsulation: &api.EncapsulationNLRI{
			Address: "192.168.101.1",
		}}},
		{Nlri: &api.NLRI_Encapsulation{Encapsulation: &api.EncapsulationNLRI{
			Address: "192.168.201.1",
		}}},
	}
	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_ENCAPSULATION,
		},
		NextHops: []string{"192.168.1.1"},
		Nlris:    nlris,
	}

	a := &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.True(proto.Equal(input, output))
}

func Test_MpReachNLRIAttribute_IPv6_ENCAP(t *testing.T) {
	assert := assert.New(t)

	nlris := []*api.NLRI{
		{Nlri: &api.NLRI_Encapsulation{Encapsulation: &api.EncapsulationNLRI{
			Address: "2001:db8:1::1",
		}}},
		{Nlri: &api.NLRI_Encapsulation{Encapsulation: &api.EncapsulationNLRI{
			Address: "2001:db8:2::1",
		}}},
	}
	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP6,
			Safi: api.Family_SAFI_ENCAPSULATION,
		},
		NextHops: []string{"2001:db8::1"},
		Nlris:    nlris,
	}

	a := &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.True(proto.Equal(input, output))
}

func Test_MpReachNLRIAttribute_VPLS(t *testing.T) {
	assert := assert.New(t)

	rd := &api.RouteDistinguisher{Rd: &api.RouteDistinguisher_TwoOctetAsn{
		TwoOctetAsn: &api.RouteDistinguisherTwoOctetASN{
			Admin:    65000,
			Assigned: 100,
		},
	}}
	nlris := []*api.NLRI{{Nlri: &api.NLRI_Vpls{Vpls: &api.VPLSNLRI{
		Rd:             rd,
		VeId:           101,
		VeBlockOffset:  100,
		VeBlockSize:    10,
		LabelBlockBase: 1000,
	}}}}
	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_L2VPN,
			Safi: api.Family_SAFI_VPLS,
		},
		NextHops: []string{"192.168.1.1"},
		Nlris:    nlris,
	}

	a := &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.True(proto.Equal(input, output))
}

func Test_MpReachNLRIAttribute_EVPN_AD_Route(t *testing.T) {
	assert := assert.New(t)

	rd := &api.RouteDistinguisher{Rd: &api.RouteDistinguisher_TwoOctetAsn{
		TwoOctetAsn: &api.RouteDistinguisherTwoOctetASN{
			Admin:    65000,
			Assigned: 100,
		},
	}}
	nlris := []*api.NLRI{
		{Nlri: &api.NLRI_EvpnEthernetAd{EvpnEthernetAd: &api.EVPNEthernetAutoDiscoveryRoute{
			Rd: rd,
			Esi: &api.EthernetSegmentIdentifier{
				Type:  0,
				Value: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
			},
			EthernetTag: 100,
			Label:       200,
		}}},
	}
	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_L2VPN,
			Safi: api.Family_SAFI_EVPN,
		},
		NextHops: []string{"192.168.1.1"},
		Nlris:    nlris,
	}

	a := &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.True(proto.Equal(input, output))
}

func Test_MpReachNLRIAttribute_EVPN_MAC_IP_Route(t *testing.T) {
	assert := assert.New(t)

	rd := &api.RouteDistinguisher{Rd: &api.RouteDistinguisher_IpAddress{
		IpAddress: &api.RouteDistinguisherIPAddress{
			Admin:    "1.1.1.1",
			Assigned: 100,
		},
	}}
	nlris := []*api.NLRI{
		{Nlri: &api.NLRI_EvpnMacadv{EvpnMacadv: &api.EVPNMACIPAdvertisementRoute{
			Rd: rd,
			Esi: &api.EthernetSegmentIdentifier{
				Type:  0,
				Value: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
			},
			EthernetTag: 100,
			MacAddress:  "aa:bb:cc:dd:ee:ff",
			IpAddress:   "192.168.101.1",
			Labels:      []uint32{200},
		}}},
	}
	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_L2VPN,
			Safi: api.Family_SAFI_EVPN,
		},
		NextHops: []string{"192.168.1.1"},
		Nlris:    nlris,
	}

	a := &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.True(proto.Equal(input, output))
}

func Test_MpReachNLRIAttribute_EVPN_MC_Route(t *testing.T) {
	assert := assert.New(t)

	rd := &api.RouteDistinguisher{Rd: &api.RouteDistinguisher_FourOctetAsn{
		FourOctetAsn: &api.RouteDistinguisherFourOctetASN{
			Admin:    65000,
			Assigned: 100,
		},
	}}
	nlris := []*api.NLRI{
		{Nlri: &api.NLRI_EvpnMulticast{EvpnMulticast: &api.EVPNInclusiveMulticastEthernetTagRoute{
			Rd:          rd,
			EthernetTag: 100,
			IpAddress:   "192.168.101.1",
		}}},
	}
	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_L2VPN,
			Safi: api.Family_SAFI_EVPN,
		},
		NextHops: []string{"192.168.1.1"},
		Nlris:    nlris,
	}

	a := &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.True(proto.Equal(input, output))
}

func Test_MpReachNLRIAttribute_EVPN_ES_Route(t *testing.T) {
	assert := assert.New(t)

	rd := &api.RouteDistinguisher{Rd: &api.RouteDistinguisher_IpAddress{
		IpAddress: &api.RouteDistinguisherIPAddress{
			Admin:    "1.1.1.1",
			Assigned: 100,
		},
	}}
	nlris := []*api.NLRI{
		{Nlri: &api.NLRI_EvpnEthernetSegment{EvpnEthernetSegment: &api.EVPNEthernetSegmentRoute{
			Rd: rd,
			Esi: &api.EthernetSegmentIdentifier{
				Type:  0,
				Value: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
			},
			IpAddress: "192.168.101.1",
		}}},
	}
	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_L2VPN,
			Safi: api.Family_SAFI_EVPN,
		},
		NextHops: []string{"192.168.1.1"},
		Nlris:    nlris,
	}

	a := &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.True(proto.Equal(input, output))
}

func Test_MpReachNLRIAttribute_EVPN_Prefix_Route(t *testing.T) {
	assert := assert.New(t)

	rd := &api.RouteDistinguisher{Rd: &api.RouteDistinguisher_IpAddress{
		IpAddress: &api.RouteDistinguisherIPAddress{
			Admin:    "1.1.1.1",
			Assigned: 100,
		},
	}}
	nlris := []*api.NLRI{
		{Nlri: &api.NLRI_EvpnIpPrefix{EvpnIpPrefix: &api.EVPNIPPrefixRoute{
			Rd: rd,
			Esi: &api.EthernetSegmentIdentifier{
				Type:  0,
				Value: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
			},
			EthernetTag: 100,
			IpPrefixLen: 24,
			IpPrefix:    "192.168.101.0",
			Label:       200,
			GwAddress:   "172.16.101.1",
		}}},
	}
	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_L2VPN,
			Safi: api.Family_SAFI_EVPN,
		},
		NextHops: []string{"192.168.1.1"},
		Nlris:    nlris,
	}

	a := &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.True(proto.Equal(input, output))
}

func Test_MpReachNLRIAttribute_IPv4_VPN(t *testing.T) {
	assert := assert.New(t)

	rd := &api.RouteDistinguisher{Rd: &api.RouteDistinguisher_IpAddress{
		IpAddress: &api.RouteDistinguisherIPAddress{
			Admin:    "1.1.1.1",
			Assigned: 100,
		},
	}}
	nlris := []*api.NLRI{{Nlri: &api.NLRI_LabeledVpnIpPrefix{
		LabeledVpnIpPrefix: &api.LabeledVPNIPAddressPrefix{
			Labels:    []uint32{100, 200},
			Rd:        rd,
			PrefixLen: 24,
			Prefix:    "192.168.101.0",
		},
	}}}
	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_MPLS_VPN,
		},
		NextHops: []string{"192.168.1.1"},
		Nlris:    nlris,
	}

	a := &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.True(proto.Equal(input, output))
}

func Test_MpReachNLRIAttribute_IPv6_VPN(t *testing.T) {
	assert := assert.New(t)

	rd := &api.RouteDistinguisher{Rd: &api.RouteDistinguisher_IpAddress{
		IpAddress: &api.RouteDistinguisherIPAddress{
			Admin:    "1.1.1.1",
			Assigned: 100,
		},
	}}
	nlris := []*api.NLRI{{Nlri: &api.NLRI_LabeledVpnIpPrefix{
		LabeledVpnIpPrefix: &api.LabeledVPNIPAddressPrefix{
			Labels:    []uint32{100, 200},
			Rd:        rd,
			PrefixLen: 64,
			Prefix:    "2001:db8:1::",
		},
	}}}
	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP6,
			Safi: api.Family_SAFI_MPLS_VPN,
		},
		NextHops: []string{"2001:db8::1"},
		Nlris:    nlris,
	}

	a := &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.True(proto.Equal(input, output))
}

func Test_MpReachNLRIAttribute_RTC_UC(t *testing.T) {
	assert := assert.New(t)

	rt := &api.RouteTarget{Rt: &api.RouteTarget_Ipv4AddressSpecific{
		Ipv4AddressSpecific: &api.IPv4AddressSpecificExtended{
			IsTransitive: true,
			SubType:      0x02, // Route Target
			Address:      "1.1.1.1",
			LocalAdmin:   100,
		},
	}}
	nlris := []*api.NLRI{{Nlri: &api.NLRI_RouteTargetMembership{
		RouteTargetMembership: &api.RouteTargetMembershipNLRI{
			Asn: 65000,
			Rt:  rt,
		},
	}}}
	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_ROUTE_TARGET_CONSTRAINTS,
		},
		NextHops: []string{"192.168.1.1"},
		Nlris:    nlris,
	}

	a := &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.True(proto.Equal(input, output))
}

func Test_MpReachNLRIAttribute_FS_IPv4_UC(t *testing.T) {
	assert := assert.New(t)

	rules := []*api.FlowSpecRule{
		{Rule: &api.FlowSpecRule_IpPrefix{IpPrefix: &api.FlowSpecIPPrefix{
			Type:      1, // Destination Prefix
			PrefixLen: 24,
			Prefix:    "192.168.101.0",
		}}},
		{Rule: &api.FlowSpecRule_IpPrefix{IpPrefix: &api.FlowSpecIPPrefix{
			Type:      2, // Source Prefix
			PrefixLen: 24,
			Prefix:    "192.168.201.0",
		}}},
		{Rule: &api.FlowSpecRule_Component{Component: &api.FlowSpecComponent{
			Type: 3, // IP Protocol
			Items: []*api.FlowSpecComponentItem{
				{
					Op:    0x80 | 0x01, // End, EQ
					Value: 6,           // TCP
				},
			},
		}}},
	}
	nlris := []*api.NLRI{{Nlri: &api.NLRI_FlowSpec{FlowSpec: &api.FlowSpecNLRI{
		Rules: rules,
	}}}}
	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_FLOW_SPEC_UNICAST,
		},
		// NextHops: // No nexthop required
		Nlris: nlris,
	}

	a := &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.True(proto.Equal(input, output))
}

func Test_MpReachNLRIAttribute_FS_IPv4_VPN(t *testing.T) {
	assert := assert.New(t)

	rd := &api.RouteDistinguisher{Rd: &api.RouteDistinguisher_IpAddress{
		IpAddress: &api.RouteDistinguisherIPAddress{
			Admin:    "1.1.1.1",
			Assigned: 100,
		},
	}}
	rules := []*api.FlowSpecRule{
		{Rule: &api.FlowSpecRule_IpPrefix{IpPrefix: &api.FlowSpecIPPrefix{
			Type:      1, // Destination Prefix
			PrefixLen: 24,
			Prefix:    "192.168.101.0",
		}}},
		{Rule: &api.FlowSpecRule_IpPrefix{IpPrefix: &api.FlowSpecIPPrefix{
			Type:      2, // Source Prefix
			PrefixLen: 24,
			Prefix:    "192.168.201.0",
		}}},
		{Rule: &api.FlowSpecRule_Component{Component: &api.FlowSpecComponent{
			Type: 3, // IP Protocol
			Items: []*api.FlowSpecComponentItem{
				{
					Op:    0x80 | 0x01, // End, EQ
					Value: 6,           // TCP
				},
			},
		}}},
	}
	nlris := []*api.NLRI{{Nlri: &api.NLRI_VpnFlowSpec{VpnFlowSpec: &api.VPNFlowSpecNLRI{
		Rd:    rd,
		Rules: rules,
	}}}}

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_FLOW_SPEC_VPN,
		},
		// NextHops: // No nexthop required
		Nlris: nlris,
	}

	a := &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.True(proto.Equal(input, output))
}

func Test_MpReachNLRIAttribute_FS_IPv6_UC(t *testing.T) {
	assert := assert.New(t)

	rules := []*api.FlowSpecRule{
		{Rule: &api.FlowSpecRule_IpPrefix{IpPrefix: &api.FlowSpecIPPrefix{
			Type:      1, // Destination Prefix
			PrefixLen: 64,
			Prefix:    "2001:db8:1::",
		}}},
		{Rule: &api.FlowSpecRule_IpPrefix{IpPrefix: &api.FlowSpecIPPrefix{
			Type:      2, // Source Prefix
			PrefixLen: 64,
			Prefix:    "2001:db8:2::",
		}}},
		{Rule: &api.FlowSpecRule_Component{Component: &api.FlowSpecComponent{
			Type: 3, // Next Header
			Items: []*api.FlowSpecComponentItem{
				{
					Op:    0x80 | 0x01, // End, EQ
					Value: 6,           // TCP
				},
			},
		}}},
	}
	nlris := []*api.NLRI{{Nlri: &api.NLRI_FlowSpec{FlowSpec: &api.FlowSpecNLRI{
		Rules: rules,
	}}}}

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP6,
			Safi: api.Family_SAFI_FLOW_SPEC_UNICAST,
		},
		// NextHops: // No nexthop required
		Nlris: nlris,
	}

	a := &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.True(proto.Equal(input, output))
}

func Test_MpReachNLRIAttribute_FS_IPv6_VPN(t *testing.T) {
	assert := assert.New(t)

	rd := &api.RouteDistinguisher{Rd: &api.RouteDistinguisher_IpAddress{
		IpAddress: &api.RouteDistinguisherIPAddress{
			Admin:    "1.1.1.1",
			Assigned: 100,
		},
	}}
	rules := []*api.FlowSpecRule{
		{Rule: &api.FlowSpecRule_IpPrefix{IpPrefix: &api.FlowSpecIPPrefix{
			Type:      1, // Destination Prefix
			PrefixLen: 64,
			Prefix:    "2001:db8:1::",
		}}},
		{Rule: &api.FlowSpecRule_IpPrefix{IpPrefix: &api.FlowSpecIPPrefix{
			Type:      2, // Source Prefix
			PrefixLen: 64,
			Prefix:    "2001:db8:2::",
		}}},
		{Rule: &api.FlowSpecRule_Component{Component: &api.FlowSpecComponent{
			Type: 3, // Next Header
			Items: []*api.FlowSpecComponentItem{
				{
					Op:    0x80 | 0x01, // End, EQ
					Value: 6,           // TCP
				},
			},
		}}},
	}
	nlris := []*api.NLRI{{Nlri: &api.NLRI_VpnFlowSpec{VpnFlowSpec: &api.VPNFlowSpecNLRI{
		Rd:    rd,
		Rules: rules,
	}}}}

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP6,
			Safi: api.Family_SAFI_FLOW_SPEC_VPN,
		},
		// NextHops: // No nexthop required
		Nlris: nlris,
	}

	a := &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.True(proto.Equal(input, output))
}

func Test_MpReachNLRIAttribute_FS_L2_VPN(t *testing.T) {
	assert := assert.New(t)

	rd := &api.RouteDistinguisher{Rd: &api.RouteDistinguisher_IpAddress{IpAddress: &api.RouteDistinguisherIPAddress{
		Admin:    "1.1.1.1",
		Assigned: 100,
	}}}
	rules := []*api.FlowSpecRule{
		{Rule: &api.FlowSpecRule_Mac{Mac: &api.FlowSpecMAC{
			Type:    15, // Source MAC
			Address: "aa:bb:cc:11:22:33",
		}}},
		{Rule: &api.FlowSpecRule_Mac{Mac: &api.FlowSpecMAC{
			Type:    16, // Destination MAC
			Address: "dd:ee:ff:11:22:33",
		}}},
		{Rule: &api.FlowSpecRule_Component{Component: &api.FlowSpecComponent{
			Type: 21, // VLAN ID
			Items: []*api.FlowSpecComponentItem{
				{
					Op:    0x80 | 0x01, // End, EQ
					Value: 100,
				},
			},
		}}},
	}
	nlris := []*api.NLRI{{Nlri: &api.NLRI_VpnFlowSpec{VpnFlowSpec: &api.VPNFlowSpecNLRI{
		Rd:    rd,
		Rules: rules,
	}}}}

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_L2VPN,
			Safi: api.Family_SAFI_FLOW_SPEC_VPN,
		},
		// NextHops: // No nexthop required
		Nlris: nlris,
	}

	a := &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.True(proto.Equal(input, output))
}

func Test_MpReachNLRIAttribute_IPv4_Opaque(t *testing.T) {
	assert := assert.New(t)

	nlris := []*api.NLRI{{Nlri: &api.NLRI_Opaque{Opaque: &api.OpaqueNLRI{
		Key:   []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f}, // hello
		Value: []byte{0x77, 0x6f, 0x72, 0x6c, 0x64}, // world
	}}}}

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_OPAQUE,
			Safi: api.Family_SAFI_KEY_VALUE,
		},
		NextHops: []string{"192.168.1.1"},
		Nlris:    nlris,
	}

	a := &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.True(proto.Equal(input, output))
}

func Test_MpReachNLRIAttribute_MUPInterworkSegmentDiscoveryRoute(t *testing.T) {
	assert := assert.New(t)

	rd := &api.RouteDistinguisher{Rd: &api.RouteDistinguisher_TwoOctetAsn{TwoOctetAsn: &api.RouteDistinguisherTwoOctetASN{
		Admin:    65000,
		Assigned: 100,
	}}}
	nlris := []*api.NLRI{{Nlri: &api.NLRI_MupInterworkSegmentDiscovery{MupInterworkSegmentDiscovery: &api.MUPInterworkSegmentDiscoveryRoute{
		Rd:     rd,
		Prefix: "10.0.0.0/24",
	}}}}

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_MUP,
		},
		NextHops: []string{"0.0.0.0"},
		Nlris:    nlris,
	}

	a := &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.True(proto.Equal(input, output))
}

func Test_MpReachNLRIAttribute_MUPDirectSegmentDiscoveryRoute(t *testing.T) {
	assert := assert.New(t)

	rd := &api.RouteDistinguisher{Rd: &api.RouteDistinguisher_TwoOctetAsn{TwoOctetAsn: &api.RouteDistinguisherTwoOctetASN{
		Admin:    65000,
		Assigned: 100,
	}}}
	nlris := []*api.NLRI{{Nlri: &api.NLRI_MupDirectSegmentDiscovery{MupDirectSegmentDiscovery: &api.MUPDirectSegmentDiscoveryRoute{
		Rd:      rd,
		Address: "10.0.0.1",
	}}}}

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_MUP,
		},
		NextHops: []string{"0.0.0.0"},
		Nlris:    nlris,
	}

	a := &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.True(proto.Equal(input, output))
}

func Test_MpReachNLRIAttribute_MUPType1SessionTransformedRoute(t *testing.T) {
	assert := assert.New(t)

	rd := &api.RouteDistinguisher{Rd: &api.RouteDistinguisher_TwoOctetAsn{TwoOctetAsn: &api.RouteDistinguisherTwoOctetASN{
		Admin:    65000,
		Assigned: 100,
	}}}
	tests := []struct {
		name string
		in   *api.MUPType1SessionTransformedRoute
	}{
		{
			name: "IPv4",
			in: &api.MUPType1SessionTransformedRoute{
				Rd:                    rd,
				Prefix:                "192.168.100.1/32",
				Teid:                  12345,
				Qfi:                   9,
				EndpointAddressLength: 32,
				EndpointAddress:       "10.0.0.1",
			},
		},
		{
			name: "IPv4_with_SourceAddress",
			in: &api.MUPType1SessionTransformedRoute{
				Rd:                    rd,
				Prefix:                "192.168.100.1/32",
				Teid:                  12345,
				Qfi:                   9,
				EndpointAddressLength: 32,
				EndpointAddress:       "10.0.0.1",
				SourceAddressLength:   32,
				SourceAddress:         "10.0.0.2",
			},
		},
	}
	for _, tt := range tests {
		nlris := []*api.NLRI{{Nlri: &api.NLRI_MupType_1SessionTransformed{MupType_1SessionTransformed: tt.in}}}

		input := &api.MpReachNLRIAttribute{
			Family: &api.Family{
				Afi:  api.Family_AFI_IP,
				Safi: api.Family_SAFI_MUP,
			},
			NextHops: []string{"0.0.0.0"},
			Nlris:    nlris,
		}

		a := &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: input}}
		n, err := UnmarshalAttribute(a)
		assert.NoError(err)

		output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
		assert.True(proto.Equal(input, output))
	}
}

func Test_MpReachNLRIAttribute_MUPType2SessionTransformedRoute(t *testing.T) {
	assert := assert.New(t)

	rd := &api.RouteDistinguisher{Rd: &api.RouteDistinguisher_TwoOctetAsn{TwoOctetAsn: &api.RouteDistinguisherTwoOctetASN{
		Admin:    65000,
		Assigned: 100,
	}}}
	nlris := []*api.NLRI{{Nlri: &api.NLRI_MupType_2SessionTransformed{MupType_2SessionTransformed: &api.MUPType2SessionTransformedRoute{
		Rd:                    rd,
		Teid:                  12345,
		EndpointAddressLength: 64,
		EndpointAddress:       "10.0.0.1",
	}}}}

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_MUP,
		},
		NextHops: []string{"0.0.0.0"},
		Nlris:    nlris,
	}

	a := &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.True(proto.Equal(input, output))
}

func Test_MpUnreachNLRIAttribute_IPv4_UC(t *testing.T) {
	assert := assert.New(t)

	nlris := []*api.NLRI{
		{Nlri: &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{
			PrefixLen: 24,
			Prefix:    "192.168.101.0",
		}}},
		{Nlri: &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{
			PrefixLen: 24,
			Prefix:    "192.168.201.0",
		}}},
	}

	input := &api.MpUnreachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_UNICAST,
		},
		Nlris: nlris,
	}

	a := &api.Attribute{Attr: &api.Attribute_MpUnreach{MpUnreach: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewMpUnreachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpUnreachNLRI))
	assert.True(proto.Equal(input, output))
}

func Test_ExtendedCommunitiesAttribute(t *testing.T) {
	assert := assert.New(t)

	communities := []*api.ExtendedCommunity{
		{Extcom: &api.ExtendedCommunity_TwoOctetAsSpecific{TwoOctetAsSpecific: &api.TwoOctetAsSpecificExtended{
			IsTransitive: true,
			SubType:      0x02, // ROUTE_TARGET
			Asn:          65001,
			LocalAdmin:   100,
		}}},
		{Extcom: &api.ExtendedCommunity_Ipv4AddressSpecific{Ipv4AddressSpecific: &api.IPv4AddressSpecificExtended{
			IsTransitive: true,
			SubType:      0x02, // ROUTE_TARGET
			Address:      "2.2.2.2",
			LocalAdmin:   200,
		}}},
		{Extcom: &api.ExtendedCommunity_FourOctetAsSpecific{FourOctetAsSpecific: &api.FourOctetAsSpecificExtended{
			IsTransitive: true,
			SubType:      0x02, // ROUTE_TARGET
			Asn:          65003,
			LocalAdmin:   300,
		}}},
		{Extcom: &api.ExtendedCommunity_Validation{Validation: &api.ValidationExtended{
			State: 0, // VALID
		}}},
		{Extcom: &api.ExtendedCommunity_Color{Color: &api.ColorExtended{
			Color: 400,
		}}},
		{Extcom: &api.ExtendedCommunity_Encap{Encap: &api.EncapExtended{
			TunnelType: 8, // VXLAN
		}}},
		{Extcom: &api.ExtendedCommunity_DefaultGateway{DefaultGateway: &api.DefaultGatewayExtended{
			// No value
		}}},
		{Extcom: &api.ExtendedCommunity_Opaque{Opaque: &api.OpaqueExtended{
			IsTransitive: true,
			Value:        []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77},
		}}},
		{Extcom: &api.ExtendedCommunity_EsiLabel{EsiLabel: &api.ESILabelExtended{
			IsSingleActive: true,
			Label:          500,
		}}},
		{Extcom: &api.ExtendedCommunity_EsImport{EsImport: &api.ESImportRouteTarget{
			EsImport: "aa:bb:cc:dd:ee:ff",
		}}},
		{Extcom: &api.ExtendedCommunity_MacMobility{MacMobility: &api.MacMobilityExtended{
			IsSticky:    true,
			SequenceNum: 1,
		}}},
		{Extcom: &api.ExtendedCommunity_RouterMac{RouterMac: &api.RouterMacExtended{
			Mac: "ff:ee:dd:cc:bb:aa",
		}}},
		{Extcom: &api.ExtendedCommunity_TrafficRate{TrafficRate: &api.TrafficRateExtended{
			Asn:  65004,
			Rate: 100.0,
		}}},
		{Extcom: &api.ExtendedCommunity_TrafficAction{TrafficAction: &api.TrafficActionExtended{
			Terminal: true,
			Sample:   false,
		}}},
		{Extcom: &api.ExtendedCommunity_RedirectTwoOctetAsSpecific{RedirectTwoOctetAsSpecific: &api.RedirectTwoOctetAsSpecificExtended{
			Asn:        65005,
			LocalAdmin: 500,
		}}},
		{Extcom: &api.ExtendedCommunity_RedirectIpv4AddressSpecific{RedirectIpv4AddressSpecific: &api.RedirectIPv4AddressSpecificExtended{
			Address:    "6.6.6.6",
			LocalAdmin: 600,
		}}},
		{Extcom: &api.ExtendedCommunity_RedirectFourOctetAsSpecific{RedirectFourOctetAsSpecific: &api.RedirectFourOctetAsSpecificExtended{
			Asn:        65007,
			LocalAdmin: 700,
		}}},
		{Extcom: &api.ExtendedCommunity_TrafficRemark{TrafficRemark: &api.TrafficRemarkExtended{
			Dscp: 0x0a, // AF11
		}}},
		{Extcom: &api.ExtendedCommunity_Mup{Mup: &api.MUPExtended{
			SegmentId2: 10,
			SegmentId4: 100,
		}}},
		{Extcom: &api.ExtendedCommunity_Unknown{Unknown: &api.UnknownExtended{
			Type:  0xff, // Max of uint8
			Value: []byte{1, 2, 3, 4, 5, 6, 7},
		}}},
		{Extcom: &api.ExtendedCommunity_LinkBandwidth{LinkBandwidth: &api.LinkBandwidthExtended{
			Asn:       65004,
			Bandwidth: 125000.0,
		}}},
		{Extcom: &api.ExtendedCommunity_Vpls{Vpls: &api.VPLSExtended{
			ControlFlags: 0x00,
			Mtu:          1500,
		}}},
		{Extcom: &api.ExtendedCommunity_Etree{Etree: &api.ETreeExtended{
			IsLeaf: true,
			Label:  5001,
		}}},
		{Extcom: &api.ExtendedCommunity_MulticastFlags{MulticastFlags: &api.MulticastFlagsExtended{
			IsIgmpProxy: true,
			IsMldProxy:  false,
		}}},
	}

	input := &api.ExtendedCommunitiesAttribute{
		Communities: communities,
	}

	a := &api.Attribute{Attr: &api.Attribute_ExtendedCommunities{ExtendedCommunities: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewExtendedCommunitiesAttributeFromNative(n.(*bgp.PathAttributeExtendedCommunities))
	assert.True(proto.Equal(input, output))
}

func Test_As4PathAttribute(t *testing.T) {
	assert := assert.New(t)

	input := &api.As4PathAttribute{
		Segments: []*api.AsSegment{
			{
				Type:    1, // SET
				Numbers: []uint32{100, 200},
			},
			{
				Type:    2, // SEQ
				Numbers: []uint32{300, 400},
			},
		},
	}

	a := &api.Attribute{Attr: &api.Attribute_As4Path{As4Path: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewAs4PathAttributeFromNative(n.(*bgp.PathAttributeAs4Path))
	assert.True(proto.Equal(input, output))
}

func Test_As4AggregatorAttribute(t *testing.T) {
	assert := assert.New(t)

	input := &api.As4AggregatorAttribute{
		Asn:     65000,
		Address: "1.1.1.1",
	}

	a := &api.Attribute{Attr: &api.Attribute_As4Aggregator{As4Aggregator: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewAs4AggregatorAttributeFromNative(n.(*bgp.PathAttributeAs4Aggregator))
	assert.True(proto.Equal(input, output))
}

func Test_PmsiTunnelAttribute(t *testing.T) {
	assert := assert.New(t)

	input := &api.PmsiTunnelAttribute{
		Flags: 0x01, // IsLeafInfoRequired = true
		Type:  6,    // INGRESS_REPL
		Label: 100,
		Id:    netip.MustParseAddr("1.1.1.1").AsSlice(), // IngressReplTunnelID with IPv4
	}

	a := &api.Attribute{Attr: &api.Attribute_PmsiTunnel{PmsiTunnel: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewPmsiTunnelAttributeFromNative(n.(*bgp.PathAttributePmsiTunnel))
	assert.True(proto.Equal(input, output))
}

func Test_TunnelEncapAttribute(t *testing.T) {
	assert := assert.New(t)

	subTlvs := []*api.TunnelEncapTLV_TLV{
		{Tlv: &api.TunnelEncapTLV_TLV_Encapsulation{Encapsulation: &api.TunnelEncapSubTLVEncapsulation{
			Key:    100,
			Cookie: []byte{0x11, 0x22, 0x33, 0x44},
		}}},
		{Tlv: &api.TunnelEncapTLV_TLV_Protocol{Protocol: &api.TunnelEncapSubTLVProtocol{
			Protocol: 200,
		}}},
		{Tlv: &api.TunnelEncapTLV_TLV_Color{Color: &api.TunnelEncapSubTLVColor{
			Color: 300,
		}}},
		{Tlv: &api.TunnelEncapTLV_TLV_UdpDestPort{UdpDestPort: &api.TunnelEncapSubTLVUDPDestPort{
			Port: 400,
		}}},
		{Tlv: &api.TunnelEncapTLV_TLV_Unknown{Unknown: &api.TunnelEncapSubTLVUnknown{
			Type:  0xff, // Max of uint8
			Value: []byte{0x55, 0x66, 0x77, 0x88},
		}}},
	}

	input := &api.TunnelEncapAttribute{
		Tlvs: []*api.TunnelEncapTLV{
			{
				Type: 8, // VXLAN
				Tlvs: subTlvs,
			},
		},
	}
	a := &api.Attribute{Attr: &api.Attribute_TunnelEncap{TunnelEncap: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewTunnelEncapAttributeFromNative(n.(*bgp.PathAttributeTunnelEncap))
	assert.True(proto.Equal(input, output))
}

func Test_IP6ExtendedCommunitiesAttribute(t *testing.T) {
	assert := assert.New(t)

	communities := []*api.IP6ExtendedCommunitiesAttribute_Community{
		{Extcom: &api.IP6ExtendedCommunitiesAttribute_Community_Ipv6AddressSpecific{
			Ipv6AddressSpecific: &api.IPv6AddressSpecificExtended{
				IsTransitive: true,
				SubType:      0xff, // Max of uint8
				Address:      "2001:db8:1::1",
				LocalAdmin:   100,
			},
		}},
		{Extcom: &api.IP6ExtendedCommunitiesAttribute_Community_RedirectIpv6AddressSpecific{
			RedirectIpv6AddressSpecific: &api.RedirectIPv6AddressSpecificExtended{
				Address:    "2001:db8:2::1",
				LocalAdmin: 200,
			},
		}},
	}

	input := &api.IP6ExtendedCommunitiesAttribute{
		Communities: communities,
	}

	a := &api.Attribute{Attr: &api.Attribute_Ip6ExtendedCommunities{Ip6ExtendedCommunities: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewIP6ExtendedCommunitiesAttributeFromNative(n.(*bgp.PathAttributeIP6ExtendedCommunities))
	assert.True(proto.Equal(input, output))
}

func Test_AigpAttribute(t *testing.T) {
	assert := assert.New(t)

	tlvs := []*api.AigpAttribute_TLV{
		{Tlv: &api.AigpAttribute_TLV_IgpMetric{IgpMetric: &api.AigpTLVIGPMetric{
			Metric: 50,
		}}},
		{Tlv: &api.AigpAttribute_TLV_Unknown{Unknown: &api.AigpTLVUnknown{
			Type:  0xff, // Max of uint8
			Value: []byte{0x11, 0x22, 0x33, 0x44},
		}}},
	}

	input := &api.AigpAttribute{
		Tlvs: tlvs,
	}

	a := &api.Attribute{Attr: &api.Attribute_Aigp{Aigp: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewAigpAttributeFromNative(n.(*bgp.PathAttributeAigp))
	assert.True(proto.Equal(input, output))
}

func Test_LargeCommunitiesAttribute(t *testing.T) {
	assert := assert.New(t)

	input := &api.LargeCommunitiesAttribute{
		Communities: []*api.LargeCommunity{
			{
				GlobalAdmin: 65001,
				LocalData1:  100,
				LocalData2:  200,
			},
			{
				GlobalAdmin: 65002,
				LocalData1:  300,
				LocalData2:  400,
			},
		},
	}

	a := &api.Attribute{Attr: &api.Attribute_LargeCommunities{LargeCommunities: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewLargeCommunitiesAttributeFromNative(n.(*bgp.PathAttributeLargeCommunities))
	assert.True(proto.Equal(input, output))
}

func Test_UnknownAttribute(t *testing.T) {
	assert := assert.New(t)

	input := &api.UnknownAttribute{
		Flags: 1<<6 | 1<<7,
		Type:  0xff,
		Value: []byte{0x11, 0x22, 0x33, 0x44},
	}

	a := &api.Attribute{Attr: &api.Attribute_Unknown{Unknown: input}}
	n, err := UnmarshalAttribute(a)
	assert.NoError(err)

	output, _ := NewUnknownAttributeFromNative(n.(*bgp.PathAttributeUnknown))
	assert.True(proto.Equal(input, output))
}

func TestFullCyclePrefixSID(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "srv6 prefix sid",
			input: []byte{0xc0, 0x28, 0x25, 0x05, 0x00, 0x22, 0x00, 0x01, 0x00, 0x1e, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x01, 0x00, 0x06, 0x28, 0x18, 0x10, 0x00, 0x10, 0x40},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attribute := bgp.PathAttributePrefixSID{}
			if err := attribute.DecodeFromBytes(tt.input); err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			// Converting from Native to API
			apiPrefixSID, err := NewPrefixSIDAttributeFromNative(&attribute)
			if err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			// Converting back from API to Native
			recoveredPrefixSID, err := UnmarshalPrefixSID(apiPrefixSID)
			if err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			if recoveredPrefixSID.Len() != attribute.Len() {
				t.Fatalf("recovered attribute length (%d) is not matching original attribute length (%d)", recoveredPrefixSID.Len(), attribute.Len())
			}
			recovered, err := recoveredPrefixSID.Serialize()
			if err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			if !bytes.Equal(tt.input, recovered) {
				t.Fatalf("round trip conversion test failed as expected prefix sid attribute %+v does not match actual: %+v", tt.input, recovered)
			}
		})
	}
}

func TestFullCycleSRv6SIDStructureSubSubTLV(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "srv6 prefix sid",
			input: []byte{0x01, 0x00, 0x06, 0x28, 0x18, 0x10, 0x00, 0x10, 0x40},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sstlv := bgp.SRv6SIDStructureSubSubTLV{}
			if err := sstlv.DecodeFromBytes(tt.input); err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			// Converting from Native to API
			apiPrefixSID, _ := MarshalSRv6SubSubTLVs([]bgp.PrefixSIDTLVInterface{&sstlv})
			// Converting back from API to Native
			_, recoveredPrefixSID, err := UnmarshalSubSubTLVs(apiPrefixSID)
			if err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			recovered, err := recoveredPrefixSID[0].Serialize()
			if err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			if !bytes.Equal(tt.input, recovered) {
				t.Fatalf("round trip conversion test failed as expected prefix sid attribute %+v does not match actual: %+v", tt.input, recovered)
			}
		})
	}
}

func TestFullCycleSRv6InformationSubTLV(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "srv6 prefix sid informationw sub tlv",
			input: []byte{0x01, 0x00, 0x1e, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x01, 0x00, 0x06, 0x28, 0x18, 0x10, 0x00, 0x10, 0x40},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stlv := bgp.SRv6InformationSubTLV{}
			if err := stlv.DecodeFromBytes(tt.input); err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			// Converting from Native to API
			apiPrefixSID, _ := MarshalSRv6SubTLVs([]bgp.PrefixSIDTLVInterface{&stlv})
			// Converting back from API to Native
			_, recoveredPrefixSID, err := UnmarshalSubTLVs(apiPrefixSID)
			if err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			recovered, err := recoveredPrefixSID[0].Serialize()
			if err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			if !bytes.Equal(tt.input, recovered) {
				t.Fatalf("round trip conversion test failed as expected prefix sid attribute %+v does not match actual: %+v", tt.input, recovered)
			}
		})
	}
}
