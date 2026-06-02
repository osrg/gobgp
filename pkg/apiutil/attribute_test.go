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
	"github.com/stretchr/testify/require"
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

func Test_LsAttributeDelayMetricRoundTrip(t *testing.T) {
	assert := assert.New(t)

	input := &api.LsAttribute{
		Link: &api.LsAttributeLink{
			UnidirectionalLinkDelayAnomalous:       true,
			UnidirectionalLinkDelay:                8516,
			MinMaxUnidirectionalLinkDelayAnomalous: true,
			MinUnidirectionalLinkDelay:             8511,
			MaxUnidirectionalLinkDelay:             8527,
			UnidirectionalDelayVariation:           51,
		},
	}

	native, err := UnmarshalLsAttribute(input)
	assert.NoError(err)

	if assert.NotNil(native.Link.UnidirectionalLinkDelay) {
		assert.True(native.Link.UnidirectionalLinkDelay.Flags.Anomalous)
		assert.Equal(uint32(8516), native.Link.UnidirectionalLinkDelay.Delay)
	}

	if assert.NotNil(native.Link.MinMaxUnidirectionalLinkDelay) {
		assert.True(native.Link.MinMaxUnidirectionalLinkDelay.Flags.Anomalous)
		assert.Equal(uint32(8511), native.Link.MinMaxUnidirectionalLinkDelay.MinDelay)
		assert.Equal(uint32(8527), native.Link.MinMaxUnidirectionalLinkDelay.MaxDelay)
	}

	if assert.NotNil(native.Link.UnidirectionalDelayVariation) {
		assert.Equal(uint32(51), *native.Link.UnidirectionalDelayVariation)
	}

	pathAttrLs := &bgp.PathAttributeLs{
		TLVs: bgp.NewLsAttributeTLVs(native),
	}
	output, err := NewLsAttributeFromNative(pathAttrLs)
	assert.NoError(err)
	if assert.NotNil(output.Link) {
		assert.True(output.Link.UnidirectionalLinkDelayAnomalous)
		assert.Equal(uint32(8516), output.Link.UnidirectionalLinkDelay)
		assert.True(output.Link.MinMaxUnidirectionalLinkDelayAnomalous)
		assert.Equal(uint32(8511), output.Link.MinUnidirectionalLinkDelay)
		assert.Equal(uint32(8527), output.Link.MaxUnidirectionalLinkDelay)
		assert.Equal(uint32(51), output.Link.UnidirectionalDelayVariation)
	}
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

func Test_MpReachNLRIAttribute_EVPN_MAC_IP_Route_MacOnly(t *testing.T) {
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
			IpAddress:   "",
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

func TestUnmarshalSRSegments_NilFlags(t *testing.T) {
	// Flags is an optional protobuf sub-message. A caller that builds
	// api.SegmentTypeA or api.SegmentTypeB without setting Flags must
	// not cause a nil pointer dereference; the result should be all-zero
	// flag bits.
	t.Run("SegmentTypeA_nil_flags", func(t *testing.T) {
		segs := []*api.TunnelEncapSubTLVSRSegmentList_Segment{
			{Segment: &api.TunnelEncapSubTLVSRSegmentList_Segment_A{
				A: &api.SegmentTypeA{Label: 100},
				// Flags intentionally omitted (nil)
			}},
		}
		result, err := UnmarshalSRSegments(segs)
		assert.NoError(t, err)
		require.Len(t, result, 1)
		seg, ok := result[0].(*bgp.SegmentTypeA)
		require.True(t, ok)
		assert.Equal(t, uint32(100), seg.Label)
		assert.Equal(t, uint8(0), seg.Flags)
	})

	t.Run("SegmentTypeB_nil_flags", func(t *testing.T) {
		sid := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
		segs := []*api.TunnelEncapSubTLVSRSegmentList_Segment{
			{Segment: &api.TunnelEncapSubTLVSRSegmentList_Segment_B{
				B: &api.SegmentTypeB{Sid: sid},
				// Flags intentionally omitted (nil)
			}},
		}
		result, err := UnmarshalSRSegments(segs)
		assert.NoError(t, err)
		require.Len(t, result, 1)
		seg, ok := result[0].(*bgp.SegmentTypeB)
		require.True(t, ok)
		assert.Equal(t, sid, seg.SID)
		assert.Equal(t, uint8(0), seg.Flags)
	})
}

func TestUnmarshalSRSegments_RoundTrip(t *testing.T) {
	t.Run("SegmentTypeA", func(t *testing.T) {
		orig := []bgp.TunnelEncapSubTLVInterface{
			&bgp.SegmentTypeA{
				TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{Type: bgp.EncapSubTLVType(bgp.TypeA), Length: 6},
				Label:             200,
				Flags:             0x80 | 0x10, // VFlag + BFlag
			},
		}
		marshaled, err := MarshalSRSegments(orig)
		require.NoError(t, err)
		result, err := UnmarshalSRSegments(marshaled)
		require.NoError(t, err)
		require.Len(t, result, 1)
		seg, ok := result[0].(*bgp.SegmentTypeA)
		require.True(t, ok)
		assert.Equal(t, uint32(200), seg.Label)
		assert.Equal(t, uint8(0x80|0x10), seg.Flags)
	})

	t.Run("SegmentTypeB", func(t *testing.T) {
		sid := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
		orig := []bgp.TunnelEncapSubTLVInterface{
			&bgp.SegmentTypeB{
				TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{Type: bgp.EncapSubTLVType(bgp.TypeB), Length: 18},
				SID:               sid,
				Flags:             0x40 | 0x20, // AFlag + SFlag
			},
		}
		marshaled, err := MarshalSRSegments(orig)
		require.NoError(t, err)
		result, err := UnmarshalSRSegments(marshaled)
		require.NoError(t, err)
		require.Len(t, result, 1)
		seg, ok := result[0].(*bgp.SegmentTypeB)
		require.True(t, ok)
		assert.Equal(t, sid, seg.SID)
		assert.Equal(t, uint8(0x40|0x20), seg.Flags)
	})

	t.Run("SegmentTypeB_with_SRv6EBS", func(t *testing.T) {
		sid := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
		orig := []bgp.TunnelEncapSubTLVInterface{
			&bgp.SegmentTypeB{
				TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{Type: bgp.EncapSubTLVType(bgp.TypeB), Length: 18},
				SID:               sid,
				Flags:             0x80,
				SRv6EBS: &bgp.SRv6EndpointBehaviorStructure{
					Behavior: bgp.END,
					BlockLen: 40,
					NodeLen:  24,
					FuncLen:  16,
					ArgLen:   0,
				},
			},
		}
		marshaled, err := MarshalSRSegments(orig)
		require.NoError(t, err)
		result, err := UnmarshalSRSegments(marshaled)
		require.NoError(t, err)
		require.Len(t, result, 1)
		seg, ok := result[0].(*bgp.SegmentTypeB)
		require.True(t, ok)
		assert.Equal(t, sid, seg.SID)
		assert.Equal(t, uint8(0x80), seg.Flags)
		require.NotNil(t, seg.SRv6EBS)
		assert.Equal(t, bgp.END, seg.SRv6EBS.Behavior)
		assert.Equal(t, uint8(40), seg.SRv6EBS.BlockLen)
		assert.Equal(t, uint8(24), seg.SRv6EBS.NodeLen)
		assert.Equal(t, uint8(16), seg.SRv6EBS.FuncLen)
	})
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

// TestFullCycleFlexAlgoDefAndFAPM exercises the api <-> packet
// round-trip for the RFC 9351 Flex-Algorithm Definition (FAD) Node
// Attribute TLV and the FAPM (Prefix Attribute TLV 1044). The packet
// layer round-trip is covered in pkg/packet/bgp; here we confirm the
// apiutil mapping preserves every field on the way from bgp.LsAttribute
// down to api.LsAttribute and back.
func TestFullCycleFlexAlgoDefAndFAPM(t *testing.T) {
	srgbStart := uint32(16000)

	// Build a synthetic PathAttributeLs whose Extract output already
	// carries the FAD + multi-SID + FAPM fields we want to surface.
	// We bypass the wire by hand-building the TLV slice; the goal is
	// to drive NewLsAttributeFromNative and UnmarshalLsAttribute.
	tlvs := []bgp.LsTLVInterface{
		&bgp.LsTLVFlexAlgoDef{
			LsTLV:       bgp.LsTLV{Type: bgp.LS_TLV_FLEX_ALGO_DEF},
			Algorithm:   128,
			MetricType:  1, // Min-Delay
			CalcType:    0,
			Priority:    200,
			ExcludeAny:  []uint32{0x0F},
			IncludeAny:  []uint32{0xF0},
			IncludeAll:  []uint32{0xAA},
			Flags:       []byte{0x80, 0x00, 0x00, 0x00},
			ExcludeSRLG: []uint32{42, 43},
		},
		&bgp.LsTLVPrefixSID{
			LsTLV:     bgp.LsTLV{Type: bgp.LS_TLV_PREFIX_SID},
			Algorithm: 0,
			Flags:     0,
			SID:       srgbStart + 1,
		},
		&bgp.LsTLVPrefixSID{
			LsTLV:     bgp.LsTLV{Type: bgp.LS_TLV_PREFIX_SID},
			Algorithm: 128,
			Flags:     0x08,
			SID:       srgbStart + 128,
		},
		&bgp.LsTLVFADPrefixMetric{
			LsTLV:     bgp.LsTLV{Type: bgp.LS_TLV_FAD_PREFIX_METRIC},
			Algorithm: 128,
			Flags:     0,
			Metric:    10000,
		},
	}
	pa := &bgp.PathAttributeLs{TLVs: tlvs}

	apiAttr, err := NewLsAttributeFromNative(pa)
	require.NoError(t, err)
	require.NotNil(t, apiAttr)

	require.Len(t, apiAttr.Node.FlexAlgoDefs, 1)
	fad := apiAttr.Node.FlexAlgoDefs[0]
	assert.Equal(t, uint32(128), fad.Algorithm)
	assert.Equal(t, uint32(1), fad.MetricType)
	assert.True(t, fad.MetricTypeKnown)
	assert.Equal(t, uint32(200), fad.Priority)
	assert.Equal(t, []uint32{0x0F}, fad.ExcludeAnyAffinity)
	assert.Equal(t, []uint32{0xF0}, fad.IncludeAnyAffinity)
	assert.Equal(t, []uint32{0xAA}, fad.IncludeAllAffinity)
	assert.Equal(t, []byte{0x80, 0x00, 0x00, 0x00}, fad.DefinitionFlags)
	assert.Equal(t, []uint32{42, 43}, fad.ExcludeSrlg)

	require.Len(t, apiAttr.Prefix.SrPrefixSids, 2)
	assert.Equal(t, uint32(0), apiAttr.Prefix.SrPrefixSids[0].Algorithm)
	assert.Equal(t, srgbStart+1, apiAttr.Prefix.SrPrefixSids[0].Sid)
	assert.Equal(t, uint32(128), apiAttr.Prefix.SrPrefixSids[1].Algorithm)
	assert.Equal(t, uint32(0x08), apiAttr.Prefix.SrPrefixSids[1].Flags)
	assert.Equal(t, srgbStart+128, apiAttr.Prefix.SrPrefixSids[1].Sid)
	// Singular field still populated for the Algorithm-0 SID.
	assert.Equal(t, srgbStart+1, apiAttr.Prefix.SrPrefixSid)

	require.Len(t, apiAttr.Prefix.FadPrefixMetrics, 1)
	assert.Equal(t, uint32(128), apiAttr.Prefix.FadPrefixMetrics[0].Algorithm)
	assert.Equal(t, uint32(10000), apiAttr.Prefix.FadPrefixMetrics[0].Metric)

	// proto round-trip: marshal + unmarshal must preserve byte-for-byte.
	enc, err := proto.Marshal(apiAttr)
	require.NoError(t, err)
	clone := &api.LsAttribute{}
	require.NoError(t, proto.Unmarshal(enc, clone))
	assert.True(t, proto.Equal(apiAttr, clone))

	// api -> bgp rehydration: every FAD / SID / FAPM field round-trips.
	back, err := UnmarshalLsAttribute(clone)
	require.NoError(t, err)
	require.Len(t, back.Node.FlexAlgoDefs, 1)
	assert.Equal(t, uint8(128), back.Node.FlexAlgoDefs[0].Algorithm)
	assert.Equal(t, uint8(1), back.Node.FlexAlgoDefs[0].MetricType)
	assert.Equal(t, []uint32{42, 43}, back.Node.FlexAlgoDefs[0].ExcludeSRLG)
	require.Len(t, back.Prefix.SrPrefixSIDs, 2)
	assert.Equal(t, uint8(128), back.Prefix.SrPrefixSIDs[1].Algorithm)
	assert.Equal(t, srgbStart+128, back.Prefix.SrPrefixSIDs[1].SID)
	require.Len(t, back.Prefix.FadPrefixMetrics, 1)
	assert.Equal(t, uint32(10000), back.Prefix.FadPrefixMetrics[0].Metric)
}

// TestFlexAlgo_FullWirePath drives the full RFC 9351 / RFC 9085
// path end-to-end:
//
//   wire bytes -> PathAttributeLs.DecodeFromBytes
//              -> Extract                 (structured fields)
//              -> NewLsAttributeFromNative (api projection)
//              -> proto.Marshal + proto.Unmarshal
//              -> UnmarshalLsAttribute     (rehydrate bgp.LsAttribute)
//              -> Serialize                (back to wire bytes)
//
// The fixture is a hand-built BGP-LS Attribute (MP_REACH stripped, we
// only test the attribute payload) carrying a Flex-Algo Definition
// (TLV 1039 with three nested sub-TLVs), two Prefix-SID TLVs (algo 0
// and algo 128) and one FAPM (TLV 1044). Every structured field on
// the way out matches the wire bytes on the way in.
func TestFlexAlgo_FullWirePath(t *testing.T) {
	const (
		srgbStart = uint32(16000)
	)

	// MP_REACH_NLRI is omitted; we test PathAttributeLs payload only.
	// Outer wrapper: flags 0x80 (Optional, Non-Transitive,
	// non-extended), type 41 (BGP_ATTR_TYPE_LS), 1-byte length.
	body := []byte{
		// TLV 1039 FAD, length 28 (4-byte fixed header + three
		// 8-byte sub-TLVs):
		//   algo=128 metric=0 (IGP) calc=0 (SPF) prio=200
		//   sub-TLV 1040 Exclude-Any 0x0000000F
		//   sub-TLV 1041 Include-Any 0x000000F0
		//   sub-TLV 1043 Definition Flags 0x80000000
		0x04, 0x0F, 0x00, 0x1C,
		0x80, 0x00, 0x00, 0xC8,
		0x04, 0x10, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0F,
		0x04, 0x11, 0x00, 0x04, 0x00, 0x00, 0x00, 0xF0,
		0x04, 0x13, 0x00, 0x04, 0x80, 0x00, 0x00, 0x00,

		// TLV 1158 Prefix-SID algo 0 (default SPF), SID 16001 in
		// 8-byte (4-byte SID) form: flags + algo + 2B reserved + 4B SID.
		0x04, 0x86, 0x00, 0x08,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x3E, 0x81,

		// TLV 1158 Prefix-SID algo 128, V-flag set (absolute label),
		// SID 16128 in 8-byte form.
		0x04, 0x86, 0x00, 0x08,
		0x08, 0x80, 0x00, 0x00,
		0x00, 0x00, 0x3F, 0x00,

		// TLV 1044 FAPM (Flexible Algorithm Prefix Metric): algo 128
		// metric 10000 (0x2710), flags 0, reserved 0.
		0x04, 0x14, 0x00, 0x08,
		0x80, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x27, 0x10,
	}
	hdr := []byte{0x80, 0x29, byte(len(body))}
	wire := append([]byte{}, hdr...)
	wire = append(wire, body...)

	// Decode the wire bytes into the structured PathAttributeLs.
	pa := &bgp.PathAttributeLs{}
	require.NoError(t, pa.DecodeFromBytes(wire))

	// Extract the structured LsAttribute and check every field.
	ls := pa.Extract()
	require.Len(t, ls.Node.FlexAlgoDefs, 1)
	fad := ls.Node.FlexAlgoDefs[0]
	assert.Equal(t, uint8(128), fad.Algorithm)
	assert.Equal(t, uint8(0), fad.MetricType)
	assert.True(t, fad.MetricTypeKnown)
	assert.Equal(t, uint8(0), fad.CalcType)
	assert.Equal(t, uint8(200), fad.Priority)
	assert.Equal(t, []uint32{0x0F}, fad.ExcludeAny)
	assert.Equal(t, []uint32{0xF0}, fad.IncludeAny)
	assert.Equal(t, []byte{0x80, 0x00, 0x00, 0x00}, fad.Flags)

	require.Len(t, ls.Prefix.SrPrefixSIDs, 2)
	assert.Equal(t, uint8(0), ls.Prefix.SrPrefixSIDs[0].Algorithm)
	assert.Equal(t, srgbStart+1, ls.Prefix.SrPrefixSIDs[0].SID)
	assert.Equal(t, uint8(128), ls.Prefix.SrPrefixSIDs[1].Algorithm)
	assert.Equal(t, uint8(0x08), ls.Prefix.SrPrefixSIDs[1].Flags)
	assert.Equal(t, srgbStart+128, ls.Prefix.SrPrefixSIDs[1].SID)
	require.NotNil(t, ls.Prefix.SrPrefixSID)
	assert.Equal(t, srgbStart+1, *ls.Prefix.SrPrefixSID)

	require.Len(t, ls.Prefix.FadPrefixMetrics, 1)
	assert.Equal(t, uint8(128), ls.Prefix.FadPrefixMetrics[0].Algorithm)
	assert.Equal(t, uint32(10000), ls.Prefix.FadPrefixMetrics[0].Metric)

	// Cross the apiutil boundary in both directions.
	apiAttr, err := NewLsAttributeFromNative(pa)
	require.NoError(t, err)
	require.Len(t, apiAttr.Node.FlexAlgoDefs, 1)
	require.Len(t, apiAttr.Prefix.SrPrefixSids, 2)
	require.Len(t, apiAttr.Prefix.FadPrefixMetrics, 1)

	enc, err := proto.Marshal(apiAttr)
	require.NoError(t, err)
	clone := &api.LsAttribute{}
	require.NoError(t, proto.Unmarshal(enc, clone))
	assert.True(t, proto.Equal(apiAttr, clone))

	back, err := UnmarshalLsAttribute(clone)
	require.NoError(t, err)
	require.Len(t, back.Node.FlexAlgoDefs, 1)
	assert.Equal(t, uint8(128), back.Node.FlexAlgoDefs[0].Algorithm)
	require.Len(t, back.Prefix.SrPrefixSIDs, 2)
	assert.Equal(t, srgbStart+128, back.Prefix.SrPrefixSIDs[1].SID)
	require.Len(t, back.Prefix.FadPrefixMetrics, 1)

	// Re-serialise the original PathAttributeLs (its TLV slice still
	// carries the original wire-shaped sub-TLVs) and confirm the
	// byte sequence matches the input. This is the strongest
	// regression signal against silent re-encoding drift.
	out, err := pa.Serialize()
	require.NoError(t, err)
	assert.True(t, bytes.Equal(wire, out),
		"wire bytes round-trip mismatch:\n  in: % x\n out: % x", wire, out)
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
