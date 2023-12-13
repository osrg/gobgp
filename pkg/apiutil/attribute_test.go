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
	"net"
	"testing"

	"google.golang.org/protobuf/proto"
	apb "google.golang.org/protobuf/types/known/anypb"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
)

func Test_OriginAttribute(t *testing.T) {
	assert := assert.New(t)

	input := &api.OriginAttribute{
		Origin: 0, // IGP
	}
	a, err := apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

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

	a, err := apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewAsPathAttributeFromNative(n.(*bgp.PathAttributeAsPath))
	assert.Equal(2, len(output.Segments))
	for i := 0; i < 2; i++ {
		assert.True(proto.Equal(input.Segments[i], output.Segments[i]))
	}
}

func Test_NextHopAttribute(t *testing.T) {
	assert := assert.New(t)

	input := &api.NextHopAttribute{
		NextHop: "192.168.0.1",
	}

	a, err := apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewNextHopAttributeFromNative(n.(*bgp.PathAttributeNextHop))
	assert.Equal(input.NextHop, output.NextHop)
}

func Test_MultiExitDiscAttribute(t *testing.T) {
	assert := assert.New(t)

	input := &api.MultiExitDiscAttribute{
		Med: 100,
	}

	a, err := apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewMultiExitDiscAttributeFromNative(n.(*bgp.PathAttributeMultiExitDisc))
	assert.Equal(input.Med, output.Med)
}

func Test_LocalPrefAttribute(t *testing.T) {
	assert := assert.New(t)

	input := &api.LocalPrefAttribute{
		LocalPref: 100,
	}

	a, err := apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewLocalPrefAttributeFromNative(n.(*bgp.PathAttributeLocalPref))
	assert.Equal(input.LocalPref, output.LocalPref)
}

func Test_AtomicAggregateAttribute(t *testing.T) {
	assert := assert.New(t)

	input := &api.AtomicAggregateAttribute{}

	a, err := apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

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

	a, err := apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewAggregatorAttributeFromNative(n.(*bgp.PathAttributeAggregator))
	assert.Equal(input.Asn, output.Asn)
	assert.Equal(input.Address, output.Address)
}

func Test_CommunitiesAttribute(t *testing.T) {
	assert := assert.New(t)

	input := &api.CommunitiesAttribute{
		Communities: []uint32{100, 200},
	}

	a, err := apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewCommunitiesAttributeFromNative(n.(*bgp.PathAttributeCommunities))
	assert.Equal(input.Communities, output.Communities)
}

func Test_OriginatorIdAttribute(t *testing.T) {
	assert := assert.New(t)

	input := &api.OriginatorIdAttribute{
		Id: "1.1.1.1",
	}

	a, err := apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewOriginatorIdAttributeFromNative(n.(*bgp.PathAttributeOriginatorId))
	assert.Equal(input.Id, output.Id)
}

func Test_ClusterListAttribute(t *testing.T) {
	assert := assert.New(t)

	input := &api.ClusterListAttribute{
		Ids: []string{"1.1.1.1", "2.2.2.2"},
	}

	a, err := apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewClusterListAttributeFromNative(n.(*bgp.PathAttributeClusterList))
	assert.Equal(input.Ids, output.Ids)
}

func Test_MpReachNLRIAttribute_IPv4_UC(t *testing.T) {
	assert := assert.New(t)

	nlris := make([]*apb.Any, 0, 2)
	a, err := apb.New(&api.IPAddressPrefix{
		PrefixLen: 24,
		Prefix:    "192.168.101.0",
	})
	assert.Nil(err)
	nlris = append(nlris, a)
	a, err = apb.New(&api.IPAddressPrefix{
		PrefixLen: 24,
		Prefix:    "192.168.201.0",
	})
	assert.Nil(err)
	nlris = append(nlris, a)

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_UNICAST,
		},
		NextHops: []string{"192.168.1.1"},
		Nlris:    nlris,
	}

	a, err = apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.Equal(input.Family.Afi, output.Family.Afi)
	assert.Equal(input.Family.Safi, output.Family.Safi)
	assert.Equal(input.NextHops, output.NextHops)
	assert.Equal(2, len(output.Nlris))
	for idx, inputNLRI := range input.Nlris {
		outputNLRI := output.Nlris[idx]
		assert.Equal(inputNLRI.TypeUrl, outputNLRI.TypeUrl)
		assert.Equal(inputNLRI.Value, outputNLRI.Value)
	}
}

func Test_MpReachNLRIAttribute_IPv6_UC(t *testing.T) {
	assert := assert.New(t)

	nlris := make([]*apb.Any, 0, 2)
	a, err := apb.New(&api.IPAddressPrefix{
		PrefixLen: 64,
		Prefix:    "2001:db8:1::",
	})
	assert.Nil(err)
	nlris = append(nlris, a)
	a, err = apb.New(&api.IPAddressPrefix{
		PrefixLen: 64,
		Prefix:    "2001:db8:2::",
	})
	assert.Nil(err)
	nlris = append(nlris, a)

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP6,
			Safi: api.Family_SAFI_UNICAST,
		},
		NextHops: []string{"2001:db8::1", "fe80::1"},
		Nlris:    nlris,
	}

	a, err = apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.Equal(input.Family.Afi, output.Family.Afi)
	assert.Equal(input.Family.Safi, output.Family.Safi)
	assert.Equal(input.NextHops, output.NextHops)
	assert.Equal(2, len(output.Nlris))
	for idx, inputNLRI := range input.Nlris {
		outputNLRI := output.Nlris[idx]
		assert.Equal(inputNLRI.TypeUrl, outputNLRI.TypeUrl)
		assert.Equal(inputNLRI.Value, outputNLRI.Value)
	}
}

func Test_MpReachNLRIAttribute_IPv4_MPLS(t *testing.T) {
	assert := assert.New(t)

	nlris := make([]*apb.Any, 0, 2)
	a, err := apb.New(&api.LabeledIPAddressPrefix{
		Labels:    []uint32{100},
		PrefixLen: 24,
		Prefix:    "192.168.101.0",
	})
	assert.Nil(err)
	nlris = append(nlris, a)
	a, err = apb.New(&api.LabeledIPAddressPrefix{
		Labels:    []uint32{200},
		PrefixLen: 24,
		Prefix:    "192.168.201.0",
	})
	assert.Nil(err)
	nlris = append(nlris, a)

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_MPLS_LABEL,
		},
		NextHops: []string{"192.168.1.1"},
		Nlris:    nlris,
	}

	a, err = apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.Equal(input.Family.Afi, output.Family.Afi)
	assert.Equal(input.Family.Safi, output.Family.Safi)
	assert.Equal(input.NextHops, output.NextHops)
	assert.Equal(2, len(output.Nlris))
	for idx, inputNLRI := range input.Nlris {
		outputNLRI := output.Nlris[idx]
		assert.Equal(inputNLRI.TypeUrl, outputNLRI.TypeUrl)
		assert.Equal(inputNLRI.Value, outputNLRI.Value)
	}
}

func Test_MpReachNLRIAttribute_IPv6_MPLS(t *testing.T) {
	assert := assert.New(t)

	nlris := make([]*apb.Any, 0, 2)
	a, err := apb.New(&api.LabeledIPAddressPrefix{
		Labels:    []uint32{100},
		PrefixLen: 64,
		Prefix:    "2001:db8:1::",
	})
	assert.Nil(err)
	nlris = append(nlris, a)
	a, err = apb.New(&api.LabeledIPAddressPrefix{
		Labels:    []uint32{200},
		PrefixLen: 64,
		Prefix:    "2001:db8:2::",
	})
	assert.Nil(err)
	nlris = append(nlris, a)

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP6,
			Safi: api.Family_SAFI_MPLS_LABEL,
		},
		NextHops: []string{"2001:db8::1"},
		Nlris:    nlris,
	}

	a, err = apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.Equal(input.Family.Afi, output.Family.Afi)
	assert.Equal(input.Family.Safi, output.Family.Safi)
	assert.Equal(input.NextHops, output.NextHops)
	assert.Equal(2, len(output.Nlris))
	for idx, inputNLRI := range input.Nlris {
		outputNLRI := output.Nlris[idx]
		assert.Equal(inputNLRI.TypeUrl, outputNLRI.TypeUrl)
		assert.Equal(inputNLRI.Value, outputNLRI.Value)
	}
}

func Test_MpReachNLRIAttribute_IPv4_ENCAP(t *testing.T) {
	assert := assert.New(t)

	nlris := make([]*apb.Any, 0, 2)
	a, err := apb.New(&api.EncapsulationNLRI{
		Address: "192.168.101.1",
	})
	assert.Nil(err)
	nlris = append(nlris, a)
	a, err = apb.New(&api.EncapsulationNLRI{
		Address: "192.168.201.1",
	})
	assert.Nil(err)
	nlris = append(nlris, a)

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_ENCAPSULATION,
		},
		NextHops: []string{"192.168.1.1"},
		Nlris:    nlris,
	}

	a, err = apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.Equal(input.Family.Afi, output.Family.Afi)
	assert.Equal(input.Family.Safi, output.Family.Safi)
	assert.Equal(input.NextHops, output.NextHops)
	assert.Equal(2, len(output.Nlris))
	for idx, inputNLRI := range input.Nlris {
		outputNLRI := output.Nlris[idx]
		assert.Equal(inputNLRI.TypeUrl, outputNLRI.TypeUrl)
		assert.Equal(inputNLRI.Value, outputNLRI.Value)
	}
}

func Test_MpReachNLRIAttribute_IPv6_ENCAP(t *testing.T) {
	assert := assert.New(t)

	nlris := make([]*apb.Any, 0, 2)
	a, err := apb.New(&api.EncapsulationNLRI{
		Address: "2001:db8:1::1",
	})
	assert.Nil(err)
	nlris = append(nlris, a)
	a, err = apb.New(&api.EncapsulationNLRI{
		Address: "2001:db8:2::1",
	})
	assert.Nil(err)
	nlris = append(nlris, a)

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP6,
			Safi: api.Family_SAFI_ENCAPSULATION,
		},
		NextHops: []string{"2001:db8::1"},
		Nlris:    nlris,
	}

	a, err = apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.Equal(input.Family.Afi, output.Family.Afi)
	assert.Equal(input.Family.Safi, output.Family.Safi)
	assert.Equal(input.NextHops, output.NextHops)
	assert.Equal(2, len(output.Nlris))
	for idx, inputNLRI := range input.Nlris {
		outputNLRI := output.Nlris[idx]
		assert.Equal(inputNLRI.TypeUrl, outputNLRI.TypeUrl)
		assert.Equal(inputNLRI.Value, outputNLRI.Value)
	}
}

func Test_MpReachNLRIAttribute_VPLS(t *testing.T) {
	assert := assert.New(t)

	nlris := make([]*apb.Any, 0, 1)
	rd, err := apb.New(&api.RouteDistinguisherTwoOctetASN{
		Admin:    65000,
		Assigned: 100,
	})
	assert.Nil(err)
	a, err := apb.New(&api.VPLSNLRI{
		Rd:             rd,
		VeId:           101,
		VeBlockOffset:  100,
		VeBlockSize:    10,
		LabelBlockBase: 1000,
	})
	assert.Nil(err)
	nlris = append(nlris, a)

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_L2VPN,
			Safi: api.Family_SAFI_VPLS,
		},
		NextHops: []string{"192.168.1.1"},
		Nlris:    nlris,
	}

	a, err = apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.Equal(input.Family.Afi, output.Family.Afi)
	assert.Equal(input.Family.Safi, output.Family.Safi)
	assert.Equal(input.NextHops, output.NextHops)
	assert.Equal(1, len(output.Nlris))
	for idx, inputNLRI := range input.Nlris {
		outputNLRI := output.Nlris[idx]
		assert.Equal(inputNLRI.TypeUrl, outputNLRI.TypeUrl)
		assert.Equal(inputNLRI.Value, outputNLRI.Value)
	}
}

func Test_MpReachNLRIAttribute_EVPN_AD_Route(t *testing.T) {
	assert := assert.New(t)

	nlris := make([]*apb.Any, 0, 1)
	rd, err := apb.New(&api.RouteDistinguisherTwoOctetASN{
		Admin:    65000,
		Assigned: 100,
	})
	assert.Nil(err)
	esi := &api.EthernetSegmentIdentifier{
		Type:  0,
		Value: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
	}
	a, err := apb.New(&api.EVPNEthernetAutoDiscoveryRoute{
		Rd:          rd,
		Esi:         esi,
		EthernetTag: 100,
		Label:       200,
	})
	assert.Nil(err)
	nlris = append(nlris, a)

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_L2VPN,
			Safi: api.Family_SAFI_EVPN,
		},
		NextHops: []string{"192.168.1.1"},
		Nlris:    nlris,
	}

	a, err = apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.Equal(input.Family.Afi, output.Family.Afi)
	assert.Equal(input.Family.Safi, output.Family.Safi)
	assert.Equal(input.NextHops, output.NextHops)
	assert.Equal(1, len(output.Nlris))
	for idx, inputNLRI := range input.Nlris {
		outputNLRI := output.Nlris[idx]
		assert.Equal(inputNLRI.TypeUrl, outputNLRI.TypeUrl)
		assert.Equal(inputNLRI.Value, outputNLRI.Value)
	}
}

func Test_MpReachNLRIAttribute_EVPN_MAC_IP_Route(t *testing.T) {
	assert := assert.New(t)

	nlris := make([]*apb.Any, 0, 1)
	rd, err := apb.New(&api.RouteDistinguisherIPAddress{
		Admin:    "1.1.1.1",
		Assigned: 100,
	})
	assert.Nil(err)
	esi := &api.EthernetSegmentIdentifier{
		Type:  0,
		Value: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
	}
	a, err := apb.New(&api.EVPNMACIPAdvertisementRoute{
		Rd:          rd,
		Esi:         esi,
		EthernetTag: 100,
		MacAddress:  "aa:bb:cc:dd:ee:ff",
		IpAddress:   "192.168.101.1",
		Labels:      []uint32{200},
	})
	assert.Nil(err)
	nlris = append(nlris, a)

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_L2VPN,
			Safi: api.Family_SAFI_EVPN,
		},
		NextHops: []string{"192.168.1.1"},
		Nlris:    nlris,
	}

	a, err = apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.Equal(input.Family.Afi, output.Family.Afi)
	assert.Equal(input.Family.Safi, output.Family.Safi)
	assert.Equal(input.NextHops, output.NextHops)
	assert.Equal(1, len(output.Nlris))
	for idx, inputNLRI := range input.Nlris {
		outputNLRI := output.Nlris[idx]
		assert.Equal(inputNLRI.TypeUrl, outputNLRI.TypeUrl)
		assert.Equal(inputNLRI.Value, outputNLRI.Value)
	}
}

func Test_MpReachNLRIAttribute_EVPN_MC_Route(t *testing.T) {
	assert := assert.New(t)

	nlris := make([]*apb.Any, 0, 1)
	rd, err := apb.New(&api.RouteDistinguisherFourOctetASN{
		Admin:    65000,
		Assigned: 100,
	})
	assert.Nil(err)
	a, err := apb.New(&api.EVPNInclusiveMulticastEthernetTagRoute{
		Rd:          rd,
		EthernetTag: 100,
		IpAddress:   "192.168.101.1",
	})
	assert.Nil(err)
	nlris = append(nlris, a)

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_L2VPN,
			Safi: api.Family_SAFI_EVPN,
		},
		NextHops: []string{"192.168.1.1"},
		Nlris:    nlris,
	}

	a, err = apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.Equal(input.Family.Afi, output.Family.Afi)
	assert.Equal(input.Family.Safi, output.Family.Safi)
	assert.Equal(input.NextHops, output.NextHops)
	assert.Equal(1, len(output.Nlris))
	for idx, inputNLRI := range input.Nlris {
		outputNLRI := output.Nlris[idx]
		assert.Equal(inputNLRI.TypeUrl, outputNLRI.TypeUrl)
		assert.Equal(inputNLRI.Value, outputNLRI.Value)
	}
}

func Test_MpReachNLRIAttribute_EVPN_ES_Route(t *testing.T) {
	assert := assert.New(t)

	nlris := make([]*apb.Any, 0, 1)
	rd, err := apb.New(&api.RouteDistinguisherIPAddress{
		Admin:    "1.1.1.1",
		Assigned: 100,
	})
	assert.Nil(err)
	esi := &api.EthernetSegmentIdentifier{
		Type:  0,
		Value: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
	}
	a, err := apb.New(&api.EVPNEthernetSegmentRoute{
		Rd:        rd,
		Esi:       esi,
		IpAddress: "192.168.101.1",
	})
	assert.Nil(err)
	nlris = append(nlris, a)

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_L2VPN,
			Safi: api.Family_SAFI_EVPN,
		},
		NextHops: []string{"192.168.1.1"},
		Nlris:    nlris,
	}

	a, err = apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.Equal(input.Family.Afi, output.Family.Afi)
	assert.Equal(input.Family.Safi, output.Family.Safi)
	assert.Equal(input.NextHops, output.NextHops)
	assert.Equal(1, len(output.Nlris))
	for idx, inputNLRI := range input.Nlris {
		outputNLRI := output.Nlris[idx]
		assert.Equal(inputNLRI.TypeUrl, outputNLRI.TypeUrl)
		assert.Equal(inputNLRI.Value, outputNLRI.Value)
	}
}

func Test_MpReachNLRIAttribute_EVPN_Prefix_Route(t *testing.T) {
	assert := assert.New(t)

	nlris := make([]*apb.Any, 0, 1)
	rd, err := apb.New(&api.RouteDistinguisherIPAddress{
		Admin:    "1.1.1.1",
		Assigned: 100,
	})
	assert.Nil(err)
	esi := &api.EthernetSegmentIdentifier{
		Type:  0,
		Value: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
	}
	a, err := apb.New(&api.EVPNIPPrefixRoute{
		Rd:          rd,
		Esi:         esi,
		EthernetTag: 100,
		IpPrefixLen: 24,
		IpPrefix:    "192.168.101.0",
		Label:       200,
		GwAddress:   "172.16.101.1",
	})
	assert.Nil(err)
	nlris = append(nlris, a)

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_L2VPN,
			Safi: api.Family_SAFI_EVPN,
		},
		NextHops: []string{"192.168.1.1"},
		Nlris:    nlris,
	}

	a, err = apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.Equal(input.Family.Afi, output.Family.Afi)
	assert.Equal(input.Family.Safi, output.Family.Safi)
	assert.Equal(input.NextHops, output.NextHops)
	assert.Equal(1, len(output.Nlris))
	for idx, inputNLRI := range input.Nlris {
		outputNLRI := output.Nlris[idx]
		assert.Equal(inputNLRI.TypeUrl, outputNLRI.TypeUrl)
		assert.Equal(inputNLRI.Value, outputNLRI.Value)
	}
}

func Test_MpReachNLRIAttribute_IPv4_VPN(t *testing.T) {
	assert := assert.New(t)

	nlris := make([]*apb.Any, 0, 1)
	rd, err := apb.New(&api.RouteDistinguisherIPAddress{
		Admin:    "1.1.1.1",
		Assigned: 100,
	})
	assert.Nil(err)
	a, err := apb.New(&api.LabeledVPNIPAddressPrefix{
		Labels:    []uint32{100, 200},
		Rd:        rd,
		PrefixLen: 24,
		Prefix:    "192.168.101.0",
	})
	assert.Nil(err)
	nlris = append(nlris, a)

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_MPLS_VPN,
		},
		NextHops: []string{"192.168.1.1"},
		Nlris:    nlris,
	}

	a, err = apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.Equal(input.Family.Afi, output.Family.Afi)
	assert.Equal(input.Family.Safi, output.Family.Safi)
	assert.Equal(input.NextHops, output.NextHops)
	assert.Equal(1, len(output.Nlris))
	for idx, inputNLRI := range input.Nlris {
		outputNLRI := output.Nlris[idx]
		assert.Equal(inputNLRI.TypeUrl, outputNLRI.TypeUrl)
		assert.Equal(inputNLRI.Value, outputNLRI.Value)
	}
}

func Test_MpReachNLRIAttribute_IPv6_VPN(t *testing.T) {
	assert := assert.New(t)

	nlris := make([]*apb.Any, 0, 1)
	rd, err := apb.New(&api.RouteDistinguisherIPAddress{
		Admin:    "1.1.1.1",
		Assigned: 100,
	})
	assert.Nil(err)
	a, err := apb.New(&api.LabeledVPNIPAddressPrefix{
		Labels:    []uint32{100, 200},
		Rd:        rd,
		PrefixLen: 64,
		Prefix:    "2001:db8:1::",
	})
	assert.Nil(err)
	nlris = append(nlris, a)

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP6,
			Safi: api.Family_SAFI_MPLS_VPN,
		},
		NextHops: []string{"2001:db8::1"},
		Nlris:    nlris,
	}

	a, err = apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.Equal(input.Family.Afi, output.Family.Afi)
	assert.Equal(input.Family.Safi, output.Family.Safi)
	assert.Equal(input.NextHops, output.NextHops)
	assert.Equal(1, len(output.Nlris))
	for idx, inputNLRI := range input.Nlris {
		outputNLRI := output.Nlris[idx]
		assert.Equal(inputNLRI.TypeUrl, outputNLRI.TypeUrl)
		assert.Equal(inputNLRI.Value, outputNLRI.Value)
	}
}

func Test_MpReachNLRIAttribute_RTC_UC(t *testing.T) {
	assert := assert.New(t)

	nlris := make([]*apb.Any, 0, 1)
	rt, err := apb.New(&api.IPv4AddressSpecificExtended{
		IsTransitive: true,
		SubType:      0x02, // Route Target
		Address:      "1.1.1.1",
		LocalAdmin:   100,
	})
	assert.Nil(err)
	a, err := apb.New(&api.RouteTargetMembershipNLRI{
		Asn: 65000,
		Rt:  rt,
	})
	assert.Nil(err)
	nlris = append(nlris, a)

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_ROUTE_TARGET_CONSTRAINTS,
		},
		NextHops: []string{"192.168.1.1"},
		Nlris:    nlris,
	}

	a, err = apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.Equal(input.Family.Afi, output.Family.Afi)
	assert.Equal(input.Family.Safi, output.Family.Safi)
	assert.Equal(input.NextHops, output.NextHops)
	assert.Equal(1, len(output.Nlris))
	for idx, inputNLRI := range input.Nlris {
		outputNLRI := output.Nlris[idx]
		assert.Equal(inputNLRI.TypeUrl, outputNLRI.TypeUrl)
		assert.Equal(inputNLRI.Value, outputNLRI.Value)
	}
}

func Test_MpReachNLRIAttribute_FS_IPv4_UC(t *testing.T) {
	assert := assert.New(t)

	rules := make([]*apb.Any, 0, 3)
	rule, err := apb.New(&api.FlowSpecIPPrefix{
		Type:      1, // Destination Prefix
		PrefixLen: 24,
		Prefix:    "192.168.101.0",
	})
	assert.Nil(err)
	rules = append(rules, rule)
	rule, err = apb.New(&api.FlowSpecIPPrefix{
		Type:      2, // Source Prefix
		PrefixLen: 24,
		Prefix:    "192.168.201.0",
	})
	assert.Nil(err)
	rules = append(rules, rule)
	rule, err = apb.New(&api.FlowSpecComponent{
		Type: 3, // IP Protocol
		Items: []*api.FlowSpecComponentItem{
			{
				Op:    0x80 | 0x01, // End, EQ
				Value: 6,           // TCP
			},
		},
	})
	assert.Nil(err)
	rules = append(rules, rule)

	nlris := make([]*apb.Any, 0, 1)
	a, err := apb.New(&api.FlowSpecNLRI{
		Rules: rules,
	})
	assert.Nil(err)
	nlris = append(nlris, a)

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_FLOW_SPEC_UNICAST,
		},
		// NextHops: // No nexthop required
		Nlris: nlris,
	}

	a, err = apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.Equal(input.Family.Afi, output.Family.Afi)
	assert.Equal(input.Family.Safi, output.Family.Safi)
	assert.Equal(input.NextHops, output.NextHops)
	assert.Equal(1, len(output.Nlris))
	for idx, inputNLRI := range input.Nlris {
		outputNLRI := output.Nlris[idx]
		assert.Equal(inputNLRI.TypeUrl, outputNLRI.TypeUrl)
		assert.Equal(inputNLRI.Value, outputNLRI.Value)
	}
}

func Test_MpReachNLRIAttribute_FS_IPv4_VPN(t *testing.T) {
	assert := assert.New(t)

	rd, err := apb.New(&api.RouteDistinguisherIPAddress{
		Admin:    "1.1.1.1",
		Assigned: 100,
	})
	assert.Nil(err)

	rules := make([]*apb.Any, 0, 3)
	rule, err := apb.New(&api.FlowSpecIPPrefix{
		Type:      1, // Destination Prefix
		PrefixLen: 24,
		Prefix:    "192.168.101.0",
	})
	assert.Nil(err)
	rules = append(rules, rule)
	rule, err = apb.New(&api.FlowSpecIPPrefix{
		Type:      2, // Source Prefix
		PrefixLen: 24,
		Prefix:    "192.168.201.0",
	})
	assert.Nil(err)
	rules = append(rules, rule)
	rule, err = apb.New(&api.FlowSpecComponent{
		Type: 3, // IP Protocol
		Items: []*api.FlowSpecComponentItem{
			{
				Op:    0x80 | 0x01, // End, EQ
				Value: 6,           // TCP
			},
		},
	})
	assert.Nil(err)
	rules = append(rules, rule)

	nlris := make([]*apb.Any, 0, 1)
	a, err := apb.New(&api.VPNFlowSpecNLRI{
		Rd:    rd,
		Rules: rules,
	})
	assert.Nil(err)
	nlris = append(nlris, a)

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_FLOW_SPEC_VPN,
		},
		// NextHops: // No nexthop required
		Nlris: nlris,
	}

	a, err = apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.Equal(input.Family.Afi, output.Family.Afi)
	assert.Equal(input.Family.Safi, output.Family.Safi)
	assert.Equal(input.NextHops, output.NextHops)
	assert.Equal(1, len(output.Nlris))
	for idx, inputNLRI := range input.Nlris {
		outputNLRI := output.Nlris[idx]
		assert.Equal(inputNLRI.TypeUrl, outputNLRI.TypeUrl)
		assert.Equal(inputNLRI.Value, outputNLRI.Value)
	}
}

func Test_MpReachNLRIAttribute_FS_IPv6_UC(t *testing.T) {
	assert := assert.New(t)

	rules := make([]*apb.Any, 0, 3)
	rule, err := apb.New(&api.FlowSpecIPPrefix{
		Type:      1, // Destination Prefix
		PrefixLen: 64,
		Prefix:    "2001:db8:1::",
	})
	assert.Nil(err)
	rules = append(rules, rule)
	rule, err = apb.New(&api.FlowSpecIPPrefix{
		Type:      2, // Source Prefix
		PrefixLen: 64,
		Prefix:    "2001:db8:2::",
	})
	assert.Nil(err)
	rules = append(rules, rule)
	rule, err = apb.New(&api.FlowSpecComponent{
		Type: 3, // Next Header
		Items: []*api.FlowSpecComponentItem{
			{
				Op:    0x80 | 0x01, // End, EQ
				Value: 6,           // TCP
			},
		},
	})
	assert.Nil(err)
	rules = append(rules, rule)

	nlris := make([]*apb.Any, 0, 1)
	a, err := apb.New(&api.FlowSpecNLRI{
		Rules: rules,
	})
	assert.Nil(err)
	nlris = append(nlris, a)

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP6,
			Safi: api.Family_SAFI_FLOW_SPEC_UNICAST,
		},
		// NextHops: // No nexthop required
		Nlris: nlris,
	}

	a, err = apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.Equal(input.Family.Afi, output.Family.Afi)
	assert.Equal(input.Family.Safi, output.Family.Safi)
	assert.Equal(input.NextHops, output.NextHops)
	assert.Equal(1, len(output.Nlris))
	for idx, inputNLRI := range input.Nlris {
		outputNLRI := output.Nlris[idx]
		assert.Equal(inputNLRI.TypeUrl, outputNLRI.TypeUrl)
		assert.Equal(inputNLRI.Value, outputNLRI.Value)
	}
}

func Test_MpReachNLRIAttribute_FS_IPv6_VPN(t *testing.T) {
	assert := assert.New(t)

	rd, err := apb.New(&api.RouteDistinguisherIPAddress{
		Admin:    "1.1.1.1",
		Assigned: 100,
	})
	assert.Nil(err)

	rules := make([]*apb.Any, 0, 3)
	rule, err := apb.New(&api.FlowSpecIPPrefix{
		Type:      1, // Destination Prefix
		PrefixLen: 64,
		Prefix:    "2001:db8:1::",
	})
	assert.Nil(err)
	rules = append(rules, rule)
	rule, err = apb.New(&api.FlowSpecIPPrefix{
		Type:      2, // Source Prefix
		PrefixLen: 64,
		Prefix:    "2001:db8:2::",
	})
	assert.Nil(err)
	rules = append(rules, rule)
	rule, err = apb.New(&api.FlowSpecComponent{
		Type: 3, // Next Header
		Items: []*api.FlowSpecComponentItem{
			{
				Op:    0x80 | 0x01, // End, EQ
				Value: 6,           // TCP
			},
		},
	})
	assert.Nil(err)
	rules = append(rules, rule)

	nlris := make([]*apb.Any, 0, 1)
	a, err := apb.New(&api.VPNFlowSpecNLRI{
		Rd:    rd,
		Rules: rules,
	})
	assert.Nil(err)
	nlris = append(nlris, a)

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP6,
			Safi: api.Family_SAFI_FLOW_SPEC_VPN,
		},
		// NextHops: // No nexthop required
		Nlris: nlris,
	}

	a, err = apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.Equal(input.Family.Afi, output.Family.Afi)
	assert.Equal(input.Family.Safi, output.Family.Safi)
	assert.Equal(input.NextHops, output.NextHops)
	assert.Equal(1, len(output.Nlris))
	for idx, inputNLRI := range input.Nlris {
		outputNLRI := output.Nlris[idx]
		assert.Equal(inputNLRI.TypeUrl, outputNLRI.TypeUrl)
		assert.Equal(inputNLRI.Value, outputNLRI.Value)
	}
}

func Test_MpReachNLRIAttribute_FS_L2_VPN(t *testing.T) {
	assert := assert.New(t)

	rd, err := apb.New(&api.RouteDistinguisherIPAddress{
		Admin:    "1.1.1.1",
		Assigned: 100,
	})
	assert.Nil(err)

	rules := make([]*apb.Any, 0, 3)
	rule, err := apb.New(&api.FlowSpecMAC{
		Type:    15, // Source MAC
		Address: "aa:bb:cc:11:22:33",
	})
	assert.Nil(err)
	rules = append(rules, rule)
	rule, err = apb.New(&api.FlowSpecMAC{
		Type:    16, // Destination MAC
		Address: "dd:ee:ff:11:22:33",
	})
	assert.Nil(err)
	rules = append(rules, rule)
	rule, err = apb.New(&api.FlowSpecComponent{
		Type: 21, // VLAN ID
		Items: []*api.FlowSpecComponentItem{
			{
				Op:    0x80 | 0x01, // End, EQ
				Value: 100,
			},
		},
	})
	assert.Nil(err)
	rules = append(rules, rule)

	nlris := make([]*apb.Any, 0, 1)
	a, err := apb.New(&api.VPNFlowSpecNLRI{
		Rd:    rd,
		Rules: rules,
	})
	assert.Nil(err)
	nlris = append(nlris, a)

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_L2VPN,
			Safi: api.Family_SAFI_FLOW_SPEC_VPN,
		},
		// NextHops: // No nexthop required
		Nlris: nlris,
	}

	a, err = apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.Equal(input.Family.Afi, output.Family.Afi)
	assert.Equal(input.Family.Safi, output.Family.Safi)
	assert.Equal(input.NextHops, output.NextHops)
	assert.Equal(1, len(output.Nlris))
	for idx, inputNLRI := range input.Nlris {
		outputNLRI := output.Nlris[idx]
		assert.Equal(inputNLRI.TypeUrl, outputNLRI.TypeUrl)
		assert.Equal(inputNLRI.Value, outputNLRI.Value)
	}
}

func Test_MpReachNLRIAttribute_MUPInterworkSegmentDiscoveryRoute(t *testing.T) {
	assert := assert.New(t)

	nlris := make([]*apb.Any, 0, 1)
	rd, err := apb.New(&api.RouteDistinguisherTwoOctetASN{
		Admin:    65000,
		Assigned: 100,
	})
	assert.Nil(err)
	a, err := apb.New(&api.MUPInterworkSegmentDiscoveryRoute{
		Rd:     rd,
		Prefix: "10.0.0.0/24",
	})
	assert.Nil(err)
	nlris = append(nlris, a)

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_MUP,
		},
		NextHops: []string{"0.0.0.0"},
		Nlris:    nlris,
	}

	a, err = apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.Equal(input.Family.Afi, output.Family.Afi)
	assert.Equal(input.Family.Safi, output.Family.Safi)
	assert.Equal(input.NextHops, output.NextHops)
	assert.Equal(1, len(output.Nlris))
	for idx, inputNLRI := range input.Nlris {
		outputNLRI := output.Nlris[idx]
		assert.Equal(inputNLRI.TypeUrl, outputNLRI.TypeUrl)
		assert.Equal(inputNLRI.Value, outputNLRI.Value)
	}
}

func Test_MpReachNLRIAttribute_MUPDirectSegmentDiscoveryRoute(t *testing.T) {
	assert := assert.New(t)

	nlris := make([]*apb.Any, 0, 1)
	rd, err := apb.New(&api.RouteDistinguisherTwoOctetASN{
		Admin:    65000,
		Assigned: 100,
	})
	assert.Nil(err)
	a, err := apb.New(&api.MUPDirectSegmentDiscoveryRoute{
		Rd:      rd,
		Address: "10.0.0.1",
	})
	assert.Nil(err)
	nlris = append(nlris, a)

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_MUP,
		},
		NextHops: []string{"0.0.0.0"},
		Nlris:    nlris,
	}

	a, err = apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.Equal(input.Family.Afi, output.Family.Afi)
	assert.Equal(input.Family.Safi, output.Family.Safi)
	assert.Equal(input.NextHops, output.NextHops)
	assert.Equal(1, len(output.Nlris))
	for idx, inputNLRI := range input.Nlris {
		outputNLRI := output.Nlris[idx]
		assert.Equal(inputNLRI.TypeUrl, outputNLRI.TypeUrl)
		assert.Equal(inputNLRI.Value, outputNLRI.Value)
	}
}

func Test_MpReachNLRIAttribute_MUPType1SessionTransformedRoute(t *testing.T) {
	assert := assert.New(t)
	rd, err := apb.New(&api.RouteDistinguisherTwoOctetASN{
		Admin:    65000,
		Assigned: 100,
	})
	assert.Nil(err)
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
		a, err := apb.New(tt.in)
		assert.Nil(err)
		nlris := []*apb.Any{a}

		input := &api.MpReachNLRIAttribute{
			Family: &api.Family{
				Afi:  api.Family_AFI_IP,
				Safi: api.Family_SAFI_MUP,
			},
			NextHops: []string{"0.0.0.0"},
			Nlris:    nlris,
		}

		a, err = apb.New(input)
		assert.Nil(err)
		n, err := UnmarshalAttribute(a)
		assert.Nil(err)

		output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
		assert.Equal(input.Family.Afi, output.Family.Afi)
		assert.Equal(input.Family.Safi, output.Family.Safi)
		assert.Equal(input.NextHops, output.NextHops)
		assert.Equal(1, len(output.Nlris))
		for idx, inputNLRI := range input.Nlris {
			outputNLRI := output.Nlris[idx]
			assert.Equal(inputNLRI.TypeUrl, outputNLRI.TypeUrl)
			assert.Equal(inputNLRI.Value, outputNLRI.Value)
		}
	}
}

func Test_MpReachNLRIAttribute_MUPType2SessionTransformedRoute(t *testing.T) {
	assert := assert.New(t)

	nlris := make([]*apb.Any, 0, 1)
	rd, err := apb.New(&api.RouteDistinguisherTwoOctetASN{
		Admin:    65000,
		Assigned: 100,
	})
	assert.Nil(err)
	a, err := apb.New(&api.MUPType2SessionTransformedRoute{
		Rd:                    rd,
		Teid:                  12345,
		EndpointAddressLength: 64,
		EndpointAddress:       "10.0.0.1",
	})
	assert.Nil(err)
	nlris = append(nlris, a)

	input := &api.MpReachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_MUP,
		},
		NextHops: []string{"0.0.0.0"},
		Nlris:    nlris,
	}

	a, err = apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewMpReachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpReachNLRI))
	assert.Equal(input.Family.Afi, output.Family.Afi)
	assert.Equal(input.Family.Safi, output.Family.Safi)
	assert.Equal(input.NextHops, output.NextHops)
	assert.Equal(1, len(output.Nlris))
	for idx, inputNLRI := range input.Nlris {
		outputNLRI := output.Nlris[idx]
		assert.Equal(inputNLRI.TypeUrl, outputNLRI.TypeUrl)
		assert.Equal(inputNLRI.Value, outputNLRI.Value)
	}
}

func Test_MpUnreachNLRIAttribute_IPv4_UC(t *testing.T) {
	assert := assert.New(t)

	nlris := make([]*apb.Any, 0, 2)
	a, err := apb.New(&api.IPAddressPrefix{
		PrefixLen: 24,
		Prefix:    "192.168.101.0",
	})
	assert.Nil(err)
	nlris = append(nlris, a)
	a, err = apb.New(&api.IPAddressPrefix{
		PrefixLen: 24,
		Prefix:    "192.168.201.0",
	})
	assert.Nil(err)
	nlris = append(nlris, a)

	input := &api.MpUnreachNLRIAttribute{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_UNICAST,
		},
		Nlris: nlris,
	}

	a, err = apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewMpUnreachNLRIAttributeFromNative(n.(*bgp.PathAttributeMpUnreachNLRI))
	assert.Equal(input.Family.Afi, output.Family.Afi)
	assert.Equal(input.Family.Safi, output.Family.Safi)
	assert.Equal(2, len(output.Nlris))
	for idx, inputNLRI := range input.Nlris {
		outputNLRI := output.Nlris[idx]
		assert.Equal(inputNLRI.TypeUrl, outputNLRI.TypeUrl)
		assert.Equal(inputNLRI.Value, outputNLRI.Value)
	}
}

func Test_ExtendedCommunitiesAttribute(t *testing.T) {
	assert := assert.New(t)

	communities := make([]*apb.Any, 0, 19)
	a, err := apb.New(&api.TwoOctetAsSpecificExtended{
		IsTransitive: true,
		SubType:      0x02, // ROUTE_TARGET
		Asn:          65001,
		LocalAdmin:   100,
	})
	assert.Nil(err)
	communities = append(communities, a)
	a, err = apb.New(&api.IPv4AddressSpecificExtended{
		IsTransitive: true,
		SubType:      0x02, // ROUTE_TARGET
		Address:      "2.2.2.2",
		LocalAdmin:   200,
	})
	assert.Nil(err)
	communities = append(communities, a)
	a, err = apb.New(&api.FourOctetAsSpecificExtended{
		IsTransitive: true,
		SubType:      0x02, // ROUTE_TARGET
		Asn:          65003,
		LocalAdmin:   300,
	})
	assert.Nil(err)
	communities = append(communities, a)
	a, err = apb.New(&api.ValidationExtended{
		State: 0, // VALID
	})
	assert.Nil(err)
	communities = append(communities, a)
	a, err = apb.New(&api.ColorExtended{
		Color: 400,
	})
	assert.Nil(err)
	communities = append(communities, a)
	a, err = apb.New(&api.EncapExtended{
		TunnelType: 8, // VXLAN
	})
	assert.Nil(err)
	communities = append(communities, a)
	a, err = apb.New(&api.DefaultGatewayExtended{
		// No value
	})
	assert.Nil(err)
	communities = append(communities, a)
	a, err = apb.New(&api.OpaqueExtended{
		IsTransitive: true,
		Value:        []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77},
	})
	assert.Nil(err)
	communities = append(communities, a)
	a, err = apb.New(&api.ESILabelExtended{
		IsSingleActive: true,
		Label:          500,
	})
	assert.Nil(err)
	communities = append(communities, a)
	a, err = apb.New(&api.ESImportRouteTarget{
		EsImport: "aa:bb:cc:dd:ee:ff",
	})
	assert.Nil(err)
	communities = append(communities, a)
	a, err = apb.New(&api.MacMobilityExtended{
		IsSticky:    true,
		SequenceNum: 1,
	})
	assert.Nil(err)
	communities = append(communities, a)
	a, err = apb.New(&api.RouterMacExtended{
		Mac: "ff:ee:dd:cc:bb:aa",
	})
	assert.Nil(err)
	communities = append(communities, a)
	a, err = apb.New(&api.TrafficRateExtended{
		Asn:  65004,
		Rate: 100.0,
	})
	assert.Nil(err)
	communities = append(communities, a)
	a, err = apb.New(&api.TrafficActionExtended{
		Terminal: true,
		Sample:   false,
	})
	assert.Nil(err)
	communities = append(communities, a)
	a, err = apb.New(&api.RedirectTwoOctetAsSpecificExtended{
		Asn:        65005,
		LocalAdmin: 500,
	})
	assert.Nil(err)
	communities = append(communities, a)
	a, err = apb.New(&api.RedirectIPv4AddressSpecificExtended{
		Address:    "6.6.6.6",
		LocalAdmin: 600,
	})
	assert.Nil(err)
	communities = append(communities, a)
	a, err = apb.New(&api.RedirectFourOctetAsSpecificExtended{
		Asn:        65007,
		LocalAdmin: 700,
	})
	assert.Nil(err)
	communities = append(communities, a)
	a, err = apb.New(&api.TrafficRemarkExtended{
		Dscp: 0x0a, // AF11
	})
	assert.Nil(err)
	communities = append(communities, a)
	a, err = apb.New(&api.MUPExtended{
		SegmentId2: 10,
		SegmentId4: 100,
	})
	assert.Nil(err)
	communities = append(communities, a)
	a, err = apb.New(&api.UnknownExtended{
		Type:  0xff, // Max of uint8
		Value: []byte{1, 2, 3, 4, 5, 6, 7},
	})
	assert.Nil(err)
	communities = append(communities, a)
	a, err = apb.New(&api.LinkBandwidthExtended{
		Asn:       65004,
		Bandwidth: 125000.0,
	})
	assert.Nil(err)
	communities = append(communities, a)
	a, err = apb.New(&api.VPLSExtended{
		ControlFlags: 0x00,
		Mtu:          1500,
	})
	assert.Nil(err)
	communities = append(communities, a)

	input := &api.ExtendedCommunitiesAttribute{
		Communities: communities,
	}

	a, err = apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewExtendedCommunitiesAttributeFromNative(n.(*bgp.PathAttributeExtendedCommunities))
	assert.Equal(22, len(output.Communities))
	for idx, inputCommunity := range input.Communities {
		outputCommunity := output.Communities[idx]
		assert.Equal(inputCommunity.TypeUrl, outputCommunity.TypeUrl)
		assert.Equal(inputCommunity.Value, outputCommunity.Value)
	}
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

	a, err := apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewAs4PathAttributeFromNative(n.(*bgp.PathAttributeAs4Path))
	assert.Equal(2, len(output.Segments))
	for i := 0; i < 2; i++ {
		assert.True(proto.Equal(input.Segments[i], output.Segments[i]))
	}
}

func Test_As4AggregatorAttribute(t *testing.T) {
	assert := assert.New(t)

	input := &api.As4AggregatorAttribute{
		Asn:     65000,
		Address: "1.1.1.1",
	}

	a, err := apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewAs4AggregatorAttributeFromNative(n.(*bgp.PathAttributeAs4Aggregator))
	assert.Equal(input.Asn, output.Asn)
	assert.Equal(input.Address, output.Address)
}

func Test_PmsiTunnelAttribute(t *testing.T) {
	assert := assert.New(t)

	input := &api.PmsiTunnelAttribute{
		Flags: 0x01, // IsLeafInfoRequired = true
		Type:  6,    // INGRESS_REPL
		Label: 100,
		Id:    net.ParseIP("1.1.1.1").To4(), // IngressReplTunnelID with IPv4
	}

	a, err := apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewPmsiTunnelAttributeFromNative(n.(*bgp.PathAttributePmsiTunnel))
	assert.Equal(input.Flags, output.Flags)
	assert.Equal(input.Type, output.Type)
	assert.Equal(input.Label, output.Label)
	assert.Equal(input.Id, output.Id)
}

func Test_TunnelEncapAttribute(t *testing.T) {
	assert := assert.New(t)

	subTlvs := make([]*apb.Any, 0, 4)
	a, err := apb.New(&api.TunnelEncapSubTLVEncapsulation{
		Key:    100,
		Cookie: []byte{0x11, 0x22, 0x33, 0x44},
	})
	assert.Nil(err)
	subTlvs = append(subTlvs, a)
	a, err = apb.New(&api.TunnelEncapSubTLVProtocol{
		Protocol: 200,
	})
	assert.Nil(err)
	subTlvs = append(subTlvs, a)
	a, err = apb.New(&api.TunnelEncapSubTLVColor{
		Color: 300,
	})
	assert.Nil(err)
	subTlvs = append(subTlvs, a)
	a, err = apb.New(&api.TunnelEncapSubTLVUDPDestPort{
		Port: 400,
	})
	assert.Nil(err)
	subTlvs = append(subTlvs, a)
	a, err = apb.New(&api.TunnelEncapSubTLVUnknown{
		Type:  0xff, // Max of uint8
		Value: []byte{0x55, 0x66, 0x77, 0x88},
	})
	assert.Nil(err)
	subTlvs = append(subTlvs, a)

	input := &api.TunnelEncapAttribute{
		Tlvs: []*api.TunnelEncapTLV{
			{
				Type: 8, // VXLAN
				Tlvs: subTlvs,
			},
		},
	}

	a, err = apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewTunnelEncapAttributeFromNative(n.(*bgp.PathAttributeTunnelEncap))
	assert.Equal(1, len(output.Tlvs))
	assert.Equal(input.Tlvs[0].Type, output.Tlvs[0].Type)
	assert.Equal(len(output.Tlvs[0].Tlvs), len(output.Tlvs[0].Tlvs))
	for idx, inputSubTlv := range input.Tlvs[0].Tlvs {
		outputSubTlv := output.Tlvs[0].Tlvs[idx]
		assert.Equal(inputSubTlv.TypeUrl, outputSubTlv.TypeUrl)
		assert.Equal(inputSubTlv.Value, outputSubTlv.Value)
	}
}

func Test_IP6ExtendedCommunitiesAttribute(t *testing.T) {
	assert := assert.New(t)

	communities := make([]*apb.Any, 0, 2)
	a, err := apb.New(&api.IPv6AddressSpecificExtended{
		IsTransitive: true,
		SubType:      0xff, // Max of uint8
		Address:      "2001:db8:1::1",
		LocalAdmin:   100,
	})
	assert.Nil(err)
	communities = append(communities, a)
	a, err = apb.New(&api.RedirectIPv6AddressSpecificExtended{
		Address:    "2001:db8:2::1",
		LocalAdmin: 200,
	})
	assert.Nil(err)
	communities = append(communities, a)

	input := &api.IP6ExtendedCommunitiesAttribute{
		Communities: communities,
	}

	a, err = apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewIP6ExtendedCommunitiesAttributeFromNative(n.(*bgp.PathAttributeIP6ExtendedCommunities))
	assert.Equal(2, len(output.Communities))
	for idx, inputCommunity := range input.Communities {
		outputCommunity := output.Communities[idx]
		assert.Equal(inputCommunity.TypeUrl, outputCommunity.TypeUrl)
		assert.Equal(inputCommunity.Value, outputCommunity.Value)
	}
}

func Test_AigpAttribute(t *testing.T) {
	assert := assert.New(t)

	tlvs := make([]*apb.Any, 0, 2)
	a, err := apb.New(&api.AigpTLVIGPMetric{
		Metric: 50,
	})
	assert.Nil(err)
	tlvs = append(tlvs, a)
	a, err = apb.New(&api.AigpTLVUnknown{
		Type:  0xff, // Max of uint8
		Value: []byte{0x11, 0x22, 0x33, 0x44},
	})
	assert.Nil(err)
	tlvs = append(tlvs, a)

	input := &api.AigpAttribute{
		Tlvs: tlvs,
	}

	a, err = apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewAigpAttributeFromNative(n.(*bgp.PathAttributeAigp))
	assert.Equal(2, len(output.Tlvs))
	for idx, inputTlv := range input.Tlvs {
		outputTlv := output.Tlvs[idx]
		assert.Equal(inputTlv.TypeUrl, outputTlv.TypeUrl)
		assert.Equal(inputTlv.Value, outputTlv.Value)
	}
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

	a, err := apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewLargeCommunitiesAttributeFromNative(n.(*bgp.PathAttributeLargeCommunities))
	assert.Equal(2, len(output.Communities))
	for i := 0; i < 2; i++ {
		assert.True(proto.Equal(input.Communities[i], output.Communities[i]))
	}
}

func Test_UnknownAttribute(t *testing.T) {
	assert := assert.New(t)

	input := &api.UnknownAttribute{
		Flags: (1 << 6) | (1 << 7), // OPTIONAL and TRANSITIVE
		Type:  0xff,
		Value: []byte{0x11, 0x22, 0x33, 0x44},
	}

	a, err := apb.New(input)
	assert.Nil(err)
	n, err := UnmarshalAttribute(a)
	assert.Nil(err)

	output, _ := NewUnknownAttributeFromNative(n.(*bgp.PathAttributeUnknown))
	assert.Equal(input.Flags, output.Flags)
	assert.Equal(input.Type, output.Type)
	assert.Equal(input.Value, output.Value)
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
