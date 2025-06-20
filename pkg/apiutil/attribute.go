// Copyright (C) 2018 Nippon Telegraph and Telephone Corporation.
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
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func UnmarshalAttribute(attr *api.Attribute) (bgp.PathAttributeInterface, error) {
	switch a := attr.GetAttr().(type) {
	case *api.Attribute_Origin:
		return bgp.NewPathAttributeOrigin(uint8(a.Origin.Origin)), nil
	case *api.Attribute_AsPath:
		params := make([]bgp.AsPathParamInterface, 0, len(a.AsPath.Segments))
		for _, segment := range a.AsPath.Segments {
			params = append(params, bgp.NewAs4PathParam(uint8(segment.Type), segment.Numbers))
		}
		return bgp.NewPathAttributeAsPath(params), nil
	case *api.Attribute_NextHop:
		nexthop := net.ParseIP(a.NextHop.NextHop).To4()
		if nexthop == nil {
			if nexthop = net.ParseIP(a.NextHop.NextHop).To16(); nexthop == nil {
				return nil, fmt.Errorf("invalid nexthop address: %s", a.NextHop)
			}
		}
		return bgp.NewPathAttributeNextHop(a.NextHop.NextHop), nil
	case *api.Attribute_MultiExitDisc:
		return bgp.NewPathAttributeMultiExitDisc(a.MultiExitDisc.Med), nil
	case *api.Attribute_LocalPref:
		return bgp.NewPathAttributeLocalPref(a.LocalPref.LocalPref), nil
	case *api.Attribute_AtomicAggregate:
		return bgp.NewPathAttributeAtomicAggregate(), nil
	case *api.Attribute_Aggregator:
		address := net.ParseIP(a.Aggregator.Address).To4()
		if address.To4() == nil {
			return nil, fmt.Errorf("invalid aggregator address: %s", a.Aggregator.Address)
		}
		return bgp.NewPathAttributeAggregator(a.Aggregator.Asn, a.Aggregator.Address), nil
	case *api.Attribute_Communities:
		return bgp.NewPathAttributeCommunities(a.Communities.Communities), nil
	case *api.Attribute_OriginatorId:
		id := net.ParseIP(a.OriginatorId.Id).To4()
		if id.To4() == nil {
			return nil, fmt.Errorf("invalid originator id: %s", a.OriginatorId.Id)
		}
		return bgp.NewPathAttributeOriginatorId(a.OriginatorId.Id), nil
	case *api.Attribute_ClusterList:
		for _, id := range a.ClusterList.Ids {
			if net.ParseIP(id).To4() == nil {
				return nil, fmt.Errorf("invalid cluster list: %s", a.ClusterList.Ids)
			}
		}
		return bgp.NewPathAttributeClusterList(a.ClusterList.Ids), nil
	case *api.Attribute_MpReach:
		if a.MpReach.Family == nil {
			return nil, fmt.Errorf("empty family")
		}
		rf := ToFamily(a.MpReach.Family)
		nlris, err := UnmarshalNLRIs(rf, a.MpReach.Nlris)
		if err != nil {
			return nil, err
		}
		afi, safi := bgp.FamilyToAfiSafi(rf)
		nexthop := "0.0.0.0"
		var linkLocalNexthop net.IP
		if afi == bgp.AFI_IP6 {
			nexthop = "::"
			if len(a.MpReach.NextHops) > 1 {
				linkLocalNexthop = net.ParseIP(a.MpReach.NextHops[1]).To16()
				if linkLocalNexthop == nil {
					return nil, fmt.Errorf("invalid nexthop: %s", a.MpReach.NextHops[1])
				}
			}
		}
		if safi == bgp.SAFI_FLOW_SPEC_UNICAST || safi == bgp.SAFI_FLOW_SPEC_VPN {
			nexthop = ""
		} else if len(a.MpReach.NextHops) > 0 {
			nexthop = a.MpReach.NextHops[0]
			if net.ParseIP(nexthop) == nil {
				return nil, fmt.Errorf("invalid nexthop: %s", nexthop)
			}
		}
		attr := bgp.NewPathAttributeMpReachNLRI(nexthop, nlris)
		attr.LinkLocalNexthop = linkLocalNexthop
		return attr, nil
	case *api.Attribute_MpUnreach:
		rf := ToFamily(a.MpUnreach.Family)
		nlris, err := UnmarshalNLRIs(rf, a.MpUnreach.Nlris)
		if err != nil {
			return nil, err
		}
		return bgp.NewPathAttributeMpUnreachNLRI(nlris), nil
	case *api.Attribute_ExtendedCommunities:
		return unmarshalExComm(a.ExtendedCommunities)
	case *api.Attribute_As4Path:
		params := make([]*bgp.As4PathParam, 0, len(a.As4Path.Segments))
		for _, segment := range a.As4Path.Segments {
			params = append(params, bgp.NewAs4PathParam(uint8(segment.Type), segment.Numbers))
		}
		return bgp.NewPathAttributeAs4Path(params), nil
	case *api.Attribute_As4Aggregator:
		address := net.ParseIP(a.As4Aggregator.Address).To4()
		if address == nil {
			return nil, fmt.Errorf("invalid as4 aggregator address: %s", a.As4Aggregator.Address)
		}
		return bgp.NewPathAttributeAs4Aggregator(a.As4Aggregator.Asn, a.As4Aggregator.Address), nil
	case *api.Attribute_PmsiTunnel:
		typ := bgp.PmsiTunnelType(a.PmsiTunnel.Type)
		var isLeafInfoRequired bool
		if a.PmsiTunnel.Flags&0x01 > 0 {
			isLeafInfoRequired = true
		}
		var id bgp.PmsiTunnelIDInterface
		switch typ {
		case bgp.PMSI_TUNNEL_TYPE_INGRESS_REPL:
			ip := net.IP(a.PmsiTunnel.Id)
			if ip.To4() == nil && ip.To16() == nil {
				return nil, fmt.Errorf("invalid pmsi tunnel identifier: %s", a.PmsiTunnel.Id)
			}
			id = bgp.NewIngressReplTunnelID(ip.String())
		default:
			id = bgp.NewDefaultPmsiTunnelID(a.PmsiTunnel.Id)
		}
		return bgp.NewPathAttributePmsiTunnel(typ, isLeafInfoRequired, a.PmsiTunnel.Label, id), nil
	case *api.Attribute_TunnelEncap:
		tlvs := make([]*bgp.TunnelEncapTLV, 0, len(a.TunnelEncap.Tlvs))
		for _, tlv := range a.TunnelEncap.Tlvs {
			subTlvs := make([]bgp.TunnelEncapSubTLVInterface, 0, len(tlv.Tlvs))
			for _, tlv := range tlv.Tlvs {
				var subTlv bgp.TunnelEncapSubTLVInterface
				switch sv := tlv.GetTlv().(type) {
				case *api.TunnelEncapTLV_TLV_Encapsulation:
					subTlv = bgp.NewTunnelEncapSubTLVEncapsulation(sv.Encapsulation.Key, sv.Encapsulation.Cookie)
				case *api.TunnelEncapTLV_TLV_Protocol:
					subTlv = bgp.NewTunnelEncapSubTLVProtocol(uint16(sv.Protocol.Protocol))
				case *api.TunnelEncapTLV_TLV_Color:
					subTlv = bgp.NewTunnelEncapSubTLVColor(sv.Color.Color)
				case *api.TunnelEncapTLV_TLV_EgressEndpoint:
					subTlv = bgp.NewTunnelEncapSubTLVEgressEndpoint(sv.EgressEndpoint.Address)
				case *api.TunnelEncapTLV_TLV_UdpDestPort:
					subTlv = bgp.NewTunnelEncapSubTLVUDPDestPort(uint16(sv.UdpDestPort.Port))
				case *api.TunnelEncapTLV_TLV_SrPreference:
					subTlv = bgp.NewTunnelEncapSubTLVSRPreference(sv.SrPreference.Flags, sv.SrPreference.Preference)
				case *api.TunnelEncapTLV_TLV_SrPriority:
					subTlv = bgp.NewTunnelEncapSubTLVSRPriority(uint8(sv.SrPriority.Priority))
				case *api.TunnelEncapTLV_TLV_SrCandidatePathName:
					subTlv = bgp.NewTunnelEncapSubTLVSRCandidatePathName(sv.SrCandidatePathName.CandidatePathName)
				case *api.TunnelEncapTLV_TLV_SrEnlp:
					subTlv = bgp.NewTunnelEncapSubTLVSRENLP(sv.SrEnlp.Flags, bgp.SRENLPValue(sv.SrEnlp.Enlp))
				case *api.TunnelEncapTLV_TLV_SrBindingSid:
					var err error
					subTlv, err = UnmarshalSRBSID(sv.SrBindingSid)
					if err != nil {
						return nil, fmt.Errorf("failed to unmarshal tunnel encapsulation attribute sub tlv: %s", err)
					}
				case *api.TunnelEncapTLV_TLV_SrSegmentList:
					var err error
					weight := uint32(0)
					flags := uint8(0)
					if sv.SrSegmentList.Weight != nil {
						weight = sv.SrSegmentList.Weight.Weight
						flags = uint8(sv.SrSegmentList.Weight.Flags)
					}
					s := &bgp.TunnelEncapSubTLVSRSegmentList{
						TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{
							Type:   bgp.ENCAP_SUBTLV_TYPE_SRSEGMENT_LIST,
							Length: uint16(6), // Weight (6 bytes) + length of segment (added later, after all segments are discovered)
						},
						Weight: &bgp.SegmentListWeight{
							TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{
								Type:   bgp.SegmentListSubTLVWeight,
								Length: uint16(6),
							},
							Flags:  flags,
							Weight: weight,
						},
						Segments: make([]bgp.TunnelEncapSubTLVInterface, 0),
					}
					if len(sv.SrSegmentList.Segments) != 0 {
						s.Segments, err = UnmarshalSRSegments(sv.SrSegmentList.Segments)
						if err != nil {
							return nil, fmt.Errorf("failed to unmarshal tunnel encapsulation attribute sub tlv: %s", err)
						}
					}
					// Get total length of Segment List Sub TLV
					for _, seg := range s.Segments {
						s.Length += uint16(seg.Len() + 2) // Adding 1 byte of type and 1 byte of length for each Segment object
					}
					subTlv = s
				case *api.TunnelEncapTLV_TLV_Unknown:
					subTlv = bgp.NewTunnelEncapSubTLVUnknown(bgp.EncapSubTLVType(sv.Unknown.Type), sv.Unknown.Value)
				default:
					return nil, fmt.Errorf("invalid tunnel encapsulation attribute sub tlv: %T", tlv.GetTlv())
				}
				subTlvs = append(subTlvs, subTlv)
			}
			tlvs = append(tlvs, bgp.NewTunnelEncapTLV(bgp.TunnelType(tlv.Type), subTlvs))
		}
		return bgp.NewPathAttributeTunnelEncap(tlvs), nil
	case *api.Attribute_Ip6ExtendedCommunities:
		communities := make([]bgp.ExtendedCommunityInterface, 0, len(a.Ip6ExtendedCommunities.Communities))
		for _, an := range a.Ip6ExtendedCommunities.Communities {
			var community bgp.ExtendedCommunityInterface
			switch an.GetExtcom().(type) {
			case *api.IP6ExtendedCommunitiesAttribute_Community_Ipv6AddressSpecific:
				v := an.GetIpv6AddressSpecific()
				community = bgp.NewIPv6AddressSpecificExtended(bgp.ExtendedCommunityAttrSubType(v.SubType), v.Address, uint16(v.LocalAdmin), v.IsTransitive)
			case *api.IP6ExtendedCommunitiesAttribute_Community_RedirectIpv6AddressSpecific:
				v := an.GetRedirectIpv6AddressSpecific()
				community = bgp.NewRedirectIPv6AddressSpecificExtended(v.Address, uint16(v.LocalAdmin))
			}
			if community == nil {
				return nil, fmt.Errorf("invalid ipv6 extended community: %T", an.GetExtcom())
			}
			communities = append(communities, community)
		}
		return bgp.NewPathAttributeIP6ExtendedCommunities(communities), nil

	case *api.Attribute_Aigp:
		tlvs := make([]bgp.AigpTLVInterface, 0, len(a.Aigp.Tlvs))
		for _, an := range a.Aigp.Tlvs {
			var tlv bgp.AigpTLVInterface
			switch an.GetTlv().(type) {
			case *api.AigpAttribute_TLV_IgpMetric:
				v := an.GetIgpMetric()
				tlv = bgp.NewAigpTLVIgpMetric(v.Metric)
			case *api.AigpAttribute_TLV_Unknown:
				v := an.GetUnknown()
				tlv = bgp.NewAigpTLVDefault(bgp.AigpTLVType(v.Type), v.Value)
			}
			if tlv == nil {
				return nil, fmt.Errorf("invalid aigp attribute tlv: %T", an.GetTlv())
			}
			tlvs = append(tlvs, tlv)
		}
		return bgp.NewPathAttributeAigp(tlvs), nil

	case *api.Attribute_LargeCommunities:
		communities := make([]*bgp.LargeCommunity, 0, len(a.LargeCommunities.Communities))
		for _, c := range a.LargeCommunities.Communities {
			communities = append(communities, bgp.NewLargeCommunity(c.GlobalAdmin, c.LocalData1, c.LocalData2))
		}
		return bgp.NewPathAttributeLargeCommunities(communities), nil
	case *api.Attribute_PrefixSid:
		return UnmarshalPrefixSID(a.PrefixSid)
	case *api.Attribute_Ls:
		lsAttr, err := UnmarshalLsAttribute(a.Ls)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal BGP-LS Attribute: %s", err)
		}
		tlvs := bgp.NewLsAttributeTLVs(lsAttr)
		var length uint16
		for _, tlv := range tlvs {
			length += uint16(tlv.Len())
		}
		t := bgp.BGP_ATTR_TYPE_LS
		pathAttributeLs := &bgp.PathAttributeLs{
			PathAttribute: bgp.PathAttribute{
				Flags:  bgp.PathAttrFlags[t],
				Type:   t,
				Length: length,
			},
			TLVs: tlvs,
		}

		return pathAttributeLs, nil

	case *api.Attribute_Unknown:
		return bgp.NewPathAttributeUnknown(bgp.BGPAttrFlag(a.Unknown.Flags), bgp.BGPAttrType(a.Unknown.Type), a.Unknown.Value), nil
	}
	return nil, errors.New("unknown path attribute")
}

func NewOriginAttributeFromNative(a *bgp.PathAttributeOrigin) (*api.OriginAttribute, error) {
	return &api.OriginAttribute{
		Origin: uint32(a.Value),
	}, nil
}

func NewAsPathAttributeFromNative(a *bgp.PathAttributeAsPath) (*api.AsPathAttribute, error) {
	segments := make([]*api.AsSegment, 0, len(a.Value))
	for _, param := range a.Value {
		segments = append(segments, &api.AsSegment{
			Type:    api.AsSegment_Type(param.GetType()),
			Numbers: param.GetAS(),
		})
	}
	return &api.AsPathAttribute{
		Segments: segments,
	}, nil
}

func NewNextHopAttributeFromNative(a *bgp.PathAttributeNextHop) (*api.NextHopAttribute, error) {
	return &api.NextHopAttribute{
		NextHop: a.Value.String(),
	}, nil
}

func NewMultiExitDiscAttributeFromNative(a *bgp.PathAttributeMultiExitDisc) (*api.MultiExitDiscAttribute, error) {
	return &api.MultiExitDiscAttribute{
		Med: a.Value,
	}, nil
}

func NewLocalPrefAttributeFromNative(a *bgp.PathAttributeLocalPref) (*api.LocalPrefAttribute, error) {
	return &api.LocalPrefAttribute{
		LocalPref: a.Value,
	}, nil
}

func NewAtomicAggregateAttributeFromNative(a *bgp.PathAttributeAtomicAggregate) (*api.AtomicAggregateAttribute, error) {
	return &api.AtomicAggregateAttribute{}, nil
}

func NewAggregatorAttributeFromNative(a *bgp.PathAttributeAggregator) (*api.AggregatorAttribute, error) {
	return &api.AggregatorAttribute{
		Asn:     a.Value.AS,
		Address: a.Value.Address.String(),
	}, nil
}

func NewCommunitiesAttributeFromNative(a *bgp.PathAttributeCommunities) (*api.CommunitiesAttribute, error) {
	return &api.CommunitiesAttribute{
		Communities: a.Value,
	}, nil
}

func NewOriginatorIdAttributeFromNative(a *bgp.PathAttributeOriginatorId) (*api.OriginatorIdAttribute, error) {
	return &api.OriginatorIdAttribute{
		Id: a.Value.String(),
	}, nil
}

func NewClusterListAttributeFromNative(a *bgp.PathAttributeClusterList) (*api.ClusterListAttribute, error) {
	ids := make([]string, 0, len(a.Value))
	for _, id := range a.Value {
		ids = append(ids, id.String())
	}
	return &api.ClusterListAttribute{
		Ids: ids,
	}, nil
}

func NewPrefixSIDAttributeFromNative(a *bgp.PathAttributePrefixSID) (*api.PrefixSID, error) {
	var err error
	psid := &api.PrefixSID{}
	psid.Tlvs, err = MarshalSRv6TLVs(a.TLVs)
	if err != nil {
		return nil, err
	}
	return psid, nil
}

func MarshalSRv6TLVs(tlvs []bgp.PrefixSIDTLVInterface) ([]*api.PrefixSID_TLV, error) {
	var err error
	mtlvs := make([]*api.PrefixSID_TLV, 0, len(tlvs))
	for _, tlv := range tlvs {
		var mtlv api.PrefixSID_TLV
		switch t := tlv.(type) {
		case *bgp.SRv6L3ServiceAttribute:
			o := &api.SRv6L3ServiceTLV{}
			o.SubTlvs, err = MarshalSRv6SubTLVs(t.SubTLVs)
			if err != nil {
				return nil, err
			}
			mtlv.Tlv = &api.PrefixSID_TLV_L3Service{L3Service: o}
		case *bgp.SRv6ServiceTLV:
			switch t.Type {
			case bgp.TLVTypeSRv6L3Service:
				o := &api.SRv6L3ServiceTLV{}
				o.SubTlvs, err = MarshalSRv6SubTLVs(t.SubTLVs)
				if err != nil {
					return nil, err
				}
				mtlv.Tlv = &api.PrefixSID_TLV_L3Service{L3Service: o}
			case bgp.TLVTypeSRv6L2Service:
				o := &api.SRv6L2ServiceTLV{}
				o.SubTlvs, err = MarshalSRv6SubTLVs(t.SubTLVs)
				if err != nil {
					return nil, err
				}
				mtlv.Tlv = &api.PrefixSID_TLV_L2Service{L2Service: o}
			}
		default:
			return nil, fmt.Errorf("invalid prefix sid tlv type to marshal %v", t)
		}
		mtlvs = append(mtlvs, &mtlv)
	}

	return mtlvs, nil
}

func MarshalSRv6SubTLVs(tlvs []bgp.PrefixSIDTLVInterface) (map[uint32]*api.SRv6SubTLVs, error) {
	mtlvs := make(map[uint32]*api.SRv6SubTLVs)
	var key uint32
	for _, tlv := range tlvs {
		r := &api.SRv6SubTLV{}
		switch t := tlv.(type) {
		case *bgp.SRv6InformationSubTLV:
			o := &api.SRv6InformationSubTLV{
				EndpointBehavior: uint32(t.EndpointBehavior),
				// TODO Once flags are used in RFC, add processing.
				Flags: &api.SRv6SIDFlags{},
			}
			o.Sid = make([]byte, len(t.SID))
			copy(o.Sid, t.SID)
			var err error
			o.SubSubTlvs, err = MarshalSRv6SubSubTLVs(t.SubSubTLVs)
			if err != nil {
				return nil, err
			}
			// SRv6 Information Sub TLV is type 1 Sub TLV
			key = 1
			r.Tlv = &api.SRv6SubTLV_Information{Information: o}
		default:
			return nil, fmt.Errorf("invalid prefix sid sub tlv type to marshal: %v", t)
		}
		tlvs, ok := mtlvs[key]
		if !ok {
			tlvs = &api.SRv6SubTLVs{
				Tlvs: make([]*api.SRv6SubTLV, 0),
			}
			mtlvs[key] = tlvs
		}
		tlvs.Tlvs = append(tlvs.Tlvs, r)
	}

	return mtlvs, nil
}

func MarshalSRv6SubSubTLVs(tlvs []bgp.PrefixSIDTLVInterface) (map[uint32]*api.SRv6SubSubTLVs, error) {
	mtlvs := make(map[uint32]*api.SRv6SubSubTLVs)
	var key uint32
	for _, tlv := range tlvs {
		r := &api.SRv6SubSubTLV{}
		switch t := tlv.(type) {
		case *bgp.SRv6SIDStructureSubSubTLV:
			o := &api.SRv6StructureSubSubTLV{
				LocatorBlockLength:  uint32(t.LocatorBlockLength),
				LocatorNodeLength:   uint32(t.LocatorNodeLength),
				FunctionLength:      uint32(t.FunctionLength),
				ArgumentLength:      uint32(t.ArgumentLength),
				TranspositionLength: uint32(t.TranspositionLength),
				TranspositionOffset: uint32(t.TranspositionOffset),
			}
			// SRv6 SID Structure Sub Sub TLV is type 1 Sub Sub TLV
			key = 1
			r.Tlv = &api.SRv6SubSubTLV_Structure{Structure: o}
		default:
			return nil, fmt.Errorf("invalid prefix sid sub sub tlv type to marshal: %v", t)
		}
		tlvs, ok := mtlvs[key]
		if !ok {
			tlvs = &api.SRv6SubSubTLVs{
				Tlvs: make([]*api.SRv6SubSubTLV, 0),
			}
			mtlvs[key] = tlvs
		}
		tlvs.Tlvs = append(tlvs.Tlvs, r)
	}
	return mtlvs, nil
}

func MarshalRD(rd bgp.RouteDistinguisherInterface) (*api.RouteDistinguisher, error) {
	var r api.RouteDistinguisher
	switch v := rd.(type) {
	case *bgp.RouteDistinguisherTwoOctetAS:
		r.Rd = &api.RouteDistinguisher_TwoOctetAsn{TwoOctetAsn: &api.RouteDistinguisherTwoOctetASN{
			Admin:    uint32(v.Admin),
			Assigned: v.Assigned,
		}}
	case *bgp.RouteDistinguisherIPAddressAS:
		r.Rd = &api.RouteDistinguisher_IpAddress{IpAddress: &api.RouteDistinguisherIPAddress{
			Admin:    v.Admin.String(),
			Assigned: uint32(v.Assigned),
		}}
	case *bgp.RouteDistinguisherFourOctetAS:
		r.Rd = &api.RouteDistinguisher_FourOctetAsn{FourOctetAsn: &api.RouteDistinguisherFourOctetASN{
			Admin:    v.Admin,
			Assigned: uint32(v.Assigned),
		}}
	default:
		return nil, fmt.Errorf("invalid rd type to marshal: %v", rd)
	}
	return &r, nil
}

func UnmarshalRD(rd *api.RouteDistinguisher) (bgp.RouteDistinguisherInterface, error) {
	switch v := rd.GetRd().(type) {
	case *api.RouteDistinguisher_TwoOctetAsn:
		return bgp.NewRouteDistinguisherTwoOctetAS(uint16(v.TwoOctetAsn.Admin), v.TwoOctetAsn.Assigned), nil
	case *api.RouteDistinguisher_IpAddress:
		rd := bgp.NewRouteDistinguisherIPAddressAS(v.IpAddress.Admin, uint16(v.IpAddress.Assigned))
		if rd == nil {
			return nil, fmt.Errorf("invalid address for route distinguisher: %s", v.IpAddress.Admin)
		}
		return rd, nil
	case *api.RouteDistinguisher_FourOctetAsn:
		return bgp.NewRouteDistinguisherFourOctetAS(v.FourOctetAsn.Admin, uint16(v.FourOctetAsn.Assigned)), nil
	}
	return nil, fmt.Errorf("unknown route distinguisher")
}

func NewEthernetSegmentIdentifierFromNative(a *bgp.EthernetSegmentIdentifier) (*api.EthernetSegmentIdentifier, error) {
	return &api.EthernetSegmentIdentifier{
		Type:  uint32(a.Type),
		Value: a.Value,
	}, nil
}

func unmarshalESI(a *api.EthernetSegmentIdentifier) (*bgp.EthernetSegmentIdentifier, error) {
	return &bgp.EthernetSegmentIdentifier{
		Type:  bgp.ESIType(a.Type),
		Value: a.Value,
	}, nil
}

func MarshalFlowSpecRules(values []bgp.FlowSpecComponentInterface) ([]*api.FlowSpecRule, error) {
	rules := make([]*api.FlowSpecRule, 0, len(values))
	for _, value := range values {
		var rule api.FlowSpecRule
		switch v := value.(type) {
		case *bgp.FlowSpecDestinationPrefix:
			rule.Rule = &api.FlowSpecRule_IpPrefix{IpPrefix: &api.FlowSpecIPPrefix{
				Type:      uint32(bgp.FLOW_SPEC_TYPE_DST_PREFIX),
				PrefixLen: uint32(v.Prefix.(*bgp.IPAddrPrefix).Length),
				Prefix:    v.Prefix.(*bgp.IPAddrPrefix).Prefix.String(),
			}}
		case *bgp.FlowSpecSourcePrefix:
			rule.Rule = &api.FlowSpecRule_IpPrefix{IpPrefix: &api.FlowSpecIPPrefix{
				Type:      uint32(bgp.FLOW_SPEC_TYPE_SRC_PREFIX),
				PrefixLen: uint32(v.Prefix.(*bgp.IPAddrPrefix).Length),
				Prefix:    v.Prefix.(*bgp.IPAddrPrefix).Prefix.String(),
			}}
		case *bgp.FlowSpecDestinationPrefix6:
			rule.Rule = &api.FlowSpecRule_IpPrefix{IpPrefix: &api.FlowSpecIPPrefix{
				Type:      uint32(bgp.FLOW_SPEC_TYPE_DST_PREFIX),
				PrefixLen: uint32(v.Prefix.(*bgp.IPv6AddrPrefix).Length),
				Prefix:    v.Prefix.(*bgp.IPv6AddrPrefix).Prefix.String(),
				Offset:    uint32(v.Offset),
			}}
		case *bgp.FlowSpecSourcePrefix6:
			rule.Rule = &api.FlowSpecRule_IpPrefix{IpPrefix: &api.FlowSpecIPPrefix{
				Type:      uint32(bgp.FLOW_SPEC_TYPE_SRC_PREFIX),
				PrefixLen: uint32(v.Prefix.(*bgp.IPv6AddrPrefix).Length),
				Prefix:    v.Prefix.(*bgp.IPv6AddrPrefix).Prefix.String(),
				Offset:    uint32(v.Offset),
			}}
		case *bgp.FlowSpecSourceMac:
			rule.Rule = &api.FlowSpecRule_Mac{Mac: &api.FlowSpecMAC{
				Type:    uint32(bgp.FLOW_SPEC_TYPE_SRC_MAC),
				Address: v.Mac.String(),
			}}
		case *bgp.FlowSpecDestinationMac:
			rule.Rule = &api.FlowSpecRule_Mac{Mac: &api.FlowSpecMAC{
				Type:    uint32(bgp.FLOW_SPEC_TYPE_DST_MAC),
				Address: v.Mac.String(),
			}}
		case *bgp.FlowSpecComponent:
			items := make([]*api.FlowSpecComponentItem, 0, len(v.Items))
			for _, i := range v.Items {
				items = append(items, &api.FlowSpecComponentItem{
					Op:    uint32(i.Op),
					Value: i.Value,
				})
			}
			rule.Rule = &api.FlowSpecRule_Component{Component: &api.FlowSpecComponent{
				Type:  uint32(v.Type()),
				Items: items,
			}}
		}
		rules = append(rules, &rule)
	}
	return rules, nil
}

func UnmarshalFlowSpecRules(values []*api.FlowSpecRule) ([]bgp.FlowSpecComponentInterface, error) {
	rules := make([]bgp.FlowSpecComponentInterface, 0, len(values))
	for _, value := range values {
		var rule bgp.FlowSpecComponentInterface
		switch r := value.GetRule().(type) {
		case *api.FlowSpecRule_IpPrefix:
			v := r.IpPrefix
			typ := bgp.BGPFlowSpecType(v.Type)
			isIPv4 := net.ParseIP(v.Prefix).To4() != nil
			switch {
			case typ == bgp.FLOW_SPEC_TYPE_DST_PREFIX && isIPv4:
				rule = bgp.NewFlowSpecDestinationPrefix(bgp.NewIPAddrPrefix(uint8(v.PrefixLen), v.Prefix))
			case typ == bgp.FLOW_SPEC_TYPE_SRC_PREFIX && isIPv4:
				rule = bgp.NewFlowSpecSourcePrefix(bgp.NewIPAddrPrefix(uint8(v.PrefixLen), v.Prefix))
			case typ == bgp.FLOW_SPEC_TYPE_DST_PREFIX && !isIPv4:
				rule = bgp.NewFlowSpecDestinationPrefix6(bgp.NewIPv6AddrPrefix(uint8(v.PrefixLen), v.Prefix), uint8(v.Offset))
			case typ == bgp.FLOW_SPEC_TYPE_SRC_PREFIX && !isIPv4:
				rule = bgp.NewFlowSpecSourcePrefix6(bgp.NewIPv6AddrPrefix(uint8(v.PrefixLen), v.Prefix), uint8(v.Offset))
			}
		case *api.FlowSpecRule_Mac:
			v := r.Mac
			typ := bgp.BGPFlowSpecType(v.Type)
			mac, err := net.ParseMAC(v.Address)
			if err != nil {
				return nil, fmt.Errorf("invalid mac address for %s flow spec component: %s", typ.String(), v.Address)
			}
			switch typ {
			case bgp.FLOW_SPEC_TYPE_SRC_MAC:
				rule = bgp.NewFlowSpecSourceMac(mac)
			case bgp.FLOW_SPEC_TYPE_DST_MAC:
				rule = bgp.NewFlowSpecDestinationMac(mac)
			}
		case *api.FlowSpecRule_Component:
			v := r.Component
			items := make([]*bgp.FlowSpecComponentItem, 0, len(v.Items))
			for _, item := range v.Items {
				items = append(items, bgp.NewFlowSpecComponentItem(uint8(item.Op), item.Value))
			}
			rule = bgp.NewFlowSpecComponent(bgp.BGPFlowSpecType(v.Type), items)
		}
		if rule == nil {
			return nil, fmt.Errorf("invalid flow spec component: %v", value)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func MarshalLsNodeDescriptor(d *bgp.LsNodeDescriptor) (*api.LsNodeDescriptor, error) {
	return &api.LsNodeDescriptor{
		Asn:                    d.Asn,
		BgpLsId:                d.BGPLsID,
		OspfAreaId:             d.OspfAreaID,
		Pseudonode:             d.PseudoNode,
		IgpRouterId:            d.IGPRouterID,
		BgpRouterId:            d.BGPRouterID.String(),
		BgpConfederationMember: d.BGPConfederationMember,
	}, nil
}

func MarshalLsLinkDescriptor(n *bgp.LsLinkDescriptor) (*api.LsLinkDescriptor, error) {
	return &api.LsLinkDescriptor{
		LinkLocalId:       uint32OrDefault(n.LinkLocalID),
		LinkRemoteId:      uint32OrDefault(n.LinkRemoteID),
		InterfaceAddrIpv4: ipOrDefault(n.InterfaceAddrIPv4),
		NeighborAddrIpv4:  ipOrDefault(n.NeighborAddrIPv4),
		InterfaceAddrIpv6: ipOrDefault(n.InterfaceAddrIPv6),
		NeighborAddrIpv6:  ipOrDefault(n.NeighborAddrIPv6),
	}, nil
}

func MarshalLsPrefixDescriptor(d *bgp.LsPrefixDescriptor) (*api.LsPrefixDescriptor, error) {
	p := &api.LsPrefixDescriptor{
		OspfRouteType: api.LsOspfRouteType(d.OSPFRouteType),
	}

	for _, ip := range d.IPReachability {
		p.IpReachability = append(p.IpReachability, ip.String())
	}
	return p, nil
}

func MarshalLsNodeNLRI(n *bgp.LsNodeNLRI) (*api.LsAddrPrefix_LsNLRI, error) {
	ln, err := MarshalLsNodeDescriptor(n.LocalNodeDesc.(*bgp.LsTLVNodeDescriptor).Extract())
	if err != nil {
		return nil, err
	}
	node := &api.LsAddrPrefix_LsNLRI{
		Nlri: &api.LsAddrPrefix_LsNLRI_Node{
			Node: &api.LsNodeNLRI{LocalNode: ln},
		},
	}
	return node, nil
}

func MarshalLsLinkNLRI(n *bgp.LsLinkNLRI) (*api.LsAddrPrefix_LsNLRI, error) {
	desc := &bgp.LsLinkDescriptor{}
	desc.ParseTLVs(n.LinkDesc)

	var err error
	ln, err := MarshalLsNodeDescriptor(n.LocalNodeDesc.(*bgp.LsTLVNodeDescriptor).Extract())
	if err != nil {
		return nil, err
	}
	rn, err := MarshalLsNodeDescriptor(n.RemoteNodeDesc.(*bgp.LsTLVNodeDescriptor).Extract())
	if err != nil {
		return nil, err
	}

	ld, err := MarshalLsLinkDescriptor(desc)
	if err != nil {
		return nil, err
	}

	link := &api.LsAddrPrefix_LsNLRI{
		Nlri: &api.LsAddrPrefix_LsNLRI_Link{
			Link: &api.LsLinkNLRI{
				LocalNode:      ln,
				RemoteNode:     rn,
				LinkDescriptor: ld,
			},
		},
	}
	return link, nil
}

func MarshalLsPrefixV4NLRI(n *bgp.LsPrefixV4NLRI) (*api.LsAddrPrefix_LsNLRI, error) {
	desc := &bgp.LsPrefixDescriptor{}
	desc.ParseTLVs(n.PrefixDesc, false)

	ln, err := MarshalLsNodeDescriptor(n.LocalNodeDesc.(*bgp.LsTLVNodeDescriptor).Extract())
	if err != nil {
		return nil, err
	}

	pd, err := MarshalLsPrefixDescriptor(desc)
	if err != nil {
		return nil, err
	}

	prefix := &api.LsAddrPrefix_LsNLRI{
		Nlri: &api.LsAddrPrefix_LsNLRI_PrefixV4{
			PrefixV4: &api.LsPrefixV4NLRI{
				LocalNode:        ln,
				PrefixDescriptor: pd,
			},
		},
	}
	return prefix, nil
}

func MarshalLsPrefixV6NLRI(n *bgp.LsPrefixV6NLRI) (*api.LsAddrPrefix_LsNLRI, error) {
	desc := &bgp.LsPrefixDescriptor{}
	desc.ParseTLVs(n.PrefixDesc, true)

	ln, err := MarshalLsNodeDescriptor(n.LocalNodeDesc.(*bgp.LsTLVNodeDescriptor).Extract())
	if err != nil {
		return nil, err
	}

	pd, err := MarshalLsPrefixDescriptor(desc)
	if err != nil {
		return nil, err
	}

	prefix := &api.LsAddrPrefix_LsNLRI{
		Nlri: &api.LsAddrPrefix_LsNLRI_PrefixV6{
			PrefixV6: &api.LsPrefixV6NLRI{
				LocalNode:        ln,
				PrefixDescriptor: pd,
			},
		},
	}
	return prefix, nil
}

func MarshalLsSRv6SIDNLRI(n *bgp.LsSrv6SIDNLRI) (*api.LsAddrPrefix_LsNLRI, error) {
	ln, err := MarshalLsNodeDescriptor(n.LocalNodeDesc.(*bgp.LsTLVNodeDescriptor).Extract())
	if err != nil {
		return nil, err
	}
	srv6Info, ok := n.Srv6SIDInfo.(*bgp.LsTLVSrv6SIDInfo)
	if !ok {
		return nil, fmt.Errorf("invalid SRv6 SID info type")
	}
	ssi, err := MarshalLsTLVSrv6SIDInfo(srv6Info)
	if err != nil {
		return nil, err
	}
	mti, err := MarshalLsTLVMultiTopoID(n.MultiTopoID.(*bgp.LsTLVMultiTopoID))
	if err != nil {
		return nil, err
	}

	srv6sid := &api.LsAddrPrefix_LsNLRI{Nlri: &api.LsAddrPrefix_LsNLRI_Srv6Sid{
		Srv6Sid: &api.LsSrv6SIDNLRI{
			LocalNode:          ln,
			Srv6SidInformation: ssi,
			MultiTopoId:        mti,
		},
	}}

	return srv6sid, nil
}

func MarshalLsBgpPeerSegmentSid(n *bgp.LsBgpPeerSegmentSID) (*api.LsBgpPeerSegmentSID, error) {
	flags := &api.LsBgpPeerSegmentSIDFlags{
		Value:      n.Flags.Value,
		Local:      n.Flags.Local,
		Backup:     n.Flags.Backup,
		Persistent: n.Flags.Persistent,
	}
	sid := &api.LsBgpPeerSegmentSID{
		Flags:  flags,
		Weight: uint32(n.Weight),
		Sid:    n.SID,
	}

	return sid, nil
}

func UnmarshalLsBgpPeerSegmentSid(a *api.LsBgpPeerSegmentSID) (*bgp.LsBgpPeerSegmentSID, error) {
	flags := &bgp.LsAttributeBgpPeerSegmentSIDFlags{
		Value:      a.Flags.Value,
		Local:      a.Flags.Local,
		Backup:     a.Flags.Backup,
		Persistent: a.Flags.Persistent,
	}

	sid := &bgp.LsBgpPeerSegmentSID{
		Flags:  *flags,
		Weight: uint8(a.Weight),
		SID:    a.Sid,
	}

	return sid, nil
}

func UnmarshalLsNodeDescriptor(nd *api.LsNodeDescriptor) (*bgp.LsNodeDescriptor, error) {
	return &bgp.LsNodeDescriptor{
		Asn:                    nd.Asn,
		BGPLsID:                nd.BgpLsId,
		OspfAreaID:             nd.OspfAreaId,
		PseudoNode:             nd.Pseudonode,
		IGPRouterID:            nd.IgpRouterId,
		BGPRouterID:            net.ParseIP(nd.BgpRouterId),
		BGPConfederationMember: nd.BgpConfederationMember,
	}, nil
}

func UnmarshalLsLinkDescriptor(ld *api.LsLinkDescriptor) (*bgp.LsLinkDescriptor, error) {
	ifAddrIPv4 := net.IP{}
	neiAddrIPv4 := net.IP{}
	ifAddrIPv6 := net.IP{}
	neiAddrIPv6 := net.IP{}

	if ld.GetInterfaceAddrIpv4() != "" {
		ifAddrIPv4 = net.ParseIP(ld.InterfaceAddrIpv4).To4()
	}
	if ld.GetNeighborAddrIpv4() != "" {
		neiAddrIPv4 = net.ParseIP(ld.NeighborAddrIpv4).To4()
	}
	if ld.GetInterfaceAddrIpv6() != "" {
		ifAddrIPv6 = net.ParseIP(ld.InterfaceAddrIpv6).To16()
	}
	if ld.GetNeighborAddrIpv6() != "" {
		neiAddrIPv6 = net.ParseIP(ld.NeighborAddrIpv6).To16()
	}

	return &bgp.LsLinkDescriptor{
		LinkLocalID:       &ld.LinkLocalId,
		LinkRemoteID:      &ld.LinkRemoteId,
		InterfaceAddrIPv4: &ifAddrIPv4,
		NeighborAddrIPv4:  &neiAddrIPv4,
		InterfaceAddrIPv6: &ifAddrIPv6,
		NeighborAddrIPv6:  &neiAddrIPv6,
	}, nil
}

func UnmarshalPrefixDescriptor(pd *api.LsPrefixDescriptor) (*bgp.LsPrefixDescriptor, error) {
	ipReachability := []net.IPNet{}
	for _, reach := range pd.IpReachability {
		_, ipnet, _ := net.ParseCIDR(reach)
		ipReachability = append(ipReachability, *ipnet)
	}

	ospfRouteType := bgp.LsOspfRouteType(pd.OspfRouteType)

	return &bgp.LsPrefixDescriptor{
		IPReachability: ipReachability,
		OSPFRouteType:  ospfRouteType,
	}, nil
}

func UnmarshalLsPrefixDescriptor(*api.LsPrefixDescriptor) (*bgp.LsPrefixDescriptor, error) {
	return nil, nil
}

func StringToNetIPLsTLVSrv6SIDInfo(s []string) ([]net.IP, uint16) {
	sids := []net.IP{}
	var ssiLen uint16
	for _, sid := range s {
		sids = append(sids, net.ParseIP(sid))
		ssiLen += 16
	}
	return sids, ssiLen
}

func UnmarshalLsTLVSrv6SIDInfo(ssi *api.LsSrv6SIDInformation) (*bgp.LsTLVSrv6SIDInfo, error) {
	sids, ssiLen := StringToNetIPLsTLVSrv6SIDInfo(ssi.Sids)
	return &bgp.LsTLVSrv6SIDInfo{
		LsTLV: bgp.LsTLV{
			Type:   bgp.LS_TLV_SRV6_SID_INFO,
			Length: ssiLen,
		},
		SIDs: sids,
	}, nil
}

func MarshalLsTLVSrv6SIDInfo(info *bgp.LsTLVSrv6SIDInfo) (*api.LsSrv6SIDInformation, error) {
	sids := make([]string, len(info.SIDs))
	for i, ip := range info.SIDs {
		sids[i] = ip.String()
	}
	return &api.LsSrv6SIDInformation{
		Sids: sids,
	}, nil
}

func UnmarshalLsTLVMultiTopoID(mti *api.LsMultiTopologyIdentifier) (*bgp.LsTLVMultiTopoID, error) {
	multiTopoIDs := make([]uint16, len(mti.MultiTopoIds))
	var mtiLen uint16
	for i, v := range mti.MultiTopoIds {
		multiTopoIDs[i] = uint16(v)
		mtiLen += 2
	}

	return &bgp.LsTLVMultiTopoID{
		LsTLV: bgp.LsTLV{
			Type:   bgp.LS_TLV_MULTI_TOPO_ID,
			Length: mtiLen,
		},
		MultiTopoIDs: multiTopoIDs,
	}, nil
}

func MarshalLsTLVMultiTopoID(mti *bgp.LsTLVMultiTopoID) (*api.LsMultiTopologyIdentifier, error) {
	multiTopoIds := make([]uint32, len(mti.MultiTopoIDs))
	for i, v := range mti.MultiTopoIDs {
		multiTopoIds[i] = uint32(v)
	}
	return &api.LsMultiTopologyIdentifier{
		MultiTopoIds: multiTopoIds,
	}, nil
}

func UnmarshalLsAttribute(a *api.LsAttribute) (*bgp.LsAttribute, error) {
	lsAttr := &bgp.LsAttribute{
		Node:           bgp.LsAttributeNode{},
		Link:           bgp.LsAttributeLink{},
		Prefix:         bgp.LsAttributePrefix{},
		BgpPeerSegment: bgp.LsAttributeBgpPeerSegment{},
	}

	// For AttributeNode
	if a.Node != nil {
		nodeLocalRouterID := net.ParseIP(a.Node.LocalRouterId)
		nodeLocalRouterIDv6 := net.ParseIP(a.Node.LocalRouterIdV6)
		srCapabilitiesRanges := []bgp.LsSrRange{}
		if a.Node.SrCapabilities != nil {
			for _, r := range a.Node.SrCapabilities.Ranges {
				srCapabilitiesRanges = append(srCapabilitiesRanges, bgp.LsSrRange{
					Begin: r.Begin,
					End:   r.End,
				})
			}
		}
		srLocalBlockRanges := []bgp.LsSrRange{}
		if a.Node.SrLocalBlock != nil {
			for _, r := range a.Node.SrLocalBlock.Ranges {
				srLocalBlockRanges = append(srLocalBlockRanges, bgp.LsSrRange{
					Begin: r.Begin,
					End:   r.End,
				})
			}
			lsAttr.Node = bgp.LsAttributeNode{
				Flags: &bgp.LsNodeFlags{
					Overload: a.Node.Flags.Overload,
					Attached: a.Node.Flags.Attached,
					External: a.Node.Flags.External,
					ABR:      a.Node.Flags.Abr,
					Router:   a.Node.Flags.Router,
					V6:       a.Node.Flags.V6,
				},
				Opaque:          &a.Node.Opaque,
				Name:            &a.Node.Name,
				IsisArea:        &a.Node.IsisArea,
				LocalRouterID:   &nodeLocalRouterID,
				LocalRouterIDv6: &nodeLocalRouterIDv6,
				SrCapabilties: &bgp.LsSrCapabilities{
					IPv4Supported: a.Node.SrCapabilities.Ipv4Supported,
					IPv6Supported: a.Node.SrCapabilities.Ipv6Supported,
					Ranges:        srCapabilitiesRanges,
				},
				SrAlgorithms: &a.Node.SrAlgorithms,
				SrLocalBlock: &bgp.LsSrLocalBlock{
					Ranges: srLocalBlockRanges,
				},
			}
		}
	}

	// For AttributeLink
	if a.Link != nil {
		var linkName *string
		if a.Link.Name != "" {
			linkName = &a.Link.Name
		}
		linkLocalRouterID := (*net.IP)(nil)
		if a.Link.LocalRouterId != "" {
			localRouterID := net.ParseIP(a.Link.LocalRouterId)
			linkLocalRouterID = &localRouterID
		}
		linkLocalRouterIDv6 := (*net.IP)(nil)
		if a.Link.LocalRouterIdV6 != "" {
			localRouterIDv6 := net.ParseIP(a.Link.LocalRouterIdV6)
			linkLocalRouterIDv6 = &localRouterIDv6
		}
		linkRemoteRouterID := (*net.IP)(nil)
		if a.Link.RemoteRouterId != "" {
			remoteRouterID := net.ParseIP(a.Link.RemoteRouterId)
			linkRemoteRouterID = &remoteRouterID
		}
		linkRemoteRouterIDv6 := (*net.IP)(nil)
		if a.Link.RemoteRouterIdV6 != "" {
			remoteRouterIDv6 := net.ParseIP(a.Link.RemoteRouterIdV6)
			linkRemoteRouterIDv6 = &remoteRouterIDv6
		}
		var linkAdminGroup *uint32
		if a.Link.AdminGroup != 0 {
			linkAdminGroup = &a.Link.AdminGroup
		}
		var linkDefaultTeMetric *uint32
		if a.Link.DefaultTeMetric != 0 {
			linkDefaultTeMetric = &a.Link.DefaultTeMetric
		}
		var linkIgpMetric *uint32
		if a.Link.IgpMetric != 0 {
			linkIgpMetric = &a.Link.IgpMetric
		}
		var linkOpaque *[]byte
		if len(a.Link.Opaque) != 0 {
			linkOpaque = &a.Link.Opaque
		}
		var linkBandwidth *float32
		if a.Link.Bandwidth != 0 {
			linkBandwidth = &a.Link.Bandwidth
		}
		var linkReservableBandwidth *float32
		if a.Link.ReservableBandwidth != 0 {
			linkBandwidth = &a.Link.ReservableBandwidth
		}
		unreservedBandwidth := [8]float32{}
		if a.Link.UnreservedBandwidth != nil {
			copy(unreservedBandwidth[:], a.Link.UnreservedBandwidth)
		}
		var linkSrlgs *[]uint32
		if a.Link.Srlgs != nil {
			linkSrlgs = &a.Link.Srlgs
		}
		var linkSrAdjacencySid *uint32
		if a.Link.SrAdjacencySid != 0 {
			linkSrAdjacencySid = &a.Link.SrAdjacencySid
		}
		lsAttr.Link = bgp.LsAttributeLink{
			Name:                linkName,
			LocalRouterID:       linkLocalRouterID,
			LocalRouterIDv6:     linkLocalRouterIDv6,
			RemoteRouterID:      linkRemoteRouterID,
			RemoteRouterIDv6:    linkRemoteRouterIDv6,
			AdminGroup:          linkAdminGroup,
			DefaultTEMetric:     linkDefaultTeMetric,
			IGPMetric:           linkIgpMetric,
			Opaque:              linkOpaque,
			Bandwidth:           linkBandwidth,
			ReservableBandwidth: linkReservableBandwidth,
			UnreservedBandwidth: &unreservedBandwidth,
			Srlgs:               linkSrlgs,
			SrAdjacencySID:      linkSrAdjacencySid,
		}
	}

	// For AttributePrefix
	if a.Prefix != nil {
		if a.Prefix.IgpFlags != nil {
			lsAttr.Prefix = bgp.LsAttributePrefix{
				IGPFlags: &bgp.LsIGPFlags{
					Down:          a.Prefix.IgpFlags.Down,
					NoUnicast:     a.Prefix.IgpFlags.NoUnicast,
					LocalAddress:  a.Prefix.IgpFlags.LocalAddress,
					PropagateNSSA: a.Prefix.IgpFlags.PropagateNssa,
				},
				Opaque:      &a.Prefix.Opaque,
				SrPrefixSID: &a.Prefix.SrPrefixSid,
			}
		}
	}

	// For AttributeBgpPeerSegment
	if a.BgpPeerSegment != nil {
		lsAttributeBgpPeerSegment := bgp.LsAttributeBgpPeerSegment{}
		if a.BgpPeerSegment.BgpPeerNodeSid != nil {
			lsAttributeBgpPeerSegment.BgpPeerNodeSid, _ = UnmarshalLsBgpPeerSegmentSid(a.BgpPeerSegment.BgpPeerNodeSid)
		}
		if a.BgpPeerSegment.BgpPeerAdjacencySid != nil {
			lsAttributeBgpPeerSegment.BgpPeerAdjacencySid, _ = UnmarshalLsBgpPeerSegmentSid(a.BgpPeerSegment.BgpPeerAdjacencySid)
		}
		if a.BgpPeerSegment.BgpPeerSetSid != nil {
			lsAttributeBgpPeerSegment.BgpPeerSetSid, _ = UnmarshalLsBgpPeerSegmentSid(a.BgpPeerSegment.BgpPeerSetSid)
		}
		lsAttr.BgpPeerSegment = lsAttributeBgpPeerSegment
	}

	return lsAttr, nil
}

func MarshalNLRI(value bgp.AddrPrefixInterface) (*api.NLRI, error) {
	var nlri api.NLRI

	switch v := value.(type) {
	case *bgp.IPAddrPrefix:
		nlri.Nlri = &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{
			PrefixLen: uint32(v.Length),
			Prefix:    v.Prefix.String(),
		}}
	case *bgp.IPv6AddrPrefix:
		nlri.Nlri = &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{
			PrefixLen: uint32(v.Length),
			Prefix:    v.Prefix.String(),
		}}
	case *bgp.LabeledIPAddrPrefix:
		nlri.Nlri = &api.NLRI_LabeledPrefix{LabeledPrefix: &api.LabeledIPAddressPrefix{
			Labels:    v.Labels.Labels,
			PrefixLen: uint32(v.IPPrefixLen()),
			Prefix:    v.Prefix.String(),
		}}
	case *bgp.LabeledIPv6AddrPrefix:
		nlri.Nlri = &api.NLRI_LabeledPrefix{LabeledPrefix: &api.LabeledIPAddressPrefix{
			Labels:    v.Labels.Labels,
			PrefixLen: uint32(v.IPPrefixLen()),
			Prefix:    v.Prefix.String(),
		}}
	case *bgp.EncapNLRI:
		nlri.Nlri = &api.NLRI_Encapsulation{Encapsulation: &api.EncapsulationNLRI{
			Address: v.String(),
		}}
	case *bgp.Encapv6NLRI:
		nlri.Nlri = &api.NLRI_Encapsulation{Encapsulation: &api.EncapsulationNLRI{
			Address: v.String(),
		}}
	case *bgp.VPLSNLRI:
		rd, err := MarshalRD(v.RD())
		if err != nil {
			return nil, err
		}
		nlri.Nlri = &api.NLRI_Vpls{Vpls: &api.VPLSNLRI{
			Rd:             rd,
			VeId:           uint32(v.VEID),
			VeBlockOffset:  uint32(v.VEBlockOffset),
			VeBlockSize:    uint32(v.VEBlockSize),
			LabelBlockBase: v.LabelBlockBase,
		}}
	case *bgp.EVPNNLRI:
		switch r := v.RouteTypeData.(type) {
		case *bgp.EVPNEthernetAutoDiscoveryRoute:
			rd, err := MarshalRD(r.RD)
			if err != nil {
				return nil, err
			}
			esi, err := NewEthernetSegmentIdentifierFromNative(&r.ESI)
			if err != nil {
				return nil, err
			}

			nlri.Nlri = &api.NLRI_EvpnEthernetAd{EvpnEthernetAd: &api.EVPNEthernetAutoDiscoveryRoute{
				Rd:          rd,
				Esi:         esi,
				EthernetTag: r.ETag,
				Label:       r.Label,
			}}
		case *bgp.EVPNMacIPAdvertisementRoute:
			rd, err := MarshalRD(r.RD)
			if err != nil {
				return nil, err
			}
			esi, err := NewEthernetSegmentIdentifierFromNative(&r.ESI)
			if err != nil {
				return nil, err
			}

			nlri.Nlri = &api.NLRI_EvpnMacadv{EvpnMacadv: &api.EVPNMACIPAdvertisementRoute{
				Rd:          rd,
				Esi:         esi,
				EthernetTag: r.ETag,
				MacAddress:  r.MacAddress.String(),
				IpAddress:   r.IPAddress.String(),
				Labels:      r.Labels,
			}}
		case *bgp.EVPNMulticastEthernetTagRoute:
			rd, err := MarshalRD(r.RD)
			if err != nil {
				return nil, err
			}
			nlri.Nlri = &api.NLRI_EvpnMulticast{EvpnMulticast: &api.EVPNInclusiveMulticastEthernetTagRoute{
				Rd:          rd,
				EthernetTag: r.ETag,
				IpAddress:   r.IPAddress.String(),
			}}
		case *bgp.EVPNEthernetSegmentRoute:
			rd, err := MarshalRD(r.RD)
			if err != nil {
				return nil, err
			}
			esi, err := NewEthernetSegmentIdentifierFromNative(&r.ESI)
			if err != nil {
				return nil, err
			}
			nlri.Nlri = &api.NLRI_EvpnEthernetSegment{EvpnEthernetSegment: &api.EVPNEthernetSegmentRoute{
				Rd:        rd,
				Esi:       esi,
				IpAddress: r.IPAddress.String(),
			}}
		case *bgp.EVPNIPPrefixRoute:
			rd, err := MarshalRD(r.RD)
			if err != nil {
				return nil, err
			}
			esi, err := NewEthernetSegmentIdentifierFromNative(&r.ESI)
			if err != nil {
				return nil, err
			}
			nlri.Nlri = &api.NLRI_EvpnIpPrefix{EvpnIpPrefix: &api.EVPNIPPrefixRoute{
				Rd:          rd,
				Esi:         esi,
				EthernetTag: r.ETag,
				IpPrefix:    r.IPPrefix.String(),
				IpPrefixLen: uint32(r.IPPrefixLength),
				Label:       r.Label,
				GwAddress:   r.GWIPAddress.String(),
			}}
		}
	case *bgp.LabeledVPNIPAddrPrefix:
		rd, err := MarshalRD(v.RD)
		if err != nil {
			return nil, err
		}
		nlri.Nlri = &api.NLRI_LabeledVpnIpPrefix{LabeledVpnIpPrefix: &api.LabeledVPNIPAddressPrefix{
			Labels:    v.Labels.Labels,
			Rd:        rd,
			PrefixLen: uint32(v.IPPrefixLen()),
			Prefix:    v.Prefix.String(),
		}}
	case *bgp.LabeledVPNIPv6AddrPrefix:
		rd, err := MarshalRD(v.RD)
		if err != nil {
			return nil, err
		}
		nlri.Nlri = &api.NLRI_LabeledVpnIpPrefix{LabeledVpnIpPrefix: &api.LabeledVPNIPAddressPrefix{
			Labels:    v.Labels.Labels,
			Rd:        rd,
			PrefixLen: uint32(v.IPPrefixLen()),
			Prefix:    v.Prefix.String(),
		}}
	case *bgp.RouteTargetMembershipNLRI:
		rt, err := func() (*api.RouteTarget, error) {
			if v.RouteTarget == nil {
				return nil, nil
			}
			return MarshalRT(v.RouteTarget)
		}()
		if err != nil {
			return nil, err
		}
		nlri.Nlri = &api.NLRI_RouteTargetMembership{RouteTargetMembership: &api.RouteTargetMembershipNLRI{
			Asn: v.AS,
			Rt:  rt,
		}}
	case *bgp.FlowSpecIPv4Unicast:
		rules, err := MarshalFlowSpecRules(v.Value)
		if err != nil {
			return nil, err
		}
		nlri.Nlri = &api.NLRI_FlowSpec{FlowSpec: &api.FlowSpecNLRI{
			Rules: rules,
		}}
	case *bgp.FlowSpecIPv6Unicast:
		rules, err := MarshalFlowSpecRules(v.Value)
		if err != nil {
			return nil, err
		}
		nlri.Nlri = &api.NLRI_FlowSpec{FlowSpec: &api.FlowSpecNLRI{
			Rules: rules,
		}}
	case *bgp.FlowSpecIPv4VPN:
		rd, err := MarshalRD(v.RD())
		if err != nil {
			return nil, err
		}
		rules, err := MarshalFlowSpecRules(v.Value)
		if err != nil {
			return nil, err
		}
		nlri.Nlri = &api.NLRI_VpnFlowSpec{VpnFlowSpec: &api.VPNFlowSpecNLRI{
			Rd:    rd,
			Rules: rules,
		}}
	case *bgp.FlowSpecIPv6VPN:
		rd, err := MarshalRD(v.RD())
		if err != nil {
			return nil, err
		}
		rules, err := MarshalFlowSpecRules(v.Value)
		if err != nil {
			return nil, err
		}
		nlri.Nlri = &api.NLRI_VpnFlowSpec{VpnFlowSpec: &api.VPNFlowSpecNLRI{
			Rd:    rd,
			Rules: rules,
		}}
	case *bgp.FlowSpecL2VPN:
		rd, err := MarshalRD(v.RD())
		if err != nil {
			return nil, err
		}
		rules, err := MarshalFlowSpecRules(v.Value)
		if err != nil {
			return nil, err
		}
		nlri.Nlri = &api.NLRI_VpnFlowSpec{VpnFlowSpec: &api.VPNFlowSpecNLRI{
			Rd:    rd,
			Rules: rules,
		}}
	case *bgp.OpaqueNLRI:
		nlri.Nlri = &api.NLRI_Opaque{Opaque: &api.OpaqueNLRI{
			Key:   v.Key,
			Value: v.Value,
		}}
	case *bgp.LsAddrPrefix:
		switch n := v.NLRI.(type) {
		case *bgp.LsNodeNLRI:
			node, err := MarshalLsNodeNLRI(n)
			if err != nil {
				return nil, err
			}
			nlri.Nlri = &api.NLRI_LsAddrPrefix{LsAddrPrefix: &api.LsAddrPrefix{
				Type:       api.LsNLRIType_LS_NLRI_TYPE_NODE,
				Nlri:       node,
				Length:     uint32(n.Length),
				ProtocolId: api.LsProtocolID(n.ProtocolID),
				Identifier: n.Identifier,
			}}
		case *bgp.LsLinkNLRI:
			node, err := MarshalLsLinkNLRI(n)
			if err != nil {
				return nil, err
			}
			nlri.Nlri = &api.NLRI_LsAddrPrefix{LsAddrPrefix: &api.LsAddrPrefix{
				Type:       api.LsNLRIType_LS_NLRI_TYPE_LINK,
				Nlri:       node,
				Length:     uint32(n.Length),
				ProtocolId: api.LsProtocolID(n.ProtocolID),
				Identifier: n.Identifier,
			}}
		case *bgp.LsPrefixV4NLRI:
			node, err := MarshalLsPrefixV4NLRI(n)
			if err != nil {
				return nil, err
			}
			nlri.Nlri = &api.NLRI_LsAddrPrefix{LsAddrPrefix: &api.LsAddrPrefix{
				Type:       api.LsNLRIType_LS_NLRI_TYPE_PREFIX_V4,
				Nlri:       node,
				Length:     uint32(n.Length),
				ProtocolId: api.LsProtocolID(n.ProtocolID),
				Identifier: n.Identifier,
			}}
		case *bgp.LsPrefixV6NLRI:
			node, err := MarshalLsPrefixV6NLRI(n)
			if err != nil {
				return nil, err
			}
			nlri.Nlri = &api.NLRI_LsAddrPrefix{LsAddrPrefix: &api.LsAddrPrefix{
				Type:       api.LsNLRIType_LS_NLRI_TYPE_PREFIX_V6,
				Nlri:       node,
				Length:     uint32(n.Length),
				ProtocolId: api.LsProtocolID(n.ProtocolID),
				Identifier: n.Identifier,
			}}
		case *bgp.LsSrv6SIDNLRI:
			srv6, err := MarshalLsSRv6SIDNLRI(n)
			if err != nil {
				return nil, err
			}
			nlri.Nlri = &api.NLRI_LsAddrPrefix{LsAddrPrefix: &api.LsAddrPrefix{
				Type:       api.LsNLRIType_LS_NLRI_TYPE_SRV6_SID,
				Nlri:       srv6,
				Length:     uint32(v.Length),
				ProtocolId: api.LsProtocolID(n.ProtocolID),
				Identifier: n.Identifier,
			}}
		}
	case *bgp.SRPolicyIPv4:
		nlri.Nlri = &api.NLRI_SrPolicy{SrPolicy: &api.SRPolicyNLRI{
			Length:        uint32(v.Length),
			Distinguisher: v.Distinguisher,
			Color:         v.Color,
			Endpoint:      v.Endpoint,
		}}
	case *bgp.SRPolicyIPv6:
		nlri.Nlri = &api.NLRI_SrPolicy{SrPolicy: &api.SRPolicyNLRI{
			Length:        uint32(v.Length),
			Distinguisher: v.Distinguisher,
			Color:         v.Color,
			Endpoint:      v.Endpoint,
		}}
	case *bgp.MUPNLRI:
		switch r := v.RouteTypeData.(type) {
		case *bgp.MUPInterworkSegmentDiscoveryRoute:
			rd, err := MarshalRD(r.RD)
			if err != nil {
				return nil, err
			}
			nlri.Nlri = &api.NLRI_MupInterworkSegmentDiscovery{
				MupInterworkSegmentDiscovery: &api.MUPInterworkSegmentDiscoveryRoute{
					Rd:     rd,
					Prefix: r.Prefix.String(),
				},
			}
		case *bgp.MUPDirectSegmentDiscoveryRoute:
			rd, err := MarshalRD(r.RD)
			if err != nil {
				return nil, err
			}
			nlri.Nlri = &api.NLRI_MupDirectSegmentDiscovery{
				MupDirectSegmentDiscovery: &api.MUPDirectSegmentDiscoveryRoute{
					Rd:      rd,
					Address: r.Address.String(),
				},
			}
		case *bgp.MUPType1SessionTransformedRoute:
			rd, err := MarshalRD(r.RD)
			if err != nil {
				return nil, err
			}
			var sal uint32
			var sa string
			if r.SourceAddressLength > 0 && r.SourceAddress != nil {
				sal = uint32(r.SourceAddressLength)
				sa = r.SourceAddress.String()
			}
			nlri.Nlri = &api.NLRI_MupType_1SessionTransformed{
				MupType_1SessionTransformed: &api.MUPType1SessionTransformedRoute{
					Rd:                    rd,
					Prefix:                r.Prefix.String(),
					Teid:                  binary.BigEndian.Uint32(r.TEID.AsSlice()),
					Qfi:                   uint32(r.QFI),
					EndpointAddressLength: uint32(r.EndpointAddressLength),
					EndpointAddress:       r.EndpointAddress.String(),
					SourceAddressLength:   sal,
					SourceAddress:         sa,
				},
			}
		case *bgp.MUPType2SessionTransformedRoute:
			rd, err := MarshalRD(r.RD)
			if err != nil {
				return nil, err
			}
			nlri.Nlri = &api.NLRI_MupType_2SessionTransformed{
				MupType_2SessionTransformed: &api.MUPType2SessionTransformedRoute{
					Rd:                    rd,
					EndpointAddressLength: uint32(r.EndpointAddressLength),
					EndpointAddress:       r.EndpointAddress.String(),
					Teid:                  binary.BigEndian.Uint32(r.TEID.AsSlice()),
				},
			}
		}
	default:
		return nil, fmt.Errorf("invalid nlri type to marshal: %T", value)
	}

	return &nlri, nil
}

func MarshalNLRIs(values []bgp.AddrPrefixInterface) ([]*api.NLRI, error) {
	nlris := make([]*api.NLRI, 0, len(values))
	for _, value := range values {
		nlri, err := MarshalNLRI(value)
		if err != nil {
			return nil, err
		}
		nlris = append(nlris, nlri)
	}
	return nlris, nil
}

func UnmarshalNLRI(rf bgp.Family, an *api.NLRI) (bgp.AddrPrefixInterface, error) {
	var nlri bgp.AddrPrefixInterface

	switch n := an.GetNlri().(type) {
	case *api.NLRI_Prefix:
		v := n.Prefix
		switch rf {
		case bgp.RF_IPv4_UC:
			nlri = bgp.NewIPAddrPrefix(uint8(v.PrefixLen), v.Prefix)
		case bgp.RF_IPv6_UC:
			nlri = bgp.NewIPv6AddrPrefix(uint8(v.PrefixLen), v.Prefix)
		}
	case *api.NLRI_LabeledPrefix:
		v := n.LabeledPrefix
		switch rf {
		case bgp.RF_IPv4_MPLS:
			nlri = bgp.NewLabeledIPAddrPrefix(uint8(v.PrefixLen), v.Prefix, *bgp.NewMPLSLabelStack(v.Labels...))
		case bgp.RF_IPv6_MPLS:
			nlri = bgp.NewLabeledIPv6AddrPrefix(uint8(v.PrefixLen), v.Prefix, *bgp.NewMPLSLabelStack(v.Labels...))
		}
	case *api.NLRI_Encapsulation:
		v := n.Encapsulation
		switch rf {
		case bgp.RF_IPv4_ENCAP:
			nlri = bgp.NewEncapNLRI(v.Address)
		case bgp.RF_IPv6_ENCAP:
			nlri = bgp.NewEncapv6NLRI(v.Address)
		}
	case *api.NLRI_Vpls:
		v := n.Vpls
		if rf == bgp.RF_VPLS {
			rd, err := UnmarshalRD(v.Rd)
			if err != nil {
				return nil, err
			}
			nlri = bgp.NewVPLSNLRI(
				rd,
				uint16(v.VeId),
				uint16(v.VeBlockOffset),
				uint16(v.VeBlockSize),
				v.LabelBlockBase)
		}
	case *api.NLRI_EvpnEthernetAd:
		v := n.EvpnEthernetAd
		if rf == bgp.RF_EVPN {
			rd, err := UnmarshalRD(v.Rd)
			if err != nil {
				return nil, err
			}
			esi, err := unmarshalESI(v.Esi)
			if err != nil {
				return nil, err
			}
			nlri = bgp.NewEVPNEthernetAutoDiscoveryRoute(rd, *esi, v.EthernetTag, v.Label)
		}
	case *api.NLRI_EvpnMacadv:
		v := n.EvpnMacadv
		if rf == bgp.RF_EVPN {
			rd, err := UnmarshalRD(v.Rd)
			if err != nil {
				return nil, err
			}
			esi, err := unmarshalESI(v.Esi)
			if err != nil {
				return nil, err
			}
			nlri = bgp.NewEVPNMacIPAdvertisementRoute(rd, *esi, v.EthernetTag, v.MacAddress, v.IpAddress, v.Labels)
		}
	case *api.NLRI_EvpnMulticast:
		v := n.EvpnMulticast
		if rf == bgp.RF_EVPN {
			rd, err := UnmarshalRD(v.Rd)
			if err != nil {
				return nil, err
			}
			nlri = bgp.NewEVPNMulticastEthernetTagRoute(rd, v.EthernetTag, v.IpAddress)
		}
	case *api.NLRI_EvpnEthernetSegment:
		v := n.EvpnEthernetSegment
		if rf == bgp.RF_EVPN {
			rd, err := UnmarshalRD(v.Rd)
			if err != nil {
				return nil, err
			}
			esi, err := unmarshalESI(v.Esi)
			if err != nil {
				return nil, err
			}
			nlri = bgp.NewEVPNEthernetSegmentRoute(rd, *esi, v.IpAddress)
		}
	case *api.NLRI_EvpnIpPrefix:
		v := n.EvpnIpPrefix
		if rf == bgp.RF_EVPN {
			rd, err := UnmarshalRD(v.Rd)
			if err != nil {
				return nil, err
			}
			esi, err := unmarshalESI(v.Esi)
			if err != nil {
				return nil, err
			}
			nlri = bgp.NewEVPNIPPrefixRoute(rd, *esi, v.EthernetTag, uint8(v.IpPrefixLen), v.IpPrefix, v.GwAddress, v.Label)
		}
	case *api.NLRI_SrPolicy:
		v := n.SrPolicy
		switch rf {
		case bgp.RF_SR_POLICY_IPv4:
			nlri = bgp.NewSRPolicyIPv4(v.Length, v.Distinguisher, v.Color, v.Endpoint)
		case bgp.RF_SR_POLICY_IPv6:
			nlri = bgp.NewSRPolicyIPv6(v.Length, v.Distinguisher, v.Color, v.Endpoint)
		}
	case *api.NLRI_LabeledVpnIpPrefix:
		v := n.LabeledVpnIpPrefix
		rd, err := UnmarshalRD(v.Rd)
		if err != nil {
			return nil, err
		}
		switch rf {
		case bgp.RF_IPv4_VPN:
			nlri = bgp.NewLabeledVPNIPAddrPrefix(uint8(v.PrefixLen), v.Prefix, *bgp.NewMPLSLabelStack(v.Labels...), rd)
		case bgp.RF_IPv6_VPN:
			nlri = bgp.NewLabeledVPNIPv6AddrPrefix(uint8(v.PrefixLen), v.Prefix, *bgp.NewMPLSLabelStack(v.Labels...), rd)
		}
	case *api.NLRI_RouteTargetMembership:
		v := n.RouteTargetMembership
		rt, err := func() (bgp.ExtendedCommunityInterface, error) {
			if v.Rt == nil {
				return nil, nil
			}
			return UnmarshalRT(v.Rt)
		}()
		if err != nil {
			return nil, err
		}
		nlri = bgp.NewRouteTargetMembershipNLRI(v.Asn, rt)
	case *api.NLRI_FlowSpec:
		v := n.FlowSpec
		rules, err := UnmarshalFlowSpecRules(v.Rules)
		if err != nil {
			return nil, err
		}
		switch rf {
		case bgp.RF_FS_IPv4_UC:
			nlri = bgp.NewFlowSpecIPv4Unicast(rules)
		case bgp.RF_FS_IPv6_UC:
			nlri = bgp.NewFlowSpecIPv6Unicast(rules)
		}
	case *api.NLRI_VpnFlowSpec:
		v := n.VpnFlowSpec
		rd, err := UnmarshalRD(v.Rd)
		if err != nil {
			return nil, err
		}
		rules, err := UnmarshalFlowSpecRules(v.Rules)
		if err != nil {
			return nil, err
		}
		switch rf {
		case bgp.RF_FS_IPv4_VPN:
			nlri = bgp.NewFlowSpecIPv4VPN(rd, rules)
		case bgp.RF_FS_IPv6_VPN:
			nlri = bgp.NewFlowSpecIPv6VPN(rd, rules)
		case bgp.RF_FS_L2_VPN:
			nlri = bgp.NewFlowSpecL2VPN(rd, rules)
		}
	case *api.NLRI_Opaque:
		v := n.Opaque
		nlri = bgp.NewOpaqueNLRI(v.Key, v.Value)
	case *api.NLRI_MupInterworkSegmentDiscovery:
		v := n.MupInterworkSegmentDiscovery
		rd, err := UnmarshalRD(v.Rd)
		if err != nil {
			return nil, err
		}
		prefix, err := netip.ParsePrefix(v.Prefix)
		if err != nil {
			return nil, err
		}
		nlri = bgp.NewMUPInterworkSegmentDiscoveryRoute(rd, prefix)
	case *api.NLRI_MupDirectSegmentDiscovery:
		v := n.MupDirectSegmentDiscovery
		rd, err := UnmarshalRD(v.Rd)
		if err != nil {
			return nil, err
		}
		address, err := netip.ParseAddr(v.Address)
		if err != nil {
			return nil, err
		}
		nlri = bgp.NewMUPDirectSegmentDiscoveryRoute(rd, address)
	case *api.NLRI_MupType_1SessionTransformed:
		v := n.MupType_1SessionTransformed
		rd, err := UnmarshalRD(v.Rd)
		if err != nil {
			return nil, err
		}
		prefix, err := netip.ParsePrefix(v.Prefix)
		if err != nil {
			return nil, err
		}
		ea, err := netip.ParseAddr(v.EndpointAddress)
		if err != nil {
			return nil, err
		}
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, v.Teid)
		teid, ok := netip.AddrFromSlice(b)
		if !ok {
			return nil, fmt.Errorf("invalid teid: %x", v.Teid)
		}
		var sa *netip.Addr
		if v.SourceAddressLength > 0 && v.SourceAddress != "" {
			a, err := netip.ParseAddr(v.SourceAddress)
			if err != nil {
				return nil, err
			}
			sa = &a
		}
		nlri = bgp.NewMUPType1SessionTransformedRoute(rd, prefix, teid, uint8(v.Qfi), ea, sa)
	case *api.NLRI_MupType_2SessionTransformed:
		v := n.MupType_2SessionTransformed
		rd, err := UnmarshalRD(v.Rd)
		if err != nil {
			return nil, err
		}
		ea, err := netip.ParseAddr(v.EndpointAddress)
		if err != nil {
			return nil, err
		}
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, v.Teid)
		teid, ok := netip.AddrFromSlice(b)
		if !ok {
			return nil, fmt.Errorf("invalid teid: %x", v.Teid)
		}
		nlri = bgp.NewMUPType2SessionTransformedRoute(rd, uint8(v.EndpointAddressLength), ea, teid)
	case *api.NLRI_LsAddrPrefix:
		v := n.LsAddrPrefix
		switch t := v.Nlri.GetNlri().(type) {
		case *api.LsAddrPrefix_LsNLRI_Node:
			tp := t.Node
			lnd, err := UnmarshalLsNodeDescriptor(tp.LocalNode)
			if err != nil {
				return nil, err
			}
			lndTLV := bgp.NewLsTLVNodeDescriptor(lnd, bgp.LS_TLV_LOCAL_NODE_DESC)
			nlri = &bgp.LsAddrPrefix{
				Type:   bgp.LS_NLRI_TYPE_NODE,
				Length: uint16(v.Length),
				NLRI: &bgp.LsNodeNLRI{
					LocalNodeDesc: &lndTLV,
					LsNLRI: bgp.LsNLRI{
						NLRIType:   bgp.LsNLRIType(v.Type),
						Length:     uint16(v.Length),
						ProtocolID: bgp.LsProtocolID(v.ProtocolId),
						Identifier: v.Identifier,
					},
				},
			}
		case *api.LsAddrPrefix_LsNLRI_Link:
			tp := t.Link
			lnd, err := UnmarshalLsNodeDescriptor(tp.LocalNode)
			if err != nil {
				return nil, err
			}
			lndTLV := bgp.NewLsTLVNodeDescriptor(lnd, bgp.LS_TLV_LOCAL_NODE_DESC)

			rnd, err := UnmarshalLsNodeDescriptor(tp.RemoteNode)
			if err != nil {
				return nil, err
			}
			rndTLV := bgp.NewLsTLVNodeDescriptor(rnd, bgp.LS_TLV_REMOTE_NODE_DESC)

			ld, err := UnmarshalLsLinkDescriptor(tp.LinkDescriptor)
			if err != nil {
				return nil, err
			}
			ldSubTLVs := bgp.NewLsLinkTLVs(ld)

			nlri = &bgp.LsAddrPrefix{
				Type:   bgp.LS_NLRI_TYPE_LINK,
				Length: uint16(v.Length),
				NLRI: &bgp.LsLinkNLRI{
					LocalNodeDesc:  &lndTLV,
					RemoteNodeDesc: &rndTLV,
					LinkDesc:       ldSubTLVs,
					LsNLRI: bgp.LsNLRI{
						NLRIType:   bgp.LsNLRIType(v.Type),
						Length:     uint16(v.Length),
						ProtocolID: bgp.LsProtocolID(v.ProtocolId),
						Identifier: v.Identifier,
					},
				},
			}
		case *api.LsAddrPrefix_LsNLRI_PrefixV4:
			tp := t.PrefixV4
			lnd, err := UnmarshalLsNodeDescriptor(tp.LocalNode)
			if err != nil {
				return nil, err
			}
			lndTLV := bgp.NewLsTLVNodeDescriptor(lnd, bgp.LS_TLV_LOCAL_NODE_DESC)

			pd, err := UnmarshalPrefixDescriptor(tp.PrefixDescriptor)
			if err != nil {
				return nil, err
			}
			pdSubTLVs := bgp.NewLsPrefixTLVs(pd)

			nlri = &bgp.LsAddrPrefix{
				Type:   bgp.LS_NLRI_TYPE_PREFIX_IPV4,
				Length: uint16(v.Length),
				NLRI: &bgp.LsPrefixV4NLRI{
					LocalNodeDesc: &lndTLV,
					PrefixDesc:    pdSubTLVs,
					LsNLRI: bgp.LsNLRI{
						NLRIType:   bgp.LsNLRIType(v.Type),
						Length:     uint16(v.Length),
						ProtocolID: bgp.LsProtocolID(v.ProtocolId),
						Identifier: v.Identifier,
					},
				},
			}
		case *api.LsAddrPrefix_LsNLRI_PrefixV6:
			tp := t.PrefixV6
			lnd, err := UnmarshalLsNodeDescriptor(tp.LocalNode)
			if err != nil {
				return nil, err
			}
			lndTLV := bgp.NewLsTLVNodeDescriptor(lnd, bgp.LS_TLV_LOCAL_NODE_DESC)

			pd, err := UnmarshalPrefixDescriptor(tp.PrefixDescriptor)
			if err != nil {
				return nil, err
			}
			pdSubTLVs := bgp.NewLsPrefixTLVs(pd)

			nlri = &bgp.LsAddrPrefix{
				Type:   bgp.LS_NLRI_TYPE_PREFIX_IPV6,
				Length: uint16(v.Length),
				NLRI: &bgp.LsPrefixV6NLRI{
					LocalNodeDesc: &lndTLV,
					PrefixDesc:    pdSubTLVs,
					LsNLRI: bgp.LsNLRI{
						NLRIType:   bgp.LsNLRIType(v.Type),
						Length:     uint16(v.Length),
						ProtocolID: bgp.LsProtocolID(v.ProtocolId),
						Identifier: v.Identifier,
					},
				},
			}
		case *api.LsAddrPrefix_LsNLRI_Srv6Sid:
			tp := t.Srv6Sid
			lnd, err := UnmarshalLsNodeDescriptor(tp.LocalNode)
			if err != nil {
				return nil, err
			}
			lndTLV := bgp.NewLsTLVNodeDescriptor(lnd, bgp.LS_TLV_LOCAL_NODE_DESC)

			mtiTLV, err := UnmarshalLsTLVMultiTopoID(tp.MultiTopoId)
			if err != nil {
				return nil, err
			}

			ssiTLV, err := UnmarshalLsTLVSrv6SIDInfo(tp.Srv6SidInformation)
			if err != nil {
				return nil, err
			}

			nlri = &bgp.LsAddrPrefix{
				Type:   bgp.LS_NLRI_TYPE_SRV6_SID,
				Length: uint16(v.Length),
				NLRI: &bgp.LsSrv6SIDNLRI{
					LocalNodeDesc: &lndTLV,
					MultiTopoID:   mtiTLV,
					Srv6SIDInfo:   ssiTLV,
					LsNLRI: bgp.LsNLRI{
						NLRIType:   bgp.LsNLRIType(v.Type),
						Length:     uint16(v.Length),
						ProtocolID: bgp.LsProtocolID(v.ProtocolId),
						Identifier: v.Identifier,
					},
				},
			}

		default:
			return nil, fmt.Errorf("unknown LS prefix type %v", t)
		}
	}

	if nlri == nil {
		return nil, fmt.Errorf("invalid nlri for %s family: %s", rf.String(), an.GetNlri())
	}
	return nlri, nil
}

func UnmarshalNLRIs(rf bgp.Family, values []*api.NLRI) ([]bgp.AddrPrefixInterface, error) {
	nlris := make([]bgp.AddrPrefixInterface, 0, len(values))
	for _, an := range values {
		nlri, err := UnmarshalNLRI(rf, an)
		if err != nil {
			return nil, err
		}
		nlris = append(nlris, nlri)
	}
	return nlris, nil
}

func NewMpReachNLRIAttributeFromNative(a *bgp.PathAttributeMpReachNLRI) (*api.MpReachNLRIAttribute, error) {
	var nexthops []string
	if a.SAFI == bgp.SAFI_FLOW_SPEC_UNICAST || a.SAFI == bgp.SAFI_FLOW_SPEC_VPN {
		nexthops = nil
	} else {
		nexthops = []string{a.Nexthop.String()}
		if a.LinkLocalNexthop != nil && a.LinkLocalNexthop.IsLinkLocalUnicast() {
			nexthops = append(nexthops, a.LinkLocalNexthop.String())
		}
	}
	n, err := MarshalNLRIs(a.Value)
	if err != nil {
		return nil, err
	}
	return &api.MpReachNLRIAttribute{
		Family:   ToApiFamily(a.AFI, a.SAFI),
		NextHops: nexthops,
		Nlris:    n,
	}, nil
}

func NewMpUnreachNLRIAttributeFromNative(a *bgp.PathAttributeMpUnreachNLRI) (*api.MpUnreachNLRIAttribute, error) {
	n, err := MarshalNLRIs(a.Value)
	if err != nil {
		return nil, err
	}
	return &api.MpUnreachNLRIAttribute{
		Family: ToApiFamily(a.AFI, a.SAFI),
		Nlris:  n,
	}, nil
}

func MarshalRT(rt bgp.ExtendedCommunityInterface) (*api.RouteTarget, error) {
	var r api.RouteTarget
	switch v := rt.(type) {
	case *bgp.TwoOctetAsSpecificExtended:
		r.Rt = &api.RouteTarget_TwoOctetAsSpecific{TwoOctetAsSpecific: &api.TwoOctetAsSpecificExtended{
			IsTransitive: true,
			SubType:      uint32(bgp.EC_SUBTYPE_ROUTE_TARGET),
			Asn:          uint32(v.AS),
			LocalAdmin:   v.LocalAdmin,
		}}
	case *bgp.IPv4AddressSpecificExtended:
		r.Rt = &api.RouteTarget_Ipv4AddressSpecific{Ipv4AddressSpecific: &api.IPv4AddressSpecificExtended{
			IsTransitive: true,
			SubType:      uint32(bgp.EC_SUBTYPE_ROUTE_TARGET),
			Address:      v.IPv4.String(),
			LocalAdmin:   uint32(v.LocalAdmin),
		}}
	case *bgp.FourOctetAsSpecificExtended:
		r.Rt = &api.RouteTarget_FourOctetAsSpecific{FourOctetAsSpecific: &api.FourOctetAsSpecificExtended{
			IsTransitive: true,
			SubType:      uint32(bgp.EC_SUBTYPE_ROUTE_TARGET),
			Asn:          v.AS,
			LocalAdmin:   uint32(v.LocalAdmin),
		}}
	default:
		return nil, fmt.Errorf("invalid rt type to marshal: %v", rt)
	}
	return &r, nil
}

func MarshalRTs(values []bgp.ExtendedCommunityInterface) ([]*api.RouteTarget, error) {
	rts := make([]*api.RouteTarget, 0, len(values))
	for _, rt := range values {
		r, err := MarshalRT(rt)
		if err != nil {
			return nil, err
		}
		rts = append(rts, r)
	}
	return rts, nil
}

func UnmarshalRT(rt *api.RouteTarget) (bgp.ExtendedCommunityInterface, error) {
	switch rt.GetRt().(type) {
	case *api.RouteTarget_TwoOctetAsSpecific:
		v := rt.GetTwoOctetAsSpecific()
		return bgp.NewTwoOctetAsSpecificExtended(bgp.ExtendedCommunityAttrSubType(v.SubType), uint16(v.Asn), v.LocalAdmin, v.IsTransitive), nil
	case *api.RouteTarget_Ipv4AddressSpecific:
		v := rt.GetIpv4AddressSpecific()
		rt := bgp.NewIPv4AddressSpecificExtended(bgp.ExtendedCommunityAttrSubType(v.SubType), v.Address, uint16(v.LocalAdmin), v.IsTransitive)
		if rt == nil {
			return nil, fmt.Errorf("invalid address for ipv4 address specific route target: %s", v.Address)
		}
		return rt, nil
	case *api.RouteTarget_FourOctetAsSpecific:
		v := rt.GetFourOctetAsSpecific()
		return bgp.NewFourOctetAsSpecificExtended(bgp.ExtendedCommunityAttrSubType(v.SubType), v.Asn, uint16(v.LocalAdmin), v.IsTransitive), nil
	}
	return nil, fmt.Errorf("invalid route target")
}

func UnmarshalRTs(values []*api.RouteTarget) ([]bgp.ExtendedCommunityInterface, error) {
	rts := make([]bgp.ExtendedCommunityInterface, 0, len(values))
	for _, an := range values {
		rt, err := UnmarshalRT(an)
		if err != nil {
			return nil, err
		}
		rts = append(rts, rt)
	}
	return rts, nil
}

func NewExtendedCommunitiesAttributeFromNative(a *bgp.PathAttributeExtendedCommunities) (*api.ExtendedCommunitiesAttribute, error) {
	communities := make([]*api.ExtendedCommunity, 0, len(a.Value))
	for _, value := range a.Value {
		var community api.ExtendedCommunity
		switch v := value.(type) {
		case *bgp.TwoOctetAsSpecificExtended:
			community.Extcom = &api.ExtendedCommunity_TwoOctetAsSpecific{
				TwoOctetAsSpecific: &api.TwoOctetAsSpecificExtended{
					IsTransitive: v.IsTransitive,
					SubType:      uint32(v.SubType),
					Asn:          uint32(v.AS),
					LocalAdmin:   v.LocalAdmin,
				},
			}
		case *bgp.IPv4AddressSpecificExtended:
			community.Extcom = &api.ExtendedCommunity_Ipv4AddressSpecific{
				Ipv4AddressSpecific: &api.IPv4AddressSpecificExtended{
					IsTransitive: v.IsTransitive,
					SubType:      uint32(v.SubType),
					Address:      v.IPv4.String(),
					LocalAdmin:   uint32(v.LocalAdmin),
				},
			}
		case *bgp.FourOctetAsSpecificExtended:
			community.Extcom = &api.ExtendedCommunity_FourOctetAsSpecific{
				FourOctetAsSpecific: &api.FourOctetAsSpecificExtended{
					IsTransitive: v.IsTransitive,
					SubType:      uint32(v.SubType),
					Asn:          v.AS,
					LocalAdmin:   uint32(v.LocalAdmin),
				},
			}
		case *bgp.ValidationExtended:
			community.Extcom = &api.ExtendedCommunity_Validation{
				Validation: &api.ValidationExtended{
					State: uint32(v.State),
				},
			}
		case *bgp.LinkBandwidthExtended:
			community.Extcom = &api.ExtendedCommunity_LinkBandwidth{
				LinkBandwidth: &api.LinkBandwidthExtended{
					Asn:       uint32(v.AS),
					Bandwidth: v.Bandwidth,
				},
			}
		case *bgp.ColorExtended:
			community.Extcom = &api.ExtendedCommunity_Color{
				Color: &api.ColorExtended{
					Color: v.Color,
				},
			}
		case *bgp.EncapExtended:
			community.Extcom = &api.ExtendedCommunity_Encap{
				Encap: &api.EncapExtended{
					TunnelType: uint32(v.TunnelType),
				},
			}
		case *bgp.DefaultGatewayExtended:
			community.Extcom = &api.ExtendedCommunity_DefaultGateway{DefaultGateway: &api.DefaultGatewayExtended{}}
		case *bgp.OpaqueExtended:
			community.Extcom = &api.ExtendedCommunity_Opaque{
				Opaque: &api.OpaqueExtended{
					IsTransitive: v.IsTransitive,
					Value:        v.Value,
				},
			}
		case *bgp.ESILabelExtended:
			community.Extcom = &api.ExtendedCommunity_EsiLabel{
				EsiLabel: &api.ESILabelExtended{
					IsSingleActive: v.IsSingleActive,
					Label:          v.Label,
				},
			}
		case *bgp.ESImportRouteTarget:
			community.Extcom = &api.ExtendedCommunity_EsImport{
				EsImport: &api.ESImportRouteTarget{
					EsImport: v.ESImport.String(),
				},
			}
		case *bgp.MacMobilityExtended:
			community.Extcom = &api.ExtendedCommunity_MacMobility{
				MacMobility: &api.MacMobilityExtended{
					IsSticky:    v.IsSticky,
					SequenceNum: v.Sequence,
				},
			}
		case *bgp.RouterMacExtended:
			community.Extcom = &api.ExtendedCommunity_RouterMac{
				RouterMac: &api.RouterMacExtended{
					Mac: v.Mac.String(),
				},
			}
		case *bgp.TrafficRateExtended:
			community.Extcom = &api.ExtendedCommunity_TrafficRate{
				TrafficRate: &api.TrafficRateExtended{
					Asn:  uint32(v.AS),
					Rate: v.Rate,
				},
			}
		case *bgp.TrafficActionExtended:
			community.Extcom = &api.ExtendedCommunity_TrafficAction{
				TrafficAction: &api.TrafficActionExtended{
					Terminal: v.Terminal,
					Sample:   v.Sample,
				},
			}
		case *bgp.RedirectTwoOctetAsSpecificExtended:
			community.Extcom = &api.ExtendedCommunity_RedirectTwoOctetAsSpecific{
				RedirectTwoOctetAsSpecific: &api.RedirectTwoOctetAsSpecificExtended{
					Asn:        uint32(v.AS),
					LocalAdmin: v.LocalAdmin,
				},
			}
		case *bgp.RedirectIPv4AddressSpecificExtended:
			community.Extcom = &api.ExtendedCommunity_RedirectIpv4AddressSpecific{
				RedirectIpv4AddressSpecific: &api.RedirectIPv4AddressSpecificExtended{
					Address:    v.IPv4.String(),
					LocalAdmin: uint32(v.LocalAdmin),
				},
			}
		case *bgp.RedirectFourOctetAsSpecificExtended:
			community.Extcom = &api.ExtendedCommunity_RedirectFourOctetAsSpecific{
				RedirectFourOctetAsSpecific: &api.RedirectFourOctetAsSpecificExtended{
					Asn:        v.AS,
					LocalAdmin: uint32(v.LocalAdmin),
				},
			}
		case *bgp.TrafficRemarkExtended:
			community.Extcom = &api.ExtendedCommunity_TrafficRemark{
				TrafficRemark: &api.TrafficRemarkExtended{
					Dscp: uint32(v.DSCP),
				},
			}
		case *bgp.MUPExtended:
			community.Extcom = &api.ExtendedCommunity_Mup{
				Mup: &api.MUPExtended{
					SubType:    uint32(v.SubType),
					SegmentId2: uint32(v.SegmentID2),
					SegmentId4: v.SegmentID4,
				},
			}
		case *bgp.VPLSExtended:
			community.Extcom = &api.ExtendedCommunity_Vpls{
				Vpls: &api.VPLSExtended{
					ControlFlags: uint32(v.ControlFlags),
					Mtu:          uint32(v.MTU),
				},
			}
		case *bgp.ETreeExtended:
			community.Extcom = &api.ExtendedCommunity_Etree{
				Etree: &api.ETreeExtended{
					IsLeaf: v.IsLeaf,
					Label:  v.Label,
				},
			}
		case *bgp.MulticastFlagsExtended:
			community.Extcom = &api.ExtendedCommunity_MulticastFlags{
				MulticastFlags: &api.MulticastFlagsExtended{
					IsIgmpProxy: v.IsIGMPProxy,
					IsMldProxy:  v.IsMLDProxy,
				},
			}
		case *bgp.UnknownExtended:
			community.Extcom = &api.ExtendedCommunity_Unknown{
				Unknown: &api.UnknownExtended{
					Type:  uint32(v.Type),
					Value: v.Value,
				},
			}
		default:
			return nil, fmt.Errorf("unsupported extended community: %v", value)
		}
		communities = append(communities, &community)
	}
	return &api.ExtendedCommunitiesAttribute{
		Communities: communities,
	}, nil
}

func unmarshalExComm(a *api.ExtendedCommunitiesAttribute) (*bgp.PathAttributeExtendedCommunities, error) {
	communities := make([]bgp.ExtendedCommunityInterface, 0, len(a.Communities))
	for _, c := range a.Communities {
		var community bgp.ExtendedCommunityInterface
		switch comm := c.GetExtcom().(type) {
		case *api.ExtendedCommunity_TwoOctetAsSpecific:
			v := comm.TwoOctetAsSpecific
			community = bgp.NewTwoOctetAsSpecificExtended(bgp.ExtendedCommunityAttrSubType(v.SubType), uint16(v.Asn), v.LocalAdmin, v.IsTransitive)
		case *api.ExtendedCommunity_Ipv4AddressSpecific:
			v := comm.Ipv4AddressSpecific
			community = bgp.NewIPv4AddressSpecificExtended(bgp.ExtendedCommunityAttrSubType(v.SubType), v.Address, uint16(v.LocalAdmin), v.IsTransitive)
		case *api.ExtendedCommunity_FourOctetAsSpecific:
			v := comm.FourOctetAsSpecific
			community = bgp.NewFourOctetAsSpecificExtended(bgp.ExtendedCommunityAttrSubType(v.SubType), v.Asn, uint16(v.LocalAdmin), v.IsTransitive)
		case *api.ExtendedCommunity_Validation:
			v := comm.Validation
			community = bgp.NewValidationExtended(bgp.ValidationState(v.State))
		case *api.ExtendedCommunity_LinkBandwidth:
			v := comm.LinkBandwidth
			community = bgp.NewLinkBandwidthExtended(uint16(v.Asn), v.Bandwidth)
		case *api.ExtendedCommunity_Color:
			v := comm.Color
			community = bgp.NewColorExtended(v.Color)
		case *api.ExtendedCommunity_Encap:
			v := comm.Encap
			community = bgp.NewEncapExtended(bgp.TunnelType(v.TunnelType))
		case *api.ExtendedCommunity_DefaultGateway:
			community = bgp.NewDefaultGatewayExtended()
		case *api.ExtendedCommunity_Opaque:
			v := comm.Opaque
			community = bgp.NewOpaqueExtended(v.IsTransitive, v.Value)
		case *api.ExtendedCommunity_EsiLabel:
			v := comm.EsiLabel
			community = bgp.NewESILabelExtended(v.Label, v.IsSingleActive)
		case *api.ExtendedCommunity_EsImport:
			v := comm.EsImport
			community = bgp.NewESImportRouteTarget(v.EsImport)
		case *api.ExtendedCommunity_MacMobility:
			v := comm.MacMobility
			community = bgp.NewMacMobilityExtended(v.SequenceNum, v.IsSticky)
		case *api.ExtendedCommunity_RouterMac:
			v := comm.RouterMac
			community = bgp.NewRoutersMacExtended(v.Mac)
		case *api.ExtendedCommunity_TrafficRate:
			v := comm.TrafficRate
			community = bgp.NewTrafficRateExtended(uint16(v.Asn), v.Rate)
		case *api.ExtendedCommunity_TrafficAction:
			v := comm.TrafficAction
			community = bgp.NewTrafficActionExtended(v.Terminal, v.Sample)
		case *api.ExtendedCommunity_RedirectTwoOctetAsSpecific:
			v := comm.RedirectTwoOctetAsSpecific
			community = bgp.NewRedirectTwoOctetAsSpecificExtended(uint16(v.Asn), v.LocalAdmin)
		case *api.ExtendedCommunity_RedirectIpv4AddressSpecific:
			v := comm.RedirectIpv4AddressSpecific
			community = bgp.NewRedirectIPv4AddressSpecificExtended(v.Address, uint16(v.LocalAdmin))
		case *api.ExtendedCommunity_RedirectFourOctetAsSpecific:
			v := comm.RedirectFourOctetAsSpecific
			community = bgp.NewRedirectFourOctetAsSpecificExtended(v.Asn, uint16(v.LocalAdmin))
		case *api.ExtendedCommunity_TrafficRemark:
			v := comm.TrafficRemark
			community = bgp.NewTrafficRemarkExtended(uint8(v.Dscp))
		case *api.ExtendedCommunity_Mup:
			v := comm.Mup
			community = bgp.NewMUPExtended(uint16(v.SegmentId2), v.SegmentId4)
		case *api.ExtendedCommunity_Vpls:
			v := comm.Vpls
			community = bgp.NewVPLSExtended(uint8(v.ControlFlags), uint16(v.Mtu))
		case *api.ExtendedCommunity_Etree:
			v := comm.Etree
			community = bgp.NewETreeExtended(v.Label, v.IsLeaf)
		case *api.ExtendedCommunity_MulticastFlags:
			v := comm.MulticastFlags
			community = bgp.NewMulticastFlagsExtended(v.IsIgmpProxy, v.IsMldProxy)
		case *api.ExtendedCommunity_Unknown:
			v := comm.Unknown
			community = bgp.NewUnknownExtended(bgp.ExtendedCommunityAttrType(v.Type), v.Value)
		}
		if community == nil {
			return nil, fmt.Errorf("invalid extended community: %T", c.GetExtcom())
		}
		communities = append(communities, community)
	}
	return bgp.NewPathAttributeExtendedCommunities(communities), nil
}

func NewAs4PathAttributeFromNative(a *bgp.PathAttributeAs4Path) (*api.As4PathAttribute, error) {
	segments := make([]*api.AsSegment, 0, len(a.Value))
	for _, param := range a.Value {
		segments = append(segments, &api.AsSegment{
			Type:    api.AsSegment_Type(param.Type),
			Numbers: param.AS,
		})
	}
	return &api.As4PathAttribute{
		Segments: segments,
	}, nil
}

func NewAs4AggregatorAttributeFromNative(a *bgp.PathAttributeAs4Aggregator) (*api.As4AggregatorAttribute, error) {
	return &api.As4AggregatorAttribute{
		Asn:     a.Value.AS,
		Address: a.Value.Address.String(),
	}, nil
}

func NewPmsiTunnelAttributeFromNative(a *bgp.PathAttributePmsiTunnel) (*api.PmsiTunnelAttribute, error) {
	var flags uint32
	if a.IsLeafInfoRequired {
		flags |= 0x01
	}
	id, _ := a.TunnelID.Serialize()
	return &api.PmsiTunnelAttribute{
		Flags: flags,
		Type:  uint32(a.TunnelType),
		Label: a.Label,
		Id:    id,
	}, nil
}

func NewTunnelEncapAttributeFromNative(a *bgp.PathAttributeTunnelEncap) (*api.TunnelEncapAttribute, error) {
	tlvs := make([]*api.TunnelEncapTLV, 0, len(a.Value))
	for _, v := range a.Value {
		subTlvs := make([]*api.TunnelEncapTLV_TLV, 0, len(v.Value))
		for _, s := range v.Value {
			var subTlv api.TunnelEncapTLV_TLV
			switch sv := s.(type) {
			case *bgp.TunnelEncapSubTLVEncapsulation:
				subTlv.Tlv = &api.TunnelEncapTLV_TLV_Encapsulation{
					Encapsulation: &api.TunnelEncapSubTLVEncapsulation{
						Key:    sv.Key,
						Cookie: sv.Cookie,
					},
				}
			case *bgp.TunnelEncapSubTLVProtocol:
				subTlv.Tlv = &api.TunnelEncapTLV_TLV_Protocol{
					Protocol: &api.TunnelEncapSubTLVProtocol{
						Protocol: uint32(sv.Protocol),
					},
				}
			case *bgp.TunnelEncapSubTLVColor:
				subTlv.Tlv = &api.TunnelEncapTLV_TLV_Color{
					Color: &api.TunnelEncapSubTLVColor{
						Color: sv.Color,
					},
				}
			case *bgp.TunnelEncapSubTLVEgressEndpoint:
				subTlv.Tlv = &api.TunnelEncapTLV_TLV_EgressEndpoint{
					EgressEndpoint: &api.TunnelEncapSubTLVEgressEndpoint{
						Address: sv.Address.String(),
					},
				}
			case *bgp.TunnelEncapSubTLVUDPDestPort:
				subTlv.Tlv = &api.TunnelEncapTLV_TLV_UdpDestPort{
					UdpDestPort: &api.TunnelEncapSubTLVUDPDestPort{
						Port: uint32(sv.UDPDestPort),
					},
				}
			case *bgp.TunnelEncapSubTLVUnknown:
				subTlv.Tlv = &api.TunnelEncapTLV_TLV_Unknown{
					Unknown: &api.TunnelEncapSubTLVUnknown{
						Type:  uint32(sv.Type),
						Value: sv.Value,
					},
				}
			case *bgp.TunnelEncapSubTLVSRBSID:
				t, err := MarshalSRBSID(sv)
				if err != nil {
					return nil, err
				}
				subTlv.Tlv = &api.TunnelEncapTLV_TLV_SrBindingSid{
					SrBindingSid: &api.TunnelEncapSubTLVSRBindingSID{
						Bsid: &api.TunnelEncapSubTLVSRBindingSID_SrBindingSid{
							SrBindingSid: t,
						},
					},
				}
				// TODO (sbezverk) Add processing of SRv6 Binding SID when it gets assigned ID
			case *bgp.TunnelEncapSubTLVSRCandidatePathName:
				subTlv.Tlv = &api.TunnelEncapTLV_TLV_SrCandidatePathName{
					SrCandidatePathName: &api.TunnelEncapSubTLVSRCandidatePathName{
						CandidatePathName: sv.CandidatePathName,
					},
				}
				// TODO (sbezverk) Add processing of SR Policy name when it gets assigned ID
			case *bgp.TunnelEncapSubTLVSRENLP:
				subTlv.Tlv = &api.TunnelEncapTLV_TLV_SrEnlp{
					SrEnlp: &api.TunnelEncapSubTLVSRENLP{
						Flags: uint32(sv.Flags),
						Enlp:  api.ENLPType(sv.ENLP),
					},
				}
			case *bgp.TunnelEncapSubTLVSRPreference:
				subTlv.Tlv = &api.TunnelEncapTLV_TLV_SrPreference{
					SrPreference: &api.TunnelEncapSubTLVSRPreference{
						Flags:      uint32(sv.Flags),
						Preference: sv.Preference,
					},
				}
			case *bgp.TunnelEncapSubTLVSRPriority:
				subTlv.Tlv = &api.TunnelEncapTLV_TLV_SrPriority{
					SrPriority: &api.TunnelEncapSubTLVSRPriority{
						Priority: uint32(sv.Priority),
					},
				}
			case *bgp.TunnelEncapSubTLVSRSegmentList:
				s, err := MarshalSRSegments(sv.Segments)
				if err != nil {
					return nil, err
				}
				subTlv.Tlv = &api.TunnelEncapTLV_TLV_SrSegmentList{
					SrSegmentList: &api.TunnelEncapSubTLVSRSegmentList{
						Weight: &api.SRWeight{
							Flags:  uint32(sv.Weight.Flags),
							Weight: sv.Weight.Weight,
						},
						Segments: s,
					},
				}
			}
			subTlvs = append(subTlvs, &subTlv)
		}
		tlvs = append(tlvs, &api.TunnelEncapTLV{
			Type: uint32(v.Type),
			Tlvs: subTlvs,
		})
	}
	return &api.TunnelEncapAttribute{
		Tlvs: tlvs,
	}, nil
}

func NewIP6ExtendedCommunitiesAttributeFromNative(a *bgp.PathAttributeIP6ExtendedCommunities) (*api.IP6ExtendedCommunitiesAttribute, error) {
	communities := make([]*api.IP6ExtendedCommunitiesAttribute_Community, 0, len(a.Value))
	for _, value := range a.Value {
		var community api.IP6ExtendedCommunitiesAttribute_Community
		switch v := value.(type) {
		case *bgp.IPv6AddressSpecificExtended:
			community.Extcom = &api.IP6ExtendedCommunitiesAttribute_Community_Ipv6AddressSpecific{
				Ipv6AddressSpecific: &api.IPv6AddressSpecificExtended{
					IsTransitive: v.IsTransitive,
					SubType:      uint32(v.SubType),
					Address:      v.IPv6.String(),
					LocalAdmin:   uint32(v.LocalAdmin),
				},
			}
		case *bgp.RedirectIPv6AddressSpecificExtended:
			community.Extcom = &api.IP6ExtendedCommunitiesAttribute_Community_RedirectIpv6AddressSpecific{
				RedirectIpv6AddressSpecific: &api.RedirectIPv6AddressSpecificExtended{
					Address:    v.IPv6.String(),
					LocalAdmin: uint32(v.LocalAdmin),
				},
			}
		default:
			return nil, fmt.Errorf("invalid ipv6 extended community: %v", value)
		}
		communities = append(communities, &community)
	}
	return &api.IP6ExtendedCommunitiesAttribute{
		Communities: communities,
	}, nil
}

func NewAigpAttributeFromNative(a *bgp.PathAttributeAigp) (*api.AigpAttribute, error) {
	tlvs := make([]*api.AigpAttribute_TLV, 0, len(a.Values))
	for _, value := range a.Values {
		var tlv api.AigpAttribute_TLV
		switch v := value.(type) {
		case *bgp.AigpTLVIgpMetric:
			tlv.Tlv = &api.AigpAttribute_TLV_IgpMetric{
				IgpMetric: &api.AigpTLVIGPMetric{
					Metric: v.Metric,
				},
			}
		case *bgp.AigpTLVDefault:
			tlv.Tlv = &api.AigpAttribute_TLV_Unknown{
				Unknown: &api.AigpTLVUnknown{
					Type:  uint32(v.Type()),
					Value: v.Value,
				},
			}
		}
		tlvs = append(tlvs, &tlv)
	}
	return &api.AigpAttribute{
		Tlvs: tlvs,
	}, nil
}

func NewLargeCommunitiesAttributeFromNative(a *bgp.PathAttributeLargeCommunities) (*api.LargeCommunitiesAttribute, error) {
	communities := make([]*api.LargeCommunity, 0, len(a.Values))
	for _, v := range a.Values {
		communities = append(communities, &api.LargeCommunity{
			GlobalAdmin: v.ASN,
			LocalData1:  v.LocalData1,
			LocalData2:  v.LocalData2,
		})
	}
	return &api.LargeCommunitiesAttribute{
		Communities: communities,
	}, nil
}

func stringOrDefault(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func bytesOrDefault(b *[]byte) []byte {
	if b == nil {
		return []byte{}
	}
	return *b
}

func ipOrDefault(ip *net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func uint32OrDefault(i *uint32) uint32 {
	if i == nil {
		return 0
	}
	return *i
}

func float32OrDefault(f *float32) float32 {
	if f == nil {
		return 0.0
	}
	return *f
}

func NewLsAttributeFromNative(a *bgp.PathAttributeLs) (*api.LsAttribute, error) {
	attr := a.Extract()

	bgpPeerSegment := &api.LsAttributeBgpPeerSegment{}
	if attr.BgpPeerSegment.BgpPeerNodeSid != nil {
		bgpPeerSegment.BgpPeerNodeSid, _ = MarshalLsBgpPeerSegmentSid(attr.BgpPeerSegment.BgpPeerNodeSid)
	}
	if attr.BgpPeerSegment.BgpPeerAdjacencySid != nil {
		bgpPeerSegment.BgpPeerAdjacencySid, _ = MarshalLsBgpPeerSegmentSid(attr.BgpPeerSegment.BgpPeerAdjacencySid)
	}
	if attr.BgpPeerSegment.BgpPeerSetSid != nil {
		bgpPeerSegment.BgpPeerSetSid, _ = MarshalLsBgpPeerSegmentSid(attr.BgpPeerSegment.BgpPeerSetSid)
	}

	apiAttr := &api.LsAttribute{
		Node: &api.LsAttributeNode{
			Name:            stringOrDefault(attr.Node.Name),
			Opaque:          bytesOrDefault(attr.Node.Opaque),
			IsisArea:        bytesOrDefault(attr.Node.IsisArea),
			LocalRouterId:   ipOrDefault(attr.Node.LocalRouterID),
			LocalRouterIdV6: ipOrDefault(attr.Node.LocalRouterIDv6),

			SrAlgorithms: bytesOrDefault(attr.Node.SrAlgorithms),
		},
		Link: &api.LsAttributeLink{
			Name:             stringOrDefault(attr.Link.Name),
			Opaque:           bytesOrDefault(attr.Link.Opaque),
			LocalRouterId:    ipOrDefault(attr.Link.LocalRouterID),
			LocalRouterIdV6:  ipOrDefault(attr.Link.LocalRouterIDv6),
			RemoteRouterId:   ipOrDefault(attr.Link.RemoteRouterID),
			RemoteRouterIdV6: ipOrDefault(attr.Link.RemoteRouterIDv6),
			AdminGroup:       uint32OrDefault(attr.Link.AdminGroup),
			DefaultTeMetric:  uint32OrDefault(attr.Link.DefaultTEMetric),
			IgpMetric:        uint32OrDefault(attr.Link.IGPMetric),

			Bandwidth:           float32OrDefault(attr.Link.Bandwidth),
			ReservableBandwidth: float32OrDefault(attr.Link.ReservableBandwidth),
			SrAdjacencySid:      uint32OrDefault(attr.Link.SrAdjacencySID),
		},
		Prefix: &api.LsAttributePrefix{
			Opaque: bytesOrDefault(attr.Prefix.Opaque),

			SrPrefixSid: uint32OrDefault(attr.Prefix.SrPrefixSID),
		},
		BgpPeerSegment: bgpPeerSegment,
	}

	if attr.Node.Flags != nil {
		apiAttr.Node.Flags = &api.LsNodeFlags{
			Overload: attr.Node.Flags.Overload,
			Attached: attr.Node.Flags.Attached,
			External: attr.Node.Flags.External,
			Abr:      attr.Node.Flags.ABR,
			Router:   attr.Node.Flags.Router,
			V6:       attr.Node.Flags.V6,
		}
	}

	if attr.Node.SrCapabilties != nil {
		apiAttr.Node.SrCapabilities = &api.LsSrCapabilities{
			Ipv4Supported: attr.Node.SrCapabilties.IPv4Supported,
			Ipv6Supported: attr.Node.SrCapabilties.IPv6Supported,
		}

		for _, r := range attr.Node.SrCapabilties.Ranges {
			apiAttr.Node.SrCapabilities.Ranges = append(apiAttr.Node.SrCapabilities.Ranges, &api.LsSrRange{
				Begin: r.Begin,
				End:   r.End,
			})
		}
	}

	if attr.Node.SrLocalBlock != nil {
		apiAttr.Node.SrLocalBlock = &api.LsSrLocalBlock{}
		for _, r := range attr.Node.SrLocalBlock.Ranges {
			apiAttr.Node.SrLocalBlock.Ranges = append(apiAttr.Node.SrLocalBlock.Ranges, &api.LsSrRange{
				Begin: r.Begin,
				End:   r.End,
			})
		}
	}

	if attr.Link.UnreservedBandwidth != nil {
		for _, f := range attr.Link.UnreservedBandwidth {
			apiAttr.Link.UnreservedBandwidth = append(apiAttr.Link.UnreservedBandwidth, f)
		}
	}

	if attr.Link.Srlgs != nil {
		apiAttr.Link.Srlgs = append(apiAttr.Link.Srlgs, *attr.Link.Srlgs...)
	}

	if attr.Prefix.IGPFlags != nil {
		apiAttr.Prefix.IgpFlags = &api.LsIGPFlags{
			Down:          attr.Prefix.IGPFlags.Down,
			NoUnicast:     attr.Prefix.IGPFlags.NoUnicast,
			LocalAddress:  attr.Prefix.IGPFlags.LocalAddress,
			PropagateNssa: attr.Prefix.IGPFlags.PropagateNSSA,
		}
	}

	return apiAttr, nil
}

func NewUnknownAttributeFromNative(a *bgp.PathAttributeUnknown) (*api.UnknownAttribute, error) {
	return &api.UnknownAttribute{
		Flags: uint32(a.Flags),
		Type:  uint32(a.Type),
		Value: a.Value,
	}, nil
}

func MarshalPathAttributes(attrList []bgp.PathAttributeInterface) ([]*api.Attribute, error) {
	apiList := make([]*api.Attribute, 0, len(attrList))
	for _, attr := range attrList {
		var attribute api.Attribute
		switch a := attr.(type) {
		case *bgp.PathAttributeOrigin:
			v, err := NewOriginAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			attribute.Attr = &api.Attribute_Origin{Origin: v}
		case *bgp.PathAttributeAsPath:
			v, err := NewAsPathAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			attribute.Attr = &api.Attribute_AsPath{AsPath: v}
		case *bgp.PathAttributeNextHop:
			v, err := NewNextHopAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			attribute.Attr = &api.Attribute_NextHop{NextHop: v}
		case *bgp.PathAttributeMultiExitDisc:
			v, err := NewMultiExitDiscAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			attribute.Attr = &api.Attribute_MultiExitDisc{MultiExitDisc: v}
		case *bgp.PathAttributeLocalPref:
			v, err := NewLocalPrefAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			attribute.Attr = &api.Attribute_LocalPref{LocalPref: v}
		case *bgp.PathAttributeAtomicAggregate:
			v, err := NewAtomicAggregateAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			attribute.Attr = &api.Attribute_AtomicAggregate{AtomicAggregate: v}
		case *bgp.PathAttributeAggregator:
			v, err := NewAggregatorAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			attribute.Attr = &api.Attribute_Aggregator{Aggregator: v}
		case *bgp.PathAttributeCommunities:
			v, err := NewCommunitiesAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			attribute.Attr = &api.Attribute_Communities{Communities: v}
		case *bgp.PathAttributeOriginatorId:
			v, err := NewOriginatorIdAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			attribute.Attr = &api.Attribute_OriginatorId{OriginatorId: v}
		case *bgp.PathAttributeClusterList:
			v, err := NewClusterListAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			attribute.Attr = &api.Attribute_ClusterList{ClusterList: v}
		case *bgp.PathAttributeMpReachNLRI:
			v, err := NewMpReachNLRIAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			attribute.Attr = &api.Attribute_MpReach{MpReach: v}
		case *bgp.PathAttributeMpUnreachNLRI:
			v, err := NewMpUnreachNLRIAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			attribute.Attr = &api.Attribute_MpUnreach{MpUnreach: v}
		case *bgp.PathAttributeExtendedCommunities:
			v, err := NewExtendedCommunitiesAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			attribute.Attr = &api.Attribute_ExtendedCommunities{ExtendedCommunities: v}
		case *bgp.PathAttributeAs4Path:
			v, err := NewAs4PathAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			attribute.Attr = &api.Attribute_As4Path{As4Path: v}
		case *bgp.PathAttributeAs4Aggregator:
			v, err := NewAs4AggregatorAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			attribute.Attr = &api.Attribute_As4Aggregator{As4Aggregator: v}
		case *bgp.PathAttributePmsiTunnel:
			v, err := NewPmsiTunnelAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			attribute.Attr = &api.Attribute_PmsiTunnel{PmsiTunnel: v}
		case *bgp.PathAttributeTunnelEncap:
			v, err := NewTunnelEncapAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			attribute.Attr = &api.Attribute_TunnelEncap{TunnelEncap: v}
		case *bgp.PathAttributeIP6ExtendedCommunities:
			v, err := NewIP6ExtendedCommunitiesAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			attribute.Attr = &api.Attribute_Ip6ExtendedCommunities{Ip6ExtendedCommunities: v}
		case *bgp.PathAttributeAigp:
			v, err := NewAigpAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			attribute.Attr = &api.Attribute_Aigp{Aigp: v}
		case *bgp.PathAttributeLargeCommunities:
			v, err := NewLargeCommunitiesAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			attribute.Attr = &api.Attribute_LargeCommunities{LargeCommunities: v}
		case *bgp.PathAttributeLs:
			v, err := NewLsAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			attribute.Attr = &api.Attribute_Ls{Ls: v}
		case *bgp.PathAttributePrefixSID:
			v, err := NewPrefixSIDAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			attribute.Attr = &api.Attribute_PrefixSid{PrefixSid: v}
		case *bgp.PathAttributeUnknown:
			v, err := NewUnknownAttributeFromNative(a)
			if err != nil {
				return nil, err
			}
			attribute.Attr = &api.Attribute_Unknown{Unknown: v}
		}
		apiList = append(apiList, &attribute)
	}
	return apiList, nil
}

func UnmarshalPathAttributes(values []*api.Attribute) ([]bgp.PathAttributeInterface, error) {
	attrList := make([]bgp.PathAttributeInterface, 0, len(values))
	typeMap := make(map[bgp.BGPAttrType]struct{})
	for _, an := range values {
		attr, err := UnmarshalAttribute(an)
		if err != nil {
			return nil, err
		}
		if _, ok := typeMap[attr.GetType()]; ok {
			return nil, fmt.Errorf("duplicated path attribute type: %d", attr.GetType())
		}
		typeMap[attr.GetType()] = struct{}{}
		attrList = append(attrList, attr)
	}
	return attrList, nil
}

// MarshalSRBSID marshals SR Policy Binding SID Sub TLV structure
func MarshalSRBSID(bsid *bgp.TunnelEncapSubTLVSRBSID) (*api.SRBindingSID, error) {
	s := &api.SRBindingSID{
		Sid: make([]byte, len(bsid.BSID.Value)),
	}
	copy(s.Sid, bsid.BSID.Value)
	s.SFlag = bsid.Flags&0x80 == 0x80
	s.IFlag = bsid.Flags&0x40 == 0x40
	return s, nil
}

// UnmarshalSRBSID unmarshals SR Policy Binding SID Sub TLV and returns native TunnelEncapSubTLVInterface interface
func UnmarshalSRBSID(bsid *api.TunnelEncapSubTLVSRBindingSID) (bgp.TunnelEncapSubTLVInterface, error) {
	switch v := bsid.GetBsid().(type) {
	case *api.TunnelEncapSubTLVSRBindingSID_SrBindingSid:
		b, err := bgp.NewBSID(v.SrBindingSid.Sid)
		if err != nil {
			return nil, err
		}
		flags := uint8(0x0)
		if v.SrBindingSid.SFlag {
			flags += 0x80
		}
		if v.SrBindingSid.IFlag {
			flags += 0x40
		}
		return &bgp.TunnelEncapSubTLVSRBSID{
			TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{
				Type:   bgp.ENCAP_SUBTLV_TYPE_SRBINDING_SID,
				Length: uint16(2 + b.Len()),
			},
			BSID:  b,
			Flags: flags,
		}, nil
	case *api.TunnelEncapSubTLVSRBindingSID_Srv6BindingSid:
		b, err := bgp.NewBSID(v.Srv6BindingSid.Sid)
		if err != nil {
			return nil, err
		}
		result := &bgp.TunnelEncapSubTLVSRv6BSID{
			TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{
				Type:   bgp.ENCAP_SUBTLV_TYPE_SRBINDING_SID,
				Length: uint16(2 + b.Len()),
			},
			Flags: 0,
			BSID:  b,
		}

		if v.Srv6BindingSid.EndpointBehaviorStructure != nil {
			result.EPBAS = &bgp.SRv6EndpointBehaviorStructure{
				Behavior: bgp.SRBehavior(v.Srv6BindingSid.EndpointBehaviorStructure.Behavior),
				BlockLen: uint8(v.Srv6BindingSid.EndpointBehaviorStructure.BlockLen),
				NodeLen:  uint8(v.Srv6BindingSid.EndpointBehaviorStructure.NodeLen),
				FuncLen:  uint8(v.Srv6BindingSid.EndpointBehaviorStructure.FuncLen),
				ArgLen:   uint8(v.Srv6BindingSid.EndpointBehaviorStructure.ArgLen),
			}
		}

		return result, nil
	default:
		return nil, fmt.Errorf("unknown binding sid type %T", bsid.GetBsid())
	}
}

// MarshalSRSegments marshals a slice of SR Policy Segment List
func MarshalSRSegments(segs []bgp.TunnelEncapSubTLVInterface) ([]*api.TunnelEncapSubTLVSRSegmentList_Segment, error) {
	segments := make([]*api.TunnelEncapSubTLVSRSegmentList_Segment, 0, len(segs))
	for _, seg := range segs {
		var r api.TunnelEncapSubTLVSRSegmentList_Segment
		switch s := seg.(type) {
		case *bgp.SegmentTypeA:
			r.Segment = &api.TunnelEncapSubTLVSRSegmentList_Segment_A{
				A: &api.SegmentTypeA{
					Label: s.Label,
					Flags: &api.SegmentFlags{
						VFlag: s.Flags&0x80 == 0x80,
						AFlag: s.Flags&0x40 == 0x40,
						SFlag: s.Flags&0x20 == 0x20,
						BFlag: s.Flags&0x10 == 0x10,
					},
				},
			}
		case *bgp.SegmentTypeB:
			flags := &api.SegmentFlags{
				VFlag: s.Flags&0x80 == 0x80,
				AFlag: s.Flags&0x40 == 0x40,
				SFlag: s.Flags&0x20 == 0x20,
				BFlag: s.Flags&0x10 == 0x10,
			}
			segment := &api.SegmentTypeB{
				Flags: flags,
				Sid:   s.SID,
			}
			if s.SRv6EBS != nil {
				segment.EndpointBehaviorStructure = &api.SRv6EndPointBehavior{
					Behavior: api.SRV6Behavior(s.SRv6EBS.Behavior),
					BlockLen: uint32(s.SRv6EBS.BlockLen),
					NodeLen:  uint32(s.SRv6EBS.NodeLen),
					FuncLen:  uint32(s.SRv6EBS.FuncLen),
					ArgLen:   uint32(s.SRv6EBS.ArgLen),
				}
			}
			r.Segment = &api.TunnelEncapSubTLVSRSegmentList_Segment_B{B: segment}
		default:
			// Unrecognize Segment type, skip it
			continue
		}
		segments = append(segments, &r)
	}
	return segments, nil
}

// UnmarshalSRSegments unmarshals SR Policy Segments slice of structs
func UnmarshalSRSegments(s []*api.TunnelEncapSubTLVSRSegmentList_Segment) ([]bgp.TunnelEncapSubTLVInterface, error) {
	if len(s) == 0 {
		return nil, nil
	}
	segments := make([]bgp.TunnelEncapSubTLVInterface, len(s))
	for i := range s {
		switch v := s[i].GetSegment().(type) {
		case *api.TunnelEncapSubTLVSRSegmentList_Segment_A:
			seg := &bgp.SegmentTypeA{
				TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{
					Type:   bgp.EncapSubTLVType(bgp.TypeA),
					Length: 6,
				},
				Label: v.A.Label,
			}
			if v.A.Flags.VFlag {
				seg.Flags += 0x80
			}
			if v.A.Flags.AFlag {
				seg.Flags += 0x40
			}
			if v.A.Flags.SFlag {
				seg.Flags += 0x20
			}
			if v.A.Flags.BFlag {
				seg.Flags += 0x10
			}
			segments[i] = seg
		case *api.TunnelEncapSubTLVSRSegmentList_Segment_B:
			seg := &bgp.SegmentTypeB{
				TunnelEncapSubTLV: bgp.TunnelEncapSubTLV{
					Type:   bgp.EncapSubTLVType(bgp.TypeB),
					Length: 18,
				},
				SID: v.B.GetSid(),
			}
			if v.B.Flags.VFlag {
				seg.Flags += 0x80
			}
			if v.B.Flags.AFlag {
				seg.Flags += 0x40
			}
			if v.B.Flags.SFlag {
				seg.Flags += 0x20
			}
			if v.B.Flags.BFlag {
				seg.Flags += 0x10
			}
			if v.B.EndpointBehaviorStructure != nil {
				ebs := v.B.GetEndpointBehaviorStructure()
				seg.SRv6EBS = &bgp.SRv6EndpointBehaviorStructure{
					Behavior: bgp.SRBehavior(ebs.Behavior),
					BlockLen: uint8(ebs.BlockLen),
					NodeLen:  uint8(ebs.NodeLen),
					FuncLen:  uint8(ebs.FuncLen),
					ArgLen:   uint8(ebs.ArgLen),
				}
			}
			segments[i] = seg
		}
	}
	return segments, nil
}

func UnmarshalPrefixSID(psid *api.PrefixSID) (*bgp.PathAttributePrefixSID, error) {
	t := bgp.BGP_ATTR_TYPE_PREFIX_SID
	s := &bgp.PathAttributePrefixSID{
		PathAttribute: bgp.PathAttribute{
			Flags: bgp.PathAttrFlags[t],
			Type:  t,
		},
		TLVs: make([]bgp.PrefixSIDTLVInterface, 0),
	}
	for _, raw := range psid.Tlvs {
		switch tlv := raw.GetTlv().(type) {
		case *api.PrefixSID_TLV_L3Service:
			v := tlv.L3Service
			tlvLength, tlvs, err := UnmarshalSubTLVs(v.SubTlvs)
			if err != nil {
				return nil, err
			}
			o := &bgp.SRv6L3ServiceAttribute{
				TLV: bgp.TLV{
					Type:   bgp.TLVType(5),
					Length: tlvLength,
				},
			}
			s.Length += tlvLength
			// Storing Sub TLVs in a Service TLV
			o.SubTLVs = append(o.SubTLVs, tlvs...)
			// Adding Service TLV to Path Attribute TLV slice.
			s.TLVs = append(s.TLVs, o)
		default:
			return nil, fmt.Errorf("unknown or not implemented Prefix SID type: %+v", tlv)
		}
	}
	// Final Path Attribute Length is 3 bytes of the Path Attribute header longer
	s.Length += 3
	return s, nil
}

func UnmarshalSubTLVs(stlvs map[uint32]*api.SRv6SubTLVs) (uint16, []bgp.PrefixSIDTLVInterface, error) {
	p := make([]bgp.PrefixSIDTLVInterface, 0, len(stlvs))
	l := uint16(0)
	// v.SubTlvs is a map by sub tlv type and the value is a slice of sub tlvs of the specific type
	for t, tlv := range stlvs {
		switch t {
		case 1:
			// Sub TLV Type 1 is SRv6 Informational Sub TLV
			for _, raw := range tlv.Tlvs {
				// Instantiating Information Sub TLV
				info := &bgp.SRv6InformationSubTLV{
					SubTLV: bgp.SubTLV{
						Type: bgp.SubTLVType(1),
					},
					SubSubTLVs: make([]bgp.PrefixSIDTLVInterface, 0),
				}
				infoProto := raw.GetInformation()
				info.SID = make([]byte, len(infoProto.Sid))
				copy(info.SID, infoProto.Sid)
				// TODO Once RFC is published add processing of flags
				info.Flags = 0
				info.EndpointBehavior = uint16(infoProto.EndpointBehavior)
				var sstlvslength uint16
				var sstlvs []bgp.PrefixSIDTLVInterface
				if len(infoProto.SubSubTlvs) != 0 {
					// Processing Sub Sub TLVs
					var err error
					sstlvslength, sstlvs, err = UnmarshalSubSubTLVs(infoProto.SubSubTlvs)
					if err != nil {
						return 0, nil, err
					}
					info.SubSubTLVs = append(info.SubSubTLVs, sstlvs...)
				}
				// SRv6 Information Sub TLV length consists 1 byte Resrved2, 16 bytes SID, 1 byte flags, 2 bytes Endpoint Behavior
				// 1 byte Reserved3 and length of Sub Sub TLVs
				info.Length = 1 + 16 + 1 + 2 + 1 + sstlvslength
				// For total Prefix SID TLV length, adding 3 bytes of the TLV header + 1 byte of Reserved1
				l += info.Length + 4
				p = append(p, info)
			}
		default:
			return 0, nil, fmt.Errorf("unknown or not implemented Prefix SID Sub TLV type: %d", t)
		}
	}

	return l, p, nil
}

func UnmarshalSubSubTLVs(stlvs map[uint32]*api.SRv6SubSubTLVs) (uint16, []bgp.PrefixSIDTLVInterface, error) {
	p := make([]bgp.PrefixSIDTLVInterface, 0)
	l := uint16(0)
	// v.SubTlvs is a map by sub tlv type and the value is a slice of sub tlvs of the specific type
	for t, tlv := range stlvs {
		switch t {
		case 1:
			// Sub Sub TLV Type 1 is SRv6 Structure Sub Sub TLV
			for _, raw := range tlv.Tlvs {
				// Instantiating Information Sub TLV
				structure := &bgp.SRv6SIDStructureSubSubTLV{
					SubSubTLV: bgp.SubSubTLV{
						Type:   bgp.SubSubTLVType(1),
						Length: 6,
					},
				}
				structureProto := raw.GetStructure()
				structure.LocatorBlockLength = uint8(structureProto.LocatorBlockLength)
				structure.LocatorNodeLength = uint8(structureProto.LocatorNodeLength)
				structure.FunctionLength = uint8(structureProto.FunctionLength)
				structure.ArgumentLength = uint8(structureProto.ArgumentLength)
				structure.TranspositionLength = uint8(structureProto.TranspositionLength)
				structure.TranspositionOffset = uint8(structureProto.TranspositionOffset)

				// SRv6 Structure Sub Sub TLV length consists of header 3 bytes, 6 bytes of value
				l += 3 + 6
				p = append(p, structure)
			}
		default:
			return 0, nil, fmt.Errorf("unknown or not implemented Prefix SID Sub TLV type: %d", t)
		}
	}

	return l, p, nil
}
