package bgp

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

type PrefixSIDTLVType uint16

type PrefixSIDTLV struct {
	Type   PrefixSIDTLVType
	Length uint16
}

type PrefixSIDTLVInterface interface {
	Len() int
	DecodeFromBytes([]byte) error
	Serialize() ([]byte, error)
	String() string
	MarshalJSON() ([]byte, error)
}

type PathAttributePrefixSID struct {
	PathAttribute
	TLVs []PrefixSIDTLVInterface
}

func (s *PrefixSIDTLV) Len() int {
	return int(s.Length) + tlvHdrLen
}

func (s *PrefixSIDTLV) Serialize(value []byte) ([]byte, error) {
	if len(value) != int(s.Length) {
		return nil, malformedAttrListErr("serialization failed: Prefix SID TLV malformed")
	}

	buf := make([]byte, tlvHdrLen+len(value))
	binary.BigEndian.PutUint16(buf[:2], uint16(s.Type))
	binary.BigEndian.PutUint16(buf[2:4], uint16(s.Length))
	copy(buf[4:], value)

	return buf, nil
}

func (s *PrefixSIDTLV) DecodeFromBytes(data []byte) ([]byte, error) {
	if len(data) < tlvHdrLen {
		return nil, malformedAttrListErr("decoding failed: Prefix SID TLV malformed")
	}
	//	l.Type = PrefixSIDTLVType(binary.BigEndian.Uint16(data[:2]))
	//	l.Length = binary.BigEndian.Uint16(data[2:4])

	//	if len(data) < l.Len() {
	//		return nil, malformedAttrListErr("decoding failed: Prefix SID TLV malformed")
	//	}

	return data[tlvHdrLen:s.Len()], nil
}

//type LsAttributePrefix struct {
//	IGPFlags *LsIGPFlags `json:"igp_flags,omitempty"`
//	Opaque   *[]byte     `json:"opaque,omitempty"`
//
//	SrPrefixSID *uint32 `json:"sr_prefix_sid,omitempty"`
//}

type PrefixSIDAttribute struct {
	//	Node   LsAttributeNode   `json:"node"`
	//	Link   LsAttributeLink   `json:"link"`
	//	Prefix LsAttributePrefix `json:"prefix"`
}

func (p *PathAttributePrefixSID) Extract() *PrefixSIDAttribute {
	s := &PrefixSIDAttribute{}

	// for _, tlv := range p.TLVs {
	// 	switch v := tlv.(type) {
	// 	case *LsTLVNodeFlagBits:
	// 		l.Node.Flags = v.Extract()

	// 	case *LsTLVOpaqueNodeAttr:
	// 		l.Node.Opaque = &v.Attr

	// 	case *LsTLVNodeName:
	// 		l.Node.Name = &v.Name

	// 	case *LsTLVIsisArea:
	// 		l.Node.IsisArea = &v.Area

	// 	case *LsTLVLocalIPv4RouterID:
	// 		l.Node.LocalRouterID = &v.IP
	// 		l.Link.LocalRouterID = &v.IP

	// 	case *LsTLVLocalIPv6RouterID:
	// 		l.Node.LocalRouterIDv6 = &v.IP
	// 		l.Link.LocalRouterIDv6 = &v.IP

	// 	case *LsTLVSrCapabilities:
	// 		l.Node.SrCapabilties = v.Extract()

	// 	case *LsTLVSrAlgorithm:
	// 		l.Node.SrAlgorithms = &v.Algorithm

	// 	case *LsTLVSrLocalBlock:
	// 		l.Node.SrLocalBlock = v.Extract()

	// 	case *LsTLVRemoteIPv4RouterID:
	// 		l.Link.RemoteRouterID = &v.IP

	// 	case *LsTLVRemoteIPv6RouterID:
	// 		l.Link.RemoteRouterIDv6 = &v.IP

	// 	case *LsTLVAdminGroup:
	// 		l.Link.AdminGroup = &v.AdminGroup

	// 	case *LsTLVMaxLinkBw:
	// 		l.Link.Bandwidth = &v.Bandwidth

	// 	case *LsTLVMaxReservableLinkBw:
	// 		l.Link.ReservableBandwidth = &v.Bandwidth

	// 	case *LsTLVUnreservedBw:
	// 		l.Link.UnreservedBandwidth = &v.Bandwidth

	// 	case *LsTLVSrlg:
	// 		l.Link.Srlgs = &v.Srlgs

	// 	case *LsTLVTEDefaultMetric:
	// 		l.Link.DefaultTEMetric = &v.Metric

	// 	case *LsTLVIGPMetric:
	// 		l.Link.IGPMetric = &v.Metric

	// 	case *LsTLVOpaqueLinkAttr:
	// 		l.Link.Opaque = &v.Attr

	// 	case *LsTLVLinkName:
	// 		l.Link.Name = &v.Name

	// 	case *LsTLVAdjacencySID:
	// 		l.Link.SrAdjacencySID = &v.SID

	// 	case *LsTLVIGPFlags:
	// 		l.Prefix.IGPFlags = v.Extract()

	// 	case *LsTLVOpaquePrefixAttr:
	// 		l.Prefix.Opaque = &v.Attr

	// 	case *LsTLVPrefixSID:
	// 		l.Prefix.SrPrefixSID = &v.SID
	// 	}
	// }

	return s
}

func (p *PathAttributePrefixSID) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	tlvs, err := p.PathAttribute.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	for len(tlvs) >= tlvHdrLen {
		t := &PrefixSIDTLV{}
		_, err := t.DecodeFromBytes(tlvs)
		if err != nil {
			return err
		}

		var tlv PrefixSIDTLVInterface
		// switch t.Type {
		// // Node NLRI-related TLVs (https://tools.ietf.org/html/rfc7752#section-3.3.1)
		// case LS_TLV_NODE_FLAG_BITS:
		// 	tlv = &LsTLVNodeFlagBits{}

		// case LS_TLV_OPAQUE_NODE_ATTR:
		// 	tlv = &LsTLVOpaqueNodeAttr{}

		// case LS_TLV_NODE_NAME:
		// 	tlv = &LsTLVNodeName{}

		// case LS_TLV_ISIS_AREA:
		// 	tlv = &LsTLVIsisArea{}

		// // Used by Link NLRI as well.
		// case LS_TLV_IPV4_LOCAL_ROUTER_ID:
		// 	tlv = &LsTLVLocalIPv4RouterID{}

		// // Used by Link NLRI as well.
		// case LS_TLV_IPV6_LOCAL_ROUTER_ID:
		// 	tlv = &LsTLVLocalIPv6RouterID{}

		// // SR-related TLVs (draft-ietf-idr-bgp-ls-segment-routing-ext-08) for Node NLRI
		// case LS_TLV_SR_CAPABILITIES:
		// 	tlv = &LsTLVSrCapabilities{}

		// case LS_TLV_SR_ALGORITHM:
		// 	tlv = &LsTLVSrAlgorithm{}

		// case LS_TLV_SR_LOCAL_BLOCK:
		// 	tlv = &LsTLVSrLocalBlock{}

		// // Link NLRI-related TLVs (https://tools.ietf.org/html/rfc7752#section-3.3.2)
		// case LS_TLV_IPV4_REMOTE_ROUTER_ID:
		// 	tlv = &LsTLVRemoteIPv4RouterID{}

		// case LS_TLV_IPV6_REMOTE_ROUTER_ID:
		// 	tlv = &LsTLVRemoteIPv6RouterID{}

		// case LS_TLV_ADMIN_GROUP:
		// 	tlv = &LsTLVAdminGroup{}

		// case LS_TLV_MAX_LINK_BANDWIDTH:
		// 	tlv = &LsTLVMaxLinkBw{}

		// case LS_TLV_MAX_RESERVABLE_BANDWIDTH:
		// 	tlv = &LsTLVMaxReservableLinkBw{}

		// case LS_TLV_UNRESERVED_BANDWIDTH:
		// 	tlv = &LsTLVUnreservedBw{}

		// case LS_TLV_SRLG:
		// 	tlv = &LsTLVSrlg{}

		// case LS_TLV_TE_DEFAULT_METRIC:
		// 	tlv = &LsTLVTEDefaultMetric{}

		// case LS_TLV_IGP_METRIC:
		// 	tlv = &LsTLVIGPMetric{}

		// case LS_TLV_OPAQUE_LINK_ATTR:
		// 	tlv = &LsTLVOpaqueLinkAttr{}

		// case LS_TLV_LINK_NAME:
		// 	tlv = &LsTLVLinkName{}

		// // SR-related TLVs (draft-ietf-idr-bgp-ls-segment-routing-ext-08) for Link NLRI
		// case LS_TLV_ADJACENCY_SID:
		// 	tlv = &LsTLVAdjacencySID{}

		// // Prefix NLRI-related TLVs (https://tools.ietf.org/html/rfc7752#section-3.3.3)
		// case LS_TLV_IGP_FLAGS:
		// 	tlv = &LsTLVIGPFlags{}

		// case LS_TLV_OPAQUE_PREFIX_ATTR:
		// 	tlv = &LsTLVOpaquePrefixAttr{}

		// // SR-related TLVs (draft-ietf-idr-bgp-ls-segment-routing-ext-08) for Prefix NLRI
		// case LS_TLV_PREFIX_SID:
		// 	tlv = &LsTLVPrefixSID{}

		// default:
		// 	tlvs = tlvs[t.Len():]
		// 	continue
		// }

		if err := tlv.DecodeFromBytes(tlvs); err != nil {
			return err
		}
		tlvs = tlvs[t.Len():]

		p.TLVs = append(p.TLVs, tlv)
	}

	return nil
}

func (p *PathAttributePrefixSID) Serialize(options ...*MarshallingOption) ([]byte, error) {
	buf := []byte{}

	for _, tlv := range p.TLVs {
		s, err := tlv.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, s...)
	}

	return p.PathAttribute.Serialize(buf, options...)
}

func (p *PathAttributePrefixSID) String() string {
	var buf bytes.Buffer

	for _, tlv := range p.TLVs {
		buf.WriteString(fmt.Sprintf("%s ", tlv.String()))
	}

	return fmt.Sprintf("{LsAttributes: %s}", buf.String())
}

func (p *PathAttributePrefixSID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPAttrType `json:"type"`
		Flags BGPAttrFlag `json:"flags"`
		PrefixSIDAttribute
	}{
		p.GetType(),
		p.GetFlags(),
		*p.Extract(),
	})
}
