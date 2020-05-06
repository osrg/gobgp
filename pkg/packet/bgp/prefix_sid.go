package bgp

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
)

// PrefixSIDTLVInterface defines standard set of methods to handle Prefix SID attribute's TLVs
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

type PrefixSIDTLVType uint8

type PrefixSIDTLV struct {
	Type   PrefixSIDTLVType
	Length uint16
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
	s.Type = PrefixSIDTLVType(binary.BigEndian.Uint16(data[:2]))
	s.Length = binary.BigEndian.Uint16(data[2:4])

	if len(data) < s.Len() {
		return nil, malformedAttrListErr("decoding failed: Prefix SID TLV malformed")
	}

	return data[tlvHdrLen:s.Len()], nil
}

type PrefixSIDAttribute struct {
	TLVs []PrefixSIDTLVInterface
}

func (p *PathAttributePrefixSID) Extract() *PrefixSIDAttribute {
	s := &PrefixSIDAttribute{
		TLVs: make([]PrefixSIDTLVInterface, 0),
	}

	for _, tlv := range p.TLVs {
		switch v := tlv.(type) {
		case *PrefixSIDType5:
			glog.Infof("><SB> v: %+v", v)
			o := &PrefixSIDType5{}
			s.TLVs = append(s.TLVs, o)
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
		}
	}

	return s
}

func (p *PathAttributePrefixSID) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	tlvs, err := p.PathAttribute.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	glog.Infof("><SB> tlvs: %+v", tlvs)
	for len(tlvs) >= tlvHdrLen {
		t := &PrefixSIDTLV{}
		_, err := t.DecodeFromBytes(tlvs)
		if err != nil {
			return err
		}

		var tlv PrefixSIDTLVInterface
		switch t.Type {
		case 5:
			tlv = &PrefixSIDType5{}
		default:
			tlvs = tlvs[t.Len():]
			continue
		}

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

	return p.PathAttribute.Serialize(buf)
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

// PrefixSIDType5 defines the structure of
type PrefixSIDType5 struct {
	PrefixSIDTLV
	ServiceTLVs []PrefixSIDTLVInterface
}

func (s *PrefixSIDType5) Len() int {
	return int(s.Length) + tlvHdrLen
}

func (s *PrefixSIDType5) Serialize() ([]byte, error) {
	//	if len(value) != int(s.Length) {
	//		return nil, malformedAttrListErr("serialization failed: Prefix SID TLV malformed")
	//	}

	//	buf := make([]byte, tlvHdrLen+len(value))
	//	binary.BigEndian.PutUint16(buf[:2], uint16(s.Type))
	//	binary.BigEndian.PutUint16(buf[2:4], uint16(s.Length))
	//	copy(buf[4:], value)

	//	return buf, nil
	return nil, nil
}

func (s *PrefixSIDType5) DecodeFromBytes(data []byte) error {
	if len(data) < tlvHdrLen {
		return malformedAttrListErr("decoding failed: Prefix SID TLV malformed")
	}
	s.Type = PrefixSIDTLVType(binary.BigEndian.Uint16(data[:2]))
	s.Length = binary.BigEndian.Uint16(data[2:4])

	if len(data) < s.Len() {
		return malformedAttrListErr("decoding failed: Prefix SID TLV malformed")
	}

	return nil
}

func (s *PrefixSIDType5) MarshalJSON() ([]byte, error) {
	return nil, nil
}

func (s *PrefixSIDType5) String() string {
	return ""
}

func (s *PrefixSIDType5) Extract() string {
	return ""
}

type SRv6ServiceSubTLV struct {
	PrefixSIDTLV
	TLV []PrefixSIDTLVInterface
}

func (s *SRv6ServiceSubTLV) Len() int {
	return int(s.Length) + tlvHdrLen
}

func (s *SRv6ServiceSubTLV) Serialize() ([]byte, error) {
	//	if len(value) != int(s.Length) {
	//		return nil, malformedAttrListErr("serialization failed: Prefix SID TLV malformed")
	//	}

	//	buf := make([]byte, tlvHdrLen+len(value))
	//	binary.BigEndian.PutUint16(buf[:2], uint16(s.Type))
	//	binary.BigEndian.PutUint16(buf[2:4], uint16(s.Length))
	//	copy(buf[4:], value)

	//	return buf, nil
	return nil, nil
}

func (s *SRv6ServiceSubTLV) DecodeFromBytes(data []byte) error {
	if len(data) < tlvHdrLen {
		return malformedAttrListErr("decoding failed: Prefix SID TLV malformed")
	}
	s.Type = PrefixSIDTLVType(binary.BigEndian.Uint16(data[:2]))
	s.Length = binary.BigEndian.Uint16(data[2:4])

	if len(data) < s.Len() {
		return malformedAttrListErr("decoding failed: Prefix SID TLV malformed")
	}

	return nil
}

func (s *SRv6ServiceSubTLV) MarshalJSON() ([]byte, error) {
	return nil, nil
}

func (s *SRv6ServiceSubTLV) String() string {
	return ""
}

// SRv6InformationSubTLV defines a structure of SRv6 Information Sub TLV (type 1) object
// https://tools.ietf.org/html/draft-dawra-bess-srv6-services-02#section-2.1.1
type SRv6InformationSubTLV struct {
	PrefixSIDTLV
	SID              []byte
	Flags            uint8
	EndpointBehavior uint16
	SubSubTLV        []PrefixSIDTLVInterface
}

// SRv6SIDStructureSubSubTLV defines a structure of SRv6 SID Structure Sub Sub TLV (type 1) object
// https://tools.ietf.org/html/draft-dawra-bess-srv6-services-02#section-2.1.2.1
type SRv6SIDStructureSubSubTLV struct {
	PrefixSIDTLV
	LocalBlockLength    uint8 `json:"local_block_length,omitempty"`
	LocatorNodeLength   uint8 `json:"locator_node_length,omitempty"`
	FunctionLength      uint8 `json:"function_length,omitempty"`
	ArgumentLength      uint8 `json:"argument_length,omitempty"`
	TranspositionLength uint8 `json:"transposition_length,omitempty"`
	TranspositionOffset uint8 `json:"transposition_offset,omitempty"`
}
