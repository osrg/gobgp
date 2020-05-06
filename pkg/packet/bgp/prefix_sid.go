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
	PrefixSIDTLV
	TLVs []PrefixSIDTLVInterface
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
		PrefixSIDAttribute{},
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
	glog.Infof("><SB> PrefixSIDType5 %+v", data)

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

type SRv6SubSubTLV struct {
	PrefixSIDTLV
	TLV []PrefixSIDTLVInterface
}

func (s *SRv6SubSubTLV) Len() int {
	return int(s.Length) + tlvHdrLen
}

func (s *SRv6SubSubTLV) Serialize() ([]byte, error) {
	s.
		if len(value) != int(s.Length) {
			return nil, malformedAttrListErr("serialization failed: Prefix SID TLV malformed")
		}

		buf := make([]byte, tlvHdrLen+len(value))
		binary.BigEndian.PutUint16(buf[:2], uint16(s.Type))
		binary.BigEndian.PutUint16(buf[2:4], uint16(s.Length))
		copy(buf[4:], value)

		return buf, nil
	return nil, nil
}

func (s *SRv6SubSubTLV) DecodeFromBytes(data []byte) error {
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

func (s *SRv6SubSubTLV) MarshalJSON() ([]byte, error) {
	return nil, nil
}

func (s *SRv6SubSubTLV) String() string {
	return ""
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



/////////////////////////////
// type LsTLVAdjacencySID struct {
// 	LsTLV
// 	Flags  uint8
// 	Weight uint8
// 	SID    uint32
// }

// func (l *LsTLVAdjacencySID) DecodeFromBytes(data []byte) error {
// 	value, err := l.LsTLV.DecodeFromBytes(data)
// 	if err != nil {
// 		return err
// 	}

// 	if l.Type != LS_TLV_ADJACENCY_SID {
// 		return malformedAttrListErr("Unexpected TLV type")
// 	}

// 	// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-08#section-2.2.1
// 	if len(value) != 7 && len(value) != 8 {
// 		return malformedAttrListErr("Incorrect Adjacency SID length")
// 	}

// 	l.Flags = value[0]
// 	l.Weight = value[1]

// 	v := value[4:]
// 	if len(v) == 4 {
// 		l.SID = binary.BigEndian.Uint32(v)
// 	} else {
// 		buf := []byte{0, 0, 0, 0}
// 		for i := 1; i < len(buf); i++ {
// 			buf[i] = v[i-1]
// 		}
// 		// Label is represented by 20 rightmost bits.
// 		l.SID = binary.BigEndian.Uint32(buf) & 0xfffff
// 	}

// 	return nil
// }

// func (l *LsTLVAdjacencySID) Serialize() ([]byte, error) {
// 	buf := make([]byte, 0)
// 	buf = append(buf, l.Flags)
// 	buf = append(buf, l.Weight)
// 	// Reserved
// 	buf = append(buf, []byte{0, 0}...)

// 	var b [4]byte
// 	binary.BigEndian.PutUint32(b[:4], l.SID)

// 	if l.Length == 7 {
// 		return l.LsTLV.Serialize(append(buf, b[1:]...))
// 	}

// 	return l.LsTLV.Serialize(append(buf, b[:]...))
// }

// func (l *LsTLVAdjacencySID) String() string {
// 	return fmt.Sprintf("{Adjacency SID: %v}", l.SID)
// }

// func (l *LsTLVAdjacencySID) MarshalJSON() ([]byte, error) {
// 	return json.Marshal(struct {
// 		Type LsTLVType `json:"type"`
// 		SID  uint32    `json:"adjacency_sid"`
// 	}{
// 		Type: l.Type,
// 		SID:  l.SID,
// 	})
// }
//////////////////////////////////////