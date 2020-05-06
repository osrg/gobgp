package bgp

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

const (
	prefixSIDtlvHdrLen = 4
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

type TLVType uint8

type TLV struct {
	Type     TLVType
	Length   uint16
	Reserved uint8
}

func (s *TLV) Len() int {
	return int(s.Length) + tlvHdrLen - 1
}

func (s *TLV) Serialize(value []byte) ([]byte, error) {
	if len(value) != int(s.Length)-1 {
		return nil, malformedAttrListErr("serialization failed: Prefix SID TLV malformed")
	}
	buf := make([]byte, prefixSIDtlvHdrLen+len(value))
	p := 0
	buf[p] = byte(s.Type)
	p++
	binary.BigEndian.PutUint16(buf[p:p+2], uint16(s.Length))
	p += 2
	// Reserved byte
	p++
	copy(buf[p:], value)

	return buf, nil
}

func (s *TLV) DecodeFromBytes(data []byte) ([]byte, error) {
	if len(data) < prefixSIDtlvHdrLen {
		return nil, malformedAttrListErr("decoding failed: Prefix SID TLV malformed")
	}
	p := 0
	s.Type = TLVType(data[p])
	p++
	s.Length = binary.BigEndian.Uint16(data[p : p+2])

	if len(data) < s.Len() {
		return nil, malformedAttrListErr("decoding failed: Prefix SID TLV malformed")
	}

	return data[prefixSIDtlvHdrLen:s.Len()], nil
}

type PrefixSIDAttribute struct {
	TLV
	TLVs []PrefixSIDTLVInterface
}

func (p *PathAttributePrefixSID) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	tlvs, err := p.PathAttribute.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	for len(tlvs) >= prefixSIDtlvHdrLen {
		t := &TLV{}
		_, err := t.DecodeFromBytes(tlvs)
		if err != nil {
			return err
		}

		var tlv PrefixSIDTLVInterface
		switch t.Type {
		case 5:
			tlv = &PrefixSIDType5{
				ServiceTLVs: make([]PrefixSIDTLVInterface, 0),
			}
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
	buf := make([]byte, 0)
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

	return fmt.Sprintf("{Prefix SID attributes: %s}", buf.String())
}

func (p *PathAttributePrefixSID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPAttrType `json:"type"`
		Flags BGPAttrFlag `json:"flags"`
		PrefixSIDAttribute
	}{
		p.GetType(),
		p.GetFlags(),
		// TODO sbezverk
		PrefixSIDAttribute{},
	})
}

// PrefixSIDType5 defines the structure of
type PrefixSIDType5 struct {
	TLV
	ServiceTLVs []PrefixSIDTLVInterface
}

func (s *PrefixSIDType5) Len() int {
	return int(s.Length) + prefixSIDtlvHdrLen
}

func (s *PrefixSIDType5) Serialize() ([]byte, error) {
	buf := make([]byte, 0)
	for _, tlv := range s.ServiceTLVs {
		s, err := tlv.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, s...)
	}
	return s.TLV.Serialize(buf)
}

func (s *PrefixSIDType5) DecodeFromBytes(data []byte) error {
	stlvs, err := s.TLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	for len(stlvs) >= subTLVHdrLen {
		t := &SubTLV{}
		_, err := t.DecodeFromBytes(stlvs)
		if err != nil {
			return err
		}

		var stlv PrefixSIDTLVInterface
		switch t.Type {
		case 1:
			stlv = &SRv6InformationSubTLV{
				SubSubTLVs: make([]PrefixSIDTLVInterface, 0),
			}
		default:
			data = data[t.Len():]
			continue
		}

		if err := stlv.DecodeFromBytes(stlvs); err != nil {
			return err
		}
		stlvs = stlvs[t.Len():]
		s.ServiceTLVs = append(s.ServiceTLVs, stlv)
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

const (
	subTLVHdrLen = 3
)

type SubTLVType uint8

type SubTLV struct {
	Type   SubTLVType
	Length uint16
}

func (s *SubTLV) Len() int {
	return int(s.Length) + subTLVHdrLen
}

func (s *SubTLV) Serialize(value []byte) ([]byte, error) {
	if len(value) != int(s.Length) {
		return nil, malformedAttrListErr("serialization failed: Prefix SID TLV malformed")
	}
	// Extra byte is reserved
	buf := make([]byte, subTLVHdrLen+len(value))
	buf[0] = byte(s.Type)
	binary.BigEndian.PutUint16(buf[1:4], uint16(s.Length))
	// 4th reserved byte
	copy(buf[4:], value)

	return buf, nil
}

func (s *SubTLV) DecodeFromBytes(data []byte) ([]byte, error) {
	if len(data) < subTLVHdrLen {
		return nil, malformedAttrListErr("decoding failed: Prefix SID TLV malformed")
	}
	s.Type = SubTLVType(data[0])
	s.Length = binary.BigEndian.Uint16(data[1:3])

	if len(data) < s.Len() {
		return nil, malformedAttrListErr("decoding failed: Prefix SID TLV malformed")
	}

	return data[subTLVHdrLen:s.Len()], nil
}

// SRv6InformationSubTLV defines a structure of SRv6 Information Sub TLV (type 1) object
// https://tools.ietf.org/html/draft-dawra-bess-srv6-services-02#section-2.1.1
type SRv6InformationSubTLV struct {
	SubTLV
	SID              []byte
	Flags            uint8
	EndpointBehavior uint16
	SubSubTLVs       []PrefixSIDTLVInterface
}

func (s *SRv6InformationSubTLV) Len() int {
	return int(s.Length) + subTLVHdrLen
}

func (s *SRv6InformationSubTLV) Serialize() ([]byte, error) {
	buf := make([]byte, s.Length)
	p := 0
	copy(buf[p:], s.SID)
	p += len(s.SID)
	buf[p] = byte(s.Flags)
	p++
	binary.BigEndian.PutUint16(buf[p:p+2], uint16(s.EndpointBehavior))
	p += 2
	// Reserved byte
	buf[p] = 0x0
	p++
	for _, sstlv := range s.SubSubTLVs {
		sbuf, err := sstlv.Serialize()
		if err != nil {
			return nil, err
		}
		copy(buf[p:], sbuf)
		p += len(sbuf)
	}

	return s.SubTLV.Serialize(buf)
}

func (s *SRv6InformationSubTLV) DecodeFromBytes(data []byte) error {
	if len(data) < subTLVHdrLen {
		return malformedAttrListErr("decoding failed: Prefix SID TLV malformed")
	}
	s.Type = SubTLVType(data[0])
	s.Length = binary.BigEndian.Uint16(data[1:3])
	// 4th reserved byte
	p := 4
	s.SID = make([]byte, 16)
	copy(s.SID, data[p:p+16])
	p += 16
	s.Flags = uint8(data[p])
	p++
	s.EndpointBehavior = binary.BigEndian.Uint16(data[p : p+2])
	p += 2
	// reserved byte
	p++
	if p+3 > len(data) {
		// There is no Sub Sub TLVs detected, returning
		return nil
	}
	stlvs := data[p:]
	for len(stlvs) >= prefixSIDtlvHdrLen {
		t := &SubSubTLV{}
		_, err := t.DecodeFromBytes(stlvs)
		if err != nil {
			return err
		}

		var sstlv PrefixSIDTLVInterface
		switch t.Type {
		case 1:
			sstlv = &SRv6SIDStructureSubSubTLV{}
		default:
			stlvs = stlvs[t.Len():]
			continue
		}

		if err := sstlv.DecodeFromBytes(stlvs); err != nil {
			return err
		}
		stlvs = stlvs[t.Len():]
		s.SubSubTLVs = append(s.SubSubTLVs, sstlv)
	}

	return nil
}

func (s *SRv6InformationSubTLV) MarshalJSON() ([]byte, error) {
	return nil, nil
}

func (s *SRv6InformationSubTLV) String() string {
	return ""
}
