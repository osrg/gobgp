package bgp

import "encoding/binary"

const (
	subSubTLVHdrLen = 3
)

type SubSubTLVType uint8

type SubSubTLV struct {
	Type   SubSubTLVType
	Length uint16
}

func (s *SubSubTLV) Len() int {
	return int(s.Length) + subSubTLVHdrLen
}

func (s *SubSubTLV) Serialize(value []byte) ([]byte, error) {
	if len(value) != int(s.Length) {
		return nil, malformedAttrListErr("serialization failed: Prefix SID TLV malformed")
	}
	// Extra byte is reserved
	buf := make([]byte, subSubTLVHdrLen+len(value))
	p := 0
	buf[p] = byte(s.Type)
	p++
	binary.BigEndian.PutUint16(buf[p:p+2], uint16(s.Length))
	p += 2
	copy(buf[p:], value)

	return buf, nil
}

func (s *SubSubTLV) DecodeFromBytes(data []byte) ([]byte, error) {
	if len(data) < prefixSIDtlvHdrLen {
		return nil, malformedAttrListErr("decoding failed: Prefix SID Sub Sub TLV malformed")
	}
	s.Type = SubSubTLVType(data[0])
	s.Length = binary.BigEndian.Uint16(data[1:3])

	if len(data) < s.Len() {
		return nil, malformedAttrListErr("decoding failed: Prefix SID Sub Sub TLV malformed")
	}

	return data[prefixSIDtlvHdrLen:s.Len()], nil
}

// SRv6SIDStructureSubSubTLV defines a structure of SRv6 SID Structure Sub Sub TLV (type 1) object
// https://tools.ietf.org/html/draft-dawra-bess-srv6-services-02#section-2.1.2.1
type SRv6SIDStructureSubSubTLV struct {
	SubSubTLV
	LocalBlockLength    uint8 `json:"local_block_length,omitempty"`
	LocatorNodeLength   uint8 `json:"locator_node_length,omitempty"`
	FunctionLength      uint8 `json:"function_length,omitempty"`
	ArgumentLength      uint8 `json:"argument_length,omitempty"`
	TranspositionLength uint8 `json:"transposition_length,omitempty"`
	TranspositionOffset uint8 `json:"transposition_offset,omitempty"`
}

func (s *SRv6SIDStructureSubSubTLV) Len() int {
	return int(s.Length) + subSubTLVHdrLen
}

func (s *SRv6SIDStructureSubSubTLV) Serialize() ([]byte, error) {
	buf := make([]byte, s.Length)
	p := 0
	buf[p] = s.LocalBlockLength
	p++
	buf[p] = s.LocatorNodeLength
	p++
	buf[p] = s.FunctionLength
	p++
	buf[p] = s.ArgumentLength
	p++
	buf[p] = s.TranspositionLength
	p++
	buf[p] = s.TranspositionOffset

	return s.SubSubTLV.Serialize(buf)
}

func (s *SRv6SIDStructureSubSubTLV) DecodeFromBytes(data []byte) error {
	if len(data) < subSubTLVHdrLen {
		return malformedAttrListErr("decoding failed: Prefix SID Sub Sub TLV malformed")
	}
	s.Type = SubSubTLVType(data[0])
	s.Length = binary.BigEndian.Uint16(data[1:3])

	s.LocalBlockLength = data[3]
	s.LocatorNodeLength = data[4]
	s.FunctionLength = data[5]
	s.ArgumentLength = data[6]
	s.TranspositionLength = data[7]
	s.TranspositionOffset = data[8]

	return nil
}

func (s *SRv6SIDStructureSubSubTLV) MarshalJSON() ([]byte, error) {
	return nil, nil
}

func (s *SRv6SIDStructureSubSubTLV) String() string {
	return ""
}
