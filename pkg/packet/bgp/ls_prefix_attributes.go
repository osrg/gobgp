package bgp

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
)

func decodeLsPrefixAttribute(data []byte, typ LsTLVType) (LsTLV, []byte, error) {
	var header LsTLV
	value, err := header.DecodeFromBytes(data)
	if err != nil {
		return LsTLV{}, nil, err
	}
	if header.Type != typ {
		return LsTLV{}, nil, malformedAttrListErr("Unexpected prefix attribute TLV type")
	}
	return header, value, nil
}

func serializeLsPrefixAttribute(header LsTLV, typ LsTLVType, value []byte) ([]byte, error) {
	if header.Type != typ {
		return nil, malformedAttrListErr("Unexpected prefix attribute TLV type")
	}
	return header.Serialize(value)
}

// LsTLVIGPRouteTag is the IGP Route Tag TLV from RFC 9552 Section 5.3.3.2.
// Tags retains every tag in wire order, including duplicates and zero values.
type LsTLVIGPRouteTag struct {
	LsTLV
	Tags []uint32
}

// NewLsTLVIGPRouteTag constructs an IGP Route Tag TLV using tags without copying.
// Serialize rejects an empty list or more than 16383 tags.
func NewLsTLVIGPRouteTag(tags []uint32) *LsTLVIGPRouteTag {
	return &LsTLVIGPRouteTag{
		LsTLV: LsTLV{Type: LS_TLV_IGP_ROUTE_TAG, Length: uint16(4 * len(tags))},
		Tags:  tags,
	}
}

// DecodeFromBytes implements [LsTLVInterface]. It replaces the receiver only
// after successful decoding, and the decoded tags do not alias data.
func (l *LsTLVIGPRouteTag) DecodeFromBytes(data []byte) error {
	header, value, err := decodeLsPrefixAttribute(data, LS_TLV_IGP_ROUTE_TAG)
	if err != nil {
		return err
	}
	if len(value) == 0 || len(value)%4 != 0 {
		return malformedAttrListErr("Incorrect IGP route tag length")
	}
	tags := make([]uint32, len(value)/4)
	for index := range tags {
		tags[index] = binary.BigEndian.Uint32(value[index*4:])
	}
	l.LsTLV, l.Tags = header, tags
	return nil
}

// Serialize implements [LsTLVInterface].
func (l *LsTLVIGPRouteTag) Serialize() ([]byte, error) {
	if len(l.Tags) == 0 || len(l.Tags) > 65535/4 {
		return nil, malformedAttrListErr("Incorrect IGP route tag length")
	}
	value := make([]byte, 4*len(l.Tags))
	for index, tag := range l.Tags {
		binary.BigEndian.PutUint32(value[index*4:], tag)
	}
	return serializeLsPrefixAttribute(l.LsTLV, LS_TLV_IGP_ROUTE_TAG, value)
}

// GetLsTLV implements [LsTLVInterface].
func (l *LsTLVIGPRouteTag) GetLsTLV() LsTLV { return l.LsTLV }

// String implements [LsTLVInterface].
func (l *LsTLVIGPRouteTag) String() string { return fmt.Sprintf("{IGP Route Tags: %v}", l.Tags) }

// MarshalJSON implements [LsTLVInterface].
func (l *LsTLVIGPRouteTag) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type LsTLVType `json:"type"`
		Tags []uint32  `json:"igp_route_tags"`
	}{Type: l.Type, Tags: l.Tags})
}

// LsTLVExtendedRouteTag is the Extended Route Tag TLV from RFC 9552 Section 5.3.3.3.
// Tags retains every tag in wire order, including duplicates and zero values.
type LsTLVExtendedRouteTag struct {
	LsTLV
	Tags []uint64
}

// NewLsTLVExtendedRouteTag constructs an Extended Route Tag TLV using tags
// without copying. Serialize rejects an empty list or more than 8191 tags.
func NewLsTLVExtendedRouteTag(tags []uint64) *LsTLVExtendedRouteTag {
	return &LsTLVExtendedRouteTag{
		LsTLV: LsTLV{Type: LS_TLV_EXTENDED_ROUTE_TAG, Length: uint16(8 * len(tags))},
		Tags:  tags,
	}
}

// DecodeFromBytes implements [LsTLVInterface]. It replaces the receiver only
// after successful decoding, and the decoded tags do not alias data.
func (l *LsTLVExtendedRouteTag) DecodeFromBytes(data []byte) error {
	header, value, err := decodeLsPrefixAttribute(data, LS_TLV_EXTENDED_ROUTE_TAG)
	if err != nil {
		return err
	}
	if len(value) == 0 || len(value)%8 != 0 {
		return malformedAttrListErr("Incorrect extended route tag length")
	}
	tags := make([]uint64, len(value)/8)
	for index := range tags {
		tags[index] = binary.BigEndian.Uint64(value[index*8:])
	}
	l.LsTLV, l.Tags = header, tags
	return nil
}

// Serialize implements [LsTLVInterface].
func (l *LsTLVExtendedRouteTag) Serialize() ([]byte, error) {
	if len(l.Tags) == 0 || len(l.Tags) > 65535/8 {
		return nil, malformedAttrListErr("Incorrect extended route tag length")
	}
	value := make([]byte, 8*len(l.Tags))
	for index, tag := range l.Tags {
		binary.BigEndian.PutUint64(value[index*8:], tag)
	}
	return serializeLsPrefixAttribute(l.LsTLV, LS_TLV_EXTENDED_ROUTE_TAG, value)
}

// GetLsTLV implements [LsTLVInterface].
func (l *LsTLVExtendedRouteTag) GetLsTLV() LsTLV { return l.LsTLV }

// String implements [LsTLVInterface].
func (l *LsTLVExtendedRouteTag) String() string {
	return fmt.Sprintf("{Extended Route Tags: %v}", l.Tags)
}

// MarshalJSON implements [LsTLVInterface].
func (l *LsTLVExtendedRouteTag) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type LsTLVType `json:"type"`
		Tags []uint64  `json:"extended_route_tags"`
	}{Type: l.Type, Tags: l.Tags})
}

// LsTLVOSPFForwardingAddress is the OSPF Forwarding Address TLV from RFC 9552
// Section 5.3.3.5. Address retains the IPv4 or IPv6 wire family.
type LsTLVOSPFForwardingAddress struct {
	LsTLV
	Address netip.Addr
}

// NewLsTLVOSPFForwardingAddress constructs an OSPF Forwarding Address TLV.
// Serialize rejects invalid addresses and addresses with an IPv6 zone.
func NewLsTLVOSPFForwardingAddress(address netip.Addr) *LsTLVOSPFForwardingAddress {
	length := 16
	if address.Is4() {
		length = 4
	}
	return &LsTLVOSPFForwardingAddress{
		LsTLV:   LsTLV{Type: LS_TLV_OSPF_FORWARDING_ADDR, Length: uint16(length)},
		Address: address,
	}
}

// DecodeFromBytes implements [LsTLVInterface]. It replaces the receiver only
// after successful decoding, and the decoded address does not alias data.
func (l *LsTLVOSPFForwardingAddress) DecodeFromBytes(data []byte) error {
	header, value, err := decodeLsPrefixAttribute(data, LS_TLV_OSPF_FORWARDING_ADDR)
	if err != nil {
		return err
	}
	if len(value) != 4 && len(value) != 16 {
		return malformedAttrListErr("Incorrect OSPF forwarding address length")
	}
	address, _ := netip.AddrFromSlice(value)
	l.LsTLV, l.Address = header, address
	return nil
}

// Serialize implements [LsTLVInterface].
func (l *LsTLVOSPFForwardingAddress) Serialize() ([]byte, error) {
	if !l.Address.IsValid() || l.Address.Zone() != "" {
		return nil, malformedAttrListErr("Invalid OSPF forwarding address")
	}
	return serializeLsPrefixAttribute(l.LsTLV, LS_TLV_OSPF_FORWARDING_ADDR, l.Address.AsSlice())
}

// GetLsTLV implements [LsTLVInterface].
func (l *LsTLVOSPFForwardingAddress) GetLsTLV() LsTLV { return l.LsTLV }

// String implements [LsTLVInterface].
func (l *LsTLVOSPFForwardingAddress) String() string {
	return fmt.Sprintf("{OSPF Forwarding Address: %v}", l.Address)
}

// MarshalJSON implements [LsTLVInterface].
func (l *LsTLVOSPFForwardingAddress) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type    LsTLVType  `json:"type"`
		Address netip.Addr `json:"ospf_forwarding_address"`
	}{Type: l.Type, Address: l.Address})
}
