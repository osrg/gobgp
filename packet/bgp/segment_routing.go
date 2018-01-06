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

package bgp

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
)

// SegmentID represents the Segment Identifier used in the Segment Routing.
type SegmentID []byte

// Len returns the length of the Segment Identifier in bytes.
func (i *SegmentID) Len() int {
	return len(*i)
}

// 4-octet SID Format:
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Label                        | TC  |S|       TTL     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func (i *SegmentID) is4Octet() bool {
	return len(*i) == 4
}

// 16-octet IPv6 SID Format:
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// //                       IPv6 SID (16 octets)                  //
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func (i *SegmentID) is16Octet() bool {
	return len(*i) == 16
}

// Label returns the significant 20 bits which represents MPLS label field if
// SegmentID is a 4-octet SID, otherwise 0.
func (i *SegmentID) Label() uint32 {
	if !i.is4Octet() {
		return 0
	}
	return binary.BigEndian.Uint32(*i) >> 12
}

// TrafficClass returns the MPLS TrafficClass (Experimental) field (3 bits) if
// SegmentID is a 4-octet SID, otherwise 0.
func (i *SegmentID) TrafficClass() uint8 {
	if !i.is4Octet() {
		return 0
	}
	b := []byte(*i)
	return (b[2] >> 1) & 0x7
}

// isBoS returns true if SegmentID is a 4-octet SID and the MPLS BoS bit is
// set, otherwise false.
func (i *SegmentID) isBoS() bool {
	if !i.is4Octet() {
		return false
	}
	b := []byte(*i)
	return (b[2] & 0x1) == 1
}

// TTL returns the MPLS TTL field (1 byte) if SegmentID is a 4-octet SID,
// otherwise 0.
func (i *SegmentID) TTL() uint8 {
	if !i.is4Octet() {
		return 0
	}
	b := []byte(*i)
	return b[3]
}

func (i *SegmentID) String() string {
	switch i.Len() {
	case 0:
		return "<nil>"
	case 4:
		// 4-octet SID
		return fmt.Sprint(binary.BigEndian.Uint32(*i))
	case 16:
		// 16-octet IPv6 SID
		return net.IP(*i).String()
	default:
		return fmt.Sprint([]byte(*i))
	}
}

func (i SegmentID) MarshalJSON() ([]byte, error) {
	switch i.Len() {
	case 0:
		return nil, nil
	case 4:
		// 4-octet SID
		return json.Marshal(binary.BigEndian.Uint32(i))
	case 16:
		// 16-octet IPv6 SID
		return json.Marshal(net.IP(i))
	default:
		return []byte(i), nil
	}
}

func ParseSegmentID(s string) (sid SegmentID, err error) {
	// Case of 4-octet SID
	if n, err := strconv.ParseUint(s, 10, 32); err == nil {
		sid = make([]byte, 4, 4)
		binary.BigEndian.PutUint32(sid, uint32(n))
	}

	// Case of 16-octet IPv6 SID
	ip := net.ParseIP(s)
	if ip.To16() != nil {
		sid = SegmentID(ip)
	}

	if sid == nil {
		return nil, fmt.Errorf("invalid sid: %s", s)
	}
	return sid, nil
}

// SRTEPolicyNLRI represents SR TE Policy NLRI.
type SRTEPolicyNLRI struct {
	PrefixDefault
	Length        uint8 // length of Distinguisher + Color + Endpoint in bits
	Distinguisher uint32
	Color         uint32
	Endpoint      net.IP
	// rf has no correpsonding NLRI field and it is used to determine AFI/SAFI
	rf RouteFamily
}

func (n *SRTEPolicyNLRI) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	if n.rf == 0 {
		n.rf = RF_IPv4_SR_TE
	}
	if IsAddPathEnabled(true, n.rf, options) {
		var err error
		data, err = n.decodePathIdentifier(data)
		if err != nil {
			return err
		}
	}
	if len(data) < 1 {
		return NewMessageError(
			uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR),
			uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST), nil,
			"sr te policy nlri misses length field")
	}
	n.Length = data[0]
	invalidLengthError := NewMessageError(
		uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR),
		uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST), nil,
		fmt.Sprintf("sr te policy nlri length invalid for %s: %x", n.rf.String(), data))
	switch n.Length {
	case 96: // Distinguisher + Color + Endpoint(IPv4)
		if n.rf != RF_IPv4_SR_TE {
			return invalidLengthError
		}
		n.Endpoint = net.IP(data[9:13]).To4()
	case 192: // Distinguisher + Color + Endpoint(IPv6)
		if n.rf != RF_IPv6_SR_TE {
			return invalidLengthError
		}
		n.Endpoint = net.IP(data[9:25]).To16()
	default:
		return invalidLengthError
	}
	n.Distinguisher = binary.BigEndian.Uint32(data[1:5])
	n.Color = binary.BigEndian.Uint32(data[5:9])
	return nil
}

func (n *SRTEPolicyNLRI) Serialize(options ...*MarshallingOption) ([]byte, error) {
	var buf []byte
	if IsAddPathEnabled(false, n.rf, options) {
		var err error
		buf, err = n.serializeIdentifier()
		if err != nil {
			return nil, err
		}
	}
	tmpBuf := make([]byte, 8, 8)
	binary.BigEndian.PutUint32(tmpBuf[0:4], n.Distinguisher)
	binary.BigEndian.PutUint32(tmpBuf[4:8], n.Color)
	tmpBuf = append(tmpBuf, n.Endpoint...)
	n.Length = uint8(len(tmpBuf) * 8)
	buf = append(buf, n.Length)
	return append(buf, tmpBuf...), nil
}

func (n *SRTEPolicyNLRI) AFI() uint16 {
	afi, _ := RouteFamilyToAfiSafi(n.rf)
	return afi
}

func (n *SRTEPolicyNLRI) SAFI() uint8 {
	return SAFI_SR_TE_POLICY
}

func (n *SRTEPolicyNLRI) Len(options ...*MarshallingOption) int {
	return 1 + ((int(n.Length) + 7) / 8)
}

func (n *SRTEPolicyNLRI) String() string {
	return fmt.Sprintf("[distinguisher:%d][color:%d][endpoint:%s]", n.Distinguisher, n.Color, n.Endpoint.String())
}

func (n *SRTEPolicyNLRI) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Distinguisher uint32 `json:"distinguisher"`
		Color         uint32 `json:"color"`
		Endpoint      string `json:"endpoint"`
	}{
		Distinguisher: n.Distinguisher,
		Color:         n.Color,
		Endpoint:      n.Endpoint.String(),
	})
}

func (n *SRTEPolicyNLRI) Flat() map[string]string {
	return map[string]string{
		"Length":        fmt.Sprintf("%d", n.Length),
		"Distinguisher": fmt.Sprintf("%d", n.Distinguisher),
		"Color":         fmt.Sprintf("%d", n.Color),
		"Endpoint":      n.Endpoint.String(),
	}
}

func NewIPv4SRTEPolicyNLRI(distinguisher uint32, color uint32, endpoint net.IP) *SRTEPolicyNLRI {
	return &SRTEPolicyNLRI{
		Distinguisher: distinguisher,
		Color:         color,
		Endpoint:      endpoint.To4(),
		rf:            RF_IPv4_SR_TE,
	}
}

func NewIPv6SRTEPolicyNLRI(distinguisher uint32, color uint32, endpoint net.IP) *SRTEPolicyNLRI {
	return &SRTEPolicyNLRI{
		Distinguisher: distinguisher,
		Color:         color,
		Endpoint:      endpoint.To16(),
		rf:            RF_IPv6_SR_TE,
	}
}

// SegmentListSubTLVInterface is the interface type for the Sub-TLVs for the Segment
// List Sub-TLV.
type SegmentListSubTLVInterface interface {
	Type() SegmentListSubTLVType
	decodeValue([]byte) error
	serializeValue() ([]byte, error)
	String() string
	MarshalJSON() ([]byte, error)
}

// SegmentListSubTLVType represents the types for the Sub-TLVs for the Segment
// List Sub-TLV.
type SegmentListSubTLVType uint8

const (
	SEGMENT_LIST_SUB_TLV_TYPE_MPLS_LABEL_SID                SegmentListSubTLVType = 1
	SEGMENT_LIST_SUB_TLV_TYPE_IPv6_ADDRESS_SID              SegmentListSubTLVType = 2
	SEGMENT_LIST_SUB_TLV_TYPE_IPv4_NODE_ADDRESS_SID         SegmentListSubTLVType = 3
	SEGMENT_LIST_SUB_TLV_TYPE_IPv6_NODE_ADDRESS_SID         SegmentListSubTLVType = 4
	SEGMENT_LIST_SUB_TLV_TYPE_IPv4_ADDRESS_INDEX_SID        SegmentListSubTLVType = 5
	SEGMENT_LIST_SUB_TLV_TYPE_IPv4_LOCAL_REMOTE_ADDRESS_SID SegmentListSubTLVType = 6
	SEGMENT_LIST_SUB_TLV_TYPE_IPv6_ADDRESS_INDEX_SID        SegmentListSubTLVType = 7
	SEGMENT_LIST_SUB_TLV_TYPE_IPv6_LOCAL_REMOTE_ADDRESS_SID SegmentListSubTLVType = 8
	SEGMENT_LIST_SUB_TLV_TYPE_WEIGHT                        SegmentListSubTLVType = 9
)

func decodeSegmentListSubTLVs(data []byte) ([]SegmentListSubTLVInterface, error) {
	tlvs := make([]SegmentListSubTLVInterface, 0)
	for len(data) > 2 {
		typ := SegmentListSubTLVType(data[0])
		length := data[1]
		var tlv SegmentListSubTLVInterface
		switch typ {
		case SEGMENT_LIST_SUB_TLV_TYPE_MPLS_LABEL_SID:
			tlv = &SegmentListSubTLVMPLSLabelSID{}
		case SEGMENT_LIST_SUB_TLV_TYPE_IPv6_ADDRESS_SID:
			tlv = &SegmentListSubTLVIPv6AddressSID{}
		case SEGMENT_LIST_SUB_TLV_TYPE_IPv4_NODE_ADDRESS_SID:
			tlv = &SegmentListSubTLVIPv4NodeAddressSID{}
		case SEGMENT_LIST_SUB_TLV_TYPE_IPv6_NODE_ADDRESS_SID:
			tlv = &SegmentListSubTLVIPv6NodeAddressSID{}
		case SEGMENT_LIST_SUB_TLV_TYPE_IPv4_ADDRESS_INDEX_SID:
			tlv = &SegmentListSubTLVIPv4AddressIndexSID{}
		case SEGMENT_LIST_SUB_TLV_TYPE_IPv4_LOCAL_REMOTE_ADDRESS_SID:
			tlv = &SegmentListSubTLVIPv4LocalRemoteAddressSID{}
		case SEGMENT_LIST_SUB_TLV_TYPE_IPv6_ADDRESS_INDEX_SID:
			tlv = &SegmentListSubTLVIPv6AddressIndexSID{}
		case SEGMENT_LIST_SUB_TLV_TYPE_IPv6_LOCAL_REMOTE_ADDRESS_SID:
			tlv = &SegmentListSubTLVIPv6LocalRemoteAddressSID{}
		case SEGMENT_LIST_SUB_TLV_TYPE_WEIGHT:
			tlv = &SegmentListSubTLVWeight{}
		default:
			tlv = &SegmentListSubTLVUnknown{typ: typ}
		}
		if err := tlv.decodeValue(data[2 : 2+length]); err != nil {
			return nil, err
		}
		tlvs = append(tlvs, tlv)
		data = data[2+length:]
	}
	return tlvs, nil
}

type SegmentListSubTLVUnknown struct {
	typ   SegmentListSubTLVType
	Value []byte
}

func (t *SegmentListSubTLVUnknown) Type() SegmentListSubTLVType {
	return t.typ
}

func (t *SegmentListSubTLVUnknown) decodeValue(data []byte) error {
	t.Value = data
	return nil
}

func (t *SegmentListSubTLVUnknown) serializeValue() ([]byte, error) {
	return t.Value, nil
}

func (t *SegmentListSubTLVUnknown) String() string {
	return fmt.Sprintf("%x", t.Value)
}

func (t *SegmentListSubTLVUnknown) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  SegmentListSubTLVType `json:"type"`
		Value []byte                `json:"value"`
	}{
		Type:  t.Type(),
		Value: t.Value,
	})
}

type SegmentListSubTLVMPLSLabelSID struct {
	Flags uint8
	SID   SegmentID
}

func (t *SegmentListSubTLVMPLSLabelSID) Type() SegmentListSubTLVType {
	return SEGMENT_LIST_SUB_TLV_TYPE_MPLS_LABEL_SID
}

func (t *SegmentListSubTLVMPLSLabelSID) decodeValue(data []byte) error {
	if len(data) < 6 {
		return fmt.Errorf("not all SegmentListSubTLVMPLSLabelSID bytes available")
	}
	t.Flags = data[0]
	t.SID = data[2:6]
	return nil
}

func (t *SegmentListSubTLVMPLSLabelSID) serializeValue() ([]byte, error) {
	buf := make([]byte, 6, 6)
	buf[0] = t.Flags
	if !t.SID.is4Octet() {
		return nil, fmt.Errorf("invalid Segment ID for SegmentListSubTLVMPLSLabelSID: %s", t.SID.String())
	}
	copy(buf[2:6], t.SID)
	return buf, nil
}

func (t *SegmentListSubTLVMPLSLabelSID) String() string {
	return fmt.Sprintf("[SID: %s]", t.SID.String())
}

func (t *SegmentListSubTLVMPLSLabelSID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type SegmentListSubTLVType `json:"type"`
		SID  SegmentID             `json:"sid"`
	}{
		Type: t.Type(),
		SID:  t.SID,
	})
}

type SegmentListSubTLVIPv6AddressSID struct {
	Flags uint8
	SID   SegmentID
}

func (t *SegmentListSubTLVIPv6AddressSID) Type() SegmentListSubTLVType {
	return SEGMENT_LIST_SUB_TLV_TYPE_IPv6_ADDRESS_SID
}

func (t *SegmentListSubTLVIPv6AddressSID) decodeValue(data []byte) error {
	if len(data) < 18 {
		return fmt.Errorf("not all SegmentListSubTLVIPv6AddressSID bytes available")
	}
	t.Flags = data[0]
	t.SID = data[2:18]
	return nil
}

func (t *SegmentListSubTLVIPv6AddressSID) serializeValue() ([]byte, error) {
	buf := make([]byte, 18, 18)
	buf[0] = t.Flags
	if !t.SID.is16Octet() {
		return nil, fmt.Errorf("invalid Segment ID for SegmentListSubTLVIPv6AddressSID: %s", t.SID.String())
	}
	copy(buf[2:18], t.SID)
	return buf, nil
}

func (t *SegmentListSubTLVIPv6AddressSID) String() string {
	return fmt.Sprintf("[SID: %s]", t.SID.String())
}

func (t *SegmentListSubTLVIPv6AddressSID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type SegmentListSubTLVType `json:"type"`
		SID  SegmentID             `json:"sid"`
	}{
		Type: t.Type(),
		SID:  t.SID,
	})
}

type SegmentListSubTLVIPv4NodeAddressSID struct {
	Flags   uint8
	Address net.IP
	SID     SegmentID
}

func (t *SegmentListSubTLVIPv4NodeAddressSID) Type() SegmentListSubTLVType {
	return SEGMENT_LIST_SUB_TLV_TYPE_IPv4_NODE_ADDRESS_SID
}

func (t *SegmentListSubTLVIPv4NodeAddressSID) decodeValue(data []byte) error {
	if len(data) < 6 {
		return fmt.Errorf("not all SegmentListSubTLVIPv4NodeAddressSID bytes available")
	}
	t.Flags = data[0]
	t.Address = data[2:6]
	switch len(data) {
	case 6:
	case 10, 22:
		t.SID = data[6:]
	default:
		return fmt.Errorf("invalid byte length for SegmentListSubTLVIPv4NodeAddressSID")
	}
	return nil
}

func (t *SegmentListSubTLVIPv4NodeAddressSID) serializeValue() ([]byte, error) {
	length := 6 + t.SID.Len()
	switch length {
	case 6, 10, 22:
	default:
		return nil, fmt.Errorf("invalid Segment ID for SegmentListSubTLVIPv4NodeAddressSID: %s", t.SID.String())
	}
	buf := make([]byte, length, length)
	buf[0] = t.Flags
	addr := t.Address.To4()
	if addr == nil {
		return nil, fmt.Errorf("invalid IP Address for SegmentListSubTLVIPv4NodeAddressSID: %s", t.Address)
	}
	copy(buf[2:6], addr)
	copy(buf[6:], t.SID)
	return buf, nil
}

func (t *SegmentListSubTLVIPv4NodeAddressSID) String() string {
	return fmt.Sprintf("[Address: %s SID: %s]", t.Address.String(), t.SID.String())
}

func (t *SegmentListSubTLVIPv4NodeAddressSID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type    SegmentListSubTLVType `json:"type"`
		Flags   uint8                 `json:"flags"`
		Address net.IP                `json:"address"`
		SID     SegmentID             `json:"sid"`
	}{
		Type:    t.Type(),
		Flags:   t.Flags,
		Address: t.Address,
		SID:     t.SID,
	})
}

type SegmentListSubTLVIPv6NodeAddressSID struct {
	Flags   uint8
	Address net.IP
	SID     SegmentID
}

func (t *SegmentListSubTLVIPv6NodeAddressSID) Type() SegmentListSubTLVType {
	return SEGMENT_LIST_SUB_TLV_TYPE_IPv6_NODE_ADDRESS_SID
}

func (t *SegmentListSubTLVIPv6NodeAddressSID) decodeValue(data []byte) error {
	if len(data) < 18 {
		return fmt.Errorf("not all SegmentListSubTLVIPv6NodeAddressSID bytes available")
	}
	t.Flags = data[0]
	t.Address = data[2:18]
	switch len(data) {
	case 18:
	case 22, 34:
		t.SID = data[18:]
	default:
		return fmt.Errorf("invalid byte length for SegmentListSubTLVIPv6NodeAddressSID")
	}
	return nil
}

func (t *SegmentListSubTLVIPv6NodeAddressSID) serializeValue() ([]byte, error) {
	length := 18 + t.SID.Len()
	switch length {
	case 18, 22, 34:
	default:
		return nil, fmt.Errorf("invalid Segment ID for SegmentListSubTLVIPv6NodeAddressSID: %s", t.SID.String())
	}
	buf := make([]byte, length, length)
	buf[0] = t.Flags
	addr := t.Address.To16()
	if addr == nil {
		return nil, fmt.Errorf("invalid IP Address for SegmentListSubTLVIPv6NodeAddressSID: %s", t.Address)
	}
	copy(buf[2:18], addr)
	copy(buf[18:], t.SID)
	return buf, nil
}

func (t *SegmentListSubTLVIPv6NodeAddressSID) String() string {
	return fmt.Sprintf("[Address: %s SID: %s]", t.Address.String(), t.SID.String())
}

func (t *SegmentListSubTLVIPv6NodeAddressSID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type    SegmentListSubTLVType `json:"type"`
		Flags   uint8                 `json:"flags"`
		Address net.IP                `json:"address"`
		SID     SegmentID             `json:"sid"`
	}{
		Type:    t.Type(),
		Flags:   t.Flags,
		Address: t.Address,
		SID:     t.SID,
	})
}

type SegmentListSubTLVIPv4AddressIndexSID struct {
	Flags       uint8
	InterfaceID uint32
	Address     net.IP
	SID         SegmentID
}

func (t *SegmentListSubTLVIPv4AddressIndexSID) Type() SegmentListSubTLVType {
	return SEGMENT_LIST_SUB_TLV_TYPE_IPv4_ADDRESS_INDEX_SID
}

func (t *SegmentListSubTLVIPv4AddressIndexSID) decodeValue(data []byte) error {
	if len(data) < 10 {
		return fmt.Errorf("not all SegmentListSubTLVIPv4AddressIndexSID bytes available")
	}
	t.Flags = data[0]
	t.InterfaceID = binary.BigEndian.Uint32(data[2:6])
	t.Address = data[6:10]
	switch len(data) {
	case 10:
	case 14, 26:
		t.SID = data[10:]
	default:
		return fmt.Errorf("invalid byte length for SegmentListSubTLVIPv4AddressIndexSID")
	}
	return nil
}

func (t *SegmentListSubTLVIPv4AddressIndexSID) serializeValue() ([]byte, error) {
	length := 10 + t.SID.Len()
	switch length {
	case 10, 14, 26:
	default:
		return nil, fmt.Errorf("invalid Segment ID for SegmentListSubTLVIPv4AddressIndexSID: %s", t.SID.String())
	}
	buf := make([]byte, length, length)
	buf[0] = t.Flags
	binary.BigEndian.PutUint32(buf[2:6], t.InterfaceID)
	addr := t.Address.To4()
	if addr == nil {
		return nil, fmt.Errorf("invalid IP Address for SegmentListSubTLVIPv4AddressIndexSID: %s", t.Address)
	}
	copy(buf[6:10], addr)
	copy(buf[10:], t.SID)
	return buf, nil
}

func (t *SegmentListSubTLVIPv4AddressIndexSID) String() string {
	return fmt.Sprintf("[InterfaceID: %d Address: %s SID: %s]", t.InterfaceID, t.Address.String(), t.SID.String())
}

func (t *SegmentListSubTLVIPv4AddressIndexSID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type        SegmentListSubTLVType `json:"type"`
		Flags       uint8                 `json:"flags"`
		InterfaceID uint32                `json:"interface-id"`
		Address     net.IP                `json:"address"`
		SID         SegmentID             `json:"sid"`
	}{
		Type:        t.Type(),
		Flags:       t.Flags,
		InterfaceID: t.InterfaceID,
		Address:     t.Address,
		SID:         t.SID,
	})
}

type SegmentListSubTLVIPv4LocalRemoteAddressSID struct {
	Flags         uint8
	LocalAddress  net.IP
	RemoteAddress net.IP
	SID           SegmentID
}

func (t *SegmentListSubTLVIPv4LocalRemoteAddressSID) Type() SegmentListSubTLVType {
	return SEGMENT_LIST_SUB_TLV_TYPE_IPv4_LOCAL_REMOTE_ADDRESS_SID
}

func (t *SegmentListSubTLVIPv4LocalRemoteAddressSID) decodeValue(data []byte) error {
	if len(data) < 10 {
		return fmt.Errorf("not all SegmentListSubTLVIPv4LocalRemoteAddressSID bytes available")
	}
	t.Flags = data[0]
	t.LocalAddress = data[2:6]
	t.RemoteAddress = data[6:10]
	switch len(data) {
	case 10:
	case 14, 26:
		t.SID = data[10:]
	default:
		return fmt.Errorf("invalid byte length for SegmentListSubTLVIPv4LocalRemoteAddressSID")
	}
	return nil
}

func (t *SegmentListSubTLVIPv4LocalRemoteAddressSID) serializeValue() ([]byte, error) {
	length := 10 + t.SID.Len()
	switch length {
	case 10, 14, 26:
	default:
		return nil, fmt.Errorf("invalid Segment ID for SegmentListSubTLVIPv4LocalRemoteAddressSID: %s", t.SID.String())
	}
	buf := make([]byte, length, length)
	buf[0] = t.Flags
	localAddr := t.LocalAddress.To4()
	if localAddr == nil {
		return nil, fmt.Errorf("invalid Local IP Address for SegmentListSubTLVIPv4LocalRemoteAddressSID: %s", t.LocalAddress)
	}
	copy(buf[2:6], localAddr)
	remoteAddr := t.RemoteAddress.To4()
	if remoteAddr == nil {
		return nil, fmt.Errorf("invalid Remote IP Address for SegmentListSubTLVIPv4LocalRemoteAddressSID: %s", t.RemoteAddress)
	}
	copy(buf[6:10], remoteAddr)
	copy(buf[10:], t.SID)
	return buf, nil
}

func (t *SegmentListSubTLVIPv4LocalRemoteAddressSID) String() string {
	return fmt.Sprintf("[LocalAddress: %s RemoteAddress: %s SID: %s]", t.LocalAddress.String(), t.RemoteAddress.String(), t.SID.String())
}

func (t *SegmentListSubTLVIPv4LocalRemoteAddressSID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type          SegmentListSubTLVType `json:"type"`
		Flags         uint8                 `json:"flags"`
		LocalAddress  net.IP                `json:"local-address"`
		RemoteAddress net.IP                `json:"remote-address"`
		SID           SegmentID             `json:"sid"`
	}{
		Type:          t.Type(),
		Flags:         t.Flags,
		LocalAddress:  t.LocalAddress,
		RemoteAddress: t.RemoteAddress,
		SID:           t.SID,
	})
}

type SegmentListSubTLVIPv6AddressIndexSID struct {
	Flags       uint8
	InterfaceID uint32
	Address     net.IP
	SID         SegmentID
}

func (t *SegmentListSubTLVIPv6AddressIndexSID) Type() SegmentListSubTLVType {
	return SEGMENT_LIST_SUB_TLV_TYPE_IPv6_ADDRESS_INDEX_SID
}

func (t *SegmentListSubTLVIPv6AddressIndexSID) decodeValue(data []byte) error {
	if len(data) < 22 {
		return fmt.Errorf("not all SegmentListSubTLVIPv6AddressIndexSID bytes available")
	}
	t.Flags = data[0]
	t.InterfaceID = binary.BigEndian.Uint32(data[2:6])
	t.Address = data[6:22]
	switch len(data) {
	case 22:
	case 26, 38:
		t.SID = data[22:]
	default:
		return fmt.Errorf("invalid byte length for SegmentListSubTLVIPv6AddressIndexSID")
	}
	return nil
}

func (t *SegmentListSubTLVIPv6AddressIndexSID) serializeValue() ([]byte, error) {
	length := 22 + t.SID.Len()
	switch length {
	case 22, 26, 38:
	default:
		return nil, fmt.Errorf("invalid Segment ID for SegmentListSubTLVIPv6AddressIndexSID: %s", t.SID.String())
	}
	buf := make([]byte, length, length)
	buf[0] = t.Flags
	binary.BigEndian.PutUint32(buf[2:6], t.InterfaceID)
	addr := t.Address.To16()
	if addr == nil {
		return nil, fmt.Errorf("invalid IP Address for SegmentListSubTLVIPv6AddressIndexSID: %s", t.Address)
	}
	copy(buf[6:22], addr)
	copy(buf[22:], t.SID)
	return buf, nil
}

func (t *SegmentListSubTLVIPv6AddressIndexSID) String() string {
	return fmt.Sprintf("[InterfaceID: %d Address: %s SID: %s]", t.InterfaceID, t.Address.String(), t.SID.String())
}

func (t *SegmentListSubTLVIPv6AddressIndexSID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type        SegmentListSubTLVType `json:"type"`
		Flags       uint8                 `json:"flags"`
		InterfaceID uint32                `json:"interface-id"`
		Address     net.IP                `json:"address"`
		SID         SegmentID             `json:"sid"`
	}{
		Type:        t.Type(),
		Flags:       t.Flags,
		InterfaceID: t.InterfaceID,
		Address:     t.Address,
		SID:         t.SID,
	})
}

type SegmentListSubTLVIPv6LocalRemoteAddressSID struct {
	Flags         uint8
	LocalAddress  net.IP
	RemoteAddress net.IP
	SID           SegmentID
}

func (t *SegmentListSubTLVIPv6LocalRemoteAddressSID) Type() SegmentListSubTLVType {
	return SEGMENT_LIST_SUB_TLV_TYPE_IPv6_LOCAL_REMOTE_ADDRESS_SID
}

func (t *SegmentListSubTLVIPv6LocalRemoteAddressSID) decodeValue(data []byte) error {
	if len(data) < 34 {
		return fmt.Errorf("not all SegmentListSubTLVIPv6LocalRemoteAddressSID bytes available")
	}
	t.Flags = data[0]
	t.LocalAddress = data[2:18]
	t.RemoteAddress = data[18:34]
	switch len(data) {
	case 34:
	case 38, 50:
		t.SID = data[34:]
	default:
		return fmt.Errorf("invalid byte length for SegmentListSubTLVIPv6LocalRemoteAddressSID")
	}
	return nil
}

func (t *SegmentListSubTLVIPv6LocalRemoteAddressSID) serializeValue() ([]byte, error) {
	length := 34 + t.SID.Len()
	switch length {
	case 34, 38, 50:
	default:
		return nil, fmt.Errorf("invalid Segment ID for SegmentListSubTLVIPv6LocalRemoteAddressSID: %s", t.SID.String())
	}
	buf := make([]byte, length, length)
	buf[0] = t.Flags
	localAddr := t.LocalAddress.To16()
	if localAddr == nil {
		return nil, fmt.Errorf("invalid Local IP Address for SegmentListSubTLVIPv6LocalRemoteAddressSID: %s", t.LocalAddress)
	}
	copy(buf[2:18], localAddr)
	remoteAddr := t.RemoteAddress.To16()
	if remoteAddr == nil {
		return nil, fmt.Errorf("invalid Remote IP Address for SegmentListSubTLVIPv6LocalRemoteAddressSID: %s", t.RemoteAddress)
	}
	copy(buf[18:34], remoteAddr)
	copy(buf[34:], t.SID)
	return buf, nil
}

func (t *SegmentListSubTLVIPv6LocalRemoteAddressSID) String() string {
	return fmt.Sprintf("[LocalAddress: %s RemoteAddress: %s SID: %s]", t.LocalAddress.String(), t.RemoteAddress.String(), t.SID.String())
}

func (t *SegmentListSubTLVIPv6LocalRemoteAddressSID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type          SegmentListSubTLVType `json:"type"`
		Flags         uint8                 `json:"flags"`
		LocalAddress  net.IP                `json:"local-address"`
		RemoteAddress net.IP                `json:"remote-address"`
		SID           SegmentID             `json:"sid"`
	}{
		Type:          t.Type(),
		Flags:         t.Flags,
		LocalAddress:  t.LocalAddress,
		RemoteAddress: t.RemoteAddress,
		SID:           t.SID,
	})
}

type SegmentListSubTLVWeight struct {
	Flags  uint8
	Weight uint32
}

func (t *SegmentListSubTLVWeight) Type() SegmentListSubTLVType {
	return SEGMENT_LIST_SUB_TLV_TYPE_WEIGHT
}

func (t *SegmentListSubTLVWeight) decodeValue(data []byte) error {
	if len(data) < 6 {
		return fmt.Errorf("not all SegmentListSubTLVWeight bytes available")
	}
	t.Flags = data[0]
	t.Weight = binary.BigEndian.Uint32(data[2:6])
	return nil
}

func (t *SegmentListSubTLVWeight) serializeValue() ([]byte, error) {
	buf := make([]byte, 6, 6)
	buf[0] = t.Flags
	binary.BigEndian.PutUint32(buf[2:6], t.Weight)
	return buf, nil
}

func (t *SegmentListSubTLVWeight) String() string {
	return fmt.Sprintf("[Weight: %d]", t.Weight)
}

func (t *SegmentListSubTLVWeight) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type   SegmentListSubTLVType `json:"type"`
		Flags  uint8                 `json:"flags"`
		Weight uint32                `json:"weight"`
	}{
		Type:   t.Type(),
		Flags:  t.Flags,
		Weight: t.Weight,
	})
}

func ParseSegmentListSubTLV(args []string) (tlvs []SegmentListSubTLVInterface, err error) {
	// Format:
	// args := []string{"weight", "100", "segment", "<TYPE>", "<ARGS>"...}
	pos := 0
	argsLen := len(args)
	parseOptionalSid := func(typ uint64) (sid SegmentID, err error) {
		switch args[pos] {
		case "segment", "weight":
			return nil, nil
		default:
			if args[pos] != "segment" {
				sid, err = ParseSegmentID(args[pos])
				if err != nil {
					return nil, fmt.Errorf("invalid sid for segment type %d: %s", typ, args[pos])
				}
				pos++
			}
			return sid, nil
		}
	}
	for pos < argsLen {
		switch args[pos] {
		case "segment":
			pos++
			typ, err := strconv.ParseUint(args[pos], 10, 8)
			if err != nil {
				return nil, fmt.Errorf("invalid segment type for segment-list: %s", err.Error())
			}
			pos++
			switch SegmentListSubTLVType(typ) {
			case SEGMENT_LIST_SUB_TLV_TYPE_MPLS_LABEL_SID:
				id, err := strconv.ParseUint(args[pos], 10, 32)
				if err != nil {
					return nil, fmt.Errorf("invalid sid for segment type %d: %s", typ, args[pos])
				}
				pos++
				sid := make([]byte, 4, 4)
				binary.BigEndian.PutUint32(sid, uint32(id))
				tlvs = append(tlvs, &SegmentListSubTLVMPLSLabelSID{
					SID: sid,
				})
			case SEGMENT_LIST_SUB_TLV_TYPE_IPv6_ADDRESS_SID:
				sid := net.ParseIP(args[pos])
				if sid.To16() == nil {
					return nil, fmt.Errorf("invalid sid for segment type %d: %s", typ, args[pos])
				}
				pos++
				tlvs = append(tlvs, &SegmentListSubTLVIPv6AddressSID{
					SID: SegmentID(sid),
				})
			case SEGMENT_LIST_SUB_TLV_TYPE_IPv4_NODE_ADDRESS_SID:
				ip := net.ParseIP(args[pos])
				if ip.To4() == nil {
					return nil, fmt.Errorf("invalid ipv4 address for segment type %d: %s", typ, args[pos])
				}
				pos++
				sid, err := parseOptionalSid(typ)
				if err != nil {
					return nil, err
				}
				tlvs = append(tlvs, &SegmentListSubTLVIPv4NodeAddressSID{
					Address: ip,
					SID:     sid,
				})
			case SEGMENT_LIST_SUB_TLV_TYPE_IPv6_NODE_ADDRESS_SID:
				ip := net.ParseIP(args[pos])
				if ip.To16() == nil {
					return nil, fmt.Errorf("invalid ipv6 address for segment type %d: %s", typ, args[pos])
				}
				pos++
				sid, err := parseOptionalSid(typ)
				if err != nil {
					return nil, err
				}
				tlvs = append(tlvs, &SegmentListSubTLVIPv6NodeAddressSID{
					Address: ip,
					SID:     sid,
				})
			case SEGMENT_LIST_SUB_TLV_TYPE_IPv4_ADDRESS_INDEX_SID:
				idx, err := strconv.ParseUint(args[pos], 10, 32)
				if err != nil {
					return nil, fmt.Errorf("invalid interface id for segment type %d: %s", typ, args[pos])
				}
				pos++
				ip := net.ParseIP(args[pos])
				if ip.To4() == nil {
					return nil, fmt.Errorf("invalid ipv4 address for segment type %d: %s", typ, args[pos])
				}
				pos++
				sid, err := parseOptionalSid(typ)
				if err != nil {
					return nil, err
				}
				tlvs = append(tlvs, &SegmentListSubTLVIPv4AddressIndexSID{
					InterfaceID: uint32(idx),
					Address:     ip,
					SID:         sid,
				})
			case SEGMENT_LIST_SUB_TLV_TYPE_IPv4_LOCAL_REMOTE_ADDRESS_SID:
				localIP := net.ParseIP(args[pos])
				if localIP.To4() == nil {
					return nil, fmt.Errorf("invalid local ipv4 address for segment type %d: %s", typ, args[pos])
				}
				pos++
				remoteIP := net.ParseIP(args[pos])
				if remoteIP.To4() == nil {
					return nil, fmt.Errorf("invalid ipv4 address for segment type %d: %s", typ, args[pos])
				}
				pos++
				sid, err := parseOptionalSid(typ)
				if err != nil {
					return nil, err
				}
				tlvs = append(tlvs, &SegmentListSubTLVIPv4LocalRemoteAddressSID{
					LocalAddress:  localIP,
					RemoteAddress: remoteIP,
					SID:           sid,
				})
			case SEGMENT_LIST_SUB_TLV_TYPE_IPv6_ADDRESS_INDEX_SID:
				idx, err := strconv.ParseUint(args[pos], 10, 32)
				if err != nil {
					return nil, fmt.Errorf("invalid interface id for segment type %d: %s", typ, args[pos])
				}
				pos++
				ip := net.ParseIP(args[pos])
				if ip.To16() == nil {
					return nil, fmt.Errorf("invalid ipv6 address for segment type %d: %s", typ, args[pos])
				}
				pos++
				sid, err := parseOptionalSid(typ)
				if err != nil {
					return nil, err
				}
				tlvs = append(tlvs, &SegmentListSubTLVIPv6AddressIndexSID{
					InterfaceID: uint32(idx),
					Address:     ip,
					SID:         sid,
				})
			case SEGMENT_LIST_SUB_TLV_TYPE_IPv6_LOCAL_REMOTE_ADDRESS_SID:
				localIP := net.ParseIP(args[pos])
				if localIP.To16() == nil {
					return nil, fmt.Errorf("invalid local ipv16 address for segment type %d: %s", typ, args[pos])
				}
				pos++
				remoteIP := net.ParseIP(args[pos])
				if remoteIP.To16() == nil {
					return nil, fmt.Errorf("invalid ipv16 address for segment type %d: %s", typ, args[pos])
				}
				pos++
				var sid SegmentID
				sid, err := parseOptionalSid(typ)
				if err != nil {
					return nil, err
				}
				tlvs = append(tlvs, &SegmentListSubTLVIPv6LocalRemoteAddressSID{
					LocalAddress:  localIP,
					RemoteAddress: remoteIP,
					SID:           sid,
				})
			default:
				return nil, fmt.Errorf("unsupported segment type: %d", typ)
			}
		case "weight":
			pos++
			weight, err := strconv.ParseUint(args[pos], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid weight: %s", args[pos])
			}
			pos++
			tlvs = append(tlvs, &SegmentListSubTLVWeight{
				Weight: uint32(weight),
			})
		default:
			return nil, fmt.Errorf("invalid segment-list arguments: %s in %s", args[pos], args)
		}
	}
	return tlvs, nil
}
