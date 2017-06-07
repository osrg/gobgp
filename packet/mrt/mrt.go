// Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
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

package mrt

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/osrg/gobgp/packet/bgp"
	"math"
	"net"
	"time"
)

const (
	MRT_COMMON_HEADER_LEN = 12
)

type MRTType uint16

const (
	NULL         MRTType = 0  // deprecated
	START        MRTType = 1  // deprecated
	DIE          MRTType = 2  // deprecated
	I_AM_DEAD    MRTType = 3  // deprecated
	PEER_DOWN    MRTType = 4  // deprecated
	BGP          MRTType = 5  // deprecated
	RIP          MRTType = 6  // deprecated
	IDRP         MRTType = 7  // deprecated
	RIPNG        MRTType = 8  // deprecated
	BGP4PLUS     MRTType = 9  // deprecated
	BGP4PLUS01   MRTType = 10 // deprecated
	OSPFv2       MRTType = 11
	TABLE_DUMP   MRTType = 12
	TABLE_DUMPv2 MRTType = 13
	BGP4MP       MRTType = 16
	BGP4MP_ET    MRTType = 17
	ISIS         MRTType = 32
	ISIS_ET      MRTType = 33
	OSPFv3       MRTType = 48
	OSPFv3_ET    MRTType = 49
)

type MRTSubTyper interface {
	ToUint16() uint16
}

type MRTSubTypeTableDumpv2 uint16

const (
	PEER_INDEX_TABLE           MRTSubTypeTableDumpv2 = 1
	RIB_IPV4_UNICAST           MRTSubTypeTableDumpv2 = 2
	RIB_IPV4_MULTICAST         MRTSubTypeTableDumpv2 = 3
	RIB_IPV6_UNICAST           MRTSubTypeTableDumpv2 = 4
	RIB_IPV6_MULTICAST         MRTSubTypeTableDumpv2 = 5
	RIB_GENERIC                MRTSubTypeTableDumpv2 = 6
	RIB_IPV4_UNICAST_ADDPATH   MRTSubTypeTableDumpv2 = 8  // RFC8050
	RIB_IPV4_MULTICAST_ADDPATH MRTSubTypeTableDumpv2 = 9  // RFC8050
	RIB_IPV6_UNICAST_ADDPATH   MRTSubTypeTableDumpv2 = 10 // RFC8050
	RIB_IPV6_MULTICAST_ADDPATH MRTSubTypeTableDumpv2 = 11 // RFC8050
	RIB_GENERIC_ADDPATH        MRTSubTypeTableDumpv2 = 12 // RFC8050
)

func (t MRTSubTypeTableDumpv2) ToUint16() uint16 {
	return uint16(t)
}

type MRTSubTypeBGP4MP uint16

const (
	STATE_CHANGE              MRTSubTypeBGP4MP = 0
	MESSAGE                   MRTSubTypeBGP4MP = 1
	MESSAGE_AS4               MRTSubTypeBGP4MP = 4
	STATE_CHANGE_AS4          MRTSubTypeBGP4MP = 5
	MESSAGE_LOCAL             MRTSubTypeBGP4MP = 6
	MESSAGE_AS4_LOCAL         MRTSubTypeBGP4MP = 7
	MESSAGE_ADDPATH           MRTSubTypeBGP4MP = 8  // RFC8050
	MESSAGE_AS4_ADDPATH       MRTSubTypeBGP4MP = 9  // RFC8050
	MESSAGE_LOCAL_ADDPATH     MRTSubTypeBGP4MP = 10 // RFC8050
	MESSAGE_AS4_LOCAL_ADDPATH MRTSubTypeBGP4MP = 11 // RFC8050
)

func (t MRTSubTypeBGP4MP) ToUint16() uint16 {
	return uint16(t)
}

type BGPState uint16

const (
	IDLE        BGPState = 1
	CONNECT     BGPState = 2
	ACTIVE      BGPState = 3
	OPENSENT    BGPState = 4
	OPENCONFIRM BGPState = 5
	ESTABLISHED BGPState = 6
)

func packValues(values []interface{}) ([]byte, error) {
	b := new(bytes.Buffer)
	for _, v := range values {
		err := binary.Write(b, binary.BigEndian, v)
		if err != nil {
			return nil, err
		}
	}
	return b.Bytes(), nil
}

type MRTHeader struct {
	Timestamp uint32
	Type      MRTType
	SubType   uint16
	Len       uint32
}

func (h *MRTHeader) DecodeFromBytes(data []byte) error {
	if len(data) < MRT_COMMON_HEADER_LEN {
		return fmt.Errorf("not all MRTHeader bytes are available. expected: %d, actual: %d", MRT_COMMON_HEADER_LEN, len(data))
	}
	h.Timestamp = binary.BigEndian.Uint32(data[:4])
	h.Type = MRTType(binary.BigEndian.Uint16(data[4:6]))
	h.SubType = binary.BigEndian.Uint16(data[6:8])
	h.Len = binary.BigEndian.Uint32(data[8:12])
	return nil
}

func (h *MRTHeader) Serialize() ([]byte, error) {
	return packValues([]interface{}{h.Timestamp, h.Type, h.SubType, h.Len})
}

func NewMRTHeader(timestamp uint32, t MRTType, subtype MRTSubTyper, l uint32) (*MRTHeader, error) {
	return &MRTHeader{
		Timestamp: timestamp,
		Type:      t,
		SubType:   subtype.ToUint16(),
		Len:       l,
	}, nil
}

func (h *MRTHeader) GetTime() time.Time {
	t := int64(h.Timestamp)
	return time.Unix(t, 0)
}

type MRTMessage struct {
	Header MRTHeader
	Body   Body
}

func (m *MRTMessage) Serialize() ([]byte, error) {
	buf, err := m.Body.Serialize()
	if err != nil {
		return nil, err
	}
	m.Header.Len = uint32(len(buf))
	bbuf, err := m.Header.Serialize()
	if err != nil {
		return nil, err
	}
	return append(bbuf, buf...), nil
}

func NewMRTMessage(timestamp uint32, t MRTType, subtype MRTSubTyper, body Body) (*MRTMessage, error) {
	header, err := NewMRTHeader(timestamp, t, subtype, 0)
	if err != nil {
		return nil, err
	}
	return &MRTMessage{
		Header: *header,
		Body:   body,
	}, nil
}

type Body interface {
	DecodeFromBytes([]byte) error
	Serialize() ([]byte, error)
}

type Peer struct {
	Type      uint8
	BgpId     net.IP
	IpAddress net.IP
	AS        uint32
}

func (p *Peer) DecodeFromBytes(data []byte) ([]byte, error) {
	notAllBytesAvail := fmt.Errorf("not all Peer bytes are available")
	if len(data) < 5 {
		return nil, notAllBytesAvail
	}
	p.Type = uint8(data[0])
	p.BgpId = net.IP(data[1:5])
	data = data[5:]

	if p.Type&1 > 0 {
		if len(data) < 16 {
			return nil, notAllBytesAvail
		}
		p.IpAddress = net.IP(data[:16])
		data = data[16:]
	} else {
		if len(data) < 4 {
			return nil, notAllBytesAvail
		}
		p.IpAddress = net.IP(data[:4])
		data = data[4:]
	}

	if p.Type&(1<<1) > 0 {
		if len(data) < 4 {
			return nil, notAllBytesAvail
		}
		p.AS = binary.BigEndian.Uint32(data[:4])
		data = data[4:]
	} else {
		if len(data) < 2 {
			return nil, notAllBytesAvail
		}
		p.AS = uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}

	return data, nil
}

func (p *Peer) Serialize() ([]byte, error) {
	var err error
	var bbuf []byte
	buf := make([]byte, 5)
	buf[0] = uint8(p.Type)
	copy(buf[1:], p.BgpId.To4())
	if p.Type&1 > 0 {
		buf = append(buf, p.IpAddress.To16()...)
	} else {
		buf = append(buf, p.IpAddress.To4()...)
	}
	if p.Type&(1<<1) > 0 {
		bbuf, err = packValues([]interface{}{p.AS})
	} else {
		if p.AS > uint32(math.MaxUint16) {
			return nil, fmt.Errorf("AS number is beyond 2 octet. %d > %d", p.AS, math.MaxUint16)
		}
		bbuf, err = packValues([]interface{}{uint16(p.AS)})
	}
	if err != nil {
		return nil, err
	}
	return append(buf, bbuf...), nil
}

func NewPeer(bgpid string, ipaddr string, asn uint32, isAS4 bool) *Peer {
	t := 0
	addr := net.ParseIP(ipaddr).To4()
	if addr == nil {
		t |= 1
		addr = net.ParseIP(ipaddr).To16()
	}
	if isAS4 {
		t |= (1 << 1)
	}
	return &Peer{
		Type:      uint8(t),
		BgpId:     net.ParseIP(bgpid).To4(),
		IpAddress: addr,
		AS:        asn,
	}
}

func (p *Peer) String() string {
	return fmt.Sprintf("PEER ENTRY: ID [%s] Addr [%s] AS [%d]", p.BgpId, p.IpAddress, p.AS)
}

type PeerIndexTable struct {
	CollectorBgpId net.IP
	ViewName       string
	Peers          []*Peer
}

func (t *PeerIndexTable) DecodeFromBytes(data []byte) error {
	notAllBytesAvail := fmt.Errorf("not all PeerIndexTable bytes are available")
	if len(data) < 6 {
		return notAllBytesAvail
	}
	t.CollectorBgpId = net.IP(data[:4])
	viewLen := binary.BigEndian.Uint16(data[4:6])
	if len(data) < 6+int(viewLen) {
		return notAllBytesAvail
	}
	t.ViewName = string(data[6 : 6+viewLen])

	data = data[6+viewLen:]

	if len(data) < 2 {
		return notAllBytesAvail
	}
	peerNum := binary.BigEndian.Uint16(data[:2])
	data = data[2:]
	t.Peers = make([]*Peer, 0, peerNum)
	var err error
	for i := 0; i < int(peerNum); i++ {
		p := &Peer{}
		data, err = p.DecodeFromBytes(data)
		if err != nil {
			return err
		}
		t.Peers = append(t.Peers, p)
	}

	return nil
}

func (t *PeerIndexTable) Serialize() ([]byte, error) {
	buf := make([]byte, 8+len(t.ViewName))
	copy(buf, t.CollectorBgpId.To4())
	binary.BigEndian.PutUint16(buf[4:], uint16(len(t.ViewName)))
	copy(buf[6:], t.ViewName)
	binary.BigEndian.PutUint16(buf[6+len(t.ViewName):], uint16(len(t.Peers)))
	for _, peer := range t.Peers {
		bbuf, err := peer.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, bbuf...)
	}
	return buf, nil
}

func NewPeerIndexTable(bgpid string, viewname string, peers []*Peer) *PeerIndexTable {
	return &PeerIndexTable{
		CollectorBgpId: net.ParseIP(bgpid).To4(),
		ViewName:       viewname,
		Peers:          peers,
	}
}

func (t *PeerIndexTable) String() string {
	return fmt.Sprintf("PEER_INDEX_TABLE: CollectorBgpId [%s] ViewName [%s] Peers [%s]", t.CollectorBgpId, t.ViewName, t.Peers)
}

type RibEntry struct {
	PeerIndex      uint16
	OriginatedTime uint32
	PathIdentifier uint32
	PathAttributes []bgp.PathAttributeInterface
	isAddPath      bool
}

func (e *RibEntry) DecodeFromBytes(data []byte) ([]byte, error) {
	notAllBytesAvail := fmt.Errorf("not all RibEntry bytes are available")
	if len(data) < 8 {
		return nil, notAllBytesAvail
	}
	e.PeerIndex = binary.BigEndian.Uint16(data[:2])
	e.OriginatedTime = binary.BigEndian.Uint32(data[2:6])
	if e.isAddPath {
		e.PathIdentifier = binary.BigEndian.Uint32(data[6:10])
		data = data[10:]
	} else {
		data = data[6:]
	}
	totalLen := binary.BigEndian.Uint16(data[:2])
	data = data[2:]
	for attrLen := totalLen; attrLen > 0; {
		p, err := bgp.GetPathAttribute(data)
		if err != nil {
			return nil, err
		}
		err = p.DecodeFromBytes(data)
		if err != nil {
			return nil, err
		}
		attrLen -= uint16(p.Len())
		if len(data) < p.Len() {
			return nil, notAllBytesAvail
		}
		data = data[p.Len():]
		e.PathAttributes = append(e.PathAttributes, p)
	}
	return data, nil
}

func (e *RibEntry) Serialize() ([]byte, error) {
	pbuf := make([]byte, 0)
	totalLen := 0
	for _, pattr := range e.PathAttributes {
		// TODO special modification is needed for MP_REACH_NLRI
		// but also Quagga doesn't implement this.
		//
		// RFC 6396 4.3.4
		// There is one exception to the encoding of BGP attributes for the BGP
		// MP_REACH_NLRI attribute (BGP Type Code 14).
		// Since the AFI, SAFI, and NLRI information is already encoded
		// in the RIB Entry Header or RIB_GENERIC Entry Header,
		// only the Next Hop Address Length and Next Hop Address fields are included.

		pb, err := pattr.Serialize()
		if err != nil {
			return nil, err
		}
		pbuf = append(pbuf, pb...)
		totalLen += len(pb)
	}
	var buf []byte
	if e.isAddPath {
		buf = make([]byte, 12)
		binary.BigEndian.PutUint16(buf, e.PeerIndex)
		binary.BigEndian.PutUint32(buf[2:], e.OriginatedTime)
		binary.BigEndian.PutUint32(buf[6:], e.PathIdentifier)
		binary.BigEndian.PutUint16(buf[10:], uint16(totalLen))
	} else {
		buf = make([]byte, 8)
		binary.BigEndian.PutUint16(buf, e.PeerIndex)
		binary.BigEndian.PutUint32(buf[2:], e.OriginatedTime)
		binary.BigEndian.PutUint16(buf[6:], uint16(totalLen))
	}
	buf = append(buf, pbuf...)
	return buf, nil
}

func NewRibEntry(index uint16, time uint32, pathid uint32, pathattrs []bgp.PathAttributeInterface) *RibEntry {
	return &RibEntry{
		PeerIndex:      index,
		OriginatedTime: time,
		PathIdentifier: pathid,
		PathAttributes: pathattrs,
		isAddPath:      pathid != 0,
	}
}

func (e *RibEntry) String() string {
	if e.isAddPath {
		return fmt.Sprintf("RIB_ENTRY: PeerIndex [%d] OriginatedTime [%d] PathIdentifier[%d] PathAttrs [%v]", e.PeerIndex, e.OriginatedTime, e.PathIdentifier, e.PathAttributes)
	} else {
		return fmt.Sprintf("RIB_ENTRY: PeerIndex [%d] OriginatedTime [%d] PathAttrs [%v]", e.PeerIndex, e.OriginatedTime, e.PathAttributes)
	}

}

type Rib struct {
	SequenceNumber uint32
	Prefix         bgp.AddrPrefixInterface
	Entries        []*RibEntry
	RouteFamily    bgp.RouteFamily
	isAddPath      bool
}

func (u *Rib) DecodeFromBytes(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("Not all RibIpv4Unicast message bytes available")
	}
	u.SequenceNumber = binary.BigEndian.Uint32(data[:4])
	data = data[4:]
	afi, safi := bgp.RouteFamilyToAfiSafi(u.RouteFamily)
	if afi == 0 && safi == 0 {
		afi = binary.BigEndian.Uint16(data[:2])
		safi = data[2]
		data = data[3:]
	}
	prefix, err := bgp.NewPrefixFromRouteFamily(afi, safi)
	if err != nil {
		return err
	}
	err = prefix.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	u.Prefix = prefix
	data = data[prefix.Len():]
	entryNum := binary.BigEndian.Uint16(data[:2])
	data = data[2:]
	u.Entries = make([]*RibEntry, 0, entryNum)
	for i := 0; i < int(entryNum); i++ {
		e := &RibEntry{
			isAddPath: u.isAddPath,
		}
		data, err = e.DecodeFromBytes(data)
		if err != nil {
			return err
		}
		u.Entries = append(u.Entries, e)
	}
	return nil
}

func (u *Rib) Serialize() ([]byte, error) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, u.SequenceNumber)
	rf := bgp.AfiSafiToRouteFamily(u.Prefix.AFI(), u.Prefix.SAFI())
	switch rf {
	case bgp.RF_IPv4_UC, bgp.RF_IPv4_MC, bgp.RF_IPv6_UC, bgp.RF_IPv6_MC:
	default:
		bbuf := make([]byte, 2)
		binary.BigEndian.PutUint16(bbuf, u.Prefix.AFI())
		buf = append(buf, bbuf...)
		buf = append(buf, u.Prefix.SAFI())
	}
	bbuf, err := u.Prefix.Serialize()
	if err != nil {
		return nil, err
	}
	buf = append(buf, bbuf...)
	bbuf, err = packValues([]interface{}{uint16(len(u.Entries))})
	if err != nil {
		return nil, err
	}
	buf = append(buf, bbuf...)
	for _, entry := range u.Entries {
		bbuf, err = entry.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, bbuf...)
	}
	return buf, nil
}

func NewRib(seq uint32, prefix bgp.AddrPrefixInterface, entries []*RibEntry) *Rib {
	rf := bgp.AfiSafiToRouteFamily(prefix.AFI(), prefix.SAFI())
	return &Rib{
		SequenceNumber: seq,
		Prefix:         prefix,
		Entries:        entries,
		RouteFamily:    rf,
		isAddPath:      entries[0].isAddPath,
	}
}

func (u *Rib) String() string {
	return fmt.Sprintf("RIB: Seq [%d] Prefix [%s] Entries [%s]", u.SequenceNumber, u.Prefix, u.Entries)
}

type BGP4MPHeader struct {
	PeerAS         uint32
	LocalAS        uint32
	InterfaceIndex uint16
	AddressFamily  uint16
	PeerIpAddress  net.IP
	LocalIpAddress net.IP
	isAS4          bool
}

func (m *BGP4MPHeader) decodeFromBytes(data []byte) ([]byte, error) {
	if m.isAS4 && len(data) < 8 {
		return nil, fmt.Errorf("Not all BGP4MPMessageAS4 bytes available")
	} else if !m.isAS4 && len(data) < 4 {
		return nil, fmt.Errorf("Not all BGP4MPMessageAS bytes available")
	}

	if m.isAS4 {
		m.PeerAS = binary.BigEndian.Uint32(data[:4])
		m.LocalAS = binary.BigEndian.Uint32(data[4:8])
		data = data[8:]
	} else {
		m.PeerAS = uint32(binary.BigEndian.Uint16(data[:2]))
		m.LocalAS = uint32(binary.BigEndian.Uint16(data[2:4]))
		data = data[4:]
	}
	m.InterfaceIndex = binary.BigEndian.Uint16(data[:2])
	m.AddressFamily = binary.BigEndian.Uint16(data[2:4])
	switch m.AddressFamily {
	case bgp.AFI_IP:
		m.PeerIpAddress = net.IP(data[4:8]).To4()
		m.LocalIpAddress = net.IP(data[8:12]).To4()
		data = data[12:]
	case bgp.AFI_IP6:
		m.PeerIpAddress = net.IP(data[4:20])
		m.LocalIpAddress = net.IP(data[20:36])
		data = data[36:]
	default:
		return nil, fmt.Errorf("unsupported address family: %d", m.AddressFamily)
	}
	return data, nil
}

func (m *BGP4MPHeader) serialize() ([]byte, error) {
	var values []interface{}
	if m.isAS4 {
		values = []interface{}{m.PeerAS, m.LocalAS, m.InterfaceIndex, m.AddressFamily}
	} else {
		values = []interface{}{uint16(m.PeerAS), uint16(m.LocalAS), m.InterfaceIndex, m.AddressFamily}
	}
	buf, err := packValues(values)
	if err != nil {
		return nil, err
	}
	var bbuf []byte
	switch m.AddressFamily {
	case bgp.AFI_IP:
		bbuf = make([]byte, 8)
		copy(bbuf, m.PeerIpAddress.To4())
		copy(bbuf[4:], m.LocalIpAddress.To4())
	case bgp.AFI_IP6:
		bbuf = make([]byte, 32)
		copy(bbuf, m.PeerIpAddress)
		copy(bbuf[16:], m.LocalIpAddress)
	default:
		return nil, fmt.Errorf("unsupported address family: %d", m.AddressFamily)
	}
	return append(buf, bbuf...), nil
}

func newBGP4MPHeader(peeras, localas uint32, intfindex uint16, peerip, localip string, isAS4 bool) (*BGP4MPHeader, error) {
	var af uint16
	paddr := net.ParseIP(peerip).To4()
	laddr := net.ParseIP(localip).To4()
	if paddr != nil && laddr != nil {
		af = bgp.AFI_IP
	} else {
		paddr = net.ParseIP(peerip).To16()
		laddr = net.ParseIP(localip).To16()
		if paddr != nil && laddr != nil {
			af = bgp.AFI_IP6
		} else {
			return nil, fmt.Errorf("Peer IP Address and Local IP Address must have the same address family")
		}
	}
	return &BGP4MPHeader{
		PeerAS:         peeras,
		LocalAS:        localas,
		InterfaceIndex: intfindex,
		AddressFamily:  af,
		PeerIpAddress:  paddr,
		LocalIpAddress: laddr,
		isAS4:          isAS4,
	}, nil
}

type BGP4MPStateChange struct {
	*BGP4MPHeader
	OldState BGPState
	NewState BGPState
}

func (m *BGP4MPStateChange) DecodeFromBytes(data []byte) error {
	rest, err := m.decodeFromBytes(data)
	if err != nil {
		return err
	}
	if len(rest) < 4 {
		return fmt.Errorf("Not all BGP4MPStateChange bytes available")
	}
	m.OldState = BGPState(binary.BigEndian.Uint16(rest[:2]))
	m.NewState = BGPState(binary.BigEndian.Uint16(rest[2:4]))
	return nil
}

func (m *BGP4MPStateChange) Serialize() ([]byte, error) {
	buf, err := m.serialize()
	if err != nil {
		return nil, err
	}
	bbuf, err := packValues([]interface{}{m.OldState, m.NewState})
	if err != nil {
		return nil, err
	}
	return append(buf, bbuf...), nil
}

func NewBGP4MPStateChange(peeras, localas uint32, intfindex uint16, peerip, localip string, isAS4 bool, oldstate, newstate BGPState) *BGP4MPStateChange {
	header, _ := newBGP4MPHeader(peeras, localas, intfindex, peerip, localip, isAS4)
	return &BGP4MPStateChange{
		BGP4MPHeader: header,
		OldState:     oldstate,
		NewState:     newstate,
	}
}

type BGP4MPMessage struct {
	*BGP4MPHeader
	BGPMessage        *bgp.BGPMessage
	BGPMessagePayload []byte
	isLocal           bool
	isAddPath         bool
}

func (m *BGP4MPMessage) DecodeFromBytes(data []byte) error {
	rest, err := m.decodeFromBytes(data)
	if err != nil {
		return err
	}

	if len(rest) < bgp.BGP_HEADER_LENGTH {
		return fmt.Errorf("Not all BGP4MPMessageAS4 bytes available")
	}

	msg, err := bgp.ParseBGPMessage(rest)
	if err != nil {
		return err
	}
	m.BGPMessage = msg
	return nil
}

func (m *BGP4MPMessage) Serialize() ([]byte, error) {
	buf, err := m.serialize()
	if err != nil {
		return nil, err
	}
	if m.BGPMessagePayload != nil {
		return append(buf, m.BGPMessagePayload...), nil
	}
	bbuf, err := m.BGPMessage.Serialize()
	if err != nil {
		return nil, err
	}
	return append(buf, bbuf...), nil
}

func NewBGP4MPMessage(peeras, localas uint32, intfindex uint16, peerip, localip string, isAS4 bool, msg *bgp.BGPMessage) *BGP4MPMessage {
	header, _ := newBGP4MPHeader(peeras, localas, intfindex, peerip, localip, isAS4)
	return &BGP4MPMessage{
		BGP4MPHeader: header,
		BGPMessage:   msg,
	}
}

func NewBGP4MPMessageLocal(peeras, localas uint32, intfindex uint16, peerip, localip string, isAS4 bool, msg *bgp.BGPMessage) *BGP4MPMessage {
	header, _ := newBGP4MPHeader(peeras, localas, intfindex, peerip, localip, isAS4)
	return &BGP4MPMessage{
		BGP4MPHeader: header,
		BGPMessage:   msg,
		isLocal:      true,
	}
}

func NewBGP4MPMessageAddPath(peeras, localas uint32, intfindex uint16, peerip, localip string, isAS4 bool, msg *bgp.BGPMessage) *BGP4MPMessage {
	header, _ := newBGP4MPHeader(peeras, localas, intfindex, peerip, localip, isAS4)
	return &BGP4MPMessage{
		BGP4MPHeader: header,
		BGPMessage:   msg,
		isAddPath:    true,
	}
}

func NewBGP4MPMessageLocalAddPath(peeras, localas uint32, intfindex uint16, peerip, localip string, isAS4 bool, msg *bgp.BGPMessage) *BGP4MPMessage {
	header, _ := newBGP4MPHeader(peeras, localas, intfindex, peerip, localip, isAS4)
	return &BGP4MPMessage{
		BGP4MPHeader: header,
		BGPMessage:   msg,
		isLocal:      true,
		isAddPath:    true,
	}
}

func (m *BGP4MPMessage) String() string {
	title := "BGP4MP_MSG"
	if m.isAS4 {
		title += "_AS4"
	}
	if m.isLocal {
		title += "_LOCAL"
	}
	if m.isAddPath {
		title += "_ADDPATH"
	}
	return fmt.Sprintf("%s: PeerAS [%d] LocalAS [%d] InterfaceIndex [%d] PeerIP [%s] LocalIP [%s] BGPMessage [%v]", title, m.PeerAS, m.LocalAS, m.InterfaceIndex, m.PeerIpAddress, m.LocalIpAddress, m.BGPMessage)
}

//This function can be passed into a bufio.Scanner.Split() to read buffered mrt msgs
func SplitMrt(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if cap(data) < MRT_COMMON_HEADER_LEN { // read more
		return 0, nil, nil
	}
	//this reads the data
	hdr := &MRTHeader{}
	errh := hdr.DecodeFromBytes(data[:MRT_COMMON_HEADER_LEN])
	if errh != nil {
		return 0, nil, errh
	}
	totlen := int(hdr.Len + MRT_COMMON_HEADER_LEN)
	if len(data) < totlen { //need to read more
		return 0, nil, nil
	}
	return totlen, data[0:totlen], nil
}

func ParseMRTBody(h *MRTHeader, data []byte) (*MRTMessage, error) {
	if len(data) < int(h.Len) {
		return nil, fmt.Errorf("Not all MRT message bytes available. expected: %d, actual: %d", int(h.Len), len(data))
	}
	msg := &MRTMessage{Header: *h}
	switch h.Type {
	case TABLE_DUMPv2:
		subType := MRTSubTypeTableDumpv2(h.SubType)
		rf := bgp.RouteFamily(0)
		isAddPath := false
		switch subType {
		case PEER_INDEX_TABLE:
			msg.Body = &PeerIndexTable{}
		case RIB_IPV4_UNICAST:
			rf = bgp.RF_IPv4_UC
		case RIB_IPV4_MULTICAST:
			rf = bgp.RF_IPv4_MC
		case RIB_IPV6_UNICAST:
			rf = bgp.RF_IPv6_UC
		case RIB_IPV6_MULTICAST:
			rf = bgp.RF_IPv6_MC
		case RIB_GENERIC:
		case RIB_IPV4_UNICAST_ADDPATH:
			rf = bgp.RF_IPv4_UC
			isAddPath = true
		case RIB_IPV4_MULTICAST_ADDPATH:
			rf = bgp.RF_IPv4_MC
			isAddPath = true
		case RIB_IPV6_UNICAST_ADDPATH:
			rf = bgp.RF_IPv6_UC
			isAddPath = true
		case RIB_IPV6_MULTICAST_ADDPATH:
			rf = bgp.RF_IPv6_MC
			isAddPath = true
		case RIB_GENERIC_ADDPATH:
			isAddPath = true
		default:
			return nil, fmt.Errorf("unsupported table dumpv2 subtype: %v\n", subType)
		}

		if subType != PEER_INDEX_TABLE {
			msg.Body = &Rib{
				RouteFamily: rf,
				isAddPath:   isAddPath,
			}
		}
	case BGP4MP:
		subType := MRTSubTypeBGP4MP(h.SubType)
		isAS4 := true
		switch subType {
		case STATE_CHANGE:
			isAS4 = false
			fallthrough
		case STATE_CHANGE_AS4:
			msg.Body = &BGP4MPStateChange{
				BGP4MPHeader: &BGP4MPHeader{isAS4: isAS4},
			}
		case MESSAGE:
			isAS4 = false
			fallthrough
		case MESSAGE_AS4:
			msg.Body = &BGP4MPMessage{
				BGP4MPHeader: &BGP4MPHeader{isAS4: isAS4},
			}
		case MESSAGE_LOCAL:
			isAS4 = false
			fallthrough
		case MESSAGE_AS4_LOCAL:
			msg.Body = &BGP4MPMessage{
				BGP4MPHeader: &BGP4MPHeader{isAS4: isAS4},
				isLocal:      true,
			}
		case MESSAGE_ADDPATH:
			isAS4 = false
			fallthrough
		case MESSAGE_AS4_ADDPATH:
			msg.Body = &BGP4MPMessage{
				BGP4MPHeader: &BGP4MPHeader{isAS4: isAS4},
				isAddPath:    true,
			}
		case MESSAGE_LOCAL_ADDPATH:
			isAS4 = false
			fallthrough
		case MESSAGE_AS4_LOCAL_ADDPATH:
			msg.Body = &BGP4MPMessage{
				BGP4MPHeader: &BGP4MPHeader{isAS4: isAS4},
				isLocal:      true,
				isAddPath:    true,
			}
		default:
			return nil, fmt.Errorf("unsupported bgp4mp subtype: %v\n", subType)
		}
	default:
		return nil, fmt.Errorf("unsupported type: %v\n", h.Type)
	}
	err := msg.Body.DecodeFromBytes(data)
	if err != nil {
		return nil, err
	}
	return msg, nil
}
