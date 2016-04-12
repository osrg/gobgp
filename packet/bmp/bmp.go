// Copyright (C) 2014,2015 Nippon Telegraph and Telephone Corporation.
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

package bmp

import (
	"encoding/binary"
	"fmt"
	"github.com/osrg/gobgp/packet/bgp"
	"math"
	"net"
)

type BMPHeader struct {
	Version uint8
	Length  uint32
	Type    uint8
}

const (
	BMP_VERSION          = 3
	BMP_HEADER_SIZE      = 6
	BMP_PEER_HEADER_SIZE = 42
)

const (
	BMP_DEFAULT_PORT = 11019
)

const (
	BMP_PEER_TYPE_GLOBAL uint8 = iota
	BMP_PEER_TYPE_L3VPN
)

func (h *BMPHeader) DecodeFromBytes(data []byte) error {
	h.Version = data[0]
	if data[0] != BMP_VERSION {
		return fmt.Errorf("error version")
	}
	h.Length = binary.BigEndian.Uint32(data[1:5])
	h.Type = data[5]
	return nil
}

func (h *BMPHeader) Serialize() ([]byte, error) {
	buf := make([]byte, BMP_HEADER_SIZE)
	buf[0] = h.Version
	binary.BigEndian.PutUint32(buf[1:], h.Length)
	buf[5] = h.Type
	return buf, nil
}

type BMPPeerHeader struct {
	PeerType          uint8
	IsPostPolicy      bool
	PeerDistinguisher uint64
	PeerAddress       net.IP
	PeerAS            uint32
	PeerBGPID         net.IP
	Timestamp         float64
	Flags             uint8
}

func NewBMPPeerHeader(t uint8, policy bool, dist uint64, address string, as uint32, id string, stamp float64) *BMPPeerHeader {
	h := &BMPPeerHeader{
		PeerType:          t,
		IsPostPolicy:      policy,
		PeerDistinguisher: dist,
		PeerAS:            as,
		PeerBGPID:         net.ParseIP(id).To4(),
		Timestamp:         stamp,
	}
	if policy == true {
		h.Flags |= (1 << 6)
	}
	if net.ParseIP(address).To4() != nil {
		h.PeerAddress = net.ParseIP(address).To4()
	} else {
		h.PeerAddress = net.ParseIP(address).To16()
		h.Flags |= (1 << 7)
	}
	return h
}

func (h *BMPPeerHeader) DecodeFromBytes(data []byte) error {
	h.PeerType = data[0]
	h.Flags = data[1]
	if h.Flags&(1<<6) != 0 {
		h.IsPostPolicy = true
	} else {
		h.IsPostPolicy = false
	}
	h.PeerDistinguisher = binary.BigEndian.Uint64(data[2:10])
	if h.Flags&(1<<7) != 0 {
		h.PeerAddress = net.IP(data[10:26]).To16()
	} else {
		h.PeerAddress = net.IP(data[22:26]).To4()
	}
	h.PeerAS = binary.BigEndian.Uint32(data[26:30])
	h.PeerBGPID = data[30:34]

	timestamp1 := binary.BigEndian.Uint32(data[34:38])
	timestamp2 := binary.BigEndian.Uint32(data[38:42])
	h.Timestamp = float64(timestamp1) + float64(timestamp2)*math.Pow10(-6)
	return nil
}

func (h *BMPPeerHeader) Serialize() ([]byte, error) {
	buf := make([]byte, BMP_PEER_HEADER_SIZE)
	buf[0] = h.PeerType
	buf[1] = h.Flags
	binary.BigEndian.PutUint64(buf[2:10], h.PeerDistinguisher)
	if h.Flags&(1<<7) != 0 {
		copy(buf[10:26], h.PeerAddress)
	} else {
		copy(buf[22:26], h.PeerAddress.To4())
	}
	binary.BigEndian.PutUint32(buf[26:30], h.PeerAS)
	copy(buf[30:34], h.PeerBGPID)
	t1, t2 := math.Modf(h.Timestamp)
	t2 = math.Ceil(t2 * math.Pow10(6))
	binary.BigEndian.PutUint32(buf[34:38], uint32(t1))
	binary.BigEndian.PutUint32(buf[38:42], uint32(t2))
	return buf, nil
}

type BMPRouteMonitoring struct {
	BGPUpdate        *bgp.BGPMessage
	BGPUpdatePayload []byte
}

func NewBMPRouteMonitoring(p BMPPeerHeader, update *bgp.BGPMessage) *BMPMessage {
	return &BMPMessage{
		Header: BMPHeader{
			Version: BMP_VERSION,
			Type:    BMP_MSG_ROUTE_MONITORING,
		},
		PeerHeader: p,
		Body: &BMPRouteMonitoring{
			BGPUpdate: update,
		},
	}
}

func (body *BMPRouteMonitoring) ParseBody(msg *BMPMessage, data []byte) error {
	update, err := bgp.ParseBGPMessage(data)
	if err != nil {
		return err
	}
	body.BGPUpdate = update
	return nil
}

func (body *BMPRouteMonitoring) Serialize() ([]byte, error) {
	if body.BGPUpdatePayload != nil {
		return body.BGPUpdatePayload, nil
	}
	return body.BGPUpdate.Serialize()
}

const (
	BMP_STAT_TYPE_REJECTED = iota
	BMP_STAT_TYPE_DUPLICATE_PREFIX
	BMP_STAT_TYPE_DUPLICATE_WITHDRAW
	BMP_STAT_TYPE_INV_UPDATE_DUE_TO_CLUSTER_LIST_LOOP
	BMP_STAT_TYPE_INV_UPDATE_DUE_TO_AS_PATH_LOOP
	BMP_STAT_TYPE_INV_UPDATE_DUE_TO_ORIGINATOR_ID
	BMP_STAT_TYPE_INV_UPDATE_DUE_TO_AS_CONFED_LOOP
	BMP_STAT_TYPE_ADJ_RIB_IN
	BMP_STAT_TYPE_LOC_RIB
)

type BMPStatsTLV struct {
	Type   uint16
	Length uint16
	Value  uint64
}

type BMPStatisticsReport struct {
	Count uint32
	Stats []BMPStatsTLV
}

const (
	BMP_PEER_DOWN_REASON_UNKNOWN = iota
	BMP_PEER_DOWN_REASON_LOCAL_BGP_NOTIFICATION
	BMP_PEER_DOWN_REASON_LOCAL_NO_NOTIFICATION
	BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION
	BMP_PEER_DOWN_REASON_REMOTE_NO_NOTIFICATION
)

type BMPPeerDownNotification struct {
	Reason          uint8
	BGPNotification *bgp.BGPMessage
	Data            []byte
}

func NewBMPPeerDownNotification(p BMPPeerHeader, reason uint8, notification *bgp.BGPMessage, data []byte) *BMPMessage {
	b := &BMPPeerDownNotification{
		Reason: reason,
	}
	switch reason {
	case BMP_PEER_DOWN_REASON_LOCAL_BGP_NOTIFICATION, BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION:
		b.BGPNotification = notification
	default:
		b.Data = data
	}
	return &BMPMessage{
		Header: BMPHeader{
			Version: BMP_VERSION,
			Type:    BMP_MSG_PEER_DOWN_NOTIFICATION,
		},
		PeerHeader: p,
		Body:       b,
	}
}

func (body *BMPPeerDownNotification) ParseBody(msg *BMPMessage, data []byte) error {
	body.Reason = data[0]
	data = data[1:]
	if body.Reason == BMP_PEER_DOWN_REASON_LOCAL_BGP_NOTIFICATION || body.Reason == BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION {
		notification, err := bgp.ParseBGPMessage(data)
		if err != nil {
			return err
		}
		body.BGPNotification = notification
	} else {
		body.Data = data
	}
	return nil
}

func (body *BMPPeerDownNotification) Serialize() ([]byte, error) {
	buf := make([]byte, 1)
	buf[0] = body.Reason
	switch body.Reason {
	case BMP_PEER_DOWN_REASON_LOCAL_BGP_NOTIFICATION, BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION:
		if body.BGPNotification != nil {
			b, err := body.BGPNotification.Serialize()
			if err != nil {
				return nil, err
			} else {
				buf = append(buf, b...)
			}
		}
	default:
		if body.Data != nil {
			buf = append(buf, body.Data...)
		}
	}
	return buf, nil
}

type BMPPeerUpNotification struct {
	LocalAddress    net.IP
	LocalPort       uint16
	RemotePort      uint16
	SentOpenMsg     *bgp.BGPMessage
	ReceivedOpenMsg *bgp.BGPMessage
}

func NewBMPPeerUpNotification(p BMPPeerHeader, lAddr string, lPort, rPort uint16, sent, recv *bgp.BGPMessage) *BMPMessage {
	b := &BMPPeerUpNotification{
		LocalPort:       lPort,
		RemotePort:      rPort,
		SentOpenMsg:     sent,
		ReceivedOpenMsg: recv,
	}
	addr := net.ParseIP(lAddr)
	if addr.To4() != nil {
		b.LocalAddress = addr.To4()
	} else {
		b.LocalAddress = addr.To16()
	}
	return &BMPMessage{
		Header: BMPHeader{
			Version: BMP_VERSION,
			Type:    BMP_MSG_PEER_UP_NOTIFICATION,
		},
		PeerHeader: p,
		Body:       b,
	}
}

func (body *BMPPeerUpNotification) ParseBody(msg *BMPMessage, data []byte) error {
	if msg.PeerHeader.Flags&(1<<7) != 0 {
		body.LocalAddress = net.IP(data[:16]).To16()
	} else {
		body.LocalAddress = net.IP(data[12:16]).To4()
	}

	body.LocalPort = binary.BigEndian.Uint16(data[16:18])
	body.RemotePort = binary.BigEndian.Uint16(data[18:20])

	data = data[20:]
	sentopen, err := bgp.ParseBGPMessage(data)
	if err != nil {
		return err
	}
	body.SentOpenMsg = sentopen
	data = data[body.SentOpenMsg.Header.Len:]
	body.ReceivedOpenMsg, err = bgp.ParseBGPMessage(data)
	if err != nil {
		return err
	}
	return nil
}

func (body *BMPPeerUpNotification) Serialize() ([]byte, error) {
	buf := make([]byte, 20)
	if body.LocalAddress.To4() != nil {
		copy(buf[12:16], body.LocalAddress.To4())
	} else {
		copy(buf[:16], body.LocalAddress.To16())
	}

	binary.BigEndian.PutUint16(buf[16:18], body.LocalPort)
	binary.BigEndian.PutUint16(buf[18:20], body.RemotePort)

	m, _ := body.SentOpenMsg.Serialize()
	buf = append(buf, m...)
	m, _ = body.ReceivedOpenMsg.Serialize()
	buf = append(buf, m...)
	return buf, nil
}

func (body *BMPStatisticsReport) ParseBody(msg *BMPMessage, data []byte) error {
	body.Count = binary.BigEndian.Uint32(data[0:4])
	data = data[4:]
	for len(data) >= 4 {
		s := BMPStatsTLV{}
		s.Type = binary.BigEndian.Uint16(data[0:2])
		s.Length = binary.BigEndian.Uint16(data[2:4])
		data = data[4:]
		if len(data) < int(s.Length) {
			break
		}
		if s.Type == BMP_STAT_TYPE_ADJ_RIB_IN || s.Type == BMP_STAT_TYPE_LOC_RIB {
			if s.Length < 8 {
				break
			}
			s.Value = binary.BigEndian.Uint64(data[:8])
		} else {
			if s.Length < 4 {
				break
			}
			s.Value = uint64(binary.BigEndian.Uint32(data[:4]))
		}
		body.Stats = append(body.Stats, s)
		data = data[s.Length:]
	}
	return nil
}

func (body *BMPStatisticsReport) Serialize() ([]byte, error) {
	// TODO
	buf := make([]byte, 4)
	body.Count = uint32(len(body.Stats))
	binary.BigEndian.PutUint32(buf[0:4], body.Count)

	return buf, nil
}

type BMPTLV struct {
	Type   uint16
	Length uint16
	Value  []byte
}

func NewBMPTLV(t uint16, v []byte) *BMPTLV {
	return &BMPTLV{
		Type:   t,
		Length: uint16(len(v)),
		Value:  v,
	}
}

func (tlv *BMPTLV) DecodeFromBytes(data []byte) error {
	//TODO: check data length
	tlv.Type = binary.BigEndian.Uint16(data[0:2])
	tlv.Length = binary.BigEndian.Uint16(data[2:4])
	tlv.Value = data[4 : 4+tlv.Length]
	return nil
}

func (tlv *BMPTLV) Serialize() ([]byte, error) {
	if tlv.Length == 0 {
		tlv.Length = uint16(len(tlv.Value))
	}
	buf := make([]byte, 4+tlv.Length)
	binary.BigEndian.PutUint16(buf[0:2], tlv.Type)
	binary.BigEndian.PutUint16(buf[2:4], tlv.Length)
	copy(buf[4:], tlv.Value)
	return buf, nil
}

func (tlv *BMPTLV) Len() int {
	return 4 + int(tlv.Length)
}

type BMPInitiation struct {
	Info []BMPTLV
}

func NewBMPInitiation(info []BMPTLV) *BMPMessage {
	return &BMPMessage{
		Header: BMPHeader{
			Version: BMP_VERSION,
			Type:    BMP_MSG_INITIATION,
		},
		Body: &BMPInitiation{
			Info: info,
		},
	}
}

func (body *BMPInitiation) ParseBody(msg *BMPMessage, data []byte) error {
	for len(data) > 0 {
		tlv := BMPTLV{}
		tlv.DecodeFromBytes(data)
		body.Info = append(body.Info, tlv)
		data = data[tlv.Len():]
	}
	return nil
}

func (body *BMPInitiation) Serialize() ([]byte, error) {
	buf := make([]byte, 0)
	for _, tlv := range body.Info {
		b, err := tlv.Serialize()
		if err != nil {
			return buf, err
		}
		buf = append(buf, b...)
	}
	return buf, nil
}

type BMPTermination struct {
	Info []BMPTLV
}

func NewBMPTermination(info []BMPTLV) *BMPMessage {
	return &BMPMessage{
		Header: BMPHeader{
			Version: BMP_VERSION,
			Type:    BMP_MSG_TERMINATION,
		},
		Body: &BMPTermination{
			Info: info,
		},
	}
}

func (body *BMPTermination) ParseBody(msg *BMPMessage, data []byte) error {
	for len(data) > 0 {
		tlv := BMPTLV{}
		tlv.DecodeFromBytes(data)
		body.Info = append(body.Info, tlv)
		data = data[tlv.Len():]
	}
	return nil
}

func (body *BMPTermination) Serialize() ([]byte, error) {
	buf := make([]byte, 0)
	for _, tlv := range body.Info {
		b, err := tlv.Serialize()
		if err != nil {
			return buf, err
		}
		buf = append(buf, b...)
	}
	return buf, nil
}

type BMPBody interface {
	// Sigh, some body messages need a BMPHeader to parse the body
	// data so we need to pass BMPHeader (avoid DecodeFromBytes
	// function name).
	ParseBody(*BMPMessage, []byte) error
	Serialize() ([]byte, error)
}

type BMPMessage struct {
	Header     BMPHeader
	PeerHeader BMPPeerHeader
	Body       BMPBody
}

func (msg *BMPMessage) Serialize() ([]byte, error) {
	buf := make([]byte, 0)
	if msg.Header.Type != BMP_MSG_INITIATION {
		p, err := msg.PeerHeader.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, p...)
	}

	b, err := msg.Body.Serialize()
	if err != nil {
		return nil, err
	}
	buf = append(buf, b...)

	if msg.Header.Length == 0 {
		msg.Header.Length = uint32(BMP_HEADER_SIZE + len(buf))
	}

	h, err := msg.Header.Serialize()
	if err != nil {
		return nil, err
	}
	return append(h, buf...), nil
}

func (msg *BMPMessage) Len() int {
	return int(msg.Header.Length)
}

const (
	BMP_MSG_ROUTE_MONITORING = iota
	BMP_MSG_STATISTICS_REPORT
	BMP_MSG_PEER_DOWN_NOTIFICATION
	BMP_MSG_PEER_UP_NOTIFICATION
	BMP_MSG_INITIATION
	BMP_MSG_TERMINATION
)

func ParseBMPMessage(data []byte) (*BMPMessage, error) {
	msg := &BMPMessage{}
	err := msg.Header.DecodeFromBytes(data)
	if err != nil {
		return nil, err
	}
	data = data[BMP_HEADER_SIZE:msg.Header.Length]

	switch msg.Header.Type {
	case BMP_MSG_ROUTE_MONITORING:
		msg.Body = &BMPRouteMonitoring{}
	case BMP_MSG_STATISTICS_REPORT:
		msg.Body = &BMPStatisticsReport{}
	case BMP_MSG_PEER_DOWN_NOTIFICATION:
		msg.Body = &BMPPeerDownNotification{}
	case BMP_MSG_PEER_UP_NOTIFICATION:
		msg.Body = &BMPPeerUpNotification{}
	case BMP_MSG_INITIATION:
		msg.Body = &BMPInitiation{}
	case BMP_MSG_TERMINATION:
		msg.Body = &BMPTermination{}
	}

	if msg.Header.Type != BMP_MSG_INITIATION {
		msg.PeerHeader.DecodeFromBytes(data)
		data = data[BMP_PEER_HEADER_SIZE:]
	}

	err = msg.Body.ParseBody(msg, data)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func SplitBMP(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 || len(data) < BMP_HEADER_SIZE {
		return 0, nil, nil
	}

	msg := &BMPMessage{}
	msg.Header.DecodeFromBytes(data)
	if uint32(len(data)) < msg.Header.Length {
		return 0, nil, nil
	}

	return int(msg.Header.Length), data[0:msg.Header.Length], nil
}
