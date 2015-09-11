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

package bgp

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
)

type BMPHeader struct {
	Version uint8
	Length  uint32
	Type    uint8
}

const (
	BMP_HEADER_SIZE = 6
)

func (msg *BMPHeader) DecodeFromBytes(data []byte) error {
	msg.Version = data[0]
	if data[0] != 3 {
		return fmt.Errorf("error version")
	}
	msg.Length = binary.BigEndian.Uint32(data[1:5])
	msg.Type = data[5]
	return nil
}

func (msg *BMPHeader) Len() int {
	return int(msg.Length)
}

type BMPPeerHeader struct {
	PeerType          uint8
	IsPostPolicy      bool
	PeerDistinguisher uint64
	PeerAddress       net.IP
	PeerAS            uint32
	PeerBGPID         net.IP
	Timestamp         float64
	flags             uint8
}

func (msg *BMPPeerHeader) DecodeFromBytes(data []byte) error {
	data = data[6:]

	msg.PeerType = data[0]
	flags := data[1]
	msg.flags = flags
	if flags&1<<6 == 1 {
		msg.IsPostPolicy = true
	} else {
		msg.IsPostPolicy = false
	}
	msg.PeerDistinguisher = binary.BigEndian.Uint64(data[2:10])
	if flags&1<<7 == 1 {
		msg.PeerAddress = data[10:26]
	} else {
		msg.PeerAddress = data[10:14]
	}
	msg.PeerAS = binary.BigEndian.Uint32(data[26:30])
	msg.PeerBGPID = data[30:34]

	timestamp1 := binary.BigEndian.Uint32(data[34:38])
	timestamp2 := binary.BigEndian.Uint32(data[38:42])
	msg.Timestamp = float64(timestamp1) + float64(timestamp2)*math.Pow(10, -6)

	return nil
}

type BMPRouteMonitoring struct {
	BGPUpdate *BGPMessage
}

func (body *BMPRouteMonitoring) ParseBody(msg *BMPMessage, data []byte) error {
	update, err := ParseBGPMessage(data)
	if err != nil {
		return err
	}
	body.BGPUpdate = update
	return nil
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
	BGPNotification *BGPMessage
	Data            []byte
}

func (body *BMPPeerDownNotification) ParseBody(msg *BMPMessage, data []byte) error {
	body.Reason = data[0]
	data = data[1:]
	if body.Reason == BMP_PEER_DOWN_REASON_LOCAL_BGP_NOTIFICATION || body.Reason == BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION {
		notification, err := ParseBGPMessage(data)
		if err != nil {
			return err
		}
		body.BGPNotification = notification
	} else {
		body.Data = data
	}
	return nil
}

type BMPPeerUpNotification struct {
	LocalAddress    net.IP
	LocalPort       uint16
	RemotePort      uint16
	SentOpenMsg     *BGPMessage
	ReceivedOpenMsg *BGPMessage
}

func (body *BMPPeerUpNotification) ParseBody(msg *BMPMessage, data []byte) error {
	if msg.PeerHeader.flags&1<<7 == 1 {
		body.LocalAddress = data[:16]
	} else {
		body.LocalAddress = data[:4]
	}

	body.LocalPort = binary.BigEndian.Uint16(data[16:18])
	body.RemotePort = binary.BigEndian.Uint16(data[18:20])

	data = data[20:]
	sentopen, err := ParseBGPMessage(data)
	if err != nil {
		return err
	}
	body.SentOpenMsg = sentopen
	data = data[body.SentOpenMsg.Header.Len:]
	body.ReceivedOpenMsg, err = ParseBGPMessage(data)
	if err != nil {
		return err
	}
	return nil
}

func (body *BMPStatisticsReport) ParseBody(msg *BMPMessage, data []byte) error {
	_ = binary.BigEndian.Uint32(data[0:4])
	data = data[4:]
	for len(data) >= 4 {
		s := BMPStatsTLV{}
		s.Type = binary.BigEndian.Uint16(data[0:2])
		s.Length = binary.BigEndian.Uint16(data[2:4])

		if s.Type == BMP_STAT_TYPE_ADJ_RIB_IN || s.Type == BMP_STAT_TYPE_LOC_RIB {
			s.Value = binary.BigEndian.Uint64(data[4:12])
		} else {
			s.Value = uint64(binary.BigEndian.Uint32(data[4:8]))
		}
		body.Stats = append(body.Stats, s)
		data = data[4+s.Length:]
	}
	return nil
}

type BMPTLV struct {
	Type   uint16
	Length uint16
	Value  []byte
}

type BMPInitiation struct {
	Info []BMPTLV
}

func (body *BMPInitiation) ParseBody(msg *BMPMessage, data []byte) error {
	for len(data) >= 4 {
		tlv := BMPTLV{}
		tlv.Type = binary.BigEndian.Uint16(data[0:2])
		tlv.Length = binary.BigEndian.Uint16(data[2:4])
		tlv.Value = data[4 : 4+tlv.Length]

		body.Info = append(body.Info, tlv)
		data = data[4+tlv.Length:]
	}
	return nil
}

type BMPTermination struct {
	Info []BMPTLV
}

func (body *BMPTermination) ParseBody(msg *BMPMessage, data []byte) error {
	for len(data) >= 4 {
		tlv := BMPTLV{}
		tlv.Type = binary.BigEndian.Uint16(data[0:2])
		tlv.Length = binary.BigEndian.Uint16(data[2:4])
		tlv.Value = data[4 : 4+tlv.Length]

		body.Info = append(body.Info, tlv)
		data = data[4+tlv.Length:]
	}
	return nil
}

type BMPBody interface {
	ParseBody(*BMPMessage, []byte) error
}

type BMPMessage struct {
	Header     BMPHeader
	PeerHeader BMPPeerHeader
	Body       BMPBody
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

// move somewhere else
func ReadBMPMessage(conn net.Conn) (*BMPMessage, error) {
	buf := make([]byte, BMP_HEADER_SIZE)
	for offset := 0; offset < BMP_HEADER_SIZE; {
		rlen, err := conn.Read(buf[offset:])
		if err != nil {
			return nil, err
		}
		offset += rlen
	}

	h := BMPHeader{}
	err := h.DecodeFromBytes(buf)
	if err != nil {
		return nil, err
	}

	data := make([]byte, h.Len())
	copy(data, buf)
	data = data[BMP_HEADER_SIZE:]
	for offset := 0; offset < h.Len()-BMP_HEADER_SIZE; {
		rlen, err := conn.Read(data[offset:])
		if err != nil {
			return nil, err
		}
		offset += rlen
	}
	msg := &BMPMessage{Header: h}

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

	if msg.Header.Type != BMP_MSG_INITIATION && msg.Header.Type != BMP_MSG_INITIATION {
		msg.PeerHeader.DecodeFromBytes(data)
		data = data[42:]
	}

	err = msg.Body.ParseBody(msg, data)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func ParseBMPMessage(data []byte) (*BMPMessage, error) {
	msg := &BMPMessage{}
	msg.Header.DecodeFromBytes(data)
	data = data[6:msg.Header.Length]

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

	if msg.Header.Type != BMP_MSG_INITIATION && msg.Header.Type != BMP_MSG_INITIATION {
		msg.PeerHeader.DecodeFromBytes(data)
		data = data[42:]
	}

	err := msg.Body.ParseBody(msg, data)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

type MessageError struct {
	TypeCode    uint8
	SubTypeCode uint8
	Data        []byte
	Message     string
}

func NewMessageError(typeCode, subTypeCode uint8, data []byte, msg string) error {
	return &MessageError{
		TypeCode:    typeCode,
		SubTypeCode: subTypeCode,
		Data:        data,
		Message:     msg,
	}
}

func (e *MessageError) Error() string {
	return e.Message
}
