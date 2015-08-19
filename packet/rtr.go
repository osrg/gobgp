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

package bgp

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	RPKI_DEFAULT_PORT = 323
)

const (
	RTR_SERIAL_NOTIFY = iota
	RTR_SERIAL_QUERY
	RTR_RESET_QUERY
	RTR_CACHE_RESPONSE
	RTR_IPV4_PREFIX
	_
	RTR_IPV6_PREFIX
	RTR_END_OF_DATA
	RTR_CACHE_RESET
	_
	RTR_ERROR_REPORT
)

const (
	RTR_SERIAL_NOTIFY_LEN  = 12
	RTR_SERIAL_QUERY_LEN   = 12
	RTR_RESET_QUERY_LEN    = 8
	RTR_CACHE_RESPONSE_LEN = 8
	RTR_IPV4_PREFIX_LEN    = 20
	RTR_IPV6_PREFIX_LEN    = 32
	RTR_END_OF_DATA_LEN    = 12
	RTR_CACHE_RESET_LEN    = 8
	RTR_MIN_LEN            = 8
)

type RTRMessage interface {
	DecodeFromBytes([]byte) error
	Serialize() ([]byte, error)
}

type RTRCommon struct {
	Version      uint8
	Type         uint8
	SessionID    uint16
	Len          uint32
	SerialNumber uint32
}

func (m *RTRCommon) DecodeFromBytes(data []byte) error {
	m.Version = data[0]
	m.Type = data[1]
	m.SessionID = binary.BigEndian.Uint16(data[2:4])
	m.Len = binary.BigEndian.Uint32(data[4:8])
	m.SerialNumber = binary.BigEndian.Uint32(data[8:12])
	return nil
}

func (m *RTRCommon) Serialize() ([]byte, error) {
	data := make([]byte, m.Len)
	data[0] = m.Version
	data[1] = m.Type
	binary.BigEndian.PutUint16(data[2:4], m.SessionID)
	binary.BigEndian.PutUint32(data[4:8], m.Len)
	binary.BigEndian.PutUint32(data[8:12], m.SerialNumber)
	return data, nil
}

type RTRSerialNotify struct {
	RTRCommon
}

type RTRSerialQuery struct {
	RTRCommon
}

type RTRReset struct {
	Version uint8
	Type    uint8
	Len     uint32
}

func (m *RTRReset) DecodeFromBytes(data []byte) error {
	m.Version = data[0]
	m.Type = data[1]
	m.Len = binary.BigEndian.Uint32(data[4:8])
	return nil
}

func (m *RTRReset) Serialize() ([]byte, error) {
	data := make([]byte, m.Len)
	data[0] = m.Version
	data[1] = m.Type
	binary.BigEndian.PutUint32(data[4:8], m.Len)
	return data, nil
}

type RTRResetQuery struct {
	RTRReset
}

func (m *RTRResetQuery) Serialize() ([]byte, error) {
	data := make([]byte, m.Len)
	data[0] = m.Version
	data[1] = m.Type
	binary.BigEndian.PutUint32(data[4:8], m.Len)
	return data, nil
}

func NewRTRResetQuery() *RTRResetQuery {
	return &RTRResetQuery{
		RTRReset{
			Type: RTR_RESET_QUERY,
			Len:  RTR_RESET_QUERY_LEN,
		},
	}
}

type RTRCacheResponse struct {
	Version   uint8
	Type      uint8
	SessionID uint16
	Len       uint32
}

func (m *RTRCacheResponse) DecodeFromBytes(data []byte) error {
	m.Version = data[0]
	m.Type = data[1]
	m.SessionID = binary.BigEndian.Uint16(data[2:4])
	m.Len = binary.BigEndian.Uint32(data[4:8])
	return nil
}

func (m *RTRCacheResponse) Serialize() ([]byte, error) {
	data := make([]byte, m.Len)
	data[0] = m.Version
	data[1] = m.Type
	binary.BigEndian.PutUint16(data[2:4], m.SessionID)
	binary.BigEndian.PutUint32(data[4:8], m.Len)
	return data, nil
}

type RTRIPPrefix struct {
	Version   uint8
	Type      uint8
	SessionID uint16
	Len       uint32
	Flags     uint8
	PrefixLen uint8
	MaxLen    uint8
	Prefix    net.IP
	AS        uint32
}

func (m *RTRIPPrefix) DecodeFromBytes(data []byte) error {
	m.Version = data[0]
	m.Type = data[1]
	m.SessionID = binary.BigEndian.Uint16(data[2:4])
	m.Len = binary.BigEndian.Uint32(data[4:8])
	m.Flags = data[8]
	m.PrefixLen = data[9]
	m.MaxLen = data[10]
	if m.Type == RTR_IPV4_PREFIX {
		m.Prefix = net.IP(data[12:16]).To4()
		m.AS = binary.BigEndian.Uint32(data[16:20])
	} else {
		m.Prefix = net.IP(data[12:28]).To16()
		m.AS = binary.BigEndian.Uint32(data[28:32])
	}
	return nil
}

func (m *RTRIPPrefix) Serialize() ([]byte, error) {
	data := make([]byte, m.Len)
	data[0] = m.Type
	data[1] = m.Version
	binary.BigEndian.PutUint16(data[2:4], m.SessionID)
	binary.BigEndian.PutUint32(data[4:8], m.Len)
	data[8] = m.Flags
	data[9] = m.PrefixLen
	data[10] = m.MaxLen
	if m.Type == RTR_IPV4_PREFIX {
		copy(data[12:16], m.Prefix.To4())
		binary.BigEndian.PutUint32(data[16:20], m.AS)
	} else {
		copy(data[12:28], m.Prefix.To16())
		binary.BigEndian.PutUint32(data[28:32], m.AS)
	}
	return data, nil
}

type RTREndOfData struct {
	RTRCommon
}

type RTRCacheReset struct {
	RTRReset
}

type RTRErrorReport struct {
	Version   uint8
	Type      uint8
	SessionID uint16
	Len       uint32
	PDULen    uint32
	PDU       []byte
	TextLen   uint32
	Text      []byte
}

func (m *RTRErrorReport) DecodeFromBytes(data []byte) error {
	m.Version = data[0]
	m.Type = data[1]
	m.SessionID = binary.BigEndian.Uint16(data[2:4])
	m.Len = binary.BigEndian.Uint32(data[4:8])
	m.PDULen = binary.BigEndian.Uint32(data[8:12])
	m.PDU = make([]byte, m.PDULen)
	copy(m.PDU, data[12:12+m.PDULen])
	m.TextLen = binary.BigEndian.Uint32(data[12+m.PDULen : 16+m.PDULen])
	m.PDU = make([]byte, m.TextLen)
	copy(m.Text, data[16+m.PDULen:])
	return nil
}

func (m *RTRErrorReport) Serialize() ([]byte, error) {
	data := make([]byte, m.Len)
	data[0] = m.Version
	data[1] = m.Type
	binary.BigEndian.PutUint16(data[2:4], m.SessionID)
	binary.BigEndian.PutUint32(data[4:8], m.Len)
	binary.BigEndian.PutUint32(data[8:12], m.PDULen)
	copy(data[12:], m.PDU)
	binary.BigEndian.PutUint32(data[12+m.PDULen:16+m.PDULen], m.TextLen)
	copy(data[16+m.PDULen:], m.Text)
	return data, nil
}

func SplitRTR(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 || len(data) < RTR_MIN_LEN {
		return 0, nil, nil
	}

	totalLen := binary.BigEndian.Uint32(data[4:8])
	if totalLen < RTR_MIN_LEN {
		return 0, nil, fmt.Errorf("Invalid length: %d", totalLen)
	}
	if uint32(len(data)) < totalLen {
		return 0, nil, nil
	}
	return int(totalLen), data[0:totalLen], nil
}

func ParseRTR(data []byte) (RTRMessage, error) {
	var msg RTRMessage
	switch data[1] {
	case RTR_SERIAL_NOTIFY:
		msg = &RTRSerialNotify{}
	case RTR_SERIAL_QUERY:
		msg = &RTRSerialQuery{}
	case RTR_RESET_QUERY:
		msg = &RTRResetQuery{}
	case RTR_CACHE_RESPONSE:
		msg = &RTRCacheResponse{}
	case RTR_IPV4_PREFIX:
		msg = &RTRIPPrefix{}
	case RTR_IPV6_PREFIX:
		msg = &RTRIPPrefix{}
	case RTR_END_OF_DATA:
		msg = &RTREndOfData{}
	case RTR_CACHE_RESET:
		msg = &RTRCacheReset{}
	case RTR_ERROR_REPORT:
		msg = &RTRErrorReport{}
	default:
		return nil, fmt.Errorf("unknown RTR message type %d:", data[1])
	}
	err := msg.DecodeFromBytes(data)
	return msg, err
}
