package bfd

import (
	"encoding"
	"encoding/binary"
	"errors"
)

type StateType uint8

const (
	StateAdminDown StateType = iota
	StateDown
	StateInit
	StateUp
)

func (s StateType) String() string {
	switch s {
	case StateDown:
		return "Down"
	case StateInit:
		return "Init"
	case StateUp:
		return "Up"
	case StateAdminDown:
		return "Admin Down"
	default:
		return "unknown"
	}
}

const (
	packetSizeMin = 24
)

var (
	ErrInvalidPacketLength = errors.New("invalid packet length")
	ErrInvalidHeader       = errors.New("invalid header")
)

type BFDHeader struct {
	Version               uint8
	State                 StateType
	Poll                  bool
	Final                 bool
	DetectTimeMultiplier  uint8
	MyDiscriminator       uint32
	YourDiscriminator     uint32
	DesiredMinTxInterval  uint32
	RequiredMinRxInterval uint32
}

var (
	_ encoding.BinaryMarshaler   = &BFDHeader{}
	_ encoding.BinaryUnmarshaler = &BFDHeader{}
)

/*
    0               1               2               3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Vers |  Diag   |Sta|P|F|C|A|D|M|  Detect Mult  |    Length     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       My Discriminator                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Your Discriminator                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Desired Min TX Interval                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                   Required Min RX Interval                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 Required Min Echo RX Interval                 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

func byteToBool(b byte) bool {
	return b != 0
}

func boolToByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

func (h *BFDHeader) UnmarshalBinary(buf []byte) error {
	if len(buf) < packetSizeMin {
		return ErrInvalidPacketLength
	}

	if len(buf) != int(buf[3]) {
		return ErrInvalidHeader
	}

	h.Version = buf[0] >> 5
	h.State = StateType(buf[1] >> 6)
	h.Poll = byteToBool(buf[1] >> 5 & 1)
	h.Final = byteToBool(buf[1] >> 4 & 1)
	// ignore other flags

	h.DetectTimeMultiplier = buf[2]

	h.MyDiscriminator = binary.BigEndian.Uint32(buf[4:])
	h.YourDiscriminator = binary.BigEndian.Uint32(buf[8:])
	h.DesiredMinTxInterval = binary.BigEndian.Uint32(buf[12:])
	h.RequiredMinRxInterval = binary.BigEndian.Uint32(buf[16:])
	// ignore other variables

	return nil
}

func (h *BFDHeader) MarshalBinary() ([]byte, error) {
	buf := make([]byte, packetSizeMin)

	buf[0] = h.Version << 5
	buf[1] = byte(h.State)<<6 | boolToByte(h.Poll)<<5 | boolToByte(h.Final)<<4
	buf[2] = h.DetectTimeMultiplier
	buf[3] = byte(packetSizeMin)

	binary.BigEndian.PutUint32(buf[4:], h.MyDiscriminator)
	binary.BigEndian.PutUint32(buf[8:], h.YourDiscriminator)
	binary.BigEndian.PutUint32(buf[12:], h.DesiredMinTxInterval)
	binary.BigEndian.PutUint32(buf[16:], h.RequiredMinRxInterval)

	return buf, nil
}
