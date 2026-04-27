package bfd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_MarshalBinary(t *testing.T) {
	assert := assert.New(t)

	target := []byte{
		0x22, 0xc0, 0x08, 0x18,
		0x4f, 0x2f, 0xd5, 0xf2,
		0xd6, 0x7e, 0xae, 0xdf,
		0x00, 0x04, 0x93, 0xe0,
		0x00, 0x0c, 0x35, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}

	packet := &BFDHeader{
		Version:               1,
		Diagnostic:            DiagnosticEchoFunctionFailed,
		State:                 StateUp,
		Poll:                  false,
		Final:                 false,
		DetectTimeMultiplier:  8,
		MyDiscriminator:       0x4f2fd5f2,
		YourDiscriminator:     0xd67eaedf,
		DesiredMinTxInterval:  300000,
		RequiredMinRxInterval: 800000,
	}

	packetBytes, err := packet.MarshalBinary()
	assert.NoError(err)
	assert.Equal(packetBytes, target)
}

func Test_UnmarshalBinary(t *testing.T) {
	assert := assert.New(t)

	packetBytes := []byte{
		0x21, 0xc0, 0x03, 0x18,
		0x12, 0x34, 0x56, 0x78,
		0xab, 0xcd, 0xef, 0x12,
		0x00, 0x01, 0x86, 0xa0,
		0x00, 0x03, 0x0d, 0x40,
		0x00, 0x00, 0x00, 0x00,
	}

	target := &BFDHeader{
		Version:               1,
		Diagnostic:            DiagnosticControlDetectionTimeExpired,
		State:                 StateUp,
		Poll:                  false,
		Final:                 false,
		DetectTimeMultiplier:  3,
		MyDiscriminator:       0x12345678,
		YourDiscriminator:     0xabcdef12,
		DesiredMinTxInterval:  100000,
		RequiredMinRxInterval: 200000,
	}

	packet := &BFDHeader{}
	err := packet.UnmarshalBinary(packetBytes)
	assert.NoError(err)
	assert.Equal(packet, target)
}

func Test_UnmarshalBinaryInvalidPacketLength(t *testing.T) {
	assert := assert.New(t)

	packetBytes := []byte{
		0x20, 0xc0, 0x03, 0x18,
		0x12, 0x34, 0x56, 0x78,
		0xab, 0xcd, 0xef, 0x12,
		0x00, 0x01, 0x86, 0xa0,
		0x00, 0x03, 0x0d, 0x40,
		0x00, 0x00, 0x00,
	}

	packet := &BFDHeader{}
	err := packet.UnmarshalBinary(packetBytes)
	assert.ErrorIs(err, ErrInvalidPacketLength)
}

func Test_UnmarshalBinaryInvalidHeader(t *testing.T) {
	assert := assert.New(t)

	packetBytes := []byte{
		0x20, 0xc0, 0x03, 0x17,
		0x12, 0x34, 0x56, 0x78,
		0xab, 0xcd, 0xef, 0x12,
		0x00, 0x01, 0x86, 0xa0,
		0x00, 0x03, 0x0d, 0x40,
		0x00, 0x00, 0x00, 0x00,
	}

	packet := &BFDHeader{}
	err := packet.UnmarshalBinary(packetBytes)
	assert.ErrorIs(err, ErrInvalidHeader)

	packetBytes = []byte{
		0x20, 0xc0, 0x03, 0x19,
		0x12, 0x34, 0x56, 0x78,
		0xab, 0xcd, 0xef, 0x12,
		0x00, 0x01, 0x86, 0xa0,
		0x00, 0x03, 0x0d, 0x40,
		0x00, 0x00, 0x00, 0x00,
	}

	err = packet.UnmarshalBinary(packetBytes)
	assert.ErrorIs(err, ErrInvalidHeader)
}

func Test_DiagnosticEncodeDecode(t *testing.T) {
	assert := assert.New(t)

	packet := &BFDHeader{
		Version:               1,
		Diagnostic:            DiagnosticReservedStart,
		State:                 StateUp,
		Poll:                  false,
		Final:                 false,
		DetectTimeMultiplier:  3,
		MyDiscriminator:       0x12345678,
		YourDiscriminator:     0xabcdef12,
		DesiredMinTxInterval:  100000,
		RequiredMinRxInterval: 200000,
	}

	b, err := packet.MarshalBinary()
	assert.NoError(err)
	assert.Equal(0x20|byte(DiagnosticReservedStart), b[0])

	decoded := &BFDHeader{}
	err = decoded.UnmarshalBinary(b)
	assert.NoError(err)
	assert.Equal(DiagnosticReservedStart, decoded.Diagnostic)
}

func Test_MarshalBinaryInvalidDiagnostic(t *testing.T) {
	assert := assert.New(t)

	packet := &BFDHeader{
		Version:               1,
		Diagnostic:            DiagnosticType(32),
		State:                 StateUp,
		DetectTimeMultiplier:  3,
		MyDiscriminator:       0x12345678,
		YourDiscriminator:     0xabcdef12,
		DesiredMinTxInterval:  100000,
		RequiredMinRxInterval: 200000,
	}

	_, err := packet.MarshalBinary()
	assert.ErrorIs(err, ErrInvalidDiagnostic)
}
