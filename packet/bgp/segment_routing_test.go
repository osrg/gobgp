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
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test4OctetSegmentID(t *testing.T) {
	assert := assert.New(t)

	bufIn := []byte{
		0x00, 0x06, 0x47, 0x40, // Label=100, TC=3, S=1, TTL=64
	}
	nStr := fmt.Sprint(0x064740)

	// Test parser
	sid, err := ParseSegmentID(nStr)
	assert.Nil(err)

	// Test decoded values
	assert.Equal(4, sid.Len())
	assert.True(sid.is4Octet())
	assert.Equal(uint32(100), sid.Label())
	assert.Equal(uint8(3), sid.TrafficClass())
	assert.True(sid.isBoS())
	assert.Equal(uint8(64), sid.TTL())

	// Test binary and string representation
	assert.Equal(bufIn, []byte(sid))
	assert.Equal(nStr, sid.String())
}

func Test16OctetIPv6SegmentID(t *testing.T) {
	assert := assert.New(t)

	ip := net.ParseIP("2001:db8::1")

	// Test parser
	sid, err := ParseSegmentID(ip.String())
	assert.Nil(err)

	// Test decoded values
	assert.Equal(16, sid.Len())
	assert.True(sid.is16Octet())
	assert.Equal(uint32(0), sid.Label())
	assert.Equal(uint8(0), sid.TrafficClass())
	assert.False(sid.isBoS())
	assert.Equal(uint8(0), sid.TTL())
	assert.Equal("2001:db8::1", sid.String())

	// Test binary and string representation
	assert.Equal([]byte(ip), []byte(sid))
	assert.Equal(ip.String(), sid.String())
}

func TestIPv4SRTEPolicyNLRI(t *testing.T) {
	assert := assert.New(t)

	bufIn := []byte{
		0x60,                   // NLRI Length = 96
		0x11, 0x11, 0x11, 0x11, // Distinguisher
		0x22, 0x22, 0x22, 0x22, // Policy Color
		0xc0, 0xa8, 0x00, 0x01, // Endpoint = "192.168.0.1"
	}

	// Test DecodeFromBytes()
	n := NewIPv4SRTEPolicyNLRI(0, 0, nil)
	err := n.DecodeFromBytes(bufIn)
	assert.Nil(err)

	// Test decoded values
	assert.Equal(uint8(96), n.Length)
	assert.Equal(uint32(0x11111111), n.Distinguisher)
	assert.Equal(uint32(0x22222222), n.Color)
	assert.Equal(net.ParseIP("192.168.0.1").To4(), n.Endpoint)

	// Test String()
	assert.Equal("[distinguisher:286331153][color:572662306][endpoint:192.168.0.1]", n.String())

	// Test Serialize()
	bufOut, err := n.Serialize()
	assert.Nil(err)

	// Test serialized value
	assert.Equal(bufIn, bufOut)
}

func TestIPv6SRTEPolicyNLRI(t *testing.T) {
	assert := assert.New(t)

	bufIn := []byte{
		0xc0,                   // NLRI Length = 192
		0x11, 0x11, 0x11, 0x11, // Distinguisher
		0x22, 0x22, 0x22, 0x22, // Policy Color
		0x20, 0x01, 0x0d, 0xb8, // Endpoint = "2001:db8::1"
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
	}

	// Test DecodeFromBytes()
	n := NewIPv6SRTEPolicyNLRI(0, 0, nil)
	err := n.DecodeFromBytes(bufIn)
	assert.Nil(err)

	// Test decoded values
	assert.Equal(uint8(192), n.Length)
	assert.Equal(uint32(0x11111111), n.Distinguisher)
	assert.Equal(uint32(0x22222222), n.Color)
	assert.Equal(net.ParseIP("2001:db8::1").To16(), n.Endpoint)

	// Test String()
	assert.Equal("[distinguisher:286331153][color:572662306][endpoint:2001:db8::1]", n.String())

	// Test Serialize()
	bufOut, err := n.Serialize()
	assert.Nil(err)
	assert.Equal(bufIn, bufOut)
}

func TestSegmentListSubTLVUnknown(t *testing.T) {
	assert := assert.New(t)

	bufIn := []byte{
		0x00,                   // RESERVED field of TunnelEncapSubTLVSegmentList
		0x00, 0x02, 0xff, 0xff, // Type=0, Length=2
	}

	// Test decoding
	segListTlv := &TunnelEncapSubTLVSegmentList{}
	err := segListTlv.decodeValue(bufIn)
	assert.Nil(err)
	tlvs := segListTlv.Value
	assert.Equal(1, len(tlvs))

	// Test decoded values
	tlv, ok := tlvs[0].(*SegmentListSubTLVUnknown)
	assert.True(ok)
	assert.Equal(SegmentListSubTLVType(0), tlv.Type())
	assert.Equal([]byte{0xff, 0xff}, tlv.Value)

	// Test serializing
	bufOut, err := segListTlv.serializeValue()
	assert.Nil(err)
	assert.Equal(bufIn, bufOut)
}

func TestSegmentListSubTLVMPLSLabelSID(t *testing.T) {
	assert := assert.New(t)

	bufIn := []byte{
		0x00,                   // RESERVED field of TunnelEncapSubTLVSegmentList
		0x01, 0x06, 0x00, 0x00, // Type=1, Length=6
		0x00, 0x06, 0x00, 0xff, // Label=100, TC=0, S=0, TTL=255
	}

	// Test decoding
	segListTlv := &TunnelEncapSubTLVSegmentList{}
	err := segListTlv.decodeValue(bufIn)
	assert.Nil(err)
	tlvs := segListTlv.Value
	assert.Equal(1, len(tlvs))

	// Test decoded values
	tlv, ok := tlvs[0].(*SegmentListSubTLVMPLSLabelSID)
	assert.True(ok)
	assert.Equal(uint8(0), tlv.Flags)
	assert.Equal(fmt.Sprint(0x000600ff), tlv.SID.String())

	// Test serializing
	bufOut, err := segListTlv.serializeValue()
	assert.Nil(err)
	assert.Equal(bufIn, bufOut)
}

func TestSegmentListSubTLVIPv6AddressSID(t *testing.T) {
	assert := assert.New(t)

	bufIn := []byte{
		0x00,                   // RESERVED field of TunnelEncapSubTLVSegmentList
		0x02, 0x12, 0x00, 0x00, // Type=2, Length=18
		0x20, 0x01, 0x0d, 0xb8, // SID="2001:db8::1"
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
	}

	// Test decoding
	segListTlv := &TunnelEncapSubTLVSegmentList{}
	err := segListTlv.decodeValue(bufIn)
	assert.Nil(err)
	tlvs := segListTlv.Value
	assert.Equal(1, len(tlvs))

	// Test decoded values
	tlv, ok := tlvs[0].(*SegmentListSubTLVIPv6AddressSID)
	assert.True(ok)
	assert.Equal(uint8(0), tlv.Flags)
	assert.Equal("2001:db8::1", tlv.SID.String())

	// Test serializing
	bufOut, err := segListTlv.serializeValue()
	assert.Nil(err)
	assert.Equal(bufIn, bufOut)
}

func TestSegmentListSubTLVIPv4NodeAddressSID(t *testing.T) {
	assert := assert.New(t)

	bufIn := []byte{
		0x00, // RESERVED field of TunnelEncapSubTLVSegmentList
		// Without SID
		0x03, 0x06, 0x00, 0x00, // Type=3, Length=6
		0xc0, 0xa8, 0x00, 0x01, // Address="192.168.0.1"
		// With 4-octet SID
		0x03, 0x0a, 0x00, 0x00, // Type=3, Length=10
		0xc0, 0xa8, 0x00, 0x02, // Address="192.168.0.2"
		0x00, 0x06, 0x00, 0xff, // Label=100, TC=0, S=0, TTL=255
		// With 16-octet IPv6 SID
		0x03, 0x16, 0x00, 0x00, // Type=3, Length=22
		0xc0, 0xa8, 0x00, 0x03, // Address="192.168.0.3"
		0x20, 0x01, 0x0d, 0xb8, // SID="2001:db8::1"
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
	}

	// Test decoding
	segListTlv := &TunnelEncapSubTLVSegmentList{}
	err := segListTlv.decodeValue(bufIn)
	assert.Nil(err)
	tlvs := segListTlv.Value
	assert.Equal(3, len(tlvs))

	// Test decoded values
	tlv, ok := tlvs[0].(*SegmentListSubTLVIPv4NodeAddressSID)
	assert.True(ok)
	assert.Equal(uint8(0), tlv.Flags)
	assert.Equal("192.168.0.1", tlv.Address.String())
	assert.Equal("<nil>", tlv.SID.String())
	tlv, ok = tlvs[1].(*SegmentListSubTLVIPv4NodeAddressSID)
	assert.True(ok)
	assert.Equal(uint8(0), tlv.Flags)
	assert.Equal("192.168.0.2", tlv.Address.String())
	assert.Equal(fmt.Sprint(0x000600ff), tlv.SID.String())
	tlv, ok = tlvs[2].(*SegmentListSubTLVIPv4NodeAddressSID)
	assert.True(ok)
	assert.Equal(uint8(0), tlv.Flags)
	assert.Equal("192.168.0.3", tlv.Address.String())
	assert.Equal("2001:db8::1", tlv.SID.String())

	// Test serializing
	bufOut, err := segListTlv.serializeValue()
	assert.Nil(err)
	assert.Equal(bufIn, bufOut)
}

func TestSegmentListSubTLVIPv6NodeAddressSID(t *testing.T) {
	assert := assert.New(t)

	bufIn := []byte{
		0x00, // RESERVED field of TunnelEncapSubTLVSegmentList
		// Without SID
		0x04, 0x12, 0x00, 0x00, // Type=4, Length=18
		0x20, 0x01, 0x0d, 0xb8, // Address="2001:db8::1"
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		// With 4-octet SID
		0x04, 0x16, 0x00, 0x00, // Type=4, Length=22
		0x20, 0x01, 0x0d, 0xb8, // Address="2001:db8::2"
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x02,
		0x00, 0x06, 0x00, 0xff, // Label=100, TC=0, S=0, TTL=255
		// With 16-octet IPv6 SID
		0x04, 0x22, 0x00, 0x00, // Type=4, Length=34
		0x20, 0x01, 0x0d, 0xb8, // Address="2001:db8::3"
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x03,
		0x20, 0x01, 0x0d, 0xb8, // SID="2001:db8::1"
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
	}

	// Test decoding
	segListTlv := &TunnelEncapSubTLVSegmentList{}
	err := segListTlv.decodeValue(bufIn)
	assert.Nil(err)
	tlvs := segListTlv.Value
	assert.Equal(3, len(tlvs))

	// Test decoded values
	tlv, ok := tlvs[0].(*SegmentListSubTLVIPv6NodeAddressSID)
	assert.True(ok)
	assert.Equal(uint8(0), tlv.Flags)
	assert.Equal("2001:db8::1", tlv.Address.String())
	assert.Equal("<nil>", tlv.SID.String())
	tlv, ok = tlvs[1].(*SegmentListSubTLVIPv6NodeAddressSID)
	assert.True(ok)
	assert.Equal(uint8(0), tlv.Flags)
	assert.Equal("2001:db8::2", tlv.Address.String())
	assert.Equal(fmt.Sprint(0x000600ff), tlv.SID.String())
	tlv, ok = tlvs[2].(*SegmentListSubTLVIPv6NodeAddressSID)
	assert.True(ok)
	assert.Equal(uint8(0), tlv.Flags)
	assert.Equal("2001:db8::3", tlv.Address.String())
	assert.Equal("2001:db8::1", tlv.SID.String())

	// Test serializing
	bufOut, err := segListTlv.serializeValue()
	assert.Nil(err)
	assert.Equal(bufIn, bufOut)
}

func TestSegmentListSubTLVIPv4AddressIndexSID(t *testing.T) {
	assert := assert.New(t)

	bufIn := []byte{
		0x00, // RESERVED field of TunnelEncapSubTLVSegmentList
		// Without SID
		0x05, 0x0a, 0x00, 0x00, // Type=5, Length=10
		0x00, 0x00, 0x00, 0x01, // InterfaceID=1
		0xc0, 0xa8, 0x00, 0x01, // Address="192.168.0.1"
		// With 4-octet SID
		0x05, 0x0e, 0x00, 0x00, // Type=5, Length=14
		0x00, 0x00, 0x00, 0x02, // InterfaceID=2
		0xc0, 0xa8, 0x00, 0x02, // Address="192.168.0.2"
		0x00, 0x06, 0x00, 0xff, // Label=100, TC=0, S=0, TTL=255
		// With 16-octet IPv6 SID
		0x05, 0x1a, 0x00, 0x00, // Type=5, Length=26
		0x00, 0x00, 0x00, 0x03, // InterfaceID=3
		0xc0, 0xa8, 0x00, 0x03, // Address="192.168.0.3"
		0x20, 0x01, 0x0d, 0xb8, // SID="2001:db8::1"
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
	}

	// Test decoding
	segListTlv := &TunnelEncapSubTLVSegmentList{}
	err := segListTlv.decodeValue(bufIn)
	assert.Nil(err)
	tlvs := segListTlv.Value
	assert.Equal(3, len(tlvs))

	// Test decoded values
	tlv, ok := tlvs[0].(*SegmentListSubTLVIPv4AddressIndexSID)
	assert.True(ok)
	assert.Equal(uint8(0), tlv.Flags)
	assert.Equal(uint32(1), tlv.InterfaceID)
	assert.Equal("192.168.0.1", tlv.Address.String())
	assert.Equal("<nil>", tlv.SID.String())
	tlv, ok = tlvs[1].(*SegmentListSubTLVIPv4AddressIndexSID)
	assert.True(ok)
	assert.Equal(uint8(0), tlv.Flags)
	assert.Equal(uint32(2), tlv.InterfaceID)
	assert.Equal("192.168.0.2", tlv.Address.String())
	assert.Equal(fmt.Sprint(0x000600ff), tlv.SID.String())
	tlv, ok = tlvs[2].(*SegmentListSubTLVIPv4AddressIndexSID)
	assert.True(ok)
	assert.Equal(uint8(0), tlv.Flags)
	assert.Equal(uint32(3), tlv.InterfaceID)
	assert.Equal("192.168.0.3", tlv.Address.String())
	assert.Equal("2001:db8::1", tlv.SID.String())

	// Test serializing
	bufOut, err := segListTlv.serializeValue()
	assert.Nil(err)
	assert.Equal(bufIn, bufOut)
}

func TestSegmentListSubTLVIPv4LocalRemoteAddressSID(t *testing.T) {
	assert := assert.New(t)

	bufIn := []byte{
		// Without SID
		0x00,                   // RESERVED field of TunnelEncapSubTLVSegmentList
		0x06, 0x0a, 0x00, 0x00, // Type=6, Length=10
		0xc0, 0xa8, 0x01, 0x01, // LocalAddress="192.168.1.1"
		0xc0, 0xa8, 0x00, 0x01, // RemoteAddress="192.168.0.1"
		// With 4-octet SID
		0x06, 0x0e, 0x00, 0x00, // Type=6, Length=14
		0xc0, 0xa8, 0x01, 0x02, // LocalAddress="192.168.1.2"
		0xc0, 0xa8, 0x00, 0x02, // RemoteAddress="192.168.0.2"
		0x00, 0x06, 0x00, 0xff, // Label=100, TC=0, S=0, TTL=255
		// With 16-octet IPv6 SID
		0x06, 0x1a, 0x00, 0x00, // Type=6, Length=26
		0xc0, 0xa8, 0x01, 0x03, // LocalAddress="192.168.1.3"
		0xc0, 0xa8, 0x00, 0x03, // RemoteAddress="192.168.0.3"
		0x20, 0x01, 0x0d, 0xb8, // SID="2001:db8::1"
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
	}

	// Test decoding
	segListTlv := &TunnelEncapSubTLVSegmentList{}
	err := segListTlv.decodeValue(bufIn)
	assert.Nil(err)
	tlvs := segListTlv.Value
	assert.Equal(3, len(tlvs))

	// Test decoded values
	tlv, ok := tlvs[0].(*SegmentListSubTLVIPv4LocalRemoteAddressSID)
	assert.True(ok)
	assert.Equal(uint8(0), tlv.Flags)
	assert.Equal("192.168.1.1", tlv.LocalAddress.String())
	assert.Equal("192.168.0.1", tlv.RemoteAddress.String())
	assert.Equal("<nil>", tlv.SID.String())
	tlv, ok = tlvs[1].(*SegmentListSubTLVIPv4LocalRemoteAddressSID)
	assert.True(ok)
	assert.Equal(uint8(0), tlv.Flags)
	assert.Equal("192.168.1.2", tlv.LocalAddress.String())
	assert.Equal("192.168.0.2", tlv.RemoteAddress.String())
	assert.Equal(fmt.Sprint(0x000600ff), tlv.SID.String())
	tlv, ok = tlvs[2].(*SegmentListSubTLVIPv4LocalRemoteAddressSID)
	assert.True(ok)
	assert.Equal(uint8(0), tlv.Flags)
	assert.Equal("192.168.1.3", tlv.LocalAddress.String())
	assert.Equal("192.168.0.3", tlv.RemoteAddress.String())
	assert.Equal("2001:db8::1", tlv.SID.String())

	// Test serializing
	bufOut, err := segListTlv.serializeValue()
	assert.Nil(err)
	assert.Equal(bufIn, bufOut)
}

func TestSegmentListSubTLVIPv6AddressIndexSID(t *testing.T) {
	assert := assert.New(t)

	bufIn := []byte{
		0x00, // RESERVED field of TunnelEncapSubTLVSegmentList
		// Without SID
		0x07, 0x16, 0x00, 0x00, // Type=7, Length=22
		0x00, 0x00, 0x00, 0x01, // InterfaceID=1
		0x20, 0x01, 0x0d, 0xb8, // Address="2001:db8::1"
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		// With 4-octet SID
		0x07, 0x1a, 0x00, 0x00, // Type=7, Length=26
		0x00, 0x00, 0x00, 0x02, // InterfaceID=2
		0x20, 0x01, 0x0d, 0xb8, // Address="2001:db8::2"
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x02,
		0x00, 0x06, 0x00, 0xff, // Label=100, TC=0, S=0, TTL=255
		// With 16-octet IPv6 SID
		0x07, 0x26, 0x00, 0x00, // Type=7, Length=38
		0x00, 0x00, 0x00, 0x03, // InterfaceID=3
		0x20, 0x01, 0x0d, 0xb8, // Address="2001:db8::3"
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x03,
		0x20, 0x01, 0x0d, 0xb8, // SID="2001:db8::1"
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
	}

	// Test decoding
	segListTlv := &TunnelEncapSubTLVSegmentList{}
	err := segListTlv.decodeValue(bufIn)
	assert.Nil(err)
	tlvs := segListTlv.Value
	assert.Equal(3, len(tlvs))

	// Test decoded values
	tlv, ok := tlvs[0].(*SegmentListSubTLVIPv6AddressIndexSID)
	assert.True(ok)
	assert.Equal(uint8(0), tlv.Flags)
	assert.Equal(uint32(1), tlv.InterfaceID)
	assert.Equal("2001:db8::1", tlv.Address.String())
	assert.Equal("<nil>", tlv.SID.String())
	tlv, ok = tlvs[1].(*SegmentListSubTLVIPv6AddressIndexSID)
	assert.True(ok)
	assert.Equal(uint8(0), tlv.Flags)
	assert.Equal(uint32(2), tlv.InterfaceID)
	assert.Equal("2001:db8::2", tlv.Address.String())
	assert.Equal(fmt.Sprint(0x000600ff), tlv.SID.String())
	tlv, ok = tlvs[2].(*SegmentListSubTLVIPv6AddressIndexSID)
	assert.True(ok)
	assert.Equal(uint8(0), tlv.Flags)
	assert.Equal(uint32(3), tlv.InterfaceID)
	assert.Equal("2001:db8::3", tlv.Address.String())
	assert.Equal("2001:db8::1", tlv.SID.String())

	// Test serializing
	bufOut, err := segListTlv.serializeValue()
	assert.Nil(err)
	assert.Equal(bufIn, bufOut)
}

func TestSegmentListSubTLVIPv6LocalRemoteAddressSID(t *testing.T) {
	assert := assert.New(t)

	bufIn := []byte{
		0x00, // RESERVED field of TunnelEncapSubTLVSegmentList
		// Without SID
		0x08, 0x22, 0x00, 0x00, // Type=8, Length=34
		0x20, 0x01, 0x0d, 0xb8, // LocalAddress="2001:db8:1::1"
		0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		0x20, 0x01, 0x0d, 0xb8, // RemoteAddress="2001:db8:2::1"
		0x00, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		// With 4-octet SID
		0x08, 0x26, 0x00, 0x00, // Type=8, Length=38
		0x20, 0x01, 0x0d, 0xb8, // LocalAddress="2001:db8:1::2"
		0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x02,
		0x20, 0x01, 0x0d, 0xb8, // RemoteAddress="2001:db8:2::2"
		0x00, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x02,
		0x00, 0x06, 0x00, 0xff, // Label=100, TC=0, S=0, TTL=255
		// With 16-octet IPv6 SID
		0x08, 0x32, 0x00, 0x00, // Type=8, Length=50
		0x20, 0x01, 0x0d, 0xb8, // LocalAddress="2001:db8:1::3"
		0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x03,
		0x20, 0x01, 0x0d, 0xb8, // RemoteAddress="2001:db8:2::3"
		0x00, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x03,
		0x20, 0x01, 0x0d, 0xb8, // SID="2001:db8::1"
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
	}

	// Test decoding
	segListTlv := &TunnelEncapSubTLVSegmentList{}
	err := segListTlv.decodeValue(bufIn)
	assert.Nil(err)
	tlvs := segListTlv.Value
	assert.Equal(3, len(tlvs))

	// Test decoded values
	tlv, ok := tlvs[0].(*SegmentListSubTLVIPv6LocalRemoteAddressSID)
	assert.True(ok)
	assert.Equal(uint8(0), tlv.Flags)
	assert.Equal("2001:db8:1::1", tlv.LocalAddress.String())
	assert.Equal("2001:db8:2::1", tlv.RemoteAddress.String())
	assert.Equal("<nil>", tlv.SID.String())
	tlv, ok = tlvs[1].(*SegmentListSubTLVIPv6LocalRemoteAddressSID)
	assert.True(ok)
	assert.Equal(uint8(0), tlv.Flags)
	assert.Equal("2001:db8:1::2", tlv.LocalAddress.String())
	assert.Equal("2001:db8:2::2", tlv.RemoteAddress.String())
	assert.Equal(fmt.Sprint(0x000600ff), tlv.SID.String())
	tlv, ok = tlvs[2].(*SegmentListSubTLVIPv6LocalRemoteAddressSID)
	assert.True(ok)
	assert.Equal(uint8(0), tlv.Flags)
	assert.Equal("2001:db8:1::3", tlv.LocalAddress.String())
	assert.Equal("2001:db8:2::3", tlv.RemoteAddress.String())
	assert.Equal("2001:db8::1", tlv.SID.String())

	// Test serializing
	bufOut, err := segListTlv.serializeValue()
	assert.Nil(err)
	assert.Equal(bufIn, bufOut)
}

func TestSegmentListSubTLVWeight(t *testing.T) {
	assert := assert.New(t)

	bufIn := []byte{
		0x00,                   // RESERVED field of TunnelEncapSubTLVSegmentList
		0x09, 0x06, 0x00, 0x00, // Type=1, Length=6
		0x00, 0x00, 0x00, 0x64, // Weight=100
	}

	// Test decoding
	segListTlv := &TunnelEncapSubTLVSegmentList{}
	err := segListTlv.decodeValue(bufIn)
	assert.Nil(err)
	tlvs := segListTlv.Value
	assert.Equal(1, len(tlvs))

	// Test decoded values
	tlv, ok := tlvs[0].(*SegmentListSubTLVWeight)
	assert.True(ok)
	assert.Equal(uint8(0), tlv.Flags)
	assert.Equal(uint32(100), tlv.Weight)

	// Test serializing
	bufOut, err := segListTlv.serializeValue()
	assert.Nil(err)
	assert.Equal(bufIn, bufOut)
}

func TestParseSegmentListSubTLV(t *testing.T) {
	assert := assert.New(t)

	args := []string{
		"segment", "1", "100",
		"segment", "2", "2001:db8:1::1",
		"segment", "3", "192.168.0.1", "200",
		"segment", "4", "2001:db8:2::1", "300",
		"segment", "5", "1", "192.168.1.1", "400",
		"segment", "6", "192.168.2.1", "192.168.3.1", // <nil>,
		"segment", "7", "2", "2001:db8:3::1", // <nil>
		"segment", "8", "2001:db8:4::1", "2001:db8:5::1", "500",
		"weight", "600",
	}

	// Test parser
	tlvs, err := ParseSegmentListSubTLV(args)
	assert.Nil(err)

	// Test decoded values
	tlv := tlvs[0]
	assert.Equal("[SID: 100]", tlv.String())
	tlv = tlvs[1]
	assert.Equal("[SID: 2001:db8:1::1]", tlv.String())
	tlv = tlvs[2]
	assert.Equal("[Address: 192.168.0.1 SID: 200]", tlv.String())
	tlv = tlvs[3]
	assert.Equal("[Address: 2001:db8:2::1 SID: 300]", tlv.String())
	tlv = tlvs[4]
	assert.Equal("[InterfaceID: 1 Address: 192.168.1.1 SID: 400]", tlv.String())
	tlv = tlvs[5]
	assert.Equal("[LocalAddress: 192.168.2.1 RemoteAddress: 192.168.3.1 SID: <nil>]", tlv.String())
	tlv = tlvs[6]
	assert.Equal("[InterfaceID: 2 Address: 2001:db8:3::1 SID: <nil>]", tlv.String())
	tlv = tlvs[7]
	assert.Equal("[LocalAddress: 2001:db8:4::1 RemoteAddress: 2001:db8:5::1 SID: 500]", tlv.String())
	tlv = tlvs[8]
	assert.Equal("[Weight: 600]", tlv.String())
}
