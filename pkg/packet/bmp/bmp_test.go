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

package bmp

import (
	"testing"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func verify(t *testing.T, m1 *BMPMessage) {
	buf1, _ := m1.Serialize()
	m2, err := ParseBMPMessage(buf1)
	require.NoError(t, err)

	assert.Equal(t, m1, m2)
}

func Test_Initiation(t *testing.T) {
	verify(t, NewBMPInitiation(nil))
	m := NewBMPInitiation([]BMPInfoTLVInterface{
		NewBMPInfoTLVString(BMP_INIT_TLV_TYPE_STRING, "free-form UTF-8 string"),
		NewBMPInfoTLVUnknown(0xff, []byte{0x01, 0x02, 0x03, 0x04}),
	})
	verify(t, m)
}

func Test_Termination(t *testing.T) {
	verify(t, NewBMPTermination(nil))
	m := NewBMPTermination([]BMPTermTLVInterface{
		NewBMPTermTLVString(BMP_TERM_TLV_TYPE_STRING, "free-form UTF-8 string"),
		NewBMPTermTLV16(BMP_TERM_TLV_TYPE_REASON, BMP_TERM_REASON_ADMIN),
		NewBMPTermTLVUnknown(0xff, []byte{0x01, 0x02, 0x03, 0x04}),
	})
	verify(t, m)
}

func Test_PeerUpNotification(t *testing.T) {
	m := bgp.NewTestBGPOpenMessage()
	p0 := NewBMPPeerHeader(0, 0, 1000, "10.0.0.1", 70000, "10.0.0.2", 1)
	verify(t, NewBMPPeerUpNotification(*p0, "10.0.0.3", 10, 100, m, m))
	p1 := NewBMPPeerHeader(0, 0, 1000, "fe80::6e40:8ff:feab:2c2a", 70000, "10.0.0.2", 1)
	verify(t, NewBMPPeerUpNotification(*p1, "fe80::6e40:8ff:feab:2c2a", 10, 100, m, m))
}

func Test_PeerDownNotification(t *testing.T) {
	p0 := NewBMPPeerHeader(0, 0, 1000, "10.0.0.1", 70000, "10.0.0.2", 1)
	verify(t, NewBMPPeerDownNotification(*p0, BMP_PEER_DOWN_REASON_LOCAL_NO_NOTIFICATION, nil, []byte{0x3, 0xb}))
	m := bgp.NewBGPNotificationMessage(1, 2, nil)
	verify(t, NewBMPPeerDownNotification(*p0, BMP_PEER_DOWN_REASON_LOCAL_BGP_NOTIFICATION, m, nil))
}

func Test_RouteMonitoring(t *testing.T) {
	m := bgp.NewTestBGPUpdateMessage()
	p0 := NewBMPPeerHeader(0, 0, 1000, "fe80::6e40:8ff:feab:2c2a", 70000, "10.0.0.2", 1)
	verify(t, NewBMPRouteMonitoring(*p0, m))
}

func Test_RouteMonitoringAdjRIBOut(t *testing.T) {
	m := bgp.NewTestBGPUpdateMessage()
	p0 := NewBMPPeerHeader(0, 16, 1000, "10.0.0.1", 12345, "10.0.0.2", 1)
	assert.True(t, p0.IsAdjRIBOut())
	verify(t, NewBMPRouteMonitoring(*p0, m))
}

func Test_RouteMonitoringAddPath(t *testing.T) {
	opt := &bgp.MarshallingOption{
		AddPath: map[bgp.RouteFamily]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_BOTH},
	}
	p1 := bgp.NewIPAddrPrefix(24, "10.10.10.0")
	p1.SetPathLocalIdentifier(10)
	p := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(3),
		bgp.NewPathAttributeNextHop("129.1.1.2"),
	}
	m := bgp.NewBGPUpdateMessage([]*bgp.IPAddrPrefix{}, p, []*bgp.IPAddrPrefix{p1})
	p0 := NewBMPPeerHeader(0, 0, 1000, "fe80::6e40:8ff:feab:2c2a", 70000, "10.0.0.2", 1)

	m1 := NewBMPRouteMonitoring(*p0, m)
	buf1, _ := m1.Serialize(opt)
	m2, err := ParseBMPMessageWithOptions(buf1, func(BMPPeerHeader) []*bgp.MarshallingOption {
		return []*bgp.MarshallingOption{opt}
	})
	require.NoError(t, err)

	// We need to fix tha path identifier (local/remote)
	u2 := m2.Body.(*BMPRouteMonitoring).BGPUpdate.Body.(*bgp.BGPUpdate).NLRI[0]
	assert.Equal(t, u2.PathIdentifier(), uint32(10))
	assert.Equal(t, u2.PathLocalIdentifier(), uint32(0))
	u2.SetPathIdentifier(0)
	u2.SetPathLocalIdentifier(10)

	assert.Equal(t, m1, m2)
}

func Test_StatisticsReport(t *testing.T) {
	p0 := NewBMPPeerHeader(0, 0, 1000, "10.0.0.1", 70000, "10.0.0.2", 1)
	s0 := NewBMPStatisticsReport(
		*p0,
		[]BMPStatsTLVInterface{
			NewBMPStatsTLV32(BMP_STAT_TYPE_REJECTED, 100),
			NewBMPStatsTLV64(BMP_STAT_TYPE_ADJ_RIB_IN, 200),
			NewBMPStatsTLVPerAfiSafi64(BMP_STAT_TYPE_PER_AFI_SAFI_LOC_RIB, bgp.AFI_IP, bgp.SAFI_UNICAST, 300),
		},
	)
	verify(t, s0)
}

func Test_StatisticsReportAdjRIBOut(t *testing.T) {
	p0 := NewBMPPeerHeader(0, 8, 1000, "10.0.0.1", 12345, "10.0.0.2", 1)
	s0 := NewBMPStatisticsReport(
		*p0,
		[]BMPStatsTLVInterface{
			NewBMPStatsTLV64(BMP_STAT_TYPE_ADJ_RIB_OUT_POST_POLICY, 200),
			NewBMPStatsTLVPerAfiSafi64(BMP_STAT_TYPE_PER_AFI_SAFI_ADJ_RIB_OUT_POST_POLICY, bgp.AFI_IP, bgp.SAFI_UNICAST, 300),
		},
	)
	verify(t, s0)
}

func Test_RouteMirroring(t *testing.T) {
	p0 := NewBMPPeerHeader(0, 0, 1000, "10.0.0.1", 70000, "10.0.0.2", 1)
	s0 := NewBMPRouteMirroring(
		*p0,
		[]BMPRouteMirrTLVInterface{
			NewBMPRouteMirrTLV16(BMP_ROUTE_MIRRORING_TLV_TYPE_INFO, BMP_ROUTE_MIRRORING_INFO_MSG_LOST),
			NewBMPRouteMirrTLVUnknown(0xff, []byte{0x01, 0x02, 0x03, 0x04}),
			// RFC7854: BGP Message TLV MUST occur last in the list of TLVs
			NewBMPRouteMirrTLVBGPMsg(BMP_ROUTE_MIRRORING_TLV_TYPE_BGP_MSG, bgp.NewTestBGPOpenMessage()),
		},
	)
	verify(t, s0)
}

func Test_BogusHeader(t *testing.T) {
	h, err := ParseBMPMessage(make([]byte, 10))
	assert.Nil(t, h)
	assert.NotNil(t, err)
}

func Test_RouteMonitoringUnknownType(t *testing.T) {
	data := []byte{0x03, 0x00, 0x00, 0x00, 0xe4, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x04, 0x70, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x1b, 0x1b, 0xd8, 0xda, 0xfc, 0xa4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x2b, 0xb5, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x2b, 0xb5, 0x7f, 0xff, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8, 0x80, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xeb, 0x80, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x80, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xeb, 0x80, 0x03, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x80, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x54, 0x80, 0x05, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc8, 0x80, 0x06, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0xa0}
	_, err := ParseBMPMessage(data)
	require.NoError(t, err)
}

func FuzzParseBMPMessage(f *testing.F) {

	f.Fuzz(func(t *testing.T, data []byte) {
		ParseBMPMessage(data)
	})
}
