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
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

func verify(t *testing.T, m1 *BMPMessage) {
	buf1, _ := m1.Serialize()
	m2, err := ParseBMPMessage(buf1)
	if err != nil {
		t.Error(err)
	}
	buf2, _ := m2.Serialize()

	if reflect.DeepEqual(m1, m2) == true {
		t.Log("OK")
	} else {
		t.Error("Something wrong")
		t.Error(len(buf1), m1, buf1)
		t.Error(len(buf2), m2, buf2)
	}
}

func Test_Initiation(t *testing.T) {
	verify(t, NewBMPInitiation(nil))
	tlv := NewBMPTLV(1, []byte{0x3, 0xb, 0x0, 0x0, 0x0, 0xf, 0x42, 0x40})
	m := NewBMPInitiation([]BMPTLV{*tlv})
	verify(t, m)
}

func Test_PeerUpNotification(t *testing.T) {
	m := bgp.NewTestBGPOpenMessage()
	p0 := NewBMPPeerHeader(0, false, 1000, "10.0.0.1", 70000, "10.0.0.2", 1)
	verify(t, NewBMPPeerUpNotification(*p0, "10.0.0.3", 10, 100, m, m))
	p1 := NewBMPPeerHeader(0, false, 1000, "fe80::6e40:8ff:feab:2c2a", 70000, "10.0.0.2", 1)
	verify(t, NewBMPPeerUpNotification(*p1, "fe80::6e40:8ff:feab:2c2a", 10, 100, m, m))
}

func Test_PeerDownNotification(t *testing.T) {
	p0 := NewBMPPeerHeader(0, false, 1000, "10.0.0.1", 70000, "10.0.0.2", 1)
	verify(t, NewBMPPeerDownNotification(*p0, BMP_PEER_DOWN_REASON_UNKNOWN, nil, []byte{0x3, 0xb}))
	m := bgp.NewBGPNotificationMessage(1, 2, nil)
	verify(t, NewBMPPeerDownNotification(*p0, BMP_PEER_DOWN_REASON_LOCAL_BGP_NOTIFICATION, m, nil))
}

func Test_RouteMonitoring(t *testing.T) {
	m := bgp.NewTestBGPUpdateMessage()
	p0 := NewBMPPeerHeader(0, false, 1000, "fe80::6e40:8ff:feab:2c2a", 70000, "10.0.0.2", 1)
	verify(t, NewBMPRouteMonitoring(*p0, m))
}

func Test_BogusHeader(t *testing.T) {
	h, err := ParseBMPMessage(make([]byte, 10))
	assert.Nil(t, h)
	assert.NotNil(t, err)
}
