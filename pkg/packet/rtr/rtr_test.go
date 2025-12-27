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

package rtr

import (
	"encoding/hex"
	"math/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func verifyRTRMessage(t *testing.T, m1 RTRMessage) {
	buf1, _ := m1.Serialize()
	m2, err := ParseRTR(buf1)
	require.NoError(t, err)

	buf2, err := m2.Serialize()
	require.NoError(t, err)

	assert.Equal(t, buf1, buf2, "buf1: %v buf2: %v", hex.EncodeToString(buf1), hex.EncodeToString(buf2))
}

func randUint32() uint32 {
	return rand.Uint32()
}

func Test_RTRSerialNotify(t *testing.T) {
	id := uint16(time.Now().Unix())
	sn := randUint32()
	verifyRTRMessage(t, NewRTRSerialNotify(id, sn))
}

func Test_RTRSerialQuery(t *testing.T) {
	id := uint16(time.Now().Unix())
	sn := randUint32()
	verifyRTRMessage(t, NewRTRSerialQuery(id, sn))
}

func Test_RTRResetQuery(t *testing.T) {
	verifyRTRMessage(t, NewRTRResetQuery())
}

func Test_RTRCacheResponse(t *testing.T) {
	id := uint16(time.Now().Unix())
	verifyRTRMessage(t, NewRTRCacheResponse(id))
}

type rtrIPPrefixTestCase struct {
	pString string
	pLen    uint8
	mLen    uint8
	asn     uint32
	flags   uint8
}

var rtrIPPrefixTestCases = []rtrIPPrefixTestCase{
	{"192.168.0.0", 16, 32, 65001, ANNOUNCEMENT},
	{"192.168.0.0", 16, 32, 65001, WITHDRAWAL},
	{"2001:db8::", 32, 128, 65001, ANNOUNCEMENT},
	{"2001:db8::", 32, 128, 65001, WITHDRAWAL},
	{"::ffff:0.0.0.0", 96, 128, 65001, ANNOUNCEMENT},
	{"::ffff:0.0.0.0", 96, 128, 65001, WITHDRAWAL},
}

func Test_RTRIPPrefix(t *testing.T) {
	for i := range rtrIPPrefixTestCases {
		test := &rtrIPPrefixTestCases[i]
		verifyRTRMessage(t, NewRTRIPPrefix(netip.MustParseAddr(test.pString), test.pLen, test.mLen, test.asn, test.flags))
	}
}

func Test_RTREndOfData(t *testing.T) {
	id := uint16(time.Now().Unix())
	sn := randUint32()
	verifyRTRMessage(t, NewRTREndOfData(id, sn))
}

func Test_RTRCacheReset(t *testing.T) {
	verifyRTRMessage(t, NewRTRCacheReset())
}

func Test_RTRErrorReport(t *testing.T) {
	errPDU, _ := NewRTRResetQuery().Serialize()
	errText1 := []byte("Couldn't send CacheResponce PDU")
	errText2 := []byte("Wrong Length of PDU: 10 bytes")

	// See 5.10 ErrorReport in RFC6810
	// when it doesn't have both "erroneous PDU" and "Arbitrary Text"
	verifyRTRMessage(t, NewRTRErrorReport(NO_DATA_AVAILABLE, nil, nil))

	// when it has "erroneous PDU"
	verifyRTRMessage(t, NewRTRErrorReport(UNSUPPORTED_PROTOCOL_VERSION, errPDU, nil))

	// when it has "ArbitaryText"
	verifyRTRMessage(t, NewRTRErrorReport(INTERNAL_ERROR, nil, errText1))

	// when it has both "erroneous PDU" and "Arbitrary Text"
	verifyRTRMessage(t, NewRTRErrorReport(CORRUPT_DATA, errPDU, errText2))
}

func Test_ParseRTR_ErrorReportRejectsOversizedTextLen(t *testing.T) {
	// Regression for OSS-Fuzz OOM: RTRErrorReport.DecodeFromBytes used TextLen
	// from the input without validating against available bytes, causing huge
	// allocations.
	//
	// Build a minimal ErrorReport with PDULen=0 and an absurd TextLen, while the
	// buffer itself is tiny.
	data := make([]byte, 21)
	data[0] = 0
	data[1] = RTR_ERROR_REPORT
	// ErrorCode (2 bytes) left as 0
	// Len (4 bytes) = 21
	putUint32BE(data[4:8], uint32(len(data)))
	// PDULen (4 bytes) = 0
	putUint32BE(data[8:12], 0)
	// TextLen (4 bytes) = very large
	putUint32BE(data[12:16], 0xfffffff0)

	_, err := ParseRTR(data)
	require.Error(t, err)
}

func putUint32BE(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

//nolint:errcheck
func FuzzParseRTR(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ParseRTR(data)
	})
}

// grep -r DecodeFromBytes pkg/packet/rtr/ | grep -e ":func " | perl -pe 's|func \(.* \*(.*?)\).*|(&\1\{\})\.DecodeFromBytes(data)|g' | awk -F ':' '{print $2}'
//
//nolint:errcheck
func FuzzDecodeFromBytes(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		(&RTRCommon{}).DecodeFromBytes(data)
		(&RTRReset{}).DecodeFromBytes(data)
		(&RTRCacheResponse{}).DecodeFromBytes(data)
		(&RTRIPPrefix{}).DecodeFromBytes(data)
		(&RTRErrorReport{}).DecodeFromBytes(data)
	})
}
