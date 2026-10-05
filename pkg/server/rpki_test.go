// Copyright (C) 2015-2021 Nippon Telegraph and Telephone Corporation.
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

package server

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/packet/rtr"
)

func Test_readRTRMessageRejectsOversizedLength(t *testing.T) {
	header := make([]byte, rtr.RTR_MIN_LEN)
	header[0] = 1 // Protocol Version
	header[1] = rtr.RTR_CACHE_RESET
	binary.BigEndian.PutUint32(header[4:8], 0xffffffff)

	if _, err := readRTRMessage(bytes.NewReader(header)); err == nil {
		t.Fatal("expected an error when the RTR Length is too large, got nil")
	}
}

func Test_readRTRMessageAcceptsValidLength(t *testing.T) {
	header := make([]byte, rtr.RTR_MIN_LEN)
	header[0] = 1 // Protocol Version
	header[1] = rtr.RTR_CACHE_RESET
	binary.BigEndian.PutUint32(header[4:8], rtr.RTR_MIN_LEN)

	data, err := readRTRMessage(bytes.NewReader(header))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) != rtr.RTR_MIN_LEN {
		t.Fatalf("expected %d bytes, got %d", rtr.RTR_MIN_LEN, len(data))
	}
}

func TestReadRTRMessageBodyAndBoundary(t *testing.T) {
	message := []byte{1, rtr.RTR_SERIAL_NOTIFY, 0, 0, 0, 0, 0, 12, 1, 2, 3, 4}
	stream := bytes.NewReader(append(append([]byte(nil), message...), 0xee))
	got, err := readRTRMessage(stream)
	if err != nil || !bytes.Equal(got, message) {
		t.Fatalf("got %x, err %v; want %x", got, err, message)
	}
	if next, err := stream.ReadByte(); err != nil || next != 0xee {
		t.Fatalf("consumed the next message: byte=%x, err=%v", next, err)
	}
	got, err = readRTRMessage(bytes.NewReader(message[:len(message)-1]))
	if got != nil || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated body: got %x, err %v", got, err)
	}
}
