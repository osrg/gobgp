// Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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

//go:build linux

package netutils

import (
	"bytes"
	"encoding/binary"
	"syscall"
	"testing"
	"unsafe"
)

func Test_buildTcpMD5Sig(t *testing.T) {
	s := buildTcpMD5Sig("1.2.3.4", "hello")

	if unsafe.Sizeof(*s) != 216 {
		t.Error("TCPM5Sig struct size is wrong", unsafe.Sizeof(s))
	}

	buf1 := new(bytes.Buffer)
	if err := binary.Write(buf1, binary.LittleEndian, s); err != nil {
		t.Error(err)
	}

	buf2 := []uint8{2, 0, 0, 0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 104, 101, 108, 108, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	if bytes.Equal(buf1.Bytes(), buf2) {
		t.Log("OK")
	} else {
		t.Error("Something wrong v4")
	}
}

func Test_buildTcpMD5Sigv6(t *testing.T) {
	s := buildTcpMD5Sig("fe80::4850:31ff:fe01:fc55", "helloworld")

	buf1 := new(bytes.Buffer)
	if err := binary.Write(buf1, binary.LittleEndian, s); err != nil {
		t.Error(err)
	}

	buf2 := []uint8{10, 0, 0, 0, 0, 0, 0, 0, 254, 128, 0, 0, 0, 0, 0, 0, 72, 80, 49, 255, 254, 1, 252, 85, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 104, 101, 108, 108, 111, 119, 111, 114, 108, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	buf2[0] = syscall.AF_INET6

	if bytes.Equal(buf1.Bytes(), buf2) {
		t.Log("OK")
	} else {
		t.Error("Something wrong v6")
	}
}

func Test_buildTcpMD5Sigv6Zone(t *testing.T) {
	s := buildTcpMD5Sig("fe80::4850:31ff:fe01:fc55%123", "helloworld")
	if s == nil {
		t.Fatal("gen sig failed")
	}

	if s.Ifindex != 123 {
		t.Error("bad ipv6 if index")
	}
}

func Test_buildTcpMD5_CIDR(t *testing.T) {
	v4buff := [216]uint8{2, 0, 0, 0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 24, 5, 0, 0, 0, 0, 0, 104, 101, 108, 108, 111, 0}
	v6buff := [216]uint8{10, 0, 0, 0, 0, 0, 0, 0, 254, 128, 0, 0, 0, 0, 0, 0, 72, 80, 49, 255, 254, 1, 252, 85, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 64, 5, 0, 0, 0, 0, 0, 104, 101, 108, 108, 111, 0}
	tests := []struct {
		name     string
		addr     string
		expected []byte
	}{
		{"v4", "1.2.3.0/24", v4buff[:]},
		{"v6", "fe80::4850:31ff:fe01:fc55/64", v6buff[:]},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig := buildTcpMD5Sig(tt.addr, "hello")
			if sig == nil {
				t.Fatal("gen v4 sig failed")
			}
			got := new(bytes.Buffer)
			if err := binary.Write(got, binary.LittleEndian, sig); err != nil {
				t.Error(err)
			}
			if bytes.Equal(got.Bytes(), tt.expected) {
				t.Log("OK")
			} else {
				t.Error("Something wrong cidr")
			}
		})
	}
}
