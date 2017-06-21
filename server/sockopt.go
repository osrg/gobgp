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
// +build !linux,!dragonfly,!freebsd,!netbsd,!openbsd

package server

import (
	"fmt"
	"net"
)

func SetTcpMD5SigSockopts(l *net.TCPListener, address string, key string) error {
	return fmt.Errorf("md5 not supported")
}

func SetTcpTTLSockopts(conn *net.TCPConn, ttl int) error {
	return fmt.Errorf("setting ttl is not supported")
}

func SetTcpMinTTLSockopts(conn *net.TCPConn, ttl int) error {
	return fmt.Errorf("setting min ttl is not supported")
}

func DialTCPTimeoutWithMD5Sig(host string, port int, localAddr, key string, msec int) (*net.TCPConn, error) {
	return nil, fmt.Errorf("md5 active connection unsupported")
}
