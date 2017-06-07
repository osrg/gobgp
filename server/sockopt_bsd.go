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
// +build dragonfly freebsd netbsd

package server

import (
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
)

const (
	TCP_MD5SIG = 0x10
)

func SetTcpMD5SigSockopts(l *net.TCPListener, address string, key string) error {
	fi, err := l.File()
	defer fi.Close()

	if err != nil {
		return err
	}

	if l, err := net.FileListener(fi); err == nil {
		defer l.Close()
	}

	// always enable and assumes that the configuration is done by
	// setkey()
	if err := syscall.SetsockoptInt(int(fi.Fd()),
		syscall.IPPROTO_TCP, TCP_MD5SIG, 1); err != nil {
		return err
	}
	return nil
}

func SetTcpTTLSockopts(conn *net.TCPConn, ttl int) error {
	level := syscall.IPPROTO_IP
	name := syscall.IP_TTL
	if strings.Contains(conn.RemoteAddr().String(), "[") {
		level = syscall.IPPROTO_IPV6
		name = syscall.IPV6_UNICAST_HOPS
	}
	fi, err := conn.File()
	defer fi.Close()
	if err != nil {
		return err
	}
	if conn, err := net.FileConn(fi); err == nil {
		defer conn.Close()
	}
	return os.NewSyscallError("setsockopt", syscall.SetsockoptInt(int(fi.Fd()), level, name, ttl))
}

func DialTCPTimeoutWithMD5Sig(host string, port int, localAddr, key string, msec int) (*net.TCPConn, error) {
	return nil, fmt.Errorf("md5 active connection unsupported")
}
