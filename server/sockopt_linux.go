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
// +build linux

package server

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"
)

func DialTCPTimeoutWithMD5Sig(host string, port int, key string, msec int) (*net.TCPConn, error) {
	var family int
	var ra syscall.Sockaddr

	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("invalid ip: %s", host)
	}
	switch {
	case ip.To4() != nil:
		family = syscall.AF_INET
		i := &syscall.SockaddrInet4{
			Port: port,
		}
		for idx, _ := range i.Addr {
			i.Addr[idx] = ip.To4()[idx]
		}
		ra = i
	default:
		family = syscall.AF_INET6
		i := &syscall.SockaddrInet6{
			Port: port,
		}
		for idx, _ := range i.Addr {
			i.Addr[idx] = ip[idx]
		}
		ra = i
	}
	sotype := syscall.SOCK_STREAM | syscall.SOCK_CLOEXEC | syscall.SOCK_NONBLOCK
	proto := 0
	fd, err := syscall.Socket(family, sotype, proto)
	if err != nil {
		return nil, err
	}
	t, err := buildTcpMD5Sig(host, key)
	if err != nil {
		return nil, err
	}
	if _, _, e := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd),
		uintptr(syscall.IPPROTO_TCP), uintptr(TCP_MD5SIG),
		uintptr(unsafe.Pointer(&t)), unsafe.Sizeof(t), 0); e > 0 {
		return nil, os.NewSyscallError("setsockopt", e)
	}

	tcpconn := func(fd uintptr) (*net.TCPConn, error) {
		fi := os.NewFile(uintptr(fd), "")
		defer fi.Close()
		conn, err := net.FileConn(fi)
		return conn.(*net.TCPConn), err
	}

	err = syscall.Connect(fd, ra)
	switch err {
	case syscall.EINPROGRESS, syscall.EALREADY, syscall.EINTR:
		// do timeout handling
	case nil, syscall.EISCONN:
		return tcpconn(uintptr(fd))
	default:
		return nil, os.NewSyscallError("connect", err)
	}

	epfd, e := syscall.EpollCreate1(0)
	if e != nil {
		return nil, e
	}
	defer syscall.Close(epfd)

	var event syscall.EpollEvent
	events := make([]syscall.EpollEvent, 1)

	event.Events = syscall.EPOLLIN
	event.Fd = int32(fd)
	if e = syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, fd, &event); e != nil {
		return nil, e
	}

	for {
		nevents, e := syscall.EpollWait(epfd, events, msec)
		if e != nil {
			return nil, e
		}
		if nevents == 0 {
			return nil, fmt.Errorf("timeout")
		} else if nevents == 1 && events[0].Fd == int32(fd) {
			nerr, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
			if err != nil {
				return nil, os.NewSyscallError("getsockopt", err)
			}
			switch err := syscall.Errno(nerr); err {
			case syscall.EINPROGRESS, syscall.EALREADY, syscall.EINTR:
			case syscall.Errno(0), syscall.EISCONN:
				return tcpconn(uintptr(fd))
			default:
				return nil, os.NewSyscallError("getsockopt", err)
			}
		} else {
			return nil, fmt.Errorf("unexpected epoll behavior")
		}
	}
}
