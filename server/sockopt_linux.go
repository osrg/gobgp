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
	"strings"
	"syscall"
	"unsafe"
)

const (
	TCP_MD5SIG = 14
)

type tcpmd5sig struct {
	ss_family uint16
	ss        [126]byte
	pad1      uint16
	keylen    uint16
	pad2      uint32
	key       [80]byte
}

func buildTcpMD5Sig(address string, key string) (tcpmd5sig, error) {
	t := tcpmd5sig{}
	addr := net.ParseIP(address)
	if addr.To4() != nil {
		t.ss_family = syscall.AF_INET
		copy(t.ss[2:], addr.To4())
	} else {
		t.ss_family = syscall.AF_INET6
		copy(t.ss[6:], addr.To16())
	}

	t.keylen = uint16(len(key))
	copy(t.key[0:], []byte(key))

	return t, nil
}

func SetTcpMD5SigSockopts(l *net.TCPListener, address string, key string) error {
	t, _ := buildTcpMD5Sig(address, key)
	fi, err := l.File()
	defer fi.Close()
	if err != nil {
		return err
	}
	if l, err := net.FileListener(fi); err == nil {
		defer l.Close()
	}
	_, _, e := syscall.Syscall6(syscall.SYS_SETSOCKOPT, fi.Fd(),
		uintptr(syscall.IPPROTO_TCP), uintptr(TCP_MD5SIG),
		uintptr(unsafe.Pointer(&t)), unsafe.Sizeof(t), 0)
	if e > 0 {
		return e
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
	var family int
	var ra, la syscall.Sockaddr

	ip, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return nil, fmt.Errorf("invalid ip: %s", err)
	}
	l, err := net.ResolveIPAddr("ip", localAddr)
	if l == nil {
		return nil, fmt.Errorf("invalid local ip: %s", err)
	}
	if (ip.IP.To4() != nil) != (l.IP.To4() != nil) {
		return nil, fmt.Errorf("remote and local ip address family is not same")
	}
	switch {
	case ip.IP.To4() != nil:
		family = syscall.AF_INET
		i := &syscall.SockaddrInet4{
			Port: port,
		}
		for idx, _ := range i.Addr {
			i.Addr[idx] = ip.IP.To4()[idx]
		}
		ra = i
		j := &syscall.SockaddrInet4{}
		for idx, _ := range j.Addr {
			j.Addr[idx] = l.IP.To4()[idx]
		}
		la = j
	default:
		family = syscall.AF_INET6
		i := &syscall.SockaddrInet6{
			Port: port,
		}
		for idx, _ := range i.Addr {
			i.Addr[idx] = ip.IP[idx]
		}
		ra = i
		var zone uint32
		if l.Zone != "" {
			intf, err := net.InterfaceByName(l.Zone)
			if err != nil {
				return nil, err
			}
			zone = uint32(intf.Index)
		}
		j := &syscall.SockaddrInet6{
			ZoneId: zone,
		}
		for idx, _ := range j.Addr {
			j.Addr[idx] = l.IP[idx]
		}
		la = j
	}
	sotype := syscall.SOCK_STREAM | syscall.SOCK_CLOEXEC | syscall.SOCK_NONBLOCK
	proto := 0
	fd, err := syscall.Socket(family, sotype, proto)
	if err != nil {
		return nil, err
	}
	fi := os.NewFile(uintptr(fd), "")
	defer fi.Close()

	t, err := buildTcpMD5Sig(host, key)
	if err != nil {
		return nil, err
	}
	if _, _, e := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd),
		uintptr(syscall.IPPROTO_TCP), uintptr(TCP_MD5SIG),
		uintptr(unsafe.Pointer(&t)), unsafe.Sizeof(t), 0); e > 0 {
		return nil, os.NewSyscallError("setsockopt", e)
	}

	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1); err != nil {
		return nil, os.NewSyscallError("setsockopt", err)
	}
	if err = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1); err != nil {
		return nil, os.NewSyscallError("setsockopt", err)
	}
	if err = syscall.Bind(fd, la); err != nil {
		return nil, os.NewSyscallError("bind", err)
	}

	tcpconn := func(fi *os.File) (*net.TCPConn, error) {
		conn, err := net.FileConn(fi)
		return conn.(*net.TCPConn), err
	}

	err = syscall.Connect(fd, ra)
	switch err {
	case syscall.EINPROGRESS, syscall.EALREADY, syscall.EINTR:
		// do timeout handling
	case nil, syscall.EISCONN:
		return tcpconn(fi)
	default:
		return nil, os.NewSyscallError("connect", err)
	}

	epfd, e := syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
	if e != nil {
		return nil, e
	}
	defer syscall.Close(epfd)

	var event syscall.EpollEvent
	events := make([]syscall.EpollEvent, 1)

	event.Events = syscall.EPOLLIN | syscall.EPOLLOUT | syscall.EPOLLPRI
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
				return tcpconn(fi)
			default:
				return nil, os.NewSyscallError("getsockopt", err)
			}
		} else {
			return nil, fmt.Errorf("unexpected epoll behavior")
		}
	}
}
