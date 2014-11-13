package io

import (
	"net"
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

func SetTcpMD5SigSockopts(fd int, address string, key string) error {
	t, _ := buildTcpMD5Sig(address, key)
	_, _, e := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd),
		uintptr(syscall.IPPROTO_TCP), uintptr(TCP_MD5SIG),
		uintptr(unsafe.Pointer(&t)), unsafe.Sizeof(t), 0)
	return e
}
