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

//go:build !linux && !openbsd && !windows
// +build !linux,!openbsd,!windows

package netutils

import (
	"fmt"
	"net"
	"syscall"

	"github.com/osrg/gobgp/v4/pkg/log"
)

func SetTCPMD5SigSockopt(l *net.TCPListener, address string, key string) error {
	return SetTcpMD5SigSockopt(l, address, key)
}

func SetTCPTTLSockopt(conn net.Conn, ttl int) error {
	return SetTcpTTLSockopt(conn, ttl)
}

func SetTCPMinTTLSockopt(conn net.Conn, ttl int) error {
	return SetTcpMinTTLSockopt(conn, ttl)
}

func SetBindToDevSockopt(sc syscall.RawConn, device string) error {
	return fmt.Errorf("binding connection to a device is not supported")
}

func SetTCPMSSSockopt(conn net.Conn, mss uint16) error {
	return SetTcpMSSSockopt(conn, mss)
}

func DialerControl(logger log.Logger, network, address string, c syscall.RawConn, ttl, minTtl uint8, mss uint16, password string, bindInterface string) error {
	if password != "" {
		logger.Warn("setting md5 for active connection is not supported",
			log.Fields{
				"Topic": "Peer",
				"Key":   address,
			})
	}
	if ttl != 0 {
		logger.Warn("setting ttl for active connection is not supported",
			log.Fields{
				"Topic": "Peer",
				"Key":   address,
			})
	}
	if minTtl != 0 {
		logger.Warn("setting min ttl for active connection is not supported",
			log.Fields{
				"Topic": "Peer",
				"Key":   address,
			})
	}
	if mss != 0 {
		logger.Warn("setting MSS for active connection is not supported",
			log.Fields{
				"Topic": "Peer",
				"Key":   address,
			})
	}
	return nil
}
