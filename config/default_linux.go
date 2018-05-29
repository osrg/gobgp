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

package config

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// For reference, see http://man7.org/linux/man-pages/man7/rtnetlink.7.html
type ndmsg struct {
	Family  uint8
	IfIndex uint32
	State   uint16
	Flags   uint8
	Type    uint8
}

func GetIPv6LinkLocalNeighborAddress(ifname string) (string, error) {
	ipAddrs := []net.IP{}
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return "", err
	}
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETNEIGH, int(syscall.AF_INET6))
	if err != nil {
		return "", fmt.Errorf("netlink: get IPv6 RIB: %s", err)
	}
	messages, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return "", fmt.Errorf("netlink: parse IPv6 RIB: %s", err)
	}
	for _, m := range messages {
		if m.Header.Type != syscall.RTM_NEWNEIGH {
			continue
		}
		data := m.Data[12:]
		routeAttrs := []syscall.NetlinkRouteAttr{}
		for len(data) >= syscall.SizeofRtAttr {
			parseRouteAttr := func(data []byte) (*syscall.RtAttr, []byte, int, error) {
				dataLen := len(data)
				attr := (*syscall.RtAttr)(unsafe.Pointer(&data[0]))
				attrLen := int(attr.Len)
				if attrLen < syscall.SizeofRtAttr || attrLen > dataLen {
					return nil, nil, 0, syscall.EINVAL
				}
				align := (attrLen + syscall.RTA_ALIGNTO - 1) & ^(syscall.RTA_ALIGNTO - 1)
				return attr, data[syscall.SizeofRtAttr:], align, nil
			}
			attr, attrBuffer, attrLen, err := parseRouteAttr(data)
			if err != nil {
				break
			}
			attrValue := attrBuffer[:int(attr.Len)-syscall.SizeofRtAttr]
			routeAttr := syscall.NetlinkRouteAttr{Attr: *attr, Value: attrValue}
			routeAttrs = append(routeAttrs, routeAttr)
			data = data[attrLen:]
		}
		if len(routeAttrs) == 0 {
			continue
		}
		for _, attr := range routeAttrs {
			if attr.Attr.Type == 1 {
				ndm := (*ndmsg)(unsafe.Pointer(&m.Data[0]))
				ipAddr := net.IP(attr.Value)
				local, err := isLocalLinkLocalAddress(ifi.Index, ipAddr)
				if err != nil {
					continue
				}
				if ndm.State&0x20 == 0 && ipAddr.IsLinkLocalUnicast() && !local {
					ipAddrs = append(ipAddrs, ipAddr)
				}
			}
		}
	}
	switch len(ipAddrs) {
	case 1:
		return fmt.Sprintf("%s%%%s", ipAddrs[0], ifname), nil
	case 0:
		return "", fmt.Errorf("no ipv6 link-local neighbor found")
	default:
		return "", fmt.Errorf("found %d link-local neighbors. only support p2p link", len(ipAddrs))
	}
}
