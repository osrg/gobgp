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

package server

import (
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/table"
	zebra "github.com/osrg/gozebra"
	"net"
	"strconv"
	"strings"
)

type broadcastZapiMsg struct {
	client *zebra.Client
	msg    *zebra.Message
}

func (m *broadcastZapiMsg) send() {
	m.client.Send(m.msg)
}

func newIPRouteMessage(path *table.Path) *zebra.Message {
	var command zebra.API_TYPE
	switch path.GetRouteFamily() {
	case bgp.RF_IPv4_UC:
		if path.IsWithdraw == true {
			command = zebra.IPV4_ROUTE_DELETE
		} else {
			command = zebra.IPV4_ROUTE_ADD
		}
	case bgp.RF_IPv6_UC:
		if path.IsWithdraw == true {
			command = zebra.IPV6_ROUTE_DELETE
		} else {
			command = zebra.IPV6_ROUTE_ADD
		}
	default:
		return nil
	}

	l := strings.SplitN(path.GetNlri().String(), "/", 2)
	plen, _ := strconv.Atoi(l[1])
	med, _ := path.GetMed()
	return &zebra.Message{
		Header: zebra.Header{
			Command: command,
		},
		Body: &zebra.IPv4RouteBody{
			Type:         zebra.ROUTE_BGP,
			SAFI:         zebra.SAFI_UNICAST,
			Message:      zebra.MESSAGE_NEXTHOP,
			Prefix:       net.ParseIP(l[0]),
			PrefixLength: uint8(plen),
			Nexthops:     []net.IP{path.GetNexthop()},
			Metric:       med,
		},
	}
}

func newBroadcastZapiBestMsg(cli *zebra.Client, path *table.Path) *broadcastZapiMsg {
	if cli == nil {
		return nil
	}
	m := newIPRouteMessage(path)
	if m == nil {
		return nil
	}
	return &broadcastZapiMsg{
		client: cli,
		msg:    m,
	}
}

func handleZapiMsg(msg *zebra.Message) {
}
