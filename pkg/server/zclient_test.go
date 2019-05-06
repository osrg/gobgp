// Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
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
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/osrg/gobgp/internal/pkg/table"
	"github.com/osrg/gobgp/internal/pkg/zebra"
)

func Test_newPathFromIPRouteMessage(t *testing.T) {
	assert := assert.New(t)

	ipv4RouteAddCommand := map[uint8]zebra.API_TYPE{
		2: zebra.IPV4_ROUTE_ADD,
		3: zebra.IPV4_ROUTE_ADD,
		4: zebra.FRR_IPV4_ROUTE_ADD,
		5: zebra.FRR_ZAPI5_IPV4_ROUTE_ADD,
		6: zebra.FRR_ZAPI6_ROUTE_ADD,
	}
	ipv4RouteDeleteCommand := map[uint8]zebra.API_TYPE{
		2: zebra.IPV4_ROUTE_DELETE,
		3: zebra.IPV4_ROUTE_DELETE,
		4: zebra.FRR_IPV4_ROUTE_DELETE,
		5: zebra.FRR_ZAPI5_IPV4_ROUTE_DELETE,
		6: zebra.FRR_ZAPI6_ROUTE_DELETE,
	}
	ipv6RouteAddCommand := map[uint8]zebra.API_TYPE{
		2: zebra.IPV6_ROUTE_ADD,
		3: zebra.IPV6_ROUTE_ADD,
		4: zebra.FRR_IPV6_ROUTE_ADD,
		5: zebra.FRR_ZAPI5_IPV6_ROUTE_ADD,
		6: zebra.FRR_ZAPI6_ROUTE_ADD,
	}
	ipv6RouteDeleteCommand := map[uint8]zebra.API_TYPE{
		2: zebra.IPV6_ROUTE_DELETE,
		3: zebra.IPV6_ROUTE_DELETE,
		4: zebra.FRR_IPV6_ROUTE_DELETE,
		5: zebra.FRR_ZAPI5_IPV6_ROUTE_DELETE,
		6: zebra.FRR_ZAPI6_ROUTE_DELETE,
	}
	message := map[uint8]zebra.MESSAGE_FLAG{
		2: zebra.MESSAGE_NEXTHOP | zebra.MESSAGE_DISTANCE | zebra.MESSAGE_METRIC | zebra.MESSAGE_MTU,
		3: zebra.MESSAGE_NEXTHOP | zebra.MESSAGE_DISTANCE | zebra.MESSAGE_METRIC | zebra.MESSAGE_MTU,
		4: zebra.FRR_MESSAGE_NEXTHOP | zebra.FRR_MESSAGE_DISTANCE | zebra.FRR_MESSAGE_METRIC | zebra.FRR_MESSAGE_MTU,
		5: zebra.FRR_ZAPI5_MESSAGE_NEXTHOP | zebra.FRR_ZAPI5_MESSAGE_DISTANCE | zebra.FRR_ZAPI5_MESSAGE_METRIC | zebra.FRR_ZAPI5_MESSAGE_MTU,
		6: zebra.FRR_ZAPI5_MESSAGE_NEXTHOP | zebra.FRR_ZAPI5_MESSAGE_DISTANCE | zebra.FRR_ZAPI5_MESSAGE_METRIC | zebra.FRR_ZAPI5_MESSAGE_MTU,
	}

	for v := zebra.MinZapiVer; v <= zebra.MaxZapiVer; v++ {
		// IPv4 Route Add
		m := &zebra.Message{}
		marker := zebra.HEADER_MARKER
		if v > 3 {
			marker = zebra.FRR_HEADER_MARKER
		}
		flag := zebra.FLAG_SELECTED
		if v > 5 {
			flag = zebra.FRR_ZAPI6_FLAG_SELECTED
		}
		h := &zebra.Header{
			Len:     zebra.HeaderSize(v),
			Marker:  marker,
			Version: v,
			Command: ipv4RouteAddCommand[v],
		}
		b := &zebra.IPRouteBody{
			Type:    zebra.ROUTE_TYPE(zebra.ROUTE_STATIC),
			Flags:   flag,
			Message: message[v],
			SAFI:    zebra.SAFI(zebra.SAFI_UNICAST), // 1, FRR_ZAPI5_SAFI_UNICAST is same
			Prefix: zebra.Prefix{
				Prefix:    net.ParseIP("192.168.100.0"),
				PrefixLen: uint8(24),
			},
			Nexthops: []zebra.Nexthop{
				{
					Gate: net.ParseIP("0.0.0.0"),
				},
				{
					Ifindex: uint32(1),
				},
			},
			Distance: uint8(0),
			Metric:   uint32(100),
			Mtu:      uint32(0),
			Api:      zebra.API_TYPE(ipv4RouteAddCommand[v]),
		}
		m.Header = *h
		m.Body = b

		path := newPathFromIPRouteMessage(m, v, "")
		pp := table.NewPath(nil, path.GetNlri(), path.IsWithdraw, path.GetPathAttrs(), time.Now(), false)
		pp.SetIsFromExternal(path.IsFromExternal())
		assert.Equal("0.0.0.0", pp.GetNexthop().String())
		assert.Equal("192.168.100.0/24", pp.GetNlri().String())
		assert.True(pp.IsFromExternal())
		assert.False(pp.IsWithdraw)

		// IPv4 Route Delete
		h.Command = ipv4RouteDeleteCommand[v]
		b.Api = ipv4RouteDeleteCommand[v]
		m.Header = *h
		m.Body = b

		path = newPathFromIPRouteMessage(m, v, "")
		pp = table.NewPath(nil, path.GetNlri(), path.IsWithdraw, path.GetPathAttrs(), time.Now(), false)
		pp.SetIsFromExternal(path.IsFromExternal())
		assert.Equal("0.0.0.0", pp.GetNexthop().String())
		assert.Equal("192.168.100.0/24", pp.GetNlri().String())
		med, _ := pp.GetMed()
		assert.Equal(uint32(100), med)
		assert.True(pp.IsFromExternal())
		assert.True(pp.IsWithdraw)

		// IPv6 Route Add
		h.Command = ipv6RouteAddCommand[v]
		b.Api = ipv6RouteAddCommand[v]
		b.Prefix.Prefix = net.ParseIP("2001:db8:0:f101::")
		b.Prefix.PrefixLen = uint8(64)
		b.Nexthops = []zebra.Nexthop{{Gate: net.ParseIP("::")}}
		m.Header = *h
		m.Body = b

		path = newPathFromIPRouteMessage(m, v, "")
		pp = table.NewPath(nil, path.GetNlri(), path.IsWithdraw, path.GetPathAttrs(), time.Now(), false)
		pp.SetIsFromExternal(path.IsFromExternal())
		assert.Equal("::", pp.GetNexthop().String())
		assert.Equal("2001:db8:0:f101::/64", pp.GetNlri().String())
		med, _ = pp.GetMed()
		assert.Equal(uint32(100), med)
		assert.True(pp.IsFromExternal())
		assert.False(pp.IsWithdraw)

		// IPv6 Route Delete
		h.Command = ipv6RouteDeleteCommand[v]
		b.Api = ipv6RouteDeleteCommand[v]
		m.Header = *h
		m.Body = b

		path = newPathFromIPRouteMessage(m, v, "")
		pp = table.NewPath(nil, path.GetNlri(), path.IsWithdraw, path.GetPathAttrs(), time.Now(), false)
		pp.SetIsFromExternal(path.IsFromExternal())
		assert.Equal("::", pp.GetNexthop().String())
		assert.Equal("2001:db8:0:f101::/64", pp.GetNlri().String())
		assert.True(pp.IsFromExternal())
		assert.True(pp.IsWithdraw)
	}
}
