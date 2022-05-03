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

	"github.com/osrg/gobgp/v3/internal/pkg/table"
	"github.com/osrg/gobgp/v3/internal/pkg/zebra"
	"github.com/osrg/gobgp/v3/pkg/log"
)

func Test_newPathFromIPRouteMessage(t *testing.T) {
	assert := assert.New(t)
	for v := zebra.MinZapiVer; v <= zebra.MaxZapiVer; v++ {
		// IPv4 Route Add
		m := &zebra.Message{}
		software := zebra.NewSoftware(v, "")
		flag := zebra.FlagSelected.ToEach(v, software)
		message := zebra.MessageNexthop | zebra.MessageDistance.ToEach(v, software) | zebra.MessageMetric.ToEach(v, software) | zebra.MessageMTU.ToEach(v, software)
		h := &zebra.Header{
			Len:     zebra.HeaderSize(v),
			Marker:  zebra.HeaderMarker(v),
			Version: v,
			Command: zebra.RouteAdd.ToEach(v, software),
		}
		b := &zebra.IPRouteBody{
			Type:    zebra.RouteType(zebra.RouteStatic),
			Flags:   flag,
			Message: message,
			Safi:    zebra.Safi(zebra.SafiUnicast), // 1, FRR_ZAPI5_SAFI_UNICAST is same
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
			API:      zebra.APIType(zebra.RouteAdd.ToEach(v, software)),
		}
		m.Header = *h
		m.Body = b
		logger := log.NewDefaultLogger()
		zebra.BackwardIPv6RouteDelete.ToEach(v, software)
		path := newPathFromIPRouteMessage(logger, m, v, software)
		pp := table.NewPath(nil, path.GetNlri(), path.IsWithdraw, path.GetPathAttrs(), time.Now(), false)
		pp.SetIsFromExternal(path.IsFromExternal())
		assert.Equal("0.0.0.0", pp.GetNexthop().String())
		assert.Equal("192.168.100.0/24", pp.GetNlri().String())
		assert.True(pp.IsFromExternal())
		assert.False(pp.IsWithdraw)

		// IPv4 Route Delete
		h.Command = zebra.RouteDelete.ToEach(v, software)
		b.API = zebra.RouteDelete.ToEach(v, software)
		m.Header = *h
		m.Body = b

		path = newPathFromIPRouteMessage(logger, m, v, software)
		pp = table.NewPath(nil, path.GetNlri(), path.IsWithdraw, path.GetPathAttrs(), time.Now(), false)
		pp.SetIsFromExternal(path.IsFromExternal())
		assert.Equal("0.0.0.0", pp.GetNexthop().String())
		assert.Equal("192.168.100.0/24", pp.GetNlri().String())
		med, _ := pp.GetMed()
		assert.Equal(uint32(100), med)
		assert.True(pp.IsFromExternal())
		assert.True(pp.IsWithdraw)

		// IPv6 Route Add
		h.Command = zebra.RouteAdd.ToEach(v, software)
		if v < 5 {
			h.Command = zebra.BackwardIPv6RouteAdd.ToEach(v, software)
		}
		b.API = zebra.RouteAdd.ToEach(v, software)
		if v < 5 {
			b.API = zebra.BackwardIPv6RouteAdd.ToEach(v, software)
		}
		b.Prefix.Prefix = net.ParseIP("2001:db8:0:f101::")
		b.Prefix.PrefixLen = uint8(64)
		b.Nexthops = []zebra.Nexthop{{Gate: net.ParseIP("::")}}
		m.Header = *h
		m.Body = b

		path = newPathFromIPRouteMessage(logger, m, v, software)
		pp = table.NewPath(nil, path.GetNlri(), path.IsWithdraw, path.GetPathAttrs(), time.Now(), false)
		pp.SetIsFromExternal(path.IsFromExternal())
		assert.Equal("::", pp.GetNexthop().String())
		assert.Equal("2001:db8:0:f101::/64", pp.GetNlri().String())
		med, _ = pp.GetMed()
		assert.Equal(uint32(100), med)
		assert.True(pp.IsFromExternal())
		assert.False(pp.IsWithdraw)

		// IPv6 Route Delete
		h.Command = zebra.RouteDelete.ToEach(v, software)
		if v < 5 {
			h.Command = zebra.BackwardIPv6RouteDelete.ToEach(v, software)
		}
		b.API = zebra.RouteDelete.ToEach(v, software)
		if v < 5 {
			b.API = zebra.BackwardIPv6RouteDelete.ToEach(v, software)
		}
		m.Header = *h
		m.Body = b

		path = newPathFromIPRouteMessage(logger, m, v, software)
		pp = table.NewPath(nil, path.GetNlri(), path.IsWithdraw, path.GetPathAttrs(), time.Now(), false)
		pp.SetIsFromExternal(path.IsFromExternal())
		assert.Equal("::", pp.GetNexthop().String())
		assert.Equal("2001:db8:0:f101::/64", pp.GetNlri().String())
		assert.True(pp.IsFromExternal())
		assert.True(pp.IsWithdraw)
	}
}
