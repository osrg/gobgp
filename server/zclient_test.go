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
	"github.com/osrg/gobgp/table"
	"github.com/osrg/gobgp/zebra"
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func Test_createPathFromIPRouteMessage(t *testing.T) {
	assert := assert.New(t)

	m := &zebra.Message{}
	h := &zebra.Header{
		Len:     zebra.HEADER_SIZE,
		Marker:  zebra.HEADER_MARKER,
		Version: zebra.VERSION,
		Command: zebra.IPV4_ROUTE_ADD,
	}

	b := &zebra.IPRouteBody{
		Type:         zebra.ROUTE_TYPE(zebra.ROUTE_STATIC),
		Flags:        zebra.FLAG(zebra.FLAG_SELECTED),
		Message:      zebra.MESSAGE_NEXTHOP | zebra.MESSAGE_DISTANCE | zebra.MESSAGE_METRIC,
		SAFI:         zebra.SAFI(zebra.SAFI_UNICAST),
		Prefix:       net.ParseIP("192.168.100.0"),
		PrefixLength: uint8(24),
		Nexthops:     []net.IP{net.ParseIP("0.0.0.0")},
		Ifindexs:     []uint32{1},
		Distance:     uint8(0),
		Metric:       uint32(100),
		Api:          zebra.API_TYPE(zebra.IPV4_ROUTE_ADD),
	}

	m.Header = *h
	m.Body = b

	pi := &table.PeerInfo{
		AS:      65000,
		LocalID: net.ParseIP("10.0.0.1"),
	}
	p := createPathFromIPRouteMessage(m, pi)
	assert.NotEqual(nil, p)
	assert.Equal("0.0.0.0", p.GetNexthop().String())
	assert.Equal("192.168.100.0/24", p.GetNlri().String())
	assert.True(p.IsFromExternal())
	assert.False(p.IsWithdraw)

	// withdraw
	h.Command = zebra.IPV4_ROUTE_DELETE
	m.Header = *h
	p = createPathFromIPRouteMessage(m, pi)
	assert.NotEqual(nil, p)
	assert.Equal("0.0.0.0", p.GetNexthop().String())
	assert.Equal("192.168.100.0/24", p.GetNlri().String())
	med, _ := p.GetMed()
	assert.Equal(uint32(100), med)
	assert.True(p.IsFromExternal())
	assert.True(p.IsWithdraw)

	// IPv6
	h.Command = zebra.IPV6_ROUTE_ADD
	b.Prefix = net.ParseIP("2001:db8:0:f101::")
	b.PrefixLength = uint8(64)
	b.Nexthops = []net.IP{net.ParseIP("::")}
	m.Header = *h
	m.Body = b

	p = createPathFromIPRouteMessage(m, pi)
	assert.NotEqual(nil, p)
	assert.Equal("::", p.GetNexthop().String())
	assert.Equal("2001:db8:0:f101::/64", p.GetNlri().String())
	med, _ = p.GetMed()
	assert.Equal(uint32(100), med)
	assert.True(p.IsFromExternal())
	assert.False(p.IsWithdraw)

	// withdraw
	h.Command = zebra.IPV6_ROUTE_DELETE
	m.Header = *h
	p = createPathFromIPRouteMessage(m, pi)
	assert.NotEqual(nil, p)
	assert.Equal("::", p.GetNexthop().String())
	assert.Equal("2001:db8:0:f101::/64", p.GetNlri().String())
	assert.True(p.IsFromExternal())
	assert.True(p.IsWithdraw)

}
