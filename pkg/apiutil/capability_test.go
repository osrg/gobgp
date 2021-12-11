// Copyright (C) 2018 Nippon Telegraph and Telephone Corporation.
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

package apiutil

import (
	"testing"

	"google.golang.org/protobuf/proto"
	apb "google.golang.org/protobuf/types/known/anypb"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
)

func Test_MultiProtocolCapability(t *testing.T) {
	assert := assert.New(t)

	input := &api.MultiProtocolCapability{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_UNICAST,
		},
	}

	a, err := apb.New(input)
	assert.Nil(err)
	n, err := unmarshalCapability(a)
	assert.Nil(err)
	c := n.(*bgp.CapMultiProtocol)
	assert.Equal(bgp.RF_IPv4_UC, c.CapValue)

	output := NewMultiProtocolCapability(c)
	assert.True(proto.Equal(input, output))
}

func Test_RouteRefreshCapability(t *testing.T) {
	assert := assert.New(t)

	input := &api.RouteRefreshCapability{}

	a, err := apb.New(input)
	assert.Nil(err)
	n, err := unmarshalCapability(a)
	assert.Nil(err)

	output := NewRouteRefreshCapability(n.(*bgp.CapRouteRefresh))
	assert.True(proto.Equal(input, output))
}

func Test_CarryingLabelInfoCapability(t *testing.T) {
	assert := assert.New(t)

	input := &api.CarryingLabelInfoCapability{}

	a, err := apb.New(input)
	assert.Nil(err)
	n, err := unmarshalCapability(a)
	assert.Nil(err)

	output := NewCarryingLabelInfoCapability(n.(*bgp.CapCarryingLabelInfo))
	assert.True(proto.Equal(input, output))
}

func Test_ExtendedNexthopCapability(t *testing.T) {
	assert := assert.New(t)

	input := &api.ExtendedNexthopCapability{
		Tuples: []*api.ExtendedNexthopCapabilityTuple{
			{
				NlriFamily: &api.Family{
					Afi:  api.Family_AFI_IP,
					Safi: api.Family_SAFI_UNICAST,
				},
				NexthopFamily: &api.Family{
					Afi:  api.Family_AFI_IP6,
					Safi: api.Family_SAFI_UNICAST,
				},
			},
		},
	}

	a, err := apb.New(input)
	assert.Nil(err)
	n, err := unmarshalCapability(a)
	assert.Nil(err)
	c := n.(*bgp.CapExtendedNexthop)
	assert.Equal(1, len(c.Tuples))
	assert.Equal(uint16(bgp.AFI_IP), c.Tuples[0].NLRIAFI)
	assert.Equal(uint16(bgp.SAFI_UNICAST), c.Tuples[0].NLRISAFI)
	assert.Equal(uint16(bgp.AFI_IP6), c.Tuples[0].NexthopAFI)

	output := NewExtendedNexthopCapability(c)
	assert.True(proto.Equal(input, output))
}

func Test_GracefulRestartCapability(t *testing.T) {
	assert := assert.New(t)

	input := &api.GracefulRestartCapability{
		Flags: 0x08 | 0x04, // restarting|notification
		Time:  90,
		Tuples: []*api.GracefulRestartCapabilityTuple{
			{
				Family: &api.Family{
					Afi:  api.Family_AFI_IP,
					Safi: api.Family_SAFI_UNICAST,
				},
				Flags: 0x80, // forward
			},
		},
	}

	a, err := apb.New(input)
	assert.Nil(err)
	n, err := unmarshalCapability(a)
	assert.Nil(err)

	c := n.(*bgp.CapGracefulRestart)
	assert.Equal(1, len(c.Tuples))
	assert.Equal(uint8(0x08|0x04), c.Flags)
	assert.Equal(uint16(90), c.Time)
	assert.Equal(uint16(bgp.AFI_IP), c.Tuples[0].AFI)
	assert.Equal(uint8(bgp.SAFI_UNICAST), c.Tuples[0].SAFI)
	assert.Equal(uint8(0x80), c.Tuples[0].Flags)

	output := NewGracefulRestartCapability(c)
	assert.True(proto.Equal(input, output))
}

func Test_FourOctetASNumberCapability(t *testing.T) {
	assert := assert.New(t)

	input := &api.FourOctetASNCapability{
		Asn: 100,
	}

	a, err := apb.New(input)
	assert.Nil(err)
	n, err := unmarshalCapability(a)
	assert.Nil(err)

	c := n.(*bgp.CapFourOctetASNumber)
	assert.Equal(uint32(100), c.CapValue)

	output := NewFourOctetASNumberCapability(c)
	assert.True(proto.Equal(input, output))
}

func Test_AddPathCapability(t *testing.T) {
	assert := assert.New(t)

	input := &api.AddPathCapability{
		Tuples: []*api.AddPathCapabilityTuple{
			{
				Family: &api.Family{
					Afi:  api.Family_AFI_IP,
					Safi: api.Family_SAFI_UNICAST,
				},
				Mode: api.AddPathCapabilityTuple_BOTH,
			},
		},
	}

	a, err := apb.New(input)
	assert.Nil(err)
	n, err := unmarshalCapability(a)
	assert.Nil(err)

	c := n.(*bgp.CapAddPath)
	assert.Equal(1, len(c.Tuples))
	assert.Equal(bgp.RF_IPv4_UC, c.Tuples[0].RouteFamily)
	assert.Equal(bgp.BGP_ADD_PATH_BOTH, c.Tuples[0].Mode)

	output := NewAddPathCapability(c)
	assert.True(proto.Equal(input, output))
}

func Test_EnhancedRouteRefreshCapability(t *testing.T) {
	assert := assert.New(t)

	input := &api.EnhancedRouteRefreshCapability{}

	a, err := apb.New(input)
	assert.Nil(err)
	n, err := unmarshalCapability(a)
	assert.Nil(err)

	output := NewEnhancedRouteRefreshCapability(n.(*bgp.CapEnhancedRouteRefresh))
	assert.True(proto.Equal(input, output))
}

func Test_LongLivedGracefulRestartCapability(t *testing.T) {
	assert := assert.New(t)

	input := &api.LongLivedGracefulRestartCapability{
		Tuples: []*api.LongLivedGracefulRestartCapabilityTuple{
			{
				Family: &api.Family{
					Afi:  api.Family_AFI_IP,
					Safi: api.Family_SAFI_UNICAST,
				},
				Flags: 0x80, // forward
				Time:  90,
			},
		},
	}

	a, err := apb.New(input)
	assert.Nil(err)
	n, err := unmarshalCapability(a)
	assert.Nil(err)

	c := n.(*bgp.CapLongLivedGracefulRestart)
	assert.Equal(1, len(c.Tuples))
	assert.Equal(uint16(bgp.AFI_IP), c.Tuples[0].AFI)
	assert.Equal(uint8(bgp.SAFI_UNICAST), c.Tuples[0].SAFI)
	assert.Equal(uint8(0x80), c.Tuples[0].Flags)
	assert.Equal(uint32(90), c.Tuples[0].RestartTime)

	output := NewLongLivedGracefulRestartCapability(c)
	assert.True(proto.Equal(input, output))
}

func Test_RouteRefreshCiscoCapability(t *testing.T) {
	assert := assert.New(t)

	input := &api.RouteRefreshCiscoCapability{}

	a, err := apb.New(input)
	assert.Nil(err)
	n, err := unmarshalCapability(a)
	assert.Nil(err)

	output := NewRouteRefreshCiscoCapability(n.(*bgp.CapRouteRefreshCisco))
	assert.True(proto.Equal(input, output))
}

func Test_UnknownCapability(t *testing.T) {
	assert := assert.New(t)

	input := &api.UnknownCapability{
		Code:  0xff,
		Value: []byte{0x11, 0x22, 0x33, 0x44},
	}

	a, err := apb.New(input)
	assert.Nil(err)
	n, err := unmarshalCapability(a)
	assert.Nil(err)

	c := n.(*bgp.CapUnknown)
	assert.Equal(bgp.BGPCapabilityCode(0xff), c.CapCode)
	assert.Equal([]byte{0x11, 0x22, 0x33, 0x44}, c.CapValue)

	output := NewUnknownCapability(c)
	assert.True(proto.Equal(input, output))
}
