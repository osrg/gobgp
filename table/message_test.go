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

package table

import (
	"github.com/osrg/gobgp/packet"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

func updateMsg1(as []uint16) *bgp.BGPMessage {
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, as)}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("192.168.50.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med,
	}

	nlri := []bgp.NLRInfo{*bgp.NewNLRInfo(24, "10.10.10.0")}
	return bgp.NewBGPUpdateMessage([]bgp.WithdrawnRoute{}, pathAttributes, nlri)
}

func TestAsPathAsTrans(t *testing.T) {
	as := []uint16{65000, 4000, bgp.AS_TRANS, bgp.AS_TRANS, 40001}
	m := updateMsg1(as).Body.(*bgp.BGPUpdate)

	m.PathAttributes = append(m.PathAttributes, m.PathAttributes[3])
	as4 := []uint32{400000, 300000}
	aspathParam := []*bgp.As4PathParam{bgp.NewAs4PathParam(2, as4)}
	m.PathAttributes[3] = bgp.NewPathAttributeAs4Path(aspathParam)
	assert.Equal(t, len(m.PathAttributes), 5)

	UpdatePathAttrs4ByteAs(m)
	assert.Equal(t, len(m.PathAttributes), 4)

	assert.Equal(t, reflect.TypeOf(m.PathAttributes[0]).String(), "*bgp.PathAttributeOrigin")
	assert.Equal(t, reflect.TypeOf(m.PathAttributes[1]).String(), "*bgp.PathAttributeAsPath")
	assert.Equal(t, reflect.TypeOf(m.PathAttributes[2]).String(), "*bgp.PathAttributeNextHop")
	assert.Equal(t, reflect.TypeOf(m.PathAttributes[3]).String(), "*bgp.PathAttributeMultiExitDisc")

	newAS := []uint32{65000, 4000, 400000, 300000, 40001}
	asAttr := m.PathAttributes[1].(*bgp.PathAttributeAsPath)
	assert.Equal(t, len(asAttr.Value), 1)
	for _, param := range asAttr.Value {
		asParam := param.(*bgp.As4PathParam)
		for i, v := range asParam.AS {
			assert.Equal(t, v, newAS[i])
		}
	}
	UpdatePathAttrs2ByteAs(m)
	assert.Equal(t, len(m.PathAttributes), 5)
	attr := m.PathAttributes[1].(*bgp.PathAttributeAsPath)
	assert.Equal(t, len(attr.Value), 1)
	assert.Equal(t, attr.Value[0].(*bgp.AsPathParam).AS, as)
	attr2 := m.PathAttributes[4].(*bgp.PathAttributeAs4Path)
	assert.Equal(t, len(attr2.Value), 1)
	assert.Equal(t, attr2.Value[0].AS, as4)
}

func TestAs4PathUnchanged(t *testing.T) {
	as4 := []uint32{65000, 4000, 500000, 400010}
	m := updateMsg1([]uint16{}).Body.(*bgp.BGPUpdate)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, as4)}
	m.PathAttributes[1] = bgp.NewPathAttributeAsPath(aspathParam)
	UpdatePathAttrs4ByteAs(m)
	assert.Equal(t, len(m.PathAttributes), 4)

	assert.Equal(t, reflect.TypeOf(m.PathAttributes[0]).String(), "*bgp.PathAttributeOrigin")
	assert.Equal(t, reflect.TypeOf(m.PathAttributes[1]).String(), "*bgp.PathAttributeAsPath")
	assert.Equal(t, reflect.TypeOf(m.PathAttributes[2]).String(), "*bgp.PathAttributeNextHop")
	assert.Equal(t, reflect.TypeOf(m.PathAttributes[3]).String(), "*bgp.PathAttributeMultiExitDisc")

	asAttr := m.PathAttributes[1].(*bgp.PathAttributeAsPath)
	assert.Equal(t, len(asAttr.Value), 1)
	for _, param := range asAttr.Value {
		asParam := param.(*bgp.As4PathParam)
		for i, v := range asParam.AS {
			assert.Equal(t, v, as4[i])
		}
	}
}
