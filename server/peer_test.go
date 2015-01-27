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
	"fmt"
	//"encoding/json"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/table"
	"github.com/stretchr/testify/assert"
	"net"
	"reflect"
	"testing"
)

func peerRC3() *table.PeerInfo {
	peer := &table.PeerInfo{
		AS:      66003,
		ID:      net.ParseIP("10.0.255.3").To4(),
		LocalID: net.ParseIP("10.0.255.1").To4(),
	}
	return peer
}

func createAsPathAttribute(ases []uint32) *bgp.PathAttributeAsPath {
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, ases)}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	return aspath
}

func createMpReach(nexthop string, prefix []bgp.AddrPrefixInterface) *bgp.PathAttributeMpReachNLRI {
	mp_reach := bgp.NewPathAttributeMpReachNLRI(nexthop, prefix)
	return mp_reach
}

func update_fromRC3() *bgp.BGPMessage {
	pathAttributes := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(1),
		createAsPathAttribute([]uint32{66003, 4000, 70000}),
		createMpReach("2001:db8::3",
			[]bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "38:38:38:38::")}),
	}
	return bgp.NewBGPUpdateMessage([]bgp.WithdrawnRoute{}, pathAttributes, []bgp.NLRInfo{})
}

func TestProcessBGPUpdate_fourbyteAS(t *testing.T) {
	rib1 := table.NewTableManager("peer_test")

	m := update_fromRC3()
	peerInfo := peerRC3()
	msg := table.NewProcessMessage(m, peerInfo)
	pathList := msg.ToPathList()

	pList, wList, _ := rib1.ProcessPaths(pathList)
	assert.Equal(t, len(pList), 1)
	assert.Equal(t, len(wList), 0)
	fmt.Println(pList)
	sendMsg := table.CreateUpdateMsgFromPaths(pList)
	assert.Equal(t, len(sendMsg), 1)
	table.UpdatePathAttrs2ByteAs(sendMsg[0].Body.(*bgp.BGPUpdate))
	update := sendMsg[0].Body.(*bgp.BGPUpdate)
	assert.Equal(t, len(update.PathAttributes), 4)
	assert.Equal(t, reflect.TypeOf(update.PathAttributes[3]).String(), "*bgp.PathAttributeAs4Path")
	attr := update.PathAttributes[3].(*bgp.PathAttributeAs4Path)
	assert.Equal(t, len(attr.Value), 1)
	assert.Equal(t, attr.Value[0].AS, []uint32{66003, 70000})
	attrAS := update.PathAttributes[1].(*bgp.PathAttributeAsPath)
	assert.Equal(t, len(attrAS.Value), 1)
	assert.Equal(t, attrAS.Value[0].(*bgp.AsPathParam).AS, []uint16{bgp.AS_TRANS, 4000, bgp.AS_TRANS})

	rib2 := table.NewTableManager("peer_test")
	pList2, wList2, _ := rib2.ProcessPaths(pathList)
	assert.Equal(t, len(pList2), 1)
	assert.Equal(t, len(wList2), 0)
	sendMsg2 := table.CreateUpdateMsgFromPaths(pList2)
	assert.Equal(t, len(sendMsg2), 1)
	update2 := sendMsg2[0].Body.(*bgp.BGPUpdate)
	assert.Equal(t, len(update2.PathAttributes), 3)
	attrAS2 := update2.PathAttributes[1].(*bgp.PathAttributeAsPath)
	assert.Equal(t, len(attrAS2.Value), 1)
	assert.Equal(t, attrAS2.Value[0].(*bgp.As4PathParam).AS, []uint32{66003, 4000, 70000})
}
