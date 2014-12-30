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
)

func UpdatePathAttrs2ByteAs(msg *bgp.BGPUpdate) error {
	var asAttr *bgp.PathAttributeAsPath
	for _, attr := range msg.PathAttributes {
		switch attr.(type) {
		case *bgp.PathAttributeAsPath:
			asAttr = attr.(*bgp.PathAttributeAsPath)
		}
	}

	as4pathParam := make([]*bgp.As4PathParam, 0)
	for i, param := range asAttr.Value {
		asParam, y := param.(*bgp.As4PathParam)
		if !y {
			continue
		}

		newAs := make([]uint32, 0)
		oldAs := make([]uint16, len(asParam.AS))
		for j := 0; j < len(asParam.AS); j++ {
			if asParam.AS[j] > (1<<16)-1 {
				oldAs[j] = bgp.AS_TRANS
				newAs = append(newAs, asParam.AS[j])
			} else {
				oldAs[j] = uint16(asParam.AS[j])
			}
		}
		asAttr.Value[i] = bgp.NewAsPathParam(asParam.Type, oldAs)
		if len(newAs) > 0 {
			as4pathParam = append(as4pathParam, bgp.NewAs4PathParam(asParam.Type, newAs))
		}
	}
	if len(as4pathParam) > 0 {
		msg.PathAttributes = append(msg.PathAttributes, bgp.NewPathAttributeAs4Path(as4pathParam))
	}
	return nil
}

func UpdatePathAttrs4ByteAs(msg *bgp.BGPUpdate) error {
	newPathAttrs := make([]bgp.PathAttributeInterface, 0)
	var asAttr *bgp.PathAttributeAsPath
	var as4Attr *bgp.PathAttributeAs4Path

	for _, attr := range msg.PathAttributes {
		switch attr.(type) {
		case *bgp.PathAttributeAsPath:
			asAttr = attr.(*bgp.PathAttributeAsPath)
			newPathAttrs = append(newPathAttrs, attr)
		case *bgp.PathAttributeAs4Path:
			as4Attr = attr.(*bgp.PathAttributeAs4Path)
		default:
			newPathAttrs = append(newPathAttrs, attr)
		}
	}

	AS := make([]uint32, 0)
	if as4Attr != nil {
		for _, p := range as4Attr.Value {
			AS = append(AS, p.AS...)
		}
		msg.PathAttributes = newPathAttrs
	}

	transIdx := 0
	for i, param := range asAttr.Value {
		asParam, y := param.(*bgp.AsPathParam)
		if !y {
			continue
		}

		newAS := make([]uint32, len(asParam.AS))
		for j := 0; j < len(asParam.AS); j++ {
			if asParam.AS[j] == bgp.AS_TRANS {
				if transIdx == len(AS) {
					//return error
				}
				newAS[j] = AS[transIdx]
				transIdx++
			} else {
				newAS[j] = uint32(asParam.AS[j])
			}
		}
		asAttr.Value[i] = bgp.NewAs4PathParam(asParam.Type, newAS)
	}
	if len(AS) != transIdx {
		//return error
	}
	return nil
}
