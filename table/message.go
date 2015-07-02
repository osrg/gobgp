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
	"bytes"
	"github.com/osrg/gobgp/packet"
)

func UpdatePathAttrs2ByteAs(msg *bgp.BGPUpdate) error {
	var asAttr *bgp.PathAttributeAsPath
	idx := 0
	for i, attr := range msg.PathAttributes {
		switch attr.(type) {
		case *bgp.PathAttributeAsPath:
			asAttr = attr.(*bgp.PathAttributeAsPath)
			idx = i
		}
	}

	if asAttr == nil {
		return nil
	}

	msg.PathAttributes = cloneAttrSlice(msg.PathAttributes)
	asAttr = msg.PathAttributes[idx].(*bgp.PathAttributeAsPath)
	as4pathParam := make([]*bgp.As4PathParam, 0)
	newASparams := make([]bgp.AsPathParamInterface, len(asAttr.Value))
	for i, param := range asAttr.Value {
		asParam := param.(*bgp.As4PathParam)

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

		newASparams[i] = bgp.NewAsPathParam(asParam.Type, oldAs)
		if len(newAs) > 0 {
			as4pathParam = append(as4pathParam, bgp.NewAs4PathParam(asParam.Type, newAs))
		}
	}
	msg.PathAttributes[idx] = bgp.NewPathAttributeAsPath(newASparams)
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

	if asAttr == nil {
		return nil
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

func cloneAttrSlice(attrs []bgp.PathAttributeInterface) []bgp.PathAttributeInterface {
	clonedAttrs := make([]bgp.PathAttributeInterface, 0)
	clonedAttrs = append(clonedAttrs, attrs...)
	return clonedAttrs
}

func createUpdateMsgFromPath(path *Path, msg *bgp.BGPMessage) *bgp.BGPMessage {
	rf := path.GetRouteFamily()

	if rf == bgp.RF_IPv4_UC {
		if path.IsWithdraw {
			draw := path.GetNlri().(*bgp.WithdrawnRoute)
			if msg != nil {
				u := msg.Body.(*bgp.BGPUpdate)
				u.WithdrawnRoutes = append(u.WithdrawnRoutes, *draw)
				return nil
			} else {
				return bgp.NewBGPUpdateMessage([]bgp.WithdrawnRoute{*draw}, []bgp.PathAttributeInterface{}, []bgp.NLRInfo{})
			}
		} else {
			nlri := path.GetNlri().(*bgp.NLRInfo)
			if msg != nil {
				u := msg.Body.(*bgp.BGPUpdate)
				u.NLRI = append(u.NLRI, *nlri)
			} else {
				pathAttrs := path.getPathAttrs()
				return bgp.NewBGPUpdateMessage([]bgp.WithdrawnRoute{}, pathAttrs, []bgp.NLRInfo{*nlri})
			}
		}
	} else if rf == bgp.RF_IPv6_UC || rf == bgp.RF_EVPN || rf == bgp.RF_ENCAP || rf == bgp.RF_RTC_UC {
		if path.IsWithdraw {
			if msg != nil {
				idx, _ := path.getPathAttr(bgp.BGP_ATTR_TYPE_MP_UNREACH_NLRI)
				u := msg.Body.(*bgp.BGPUpdate)
				unreach := u.PathAttributes[idx].(*bgp.PathAttributeMpUnreachNLRI)
				unreach.Value = append(unreach.Value, path.GetNlri())
			} else {
				clonedAttrs := cloneAttrSlice(path.getPathAttrs())
				idx, attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
				reach := attr.(*bgp.PathAttributeMpReachNLRI)
				clonedAttrs[idx] = bgp.NewPathAttributeMpUnreachNLRI(reach.Value)
				return bgp.NewBGPUpdateMessage([]bgp.WithdrawnRoute{}, clonedAttrs, []bgp.NLRInfo{})
			}
		} else {
			if msg != nil {
				idx, _ := path.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
				u := msg.Body.(*bgp.BGPUpdate)
				reachAttr := u.PathAttributes[idx].(*bgp.PathAttributeMpReachNLRI)
				u.PathAttributes[idx] = bgp.NewPathAttributeMpReachNLRI(reachAttr.Nexthop.String(),
					append(reachAttr.Value, path.GetNlri()))
			} else {
				// we don't need to clone here but we
				// might merge path to this message in
				// the future so let's clone anyway.
				clonedAttrs := cloneAttrSlice(path.getPathAttrs())
				return bgp.NewBGPUpdateMessage([]bgp.WithdrawnRoute{}, clonedAttrs, []bgp.NLRInfo{})
			}
		}
	}
	return nil
}

func isSamePathAttrs(pList1 []bgp.PathAttributeInterface, pList2 []bgp.PathAttributeInterface) bool {
	if len(pList1) != len(pList2) {
		return false
	}
	for i, p1 := range pList1 {
		_, y := p1.(*bgp.PathAttributeMpReachNLRI)
		if y {
			continue
		}
		b1, _ := p1.Serialize()
		b2, _ := pList2[i].Serialize()

		if bytes.Compare(b1, b2) != 0 {
			return false
		}
	}
	return true
}

func isMergeable(p1, p2 *Path) bool {
	return false
	if p1 == nil {
		return false
	}
	if p1.GetRouteFamily() != bgp.RF_IPv4_UC {
		return false
	}
	if p1.GetSource().Equal(p2.GetSource()) && isSamePathAttrs(p1.getPathAttrs(), p2.getPathAttrs()) {
		return true
	}
	return false
}

func CreateUpdateMsgFromPaths(pathList []*Path) []*bgp.BGPMessage {
	var pre *Path
	var msgs []*bgp.BGPMessage
	for _, path := range pathList {
		y := isMergeable(pre, path)
		if y {
			msg := msgs[len(msgs)-1]
			createUpdateMsgFromPath(path, msg)
		} else {
			msg := createUpdateMsgFromPath(path, nil)
			pre = path
			msgs = append(msgs, msg)
		}
	}
	return msgs
}
