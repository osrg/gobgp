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
	"hash/fnv"
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
		nlri := path.GetNlri().(*bgp.IPAddrPrefix)
		if path.IsWithdraw {
			if msg != nil {
				u := msg.Body.(*bgp.BGPUpdate)
				u.WithdrawnRoutes = append(u.WithdrawnRoutes, nlri)
				return nil
			} else {
				return bgp.NewBGPUpdateMessage([]*bgp.IPAddrPrefix{nlri}, nil, nil)
			}
		} else {
			if msg != nil {
				u := msg.Body.(*bgp.BGPUpdate)
				u.NLRI = append(u.NLRI, nlri)
			} else {
				pathAttrs := path.GetPathAttrs()
				return bgp.NewBGPUpdateMessage(nil, pathAttrs, []*bgp.IPAddrPrefix{nlri})
			}
		}
	} else {
		if path.IsWithdraw {
			if msg != nil {
				idx, _ := path.getPathAttr(bgp.BGP_ATTR_TYPE_MP_UNREACH_NLRI)
				u := msg.Body.(*bgp.BGPUpdate)
				unreach := u.PathAttributes[idx].(*bgp.PathAttributeMpUnreachNLRI)
				unreach.Value = append(unreach.Value, path.GetNlri())
			} else {
				clonedAttrs := cloneAttrSlice(path.GetPathAttrs())
				idx, attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
				reach := attr.(*bgp.PathAttributeMpReachNLRI)
				clonedAttrs[idx] = bgp.NewPathAttributeMpUnreachNLRI(reach.Value)
				return bgp.NewBGPUpdateMessage(nil, clonedAttrs, nil)
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
				clonedAttrs := cloneAttrSlice(path.GetPathAttrs())
				return bgp.NewBGPUpdateMessage(nil, clonedAttrs, nil)
			}
		}
	}
	return nil
}

type bucket struct {
	attrs []byte
	paths []*Path
}

func CreateUpdateMsgFromPaths(pathList []*Path) []*bgp.BGPMessage {
	var msgs []*bgp.BGPMessage

	pathByAttrs := make(map[uint32][]*bucket)
	pathLen := len(pathList)
	for _, path := range pathList {
		y := func(p *Path) bool {
			// the merging logic makes gobgpd slower so if
			// paths are not many, let's avoid mering.
			if pathLen < 1024 {
				return false
			}
			if p.GetRouteFamily() != bgp.RF_IPv4_UC {
				return false
			}
			if p.IsWithdraw {
				return false
			}
			return true
		}(path)

		if y {
			key, attrs := func(p *Path) (uint32, []byte) {
				h := fnv.New32()
				total := bytes.NewBuffer(make([]byte, 0))
				for _, v := range p.GetPathAttrs() {
					b, _ := v.Serialize()
					total.Write(b)
				}
				h.Write(total.Bytes())
				return h.Sum32(), total.Bytes()
			}(path)

			if bl, y := pathByAttrs[key]; y {
				found := false
				for _, b := range bl {
					if bytes.Compare(b.attrs, attrs) == 0 {
						b.paths = append(b.paths, path)
						found = true
						break
					}
				}
				if found == false {
					nb := &bucket{
						attrs: attrs,
						paths: []*Path{path},
					}
					pathByAttrs[key] = append(pathByAttrs[key], nb)
				}
			} else {
				nb := &bucket{
					attrs: attrs,
					paths: []*Path{path},
				}
				pathByAttrs[key] = []*bucket{nb}
			}
		} else {
			msg := createUpdateMsgFromPath(path, nil)
			msgs = append(msgs, msg)
		}
	}

	for _, bList := range pathByAttrs {
		for _, b := range bList {
			var msg *bgp.BGPMessage
			for i, path := range b.paths {
				if i == 0 {
					msg = createUpdateMsgFromPath(path, nil)
					msgs = append(msgs, msg)
				} else {
					msgLen := func(u *bgp.BGPUpdate) int {
						attrsLen := 0
						for _, a := range u.PathAttributes {
							attrsLen += a.Len()
						}
						// Header + Update (WithdrawnRoutesLen +
						// TotalPathAttributeLen + attributes + maxlen of
						// NLRI). Note that we try to add one NLRI.
						return 19 + 2 + 2 + attrsLen + (len(u.NLRI)+1)*5
					}(msg.Body.(*bgp.BGPUpdate))

					if msgLen+32 > bgp.BGP_MAX_MESSAGE_LENGTH {
						// don't marge
						msg = createUpdateMsgFromPath(path, nil)
						msgs = append(msgs, msg)
					} else {
						createUpdateMsgFromPath(path, msg)
					}
				}
			}
		}
	}

	return msgs
}
