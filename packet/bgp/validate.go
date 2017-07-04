package bgp

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

// Validator for BGPUpdate
func ValidateUpdateMsg(m *BGPUpdate, rfs map[RouteFamily]BGPAddPathMode, doConfedCheck bool) (bool, error) {
	eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
	eSubCodeAttrList := uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST)
	eSubCodeMissing := uint8(BGP_ERROR_SUB_MISSING_WELL_KNOWN_ATTRIBUTE)

	if len(m.NLRI) > 0 || len(m.WithdrawnRoutes) > 0 {
		if _, ok := rfs[RF_IPv4_UC]; !ok {
			return false, NewMessageError(0, 0, nil, fmt.Sprintf("Address-family rf %d not avalible for session", RF_IPv4_UC))
		}
	}

	seen := make(map[BGPAttrType]PathAttributeInterface)
	// check path attribute
	for _, a := range m.PathAttributes {
		// check duplication
		if _, ok := seen[a.GetType()]; !ok {
			seen[a.GetType()] = a
		} else {
			eMsg := "the path attribute apears twice. Type : " + strconv.Itoa(int(a.GetType()))
			return false, NewMessageError(eCode, eSubCodeAttrList, nil, eMsg)
		}

		//check specific path attribute
		ok, e := ValidateAttribute(a, rfs, doConfedCheck)
		if !ok {
			return false, e
		}
	}

	if len(m.NLRI) > 0 {
		// check the existence of well-known mandatory attributes
		exist := func(attrs []BGPAttrType) (bool, BGPAttrType) {
			for _, attr := range attrs {
				_, ok := seen[attr]
				if !ok {
					return false, attr
				}
			}
			return true, 0
		}
		mandatory := []BGPAttrType{BGP_ATTR_TYPE_ORIGIN, BGP_ATTR_TYPE_AS_PATH, BGP_ATTR_TYPE_NEXT_HOP}
		if ok, t := exist(mandatory); !ok {
			eMsg := "well-known mandatory attributes are not present. type : " + strconv.Itoa(int(t))
			data := []byte{byte(t)}
			return false, NewMessageError(eCode, eSubCodeMissing, data, eMsg)
		}
	}
	return true, nil
}

func ValidateAttribute(a PathAttributeInterface, rfs map[RouteFamily]BGPAddPathMode, doConfedCheck bool) (bool, error) {

	eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
	eSubCodeBadOrigin := uint8(BGP_ERROR_SUB_INVALID_ORIGIN_ATTRIBUTE)
	eSubCodeBadNextHop := uint8(BGP_ERROR_SUB_INVALID_NEXT_HOP_ATTRIBUTE)
	eSubCodeUnknown := uint8(BGP_ERROR_SUB_UNRECOGNIZED_WELL_KNOWN_ATTRIBUTE)
	eSubCodeMalformedAspath := uint8(BGP_ERROR_SUB_MALFORMED_AS_PATH)

	checkPrefix := func(l []AddrPrefixInterface) error {
		for _, prefix := range l {
			rf := AfiSafiToRouteFamily(prefix.AFI(), prefix.SAFI())
			if _, ok := rfs[rf]; !ok {
				return NewMessageError(0, 0, nil, fmt.Sprintf("Address-family %s not avalible for this session", rf))
			}
			switch rf {
			case RF_FS_IPv4_UC, RF_FS_IPv6_UC, RF_FS_IPv4_VPN, RF_FS_IPv6_VPN, RF_FS_L2_VPN:
				t := BGPFlowSpecType(0)
				value := make([]FlowSpecComponentInterface, 0)
				switch rf {
				case RF_FS_IPv4_UC:
					value = prefix.(*FlowSpecIPv4Unicast).Value
				case RF_FS_IPv6_UC:
					value = prefix.(*FlowSpecIPv6Unicast).Value
				case RF_FS_IPv4_VPN:
					value = prefix.(*FlowSpecIPv4VPN).Value
				case RF_FS_IPv6_VPN:
					value = prefix.(*FlowSpecIPv6VPN).Value
				case RF_FS_L2_VPN:
					value = prefix.(*FlowSpecL2VPN).Value
				}
				for _, v := range value {
					if v.Type() <= t {
						return NewMessageError(0, 0, nil, fmt.Sprintf("%s nlri violate strict type ordering", rf))
					}
					t = v.Type()
				}
			}
		}
		return nil
	}

	switch p := a.(type) {
	case *PathAttributeMpUnreachNLRI:
		rf := AfiSafiToRouteFamily(p.AFI, p.SAFI)
		if _, ok := rfs[rf]; !ok {
			return false, NewMessageError(0, 0, nil, fmt.Sprintf("Address-family rf %d not avalible for session", rf))
		}
		if err := checkPrefix(p.Value); err != nil {
			return false, err
		}
	case *PathAttributeMpReachNLRI:
		rf := AfiSafiToRouteFamily(p.AFI, p.SAFI)
		if _, ok := rfs[rf]; !ok {
			return false, NewMessageError(0, 0, nil, fmt.Sprintf("Address-family rf %d not avalible for session", rf))
		}
		if err := checkPrefix(p.Value); err != nil {
			return false, err
		}
	case *PathAttributeOrigin:
		v := uint8(p.Value[0])
		if v != BGP_ORIGIN_ATTR_TYPE_IGP &&
			v != BGP_ORIGIN_ATTR_TYPE_EGP &&
			v != BGP_ORIGIN_ATTR_TYPE_INCOMPLETE {
			data, _ := a.Serialize()
			eMsg := "invalid origin attribute. value : " + strconv.Itoa(int(v))
			return false, NewMessageError(eCode, eSubCodeBadOrigin, data, eMsg)
		}
	case *PathAttributeNextHop:

		isZero := func(ip net.IP) bool {
			res := ip[0] & 0xff
			return res == 0x00
		}

		isClassDorE := func(ip net.IP) bool {
			res := ip[0] & 0xe0
			return res == 0xe0
		}

		//check IP address represents host address
		if p.Value.IsLoopback() || isZero(p.Value) || isClassDorE(p.Value) {
			eMsg := "invalid nexthop address"
			data, _ := a.Serialize()
			return false, NewMessageError(eCode, eSubCodeBadNextHop, data, eMsg)
		}
	case *PathAttributeAsPath:
		if doConfedCheck {
			for _, paramIf := range p.Value {
				var segType uint8
				asParam, y := paramIf.(*As4PathParam)
				if y {
					segType = asParam.Type
				} else {
					segType = paramIf.(*AsPathParam).Type
				}

				if segType == BGP_ASPATH_ATTR_TYPE_CONFED_SET || segType == BGP_ASPATH_ATTR_TYPE_CONFED_SEQ {
					return false, NewMessageError(eCode, eSubCodeMalformedAspath, nil, fmt.Sprintf("segment type confederation(%d) found", segType))
				}
			}
		}
	case *PathAttributeLargeCommunities:
		uniq := make([]*LargeCommunity, 0, len(p.Values))
		for _, x := range p.Values {
			found := false
			for _, y := range uniq {
				if x.String() == y.String() {
					found = true
					break
				}
			}
			if !found {
				uniq = append(uniq, x)
			}
		}
		p.Values = uniq

	case *PathAttributeUnknown:
		if p.GetFlags()&BGP_ATTR_FLAG_OPTIONAL == 0 {
			eMsg := fmt.Sprintf("unrecognized well-known attribute %s", p.GetType())
			data, _ := a.Serialize()
			return false, NewMessageError(eCode, eSubCodeUnknown, data, eMsg)
		}
	}

	return true, nil

}

// validator for PathAttribute
func ValidateFlags(t BGPAttrType, flags BGPAttrFlag) (bool, string) {

	/*
	 * RFC 4271 P.17 For well-known attributes, the Transitive bit MUST be set to 1.
	 */
	if flags&BGP_ATTR_FLAG_OPTIONAL == 0 && flags&BGP_ATTR_FLAG_TRANSITIVE == 0 {
		eMsg := fmt.Sprintf("well-known attribute %s must have transitive flag 1", t)
		return false, eMsg
	}
	/*
	 * RFC 4271 P.17 For well-known attributes and for optional non-transitive attributes,
	 * the Partial bit MUST be set to 0.
	 */
	if flags&BGP_ATTR_FLAG_OPTIONAL == 0 && flags&BGP_ATTR_FLAG_PARTIAL != 0 {
		eMsg := fmt.Sprintf("well-known attribute %s must have partial bit 0", t)
		return false, eMsg
	}
	if flags&BGP_ATTR_FLAG_OPTIONAL != 0 && flags&BGP_ATTR_FLAG_TRANSITIVE == 0 && flags&BGP_ATTR_FLAG_PARTIAL != 0 {
		eMsg := fmt.Sprintf("optional non-transitive attribute %s must have partial bit 0", t)
		return false, eMsg
	}

	// check flags are correct
	if f, ok := PathAttrFlags[t]; ok {
		if f != flags & ^BGP_ATTR_FLAG_EXTENDED_LENGTH & ^BGP_ATTR_FLAG_PARTIAL {
			eMsg := fmt.Sprintf("flags are invalid. attribute type: %s, expect: %s, actual: %s", t, f, flags)
			return false, eMsg
		}
	}
	return true, ""
}

func ValidateBGPMessage(m *BGPMessage) error {
	if m.Header.Len > BGP_MAX_MESSAGE_LENGTH {
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, m.Header.Len)
		return NewMessageError(BGP_ERROR_MESSAGE_HEADER_ERROR, BGP_ERROR_SUB_BAD_MESSAGE_LENGTH, buf, "too long length")
	}

	return nil
}

func ValidateOpenMsg(m *BGPOpen, expectedAS uint32) (uint32, error) {
	if m.Version != 4 {
		return 0, NewMessageError(BGP_ERROR_OPEN_MESSAGE_ERROR, BGP_ERROR_SUB_UNSUPPORTED_VERSION_NUMBER, nil, fmt.Sprintf("upsuppored version %d", m.Version))
	}

	as := uint32(m.MyAS)
	for _, p := range m.OptParams {
		paramCap, y := p.(*OptionParameterCapability)
		if !y {
			continue
		}
		for _, c := range paramCap.Capability {
			if c.Code() == BGP_CAP_FOUR_OCTET_AS_NUMBER {
				cap := c.(*CapFourOctetASNumber)
				as = cap.CapValue
			}
		}
	}
	if expectedAS != 0 && as != expectedAS {
		return 0, NewMessageError(BGP_ERROR_OPEN_MESSAGE_ERROR, BGP_ERROR_SUB_BAD_PEER_AS, nil, fmt.Sprintf("as number mismatch expected %d, received %d", expectedAS, as))
	}

	if m.HoldTime < 3 && m.HoldTime != 0 {
		return 0, NewMessageError(BGP_ERROR_OPEN_MESSAGE_ERROR, BGP_ERROR_SUB_UNACCEPTABLE_HOLD_TIME, nil, fmt.Sprintf("unacceptable hold time %d", m.HoldTime))
	}
	return as, nil
}
