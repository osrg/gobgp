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

package bgp

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

const (
	AFI_IP     = 1
	AFI_IP6    = 2
	AFI_L2VPN  = 25
	AFI_OPAQUE = 16397
)

const (
	SAFI_UNICAST                  = 1
	SAFI_MULTICAST                = 2
	SAFI_MPLS_LABEL               = 4
	SAFI_ENCAPSULATION            = 7
	SAFI_VPLS                     = 65
	SAFI_EVPN                     = 70
	SAFI_MPLS_VPN                 = 128
	SAFI_MPLS_VPN_MULTICAST       = 129
	SAFI_ROUTE_TARGET_CONSTRAINTS = 132
	SAFI_FLOW_SPEC_UNICAST        = 133
	SAFI_FLOW_SPEC_VPN            = 134
	SAFI_KEY_VALUE                = 241
)

const (
	BGP_ORIGIN_ATTR_TYPE_IGP        = 0
	BGP_ORIGIN_ATTR_TYPE_EGP        = 1
	BGP_ORIGIN_ATTR_TYPE_INCOMPLETE = 2
)

const (
	BGP_ASPATH_ATTR_TYPE_SET        = 1
	BGP_ASPATH_ATTR_TYPE_SEQ        = 2
	BGP_ASPATH_ATTR_TYPE_CONFED_SEQ = 3
	BGP_ASPATH_ATTR_TYPE_CONFED_SET = 4
)

// RFC7153 5.1. Registries for the "Type" Field
// RANGE	REGISTRATION PROCEDURES
// 0x00-0x3F	Transitive First Come First Served
// 0x40-0x7F	Non-Transitive First Come First Served
// 0x80-0x8F	Transitive Experimental Use
// 0x90-0xBF	Transitive Standards Action
// 0xC0-0xCF	Non-Transitive Experimental Use
// 0xD0-0xFF	Non-Transitive Standards Action
type ExtendedCommunityAttrType uint8

const (
	EC_TYPE_TRANSITIVE_TWO_OCTET_AS_SPECIFIC      ExtendedCommunityAttrType = 0x00
	EC_TYPE_TRANSITIVE_IP6_SPECIFIC               ExtendedCommunityAttrType = 0x00 // RFC5701
	EC_TYPE_TRANSITIVE_IP4_SPECIFIC               ExtendedCommunityAttrType = 0x01
	EC_TYPE_TRANSITIVE_FOUR_OCTET_AS_SPECIFIC     ExtendedCommunityAttrType = 0x02
	EC_TYPE_TRANSITIVE_OPAQUE                     ExtendedCommunityAttrType = 0x03
	EC_TYPE_TRANSITIVE_QOS_MARKING                ExtendedCommunityAttrType = 0x04
	EC_TYPE_COS_CAPABILITY                        ExtendedCommunityAttrType = 0x05
	EC_TYPE_EVPN                                  ExtendedCommunityAttrType = 0x06
	EC_TYPE_FLOWSPEC_REDIRECT_MIRROR              ExtendedCommunityAttrType = 0x08
	EC_TYPE_NON_TRANSITIVE_TWO_OCTET_AS_SPECIFIC  ExtendedCommunityAttrType = 0x40
	EC_TYPE_NON_TRANSITIVE_IP6_SPECIFIC           ExtendedCommunityAttrType = 0x40 // RFC5701
	EC_TYPE_NON_TRANSITIVE_IP4_SPECIFIC           ExtendedCommunityAttrType = 0x41
	EC_TYPE_NON_TRANSITIVE_FOUR_OCTET_AS_SPECIFIC ExtendedCommunityAttrType = 0x42
	EC_TYPE_NON_TRANSITIVE_OPAQUE                 ExtendedCommunityAttrType = 0x43
	EC_TYPE_NON_TRANSITIVE_QOS_MARKING            ExtendedCommunityAttrType = 0x44
	EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL       ExtendedCommunityAttrType = 0x80
	EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL2      ExtendedCommunityAttrType = 0x81 // RFC7674
	EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL3      ExtendedCommunityAttrType = 0x82 // RFC7674
)

// RFC7153 5.2. Registries for the "Sub-Type" Field
// RANGE	REGISTRATION PROCEDURES
// 0x00-0xBF	First Come First Served
// 0xC0-0xFF	IETF Review
type ExtendedCommunityAttrSubType uint8

const (
	EC_SUBTYPE_ROUTE_TARGET            ExtendedCommunityAttrSubType = 0x02 // EC_TYPE: 0x00, 0x01, 0x02
	EC_SUBTYPE_ROUTE_ORIGIN            ExtendedCommunityAttrSubType = 0x03 // EC_TYPE: 0x00, 0x01, 0x02
	EC_SUBTYPE_LINK_BANDWIDTH          ExtendedCommunityAttrSubType = 0x04 // EC_TYPE: 0x40
	EC_SUBTYPE_GENERIC                 ExtendedCommunityAttrSubType = 0x04 // EC_TYPE: 0x02, 0x42
	EC_SUBTYPE_OSPF_DOMAIN_ID          ExtendedCommunityAttrSubType = 0x05 // EC_TYPE: 0x00, 0x01, 0x02
	EC_SUBTYPE_OSPF_ROUTE_ID           ExtendedCommunityAttrSubType = 0x07 // EC_TYPE: 0x01
	EC_SUBTYPE_BGP_DATA_COLLECTION     ExtendedCommunityAttrSubType = 0x08 // EC_TYPE: 0x00, 0x02
	EC_SUBTYPE_SOURCE_AS               ExtendedCommunityAttrSubType = 0x09 // EC_TYPE: 0x00, 0x02
	EC_SUBTYPE_L2VPN_ID                ExtendedCommunityAttrSubType = 0x0A // EC_TYPE: 0x00, 0x01
	EC_SUBTYPE_VRF_ROUTE_IMPORT        ExtendedCommunityAttrSubType = 0x0B // EC_TYPE: 0x01
	EC_SUBTYPE_CISCO_VPN_DISTINGUISHER ExtendedCommunityAttrSubType = 0x10 // EC_TYPE: 0x00, 0x01, 0x02

	EC_SUBTYPE_OSPF_ROUTE_TYPE ExtendedCommunityAttrSubType = 0x06 // EC_TYPE: 0x03
	EC_SUBTYPE_COLOR           ExtendedCommunityAttrSubType = 0x0B // EC_TYPE: 0x03
	EC_SUBTYPE_ENCAPSULATION   ExtendedCommunityAttrSubType = 0x0C // EC_TYPE: 0x03
	EC_SUBTYPE_DEFAULT_GATEWAY ExtendedCommunityAttrSubType = 0x0D // EC_TYPE: 0x03

	EC_SUBTYPE_ORIGIN_VALIDATION ExtendedCommunityAttrSubType = 0x00 // EC_TYPE: 0x43

	EC_SUBTYPE_FLOWSPEC_TRAFFIC_RATE   ExtendedCommunityAttrSubType = 0x06 // EC_TYPE: 0x80
	EC_SUBTYPE_FLOWSPEC_TRAFFIC_ACTION ExtendedCommunityAttrSubType = 0x07 // EC_TYPE: 0x80
	EC_SUBTYPE_FLOWSPEC_REDIRECT       ExtendedCommunityAttrSubType = 0x08 // EC_TYPE: 0x80
	EC_SUBTYPE_FLOWSPEC_TRAFFIC_REMARK ExtendedCommunityAttrSubType = 0x09 // EC_TYPE: 0x80
	EC_SUBTYPE_L2_INFO                 ExtendedCommunityAttrSubType = 0x0A // EC_TYPE: 0x80
	EC_SUBTYPE_FLOWSPEC_REDIRECT_IP6   ExtendedCommunityAttrSubType = 0x0B // EC_TYPE: 0x80

	EC_SUBTYPE_MAC_MOBILITY ExtendedCommunityAttrSubType = 0x00 // EC_TYPE: 0x06
	EC_SUBTYPE_ESI_LABEL    ExtendedCommunityAttrSubType = 0x01 // EC_TYPE: 0x06
	EC_SUBTYPE_ES_IMPORT    ExtendedCommunityAttrSubType = 0x02 // EC_TYPE: 0x06

	EC_SUBTYPE_UUID_BASED_RT ExtendedCommunityAttrSubType = 0x11
)

type TunnelType uint16

const (
	TUNNEL_TYPE_L2TP3       TunnelType = 1
	TUNNEL_TYPE_GRE         TunnelType = 2
	TUNNEL_TYPE_IP_IN_IP    TunnelType = 7
	TUNNEL_TYPE_VXLAN       TunnelType = 8
	TUNNEL_TYPE_NVGRE       TunnelType = 9
	TUNNEL_TYPE_MPLS        TunnelType = 10
	TUNNEL_TYPE_MPLS_IN_GRE TunnelType = 11
	TUNNEL_TYPE_VXLAN_GRE   TunnelType = 12
	TUNNEL_TYPE_MPLS_IN_UDP TunnelType = 13
)

type PmsiTunnelType uint8

const (
	PMSI_TUNNEL_TYPE_NO_TUNNEL      PmsiTunnelType = 0
	PMSI_TUNNEL_TYPE_RSVP_TE_P2MP   PmsiTunnelType = 1
	PMSI_TUNNEL_TYPE_MLDP_P2MP      PmsiTunnelType = 2
	PMSI_TUNNEL_TYPE_PIM_SSM_TREE   PmsiTunnelType = 3
	PMSI_TUNNEL_TYPE_PIM_SM_TREE    PmsiTunnelType = 4
	PMSI_TUNNEL_TYPE_BIDIR_PIM_TREE PmsiTunnelType = 5
	PMSI_TUNNEL_TYPE_INGRESS_REPL   PmsiTunnelType = 6
	PMSI_TUNNEL_TYPE_MLDP_MP2MP     PmsiTunnelType = 7
)

func (p PmsiTunnelType) String() string {
	switch p {
	case PMSI_TUNNEL_TYPE_NO_TUNNEL:
		return "no-tunnel"
	case PMSI_TUNNEL_TYPE_RSVP_TE_P2MP:
		return "rsvp-te-p2mp"
	case PMSI_TUNNEL_TYPE_MLDP_P2MP:
		return "mldp-p2mp"
	case PMSI_TUNNEL_TYPE_PIM_SSM_TREE:
		return "pim-ssm-tree"
	case PMSI_TUNNEL_TYPE_PIM_SM_TREE:
		return "pim-sm-tree"
	case PMSI_TUNNEL_TYPE_BIDIR_PIM_TREE:
		return "bidir-pim-tree"
	case PMSI_TUNNEL_TYPE_INGRESS_REPL:
		return "ingress-repl"
	case PMSI_TUNNEL_TYPE_MLDP_MP2MP:
		return "mldp-mp2mp"
	default:
		return fmt.Sprintf("PmsiTunnelType(%d)", uint8(p))
	}
}

type EncapSubTLVType uint8

const (
	ENCAP_SUBTLV_TYPE_ENCAPSULATION EncapSubTLVType = 1
	ENCAP_SUBTLV_TYPE_PROTOCOL      EncapSubTLVType = 2
	ENCAP_SUBTLV_TYPE_COLOR         EncapSubTLVType = 4
)

const (
	_ = iota
	BGP_MSG_OPEN
	BGP_MSG_UPDATE
	BGP_MSG_NOTIFICATION
	BGP_MSG_KEEPALIVE
	BGP_MSG_ROUTE_REFRESH
)

const (
	BGP_OPT_CAPABILITY = 2
)

type BGPCapabilityCode uint8

const (
	BGP_CAP_MULTIPROTOCOL               BGPCapabilityCode = 1
	BGP_CAP_ROUTE_REFRESH               BGPCapabilityCode = 2
	BGP_CAP_CARRYING_LABEL_INFO         BGPCapabilityCode = 4
	BGP_CAP_EXTENDED_NEXTHOP            BGPCapabilityCode = 5
	BGP_CAP_GRACEFUL_RESTART            BGPCapabilityCode = 64
	BGP_CAP_FOUR_OCTET_AS_NUMBER        BGPCapabilityCode = 65
	BGP_CAP_ADD_PATH                    BGPCapabilityCode = 69
	BGP_CAP_ENHANCED_ROUTE_REFRESH      BGPCapabilityCode = 70
	BGP_CAP_ROUTE_REFRESH_CISCO         BGPCapabilityCode = 128
	BGP_CAP_LONG_LIVED_GRACEFUL_RESTART BGPCapabilityCode = 129
)

var CapNameMap = map[BGPCapabilityCode]string{
	BGP_CAP_MULTIPROTOCOL:               "multiprotocol",
	BGP_CAP_ROUTE_REFRESH:               "route-refresh",
	BGP_CAP_CARRYING_LABEL_INFO:         "carrying-label-info",
	BGP_CAP_GRACEFUL_RESTART:            "graceful-restart",
	BGP_CAP_EXTENDED_NEXTHOP:            "extended-nexthop",
	BGP_CAP_FOUR_OCTET_AS_NUMBER:        "4-octet-as",
	BGP_CAP_ADD_PATH:                    "add-path",
	BGP_CAP_ENHANCED_ROUTE_REFRESH:      "enhanced-route-refresh",
	BGP_CAP_ROUTE_REFRESH_CISCO:         "cisco-route-refresh",
	BGP_CAP_LONG_LIVED_GRACEFUL_RESTART: "long-lived-graceful-restart",
}

func (c BGPCapabilityCode) String() string {
	if n, y := CapNameMap[c]; y {
		return n
	}
	return fmt.Sprintf("UnknownCapability(%d)", c)
}

type ParameterCapabilityInterface interface {
	DecodeFromBytes([]byte) error
	Serialize() ([]byte, error)
	Len() int
	Code() BGPCapabilityCode
}

type DefaultParameterCapability struct {
	CapCode  BGPCapabilityCode `json:"code"`
	CapLen   uint8             `json:"-"`
	CapValue []byte            `json:"value,omitempty"`
}

func (c *DefaultParameterCapability) Code() BGPCapabilityCode {
	return c.CapCode
}

func (c *DefaultParameterCapability) DecodeFromBytes(data []byte) error {
	c.CapCode = BGPCapabilityCode(data[0])
	c.CapLen = data[1]
	if len(data) < 2+int(c.CapLen) {
		return NewMessageError(BGP_ERROR_OPEN_MESSAGE_ERROR, BGP_ERROR_SUB_UNSUPPORTED_CAPABILITY, nil, "Not all OptionParameterCapability bytes available")
	}
	if c.CapLen > 0 {
		c.CapValue = data[2 : 2+c.CapLen]
	}
	return nil
}

func (c *DefaultParameterCapability) Serialize() ([]byte, error) {
	c.CapLen = uint8(len(c.CapValue))
	buf := make([]byte, 2)
	buf[0] = uint8(c.CapCode)
	buf[1] = c.CapLen
	buf = append(buf, c.CapValue...)
	return buf, nil
}

func (c *DefaultParameterCapability) Len() int {
	return int(c.CapLen + 2)
}

type CapMultiProtocol struct {
	DefaultParameterCapability
	CapValue RouteFamily
}

func (c *CapMultiProtocol) DecodeFromBytes(data []byte) error {
	c.DefaultParameterCapability.DecodeFromBytes(data)
	data = data[2:]
	if len(data) < 4 {
		return NewMessageError(BGP_ERROR_OPEN_MESSAGE_ERROR, BGP_ERROR_SUB_UNSUPPORTED_CAPABILITY, nil, "Not all CapabilityMultiProtocol bytes available")
	}
	c.CapValue = AfiSafiToRouteFamily(binary.BigEndian.Uint16(data[0:2]), data[3])
	return nil
}

func (c *CapMultiProtocol) Serialize() ([]byte, error) {
	buf := make([]byte, 4)
	afi, safi := RouteFamilyToAfiSafi(c.CapValue)
	binary.BigEndian.PutUint16(buf[0:], afi)
	buf[3] = safi
	c.DefaultParameterCapability.CapValue = buf
	return c.DefaultParameterCapability.Serialize()
}

func (c *CapMultiProtocol) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Code  BGPCapabilityCode `json:"code"`
		Value RouteFamily       `json:"value"`
	}{
		Code:  c.Code(),
		Value: c.CapValue,
	})
}

func NewCapMultiProtocol(rf RouteFamily) *CapMultiProtocol {
	return &CapMultiProtocol{
		DefaultParameterCapability{
			CapCode: BGP_CAP_MULTIPROTOCOL,
		},
		rf,
	}
}

type CapRouteRefresh struct {
	DefaultParameterCapability
}

func NewCapRouteRefresh() *CapRouteRefresh {
	return &CapRouteRefresh{
		DefaultParameterCapability{
			CapCode: BGP_CAP_ROUTE_REFRESH,
		},
	}
}

type CapCarryingLabelInfo struct {
	DefaultParameterCapability
}

type CapExtendedNexthopTuple struct {
	NLRIAFI    uint16
	NLRISAFI   uint16
	NexthopAFI uint16
}

func (c *CapExtendedNexthopTuple) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		NLRIAddressFamily    RouteFamily `json:"nlri_address_family"`
		NexthopAddressFamily uint16      `json:"nexthop_address_family"`
	}{
		NLRIAddressFamily:    AfiSafiToRouteFamily(c.NLRIAFI, uint8(c.NLRISAFI)),
		NexthopAddressFamily: c.NexthopAFI,
	})
}

func NewCapExtendedNexthopTuple(af RouteFamily, nexthop uint16) *CapExtendedNexthopTuple {
	afi, safi := RouteFamilyToAfiSafi(af)
	return &CapExtendedNexthopTuple{
		NLRIAFI:    afi,
		NLRISAFI:   uint16(safi),
		NexthopAFI: nexthop,
	}
}

type CapExtendedNexthop struct {
	DefaultParameterCapability
	Tuples []*CapExtendedNexthopTuple
}

func (c *CapExtendedNexthop) DecodeFromBytes(data []byte) error {
	c.DefaultParameterCapability.DecodeFromBytes(data)
	data = data[2:]
	if len(data) < 6 {
		return NewMessageError(BGP_ERROR_OPEN_MESSAGE_ERROR, BGP_ERROR_SUB_UNSUPPORTED_CAPABILITY, nil, "Not all CapabilityExtendedNexthop bytes available")
	}
	c.Tuples = []*CapExtendedNexthopTuple{}
	for len(data) >= 6 {
		t := &CapExtendedNexthopTuple{
			binary.BigEndian.Uint16(data[0:2]),
			binary.BigEndian.Uint16(data[2:4]),
			binary.BigEndian.Uint16(data[4:6]),
		}
		c.Tuples = append(c.Tuples, t)
		data = data[6:]
	}
	return nil
}

func (c *CapExtendedNexthop) Serialize() ([]byte, error) {
	buf := make([]byte, len(c.Tuples)*6)
	for i, t := range c.Tuples {
		binary.BigEndian.PutUint16(buf[i*6:i*6+2], t.NLRIAFI)
		binary.BigEndian.PutUint16(buf[i*6+2:i*6+4], t.NLRISAFI)
		binary.BigEndian.PutUint16(buf[i*6+4:i*6+6], t.NexthopAFI)
	}
	c.DefaultParameterCapability.CapValue = buf
	return c.DefaultParameterCapability.Serialize()
}

func (c *CapExtendedNexthop) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Code   BGPCapabilityCode          `json:"code"`
		Tuples []*CapExtendedNexthopTuple `json:"tuples"`
	}{
		Code:   c.Code(),
		Tuples: c.Tuples,
	})
}

func NewCapExtendedNexthop(tuples []*CapExtendedNexthopTuple) *CapExtendedNexthop {
	return &CapExtendedNexthop{
		DefaultParameterCapability{
			CapCode: BGP_CAP_EXTENDED_NEXTHOP,
		},
		tuples,
	}
}

type CapGracefulRestartTuple struct {
	AFI   uint16
	SAFI  uint8
	Flags uint8
}

func (c *CapGracefulRestartTuple) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RouteFamily RouteFamily `json:"route_family"`
		Flags       uint8       `json:"flags"`
	}{
		RouteFamily: AfiSafiToRouteFamily(c.AFI, c.SAFI),
		Flags:       c.Flags,
	})
}

func NewCapGracefulRestartTuple(rf RouteFamily, forward bool) *CapGracefulRestartTuple {
	afi, safi := RouteFamilyToAfiSafi(rf)
	flags := 0
	if forward {
		flags = 0x80
	}
	return &CapGracefulRestartTuple{
		AFI:   afi,
		SAFI:  safi,
		Flags: uint8(flags),
	}
}

type CapGracefulRestart struct {
	DefaultParameterCapability
	Flags  uint8
	Time   uint16
	Tuples []*CapGracefulRestartTuple
}

func (c *CapGracefulRestart) DecodeFromBytes(data []byte) error {
	c.DefaultParameterCapability.DecodeFromBytes(data)
	data = data[2:]
	if len(data) < 2 {
		return NewMessageError(BGP_ERROR_OPEN_MESSAGE_ERROR, BGP_ERROR_SUB_UNSUPPORTED_CAPABILITY, nil, "Not all CapabilityGracefulRestart bytes available")
	}
	restart := binary.BigEndian.Uint16(data[0:2])
	c.Flags = uint8(restart >> 12)
	c.Time = restart & 0xfff
	data = data[2:]

	valueLen := int(c.CapLen) - 2

	if valueLen >= 4 && len(data) >= valueLen {
		c.Tuples = make([]*CapGracefulRestartTuple, 0, valueLen/4)

		for i := valueLen; i >= 4; i -= 4 {
			t := &CapGracefulRestartTuple{binary.BigEndian.Uint16(data[0:2]),
				data[2], data[3]}
			c.Tuples = append(c.Tuples, t)
			data = data[4:]
		}
	}
	return nil
}

func (c *CapGracefulRestart) Serialize() ([]byte, error) {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf[0:], uint16(c.Flags)<<12|c.Time)
	for _, t := range c.Tuples {
		tbuf := make([]byte, 4)
		binary.BigEndian.PutUint16(tbuf[0:2], t.AFI)
		tbuf[2] = t.SAFI
		tbuf[3] = t.Flags
		buf = append(buf, tbuf...)
	}
	c.DefaultParameterCapability.CapValue = buf
	return c.DefaultParameterCapability.Serialize()
}

func (c *CapGracefulRestart) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Code   BGPCapabilityCode          `json:"code"`
		Flags  uint8                      `json:"flags"`
		Time   uint16                     `json:"time"`
		Tuples []*CapGracefulRestartTuple `json:"tuples"`
	}{
		Code:   c.Code(),
		Flags:  c.Flags,
		Time:   c.Time,
		Tuples: c.Tuples,
	})
}

func NewCapGracefulRestart(restarting, notification bool, time uint16, tuples []*CapGracefulRestartTuple) *CapGracefulRestart {
	flags := 0
	if restarting {
		flags = 0x08
	}
	if notification {
		flags |= 0x04
	}
	return &CapGracefulRestart{
		DefaultParameterCapability: DefaultParameterCapability{
			CapCode: BGP_CAP_GRACEFUL_RESTART,
		},
		Flags:  uint8(flags),
		Time:   time,
		Tuples: tuples,
	}
}

type CapFourOctetASNumber struct {
	DefaultParameterCapability
	CapValue uint32
}

func (c *CapFourOctetASNumber) DecodeFromBytes(data []byte) error {
	c.DefaultParameterCapability.DecodeFromBytes(data)
	data = data[2:]
	if len(data) < 4 {
		return NewMessageError(BGP_ERROR_OPEN_MESSAGE_ERROR, BGP_ERROR_SUB_UNSUPPORTED_CAPABILITY, nil, "Not all CapabilityFourOctetASNumber bytes available")
	}
	c.CapValue = binary.BigEndian.Uint32(data[0:4])
	return nil
}

func (c *CapFourOctetASNumber) Serialize() ([]byte, error) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, c.CapValue)
	c.DefaultParameterCapability.CapValue = buf
	return c.DefaultParameterCapability.Serialize()
}

func (c *CapFourOctetASNumber) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Code  BGPCapabilityCode `json:"code"`
		Value uint32            `json:"value"`
	}{
		Code:  c.Code(),
		Value: c.CapValue,
	})
}

func NewCapFourOctetASNumber(asnum uint32) *CapFourOctetASNumber {
	return &CapFourOctetASNumber{
		DefaultParameterCapability{
			CapCode: BGP_CAP_FOUR_OCTET_AS_NUMBER,
		},
		asnum,
	}
}

type BGPAddPathMode uint8

const (
	BGP_ADD_PATH_RECEIVE BGPAddPathMode = 1
	BGP_ADD_PATH_SEND    BGPAddPathMode = 2
	BGP_ADD_PATH_BOTH    BGPAddPathMode = 3
)

func (m BGPAddPathMode) String() string {
	switch m {
	case BGP_ADD_PATH_RECEIVE:
		return "receive"
	case BGP_ADD_PATH_SEND:
		return "send"
	case BGP_ADD_PATH_BOTH:
		return "receive/send"
	default:
		return fmt.Sprintf("unknown(%d)", m)
	}
}

type CapAddPath struct {
	DefaultParameterCapability
	RouteFamily RouteFamily
	Mode        BGPAddPathMode
}

func (c *CapAddPath) DecodeFromBytes(data []byte) error {
	c.DefaultParameterCapability.DecodeFromBytes(data)
	data = data[2:]
	if len(data) < 4 {
		return NewMessageError(BGP_ERROR_OPEN_MESSAGE_ERROR, BGP_ERROR_SUB_UNSUPPORTED_CAPABILITY, nil, "Not all CapabilityAddPath bytes available")
	}
	c.RouteFamily = AfiSafiToRouteFamily(binary.BigEndian.Uint16(data[:2]), data[2])
	c.Mode = BGPAddPathMode(data[3])
	return nil
}

func (c *CapAddPath) Serialize() ([]byte, error) {
	buf := make([]byte, 4)
	afi, safi := RouteFamilyToAfiSafi(c.RouteFamily)
	binary.BigEndian.PutUint16(buf, afi)
	buf[2] = safi
	buf[3] = byte(c.Mode)
	c.DefaultParameterCapability.CapValue = buf
	return c.DefaultParameterCapability.Serialize()
}

func (c *CapAddPath) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Code  BGPCapabilityCode `json:"code"`
		Value RouteFamily       `json:"value"`
		Mode  BGPAddPathMode    `json:"mode"`
	}{
		Code:  c.Code(),
		Value: c.RouteFamily,
		Mode:  c.Mode,
	})
}

func NewCapAddPath(rf RouteFamily, mode BGPAddPathMode) *CapAddPath {
	return &CapAddPath{
		DefaultParameterCapability: DefaultParameterCapability{
			CapCode: BGP_CAP_ADD_PATH,
		},
		RouteFamily: rf,
		Mode:        mode,
	}
}

type CapEnhancedRouteRefresh struct {
	DefaultParameterCapability
}

func NewCapEnhancedRouteRefresh() *CapEnhancedRouteRefresh {
	return &CapEnhancedRouteRefresh{
		DefaultParameterCapability{
			CapCode: BGP_CAP_ENHANCED_ROUTE_REFRESH,
		},
	}
}

type CapRouteRefreshCisco struct {
	DefaultParameterCapability
}

func NewCapRouteRefreshCisco() *CapRouteRefreshCisco {
	return &CapRouteRefreshCisco{
		DefaultParameterCapability{
			CapCode: BGP_CAP_ROUTE_REFRESH_CISCO,
		},
	}
}

type CapLongLivedGracefulRestartTuple struct {
	AFI         uint16
	SAFI        uint8
	Flags       uint8
	RestartTime uint32
}

func (c *CapLongLivedGracefulRestartTuple) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RouteFamily RouteFamily `json:"route_family"`
		Flags       uint8       `json:"flags"`
		RestartTime uint32      `json:"restart_time"`
	}{
		RouteFamily: AfiSafiToRouteFamily(c.AFI, c.SAFI),
		Flags:       c.Flags,
		RestartTime: c.RestartTime,
	})
}

func NewCapLongLivedGracefulRestartTuple(rf RouteFamily, forward bool, restartTime uint32) *CapLongLivedGracefulRestartTuple {
	afi, safi := RouteFamilyToAfiSafi(rf)
	flags := 0
	if forward {
		flags = 0x80
	}
	return &CapLongLivedGracefulRestartTuple{
		AFI:         afi,
		SAFI:        safi,
		Flags:       uint8(flags),
		RestartTime: restartTime,
	}
}

type CapLongLivedGracefulRestart struct {
	DefaultParameterCapability
	Tuples []*CapLongLivedGracefulRestartTuple
}

func (c *CapLongLivedGracefulRestart) DecodeFromBytes(data []byte) error {
	c.DefaultParameterCapability.DecodeFromBytes(data)
	data = data[2:]

	valueLen := int(c.CapLen)
	if valueLen%7 != 0 || len(data) < valueLen {
		return NewMessageError(BGP_ERROR_OPEN_MESSAGE_ERROR, BGP_ERROR_SUB_UNSUPPORTED_CAPABILITY, nil, "invalid length of long lived graceful restart capablity")
	}
	for i := valueLen; i >= 7; i -= 7 {
		t := &CapLongLivedGracefulRestartTuple{
			binary.BigEndian.Uint16(data),
			data[2],
			data[3],
			uint32(data[4])<<16 | uint32(data[5])<<8 | uint32(data[6]),
		}
		c.Tuples = append(c.Tuples, t)
		data = data[7:]
	}
	return nil
}

func (c *CapLongLivedGracefulRestart) Serialize() ([]byte, error) {
	buf := make([]byte, 7*len(c.Tuples))
	for idx, t := range c.Tuples {
		binary.BigEndian.PutUint16(buf[idx*7:], t.AFI)
		buf[idx*7+2] = t.SAFI
		buf[idx*7+3] = t.Flags
		buf[idx*7+4] = uint8((t.RestartTime >> 16) & 0xff)
		buf[idx*7+5] = uint8((t.RestartTime >> 8) & 0xff)
		buf[idx*7+6] = uint8(t.RestartTime & 0xff)
	}
	c.DefaultParameterCapability.CapValue = buf
	return c.DefaultParameterCapability.Serialize()
}

func (c *CapLongLivedGracefulRestart) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Code   BGPCapabilityCode                   `json:"code"`
		Tuples []*CapLongLivedGracefulRestartTuple `json:"tuples"`
	}{
		Code:   c.Code(),
		Tuples: c.Tuples,
	})
}

func NewCapLongLivedGracefulRestart(tuples []*CapLongLivedGracefulRestartTuple) *CapLongLivedGracefulRestart {
	return &CapLongLivedGracefulRestart{
		DefaultParameterCapability: DefaultParameterCapability{
			CapCode: BGP_CAP_LONG_LIVED_GRACEFUL_RESTART,
		},
		Tuples: tuples,
	}
}

type CapUnknown struct {
	DefaultParameterCapability
}

func DecodeCapability(data []byte) (ParameterCapabilityInterface, error) {
	if len(data) < 2 {
		return nil, NewMessageError(BGP_ERROR_OPEN_MESSAGE_ERROR, BGP_ERROR_SUB_UNSUPPORTED_CAPABILITY, nil, "Not all ParameterCapability bytes available")
	}
	var c ParameterCapabilityInterface
	switch BGPCapabilityCode(data[0]) {
	case BGP_CAP_MULTIPROTOCOL:
		c = &CapMultiProtocol{}
	case BGP_CAP_ROUTE_REFRESH:
		c = &CapRouteRefresh{}
	case BGP_CAP_CARRYING_LABEL_INFO:
		c = &CapCarryingLabelInfo{}
	case BGP_CAP_EXTENDED_NEXTHOP:
		c = &CapExtendedNexthop{}
	case BGP_CAP_GRACEFUL_RESTART:
		c = &CapGracefulRestart{}
	case BGP_CAP_FOUR_OCTET_AS_NUMBER:
		c = &CapFourOctetASNumber{}
	case BGP_CAP_ADD_PATH:
		c = &CapAddPath{}
	case BGP_CAP_ENHANCED_ROUTE_REFRESH:
		c = &CapEnhancedRouteRefresh{}
	case BGP_CAP_ROUTE_REFRESH_CISCO:
		c = &CapRouteRefreshCisco{}
	case BGP_CAP_LONG_LIVED_GRACEFUL_RESTART:
		c = &CapLongLivedGracefulRestart{}
	default:
		c = &CapUnknown{}
	}
	err := c.DecodeFromBytes(data)
	return c, err
}

type OptionParameterInterface interface {
	Serialize() ([]byte, error)
}

type OptionParameterCapability struct {
	ParamType  uint8
	ParamLen   uint8
	Capability []ParameterCapabilityInterface
}

func (o *OptionParameterCapability) DecodeFromBytes(data []byte) error {
	if uint8(len(data)) < o.ParamLen {
		return NewMessageError(BGP_ERROR_OPEN_MESSAGE_ERROR, BGP_ERROR_SUB_UNSUPPORTED_OPTIONAL_PARAMETER, nil, "Not all OptionParameterCapability bytes available")
	}
	for len(data) >= 2 {
		c, err := DecodeCapability(data)
		if err != nil {
			return err
		}
		o.Capability = append(o.Capability, c)
		data = data[c.Len():]
	}
	return nil
}

func (o *OptionParameterCapability) Serialize() ([]byte, error) {
	buf := make([]byte, 2)
	buf[0] = o.ParamType
	for _, p := range o.Capability {
		pbuf, err := p.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, pbuf...)
	}
	o.ParamLen = uint8(len(buf) - 2)
	buf[1] = o.ParamLen
	return buf, nil
}

func NewOptionParameterCapability(capability []ParameterCapabilityInterface) *OptionParameterCapability {
	return &OptionParameterCapability{
		ParamType:  BGP_OPT_CAPABILITY,
		Capability: capability,
	}
}

type OptionParameterUnknown struct {
	ParamType uint8
	ParamLen  uint8
	Value     []byte
}

func (o *OptionParameterUnknown) Serialize() ([]byte, error) {
	buf := make([]byte, 2)
	buf[0] = o.ParamType
	if o.ParamLen == 0 {
		o.ParamLen = uint8(len(o.Value))
	}
	buf[1] = o.ParamLen
	return append(buf, o.Value...), nil
}

type BGPOpen struct {
	Version     uint8
	MyAS        uint16
	HoldTime    uint16
	ID          net.IP
	OptParamLen uint8
	OptParams   []OptionParameterInterface
}

func (msg *BGPOpen) DecodeFromBytes(data []byte) error {
	msg.Version = data[0]
	msg.MyAS = binary.BigEndian.Uint16(data[1:3])
	msg.HoldTime = binary.BigEndian.Uint16(data[3:5])
	msg.ID = net.IP(data[5:9]).To4()
	msg.OptParamLen = data[9]
	data = data[10:]
	if len(data) < int(msg.OptParamLen) {
		return NewMessageError(BGP_ERROR_MESSAGE_HEADER_ERROR, BGP_ERROR_SUB_BAD_MESSAGE_LENGTH, nil, "Not all BGP Open message bytes available")
	}

	msg.OptParams = []OptionParameterInterface{}
	for rest := msg.OptParamLen; rest > 0; {
		if rest < 2 {
			return NewMessageError(BGP_ERROR_MESSAGE_HEADER_ERROR, BGP_ERROR_SUB_BAD_MESSAGE_LENGTH, nil, "Malformed BGP Open message")
		}
		paramtype := data[0]
		paramlen := data[1]
		if rest < paramlen+2 {
			return NewMessageError(BGP_ERROR_MESSAGE_HEADER_ERROR, BGP_ERROR_SUB_BAD_MESSAGE_LENGTH, nil, "Malformed BGP Open message")
		}
		rest -= paramlen + 2

		if paramtype == BGP_OPT_CAPABILITY {
			p := &OptionParameterCapability{}
			p.ParamType = paramtype
			p.ParamLen = paramlen
			p.DecodeFromBytes(data[2 : 2+paramlen])
			msg.OptParams = append(msg.OptParams, p)
		} else {
			p := &OptionParameterUnknown{}
			p.ParamType = paramtype
			p.ParamLen = paramlen
			p.Value = data[2 : 2+paramlen]
			msg.OptParams = append(msg.OptParams, p)
		}
		data = data[2+paramlen:]
	}
	return nil
}

func (msg *BGPOpen) Serialize() ([]byte, error) {
	buf := make([]byte, 10)
	buf[0] = msg.Version
	binary.BigEndian.PutUint16(buf[1:3], msg.MyAS)
	binary.BigEndian.PutUint16(buf[3:5], msg.HoldTime)
	copy(buf[5:9], msg.ID.To4())
	pbuf := make([]byte, 0)
	for _, p := range msg.OptParams {
		onepbuf, err := p.Serialize()
		if err != nil {
			return nil, err
		}
		pbuf = append(pbuf, onepbuf...)
	}
	msg.OptParamLen = uint8(len(pbuf))
	buf[9] = msg.OptParamLen
	return append(buf, pbuf...), nil
}

func NewBGPOpenMessage(myas uint16, holdtime uint16, id string, optparams []OptionParameterInterface) *BGPMessage {
	return &BGPMessage{
		Header: BGPHeader{Type: BGP_MSG_OPEN},
		Body:   &BGPOpen{4, myas, holdtime, net.ParseIP(id).To4(), 0, optparams},
	}
}

type AddrPrefixInterface interface {
	DecodeFromBytes([]byte) error
	Serialize() ([]byte, error)
	AFI() uint16
	SAFI() uint8
	Len() int
	String() string
	MarshalJSON() ([]byte, error)

	// Create a flat map to describe attributes and their
	// values. This can be used to create structured outputs.
	Flat() map[string]string
}

type IPAddrPrefixDefault struct {
	Length uint8
	Prefix net.IP
}

func (r *IPAddrPrefixDefault) decodePrefix(data []byte, bitlen uint8, addrlen uint8) error {
	bytelen := (int(bitlen) + 7) / 8
	if len(data) < bytelen {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST)
		return NewMessageError(eCode, eSubCode, nil, "network bytes is short")
	}
	b := make([]byte, addrlen)
	copy(b, data[:bytelen])
	r.Prefix = b
	return nil
}

func (r *IPAddrPrefixDefault) serializePrefix(bitlen uint8) ([]byte, error) {
	bytelen := (int(bitlen) + 7) / 8
	buf := make([]byte, bytelen)
	copy(buf, r.Prefix)
	// clear trailing bits in the last byte. rfc doesn't require
	// this though.
	if bitlen%8 != 0 {
		mask := 0xff00 >> (bitlen % 8)
		last_byte_value := buf[bytelen-1] & byte(mask)
		buf[bytelen-1] = last_byte_value
	}
	b := make([]byte, len(r.Prefix))
	copy(b, buf)
	copy(r.Prefix, b)
	return buf, nil
}

func (r *IPAddrPrefixDefault) Len() int {
	return 1 + ((int(r.Length) + 7) / 8)
}

func (r *IPAddrPrefixDefault) String() string {
	return fmt.Sprintf("%s/%d", r.Prefix.String(), r.Length)
}

func (r *IPAddrPrefixDefault) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Prefix string `json:"prefix"`
	}{
		Prefix: r.String(),
	})
}

type IPAddrPrefix struct {
	IPAddrPrefixDefault
	addrlen uint8
}

func (r *IPAddrPrefix) DecodeFromBytes(data []byte) error {
	if len(data) < 1 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST)
		return NewMessageError(eCode, eSubCode, nil, "prefix misses length field")
	}
	r.Length = data[0]
	if r.addrlen == 0 {
		r.addrlen = 4
	}
	return r.decodePrefix(data[1:], r.Length, r.addrlen)
}

func (r *IPAddrPrefix) Serialize() ([]byte, error) {
	buf := make([]byte, 1)
	buf[0] = r.Length
	pbuf, err := r.serializePrefix(r.Length)
	if err != nil {
		return nil, err
	}
	return append(buf, pbuf...), nil
}

func (r *IPAddrPrefix) AFI() uint16 {
	return AFI_IP
}

func (r *IPAddrPrefix) SAFI() uint8 {
	return SAFI_UNICAST
}

func NewIPAddrPrefix(length uint8, prefix string) *IPAddrPrefix {
	return &IPAddrPrefix{
		IPAddrPrefixDefault{length, net.ParseIP(prefix).To4()},
		4,
	}
}

func isIPv4MappedIPv6(ip net.IP) bool {
	return len(ip) == net.IPv6len && ip.To4() != nil
}

type IPv6AddrPrefix struct {
	IPAddrPrefix
}

func (r *IPv6AddrPrefix) AFI() uint16 {
	return AFI_IP6
}

func (r *IPv6AddrPrefix) String() string {
	prefix := r.Prefix.String()
	if isIPv4MappedIPv6(r.Prefix) {
		prefix = "::ffff:" + prefix
	}
	return fmt.Sprintf("%s/%d", prefix, r.Length)
}

func NewIPv6AddrPrefix(length uint8, prefix string) *IPv6AddrPrefix {
	return &IPv6AddrPrefix{
		IPAddrPrefix{
			IPAddrPrefixDefault{length, net.ParseIP(prefix)},
			16,
		},
	}
}

const (
	BGP_RD_TWO_OCTET_AS = iota
	BGP_RD_IPV4_ADDRESS
	BGP_RD_FOUR_OCTET_AS
)

type RouteDistinguisherInterface interface {
	DecodeFromBytes([]byte) error
	Serialize() ([]byte, error)
	Len() int
	String() string
	MarshalJSON() ([]byte, error)
}

type DefaultRouteDistinguisher struct {
	Type  uint16
	Value []byte
}

func (rd *DefaultRouteDistinguisher) DecodeFromBytes(data []byte) error {
	rd.Type = binary.BigEndian.Uint16(data[0:2])
	rd.Value = data[2:8]
	return nil
}

func (rd *DefaultRouteDistinguisher) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint16(buf, rd.Type)
	copy(buf[2:], rd.Value)
	return buf, nil
}

func (rd *DefaultRouteDistinguisher) String() string {
	return fmt.Sprintf("%v", rd.Value)
}

func (rd *DefaultRouteDistinguisher) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  uint16 `json:"type"`
		Value []byte `json:"value"`
	}{
		Type:  rd.Type,
		Value: rd.Value,
	})
}

func (rd *DefaultRouteDistinguisher) Len() int { return 8 }

type RouteDistinguisherTwoOctetAS struct {
	DefaultRouteDistinguisher
	Admin    uint16
	Assigned uint32
}

func (rd *RouteDistinguisherTwoOctetAS) Serialize() ([]byte, error) {
	buf := make([]byte, 6)
	binary.BigEndian.PutUint16(buf[0:], rd.Admin)
	binary.BigEndian.PutUint32(buf[2:], rd.Assigned)
	rd.Value = buf
	return rd.DefaultRouteDistinguisher.Serialize()
}

func (rd *RouteDistinguisherTwoOctetAS) String() string {
	return fmt.Sprintf("%d:%d", rd.Admin, rd.Assigned)
}

func (rd *RouteDistinguisherTwoOctetAS) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type     uint16 `json:"type"`
		Admin    uint16 `json:"admin"`
		Assigned uint32 `json:"assigned"`
	}{
		Type:     rd.Type,
		Admin:    rd.Admin,
		Assigned: rd.Assigned,
	})
}

func NewRouteDistinguisherTwoOctetAS(admin uint16, assigned uint32) *RouteDistinguisherTwoOctetAS {
	return &RouteDistinguisherTwoOctetAS{
		DefaultRouteDistinguisher: DefaultRouteDistinguisher{
			Type: BGP_RD_TWO_OCTET_AS,
		},
		Admin:    admin,
		Assigned: assigned,
	}
}

type RouteDistinguisherIPAddressAS struct {
	DefaultRouteDistinguisher
	Admin    net.IP
	Assigned uint16
}

func (rd *RouteDistinguisherIPAddressAS) Serialize() ([]byte, error) {
	buf := make([]byte, 6)
	copy(buf[0:], rd.Admin.To4())
	binary.BigEndian.PutUint16(buf[4:], rd.Assigned)
	rd.Value = buf
	return rd.DefaultRouteDistinguisher.Serialize()
}

func (rd *RouteDistinguisherIPAddressAS) String() string {
	return fmt.Sprintf("%s:%d", rd.Admin.String(), rd.Assigned)
}

func (rd *RouteDistinguisherIPAddressAS) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type     uint16 `json:"type"`
		Admin    string `json:"admin"`
		Assigned uint16 `json:"assigned"`
	}{
		Type:     rd.Type,
		Admin:    rd.Admin.String(),
		Assigned: rd.Assigned,
	})
}

func NewRouteDistinguisherIPAddressAS(admin string, assigned uint16) *RouteDistinguisherIPAddressAS {
	return &RouteDistinguisherIPAddressAS{
		DefaultRouteDistinguisher: DefaultRouteDistinguisher{
			Type: BGP_RD_IPV4_ADDRESS,
		},
		Admin:    net.ParseIP(admin).To4(),
		Assigned: assigned,
	}
}

type RouteDistinguisherFourOctetAS struct {
	DefaultRouteDistinguisher
	Admin    uint32
	Assigned uint16
}

func (rd *RouteDistinguisherFourOctetAS) Serialize() ([]byte, error) {
	buf := make([]byte, 6)
	binary.BigEndian.PutUint32(buf[0:], rd.Admin)
	binary.BigEndian.PutUint16(buf[4:], rd.Assigned)
	rd.Value = buf
	return rd.DefaultRouteDistinguisher.Serialize()
}

func (rd *RouteDistinguisherFourOctetAS) String() string {
	fst := rd.Admin >> 16 & 0xffff
	snd := rd.Admin & 0xffff
	return fmt.Sprintf("%d.%d:%d", fst, snd, rd.Assigned)
}

func (rd *RouteDistinguisherFourOctetAS) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type     uint16 `json:"type"`
		Admin    uint32 `json:"admin"`
		Assigned uint16 `json:"assigned"`
	}{
		Type:     rd.Type,
		Admin:    rd.Admin,
		Assigned: rd.Assigned,
	})
}

func NewRouteDistinguisherFourOctetAS(admin uint32, assigned uint16) *RouteDistinguisherFourOctetAS {
	return &RouteDistinguisherFourOctetAS{
		DefaultRouteDistinguisher: DefaultRouteDistinguisher{
			Type: BGP_RD_FOUR_OCTET_AS,
		},
		Admin:    admin,
		Assigned: assigned,
	}
}

type RouteDistinguisherUnknown struct {
	DefaultRouteDistinguisher
}

func GetRouteDistinguisher(data []byte) RouteDistinguisherInterface {
	rdtype := binary.BigEndian.Uint16(data[0:2])
	switch rdtype {
	case BGP_RD_TWO_OCTET_AS:
		return NewRouteDistinguisherTwoOctetAS(binary.BigEndian.Uint16(data[2:4]), binary.BigEndian.Uint32(data[4:8]))
	case BGP_RD_IPV4_ADDRESS:
		return NewRouteDistinguisherIPAddressAS(net.IP(data[2:6]).String(), binary.BigEndian.Uint16(data[6:8]))
	case BGP_RD_FOUR_OCTET_AS:
		return NewRouteDistinguisherFourOctetAS(binary.BigEndian.Uint32(data[2:6]), binary.BigEndian.Uint16(data[6:8]))
	}
	rd := &RouteDistinguisherUnknown{}
	rd.Type = rdtype
	return rd
}

func parseRdAndRt(input string) ([]string, error) {
	exp := regexp.MustCompile("^((\\d+)\\.(\\d+)\\.(\\d+)\\.(\\d+)|((\\d+)\\.)?(\\d+)|([\\w]+:[\\w:]*:[\\w]+)):(\\d+)$")
	elems := exp.FindStringSubmatch(input)
	if len(elems) != 11 {
		return nil, fmt.Errorf("failed to parse")
	}
	return elems, nil
}

func ParseRouteDistinguisher(rd string) (RouteDistinguisherInterface, error) {
	elems, err := parseRdAndRt(rd)
	if err != nil {
		return nil, err
	}
	assigned, _ := strconv.Atoi(elems[10])
	ip := net.ParseIP(elems[1])
	switch {
	case ip.To4() != nil:
		return NewRouteDistinguisherIPAddressAS(elems[1], uint16(assigned)), nil
	case elems[6] == "" && elems[7] == "":
		asn, _ := strconv.Atoi(elems[8])
		return NewRouteDistinguisherTwoOctetAS(uint16(asn), uint32(assigned)), nil
	default:
		fst, _ := strconv.Atoi(elems[7])
		snd, _ := strconv.Atoi(elems[8])
		asn := fst<<16 | snd
		return NewRouteDistinguisherFourOctetAS(uint32(asn), uint16(assigned)), nil
	}
}

//
// RFC3107 Carrying Label Information in BGP-4
//
// 3. Carrying Label Mapping Information
//
// b) Label:
//
// The Label field carries one or more labels (that corresponds to
// the stack of labels [MPLS-ENCAPS(RFC3032)]). Each label is encoded as
// 4 octets, where the high-order 20 bits contain the label value, and
// the low order bit contains "Bottom of Stack"
//
// RFC3032 MPLS Label Stack Encoding
//
// 2.1. Encoding the Label Stack
//
//  0       1       2               3
//  0 ... 9 0 ... 9 0 1 2 3 4 ... 9 0 1
// +-----+-+-+---+-+-+-+-+-+-----+-+-+-+
// |     Label     | Exp |S|    TTL    |
// +-----+-+-+---+-+-+-+-+-+-----+-+-+-+
//

// RFC3107 Carrying Label Information in BGP-4
//
// 3. Carrying Label Mapping Information
//
// The label information carried (as part of NLRI) in the Withdrawn
// Routes field should be set to 0x800000.
const WITHDRAW_LABEL = uint32(0x800000)
const ZERO_LABEL = uint32(0) // some platform uses this as withdraw label

type MPLSLabelStack struct {
	Labels []uint32
}

func (l *MPLSLabelStack) DecodeFromBytes(data []byte) error {
	labels := []uint32{}
	foundBottom := false
	for len(data) >= 3 {
		label := uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
		if label == WITHDRAW_LABEL || label == ZERO_LABEL {
			l.Labels = []uint32{label}
			return nil
		}
		data = data[3:]
		labels = append(labels, label>>4)
		if label&1 == 1 {
			foundBottom = true
			break
		}
	}
	if foundBottom == false {
		l.Labels = []uint32{}
		return nil
	}
	l.Labels = labels
	return nil
}

func (l *MPLSLabelStack) Serialize() ([]byte, error) {
	buf := make([]byte, len(l.Labels)*3)
	for i, label := range l.Labels {
		if label == WITHDRAW_LABEL {
			return []byte{128, 0, 0}, nil
		}
		label = label << 4
		buf[i*3] = byte((label >> 16) & 0xff)
		buf[i*3+1] = byte((label >> 8) & 0xff)
		buf[i*3+2] = byte(label & 0xff)
	}
	buf[len(buf)-1] |= 1
	return buf, nil
}

func (l *MPLSLabelStack) Len() int { return 3 * len(l.Labels) }

func (l *MPLSLabelStack) String() string {
	if len(l.Labels) == 0 {
		return ""
	}
	s := bytes.NewBuffer(make([]byte, 0, 64))
	s.WriteString("[")
	ss := make([]string, 0, len(l.Labels))
	for _, label := range l.Labels {
		ss = append(ss, fmt.Sprintf("%d", label))
	}
	s.WriteString(strings.Join(ss, ", "))
	s.WriteString("]")
	return s.String()
}

func NewMPLSLabelStack(labels ...uint32) *MPLSLabelStack {
	if len(labels) == 0 {
		labels = []uint32{0}
	}
	return &MPLSLabelStack{labels}
}

func ParseMPLSLabelStack(buf string) (*MPLSLabelStack, error) {
	elems := strings.Split(buf, "/")
	labels := make([]uint32, 0, len(elems))
	if len(elems) == 0 {
		goto ERR
	}
	for _, elem := range elems {
		i, err := strconv.Atoi(elem)
		if err != nil {
			goto ERR
		}
		if i < 0 || i > ((1<<20)-1) {
			goto ERR
		}
		labels = append(labels, uint32(i))
	}
	return NewMPLSLabelStack(labels...), nil
ERR:
	return nil, NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "invalid mpls label stack format")
}

//
// RFC3107 Carrying Label Information in BGP-4
//
// 3. Carrying Label Mapping Information
//
// +----------------------+
// |   Length (1 octet)   |
// +----------------------+
// |   Label (3 octets)   |
// +----------------------+
// .......................
// +----------------------+
// |   Prefix (variable)  |
// +----------------------+
//
// RFC4364 BGP/MPLS IP VPNs
//
// 4.3.4. How VPN-IPv4 NLRI Is Carried in BGP
//
// The labeled VPN-IPv4 NLRI itself is encoded as specified in
// [MPLS-BGP(RFC3107)], where the prefix consists of an 8-byte RD
// followed by an IPv4 prefix.
//

type LabeledVPNIPAddrPrefix struct {
	IPAddrPrefixDefault
	Labels  MPLSLabelStack
	RD      RouteDistinguisherInterface
	addrlen uint8
}

func (l *LabeledVPNIPAddrPrefix) DecodeFromBytes(data []byte) error {
	l.Length = uint8(data[0])
	data = data[1:]
	l.Labels.DecodeFromBytes(data)
	if int(l.Length)-8*(l.Labels.Len()) < 0 {
		l.Labels.Labels = []uint32{}
	}
	data = data[l.Labels.Len():]
	l.RD = GetRouteDistinguisher(data)
	data = data[l.RD.Len():]
	restbits := int(l.Length) - 8*(l.Labels.Len()+l.RD.Len())
	l.decodePrefix(data, uint8(restbits), l.addrlen)
	return nil
}

func (l *LabeledVPNIPAddrPrefix) Serialize() ([]byte, error) {
	buf := make([]byte, 1)
	buf[0] = l.Length
	lbuf, err := l.Labels.Serialize()
	if err != nil {
		return nil, err
	}
	buf = append(buf, lbuf...)
	rbuf, err := l.RD.Serialize()
	if err != nil {
		return nil, err
	}
	buf = append(buf, rbuf...)
	restbits := int(l.Length) - 8*(l.Labels.Len()+l.RD.Len())
	pbuf, err := l.serializePrefix(uint8(restbits))
	if err != nil {
		return nil, err
	}
	buf = append(buf, pbuf...)
	return buf, nil
}

func (l *LabeledVPNIPAddrPrefix) AFI() uint16 {
	return AFI_IP
}

func (l *LabeledVPNIPAddrPrefix) SAFI() uint8 {
	return SAFI_MPLS_VPN
}

func (l *LabeledVPNIPAddrPrefix) String() string {
	return fmt.Sprintf("%s:%s", l.RD, l.IPPrefix())
}

func (l *LabeledVPNIPAddrPrefix) IPPrefix() string {
	masklen := l.IPAddrPrefixDefault.Length - uint8(8*(l.Labels.Len()+l.RD.Len()))
	return fmt.Sprintf("%s/%d", l.IPAddrPrefixDefault.Prefix, masklen)
}

func (l *LabeledVPNIPAddrPrefix) MarshalJSON() ([]byte, error) {
	masklen := l.IPAddrPrefixDefault.Length - uint8(8*(l.Labels.Len()+l.RD.Len()))
	return json.Marshal(struct {
		Prefix string                      `json:"prefix"`
		Labels []uint32                    `json:"labels"`
		RD     RouteDistinguisherInterface `json:"rd"`
	}{
		Prefix: fmt.Sprintf("%s/%d", l.IPAddrPrefixDefault.Prefix, masklen),
		Labels: l.Labels.Labels,
		RD:     l.RD,
	})
}

func NewLabeledVPNIPAddrPrefix(length uint8, prefix string, label MPLSLabelStack, rd RouteDistinguisherInterface) *LabeledVPNIPAddrPrefix {
	rdlen := 0
	if rd != nil {
		rdlen = rd.Len()
	}
	return &LabeledVPNIPAddrPrefix{
		IPAddrPrefixDefault{length + uint8(8*(label.Len()+rdlen)), net.ParseIP(prefix).To4()},
		label,
		rd,
		4,
	}
}

type LabeledVPNIPv6AddrPrefix struct {
	LabeledVPNIPAddrPrefix
}

func (l *LabeledVPNIPv6AddrPrefix) AFI() uint16 {
	return AFI_IP6
}

func NewLabeledVPNIPv6AddrPrefix(length uint8, prefix string, label MPLSLabelStack, rd RouteDistinguisherInterface) *LabeledVPNIPv6AddrPrefix {
	rdlen := 0
	if rd != nil {
		rdlen = rd.Len()
	}
	return &LabeledVPNIPv6AddrPrefix{
		LabeledVPNIPAddrPrefix{
			IPAddrPrefixDefault{length + uint8(8*(label.Len()+rdlen)), net.ParseIP(prefix)},
			label,
			rd,
			16,
		},
	}
}

type LabeledIPAddrPrefix struct {
	IPAddrPrefixDefault
	Labels  MPLSLabelStack
	addrlen uint8
}

func (r *LabeledIPAddrPrefix) AFI() uint16 {
	return AFI_IP
}

func (r *LabeledIPAddrPrefix) SAFI() uint8 {
	return SAFI_MPLS_LABEL
}

func (l *LabeledIPAddrPrefix) DecodeFromBytes(data []byte) error {
	l.Length = uint8(data[0])
	data = data[1:]
	l.Labels.DecodeFromBytes(data)
	if int(l.Length)-8*(l.Labels.Len()) < 0 {
		l.Labels.Labels = []uint32{}
	}
	restbits := int(l.Length) - 8*(l.Labels.Len())
	data = data[l.Labels.Len():]
	l.decodePrefix(data, uint8(restbits), l.addrlen)
	return nil
}

func (l *LabeledIPAddrPrefix) Serialize() ([]byte, error) {
	buf := make([]byte, 1)
	buf[0] = l.Length
	restbits := int(l.Length) - 8*(l.Labels.Len())
	lbuf, err := l.Labels.Serialize()
	if err != nil {
		return nil, err
	}
	buf = append(buf, lbuf...)
	pbuf, err := l.serializePrefix(uint8(restbits))
	if err != nil {
		return nil, err
	}
	buf = append(buf, pbuf...)
	return buf, nil
}

func (l *LabeledIPAddrPrefix) String() string {
	prefix := l.Prefix.String()
	if isIPv4MappedIPv6(l.Prefix) {
		prefix = "::ffff:" + prefix
	}
	return fmt.Sprintf("%s/%d", prefix, int(l.Length)-l.Labels.Len()*8)
}

func (l *LabeledIPAddrPrefix) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Prefix string   `json:"prefix"`
		Labels []uint32 `json:"labels"`
	}{
		Prefix: l.String(),
		Labels: l.Labels.Labels,
	})
}

func NewLabeledIPAddrPrefix(length uint8, prefix string, label MPLSLabelStack) *LabeledIPAddrPrefix {
	return &LabeledIPAddrPrefix{
		IPAddrPrefixDefault{length + uint8(label.Len()*8), net.ParseIP(prefix).To4()},
		label,
		4,
	}
}

type LabeledIPv6AddrPrefix struct {
	LabeledIPAddrPrefix
}

func (l *LabeledIPv6AddrPrefix) AFI() uint16 {
	return AFI_IP6
}

func NewLabeledIPv6AddrPrefix(length uint8, prefix string, label MPLSLabelStack) *LabeledIPv6AddrPrefix {
	return &LabeledIPv6AddrPrefix{
		LabeledIPAddrPrefix{
			IPAddrPrefixDefault{length + uint8(label.Len()*8), net.ParseIP(prefix)},
			label,
			16,
		},
	}
}

type RouteTargetMembershipNLRI struct {
	Length      uint8
	AS          uint32
	RouteTarget ExtendedCommunityInterface
}

func (n *RouteTargetMembershipNLRI) DecodeFromBytes(data []byte) error {
	n.Length = data[0]
	data = data[1:]
	if len(data) == 0 {
		return nil
	} else if len(data) != 12 {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Not all RouteTargetMembershipNLRI bytes available")
	}
	n.AS = binary.BigEndian.Uint32(data[0:4])
	rt, err := ParseExtended(data[4:])
	n.RouteTarget = rt
	if err != nil {
		return err
	}
	return nil
}

func (n *RouteTargetMembershipNLRI) Serialize() ([]byte, error) {
	if n.RouteTarget == nil {
		return []byte{0}, nil
	}
	buf := make([]byte, 5)
	buf[0] = 12 * 8
	binary.BigEndian.PutUint32(buf[1:], n.AS)
	ebuf, err := n.RouteTarget.Serialize()
	if err != nil {
		return nil, err
	}
	buf = append(buf, ebuf...)
	return buf, nil
}

func (n *RouteTargetMembershipNLRI) AFI() uint16 {
	return AFI_IP
}

func (n *RouteTargetMembershipNLRI) SAFI() uint8 {
	return SAFI_ROUTE_TARGET_CONSTRAINTS
}

func (n *RouteTargetMembershipNLRI) Len() int {
	if n.AS == 0 && n.RouteTarget == nil {
		return 1
	}
	return 13
}

func (n *RouteTargetMembershipNLRI) String() string {
	target := "default"
	if n.RouteTarget != nil {
		target = n.RouteTarget.String()
	}
	return fmt.Sprintf("%d:%s", n.AS, target)
}

func (n *RouteTargetMembershipNLRI) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Prefix string `json:"prefix"`
	}{
		Prefix: n.String(),
	})
}

func NewRouteTargetMembershipNLRI(as uint32, target ExtendedCommunityInterface) *RouteTargetMembershipNLRI {
	l := 12 * 8
	if as == 0 && target == nil {
		l = 1
	}
	return &RouteTargetMembershipNLRI{
		Length:      uint8(l),
		AS:          as,
		RouteTarget: target,
	}
}

type ESIType uint8

const (
	ESI_ARBITRARY ESIType = iota
	ESI_LACP
	ESI_MSTP
	ESI_MAC
	ESI_ROUTERID
	ESI_AS
)

type EthernetSegmentIdentifier struct {
	Type  ESIType
	Value []byte
}

func (esi *EthernetSegmentIdentifier) DecodeFromBytes(data []byte) error {
	esi.Type = ESIType(data[0])
	esi.Value = data[1:10]
	switch esi.Type {
	case ESI_LACP, ESI_MSTP, ESI_ROUTERID, ESI_AS:
		if esi.Value[8] != 0x00 {
			return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("invalid %s. last octet must be 0x00 (0x%02x)", esi.Type.String(), esi.Value[8]))
		}
	}
	return nil
}

func (esi *EthernetSegmentIdentifier) Serialize() ([]byte, error) {
	buf := make([]byte, 10)
	buf[0] = uint8(esi.Type)
	copy(buf[1:], esi.Value)
	return buf, nil
}

func isZeroBuf(buf []byte) bool {
	for _, b := range buf {
		if b != 0 {
			return false
		}
	}
	return true
}

func (esi *EthernetSegmentIdentifier) String() string {
	s := bytes.NewBuffer(make([]byte, 0, 64))
	s.WriteString(fmt.Sprintf("%s | ", esi.Type.String()))
	switch esi.Type {
	case ESI_ARBITRARY:
		if isZeroBuf(esi.Value) {
			return "single-homed"
		}
		s.WriteString(fmt.Sprintf("%s", esi.Value))
	case ESI_LACP:
		s.WriteString(fmt.Sprintf("system mac %s, ", net.HardwareAddr(esi.Value[:6]).String()))
		s.WriteString(fmt.Sprintf("port key %d", binary.BigEndian.Uint16(esi.Value[6:8])))
	case ESI_MSTP:
		s.WriteString(fmt.Sprintf("bridge mac %s, ", net.HardwareAddr(esi.Value[:6]).String()))
		s.WriteString(fmt.Sprintf("priority %d", binary.BigEndian.Uint16(esi.Value[6:8])))
	case ESI_MAC:
		s.WriteString(fmt.Sprintf("system mac %s, ", net.HardwareAddr(esi.Value[:6]).String()))
		s.WriteString(fmt.Sprintf("local discriminator %d", uint32(esi.Value[6])<<16|uint32(esi.Value[7])<<8|uint32(esi.Value[8])))
	case ESI_ROUTERID:
		s.WriteString(fmt.Sprintf("router id %s, ", net.IP(esi.Value[:4])))
		s.WriteString(fmt.Sprintf("local discriminator %d", binary.BigEndian.Uint32(esi.Value[4:8])))
	case ESI_AS:
		s.WriteString(fmt.Sprintf("as %d:%d, ", binary.BigEndian.Uint16(esi.Value[:2]), binary.BigEndian.Uint16(esi.Value[2:4])))
		s.WriteString(fmt.Sprintf("local discriminator %d", binary.BigEndian.Uint32(esi.Value[4:8])))
	default:
		s.WriteString(fmt.Sprintf("value %s", esi.Value))
	}
	return s.String()
}

//
// I-D bess-evpn-overlay-01
//
// 5.1.3 Constructing EVPN BGP Routes
//
// For the balance of this memo, the MPLS label field will be
// referred to as the VNI/VSID field. The VNI/VSID field is used for
// both local and global VNIs/VSIDs, and for either case the entire 24-
// bit field is used to encode the VNI/VSID value.
//
// We can't use type MPLSLabelStack for EVPN NLRI, because EVPN NLRI's MPLS
// field can be filled with VXLAN VNI. In that case, we must avoid modifying
// bottom of stack bit.
//

func labelDecode(data []byte) uint32 {
	return uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
}

func labelSerialize(label uint32, buf []byte) {
	buf[0] = byte((label >> 16) & 0xff)
	buf[1] = byte((label >> 8) & 0xff)
	buf[2] = byte(label & 0xff)
}

type EVPNEthernetAutoDiscoveryRoute struct {
	RD    RouteDistinguisherInterface
	ESI   EthernetSegmentIdentifier
	ETag  uint32
	Label uint32
}

func (er *EVPNEthernetAutoDiscoveryRoute) DecodeFromBytes(data []byte) error {
	er.RD = GetRouteDistinguisher(data)
	data = data[er.RD.Len():]
	err := er.ESI.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	data = data[10:]
	er.ETag = binary.BigEndian.Uint32(data[0:4])
	data = data[4:]
	er.Label = labelDecode(data)
	return nil
}

func (er *EVPNEthernetAutoDiscoveryRoute) Serialize() ([]byte, error) {
	var buf []byte
	var err error
	if er.RD != nil {
		buf, err = er.RD.Serialize()
		if err != nil {
			return nil, err
		}
	} else {
		buf = make([]byte, 8)
	}
	tbuf, err := er.ESI.Serialize()
	if err != nil {
		return nil, err
	}
	buf = append(buf, tbuf...)

	tbuf = make([]byte, 4)
	binary.BigEndian.PutUint32(tbuf, er.ETag)
	buf = append(buf, tbuf...)

	tbuf = make([]byte, 3)
	labelSerialize(er.Label, tbuf)
	buf = append(buf, tbuf...)

	return buf, nil
}

func (er *EVPNEthernetAutoDiscoveryRoute) String() string {
	return fmt.Sprintf("[type:A-D][rd:%s][esi:%s][etag:%d][label:%d]", er.RD, er.ESI.String(), er.ETag, er.Label)
}

func (er *EVPNEthernetAutoDiscoveryRoute) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RD    RouteDistinguisherInterface `json:"rd"`
		ESI   string                      `json:"esi"`
		Etag  uint32                      `json:"etag"`
		Label uint32                      `json:"label"`
	}{
		RD:    er.RD,
		ESI:   er.ESI.String(),
		Etag:  er.ETag,
		Label: er.Label,
	})
}

func (er *EVPNEthernetAutoDiscoveryRoute) rd() RouteDistinguisherInterface {
	return er.RD
}

type EVPNMacIPAdvertisementRoute struct {
	RD               RouteDistinguisherInterface
	ESI              EthernetSegmentIdentifier
	ETag             uint32
	MacAddressLength uint8
	MacAddress       net.HardwareAddr
	IPAddressLength  uint8
	IPAddress        net.IP
	Labels           []uint32
}

func (er *EVPNMacIPAdvertisementRoute) DecodeFromBytes(data []byte) error {
	er.RD = GetRouteDistinguisher(data)
	data = data[er.RD.Len():]
	err := er.ESI.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	data = data[10:]
	er.ETag = binary.BigEndian.Uint32(data[0:4])
	data = data[4:]
	er.MacAddressLength = data[0]
	er.MacAddress = net.HardwareAddr(data[1:7])
	er.IPAddressLength = data[7]
	data = data[8:]
	if er.IPAddressLength == 32 || er.IPAddressLength == 128 {
		er.IPAddress = net.IP(data[0:((er.IPAddressLength) / 8)])
	} else if er.IPAddressLength != 0 {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("Invalid IP address length: %d", er.IPAddressLength))
	}
	data = data[(er.IPAddressLength / 8):]
	label1 := labelDecode(data)
	er.Labels = append(er.Labels, label1)
	data = data[3:]
	if len(data) == 3 {
		label2 := labelDecode(data)
		er.Labels = append(er.Labels, label2)

	}
	return nil
}

func (er *EVPNMacIPAdvertisementRoute) Serialize() ([]byte, error) {
	var buf []byte
	var err error
	if er.RD != nil {
		buf, err = er.RD.Serialize()
		if err != nil {
			return nil, err
		}
	} else {
		buf = make([]byte, 8)
	}

	tbuf, err := er.ESI.Serialize()
	if err != nil {
		return nil, err
	}

	buf = append(buf, tbuf...)
	tbuf = make([]byte, 4)
	binary.BigEndian.PutUint32(tbuf, er.ETag)
	buf = append(buf, tbuf...)
	tbuf = make([]byte, 7)
	tbuf[0] = er.MacAddressLength
	copy(tbuf[1:], er.MacAddress)
	buf = append(buf, tbuf...)

	if er.IPAddressLength == 0 {
		buf = append(buf, 0)
	} else if er.IPAddressLength == 32 || er.IPAddressLength == 128 {
		buf = append(buf, er.IPAddressLength)
		if er.IPAddressLength == 32 {
			er.IPAddress = er.IPAddress.To4()
		}
		buf = append(buf, []byte(er.IPAddress)...)
	} else {
		return nil, NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("Invalid IP address length: %d", er.IPAddressLength))
	}

	for _, l := range er.Labels {
		tbuf = make([]byte, 3)
		labelSerialize(l, tbuf)
		buf = append(buf, tbuf...)
	}
	return buf, nil
}

func (er *EVPNMacIPAdvertisementRoute) String() string {
	return fmt.Sprintf("[type:macadv][rd:%s][esi:%s][etag:%d][mac:%s][ip:%s][labels:%v]", er.RD, er.ESI.String(), er.ETag, er.MacAddress, er.IPAddress, er.Labels)
}

func (er *EVPNMacIPAdvertisementRoute) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RD         RouteDistinguisherInterface `json:"rd"`
		ESI        string                      `json:"esi"`
		Etag       uint32                      `json:"etag"`
		MacAddress string                      `json:"mac"`
		IPAddress  string                      `json:"ip"`
		Labels     []uint32                    `json:"labels"`
	}{
		RD:         er.RD,
		ESI:        er.ESI.String(),
		Etag:       er.ETag,
		MacAddress: er.MacAddress.String(),
		IPAddress:  er.IPAddress.String(),
		Labels:     er.Labels,
	})
}

func (er *EVPNMacIPAdvertisementRoute) rd() RouteDistinguisherInterface {
	return er.RD
}

type EVPNMulticastEthernetTagRoute struct {
	RD              RouteDistinguisherInterface
	ETag            uint32
	IPAddressLength uint8
	IPAddress       net.IP
}

func (er *EVPNMulticastEthernetTagRoute) DecodeFromBytes(data []byte) error {
	er.RD = GetRouteDistinguisher(data)
	data = data[er.RD.Len():]
	er.ETag = binary.BigEndian.Uint32(data[0:4])
	er.IPAddressLength = data[4]
	data = data[5:]
	if er.IPAddressLength == 32 || er.IPAddressLength == 128 {
		er.IPAddress = net.IP(data[:er.IPAddressLength/8])
	} else {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("Invalid IP address length: %d", er.IPAddressLength))
	}
	return nil
}

func (er *EVPNMulticastEthernetTagRoute) Serialize() ([]byte, error) {
	var buf []byte
	var err error
	if er.RD != nil {
		buf, err = er.RD.Serialize()
		if err != nil {
			return nil, err
		}
	} else {
		buf = make([]byte, 8)
	}
	tbuf := make([]byte, 4)
	binary.BigEndian.PutUint32(tbuf, er.ETag)
	buf = append(buf, tbuf...)
	if er.IPAddressLength == 32 || er.IPAddressLength == 128 {
		buf = append(buf, er.IPAddressLength)
		if er.IPAddressLength == 32 {
			er.IPAddress = er.IPAddress.To4()
		}
		buf = append(buf, []byte(er.IPAddress)...)
	} else {
		return nil, fmt.Errorf("Invalid IP address length: %d", er.IPAddressLength)
	}
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func (er *EVPNMulticastEthernetTagRoute) String() string {
	return fmt.Sprintf("[type:multicast][rd:%s][etag:%d][ip:%s]", er.RD, er.ETag, er.IPAddress)
}

func (er *EVPNMulticastEthernetTagRoute) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RD        RouteDistinguisherInterface `json:"rd"`
		Etag      uint32                      `json:"etag"`
		IPAddress string                      `json:"ip"`
	}{
		RD:        er.RD,
		Etag:      er.ETag,
		IPAddress: er.IPAddress.String(),
	})
}

func (er *EVPNMulticastEthernetTagRoute) rd() RouteDistinguisherInterface {
	return er.RD
}

type EVPNEthernetSegmentRoute struct {
	RD              RouteDistinguisherInterface
	ESI             EthernetSegmentIdentifier
	IPAddressLength uint8
	IPAddress       net.IP
}

func (er *EVPNEthernetSegmentRoute) DecodeFromBytes(data []byte) error {
	er.RD = GetRouteDistinguisher(data)
	data = data[er.RD.Len():]
	er.ESI.DecodeFromBytes(data)
	data = data[10:]
	er.IPAddressLength = data[0]
	data = data[1:]
	if er.IPAddressLength == 32 || er.IPAddressLength == 128 {
		er.IPAddress = net.IP(data[:er.IPAddressLength/8])
	} else {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("Invalid IP address length: %d", er.IPAddressLength))
	}
	return nil
}

func (er *EVPNEthernetSegmentRoute) Serialize() ([]byte, error) {
	var buf []byte
	var err error
	if er.RD != nil {
		buf, err = er.RD.Serialize()
		if err != nil {
			return nil, err
		}
	} else {
		buf = make([]byte, 8)
	}
	tbuf, err := er.ESI.Serialize()
	if err != nil {
		return nil, err
	}
	buf = append(buf, tbuf...)
	buf = append(buf, er.IPAddressLength)
	if er.IPAddressLength == 32 || er.IPAddressLength == 128 {
		if er.IPAddressLength == 32 {
			er.IPAddress = er.IPAddress.To4()
		}
		buf = append(buf, []byte(er.IPAddress)...)
	} else {
		return nil, fmt.Errorf("Invalid IP address length: %d", er.IPAddressLength)
	}
	return buf, nil
}

func (er *EVPNEthernetSegmentRoute) String() string {
	return fmt.Sprintf("[type:esi][rd:%s][esi:%d][ip:%s]", er.RD, er.ESI, er.IPAddress)
}

func (er *EVPNEthernetSegmentRoute) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RD        RouteDistinguisherInterface `json:"rd"`
		ESI       string                      `json:"esi"`
		IPAddress string                      `json:"ip"`
	}{
		RD:        er.RD,
		ESI:       er.ESI.String(),
		IPAddress: er.IPAddress.String(),
	})
}

func (er *EVPNEthernetSegmentRoute) rd() RouteDistinguisherInterface {
	return er.RD
}

type EVPNIPPrefixRoute struct {
	RD             RouteDistinguisherInterface
	ESI            EthernetSegmentIdentifier
	ETag           uint32
	IPPrefixLength uint8
	IPPrefix       net.IP
	GWIPAddress    net.IP
	Label          uint32
}

func (er *EVPNIPPrefixRoute) DecodeFromBytes(data []byte) error {
	if len(data) < 30 { // rd + esi + etag + prefix-len + ipv4 addr + label
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Not all EVPN IP Prefix Route bytes available")
	}
	er.RD = GetRouteDistinguisher(data)
	data = data[er.RD.Len():]
	err := er.ESI.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	data = data[10:]
	er.ETag = binary.BigEndian.Uint32(data[0:4])
	data = data[4:]
	er.IPPrefixLength = data[0]
	addrLen := 4
	data = data[1:]
	if len(data) > 19 { // ipv6 addr + label
		addrLen = 16
	}
	er.IPPrefix = net.IP(data[:addrLen])
	data = data[addrLen:]
	switch {
	case len(data) == 3:
		er.Label = labelDecode(data)
	case len(data) == addrLen+3:
		er.GWIPAddress = net.IP(data[:addrLen])
		er.Label = labelDecode(data[addrLen:])
	default:
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Not all EVPN IP Prefix Route bytes available")
	}
	return nil
}

func (er *EVPNIPPrefixRoute) Serialize() ([]byte, error) {
	var buf []byte
	var err error
	if er.RD != nil {
		buf, err = er.RD.Serialize()
		if err != nil {
			return nil, err
		}
	} else {
		buf = make([]byte, 8)
	}
	tbuf, err := er.ESI.Serialize()
	if err != nil {
		return nil, err
	}
	buf = append(buf, tbuf...)

	tbuf = make([]byte, 4)
	binary.BigEndian.PutUint32(tbuf, er.ETag)
	buf = append(buf, tbuf...)

	buf = append(buf, er.IPPrefixLength)

	if er.IPPrefix == nil {
		return nil, NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("IP Prefix is nil"))
	} else if er.IPPrefix.To4() != nil {
		buf = append(buf, []byte(er.IPPrefix.To4())...)
	} else {
		buf = append(buf, []byte(er.IPPrefix)...)
	}

	if er.GWIPAddress != nil {
		if er.GWIPAddress.To4() != nil {
			buf = append(buf, []byte(er.GWIPAddress.To4())...)
		} else {
			buf = append(buf, []byte(er.GWIPAddress.To16())...)
		}
	}

	tbuf = make([]byte, 3)
	labelSerialize(er.Label, tbuf)
	buf = append(buf, tbuf...)

	return buf, nil
}

func (er *EVPNIPPrefixRoute) String() string {
	return fmt.Sprintf("[type:Prefix][rd:%s][esi:%s][etag:%d][prefix:%s/%d][gw:%s][label:%d]", er.RD, er.ESI.String(), er.ETag, er.IPPrefix, er.IPPrefixLength, er.GWIPAddress, er.Label)
}

func (er *EVPNIPPrefixRoute) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RD      RouteDistinguisherInterface `json:"rd"`
		ESI     string                      `json:"esi"`
		Etag    uint32                      `json:"etag"`
		Prefix  string                      `json:"prefix"`
		Gateway string                      `json:"gateway"`
		Label   uint32                      `json:"label"`
	}{
		RD:      er.RD,
		ESI:     er.ESI.String(),
		Etag:    er.ETag,
		Prefix:  fmt.Sprintf("%s/%d", er.IPPrefix, er.IPPrefixLength),
		Gateway: er.GWIPAddress.String(),
		Label:   er.Label,
	})
}

func (er *EVPNIPPrefixRoute) rd() RouteDistinguisherInterface {
	return er.RD
}

type EVPNRouteTypeInterface interface {
	DecodeFromBytes([]byte) error
	Serialize() ([]byte, error)
	String() string
	rd() RouteDistinguisherInterface
	MarshalJSON() ([]byte, error)
}

func getEVPNRouteType(t uint8) (EVPNRouteTypeInterface, error) {
	switch t {
	case EVPN_ROUTE_TYPE_ETHERNET_AUTO_DISCOVERY:
		return &EVPNEthernetAutoDiscoveryRoute{}, nil
	case EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT:
		return &EVPNMacIPAdvertisementRoute{}, nil
	case EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG:
		return &EVPNMulticastEthernetTagRoute{}, nil
	case EVPN_ETHERNET_SEGMENT_ROUTE:
		return &EVPNEthernetSegmentRoute{}, nil
	case EVPN_IP_PREFIX:
		return &EVPNIPPrefixRoute{}, nil
	}
	return nil, NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("Unknown EVPN Route type: %d", t))
}

const (
	EVPN_ROUTE_TYPE_ETHERNET_AUTO_DISCOVERY = 1
	EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT    = 2
	EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG   = 3
	EVPN_ETHERNET_SEGMENT_ROUTE             = 4
	EVPN_IP_PREFIX                          = 5
)

type EVPNNLRI struct {
	RouteType     uint8
	Length        uint8
	RouteTypeData EVPNRouteTypeInterface
}

func (n *EVPNNLRI) DecodeFromBytes(data []byte) error {
	if len(data) < 2 {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Not all EVPNNLRI bytes available")
	}
	n.RouteType = data[0]
	n.Length = data[1]
	data = data[2:]
	if len(data) < int(n.Length) {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Not all EVPNNLRI Route type bytes available")
	}
	r, err := getEVPNRouteType(n.RouteType)
	if err != nil {
		return err
	}
	n.RouteTypeData = r
	return n.RouteTypeData.DecodeFromBytes(data[:n.Length])
}

func (n *EVPNNLRI) Serialize() ([]byte, error) {
	buf := make([]byte, 2)
	buf[0] = n.RouteType
	tbuf, err := n.RouteTypeData.Serialize()
	n.Length = uint8(len(tbuf))
	buf[1] = n.Length
	if err != nil {
		return nil, err
	}
	buf = append(buf, tbuf...)
	return buf, nil
}

func (n *EVPNNLRI) AFI() uint16 {
	return AFI_L2VPN
}

func (n *EVPNNLRI) SAFI() uint8 {
	return SAFI_EVPN
}

func (n *EVPNNLRI) Len() int {
	return int(n.Length) + 2
}

func (n *EVPNNLRI) String() string {
	if n.RouteTypeData != nil {
		return n.RouteTypeData.String()
	}
	return fmt.Sprintf("%d:%d", n.RouteType, n.Length)
}

func (n *EVPNNLRI) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  uint8                  `json:"type"`
		Value EVPNRouteTypeInterface `json:"value"`
	}{
		Type:  n.RouteType,
		Value: n.RouteTypeData,
	})
}

func (n *EVPNNLRI) RD() RouteDistinguisherInterface {
	return n.RouteTypeData.rd()
}

func NewEVPNNLRI(routetype uint8, length uint8, routetypedata EVPNRouteTypeInterface) *EVPNNLRI {
	return &EVPNNLRI{
		routetype,
		length,
		routetypedata,
	}
}

type EncapNLRI struct {
	IPAddrPrefixDefault
	addrlen uint8
}

func (n *EncapNLRI) DecodeFromBytes(data []byte) error {
	if len(data) < 4 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST)
		return NewMessageError(eCode, eSubCode, nil, "prefix misses length field")
	}
	n.Length = data[0]
	if n.addrlen == 0 {
		n.addrlen = 4
	}
	return n.decodePrefix(data[1:], n.Length, n.addrlen)
}

func (n *EncapNLRI) Serialize() ([]byte, error) {
	buf := make([]byte, 1)
	buf[0] = n.Length
	pbuf, err := n.serializePrefix(n.Length)
	if err != nil {
		return nil, err
	}
	return append(buf, pbuf...), nil
}

func (n *EncapNLRI) String() string {
	return n.Prefix.String()
}

func (n *EncapNLRI) AFI() uint16 {
	return AFI_IP
}

func (n *EncapNLRI) SAFI() uint8 {
	return SAFI_ENCAPSULATION
}

func NewEncapNLRI(endpoint string) *EncapNLRI {
	return &EncapNLRI{
		IPAddrPrefixDefault{32, net.ParseIP(endpoint).To4()},
		4,
	}
}

type Encapv6NLRI struct {
	EncapNLRI
}

func (n *Encapv6NLRI) AFI() uint16 {
	return AFI_IP6
}

func NewEncapv6NLRI(endpoint string) *Encapv6NLRI {
	return &Encapv6NLRI{
		EncapNLRI{
			IPAddrPrefixDefault{128, net.ParseIP(endpoint)},
			16,
		},
	}
}

type BGPFlowSpecType uint8

const (
	FLOW_SPEC_TYPE_UNKNOWN BGPFlowSpecType = iota
	FLOW_SPEC_TYPE_DST_PREFIX
	FLOW_SPEC_TYPE_SRC_PREFIX
	FLOW_SPEC_TYPE_IP_PROTO
	FLOW_SPEC_TYPE_PORT
	FLOW_SPEC_TYPE_DST_PORT
	FLOW_SPEC_TYPE_SRC_PORT
	FLOW_SPEC_TYPE_ICMP_TYPE
	FLOW_SPEC_TYPE_ICMP_CODE
	FLOW_SPEC_TYPE_TCP_FLAG
	FLOW_SPEC_TYPE_PKT_LEN
	FLOW_SPEC_TYPE_DSCP
	FLOW_SPEC_TYPE_FRAGMENT
	FLOW_SPEC_TYPE_LABEL
	FLOW_SPEC_TYPE_ETHERNET_TYPE // 14
	FLOW_SPEC_TYPE_SRC_MAC
	FLOW_SPEC_TYPE_DST_MAC
	FLOW_SPEC_TYPE_LLC_DSAP
	FLOW_SPEC_TYPE_LLC_SSAP
	FLOW_SPEC_TYPE_LLC_CONTROL
	FLOW_SPEC_TYPE_SNAP
	FLOW_SPEC_TYPE_VID
	FLOW_SPEC_TYPE_COS
	FLOW_SPEC_TYPE_INNER_VID
	FLOW_SPEC_TYPE_INNER_COS
)

var FlowSpecNameMap = map[BGPFlowSpecType]string{
	FLOW_SPEC_TYPE_UNKNOWN:       "unknown",
	FLOW_SPEC_TYPE_DST_PREFIX:    "destination",
	FLOW_SPEC_TYPE_SRC_PREFIX:    "source",
	FLOW_SPEC_TYPE_IP_PROTO:      "protocol",
	FLOW_SPEC_TYPE_PORT:          "port",
	FLOW_SPEC_TYPE_DST_PORT:      "destination-port",
	FLOW_SPEC_TYPE_SRC_PORT:      "source-port",
	FLOW_SPEC_TYPE_ICMP_TYPE:     "icmp-type",
	FLOW_SPEC_TYPE_ICMP_CODE:     "icmp-code",
	FLOW_SPEC_TYPE_TCP_FLAG:      "tcp-flags",
	FLOW_SPEC_TYPE_PKT_LEN:       "packet-length",
	FLOW_SPEC_TYPE_DSCP:          "dscp",
	FLOW_SPEC_TYPE_FRAGMENT:      "fragment",
	FLOW_SPEC_TYPE_LABEL:         "label",
	FLOW_SPEC_TYPE_ETHERNET_TYPE: "ether-type",
	FLOW_SPEC_TYPE_SRC_MAC:       "source-mac",
	FLOW_SPEC_TYPE_DST_MAC:       "destination-mac",
	FLOW_SPEC_TYPE_LLC_DSAP:      "llc-dsap",
	FLOW_SPEC_TYPE_LLC_SSAP:      "llc-ssap",
	FLOW_SPEC_TYPE_LLC_CONTROL:   "llc-control",
	FLOW_SPEC_TYPE_SNAP:          "snap",
	FLOW_SPEC_TYPE_VID:           "vid",
	FLOW_SPEC_TYPE_COS:           "cos",
	FLOW_SPEC_TYPE_INNER_VID:     "inner-vid",
	FLOW_SPEC_TYPE_INNER_COS:     "inner-cos",
}

var FlowSpecValueMap = map[string]BGPFlowSpecType{
	FlowSpecNameMap[FLOW_SPEC_TYPE_DST_PREFIX]:    FLOW_SPEC_TYPE_DST_PREFIX,
	FlowSpecNameMap[FLOW_SPEC_TYPE_SRC_PREFIX]:    FLOW_SPEC_TYPE_SRC_PREFIX,
	FlowSpecNameMap[FLOW_SPEC_TYPE_IP_PROTO]:      FLOW_SPEC_TYPE_IP_PROTO,
	FlowSpecNameMap[FLOW_SPEC_TYPE_PORT]:          FLOW_SPEC_TYPE_PORT,
	FlowSpecNameMap[FLOW_SPEC_TYPE_DST_PORT]:      FLOW_SPEC_TYPE_DST_PORT,
	FlowSpecNameMap[FLOW_SPEC_TYPE_SRC_PORT]:      FLOW_SPEC_TYPE_SRC_PORT,
	FlowSpecNameMap[FLOW_SPEC_TYPE_ICMP_TYPE]:     FLOW_SPEC_TYPE_ICMP_TYPE,
	FlowSpecNameMap[FLOW_SPEC_TYPE_ICMP_CODE]:     FLOW_SPEC_TYPE_ICMP_CODE,
	FlowSpecNameMap[FLOW_SPEC_TYPE_TCP_FLAG]:      FLOW_SPEC_TYPE_TCP_FLAG,
	FlowSpecNameMap[FLOW_SPEC_TYPE_PKT_LEN]:       FLOW_SPEC_TYPE_PKT_LEN,
	FlowSpecNameMap[FLOW_SPEC_TYPE_DSCP]:          FLOW_SPEC_TYPE_DSCP,
	FlowSpecNameMap[FLOW_SPEC_TYPE_FRAGMENT]:      FLOW_SPEC_TYPE_FRAGMENT,
	FlowSpecNameMap[FLOW_SPEC_TYPE_LABEL]:         FLOW_SPEC_TYPE_LABEL,
	FlowSpecNameMap[FLOW_SPEC_TYPE_ETHERNET_TYPE]: FLOW_SPEC_TYPE_ETHERNET_TYPE,
	FlowSpecNameMap[FLOW_SPEC_TYPE_SRC_MAC]:       FLOW_SPEC_TYPE_SRC_MAC,
	FlowSpecNameMap[FLOW_SPEC_TYPE_DST_MAC]:       FLOW_SPEC_TYPE_DST_MAC,
	FlowSpecNameMap[FLOW_SPEC_TYPE_LLC_DSAP]:      FLOW_SPEC_TYPE_LLC_DSAP,
	FlowSpecNameMap[FLOW_SPEC_TYPE_LLC_SSAP]:      FLOW_SPEC_TYPE_LLC_SSAP,
	FlowSpecNameMap[FLOW_SPEC_TYPE_LLC_CONTROL]:   FLOW_SPEC_TYPE_LLC_CONTROL,
	FlowSpecNameMap[FLOW_SPEC_TYPE_SNAP]:          FLOW_SPEC_TYPE_SNAP,
	FlowSpecNameMap[FLOW_SPEC_TYPE_VID]:           FLOW_SPEC_TYPE_VID,
	FlowSpecNameMap[FLOW_SPEC_TYPE_COS]:           FLOW_SPEC_TYPE_COS,
	FlowSpecNameMap[FLOW_SPEC_TYPE_INNER_VID]:     FLOW_SPEC_TYPE_INNER_VID,
	FlowSpecNameMap[FLOW_SPEC_TYPE_INNER_COS]:     FLOW_SPEC_TYPE_INNER_COS,
}

func flowSpecPrefixParser(rf RouteFamily, args []string) (FlowSpecComponentInterface, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("invalid flowspec dst/src prefix")
	}
	typ := args[0]
	ip, nw, err := net.ParseCIDR(args[1])
	if err != nil {
		return nil, fmt.Errorf("invalid ip prefix")
	}
	afi, _ := RouteFamilyToAfiSafi(rf)
	if afi == AFI_IP && ip.To4() == nil {
		return nil, fmt.Errorf("invalid ipv4 prefix")
	} else if afi == AFI_IP6 && !strings.Contains(ip.String(), ":") {
		return nil, fmt.Errorf("invalid ipv6 prefix")
	}
	ones, _ := nw.Mask.Size()
	var offset uint8
	if len(args) > 2 {
		o, err := strconv.Atoi(args[2])
		offset = uint8(o)
		if err != nil {
			return nil, err
		}
	}

	switch typ {
	case FlowSpecNameMap[FLOW_SPEC_TYPE_DST_PREFIX]:
		switch rf {
		case RF_FS_IPv4_UC, RF_FS_IPv4_VPN:
			return NewFlowSpecDestinationPrefix(NewIPAddrPrefix(uint8(ones), ip.String())), nil
		case RF_FS_IPv6_UC, RF_FS_IPv6_VPN:
			return NewFlowSpecDestinationPrefix6(NewIPv6AddrPrefix(uint8(ones), ip.String()), offset), nil
		default:
			return nil, fmt.Errorf("invalid type")
		}
	case FlowSpecNameMap[FLOW_SPEC_TYPE_SRC_PREFIX]:
		switch rf {
		case RF_FS_IPv4_UC, RF_FS_IPv4_VPN:
			return NewFlowSpecSourcePrefix(NewIPAddrPrefix(uint8(ones), ip.String())), nil
		case RF_FS_IPv6_UC, RF_FS_IPv6_VPN:
			return NewFlowSpecSourcePrefix6(NewIPv6AddrPrefix(uint8(ones), ip.String()), offset), nil
		default:
			return nil, fmt.Errorf("invalid type")
		}
	}
	return nil, fmt.Errorf("invalid type. only destination or source is allowed")
}

func flowSpecIpProtoParser(rf RouteFamily, args []string) (FlowSpecComponentInterface, error) {
	if len(args) < 2 || args[0] != FlowSpecNameMap[FLOW_SPEC_TYPE_IP_PROTO] {
		return nil, fmt.Errorf("invalid ip-proto format")
	}
	s := strings.Join(args, " ")
	for i, name := range ProtocolNameMap {
		s = strings.Replace(s, name, fmt.Sprintf("%d", i), -1)
	}
	args = strings.Split(s, " ")
	validationFunc := func(i int) error {
		if 0 < i && i < 255 {
			return nil
		}
		return fmt.Errorf("ip protocol range exceeded")
	}
	return doFlowSpecNumericParser(0, args, validationFunc)
}

func flowSpecTcpFlagParser(rf RouteFamily, args []string) (FlowSpecComponentInterface, error) {
	args = append(args[:0], args[1:]...) // removing tcp-flags string
	fullCmd := strings.Join(args, " ")   // rebuiling tcp filters
	opsFlags, err := parseTcpFlagCmd(fullCmd)
	if err != nil {
		return nil, err
	}
	items := make([]*FlowSpecComponentItem, 0)
	for _, opFlag := range opsFlags {
		items = append(items, NewFlowSpecComponentItem(opFlag[0], opFlag[1]))
	}
	return NewFlowSpecComponent(FLOW_SPEC_TYPE_TCP_FLAG, items), nil
}

func parseTcpFlagCmd(myCmd string) ([][2]int, error) {
	var index int = 0
	var tcpOperatorsFlagsValues [][2]int
	var operatorValue [2]int
	for index < len(myCmd) {
		myCmdChar := myCmd[index : index+1]
		switch myCmdChar {
		case TCPFlagOpNameMap[TCP_FLAG_OP_MATCH]:
			if bit := TCPFlagOpValueMap[myCmdChar]; bit&TCPFlagOp(operatorValue[0]) == 0 {
				operatorValue[0] |= int(bit)
				index++
			} else {
				err := fmt.Errorf("Match flag appears multiple time")
				return nil, err
			}
		case TCPFlagOpNameMap[TCP_FLAG_OP_NOT]:
			if bit := TCPFlagOpValueMap[myCmdChar]; bit&TCPFlagOp(operatorValue[0]) == 0 {
				operatorValue[0] |= int(bit)
				index++
			} else {
				err := fmt.Errorf("Not flag appears multiple time")
				return nil, err
			}
		case TCPFlagOpNameMap[TCP_FLAG_OP_AND], TCPFlagOpNameMap[TCP_FLAG_OP_OR]:
			if bit := TCPFlagOpValueMap[myCmdChar]; bit&TCPFlagOp(operatorValue[0]) == 0 {
				operatorValue[0] |= int(bit)
				tcpOperatorsFlagsValues = append(tcpOperatorsFlagsValues, operatorValue)
				operatorValue[0] = 0
				operatorValue[1] = 0
				index++
			} else {
				err := fmt.Errorf("AND or OR (space) operator appears multiple time")
				return nil, err
			}
		case TCPFlagNameMap[TCP_FLAG_ACK], TCPFlagNameMap[TCP_FLAG_SYN], TCPFlagNameMap[TCP_FLAG_FIN],
			TCPFlagNameMap[TCP_FLAG_URGENT], TCPFlagNameMap[TCP_FLAG_ECE], TCPFlagNameMap[TCP_FLAG_RST],
			TCPFlagNameMap[TCP_FLAG_CWR], TCPFlagNameMap[TCP_FLAG_PUSH]:
			myLoopChar := myCmdChar
			loopIndex := index
			// we loop till we reach the end of TCP flags description
			// exit conditions : we reach the end of tcp flags (we find & or ' ') or we reach the end of the line
			for loopIndex < len(myCmd) &&
				(myLoopChar != TCPFlagOpNameMap[TCP_FLAG_OP_AND] && myLoopChar != TCPFlagOpNameMap[TCP_FLAG_OP_OR]) {
				// we check if inspected charater is a well known tcp flag and if it doesn't appear twice
				if bit, isPresent := TCPFlagValueMap[myLoopChar]; isPresent && (bit&TCPFlag(operatorValue[1]) == 0) {
					operatorValue[1] |= int(bit) // we set this flag
					loopIndex++                  // we move to next character
					if loopIndex < len(myCmd) {
						myLoopChar = myCmd[loopIndex : loopIndex+1] // we move to the next character only if we didn't reach the end of cmd
					}
				} else {
					err := fmt.Errorf("flag %s appears multiple time or is not part of TCP flags", myLoopChar)
					return nil, err
				}
			}
			// we are done with flags, we give back the next cooming charater to the main loop
			index = loopIndex
		default:
			err := fmt.Errorf("flag %s not part of tcp flags", myCmdChar)
			return nil, err
		}
	}
	operatorValue[0] |= int(TCPFlagOpValueMap["E"])
	tcpOperatorsFlagsValues = append(tcpOperatorsFlagsValues, operatorValue)
	return tcpOperatorsFlagsValues, nil
}

func flowSpecEtherTypeParser(rf RouteFamily, args []string) (FlowSpecComponentInterface, error) {
	if len(args) < 2 || args[0] != FlowSpecNameMap[FLOW_SPEC_TYPE_ETHERNET_TYPE] {
		return nil, fmt.Errorf("invalid ethernet-type format")
	}
	s := strings.Join(args, " ")
	for i, name := range EthernetTypeNameMap {
		s = strings.Replace(s, name, fmt.Sprintf("%d", i), -1)
	}
	args = strings.Split(s, " ")
	validationFunc := func(i int) error {
		if 0 < i && i < 0xffff {
			return nil
		}
		return fmt.Errorf("ethernet type range exceeded")
	}
	return doFlowSpecNumericParser(0, args, validationFunc)
}

func doFlowSpecNumericParser(rf RouteFamily, args []string, validationFunc func(int) error) (FlowSpecComponentInterface, error) {
	if afi, _ := RouteFamilyToAfiSafi(rf); afi == AFI_IP && FlowSpecValueMap[args[0]] == FLOW_SPEC_TYPE_LABEL {
		return nil, fmt.Errorf("flow label spec is only allowed for ipv6")
	}
	cmdType := args[0]
	args = append(args[:0], args[1:]...) // removing command string
	fullCmd := strings.Join(args, " ")   // rebuiling tcp filters
	opsFlags, err := parseDecValuesCmd(fullCmd, validationFunc)
	if err != nil {
		return nil, err
	}
	items := make([]*FlowSpecComponentItem, 0)
	for _, opFlag := range opsFlags {
		items = append(items, NewFlowSpecComponentItem(opFlag[0], opFlag[1]))
	}
	return NewFlowSpecComponent(FlowSpecValueMap[cmdType], items), nil
}

func parseDecValuesCmd(myCmd string, validationFunc func(int) error) ([][2]int, error) {
	var index int = 0
	var decOperatorsAndValues [][2]int
	var operatorValue [2]int
	var errorNum error
	for index < len(myCmd) {
		myCmdChar := myCmd[index : index+1]
		switch myCmdChar {
		case DECNumOpNameMap[DEC_NUM_OP_GT], DECNumOpNameMap[DEC_NUM_OP_LT]:
			// We found a < or > let's check if we face >= or <=
			if myCmd[index+1:index+2] == "=" {
				myCmdChar = myCmd[index : index+2]
				index++
			}
			if bit := DECNumOpValueMap[myCmdChar]; bit&DECNumOp(operatorValue[0]) == 0 {
				operatorValue[0] |= int(bit)
				index++
			} else {
				err := fmt.Errorf("Operator > < or >= <= appears multiple times")
				return nil, err
			}
		case "!", "=":
			// we found the beginning of a not let's check secong character
			if myCmd[index+1:index+2] == "=" {
				myCmdChar = myCmd[index : index+2]
				if bit := DECNumOpValueMap[myCmdChar]; bit&DECNumOp(operatorValue[0]) == 0 {
					operatorValue[0] |= int(bit)
					index += 2
				} else {
					err := fmt.Errorf("Not or Equal operator appears multiple time")
					return nil, err
				}
			} else {
				err := fmt.Errorf("Malformated not or equal operator")
				return nil, err
			}
		case "t", "f": // we could be facing true or false, let's check
			if myCmd == DECNumOpNameMap[DEC_NUM_OP_FALSE] || myCmd == DECNumOpNameMap[DEC_NUM_OP_TRUE] {
				if bit := DECNumOpValueMap[myCmd]; bit&DECNumOp(operatorValue[0]) == 0 {
					operatorValue[0] |= int(bit)
					index = index + len(myCmd)
				} else {
					err := fmt.Errorf("Boolean operator appears multiple times")
					return nil, err
				}
			} else {
				err := fmt.Errorf("Boolean operator %s badly formatted", myCmd)
				return nil, err
			}
		case DECLogicOpNameMap[DEC_LOGIC_OP_AND], DECLogicOpNameMap[DEC_LOGIC_OP_OR]:
			bit := DECLogicOpValueMap[myCmdChar]
			decOperatorsAndValues = append(decOperatorsAndValues, operatorValue)
			if myCmdChar == DECLogicOpNameMap[DEC_LOGIC_OP_AND] {
				operatorValue[0] = int(bit)
			} else {
				operatorValue[0] = 0
			}
			operatorValue[1] = 0
			index++
		case "0", "1", "2", "3", "4", "5", "6", "7", "8", "9":
			myLoopChar := myCmdChar
			loopIndex := index
			// we loop till we reach the end of decimal value
			// exit conditions : we reach the end of decimal value (we found & or ' ') or we reach the end of the line
			for loopIndex < len(myCmd) &&
				(myLoopChar != DECLogicOpNameMap[DEC_LOGIC_OP_AND] && myLoopChar != DECLogicOpNameMap[DEC_LOGIC_OP_OR]) {
				// we check if inspected charater is a number
				if _, err := strconv.Atoi(myLoopChar); err == nil {
					// we move to next character
					loopIndex++
					if loopIndex < len(myCmd) {
						myLoopChar = myCmd[loopIndex : loopIndex+1] // we move to the next character only if we didn't reach the end of cmd
					}
				} else {
					err := fmt.Errorf("Decimal value badly formatted: %s", myLoopChar)
					return nil, err
				}
			}
			decimalValueString := myCmd[index:loopIndex]
			operatorValue[1], errorNum = strconv.Atoi(decimalValueString)
			if errorNum != nil {
				return nil, errorNum
			}
			err := validationFunc(operatorValue[1])
			if err != nil {
				return nil, err
			}
			// we check if we found any operator, if not we set default as ==
			if operatorValue[0] == 0 {
				operatorValue[0] = DEC_NUM_OP_EQ
			}
			// we are done with decimal value, we give back the next cooming charater to the main loop
			index = loopIndex
		default:
			err := fmt.Errorf("%s not part of flowspec decimal value or operators", myCmdChar)
			return nil, err
		}
	}
	operatorValue[0] |= int(DECLogicOpValueMap["E"])
	decOperatorsAndValues = append(decOperatorsAndValues, operatorValue)
	return decOperatorsAndValues, nil
}

func flowSpecNumericParser(rf RouteFamily, args []string) (FlowSpecComponentInterface, error) {
	f := func(i int) error {
		return nil
	}
	return doFlowSpecNumericParser(rf, args, f)
}

func flowSpecPortParser(rf RouteFamily, args []string) (FlowSpecComponentInterface, error) {
	f := func(i int) error {
		if 0 <= i && i < 65536 {
			return nil
		}
		return fmt.Errorf("port range exceeded")
	}
	return doFlowSpecNumericParser(rf, args, f)
}

func flowSpecDscpParser(rf RouteFamily, args []string) (FlowSpecComponentInterface, error) {
	f := func(i int) error {
		if 0 < i && i < 64 {
			return nil
		}
		return fmt.Errorf("dscp value range exceeded")
	}
	return doFlowSpecNumericParser(rf, args, f)
}

func flowSpecFragmentParser(rf RouteFamily, args []string) (FlowSpecComponentInterface, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("invalid flowspec fragment specifier")
	}
	items := make([]*FlowSpecComponentItem, 0)
	for _, a := range args[1:] {
		value := 0
		switch a {
		case "dont-fragment":
			if afi, _ := RouteFamilyToAfiSafi(rf); afi == AFI_IP6 {
				return nil, fmt.Errorf("can't specify dont-fragment for ipv6")
			}
			value = 0x1
		case "is-fragment":
			value = 0x2
		case "first-fragment":
			value = 0x4
		case "last-fragment":
			value = 0x8
		case "not-a-fragment":
			value = 0x0
		default:
			return nil, fmt.Errorf("invalid flowspec fragment specifier")
		}
		items = append(items, NewFlowSpecComponentItem(0, value))
	}
	return NewFlowSpecComponent(FlowSpecValueMap[args[0]], items), nil
}

func flowSpecMacParser(rf RouteFamily, args []string) (FlowSpecComponentInterface, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("invalid flowspec dst/src mac")
	}
	if rf != RF_FS_L2_VPN {
		return nil, fmt.Errorf("invalid family")
	}
	typ := args[0]
	mac, err := net.ParseMAC(args[1])
	if err != nil {
		return nil, fmt.Errorf("invalid mac")
	}
	switch typ {
	case FlowSpecNameMap[FLOW_SPEC_TYPE_DST_MAC]:
		return NewFlowSpecDestinationMac(mac), nil
	case FlowSpecNameMap[FLOW_SPEC_TYPE_SRC_MAC]:
		return NewFlowSpecSourceMac(mac), nil
	}
	return nil, fmt.Errorf("invalid type. only %s or %s allowed", FlowSpecNameMap[FLOW_SPEC_TYPE_DST_MAC], FlowSpecNameMap[FLOW_SPEC_TYPE_SRC_MAC])
}

var flowSpecParserMap = map[BGPFlowSpecType]func(RouteFamily, []string) (FlowSpecComponentInterface, error){
	FLOW_SPEC_TYPE_DST_PREFIX:    flowSpecPrefixParser,
	FLOW_SPEC_TYPE_SRC_PREFIX:    flowSpecPrefixParser,
	FLOW_SPEC_TYPE_IP_PROTO:      flowSpecIpProtoParser,
	FLOW_SPEC_TYPE_PORT:          flowSpecPortParser,
	FLOW_SPEC_TYPE_DST_PORT:      flowSpecPortParser,
	FLOW_SPEC_TYPE_SRC_PORT:      flowSpecPortParser,
	FLOW_SPEC_TYPE_ICMP_TYPE:     flowSpecNumericParser,
	FLOW_SPEC_TYPE_ICMP_CODE:     flowSpecNumericParser,
	FLOW_SPEC_TYPE_TCP_FLAG:      flowSpecTcpFlagParser,
	FLOW_SPEC_TYPE_PKT_LEN:       flowSpecNumericParser,
	FLOW_SPEC_TYPE_DSCP:          flowSpecDscpParser,
	FLOW_SPEC_TYPE_FRAGMENT:      flowSpecFragmentParser,
	FLOW_SPEC_TYPE_LABEL:         flowSpecNumericParser,
	FLOW_SPEC_TYPE_ETHERNET_TYPE: flowSpecEtherTypeParser,
	FLOW_SPEC_TYPE_DST_MAC:       flowSpecMacParser,
	FLOW_SPEC_TYPE_SRC_MAC:       flowSpecMacParser,
	FLOW_SPEC_TYPE_LLC_DSAP:      flowSpecNumericParser,
	FLOW_SPEC_TYPE_LLC_SSAP:      flowSpecNumericParser,
	FLOW_SPEC_TYPE_LLC_CONTROL:   flowSpecNumericParser,
	FLOW_SPEC_TYPE_SNAP:          flowSpecNumericParser,
	FLOW_SPEC_TYPE_VID:           flowSpecNumericParser,
	FLOW_SPEC_TYPE_COS:           flowSpecNumericParser,
	FLOW_SPEC_TYPE_INNER_VID:     flowSpecNumericParser,
	FLOW_SPEC_TYPE_INNER_COS:     flowSpecNumericParser,
}

func ParseFlowSpecComponents(rf RouteFamily, input string) ([]FlowSpecComponentInterface, error) {
	idxs := make([]struct {
		t BGPFlowSpecType
		i int
	}, 0, 8)
	args := strings.Split(input, " ")
	for idx, v := range args {
		if t, ok := FlowSpecValueMap[v]; ok {
			idxs = append(idxs, struct {
				t BGPFlowSpecType
				i int
			}{t, idx})
		}
	}
	if len(idxs) == 0 {
		return nil, fmt.Errorf("failed to parse: %s", input)
	}
	cmps := make([]FlowSpecComponentInterface, 0, len(idxs))
	for i, idx := range idxs {
		var a []string
		f := flowSpecParserMap[idx.t]
		if i < len(idxs)-1 {
			a = args[idx.i:idxs[i+1].i]
		} else {
			a = args[idx.i:]
		}
		cmp, err := f(rf, a)
		if err != nil {
			return nil, err
		}
		cmps = append(cmps, cmp)
	}
	return cmps, nil
}

func (t BGPFlowSpecType) String() string {
	name, ok := FlowSpecNameMap[t]
	if !ok {
		return fmt.Sprintf("%s(%d)", FlowSpecNameMap[FLOW_SPEC_TYPE_UNKNOWN], t)
	}
	return name
}

type FlowSpecComponentInterface interface {
	DecodeFromBytes([]byte) error
	Serialize() ([]byte, error)
	Len() int
	Type() BGPFlowSpecType
	String() string
}

type flowSpecPrefix struct {
	Prefix AddrPrefixInterface
	type_  BGPFlowSpecType
}

func (p *flowSpecPrefix) DecodeFromBytes(data []byte) error {
	p.type_ = BGPFlowSpecType(data[0])
	return p.Prefix.DecodeFromBytes(data[1:])
}

func (p *flowSpecPrefix) Serialize() ([]byte, error) {
	buf := []byte{byte(p.Type())}
	bbuf, err := p.Prefix.Serialize()
	if err != nil {
		return nil, err
	}
	return append(buf, bbuf...), nil
}

func (p *flowSpecPrefix) Len() int {
	buf, _ := p.Serialize()
	return len(buf)
}

func (p *flowSpecPrefix) Type() BGPFlowSpecType {
	return p.type_
}

func (p *flowSpecPrefix) String() string {
	return fmt.Sprintf("[%s:%s]", p.Type(), p.Prefix.String())
}

func (p *flowSpecPrefix) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPFlowSpecType     `json:"type"`
		Value AddrPrefixInterface `json:"value"`
	}{
		Type:  p.Type(),
		Value: p.Prefix,
	})
}

type flowSpecPrefix6 struct {
	Prefix AddrPrefixInterface
	Offset uint8
	type_  BGPFlowSpecType
}

// draft-ietf-idr-flow-spec-v6-06
// <type (1 octet), prefix length (1 octet), prefix offset(1 octet), prefix>
func (p *flowSpecPrefix6) DecodeFromBytes(data []byte) error {
	p.type_ = BGPFlowSpecType(data[0])
	p.Offset = data[2]
	prefix := append([]byte{data[1]}, data[3:]...)
	return p.Prefix.DecodeFromBytes(prefix)
}

func (p *flowSpecPrefix6) Serialize() ([]byte, error) {
	buf := []byte{byte(p.Type())}
	bbuf, err := p.Prefix.Serialize()
	if err != nil {
		return nil, err
	}
	buf = append(buf, bbuf[0])
	buf = append(buf, p.Offset)
	return append(buf, bbuf[1:]...), nil
}

func (p *flowSpecPrefix6) Len() int {
	buf, _ := p.Serialize()
	return len(buf)
}

func (p *flowSpecPrefix6) Type() BGPFlowSpecType {
	return p.type_
}

func (p *flowSpecPrefix6) String() string {
	return fmt.Sprintf("[%s:%s/%d]", p.Type(), p.Prefix.String(), p.Offset)
}

func (p *flowSpecPrefix6) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type   BGPFlowSpecType     `json:"type"`
		Value  AddrPrefixInterface `json:"value"`
		Offset uint8               `json:"offset"`
	}{
		Type:   p.Type(),
		Value:  p.Prefix,
		Offset: p.Offset,
	})
}

type FlowSpecDestinationPrefix struct {
	flowSpecPrefix
}

func NewFlowSpecDestinationPrefix(prefix AddrPrefixInterface) *FlowSpecDestinationPrefix {
	return &FlowSpecDestinationPrefix{flowSpecPrefix{prefix, FLOW_SPEC_TYPE_DST_PREFIX}}
}

type FlowSpecSourcePrefix struct {
	flowSpecPrefix
}

func NewFlowSpecSourcePrefix(prefix AddrPrefixInterface) *FlowSpecSourcePrefix {
	return &FlowSpecSourcePrefix{flowSpecPrefix{prefix, FLOW_SPEC_TYPE_SRC_PREFIX}}
}

type FlowSpecDestinationPrefix6 struct {
	flowSpecPrefix6
}

func NewFlowSpecDestinationPrefix6(prefix AddrPrefixInterface, offset uint8) *FlowSpecDestinationPrefix6 {
	return &FlowSpecDestinationPrefix6{flowSpecPrefix6{prefix, offset, FLOW_SPEC_TYPE_DST_PREFIX}}
}

type FlowSpecSourcePrefix6 struct {
	flowSpecPrefix6
}

func NewFlowSpecSourcePrefix6(prefix AddrPrefixInterface, offset uint8) *FlowSpecSourcePrefix6 {
	return &FlowSpecSourcePrefix6{flowSpecPrefix6{prefix, offset, FLOW_SPEC_TYPE_SRC_PREFIX}}
}

type flowSpecMac struct {
	Mac   net.HardwareAddr
	type_ BGPFlowSpecType
}

func (p *flowSpecMac) DecodeFromBytes(data []byte) error {
	if len(data) < 2 || len(data) < 2+int(data[1]) {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "not all mac bits available")
	}
	p.type_ = BGPFlowSpecType(data[0])
	p.Mac = net.HardwareAddr(data[2 : 2+int(data[1])])
	return nil
}

func (p *flowSpecMac) Serialize() ([]byte, error) {
	if len(p.Mac) == 0 {
		return nil, fmt.Errorf("mac unset")
	}
	buf := []byte{byte(p.Type()), byte(len(p.Mac))}
	return append(buf, []byte(p.Mac)...), nil
}

func (p *flowSpecMac) Len() int {
	return 2 + len(p.Mac)
}

func (p *flowSpecMac) Type() BGPFlowSpecType {
	return p.type_
}

func (p *flowSpecMac) String() string {
	return fmt.Sprintf("[%s:%s]", p.Type(), p.Mac.String())
}

func (p *flowSpecMac) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPFlowSpecType `json:"type"`
		Value string          `json:"value"`
	}{
		Type:  p.Type(),
		Value: p.Mac.String(),
	})
}

type FlowSpecSourceMac struct {
	flowSpecMac
}

func NewFlowSpecSourceMac(mac net.HardwareAddr) *FlowSpecSourceMac {
	return &FlowSpecSourceMac{flowSpecMac{Mac: mac, type_: FLOW_SPEC_TYPE_SRC_MAC}}
}

type FlowSpecDestinationMac struct {
	flowSpecMac
}

func NewFlowSpecDestinationMac(mac net.HardwareAddr) *FlowSpecDestinationMac {
	return &FlowSpecDestinationMac{flowSpecMac{Mac: mac, type_: FLOW_SPEC_TYPE_DST_MAC}}
}

type FlowSpecComponentItem struct {
	Op    int `json:"op"`
	Value int `json:"value"`
}

func (v *FlowSpecComponentItem) Len() int {
	return 1 << ((uint32(v.Op) >> 4) & 0x3)
}

func (v *FlowSpecComponentItem) Serialize() ([]byte, error) {
	if v.Value < 0 {
		return nil, fmt.Errorf("invalid value size(too small): %d", v.Value)
	}
	if v.Op < 0 || v.Op > math.MaxUint8 {
		return nil, fmt.Errorf("invalid op size: %d", v.Op)

	}
	order := uint32(math.Log2(float64(v.Len())))
	buf := make([]byte, 1+(1<<order))
	buf[0] = byte(uint32(v.Op) | order<<4)
	switch order {
	case 0:
		buf[1] = byte(v.Value)
	case 1:
		binary.BigEndian.PutUint16(buf[1:], uint16(v.Value))
	case 2:
		binary.BigEndian.PutUint32(buf[1:], uint32(v.Value))
	case 3:
		binary.BigEndian.PutUint64(buf[1:], uint64(v.Value))
	default:
		return nil, fmt.Errorf("invalid value size(too big): %d", v.Value)
	}
	return buf, nil
}

func NewFlowSpecComponentItem(op int, value int) *FlowSpecComponentItem {
	v := &FlowSpecComponentItem{op, value}
	order := uint32(math.Log2(float64(v.Len())))
	// we don't know if not initialized properly or initialized to
	// zero...
	if order == 0 {
		order = func() uint32 {
			for i := 0; i < 3; i++ {
				if v.Value < (1 << ((1 << uint(i)) * 8)) {
					return uint32(i)
				}
			}
			// return invalid order
			return 4
		}()
	}
	if order > 3 {
		return nil
	}
	v.Op = int(uint32(v.Op) | order<<4)
	return v
}

type FlowSpecComponent struct {
	Items []*FlowSpecComponentItem
	type_ BGPFlowSpecType
}

func (p *FlowSpecComponent) DecodeFromBytes(data []byte) error {
	p.type_ = BGPFlowSpecType(data[0])
	data = data[1:]
	p.Items = make([]*FlowSpecComponentItem, 0)
	for {
		if len(data) < 2 {
			return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "not all flowspec component bytes available")
		}
		op := data[0]
		end := op & 0x80
		l := 1 << ((op >> 4) & 0x3) // (min, max) = (1, 8)
		v := make([]byte, 8)
		copy(v[8-l:], data[1:1+l])
		i := int(binary.BigEndian.Uint64(v))
		item := &FlowSpecComponentItem{int(op), i}
		p.Items = append(p.Items, item)
		if end > 0 {
			break
		}
		data = data[1+l:]
	}
	return nil
}

func (p *FlowSpecComponent) Serialize() ([]byte, error) {
	buf := []byte{byte(p.Type())}
	for i, v := range p.Items {
		//set end-of-list bit
		if i == (len(p.Items) - 1) {
			v.Op |= 0x80
		} else {
			v.Op &^= 0x80
		}
		bbuf, err := v.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, bbuf...)
	}
	return buf, nil
}

func (p *FlowSpecComponent) Len() int {
	l := 1
	for _, item := range p.Items {
		l += (item.Len() + 1)
	}
	return l
}

func (p *FlowSpecComponent) Type() BGPFlowSpecType {
	return p.type_
}

func formatRaw(op int, value int) string {
	return fmt.Sprintf("op: %b, value: %d", op, value)
}

func formatNumericOp(op int) string {
	var opstr string
	if op&0x40 > 0 {
		opstr = "&"
	} else {
		opstr = " "
	}
	if op&0x2 > 0 {
		opstr += ">"
	}
	if op&0x4 > 0 {
		opstr += "<"
	}
	if op&0x1 > 0 {
		opstr += "="
	}
	return opstr
}

func formatNumericOpFrontQty(op int) string {
	gtlteqOnly := op & 0x07
	return fmt.Sprintf("%s", DECNumOpNameMap[DECNumOp(gtlteqOnly)])
}

func formatNumericOpBackLogic(op int) string {
	andOrOnly := op & 0x40 // let's ignore the END bit to avoid having an E at the end of the string
	return fmt.Sprintf("%s", DECLogicOpNameMap[DECLogicOp(andOrOnly)])
}

func formatNumeric(op int, value int) string {
	gtlteqOnly := op & 0x07
	if DECNumOp(gtlteqOnly) == DECNumOpValueMap[DECNumOpNameMap[DEC_NUM_OP_FALSE]] || DECNumOp(gtlteqOnly) == DECNumOpValueMap[DECNumOpNameMap[DEC_NUM_OP_TRUE]] {
		return fmt.Sprintf("%s%s", formatNumericOpFrontQty(op), formatNumericOpBackLogic(op))
	} else {
		return fmt.Sprintf("%s%s%d", formatNumericOpBackLogic(op), formatNumericOpFrontQty(op), value)
	}
}

func formatProto(op int, value int) string {
	return fmt.Sprintf("%s%s%s", formatNumericOpFrontQty(op), Protocol(value).String(), formatNumericOpBackLogic(op))
}

func formatFlag(op int, value int) string {
	var retString string
	if op&TCP_FLAG_OP_MATCH > 0 {
		retString = fmt.Sprintf("%s%s", retString, TCPFlagOpNameMap[TCP_FLAG_OP_MATCH])
	}
	if op&TCP_FLAG_OP_NOT > 0 {
		retString = fmt.Sprintf("%s%s", retString, TCPFlagOpNameMap[TCP_FLAG_OP_NOT])
	}
	for flag, valueFlag := range TCPFlagValueMap {
		if value&int(valueFlag) > 0 {
			retString = fmt.Sprintf("%s%s", retString, flag)
		}
	}
	if op&TCP_FLAG_OP_AND > 0 {
		retString = fmt.Sprintf("%s%s", retString, TCPFlagOpNameMap[TCP_FLAG_OP_AND])
	} else { // default is or
		retString = fmt.Sprintf("%s%s", retString, TCPFlagOpNameMap[TCP_FLAG_OP_OR])
	}
	return retString
}

func formatFragment(op int, value int) string {
	ss := make([]string, 0)
	if value == 0 {
		ss = append(ss, "not-a-fragment")
	}
	if value&0x1 > 0 {
		ss = append(ss, "dont-fragment")
	}
	if value&0x2 > 0 {
		ss = append(ss, "is-fragment")
	}
	if value&0x4 > 0 {
		ss = append(ss, "first-fragment")
	}
	if value&0x8 > 0 {
		ss = append(ss, "last-fragment")
	}
	if len(ss) > 1 {
		return fmt.Sprintf("%s(%s)", formatNumericOp(op), strings.Join(ss, "|"))
	}
	return fmt.Sprintf("%s%s", formatNumericOp(op), ss[0])
}

func formatEtherType(op int, value int) string {
	return fmt.Sprintf("%s%s", formatNumericOp(op), EthernetType(value).String())
}

var flowSpecFormatMap = map[BGPFlowSpecType]func(op int, value int) string{
	FLOW_SPEC_TYPE_UNKNOWN:       formatRaw,
	FLOW_SPEC_TYPE_IP_PROTO:      formatProto,
	FLOW_SPEC_TYPE_PORT:          formatNumeric,
	FLOW_SPEC_TYPE_DST_PORT:      formatNumeric,
	FLOW_SPEC_TYPE_SRC_PORT:      formatNumeric,
	FLOW_SPEC_TYPE_ICMP_TYPE:     formatNumeric,
	FLOW_SPEC_TYPE_ICMP_CODE:     formatNumeric,
	FLOW_SPEC_TYPE_TCP_FLAG:      formatFlag,
	FLOW_SPEC_TYPE_PKT_LEN:       formatNumeric,
	FLOW_SPEC_TYPE_DSCP:          formatNumeric,
	FLOW_SPEC_TYPE_FRAGMENT:      formatFragment,
	FLOW_SPEC_TYPE_LABEL:         formatNumeric,
	FLOW_SPEC_TYPE_ETHERNET_TYPE: formatEtherType,
	FLOW_SPEC_TYPE_LLC_DSAP:      formatNumeric,
	FLOW_SPEC_TYPE_LLC_SSAP:      formatNumeric,
	FLOW_SPEC_TYPE_LLC_CONTROL:   formatNumeric,
	FLOW_SPEC_TYPE_SNAP:          formatNumeric,
	FLOW_SPEC_TYPE_VID:           formatNumeric,
	FLOW_SPEC_TYPE_COS:           formatNumeric,
	FLOW_SPEC_TYPE_INNER_VID:     formatNumeric,
	FLOW_SPEC_TYPE_INNER_COS:     formatNumeric,
}

func (p *FlowSpecComponent) String() string {
	f := flowSpecFormatMap[FLOW_SPEC_TYPE_UNKNOWN]
	if _, ok := flowSpecFormatMap[p.Type()]; ok {
		f = flowSpecFormatMap[p.Type()]
	}
	buf := bytes.NewBuffer(make([]byte, 0, 32))
	for _, i := range p.Items {
		buf.WriteString(f(i.Op, i.Value))
	}
	return fmt.Sprintf("[%s:%s]", p.type_, buf.String())
}

func (p *FlowSpecComponent) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPFlowSpecType          `json:"type"`
		Value []*FlowSpecComponentItem `json:"value"`
	}{
		Type:  p.Type(),
		Value: p.Items,
	})
}

func NewFlowSpecComponent(type_ BGPFlowSpecType, items []*FlowSpecComponentItem) *FlowSpecComponent {
	return &FlowSpecComponent{
		Items: items,
		type_: type_,
	}
}

type FlowSpecUnknown struct {
	Value []byte
}

func (p *FlowSpecUnknown) DecodeFromBytes(data []byte) error {
	p.Value = data
	return nil
}

func (p *FlowSpecUnknown) Serialize() ([]byte, error) {
	return p.Value, nil
}

func (p *FlowSpecUnknown) Len() int {
	return len(p.Value)
}

func (p *FlowSpecUnknown) Type() BGPFlowSpecType {
	if len(p.Value) > 0 {
		return BGPFlowSpecType(p.Value[0])
	}
	return FLOW_SPEC_TYPE_UNKNOWN
}

func (p *FlowSpecUnknown) String() string {
	return fmt.Sprintf("[unknown:%v]", p.Value)
}

func (p *FlowSpecUnknown) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPFlowSpecType `json:"type"`
		Value string          `json:"value"`
	}{
		Type:  p.Type(),
		Value: string(p.Value),
	})
}

type FlowSpecNLRI struct {
	Value []FlowSpecComponentInterface
	rf    RouteFamily
	rd    RouteDistinguisherInterface
}

func (n *FlowSpecNLRI) AFI() uint16 {
	afi, _ := RouteFamilyToAfiSafi(n.rf)
	return afi
}

func (n *FlowSpecNLRI) SAFI() uint8 {
	_, safi := RouteFamilyToAfiSafi(n.rf)
	return safi
}

func (n *FlowSpecNLRI) RD() RouteDistinguisherInterface {
	return n.rd
}

func (n *FlowSpecNLRI) decodeFromBytes(rf RouteFamily, data []byte) error {
	var length int
	if (data[0]>>4) == 0xf && len(data) > 2 {
		length = int(binary.BigEndian.Uint16(data[0:2]))
		data = data[2:]
	} else if len(data) > 1 {
		length = int(data[0])
		data = data[1:]
	} else {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "not all flowspec component bytes available")
	}

	n.rf = rf

	if n.SAFI() == SAFI_FLOW_SPEC_VPN {
		if length < 8 {
			return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "not all flowspec component bytes available")
		}
		n.rd = GetRouteDistinguisher(data[:8])
		data = data[8:]
		length -= 8
	}

	for l := length; l > 0; {
		if len(data) == 0 {
			return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "not all flowspec component bytes available")
		}
		t := BGPFlowSpecType(data[0])
		var i FlowSpecComponentInterface
		switch t {
		case FLOW_SPEC_TYPE_DST_PREFIX:
			switch {
			case rf>>16 == AFI_IP:
				i = NewFlowSpecDestinationPrefix(NewIPAddrPrefix(0, ""))
			case rf>>16 == AFI_IP6:
				i = NewFlowSpecDestinationPrefix6(NewIPv6AddrPrefix(0, ""), 0)
			default:
				return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("Invalid address family: %v", rf))
			}
		case FLOW_SPEC_TYPE_SRC_PREFIX:
			switch {
			case rf>>16 == AFI_IP:
				i = NewFlowSpecSourcePrefix(NewIPAddrPrefix(0, ""))
			case rf>>16 == AFI_IP6:
				i = NewFlowSpecSourcePrefix6(NewIPv6AddrPrefix(0, ""), 0)
			default:
				return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("Invalid address family: %v", rf))
			}
		case FLOW_SPEC_TYPE_SRC_MAC:
			switch rf {
			case RF_FS_L2_VPN:
				i = NewFlowSpecSourceMac(nil)
			default:
				return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("Invalid address family: %v", rf))
			}
		case FLOW_SPEC_TYPE_DST_MAC:
			switch rf {
			case RF_FS_L2_VPN:
				i = NewFlowSpecDestinationMac(nil)
			default:
				return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("Invalid address family: %v", rf))
			}
		case FLOW_SPEC_TYPE_IP_PROTO, FLOW_SPEC_TYPE_PORT, FLOW_SPEC_TYPE_DST_PORT, FLOW_SPEC_TYPE_SRC_PORT,
			FLOW_SPEC_TYPE_ICMP_TYPE, FLOW_SPEC_TYPE_ICMP_CODE, FLOW_SPEC_TYPE_TCP_FLAG, FLOW_SPEC_TYPE_PKT_LEN,
			FLOW_SPEC_TYPE_DSCP, FLOW_SPEC_TYPE_FRAGMENT, FLOW_SPEC_TYPE_LABEL, FLOW_SPEC_TYPE_ETHERNET_TYPE,
			FLOW_SPEC_TYPE_LLC_DSAP, FLOW_SPEC_TYPE_LLC_SSAP, FLOW_SPEC_TYPE_LLC_CONTROL, FLOW_SPEC_TYPE_SNAP,
			FLOW_SPEC_TYPE_VID, FLOW_SPEC_TYPE_COS, FLOW_SPEC_TYPE_INNER_VID, FLOW_SPEC_TYPE_INNER_COS:
			i = NewFlowSpecComponent(t, nil)
		default:
			i = &FlowSpecUnknown{}
		}

		err := i.DecodeFromBytes(data)
		if err != nil {
			i = &FlowSpecUnknown{data}
		}
		l -= i.Len()
		data = data[i.Len():]
		n.Value = append(n.Value, i)
	}

	return nil
}

func (n *FlowSpecNLRI) Serialize() ([]byte, error) {
	buf := make([]byte, 0, 32)
	if n.SAFI() == SAFI_FLOW_SPEC_VPN {
		if n.rd == nil {
			return nil, fmt.Errorf("RD is nil")
		}
		b, err := n.rd.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, b...)
	}
	for _, v := range n.Value {
		b, err := v.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, b...)
	}
	length := n.Len()
	if length > 0xfff {
		return nil, fmt.Errorf("Too large: %d", length)
	} else if length < 0xf0 {
		length -= 1
		buf = append([]byte{byte(length)}, buf...)
	} else {
		length -= 2
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, uint16(length))
		buf = append(b, buf...)
	}

	return buf, nil
}

func (n *FlowSpecNLRI) Len() int {
	l := 0
	if n.SAFI() == SAFI_FLOW_SPEC_VPN {
		l += n.RD().Len()
	}
	for _, v := range n.Value {
		l += v.Len()
	}
	if l < 0xf0 {
		return l + 1
	} else {
		return l + 2
	}
}

func (n *FlowSpecNLRI) String() string {
	buf := bytes.NewBuffer(make([]byte, 0, 32))
	if n.SAFI() == SAFI_FLOW_SPEC_VPN {
		buf.WriteString(fmt.Sprintf("[rd: %s]", n.rd))
	}
	for _, v := range n.Value {
		buf.WriteString(v.String())
	}
	return buf.String()
}

func (n *FlowSpecNLRI) MarshalJSON() ([]byte, error) {
	if n.rd != nil {
		return json.Marshal(struct {
			RD    RouteDistinguisherInterface  `json:"rd"`
			Value []FlowSpecComponentInterface `json:"value"`
		}{
			RD:    n.rd,
			Value: n.Value,
		})
	}
	return json.Marshal(struct {
		Value []FlowSpecComponentInterface `json:"value"`
	}{
		Value: n.Value,
	})

}

//
// CompareFlowSpecNLRI(n, m) returns
// -1 when m has precedence
//  0 when n and m have same precedence
//  1 when n has precedence
//
func CompareFlowSpecNLRI(n, m *FlowSpecNLRI) (int, error) {
	family := AfiSafiToRouteFamily(n.AFI(), n.SAFI())
	if family != AfiSafiToRouteFamily(m.AFI(), m.SAFI()) {
		return 0, fmt.Errorf("address family mismatch")
	}
	longer := n.Value
	shorter := m.Value
	invert := 1
	if n.SAFI() == SAFI_FLOW_SPEC_VPN {
		k, _ := n.Serialize()
		l, _ := m.Serialize()
		if result := bytes.Compare(k, l); result != 0 {
			return result, nil
		}
	}
	if len(n.Value) < len(m.Value) {
		longer = m.Value
		shorter = n.Value
		invert = -1
	}
	for idx, v := range longer {
		if len(shorter) < idx+1 {
			return invert, nil
		}
		w := shorter[idx]
		if v.Type() < w.Type() {
			return invert, nil
		} else if v.Type() > w.Type() {
			return invert * -1, nil
		} else if v.Type() == FLOW_SPEC_TYPE_DST_PREFIX || v.Type() == FLOW_SPEC_TYPE_SRC_PREFIX {
			// RFC5575 5.1
			//
			// For IP prefix values (IP destination and source prefix) precedence is
			// given to the lowest IP value of the common prefix length; if the
			// common prefix is equal, then the most specific prefix has precedence.
			var p, q *IPAddrPrefixDefault
			var pCommon, qCommon uint64
			if n.AFI() == AFI_IP {
				if v.Type() == FLOW_SPEC_TYPE_DST_PREFIX {
					p = &v.(*FlowSpecDestinationPrefix).Prefix.(*IPAddrPrefix).IPAddrPrefixDefault
					q = &w.(*FlowSpecDestinationPrefix).Prefix.(*IPAddrPrefix).IPAddrPrefixDefault
				} else {
					p = &v.(*FlowSpecSourcePrefix).Prefix.(*IPAddrPrefix).IPAddrPrefixDefault
					q = &w.(*FlowSpecSourcePrefix).Prefix.(*IPAddrPrefix).IPAddrPrefixDefault
				}
				min := p.Length
				if q.Length < p.Length {
					min = q.Length
				}
				pCommon = uint64(binary.BigEndian.Uint32([]byte(p.Prefix.To4())) >> (32 - min))
				qCommon = uint64(binary.BigEndian.Uint32([]byte(q.Prefix.To4())) >> (32 - min))
			} else if n.AFI() == AFI_IP6 {
				if v.Type() == FLOW_SPEC_TYPE_DST_PREFIX {
					p = &v.(*FlowSpecDestinationPrefix6).Prefix.(*IPv6AddrPrefix).IPAddrPrefixDefault
					q = &w.(*FlowSpecDestinationPrefix6).Prefix.(*IPv6AddrPrefix).IPAddrPrefixDefault
				} else {
					p = &v.(*FlowSpecSourcePrefix6).Prefix.(*IPv6AddrPrefix).IPAddrPrefixDefault
					q = &w.(*FlowSpecSourcePrefix6).Prefix.(*IPv6AddrPrefix).IPAddrPrefixDefault
				}
				min := uint(p.Length)
				if q.Length < p.Length {
					min = uint(q.Length)
				}
				var mask uint
				if min-64 > 0 {
					mask = min - 64
				}
				pCommon = binary.BigEndian.Uint64([]byte(p.Prefix.To16()[:8])) >> mask
				qCommon = binary.BigEndian.Uint64([]byte(q.Prefix.To16()[:8])) >> mask
				if pCommon == qCommon && mask == 0 {
					mask = 64 - min
					pCommon = binary.BigEndian.Uint64([]byte(p.Prefix.To16()[8:])) >> mask
					qCommon = binary.BigEndian.Uint64([]byte(q.Prefix.To16()[8:])) >> mask
				}
			}

			if pCommon < qCommon {
				return invert, nil
			} else if pCommon > qCommon {
				return invert * -1, nil
			} else if p.Length > q.Length {
				return invert, nil
			} else if p.Length < q.Length {
				return invert * -1, nil
			}

		} else {
			// RFC5575 5.1
			//
			// For all other component types, unless otherwise specified, the
			// comparison is performed by comparing the component data as a binary
			// string using the memcmp() function as defined by the ISO C standard.
			// For strings of different lengths, the common prefix is compared.  If
			// equal, the longest string is considered to have higher precedence
			// than the shorter one.
			p, _ := v.Serialize()
			q, _ := w.Serialize()
			min := len(p)
			if len(q) < len(p) {
				min = len(q)
			}
			if result := bytes.Compare(p[:min], q[:min]); result < 0 {
				return invert, nil
			} else if result > 0 {
				return invert * -1, nil
			} else if len(p) > len(q) {
				return invert, nil
			} else if len(q) > len(p) {
				return invert * -1, nil
			}
		}
	}
	return 0, nil
}

type FlowSpecIPv4Unicast struct {
	FlowSpecNLRI
}

func (n *FlowSpecIPv4Unicast) DecodeFromBytes(data []byte) error {
	return n.decodeFromBytes(AfiSafiToRouteFamily(n.AFI(), n.SAFI()), data)
}

func NewFlowSpecIPv4Unicast(value []FlowSpecComponentInterface) *FlowSpecIPv4Unicast {
	return &FlowSpecIPv4Unicast{FlowSpecNLRI{value, RF_FS_IPv4_UC, nil}}
}

type FlowSpecIPv4VPN struct {
	FlowSpecNLRI
}

func (n *FlowSpecIPv4VPN) DecodeFromBytes(data []byte) error {
	return n.decodeFromBytes(AfiSafiToRouteFamily(n.AFI(), n.SAFI()), data)
}

func NewFlowSpecIPv4VPN(rd RouteDistinguisherInterface, value []FlowSpecComponentInterface) *FlowSpecIPv4VPN {
	return &FlowSpecIPv4VPN{FlowSpecNLRI{value, RF_FS_IPv4_VPN, rd}}
}

type FlowSpecIPv6Unicast struct {
	FlowSpecNLRI
}

func (n *FlowSpecIPv6Unicast) DecodeFromBytes(data []byte) error {
	return n.decodeFromBytes(AfiSafiToRouteFamily(n.AFI(), n.SAFI()), data)
}

func NewFlowSpecIPv6Unicast(value []FlowSpecComponentInterface) *FlowSpecIPv6Unicast {
	return &FlowSpecIPv6Unicast{FlowSpecNLRI{
		Value: value,
		rf:    RF_FS_IPv6_UC,
	}}
}

type FlowSpecIPv6VPN struct {
	FlowSpecNLRI
}

func (n *FlowSpecIPv6VPN) DecodeFromBytes(data []byte) error {
	return n.decodeFromBytes(AfiSafiToRouteFamily(n.AFI(), n.SAFI()), data)
}

func NewFlowSpecIPv6VPN(rd RouteDistinguisherInterface, value []FlowSpecComponentInterface) *FlowSpecIPv6VPN {
	return &FlowSpecIPv6VPN{FlowSpecNLRI{
		Value: value,
		rf:    RF_FS_IPv6_VPN,
		rd:    rd,
	}}
}

type FlowSpecL2VPN struct {
	FlowSpecNLRI
}

func (n *FlowSpecL2VPN) DecodeFromBytes(data []byte) error {
	return n.decodeFromBytes(AfiSafiToRouteFamily(n.AFI(), n.SAFI()), data)
}

func NewFlowSpecL2VPN(rd RouteDistinguisherInterface, value []FlowSpecComponentInterface) *FlowSpecL2VPN {
	return &FlowSpecL2VPN{FlowSpecNLRI{
		Value: value,
		rf:    RF_FS_L2_VPN,
		rd:    rd,
	}}
}

type OpaqueNLRI struct {
	Length uint16
	Key    []byte
	Value  []byte
}

func (n *OpaqueNLRI) DecodeFromBytes(data []byte) error {
	if len(data) < 2 {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Not all OpaqueNLRI bytes available")
	}
	n.Length = binary.BigEndian.Uint16(data[0:2])
	if len(data)-2 < int(n.Length) {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Not all OpaqueNLRI bytes available")
	}
	n.Key = data[2 : 2+n.Length]
	n.Value = data[2+n.Length:]
	return nil
}

func (n *OpaqueNLRI) Serialize() ([]byte, error) {
	if len(n.Key) > math.MaxUint16 {
		return nil, fmt.Errorf("Key length too big")
	}
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(len(n.Key)))
	buf = append(buf, n.Key...)
	return append(buf, n.Value...), nil
}

func (n *OpaqueNLRI) AFI() uint16 {
	return AFI_OPAQUE
}

func (n *OpaqueNLRI) SAFI() uint8 {
	return SAFI_KEY_VALUE
}

func (n *OpaqueNLRI) Len() int {
	return 2 + len(n.Key) + len(n.Value)
}

func (n *OpaqueNLRI) String() string {
	return fmt.Sprintf("%s", n.Key)
}

func (n *OpaqueNLRI) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}{
		Key:   string(n.Key),
		Value: string(n.Value),
	})
}

func NewOpaqueNLRI(key, value []byte) *OpaqueNLRI {
	return &OpaqueNLRI{
		Key:   key,
		Value: value,
	}
}

func AfiSafiToRouteFamily(afi uint16, safi uint8) RouteFamily {
	return RouteFamily(int(afi)<<16 | int(safi))
}

func RouteFamilyToAfiSafi(rf RouteFamily) (uint16, uint8) {
	return uint16(int(rf) >> 16), uint8(int(rf) & 0xff)
}

type RouteFamily int

func (f RouteFamily) String() string {
	if n, y := AddressFamilyNameMap[f]; y {
		return n
	}
	return fmt.Sprintf("UnknownFamily(%d)", f)
}

const (
	RF_IPv4_UC     RouteFamily = AFI_IP<<16 | SAFI_UNICAST
	RF_IPv6_UC     RouteFamily = AFI_IP6<<16 | SAFI_UNICAST
	RF_IPv4_MC     RouteFamily = AFI_IP<<16 | SAFI_MULTICAST
	RF_IPv6_MC     RouteFamily = AFI_IP6<<16 | SAFI_MULTICAST
	RF_IPv4_VPN    RouteFamily = AFI_IP<<16 | SAFI_MPLS_VPN
	RF_IPv6_VPN    RouteFamily = AFI_IP6<<16 | SAFI_MPLS_VPN
	RF_IPv4_VPN_MC RouteFamily = AFI_IP<<16 | SAFI_MPLS_VPN_MULTICAST
	RF_IPv6_VPN_MC RouteFamily = AFI_IP6<<16 | SAFI_MPLS_VPN_MULTICAST
	RF_IPv4_MPLS   RouteFamily = AFI_IP<<16 | SAFI_MPLS_LABEL
	RF_IPv6_MPLS   RouteFamily = AFI_IP6<<16 | SAFI_MPLS_LABEL
	RF_VPLS        RouteFamily = AFI_L2VPN<<16 | SAFI_VPLS
	RF_EVPN        RouteFamily = AFI_L2VPN<<16 | SAFI_EVPN
	RF_RTC_UC      RouteFamily = AFI_IP<<16 | SAFI_ROUTE_TARGET_CONSTRAINTS
	RF_IPv4_ENCAP  RouteFamily = AFI_IP<<16 | SAFI_ENCAPSULATION
	RF_IPv6_ENCAP  RouteFamily = AFI_IP6<<16 | SAFI_ENCAPSULATION
	RF_FS_IPv4_UC  RouteFamily = AFI_IP<<16 | SAFI_FLOW_SPEC_UNICAST
	RF_FS_IPv4_VPN RouteFamily = AFI_IP<<16 | SAFI_FLOW_SPEC_VPN
	RF_FS_IPv6_UC  RouteFamily = AFI_IP6<<16 | SAFI_FLOW_SPEC_UNICAST
	RF_FS_IPv6_VPN RouteFamily = AFI_IP6<<16 | SAFI_FLOW_SPEC_VPN
	RF_FS_L2_VPN   RouteFamily = AFI_L2VPN<<16 | SAFI_FLOW_SPEC_VPN
	RF_OPAQUE      RouteFamily = AFI_OPAQUE<<16 | SAFI_KEY_VALUE
)

var AddressFamilyNameMap = map[RouteFamily]string{
	RF_IPv4_UC:     "ipv4-unicast",
	RF_IPv6_UC:     "ipv6-unicast",
	RF_IPv4_MC:     "ipv4-multicast",
	RF_IPv6_MC:     "ipv6-multicast",
	RF_IPv4_MPLS:   "ipv4-labelled-unicast",
	RF_IPv6_MPLS:   "ipv6-labelled-unicast",
	RF_IPv4_VPN:    "l3vpn-ipv4-unicast",
	RF_IPv6_VPN:    "l3vpn-ipv6-unicast",
	RF_IPv4_VPN_MC: "l3vpn-ipv4-multicast",
	RF_IPv6_VPN_MC: "l3vpn-ipv6-multicast",
	RF_VPLS:        "l2vpn-vpls",
	RF_EVPN:        "l2vpn-evpn",
	RF_RTC_UC:      "rtc",
	RF_IPv4_ENCAP:  "ipv4-encap",
	RF_IPv6_ENCAP:  "ipv6-encap",
	RF_FS_IPv4_UC:  "ipv4-flowspec",
	RF_FS_IPv4_VPN: "l3vpn-ipv4-flowspec",
	RF_FS_IPv6_UC:  "ipv6-flowspec",
	RF_FS_IPv6_VPN: "l3vpn-ipv6-flowspec",
	RF_FS_L2_VPN:   "l2vpn-flowspec",
	RF_OPAQUE:      "opaque",
}

var AddressFamilyValueMap = map[string]RouteFamily{
	AddressFamilyNameMap[RF_IPv4_UC]:     RF_IPv4_UC,
	AddressFamilyNameMap[RF_IPv6_UC]:     RF_IPv6_UC,
	AddressFamilyNameMap[RF_IPv4_MC]:     RF_IPv4_MC,
	AddressFamilyNameMap[RF_IPv6_MC]:     RF_IPv6_MC,
	AddressFamilyNameMap[RF_IPv4_MPLS]:   RF_IPv4_MPLS,
	AddressFamilyNameMap[RF_IPv6_MPLS]:   RF_IPv6_MPLS,
	AddressFamilyNameMap[RF_IPv4_VPN]:    RF_IPv4_VPN,
	AddressFamilyNameMap[RF_IPv6_VPN]:    RF_IPv6_VPN,
	AddressFamilyNameMap[RF_IPv4_VPN_MC]: RF_IPv4_VPN_MC,
	AddressFamilyNameMap[RF_IPv6_VPN_MC]: RF_IPv6_VPN_MC,
	AddressFamilyNameMap[RF_VPLS]:        RF_VPLS,
	AddressFamilyNameMap[RF_EVPN]:        RF_EVPN,
	AddressFamilyNameMap[RF_RTC_UC]:      RF_RTC_UC,
	AddressFamilyNameMap[RF_IPv4_ENCAP]:  RF_IPv4_ENCAP,
	AddressFamilyNameMap[RF_IPv6_ENCAP]:  RF_IPv6_ENCAP,
	AddressFamilyNameMap[RF_FS_IPv4_UC]:  RF_FS_IPv4_UC,
	AddressFamilyNameMap[RF_FS_IPv4_VPN]: RF_FS_IPv4_VPN,
	AddressFamilyNameMap[RF_FS_IPv6_UC]:  RF_FS_IPv6_UC,
	AddressFamilyNameMap[RF_FS_IPv6_VPN]: RF_FS_IPv6_VPN,
	AddressFamilyNameMap[RF_FS_L2_VPN]:   RF_FS_L2_VPN,
	AddressFamilyNameMap[RF_OPAQUE]:      RF_OPAQUE,
}

func GetRouteFamily(name string) (RouteFamily, error) {
	if v, ok := AddressFamilyValueMap[name]; ok {
		return v, nil
	}
	return RouteFamily(0), fmt.Errorf("%s isn't a valid route family name", name)
}

func NewPrefixFromRouteFamily(afi uint16, safi uint8) (prefix AddrPrefixInterface, err error) {
	switch AfiSafiToRouteFamily(afi, safi) {
	case RF_IPv4_UC, RF_IPv4_MC:
		prefix = NewIPAddrPrefix(0, "")
	case RF_IPv6_UC, RF_IPv6_MC:
		prefix = NewIPv6AddrPrefix(0, "")
	case RF_IPv4_VPN:
		prefix = NewLabeledVPNIPAddrPrefix(0, "", *NewMPLSLabelStack(), nil)
	case RF_IPv6_VPN:
		prefix = NewLabeledVPNIPv6AddrPrefix(0, "", *NewMPLSLabelStack(), nil)
	case RF_IPv4_MPLS:
		prefix = NewLabeledIPAddrPrefix(0, "", *NewMPLSLabelStack())
	case RF_IPv6_MPLS:
		prefix = NewLabeledIPv6AddrPrefix(0, "", *NewMPLSLabelStack())
	case RF_EVPN:
		prefix = NewEVPNNLRI(0, 0, nil)
	case RF_RTC_UC:
		prefix = &RouteTargetMembershipNLRI{}
	case RF_IPv4_ENCAP:
		prefix = NewEncapNLRI("")
	case RF_IPv6_ENCAP:
		prefix = NewEncapv6NLRI("")
	case RF_FS_IPv4_UC:
		prefix = &FlowSpecIPv4Unicast{FlowSpecNLRI{rf: RF_FS_IPv4_UC}}
	case RF_FS_IPv4_VPN:
		prefix = &FlowSpecIPv4VPN{FlowSpecNLRI{rf: RF_FS_IPv4_VPN}}
	case RF_FS_IPv6_UC:
		prefix = &FlowSpecIPv6Unicast{FlowSpecNLRI{rf: RF_FS_IPv6_UC}}
	case RF_FS_IPv6_VPN:
		prefix = &FlowSpecIPv6VPN{FlowSpecNLRI{rf: RF_FS_IPv6_VPN}}
	case RF_FS_L2_VPN:
		prefix = &FlowSpecL2VPN{FlowSpecNLRI{rf: RF_FS_L2_VPN}}
	case RF_OPAQUE:
		prefix = &OpaqueNLRI{}
	default:
		err = fmt.Errorf("unknown route family. AFI: %d, SAFI: %d", afi, safi)
	}
	return prefix, err
}

type BGPAttrFlag uint8

const (
	BGP_ATTR_FLAG_EXTENDED_LENGTH BGPAttrFlag = 1 << 4
	BGP_ATTR_FLAG_PARTIAL         BGPAttrFlag = 1 << 5
	BGP_ATTR_FLAG_TRANSITIVE      BGPAttrFlag = 1 << 6
	BGP_ATTR_FLAG_OPTIONAL        BGPAttrFlag = 1 << 7
)

func (f BGPAttrFlag) String() string {
	strs := make([]string, 0, 4)
	if f&BGP_ATTR_FLAG_EXTENDED_LENGTH > 0 {
		strs = append(strs, "EXTENDED_LENGTH")
	}
	if f&BGP_ATTR_FLAG_PARTIAL > 0 {
		strs = append(strs, "PARTIAL")
	}
	if f&BGP_ATTR_FLAG_TRANSITIVE > 0 {
		strs = append(strs, "TRANSITIVE")
	}
	if f&BGP_ATTR_FLAG_OPTIONAL > 0 {
		strs = append(strs, "OPTIONAL")
	}
	return strings.Join(strs, "|")
}

type BGPAttrType uint8

const (
	_ BGPAttrType = iota
	BGP_ATTR_TYPE_ORIGIN
	BGP_ATTR_TYPE_AS_PATH
	BGP_ATTR_TYPE_NEXT_HOP
	BGP_ATTR_TYPE_MULTI_EXIT_DISC
	BGP_ATTR_TYPE_LOCAL_PREF
	BGP_ATTR_TYPE_ATOMIC_AGGREGATE
	BGP_ATTR_TYPE_AGGREGATOR
	BGP_ATTR_TYPE_COMMUNITIES
	BGP_ATTR_TYPE_ORIGINATOR_ID
	BGP_ATTR_TYPE_CLUSTER_LIST
	_
	_
	_
	BGP_ATTR_TYPE_MP_REACH_NLRI // = 14
	BGP_ATTR_TYPE_MP_UNREACH_NLRI
	BGP_ATTR_TYPE_EXTENDED_COMMUNITIES
	BGP_ATTR_TYPE_AS4_PATH
	BGP_ATTR_TYPE_AS4_AGGREGATOR
	_
	_
	_
	BGP_ATTR_TYPE_PMSI_TUNNEL // = 22
	BGP_ATTR_TYPE_TUNNEL_ENCAP
	_
	BGP_ATTR_TYPE_IP6_EXTENDED_COMMUNITIES             // = 25
	BGP_ATTR_TYPE_AIGP                                 // = 26
	BGP_ATTR_TYPE_LARGE_COMMUNITY          BGPAttrType = 32
)

// NOTIFICATION Error Code  RFC 4271 4.5.
const (
	_ = iota
	BGP_ERROR_MESSAGE_HEADER_ERROR
	BGP_ERROR_OPEN_MESSAGE_ERROR
	BGP_ERROR_UPDATE_MESSAGE_ERROR
	BGP_ERROR_HOLD_TIMER_EXPIRED
	BGP_ERROR_FSM_ERROR
	BGP_ERROR_CEASE
	BGP_ERROR_ROUTE_REFRESH_MESSAGE_ERROR
)

// NOTIFICATION Error Subcode for BGP_ERROR_MESSAGE_HEADER_ERROR
const (
	_ = iota
	BGP_ERROR_SUB_CONNECTION_NOT_SYNCHRONIZED
	BGP_ERROR_SUB_BAD_MESSAGE_LENGTH
	BGP_ERROR_SUB_BAD_MESSAGE_TYPE
)

// NOTIFICATION Error Subcode for BGP_ERROR_OPEN_MESSAGE_ERROR
const (
	_ = iota
	BGP_ERROR_SUB_UNSUPPORTED_VERSION_NUMBER
	BGP_ERROR_SUB_BAD_PEER_AS
	BGP_ERROR_SUB_BAD_BGP_IDENTIFIER
	BGP_ERROR_SUB_UNSUPPORTED_OPTIONAL_PARAMETER
	BGP_ERROR_SUB_DEPRECATED_AUTHENTICATION_FAILURE
	BGP_ERROR_SUB_UNACCEPTABLE_HOLD_TIME
	BGP_ERROR_SUB_UNSUPPORTED_CAPABILITY
)

// NOTIFICATION Error Subcode for BGP_ERROR_UPDATE_MESSAGE_ERROR
const (
	_ = iota
	BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST
	BGP_ERROR_SUB_UNRECOGNIZED_WELL_KNOWN_ATTRIBUTE
	BGP_ERROR_SUB_MISSING_WELL_KNOWN_ATTRIBUTE
	BGP_ERROR_SUB_ATTRIBUTE_FLAGS_ERROR
	BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR
	BGP_ERROR_SUB_INVALID_ORIGIN_ATTRIBUTE
	BGP_ERROR_SUB_DEPRECATED_ROUTING_LOOP
	BGP_ERROR_SUB_INVALID_NEXT_HOP_ATTRIBUTE
	BGP_ERROR_SUB_OPTIONAL_ATTRIBUTE_ERROR
	BGP_ERROR_SUB_INVALID_NETWORK_FIELD
	BGP_ERROR_SUB_MALFORMED_AS_PATH
)

// NOTIFICATION Error Subcode for BGP_ERROR_HOLD_TIMER_EXPIRED
const (
	_ = iota
	BGP_ERROR_SUB_HOLD_TIMER_EXPIRED
)

// NOTIFICATION Error Subcode for BGP_ERROR_FSM_ERROR
const (
	_ = iota
	BGP_ERROR_SUB_RECEIVE_UNEXPECTED_MESSAGE_IN_OPENSENT_STATE
	BGP_ERROR_SUB_RECEIVE_UNEXPECTED_MESSAGE_IN_OPENCONFIRM_STATE
	BGP_ERROR_SUB_RECEIVE_UNEXPECTED_MESSAGE_IN_ESTABLISHED_STATE
)

// NOTIFICATION Error Subcode for BGP_ERROR_CEASE  (RFC 4486)
const (
	_ = iota
	BGP_ERROR_SUB_MAXIMUM_NUMBER_OF_PREFIXES_REACHED
	BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN
	BGP_ERROR_SUB_PEER_DECONFIGURED
	BGP_ERROR_SUB_ADMINISTRATIVE_RESET
	BGP_ERROR_SUB_CONNECTION_REJECTED
	BGP_ERROR_SUB_OTHER_CONFIGURATION_CHANGE
	BGP_ERROR_SUB_CONNECTION_COLLISION_RESOLUTION
	BGP_ERROR_SUB_OUT_OF_RESOURCES
	BGP_ERROR_SUB_HARD_RESET //draft-ietf-idr-bgp-gr-notification-07
)

// Constants for BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN and BGP_ERROR_SUB_ADMINISTRATIVE_RESET
const (
	BGP_ERROR_ADMINISTRATIVE_COMMUNICATION_MAX = 128
)

// NOTIFICATION Error Subcode for BGP_ERROR_ROUTE_REFRESH
const (
	_ = iota
	BGP_ERROR_SUB_INVALID_MESSAGE_LENGTH
)

type NotificationErrorCode uint16

func (c NotificationErrorCode) String() string {
	code := uint8(uint16(c) >> 8)
	subcode := uint8(uint16(c) & 0xff)
	UNDEFINED := "undefined"
	codeStr := UNDEFINED
	subcodeList := []string{}
	switch code {
	case BGP_ERROR_MESSAGE_HEADER_ERROR:
		codeStr = "header"
		subcodeList = []string{
			UNDEFINED,
			"connection not synchronized",
			"bad message length",
			"bad message type"}
	case BGP_ERROR_OPEN_MESSAGE_ERROR:
		codeStr = "open"
		subcodeList = []string{
			UNDEFINED,
			"unsupported version number",
			"bad peer as",
			"bad bgp identifier",
			"unsupported optional parameter",
			"deprecated authentication failure",
			"unacceptable hold time",
			"unsupported capability"}
	case BGP_ERROR_UPDATE_MESSAGE_ERROR:
		codeStr = "update"
		subcodeList = []string{
			UNDEFINED,
			"malformed attribute list",
			"unrecognized well known attribute",
			"missing well known attribute",
			"attribute flags error",
			"attribute length error",
			"invalid origin attribute",
			"deprecated routing loop",
			"invalid next hop attribute",
			"optional attribute error",
			"invalid network field",
			"sub malformed as path"}
	case BGP_ERROR_HOLD_TIMER_EXPIRED:
		codeStr = "hold timer expired"
		subcodeList = []string{
			UNDEFINED,
			"hold timer expired"}
	case BGP_ERROR_FSM_ERROR:
		codeStr = "fsm"
		subcodeList = []string{
			UNDEFINED,
			"receive unexpected message in opensent state",
			"receive unexpected message in openconfirm state",
			"receive unexpected message in established state"}
	case BGP_ERROR_CEASE:
		codeStr = "cease"
		subcodeList = []string{
			UNDEFINED,
			"maximum number of prefixes reached",
			"administrative shutdown",
			"peer deconfigured",
			"administrative reset",
			"connection rejected",
			"other configuration change",
			"connection collision resolution",
			"out of resources"}
	case BGP_ERROR_ROUTE_REFRESH_MESSAGE_ERROR:
		codeStr = "route refresh"
		subcodeList = []string{"invalid message length"}
	}
	subcodeStr := func(idx uint8, l []string) string {
		if len(l) == 0 || int(idx) > len(l)-1 {
			return UNDEFINED
		}
		return l[idx]
	}(subcode, subcodeList)
	return fmt.Sprintf("code %v(%v) subcode %v(%v)", code, codeStr, subcode, subcodeStr)
}

func NewNotificationErrorCode(code, subcode uint8) NotificationErrorCode {
	return NotificationErrorCode(uint16(code)<<8 | uint16(subcode))
}

var PathAttrFlags map[BGPAttrType]BGPAttrFlag = map[BGPAttrType]BGPAttrFlag{
	BGP_ATTR_TYPE_ORIGIN:                   BGP_ATTR_FLAG_TRANSITIVE,
	BGP_ATTR_TYPE_AS_PATH:                  BGP_ATTR_FLAG_TRANSITIVE,
	BGP_ATTR_TYPE_NEXT_HOP:                 BGP_ATTR_FLAG_TRANSITIVE,
	BGP_ATTR_TYPE_MULTI_EXIT_DISC:          BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_LOCAL_PREF:               BGP_ATTR_FLAG_TRANSITIVE,
	BGP_ATTR_TYPE_ATOMIC_AGGREGATE:         BGP_ATTR_FLAG_TRANSITIVE,
	BGP_ATTR_TYPE_AGGREGATOR:               BGP_ATTR_FLAG_TRANSITIVE | BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_COMMUNITIES:              BGP_ATTR_FLAG_TRANSITIVE | BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_ORIGINATOR_ID:            BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_CLUSTER_LIST:             BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_MP_REACH_NLRI:            BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_MP_UNREACH_NLRI:          BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_EXTENDED_COMMUNITIES:     BGP_ATTR_FLAG_TRANSITIVE | BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_AS4_PATH:                 BGP_ATTR_FLAG_TRANSITIVE | BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_AS4_AGGREGATOR:           BGP_ATTR_FLAG_TRANSITIVE | BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_PMSI_TUNNEL:              BGP_ATTR_FLAG_TRANSITIVE | BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_TUNNEL_ENCAP:             BGP_ATTR_FLAG_TRANSITIVE | BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_IP6_EXTENDED_COMMUNITIES: BGP_ATTR_FLAG_TRANSITIVE | BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_AIGP:                     BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_LARGE_COMMUNITY:          BGP_ATTR_FLAG_TRANSITIVE | BGP_ATTR_FLAG_OPTIONAL,
}

type PathAttributeInterface interface {
	DecodeFromBytes([]byte) error
	Serialize() ([]byte, error)
	Len() int
	GetFlags() BGPAttrFlag
	GetType() BGPAttrType
	String() string
	MarshalJSON() ([]byte, error)
	Flat() map[string]string
}

type PathAttribute struct {
	Flags  BGPAttrFlag
	Type   BGPAttrType
	Length uint16
	Value  []byte
}

func (p *PathAttribute) Len() int {
	if p.Length == 0 {
		p.Length = uint16(len(p.Value))
	}
	l := 2 + p.Length
	if p.Flags&BGP_ATTR_FLAG_EXTENDED_LENGTH != 0 {
		l += 2
	} else {
		l += 1
	}
	return int(l)
}

func (p *PathAttribute) GetFlags() BGPAttrFlag {
	return p.Flags
}

func (p *PathAttribute) GetType() BGPAttrType {
	return p.Type
}

func (p *PathAttribute) DecodeFromBytes(data []byte) error {
	odata := data
	eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
	eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)
	if len(data) < 2 {
		return NewMessageError(eCode, eSubCode, data, "attribute header length is short")
	}
	p.Flags = BGPAttrFlag(data[0])
	p.Type = BGPAttrType(data[1])

	if p.Flags&BGP_ATTR_FLAG_EXTENDED_LENGTH != 0 {
		if len(data) < 4 {
			return NewMessageError(eCode, eSubCode, data, "attribute header length is short")
		}
		p.Length = binary.BigEndian.Uint16(data[2:4])
		data = data[4:]
	} else {
		if len(data) < 3 {
			return NewMessageError(eCode, eSubCode, data, "attribute header length is short")
		}
		p.Length = uint16(data[2])
		data = data[3:]
	}
	if len(data) < int(p.Length) {
		return NewMessageError(eCode, eSubCode, data, "attribute value length is short")
	}
	if len(data[:p.Length]) > 0 {
		p.Value = data[:p.Length]
	}

	ok, eMsg := ValidateFlags(p.Type, p.Flags)
	if !ok {
		return NewMessageError(eCode, BGP_ERROR_SUB_ATTRIBUTE_FLAGS_ERROR, odata[:p.Len()], eMsg)
	}
	return nil
}

func (p *PathAttribute) Serialize() ([]byte, error) {
	p.Length = uint16(len(p.Value))
	if p.Length > 255 {
		p.Flags |= BGP_ATTR_FLAG_EXTENDED_LENGTH
	} else {
		p.Flags &^= BGP_ATTR_FLAG_EXTENDED_LENGTH
	}
	buf := make([]byte, p.Len())
	buf[0] = uint8(p.Flags)
	buf[1] = uint8(p.Type)
	if p.Flags&BGP_ATTR_FLAG_EXTENDED_LENGTH != 0 {
		binary.BigEndian.PutUint16(buf[2:4], p.Length)
		copy(buf[4:], p.Value)
	} else {
		buf[2] = byte(p.Length)
		copy(buf[3:], p.Value)
	}
	return buf, nil
}

func (p *PathAttribute) String() string {
	return fmt.Sprintf("%s %s %s", p.Type.String(), p.Flags, []byte(p.Value))
}

func (p *PathAttribute) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPAttrType `json:"type"`
		Value []byte      `json:"value"`
	}{
		Type:  p.GetType(),
		Value: p.Value,
	})
}

type PathAttributeOrigin struct {
	PathAttribute
}

func (p *PathAttributeOrigin) String() string {
	typ := "-"
	switch p.Value[0] {
	case BGP_ORIGIN_ATTR_TYPE_IGP:
		typ = "i"
	case BGP_ORIGIN_ATTR_TYPE_EGP:
		typ = "e"
	case BGP_ORIGIN_ATTR_TYPE_INCOMPLETE:
		typ = "?"
	}
	return fmt.Sprintf("{Origin: %s}", typ)
}

func (p *PathAttributeOrigin) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPAttrType `json:"type"`
		Value uint8       `json:"value"`
	}{
		Type:  p.GetType(),
		Value: p.Value[0],
	})
}

func NewPathAttributeOrigin(value uint8) *PathAttributeOrigin {
	t := BGP_ATTR_TYPE_ORIGIN
	return &PathAttributeOrigin{

		PathAttribute: PathAttribute{
			Flags: PathAttrFlags[t],
			Type:  t,
			Value: []byte{byte(value)},
		},
	}
}

type AsPathParamFormat struct {
	start     string
	end       string
	separator string
}

var asPathParamFormatMap = map[uint8]*AsPathParamFormat{
	BGP_ASPATH_ATTR_TYPE_SET:        {"{", "}", ","},
	BGP_ASPATH_ATTR_TYPE_SEQ:        {"", "", " "},
	BGP_ASPATH_ATTR_TYPE_CONFED_SET: {"(", ")", " "},
	BGP_ASPATH_ATTR_TYPE_CONFED_SEQ: {"[", "]", ","},
}

type AsPathParamInterface interface {
	Serialize() ([]byte, error)
	DecodeFromBytes([]byte) error
	Len() int
	ASLen() int
	MarshalJSON() ([]byte, error)
	String() string
}

type AsPathParam struct {
	Type uint8
	Num  uint8
	AS   []uint16
}

func (a *AsPathParam) Serialize() ([]byte, error) {
	buf := make([]byte, 2+len(a.AS)*2)
	buf[0] = uint8(a.Type)
	buf[1] = a.Num
	for j, as := range a.AS {
		binary.BigEndian.PutUint16(buf[2+j*2:], as)
	}
	return buf, nil
}

func (a *AsPathParam) DecodeFromBytes(data []byte) error {
	eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
	eSubCode := uint8(BGP_ERROR_SUB_MALFORMED_AS_PATH)
	if len(data) < 2 {
		return NewMessageError(eCode, eSubCode, nil, "AS param header length is short")
	}
	a.Type = data[0]
	a.Num = data[1]
	data = data[2:]
	if len(data) < int(a.Num*2) {
		return NewMessageError(eCode, eSubCode, nil, "AS param data length is short")
	}
	for i := 0; i < int(a.Num); i++ {
		a.AS = append(a.AS, binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	return nil
}

func (a *AsPathParam) Len() int {
	return 2 + len(a.AS)*2
}

func (a *AsPathParam) ASLen() int {
	switch a.Type {
	case BGP_ASPATH_ATTR_TYPE_SEQ:
		return len(a.AS)
	case BGP_ASPATH_ATTR_TYPE_SET:
		return 1
	case BGP_ASPATH_ATTR_TYPE_CONFED_SET, BGP_ASPATH_ATTR_TYPE_CONFED_SEQ:
		return 0
	}
	return 0
}

func (a *AsPathParam) String() string {
	format, ok := asPathParamFormatMap[a.Type]
	if !ok {
		return fmt.Sprintf("%v", a.AS)
	}
	aspath := make([]string, 0, len(a.AS))
	for _, asn := range a.AS {
		aspath = append(aspath, fmt.Sprintf("%d", asn))
	}
	s := bytes.NewBuffer(make([]byte, 0, 32))
	s.WriteString(format.start)
	s.WriteString(strings.Join(aspath, format.separator))
	s.WriteString(format.end)
	return s.String()
}

func (a *AsPathParam) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type uint8    `json:"segment_type"`
		Num  uint8    `json:"num"`
		AS   []uint16 `json:"asns"`
	}{
		Type: a.Type,
		Num:  a.Num,
		AS:   a.AS,
	})
}

func NewAsPathParam(segType uint8, as []uint16) *AsPathParam {
	return &AsPathParam{
		Type: segType,
		Num:  uint8(len(as)),
		AS:   as,
	}
}

type As4PathParam struct {
	Type uint8
	Num  uint8
	AS   []uint32
}

func (a *As4PathParam) Serialize() ([]byte, error) {
	buf := make([]byte, 2+len(a.AS)*4)
	buf[0] = a.Type
	buf[1] = a.Num
	for j, as := range a.AS {
		binary.BigEndian.PutUint32(buf[2+j*4:], as)
	}
	return buf, nil
}

func (a *As4PathParam) DecodeFromBytes(data []byte) error {
	eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
	eSubCode := uint8(BGP_ERROR_SUB_MALFORMED_AS_PATH)
	if len(data) < 2 {
		return NewMessageError(eCode, eSubCode, nil, "AS4 param header length is short")
	}
	a.Type = data[0]
	a.Num = data[1]
	data = data[2:]
	if len(data) < int(a.Num)*4 {
		return NewMessageError(eCode, eSubCode, nil, "AS4 param data length is short")
	}
	for i := 0; i < int(a.Num); i++ {
		a.AS = append(a.AS, binary.BigEndian.Uint32(data))
		data = data[4:]
	}
	return nil
}

func (a *As4PathParam) Len() int {
	return 2 + len(a.AS)*4
}

func (a *As4PathParam) ASLen() int {
	switch a.Type {
	case BGP_ASPATH_ATTR_TYPE_SEQ:
		return len(a.AS)
	case BGP_ASPATH_ATTR_TYPE_SET:
		return 1
	case BGP_ASPATH_ATTR_TYPE_CONFED_SET, BGP_ASPATH_ATTR_TYPE_CONFED_SEQ:
		return 0
	}
	return 0
}

func (a *As4PathParam) String() string {
	format, ok := asPathParamFormatMap[a.Type]
	if !ok {
		return fmt.Sprintf("%v", a.AS)
	}
	aspath := make([]string, 0, len(a.AS))
	for _, asn := range a.AS {
		aspath = append(aspath, fmt.Sprintf("%d", asn))
	}
	s := bytes.NewBuffer(make([]byte, 0, 32))
	s.WriteString(format.start)
	s.WriteString(strings.Join(aspath, format.separator))
	s.WriteString(format.end)
	return s.String()
}

func (a *As4PathParam) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type uint8    `json:"segment_type"`
		Num  uint8    `json:"num"`
		AS   []uint32 `json:"asns"`
	}{
		Type: a.Type,
		Num:  a.Num,
		AS:   a.AS,
	})
}

func NewAs4PathParam(segType uint8, as []uint32) *As4PathParam {
	return &As4PathParam{
		Type: segType,
		Num:  uint8(len(as)),
		AS:   as,
	}
}

type DefaultAsPath struct {
}

func (p *DefaultAsPath) isValidAspath(data []byte) (bool, error) {
	eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
	eSubCode := uint8(BGP_ERROR_SUB_MALFORMED_AS_PATH)
	if len(data)%2 != 0 {
		return false, NewMessageError(eCode, eSubCode, nil, "AS PATH length is not odd")
	}

	tryParse := func(data []byte, use4byte bool) (bool, error) {
		for len(data) > 0 {
			if len(data) < 2 {
				return false, NewMessageError(eCode, eSubCode, nil, "AS PATH header is short")
			}
			segType := data[0]
			if segType == 0 || segType > 4 {
				return false, NewMessageError(eCode, eSubCode, nil, "unknown AS_PATH seg type")
			}
			asNum := data[1]
			data = data[2:]
			if asNum == 0 || int(asNum) > math.MaxUint8 {
				return false, NewMessageError(eCode, eSubCode, nil, "AS PATH the number of AS is incorrect")
			}
			segLength := int(asNum)
			if use4byte == true {
				segLength *= 4
			} else {
				segLength *= 2
			}
			if int(segLength) > len(data) {
				return false, NewMessageError(eCode, eSubCode, nil, "seg length is short")
			}
			data = data[segLength:]
		}
		return true, nil
	}
	_, err := tryParse(data, true)
	if err == nil {
		return true, nil
	}

	_, err = tryParse(data, false)
	if err == nil {
		return false, nil
	}
	return false, NewMessageError(eCode, eSubCode, nil, "can't parse AS_PATH")
}

type PathAttributeAsPath struct {
	DefaultAsPath
	PathAttribute
	Value []AsPathParamInterface
}

func (p *PathAttributeAsPath) DecodeFromBytes(data []byte) error {
	err := p.PathAttribute.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	if p.PathAttribute.Length == 0 {
		// ibgp or something
		return nil
	}
	as4Bytes, err := p.DefaultAsPath.isValidAspath(p.PathAttribute.Value)
	if err != nil {
		err.(*MessageError).Data = data[:p.Len()]
		return err
	}
	v := p.PathAttribute.Value
	for len(v) > 0 {
		var tuple AsPathParamInterface
		if as4Bytes == true {
			tuple = &As4PathParam{}
		} else {
			tuple = &AsPathParam{}
		}
		err := tuple.DecodeFromBytes(v)
		if err != nil {
			return err
		}
		p.Value = append(p.Value, tuple)
		if tuple.Len() > len(v) {

		}
		v = v[tuple.Len():]
	}
	return nil
}

func (p *PathAttributeAsPath) Serialize() ([]byte, error) {
	buf := make([]byte, 0)
	for _, v := range p.Value {
		vbuf, err := v.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, vbuf...)
	}
	p.PathAttribute.Value = buf
	return p.PathAttribute.Serialize()
}

func (p *PathAttributeAsPath) String() string {
	params := make([]string, 0, len(p.Value))
	for _, param := range p.Value {
		params = append(params, param.String())
	}
	return strings.Join(params, " ")
}

func (p *PathAttributeAsPath) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPAttrType            `json:"type"`
		Value []AsPathParamInterface `json:"as_paths"`
	}{
		Type:  p.GetType(),
		Value: p.Value,
	})
}

func NewPathAttributeAsPath(value []AsPathParamInterface) *PathAttributeAsPath {
	t := BGP_ATTR_TYPE_AS_PATH
	return &PathAttributeAsPath{
		PathAttribute: PathAttribute{
			Flags: PathAttrFlags[t],
			Type:  t,
		},
		Value: value,
	}
}

type PathAttributeNextHop struct {
	PathAttribute
	Value net.IP
}

func (p *PathAttributeNextHop) DecodeFromBytes(data []byte) error {
	err := p.PathAttribute.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	if len(p.PathAttribute.Value) != 4 && len(p.PathAttribute.Value) != 16 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)
		return NewMessageError(eCode, eSubCode, nil, "nexthop length isn't correct")
	}
	p.Value = p.PathAttribute.Value
	return nil
}

func (p *PathAttributeNextHop) Serialize() ([]byte, error) {
	p.PathAttribute.Value = p.Value
	return p.PathAttribute.Serialize()
}

func (p *PathAttributeNextHop) String() string {
	return fmt.Sprintf("{Nexthop: %s}", p.Value)
}

func (p *PathAttributeNextHop) MarshalJSON() ([]byte, error) {
	value := "0.0.0.0"
	if p.Value != nil {
		value = p.Value.String()
	}
	return json.Marshal(struct {
		Type  BGPAttrType `json:"type"`
		Value string      `json:"nexthop"`
	}{
		Type:  p.GetType(),
		Value: value,
	})
}

func NewPathAttributeNextHop(value string) *PathAttributeNextHop {
	t := BGP_ATTR_TYPE_NEXT_HOP
	return &PathAttributeNextHop{
		PathAttribute: PathAttribute{
			Flags: PathAttrFlags[t],
			Type:  t,
		},
		Value: net.ParseIP(value).To4(),
	}
}

type PathAttributeMultiExitDisc struct {
	PathAttribute
	Value uint32
}

func (p *PathAttributeMultiExitDisc) DecodeFromBytes(data []byte) error {
	err := p.PathAttribute.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	if len(p.PathAttribute.Value) != 4 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)
		return NewMessageError(eCode, eSubCode, nil, "med length isn't correct")
	}
	p.Value = binary.BigEndian.Uint32(p.PathAttribute.Value)
	return nil
}

func (p *PathAttributeMultiExitDisc) Serialize() ([]byte, error) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, p.Value)
	p.PathAttribute.Value = buf
	return p.PathAttribute.Serialize()
}

func (p *PathAttributeMultiExitDisc) String() string {
	return fmt.Sprintf("{Med: %d}", p.Value)
}

func (p *PathAttributeMultiExitDisc) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPAttrType `json:"type"`
		Value uint32      `json:"metric"`
	}{
		Type:  p.GetType(),
		Value: p.Value,
	})
}

func NewPathAttributeMultiExitDisc(value uint32) *PathAttributeMultiExitDisc {
	t := BGP_ATTR_TYPE_MULTI_EXIT_DISC
	return &PathAttributeMultiExitDisc{
		PathAttribute: PathAttribute{
			Flags: PathAttrFlags[t],
			Type:  t,
		},
		Value: value,
	}
}

type PathAttributeLocalPref struct {
	PathAttribute
	Value uint32
}

func (p *PathAttributeLocalPref) DecodeFromBytes(data []byte) error {
	err := p.PathAttribute.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	if len(p.PathAttribute.Value) != 4 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)
		return NewMessageError(eCode, eSubCode, nil, "local pref length isn't correct")
	}
	p.Value = binary.BigEndian.Uint32(p.PathAttribute.Value)
	return nil
}

func (p *PathAttributeLocalPref) Serialize() ([]byte, error) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, p.Value)
	p.PathAttribute.Value = buf
	return p.PathAttribute.Serialize()
}

func (p *PathAttributeLocalPref) String() string {
	return fmt.Sprintf("{LocalPref: %d}", p.Value)
}

func (p *PathAttributeLocalPref) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPAttrType `json:"type"`
		Value uint32      `json:"value"`
	}{
		Type:  p.GetType(),
		Value: p.Value,
	})
}

func NewPathAttributeLocalPref(value uint32) *PathAttributeLocalPref {
	t := BGP_ATTR_TYPE_LOCAL_PREF
	return &PathAttributeLocalPref{
		PathAttribute: PathAttribute{
			Flags: PathAttrFlags[t],
			Type:  t,
		},
		Value: value,
	}
}

type PathAttributeAtomicAggregate struct {
	PathAttribute
}

func (p *PathAttributeAtomicAggregate) String() string {
	return "{AtomicAggregate}"
}

func (p *PathAttributeAtomicAggregate) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type BGPAttrType `json:"type"`
	}{
		Type: p.GetType(),
	})
}

func NewPathAttributeAtomicAggregate() *PathAttributeAtomicAggregate {
	t := BGP_ATTR_TYPE_ATOMIC_AGGREGATE
	return &PathAttributeAtomicAggregate{
		PathAttribute: PathAttribute{
			Flags: PathAttrFlags[t],
			Type:  t,
		},
	}
}

type PathAttributeAggregatorParam struct {
	AS      uint32
	Askind  reflect.Kind
	Address net.IP
}

type PathAttributeAggregator struct {
	PathAttribute
	Value PathAttributeAggregatorParam
}

func (p *PathAttributeAggregator) DecodeFromBytes(data []byte) error {
	err := p.PathAttribute.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	if len(p.PathAttribute.Value) != 6 && len(p.PathAttribute.Value) != 8 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)
		return NewMessageError(eCode, eSubCode, nil, "aggregator length isn't correct")
	}
	if len(p.PathAttribute.Value) == 6 {
		p.Value.AS = uint32(binary.BigEndian.Uint16(p.PathAttribute.Value[0:2]))
		p.Value.Address = p.PathAttribute.Value[2:]
		p.Value.Askind = reflect.Uint16
	} else {
		p.Value.AS = binary.BigEndian.Uint32(p.PathAttribute.Value[0:4])
		p.Value.Address = p.PathAttribute.Value[4:]
		p.Value.Askind = reflect.Uint32
	}
	return nil
}

func (p *PathAttributeAggregator) Serialize() ([]byte, error) {
	var buf []byte
	switch p.Value.Askind {
	case reflect.Uint16:
		buf = make([]byte, 6)
		binary.BigEndian.PutUint16(buf, uint16(p.Value.AS))
		copy(buf[2:], p.Value.Address)
	case reflect.Uint32:
		buf = make([]byte, 8)
		binary.BigEndian.PutUint32(buf, p.Value.AS)
		copy(buf[4:], p.Value.Address)
	}

	p.PathAttribute.Value = buf
	return p.PathAttribute.Serialize()
}

func (p *PathAttributeAggregator) String() string {
	return fmt.Sprintf("{Aggregate: {AS: %d, Address: %s}}", p.Value.AS, p.Value.Address)
}

func (p *PathAttributeAggregator) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type    BGPAttrType `json:"type"`
		AS      uint32      `json:"as"`
		Address string      `json:"address"`
	}{
		Type:    p.GetType(),
		AS:      p.Value.AS,
		Address: p.Value.Address.String(),
	})
}

func NewPathAttributeAggregator(as interface{}, address string) *PathAttributeAggregator {
	v := reflect.ValueOf(as)
	t := BGP_ATTR_TYPE_AGGREGATOR
	return &PathAttributeAggregator{
		PathAttribute: PathAttribute{
			Flags: PathAttrFlags[t],
			Type:  t,
		},
		Value: PathAttributeAggregatorParam{
			AS:      uint32(v.Uint()),
			Askind:  v.Kind(),
			Address: net.ParseIP(address).To4(),
		},
	}
}

type PathAttributeCommunities struct {
	PathAttribute
	Value []uint32
}

func (p *PathAttributeCommunities) DecodeFromBytes(data []byte) error {
	err := p.PathAttribute.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	if len(p.PathAttribute.Value)%4 != 0 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)
		return NewMessageError(eCode, eSubCode, nil, "communities length isn't correct")
	}
	value := p.PathAttribute.Value
	for len(value) >= 4 {
		p.Value = append(p.Value, binary.BigEndian.Uint32(value))
		value = value[4:]
	}
	return nil
}

func (p *PathAttributeCommunities) Serialize() ([]byte, error) {
	buf := make([]byte, len(p.Value)*4)
	for i, v := range p.Value {
		binary.BigEndian.PutUint32(buf[i*4:], v)
	}
	p.PathAttribute.Value = buf
	return p.PathAttribute.Serialize()
}

type WellKnownCommunity uint32

const (
	COMMUNITY_INTERNET                   WellKnownCommunity = 0x00000000
	COMMUNITY_PLANNED_SHUT                                  = 0xffff0000
	COMMUNITY_ACCEPT_OWN                                    = 0xffff0001
	COMMUNITY_ROUTE_FILTER_TRANSLATED_v4                    = 0xffff0002
	COMMUNITY_ROUTE_FILTER_v4                               = 0xffff0003
	COMMUNITY_ROUTE_FILTER_TRANSLATED_v6                    = 0xffff0004
	COMMUNITY_ROUTE_FILTER_v6                               = 0xffff0005
	COMMUNITY_LLGR_STALE                                    = 0xffff0006
	COMMUNITY_NO_LLGR                                       = 0xffff0007
	COMMUNITY_BLACKHOLE                                     = 0xffff029a
	COMMUNITY_NO_EXPORT                                     = 0xffffff01
	COMMUNITY_NO_ADVERTISE                                  = 0xffffff02
	COMMUNITY_NO_EXPORT_SUBCONFED                           = 0xffffff03
	COMMUNITY_NO_PEER                                       = 0xffffff04
)

var WellKnownCommunityNameMap = map[WellKnownCommunity]string{
	COMMUNITY_INTERNET:                   "internet",
	COMMUNITY_PLANNED_SHUT:               "planned-shut",
	COMMUNITY_ACCEPT_OWN:                 "accept-own",
	COMMUNITY_ROUTE_FILTER_TRANSLATED_v4: "route-filter-translated-v4",
	COMMUNITY_ROUTE_FILTER_v4:            "route-filter-v4",
	COMMUNITY_ROUTE_FILTER_TRANSLATED_v6: "route-filter-translated-v6",
	COMMUNITY_ROUTE_FILTER_v6:            "route-filter-v6",
	COMMUNITY_LLGR_STALE:                 "llgr-stale",
	COMMUNITY_NO_LLGR:                    "no-llgr",
	COMMUNITY_BLACKHOLE:                  "blackhole",
	COMMUNITY_NO_EXPORT:                  "no-export",
	COMMUNITY_NO_ADVERTISE:               "no-advertise",
	COMMUNITY_NO_EXPORT_SUBCONFED:        "no-export-subconfed",
	COMMUNITY_NO_PEER:                    "no-peer",
}

var WellKnownCommunityValueMap = map[string]WellKnownCommunity{
	WellKnownCommunityNameMap[COMMUNITY_INTERNET]:                   COMMUNITY_INTERNET,
	WellKnownCommunityNameMap[COMMUNITY_PLANNED_SHUT]:               COMMUNITY_PLANNED_SHUT,
	WellKnownCommunityNameMap[COMMUNITY_ACCEPT_OWN]:                 COMMUNITY_ACCEPT_OWN,
	WellKnownCommunityNameMap[COMMUNITY_ROUTE_FILTER_TRANSLATED_v4]: COMMUNITY_ROUTE_FILTER_TRANSLATED_v4,
	WellKnownCommunityNameMap[COMMUNITY_ROUTE_FILTER_v4]:            COMMUNITY_ROUTE_FILTER_v4,
	WellKnownCommunityNameMap[COMMUNITY_ROUTE_FILTER_TRANSLATED_v6]: COMMUNITY_ROUTE_FILTER_TRANSLATED_v6,
	WellKnownCommunityNameMap[COMMUNITY_ROUTE_FILTER_v6]:            COMMUNITY_ROUTE_FILTER_v6,
	WellKnownCommunityNameMap[COMMUNITY_LLGR_STALE]:                 COMMUNITY_LLGR_STALE,
	WellKnownCommunityNameMap[COMMUNITY_NO_LLGR]:                    COMMUNITY_NO_LLGR,
	WellKnownCommunityNameMap[COMMUNITY_NO_EXPORT]:                  COMMUNITY_NO_EXPORT,
	WellKnownCommunityNameMap[COMMUNITY_BLACKHOLE]:                  COMMUNITY_BLACKHOLE,
	WellKnownCommunityNameMap[COMMUNITY_NO_ADVERTISE]:               COMMUNITY_NO_ADVERTISE,
	WellKnownCommunityNameMap[COMMUNITY_NO_EXPORT_SUBCONFED]:        COMMUNITY_NO_EXPORT_SUBCONFED,
	WellKnownCommunityNameMap[COMMUNITY_NO_PEER]:                    COMMUNITY_NO_PEER,
}

func (p *PathAttributeCommunities) String() string {
	l := []string{}
	for _, v := range p.Value {
		n, ok := WellKnownCommunityNameMap[WellKnownCommunity(v)]
		if ok {
			l = append(l, n)
		} else {
			l = append(l, fmt.Sprintf("%d:%d", (0xffff0000&v)>>16, 0xffff&v))
		}
	}
	return fmt.Sprintf("{Communities: %s}", strings.Join(l, ", "))
}

func (p *PathAttributeCommunities) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPAttrType `json:"type"`
		Value []uint32    `json:"communities"`
	}{
		Type:  p.GetType(),
		Value: p.Value,
	})
}

func NewPathAttributeCommunities(value []uint32) *PathAttributeCommunities {
	t := BGP_ATTR_TYPE_COMMUNITIES
	return &PathAttributeCommunities{
		PathAttribute{
			Flags:  PathAttrFlags[t],
			Type:   t,
			Length: 0,
			Value:  nil},
		value,
	}
}

type PathAttributeOriginatorId struct {
	PathAttribute
	Value net.IP
}

func (p *PathAttributeOriginatorId) DecodeFromBytes(data []byte) error {
	err := p.PathAttribute.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	if len(p.PathAttribute.Value) != 4 && len(p.PathAttribute.Value) != 16 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)
		return NewMessageError(eCode, eSubCode, nil, "originatorid length isn't correct")
	}
	p.Value = p.PathAttribute.Value
	return nil
}

func (p *PathAttributeOriginatorId) String() string {
	return fmt.Sprintf("{Originator: %s}", p.Value)
}

func (p *PathAttributeOriginatorId) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPAttrType `json:"type"`
		Value string      `json:"value"`
	}{
		Type:  p.GetType(),
		Value: p.Value.String(),
	})
}

func (p *PathAttributeOriginatorId) Serialize() ([]byte, error) {
	buf := make([]byte, 4)
	copy(buf, p.Value)
	p.PathAttribute.Value = buf
	return p.PathAttribute.Serialize()
}

func NewPathAttributeOriginatorId(value string) *PathAttributeOriginatorId {
	t := BGP_ATTR_TYPE_ORIGINATOR_ID
	return &PathAttributeOriginatorId{
		PathAttribute{
			Flags:  PathAttrFlags[t],
			Type:   t,
			Length: 0,
			Value:  nil},
		net.ParseIP(value).To4(),
	}
}

type PathAttributeClusterList struct {
	PathAttribute
	Value []net.IP
}

func (p *PathAttributeClusterList) DecodeFromBytes(data []byte) error {
	err := p.PathAttribute.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	value := p.PathAttribute.Value
	if len(p.PathAttribute.Value)%4 != 0 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)
		return NewMessageError(eCode, eSubCode, nil, "clusterlist length isn't correct")
	}
	for len(value) >= 4 {
		p.Value = append(p.Value, value[:4])
		value = value[4:]
	}
	return nil
}

func (p *PathAttributeClusterList) Serialize() ([]byte, error) {
	buf := make([]byte, len(p.Value)*4)
	for i, v := range p.Value {
		copy(buf[i*4:], v)
	}
	p.PathAttribute.Value = buf
	return p.PathAttribute.Serialize()
}

func (p *PathAttributeClusterList) String() string {
	return fmt.Sprintf("{ClusterList: %v}", p.Value)
}

func (p *PathAttributeClusterList) MarshalJSON() ([]byte, error) {
	value := make([]string, 0, len(p.Value))
	for _, v := range p.Value {
		value = append(value, v.String())
	}
	return json.Marshal(struct {
		Type  BGPAttrType `json:"type"`
		Value []string    `json:"value"`
	}{
		Type:  p.GetType(),
		Value: value,
	})
}

func NewPathAttributeClusterList(value []string) *PathAttributeClusterList {
	l := make([]net.IP, len(value))
	for i, v := range value {
		l[i] = net.ParseIP(v).To4()
	}
	t := BGP_ATTR_TYPE_CLUSTER_LIST
	return &PathAttributeClusterList{
		PathAttribute{
			Flags:  PathAttrFlags[t],
			Type:   t,
			Length: 0,
			Value:  nil},
		l,
	}
}

type PathAttributeMpReachNLRI struct {
	PathAttribute
	Nexthop          net.IP
	LinkLocalNexthop net.IP
	AFI              uint16
	SAFI             uint8
	Value            []AddrPrefixInterface
}

func (p *PathAttributeMpReachNLRI) DecodeFromBytes(data []byte) error {
	err := p.PathAttribute.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
	eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)
	value := p.PathAttribute.Value
	if len(value) < 3 {
		return NewMessageError(eCode, eSubCode, value, "mpreach header length is short")
	}
	afi := binary.BigEndian.Uint16(value[0:2])
	safi := value[2]
	p.AFI = afi
	p.SAFI = safi
	_, err = NewPrefixFromRouteFamily(afi, safi)
	if err != nil {
		return NewMessageError(eCode, BGP_ERROR_SUB_ATTRIBUTE_FLAGS_ERROR, data[:p.PathAttribute.Len()], err.Error())
	}
	nexthoplen := int(value[3])
	if len(value) < 4+nexthoplen {
		return NewMessageError(eCode, eSubCode, value, "mpreach nexthop length is short")
	}
	nexthopbin := value[4 : 4+nexthoplen]
	if nexthoplen > 0 {
		v4addrlen := 4
		v6addrlen := 16
		offset := 0
		if safi == SAFI_MPLS_VPN {
			offset = 8
		}
		switch nexthoplen {
		case 2 * (offset + v6addrlen):
			p.LinkLocalNexthop = nexthopbin[offset+v6addrlen+offset : 2*(offset+v6addrlen)]
			fallthrough
		case offset + v6addrlen:
			p.Nexthop = nexthopbin[offset : offset+v6addrlen]
		case offset + v4addrlen:
			p.Nexthop = nexthopbin[offset : offset+v4addrlen]
		default:
			return NewMessageError(eCode, eSubCode, value, "mpreach nexthop length is incorrect")
		}
	}
	value = value[4+nexthoplen:]
	// skip reserved
	if len(value) == 0 {
		return NewMessageError(eCode, eSubCode, value, "no skip byte")
	}
	value = value[1:]
	for len(value) > 0 {
		prefix, err := NewPrefixFromRouteFamily(afi, safi)
		if err != nil {
			return NewMessageError(eCode, BGP_ERROR_SUB_ATTRIBUTE_FLAGS_ERROR, data[:p.PathAttribute.Len()], err.Error())
		}
		err = prefix.DecodeFromBytes(value)
		if err != nil {
			return err
		}
		if prefix.Len() > len(value) {
			return NewMessageError(eCode, eSubCode, value, "prefix length is incorrect")
		}
		value = value[prefix.Len():]
		p.Value = append(p.Value, prefix)
	}
	return nil
}

func (p *PathAttributeMpReachNLRI) Serialize() ([]byte, error) {
	afi := p.AFI
	safi := p.SAFI
	nexthoplen := 4
	if afi == AFI_IP6 || p.Nexthop.To4() == nil {
		nexthoplen = 16
	}
	offset := 0
	switch safi {
	case SAFI_MPLS_VPN:
		offset = 8
		nexthoplen += offset
	case SAFI_FLOW_SPEC_VPN, SAFI_FLOW_SPEC_UNICAST:
		nexthoplen = 0
	}
	if p.LinkLocalNexthop != nil {
		nexthoplen *= 2
	}
	buf := make([]byte, 4+nexthoplen)
	binary.BigEndian.PutUint16(buf[0:], afi)
	buf[2] = safi
	buf[3] = uint8(nexthoplen)
	if nexthoplen != 0 {
		if p.Nexthop.To4() == nil {
			copy(buf[4+offset:], p.Nexthop.To16())
			if p.LinkLocalNexthop != nil {
				copy(buf[4+offset+16:], p.LinkLocalNexthop.To16())
			}
		} else {
			copy(buf[4+offset:], p.Nexthop)
		}
	}
	buf = append(buf, make([]byte, 1)...)
	for _, prefix := range p.Value {
		pbuf, err := prefix.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, pbuf...)
	}
	p.PathAttribute.Value = buf
	return p.PathAttribute.Serialize()
}

func (p *PathAttributeMpReachNLRI) MarshalJSON() ([]byte, error) {
	nexthop := p.Nexthop.String()
	if p.Nexthop == nil {
		switch p.AFI {
		case AFI_IP:
			nexthop = "0.0.0.0"
		case AFI_IP6:
			nexthop = "::"
		default:
			nexthop = "fictitious"
		}
	}
	return json.Marshal(struct {
		Type    BGPAttrType           `json:"type"`
		Nexthop string                `json:"nexthop"`
		AFI     uint16                `json:"afi"`
		SAFI    uint8                 `json:"safi"`
		Value   []AddrPrefixInterface `json:"value"`
	}{
		Type:    p.GetType(),
		Nexthop: nexthop,
		AFI:     p.AFI,
		SAFI:    p.SAFI,
		Value:   p.Value,
	})
}

func (p *PathAttributeMpReachNLRI) String() string {
	return fmt.Sprintf("{MpReach(%s): {Nexthop: %s, NLRIs: %s}}", AfiSafiToRouteFamily(p.AFI, p.SAFI), p.Nexthop, p.Value)
}

func NewPathAttributeMpReachNLRI(nexthop string, nlri []AddrPrefixInterface) *PathAttributeMpReachNLRI {
	t := BGP_ATTR_TYPE_MP_REACH_NLRI
	p := &PathAttributeMpReachNLRI{
		PathAttribute: PathAttribute{
			Flags: PathAttrFlags[t],
			Type:  t,
		},
		Value: nlri,
	}
	if len(nlri) > 0 {
		p.AFI = nlri[0].AFI()
		p.SAFI = nlri[0].SAFI()
	}
	nh := net.ParseIP(nexthop)
	if nh.To4() != nil && p.AFI != AFI_IP6 {
		nh = nh.To4()
	}
	p.Nexthop = nh
	return p
}

type PathAttributeMpUnreachNLRI struct {
	PathAttribute
	AFI   uint16
	SAFI  uint8
	Value []AddrPrefixInterface
}

func (p *PathAttributeMpUnreachNLRI) DecodeFromBytes(data []byte) error {
	err := p.PathAttribute.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
	eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)

	value := p.PathAttribute.Value
	if len(value) < 3 {
		return NewMessageError(eCode, eSubCode, value, "unreach header length is incorrect")
	}
	afi := binary.BigEndian.Uint16(value[0:2])
	safi := value[2]
	_, err = NewPrefixFromRouteFamily(afi, safi)
	if err != nil {
		return NewMessageError(eCode, BGP_ERROR_SUB_ATTRIBUTE_FLAGS_ERROR, data[:p.PathAttribute.Len()], err.Error())
	}
	value = value[3:]
	p.AFI = afi
	p.SAFI = safi
	for len(value) > 0 {
		prefix, err := NewPrefixFromRouteFamily(afi, safi)
		if err != nil {
			return NewMessageError(eCode, BGP_ERROR_SUB_ATTRIBUTE_FLAGS_ERROR, data[:p.PathAttribute.Len()], err.Error())
		}
		err = prefix.DecodeFromBytes(value)
		if err != nil {
			return err
		}
		if prefix.Len() > len(value) {
			return NewMessageError(eCode, eSubCode, data[:p.PathAttribute.Len()], "prefix length is incorrect")
		}
		value = value[prefix.Len():]
		p.Value = append(p.Value, prefix)
	}
	return nil
}

func (p *PathAttributeMpUnreachNLRI) Serialize() ([]byte, error) {
	buf := make([]byte, 3)
	binary.BigEndian.PutUint16(buf, p.AFI)
	buf[2] = p.SAFI
	for _, prefix := range p.Value {
		pbuf, err := prefix.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, pbuf...)
	}
	p.PathAttribute.Value = buf
	return p.PathAttribute.Serialize()
}

func (p *PathAttributeMpUnreachNLRI) String() string {
	if len(p.Value) > 0 {
		return fmt.Sprintf("{MpUnreach(%s): {NLRIs: %s}}", AfiSafiToRouteFamily(p.AFI, p.SAFI), p.Value)
	}
	return fmt.Sprintf("{MpUnreach(%s): End-of-Rib}", AfiSafiToRouteFamily(p.AFI, p.SAFI))
}

func NewPathAttributeMpUnreachNLRI(nlri []AddrPrefixInterface) *PathAttributeMpUnreachNLRI {
	t := BGP_ATTR_TYPE_MP_UNREACH_NLRI
	p := &PathAttributeMpUnreachNLRI{
		PathAttribute: PathAttribute{
			Flags:  PathAttrFlags[t],
			Type:   t,
			Length: 0,
		},
		Value: nlri,
	}
	if len(nlri) > 0 {
		p.AFI = nlri[0].AFI()
		p.SAFI = nlri[0].SAFI()
	}
	return p
}

type ExtendedCommunityInterface interface {
	Serialize() ([]byte, error)
	String() string
	GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType)
	MarshalJSON() ([]byte, error)
	Flat() map[string]string
}

type TwoOctetAsSpecificExtended struct {
	SubType      ExtendedCommunityAttrSubType
	AS           uint16
	LocalAdmin   uint32
	IsTransitive bool
}

func (e *TwoOctetAsSpecificExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	if e.IsTransitive {
		buf[0] = byte(EC_TYPE_TRANSITIVE_TWO_OCTET_AS_SPECIFIC)
	} else {
		buf[0] = byte(EC_TYPE_NON_TRANSITIVE_TWO_OCTET_AS_SPECIFIC)
	}
	buf[1] = byte(e.SubType)
	binary.BigEndian.PutUint16(buf[2:], e.AS)
	binary.BigEndian.PutUint32(buf[4:], e.LocalAdmin)
	return buf, nil
}

func (e *TwoOctetAsSpecificExtended) String() string {
	return fmt.Sprintf("%d:%d", e.AS, e.LocalAdmin)
}

func (e *TwoOctetAsSpecificExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		Subtype ExtendedCommunityAttrSubType `json:"subtype"`
		Value   string                       `json:"value"`
	}{
		Type:    t,
		Subtype: s,
		Value:   e.String(),
	})
}

func (e *TwoOctetAsSpecificExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	t := EC_TYPE_TRANSITIVE_TWO_OCTET_AS_SPECIFIC
	if !e.IsTransitive {
		t = EC_TYPE_NON_TRANSITIVE_TWO_OCTET_AS_SPECIFIC
	}
	return t, e.SubType
}

func NewTwoOctetAsSpecificExtended(subtype ExtendedCommunityAttrSubType, as uint16, localAdmin uint32, isTransitive bool) *TwoOctetAsSpecificExtended {
	return &TwoOctetAsSpecificExtended{
		SubType:      subtype,
		AS:           as,
		LocalAdmin:   localAdmin,
		IsTransitive: isTransitive,
	}
}

type IPv4AddressSpecificExtended struct {
	SubType      ExtendedCommunityAttrSubType
	IPv4         net.IP
	LocalAdmin   uint16
	IsTransitive bool
}

func (e *IPv4AddressSpecificExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	if e.IsTransitive {
		buf[0] = byte(EC_TYPE_TRANSITIVE_IP4_SPECIFIC)
	} else {
		buf[0] = byte(EC_TYPE_NON_TRANSITIVE_IP4_SPECIFIC)
	}
	buf[1] = byte(e.SubType)
	copy(buf[2:6], e.IPv4)
	binary.BigEndian.PutUint16(buf[6:], e.LocalAdmin)
	return buf, nil
}

func (e *IPv4AddressSpecificExtended) String() string {
	return fmt.Sprintf("%s:%d", e.IPv4.String(), e.LocalAdmin)
}

func (e *IPv4AddressSpecificExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		Subtype ExtendedCommunityAttrSubType `json:"subtype"`
		Value   string                       `json:"value"`
	}{
		Type:    t,
		Subtype: s,
		Value:   e.String(),
	})
}

func (e *IPv4AddressSpecificExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	t := EC_TYPE_TRANSITIVE_IP4_SPECIFIC
	if !e.IsTransitive {
		t = EC_TYPE_NON_TRANSITIVE_IP4_SPECIFIC
	}
	return t, e.SubType
}

func NewIPv4AddressSpecificExtended(subtype ExtendedCommunityAttrSubType, ip string, localAdmin uint16, isTransitive bool) *IPv4AddressSpecificExtended {
	ipv4 := net.ParseIP(ip)
	if ipv4.To4() == nil {
		return nil
	}
	return &IPv4AddressSpecificExtended{
		SubType:      subtype,
		IPv4:         ipv4.To4(),
		LocalAdmin:   localAdmin,
		IsTransitive: isTransitive,
	}
}

type IPv6AddressSpecificExtended struct {
	SubType      ExtendedCommunityAttrSubType
	IPv6         net.IP
	LocalAdmin   uint16
	IsTransitive bool
}

func (e *IPv6AddressSpecificExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 20)
	if e.IsTransitive {
		buf[0] = byte(EC_TYPE_TRANSITIVE_IP6_SPECIFIC)
	} else {
		buf[0] = byte(EC_TYPE_NON_TRANSITIVE_IP6_SPECIFIC)
	}
	buf[1] = byte(e.SubType)
	copy(buf[2:18], e.IPv6)
	binary.BigEndian.PutUint16(buf[18:], e.LocalAdmin)
	return buf, nil
}

func (e *IPv6AddressSpecificExtended) String() string {
	return fmt.Sprintf("%s:%d", e.IPv6.String(), e.LocalAdmin)
}

func (e *IPv6AddressSpecificExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		Subtype ExtendedCommunityAttrSubType `json:"subtype"`
		Value   string                       `json:"value"`
	}{
		Type:    t,
		Subtype: s,
		Value:   e.String(),
	})
}

func (e *IPv6AddressSpecificExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	t := EC_TYPE_TRANSITIVE_IP6_SPECIFIC
	if !e.IsTransitive {
		t = EC_TYPE_NON_TRANSITIVE_IP6_SPECIFIC
	}
	return t, e.SubType
}

func NewIPv6AddressSpecificExtended(subtype ExtendedCommunityAttrSubType, ip string, localAdmin uint16, isTransitive bool) *IPv6AddressSpecificExtended {
	ipv6 := net.ParseIP(ip)
	if ipv6.To16() == nil {
		return nil
	}
	return &IPv6AddressSpecificExtended{
		SubType:      subtype,
		IPv6:         ipv6.To16(),
		LocalAdmin:   localAdmin,
		IsTransitive: isTransitive,
	}
}

type FourOctetAsSpecificExtended struct {
	SubType      ExtendedCommunityAttrSubType
	AS           uint32
	LocalAdmin   uint16
	IsTransitive bool
}

func (e *FourOctetAsSpecificExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	if e.IsTransitive {
		buf[0] = byte(EC_TYPE_TRANSITIVE_FOUR_OCTET_AS_SPECIFIC)
	} else {
		buf[0] = byte(EC_TYPE_NON_TRANSITIVE_FOUR_OCTET_AS_SPECIFIC)
	}
	buf[1] = byte(e.SubType)
	binary.BigEndian.PutUint32(buf[2:], e.AS)
	binary.BigEndian.PutUint16(buf[6:], e.LocalAdmin)
	return buf, nil
}

func (e *FourOctetAsSpecificExtended) String() string {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, e.AS)
	asUpper := binary.BigEndian.Uint16(buf[0:2])
	asLower := binary.BigEndian.Uint16(buf[2:])
	return fmt.Sprintf("%d.%d:%d", asUpper, asLower, e.LocalAdmin)
}

func (e *FourOctetAsSpecificExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		Subtype ExtendedCommunityAttrSubType `json:"subtype"`
		Value   string                       `json:"value"`
	}{
		Type:    t,
		Subtype: s,
		Value:   e.String(),
	})
}

func (e *FourOctetAsSpecificExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	t := EC_TYPE_TRANSITIVE_FOUR_OCTET_AS_SPECIFIC
	if !e.IsTransitive {
		t = EC_TYPE_NON_TRANSITIVE_FOUR_OCTET_AS_SPECIFIC
	}
	return t, e.SubType
}

func NewFourOctetAsSpecificExtended(subtype ExtendedCommunityAttrSubType, as uint32, localAdmin uint16, isTransitive bool) *FourOctetAsSpecificExtended {
	return &FourOctetAsSpecificExtended{
		SubType:      subtype,
		AS:           as,
		LocalAdmin:   localAdmin,
		IsTransitive: isTransitive,
	}
}

func ParseExtendedCommunity(subtype ExtendedCommunityAttrSubType, com string) (ExtendedCommunityInterface, error) {
	if subtype == EC_SUBTYPE_ORIGIN_VALIDATION {
		var value ValidationState
		switch com {
		case VALIDATION_STATE_VALID.String():
			value = VALIDATION_STATE_VALID
		case VALIDATION_STATE_NOT_FOUND.String():
			value = VALIDATION_STATE_NOT_FOUND
		case VALIDATION_STATE_INVALID.String():
			value = VALIDATION_STATE_INVALID
		default:
			return nil, fmt.Errorf("invalid validation state")
		}
		return &OpaqueExtended{
			SubType: EC_SUBTYPE_ORIGIN_VALIDATION,
			Value: &ValidationExtended{
				Value: value,
			},
		}, nil
	}
	elems, err := parseRdAndRt(com)
	if err != nil {
		return nil, err
	}
	localAdmin, _ := strconv.Atoi(elems[10])
	ip := net.ParseIP(elems[1])
	isTransitive := true
	switch {
	case ip.To4() != nil:
		return NewIPv4AddressSpecificExtended(subtype, elems[1], uint16(localAdmin), isTransitive), nil
	case ip.To16() != nil:
		return NewIPv6AddressSpecificExtended(subtype, elems[1], uint16(localAdmin), isTransitive), nil
	case elems[6] == "" && elems[7] == "":
		asn, _ := strconv.Atoi(elems[8])
		return NewTwoOctetAsSpecificExtended(subtype, uint16(asn), uint32(localAdmin), isTransitive), nil
	default:
		fst, _ := strconv.Atoi(elems[7])
		snd, _ := strconv.Atoi(elems[8])
		asn := fst<<16 | snd
		return NewFourOctetAsSpecificExtended(subtype, uint32(asn), uint16(localAdmin), isTransitive), nil
	}
}

func ParseRouteTarget(rt string) (ExtendedCommunityInterface, error) {
	return ParseExtendedCommunity(EC_SUBTYPE_ROUTE_TARGET, rt)
}

type OpaqueExtendedValueInterface interface {
	Serialize() ([]byte, error)
	String() string
}

type DefaultOpaqueExtendedValue struct {
	Value []byte
}

func (v *DefaultOpaqueExtendedValue) Serialize() ([]byte, error) {
	v.Value = v.Value[:7]
	return v.Value[:7], nil
}

func (v *DefaultOpaqueExtendedValue) String() string {
	buf := make([]byte, 8)
	copy(buf[1:], v.Value)
	d := binary.BigEndian.Uint64(buf)
	return fmt.Sprintf("%d", d)
}

type ValidationState uint8

const (
	VALIDATION_STATE_VALID     ValidationState = 0
	VALIDATION_STATE_NOT_FOUND ValidationState = 1
	VALIDATION_STATE_INVALID   ValidationState = 2
)

func (s ValidationState) String() string {
	switch s {
	case VALIDATION_STATE_VALID:
		return "valid"
	case VALIDATION_STATE_NOT_FOUND:
		return "not-found"
	case VALIDATION_STATE_INVALID:
		return "invalid"
	}
	return fmt.Sprintf("unknown validatation state(%d)", s)
}

type ValidationExtended struct {
	Value ValidationState
}

func (e *ValidationExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 7)
	buf[0] = byte(EC_SUBTYPE_ORIGIN_VALIDATION)
	buf[6] = byte(e.Value)
	return buf, nil
}

func (e *ValidationExtended) String() string {
	return e.Value.String()
}

type ColorExtended struct {
	Value uint32
}

func (e *ColorExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 7)
	buf[0] = byte(EC_SUBTYPE_COLOR)
	binary.BigEndian.PutUint32(buf[3:], uint32(e.Value))
	return buf, nil
}

func (e *ColorExtended) String() string {
	return fmt.Sprintf("%d", e.Value)
}

type EncapExtended struct {
	TunnelType TunnelType
}

func (e *EncapExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 7)
	buf[0] = byte(EC_SUBTYPE_ENCAPSULATION)
	binary.BigEndian.PutUint16(buf[5:], uint16(e.TunnelType))
	return buf, nil
}

func (e *EncapExtended) String() string {
	switch e.TunnelType {
	case TUNNEL_TYPE_L2TP3:
		return "L2TPv3 over IP"
	case TUNNEL_TYPE_GRE:
		return "GRE"
	case TUNNEL_TYPE_IP_IN_IP:
		return "IP in IP"
	case TUNNEL_TYPE_VXLAN:
		return "VXLAN"
	case TUNNEL_TYPE_NVGRE:
		return "NVGRE"
	case TUNNEL_TYPE_MPLS:
		return "MPLS"
	case TUNNEL_TYPE_MPLS_IN_GRE:
		return "MPLS in GRE"
	case TUNNEL_TYPE_VXLAN_GRE:
		return "VXLAN GRE"
	case TUNNEL_TYPE_MPLS_IN_UDP:
		return "MPLS in UDP"
	default:
		return fmt.Sprintf("tunnel: %d", e.TunnelType)
	}
}

type OpaqueExtended struct {
	IsTransitive bool
	Value        OpaqueExtendedValueInterface
	SubType      ExtendedCommunityAttrSubType
}

func (e *OpaqueExtended) DecodeFromBytes(data []byte) error {
	if len(data) != 7 {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("Invalid OpaqueExtended bytes len: %d", len(data)))
	}
	e.SubType = ExtendedCommunityAttrSubType(data[0])

	if e.IsTransitive {
		switch e.SubType {
		case EC_SUBTYPE_COLOR:
			v := binary.BigEndian.Uint32(data[3:7])
			e.Value = &ColorExtended{
				Value: v,
			}
		case EC_SUBTYPE_ENCAPSULATION:
			t := TunnelType(binary.BigEndian.Uint16(data[5:7]))
			e.Value = &EncapExtended{
				TunnelType: t,
			}
		default:
			e.Value = &DefaultOpaqueExtendedValue{
				Value: data, //7byte
			}
		}
	} else {
		switch e.SubType {
		case EC_SUBTYPE_ORIGIN_VALIDATION:
			e.Value = &ValidationExtended{
				Value: ValidationState(data[6]),
			}
		default:
			e.Value = &DefaultOpaqueExtendedValue{
				Value: data, //7byte
			}
		}
	}
	return nil
}

func (e *OpaqueExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 1, 7)
	if e.IsTransitive {
		buf[0] = byte(EC_TYPE_TRANSITIVE_OPAQUE)
	} else {
		buf[0] = byte(EC_TYPE_NON_TRANSITIVE_OPAQUE)
	}
	bbuf, err := e.Value.Serialize()
	e.SubType = ExtendedCommunityAttrSubType(bbuf[0])
	if err != nil {
		return nil, err
	}
	buf = append(buf, bbuf...)
	return buf, nil
}

func (e *OpaqueExtended) String() string {
	return e.Value.String()
}

func (e *OpaqueExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		Subtype ExtendedCommunityAttrSubType `json:"subtype"`
		Value   OpaqueExtendedValueInterface `json:"value"`
	}{
		Type:    t,
		Subtype: s,
		Value:   e.Value,
	})
}

func (e *OpaqueExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	t := EC_TYPE_TRANSITIVE_OPAQUE
	if !e.IsTransitive {
		t = EC_TYPE_NON_TRANSITIVE_OPAQUE
	}
	return t, e.SubType
}

func NewOpaqueExtended(isTransitive bool) *OpaqueExtended {
	return &OpaqueExtended{
		IsTransitive: isTransitive,
	}
}

type ESILabelExtended struct {
	Label          uint32
	IsSingleActive bool
}

func (e *ESILabelExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	buf[0] = byte(EC_TYPE_EVPN)
	buf[1] = byte(EC_SUBTYPE_ESI_LABEL)
	if e.IsSingleActive {
		buf[2] = byte(1)
	}
	buf[3] = 0
	buf[4] = 0
	buf[5] = byte((e.Label >> 16) & 0xff)
	buf[6] = byte((e.Label >> 8) & 0xff)
	buf[7] = byte(e.Label & 0xff)
	return buf, nil
}

func (e *ESILabelExtended) String() string {
	buf := bytes.NewBuffer(make([]byte, 0, 32))
	buf.WriteString(fmt.Sprintf("esi-label: %d", e.Label))
	if e.IsSingleActive {
		buf.WriteString(", single-active")
	}
	return buf.String()
}

func (e *ESILabelExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type           ExtendedCommunityAttrType    `json:"type"`
		Subtype        ExtendedCommunityAttrSubType `json:"subtype"`
		Label          uint32                       `json:"label"`
		IsSingleActive bool                         `json:"is_single_active"`
	}{
		Type:           t,
		Subtype:        s,
		Label:          e.Label,
		IsSingleActive: e.IsSingleActive,
	})
}

func (e *ESILabelExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return EC_TYPE_EVPN, EC_SUBTYPE_ESI_LABEL
}

func NewESILabelExtended(label uint32, isSingleActive bool) *ESILabelExtended {
	return &ESILabelExtended{
		Label:          label,
		IsSingleActive: isSingleActive,
	}
}

type ESImportRouteTarget struct {
	ESImport net.HardwareAddr
}

func (e *ESImportRouteTarget) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	buf[0] = byte(EC_TYPE_EVPN)
	buf[1] = byte(EC_SUBTYPE_ES_IMPORT)
	copy(buf[2:], e.ESImport)
	return buf, nil
}

func (e *ESImportRouteTarget) String() string {
	return fmt.Sprintf("es-import rt: %s", e.ESImport.String())
}

func (e *ESImportRouteTarget) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		Subtype ExtendedCommunityAttrSubType `json:"subtype"`
		Value   string                       `json:"value"`
	}{
		Type:    t,
		Subtype: s,
		Value:   e.ESImport.String(),
	})
}

func (e *ESImportRouteTarget) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return EC_TYPE_EVPN, EC_SUBTYPE_ES_IMPORT
}

func NewESImportRouteTarget(mac string) *ESImportRouteTarget {
	esImport, err := net.ParseMAC(mac)
	if err != nil {
		return nil
	}
	return &ESImportRouteTarget{
		ESImport: esImport,
	}
}

type MacMobilityExtended struct {
	Sequence uint32
	IsSticky bool
}

func (e *MacMobilityExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	buf[0] = byte(EC_TYPE_EVPN)
	buf[1] = byte(EC_SUBTYPE_MAC_MOBILITY)
	if e.IsSticky {
		buf[2] = byte(1)
	}
	binary.BigEndian.PutUint32(buf[4:], e.Sequence)
	return buf, nil
}

func (e *MacMobilityExtended) String() string {
	buf := bytes.NewBuffer(make([]byte, 0, 32))
	buf.WriteString(fmt.Sprintf("mac-mobility: %d", e.Sequence))
	if e.IsSticky {
		buf.WriteString(", sticky")
	}
	return buf.String()
}

func (e *MacMobilityExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type     ExtendedCommunityAttrType    `json:"type"`
		Subtype  ExtendedCommunityAttrSubType `json:"subtype"`
		Sequence uint32                       `json:"sequence"`
		IsSticky bool                         `json:"is_sticky"`
	}{
		Type:     t,
		Subtype:  s,
		Sequence: e.Sequence,
		IsSticky: e.IsSticky,
	})
}

func (e *MacMobilityExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return EC_TYPE_EVPN, EC_SUBTYPE_MAC_MOBILITY
}

func NewMacMobilityExtended(seq uint32, isSticky bool) *MacMobilityExtended {
	return &MacMobilityExtended{
		Sequence: seq,
		IsSticky: isSticky,
	}
}

func parseEvpnExtended(data []byte) (ExtendedCommunityInterface, error) {
	if ExtendedCommunityAttrType(data[0]) != EC_TYPE_EVPN {
		return nil, NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("ext comm type is not EC_TYPE_EVPN: %d", data[0]))
	}
	subType := ExtendedCommunityAttrSubType(data[1])
	switch subType {
	case EC_SUBTYPE_ESI_LABEL:
		var isSingleActive bool
		if data[2] > 0 {
			isSingleActive = true
		}
		label := uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7])
		return &ESILabelExtended{
			IsSingleActive: isSingleActive,
			Label:          label,
		}, nil
	case EC_SUBTYPE_ES_IMPORT:
		return &ESImportRouteTarget{
			ESImport: net.HardwareAddr(data[2:8]),
		}, nil
	case EC_SUBTYPE_MAC_MOBILITY:
		var isSticky bool
		if data[2] > 0 {
			isSticky = true
		}
		seq := binary.BigEndian.Uint32(data[4:8])
		return &MacMobilityExtended{
			Sequence: seq,
			IsSticky: isSticky,
		}, nil
	}
	return nil, NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("unknown evpn subtype: %d", subType))
}

type TrafficRateExtended struct {
	AS   uint16
	Rate float32
}

func (e *TrafficRateExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	buf[0] = byte(EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL)
	buf[1] = byte(EC_SUBTYPE_FLOWSPEC_TRAFFIC_RATE)
	binary.BigEndian.PutUint16(buf[2:4], e.AS)
	binary.BigEndian.PutUint32(buf[4:8], math.Float32bits(e.Rate))
	return buf, nil
}

func (e *TrafficRateExtended) String() string {
	buf := bytes.NewBuffer(make([]byte, 0, 32))
	if e.Rate == 0 {
		buf.WriteString("discard")
	} else {
		buf.WriteString(fmt.Sprintf("rate: %f", e.Rate))
	}
	if e.AS != 0 {
		buf.WriteString(fmt.Sprintf("(as: %d)", e.AS))
	}
	return buf.String()
}

func (e *TrafficRateExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		Subtype ExtendedCommunityAttrSubType `json:"subtype"`
		As      uint16                       `json:"as"`
		Rate    float32                      `json:"rate"`
	}{t, s, e.AS, e.Rate})
}

func (e *TrafficRateExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL, EC_SUBTYPE_FLOWSPEC_TRAFFIC_RATE
}

func NewTrafficRateExtended(as uint16, rate float32) *TrafficRateExtended {
	return &TrafficRateExtended{as, rate}
}

type TrafficActionExtended struct {
	Terminal bool
	Sample   bool
}

func (e *TrafficActionExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	buf[0] = byte(EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL)
	buf[1] = byte(EC_SUBTYPE_FLOWSPEC_TRAFFIC_ACTION)
	if e.Terminal {
		buf[7] = 0x01
	}
	if e.Sample {
		buf[7] = buf[7] | 0x2
	}
	return buf, nil
}

func (e *TrafficActionExtended) String() string {
	ss := make([]string, 0, 2)
	if e.Terminal {
		ss = append(ss, "terminal")
	}
	if e.Sample {
		ss = append(ss, "sample")
	}
	return fmt.Sprintf("action: %s", strings.Join(ss, "-"))
}

func (e *TrafficActionExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type     ExtendedCommunityAttrType    `json:"type"`
		Subtype  ExtendedCommunityAttrSubType `json:"subtype"`
		Terminal bool                         `json:"terminal"`
		Sample   bool                         `json:"sample"`
	}{t, s, e.Terminal, e.Sample})
}

func (e *TrafficActionExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL, EC_SUBTYPE_FLOWSPEC_TRAFFIC_ACTION
}

func NewTrafficActionExtended(terminal bool, sample bool) *TrafficActionExtended {
	return &TrafficActionExtended{terminal, sample}
}

type RedirectTwoOctetAsSpecificExtended struct {
	TwoOctetAsSpecificExtended
}

func (e *RedirectTwoOctetAsSpecificExtended) Serialize() ([]byte, error) {
	buf, err := e.TwoOctetAsSpecificExtended.Serialize()
	buf[0] = byte(EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL)
	buf[1] = byte(EC_SUBTYPE_FLOWSPEC_REDIRECT)
	return buf, err
}

func (e *RedirectTwoOctetAsSpecificExtended) String() string {
	return fmt.Sprintf("redirect: %s", e.TwoOctetAsSpecificExtended.String())
}

func (e *RedirectTwoOctetAsSpecificExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		Subtype ExtendedCommunityAttrSubType `json:"subtype"`
		Value   string                       `json:"value"`
	}{t, s, e.TwoOctetAsSpecificExtended.String()})
}

func (e *RedirectTwoOctetAsSpecificExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL, EC_SUBTYPE_FLOWSPEC_REDIRECT
}

func NewRedirectTwoOctetAsSpecificExtended(as uint16, localAdmin uint32) *RedirectTwoOctetAsSpecificExtended {
	return &RedirectTwoOctetAsSpecificExtended{*NewTwoOctetAsSpecificExtended(EC_SUBTYPE_ROUTE_TARGET, as, localAdmin, false)}
}

type RedirectIPv4AddressSpecificExtended struct {
	IPv4AddressSpecificExtended
}

func (e *RedirectIPv4AddressSpecificExtended) Serialize() ([]byte, error) {
	buf, err := e.IPv4AddressSpecificExtended.Serialize()
	buf[0] = byte(EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL2)
	buf[1] = byte(EC_SUBTYPE_FLOWSPEC_REDIRECT)
	return buf, err
}

func (e *RedirectIPv4AddressSpecificExtended) String() string {
	return fmt.Sprintf("redirect: %s", e.IPv4AddressSpecificExtended.String())
}

func (e *RedirectIPv4AddressSpecificExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		Subtype ExtendedCommunityAttrSubType `json:"subtype"`
		Value   string                       `json:"value"`
	}{t, s, e.IPv4AddressSpecificExtended.String()})
}

func (e *RedirectIPv4AddressSpecificExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL2, EC_SUBTYPE_FLOWSPEC_REDIRECT
}

func NewRedirectIPv4AddressSpecificExtended(ipv4 string, localAdmin uint16) *RedirectIPv4AddressSpecificExtended {
	return &RedirectIPv4AddressSpecificExtended{*NewIPv4AddressSpecificExtended(EC_SUBTYPE_ROUTE_TARGET, ipv4, localAdmin, false)}
}

type RedirectIPv6AddressSpecificExtended struct {
	IPv6AddressSpecificExtended
}

func (e *RedirectIPv6AddressSpecificExtended) Serialize() ([]byte, error) {
	buf, err := e.IPv6AddressSpecificExtended.Serialize()
	buf[0] = byte(EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL)
	buf[1] = byte(EC_SUBTYPE_FLOWSPEC_REDIRECT_IP6)
	return buf, err
}

func (e *RedirectIPv6AddressSpecificExtended) String() string {
	return fmt.Sprintf("redirect: %s", e.IPv6AddressSpecificExtended.String())
}

func (e *RedirectIPv6AddressSpecificExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		Subtype ExtendedCommunityAttrSubType `json:"subtype"`
		Value   string                       `json:"value"`
	}{t, s, e.IPv6AddressSpecificExtended.String()})
}

func (e *RedirectIPv6AddressSpecificExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL, EC_SUBTYPE_FLOWSPEC_REDIRECT_IP6
}

func NewRedirectIPv6AddressSpecificExtended(ipv6 string, localAdmin uint16) *RedirectIPv6AddressSpecificExtended {
	return &RedirectIPv6AddressSpecificExtended{*NewIPv6AddressSpecificExtended(EC_SUBTYPE_ROUTE_TARGET, ipv6, localAdmin, false)}
}

type RedirectFourOctetAsSpecificExtended struct {
	FourOctetAsSpecificExtended
}

func (e *RedirectFourOctetAsSpecificExtended) Serialize() ([]byte, error) {
	buf, err := e.FourOctetAsSpecificExtended.Serialize()
	buf[0] = byte(EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL3)
	buf[1] = byte(EC_SUBTYPE_FLOWSPEC_REDIRECT)
	return buf, err
}

func (e *RedirectFourOctetAsSpecificExtended) String() string {
	return fmt.Sprintf("redirect: %s", e.FourOctetAsSpecificExtended.String())
}

func (e *RedirectFourOctetAsSpecificExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		Subtype ExtendedCommunityAttrSubType `json:"subtype"`
		Value   string                       `json:"value"`
	}{t, s, e.FourOctetAsSpecificExtended.String()})
}

func (e *RedirectFourOctetAsSpecificExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL3, EC_SUBTYPE_FLOWSPEC_REDIRECT
}

func NewRedirectFourOctetAsSpecificExtended(as uint32, localAdmin uint16) *RedirectFourOctetAsSpecificExtended {
	return &RedirectFourOctetAsSpecificExtended{*NewFourOctetAsSpecificExtended(EC_SUBTYPE_ROUTE_TARGET, as, localAdmin, false)}
}

type TrafficRemarkExtended struct {
	DSCP uint8
}

func (e *TrafficRemarkExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	buf[0] = byte(EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL)
	buf[1] = byte(EC_SUBTYPE_FLOWSPEC_TRAFFIC_REMARK)
	buf[7] = byte(e.DSCP)
	return buf, nil
}

func (e *TrafficRemarkExtended) String() string {
	return fmt.Sprintf("remark: %d", e.DSCP)
}

func (e *TrafficRemarkExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		Subtype ExtendedCommunityAttrSubType `json:"subtype"`
		Value   uint8                        `json:"value"`
	}{t, s, e.DSCP})
}

func (e *TrafficRemarkExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL, EC_SUBTYPE_FLOWSPEC_TRAFFIC_REMARK
}

func NewTrafficRemarkExtended(dscp uint8) *TrafficRemarkExtended {
	return &TrafficRemarkExtended{dscp}
}

func parseFlowSpecExtended(data []byte) (ExtendedCommunityInterface, error) {
	typ := ExtendedCommunityAttrType(data[0])
	if typ != EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL && typ != EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL2 && typ != EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL3 {
		return nil, NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("ext comm type is not EC_TYPE_FLOWSPEC: %d", data[0]))
	}
	subType := ExtendedCommunityAttrSubType(data[1])
	switch subType {
	case EC_SUBTYPE_FLOWSPEC_TRAFFIC_RATE:
		asn := binary.BigEndian.Uint16(data[2:4])
		bits := binary.BigEndian.Uint32(data[4:8])
		rate := math.Float32frombits(bits)
		return NewTrafficRateExtended(asn, rate), nil
	case EC_SUBTYPE_FLOWSPEC_TRAFFIC_ACTION:
		terminal := data[7]&0x1 == 1
		sample := (data[7]>>1)&0x1 == 1
		return NewTrafficActionExtended(terminal, sample), nil
	case EC_SUBTYPE_FLOWSPEC_REDIRECT:
		// RFC7674
		switch typ {
		case EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL:
			as := binary.BigEndian.Uint16(data[2:4])
			localAdmin := binary.BigEndian.Uint32(data[4:8])
			return NewRedirectTwoOctetAsSpecificExtended(as, localAdmin), nil
		case EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL2:
			ipv4 := net.IP(data[2:6]).String()
			localAdmin := binary.BigEndian.Uint16(data[6:8])
			return NewRedirectIPv4AddressSpecificExtended(ipv4, localAdmin), nil
		case EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL3:
			as := binary.BigEndian.Uint32(data[2:6])
			localAdmin := binary.BigEndian.Uint16(data[6:8])
			return NewRedirectFourOctetAsSpecificExtended(as, localAdmin), nil
		}
	case EC_SUBTYPE_FLOWSPEC_TRAFFIC_REMARK:
		dscp := data[7]
		return NewTrafficRemarkExtended(dscp), nil
	case EC_SUBTYPE_FLOWSPEC_REDIRECT_IP6:
		ipv6 := net.IP(data[2:18]).String()
		localAdmin := binary.BigEndian.Uint16(data[18:20])
		return NewRedirectIPv6AddressSpecificExtended(ipv6, localAdmin), nil
	}
	return &UnknownExtended{
		Type:  ExtendedCommunityAttrType(data[0]),
		Value: data[1:8],
	}, nil
}

func parseIP6FlowSpecExtended(data []byte) (ExtendedCommunityInterface, error) {
	typ := ExtendedCommunityAttrType(data[0])
	if typ != EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL && typ != EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL2 && typ != EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL3 {
		return nil, NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("ext comm type is not EC_TYPE_FLOWSPEC: %d", data[0]))
	}
	subType := ExtendedCommunityAttrSubType(data[1])
	switch subType {
	case EC_SUBTYPE_FLOWSPEC_REDIRECT_IP6:
		// RFC7674
		switch typ {
		case EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL:
			ipv6 := net.IP(data[2:18]).String()
			localAdmin := binary.BigEndian.Uint16(data[18:20])
			return NewRedirectIPv6AddressSpecificExtended(ipv6, localAdmin), nil
		}
	}
	return &UnknownExtended{
		Type:  ExtendedCommunityAttrType(data[0]),
		Value: data[1:20],
	}, nil
}

type UnknownExtended struct {
	Type  ExtendedCommunityAttrType
	Value []byte
}

func (e *UnknownExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	buf[0] = uint8(e.Type)
	copy(buf[1:], e.Value)
	e.Value = buf[1:]
	return buf, nil
}

func (e *UnknownExtended) String() string {
	buf := make([]byte, 8)
	copy(buf[1:], e.Value)
	v := binary.BigEndian.Uint64(buf)
	return fmt.Sprintf("%d", v)
}

func (e *UnknownExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		Subtype ExtendedCommunityAttrSubType `json:"subtype"`
		Value   []byte                       `json:"value"`
	}{
		Type:    t,
		Subtype: s,
		Value:   e.Value,
	})
}

func (e *UnknownExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return ExtendedCommunityAttrType(0xFF), ExtendedCommunityAttrSubType(0xFF)
}

type PathAttributeExtendedCommunities struct {
	PathAttribute
	Value []ExtendedCommunityInterface
}

func ParseExtended(data []byte) (ExtendedCommunityInterface, error) {
	if len(data) < 8 {
		return nil, NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "not all extended community bytes are available")
	}
	attrType := ExtendedCommunityAttrType(data[0])
	subtype := ExtendedCommunityAttrSubType(data[1])
	transitive := false
	switch attrType {
	case EC_TYPE_TRANSITIVE_TWO_OCTET_AS_SPECIFIC:
		transitive = true
		fallthrough
	case EC_TYPE_NON_TRANSITIVE_TWO_OCTET_AS_SPECIFIC:
		as := binary.BigEndian.Uint16(data[2:4])
		localAdmin := binary.BigEndian.Uint32(data[4:8])
		return NewTwoOctetAsSpecificExtended(subtype, as, localAdmin, transitive), nil
	case EC_TYPE_TRANSITIVE_IP4_SPECIFIC:
		transitive = true
		fallthrough
	case EC_TYPE_NON_TRANSITIVE_IP4_SPECIFIC:
		ipv4 := net.IP(data[2:6]).String()
		localAdmin := binary.BigEndian.Uint16(data[6:8])
		return NewIPv4AddressSpecificExtended(subtype, ipv4, localAdmin, transitive), nil
	case EC_TYPE_TRANSITIVE_FOUR_OCTET_AS_SPECIFIC:
		transitive = true
		fallthrough
	case EC_TYPE_NON_TRANSITIVE_FOUR_OCTET_AS_SPECIFIC:
		as := binary.BigEndian.Uint32(data[2:6])
		localAdmin := binary.BigEndian.Uint16(data[6:8])
		return NewFourOctetAsSpecificExtended(subtype, as, localAdmin, transitive), nil
	case EC_TYPE_TRANSITIVE_OPAQUE:
		transitive = true
		fallthrough
	case EC_TYPE_NON_TRANSITIVE_OPAQUE:
		e := NewOpaqueExtended(transitive)
		err := e.DecodeFromBytes(data[1:8])
		return e, err
	case EC_TYPE_EVPN:
		return parseEvpnExtended(data)
	case EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL, EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL2, EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL3:
		return parseFlowSpecExtended(data)
	default:
		return &UnknownExtended{
			Type:  ExtendedCommunityAttrType(data[0]),
			Value: data[1:8],
		}, nil
	}
}

func (p *PathAttributeExtendedCommunities) DecodeFromBytes(data []byte) error {
	err := p.PathAttribute.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	if len(p.PathAttribute.Value)%8 != 0 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)
		return NewMessageError(eCode, eSubCode, nil, "extendedcommunities length isn't correct")
	}
	value := p.PathAttribute.Value
	for len(value) >= 8 {
		e, err := ParseExtended(value)
		if err != nil {
			return err
		}
		p.Value = append(p.Value, e)
		value = value[8:]
	}
	return nil
}

func (p *PathAttributeExtendedCommunities) Serialize() ([]byte, error) {
	buf := make([]byte, 0)
	for _, p := range p.Value {
		ebuf, err := p.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, ebuf...)
	}
	p.PathAttribute.Value = buf
	return p.PathAttribute.Serialize()
}

func (p *PathAttributeExtendedCommunities) String() string {
	buf := bytes.NewBuffer(make([]byte, 0, 32))
	for idx, v := range p.Value {
		buf.WriteString("[")
		buf.WriteString(v.String())
		buf.WriteString("]")
		if idx < len(p.Value)-1 {
			buf.WriteString(", ")
		}
	}
	return fmt.Sprintf("{Extcomms: %s}", buf.String())
}

func (p *PathAttributeExtendedCommunities) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPAttrType                  `json:"type"`
		Value []ExtendedCommunityInterface `json:"value"`
	}{
		Type:  p.GetType(),
		Value: p.Value,
	})
}

func NewPathAttributeExtendedCommunities(value []ExtendedCommunityInterface) *PathAttributeExtendedCommunities {
	t := BGP_ATTR_TYPE_EXTENDED_COMMUNITIES
	return &PathAttributeExtendedCommunities{
		PathAttribute: PathAttribute{
			Flags: PathAttrFlags[t],
			Type:  t,
		},
		Value: value,
	}
}

type PathAttributeAs4Path struct {
	PathAttribute
	Value []*As4PathParam
	DefaultAsPath
}

func (p *PathAttributeAs4Path) DecodeFromBytes(data []byte) error {
	err := p.PathAttribute.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
	eSubCode := uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST)
	v := p.PathAttribute.Value
	as4Bytes, err := p.DefaultAsPath.isValidAspath(p.PathAttribute.Value)
	if err != nil {
		return err
	}
	if as4Bytes == false {
		return NewMessageError(eCode, eSubCode, nil, "AS4 PATH param is malformed")
	}
	for len(v) > 0 {
		tuple := &As4PathParam{}
		tuple.DecodeFromBytes(v)
		p.Value = append(p.Value, tuple)
		if len(v) < tuple.Len() {
			return NewMessageError(eCode, eSubCode, nil, "AS4 PATH param is malformed")
		}
		v = v[tuple.Len():]
	}
	return nil
}

func (p *PathAttributeAs4Path) Serialize() ([]byte, error) {
	buf := make([]byte, 0)
	for _, v := range p.Value {
		vbuf, err := v.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, vbuf...)
	}
	p.PathAttribute.Value = buf
	return p.PathAttribute.Serialize()
}

func (p *PathAttributeAs4Path) String() string {
	params := make([]string, 0, len(p.Value))
	for _, param := range p.Value {
		params = append(params, param.String())
	}
	return strings.Join(params, " ")
}

func NewPathAttributeAs4Path(value []*As4PathParam) *PathAttributeAs4Path {
	t := BGP_ATTR_TYPE_AS4_PATH
	return &PathAttributeAs4Path{
		PathAttribute: PathAttribute{
			Flags: PathAttrFlags[t],
			Type:  t,
		},
		Value: value,
	}
}

type PathAttributeAs4Aggregator struct {
	PathAttribute
	Value PathAttributeAggregatorParam
}

func (p *PathAttributeAs4Aggregator) DecodeFromBytes(data []byte) error {
	err := p.PathAttribute.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	if len(p.PathAttribute.Value) != 8 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST)
		return NewMessageError(eCode, eSubCode, nil, "AS4 Aggregator length is incorrect")
	}
	p.Value.AS = binary.BigEndian.Uint32(p.PathAttribute.Value[0:4])
	p.Value.Address = p.PathAttribute.Value[4:]
	return nil
}

func (p *PathAttributeAs4Aggregator) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint32(buf[0:], p.Value.AS)
	copy(buf[4:], p.Value.Address.To4())
	p.PathAttribute.Value = buf
	return p.PathAttribute.Serialize()
}

func NewPathAttributeAs4Aggregator(as uint32, address string) *PathAttributeAs4Aggregator {
	t := BGP_ATTR_TYPE_AS4_AGGREGATOR
	return &PathAttributeAs4Aggregator{
		PathAttribute: PathAttribute{
			Flags: PathAttrFlags[t],
			Type:  t,
		},
		Value: PathAttributeAggregatorParam{
			AS:      as,
			Address: net.ParseIP(address).To4(),
		},
	}
}

type TunnelEncapSubTLVValue interface {
	Serialize() ([]byte, error)
}

type TunnelEncapSubTLVDefault struct {
	Value []byte
}

func (t *TunnelEncapSubTLVDefault) Serialize() ([]byte, error) {
	return t.Value, nil
}

type TunnelEncapSubTLVEncapsulation struct {
	Key    uint32 // this represent both SessionID for L2TPv3 case and GRE-key for GRE case (RFC5512 4.)
	Cookie []byte
}

func (t *TunnelEncapSubTLVEncapsulation) Serialize() ([]byte, error) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, t.Key)
	return append(buf, t.Cookie...), nil
}

type TunnelEncapSubTLVProtocol struct {
	Protocol uint16
}

func (t *TunnelEncapSubTLVProtocol) Serialize() ([]byte, error) {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, t.Protocol)
	return buf, nil
}

type TunnelEncapSubTLVColor struct {
	Color uint32
}

func (t *TunnelEncapSubTLVColor) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	buf[0] = byte(EC_TYPE_TRANSITIVE_OPAQUE)
	buf[1] = byte(EC_SUBTYPE_COLOR)
	binary.BigEndian.PutUint32(buf[4:], t.Color)
	return buf, nil
}

type TunnelEncapSubTLV struct {
	Type  EncapSubTLVType
	Len   int
	Value TunnelEncapSubTLVValue
}

func (p *TunnelEncapSubTLV) Serialize() ([]byte, error) {
	buf := make([]byte, 2)
	bbuf, err := p.Value.Serialize()
	if err != nil {
		return nil, err
	}
	buf = append(buf, bbuf...)
	buf[0] = byte(p.Type)
	p.Len = len(buf) - 2
	buf[1] = byte(p.Len)
	return buf, nil
}

func (p *TunnelEncapSubTLV) DecodeFromBytes(data []byte) error {
	switch p.Type {
	case ENCAP_SUBTLV_TYPE_ENCAPSULATION:
		if len(data) < 4 {
			return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Not all TunnelEncapSubTLV bytes available")
		}
		key := binary.BigEndian.Uint32(data[:4])
		p.Value = &TunnelEncapSubTLVEncapsulation{
			Key:    key,
			Cookie: data[4:],
		}
	case ENCAP_SUBTLV_TYPE_PROTOCOL:
		if len(data) < 2 {
			return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Not all TunnelEncapSubTLV bytes available")
		}
		protocol := binary.BigEndian.Uint16(data[:2])
		p.Value = &TunnelEncapSubTLVProtocol{protocol}
	case ENCAP_SUBTLV_TYPE_COLOR:
		if len(data) < 8 {
			return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Not all TunnelEncapSubTLV bytes available")
		}
		color := binary.BigEndian.Uint32(data[4:])
		p.Value = &TunnelEncapSubTLVColor{color}
	default:
		p.Value = &TunnelEncapSubTLVDefault{data}
	}
	return nil
}

type TunnelEncapTLV struct {
	Type  TunnelType
	Len   int
	Value []*TunnelEncapSubTLV
}

func (t *TunnelEncapTLV) DecodeFromBytes(data []byte) error {
	curr := 0
	for {
		if len(data) < curr+2 {
			break
		}
		subType := EncapSubTLVType(data[curr])
		l := int(data[curr+1])
		if len(data) < curr+2+l {
			return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Not all TunnelEncapSubTLV bytes available")
		}
		v := data[curr+2 : curr+2+l]
		subTlv := &TunnelEncapSubTLV{
			Type: subType,
		}
		err := subTlv.DecodeFromBytes(v)
		if err != nil {
			return err
		}
		t.Value = append(t.Value, subTlv)
		curr += 2 + l
	}
	return nil
}

func (p *TunnelEncapTLV) Serialize() ([]byte, error) {
	buf := make([]byte, 4)
	for _, s := range p.Value {
		bbuf, err := s.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, bbuf...)
	}
	binary.BigEndian.PutUint16(buf, uint16(p.Type))
	p.Len = len(buf) - 4
	binary.BigEndian.PutUint16(buf[2:], uint16(p.Len))
	return buf, nil
}

type PathAttributeTunnelEncap struct {
	PathAttribute
	Value []*TunnelEncapTLV
}

func (p *PathAttributeTunnelEncap) DecodeFromBytes(data []byte) error {
	err := p.PathAttribute.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	curr := 0
	for {
		if len(p.PathAttribute.Value) < curr+4 {
			break
		}
		t := binary.BigEndian.Uint16(p.PathAttribute.Value[curr : curr+2])
		tunnelType := TunnelType(t)
		l := int(binary.BigEndian.Uint16(p.PathAttribute.Value[curr+2 : curr+4]))
		if len(p.PathAttribute.Value) < curr+4+l {
			return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("Not all TunnelEncapTLV bytes available. %d < %d", len(p.PathAttribute.Value), curr+4+l))
		}
		v := p.PathAttribute.Value[curr+4 : curr+4+l]
		tlv := &TunnelEncapTLV{
			Type: tunnelType,
			Len:  l,
		}
		err = tlv.DecodeFromBytes(v)
		if err != nil {
			return err
		}
		p.Value = append(p.Value, tlv)
		curr += 4 + l
	}
	return nil
}

func (p *PathAttributeTunnelEncap) Serialize() ([]byte, error) {
	buf := make([]byte, 0)
	for _, t := range p.Value {
		bbuf, err := t.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, bbuf...)
	}
	p.PathAttribute.Value = buf
	return p.PathAttribute.Serialize()
}

func NewPathAttributeTunnelEncap(value []*TunnelEncapTLV) *PathAttributeTunnelEncap {
	t := BGP_ATTR_TYPE_TUNNEL_ENCAP
	return &PathAttributeTunnelEncap{
		PathAttribute: PathAttribute{
			Flags: PathAttrFlags[t],
			Type:  t,
		},
		Value: value,
	}
}

type PmsiTunnelIDInterface interface {
	Serialize() ([]byte, error)
	String() string
}

type DefaultPmsiTunnelID struct {
	Value []byte
}

func (i *DefaultPmsiTunnelID) Serialize() ([]byte, error) {
	return i.Value, nil
}

func (i *DefaultPmsiTunnelID) String() string {
	return string(i.Value)
}

type IngressReplTunnelID struct {
	Value net.IP
}

func (i *IngressReplTunnelID) Serialize() ([]byte, error) {
	if i.Value.To4() != nil {
		return []byte(i.Value.To4()), nil
	}
	return []byte(i.Value), nil
}

func (i *IngressReplTunnelID) String() string {
	return i.Value.String()
}

type PathAttributePmsiTunnel struct {
	PathAttribute
	IsLeafInfoRequired bool
	TunnelType         PmsiTunnelType
	Label              uint32
	TunnelID           PmsiTunnelIDInterface
}

func (p *PathAttributePmsiTunnel) DecodeFromBytes(data []byte) error {
	err := p.PathAttribute.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	if len(p.PathAttribute.Value) < 5 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST)
		return NewMessageError(eCode, eSubCode, nil, "PMSI Tunnel length is incorrect")
	}

	if (p.PathAttribute.Value[0] & 0x01) > 0 {
		p.IsLeafInfoRequired = true
	}
	p.TunnelType = PmsiTunnelType(p.PathAttribute.Value[1])
	p.Label = labelDecode(p.PathAttribute.Value[2:5])

	switch p.TunnelType {
	case PMSI_TUNNEL_TYPE_INGRESS_REPL:
		p.TunnelID = &IngressReplTunnelID{net.IP(p.PathAttribute.Value[5:])}
	default:
		p.TunnelID = &DefaultPmsiTunnelID{p.PathAttribute.Value[5:]}
	}
	return nil
}

func (p *PathAttributePmsiTunnel) Serialize() ([]byte, error) {
	buf := make([]byte, 2)
	if p.IsLeafInfoRequired {
		buf[0] = 0x01
	}
	buf[1] = byte(p.TunnelType)
	lbuf := make([]byte, 3)
	labelSerialize(p.Label, lbuf)
	buf = append(buf, lbuf...)
	ibuf, err := p.TunnelID.Serialize()
	if err != nil {
		return nil, err
	}
	buf = append(buf, ibuf...)
	p.PathAttribute.Value = buf
	return p.PathAttribute.Serialize()
}

func (p *PathAttributePmsiTunnel) String() string {
	buf := bytes.NewBuffer(make([]byte, 0, 32))
	buf.WriteString(fmt.Sprintf("{Pmsi: type: %s,", p.TunnelType))
	if p.IsLeafInfoRequired {
		buf.WriteString(" leaf-info-required,")
	}
	buf.WriteString(fmt.Sprintf(" label: %d, tunnel-id: %s}", p.Label, p.TunnelID))
	return buf.String()
}

func (p *PathAttributePmsiTunnel) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type               BGPAttrType `json:"type"`
		IsLeafInfoRequired bool        `json:"is-leaf-info-required"`
		TunnelType         uint8       `json:"tunnel-type"`
		Label              uint32      `json:"label"`
		TunnelID           string      `json:"tunnel-id"`
	}{
		Type:               p.Type,
		IsLeafInfoRequired: p.IsLeafInfoRequired,
		TunnelType:         uint8(p.TunnelType),
		Label:              p.Label,
		TunnelID:           p.TunnelID.String(),
	})
}

func NewPathAttributePmsiTunnel(typ PmsiTunnelType, isLeafInfoRequired bool, label uint32, id PmsiTunnelIDInterface) *PathAttributePmsiTunnel {
	t := BGP_ATTR_TYPE_PMSI_TUNNEL
	return &PathAttributePmsiTunnel{
		PathAttribute: PathAttribute{
			Flags: PathAttrFlags[t],
			Type:  t,
		},
		IsLeafInfoRequired: isLeafInfoRequired,
		TunnelType:         typ,
		Label:              label,
		TunnelID:           id,
	}
}

type AigpTLVType uint8

const (
	AIGP_TLV_UNKNOWN AigpTLVType = iota
	AIGP_TLV_IGP_METRIC
)

type AigpTLV interface {
	Serialize() ([]byte, error)
	String() string
	MarshalJSON() ([]byte, error)
	Type() AigpTLVType
}

type AigpTLVDefault struct {
	typ   AigpTLVType
	Value []byte
}

func (t *AigpTLVDefault) Serialize() ([]byte, error) {
	buf := make([]byte, 3+len(t.Value))
	buf[0] = uint8(t.Type())
	binary.BigEndian.PutUint16(buf[1:], uint16(3+len(t.Value)))
	copy(buf[3:], t.Value)
	return buf, nil
}

func (t *AigpTLVDefault) String() string {
	return fmt.Sprintf("{Type: %d, Value: %v}", t.Type(), t.Value)
}

func (t *AigpTLVDefault) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  AigpTLVType `json:"type"`
		Value []byte      `json:"value"`
	}{
		Type:  t.Type(),
		Value: t.Value,
	})
}

func (t *AigpTLVDefault) Type() AigpTLVType {
	return t.typ
}

type AigpTLVIgpMetric struct {
	Metric uint64
}

func (t *AigpTLVIgpMetric) Serialize() ([]byte, error) {
	buf := make([]byte, 11)
	buf[0] = uint8(AIGP_TLV_IGP_METRIC)
	binary.BigEndian.PutUint16(buf[1:], uint16(11))
	binary.BigEndian.PutUint64(buf[3:], t.Metric)
	return buf, nil
}

func (t *AigpTLVIgpMetric) String() string {
	return fmt.Sprintf("{Metric: %d}", t.Metric)
}

func (t *AigpTLVIgpMetric) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type   AigpTLVType `json:"type"`
		Metric uint64      `json:"metric"`
	}{
		Type:   AIGP_TLV_IGP_METRIC,
		Metric: t.Metric,
	})
}

func NewAigpTLVIgpMetric(metric uint64) *AigpTLVIgpMetric {
	return &AigpTLVIgpMetric{
		Metric: metric,
	}
}

func (t *AigpTLVIgpMetric) Type() AigpTLVType {
	return AIGP_TLV_IGP_METRIC
}

type PathAttributeIP6ExtendedCommunities struct {
	PathAttribute
	Value []ExtendedCommunityInterface
}

func ParseIP6Extended(data []byte) (ExtendedCommunityInterface, error) {
	if len(data) < 8 {
		return nil, NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "not all extended community bytes are available")
	}
	attrType := ExtendedCommunityAttrType(data[0])
	subtype := ExtendedCommunityAttrSubType(data[1])
	transitive := false
	switch attrType {
	case EC_TYPE_TRANSITIVE_IP6_SPECIFIC:
		transitive = true
		fallthrough
	case EC_TYPE_NON_TRANSITIVE_IP6_SPECIFIC:
		ipv6 := net.IP(data[2:18]).String()
		localAdmin := binary.BigEndian.Uint16(data[18:20])
		return NewIPv6AddressSpecificExtended(subtype, ipv6, localAdmin, transitive), nil
	case EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL:
		return parseIP6FlowSpecExtended(data)
	default:
		return &UnknownExtended{
			Type:  ExtendedCommunityAttrType(data[0]),
			Value: data[1:8],
		}, nil
	}
}

func (p *PathAttributeIP6ExtendedCommunities) DecodeFromBytes(data []byte) error {
	err := p.PathAttribute.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	if len(p.PathAttribute.Value)%20 != 0 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)
		return NewMessageError(eCode, eSubCode, nil, "extendedcommunities length isn't correct")
	}
	value := p.PathAttribute.Value
	for len(value) >= 20 {
		e, err := ParseIP6Extended(value)
		if err != nil {
			return err
		}
		p.Value = append(p.Value, e)
		value = value[20:]
	}
	return nil
}

func (p *PathAttributeIP6ExtendedCommunities) Serialize() ([]byte, error) {
	buf := make([]byte, 0)
	for _, p := range p.Value {
		ebuf, err := p.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, ebuf...)
	}
	p.PathAttribute.Value = buf
	return p.PathAttribute.Serialize()
}

func (p *PathAttributeIP6ExtendedCommunities) String() string {
	var buf []string
	for _, v := range p.Value {
		buf = append(buf, fmt.Sprintf("[%s]", v.String()))
	}
	return fmt.Sprintf("{Extcomms: %s}", strings.Join(buf, ","))
}

func (p *PathAttributeIP6ExtendedCommunities) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPAttrType                  `json:"type"`
		Value []ExtendedCommunityInterface `json:"value"`
	}{
		Type:  p.GetType(),
		Value: p.Value,
	})
}

func NewPathAttributeIP6ExtendedCommunities(value []ExtendedCommunityInterface) *PathAttributeIP6ExtendedCommunities {
	t := BGP_ATTR_TYPE_IP6_EXTENDED_COMMUNITIES
	return &PathAttributeIP6ExtendedCommunities{
		PathAttribute: PathAttribute{
			Flags: PathAttrFlags[t],
			Type:  t,
		},
		Value: value,
	}
}

type PathAttributeAigp struct {
	PathAttribute
	Values []AigpTLV
}

func (p *PathAttributeAigp) DecodeFromBytes(data []byte) error {
	err := p.PathAttribute.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	rest := p.PathAttribute.Value
	values := make([]AigpTLV, 0)

	for {
		if len(rest) < 3 {
			break
		}
		typ := rest[0]
		length := binary.BigEndian.Uint16(rest[1:3])
		if len(rest) < int(length) {
			break
		}
		v := rest[3:length]
		switch AigpTLVType(typ) {
		case AIGP_TLV_IGP_METRIC:
			if len(v) < 8 {
				break
			}
			metric := binary.BigEndian.Uint64(v)
			values = append(values, NewAigpTLVIgpMetric(metric))
		default:
			values = append(values, &AigpTLVDefault{AigpTLVType(typ), v})
		}
		rest = rest[length:]
		if len(rest) == 0 {
			p.Values = values
			return nil
		}
	}
	eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
	eSubCode := uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST)
	return NewMessageError(eCode, eSubCode, nil, "Aigp length is incorrect")
}

func (p *PathAttributeAigp) Serialize() ([]byte, error) {
	buf := make([]byte, 0)
	for _, t := range p.Values {
		bbuf, err := t.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, bbuf...)
	}
	p.PathAttribute.Value = buf
	return p.PathAttribute.Serialize()
}

func (p *PathAttributeAigp) String() string {
	buf := bytes.NewBuffer(make([]byte, 0, 32))
	buf.WriteString("{Aigp: [")
	for _, v := range p.Values {
		buf.WriteString(v.String())
	}
	buf.WriteString("]}")
	return buf.String()
}

func (p *PathAttributeAigp) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPAttrType `json:"type"`
		Value []AigpTLV   `json:"value"`
	}{
		Type:  p.GetType(),
		Value: p.Values,
	})
}

func NewPathAttributeAigp(values []AigpTLV) *PathAttributeAigp {
	t := BGP_ATTR_TYPE_AIGP
	return &PathAttributeAigp{
		PathAttribute: PathAttribute{
			Flags: PathAttrFlags[t],
			Type:  t,
		},
		Values: values,
	}
}

type LargeCommunity struct {
	ASN        uint32
	LocalData1 uint32
	LocalData2 uint32
}

func (c *LargeCommunity) Serialize() ([]byte, error) {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint32(buf, c.ASN)
	binary.BigEndian.PutUint32(buf[4:], c.LocalData1)
	binary.BigEndian.PutUint32(buf[8:], c.LocalData2)
	return buf, nil
}

func (c *LargeCommunity) String() string {
	return fmt.Sprintf("%d:%d:%d", c.ASN, c.LocalData1, c.LocalData2)
}

func NewLargeCommunity(asn, data1, data2 uint32) *LargeCommunity {
	return &LargeCommunity{
		ASN:        asn,
		LocalData1: data1,
		LocalData2: data2,
	}
}

func ParseLargeCommunity(value string) (*LargeCommunity, error) {
	elems := strings.Split(value, ":")
	if len(elems) != 3 {
		return nil, fmt.Errorf("invalid large community format")
	}
	v := make([]uint32, 0, 3)
	for _, elem := range elems {
		e, err := strconv.ParseUint(elem, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid large community format")
		}
		v = append(v, uint32(e))
	}
	return NewLargeCommunity(v[0], v[1], v[2]), nil
}

type PathAttributeLargeCommunities struct {
	PathAttribute
	Values []*LargeCommunity
}

func (p *PathAttributeLargeCommunities) DecodeFromBytes(data []byte) error {
	err := p.PathAttribute.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	rest := p.PathAttribute.Value

	if len(rest)%12 != 0 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)
		return NewMessageError(eCode, eSubCode, nil, "large communities length isn't correct")
	}

	p.Values = make([]*LargeCommunity, 0, len(rest)/12)

	for len(rest) >= 12 {
		asn := binary.BigEndian.Uint32(rest[:4])
		data1 := binary.BigEndian.Uint32(rest[4:8])
		data2 := binary.BigEndian.Uint32(rest[8:12])
		p.Values = append(p.Values, NewLargeCommunity(asn, data1, data2))
		rest = rest[12:]
	}
	return nil
}

func (p *PathAttributeLargeCommunities) Serialize() ([]byte, error) {
	buf := make([]byte, 0)
	for _, t := range p.Values {
		bbuf, err := t.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, bbuf...)
	}
	p.PathAttribute.Value = buf
	return p.PathAttribute.Serialize()
}

func (p *PathAttributeLargeCommunities) String() string {
	buf := bytes.NewBuffer(make([]byte, 0, 32))
	buf.WriteString("{LargeCommunity: [ ")
	ss := []string{}
	for _, v := range p.Values {
		ss = append(ss, v.String())
	}
	buf.WriteString(strings.Join(ss, ", "))
	buf.WriteString("]}")
	return buf.String()
}

func (p *PathAttributeLargeCommunities) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPAttrType       `json:"type"`
		Value []*LargeCommunity `json:"value"`
	}{
		Type:  p.GetType(),
		Value: p.Values,
	})
}

func NewPathAttributeLargeCommunities(values []*LargeCommunity) *PathAttributeLargeCommunities {
	t := BGP_ATTR_TYPE_LARGE_COMMUNITY
	return &PathAttributeLargeCommunities{
		PathAttribute: PathAttribute{
			Flags: PathAttrFlags[t],
			Type:  t,
		},
		Values: values,
	}
}

type PathAttributeUnknown struct {
	PathAttribute
}

func GetPathAttribute(data []byte) (PathAttributeInterface, error) {
	if len(data) < 2 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)
		return nil, NewMessageError(eCode, eSubCode, data, "attribute type length is short")
	}
	switch BGPAttrType(data[1]) {
	case BGP_ATTR_TYPE_ORIGIN:
		return &PathAttributeOrigin{}, nil
	case BGP_ATTR_TYPE_AS_PATH:
		return &PathAttributeAsPath{}, nil
	case BGP_ATTR_TYPE_NEXT_HOP:
		return &PathAttributeNextHop{}, nil
	case BGP_ATTR_TYPE_MULTI_EXIT_DISC:
		return &PathAttributeMultiExitDisc{}, nil
	case BGP_ATTR_TYPE_LOCAL_PREF:
		return &PathAttributeLocalPref{}, nil
	case BGP_ATTR_TYPE_ATOMIC_AGGREGATE:
		return &PathAttributeAtomicAggregate{}, nil
	case BGP_ATTR_TYPE_AGGREGATOR:
		return &PathAttributeAggregator{}, nil
	case BGP_ATTR_TYPE_COMMUNITIES:
		return &PathAttributeCommunities{}, nil
	case BGP_ATTR_TYPE_ORIGINATOR_ID:
		return &PathAttributeOriginatorId{}, nil
	case BGP_ATTR_TYPE_CLUSTER_LIST:
		return &PathAttributeClusterList{}, nil
	case BGP_ATTR_TYPE_MP_REACH_NLRI:
		return &PathAttributeMpReachNLRI{}, nil
	case BGP_ATTR_TYPE_MP_UNREACH_NLRI:
		return &PathAttributeMpUnreachNLRI{}, nil
	case BGP_ATTR_TYPE_EXTENDED_COMMUNITIES:
		return &PathAttributeExtendedCommunities{}, nil
	case BGP_ATTR_TYPE_AS4_PATH:
		return &PathAttributeAs4Path{}, nil
	case BGP_ATTR_TYPE_AS4_AGGREGATOR:
		return &PathAttributeAs4Aggregator{}, nil
	case BGP_ATTR_TYPE_TUNNEL_ENCAP:
		return &PathAttributeTunnelEncap{}, nil
	case BGP_ATTR_TYPE_PMSI_TUNNEL:
		return &PathAttributePmsiTunnel{}, nil
	case BGP_ATTR_TYPE_IP6_EXTENDED_COMMUNITIES:
		return &PathAttributeIP6ExtendedCommunities{}, nil
	case BGP_ATTR_TYPE_AIGP:
		return &PathAttributeAigp{}, nil
	case BGP_ATTR_TYPE_LARGE_COMMUNITY:
		return &PathAttributeLargeCommunities{}, nil
	}
	return &PathAttributeUnknown{}, nil
}

type BGPUpdate struct {
	WithdrawnRoutesLen    uint16
	WithdrawnRoutes       []*IPAddrPrefix
	TotalPathAttributeLen uint16
	PathAttributes        []PathAttributeInterface
	NLRI                  []*IPAddrPrefix
}

func (msg *BGPUpdate) DecodeFromBytes(data []byte) error {

	// cache error codes
	eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
	eSubCode := uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST)

	// check withdrawn route length
	if len(data) < 2 {
		return NewMessageError(eCode, eSubCode, nil, "message length isn't enough for withdrawn route length")
	}

	msg.WithdrawnRoutesLen = binary.BigEndian.Uint16(data[0:2])
	data = data[2:]

	// check withdrawn route
	if len(data) < int(msg.WithdrawnRoutesLen) {
		return NewMessageError(eCode, eSubCode, nil, "withdrawn route length exceeds message length")
	}

	msg.WithdrawnRoutes = make([]*IPAddrPrefix, 0, msg.WithdrawnRoutesLen)
	for routelen := msg.WithdrawnRoutesLen; routelen > 0; {
		w := &IPAddrPrefix{}
		err := w.DecodeFromBytes(data)
		if err != nil {
			return err
		}
		routelen -= uint16(w.Len())
		if len(data) < w.Len() {
			return NewMessageError(eCode, eSubCode, nil, "Withdrawn route length is short")
		}
		data = data[w.Len():]
		msg.WithdrawnRoutes = append(msg.WithdrawnRoutes, w)
	}

	// check path total attribute length
	if len(data) < 2 {
		return NewMessageError(eCode, eSubCode, nil, "message length isn't enough for path total attribute length")
	}

	msg.TotalPathAttributeLen = binary.BigEndian.Uint16(data[0:2])
	data = data[2:]

	// check path attribute
	if len(data) < int(msg.TotalPathAttributeLen) {
		return NewMessageError(eCode, eSubCode, nil, "path total attribute length exceeds message length")
	}

	msg.PathAttributes = []PathAttributeInterface{}
	for pathlen := msg.TotalPathAttributeLen; pathlen > 0; {
		p, err := GetPathAttribute(data)
		if err != nil {
			return err
		}
		err = p.DecodeFromBytes(data)
		if err != nil {
			return err
		}
		pathlen -= uint16(p.Len())
		if len(data) < p.Len() {
			return NewMessageError(eCode, BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR, data, "attribute length is short")
		}
		data = data[p.Len():]
		msg.PathAttributes = append(msg.PathAttributes, p)
	}

	msg.NLRI = make([]*IPAddrPrefix, 0)
	for restlen := len(data); restlen > 0; {
		n := &IPAddrPrefix{}
		err := n.DecodeFromBytes(data)
		if err != nil {
			return err
		}
		restlen -= n.Len()
		if len(data) < n.Len() {
			return NewMessageError(eCode, BGP_ERROR_SUB_INVALID_NETWORK_FIELD, nil, "NLRI length is short")
		}
		data = data[n.Len():]
		msg.NLRI = append(msg.NLRI, n)
	}

	return nil
}

func (msg *BGPUpdate) Serialize() ([]byte, error) {
	wbuf := make([]byte, 2)
	for _, w := range msg.WithdrawnRoutes {
		onewbuf, err := w.Serialize()
		if err != nil {
			return nil, err
		}
		wbuf = append(wbuf, onewbuf...)
	}
	msg.WithdrawnRoutesLen = uint16(len(wbuf) - 2)
	binary.BigEndian.PutUint16(wbuf, msg.WithdrawnRoutesLen)

	pbuf := make([]byte, 2)
	for _, p := range msg.PathAttributes {
		onepbuf, err := p.Serialize()
		if err != nil {
			return nil, err
		}
		pbuf = append(pbuf, onepbuf...)
	}
	msg.TotalPathAttributeLen = uint16(len(pbuf) - 2)
	binary.BigEndian.PutUint16(pbuf, msg.TotalPathAttributeLen)

	buf := append(wbuf, pbuf...)
	for _, n := range msg.NLRI {
		nbuf, err := n.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, nbuf...)
	}
	return buf, nil
}

func (msg *BGPUpdate) IsEndOfRib() (bool, RouteFamily) {
	if len(msg.WithdrawnRoutes) == 0 && len(msg.NLRI) == 0 {
		if len(msg.PathAttributes) == 0 {
			return true, RF_IPv4_UC
		} else if len(msg.PathAttributes) == 1 && msg.PathAttributes[0].GetType() == BGP_ATTR_TYPE_MP_UNREACH_NLRI {
			unreach := msg.PathAttributes[0].(*PathAttributeMpUnreachNLRI)
			if len(unreach.Value) == 0 {
				return true, AfiSafiToRouteFamily(unreach.AFI, unreach.SAFI)
			}
		}
	}
	return false, RouteFamily(0)
}

func NewBGPUpdateMessage(withdrawnRoutes []*IPAddrPrefix, pathattrs []PathAttributeInterface, nlri []*IPAddrPrefix) *BGPMessage {
	return &BGPMessage{
		Header: BGPHeader{Type: BGP_MSG_UPDATE},
		Body:   &BGPUpdate{0, withdrawnRoutes, 0, pathattrs, nlri},
	}
}

func NewEndOfRib(family RouteFamily) *BGPMessage {
	if family == RF_IPv4_UC {
		return NewBGPUpdateMessage(nil, nil, nil)
	} else {
		afi, safi := RouteFamilyToAfiSafi(family)
		t := BGP_ATTR_TYPE_MP_UNREACH_NLRI
		unreach := &PathAttributeMpUnreachNLRI{
			PathAttribute: PathAttribute{
				Flags:  PathAttrFlags[t],
				Type:   t,
				Length: 3,
			},
			AFI:  afi,
			SAFI: safi,
		}
		return NewBGPUpdateMessage(nil, []PathAttributeInterface{unreach}, nil)
	}
}

type BGPNotification struct {
	ErrorCode    uint8
	ErrorSubcode uint8
	Data         []byte
}

func (msg *BGPNotification) DecodeFromBytes(data []byte) error {
	if len(data) < 2 {
		return NewMessageError(BGP_ERROR_MESSAGE_HEADER_ERROR, BGP_ERROR_SUB_BAD_MESSAGE_LENGTH, nil, "Not all Notificaiton bytes available")
	}
	msg.ErrorCode = data[0]
	msg.ErrorSubcode = data[1]
	if len(data) > 2 {
		msg.Data = data[2:]
	}
	return nil
}

func (msg *BGPNotification) Serialize() ([]byte, error) {
	buf := make([]byte, 2)
	buf[0] = msg.ErrorCode
	buf[1] = msg.ErrorSubcode
	buf = append(buf, msg.Data...)
	return buf, nil
}

func NewBGPNotificationMessage(errcode uint8, errsubcode uint8, data []byte) *BGPMessage {
	return &BGPMessage{
		Header: BGPHeader{Type: BGP_MSG_NOTIFICATION},
		Body:   &BGPNotification{errcode, errsubcode, data},
	}
}

type BGPKeepAlive struct {
}

func (msg *BGPKeepAlive) DecodeFromBytes(data []byte) error {
	return nil
}

func (msg *BGPKeepAlive) Serialize() ([]byte, error) {
	return nil, nil
}

func NewBGPKeepAliveMessage() *BGPMessage {
	return &BGPMessage{
		Header: BGPHeader{Len: 19, Type: BGP_MSG_KEEPALIVE},
		Body:   &BGPKeepAlive{},
	}
}

type BGPRouteRefresh struct {
	AFI         uint16
	Demarcation uint8
	SAFI        uint8
}

func (msg *BGPRouteRefresh) DecodeFromBytes(data []byte) error {
	if len(data) < 4 {
		return NewMessageError(BGP_ERROR_ROUTE_REFRESH_MESSAGE_ERROR, BGP_ERROR_SUB_INVALID_MESSAGE_LENGTH, nil, "Not all RouteRefresh bytes available")
	}
	msg.AFI = binary.BigEndian.Uint16(data[0:2])
	msg.Demarcation = data[2]
	msg.SAFI = data[3]
	return nil
}

func (msg *BGPRouteRefresh) Serialize() ([]byte, error) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint16(buf[0:2], msg.AFI)
	buf[2] = msg.Demarcation
	buf[3] = msg.SAFI
	return buf, nil
}

func NewBGPRouteRefreshMessage(afi uint16, demarcation uint8, safi uint8) *BGPMessage {
	return &BGPMessage{
		Header: BGPHeader{Type: BGP_MSG_ROUTE_REFRESH},
		Body:   &BGPRouteRefresh{afi, demarcation, safi},
	}
}

type BGPBody interface {
	DecodeFromBytes([]byte) error
	Serialize() ([]byte, error)
}

const (
	BGP_HEADER_LENGTH      = 19
	BGP_MAX_MESSAGE_LENGTH = 4096
)

type BGPHeader struct {
	Marker []byte
	Len    uint16
	Type   uint8
}

func (msg *BGPHeader) DecodeFromBytes(data []byte) error {
	// minimum BGP message length
	if uint16(len(data)) < BGP_HEADER_LENGTH {
		return NewMessageError(BGP_ERROR_MESSAGE_HEADER_ERROR, BGP_ERROR_SUB_BAD_MESSAGE_LENGTH, nil, "not all BGP message header")
	}
	msg.Len = binary.BigEndian.Uint16(data[16:18])
	if int(msg.Len) < BGP_HEADER_LENGTH {
		return NewMessageError(BGP_ERROR_MESSAGE_HEADER_ERROR, BGP_ERROR_SUB_BAD_MESSAGE_LENGTH, nil, "unknown message type")
	}
	msg.Type = data[18]
	return nil
}

func (msg *BGPHeader) Serialize() ([]byte, error) {
	buf := make([]byte, 19)
	for i := range buf[:16] {
		buf[i] = 0xff
	}
	binary.BigEndian.PutUint16(buf[16:18], msg.Len)
	buf[18] = msg.Type
	return buf, nil
}

type BGPMessage struct {
	Header BGPHeader
	Body   BGPBody
}

func parseBody(h *BGPHeader, data []byte) (*BGPMessage, error) {
	if len(data) < int(h.Len)-BGP_HEADER_LENGTH {
		return nil, NewMessageError(BGP_ERROR_MESSAGE_HEADER_ERROR, BGP_ERROR_SUB_BAD_MESSAGE_LENGTH, nil, "Not all BGP message bytes available")
	}
	msg := &BGPMessage{Header: *h}

	switch msg.Header.Type {
	case BGP_MSG_OPEN:
		msg.Body = &BGPOpen{}
	case BGP_MSG_UPDATE:
		msg.Body = &BGPUpdate{}
	case BGP_MSG_NOTIFICATION:
		msg.Body = &BGPNotification{}
	case BGP_MSG_KEEPALIVE:
		msg.Body = &BGPKeepAlive{}
	case BGP_MSG_ROUTE_REFRESH:
		msg.Body = &BGPRouteRefresh{}
	default:
		return nil, NewMessageError(BGP_ERROR_MESSAGE_HEADER_ERROR, BGP_ERROR_SUB_BAD_MESSAGE_TYPE, nil, "unknown message type")
	}
	err := msg.Body.DecodeFromBytes(data)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func ParseBGPMessage(data []byte) (*BGPMessage, error) {
	h := &BGPHeader{}
	err := h.DecodeFromBytes(data)
	if err != nil {
		return nil, err
	}
	return parseBody(h, data[19:h.Len])
}

func ParseBGPBody(h *BGPHeader, data []byte) (*BGPMessage, error) {
	return parseBody(h, data)
}

func (msg *BGPMessage) Serialize() ([]byte, error) {
	b, err := msg.Body.Serialize()
	if err != nil {
		return nil, err
	}
	if msg.Header.Len == 0 {
		if 19+len(b) > BGP_MAX_MESSAGE_LENGTH {
			return nil, NewMessageError(0, 0, nil, fmt.Sprintf("too long message length %d", 19+len(b)))
		}
		msg.Header.Len = 19 + uint16(len(b))
	}
	h, err := msg.Header.Serialize()
	if err != nil {
		return nil, err
	}
	return append(h, b...), nil
}

type MessageError struct {
	TypeCode    uint8
	SubTypeCode uint8
	Data        []byte
	Message     string
}

func NewMessageError(typeCode, subTypeCode uint8, data []byte, msg string) error {
	return &MessageError{
		TypeCode:    typeCode,
		SubTypeCode: subTypeCode,
		Data:        data,
		Message:     msg,
	}
}

func (e *MessageError) Error() string {
	return e.Message
}

func (e *TwoOctetAsSpecificExtended) Flat() map[string]string {
	if e.SubType == EC_SUBTYPE_ROUTE_TARGET {
		return map[string]string{"routeTarget": e.String()}
	}
	return map[string]string{}
}

func (e *OpaqueExtended) Flat() map[string]string {
	if e.SubType == EC_SUBTYPE_ENCAPSULATION {
		return map[string]string{"encaspulation": e.Value.String()}
	}
	return map[string]string{}
}

func (e *IPv4AddressSpecificExtended) Flat() map[string]string {
	return map[string]string{}
}

func (e *IPv6AddressSpecificExtended) Flat() map[string]string {
	return map[string]string{}
}

func (e *FourOctetAsSpecificExtended) Flat() map[string]string {
	return map[string]string{}
}

func (e *ESILabelExtended) Flat() map[string]string {
	return map[string]string{}
}

func (e *ESImportRouteTarget) Flat() map[string]string {
	return map[string]string{}
}

func (e *MacMobilityExtended) Flat() map[string]string {
	return map[string]string{}
}

func (e *TrafficRateExtended) Flat() map[string]string {
	return map[string]string{}
}

func (e *TrafficRemarkExtended) Flat() map[string]string {
	return map[string]string{}
}

func (e *RedirectIPv4AddressSpecificExtended) Flat() map[string]string {
	return map[string]string{}
}

func (e *RedirectIPv6AddressSpecificExtended) Flat() map[string]string {
	return map[string]string{}
}

func (e *RedirectFourOctetAsSpecificExtended) Flat() map[string]string {
	return map[string]string{}
}

func (e *UnknownExtended) Flat() map[string]string {
	return map[string]string{}
}

func (e *TrafficActionExtended) Flat() map[string]string {
	return map[string]string{}
}

func (p *PathAttributeExtendedCommunities) Flat() map[string]string {
	flat := map[string]string{}
	for _, ec := range p.Value {
		FlatUpdate(flat, ec.Flat())
	}
	return flat
}

func (p *PathAttribute) Flat() map[string]string {
	return map[string]string{}
}

func (l *LabeledVPNIPAddrPrefix) Flat() map[string]string {
	prefixLen := l.IPAddrPrefixDefault.Length - uint8(8*(l.Labels.Len()+l.RD.Len()))
	return map[string]string{
		"Prefix":    l.IPAddrPrefixDefault.Prefix.String(),
		"PrefixLen": fmt.Sprintf("%d", prefixLen),
		"NLRI":      l.String(),
		"Label":     l.Labels.String(),
	}
}

func (p *IPAddrPrefixDefault) Flat() map[string]string {
	l := strings.Split(p.String(), "/")
	if len(l) == 2 {
		return map[string]string{
			"Prefix":    l[0],
			"PrefixLen": l[1],
		}
	}
	return map[string]string{}
}

func (l *EVPNNLRI) Flat() map[string]string {
	return map[string]string{}
}
func (l *RouteTargetMembershipNLRI) Flat() map[string]string {
	return map[string]string{}
}
func (l *FlowSpecIPv4Unicast) Flat() map[string]string {
	return map[string]string{}
}
func (l *FlowSpecIPv4VPN) Flat() map[string]string {
	return map[string]string{}
}
func (l *FlowSpecIPv6Unicast) Flat() map[string]string {
	return map[string]string{}
}
func (l *FlowSpecIPv6VPN) Flat() map[string]string {
	return map[string]string{}
}
func (l *FlowSpecL2VPN) Flat() map[string]string {
	return map[string]string{}
}
func (l *OpaqueNLRI) Flat() map[string]string {
	return map[string]string{}
}

// Update a Flat representation by adding elements of the second
// one. If two elements use same keys, values are separated with
// ';'. In this case, it returns an error but the update has been
// realized.
func FlatUpdate(f1, f2 map[string]string) error {
	conflict := false
	for k2, v2 := range f2 {
		if v1, ok := f1[k2]; ok {
			f1[k2] = v1 + ";" + v2
			conflict = true
		} else {
			f1[k2] = v2
		}
	}
	if conflict {
		return fmt.Errorf("Keys conflict")
	} else {
		return nil
	}
}
