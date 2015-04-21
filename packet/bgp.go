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
	"errors"
	"fmt"
	"github.com/osrg/gobgp/api"
	"math"
	"net"
	"reflect"
	"strings"
)

const (
	AFI_IP    = 1
	AFI_IP6   = 2
	AFI_L2VPN = 25
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
	SAFI_ROUTE_TARGET_CONSTRTAINS = 132
)

const (
	BGP_ORIGIN_ATTR_TYPE_IGP        = 0
	BGP_ORIGIN_ATTR_TYPE_EGP        = 1
	BGP_ORIGIN_ATTR_TYPE_INCOMPLETE = 2
)

const (
	BGP_ASPATH_ATTR_TYPE_SET = 1
	BGP_ASPATH_ATTR_TYPE_SEQ = 2
)

// RFC7153 5.1. Registries for the "Type" Field
// RANGE	REGISTRACTION PROCEDURES
// 0x00-0x3F	Transitive First Come First Served
// 0x40-0x7F	Non-Transitive First Come First Served
// 0x80-0x8F	Transitive Experimental Use
// 0x90-0xBF	Transitive Standards Action
// 0xC0-0xCF	Non-Transitive Experimental Use
// 0xD0-0xFF	Non-Transitive Standards Action
type ExtendedCommunityAttrType uint8

const (
	EC_TYPE_TRANSITIVE_TWO_OCTET_AS_SPECIFIC      ExtendedCommunityAttrType = 0x00
	EC_TYPE_TRANSITIVE_IP4_SPECIFIC               ExtendedCommunityAttrType = 0x01
	EC_TYPE_TRANSITIVE_FOUR_OCTET_AS_SPECIFIC     ExtendedCommunityAttrType = 0x02
	EC_TYPE_TRANSITIVE_OPAQUE                     ExtendedCommunityAttrType = 0x03
	EC_TYPE_TRANSITIVE_QOS_MARKING                ExtendedCommunityAttrType = 0x04
	EC_TYPE_COS_CAPABILITY                        ExtendedCommunityAttrType = 0x05
	EC_TYPE_EVPN                                  ExtendedCommunityAttrType = 0x06
	EC_TYPE_FLOWSPEC_REDIRECT_MIRROR              ExtendedCommunityAttrType = 0x08
	EC_TYPE_NON_TRANSITIVE_TWO_OCTET_AS_SPECIFIC  ExtendedCommunityAttrType = 0x40
	EC_TYPE_NON_TRANSITIVE_IP4_SPECIFIC           ExtendedCommunityAttrType = 0x41
	EC_TYPE_NON_TRANSITIVE_FOUR_OCTET_AS_SPECIFIC ExtendedCommunityAttrType = 0x42
	EC_TYPE_NON_TRANSITIVE_OPAQUE                 ExtendedCommunityAttrType = 0x43
	EC_TYPE_NON_TRANSITIVE_QOS_MARKING            ExtendedCommunityAttrType = 0x44
	EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL       ExtendedCommunityAttrType = 0x80
)

// RFC7153 5.2. Registraction for the "Sub-Type" Field
// RANGE	REGISTRACTION PROCEDURES
// 0x00-0xBF	First Come First Served
// 0xC0-0xFF	IETF Review
type ExtendedCommunityAttrSubType uint8

const (
	EC_SUBTYPE_ORIGIN_VALIDATION       ExtendedCommunityAttrSubType = 0x00
	EC_SUBTYPE_ROUTE_TARGET            ExtendedCommunityAttrSubType = 0x02
	EC_SUBTYPE_ROUTE_ORIGIN            ExtendedCommunityAttrSubType = 0x03
	EC_SUBTYPE_LINK_BANDWIDTH          ExtendedCommunityAttrSubType = 0x04
	EC_SUBTYPE_GENERIC                 ExtendedCommunityAttrSubType = 0x04
	EC_SUBTYPE_OSPF_DOMAIN_ID          ExtendedCommunityAttrSubType = 0x05
	EC_SUBTYPE_OSPF_ROUTE_TYPE         ExtendedCommunityAttrSubType = 0x06
	EC_SUBTYPE_OSPF_ROUTE_ID           ExtendedCommunityAttrSubType = 0x07
	EC_SUBTYPE_BGP_DATA_COLLECTION     ExtendedCommunityAttrSubType = 0x08
	EC_SUBTYPE_SOURCE_AS               ExtendedCommunityAttrSubType = 0x09
	EC_SUBTYPE_L2VPN_ID                ExtendedCommunityAttrSubType = 0x0A
	EC_SUBTYPE_L2_INFO                 ExtendedCommunityAttrSubType = 0x0A
	EC_SUBTYPE_VRF_ROUTE_IMPORT        ExtendedCommunityAttrSubType = 0x0B
	EC_SUBTYPE_COLOR                   ExtendedCommunityAttrSubType = 0x0B
	EC_SUBTYPE_ENCAPSULATION           ExtendedCommunityAttrSubType = 0x0C
	EC_SUBTYPE_DEFAULT_GATEWAY         ExtendedCommunityAttrSubType = 0x0D
	EC_SUBTYPE_CISCO_VPN_DISTINGUISHER ExtendedCommunityAttrSubType = 0x10
	EC_SUBTYPE_UUID_BASED_RT           ExtendedCommunityAttrSubType = 0x11

	EC_SUBTYPE_FLOWSPEC_TRAFFIC_RATE   ExtendedCommunityAttrSubType = 0x06
	EC_SUBTYPE_FLOWSPEC_TRAFFIC_ACTION ExtendedCommunityAttrSubType = 0x07
	EC_SUBTYPE_FLOWSPEC_REDIRECT       ExtendedCommunityAttrSubType = 0x08
	EC_SUBTYPE_FLOWSPEC_TRAFFIC_REMARK ExtendedCommunityAttrSubType = 0x09

	EC_SUBTYPE_MAC_MOBILITY   ExtendedCommunityAttrSubType = 0x00
	EC_SUBTYPE_ESI_MPLS_LABEL ExtendedCommunityAttrSubType = 0x01
	EC_SUBTYPE_ES_IMPORT      ExtendedCommunityAttrSubType = 0x02
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
)

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
	BGP_CAP_MULTIPROTOCOL          BGPCapabilityCode = 1
	BGP_CAP_ROUTE_REFRESH          BGPCapabilityCode = 2
	BGP_CAP_CARRYING_LABEL_INFO    BGPCapabilityCode = 4
	BGP_CAP_GRACEFUL_RESTART       BGPCapabilityCode = 64
	BGP_CAP_FOUR_OCTET_AS_NUMBER   BGPCapabilityCode = 65
	BGP_CAP_ENHANCED_ROUTE_REFRESH BGPCapabilityCode = 70
	BGP_CAP_ROUTE_REFRESH_CISCO    BGPCapabilityCode = 128
)

type ParameterCapabilityInterface interface {
	DecodeFromBytes([]byte) error
	Serialize() ([]byte, error)
	Len() int
	Code() BGPCapabilityCode
}

type DefaultParameterCapability struct {
	CapCode  BGPCapabilityCode
	CapLen   uint8
	CapValue []byte
}

func (c *DefaultParameterCapability) Code() BGPCapabilityCode {
	return c.CapCode
}

func (c *DefaultParameterCapability) DecodeFromBytes(data []byte) error {
	c.CapCode = BGPCapabilityCode(data[0])
	c.CapLen = data[1]
	if len(data) < 2+int(c.CapLen) {
		return fmt.Errorf("Not all OptionParameterCapability bytes available")
	}
	c.CapValue = data[2 : 2+c.CapLen]
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

type CapMultiProtocolValue struct {
	AFI  uint16
	SAFI uint8
}

type CapMultiProtocol struct {
	DefaultParameterCapability
	CapValue CapMultiProtocolValue
}

func (c *CapMultiProtocol) DecodeFromBytes(data []byte) error {
	c.DefaultParameterCapability.DecodeFromBytes(data)
	data = data[2:]
	if len(data) < 4 {
		return fmt.Errorf("Not all CapabilityMultiProtocol bytes available")
	}
	c.CapValue.AFI = binary.BigEndian.Uint16(data[0:2])
	c.CapValue.SAFI = data[3]
	return nil
}

func (c *CapMultiProtocol) Serialize() ([]byte, error) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint16(buf[0:], c.CapValue.AFI)
	buf[3] = c.CapValue.SAFI
	c.DefaultParameterCapability.CapValue = buf
	return c.DefaultParameterCapability.Serialize()
}

func NewCapMultiProtocol(afi uint16, safi uint8) *CapMultiProtocol {
	return &CapMultiProtocol{
		DefaultParameterCapability{
			CapCode: BGP_CAP_MULTIPROTOCOL,
		},
		CapMultiProtocolValue{
			AFI:  afi,
			SAFI: safi,
		},
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

type CapGracefulRestartTuples struct {
	AFI   uint16
	SAFI  uint8
	Flags uint8
}

type CapGracefulRestartValue struct {
	Flags  uint8
	Time   uint16
	Tuples []CapGracefulRestartTuples
}

type CapGracefulRestart struct {
	DefaultParameterCapability
	CapValue CapGracefulRestartValue
}

func (c *CapGracefulRestart) DecodeFromBytes(data []byte) error {
	c.DefaultParameterCapability.DecodeFromBytes(data)
	data = data[2:]
	restart := binary.BigEndian.Uint16(data[0:2])
	c.CapValue.Flags = uint8(restart >> 12)
	c.CapValue.Time = restart & 0xfff
	data = data[2:]
	for len(data) >= 4 {
		t := CapGracefulRestartTuples{binary.BigEndian.Uint16(data[0:2]),
			data[2], data[3]}
		c.CapValue.Tuples = append(c.CapValue.Tuples, t)
		data = data[4:]
	}
	return nil
}

func (c *CapGracefulRestart) Serialize() ([]byte, error) {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf[0:], uint16(c.CapValue.Flags)<<12|c.CapValue.Time)
	for _, t := range c.CapValue.Tuples {
		tbuf := make([]byte, 4)
		binary.BigEndian.PutUint16(tbuf[0:2], t.AFI)
		tbuf[2] = t.SAFI
		tbuf[3] = t.Flags
		buf = append(buf, tbuf...)
	}
	c.DefaultParameterCapability.CapValue = buf
	return c.DefaultParameterCapability.Serialize()
}

func NewCapGracefulRestart(flags uint8, time uint16, tuples []CapGracefulRestartTuples) *CapGracefulRestart {
	return &CapGracefulRestart{
		DefaultParameterCapability{
			CapCode: BGP_CAP_GRACEFUL_RESTART,
		},
		CapGracefulRestartValue{
			flags,
			time,
			tuples,
		},
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
		return fmt.Errorf("Not all CapabilityMultiProtocol bytes available")
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

func NewCapFourOctetASNumber(asnum uint32) *CapFourOctetASNumber {
	return &CapFourOctetASNumber{
		DefaultParameterCapability{
			CapCode: BGP_CAP_FOUR_OCTET_AS_NUMBER,
		},
		asnum,
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

type CapUnknown struct {
	DefaultParameterCapability
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
		return fmt.Errorf("Not all OptionParameterCapability bytes available")
	}
	for len(data) >= 2 {
		var c ParameterCapabilityInterface
		switch BGPCapabilityCode(data[0]) {
		case BGP_CAP_MULTIPROTOCOL:
			c = &CapMultiProtocol{}
		case BGP_CAP_ROUTE_REFRESH:
			c = &CapRouteRefresh{}
		case BGP_CAP_CARRYING_LABEL_INFO:
			c = &CapCarryingLabelInfo{}
		case BGP_CAP_GRACEFUL_RESTART:
			c = &CapGracefulRestart{}
		case BGP_CAP_FOUR_OCTET_AS_NUMBER:
			c = &CapFourOctetASNumber{}
		case BGP_CAP_ENHANCED_ROUTE_REFRESH:
			c = &CapEnhancedRouteRefresh{}
		case BGP_CAP_ROUTE_REFRESH_CISCO:
			c = &CapRouteRefreshCisco{}
		default:
			c = &CapUnknown{}
		}
		err := c.DecodeFromBytes(data)
		if err != nil {
			return nil
		}
		o.Capability = append(o.Capability, c)
		data = data[c.Len():]
	}
	return nil
}

func (o *OptionParameterCapability) Serialize() ([]byte, error) {
	buf := make([]byte, 2)
	buf[0] = o.ParamType
	//buf[1] = o.ParamLen
	for _, p := range o.Capability {
		pbuf, err := p.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, pbuf...)
	}
	buf[1] = uint8(len(buf) - 2)
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
	msg.ID = data[5:9]
	msg.OptParamLen = data[9]
	data = data[10:]
	if len(data) < int(msg.OptParamLen) {
		return fmt.Errorf("Not all BGP Open message bytes available")
	}

	for rest := msg.OptParamLen; rest > 0; {
		paramtype := data[0]
		paramlen := data[1]
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
	copy(buf[5:9], msg.ID)
	pbuf := make([]byte, 0)
	for _, p := range msg.OptParams {
		onepbuf, err := p.Serialize()
		if err != nil {
			return nil, err
		}
		pbuf = append(pbuf, onepbuf...)
	}
	buf[9] = uint8(len(pbuf))
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
	ToApiStruct() *api.Nlri
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
	return buf, nil
}

func (r *IPAddrPrefixDefault) Len() int {
	return 1 + ((int(r.Length) + 7) / 8)
}

func (r *IPAddrPrefixDefault) String() string {
	return fmt.Sprintf("%s/%d", r.Prefix.String(), r.Length)
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

func (r *IPAddrPrefix) ToApiStruct() *api.Nlri {
	return &api.Nlri{
		Af:     &api.AddressFamily{api.AFI(r.AFI()), api.SAFI(r.SAFI())},
		Prefix: r.String(),
	}
}

func NewIPAddrPrefix(length uint8, prefix string) *IPAddrPrefix {
	return &IPAddrPrefix{
		IPAddrPrefixDefault{length, net.ParseIP(prefix).To4()},
		4,
	}
}

type IPv6AddrPrefix struct {
	IPAddrPrefix
}

func (r *IPv6AddrPrefix) AFI() uint16 {
	return AFI_IP6
}

func NewIPv6AddrPrefix(length uint8, prefix string) *IPv6AddrPrefix {
	return &IPv6AddrPrefix{
		IPAddrPrefix{
			IPAddrPrefixDefault{length, net.ParseIP(prefix)},
			16,
		},
	}
}

type WithdrawnRoute struct {
	IPAddrPrefix
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

func (rd *DefaultRouteDistinguisher) Len() int { return 8 }

type RouteDistinguisherTwoOctetASValue struct {
	Admin    uint16
	Assigned uint32
}

type RouteDistinguisherTwoOctetAS struct {
	DefaultRouteDistinguisher
	Value RouteDistinguisherTwoOctetASValue
}

func (rd *RouteDistinguisherTwoOctetAS) Serialize() ([]byte, error) {
	buf := make([]byte, 6)
	binary.BigEndian.PutUint16(buf[0:], rd.Value.Admin)
	binary.BigEndian.PutUint32(buf[2:], rd.Value.Assigned)
	rd.DefaultRouteDistinguisher.Value = buf
	return rd.DefaultRouteDistinguisher.Serialize()
}

func (rd *RouteDistinguisherTwoOctetAS) String() string {
	return fmt.Sprintf("%d:%d", rd.Value.Admin, rd.Value.Assigned)
}

func NewRouteDistinguisherTwoOctetAS(admin uint16, assigned uint32) *RouteDistinguisherTwoOctetAS {
	return &RouteDistinguisherTwoOctetAS{
		DefaultRouteDistinguisher{
			Type: BGP_RD_TWO_OCTET_AS,
		},
		RouteDistinguisherTwoOctetASValue{
			Admin:    admin,
			Assigned: assigned,
		},
	}
}

type RouteDistinguisherIPAddressASValue struct {
	Admin    net.IP
	Assigned uint16
}

type RouteDistinguisherIPAddressAS struct {
	DefaultRouteDistinguisher
	Value RouteDistinguisherIPAddressASValue
}

func (rd *RouteDistinguisherIPAddressAS) Serialize() ([]byte, error) {
	buf := make([]byte, 6)
	copy(buf[0:], rd.Value.Admin)
	binary.BigEndian.PutUint16(buf[4:], rd.Value.Assigned)
	rd.DefaultRouteDistinguisher.Value = buf
	return rd.DefaultRouteDistinguisher.Serialize()
}

func (rd *RouteDistinguisherIPAddressAS) String() string {
	return fmt.Sprintf("%s:%d", rd.Value.Admin.String(), rd.Value.Assigned)
}

func NewRouteDistinguisherIPAddressAS(admin string, assigned uint16) *RouteDistinguisherIPAddressAS {
	return &RouteDistinguisherIPAddressAS{
		DefaultRouteDistinguisher{
			Type: BGP_RD_IPV4_ADDRESS,
		},
		RouteDistinguisherIPAddressASValue{
			Admin:    net.ParseIP(admin),
			Assigned: assigned,
		},
	}
}

type RouteDistinguisherFourOctetASValue struct {
	Admin    uint32
	Assigned uint16
}

type RouteDistinguisherFourOctetAS struct {
	DefaultRouteDistinguisher
	Value RouteDistinguisherFourOctetASValue
}

func (rd *RouteDistinguisherFourOctetAS) Serialize() ([]byte, error) {
	buf := make([]byte, 6)
	binary.BigEndian.PutUint32(buf[0:], rd.Value.Admin)
	binary.BigEndian.PutUint16(buf[4:], rd.Value.Assigned)
	rd.DefaultRouteDistinguisher.Value = buf
	return rd.DefaultRouteDistinguisher.Serialize()
}

func (rd *RouteDistinguisherFourOctetAS) String() string {
	return fmt.Sprintf("%d:%d", rd.Value.Admin, rd.Value.Assigned)
}

func NewRouteDistinguisherFourOctetAS(admin uint32, assigned uint16) *RouteDistinguisherFourOctetAS {
	return &RouteDistinguisherFourOctetAS{
		DefaultRouteDistinguisher{
			Type: BGP_RD_FOUR_OCTET_AS,
		},
		RouteDistinguisherFourOctetASValue{
			Admin:    admin,
			Assigned: assigned,
		},
	}
}

type RouteDistinguisherUnknown struct {
	DefaultRouteDistinguisher
}

func getRouteDistinguisher(data []byte) RouteDistinguisherInterface {
	rdtype := binary.BigEndian.Uint16(data[0:2])
	switch rdtype {
	case BGP_RD_TWO_OCTET_AS:
		rd := &RouteDistinguisherTwoOctetAS{}
		rd.Type = rdtype
		rd.Value.Admin = binary.BigEndian.Uint16(data[2:4])
		rd.Value.Assigned = binary.BigEndian.Uint32(data[4:8])
		return rd
	case BGP_RD_IPV4_ADDRESS:
		rd := &RouteDistinguisherIPAddressAS{}
		rd.Type = rdtype
		rd.Value.Admin = data[2:6]
		rd.Value.Assigned = binary.BigEndian.Uint16(data[6:8])
		return rd
	case BGP_RD_FOUR_OCTET_AS:
		rd := &RouteDistinguisherFourOctetAS{}
		rd.Type = rdtype
		rd.Value.Admin = binary.BigEndian.Uint32(data[2:6])
		rd.Value.Assigned = binary.BigEndian.Uint16(data[6:8])
		return rd
	}
	rd := &RouteDistinguisherUnknown{}
	rd.Type = rdtype
	return rd
}

func labelDecode(data []byte) uint32 {
	return uint32(data[0]<<16 | data[1]<<8 | data[2])
}

func labelSerialize(label uint32, buf []byte) {
	buf[0] = byte((label >> 16) & 0xff)
	buf[1] = byte((label >> 8) & 0xff)
	buf[2] = byte(label & 0xff)
}

type Label struct {
	Labels []uint32
}

func (l *Label) DecodeFromBytes(data []byte) error {
	labels := []uint32{}
	foundBottom := false
	for len(data) >= 4 {
		label := uint32(data[0]<<16 | data[1]<<8 | data[2])
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

func (l *Label) Serialize() ([]byte, error) {
	buf := make([]byte, len(l.Labels)*3)
	for i, label := range l.Labels {
		label = label << 4
		buf[i*3] = byte((label >> 16) & 0xff)
		buf[i*3+1] = byte((label >> 8) & 0xff)
		buf[i*3+2] = byte(label & 0xff)
	}
	buf[len(buf)-1] |= 1
	return buf, nil
}

func (l *Label) Len() int { return 3 * len(l.Labels) }

func NewLabel(labels ...uint32) *Label {
	return &Label{labels}
}

type LabelledVPNIPAddrPrefix struct {
	IPAddrPrefixDefault
	Labels  Label
	RD      RouteDistinguisherInterface
	addrlen uint8
}

func (l *LabelledVPNIPAddrPrefix) DecodeFromBytes(data []byte) error {
	l.Length = uint8(data[0])
	data = data[1:]
	l.Labels.DecodeFromBytes(data)
	if int(l.Length)-8*(l.Labels.Len()) < 0 {
		l.Labels.Labels = []uint32{}
	}
	data = data[l.Labels.Len():]
	l.RD = getRouteDistinguisher(data)
	data = data[l.RD.Len():]
	restbits := int(l.Length) - 8*(l.Labels.Len()+l.RD.Len())
	l.decodePrefix(data, uint8(restbits), l.addrlen)
	return nil
}

func (l *LabelledVPNIPAddrPrefix) Serialize() ([]byte, error) {
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

func (l *LabelledVPNIPAddrPrefix) AFI() uint16 {
	return AFI_IP
}

func (l *LabelledVPNIPAddrPrefix) SAFI() uint8 {
	return SAFI_MPLS_VPN
}

func (l *LabelledVPNIPAddrPrefix) ToApiStruct() *api.Nlri {
	return &api.Nlri{
		Af:     &api.AddressFamily{api.AFI(l.AFI()), api.SAFI(l.SAFI())},
		Prefix: l.String(),
	}
}

func NewLabelledVPNIPAddrPrefix(length uint8, prefix string, label Label, rd RouteDistinguisherInterface) *LabelledVPNIPAddrPrefix {
	rdlen := 0
	if rd != nil {
		rdlen = rd.Len()
	}
	return &LabelledVPNIPAddrPrefix{
		IPAddrPrefixDefault{length + uint8(8*(label.Len()+rdlen)), net.ParseIP(prefix)},
		label,
		rd,
		4,
	}
}

type LabelledVPNIPv6AddrPrefix struct {
	LabelledVPNIPAddrPrefix
}

func (l *LabelledVPNIPv6AddrPrefix) AFI() uint16 {
	return AFI_IP6
}

func NewLabelledVPNIPv6AddrPrefix(length uint8, prefix string, label Label, rd RouteDistinguisherInterface) *LabelledVPNIPv6AddrPrefix {
	rdlen := 0
	if rd != nil {
		rdlen = rd.Len()
	}
	return &LabelledVPNIPv6AddrPrefix{
		LabelledVPNIPAddrPrefix{
			IPAddrPrefixDefault{length + uint8(8*(label.Len()+rdlen)), net.ParseIP(prefix)},
			label,
			rd,
			16,
		},
	}
}

type LabelledIPAddrPrefix struct {
	IPAddrPrefixDefault
	Labels  Label
	addrlen uint8
}

func (r *LabelledIPAddrPrefix) AFI() uint16 {
	return AFI_IP
}

func (r *LabelledIPAddrPrefix) SAFI() uint8 {
	return SAFI_MPLS_LABEL
}

func (r *LabelledIPAddrPrefix) ToApiStruct() *api.Nlri {
	return &api.Nlri{
		Af:     &api.AddressFamily{api.AFI(r.AFI()), api.SAFI(r.SAFI())},
		Prefix: r.String(),
	}
}

func (r *IPAddrPrefix) decodeNextHop(data []byte) net.IP {
	if r.addrlen == 0 {
		r.addrlen = 4
	}
	var next net.IP = data[0:r.addrlen]
	return next
}

func (r *LabelledVPNIPAddrPrefix) decodeNextHop(data []byte) net.IP {
	// skip rd
	var next net.IP = data[8 : 8+r.addrlen]
	return next
}

func (r *LabelledIPAddrPrefix) decodeNextHop(data []byte) net.IP {
	var next net.IP = data[0:r.addrlen]
	return next
}

func (l *LabelledIPAddrPrefix) DecodeFromBytes(data []byte) error {
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

func (l *LabelledIPAddrPrefix) Serialize() ([]byte, error) {
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

func NewLabelledIPAddrPrefix(length uint8, prefix string, label Label) *LabelledIPAddrPrefix {
	return &LabelledIPAddrPrefix{
		IPAddrPrefixDefault{length + uint8(label.Len()*8), net.ParseIP(prefix)},
		label,
		4,
	}
}

type LabelledIPv6AddrPrefix struct {
	LabelledIPAddrPrefix
}

func NewLabelledIPv6AddrPrefix(length uint8, prefix string, label Label) *LabelledIPv6AddrPrefix {
	return &LabelledIPv6AddrPrefix{
		LabelledIPAddrPrefix{
			IPAddrPrefixDefault{length + uint8(label.Len()*8), net.ParseIP(prefix)},
			label,
			16,
		},
	}
}

type RouteTargetMembershipNLRI struct {
	AS          uint32
	RouteTarget ExtendedCommunityInterface
}

func (n *RouteTargetMembershipNLRI) DecodeFromBytes(data []byte) error {
	n.AS = binary.BigEndian.Uint32(data[0:4])
	rt, err := parseExtended(data[4:])
	n.RouteTarget = rt
	if err != nil {
		return err
	}
	return nil
}

func (n *RouteTargetMembershipNLRI) Serialize() ([]byte, error) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, n.AS)
	ebuf, err := n.RouteTarget.Serialize()
	if err != nil {
		return nil, err
	}
	return append(buf, ebuf...), nil
}

func (n *RouteTargetMembershipNLRI) AFI() uint16 {
	return AFI_IP
}

func (n *RouteTargetMembershipNLRI) SAFI() uint8 {
	return SAFI_ROUTE_TARGET_CONSTRTAINS
}

func (n *RouteTargetMembershipNLRI) Len() int { return 12 }

func (n *RouteTargetMembershipNLRI) String() string {
	return fmt.Sprintf("%d:%s/%d", n.AS, n.RouteTarget.String(), n.Len()*8)
}

func (n *RouteTargetMembershipNLRI) ToApiStruct() *api.Nlri {
	return &api.Nlri{
		Af:     &api.AddressFamily{api.AFI(n.AFI()), api.SAFI(n.SAFI())},
		Prefix: n.String(),
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
			return fmt.Errorf("invalid %s. last octet must be 0x00 (0x%02x)", esi.Type, esi.Value[8])
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

func (esi *EthernetSegmentIdentifier) String() string {
	s := bytes.NewBuffer(make([]byte, 0, 64))
	s.WriteString(fmt.Sprintf("%s | ", esi.Type))
	switch esi.Type {
	case ESI_LACP:
		s.WriteString(fmt.Sprintf("system mac %s, ", net.HardwareAddr(esi.Value[:6]).String()))
		s.WriteString(fmt.Sprintf("port key %d", binary.BigEndian.Uint16(esi.Value[6:8])))
	case ESI_MSTP:
		s.WriteString(fmt.Sprintf("bridge mac %s, ", net.HardwareAddr(esi.Value[:6]).String()))
		s.WriteString(fmt.Sprintf("priority %d", binary.BigEndian.Uint16(esi.Value[6:8])))
	case ESI_MAC:
		s.WriteString(fmt.Sprintf("system mac %s, ", net.HardwareAddr(esi.Value[:6]).String()))
		s.WriteString(fmt.Sprintf("local discriminator %d", esi.Value[6]<<16|esi.Value[7]<<8|esi.Value[8]))
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

type EVPNEthernetAutoDiscoveryRoute struct {
	RD    RouteDistinguisherInterface
	ESI   EthernetSegmentIdentifier
	ETag  uint32
	Label uint32
}

func (er *EVPNEthernetAutoDiscoveryRoute) DecodeFromBytes(data []byte) error {
	er.RD = getRouteDistinguisher(data)
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
	buf, err := er.RD.Serialize()
	if err != nil {
		return nil, err
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
	er.RD = getRouteDistinguisher(data)
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
		return fmt.Errorf("Invalid IP address length", er.IPAddressLength)
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
	buf, err := er.RD.Serialize()
	if err != nil {
		return nil, err
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

	if er.IPAddressLength == 32 || er.IPAddressLength == 128 {
		buf = append(buf, er.IPAddressLength)
		if er.IPAddressLength == 32 {
			er.IPAddress = er.IPAddress.To4()
		}
		buf = append(buf, []byte(er.IPAddress)...)
	} else if er.IPAddressLength != 0 {
		return nil, fmt.Errorf("Invalid IP address length", er.IPAddressLength)
	}

	for _, l := range er.Labels {
		tbuf = make([]byte, 3)
		labelSerialize(l, tbuf)
		buf = append(buf, tbuf...)
	}
	return buf, nil
}

type EVPNMulticastEthernetTagRoute struct {
	RD              RouteDistinguisherInterface
	ETag            uint32
	IPAddressLength uint8
	IPAddress       net.IP
}

func (er *EVPNMulticastEthernetTagRoute) DecodeFromBytes(data []byte) error {
	er.RD = getRouteDistinguisher(data)
	data = data[er.RD.Len():]
	er.ETag = binary.BigEndian.Uint32(data[0:4])
	er.IPAddressLength = data[4]
	data = data[5:]
	if er.IPAddressLength == 32 || er.IPAddressLength == 128 {
		er.IPAddress = net.IP(data[:er.IPAddressLength/8])
	} else {
		return fmt.Errorf("Invalid IP address length", er.IPAddressLength)
	}
	return nil
}

func (er *EVPNMulticastEthernetTagRoute) Serialize() ([]byte, error) {
	buf, err := er.RD.Serialize()
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("Invalid IP address length", er.IPAddressLength)
	}
	if err != nil {
		return nil, err
	}
	return buf, nil
}

type EVPNEthernetSegmentRoute struct {
	RD              RouteDistinguisherInterface
	ESI             EthernetSegmentIdentifier
	IPAddressLength uint8
	IPAddress       net.IP
}

func (er *EVPNEthernetSegmentRoute) DecodeFromBytes(data []byte) error {
	er.RD = getRouteDistinguisher(data)
	data = data[er.RD.Len():]
	er.ESI.DecodeFromBytes(data)
	data = data[10:]
	er.IPAddressLength = data[0]
	data = data[1:]
	if er.IPAddressLength == 32 || er.IPAddressLength == 128 {
		er.IPAddress = net.IP(data[:er.IPAddressLength/8])
	} else {
		return fmt.Errorf("Invalid IP address length", er.IPAddressLength)
	}
	return nil
}

func (er *EVPNEthernetSegmentRoute) Serialize() ([]byte, error) {
	buf, err := er.RD.Serialize()
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("Invalid IP address length", er.IPAddressLength)
	}
	return buf, nil
}

type EVPNRouteTypeInterface interface {
	DecodeFromBytes([]byte) error
	Serialize() ([]byte, error)
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
	}
	return nil, fmt.Errorf("Unknown EVPN Route type", t)
}

const (
	EVPN_ROUTE_TYPE_ETHERNET_AUTO_DISCOVERY = 1
	EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT    = 2
	EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG   = 3
	EVPN_ETHERNET_SEGMENT_ROUTE             = 4
)

type EVPNNLRI struct {
	RouteType     uint8
	Length        uint8
	RouteTypeData EVPNRouteTypeInterface
}

func (n *EVPNNLRI) DecodeFromBytes(data []byte) error {
	if len(data) < 2 {
		return fmt.Errorf("Not all EVPNNLRI bytes available")
	}
	n.RouteType = data[0]
	n.Length = data[1]
	data = data[2:]
	if len(data) < int(n.Length) {
		return fmt.Errorf("Not all EVPNNLRI Route type bytes available")
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

	switch n.RouteType {

	case EVPN_ROUTE_TYPE_ETHERNET_AUTO_DISCOVERY:
		return fmt.Sprintf("%d:%d", n.RouteType, n.Length)

	case EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT:
		m := n.RouteTypeData.(*EVPNMacIPAdvertisementRoute)
		var ss []string
		switch m.RD.(type) {
		case *RouteDistinguisherIPAddressAS:
			ss = append(ss, fmt.Sprintf("%s", m.IPAddress.String()))
		}
		ss = append(ss, m.MacAddress.String())
		return strings.Join(ss, ".")

	case EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG:
		m := n.RouteTypeData.(*EVPNMulticastEthernetTagRoute)
		switch m.RD.(type) {
		case *RouteDistinguisherIPAddressAS:
			return fmt.Sprintf("%s", m.IPAddress.String())
		}

	case EVPN_ETHERNET_SEGMENT_ROUTE:
		return fmt.Sprintf("%d:%d", n.RouteType, n.Length)

	}
	return fmt.Sprintf("%d:%d", n.RouteType, n.Length)
}

func (n *EVPNNLRI) ToApiStruct() *api.Nlri {
	return &api.Nlri{
		Af:     &api.AddressFamily{api.AFI(n.AFI()), api.SAFI(n.SAFI())},
		Prefix: n.String(),
	}
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
}

func (n *EncapNLRI) DecodeFromBytes(data []byte) error {
	if len(data) < 4 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST)
		return NewMessageError(eCode, eSubCode, nil, "prefix misses length field")
	}
	n.Length = data[0]
	return n.decodePrefix(data[1:], n.Length, n.Length/8)
}

func (n *EncapNLRI) Serialize() ([]byte, error) {
	buf := make([]byte, 1)
	buf[0] = net.IPv6len * 8
	if n.Prefix.To4() != nil {
		buf[0] = net.IPv4len * 8
		n.Prefix = n.Prefix.To4()
	}
	n.Length = buf[0]
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
	if n.Prefix.To4() != nil {
		return AFI_IP
	}
	return AFI_IP6
}

func (n *EncapNLRI) SAFI() uint8 {
	return SAFI_ENCAPSULATION
}

func (n *EncapNLRI) ToApiStruct() *api.Nlri {
	return &api.Nlri{
		Af:     &api.AddressFamily{api.AFI(n.AFI()), api.SAFI(n.SAFI())},
		Prefix: n.String(),
	}
}

func NewEncapNLRI(endpoint string) *EncapNLRI {
	return &EncapNLRI{
		IPAddrPrefixDefault{0, net.ParseIP(endpoint)},
	}
}

func AfiSafiToRouteFamily(afi uint16, safi uint8) RouteFamily {
	return RouteFamily(int(afi)<<16 | int(safi))
}

func RouteFamilyToAfiSafi(rf RouteFamily) (uint16, uint8) {
	return uint16(int(rf) >> 16), uint8(int(rf) & 0xff)
}

type RouteFamily int

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
	RF_RTC_UC      RouteFamily = AFI_IP<<16 | SAFI_ROUTE_TARGET_CONSTRTAINS
	RF_ENCAP       RouteFamily = AFI_IP<<16 | SAFI_ENCAPSULATION
)

func GetRouteFamily(name string) (RouteFamily, error) {
	switch name {
	case "ipv4-unicast":
		return RF_IPv4_UC, nil
	case "ipv6-unicast":
		return RF_IPv6_UC, nil
	case "ipv4-multicast":
		return RF_IPv4_MC, nil
	case "ipv6-multicast":
		return RF_IPv6_MC, nil
	case "ipv4-labelled-unicast":
		return RF_IPv4_MPLS, nil
	case "ipv6-labelled-unicast":
		return RF_IPv6_MPLS, nil
	case "l3vpn-ipv4-unicast":
		return RF_IPv4_VPN, nil
	case "l3vpn-ipv6-unicast":
		return RF_IPv6_VPN, nil
	case "l3vpn-ipv4-multicast":
		return RF_IPv4_VPN_MC, nil
	case "l3vpn-ipv6-multicast":
		return RF_IPv6_VPN_MC, nil
	case "l2vpn-vpls":
		return RF_VPLS, nil
	case "l2vpn-evpn":
		return RF_EVPN, nil
	case "encap":
		return RF_ENCAP, nil
	}
	return RouteFamily(0), fmt.Errorf("%s isn't a valid route family name", name)
}

func routeFamilyPrefix(afi uint16, safi uint8) (prefix AddrPrefixInterface, err error) {
	switch AfiSafiToRouteFamily(afi, safi) {
	case RF_IPv4_UC:
		prefix = NewIPAddrPrefix(0, "")
	case RF_IPv6_UC:
		prefix = NewIPv6AddrPrefix(0, "")
	case RF_IPv4_VPN:
		prefix = NewLabelledVPNIPAddrPrefix(0, "", *NewLabel(), nil)
	case RF_IPv6_VPN:
		prefix = NewLabelledVPNIPv6AddrPrefix(0, "", *NewLabel(), nil)
	case RF_IPv4_MPLS:
		prefix = NewLabelledIPAddrPrefix(0, "", *NewLabel())
	case RF_IPv6_MPLS:
		prefix = NewLabelledIPv6AddrPrefix(0, "", *NewLabel())
	case RF_EVPN:
		prefix = NewEVPNNLRI(0, 0, nil)
	case RF_RTC_UC:
		prefix = &RouteTargetMembershipNLRI{}
	case RF_ENCAP:
		prefix = NewEncapNLRI("")
	default:
		return nil, errors.New("unknown route family")
	}
	return prefix, nil
}

const (
	BGP_ATTR_FLAG_EXTENDED_LENGTH = 1 << 4
	BGP_ATTR_FLAG_PARTIAL         = 1 << 5
	BGP_ATTR_FLAG_TRANSITIVE      = 1 << 6
	BGP_ATTR_FLAG_OPTIONAL        = 1 << 7
)

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
	_
	BGP_ATTR_TYPE_TUNNEL_ENCAP // = 23
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
	BGP_ERROR_SUB_AUTHENTICATION_FAILURE
	BGP_ERROR_SUB_UNACCEPTABLE_HOLD_TIME
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
	BGP_ERROR_SUB_ROUTING_LOOP
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
	BGP_ERROR_SUB_FSM_ERROR
)

// NOTIFICATION Error Subcode for BGP_ERROR_CEASE  (RFC 4486)
const (
	_ = iota
	BGP_ERROR_SUB_MAXIMUM_NUMBER_OF_PREFIXES_REACHED
	BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN
	BGP_ERROR_SUB_PEER_DECONFIGURED
	BGP_ERROR_SUB_ADMINISTRATIVE_RESET
	BGP_ERROR_SUB_CONNECTION_RESET
	BGP_ERROR_SUB_OTHER_CONFIGURATION_CHANGE
	BGP_ERROR_SUB_CONNECTION_COLLISION_RESOLUTION
	BGP_ERROR_SUB_OUT_OF_RESOURCES
)

var pathAttrFlags map[BGPAttrType]uint8 = map[BGPAttrType]uint8{
	BGP_ATTR_TYPE_ORIGIN:               BGP_ATTR_FLAG_TRANSITIVE,
	BGP_ATTR_TYPE_AS_PATH:              BGP_ATTR_FLAG_TRANSITIVE,
	BGP_ATTR_TYPE_NEXT_HOP:             BGP_ATTR_FLAG_TRANSITIVE,
	BGP_ATTR_TYPE_MULTI_EXIT_DISC:      BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_LOCAL_PREF:           BGP_ATTR_FLAG_TRANSITIVE,
	BGP_ATTR_TYPE_ATOMIC_AGGREGATE:     BGP_ATTR_FLAG_TRANSITIVE,
	BGP_ATTR_TYPE_AGGREGATOR:           BGP_ATTR_FLAG_TRANSITIVE | BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_COMMUNITIES:          BGP_ATTR_FLAG_TRANSITIVE | BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_ORIGINATOR_ID:        BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_CLUSTER_LIST:         BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_MP_REACH_NLRI:        BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_MP_UNREACH_NLRI:      BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_EXTENDED_COMMUNITIES: BGP_ATTR_FLAG_TRANSITIVE | BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_AS4_PATH:             BGP_ATTR_FLAG_TRANSITIVE | BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_AS4_AGGREGATOR:       BGP_ATTR_FLAG_TRANSITIVE | BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_TUNNEL_ENCAP:         BGP_ATTR_FLAG_TRANSITIVE | BGP_ATTR_FLAG_OPTIONAL,
}

type PathAttributeInterface interface {
	DecodeFromBytes([]byte) error
	Serialize() ([]byte, error)
	Len() int
	getFlags() uint8
	getType() BGPAttrType
	ToApiStruct() *api.PathAttr
}

type PathAttribute struct {
	Flags  uint8
	Type   BGPAttrType
	Length uint16
	Value  []byte
}

func (p *PathAttribute) Len() int {
	l := 2 + p.Length
	if p.Flags&BGP_ATTR_FLAG_EXTENDED_LENGTH != 0 {
		l += 2
	} else {
		l += 1
	}
	return int(l)
}

func (p *PathAttribute) getFlags() uint8 {
	return p.Flags
}

func (p *PathAttribute) getType() BGPAttrType {
	return p.Type
}

func (p *PathAttribute) DecodeFromBytes(data []byte) error {
	odata := data
	eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
	eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)
	if len(data) < 2 {
		return NewMessageError(eCode, eSubCode, data, "attribute header length is short")
	}
	p.Flags = data[0]
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
	p.Value = data[:p.Length]

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
	buf[0] = p.Flags
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

type PathAttributeOrigin struct {
	PathAttribute
}

func (p *PathAttributeOrigin) ToApiStruct() *api.PathAttr {
	return &api.PathAttr{
		Type:   api.BGP_ATTR_TYPE_ORIGIN,
		Origin: api.Origin(uint8(p.Value[0])),
	}
}

func (p *PathAttributeOrigin) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.ToApiStruct())
}

func NewPathAttributeOrigin(value uint8) *PathAttributeOrigin {
	t := BGP_ATTR_TYPE_ORIGIN
	return &PathAttributeOrigin{

		PathAttribute: PathAttribute{
			Flags: pathAttrFlags[t],
			Type:  t,
			Value: []byte{byte(value)},
		},
	}
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
	return len(a.AS)
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
	return len(a.AS)
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

type AsPathParamInterface interface {
	Serialize() ([]byte, error)
	DecodeFromBytes([]byte) error
	Len() int
	ASLen() int
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

func (p *PathAttributeAsPath) ToApiStruct() *api.PathAttr {
	aslist := make([]uint32, 0)
	for _, a := range p.Value {
		path, y := a.(*As4PathParam)
		if y {
			aslist = append(aslist, path.AS...)
		} else {
			path := a.(*AsPathParam)
			for _, v := range path.AS {
				aslist = append(aslist, uint32(v))
			}
		}
	}
	return &api.PathAttr{
		Type:   api.BGP_ATTR_TYPE_AS_PATH,
		AsPath: aslist,
	}
}

func (p *PathAttributeAsPath) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.ToApiStruct())
}

func NewPathAttributeAsPath(value []AsPathParamInterface) *PathAttributeAsPath {
	t := BGP_ATTR_TYPE_AS_PATH
	return &PathAttributeAsPath{
		PathAttribute: PathAttribute{
			Flags: pathAttrFlags[t],
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

func (p *PathAttributeNextHop) ToApiStruct() *api.PathAttr {
	return &api.PathAttr{
		Type:    api.BGP_ATTR_TYPE_NEXT_HOP,
		Nexthop: p.Value.String(),
	}
}

func (p *PathAttributeNextHop) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.ToApiStruct())
}

func NewPathAttributeNextHop(value string) *PathAttributeNextHop {
	t := BGP_ATTR_TYPE_NEXT_HOP
	return &PathAttributeNextHop{
		PathAttribute: PathAttribute{
			Flags: pathAttrFlags[t],
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

func (p *PathAttributeMultiExitDisc) ToApiStruct() *api.PathAttr {
	return &api.PathAttr{
		Type:   api.BGP_ATTR_TYPE_MULTI_EXIT_DISC,
		Metric: p.Value,
	}
}

func (p *PathAttributeMultiExitDisc) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.ToApiStruct())
}

func NewPathAttributeMultiExitDisc(value uint32) *PathAttributeMultiExitDisc {
	t := BGP_ATTR_TYPE_MULTI_EXIT_DISC
	return &PathAttributeMultiExitDisc{
		PathAttribute: PathAttribute{
			Flags: pathAttrFlags[t],
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

func (p *PathAttributeLocalPref) ToApiStruct() *api.PathAttr {
	return &api.PathAttr{
		Type: api.BGP_ATTR_TYPE_LOCAL_PREF,
		Pref: p.Value,
	}
}

func (p *PathAttributeLocalPref) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.ToApiStruct())
}

func NewPathAttributeLocalPref(value uint32) *PathAttributeLocalPref {
	t := BGP_ATTR_TYPE_LOCAL_PREF
	return &PathAttributeLocalPref{
		PathAttribute: PathAttribute{
			Flags: pathAttrFlags[t],
			Type:  t,
		},
		Value: value,
	}
}

type PathAttributeAtomicAggregate struct {
	PathAttribute
}

func (p *PathAttributeAtomicAggregate) ToApiStruct() *api.PathAttr {
	return &api.PathAttr{
		Type: api.BGP_ATTR_TYPE_ATOMIC_AGGREGATE,
	}
}

func (p *PathAttributeAtomicAggregate) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.ToApiStruct())
}

func NewPathAttributeAtomicAggregate() *PathAttributeAtomicAggregate {
	t := BGP_ATTR_TYPE_ATOMIC_AGGREGATE
	return &PathAttributeAtomicAggregate{
		PathAttribute: PathAttribute{
			Flags: pathAttrFlags[t],
			Type:  t,
		},
	}
}

type PathAttributeAggregatorParam struct {
	AS      uint32
	askind  reflect.Kind
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
		p.Value.askind = reflect.Uint16
	} else {
		p.Value.AS = binary.BigEndian.Uint32(p.PathAttribute.Value[0:4])
		p.Value.Address = p.PathAttribute.Value[4:]
		p.Value.askind = reflect.Uint32
	}
	return nil
}

func (p *PathAttributeAggregator) Serialize() ([]byte, error) {
	var buf []byte
	switch p.Value.askind {
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

func (p *PathAttributeAggregator) ToApiStruct() *api.PathAttr {
	return &api.PathAttr{
		Type: api.BGP_ATTR_TYPE_AGGREGATOR,
		Aggregator: &api.Aggregator{
			As:      p.Value.AS,
			Address: p.Value.Address.String(),
		},
	}
}

func (p *PathAttributeAggregator) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.ToApiStruct())
}

func NewPathAttributeAggregator(as interface{}, address string) *PathAttributeAggregator {
	v := reflect.ValueOf(as)
	t := BGP_ATTR_TYPE_AGGREGATOR
	return &PathAttributeAggregator{
		PathAttribute: PathAttribute{
			Flags: pathAttrFlags[t],
			Type:  t,
		},
		Value: PathAttributeAggregatorParam{
			AS:      uint32(v.Uint()),
			askind:  v.Kind(),
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

func (p *PathAttributeCommunities) ToApiStruct() *api.PathAttr {
	return &api.PathAttr{
		Type:       api.BGP_ATTR_TYPE_COMMUNITIES,
		Communites: p.Value,
	}
}

func (p *PathAttributeCommunities) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.ToApiStruct())
}

func NewPathAttributeCommunities(value []uint32) *PathAttributeCommunities {
	t := BGP_ATTR_TYPE_COMMUNITIES
	return &PathAttributeCommunities{
		PathAttribute{
			Flags:  pathAttrFlags[t],
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

func (p *PathAttributeOriginatorId) Serialize() ([]byte, error) {
	buf := make([]byte, 4)
	copy(buf, p.Value)
	p.PathAttribute.Value = buf
	return p.PathAttribute.Serialize()
}

func (p *PathAttributeOriginatorId) ToApiStruct() *api.PathAttr {
	return &api.PathAttr{
		Type:       api.BGP_ATTR_TYPE_ORIGINATOR_ID,
		Originator: p.Value.String(),
	}
}

func (p *PathAttributeOriginatorId) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.ToApiStruct())
}

func NewPathAttributeOriginatorId(value string) *PathAttributeOriginatorId {
	t := BGP_ATTR_TYPE_ORIGINATOR_ID
	return &PathAttributeOriginatorId{
		PathAttribute{
			Flags:  pathAttrFlags[t],
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

func (p *PathAttributeClusterList) ToApiStruct() *api.PathAttr {
	l := make([]string, 0)
	for _, addr := range p.Value {
		l = append(l, addr.String())
	}
	return &api.PathAttr{
		Type:    api.BGP_ATTR_TYPE_CLUSTER_LIST,
		Cluster: l,
	}
}

func (p *PathAttributeClusterList) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.ToApiStruct())
}

func NewPathAttributeClusterList(value []string) *PathAttributeClusterList {
	l := make([]net.IP, len(value))
	for i, v := range value {
		l[i] = net.ParseIP(v).To4()
	}
	t := BGP_ATTR_TYPE_CLUSTER_LIST
	return &PathAttributeClusterList{
		PathAttribute{
			Flags:  pathAttrFlags[t],
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
	_, err = routeFamilyPrefix(afi, safi)
	if err != nil {
		return NewMessageError(eCode, BGP_ERROR_SUB_ATTRIBUTE_FLAGS_ERROR, data[:p.PathAttribute.Len()], err.Error())
	}
	nexthopLen := value[3]
	if len(value) < 4+int(nexthopLen) {
		return NewMessageError(eCode, eSubCode, value, "mpreach nexthop length is short")
	}
	nexthopbin := value[4 : 4+nexthopLen]
	value = value[4+nexthopLen:]
	if nexthopLen > 0 {
		offset := 0
		if safi == SAFI_MPLS_VPN {
			offset = 8
		}
		addrlen := 4
		hasLinkLocal := false

		if afi == AFI_IP6 {
			addrlen = 16
			hasLinkLocal = len(nexthopbin) == offset+2*addrlen
		}

		isValid := len(nexthopbin) == offset+addrlen || hasLinkLocal

		if !isValid {
			return NewMessageError(eCode, eSubCode, value, "mpreach nexthop length is incorrect")
		}
		p.Nexthop = nexthopbin[offset : +offset+addrlen]
		if hasLinkLocal {
			p.LinkLocalNexthop = nexthopbin[offset+addrlen : offset+2*addrlen]
		}
	}
	// skip reserved
	if len(value) == 0 {
		return NewMessageError(eCode, eSubCode, value, "no skip byte")
	}
	value = value[1:]
	for len(value) > 0 {
		prefix, err := routeFamilyPrefix(afi, safi)
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
	if afi == AFI_IP6 {
		nexthoplen = 16
	}
	offset := 0
	if safi == SAFI_MPLS_VPN {
		offset = 8
		nexthoplen += 8
	}
	buf := make([]byte, 4+nexthoplen)
	binary.BigEndian.PutUint16(buf[0:], afi)
	buf[2] = safi
	buf[3] = uint8(nexthoplen)
	copy(buf[4+offset:], p.Nexthop)
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

func (p *PathAttributeMpReachNLRI) ToApiStruct() *api.PathAttr {
	return &api.PathAttr{
		Type:    api.BGP_ATTR_TYPE_MP_REACH_NLRI,
		Nexthop: p.Nexthop.String(),
	}
}

func (p *PathAttributeMpReachNLRI) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.ToApiStruct())
}

func NewPathAttributeMpReachNLRI(nexthop string, nlri []AddrPrefixInterface) *PathAttributeMpReachNLRI {
	t := BGP_ATTR_TYPE_MP_REACH_NLRI
	ip := net.ParseIP(nexthop)
	if ip.To4() != nil {
		ip = ip.To4()
	}
	p := &PathAttributeMpReachNLRI{
		PathAttribute: PathAttribute{
			Flags: pathAttrFlags[t],
			Type:  t,
		},
		Nexthop: ip,
		Value:   nlri,
	}
	if len(nlri) > 0 {
		p.AFI = nlri[0].AFI()
		p.SAFI = nlri[0].SAFI()
	}
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
	_, err = routeFamilyPrefix(afi, safi)
	if err != nil {
		return NewMessageError(eCode, BGP_ERROR_SUB_ATTRIBUTE_FLAGS_ERROR, data[:p.PathAttribute.Len()], err.Error())
	}
	value = value[3:]
	p.AFI = afi
	p.SAFI = safi
	for len(value) > 0 {
		prefix, err := routeFamilyPrefix(afi, safi)
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

func (p *PathAttributeMpUnreachNLRI) ToApiStruct() *api.PathAttr {
	return &api.PathAttr{
		Type: api.BGP_ATTR_TYPE_MP_UNREACH_NLRI,
	}
}

func (p *PathAttributeMpUnreachNLRI) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.ToApiStruct())
}

func NewPathAttributeMpUnreachNLRI(nlri []AddrPrefixInterface) *PathAttributeMpUnreachNLRI {
	t := BGP_ATTR_TYPE_MP_UNREACH_NLRI
	p := &PathAttributeMpUnreachNLRI{
		PathAttribute: PathAttribute{
			Flags:  pathAttrFlags[t],
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
}

type TwoOctetAsSpecificExtended struct {
	SubType      uint8
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
	buf[1] = e.SubType
	binary.BigEndian.PutUint16(buf[2:], e.AS)
	binary.BigEndian.PutUint32(buf[4:], e.LocalAdmin)
	return buf, nil
}

func (e *TwoOctetAsSpecificExtended) String() string {
	return fmt.Sprintf("%d:%d", e.AS, e.LocalAdmin)
}

type IPv4AddressSpecificExtended struct {
	SubType      uint8
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
	buf[1] = e.SubType
	copy(buf[2:6], e.IPv4)
	binary.BigEndian.PutUint16(buf[6:], e.LocalAdmin)
	return buf, nil
}

func (e *IPv4AddressSpecificExtended) String() string {
	return fmt.Sprintf("%s:%d", e.IPv4.String(), e.LocalAdmin)
}

type FourOctetAsSpecificExtended struct {
	SubType      uint8
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
	buf[1] = e.SubType
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

type OpaqueExtendedValueInterface interface {
	Serialize() ([]byte, error)
	String() string
}

type DefaultOpaqueExtendedValue struct {
	Value []byte
}

func (v *DefaultOpaqueExtendedValue) Serialize() ([]byte, error) {
	return v.Value[:7], nil
}

func (v *DefaultOpaqueExtendedValue) String() string {
	buf := make([]byte, 8)
	copy(buf[1:], v.Value)
	d := binary.BigEndian.Uint64(buf)
	return fmt.Sprintf("%d", d)
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
	default:
		return fmt.Sprintf("TUNNEL TYPE: %d", e.TunnelType)
	}
}

type OpaqueExtended struct {
	IsTransitive bool
	Value        OpaqueExtendedValueInterface
}

func (e *OpaqueExtended) DecodeFromBytes(data []byte) error {
	if len(data) != 7 {
		return fmt.Errorf("Invalid OpaqueExtended bytes len: %d", len(data))
	}
	subType := ExtendedCommunityAttrSubType(data[0])

	switch subType {
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
	if err != nil {
		return nil, err
	}
	buf = append(buf, bbuf...)
	return buf, nil
}

func (e *OpaqueExtended) String() string {
	return e.Value.String()
}

func NewOpaqueExtended(isTransitive bool) *OpaqueExtended {
	return &OpaqueExtended{
		IsTransitive: isTransitive,
	}
}

type UnknownExtended struct {
	Type  BGPAttrType
	Value []byte
}

func (e *UnknownExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	buf[0] = uint8(e.Type)
	copy(buf[1:], e.Value)
	return buf, nil
}

func (e *UnknownExtended) String() string {
	buf := make([]byte, 8)
	copy(buf[1:], e.Value)
	v := binary.BigEndian.Uint64(buf)
	return fmt.Sprintf("%d", v)
}

type PathAttributeExtendedCommunities struct {
	PathAttribute
	Value []ExtendedCommunityInterface
}

func parseExtended(data []byte) (ExtendedCommunityInterface, error) {
	attrType := ExtendedCommunityAttrType(data[0])
	transitive := false
	switch attrType {
	case EC_TYPE_TRANSITIVE_TWO_OCTET_AS_SPECIFIC:
		transitive = true
		fallthrough
	case EC_TYPE_NON_TRANSITIVE_TWO_OCTET_AS_SPECIFIC:
		e := &TwoOctetAsSpecificExtended{}
		e.IsTransitive = transitive
		e.SubType = data[1]
		e.AS = binary.BigEndian.Uint16(data[2:4])
		e.LocalAdmin = binary.BigEndian.Uint32(data[4:8])
		return e, nil
	case EC_TYPE_TRANSITIVE_IP4_SPECIFIC:
		transitive = true
		fallthrough
	case EC_TYPE_NON_TRANSITIVE_IP4_SPECIFIC:
		e := &IPv4AddressSpecificExtended{}
		e.IsTransitive = transitive
		e.SubType = data[1]
		e.IPv4 = data[2:6]
		e.LocalAdmin = binary.BigEndian.Uint16(data[6:8])
		return e, nil
	case EC_TYPE_TRANSITIVE_FOUR_OCTET_AS_SPECIFIC:
		transitive = true
		fallthrough
	case EC_TYPE_NON_TRANSITIVE_FOUR_OCTET_AS_SPECIFIC:
		e := &FourOctetAsSpecificExtended{}
		e.IsTransitive = transitive
		e.SubType = data[1]
		e.AS = binary.BigEndian.Uint32(data[2:6])
		e.LocalAdmin = binary.BigEndian.Uint16(data[6:8])
		return e, nil
	case EC_TYPE_TRANSITIVE_OPAQUE:
		transitive = true
		fallthrough
	case EC_TYPE_NON_TRANSITIVE_OPAQUE:
		e := NewOpaqueExtended(transitive)
		err := e.DecodeFromBytes(data[1:8])
		return e, err
	default:
		e := &UnknownExtended{}
		e.Type = BGPAttrType(data[0])
		e.Value = data[1:8]
		return e, nil
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
		e, err := parseExtended(value)
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

func (p *PathAttributeExtendedCommunities) ToApiStruct() *api.PathAttr {
	value := func(arg []ExtendedCommunityInterface) []string {
		ret := make([]string, 0, len(arg))
		for _, v := range p.Value {
			ret = append(ret, v.String())
		}
		return ret
	}(p.Value)
	return &api.PathAttr{
		Type:  api.BGP_ATTR_TYPE_EXTENDED_COMMUNITIES,
		Value: value,
	}
}

func (p *PathAttributeExtendedCommunities) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.ToApiStruct())
}

func NewPathAttributeExtendedCommunities(value []ExtendedCommunityInterface) *PathAttributeExtendedCommunities {
	t := BGP_ATTR_TYPE_EXTENDED_COMMUNITIES
	return &PathAttributeExtendedCommunities{
		PathAttribute: PathAttribute{
			Flags: pathAttrFlags[t],
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

func (p *PathAttributeAs4Path) ToApiStruct() *api.PathAttr {
	aslist := make([]uint32, 0)
	for _, a := range p.Value {
		aslist = append(aslist, a.AS...)
	}
	return &api.PathAttr{
		Type:   api.BGP_ATTR_TYPE_AS4_PATH,
		AsPath: aslist,
	}
}

func (p *PathAttributeAs4Path) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.ToApiStruct())
}

func NewPathAttributeAs4Path(value []*As4PathParam) *PathAttributeAs4Path {
	t := BGP_ATTR_TYPE_AS4_PATH
	return &PathAttributeAs4Path{
		PathAttribute: PathAttribute{
			Flags: pathAttrFlags[t],
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
	copy(buf[4:], p.Value.Address)
	p.PathAttribute.Value = buf
	return p.PathAttribute.Serialize()
}

func (p *PathAttributeAs4Aggregator) ToApiStruct() *api.PathAttr {
	return &api.PathAttr{
		Type: api.BGP_ATTR_TYPE_AS4_AGGREGATOR,
		Aggregator: &api.Aggregator{
			As:      p.Value.AS,
			Address: p.Value.Address.String(),
		},
	}
}

func (p *PathAttributeAs4Aggregator) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.ToApiStruct())
}

func NewPathAttributeAs4Aggregator(as uint32, address string) *PathAttributeAs4Aggregator {
	t := BGP_ATTR_TYPE_AS4_AGGREGATOR
	return &PathAttributeAs4Aggregator{
		PathAttribute: PathAttribute{
			Flags: pathAttrFlags[t],
			Type:  t,
		},
		Value: PathAttributeAggregatorParam{
			AS:      as,
			Address: net.ParseIP(address),
		},
	}
}

type TunnelEncapSubTLVValue interface {
	Serialize() ([]byte, error)
	ToApiStruct() *api.TunnelEncapSubTLV
}

type TunnelEncapSubTLVDefault struct {
	Value []byte
}

func (t *TunnelEncapSubTLVDefault) Serialize() ([]byte, error) {
	return t.Value, nil
}

func (t *TunnelEncapSubTLVDefault) ToApiStruct() *api.TunnelEncapSubTLV {
	return &api.TunnelEncapSubTLV{
		Type:  api.ENCAP_SUBTLV_TYPE_UNKNOWN_SUBTLV_TYPE,
		Value: string(t.Value),
	}
}

type TunnelEncapSubTLVEncapuslation struct {
	Key    uint32 // this represent both SessionID for L2TPv3 case and GRE-key for GRE case (RFC5512 4.)
	Cookie []byte
}

func (t *TunnelEncapSubTLVEncapuslation) Serialize() ([]byte, error) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, t.Key)
	return append(buf, t.Cookie...), nil
}

func (t *TunnelEncapSubTLVEncapuslation) ToApiStruct() *api.TunnelEncapSubTLV {
	return &api.TunnelEncapSubTLV{
		Type:   api.ENCAP_SUBTLV_TYPE_ENCAPSULATION,
		Key:    t.Key,
		Cookie: string(t.Cookie),
	}
}

type TunnelEncapSubTLVProtocol struct {
	Protocol uint16
}

func (t *TunnelEncapSubTLVProtocol) Serialize() ([]byte, error) {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, t.Protocol)
	return buf, nil
}

func (t *TunnelEncapSubTLVProtocol) ToApiStruct() *api.TunnelEncapSubTLV {
	return &api.TunnelEncapSubTLV{
		Type:     api.ENCAP_SUBTLV_TYPE_PROTOCOL,
		Protocol: uint32(t.Protocol),
	}
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

func (t *TunnelEncapSubTLVColor) ToApiStruct() *api.TunnelEncapSubTLV {
	return &api.TunnelEncapSubTLV{
		Type:  api.ENCAP_SUBTLV_TYPE_COLOR,
		Color: t.Color,
	}
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
			return fmt.Errorf("Not all TunnelEncapSubTLV bytes available")
		}
		key := binary.BigEndian.Uint32(data[:4])
		p.Value = &TunnelEncapSubTLVEncapuslation{
			Key:    key,
			Cookie: data[4:],
		}
	case ENCAP_SUBTLV_TYPE_PROTOCOL:
		if len(data) < 2 {
			return fmt.Errorf("Not all TunnelEncapSubTLV bytes available")
		}
		protocol := binary.BigEndian.Uint16(data[:2])
		p.Value = &TunnelEncapSubTLVProtocol{protocol}
	case ENCAP_SUBTLV_TYPE_COLOR:
		if len(data) < 8 {
			return fmt.Errorf("Not all TunnelEncapSubTLV bytes available")
		}
		color := binary.BigEndian.Uint32(data[4:])
		p.Value = &TunnelEncapSubTLVColor{color}
	default:
		p.Value = &TunnelEncapSubTLVDefault{data}
	}
	return nil
}

func (p *TunnelEncapSubTLV) ToApiStruct() *api.TunnelEncapSubTLV {
	return p.Value.ToApiStruct()
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
			return fmt.Errorf("Not all TunnelEncapSubTLV bytes available")
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

func (p *TunnelEncapTLV) ToApiStruct() *api.TunnelEncapTLV {
	subTlvs := make([]*api.TunnelEncapSubTLV, 0, len(p.Value))
	for _, v := range p.Value {
		subTlvs = append(subTlvs, v.ToApiStruct())
	}
	return &api.TunnelEncapTLV{
		Type:   api.TUNNEL_TYPE(p.Type),
		SubTlv: subTlvs,
	}
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
			return fmt.Errorf("Not all TunnelEncapTLV bytes available. %d < %d", len(p.PathAttribute.Value), curr+4+l)
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

func (p *PathAttributeTunnelEncap) ToApiStruct() *api.PathAttr {
	tlvs := make([]*api.TunnelEncapTLV, 0, len(p.Value))
	for _, v := range p.Value {
		tlvs = append(tlvs, v.ToApiStruct())
	}
	return &api.PathAttr{
		Type:        api.BGP_ATTR_TYPE_TUNNEL_ENCAP,
		TunnelEncap: tlvs,
	}
}

func (p *PathAttributeTunnelEncap) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.ToApiStruct())
}

func NewPathAttributeTunnelEncap(value []*TunnelEncapTLV) *PathAttributeTunnelEncap {
	t := BGP_ATTR_TYPE_TUNNEL_ENCAP
	return &PathAttributeTunnelEncap{
		PathAttribute: PathAttribute{
			Flags: pathAttrFlags[t],
			Type:  t,
		},
		Value: value,
	}
}

type PathAttributeUnknown struct {
	PathAttribute
}

func (p *PathAttributeUnknown) ToApiStruct() *api.PathAttr {
	return &api.PathAttr{
		Type:  api.BGP_ATTR_TYPE_UNKNOWN_ATTR,
		Value: []string{string(p.Value)},
	}
}

func (p *PathAttributeUnknown) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.ToApiStruct())
}

func getPathAttribute(data []byte) (PathAttributeInterface, error) {
	if len(data) < 1 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST)
		msg := "attribute type length is short"
		return nil, NewMessageError(eCode, eSubCode, nil, msg)
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
	}
	return &PathAttributeUnknown{}, nil
}

type NLRInfo struct {
	IPAddrPrefix
}

func NewNLRInfo(length uint8, prefix string) *NLRInfo {
	return &NLRInfo{
		IPAddrPrefix: *NewIPAddrPrefix(length, prefix),
	}
}

type BGPUpdate struct {
	WithdrawnRoutesLen    uint16
	WithdrawnRoutes       []WithdrawnRoute
	TotalPathAttributeLen uint16
	PathAttributes        []PathAttributeInterface
	NLRI                  []NLRInfo
}

func (msg *BGPUpdate) DecodeFromBytes(data []byte) error {

	// cache error codes
	eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
	eSubCode := uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST)

	// check withdrawn route length
	if len(data) < 2 {
		msg := "message length isn't enough for withdrawn route length"
		e := NewMessageError(eCode, eSubCode, nil, msg)
		return e
	}

	msg.WithdrawnRoutesLen = binary.BigEndian.Uint16(data[0:2])
	data = data[2:]

	// check withdrawn route
	if len(data) < int(msg.WithdrawnRoutesLen) {
		msg := "withdrawn route length exceeds message length"
		e := NewMessageError(eCode, eSubCode, nil, msg)
		return e
	}

	for routelen := msg.WithdrawnRoutesLen; routelen > 0; {
		w := WithdrawnRoute{}
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
		msg := "message length isn't enough for path total attribute length"
		e := NewMessageError(eCode, eSubCode, nil, msg)
		return e
	}

	msg.TotalPathAttributeLen = binary.BigEndian.Uint16(data[0:2])
	data = data[2:]

	// check path attribute
	if len(data) < int(msg.TotalPathAttributeLen) {
		msg := "path total attribute length exceeds message length"
		e := NewMessageError(eCode, eSubCode, nil, msg)
		return e
	}

	for pathlen := msg.TotalPathAttributeLen; pathlen > 0; {
		p, err := getPathAttribute(data)
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

	for restlen := len(data); restlen > 0; {
		n := NLRInfo{}
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
	binary.BigEndian.PutUint16(wbuf, uint16(len(wbuf)-2))

	pbuf := make([]byte, 2)
	for _, p := range msg.PathAttributes {
		onepbuf, err := p.Serialize()
		if err != nil {
			return nil, err
		}
		pbuf = append(pbuf, onepbuf...)
	}
	binary.BigEndian.PutUint16(pbuf, uint16(len(pbuf)-2))

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

func NewBGPUpdateMessage(withdrawnRoutes []WithdrawnRoute, pathattrs []PathAttributeInterface, nlri []NLRInfo) *BGPMessage {
	return &BGPMessage{
		Header: BGPHeader{Type: BGP_MSG_UPDATE},
		Body:   &BGPUpdate{0, withdrawnRoutes, 0, pathattrs, nlri},
	}
}

type BGPNotification struct {
	ErrorCode    uint8
	ErrorSubcode uint8
	Data         []byte
}

func (msg *BGPNotification) DecodeFromBytes(data []byte) error {
	if len(data) < 2 {
		return fmt.Errorf("Not all Notificaiton bytes available")
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
		return fmt.Errorf("Not all RouteRefresh bytes available")
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
		return fmt.Errorf("Not all BGP message header")
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
	for i, _ := range buf[:16] {
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
		return nil, fmt.Errorf("Not all BGP message bytes available")
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

// BMP

type BMPHeader struct {
	Version uint8
	Length  uint32
	Type    uint8
}

const (
	BMP_HEADER_SIZE = 6
)

func (msg *BMPHeader) DecodeFromBytes(data []byte) error {
	msg.Version = data[0]
	if data[0] != 3 {
		return fmt.Errorf("error version")
	}
	msg.Length = binary.BigEndian.Uint32(data[1:5])
	msg.Type = data[5]
	return nil
}

func (msg *BMPHeader) Len() int {
	return int(msg.Length)
}

type BMPPeerHeader struct {
	PeerType          uint8
	IsPostPolicy      bool
	PeerDistinguisher uint64
	PeerAddress       net.IP
	PeerAS            uint32
	PeerBGPID         net.IP
	Timestamp         float64
	flags             uint8
}

func (msg *BMPPeerHeader) DecodeFromBytes(data []byte) error {
	data = data[6:]

	msg.PeerType = data[0]
	flags := data[1]
	msg.flags = flags
	if flags&1<<6 == 1 {
		msg.IsPostPolicy = true
	} else {
		msg.IsPostPolicy = false
	}
	msg.PeerDistinguisher = binary.BigEndian.Uint64(data[2:10])
	if flags&1<<7 == 1 {
		msg.PeerAddress = data[10:26]
	} else {
		msg.PeerAddress = data[10:14]
	}
	msg.PeerAS = binary.BigEndian.Uint32(data[26:30])
	msg.PeerBGPID = data[30:34]

	timestamp1 := binary.BigEndian.Uint32(data[34:38])
	timestamp2 := binary.BigEndian.Uint32(data[38:42])
	msg.Timestamp = float64(timestamp1) + float64(timestamp2)*math.Pow(10, -6)

	return nil
}

type BMPRouteMonitoring struct {
	BGPUpdate *BGPMessage
}

func (body *BMPRouteMonitoring) ParseBody(msg *BMPMessage, data []byte) error {
	update, err := ParseBGPMessage(data)
	if err != nil {
		return err
	}
	body.BGPUpdate = update
	return nil
}

const (
	BMP_STAT_TYPE_REJECTED = iota
	BMP_STAT_TYPE_DUPLICATE_PREFIX
	BMP_STAT_TYPE_DUPLICATE_WITHDRAW
	BMP_STAT_TYPE_INV_UPDATE_DUE_TO_CLUSTER_LIST_LOOP
	BMP_STAT_TYPE_INV_UPDATE_DUE_TO_AS_PATH_LOOP
	BMP_STAT_TYPE_INV_UPDATE_DUE_TO_ORIGINATOR_ID
	BMP_STAT_TYPE_INV_UPDATE_DUE_TO_AS_CONFED_LOOP
	BMP_STAT_TYPE_ADJ_RIB_IN
	BMP_STAT_TYPE_LOC_RIB
)

type BMPStatsTLV struct {
	Type   uint16
	Length uint16
	Value  uint64
}

type BMPStatisticsReport struct {
	Stats []BMPStatsTLV
}

const (
	BMP_PEER_DOWN_REASON_UNKNOWN = iota
	BMP_PEER_DOWN_REASON_LOCAL_BGP_NOTIFICATION
	BMP_PEER_DOWN_REASON_LOCAL_NO_NOTIFICATION
	BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION
	BMP_PEER_DOWN_REASON_REMOTE_NO_NOTIFICATION
)

type BMPPeerDownNotification struct {
	Reason          uint8
	BGPNotification *BGPMessage
	Data            []byte
}

func (body *BMPPeerDownNotification) ParseBody(msg *BMPMessage, data []byte) error {
	body.Reason = data[0]
	data = data[1:]
	if body.Reason == BMP_PEER_DOWN_REASON_LOCAL_BGP_NOTIFICATION || body.Reason == BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION {
		notification, err := ParseBGPMessage(data)
		if err != nil {
			return err
		}
		body.BGPNotification = notification
	} else {
		body.Data = data
	}
	return nil
}

type BMPPeerUpNotification struct {
	LocalAddress    net.IP
	LocalPort       uint16
	RemotePort      uint16
	SentOpenMsg     *BGPMessage
	ReceivedOpenMsg *BGPMessage
}

func (body *BMPPeerUpNotification) ParseBody(msg *BMPMessage, data []byte) error {
	if msg.PeerHeader.flags&1<<7 == 1 {
		body.LocalAddress = data[:16]
	} else {
		body.LocalAddress = data[:4]
	}

	body.LocalPort = binary.BigEndian.Uint16(data[16:18])
	body.RemotePort = binary.BigEndian.Uint16(data[18:20])

	data = data[20:]
	sentopen, err := ParseBGPMessage(data)
	if err != nil {
		return err
	}
	body.SentOpenMsg = sentopen
	data = data[body.SentOpenMsg.Header.Len:]
	body.ReceivedOpenMsg, err = ParseBGPMessage(data)
	if err != nil {
		return err
	}
	return nil
}

func (body *BMPStatisticsReport) ParseBody(msg *BMPMessage, data []byte) error {
	_ = binary.BigEndian.Uint32(data[0:4])
	data = data[4:]
	for len(data) >= 4 {
		s := BMPStatsTLV{}
		s.Type = binary.BigEndian.Uint16(data[0:2])
		s.Length = binary.BigEndian.Uint16(data[2:4])

		if s.Type == BMP_STAT_TYPE_ADJ_RIB_IN || s.Type == BMP_STAT_TYPE_LOC_RIB {
			s.Value = binary.BigEndian.Uint64(data[4:12])
		} else {
			s.Value = uint64(binary.BigEndian.Uint32(data[4:8]))
		}
		body.Stats = append(body.Stats, s)
		data = data[4+s.Length:]
	}
	return nil
}

type BMPTLV struct {
	Type   uint16
	Length uint16
	Value  []byte
}

type BMPInitiation struct {
	Info []BMPTLV
}

func (body *BMPInitiation) ParseBody(msg *BMPMessage, data []byte) error {
	for len(data) >= 4 {
		tlv := BMPTLV{}
		tlv.Type = binary.BigEndian.Uint16(data[0:2])
		tlv.Length = binary.BigEndian.Uint16(data[2:4])
		tlv.Value = data[4 : 4+tlv.Length]

		body.Info = append(body.Info, tlv)
		data = data[4+tlv.Length:]
	}
	return nil
}

type BMPTermination struct {
	Info []BMPTLV
}

func (body *BMPTermination) ParseBody(msg *BMPMessage, data []byte) error {
	for len(data) >= 4 {
		tlv := BMPTLV{}
		tlv.Type = binary.BigEndian.Uint16(data[0:2])
		tlv.Length = binary.BigEndian.Uint16(data[2:4])
		tlv.Value = data[4 : 4+tlv.Length]

		body.Info = append(body.Info, tlv)
		data = data[4+tlv.Length:]
	}
	return nil
}

type BMPBody interface {
	ParseBody(*BMPMessage, []byte) error
}

type BMPMessage struct {
	Header     BMPHeader
	PeerHeader BMPPeerHeader
	Body       BMPBody
}

func (msg *BMPMessage) Len() int {
	return int(msg.Header.Length)
}

const (
	BMP_MSG_ROUTE_MONITORING = iota
	BMP_MSG_STATISTICS_REPORT
	BMP_MSG_PEER_DOWN_NOTIFICATION
	BMP_MSG_PEER_UP_NOTIFICATION
	BMP_MSG_INITIATION
	BMP_MSG_TERMINATION
)

// move somewhere else
func ReadBMPMessage(conn net.Conn) (*BMPMessage, error) {
	buf := make([]byte, BMP_HEADER_SIZE)
	for offset := 0; offset < BMP_HEADER_SIZE; {
		rlen, err := conn.Read(buf[offset:])
		if err != nil {
			return nil, err
		}
		offset += rlen
	}

	h := BMPHeader{}
	err := h.DecodeFromBytes(buf)
	if err != nil {
		return nil, err
	}

	data := make([]byte, h.Len())
	copy(data, buf)
	data = data[BMP_HEADER_SIZE:]
	for offset := 0; offset < h.Len()-BMP_HEADER_SIZE; {
		rlen, err := conn.Read(data[offset:])
		if err != nil {
			return nil, err
		}
		offset += rlen
	}
	msg := &BMPMessage{Header: h}

	switch msg.Header.Type {
	case BMP_MSG_ROUTE_MONITORING:
		msg.Body = &BMPRouteMonitoring{}
	case BMP_MSG_STATISTICS_REPORT:
		msg.Body = &BMPStatisticsReport{}
	case BMP_MSG_PEER_DOWN_NOTIFICATION:
		msg.Body = &BMPPeerDownNotification{}
	case BMP_MSG_PEER_UP_NOTIFICATION:
		msg.Body = &BMPPeerUpNotification{}
	case BMP_MSG_INITIATION:
		msg.Body = &BMPInitiation{}
	case BMP_MSG_TERMINATION:
		msg.Body = &BMPTermination{}
	}

	if msg.Header.Type != BMP_MSG_INITIATION && msg.Header.Type != BMP_MSG_INITIATION {
		msg.PeerHeader.DecodeFromBytes(data)
		data = data[42:]
	}

	err = msg.Body.ParseBody(msg, data)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func ParseBMPMessage(data []byte) (*BMPMessage, error) {
	msg := &BMPMessage{}
	msg.Header.DecodeFromBytes(data)
	data = data[6:msg.Header.Length]

	switch msg.Header.Type {
	case BMP_MSG_ROUTE_MONITORING:
		msg.Body = &BMPRouteMonitoring{}
	case BMP_MSG_STATISTICS_REPORT:
		msg.Body = &BMPStatisticsReport{}
	case BMP_MSG_PEER_DOWN_NOTIFICATION:
		msg.Body = &BMPPeerDownNotification{}
	case BMP_MSG_PEER_UP_NOTIFICATION:
		msg.Body = &BMPPeerUpNotification{}
	case BMP_MSG_INITIATION:
		msg.Body = &BMPInitiation{}
	case BMP_MSG_TERMINATION:
		msg.Body = &BMPTermination{}
	}

	if msg.Header.Type != BMP_MSG_INITIATION && msg.Header.Type != BMP_MSG_INITIATION {
		msg.PeerHeader.DecodeFromBytes(data)
		data = data[42:]
	}

	err := msg.Body.ParseBody(msg, data)
	if err != nil {
		return nil, err
	}
	return msg, nil
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
