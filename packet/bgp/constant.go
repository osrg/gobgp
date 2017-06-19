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
	"fmt"
	"strings"
)

const AS_TRANS = 23456

const BGP_PORT = 179

type FSMState int

const (
	BGP_FSM_IDLE FSMState = iota
	BGP_FSM_CONNECT
	BGP_FSM_ACTIVE
	BGP_FSM_OPENSENT
	BGP_FSM_OPENCONFIRM
	BGP_FSM_ESTABLISHED
)

// partially taken from http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
type Protocol int

const (
	Unknown Protocol = iota
	ICMP             = 0x01
	IGMP             = 0x02
	TCP              = 0x06
	EGP              = 0x08
	IGP              = 0x09
	UDP              = 0x11
	RSVP             = 0x2e
	GRE              = 0x2f
	OSPF             = 0x59
	IPIP             = 0x5e
	PIM              = 0x67
	SCTP             = 0x84
)

var ProtocolNameMap = map[Protocol]string{
	Unknown: "unknown",
	ICMP:    "icmp",
	IGMP:    "igmp",
	TCP:     "tcp",
	EGP:     "egp",
	IGP:     "igp",
	UDP:     "udp",
	RSVP:    "rsvp",
	GRE:     "gre",
	OSPF:    "ospf",
	IPIP:    "ipip",
	PIM:     "pim",
	SCTP:    "sctp",
}

var ProtocolValueMap = map[string]Protocol{
	ProtocolNameMap[ICMP]: ICMP,
	ProtocolNameMap[IGMP]: IGMP,
	ProtocolNameMap[TCP]:  TCP,
	ProtocolNameMap[EGP]:  EGP,
	ProtocolNameMap[IGP]:  IGP,
	ProtocolNameMap[UDP]:  UDP,
	ProtocolNameMap[RSVP]: RSVP,
	ProtocolNameMap[GRE]:  GRE,
	ProtocolNameMap[OSPF]: OSPF,
	ProtocolNameMap[IPIP]: IPIP,
	ProtocolNameMap[PIM]:  PIM,
	ProtocolNameMap[SCTP]: SCTP,
}

func (p Protocol) String() string {
	name, ok := ProtocolNameMap[p]
	if !ok {
		return fmt.Sprintf("%d", p)
	}
	return name
}

type TCPFlag int

const (
	TCP_FLAG_FIN    = 0x01
	TCP_FLAG_SYN    = 0x02
	TCP_FLAG_RST    = 0x04
	TCP_FLAG_PUSH   = 0x08
	TCP_FLAG_ACK    = 0x10
	TCP_FLAG_URGENT = 0x20
	TCP_FLAG_ECE    = 0x40
	TCP_FLAG_CWR    = 0x80
)

var TCPFlagNameMap = map[TCPFlag]string{
	TCP_FLAG_FIN:    "F",
	TCP_FLAG_SYN:    "S",
	TCP_FLAG_RST:    "R",
	TCP_FLAG_PUSH:   "P",
	TCP_FLAG_ACK:    "A",
	TCP_FLAG_URGENT: "U",
	TCP_FLAG_CWR:    "C",
	TCP_FLAG_ECE:    "E",
}

var TCPFlagValueMap = map[string]TCPFlag{
	TCPFlagNameMap[TCP_FLAG_FIN]:    TCP_FLAG_FIN,
	TCPFlagNameMap[TCP_FLAG_SYN]:    TCP_FLAG_SYN,
	TCPFlagNameMap[TCP_FLAG_RST]:    TCP_FLAG_RST,
	TCPFlagNameMap[TCP_FLAG_PUSH]:   TCP_FLAG_PUSH,
	TCPFlagNameMap[TCP_FLAG_ACK]:    TCP_FLAG_ACK,
	TCPFlagNameMap[TCP_FLAG_URGENT]: TCP_FLAG_URGENT,
	TCPFlagNameMap[TCP_FLAG_CWR]:    TCP_FLAG_CWR,
	TCPFlagNameMap[TCP_FLAG_ECE]:    TCP_FLAG_ECE,
}

type BitmaskFlagOp int

const (
	BITMASK_FLAG_OP_OR    = 0x00
	BITMASK_FLAG_OP_AND   = 0x40
	BITMASK_FLAG_OP_END   = 0x80
	BITMASK_FLAG_OP_NOT   = 0x02
	BITMASK_FLAG_OP_MATCH = 0x01
)

var BitmaskFlagOpNameMap = map[BitmaskFlagOp]string{
	BITMASK_FLAG_OP_OR:    " ",
	BITMASK_FLAG_OP_AND:   "&",
	BITMASK_FLAG_OP_END:   "E",
	BITMASK_FLAG_OP_NOT:   "!",
	BITMASK_FLAG_OP_MATCH: "=",
}

var BitmaskFlagOpValueMap = map[string]BitmaskFlagOp{
	BitmaskFlagOpNameMap[BITMASK_FLAG_OP_OR]:    BITMASK_FLAG_OP_OR,
	BitmaskFlagOpNameMap[BITMASK_FLAG_OP_AND]:   BITMASK_FLAG_OP_AND,
	BitmaskFlagOpNameMap[BITMASK_FLAG_OP_END]:   BITMASK_FLAG_OP_END,
	BitmaskFlagOpNameMap[BITMASK_FLAG_OP_NOT]:   BITMASK_FLAG_OP_NOT,
	BitmaskFlagOpNameMap[BITMASK_FLAG_OP_MATCH]: BITMASK_FLAG_OP_MATCH,
}

type FragmentFlag int

const (
	FRAG_FLAG_NOT   = 0x00
	FRAG_FLAG_DONT  = 0x01
	FRAG_FLAG_IS    = 0x02
	FRAG_FLAG_FIRST = 0x04
	FRAG_FLAG_LAST  = 0x08
)

var FragmentFlagNameMap = map[FragmentFlag]string{
	FRAG_FLAG_NOT:   "not-a-fragment",
	FRAG_FLAG_DONT:  "dont-fragment",
	FRAG_FLAG_IS:    "is-fragment",
	FRAG_FLAG_FIRST: "first-fragment",
	FRAG_FLAG_LAST:  "last-fragment",
}

var FragmentFlagValueMap = map[string]FragmentFlag{
	FragmentFlagNameMap[FRAG_FLAG_NOT]:   FRAG_FLAG_NOT,
	FragmentFlagNameMap[FRAG_FLAG_DONT]:  FRAG_FLAG_DONT,
	FragmentFlagNameMap[FRAG_FLAG_IS]:    FRAG_FLAG_IS,
	FragmentFlagNameMap[FRAG_FLAG_FIRST]: FRAG_FLAG_FIRST,
	FragmentFlagNameMap[FRAG_FLAG_LAST]:  FRAG_FLAG_LAST,
}

type DECNumOp int

const (
	DEC_NUM_OP_TRUE   = 0x00 // true always with END bit set
	DEC_NUM_OP_EQ     = 0x01
	DEC_NUM_OP_GT     = 0x02
	DEC_NUM_OP_GT_EQ  = 0x03
	DEC_NUM_OP_LT     = 0x04
	DEC_NUM_OP_LT_EQ  = 0x05
	DEC_NUM_OP_NOT_EQ = 0x06
	DEC_NUM_OP_FALSE  = 0x07 // true always with END bit set
)

var DECNumOpNameMap = map[DECNumOp]string{
	DEC_NUM_OP_TRUE:   "true",
	DEC_NUM_OP_EQ:     "==",
	DEC_NUM_OP_GT:     ">",
	DEC_NUM_OP_GT_EQ:  ">=",
	DEC_NUM_OP_LT:     "<",
	DEC_NUM_OP_LT_EQ:  "<=",
	DEC_NUM_OP_NOT_EQ: "!=",
	DEC_NUM_OP_FALSE:  "false",
}

var DECNumOpValueMap = map[string]DECNumOp{
	DECNumOpNameMap[DEC_NUM_OP_TRUE]:   DEC_NUM_OP_TRUE,
	DECNumOpNameMap[DEC_NUM_OP_EQ]:     DEC_NUM_OP_EQ,
	DECNumOpNameMap[DEC_NUM_OP_GT]:     DEC_NUM_OP_GT,
	DECNumOpNameMap[DEC_NUM_OP_GT_EQ]:  DEC_NUM_OP_GT_EQ,
	DECNumOpNameMap[DEC_NUM_OP_LT]:     DEC_NUM_OP_LT,
	DECNumOpNameMap[DEC_NUM_OP_LT_EQ]:  DEC_NUM_OP_LT_EQ,
	DECNumOpNameMap[DEC_NUM_OP_NOT_EQ]: DEC_NUM_OP_NOT_EQ,
	DECNumOpNameMap[DEC_NUM_OP_FALSE]:  DEC_NUM_OP_FALSE,
}

type DECLogicOp int

const (
	DEC_LOGIC_OP_END = 0x80
	DEC_LOGIC_OP_OR  = 0x00
	DEC_LOGIC_OP_AND = 0x40
)

var DECLogicOpNameMap = map[DECLogicOp]string{
	DEC_LOGIC_OP_OR:  " ",
	DEC_LOGIC_OP_AND: "&",
	DEC_LOGIC_OP_END: "E",
}

var DECLogicOpValueMap = map[string]DECLogicOp{
	DECLogicOpNameMap[DEC_LOGIC_OP_OR]:  DEC_LOGIC_OP_OR,
	DECLogicOpNameMap[DEC_LOGIC_OP_AND]: DEC_LOGIC_OP_AND,
	DECLogicOpNameMap[DEC_LOGIC_OP_END]: DEC_LOGIC_OP_END,
}

func (f TCPFlag) String() string {
	ss := make([]string, 0, 6)
	for _, v := range []TCPFlag{TCP_FLAG_FIN, TCP_FLAG_SYN, TCP_FLAG_RST, TCP_FLAG_PUSH, TCP_FLAG_ACK, TCP_FLAG_URGENT, TCP_FLAG_CWR, TCP_FLAG_ECE} {
		if f&v > 0 {
			ss = append(ss, TCPFlagNameMap[v])
		}
	}
	return strings.Join(ss, "|")
}

type EthernetType int

const (
	IPv4            EthernetType = 0x0800
	ARP             EthernetType = 0x0806
	RARP            EthernetType = 0x8035
	VMTP            EthernetType = 0x805B
	APPLE_TALK      EthernetType = 0x809B
	AARP            EthernetType = 0x80F3
	IPX             EthernetType = 0x8137
	SNMP            EthernetType = 0x814C
	NET_BIOS        EthernetType = 0x8191
	XTP             EthernetType = 0x817D
	IPv6            EthernetType = 0x86DD
	PPPoE_DISCOVERY EthernetType = 0x8863
	PPPoE_SESSION   EthernetType = 0x8864
	LOOPBACK        EthernetType = 0x9000
)

var EthernetTypeNameMap = map[EthernetType]string{
	IPv4:            "ipv4",
	ARP:             "arp",
	RARP:            "rarp",
	VMTP:            "vmtp",
	APPLE_TALK:      "apple-talk",
	AARP:            "aarp",
	IPX:             "ipx",
	SNMP:            "snmp",
	NET_BIOS:        "net-bios",
	XTP:             "xtp",
	IPv6:            "ipv6",
	PPPoE_DISCOVERY: "pppoe-discovery",
	PPPoE_SESSION:   "pppoe-session",
	LOOPBACK:        "loopback",
}

var EthernetTypeValueMap = map[string]EthernetType{
	EthernetTypeNameMap[IPv4]:            IPv4,
	EthernetTypeNameMap[ARP]:             ARP,
	EthernetTypeNameMap[RARP]:            RARP,
	EthernetTypeNameMap[VMTP]:            VMTP,
	EthernetTypeNameMap[APPLE_TALK]:      APPLE_TALK,
	EthernetTypeNameMap[AARP]:            AARP,
	EthernetTypeNameMap[IPX]:             IPX,
	EthernetTypeNameMap[SNMP]:            SNMP,
	EthernetTypeNameMap[NET_BIOS]:        NET_BIOS,
	EthernetTypeNameMap[XTP]:             XTP,
	EthernetTypeNameMap[IPv6]:            IPv6,
	EthernetTypeNameMap[PPPoE_DISCOVERY]: PPPoE_DISCOVERY,
	EthernetTypeNameMap[PPPoE_SESSION]:   PPPoE_SESSION,
	EthernetTypeNameMap[LOOPBACK]:        LOOPBACK,
}

func (t EthernetType) String() string {
	n, ok := EthernetTypeNameMap[t]
	if !ok {
		return fmt.Sprintf("%d", t)
	}
	return n
}
