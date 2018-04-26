// Copyright (C) 2014, 2015 Nippon Telegraph and Telephone Corporation.
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

package zebra

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"

	"github.com/osrg/gobgp/packet/bgp"
	log "github.com/sirupsen/logrus"
)

const (
	HEADER_MARKER     = 255
	FRR_HEADER_MARKER = 254
	INTERFACE_NAMSIZ  = 20
)

// Internal Interface Status.
type INTERFACE_STATUS uint8

const (
	INTERFACE_ACTIVE        INTERFACE_STATUS = 0x01
	INTERFACE_SUB           INTERFACE_STATUS = 0x02
	INTERFACE_LINKDETECTION INTERFACE_STATUS = 0x04
	INTERFACE_VRF_LOOPBACK  INTERFACE_STATUS = 0x08
)

// Interface Link Layer Types.
//go:generate stringer -type=LINK_TYPE
type LINK_TYPE uint32

const (
	LINK_TYPE_UNKNOWN LINK_TYPE = iota
	LINK_TYPE_ETHER
	LINK_TYPE_EETHER
	LINK_TYPE_AX25
	LINK_TYPE_PRONET
	LINK_TYPE_IEEE802
	LINK_TYPE_ARCNET
	LINK_TYPE_APPLETLK
	LINK_TYPE_DLCI
	LINK_TYPE_ATM
	LINK_TYPE_METRICOM
	LINK_TYPE_IEEE1394
	LINK_TYPE_EUI64
	LINK_TYPE_INFINIBAND
	LINK_TYPE_SLIP
	LINK_TYPE_CSLIP
	LINK_TYPE_SLIP6
	LINK_TYPE_CSLIP6
	LINK_TYPE_RSRVD
	LINK_TYPE_ADAPT
	LINK_TYPE_ROSE
	LINK_TYPE_X25
	LINK_TYPE_PPP
	LINK_TYPE_CHDLC
	LINK_TYPE_LAPB
	LINK_TYPE_RAWHDLC
	LINK_TYPE_IPIP
	LINK_TYPE_IPIP6
	LINK_TYPE_FRAD
	LINK_TYPE_SKIP
	LINK_TYPE_LOOPBACK
	LINK_TYPE_LOCALTLK
	LINK_TYPE_FDDI
	LINK_TYPE_SIT
	LINK_TYPE_IPDDP
	LINK_TYPE_IPGRE
	LINK_TYPE_IP6GRE
	LINK_TYPE_PIMREG
	LINK_TYPE_HIPPI
	LINK_TYPE_ECONET
	LINK_TYPE_IRDA
	LINK_TYPE_FCPP
	LINK_TYPE_FCAL
	LINK_TYPE_FCPL
	LINK_TYPE_FCFABRIC
	LINK_TYPE_IEEE802_TR
	LINK_TYPE_IEEE80211
	LINK_TYPE_IEEE80211_RADIOTAP
	LINK_TYPE_IEEE802154
	LINK_TYPE_IEEE802154_PHY
)

const VRF_DEFAULT = 0

func HeaderSize(version uint8) uint16 {
	switch version {
	case 3, 4:
		return 8
	case 5:
		return 10
	default:
		return 6
	}
}

func (t INTERFACE_STATUS) String() string {
	ss := make([]string, 0, 3)
	if t&INTERFACE_ACTIVE > 0 {
		ss = append(ss, "ACTIVE")
	}
	if t&INTERFACE_SUB > 0 {
		ss = append(ss, "SUB")
	}
	if t&INTERFACE_LINKDETECTION > 0 {
		ss = append(ss, "LINKDETECTION")
	}
	if t&INTERFACE_VRF_LOOPBACK > 0 {
		ss = append(ss, "VRF_LOOPBACK")
	}
	return strings.Join(ss, "|")
}

// Interface Connected Address Flags
type INTERFACE_ADDRESS_FLAG uint8

const (
	INTERFACE_ADDRESS_SECONDARY  INTERFACE_ADDRESS_FLAG = 0x01
	INTERFACE_ADDRESS_PEER       INTERFACE_ADDRESS_FLAG = 0x02
	INTERFACE_ADDRESS_UNNUMBERED INTERFACE_ADDRESS_FLAG = 0x04
)

func (t INTERFACE_ADDRESS_FLAG) String() string {
	ss := make([]string, 0, 3)
	if t&INTERFACE_ADDRESS_SECONDARY > 0 {
		ss = append(ss, "SECONDARY")
	}
	if t&INTERFACE_ADDRESS_PEER > 0 {
		ss = append(ss, "PEER")
	}
	if t&INTERFACE_ADDRESS_UNNUMBERED > 0 {
		ss = append(ss, "UNNUMBERED")
	}
	return strings.Join(ss, "|")
}

// Address Family Identifier.
//go:generate stringer -type=AFI
type AFI uint8

const (
	AFI_IP    AFI = 1
	AFI_IP6   AFI = 2
	AFI_ETHER AFI = 3
	AFI_MAX   AFI = 4
)

// Socket Address Family Identifier.
//go:generate stringer -type=SOCK_AF
type SOCK_AF uint8

const (
	SOCK_AF_UNSPEC = iota
	SOCK_AF_UNIX
	SOCK_AF_INET
	SOCK_AF_AX25
	SOCK_AF_IPX
	SOCK_AF_APPLETALK
	SOCK_AF_NETROM
	SOCK_AF_BRIDGE
	SOCK_AF_AAL5
	SOCK_AF_X25
	SOCK_AF_INET6
	SOCK_AF_MAX
)

// Subsequent Address Family Identifier.
//go:generate stringer -type=SAFI
type SAFI uint8

const (
	_ SAFI = iota
	SAFI_UNICAST
	SAFI_MULTICAST
	SAFI_RESERVED_3
	SAFI_MPLS_VPN
	SAFI_MAX
)

// API Types.
//go:generate stringer -type=API_TYPE
type API_TYPE uint16

// For Quagga.
const (
	_ API_TYPE = iota
	INTERFACE_ADD
	INTERFACE_DELETE
	INTERFACE_ADDRESS_ADD
	INTERFACE_ADDRESS_DELETE
	INTERFACE_UP
	INTERFACE_DOWN
	IPV4_ROUTE_ADD
	IPV4_ROUTE_DELETE
	IPV6_ROUTE_ADD
	IPV6_ROUTE_DELETE
	REDISTRIBUTE_ADD
	REDISTRIBUTE_DELETE
	REDISTRIBUTE_DEFAULT_ADD
	REDISTRIBUTE_DEFAULT_DELETE
	IPV4_NEXTHOP_LOOKUP
	IPV6_NEXTHOP_LOOKUP
	IPV4_IMPORT_LOOKUP
	IPV6_IMPORT_LOOKUP
	INTERFACE_RENAME
	ROUTER_ID_ADD
	ROUTER_ID_DELETE
	ROUTER_ID_UPDATE
	HELLO
	IPV4_NEXTHOP_LOOKUP_MRIB
	VRF_UNREGISTER
	INTERFACE_LINK_PARAMS
	NEXTHOP_REGISTER
	NEXTHOP_UNREGISTER
	NEXTHOP_UPDATE
	MESSAGE_MAX
)

// For FRRouting: version 4.
const (
	FRR_INTERFACE_ADD API_TYPE = iota
	FRR_INTERFACE_DELETE
	FRR_INTERFACE_ADDRESS_ADD
	FRR_INTERFACE_ADDRESS_DELETE
	FRR_INTERFACE_UP
	FRR_INTERFACE_DOWN
	FRR_IPV4_ROUTE_ADD
	FRR_IPV4_ROUTE_DELETE
	FRR_IPV6_ROUTE_ADD
	FRR_IPV6_ROUTE_DELETE
	FRR_REDISTRIBUTE_ADD
	FRR_REDISTRIBUTE_DELETE
	FRR_REDISTRIBUTE_DEFAULT_ADD
	FRR_REDISTRIBUTE_DEFAULT_DELETE
	FRR_ROUTER_ID_ADD
	FRR_ROUTER_ID_DELETE
	FRR_ROUTER_ID_UPDATE
	FRR_HELLO
	FRR_NEXTHOP_REGISTER
	FRR_NEXTHOP_UNREGISTER
	FRR_NEXTHOP_UPDATE
	FRR_INTERFACE_NBR_ADDRESS_ADD
	FRR_INTERFACE_NBR_ADDRESS_DELETE
	FRR_INTERFACE_BFD_DEST_UPDATE
	FRR_IMPORT_ROUTE_REGISTER
	FRR_IMPORT_ROUTE_UNREGISTER
	FRR_IMPORT_CHECK_UPDATE
	FRR_IPV4_ROUTE_IPV6_NEXTHOP_ADD
	FRR_BFD_DEST_REGISTER
	FRR_BFD_DEST_DEREGISTER
	FRR_BFD_DEST_UPDATE
	FRR_BFD_DEST_REPLAY
	FRR_REDISTRIBUTE_IPV4_ADD
	FRR_REDISTRIBUTE_IPV4_DEL
	FRR_REDISTRIBUTE_IPV6_ADD
	FRR_REDISTRIBUTE_IPV6_DEL
	FRR_VRF_UNREGISTER
	FRR_VRF_ADD
	FRR_VRF_DELETE
	FRR_INTERFACE_VRF_UPDATE
	FRR_BFD_CLIENT_REGISTER
	FRR_INTERFACE_ENABLE_RADV
	FRR_INTERFACE_DISABLE_RADV
	FRR_IPV4_NEXTHOP_LOOKUP_MRIB
	FRR_INTERFACE_LINK_PARAMS
	FRR_MPLS_LABELS_ADD
	FRR_MPLS_LABELS_DELETE
	FRR_IPV4_NEXTHOP_ADD
	FRR_IPV4_NEXTHOP_DELETE
	FRR_IPV6_NEXTHOP_ADD
	FRR_IPV6_NEXTHOP_DELETE
	FRR_IPMR_ROUTE_STATS
	FRR_LABEL_MANAGER_CONNECT
	FRR_GET_LABEL_CHUNK
	FRR_RELEASE_LABEL_CHUNK
	FRR_PW_ADD
	FRR_PW_DELETE
	FRR_PW_SET
	FRR_PW_UNSET
	FRR_PW_STATUS_UPDATE
)

// For FRRouting: version 5.
const (
	FRR5_INTERFACE_ADD API_TYPE = iota
	FRR5_INTERFACE_DELETE
	FRR5_INTERFACE_ADDRESS_ADD
	FRR5_INTERFACE_ADDRESS_DELETE
	FRR5_INTERFACE_UP
	FRR5_INTERFACE_DOWN
	FRR5_INTERFACE_SET_MASTER
	FRR5_ROUTE_ADD
	FRR5_ROUTE_DELETE
	FRR5_ROUTE_NOTIFY_OWNER
	FRR5_IPV4_ROUTE_ADD
	FRR5_IPV4_ROUTE_DELETE
	FRR5_IPV6_ROUTE_ADD
	FRR5_IPV6_ROUTE_DELETE
	FRR5_REDISTRIBUTE_ADD
	FRR5_REDISTRIBUTE_DELETE
	FRR5_REDISTRIBUTE_DEFAULT_ADD
	FRR5_REDISTRIBUTE_DEFAULT_DELETE
	FRR5_ROUTER_ID_ADD
	FRR5_ROUTER_ID_DELETE
	FRR5_ROUTER_ID_UPDATE
	FRR5_HELLO
	FRR5_NEXTHOP_REGISTER
	FRR5_NEXTHOP_UNREGISTER
	FRR5_NEXTHOP_UPDATE
	FRR5_INTERFACE_NBR_ADDRESS_ADD
	FRR5_INTERFACE_NBR_ADDRESS_DELETE
	FRR5_INTERFACE_BFD_DEST_UPDATE
	FRR5_IMPORT_ROUTE_REGISTER
	FRR5_IMPORT_ROUTE_UNREGISTER
	FRR5_IMPORT_CHECK_UPDATE
	FRR5_IPV4_ROUTE_IPV6_NEXTHOP_ADD
	FRR5_BFD_DEST_REGISTER
	FRR5_BFD_DEST_DEREGISTER
	FRR5_BFD_DEST_UPDATE
	FRR5_BFD_DEST_REPLAY
	FRR5_REDISTRIBUTE_ROUTE_ADD
	FRR5_REDISTRIBUTE_ROUTE_DEL
	FRR5_VRF_UNREGISTER
	FRR5_VRF_ADD
	FRR5_VRF_DELETE
	FRR5_VRF_LABEL
	FRR5_INTERFACE_VRF_UPDATE
	FRR5_BFD_CLIENT_REGISTER
	FRR5_INTERFACE_ENABLE_RADV
	FRR5_INTERFACE_DISABLE_RADV
	FRR5_IPV4_NEXTHOP_LOOKUP_MRIB
	FRR5_INTERFACE_LINK_PARAMS
	FRR5_MPLS_LABELS_ADD
	FRR5_MPLS_LABELS_DELETE
	FRR5_IPMR_ROUTE_STATS
	FRR5_LABEL_MANAGER_CONNECT
	FRR5_GET_LABEL_CHUNK
	FRR5_RELEASE_LABEL_CHUNK
	FRR5_FEC_REGISTER
	FRR5_FEC_UNREGISTER
	FRR5_FEC_UPDATE
	FRR5_ADVERTISE_DEFAULT_GW
	FRR5_ADVERTISE_SUBNET
	FRR5_ADVERTISE_ALL_VNI
	FRR5_VNI_ADD
	FRR5_VNI_DEL
	FRR5_L3VNI_ADD
	FRR5_L3VNI_DEL
	FRR5_REMOTE_VTEP_ADD
	FRR5_REMOTE_VTEP_DEL
	FRR5_MACIP_ADD
	FRR5_MACIP_DEL
	FRR5_IP_PREFIX_ROUTE_ADD
	FRR5_IP_PREFIX_ROUTE_DEL
	FRR5_REMOTE_MACIP_ADD
	FRR5_REMOTE_MACIP_DEL
	FRR5_PW_ADD
	FRR5_PW_DELETE
	FRR5_PW_SET
	FRR5_PW_UNSET
	FRR5_PW_STATUS_UPDATE
)

// Route Types.
//go:generate stringer -type=ROUTE_TYPE
type ROUTE_TYPE uint8

// For Quagga.
const (
	ROUTE_SYSTEM ROUTE_TYPE = iota
	ROUTE_KERNEL
	ROUTE_CONNECT
	ROUTE_STATIC
	ROUTE_RIP
	ROUTE_RIPNG
	ROUTE_OSPF
	ROUTE_OSPF6
	ROUTE_ISIS
	ROUTE_BGP
	ROUTE_PIM
	ROUTE_HSLS
	ROUTE_OLSR
	ROUTE_BABEL
	ROUTE_MAX
)

// For FRRouting: versions 4.
const (
	FRR_ROUTE_SYSTEM ROUTE_TYPE = iota
	FRR_ROUTE_KERNEL
	FRR_ROUTE_CONNECT
	FRR_ROUTE_STATIC
	FRR_ROUTE_RIP
	FRR_ROUTE_RIPNG
	FRR_ROUTE_OSPF
	FRR_ROUTE_OSPF6
	FRR_ROUTE_ISIS
	FRR_ROUTE_BGP
	FRR_ROUTE_PIM
	FRR_ROUTE_HSLS
	FRR_ROUTE_OLSR
	FRR_ROUTE_TABLE
	FRR_ROUTE_LDP
	FRR_ROUTE_VNC
	FRR_ROUTE_VNC_DIRECT
	FRR_ROUTE_VNC_DIRECT_RH
	FRR_ROUTE_BGP_DIRECT
	FRR_ROUTE_BGP_DIRECT_EXT
	FRR_ROUTE_ALL
	FRR_ROUTE_MAX
)

// For FRRouting: versions 5.
const (
	FRR5_ROUTE_SYSTEM ROUTE_TYPE = iota
	FRR5_ROUTE_KERNEL
	FRR5_ROUTE_CONNECT
	FRR5_ROUTE_STATIC
	FRR5_ROUTE_RIP
	FRR5_ROUTE_RIPNG
	FRR5_ROUTE_OSPF
	FRR5_ROUTE_OSPF6
	FRR5_ROUTE_ISIS
	FRR5_ROUTE_BGP
	FRR5_ROUTE_PIM
	FRR5_ROUTE_EIGRP
	FRR5_ROUTE_NHRP
	FRR5_ROUTE_HSLS
	FRR5_ROUTE_OLSR
	FRR5_ROUTE_TABLE
	FRR5_ROUTE_LDP
	FRR5_ROUTE_VNC
	FRR5_ROUTE_VNC_DIRECT
	FRR5_ROUTE_VNC_DIRECT_RH
	FRR5_ROUTE_BGP_DIRECT
	FRR5_ROUTE_BGP_DIRECT_EXT
	FRR5_ROUTE_BABEL
	FRR5_ROUTE_SHARP
	FRR5_ROUTE_ALL
	FRR5_ROUTE_MAX
)

var routeTypeValueMap = map[string]ROUTE_TYPE{
	"system":             ROUTE_SYSTEM,
	"kernel":             ROUTE_KERNEL,
	"connect":            ROUTE_CONNECT, // hack for backyard compatibility
	"directly-connected": ROUTE_CONNECT,
	"static":             ROUTE_STATIC,
	"rip":                ROUTE_RIP,
	"ripng":              ROUTE_RIPNG,
	"ospf":               ROUTE_OSPF,
	"ospf3":              ROUTE_OSPF6,
	"isis":               ROUTE_ISIS,
	"bgp":                ROUTE_BGP,
	"pim":                ROUTE_PIM,
	"hsls":               ROUTE_HSLS,
	"olsr":               ROUTE_OLSR,
	"babel":              ROUTE_BABEL,
	"table":              FRR_ROUTE_TABLE,
	"ldp":                FRR_ROUTE_LDP,
	"vnc":                FRR_ROUTE_VNC,
	"vnc-direct":         FRR_ROUTE_VNC_DIRECT,
	"vnc-direct-rh":      FRR_ROUTE_VNC_DIRECT_RH,
	"bgp-direct":         FRR_ROUTE_BGP_DIRECT,
	"bgp-direct-ext":     FRR_ROUTE_BGP_DIRECT_EXT,
	"all":                FRR_ROUTE_ALL,
	"eigrp":              FRR5_ROUTE_EIGRP,
	"nhrp":               FRR5_ROUTE_NHRP,
	"sharp":              FRR5_ROUTE_SHARP,
}

func RouteTypeFromString(typ string) (ROUTE_TYPE, error) {
	t, ok := routeTypeValueMap[typ]
	if ok {
		return t, nil
	}
	return t, fmt.Errorf("unknown route type: %s", typ)
}

// API Message Flags.
type MESSAGE_FLAG uint8

// For Quagga.
const (
	MESSAGE_NEXTHOP  MESSAGE_FLAG = 0x01
	MESSAGE_IFINDEX  MESSAGE_FLAG = 0x02
	MESSAGE_DISTANCE MESSAGE_FLAG = 0x04
	MESSAGE_METRIC   MESSAGE_FLAG = 0x08
	MESSAGE_MTU      MESSAGE_FLAG = 0x10
	MESSAGE_TAG      MESSAGE_FLAG = 0x20
)

func (t MESSAGE_FLAG) String() string {
	var ss []string
	if t&MESSAGE_NEXTHOP > 0 {
		ss = append(ss, "NEXTHOP")
	}
	if t&MESSAGE_IFINDEX > 0 {
		ss = append(ss, "IFINDEX")
	}
	if t&MESSAGE_DISTANCE > 0 {
		ss = append(ss, "DISTANCE")
	}
	if t&MESSAGE_METRIC > 0 {
		ss = append(ss, "METRIC")
	}
	if t&MESSAGE_MTU > 0 {
		ss = append(ss, "MTU")
	}
	if t&MESSAGE_TAG > 0 {
		ss = append(ss, "TAG")
	}
	return strings.Join(ss, "|")
}

// For FRRouting: version 4
const (
	FRR_MESSAGE_NEXTHOP  MESSAGE_FLAG = 0x01
	FRR_MESSAGE_IFINDEX  MESSAGE_FLAG = 0x02
	FRR_MESSAGE_DISTANCE MESSAGE_FLAG = 0x04
	FRR_MESSAGE_METRIC   MESSAGE_FLAG = 0x08
	FRR_MESSAGE_TAG      MESSAGE_FLAG = 0x10
	FRR_MESSAGE_MTU      MESSAGE_FLAG = 0x20
	FRR_MESSAGE_SRCPFX   MESSAGE_FLAG = 0x40
)

const (
	FRR5_MESSAGE_NEXTHOP  MESSAGE_FLAG = 0x01
	FRR5_MESSAGE_DISTANCE MESSAGE_FLAG = 0x02
	FRR5_MESSAGE_METRIC   MESSAGE_FLAG = 0x04
	FRR5_MESSAGE_TAG      MESSAGE_FLAG = 0x08
	FRR5_MESSAGE_MTU      MESSAGE_FLAG = 0x10
	FRR5_MESSAGE_SRCPFX   MESSAGE_FLAG = 0x20
	FRR5_MESSAGE_LABEL    MESSAGE_FLAG = 0x40
)

// Message Flags
type FLAG uint64

// For Quagga and FRRouting version 4.
const (
	FLAG_INTERNAL     FLAG = 0x01
	FLAG_SELFROUTE    FLAG = 0x02
	FLAG_BLACKHOLE    FLAG = 0x04
	FLAG_IBGP         FLAG = 0x08
	FLAG_SELECTED     FLAG = 0x10
	FLAG_CHANGED      FLAG = 0x20
	FLAG_STATIC       FLAG = 0x40
	FLAG_REJECT       FLAG = 0x80
	FLAG_SCOPE_LINK   FLAG = 0x100
	FLAG_FIB_OVERRIDE FLAG = 0x200
)

func (t FLAG) String() string {
	var ss []string
	if t&FLAG_INTERNAL > 0 {
		ss = append(ss, "FLAG_INTERNAL")
	}
	if t&FLAG_SELFROUTE > 0 {
		ss = append(ss, "FLAG_SELFROUTE")
	}
	if t&FLAG_BLACKHOLE > 0 {
		ss = append(ss, "FLAG_BLACKHOLE")
	}
	if t&FLAG_IBGP > 0 {
		ss = append(ss, "FLAG_IBGP")
	}
	if t&FLAG_SELECTED > 0 {
		ss = append(ss, "FLAG_SELECTED")
	}
	if t&FLAG_CHANGED > 0 {
		ss = append(ss, "FLAG_CHANGED")
	}
	if t&FLAG_STATIC > 0 {
		ss = append(ss, "FLAG_STATIC")
	}
	if t&FLAG_REJECT > 0 {
		ss = append(ss, "FLAG_REJECT")
	}
	if t&FLAG_SCOPE_LINK > 0 {
		ss = append(ss, "FLAG_SCOPE_LINK")
	}
	if t&FLAG_FIB_OVERRIDE > 0 {
		ss = append(ss, "FLAG_FIB_OVERRIDE")
	}
	return strings.Join(ss, "|")
}

// For FRRouting: version 5.
const (
	FRR5_FLAG_INTERNAL     FLAG = 0x01
	FRR5_FLAG_SELFROUTE    FLAG = 0x02
	FRR5_FLAG_IBGP         FLAG = 0x08
	FRR5_FLAG_SELECTED     FLAG = 0x10
	FRR5_FLAG_STATIC       FLAG = 0x40
	FRR5_FLAG_SCOPE_LINK   FLAG = 0x100
	FRR5_FLAG_FIB_OVERRIDE FLAG = 0x200
	FRR5_FLAG_EVPN_ROUTE   FLAG = 0x400
)

// Nexthop type to be used across all ZAPI versions.
//go:generate stringer -type=NEXTHOP_TYPE
type NEXTHOP_TYPE uint8

const (
	_ NEXTHOP_TYPE = iota
	NEXTHOP_IFINDEX
	NEXTHOP_IPV4
	NEXTHOP_IPV4_IFINDEX
	NEXTHOP_IPV6
	NEXTHOP_IPV6_IFINDEX
	NEXTHOP_BLACKHOLE
)

// Nexthop types use by various ZAPI versions.
//go:generate stringer -type=ZAPI_NEXTHOP_TYPE
type ZAPI_NEXTHOP_TYPE uint8

// For Quagga.
const (
	_ ZAPI_NEXTHOP_TYPE = iota
	QUAGGA_NEXTHOP_IFINDEX
	QUAGGA_NEXTHOP_IFNAME
	QUAGGA_NEXTHOP_IPV4
	QUAGGA_NEXTHOP_IPV4_IFINDEX
	QUAGGA_NEXTHOP_IPV4_IFNAME
	QUAGGA_NEXTHOP_IPV6
	QUAGGA_NEXTHOP_IPV6_IFINDEX
	QUAGGA_NEXTHOP_IPV6_IFNAME
	QUAGGA_NEXTHOP_BLACKHOLE
)

// For FRRouting: versions 4 and 5.
const (
	_ ZAPI_NEXTHOP_TYPE = iota
	FRR_NEXTHOP_IFINDEX
	FRR_NEXTHOP_IPV4
	FRR_NEXTHOP_IPV4_IFINDEX
	FRR_NEXTHOP_IPV6
	FRR_NEXTHOP_IPV6_IFINDEX
	FRR_NEXTHOP_BLACKHOLE
)

var nextHopToZapiNextHopMap = map[uint8]map[NEXTHOP_TYPE]ZAPI_NEXTHOP_TYPE{
	3: {
		NEXTHOP_IFINDEX:      QUAGGA_NEXTHOP_IFINDEX,
		NEXTHOP_IPV4:         QUAGGA_NEXTHOP_IPV4,
		NEXTHOP_IPV4_IFINDEX: QUAGGA_NEXTHOP_IPV4_IFINDEX,
		NEXTHOP_IPV6:         QUAGGA_NEXTHOP_IPV6,
		NEXTHOP_IPV6_IFINDEX: QUAGGA_NEXTHOP_IPV6_IFINDEX,
		NEXTHOP_BLACKHOLE:    QUAGGA_NEXTHOP_BLACKHOLE,
	},
	4: {
		NEXTHOP_IFINDEX:      FRR_NEXTHOP_IFINDEX,
		NEXTHOP_IPV4:         FRR_NEXTHOP_IPV4,
		NEXTHOP_IPV4_IFINDEX: FRR_NEXTHOP_IPV4_IFINDEX,
		NEXTHOP_IPV6:         FRR_NEXTHOP_IPV6,
		NEXTHOP_IPV6_IFINDEX: FRR_NEXTHOP_IPV6_IFINDEX,
		NEXTHOP_BLACKHOLE:    FRR_NEXTHOP_BLACKHOLE,
	},
	5: {
		NEXTHOP_IFINDEX:      FRR_NEXTHOP_IFINDEX,
		NEXTHOP_IPV4:         FRR_NEXTHOP_IPV4,
		NEXTHOP_IPV4_IFINDEX: FRR_NEXTHOP_IPV4_IFINDEX,
		NEXTHOP_IPV6:         FRR_NEXTHOP_IPV6,
		NEXTHOP_IPV6_IFINDEX: FRR_NEXTHOP_IPV6_IFINDEX,
		NEXTHOP_BLACKHOLE:    FRR_NEXTHOP_BLACKHOLE,
	},
}

var zapiNextHopToNextHopMap = map[uint8]map[ZAPI_NEXTHOP_TYPE]NEXTHOP_TYPE{
	3: {
		QUAGGA_NEXTHOP_IFINDEX:      NEXTHOP_IFINDEX,
		QUAGGA_NEXTHOP_IFNAME:       NEXTHOP_IFINDEX,
		QUAGGA_NEXTHOP_IPV4:         NEXTHOP_IPV4,
		QUAGGA_NEXTHOP_IPV4_IFINDEX: NEXTHOP_IPV4_IFINDEX,
		QUAGGA_NEXTHOP_IPV4_IFNAME:  NEXTHOP_IPV4_IFINDEX,
		QUAGGA_NEXTHOP_IPV6:         NEXTHOP_IPV6,
		QUAGGA_NEXTHOP_IPV6_IFINDEX: NEXTHOP_IPV6_IFINDEX,
		QUAGGA_NEXTHOP_IPV6_IFNAME:  NEXTHOP_IPV6_IFINDEX,
		QUAGGA_NEXTHOP_BLACKHOLE:    NEXTHOP_BLACKHOLE,
	},
	4: {
		FRR_NEXTHOP_IFINDEX:      NEXTHOP_IFINDEX,
		FRR_NEXTHOP_IPV4:         NEXTHOP_IPV4,
		FRR_NEXTHOP_IPV4_IFINDEX: NEXTHOP_IPV4_IFINDEX,
		FRR_NEXTHOP_IPV6:         NEXTHOP_IPV6,
		FRR_NEXTHOP_IPV6_IFINDEX: NEXTHOP_IPV6_IFINDEX,
		FRR_NEXTHOP_BLACKHOLE:    NEXTHOP_BLACKHOLE,
	},
	5: {
		FRR_NEXTHOP_IFINDEX:      NEXTHOP_IFINDEX,
		FRR_NEXTHOP_IPV4:         NEXTHOP_IPV4,
		FRR_NEXTHOP_IPV4_IFINDEX: NEXTHOP_IPV4_IFINDEX,
		FRR_NEXTHOP_IPV6:         NEXTHOP_IPV6,
		FRR_NEXTHOP_IPV6_IFINDEX: NEXTHOP_IPV6_IFINDEX,
		FRR_NEXTHOP_BLACKHOLE:    NEXTHOP_BLACKHOLE,
	},
}

// For FRRouting: verion 5.
// Black-hole types.
//go:generate stringer -type=BLACKHOLE_TYPE
type BLACKHOLE_TYPE uint8

const (
	BLACKHOLE_UNSPEC BLACKHOLE_TYPE = iota
	BLACKHOLE_NULL
	BLACKHOLE_REJECT
	BLACKHOLE_ADMINPROHIB
)

// Interface PTM Enable Configuration.
//go:generate stringer -type=PTM_ENABLE
type PTM_ENABLE uint8

const (
	PTM_ENABLE_OFF    PTM_ENABLE = 0
	PTM_ENABLE_ON     PTM_ENABLE = 1
	PTM_ENABLE_UNSPEC PTM_ENABLE = 2
)

// PTM Status.
//go:generate stringer -type=PTM_STATUS
type PTM_STATUS uint8

const (
	PTM_STATUS_DOWN    PTM_STATUS = 0
	PTM_STATUS_UP      PTM_STATUS = 1
	PTM_STATUS_UNKNOWN PTM_STATUS = 2
)

type Client struct {
	outgoing      chan *Message
	incoming      chan *Message
	redistDefault ROUTE_TYPE
	conn          net.Conn
	Version       uint8
}

func NewClient(network, address string, typ ROUTE_TYPE, version uint8) (*Client, error) {
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	outgoing := make(chan *Message)
	incoming := make(chan *Message, 64)
	if version < 2 {
		version = 2
	} else if version > 5 {
		version = 5
	}

	c := &Client{
		outgoing:      outgoing,
		incoming:      incoming,
		redistDefault: typ,
		conn:          conn,
		Version:       version,
	}

	go func() {
		for {
			m, more := <-outgoing
			if more {
				b, err := m.Serialize()
				if err != nil {
					log.WithFields(log.Fields{
						"Topic": "Zebra",
					}).Warnf("failed to serialize: %s", m)
					continue
				}

				_, err = conn.Write(b)
				if err != nil {
					log.WithFields(log.Fields{
						"Topic": "Zebra",
					}).Errorf("failed to write: %s", err)
					close(outgoing)
				}
			} else {
				log.Debug("finish outgoing loop")
				return
			}
		}
	}()

	// Send HELLO/ROUTER_ID_ADD messages to negotiate the Zebra message version.
	c.SendHello()
	c.SendRouterIDAdd()
	if version >= 4 {
		c.SendLabelManagerConnect()
	}

	receiveSingleMsg := func() (*Message, error) {
		headerBuf, err := readAll(conn, int(HeaderSize(version)))
		if err != nil {
			err = fmt.Errorf("failed to read header: %s", err)
			log.WithFields(log.Fields{
				"Topic": "Zebra",
			}).Error(err)
			return nil, err
		}
		log.WithFields(log.Fields{
			"Topic": "Zebra",
		}).Debugf("read header from zebra: %v", headerBuf)
		hd := &Header{}
		err = hd.DecodeFromBytes(headerBuf)
		if err != nil {
			err = fmt.Errorf("failed to decode header: %s", err)
			log.WithFields(log.Fields{
				"Topic": "Zebra",
			}).Error(err)
			return nil, err
		}

		bodyBuf, err := readAll(conn, int(hd.Len-HeaderSize(version)))
		if err != nil {
			err = fmt.Errorf("failed to read body: %s", err)
			log.WithFields(log.Fields{
				"Topic": "Zebra",
			}).Error(err)
			return nil, err
		}
		log.WithFields(log.Fields{
			"Topic": "Zebra",
		}).Debugf("read body from zebra: %v", bodyBuf)
		m, err := ParseMessage(hd, bodyBuf)
		if err != nil {
			log.WithFields(log.Fields{
				"Topic": "Zebra",
			}).Warnf("failed to parse message: %s", err)
			return nil, nil
		}

		return m, nil
	}

	// Try to receive the first message from Zebra.
	if m, err := receiveSingleMsg(); err != nil {
		c.Close()
		// Return error explicitly in order to retry connection.
		return nil, err
	} else if m != nil {
		incoming <- m
	}

	// Start receive loop only when the first message successfully received.
	go func() {
		for {
			if m, err := receiveSingleMsg(); err != nil {
				return
			} else if m != nil {
				incoming <- m
			}
		}
	}()

	return c, nil
}

func readAll(conn net.Conn, length int) ([]byte, error) {
	buf := make([]byte, length)
	_, err := io.ReadFull(conn, buf)
	return buf, err
}

func (c *Client) Receive() chan *Message {
	return c.incoming
}

func (c *Client) Send(m *Message) {
	defer func() {
		if err := recover(); err != nil {
			log.WithFields(log.Fields{
				"Topic": "Zebra",
			}).Debugf("recovered: %s", err)
		}
	}()
	log.WithFields(log.Fields{
		"Topic":  "Zebra",
		"Header": m.Header,
		"Body":   m.Body,
	}).Debug("send command to zebra")
	c.outgoing <- m
}

func (c *Client) SendCommand(command API_TYPE, vrfId uint32, body Body) error {
	var marker uint8 = HEADER_MARKER
	if c.Version >= 4 {
		marker = FRR_HEADER_MARKER
	}
	m := &Message{
		Header: Header{
			Len:     HeaderSize(c.Version),
			Marker:  marker,
			Version: c.Version,
			VrfId:   vrfId,
			Command: command,
		},
		Body: body,
	}
	c.Send(m)
	return nil
}

func (c *Client) SendHello() error {
	if c.redistDefault > 0 {
		command := HELLO
		body := &HelloBody{
			RedistDefault: c.redistDefault,
			Instance:      0,
		}
		switch c.Version {
		case 4:
			command = FRR_HELLO
		case 5:
			command = FRR5_HELLO
		}
		return c.SendCommand(command, VRF_DEFAULT, body)
	}
	return nil
}

func (c *Client) SendRouterIDAdd() error {
	command := ROUTER_ID_ADD
	switch c.Version {
	case 4:
		command = FRR_ROUTER_ID_ADD
	case 5:
		command = FRR5_ROUTER_ID_ADD
	}
	return c.SendCommand(command, VRF_DEFAULT, nil)
}

func (c *Client) SendInterfaceAdd() error {
	command := INTERFACE_ADD
	switch c.Version {
	case 4:
		command = FRR_INTERFACE_ADD
	case 5:
		command = FRR5_INTERFACE_ADD
	}
	return c.SendCommand(command, VRF_DEFAULT, nil)
}

func (c *Client) SendRedistribute(t ROUTE_TYPE, vrfId uint32) error {
	command := REDISTRIBUTE_ADD
	if c.redistDefault != t {
		bodies := make([]*RedistributeBody, 0)
		if c.Version <= 3 {
			bodies = append(bodies, &RedistributeBody{
				Redist: t,
			})
		} else { // version >= 4
			switch c.Version {
			case 4:
				command = FRR_REDISTRIBUTE_ADD
			case 5:
				command = FRR5_REDISTRIBUTE_ADD
			}
			for _, afi := range []AFI{AFI_IP, AFI_IP6} {
				bodies = append(bodies, &RedistributeBody{
					Afi:      afi,
					Redist:   t,
					Instance: 0,
				})
			}
		}

		for _, body := range bodies {
			return c.SendCommand(command, vrfId, body)
		}
	}

	return nil
}

func (c *Client) SendRedistributeDelete(t ROUTE_TYPE) error {
	if t < ROUTE_MAX {
		command := REDISTRIBUTE_DELETE
		switch c.Version {
		case 4:
			command = FRR_REDISTRIBUTE_DELETE
		case 5:
			command = FRR5_REDISTRIBUTE_DELETE
		}
		body := &RedistributeBody{
			Redist: t,
		}
		return c.SendCommand(command, VRF_DEFAULT, body)
	} else {
		return fmt.Errorf("unknown route type: %d", t)
	}
}

func (c *Client) SendIPRoute(vrfId uint32, body *IPRouteBody, isWithdraw bool) error {
	command := IPV4_ROUTE_ADD
	if c.Version <= 3 {
		if body.Prefix.To4() != nil {
			if isWithdraw {
				command = IPV4_ROUTE_DELETE
			}
		} else {
			if isWithdraw {
				command = IPV6_ROUTE_DELETE
			} else {
				command = IPV6_ROUTE_ADD
			}
		}
		if body.Tag != 0 {
			body.Message |= MESSAGE_TAG
		}
	} else if c.Version == 4 {
		if body.Prefix.To4() != nil {
			if isWithdraw {
				command = FRR_IPV4_ROUTE_DELETE
			} else {
				command = FRR_IPV4_ROUTE_ADD
			}
		} else {
			if isWithdraw {
				command = FRR_IPV6_ROUTE_DELETE
			} else {
				command = FRR_IPV6_ROUTE_ADD
			}
		}
		if body.Tag != 0 {
			body.Message |= FRR_MESSAGE_TAG
		}
	} else { // version >= 5
		/*
			if body.Prefix.To4() != nil {
				if isWithdraw {
					command = FRR5_IPV4_ROUTE_DELETE
				} else {
					command = FRR5_IPV4_ROUTE_ADD
				}
			} else {
				if isWithdraw {
					command = FRR5_IPV6_ROUTE_DELETE
				} else {
					command = FRR5_IPV6_ROUTE_ADD
				}
			}
		*/
		if isWithdraw {
			command = FRR5_ROUTE_DELETE
		} else {
			command = FRR5_ROUTE_ADD
		}
		if body.Tag != 0 {
			body.Message |= FRR5_MESSAGE_TAG
		}
	}
	log.WithFields(log.Fields{
		"Topic": "Zebra",
		"VrfId": vrfId,
		"body":  body,
	}).Debugf("send IP route to zebra")
	return c.SendCommand(command, vrfId, body)
}

func (c *Client) SendNexthopRegister(vrfId uint32, body *NexthopRegisterBody, isWithdraw bool) error {
	// Note: NEXTHOP_REGISTER and NEXTHOP_UNREGISTER messages are not
	// supported in Zebra protocol version<3.
	if c.Version < 3 {
		return fmt.Errorf("NEXTHOP_REGISTER/NEXTHOP_UNREGISTER are not supported in version: %d", c.Version)
	}
	command := NEXTHOP_REGISTER
	if c.Version == 3 {
		if isWithdraw {
			command = NEXTHOP_UNREGISTER
		}
	} else if c.Version == 4 {
		if isWithdraw {
			command = FRR_NEXTHOP_UNREGISTER
		} else {
			command = FRR_NEXTHOP_REGISTER
		}
	} else if c.Version == 5 { // version >= 5
		if isWithdraw {
			command = FRR5_NEXTHOP_UNREGISTER
		} else {
			command = FRR5_NEXTHOP_REGISTER
		}
	}
	return c.SendCommand(command, vrfId, body)
}

func (c *Client) SendLabelManagerConnect() error {
	if c.Version < 4 {
		return fmt.Errorf("LABEL_MANAGER_CONNECT is not supported in version: %d", c.Version)
	}
	var command API_TYPE
	var rdistType ROUTE_TYPE
	switch c.Version {
	case 4:
		command = FRR_LABEL_MANAGER_CONNECT
		rdistType = FRR_ROUTE_BGP
	case 5:
		command = FRR5_LABEL_MANAGER_CONNECT
		rdistType = FRR5_ROUTE_BGP
	}
	return c.SendCommand(
		command, 0,
		&LabelManagerConnectBody{
			RedistDefault: rdistType,
			Instance:      0,
		})
}

func (c *Client) SendGetLabelChunk(body *GetLabelChunkBody) error {
	switch c.Version {
	case 4:
		return c.SendCommand(FRR_GET_LABEL_CHUNK, 0, body)
	case 5:
		return c.SendCommand(FRR5_GET_LABEL_CHUNK, 0, body)
	}
	return fmt.Errorf("GET_LABEL_CHUNK is not supported in version: %d", c.Version)
}

func (c *Client) Close() error {
	close(c.outgoing)
	return c.conn.Close()
}

type Header struct {
	Len     uint16
	Marker  uint8
	Version uint8
	VrfId   uint32
	Command API_TYPE
}

func (h *Header) Serialize() ([]byte, error) {
	buf := make([]byte, HeaderSize(h.Version))
	binary.BigEndian.PutUint16(buf[0:2], h.Len)
	buf[2] = h.Marker
	buf[3] = h.Version
	switch h.Version {
	case 2:
		binary.BigEndian.PutUint16(buf[4:6], uint16(h.Command))
	case 3, 4:
		binary.BigEndian.PutUint16(buf[4:6], uint16(h.VrfId))
		binary.BigEndian.PutUint16(buf[6:8], uint16(h.Command))
	case 5:
		binary.BigEndian.PutUint32(buf[4:8], uint32(h.VrfId))
		binary.BigEndian.PutUint16(buf[8:10], uint16(h.Command))
	default:
		return nil, fmt.Errorf("Unsupported ZAPI version: %d", h.Version)
	}
	return buf, nil
}

func (h *Header) DecodeFromBytes(data []byte) error {
	if uint16(len(data)) < 4 {
		return fmt.Errorf("Not all ZAPI message header")
	}
	h.Len = binary.BigEndian.Uint16(data[0:2])
	h.Marker = data[2]
	h.Version = data[3]
	if uint16(len(data)) < HeaderSize(h.Version) {
		return fmt.Errorf("Not all ZAPI message header")
	}
	switch h.Version {
	case 2:
		h.Command = API_TYPE(binary.BigEndian.Uint16(data[4:6]))
	case 3, 4:
		h.VrfId = uint32(binary.BigEndian.Uint16(data[4:6]))
		h.Command = API_TYPE(binary.BigEndian.Uint16(data[6:8]))
	case 5:
		h.VrfId = binary.BigEndian.Uint32(data[4:8])
		h.Command = API_TYPE(binary.BigEndian.Uint16(data[8:10]))
	default:
		return fmt.Errorf("Unsupported ZAPI version: %d", h.Version)
	}
	return nil
}

type Body interface {
	DecodeFromBytes([]byte, uint8) error
	Serialize(uint8) ([]byte, error)
	String() string
}

type UnknownBody struct {
	Data []byte
}

func (b *UnknownBody) DecodeFromBytes(data []byte, version uint8) error {
	b.Data = data
	return nil
}

func (b *UnknownBody) Serialize(version uint8) ([]byte, error) {
	return b.Data, nil
}

func (b *UnknownBody) String() string {
	return fmt.Sprintf("data: %v", b.Data)
}

type HelloBody struct {
	RedistDefault ROUTE_TYPE
	Instance      uint16
}

func (b *HelloBody) DecodeFromBytes(data []byte, version uint8) error {
	b.RedistDefault = ROUTE_TYPE(data[0])
	if version >= 4 {
		b.Instance = binary.BigEndian.Uint16(data[1:3])
	}
	return nil
}

func (b *HelloBody) Serialize(version uint8) ([]byte, error) {
	if version <= 3 {
		return []byte{uint8(b.RedistDefault)}, nil
	} else { // version >= 4
		buf := make([]byte, 3, 3)
		buf[0] = uint8(b.RedistDefault)
		binary.BigEndian.PutUint16(buf[1:3], b.Instance)
		return buf, nil

	}
}

func (b *HelloBody) String() string {
	return fmt.Sprintf(
		"route_type: %s, instance :%d",
		b.RedistDefault, b.Instance)
}

type RedistributeBody struct {
	Afi      AFI
	Redist   ROUTE_TYPE
	Instance uint16
}

func (b *RedistributeBody) DecodeFromBytes(data []byte, version uint8) error {
	if version <= 3 {
		b.Redist = ROUTE_TYPE(data[0])
	} else { // version >= 4
		b.Afi = AFI(data[0])
		b.Redist = ROUTE_TYPE(data[1])
		b.Instance = binary.BigEndian.Uint16(data[2:4])
	}
	return nil
}

func (b *RedistributeBody) Serialize(version uint8) ([]byte, error) {
	if version <= 3 {
		return []byte{uint8(b.Redist)}, nil
	} else { // version >= 4
		buf := make([]byte, 4, 4)
		buf[0] = uint8(b.Afi)
		buf[1] = uint8(b.Redist)
		binary.BigEndian.PutUint16(buf[2:4], b.Instance)
		return buf, nil
	}
}

func (b *RedistributeBody) String() string {
	return fmt.Sprintf(
		"afi: %s, route_type: %s, instance :%d",
		b.Afi, b.Redist, b.Instance)
}

type InterfaceUpdateBody struct {
	Name         string
	Index        uint32
	Status       INTERFACE_STATUS
	Flags        uint64
	PTMEnable    PTM_ENABLE
	PTMStatus    PTM_STATUS
	Metric       uint32
	Speed        uint32
	MTU          uint32
	MTU6         uint32
	Bandwidth    uint32
	Linktype     LINK_TYPE
	HardwareAddr net.HardwareAddr
}

func (b *InterfaceUpdateBody) DecodeFromBytes(data []byte, version uint8) error {
	if len(data) < INTERFACE_NAMSIZ+29 {
		return fmt.Errorf("lack of bytes. need %d but %d", INTERFACE_NAMSIZ+29, len(data))
	}

	b.Name = strings.Trim(string(data[:INTERFACE_NAMSIZ]), "\u0000")
	data = data[INTERFACE_NAMSIZ:]
	b.Index = binary.BigEndian.Uint32(data[0:4])
	b.Status = INTERFACE_STATUS(data[4])
	b.Flags = binary.BigEndian.Uint64(data[5:13])
	if version >= 4 {
		b.PTMEnable = PTM_ENABLE(data[13])
		b.PTMStatus = PTM_STATUS(data[14])
		b.Metric = binary.BigEndian.Uint32(data[15:19])
		b.Speed = binary.BigEndian.Uint32(data[19:23])
		data = data[23:]
	} else {
		b.Metric = binary.BigEndian.Uint32(data[13:17])
		data = data[17:]
	}
	b.MTU = binary.BigEndian.Uint32(data[0:4])
	b.MTU6 = binary.BigEndian.Uint32(data[4:8])
	b.Bandwidth = binary.BigEndian.Uint32(data[8:12])
	if version >= 3 {
		b.Linktype = LINK_TYPE(binary.BigEndian.Uint32(data[12:16]))
		data = data[16:]
	} else {
		data = data[12:]
	}
	l := binary.BigEndian.Uint32(data[:4])
	if l > 0 {
		if len(data) < 4+int(l) {
			return fmt.Errorf("lack of bytes. need %d but %d", 4+l, len(data))
		}
		b.HardwareAddr = data[4 : 4+l]
	}
	return nil
}

func (b *InterfaceUpdateBody) Serialize(version uint8) ([]byte, error) {
	return []byte{}, nil
}

func (b *InterfaceUpdateBody) String() string {
	s := fmt.Sprintf(
		"name: %s, idx: %d, status: %s, flags: %s, ptm_enable: %s, ptm_status: %s, metric: %d, speed: %d, mtu: %d, mtu6: %d, bandwidth: %d, linktype: %s",
		b.Name, b.Index, b.Status.String(), intfflag2string(b.Flags), b.PTMEnable.String(), b.PTMStatus.String(), b.Metric, b.Speed, b.MTU, b.MTU6, b.Bandwidth, b.Linktype.String())
	if len(b.HardwareAddr) > 0 {
		return s + fmt.Sprintf(", mac: %s", b.HardwareAddr.String())
	}
	return s
}

type InterfaceAddressUpdateBody struct {
	Index       uint32
	Flags       INTERFACE_ADDRESS_FLAG
	Prefix      net.IP
	Length      uint8
	Destination net.IP
}

func (b *InterfaceAddressUpdateBody) DecodeFromBytes(data []byte, version uint8) error {
	b.Index = binary.BigEndian.Uint32(data[:4])
	b.Flags = INTERFACE_ADDRESS_FLAG(data[4])
	family := data[5]
	var addrlen int8
	switch family {
	case syscall.AF_INET:
		addrlen = net.IPv4len
	case syscall.AF_INET6:
		addrlen = net.IPv6len
	default:
		return fmt.Errorf("unknown address family: %d", family)
	}
	b.Prefix = data[6 : 6+addrlen]
	b.Length = data[6+addrlen]
	b.Destination = data[7+addrlen : 7+addrlen*2]
	return nil
}

func (b *InterfaceAddressUpdateBody) Serialize(version uint8) ([]byte, error) {
	return []byte{}, nil
}

func (b *InterfaceAddressUpdateBody) String() string {
	return fmt.Sprintf(
		"idx: %d, flags: %s, addr: %s/%d",
		b.Index, b.Flags.String(), b.Prefix.String(), b.Length)
}

type RouterIDUpdateBody struct {
	Length uint8
	Prefix net.IP
}

func (b *RouterIDUpdateBody) DecodeFromBytes(data []byte, version uint8) error {
	family := data[0]
	var addrlen int8
	switch family {
	case syscall.AF_INET:
		addrlen = net.IPv4len
	case syscall.AF_INET6:
		addrlen = net.IPv6len
	default:
		return fmt.Errorf("unknown address family: %d", family)
	}
	b.Prefix = data[1 : 1+addrlen]
	b.Length = data[1+addrlen]
	return nil
}

func (b *RouterIDUpdateBody) Serialize(version uint8) ([]byte, error) {
	return []byte{}, nil
}

func (b *RouterIDUpdateBody) String() string {
	return fmt.Sprintf("id: %s/%d", b.Prefix.String(), b.Length)
}

type IPRouteBody struct {
	Type            ROUTE_TYPE
	Instance        uint16
	Flags           FLAG
	Message         MESSAGE_FLAG
	SAFI            SAFI
	SockAf          SOCK_AF
	Prefix          net.IP
	PrefixLength    uint8
	SrcPrefix       net.IP
	SrcPrefixLength uint8
	Nexthops        []*Nexthop
	Ifindexs        []uint32
	Distance        uint8
	Metric          uint32
	Mtu             uint32
	Tag             uint32
	Api             API_TYPE
}

func (b *IPRouteBody) RouteFamily(zapiVersion uint8) bgp.RouteFamily {
	switch zapiVersion {
	case 1, 2, 3:
		switch b.Api {
		case IPV4_ROUTE_ADD, IPV4_ROUTE_DELETE:
			return bgp.RF_IPv4_UC
		case IPV6_ROUTE_ADD, IPV6_ROUTE_DELETE:
			return bgp.RF_IPv6_UC
		}
	case 4:
		switch b.Api {
		case FRR_REDISTRIBUTE_IPV4_ADD, FRR_REDISTRIBUTE_IPV4_DEL:
			return bgp.RF_IPv4_UC
		case FRR_REDISTRIBUTE_IPV6_ADD, FRR_REDISTRIBUTE_IPV6_DEL:
			return bgp.RF_IPv6_UC
		}
	case 5:
		switch b.Api {
		case FRR5_IPV4_ROUTE_ADD, FRR5_IPV4_ROUTE_DELETE:
			return bgp.RF_IPv4_UC
		case FRR5_IPV6_ROUTE_ADD, FRR5_IPV6_ROUTE_DELETE:
			return bgp.RF_IPv6_UC
		}
	}
	return bgp.RF_OPAQUE
}

func (b *IPRouteBody) IsWithdraw(zapiVersion uint8) bool {
	switch zapiVersion {
	case 1, 2, 3:
		switch b.Api {
		case IPV4_ROUTE_DELETE, IPV6_ROUTE_DELETE:
			return true
		}
	case 4:
		switch b.Api {
		case FRR_REDISTRIBUTE_IPV4_DEL, FRR_REDISTRIBUTE_IPV6_DEL:
			return true
		}
	case 5:
		switch b.Api {
		case FRR5_ROUTE_DELETE, FRR5_IPV4_ROUTE_DELETE, FRR_IPV6_ROUTE_DELETE:
			return true
		}
	}
	return false
}

func (b *IPRouteBody) Serialize(version uint8) ([]byte, error) {

	var buf []byte
	var nhfBlkH, nhfIndx, nhfIPv4, nhfIPv6 uint8

	if version <= 3 {
		buf = make([]byte, 5)
		buf[0] = uint8(b.Type)
		buf[1] = uint8(b.Flags)
		buf[2] = uint8(b.Message)
		binary.BigEndian.PutUint16(buf[3:5], uint16(b.SAFI))
		nhfIPv4 := uint8(QUAGGA_NEXTHOP_IPV4)
		nhfIPv6 := uint8(QUAGGA_NEXTHOP_IPV6)
		nhfIndx := uint8(QUAGGA_NEXTHOP_IFINDEX)
		nhfBlkH := uint8(QUAGGA_NEXTHOP_BLACKHOLE)
		byteLen := (int(b.PrefixLength) + 7) / 8
		buf = append(buf, b.PrefixLength)
		buf = append(buf, b.Prefix[:byteLen]...)
		if b.Message&MESSAGE_NEXTHOP > 0 {
			if b.Flags&FLAG_BLACKHOLE > 0 {
				buf = append(buf, []byte{1, nhfBlkH}...)
			} else {
				buf = append(buf, uint8(len(b.Nexthops)+len(b.Ifindexs)))
			}

			for _, v := range b.Nexthops {
				if v.Addr.To4() != nil {
					buf = append(buf, nhfIPv4)
					buf = append(buf, v.Addr.To4()...)
				} else {
					buf = append(buf, nhfIPv6)
					buf = append(buf, v.Addr.To16()...)
				}
			}

			for _, v := range b.Ifindexs {
				buf = append(buf, nhfIndx)
				bbuf := make([]byte, 4)
				binary.BigEndian.PutUint32(bbuf, v)
				buf = append(buf, bbuf...)
			}
		}
		if b.Message&MESSAGE_DISTANCE > 0 {
			buf = append(buf, b.Distance)
		}
		if b.Message&MESSAGE_METRIC > 0 {
			bbuf := make([]byte, 4)
			binary.BigEndian.PutUint32(bbuf, b.Metric)
			buf = append(buf, bbuf...)
		}
		if b.Message&MESSAGE_MTU > 0 {
			bbuf := make([]byte, 4)
			binary.BigEndian.PutUint32(bbuf, b.Mtu)
			buf = append(buf, bbuf...)
		}
		if b.Message&MESSAGE_TAG > 0 {
			bbuf := make([]byte, 4)
			binary.BigEndian.PutUint32(bbuf, b.Tag)
			buf = append(buf, bbuf...)
		}
	} else if version == 4 {
		buf = make([]byte, 10)
		buf[0] = uint8(b.Type)
		binary.BigEndian.PutUint16(buf[1:3], uint16(b.Instance))
		binary.BigEndian.PutUint32(buf[3:7], uint32(b.Flags))
		buf[7] = uint8(b.Message)
		binary.BigEndian.PutUint16(buf[8:10], uint16(b.SAFI))
		nhfIPv4 = uint8(FRR_NEXTHOP_IPV4)
		nhfIPv6 = uint8(FRR_NEXTHOP_IPV6)
		nhfIndx = uint8(FRR_NEXTHOP_IFINDEX)
		nhfBlkH = uint8(FRR_NEXTHOP_BLACKHOLE)
		byteLen := (int(b.PrefixLength) + 7) / 8
		buf = append(buf, b.PrefixLength)
		buf = append(buf, b.Prefix[:byteLen]...)
		if b.Message&FRR_MESSAGE_SRCPFX > 0 {
			byteLen = (int(b.SrcPrefixLength) + 7) / 8
			buf = append(buf, b.SrcPrefixLength)
			buf = append(buf, b.SrcPrefix[:byteLen]...)
		}
		if b.Message&FRR_MESSAGE_NEXTHOP > 0 {
			if b.Flags&FLAG_BLACKHOLE > 0 {
				buf = append(buf, []byte{1, nhfBlkH}...)
			} else {
				buf = append(buf, uint8(len(b.Nexthops)+len(b.Ifindexs)))
			}

			for _, v := range b.Nexthops {
				if v.Addr.To4() != nil {
					buf = append(buf, nhfIPv4)
					buf = append(buf, v.Addr.To4()...)
				} else {
					buf = append(buf, nhfIPv6)
					buf = append(buf, v.Addr.To16()...)
				}
			}

			for _, v := range b.Ifindexs {
				buf = append(buf, nhfIndx)
				bbuf := make([]byte, 4)
				binary.BigEndian.PutUint32(bbuf, v)
				buf = append(buf, bbuf...)
			}
		}
		if b.Message&FRR_MESSAGE_DISTANCE > 0 {
			buf = append(buf, b.Distance)
		}
		if b.Message&FRR_MESSAGE_METRIC > 0 {
			bbuf := make([]byte, 4)
			binary.BigEndian.PutUint32(bbuf, b.Metric)
			buf = append(buf, bbuf...)
		}
		if b.Message&FRR_MESSAGE_TAG > 0 {
			bbuf := make([]byte, 4)
			binary.BigEndian.PutUint32(bbuf, b.Tag)
			buf = append(buf, bbuf...)
		}
		if b.Message&FRR_MESSAGE_MTU > 0 {
			bbuf := make([]byte, 4)
			binary.BigEndian.PutUint32(bbuf, b.Mtu)
			buf = append(buf, bbuf...)
		}
	} else { // version >= 5
		log.WithFields(log.Fields{
			"Topic": "Zebra",
		}).Debugf("in IPRouteBody.serialize()")
		buf = make([]byte, 10)
		buf[0] = uint8(b.Type)
		binary.BigEndian.PutUint16(buf[1:3], uint16(b.Instance))
		binary.BigEndian.PutUint32(buf[3:7], uint32(b.Flags))
		buf[7] = uint8(b.Message)
		buf[8] = uint8(b.SAFI)
		buf[9] = uint8(b.SockAf)
		nhfIPv4 = uint8(FRR_NEXTHOP_IPV4)
		nhfIPv6 = uint8(FRR_NEXTHOP_IPV6)
		nhfIndx = uint8(FRR_NEXTHOP_IFINDEX)
		nhfBlkH = uint8(FRR_NEXTHOP_BLACKHOLE)
		byteLen := (int(b.PrefixLength) + 7) / 8
		log.WithFields(log.Fields{
			"Topic":            "Zebra",
			"prefix_len_bytes": byteLen,
		}).Debugf("IPRouteBody.serialize()")
		buf[10] = b.PrefixLength
		buf = append(buf, b.Prefix[:byteLen]...)
		if b.Message&FRR5_MESSAGE_SRCPFX > 0 {
			log.WithFields(log.Fields{
				"Topic":        "Zebra",
				"Message_flag": b.Message,
			}).Debugf("IPRouteBody.serialize() within source-prefix block")
			byteLen = (int(b.SrcPrefixLength) + 7) / 8
			buf = append(buf, b.SrcPrefixLength)
			buf = append(buf, b.SrcPrefix[:byteLen]...)
		}
		if b.Message&FRR5_MESSAGE_NEXTHOP > 0 {
			nextHopsBuf, err := serializeNexthops(b.Nexthops, b.Message&FRR5_MESSAGE_LABEL > 0, version)
			if err != nil {
				buf = append(buf, nextHopsBuf...)
			}
		}
		if b.Message&FRR5_MESSAGE_DISTANCE > 0 {
			buf = append(buf, b.Distance)
		}
		if b.Message&FRR5_MESSAGE_METRIC > 0 {
			bbuf := make([]byte, 4)
			binary.BigEndian.PutUint32(bbuf, b.Metric)
			buf = append(buf, bbuf...)
		}
		if b.Message&FRR5_MESSAGE_TAG > 0 {
			bbuf := make([]byte, 4)
			binary.BigEndian.PutUint32(bbuf, b.Tag)
			buf = append(buf, bbuf...)
		}
		if b.Message&FRR5_MESSAGE_MTU > 0 {
			bbuf := make([]byte, 4)
			binary.BigEndian.PutUint32(bbuf, b.Mtu)
			buf = append(buf, bbuf...)
		}
	}
	log.WithFields(log.Fields{
		"Topic":   "Zebra",
		"buf_len": len(buf),
	}).Debugf("Exiting IPRouteBody.serialize()")
	return buf, nil
}

func (b *IPRouteBody) DecodeFromBytes(data []byte, version uint8) error {
	isV4 := true
	if version <= 3 {
		isV4 = b.Api == IPV4_ROUTE_ADD || b.Api == IPV4_ROUTE_DELETE
	} else if version == 4 {
		isV4 = b.Api == FRR_REDISTRIBUTE_IPV4_ADD || b.Api == FRR_REDISTRIBUTE_IPV4_DEL
	} else { // version >= 5
		isV4 = b.Api == FRR5_IPV4_ROUTE_ADD || b.Api == FRR5_IPV4_ROUTE_DELETE
	}
	var addrLen uint8 = net.IPv4len
	if !isV4 {
		addrLen = net.IPv6len
	}
	b.Type = ROUTE_TYPE(data[0])
	if version <= 3 {
		b.Flags = FLAG(data[1])
		data = data[2:]
	} else { // version >= 4
		b.Instance = binary.BigEndian.Uint16(data[1:3])
		b.Flags = FLAG(binary.BigEndian.Uint32(data[3:7]))
		data = data[7:]
	}
	b.Message = MESSAGE_FLAG(data[0])
	b.SAFI = SAFI(SAFI_UNICAST)
	b.PrefixLength = data[1]
	if b.PrefixLength > addrLen*8 {
		return fmt.Errorf("prefix length is greater than %d", addrLen*8)
	}
	pos := 2
	buf := make([]byte, addrLen)
	byteLen := int((b.PrefixLength + 7) / 8)
	copy(buf, data[pos:pos+byteLen])
	if isV4 {
		b.Prefix = net.IP(buf).To4()
	} else {
		b.Prefix = net.IP(buf).To16()
	}
	pos += byteLen
	rest := 0
	var numNexthop int
	if version <= 3 {
		if b.Message&MESSAGE_NEXTHOP > 0 {
			numNexthop = int(data[pos])
			rest += 1 + numNexthop*(int(addrLen)+5)
		}
		if b.Message&MESSAGE_DISTANCE > 0 {
			// distance(1)
			rest += 1
		}
		if b.Message&MESSAGE_METRIC > 0 {
			// metric(4)
			rest += 4
		}
	} else if version == 4 {
		if b.Message&FRR_MESSAGE_SRCPFX > 0 {
			b.SrcPrefixLength = data[pos]
			pos += 1
			buf = make([]byte, addrLen)
			byteLen = int((b.SrcPrefixLength + 7) / 8)
			copy(buf, data[pos:pos+byteLen])
			if isV4 {
				b.SrcPrefix = net.IP(buf).To4()
			} else {
				b.SrcPrefix = net.IP(buf).To16()
			}
			pos += byteLen
		}
		if b.Message&FRR_MESSAGE_NEXTHOP > 0 {
			numNexthop = int(data[pos])
			rest += 1 + numNexthop*(int(addrLen)+5)
		}
		if b.Message&FRR_MESSAGE_DISTANCE > 0 {
			// distance(1)
			rest += 1
		}
		if b.Message&FRR_MESSAGE_METRIC > 0 {
			// metric(4)
			rest += 4
		}
		if b.Message&MESSAGE_MTU > 0 {
			// mtu(4)
			rest += 4
		}
		if b.Message&MESSAGE_TAG > 0 {
			// tag(4)
			rest += 4
		}
		if b.Message&FRR_MESSAGE_TAG > 0 {
			// tag(4)
			rest += 4
		}
		if b.Message&FRR_MESSAGE_MTU > 0 {
			// mtu(4)
			rest += 4
		}
	} else { // version >= 5
		if b.Message&FRR5_MESSAGE_SRCPFX > 0 {
			b.SrcPrefixLength = data[pos]
			pos += 1
			buf = make([]byte, addrLen)
			byteLen = int((b.SrcPrefixLength + 7) / 8)
			copy(buf, data[pos:pos+byteLen])
			if isV4 {
				b.SrcPrefix = net.IP(buf).To4()
			} else {
				b.SrcPrefix = net.IP(buf).To16()
			}
			pos += byteLen
		}
		if b.Message&FRR5_MESSAGE_NEXTHOP > 0 {
			numNexthop = int(data[pos])
			rest += 1 + numNexthop*(int(addrLen)+5)
		}
		if b.Message&FRR5_MESSAGE_DISTANCE > 0 {
			// distance(1)
			rest += 1
		}
		if b.Message&FRR5_MESSAGE_METRIC > 0 {
			// metric(4)
			rest += 4
		}
		if b.Message&FRR5_MESSAGE_TAG > 0 {
			// tag(4)
			rest += 4
		}
		if b.Message&FRR5_MESSAGE_MTU > 0 {
			// mtu(4)
			rest += 4
		}
	}
	if len(data[pos:]) != rest {
		return fmt.Errorf("message length invalid")
	}
	b.Nexthops = []*Nexthop{}
	b.Ifindexs = []uint32{}
	if version <= 3 {
		if b.Message&MESSAGE_NEXTHOP > 0 {
			pos += 1
			for i := 0; i < numNexthop; i++ {
				addr := data[pos : pos+int(addrLen)]
				nexthop := &Nexthop{}
				if isV4 {
					nexthop.Type = zapiNextHopToNextHopMap[version][QUAGGA_NEXTHOP_IPV4]
					nexthop.Addr = net.IP(addr).To4()
				} else {
					nexthop.Type = zapiNextHopToNextHopMap[version][QUAGGA_NEXTHOP_IPV6]
					nexthop.Addr = net.IP(addr).To16()
				}
				b.Nexthops = append(b.Nexthops, nexthop)

				// skip nexthop and 1byte place holder
				pos += int(addrLen + 1)
				ifidx := binary.BigEndian.Uint32(data[pos : pos+4])
				b.Ifindexs = append(b.Ifindexs, ifidx)
				pos += 4
			}
		}
		if b.Message&MESSAGE_DISTANCE > 0 {
			b.Distance = data[pos]
			pos += 1
		}
		if b.Message&MESSAGE_METRIC > 0 {
			b.Metric = binary.BigEndian.Uint32(data[pos : pos+4])
			pos += 4
		}
		if b.Message&MESSAGE_MTU > 0 {
			b.Mtu = binary.BigEndian.Uint32(data[pos : pos+4])
			pos += 4
		}
		if b.Message&MESSAGE_TAG > 0 {
			b.Tag = binary.BigEndian.Uint32(data[pos : pos+4])
			pos += 4
		}
	} else if version == 4 {
		if b.Message&FRR_MESSAGE_NEXTHOP > 0 {
			pos += 1
			for i := 0; i < numNexthop; i++ {
				addr := data[pos : pos+int(addrLen)]
				nexthop := &Nexthop{}
				if isV4 {
					nexthop.Type = zapiNextHopToNextHopMap[version][FRR_NEXTHOP_IPV4]
					nexthop.Addr = net.IP(addr).To4()
				} else {
					nexthop.Type = zapiNextHopToNextHopMap[version][FRR_NEXTHOP_IPV6]
					nexthop.Addr = net.IP(addr).To16()
				}
				b.Nexthops = append(b.Nexthops, nexthop)

				// skip nexthop and 1byte place holder
				pos += int(addrLen + 1)
				ifidx := binary.BigEndian.Uint32(data[pos : pos+4])
				b.Ifindexs = append(b.Ifindexs, ifidx)
				pos += 4
			}
		}
		if b.Message&FRR_MESSAGE_DISTANCE > 0 {
			b.Distance = data[pos]
			pos += 1
		}
		if b.Message&FRR_MESSAGE_METRIC > 0 {
			b.Metric = binary.BigEndian.Uint32(data[pos : pos+4])
			pos += 4
		}
		if b.Message&FRR_MESSAGE_TAG > 0 {
			b.Tag = binary.BigEndian.Uint32(data[pos : pos+4])
			pos += 4
		}
		if b.Message&FRR_MESSAGE_MTU > 0 {
			b.Mtu = binary.BigEndian.Uint32(data[pos : pos+4])
			pos += 4
		}
	} else { // version >= 5
		if b.Message&FRR5_MESSAGE_NEXTHOP > 0 {
			pos += 1
			for i := 0; i < numNexthop; i++ {
				addr := data[pos : pos+int(addrLen)]
				nexthop := &Nexthop{}
				if isV4 {
					nexthop.Type = zapiNextHopToNextHopMap[version][FRR_NEXTHOP_IPV4]
					nexthop.Addr = net.IP(addr).To4()
				} else {
					nexthop.Type = zapiNextHopToNextHopMap[version][FRR_NEXTHOP_IPV6]
					nexthop.Addr = net.IP(addr).To16()
				}
				b.Nexthops = append(b.Nexthops, nexthop)

				// skip nexthop and 1byte place holder
				pos += int(addrLen + 1)
				ifidx := binary.BigEndian.Uint32(data[pos : pos+4])
				b.Ifindexs = append(b.Ifindexs, ifidx)
				pos += 4
			}
		}
		if b.Message&FRR5_MESSAGE_DISTANCE > 0 {
			b.Distance = data[pos]
			pos += 1
		}
		if b.Message&FRR5_MESSAGE_METRIC > 0 {
			b.Metric = binary.BigEndian.Uint32(data[pos : pos+4])
			pos += 4
		}
		if b.Message&FRR5_MESSAGE_TAG > 0 {
			b.Tag = binary.BigEndian.Uint32(data[pos : pos+4])
			pos += 4
		}
		if b.Message&FRR5_MESSAGE_MTU > 0 {
			b.Mtu = binary.BigEndian.Uint32(data[pos : pos+4])
			pos += 4
		}
	}
	return nil
}

func (b *IPRouteBody) String() string {
	s := fmt.Sprintf(
		"type: %s, instance: %d, flags: %s, message: %d, safi: %s, prefix: %s/%d, src_prefix: %s/%d",
		b.Type, b.Instance, b.Flags.String(), b.Message, b.SAFI, b.Prefix.String(), b.PrefixLength, b.SrcPrefix.String(), b.SrcPrefixLength)
	for i, nh := range b.Nexthops {
		s += fmt.Sprintf(", nexthops[%d]: %s", i, nh.String())
	}
	for i, idx := range b.Ifindexs {
		s += fmt.Sprintf(", ifindex[%d]: %d", i, idx)
	}
	return s + fmt.Sprintf(
		", distance: %d, metric: %d, mtu: %d, tag: %d",
		b.Distance, b.Metric, b.Mtu, b.Tag)
}

type NexthopLookupBody struct {
	Api      API_TYPE
	Addr     net.IP
	Distance uint8
	Metric   uint32
	Nexthops []*Nexthop
}

type Nexthop struct {
	Ifname  string
	Ifindex uint32
	VrfId   uint32
	Type    NEXTHOP_TYPE
	BhType  BLACKHOLE_TYPE
	Addr    net.IP
	Labels  []uint32
}

func (n *Nexthop) String() string {
	s := fmt.Sprintf(
		"vrf_id: %d, type: %s, bh_type: %s, addr: %s, ifindex: %d, ifname: %s, labels: %s",
		n.VrfId, n.Type, n.BhType, n.Addr.String(), n.Ifindex, n.Ifname, n.Labels)
	return s
}

func serializeNexthops(nexthops []*Nexthop, addLabels bool, version uint8) ([]byte, error) {
	buf := make([]byte, 0)
	log.WithFields(log.Fields{
		"Topic":        "Zebra",
		"no_next_hops": len(nexthops),
		"version":      version,
	}).Debugf("serializing next-hops")
	if len(nexthops) == 0 {
		return buf, nil
	}
	if version >= 5 {
		bbuf := make([]byte, 2)
		binary.BigEndian.PutUint16(bbuf, uint16(len(nexthops)))
		buf = append(buf, bbuf...)
		log.WithFields(log.Fields{
			"Topic": "Zebra",
			"buf":   buf,
		}).Debugf("serializing number of next-hops")
	} else {
		buf = append(buf, byte(len(nexthops)))
	}
	for _, nh := range nexthops {
		if version >= 5 {
			bbuf := make([]byte, 4)
			binary.BigEndian.PutUint32(bbuf, nh.VrfId)
			buf = append(buf, bbuf...)
		}
		buf = append(buf, byte(nh.Type))

		switch nh.Type {
		case NEXTHOP_BLACKHOLE:
			if version >= 5 {
				buf = append(buf, byte(nextHopToZapiNextHopMap[version][nh.Type]))
			}

		case NEXTHOP_IFINDEX:
			bbuf := make([]byte, 4)
			binary.BigEndian.PutUint32(bbuf, uint32(nextHopToZapiNextHopMap[version][nh.Type]))
			buf = append(buf, bbuf...)

		case NEXTHOP_IPV4:
			buf = append(buf, nh.Addr.To4()...)
			log.WithFields(log.Fields{
				"Topic":         "Zebra",
				"next_hop_ipv4": nh.Addr,
			}).Debugf("serializing an IPv4 next-hop")
			if version == 4 {

				// On FRRouting version 3.0 or later, NEXTHOP_IPV4 and
				// NEXTHOP_IPV6 have the same structure with
				// NEXTHOP_TYPE_IPV4_IFINDEX and NEXTHOP_TYPE_IPV6_IFINDEX.
				bbuf := make([]byte, 4)
				binary.BigEndian.PutUint32(bbuf, uint32(nextHopToZapiNextHopMap[version][NEXTHOP_IFINDEX]))
				buf = append(buf, bbuf...)
			}

		case NEXTHOP_IPV6:
			buf = append(buf, nh.Addr.To16()...)
			if version == 4 {

				// On FRRouting version 3.0 or later, NEXTHOP_IPV4 and
				// NEXTHOP_IPV6 have the same structure with
				// NEXTHOP_TYPE_IPV4_IFINDEX and NEXTHOP_TYPE_IPV6_IFINDEX.
				bbuf := make([]byte, 4)
				binary.BigEndian.PutUint32(bbuf, uint32(nextHopToZapiNextHopMap[version][NEXTHOP_IFINDEX]))
				buf = append(buf, bbuf...)
			}

		case NEXTHOP_IPV4_IFINDEX:
			buf = append(buf, nh.Addr.To4()...)
			bbuf := make([]byte, 4)
			binary.BigEndian.PutUint32(bbuf, uint32(nextHopToZapiNextHopMap[version][NEXTHOP_IPV4_IFINDEX]))
			buf = append(buf, bbuf...)

		case NEXTHOP_IPV6_IFINDEX:
			buf = append(buf, nh.Addr.To16()...)
			bbuf := make([]byte, 4)
			binary.BigEndian.PutUint32(bbuf, uint32(nextHopToZapiNextHopMap[version][NEXTHOP_IPV6_IFINDEX]))
			buf = append(buf, bbuf...)
		}
		if (version >= 5) && addLabels {
			log.WithFields(log.Fields{
				"Topic":     "Zebra",
				"no_labels": len(nh.Labels),
			}).Debugf("serializing labels")
			buf = append(buf, byte(len(nh.Labels)))
			for _, label := range nh.Labels {
				bbuf := make([]byte, 4)
				binary.BigEndian.PutUint32(bbuf, label)
				buf = append(buf, bbuf...)
			}
		}
	}

	return buf, nil
}

func decodeNexthopsFromBytes(nexthops *[]*Nexthop, data []byte, isV4 bool, version uint8) (int, error) {
	addrLen := net.IPv4len
	if !isV4 {
		addrLen = net.IPv6len
	}
	numNexthop := int(data[0])
	offset := 1
	for i := 0; i < numNexthop; i++ {
		nh := &Nexthop{}
		var ok bool
		nh.Type, ok = zapiNextHopToNextHopMap[version][ZAPI_NEXTHOP_TYPE(data[offset])]
		if !ok {
			return offset, fmt.Errorf("cannot determine next-hop type %d for version %d", data[offset], version)
		}
		offset += 1

		switch nh.Type {
		case NEXTHOP_IFINDEX:
			nh.Ifindex = binary.BigEndian.Uint32(data[offset : offset+4])
			offset += 4

		case NEXTHOP_IPV4, NEXTHOP_IPV6:
			if isV4 {
				nh.Addr = net.IP(data[offset : offset+addrLen]).To4()
			} else {
				nh.Addr = net.IP(data[offset : offset+addrLen]).To16()
			}
			offset += addrLen
			if version >= 4 {
				// On FRRouting version 3.0 or later, NEXTHOP_IPV4 and
				// NEXTHOP_IPV6 have the same structure with
				// NEXTHOP_TYPE_IPV4_IFINDEX and NEXTHOP_TYPE_IPV6_IFINDEX.
				nh.Ifindex = binary.BigEndian.Uint32(data[offset : offset+4])
				offset += 4
			}

		case NEXTHOP_IPV4_IFINDEX, NEXTHOP_IPV6_IFINDEX:
			if isV4 {
				nh.Addr = net.IP(data[offset : offset+addrLen]).To4()
			} else {
				nh.Addr = net.IP(data[offset : offset+addrLen]).To16()
			}
			offset += addrLen
			nh.Ifindex = binary.BigEndian.Uint32(data[offset : offset+4])
			offset += 4
		}
		*nexthops = append(*nexthops, nh)
	}

	return offset, nil
}

func (b *NexthopLookupBody) Serialize(version uint8) ([]byte, error) {
	isV4 := false
	if version <= 3 {
		isV4 = b.Api == IPV4_NEXTHOP_LOOKUP
	} else if version == 4 {
		isV4 = b.Api == FRR_IPV4_NEXTHOP_LOOKUP_MRIB
	} else { // version >= 5
		isV4 = b.Api == FRR5_IPV4_NEXTHOP_LOOKUP_MRIB
	}
	buf := make([]byte, 0)
	if isV4 {
		buf = append(buf, b.Addr.To4()...)
	} else {
		buf = append(buf, b.Addr.To16()...)
	}
	return buf, nil
}

func (b *NexthopLookupBody) DecodeFromBytes(data []byte, version uint8) error {
	isV4 := false
	if version <= 3 {
		isV4 = b.Api == IPV4_NEXTHOP_LOOKUP
	} else if version == 4 {
		isV4 = b.Api == FRR_IPV4_NEXTHOP_LOOKUP_MRIB
	} else { // version >= 5
		isV4 = b.Api == FRR5_IPV4_NEXTHOP_LOOKUP_MRIB
	}
	addrLen := net.IPv4len
	if !isV4 {
		addrLen = net.IPv6len
	}
	if len(data) < addrLen {
		return fmt.Errorf("message length invalid")
	}
	buf := make([]byte, addrLen)
	copy(buf, data[0:addrLen])
	pos := addrLen
	if isV4 {
		b.Addr = net.IP(buf).To4()
	} else {
		b.Addr = net.IP(buf).To16()
	}
	if version >= 4 {
		b.Distance = data[pos]
		pos++
	}
	if len(data[pos:]) > int(1+addrLen) {
		b.Metric = binary.BigEndian.Uint32(data[pos : pos+4])
		pos += 4
		b.Nexthops = []*Nexthop{}
		if nexthopsByteLen, err := decodeNexthopsFromBytes(&b.Nexthops, data[pos:], isV4, version); err != nil {
			return err
		} else {
			pos += nexthopsByteLen
		}
	}
	return nil
}

func (b *NexthopLookupBody) String() string {
	s := fmt.Sprintf(
		"addr: %s, distance:%d, metric: %d",
		b.Addr.String(), b.Distance, b.Metric)
	if len(b.Nexthops) > 0 {
		for _, nh := range b.Nexthops {
			s = s + fmt.Sprintf(", nexthop:{%s}", nh.String())
		}
	}
	return s
}

type ImportLookupBody struct {
	Api          API_TYPE
	PrefixLength uint8
	Prefix       net.IP
	Addr         net.IP
	Metric       uint32
	Nexthops     []*Nexthop
}

func (b *ImportLookupBody) Serialize(version uint8) ([]byte, error) {
	buf := make([]byte, 1)
	buf[0] = b.PrefixLength
	buf = append(buf, b.Addr.To4()...)
	return buf, nil
}

func (b *ImportLookupBody) DecodeFromBytes(data []byte, version uint8) error {
	isV4 := b.Api == IPV4_IMPORT_LOOKUP
	addrLen := net.IPv4len
	if !isV4 {
		addrLen = net.IPv6len
	}

	if len(data) < addrLen {
		return fmt.Errorf("message length invalid")
	}

	buf := make([]byte, addrLen)
	copy(buf, data[0:addrLen])
	pos := addrLen

	b.Addr = net.IP(buf).To4()

	if len(data[pos:]) > int(1+addrLen) {
		b.Metric = binary.BigEndian.Uint32(data[pos : pos+4])
		pos += 4
		b.Nexthops = []*Nexthop{}
		if nexthopsByteLen, err := decodeNexthopsFromBytes(&b.Nexthops, data[pos:], isV4, version); err != nil {
			return err
		} else {
			pos += nexthopsByteLen
		}
	}

	return nil
}

func (b *ImportLookupBody) String() string {
	s := fmt.Sprintf(
		"prefix: %s/%d, addr: %s, metric: %d",
		b.Prefix.String(), b.PrefixLength, b.Addr.String(), b.Metric)
	if len(b.Nexthops) > 0 {
		for _, nh := range b.Nexthops {
			s = s + fmt.Sprintf(", nexthop:{%s}", nh.String())
		}
	}
	return s
}

type RegisteredNexthop struct {
	Connected uint8
	Family    uint16
	// Note: Ignores PrefixLength (uint8),
	// because this field should be always:
	// - 32 if Address Family is AF_INET
	// - 128 if Address Family is AF_INET6
	Prefix net.IP
}

func (n *RegisteredNexthop) Len() int {
	// Connected (1 byte) + Address Family (2 bytes) + Prefix Length (1 byte) + Prefix (variable)
	if n.Family == uint16(syscall.AF_INET) {
		return 4 + net.IPv4len
	} else {
		return 4 + net.IPv6len
	}
}

func (n *RegisteredNexthop) Serialize() ([]byte, error) {
	// Connected (1 byte)
	buf := make([]byte, 4)
	buf[0] = byte(n.Connected)

	// Address Family (2 bytes)
	binary.BigEndian.PutUint16(buf[1:3], n.Family)

	// Prefix Length (1 byte) + Prefix (variable)
	switch n.Family {
	case uint16(syscall.AF_INET):
		buf[3] = byte(net.IPv4len * 8)
		buf = append(buf, n.Prefix.To4()...)
	case uint16(syscall.AF_INET6):
		buf[3] = byte(net.IPv6len * 8)
		buf = append(buf, n.Prefix.To16()...)
	default:
		return nil, fmt.Errorf("invalid address family: %d", n.Family)
	}

	return buf, nil
}

func (n *RegisteredNexthop) DecodeFromBytes(data []byte) error {
	// Connected (1 byte)
	n.Connected = uint8(data[0])
	offset := 1

	// Address Family (2 bytes)
	n.Family = binary.BigEndian.Uint16(data[offset : offset+2])
	isV4 := n.Family == uint16(syscall.AF_INET)
	addrLen := int(net.IPv4len)
	if !isV4 {
		addrLen = net.IPv6len
	}
	// Note: Ignores Prefix Length (1 byte)
	offset += 3

	// Prefix (variable)
	if isV4 {
		n.Prefix = net.IP(data[offset : offset+addrLen]).To4()
	} else {
		n.Prefix = net.IP(data[offset : offset+addrLen]).To16()
	}

	return nil
}

func (n *RegisteredNexthop) String() string {
	return fmt.Sprintf(
		"connected: %d, family: %d, prefix: %s",
		n.Connected, n.Family, n.Prefix.String())
}

type NexthopRegisterBody struct {
	Api      API_TYPE
	Nexthops []*RegisteredNexthop
}

func (b *NexthopRegisterBody) Serialize(version uint8) ([]byte, error) {
	buf := make([]byte, 0)

	// List of Registered Nexthops
	for _, nh := range b.Nexthops {
		nhBuf, err := nh.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, nhBuf...)
	}

	return buf, nil
}

func (b *NexthopRegisterBody) DecodeFromBytes(data []byte, version uint8) error {
	offset := 0

	// List of Registered Nexthops
	b.Nexthops = []*RegisteredNexthop{}
	for len(data[offset:]) > 0 {
		nh := new(RegisteredNexthop)
		err := nh.DecodeFromBytes(data[offset:])
		if err != nil {
			return err
		}
		b.Nexthops = append(b.Nexthops, nh)

		offset += nh.Len()
		if len(data) < offset {
			break
		}
	}

	return nil
}

func (b *NexthopRegisterBody) String() string {
	s := make([]string, 0)
	for _, nh := range b.Nexthops {
		s = append(s, fmt.Sprintf("nexthop:{%s}", nh.String()))
	}
	return strings.Join(s, ", ")
}

type NexthopUpdateBody struct {
	Api    API_TYPE
	Family uint16
	// Note: Ignores PrefixLength (uint8),
	// because this field should be always:
	// - 32 if Address Family is AF_INET
	// - 128 if Address Family is AF_INET6
	Prefix   net.IP
	Distance uint8
	Metric   uint32
	Nexthops []*Nexthop
}

func (b *NexthopUpdateBody) Serialize(version uint8) ([]byte, error) {
	// Address Family (2 bytes)
	buf := make([]byte, 3)
	binary.BigEndian.PutUint16(buf, b.Family)

	// Prefix Length (1 byte) + Prefix (variable)
	switch b.Family {
	case uint16(syscall.AF_INET):
		buf[2] = byte(net.IPv4len * 8)
		buf = append(buf, b.Prefix.To4()...)
	case uint16(syscall.AF_INET6):
		buf[2] = byte(net.IPv6len * 8)
		buf = append(buf, b.Prefix.To16()...)
	default:
		return nil, fmt.Errorf("invalid address family: %d", b.Family)
	}

	return buf, nil
}

func (b *NexthopUpdateBody) DecodeFromBytes(data []byte, version uint8) error {
	// Address Family (2 bytes)
	b.Family = binary.BigEndian.Uint16(data[0:2])
	isV4 := b.Family == uint16(syscall.AF_INET)
	addrLen := int(net.IPv4len)
	if !isV4 {
		addrLen = net.IPv6len
	}
	// Note: Ignores Prefix Length (1 byte)
	offset := 3

	// Prefix (variable)
	if isV4 {
		b.Prefix = net.IP(data[offset : offset+addrLen]).To4()
	} else {
		b.Prefix = net.IP(data[offset : offset+addrLen]).To16()
	}
	offset += addrLen

	// Distance (1 byte) (if version>=4)
	// Metric (4 bytes)
	// Number of Nexthops (1 byte)
	if version >= 4 {
		if len(data[offset:]) < 6 {
			return fmt.Errorf("invalid message length: missing distance(1 byte), metric(4 bytes) or nexthops(1 byte): %d<6", len(data[offset:]))
		}
		b.Distance = data[offset]
		offset += 1
	} else if len(data[offset:]) < 5 {
		return fmt.Errorf("invalid message length: missing metric(4 bytes) or nexthops(1 byte): %d<5", len(data[offset:]))
	}
	b.Metric = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	// List of Nexthops
	b.Nexthops = []*Nexthop{}
	if nexthopsByteLen, err := decodeNexthopsFromBytes(&b.Nexthops, data[offset:], isV4, version); err != nil {
		return err
	} else {
		offset += nexthopsByteLen
	}

	return nil
}

func (b *NexthopUpdateBody) String() string {
	s := fmt.Sprintf(
		"family: %d, prefix: %s, distance: %d, metric: %d",
		b.Family, b.Prefix.String(), b.Distance, b.Metric)
	for _, nh := range b.Nexthops {
		s = s + fmt.Sprintf(", nexthop:{%s}", nh.String())
	}
	return s
}

type LabelManagerConnectBody struct {
	RedistDefault ROUTE_TYPE
	Instance      uint16
	// The followings are used in response from Zebra
	Result uint8 // 0 means success
}

func (b *LabelManagerConnectBody) Serialize(version uint8) ([]byte, error) {
	buf := make([]byte, 3)
	buf[0] = uint8(b.RedistDefault)
	binary.BigEndian.PutUint16(buf[1:3], b.Instance)
	return buf, nil
}

func (b *LabelManagerConnectBody) DecodeFromBytes(data []byte, version uint8) error {
	if len(data) < 1 {
		return fmt.Errorf("invalid message length for LABEL_MANAGER_CONNECT response: %d<1", len(data))
	}
	b.Result = data[0]
	return nil
}

func (b *LabelManagerConnectBody) String() string {
	return fmt.Sprintf(
		"route_type: %s, instance: %d, result: %d",
		b.RedistDefault.String(), b.Instance, b.Result)
}

type GetLabelChunkBody struct {
	Keep      uint8
	ChunkSize uint32
	// The followings are used in response from Zebra
	Start uint32
	End   uint32
}

func (b *GetLabelChunkBody) Serialize(version uint8) ([]byte, error) {
	buf := make([]byte, 5)
	buf[0] = b.Keep
	binary.BigEndian.PutUint32(buf[1:5], b.ChunkSize)
	return buf, nil
}

func (b *GetLabelChunkBody) DecodeFromBytes(data []byte, version uint8) error {
	if len(data) < 9 {
		return fmt.Errorf("invalid message length for GET_LABEL_CHUNK response: %d<9", len(data))
	}
	b.Keep = data[0]
	b.Start = binary.BigEndian.Uint32(data[1:5])
	b.End = binary.BigEndian.Uint32(data[5:9])
	return nil
}

func (b *GetLabelChunkBody) String() string {
	return fmt.Sprintf(
		"keep: %d, chunk_size: %d, start: %d, end: %d",
		b.Keep, b.ChunkSize, b.Start, b.End)
}

type ReleaseLabelChunkBody struct {
	Start uint32
	End   uint32
}

func (b *ReleaseLabelChunkBody) Serialize(version uint8) ([]byte, error) {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint32(buf[0:4], b.Start)
	binary.BigEndian.PutUint32(buf[4:8], b.End)
	return buf, nil
}

func (b *ReleaseLabelChunkBody) DecodeFromBytes(data []byte, version uint8) error {
	// No response from Zebra
	return nil
}

func (b *ReleaseLabelChunkBody) String() string {
	return fmt.Sprintf(
		"start: %d, end: %d",
		b.Start, b.End)
}

//go:generate stringer -type=LSP_TYPE
type LSP_TYPE uint8

const (
	FRR5_LSP_NONE LSP_TYPE = iota
	FRR5_LSP_STATIC
	FRR5_LSP_LDP
	FRR5_LSP_BGP
	FRR5_LSP_SR
	FRR5_LSP_SHARP
)

type VrfLabelBody struct {
	Label     uint32
	Afi       AFI
	LabelType LSP_TYPE
}

func (b *VrfLabelBody) Serialize(version uint8) ([]byte, error) {
	buf := make([]byte, 6)
	binary.BigEndian.PutUint32(buf[0:4], b.Label)
	buf[4] = uint8(b.Afi)
	buf[5] = uint8(b.LabelType)
	return buf, nil
}

func (b *VrfLabelBody) DecodeFromBytes(data []byte, version uint8) error {
	if len(data) < 6 {
		return fmt.Errorf("invalid message length for VRF_LABEL message: %d<6", len(data))
	}
	b.Label = binary.BigEndian.Uint32(data[0:4])
	b.Afi = AFI(data[4])
	b.LabelType = LSP_TYPE(data[5])
	return nil
}

func (b *VrfLabelBody) String() string {
	return fmt.Sprintf(
		"label: %d, AFI: %s LSP_type: %s",
		b.Label, b.Afi, b.LabelType)
}

type Message struct {
	Header Header
	Body   Body
}

func (m *Message) Serialize() ([]byte, error) {
	var body []byte
	if m.Body != nil {
		var err error
		body, err = m.Body.Serialize(m.Header.Version)
		if err != nil {
			return nil, err
		}
	}
	m.Header.Len = uint16(len(body)) + HeaderSize(m.Header.Version)
	hdr, err := m.Header.Serialize()
	if err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}

func (m *Message) parseMessage(data []byte) error {
	switch m.Header.Command {
	case INTERFACE_ADD, INTERFACE_DELETE, INTERFACE_UP, INTERFACE_DOWN:
		m.Body = &InterfaceUpdateBody{}
	case INTERFACE_ADDRESS_ADD, INTERFACE_ADDRESS_DELETE:
		m.Body = &InterfaceAddressUpdateBody{}
	case ROUTER_ID_UPDATE:
		m.Body = &RouterIDUpdateBody{}
	case IPV4_ROUTE_ADD, IPV6_ROUTE_ADD, IPV4_ROUTE_DELETE, IPV6_ROUTE_DELETE:
		m.Body = &IPRouteBody{Api: m.Header.Command}
	case IPV4_NEXTHOP_LOOKUP, IPV6_NEXTHOP_LOOKUP:
		m.Body = &NexthopLookupBody{Api: m.Header.Command}
	case IPV4_IMPORT_LOOKUP:
		m.Body = &ImportLookupBody{Api: m.Header.Command}
	case NEXTHOP_UPDATE:
		m.Body = &NexthopUpdateBody{Api: m.Header.Command}
	default:
		m.Body = &UnknownBody{}
	}
	return m.Body.DecodeFromBytes(data, m.Header.Version)
}

func (m *Message) parseFrrMessage(data []byte) error {
	switch m.Header.Command {
	case FRR_INTERFACE_ADD, FRR_INTERFACE_DELETE, FRR_INTERFACE_UP, FRR_INTERFACE_DOWN:
		m.Body = &InterfaceUpdateBody{}
	case FRR_INTERFACE_ADDRESS_ADD, FRR_INTERFACE_ADDRESS_DELETE:
		m.Body = &InterfaceAddressUpdateBody{}
	case FRR_ROUTER_ID_UPDATE:
		m.Body = &RouterIDUpdateBody{}
	case FRR_NEXTHOP_UPDATE:
		m.Body = &NexthopUpdateBody{}
	case FRR_INTERFACE_NBR_ADDRESS_ADD, FRR_INTERFACE_NBR_ADDRESS_DELETE:
		// TODO
		m.Body = &UnknownBody{}
	case FRR_INTERFACE_BFD_DEST_UPDATE:
		// TODO
		m.Body = &UnknownBody{}
	case FRR_IMPORT_CHECK_UPDATE:
		// TODO
		m.Body = &UnknownBody{}
	case FRR_BFD_DEST_REPLAY:
		// TODO
		m.Body = &UnknownBody{}
	case FRR_REDISTRIBUTE_IPV4_ADD, FRR_REDISTRIBUTE_IPV4_DEL, FRR_REDISTRIBUTE_IPV6_ADD, FRR_REDISTRIBUTE_IPV6_DEL:
		m.Body = &IPRouteBody{Api: m.Header.Command}
	case FRR_INTERFACE_VRF_UPDATE:
		// TODO
		m.Body = &UnknownBody{}
	case FRR_INTERFACE_LINK_PARAMS:
		// TODO
		m.Body = &UnknownBody{}
	case FRR_PW_STATUS_UPDATE:
		// TODO
		m.Body = &UnknownBody{}
	case FRR_LABEL_MANAGER_CONNECT:
		// Note: Synchronous message
		m.Body = &LabelManagerConnectBody{}
	case FRR_GET_LABEL_CHUNK:
		// Note: Synchronous message
		m.Body = &GetLabelChunkBody{}
	case FRR_RELEASE_LABEL_CHUNK:
		// Note: Synchronous message
		m.Body = &ReleaseLabelChunkBody{}
	default:
		m.Body = &UnknownBody{}
	}
	return m.Body.DecodeFromBytes(data, m.Header.Version)
}

func (m *Message) parseFrr5Message(data []byte) error {
	switch m.Header.Command {
	case FRR5_INTERFACE_ADD, FRR5_INTERFACE_DELETE, FRR5_INTERFACE_UP, FRR5_INTERFACE_DOWN:
		m.Body = &InterfaceUpdateBody{}
	case FRR5_INTERFACE_ADDRESS_ADD, FRR5_INTERFACE_ADDRESS_DELETE:
		m.Body = &InterfaceAddressUpdateBody{}
	case FRR5_INTERFACE_SET_MASTER:
		// TODO
		m.Body = &UnknownBody{}
	case FRR5_ROUTER_ID_UPDATE:
		m.Body = &RouterIDUpdateBody{}
	case FRR5_NEXTHOP_UPDATE:
		m.Body = &NexthopUpdateBody{}
	case FRR5_INTERFACE_NBR_ADDRESS_ADD, FRR5_INTERFACE_NBR_ADDRESS_DELETE:
		// TODO
		m.Body = &UnknownBody{}
	case FRR5_INTERFACE_BFD_DEST_UPDATE:
		// TODO
		m.Body = &UnknownBody{}
	case FRR5_IMPORT_CHECK_UPDATE:
		// TODO
		m.Body = &UnknownBody{}
	case FRR5_BFD_DEST_REPLAY:
		// TODO
		m.Body = &UnknownBody{}
	case FRR5_IPV4_ROUTE_ADD, FRR5_IPV4_ROUTE_DELETE, FRR_IPV6_ROUTE_ADD, FRR_IPV6_ROUTE_DELETE:
		m.Body = &IPRouteBody{Api: m.Header.Command}
	case FRR5_INTERFACE_VRF_UPDATE:
		// TODO
		m.Body = &UnknownBody{}
	case FRR5_INTERFACE_LINK_PARAMS:
		// TODO
		m.Body = &UnknownBody{}
	case FRR5_PW_STATUS_UPDATE:
		// TODO
		m.Body = &UnknownBody{}
	case FRR5_LABEL_MANAGER_CONNECT:
		// Note: Synchronous message
		m.Body = &LabelManagerConnectBody{}
	case FRR5_GET_LABEL_CHUNK:
		// Note: Synchronous message
		m.Body = &GetLabelChunkBody{}
	case FRR5_RELEASE_LABEL_CHUNK:
		// Note: Synchronous message
		m.Body = &ReleaseLabelChunkBody{}
	case FRR5_VRF_LABEL:
		m.Body = &VrfLabelBody{}
	default:
		m.Body = &UnknownBody{}
	}
	return m.Body.DecodeFromBytes(data, m.Header.Version)
}

func ParseMessage(hdr *Header, data []byte) (m *Message, err error) {
	m = &Message{Header: *hdr}
	if m.Header.Version >= 5 {
		err = m.parseFrr5Message(data)
	} else if m.Header.Version == 4 {
		err = m.parseFrrMessage(data)
	} else {
		err = m.parseMessage(data)
	}
	if err != nil {
		return nil, err
	}
	return m, nil
}
