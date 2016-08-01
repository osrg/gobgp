// Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
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

package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/packet/bgp"
	"google.golang.org/grpc"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	CMD_GLOBAL         = "global"
	CMD_NEIGHBOR       = "neighbor"
	CMD_POLICY         = "policy"
	CMD_RIB            = "rib"
	CMD_ADD            = "add"
	CMD_DEL            = "del"
	CMD_ALL            = "all"
	CMD_SET            = "set"
	CMD_LOCAL          = "local"
	CMD_ADJ_IN         = "adj-in"
	CMD_ADJ_OUT        = "adj-out"
	CMD_RESET          = "reset"
	CMD_SOFT_RESET     = "softreset"
	CMD_SOFT_RESET_IN  = "softresetin"
	CMD_SOFT_RESET_OUT = "softresetout"
	CMD_SHUTDOWN       = "shutdown"
	CMD_ENABLE         = "enable"
	CMD_DISABLE        = "disable"
	CMD_PREFIX         = "prefix"
	CMD_ASPATH         = "as-path"
	CMD_COMMUNITY      = "community"
	CMD_EXTCOMMUNITY   = "ext-community"
	CMD_IMPORT         = "import"
	CMD_EXPORT         = "export"
	CMD_IN             = "in"
	CMD_MONITOR        = "monitor"
	CMD_MRT            = "mrt"
	CMD_DUMP           = "dump"
	CMD_INJECT         = "inject"
	CMD_RPKI           = "rpki"
	CMD_RPKI_TABLE     = "table"
	CMD_RPKI_SERVER    = "server"
	CMD_VRF            = "vrf"
	CMD_ACCEPTED       = "accepted"
	CMD_REJECTED       = "rejected"
	CMD_STATEMENT      = "statement"
	CMD_CONDITION      = "condition"
	CMD_ACTION         = "action"
	CMD_UPDATE         = "update"
	CMD_ROTATE         = "rotate"
	CMD_BMP            = "bmp"
)

var subOpts struct {
	AddressFamily string `short:"a" long:"address-family" description:"specifying an address family"`
}

var neighborsOpts struct {
	Transport string `short:"t" long:"transport" description:"specifying a transport protocol"`
}

var conditionOpts struct {
	Prefix       string `long:"prefix" description:"specifying a prefix set name of policy"`
	Neighbor     string `long:"neighbor" description:"specifying a neighbor set name of policy"`
	AsPath       string `long:"aspath" description:"specifying an as set name of policy"`
	Community    string `long:"community" description:"specifying a community set name of policy"`
	ExtCommunity string `long:"extcommunity" description:"specifying a extended community set name of policy"`
	AsPathLength string `long:"aspath-len" description:"specifying an as path length of policy (<operator>,<numeric>)"`
}

var actionOpts struct {
	RouteAction         string `long:"route-action" description:"specifying a route action of policy (accept | reject)"`
	CommunityAction     string `long:"community" description:"specifying a community action of policy"`
	MedAction           string `long:"med" description:"specifying a med action of policy"`
	AsPathPrependAction string `long:"as-prepend" description:"specifying a as-prepend action of policy"`
	NexthopAction       string `long:"next-hop" description:"specifying a next-hop action of policy"`
}

var mrtOpts struct {
	OutputDir  string
	FileFormat string
	Best       bool `long:"only-best" description:"only keep best path routes"`
}

func formatTimedelta(d int64) string {
	u := uint64(d)
	neg := d < 0
	if neg {
		u = -u
	}
	secs := u % 60
	u /= 60
	mins := u % 60
	u /= 60
	hours := u % 24
	days := u / 24

	if days == 0 {
		return fmt.Sprintf("%02d:%02d:%02d", hours, mins, secs)
	} else {
		return fmt.Sprintf("%dd ", days) + fmt.Sprintf("%02d:%02d:%02d", hours, mins, secs)
	}
}

func cidr2prefix(cidr string) string {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return cidr
	}
	var buffer bytes.Buffer
	for i := 0; i < len(n.IP); i++ {
		buffer.WriteString(fmt.Sprintf("%08b", n.IP[i]))
	}
	ones, _ := n.Mask.Size()
	return buffer.String()[:ones]
}

type Destination struct {
	Prefix string  `json:"prefix"`
	Paths  []*Path `json:"paths"`
}

func ApiStruct2Destination(dst *gobgpapi.Destination) (*Destination, error) {
	paths := make([]*Path, 0, len(dst.Paths))
	for _, p := range dst.Paths {
		ps, err := ApiStruct2Path(p)
		if err != nil {
			return nil, err
		}
		paths = append(paths, ps...)
	}
	return &Destination{
		Prefix: dst.Prefix,
		Paths:  paths,
	}, nil

}

type Path struct {
	Nlri       bgp.AddrPrefixInterface      `json:"nlri"`
	PathAttrs  []bgp.PathAttributeInterface `json:"attrs"`
	Age        int64                        `json:"age"`
	Best       bool                         `json:"best"`
	IsWithdraw bool                         `json:"isWithdraw"`
	Validation int32                        `json:"validation"`
	Filtered   bool                         `json:"filtered"`
	SourceId   string                       `json:"source-id"`
	NeighborIp string                       `json:"neighbor-ip"`
	Stale      bool                         `json:"stale"`
}

func ApiStruct2Path(p *gobgpapi.Path) ([]*Path, error) {
	nlris := make([]bgp.AddrPrefixInterface, 0, 1)
	if len(p.Nlri) == 0 {
		return nil, fmt.Errorf("path doesn't have nlri")
	}
	afi, safi := bgp.RouteFamilyToAfiSafi(bgp.RouteFamily(p.Family))
	nlri, err := bgp.NewPrefixFromRouteFamily(afi, safi)
	if err != nil {
		return nil, err
	}

	if err := nlri.DecodeFromBytes(p.Nlri); err != nil {
		return nil, err
	}
	nlris = append(nlris, nlri)

	pattr := make([]bgp.PathAttributeInterface, 0, len(p.Pattrs))
	for _, attr := range p.Pattrs {
		p, err := bgp.GetPathAttribute(attr)
		if err != nil {
			return nil, err
		}

		err = p.DecodeFromBytes(attr)
		if err != nil {
			return nil, err
		}
		pattr = append(pattr, p)
	}

	paths := make([]*Path, 0, len(nlris))
	for _, nlri := range nlris {
		paths = append(paths, &Path{
			Nlri:       nlri,
			PathAttrs:  pattr,
			Age:        p.Age,
			Best:       p.Best,
			IsWithdraw: p.IsWithdraw,
			Validation: p.Validation,
			SourceId:   p.SourceId,
			NeighborIp: p.NeighborIp,
			Filtered:   p.Filtered,
			Stale:      p.Stale,
		})
	}
	return paths, nil
}

type paths []*Path

func (p paths) Len() int {
	return len(p)
}

func (p paths) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

func (p paths) Less(i, j int) bool {
	if p[i].Nlri.String() == p[j].Nlri.String() {
		if p[i].Best {
			return true
		}
	}
	strings := sort.StringSlice{cidr2prefix(p[i].Nlri.String()),
		cidr2prefix(p[j].Nlri.String())}
	return strings.Less(0, 1)
}

func extractReserved(args, keys []string) map[string][]string {
	m := make(map[string][]string, len(keys))
	var k string
	isReserved := func(s string) bool {
		for _, r := range keys {
			if s == r {
				return true
			}
		}
		return false
	}
	for _, arg := range args {
		if isReserved(arg) {
			k = arg
			m[k] = make([]string, 0, 1)
		} else {
			m[k] = append(m[k], arg)
		}
	}
	return m
}

type PeerConf struct {
	RemoteIp          string                             `json:"remote_ip,omitempty"`
	Id                net.IP                             `json:"id,omitempty"`
	RemoteAs          uint32                             `json:"remote_as,omitempty"`
	LocalAs           uint32                             `json:"local-as,omitempty"`
	RemoteCap         []bgp.ParameterCapabilityInterface `json:"remote_cap,omitempty"`
	LocalCap          []bgp.ParameterCapabilityInterface `json:"local_cap,omitempty"`
	Holdtime          uint32                             `json:"holdtime,omitempty"`
	KeepaliveInterval uint32                             `json:"keepalive_interval,omitempty"`
	PrefixLimits      []*gobgpapi.PrefixLimit            `json:"prefix_limits,omitempty"`
	LocalIp           string                             `json:"local_ip,omitempty"`
	Interface         string                             `json:"interface,omitempty"`
}

type Peer struct {
	Conf           PeerConf                 `json:"conf,omitempty"`
	Info           *gobgpapi.PeerState      `json:"info,omitempty"`
	Timers         *gobgpapi.Timers         `json:"timers,omitempty"`
	RouteReflector *gobgpapi.RouteReflector `json:"route_reflector,omitempty"`
	RouteServer    *gobgpapi.RouteServer    `json:"route_server,omitempty"`
}

func ApiStruct2Peer(p *gobgpapi.Peer) *Peer {
	localCaps := capabilities{}
	remoteCaps := capabilities{}
	for _, buf := range p.Conf.LocalCap {
		c, _ := bgp.DecodeCapability(buf)
		localCaps = append(localCaps, c)
	}
	for _, buf := range p.Conf.RemoteCap {
		c, _ := bgp.DecodeCapability(buf)
		remoteCaps = append(remoteCaps, c)
	}
	remoteIp, _ := net.ResolveIPAddr("ip", p.Conf.NeighborAddress)
	localIp, _ := net.ResolveIPAddr("ip", p.Conf.LocalAddress)
	conf := PeerConf{
		RemoteIp:     remoteIp.String(),
		Id:           net.ParseIP(p.Conf.Id),
		RemoteAs:     p.Conf.PeerAs,
		LocalAs:      p.Conf.LocalAs,
		RemoteCap:    remoteCaps,
		LocalCap:     localCaps,
		PrefixLimits: p.Conf.PrefixLimits,
		LocalIp:      localIp.String(),
		Interface:    p.Conf.NeighborInterface,
	}
	return &Peer{
		Conf:           conf,
		Info:           p.Info,
		Timers:         p.Timers,
		RouteReflector: p.RouteReflector,
		RouteServer:    p.RouteServer,
	}
}

type peers []*Peer

func (p peers) Len() int {
	return len(p)
}

func (p peers) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

func (p peers) Less(i, j int) bool {
	p1 := p[i].Conf.RemoteIp
	p2 := p[j].Conf.RemoteIp
	p1Isv4 := !strings.Contains(p1, ":")
	p2Isv4 := !strings.Contains(p2, ":")
	if p1Isv4 != p2Isv4 {
		if p1Isv4 {
			return true
		}
		return false
	}
	addrlen := 128
	if p1Isv4 {
		addrlen = 32
	}
	strings := sort.StringSlice{cidr2prefix(fmt.Sprintf("%s/%d", p1, addrlen)),
		cidr2prefix(fmt.Sprintf("%s/%d", p2, addrlen))}
	return strings.Less(0, 1)
}

type capabilities []bgp.ParameterCapabilityInterface

func (c capabilities) Len() int {
	return len(c)
}

func (c capabilities) Swap(i, j int) {
	c[i], c[j] = c[j], c[i]
}

func (c capabilities) Less(i, j int) bool {
	return c[i].Code() < c[j].Code()
}

type sets []*gobgpapi.DefinedSet

func (n sets) Len() int {
	return len(n)
}

func (n sets) Swap(i, j int) {
	n[i], n[j] = n[j], n[i]
}

func (n sets) Less(i, j int) bool {
	return n[i].Name < n[j].Name
}

type policies []*gobgpapi.Policy

func (p policies) Len() int {
	return len(p)
}

func (p policies) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

func (p policies) Less(i, j int) bool {
	return p[i].Name < p[j].Name
}

type roas []*gobgpapi.Roa

func (r roas) Len() int {
	return len(r)
}

func (r roas) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}

func (r roas) Less(i, j int) bool {
	strings := sort.StringSlice{cidr2prefix(fmt.Sprintf("%s/%d", r[i].Prefix, r[i].Prefixlen)),
		cidr2prefix(fmt.Sprintf("%s/%d", r[j].Prefix, r[j].Prefixlen))}
	return strings.Less(0, 1)
}

type vrfs []*gobgpapi.Vrf

func (v vrfs) Len() int {
	return len(v)
}

func (v vrfs) Swap(i, j int) {
	v[i], v[j] = v[j], v[i]
}

func (v vrfs) Less(i, j int) bool {
	return v[i].Name < v[j].Name
}

func connGrpc() *grpc.ClientConn {
	timeout := grpc.WithTimeout(time.Second)
	target := net.JoinHostPort(globalOpts.Host, strconv.Itoa(globalOpts.Port))
	conn, err := grpc.Dial(target, timeout, grpc.WithBlock(), grpc.WithInsecure())
	if err != nil {
		exitWithError(err)
	}
	return conn
}

func addr2AddressFamily(a net.IP) bgp.RouteFamily {
	if a.To4() != nil {
		return bgp.RF_IPv4_UC
	} else if a.To16() != nil {
		return bgp.RF_IPv6_UC
	}
	return bgp.RouteFamily(0)
}

func checkAddressFamily(def bgp.RouteFamily) (bgp.RouteFamily, error) {
	var rf bgp.RouteFamily
	var e error
	switch subOpts.AddressFamily {
	case "ipv4", "v4", "4":
		rf = bgp.RF_IPv4_UC
	case "ipv6", "v6", "6":
		rf = bgp.RF_IPv6_UC
	case "ipv4-l3vpn", "vpnv4", "vpn-ipv4":
		rf = bgp.RF_IPv4_VPN
	case "ipv6-l3vpn", "vpnv6", "vpn-ipv6":
		rf = bgp.RF_IPv6_VPN
	case "ipv4-labeled", "ipv4-labelled", "ipv4-mpls":
		rf = bgp.RF_IPv4_MPLS
	case "ipv6-labeled", "ipv6-labelled", "ipv6-mpls":
		rf = bgp.RF_IPv6_MPLS
	case "evpn":
		rf = bgp.RF_EVPN
	case "encap", "ipv4-encap":
		rf = bgp.RF_IPv4_ENCAP
	case "ipv6-encap":
		rf = bgp.RF_IPv6_ENCAP
	case "rtc":
		rf = bgp.RF_RTC_UC
	case "ipv4-flowspec", "ipv4-flow", "flow4":
		rf = bgp.RF_FS_IPv4_UC
	case "ipv6-flowspec", "ipv6-flow", "flow6":
		rf = bgp.RF_FS_IPv6_UC
	case "ipv4-l3vpn-flowspec", "ipv4vpn-flowspec", "flowvpn4":
		rf = bgp.RF_FS_IPv4_VPN
	case "ipv6-l3vpn-flowspec", "ipv6vpn-flowspec", "flowvpn6":
		rf = bgp.RF_FS_IPv6_VPN
	case "l2vpn-flowspec":
		rf = bgp.RF_FS_L2_VPN
	case "opaque":
		rf = bgp.RF_OPAQUE
	case "":
		rf = def
	default:
		e = fmt.Errorf("unsupported address family: %s", subOpts.AddressFamily)
	}
	return rf, e
}

func printError(err error) {
	if globalOpts.Json {
		j, _ := json.Marshal(struct {
			Error string `json:"error"`
		}{Error: err.Error()})
		fmt.Println(string(j))
	} else {
		fmt.Println(err)
	}
}

func exitWithError(err error) {
	printError(err)
	os.Exit(1)
}
