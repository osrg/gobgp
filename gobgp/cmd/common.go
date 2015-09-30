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
	"fmt"
	"github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/packet"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"net"
	"os"
	"sort"
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
	CMD_ASPATH         = "aspath"
	CMD_COMMUNITY      = "community"
	CMD_EXTCOMMUNITY   = "extcommunity"
	CMD_ROUTEPOLICY    = "routepolicy"
	CMD_CONDITIONS     = "conditions"
	CMD_ACTIONS        = "actions"
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
}

var mrtOpts struct {
	OutputDir  string
	FileFormat string
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

func ApiStruct2Destination(dst *gobgpapi.Destination, addpath bool) (*Destination, error) {
	paths := make([]*Path, 0, len(dst.Paths))
	for _, p := range dst.Paths {
		path, err := ApiStruct2Path(p, addpath)
		if err != nil {
			return nil, err
		}
		paths = append(paths, path)
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
	Validation int32
}

func ApiStruct2Path(p *gobgpapi.Path, addpath bool) (*Path, error) {

	ctx := context.Background()
	if addpath {
		m := map[bgp.RouteFamily]bgp.BGPAddPathMode{
			bgp.RouteFamily(p.Rf): bgp.BGP_ADD_PATH_BOTH,
		}
		ctx = context.WithValue(ctx, bgp.CTX_ADDPATH, m)
	}

	var nlri bgp.AddrPrefixInterface
	data := p.Nlri
	if len(data) > 0 {
		nlri = &bgp.IPAddrPrefix{}
		err := nlri.DecodeFromBytes(ctx, data)
		if err != nil {
			return nil, err
		}
	}

	pattr := make([]bgp.PathAttributeInterface, 0, len(p.Pattrs))
	for _, attr := range p.Pattrs {
		p, err := bgp.GetPathAttribute(attr)
		if err != nil {
			return nil, err
		}

		err = p.DecodeFromBytes(ctx, attr)
		if err != nil {
			return nil, err
		}

		switch p.GetType() {
		case bgp.BGP_ATTR_TYPE_MP_REACH_NLRI:
			mpreach := p.(*bgp.PathAttributeMpReachNLRI)
			if len(mpreach.Value) != 1 {
				return nil, fmt.Errorf("include only one route in mp_reach_nlri")
			}
			nlri = mpreach.Value[0]
		}
		pattr = append(pattr, p)
	}
	return &Path{
		Nlri:       nlri,
		PathAttrs:  pattr,
		Age:        p.Age,
		Best:       p.Best,
		IsWithdraw: p.IsWithdraw,
		Validation: p.Validation,
	}, nil
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

type PeerConf struct {
	RemoteIp          net.IP                             `json:"remote_ip,omitempty"`
	Id                net.IP                             `json:"id,omitempty"`
	RemoteAs          uint32                             `json:"remote_as,omitempty"`
	RemoteCap         []bgp.ParameterCapabilityInterface `json:"remote_cap,omitempty"`
	LocalCap          []bgp.ParameterCapabilityInterface `json:"local_cap,omitempty"`
	Holdtime          uint32                             `json:"holdtime,omitempty"`
	KeepaliveInterval uint32                             `json:"keepalive_interval,omitempty"`
}

type Peer struct {
	Conf PeerConf           `json:"conf,omitempty"`
	Info *gobgpapi.PeerInfo `json:"info,omitempty"`
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
	conf := PeerConf{
		RemoteIp:          net.ParseIP(p.Conf.RemoteIp),
		Id:                net.ParseIP(p.Conf.Id),
		RemoteAs:          p.Conf.RemoteAs,
		RemoteCap:         remoteCaps,
		LocalCap:          localCaps,
		Holdtime:          p.Conf.Holdtime,
		KeepaliveInterval: p.Conf.KeepaliveInterval,
	}
	return &Peer{
		Conf: conf,
		Info: p.Info,
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
	p1Isv4 := p1.To4() != nil
	p2Isv4 := p2.To4() != nil
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
	strings := sort.StringSlice{cidr2prefix(fmt.Sprintf("%s/%d", p1.String(), addrlen)),
		cidr2prefix(fmt.Sprintf("%s/%d", p2.String(), addrlen))}
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

type prefixes []*gobgpapi.PrefixSet

func (p prefixes) Len() int {
	return len(p)
}

func (p prefixes) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

func (p prefixes) Less(i, j int) bool {
	return p[i].PrefixSetName < p[j].PrefixSetName
}

type neighbors []*gobgpapi.NeighborSet

func (n neighbors) Len() int {
	return len(n)
}

func (n neighbors) Swap(i, j int) {
	n[i], n[j] = n[j], n[i]
}

func (n neighbors) Less(i, j int) bool {
	return n[i].NeighborSetName < n[j].NeighborSetName
}

type aspaths []*gobgpapi.AsPathSet

func (a aspaths) Len() int {
	return len(a)
}

func (a aspaths) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a aspaths) Less(i, j int) bool {
	return a[i].AsPathSetName < a[j].AsPathSetName
}

type communities []*gobgpapi.CommunitySet

func (c communities) Len() int {
	return len(c)
}

func (c communities) Swap(i, j int) {
	c[i], c[j] = c[j], c[i]
}

func (c communities) Less(i, j int) bool {
	return c[i].CommunitySetName < c[j].CommunitySetName
}

type extcommunities []*gobgpapi.ExtCommunitySet

func (e extcommunities) Len() int {
	return len(e)
}

func (e extcommunities) Swap(i, j int) {
	e[i], e[j] = e[j], e[i]
}

func (e extcommunities) Less(i, j int) bool {
	return e[i].ExtCommunitySetName < e[j].ExtCommunitySetName
}

type policyDefinitions []*gobgpapi.PolicyDefinition

func (p policyDefinitions) Len() int {
	return len(p)
}

func (p policyDefinitions) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

func (p policyDefinitions) Less(i, j int) bool {
	return p[i].PolicyDefinitionName < p[j].PolicyDefinitionName
}

type roas []*gobgpapi.ROA

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

	// determine IP address version
	host := net.ParseIP(globalOpts.Host)
	target := fmt.Sprintf("%s:%d", globalOpts.Host, globalOpts.Port)
	if host.To4() == nil {
		target = fmt.Sprintf("[%s]:%d", globalOpts.Host, globalOpts.Port)
	}

	conn, err := grpc.Dial(target, timeout, grpc.WithBlock(), grpc.WithInsecure())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return conn
}

func checkAddressFamily(ip net.IP) (bgp.RouteFamily, error) {
	var rf bgp.RouteFamily
	var e error
	switch subOpts.AddressFamily {
	case "ipv4", "v4", "4":
		rf = bgp.RF_IPv4_UC
	case "ipv6", "v6", "6":
		rf = bgp.RF_IPv6_UC
	case "vpnv4", "vpn-ipv4":
		rf = bgp.RF_IPv4_VPN
	case "vpnv6", "vpn-ipv6":
		rf = bgp.RF_IPv6_VPN
	case "evpn":
		rf = bgp.RF_EVPN
	case "encap":
		rf = bgp.RF_ENCAP
	case "rtc":
		rf = bgp.RF_RTC_UC
	case "ipv4-flowspec", "ipv4-flow", "flow4":
		rf = bgp.RF_FS_IPv4_UC
	case "ipv6-flowspec", "ipv6-flow", "flow6":
		rf = bgp.RF_FS_IPv6_UC
	case "":
		if len(ip) == 0 || ip.To4() != nil {
			rf = bgp.RF_IPv4_UC
		} else {
			rf = bgp.RF_IPv6_UC
		}
	default:
		e = fmt.Errorf("unsupported address family: %s", subOpts.AddressFamily)
	}
	return rf, e
}
