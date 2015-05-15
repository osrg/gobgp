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

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/jessevdk/go-flags"
	"github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/policy"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"io"
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
	CMD_ROUTEPOLICY    = "routepolicy"
)

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

type paths []*api.Path

func (p paths) Len() int {
	return len(p)
}

func (p paths) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

func (p paths) Less(i, j int) bool {
	if p[i].Nlri.Prefix == p[j].Nlri.Prefix {
		if p[i].Best {
			return true
		}
	}
	strings := sort.StringSlice{cidr2prefix(p[i].Nlri.Prefix),
		cidr2prefix(p[j].Nlri.Prefix)}
	return strings.Less(0, 1)
}

type peers []*api.Peer

func (p peers) Len() int {
	return len(p)
}

func (p peers) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

func (p peers) Less(i, j int) bool {
	p1 := net.ParseIP(p[i].Conf.RemoteIp)
	p2 := net.ParseIP(p[j].Conf.RemoteIp)
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

type prefixes []*api.PrefixSet

func (p prefixes) Len() int {
	return len(p)
}

func (p prefixes) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

func (p prefixes) Less(i, j int) bool {
	return p[i].PrefixSetName < p[j].PrefixSetName
}

type neighbors []*api.NeighborSet

func (n neighbors) Len() int {
	return len(n)
}

func (n neighbors) Swap(i, j int) {
	n[i], n[j] = n[j], n[i]
}

func (n neighbors) Less(i, j int) bool {
	return n[i].NeighborSetName < n[j].NeighborSetName
}

type policyDefinitions []*api.PolicyDefinition

func (p policyDefinitions) Len() int {
	return len(p)
}

func (p policyDefinitions) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

func (p policyDefinitions) Less(i, j int) bool {
	return p[i].PolicyDefinitionName < p[j].PolicyDefinitionName
}

func connGrpc() *grpc.ClientConn {
	timeout := grpc.WithTimeout(time.Second)

	// determine IP address version
	host := net.ParseIP(globalOpts.Host)
	target := fmt.Sprintf("%s:%d", globalOpts.Host, globalOpts.Port)
	if host.To4() == nil {
		target = fmt.Sprintf("[%s]:%d", globalOpts.Host, globalOpts.Port)
	}

	conn, err := grpc.Dial(target, timeout)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return conn
}

func requestGrpc(cmd string, eArgs []string, remoteIP net.IP) error {
	conn := connGrpc()
	defer conn.Close()
	client = api.NewGrpcClient(conn)

	switch cmd {
	case CMD_GLOBAL + "_" + CMD_RIB:
		return showGlobalRib()
	case CMD_GLOBAL + "_" + CMD_RIB + "_" + CMD_ADD:
		return modPath(CMD_ADD, eArgs)
	case CMD_GLOBAL + "_" + CMD_RIB + "_" + CMD_DEL:
		return modPath(CMD_DEL, eArgs)
	case CMD_NEIGHBOR:
		if len(eArgs) == 0 {
			return showNeighbors()
		} else {
			return showNeighbor(eArgs)
		}
	case CMD_NEIGHBOR + "_" + CMD_LOCAL:
		return showNeighborRib(api.Resource_LOCAL, remoteIP)
	case CMD_NEIGHBOR + "_" + CMD_ADJ_IN:
		return showNeighborRib(api.Resource_ADJ_IN, remoteIP)
	case CMD_NEIGHBOR + "_" + CMD_ADJ_OUT:
		return showNeighborRib(api.Resource_ADJ_OUT, remoteIP)
	case CMD_NEIGHBOR + "_" + CMD_RESET:
		return resetNeighbor(CMD_RESET, remoteIP)
	case CMD_NEIGHBOR + "_" + CMD_SOFT_RESET:
		return resetNeighbor(CMD_SOFT_RESET, remoteIP)
	case CMD_NEIGHBOR + "_" + CMD_SOFT_RESET_IN:
		return resetNeighbor(CMD_SOFT_RESET_IN, remoteIP)
	case CMD_NEIGHBOR + "_" + CMD_SOFT_RESET_OUT:
		return resetNeighbor(CMD_SOFT_RESET_OUT, remoteIP)
	case CMD_NEIGHBOR + "_" + CMD_SHUTDOWN:
		return stateChangeNeighbor(CMD_SHUTDOWN, remoteIP)
	case CMD_NEIGHBOR + "_" + CMD_ENABLE:
		return stateChangeNeighbor(CMD_ENABLE, remoteIP)
	case CMD_NEIGHBOR + "_" + CMD_DISABLE:
		return stateChangeNeighbor(CMD_DISABLE, remoteIP)
	case CMD_NEIGHBOR + "_" + CMD_POLICY:
		return showNeighborPolicy(remoteIP)
	case CMD_POLICY + "_" + CMD_PREFIX:
		if len(eArgs) == 0 {
			return showPolicyPrefixes()
		} else {
			return showPolicyPrefix(eArgs)
		}
	case CMD_POLICY + "_" + CMD_PREFIX + "_" + CMD_ADD:
		return modPolicyPrefix(CMD_ADD, eArgs)
	case CMD_POLICY + "_" + CMD_PREFIX + "_" + CMD_DEL:
		return modPolicyPrefix(CMD_DEL, eArgs)
	case CMD_POLICY + "_" + CMD_NEIGHBOR:
		if len(eArgs) == 0 {
			return showPolicyNeighbors()
		} else {
			return showPolicyNeighbor(eArgs)
		}
	case CMD_POLICY + "_" + CMD_NEIGHBOR + "_" + CMD_ADD:
		return modPolicyNeighbor(CMD_ADD, eArgs)
	case CMD_POLICY + "_" + CMD_NEIGHBOR + "_" + CMD_DEL:
		return modPolicyNeighbor(CMD_DEL, eArgs)
	case CMD_POLICY + "_" + CMD_ROUTEPOLICY:
		if len(eArgs) == 0 {
			return showPolicyRoutePolicies()
		} else {
			return showPolicyRoutePolicy(eArgs)
		}
	}
	return nil
}

var cmds []string

func extractArgs(head string) []string {
	eArgs := make([]string, 0)
	existHead := false
	existRear := false
	if head == "" {
		existHead = true
	}
	for _, arg := range os.Args {
		if existHead {
			eArgs = append(eArgs, arg)
			for _, cmd := range cmds {
				if arg == cmd {
					existRear = true
					break
				}
			}
			if existRear {
				break
			}
		} else {
			if arg == head {
				existHead = true
			}
		}
	}
	return eArgs
}

func checkAddressFamily(ip net.IP) (*api.AddressFamily, error) {
	var rf *api.AddressFamily
	var e error
	switch subOpts.AddressFamily {
	case "ipv4", "v4", "4":
		rf = api.AF_IPV4_UC
	case "ipv6", "v6", "6":
		rf = api.AF_IPV6_UC
	case "evpn":
		rf = api.AF_EVPN
	case "encap":
		rf = api.AF_ENCAP
	case "rtc":
		rf = api.AF_RTC
	case "":
		if len(ip) == 0 || ip.To4() != nil {
			rf = api.AF_IPV4_UC
		} else {
			rf = api.AF_IPV6_UC
		}
	default:
		e = fmt.Errorf("unsupported address family: %s", subOpts.AddressFamily)
	}
	return rf, e
}

var client api.GrpcClient

type GlobalCommand struct{}

func (x *GlobalCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_GLOBAL)
	parser := flags.NewParser(nil, flags.Default)
	parser.Usage = "global"
	parser.AddCommand(CMD_RIB, "subcommand for rib of global", "", &GlobalRibCommand{})
	if _, err := parser.ParseArgs(eArgs); err != nil {
		os.Exit(1)
	}
	return nil
}

type GlobalRibCommand struct{}

func showGlobalRib() error {
	rt, err := checkAddressFamily(net.IP{})
	if err != nil {
		return err
	}
	arg := &api.Arguments{
		Resource: api.Resource_GLOBAL,
		Af:       rt,
	}

	stream, e := client.GetRib(context.Background(), arg)
	if e != nil {
		return e
	}
	ds := []*api.Destination{}
	for {
		d, e := stream.Recv()
		if e == io.EOF {
			break
		} else if e != nil {
			return e
		}
		ds = append(ds, d)
	}

	if globalOpts.Json {
		j, _ := json.Marshal(ds)
		fmt.Println(string(j))
		return nil
	}

	ps := paths{}
	for _, d := range ds {
		for idx, p := range d.Paths {
			if idx == int(d.BestPathIdx) {
				p.Best = true
			}
			ps = append(ps, p)
		}
	}

	sort.Sort(ps)

	showRoute(ps, true, true)
	return nil
}
func (x *GlobalRibCommand) Execute(args []string) error {

	eArgs := extractArgs(CMD_RIB)
	parser := flags.NewParser(&subOpts, flags.Default)
	if len(eArgs) == 0 || (len(eArgs) < 3 && eArgs[0] == "-a") {
		if _, err := parser.ParseArgs(eArgs); err != nil {
			os.Exit(1)
		}
		if err := requestGrpc(CMD_GLOBAL+"_"+CMD_RIB, eArgs, nil); err != nil {
			return err
		}
	} else {
		parser.Usage = "global rib [OPTIONS]\n  gobgp global rib"
		parser.AddCommand(CMD_ADD, "subcommand for add route to global rib", "", &GlobalRibAddCommand{})
		parser.AddCommand(CMD_DEL, "subcommand for delete route from global rib", "", &GlobalRibDelCommand{})
		if _, err := parser.ParseArgs(eArgs); err != nil {
			os.Exit(1)
		}
	}
	return nil
}

type GlobalRibAddCommand struct{}

func modPath(modtype string, eArgs []string) error {
	rf, err := checkAddressFamily(net.IP{})
	if err != nil {
		return err
	}

	path := &api.Path{}
	var prefix, macAddr, ipAddr string
	switch rf {
	case api.AF_IPV4_UC, api.AF_IPV6_UC:
		if len(eArgs) == 1 || len(eArgs) == 3 {
			prefix = eArgs[0]
		} else {
			return fmt.Errorf("usage: global rib %s <prefix> -a { ipv4 | ipv6 }", modtype)
		}
		path.Nlri = &api.Nlri{
			Af:     rf,
			Prefix: prefix,
		}
	case api.AF_EVPN:
		if len(eArgs) == 4 {
			macAddr = eArgs[0]
			ipAddr = eArgs[1]
		} else {
			return fmt.Errorf("usage: global rib %s <mac address> <ip address> -a evpn", modtype)
		}
		path.Nlri = &api.Nlri{
			Af: rf,
			EvpnNlri: &api.EVPNNlri{
				Type: api.EVPN_TYPE_ROUTE_TYPE_MAC_IP_ADVERTISEMENT,
				MacIpAdv: &api.EvpnMacIpAdvertisement{
					MacAddr: macAddr,
					IpAddr:  ipAddr,
				},
			},
		}
	case api.AF_ENCAP:
		if len(eArgs) < 3 {
			return fmt.Errorf("usage: global rib %s <end point ip address> [<vni>] -a encap", modtype)
		}
		prefix = eArgs[0]

		path.Nlri = &api.Nlri{
			Af:     rf,
			Prefix: prefix,
		}

		if len(eArgs) > 3 {
			vni, err := strconv.Atoi(eArgs[1])
			if err != nil {
				return fmt.Errorf("invalid vni: %s", eArgs[1])
			}
			subTlv := &api.TunnelEncapSubTLV{
				Type:  api.ENCAP_SUBTLV_TYPE_COLOR,
				Color: uint32(vni),
			}
			tlv := &api.TunnelEncapTLV{
				Type:   api.TUNNEL_TYPE_VXLAN,
				SubTlv: []*api.TunnelEncapSubTLV{subTlv},
			}
			attr := &api.PathAttr{
				Type:        api.BGP_ATTR_TYPE_TUNNEL_ENCAP,
				TunnelEncap: []*api.TunnelEncapTLV{tlv},
			}

			path.Attrs = append(path.Attrs, attr)
		}
	case api.AF_RTC:
		if !(len(eArgs) == 3 && eArgs[0] == "default") && len(eArgs) < 4 {
			return fmt.Errorf("usage: global rib add <asn> <local admin> -a rtc")
		}
		var asn, admin int

		if eArgs[0] != "default" {
			asn, err = strconv.Atoi(eArgs[0])
			if err != nil {
				return fmt.Errorf("invalid asn: %s", eArgs[0])
			}
			admin, err = strconv.Atoi(eArgs[1])
			if err != nil {
				return fmt.Errorf("invalid local admin: %s", eArgs[1])
			}
		}
		path.Nlri = &api.Nlri{
			Af: rf,
			RtNlri: &api.RTNlri{
				Target: &api.ExtendedCommunity{
					Type:       api.EXTENDED_COMMUNITIE_TYPE_TWO_OCTET_AS_SPECIFIC,
					Subtype:    api.EXTENDED_COMMUNITIE_SUBTYPE_ROUTE_TARGET,
					Asn:        uint32(asn),
					LocalAdmin: uint32(admin),
				},
			},
		}
	}
	switch modtype {
	case "add":
		path.IsWithdraw = false
	case "del":
		path.IsWithdraw = true
	}

	arg := &api.ModPathArguments{
		Resource: api.Resource_GLOBAL,
		Path:     path,
	}
	stream, err := client.ModPath(context.Background())
	if err != nil {
		return err
	}
	err = stream.Send(arg)
	if err != nil {
		return err
	}
	stream.CloseSend()

	res, e := stream.Recv()
	if e != nil {
		return e
	}
	if res.Code != api.Error_SUCCESS {
		return fmt.Errorf("error: code: %d, msg: %s", res.Code, res.Msg)
	}
	return nil
}

func (x *GlobalRibAddCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_ADD)
	parser := flags.NewParser(&subOpts, flags.Default)
	parser.Usage = "global rib add <prefix> -a { ipv4 | ipv6 }\n" +
		"    -> if -a option is ipv4 or ipv6\n" +
		"  gobgp global rib add <mac address> <ip address> -a evpn\n" +
		"    -> if -a option is evpn"
	parser.ParseArgs(eArgs)
	if len(eArgs) == 1 {
		if eArgs[0] == "-h" || eArgs[0] == "--help" {
			return nil
		}
	}
	if err := requestGrpc(CMD_GLOBAL+"_"+CMD_RIB+"_"+CMD_ADD, eArgs, nil); err != nil {
		return err
	}
	return nil
}

type GlobalRibDelCommand struct{}

func (x *GlobalRibDelCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_DEL)
	parser := flags.NewParser(&subOpts, flags.Default)
	parser.Usage = "global rib del <prefix> -a { ipv4 | ipv6 }\n" +
		"    -> if -a option is ipv4 or ipv6\n" +
		"  gobgp global rib del <mac address> <ip address> -a evpn\n" +
		"    -> if -a option is evpn"
	parser.ParseArgs(eArgs)
	if len(eArgs) == 1 {
		if eArgs[0] == "-h" || eArgs[0] == "--help" {
			return nil
		}
	}
	if err := requestGrpc(CMD_GLOBAL+"_"+CMD_RIB+"_"+CMD_DEL, eArgs, nil); err != nil {
		return err
	}
	return nil
}

type NeighborCommand struct {
}

func showNeighbors() error {
	arg := &api.Arguments{}
	stream, e := client.GetNeighbors(context.Background(), arg)
	if e != nil {
		fmt.Println(e)
		return e
	}
	m := peers{}
	for {
		p, e := stream.Recv()
		if e == io.EOF {
			break
		} else if e != nil {
			return e
		}
		if neighborsOpts.Transport != "" {
			addr := net.ParseIP(p.Conf.RemoteIp)
			if addr.To4() != nil {
				if neighborsOpts.Transport != "ipv4" {
					continue
				}
			} else {
				if neighborsOpts.Transport != "ipv6" {
					continue
				}
			}
		}
		m = append(m, p)
	}

	if globalOpts.Json {
		j, _ := json.Marshal(m)
		fmt.Println(string(j))
		return nil
	}

	if globalOpts.Quiet {
		for _, p := range m {
			fmt.Println(p.Conf.RemoteIp)
		}
		return nil
	}
	maxaddrlen := 0
	maxaslen := 0
	maxtimelen := len("Up/Down")
	timedelta := []string{}

	sort.Sort(m)

	for _, p := range m {
		if len(p.Conf.RemoteIp) > maxaddrlen {
			maxaddrlen = len(p.Conf.RemoteIp)
		}

		if len(fmt.Sprint(p.Conf.RemoteAs)) > maxaslen {
			maxaslen = len(fmt.Sprint(p.Conf.RemoteAs))
		}
		var t string
		if p.Info.Uptime == 0 {
			t = "never"
		} else if p.Info.BgpState == "BGP_FSM_ESTABLISHED" {
			t = formatTimedelta(p.Info.Uptime)
		} else {
			t = formatTimedelta(p.Info.Downtime)
		}
		if len(t) > maxtimelen {
			maxtimelen = len(t)
		}
		timedelta = append(timedelta, t)
	}
	var format string
	format = "%-" + fmt.Sprint(maxaddrlen) + "s" + " %" + fmt.Sprint(maxaslen) + "s" + " %" + fmt.Sprint(maxtimelen) + "s"
	format += " %-11s |%11s %8s %8s\n"
	fmt.Printf(format, "Peer", "AS", "Up/Down", "State", "#Advertised", "Received", "Accepted")
	format_fsm := func(admin, fsm string) string {
		if admin == "ADMIN_STATE_DOWN" {
			return "Idle(Admin)"
		}

		if fsm == "BGP_FSM_IDLE" {
			return "Idle"
		} else if fsm == "BGP_FSM_CONNECT" {
			return "Connect"
		} else if fsm == "BGP_FSM_ACTIVE" {
			return "Active"
		} else if fsm == "BGP_FSM_OPENSENT" {
			return "Sent"
		} else if fsm == "BGP_FSM_OPENCONFIRM" {
			return "Confirm"
		} else {
			return "Establ"
		}
	}

	for i, p := range m {
		fmt.Printf(format, p.Conf.RemoteIp, fmt.Sprint(p.Conf.RemoteAs), timedelta[i], format_fsm(p.Info.AdminState, p.Info.BgpState), fmt.Sprint(p.Info.Advertized), fmt.Sprint(p.Info.Received), fmt.Sprint(p.Info.Accepted))
	}

	return nil
}

type capabilities []*api.Capability

func (c capabilities) Len() int {
	return len(c)
}

func (c capabilities) Swap(i, j int) {
	c[i], c[j] = c[j], c[i]
}

func (c capabilities) Less(i, j int) bool {
	return c[i].Code < c[j].Code
}

func showNeighbor(args []string) error {
	id := &api.Arguments{
		RouterId: args[0],
	}
	p, e := client.GetNeighbor(context.Background(), id)
	if e != nil {
		fmt.Println(e)
		return e
	}

	if globalOpts.Json {
		j, _ := json.Marshal(p)
		fmt.Println(string(j))
		return nil
	}

	fmt.Printf("BGP neighbor is %s, remote AS %d\n", p.Conf.RemoteIp, p.Conf.RemoteAs)
	fmt.Printf("  BGP version 4, remote router ID %s\n", p.Conf.Id)
	fmt.Printf("  BGP state = %s, up for %s\n", p.Info.BgpState, formatTimedelta(p.Info.Uptime))
	fmt.Printf("  BGP OutQ = %d, Flops = %d\n", p.Info.OutQ, p.Info.Flops)
	fmt.Printf("  Hold time is %d, keepalive interval is %d seconds\n", p.Info.NegotiatedHoldtime, p.Info.KeepaliveInterval)
	fmt.Printf("  Configured hold time is %d, keepalive interval is %d seconds\n", p.Conf.Holdtime, p.Conf.KeepaliveInterval)

	fmt.Printf("  Neighbor capabilities:\n")
	caps := capabilities{}
	lookup := func(val *api.Capability, l capabilities) *api.Capability {
		for _, v := range l {
			if v.Code == val.Code {
				if v.Code == api.BGP_CAPABILITY_MULTIPROTOCOL {
					if v.MultiProtocol.Equal(val.MultiProtocol) {
						return v
					}
					continue
				}
				return v
			}
		}
		return nil
	}
	caps = append(caps, p.Conf.LocalCap...)
	for _, v := range p.Conf.RemoteCap {
		if lookup(v, caps) == nil {
			caps = append(caps, v)
		}
	}

	sort.Sort(caps)

	for _, c := range caps {
		support := ""
		if m := lookup(c, p.Conf.LocalCap); m != nil {
			support += "advertised"
		}
		if lookup(c, p.Conf.RemoteCap) != nil {
			if len(support) != 0 {
				support += " and "
			}
			support += "received"
		}

		if c.Code != api.BGP_CAPABILITY_MULTIPROTOCOL {
			fmt.Printf("    %s: %s\n", c.Code, support)
		} else {
			fmt.Printf("    %s(%s,%s): %s\n", c.Code, c.MultiProtocol.Afi, c.MultiProtocol.Safi, support)
		}
	}
	fmt.Print("  Message statistics:\n")
	fmt.Print("                         Sent       Rcvd\n")
	fmt.Printf("    Opens:         %10d %10d\n", p.Info.OpenMessageOut, p.Info.OpenMessageIn)
	fmt.Printf("    Notifications: %10d %10d\n", p.Info.NotificationOut, p.Info.NotificationIn)
	fmt.Printf("    Updates:       %10d %10d\n", p.Info.UpdateMessageOut, p.Info.UpdateMessageIn)
	fmt.Printf("    Keepalives:    %10d %10d\n", p.Info.KeepAliveMessageOut, p.Info.KeepAliveMessageIn)
	fmt.Printf("    Route Refesh:  %10d %10d\n", p.Info.RefreshMessageOut, p.Info.RefreshMessageIn)
	fmt.Printf("    Discarded:     %10d %10d\n", p.Info.DiscardedOut, p.Info.DiscardedIn)
	fmt.Printf("    Total:         %10d %10d\n", p.Info.TotalMessageOut, p.Info.TotalMessageIn)

	return nil
}

func (x *NeighborCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_NEIGHBOR)

	if len(eArgs) == 0 || (strings.HasPrefix(eArgs[0], "-") && !(eArgs[0] == "-h" || eArgs[0] == "--help")) {
		parser := flags.NewParser(&neighborsOpts, flags.Default)
		if _, err := parser.ParseArgs(eArgs); err != nil {
			os.Exit(1)
		}
		if err := requestGrpc(CMD_NEIGHBOR, []string{}, nil); err != nil {
			return err
		}
	} else if len(eArgs) == 1 && !(eArgs[0] == "-h" || eArgs[0] == "--help") {
		if err := requestGrpc(CMD_NEIGHBOR, eArgs, nil); err != nil {
			return err
		}
	} else {
		parser := flags.NewParser(nil, flags.Default)
		parser.Usage = "neighbor [ <neighbor address> ]\n  gobgp neighbor"
		parser.AddCommand(CMD_LOCAL, "subcommand for local-rib of neighbor", "", NewNeighborRibCommand(eArgs[0], api.Resource_LOCAL, CMD_LOCAL))
		parser.AddCommand(CMD_ADJ_IN, "subcommand for adj-rib-in of neighbor", "", NewNeighborRibCommand(eArgs[0], api.Resource_ADJ_IN, CMD_ADJ_IN))
		parser.AddCommand(CMD_ADJ_OUT, "subcommand for adj-rib-out of neighbor", "", NewNeighborRibCommand(eArgs[0], api.Resource_ADJ_OUT, CMD_ADJ_OUT))
		parser.AddCommand(CMD_RESET, "subcommand for reset the rib of neighbor", "", NewNeighborResetCommand(eArgs[0], CMD_RESET))
		parser.AddCommand(CMD_SOFT_RESET, "subcommand for softreset the rib of neighbor", "", NewNeighborResetCommand(eArgs[0], CMD_SOFT_RESET))
		parser.AddCommand(CMD_SOFT_RESET_IN, "subcommand for softreset the adj-rib-in of neighbor", "", NewNeighborResetCommand(eArgs[0], CMD_SOFT_RESET_IN))
		parser.AddCommand(CMD_SOFT_RESET_OUT, "subcommand for softreset the adj-rib-out of neighbor", "", NewNeighborResetCommand(eArgs[0], CMD_SOFT_RESET_OUT))
		parser.AddCommand(CMD_SHUTDOWN, "subcommand for shutdown to neighbor", "", NewNeighborChangeStateCommand(eArgs[0], CMD_SHUTDOWN))
		parser.AddCommand(CMD_ENABLE, "subcommand for enable to neighbor", "", NewNeighborChangeStateCommand(eArgs[0], CMD_ENABLE))
		parser.AddCommand(CMD_DISABLE, "subcommand for disable to neighbor", "", NewNeighborChangeStateCommand(eArgs[0], CMD_DISABLE))
		parser.AddCommand(CMD_POLICY, "subcommand for policy of neighbor", "", NewNeighborPolicyCommand(eArgs[0]))
		if _, err := parser.ParseArgs(eArgs); err != nil {
			os.Exit(1)
		}
	}
	return nil
}

type NeighborRibCommand struct {
	remoteIP net.IP
	resource api.Resource
	command  string
}

func NewNeighborRibCommand(addr string, resource api.Resource, cmd string) *NeighborRibCommand {
	return &NeighborRibCommand{
		remoteIP: net.ParseIP(addr),
		resource: resource,
		command:  cmd,
	}
}

func showRoute(pathList []*api.Path, showAge bool, showBest bool) {

	var pathStrs [][]interface{}
	maxPrefixLen := len("Network")
	maxNexthopLen := len("Next Hop")
	maxAsPathLen := len("AS_PATH")

	for _, p := range pathList {
		aspath := func(attrs []*api.PathAttr) string {
			s := bytes.NewBuffer(make([]byte, 0, 64))
			s.WriteString("[")
			for _, a := range attrs {
				if a.Type == api.BGP_ATTR_TYPE_AS_PATH {
					var ss []string
					for _, as := range a.AsPath {
						ss = append(ss, fmt.Sprintf("%d", as))
					}
					s.WriteString(strings.Join(ss, " "))
				}
			}
			s.WriteString("]")
			return s.String()
		}
		formatAttrs := func(attrs []*api.PathAttr) string {
			s := []string{}
			for _, a := range attrs {
				switch a.Type {
				case api.BGP_ATTR_TYPE_ORIGIN:
					s = append(s, fmt.Sprintf("{Origin: %s}", a.Origin))
				case api.BGP_ATTR_TYPE_MULTI_EXIT_DISC:
					s = append(s, fmt.Sprintf("{Med: %d}", a.Metric))
				case api.BGP_ATTR_TYPE_LOCAL_PREF:
					s = append(s, fmt.Sprintf("{LocalPref: %v}", a.Pref))
				case api.BGP_ATTR_TYPE_ATOMIC_AGGREGATE:
					s = append(s, "AtomicAggregate")
				case api.BGP_ATTR_TYPE_AGGREGATOR:
					s = append(s, fmt.Sprintf("{Aggregate: {AS: %d, Address: %s}", a.GetAggregator().As, a.GetAggregator().Address))
				case api.BGP_ATTR_TYPE_COMMUNITIES:
					l := []string{}
					known := map[uint32]string{
						0xffff0000: "planned-shut",
						0xffff0001: "accept-own",
						0xffff0002: "ROUTE_FILTER_TRANSLATED_v4",
						0xffff0003: "ROUTE_FILTER_v4",
						0xffff0004: "ROUTE_FILTER_TRANSLATED_v6",
						0xffff0005: "ROUTE_FILTER_v6",
						0xffff0006: "LLGR_STALE",
						0xffff0007: "NO_LLGR",
						0xFFFFFF01: "NO_EXPORT",
						0xFFFFFF02: "NO_ADVERTISE",
						0xFFFFFF03: "NO_EXPORT_SUBCONFED",
						0xFFFFFF04: "NOPEER"}

					for _, v := range a.Communites {
						k, found := known[v]
						if found {
							l = append(l, fmt.Sprint(k))
						} else {
							l = append(l, fmt.Sprintf("%d:%d", (0xffff0000&v)>>16, 0xffff&v))
						}
					}
					s = append(s, fmt.Sprintf("{Community: %v}", l))
				case api.BGP_ATTR_TYPE_ORIGINATOR_ID:
					s = append(s, fmt.Sprintf("{Originator: %v}", a.Originator))
				case api.BGP_ATTR_TYPE_CLUSTER_LIST:
					s = append(s, fmt.Sprintf("{Cluster: %v}", a.Cluster))
				case api.BGP_ATTR_TYPE_TUNNEL_ENCAP:
					s1 := bytes.NewBuffer(make([]byte, 0, 64))
					s1.WriteString("{Encap: ")
					var s2 []string
					for _, tlv := range a.TunnelEncap {
						s3 := bytes.NewBuffer(make([]byte, 0, 64))
						s3.WriteString(fmt.Sprintf("< %s | ", tlv.Type))
						var s4 []string
						for _, subTlv := range tlv.SubTlv {
							if subTlv.Type == api.ENCAP_SUBTLV_TYPE_COLOR {
								s4 = append(s4, fmt.Sprintf("color: %d", subTlv.Color))
							}
						}
						s3.WriteString(strings.Join(s4, ","))
						s3.WriteString(" >")
						s2 = append(s2, s3.String())
					}
					s1.WriteString(strings.Join(s2, "|"))
					s1.WriteString("}")
					s = append(s, s1.String())
				case api.BGP_ATTR_TYPE_AS4_PATH, api.BGP_ATTR_TYPE_MP_REACH_NLRI, api.BGP_ATTR_TYPE_MP_UNREACH_NLRI, api.BGP_ATTR_TYPE_NEXT_HOP, api.BGP_ATTR_TYPE_AS_PATH:
				default:
					s = append(s, fmt.Sprintf("{%v: %v}", a.Type, a.Value))
				}
			}
			return fmt.Sprint(s)
		}
		best := ""
		if showBest {
			if p.Best {
				best = "*>"
			} else {
				best = "* "
			}
		}

		if maxPrefixLen < len(p.Nlri.Prefix) {
			maxPrefixLen = len(p.Nlri.Prefix)
		}

		if maxNexthopLen < len(p.Nexthop) {
			maxNexthopLen = len(p.Nexthop)
		}

		if maxAsPathLen < len(aspath(p.Attrs)) {
			maxAsPathLen = len(aspath(p.Attrs))
		}

		if showAge {
			pathStrs = append(pathStrs, []interface{}{best, p.Nlri.Prefix, p.Nexthop, aspath(p.Attrs), formatTimedelta(p.Age), formatAttrs(p.Attrs)})
		} else {
			pathStrs = append(pathStrs, []interface{}{best, p.Nlri.Prefix, p.Nexthop, aspath(p.Attrs), formatAttrs(p.Attrs)})
		}
	}

	var format string
	if showAge {
		format = fmt.Sprintf("%%-2s %%-%ds %%-%ds %%-%ds %%-10s %%-s\n", maxPrefixLen, maxNexthopLen, maxAsPathLen)
		fmt.Printf(format, "", "Network", "Next Hop", "AS_PATH", "Age", "Attrs")
	} else {
		format = fmt.Sprintf("%%-2s %%-%ds %%-%ds %%-%ds %%-s\n", maxPrefixLen, maxNexthopLen, maxAsPathLen)
		fmt.Printf(format, "", "Network", "Next Hop", "AS_PATH", "Attrs")
	}

	for _, pathStr := range pathStrs {
		fmt.Printf(format, pathStr...)
	}
}

func showNeighborRib(resource api.Resource, remoteIP net.IP) error {
	rt, err := checkAddressFamily(remoteIP)
	if err != nil {
		return err
	}
	arg := &api.Arguments{
		Resource: resource,
		Af:       rt,
		RouterId: remoteIP.String(),
	}

	ps := paths{}
	showBest := false
	showAge := true
	switch resource {
	case api.Resource_LOCAL:
		showBest = true
		stream, e := client.GetRib(context.Background(), arg)
		if e != nil {
			return e
		}

		ds := []*api.Destination{}
		for {
			d, e := stream.Recv()
			if e == io.EOF {
				break
			} else if e != nil {
				return e
			}
			ds = append(ds, d)
		}

		if globalOpts.Json {
			j, _ := json.Marshal(ds)
			fmt.Println(string(j))
			return nil
		}

		for _, d := range ds {
			for idx, p := range d.Paths {
				if idx == int(d.BestPathIdx) {
					p.Best = true
				}
				ps = append(ps, p)
			}
		}
	case api.Resource_ADJ_OUT:
		showAge = false
		fallthrough
	case api.Resource_ADJ_IN:
		stream, e := client.GetAdjRib(context.Background(), arg)
		if e != nil {
			return e
		}
		for {
			p, e := stream.Recv()
			if e == io.EOF {
				break
			} else if e != nil {
				return e
			}
			ps = append(ps, p)
		}
		if globalOpts.Json {
			j, _ := json.Marshal(ps)
			fmt.Println(string(j))
			return nil
		}
	}

	sort.Sort(ps)
	showRoute(ps, showAge, showBest)
	return nil
}

func (x *NeighborRibCommand) Execute(args []string) error {
	eArgs := extractArgs(x.command)
	parser := flags.NewParser(&subOpts, flags.Default)
	parser.Usage = fmt.Sprintf("neighbor <neighbor address> %s [OPTIONS]", x.command)
	parser.ParseArgs(eArgs)
	if len(eArgs) != 0 && (eArgs[0] == "-h" || eArgs[0] == "--help") {
		return nil
	}
	if err := requestGrpc(CMD_NEIGHBOR+"_"+x.command, eArgs, x.remoteIP); err != nil {
		return err
	}
	return nil
}

type NeighborResetCommand struct {
	remoteIP net.IP
	command  string
}

func NewNeighborResetCommand(addr string, cmd string) *NeighborResetCommand {
	return &NeighborResetCommand{
		remoteIP: net.ParseIP(addr),
		command:  cmd,
	}
}

func resetNeighbor(cmd string, remoteIP net.IP) error {
	rt, err := checkAddressFamily(remoteIP)
	if err != nil {
		return err
	}
	arg := &api.Arguments{
		RouterId: remoteIP.String(),
		Af:       rt,
	}
	switch cmd {
	case CMD_RESET:
		client.Reset(context.Background(), arg)
	case CMD_SOFT_RESET:
		client.SoftReset(context.Background(), arg)
	case CMD_SOFT_RESET_IN:
		client.SoftResetIn(context.Background(), arg)
	case CMD_SOFT_RESET_OUT:
		client.SoftResetOut(context.Background(), arg)
	}
	return nil
}

func (x *NeighborResetCommand) Execute(args []string) error {
	eArgs := extractArgs(x.command)
	parser := flags.NewParser(&subOpts, flags.Default)
	parser.Usage = fmt.Sprintf("neighbor <neighbor address> %s [OPTIONS]", x.command)
	parser.ParseArgs(eArgs)
	if len(eArgs) != 0 && (eArgs[0] == "-h" || eArgs[0] == "--help") {
		return nil
	}
	if err := requestGrpc(CMD_NEIGHBOR+"_"+x.command, eArgs, x.remoteIP); err != nil {
		return err
	}
	return nil
}

type NeighborChangeStateCommand struct {
	remoteIP net.IP
	command  string
}

func NewNeighborChangeStateCommand(addr string, cmd string) *NeighborChangeStateCommand {
	return &NeighborChangeStateCommand{
		remoteIP: net.ParseIP(addr),
		command:  cmd,
	}
}

func stateChangeNeighbor(cmd string, remoteIP net.IP) error {
	arg := &api.Arguments{
		RouterId: remoteIP.String(),
	}
	switch cmd {
	case CMD_SHUTDOWN:
		client.Shutdown(context.Background(), arg)
	case CMD_ENABLE:
		client.Enable(context.Background(), arg)
	case CMD_DISABLE:
		client.Disable(context.Background(), arg)
	}
	return nil
}

func (x *NeighborChangeStateCommand) Execute(args []string) error {
	eArgs := extractArgs(x.command)
	if err := requestGrpc(CMD_NEIGHBOR+"_"+x.command, eArgs, x.remoteIP); err != nil {
		return err
	}
	return nil
}

type NeighborPolicyCommand struct {
	remoteIP net.IP
}

func NewNeighborPolicyCommand(addr string) *NeighborPolicyCommand {
	return &NeighborPolicyCommand{
		remoteIP: net.ParseIP(addr),
	}
}

func showNeighborPolicy(remoteIP net.IP) error {
	rt, err := checkAddressFamily(net.IP{})
	if err != nil {
		return err
	}
	arg := &api.Arguments{
		Af:       rt,
		RouterId: remoteIP.String(),
	}

	ap, e := client.GetNeighborPolicy(context.Background(), arg)
	if e != nil {
		return e
	}

	if globalOpts.Json {
		j, _ := json.Marshal(ap)
		fmt.Println(string(j))
		return nil
	}
	var defaultInPolicy, defaultOutPolicy string
	switch ap.DefaultImportPolicy {
	case int64(policy.ROUTE_TYPE_ACCEPT):
		defaultInPolicy = "ACCEPT"
	case int64(policy.ROUTE_TYPE_REJECT):
		defaultInPolicy = "REJECT"
	}
	switch ap.DefaultExportPolicy {
	case int64(policy.ROUTE_TYPE_ACCEPT):
		defaultOutPolicy = "ACCEPT"
	case int64(policy.ROUTE_TYPE_REJECT):
		defaultOutPolicy = "REJECT"
	}

	fmt.Printf("DefaultImportPolicy: %s\n", defaultInPolicy)
	fmt.Printf("DefaultImportPolicy: %s\n", defaultOutPolicy)
	fmt.Printf("ImportPolicies:\n")

	for _, inPolicy := range ap.ImportPolicies {
		fmt.Printf("  PolicyName %s:\n", inPolicy.PolicyDefinitionName)
		showPolicyStatement("  ", inPolicy)
	}
	fmt.Printf("ExportPolicies:\n")
	for _, outPolicy := range ap.ExportPolicies {
		fmt.Printf("  PolicyName %s:\n", outPolicy.PolicyDefinitionName)
		showPolicyStatement("  ", outPolicy)
	}
	return nil
}

func (x *NeighborPolicyCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_POLICY)
	parser := flags.NewParser(nil, flags.Default)
	if len(eArgs) == 0 {
		if _, err := parser.ParseArgs(eArgs); err != nil {
			os.Exit(1)
		}
		if err := requestGrpc(CMD_NEIGHBOR+"_"+CMD_POLICY, eArgs, x.remoteIP); err != nil {
			return err
		}
	} else {
		parser.Usage = "neighbor [ <neighbor address> ] policy \n  gobgp neighbor [ <neighbor address> ]"
		if _, err := parser.ParseArgs(eArgs); err != nil {
			os.Exit(1)
		}
	}
	return nil
}

type PolicyCommand struct{}

func (x *PolicyCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_POLICY)
	parser := flags.NewParser(nil, flags.Default)
	parser.Usage = "policy"
	parser.AddCommand(CMD_PREFIX, "subcommand for prefix of policy", "", &PolicyPrefixCommand{})
	parser.AddCommand(CMD_NEIGHBOR, "subcommand for neighbor of policy", "", &PolicyNeighborCommand{})
	parser.AddCommand(CMD_ROUTEPOLICY, "subcommand for routepolicy of policy", "", &PolicyRoutePolicyCommand{})
	if _, err := parser.ParseArgs(eArgs); err != nil {
		os.Exit(1)
	}
	return nil
}

type PolicyPrefixCommand struct{}

func formatPolicyPrefix(prefixSetList []*api.PrefixSet) (string, string) {
	maxNameLen := len("Name")
	maxPrefixLen := len("Prefix")
	maxRangeLen := len("MaskRange")
	for _, ps := range prefixSetList {
		if len(ps.PrefixSetName) > maxNameLen {
			maxNameLen = len(ps.PrefixSetName)
		}
		for _, p := range ps.PrefixList {
			if len(p.Address)+len(fmt.Sprint(p.MaskLength))+1 > maxPrefixLen {
				maxPrefixLen = len(p.Address) + len(fmt.Sprint(p.MaskLength)) + 1
			}
			if len(p.MaskLengthRange) > maxRangeLen {
				maxRangeLen = len(p.MaskLengthRange)
			}
		}
	}
	formatPrefixSet := "%-" + fmt.Sprint(maxNameLen) + "s  %-" + fmt.Sprint(maxPrefixLen) + "s  %-" + fmt.Sprint(maxRangeLen) + "s\n"
	formatPrefixListOnly := "%-" + fmt.Sprint(maxPrefixLen) + "s  %-" + fmt.Sprint(maxRangeLen) + "s\n"
	return formatPrefixSet, formatPrefixListOnly
}

func showPolicyPrefixes() error {
	arg := &api.PolicyArguments{
		Resource: api.Resource_POLICY_PREFIX,
	}
	stream, e := client.GetPolicyPrefixes(context.Background(), arg)
	if e != nil {
		fmt.Println(e)
		return e
	}
	m := prefixes{}
	for {
		p, e := stream.Recv()
		if e == io.EOF {
			break
		} else if e != nil {
			return e
		}
		m = append(m, p)
	}

	if globalOpts.Json {
		j, _ := json.Marshal(m)
		fmt.Println(string(j))
		return nil
	}

	if globalOpts.Quiet {
		for _, p := range m {
			fmt.Println(p.PrefixSetName)
		}
		return nil
	}
	sort.Sort(m)

	format, _ := formatPolicyPrefix(m)
	fmt.Printf(format, "Name", "Prefix", "MaskRange")
	for _, ps := range m {
		for i, p := range ps.PrefixList {
			prefix := fmt.Sprintf("%s/%d", p.Address, p.MaskLength)
			if i == 0 {
				fmt.Printf(format, ps.PrefixSetName, prefix, p.MaskLengthRange)
			} else {
				fmt.Printf(format, "", prefix, p.MaskLengthRange)
			}
		}
	}
	return nil
}

func showPolicyPrefix(args []string) error {
	arg := &api.PolicyArguments{
		Resource: api.Resource_POLICY_PREFIX,
		Name:     args[0],
	}
	ps, e := client.GetPolicyPrefix(context.Background(), arg)
	if e != nil {
		return e
	}

	if globalOpts.Json {
		j, _ := json.Marshal(ps)
		fmt.Println(string(j))
		return nil
	}

	format, _ := formatPolicyPrefix([]*api.PrefixSet{ps})
	fmt.Printf(format, "Name", "Prefix", "MaskRange")
	for i, p := range ps.PrefixList {
		prefix := fmt.Sprintf("%s/%d", p.Address, p.MaskLength)
		if i == 0 {
			fmt.Printf(format, ps.PrefixSetName, prefix, p.MaskLengthRange)
		} else {
			fmt.Printf(format, "", prefix, p.MaskLengthRange)
		}
	}
	return nil
}

func (x *PolicyPrefixCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_PREFIX)
	if len(eArgs) == 0 {
		if err := requestGrpc(CMD_POLICY+"_"+CMD_PREFIX, eArgs, nil); err != nil {
			return err
		}
		return nil
	} else if len(eArgs) == 1 && !(eArgs[0] == "-h" || eArgs[0] == "--help" || eArgs[0] == "add" || eArgs[0] == "del") {
		if err := requestGrpc(CMD_POLICY+"_"+CMD_PREFIX, eArgs, nil); err != nil {
			return err
		}
		return nil
	}
	parser := flags.NewParser(nil, flags.Default)
	parser.Usage = "policy prefix [OPTIONS]\n  gobgp policy prefix"
	parser.AddCommand(CMD_ADD, "subcommand for add prefix condition to policy", "", &PolicyPrefixAddCommand{})
	parser.AddCommand(CMD_DEL, "subcommand for delete prefix condition from policy", "", &PolicyPrefixDelCommand{})
	parser.ParseArgs(eArgs)
	return nil
}

type PolicyPrefixAddCommand struct{}

func parsePrefixSet(eArgs []string) (*api.PrefixSet, error) {
	_, ipNet, e := net.ParseCIDR(eArgs[1])
	if e != nil {
		return nil, fmt.Errorf("prefix is invalid format %s\nplease enter ipv4 or ipv6 format", eArgs[1])
	}
	mask, _ := ipNet.Mask.Size()
	prefix := &api.Prefix{
		Address:    ipNet.IP.String(),
		MaskLength: uint32(mask),
	}

	if len(eArgs) == 3 {
		maskRange := eArgs[2]
		idx := strings.Index(maskRange, "..")
		if idx == -1 {
			return nil, fmt.Errorf("mask length range invalid format %s", maskRange)
		}
		var min, max int
		var e error
		if idx != 0 {
			if min, e = strconv.Atoi(maskRange[:idx]); e != nil {
				return nil, fmt.Errorf("mask length range invalid format %s", maskRange)
			}
		}
		if idx != len(maskRange)-1 {
			if max, e = strconv.Atoi(maskRange[idx+2:]); e != nil {
				return nil, fmt.Errorf("mask length range invalid format %s", maskRange)
			}
		}
		if ipv4 := ipNet.IP.To4(); ipv4 != nil {
			if min < 0 || 32 < max {
				return nil, fmt.Errorf("ipv4 mask length range outside scope %s", maskRange)
			}
		} else {
			if min < 0 || 128 < max {
				return nil, fmt.Errorf("ipv6 mask length range outside scope %s", maskRange)
			}
		}
		if min >= max {
			return nil, fmt.Errorf("mask length range invalid format %s\nTo a large value to the right from the left", maskRange)
		}
		prefix.MaskLengthRange = maskRange
	}
	prefixList := []*api.Prefix{prefix}
	prefixSet := &api.PrefixSet{
		PrefixSetName: eArgs[0],
		PrefixList:    prefixList,
	}
	return prefixSet, nil
}

func modPolicyPrefix(modtype string, eArgs []string) error {
	prefixSet := &api.PrefixSet{}
	var e error
	var operation api.Operation

	switch modtype {
	case CMD_ADD:
		if len(eArgs) < 2 {
			return fmt.Errorf("policy prefix add <prefix set name> <prefix> [<mask length renge>]")
		}
		if prefixSet, e = parsePrefixSet(eArgs); e != nil {
			return e
		}
		operation = api.Operation_ADD
	case CMD_DEL:
		if len(eArgs) == 0 {
			operation = api.Operation_DEL_ALL
		} else if len(eArgs) == 1 {
			prefixSet = &api.PrefixSet{
				PrefixSetName: eArgs[0],
				PrefixList:    nil,
			}
			operation = api.Operation_DEL
		} else {
			if prefixSet, e = parsePrefixSet(eArgs); e != nil {
				return e
			}
			operation = api.Operation_DEL
		}
	}

	arg := &api.PolicyArguments{
		Resource:  api.Resource_POLICY_PREFIX,
		Operation: operation,
		PrefixSet: prefixSet,
	}
	stream, err := client.ModPolicyPrefix(context.Background())
	if err != nil {
		return err
	}
	err = stream.Send(arg)
	if err != nil {
		return err
	}
	stream.CloseSend()

	res, e := stream.Recv()
	if e != nil {
		return e
	}
	if res.Code != api.Error_SUCCESS {
		return fmt.Errorf("error: code: %d, msg: %s", res.Code, res.Msg)
	}
	return nil
}

func (x *PolicyPrefixAddCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_ADD)
	if len(eArgs) == 0 || len(eArgs) > 3 {
		return fmt.Errorf("policy prefix add <prefix set name> <prefix> [<mask length renge> ]")
	} else if !(eArgs[0] == "-h" || eArgs[0] == "--help") {
		if err := requestGrpc(CMD_POLICY+"_"+CMD_PREFIX+"_"+CMD_ADD, eArgs, nil); err != nil {
			return err
		}
		return nil
	}
	parser := flags.NewParser(nil, flags.Default)
	parser.Usage = "policy prefix add <prefix set name> <prefix> [mask length renge]"
	parser.ParseArgs(eArgs)
	return nil
}

type PolicyPrefixDelCommand struct{}

func (x *PolicyPrefixDelCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_DEL)
	if len(eArgs) > 3 {
		return fmt.Errorf("policy prefix del <prefix set name> [<prefix> [<mask length range>]] ")
	} else if len(eArgs) > 0 && !(eArgs[0] == "-h" || eArgs[0] == "--help" || eArgs[0] == "all") {
		if err := requestGrpc(CMD_POLICY+"_"+CMD_PREFIX+"_"+CMD_DEL, eArgs, nil); err != nil {
			return err
		}
		return nil
	}
	parser := flags.NewParser(nil, flags.Default)
	parser.Usage = "policy prefix del  <prefix set name> [<prefix> [<mask length range>]]"
	parser.AddCommand(CMD_ALL, "subcommand for delete all prefix condition from policy", "", &PolicyPrefixDelAllCommand{})
	parser.ParseArgs(eArgs)
	return nil
}

type PolicyPrefixDelAllCommand struct{}

func (x *PolicyPrefixDelAllCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_ALL)
	if len(eArgs) > 0 && !(eArgs[0] == "-h" || eArgs[0] == "--help") {
		return fmt.Errorf("Argument can not be entered")
	} else if len(eArgs) == 0 {
		if err := requestGrpc(CMD_POLICY+"_"+CMD_PREFIX+"_"+CMD_DEL, eArgs, nil); err != nil {
			return err
		}
	}

	parser := flags.NewParser(nil, flags.Default)
	parser.Usage = "policy prefix del all"
	parser.ParseArgs(eArgs)
	return nil
}

type PolicyNeighborCommand struct{}

func formatPolicyNeighbor(neighborSetList []*api.NeighborSet) string {
	maxNameLen := len("Name")
	maxAddressLen := len("Address")
	for _, ns := range neighborSetList {
		if len(ns.NeighborSetName) > maxNameLen {
			maxNameLen = len(ns.NeighborSetName)
		}
		for _, n := range ns.NeighborList {
			if len(n.Address) > maxAddressLen {
				maxAddressLen = len(n.Address)
			}
		}
	}
	format := "%-" + fmt.Sprint(maxNameLen) + "s  %-" + fmt.Sprint(maxAddressLen) + "s\n"
	return format
}

func showPolicyNeighbors() error {
	arg := &api.PolicyArguments{
		Resource: api.Resource_POLICY_NEIGHBOR,
	}
	stream, e := client.GetPolicyNeighbors(context.Background(), arg)
	if e != nil {
		fmt.Println(e)
		return e
	}
	m := neighbors{}
	for {
		n, e := stream.Recv()
		if e == io.EOF {
			break
		} else if e != nil {
			return e
		}
		m = append(m, n)
	}

	if globalOpts.Json {
		j, _ := json.Marshal(m)
		fmt.Println(string(j))
		return nil
	}

	if globalOpts.Quiet {
		for _, n := range m {
			fmt.Println(n.NeighborSetName)
		}
		return nil
	}
	sort.Sort(m)

	format := formatPolicyNeighbor(m)
	fmt.Printf(format, "Name", "Address")
	for _, ns := range m {
		for i, n := range ns.NeighborList {
			if i == 0 {
				fmt.Printf(format, ns.NeighborSetName, n.Address)
			} else {
				fmt.Printf(format, "", n.Address)
			}
		}
	}
	return nil
}

func showPolicyNeighbor(args []string) error {
	arg := &api.PolicyArguments{
		Resource: api.Resource_POLICY_NEIGHBOR,
		Name:     args[0],
	}
	ns, e := client.GetPolicyNeighbor(context.Background(), arg)
	if e != nil {
		return e
	}

	if globalOpts.Json {
		j, _ := json.Marshal(ns)
		fmt.Println(string(j))
		return nil
	}

	format := formatPolicyNeighbor([]*api.NeighborSet{ns})
	fmt.Printf(format, "Name", "Address")
	for i, n := range ns.NeighborList {
		if i == 0 {
			fmt.Printf(format, ns.NeighborSetName, n.Address)
		} else {
			fmt.Printf(format, "", n.Address)

		}
	}
	return nil
}

func (x *PolicyNeighborCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_NEIGHBOR)
	if len(eArgs) == 0 {
		if err := requestGrpc(CMD_POLICY+"_"+CMD_NEIGHBOR, eArgs, nil); err != nil {
			return err
		}
		return nil
	} else if len(eArgs) == 1 && !(eArgs[0] == "-h" || eArgs[0] == "--help" || eArgs[0] == "add" || eArgs[0] == "del") {
		if err := requestGrpc(CMD_POLICY+"_"+CMD_NEIGHBOR, eArgs, nil); err != nil {
			return err
		}
		return nil
	}
	parser := flags.NewParser(nil, flags.Default)
	parser.Usage = "policy neighbor [OPTIONS]\n  gobgp policy neighbor"
	parser.AddCommand(CMD_ADD, "subcommand for add neighbor condition to policy", "", &PolicyNeighborAddCommand{})
	parser.AddCommand(CMD_DEL, "subcommand for delete neighbor condition from policy", "", &PolicyNeighborDelCommand{})
	parser.ParseArgs(eArgs)
	return nil
}

type PolicyNeighborAddCommand struct{}

func parseNeighborSet(eArgs []string) (*api.NeighborSet, error) {
	address := net.ParseIP(eArgs[1])
	if address.To4() == nil {
		if address.To16() == nil {
			return nil, fmt.Errorf("address is invalid format %s\nplease enter ipv4 or ipv6 format", eArgs[1])
		}
	}

	neighbor := &api.Neighbor{
		Address: address.String(),
	}
	neighborList := []*api.Neighbor{neighbor}
	neighborSet := &api.NeighborSet{
		NeighborSetName: eArgs[0],
		NeighborList:    neighborList,
	}
	return neighborSet, nil
}

func modPolicyNeighbor(modtype string, eArgs []string) error {
	neighborSet := &api.NeighborSet{}
	var e error
	var operation api.Operation

	switch modtype {
	case CMD_ADD:
		if len(eArgs) < 2 {
			return fmt.Errorf("policy neighbor add <neighbor set name> <address>")
		}
		if neighborSet, e = parseNeighborSet(eArgs); e != nil {
			return e
		}
		operation = api.Operation_ADD
	case CMD_DEL:
		if len(eArgs) == 0 {
			operation = api.Operation_DEL_ALL
		} else if len(eArgs) == 1 {
			neighborSet = &api.NeighborSet{
				NeighborSetName: eArgs[0],
				NeighborList:    nil,
			}
			operation = api.Operation_DEL
		} else {
			if neighborSet, e = parseNeighborSet(eArgs); e != nil {
				return e
			}
			operation = api.Operation_DEL
		}
	}

	arg := &api.PolicyArguments{
		Resource:    api.Resource_POLICY_NEIGHBOR,
		Operation:   operation,
		NeighborSet: neighborSet,
	}
	stream, err := client.ModPolicyNeighbor(context.Background())
	if err != nil {
		return err
	}
	err = stream.Send(arg)
	if err != nil {
		return err
	}
	stream.CloseSend()

	res, e := stream.Recv()
	if e != nil {
		return e
	}
	if res.Code != api.Error_SUCCESS {
		return fmt.Errorf("error: code: %d, msg: %s", res.Code, res.Msg)
	}
	return nil
}

func (x *PolicyNeighborAddCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_ADD)
	if len(eArgs) == 0 || len(eArgs) > 2 {
		return fmt.Errorf("policy neighbor add <neighbor set name> <address>")
	} else if !(eArgs[0] == "-h" || eArgs[0] == "--help") {
		if err := requestGrpc(CMD_POLICY+"_"+CMD_NEIGHBOR+"_"+CMD_ADD, eArgs, nil); err != nil {
			return err
		}
		return nil
	}
	parser := flags.NewParser(nil, flags.Default)
	parser.Usage = "policy neighbor add <neighbor set name> <address>"
	parser.ParseArgs(eArgs)
	return nil
}

type PolicyNeighborDelCommand struct{}

func (x *PolicyNeighborDelCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_DEL)
	if len(eArgs) > 3 {
		return fmt.Errorf("policy neighbor del [<neighbor set name> [<address>]] ")
	} else if len(eArgs) > 0 && !(eArgs[0] == "-h" || eArgs[0] == "--help" || eArgs[0] == "all") {
		if err := requestGrpc(CMD_POLICY+"_"+CMD_NEIGHBOR+"_"+CMD_DEL, eArgs, nil); err != nil {
			return err
		}
		return nil
	}
	parser := flags.NewParser(nil, flags.Default)
	parser.Usage = "policy neighbor del [<neighbor set name> [<address>]]"
	parser.AddCommand(CMD_ALL, "subcommand for delete all neighbor condition from policy", "", &PolicyNeighborDelAllCommand{})
	parser.ParseArgs(eArgs)
	return nil
}

type PolicyNeighborDelAllCommand struct{}

func (x *PolicyNeighborDelAllCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_ALL)
	if len(eArgs) > 0 && !(eArgs[0] == "-h" || eArgs[0] == "--help") {
		return fmt.Errorf("Argument can not be entered")
	} else if len(eArgs) == 0 {
		if err := requestGrpc(CMD_POLICY+"_"+CMD_NEIGHBOR+"_"+CMD_DEL, eArgs, nil); err != nil {
			return err
		}
	}

	parser := flags.NewParser(nil, flags.Default)
	parser.Usage = "policy neighbor del all"
	parser.ParseArgs(eArgs)
	return nil
}

type PolicyRoutePolicyCommand struct{}

func showPolicyStatement(head string, pd *api.PolicyDefinition) {
	for _, st := range pd.StatementList {
		fmt.Printf("%s  StatementName %s:\n", head, st.StatementNeme)
		fmt.Printf("%s    Conditions:\n", head)
		prefixSet := st.Conditions.MatchPrefixSet
		fmt.Printf("%s      PrefixSet:    %s  ", head, prefixSet.PrefixSetName)
		if len(prefixSet.PrefixList) != 0 {
			nameFormat := "%-" + fmt.Sprint(len(prefixSet.PrefixSetName)+2) + "s"
			_, format := formatPolicyPrefix([]*api.PrefixSet{st.Conditions.MatchPrefixSet})
			for i, prefix := range prefixSet.PrefixList {
				p := fmt.Sprintf("%s/%d", prefix.Address, prefix.MaskLength)
				if i != 0 {
					fmt.Printf("%s                    ", head)
					fmt.Printf(nameFormat, "")
				}
				fmt.Printf(format, p, prefix.MaskLengthRange)
			}
		} else {
			fmt.Print("\n")
		}
		neighborSet := st.Conditions.MatchNeighborSet
		fmt.Printf("%s      NeighborSet:  %s  ", head, neighborSet.NeighborSetName)
		if len(neighborSet.NeighborList) != 0 {
			nameFormat := "%-" + fmt.Sprint(len(neighborSet.NeighborSetName)+2) + "s"
			for i, neighbor := range neighborSet.NeighborList {
				if i != 0 {
					fmt.Printf("%s                ", head)
					fmt.Printf(nameFormat, "")
				}
				fmt.Println(neighbor.Address)
			}
		} else {
			fmt.Print("\n")
		}
		asPathLentgh := st.Conditions.MatchAsPathLength
		fmt.Printf("%s      AsPathLength: %s    %s\n", head, asPathLentgh.Value, asPathLentgh.Operator)
		var option string
		switch st.Conditions.MatchSetOptions {
		case config.MATCH_SET_OPTIONS_TYPE_ANY:
			option = "ANY"
		case config.MATCH_SET_OPTIONS_TYPE_ALL:
			option = "ALL"
		case config.MATCH_SET_OPTIONS_TYPE_INVERT:
			option = "INVERT"
		}
		fmt.Printf("%s      MatchOption:  %s\n", head, option)
		fmt.Printf("%s    Actions:\n", head)
		action := "REJECT"
		if st.Actions.AcceptRoute {
			action = "ACCEPT"
		}
		fmt.Printf("%s      %s\n", head, action)
	}

}

func showPolicyRoutePolicies() error {
	arg := &api.PolicyArguments{
		Resource: api.Resource_POLICY_ROUTEPOLICY,
	}
	stream, e := client.GetPolicyRoutePolicies(context.Background(), arg)
	if e != nil {
		fmt.Println(e)
		return e
	}
	m := policyDefinitions{}
	for {
		n, e := stream.Recv()
		if e == io.EOF {
			break
		} else if e != nil {
			return e
		}
		m = append(m, n)
	}

	if globalOpts.Json {
		j, _ := json.Marshal(m)
		fmt.Println(string(j))
		return nil
	}
	if globalOpts.Quiet {
		for _, p := range m {
			fmt.Println(p.PolicyDefinitionName)
		}
		return nil
	}
	sort.Sort(m)

	for _, pd := range m {
		fmt.Printf("PolicyName %s:\n", pd.PolicyDefinitionName)
		showPolicyStatement("", pd)
	}
	return nil
}

func showPolicyRoutePolicy(args []string) error {
	arg := &api.PolicyArguments{
		Resource: api.Resource_POLICY_ROUTEPOLICY,
		Name:     args[0],
	}
	pd, e := client.GetPolicyRoutePolicy(context.Background(), arg)
	if e != nil {
		return e
	}

	if globalOpts.Json {
		j, _ := json.Marshal(pd)
		fmt.Println(string(j))
		return nil
	}

	fmt.Printf("PolicyName %s:\n", pd.PolicyDefinitionName)
	showPolicyStatement("", pd)
	return nil
}

func (x *PolicyRoutePolicyCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_ROUTEPOLICY)
	if len(eArgs) == 0 {
		if err := requestGrpc(CMD_POLICY+"_"+CMD_ROUTEPOLICY, eArgs, nil); err != nil {
			return err
		}
		return nil
	} else if len(eArgs) == 1 && !(eArgs[0] == "-h" || eArgs[0] == "--help" || eArgs[0] == "add" || eArgs[0] == "del") {
		if err := requestGrpc(CMD_POLICY+"_"+CMD_ROUTEPOLICY, eArgs, nil); err != nil {
			return err
		}
		return nil
	}
	parser := flags.NewParser(nil, flags.Default)
	parser.Usage = "policy routepolicy [OPTIONS]\n  gobgp policy routepolicy"
	parser.ParseArgs(eArgs)
	return nil
}

var globalOpts struct {
	Host  string `short:"u" long:"url" description:"specifying an url" default:"127.0.0.1"`
	Port  int    `short:"p" long:"port" description:"specifying a port" default:"8080"`
	Debug bool   `short:"d" long:"debug" description:"use debug"`
	Quiet bool   `short:"q" long:"quiet" description:"use quiet"`
	Json  bool   `short:"j" long:"json" description:"use json format to output format"`
}

var subOpts struct {
	AddressFamily string `short:"a" long:"address-family" description:"specifying an address family"`
}

var neighborsOpts struct {
	Transport string `short:"t" long:"transport" description:"specifying a transport protocol"`
}

func main() {
	cmds = []string{CMD_GLOBAL, CMD_NEIGHBOR, CMD_POLICY, CMD_RIB, CMD_ADD, CMD_DEL, CMD_ALL, CMD_LOCAL, CMD_ADJ_IN,
		CMD_ADJ_OUT, CMD_RESET, CMD_SOFT_RESET, CMD_SOFT_RESET_IN, CMD_SOFT_RESET_OUT, CMD_SHUTDOWN, CMD_ENABLE,
		CMD_DISABLE, CMD_PREFIX, CMD_ROUTEPOLICY}

	eArgs := extractArgs("")
	parser := flags.NewParser(&globalOpts, flags.Default)
	parser.AddCommand(CMD_GLOBAL, "subcommand for global", "", &GlobalCommand{})
	parser.AddCommand(CMD_NEIGHBOR, "subcommand for neighbor", "", &NeighborCommand{})
	parser.AddCommand(CMD_POLICY, "subcommand for policy", "", &PolicyCommand{})
	if _, err := parser.ParseArgs(eArgs); err != nil {
		os.Exit(1)
	}

}
