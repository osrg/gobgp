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
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"time"
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
	hours := u % 60
	days := u / 24

	if days == 0 {
		return fmt.Sprintf("%02d:%02d:%02d", hours, mins, secs)
	} else {
		hours -= days * 24
		return fmt.Sprintf("%dd ", days) + fmt.Sprintf("%02d:%02d:%02d", hours, mins, secs)
	}
}

var client api.GrpcClient

type ShowNeighborCommand struct {
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
	fmt.Printf("  Neighbor capabilities:\n")
	caps := []int32{}
	lookup := func(val int32, l []int32) bool {
		for _, v := range l {
			if v == val {
				return true
			}
		}
		return false
	}
	caps = append(caps, p.Conf.LocalCap...)
	for _, v := range p.Conf.RemoteCap {
		if !lookup(v, caps) {
			caps = append(caps, v)
		}
	}

	toInt := func(arg []int32) []int {
		ret := make([]int, 0, len(arg))
		for _, v := range arg {
			ret = append(ret, int(v))
		}
		return ret
	}

	sort.Sort(sort.IntSlice(toInt(caps)))
	capdict := map[int]string{1: "MULTIPROTOCOL",
		2:   "ROUTE_REFRESH",
		4:   "CARRYING_LABEL_INFO",
		64:  "GRACEFUL_RESTART",
		65:  "FOUR_OCTET_AS_NUMBER",
		70:  "ENHANCED_ROUTE_REFRESH",
		128: "ROUTE_REFRESH_CISCO"}
	for _, c := range caps {
		k, found := capdict[int(c)]
		if !found {
			k = "UNKNOWN (" + fmt.Sprint(c) + ")"
		}
		support := ""
		if lookup(c, p.Conf.LocalCap) {
			support += "advertised"
		}
		if lookup(c, p.Conf.RemoteCap) {
			if len(support) != 0 {
				support += " and "
			}
			support += "received"
		}
		fmt.Printf("    %s: %s\n", k, support)
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

func (x *ShowNeighborCommand) Execute(args []string) error {
	if len(args) < 1 || len(args) > 3 {
		// TODO: proper help
		fmt.Print("syntax error\n")
		return nil
	}

	if len(args) == 1 {
		showNeighbor(args)
	} else {
		parser := flags.NewParser(nil, flags.Default)
		parser.AddCommand("local", "", "", NewShowNeighborRibCommand(args[0], api.Resource_LOCAL))
		parser.AddCommand("adj-in", "", "", NewShowNeighborRibCommand(args[0], api.Resource_ADJ_IN))
		parser.AddCommand("adj-out", "", "", NewShowNeighborRibCommand(args[0], api.Resource_ADJ_OUT))
		if _, err := parser.ParseArgs(args[1:]); err != nil {
			os.Exit(1)
		}
	}
	return nil
}

type ShowNeighborRibCommand struct {
	remoteIP net.IP
	resource api.Resource
}

func showRoute(pathList []*api.Path, showAge bool, showBest bool) {
	var format string
	if showAge {
		format = "%-2s %-18s %-15s %-10s %-10s %-s\n"
		fmt.Printf(format, "", "Network", "Next Hop", "AS_PATH", "Age", "Attrs")
	} else {
		format = "%-2s %-18s %-15s %-10s %-s\n"
		fmt.Printf(format, "", "Network", "Next Hop", "AS_PATH", "Attrs")
	}

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
					s = append(s, fmt.Sprintf("{Cummunity: %v}", l))
				case api.BGP_ATTR_TYPE_ORIGINATOR_ID:
					s = append(s, fmt.Sprintf("{Originator: %v|", a.Originator))
				case api.BGP_ATTR_TYPE_CLUSTER_LIST:
					s = append(s, fmt.Sprintf("{Cluster: %v|", a.Cluster))
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
		if showAge {
			fmt.Printf(format, best, p.Nlri.Prefix, p.Nexthop, aspath(p.Attrs), formatTimedelta(p.Age), formatAttrs(p.Attrs))
		} else {
			fmt.Printf(format, best, p.Nlri.Prefix, p.Nexthop, aspath(p.Attrs), formatAttrs(p.Attrs))
		}
	}
}

func (x *ShowNeighborRibCommand) Execute(args []string) error {
	var rt *api.AddressFamily
	if len(args) == 0 {
		if x.remoteIP.To4() != nil {
			rt = api.AF_IPV4_UC
		} else {
			rt = api.AF_IPV6_UC
		}
	} else {
		switch args[0] {
		case "ipv4":
			rt = api.AF_IPV4_UC
		case "ipv6":
			rt = api.AF_IPV6_UC
		case "evpn":
			rt = api.AF_EVPN
		}
	}

	arg := &api.Arguments{
		Resource: x.resource,
		Af:       rt,
		RouterId: x.remoteIP.String(),
	}

	ps := []*api.Path{}
	showBest := false
	showAge := true

	switch x.resource {
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

	showRoute(ps, showAge, showBest)
	return nil
}

func NewShowNeighborRibCommand(addr string, resource api.Resource) *ShowNeighborRibCommand {
	return &ShowNeighborRibCommand{
		remoteIP: net.ParseIP(addr),
		resource: resource,
	}
}

type ShowNeighborsCommand struct {
}

func (x *ShowNeighborsCommand) Execute(args []string) error {
	arg := &api.Arguments{}
	stream, e := client.GetNeighbors(context.Background(), arg)
	if e != nil {
		fmt.Println(e)
		return e
	}
	m := []*api.Peer{}
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
			fmt.Println(p.Conf.RemoteIp)
		}
		return nil
	}
	maxaddrlen := 0
	maxaslen := 0
	maxtimelen := len("Up/Down")
	timedelta := []string{}
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

	for i, p := range m {
		fmt.Printf(format, p.Conf.RemoteIp, fmt.Sprint(p.Conf.RemoteAs), timedelta[i], format_fsm(p.Info.AdminState, p.Info.BgpState), fmt.Sprint(p.Info.Advertized), fmt.Sprint(p.Info.Received), fmt.Sprint(p.Info.Accepted))
	}

	return nil
}

type ShowGlobalCommand struct {
}

func (x *ShowGlobalCommand) Execute(args []string) error {
	var rt *api.AddressFamily
	if len(args) == 0 {
		rt = api.AF_IPV4_UC
	} else {
		switch args[0] {
		case "ipv4":
			rt = api.AF_IPV4_UC
		case "ipv6":
			rt = api.AF_IPV6_UC
		case "evpn":
			rt = api.AF_EVPN
		}
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

	ps := []*api.Path{}
	for _, d := range ds {
		for idx, p := range d.Paths {
			if idx == int(d.BestPathIdx) {
				p.Best = true
			}
			ps = append(ps, p)
		}
	}

	showRoute(ps, true, true)
	return nil
}

type ShowCommand struct {
}

func (x *ShowCommand) Execute(args []string) error {
	parser := flags.NewParser(nil, flags.Default)
	parser.AddCommand("neighbor", "", "", &ShowNeighborCommand{})
	parser.AddCommand("neighbors", "", "", &ShowNeighborsCommand{})
	parser.AddCommand("global", "", "", &ShowGlobalCommand{})
	if _, err := parser.ParseArgs(args); err != nil {
		os.Exit(1)
	}
	return nil
}

type ResetCommand struct {
	resource string
}

func (x *ResetCommand) Execute(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: %s neighbor <router_id> [ipv4|ipv6]", x.resource)
	}

	var rt *api.AddressFamily
	switch x.resource {
	case "softreset", "softresetin", "softresetout":
		if len(args) == 2 {
			rt = api.AF_IPV4_UC
		} else {
			switch args[2] {
			case "ipv4":
				rt = api.AF_IPV4_UC
			case "ipv6":
				rt = api.AF_IPV6_UC
			case "evpn":
				rt = api.AF_EVPN
			default:
				return fmt.Errorf("unsupported rf: %s", args[2])
			}
		}
	}

	arg := &api.Arguments{
		RouterId: args[1],
		Af:       rt,
	}

	switch x.resource {
	case "reset":
		client.Reset(context.Background(), arg)
	case "softreset":
		client.SoftReset(context.Background(), arg)
	case "softresetin":
		client.SoftResetIn(context.Background(), arg)
	case "softresetout":
		client.SoftResetOut(context.Background(), arg)
	case "shutdown":
		client.Shutdown(context.Background(), arg)
	case "enable":
		client.Enable(context.Background(), arg)
	case "disable":
		client.Disable(context.Background(), arg)
	default:
		return fmt.Errorf("unsupported command: %s", x.resource)
	}
	return nil
}

func NewResetCommand(resource string) *ResetCommand {
	return &ResetCommand{
		resource: resource,
	}
}

type PathCommand struct {
	modtype string
}

func (x *PathCommand) Execute(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: %s global <af> <prefix>", x.modtype)
	}

	if args[0] != "global" {
		return fmt.Errorf("unsupported resource (currently only 'global' is supported): %s", args[0])
	}

	var rt *api.AddressFamily
	switch args[1] {
	case "ipv4", "v4", "4":
		rt = api.AF_IPV4_UC
	case "ipv6", "v6", "6":
		rt = api.AF_IPV6_UC
	case "evpn":
		rt = api.AF_EVPN
	default:
		return fmt.Errorf("unsupported address family: %s", args[1])
	}

	path := &api.Path{}

	switch rt {
	case api.AF_IPV4_UC, api.AF_IPV6_UC:
		path.Nlri = &api.Nlri{
			Af:     rt,
			Prefix: args[2],
		}
	case api.AF_EVPN:
		path.Nlri = &api.Nlri{
			Af: rt,
			EvpnNlri: &api.EVPNNlri{
				Type: api.EVPN_TYPE_ROUTE_TYPE_MAC_IP_ADVERTISEMENT,
				MacIpAdv: &api.EvpnMacIpAdvertisement{
					MacAddr: args[2],
					IpAddr:  args[3],
				},
			},
		}
	}

	switch x.modtype {
	case "add":
		path.IsWithdraw = false
	case "delete":
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

func NewPathCommand(modtype string) *PathCommand {
	return &PathCommand{
		modtype: modtype,
	}
}

var globalOpts struct {
	Host  string `short:"u" long:"url" description:"specifying an url" default:"127.0.0.1"`
	Port  int    `short:"p" long:"port" description:"specifying a port" default:"8080"`
	Debug bool   `short:"d" long:"debug"`
	Quiet bool   `short:"q" long:"quiet"`
	Json  bool   `short:"j" long:"json"`
}

func main() {
	parser := flags.NewParser(&globalOpts, flags.Default)
	parser.Parse()
	timeout := grpc.WithTimeout(time.Second)
	conn, err := grpc.Dial(fmt.Sprintf("%s:%d", globalOpts.Host, globalOpts.Port), timeout)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer conn.Close()
	client = api.NewGrpcClient(conn)

	parser.AddCommand("show", "show stuff", "get information", &ShowCommand{})
	parser.AddCommand("reset", "show stuff", "get information", NewResetCommand("reset"))
	parser.AddCommand("softreset", "show stuff", "get information", NewResetCommand("softreset"))
	parser.AddCommand("softresetin", "show stuff", "get information", NewResetCommand("softresetin"))
	parser.AddCommand("softresetout", "show stuff", "get information", NewResetCommand("softresetout"))
	parser.AddCommand("shutdown", "show stuff", "get information", NewResetCommand("shutdown"))
	parser.AddCommand("enable", "show stuff", "get information", NewResetCommand("enable"))
	parser.AddCommand("disable", "show stuff", "get information", NewResetCommand("disable"))
	parser.AddCommand("add", "show stuff", "get information", NewPathCommand("add"))
	parser.AddCommand("delete", "show stuff", "get information", NewPathCommand("delete"))

	if _, err := parser.Parse(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
