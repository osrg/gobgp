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
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/policy"
	"golang.org/x/net/context"
	"io"
	"net"
	"os"
	"sort"
	"strings"
)

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

func showNeighbor(args []string) error {
	id := &api.Arguments{
		RouterId: args[0],
	}
	p, e := client.GetNeighbor(context.Background(), id)
	if e != nil {
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

type AsPathFormat struct {
	start string
	end string
	separator string
}

func showRoute(pathList []*api.Path, showAge bool, showBest bool) {

	var pathStrs [][]interface{}
	maxPrefixLen := len("Network")
	maxNexthopLen := len("Next Hop")
	maxAsPathLen := len("AS_PATH")

	for _, p := range pathList {
		aspath := func(attrs []*api.PathAttr) string {

			delimiter := make(map[int]*AsPathFormat)
			delimiter[bgp.BGP_ASPATH_ATTR_TYPE_SET] = &AsPathFormat{"{", "}", ","}
			delimiter[bgp.BGP_ASPATH_ATTR_TYPE_SEQ] = &AsPathFormat{"", "", " "}
			delimiter[bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ] = &AsPathFormat{"(", ")", " "}
			delimiter[bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET] = &AsPathFormat{"[", "]", ","}

			var segments []string = make([]string, 0)
			for _, a := range attrs {
				if a.Type == api.BGP_ATTR_TYPE_AS_PATH {

					outAspath := func(aspath *api.AsPath) string {
						s := bytes.NewBuffer(make([]byte, 0, 64))

						t := int(aspath.SegmentType)
						start := delimiter[t].start
						end := delimiter[t].end
						separator := delimiter[t].separator
						s.WriteString(start)

						var asnsStr []string
						for _, asn := range aspath.Asns {
							asnsStr = append(asnsStr, fmt.Sprintf("%d", asn))
						}

						s.WriteString(strings.Join(asnsStr, separator))
						s.WriteString(end)
						return s.String()
					}

					// convert to map
					m := make(map[int]*api.AsPath)
					for _, aspath := range a.AsPaths {
						m[int(aspath.SegmentType)] = aspath
					}

					if s, ok := m[bgp.BGP_ASPATH_ATTR_TYPE_SEQ]; ok {
						segments = append(segments, outAspath(s))
					}
					if s, ok := m[bgp.BGP_ASPATH_ATTR_TYPE_SET]; ok {
						segments = append(segments, outAspath(s))
					}
					if s, ok := m[bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ]; ok {
						segments = append(segments, outAspath(s))
					}
					if s, ok := m[bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET]; ok {
						segments = append(segments, outAspath(s))
					}
				}
			}
			return strings.Join(segments, " ")
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

func showNeighborRib(resource api.Resource, request *NeighborRibCommand) error {
	remoteIP := request.remoteIP
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
	if err := requestGrpc(CMD_NEIGHBOR+"_"+x.command, eArgs, x); err != nil {
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

func resetNeighbor(request *NeighborResetCommand) error {
	remoteIP := request.remoteIP
	cmd := request.command
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
	if err := requestGrpc(CMD_NEIGHBOR+"_"+x.command, eArgs, x); err != nil {
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

func stateChangeNeighbor(request *NeighborChangeStateCommand) error {
	remoteIP := request.remoteIP
	cmd := request.command
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
	if err := requestGrpc(CMD_NEIGHBOR+"_"+x.command, eArgs, x); err != nil {
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

func showNeighborPolicy(request *NeighborPolicyCommand) error {
	remoteIP := request.remoteIP
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

	fmt.Printf("DefaultImportPolicy: %s\n", ap.DefaultImportPolicy)
	fmt.Printf("DefaultExportPolicy: %s\n", ap.DefaultExportPolicy)
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
		if err := requestGrpc(CMD_NEIGHBOR+"_"+CMD_POLICY, eArgs, x); err != nil {
			return err
		}
	} else {
		parser.Usage = "neighbor <neighbor address> policy \n  gobgp neighbor <neighbor address> policy"
		parser.AddCommand(CMD_ADD, "subcommand to add routing policy", "", NewNeighborPolicyAddCommand(x.remoteIP))
		parser.AddCommand(CMD_DEL, "subcommand to delete routing policy", "", NewNeighborPolicyDelCommand(x.remoteIP))
		if _, err := parser.ParseArgs(eArgs); err != nil {
			os.Exit(1)
		}
	}
	return nil
}

type NeighborPolicyAddCommand struct {
	remoteIP net.IP
}

func NewNeighborPolicyAddCommand(addr net.IP) *NeighborPolicyAddCommand {
	return &NeighborPolicyAddCommand{
		remoteIP: addr,
	}
}
func (x *NeighborPolicyAddCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_ADD)
	parser := flags.NewParser(nil, flags.Default)
	parser.Usage = "neighbor <neighbor address> policy add"
	parser.AddCommand(CMD_IMPORT, "subcommand to add import policies to neighbor", "", NewNeighborPolicyChangeCommand(CMD_ADD, CMD_IMPORT, x.remoteIP))
	parser.AddCommand(CMD_EXPORT, "subcommand to add export policies to neighbor", "", NewNeighborPolicyChangeCommand(CMD_ADD, CMD_EXPORT, x.remoteIP))
	if _, err := parser.ParseArgs(eArgs); err != nil {
		os.Exit(1)
	}
	return nil
}

type NeighborPolicyDelCommand struct {
	remoteIP net.IP
}

func NewNeighborPolicyDelCommand(addr net.IP) *NeighborPolicyDelCommand {
	return &NeighborPolicyDelCommand{
		remoteIP: addr,
	}
}

func (x *NeighborPolicyDelCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_DEL)
	parser := flags.NewParser(nil, flags.Default)
	parser.Usage = "neighbor <neighbor address> policy del"
	parser.AddCommand(CMD_IMPORT, "subcommand to delete import policies from neighbor", "", NewNeighborPolicyChangeCommand(CMD_DEL, CMD_IMPORT, x.remoteIP))
	parser.AddCommand(CMD_EXPORT, "subcommand to delete export policies from neighbor", "", NewNeighborPolicyChangeCommand(CMD_DEL, CMD_EXPORT, x.remoteIP))
	if _, err := parser.ParseArgs(eArgs); err != nil {
		os.Exit(1)
	}
	return nil
}

type NeighborPolicyChangeCommand struct {
	operation       string
	policyOperation string
	remoteIP        net.IP
}

func NewNeighborPolicyChangeCommand(operation string, pOperation string, addr net.IP) *NeighborPolicyChangeCommand {
	return &NeighborPolicyChangeCommand{
		operation:       operation,
		policyOperation: pOperation,
		remoteIP:        addr,
	}
}

func parseRouteAction(rType string) (string, error) {
	routeActionUpper := strings.ToUpper(rType)
	var routeAction string
	switch routeActionUpper {
	case policy.ROUTE_ACCEPT, policy.ROUTE_REJECT:
		routeAction = routeActionUpper
	default:
		return "", fmt.Errorf("invalid route action: %s\nPlease enter the accept or reject", rType)
	}
	return routeAction, nil
}

func parsePolicy(pNames string) []*api.PolicyDefinition {
	pList := strings.Split(pNames, ",")
	policyList := make([]*api.PolicyDefinition, 0)
	for _, p := range pList {
		if p != "" {
			policy := &api.PolicyDefinition{
				PolicyDefinitionName: p,
			}
			policyList = append(policyList, policy)
		}
	}
	return policyList
}

func modNeighborPolicy(eArg []string, request *NeighborPolicyChangeCommand) error {
	var operation api.Operation
	pol := &api.ApplyPolicy{}
	switch request.operation {
	case CMD_ADD:
		policies := parsePolicy(eArg[0])
		defaultPolicy, err := parseRouteAction(eArg[1])
		if err != nil {
			return err
		}
		switch request.policyOperation {
		case CMD_IMPORT:
			pol.ImportPolicies = policies
			pol.DefaultImportPolicy = defaultPolicy
		case CMD_EXPORT:
			pol.ExportPolicies = policies
			pol.DefaultExportPolicy = defaultPolicy
		}
		operation = api.Operation_ADD

	case CMD_DEL:
		operation = api.Operation_DEL
	}
	arg := &api.PolicyArguments{
		Resource:    api.Resource_POLICY_ROUTEPOLICY,
		Operation:   operation,
		RouterId:    request.remoteIP.String(),
		Name:        request.policyOperation,
		ApplyPolicy: pol,
	}
	stream, err := client.ModNeighborPolicy(context.Background())
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

func (x *NeighborPolicyChangeCommand) Execute(args []string) error {
	eArgs := extractArgs(x.policyOperation)
	if x.operation == CMD_ADD && len(eArgs) != 2 {
		return fmt.Errorf("usage: neighbor <neighbor address> policy %s %s <%s policy name> <default %s policy>",
			x.operation, x.policyOperation, x.policyOperation, x.policyOperation)
	} else if x.operation == CMD_DEL && len(eArgs) != 0 {
		return fmt.Errorf("usage: neighbor <neighbor address> policy %s %s", x.operation, x.policyOperation)
	} else {
		if err := requestGrpc(CMD_NEIGHBOR+"_"+CMD_POLICY+"_"+x.operation, eArgs, x); err != nil {
			return err
		}
	}
	return nil
}
