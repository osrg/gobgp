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
	"github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/policy"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"io"
	"net"
	"os"
	"sort"
	"strings"
)

func getNeighbors() (peers, error) {
	arg := &api.Arguments{}
	stream, e := client.GetNeighbors(context.Background(), arg)
	if e != nil {
		fmt.Println(e)
		return nil, e
	}
	m := peers{}
	for {
		p, e := stream.Recv()
		if e == io.EOF {
			break
		} else if e != nil {
			return nil, e
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
	return m, nil
}

func showNeighbors() error {
	m, err := getNeighbors()
	if err != nil {
		return err
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

type AsPathFormat struct {
	start     string
	end       string
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
					aspaths := a.AsPaths
					for _, aspath := range aspaths {
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
						segments = append(segments, s.String())
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

func showNeighborRib(r string, remoteIP net.IP) error {
	var resource api.Resource
	switch r {
	case CMD_LOCAL:
		resource = api.Resource_LOCAL
	case CMD_ADJ_IN:
		resource = api.Resource_ADJ_IN
	case CMD_ADJ_OUT:
		resource = api.Resource_ADJ_OUT
	}
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

func stateChangeNeighbor(cmd string, remoteIP net.IP) error {
	arg := &api.Arguments{
		Af:       api.AF_IPV4_UC,
		RouterId: remoteIP.String(),
	}
	var err error
	switch cmd {
	case CMD_SHUTDOWN:
		_, err = client.Shutdown(context.Background(), arg)
	case CMD_ENABLE:
		_, err = client.Enable(context.Background(), arg)
	case CMD_DISABLE:
		_, err = client.Disable(context.Background(), arg)
	}
	return err
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
	policyList := make([]*api.PolicyDefinition, 0, len(pList))
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

func modNeighborPolicy(remoteIP net.IP, cmdType string, eArg []string) error {
	var operation api.Operation
	pol := &api.ApplyPolicy{}
	switch cmdType {
	case CMD_ADD:
		if len(eArg) < 4 {
			return fmt.Errorf("Usage: gobgp neighbor <ipaddr> policy %s {%s|%s} <policies> {%s|%s}", cmdType, CMD_IMPORT, CMD_EXPORT, policy.ROUTE_ACCEPT, policy.ROUTE_REJECT)
		}
		policies := parsePolicy(eArg[1])
		defaultPolicy, err := parseRouteAction(eArg[2])
		if err != nil {
			return err
		}
		switch eArg[0] {
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
		RouterId:    remoteIP.String(),
		Name:        eArg[0],
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

func NewNeighborCmd() *cobra.Command {

	neighborCmdImpl := &cobra.Command{}

	type cmds struct {
		names []string
		f     func(string, net.IP) error
	}

	c := make([]cmds, 0, 3)
	c = append(c, cmds{[]string{CMD_LOCAL, CMD_ADJ_IN, CMD_ADJ_OUT}, showNeighborRib})
	c = append(c, cmds{[]string{CMD_RESET, CMD_SOFT_RESET, CMD_SOFT_RESET_IN, CMD_SOFT_RESET_OUT}, resetNeighbor})
	c = append(c, cmds{[]string{CMD_SHUTDOWN, CMD_ENABLE, CMD_DISABLE}, stateChangeNeighbor})

	for _, v := range c {
		f := v.f
		for _, name := range v.names {
			c := &cobra.Command{
				Use: name,
				Run: func(cmd *cobra.Command, args []string) {
					remoteIP := net.ParseIP(args[len(args)-1])
					if remoteIP == nil {
						fmt.Println("invalid ip address:", args[len(args)-1])
						os.Exit(1)
					}
					err := f(cmd.Use, remoteIP)
					if err != nil {
						fmt.Println(err)
						os.Exit(1)
					}
				},
			}
			neighborCmdImpl.AddCommand(c)
		}
	}

	policyCmd := &cobra.Command{
		Use: CMD_POLICY,
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			remoteIP := net.ParseIP(args[0])
			if remoteIP == nil {
				err = fmt.Errorf("invalid ip address: %s", args[0])
			} else {
				err = showNeighborPolicy(remoteIP)
			}
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}

	for _, v := range []string{CMD_ADD, CMD_DEL} {
		cmd := &cobra.Command{
			Use: v,
			Run: func(cmd *cobra.Command, args []string) {
				var err error
				remoteIP := net.ParseIP(args[len(args)-1])
				if remoteIP == nil {
					fmt.Println("invalid ip address:", args[len(args)-1])
					os.Exit(1)
				}
				err = modNeighborPolicy(remoteIP, cmd.Use, args)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
			},
		}
		policyCmd.AddCommand(cmd)
	}

	neighborCmdImpl.AddCommand(policyCmd)

	neighborCmd := &cobra.Command{
		Use: CMD_NEIGHBOR,
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			if len(args) == 0 {
				err = showNeighbors()
			} else if len(args) == 1 {
				remoteIP := net.ParseIP(args[0])
				if remoteIP == nil {
					err = fmt.Errorf("invalid ip address: %s", args[0])
				} else {
					err = showNeighbor(args)
				}
			} else {
				args = append(args[1:], args[0])
				neighborCmdImpl.SetArgs(args)
				err = neighborCmdImpl.Execute()
			}
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
	neighborCmd.PersistentFlags().StringVarP(&subOpts.AddressFamily, "address-family", "a", "", "address family")
	return neighborCmd
}
