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
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
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
			addr := net.ParseIP(p.Conf.NeighborAddress)
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
		m = append(m, ApiStruct2Peer(p))
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
		if p.Timers.State.Uptime == 0 {
			t = "never"
		} else if p.Info.BgpState == "BGP_FSM_ESTABLISHED" {
			t = formatTimedelta(int64(p.Timers.State.Uptime))
		} else {
			t = formatTimedelta(int64(p.Timers.State.Downtime))
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
		Name: args[0],
	}
	peer, e := client.GetNeighbor(context.Background(), id)
	if e != nil {
		return e
	}
	p := ApiStruct2Peer(peer)

	if globalOpts.Json {
		j, _ := json.Marshal(p)
		fmt.Println(string(j))
		return nil
	}

	fmt.Printf("BGP neighbor is %s, remote AS %d\n", p.Conf.RemoteIp, p.Conf.RemoteAs)
	fmt.Printf("  BGP version 4, remote router ID %s\n", p.Conf.Id)
	fmt.Printf("  BGP state = %s, up for %s\n", p.Info.BgpState, formatTimedelta(int64(p.Timers.State.Uptime)))
	fmt.Printf("  BGP OutQ = %d, Flops = %d\n", p.Info.OutQ, p.Info.Flops)
	fmt.Printf("  Hold time is %d, keepalive interval is %d seconds\n", p.Timers.State.NegotiatedHoldTime, p.Timers.Config.KeepaliveInterval)
	fmt.Printf("  Configured hold time is %d, keepalive interval is %d seconds\n", p.Timers.Config.HoldTime, p.Timers.Config.KeepaliveInterval)

	fmt.Printf("  Neighbor capabilities:\n")
	caps := capabilities{}
	lookup := func(val bgp.ParameterCapabilityInterface, l capabilities) bgp.ParameterCapabilityInterface {
		for _, v := range l {
			if v.Code() == val.Code() {
				if v.Code() == bgp.BGP_CAP_MULTIPROTOCOL {
					lhs := v.(*bgp.CapMultiProtocol).CapValue
					rhs := val.(*bgp.CapMultiProtocol).CapValue
					if lhs == rhs {
						return v
					}
					continue
				}
				return v
			}
		}
		return nil
	}
	for _, c := range p.Conf.LocalCap {
		caps = append(caps, c)
	}
	for _, c := range p.Conf.RemoteCap {
		if lookup(c, caps) == nil {
			caps = append(caps, c)
		}
	}

	sort.Sort(caps)

	firstMp := true

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

		if c.Code() != bgp.BGP_CAP_MULTIPROTOCOL {
			fmt.Printf("    %s:\t%s\n", c.Code(), support)
		} else {
			if firstMp {
				fmt.Printf("    %s:\n", c.Code())
				firstMp = false
			}
			m := c.(*bgp.CapMultiProtocol).CapValue
			fmt.Printf("        %s:\t%s\n", m, support)
		}
	}
	fmt.Print("  Message statistics:\n")
	fmt.Print("                         Sent       Rcvd\n")
	fmt.Printf("    Opens:         %10d %10d\n", p.Info.Messages.Sent.OPEN, p.Info.Messages.Received.OPEN)
	fmt.Printf("    Notifications: %10d %10d\n", p.Info.Messages.Sent.NOTIFICATION, p.Info.Messages.Received.NOTIFICATION)
	fmt.Printf("    Updates:       %10d %10d\n", p.Info.Messages.Sent.UPDATE, p.Info.Messages.Received.UPDATE)
	fmt.Printf("    Keepalives:    %10d %10d\n", p.Info.Messages.Sent.KEEPALIVE, p.Info.Messages.Received.KEEPALIVE)
	fmt.Printf("    Route Refesh:  %10d %10d\n", p.Info.Messages.Sent.REFRESH, p.Info.Messages.Received.REFRESH)
	fmt.Printf("    Discarded:     %10d %10d\n", p.Info.Messages.Sent.DISCARDED, p.Info.Messages.Received.DISCARDED)
	fmt.Printf("    Total:         %10d %10d\n", p.Info.Messages.Sent.TOTAL, p.Info.Messages.Received.TOTAL)
	fmt.Print("  Route statistics:\n")
	fmt.Printf("    Advertised:    %10d\n", p.Info.Advertized)
	fmt.Printf("    Received:      %10d\n", p.Info.Received)
	fmt.Printf("    Accepted:      %10d\n", p.Info.Accepted)

	return nil
}

type AsPathFormat struct {
	start     string
	end       string
	separator string
}

func showRoute(pathList []*Path, showAge, showBest, showLabel, isMonitor, printHeader bool) {

	var pathStrs [][]interface{}
	maxPrefixLen := 20
	maxNexthopLen := 20
	maxAsPathLen := 20
	maxLabelLen := 10
	aspath := func(a bgp.PathAttributeInterface) string {

		delimiter := make(map[uint8]*AsPathFormat)
		delimiter[bgp.BGP_ASPATH_ATTR_TYPE_SET] = &AsPathFormat{"{", "}", ","}
		delimiter[bgp.BGP_ASPATH_ATTR_TYPE_SEQ] = &AsPathFormat{"", "", " "}
		delimiter[bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ] = &AsPathFormat{"(", ")", " "}
		delimiter[bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET] = &AsPathFormat{"[", "]", ","}

		var segments []string = make([]string, 0)
		aspaths := a.(*bgp.PathAttributeAsPath).Value
		for _, aspath := range aspaths {
			var t uint8
			var asnsStr []string
			switch aspath.(type) {
			case *bgp.AsPathParam:
				a := aspath.(*bgp.AsPathParam)
				t = a.Type
				for _, asn := range a.AS {
					asnsStr = append(asnsStr, fmt.Sprintf("%d", asn))
				}
			case *bgp.As4PathParam:
				a := aspath.(*bgp.As4PathParam)
				t = a.Type
				for _, asn := range a.AS {
					asnsStr = append(asnsStr, fmt.Sprintf("%d", asn))
				}
			}
			s := bytes.NewBuffer(make([]byte, 0, 64))
			start := delimiter[t].start
			end := delimiter[t].end
			separator := delimiter[t].separator
			s.WriteString(start)
			s.WriteString(strings.Join(asnsStr, separator))
			s.WriteString(end)
			segments = append(segments, s.String())
		}
		return strings.Join(segments, " ")
	}

	for _, p := range pathList {
		var nexthop string
		var aspathstr string

		s := []string{}
		for _, a := range p.PathAttrs {
			switch a.GetType() {
			case bgp.BGP_ATTR_TYPE_NEXT_HOP:
				nexthop = a.(*bgp.PathAttributeNextHop).Value.String()
			case bgp.BGP_ATTR_TYPE_MP_REACH_NLRI:
				n := a.(*bgp.PathAttributeMpReachNLRI).Nexthop
				if n != nil {
					nexthop = n.String()
				} else {
					nexthop = "fictitious"
				}
			case bgp.BGP_ATTR_TYPE_AS_PATH:
				aspathstr = aspath(a)
			case bgp.BGP_ATTR_TYPE_AS4_PATH:
				continue
			default:
				s = append(s, a.String())
			}
		}
		pattrstr := fmt.Sprint(s)

		if maxNexthopLen < len(nexthop) {
			maxNexthopLen = len(nexthop)
		}

		if maxAsPathLen < len(aspathstr) {
			maxAsPathLen = len(aspathstr)
		}

		best := ""
		switch config.RpkiValidationResultType(p.Validation) {
		case config.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND:
			best += "N"
		case config.RPKI_VALIDATION_RESULT_TYPE_VALID:
			best += "V"
		case config.RPKI_VALIDATION_RESULT_TYPE_INVALID:
			best += "I"
		}
		if showBest {
			if p.Best {
				best += "*>"
			} else {
				best += "* "
			}
		}
		nlri := p.Nlri.String()
		if maxPrefixLen < len(nlri) {
			maxPrefixLen = len(nlri)
		}

		if isMonitor {
			title := "ROUTE"
			if p.IsWithdraw {
				title = "DELROUTE"
			}
			pathStrs = append(pathStrs, []interface{}{title, nlri, nexthop, aspathstr, pattrstr})
		} else {
			args := []interface{}{best, nlri}
			if showLabel {
				label := ""
				switch p.Nlri.(type) {
				case *bgp.LabeledIPAddrPrefix:
					label = p.Nlri.(*bgp.LabeledIPAddrPrefix).Labels.String()
				case *bgp.LabeledIPv6AddrPrefix:
					label = p.Nlri.(*bgp.LabeledIPv6AddrPrefix).Labels.String()
				case *bgp.LabeledVPNIPAddrPrefix:
					label = p.Nlri.(*bgp.LabeledVPNIPAddrPrefix).Labels.String()
				case *bgp.LabeledVPNIPv6AddrPrefix:
					label = p.Nlri.(*bgp.LabeledVPNIPv6AddrPrefix).Labels.String()
				}
				if maxLabelLen < len(label) {
					maxLabelLen = len(label)
				}
				args = append(args, label)
			}
			args = append(args, []interface{}{nexthop, aspathstr}...)
			if showAge {
				args = append(args, formatTimedelta(p.Age))
			}
			args = append(args, pattrstr)
			pathStrs = append(pathStrs, args)
		}
	}

	var format string
	if isMonitor {
		format = "[%s] %s via %s aspath [%s] attrs %s\n"
	} else {
		format = fmt.Sprintf("%%-3s %%-%ds", maxPrefixLen)
		if showLabel {
			format += fmt.Sprintf("%%-%ds ", maxLabelLen)
		}
		format += fmt.Sprintf("%%-%ds %%-%ds ", maxNexthopLen, maxAsPathLen)
		if showAge {
			format += "%-10s "
		}
		format += "%-s\n"

	}

	if printHeader {
		args := []interface{}{"", "Network"}
		if showLabel {
			args = append(args, "Labels")
		}
		args = append(args, []interface{}{"Next Hop", "AS_PATH"}...)
		if showAge {
			args = append(args, "Age")
		}
		args = append(args, "Attrs")
		fmt.Printf(format, args...)
	}

	for _, pathStr := range pathStrs {
		fmt.Printf(format, pathStr...)
	}
}

func showNeighborRib(r string, name string, args []string) error {
	var resource api.Resource
	showBest := false
	showAge := true
	showLabel := false
	def := addr2AddressFamily(net.ParseIP(name))
	switch r {
	case CMD_GLOBAL:
		def = bgp.RF_IPv4_UC
		showBest = true
		resource = api.Resource_GLOBAL
	case CMD_LOCAL:
		showBest = true
		resource = api.Resource_LOCAL
	case CMD_ADJ_IN, CMD_ACCEPTED, CMD_REJECTED:
		resource = api.Resource_ADJ_IN
	case CMD_ADJ_OUT:
		showAge = false
		resource = api.Resource_ADJ_OUT
	case CMD_VRF:
		def = bgp.RF_IPv4_UC
		showLabel = true
		resource = api.Resource_VRF
	}
	rf, err := checkAddressFamily(def)
	if err != nil {
		return err
	}

	var prefix string
	var host net.IP
	if len(args) > 0 {
		if rf != bgp.RF_IPv4_UC && rf != bgp.RF_IPv6_UC {
			return fmt.Errorf("route filtering is only supported for IPv4/IPv6 unicast routes")
		}
		_, p, err := net.ParseCIDR(args[0])
		if err != nil {
			host = net.ParseIP(args[0])
			if host == nil {
				return err
			}
		} else {
			prefix = p.String()
		}
	}

	arg := &api.Arguments{
		Resource: resource,
		Rf:       uint32(rf),
		Name:     name,
	}

	stream, err := client.GetRib(context.Background(), arg)
	if err != nil {
		return err
	}

	isResultSorted := func(rf bgp.RouteFamily) bool {
		switch rf {
		case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
			return true
		}
		return false
	}

	dsts := []*Destination{}
	maxOnes := 0
	counter := 0
	for {
		d, e := stream.Recv()
		if e == io.EOF {
			break
		} else if e != nil {
			return e
		}
		if prefix != "" && prefix != d.Prefix {
			continue
		}
		if host != nil {
			_, prefix, _ := net.ParseCIDR(d.Prefix)
			ones, _ := prefix.Mask.Size()
			if prefix.Contains(host) {
				if maxOnes < ones {
					dsts = []*Destination{}
					maxOnes = ones
				} else if maxOnes > ones {
					continue
				}
			} else {
				continue
			}
		}

		dst, err := ApiStruct2Destination(d)
		if err != nil {
			return err
		}
		if isResultSorted(rf) && !globalOpts.Json && len(dst.Paths) > 0 {
			ps := paths{}
			for _, p := range dst.Paths {
				switch r {
				case CMD_ACCEPTED:
					if !p.Filtered {
						ps = append(ps, p)
					}
				case CMD_REJECTED:
					if p.Filtered {
						ps = append(ps, p)
					}
				default:
					ps = append(ps, p)
				}
			}
			sort.Sort(ps)
			if counter == 0 {
				showRoute(ps, showAge, showBest, showLabel, false, true)
			} else {
				showRoute(ps, showAge, showBest, showLabel, false, false)
			}
			counter++
		}
		dsts = append(dsts, dst)
	}

	if globalOpts.Json {
		j, _ := json.Marshal(dsts)
		fmt.Println(string(j))
		return nil
	}

	if isResultSorted(rf) && counter != 0 {
		// we already showed
		return nil
	}

	ps := paths{}
	for _, dst := range dsts {
		for _, p := range dst.Paths {
			switch r {
			case CMD_ACCEPTED:
				if !p.Filtered {
					ps = append(ps, p)
				}
			case CMD_REJECTED:
				if p.Filtered {
					ps = append(ps, p)
				}
			default:
				ps = append(ps, p)
			}
		}
	}

	if len(ps) == 0 {
		fmt.Println("Network not in table")
		return nil
	}

	sort.Sort(ps)
	showRoute(ps, showAge, showBest, showLabel, false, true)
	return nil
}

func resetNeighbor(cmd string, remoteIP string, args []string) error {
	rf, err := checkAddressFamily(addr2AddressFamily(net.ParseIP(remoteIP)))
	if err != nil {
		return err
	}
	arg := &api.Arguments{
		Name: remoteIP,
		Rf:   uint32(rf),
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

func stateChangeNeighbor(cmd string, remoteIP string, args []string) error {
	arg := &api.Arguments{
		Rf:   uint32(bgp.RF_IPv4_UC),
		Name: remoteIP,
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

func showNeighborPolicy(remoteIP net.IP, policyType string, indent int) error {
	var typ api.PolicyType
	switch strings.ToLower(policyType) {
	case "in":
		typ = api.PolicyType_IN
	case "import":
		typ = api.PolicyType_IMPORT
	case "export":
		typ = api.PolicyType_EXPORT
	}
	r := api.Resource_LOCAL
	if remoteIP == nil {
		r = api.Resource_GLOBAL
	}
	arg := &api.PolicyAssignment{
		Name:     remoteIP.String(),
		Resource: r,
		Type:     typ,
	}

	ap, e := client.GetPolicyAssignment(context.Background(), arg)
	if e != nil {
		return e
	}

	if globalOpts.Json {
		j, _ := json.Marshal(ap)
		fmt.Println(string(j))
		return nil
	}

	fmt.Printf("%sDefault: %s\n", strings.Repeat(" ", indent), ap.Default)
	for _, p := range ap.Policies {
		fmt.Printf("%sName %s:\n", strings.Repeat(" ", indent), p.Name)
		printPolicy(indent+4, p)
	}
	return nil
}

func extractDefaultAction(args []string) ([]string, api.RouteAction, error) {
	for idx, arg := range args {
		if arg == "default" {
			if len(args) < (idx + 2) {
				return nil, api.RouteAction_NONE, fmt.Errorf("specify default action [accept|reject]")
			}
			typ := args[idx+1]
			switch strings.ToLower(typ) {
			case "accept":
				return append(args[:idx], args[idx+2:]...), api.RouteAction_ACCEPT, nil
			case "reject":
				return append(args[:idx], args[idx+2:]...), api.RouteAction_REJECT, nil
			default:
				return nil, api.RouteAction_NONE, fmt.Errorf("invalid default action")
			}
		}
	}
	return args, api.RouteAction_NONE, nil
}

func modNeighborPolicy(remoteIP net.IP, policyType, cmdType string, args []string) error {
	var typ api.PolicyType
	switch strings.ToLower(policyType) {
	case "in":
		typ = api.PolicyType_IN
	case "import":
		typ = api.PolicyType_IMPORT
	case "export":
		typ = api.PolicyType_EXPORT
	}
	r := api.Resource_LOCAL
	usage := fmt.Sprintf("usage: gobgp neighbor %s policy %s %s", remoteIP, policyType, cmdType)
	if remoteIP == nil {
		r = api.Resource_GLOBAL
		usage = fmt.Sprintf("usage: gobgp global policy %s %s", policyType, cmdType)
	}

	arg := &api.ModPolicyAssignmentArguments{
		Assignment: &api.PolicyAssignment{
			Type:     typ,
			Resource: r,
			Name:     remoteIP.String(),
		},
	}

	switch cmdType {
	case CMD_ADD, CMD_SET:
		if len(args) < 1 {
			return fmt.Errorf("%s <policy name>... [default {%s|%s}]", usage, "accept", "reject")
		}
		var err error
		var def api.RouteAction
		args, def, err = extractDefaultAction(args)
		if err != nil {
			return fmt.Errorf("%s\n%s <policy name>... [default {%s|%s}]", err, usage, "accept", "reject")
		}
		if cmdType == CMD_ADD {
			arg.Operation = api.Operation_ADD
		} else {
			arg.Operation = api.Operation_REPLACE
		}
		arg.Assignment.Default = def
	case CMD_DEL:
		arg.Operation = api.Operation_DEL
		if len(args) == 0 {
			arg.Operation = api.Operation_DEL_ALL
		}
	}
	ps := make([]*api.Policy, 0, len(args))
	for _, name := range args {
		ps = append(ps, &api.Policy{Name: name})
	}
	arg.Assignment.Policies = ps
	_, err := client.ModPolicyAssignment(context.Background(), arg)
	return err
}

func NewNeighborCmd() *cobra.Command {

	neighborCmdImpl := &cobra.Command{}

	type cmds struct {
		names []string
		f     func(string, string, []string) error
	}

	c := make([]cmds, 0, 3)
	c = append(c, cmds{[]string{CMD_LOCAL, CMD_ADJ_IN, CMD_ADJ_OUT, CMD_ACCEPTED, CMD_REJECTED}, showNeighborRib})
	c = append(c, cmds{[]string{CMD_RESET, CMD_SOFT_RESET, CMD_SOFT_RESET_IN, CMD_SOFT_RESET_OUT}, resetNeighbor})
	c = append(c, cmds{[]string{CMD_SHUTDOWN, CMD_ENABLE, CMD_DISABLE}, stateChangeNeighbor})

	for _, v := range c {
		f := v.f
		for _, name := range v.names {
			c := &cobra.Command{
				Use: name,
				Run: func(cmd *cobra.Command, args []string) {
					addr := ""
					switch name {
					case CMD_RESET, CMD_SOFT_RESET, CMD_SOFT_RESET_IN, CMD_SOFT_RESET_OUT, CMD_SHUTDOWN:
						if args[len(args)-1] == "all" {
							addr = "all"
						}
					}
					if addr == "" {
						remoteIP := net.ParseIP(args[len(args)-1])
						if remoteIP == nil {
							fmt.Println("invalid ip address:", args[len(args)-1])
							os.Exit(1)
						}
						addr = remoteIP.String()
					}
					err := f(cmd.Use, addr, args[:len(args)-1])
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
			remoteIP := net.ParseIP(args[0])
			if remoteIP == nil {
				fmt.Println("invalid ip address:", args[0])
				os.Exit(1)
			}

			for _, v := range []string{CMD_IN, CMD_IMPORT, CMD_EXPORT} {
				fmt.Printf("%s policy:\n", strings.Title(v))
				if err := showNeighborPolicy(remoteIP, v, 4); err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
			}
		},
	}

	for _, v := range []string{CMD_IN, CMD_IMPORT, CMD_EXPORT} {
		cmd := &cobra.Command{
			Use: v,
			Run: func(cmd *cobra.Command, args []string) {
				var err error
				remoteIP := net.ParseIP(args[0])
				if remoteIP == nil {
					err = fmt.Errorf("invalid ip address: %s", args[0])
				} else {
					err = showNeighborPolicy(remoteIP, cmd.Use, 0)
				}
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}

			},
		}

		for _, w := range []string{CMD_ADD, CMD_DEL, CMD_SET} {
			subcmd := &cobra.Command{
				Use: w,
				Run: func(subcmd *cobra.Command, args []string) {
					remoteIP := net.ParseIP(args[len(args)-1])
					args = args[:len(args)-1]
					if remoteIP == nil {
						fmt.Println("invalid ip address:", args[len(args)-1])
						os.Exit(1)
					}
					err := modNeighborPolicy(remoteIP, cmd.Use, subcmd.Use, args)
					if err != nil {
						fmt.Println(err)
						os.Exit(1)
					}
				},
			}
			cmd.AddCommand(subcmd)
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
	neighborCmd.PersistentFlags().StringVarP(&neighborsOpts.Transport, "transport", "t", "", "specifying a transport protocol")
	return neighborCmd
}
