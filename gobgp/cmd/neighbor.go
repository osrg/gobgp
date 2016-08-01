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
	"encoding/json"
	"fmt"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

func getNeighbors() (peers, error) {
	r, e := client.GetNeighbor(context.Background(), &api.GetNeighborRequest{})
	if e != nil {
		fmt.Println(e)
		return nil, e
	}
	m := peers{}
	for _, p := range r.Peers {
		if neighborsOpts.Transport != "" {
			addr, _ := net.ResolveIPAddr("ip", p.Conf.NeighborAddress)
			if addr.IP.To4() != nil {
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

func getNeighbor(name string) (*Peer, error) {
	l, e := getNeighbors()
	if e != nil {
		return nil, e
	}
	for _, p := range l {
		if p.Conf.RemoteIp == name || p.Conf.Interface == name {
			return p, nil
		}
	}
	return nil, fmt.Errorf("Neighbor %v doesn't exist.", name)
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

	now := time.Now()
	for _, p := range m {
		if i := len(p.Conf.Interface); i > maxaddrlen {
			maxaddrlen = i
		} else if j := len(p.Conf.RemoteIp); j > maxaddrlen {
			maxaddrlen = j
		}
		if len(fmt.Sprint(p.Conf.RemoteAs)) > maxaslen {
			maxaslen = len(fmt.Sprint(p.Conf.RemoteAs))
		}
		timeStr := "never"
		if p.Timers.State.Uptime != 0 {
			t := int64(p.Timers.State.Downtime)
			if p.Info.BgpState == "BGP_FSM_ESTABLISHED" {
				t = int64(p.Timers.State.Uptime)
			}
			timeStr = formatTimedelta(int64(now.Sub(time.Unix(int64(t), 0)).Seconds()))
		}
		if len(timeStr) > maxtimelen {
			maxtimelen = len(timeStr)
		}
		timedelta = append(timedelta, timeStr)
	}
	var format string
	format = "%-" + fmt.Sprint(maxaddrlen) + "s" + " %" + fmt.Sprint(maxaslen) + "s" + " %" + fmt.Sprint(maxtimelen) + "s"
	format += " %-11s |%11s %8s %8s\n"
	fmt.Printf(format, "Peer", "AS", "Up/Down", "State", "#Advertised", "Received", "Accepted")
	format_fsm := func(admin, fsm string) string {
		switch admin {
		case "ADMIN_STATE_DOWN":
			return "Idle(Admin)"
		case "ADMIN_STATE_PFX_CT":
			return "Idle(PfxCt)"
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
		neigh := p.Conf.RemoteIp
		if p.Conf.Interface != "" {
			neigh = p.Conf.Interface
		}
		fmt.Printf(format, neigh, fmt.Sprint(p.Conf.RemoteAs), timedelta[i], format_fsm(p.Info.AdminState, p.Info.BgpState), fmt.Sprint(p.Info.Advertised), fmt.Sprint(p.Info.Received), fmt.Sprint(p.Info.Accepted))
	}

	return nil
}

func showNeighbor(args []string) error {
	p, e := getNeighbor(args[0])
	if e != nil {
		return e
	}
	if globalOpts.Json {
		j, _ := json.Marshal(p)
		fmt.Println(string(j))
		return nil
	}

	fmt.Printf("BGP neighbor is %s, remote AS %d", p.Conf.RemoteIp, p.Conf.RemoteAs)

	if p.RouteReflector != nil && p.RouteReflector.RouteReflectorClient {
		fmt.Printf(", route-reflector-client\n")
	} else if p.RouteServer != nil && p.RouteServer.RouteServerClient {
		fmt.Printf(", route-server-client\n")
	} else {
		fmt.Printf("\n")
	}

	id := "unknown"
	if p.Conf.Id != nil {
		id = p.Conf.Id.String()
	}
	fmt.Printf("  BGP version 4, remote router ID %s\n", id)
	fmt.Printf("  BGP state = %s, up for %s\n", p.Info.BgpState, formatTimedelta(int64(p.Timers.State.Uptime)-time.Now().Unix()))
	fmt.Printf("  BGP OutQ = %d, Flops = %d\n", p.Info.OutQ, p.Info.Flops)
	fmt.Printf("  Hold time is %d, keepalive interval is %d seconds\n", p.Timers.State.NegotiatedHoldTime, p.Timers.State.KeepaliveInterval)
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

		switch c.Code() {
		case bgp.BGP_CAP_MULTIPROTOCOL:
			if firstMp {
				fmt.Printf("    %s:\n", c.Code())
				firstMp = false
			}
			m := c.(*bgp.CapMultiProtocol).CapValue
			fmt.Printf("        %s:\t%s\n", m, support)
		case bgp.BGP_CAP_GRACEFUL_RESTART:
			fmt.Printf("    %s:\t%s\n", c.Code(), support)
			grStr := func(g *bgp.CapGracefulRestart) string {
				str := ""
				if len(g.Tuples) > 0 {
					str += fmt.Sprintf("restart time %d sec", g.Time)
				}
				if g.Flags == 0x08 {
					if len(str) > 0 {
						str += ", "
					}
					str += "restart flag set"
				}
				if len(str) > 0 {
					str += "\n"
				}
				for _, t := range g.Tuples {
					str += fmt.Sprintf("	    %s", bgp.AfiSafiToRouteFamily(t.AFI, t.SAFI))
					if t.Flags == 0x80 {
						str += ", forward flag set"
					}
					str += "\n"
				}
				return str
			}
			if m := lookup(c, p.Conf.LocalCap); m != nil {
				g := m.(*bgp.CapGracefulRestart)
				if s := grStr(g); len(s) > 0 {
					fmt.Printf("        Local: %s", s)
				}
			}
			if m := lookup(c, p.Conf.RemoteCap); m != nil {
				g := m.(*bgp.CapGracefulRestart)
				if s := grStr(g); len(s) > 0 {
					fmt.Printf("        Remote: %s", s)
				}
			}
		default:
			fmt.Printf("    %s:\t%s\n", c.Code(), support)
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
	fmt.Printf("    Advertised:    %10d\n", p.Info.Advertised)
	fmt.Printf("    Received:      %10d\n", p.Info.Received)
	fmt.Printf("    Accepted:      %10d\n", p.Info.Accepted)
	if len(p.Conf.PrefixLimits) > 0 {
		fmt.Println("  Prefix Limits:")
		for _, c := range p.Conf.PrefixLimits {
			fmt.Printf("    %s:\tMaximum prefixes allowed %d", bgp.RouteFamily(c.Family), c.MaxPrefixes)
			if c.ShutdownThresholdPct > 0 {
				fmt.Printf(", Threshold for warning message %d%%\n", c.ShutdownThresholdPct)
			} else {
				fmt.Printf("\n")
			}
		}
	}

	return nil
}

type AsPathFormat struct {
	start     string
	end       string
	separator string
}

func ShowRoute(pathList []*Path, showAge, showBest, showLabel, isMonitor, printHeader bool) {

	var pathStrs [][]interface{}
	maxPrefixLen := 20
	maxNexthopLen := 20
	maxAsPathLen := 20
	maxLabelLen := 10

	now := time.Now()
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
				aspathstr = a.String()
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
		if p.Stale {
			best += "S"
		}
		switch int(p.Validation) {
		case config.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND.ToInt():
			best += "N"
		case config.RPKI_VALIDATION_RESULT_TYPE_VALID.ToInt():
			best += "V"
		case config.RPKI_VALIDATION_RESULT_TYPE_INVALID.ToInt():
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
				args = append(args, formatTimedelta(int64(now.Sub(time.Unix(int64(p.Age), 0)).Seconds())))
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
	switch rf {
	case bgp.RF_IPv4_MPLS, bgp.RF_IPv6_MPLS, bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN:
		showLabel = true
	}

	arg := &api.Table{
		Type:   resource,
		Family: uint32(rf),
		Name:   name,
	}

	if len(args) > 0 {
		if rf != bgp.RF_IPv4_UC && rf != bgp.RF_IPv6_UC {
			return fmt.Errorf("route filtering is only supported for IPv4/IPv6 unicast routes")
		}
		longerPrefixes := false
		shorterPrefixes := false
		if len(args) > 1 {
			if args[1] == "longer-prefixes" {
				longerPrefixes = true
			} else if args[1] == "shorter-prefixes" {
				shorterPrefixes = true
			} else {
				return fmt.Errorf("invalid format for route filtering")
			}
		}
		arg.Destinations = []*api.Destination{
			&api.Destination{
				Prefix:          args[0],
				LongerPrefixes:  longerPrefixes,
				ShorterPrefixes: shorterPrefixes,
			},
		}
	}

	rsp, err := client.GetRib(context.Background(), &api.GetRibRequest{
		Table: arg,
	})
	if err != nil {
		return err
	}
	rib := rsp.Table
	switch r {
	case CMD_LOCAL, CMD_ADJ_IN, CMD_ACCEPTED, CMD_REJECTED, CMD_ADJ_OUT:
		if len(rib.Destinations) == 0 {
			peer, err := getNeighbor(name)
			if err != nil {
				return err
			}
			if peer.Info.BgpState != "BGP_FSM_ESTABLISHED" {
				return fmt.Errorf("Neighbor %v's BGP session is not established", name)
			}
		}
	}

	isResultSorted := func(rf bgp.RouteFamily) bool {
		switch rf {
		case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC, bgp.RF_FS_IPv4_UC, bgp.RF_FS_IPv6_UC, bgp.RF_FS_IPv4_VPN, bgp.RF_FS_IPv6_VPN, bgp.RF_FS_L2_VPN:
			return true
		}
		return false
	}

	dsts := []*Destination{}
	counter := 0
	for _, d := range rib.Destinations {
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
				ShowRoute(ps, showAge, showBest, showLabel, false, true)
			} else {
				ShowRoute(ps, showAge, showBest, showLabel, false, false)
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
	ShowRoute(ps, showAge, showBest, showLabel, false, true)
	return nil
}

func resetNeighbor(cmd string, remoteIP string, args []string) error {
	switch cmd {
	case CMD_RESET:
		client.ResetNeighbor(context.Background(), &api.ResetNeighborRequest{Address: remoteIP})
	case CMD_SOFT_RESET:
		client.SoftResetNeighbor(context.Background(), &api.SoftResetNeighborRequest{
			Address:   remoteIP,
			Direction: api.SoftResetNeighborRequest_BOTH,
		})
	case CMD_SOFT_RESET_IN:
		client.SoftResetNeighbor(context.Background(), &api.SoftResetNeighborRequest{
			Address:   remoteIP,
			Direction: api.SoftResetNeighborRequest_IN,
		})
	case CMD_SOFT_RESET_OUT:
		client.SoftResetNeighbor(context.Background(), &api.SoftResetNeighborRequest{
			Address:   remoteIP,
			Direction: api.SoftResetNeighborRequest_OUT,
		})
	}
	return nil
}

func stateChangeNeighbor(cmd string, remoteIP string, args []string) error {
	var err error
	switch cmd {
	case CMD_SHUTDOWN:
		_, err = client.ShutdownNeighbor(context.Background(), &api.ShutdownNeighborRequest{Address: remoteIP})
	case CMD_ENABLE:
		_, err = client.EnableNeighbor(context.Background(), &api.EnableNeighborRequest{Address: remoteIP})
	case CMD_DISABLE:
		_, err = client.DisableNeighbor(context.Background(), &api.DisableNeighborRequest{Address: remoteIP})
	}
	return err
}

func showNeighborPolicy(remoteIP, policyType string, indent int) error {
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
	if remoteIP == "" {
		r = api.Resource_GLOBAL
	}
	arg := &api.GetPolicyAssignmentRequest{
		Assignment: &api.PolicyAssignment{
			Name:     remoteIP,
			Resource: r,
			Type:     typ,
		},
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

	fmt.Printf("%s policy:\n", strings.Title(policyType))
	fmt.Printf("%sDefault: %s\n", strings.Repeat(" ", indent), ap.Assignment.Default)
	for _, p := range ap.Assignment.Policies {
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

func modNeighborPolicy(remoteIP, policyType, cmdType string, args []string) error {
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
	if remoteIP == "" {
		r = api.Resource_GLOBAL
		usage = fmt.Sprintf("usage: gobgp global policy %s %s", policyType, cmdType)
	}

	assign := &api.PolicyAssignment{
		Type:     typ,
		Resource: r,
		Name:     remoteIP,
	}

	var err error
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
		assign.Default = def
	}
	ps := make([]*api.Policy, 0, len(args))
	for _, name := range args {
		ps = append(ps, &api.Policy{Name: name})
	}
	assign.Policies = ps
	switch cmdType {
	case CMD_ADD:
		_, err = client.AddPolicyAssignment(context.Background(), &api.AddPolicyAssignmentRequest{
			Assignment: assign,
		})
	case CMD_SET:
		_, err = client.ReplacePolicyAssignment(context.Background(), &api.ReplacePolicyAssignmentRequest{
			Assignment: assign,
		})
	case CMD_DEL:
		all := false
		if len(args) == 0 {
			all = true
		}
		_, err = client.DeletePolicyAssignment(context.Background(), &api.DeletePolicyAssignmentRequest{
			Assignment: assign,
			All:        all,
		})
	}
	return err
}

func modNeighbor(cmdType string, args []string) error {
	m := extractReserved(args, []string{"interface", "as"})
	usage := fmt.Sprintf("usage: gobgp neighbor %s [<neighbor-address>| interface <neighbor-interface>]", cmdType)
	if cmdType == CMD_ADD {
		usage += " as <VALUE>"
	}

	if len(m[""]) < 1 && len(m["interface"]) < 1 {
		return fmt.Errorf("%s", usage)
	}
	unnumbered := len(m["interface"]) > 0
	if !unnumbered {
		if _, err := net.ResolveIPAddr("ip", m[""][0]); err != nil {
			return err
		}
	}

	getConf := func(asn int) *api.Peer {
		peer := &api.Peer{
			Conf: &api.PeerConf{
				PeerAs: uint32(asn),
			},
		}
		if unnumbered {
			peer.Conf.NeighborInterface = m["interface"][0]
		} else {
			peer.Conf.NeighborAddress = m[""][0]
		}
		return peer
	}
	var err error
	switch cmdType {
	case CMD_ADD:
		if len(m["as"]) != 1 {
			return fmt.Errorf("%s", usage)
		}
		var as int
		as, err = strconv.Atoi(m["as"][0])
		if err != nil {
			return err
		}
		_, err = client.AddNeighbor(context.Background(), &api.AddNeighborRequest{Peer: getConf(as)})
	case CMD_DEL:
		_, err = client.DeleteNeighbor(context.Background(), &api.DeleteNeighborRequest{Peer: getConf(0)})
	}
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
						peer, err := getNeighbor(args[len(args)-1])
						if err != nil {
							exitWithError(err)
						}
						addr = peer.Conf.RemoteIp
					}
					err := f(cmd.Use, addr, args[:len(args)-1])
					if err != nil {
						exitWithError(err)
					}
				},
			}
			neighborCmdImpl.AddCommand(c)
		}
	}

	policyCmd := &cobra.Command{
		Use: CMD_POLICY,
		Run: func(cmd *cobra.Command, args []string) {
			peer, err := getNeighbor(args[0])
			if err != nil {
				exitWithError(err)
			}
			remoteIP := peer.Conf.RemoteIp
			for _, v := range []string{CMD_IN, CMD_IMPORT, CMD_EXPORT} {
				if err := showNeighborPolicy(remoteIP, v, 4); err != nil {
					exitWithError(err)
				}
			}
		},
	}

	for _, v := range []string{CMD_IN, CMD_IMPORT, CMD_EXPORT} {
		cmd := &cobra.Command{
			Use: v,
			Run: func(cmd *cobra.Command, args []string) {
				peer, err := getNeighbor(args[0])
				if err != nil {
					exitWithError(err)
				}
				remoteIP := peer.Conf.RemoteIp
				err = showNeighborPolicy(remoteIP, cmd.Use, 0)
				if err != nil {
					exitWithError(err)
				}
			},
		}

		for _, w := range []string{CMD_ADD, CMD_DEL, CMD_SET} {
			subcmd := &cobra.Command{
				Use: w,
				Run: func(subcmd *cobra.Command, args []string) {
					peer, err := getNeighbor(args[len(args)-1])
					if err != nil {
						exitWithError(err)
					}
					remoteIP := peer.Conf.RemoteIp
					args = args[:len(args)-1]
					if err = modNeighborPolicy(remoteIP, cmd.Use, subcmd.Use, args); err != nil {
						exitWithError(err)
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
				err = showNeighbor(args)
			} else {
				args = append(args[1:], args[0])
				neighborCmdImpl.SetArgs(args)
				err = neighborCmdImpl.Execute()
			}
			if err != nil {
				exitWithError(err)
			}
		},
	}

	for _, v := range []string{CMD_ADD, CMD_DEL} {
		cmd := &cobra.Command{
			Use: v,
			Run: func(c *cobra.Command, args []string) {
				if err := modNeighbor(c.Use, args); err != nil {
					exitWithError(err)
				}
			},
		}
		neighborCmd.AddCommand(cmd)
	}

	neighborCmd.PersistentFlags().StringVarP(&subOpts.AddressFamily, "address-family", "a", "", "address family")
	neighborCmd.PersistentFlags().StringVarP(&neighborsOpts.Transport, "transport", "t", "", "specifying a transport protocol")
	return neighborCmd
}
