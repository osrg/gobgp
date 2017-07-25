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
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/osrg/gobgp/table"
)

func getNeighbors(vrf string) (neighbors, error) {
	if vrf != "" {
		n, err := client.ListNeighborByVRF(vrf)
		return neighbors(n), err
	} else if t := neighborsOpts.Transport; t != "" {
		switch t {
		case "ipv4":
			n, err := client.ListNeighborByTransport(bgp.AFI_IP)
			return neighbors(n), err
		case "ipv6":
			n, err := client.ListNeighborByTransport(bgp.AFI_IP6)
			return neighbors(n), err
		default:
			return nil, fmt.Errorf("invalid transport: %s", t)
		}
	}
	n, err := client.ListNeighbor()
	return neighbors(n), err
}

func getNeighbor(name string, enableAdvertised bool) (*config.Neighbor, error) {
	if net.ParseIP(name) == nil {
		name = ""
	}
	return client.GetNeighbor(name, enableAdvertised)
}

func getASN(p *config.Neighbor) string {
	asn := "*"
	if p.State.PeerAs > 0 {
		asn = fmt.Sprint(p.State.PeerAs)
	}
	return asn
}

func showNeighbors(vrf string) error {
	m, err := getNeighbors(vrf)
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
			fmt.Println(p.State.NeighborAddress)
		}
		return nil
	}
	maxaddrlen := 0
	maxaslen := 2
	maxtimelen := len("Up/Down")
	timedelta := []string{}

	sort.Sort(m)

	now := time.Now()
	for _, n := range m {
		if i := len(n.Config.NeighborInterface); i > maxaddrlen {
			maxaddrlen = i
		} else if j := len(n.State.NeighborAddress); j > maxaddrlen {
			maxaddrlen = j
		}
		if l := len(getASN(n)); l > maxaslen {
			maxaslen = l
		}
		timeStr := "never"
		if n.Timers.State.Uptime != 0 {
			t := int64(n.Timers.State.Downtime)
			if n.State.SessionState == config.SESSION_STATE_ESTABLISHED {
				t = int64(n.Timers.State.Uptime)
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
	format += " %-11s |%9s %9s\n"
	fmt.Printf(format, "Peer", "AS", "Up/Down", "State", "#Received", "Accepted")
	format_fsm := func(admin config.AdminState, fsm config.SessionState) string {
		switch admin {
		case config.ADMIN_STATE_DOWN:
			return "Idle(Admin)"
		case config.ADMIN_STATE_PFX_CT:
			return "Idle(PfxCt)"
		}

		switch fsm {
		case config.SESSION_STATE_IDLE:
			return "Idle"
		case config.SESSION_STATE_CONNECT:
			return "Connect"
		case config.SESSION_STATE_ACTIVE:
			return "Active"
		case config.SESSION_STATE_OPENSENT:
			return "Sent"
		case config.SESSION_STATE_OPENCONFIRM:
			return "Confirm"
		case config.SESSION_STATE_ESTABLISHED:
			return "Establ"
		default:
			return string(fsm)
		}
	}

	for i, n := range m {
		neigh := n.State.NeighborAddress
		if n.Config.NeighborInterface != "" {
			neigh = n.Config.NeighborInterface
		}
		fmt.Printf(format, neigh, getASN(n), timedelta[i], format_fsm(n.State.AdminState, n.State.SessionState), fmt.Sprint(n.State.AdjTable.Received), fmt.Sprint(n.State.AdjTable.Accepted))
	}

	return nil
}

func showNeighbor(args []string) error {
	p, e := getNeighbor(args[0], true)
	if e != nil {
		return e
	}
	if globalOpts.Json {
		j, _ := json.Marshal(p)
		fmt.Println(string(j))
		return nil
	}

	fmt.Printf("BGP neighbor is %s, remote AS %s", p.State.NeighborAddress, getASN(p))

	if p.RouteReflector.Config.RouteReflectorClient {
		fmt.Printf(", route-reflector-client\n")
	} else if p.RouteServer.Config.RouteServerClient {
		fmt.Printf(", route-server-client\n")
	} else {
		fmt.Printf("\n")
	}

	id := "unknown"
	if p.State.RemoteRouterId != "" {
		id = p.State.RemoteRouterId
	}
	fmt.Printf("  BGP version 4, remote router ID %s\n", id)
	fmt.Printf("  BGP state = %s, up for %s\n", p.State.SessionState, formatTimedelta(int64(p.Timers.State.Uptime)-time.Now().Unix()))
	fmt.Printf("  BGP OutQ = %d, Flops = %d\n", p.State.Queues.Output, p.State.Flops)
	fmt.Printf("  Hold time is %d, keepalive interval is %d seconds\n", int(p.Timers.State.NegotiatedHoldTime), int(p.Timers.State.KeepaliveInterval))
	fmt.Printf("  Configured hold time is %d, keepalive interval is %d seconds\n", int(p.Timers.Config.HoldTime), int(p.Timers.Config.KeepaliveInterval))

	elems := make([]string, 0, 3)
	if as := p.AsPathOptions.Config.AllowOwnAs; as > 0 {
		elems = append(elems, fmt.Sprintf("Allow Own AS: %d", as))
	}
	switch p.Config.RemovePrivateAs {
	case config.REMOVE_PRIVATE_AS_OPTION_ALL:
		elems = append(elems, "Remove private AS: all")
	case config.REMOVE_PRIVATE_AS_OPTION_REPLACE:
		elems = append(elems, "Remove private AS: replace")
	}
	if p.AsPathOptions.Config.ReplacePeerAs {
		elems = append(elems, "Replace peer AS: enabled")
	}

	fmt.Printf("  %s\n", strings.Join(elems, ", "))

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
	for _, c := range p.State.LocalCapabilityList {
		caps = append(caps, c)
	}
	for _, c := range p.State.RemoteCapabilityList {
		if lookup(c, caps) == nil {
			caps = append(caps, c)
		}
	}

	sort.Sort(caps)

	firstMp := true

	for _, c := range caps {
		support := ""
		if m := lookup(c, p.State.LocalCapabilityList); m != nil {
			support += "advertised"
		}
		if lookup(c, p.State.RemoteCapabilityList) != nil {
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
				if g.Flags&0x08 > 0 {
					if len(str) > 0 {
						str += ", "
					}
					str += "restart flag set"
				}
				if g.Flags&0x04 > 0 {
					if len(str) > 0 {
						str += ", "
					}
					str += "notification flag set"
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
			if m := lookup(c, p.State.LocalCapabilityList); m != nil {
				g := m.(*bgp.CapGracefulRestart)
				if s := grStr(g); len(s) > 0 {
					fmt.Printf("        Local: %s", s)
				}
			}
			if m := lookup(c, p.State.RemoteCapabilityList); m != nil {
				g := m.(*bgp.CapGracefulRestart)
				if s := grStr(g); len(s) > 0 {
					fmt.Printf("        Remote: %s", s)
				}
			}
		case bgp.BGP_CAP_LONG_LIVED_GRACEFUL_RESTART:
			fmt.Printf("    %s:\t%s\n", c.Code(), support)
			grStr := func(g *bgp.CapLongLivedGracefulRestart) string {
				var str string
				for _, t := range g.Tuples {
					str += fmt.Sprintf("	    %s, restart time %d sec", bgp.AfiSafiToRouteFamily(t.AFI, t.SAFI), t.RestartTime)
					if t.Flags == 0x80 {
						str += ", forward flag set"
					}
					str += "\n"
				}
				return str
			}
			if m := lookup(c, p.State.LocalCapabilityList); m != nil {
				g := m.(*bgp.CapLongLivedGracefulRestart)
				if s := grStr(g); len(s) > 0 {
					fmt.Printf("        Local:\n%s", s)
				}
			}
			if m := lookup(c, p.State.RemoteCapabilityList); m != nil {
				g := m.(*bgp.CapLongLivedGracefulRestart)
				if s := grStr(g); len(s) > 0 {
					fmt.Printf("        Remote:\n%s", s)
				}
			}
		case bgp.BGP_CAP_EXTENDED_NEXTHOP:
			fmt.Printf("    %s:\t%s\n", c.Code(), support)
			exnhStr := func(e *bgp.CapExtendedNexthop) string {
				lines := make([]string, 0, len(e.Tuples))
				for _, t := range e.Tuples {
					var nhafi string
					switch int(t.NexthopAFI) {
					case bgp.AFI_IP:
						nhafi = "ipv4"
					case bgp.AFI_IP6:
						nhafi = "ipv6"
					default:
						nhafi = fmt.Sprintf("%d", t.NexthopAFI)
					}
					line := fmt.Sprintf("nlri: %s, nexthop: %s", bgp.AfiSafiToRouteFamily(t.NLRIAFI, uint8(t.NLRISAFI)), nhafi)
					lines = append(lines, line)
				}
				return strings.Join(lines, "\n")
			}
			if m := lookup(c, p.State.LocalCapabilityList); m != nil {
				e := m.(*bgp.CapExtendedNexthop)
				if s := exnhStr(e); len(s) > 0 {
					fmt.Printf("        Local:  %s\n", s)
				}
			}
			if m := lookup(c, p.State.RemoteCapabilityList); m != nil {
				e := m.(*bgp.CapExtendedNexthop)
				if s := exnhStr(e); len(s) > 0 {
					fmt.Printf("        Remote: %s\n", s)
				}
			}
		case bgp.BGP_CAP_ADD_PATH:
			fmt.Printf("    %s:\t%s\n", c.Code(), support)
			if m := lookup(c, p.State.LocalCapabilityList); m != nil {
				fmt.Println("      Local:")
				for _, item := range m.(*bgp.CapAddPath).Tuples {
					fmt.Printf("         %s:\t%s\n", item.RouteFamily, item.Mode)
				}
			}
			if m := lookup(c, p.State.RemoteCapabilityList); m != nil {
				fmt.Println("      Remote:")
				for _, item := range m.(*bgp.CapAddPath).Tuples {
					fmt.Printf("         %s:\t%s\n", item.RouteFamily, item.Mode)
				}
			}
		default:
			fmt.Printf("    %s:\t%s\n", c.Code(), support)
		}
	}
	fmt.Print("  Message statistics:\n")
	fmt.Print("                         Sent       Rcvd\n")
	fmt.Printf("    Opens:         %10d %10d\n", p.State.Messages.Sent.Open, p.State.Messages.Received.Open)
	fmt.Printf("    Notifications: %10d %10d\n", p.State.Messages.Sent.Notification, p.State.Messages.Received.Notification)
	fmt.Printf("    Updates:       %10d %10d\n", p.State.Messages.Sent.Update, p.State.Messages.Received.Update)
	fmt.Printf("    Keepalives:    %10d %10d\n", p.State.Messages.Sent.Keepalive, p.State.Messages.Received.Keepalive)
	fmt.Printf("    Route Refresh: %10d %10d\n", p.State.Messages.Sent.Refresh, p.State.Messages.Received.Refresh)
	fmt.Printf("    Discarded:     %10d %10d\n", p.State.Messages.Sent.Discarded, p.State.Messages.Received.Discarded)
	fmt.Printf("    Total:         %10d %10d\n", p.State.Messages.Sent.Total, p.State.Messages.Received.Total)
	fmt.Print("  Route statistics:\n")
	fmt.Printf("    Advertised:    %10d\n", p.State.AdjTable.Advertised)
	fmt.Printf("    Received:      %10d\n", p.State.AdjTable.Received)
	fmt.Printf("    Accepted:      %10d\n", p.State.AdjTable.Accepted)
	first := true
	for _, afisafi := range p.AfiSafis {
		if afisafi.PrefixLimit.Config.MaxPrefixes > 0 {
			if first {
				fmt.Println("  Prefix Limits:")
				first = false
			}
			fmt.Printf("    %s:\tMaximum prefixes allowed %d", afisafi.Config.AfiSafiName, afisafi.PrefixLimit.Config.MaxPrefixes)
			if afisafi.PrefixLimit.Config.ShutdownThresholdPct > 0 {
				fmt.Printf(", Threshold for warning message %d%%\n", afisafi.PrefixLimit.Config.ShutdownThresholdPct)
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

func ShowRoute(pathList []*table.Path, showAge, showBest, showLabel, isMonitor, printHeader bool, showIdentifier bgp.BGPAddPathMode) {

	var pathStrs [][]interface{}
	maxPrefixLen := 20
	maxNexthopLen := 20
	maxAsPathLen := 20
	maxLabelLen := 10

	now := time.Now()
	for idx, p := range pathList {
		nexthop := "fictitious"
		if n := p.GetNexthop(); n != nil {
			nexthop = p.GetNexthop().String()
		}
		aspathstr := p.GetAsString()

		s := []string{}
		for _, a := range p.GetPathAttrs() {
			switch a.GetType() {
			case bgp.BGP_ATTR_TYPE_NEXT_HOP, bgp.BGP_ATTR_TYPE_MP_REACH_NLRI, bgp.BGP_ATTR_TYPE_AS_PATH, bgp.BGP_ATTR_TYPE_AS4_PATH:
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
		if p.IsStale() {
			best += "S"
		}
		switch p.ValidationStatus() {
		case config.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND:
			best += "N"
		case config.RPKI_VALIDATION_RESULT_TYPE_VALID:
			best += "V"
		case config.RPKI_VALIDATION_RESULT_TYPE_INVALID:
			best += "I"
		}
		if showBest {
			if idx == 0 && !p.IsNexthopInvalid {
				best += "*>"
			} else {
				best += "* "
			}
		}
		nlri := p.GetNlri()
		if maxPrefixLen < len(nlri.String()) {
			maxPrefixLen = len(nlri.String())
		}

		if isMonitor {
			title := "ROUTE"
			if p.IsWithdraw {
				title = "DELROUTE"
			}
			if showIdentifier != bgp.BGP_ADD_PATH_NONE {
				pathStrs = append(pathStrs, []interface{}{title, nlri.PathIdentifier(), nlri, nexthop, aspathstr, pattrstr})
			} else {
				pathStrs = append(pathStrs, []interface{}{title, nlri, nexthop, aspathstr, pattrstr})
			}
		} else {
			args := []interface{}{best}
			switch showIdentifier {
			case bgp.BGP_ADD_PATH_RECEIVE:
				args = append(args, fmt.Sprint(nlri.PathIdentifier()))
			case bgp.BGP_ADD_PATH_SEND:
				args = append(args, fmt.Sprint(nlri.PathLocalIdentifier()))
			}
			args = append(args, nlri)
			if showLabel {
				label := ""
				switch nlri.(type) {
				case *bgp.LabeledIPAddrPrefix:
					label = nlri.(*bgp.LabeledIPAddrPrefix).Labels.String()
				case *bgp.LabeledIPv6AddrPrefix:
					label = nlri.(*bgp.LabeledIPv6AddrPrefix).Labels.String()
				case *bgp.LabeledVPNIPAddrPrefix:
					label = nlri.(*bgp.LabeledVPNIPAddrPrefix).Labels.String()
				case *bgp.LabeledVPNIPv6AddrPrefix:
					label = nlri.(*bgp.LabeledVPNIPv6AddrPrefix).Labels.String()
				}
				if maxLabelLen < len(label) {
					maxLabelLen = len(label)
				}
				args = append(args, label)
			}
			args = append(args, []interface{}{nexthop, aspathstr}...)
			if showAge {
				args = append(args, formatTimedelta(int64(now.Sub(p.GetTimestamp()).Seconds())))
			}
			args = append(args, pattrstr)
			pathStrs = append(pathStrs, args)
		}
	}

	var format string
	if isMonitor {
		format = "[%s] %d:%s via %s aspath [%s] attrs %s\n"
	} else {
		format = fmt.Sprintf("%%-3s")
		if showIdentifier != bgp.BGP_ADD_PATH_NONE {
			format += "%-3s "
		}
		format += fmt.Sprintf("%%-%ds ", maxPrefixLen)
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
		args := []interface{}{""}
		if showIdentifier != bgp.BGP_ADD_PATH_NONE {
			args = append(args, "ID")
		}
		args = append(args, "Network")
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

func checkOriginAsWasNotShown(p *table.Path, shownAs map[uint32]struct{}) bool {
	asPath := p.GetAsPath().Value
	// the path was generated in internal
	if len(asPath) == 0 {
		return false
	}
	aslist := asPath[len(asPath)-1].(*bgp.As4PathParam).AS
	origin := aslist[len(aslist)-1]

	if _, ok := shownAs[origin]; ok {
		return false
	}
	shownAs[origin] = struct{}{}
	return true
}

func ShowValidationInfo(p *table.Path) {
	status := p.Validation().Status
	reason := p.Validation().Reason
	asPath := p.GetAsPath().Value
	aslist := asPath[len(asPath)-1].(*bgp.As4PathParam).AS
	origin := aslist[len(aslist)-1]

	fmt.Printf("Target Prefix: %s, AS: %d\n", p.GetNlri().String(), origin)
	fmt.Printf("  This route is %s", status)
	switch status {
	case config.RPKI_VALIDATION_RESULT_TYPE_INVALID:
		fmt.Printf("  reason: %s\n", reason)
		switch reason {
		case table.RPKI_VALIDATION_REASON_TYPE_AS:
			fmt.Println("  No VRP ASN matches the route origin ASN.")
		case table.RPKI_VALIDATION_REASON_TYPE_LENGTH:
			fmt.Println("  Route Prefix length is greater than the maximum length allowed by VRP(s) matching this route origin ASN.")
		}
	case config.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND:
		fmt.Println("\n  No VRP Covers the Route Prefix")
	default:
		fmt.Print("\n\n")
	}

	printVRPs := func(l []*table.ROA) {
		if len(l) == 0 {
			fmt.Println("    No Entry")
		} else {
			var format string
			if ip, _, _ := net.ParseCIDR(p.GetNlri().String()); ip.To4() != nil {
				format = "    %-18s %-6s %-10s\n"
			} else {
				format = "    %-42s %-6s %-10s\n"
			}
			fmt.Printf(format, "Network", "AS", "MaxLen")
			for _, m := range l {
				fmt.Printf(format, m.Prefix, fmt.Sprint(m.AS), fmt.Sprint(m.MaxLen))
			}
		}
	}

	fmt.Println("  Matched VRPs: ")
	printVRPs(p.Validation().Matched)
	fmt.Println("  Unmatched AS VRPs: ")
	printVRPs(p.Validation().UnmatchedAs)
	fmt.Println("  Unmatched Length VRPs: ")
	printVRPs(p.Validation().UnmatchedLength)
}

func showRibInfo(r, name string) error {
	def := addr2AddressFamily(net.ParseIP(name))
	if r == CMD_GLOBAL {
		def = bgp.RF_IPv4_UC
	}
	family, err := checkAddressFamily(def)
	if err != nil {
		return err
	}

	var info *table.TableInfo
	switch r {
	case CMD_GLOBAL:
		info, err = client.GetRIBInfo(family)
	case CMD_LOCAL:
		info, err = client.GetLocalRIBInfo(name, family)
	case CMD_ADJ_IN:
		info, err = client.GetAdjRIBInInfo(name, family)
	case CMD_ADJ_OUT:
		info, err = client.GetAdjRIBOutInfo(name, family)
	default:
		return fmt.Errorf("invalid resource to show RIB info: %s", r)
	}

	if err != nil {
		return err
	}

	if globalOpts.Json {
		j, _ := json.Marshal(info)
		fmt.Println(string(j))
		return nil
	}
	fmt.Printf("Table %s\n", family)
	fmt.Printf("Destination: %d, Path: %d\n", info.NumDestination, info.NumPath)
	return nil

}

func parseCIDRorIP(str string) (net.IP, *net.IPNet, error) {
	ip, n, err := net.ParseCIDR(str)
	if err == nil {
		return ip, n, nil
	}
	ip = net.ParseIP(str)
	if ip == nil {
		return ip, nil, fmt.Errorf("invalid CIDR/IP")
	}
	return ip, nil, nil
}

func showNeighborRib(r string, name string, args []string) error {
	showBest := false
	showAge := true
	showLabel := false
	showIdentifier := bgp.BGP_ADD_PATH_NONE
	validationTarget := ""

	def := addr2AddressFamily(net.ParseIP(name))
	switch r {
	case CMD_GLOBAL:
		def = bgp.RF_IPv4_UC
		showBest = true
	case CMD_LOCAL:
		showBest = true
	case CMD_ADJ_OUT:
		showAge = false
	case CMD_VRF:
		def = bgp.RF_IPv4_UC
	}
	family, err := checkAddressFamily(def)
	if err != nil {
		return err
	}
	switch family {
	case bgp.RF_IPv4_MPLS, bgp.RF_IPv6_MPLS, bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN:
		showLabel = true
	}

	var filter []*table.LookupPrefix
	if len(args) > 0 {
		target := args[0]
		if _, _, err = parseCIDRorIP(args[0]); err != nil {
			return err
		}
		var option table.LookupOption
		args = args[1:]
		for len(args) != 0 {
			if args[0] == "longer-prefixes" {
				option = table.LOOKUP_LONGER
			} else if args[0] == "shorter-prefixes" {
				option = table.LOOKUP_SHORTER
			} else if args[0] == "validation" {
				if r != CMD_ADJ_IN {
					return fmt.Errorf("RPKI information is supported for only adj-in.")
				}
				validationTarget = target
			} else {
				return fmt.Errorf("invalid format for route filtering")
			}
			args = args[1:]
		}
		filter = []*table.LookupPrefix{&table.LookupPrefix{
			Prefix:       target,
			LookupOption: option,
		},
		}
	}

	var rib *table.Table
	switch r {
	case CMD_GLOBAL:
		rib, err = client.GetRIB(family, filter)
	case CMD_LOCAL:
		rib, err = client.GetLocalRIB(name, family, filter)
	case CMD_ADJ_IN, CMD_ACCEPTED, CMD_REJECTED:
		showIdentifier = bgp.BGP_ADD_PATH_RECEIVE
		rib, err = client.GetAdjRIBIn(name, family, filter)
	case CMD_ADJ_OUT:
		showIdentifier = bgp.BGP_ADD_PATH_SEND
		rib, err = client.GetAdjRIBOut(name, family, filter)
	case CMD_VRF:
		rib, err = client.GetVRFRIB(name, family, filter)
	}

	if err != nil {
		return err
	}

	switch r {
	case CMD_LOCAL, CMD_ADJ_IN, CMD_ACCEPTED, CMD_REJECTED, CMD_ADJ_OUT:
		if rib.Info("").NumDestination == 0 {
			peer, err := getNeighbor(name, false)
			if err != nil {
				return err
			}
			if peer.State.SessionState != config.SESSION_STATE_ESTABLISHED {
				return fmt.Errorf("Neighbor %v's BGP session is not established", name)
			}
		}
	}

	if globalOpts.Json {
		j, _ := json.Marshal(rib.GetDestinations())
		fmt.Println(string(j))
		return nil
	}

	shownAs := make(map[uint32]struct{})
	counter := 0
	for _, d := range rib.GetSortedDestinations() {
		if validationTarget != "" && d.GetNlri().String() != validationTarget {
			continue
		}
		var ps []*table.Path
		if r == CMD_ACCEPTED || r == CMD_REJECTED {
			for _, p := range d.GetAllKnownPathList() {
				switch r {
				case CMD_ACCEPTED:
					if p.Filtered("") > table.POLICY_DIRECTION_NONE {
						continue
					}
				case CMD_REJECTED:
					if p.Filtered("") == table.POLICY_DIRECTION_NONE {
						continue
					}
				}
				ps = append(ps, p)
			}
		} else {
			ps = d.GetAllKnownPathList()
		}
		showHeader := false
		if counter == 0 {
			showHeader = true
		}
		if validationTarget != "" {
			for _, p := range ps {
				asPath := p.GetAsPath().Value
				if len(asPath) == 0 {
					fmt.Printf("The path to %s was locally generated.\n", p.GetNlri().String())
				} else if checkOriginAsWasNotShown(p, shownAs) {
					ShowValidationInfo(p)
				}
			}
		} else {
			ShowRoute(ps, showAge, showBest, showLabel, false, showHeader, showIdentifier)
		}
		counter++
	}

	if counter == 0 {
		fmt.Println("Network not in table")
	}
	return nil
}

func resetNeighbor(cmd string, remoteIP string, args []string) error {
	family := bgp.RouteFamily(0)
	if reasonLen := len(neighborsOpts.Reason); reasonLen > bgp.BGP_ERROR_ADMINISTRATIVE_COMMUNICATION_MAX {
		return fmt.Errorf("Too long reason for shutdown communication (max %d bytes)", bgp.BGP_ERROR_ADMINISTRATIVE_COMMUNICATION_MAX)
	}
	switch cmd {
	case CMD_RESET:
		return client.ResetNeighbor(remoteIP, neighborsOpts.Reason)
	case CMD_SOFT_RESET:
		return client.SoftReset(remoteIP, family)
	case CMD_SOFT_RESET_IN:
		return client.SoftResetIn(remoteIP, family)
	case CMD_SOFT_RESET_OUT:
		return client.SoftResetOut(remoteIP, family)
	}
	return nil
}

func stateChangeNeighbor(cmd string, remoteIP string, args []string) error {
	if reasonLen := len(neighborsOpts.Reason); reasonLen > bgp.BGP_ERROR_ADMINISTRATIVE_COMMUNICATION_MAX {
		return fmt.Errorf("Too long reason for shutdown communication (max %d bytes)", bgp.BGP_ERROR_ADMINISTRATIVE_COMMUNICATION_MAX)
	}
	switch cmd {
	case CMD_SHUTDOWN:
		fmt.Printf("WARNING: command `%s` is deprecated. use `%s` instead\n", CMD_SHUTDOWN, CMD_DISABLE)
		return client.ShutdownNeighbor(remoteIP, neighborsOpts.Reason)
	case CMD_ENABLE:
		return client.EnableNeighbor(remoteIP)
	case CMD_DISABLE:
		return client.DisableNeighbor(remoteIP, neighborsOpts.Reason)
	}
	return nil
}

func showNeighborPolicy(remoteIP, policyType string, indent int) error {
	var assignment *table.PolicyAssignment
	var err error

	switch strings.ToLower(policyType) {
	case "in":
		assignment, err = client.GetRouteServerInPolicy(remoteIP)
	case "import":
		assignment, err = client.GetRouteServerImportPolicy(remoteIP)
	case "export":
		assignment, err = client.GetRouteServerExportPolicy(remoteIP)
	default:
		return fmt.Errorf("invalid policy type: choose from (in|import|export)")
	}

	if err != nil {
		return err
	}

	if globalOpts.Json {
		j, _ := json.Marshal(assignment)
		fmt.Println(string(j))
		return nil
	}

	fmt.Printf("%s policy:\n", strings.Title(policyType))
	fmt.Printf("%sDefault: %s\n", strings.Repeat(" ", indent), assignment.Default.String())
	for _, p := range assignment.Policies {
		fmt.Printf("%sName %s:\n", strings.Repeat(" ", indent), p.Name)
		printPolicy(indent+4, p)
	}
	return nil
}

func extractDefaultAction(args []string) ([]string, table.RouteType, error) {
	for idx, arg := range args {
		if arg == "default" {
			if len(args) < (idx + 2) {
				return nil, table.ROUTE_TYPE_NONE, fmt.Errorf("specify default action [accept|reject]")
			}
			typ := args[idx+1]
			switch strings.ToLower(typ) {
			case "accept":
				return append(args[:idx], args[idx+2:]...), table.ROUTE_TYPE_ACCEPT, nil
			case "reject":
				return append(args[:idx], args[idx+2:]...), table.ROUTE_TYPE_REJECT, nil
			default:
				return nil, table.ROUTE_TYPE_NONE, fmt.Errorf("invalid default action")
			}
		}
	}
	return args, table.ROUTE_TYPE_NONE, nil
}

func modNeighborPolicy(remoteIP, policyType, cmdType string, args []string) error {
	assign := &table.PolicyAssignment{
		Name: remoteIP,
	}
	switch strings.ToLower(policyType) {
	case "in":
		assign.Type = table.POLICY_DIRECTION_IN
	case "import":
		assign.Type = table.POLICY_DIRECTION_IMPORT
	case "export":
		assign.Type = table.POLICY_DIRECTION_EXPORT
	}

	usage := fmt.Sprintf("usage: gobgp neighbor %s policy %s %s", remoteIP, policyType, cmdType)
	if remoteIP == "" {
		usage = fmt.Sprintf("usage: gobgp global policy %s %s", policyType, cmdType)
	}

	var err error
	switch cmdType {
	case CMD_ADD, CMD_SET:
		if len(args) < 1 {
			return fmt.Errorf("%s <policy name>... [default {%s|%s}]", usage, "accept", "reject")
		}
		var err error
		var def table.RouteType
		args, def, err = extractDefaultAction(args)
		if err != nil {
			return fmt.Errorf("%s\n%s <policy name>... [default {%s|%s}]", err, usage, "accept", "reject")
		}
		assign.Default = def
	}
	ps := make([]*table.Policy, 0, len(args))
	for _, name := range args {
		ps = append(ps, &table.Policy{Name: name})
	}
	assign.Policies = ps
	switch cmdType {
	case CMD_ADD:
		err = client.AddPolicyAssignment(assign)
	case CMD_SET:
		err = client.ReplacePolicyAssignment(assign)
	case CMD_DEL:
		all := false
		if len(args) == 0 {
			all = true
		}
		err = client.DeletePolicyAssignment(assign, all)
	}
	return err
}

func modNeighbor(cmdType string, args []string) error {
	m := extractReserved(args, []string{"interface", "as", "vrf", "route-reflector-client", "route-server-client", "allow-own-as", "remove-private-as", "replace-peer-as"})
	usage := fmt.Sprintf("usage: gobgp neighbor %s [<neighbor-address>| interface <neighbor-interface>]", cmdType)
	if cmdType == CMD_ADD {
		usage += " as <VALUE> [ vrf <vrf-name> | route-reflector-client [<cluster-id>] | route-server-client | allow-own-as <num> | remove-private-as (all|replace) | replace-peer-as ]"
	}

	if (len(m[""]) != 1 && len(m["interface"]) != 1) || len(m["as"]) > 1 || len(m["vrf"]) > 1 || len(m["route-reflector-client"]) > 1 || len(m["allow-own-as"]) > 1 || len(m["remove-private-as"]) > 1 {
		return fmt.Errorf("%s", usage)
	}
	unnumbered := len(m["interface"]) > 0
	if !unnumbered {
		if _, err := net.ResolveIPAddr("ip", m[""][0]); err != nil {
			return err
		}
	}

	getConf := func(asn int) (*config.Neighbor, error) {
		peer := &config.Neighbor{
			Config: config.NeighborConfig{
				PeerAs: uint32(asn),
			},
		}
		if unnumbered {
			peer.Config.NeighborInterface = m["interface"][0]
		} else {
			peer.Config.NeighborAddress = m[""][0]
			peer.State.NeighborAddress = m[""][0]
		}
		if len(m["vrf"]) == 1 {
			peer.Config.Vrf = m["vrf"][0]
		}
		if rr, ok := m["route-reflector-client"]; ok {
			peer.RouteReflector.Config = config.RouteReflectorConfig{
				RouteReflectorClient: true,
			}
			if len(rr) == 1 {
				peer.RouteReflector.Config.RouteReflectorClusterId = config.RrClusterIdType(rr[0])
			}
		}
		if _, ok := m["route-server-client"]; ok {
			peer.RouteServer.Config = config.RouteServerConfig{
				RouteServerClient: true,
			}
		}
		if option, ok := m["allow-own-as"]; ok {
			as, err := strconv.Atoi(option[0])
			if err != nil {
				return nil, err
			}
			peer.AsPathOptions.Config.AllowOwnAs = uint8(as)
		}
		if option, ok := m["remove-private-as"]; ok {
			switch option[0] {
			case "all":
				peer.Config.RemovePrivateAs = config.REMOVE_PRIVATE_AS_OPTION_ALL
			case "replace":
				peer.Config.RemovePrivateAs = config.REMOVE_PRIVATE_AS_OPTION_REPLACE
			default:
				return nil, fmt.Errorf("invalid remove-private-as value: all or replace")
			}
		}
		if _, ok := m["replace-peer-as"]; ok {
			peer.AsPathOptions.Config.ReplacePeerAs = true
		}
		return peer, nil
	}

	var as int
	if len(m["as"]) > 0 {
		var err error
		as, err = strconv.Atoi(m["as"][0])
		if err != nil {
			return err
		}
	}

	n, err := getConf(as)
	if err != nil {
		return err
	}

	switch cmdType {
	case CMD_ADD:
		if len(m[""]) > 0 && len(m["as"]) != 1 {
			return fmt.Errorf("%s", usage)
		}
		return client.AddNeighbor(n)
	case CMD_DEL:
		return client.DeleteNeighbor(n)
	}
	return nil
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
						peer, err := getNeighbor(args[len(args)-1], false)
						if err != nil {
							exitWithError(err)
						}
						addr = peer.State.NeighborAddress
					}
					err := f(cmd.Use, addr, args[:len(args)-1])
					if err != nil {
						exitWithError(err)
					}
				},
			}
			neighborCmdImpl.AddCommand(c)
			switch name {
			case CMD_LOCAL, CMD_ADJ_IN, CMD_ADJ_OUT:
				n := name
				c.AddCommand(&cobra.Command{
					Use: CMD_SUMMARY,
					Run: func(cmd *cobra.Command, args []string) {
						if err := showRibInfo(n, args[len(args)-1]); err != nil {
							exitWithError(err)
						}
					},
				})
			}
		}
	}

	policyCmd := &cobra.Command{
		Use: CMD_POLICY,
		Run: func(cmd *cobra.Command, args []string) {
			peer, err := getNeighbor(args[0], false)
			if err != nil {
				exitWithError(err)
			}
			remoteIP := peer.State.NeighborAddress
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
				peer, err := getNeighbor(args[0], false)
				if err != nil {
					exitWithError(err)
				}
				remoteIP := peer.State.NeighborAddress
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
					peer, err := getNeighbor(args[len(args)-1], false)
					if err != nil {
						exitWithError(err)
					}
					remoteIP := peer.State.NeighborAddress
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
				err = showNeighbors("")
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
	neighborCmd.PersistentFlags().StringVarP(&neighborsOpts.Reason, "reason", "", "", "specifying communication field on Cease NOTIFICATION message with Administrative Shutdown subcode")
	neighborCmd.PersistentFlags().StringVarP(&neighborsOpts.Transport, "transport", "t", "", "specifying a transport protocol")
	return neighborCmd
}
