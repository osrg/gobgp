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
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/spf13/cobra"

	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/internal/pkg/apiutil"
	"github.com/osrg/gobgp/internal/pkg/config"
	"github.com/osrg/gobgp/pkg/packet/bgp"
)

// used in showRoute() to determine the width of each column
var (
	columnWidthPrefix  = 20
	columnWidthNextHop = 20
	columnWidthAsPath  = 20
	columnWidthLabel   = 10
)

func updateColumnWidth(nlri, nexthop, aspath, label string) {
	if prefixLen := len(nlri); columnWidthPrefix < prefixLen {
		columnWidthPrefix = prefixLen
	}
	if columnWidthNextHop < len(nexthop) {
		columnWidthNextHop = len(nexthop)
	}
	if columnWidthAsPath < len(aspath) {
		columnWidthAsPath = len(aspath)
	}
	if columnWidthLabel < len(label) {
		columnWidthLabel = len(label)
	}
}

func getNeighbors(address string, enableAdv bool) ([]*api.Peer, error) {
	stream, err := client.ListPeer(ctx, &api.ListPeerRequest{
		Address:          address,
		EnableAdvertised: enableAdv,
	})
	if err != nil {
		return nil, err
	}

	l := make([]*api.Peer, 0, 1024)
	for {
		r, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		l = append(l, r.Peer)
	}
	if address != "" && len(l) == 0 {
		return l, fmt.Errorf("not found neighbor %s", address)
	}
	return l, err
}

func getASN(p *api.Peer) string {
	asn := "*"
	if p.State.PeerAs > 0 {
		asn = fmt.Sprint(p.State.PeerAs)
	}
	return asn
}

func counter(p *api.Peer) (uint64, uint64, uint64, error) {
	accepted := uint64(0)
	received := uint64(0)
	advertised := uint64(0)
	for _, afisafi := range p.AfiSafis {
		if subOpts.AddressFamily != "" {
			f, e := checkAddressFamily(&api.Family{})
			if e != nil {
				return 0, 0, 0, e
			}
			if f.Afi != afisafi.State.Family.Afi || f.Safi != afisafi.State.Family.Safi {
				continue
			}
		}
		accepted += afisafi.State.Accepted
		received += afisafi.State.Received
		advertised += afisafi.State.Advertised
	}
	return received, accepted, advertised, nil
}

func showNeighbors(vrf string) error {
	m, err := getNeighbors("", false)
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

	sort.Slice(m, func(i, j int) bool {
		p1 := m[i].Conf.NeighborAddress
		p2 := m[j].Conf.NeighborAddress
		p1Isv4 := !strings.Contains(p1, ":")
		p2Isv4 := !strings.Contains(p2, ":")
		if p1Isv4 != p2Isv4 {
			return p1Isv4
		}
		addrlen := 128
		if p1Isv4 {
			addrlen = 32
		}
		strings := sort.StringSlice{cidr2prefix(fmt.Sprintf("%s/%d", p1, addrlen)),
			cidr2prefix(fmt.Sprintf("%s/%d", p2, addrlen))}
		return strings.Less(0, 1)
	})

	for _, n := range m {
		if i := len(n.Conf.NeighborInterface); i > maxaddrlen {
			maxaddrlen = i
		} else if j := len(n.State.NeighborAddress); j > maxaddrlen {
			maxaddrlen = j
		}
		if l := len(getASN(n)); l > maxaslen {
			maxaslen = l
		}
		timeStr := "never"
		if n.Timers.State.Uptime != nil {
			t, _ := ptypes.Timestamp(n.Timers.State.Downtime)
			if n.State.SessionState == api.PeerState_ESTABLISHED {
				t, _ = ptypes.Timestamp(n.Timers.State.Uptime)
			}
			timeStr = formatTimedelta(t)
		}
		if len(timeStr) > maxtimelen {
			maxtimelen = len(timeStr)
		}
		timedelta = append(timedelta, timeStr)
	}

	format := "%-" + fmt.Sprint(maxaddrlen) + "s" + " %" + fmt.Sprint(maxaslen) + "s" + " %" + fmt.Sprint(maxtimelen) + "s"
	format += " %-11s |%9s %9s\n"
	fmt.Printf(format, "Peer", "AS", "Up/Down", "State", "#Received", "Accepted")
	formatFsm := func(admin api.PeerState_AdminState, fsm api.PeerState_SessionState) string {
		switch admin {
		case api.PeerState_DOWN:
			return "Idle(Admin)"
		case api.PeerState_PFX_CT:
			return "Idle(PfxCt)"
		}

		switch fsm {
		case api.PeerState_UNKNOWN:
			// should never happen
			return "Unknown"
		case api.PeerState_IDLE:
			return "Idle"
		case api.PeerState_CONNECT:
			return "Connect"
		case api.PeerState_ACTIVE:
			return "Active"
		case api.PeerState_OPENSENT:
			return "Sent"
		case api.PeerState_OPENCONFIRM:
			return "Confirm"
		case api.PeerState_ESTABLISHED:
			return "Establ"
		default:
			return string(fsm)
		}
	}

	for i, n := range m {
		neigh := n.State.NeighborAddress
		if n.Conf.NeighborInterface != "" {
			neigh = n.Conf.NeighborInterface
		}
		received, accepted, _, _ := counter(n)
		fmt.Printf(format, neigh, getASN(n), timedelta[i], formatFsm(n.State.AdminState, n.State.SessionState), fmt.Sprint(received), fmt.Sprint(accepted))
	}

	return nil
}

func showNeighbor(args []string) error {
	l, err := getNeighbors(args[0], true)
	if err != nil {
		return err
	}
	p := l[0]

	if globalOpts.Json {
		j, _ := json.Marshal(p)
		fmt.Println(string(j))
		return nil
	}

	fmt.Printf("BGP neighbor is %s, remote AS %s", p.State.NeighborAddress, getASN(p))

	if p.RouteReflector.RouteReflectorClient {
		fmt.Printf(", route-reflector-client\n")
	} else if p.RouteServer.RouteServerClient {
		fmt.Printf(", route-server-client\n")
	} else {
		fmt.Printf("\n")
	}

	id := "unknown"
	if p.State != nil && p.State.RouterId != "" {
		id = p.State.RouterId
	}
	fmt.Printf("  BGP version 4, remote router ID %s\n", id)
	fmt.Printf("  BGP state = %s", p.State.SessionState)
	if p.Timers.State.Uptime != nil {
		t, _ := ptypes.Timestamp(p.Timers.State.Uptime)
		fmt.Printf(", up for %s\n", formatTimedelta(t))
	} else {
		fmt.Print("\n")
	}
	fmt.Printf("  BGP OutQ = %d, Flops = %d\n", p.State.Queues.Output, p.State.Flops)
	fmt.Printf("  Hold time is %d, keepalive interval is %d seconds\n", int(p.Timers.State.NegotiatedHoldTime), int(p.Timers.State.KeepaliveInterval))
	fmt.Printf("  Configured hold time is %d, keepalive interval is %d seconds\n", int(p.Timers.Config.HoldTime), int(p.Timers.Config.KeepaliveInterval))

	elems := make([]string, 0, 3)
	if as := p.Conf.AllowOwnAs; as > 0 {
		elems = append(elems, fmt.Sprintf("Allow Own AS: %d", as))
	}
	switch p.Conf.RemovePrivateAs {
	case api.PeerConf_ALL:
		elems = append(elems, "Remove private AS: all")
	case api.PeerConf_REPLACE:
		elems = append(elems, "Remove private AS: replace")
	}
	if p.Conf.ReplacePeerAs {
		elems = append(elems, "Replace peer AS: enabled")
	}

	fmt.Printf("  %s\n", strings.Join(elems, ", "))

	fmt.Printf("  Neighbor capabilities:\n")
	caps := []bgp.ParameterCapabilityInterface{}
	lookup := func(val bgp.ParameterCapabilityInterface, l []bgp.ParameterCapabilityInterface) bgp.ParameterCapabilityInterface {
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
	lcaps, _ := apiutil.UnmarshalCapabilities(p.State.LocalCap)
	caps = append(caps, lcaps...)

	rcaps, _ := apiutil.UnmarshalCapabilities(p.State.RemoteCap)
	for _, c := range rcaps {
		if lookup(c, caps) == nil {
			caps = append(caps, c)
		}
	}

	sort.Slice(caps, func(i, j int) bool {
		return caps[i].Code() < caps[j].Code()
	})

	firstMp := true

	for _, c := range caps {
		support := ""
		if m := lookup(c, lcaps); m != nil {
			support += "advertised"
		}
		if lookup(c, rcaps) != nil {
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
			if m := lookup(c, lcaps); m != nil {
				g := m.(*bgp.CapGracefulRestart)
				if s := grStr(g); len(s) > 0 {
					fmt.Printf("        Local: %s", s)
				}
			}
			if m := lookup(c, rcaps); m != nil {
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
			if m := lookup(c, lcaps); m != nil {
				g := m.(*bgp.CapLongLivedGracefulRestart)
				if s := grStr(g); len(s) > 0 {
					fmt.Printf("        Local:\n%s", s)
				}
			}
			if m := lookup(c, rcaps); m != nil {
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
			if m := lookup(c, lcaps); m != nil {
				e := m.(*bgp.CapExtendedNexthop)
				if s := exnhStr(e); len(s) > 0 {
					fmt.Printf("        Local:  %s\n", s)
				}
			}
			if m := lookup(c, rcaps); m != nil {
				e := m.(*bgp.CapExtendedNexthop)
				if s := exnhStr(e); len(s) > 0 {
					fmt.Printf("        Remote: %s\n", s)
				}
			}
		case bgp.BGP_CAP_ADD_PATH:
			fmt.Printf("    %s:\t%s\n", c.Code(), support)
			if m := lookup(c, lcaps); m != nil {
				fmt.Println("      Local:")
				for _, item := range m.(*bgp.CapAddPath).Tuples {
					fmt.Printf("         %s:\t%s\n", item.RouteFamily, item.Mode)
				}
			}
			if m := lookup(c, rcaps); m != nil {
				fmt.Println("      Remote:")
				for _, item := range m.(*bgp.CapAddPath).Tuples {
					fmt.Printf("         %s:\t%s\n", item.RouteFamily, item.Mode)
				}
			}
		default:
			fmt.Printf("    %s:\t%s\n", c.Code(), support)
		}
	}
	received, accepted, advertised, e := counter(p)
	if e != nil {
		return e
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
	fmt.Printf("    Advertised:    %10d\n", advertised)
	fmt.Printf("    Received:      %10d\n", received)
	fmt.Printf("    Accepted:      %10d\n", accepted)
	first := true
	for _, a := range p.AfiSafis {
		limit := a.PrefixLimits
		if limit != nil && limit.MaxPrefixes > 0 {
			if first {
				fmt.Println("  Prefix Limits:")
				first = false
			}
			rf := apiutil.ToRouteFamily(limit.Family)
			fmt.Printf("    %s:\tMaximum prefixes allowed %d", bgp.AddressFamilyNameMap[rf], limit.MaxPrefixes)
			if limit.ShutdownThresholdPct > 0 {
				fmt.Printf(", Threshold for warning message %d%%\n", limit.ShutdownThresholdPct)
			} else {
				fmt.Printf("\n")
			}
		}
	}
	return nil
}

func getPathSymbolString(p *api.Path, idx int, showBest bool) string {
	symbols := ""
	if p.Stale {
		symbols += "S"
	}
	if v := p.GetValidation(); v != nil {
		switch v.State {
		case api.Validation_STATE_NOT_FOUND:
			symbols += "N"
		case api.Validation_STATE_VALID:
			symbols += "V"
		case api.Validation_STATE_INVALID:
			symbols += "I"
		}

	}
	if showBest {
		if p.Best && !p.IsNexthopInvalid {
			symbols += "*>"
		} else {
			symbols += "* "
		}
	}
	return symbols
}

func getPathAttributeString(nlri bgp.AddrPrefixInterface, attrs []bgp.PathAttributeInterface) string {
	s := make([]string, 0)
	for _, a := range attrs {
		switch a.GetType() {
		case bgp.BGP_ATTR_TYPE_NEXT_HOP, bgp.BGP_ATTR_TYPE_MP_REACH_NLRI, bgp.BGP_ATTR_TYPE_AS_PATH, bgp.BGP_ATTR_TYPE_AS4_PATH:
			continue
		default:
			s = append(s, a.String())
		}
	}
	switch n := nlri.(type) {
	case *bgp.EVPNNLRI:
		// We print non route key fields like path attributes.
		switch route := n.RouteTypeData.(type) {
		case *bgp.EVPNMacIPAdvertisementRoute:
			s = append(s, fmt.Sprintf("[ESI: %s]", route.ESI.String()))
		case *bgp.EVPNIPPrefixRoute:
			s = append(s, fmt.Sprintf("[ESI: %s]", route.ESI.String()))
			if route.GWIPAddress != nil {
				s = append(s, fmt.Sprintf("[GW: %s]", route.GWIPAddress.String()))
			}
		}
	}
	return fmt.Sprint(s)
}

func makeShowRouteArgs(p *api.Path, idx int, now time.Time, showAge, showBest, showLabel bool, showIdentifier bgp.BGPAddPathMode) []interface{} {
	nlri, _ := apiutil.GetNativeNlri(p)

	// Path Symbols (e.g. "*>")
	args := []interface{}{getPathSymbolString(p, idx, showBest)}

	// Path Identifier
	switch showIdentifier {
	case bgp.BGP_ADD_PATH_RECEIVE:
		args = append(args, fmt.Sprint(p.GetIdentifier()))
	case bgp.BGP_ADD_PATH_SEND:
		args = append(args, fmt.Sprint(p.GetLocalIdentifier()))
	}

	// NLRI
	args = append(args, nlri)

	// Label
	label := ""
	if showLabel {
		label = bgp.LabelString(nlri)
		args = append(args, label)
	}

	attrs, _ := apiutil.GetNativePathAttributes(p)
	// Next Hop
	nexthop := "fictitious"
	if n := getNextHopFromPathAttributes(attrs); n != nil {
		nexthop = n.String()
	}
	args = append(args, nexthop)

	// AS_PATH
	aspathstr := func() string {
		for _, attr := range attrs {
			switch a := attr.(type) {
			case *bgp.PathAttributeAsPath:
				return bgp.AsPathString(a)
			}
		}
		return ""
	}()
	args = append(args, aspathstr)

	// Age
	if showAge {
		t, _ := ptypes.Timestamp(p.Age)
		args = append(args, formatTimedelta(t))
	}

	// Path Attributes
	pattrstr := getPathAttributeString(nlri, attrs)
	args = append(args, pattrstr)

	updateColumnWidth(nlri.String(), nexthop, aspathstr, label)

	return args
}

func showRoute(dsts []*api.Destination, showAge, showBest, showLabel bool, showIdentifier bgp.BGPAddPathMode) {
	pathStrs := make([][]interface{}, 0, len(dsts))
	now := time.Now()
	for _, dst := range dsts {
		for idx, p := range dst.Paths {
			pathStrs = append(pathStrs, makeShowRouteArgs(p, idx, now, showAge, showBest, showLabel, showIdentifier))
		}
	}

	headers := make([]interface{}, 0)
	var format string
	headers = append(headers, "") // Symbols
	format = fmt.Sprintf("%%-3s")
	if showIdentifier != bgp.BGP_ADD_PATH_NONE {
		headers = append(headers, "ID")
		format += "%-3s "
	}
	headers = append(headers, "Network")
	format += fmt.Sprintf("%%-%ds ", columnWidthPrefix)
	if showLabel {
		headers = append(headers, "Labels")
		format += fmt.Sprintf("%%-%ds ", columnWidthLabel)
	}
	headers = append(headers, "Next Hop", "AS_PATH")
	format += fmt.Sprintf("%%-%ds %%-%ds ", columnWidthNextHop, columnWidthAsPath)
	if showAge {
		headers = append(headers, "Age")
		format += "%-10s "
	}
	headers = append(headers, "Attrs")
	format += "%-s\n"

	fmt.Printf(format, headers...)
	for _, pathStr := range pathStrs {
		fmt.Printf(format, pathStr...)
	}
}

func checkOriginAsWasNotShown(p *api.Path, asPath []bgp.AsPathParamInterface, shownAs map[uint32]struct{}) bool {
	// the path was generated in internal
	if len(asPath) == 0 {
		return false
	}
	asList := asPath[len(asPath)-1].GetAS()
	origin := asList[len(asList)-1]

	if _, ok := shownAs[origin]; ok {
		return false
	}
	shownAs[origin] = struct{}{}
	return true
}

func showValidationInfo(p *api.Path, shownAs map[uint32]struct{}) error {
	var asPath []bgp.AsPathParamInterface
	attrs, _ := apiutil.GetNativePathAttributes(p)
	for _, attr := range attrs {
		if attr.GetType() == bgp.BGP_ATTR_TYPE_AS_PATH {
			asPath = attr.(*bgp.PathAttributeAsPath).Value
		}
	}

	nlri, _ := apiutil.GetNativeNlri(p)
	if len(asPath) == 0 {
		return fmt.Errorf("the path to %s was locally generated", nlri.String())
	} else if !checkOriginAsWasNotShown(p, asPath, shownAs) {
		return nil
	}

	status := p.GetValidation().State
	reason := p.GetValidation().Reason
	asList := asPath[len(asPath)-1].GetAS()
	origin := asList[len(asList)-1]

	fmt.Printf("Target Prefix: %s, AS: %d\n", nlri.String(), origin)
	fmt.Printf("  This route is %s", status)
	switch status {
	case api.Validation_STATE_INVALID:
		fmt.Printf("  reason: %s\n", reason)
		switch reason {
		case api.Validation_REASON_AS:
			fmt.Println("  No VRP ASN matches the route origin ASN.")
		case api.Validation_REASON_LENGTH:
			fmt.Println("  Route Prefix length is greater than the maximum length allowed by VRP(s) matching this route origin ASN.")
		}
	case api.Validation_STATE_NOT_FOUND:
		fmt.Println("\n  No VRP Covers the Route Prefix")
	default:
		fmt.Print("\n\n")
	}

	printVRPs := func(l []*api.Roa) {
		if len(l) == 0 {
			fmt.Println("    No Entry")
		} else {
			var format string
			if ip, _, _ := net.ParseCIDR(nlri.String()); ip.To4() != nil {
				format = "    %-18s %-6s %-10s\n"
			} else {
				format = "    %-42s %-6s %-10s\n"
			}
			fmt.Printf(format, "Network", "AS", "MaxLen")
			for _, m := range l {
				fmt.Printf(format, m.Prefix, fmt.Sprint(m.As), fmt.Sprint(m.Maxlen))
			}
		}
	}

	fmt.Println("  Matched VRPs: ")
	printVRPs(p.GetValidation().Matched)
	fmt.Println("  Unmatched AS VRPs: ")
	printVRPs(p.GetValidation().UnmatchedAs)
	fmt.Println("  Unmatched Length VRPs: ")
	printVRPs(p.GetValidation().UnmatchedLength)

	return nil
}

func showRibInfo(r, name string) error {
	def := addr2AddressFamily(net.ParseIP(name))
	if r == cmdGlobal || r == cmdVRF {
		def = ipv4UC
	}
	family, err := checkAddressFamily(def)
	if err != nil {
		return err
	}

	var t api.TableType
	switch r {
	case cmdGlobal:
		t = api.TableType_GLOBAL
	case cmdLocal:
		t = api.TableType_LOCAL
	case cmdAdjIn:
		t = api.TableType_ADJ_IN
	case cmdAdjOut:
		t = api.TableType_ADJ_OUT
	case cmdVRF:
		t = api.TableType_VRF
	default:
		return fmt.Errorf("invalid resource to show RIB info: %s", r)
	}
	rsp, err := client.GetTable(ctx, &api.GetTableRequest{
		TableType: t,
		Family:    family,
		Name:      name,
	})

	if err != nil {
		return err
	}

	if globalOpts.Json {
		j, _ := json.Marshal(rsp)
		fmt.Println(string(j))
		return nil
	}
	fmt.Printf("Table %s\n", family)
	fmt.Printf("Destination: %d, Path: %d\n", rsp.NumDestination, rsp.NumPath)
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
	case cmdGlobal:
		def = ipv4UC
		showBest = true
	case cmdLocal:
		showBest = true
	case cmdAdjOut:
		showAge = false
	case cmdVRF:
		def = ipv4UC
		showBest = true
	}
	family, err := checkAddressFamily(def)
	if err != nil {
		return err
	}
	rf := apiutil.ToRouteFamily(family)
	switch rf {
	case bgp.RF_IPv4_MPLS, bgp.RF_IPv6_MPLS, bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN, bgp.RF_EVPN:
		showLabel = true
	}

	var filter []*api.TableLookupPrefix
	if len(args) > 0 {
		target := args[0]
		switch rf {
		case bgp.RF_EVPN:
			// Uses target as EVPN Route Type string
		default:
			if _, _, err = parseCIDRorIP(target); err != nil {
				return err
			}
		}
		var option api.TableLookupOption
		args = args[1:]
		for len(args) != 0 {
			if args[0] == "longer-prefixes" {
				option = api.TableLookupOption_LOOKUP_LONGER
			} else if args[0] == "shorter-prefixes" {
				option = api.TableLookupOption_LOOKUP_SHORTER
			} else if args[0] == "validation" {
				if r != cmdAdjIn {
					return fmt.Errorf("RPKI information is supported for only adj-in")
				}
				validationTarget = target
			} else {
				return fmt.Errorf("invalid format for route filtering")
			}
			args = args[1:]
		}
		filter = []*api.TableLookupPrefix{&api.TableLookupPrefix{
			Prefix:       target,
			LookupOption: option,
		},
		}
	}

	var t api.TableType
	switch r {
	case cmdGlobal:
		t = api.TableType_GLOBAL
	case cmdLocal:
		t = api.TableType_LOCAL
	case cmdAdjIn, cmdAccepted, cmdRejected:
		t = api.TableType_ADJ_IN
		showIdentifier = bgp.BGP_ADD_PATH_RECEIVE
	case cmdAdjOut:
		t = api.TableType_ADJ_OUT
		showIdentifier = bgp.BGP_ADD_PATH_SEND
	case cmdVRF:
		t = api.TableType_VRF
	}

	stream, err := client.ListPath(ctx, &api.ListPathRequest{
		TableType: t,
		Family:    family,
		Name:      name,
		Prefixes:  filter,
		SortType:  api.ListPathRequest_PREFIX,
	})
	if err != nil {
		return err
	}

	rib := make([]*api.Destination, 0)
	for {
		r, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		rib = append(rib, r.Destination)
	}

	switch r {
	case cmdLocal, cmdAdjIn, cmdAccepted, cmdRejected, cmdAdjOut:
		if len(rib) == 0 {
			l, err := getNeighbors(name, false)
			if err != nil {
				return err
			}
			if l[0].State.SessionState != api.PeerState_ESTABLISHED {
				return fmt.Errorf("neighbor %v's BGP session is not established", name)
			}
		}
	}

	if globalOpts.Json {
		d := make(map[string]*apiutil.Destination)
		for _, dst := range rib {
			d[dst.Prefix] = apiutil.NewDestination(dst)
		}
		j, _ := json.Marshal(d)
		fmt.Println(string(j))
		return nil
	}

	if validationTarget != "" {
		// show RPKI validation info
		d := func() *api.Destination {
			for _, dst := range rib {
				if dst.Prefix == validationTarget {
					return dst
				}
			}
			return nil
		}()
		if d == nil {
			fmt.Println("Network not in table")
			return nil
		}
		shownAs := make(map[uint32]struct{})
		for _, p := range d.GetPaths() {
			if err := showValidationInfo(p, shownAs); err != nil {
				return err
			}
		}
	} else {
		// show RIB
		var dsts []*api.Destination
		switch rf {
		case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
			type d struct {
				prefix net.IP
				dst    *api.Destination
			}
			l := make([]*d, 0, len(rib))
			for _, dst := range rib {
				prefix := dst.Prefix
				if t == api.TableType_VRF {
					// extract prefix from original which is RD(AS:VRF):IPv4 or IPv6 address
					s := strings.SplitN(prefix, ":", 3)
					prefix = s[len(s)-1]
				}
				_, p, _ := net.ParseCIDR(prefix)
				l = append(l, &d{prefix: p.IP, dst: dst})
			}

			sort.Slice(l, func(i, j int) bool {
				return bytes.Compare(l[i].prefix, l[j].prefix) < 0
			})

			dsts = make([]*api.Destination, 0, len(rib))
			for _, s := range l {
				dsts = append(dsts, s.dst)
			}
		default:
			dsts = append(dsts, rib...)
		}

		for _, d := range dsts {
			switch r {
			case cmdAccepted:
				l := make([]*api.Path, 0, len(d.Paths))
				for _, p := range d.GetPaths() {
					if !p.Filtered {
						l = append(l, p)
					}
				}
				d.Paths = l
			case cmdRejected:
				// always nothing
				d.Paths = []*api.Path{}
			default:
			}
		}
		if len(dsts) > 0 {
			showRoute(dsts, showAge, showBest, showLabel, showIdentifier)
		} else {
			fmt.Println("Network not in table")
		}
	}
	return nil
}

func resetNeighbor(cmd string, remoteIP string, args []string) error {
	if reasonLen := len(neighborsOpts.Reason); reasonLen > bgp.BGP_ERROR_ADMINISTRATIVE_COMMUNICATION_MAX {
		return fmt.Errorf("too long reason for shutdown communication (max %d bytes)", bgp.BGP_ERROR_ADMINISTRATIVE_COMMUNICATION_MAX)
	}
	var comm string
	soft := true
	dir := api.ResetPeerRequest_BOTH
	switch cmd {
	case cmdReset:
		soft = false
		comm = neighborsOpts.Reason
	case cmdSoftReset:
	case cmdSoftResetIn:
		dir = api.ResetPeerRequest_IN
	case cmdSoftResetOut:
		dir = api.ResetPeerRequest_OUT
	}
	_, err := client.ResetPeer(ctx, &api.ResetPeerRequest{
		Address:       remoteIP,
		Communication: comm,
		Soft:          soft,
		Direction:     dir,
	})
	return err
}

func stateChangeNeighbor(cmd string, remoteIP string, args []string) error {
	if reasonLen := len(neighborsOpts.Reason); reasonLen > bgp.BGP_ERROR_ADMINISTRATIVE_COMMUNICATION_MAX {
		return fmt.Errorf("too long reason for shutdown communication (max %d bytes)", bgp.BGP_ERROR_ADMINISTRATIVE_COMMUNICATION_MAX)
	}
	switch cmd {
	case cmdShutdown:
		fmt.Printf("WARNING: command `%s` is deprecated. use `%s` instead\n", cmdShutdown, cmdDisable)
		_, err := client.ShutdownPeer(ctx, &api.ShutdownPeerRequest{
			Address:       remoteIP,
			Communication: neighborsOpts.Reason,
		})
		return err
	case cmdEnable:
		_, err := client.EnablePeer(ctx, &api.EnablePeerRequest{
			Address: remoteIP,
		})
		return err
	case cmdDisable:
		_, err := client.DisablePeer(ctx, &api.DisablePeerRequest{
			Address: remoteIP,
		})
		return err
	}
	return nil
}

func showNeighborPolicy(remoteIP, policyType string, indent int) error {
	var err error
	var dir api.PolicyDirection

	switch strings.ToLower(policyType) {
	case "import":
		dir = api.PolicyDirection_IMPORT
	case "export":
		dir = api.PolicyDirection_EXPORT
	default:
		return fmt.Errorf("invalid policy type: choose from (import|export)")
	}
	if remoteIP == "" {
		remoteIP = globalRIBName
	}
	stream, err := client.ListPolicyAssignment(ctx, &api.ListPolicyAssignmentRequest{
		Name:      remoteIP,
		Direction: dir,
	})
	if err != nil {
		return err
	}
	assignment := &api.PolicyAssignment{}
	r, err := stream.Recv()
	if err == nil {
		assignment = r.Assignment
	} else if err != io.EOF {
		return err
	}

	if globalOpts.Json {
		j, _ := json.Marshal(assignment)
		fmt.Println(string(j))
		return nil
	}

	fmt.Printf("%s policy:\n", strings.Title(policyType))
	fmt.Printf("%sDefault: %s\n", strings.Repeat(" ", indent), assignment.DefaultAction.String())
	for _, p := range assignment.Policies {
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
	if remoteIP == "" {
		remoteIP = globalRIBName
	}

	assign := &api.PolicyAssignment{
		Name: remoteIP,
	}

	switch strings.ToLower(policyType) {
	case "import":
		assign.Direction = api.PolicyDirection_IMPORT
	case "export":
		assign.Direction = api.PolicyDirection_EXPORT
	}

	usage := fmt.Sprintf("usage: gobgp neighbor %s policy %s %s", remoteIP, policyType, cmdType)
	if remoteIP == "" {
		usage = fmt.Sprintf("usage: gobgp global policy %s %s", policyType, cmdType)
	}

	var err error
	switch cmdType {
	case cmdAdd, cmdSet:
		if len(args) < 1 {
			return fmt.Errorf("%s <policy name>... [default {%s|%s}]", usage, "accept", "reject")
		}
		var err error
		var def api.RouteAction
		args, def, err = extractDefaultAction(args)
		if err != nil {
			return fmt.Errorf("%s\n%s <policy name>... [default {%s|%s}]", err, usage, "accept", "reject")
		}
		assign.DefaultAction = def
	}
	ps := make([]*api.Policy, 0, len(args))
	for _, name := range args {
		ps = append(ps, &api.Policy{Name: name})
	}
	assign.Policies = ps
	switch cmdType {
	case cmdAdd:
		_, err = client.AddPolicyAssignment(ctx, &api.AddPolicyAssignmentRequest{
			Assignment: assign,
		})
	case cmdSet:
		_, err = client.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{
			Assignment: assign,
		})
	case cmdDel:
		all := false
		if len(args) == 0 {
			all = true
		}
		_, err = client.DeletePolicyAssignment(ctx, &api.DeletePolicyAssignmentRequest{
			Assignment: assign,
			All:        all,
		})
	}
	return err
}

func modNeighbor(cmdType string, args []string) error {
	params := map[string]int{
		"interface": paramSingle,
	}
	usage := fmt.Sprintf("usage: gobgp neighbor %s [ <neighbor-address> | interface <neighbor-interface> ]", cmdType)
	if cmdType == cmdAdd {
		usage += " as <VALUE>"
	} else if cmdType == cmdUpdate {
		usage += " [ as <VALUE> ]"
	}
	if cmdType == cmdAdd || cmdType == cmdUpdate {
		params["as"] = paramSingle
		params["family"] = paramSingle
		params["vrf"] = paramSingle
		params["route-reflector-client"] = paramSingle
		params["route-server-client"] = paramFlag
		params["allow-own-as"] = paramSingle
		params["remove-private-as"] = paramSingle
		params["replace-peer-as"] = paramFlag
		params["ebgp-multihop-ttl"] = paramSingle
		usage += " [ family <address-families-list> | vrf <vrf-name> | route-reflector-client [<cluster-id>] | route-server-client | allow-own-as <num> | remove-private-as (all|replace) | replace-peer-as | ebgp-multihop-ttl <ttl>]"
	}

	m, err := extractReserved(args, params)
	if err != nil || (len(m[""]) != 1 && len(m["interface"]) != 1) {
		return fmt.Errorf("%s", usage)
	}

	unnumbered := len(m["interface"]) > 0
	if !unnumbered {
		if _, err := net.ResolveIPAddr("ip", m[""][0]); err != nil {
			return err
		}
	}

	getNeighborAddress := func() (string, error) {
		if unnumbered {
			return config.GetIPv6LinkLocalNeighborAddress(m["interface"][0])
		}
		return m[""][0], nil
	}

	getNeighborConfig := func() (*api.Peer, error) {
		addr, err := getNeighborAddress()
		if err != nil {
			return nil, err
		}
		var peer *api.Peer
		switch cmdType {
		case cmdAdd, cmdDel:
			peer = &api.Peer{
				Conf:  &api.PeerConf{},
				State: &api.PeerState{},
			}
			if unnumbered {
				peer.Conf.NeighborInterface = m["interface"][0]
			} else {
				peer.Conf.NeighborAddress = addr
			}
			peer.State.NeighborAddress = addr
		case cmdUpdate:
			l, err := getNeighbors(addr, false)
			if err != nil {
				return nil, err
			}
			peer = l[0]
		default:
			return nil, fmt.Errorf("invalid command: %s", cmdType)
		}
		return peer, nil
	}

	updateNeighborConfig := func(peer *api.Peer) error {
		if len(m["as"]) > 0 {
			as, err := strconv.ParseUint(m["as"][0], 10, 32)
			if err != nil {
				return err
			}
			peer.Conf.PeerAs = uint32(as)
		}
		if len(m["family"]) == 1 {
			peer.AfiSafis = make([]*api.AfiSafi, 0) // for the case of cmdUpdate
			for _, f := range strings.Split(m["family"][0], ",") {
				rf, err := bgp.GetRouteFamily(f)
				if err != nil {
					return err
				}
				afi, safi := bgp.RouteFamilyToAfiSafi(rf)
				peer.AfiSafis = append(peer.AfiSafis, &api.AfiSafi{Config: &api.AfiSafiConfig{Family: apiutil.ToApiFamily(afi, safi)}})
			}
		}
		if len(m["vrf"]) == 1 {
			peer.Conf.Vrf = m["vrf"][0]
		}
		if option, ok := m["route-reflector-client"]; ok {
			peer.RouteReflector.RouteReflectorClient = true
			if len(option) == 1 {
				peer.RouteReflector.RouteReflectorClusterId = option[0]
			}
		}
		if _, ok := m["route-server-client"]; ok {
			peer.RouteServer.RouteServerClient = true
		}
		if option, ok := m["allow-own-as"]; ok {
			as, err := strconv.ParseUint(option[0], 10, 8)
			if err != nil {
				return err
			}
			peer.Conf.AllowOwnAs = uint32(as)
		}
		if option, ok := m["remove-private-as"]; ok {
			switch option[0] {
			case "all":
				peer.Conf.RemovePrivateAs = api.PeerConf_ALL
			case "replace":
				peer.Conf.RemovePrivateAs = api.PeerConf_REPLACE
			default:
				return fmt.Errorf("invalid remove-private-as value: all or replace")
			}
		}
		if _, ok := m["replace-peer-as"]; ok {
			peer.Conf.ReplacePeerAs = true
		}
		if len(m["ebgp-multihop-ttl"]) == 1 {
			ttl, err := strconv.ParseUint(m["ebgp-multihop-ttl"][0], 10, 32)
			if err != nil {
				return err
			}
			peer.EbgpMultihop = &api.EbgpMultihop{
				Enabled:     true,
				MultihopTtl: uint32(ttl),
			}
		}
		return nil
	}

	n, err := getNeighborConfig()
	if err != nil {
		return err
	}

	switch cmdType {
	case cmdAdd:
		if err = updateNeighborConfig(n); err != nil {
			return err
		}
		_, err = client.AddPeer(ctx, &api.AddPeerRequest{
			Peer: n,
		})
	case cmdDel:
		_, err = client.DeletePeer(ctx, &api.DeletePeerRequest{
			Address:   n.Conf.NeighborAddress,
			Interface: n.Conf.NeighborInterface,
		})
	case cmdUpdate:
		if err = updateNeighborConfig(n); err != nil {
			return err
		}
		_, err = client.UpdatePeer(ctx, &api.UpdatePeerRequest{
			Peer:          n,
			DoSoftResetIn: true,
		})
	}
	return err
}

func newNeighborCmd() *cobra.Command {

	neighborCmdImpl := &cobra.Command{}

	type cmds struct {
		names []string
		f     func(string, string, []string) error
	}

	c := make([]cmds, 0, 3)
	c = append(c, cmds{[]string{cmdLocal, cmdAdjIn, cmdAdjOut, cmdAccepted, cmdRejected}, showNeighborRib})
	c = append(c, cmds{[]string{cmdReset, cmdSoftReset, cmdSoftResetIn, cmdSoftResetOut}, resetNeighbor})
	c = append(c, cmds{[]string{cmdShutdown, cmdEnable, cmdDisable}, stateChangeNeighbor})

	for _, v := range c {
		f := v.f
		for _, name := range v.names {
			c := &cobra.Command{
				Use: name,
				Run: func(cmd *cobra.Command, args []string) {
					addr := ""
					switch name {
					case cmdReset, cmdSoftReset, cmdSoftResetIn, cmdSoftResetOut, cmdShutdown:
						if args[len(args)-1] == "all" {
							addr = "all"
						}
					}
					if addr == "" {
						l, err := getNeighbors(args[len(args)-1], false)
						if err != nil {
							exitWithError(err)
						}
						addr = l[0].State.NeighborAddress
					}
					err := f(cmd.Use, addr, args[:len(args)-1])
					if err != nil {
						exitWithError(err)
					}
				},
			}
			neighborCmdImpl.AddCommand(c)
			switch name {
			case cmdLocal, cmdAdjIn, cmdAdjOut:
				n := name
				c.AddCommand(&cobra.Command{
					Use: cmdSummary,
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
		Use: cmdPolicy,
		Run: func(cmd *cobra.Command, args []string) {
			l, err := getNeighbors(args[0], false)
			if err != nil {
				exitWithError(err)
			}
			remoteIP := l[0].State.NeighborAddress
			for _, v := range []string{cmdImport, cmdExport} {
				if err := showNeighborPolicy(remoteIP, v, 4); err != nil {
					exitWithError(err)
				}
			}
		},
	}

	for _, v := range []string{cmdImport, cmdExport} {
		cmd := &cobra.Command{
			Use: v,
			Run: func(cmd *cobra.Command, args []string) {
				l, err := getNeighbors(args[0], false)
				if err != nil {
					exitWithError(err)
				}
				remoteIP := l[0].State.NeighborAddress
				err = showNeighborPolicy(remoteIP, cmd.Use, 0)
				if err != nil {
					exitWithError(err)
				}
			},
		}

		for _, w := range []string{cmdAdd, cmdDel, cmdSet} {
			subcmd := &cobra.Command{
				Use: w,
				Run: func(subcmd *cobra.Command, args []string) {
					l, err := getNeighbors(args[len(args)-1], false)
					if err != nil {
						exitWithError(err)
					}
					remoteIP := l[0].State.NeighborAddress
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
		Use: cmdNeighbor,
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

	for _, v := range []string{cmdAdd, cmdDel, cmdUpdate} {
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
