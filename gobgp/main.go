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
	"encoding/json"
	"fmt"
	"github.com/jessevdk/go-flags"
	"github.com/parnurzeal/gorequest"
	"net"
	"os"
	"sort"
)

func execute(resource string, callback func(url string, r *gorequest.SuperAgent) *gorequest.SuperAgent) []byte {
	r := gorequest.New()
	url := globalOpts.URL + ":" + fmt.Sprint(globalOpts.Port) + "/v1/bgp/" + resource
	if globalOpts.Debug {
		fmt.Println(url)
	}
	r = callback(url, r)
	_, body, err := r.End()
	if err != nil {
		fmt.Print("Failed to connect to gobgpd. It runs?\n")
		if globalOpts.Debug {
			fmt.Println(err)
		}
		os.Exit(1)
	}
	if globalOpts.Debug {
		fmt.Println(body)
	}
	return []byte(body)
}

func post(resource string) []byte {
	f := func(url string, r *gorequest.SuperAgent) *gorequest.SuperAgent {
		return r.Post(url)
	}
	return execute(resource, f)
}

func get(resource string) []byte {
	f := func(url string, r *gorequest.SuperAgent) *gorequest.SuperAgent {
		return r.Get(url)
	}
	return execute(resource, f)
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
	hours := u % 60
	days := u / 24

	if days == 0 {
		return fmt.Sprintf("%02d:%02d:%02d", hours, mins, secs)
	} else {
		hours -= days * 24
		return fmt.Sprintf("%dd ", days) + fmt.Sprintf("%02d:%02d:%02d", hours, mins, secs)
	}
}

type PeerConf struct {
	RemoteIP           string `json:"remote_ip"`
	Id                 string `json:"id"`
	RemoteAS           uint32 `json:"remote_as"`
	CapRefresh         bool   `json:"cap_refresh"`
	CapEnhancedRefresh bool   `json:"cap_enhanced_refresh"`
	RemoteCap          []int
	LocalCap           []int
}

type PeerInfo struct {
	BgpState                  string `json:"bgp_state"`
	AdminState                string
	FsmEstablishedTransitions uint32 `json:"fsm_established_transitions"`
	TotalMessageOut           uint32 `json:"total_message_out"`
	TotalMessageIn            uint32 `json:"total_message_in"`
	UpdateMessageOut          uint32 `json:"update_message_out"`
	UpdateMessageIn           uint32 `json:"update_message_in"`
	KeepAliveMessageOut       uint32 `json:"keepalive_message_out"`
	KeepAliveMessageIn        uint32 `json:"keepalive_message_in"`
	OpenMessageOut            uint32 `json:"open_message_out"`
	OpenMessageIn             uint32 `json:"open_message_in"`
	NotificationOut           uint32 `json:"notification_out"`
	NotificationIn            uint32 `json:"notification_in"`
	RefreshMessageOut         uint32 `json:"refresh_message_out"`
	RefreshMessageIn          uint32 `json:"refresh_message_in"`
	DiscardedOut              uint32
	DiscardedIn               uint32
	Uptime                    int64  `json:"uptime"`
	Downtime                  int64  `json:"downtime"`
	LastError                 string `json:"last_error"`
	Received                  uint32
	Accepted                  uint32
	Advertized                uint32
	OutQ                      int
	Flops                     uint32
}

type peer struct {
	Conf PeerConf
	Info PeerInfo
}

type ShowNeighborCommand struct {
}

func showNeighbor(args []string) {
	p := peer{}
	b := get("neighbor/" + args[0])
	e := json.Unmarshal(b, &p)
	if e != nil {
		fmt.Println(e)
	} else {
		fmt.Printf("BGP neighbor is %s, remote AS %d\n", p.Conf.RemoteIP, p.Conf.RemoteAS)
		fmt.Printf("  BGP version 4, remote router ID %s\n", p.Conf.Id)
		fmt.Printf("  BGP state = %s, up for %s\n", p.Info.BgpState, formatTimedelta(p.Info.Uptime))
		fmt.Printf("  BGP OutQ = %d, Flops = %d\n", p.Info.OutQ, p.Info.Flops)
		fmt.Printf("  Neighbor capabilities:\n")
		caps := []int{}
		lookup := func(val int, l []int) bool {
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

		sort.Sort(sort.IntSlice(caps))
		capdict := map[int]string{1: "MULTIPROTOCOL",
			2:   "ROUTE_REFRESH",
			4:   "CARRYING_LABEL_INFO",
			64:  "GRACEFUL_RESTART",
			65:  "FOUR_OCTET_AS_NUMBER",
			70:  "ENHANCED_ROUTE_REFRESH",
			128: "ROUTE_REFRESH_CISCO"}
		for _, c := range caps {
			k, found := capdict[c]
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
	}
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
		parser.AddCommand("local", "", "", NewShowNeighborRibCommand(args[0], "local-rib"))
		parser.AddCommand("adj-in", "", "", NewShowNeighborRibCommand(args[0], "adj-rib-in"))
		parser.AddCommand("adj-out", "", "", NewShowNeighborRibCommand(args[0], "adj-rib-out"))
		if _, err := parser.ParseArgs(args[1:]); err != nil {
			os.Exit(1)
		}
	}
	return nil
}

type ShowNeighborRibCommand struct {
	remoteIP net.IP
	resource string
}

type path struct {
	Network string
	Nexthop string
	Age     float64
	Attrs   []map[string]interface{}
	best    bool
}

func showRoute(pathList []path, showAge bool, showBest bool) {
	var format string
	if showAge {
		format = "%-2s %-18s %-15s %-10s %-10s %-s\n"
		fmt.Printf(format, "", "Network", "Next Hop", "AS_PATH", "Age", "Attrs")
	} else {
		format = "%-2s %-18s %-15s %-10s %-s\n"
		fmt.Printf(format, "", "Network", "Next Hop", "AS_PATH", "Attrs")
	}

	for _, p := range pathList {
		aspath := func(attrs []map[string]interface{}) string {
			for _, a := range attrs {
				if a["Type"] == "BGP_ATTR_TYPE_AS_PATH" {
					return fmt.Sprint(a["AsPath"])
				}
			}
			return ""
		}
		formatAttrs := func(attrs []map[string]interface{}) string {
			s := []string{}
			for _, a := range attrs {
				switch a["Type"] {
				case "BGP_ATTR_TYPE_ORIGIN":
					s = append(s, fmt.Sprintf("{Origin: %v}", a["Value"]))
				case "BGP_ATTR_TYPE_MULTI_EXIT_DISC":
					s = append(s, fmt.Sprintf("{Med: %v}", a["Metric"]))
				case "BGP_ATTR_TYPE_LOCAL_PREF":
					s = append(s, fmt.Sprintf("{LocalPref: %v}", a["Pref"]))
				case "BGP_ATTR_TYPE_ATOMIC_AGGREGATE":
					s = append(s, "AtomicAggregate")
				case "BGP_ATTR_TYPE_AGGREGATE":
					s = append(s, fmt.Sprintf("{Aggregate: {AS: %v, Address: %v}", a["AS"], a["Address"]))
				case "BGP_ATTR_TYPE_COMMUNITIES":
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

					for _, vv := range a["Value"].([]interface{}) {
						v := uint32(vv.(float64))
						k, found := known[v]
						if found {
							l = append(l, fmt.Sprint(k))
						} else {
							l = append(l, fmt.Sprintf("%d:%d", (0xffff0000&v)>>16, 0xffff&v))
						}
					}
					s = append(s, fmt.Sprintf("{Cummunity: %v}", l))
				case "BGP_ATTR_TYPE_ORIGINATOR_ID":
					s = append(s, fmt.Sprintf("{Originator: %v|", a["Address"]))
				case "BGP_ATTR_TYPE_CLUSTER_LIST":
					s = append(s, fmt.Sprintf("{Cluster: %v|", a["Address"]))
				case "BGP_ATTR_TYPE_AS4_PATH", "BGP_ATTR_TYPE_MP_UNREACH_NLRI", "BGP_ATTR_TYPE_MP_REACH_NLRI", "BGP_ATTR_TYPE_NEXT_HOP", "BGP_ATTR_TYPE_AS_PATH":
				default:
					s = append(s, fmt.Sprintf("{%v: %v}", a["Type"], a["Value"]))
				}
			}
			return fmt.Sprint(s)
		}
		best := ""
		if showBest {
			if p.best {
				best = "*>"
			} else {
				best = "* "
			}
		}
		if showAge {
			fmt.Printf(format, best, p.Network, p.Nexthop, aspath(p.Attrs), formatTimedelta(int64(p.Age)), formatAttrs(p.Attrs))
		} else {
			fmt.Printf(format, best, p.Network, p.Nexthop, aspath(p.Attrs), formatAttrs(p.Attrs))
		}
	}
}

func showRibCommand(isAdj, showAge, showBest bool, b []byte) {
	type dest struct {
		Prefix      string
		Paths       []path
		BestPathIdx int
	}
	type local struct {
		Destinations []dest
	}

	m := []path{}
	var e error
	if isAdj == false {
		l := local{}
		e = json.Unmarshal(b, &l)
		if e == nil {
			for _, d := range l.Destinations {
				for i, p := range d.Paths {
					if i == d.BestPathIdx {
						p.best = true
					}
					m = append(m, p)
				}
			}
		}
	} else {
		e = json.Unmarshal(b, &m)
	}
	if e != nil {
		return
	}
	showRoute(m, showAge, showBest)
}

func (x *ShowNeighborRibCommand) Execute(args []string) error {
	var rt string
	if len(args) == 0 {
		if x.remoteIP.To4() != nil {
			rt = "ipv4"
		} else {
			rt = "ipv6"
		}
	} else {
		rt = args[0]
	}
	b := get("neighbor/" + x.remoteIP.String() + "/" + x.resource + "/" + rt)

	isAdj := false
	showBest := false
	showAge := true
	if x.resource == "adj-rib-out" || x.resource == "adj-rib-in" {
		isAdj = true
		if x.resource == "adj-rib-out" {
			showAge = false
		}
	}
	if x.resource == "local-rib" {
		showBest = true
	}
	showRibCommand(isAdj, showAge, showBest, b)
	return nil
}

func NewShowNeighborRibCommand(addr, resource string) *ShowNeighborRibCommand {
	return &ShowNeighborRibCommand{
		remoteIP: net.ParseIP(addr),
		resource: resource,
	}
}

type ShowNeighborsCommand struct {
}

func (x *ShowNeighborsCommand) Execute(args []string) error {
	m := []peer{}
	b := get("neighbors")
	e := json.Unmarshal(b, &m)
	if e != nil {
		fmt.Println(e)
	} else {
		if globalOpts.Quiet {
			for _, p := range m {
				fmt.Println(p.Conf.RemoteIP)
			}
			return nil
		}
		maxaddrlen := 0
		maxaslen := 0
		maxtimelen := len("Up/Down")
		timedelta := []string{}
		for _, p := range m {
			if len(p.Conf.RemoteIP) > maxaddrlen {
				maxaddrlen = len(p.Conf.RemoteIP)
			}

			if len(fmt.Sprint(p.Conf.RemoteAS)) > maxaslen {
				maxaslen = len(fmt.Sprint(p.Conf.RemoteAS))
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
			fmt.Printf(format, p.Conf.RemoteIP, fmt.Sprint(p.Conf.RemoteAS), timedelta[i], format_fsm(p.Info.AdminState, p.Info.BgpState), fmt.Sprint(p.Info.Advertized), fmt.Sprint(p.Info.Received), fmt.Sprint(p.Info.Accepted))
		}
	}

	return nil
}

type ShowGlobalCommand struct {
}

func (x *ShowGlobalCommand) Execute(args []string) error {
	var rt string
	if len(args) == 0 {
		rt = "ipv4"
	} else {
		rt = args[0]
	}
	b := get("global/rib/" + rt)
	showRibCommand(false, true, true, b)
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
	if len(args) != 2 {
		return nil
	}
	post("neighbor/" + args[1] + "/" + x.resource)
	return nil
}

func NewResetCommand(resource string) *ResetCommand {
	return &ResetCommand{
		resource: resource,
	}
}

var globalOpts struct {
	URL   string `short:"u" long:"url" description:"specifying an url" default:"http://127.0.0.1"`
	Port  int    `short:"p" long:"port" description:"specifying a port" default:"8080"`
	Debug bool   `short:"d" long:"debug"`
	Quiet bool   `short:"q" long:"quiet"`
}

func main() {
	parser := flags.NewParser(&globalOpts, flags.Default)
	parser.AddCommand("show", "show stuff", "get information", &ShowCommand{})
	parser.AddCommand("reset", "show stuff", "get information", NewResetCommand("reset"))
	parser.AddCommand("softreset", "show stuff", "get information", NewResetCommand("softreset"))
	parser.AddCommand("softresetin", "show stuff", "get information", NewResetCommand("softresetin"))
	parser.AddCommand("softresetout", "show stuff", "get information", NewResetCommand("softresetout"))
	parser.AddCommand("shutdown", "show stuff", "get information", NewResetCommand("shutdown"))
	parser.AddCommand("enable", "show stuff", "get information", NewResetCommand("enable"))
	parser.AddCommand("disable", "show stuff", "get information", NewResetCommand("disable"))

	if _, err := parser.Parse(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
