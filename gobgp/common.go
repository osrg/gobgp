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
	"fmt"
	"github.com/osrg/gobgp/api"
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
	CMD_ROUTEPOLICY    = "routepolicy"
	CMD_CONDITIONS     = "conditions"
	CMD_ACTIONS        = "actions"
	CMD_IMPORT         = "import"
	CMD_EXPORT         = "export"
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
	AsPathLength string `long:"aspath-len" description:"specifying an as path length of policy (<operator>,<numeric>)"`
	Option       string `long:"option" description:"specifying an option of policy (any | all | invert)"`
}

var actionOpts struct {
	RouteAction string `long:"route-action" description:"specifying a route action of policy (accept | reject)"`
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

var client api.GrpcClient

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

func requestGrpc(cmd string, eArgs []string, request interface{}) error {
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
		return showNeighborRib(api.Resource_LOCAL, request.(*NeighborRibCommand))
	case CMD_NEIGHBOR + "_" + CMD_ADJ_IN:
		return showNeighborRib(api.Resource_ADJ_IN, request.(*NeighborRibCommand))
	case CMD_NEIGHBOR + "_" + CMD_ADJ_OUT:
		return showNeighborRib(api.Resource_ADJ_OUT, request.(*NeighborRibCommand))
	case CMD_NEIGHBOR + "_" + CMD_RESET:
		return resetNeighbor(request.(*NeighborResetCommand))
	case CMD_NEIGHBOR + "_" + CMD_SOFT_RESET:
		return resetNeighbor(request.(*NeighborResetCommand))
	case CMD_NEIGHBOR + "_" + CMD_SOFT_RESET_IN:
		return resetNeighbor(request.(*NeighborResetCommand))
	case CMD_NEIGHBOR + "_" + CMD_SOFT_RESET_OUT:
		return resetNeighbor(request.(*NeighborResetCommand))
	case CMD_NEIGHBOR + "_" + CMD_SHUTDOWN:
		return stateChangeNeighbor(request.(*NeighborChangeStateCommand))
	case CMD_NEIGHBOR + "_" + CMD_ENABLE:
		return stateChangeNeighbor(request.(*NeighborChangeStateCommand))
	case CMD_NEIGHBOR + "_" + CMD_DISABLE:
		return stateChangeNeighbor(request.(*NeighborChangeStateCommand))
	case CMD_NEIGHBOR + "_" + CMD_POLICY:
		return showNeighborPolicy(request.(*NeighborPolicyCommand))
	case CMD_NEIGHBOR + "_" + CMD_POLICY + "_" + CMD_ADD:
		return modNeighborPolicy(eArgs, request.(*NeighborPolicyChangeCommand))
	case CMD_NEIGHBOR + "_" + CMD_POLICY + "_" + CMD_DEL:
		return modNeighborPolicy(eArgs, request.(*NeighborPolicyChangeCommand))
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
	case CMD_POLICY + "_" + CMD_ROUTEPOLICY + "_" + CMD_ADD + "_" + CMD_CONDITIONS:
		return modPolicyRoutePolicy(CMD_ADD, CMD_CONDITIONS, eArgs, request)
	case CMD_POLICY + "_" + CMD_ROUTEPOLICY + "_" + CMD_ADD + "_" + CMD_ACTIONS:
		return modPolicyRoutePolicy(CMD_ADD, CMD_ACTIONS, eArgs, request)
	case CMD_POLICY + "_" + CMD_ROUTEPOLICY + "_" + CMD_DEL:
		return modPolicyRoutePolicy(CMD_DEL, "", eArgs, nil)
	}
	return nil
}

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
