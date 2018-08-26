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
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/pkg/packet/bgp"
)

const GLOBAL_RIB_NAME = "global"

const (
	CMD_GLOBAL         = "global"
	CMD_NEIGHBOR       = "neighbor"
	CMD_POLICY         = "policy"
	CMD_RIB            = "rib"
	CMD_ADD            = "add"
	CMD_DEL            = "del"
	CMD_ALL            = "all"
	CMD_SET            = "set"
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
	CMD_ASPATH         = "as-path"
	CMD_COMMUNITY      = "community"
	CMD_EXTCOMMUNITY   = "ext-community"
	CMD_IMPORT         = "import"
	CMD_EXPORT         = "export"
	CMD_IN             = "in"
	CMD_MONITOR        = "monitor"
	CMD_MRT            = "mrt"
	CMD_DUMP           = "dump"
	CMD_INJECT         = "inject"
	CMD_RPKI           = "rpki"
	CMD_RPKI_TABLE     = "table"
	CMD_RPKI_SERVER    = "server"
	CMD_VRF            = "vrf"
	CMD_ACCEPTED       = "accepted"
	CMD_REJECTED       = "rejected"
	CMD_STATEMENT      = "statement"
	CMD_CONDITION      = "condition"
	CMD_ACTION         = "action"
	CMD_UPDATE         = "update"
	CMD_ROTATE         = "rotate"
	CMD_BMP            = "bmp"
	CMD_LARGECOMMUNITY = "large-community"
	CMD_SUMMARY        = "summary"
	CMD_VALIDATION     = "validation"
)

const (
	PARAM_FLAG = iota
	PARAM_SINGLE
	PARAM_LIST
)

var subOpts struct {
	AddressFamily string `short:"a" long:"address-family" description:"specifying an address family"`
}

var neighborsOpts struct {
	Reason    string `short:"r" long:"reason" description:"specifying communication field on Cease NOTIFICATION message with Administrative Shutdown subcode"`
	Transport string `short:"t" long:"transport" description:"specifying a transport protocol"`
}

var mrtOpts struct {
	OutputDir   string
	FileFormat  string
	Filename    string `long:"filename" description:"MRT file name"`
	RecordCount int64  `long:"count" description:"Number of records to inject"`
	RecordSkip  int64  `long:"skip" description:"Number of records to skip before injecting"`
	QueueSize   int    `long:"batch-size" description:"Maximum number of updates to keep queued"`
	Best        bool   `long:"only-best" description:"only keep best path routes"`
	SkipV4      bool   `long:"no-ipv4" description:"Skip importing IPv4 routes"`
	SkipV6      bool   `long:"no-ipv4" description:"Skip importing IPv6 routes"`
	NextHop     net.IP `long:"nexthop" description:"Rewrite nexthop"`
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
	}
	return fmt.Sprintf("%dd ", days) + fmt.Sprintf("%02d:%02d:%02d", hours, mins, secs)
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

func extractReserved(args []string, keys map[string]int) (map[string][]string, error) {
	m := make(map[string][]string, len(keys))
	var k string
	isReserved := func(s string) bool {
		for r := range keys {
			if s == r {
				return true
			}
		}
		return false
	}
	for _, arg := range args {
		if isReserved(arg) {
			k = arg
			m[k] = make([]string, 0, 1)
		} else {
			m[k] = append(m[k], arg)
		}
	}
	for k, v := range m {
		if k == "" {
			continue
		}
		switch keys[k] {
		case PARAM_FLAG:
			if len(v) != 0 {
				return nil, fmt.Errorf("%s should not have arguments", k)
			}
		case PARAM_SINGLE:
			if len(v) != 1 {
				return nil, fmt.Errorf("%s should have one argument", k)
			}
		case PARAM_LIST:
			if len(v) == 0 {
				return nil, fmt.Errorf("%s should have one or more arguments", k)
			}
		}
	}
	return m, nil
}

func newClient(ctx context.Context) (api.GobgpApiClient, error) {
	grpcOpts := []grpc.DialOption{grpc.WithTimeout(time.Second), grpc.WithBlock()}
	if globalOpts.TLS {
		var creds credentials.TransportCredentials
		if globalOpts.CaFile == "" {
			creds = credentials.NewClientTLSFromCert(nil, "")
		} else {
			var err error
			creds, err = credentials.NewClientTLSFromFile(globalOpts.CaFile, "")
			if err != nil {
				exitWithError(err)
			}
		}
		grpcOpts = append(grpcOpts, grpc.WithTransportCredentials(creds))
	} else {
		grpcOpts = append(grpcOpts, grpc.WithInsecure())
	}

	target := net.JoinHostPort(globalOpts.Host, strconv.Itoa(globalOpts.Port))
	if target == "" {
		target = ":50051"
	}

	conn, err := grpc.DialContext(ctx, target, grpcOpts...)
	if err != nil {
		return nil, err
	}
	return api.NewGobgpApiClient(conn), nil
}

func addr2AddressFamily(a net.IP) *api.Family {
	if a.To4() != nil {
		return &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_UNICAST,
		}
	} else if a.To16() != nil {
		return &api.Family{
			Afi:  api.Family_AFI_IP6,
			Safi: api.Family_SAFI_UNICAST,
		}
	}
	return nil
}

var (
	IPv4_UC = &api.Family{
		Afi:  api.Family_AFI_IP,
		Safi: api.Family_SAFI_UNICAST,
	}
	IPv6_UC = &api.Family{
		Afi:  api.Family_AFI_IP6,
		Safi: api.Family_SAFI_UNICAST,
	}
	IPv4_VPN = &api.Family{
		Afi:  api.Family_AFI_IP,
		Safi: api.Family_SAFI_MPLS_VPN,
	}
	IPv6_VPN = &api.Family{
		Afi:  api.Family_AFI_IP6,
		Safi: api.Family_SAFI_MPLS_VPN,
	}
	IPv4_MPLS = &api.Family{
		Afi:  api.Family_AFI_IP,
		Safi: api.Family_SAFI_MPLS_LABEL,
	}
	IPv6_MPLS = &api.Family{
		Afi:  api.Family_AFI_IP6,
		Safi: api.Family_SAFI_MPLS_LABEL,
	}
	EVPN = &api.Family{
		Afi:  api.Family_AFI_L2VPN,
		Safi: api.Family_SAFI_EVPN,
	}
	IPv4_ENCAP = &api.Family{
		Afi:  api.Family_AFI_IP,
		Safi: api.Family_SAFI_ENCAPSULATION,
	}
	IPv6_ENCAP = &api.Family{
		Afi:  api.Family_AFI_IP6,
		Safi: api.Family_SAFI_ENCAPSULATION,
	}
	RTC = &api.Family{
		Afi:  api.Family_AFI_IP,
		Safi: api.Family_SAFI_ROUTE_TARGET_CONSTRAINTS,
	}
	IPv4_FS = &api.Family{
		Afi:  api.Family_AFI_IP,
		Safi: api.Family_SAFI_FLOW_SPEC_UNICAST,
	}
	IPv6_FS = &api.Family{
		Afi:  api.Family_AFI_IP6,
		Safi: api.Family_SAFI_FLOW_SPEC_UNICAST,
	}
	IPv4_VPN_FS = &api.Family{
		Afi:  api.Family_AFI_IP,
		Safi: api.Family_SAFI_FLOW_SPEC_VPN,
	}
	IPv6_VPN_FS = &api.Family{
		Afi:  api.Family_AFI_IP6,
		Safi: api.Family_SAFI_FLOW_SPEC_VPN,
	}
	L2_VPN_FS = &api.Family{
		Afi:  api.Family_AFI_L2VPN,
		Safi: api.Family_SAFI_FLOW_SPEC_VPN,
	}
	OPAQUE = &api.Family{
		Afi:  api.Family_AFI_OPAQUE,
		Safi: api.Family_SAFI_KEY_VALUE,
	}
)

func checkAddressFamily(def *api.Family) (*api.Family, error) {
	var f *api.Family
	var e error
	switch subOpts.AddressFamily {
	case "ipv4", "v4", "4":
		f = IPv4_UC
	case "ipv6", "v6", "6":
		f = IPv6_UC
	case "ipv4-l3vpn", "vpnv4", "vpn-ipv4":
		f = IPv4_VPN
	case "ipv6-l3vpn", "vpnv6", "vpn-ipv6":
		f = IPv6_VPN
	case "ipv4-labeled", "ipv4-labelled", "ipv4-mpls":
		f = IPv4_MPLS
	case "ipv6-labeled", "ipv6-labelled", "ipv6-mpls":
		f = IPv6_MPLS
	case "evpn":
		f = EVPN
	case "encap", "ipv4-encap":
		f = IPv4_ENCAP
	case "ipv6-encap":
		f = IPv6_ENCAP
	case "rtc":
		f = RTC
	case "ipv4-flowspec", "ipv4-flow", "flow4":
		f = IPv4_FS
	case "ipv6-flowspec", "ipv6-flow", "flow6":
		f = IPv6_FS
	case "ipv4-l3vpn-flowspec", "ipv4vpn-flowspec", "flowvpn4":
		f = IPv4_VPN_FS
	case "ipv6-l3vpn-flowspec", "ipv6vpn-flowspec", "flowvpn6":
		f = IPv6_VPN_FS
	case "l2vpn-flowspec":
		f = L2_VPN_FS
	case "opaque":
		f = OPAQUE
	case "":
		f = def
	default:
		e = fmt.Errorf("unsupported address family: %s", subOpts.AddressFamily)
	}
	return f, e
}

func printError(err error) {
	if globalOpts.Json {
		j, _ := json.Marshal(struct {
			Error string `json:"error"`
		}{Error: err.Error()})
		fmt.Println(string(j))
	} else {
		fmt.Println(err)
	}
}

func exitWithError(err error) {
	printError(err)
	os.Exit(1)
}

func getNextHopFromPathAttributes(attrs []bgp.PathAttributeInterface) net.IP {
	for _, attr := range attrs {
		switch a := attr.(type) {
		case *bgp.PathAttributeNextHop:
			return a.Value
		case *bgp.PathAttributeMpReachNLRI:
			return a.Nexthop
		}
	}
	return nil
}
