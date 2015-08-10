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
	"fmt"
	"github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/packet"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

func showGlobalRib(args []string) error {
	return showNeighborRib(CMD_GLOBAL, "", args)
}

type ExtCommType int

const (
	ACCEPT ExtCommType = iota
	DISCARD
	RATE
	REDIRECT
	MARK
	ACTION
	RT
)

var ExtCommNameMap = map[ExtCommType]string{
	ACCEPT:   "accept",
	DISCARD:  "discard",
	RATE:     "rate-limit",
	REDIRECT: "redirect",
	MARK:     "mark",
	ACTION:   "action",
	RT:       "rt",
}

var ExtCommValueMap = map[string]ExtCommType{
	ExtCommNameMap[ACCEPT]:   ACCEPT,
	ExtCommNameMap[DISCARD]:  DISCARD,
	ExtCommNameMap[RATE]:     RATE,
	ExtCommNameMap[REDIRECT]: REDIRECT,
	ExtCommNameMap[MARK]:     MARK,
	ExtCommNameMap[ACTION]:   ACTION,
	ExtCommNameMap[RT]:       RT,
}

func rateLimitParser(args []string) ([]bgp.ExtendedCommunityInterface, error) {
	exp := regexp.MustCompile(fmt.Sprintf("^(%s|(%s) (\\d+)(\\.(\\d+))?)( as (\\d+))?$", ExtCommNameMap[DISCARD], ExtCommNameMap[RATE]))
	elems := exp.FindStringSubmatch(strings.Join(args, " "))
	if len(elems) != 8 {
		return nil, fmt.Errorf("invalid rate-limit")
	}
	var rate float32
	var as int
	if elems[2] == ExtCommNameMap[RATE] {
		f, err := strconv.ParseFloat(elems[3]+elems[4], 32)
		if err != nil {
			return nil, err
		}
		rate = float32(f)
	}
	if elems[7] != "" {
		var err error
		as, err = strconv.Atoi(elems[7])
		if err != nil {
			return nil, err
		}
	}
	return []bgp.ExtendedCommunityInterface{bgp.NewTrafficRateExtended(uint16(as), rate)}, nil
}

func redirectParser(args []string) ([]bgp.ExtendedCommunityInterface, error) {
	if len(args) < 2 || args[0] != ExtCommNameMap[REDIRECT] {
		return nil, fmt.Errorf("invalid redirect")
	}
	rt, err := bgp.ParseRouteTarget(strings.Join(args[1:], " "))
	if err != nil {
		return nil, err
	}
	t, _ := rt.GetTypes()
	switch t {
	case bgp.EC_TYPE_TRANSITIVE_TWO_OCTET_AS_SPECIFIC:
		r := rt.(*bgp.TwoOctetAsSpecificExtended)
		return []bgp.ExtendedCommunityInterface{bgp.NewRedirectTwoOctetAsSpecificExtended(r.AS, r.LocalAdmin)}, nil
	case bgp.EC_TYPE_TRANSITIVE_IP4_SPECIFIC:
		r := rt.(*bgp.IPv4AddressSpecificExtended)
		return []bgp.ExtendedCommunityInterface{bgp.NewRedirectIPv4AddressSpecificExtended(r.IPv4.String(), r.LocalAdmin)}, nil
	case bgp.EC_TYPE_TRANSITIVE_FOUR_OCTET_AS_SPECIFIC:
		r := rt.(*bgp.FourOctetAsSpecificExtended)
		return []bgp.ExtendedCommunityInterface{bgp.NewRedirectFourOctetAsSpecificExtended(r.AS, r.LocalAdmin)}, nil
	}
	return nil, fmt.Errorf("invalid redirect")
}

func markParser(args []string) ([]bgp.ExtendedCommunityInterface, error) {
	if len(args) < 2 || args[0] != ExtCommNameMap[MARK] {
		return nil, fmt.Errorf("invalid mark")
	}
	dscp, err := strconv.Atoi(args[1])
	if err != nil {
		return nil, fmt.Errorf("invalid mark")
	}
	return []bgp.ExtendedCommunityInterface{bgp.NewTrafficRemarkExtended(uint8(dscp))}, nil
}

func actionParser(args []string) ([]bgp.ExtendedCommunityInterface, error) {
	if len(args) < 2 || args[0] != ExtCommNameMap[ACTION] {
		return nil, fmt.Errorf("invalid action")
	}
	sample := false
	terminal := false
	switch args[1] {
	case "sample":
		sample = true
	case "terminal":
		terminal = true
	case "terminal-sample", "sample-terminal":
		sample = true
		terminal = true
	default:
		return nil, fmt.Errorf("invalid action")
	}
	return []bgp.ExtendedCommunityInterface{bgp.NewTrafficActionExtended(terminal, sample)}, nil
}

func rtParser(args []string) ([]bgp.ExtendedCommunityInterface, error) {
	if len(args) < 2 || args[0] != ExtCommNameMap[RT] {
		return nil, fmt.Errorf("invalid rt")
	}
	exts := make([]bgp.ExtendedCommunityInterface, 0, len(args[1:]))
	for _, arg := range args[1:] {
		rt, err := bgp.ParseRouteTarget(arg)
		if err != nil {
			return nil, err
		}
		exts = append(exts, rt)
	}
	return exts, nil
}

var ExtCommParserMap = map[ExtCommType]func([]string) ([]bgp.ExtendedCommunityInterface, error){
	ACCEPT:   nil,
	DISCARD:  rateLimitParser,
	RATE:     rateLimitParser,
	REDIRECT: redirectParser,
	MARK:     markParser,
	ACTION:   actionParser,
	RT:       rtParser,
}

func ParseExtendedCommunities(input string) ([]bgp.ExtendedCommunityInterface, error) {
	idxs := make([]struct {
		t ExtCommType
		i int
	}, 0, len(ExtCommNameMap))
	args := strings.Split(input, " ")
	for idx, v := range args {
		if t, ok := ExtCommValueMap[v]; ok {
			idxs = append(idxs, struct {
				t ExtCommType
				i int
			}{t, idx})
		}
	}
	exts := make([]bgp.ExtendedCommunityInterface, 0, len(idxs))
	for i, idx := range idxs {
		var a []string
		f := ExtCommParserMap[idx.t]
		if f == nil {
			continue
		}
		if i < len(idxs)-1 {
			a = args[idx.i:idxs[i+1].i]
		} else {
			a = args[idx.i:]
		}
		ext, err := f(a)
		if err != nil {
			return nil, err
		}
		exts = append(exts, ext...)
	}
	return exts, nil
}

func parseFlowSpecArgs(modtype string, args []string) (bgp.AddrPrefixInterface, string, []string, error) {
	thenPos := len(args)
	for idx, v := range args {
		if v == "then" {
			thenPos = idx
		}
	}
	ss := make([]string, 0, len(bgp.ProtocolNameMap))
	for _, v := range bgp.ProtocolNameMap {
		ss = append(ss, v)
	}
	protos := strings.Join(ss, ", ")
	ss = make([]string, 0, len(bgp.TCPFlagNameMap))
	for _, v := range bgp.TCPFlagNameMap {
		ss = append(ss, v)
	}
	flags := strings.Join(ss, ", ")
	helpErr := fmt.Errorf(`usage: global rib %s match <MATCH_EXPR> then <THEN_EXPR> -a ipv4-flowspec
    <MATCH_EXPR> : { %s <PREFIX> | %s <PREFIX> |
		     %s <PROTO>... | %s <FRAGMENT_TYPE> | %s <TCPFLAG>... |
		     { %s | %s | %s | %s | %s | %s | %s } <ITEM>... }...
	<PROTO> : %s
	<FRAGMENT_TYPE> : not-a-fragment, is-a-fragment, first-fragment, last-fragment
	<TCPFLAG> : %s
	<ITEM> : &?{<|>|=}<value>
    <THEN_EXPR> : { %s | %s | %s <value> | %s <RT> | %s <value> | %s { sample | terminal | sample-terminal } | %s <RT>... }...
	<RT> : xxx:yyy, xx.xx.xx.xx:yyy, xxx.xxx:yyy`, modtype,
		bgp.FlowSpecNameMap[bgp.FLOW_SPEC_TYPE_DST_PREFIX],
		bgp.FlowSpecNameMap[bgp.FLOW_SPEC_TYPE_SRC_PREFIX],
		bgp.FlowSpecNameMap[bgp.FLOW_SPEC_TYPE_IP_PROTO],
		bgp.FlowSpecNameMap[bgp.FLOW_SPEC_TYPE_FRAGMENT],
		bgp.FlowSpecNameMap[bgp.FLOW_SPEC_TYPE_TCP_FLAG],
		bgp.FlowSpecNameMap[bgp.FLOW_SPEC_TYPE_PORT],
		bgp.FlowSpecNameMap[bgp.FLOW_SPEC_TYPE_DST_PORT],
		bgp.FlowSpecNameMap[bgp.FLOW_SPEC_TYPE_SRC_PORT],
		bgp.FlowSpecNameMap[bgp.FLOW_SPEC_TYPE_ICMP_TYPE],
		bgp.FlowSpecNameMap[bgp.FLOW_SPEC_TYPE_ICMP_CODE],
		bgp.FlowSpecNameMap[bgp.FLOW_SPEC_TYPE_PKT_LEN],
		bgp.FlowSpecNameMap[bgp.FLOW_SPEC_TYPE_DSCP],
		protos, flags,
		ExtCommNameMap[ACCEPT], ExtCommNameMap[DISCARD],
		ExtCommNameMap[RATE], ExtCommNameMap[REDIRECT],
		ExtCommNameMap[MARK], ExtCommNameMap[ACTION], ExtCommNameMap[RT])

	if len(args) < 4 || args[0] != "match" || thenPos > len(args)-2 {
		return nil, "", nil, helpErr
	}
	matchArgs := args[1:thenPos]
	cmp, err := bgp.ParseFlowSpecComponents(strings.Join(matchArgs, " "))
	if err != nil {
		return nil, "", nil, fmt.Errorf("%s\n%s", err, helpErr)
	}
	nlri := bgp.NewFlowSpecIPv4Unicast(cmp)
	return nlri, "0.0.0.0", args[thenPos:], nil
}
func parseEvpnArgs(modtype string, args []string) (bgp.AddrPrefixInterface, string, []string, error) {
	if len(args) < 1 {
		return nil, "", nil, fmt.Errorf("usage: global rib %s { macadv | multicast } ... -a evpn", modtype)
	}
	subtype := args[0]
	args = args[1:]

	var nlri bgp.AddrPrefixInterface
	var rts []string

	switch subtype {
	case "macadv":
		if len(args) < 6 || args[4] != "rd" || args[6] != "rt" {
			return nil, "", nil, fmt.Errorf("usage: global rib %s macadv <mac address> <ip address> <etag> <label> rd <rd> rt <rt>... -a evpn", modtype)
		}
		mac, err := net.ParseMAC(args[0])
		if err != nil {
			return nil, "", nil, fmt.Errorf("invalid mac: %s", args[0])
		}
		var ip net.IP
		iplen := 0
		if args[1] != "0.0.0.0" || args[1] != "::" {
			ip = net.ParseIP(args[1])
			if ip == nil {
				return nil, "", nil, fmt.Errorf("invalid ip prefix: %s", args[1])
			}
			iplen = net.IPv4len * 8
			if ip.To4() == nil {
				iplen = net.IPv6len * 8
			}
		}
		eTag, err := strconv.Atoi(args[2])
		if err != nil {
			return nil, "", nil, fmt.Errorf("invalid eTag: %s. err: %s", args[2], err)
		}
		label, err := strconv.Atoi(args[3])
		if err != nil {
			return nil, "", nil, fmt.Errorf("invalid label: %s. err: %s", args[3], err)
		}
		rd, err := bgp.ParseRouteDistinguisher(args[5])
		if err != nil {
			return nil, "", nil, err
		}

		rts = args[6:]

		macIpAdv := &bgp.EVPNMacIPAdvertisementRoute{
			RD: rd,
			ESI: bgp.EthernetSegmentIdentifier{
				Type: bgp.ESI_ARBITRARY,
			},
			MacAddressLength: 48,
			MacAddress:       mac,
			IPAddressLength:  uint8(iplen),
			IPAddress:        ip,
			Labels:           []uint32{uint32(label)},
			ETag:             uint32(eTag),
		}
		nlri = bgp.NewEVPNNLRI(bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT, 0, macIpAdv)
	case "multicast":
		if len(args) < 5 || args[2] != "rd" || args[4] != "rt" {
			return nil, "", nil, fmt.Errorf("usage : global rib %s multicast <ip address> <etag> rd <rd> rt <rt> -a evpn", modtype)
		}

		var ip net.IP
		iplen := 0
		if args[0] != "0.0.0.0" || args[0] != "::" {
			ip = net.ParseIP(args[0])
			if ip == nil {
				return nil, "", nil, fmt.Errorf("invalid ip prefix: %s", args[0])
			}
			iplen = net.IPv4len * 8
			if ip.To4() == nil {
				iplen = net.IPv6len * 8
			}
		}

		eTag, err := strconv.Atoi(args[1])
		if err != nil {
			return nil, "", nil, fmt.Errorf("invalid eTag: %s. err: %s", args[1], err)
		}

		rd, err := bgp.ParseRouteDistinguisher(args[3])
		if err != nil {
			return nil, "", nil, err
		}

		rts = args[4:]

		multicastEtag := &bgp.EVPNMulticastEthernetTagRoute{
			RD:              rd,
			IPAddressLength: uint8(iplen),
			IPAddress:       ip,
			ETag:            uint32(eTag),
		}
		nlri = bgp.NewEVPNNLRI(bgp.EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG, 0, multicastEtag)
	default:
		return nil, "", nil, fmt.Errorf("usage: global rib add { macadv | multicast | ... -a evpn")
	}
	return nlri, "0.0.0.0", rts, nil
}

func modPath(modtype string, args []string) error {
	rf, err := checkAddressFamily(net.IP{})
	if err != nil {
		return err
	}

	var nlri bgp.AddrPrefixInterface
	var nexthop string
	var extcomms []string

	switch rf {
	case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
		if len(args) != 1 {
			return fmt.Errorf("usage: global rib %s <prefix> -a { ipv4 | ipv6 }", modtype)
		}
		ip, net, _ := net.ParseCIDR(args[0])
		if rf == bgp.RF_IPv4_UC {
			if ip.To4() == nil {
				return fmt.Errorf("invalid ipv4 prefix")
			}
			nexthop = "0.0.0.0"
			ones, _ := net.Mask.Size()
			nlri = bgp.NewNLRInfo(uint8(ones), ip.String())
		} else {
			if ip.To16() == nil {
				return fmt.Errorf("invalid ipv6 prefix")
			}
			nexthop = "::"
			ones, _ := net.Mask.Size()
			nlri = bgp.NewIPv6AddrPrefix(uint8(ones), ip.String())
		}
	case bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN:
		if len(args) < 3 || args[1] != "rd" || args[3] != "rt" {
			return fmt.Errorf("usage: global rib %s <prefix> rd <rd> rt <rt>... -a { vpn-ipv4 | vpn-ipv6 }", modtype)
		}
		ip, net, _ := net.ParseCIDR(args[0])
		ones, _ := net.Mask.Size()

		rd, err := bgp.ParseRouteDistinguisher(args[2])
		if err != nil {
			return err
		}

		extcomms = args[3:]

		mpls := bgp.NewMPLSLabelStack()

		if rf == bgp.RF_IPv4_VPN {
			if ip.To4() == nil {
				return fmt.Errorf("invalid ipv4 prefix")
			}
			nexthop = "0.0.0.0"
			nlri = bgp.NewLabeledVPNIPAddrPrefix(uint8(ones), ip.String(), *mpls, rd)
		} else {
			if ip.To16() == nil {
				return fmt.Errorf("invalid ipv6 prefix")
			}
			nexthop = "::"
			nlri = bgp.NewLabeledVPNIPv6AddrPrefix(uint8(ones), ip.String(), *mpls, rd)
		}

	case bgp.RF_EVPN:
		nlri, nexthop, extcomms, err = parseEvpnArgs(modtype, args)
		if err != nil {
			return err
		}
	case bgp.RF_FS_IPv4_UC:
		nlri, nexthop, extcomms, err = parseFlowSpecArgs(modtype, args)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("Unsupported route family: %s", rf)
	}

	arg := &api.ModPathArguments{
		Resource:  api.Resource_GLOBAL,
		RawPattrs: make([][]byte, 0),
	}

	switch modtype {
	case CMD_ADD:
		arg.IsWithdraw = false
	case CMD_DEL:
		arg.IsWithdraw = true
	}

	if rf == bgp.RF_IPv4_UC {
		arg.RawNlri, _ = nlri.Serialize()
		n, _ := bgp.NewPathAttributeNextHop(nexthop).Serialize()
		arg.RawPattrs = append(arg.RawPattrs, n)
	} else {
		mpreach, _ := bgp.NewPathAttributeMpReachNLRI(nexthop, []bgp.AddrPrefixInterface{nlri}).Serialize()
		arg.RawPattrs = append(arg.RawPattrs, mpreach)
	}

	origin, _ := bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP).Serialize()
	arg.RawPattrs = append(arg.RawPattrs, origin)

	if extcomms != nil && len(extcomms) > 0 {
		extcomms, err := ParseExtendedCommunities(strings.Join(extcomms, " "))
		if err != nil {
			return err
		}
		p := bgp.NewPathAttributeExtendedCommunities(extcomms)
		buf, err := p.Serialize()
		if err != nil {
			return err
		}
		arg.RawPattrs = append(arg.RawPattrs, buf)
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

	res, e := stream.CloseAndRecv()
	if e != nil {
		return e
	}
	if res.Code != api.Error_SUCCESS {
		return fmt.Errorf("error: code: %d, msg: %s", res.Code, res.Msg)
	}
	return nil
}

func NewGlobalCmd() *cobra.Command {
	globalCmd := &cobra.Command{
		Use: CMD_GLOBAL,
	}

	ribCmd := &cobra.Command{
		Use: CMD_RIB,
		Run: func(cmd *cobra.Command, args []string) {
			showGlobalRib(args)
		},
	}

	ribCmd.PersistentFlags().StringVarP(&subOpts.AddressFamily, "address-family", "a", "", "address family")

	addCmd := &cobra.Command{
		Use: CMD_ADD,
		Run: func(cmd *cobra.Command, args []string) {
			err := modPath(CMD_ADD, args)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}

	delCmd := &cobra.Command{
		Use: CMD_DEL,
		Run: func(cmd *cobra.Command, args []string) {
			err := modPath(CMD_DEL, args)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}

	ribCmd.AddCommand(addCmd, delCmd)
	globalCmd.AddCommand(ribCmd)
	return globalCmd
}
