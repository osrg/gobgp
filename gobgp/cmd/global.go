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
	"fmt"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/packet"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type ExtCommType int

const (
	ACCEPT ExtCommType = iota
	DISCARD
	RATE
	REDIRECT
	MARK
	ACTION
	RT
	ENCAP
)

var ExtCommNameMap = map[ExtCommType]string{
	ACCEPT:   "accept",
	DISCARD:  "discard",
	RATE:     "rate-limit",
	REDIRECT: "redirect",
	MARK:     "mark",
	ACTION:   "action",
	RT:       "rt",
	ENCAP:    "encap",
}

var ExtCommValueMap = map[string]ExtCommType{
	ExtCommNameMap[ACCEPT]:   ACCEPT,
	ExtCommNameMap[DISCARD]:  DISCARD,
	ExtCommNameMap[RATE]:     RATE,
	ExtCommNameMap[REDIRECT]: REDIRECT,
	ExtCommNameMap[MARK]:     MARK,
	ExtCommNameMap[ACTION]:   ACTION,
	ExtCommNameMap[RT]:       RT,
	ExtCommNameMap[ENCAP]:    ENCAP,
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

func encapParser(args []string) ([]bgp.ExtendedCommunityInterface, error) {
	if len(args) < 2 || args[0] != ExtCommNameMap[ENCAP] {
		return nil, fmt.Errorf("invalid encap")
	}
	var typ bgp.TunnelType
	switch args[1] {
	case "l2tpv3":
		typ = bgp.TUNNEL_TYPE_L2TP3
	case "gre":
		typ = bgp.TUNNEL_TYPE_GRE
	case "ip-in-ip":
		typ = bgp.TUNNEL_TYPE_IP_IN_IP
	case "vxlan":
		typ = bgp.TUNNEL_TYPE_VXLAN
	case "nvgre":
		typ = bgp.TUNNEL_TYPE_NVGRE
	case "mpls":
		typ = bgp.TUNNEL_TYPE_MPLS
	case "mpls-in-gre":
		typ = bgp.TUNNEL_TYPE_MPLS_IN_GRE
	case "vxlan-gre":
		typ = bgp.TUNNEL_TYPE_VXLAN_GRE
	default:
		return nil, fmt.Errorf("invalid encap type")
	}
	isTransitive := true
	o := bgp.NewOpaqueExtended(isTransitive)
	o.SubType = bgp.EC_SUBTYPE_ENCAPSULATION
	o.Value = &bgp.EncapExtended{typ}
	return []bgp.ExtendedCommunityInterface{o}, nil
}

var ExtCommParserMap = map[ExtCommType]func([]string) ([]bgp.ExtendedCommunityInterface, error){
	ACCEPT:   nil,
	DISCARD:  rateLimitParser,
	RATE:     rateLimitParser,
	REDIRECT: redirectParser,
	MARK:     markParser,
	ACTION:   actionParser,
	RT:       rtParser,
	ENCAP:    encapParser,
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

func ParseFlowSpecArgs(rf bgp.RouteFamily, args []string) (bgp.AddrPrefixInterface, []string, error) {
	thenPos := len(args)
	for idx, v := range args {
		if v == "then" {
			thenPos = idx
		}
	}
	if len(args) < 4 || args[0] != "match" || thenPos > len(args)-2 {
		return nil, nil, fmt.Errorf("invalid format")
	}
	matchArgs := args[1:thenPos]
	cmp, err := bgp.ParseFlowSpecComponents(rf, strings.Join(matchArgs, " "))
	if err != nil {
		return nil, nil, err
	}
	var nlri bgp.AddrPrefixInterface
	switch rf {
	case bgp.RF_FS_IPv4_UC:
		nlri = bgp.NewFlowSpecIPv4Unicast(cmp)
	case bgp.RF_FS_IPv6_UC:
		nlri = bgp.NewFlowSpecIPv6Unicast(cmp)
	default:
		return nil, nil, fmt.Errorf("invalid route family")
	}
	return nlri, args[thenPos:], nil
}

func ParseEvpnMacAdvArgs(args []string) (bgp.AddrPrefixInterface, []string, error) {
	if len(args) < 4 {
		return nil, nil, fmt.Errorf("lack of number of args needs 4 but %d", len(args))
	}
	var nlri bgp.AddrPrefixInterface
	var ip net.IP
	iplen := 0

	mac, err := net.ParseMAC(args[0])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid mac: %s", args[0])
	}
	if args[1] != "0.0.0.0" && args[1] != "::" {
		ip = net.ParseIP(args[1])
		if ip == nil {
			return nil, nil, fmt.Errorf("invalid ip prefix: %s", args[1])
		}
		iplen = net.IPv4len * 8
		if ip.To4() == nil {
			iplen = net.IPv6len * 8
		}
	}
	eTag, err := strconv.Atoi(args[2])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid eTag: %s. err: %s", args[2], err)
	}
	label, err := strconv.Atoi(args[3])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid label: %s. err: %s", args[3], err)
	}

	var rd bgp.RouteDistinguisherInterface
	if args[4] == "rd" && len(args) > 5 {
		rd, err = bgp.ParseRouteDistinguisher(args[5])
		if err != nil {
			return nil, nil, err
		}
	}

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
	extcomms := args[6:]
	return nlri, extcomms, nil
}

func ParseEvpnMulticastArgs(args []string) (bgp.AddrPrefixInterface, []string, error) {
	if len(args) < 2 {
		return nil, nil, fmt.Errorf("lack of number of args needs 2 but %d", len(args))
	}
	var nlri bgp.AddrPrefixInterface
	var ip net.IP
	iplen := 0

	if args[0] != "0.0.0.0" && args[0] != "::" {
		ip = net.ParseIP(args[0])
		if ip == nil {
			return nil, nil, fmt.Errorf("invalid ip prefix: %s", args[0])
		}
		iplen = net.IPv4len * 8
		if ip.To4() == nil {
			iplen = net.IPv6len * 8
		}
	}

	eTag, err := strconv.Atoi(args[1])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid eTag: %s. err: %s", args[1], err)
	}

	var rd bgp.RouteDistinguisherInterface
	if args[2] == "rd" && len(args) > 3 {
		rd, err = bgp.ParseRouteDistinguisher(args[3])
		if err != nil {
			return nil, nil, err
		}
	}

	multicastEtag := &bgp.EVPNMulticastEthernetTagRoute{
		RD:              rd,
		IPAddressLength: uint8(iplen),
		IPAddress:       ip,
		ETag:            uint32(eTag),
	}
	extcomms := args[4:]
	nlri = bgp.NewEVPNNLRI(bgp.EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG, 0, multicastEtag)
	return nlri, extcomms, nil

}

func ParseEvpnArgs(args []string) (bgp.AddrPrefixInterface, []string, error) {
	if len(args) < 1 {
		return nil, nil, fmt.Errorf("lack of args. need 1 but %d", len(args))
	}
	subtype := args[0]
	args = args[1:]
	switch subtype {
	case "macadv":
		return ParseEvpnMacAdvArgs(args)
	case "multicast":
		return ParseEvpnMulticastArgs(args)
	}
	return nil, nil, fmt.Errorf("invalid subtype. expect [macadv|multicast] but %s", subtype)
}

func extractNexthop(rf bgp.RouteFamily, args []string) ([]string, string, error) {
	afi, _ := bgp.RouteFamilyToAfiSafi(rf)
	nexthop := "0.0.0.0"
	if afi == bgp.AFI_IP6 {
		nexthop = "::"
	}
	for idx, arg := range args {
		if arg == "nexthop" && len(args) > (idx+1) {
			if net.ParseIP(args[idx+1]) == nil {
				return nil, "", fmt.Errorf("invalid nexthop address")
			}
			nexthop = args[idx+1]
			args = append(args[:idx], args[idx+2:]...)
			break
		}
	}
	return args, nexthop, nil
}

func extractLocalPref(args []string) ([]string, []byte, error) {
	for idx, arg := range args {
		if arg == "local-pref" && len(args) > (idx+1) {
			metric, err := strconv.Atoi(args[idx+1])
			if err != nil {
				return nil, nil, err
			}
			args = append(args[:idx], args[idx+2:]...)
			localPref, _ := bgp.NewPathAttributeLocalPref(uint32(metric)).Serialize(bgp.DefaultMarshallingOptions())
			return args, localPref, nil
		}
	}
	return args, nil, nil
}

func extractMed(args []string) ([]string, []byte, error) {
	for idx, arg := range args {
		if arg == "med" && len(args) > (idx+1) {
			metric, err := strconv.Atoi(args[idx+1])
			if err != nil {
				return nil, nil, err
			}
			args = append(args[:idx], args[idx+2:]...)
			med, _ := bgp.NewPathAttributeMultiExitDisc(uint32(metric)).Serialize(bgp.DefaultMarshallingOptions())
			return args, med, nil
		}
	}
	return args, nil, nil
}

func extractAigp(args []string) ([]string, []byte, error) {
	for idx, arg := range args {
		if arg == "aigp" {
			if len(args) < (idx + 3) {
				return nil, nil, fmt.Errorf("invalid aigp format")
			}
			typ := args[idx+1]
			switch typ {
			case "metric":
				metric, err := strconv.Atoi(args[idx+2])
				if err != nil {
					return nil, nil, err
				}
				aigp, _ := bgp.NewPathAttributeAigp([]bgp.AigpTLV{bgp.NewAigpTLVIgpMetric(uint64(metric))}).Serialize(bgp.DefaultMarshallingOptions())
				return append(args[:idx], args[idx+3:]...), aigp, nil
			default:
				return nil, nil, fmt.Errorf("unknown aigp type: %s", typ)
			}
		}
	}
	return args, nil, nil
}

func ParsePath(rf bgp.RouteFamily, args []string) (*api.Path, error) {
	var nlri bgp.AddrPrefixInterface
	var extcomms []string
	var err error

	path := &api.Path{
		Pattrs: make([][]byte, 0),
	}

	args, nexthop, err := extractNexthop(rf, args)
	if err != nil {
		return nil, err
	}

	var med []byte
	args, med, err = extractMed(args)
	if err != nil {
		return nil, err
	}
	if med != nil {
		path.Pattrs = append(path.Pattrs, med)
	}

	var localPref []byte
	args, localPref, err = extractLocalPref(args)
	if err != nil {
		return nil, err
	}
	if localPref != nil {
		path.Pattrs = append(path.Pattrs, localPref)
	}

	var aigp []byte
	args, aigp, err = extractAigp(args)
	if err != nil {
		return nil, err
	}
	if aigp != nil {
		path.Pattrs = append(path.Pattrs, aigp)
	}

	switch rf {
	case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
		if len(args) != 1 {
			return nil, fmt.Errorf("invalid format")
		}
		ip, net, err := net.ParseCIDR(args[0])
		if err != nil {
			return nil, err
		}
		ones, _ := net.Mask.Size()
		if rf == bgp.RF_IPv4_UC {
			if ip.To4() == nil {
				return nil, fmt.Errorf("invalid ipv4 prefix")
			}
			nlri = bgp.NewIPAddrPrefix(uint8(ones), ip.String())
		} else {
			if ip.To16() == nil {
				return nil, fmt.Errorf("invalid ipv6 prefix")
			}
			nlri = bgp.NewIPv6AddrPrefix(uint8(ones), ip.String())
		}
	case bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN:
		if len(args) < 3 || args[1] != "rd" {
			return nil, fmt.Errorf("invalid format")
		}
		ip, net, _ := net.ParseCIDR(args[0])
		ones, _ := net.Mask.Size()

		rd, err := bgp.ParseRouteDistinguisher(args[2])
		if err != nil {
			return nil, err
		}

		extcomms = args[3:]

		mpls := bgp.NewMPLSLabelStack()

		if rf == bgp.RF_IPv4_VPN {
			if ip.To4() == nil {
				return nil, fmt.Errorf("invalid ipv4 prefix")
			}
			nlri = bgp.NewLabeledVPNIPAddrPrefix(uint8(ones), ip.String(), *mpls, rd)
		} else {
			if ip.To16() == nil {
				return nil, fmt.Errorf("invalid ipv6 prefix")
			}
			nlri = bgp.NewLabeledVPNIPv6AddrPrefix(uint8(ones), ip.String(), *mpls, rd)
		}
	case bgp.RF_EVPN:
		nlri, extcomms, err = ParseEvpnArgs(args)
	case bgp.RF_FS_IPv4_UC, bgp.RF_FS_IPv6_UC:
		nlri, extcomms, err = ParseFlowSpecArgs(rf, args)
	default:
		return nil, fmt.Errorf("Unsupported route family: %s", rf)
	}
	if err != nil {
		return nil, err
	}

	if rf == bgp.RF_IPv4_UC {
		path.Nlri, _ = nlri.Serialize(bgp.DefaultMarshallingOptions())
		n, _ := bgp.NewPathAttributeNextHop(nexthop).Serialize(bgp.DefaultMarshallingOptions())
		path.Pattrs = append(path.Pattrs, n)
	} else {
		mpreach, _ := bgp.NewPathAttributeMpReachNLRI(nexthop, []bgp.AddrPrefixInterface{nlri}).Serialize(bgp.DefaultMarshallingOptions())
		path.Pattrs = append(path.Pattrs, mpreach)
	}

	origin, _ := bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE).Serialize(bgp.DefaultMarshallingOptions())
	path.Pattrs = append(path.Pattrs, origin)

	if extcomms != nil && len(extcomms) > 0 {
		extcomms, err := ParseExtendedCommunities(strings.Join(extcomms, " "))
		if err != nil {
			return nil, err
		}
		p := bgp.NewPathAttributeExtendedCommunities(extcomms)
		buf, err := p.Serialize(bgp.DefaultMarshallingOptions())
		if err != nil {
			return nil, err
		}
		path.Pattrs = append(path.Pattrs, buf)
	}
	return path, nil
}

func showGlobalRib(args []string) error {
	return showNeighborRib(CMD_GLOBAL, "", args)
}

func modPath(resource api.Resource, name, modtype string, args []string) error {
	rf, err := checkAddressFamily(bgp.RF_IPv4_UC)
	if err != nil {
		return err
	}

	path, err := ParsePath(rf, args)

	if err != nil {
		cmdstr := "global"
		if resource == api.Resource_VRF {
			cmdstr = fmt.Sprintf("vrf %s", name)
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
		helpErrMap := map[bgp.RouteFamily]error{}
		helpErrMap[bgp.RF_IPv4_UC] = fmt.Errorf("usage: %s rib %s <PREFIX> [nexthop <ADDRESS>] [med <VALUE>] [local-pref <VALUE>] [aigp metric <METRIC>] -a ipv4", cmdstr, modtype)
		helpErrMap[bgp.RF_IPv6_UC] = fmt.Errorf("usage: %s rib %s <PREFIX> [nexthop <ADDRESS>] [med <VALUE>] [local-pref <VALUE>] [aigp metric <METRIC>] -a ipv6", cmdstr, modtype)
		fsHelpMsgFmt := fmt.Sprintf(`err: %s
usage: %s rib %s match <MATCH_EXPR> then <THEN_EXPR> -a %%s
    <MATCH_EXPR> : { %s <PREFIX> [<OFFSET>] | %s <PREFIX> [<OFFSET>] |
		     %s <PROTO>... | %s <FRAGMENT_TYPE> | %s [not] [match] <TCPFLAG>... |
		     { %s | %s | %s | %s | %s | %s | %s | %s } <ITEM>... }...
	<PROTO> : %s
	<FRAGMENT_TYPE> : not-a-fragment, is-a-fragment, first-fragment, last-fragment
	<TCPFLAG> : %s
	<ITEM> : &?{<|>|=}<value>
    <THEN_EXPR> : { %s | %s | %s <value> | %s <RT> | %s <value> | %s { sample | terminal | sample-terminal } | %s <RT>... }...
	<RT> : xxx:yyy, xx.xx.xx.xx:yyy, xxx.xxx:yyy`, err, cmdstr, modtype,
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
			bgp.FlowSpecNameMap[bgp.FLOW_SPEC_TYPE_LABEL],
			protos, flags,
			ExtCommNameMap[ACCEPT], ExtCommNameMap[DISCARD],
			ExtCommNameMap[RATE], ExtCommNameMap[REDIRECT],
			ExtCommNameMap[MARK], ExtCommNameMap[ACTION], ExtCommNameMap[RT])
		helpErrMap[bgp.RF_FS_IPv4_UC] = fmt.Errorf(fsHelpMsgFmt, "ipv4-flowspec")
		helpErrMap[bgp.RF_FS_IPv6_UC] = fmt.Errorf(fsHelpMsgFmt, "ipv6-flowspec")
		helpErrMap[bgp.RF_EVPN] = fmt.Errorf(`usage: %s rib %s { macadv <MACADV> | multicast <MULTICAST> } -a evpn
    <MACADV>    : <mac address> <ip address> <etag> <label> rd <rd> rt <rt>... [encap <encap type>]
    <MULTICAST> : <ip address> <etag> rd <rd> rt <rt>... [encap <encap type>]`, cmdstr, modtype)
		if err, ok := helpErrMap[rf]; ok {
			return err
		}
		return err
	}

	arg := &api.ModPathArguments{
		Operation: api.Operation_ADD,
		Resource:  resource,
		Name:      name,
		Path:      path,
	}

	if modtype == CMD_DEL {
		arg.Operation = api.Operation_DEL
	}

	_, err = client.ModPath(context.Background(), arg)
	return err
}

func showGlobalConfig(args []string) error {
	g, err := client.GetGlobalConfig(context.Background(), &api.Arguments{})
	if err != nil {
		return err
	}
	fmt.Println("AS:       ", g.As)
	fmt.Println("Router-ID:", g.RouterId)
	return nil
}

func modGlobalConfig(args []string) error {
	if len(args) != 4 || args[0] != "as" || args[2] != "router-id" {
		return fmt.Errorf("usage: gobgp global as <asn> router-id <route-id>")
	}
	asn, err := strconv.Atoi(args[1])
	if err != nil {
		return err
	}
	id := net.ParseIP(args[3])
	if id.To4() == nil {
		return fmt.Errorf("invalid router-id format")
	}
	_, err = client.ModGlobalConfig(context.Background(), &api.ModGlobalConfigArguments{
		Operation: api.Operation_ADD,
		Global: &api.Global{
			As:       uint32(asn),
			RouterId: args[3],
		},
	})
	return err
}

func NewGlobalCmd() *cobra.Command {
	globalCmd := &cobra.Command{
		Use: CMD_GLOBAL,
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			if len(args) != 0 {
				err = modGlobalConfig(args)
			} else {
				err = showGlobalConfig(args)
			}
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}

	ribCmd := &cobra.Command{
		Use: CMD_RIB,
		Run: func(cmd *cobra.Command, args []string) {
			if err := showGlobalRib(args); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}

	ribCmd.PersistentFlags().StringVarP(&subOpts.AddressFamily, "address-family", "a", "", "address family")

	for _, v := range []string{CMD_ADD, CMD_DEL} {
		cmd := &cobra.Command{
			Use: v,
			Run: func(cmd *cobra.Command, args []string) {
				err := modPath(api.Resource_GLOBAL, "", cmd.Use, args)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
			},
		}
		ribCmd.AddCommand(cmd)
	}

	policyCmd := &cobra.Command{
		Use: CMD_POLICY,
		Run: func(cmd *cobra.Command, args []string) {
			for _, v := range []string{CMD_IMPORT, CMD_EXPORT} {
				if err := showNeighborPolicy(nil, v, 4); err != nil {
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
				if err := showNeighborPolicy(nil, cmd.Use, 0); err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
			},
		}

		for _, w := range []string{CMD_ADD, CMD_DEL, CMD_SET} {
			subcmd := &cobra.Command{
				Use: w,
				Run: func(subcmd *cobra.Command, args []string) {
					err := modNeighborPolicy(nil, cmd.Use, subcmd.Use, args)
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

	globalCmd.AddCommand(ribCmd, policyCmd)
	return globalCmd
}
