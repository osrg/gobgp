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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

type extCommType int

const (
	ctAccept extCommType = iota
	ctDiscard
	ctRate
	ctRedirect
	ctMark
	ctAction
	ctRT
	ctEncap
	ctESILabel
	ctETree
	ctMulticastFlags
	ctRouterMAC
	ctDefaultGateway
	ctValid
	ctNotFound
	ctInvalid
	ctColor
	ctLb
	ctMup
)

var extCommNameMap = map[extCommType]string{
	ctAccept:         "accept",
	ctDiscard:        "discard",
	ctRate:           "rate-limit",
	ctRedirect:       "redirect",
	ctMark:           "mark",
	ctAction:         "action",
	ctRT:             "rt",
	ctEncap:          "encap",
	ctESILabel:       "esi-label",
	ctETree:          "etree",
	ctMulticastFlags: "multicast-flags",
	ctRouterMAC:      "router-mac",
	ctDefaultGateway: "default-gateway",
	ctValid:          "valid",
	ctNotFound:       "not-found",
	ctInvalid:        "invalid",
	ctColor:          "color",
	ctLb:             "lb",
	ctMup:            "mup",
}

var extCommValueMap = map[string]extCommType{
	extCommNameMap[ctAccept]:         ctAccept,
	extCommNameMap[ctDiscard]:        ctDiscard,
	extCommNameMap[ctRate]:           ctRate,
	extCommNameMap[ctRedirect]:       ctRedirect,
	extCommNameMap[ctMark]:           ctMark,
	extCommNameMap[ctAction]:         ctAction,
	extCommNameMap[ctRT]:             ctRT,
	extCommNameMap[ctEncap]:          ctEncap,
	extCommNameMap[ctESILabel]:       ctESILabel,
	extCommNameMap[ctETree]:          ctETree,
	extCommNameMap[ctMulticastFlags]: ctMulticastFlags,
	extCommNameMap[ctRouterMAC]:      ctRouterMAC,
	extCommNameMap[ctDefaultGateway]: ctDefaultGateway,
	extCommNameMap[ctValid]:          ctValid,
	extCommNameMap[ctNotFound]:       ctNotFound,
	extCommNameMap[ctInvalid]:        ctInvalid,
	extCommNameMap[ctColor]:          ctColor,
	extCommNameMap[ctLb]:             ctLb,
	extCommNameMap[ctMup]:            ctMup,
}

func rateLimitParser(args []string) ([]bgp.ExtendedCommunityInterface, error) {
	exp := regexp.MustCompile(fmt.Sprintf("^(%s|(%s) (\\d+)(\\.(\\d+))?)( as (\\d+))?$", extCommNameMap[ctDiscard], extCommNameMap[ctRate]))
	elems := exp.FindStringSubmatch(strings.Join(args, " "))
	if len(elems) != 8 {
		return nil, fmt.Errorf("invalid rate-limit")
	}
	var rate float32
	var as uint64
	if elems[2] == extCommNameMap[ctRate] {
		f, err := strconv.ParseFloat(elems[3]+elems[4], 32)
		if err != nil {
			return nil, err
		}
		rate = float32(f)
	}
	if elems[7] != "" {
		var err error
		as, err = strconv.ParseUint(elems[7], 10, 16)
		if err != nil {
			return nil, err
		}
	}
	return []bgp.ExtendedCommunityInterface{bgp.NewTrafficRateExtended(uint16(as), rate)}, nil
}

func redirectParser(args []string) ([]bgp.ExtendedCommunityInterface, error) {
	if len(args) < 2 || args[0] != extCommNameMap[ctRedirect] {
		return nil, fmt.Errorf("invalid redirect")
	}
	rt, err := bgp.ParseRouteTarget(strings.Join(args[1:], " "))
	if err != nil {
		return nil, err
	}
	switch r := rt.(type) {
	case *bgp.TwoOctetAsSpecificExtended:
		return []bgp.ExtendedCommunityInterface{bgp.NewRedirectTwoOctetAsSpecificExtended(r.AS, r.LocalAdmin)}, nil
	case *bgp.IPv4AddressSpecificExtended:
		ex, _ := bgp.NewRedirectIPv4AddressSpecificExtended(r.IPv4, r.LocalAdmin)
		return []bgp.ExtendedCommunityInterface{ex}, nil
	case *bgp.FourOctetAsSpecificExtended:
		return []bgp.ExtendedCommunityInterface{bgp.NewRedirectFourOctetAsSpecificExtended(r.AS, r.LocalAdmin)}, nil
	case *bgp.IPv6AddressSpecificExtended:
		ex, _ := bgp.NewRedirectIPv6AddressSpecificExtended(r.IPv6, r.LocalAdmin)
		return []bgp.ExtendedCommunityInterface{ex}, nil
	}
	return nil, fmt.Errorf("invalid redirect")
}

func markParser(args []string) ([]bgp.ExtendedCommunityInterface, error) {
	if len(args) < 2 || args[0] != extCommNameMap[ctMark] {
		return nil, fmt.Errorf("invalid mark")
	}
	dscp, err := strconv.ParseUint(args[1], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid mark")
	}
	return []bgp.ExtendedCommunityInterface{bgp.NewTrafficRemarkExtended(uint8(dscp))}, nil
}

func actionParser(args []string) ([]bgp.ExtendedCommunityInterface, error) {
	if len(args) < 2 || args[0] != extCommNameMap[ctAction] {
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
	if len(args) < 2 || args[0] != extCommNameMap[ctRT] {
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
	if len(args) < 2 || args[0] != extCommNameMap[ctEncap] {
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
	case "mpls-in-udp":
		typ = bgp.TUNNEL_TYPE_MPLS_IN_UDP
	case "vxlan-gre":
		typ = bgp.TUNNEL_TYPE_VXLAN_GRE
	case "geneve":
		typ = bgp.TUNNEL_TYPE_GENEVE
	default:
		return nil, fmt.Errorf("invalid encap type")
	}
	return []bgp.ExtendedCommunityInterface{bgp.NewEncapExtended(typ)}, nil
}

func esiLabelParser(args []string) ([]bgp.ExtendedCommunityInterface, error) {
	if len(args) < 2 || args[0] != extCommNameMap[ctESILabel] {
		return nil, fmt.Errorf("invalid esi-label")
	}
	label, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil {
		return nil, err
	}
	isSingleActive := false
	if len(args) > 2 {
		switch args[2] {
		case "single-active":
			isSingleActive = true
		case "all-active":
			// isSingleActive = false
		default:
			return nil, fmt.Errorf("invalid esi-label")
		}
	}
	o := &bgp.ESILabelExtended{
		Label:          uint32(label),
		IsSingleActive: isSingleActive,
	}
	return []bgp.ExtendedCommunityInterface{o}, nil
}

func eTreeParser(args []string) ([]bgp.ExtendedCommunityInterface, error) {
	if len(args) < 2 || args[0] != extCommNameMap[ctETree] {
		return nil, fmt.Errorf("invalid etree")
	}
	label, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil {
		return nil, err
	}
	isLeaf := false
	if len(args) > 2 {
		switch args[2] {
		case "leaf":
			isLeaf = true
		case "root":
			isLeaf = false
		default:
			return nil, fmt.Errorf("invalid etree")
		}
	}
	o := &bgp.ETreeExtended{
		Label:  uint32(label),
		IsLeaf: isLeaf,
	}
	return []bgp.ExtendedCommunityInterface{o}, nil
}

func multicastFlagsParser(args []string) ([]bgp.ExtendedCommunityInterface, error) {
	if len(args) < 2 || args[0] != extCommNameMap[ctMulticastFlags] {
		return nil, fmt.Errorf("invalid multicast flags")
	}
	isIGMPProxy := false
	isMLDProxy := false
	if len(args) > 1 {
		switch args[1] {
		case "igmp-proxy":
			isIGMPProxy = true
		case "mld-proxy":
			isMLDProxy = true
		default:
			return nil, fmt.Errorf("unknown multicast flag")
		}
	}
	o := &bgp.MulticastFlagsExtended{
		IsIGMPProxy: isIGMPProxy,
		IsMLDProxy:  isMLDProxy,
	}
	return []bgp.ExtendedCommunityInterface{o}, nil
}

func routerMacParser(args []string) ([]bgp.ExtendedCommunityInterface, error) {
	if len(args) < 2 || args[0] != extCommNameMap[ctRouterMAC] {
		return nil, fmt.Errorf("invalid router's mac")
	}
	hw, err := net.ParseMAC(args[1])
	if err != nil {
		return nil, err
	}
	o := &bgp.RouterMacExtended{Mac: hw}
	return []bgp.ExtendedCommunityInterface{o}, nil
}

func defaultGatewayParser(args []string) ([]bgp.ExtendedCommunityInterface, error) {
	if len(args) < 1 || args[0] != extCommNameMap[ctDefaultGateway] {
		return nil, fmt.Errorf("invalid default-gateway")
	}
	return []bgp.ExtendedCommunityInterface{bgp.NewDefaultGatewayExtended()}, nil
}

func validationParser(args []string) ([]bgp.ExtendedCommunityInterface, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("invalid validation state")
	}
	var typ bgp.ValidationState
	switch args[0] {
	case "valid":
		typ = bgp.VALIDATION_STATE_VALID
	case "not-found":
		typ = bgp.VALIDATION_STATE_NOT_FOUND
	case "invalid":
		typ = bgp.VALIDATION_STATE_INVALID
	default:
		return nil, fmt.Errorf("invalid validation state")
	}
	return []bgp.ExtendedCommunityInterface{bgp.NewValidationExtended(typ)}, nil
}

func colorParser(args []string) ([]bgp.ExtendedCommunityInterface, error) {
	if len(args) != 2 || args[0] != extCommNameMap[ctColor] {
		return nil, fmt.Errorf("invalid color")
	}
	color, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid color")
	}
	return []bgp.ExtendedCommunityInterface{bgp.NewColorExtended(uint32(color))}, nil
}

func lbParser(args []string) ([]bgp.ExtendedCommunityInterface, error) {
	if len(args) != 2 || args[0] != extCommNameMap[ctLb] {
		return nil, fmt.Errorf("invalid link-bandwidth")
	}

	as, err := strconv.ParseUint(args[1], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid lb ASN")
	}

	bw, err := strconv.ParseFloat(args[2], 32)
	if err != nil {
		return nil, fmt.Errorf("invalid lb bandwidth")
	}
	return []bgp.ExtendedCommunityInterface{bgp.NewLinkBandwidthExtended(uint16(as), float32(bw))}, nil
}

func mupParser(args []string) ([]bgp.ExtendedCommunityInterface, error) {
	if len(args) != 2 || args[0] != extCommNameMap[ctMup] {
		return nil, fmt.Errorf("invalid mup")
	}
	a := strings.Split(args[1], ":")
	sid2, err := strconv.ParseUint(a[0], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid mup segment ID")
	}
	sid4, err := strconv.ParseUint(a[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid mup segment ID")
	}
	return []bgp.ExtendedCommunityInterface{bgp.NewMUPExtended(uint16(sid2), uint32(sid4))}, nil
}

var extCommParserMap = map[extCommType]func([]string) ([]bgp.ExtendedCommunityInterface, error){
	ctAccept:         nil,
	ctDiscard:        rateLimitParser,
	ctRate:           rateLimitParser,
	ctRedirect:       redirectParser,
	ctMark:           markParser,
	ctAction:         actionParser,
	ctRT:             rtParser,
	ctEncap:          encapParser,
	ctESILabel:       esiLabelParser,
	ctETree:          eTreeParser,
	ctMulticastFlags: multicastFlagsParser,
	ctRouterMAC:      routerMacParser,
	ctDefaultGateway: defaultGatewayParser,
	ctValid:          validationParser,
	ctNotFound:       validationParser,
	ctInvalid:        validationParser,
	ctColor:          colorParser,
	ctLb:             lbParser,
	ctMup:            mupParser,
}

func parseExtendedCommunities(args []string) ([]bgp.ExtendedCommunityInterface, error) {
	idxs := make([]struct {
		t extCommType
		i int
	}, 0, len(extCommNameMap))
	for idx, v := range args {
		if t, ok := extCommValueMap[v]; ok {
			idxs = append(idxs, struct {
				t extCommType
				i int
			}{t, idx})
		}
	}
	exts := make([]bgp.ExtendedCommunityInterface, 0, len(idxs))
	for i, idx := range idxs {
		var a []string
		f := extCommParserMap[idx.t]
		if i < len(idxs)-1 {
			a = args[:idxs[i+1].i-idx.i]
			args = args[idxs[i+1].i-idx.i:]
		} else {
			a = args
			args = nil
		}
		if f == nil {
			continue
		}
		ext, err := f(a)
		if err != nil {
			return nil, err
		}
		exts = append(exts, ext...)
	}
	if len(args) > 0 {
		return nil, fmt.Errorf("failed to parse %v", args)
	}
	return exts, nil
}

func parseFlowSpecArgs(rf bgp.Family, args []string) (bgp.NLRI, *bgp.PathAttributePrefixSID, []string, error) {
	// Format:
	// match <rule>... [then <action>...] [rd <rd>] [rt <rt>...]
	// or
	// match <rule>... then redirect <rt> [color <color>] [prefix <prefix>] [locator-node-length <length>] [function-length <length>] [behavior <behavior>]
	req := 3 // match <key1> <arg1> [<key2> <arg2>...]
	if len(args) < req {
		return nil, nil, nil, fmt.Errorf("%d args required at least, but got %d", req, len(args))
	}
	m, err := extractReserved(args, map[string]int{
		"match":               paramList,
		"then":                paramList,
		"rd":                  paramSingle,
		"rt":                  paramList,
		"color":               paramSingle,
		"prefix":              paramSingle,
		"locator-node-length": paramSingle,
		"function-length":     paramSingle,
		"behavior":            paramSingle,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	if len(m["match"]) == 0 {
		return nil, nil, nil, fmt.Errorf("specify filtering rules with keyword 'match'")
	}

	var rd bgp.RouteDistinguisherInterface
	extcomms := m["then"]
	switch rf {
	case bgp.RF_FS_IPv4_VPN, bgp.RF_FS_IPv6_VPN, bgp.RF_FS_L2_VPN:
		if len(m["rd"]) == 0 {
			return nil, nil, nil, fmt.Errorf("specify rd")
		}
		var err error
		if rd, err = bgp.ParseRouteDistinguisher(m["rd"][0]); err != nil {
			return nil, nil, nil, fmt.Errorf("invalid rd: %s", m["rd"][0])
		}
		if len(m["rt"]) > 0 {
			extcomms = append(extcomms, "rt")
			extcomms = append(extcomms, m["rt"]...)
		}
	default:
		if len(m["rd"]) > 0 {
			return nil, nil, nil, fmt.Errorf("cannot specify rd for %s", rf.String())
		}
		if len(m["rt"]) > 0 {
			return nil, nil, nil, fmt.Errorf("cannot specify rt for %s", rf.String())
		}
	}

	rules, err := bgp.ParseFlowSpecComponents(rf, strings.Join(m["match"], " "))
	if err != nil {
		return nil, nil, nil, err
	}

	var nlri bgp.NLRI
	switch rf {
	case bgp.RF_FS_IPv4_UC, bgp.RF_FS_IPv6_UC:
		nlri, _ = bgp.NewFlowSpecUnicast(rf, rules)
	case bgp.RF_FS_IPv4_VPN, bgp.RF_FS_IPv6_VPN, bgp.RF_FS_L2_VPN:
		nlri, _ = bgp.NewFlowSpecVPN(rf, rd, rules)
	default:
		return nil, nil, nil, fmt.Errorf("invalid route family")
	}

	var psid *bgp.PathAttributePrefixSID
	hasAnySRv6PolicyParam := len(m["prefix"]) > 0 || len(m["locator-node-length"]) > 0 || len(m["function-length"]) > 0 || len(m["behavior"]) > 0

	if len(m["then"]) != 0 && m["then"][0] == "redirect" {
		if len(m["color"]) == 0 && hasAnySRv6PolicyParam {
			return nil, nil, nil, fmt.Errorf("specify color")
		}
		if len(m["color"]) > 0 {
			extcomms = append(extcomms, "color", m["color"][0])
			if hasAnySRv6PolicyParam {
				// Check if all optional SRv6 Policy parameters are specified.
				required := []string{"prefix", "locator-node-length", "function-length", "behavior"}
				for _, param := range required {
					if len(m[param]) == 0 {
						return nil, nil, nil, fmt.Errorf("specify %s", param)
					}
				}

				sid, err := netip.ParsePrefix(m["prefix"][0])
				if err != nil {
					return nil, nil, nil, err
				}
				nl, err := strconv.ParseUint(m["locator-node-length"][0], 10, 8)
				if err != nil {
					return nil, nil, nil, err
				}
				fl, err := strconv.ParseUint(m["function-length"][0], 10, 8)
				if err != nil {
					return nil, nil, nil, err
				}
				behavior, ok := api.SRV6Behavior_value["SRV6_BEHAVIOR_"+m["behavior"][0]]
				if !ok {
					return nil, nil, nil, fmt.Errorf("unknown behavior: %s", m["behavior"][0])
				}

				psid = bgp.NewPathAttributePrefixSID(
					bgp.NewSRv6ServiceTLV(
						bgp.TLVTypeSRv6L3Service,
						bgp.NewSRv6InformationSubTLV(
							sid.Addr(),
							bgp.SRBehavior(behavior),
							bgp.NewSRv6SIDStructureSubSubTLV(uint8(sid.Bits()), uint8(nl), uint8(fl), 0, 0, 0),
						),
					),
				)
			}
		}
	} else if hasAnySRv6PolicyParam {
		return nil, nil, nil, fmt.Errorf("cannot specify %s for %s", strings.Join([]string{"prefix", "locator-node-length", "function-length", "behavior"}, ", "), m["then"][0])
	}

	return nlri, psid, extcomms, nil
}

func parseEvpnEthernetAutoDiscoveryArgs(args []string) (bgp.NLRI, []string, error) {
	// Format:
	// esi <esi> etag <etag> label <label> rd <rd> [rt <rt>...] [encap <encap type>] [esi-label <esi-label> [single-active | all-active]]
	req := 8
	if len(args) < req {
		return nil, nil, fmt.Errorf("%d args required at least, but got %d", req, len(args))
	}
	m, err := extractReserved(args, map[string]int{
		"esi":       paramList,
		"etag":      paramSingle,
		"label":     paramSingle,
		"rd":        paramSingle,
		"rt":        paramList,
		"encap":     paramSingle,
		"esi-label": paramList,
	})
	if err != nil {
		return nil, nil, err
	}
	for _, f := range []string{"esi", "etag", "label", "rd"} {
		for len(m[f]) == 0 {
			return nil, nil, fmt.Errorf("specify %s", f)
		}
	}

	esi, err := bgp.ParseEthernetSegmentIdentifier(m["esi"])
	if err != nil {
		return nil, nil, err
	}

	e, err := strconv.ParseUint(m["etag"][0], 10, 32)
	if err != nil {
		return nil, nil, err
	}
	etag := uint32(e)

	l, err := strconv.ParseUint(m["label"][0], 10, 32)
	if err != nil {
		return nil, nil, err
	}
	label := uint32(l)

	rd, err := bgp.ParseRouteDistinguisher(m["rd"][0])
	if err != nil {
		return nil, nil, err
	}

	extcomms := make([]string, 0)
	if len(m["rt"]) > 0 {
		extcomms = append(extcomms, "rt")
		extcomms = append(extcomms, m["rt"]...)
	}
	if len(m["encap"]) > 0 {
		extcomms = append(extcomms, "encap", m["encap"][0])
	}
	if len(m["esi-label"]) > 0 {
		extcomms = append(extcomms, "esi-label")
		extcomms = append(extcomms, m["esi-label"]...)
	}

	r := &bgp.EVPNEthernetAutoDiscoveryRoute{
		RD:    rd,
		ESI:   esi,
		ETag:  etag,
		Label: label,
	}
	return bgp.NewEVPNNLRI(bgp.EVPN_ROUTE_TYPE_ETHERNET_AUTO_DISCOVERY, r), extcomms, nil
}

func parseEvpnMacAdvArgs(args []string) (bgp.NLRI, []string, error) {
	// Format:
	// <mac address> <ip address> [esi <esi>] etag <etag> label <label> rd <rd> [rt <rt>...] [encap <encap type>] [router-mac <mac address>] [default-gateway]
	// or
	// <mac address> <ip address> <etag> [esi <esi>] label <label> rd <rd> [rt <rt>...] [encap <encap type>] [router-mac <mac address>] [default-gateway]
	// or
	// <mac address> <ip address> <etag> <label> [esi <esi>] rd <rd> [rt <rt>...] [encap <encap type>] [router-mac <mac address>] [default-gateway]
	req := 6
	if len(args) < req {
		return nil, nil, fmt.Errorf("%d args required at least, but got %d", req, len(args))
	}
	m, err := extractReserved(args, map[string]int{
		"esi":             paramList,
		"etag":            paramSingle,
		"label":           paramSingle,
		"rd":              paramSingle,
		"rt":              paramList,
		"encap":           paramSingle,
		"router-mac":      paramSingle,
		"default-gateway": paramFlag,
	})
	if err != nil {
		return nil, nil, err
	}
	if len(m[""]) < 2 {
		return nil, nil, fmt.Errorf("specify mac and ip address")
	}
	macStr := m[""][0]
	ipStr := m[""][1]
	eTagStr := ""
	labelStr := ""
	if len(m[""]) == 2 {
		if len(m["etag"]) == 0 || len(m["label"]) == 0 {
			return nil, nil, fmt.Errorf("specify etag and label")
		}
		eTagStr = m["etag"][0]
		labelStr = m["label"][0]
	} else if len(m[""]) == 3 {
		if len(m["label"]) == 0 {
			return nil, nil, fmt.Errorf("specify label")
		}
		eTagStr = m[""][2]
		labelStr = m["label"][0]
	} else {
		eTagStr = m[""][2]
		labelStr = m[""][3]
	}
	if len(m["rd"]) == 0 {
		return nil, nil, fmt.Errorf("specify rd")
	}

	mac, err := net.ParseMAC(macStr)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid mac address: %s", macStr)
	}

	ip, err := netip.ParseAddr(ipStr)
	ipLen := 0
	if err != nil {
		return nil, nil, fmt.Errorf("invalid ip address: %s", ipStr)
	} else if ip.IsUnspecified() {
		ip = netip.Addr{}
	} else if ip.Is4() {
		ipLen = net.IPv4len * 8
	} else {
		ipLen = net.IPv6len * 8
	}

	esi, err := bgp.ParseEthernetSegmentIdentifier(m["esi"])
	if err != nil {
		return nil, nil, err
	}

	eTag, err := strconv.ParseUint(eTagStr, 10, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid etag: %s: %s", eTagStr, err)
	}

	var labels []uint32
	for _, l := range strings.SplitN(labelStr, ",", 2) {
		label, err := strconv.ParseUint(l, 10, 32)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid label: %s: %s", labelStr, err)
		}
		labels = append(labels, uint32(label))
	}

	rd, err := bgp.ParseRouteDistinguisher(m["rd"][0])
	if err != nil {
		return nil, nil, err
	}

	extcomms := make([]string, 0)
	if len(m["rt"]) > 0 {
		extcomms = append(extcomms, "rt")
		extcomms = append(extcomms, m["rt"]...)
	}
	if len(m["encap"]) > 0 {
		extcomms = append(extcomms, "encap", m["encap"][0])
	}

	if len(m["router-mac"]) != 0 {
		_, err := net.ParseMAC(m["router-mac"][0])
		if err != nil {
			return nil, nil, fmt.Errorf("invalid router-mac address: %s", m["router-mac"][0])
		}
		extcomms = append(extcomms, "router-mac", m["router-mac"][0])
	}

	if _, ok := m["default-gateway"]; ok {
		extcomms = append(extcomms, "default-gateway")
	}

	r := &bgp.EVPNMacIPAdvertisementRoute{
		RD:               rd,
		ESI:              esi,
		MacAddressLength: 48,
		MacAddress:       mac,
		IPAddressLength:  uint8(ipLen),
		IPAddress:        ip,
		Labels:           labels,
		ETag:             uint32(eTag),
	}
	return bgp.NewEVPNNLRI(bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT, r), extcomms, nil
}

func parseEvpnMulticastArgs(args []string) (bgp.NLRI, []string, error) {
	// Format:
	// <ip address> etag <etag> rd <rd> [rt <rt>...] [encap <encap type>]
	// or
	// <ip address> <etag> rd <rd> [rt <rt>...] [encap <encap type>]
	req := 4
	if len(args) < req {
		return nil, nil, fmt.Errorf("%d args required at least, but got %d", req, len(args))
	}
	m, err := extractReserved(args, map[string]int{
		"etag":  paramSingle,
		"rd":    paramSingle,
		"rt":    paramList,
		"encap": paramSingle,
	})
	if err != nil {
		return nil, nil, err
	}
	if len(m[""]) < 1 {
		return nil, nil, fmt.Errorf("specify ip address")
	}
	ipStr := m[""][0]
	eTagStr := ""
	if len(m[""]) == 1 {
		if len(m["etag"]) == 0 {
			return nil, nil, fmt.Errorf("specify etag")
		}
		eTagStr = m["etag"][0]
	} else {
		eTagStr = m[""][1]
	}
	if len(m["rd"]) == 0 {
		return nil, nil, fmt.Errorf("specify rd")
	}

	ip, err := netip.ParseAddr(ipStr)
	ipLen := 0
	if err != nil {
		return nil, nil, fmt.Errorf("invalid ip address: %s", ipStr)
	} else if ip.IsUnspecified() {
		ip = netip.Addr{}
	} else {
		ipLen = ip.BitLen()
	}

	eTag, err := strconv.ParseUint(eTagStr, 10, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid etag: %s: %s", eTagStr, err)
	}

	rd, err := bgp.ParseRouteDistinguisher(m["rd"][0])
	if err != nil {
		return nil, nil, err
	}

	extcomms := make([]string, 0)
	if len(m["rt"]) > 0 {
		extcomms = append(extcomms, "rt")
		extcomms = append(extcomms, m["rt"]...)
	}
	if len(m["encap"]) > 0 {
		extcomms = append(extcomms, "encap", m["encap"][0])
	}

	r := &bgp.EVPNMulticastEthernetTagRoute{
		RD:              rd,
		IPAddressLength: uint8(ipLen),
		IPAddress:       ip,
		ETag:            uint32(eTag),
	}
	return bgp.NewEVPNNLRI(bgp.EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG, r), extcomms, nil
}

func parseEvpnEthernetSegmentArgs(args []string) (bgp.NLRI, []string, error) {
	// Format:
	// <ip address> esi <esi> rd <rd> [rt <rt>...] [encap <encap type>]
	req := 5
	if len(args) < req {
		return nil, nil, fmt.Errorf("%d args required at least, but got %d", req, len(args))
	}
	m, err := extractReserved(args, map[string]int{
		"esi":   paramList,
		"rd":    paramSingle,
		"rt":    paramList,
		"encap": paramSingle,
	})
	if err != nil {
		return nil, nil, err
	}
	if len(m[""]) < 1 {
		return nil, nil, fmt.Errorf("specify ip address")
	}
	for _, f := range []string{"esi", "rd"} {
		for len(m[f]) == 0 {
			return nil, nil, fmt.Errorf("specify %s", f)
		}
	}

	ip, err := netip.ParseAddr(m[""][0])
	ipLen := 0
	if err != nil {
		return nil, nil, fmt.Errorf("invalid ip address: %s", m[""][0])
	} else if ip.IsUnspecified() {
		ip = netip.Addr{}
	} else {
		ipLen = ip.BitLen()
	}

	esi, err := bgp.ParseEthernetSegmentIdentifier(m["esi"])
	if err != nil {
		return nil, nil, err
	}

	rd, err := bgp.ParseRouteDistinguisher(m["rd"][0])
	if err != nil {
		return nil, nil, err
	}

	extcomms := make([]string, 0)
	if len(m["rt"]) > 0 {
		extcomms = append(extcomms, "rt")
		extcomms = append(extcomms, m["rt"]...)
	}
	if len(m["encap"]) > 0 {
		extcomms = append(extcomms, "encap", m["encap"][0])
	}

	r := &bgp.EVPNEthernetSegmentRoute{
		RD:              rd,
		ESI:             esi,
		IPAddressLength: uint8(ipLen),
		IPAddress:       ip,
	}
	return bgp.NewEVPNNLRI(bgp.EVPN_ETHERNET_SEGMENT_ROUTE, r), extcomms, nil
}

func parseEvpnIPPrefixArgs(args []string) (bgp.NLRI, []string, error) {
	// Format:
	// <ip prefix> [gw <gateway>] [esi <esi>] etag <etag> [label <label>] rd <rd> [rt <rt>...] [encap <encap type>]
	req := 5
	if len(args) < req {
		return nil, nil, fmt.Errorf("%d args required at least, but got %d", req, len(args))
	}
	m, err := extractReserved(args, map[string]int{
		"gw":         paramSingle,
		"esi":        paramList,
		"etag":       paramSingle,
		"label":      paramSingle,
		"rd":         paramSingle,
		"rt":         paramList,
		"encap":      paramSingle,
		"router-mac": paramSingle,
	})
	if err != nil {
		return nil, nil, err
	}
	if len(m[""]) < 1 {
		return nil, nil, fmt.Errorf("specify prefix")
	}
	for _, f := range []string{"etag", "rd"} {
		for len(m[f]) == 0 {
			return nil, nil, fmt.Errorf("specify %s", f)
		}
	}

	prefix, err := netip.ParsePrefix(m[""][0])
	if err != nil {
		return nil, nil, err
	}
	ones := prefix.Bits()

	var gw netip.Addr
	if len(m["gw"]) > 0 {
		gw, _ = netip.ParseAddr(m["gw"][0])
	}

	rd, err := bgp.ParseRouteDistinguisher(m["rd"][0])
	if err != nil {
		return nil, nil, err
	}

	esi, err := bgp.ParseEthernetSegmentIdentifier(m["esi"])
	if err != nil {
		return nil, nil, err
	}

	e, err := strconv.ParseUint(m["etag"][0], 10, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid etag: %s: %s", m["etag"][0], err)
	}
	etag := uint32(e)

	var label uint32
	if len(m["label"]) > 0 {
		e, err := strconv.ParseUint(m["label"][0], 10, 32)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid label: %s: %s", m["label"][0], err)
		}
		label = uint32(e)
	}

	extcomms := make([]string, 0)
	if len(m["rt"]) > 0 {
		extcomms = append(extcomms, "rt")
		extcomms = append(extcomms, m["rt"]...)
	}
	if len(m["encap"]) > 0 {
		extcomms = append(extcomms, "encap", m["encap"][0])
	}
	if len(m["router-mac"]) > 0 {
		extcomms = append(extcomms, "router-mac", m["router-mac"][0])
	}

	r := &bgp.EVPNIPPrefixRoute{
		RD:             rd,
		ESI:            esi,
		ETag:           etag,
		IPPrefixLength: uint8(ones),
		IPPrefix:       prefix.Addr(),
		GWIPAddress:    gw,
		Label:          label,
	}
	return bgp.NewEVPNNLRI(bgp.EVPN_IP_PREFIX, r), extcomms, nil
}

func parseEvpnIPMSIArgs(args []string) (bgp.NLRI, []string, error) {
	// Format:
	// etag <etag> rd <rd> [rt <rt>...] [encap <encap type>]
	req := 4
	if len(args) < req {
		return nil, nil, fmt.Errorf("%d args required at least, but got %d", req, len(args))
	}
	m, err := extractReserved(args, map[string]int{
		"etag":  paramSingle,
		"rd":    paramSingle,
		"rt":    paramSingle,
		"encap": paramSingle,
	})
	if err != nil {
		return nil, nil, err
	}
	for _, f := range []string{"etag", "rd"} {
		for len(m[f]) == 0 {
			return nil, nil, fmt.Errorf("specify %s", f)
		}
	}

	rd, err := bgp.ParseRouteDistinguisher(m["rd"][0])
	if err != nil {
		return nil, nil, err
	}

	e, err := strconv.ParseUint(m["etag"][0], 10, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid etag: %s: %s", m["etag"][0], err)
	}
	etag := uint32(e)

	extcomms := make([]string, 0)
	if len(m["rt"]) > 0 {
		extcomms = append(extcomms, "rt")
		extcomms = append(extcomms, m["rt"]...)
	}
	ec, err := bgp.ParseExtendedCommunity(bgp.EC_SUBTYPE_SOURCE_AS, m["rt"][0])
	if err != nil {
		return nil, nil, fmt.Errorf("route target parse failed")
	}

	if len(m["encap"]) > 0 {
		extcomms = append(extcomms, "encap", m["encap"][0])
	}

	r := &bgp.EVPNIPMSIRoute{
		RD:   rd,
		ETag: etag,
		EC:   ec,
	}
	return bgp.NewEVPNNLRI(bgp.EVPN_I_PMSI, r), extcomms, nil
}

func parseEvpnArgs(args []string) (bgp.NLRI, []string, error) {
	if len(args) < 1 {
		return nil, nil, fmt.Errorf("lack of args. need 1 but %d", len(args))
	}
	subtype := args[0]
	args = args[1:]
	switch subtype {
	case "a-d":
		return parseEvpnEthernetAutoDiscoveryArgs(args)
	case "macadv":
		return parseEvpnMacAdvArgs(args)
	case "multicast":
		return parseEvpnMulticastArgs(args)
	case "esi":
		return parseEvpnEthernetSegmentArgs(args)
	case "prefix":
		return parseEvpnIPPrefixArgs(args)
	case "i-pmsi":
		return parseEvpnIPMSIArgs(args)
	}
	return nil, nil, fmt.Errorf("invalid subtype. expect [macadv|multicast|prefix] but %s", subtype)
}

func parseMUPInterworkSegmentDiscoveryRouteArgs(args []string, afi uint16, nexthop string) (bgp.NLRI, *bgp.PathAttributePrefixSID, []string, error) {
	// Format:
	// <ip prefix> rd <rd> prefix <prefix> locator-node-length <locator-node-length> function-length <function-length> behavior <behavior> [rt <rt>...]
	req := 13
	if len(args) < req {
		return nil, nil, nil, fmt.Errorf("%d args required at least, but got %d", req, len(args))
	}
	m, err := extractReserved(args, map[string]int{
		"rd":                  paramSingle,
		"prefix":              paramSingle,
		"locator-node-length": paramSingle,
		"function-length":     paramSingle,
		"behavior":            paramSingle,
		"rt":                  paramSingle,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	if len(m[""]) < 1 {
		return nil, nil, nil, fmt.Errorf("specify prefix")
	}
	for _, f := range []string{"rd", "prefix", "locator-node-length", "function-length", "rt"} {
		for len(m[f]) == 0 {
			return nil, nil, nil, fmt.Errorf("specify %s", f)
		}
	}
	rd, err := bgp.ParseRouteDistinguisher(m["rd"][0])
	if err != nil {
		return nil, nil, nil, err
	}
	prefix, err := netip.ParsePrefix(m[""][0])
	if err != nil {
		return nil, nil, nil, err
	}
	nh, err := netip.ParseAddr(nexthop)
	if err != nil {
		return nil, nil, nil, err
	}
	if nh.Is4() {
		return nil, nil, nil, fmt.Errorf("nexthop should be IPv6 address: %s", nexthop)
	}
	sid, err := netip.ParsePrefix(m["prefix"][0])
	if err != nil {
		return nil, nil, nil, err
	}
	nl, err := strconv.ParseUint(m["locator-node-length"][0], 10, 8)
	if err != nil {
		return nil, nil, nil, err
	}
	fl, err := strconv.ParseUint(m["function-length"][0], 10, 8)
	if err != nil {
		return nil, nil, nil, err
	}
	behavior, ok := api.SRV6Behavior_value["SRV6_BEHAVIOR_"+m["behavior"][0]]
	if !ok {
		return nil, nil, nil, fmt.Errorf("unknown behavior: %s", m["behavior"][0])
	}
	if (afi != bgp.AFI_IP || behavior != int32(bgp.ENDM_GTP4E)) && (afi != bgp.AFI_IP6 || behavior != int32(bgp.ENDM_GTP6E)) {
		return nil, nil, nil, fmt.Errorf("invalid behavior: %s. behavior must be ENDM_GTP4E or ENDM_GTP6E", m["behavior"][0])
	}
	psid := bgp.NewPathAttributePrefixSID(
		bgp.NewSRv6ServiceTLV(
			bgp.TLVTypeSRv6L3Service,
			bgp.NewSRv6InformationSubTLV(
				sid.Addr(),
				bgp.SRBehavior(behavior),
				bgp.NewSRv6SIDStructureSubSubTLV(uint8(sid.Bits()), uint8(nl), uint8(fl), 0, 0, 0),
			),
		),
	)

	extcomms := make([]string, 0)
	if len(m["rt"]) > 0 {
		extcomms = append(extcomms, "rt")
		extcomms = append(extcomms, m["rt"]...)
	}

	r := &bgp.MUPInterworkSegmentDiscoveryRoute{
		RD:     rd,
		Prefix: prefix,
	}
	return bgp.NewMUPNLRI(afi, bgp.MUP_ARCH_TYPE_UNDEFINED, bgp.MUP_ROUTE_TYPE_INTERWORK_SEGMENT_DISCOVERY, r), psid, extcomms, nil
}

func parseMUPDirectSegmentDiscoveryRouteArgs(args []string, afi uint16, nexthop string) (bgp.NLRI, *bgp.PathAttributePrefixSID, []string, error) {
	// Format:
	// <ip address> rd <rd> prefix <prefix> locator-node-length <locator-node-length> function-length <function-length> behavior <behavior> [rt <rt>...] [mup <segment identifier>]
	req := 15
	if len(args) < req {
		return nil, nil, nil, fmt.Errorf("%d args required at least, but got %d", req, len(args))
	}
	m, err := extractReserved(args, map[string]int{
		"rd":                  paramSingle,
		"rt":                  paramSingle,
		"prefix":              paramSingle,
		"locator-node-length": paramSingle,
		"function-length":     paramSingle,
		"behavior":            paramSingle,
		"mup":                 paramSingle,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	if len(m[""]) < 1 {
		return nil, nil, nil, fmt.Errorf("specify address")
	}
	for _, f := range []string{"rd", "rt", "prefix", "locator-node-length", "function-length", "behavior", "mup"} {
		for len(m[f]) == 0 {
			return nil, nil, nil, fmt.Errorf("specify %s", f)
		}
	}
	rd, err := bgp.ParseRouteDistinguisher(m["rd"][0])
	if err != nil {
		return nil, nil, nil, err
	}
	addr, err := netip.ParseAddr(m[""][0])
	if err != nil {
		return nil, nil, nil, err
	}
	nh, err := netip.ParseAddr(nexthop)
	if err != nil {
		return nil, nil, nil, err
	}
	if nh.Is4() {
		return nil, nil, nil, fmt.Errorf("nexthop should be IPv6 address: %s", nexthop)
	}
	sid, err := netip.ParsePrefix(m["prefix"][0])
	if err != nil {
		return nil, nil, nil, err
	}
	nl, err := strconv.ParseUint(m["locator-node-length"][0], 10, 8)
	if err != nil {
		return nil, nil, nil, err
	}
	fl, err := strconv.ParseUint(m["function-length"][0], 10, 8)
	if err != nil {
		return nil, nil, nil, err
	}
	behavior, ok := api.SRV6Behavior_value["SRV6_BEHAVIOR_"+m["behavior"][0]]
	if !ok {
		return nil, nil, nil, fmt.Errorf("unknown behavior: %s", m["behavior"][0])
	}
	psid := bgp.NewPathAttributePrefixSID(
		bgp.NewSRv6ServiceTLV(
			bgp.TLVTypeSRv6L3Service,
			bgp.NewSRv6InformationSubTLV(
				sid.Addr(),
				bgp.SRBehavior(behavior),
				bgp.NewSRv6SIDStructureSubSubTLV(uint8(sid.Bits()), uint8(nl), uint8(fl), 0, 0, 0),
			),
		),
	)

	extcomms := make([]string, 0)
	if len(m["rt"]) > 0 {
		extcomms = append(extcomms, "rt")
		extcomms = append(extcomms, m["rt"]...)
	}
	if len(m["mup"]) > 0 {
		extcomms = append(extcomms, "mup", m["mup"][0])
	}

	r := &bgp.MUPDirectSegmentDiscoveryRoute{
		RD:      rd,
		Address: addr,
	}
	return bgp.NewMUPNLRI(afi, bgp.MUP_ARCH_TYPE_UNDEFINED, bgp.MUP_ROUTE_TYPE_DIRECT_SEGMENT_DISCOVERY, r), psid, extcomms, nil
}

func parseTeid(s string) (teid netip.Addr, err error) {
	// Hex format
	if s, ok := strings.CutPrefix(s, "0x"); ok {
		b, err := hex.DecodeString(s)
		if err != nil {
			return teid, err
		}
		if len(b) < 4 {
			b = append(b, make([]byte, 4-len(b))...)
		}
		if teid, ok = netip.AddrFromSlice(b); ok {
			return teid, nil
		}
	}
	// IP address format
	if teid, err = netip.ParseAddr(s); err == nil {
		return teid, err
	}
	// Decimal format
	b := [4]byte{}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return teid, err
	}
	binary.BigEndian.PutUint32(b[:], uint32(n))
	teid = netip.AddrFrom4(b)
	return teid, nil
}

func parseMUPType1SessionTransformedRouteArgs(args []string, afi uint16) (bgp.NLRI, *bgp.PathAttributePrefixSID, []string, error) {
	// Format:
	// <ip prefix> rd <rd> [rt <rt>...] teid <teid> qfi <qfi> endpoint <endpoint> [source <source>]
	req := 5
	if len(args) < req {
		return nil, nil, nil, fmt.Errorf("%d args required at least, but got %d", req, len(args))
	}
	m, err := extractReserved(args, map[string]int{
		"rd":       paramSingle,
		"rt":       paramSingle,
		"teid":     paramSingle,
		"qfi":      paramSingle,
		"endpoint": paramSingle,
		"source":   paramSingle,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	if len(m[""]) < 1 {
		return nil, nil, nil, fmt.Errorf("specify prefix")
	}
	for _, f := range []string{"rd", "rt", "teid", "qfi", "endpoint"} {
		for len(m[f]) == 0 {
			return nil, nil, nil, fmt.Errorf("specify %s", f)
		}
	}
	rd, err := bgp.ParseRouteDistinguisher(m["rd"][0])
	if err != nil {
		return nil, nil, nil, err
	}
	prefix, err := netip.ParsePrefix(m[""][0])
	if err != nil {
		return nil, nil, nil, err
	}
	teid, err := parseTeid(m["teid"][0])
	if err != nil {
		return nil, nil, nil, err
	}
	qfi, err := strconv.ParseUint(m["qfi"][0], 10, 8)
	if err != nil {
		return nil, nil, nil, err
	}
	ea, err := netip.ParseAddr(m["endpoint"][0])
	if err != nil {
		return nil, nil, nil, err
	}
	extcomms := make([]string, 0)
	if len(m["rt"]) > 0 {
		extcomms = append(extcomms, "rt")
		extcomms = append(extcomms, m["rt"]...)
	}

	r := &bgp.MUPType1SessionTransformedRoute{
		RD:                    rd,
		Prefix:                prefix,
		TEID:                  teid,
		QFI:                   uint8(qfi),
		EndpointAddressLength: uint8(ea.BitLen()),
		EndpointAddress:       ea,
	}
	if len(m["source"]) > 0 {
		sa, err := netip.ParseAddr(m["source"][0])
		if err != nil {
			return nil, nil, nil, err
		}
		r.SourceAddressLength = uint8(sa.BitLen())
		r.SourceAddress = &sa
	}
	return bgp.NewMUPNLRI(afi, bgp.MUP_ARCH_TYPE_UNDEFINED, bgp.MUP_ROUTE_TYPE_TYPE_1_SESSION_TRANSFORMED, r), nil, extcomms, nil
}

func parseMUPType2SessionTransformedRouteArgs(args []string, afi uint16) (bgp.NLRI, *bgp.PathAttributePrefixSID, []string, error) {
	// Format:
	// <endpoint address> rd <rd> [rt <rt>...] endpoint-address-length <endpoint-address-length> teid <teid> [mup <segment identifier>]
	req := 6
	if len(args) < req {
		return nil, nil, nil, fmt.Errorf("%d args required at least, but got %d", req, len(args))
	}
	m, err := extractReserved(args, map[string]int{
		"rd":                      paramSingle,
		"rt":                      paramSingle,
		"endpoint-address-length": paramSingle,
		"teid":                    paramSingle,
		"mup":                     paramSingle,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	if len(m[""]) < 1 {
		return nil, nil, nil, fmt.Errorf("specify endpoint")
	}
	for _, f := range []string{"rd", "rt", "endpoint-address-length", "teid", "mup"} {
		for len(m[f]) == 0 {
			return nil, nil, nil, fmt.Errorf("specify %s", f)
		}
	}
	rd, err := bgp.ParseRouteDistinguisher(m["rd"][0])
	if err != nil {
		return nil, nil, nil, err
	}
	ea, err := netip.ParseAddr(m[""][0])
	if err != nil {
		return nil, nil, nil, err
	}
	eaLen, err := strconv.ParseUint(m["endpoint-address-length"][0], 10, 8)
	if err != nil {
		return nil, nil, nil, err
	}
	if ea.Is4() && eaLen > 64 || ea.Is6() && eaLen > 160 {
		return nil, nil, nil, fmt.Errorf("endpoint-address-length too large: %d", eaLen)
	}
	teid, err := parseTeid(m["teid"][0])
	if err != nil {
		return nil, nil, nil, err
	}
	extcomms := make([]string, 0)
	if len(m["rt"]) > 0 {
		extcomms = append(extcomms, "rt")
		extcomms = append(extcomms, m["rt"]...)
	}
	if len(m["mup"]) > 0 {
		extcomms = append(extcomms, "mup", m["mup"][0])
	}

	r := &bgp.MUPType2SessionTransformedRoute{
		RD:                    rd,
		EndpointAddressLength: uint8(eaLen),
		EndpointAddress:       ea,
		TEID:                  teid,
	}
	return bgp.NewMUPNLRI(afi, bgp.MUP_ARCH_TYPE_UNDEFINED, bgp.MUP_ROUTE_TYPE_TYPE_2_SESSION_TRANSFORMED, r), nil, extcomms, nil
}

func parseMUPArgs(args []string, afi uint16, nexthop string) (bgp.NLRI, *bgp.PathAttributePrefixSID, []string, error) {
	if len(args) < 1 {
		return nil, nil, nil, fmt.Errorf("lack of args. need 1 but %d", len(args))
	}
	subtype := args[0]
	args = args[1:]
	switch subtype {
	case "isd":
		return parseMUPInterworkSegmentDiscoveryRouteArgs(args, afi, nexthop)
	case "dsd":
		return parseMUPDirectSegmentDiscoveryRouteArgs(args, afi, nexthop)
	case "t1st":
		return parseMUPType1SessionTransformedRouteArgs(args, afi)
	case "t2st":
		return parseMUPType2SessionTransformedRouteArgs(args, afi)
	}
	return nil, nil, nil, fmt.Errorf("invalid subtype. expect [isd|dsd|t1st|t2st] but %s", subtype)
}

func parseIgpRouterId(input string) (string, error) {
	if len(input) == 0 {
		return "", nil
	}
	// IPv4 format: "10.0.0.1"
	if ip := net.ParseIP(input); ip != nil && ip.To4() != nil {
		return string(ip.To4()), nil
	}
	// IS-IS non-pseudonode format: "0000.0000.0001"
	if len(input) == 14 && strings.Count(input, ".") == 2 {
		parts := strings.Split(input, ".")
		if len(parts) == 3 && len(parts[0]) == 4 && len(parts[1]) == 4 && len(parts[2]) == 4 {
			var result []byte
			for _, part := range parts {
				if bytes, err := hex.DecodeString(part); err == nil && len(bytes) == 2 {
					result = append(result, bytes...)
				} else {
					return "", fmt.Errorf("invalid IS-IS Router ID format: cannot decode hex string %s", part)
				}
			}
			if len(result) == 6 {
				return string(result), nil
			}
		}
		return "", fmt.Errorf("invalid IS-IS Router ID format: %s", input)
	}
	// IS-IS pseudonode format: "0000.0000.0001-01"
	if strings.Contains(input, "-") && len(input) == 17 {
		parts := strings.Split(input, "-")
		if len(parts) == 2 && len(parts[1]) == 2 {
			// Process the first part like IS-IS non-pseudonode
			idParts := strings.Split(parts[0], ".")
			if len(idParts) == 3 && len(idParts[0]) == 4 && len(idParts[1]) == 4 && len(idParts[2]) == 4 {
				var result []byte
				for _, part := range idParts {
					if bytes, err := hex.DecodeString(part); err == nil && len(bytes) == 2 {
						result = append(result, bytes...)
					} else {
						return "", fmt.Errorf("invalid IS-IS pseudonode Router ID format: cannot decode hex string %s", part)
					}
				}
				// Add pseudonode ID byte
				if pseudoByte, err := hex.DecodeString(parts[1]); err == nil && len(pseudoByte) == 1 {
					result = append(result, pseudoByte[0])
				} else {
					return "", fmt.Errorf("invalid IS-IS pseudonode Router ID format: cannot decode pseudonode ID %s", parts[1])
				}
				if len(result) == 7 {
					return string(result), nil
				}
			}
		}
		return "", fmt.Errorf("invalid IS-IS pseudonode Router ID format: %s", input)
	}
	// OSPF pseudonode format: "10.0.0.1:192.168.1.1"
	if strings.Contains(input, ":") {
		parts := strings.Split(input, ":")
		if len(parts) == 2 {
			ip1 := net.ParseIP(parts[0])
			ip2 := net.ParseIP(parts[1])
			if ip1 != nil && ip1.To4() != nil && ip2 != nil && ip2.To4() != nil {
				result := make([]byte, 8)
				copy(result[:4], ip1.To4())
				copy(result[4:], ip2.To4())
				return string(result), nil
			}
		}
		return "", fmt.Errorf("invalid OSPF pseudonode Router ID format: %s", input)
	}

	return "", fmt.Errorf("unsupported IGP Router ID format: %s", input)
}

func parseLsNodeNLRIType(args []string) (bgp.NLRI, *bgp.PathAttributeLs, error) {
	// Format:
	// <ip prefix> protocol <bgp|isis-l2> identifier <identifier> local-asn <asn> local-bgp-ls-id <bgp-ls-id> local-igp-router-id <igp-router-id>
	req := 7
	if len(args) < req {
		return nil, nil, fmt.Errorf("%d args required at least, but got %d", req, len(args))
	}

	m, err := extractReserved(args, map[string]int{
		"protocol":                       paramSingle,
		"identifier":                     paramSingle,
		"local-asn":                      paramSingle, // optional, one of the four local fields is required
		"local-bgp-ls-id":                paramSingle, // optional, one of the four local fields is required
		"local-bgp-router-id":            paramSingle, // optional, one of the four local fields is required
		"local-igp-router-id":            paramSingle, // optional, one of the four local fields is required
		"local-bgp-confederation-member": paramSingle, // optional
		"node-name":                      paramSingle, // optional
		"isis-area-id":                   paramSingle, // optional
		"sr-algorithm":                   paramList,   // optional
	})
	if err != nil {
		return nil, nil, err
	}

	protocol, err := strconv.ParseUint(m["protocol"][0], 10, 64)
	if err != nil {
		return nil, nil, err
	}

	identifier, err := strconv.ParseUint(m["identifier"][0], 10, 64)
	if err != nil {
		return nil, nil, err
	}

	var localAsn uint64
	if asn, ok := m["local-asn"]; ok && len(asn) > 0 {
		localAsn, err = strconv.ParseUint(asn[0], 10, 32)
		if err != nil {
			return nil, nil, err
		}
	}
	var localBgpLsId uint64
	if bgpLsId, ok := m["local-bgp-ls-id"]; ok && len(bgpLsId) > 0 {
		localBgpLsId, err = strconv.ParseUint(bgpLsId[0], 10, 64)
		if err != nil {
			return nil, nil, err
		}
	}
	var localBgpRouterId netip.Addr
	if bgpRouterId, ok := m["local-bgp-router-id"]; ok && len(bgpRouterId) > 0 {
		localBgpRouterId, err = netip.ParseAddr(bgpRouterId[0])
		if err != nil {
			return nil, nil, err
		}
	}
	var localBgpConfederationMember uint64
	if confMember, ok := m["local-bgp-confederation-member"]; ok && len(confMember) > 0 {
		localBgpConfederationMember, err = strconv.ParseUint(confMember[0], 10, 64)
		if err != nil {
			return nil, nil, err
		}
	}
	var localIgpRouterId string
	if igpRouterId, ok := m["local-igp-router-id"]; ok && len(igpRouterId) > 0 {
		localIgpRouterId, err = parseIgpRouterId(igpRouterId[0])
		if err != nil {
			return nil, nil, fmt.Errorf("invalid local-igp-router-id: %v", err)
		}
	}
	lnd := &bgp.LsNodeDescriptor{
		Asn:                    uint32(localAsn),
		BGPLsID:                uint32(localBgpLsId),
		OspfAreaID:             0,
		PseudoNode:             false,
		IGPRouterID:            localIgpRouterId,
		BGPRouterID:            localBgpRouterId,
		BGPConfederationMember: uint32(localBgpConfederationMember),
	}
	lndTLV := bgp.NewLsTLVNodeDescriptor(lnd, bgp.LS_TLV_LOCAL_NODE_DESC)

	const CodeLen = 1
	const topologyLen = 8
	LsNLRIhdrlen := lndTLV.Len() + topologyLen + CodeLen
	lsNlri := bgp.LsNLRI{
		NLRIType:   bgp.LS_NLRI_TYPE_NODE,
		Length:     uint16(LsNLRIhdrlen),
		ProtocolID: bgp.LsProtocolID(protocol),
		Identifier: identifier,
	}
	nlri := &bgp.LsAddrPrefix{
		Type:   bgp.LS_NLRI_TYPE_NODE,
		Length: 4,
		NLRI: &bgp.LsNodeNLRI{
			LsNLRI:        lsNlri,
			LocalNodeDesc: &lndTLV,
		},
	}

	// Create PathAttributeLs if there are TLVs to include
	var pathAttributeLs *bgp.PathAttributeLs
	var tlvs []bgp.LsTLVInterface

	var nodeName string
	if name, ok := m["node-name"]; ok && len(name) > 0 {
		nodeName = name[0]
		tlv := bgp.NewLsTLVNodeName(&nodeName)
		if tlv != nil {
			tlvs = append(tlvs, tlv)
		}
	}

	// Parse ISIS Area ID for LsTLVIsisArea
	var isisAreaBytes []byte
	if areaId, ok := m["isis-area-id"]; ok && len(areaId) > 0 {
		if bytes, err := hex.DecodeString(areaId[0]); err == nil {
			isisAreaBytes = bytes
		} else {
			return nil, nil, fmt.Errorf("invalid isis-area-id format, must be hex string: %v", err)
		}
		tlv := bgp.NewLsTLVIsisArea(&isisAreaBytes)
		if tlv != nil {
			tlvs = append(tlvs, tlv)
		}
	}

	// Parse SR Algorithm values and create TLV
	var srAlgorithmBytes []byte
	if algorithms, ok := m["sr-algorithm"]; ok && len(algorithms) > 0 {
		for _, algoStr := range algorithms {
			algo, err := strconv.ParseUint(algoStr, 10, 8)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid sr-algorithm value '%s': %v", algoStr, err)
			}
			srAlgorithmBytes = append(srAlgorithmBytes, uint8(algo))
		}
		tlv := bgp.NewLsTLVSrAlgorithm(&srAlgorithmBytes)
		if tlv != nil {
			tlvs = append(tlvs, tlv)
		}
	}

	if len(tlvs) > 0 {
		pathAttributeLs = &bgp.PathAttributeLs{
			PathAttribute: bgp.PathAttribute{
				Type:  bgp.BGP_ATTR_TYPE_LS,
				Flags: bgp.BGP_ATTR_FLAG_OPTIONAL,
			},
			TLVs: tlvs,
		}
	}

	return nlri, pathAttributeLs, nil
}

func parseLsPrefixV6NLRIType(args []string) (bgp.NLRI, *bgp.PathAttributeLs, error) {
	// Format:
	// protocol <protocol> identifier <identifier> local-asn <asn> local-bgp-ls-id <bgp-ls-id> local-igp-router-id <igp-router-id> ip-reachability-info <ipv6-prefix>
	req := 9
	if len(args) < req {
		return nil, nil, fmt.Errorf("%d args required at least, but got %d", req, len(args))
	}

	m, err := extractReserved(args, map[string]int{
		"protocol":                       paramSingle,
		"identifier":                     paramSingle,
		"local-asn":                      paramSingle, // optional, one of the four local fields is required
		"local-bgp-ls-id":                paramSingle, // optional, one of the four local fields is required
		"local-bgp-router-id":            paramSingle, // optional, one of the four local fields is required
		"local-igp-router-id":            paramSingle, // optional, one of the four local fields is required
		"local-bgp-confederation-member": paramSingle, // optional
		"ip-reachability-info":           paramSingle,
	})
	if err != nil {
		return nil, nil, err
	}

	protocol, err := strconv.ParseUint(m["protocol"][0], 10, 64)
	if err != nil {
		return nil, nil, err
	}

	identifier, err := strconv.ParseUint(m["identifier"][0], 10, 64)
	if err != nil {
		return nil, nil, err
	}

	var localAsn uint64
	if asn, ok := m["local-asn"]; ok && len(asn) > 0 {
		localAsn, err = strconv.ParseUint(asn[0], 10, 32)
		if err != nil {
			return nil, nil, err
		}
	}
	var localBgpLsId uint64
	if bgpLsId, ok := m["local-bgp-ls-id"]; ok && len(bgpLsId) > 0 {
		localBgpLsId, err = strconv.ParseUint(bgpLsId[0], 10, 64)
		if err != nil {
			return nil, nil, err
		}
	}
	var localBgpRouterId netip.Addr
	if bgpRouterId, ok := m["local-bgp-router-id"]; ok && len(bgpRouterId) > 0 {
		localBgpRouterId, err = netip.ParseAddr(bgpRouterId[0])
		if err != nil {
			return nil, nil, err
		}
	}
	var localBgpConfederationMember uint64
	if confMember, ok := m["local-bgp-confederation-member"]; ok && len(confMember) > 0 {
		localBgpConfederationMember, err = strconv.ParseUint(confMember[0], 10, 64)
		if err != nil {
			return nil, nil, err
		}
	}
	var localIgpRouterId string
	if igpRouterId, ok := m["local-igp-router-id"]; ok && len(igpRouterId) > 0 {
		localIgpRouterId, err = parseIgpRouterId(igpRouterId[0])
		if err != nil {
			return nil, nil, fmt.Errorf("invalid local-igp-router-id: %v", err)
		}
	}
	// Create Local Node Descriptor TLV
	lnd := &bgp.LsNodeDescriptor{
		Asn:                    uint32(localAsn),
		BGPLsID:                uint32(localBgpLsId),
		OspfAreaID:             0,
		PseudoNode:             false,
		IGPRouterID:            localIgpRouterId,
		BGPRouterID:            localBgpRouterId,
		BGPConfederationMember: uint32(localBgpConfederationMember),
	}
	lndTLV := bgp.NewLsTLVNodeDescriptor(lnd, bgp.LS_TLV_LOCAL_NODE_DESC)

	// Parse IP Reachability Information (required)
	if _, ok := m["ip-reachability-info"]; !ok {
		return nil, nil, fmt.Errorf("ip-reachability-info is required")
	}
	ipReachPrefix, err := netip.ParsePrefix(m["ip-reachability-info"][0])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid ip-reachability-info format: %v", err)
	}
	if !ipReachPrefix.Addr().Is6() {
		return nil, nil, fmt.Errorf("ip-reachability-info must be IPv6 prefix for PrefixV6 NLRI")
	}

	// Create Prefix Descriptor using LsPrefixDescriptor and NewLsPrefixTLVs
	prefixDescriptor := &bgp.LsPrefixDescriptor{
		IPReachability: []netip.Prefix{ipReachPrefix},
		OSPFRouteType:  0, // Default route type
	}
	prefixDescTLVs := bgp.NewLsPrefixTLVs(prefixDescriptor)

	// Calculate total length
	const CodeLen = 1
	const topologyLen = 8
	prefixDescLen := 0
	for _, tlv := range prefixDescTLVs {
		prefixDescLen += tlv.Len()
	}
	LsNLRIhdrlen := lndTLV.Len() + prefixDescLen + topologyLen + CodeLen

	lsNlri := bgp.LsNLRI{
		NLRIType:   bgp.LS_NLRI_TYPE_PREFIX_IPV6,
		Length:     uint16(LsNLRIhdrlen),
		ProtocolID: bgp.LsProtocolID(protocol),
		Identifier: identifier,
	}
	nlri := &bgp.LsAddrPrefix{
		Type:   bgp.LS_NLRI_TYPE_PREFIX_IPV6,
		Length: 4,
		NLRI: &bgp.LsPrefixV6NLRI{
			LsNLRI:        lsNlri,
			LocalNodeDesc: &lndTLV,
			PrefixDesc:    prefixDescTLVs,
		},
	}

	return nlri, nil, nil
}

func parseLsLinkNLRIType(args []string) (bgp.NLRI, *bgp.PathAttributeLs, error) {
	// Format:
	// <ip prefix> protocol <protocol> identifier <identifier> asn <asn> bgp-ls-id <bgp-ls-id> ospf
	req := 7
	if len(args) < req {
		return nil, nil, fmt.Errorf("%d args required at least, but got %d", req, len(args))
	}

	m, err := extractReserved(args, map[string]int{
		"protocol":                        paramSingle,
		"identifier":                      paramSingle,
		"local-asn":                       paramSingle, // optional, one of the four local fields is required
		"local-bgp-ls-id":                 paramSingle, // optional, one of the four local fields is required
		"local-bgp-router-id":             paramSingle, // optional, one of the four local fields is required
		"local-igp-router-id":             paramSingle, // optional, one of the four local fields is required
		"local-bgp-confederation-member":  paramSingle, // optional
		"remote-asn":                      paramSingle, // optional, one of the four remote fields is required
		"remote-bgp-ls-id":                paramSingle, // optional, one of the four remote fields is required
		"remote-bgp-router-id":            paramSingle, // optional, one of the four remote fields is required
		"remote-igp-router-id":            paramSingle, // optional, one of the four remote fields is required
		"remote-bgp-confederation-member": paramSingle, // optional
		"link-local-id":                   paramSingle, // optional, link local id
		"link-remote-id":                  paramSingle, // optional, link remote id
		"ipv4-interface-address":          paramSingle, // optional, IPv4 interface address
		"ipv4-neighbor-address":           paramSingle, // optional, IPv4 neighbor address
		"ipv6-interface-address":          paramSingle, // optional, IPv6 interface address
		"ipv6-neighbor-address":           paramSingle, // optional, IPv6 neighbor address
		"sid":                             paramSingle, // optional
		"sid-type":                        paramSingle, // optional
		"v-flag":                          paramFlag,   // optional
		"l-flag":                          paramFlag,   // optional
		"b-flag":                          paramFlag,   // optional
		"p-flag":                          paramFlag,   // optional
		"weight":                          paramSingle, // optional
		"max-link-bandwidth":              paramSingle, // optional, maximum link bandwidth
		"te-default-metric":               paramSingle, // optional, te default metric
		"metric":                          paramSingle, // optional, metric
		"srv6-endpoint-behavior":          paramSingle, // optional, srv6 end.x sid
		"srv6-sids":                       paramList,   // optional, srv6 end.x sid
		"srv6-weight":                     paramSingle, // optional, srv6 end.x sid
		"srv6-flags":                      paramSingle, // optional, srv6 end.x sid
		"srv6-algo":                       paramSingle, // optional, srv6 end.x sid
		"srv6-structure-lb":               paramSingle, // optional, srv6 sid structure
		"srv6-structure-ln":               paramSingle, // optional, srv6 sid structure
		"srv6-structure-fun":              paramSingle, // optional, srv6 sid structure
		"srv6-structure-arg":              paramSingle, // optional, srv6 sid structure
	})
	if err != nil {
		return nil, nil, err
	}

	protocol, err := strconv.ParseUint(m["protocol"][0], 10, 64)
	if err != nil {
		return nil, nil, err
	}

	identifier, err := strconv.ParseUint(m["identifier"][0], 10, 64)
	if err != nil {
		return nil, nil, err
	}

	var localAsn uint64
	if asn, ok := m["local-asn"]; ok && len(asn) > 0 {
		localAsn, err = strconv.ParseUint(asn[0], 10, 32)
		if err != nil {
			return nil, nil, err
		}
	}
	var localBgpLsId uint64
	if bgpLsId, ok := m["local-bgp-ls-id"]; ok && len(bgpLsId) > 0 {
		localBgpLsId, err = strconv.ParseUint(bgpLsId[0], 10, 64)
		if err != nil {
			return nil, nil, err
		}
	}
	var localBgpRouterId netip.Addr
	if bgpRouterId, ok := m["local-bgp-router-id"]; ok && len(bgpRouterId) > 0 {
		localBgpRouterId, err = netip.ParseAddr(bgpRouterId[0])
		if err != nil {
			return nil, nil, err
		}
	}
	var localBgpConfederationMember uint64
	if confMember, ok := m["local-bgp-confederation-member"]; ok && len(confMember) > 0 {
		localBgpConfederationMember, err = strconv.ParseUint(confMember[0], 10, 64)
		if err != nil {
			return nil, nil, err
		}
	}
	var localIgpRouterId string
	if igpRouterId, ok := m["local-igp-router-id"]; ok && len(igpRouterId) > 0 {
		localIgpRouterId, err = parseIgpRouterId(igpRouterId[0])
		if err != nil {
			return nil, nil, fmt.Errorf("invalid local-igp-router-id: %v", err)
		}
	}
	lnd := &bgp.LsNodeDescriptor{
		Asn:                    uint32(localAsn),
		BGPLsID:                uint32(localBgpLsId),
		OspfAreaID:             0,
		PseudoNode:             false,
		IGPRouterID:            localIgpRouterId,
		BGPRouterID:            localBgpRouterId,
		BGPConfederationMember: uint32(localBgpConfederationMember),
	}

	var remoteAsn uint64
	if asn, ok := m["remote-asn"]; ok && len(asn) > 0 {
		remoteAsn, err = strconv.ParseUint(asn[0], 10, 32)
		if err != nil {
			return nil, nil, err
		}
	}
	var remoteBgpLsId uint64
	if bgpLsId, ok := m["remote-bgp-ls-id"]; ok && len(bgpLsId) > 0 {
		remoteBgpLsId, err = strconv.ParseUint(bgpLsId[0], 10, 64)
		if err != nil {
			return nil, nil, err
		}
	}
	var remoteBgpRouterId netip.Addr
	if bgpRouterId, ok := m["remote-bgp-router-id"]; ok && len(bgpRouterId) > 0 {
		remoteBgpRouterId, err = netip.ParseAddr(bgpRouterId[0])
		if err != nil {
			return nil, nil, err
		}
	}
	var remoteBgpConfederationMember uint64
	if confMember, ok := m["remote-bgp-confederation-member"]; ok && len(confMember) > 0 {
		remoteBgpConfederationMember, err = strconv.ParseUint(confMember[0], 10, 64)
		if err != nil {
			return nil, nil, err
		}
	}
	var remoteIgpRouterId string
	if igpRouterId, ok := m["remote-igp-router-id"]; ok && len(igpRouterId) > 0 {
		remoteIgpRouterId, err = parseIgpRouterId(igpRouterId[0])
		if err != nil {
			return nil, nil, fmt.Errorf("invalid remote-igp-router-id: %v", err)
		}
	}
	rnd := &bgp.LsNodeDescriptor{
		Asn:                    uint32(remoteAsn),
		BGPLsID:                uint32(remoteBgpLsId),
		OspfAreaID:             0,
		PseudoNode:             false,
		IGPRouterID:            remoteIgpRouterId,
		BGPRouterID:            remoteBgpRouterId,
		BGPConfederationMember: uint32(remoteBgpConfederationMember),
	}

	var interfaceAddrIPv4 netip.Addr
	if ipv4IntfAddr, ok := m["ipv4-interface-address"]; ok && len(ipv4IntfAddr) > 0 {
		if interfaceAddrIPv4, err = netip.ParseAddr(ipv4IntfAddr[0]); err != nil {
			return nil, nil, err
		}
	}
	var neighborAddrIPv4 netip.Addr
	if ipv4NeighAddr, ok := m["ipv4-neighbor-address"]; ok && len(ipv4NeighAddr) > 0 {
		if neighborAddrIPv4, err = netip.ParseAddr(ipv4NeighAddr[0]); err != nil {
			return nil, nil, err
		}
	}
	var interfaceAddrIPv6 netip.Addr
	if ipv6IntfAddr, ok := m["ipv6-interface-address"]; ok && len(ipv6IntfAddr) > 0 {
		if interfaceAddrIPv6, err = netip.ParseAddr(ipv6IntfAddr[0]); err != nil {
			return nil, nil, err
		}
	}
	var neighborAddrIPv6 netip.Addr
	if ipv6NeighAddr, ok := m["ipv6-neighbor-address"]; ok && len(ipv6NeighAddr) > 0 {
		if neighborAddrIPv6, err = netip.ParseAddr(ipv6NeighAddr[0]); err != nil {
			return nil, nil, err
		}
	}
	var linkLocalId uint32
	if linkID, ok := m["link-local-id"]; ok && len(linkID) > 0 {
		linkLocalIdVal, err := strconv.ParseUint(linkID[0], 10, 64)
		if err != nil {
			return nil, nil, err
		}
		linkLocalId = uint32(linkLocalIdVal)
	}
	var linkRemoteId uint32
	if linkID, ok := m["link-remote-id"]; ok && len(linkID) > 0 {
		linkRemoteIdVal, err := strconv.ParseUint(linkID[0], 10, 32)
		if err != nil {
			return nil, nil, err
		}
		linkRemoteId = uint32(linkRemoteIdVal)
	}
	ld := &bgp.LsLinkDescriptor{
		LinkLocalID:  &linkLocalId,
		LinkRemoteID: &linkRemoteId,
	}

	// Set IPv4/IPv6 addresses only if they are actually specified
	if _, ok := m["ipv4-interface-address"]; ok && interfaceAddrIPv4.IsValid() {
		ld.InterfaceAddrIPv4 = &interfaceAddrIPv4
	}
	if _, ok := m["ipv4-neighbor-address"]; ok && neighborAddrIPv4.IsValid() {
		ld.NeighborAddrIPv4 = &neighborAddrIPv4
	}
	if _, ok := m["ipv6-interface-address"]; ok && interfaceAddrIPv6.IsValid() {
		ld.InterfaceAddrIPv6 = &interfaceAddrIPv6
	}
	if _, ok := m["ipv6-neighbor-address"]; ok && neighborAddrIPv6.IsValid() {
		ld.NeighborAddrIPv6 = &neighborAddrIPv6
	}

	lndTLV := bgp.NewLsTLVNodeDescriptor(lnd, bgp.LS_TLV_LOCAL_NODE_DESC)
	rndTLV := bgp.NewLsTLVNodeDescriptor(rnd, bgp.LS_TLV_REMOTE_NODE_DESC)
	ldTLV := bgp.NewLsLinkTLVs(ld)

	var sidTypeString string
	if sidType, ok := m["sid-type"]; ok && len(sidType) > 0 {
		sidTypeString = m["sid-type"][0]
	}
	sidtype := lsTLVTypeSelect(sidTypeString)

	var peerNodeFlag uint8
	if _, ok := m["v-flag"]; ok {
		peerNodeFlag = peerNodeFlag | 0x80
	}
	if _, ok := m["l-flag"]; ok {
		peerNodeFlag = peerNodeFlag | 0x40
	}
	if _, ok := m["b-flag"]; ok {
		peerNodeFlag = peerNodeFlag | 0x20
	}
	if _, ok := m["p-flag"]; ok {
		peerNodeFlag = peerNodeFlag | 0x10
	}

	var lsTLVWeight uint64
	if weight, ok := m["weight"]; ok && len(weight) > 0 {
		lsTLVWeight, err = strconv.ParseUint(m["weight"][0], 10, 64)
		if err != nil {
			return nil, nil, err
		}
	}
	var lsTLVSid uint64
	if sid, ok := m["sid"]; ok && len(sid) > 0 {
		lsTLVSid, err = strconv.ParseUint(m["sid"][0], 10, 64)
		if err != nil {
			return nil, nil, err
		}
	}

	const lsTlvLen = 7
	const t = bgp.BGP_ATTR_TYPE_LS
	const pathAttrHdrLen = 4
	var tlvs []bgp.LsTLVInterface
	length := uint16(pathAttrHdrLen)

	if sidtype != 0 && lsTLVSid != 0 {
		length += lsTlvLen
		switch sidtype {
		case bgp.LS_TLV_PEER_NODE_SID:

			lsTLV := &bgp.LsTLVPeerNodeSID{
				LsTLV: bgp.LsTLV{
					Type:   sidtype,
					Length: uint16(lsTlvLen),
				},
				Flags:  peerNodeFlag,
				Weight: uint8(lsTLVWeight),
				SID:    uint32(lsTLVSid),
			}
			tlvs = append(tlvs, lsTLV)
		case bgp.LS_TLV_ADJACENCY_SID:
			lsTLV := &bgp.LsTLVAdjacencySID{
				LsTLV: bgp.LsTLV{
					Type:   sidtype,
					Length: uint16(lsTlvLen),
				},
				Flags:  peerNodeFlag,
				Weight: uint8(lsTLVWeight),
				SID:    uint32(lsTLVSid),
			}
			tlvs = append(tlvs, lsTLV)
		case bgp.LS_TLV_PEER_SET_SID:
			lsTLV := &bgp.LsTLVPeerSetSID{
				LsTLV: bgp.LsTLV{
					Type:   sidtype,
					Length: uint16(lsTlvLen),
				},
				Flags:  peerNodeFlag,
				Weight: uint8(lsTLVWeight),
				SID:    uint32(lsTLVSid),
			}
			tlvs = append(tlvs, lsTLV)
		}
	}

	if maxBandwidthStr, ok := m["max-link-bandwidth"]; ok && len(maxBandwidthStr) > 0 {
		maxBandwidth, err := strconv.ParseFloat(maxBandwidthStr[0], 32)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid max-link-bandwidth: %v", err)
		}
		lsTLV := &bgp.LsTLVMaxLinkBw{
			LsTLV: bgp.LsTLV{
				Type:   bgp.LS_TLV_MAX_LINK_BANDWIDTH,
				Length: 4,
			},
			Bandwidth: float32(maxBandwidth),
		}
		tlvs = append(tlvs, lsTLV)
		length += uint16(lsTLV.Len())
	}

	if teMetricStr, ok := m["te-default-metric"]; ok && len(teMetricStr) > 0 {
		teMetric, err := strconv.ParseUint(teMetricStr[0], 10, 32)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid te-default-metric: %v", err)
		}
		lsTLV := &bgp.LsTLVTEDefaultMetric{
			LsTLV: bgp.LsTLV{
				Type:   bgp.LS_TLV_TE_DEFAULT_METRIC,
				Length: 4,
			},
			Metric: uint32(teMetric),
		}
		tlvs = append(tlvs, lsTLV)
		length += uint16(lsTLV.Len())
	}

	if metricStr, ok := m["metric"]; ok && len(metricStr) > 0 {
		metric, err := strconv.ParseUint(metricStr[0], 10, 32)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid metric: %v", err)
		}
		lsTLV := &bgp.LsTLVIGPMetric{
			LsTLV: bgp.LsTLV{
				Type:   bgp.LS_TLV_IGP_METRIC,
				Length: 4,
			},
			Metric: uint32(metric),
		}
		tlvs = append(tlvs, lsTLV)
		length += uint16(lsTLV.Len())
	}

	if srv6SidsStr, ok := m["srv6-sids"]; ok && len(srv6SidsStr) > 0 {
		for _, sidStr := range srv6SidsStr {
			sid := net.ParseIP(sidStr)
			if sid == nil || sid.To16() == nil {
				return nil, nil, fmt.Errorf("invalid srv6-sids: %s", sidStr)
			}

			var flags uint8
			if srv6FlagsStr, ok := m["srv6-flags"]; ok && len(srv6FlagsStr) > 0 {
				flagsVal, err := strconv.ParseUint(srv6FlagsStr[0], 10, 8)
				if err != nil {
					return nil, nil, fmt.Errorf("invalid srv6-flags: %v", err)
				}
				flags = uint8(flagsVal)
			}

			var weight uint8
			if srv6WeightStr, ok := m["srv6-weight"]; ok && len(srv6WeightStr) > 0 {
				weightVal, err := strconv.ParseUint(srv6WeightStr[0], 10, 8)
				if err != nil {
					return nil, nil, fmt.Errorf("invalid srv6-weight: %v", err)
				}
				weight = uint8(weightVal)
			}

			var algorithm uint8
			if srv6AlgoStr, ok := m["srv6-algo"]; ok && len(srv6AlgoStr) > 0 {
				algoVal, err := strconv.ParseUint(srv6AlgoStr[0], 10, 8)
				if err != nil {
					return nil, nil, fmt.Errorf("invalid srv6-algo: %v", err)
				}
				algorithm = uint8(algoVal)
			}

			var endpointBehavior uint16
			if srv6BehaviorStr, ok := m["srv6-endpoint-behavior"]; ok && len(srv6BehaviorStr) > 0 {
				behaviorVal, err := strconv.ParseUint(srv6BehaviorStr[0], 10, 16)
				if err != nil {
					return nil, nil, fmt.Errorf("invalid srv6-endpoint-behavior: %v", err)
				}
				endpointBehavior = uint16(behaviorVal)
			}

			var srv6Structure *bgp.LsSrv6SIDStructure
			if lbStr, ok := m["srv6-structure-lb"]; ok && len(lbStr) > 0 {
				locatorBlockLen, err := strconv.ParseUint(lbStr[0], 10, 8)
				if err != nil {
					return nil, nil, fmt.Errorf("invalid srv6-structure-lb: %v", err)
				}

				var locatorNodeLen, functionLen, argumentLen uint8
				if lnStr, ok := m["srv6-structure-ln"]; ok && len(lnStr) > 0 {
					lnVal, err := strconv.ParseUint(lnStr[0], 10, 8)
					if err != nil {
						return nil, nil, fmt.Errorf("invalid srv6-structure-ln: %v", err)
					}
					locatorNodeLen = uint8(lnVal)
				}
				if funStr, ok := m["srv6-structure-fun"]; ok && len(funStr) > 0 {
					funVal, err := strconv.ParseUint(funStr[0], 10, 8)
					if err != nil {
						return nil, nil, fmt.Errorf("invalid srv6-structure-fun: %v", err)
					}
					functionLen = uint8(funVal)
				}
				if argStr, ok := m["srv6-structure-arg"]; ok && len(argStr) > 0 {
					argVal, err := strconv.ParseUint(argStr[0], 10, 8)
					if err != nil {
						return nil, nil, fmt.Errorf("invalid srv6-structure-arg: %v", err)
					}
					argumentLen = uint8(argVal)
				}

				srv6Structure = &bgp.LsSrv6SIDStructure{
					LocalBlock: uint8(locatorBlockLen),
					LocalNode:  locatorNodeLen,
					LocalFunc:  functionLen,
					LocalArg:   argumentLen,
				}
			}

			lsTLV := &bgp.LsTLVSrv6EndXSID{
				LsTLV: bgp.LsTLV{
					Type:   bgp.LS_TLV_SRV6_END_X_SID,
					Length: 0,
				},
				Flags:            flags,
				Algorithm:        algorithm,
				Weight:           weight,
				EndpointBehavior: endpointBehavior,
				SIDs:             []netip.Addr{netip.AddrFrom16([16]byte(sid.To16()))},
			}
			if srv6Structure != nil {
				lsTLV.Srv6SIDStructure = *bgp.NewLsTLVSrv6SIDStructure(srv6Structure)
			}
			tlvs = append(tlvs, lsTLV)
			length += uint16(lsTLV.Len())
		}
	}

	pathAttributeLs := &bgp.PathAttributeLs{
		PathAttribute: bgp.PathAttribute{
			Flags:  bgp.PathAttrFlags[t],
			Type:   t,
			Length: length,
		},
		TLVs: tlvs,
	}
	len := len(ldTLV)
	var sum int
	for i := range len {
		sum += ldTLV[i].Len()
	}
	const CodeLen = 1
	const topologyLen = 8
	LsNLRIhdrlen := sum + lndTLV.Len() + rndTLV.Len() + topologyLen + CodeLen
	lsNlri := bgp.LsNLRI{
		NLRIType:   bgp.LS_NLRI_TYPE_LINK,
		Length:     uint16(LsNLRIhdrlen),
		ProtocolID: bgp.LsProtocolID(protocol),
		Identifier: identifier,
	}
	nlri := &bgp.LsAddrPrefix{
		Type:   bgp.LS_NLRI_TYPE_LINK,
		Length: 4,
		NLRI: &bgp.LsLinkNLRI{
			LsNLRI:         lsNlri,
			LocalNodeDesc:  &lndTLV,
			RemoteNodeDesc: &rndTLV,
			LinkDesc:       ldTLV,
		},
	}
	return nlri, pathAttributeLs, nil
}

func parseLsSRv6SIDNLRIType(args []string) (bgp.NLRI, *bgp.PathAttributeLs, error) {
	// Format:
	// gobgp global rib add -a ls srv6sid bgp identifier <identifier> local-asn <local-asn> local-bgp-ls-id <local-bgp-ls-id> local-bgp-router-id <local-bgp-router-id> [local-bgp-confederation-member <confederation-member>] sids <sids>... [multi-topology-id <multi-topology-id>...]
	req := 11
	if len(args) < req {
		return nil, nil, fmt.Errorf("%d args required at least, but got %d", req, len(args))
	}

	m, err := extractReserved(args, map[string]int{
		"protocol":                       paramSingle,
		"identifier":                     paramSingle,
		"local-asn":                      paramSingle,
		"local-bgp-ls-id":                paramSingle,
		"local-bgp-router-id":            paramSingle,
		"local-igp-router-id":            paramSingle,
		"local-bgp-confederation-member": paramSingle,
		"sids":                           paramList,
		"multi-topology-id":              paramList,
		"peer-as":                        paramSingle,
		"peer-bgp-id":                    paramSingle,
		"flags":                          paramSingle,
		"weight":                         paramSingle,
		"srv6-endpoint-behavior":         paramSingle,
		"srv6-flags":                     paramSingle,
		"srv6-algo":                      paramSingle,
		"srv6-structure-lb":              paramSingle,
		"srv6-structure-ln":              paramSingle,
		"srv6-structure-fun":             paramSingle,
		"srv6-structure-arg":             paramSingle,
	})
	if err != nil {
		return nil, nil, err
	}

	protocol, err := strconv.ParseUint(m["protocol"][0], 10, 64)
	if err != nil {
		return nil, nil, err
	}

	identifier, err := strconv.ParseUint(m["identifier"][0], 10, 64)
	if err != nil {
		return nil, nil, err
	}

	var localAsn uint64
	if asn, ok := m["local-asn"]; ok && len(asn) > 0 {
		localAsn, err = strconv.ParseUint(asn[0], 10, 32)
		if err != nil {
			return nil, nil, err
		}
	}
	var localBgpLsId uint64
	if bgpLsId, ok := m["local-bgp-ls-id"]; ok && len(bgpLsId) > 0 {
		localBgpLsId, err = strconv.ParseUint(bgpLsId[0], 10, 64)
		if err != nil {
			return nil, nil, err
		}
	}
	var localBgpRouterId netip.Addr
	if bgpRouterId, ok := m["local-bgp-router-id"]; ok && len(bgpRouterId) > 0 {
		localBgpRouterId, err = netip.ParseAddr(bgpRouterId[0])
		if err != nil {
			return nil, nil, err
		}
	}
	var localBgpConfederationMember uint64
	if confMember, ok := m["local-bgp-confederation-member"]; ok && len(confMember) > 0 {
		localBgpConfederationMember, err = strconv.ParseUint(confMember[0], 10, 64)
		if err != nil {
			return nil, nil, err
		}
	}
	var localIgpRouterId string
	if igpRouterId, ok := m["local-igp-router-id"]; ok && len(igpRouterId) > 0 {
		localIgpRouterId, err = parseIgpRouterId(igpRouterId[0])
		if err != nil {
			return nil, nil, fmt.Errorf("invalid local-igp-router-id: %v", err)
		}
	}
	lnd := &bgp.LsNodeDescriptor{
		Asn:                    uint32(localAsn),
		BGPLsID:                uint32(localBgpLsId),
		OspfAreaID:             0,
		PseudoNode:             false,
		IGPRouterID:            localIgpRouterId,
		BGPRouterID:            localBgpRouterId,
		BGPConfederationMember: uint32(localBgpConfederationMember),
	}
	lndTLV := bgp.NewLsTLVNodeDescriptor(lnd, bgp.LS_TLV_LOCAL_NODE_DESC)

	sids, ssiLen, err := apiutil.StringToNetIPLsTLVSrv6SIDInfo(m["sids"])
	if err != nil {
		return nil, nil, err
	}
	ssi := &bgp.LsTLVSrv6SIDInfo{
		LsTLV: bgp.LsTLV{
			Type:   bgp.LS_TLV_SRV6_SID_INFO,
			Length: ssiLen,
		},
		SIDs: sids,
	}

	// Parse multi-topology-id values from the reserved parameters.
	var multiTopoIDs []uint16
	if ids, ok := m["multi-topology-id"]; ok && len(ids) > 0 {
		for _, idStr := range ids {
			id, err := strconv.ParseUint(idStr, 10, 16)
			if err != nil {
				return nil, nil, err
			}
			multiTopoIDs = append(multiTopoIDs, uint16(id))
		}
	}
	var mti *bgp.LsTLVMultiTopoID
	if len(multiTopoIDs) > 0 {
		mti = &bgp.LsTLVMultiTopoID{
			LsTLV: bgp.LsTLV{
				Type:   bgp.LS_TLV_MULTI_TOPO_ID,
				Length: uint16(2 * len(multiTopoIDs)),
			},
			MultiTopoIDs: multiTopoIDs,
		}
	}

	const CodeLen = 1
	const topologyLen = 8
	LsNLRIhdrlen := lndTLV.Len() + ssi.Len() + topologyLen + CodeLen
	if mti != nil {
		LsNLRIhdrlen += mti.Len()
	}
	lsNlri := bgp.LsNLRI{
		NLRIType:   bgp.LS_NLRI_TYPE_SRV6_SID,
		Length:     uint16(LsNLRIhdrlen),
		ProtocolID: bgp.LsProtocolID(protocol),
		Identifier: identifier,
	}
	nlri := &bgp.LsAddrPrefix{
		Type:   bgp.LS_NLRI_TYPE_SRV6_SID,
		Length: 4,
		NLRI: &bgp.LsSrv6SIDNLRI{
			LsNLRI:        lsNlri,
			LocalNodeDesc: &lndTLV,
			MultiTopoID:   mti,
			Srv6SIDInfo:   ssi,
		},
	}

	var pathAttr *bgp.PathAttributeLs
	var tlvs []bgp.LsTLVInterface

	// Add SRv6 BGP Peer Node SID
	var srv6BgpPeerNodeSID *bgp.LsSrv6BgpPeerNodeSID
	if peerAs, ok := m["peer-as"]; ok && len(peerAs) > 0 {
		if peerBgpID, ok := m["peer-bgp-id"]; ok && len(peerBgpID) > 0 {
			peerAS, err := strconv.ParseUint(peerAs[0], 10, 32)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid peer-as: %v", err)
			}

			addr, err := netip.ParseAddr(peerBgpID[0])
			if err != nil || !addr.Is4() {
				return nil, nil, fmt.Errorf("invalid peer-bgp-id format, must be IPv4 address: %s", peerBgpID[0])
			}

			var flags, weight uint8
			if flagsStr, ok := m["flags"]; ok && len(flagsStr) > 0 {
				flagsVal, err := strconv.ParseUint(flagsStr[0], 10, 8)
				if err != nil {
					return nil, nil, fmt.Errorf("invalid flags: %v", err)
				}
				flags = uint8(flagsVal)
			}

			if weightStr, ok := m["weight"]; ok && len(weightStr) > 0 {
				weightVal, err := strconv.ParseUint(weightStr[0], 10, 8)
				if err != nil {
					return nil, nil, fmt.Errorf("invalid weight: %v", err)
				}
				weight = uint8(weightVal)
			}

			srv6BgpPeerNodeSID = &bgp.LsSrv6BgpPeerNodeSID{
				Flags:     flags,
				Weight:    weight,
				PeerAS:    uint32(peerAS),
				PeerBgpID: peerBgpID[0],
			}
		}
		tlv := bgp.NewLsTLVSrv6BgpPeerNodeSID(srv6BgpPeerNodeSID)
		if tlv != nil {
			tlvs = append(tlvs, tlv)
		}
	}

	// Add SRv6 Endpoint Behavior
	if endpointBehaviorStr, ok := m["srv6-endpoint-behavior"]; ok && len(endpointBehaviorStr) > 0 {
		behavior, err := strconv.ParseUint(endpointBehaviorStr[0], 10, 16)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid srv6-endpoint-behavior: %v", err)
		}

		var flags uint8
		if flagsStr, ok := m["srv6-flags"]; ok && len(flagsStr) > 0 {
			flagsVal, err := strconv.ParseUint(flagsStr[0], 10, 8)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid srv6-flags: %v", err)
			}
			flags = uint8(flagsVal)
		}

		var algorithm uint8
		if algoStr, ok := m["srv6-algo"]; ok && len(algoStr) > 0 {
			algoVal, err := strconv.ParseUint(algoStr[0], 10, 8)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid srv6-algo: %v", err)
			}
			algorithm = uint8(algoVal)
		}

		srv6EndpointBehavior := &bgp.LsSrv6EndpointBehavior{
			Flags:            flags,
			EndpointBehavior: uint16(behavior),
			Algorithm:        algorithm,
		}
		tlv := bgp.NewLsTLVSrv6EndpointBehavior(srv6EndpointBehavior)
		if tlv != nil {
			tlvs = append(tlvs, tlv)
		}
	}

	// Add SRv6 SID Structure
	if lbStr, ok := m["srv6-structure-lb"]; ok && len(lbStr) > 0 {
		locatorBlockLen, err := strconv.ParseUint(lbStr[0], 10, 8)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid srv6-structure-lb: %v", err)
		}

		var locatorNodeLen, functionLen, argumentLen uint8
		if lnStr, ok := m["srv6-structure-ln"]; ok && len(lnStr) > 0 {
			ln, err := strconv.ParseUint(lnStr[0], 10, 8)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid srv6-structure-ln: %v", err)
			}
			locatorNodeLen = uint8(ln)
		}
		if funStr, ok := m["srv6-structure-fun"]; ok && len(funStr) > 0 {
			fun, err := strconv.ParseUint(funStr[0], 10, 8)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid srv6-structure-fun: %v", err)
			}
			functionLen = uint8(fun)
		}
		if argStr, ok := m["srv6-structure-arg"]; ok && len(argStr) > 0 {
			arg, err := strconv.ParseUint(argStr[0], 10, 8)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid srv6-structure-arg: %v", err)
			}
			argumentLen = uint8(arg)
		}

		srv6SIDStructure := &bgp.LsSrv6SIDStructure{
			LocalBlock: uint8(locatorBlockLen),
			LocalNode:  locatorNodeLen,
			LocalFunc:  functionLen,
			LocalArg:   argumentLen,
		}
		tlv := bgp.NewLsTLVSrv6SIDStructure(srv6SIDStructure)
		if tlv != nil {
			tlvs = append(tlvs, tlv)
		}
	}

	if len(tlvs) > 0 {
		pathAttr = &bgp.PathAttributeLs{
			PathAttribute: bgp.PathAttribute{
				Type:  bgp.BGP_ATTR_TYPE_LS,
				Flags: bgp.BGP_ATTR_FLAG_OPTIONAL,
			},
			TLVs: tlvs,
		}
	}

	return nlri, pathAttr, nil
}

func lsTLVTypeSelect(s string) bgp.LsTLVType {
	switch s {
	case "node":
		return bgp.LS_TLV_PEER_NODE_SID
	case "adj":
		return bgp.LS_TLV_ADJACENCY_SID
	case "set":
		return bgp.LS_TLV_PEER_SET_SID
	}

	return bgp.LS_TLV_UNKNOWN
}

func parseLsArgs(args []string) (bgp.NLRI, *bgp.PathAttributeLs, error) {
	if len(args) < 1 {
		return nil, nil, fmt.Errorf("lack of nlriType")
	}
	nlriType := args[0]
	// TODO: case IPv4 Topology Prefix / TE Policy
	switch nlriType {
	case "node":
		return parseLsNodeNLRIType(args)
	case "link":
		return parseLsLinkNLRIType(args)
	case "prefixv6":
		return parseLsPrefixV6NLRIType(args)
	case "srv6sid":
		return parseLsSRv6SIDNLRIType(args)
	}

	return nil, nil, fmt.Errorf("invalid nlriType. expect [node, link, prefixv6, srv6sid] but %s", nlriType)
}

func parseRtcArgs(args []string) (bgp.NLRI, error) {
	// Format:
	// asn <asn> rt <rt> | default
	m, err := extractReserved(args, map[string]int{
		"asn":     paramSingle,
		"rt":      paramSingle,
		"default": paramFlag,
	})
	if err != nil {
		return nil, err
	}

	if _, ok := m["default"]; ok {
		return bgp.NewRouteTargetMembershipNLRI(0, nil), nil
	}

	for _, f := range []string{"asn", "rt"} {
		if len(m[f]) == 0 {
			return nil, fmt.Errorf("specify %s", f)
		}
	}

	asn, err := toAs4Value(m["asn"][0])
	if err != nil {
		return nil, err
	}

	rt, err := bgp.ParseRouteTarget(m["rt"][0])
	if err != nil {
		return nil, err
	}

	return bgp.NewRouteTargetMembershipNLRI(asn, rt), nil
}

func extractOrigin(args []string) ([]string, bgp.PathAttributeInterface, error) {
	typ := bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE
	for idx, arg := range args {
		if arg == "origin" && len(args) > idx+1 {
			switch args[idx+1] {
			case "igp":
				typ = bgp.BGP_ORIGIN_ATTR_TYPE_IGP
			case "egp":
				typ = bgp.BGP_ORIGIN_ATTR_TYPE_EGP
			case "incomplete":
			default:
				return nil, nil, fmt.Errorf("invalid origin type. expect [igp|egp|incomplete] but %s", args[idx+1])
			}
			args = append(args[:idx], args[idx+2:]...)
			break
		}
	}
	return args, bgp.NewPathAttributeOrigin(typ), nil
}

func toAs4Value(s string) (uint32, error) {
	if strings.Contains(s, ".") {
		v := strings.Split(s, ".")
		upper, err := strconv.ParseUint(v[0], 10, 16)
		if err != nil {
			return 0, nil
		}
		lower, err := strconv.ParseUint(v[1], 10, 16)
		if err != nil {
			return 0, nil
		}
		return uint32(upper<<16 | lower), nil
	}
	i, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(i), nil
}

var (
	_regexpASPathGroups  = regexp.MustCompile("[{}]")
	_regexpASPathSegment = regexp.MustCompile(`,|\s+`)
)

func newAsPath(aspath string) (bgp.PathAttributeInterface, error) {
	// For the first step, parses "aspath" into a list of uint32 list.
	// e.g.) "10 20 {30,40} 50" -> [][]uint32{{10, 20}, {30, 40}, {50}}
	segments := _regexpASPathGroups.Split(aspath, -1)
	asPathPrams := make([]bgp.AsPathParamInterface, 0, len(segments))
	for idx, segment := range segments {
		if segment == "" {
			continue
		}
		nums := _regexpASPathSegment.Split(segment, -1)
		asNums := make([]uint32, 0, len(nums))
		for _, n := range nums {
			if n == "" {
				continue
			}
			if asn, err := toAs4Value(n); err != nil {
				return nil, err
			} else {
				asNums = append(asNums, asn)
			}
		}
		// Assumes "idx" is even, the given "segment" is of type AS_SEQUENCE,
		// otherwise AS_SET, because the "segment" enclosed in parentheses is
		// of type AS_SET.
		if idx%2 == 0 {
			asPathPrams = append(asPathPrams, bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, asNums))
		} else {
			asPathPrams = append(asPathPrams, bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SET, asNums))
		}
	}
	return bgp.NewPathAttributeAsPath(asPathPrams), nil
}

func extractAsPath(args []string) ([]string, bgp.PathAttributeInterface, error) {
	for idx, arg := range args {
		if arg == "aspath" && len(args) > idx+1 {
			attr, err := newAsPath(args[idx+1])
			if err != nil {
				return nil, nil, err
			}
			args = append(args[:idx], args[idx+2:]...)
			return args, attr, nil
		}
	}
	return args, nil, nil
}

func extractNexthop(rf bgp.Family, args []string) ([]string, string, error) {
	nexthop := "0.0.0.0"
	if rf.Afi() == bgp.AFI_IP6 {
		nexthop = "::"
	}
	for idx, arg := range args {
		if arg == "nexthop" && len(args) > idx+1 {
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

func extractLocalPref(args []string) ([]string, bgp.PathAttributeInterface, error) {
	for idx, arg := range args {
		if arg == "local-pref" && len(args) > idx+1 {
			metric, err := strconv.ParseUint(args[idx+1], 10, 32)
			if err != nil {
				return nil, nil, err
			}
			args = append(args[:idx], args[idx+2:]...)
			return args, bgp.NewPathAttributeLocalPref(uint32(metric)), nil
		}
	}
	return args, nil, nil
}

func extractMed(args []string) ([]string, bgp.PathAttributeInterface, error) {
	for idx, arg := range args {
		if arg == "med" && len(args) > idx+1 {
			med, err := strconv.ParseUint(args[idx+1], 10, 32)
			if err != nil {
				return nil, nil, err
			}
			args = append(args[:idx], args[idx+2:]...)
			return args, bgp.NewPathAttributeMultiExitDisc(uint32(med)), nil
		}
	}
	return args, nil, nil
}

func extractCommunity(args []string) ([]string, bgp.PathAttributeInterface, error) {
	for idx, arg := range args {
		if arg == "community" && len(args) > idx+1 {
			elems := strings.Split(args[idx+1], ",")
			comms := make([]uint32, 0, 1)
			for _, elem := range elems {
				c, err := table.ParseCommunity(elem)
				if err != nil {
					return nil, nil, err
				}
				comms = append(comms, c)
			}
			args = append(args[:idx], args[idx+2:]...)
			return args, bgp.NewPathAttributeCommunities(comms), nil
		}
	}
	return args, nil, nil
}

func extractLargeCommunity(args []string) ([]string, bgp.PathAttributeInterface, error) {
	for idx, arg := range args {
		if arg == "large-community" && len(args) > idx+1 {
			elems := strings.Split(args[idx+1], ",")
			comms := make([]*bgp.LargeCommunity, 0, 1)
			for _, elem := range elems {
				c, err := bgp.ParseLargeCommunity(elem)
				if err != nil {
					return nil, nil, err
				}
				comms = append(comms, c)
			}
			args = append(args[:idx], args[idx+2:]...)
			return args, bgp.NewPathAttributeLargeCommunities(comms), nil
		}
	}
	return args, nil, nil
}

func extractPmsiTunnel(args []string) ([]string, bgp.PathAttributeInterface, error) {
	for idx, arg := range args {
		if arg == "pmsi" {
			pmsi, err := bgp.ParsePmsiTunnel(args[idx+1:])
			if err != nil {
				return nil, nil, err
			}
			if pmsi.IsLeafInfoRequired {
				return append(args[:idx], args[idx+5:]...), pmsi, nil
			}
			return append(args[:idx], args[idx+4:]...), pmsi, nil
		}
	}
	return args, nil, nil
}

func extractAigp(args []string) ([]string, bgp.PathAttributeInterface, error) {
	for idx, arg := range args {
		if arg == "aigp" {
			if len(args) < idx+3 {
				return nil, nil, fmt.Errorf("invalid aigp format")
			}
			typ := args[idx+1]
			switch typ {
			case "metric":
				metric, err := strconv.ParseUint(args[idx+2], 10, 64)
				if err != nil {
					return nil, nil, err
				}
				aigp := bgp.NewPathAttributeAigp([]bgp.AigpTLVInterface{bgp.NewAigpTLVIgpMetric(metric)})
				return append(args[:idx], args[idx+3:]...), aigp, nil
			default:
				return nil, nil, fmt.Errorf("unknown aigp type: %s", typ)
			}
		}
	}
	return args, nil, nil
}

func extractAggregator(args []string) ([]string, bgp.PathAttributeInterface, error) {
	for idx, arg := range args {
		if arg == "aggregator" {
			if len(args) < idx+1 {
				return nil, nil, fmt.Errorf("invalid aggregator format")
			}
			v := strings.SplitN(args[idx+1], ":", 2)
			if len(v) != 2 {
				return nil, nil, fmt.Errorf("invalid aggregator format")
			}
			as, err := strconv.ParseUint(v[0], 10, 32)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid aggregator format")
			}
			addr, err := netip.ParseAddr(v[1])
			if err != nil {
				return nil, nil, fmt.Errorf("invalid aggregator format")
			}
			attr, _ := bgp.NewPathAttributeAggregator(uint32(as), addr)
			return append(args[:idx], args[idx+2:]...), attr, nil
		}
	}
	return args, nil, nil
}

func parsePath(rf bgp.Family, args []string) (*api.Path, error) {
	var nlri bgp.NLRI
	var extcomms []string
	var psid *bgp.PathAttributePrefixSID
	var ls *bgp.PathAttributeLs
	var err error
	attrs := make([]bgp.PathAttributeInterface, 0, 1)
	remoteID := uint32(0)

	fns := []func([]string) ([]string, bgp.PathAttributeInterface, error){
		extractOrigin,         // 1 ORIGIN
		extractAsPath,         // 2 AS_PATH
		extractMed,            // 4 MULTI_EXIT_DISC
		extractLocalPref,      // 5 LOCAL_PREF
		extractAggregator,     // 7 AGGREGATOR
		extractCommunity,      // 8 COMMUNITY
		extractPmsiTunnel,     // 22 PMSI_TUNNEL
		extractAigp,           // 26 AIGP
		extractLargeCommunity, // 32 LARGE_COMMUNITY
	}

	for _, fn := range fns {
		var a bgp.PathAttributeInterface
		args, a, err = fn(args)
		if err != nil {
			return nil, err
		}
		if a != nil {
			attrs = append(attrs, a)
		}
	}

	args, nexthop, err := extractNexthop(rf, args)
	if err != nil {
		return nil, err
	}

	switch rf {
	case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
		if len(args) < 1 {
			return nil, fmt.Errorf("invalid format")
		}
		prefix, err := netip.ParsePrefix(args[0])
		if err != nil {
			return nil, err
		}
		if rf == bgp.RF_IPv4_UC {
			if !prefix.Addr().Is4() {
				return nil, fmt.Errorf("not ipv4 prefix")
			}
		} else if !prefix.Addr().Is6() {
			return nil, fmt.Errorf("not ipv6 prefix")
		}
		nlri, _ = bgp.NewIPAddrPrefix(prefix)

		if len(args) > 2 && args[1] == "identifier" {
			id, err := strconv.ParseUint(args[2], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid format")
			}
			remoteID = uint32(id)
			extcomms = args[3:]
		} else {
			extcomms = args[1:]
		}

	case bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN:
		if len(args) < 5 || args[1] != "label" || args[3] != "rd" {
			return nil, fmt.Errorf("invalid format")
		}
		prefix, err := netip.ParsePrefix(args[0])
		if err != nil {
			return nil, err
		}

		label, err := strconv.ParseUint(args[2], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid format")
		}
		mpls := bgp.NewMPLSLabelStack(uint32(label))

		rd, err := bgp.ParseRouteDistinguisher(args[4])
		if err != nil {
			return nil, err
		}

		if rf == bgp.RF_IPv4_VPN {
			if !prefix.Addr().Is4() {
				return nil, fmt.Errorf("invalid ipv4 prefix")
			}
		} else if !prefix.Addr().Is6() {
			return nil, fmt.Errorf("invalid ipv6 prefix")
		}
		nlri, _ = bgp.NewLabeledVPNIPAddrPrefix(prefix, *mpls, rd)

		args = args[5:]

		if len(args) > 1 && args[0] == "identifier" {
			id, err := strconv.ParseUint(args[1], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid format")
			}
			remoteID = uint32(id)
			args = args[2:]
		}

		extcomms = args
	case bgp.RF_IPv4_MPLS, bgp.RF_IPv6_MPLS:
		if len(args) < 2 {
			return nil, fmt.Errorf("invalid format")
		}

		prefix, err := netip.ParsePrefix(args[0])
		if err != nil {
			return nil, err
		}

		mpls, err := bgp.ParseMPLSLabelStack(args[1])
		if err != nil {
			return nil, err
		}

		extcomms = args[2:]

		if rf == bgp.RF_IPv4_MPLS {
			if !prefix.Addr().Is4() {
				return nil, fmt.Errorf("invalid ipv4 prefix")
			}
		} else if !prefix.Addr().Is6() {
			return nil, fmt.Errorf("invalid ipv6 prefix")
		}
		nlri, _ = bgp.NewLabeledIPAddrPrefix(prefix, *mpls)
	case bgp.RF_EVPN:
		nlri, extcomms, err = parseEvpnArgs(args)
	case bgp.RF_FS_IPv4_UC, bgp.RF_FS_IPv4_VPN, bgp.RF_FS_IPv6_UC, bgp.RF_FS_IPv6_VPN, bgp.RF_FS_L2_VPN:
		nlri, psid, extcomms, err = parseFlowSpecArgs(rf, args)
	case bgp.RF_OPAQUE:
		m, err := extractReserved(args, map[string]int{
			"key":   paramSingle,
			"value": paramSingle,
		})
		if err != nil {
			return nil, err
		}
		if len(m["key"]) != 1 {
			return nil, fmt.Errorf("opaque nlri key missing")
		}
		if len(m["value"]) > 0 {
			nlri = bgp.NewOpaqueNLRI([]byte(m["key"][0]), []byte(m["value"][0]))
		} else {
			nlri = bgp.NewOpaqueNLRI([]byte(m["key"][0]), nil)
		}
	case bgp.RF_MUP_IPv4:
		nlri, psid, extcomms, err = parseMUPArgs(args, bgp.AFI_IP, nexthop)
	case bgp.RF_MUP_IPv6:
		nlri, psid, extcomms, err = parseMUPArgs(args, bgp.AFI_IP6, nexthop)
	case bgp.RF_LS:
		nlri, ls, err = parseLsArgs(args)
	case bgp.RF_RTC_UC:
		nlri, err = parseRtcArgs(args)
	default:
		return nil, fmt.Errorf("unsupported route family: %s", rf)
	}
	if err != nil {
		return nil, err
	}
	if ls != nil {
		attrs = append(attrs, ls)
	}

	nh, _ := netip.ParseAddr(nexthop)
	if rf == bgp.RF_IPv4_UC && nh.Is4() {
		attr, _ := bgp.NewPathAttributeNextHop(nh)
		attrs = append(attrs, attr)
	} else {
		mpreach, _ := bgp.NewPathAttributeMpReachNLRI(rf, []bgp.PathNLRI{{NLRI: nlri, ID: remoteID}}, nh)
		attrs = append(attrs, mpreach)
	}

	if psid != nil {
		attrs = append(attrs, psid)
	}

	if extcomms != nil {
		extcomms, err := parseExtendedCommunities(extcomms)
		if err != nil {
			return nil, err
		}
		normalextcomms := make([]bgp.ExtendedCommunityInterface, 0)
		ipv6extcomms := make([]bgp.ExtendedCommunityInterface, 0)
		for _, com := range extcomms {
			switch com.(type) {
			case *bgp.RedirectIPv6AddressSpecificExtended:
				ipv6extcomms = append(ipv6extcomms, com)
			default:
				normalextcomms = append(normalextcomms, com)
			}
		}
		if len(normalextcomms) != 0 {
			p := bgp.NewPathAttributeExtendedCommunities(normalextcomms)
			attrs = append(attrs, p)
		}
		if len(ipv6extcomms) != 0 {
			ip6p := bgp.NewPathAttributeIP6ExtendedCommunities(ipv6extcomms)
			attrs = append(attrs, ip6p)
		}
	}
	sort.Slice(attrs, func(i, j int) bool { return attrs[i].GetType() < attrs[j].GetType() })

	p, err := apiutil.NewPath(rf, nlri, false, attrs, time.Now())
	if err != nil {
		return nil, err
	}
	p.Identifier = remoteID
	return p, nil
}

func showGlobalRib(args []string) error {
	return showNeighborRib(cmdGlobal, "", args)
}

func modPath(resource string, name, modtype string, args []string) error {
	f, err := checkAddressFamily(ipv4UC)
	if err != nil {
		return err
	}
	rf := apiutil.ToFamily(f)
	path, err := parsePath(rf, args)
	if err != nil {
		cmdstr := "global"
		if resource == cmdVRF {
			cmdstr = fmt.Sprintf("vrf %s", name)
		}
		rdHelpMsgFmt := `
    <RD> : xxx:yyy, xxx.xxx.xxx.xxx:yyy, xxx.xxx:yyy`
		ss := make([]string, 0, len(bgp.ProtocolNameMap))
		for _, v := range bgp.ProtocolNameMap {
			ss = append(ss, v)
		}
		sort.SliceStable(ss, func(i, j int) bool { return ss[i] < ss[j] })
		ss = append(ss, "<DEC_NUM>")
		ipProtocols := strings.Join(ss, ", ")
		ss = make([]string, 0, len(bgp.TCPFlagNameMap))
		for _, v := range bgp.TCPSortedFlags {
			ss = append(ss, bgp.TCPFlagNameMap[v])
		}
		tcpFlags := strings.Join(ss, ", ")
		ss = make([]string, 0, len(bgp.EthernetTypeNameMap))
		for _, v := range bgp.EthernetTypeNameMap {
			ss = append(ss, v)
		}
		sort.SliceStable(ss, func(i, j int) bool { return ss[i] < ss[j] })
		ss = append(ss, "<DEC_NUM>")
		etherTypes := strings.Join(ss, ", ")
		helpErrMap := map[bgp.Family]error{}
		baseHelpMsgFmt := fmt.Sprintf(`error: %s
usage: %s rib -a %%s %s <PREFIX> %%s [origin { igp | egp | incomplete }] [aspath <ASPATH>] [nexthop <ADDRESS>] [med <NUM>] [local-pref <NUM>] [community <COMMUNITY>] [aigp metric <NUM>] [large-community <LARGE_COMMUNITY>] [aggregator <AGGREGATOR>]
    <ASPATH>: <AS>[,<AS>],
    <COMMUNITY>: xxx:xxx|internet|planned-shut|accept-own|route-filter-translated-v4|route-filter-v4|route-filter-translated-v6|route-filter-v6|llgr-stale|no-llgr|blackhole|no-export|no-advertise|no-export-subconfed|no-peer,
    <LARGE_COMMUNITY>: xxx:xxx:xxx[,<LARGE_COMMUNITY>],
    <AGGREGATOR>: <AS>:<ADDRESS>`,
			err,
			cmdstr,
			// <address family>
			modtype,
			// <label, rd>
		)
		helpErrMap[bgp.RF_IPv4_UC] = fmt.Errorf(baseHelpMsgFmt, "ipv4", "[identifier <VALUE>]")
		helpErrMap[bgp.RF_IPv6_UC] = fmt.Errorf(baseHelpMsgFmt, "ipv6", "[identifier <VALUE>]")
		helpErrMap[bgp.RF_IPv4_VPN] = fmt.Errorf(baseHelpMsgFmt, "vpnv4", "label <LABEL> rd <RD> [rt <RT>]")
		helpErrMap[bgp.RF_IPv6_VPN] = fmt.Errorf(baseHelpMsgFmt, "vpnv6", "label <LABEL> rd <RD> [rt <RT>]")
		helpErrMap[bgp.RF_IPv4_MPLS] = fmt.Errorf(baseHelpMsgFmt, "ipv4-mpls", "<LABEL>")
		helpErrMap[bgp.RF_IPv6_MPLS] = fmt.Errorf(baseHelpMsgFmt, "ipv6-mpls", "<LABEL>")

		fsHelpMsgFmt := fmt.Sprintf(`error: %s
usage: %s rib -a %%s %s%%s match <MATCH> then <THEN>%%s%%s%%s
    <THEN> : { %s |
               %s |
               %s <RATE> [as <AS>] |
               %s <RT> [color <color>] [prefix <prefix>] [locator-node-length <length>] [function-length <length>] [behavior <behavior>] |
               %s <DEC_NUM> |
               %s { sample | terminal | sample-terminal } }...
    <RT> : xxx:yyy, xxx.xxx.xxx.xxx:yyy, xxxx::xxxx:yyy, xxx.xxx:yyy`,
			err,
			cmdstr,
			// <address family>
			modtype,
			// "" or " rd <RD>"
			// "" or " [rt <RT>]"
			// <help message for RD>
			// <MATCH>
			extCommNameMap[ctAccept],
			extCommNameMap[ctDiscard],
			extCommNameMap[ctRate],
			extCommNameMap[ctRedirect],
			extCommNameMap[ctMark],
			extCommNameMap[ctAction],
		)
		baseFsMatchExpr := fmt.Sprintf(`
    <MATCH> : { %s <PREFIX> [<OFFSET>] |
                %s <PREFIX> [<OFFSET>] |
                %s <PROTOCOLS>... |
                %s <FRAGMENTS>... |
                %s <TCP_FLAGS>... |
                %s <ITEM>... |
                %s <ITEM>... |
                %s <ITEM>... |
                %s <ITEM>... |
                %s <ITEM>... |
                %s <ITEM>... |
                %s <ITEM>... %%s}...
    <PROTOCOLS> : [&] [<|<=|>|>=|==|!=] <PROTOCOL>
    <PROTOCOL> : %s
    <FRAGMENTS> : [&] [=|!|!=] <FRAGMENT>
    <FRAGMENT> : dont-fragment, is-fragment, first-fragment, last-fragment, not-a-fragment
    <TCP_FLAGS> : [&] [=|!|!=] <TCP_FLAG>
    <TCP_FLAG> : %s%%s
    <ITEM> : [&] [<|<=|>|>=|==|!=] <DEC_NUM>`,
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
			// <additional help messages if exists>
			ipProtocols,
			tcpFlags,
			// <additional help messages if exists>
		)
		ipv4FsMatchExpr := fmt.Sprintf(baseFsMatchExpr, "", "")
		ipv6FsMatchExpr := fmt.Sprintf(baseFsMatchExpr, fmt.Sprintf(`|
                %s <ITEM>... `,
			bgp.FlowSpecNameMap[bgp.FLOW_SPEC_TYPE_LABEL]), "")
		l2vpnFsMatchExpr := fmt.Sprintf(baseFsMatchExpr, fmt.Sprintf(`|
                %s <ITEM>... |
                %s <MAC_ADDRESS> |
                %s <MAC_ADDRESS> |
                %s <ETHER_TYPES>... |
                %s <ITEM>... |
                %s <ITEM>... |
                %s <ITEM>... |
                %s <ITEM>... |
                %s <ITEM>... |
                %s <ITEM>... |
                %s <ITEM>... |
                %s <ITEM>... `,
			bgp.FlowSpecNameMap[bgp.FLOW_SPEC_TYPE_LABEL],
			bgp.FlowSpecNameMap[bgp.FLOW_SPEC_TYPE_DST_MAC],
			bgp.FlowSpecNameMap[bgp.FLOW_SPEC_TYPE_SRC_MAC],
			bgp.FlowSpecNameMap[bgp.FLOW_SPEC_TYPE_ETHERNET_TYPE],
			bgp.FlowSpecNameMap[bgp.FLOW_SPEC_TYPE_LLC_DSAP],
			bgp.FlowSpecNameMap[bgp.FLOW_SPEC_TYPE_LLC_SSAP],
			bgp.FlowSpecNameMap[bgp.FLOW_SPEC_TYPE_LLC_CONTROL],
			bgp.FlowSpecNameMap[bgp.FLOW_SPEC_TYPE_SNAP],
			bgp.FlowSpecNameMap[bgp.FLOW_SPEC_TYPE_VID],
			bgp.FlowSpecNameMap[bgp.FLOW_SPEC_TYPE_COS],
			bgp.FlowSpecNameMap[bgp.FLOW_SPEC_TYPE_INNER_VID],
			bgp.FlowSpecNameMap[bgp.FLOW_SPEC_TYPE_INNER_COS]), fmt.Sprintf(`
    <ETHER_TYPES> : [&] [<|<=|>|>=|==|!=] <ETHER_TYPE>
    <ETHER_TYPE> : %s`,
			etherTypes))
		helpErrMap[bgp.RF_FS_IPv4_UC] = fmt.Errorf(fsHelpMsgFmt, "ipv4-flowspec", "", "", "", ipv4FsMatchExpr)
		helpErrMap[bgp.RF_FS_IPv6_UC] = fmt.Errorf(fsHelpMsgFmt, "ipv6-flowspec", "", "", "", ipv6FsMatchExpr)
		helpErrMap[bgp.RF_FS_IPv4_VPN] = fmt.Errorf(fsHelpMsgFmt, "ipv4-l3vpn-flowspec", " rd <RD>", " [rt <RT>]", rdHelpMsgFmt, ipv4FsMatchExpr)
		helpErrMap[bgp.RF_FS_IPv6_VPN] = fmt.Errorf(fsHelpMsgFmt, "ipv6-l3vpn-flowspec", " rd <RD>", " [rt <RT>]", rdHelpMsgFmt, ipv6FsMatchExpr)
		helpErrMap[bgp.RF_FS_L2_VPN] = fmt.Errorf(fsHelpMsgFmt, "l2vpn-flowspec", " rd <RD>", " [rt <RT>]", rdHelpMsgFmt, l2vpnFsMatchExpr)
		helpErrMap[bgp.RF_EVPN] = fmt.Errorf(`error: %s
usage: %s rib %s { a-d <A-D> | macadv <MACADV> | multicast <MULTICAST> | esi <ESI> | prefix <PREFIX> } -a evpn
    <A-D>       : esi <esi> etag <etag> label <label> rd <rd> [rt <rt>...] [encap <encap type>] [esi-label <esi-label> [single-active | all-active]]
    <MACADV>    : <mac address> <ip address> [esi <esi>] etag <etag> label <label> rd <rd> [rt <rt>...] [encap <encap type>] [router-mac <mac address>] [default-gateway]
    <MULTICAST> : <ip address> etag <etag> rd <rd> [rt <rt>...] [encap <encap type>] [pmsi <type> [leaf-info-required] <label> <tunnel-id>]
    <ESI>       : <ip address> esi <esi> rd <rd> [rt <rt>...] [encap <encap type>]
    <PREFIX>    : <ip prefix> [gw <gateway>] [esi <esi>] etag <etag> [label <label>] rd <rd> [rt <rt>...] [encap <encap type>] [router-mac <mac address>]`,
			err,
			cmdstr,
			modtype,
		)
		helpErrMap[bgp.RF_MUP_IPv4] = fmt.Errorf(`error: %s
usage: %s rib %s { isd <ISD> | dsd <DSD> | t1st <T1ST> | t2st <T2ST> } -a mup-ipv4
    <ISD>  : <ip prefix> rd <rd> prefix <prefix> locator-node-length <locator-node-length> function-length <function-length> behavior <behavior> [rt <rt>...]
    <DSD>  : <ip address> rd <rd> prefix <prefix> locator-node-length <locator-node-length> function-length <function-length> behavior <behavior> [rt <rt>...] [mup <segment identifier>]
    <T1ST> : <ip prefix> rd <rd> [rt <rt>...] teid <teid> qfi <qfi> endpoint <endpoint> [source <source>]
    <T2ST> : <endpoint address> rd <rd> [rt <rt>...] endpoint-address-length <endpoint-address-length> teid <teid> [mup <segment identifier>]`,
			err,
			cmdstr,
			modtype,
		)
		helpErrMap[bgp.RF_MUP_IPv6] = fmt.Errorf(`error: %s
usage: %s rib %s { isd <ISD> | dsd <DSD> | t1st <T1ST> | t2st <T2ST> } -a mup-ipv6
    <ISD>  : <ip prefix> rd <rd> prefix <prefix> locator-node-length <locator-node-length> function-length <function-length> behavior <behavior> [rt <rt>...]
    <DSD>  : <ip address> rd <rd> prefix <prefix> locator-node-length <locator-node-length> function-length <function-length> behavior <behavior> [rt <rt>...] [mup <segment identifier>]
    <T1ST> : <ip prefix> rd <rd> [rt <rt>...] teid <teid> qfi <qfi> endpoint <endpoint> [source <source>]
    <T2ST> : <endpoint address> rd <rd> [rt <rt>...] endpoint-address-length <endpoint-address-length> teid <teid> [mup <segment identifier>]`,
			err,
			cmdstr,
			modtype,
		)
		helpErrMap[bgp.RF_OPAQUE] = fmt.Errorf(`error: %s
usage: %s rib %s key <KEY> [value <VALUE>]`,
			err,
			cmdstr,
			modtype,
		)

		rtcHelpMsgFmt := fmt.Sprintf(`error: %s
usage: %s rib -a %%s %s %%s [origin { igp | egp | incomplete }] [aspath <ASPATH>] [nexthop <ADDRESS>] [med <NUM>] [local-pref <NUM>] [community <COMMUNITY>] [aigp metric <NUM>] [large-community <LARGE_COMMUNITY>] [aggregator <AGGREGATOR>]
    <ASPATH>: <AS>[,<AS>],
    <COMMUNITY>: xxx:xxx|internet|planned-shut|accept-own|route-filter-translated-v4|route-filter-v4|route-filter-translated-v6|route-filter-v6|llgr-stale|no-llgr|blackhole|no-export|no-advertise|no-export-subconfed|no-peer,
    <LARGE_COMMUNITY>: xxx:xxx:xxx[,<LARGE_COMMUNITY>],
    <AGGREGATOR>: <AS>:<ADDRESS>`,
			err,
			cmdstr,
			modtype,
		)
		helpErrMap[bgp.RF_RTC_UC] = fmt.Errorf(rtcHelpMsgFmt, "rtc", "{ asn <ASN> rt <RT> | default }")

		if err, ok := helpErrMap[rf]; ok {
			return err
		}
		return err
	}

	r := api.TableType_TABLE_TYPE_GLOBAL
	if resource == cmdVRF {
		r = api.TableType_TABLE_TYPE_VRF
	}

	if modtype == cmdAdd {
		_, err = client.AddPath(ctx, &api.AddPathRequest{
			TableType: r,
			VrfId:     name,
			Path:      path,
		})
	} else {
		_, err = client.DeletePath(ctx, &api.DeletePathRequest{
			TableType: r,
			VrfId:     name,
			Path:      path,
		})
	}
	return err
}

func showGlobalConfig() error {
	r, err := client.GetBgp(ctx, &api.GetBgpRequest{})
	if err != nil {
		return err
	}
	if globalOpts.Json {
		j, _ := json.Marshal(r.Global)
		fmt.Println(string(j))
		return nil
	}
	g := r.Global
	fmt.Println("AS:       ", g.Asn)
	fmt.Println("Router-ID:", g.RouterId)
	if len(g.ListenAddresses) > 0 {
		fmt.Printf("Listening Port: %d, Addresses: %s\n", g.ListenPort, strings.Join(g.ListenAddresses, ", "))
	}
	if g.UseMultiplePaths {
		fmt.Printf("Multipath: enabled")
	}
	return nil
}

func modGlobalConfig(args []string) error {
	m, err := extractReserved(args, map[string]int{
		"as":               paramSingle,
		"router-id":        paramSingle,
		"listen-port":      paramSingle,
		"listen-addresses": paramList,
		"use-multipath":    paramFlag,
	})
	if err != nil || len(m["as"]) != 1 || len(m["router-id"]) != 1 {
		return fmt.Errorf("usage: gobgp global as <VALUE> router-id <VALUE> [use-multipath] [listen-port <VALUE>] [listen-addresses <VALUE>...]")
	}
	asn, err := strconv.ParseUint(m["as"][0], 10, 32)
	if err != nil {
		return err
	}
	id := net.ParseIP(m["router-id"][0])
	if id.To4() == nil {
		return fmt.Errorf("invalid router-id format")
	}
	var port uint64
	if len(m["listen-port"]) > 0 {
		// Note: GlobalConfig.Port is uint32 type, but the TCP/UDP port is
		// 16-bit length.
		port, err = strconv.ParseUint(m["listen-port"][0], 10, 16)
		if err != nil {
			return err
		}
	}
	useMultipath := false
	if _, ok := m["use-multipath"]; ok {
		useMultipath = true
	}
	_, err = client.StartBgp(ctx, &api.StartBgpRequest{
		Global: &api.Global{
			Asn:              uint32(asn),
			RouterId:         id.String(),
			ListenPort:       int32(port),
			ListenAddresses:  m["listen-addresses"],
			UseMultiplePaths: useMultipath,
		},
	})
	return err
}

func newGlobalCmd() *cobra.Command {
	globalCmd := &cobra.Command{
		Use: cmdGlobal,
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			if len(args) != 0 {
				err = modGlobalConfig(args)
			} else {
				err = showGlobalConfig()
			}
			if err != nil {
				exitWithError(err)
			}
		},
	}

	ribCmd := &cobra.Command{
		Use: cmdRib,
		Run: func(cmd *cobra.Command, args []string) {
			if err := showGlobalRib(args); err != nil {
				exitWithError(err)
			}
		},
	}

	ribCmd.PersistentFlags().StringVarP(&subOpts.AddressFamily, "address-family", "a", "", "address family")
	ribCmd.PersistentFlags().Uint64VarP(&subOpts.BatchSize, "batch-size", "b", 0, "Size of the temporary buffer in the server memory. Zero is unlimited (default)")

	for _, v := range []string{cmdAdd, cmdDel} {
		cmd := &cobra.Command{
			Use: v,
			Run: func(cmd *cobra.Command, args []string) {
				err := modPath(cmdGlobal, "", cmd.Use, args)
				if err != nil {
					exitWithError(err)
				}
			},
		}
		ribCmd.AddCommand(cmd)

		if v == cmdDel {
			subcmd := &cobra.Command{
				Use: cmdAll,
				Run: func(cmd *cobra.Command, args []string) {
					family, err := checkAddressFamily(ipv4UC)
					if err != nil {
						exitWithError(err)
					}
					if _, err = client.DeletePath(ctx, &api.DeletePathRequest{
						TableType: api.TableType_TABLE_TYPE_GLOBAL,
						Family:    family,
					}); err != nil {
						exitWithError(err)
					}
				},
			}
			cmd.AddCommand(subcmd)
		}
	}

	summaryCmd := &cobra.Command{
		Use: cmdSummary,
		Run: func(cmd *cobra.Command, args []string) {
			if err := showRibInfo(cmdGlobal, ""); err != nil {
				exitWithError(err)
			}
		},
	}
	ribCmd.AddCommand(summaryCmd)

	policyCmd := &cobra.Command{
		Use: cmdPolicy,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				exitWithError(fmt.Errorf("usage: gobgp global policy [{ import | export }]"))
			}
			for _, v := range []string{cmdImport, cmdExport} {
				if err := showNeighborPolicy("", v, 4); err != nil {
					exitWithError(err)
				}
			}
		},
	}

	for _, v := range []string{cmdImport, cmdExport} {
		cmd := &cobra.Command{
			Use: v,
			Run: func(cmd *cobra.Command, args []string) {
				if err := showNeighborPolicy("", cmd.Use, 0); err != nil {
					exitWithError(err)
				}
			},
		}

		for _, w := range []string{cmdAdd, cmdDel, cmdSet} {
			subcmd := &cobra.Command{
				Use: w,
				Run: func(subcmd *cobra.Command, args []string) {
					err := modNeighborPolicy("", cmd.Use, subcmd.Use, args)
					if err != nil {
						exitWithError(err)
					}
				},
			}
			cmd.AddCommand(subcmd)
		}

		policyCmd.AddCommand(cmd)
	}

	delCmd := &cobra.Command{
		Use: cmdDel,
	}

	allCmd := &cobra.Command{
		Use: cmdAll,
		Run: func(cmd *cobra.Command, args []string) {
			if _, err := client.StopBgp(ctx, &api.StopBgpRequest{}); err != nil {
				exitWithError(err)
			}
		},
	}
	delCmd.AddCommand(allCmd)

	globalCmd.AddCommand(ribCmd, policyCmd, delCmd)
	return globalCmd
}
