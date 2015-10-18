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
	"github.com/osrg/gobgp/table"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"io"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func formatPolicyPrefix(head bool, indent int, psl []*api.DefinedSet) string {
	if len(psl) == 0 {
		return "Nothing defined yet\n"
	}
	buff := bytes.NewBuffer(make([]byte, 0, 64))
	sIndent := strings.Repeat(" ", indent)
	maxNameLen := 0
	maxPrefixLen := 0
	for _, ps := range psl {
		if len(ps.Name) > maxNameLen {
			maxNameLen = len(ps.Name)
		}
		for _, p := range ps.Prefixes {
			if len(p.IpPrefix) > maxPrefixLen {
				maxPrefixLen = len(p.IpPrefix)
			}
		}
	}

	if head {
		if len("NAME") > maxNameLen {
			maxNameLen = len("NAME")
		}
		if len("PREFIX") > maxPrefixLen {
			maxPrefixLen = len("PREFIX")
		}
	}

	format := fmt.Sprintf("%%-%ds  %%-%ds ", maxNameLen, maxPrefixLen)
	if head {
		buff.WriteString(fmt.Sprintf(format, "NAME", "PREFIX"))
		buff.WriteString("MaskLengthRange\n")
	}
	for _, ps := range psl {
		if len(ps.Prefixes) == 0 {
			buff.WriteString(fmt.Sprintf(format, ps.Name, ""))
			buff.WriteString("\n")
		}
		for i, p := range ps.Prefixes {
			if i == 0 {
				buff.WriteString(fmt.Sprintf(format, ps.Name, p.IpPrefix))
				buff.WriteString(fmt.Sprintf("%d..%d\n", p.MaskLengthMin, p.MaskLengthMax))
			} else {
				buff.WriteString(fmt.Sprintf(sIndent))
				buff.WriteString(fmt.Sprintf(format, "", p.IpPrefix))
				buff.WriteString(fmt.Sprintf("%d..%d\n", p.MaskLengthMin, p.MaskLengthMax))
			}
		}
	}
	return buff.String()
}

func formatDefinedSet(head bool, typ string, indent int, list []*api.DefinedSet) string {
	if len(list) == 0 {
		return "Nothing defined yet\n"
	}
	buff := bytes.NewBuffer(make([]byte, 0, 64))
	sIndent := strings.Repeat(" ", indent)
	maxNameLen := 0
	maxValueLen := 0
	for _, s := range list {
		if len(s.Name) > maxNameLen {
			maxNameLen = len(s.Name)
		}
		for _, x := range s.List {
			if len(x) > maxValueLen {
				maxValueLen = len(x)
			}
		}
	}
	if head {
		if len("NAME") > maxNameLen {
			maxNameLen = len("NAME")
		}
		if len(typ) > maxValueLen {
			maxValueLen = len(typ)
		}
	}
	format := fmt.Sprintf("%%-%ds  %%-%ds\n", maxNameLen, maxValueLen)
	if head {
		buff.WriteString(fmt.Sprintf(format, "NAME", typ))
	}
	for _, s := range list {
		if len(s.List) == 0 {
			buff.WriteString(fmt.Sprintf(format, s.Name, ""))
		}
		for i, x := range s.List {
			if i == 0 {
				buff.WriteString(fmt.Sprintf(format, s.Name, x))
			} else {
				buff.WriteString(fmt.Sprintf(sIndent))
				buff.WriteString(fmt.Sprintf(format, "", x))
			}
		}
	}
	return buff.String()
}

func showDefinedSet(v string, args []string) error {
	var typ table.DefinedType
	switch v {
	case CMD_PREFIX:
		typ = table.DEFINED_TYPE_PREFIX
	case CMD_NEIGHBOR:
		typ = table.DEFINED_TYPE_NEIGHBOR
	case CMD_ASPATH:
		typ = table.DEFINED_TYPE_AS_PATH
	case CMD_COMMUNITY:
		typ = table.DEFINED_TYPE_COMMUNITY
	case CMD_EXTCOMMUNITY:
		typ = table.DEFINED_TYPE_EXT_COMMUNITY
	default:
		return fmt.Errorf("unknown defined type: %s", v)
	}
	m := sets{}
	if len(args) > 0 {
		arg := &api.DefinedSet{
			Type: int32(typ),
			Name: args[0],
		}
		p, e := client.GetDefinedSet(context.Background(), arg)
		if e != nil {
			return e
		}
		m = append(m, p)
	} else {
		arg := &api.DefinedSet{
			Type: int32(typ),
		}
		stream, e := client.GetDefinedSets(context.Background(), arg)
		if e != nil {
			return e
		}
		for {
			p, e := stream.Recv()
			if e == io.EOF {
				break
			} else if e != nil {
				return e
			}
			m = append(m, p)
		}
	}
	if globalOpts.Json {
		j, _ := json.Marshal(m)
		fmt.Println(string(j))
		return nil
	}
	if globalOpts.Quiet {
		if len(args) > 0 {
			for _, p := range m[0].List {
				fmt.Println(p)
			}
			for _, p := range m[0].Prefixes {
				fmt.Printf("%s %d..%d\n", p.IpPrefix, p.MaskLengthMin, p.MaskLengthMax)
			}
		} else {
			for _, p := range m {
				fmt.Println(p.Name)
			}
		}
		return nil
	}
	sort.Sort(m)
	var output string
	switch v {
	case CMD_PREFIX:
		output = formatPolicyPrefix(true, 0, m)
	case CMD_NEIGHBOR:
		output = formatDefinedSet(true, "ADDRESS", 0, m)
	case CMD_ASPATH:
		output = formatDefinedSet(true, "AS-PATH", 0, m)
	case CMD_COMMUNITY:
		output = formatDefinedSet(true, "COMMUNITY", 0, m)
	case CMD_EXTCOMMUNITY:
		output = formatDefinedSet(true, "EXT-COMMUNITY", 0, m)
	}
	fmt.Print(output)
	return nil
}

func parsePrefixSet(args []string) (*api.DefinedSet, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("empty neighbor set name")
	}
	name := args[0]
	args = args[1:]
	var list []*api.Prefix
	if len(args) > 0 {
		_, ipNet, err := net.ParseCIDR(args[0])
		if err != nil {
			return nil, fmt.Errorf("invalid prefix: %s\nplease enter ipv4 or ipv6 format", args[1])
		}
		l, _ := ipNet.Mask.Size()
		prefix := &api.Prefix{
			IpPrefix:      args[0],
			MaskLengthMin: uint32(l),
			MaskLengthMax: uint32(l),
		}
		if len(args) > 1 {
			maskRange := args[1]
			exp := regexp.MustCompile("(\\d+)\\.\\.(\\d+)")
			elems := exp.FindStringSubmatch(maskRange)
			if len(elems) != 3 {
				return nil, fmt.Errorf("invalid mask length range: %s", maskRange)
			}
			// we've already checked the range is sane by regexp
			min, _ := strconv.Atoi(elems[1])
			max, _ := strconv.Atoi(elems[2])
			if min > max {
				return nil, fmt.Errorf("invalid mask length range: %s", maskRange)
			}
			if ipv4 := ipNet.IP.To4(); ipv4 != nil {
				f := func(i int) bool {
					return i >= 0 && i <= 32
				}
				if !f(min) || !f(max) {
					return nil, fmt.Errorf("ipv4 mask length range outside scope :%s", maskRange)
				}
			} else {
				f := func(i int) bool {
					return i >= 0 && i <= 128
				}
				if !f(min) || !f(max) {
					return nil, fmt.Errorf("ipv6 mask length range outside scope :%s", maskRange)
				}
			}
			prefix.MaskLengthMin = uint32(min)
			prefix.MaskLengthMax = uint32(max)
		}
		list = []*api.Prefix{prefix}
	}
	return &api.DefinedSet{
		Type:     int32(table.DEFINED_TYPE_PREFIX),
		Name:     name,
		Prefixes: list,
	}, nil
}

func parseNeighborSet(args []string) (*api.DefinedSet, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("empty neighbor set name")
	}
	name := args[0]
	args = args[1:]
	for _, arg := range args {
		address := net.ParseIP(arg)
		if address.To4() == nil && address.To16() == nil {
			return nil, fmt.Errorf("invalid address: %s\nplease enter ipv4 or ipv6 format", arg)
		}
	}
	return &api.DefinedSet{
		Type: int32(table.DEFINED_TYPE_NEIGHBOR),
		Name: name,
		List: args,
	}, nil
}

func parseAsPathSet(args []string) (*api.DefinedSet, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("empty as-path set name")
	}
	name := args[0]
	args = args[1:]
	for _, arg := range args {
		_, err := regexp.Compile(arg)
		if err != nil {
			return nil, err
		}
	}
	return &api.DefinedSet{
		Type: int32(table.DEFINED_TYPE_AS_PATH),
		Name: name,
		List: args,
	}, nil
}

func parseCommunitySet(args []string) (*api.DefinedSet, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("empty community set name")
	}
	name := args[0]
	args = args[1:]
	for _, arg := range args {
		if _, err := table.ParseCommunityRegexp(arg); err != nil {
			return nil, err
		}
	}
	return &api.DefinedSet{
		Type: int32(table.DEFINED_TYPE_COMMUNITY),
		Name: name,
		List: args,
	}, nil
}

func parseExtCommunitySet(args []string) (*api.DefinedSet, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("empty ext-community set name")
	}
	name := args[0]
	args = args[1:]
	for _, arg := range args {
		if _, _, err := table.ParseExtCommunityRegexp(arg); err != nil {
			return nil, err
		}
	}
	return &api.DefinedSet{
		Type: int32(table.DEFINED_TYPE_EXT_COMMUNITY),
		Name: name,
		List: args,
	}, nil
}

func parseDefinedSet(settype string, args []string) (*api.DefinedSet, error) {
	switch settype {
	case CMD_PREFIX:
		return parsePrefixSet(args)
	case CMD_NEIGHBOR:
		return parseNeighborSet(args)
	case CMD_ASPATH:
		return parseAsPathSet(args)
	case CMD_COMMUNITY:
		return parseCommunitySet(args)
	case CMD_EXTCOMMUNITY:
		return parseExtCommunitySet(args)
	default:
		return nil, fmt.Errorf("invalid setype: %s", settype)
	}
}

var modPolicyUsageFormat = map[string]string{
	CMD_PREFIX:       "usage: policy prefix %s <name> [<prefix> [<mask range>]]",
	CMD_NEIGHBOR:     "usage: policy neighbor %s <name> [<neighbor address>...]",
	CMD_ASPATH:       "usage: policy aspath %s <name> [<regexp>...]",
	CMD_COMMUNITY:    "usage: policy community %s <name> [<regexp>...]",
	CMD_EXTCOMMUNITY: "usage: policy extcommunity %s <name> [<regexp>...]",
}

func modDefinedSet(settype string, modtype string, args []string) error {
	var d *api.DefinedSet
	var err error
	if len(args) < 1 {
		return fmt.Errorf(modPolicyUsageFormat[settype], modtype)
	}
	if d, err = parseDefinedSet(settype, args); err != nil {
		return err
	}
	var op api.Operation
	switch modtype {
	case CMD_ADD:
		op = api.Operation_ADD
	case CMD_DEL:
		if len(args) < 2 {
			op = api.Operation_DEL_ALL
		} else {
			op = api.Operation_DEL
		}
	case CMD_SET:
		op = api.Operation_REPLACE
	}
	_, err = client.ModDefinedSet(context.Background(), &api.ModDefinedSetArguments{
		Operation: op,
		Set:       d,
	})
	return err
}

func printStatement(indent int, s *api.Statement) {
	sIndent := func(indent int) string {
		return strings.Repeat(" ", indent)
	}
	fmt.Printf("%sStatementName %s:\n", sIndent(indent), s.Name)
	fmt.Printf("%sConditions:\n", sIndent(indent+2))

	ps := s.Conditions.PrefixSet
	if ps != nil {
		fmt.Printf("%sPrefixSet: %s %s\n", sIndent(indent+4), table.MatchOption(ps.Option), ps.Name)
	}

	ns := s.Conditions.NeighborSet
	if ns != nil {
		fmt.Printf("%sNeighborSet: %s %s\n", sIndent(indent+4), table.MatchOption(ns.Option), ns.Name)
	}

	aps := s.Conditions.AsPathSet
	if aps != nil {
		fmt.Printf("%sAsPathSet: %s %s\n", sIndent(indent+4), table.MatchOption(aps.Option), aps.Name)
	}

	cs := s.Conditions.CommunitySet
	if cs != nil {
		fmt.Printf("%sCommunitySet: %s %s\n", sIndent(indent+4), table.MatchOption(cs.Option), cs.Name)
	}

	ecs := s.Conditions.ExtCommunitySet
	if ecs != nil {
		fmt.Printf("%sExtCommunitySet: %s %s\n", sIndent(indent+4), table.MatchOption(ecs.Option), ecs.Name)
	}

	asPathLentgh := s.Conditions.AsPathLength
	if asPathLentgh != nil {
		fmt.Printf("%sAsPathLength: %s %s\n", sIndent(indent+4), asPathLentgh.Type, asPathLentgh.Length)
	}
	fmt.Printf("%sActions:\n", sIndent(indent+2))

	formatComAction := func(c *api.CommunityAction) string {
		option := table.CommunityOptionNameMap[config.BgpSetCommunityOptionType(c.Option)]
		if len(c.Communities) != 0 {
			communities := strings.Join(c.Communities, ",")
			option = fmt.Sprintf("%s[%s]", option, communities)
		}
		return option
	}
	if s.Actions.Community != nil {
		fmt.Printf("%sCommunity:       %s\n", sIndent(indent+4), formatComAction(s.Actions.Community))
	}
	if s.Actions.ExtCommunity != nil {
		fmt.Printf("%sExtCommunity:    %s\n", sIndent(indent+4), formatComAction(s.Actions.ExtCommunity))
	}
	if s.Actions.Med != nil {
		fmt.Printf("%sMed:             %s\n", sIndent(indent+4), s.Actions.Med.Value)
	}
	if s.Actions.AsPrepend != nil {
		var asn string
		if s.Actions.AsPrepend.UseLeftMost {
			asn = "left-most"
		} else {
			asn = fmt.Sprintf("%d", s.Actions.AsPrepend.Asn)
		}

		fmt.Printf("%sAsPrepend:       %s   %d\n", sIndent(indent+4), asn, s.Actions.AsPrepend.Repeat)
	}
	fmt.Printf("%s%s\n", sIndent(indent+4), s.Actions.RouteAction)
}

func showPolicyStatement(indent int, pd *api.PolicyDefinition) {
	for _, s := range pd.Statements {
		printStatement(indent, s)
	}
}

func showPolicyRoutePolicies() error {
	arg := &api.PolicyArguments{
		Resource: api.Resource_POLICY_ROUTEPOLICY,
	}
	stream, e := client.GetPolicyRoutePolicies(context.Background(), arg)
	if e != nil {
		return e
	}
	m := policyDefinitions{}
	for {
		n, e := stream.Recv()
		if e == io.EOF {
			break
		} else if e != nil {
			return e
		}
		m = append(m, n)
	}

	if globalOpts.Json {
		j, _ := json.Marshal(m)
		fmt.Println(string(j))
		return nil
	}
	if globalOpts.Quiet {
		for _, p := range m {
			fmt.Println(p.Name)
		}
		return nil
	}
	sort.Sort(m)

	for _, pd := range m {
		fmt.Printf("PolicyName %s:\n", pd.Name)
		showPolicyStatement(4, pd)
	}
	return nil
}

func showPolicyRoutePolicy(args []string) error {
	arg := &api.PolicyArguments{
		Resource: api.Resource_POLICY_ROUTEPOLICY,
		Name:     args[0],
	}
	pd, e := client.GetPolicyRoutePolicy(context.Background(), arg)
	if e != nil {
		return e
	}

	if globalOpts.Json {
		j, _ := json.Marshal(pd)
		fmt.Println(string(j))
		return nil
	}

	if globalOpts.Quiet {
		for _, st := range pd.Statements {
			fmt.Println(st.Name)
		}
		return nil
	}

	fmt.Printf("PolicyName %s:\n", pd.Name)
	showPolicyStatement(2, pd)
	return nil
}

func parseConditions() (*api.Conditions, error) {
	checkFormat := func(option string, isRestricted bool) (int32, string, error) {
		regStr, _ := regexp.Compile("^(.*)\\[(.*)\\]$")
		isMatched := regStr.MatchString(option)
		var op int32
		var name string
		if !isMatched {
			return op, name, fmt.Errorf("Please enter the <match option>[condition name]")
		}
		group := regStr.FindStringSubmatch(option)
		switch strings.ToLower(group[1]) {
		case "any":
			op = int32(table.MATCH_OPTION_ANY)
		case "invert":
			op = int32(table.MATCH_OPTION_INVERT)
		case "all":
			if isRestricted {
				return op, name, fmt.Errorf("can't use 'all' for the condition option")
			}
			op = int32(table.MATCH_OPTION_ALL)
		default:
			return op, name, fmt.Errorf("unknown condition option")
		}
		name = group[2]
		return op, name, nil
	}

	conditions := &api.Conditions{}
	if conditionOpts.Prefix != "" {
		op, name, err := checkFormat(conditionOpts.Prefix, true)
		if err != nil {
			return nil, fmt.Errorf("invalid prefix option format\n%s", err)
		}
		conditions.PrefixSet = &api.MatchSet{
			Name:   name,
			Option: op,
		}
	}
	if conditionOpts.Neighbor != "" {
		op, name, err := checkFormat(conditionOpts.Neighbor, true)
		if err != nil {
			return nil, fmt.Errorf("invalid neighbor option format\n%s", err)
		}
		conditions.NeighborSet = &api.MatchSet{
			Name:   name,
			Option: op,
		}
	}
	if conditionOpts.AsPath != "" {
		op, name, err := checkFormat(conditionOpts.AsPath, false)
		if err != nil {
			return nil, fmt.Errorf("invalid aspath option format\n%s", err)
		}
		conditions.AsPathSet = &api.MatchSet{
			Name:   name,
			Option: op,
		}
	}
	if conditionOpts.Community != "" {
		op, name, err := checkFormat(conditionOpts.Community, false)
		if err != nil {
			return nil, fmt.Errorf("invalid community option format\n%s", err)
		}
		conditions.CommunitySet = &api.MatchSet{
			Name:   name,
			Option: op,
		}
	}
	if conditionOpts.ExtCommunity != "" {
		op, name, err := checkFormat(conditionOpts.ExtCommunity, false)
		if err != nil {
			return nil, fmt.Errorf("invalid extended community option format\n%s", err)
		}
		conditions.ExtCommunitySet = &api.MatchSet{
			Name:   name,
			Option: op,
		}
	}
	if conditionOpts.AsPathLength != "" {
		asPathLen := conditionOpts.AsPathLength
		elems := strings.Split(asPathLen, ",")
		if len(elems) != 2 {
			return nil, fmt.Errorf("invalid as path length: %s\nPlease enter the <value>,<operator>", asPathLen)
		}
		var typ int32
		switch strings.ToLower(elems[0]) {
		case "eq":
			typ = int32(table.ATTRIBUTE_EQ)
		case "ge":
			typ = int32(table.ATTRIBUTE_GE)
		case "le":
			typ = int32(table.ATTRIBUTE_LE)
		default:
			return nil, fmt.Errorf("invalid aspath length action type")

		}
		length, err := strconv.Atoi(elems[1])
		if err != nil {
			return nil, fmt.Errorf("invalid as path length: %s\nPlease enter a numeric", elems[1])
		}
		conditions.AsPathLength = &api.AsPathLength{
			Type:   typ,
			Length: uint32(length),
		}
	}
	return conditions, nil
}

func parseRouteAction(rType string) (api.RouteAction, error) {
	routeActionUpper := strings.ToUpper(rType)
	switch routeActionUpper {
	case "ACCEPT":
		return api.RouteAction_ACCEPT, nil
	case "REJECT":
		return api.RouteAction_REJECT, nil
	default:
		return api.RouteAction_NONE, fmt.Errorf("invalid route action: %s\nPlease enter the accept or reject", rType)
	}
}

func parseCommunityAction(communityStr string) (*api.CommunityAction, error) {
	exp := regexp.MustCompile("^(.*)\\[(.*)\\]$")
	elems := exp.FindStringSubmatch(communityStr)
	if len(elems) != 3 {
		e := fmt.Sprintf("invalid format: %s\n", communityStr)
		e += "please enter the <option>[<comunity>,<comunity>,...]"
		return nil, fmt.Errorf("%s", e)
	}

	var op int32
	switch strings.ToLower(elems[1]) {
	case "add":
		op = int32(config.BGP_SET_COMMUNITY_OPTION_TYPE_ADD)
	case "remove":
		op = int32(config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE)
	case "replace":
		op = int32(config.BGP_SET_COMMUNITY_OPTION_TYPE_REPLACE)
	default:
		return nil, fmt.Errorf("invalid community action option")
	}
	return &api.CommunityAction{
		Communities: strings.Split(elems[2], ","),
		Option:      op,
	}, nil
}

func parseAsPrependAction(communityStr string) (*api.AsPrependAction, error) {
	exp := regexp.MustCompile("^([0-9]+|last-as),([0-9]+)$")
	elems := exp.FindStringSubmatch(communityStr)
	if len(elems) != 3 {
		return nil, fmt.Errorf("invalid asprepend action format")
	}
	asn, err := strconv.Atoi(elems[1])
	var lastAs bool
	if err != nil {
		lastAs = true
	}
	repeat, err := strconv.Atoi(elems[2])
	if err != nil {
		return nil, fmt.Errorf("%s", "invalid repeat count")
	}
	return &api.AsPrependAction{
		Asn:         uint32(asn),
		Repeat:      uint32(repeat),
		UseLeftMost: lastAs,
	}, nil
}

func parseMedAction(arg string) (*api.MedAction, error) {
	exp := regexp.MustCompile("^(\\+|\\-)?([0-9]+)$")
	elems := exp.FindStringSubmatch(arg)
	if len(elems) != 3 {
		return nil, fmt.Errorf("invalid med action format")
	}
	typ := int32(table.MED_ACTION_MOD)
	if elems[1] == "" {
		typ = int32(table.MED_ACTION_REPLACE)
	}
	value, _ := strconv.Atoi(elems[2])
	return &api.MedAction{
		Type:  typ,
		Value: int64(value),
	}, nil
}

func checkAsPrependAction(asStr string) error {
	regPrepend, _ := regexp.Compile("^([0-9]+|last-as),([0-9]+)$")
	if !regPrepend.MatchString(asStr) {
		e := fmt.Sprintf("invalid format: %s\n", asStr)
		e += "please enter as <AS>,<repeat count>"
		return fmt.Errorf("%s", e)
	}
	return nil
}

func parseActions() (*api.Actions, error) {
	actions := &api.Actions{}
	if actionOpts.RouteAction != "" {
		routeAction, e := parseRouteAction(actionOpts.RouteAction)
		if e != nil {
			return nil, e
		}
		actions.RouteAction = routeAction
	}
	if actionOpts.CommunityAction != "" {
		community, e := parseCommunityAction(actionOpts.CommunityAction)
		if e != nil {
			return nil, e
		}
		actions.Community = community
	}
	if actionOpts.MedAction != "" {
		med, e := parseMedAction(actionOpts.MedAction)
		if e != nil {
			return nil, e
		}
		actions.Med = med
	}
	if actionOpts.AsPathPrependAction != "" {

		s := actionOpts.AsPathPrependAction
		e := checkAsPrependAction(s)
		if e != nil {
			return nil, e
		}

		p, e := parseAsPrependAction(s)
		if e != nil {
			return nil, e
		}
		actions.AsPrepend = p
	}
	return actions, nil
}

func modPolicy(resource api.Resource, op api.Operation, data interface{}) error {
	pd := &api.PolicyDefinition{}
	if resource != api.Resource_POLICY_ROUTEPOLICY {
		co := &api.Conditions{}
		switch resource {
		case api.Resource_POLICY_PREFIX:
			co.PrefixSet = data.(*api.MatchSet)
		case api.Resource_POLICY_NEIGHBOR:
			co.NeighborSet = data.(*api.MatchSet)
		case api.Resource_POLICY_ASPATH:
			co.AsPathSet = data.(*api.MatchSet)
		case api.Resource_POLICY_COMMUNITY:
			co.CommunitySet = data.(*api.MatchSet)
		case api.Resource_POLICY_EXTCOMMUNITY:
			co.ExtCommunitySet = data.(*api.MatchSet)
		}
		pd.Statements = []*api.Statement{{Conditions: co}}
	} else {
		pd = data.(*api.PolicyDefinition)
	}
	arg := &api.PolicyArguments{
		Resource:         resource,
		Operation:        op,
		PolicyDefinition: pd,
	}
	stream, err := client.ModPolicyRoutePolicy(context.Background())
	if err != nil {
		return err
	}
	err = stream.Send(arg)
	if err != nil {
		return err
	}
	stream.CloseSend()

	res, e := stream.Recv()
	if e != nil {
		return e
	}
	if res.Code != api.Error_SUCCESS {
		return fmt.Errorf("error: code: %d, msg: %s", res.Code, res.Msg)
	}
	return nil
}

func modPolicyRoutePolicy(modtype string, eArgs []string) error {
	var operation api.Operation
	pd := &api.PolicyDefinition{}
	if len(eArgs) > 0 {
		pd.Name = eArgs[0]
	}

	switch modtype {
	case CMD_ADD:
		if len(eArgs) != 2 {
			return fmt.Errorf("usage:  gobgp policy routepoilcy add <route policy name> <statement name>")
		}
		stmt := &api.Statement{
			Name: eArgs[1],
		}
		conditions, err := parseConditions()
		if err != nil {
			return err
		}
		actions, err := parseActions()
		if err != nil {
			return err
		}
		stmt.Conditions = conditions
		stmt.Actions = actions

		pd.Statements = []*api.Statement{stmt}
		operation = api.Operation_ADD

	case CMD_DEL:
		if len(eArgs) == 0 {
			return fmt.Errorf("usage: policy neighbor del <route policy name> [<statement name>]")
		} else if len(eArgs) == 1 {
			operation = api.Operation_DEL
		} else if len(eArgs) == 2 {
			stmt := &api.Statement{
				Name: eArgs[1],
			}
			pd.Statements = []*api.Statement{stmt}
			operation = api.Operation_DEL
		}
	case CMD_ALL:
		if len(eArgs) > 0 {
			return fmt.Errorf("Argument can not be entered: %s", eArgs[0:])
		}
		operation = api.Operation_DEL_ALL
	default:
		return fmt.Errorf("invalid modType %s", modtype)
	}
	if e := modPolicy(api.Resource_POLICY_ROUTEPOLICY, operation, pd); e != nil {
		return e
	}
	return nil
}

func showStatement(args []string) error {
	m := []*api.Statement{}
	if len(args) > 0 {
		arg := &api.Statement{
			Name: args[0],
		}
		p, e := client.GetStatement(context.Background(), arg)
		if e != nil {
			return e
		}
		m = append(m, p)
	} else {
		arg := &api.Statement{}
		stream, e := client.GetStatements(context.Background(), arg)
		if e != nil {
			return e
		}
		for {
			p, e := stream.Recv()
			if e == io.EOF {
				break
			} else if e != nil {
				return e
			}
			m = append(m, p)
		}
	}
	for _, s := range m {
		printStatement(0, s)
	}
	return nil
}

func modStatement(op string, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gobgp policy statement %s <name>", op)
	}
	name := args[0]
	var o api.Operation
	switch op {
	case CMD_ADD:
		o = api.Operation_ADD
	case CMD_DEL:
		o = api.Operation_DEL
	default:
		return fmt.Errorf("invalid operation: %s", op)
	}
	stmt := &api.Statement{
		Name: name,
	}
	arg := &api.ModStatementArguments{
		Operation: o,
		Statement: stmt,
	}
	_, err := client.ModStatement(context.Background(), arg)
	return err
}

func modCondition(name, op string, args []string) error {
	var o api.Operation
	switch op {
	case CMD_ADD:
		o = api.Operation_ADD
	case CMD_DEL:
		o = api.Operation_DEL
	case CMD_SET:
		o = api.Operation_REPLACE
	default:
		return fmt.Errorf("invalid operation: %s", op)
	}
	stmt := &api.Statement{
		Name:       name,
		Conditions: &api.Conditions{},
	}
	arg := &api.ModStatementArguments{
		Operation: o,
		Statement: stmt,
	}
	usage := fmt.Sprintf("usage: gobgp policy statement %s %s condition", name, op)
	if len(args) < 1 {
		return fmt.Errorf("%s { prefix | neighbor | as-path | community | ext-community | as-path-length | rpki }", usage)
	}
	typ := args[0]
	args = args[1:]
	switch typ {
	case "prefix":
		if len(args) < 1 {
			return fmt.Errorf("%s prefix <set-name> [{ any | invert }]", usage)
		}
		stmt.Conditions.PrefixSet = &api.MatchSet{
			Name: args[0],
		}
		if len(args) == 1 {
			break
		}
		switch strings.ToLower(args[1]) {
		case "any":
			stmt.Conditions.PrefixSet.Option = int32(config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY)
		case "invert":
			stmt.Conditions.PrefixSet.Option = int32(config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_INVERT)
		default:
			return fmt.Errorf("%s prefix <set-name> [{ any | invert }]", usage)
		}
	case "neighbor":
		if len(args) < 1 {
			return fmt.Errorf("%s neighbor <set-name> [{ any | invert }]", usage)
		}
		stmt.Conditions.NeighborSet = &api.MatchSet{
			Name: args[0],
		}
		if len(args) == 1 {
			break
		}
		switch strings.ToLower(args[1]) {
		case "any":
			stmt.Conditions.NeighborSet.Option = int32(config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY)
		case "invert":
			stmt.Conditions.NeighborSet.Option = int32(config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_INVERT)
		default:
			return fmt.Errorf("%s neighbor <set-name> [{ any | invert }]", usage)
		}
	case "as-path":
		if len(args) < 1 {
			return fmt.Errorf("%s as-path <set-name> [{ any | all | invert }]", usage)
		}
		stmt.Conditions.AsPathSet = &api.MatchSet{
			Name: args[0],
		}
		if len(args) == 1 {
			break
		}
		switch strings.ToLower(args[1]) {
		case "any":
			stmt.Conditions.AsPathSet.Option = int32(config.MATCH_SET_OPTIONS_TYPE_ANY)
		case "all":
			stmt.Conditions.AsPathSet.Option = int32(config.MATCH_SET_OPTIONS_TYPE_ALL)
		case "invert":
			stmt.Conditions.AsPathSet.Option = int32(config.MATCH_SET_OPTIONS_TYPE_INVERT)
		default:
			return fmt.Errorf("%s as-path <set-name> [{ any | all | invert }]", usage)
		}
	case "community":
		if len(args) < 1 {
			return fmt.Errorf("%s community <set-name> [{ any | all | invert }]", usage)
		}
		stmt.Conditions.CommunitySet = &api.MatchSet{
			Name: args[0],
		}
		if len(args) == 1 {
			break
		}
		switch strings.ToLower(args[1]) {
		case "any":
			stmt.Conditions.CommunitySet.Option = int32(config.MATCH_SET_OPTIONS_TYPE_ANY)
		case "all":
			stmt.Conditions.CommunitySet.Option = int32(config.MATCH_SET_OPTIONS_TYPE_ALL)
		case "invert":
			stmt.Conditions.CommunitySet.Option = int32(config.MATCH_SET_OPTIONS_TYPE_INVERT)
		default:
			return fmt.Errorf("%s community <set-name> [{ any | all | invert }]", usage)
		}
	case "ext-community":
		if len(args) < 1 {
			return fmt.Errorf("%s ext-community <set-name> [{ any | all | invert }]", usage)
		}
		stmt.Conditions.ExtCommunitySet = &api.MatchSet{
			Name: args[0],
		}
		if len(args) == 1 {
			break
		}
		switch strings.ToLower(args[1]) {
		case "any":
			stmt.Conditions.ExtCommunitySet.Option = int32(config.MATCH_SET_OPTIONS_TYPE_ANY)
		case "all":
			stmt.Conditions.ExtCommunitySet.Option = int32(config.MATCH_SET_OPTIONS_TYPE_ALL)
		case "invert":
			stmt.Conditions.ExtCommunitySet.Option = int32(config.MATCH_SET_OPTIONS_TYPE_INVERT)
		default:
			return fmt.Errorf("%s ext-community <set-name> [{ any | all | invert }]", usage)
		}
	case "as-path-length":
		if len(args) < 2 {
			return fmt.Errorf("%s as-path-length <length> { eq | ge | le }", usage)
		}
		length, err := strconv.Atoi(args[0])
		if err != nil {
			return err
		}
		stmt.Conditions.AsPathLength = &api.AsPathLength{
			Length: uint32(length),
		}
		switch strings.ToLower(args[1]) {
		case "eq":
			stmt.Conditions.AsPathLength.Type = int32(table.ATTRIBUTE_EQ)
		case "ge":
			stmt.Conditions.AsPathLength.Type = int32(table.ATTRIBUTE_GE)
		case "le":
			stmt.Conditions.AsPathLength.Type = int32(table.ATTRIBUTE_LE)
		default:
			return fmt.Errorf("%s as-path-length <length> { eq | ge | le }", usage)
		}
	case "rpki":
		if len(args) < 1 {
			return fmt.Errorf("%s rpki { valid | invalid | not-found }")
		}
		switch strings.ToLower(args[0]) {
		case "valid":
			stmt.Conditions.RpkiResult = int32(config.RPKI_VALIDATION_RESULT_TYPE_VALID)
		case "invalid":
			stmt.Conditions.RpkiResult = int32(config.RPKI_VALIDATION_RESULT_TYPE_INVALID)
		case "not-found":
			stmt.Conditions.RpkiResult = int32(config.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND)
		default:
			return fmt.Errorf("%s rpki { valid | invalid | not-found }")
		}
	}
	_, err := client.ModStatement(context.Background(), arg)
	return err
}

func modAction(name, op string, args []string) error {
	var o api.Operation
	switch op {
	case CMD_ADD:
		o = api.Operation_ADD
	case CMD_DEL:
		o = api.Operation_DEL
	case CMD_SET:
		o = api.Operation_REPLACE
	default:
		return fmt.Errorf("invalid operation: %s", op)
	}
	stmt := &api.Statement{
		Name:    name,
		Actions: &api.Actions{},
	}
	arg := &api.ModStatementArguments{
		Operation: o,
		Statement: stmt,
	}
	usage := fmt.Sprintf("usage: gobgp policy statement %s %s action", name, op)
	if len(args) < 1 {
		return fmt.Errorf("%s { reject | accept | community | ext-community | med | as-prepend }", usage)
	}
	typ := args[0]
	args = args[1:]
	switch typ {
	case "reject":
		stmt.Actions.RouteAction = api.RouteAction_REJECT
	case "accept":
		stmt.Actions.RouteAction = api.RouteAction_ACCEPT
	case "community":
		if len(args) < 1 {
			return fmt.Errorf("%s community { add | remove | replace } <value>...", usage)
		}
		stmt.Actions.Community = &api.CommunityAction{
			Communities: args[1:],
		}
		switch strings.ToLower(args[0]) {
		case "add":
			stmt.Actions.Community.Option = int32(config.BGP_SET_COMMUNITY_OPTION_TYPE_ADD)
		case "remove":
			stmt.Actions.Community.Option = int32(config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE)
		case "replace":
			stmt.Actions.Community.Option = int32(config.BGP_SET_COMMUNITY_OPTION_TYPE_REPLACE)
		default:
			return fmt.Errorf("%s community { add | remove | replace } <value>...", usage)
		}
	case "ext-community":
		if len(args) < 1 {
			return fmt.Errorf("%s ext-community { add | remove | replace } <value>...", usage)
		}
		stmt.Actions.ExtCommunity = &api.CommunityAction{
			Communities: args[1:],
		}
		switch strings.ToLower(args[0]) {
		case "add":
			stmt.Actions.ExtCommunity.Option = int32(config.BGP_SET_COMMUNITY_OPTION_TYPE_ADD)
		case "remove":
			stmt.Actions.ExtCommunity.Option = int32(config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE)
		case "replace":
			stmt.Actions.ExtCommunity.Option = int32(config.BGP_SET_COMMUNITY_OPTION_TYPE_REPLACE)
		default:
			return fmt.Errorf("%s ext-community { add | remove | replace } <value>...", usage)
		}
	case "med":
		if len(args) < 2 {
			return fmt.Errorf("%s med { add | sub | set } <value>")
		}
		med, err := strconv.Atoi(args[1])
		if err != nil {
			return err
		}
		stmt.Actions.Med = &api.MedAction{
			Value: int64(med),
		}
		switch strings.ToLower(args[0]) {
		case "add":
			stmt.Actions.Med.Type = int32(table.MED_ACTION_MOD)
		case "sub":
			stmt.Actions.Med.Type = int32(table.MED_ACTION_MOD)
			stmt.Actions.Med.Value *= -1
		case "set":
			stmt.Actions.Med.Type = int32(table.MED_ACTION_REPLACE)
		default:
			return fmt.Errorf("%s med { add | sub | set } <value>")
		}
	case "as-prepend":
		if len(args) < 2 {
			return fmt.Errorf("%s as-prepend { <asn> | last-as } <repeat-value>", usage)
		}
		asn, err := strconv.Atoi(args[0])
		last := false
		if args[0] == "last-as" {
			last = true
		} else if err != nil {
			return err
		}
		repeat, err := strconv.Atoi(args[1])
		if err != nil {
			return err
		}
		stmt.Actions.AsPrepend = &api.AsPrependAction{
			Asn:         uint32(asn),
			Repeat:      uint32(repeat),
			UseLeftMost: last,
		}
	}
	_, err := client.ModStatement(context.Background(), arg)
	return err
}

func NewPolicyCmd() *cobra.Command {
	policyCmd := &cobra.Command{
		Use: CMD_POLICY,
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			if len(args) == 0 {
				err = showPolicyRoutePolicies()
			} else {
				err = showPolicyRoutePolicy(args)
			}
			if err != nil {
				fmt.Println(err)
			}
		},
	}

	for _, v := range []string{CMD_PREFIX, CMD_NEIGHBOR, CMD_ASPATH, CMD_COMMUNITY, CMD_EXTCOMMUNITY} {
		cmd := &cobra.Command{
			Use: v,
			Run: func(cmd *cobra.Command, args []string) {
				if err := showDefinedSet(cmd.Use, args); err != nil {
					fmt.Println(err)
				}
			},
		}
		for _, w := range []string{CMD_ADD, CMD_DEL, CMD_SET} {
			subcmd := &cobra.Command{
				Use: w,
				Run: func(c *cobra.Command, args []string) {
					if err := modDefinedSet(cmd.Use, c.Use, args); err != nil {
						fmt.Println(err)
					}
				},
			}
			cmd.AddCommand(subcmd)
		}
		policyCmd.AddCommand(cmd)
	}

	stmtCmdImpl := &cobra.Command{}
	for _, v := range []string{CMD_ADD, CMD_DEL, CMD_SET} {
		cmd := &cobra.Command{
			Use: v,
		}
		for _, w := range []string{CMD_CONDITION, CMD_ACTION} {
			subcmd := &cobra.Command{
				Use: w,
				Run: func(c *cobra.Command, args []string) {
					name := args[len(args)-1]
					args = args[:len(args)-1]
					var err error
					if c.Use == CMD_CONDITION {
						err = modCondition(name, cmd.Use, args)
					} else {
						err = modAction(name, cmd.Use, args)
					}
					if err != nil {
						fmt.Println(err)
						os.Exit(1)
					}
				},
			}
			cmd.AddCommand(subcmd)
		}
		stmtCmdImpl.AddCommand(cmd)
	}

	stmtCmd := &cobra.Command{
		Use: CMD_STATEMENT,
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			if len(args) < 2 {
				err = showStatement(args)
			} else {
				args = append(args[1:], args[0])
				stmtCmdImpl.SetArgs(args)
				err = stmtCmdImpl.Execute()
			}
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
	for _, v := range []string{CMD_ADD, CMD_DEL} {
		cmd := &cobra.Command{
			Use: v,
			Run: func(c *cobra.Command, args []string) {
				err := modStatement(c.Use, args)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
			},
		}
		stmtCmd.AddCommand(cmd)
	}
	policyCmd.AddCommand(stmtCmd)

	return policyCmd
}
