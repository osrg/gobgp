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
	"regexp"
	"strconv"
	"strings"

	"github.com/osrg/gobgp/internal/pkg/apiutil"

	"github.com/spf13/cobra"

	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/internal/pkg/config"
	"github.com/osrg/gobgp/pkg/packet/bgp"
)

var (
	_regexpCommunity      = regexp.MustCompile(`\^\^(\S+)\$\$`)
	repexpCommunity       = regexp.MustCompile(`(\d+.)*\d+:\d+`)
	regexpLargeCommunity  = regexp.MustCompile(`\d+:\d+:\d+`)
	regexpCommunityString = regexp.MustCompile(`[\^\$]`)
)

func parseCommunityRegexp(arg string) (*regexp.Regexp, error) {
	i, err := strconv.ParseUint(arg, 10, 32)
	if err == nil {
		return regexp.Compile(fmt.Sprintf("^%d:%d$", i>>16, i&0x0000ffff))
	}
	if repexpCommunity.MatchString(arg) {
		return regexp.Compile(fmt.Sprintf("^%s$", arg))
	}
	for i, v := range bgp.WellKnownCommunityNameMap {
		if strings.Replace(strings.ToLower(arg), "_", "-", -1) == v {
			return regexp.Compile(fmt.Sprintf("^%d:%d$", i>>16, i&0x0000ffff))
		}
	}
	exp, err := regexp.Compile(arg)
	if err != nil {
		return nil, fmt.Errorf("invalid community format: %s", arg)
	}
	return exp, nil
}

func parseExtCommunityRegexp(arg string) (bgp.ExtendedCommunityAttrSubType, *regexp.Regexp, error) {
	var subtype bgp.ExtendedCommunityAttrSubType
	elems := strings.SplitN(arg, ":", 2)
	if len(elems) < 2 {
		return subtype, nil, fmt.Errorf("invalid ext-community format([rt|soo]:<value>)")
	}
	switch strings.ToLower(elems[0]) {
	case "rt":
		subtype = bgp.EC_SUBTYPE_ROUTE_TARGET
	case "soo":
		subtype = bgp.EC_SUBTYPE_ROUTE_ORIGIN
	default:
		return subtype, nil, fmt.Errorf("unknown ext-community subtype. rt, soo is supported")
	}
	exp, err := parseCommunityRegexp(elems[1])
	return subtype, exp, err
}

func parseLargeCommunityRegexp(arg string) (*regexp.Regexp, error) {
	if regexpLargeCommunity.MatchString(arg) {
		return regexp.Compile(fmt.Sprintf("^%s$", arg))
	}
	exp, err := regexp.Compile(arg)
	if err != nil {
		return nil, fmt.Errorf("invalid large-community format: %s", arg)
	}
	return exp, nil
}

func routeTypePrettyString(s api.Conditions_RouteType) string {
	switch s {
	case api.Conditions_ROUTE_TYPE_EXTERNAL:
		return "external"
	case api.Conditions_ROUTE_TYPE_INTERNAL:
		return "internal"
	case api.Conditions_ROUTE_TYPE_LOCAL:
		return "local"
	}
	return "unknown"
}

func prettyString(v interface{}) string {
	switch a := v.(type) {
	case *api.MatchSet:
		var typ string
		switch a.MatchType {
		case api.MatchType_ALL:
			typ = "all"
		case api.MatchType_ANY:
			typ = "any"
		case api.MatchType_INVERT:
			typ = "invert"
		}
		return fmt.Sprintf("%s %s", typ, a.GetName())
	case *api.AsPathLength:
		var typ string
		switch a.LengthType {
		case api.AsPathLengthType_EQ:
			typ = "="
		case api.AsPathLengthType_GE:
			typ = ">="
		case api.AsPathLengthType_LE:
			typ = "<="
		}
		return fmt.Sprintf("%s%d", typ, a.Length)
	case *api.CommunityAction:
		l := regexpCommunityString.ReplaceAllString(strings.Join(a.Communities, ", "), "")
		var typ string
		switch a.ActionType {
		case api.CommunityActionType_COMMUNITY_ADD:
			typ = "add"
		case api.CommunityActionType_COMMUNITY_REMOVE:
			typ = "remove"
		case api.CommunityActionType_COMMUNITY_REPLACE:
			typ = "replace"
		}
		return fmt.Sprintf("%s[%s]", typ, l)
	case *api.MedAction:
		if a.ActionType == api.MedActionType_MED_MOD && a.Value > 0 {
			return fmt.Sprintf("+%d", a.Value)
		}
		return fmt.Sprintf("%d", a.Value)
	case *api.LocalPrefAction:
		return fmt.Sprintf("%d", a.Value)
	case *api.NexthopAction:
		if a.Self {
			return "self"
		}
		return a.Address
	case *api.AsPrependAction:
		return fmt.Sprintf("prepend %d %d times", a.Asn, a.Repeat)
	}
	return "unknown"
}

func formatDefinedSet(head bool, typ string, indent int, list []*api.DefinedSet) string {
	if len(list) == 0 {
		return "Nothing defined yet\n"
	}
	buff := bytes.NewBuffer(make([]byte, 0, 64))
	sIndent := strings.Repeat(" ", indent)
	maxNameLen := 0
	for _, s := range list {
		if len(s.GetName()) > maxNameLen {
			maxNameLen = len(s.GetName())
		}
	}
	if head {
		if len("NAME") > maxNameLen {
			maxNameLen = len("NAME")
		}
	}
	format := fmt.Sprintf("%%-%ds  %%s\n", maxNameLen)
	if head {
		buff.WriteString(fmt.Sprintf(format, "NAME", typ))
	}
	for _, s := range list {
		if typ == "PREFIX" {
			l := s.GetPrefixes()
			if len(l) == 0 {
				buff.WriteString(fmt.Sprintf(format, s.GetName(), ""))
			}
			for i, x := range l {
				prefix := fmt.Sprintf("%s %d..%d", x.GetIpPrefix(), x.GetMaskLengthMin(), x.GetMaskLengthMax())
				if i == 0 {
					buff.WriteString(fmt.Sprintf(format, s.GetName(), prefix))
				} else {
					buff.WriteString(fmt.Sprint(sIndent))
					buff.WriteString(fmt.Sprintf(format, "", prefix))
				}
			}
		} else {
			l := s.GetList()
			if len(l) == 0 {
				buff.WriteString(fmt.Sprintf(format, s.GetName(), ""))
			}
			for i, x := range l {
				if typ == "COMMUNITY" || typ == "EXT-COMMUNITY" || typ == "LARGE-COMMUNITY" {
					x = _regexpCommunity.ReplaceAllString(x, "$1")
				}
				if i == 0 {
					buff.WriteString(fmt.Sprintf(format, s.GetName(), x))
				} else {
					buff.WriteString(fmt.Sprint(sIndent))
					buff.WriteString(fmt.Sprintf(format, "", x))
				}
			}
		}
	}
	return buff.String()
}

func showDefinedSet(v string, args []string) error {
	var typ api.DefinedType
	switch v {
	case cmdPrefix:
		typ = api.DefinedType_PREFIX
	case cmdNeighbor:
		typ = api.DefinedType_NEIGHBOR
	case cmdAspath:
		typ = api.DefinedType_AS_PATH
	case cmdCommunity:
		typ = api.DefinedType_COMMUNITY
	case cmdExtcommunity:
		typ = api.DefinedType_EXT_COMMUNITY
	case cmdLargecommunity:
		typ = api.DefinedType_LARGE_COMMUNITY
	default:
		return fmt.Errorf("unknown defined type: %s", v)
	}
	m := make([]*api.DefinedSet, 0)
	var name string
	if len(args) > 0 {
		name = args[0]
	}
	stream, err := client.ListDefinedSet(ctx, &api.ListDefinedSetRequest{
		DefinedType: typ,
		Name:        name,
	})
	if err != nil {
		return err
	}
	for {
		r, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		m = append(m, r.DefinedSet)
	}

	if globalOpts.Json {
		j, _ := json.Marshal(m)
		fmt.Println(string(j))
		return nil
	}
	if globalOpts.Quiet {
		if len(args) > 0 {
			fmt.Println(m)
		} else {
			for _, p := range m {
				fmt.Println(p.GetName())
			}
		}
		return nil
	}
	var output string
	switch v {
	case cmdPrefix:
		output = formatDefinedSet(true, "PREFIX", 0, m)
	case cmdNeighbor:
		output = formatDefinedSet(true, "ADDRESS", 0, m)
	case cmdAspath:
		output = formatDefinedSet(true, "AS-PATH", 0, m)
	case cmdCommunity:
		output = formatDefinedSet(true, "COMMUNITY", 0, m)
	case cmdExtcommunity:
		output = formatDefinedSet(true, "EXT-COMMUNITY", 0, m)
	case cmdLargecommunity:
		output = formatDefinedSet(true, "LARGE-COMMUNITY", 0, m)
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
		mask := ""
		if len(args) > 1 {
			mask = args[1]
		}
		min, max, err := config.ParseMaskLength(args[0], mask)
		if err != nil {
			return nil, err
		}
		prefix := &api.Prefix{
			IpPrefix:      args[0],
			MaskLengthMax: uint32(max),
			MaskLengthMin: uint32(min),
		}
		list = []*api.Prefix{prefix}
	}
	return &api.DefinedSet{
		DefinedType: api.DefinedType_PREFIX,
		Name:        name,
		Prefixes:    list,
	}, nil
}

func parseNeighborSet(args []string) (*api.DefinedSet, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("empty neighbor set name")
	}
	name := args[0]
	args = args[1:]
	list := make([]string, 0, len(args[1:]))
	for _, arg := range args {
		address := net.ParseIP(arg)
		if address.To4() != nil {
			list = append(list, fmt.Sprintf("%s/32", arg))
		} else if address.To16() != nil {
			list = append(list, fmt.Sprintf("%s/128", arg))
		} else {
			_, _, err := net.ParseCIDR(arg)
			if err != nil {
				return nil, fmt.Errorf("invalid address or prefix: %s\nplease enter ipv4 or ipv6 format", arg)
			}
		}
	}
	return &api.DefinedSet{
		DefinedType: api.DefinedType_NEIGHBOR,
		Name:        name,
		List:        list,
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
		DefinedType: api.DefinedType_AS_PATH,
		Name:        name,
		List:        args,
	}, nil
}

func parseCommunitySet(args []string) (*api.DefinedSet, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("empty community set name")
	}
	name := args[0]
	args = args[1:]
	for _, arg := range args {
		if _, err := parseCommunityRegexp(arg); err != nil {
			return nil, err
		}
	}
	return &api.DefinedSet{
		DefinedType: api.DefinedType_COMMUNITY,
		Name:        name,
		List:        args,
	}, nil
}

func parseExtCommunitySet(args []string) (*api.DefinedSet, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("empty ext-community set name")
	}
	name := args[0]
	args = args[1:]
	for _, arg := range args {
		if _, _, err := parseExtCommunityRegexp(arg); err != nil {
			return nil, err
		}
	}
	return &api.DefinedSet{
		DefinedType: api.DefinedType_EXT_COMMUNITY,
		Name:        name,
		List:        args,
	}, nil
}

func parseLargeCommunitySet(args []string) (*api.DefinedSet, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("empty large-community set name")
	}
	name := args[0]
	args = args[1:]
	for _, arg := range args {
		if _, err := parseLargeCommunityRegexp(arg); err != nil {
			return nil, err
		}
	}
	return &api.DefinedSet{
		DefinedType: api.DefinedType_LARGE_COMMUNITY,
		Name:        name,
		List:        args,
	}, nil
}

func parseDefinedSet(settype string, args []string) (*api.DefinedSet, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("empty large-community set name")
	}

	switch settype {
	case cmdPrefix:
		return parsePrefixSet(args)
	case cmdNeighbor:
		return parseNeighborSet(args)
	case cmdAspath:
		return parseAsPathSet(args)
	case cmdCommunity:
		return parseCommunitySet(args)
	case cmdExtcommunity:
		return parseExtCommunitySet(args)
	case cmdLargecommunity:
		return parseLargeCommunitySet(args)
	default:
		return nil, fmt.Errorf("invalid defined set type: %s", settype)
	}
}

var modPolicyUsageFormat = map[string]string{
	cmdPrefix:         "usage: policy prefix %s <name> [<prefix> [<mask range>]]",
	cmdNeighbor:       "usage: policy neighbor %s <name> [<neighbor address>...]",
	cmdAspath:         "usage: policy aspath %s <name> [<regexp>...]",
	cmdCommunity:      "usage: policy community %s <name> [<regexp>...]",
	cmdExtcommunity:   "usage: policy extcommunity %s <name> [<regexp>...]",
	cmdLargecommunity: "usage: policy large-community %s <name> [<regexp>...]",
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
	switch modtype {
	case cmdAdd:
		_, err = client.AddDefinedSet(ctx, &api.AddDefinedSetRequest{
			DefinedSet: d,
		})
	case cmdDel:
		all := false
		if len(args) < 2 {
			all = true
		}
		_, err = client.DeleteDefinedSet(ctx, &api.DeleteDefinedSetRequest{
			DefinedSet: d,
			All:        all,
		})
	}
	return err
}

func printStatement(indent int, s *api.Statement) {
	sIndent := func(indent int) string {
		return strings.Repeat(" ", indent)
	}
	fmt.Printf("%sStatementName %s:\n", sIndent(indent), s.Name)
	fmt.Printf("%sConditions:\n", sIndent(indent+2))

	ind := sIndent(indent + 4)

	c := s.Conditions
	if c.PrefixSet != nil {
		fmt.Printf("%sPrefixSet: %s \n", ind, prettyString(c.PrefixSet))
	}
	if c.NeighborSet != nil {
		fmt.Printf("%sNeighborSet: %s\n", ind, prettyString(c.NeighborSet))
	}
	if c.AsPathSet != nil {
		fmt.Printf("%sAsPathSet: %s \n", ind, prettyString(c.AsPathSet))
	}
	if c.CommunitySet != nil {
		fmt.Printf("%sCommunitySet: %s\n", ind, prettyString(c.CommunitySet))
	}
	if c.ExtCommunitySet != nil {
		fmt.Printf("%sExtCommunitySet: %s\n", ind, prettyString(c.ExtCommunitySet))
	}
	if c.LargeCommunitySet != nil {
		fmt.Printf("%sLargeCommunitySet: %s\n", ind, prettyString(c.LargeCommunitySet))
	}
	if c.NextHopInList != nil {
		fmt.Printf("%sNextHopInList: %s\n", ind, "[ "+strings.Join(c.NextHopInList, ", ")+" ]")
	}
	if c.AsPathLength != nil {
		fmt.Printf("%sAsPathLength: %s\n", ind, prettyString(c.AsPathLength))
	}
	if c.RpkiResult != -1 {
		fmt.Printf("%sRPKI result: %s\n", ind, strings.TrimPrefix(api.Validation_State(c.RpkiResult).String(), "STATE_"))
	}
	if c.RouteType != api.Conditions_ROUTE_TYPE_NONE {
		fmt.Printf("%sRoute Type: %s\n", ind, routeTypePrettyString(c.RouteType))
	}
	if c.AfiSafiIn != nil {
		fmt.Printf("%sAFI SAFI In: %s\n", ind, c.AfiSafiIn)
	}

	fmt.Printf("%sActions:\n", sIndent(indent+2))
	a := s.Actions
	if a.Community != nil {
		fmt.Println(ind, "Community: ", prettyString(a.Community))
	}
	if a.ExtCommunity != nil {
		fmt.Println(ind, "ExtCommunity: ", prettyString(a.ExtCommunity))
	}
	if a.LargeCommunity != nil {
		fmt.Println(ind, "LargeCommunity: ", prettyString(a.LargeCommunity))
	}
	if a.Med != nil {
		fmt.Println(ind, "MED: ", prettyString(a.Med))
	}
	if a.LocalPref != nil {
		fmt.Println(ind, "LocalPref: ", prettyString(a.LocalPref))
	}
	if a.AsPrepend != nil {
		fmt.Println(ind, "ASPathPrepend: ", prettyString(a.AsPrepend))
	}
	if a.Nexthop != nil {
		fmt.Println(ind, "Nexthop: ", prettyString(a.Nexthop))
	}

	if a.RouteAction != api.RouteAction_NONE {
		action := "accept"
		if a.RouteAction == api.RouteAction_REJECT {
			action = "reject"
		}
		fmt.Println(ind, action)
	}
}

func printPolicy(indent int, pd *api.Policy) {
	for _, s := range pd.Statements {
		printStatement(indent, s)
	}
}

func showPolicy(args []string) error {
	policies := make([]*api.Policy, 0)
	stream, err := client.ListPolicy(ctx, &api.ListPolicyRequest{})
	if err != nil {
		return err
	}
	for {
		r, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil
		}
		policies = append(policies, r.Policy)
	}

	var m []*api.Policy
	if len(args) > 0 {
		for _, p := range policies {
			if args[0] == p.Name {
				m = append(m, p)
				break
			}
		}
		if len(m) == 0 {
			return fmt.Errorf("not found %s", args[0])
		}
	} else {
		m = policies
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

	for _, pd := range m {
		fmt.Printf("Name %s:\n", pd.Name)
		printPolicy(4, pd)
	}
	return nil
}

func showStatement(args []string) error {
	stmts := make([]*api.Statement, 0)
	stream, err := client.ListStatement(ctx, &api.ListStatementRequest{})
	if err != nil {
		return err
	}
	for {
		r, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		stmts = append(stmts, r.Statement)
	}

	var m []*api.Statement
	if len(args) > 0 {
		for _, s := range stmts {
			if args[0] == s.Name {
				m = append(m, s)
				break
			}
		}
		if len(m) == 0 {
			return fmt.Errorf("not found %s", args[0])
		}
	} else {
		m = stmts
	}
	if globalOpts.Json {
		j, _ := json.Marshal(m)
		fmt.Println(string(j))
		return nil
	}
	if globalOpts.Quiet {
		for _, s := range m {
			fmt.Println(s.Name)
		}
		return nil
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
	stmt := &api.Statement{
		Name: args[0],
	}
	var err error
	switch op {
	case cmdAdd:
		_, err = client.AddStatement(ctx, &api.AddStatementRequest{
			Statement: stmt,
		})
	case cmdDel:
		_, err = client.DeleteStatement(ctx, &api.DeleteStatementRequest{
			Statement: stmt,
			All:       true,
		})
	default:
		return fmt.Errorf("invalid operation: %s", op)
	}
	return err
}

func modCondition(name, op string, args []string) error {
	stmt := &api.Statement{
		Name:       name,
		Conditions: &api.Conditions{},
	}
	usage := fmt.Sprintf("usage: gobgp policy statement %s %s condition", name, op)
	if len(args) < 1 {
		return fmt.Errorf("%s { prefix | neighbor | as-path | community | ext-community | large-community | as-path-length | rpki | route-type | next-hop-in-list | afi-safi-in }", usage)
	}
	typ := args[0]
	args = args[1:]
	switch typ {
	case "prefix":
		stmt.Conditions.PrefixSet = &api.MatchSet{}
		if len(args) < 1 {
			return fmt.Errorf("%s prefix <set-name> [{ any | invert }]", usage)
		}
		stmt.Conditions.PrefixSet.Name = args[0]
		if len(args) == 1 {
			break
		}
		switch strings.ToLower(args[1]) {
		case "any":
			stmt.Conditions.PrefixSet.MatchType = api.MatchType_ANY
		case "invert":
			stmt.Conditions.PrefixSet.MatchType = api.MatchType_INVERT
		default:
			return fmt.Errorf("%s prefix <set-name> [{ any | invert }]", usage)
		}
	case "neighbor":
		stmt.Conditions.NeighborSet = &api.MatchSet{}
		if len(args) < 1 {
			return fmt.Errorf("%s neighbor <set-name> [{ any | invert }]", usage)
		}
		stmt.Conditions.NeighborSet.Name = args[0]
		if len(args) == 1 {
			break
		}
		switch strings.ToLower(args[1]) {
		case "any":
			stmt.Conditions.NeighborSet.MatchType = api.MatchType_ANY
		case "invert":
			stmt.Conditions.NeighborSet.MatchType = api.MatchType_INVERT
		default:
			return fmt.Errorf("%s neighbor <set-name> [{ any | invert }]", usage)
		}
	case "as-path":
		stmt.Conditions.AsPathSet = &api.MatchSet{}
		if len(args) < 1 {
			return fmt.Errorf("%s as-path <set-name> [{ any | all | invert }]", usage)
		}
		stmt.Conditions.AsPathSet.Name = args[0]
		if len(args) == 1 {
			break
		}
		switch strings.ToLower(args[1]) {
		case "any":
			stmt.Conditions.AsPathSet.MatchType = api.MatchType_ANY
		case "all":
			stmt.Conditions.AsPathSet.MatchType = api.MatchType_ALL
		case "invert":
			stmt.Conditions.AsPathSet.MatchType = api.MatchType_INVERT
		default:
			return fmt.Errorf("%s as-path <set-name> [{ any | all | invert }]", usage)
		}
	case "community":
		stmt.Conditions.CommunitySet = &api.MatchSet{}
		if len(args) < 1 {
			return fmt.Errorf("%s community <set-name> [{ any | all | invert }]", usage)
		}
		stmt.Conditions.CommunitySet.Name = args[0]
		if len(args) == 1 {
			break
		}
		switch strings.ToLower(args[1]) {
		case "any":
			stmt.Conditions.CommunitySet.MatchType = api.MatchType_ANY
		case "all":
			stmt.Conditions.CommunitySet.MatchType = api.MatchType_ALL
		case "invert":
			stmt.Conditions.CommunitySet.MatchType = api.MatchType_INVERT
		default:
			return fmt.Errorf("%s community <set-name> [{ any | all | invert }]", usage)
		}
	case "ext-community":
		stmt.Conditions.ExtCommunitySet = &api.MatchSet{}
		if len(args) < 1 {
			return fmt.Errorf("%s ext-community <set-name> [{ any | all | invert }]", usage)
		}
		stmt.Conditions.ExtCommunitySet.Name = args[0]
		if len(args) == 1 {
			break
		}
		switch strings.ToLower(args[1]) {
		case "any":
			stmt.Conditions.ExtCommunitySet.MatchType = api.MatchType_ANY
		case "all":
			stmt.Conditions.ExtCommunitySet.MatchType = api.MatchType_ALL
		case "invert":
			stmt.Conditions.ExtCommunitySet.MatchType = api.MatchType_INVERT
		default:
			return fmt.Errorf("%s ext-community <set-name> [{ any | all | invert }]", usage)
		}
	case "large-community":
		stmt.Conditions.LargeCommunitySet = &api.MatchSet{}
		if len(args) < 1 {
			return fmt.Errorf("%s large-community <set-name> [{ any | all | invert }]", usage)
		}
		stmt.Conditions.LargeCommunitySet.Name = args[0]
		if len(args) == 1 {
			break
		}
		switch strings.ToLower(args[1]) {
		case "any":
			stmt.Conditions.LargeCommunitySet.MatchType = api.MatchType_ANY
		case "all":
			stmt.Conditions.LargeCommunitySet.MatchType = api.MatchType_ALL
		case "invert":
			stmt.Conditions.LargeCommunitySet.MatchType = api.MatchType_INVERT
		default:
			return fmt.Errorf("%s large-community <set-name> [{ any | all | invert }]", usage)
		}
	case "as-path-length":
		stmt.Conditions.AsPathLength = &api.AsPathLength{}
		if len(args) < 2 {
			return fmt.Errorf("%s as-path-length <length> { eq | ge | le }", usage)
		}
		length, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil {
			return err
		}
		stmt.Conditions.AsPathLength.Length = uint32(length)
		switch strings.ToLower(args[1]) {
		case "eq":
			stmt.Conditions.AsPathLength.LengthType = api.AsPathLengthType_EQ
		case "ge":
			stmt.Conditions.AsPathLength.LengthType = api.AsPathLengthType_GE
		case "le":
			stmt.Conditions.AsPathLength.LengthType = api.AsPathLengthType_LE
		default:
			return fmt.Errorf("%s as-path-length <length> { eq | ge | le }", usage)
		}
	case "rpki":
		if len(args) < 1 {
			return fmt.Errorf("%s rpki { valid | invalid | not-found }", usage)
		}
		switch strings.ToLower(args[0]) {
		case "valid":
			stmt.Conditions.RpkiResult = int32(config.RpkiValidationResultTypeToIntMap[config.RPKI_VALIDATION_RESULT_TYPE_VALID])
		case "invalid":
			stmt.Conditions.RpkiResult = int32(config.RpkiValidationResultTypeToIntMap[config.RPKI_VALIDATION_RESULT_TYPE_INVALID])
		case "not-found":
			stmt.Conditions.RpkiResult = int32(config.RpkiValidationResultTypeToIntMap[config.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND])
		default:
			return fmt.Errorf("%s rpki { valid | invalid | not-found }", usage)
		}
	case "route-type":
		err := fmt.Errorf("%s route-type { internal | external | local }", usage)
		if len(args) < 1 {
			return err
		}
		switch strings.ToLower(args[0]) {
		case "internal":
			stmt.Conditions.RouteType = api.Conditions_ROUTE_TYPE_INTERNAL
		case "external":
			stmt.Conditions.RouteType = api.Conditions_ROUTE_TYPE_EXTERNAL
		case "local":
			stmt.Conditions.RouteType = api.Conditions_ROUTE_TYPE_LOCAL
		default:
			return err
		}
	case "next-hop-in-list":
		stmt.Conditions.NextHopInList = args
	case "afi-safi-in":
		afiSafisInList := make([]*api.Family, 0, len(args))
		for _, arg := range args {
			afi, safi := bgp.RouteFamilyToAfiSafi(bgp.AddressFamilyValueMap[arg])
			afiSafisInList = append(afiSafisInList, apiutil.ToApiFamily(afi, safi))
		}
		stmt.Conditions.AfiSafiIn = afiSafisInList
	default:
		return fmt.Errorf("%s { prefix | neighbor | as-path | community | ext-community | large-community | as-path-length | rpki | route-type | next-hop-in-list | afi-safi-in }", usage)
	}

	var err error
	switch op {
	case cmdAdd:
		_, err = client.AddStatement(ctx, &api.AddStatementRequest{
			Statement: stmt,
		})
	case cmdDel:
		_, err = client.DeleteStatement(ctx, &api.DeleteStatementRequest{
			Statement: stmt,
		})
	default:
		return fmt.Errorf("invalid operation: %s", op)
	}
	return err
}

func modAction(name, op string, args []string) error {
	stmt := &api.Statement{
		Name:    name,
		Actions: &api.Actions{},
	}
	usage := fmt.Sprintf("usage: gobgp policy statement %s %s action", name, op)
	if len(args) < 1 {
		return fmt.Errorf("%s { reject | accept | community | ext-community | large-community | med | local-pref | as-prepend | next-hop }", usage)
	}
	typ := args[0]
	args = args[1:]
	cmd := "{ add | remove | replace } <value>..."
	switch typ {
	case "reject":
		stmt.Actions.RouteAction = api.RouteAction_REJECT
	case "accept":
		stmt.Actions.RouteAction = api.RouteAction_ACCEPT
	case "community":
		stmt.Actions.Community = &api.CommunityAction{}
		if len(args) < 1 {
			return fmt.Errorf("%s community %s", usage, cmd)
		}
		stmt.Actions.Community.Communities = args[1:]
		switch strings.ToLower(args[0]) {
		case "add":
			stmt.Actions.Community.ActionType = api.CommunityActionType_COMMUNITY_ADD
		case "remove":
			stmt.Actions.Community.ActionType = api.CommunityActionType_COMMUNITY_REMOVE
		case "replace":
			stmt.Actions.Community.ActionType = api.CommunityActionType_COMMUNITY_REPLACE
		default:
			return fmt.Errorf("%s community %s", usage, cmd)
		}
	case "ext-community":
		stmt.Actions.ExtCommunity = &api.CommunityAction{}
		if len(args) < 1 {
			return fmt.Errorf("%s ext-community %s", usage, cmd)
		}
		stmt.Actions.ExtCommunity.Communities = args[1:]
		switch strings.ToLower(args[0]) {
		case "add":
			stmt.Actions.ExtCommunity.ActionType = api.CommunityActionType_COMMUNITY_ADD
		case "remove":
			stmt.Actions.ExtCommunity.ActionType = api.CommunityActionType_COMMUNITY_REMOVE
		case "replace":
			stmt.Actions.ExtCommunity.ActionType = api.CommunityActionType_COMMUNITY_REPLACE
		default:
			return fmt.Errorf("%s ext-community %s", usage, cmd)
		}
	case "large-community":
		stmt.Actions.LargeCommunity = &api.CommunityAction{}
		if len(args) < 1 {
			return fmt.Errorf("%s large-community %s", usage, cmd)
		}
		stmt.Actions.LargeCommunity.Communities = args[1:]
		switch strings.ToLower(args[0]) {
		case "add":
			stmt.Actions.LargeCommunity.ActionType = api.CommunityActionType_COMMUNITY_ADD
		case "remove":
			stmt.Actions.LargeCommunity.ActionType = api.CommunityActionType_COMMUNITY_REMOVE
		case "replace":
			stmt.Actions.LargeCommunity.ActionType = api.CommunityActionType_COMMUNITY_REPLACE
		default:
			return fmt.Errorf("%s large-community %s", usage, cmd)
		}
	case "med":
		stmt.Actions.Med = &api.MedAction{}
		if len(args) < 2 {
			return fmt.Errorf("%s med { add | sub | set } <value>", usage)
		}
		med, err := strconv.ParseInt(args[1], 10, 32)
		if err != nil {
			return err
		}
		stmt.Actions.Med.Value = int64(med)
		switch strings.ToLower(args[0]) {
		case "add":
			stmt.Actions.Med.ActionType = api.MedActionType_MED_MOD
		case "sub":
			stmt.Actions.Med.ActionType = api.MedActionType_MED_MOD
			stmt.Actions.Med.Value = -1 * stmt.Actions.Med.Value
		case "set":
			stmt.Actions.Med.ActionType = api.MedActionType_MED_REPLACE
		default:
			return fmt.Errorf("%s med { add | sub | set } <value>", usage)
		}
	case "local-pref":
		stmt.Actions.LocalPref = &api.LocalPrefAction{}
		if len(args) < 1 {
			return fmt.Errorf("%s local-pref <value>", usage)
		}
		value, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil {
			return err
		}
		stmt.Actions.LocalPref.Value = uint32(value)
	case "as-prepend":
		stmt.Actions.AsPrepend = &api.AsPrependAction{}
		if len(args) < 2 {
			return fmt.Errorf("%s as-prepend { <asn> | last-as } <repeat-value>", usage)
		}
		asn, _ := strconv.ParseUint(args[0], 10, 32)
		stmt.Actions.AsPrepend.Asn = uint32(asn)
		repeat, err := strconv.ParseUint(args[1], 10, 8)
		if err != nil {
			return err
		}
		stmt.Actions.AsPrepend.Repeat = uint32(repeat)
	case "next-hop":
		stmt.Actions.Nexthop = &api.NexthopAction{}
		if len(args) != 1 {
			return fmt.Errorf("%s next-hop { <value> | self }", usage)
		}
		stmt.Actions.Nexthop.Address = args[0]
	}
	var err error
	switch op {
	case cmdAdd:
		_, err = client.AddStatement(ctx, &api.AddStatementRequest{
			Statement: stmt,
		})
	case cmdDel:
		_, err = client.DeleteStatement(ctx, &api.DeleteStatementRequest{
			Statement: stmt,
		})
	default:
		return fmt.Errorf("invalid operation: %s", op)
	}
	return err
}

func modPolicy(modtype string, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gobgp policy %s <name> [<statement name>...]", modtype)
	}
	name := args[0]
	args = args[1:]
	stmts := make([]*api.Statement, 0, len(args))
	for _, n := range args {
		stmts = append(stmts, &api.Statement{Name: n})
	}
	policy := &api.Policy{
		Name:       name,
		Statements: stmts,
	}

	var err error
	switch modtype {
	case cmdAdd:
		_, err = client.AddPolicy(ctx, &api.AddPolicyRequest{
			Policy:                  policy,
			ReferExistingStatements: true,
		})
	case cmdDel:
		all := false
		if len(args) < 1 {
			all = true
		}
		_, err = client.DeletePolicy(ctx, &api.DeletePolicyRequest{
			Policy:             policy,
			All:                all,
			PreserveStatements: true,
		})
	}
	return err
}

func newPolicyCmd() *cobra.Command {
	policyCmd := &cobra.Command{
		Use: cmdPolicy,
		Run: func(cmd *cobra.Command, args []string) {
			err := showPolicy(args)
			if err != nil {
				exitWithError(err)
			}
		},
	}

	for _, v := range []string{cmdPrefix, cmdNeighbor, cmdAspath, cmdCommunity, cmdExtcommunity, cmdLargecommunity} {
		cmd := &cobra.Command{
			Use: v,
			Run: func(cmd *cobra.Command, args []string) {
				if err := showDefinedSet(cmd.Use, args); err != nil {
					exitWithError(err)
				}
			},
		}
		for _, w := range []string{cmdAdd, cmdDel} {
			subcmd := &cobra.Command{
				Use: w,
				Run: func(c *cobra.Command, args []string) {
					if err := modDefinedSet(cmd.Use, c.Use, args); err != nil {
						exitWithError(err)
					}
				},
			}
			cmd.AddCommand(subcmd)
		}
		policyCmd.AddCommand(cmd)
	}

	stmtCmdImpl := &cobra.Command{}
	for _, v := range []string{cmdAdd, cmdDel} {
		cmd := &cobra.Command{
			Use: v,
		}
		for _, w := range []string{cmdCondition, cmdAction} {
			subcmd := &cobra.Command{
				Use: w,
				Run: func(c *cobra.Command, args []string) {
					name := args[len(args)-1]
					args = args[:len(args)-1]
					var err error
					if c.Use == cmdCondition {
						err = modCondition(name, cmd.Use, args)
					} else {
						err = modAction(name, cmd.Use, args)
					}
					if err != nil {
						exitWithError(err)
					}
				},
			}
			cmd.AddCommand(subcmd)
		}
		stmtCmdImpl.AddCommand(cmd)
	}

	stmtCmd := &cobra.Command{
		Use: cmdStatement,
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
				exitWithError(err)
			}
		},
	}
	for _, v := range []string{cmdAdd, cmdDel} {
		cmd := &cobra.Command{
			Use: v,
			Run: func(c *cobra.Command, args []string) {
				err := modStatement(c.Use, args)
				if err != nil {
					exitWithError(err)
				}
			},
		}
		stmtCmd.AddCommand(cmd)
	}
	policyCmd.AddCommand(stmtCmd)

	for _, v := range []string{cmdAdd, cmdDel} {
		cmd := &cobra.Command{
			Use: v,
			Run: func(c *cobra.Command, args []string) {
				err := modPolicy(c.Use, args)
				if err != nil {
					exitWithError(err)
				}
			},
		}
		policyCmd.AddCommand(cmd)
	}

	return policyCmd
}
