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
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
)

var _regexpCommunity = regexp.MustCompile(`\^\^(\S+)\$\$`)

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
	return buff.String()
}

func showDefinedSet(v string, args []string) error {
	var typ api.DefinedType
	switch v {
	case CMD_PREFIX:
		typ = api.DefinedType_PREFIX
	case CMD_NEIGHBOR:
		typ = api.DefinedType_NEIGHBOR
	case CMD_ASPATH:
		typ = api.DefinedType_AS_PATH
	case CMD_COMMUNITY:
		typ = api.DefinedType_COMMUNITY
	case CMD_EXTCOMMUNITY:
		typ = api.DefinedType_EXT_COMMUNITY
	case CMD_LARGECOMMUNITY:
		typ = api.DefinedType_LARGE_COMMUNITY
	default:
		return fmt.Errorf("unknown defined type: %s", v)
	}
	var m []*api.DefinedSet
	if len(args) > 0 {
		d, err := client.GetDefinedSetByName(typ, args[0])
		if err != nil {
			return err
		}
		m = []*api.DefinedSet{d}
	} else {
		var err error
		m, err = client.GetDefinedSet(typ)
		if err != nil {
			return err
		}
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
	case CMD_PREFIX:
		output = formatDefinedSet(true, "PREFIX", 0, m)
	case CMD_NEIGHBOR:
		output = formatDefinedSet(true, "ADDRESS", 0, m)
	case CMD_ASPATH:
		output = formatDefinedSet(true, "AS-PATH", 0, m)
	case CMD_COMMUNITY:
		output = formatDefinedSet(true, "COMMUNITY", 0, m)
	case CMD_EXTCOMMUNITY:
		output = formatDefinedSet(true, "EXT-COMMUNITY", 0, m)
	case CMD_LARGECOMMUNITY:
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
		Type:     api.DefinedType_PREFIX,
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
		Type: api.DefinedType_NEIGHBOR,
		Name: name,
		List: list,
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
		Type: api.DefinedType_AS_PATH,
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
		if _, err := api.ParseCommunityRegexp(arg); err != nil {
			return nil, err
		}
	}
	return &api.DefinedSet{
		Type: api.DefinedType_COMMUNITY,
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
		if _, _, err := api.ParseExtCommunityRegexp(arg); err != nil {
			return nil, err
		}
	}
	return &api.DefinedSet{
		Type: api.DefinedType_EXT_COMMUNITY,
		Name: name,
		List: args,
	}, nil
}

func parseLargeCommunitySet(args []string) (*api.DefinedSet, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("empty large-community set name")
	}
	name := args[0]
	args = args[1:]
	for _, arg := range args {
		if _, err := api.ParseLargeCommunityRegexp(arg); err != nil {
			return nil, err
		}
	}
	return &api.DefinedSet{
		Type: api.DefinedType_LARGE_COMMUNITY,
		Name: name,
		List: args,
	}, nil
}

func parseDefinedSet(settype string, args []string) (*api.DefinedSet, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("empty large-community set name")
	}

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
	case CMD_LARGECOMMUNITY:
		return parseLargeCommunitySet(args)
	default:
		return nil, fmt.Errorf("invalid defined set type: %s", settype)
	}
}

var modPolicyUsageFormat = map[string]string{
	CMD_PREFIX:         "usage: policy prefix %s <name> [<prefix> [<mask range>]]",
	CMD_NEIGHBOR:       "usage: policy neighbor %s <name> [<neighbor address>...]",
	CMD_ASPATH:         "usage: policy aspath %s <name> [<regexp>...]",
	CMD_COMMUNITY:      "usage: policy community %s <name> [<regexp>...]",
	CMD_EXTCOMMUNITY:   "usage: policy extcommunity %s <name> [<regexp>...]",
	CMD_LARGECOMMUNITY: "usage: policy large-community %s <name> [<regexp>...]",
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
	case CMD_ADD:
		err = client.AddDefinedSet(d)
	case CMD_DEL:
		all := false
		if len(args) < 2 {
			all = true
		}
		err = client.DeleteDefinedSet(d, all)
	case CMD_SET:
		err = client.ReplaceDefinedSet(d)
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
		fmt.Printf("%sPrefixSet: %s \n", ind, c.PrefixSet.PrettyString())
	} else if c.NeighborSet != nil {
		fmt.Printf("%sNeighborSet: %s\n", ind, c.NeighborSet.PrettyString())
	} else if c.AsPathSet != nil {
		fmt.Printf("%sAsPathSet: %s \n", ind, c.AsPathSet.PrettyString())
	} else if c.CommunitySet != nil {
		fmt.Printf("%sCommunitySet: %s\n", ind, c.CommunitySet.PrettyString())
	} else if c.ExtCommunitySet != nil {
		fmt.Printf("%sExtCommunitySet: %s\n", ind, c.ExtCommunitySet.PrettyString())
	} else if c.LargeCommunitySet != nil {
		fmt.Printf("%sLargeCommunitySet: %s\n", ind, c.LargeCommunitySet.PrettyString())
	} else if c.NextHopInList != nil {
		fmt.Printf("%sNextHopInList: %s\n", ind, "[ "+strings.Join(c.NextHopInList, ", ")+" ]")
	} else if c.AsPathLength != nil {
		fmt.Printf("%sAsPathLength: %s\n", ind, c.AsPathLength.PrettyString())
	} else if c.RpkiResult != -1 {
		var result string
		switch c.RpkiResult {
		case 0:
			result = "none"
		case 1:
			result = "valid"
		case 2:
			result = "invalid"
		case 3:
			result = "not-found"
		}
		fmt.Printf("%sRPKI result: %s\n", ind, result)
	} else if c.RouteType != api.Conditions_ROUTE_TYPE_NONE {
		fmt.Printf("%sRoute Type: %s\n", ind, c.RouteType.PrettyString())
	} else if c.AfiSafiIn != nil {
		fmt.Printf("%sAFI SAFI In: %s\n", ind, c.AfiSafiIn)
	}

	fmt.Printf("%sActions:\n", sIndent(indent+2))
	a := s.Actions
	if a.Community != nil {
		fmt.Println(ind, "Community: ", a.Community.PrettyString())
	} else if a.ExtCommunity != nil {
		fmt.Println(ind, "ExtCommunity: ", a.ExtCommunity.PrettyString())
	} else if a.LargeCommunity != nil {
		fmt.Println(ind, "LargeCommunity: ", a.LargeCommunity.PrettyString())
	} else if a.Med != nil {
		fmt.Println(ind, "MED: ", a.Med.PrettyString())
	} else if a.LocalPref != nil {
		fmt.Println(ind, "LocalPref: ", a.LocalPref.PrettyString())
	} else if a.AsPrepend != nil {
		fmt.Println(ind, "ASPathPrepend: ", a.AsPrepend.PrettyString())
	} else if a.Nexthop != nil {
		fmt.Println(ind, "Nexthop: ", a.Nexthop.PrettyString())
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
	policies, err := client.GetPolicy()
	if err != nil {
		return err
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
	stmts, err := client.GetStatement()
	if err != nil {
		return err
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
	case CMD_ADD:
		err = client.AddStatement(stmt)
	case CMD_DEL:
		err = client.DeleteStatement(stmt, true)
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
			stmt.Conditions.PrefixSet.Type = api.MatchType_ANY
		case "invert":
			stmt.Conditions.PrefixSet.Type = api.MatchType_INVERT
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
			stmt.Conditions.NeighborSet.Type = api.MatchType_ANY
		case "invert":
			stmt.Conditions.NeighborSet.Type = api.MatchType_INVERT
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
			stmt.Conditions.AsPathSet.Type = api.MatchType_ANY
		case "all":
			stmt.Conditions.AsPathSet.Type = api.MatchType_ALL
		case "invert":
			stmt.Conditions.AsPathSet.Type = api.MatchType_INVERT
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
			stmt.Conditions.CommunitySet.Type = api.MatchType_ANY
		case "all":
			stmt.Conditions.CommunitySet.Type = api.MatchType_ALL
		case "invert":
			stmt.Conditions.CommunitySet.Type = api.MatchType_INVERT
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
			stmt.Conditions.ExtCommunitySet.Type = api.MatchType_ANY
		case "all":
			stmt.Conditions.ExtCommunitySet.Type = api.MatchType_ALL
		case "invert":
			stmt.Conditions.ExtCommunitySet.Type = api.MatchType_INVERT
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
			stmt.Conditions.LargeCommunitySet.Type = api.MatchType_ANY
		case "all":
			stmt.Conditions.LargeCommunitySet.Type = api.MatchType_ALL
		case "invert":
			stmt.Conditions.LargeCommunitySet.Type = api.MatchType_INVERT
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
			stmt.Conditions.AsPathLength.Type = api.AsPathLengthType_EQ
		case "ge":
			stmt.Conditions.AsPathLength.Type = api.AsPathLengthType_GE
		case "le":
			stmt.Conditions.AsPathLength.Type = api.AsPathLengthType_LE
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
		afiSafisInList := make([]api.Family, 0, len(args))
		for _, arg := range args {
			afiSafisInList = append(afiSafisInList, api.Family(bgp.AddressFamilyValueMap[arg]))
		}
		stmt.Conditions.AfiSafiIn = afiSafisInList
	default:
		return fmt.Errorf("%s { prefix | neighbor | as-path | community | ext-community | large-community | as-path-length | rpki | route-type | next-hop-in-list | afi-safi-in }", usage)
	}

	var err error
	switch op {
	case CMD_ADD:
		err = client.AddStatement(stmt)
	case CMD_DEL:
		err = client.DeleteStatement(stmt, false)
	case CMD_SET:
		err = client.ReplaceStatement(stmt)
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
	switch typ {
	case "reject":
		stmt.Actions.RouteAction = api.RouteAction_REJECT
	case "accept":
		stmt.Actions.RouteAction = api.RouteAction_ACCEPT
	case "community":
		stmt.Actions.Community = &api.CommunityAction{}
		if len(args) < 1 {
			return fmt.Errorf("%s community { add | remove | replace } <value>...", usage)
		}
		stmt.Actions.Community.Communities = args[1:]
		switch strings.ToLower(args[0]) {
		case "add":
			stmt.Actions.Community.Type = api.CommunityActionType_COMMUNITY_ADD
		case "remove":
			stmt.Actions.Community.Type = api.CommunityActionType_COMMUNITY_REMOVE
		case "replace":
			stmt.Actions.Community.Type = api.CommunityActionType_COMMUNITY_REPLACE
		default:
			return fmt.Errorf("%s community { add | remove | replace } <value>...", usage)
		}
	case "ext-community":
		stmt.Actions.ExtCommunity = &api.CommunityAction{}
		if len(args) < 1 {
			return fmt.Errorf("%s ext-community { add | remove | replace } <value>...", usage)
		}
		stmt.Actions.ExtCommunity.Communities = args[1:]
		switch strings.ToLower(args[0]) {
		case "add":
			stmt.Actions.ExtCommunity.Type = api.CommunityActionType_COMMUNITY_ADD
		case "remove":
			stmt.Actions.ExtCommunity.Type = api.CommunityActionType_COMMUNITY_REMOVE
		case "replace":
			stmt.Actions.ExtCommunity.Type = api.CommunityActionType_COMMUNITY_REPLACE
		default:
			return fmt.Errorf("%s ext-community { add | remove | replace } <value>...", usage)
		}
	case "large-community":
		stmt.Actions.LargeCommunity = &api.CommunityAction{}
		if len(args) < 1 {
			return fmt.Errorf("%s large-community { add | remove | replace } <value>...", usage)
		}
		stmt.Actions.LargeCommunity.Communities = args[1:]
		switch strings.ToLower(args[0]) {
		case "add":
			stmt.Actions.LargeCommunity.Type = api.CommunityActionType_COMMUNITY_ADD
		case "remove":
			stmt.Actions.LargeCommunity.Type = api.CommunityActionType_COMMUNITY_REMOVE
		case "replace":
			stmt.Actions.LargeCommunity.Type = api.CommunityActionType_COMMUNITY_REPLACE
		default:
			return fmt.Errorf("%s large-community { add | remove | replace } <value>...", usage)
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
			stmt.Actions.Med.Type = api.MedActionType_MED_MOD
		case "sub":
			stmt.Actions.Med.Type = api.MedActionType_MED_MOD
			stmt.Actions.Med.Value = -1 * stmt.Actions.Med.Value
		case "set":
			stmt.Actions.Med.Type = api.MedActionType_MED_REPLACE
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
	case CMD_ADD:
		err = client.AddStatement(stmt)
	case CMD_DEL:
		err = client.DeleteStatement(stmt, false)
	case CMD_SET:
		err = client.ReplaceStatement(stmt)
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
	case CMD_ADD:
		err = client.AddPolicy(policy, true)
	case CMD_DEL:
		all := false
		if len(args) < 1 {
			all = true
		}
		err = client.DeletePolicy(policy, all, true)
	case CMD_SET:
		err = client.ReplacePolicy(policy, true, true)
	}
	return err
}

func NewPolicyCmd() *cobra.Command {
	policyCmd := &cobra.Command{
		Use: CMD_POLICY,
		Run: func(cmd *cobra.Command, args []string) {
			err := showPolicy(args)
			if err != nil {
				exitWithError(err)
			}
		},
	}

	for _, v := range []string{CMD_PREFIX, CMD_NEIGHBOR, CMD_ASPATH, CMD_COMMUNITY, CMD_EXTCOMMUNITY, CMD_LARGECOMMUNITY} {
		cmd := &cobra.Command{
			Use: v,
			Run: func(cmd *cobra.Command, args []string) {
				if err := showDefinedSet(cmd.Use, args); err != nil {
					exitWithError(err)
				}
			},
		}
		for _, w := range []string{CMD_ADD, CMD_DEL, CMD_SET} {
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
						exitWithError(err)
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
				exitWithError(err)
			}
		},
	}
	for _, v := range []string{CMD_ADD, CMD_DEL} {
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

	for _, v := range []string{CMD_ADD, CMD_DEL, CMD_SET} {
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
