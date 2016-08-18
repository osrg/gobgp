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
	"net"
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
			if typ == "COMMUNITY" || typ == "EXT-COMMUNITY" {
				exp := regexp.MustCompile("\\^(\\S+)\\$")
				x = exp.ReplaceAllString(x, "$1")
			}
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
	default:
		return fmt.Errorf("unknown defined type: %s", v)
	}
	rsp, err := client.GetDefinedSet(context.Background(), &api.GetDefinedSetRequest{Type: typ})
	if err != nil {
		return err
	}
	m := sets{}
	if len(args) > 0 {
		for _, set := range rsp.Sets {
			if args[0] == set.Name {
				m = append(m, set)
			}
		}
		if len(m) == 0 {
			return fmt.Errorf("not found %s", args[0])
		}
	} else {
		m = rsp.Sets
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
	for _, arg := range args {
		address := net.ParseIP(arg)
		if address.To4() == nil && address.To16() == nil {
			return nil, fmt.Errorf("invalid address: %s\nplease enter ipv4 or ipv6 format", arg)
		}
	}
	return &api.DefinedSet{
		Type: api.DefinedType_NEIGHBOR,
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
		if _, err := table.ParseCommunityRegexp(arg); err != nil {
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
		if _, _, err := table.ParseExtCommunityRegexp(arg); err != nil {
			return nil, err
		}
	}
	return &api.DefinedSet{
		Type: api.DefinedType_EXT_COMMUNITY,
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
	switch modtype {
	case CMD_ADD:
		_, err = client.AddDefinedSet(context.Background(), &api.AddDefinedSetRequest{
			Set: d,
		})
	case CMD_DEL:
		all := false
		if len(args) < 2 {
			all = true
		}
		_, err = client.DeleteDefinedSet(context.Background(), &api.DeleteDefinedSetRequest{
			Set: d,
			All: all,
		})
	case CMD_SET:
		_, err = client.ReplaceDefinedSet(context.Background(), &api.ReplaceDefinedSetRequest{
			Set: d,
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

	ps := s.Conditions.PrefixSet
	if ps != nil {
		fmt.Printf("%sPrefixSet: %s %s\n", sIndent(indent+4), ps.Type, ps.Name)
	}

	ns := s.Conditions.NeighborSet
	if ns != nil {
		fmt.Printf("%sNeighborSet: %s %s\n", sIndent(indent+4), ns.Type, ns.Name)
	}

	aps := s.Conditions.AsPathSet
	if aps != nil {
		fmt.Printf("%sAsPathSet: %s %s\n", sIndent(indent+4), aps.Type, aps.Name)
	}

	cs := s.Conditions.CommunitySet
	if cs != nil {
		fmt.Printf("%sCommunitySet: %s %s\n", sIndent(indent+4), cs.Type, cs.Name)
	}

	ecs := s.Conditions.ExtCommunitySet
	if ecs != nil {
		fmt.Printf("%sExtCommunitySet: %s %s\n", sIndent(indent+4), ecs.Type, ecs.Name)
	}

	asPathLentgh := s.Conditions.AsPathLength
	if asPathLentgh != nil {
		fmt.Printf("%sAsPathLength: %s %d\n", sIndent(indent+4), asPathLentgh.Type, asPathLentgh.Length)
	}

	rpki := s.Conditions.RpkiResult
	if rpki > 0 {
		fmt.Printf("%sRPKI result: %s\n", sIndent(indent+4), config.IntToRpkiValidationResultTypeMap[int(rpki)])
	}

	if routeType := s.Conditions.RouteType; routeType > 0 {
		fmt.Printf("%sRoute Type: %s\n", sIndent(indent+4), config.IntToRouteTypeMap[int(routeType)])
	}

	fmt.Printf("%sActions:\n", sIndent(indent+2))

	formatComAction := func(c *api.CommunityAction) string {
		option := c.Type.String()
		if len(c.Communities) != 0 {
			exp := regexp.MustCompile("[\\^\\$]")
			communities := exp.ReplaceAllString(strings.Join(c.Communities, ","), "")
			option = fmt.Sprintf("%s[%s]", c.Type, communities)
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
		fmt.Printf("%sMed:             %d\n", sIndent(indent+4), s.Actions.Med.Value)
	}
	if s.Actions.LocalPref != nil {
		fmt.Printf("%sLocalPref:             %d\n", sIndent(indent+4), s.Actions.LocalPref.Value)
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
	if s.Actions.Nexthop != nil {
		addr := s.Actions.Nexthop.Address
		if s.Actions.Nexthop.Self {
			addr = "SELF"
		}
		fmt.Printf("%sNexthop:             %s\n", sIndent(indent+4), addr)
	}
	fmt.Printf("%s%s\n", sIndent(indent+4), s.Actions.RouteAction)
}

func printPolicy(indent int, pd *api.Policy) {
	for _, s := range pd.Statements {
		printStatement(indent, s)
	}
}

func showPolicy(args []string) error {
	rsp, err := client.GetPolicy(context.Background(), &api.GetPolicyRequest{})
	if err != nil {
		return err
	}
	m := policies{}
	if len(args) > 0 {
		for _, p := range rsp.Policies {
			if args[0] == p.Name {
				m = append(m, p)
				break
			}
		}
		if len(m) == 0 {
			return fmt.Errorf("not found %s", args[0])
		}
	} else {
		m = rsp.Policies
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
		fmt.Printf("Name %s:\n", pd.Name)
		printPolicy(4, pd)
	}
	return nil
}

func showStatement(args []string) error {
	rsp, err := client.GetStatement(context.Background(), &api.GetStatementRequest{})
	if err != nil {
		return err
	}
	m := []*api.Statement{}
	if len(args) > 0 {
		for _, s := range rsp.Statements {
			if args[0] == s.Name {
				m = append(m, s)
				break
			}
		}
		if len(m) == 0 {
			return fmt.Errorf("not found %s", args[0])
		}
	} else {
		m = rsp.Statements
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
		_, err = client.AddStatement(context.Background(), &api.AddStatementRequest{
			Statement: stmt,
		})
	case CMD_DEL:
		_, err = client.DeleteStatement(context.Background(), &api.DeleteStatementRequest{
			Statement: stmt,
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
		return fmt.Errorf("%s { prefix | neighbor | as-path | community | ext-community | as-path-length | rpki | route-type }", usage)
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
			stmt.Conditions.PrefixSet.Type = api.MatchType_ANY
		case "invert":
			stmt.Conditions.PrefixSet.Type = api.MatchType_INVERT
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
			stmt.Conditions.NeighborSet.Type = api.MatchType_ANY
		case "invert":
			stmt.Conditions.NeighborSet.Type = api.MatchType_ANY
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
			stmt.Conditions.AsPathSet.Type = api.MatchType_ANY
		case "all":
			stmt.Conditions.AsPathSet.Type = api.MatchType_ALL
		case "invert":
			stmt.Conditions.AsPathSet.Type = api.MatchType_INVERT
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
			stmt.Conditions.CommunitySet.Type = api.MatchType_ANY
		case "all":
			stmt.Conditions.CommunitySet.Type = api.MatchType_ALL
		case "invert":
			stmt.Conditions.CommunitySet.Type = api.MatchType_INVERT
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
			stmt.Conditions.ExtCommunitySet.Type = api.MatchType_ANY
		case "all":
			stmt.Conditions.ExtCommunitySet.Type = api.MatchType_ALL
		case "invert":
			stmt.Conditions.ExtCommunitySet.Type = api.MatchType_INVERT
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
			stmt.Conditions.RpkiResult = int32(config.RPKI_VALIDATION_RESULT_TYPE_VALID.ToInt())
		case "invalid":
			stmt.Conditions.RpkiResult = int32(config.RPKI_VALIDATION_RESULT_TYPE_INVALID.ToInt())
		case "not-found":
			stmt.Conditions.RpkiResult = int32(config.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND.ToInt())
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
	default:
		return fmt.Errorf("%s { prefix | neighbor | as-path | community | ext-community | as-path-length | rpki | route-type }", usage)
	}
	var err error
	switch op {
	case CMD_ADD:
		_, err = client.AddStatement(context.Background(), &api.AddStatementRequest{
			Statement: stmt,
		})
	case CMD_DEL:
		_, err = client.DeleteStatement(context.Background(), &api.DeleteStatementRequest{
			Statement: stmt,
		})
	case CMD_SET:
		_, err = client.ReplaceStatement(context.Background(), &api.ReplaceStatementRequest{
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
		return fmt.Errorf("%s { reject | accept | community | ext-community | med | local-pref | as-prepend | next-hop }", usage)
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
			stmt.Actions.Community.Type = api.CommunityActionType_COMMUNITY_ADD
		case "remove":
			stmt.Actions.Community.Type = api.CommunityActionType_COMMUNITY_REMOVE
		case "replace":
			stmt.Actions.Community.Type = api.CommunityActionType_COMMUNITY_REPLACE
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
			stmt.Actions.ExtCommunity.Type = api.CommunityActionType_COMMUNITY_ADD
		case "remove":
			stmt.Actions.ExtCommunity.Type = api.CommunityActionType_COMMUNITY_REMOVE
		case "replace":
			stmt.Actions.ExtCommunity.Type = api.CommunityActionType_COMMUNITY_REPLACE
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
			stmt.Actions.Med.Type = api.MedActionType_MED_MOD
		case "sub":
			stmt.Actions.Med.Type = api.MedActionType_MED_MOD
			stmt.Actions.Med.Value *= -1
		case "set":
			stmt.Actions.Med.Type = api.MedActionType_MED_REPLACE
		default:
			return fmt.Errorf("%s med { add | sub | set } <value>")
		}
	case "local-pref":
		if len(args) < 1 {
			return fmt.Errorf("%s local-pref <value>", usage)
		}
		value, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil {
			return err
		}
		stmt.Actions.LocalPref = &api.LocalPrefAction{
			Value: uint32(value),
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
	case "next-hop":
		if len(args) != 1 {
			return fmt.Errorf("%s next-hop { <value> | self }", usage)
		}
		if strings.ToLower(args[0]) == "self" {
			stmt.Actions.Nexthop = &api.NexthopAction{
				Self: true,
			}
		} else {
			if net.ParseIP(args[0]) == nil {
				return fmt.Errorf("invalid next-hop format: %s", args[0])
			}
			stmt.Actions.Nexthop = &api.NexthopAction{
				Address: args[0],
			}
		}
	}
	var err error
	switch op {
	case CMD_ADD:
		_, err = client.AddStatement(context.Background(), &api.AddStatementRequest{
			Statement: stmt,
		})
	case CMD_DEL:
		_, err = client.DeleteStatement(context.Background(), &api.DeleteStatementRequest{
			Statement: stmt,
		})
	case CMD_SET:
		_, err = client.ReplaceStatement(context.Background(), &api.ReplaceStatementRequest{
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
	var err error
	switch modtype {
	case CMD_ADD:
		_, err = client.AddPolicy(context.Background(), &api.AddPolicyRequest{
			Policy: &api.Policy{
				Name:       name,
				Statements: stmts,
			},
			ReferExistingStatements: true,
		})
	case CMD_DEL:
		all := false
		if len(args) < 1 {
			all = true
		}
		_, err = client.DeletePolicy(context.Background(), &api.DeletePolicyRequest{
			Policy: &api.Policy{
				Name:       name,
				Statements: stmts,
			},
			All:                all,
			PreserveStatements: true,
		})
	case CMD_SET:
		_, err = client.ReplacePolicy(context.Background(), &api.ReplacePolicyRequest{
			Policy: &api.Policy{
				Name:       name,
				Statements: stmts,
			},
			ReferExistingStatements: true,
			PreserveStatements:      true,
		})
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

	for _, v := range []string{CMD_PREFIX, CMD_NEIGHBOR, CMD_ASPATH, CMD_COMMUNITY, CMD_EXTCOMMUNITY} {
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
