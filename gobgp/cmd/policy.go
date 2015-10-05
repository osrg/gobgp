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
	"github.com/osrg/gobgp/table"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"io"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func formatPolicyPrefix(head bool, indent int, psl []*api.PrefixSet) string {
	buff := bytes.NewBuffer(make([]byte, 0, 64))
	sIndent := strings.Repeat(" ", indent)
	maxNameLen := 0
	maxPrefixLen := 0
	maxRangeLen := 0
	for _, ps := range psl {
		if len(ps.PrefixSetName) > maxNameLen {
			maxNameLen = len(ps.PrefixSetName)
		}
		for _, p := range ps.PrefixList {
			if len(p.IpPrefix) > maxPrefixLen {
				maxPrefixLen = len(p.IpPrefix)
			}
			if len(p.MaskLengthRange) > maxRangeLen {
				maxRangeLen = len(p.MaskLengthRange)
			}
		}
	}

	if head {
		if len("Name") > maxNameLen {
			maxNameLen = len("Name")
		}
		if len("Prefix") > maxPrefixLen {
			maxPrefixLen = len("Prefix")
		}
		if len("MaskRange") > maxRangeLen {
			maxRangeLen = len("MaskRange")
		}
	}

	format := "%-" + fmt.Sprint(maxNameLen) + "s  %-" + fmt.Sprint(maxPrefixLen) + "s  %-" + fmt.Sprint(maxRangeLen) + "s\n"
	if head {
		buff.WriteString(fmt.Sprintf(format, "Name", "Address", "MaskRange"))
	}
	for _, ps := range psl {
		for i, p := range ps.PrefixList {
			prefix := fmt.Sprintf("%s", p.IpPrefix)
			if i == 0 {
				buff.WriteString(fmt.Sprintf(format, ps.PrefixSetName, prefix, p.MaskLengthRange))
			} else {
				buff.WriteString(fmt.Sprintf(sIndent))
				buff.WriteString(fmt.Sprintf(format, "", prefix, p.MaskLengthRange))
			}
		}
	}
	return buff.String()
}

func showPolicyPrefixes() error {
	arg := &api.PolicyArguments{
		Resource: api.Resource_POLICY_PREFIX,
	}
	stream, e := client.GetPolicyRoutePolicies(context.Background(), arg)
	if e != nil {
		return e
	}
	m := prefixes{}
	for {
		p, e := stream.Recv()
		if e == io.EOF {
			break
		} else if e != nil {
			return e
		}
		m = append(m, p.StatementList[0].Conditions.MatchPrefixSet)
	}

	if globalOpts.Json {
		j, _ := json.Marshal(m)
		fmt.Println(string(j))
		return nil
	}

	if globalOpts.Quiet {
		for _, p := range m {
			fmt.Println(p.PrefixSetName)
		}
		return nil
	}
	sort.Sort(m)

	output := formatPolicyPrefix(true, 0, m)
	fmt.Print(output)

	return nil
}

func showPolicyPrefix(args []string) error {
	arg := &api.PolicyArguments{
		Resource: api.Resource_POLICY_PREFIX,
		Name:     args[0],
	}
	pd, e := client.GetPolicyRoutePolicy(context.Background(), arg)
	if e != nil {
		return e
	}
	ps := pd.StatementList[0].Conditions.MatchPrefixSet
	if globalOpts.Json {
		j, _ := json.Marshal(ps)
		fmt.Println(string(j))
		return nil
	}
	if globalOpts.Quiet {
		for _, p := range ps.PrefixList {
			fmt.Printf("%s %s\n", p.IpPrefix, p.MaskLengthRange)
		}
		return nil
	}
	output := formatPolicyPrefix(true, 0, []*api.PrefixSet{ps})
	fmt.Print(output)
	return nil
}

func parsePrefixSet(eArgs []string) (*api.PrefixSet, error) {
	_, ipNet, e := net.ParseCIDR(eArgs[1])
	if e != nil {
		return nil, fmt.Errorf("invalid prefix: %s\nplease enter ipv4 or ipv6 format", eArgs[1])
	}
	prefix := &api.Prefix{
		IpPrefix: eArgs[1],
	}

	if len(eArgs) == 3 {
		maskRange := eArgs[2]
		idx := strings.Index(maskRange, "..")
		if idx == -1 {
			return nil, fmt.Errorf("invalid mask length range: %s", maskRange)
		}
		var min, max int
		var e error
		if idx != 0 {
			if min, e = strconv.Atoi(maskRange[:idx]); e != nil {
				return nil, fmt.Errorf("invalid mask length range: %s", maskRange)
			}
		}
		if idx != len(maskRange)-1 {
			if max, e = strconv.Atoi(maskRange[idx+2:]); e != nil {
				return nil, fmt.Errorf("invalid mask length range: %s", maskRange)
			}
		}
		if ipv4 := ipNet.IP.To4(); ipv4 != nil {
			if min < 0 || 32 < max {
				return nil, fmt.Errorf("ipv4 mask length range outside scope :%s", maskRange)
			}
		} else {
			if min < 0 || 128 < max {
				return nil, fmt.Errorf("ipv6 mask length range outside scope :%s", maskRange)
			}
		}
		if min >= max {
			return nil, fmt.Errorf("invalid mask length range: %s\nlarge value to the right from the left", maskRange)
		}
		prefix.MaskLengthRange = maskRange
	}
	prefixList := []*api.Prefix{prefix}
	prefixSet := &api.PrefixSet{
		PrefixSetName: eArgs[0],
		PrefixList:    prefixList,
	}
	return prefixSet, nil
}
func modPolicy(resource api.Resource, op api.Operation, data interface{}) error {
	pd := &api.PolicyDefinition{}
	if resource != api.Resource_POLICY_ROUTEPOLICY {
		co := &api.Conditions{}
		switch resource {
		case api.Resource_POLICY_PREFIX:
			co.MatchPrefixSet = data.(*api.PrefixSet)
		case api.Resource_POLICY_NEIGHBOR:
			co.MatchNeighborSet = data.(*api.NeighborSet)
		case api.Resource_POLICY_ASPATH:
			co.MatchAsPathSet = data.(*api.AsPathSet)
		case api.Resource_POLICY_COMMUNITY:
			co.MatchCommunitySet = data.(*api.CommunitySet)
		case api.Resource_POLICY_EXTCOMMUNITY:
			co.MatchExtCommunitySet = data.(*api.ExtCommunitySet)
		}
		pd.StatementList = []*api.Statement{{Conditions: co}}
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

func modPolicyPrefix(modtype string, eArgs []string) error {
	prefixSet := &api.PrefixSet{}
	var e error
	var operation api.Operation

	switch modtype {
	case CMD_ADD:
		if len(eArgs) < 2 {
			return fmt.Errorf("usage: policy prefix add <prefix set name> <prefix> [<mask length renge>]")
		}
		if prefixSet, e = parsePrefixSet(eArgs); e != nil {
			return e
		}
		operation = api.Operation_ADD
	case CMD_DEL:
		if len(eArgs) == 0 {
			return fmt.Errorf("usage: policy prefix del <prefix set name> [<prefix> [<mask length renge>]]")
		} else if len(eArgs) == 1 {
			prefixSet = &api.PrefixSet{
				PrefixSetName: eArgs[0],
				PrefixList:    nil,
			}
		} else {
			if prefixSet, e = parsePrefixSet(eArgs); e != nil {
				return e
			}
		}
		operation = api.Operation_DEL
	case CMD_ALL:
		if len(eArgs) > 0 {
			return fmt.Errorf("Argument can not be entered: %s", eArgs[0:])
		}
		operation = api.Operation_DEL_ALL
	default:
		return fmt.Errorf("invalid modType %s", modtype)
	}
	if e = modPolicy(api.Resource_POLICY_PREFIX, operation, prefixSet); e != nil {
		return e
	}
	return nil
}

func formatPolicyNeighbor(head bool, indent int, nsl []*api.NeighborSet) string {
	buff := bytes.NewBuffer(make([]byte, 0, 64))
	sIndent := strings.Repeat(" ", indent)
	maxNameLen := 0
	maxAddressLen := 0
	for _, ns := range nsl {
		if len(ns.NeighborSetName) > maxNameLen {
			maxNameLen = len(ns.NeighborSetName)
		}
		for _, n := range ns.NeighborList {
			if len(n.Address) > maxAddressLen {
				maxAddressLen = len(n.Address)
			}
		}
	}

	if head {
		if len("Name") > maxNameLen {
			maxNameLen = len("Name")
		}
		if len("Address") > maxAddressLen {
			maxAddressLen = len("Address")
		}
	}

	format := "%-" + fmt.Sprint(maxNameLen) + "s  %-" + fmt.Sprint(maxAddressLen) + "s\n"
	if head {
		buff.WriteString(fmt.Sprintf(format, "Name", "Address"))
	}
	for _, ns := range nsl {
		for i, n := range ns.NeighborList {
			if i == 0 {
				buff.WriteString(fmt.Sprintf(format, ns.NeighborSetName, n.Address))
			} else {
				buff.WriteString(fmt.Sprintf(sIndent))
				buff.WriteString(fmt.Sprintf(format, "", n.Address))
			}
		}
	}
	return buff.String()
}

func showPolicyNeighbors() error {
	arg := &api.PolicyArguments{
		Resource: api.Resource_POLICY_NEIGHBOR,
	}
	stream, e := client.GetPolicyRoutePolicies(context.Background(), arg)
	if e != nil {
		return e
	}
	m := neighbors{}
	for {
		p, e := stream.Recv()
		if e == io.EOF {
			break
		} else if e != nil {
			return e
		}
		m = append(m, p.StatementList[0].Conditions.MatchNeighborSet)
	}

	if globalOpts.Json {
		j, _ := json.Marshal(m)
		fmt.Println(string(j))
		return nil
	}

	if globalOpts.Quiet {
		for _, n := range m {
			fmt.Println(n.NeighborSetName)
		}
		return nil
	}
	sort.Sort(m)

	output := formatPolicyNeighbor(true, 0, m)
	fmt.Print(output)
	return nil
}

func showPolicyNeighbor(args []string) error {
	arg := &api.PolicyArguments{
		Resource: api.Resource_POLICY_NEIGHBOR,
		Name:     args[0],
	}
	pd, e := client.GetPolicyRoutePolicy(context.Background(), arg)
	if e != nil {
		return e
	}
	ns := pd.StatementList[0].Conditions.MatchNeighborSet
	if globalOpts.Json {
		j, _ := json.Marshal(ns)
		fmt.Println(string(j))
		return nil
	}
	if globalOpts.Quiet {
		for _, n := range ns.NeighborList {
			fmt.Println(n.Address)
		}
		return nil
	}
	output := formatPolicyNeighbor(true, 0, []*api.NeighborSet{ns})
	fmt.Print(output)
	return nil
}

func parseNeighborSet(eArgs []string) (*api.NeighborSet, error) {
	address := net.ParseIP(eArgs[1])
	if address.To4() == nil {
		if address.To16() == nil {
			return nil, fmt.Errorf("invalid address: %s\nplease enter ipv4 or ipv6 format", eArgs[1])
		}
	}

	neighbor := &api.Neighbor{
		Address: address.String(),
	}
	neighborList := []*api.Neighbor{neighbor}
	neighborSet := &api.NeighborSet{
		NeighborSetName: eArgs[0],
		NeighborList:    neighborList,
	}
	return neighborSet, nil
}

func modPolicyNeighbor(modtype string, eArgs []string) error {
	neighborSet := &api.NeighborSet{}
	var e error
	var operation api.Operation

	switch modtype {
	case CMD_ADD:
		if len(eArgs) < 2 {
			return fmt.Errorf("usage: policy neighbor add <neighbor set name> <address>")
		}
		if neighborSet, e = parseNeighborSet(eArgs); e != nil {
			return e
		}
		operation = api.Operation_ADD
	case CMD_DEL:
		if len(eArgs) == 0 {
			return fmt.Errorf("usage: policy neighbor del <neighbor set name> [<address>]")
		} else if len(eArgs) == 1 {
			neighborSet = &api.NeighborSet{
				NeighborSetName: eArgs[0],
				NeighborList:    nil,
			}
		} else {
			if neighborSet, e = parseNeighborSet(eArgs); e != nil {
				return e
			}
		}
		operation = api.Operation_DEL
	case CMD_ALL:
		if len(eArgs) > 0 {
			return fmt.Errorf("Argument can not be entered: %s", eArgs[0:])
		}
		operation = api.Operation_DEL_ALL
	default:
		return fmt.Errorf("invalid modType %s", modtype)
	}
	if e = modPolicy(api.Resource_POLICY_NEIGHBOR, operation, neighborSet); e != nil {
		return e
	}
	return nil
}

func formatPolicyAsPath(haed bool, indent int, apsl []*api.AsPathSet) string {
	buff := bytes.NewBuffer(make([]byte, 0, 64))
	sIndent := strings.Repeat(" ", indent)
	maxNameLen := 0
	maxPathLen := 0
	for _, aps := range apsl {
		if len(aps.AsPathSetName) > maxNameLen {
			maxNameLen = len(aps.AsPathSetName)
		}
		for _, m := range aps.AsPathMembers {
			if len(m) > maxPathLen {
				maxPathLen = len(m)
			}
		}
	}

	if haed {
		if len("Name") > maxNameLen {
			maxNameLen = len("Name")
		}
		if len("AsPath") > maxPathLen {
			maxPathLen = len("AsPath")
		}
	}

	format := "%-" + fmt.Sprint(maxNameLen) + "s  %-" + fmt.Sprint(maxPathLen) + "s\n"
	if haed {
		buff.WriteString(fmt.Sprintf(format, "Name", "AsPath"))
	}
	for _, aps := range apsl {
		for i, a := range aps.AsPathMembers {
			if i == 0 {
				buff.WriteString(fmt.Sprintf(format, aps.AsPathSetName, a))
			} else {
				buff.WriteString(fmt.Sprintf(sIndent))
				buff.WriteString(fmt.Sprintf(format, "", a))
			}
		}
	}
	return buff.String()
}

func showPolicyAsPaths() error {
	arg := &api.PolicyArguments{
		Resource: api.Resource_POLICY_ASPATH,
	}
	stream, e := client.GetPolicyRoutePolicies(context.Background(), arg)
	if e != nil {
		return e
	}
	m := aspaths{}
	for {
		a, e := stream.Recv()
		if e == io.EOF {
			break
		} else if e != nil {
			return e
		}
		m = append(m, a.StatementList[0].Conditions.MatchAsPathSet)
	}
	if globalOpts.Json {
		j, _ := json.Marshal(m)
		fmt.Println(string(j))
		return nil
	}
	if globalOpts.Quiet {
		for _, a := range m {
			fmt.Println(a.AsPathSetName)
		}
		return nil
	}
	sort.Sort(m)

	output := formatPolicyAsPath(true, 0, m)
	fmt.Print(output)
	return nil
}

func showPolicyAsPath(args []string) error {
	arg := &api.PolicyArguments{
		Resource: api.Resource_POLICY_ASPATH,
		Name:     args[0],
	}
	pd, e := client.GetPolicyRoutePolicy(context.Background(), arg)
	if e != nil {
		return e
	}
	as := pd.StatementList[0].Conditions.MatchAsPathSet
	if globalOpts.Json {
		j, _ := json.Marshal(as)
		fmt.Println(string(j))
		return nil
	}
	if globalOpts.Quiet {
		for _, a := range as.AsPathMembers {
			fmt.Println(a)
		}
		return nil
	}
	output := formatPolicyAsPath(true, 0, []*api.AsPathSet{as})
	fmt.Print(output)
	return nil
}

func parseAsPathSet(eArgs []string) (*api.AsPathSet, error) {
	as := eArgs[1]
	isTop := as[:1] == "^"
	if isTop {
		as = as[1:]
	}
	isEnd := as[len(as)-1:] == "$"
	if isEnd {
		as = as[:len(as)-1]
	}
	elems := strings.Split(as, "_")
	for _, el := range elems {
		if len(el) == 0 {
			return nil, fmt.Errorf("invalid aspath element: %s \ndo not enter a blank", eArgs[1])
		}
		_, err := regexp.Compile(el)
		if err != nil {
			return nil, fmt.Errorf("invalid aspath element: %s \n"+
				"can not comple aspath values to regular expressions.", eArgs[1])
		}
	}
	asPathSet := &api.AsPathSet{
		AsPathSetName: eArgs[0],
		AsPathMembers: []string{eArgs[1]},
	}
	return asPathSet, nil
}

func modPolicyAsPath(modtype string, eArgs []string) error {
	asPathSet := &api.AsPathSet{}
	var e error
	var operation api.Operation

	switch modtype {
	case CMD_ADD:
		if len(eArgs) < 2 {
			return fmt.Errorf("usage: policy aspath add <aspath set name> <aspath>")
		}
		if asPathSet, e = parseAsPathSet(eArgs); e != nil {
			return e
		}
		operation = api.Operation_ADD
	case CMD_DEL:
		if len(eArgs) == 0 {
			return fmt.Errorf("usage: policy aspath del <aspath set name> [<aspath>]")
		} else if len(eArgs) == 1 {
			asPathSet = &api.AsPathSet{
				AsPathSetName: eArgs[0],
				AsPathMembers: nil,
			}
		} else {
			if asPathSet, e = parseAsPathSet(eArgs); e != nil {
				return e
			}
		}
		operation = api.Operation_DEL
	case CMD_ALL:
		if len(eArgs) > 0 {
			return fmt.Errorf("Argument can not be entered: %s", eArgs[0:])
		}
		operation = api.Operation_DEL_ALL
	default:
		return fmt.Errorf("invalid modType %s", modtype)
	}
	if e = modPolicy(api.Resource_POLICY_ASPATH, operation, asPathSet); e != nil {
		return e
	}
	return nil
}

func formatPolicyCommunity(head bool, indent int, csl []*api.CommunitySet) string {
	buff := bytes.NewBuffer(make([]byte, 0, 64))
	sIndent := strings.Repeat(" ", indent)
	maxNameLen := 0
	maxCommunityLen := 0
	for _, cs := range csl {
		if len(cs.CommunitySetName) > maxNameLen {
			maxNameLen = len(cs.CommunitySetName)
		}
		for _, m := range cs.CommunityMembers {
			if len(m) > maxCommunityLen {
				maxCommunityLen = len(m)
			}
		}
	}

	if head {
		if len("Name") > maxNameLen {
			maxNameLen = len("Name")
		}
		if len("Community") > maxCommunityLen {
			maxCommunityLen = len("Community")
		}
	}

	format := "%-" + fmt.Sprint(maxNameLen) + "s  %-" + fmt.Sprint(maxCommunityLen) + "s\n"
	if head {
		buff.WriteString(fmt.Sprintf(format, "Name", "Community"))
	}
	for _, cs := range csl {
		for i, c := range cs.CommunityMembers {
			if i == 0 {
				buff.WriteString(fmt.Sprintf(format, cs.CommunitySetName, c))
			} else {
				buff.WriteString(fmt.Sprintf(sIndent))
				buff.WriteString(fmt.Sprintf(format, "", c))
			}
		}
	}
	return buff.String()
}

func showPolicyCommunities() error {
	arg := &api.PolicyArguments{
		Resource: api.Resource_POLICY_COMMUNITY,
	}
	stream, e := client.GetPolicyRoutePolicies(context.Background(), arg)
	if e != nil {
		return e
	}
	m := communities{}
	for {
		a, e := stream.Recv()
		if e == io.EOF {
			break
		} else if e != nil {
			return e
		}
		m = append(m, a.StatementList[0].Conditions.MatchCommunitySet)
	}
	if globalOpts.Json {
		j, _ := json.Marshal(m)
		fmt.Println(string(j))
		return nil
	}
	if globalOpts.Quiet {
		for _, c := range m {
			fmt.Println(c.CommunitySetName)
		}
		return nil
	}
	sort.Sort(m)

	output := formatPolicyCommunity(true, 0, m)
	fmt.Print(output)
	return nil
}

func showPolicyCommunity(args []string) error {
	arg := &api.PolicyArguments{
		Resource: api.Resource_POLICY_COMMUNITY,
		Name:     args[0],
	}
	pd, e := client.GetPolicyRoutePolicy(context.Background(), arg)
	if e != nil {
		return e
	}
	cs := pd.StatementList[0].Conditions.GetMatchCommunitySet()
	if globalOpts.Json {
		j, _ := json.Marshal(cs)
		fmt.Println(string(j))
		return nil
	}
	if globalOpts.Quiet {
		for _, c := range cs.CommunityMembers {
			fmt.Println(c)
		}
		return nil
	}
	output := formatPolicyCommunity(true, 0, []*api.CommunitySet{cs})
	fmt.Print(output)
	return nil
}

func checkCommunityFormat(comStr string) bool {
	// community regexp
	regUint, _ := regexp.Compile("^([0-9]+)$")
	regString, _ := regexp.Compile("([0-9]+):([0-9]+)")
	regWellKnown, _ := regexp.Compile("^(" +
		table.COMMUNITY_INTERNET + "|" +
		table.COMMUNITY_NO_EXPORT + "|" +
		table.COMMUNITY_NO_ADVERTISE + "|" +
		table.COMMUNITY_NO_EXPORT_SUBCONFED + ")$")
	if regUint.MatchString(comStr) || regString.MatchString(comStr) || regWellKnown.MatchString(comStr) {
		return true
	}
	return false
}

func parseCommunitySet(eArgs []string) (*api.CommunitySet, error) {
	if !checkCommunityFormat(eArgs[1]) {
		if _, err := regexp.Compile(eArgs[1]); err != nil {
			return nil, fmt.Errorf("invalid community: %s\nplease enter community format", eArgs[1])
		}
	}
	communitySet := &api.CommunitySet{
		CommunitySetName: eArgs[0],
		CommunityMembers: []string{eArgs[1]},
	}
	return communitySet, nil
}

func modPolicyCommunity(modtype string, eArgs []string) error {
	communitySet := &api.CommunitySet{}
	var e error
	var operation api.Operation

	switch modtype {
	case CMD_ADD:
		if len(eArgs) < 2 {
			return fmt.Errorf("usage: policy community add <community set name> <community>")
		}
		if communitySet, e = parseCommunitySet(eArgs); e != nil {
			return e
		}
		operation = api.Operation_ADD
	case CMD_DEL:
		if len(eArgs) == 0 {
			return fmt.Errorf("usage: policy community add <community set name> [<community>]")
		} else if len(eArgs) == 1 {
			communitySet = &api.CommunitySet{
				CommunitySetName: eArgs[0],
				CommunityMembers: nil,
			}
		} else {
			if communitySet, e = parseCommunitySet(eArgs); e != nil {
				return e
			}
		}
		operation = api.Operation_DEL
	case CMD_ALL:
		if len(eArgs) > 0 {
			return fmt.Errorf("Argument can not be entered: %s", eArgs[0:])
		}
		operation = api.Operation_DEL_ALL
	default:
		return fmt.Errorf("invalid modType %s", modtype)
	}
	if e = modPolicy(api.Resource_POLICY_COMMUNITY, operation, communitySet); e != nil {
		return e
	}
	return nil
}

func formatPolicyExtCommunity(head bool, indent int, ecsl []*api.ExtCommunitySet) string {
	buff := bytes.NewBuffer(make([]byte, 0, 64))
	sIndent := strings.Repeat(" ", indent)
	maxNameLen := 0
	maxCommunityLen := 0
	for _, es := range ecsl {
		if len(es.ExtCommunitySetName) > maxNameLen {
			maxNameLen = len(es.ExtCommunitySetName)
		}
		for _, m := range es.ExtCommunityMembers {
			if len(m) > maxCommunityLen {
				maxCommunityLen = len(m)
			}
		}
	}

	if head {
		if len("Name") > maxNameLen {
			maxNameLen = len("Name")
		}
		if len("ExtCommunity") > maxCommunityLen {
			maxCommunityLen = len("ExtCommunity")
		}
	}

	format := "%-" + fmt.Sprint(maxNameLen) + "s  %-" + fmt.Sprint(maxCommunityLen) + "s\n"
	if head {
		buff.WriteString(fmt.Sprintf(format, "Name", "ExtCommunity"))
	}
	for _, ecs := range ecsl {
		for i, ec := range ecs.ExtCommunityMembers {
			if i == 0 {
				buff.WriteString(fmt.Sprintf(format, ecs.ExtCommunitySetName, ec))
			} else {
				buff.WriteString(fmt.Sprintf(sIndent))
				buff.WriteString(fmt.Sprintf(format, "", ec))
			}
		}
	}
	return buff.String()
}

func showPolicyExtCommunities() error {
	arg := &api.PolicyArguments{
		Resource: api.Resource_POLICY_EXTCOMMUNITY,
	}
	stream, e := client.GetPolicyRoutePolicies(context.Background(), arg)
	if e != nil {
		return e
	}
	m := extcommunities{}
	for {
		a, e := stream.Recv()
		if e == io.EOF {
			break
		} else if e != nil {
			return e
		}
		m = append(m, a.StatementList[0].Conditions.MatchExtCommunitySet)
	}
	if globalOpts.Json {
		j, _ := json.Marshal(m)
		fmt.Println(string(j))
		return nil
	}
	if globalOpts.Quiet {
		for _, e := range m {
			fmt.Println(e.ExtCommunitySetName)
		}
		return nil
	}
	sort.Sort(m)

	output := formatPolicyExtCommunity(true, 0, m)
	fmt.Print(output)
	return nil
}

func showPolicyExtCommunity(args []string) error {
	arg := &api.PolicyArguments{
		Resource: api.Resource_POLICY_EXTCOMMUNITY,
		Name:     args[0],
	}
	pd, e := client.GetPolicyRoutePolicy(context.Background(), arg)
	if e != nil {
		return e
	}
	ecs := pd.StatementList[0].Conditions.GetMatchExtCommunitySet()
	if globalOpts.Json {
		j, _ := json.Marshal(ecs)
		fmt.Println(string(j))
		return nil
	}
	if globalOpts.Quiet {
		for _, ec := range ecs.ExtCommunityMembers {
			fmt.Println(ec)
		}
		return nil
	}
	output := formatPolicyExtCommunity(true, 0, []*api.ExtCommunitySet{ecs})
	fmt.Print(output)
	return nil
}

func checkExtCommunityFormat(eComStr string) bool {
	// extended community regexp
	checkSubType := func(eComStr string) (bool, string) {
		regSubType, _ := regexp.Compile("^(RT|SoO):(.*)$")
		if regSubType.MatchString(eComStr) {
			regResult := regSubType.FindStringSubmatch(eComStr)
			return true, regResult[2]
		}
		return false, ""
	}
	checkValue := func(eComVal string) (bool, string) {
		regVal, _ := regexp.Compile("^([0-9\\.]+):([0-9]+)$")
		if regVal.MatchString(eComVal) {
			regResult := regVal.FindStringSubmatch(eComVal)
			return true, regResult[1]
		}
		return false, ""
	}
	checkElem := func(gAdmin string) bool {
		addr := net.ParseIP(gAdmin)
		if addr.To4() != nil {
			return true
		}
		regAs, _ := regexp.Compile("^([0-9]+)$")
		regAs4, _ := regexp.Compile("^([0-9]+).([0-9]+)$")
		if regAs.MatchString(gAdmin) || regAs4.MatchString(gAdmin) {
			return true
		}
		return false
	}

	if subTypeOk, eComVal := checkSubType(eComStr); subTypeOk {
		if valOk, gAdmin := checkValue(eComVal); valOk {
			if checkElem(gAdmin) {
				return true
			}
		}
		_, err := regexp.Compile(eComVal)
		if err == nil {
			return true
		}
	}
	return false
}

func parseExtCommunitySet(eArgs []string) (*api.ExtCommunitySet, error) {
	if !checkExtCommunityFormat(eArgs[1]) {
		return nil, fmt.Errorf("invalid extended community: %s\nplease enter extended community format", eArgs[1])
	}
	extCommunitySet := &api.ExtCommunitySet{
		ExtCommunitySetName: eArgs[0],
		ExtCommunityMembers: []string{eArgs[1]},
	}
	return extCommunitySet, nil
}

func modPolicyExtCommunity(modtype string, eArgs []string) error {
	extCommunitySet := &api.ExtCommunitySet{}
	var e error
	var operation api.Operation

	switch modtype {
	case CMD_ADD:
		if len(eArgs) < 2 {
			return fmt.Errorf("usage: policy extcommunity add <community set name> <community>")
		}
		if extCommunitySet, e = parseExtCommunitySet(eArgs); e != nil {
			return e
		}
		operation = api.Operation_ADD
	case CMD_DEL:
		if len(eArgs) == 0 {
			return fmt.Errorf("usage: policy extcommunity add <community set name> [<community>]")
		} else if len(eArgs) == 1 {
			extCommunitySet = &api.ExtCommunitySet{
				ExtCommunitySetName: eArgs[0],
				ExtCommunityMembers: nil,
			}
		} else {
			if extCommunitySet, e = parseExtCommunitySet(eArgs); e != nil {
				return e
			}
		}
		operation = api.Operation_DEL
	case CMD_ALL:
		if len(eArgs) > 0 {
			return fmt.Errorf("Argument can not be entered: %s", eArgs[0:])
		}
		operation = api.Operation_DEL_ALL
	default:
		return fmt.Errorf("invalid modType %s", modtype)
	}
	if e = modPolicy(api.Resource_POLICY_EXTCOMMUNITY, operation, extCommunitySet); e != nil {
		return e
	}
	return nil
}

func showPolicyStatement(indent int, pd *api.PolicyDefinition) {
	sIndent := func(indent int) string {
		return strings.Repeat(" ", indent)
	}
	baseIndent := 28
	for _, st := range pd.StatementList {
		fmt.Printf("%sStatementName %s:\n", sIndent(indent), st.StatementNeme)
		fmt.Printf("%sConditions:\n", sIndent(indent+2))

		ps := st.Conditions.MatchPrefixSet
		fmt.Printf("%sPrefixSet:       %-6s ", sIndent(indent+4), ps.MatchSetOptions)
		if out := formatPolicyPrefix(false, baseIndent+indent, []*api.PrefixSet{ps}); out != "" {
			fmt.Print(out)
		} else {
			fmt.Printf("\n")
		}

		ns := st.Conditions.MatchNeighborSet
		fmt.Printf("%sNeighborSet:     %-6s ", sIndent(indent+4), ns.MatchSetOptions)
		if out := formatPolicyNeighbor(false, baseIndent+indent, []*api.NeighborSet{ns}); out != "" {
			fmt.Print(out)
		} else {
			fmt.Printf("\n")
		}

		aps := st.Conditions.MatchAsPathSet
		fmt.Printf("%sAsPathSet:       %-6s ", sIndent(indent+4), aps.MatchSetOptions)
		if out := formatPolicyAsPath(false, baseIndent+indent, []*api.AsPathSet{aps}); out != "" {
			fmt.Print(out)
		} else {
			fmt.Printf("\n")
		}

		cs := st.Conditions.MatchCommunitySet
		fmt.Printf("%sCommunitySet:    %-6s ", sIndent(indent+4), cs.MatchSetOptions)
		if out := formatPolicyCommunity(false, baseIndent+indent, []*api.CommunitySet{cs}); out != "" {
			fmt.Print(out)
		} else {
			fmt.Printf("\n")
		}

		ecs := st.Conditions.MatchExtCommunitySet
		fmt.Printf("%sExtCommunitySet: %-6s ", sIndent(indent+4), ecs.MatchSetOptions)
		if out := formatPolicyExtCommunity(false, baseIndent+indent, []*api.ExtCommunitySet{ecs}); out != "" {
			fmt.Print(out)
		} else {
			fmt.Printf("\n")
		}

		asPathLentgh := st.Conditions.MatchAsPathLength
		fmt.Printf("%sAsPathLength:    %-6s   %s\n", sIndent(indent+4), asPathLentgh.Operator, asPathLentgh.Value)
		fmt.Printf("%sActions:\n", sIndent(indent+2))

		formatComAction := func(c *api.CommunityAction) string {
			communityAction := c.Options
			if len(c.Communities) != 0 || c.Options == "NULL" {
				communities := strings.Join(c.Communities, ",")
				communityAction = fmt.Sprintf("%s[%s]", c.Options, communities)
			}
			return communityAction
		}
		fmt.Printf("%sCommunity:       %s\n", sIndent(indent+4), formatComAction(st.Actions.Community))
		fmt.Printf("%sExtCommunity:    %s\n", sIndent(indent+4), formatComAction(st.Actions.ExtCommunity))
		fmt.Printf("%sMed:             %s\n", sIndent(indent+4), st.Actions.Med)

		asn := ""
		repeat := ""
		if st.Actions.AsPrepend.As != "" {
			asn = st.Actions.AsPrepend.As
			repeat = fmt.Sprintf("%d", st.Actions.AsPrepend.Repeatn)
		}
		fmt.Printf("%sAsPrepend:       %s   %s\n", sIndent(indent+4), asn, repeat)
		fmt.Printf("%s%s\n", sIndent(indent+4), st.Actions.RouteAction)
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
			fmt.Println(p.PolicyDefinitionName)
		}
		return nil
	}
	sort.Sort(m)

	for _, pd := range m {
		fmt.Printf("PolicyName %s:\n", pd.PolicyDefinitionName)
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
		for _, st := range pd.StatementList {
			fmt.Println(st.StatementNeme)
		}
		return nil
	}

	fmt.Printf("PolicyName %s:\n", pd.PolicyDefinitionName)
	showPolicyStatement(2, pd)
	return nil
}

func parseConditions() (*api.Conditions, error) {
	checkFormat := func(option string, isRestricted bool) ([]string, error) {
		regStr, _ := regexp.Compile("^(.*)\\[(.*)\\]$")
		isMatched := regStr.MatchString(option)
		if !isMatched {
			return nil, fmt.Errorf("Please enter the <match option>[condition name]")
		}
		group := regStr.FindStringSubmatch(option)
		if isRestricted {
			if group[1] != "ANY" && group[1] != "INVERT" {
				return nil, fmt.Errorf("Please enter the <ANY|INVERT>[condition name]")
			}
		} else {
			if group[1] != "ANY" && group[1] != "ALL" && group[1] != "INVERT" {
				return nil, fmt.Errorf("Please enter the <ANY|ALL|INVERT>[condition name]")
			}
		}
		return group, nil
	}

	conditions := &api.Conditions{}
	if conditionOpts.Prefix != "" {
		op, err := checkFormat(conditionOpts.Prefix, true)
		if err != nil {
			return nil, fmt.Errorf("invalid prefix option format\n%s", err)
		}
		conditions.MatchPrefixSet = &api.PrefixSet{
			PrefixSetName:   op[2],
			MatchSetOptions: op[1],
		}
	}
	if conditionOpts.Neighbor != "" {
		op, err := checkFormat(conditionOpts.Neighbor, true)
		if err != nil {
			return nil, fmt.Errorf("invalid neighbor option format\n%s", err)
		}
		conditions.MatchNeighborSet = &api.NeighborSet{
			NeighborSetName: op[2],
			MatchSetOptions: op[1],
		}
	}
	if conditionOpts.AsPath != "" {
		op, err := checkFormat(conditionOpts.AsPath, false)
		if err != nil {
			return nil, fmt.Errorf("invalid aspath option format\n%s", err)
		}
		conditions.MatchAsPathSet = &api.AsPathSet{
			AsPathSetName:   op[2],
			MatchSetOptions: op[1],
		}
	}
	if conditionOpts.Community != "" {
		op, err := checkFormat(conditionOpts.Community, false)
		if err != nil {
			return nil, fmt.Errorf("invalid community option format\n%s", err)
		}
		conditions.MatchCommunitySet = &api.CommunitySet{
			CommunitySetName: op[2],
			MatchSetOptions:  op[1],
		}
	}
	if conditionOpts.ExtCommunity != "" {
		op, err := checkFormat(conditionOpts.ExtCommunity, false)
		if err != nil {
			return nil, fmt.Errorf("invalid extended community option format\n%s", err)
		}
		conditions.MatchExtCommunitySet = &api.ExtCommunitySet{
			ExtCommunitySetName: op[2],
			MatchSetOptions:     op[1],
		}
	}
	if conditionOpts.AsPathLength != "" {
		asPathLen := conditionOpts.AsPathLength
		idx := strings.Index(asPathLen, ",")
		if idx == -1 {
			return nil, fmt.Errorf("invalid as path length: %s\nPlease enter the <value>,<operator>", asPathLen)
		}
		operator := asPathLen[:idx]
		value := asPathLen[idx+1:]
		if _, err := strconv.ParseUint(value, 10, 32); err != nil {
			return nil, fmt.Errorf("invalid as path length: %s\nPlease enter a numeric", value)
		}
		conditions.MatchAsPathLength = &api.AsPathLength{
			Value:    value,
			Operator: operator,
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
	regStr, _ := regexp.Compile("^(.*)\\[(.*)\\]$")
	var communities, option string
	communityList := make([]string, 0)
	if regStr.MatchString(communityStr) {
		group := regStr.FindStringSubmatch(communityStr)
		option = group[1]
		communities = group[2]

		// check options
		communityActionTypes := table.COMMUNITY_ACTION_ADD + "|" +
			table.COMMUNITY_ACTION_REPLACE + "|" +
			table.COMMUNITY_ACTION_REMOVE + "|" +
			table.COMMUNITY_ACTION_NULL
		regOption, _ := regexp.Compile(fmt.Sprintf("^(%s)$", communityActionTypes))
		if !regOption.MatchString(option) {
			e := fmt.Sprintf("invalid Option: %s\n", option)
			e += fmt.Sprintf("please enter the (%s)", communityActionTypes)
			return nil, fmt.Errorf("%s", e)
		}
		// check the relationship between the community and the option
		if option == "NULL" && communities != "" {
			e := "invalid relationship between  community and option\n"
			e += "When the option is NULL, community should not be input"
			return nil, fmt.Errorf("%s", e)
		} else if !(communities == "" && option == "NULL") {
			// check communities
			communityList = strings.Split(communities, ",")
			for _, community := range communityList {
				if !checkCommunityFormat(community) {
					return nil, fmt.Errorf("invalid Community %s:", community)
				}
			}
		}
	} else {
		e := fmt.Sprintf("invalid format: %s\n", communityStr)
		e += "please enter the <option>[<comunity>,<comunity>,...]"
		return nil, fmt.Errorf("%s", e)
	}
	communityAction := &api.CommunityAction{
		Communities: communityList,
		Options:     option,
	}
	return communityAction, nil
}

func parseAsPrependAction(communityStr string) (*api.AsPrependAction, error) {
	regStr, _ := regexp.Compile("^([0-9]+|last-as),([0-9]+)$")
	group := regStr.FindStringSubmatch(communityStr)

	as := group[1]
	if as != "last-as" {
		_, e := strconv.ParseUint(as, 10, 32)
		if e != nil {
			return nil, fmt.Errorf("%s", "invalid as number")
		}
	}

	repeatn, e := strconv.ParseUint(group[2], 10, 8)
	if e != nil {
		return nil, fmt.Errorf("%s", "invalid repeat count")
	}

	asprependAction := &api.AsPrependAction{
		As:      as,
		Repeatn: uint32(repeatn),
	}

	return asprependAction, nil
}

func checkMedAction(medStr string) error {
	regMed, _ := regexp.Compile("^(\\+|\\-)?([0-9]+)$")
	if !regMed.MatchString(medStr) {
		e := fmt.Sprintf("invalid format: %s\n", medStr)
		e += "please enter the [+|-]<med>"
		return fmt.Errorf("%s", e)
	}
	return nil
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
		e := checkMedAction(actionOpts.MedAction)
		if e != nil {
			return nil, e
		}
		actions.Med = actionOpts.MedAction
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

func modPolicyRoutePolicy(modtype string, eArgs []string) error {
	var operation api.Operation
	pd := &api.PolicyDefinition{}
	if len(eArgs) > 0 {
		pd.PolicyDefinitionName = eArgs[0]
	}

	switch modtype {
	case CMD_ADD:
		if len(eArgs) != 2 {
			return fmt.Errorf("usage:  gobgp policy routepoilcy add <route policy name> <statement name>")
		}
		stmt := &api.Statement{
			StatementNeme: eArgs[1],
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

		pd.StatementList = []*api.Statement{stmt}
		operation = api.Operation_ADD

	case CMD_DEL:
		if len(eArgs) == 0 {
			return fmt.Errorf("usage: policy neighbor del <route policy name> [<statement name>]")
		} else if len(eArgs) == 1 {
			operation = api.Operation_DEL
		} else if len(eArgs) == 2 {
			stmt := &api.Statement{
				StatementNeme: eArgs[1],
			}
			pd.StatementList = []*api.Statement{stmt}
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

func NewPolicyAddCmd(v string, mod func(string, []string) error) *cobra.Command {
	policyAddCmd := &cobra.Command{
		Use: CMD_ADD,
		Run: func(cmd *cobra.Command, args []string) {
			err := mod(cmd.Use, args)
			if err != nil {
				fmt.Println(err)
			}
		},
	}
	if v == CMD_ROUTEPOLICY {
		policyAddCmd.Flags().StringVarP(&conditionOpts.Prefix, "c-prefix", "", "", "a prefix set name of policy condition")
		policyAddCmd.Flags().StringVarP(&conditionOpts.Neighbor, "c-neighbor", "", "", "a neighbor set name of policy condition")
		policyAddCmd.Flags().StringVarP(&conditionOpts.AsPath, "c-aspath", "", "", "an as path set name of policy condition")
		policyAddCmd.Flags().StringVarP(&conditionOpts.Community, "c-community", "", "", "a community set name of policy condition")
		policyAddCmd.Flags().StringVarP(&conditionOpts.ExtCommunity, "c-extcommunity", "", "", "a extended community set name of policy condition")
		policyAddCmd.Flags().StringVarP(&conditionOpts.AsPathLength, "c-aslen", "", "", "an as path length of policy condition (<operator>,<numeric>)")
		policyAddCmd.Flags().StringVarP(&actionOpts.RouteAction, "a-route", "", "", "a route action of policy action (accept | reject)")
		policyAddCmd.Flags().StringVarP(&actionOpts.CommunityAction, "a-community", "", "", "a community of policy action")
		policyAddCmd.Flags().StringVarP(&actionOpts.MedAction, "a-med", "", "", "a med of policy action")
		policyAddCmd.Flags().StringVarP(&actionOpts.AsPathPrependAction, "a-asprepend", "", "", "aspath prepend for policy action")
	}

	return policyAddCmd
}

func NewPolicyDelCmd(mod func(string, []string) error) *cobra.Command {
	policyDelCmd := &cobra.Command{
		Use: CMD_DEL,
		Run: func(cmd *cobra.Command, args []string) {
			err := mod(cmd.Use, args)
			if err != nil {
				fmt.Println(err)
			}
		},
	}

	subcmd := &cobra.Command{
		Use: CMD_ALL,
		Run: func(cmd *cobra.Command, args []string) {
			err := mod(cmd.Use, args)
			if err != nil {
				fmt.Println(err)
			}
		},
	}
	policyDelCmd.AddCommand(subcmd)
	return policyDelCmd
}

func NewPolicyCmd() *cobra.Command {
	policyCmd := &cobra.Command{
		Use: CMD_POLICY,
	}

	for _, v := range []string{CMD_PREFIX, CMD_NEIGHBOR, CMD_ASPATH, CMD_COMMUNITY, CMD_EXTCOMMUNITY, CMD_ROUTEPOLICY} {
		var showAll func() error
		var showOne func([]string) error
		var mod func(string, []string) error
		switch v {
		case CMD_PREFIX:
			showAll = showPolicyPrefixes
			showOne = showPolicyPrefix
			mod = modPolicyPrefix
		case CMD_NEIGHBOR:
			showAll = showPolicyNeighbors
			showOne = showPolicyNeighbor
			mod = modPolicyNeighbor
		case CMD_ASPATH:
			showAll = showPolicyAsPaths
			showOne = showPolicyAsPath
			mod = modPolicyAsPath
		case CMD_COMMUNITY:
			showAll = showPolicyCommunities
			showOne = showPolicyCommunity
			mod = modPolicyCommunity
		case CMD_EXTCOMMUNITY:
			showAll = showPolicyExtCommunities
			showOne = showPolicyExtCommunity
			mod = modPolicyExtCommunity
		case CMD_ROUTEPOLICY:
			showAll = showPolicyRoutePolicies
			showOne = showPolicyRoutePolicy
			mod = modPolicyRoutePolicy
		}
		cmd := &cobra.Command{
			Use: v,
			Run: func(cmd *cobra.Command, args []string) {
				var err error
				if len(args) == 0 {
					err = showAll()
				} else {
					err = showOne(args)
				}

				if err != nil {
					fmt.Println(err)
				}
			},
		}

		policyAddCmd := NewPolicyAddCmd(v, mod)
		cmd.AddCommand(policyAddCmd)
		policyDelCmd := NewPolicyDelCmd(mod)
		cmd.AddCommand(policyDelCmd)

		policyCmd.AddCommand(cmd)
	}

	return policyCmd
}
