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
	"encoding/json"
	"fmt"
	"github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/policy"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"io"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func formatPolicyPrefix(prefixSetList []*api.PrefixSet) (string, string) {
	maxNameLen := len("Name")
	maxPrefixLen := len("Prefix")
	maxRangeLen := len("MaskRange")
	for _, ps := range prefixSetList {
		if len(ps.PrefixSetName) > maxNameLen {
			maxNameLen = len(ps.PrefixSetName)
		}
		for _, p := range ps.PrefixList {
			if len(p.Address)+len(fmt.Sprint(p.MaskLength))+1 > maxPrefixLen {
				maxPrefixLen = len(p.Address) + len(fmt.Sprint(p.MaskLength)) + 1
			}
			if len(p.MaskLengthRange) > maxRangeLen {
				maxRangeLen = len(p.MaskLengthRange)
			}
		}
	}
	formatPrefixSet := "%-" + fmt.Sprint(maxNameLen) + "s  %-" + fmt.Sprint(maxPrefixLen) + "s  %-" + fmt.Sprint(maxRangeLen) + "s\n"
	formatPrefixListOnly := "%-" + fmt.Sprint(maxPrefixLen) + "s  %-" + fmt.Sprint(maxRangeLen) + "s\n"
	return formatPrefixSet, formatPrefixListOnly
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

	format, _ := formatPolicyPrefix(m)
	fmt.Printf(format, "Name", "Prefix", "MaskRange")
	for _, ps := range m {
		for i, p := range ps.PrefixList {
			prefix := fmt.Sprintf("%s/%d", p.Address, p.MaskLength)
			if i == 0 {
				fmt.Printf(format, ps.PrefixSetName, prefix, p.MaskLengthRange)
			} else {
				fmt.Printf(format, "", prefix, p.MaskLengthRange)
			}
		}
	}
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
			fmt.Printf("%s/%d %s\n", p.Address, p.MaskLength, p.MaskLengthRange)
		}
		return nil
	}
	format, _ := formatPolicyPrefix([]*api.PrefixSet{ps})
	fmt.Printf(format, "Name", "Prefix", "MaskRange")
	for i, p := range ps.PrefixList {
		prefix := fmt.Sprintf("%s/%d", p.Address, p.MaskLength)
		if i == 0 {
			fmt.Printf(format, ps.PrefixSetName, prefix, p.MaskLengthRange)
		} else {
			fmt.Printf(format, "", prefix, p.MaskLengthRange)
		}
	}
	return nil
}

func parsePrefixSet(eArgs []string) (*api.PrefixSet, error) {
	_, ipNet, e := net.ParseCIDR(eArgs[1])
	if e != nil {
		return nil, fmt.Errorf("invalid prefix: %s\nplease enter ipv4 or ipv6 format", eArgs[1])
	}
	mask, _ := ipNet.Mask.Size()
	prefix := &api.Prefix{
		Address:    ipNet.IP.String(),
		MaskLength: uint32(mask),
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

func formatPolicyNeighbor(neighborSetList []*api.NeighborSet) string {
	maxNameLen := len("Name")
	maxAddressLen := len("Address")
	for _, ns := range neighborSetList {
		if len(ns.NeighborSetName) > maxNameLen {
			maxNameLen = len(ns.NeighborSetName)
		}
		for _, n := range ns.NeighborList {
			if len(n.Address) > maxAddressLen {
				maxAddressLen = len(n.Address)
			}
		}
	}
	format := "%-" + fmt.Sprint(maxNameLen) + "s  %-" + fmt.Sprint(maxAddressLen) + "s\n"
	return format
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

	format := formatPolicyNeighbor(m)
	fmt.Printf(format, "Name", "Address")
	for _, ns := range m {
		for i, n := range ns.NeighborList {
			if i == 0 {
				fmt.Printf(format, ns.NeighborSetName, n.Address)
			} else {
				fmt.Printf(format, "", n.Address)
			}
		}
	}
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
	format := formatPolicyNeighbor([]*api.NeighborSet{ns})
	fmt.Printf(format, "Name", "Address")
	for i, n := range ns.NeighborList {
		if i == 0 {
			fmt.Printf(format, ns.NeighborSetName, n.Address)
		} else {
			fmt.Printf(format, "", n.Address)

		}
	}
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

func formatPolicyAsPath(asPathSetList []*api.AsPathSet) string {
	maxNameLen := len("Name")
	maxPathLen := len("AsPath")
	for _, as := range asPathSetList {
		if len(as.AsPathSetName) > maxNameLen {
			maxNameLen = len(as.AsPathSetName)
		}
		for _, m := range as.AsPathMembers {
			if len(m) > maxPathLen {
				maxPathLen = len(m)
			}
		}
	}
	format := "%-" + fmt.Sprint(maxNameLen) + "s  %-" + fmt.Sprint(maxPathLen) + "s\n"
	return format
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

	format := formatPolicyAsPath(m)
	fmt.Printf(format, "Name", "AsPath")
	for _, as := range m {
		for i, m := range as.AsPathMembers {
			if i == 0 {
				fmt.Printf(format, as.AsPathSetName, m)
			} else {
				fmt.Printf(format, "", m)
			}
		}
	}
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
	format := formatPolicyAsPath([]*api.AsPathSet{as})
	fmt.Printf(format, "Name", "AsPath")
	for i, m := range as.AsPathMembers {
		if i == 0 {
			fmt.Printf(format, as.AsPathSetName, m)
		} else {
			fmt.Printf(format, "", m)
		}
	}
	return nil
}

func parseAsPathSet(eArgs []string) (*api.AsPathSet, error) {
	regAsn, _ := regexp.Compile("^(\\^?)([0-9]+)(\\$?)$")
	if !regAsn.MatchString(eArgs[1]) {
		return nil, fmt.Errorf("invalid aspath: %s\nplease enter aspath format", eArgs[1])
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

func formatPolicyCommunity(CommunitySetList []*api.CommunitySet) string {
	maxNameLen := len("Name")
	maxCommunityLen := len("Community")
	for _, cs := range CommunitySetList {
		if len(cs.CommunitySetName) > maxNameLen {
			maxNameLen = len(cs.CommunitySetName)
		}
		for _, m := range cs.CommunityMembers {
			if len(m) > maxCommunityLen {
				maxCommunityLen = len(m)
			}
		}
	}
	format := "%-" + fmt.Sprint(maxNameLen) + "s  %-" + fmt.Sprint(maxCommunityLen) + "s\n"
	return format
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

	format := formatPolicyCommunity(m)
	fmt.Printf(format, "Name", "Community")
	for _, cs := range m {
		for i, m := range cs.CommunityMembers {
			if i == 0 {
				fmt.Printf(format, cs.CommunitySetName, m)
			} else {
				fmt.Printf(format, "", m)
			}
		}
	}
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
	format := formatPolicyCommunity([]*api.CommunitySet{cs})
	fmt.Printf(format, "Name", "Community")
	for i, m := range cs.CommunityMembers {
		if i == 0 {
			fmt.Printf(format, cs.CommunitySetName, m)
		} else {
			fmt.Printf(format, "", m)
		}
	}
	return nil
}

func checkCommunityFormat(comStr string) bool {
	// community regexp
	regUint, _ := regexp.Compile("^([0-9]+)$")
	regString, _ := regexp.Compile("([0-9]+):([0-9]+)")
	regWellKnown, _ := regexp.Compile("^(" +
		policy.COMMUNITY_INTERNET + "|" +
		policy.COMMUNITY_NO_EXPORT + "|" +
		policy.COMMUNITY_NO_ADVERTISE + "|" +
		policy.COMMUNITY_NO_EXPORT_SUBCONFED + ")$")
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

func showPolicyStatement(head string, pd *api.PolicyDefinition) {
	for _, st := range pd.StatementList {
		fmt.Printf("%s  StatementName %s:\n", head, st.StatementNeme)
		fmt.Printf("%s    Conditions:\n", head)
		prefixSet := st.Conditions.MatchPrefixSet
		fmt.Printf("%s      PrefixSet:    %s  ", head, prefixSet.PrefixSetName)
		if len(prefixSet.PrefixList) != 0 {
			nameFormat := "%-" + fmt.Sprint(len(prefixSet.PrefixSetName)+2) + "s"
			_, format := formatPolicyPrefix([]*api.PrefixSet{st.Conditions.MatchPrefixSet})
			for i, prefix := range prefixSet.PrefixList {
				p := fmt.Sprintf("%s/%d", prefix.Address, prefix.MaskLength)
				if i != 0 {
					fmt.Printf("%s                    ", head)
					fmt.Printf(nameFormat, "")
				}
				fmt.Printf(format, p, prefix.MaskLengthRange)
			}
		} else {
			fmt.Print("\n")
		}
		neighborSet := st.Conditions.MatchNeighborSet
		fmt.Printf("%s      NeighborSet:  %s  ", head, neighborSet.NeighborSetName)
		if len(neighborSet.NeighborList) != 0 {
			nameFormat := "%-" + fmt.Sprint(len(neighborSet.NeighborSetName)+2) + "s"
			for i, neighbor := range neighborSet.NeighborList {
				if i != 0 {
					fmt.Printf("%s                    ", head)
					fmt.Printf(nameFormat, "")
				}
				fmt.Println(neighbor.Address)
			}
		} else {
			fmt.Print("\n")
		}
		asPathSet := st.Conditions.MatchAsPathSet
		fmt.Printf("%s      AsPathSet:    %s  ", head, asPathSet.AsPathSetName)
		if len(asPathSet.AsPathMembers) != 0 {
			nameFormat := "%-" + fmt.Sprint(len(asPathSet.AsPathSetName)+2) + "s"
			for i, asPath := range asPathSet.AsPathMembers {
				if i != 0 {
					fmt.Printf("%s                    ", head)
					fmt.Printf(nameFormat, "")
				}
				fmt.Println(asPath)
			}
		} else {
			fmt.Print("\n")
		}
		communitySet := st.Conditions.MatchCommunitySet
		fmt.Printf("%s      CommunitySet: %s  ", head, communitySet.CommunitySetName)
		if len(communitySet.CommunityMembers) != 0 {
			nameFormat := "%-" + fmt.Sprint(len(communitySet.CommunitySetName)+2) + "s"
			for i, community := range communitySet.CommunityMembers {
				if i != 0 {
					fmt.Printf("%s                    ", head)
					fmt.Printf(nameFormat, "")
				}
				fmt.Println(community)
			}
		} else {
			fmt.Print("\n")
		}
		asPathLentgh := st.Conditions.MatchAsPathLength
		fmt.Printf("%s      AsPathLength: %s   %s\n", head, asPathLentgh.Operator, asPathLentgh.Value)
		fmt.Printf("%s      MatchOption:  %s\n", head, st.Conditions.MatchSetOptions)
		fmt.Printf("%s    Actions:\n", head)

		communityAction := st.Actions.Community.Options
		if len(st.Actions.Community.Communities) != 0 || st.Actions.Community.Options == "NULL" {
			communities := strings.Join(st.Actions.Community.Communities, ",")
			communityAction = fmt.Sprintf("%s[%s]", st.Actions.Community.Options, communities)
		}
		fmt.Printf("%s      Community:    %s\n", head, communityAction)
		fmt.Printf("%s      Med:          %s\n", head, st.Actions.Med)

		asn := ""
		repeat := ""
		if st.Actions.AsPrepend.As != "" {
			asn = st.Actions.AsPrepend.As
			repeat = fmt.Sprintf("%d", st.Actions.AsPrepend.Repeatn)
		}
		fmt.Printf("%s      AsPrepend:    %s   %s\n", head, asn, repeat)
		fmt.Printf("%s      %s\n", head, st.Actions.RouteAction)
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
		showPolicyStatement("", pd)
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
	showPolicyStatement("", pd)
	return nil
}

func parseConditions() (*api.Conditions, error) {
	conditions := &api.Conditions{}
	if conditionOpts.Prefix != "" {
		conditions.MatchPrefixSet = &api.PrefixSet{
			PrefixSetName: conditionOpts.Prefix,
		}
	}
	if conditionOpts.Neighbor != "" {
		conditions.MatchNeighborSet = &api.NeighborSet{
			NeighborSetName: conditionOpts.Neighbor,
		}
	}
	if conditionOpts.AsPath != "" {
		conditions.MatchAsPathSet = &api.AsPathSet{
			AsPathSetName: conditionOpts.AsPath,
		}
	}
	if conditionOpts.Community != "" {
		conditions.MatchCommunitySet = &api.CommunitySet{
			CommunitySetName: conditionOpts.Community,
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
	if conditionOpts.Option != "" {
		optionUpper := strings.ToUpper(conditionOpts.Option)
		var option string
		switch optionUpper {
		case policy.OPTIONS_ANY, policy.OPTIONS_ALL, policy.OPTIONS_INVERT:
			option = optionUpper
		default:
			return nil, fmt.Errorf("invalid condition option: %s\nPlease enter the any or all or invert",
				conditionOpts.Option)
		}
		conditions.MatchSetOptions = option
	}
	return conditions, nil
}

func parseRouteAction(rType string) (string, error) {
	routeActionUpper := strings.ToUpper(rType)
	var routeAction string
	switch routeActionUpper {
	case policy.ROUTE_ACCEPT, policy.ROUTE_REJECT:
		routeAction = routeActionUpper
	default:
		return "", fmt.Errorf("invalid route action: %s\nPlease enter the accept or reject", rType)
	}
	return routeAction, nil
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
		communityActionTypes := policy.COMMUNITY_ACTION_ADD + "|" +
			policy.COMMUNITY_ACTION_REPLACE + "|" +
			policy.COMMUNITY_ACTION_REMOVE + "|" +
			policy.COMMUNITY_ACTION_NULL
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
		policyAddCmd.Flags().StringVarP(&conditionOpts.AsPathLength, "c-aslen", "", "", "an as path length of policy condition (<operator>,<numeric>)")
		policyAddCmd.Flags().StringVarP(&conditionOpts.Option, "c-option", "", "", "an option of policy condition")
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

	for _, v := range []string{CMD_PREFIX, CMD_NEIGHBOR, CMD_ASPATH, CMD_COMMUNITY, CMD_ROUTEPOLICY} {
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
