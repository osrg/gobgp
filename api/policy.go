// Copyright (C) 2018 Nippon Telegraph and Telephone Corporation.
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

package gobgpapi

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/osrg/gobgp/packet/bgp"
)

var (
	repexpCommunity       = regexp.MustCompile(`(\d+.)*\d+:\d+`)
	regexpLargeCommunity  = regexp.MustCompile(`\d+:\d+:\d+`)
	regexpCommunityString = regexp.MustCompile(`[\^\$]`)
)

func ParseCommunityRegexp(arg string) (*regexp.Regexp, error) {
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

func ParseExtCommunityRegexp(arg string) (bgp.ExtendedCommunityAttrSubType, *regexp.Regexp, error) {
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
	exp, err := ParseCommunityRegexp(elems[1])
	return subtype, exp, err
}

func ParseLargeCommunityRegexp(arg string) (*regexp.Regexp, error) {
	if regexpLargeCommunity.MatchString(arg) {
		return regexp.Compile(fmt.Sprintf("^%s$", arg))
	}
	exp, err := regexp.Compile(arg)
	if err != nil {
		return nil, fmt.Errorf("invalid large-community format: %s", arg)
	}
	return exp, nil
}

func (s *MatchSet) PrettyString() string {
	var typ string
	switch s.Type {
	case MatchType_ALL:
		typ = "all"
	case MatchType_ANY:
		typ = "any"
	case MatchType_INVERT:
		typ = "invert"
	}
	return fmt.Sprintf("%s %s", typ, s.GetName())
}

func (s *AsPathLength) PrettyString() string {
	var typ string
	switch s.Type {
	case AsPathLengthType_EQ:
		typ = "="
	case AsPathLengthType_GE:
		typ = ">="
	case AsPathLengthType_LE:
		typ = "<="
	}
	return fmt.Sprintf("%s%d", typ, s.Length)
}

func (s Conditions_RouteType) PrettyString() string {
	switch s {
	case Conditions_ROUTE_TYPE_EXTERNAL:
		return "external"
	case Conditions_ROUTE_TYPE_INTERNAL:
		return "internal"
	case Conditions_ROUTE_TYPE_LOCAL:
		return "local"
	}
	return "unknown"
}

func (a *CommunityAction) PrettyString() string {
	l := regexpCommunityString.ReplaceAllString(strings.Join(a.Communities, ", "), "")
	var typ string
	switch a.Type {
	case CommunityActionType_COMMUNITY_ADD:
		typ = "add"
	case CommunityActionType_COMMUNITY_REMOVE:
		typ = "remove"
	case CommunityActionType_COMMUNITY_REPLACE:
		typ = "replace"
	}
	return fmt.Sprintf("%s[%s]", typ, l)
}

func (a *MedAction) PrettyString() string {
	if a.Type == MedActionType_MED_MOD && a.Value > 0 {
		return fmt.Sprintf("+%d", a.Value)
	}
	return fmt.Sprintf("%d", a.Value)
}

func (a *LocalPrefAction) PrettyString() string {
	return fmt.Sprintf("%d", a.Value)
}

func (a *NexthopAction) PrettyString() string {
	if a.Self {
		return "self"
	}
	return a.Address
}

func (a *AsPrependAction) PrettyString() string {
	return fmt.Sprintf("prepend %d %d times", a.Asn, a.Repeat)
}
