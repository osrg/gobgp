// Copyright (C) 2014,2015 Nippon Telegraph and Telephone Corporation.
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

package policy

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/table"
	"net"
	"regexp"
	"reflect"
	"strconv"
	"strings"
)

type RouteType int

const (
	ROUTE_TYPE_NONE RouteType = iota
	ROUTE_TYPE_ACCEPT
	ROUTE_TYPE_REJECT
)

type MaskLengthRangeType int

const (
	MASK_LENGTH_RANGE_MIN MaskLengthRangeType = iota
	MASK_LENGTH_RANGE_MAX
)

type AttributeComparison int

const (
	// "== comparison"
	ATTRIBUTE_EQ AttributeComparison = iota
	// ">= comparison"
	ATTRIBUTE_GE
	// "<= comparison"
	ATTRIBUTE_LE
)

type Policy struct {
	Name       string
	Statements []*Statement
}

func NewPolicy(pd config.PolicyDefinition, ds config.DefinedSets) *Policy {
	stmtList := pd.StatementList
	st := make([]*Statement, 0)
	p := &Policy{
		Name: pd.Name,
	}

	for _, statement := range stmtList {

		conditions := make([]Condition, 0)

		// prefix match
		prefixSetName := statement.Conditions.MatchPrefixSet
		pc := NewPrefixCondition(prefixSetName, ds.PrefixSetList)
		conditions = append(conditions, pc)

		// neighbor match
		neighborSetName := statement.Conditions.MatchNeighborSet
		nc := NewNeighborCondition(neighborSetName, ds.NeighborSetList)
		conditions = append(conditions, nc)

		// AsPathLengthCondition
		c := statement.Conditions.BgpConditions.AsPathLength
		ac := NewAsPathLengthCondition(c)
		if ac != nil {
			conditions = append(conditions, ac)
		}

		// AsPathCondition
		asPathSetName := statement.Conditions.BgpConditions.MatchAsPathSet
		asc := NewAsPathCondition(asPathSetName, ds.BgpDefinedSets.AsPathSetList)
		if asc != nil {
			conditions = append(conditions, asc)
		}

		// CommunityCondition
		communitySetName := statement.Conditions.BgpConditions.MatchCommunitySet
		cc := NewCommunityCondition(communitySetName, ds.BgpDefinedSets.CommunitySetList)
		if cc != nil {
			conditions = append(conditions, cc)
		}

		action := &RoutingActions{
			AcceptRoute: false,
		}

		if statement.Actions.AcceptRoute {
			action.AcceptRoute = true
		}

		s := &Statement{
			Name:            statement.Name,
			Conditions:      conditions,
			Actions:         action,
			MatchSetOptions: statement.Conditions.MatchSetOptions,
		}

		st = append(st, s)
	}
	p.Statements = st
	return p
}

type Statement struct {
	Name            string
	Conditions      []Condition
	Actions         Actions
	MatchSetOptions config.MatchSetOptionsType
}

// evaluate each condition in the statement according to MatchSetOptions
func (s *Statement) evaluate(p table.Path) bool {

	optionType := s.MatchSetOptions

	result := false
	if optionType == config.MATCH_SET_OPTIONS_TYPE_ALL {
		result = true
	}

	for _, condition := range s.Conditions {

		r := condition.evaluate(p)

		switch optionType {
		case config.MATCH_SET_OPTIONS_TYPE_ALL:
			result = result && r
			if !result {
				return false
			}

		case config.MATCH_SET_OPTIONS_TYPE_ANY:
			result = result || r
			if result {
				return true
			}

		case config.MATCH_SET_OPTIONS_TYPE_INVERT:
			result = result || r
			if result {
				return false
			}

		default:
			return false
		}
	}

	if optionType == config.MATCH_SET_OPTIONS_TYPE_INVERT {
		return !result
	} else {
		return result
	}
}

type Condition interface {
	evaluate(table.Path) bool
}

type DefaultCondition struct {
	CallPolicy string
}

func (c *DefaultCondition) evaluate(path table.Path) bool {
	return false
}

type PrefixCondition struct {
	DefaultCondition
	PrefixConditionName string
	PrefixList          []Prefix
}

func NewPrefixCondition(prefixSetName string, defPrefixList []config.PrefixSet) *PrefixCondition {

	prefixList := make([]Prefix, 0)
	for _, ps := range defPrefixList {
		if ps.PrefixSetName == prefixSetName {
			for _, pl := range ps.PrefixList {
				prefix, e := NewPrefix(pl.Address, pl.Masklength, pl.MasklengthRange)
				if e != nil {
					log.WithFields(log.Fields{
						"Topic":  "Policy",
						"prefix": prefix,
						"msg":    e,
					}).Error("failed to generate a NewPrefix from configration.")
				} else {
					prefixList = append(prefixList, prefix)
				}
			}
		}
	}

	pc := &PrefixCondition{
		PrefixConditionName: prefixSetName,
		PrefixList:          prefixList,
	}

	return pc

}

// compare prefixes in this condition and nlri of path and
// subsequent comparison is skipped if that matches the conditions.
// If PrefixList's length is zero, return true.
func (c *PrefixCondition) evaluate(path table.Path) bool {

	if len(c.PrefixList) == 0 {
		log.Debug("PrefixList doesn't have elements")
		return true
	}

	for _, cp := range c.PrefixList {
		if ipPrefixCalculate(path, cp) {
			log.Debug("prefix matched : ", cp)
			return true
		}
	}
	return false
}

type NeighborCondition struct {
	DefaultCondition
	NeighborConditionName string
	NeighborList          []net.IP
}

func NewNeighborCondition(neighborSetName string, defNeighborSetList []config.NeighborSet) *NeighborCondition {

	neighborList := make([]net.IP, 0)
	for _, neighborSet := range defNeighborSetList {
		if neighborSet.NeighborSetName == neighborSetName {
			for _, nl := range neighborSet.NeighborInfoList {
				neighborList = append(neighborList, nl.Address)
			}
		}
	}

	nc := &NeighborCondition{
		NeighborConditionName: neighborSetName,
		NeighborList:          neighborList,
	}

	return nc
}

// compare neighbor ipaddress of this condition and source address of path
// and, subsequent comparisons are skipped if that matches the conditions.
// If NeighborList's length is zero, return true.
func (c *NeighborCondition) evaluate(path table.Path) bool {

	if len(c.NeighborList) == 0 {
		log.Debug("NeighborList doesn't have elements")
		return true
	}

	for _, neighbor := range c.NeighborList {
		cAddr := neighbor
		pAddr := path.GetSource().Address
		if pAddr.Equal(cAddr) {
			log.Debug("neighbor matched : ", pAddr.String())
			return true
		}
	}
	return false
}

type AsPathLengthCondition struct {
	DefaultCondition
	Value    uint32
	Operator AttributeComparison
}

// create AsPathLengthCondition object
func NewAsPathLengthCondition(defAsPathLength config.AsPathLength) *AsPathLengthCondition {

	value := defAsPathLength.Value
	var op AttributeComparison

	switch defAsPathLength.Operator {
	case "eq":
		op = ATTRIBUTE_EQ

	case "ge":
		op = ATTRIBUTE_GE

	case "le":
		op = ATTRIBUTE_LE
	default:
		return nil
	}

	ac := &AsPathLengthCondition{
		Value:    value,
		Operator: op,
	}

	return ac
}

// compare AS_PATH length in the message's AS_PATH attribute with
// the one in condition.
func (c *AsPathLengthCondition) evaluate(path table.Path) bool {

	length := uint32(path.GetAsPathLen())

	switch c.Operator {
	case ATTRIBUTE_EQ:
		return c.Value == length

	case ATTRIBUTE_GE:
		return c.Value <= length

	case ATTRIBUTE_LE:
		return c.Value >= length
	default:
		return false
	}

}

type AsPathCondition struct {
	DefaultCondition
	AsPathList []*AsPathElement
}

type AsnPos int

const (
	AS_FROM AsnPos = iota
	AS_ANY
	AS_ORIGIN
	AS_ONLY
)

type AsPathElement struct {
	postiion AsnPos
	asn      uint32
}

// create AsPathCondition object
// AsPathCondition supports only following regexp:
// - ^100  (from as100)
// - ^100$ (from as100 and originated by as100)
// - 100$  (originated by as100)
// - 100   (from or through or originated by as100)
func NewAsPathCondition(asPathSetName string, defAsPathSetList []config.AsPathSet) *AsPathCondition {

	regAsn, _ := regexp.Compile("^(\\^?)([0-9]+)(\\$?)$")

	asPathList := make([]*AsPathElement, 0)
	for _, asPathSet := range defAsPathSetList {
		if asPathSet.AsPathSetName == asPathSetName {
			for _, as := range asPathSet.AsPathSetMembers {
				if regAsn.MatchString(as) {

					group := regAsn.FindStringSubmatch(as)
					asn, err := strconv.Atoi(group[2])
					if err != nil {
						log.WithFields(log.Fields{
							"Topic": "Policy",
							"Type":  "AsPath Condition",
						}).Error("cannot parse AS Number.")
						return nil
					}
					e := &AsPathElement{}
					e.asn = uint32(asn)

					if len(group[1]) == 0 && len(group[3]) == 0 {
						e.postiion = AS_ANY
					} else if len(group[1]) == 1 && len(group[3]) == 0 {
						e.postiion = AS_FROM
					} else if len(group[1]) == 0 && len(group[3]) == 1 {
						e.postiion = AS_ORIGIN
					} else {
						e.postiion = AS_ONLY
					}

					asPathList = append(asPathList, e)

				} else {
					log.WithFields(log.Fields{
						"Topic": "Policy",
						"Type":  "AsPath Condition",
					}).Error("cannot parse AS_PATH condition value.")

					return nil
				}
			}

			c := &AsPathCondition{
				AsPathList: asPathList,
			}
			return c
		}
	}
	return nil
}

// compare AS_PATH in the message's AS_PATH attribute with
// the one in condition.
func (c *AsPathCondition) evaluate(path table.Path) bool {

	aspath := path.GetAsSeqList()

	if len(aspath) == 0 {
		return false
	}

	matched := false
	for _, member := range c.AsPathList {

		switch member.postiion {
		case AS_FROM:
			matched = aspath[0] == member.asn
		case AS_ANY:
			for _, n := range aspath {
				if n == member.asn {
					matched = true
					break
				}
			}
		case AS_ORIGIN:
			matched = aspath[len(aspath)-1] == member.asn

		case AS_ONLY:
			matched = len(aspath) == 1 && aspath[0] == member.asn

		}

		if matched {
			log.Debugf("aspath matched : asn=%d, pos=%v)", member.asn, member.postiion)
			return true
		}

	}
	return false
}

type CommunityCondition struct {
	DefaultCondition
	CommunityList []*CommunityElement
}

const (
	COMMUNITY_INTERNET            string = "INTERNET"
	COMMUNITY_NO_EXPORT           string = "NO_EXPORT"
	COMMUNITY_NO_ADVERTISE        string = "NO_ADVERTISE"
	COMMUNITY_NO_EXPORT_SUBCONFED string = "NO_EXPORT_SUBCONFED"
)

const (
	COMMUNITY_INTERNET_VAL            uint32 = 0x00000000
	COMMUNITY_NO_EXPORT_VAL                  = 0xFFFFFF01
	COMMUNITY_NO_ADVERTISE_VAL               = 0xFFFFFF02
	COMMUNITY_NO_EXPORT_SUBCONFED_VAL        = 0xFFFFFF03
)

type CommunityElement struct {
	community       uint32
	communityStr    string
	isRegExp        bool
	communityRegExp *regexp.Regexp
}

// create CommunityCondition object
// CommunityCondition supports uint and string like 65000:100
// and also supports regular expressions that are available in golang.
// if GoBGP can't parse the regular expression, it return nil and an error message is logged.
func NewCommunityCondition(communitySetName string, defAsPathSetList []config.CommunitySet) *CommunityCondition {

	// check format
	regUint, _ := regexp.Compile("^([0-9]+)$")
	regString, _ := regexp.Compile("([0-9]+):([0-9]+)")
	regWellKnown, _ := regexp.Compile("^(" +
		COMMUNITY_INTERNET + "|" +
		COMMUNITY_NO_EXPORT + "|" +
		COMMUNITY_NO_ADVERTISE + "|" +
		COMMUNITY_NO_EXPORT_SUBCONFED + ")$")

	communityList := make([]*CommunityElement, 0)
	for _, asPathSet := range defAsPathSetList {
		if asPathSet.CommunitySetName == communitySetName {
			for _, as := range asPathSet.CommunityMembers {

				e := &CommunityElement{
					isRegExp: false,
				}

				if regUint.MatchString(as) {
					// specified by Uint
					community, err := strconv.ParseUint(as, 10, 32)
					if err != nil {
						log.WithFields(log.Fields{
							"Topic": "Policy",
							"Type":  "Community Condition",
						}).Error("failed to parse the community value.")
						return nil
					}

					e.community = uint32(community)
					e.communityStr = as

				} else if regString.MatchString(as) {
					// specified by string containing ":"
					group := regString.FindStringSubmatch(as)
					asn, errAsn := strconv.ParseUint(group[1], 10, 16)
					val, errVal := strconv.ParseUint(group[2], 10, 16)

					if errAsn != nil || errVal != nil {
						log.WithFields(log.Fields{
							"Topic": "Policy",
							"Type":  "Community Condition",
						}).Error("failed to parser as number or community value.")
						return nil
					}
					e.community = uint32(asn<<16 | val)
					e.communityStr = as

				} else if regWellKnown.MatchString(as) {
					// specified by well known community name
					e.communityStr = as
					switch as {
					case COMMUNITY_INTERNET:
						e.community = COMMUNITY_INTERNET_VAL
					case COMMUNITY_NO_EXPORT:
						e.community = COMMUNITY_NO_EXPORT_VAL
					case COMMUNITY_NO_ADVERTISE:
						e.community = COMMUNITY_NO_ADVERTISE_VAL
					case COMMUNITY_NO_EXPORT_SUBCONFED:
						e.community = COMMUNITY_NO_EXPORT_SUBCONFED_VAL
					}

				} else {
					// specified by regular expression
					e.isRegExp = true
					e.communityStr = as
					reg, err := regexp.Compile(as)
					if err != nil {
						log.WithFields(log.Fields{
							"Topic": "Policy",
							"Type":  "Community Condition",
						}).Error("Regular expression can't be compiled.")
						return nil
					}
					e.communityRegExp = reg
				}
				communityList = append(communityList, e)
			}

			c := &CommunityCondition{
				CommunityList: communityList,
			}
			return c
		}
	}
	return nil
}

// compare community in the message's attribute with
// the one in the condition.
func (c *CommunityCondition) evaluate(path table.Path) bool {

	communities := path.GetCommunities()

	if len(communities) == 0 {
		return false
	}

	// create community string in advance.
	strCommunities := make([]string, len(communities))
	for i, c := range communities {
		upper := strconv.FormatUint(uint64(c&0xFFFF0000>>16), 10)
		lower := strconv.FormatUint(uint64(c&0x0000FFFF), 10)
		strCommunities[i] = upper + ":" + lower
	}

	matched := false
	idx := -1
	for _, member := range c.CommunityList {
		if member.isRegExp {
			for i, c := range strCommunities {
				if member.communityRegExp.MatchString(c) {
					matched = true
					idx = i
					break
				}
			}
		} else {
			for i, c := range communities {
				if c == member.community {
					matched = true
					idx = i
					break
				}
			}
		}

		if matched {
			log.Debugf("community matched : community=%s)", strCommunities[idx])
			return true
		}
	}
	return false
}

type Actions interface {
	apply(table.Path) table.Path
}

type DefaultActions struct {
}

func (a *DefaultActions) apply(path table.Path) table.Path {
	return path
}

type RoutingActions struct {
	DefaultActions
	AcceptRoute bool
}

func (r *RoutingActions) apply(path table.Path) table.Path {
	if r.AcceptRoute {
		return path
	} else {
		return nil
	}
}

type ModificationActions struct {
	DefaultActions
	AttrType bgp.BGPAttrType
	Value    string
}

type Prefix struct {
	Address         net.IP
	AddressFamily   bgp.RouteFamily
	Masklength      uint8
	MasklengthRange map[MaskLengthRangeType]uint8
}

func NewPrefix(addr net.IP, maskLen uint8, maskRange string) (Prefix, error) {
	mlr := make(map[MaskLengthRangeType]uint8)
	p := Prefix{
		Address:         addr,
		Masklength:      maskLen,
		MasklengthRange: make(map[MaskLengthRangeType]uint8),
	}

	if ipv4Family := addr.To4(); ipv4Family != nil {
		p.AddressFamily, _ = bgp.GetRouteFamily("ipv4-unicast")
	} else if ipv6Family := addr.To16(); ipv6Family != nil {
		p.AddressFamily, _ = bgp.GetRouteFamily("ipv6-unicast")
	} else {
		return p, fmt.Errorf("can not determine the address family.")
	}

	// TODO: validate mask length by using regexp

	idx := strings.Index(maskRange, "..")
	if idx == -1 {
		log.WithFields(log.Fields{
			"Topic":           "Policy",
			"Type":            "Prefix",
			"MaskRangeFormat": maskRange,
		}).Warn("mask length range format is invalid. mask range was skipped.")
		return p, nil
	}

	if idx != 0 {
		min, e := strconv.ParseUint(maskRange[:idx], 10, 8)
		if e != nil {
			return p, e
		}
		mlr[MASK_LENGTH_RANGE_MIN] = uint8(min)
	}
	if idx != len(maskRange)-1 {
		max, e := strconv.ParseUint(maskRange[idx+2:], 10, 8)
		if e != nil {
			return p, e
		}
		mlr[MASK_LENGTH_RANGE_MAX] = uint8(max)
	}
	p.MasklengthRange = mlr
	return p, nil
}

// Compare path with a policy's condition in stored order in the policy.
// If a condition match, then this function stops evaluation and
// subsequent conditions are skipped.
func (p *Policy) Apply(path table.Path) (bool, RouteType, table.Path) {
	for _, statement := range p.Statements {

		result := statement.evaluate(path)
		log.WithFields(log.Fields{
			"Topic":      "Policy",
			"Path":       path,
			"PolicyName": p.Name,
		}).Debug("statement.Conditions.evaluate : ", result)

		var p table.Path
		if result {
			p = statement.Actions.apply(path)
			if p != nil {
				return true, ROUTE_TYPE_ACCEPT, p
			} else {
				return true, ROUTE_TYPE_REJECT, nil
			}
		}
	}
	return false, ROUTE_TYPE_NONE, nil
}

func ipPrefixCalculate(path table.Path, cPrefix Prefix) bool {
	rf := path.GetRouteFamily()
	log.Debug("path routefamily : ", rf.String())
	var pAddr net.IP
	var pMasklen uint8

	if rf != cPrefix.AddressFamily {
		return false
	}

	switch rf {
	case bgp.RF_IPv4_UC:
		pAddr = path.GetNlri().(*bgp.NLRInfo).IPAddrPrefix.Prefix
		pMasklen = path.GetNlri().(*bgp.NLRInfo).IPAddrPrefix.Length
	case bgp.RF_IPv6_UC:
		pAddr = path.GetNlri().(*bgp.IPv6AddrPrefix).Prefix
		pMasklen = path.GetNlri().(*bgp.IPv6AddrPrefix).Length
	default:
		return false
	}

	cp := fmt.Sprintf("%s/%d", cPrefix.Address, cPrefix.Masklength)
	rMin, okMin := cPrefix.MasklengthRange[MASK_LENGTH_RANGE_MIN]
	rMax, okMax := cPrefix.MasklengthRange[MASK_LENGTH_RANGE_MAX]
	if !okMin && !okMax {
		if pAddr.Equal(cPrefix.Address) && pMasklen == cPrefix.Masklength {
			return true
		} else {
			return false
		}
	}

	_, ipNet, e := net.ParseCIDR(cp)
	if e != nil {
		log.WithFields(log.Fields{
			"Topic":  "Policy",
			"Prefix": ipNet,
			"Error":  e,
		}).Error("failed to parse the prefix of condition")
		return false
	}
	if ipNet.Contains(pAddr) && (rMin <= pMasklen && pMasklen <= rMax) {
		return true
	}
	return false
}

func (p *Policy) ToApiStruct() *api.PolicyDefinition {
	resStatements := make([]*api.Statement, 0)
	for _, st := range p.Statements {
		resPrefixSet := &api.PrefixSet{}
		resNeighborSet := &api.NeighborSet{}
		resAsPathLength := &api.AsPathLength{}
		for _, condition := range st.Conditions {
			switch reflect.TypeOf(condition) {
			case reflect.TypeOf(&PrefixCondition{}):
				prefixCondition := condition.(*PrefixCondition)
				resPrefixList := make([]*api.Prefix, 0)
				for _, prefix := range prefixCondition.PrefixList {

					resPrefix := &api.Prefix{
						Address:    prefix.Address.String(),
						MaskLength: uint32(prefix.Masklength),
					}
					if min, ok := prefix.MasklengthRange[MASK_LENGTH_RANGE_MIN]; ok {
						if max, ok := prefix.MasklengthRange[MASK_LENGTH_RANGE_MAX]; ok {
							resPrefix.MaskLengthRange = fmt.Sprintf("%d..%d", min, max)
						}
					}

					resPrefixList = append(resPrefixList, resPrefix)
				}
				resPrefixSet = &api.PrefixSet{
					PrefixSetName: prefixCondition.PrefixConditionName,
					PrefixList:    resPrefixList,
				}
			case reflect.TypeOf(&NeighborCondition{}):
				neighborCondition := condition.(*NeighborCondition)
				resNeighborList := make([]*api.Neighbor, 0)
				for _, neighbor := range neighborCondition.NeighborList {
					resNeighbor := &api.Neighbor{
						Address: neighbor.String(),
					}
					resNeighborList = append(resNeighborList, resNeighbor)
				}
				resNeighborSet = &api.NeighborSet{
					NeighborSetName: neighborCondition.NeighborConditionName,
					NeighborList:    resNeighborList,
				}
			case reflect.TypeOf(&AsPathLengthCondition{}):
				asPathLengthCondition := condition.(*AsPathLengthCondition)
				var op string
				switch asPathLengthCondition.Operator {
				case ATTRIBUTE_EQ:
					op = "eq"
				case ATTRIBUTE_GE:
					op = "ge"
				case ATTRIBUTE_LE:
					op = "le"
				}
				resAsPathLength = &api.AsPathLength{
					Value:    fmt.Sprintf("%d", asPathLengthCondition.Value),
					Operator: op,
				}
			}
		}
		resCondition := &api.Conditions{
			MatchPrefixSet:    resPrefixSet,
			MatchNeighborSet:  resNeighborSet,
			MatchAsPathLength: resAsPathLength,
			MatchSetOptions:   int64(st.MatchSetOptions),
		}
		resAction := &api.Actions{
			AcceptRoute: false,
			RejectRoute: true,
		}
		if st.Actions.(*RoutingActions).AcceptRoute {
			resAction.AcceptRoute = true
			resAction.RejectRoute = false
		}
		resStatement := &api.Statement{
			StatementNeme: st.Name,
			Conditions:    resCondition,
			Actions:       resAction,
		}
		resStatements = append(resStatements, resStatement)
	}

	return &api.PolicyDefinition{
		PolicyDefinitionName: p.Name,
		StatementList:        resStatements,
	}
}

// find index PrefixSet of request from PrefixSet of configuration file.
// Return the idxPrefixSet of the location where the name of PrefixSet matches,
// and idxPrefix of the location where element of PrefixSet matches
func IndexOfPrefixSet(conPrefixSetList []config.PrefixSet, reqPrefixSet config.PrefixSet) (int, int) {
	idxPrefixSet := -1
	idxPrefix := -1
	for i, conPrefixSet := range conPrefixSetList {
		if conPrefixSet.PrefixSetName == reqPrefixSet.PrefixSetName {
			idxPrefixSet = i
			if reqPrefixSet.PrefixList == nil {
				return idxPrefixSet, idxPrefix
			}
			for j, conPrefix := range conPrefixSet.PrefixList {
				if reflect.DeepEqual(conPrefix.Address, reqPrefixSet.PrefixList[0].Address) && conPrefix.Masklength == reqPrefixSet.PrefixList[0].Masklength &&
					conPrefix.MasklengthRange == reqPrefixSet.PrefixList[0].MasklengthRange {
					idxPrefix = j
					return idxPrefixSet, idxPrefix
				}
			}
		}
	}
	return idxPrefixSet, idxPrefix
}

// find index NeighborSet of request from NeighborSet of configuration file.
// Return the idxNeighborSet of the location where the name of NeighborSet matches,
// and idxNeighbor of the location where element of NeighborSet matches
func IndexOfNeighborSet(conNeighborSetList []config.NeighborSet, reqNeighborSet config.NeighborSet) (int, int) {
	idxNeighborSet := -1
	idxNeighbor := -1
	for i, conNeighborSet := range conNeighborSetList {
		if conNeighborSet.NeighborSetName == reqNeighborSet.NeighborSetName {
			idxNeighborSet = i
			if reqNeighborSet.NeighborInfoList == nil {
				return idxNeighborSet, idxNeighbor
			}
			for j, conNeighbor := range conNeighborSet.NeighborInfoList {
				if reflect.DeepEqual(conNeighbor.Address, reqNeighborSet.NeighborInfoList[0].Address) {
					idxNeighbor = j
					return idxNeighborSet, idxNeighbor
				}
			}
		}
	}
	return idxNeighborSet, idxNeighbor
}

func PrefixSetToApiStruct(ps config.PrefixSet) *api.PrefixSet {
	resPrefixList := make([]*api.Prefix, 0)
	for _, p := range ps.PrefixList {
		resPrefix := &api.Prefix{
			Address:         p.Address.String(),
			MaskLength:      uint32(p.Masklength),
			MaskLengthRange: p.MasklengthRange,
		}
		resPrefixList = append(resPrefixList, resPrefix)
	}
	resPrefixSet := &api.PrefixSet{
		PrefixSetName: ps.PrefixSetName,
		PrefixList:    resPrefixList,
	}
	return resPrefixSet
}

func PrefixSetToConfigStruct(reqPrefixSet *api.PrefixSet) (bool, config.PrefixSet) {
	var prefix config.Prefix
	var prefixSet config.PrefixSet
	isReqPrefixSet := true
	if reqPrefixSet.PrefixList != nil {
		prefix = config.Prefix{
			Address:         net.ParseIP(reqPrefixSet.PrefixList[0].Address),
			Masklength:      uint8(reqPrefixSet.PrefixList[0].MaskLength),
			MasklengthRange: reqPrefixSet.PrefixList[0].MaskLengthRange,
		}
		prefixList := []config.Prefix{prefix}

		prefixSet = config.PrefixSet{
			PrefixSetName: reqPrefixSet.PrefixSetName,
			PrefixList:    prefixList,
		}
	} else {
		isReqPrefixSet = false
		prefixSet = config.PrefixSet{
			PrefixSetName: reqPrefixSet.PrefixSetName,
			PrefixList:    nil,
		}
	}
	return isReqPrefixSet, prefixSet
}

func NeighborSetToApiStruct(ns config.NeighborSet) *api.NeighborSet {
	resNeighborList := make([]*api.Neighbor, 0)
	for _, n := range ns.NeighborInfoList {
		resNeighbor := &api.Neighbor{
			Address: n.Address.String(),
		}
		resNeighborList = append(resNeighborList, resNeighbor)
	}
	resNeighborSet := &api.NeighborSet{
		NeighborSetName: ns.NeighborSetName,
		NeighborList:    resNeighborList,
	}
	return resNeighborSet
}

func NeighborSetToConfigStruct(reqNeighborSet *api.NeighborSet) (bool, config.NeighborSet) {
	var neighbor config.NeighborInfo
	var neighborSet config.NeighborSet
	isReqNeighborSet := true
	if reqNeighborSet.NeighborList != nil {
		neighbor = config.NeighborInfo{
			Address: net.ParseIP(reqNeighborSet.NeighborList[0].Address),
		}
		neighborList := []config.NeighborInfo{neighbor}

		neighborSet = config.NeighborSet{
			NeighborSetName:  reqNeighborSet.NeighborSetName,
			NeighborInfoList: neighborList,
		}
	} else {
		isReqNeighborSet = false
		neighborSet = config.NeighborSet{
			NeighborSetName:  reqNeighborSet.NeighborSetName,
			NeighborInfoList: nil,
		}
	}
	return isReqNeighborSet, neighborSet
}

func AsPathLengthToApiStruct(asPathLength config.AsPathLength) *api.AsPathLength {
	value := ""
	if asPathLength.Operator != "" {
		value = fmt.Sprintf("%d", asPathLength.Value)
	}
	resAsPathLength := &api.AsPathLength{
		Value:    value,
		Operator: asPathLength.Operator,
	}
	return resAsPathLength
}

func PolicyDefinitionToApiStruct(pd config.PolicyDefinition, df config.DefinedSets) *api.PolicyDefinition {
	conPrefixSetList := df.PrefixSetList
	conNeighborSetList := df.NeighborSetList
	resStatementList := make([]*api.Statement, 0)
	for _, st := range pd.StatementList {
		conditions := st.Conditions
		actions := st.Actions

		prefixSet := &api.PrefixSet{
			PrefixSetName: conditions.MatchPrefixSet,
		}
		neighborSet := &api.NeighborSet{
			NeighborSetName: conditions.MatchNeighborSet,
		}
		_, conPrefixSet := PrefixSetToConfigStruct(prefixSet)
		_, conNeighborSet := NeighborSetToConfigStruct(neighborSet)
		idxPrefixSet, _ := IndexOfPrefixSet(conPrefixSetList, conPrefixSet)
		idxNeighborSet, _ := IndexOfNeighborSet(conNeighborSetList, conNeighborSet)

		if idxPrefixSet != -1 {
			prefixSet = PrefixSetToApiStruct(conPrefixSetList[idxPrefixSet])
		}
		if idxNeighborSet != -1 {
			neighborSet = NeighborSetToApiStruct(conNeighborSetList[idxNeighborSet])
		}
		asPathLength := AsPathLengthToApiStruct(st.Conditions.BgpConditions.AsPathLength)

		resConditions := &api.Conditions{
			MatchPrefixSet:    prefixSet,
			MatchNeighborSet:  neighborSet,
			MatchAsPathLength: asPathLength,
			MatchSetOptions:   int64(conditions.MatchSetOptions),
		}
		resActions := &api.Actions{
			AcceptRoute: actions.AcceptRoute,
			RejectRoute: actions.RejectRoute,
		}
		resStatement := &api.Statement{
			StatementNeme: st.Name,
			Conditions:    resConditions,
			Actions:       resActions,
		}
		resStatementList = append(resStatementList, resStatement)
	}
	resPolicyDefinition := &api.PolicyDefinition{
		PolicyDefinitionName: pd.Name,
		StatementList:        resStatementList,
	}
	return resPolicyDefinition
}
