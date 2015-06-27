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
	"reflect"
	"regexp"
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

		// routeing action
		ra := NewRoutingAction(statement.Actions)

		// Community action
		mda := make([]Action, 0)
		com := NewCommunityAction(statement.Actions.BgpActions.SetCommunity)
		if com != nil {
			mda = append(mda, com)
		}

		// Med Action
		med := NewMedAction(statement.Actions.BgpActions.SetMed)
		if med != nil {
			mda = append(mda, med)
		}

		s := &Statement{
			Name:                statement.Name,
			Conditions:          conditions,
			routingAction:       ra,
			modificationActions: mda,
			MatchSetOptions:     statement.Conditions.MatchSetOptions,
		}

		st = append(st, s)
	}
	p.Statements = st
	return p
}

type Statement struct {
	Name                string
	Conditions          []Condition
	routingAction       *RoutingAction
	modificationActions []Action
	MatchSetOptions     config.MatchSetOptionsType
}

// evaluate each condition in the statement according to MatchSetOptions
func (s *Statement) evaluate(p *table.Path) bool {

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
	evaluate(*table.Path) bool
}

type DefaultCondition struct {
	CallPolicy string
}

func (c *DefaultCondition) evaluate(path *table.Path) bool {
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
func (c *PrefixCondition) evaluate(path *table.Path) bool {

	if len(c.PrefixList) == 0 {
		log.Debug("PrefixList doesn't have elements")
		return true
	}

	for _, cp := range c.PrefixList {
		if ipPrefixCalculate(path, cp) {
			log.WithFields(log.Fields{
				"Topic":  "Policy",
				"Prefix": cp.Address.String(),
			}).Debug("prefix matched")

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
func (c *NeighborCondition) evaluate(path *table.Path) bool {

	if len(c.NeighborList) == 0 {
		log.Debug("NeighborList doesn't have elements")
		return true
	}

	for _, neighbor := range c.NeighborList {
		cAddr := neighbor
		pAddr := path.GetSource().Address
		if pAddr.Equal(cAddr) {
			log.WithFields(log.Fields{
				"Topic":           "Policy",
				"NeighborAddress": pAddr.String(),
			}).Debug("neighbor matched")
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
func (c *AsPathLengthCondition) evaluate(path *table.Path) bool {

	length := uint32(path.GetAsPathLen())
	result := false

	switch c.Operator {
	case ATTRIBUTE_EQ:
		result = c.Value == length

	case ATTRIBUTE_GE:
		result = c.Value <= length

	case ATTRIBUTE_LE:
		result = c.Value >= length
	default:
		return false
	}

	if result {
		log.WithFields(log.Fields{
			"Topic":     "Policy",
			"Condition": "aspath length",
			"Reason":    c.Operator,
		}).Debug("condition matched")
	}

	return result
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
func (c *AsPathCondition) evaluate(path *table.Path) bool {

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
			log.WithFields(log.Fields{
				"Topic":     "Policy",
				"Condition": "aspath length",
				"ASN":       member.asn,
				"Position":  member.postiion,
			}).Debug("condition matched")
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
func NewCommunityCondition(communitySetName string, defCommunitySetList []config.CommunitySet) *CommunityCondition {

	communityList := make([]*CommunityElement, 0)
	for _, communitySet := range defCommunitySetList {
		if communitySet.CommunitySetName == communitySetName {
			for _, c := range communitySet.CommunityMembers {

				e := &CommunityElement{
					isRegExp:     false,
					communityStr: c,
				}

				if matched, v := getCommunityValue(c); matched {
					e.community = v
				} else {
					// specified by regular expression
					e.isRegExp = true
					reg, err := regexp.Compile(c)
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

// getCommunityValue returns uint32 community value converted from the string.
// if the string doesn't match a number or string like "65000:1000" or well known
// community name, it returns false and 0, otherwise returns true and its uint32 value.
func getCommunityValue(comStr string) (bool, uint32) {
	// community regexp
	regUint, _ := regexp.Compile("^([0-9]+)$")
	regString, _ := regexp.Compile("([0-9]+):([0-9]+)")
	regWellKnown, _ := regexp.Compile("^(" +
		COMMUNITY_INTERNET + "|" +
		COMMUNITY_NO_EXPORT + "|" +
		COMMUNITY_NO_ADVERTISE + "|" +
		COMMUNITY_NO_EXPORT_SUBCONFED + ")$")

	if regUint.MatchString(comStr) {
		// specified by Uint
		community, err := strconv.ParseUint(comStr, 10, 32)
		if err != nil {
			log.WithFields(log.Fields{
				"Topic": "Policy",
				"Type":  "Community Condition",
			}).Error("failed to parse the community value.")
		}
		return true, uint32(community)

	} else if regString.MatchString(comStr) {
		// specified by string containing ":"
		group := regString.FindStringSubmatch(comStr)
		asn, errAsn := strconv.ParseUint(group[1], 10, 16)
		val, errVal := strconv.ParseUint(group[2], 10, 16)

		if errAsn != nil || errVal != nil {
			log.WithFields(log.Fields{
				"Topic": "Policy",
				"Type":  "Community Condition",
			}).Error("failed to parser as number or community value.")
		}
		community := uint32(asn<<16 | val)
		return true, community

	} else if regWellKnown.MatchString(comStr) {
		// specified by well known community name
		var community uint32
		switch comStr {
		case COMMUNITY_INTERNET:
			community = COMMUNITY_INTERNET_VAL
		case COMMUNITY_NO_EXPORT:
			community = COMMUNITY_NO_EXPORT_VAL
		case COMMUNITY_NO_ADVERTISE:
			community = COMMUNITY_NO_ADVERTISE_VAL
		case COMMUNITY_NO_EXPORT_SUBCONFED:
			community = COMMUNITY_NO_EXPORT_SUBCONFED_VAL
		}
		return true, community
	}
	return false, 0
}

// compare community in the message's attribute with
// the one in the condition.
func (c *CommunityCondition) evaluate(path *table.Path) bool {

	communities := path.GetCommunities()

	if len(communities) == 0 {
		return false
	}

	makeStr := func(c uint32) string {
		upper := strconv.FormatUint(uint64(c&0xFFFF0000>>16), 10)
		lower := strconv.FormatUint(uint64(c&0x0000FFFF), 10)
		return upper + ":" + lower
	}

	var strCommunities []string = nil
	matched := false
	idx := -1
	for _, member := range c.CommunityList {
		if member.isRegExp {

			if strCommunities == nil {
				// create community string.
				strCommunities = make([]string, len(communities))
				for i, c := range communities {
					strCommunities[i] = makeStr(c)
				}
			}

			for i, c := range strCommunities {
				if member.communityRegExp.MatchString(c) {
					matched = true
					idx = i
					log.WithFields(log.Fields{
						"Topic":  "Policy",
						"RegExp": member.communityRegExp.String(),
					}).Debug("community regexp used")
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
			log.WithFields(log.Fields{
				"Topic":     "Policy",
				"Condition": "Community",
				"Community": makeStr(communities[idx]),
			}).Debug("condition matched")

			return true
		}
	}
	return false
}

type Action interface {
	apply(*table.Path) *table.Path
}

type DefaultAction struct {
}

func (a *DefaultAction) apply(path *table.Path) *table.Path {
	return path
}

type RoutingAction struct {
	DefaultAction
	AcceptRoute bool
}

func NewRoutingAction(action config.Actions) *RoutingAction {
	r := &RoutingAction{
		AcceptRoute: action.AcceptRoute,
	}
	return r
}

func (r *RoutingAction) apply(path *table.Path) *table.Path {
	if r.AcceptRoute {
		return path
	} else {
		return nil
	}
}

type ActionType int

type CommunityAction struct {
	DefaultAction
	Values []uint32
	action ActionType
}

const (
	COMMUNITY_ACTION_ADD     string = "ADD"
	COMMUNITY_ACTION_REPLACE        = "REPLACE"
	COMMUNITY_ACTION_REMOVE         = "REMOVE"
	COMMUNITY_ACTION_NULL           = "NULL"
)

// NewCommunityAction creates CommunityAction object.
// If it cannot parse community string, then return nil.
// Similarly, if option string is invalid, return nil.
func NewCommunityAction(action config.SetCommunity) *CommunityAction {

	m := &CommunityAction{}

	if len(action.Communities) == 0 && action.Options != COMMUNITY_ACTION_NULL {
		return nil
	}

	values := make([]uint32, len(action.Communities))
	for i, com := range action.Communities {
		matched, value := getCommunityValue(com)
		if matched {
			values[i] = value
		} else {
			log.WithFields(log.Fields{
				"Topic": "Policy",
				"Type":  "Community Action",
			}).Error("community string invalid.")
			return nil
		}
	}
	m.Values = values

	switch action.Options {
	case COMMUNITY_ACTION_ADD:
		m.action = config.BGP_SET_COMMUNITY_OPTION_TYPE_ADD
	case COMMUNITY_ACTION_REMOVE:
		m.action = config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE
	case COMMUNITY_ACTION_REPLACE:
		m.action = config.BGP_SET_COMMUNITY_OPTION_TYPE_REPLACE
	case COMMUNITY_ACTION_NULL:
		m.action = config.BGP_SET_COMMUNITY_OPTION_TYPE_NULL
	default:
		log.WithFields(log.Fields{
			"Topic": "Policy",
			"Type":  "Community Action",
		}).Error("action string should be ADD or REMOVE or REPLACE or NULL.")
		return nil
	}
	return m
}

func (a *CommunityAction) apply(path *table.Path) *table.Path {

	list := a.Values
	switch a.action {
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_ADD:
		path.SetCommunities(list, false)
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE:
		path.RemoveCommunities(list)
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_REPLACE:
		path.SetCommunities(list, true)
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_NULL:
		path.ClearCommunities()
	}
	return path
}

type MedAction struct {
	DefaultAction
	Value  int64
	action ActionType
}

const (
	MED_ACTION_NONE ActionType = iota
	MED_ACTION_REPLACE
	MED_ACTION_ADD
	MED_ACTION_SUB
)

// NewMedAction creates MedAction object.
// If it cannot parse med string, then return nil.
func NewMedAction(med config.BgpSetMedType) *MedAction {

	if med == "" {
		return nil
	}

	m := &MedAction{}

	matched, value, action := getMedValue(fmt.Sprintf("%s", med))
	if !matched {
		log.WithFields(log.Fields{
			"Topic": "Policy",
			"Type":  "Med Action",
		}).Error("med string invalid.")
		return nil
	}
	m.Value = value
	m.action = action
	return m
}

// getMedValue returns uint32 med value and action type (+ or -).
// if the string doesn't match a number or operator,
// it returns false and 0.
func getMedValue(medStr string) (bool, int64, ActionType) {
	regMed, _ := regexp.Compile("^(\\+|\\-)?([0-9]+)$")
	if regMed.MatchString(medStr) {
		group := regMed.FindStringSubmatch(medStr)
		action := MED_ACTION_REPLACE
		if group[1] == "+" {
			action = MED_ACTION_ADD
		} else if group[1] == "-" {
			action = MED_ACTION_SUB
		}
		val, err := strconv.ParseInt(medStr, 10, 64)
		if err != nil {
			log.WithFields(log.Fields{
				"Topic": "Policy",
				"Type":  "Med Action",
			}).Error("failed to parser as number or med value.")
		}
		return true, int64(val), action
	}
	return false, int64(0), MED_ACTION_NONE
}
func (a *MedAction) apply(path *table.Path) *table.Path {

	var err error
	switch a.action {
	case MED_ACTION_REPLACE:
		err = path.SetMed(a.Value, true)
	case MED_ACTION_ADD:
		err = path.SetMed(a.Value, false)
	case MED_ACTION_SUB:
		err = path.SetMed(a.Value, false)
	}
	if err != nil {
		log.WithFields(log.Fields{
			"Topic": "Policy",
			"Type":  "Med Action",
		}).Warn(err)
	}

	return path
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
func (p *Policy) Apply(path *table.Path) (bool, RouteType, *table.Path) {
	for _, statement := range p.Statements {

		result := statement.evaluate(path)
		log.WithFields(log.Fields{
			"Topic":      "Policy",
			"Path":       path,
			"PolicyName": p.Name,
		}).Debug("statement.Conditions.evaluate : ", result)

		var p *table.Path
		if result {
			//Routing action
			p = statement.routingAction.apply(path)
			if p != nil {
				// apply all modification actions
				cloned := path.Clone(p.IsWithdraw)
				for _, action := range statement.modificationActions {
					cloned = action.apply(cloned)
				}
				return true, ROUTE_TYPE_ACCEPT, cloned
			} else {
				return true, ROUTE_TYPE_REJECT, nil
			}
		}
	}
	return false, ROUTE_TYPE_NONE, nil
}

func ipPrefixCalculate(path *table.Path, cPrefix Prefix) bool {
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

const (
	ROUTE_ACCEPT string = "ACCEPT"
	ROUTE_REJECT        = "REJECT"
)

const (
	OPTIONS_ALL    string = "ALL"
	OPTIONS_ANY           = "ANY"
	OPTIONS_INVERT        = "INVERT"
)

func MatchSetOptionToString(option config.MatchSetOptionsType) string {
	var op string
	switch option {
	case config.MATCH_SET_OPTIONS_TYPE_ALL:
		op = OPTIONS_ALL
	case config.MATCH_SET_OPTIONS_TYPE_ANY:
		op = OPTIONS_ANY
	case config.MATCH_SET_OPTIONS_TYPE_INVERT:
		op = OPTIONS_INVERT
	}
	return op
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

// find index AsPathSet of request from AsPathSet of configuration file.
// Return the idxAsPathSet of the location where the name of AsPathSet matches,
// and idxAsPath of the location where element of AsPathSet matches
func IndexOfAsPathSet(conAsPathSetList []config.AsPathSet, reqAsPathSet config.AsPathSet) (int, int) {
	idxAsPathSet := -1
	idxAsPath := -1
	for i, conAsPathSet := range conAsPathSetList {
		if conAsPathSet.AsPathSetName == reqAsPathSet.AsPathSetName {
			idxAsPathSet = i
			if len(reqAsPathSet.AsPathSetMembers) == 0 {
				return idxAsPathSet, idxAsPath
			}
			for j, conAsPath := range conAsPathSet.AsPathSetMembers {
				if conAsPath == reqAsPathSet.AsPathSetMembers[0] {
					idxAsPath = j
					return idxAsPathSet, idxAsPath
				}
			}
		}
	}
	return idxAsPathSet, idxAsPath
}

// find index CommunitySet of request from CommunitySet of configuration file.
// Return the idxCommunitySet of the location where the name of CommunitySet matches,
// and idxCommunity of the location where element of CommunitySet matches
func IndexOfCommunitySet(conCommunitySetList []config.CommunitySet, reqCommunitySet config.CommunitySet) (int, int) {
	idxCommunitySet := -1
	idxCommunity := -1
	for i, conCommunitySet := range conCommunitySetList {
		if conCommunitySet.CommunitySetName == reqCommunitySet.CommunitySetName {
			idxCommunitySet = i
			if len(reqCommunitySet.CommunityMembers) == 0 {
				return idxCommunitySet, idxCommunity
			}
			for j, conCommunity := range conCommunitySet.CommunityMembers {
				if conCommunity == reqCommunitySet.CommunityMembers[0] {
					idxCommunity = j
					return idxCommunitySet, idxCommunity
				}
			}
		}
	}
	return idxCommunitySet, idxCommunity
}

// find index PolicyDefinition of request from PolicyDefinition of configuration file.
// Return the idxPolicyDefinition of the location where the name of PolicyDefinition matches,
// and idxStatement of the location where Statement of PolicyDefinition matches
func IndexOfPolicyDefinition(conPolicyList []config.PolicyDefinition, reqPolicy config.PolicyDefinition) (int, int) {
	idxPolicyDefinition := -1
	idxStatement := -1
	for i, conPolicy := range conPolicyList {
		if conPolicy.Name == reqPolicy.Name {
			idxPolicyDefinition = i
			if reqPolicy.StatementList == nil {
				return idxPolicyDefinition, idxStatement
			}
			for j, conStatement := range conPolicy.StatementList {
				if conStatement.Name == reqPolicy.StatementList[0].Name {
					idxStatement = j
					return idxPolicyDefinition, idxStatement
				}
			}
		}
	}
	return idxPolicyDefinition, idxStatement
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

func AsPathSetToApiStruct(as config.AsPathSet) *api.AsPathSet {
	resAsPathMembers := make([]string, 0)
	for _, m := range as.AsPathSetMembers {
		resAsPathMembers = append(resAsPathMembers, m)
	}
	resAsPathSet := &api.AsPathSet{
		AsPathSetName: as.AsPathSetName,
		AsPathMembers: resAsPathMembers,
	}
	return resAsPathSet
}

func AsPathSetToConfigStruct(reqAsPathSet *api.AsPathSet) (bool, config.AsPathSet) {
	isAsPathSetSet := true
	if len(reqAsPathSet.AsPathMembers) == 0 {
		isAsPathSetSet = false
	}
	asPathSet := config.AsPathSet{
		AsPathSetName:    reqAsPathSet.AsPathSetName,
		AsPathSetMembers: reqAsPathSet.AsPathMembers,
	}
	return isAsPathSetSet, asPathSet
}

func CommunitySetToApiStruct(cs config.CommunitySet) *api.CommunitySet {
	resCommunityMembers := make([]string, 0)
	for _, m := range cs.CommunityMembers {
		resCommunityMembers = append(resCommunityMembers, m)
	}
	resCommunitySet := &api.CommunitySet{
		CommunitySetName: cs.CommunitySetName,
		CommunityMembers: resCommunityMembers,
	}
	return resCommunitySet
}

func CommunitySetToConfigStruct(reqCommunitySet *api.CommunitySet) (bool, config.CommunitySet) {
	isCommunitySet := true
	if len(reqCommunitySet.CommunityMembers) == 0 {
		isCommunitySet = false
	}
	communitySet := config.CommunitySet{
		CommunitySetName: reqCommunitySet.CommunitySetName,
		CommunityMembers: reqCommunitySet.CommunityMembers,
	}
	return isCommunitySet, communitySet
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

func AsPathLengthToConfigStruct(reqAsPathLength *api.AsPathLength) config.AsPathLength {
	operator := reqAsPathLength.Operator
	value := reqAsPathLength.Value
	valueUint, _ := strconv.ParseUint(value, 10, 32)
	asPathLength := config.AsPathLength{
		Operator: operator,
		Value:    uint32(valueUint),
	}
	return asPathLength
}

func ConditionsToConfigStruct(reqConditions *api.Conditions) config.Conditions {
	conditions := config.Conditions{}
	if reqConditions.MatchPrefixSet != nil {
		conditions.MatchPrefixSet = reqConditions.MatchPrefixSet.PrefixSetName
	}
	if reqConditions.MatchNeighborSet != nil {
		conditions.MatchNeighborSet = reqConditions.MatchNeighborSet.NeighborSetName
	}
	if reqConditions.MatchAsPathSet != nil {
		conditions.BgpConditions.MatchAsPathSet = reqConditions.MatchAsPathSet.AsPathSetName
	}
	if reqConditions.MatchCommunitySet != nil {
		conditions.BgpConditions.MatchCommunitySet = reqConditions.MatchCommunitySet.CommunitySetName
	}
	if reqConditions.MatchAsPathLength != nil {
		conditions.BgpConditions.AsPathLength =
			AsPathLengthToConfigStruct(reqConditions.MatchAsPathLength)
	}
	var setOption config.MatchSetOptionsType
	switch reqConditions.MatchSetOptions {
	case OPTIONS_ALL:
		setOption = config.MATCH_SET_OPTIONS_TYPE_ALL
	case OPTIONS_ANY:
		setOption = config.MATCH_SET_OPTIONS_TYPE_ANY
	case OPTIONS_INVERT:
		setOption = config.MATCH_SET_OPTIONS_TYPE_INVERT
	}
	conditions.MatchSetOptions = setOption
	return conditions
}

func ActionsToApiStruct(conActions config.Actions) *api.Actions {
	action := ROUTE_REJECT
	if conActions.AcceptRoute {
		action = ROUTE_ACCEPT
	}
	communityAction := &api.CommunityAction{
		Communities: conActions.BgpActions.SetCommunity.Communities,
		Options:     conActions.BgpActions.SetCommunity.Options,
	}
	resActions := &api.Actions{
		RouteAction: action,
		Community:   communityAction,
	}
	return resActions
}

func ActionsToConfigStruct(reqActions *api.Actions) config.Actions {
	actions := config.Actions{}
	if reqActions.Community != nil {
		actions.BgpActions.SetCommunity.Communities = reqActions.Community.Communities
		actions.BgpActions.SetCommunity.Options = reqActions.Community.Options
	}
	switch reqActions.RouteAction {
	case ROUTE_ACCEPT:
		actions.AcceptRoute = true
	case ROUTE_REJECT:
		actions.RejectRoute = true
	}
	return actions
}

func StatementToConfigStruct(reqStatement *api.Statement) config.Statement {
	statement := config.Statement{
		Name:       reqStatement.StatementNeme,
		Conditions: ConditionsToConfigStruct(reqStatement.Conditions),
		Actions:    ActionsToConfigStruct(reqStatement.Actions),
	}
	return statement
}

func PolicyDefinitionToConfigStruct(reqPolicy *api.PolicyDefinition) (bool, config.PolicyDefinition) {
	isReqStatement := true
	policy := config.PolicyDefinition{
		Name: reqPolicy.PolicyDefinitionName,
	}
	if reqPolicy.StatementList != nil {
		statement := StatementToConfigStruct(reqPolicy.StatementList[0])
		policy.StatementList = []config.Statement{statement}
	} else {
		isReqStatement = false
	}
	return isReqStatement, policy
}

func PolicyDefinitionToApiStruct(pd config.PolicyDefinition, df config.DefinedSets) *api.PolicyDefinition {
	conPrefixSetList := df.PrefixSetList
	conNeighborSetList := df.NeighborSetList
	conAsPathSetList := df.BgpDefinedSets.AsPathSetList
	conCommunitySetList := df.BgpDefinedSets.CommunitySetList
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
		asPathSet := &api.AsPathSet{
			AsPathSetName: conditions.BgpConditions.MatchAsPathSet,
		}
		communitySet := &api.CommunitySet{
			CommunitySetName: conditions.BgpConditions.MatchCommunitySet,
		}
		// consider later whether treatment of here need
		_, conPrefixSet := PrefixSetToConfigStruct(prefixSet)
		_, conNeighborSet := NeighborSetToConfigStruct(neighborSet)
		_, conAsPathSet := AsPathSetToConfigStruct(asPathSet)
		_, conCommunitySet := CommunitySetToConfigStruct(communitySet)
		idxPrefixSet, _ := IndexOfPrefixSet(conPrefixSetList, conPrefixSet)
		idxNeighborSet, _ := IndexOfNeighborSet(conNeighborSetList, conNeighborSet)
		idxAsPathSet, _ := IndexOfAsPathSet(conAsPathSetList, conAsPathSet)
		idxCommunitySet, _ := IndexOfCommunitySet(conCommunitySetList, conCommunitySet)
		if idxPrefixSet != -1 {
			prefixSet = PrefixSetToApiStruct(conPrefixSetList[idxPrefixSet])
		}
		if idxNeighborSet != -1 {
			neighborSet = NeighborSetToApiStruct(conNeighborSetList[idxNeighborSet])
		}
		if idxAsPathSet != -1 {
			asPathSet = AsPathSetToApiStruct(conAsPathSetList[idxAsPathSet])
		}
		if idxCommunitySet != -1 {
			communitySet = CommunitySetToApiStruct(conCommunitySetList[idxCommunitySet])
		}
		resConditions := &api.Conditions{
			MatchPrefixSet:    prefixSet,
			MatchNeighborSet:  neighborSet,
			MatchAsPathSet:    asPathSet,
			MatchCommunitySet: communitySet,
			MatchAsPathLength: AsPathLengthToApiStruct(st.Conditions.BgpConditions.AsPathLength),
			MatchSetOptions:   MatchSetOptionToString(conditions.MatchSetOptions),
		}
		resActions := ActionsToApiStruct(actions)
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

func PoliciesToString(reqPolicies []*api.PolicyDefinition) []string {
	policies := make([]string, 0)
	for _, reqPolicy := range reqPolicies {
		policies = append(policies, reqPolicy.PolicyDefinitionName)
	}
	return policies
}
