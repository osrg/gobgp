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
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/table"
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
	stmtList := pd.Statements.StatementList
	st := make([]*Statement, 0)
	p := &Policy{
		Name: pd.Name,
	}

	for _, statement := range stmtList {

		conditions := make([]Condition, 0)

		// prefix match
		pc := NewPrefixCondition(statement.Conditions.MatchPrefixSet, ds.PrefixSets.PrefixSetList)
		if pc != nil {
			conditions = append(conditions, pc)
		}

		// neighbor match
		nc := NewNeighborCondition(statement.Conditions.MatchNeighborSet, ds.NeighborSets.NeighborSetList)
		if nc != nil {
			conditions = append(conditions, nc)
		}

		// AsPathLengthCondition
		c := statement.Conditions.BgpConditions.AsPathLength
		ac := NewAsPathLengthCondition(c)
		if ac != nil {
			conditions = append(conditions, ac)
		}

		bgpDefset := &ds.BgpDefinedSets
		bgpConditions := &statement.Conditions.BgpConditions
		// AsPathCondition
		asc := NewAsPathCondition(bgpConditions.MatchAsPathSet, bgpDefset.AsPathSets.AsPathSetList)
		if asc != nil {
			conditions = append(conditions, asc)
		}

		// CommunityCondition
		cc := NewCommunityCondition(bgpConditions.MatchCommunitySet, bgpDefset.CommunitySets.CommunitySetList)
		if cc != nil {
			conditions = append(conditions, cc)
		}

		// ExtendedCommunityCondition
		ecc := NewExtCommunityCondition(bgpConditions.MatchExtCommunitySet, bgpDefset.ExtCommunitySets.ExtCommunitySetList)
		if ecc != nil {
			conditions = append(conditions, ecc)
		}

		// routing action
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

		//AsPathPrependAction
		ppa := NewAsPathPrependAction(statement.Actions.BgpActions.SetAsPathPrepend)
		if ppa != nil {
			mda = append(mda, ppa)
		}

		s := &Statement{
			Name:                statement.Name,
			Conditions:          conditions,
			routingAction:       ra,
			modificationActions: mda,
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
}

// evaluate each condition in the statement according to MatchSetOptions
func (s *Statement) evaluate(p *table.Path) bool {

	for _, condition := range s.Conditions {
		r := condition.evaluate(p)
		if !r {
			return false
		}
	}
	return true
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
	MatchOption         config.MatchSetOptionsRestrictedType
}

func NewPrefixCondition(matchPref config.MatchPrefixSet, defPrefixList []config.PrefixSet) *PrefixCondition {

	prefixSetName := matchPref.PrefixSet
	options := matchPref.MatchSetOptions

	prefixList := make([]Prefix, 0)
	for _, ps := range defPrefixList {
		if ps.PrefixSetName == prefixSetName {
			for _, prefix := range ps.PrefixList {
				prefix, e := NewPrefix(prefix.IpPrefix, prefix.MasklengthRange)
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

	if len(prefixList) == 0 {
		return nil
	}

	pc := &PrefixCondition{
		PrefixConditionName: prefixSetName,
		PrefixList:          prefixList,
		MatchOption:         options,
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

	result := false
	for _, cp := range c.PrefixList {
		if ipPrefixCalculate(path, cp) {
			result = true
			break
		}
	}
	if c.MatchOption == config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_INVERT {
		result = !result
	}

	log.WithFields(log.Fields{
		"Topic":     "Policy",
		"Condition": "prefix",
		"Path":      path,
		"Matched":   result,
	}).Debug("evaluate prefix")

	return result
}

type NeighborCondition struct {
	DefaultCondition
	NeighborConditionName string
	NeighborList          []net.IP
	MatchOption           config.MatchSetOptionsRestrictedType
}

func NewNeighborCondition(matchNeighborSet config.MatchNeighborSet, defNeighborSetList []config.NeighborSet) *NeighborCondition {

	neighborSetName := matchNeighborSet.NeighborSet
	options := matchNeighborSet.MatchSetOptions

	neighborList := make([]net.IP, 0)
	for _, neighborSet := range defNeighborSetList {
		if neighborSet.NeighborSetName == neighborSetName {
			for _, nl := range neighborSet.NeighborInfoList {
				neighborList = append(neighborList, nl.Address)
			}
		}
	}

	if len(neighborList) == 0 {
		return nil
	}

	nc := &NeighborCondition{
		NeighborConditionName: neighborSetName,
		NeighborList:          neighborList,
		MatchOption:           options,
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

	sAddr := path.GetSource().Address
	result := false
	for _, neighbor := range c.NeighborList {
		if sAddr.Equal(neighbor) {
			result = true
			break
		}
	}

	if c.MatchOption == config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_INVERT {
		result = !result
	}

	log.WithFields(log.Fields{
		"Topic":           "Policy",
		"Condition":       "neighbor",
		"NeighborAddress": sAddr.String(),
		"Matched":         result,
	}).Debug("evaluate neighbor")

	return result
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
		result = false
	}

	log.WithFields(log.Fields{
		"Topic":     "Policy",
		"Condition": "aspath length",
		"Reason":    c.Operator,
		"Matched":   result,
	}).Debug("evaluate aspath length")

	return result
}

type AsPathCondition struct {
	DefaultCondition
	AsPathList  []*AsPathElement
	MatchOption config.MatchSetOptionsType
}

type AsnPos int

const (
	AS_FROM AsnPos = iota
	AS_ANY
	AS_ORIGIN
	AS_ONLY
)

type AsPathElement struct {
	postiion  AsnPos
	asStr     string
	asRegExps []*regexp.Regexp
}

// create AsPathCondition object
// AsPathCondition supports only following regexp:
// - ^100  (from as100)
// - ^100$ (from as100 and originated by as100)
// - 100$  (originated by as100)
// - 100   (from or through or originated by as100)
func NewAsPathCondition(matchSet config.MatchAsPathSet, defAsPathSetList []config.AsPathSet) *AsPathCondition {

	asPathSetName := matchSet.AsPathSet
	options := matchSet.MatchSetOptions

	asPathList := make([]*AsPathElement, 0)
	for _, asPathSet := range defAsPathSetList {
		if asPathSet.AsPathSetName == asPathSetName {
			for _, aspath := range asPathSet.AsPathList {
				a := aspath.AsPath
				if len(a) != 0 {
					isTop := a[:1] == "^"
					if isTop {
						a = a[1:]
					}
					isEnd := a[len(a)-1:] == "$"
					if isEnd {
						a = a[:len(a)-1]
					}
					elems := strings.Split(a, "_")
					asRegExps := make([]*regexp.Regexp, 0)
					for _, el := range elems {
						if len(el) == 0 {
							log.WithFields(log.Fields{
								"Topic": "Policy",
								"Type":  "AsPath Condition",
								"Value": aspath.AsPath,
								"Elem":  el,
							}).Error("invalid element. do not enter a blank.")
							return nil
						}
						regElem, err := regexp.Compile(el)
						if err != nil {
							log.WithFields(log.Fields{
								"Topic": "Policy",
								"Type":  "AsPath Condition",
								"Value": aspath.AsPath,
								"Elem":  el,
								"Error": err,
							}).Error("can not comple AS_PATH values to Regular expressions.")
							return nil
						}
						asRegExps = append(asRegExps, regElem)
					}

					e := &AsPathElement{}
					e.asRegExps = asRegExps
					e.asStr = a
					if isTop && isEnd {
						e.postiion = AS_ONLY
					} else if isTop && !isEnd {
						e.postiion = AS_FROM
					} else if !isTop && isEnd {
						e.postiion = AS_ORIGIN
					} else {
						e.postiion = AS_ANY
					}
					asPathList = append(asPathList, e)

				} else {
					log.WithFields(log.Fields{
						"Topic": "Policy",
						"Type":  "AsPath Condition",
					}).Error("does not parse AS_PATH condition value.")

					return nil
				}
			}
			c := &AsPathCondition{
				AsPathList:  asPathList,
				MatchOption: options,
			}
			return c
		}
	}
	return nil
}

func (c *AsPathCondition) checkMembers(aspath []uint32, checkAll bool) bool {

	checkElem := func(checkType AsnPos, regElems []*regexp.Regexp) bool {
		aslen := len(aspath)
		reglen := len(regElems)

		if aslen < reglen {
			return false
		}

		switch checkType {
		case AS_ONLY:
			if aslen != reglen {
				return false
			}
			fallthrough
		case AS_FROM:
			for i := 0; i < reglen; i++ {
				if !regElems[i].MatchString(fmt.Sprintf("%d", aspath[i])) {
					return false
				}
			}
		case AS_ORIGIN:
			for i := 0; i < reglen; i++ {
				if !regElems[reglen-i-1].MatchString(fmt.Sprintf("%d", aspath[aslen-i-1])) {
					return false
				}
			}
		case AS_ANY:
			for i := 0; i < aslen; i++ {
				eMatched := true
				if aslen < i+reglen {
					break
				}
				for j := 0; j < reglen; j++ {
					if !regElems[j].MatchString(fmt.Sprintf("%d", aspath[i+j])) {
						eMatched = false
						break
					}
				}
				if eMatched {
					return true
				}
			}
			return false
		}
		return true
	}

	result := false
	if checkAll {
		result = true
	}
	for _, member := range c.AsPathList {
		if checkElem(member.postiion, member.asRegExps) {
			log.WithFields(log.Fields{
				"Topic":     "Policy",
				"Condition": "aspath length",
				"ASN":       member.asStr,
				"Position":  member.postiion,
			}).Debug("aspath condition matched")

			if !checkAll {
				result = true
				break
			}

		} else {
			if checkAll {
				result = false
				break
			}
		}
	}

	return result
}

// compare AS_PATH in the message's AS_PATH attribute with
// the one in condition.
func (c *AsPathCondition) evaluate(path *table.Path) bool {

	aspath := path.GetAsSeqList()

	if c == nil || len(aspath) == 0 {
		return false
	}

	result := false
	if c.MatchOption == config.MATCH_SET_OPTIONS_TYPE_ALL {
		result = c.checkMembers(aspath, true)
	} else if c.MatchOption == config.MATCH_SET_OPTIONS_TYPE_ANY {
		result = c.checkMembers(aspath, false)
	} else if c.MatchOption == config.MATCH_SET_OPTIONS_TYPE_INVERT {
		result = !c.checkMembers(aspath, false)
	}

	log.WithFields(log.Fields{
		"Topic":       "Policy",
		"Condition":   "aspath",
		"MatchOption": c.MatchOption,
		"Matched":     result,
	}).Debug("evaluate aspath")

	return result
}

type CommunityCondition struct {
	DefaultCondition
	CommunityList []*CommunityElement
	MatchOption   config.MatchSetOptionsType
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
func NewCommunityCondition(matchSet config.MatchCommunitySet, defCommunitySetList []config.CommunitySet) *CommunityCondition {

	communitySetName := matchSet.CommunitySet
	options := matchSet.MatchSetOptions

	communityList := make([]*CommunityElement, 0)
	for _, communitySet := range defCommunitySetList {
		if communitySet.CommunitySetName == communitySetName {
			for _, community := range communitySet.CommunityList {
				c := community.Community
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
				MatchOption:   options,
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

func (c *CommunityCondition) checkMembers(communities []uint32, checkAll bool) bool {

	result := false
	if checkAll {
		result = true
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

			if !checkAll {
				result = true
				break
			}

		} else {
			if checkAll {
				result = false
				break
			}
		}
	}

	return result

}

// compare community in the message's attribute with
// the one in the condition.
func (c *CommunityCondition) evaluate(path *table.Path) bool {

	communities := path.GetCommunities()

	if len(communities) == 0 {
		log.WithFields(log.Fields{
			"Topic":       "Policy",
			"Condition":   "community",
			"MatchOption": c.MatchOption,
			"Matched":     false,
		}).Debug("community length is zero")
		return false
	}

	result := false
	if c.MatchOption == config.MATCH_SET_OPTIONS_TYPE_ALL {
		result = c.checkMembers(communities, true)
	} else if c.MatchOption == config.MATCH_SET_OPTIONS_TYPE_ANY {
		result = c.checkMembers(communities, false)
	} else if c.MatchOption == config.MATCH_SET_OPTIONS_TYPE_INVERT {
		result = !c.checkMembers(communities, false)
	}

	log.WithFields(log.Fields{
		"Topic":       "Policy",
		"Condition":   "community",
		"MatchOption": c.MatchOption,
		"Matched":     result,
	}).Debug("evaluate community")

	return result
}

type ExtCommunityCondition struct {
	DefaultCondition
	ExtCommunityList []*ExtCommunityElement
	MatchOption      config.MatchSetOptionsType
}

type ExtCommunityElement struct {
	ecType      bgp.ExtendedCommunityAttrType
	ecSubType   bgp.ExtendedCommunityAttrSubType
	globalAdmin interface{}
	localAdmin  uint32
	comStr      string
	isRegExp    bool
	regExp      *regexp.Regexp
}

func NewExtCommunityCondition(matchSet config.MatchExtCommunitySet, defExtComSetList []config.ExtCommunitySet) *ExtCommunityCondition {

	extComSetName := matchSet.ExtCommunitySet
	option := matchSet.MatchSetOptions

	extCommunityElemList := make([]*ExtCommunityElement, 0)
	for _, extComSet := range defExtComSetList {
		if extComSet.ExtCommunitySetName == extComSetName {
			for _, ecommunity := range extComSet.ExtCommunityList {
				matchAll := false
				ec := ecommunity.ExtCommunity
				e := &ExtCommunityElement{
					isRegExp: false,
					comStr:   ec,
				}
				matchType, val := getECommunitySubType(ec)
				if !matchType {
					log.WithFields(log.Fields{
						"Topic": "Policy",
						"Type":  "Extended Community Condition",
					}).Error("failed to parse the sub type %s.", ec)
					return nil
				}
				switch val[1] {
				case "RT":
					e.ecSubType = bgp.EC_SUBTYPE_ROUTE_TARGET
				case "SoO":
					e.ecSubType = bgp.EC_SUBTYPE_ROUTE_ORIGIN
				default:
					e.ecSubType = bgp.ExtendedCommunityAttrSubType(0xFF)
				}

				if matchVal, elem := getECommunityValue(val[2]); matchVal {
					if matchElem, ecType, gAdmin := getECommunityElem(elem[1]); matchElem {
						e.ecType = ecType
						e.globalAdmin = gAdmin
						lAdmin, err := strconv.ParseUint(elem[2], 10, 32)
						if err != nil {
							log.WithFields(log.Fields{
								"Topic": "Policy",
								"Type":  "Extended Community Condition",
							}).Errorf("failed to parse the local administrator %d.", elem[2])
							return nil
						}
						e.localAdmin = uint32(lAdmin)
						matchAll = true
					}
				}
				if !matchAll {
					e.isRegExp = true
					reg, err := regexp.Compile(ec)
					if err != nil {
						log.WithFields(log.Fields{
							"Topic": "Policy",
							"Type":  "Extended Community Condition",
						}).Errorf("Regular expression can't be compiled %s.", val[2])
						return nil
					}
					e.regExp = reg
				}
				extCommunityElemList = append(extCommunityElemList, e)
			}
			ce := &ExtCommunityCondition{
				ExtCommunityList: extCommunityElemList,
				MatchOption:      option,
			}
			return ce
		}
	}
	return nil
}

func getECommunitySubType(eComStr string) (bool, []string) {
	regSubType, _ := regexp.Compile("^(RT|SoO):(.*)$")
	if regSubType.MatchString(eComStr) {
		eComVal := regSubType.FindStringSubmatch(eComStr)
		return true, eComVal
	}
	return false, nil
}

func getECommunityValue(eComVal string) (bool, []string) {
	regVal, _ := regexp.Compile("^([0-9\\.]+):([0-9]+)$")
	if regVal.MatchString(eComVal) {
		eComElem := regVal.FindStringSubmatch(eComVal)
		return true, eComElem
	}
	return false, nil
}

func getECommunityElem(gAdmin string) (bool, bgp.ExtendedCommunityAttrType, interface{}) {
	addr := net.ParseIP(gAdmin)
	if addr.To4() != nil {
		return true, bgp.EC_TYPE_TRANSITIVE_IP4_SPECIFIC, addr
	}
	regAs, _ := regexp.Compile("^([0-9]+)$")
	if regAs.MatchString(gAdmin) {
		as, err := strconv.ParseUint(gAdmin, 10, 16)
		if err != nil {
			log.WithFields(log.Fields{
				"Topic": "Policy",
				"Type":  "Extended Community Condition",
			}).Errorf("failed to parse the global administrator %d.", gAdmin)
		}
		return true, bgp.EC_TYPE_TRANSITIVE_TWO_OCTET_AS_SPECIFIC, uint16(as)
	}
	regAs4, _ := regexp.Compile("^([0-9]+).([0-9]+)$")
	if regAs4.MatchString(gAdmin) {
		as4Elem := regAs4.FindStringSubmatch(gAdmin)
		highAs, errHigh := strconv.ParseUint(as4Elem[1], 10, 16)
		lowAs, errLow := strconv.ParseUint(as4Elem[2], 10, 16)
		if errHigh != nil || errLow != nil {
			log.WithFields(log.Fields{
				"Topic": "Policy",
				"Type":  "Extended Community Condition",
			}).Errorf("failed to parse the global administrator %d.", gAdmin)
		}
		return true, bgp.EC_TYPE_TRANSITIVE_FOUR_OCTET_AS_SPECIFIC, uint32(highAs<<16 | lowAs)
	}
	return false, bgp.ExtendedCommunityAttrType(0xFF), nil
}

func (c *ExtCommunityCondition) checkMembers(eCommunities []bgp.ExtendedCommunityInterface, checkAll bool) bool {

	result := false
	if checkAll {
		result = true
	}

	makeAs4Str := func(ec *ExtCommunityElement) string {
		t := ec.ecType
		str := fmt.Sprintf("%d", ec.localAdmin)
		switch t {
		case bgp.EC_TYPE_TRANSITIVE_TWO_OCTET_AS_SPECIFIC:
			str = fmt.Sprintf("%d:%s", ec.globalAdmin.(uint16), str)
		case bgp.EC_TYPE_TRANSITIVE_IP4_SPECIFIC:
			str = fmt.Sprintf("%s:%s", ec.globalAdmin.(net.IP).String(), str)
		case bgp.EC_TYPE_TRANSITIVE_FOUR_OCTET_AS_SPECIFIC:
			ga := ec.globalAdmin.(uint32)
			upper := strconv.FormatUint(uint64(ga&0xFFFF0000>>16), 10)
			lower := strconv.FormatUint(uint64(ga&0x0000FFFF), 10)
			str = fmt.Sprintf("%s.%s:%s", upper, lower, str)
		}
		return str
	}

	makeTypeSubStr := func(st bgp.ExtendedCommunityAttrSubType) string {
		subStr := ""
		switch st {
		case bgp.EC_SUBTYPE_ROUTE_TARGET:
			subStr = "RT"
		case bgp.EC_SUBTYPE_ROUTE_ORIGIN:
			subStr = "SoO"
		}
		return subStr
	}

	matched := false
	matchStr := ""
	for _, member := range c.ExtCommunityList {
		for _, ec := range eCommunities {
			t, st := ec.GetTypes()
			if member.isRegExp {
				ecString := fmt.Sprintf("%s:%s", makeTypeSubStr(st), ec.String())
				if member.regExp.MatchString(ecString) {
					matched = true
					log.WithFields(log.Fields{
						"Topic":  "Policy",
						"RegExp": member.regExp.String(),
					}).Debug("extended community regexp used")
					matchStr = ec.String()
					break
				}
			} else if member.ecType == t && member.ecSubType == st {
				if makeAs4Str(member) == ec.String() {
					matched = true
					matchStr = ec.String()
					break
				}

			}
		}
		if matched {
			log.WithFields(log.Fields{
				"Topic":              "Policy",
				"Condition":          "Extended Community",
				"Extended Community": matchStr,
			}).Debug("condition matched")

			if !checkAll {
				result = true
				break
			}

		} else {
			if checkAll {
				result = false
				break
			}
		}
	}
	return result
}

// compare extended community in the message's attribute with
// the one in the condition.
func (c *ExtCommunityCondition) evaluate(path *table.Path) bool {

	eCommunities := path.GetExtCommunities()
	if len(eCommunities) == 0 {
		log.WithFields(log.Fields{
			"Topic":     "Policy",
			"Condition": "extended community",
			"Matched":   false,
			"Path":      path,
		}).Debug("extended community length is zero")
		return false
	}

	result := false
	if c.MatchOption == config.MATCH_SET_OPTIONS_TYPE_ALL {
		result = c.checkMembers(eCommunities, true)
	} else if c.MatchOption == config.MATCH_SET_OPTIONS_TYPE_ANY {
		result = c.checkMembers(eCommunities, false)
	} else if c.MatchOption == config.MATCH_SET_OPTIONS_TYPE_INVERT {
		result = !c.checkMembers(eCommunities, false)
	}

	log.WithFields(log.Fields{
		"Topic":       "Policy",
		"Condition":   "extended community",
		"MatchOption": c.MatchOption,
		"Matched":     result,
		"Path":        path,
	}).Debug("evaluate extended community")

	return result
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
		AcceptRoute: action.RouteDisposition.AcceptRoute,
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

type CommunityAction struct {
	DefaultAction
	Values []uint32
	action config.BgpSetCommunityOptionType
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
	communities := action.SetCommunityMethod.Communities
	if len(communities) == 0 && action.Options != COMMUNITY_ACTION_REPLACE {
		return nil
	}

	values := make([]uint32, len(communities))
	for i, com := range communities {
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
	}

	log.WithFields(log.Fields{
		"Topic":  "Policy",
		"Action": "community",
		"Values": list,
		"Method": a.action,
	}).Debug("community action applied")

	return path
}

type ActionType int

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
	} else {
		log.WithFields(log.Fields{
			"Topic":      "Policy",
			"Action":     "med",
			"Value":      a.Value,
			"ActionType": a.action,
		}).Debug("med action applied")
	}

	return path
}

type AsPathPrependAction struct {
	DefaultAction
	asn         uint32
	useLeftMost bool
	repeat      uint8
}

// NewAsPathPrependAction creates AsPathPrependAction object.
// If ASN cannot be parsed, nil will be returned.
func NewAsPathPrependAction(action config.SetAsPathPrepend) *AsPathPrependAction {

	a := &AsPathPrependAction{}

	if action.As == "" {
		return nil
	}

	if action.As == "last-as" {
		a.useLeftMost = true
	} else {
		asn, err := strconv.ParseUint(action.As, 10, 32)
		if err != nil {
			log.WithFields(log.Fields{
				"Topic": "Policy",
				"Type":  "AsPathPrepend Action",
				"Value": action.As,
			}).Error("As number string invalid.")
			return nil
		}
		a.asn = uint32(asn)
	}
	a.repeat = action.RepeatN

	return a
}

func (a *AsPathPrependAction) apply(path *table.Path) *table.Path {

	var asn uint32
	if a.useLeftMost {
		asns := path.GetAsSeqList()
		if len(asns) == 0 {
			log.WithFields(log.Fields{
				"Topic": "Policy",
				"Type":  "AsPathPrepend Action",
			}).Error("aspath length is zero.")
			return path
		}
		asn = asns[0]
		log.WithFields(log.Fields{
			"Topic":  "Policy",
			"Type":   "AsPathPrepend Action",
			"LastAs": asn,
			"Repeat": a.repeat,
		}).Debug("use last AS.")
	} else {
		asn = a.asn
	}

	path.PrependAsn(asn, a.repeat)

	log.WithFields(log.Fields{
		"Topic":  "Policy",
		"Action": "aspath prepend",
		"ASN":    asn,
		"Repeat": a.repeat,
	}).Debug("aspath prepend action applied")

	return path
}

type Prefix struct {
	Address         net.IP
	AddressFamily   bgp.RouteFamily
	Masklength      uint8
	MasklengthRange map[MaskLengthRangeType]uint8
}

func NewPrefix(prefixStr string, maskRange string) (Prefix, error) {
	p := Prefix{}
	mlr := make(map[MaskLengthRangeType]uint8)
	addr, ipPref, e := net.ParseCIDR(prefixStr)

	if e != nil {
		return p, e
	}
	maskLength, _ := ipPref.Mask.Size()
	p.Address = addr
	p.Masklength = uint8(maskLength)

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
		}).Debug("statement evaluate : ", result)

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
	OPTIONS_ANY    string = "ANY"
	OPTIONS_ALL           = "ALL"
	OPTIONS_INVERT        = "INVERT"
)

func MatchSetOptionToString(option config.MatchSetOptionsType) string {
	op := OPTIONS_ANY
	switch option {
	case config.MATCH_SET_OPTIONS_TYPE_ALL:
		op = OPTIONS_ALL
	case config.MATCH_SET_OPTIONS_TYPE_INVERT:
		op = OPTIONS_INVERT
	}
	return op
}

func MatchSetOptionsRestrictedToString(option config.MatchSetOptionsRestrictedType) string {
	op := OPTIONS_ANY
	if option == config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_INVERT {
		op = OPTIONS_INVERT
	}
	return op
}

func MatchSetOptionsToType(option string) config.MatchSetOptionsType {
	op := config.MATCH_SET_OPTIONS_TYPE_ANY
	switch option {
	case OPTIONS_ALL:
		op = config.MATCH_SET_OPTIONS_TYPE_ALL
	case OPTIONS_INVERT:
		op = config.MATCH_SET_OPTIONS_TYPE_INVERT
	}
	return op
}

func MatchSetOptionsRestrictedToType(option string) config.MatchSetOptionsRestrictedType {
	op := config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY
	if option == OPTIONS_INVERT {
		op = config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_INVERT
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
				if reflect.DeepEqual(conPrefix.IpPrefix, reqPrefixSet.PrefixList[0].IpPrefix) &&
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
			if len(reqAsPathSet.AsPathList) == 0 {
				return idxAsPathSet, idxAsPath
			}
			for j, conAsPath := range conAsPathSet.AsPathList {
				if conAsPath == reqAsPathSet.AsPathList[0] {
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
			if len(reqCommunitySet.CommunityList) == 0 {
				return idxCommunitySet, idxCommunity
			}
			for j, conCommunity := range conCommunitySet.CommunityList {
				if conCommunity == reqCommunitySet.CommunityList[0] {
					idxCommunity = j
					return idxCommunitySet, idxCommunity
				}
			}
		}
	}
	return idxCommunitySet, idxCommunity
}

// find index ExtCommunitySet of request from ExtCommunitySet of configuration file.
// Return the idxExtCommunitySet of the location where the name of ExtCommunitySet matches,
// and idxExtCommunity of the location where element of ExtCommunitySet matches
func IndexOfExtCommunitySet(conExtCommunitySetList []config.ExtCommunitySet, reqExtCommunitySet config.ExtCommunitySet) (int, int) {
	idxExtCommunitySet := -1
	idxExtCommunity := -1
	for i, conExtCommunitySet := range conExtCommunitySetList {
		if conExtCommunitySet.ExtCommunitySetName == reqExtCommunitySet.ExtCommunitySetName {
			idxExtCommunitySet = i
			if len(reqExtCommunitySet.ExtCommunityList) == 0 {
				return idxExtCommunitySet, idxExtCommunity
			}
			for j, conExtCommunity := range conExtCommunitySet.ExtCommunityList {
				if conExtCommunity == reqExtCommunitySet.ExtCommunityList[0] {
					idxExtCommunity = j
					return idxExtCommunitySet, idxExtCommunity
				}
			}
		}
	}
	return idxExtCommunitySet, idxExtCommunity
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
			if reqPolicy.Statements.StatementList == nil {
				return idxPolicyDefinition, idxStatement
			}
			for j, conStatement := range conPolicy.Statements.StatementList {
				if conStatement.Name == reqPolicy.Statements.StatementList[0].Name {
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
			IpPrefix:        p.IpPrefix,
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
			IpPrefix:        reqPrefixSet.PrefixList[0].IpPrefix,
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
	for _, a := range as.AsPathList {
		resAsPathMembers = append(resAsPathMembers, a.AsPath)
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
	asPathList := make([]config.AsPath, 0)
	for _, a := range reqAsPathSet.AsPathMembers {
		asPathList = append(asPathList, config.AsPath{AsPath: a})
	}
	asPathSet := config.AsPathSet{
		AsPathSetName: reqAsPathSet.AsPathSetName,
		AsPathList:    asPathList,
	}
	return isAsPathSetSet, asPathSet
}

func CommunitySetToApiStruct(cs config.CommunitySet) *api.CommunitySet {
	resCommunityMembers := make([]string, 0)
	for _, c := range cs.CommunityList {
		resCommunityMembers = append(resCommunityMembers, c.Community)
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
	communityList := make([]config.Community, 0)
	for _, c := range reqCommunitySet.CommunityMembers {
		communityList = append(communityList, config.Community{Community: c})
	}
	communitySet := config.CommunitySet{
		CommunitySetName: reqCommunitySet.CommunitySetName,
		CommunityList:    communityList,
	}
	return isCommunitySet, communitySet
}

func ExtCommunitySetToApiStruct(es config.ExtCommunitySet) *api.ExtCommunitySet {
	resExtCommunityMembers := make([]string, 0)
	for _, ec := range es.ExtCommunityList {
		resExtCommunityMembers = append(resExtCommunityMembers, ec.ExtCommunity)
	}
	resExtCommunitySet := &api.ExtCommunitySet{
		ExtCommunitySetName: es.ExtCommunitySetName,
		ExtCommunityMembers: resExtCommunityMembers,
	}
	return resExtCommunitySet
}

func ExtCommunitySetToConfigStruct(reqExtCommunitySet *api.ExtCommunitySet) (bool, config.ExtCommunitySet) {
	isExtCommunitySet := true
	if len(reqExtCommunitySet.ExtCommunityMembers) == 0 {
		isExtCommunitySet = false
	}
	extCommunityList := make([]config.ExtCommunity, 0)
	for _, ec := range reqExtCommunitySet.ExtCommunityMembers {
		extCommunityList = append(extCommunityList, config.ExtCommunity{ExtCommunity: ec})
	}
	ExtCommunitySet := config.ExtCommunitySet{
		ExtCommunitySetName: reqExtCommunitySet.ExtCommunitySetName,
		ExtCommunityList:    extCommunityList,
	}
	return isExtCommunitySet, ExtCommunitySet
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
	if reqConditions == nil {
		return conditions
	}
	if reqConditions.MatchPrefixSet != nil {
		conditions.MatchPrefixSet.PrefixSet = reqConditions.MatchPrefixSet.PrefixSetName
		conditions.MatchPrefixSet.MatchSetOptions =
			MatchSetOptionsRestrictedToType(reqConditions.MatchPrefixSet.MatchSetOptions)
	}
	if reqConditions.MatchNeighborSet != nil {
		conditions.MatchNeighborSet.NeighborSet = reqConditions.MatchNeighborSet.NeighborSetName
		conditions.MatchNeighborSet.MatchSetOptions =
			MatchSetOptionsRestrictedToType(reqConditions.MatchNeighborSet.MatchSetOptions)
	}
	if reqConditions.MatchAsPathSet != nil {
		conditions.BgpConditions.MatchAsPathSet.AsPathSet = reqConditions.MatchAsPathSet.AsPathSetName
		conditions.BgpConditions.MatchAsPathSet.MatchSetOptions =
			MatchSetOptionsToType(reqConditions.MatchAsPathSet.MatchSetOptions)
	}
	if reqConditions.MatchCommunitySet != nil {
		conditions.BgpConditions.MatchCommunitySet.CommunitySet = reqConditions.MatchCommunitySet.CommunitySetName
		conditions.BgpConditions.MatchCommunitySet.MatchSetOptions =
			MatchSetOptionsToType(reqConditions.MatchCommunitySet.MatchSetOptions)
	}
	if reqConditions.MatchExtCommunitySet != nil {
		conditions.BgpConditions.MatchExtCommunitySet.ExtCommunitySet = reqConditions.MatchExtCommunitySet.ExtCommunitySetName
		conditions.BgpConditions.MatchExtCommunitySet.MatchSetOptions =
			MatchSetOptionsToType(reqConditions.MatchExtCommunitySet.MatchSetOptions)
	}
	if reqConditions.MatchAsPathLength != nil {
		conditions.BgpConditions.AsPathLength =
			AsPathLengthToConfigStruct(reqConditions.MatchAsPathLength)
	}
	return conditions
}

func ActionsToApiStruct(conActions config.Actions) *api.Actions {
	action := ROUTE_REJECT
	if conActions.RouteDisposition.AcceptRoute {
		action = ROUTE_ACCEPT
	}

	//TODO: support CommunitySetRef
	communityAction := &api.CommunityAction{
		Communities: conActions.BgpActions.SetCommunity.SetCommunityMethod.Communities,
		Options:     conActions.BgpActions.SetCommunity.Options,
	}
	medAction := fmt.Sprintf("%s", conActions.BgpActions.SetMed)
	asprependAction := &api.AsPrependAction{
		conActions.BgpActions.SetAsPathPrepend.As,
		uint32(conActions.BgpActions.SetAsPathPrepend.RepeatN),
	}

	resActions := &api.Actions{
		RouteAction: action,
		Community:   communityAction,
		Med:         medAction,
		AsPrepend:   asprependAction,
	}
	return resActions
}

func ActionsToConfigStruct(reqActions *api.Actions) config.Actions {
	actions := config.Actions{}
	if reqActions == nil {
		return actions
	}
	if reqActions.Community != nil {
		actions.BgpActions.SetCommunity.SetCommunityMethod.Communities = reqActions.Community.Communities
		actions.BgpActions.SetCommunity.Options = reqActions.Community.Options
	}
	if reqActions.Med != "" {
		actions.BgpActions.SetMed = config.BgpSetMedType(reqActions.Med)
	}
	if reqActions.AsPrepend != nil {
		actions.BgpActions.SetAsPathPrepend.As = reqActions.AsPrepend.As
		actions.BgpActions.SetAsPathPrepend.RepeatN = uint8(reqActions.AsPrepend.Repeatn)
	}

	switch reqActions.RouteAction {
	case ROUTE_ACCEPT:
		actions.RouteDisposition.AcceptRoute = true
	case ROUTE_REJECT:
		actions.RouteDisposition.RejectRoute = true
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
		policy.Statements.StatementList = []config.Statement{statement}
	} else {
		isReqStatement = false
	}
	return isReqStatement, policy
}

func PolicyDefinitionToApiStruct(pd config.PolicyDefinition, df config.DefinedSets) *api.PolicyDefinition {
	conPrefixSetList := df.PrefixSets.PrefixSetList
	conNeighborSetList := df.NeighborSets.NeighborSetList
	conAsPathSetList := df.BgpDefinedSets.AsPathSets.AsPathSetList
	conCommunitySetList := df.BgpDefinedSets.CommunitySets.CommunitySetList
	conExtCommunitySetList := df.BgpDefinedSets.ExtCommunitySets.ExtCommunitySetList
	resStatementList := make([]*api.Statement, 0)
	for _, st := range pd.Statements.StatementList {
		co := st.Conditions
		bco := co.BgpConditions
		ac := st.Actions

		prefixSet := &api.PrefixSet{PrefixSetName: co.MatchPrefixSet.PrefixSet}
		conPrefixSet := config.PrefixSet{PrefixSetName: co.MatchPrefixSet.PrefixSet}
		idxPrefixSet, _ := IndexOfPrefixSet(conPrefixSetList, conPrefixSet)
		if idxPrefixSet != -1 {
			prefixSet = PrefixSetToApiStruct(conPrefixSetList[idxPrefixSet])
			prefixSet.MatchSetOptions = MatchSetOptionsRestrictedToString(st.Conditions.MatchPrefixSet.MatchSetOptions)
		}
		neighborSet := &api.NeighborSet{NeighborSetName: co.MatchNeighborSet.NeighborSet}
		conNeighborSet := config.NeighborSet{NeighborSetName: co.MatchNeighborSet.NeighborSet}
		idxNeighborSet, _ := IndexOfNeighborSet(conNeighborSetList, conNeighborSet)
		if idxNeighborSet != -1 {
			neighborSet = NeighborSetToApiStruct(conNeighborSetList[idxNeighborSet])
			neighborSet.MatchSetOptions = MatchSetOptionsRestrictedToString(st.Conditions.MatchNeighborSet.MatchSetOptions)
		}

		asPathSet := &api.AsPathSet{AsPathSetName: bco.MatchAsPathSet.AsPathSet}
		conAsPathSet := config.AsPathSet{AsPathSetName: bco.MatchAsPathSet.AsPathSet}
		idxAsPathSet, _ := IndexOfAsPathSet(conAsPathSetList, conAsPathSet)
		if idxAsPathSet != -1 {
			asPathSet = AsPathSetToApiStruct(conAsPathSetList[idxAsPathSet])
			asPathSet.MatchSetOptions = MatchSetOptionToString(bco.MatchAsPathSet.MatchSetOptions)
		}

		communitySet := &api.CommunitySet{CommunitySetName: bco.MatchCommunitySet.CommunitySet}
		conCommunitySet := config.CommunitySet{CommunitySetName: bco.MatchCommunitySet.CommunitySet}
		idxCommunitySet, _ := IndexOfCommunitySet(conCommunitySetList, conCommunitySet)
		if idxCommunitySet != -1 {
			communitySet = CommunitySetToApiStruct(conCommunitySetList[idxCommunitySet])
			communitySet.MatchSetOptions = MatchSetOptionToString(bco.MatchCommunitySet.MatchSetOptions)
		}

		extCommunitySet := &api.ExtCommunitySet{ExtCommunitySetName: bco.MatchExtCommunitySet.ExtCommunitySet}
		conExtCommunitySet := config.ExtCommunitySet{ExtCommunitySetName: bco.MatchExtCommunitySet.ExtCommunitySet}
		idxExtCommunitySet, _ := IndexOfExtCommunitySet(conExtCommunitySetList, conExtCommunitySet)
		if idxExtCommunitySet != -1 {
			extCommunitySet = ExtCommunitySetToApiStruct(conExtCommunitySetList[idxExtCommunitySet])
			extCommunitySet.MatchSetOptions = MatchSetOptionToString(bco.MatchExtCommunitySet.MatchSetOptions)
		}

		resConditions := &api.Conditions{
			MatchPrefixSet:       prefixSet,
			MatchNeighborSet:     neighborSet,
			MatchAsPathSet:       asPathSet,
			MatchCommunitySet:    communitySet,
			MatchExtCommunitySet: extCommunitySet,
			MatchAsPathLength:    AsPathLengthToApiStruct(st.Conditions.BgpConditions.AsPathLength),
		}
		resActions := ActionsToApiStruct(ac)
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
