// Copyright (C) 2014-2016 Nippon Telegraph and Telephone Corporation.
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

package table

import (
	"bytes"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/armon/go-radix"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
)

type PolicyOptions struct {
	Info *PeerInfo
}

type DefinedType int

const (
	DEFINED_TYPE_PREFIX DefinedType = iota
	DEFINED_TYPE_NEIGHBOR
	DEFINED_TYPE_TAG
	DEFINED_TYPE_AS_PATH
	DEFINED_TYPE_COMMUNITY
	DEFINED_TYPE_EXT_COMMUNITY
)

type RouteType int

const (
	ROUTE_TYPE_NONE RouteType = iota
	ROUTE_TYPE_ACCEPT
	ROUTE_TYPE_REJECT
)

type PolicyDirection int

const (
	POLICY_DIRECTION_NONE PolicyDirection = iota
	POLICY_DIRECTION_IN
	POLICY_DIRECTION_IMPORT
	POLICY_DIRECTION_EXPORT
)

func (d PolicyDirection) String() string {
	switch d {
	case POLICY_DIRECTION_IN:
		return "in"
	case POLICY_DIRECTION_IMPORT:
		return "import"
	case POLICY_DIRECTION_EXPORT:
		return "export"
	}
	return fmt.Sprintf("unknown(%d)", d)
}

type MatchOption int

const (
	MATCH_OPTION_ANY MatchOption = iota
	MATCH_OPTION_ALL
	MATCH_OPTION_INVERT
)

func (o MatchOption) String() string {
	switch o {
	case MATCH_OPTION_ANY:
		return "any"
	case MATCH_OPTION_ALL:
		return "all"
	case MATCH_OPTION_INVERT:
		return "invert"
	default:
		return fmt.Sprintf("MatchOption(%d)", o)
	}
}

type MedActionType int

const (
	MED_ACTION_MOD MedActionType = iota
	MED_ACTION_REPLACE
)

var CommunityOptionNameMap = map[config.BgpSetCommunityOptionType]string{
	config.BGP_SET_COMMUNITY_OPTION_TYPE_ADD:     "add",
	config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE:  "remove",
	config.BGP_SET_COMMUNITY_OPTION_TYPE_REPLACE: "replace",
}

var CommunityOptionValueMap = map[string]config.BgpSetCommunityOptionType{
	CommunityOptionNameMap[config.BGP_SET_COMMUNITY_OPTION_TYPE_ADD]:     config.BGP_SET_COMMUNITY_OPTION_TYPE_ADD,
	CommunityOptionNameMap[config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE]:  config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE,
	CommunityOptionNameMap[config.BGP_SET_COMMUNITY_OPTION_TYPE_REPLACE]: config.BGP_SET_COMMUNITY_OPTION_TYPE_REPLACE,
}

type ConditionType int

const (
	CONDITION_PREFIX ConditionType = iota
	CONDITION_NEIGHBOR
	CONDITION_AS_PATH
	CONDITION_COMMUNITY
	CONDITION_EXT_COMMUNITY
	CONDITION_AS_PATH_LENGTH
	CONDITION_RPKI
)

type ActionType int

const (
	ACTION_ROUTING ActionType = iota
	ACTION_COMMUNITY
	ACTION_EXT_COMMUNITY
	ACTION_MED
	ACTION_AS_PATH_PREPEND
	ACTION_NEXTHOP
	ACTION_LOCAL_PREF
)

func NewMatchOption(c interface{}) (MatchOption, error) {
	switch t := c.(type) {
	case config.MatchSetOptionsType:
		t = t.DefaultAsNeeded()
		switch t {
		case config.MATCH_SET_OPTIONS_TYPE_ANY:
			return MATCH_OPTION_ANY, nil
		case config.MATCH_SET_OPTIONS_TYPE_ALL:
			return MATCH_OPTION_ALL, nil
		case config.MATCH_SET_OPTIONS_TYPE_INVERT:
			return MATCH_OPTION_INVERT, nil
		}
	case config.MatchSetOptionsRestrictedType:
		t = t.DefaultAsNeeded()
		switch t {
		case config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY:
			return MATCH_OPTION_ANY, nil
		case config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_INVERT:
			return MATCH_OPTION_INVERT, nil
		}
	}
	return MATCH_OPTION_ANY, fmt.Errorf("invalid argument to create match option: %v", c)
}

type AttributeComparison int

const (
	// "== comparison"
	ATTRIBUTE_EQ AttributeComparison = iota
	// ">= comparison"
	ATTRIBUTE_GE
	// "<= comparison"
	ATTRIBUTE_LE
)

const (
	ASPATH_REGEXP_MAGIC = "(^|[,{}() ]|$)"
)

type DefinedSet interface {
	Type() DefinedType
	Name() string
	Append(DefinedSet) error
	Remove(DefinedSet) error
	Replace(DefinedSet) error
}

type DefinedSetMap map[DefinedType]map[string]DefinedSet

type Prefix struct {
	Prefix             *net.IPNet
	AddressFamily      bgp.RouteFamily
	MasklengthRangeMax uint8
	MasklengthRangeMin uint8
}

func (p *Prefix) Match(path *Path) bool {
	rf := path.GetRouteFamily()
	if rf != p.AddressFamily {
		return false
	}

	var pAddr net.IP
	var pMasklen uint8
	switch rf {
	case bgp.RF_IPv4_UC:
		pAddr = path.GetNlri().(*bgp.IPAddrPrefix).Prefix
		pMasklen = path.GetNlri().(*bgp.IPAddrPrefix).Length
	case bgp.RF_IPv6_UC:
		pAddr = path.GetNlri().(*bgp.IPv6AddrPrefix).Prefix
		pMasklen = path.GetNlri().(*bgp.IPv6AddrPrefix).Length
	default:
		return false
	}

	return (p.MasklengthRangeMin <= pMasklen && pMasklen <= p.MasklengthRangeMax) && p.Prefix.Contains(pAddr)
}

func (lhs *Prefix) Equal(rhs *Prefix) bool {
	if lhs == rhs {
		return true
	}
	if rhs == nil {
		return false
	}
	return lhs.Prefix.String() == rhs.Prefix.String() && lhs.MasklengthRangeMin == rhs.MasklengthRangeMin && lhs.MasklengthRangeMax == rhs.MasklengthRangeMax
}

func NewPrefix(c config.Prefix) (*Prefix, error) {
	addr, prefix, err := net.ParseCIDR(c.IpPrefix)
	if err != nil {
		return nil, err
	}

	rf := bgp.RF_IPv4_UC
	if addr.To4() == nil {
		rf = bgp.RF_IPv6_UC
	}
	p := &Prefix{
		Prefix:        prefix,
		AddressFamily: rf,
	}
	maskRange := c.MasklengthRange
	if maskRange == "" {
		l, _ := prefix.Mask.Size()
		maskLength := uint8(l)
		p.MasklengthRangeMax = maskLength
		p.MasklengthRangeMin = maskLength
	} else {
		exp := regexp.MustCompile("(\\d+)\\.\\.(\\d+)")
		elems := exp.FindStringSubmatch(maskRange)
		if len(elems) != 3 {
			log.WithFields(log.Fields{
				"Topic":           "Policy",
				"Type":            "Prefix",
				"MaskRangeFormat": maskRange,
			}).Warn("mask length range format is invalid.")
			return nil, fmt.Errorf("mask length range format is invalid")
		}
		// we've already checked the range is sane by regexp
		min, _ := strconv.Atoi(elems[1])
		max, _ := strconv.Atoi(elems[2])
		p.MasklengthRangeMin = uint8(min)
		p.MasklengthRangeMax = uint8(max)
	}
	return p, nil
}

type PrefixSet struct {
	name string
	tree *radix.Tree
}

func (s *PrefixSet) Name() string {
	return s.name
}

func (s *PrefixSet) Type() DefinedType {
	return DEFINED_TYPE_PREFIX
}

func (lhs *PrefixSet) Append(arg DefinedSet) error {
	rhs, ok := arg.(*PrefixSet)
	if !ok {
		return fmt.Errorf("type cast failed")
	}
	rhs.tree.Walk(func(s string, v interface{}) bool {
		lhs.tree.Insert(s, v)
		return false
	})
	return nil
}

func (lhs *PrefixSet) Remove(arg DefinedSet) error {
	rhs, ok := arg.(*PrefixSet)
	if !ok {
		return fmt.Errorf("type cast failed")
	}
	rhs.tree.Walk(func(s string, v interface{}) bool {
		lhs.tree.Delete(s)
		return false
	})
	return nil
}

func (lhs *PrefixSet) Replace(arg DefinedSet) error {
	rhs, ok := arg.(*PrefixSet)
	if !ok {
		return fmt.Errorf("type cast failed")
	}
	lhs.tree = rhs.tree
	return nil
}

func (s *PrefixSet) ToConfig() *config.PrefixSet {
	list := make([]config.Prefix, 0, s.tree.Len())
	s.tree.Walk(func(s string, v interface{}) bool {
		p := v.(*Prefix)
		list = append(list, config.Prefix{IpPrefix: p.Prefix.String(), MasklengthRange: fmt.Sprintf("%d..%d", p.MasklengthRangeMin, p.MasklengthRangeMax)})
		return false
	})
	return &config.PrefixSet{
		PrefixSetName: s.name,
		PrefixList:    list,
	}
}

func NewPrefixSetFromApiStruct(name string, prefixes []*Prefix) (*PrefixSet, error) {
	if name == "" {
		return nil, fmt.Errorf("empty prefix set name")
	}
	tree := radix.New()
	for _, x := range prefixes {
		tree.Insert(CidrToRadixkey(x.Prefix.String()), x)
	}
	return &PrefixSet{
		name: name,
		tree: tree,
	}, nil
}

func NewPrefixSet(c config.PrefixSet) (*PrefixSet, error) {
	name := c.PrefixSetName
	if name == "" {
		if len(c.PrefixList) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("empty prefix set name")
	}
	tree := radix.New()
	for _, x := range c.PrefixList {
		y, err := NewPrefix(x)
		if err != nil {
			return nil, err
		}
		tree.Insert(CidrToRadixkey(y.Prefix.String()), y)
	}
	return &PrefixSet{
		name: name,
		tree: tree,
	}, nil
}

type NeighborSet struct {
	name string
	list []net.IP
}

func (s *NeighborSet) Name() string {
	return s.name
}

func (s *NeighborSet) Type() DefinedType {
	return DEFINED_TYPE_NEIGHBOR
}

func (lhs *NeighborSet) Append(arg DefinedSet) error {
	rhs, ok := arg.(*NeighborSet)
	if !ok {
		return fmt.Errorf("type cast failed")
	}
	lhs.list = append(lhs.list, rhs.list...)
	return nil
}

func (lhs *NeighborSet) Remove(arg DefinedSet) error {
	rhs, ok := arg.(*NeighborSet)
	if !ok {
		return fmt.Errorf("type cast failed")
	}
	ps := make([]net.IP, 0, len(lhs.list))
	for _, x := range lhs.list {
		found := false
		for _, y := range rhs.list {
			if x.Equal(y) {
				found = true
				break
			}
		}
		if !found {
			ps = append(ps, x)
		}
	}
	lhs.list = ps
	return nil
}

func (lhs *NeighborSet) Replace(arg DefinedSet) error {
	rhs, ok := arg.(*NeighborSet)
	if !ok {
		return fmt.Errorf("type cast failed")
	}
	lhs.list = rhs.list
	return nil
}

func (s *NeighborSet) ToConfig() *config.NeighborSet {
	list := make([]string, 0, len(s.list))
	for _, n := range s.list {
		list = append(list, n.String())
	}
	return &config.NeighborSet{
		NeighborSetName:  s.name,
		NeighborInfoList: list,
	}
}

func NewNeighborSetFromApiStruct(name string, list []net.IP) (*NeighborSet, error) {
	return &NeighborSet{
		name: name,
		list: list,
	}, nil
}

func NewNeighborSet(c config.NeighborSet) (*NeighborSet, error) {
	name := c.NeighborSetName
	if name == "" {
		if len(c.NeighborInfoList) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("empty neighbor set name")
	}
	list := make([]net.IP, 0, len(c.NeighborInfoList))
	for _, x := range c.NeighborInfoList {
		addr := net.ParseIP(x)
		if addr == nil {
			return nil, fmt.Errorf("invalid address: %s", x)
		}
		list = append(list, addr)
	}
	return &NeighborSet{
		name: name,
		list: list,
	}, nil
}

type singleAsPathMatchMode int

const (
	INCLUDE singleAsPathMatchMode = iota
	LEFT_MOST
	ORIGIN
	ONLY
)

type singleAsPathMatch struct {
	asn  uint32
	mode singleAsPathMatchMode
}

func (lhs *singleAsPathMatch) Equal(rhs *singleAsPathMatch) bool {
	return lhs.asn == rhs.asn && lhs.mode == rhs.mode
}

func (lhs *singleAsPathMatch) String() string {
	switch lhs.mode {
	case INCLUDE:
		return fmt.Sprintf("_%d_", lhs.asn)
	case LEFT_MOST:
		return fmt.Sprintf("^%d_", lhs.asn)
	case ORIGIN:
		return fmt.Sprintf("_%d$", lhs.asn)
	case ONLY:
		return fmt.Sprintf("^%d$", lhs.asn)
	}
	return ""
}

func (m *singleAsPathMatch) Match(aspath []uint32) bool {
	if len(aspath) == 0 {
		return false
	}
	switch m.mode {
	case INCLUDE:
		for _, asn := range aspath {
			if m.asn == asn {
				return true
			}
		}
	case LEFT_MOST:
		if m.asn == aspath[0] {
			return true
		}
	case ORIGIN:
		if m.asn == aspath[len(aspath)-1] {
			return true
		}
	case ONLY:
		if len(aspath) == 1 && m.asn == aspath[0] {
			return true
		}
	}
	return false
}

func NewSingleAsPathMatch(arg string) *singleAsPathMatch {
	leftMostRe := regexp.MustCompile("$\\^([0-9]+)_^")
	originRe := regexp.MustCompile("^_([0-9]+)\\$$")
	includeRe := regexp.MustCompile("^_([0-9]+)_$")
	onlyRe := regexp.MustCompile("^\\^([0-9]+)\\$$")
	switch {
	case leftMostRe.MatchString(arg):
		asn, _ := strconv.Atoi(leftMostRe.FindStringSubmatch(arg)[1])
		return &singleAsPathMatch{
			asn:  uint32(asn),
			mode: LEFT_MOST,
		}
	case originRe.MatchString(arg):
		asn, _ := strconv.Atoi(originRe.FindStringSubmatch(arg)[1])
		return &singleAsPathMatch{
			asn:  uint32(asn),
			mode: ORIGIN,
		}
	case includeRe.MatchString(arg):
		asn, _ := strconv.Atoi(includeRe.FindStringSubmatch(arg)[1])
		return &singleAsPathMatch{
			asn:  uint32(asn),
			mode: INCLUDE,
		}
	case onlyRe.MatchString(arg):
		asn, _ := strconv.Atoi(onlyRe.FindStringSubmatch(arg)[1])
		return &singleAsPathMatch{
			asn:  uint32(asn),
			mode: ONLY,
		}
	}
	return nil
}

type AsPathSet struct {
	typ        DefinedType
	name       string
	list       []*regexp.Regexp
	singleList []*singleAsPathMatch
}

func (s *AsPathSet) Name() string {
	return s.name
}

func (s *AsPathSet) Type() DefinedType {
	return s.typ
}

func (lhs *AsPathSet) Append(arg DefinedSet) error {
	if lhs.Type() != arg.Type() {
		return fmt.Errorf("can't append to different type of defined-set")
	}
	lhs.list = append(lhs.list, arg.(*AsPathSet).list...)
	lhs.singleList = append(lhs.singleList, arg.(*AsPathSet).singleList...)
	return nil
}

func (lhs *AsPathSet) Remove(arg DefinedSet) error {
	if lhs.Type() != arg.Type() {
		return fmt.Errorf("can't append to different type of defined-set")
	}
	newList := make([]*regexp.Regexp, 0, len(lhs.list))
	for _, x := range lhs.list {
		found := false
		for _, y := range arg.(*AsPathSet).list {
			if x.String() == y.String() {
				found = true
				break
			}
		}
		if !found {
			newList = append(newList, x)
		}
	}
	lhs.list = newList
	newSingleList := make([]*singleAsPathMatch, 0, len(lhs.singleList))
	for _, x := range lhs.singleList {
		found := false
		for _, y := range arg.(*AsPathSet).singleList {
			if x.Equal(y) {
				found = true
				break
			}
		}
		if !found {
			newSingleList = append(newSingleList, x)
		}
	}
	lhs.singleList = newSingleList
	return nil
}

func (lhs *AsPathSet) Replace(arg DefinedSet) error {
	rhs, ok := arg.(*AsPathSet)
	if !ok {
		return fmt.Errorf("type cast failed")
	}
	lhs.list = rhs.list
	lhs.singleList = rhs.singleList
	return nil
}

func (s *AsPathSet) ToConfig() *config.AsPathSet {
	list := make([]string, 0, len(s.list)+len(s.singleList))
	for _, exp := range s.singleList {
		list = append(list, exp.String())
	}
	for _, exp := range s.list {
		list = append(list, exp.String())
	}
	return &config.AsPathSet{
		AsPathSetName: s.name,
		AsPathList:    list,
	}
}

func NewAsPathSet(c config.AsPathSet) (*AsPathSet, error) {
	name := c.AsPathSetName
	if name == "" {
		if len(c.AsPathList) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("empty as-path set name")
	}
	list := make([]*regexp.Regexp, 0, len(c.AsPathList))
	singleList := make([]*singleAsPathMatch, 0, len(c.AsPathList))
	for _, x := range c.AsPathList {
		if s := NewSingleAsPathMatch(x); s != nil {
			singleList = append(singleList, s)
		} else {
			exp, err := regexp.Compile(strings.Replace(x, "_", ASPATH_REGEXP_MAGIC, -1))
			if err != nil {
				return nil, fmt.Errorf("invalid regular expression: %s", x)
			}
			list = append(list, exp)
		}
	}
	return &AsPathSet{
		typ:        DEFINED_TYPE_AS_PATH,
		name:       name,
		list:       list,
		singleList: singleList,
	}, nil
}

type regExpSet struct {
	typ  DefinedType
	name string
	list []*regexp.Regexp
}

func (s *regExpSet) Name() string {
	return s.name
}

func (s *regExpSet) Type() DefinedType {
	return s.typ
}

func (lhs *regExpSet) Append(arg DefinedSet) error {
	if lhs.Type() != arg.Type() {
		return fmt.Errorf("can't append to different type of defined-set")
	}
	var list []*regexp.Regexp
	switch lhs.Type() {
	case DEFINED_TYPE_AS_PATH:
		list = arg.(*AsPathSet).list
	case DEFINED_TYPE_COMMUNITY:
		list = arg.(*CommunitySet).list
	case DEFINED_TYPE_EXT_COMMUNITY:
		list = arg.(*ExtCommunitySet).list
	default:
		return fmt.Errorf("invalid defined-set type: %d", lhs.Type())
	}
	lhs.list = append(lhs.list, list...)
	return nil
}

func (lhs *regExpSet) Remove(arg DefinedSet) error {
	if lhs.Type() != arg.Type() {
		return fmt.Errorf("can't append to different type of defined-set")
	}
	var list []*regexp.Regexp
	switch lhs.Type() {
	case DEFINED_TYPE_AS_PATH:
		list = arg.(*AsPathSet).list
	case DEFINED_TYPE_COMMUNITY:
		list = arg.(*CommunitySet).list
	case DEFINED_TYPE_EXT_COMMUNITY:
		list = arg.(*ExtCommunitySet).list
	default:
		return fmt.Errorf("invalid defined-set type: %d", lhs.Type())
	}
	ps := make([]*regexp.Regexp, 0, len(lhs.list))
	for _, x := range lhs.list {
		found := false
		for _, y := range list {
			if x.String() == y.String() {
				found = true
				break
			}
		}
		if !found {
			ps = append(ps, x)
		}
	}
	lhs.list = ps
	return nil
}

func (lhs *regExpSet) Replace(arg DefinedSet) error {
	rhs, ok := arg.(*regExpSet)
	if !ok {
		return fmt.Errorf("type cast failed")
	}
	lhs.list = rhs.list
	return nil
}

type CommunitySet struct {
	regExpSet
}

func (s *CommunitySet) ToConfig() *config.CommunitySet {
	list := make([]string, 0, len(s.list))
	for _, exp := range s.list {
		list = append(list, exp.String())
	}
	return &config.CommunitySet{
		CommunitySetName: s.name,
		CommunityList:    list,
	}
}

func ParseCommunity(arg string) (uint32, error) {
	i, err := strconv.Atoi(arg)
	if err == nil {
		return uint32(i), nil
	}
	exp := regexp.MustCompile("(\\d+):(\\d+)")
	elems := exp.FindStringSubmatch(arg)
	if len(elems) == 3 {
		fst, _ := strconv.Atoi(elems[1])
		snd, _ := strconv.Atoi(elems[2])
		return uint32(fst<<16 | snd), nil
	}
	for i, v := range bgp.WellKnownCommunityNameMap {
		if arg == v {
			return uint32(i), nil
		}
	}
	return 0, fmt.Errorf("failed to parse %s as community", arg)
}

func ParseExtCommunity(arg string) (bgp.ExtendedCommunityInterface, error) {
	var subtype bgp.ExtendedCommunityAttrSubType
	var value string
	elems := strings.SplitN(arg, ":", 2)

	isValidationState := func(s string) bool {
		s = strings.ToLower(s)
		r := s == bgp.VALIDATION_STATE_VALID.String()
		r = r || s == bgp.VALIDATION_STATE_NOT_FOUND.String()
		return r || s == bgp.VALIDATION_STATE_INVALID.String()
	}
	if len(elems) < 2 && (len(elems) < 1 && !isValidationState(elems[0])) {
		return nil, fmt.Errorf("invalid ext-community (rt|soo):<value> | valid | not-found | invalid")
	}
	if isValidationState(elems[0]) {
		subtype = bgp.EC_SUBTYPE_ORIGIN_VALIDATION
		value = elems[0]
	} else {
		switch strings.ToLower(elems[0]) {
		case "rt":
			subtype = bgp.EC_SUBTYPE_ROUTE_TARGET
		case "soo":
			subtype = bgp.EC_SUBTYPE_ROUTE_ORIGIN
		default:
			return nil, fmt.Errorf("invalid ext-community (rt|soo):<value> | valid | not-found | invalid")
		}
		value = elems[1]
	}
	return bgp.ParseExtendedCommunity(subtype, value)
}

func ParseCommunityRegexp(arg string) (*regexp.Regexp, error) {
	i, err := strconv.Atoi(arg)
	if err == nil {
		return regexp.MustCompile(fmt.Sprintf("^%d:%d$", i>>16, i&0x0000ffff)), nil
	}
	if regexp.MustCompile("(\\d+.)*\\d+:\\d+").MatchString(arg) {
		return regexp.MustCompile(fmt.Sprintf("^%s$", arg)), nil
	}
	for i, v := range bgp.WellKnownCommunityNameMap {
		if strings.Replace(strings.ToLower(arg), "_", "-", -1) == v {
			return regexp.MustCompile(fmt.Sprintf("^%d:%d$", i>>16, i&0x0000ffff)), nil
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

func NewCommunitySet(c config.CommunitySet) (*CommunitySet, error) {
	name := c.CommunitySetName
	if name == "" {
		if len(c.CommunityList) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("empty community set name")
	}
	list := make([]*regexp.Regexp, 0, len(c.CommunityList))
	for _, x := range c.CommunityList {
		exp, err := ParseCommunityRegexp(x)
		if err != nil {
			return nil, err
		}
		list = append(list, exp)
	}
	return &CommunitySet{
		regExpSet: regExpSet{
			typ:  DEFINED_TYPE_COMMUNITY,
			name: name,
			list: list,
		},
	}, nil
}

type ExtCommunitySet struct {
	regExpSet
	subtypeList []bgp.ExtendedCommunityAttrSubType
}

func (s *ExtCommunitySet) ToConfig() *config.ExtCommunitySet {
	list := make([]string, 0, len(s.list))
	f := func(idx int, arg string) string {
		switch s.subtypeList[idx] {
		case bgp.EC_SUBTYPE_ROUTE_TARGET:
			return fmt.Sprintf("rt:%s", arg)
		case bgp.EC_SUBTYPE_ROUTE_ORIGIN:
			return fmt.Sprintf("soo:%s", arg)
		case bgp.EC_SUBTYPE_ORIGIN_VALIDATION:
			return arg
		default:
			return fmt.Sprintf("%d:%s", s.subtypeList[idx], arg)
		}
	}
	for idx, exp := range s.list {
		list = append(list, f(idx, exp.String()))
	}
	return &config.ExtCommunitySet{
		ExtCommunitySetName: s.name,
		ExtCommunityList:    list,
	}
}

func NewExtCommunitySet(c config.ExtCommunitySet) (*ExtCommunitySet, error) {
	name := c.ExtCommunitySetName
	if name == "" {
		if len(c.ExtCommunityList) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("empty ext-community set name")
	}
	list := make([]*regexp.Regexp, 0, len(c.ExtCommunityList))
	subtypeList := make([]bgp.ExtendedCommunityAttrSubType, 0, len(c.ExtCommunityList))
	for _, x := range c.ExtCommunityList {
		subtype, exp, err := ParseExtCommunityRegexp(x)
		if err != nil {
			return nil, err
		}
		list = append(list, exp)
		subtypeList = append(subtypeList, subtype)
	}
	return &ExtCommunitySet{
		regExpSet: regExpSet{
			typ:  DEFINED_TYPE_EXT_COMMUNITY,
			name: name,
			list: list,
		},
		subtypeList: subtypeList,
	}, nil
}

type Condition interface {
	Name() string
	Type() ConditionType
	Evaluate(*Path, *PolicyOptions) bool
	Set() DefinedSet
}

type PrefixCondition struct {
	name   string
	set    *PrefixSet
	option MatchOption
}

func (c *PrefixCondition) Type() ConditionType {
	return CONDITION_PREFIX
}

func (c *PrefixCondition) Set() DefinedSet {
	return c.set
}

func (c *PrefixCondition) Option() MatchOption {
	return c.option
}

// compare prefixes in this condition and nlri of path and
// subsequent comparison is skipped if that matches the conditions.
// If PrefixList's length is zero, return true.
func (c *PrefixCondition) Evaluate(path *Path, _ *PolicyOptions) bool {
	var key string
	var masklen uint8
	keyf := func(ip net.IP, ones int) string {
		var buffer bytes.Buffer
		for i := 0; i < len(ip) && i < ones; i++ {
			buffer.WriteString(fmt.Sprintf("%08b", ip[i]))
		}
		return buffer.String()[:ones]
	}
	switch path.GetRouteFamily() {
	case bgp.RF_IPv4_UC:
		masklen = path.GetNlri().(*bgp.IPAddrPrefix).Length
		key = keyf(path.GetNlri().(*bgp.IPAddrPrefix).Prefix, int(masklen))
	case bgp.RF_IPv6_UC:
		masklen = path.GetNlri().(*bgp.IPv6AddrPrefix).Length
		key = keyf(path.GetNlri().(*bgp.IPv6AddrPrefix).Prefix, int(masklen))
	default:
		return false
	}

	result := false
	_, p, ok := c.set.tree.LongestPrefix(key)
	if ok && p.(*Prefix).MasklengthRangeMin <= masklen && masklen <= p.(*Prefix).MasklengthRangeMax {
		result = true
	}

	if c.option == MATCH_OPTION_INVERT {
		result = !result
	}

	return result
}

func (c *PrefixCondition) Name() string { return c.name }

func NewPrefixCondition(c config.MatchPrefixSet) (*PrefixCondition, error) {
	if c.PrefixSet == "" {
		return nil, nil
	}
	o, err := NewMatchOption(c.MatchSetOptions)
	if err != nil {
		return nil, err
	}
	return &PrefixCondition{
		name:   c.PrefixSet,
		option: o,
	}, nil
}

type NeighborCondition struct {
	name   string
	set    *NeighborSet
	option MatchOption
}

func (c *NeighborCondition) Type() ConditionType {
	return CONDITION_NEIGHBOR
}

func (c *NeighborCondition) Set() DefinedSet {
	return c.set
}

func (c *NeighborCondition) Option() MatchOption {
	return c.option
}

// compare neighbor ipaddress of this condition and source address of path
// and, subsequent comparisons are skipped if that matches the conditions.
// If NeighborList's length is zero, return true.
func (c *NeighborCondition) Evaluate(path *Path, options *PolicyOptions) bool {

	if len(c.set.list) == 0 {
		log.WithFields(log.Fields{
			"Topic": "Policy",
		}).Debug("NeighborList doesn't have elements")
		return true
	}

	neighbor := path.GetSource().Address
	if options != nil && options.Info != nil && options.Info.Address != nil {
		neighbor = options.Info.Address
	}

	if neighbor == nil {
		return false
	}
	result := false
	for _, n := range c.set.list {
		if neighbor.Equal(n) {
			result = true
			break
		}
	}

	if c.option == MATCH_OPTION_INVERT {
		result = !result
	}

	return result
}

func (c *NeighborCondition) Name() string { return c.name }

func NewNeighborCondition(c config.MatchNeighborSet) (*NeighborCondition, error) {
	if c.NeighborSet == "" {
		return nil, nil
	}
	o, err := NewMatchOption(c.MatchSetOptions)
	if err != nil {
		return nil, err
	}
	return &NeighborCondition{
		name:   c.NeighborSet,
		option: o,
	}, nil
}

type AsPathCondition struct {
	name   string
	set    *AsPathSet
	option MatchOption
}

func (c *AsPathCondition) Type() ConditionType {
	return CONDITION_AS_PATH
}

func (c *AsPathCondition) Set() DefinedSet {
	return c.set
}

func (c *AsPathCondition) Option() MatchOption {
	return c.option
}

func (c *AsPathCondition) Evaluate(path *Path, _ *PolicyOptions) bool {
	if len(c.set.singleList) > 0 {
		aspath := path.GetAsSeqList()
		for _, m := range c.set.singleList {
			result := m.Match(aspath)
			if c.option == MATCH_OPTION_ALL && !result {
				return false
			}
			if c.option == MATCH_OPTION_ANY && result {
				return true
			}
			if c.option == MATCH_OPTION_INVERT && result {
				return false
			}
		}
	}
	if len(c.set.list) > 0 {
		aspath := path.GetAsString()
		for _, r := range c.set.list {
			result := r.MatchString(aspath)
			if c.option == MATCH_OPTION_ALL && !result {
				return false
			}
			if c.option == MATCH_OPTION_ANY && result {
				return true
			}
			if c.option == MATCH_OPTION_INVERT && result {
				return false
			}
		}
	}
	if c.option == MATCH_OPTION_ANY {
		return false
	}
	return true
}

func (c *AsPathCondition) Name() string { return c.name }

func NewAsPathCondition(c config.MatchAsPathSet) (*AsPathCondition, error) {
	if c.AsPathSet == "" {
		return nil, nil
	}
	o, err := NewMatchOption(c.MatchSetOptions)
	if err != nil {
		return nil, err
	}
	return &AsPathCondition{
		name:   c.AsPathSet,
		option: o,
	}, nil
}

type CommunityCondition struct {
	name   string
	set    *CommunitySet
	option MatchOption
}

func (c *CommunityCondition) Type() ConditionType {
	return CONDITION_COMMUNITY
}

func (c *CommunityCondition) Set() DefinedSet {
	return c.set
}

func (c *CommunityCondition) Option() MatchOption {
	return c.option
}

func (c *CommunityCondition) Evaluate(path *Path, _ *PolicyOptions) bool {
	cs := path.GetCommunities()
	result := false
	for _, x := range c.set.list {
		result = false
		for _, y := range cs {
			if x.MatchString(fmt.Sprintf("%d:%d", y>>16, y&0x0000ffff)) {
				result = true
				break
			}
		}
		if c.option == MATCH_OPTION_ALL && !result {
			break
		}
		if (c.option == MATCH_OPTION_ANY || c.option == MATCH_OPTION_INVERT) && result {
			break
		}
	}
	if c.option == MATCH_OPTION_INVERT {
		result = !result
	}
	return result
}

func (c *CommunityCondition) Name() string { return c.name }

func NewCommunityCondition(c config.MatchCommunitySet) (*CommunityCondition, error) {
	if c.CommunitySet == "" {
		return nil, nil
	}
	o, err := NewMatchOption(c.MatchSetOptions)
	if err != nil {
		return nil, err
	}
	return &CommunityCondition{
		name:   c.CommunitySet,
		option: o,
	}, nil
}

type ExtCommunityCondition struct {
	name   string
	set    *ExtCommunitySet
	option MatchOption
}

func (c *ExtCommunityCondition) Type() ConditionType {
	return CONDITION_EXT_COMMUNITY
}

func (c *ExtCommunityCondition) Set() DefinedSet {
	return c.set
}

func (c *ExtCommunityCondition) Option() MatchOption {
	return c.option
}

func (c *ExtCommunityCondition) Evaluate(path *Path, _ *PolicyOptions) bool {
	es := path.GetExtCommunities()
	result := false
	for _, x := range es {
		result = false
		typ, subtype := x.GetTypes()
		// match only with transitive community. see RFC7153
		if typ >= 0x3f {
			continue
		}
		for idx, y := range c.set.list {
			if subtype == c.set.subtypeList[idx] && y.MatchString(x.String()) {
				result = true
				break
			}
		}
		if c.option == MATCH_OPTION_ALL && !result {
			break
		}
		if c.option == MATCH_OPTION_ANY && result {
			break
		}
	}
	if c.option == MATCH_OPTION_INVERT {
		result = !result
	}
	return result
}

func (c *ExtCommunityCondition) Name() string { return c.name }

func NewExtCommunityCondition(c config.MatchExtCommunitySet) (*ExtCommunityCondition, error) {
	if c.ExtCommunitySet == "" {
		return nil, nil
	}
	o, err := NewMatchOption(c.MatchSetOptions)
	if err != nil {
		return nil, err
	}
	return &ExtCommunityCondition{
		name:   c.ExtCommunitySet,
		option: o,
	}, nil
}

type AsPathLengthCondition struct {
	length   uint32
	operator AttributeComparison
}

func (c *AsPathLengthCondition) Type() ConditionType {
	return CONDITION_AS_PATH_LENGTH
}

// compare AS_PATH length in the message's AS_PATH attribute with
// the one in condition.
func (c *AsPathLengthCondition) Evaluate(path *Path, _ *PolicyOptions) bool {

	length := uint32(path.GetAsPathLen())
	result := false
	switch c.operator {
	case ATTRIBUTE_EQ:
		result = c.length == length
	case ATTRIBUTE_GE:
		result = c.length <= length
	case ATTRIBUTE_LE:
		result = c.length >= length
	}

	return result
}

func (c *AsPathLengthCondition) Set() DefinedSet {
	return nil
}

func (c *AsPathLengthCondition) Name() string { return "" }

func NewAsPathLengthCondition(c config.AsPathLength) (*AsPathLengthCondition, error) {
	if c.Value == 0 && c.Operator == "" {
		return nil, nil
	}
	var op AttributeComparison
	if i := c.Operator.ToInt(); i < 0 {
		return nil, fmt.Errorf("invalid as path length operator: %s", c.Operator)
	} else {
		// take mod 3 because we have extended openconfig attribute-comparison
		// for simple configuration. see config.AttributeComparison definition
		op = AttributeComparison(i % 3)
	}
	return &AsPathLengthCondition{
		length:   c.Value,
		operator: op,
	}, nil
}

type RpkiValidationCondition struct {
	result config.RpkiValidationResultType
}

func (c *RpkiValidationCondition) Type() ConditionType {
	return CONDITION_RPKI
}

func (c *RpkiValidationCondition) Evaluate(path *Path, _ *PolicyOptions) bool {
	return c.result == path.Validation()
}

func (c *RpkiValidationCondition) Set() DefinedSet {
	return nil
}

func (c *RpkiValidationCondition) Name() string { return "" }

func NewRpkiValidationCondition(c config.RpkiValidationResultType) (*RpkiValidationCondition, error) {
	if c == config.RPKI_VALIDATION_RESULT_TYPE_NONE {
		return nil, nil
	}
	return &RpkiValidationCondition{
		result: c,
	}, nil
}

type Action interface {
	Type() ActionType
	Apply(*Path, *PolicyOptions) *Path
}

type RoutingAction struct {
	AcceptRoute bool
}

func (a *RoutingAction) Type() ActionType {
	return ACTION_ROUTING
}

func (a *RoutingAction) Apply(path *Path, _ *PolicyOptions) *Path {
	if a.AcceptRoute {
		return path
	}
	return nil
}

func NewRoutingAction(c config.RouteDisposition) (*RoutingAction, error) {
	if c.AcceptRoute == c.RejectRoute && c.AcceptRoute {
		return nil, fmt.Errorf("invalid route disposition")
	}
	accept := false
	if c.AcceptRoute && !c.RejectRoute {
		accept = true
	}
	return &RoutingAction{
		AcceptRoute: accept,
	}, nil
}

type CommunityAction struct {
	action     config.BgpSetCommunityOptionType
	list       []uint32
	removeList []*regexp.Regexp
}

func RegexpRemoveCommunities(path *Path, exps []*regexp.Regexp) {
	comms := path.GetCommunities()
	newComms := make([]uint32, 0, len(comms))
	for _, comm := range comms {
		c := fmt.Sprintf("%d:%d", comm>>16, comm&0x0000ffff)
		match := false
		for _, exp := range exps {
			if exp.MatchString(c) {
				match = true
				break
			}
		}
		if match == false {
			newComms = append(newComms, comm)
		}
	}
	path.SetCommunities(newComms, true)
}

func RegexpRemoveExtCommunities(path *Path, exps []*regexp.Regexp, subtypes []bgp.ExtendedCommunityAttrSubType) {
	comms := path.GetExtCommunities()
	newComms := make([]bgp.ExtendedCommunityInterface, 0, len(comms))
	for _, comm := range comms {
		match := false
		typ, subtype := comm.GetTypes()
		// match only with transitive community. see RFC7153
		if typ >= 0x3f {
			continue
		}
		for idx, exp := range exps {
			if subtype == subtypes[idx] && exp.MatchString(comm.String()) {
				match = true
				break
			}
		}
		if match == false {
			newComms = append(newComms, comm)
		}
	}
	path.SetExtCommunities(newComms, true)
}

func (a *CommunityAction) Type() ActionType {
	return ACTION_COMMUNITY
}

func (a *CommunityAction) Apply(path *Path, _ *PolicyOptions) *Path {
	switch a.action {
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_ADD:
		path.SetCommunities(a.list, false)
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE:
		RegexpRemoveCommunities(path, a.removeList)
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_REPLACE:
		path.SetCommunities(a.list, true)
	}
	return path
}

func (a *CommunityAction) ToConfig() *config.SetCommunity {
	cs := make([]string, 0, len(a.list)+len(a.removeList))
	for _, comm := range a.list {
		c := fmt.Sprintf("%d:%d", comm>>16, comm&0x0000ffff)
		cs = append(cs, c)
	}
	for _, exp := range a.removeList {
		cs = append(cs, exp.String())
	}
	return &config.SetCommunity{
		Options:            string(a.action),
		SetCommunityMethod: config.SetCommunityMethod{CommunitiesList: cs},
	}
}

func NewCommunityAction(c config.SetCommunity) (*CommunityAction, error) {
	a, ok := CommunityOptionValueMap[strings.ToLower(c.Options)]
	if !ok {
		if len(c.SetCommunityMethod.CommunitiesList) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("invalid option name: %s", c.Options)
	}
	var list []uint32
	var removeList []*regexp.Regexp
	if a == config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE {
		removeList = make([]*regexp.Regexp, 0, len(c.SetCommunityMethod.CommunitiesList))
	} else {
		list = make([]uint32, 0, len(c.SetCommunityMethod.CommunitiesList))
	}
	for _, x := range c.SetCommunityMethod.CommunitiesList {
		if a == config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE {
			exp, err := ParseCommunityRegexp(x)
			if err != nil {
				return nil, err
			}
			removeList = append(removeList, exp)
		} else {
			comm, err := ParseCommunity(x)
			if err != nil {
				return nil, err
			}
			list = append(list, comm)
		}
	}
	return &CommunityAction{
		action:     a,
		list:       list,
		removeList: removeList,
	}, nil
}

type ExtCommunityAction struct {
	action      config.BgpSetCommunityOptionType
	list        []bgp.ExtendedCommunityInterface
	removeList  []*regexp.Regexp
	subtypeList []bgp.ExtendedCommunityAttrSubType
}

func (a *ExtCommunityAction) Type() ActionType {
	return ACTION_EXT_COMMUNITY
}

func (a *ExtCommunityAction) Apply(path *Path, _ *PolicyOptions) *Path {
	switch a.action {
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_ADD:
		path.SetExtCommunities(a.list, false)
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE:
		RegexpRemoveExtCommunities(path, a.removeList, a.subtypeList)
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_REPLACE:
		path.SetExtCommunities(a.list, true)
	}
	return path
}

func (a *ExtCommunityAction) ToConfig() *config.SetExtCommunity {
	cs := make([]string, 0, len(a.list)+len(a.removeList))
	f := func(idx int, arg string) string {
		switch a.subtypeList[idx] {
		case bgp.EC_SUBTYPE_ROUTE_TARGET:
			return fmt.Sprintf("rt:%s", arg)
		case bgp.EC_SUBTYPE_ROUTE_ORIGIN:
			return fmt.Sprintf("soo:%s", arg)
		case bgp.EC_SUBTYPE_ORIGIN_VALIDATION:
			return arg
		default:
			return fmt.Sprintf("%d:%s", a.subtypeList[idx], arg)
		}
	}
	for idx, c := range a.list {
		cs = append(cs, f(idx, c.String()))
	}
	for idx, exp := range a.removeList {
		cs = append(cs, f(idx, exp.String()))
	}
	return &config.SetExtCommunity{
		Options: string(a.action),
		SetExtCommunityMethod: config.SetExtCommunityMethod{
			CommunitiesList: cs,
		},
	}
}

func NewExtCommunityAction(c config.SetExtCommunity) (*ExtCommunityAction, error) {
	a, ok := CommunityOptionValueMap[strings.ToLower(c.Options)]
	if !ok {
		if len(c.SetExtCommunityMethod.CommunitiesList) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("invalid option name: %s", c.Options)
	}
	var list []bgp.ExtendedCommunityInterface
	var removeList []*regexp.Regexp
	subtypeList := make([]bgp.ExtendedCommunityAttrSubType, 0, len(c.SetExtCommunityMethod.CommunitiesList))
	if a == config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE {
		removeList = make([]*regexp.Regexp, 0, len(c.SetExtCommunityMethod.CommunitiesList))
	} else {
		list = make([]bgp.ExtendedCommunityInterface, 0, len(c.SetExtCommunityMethod.CommunitiesList))
	}
	for _, x := range c.SetExtCommunityMethod.CommunitiesList {
		if a == config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE {
			subtype, exp, err := ParseExtCommunityRegexp(x)
			if err != nil {
				return nil, err
			}
			removeList = append(removeList, exp)
			subtypeList = append(subtypeList, subtype)
		} else {
			comm, err := ParseExtCommunity(x)
			if err != nil {
				return nil, err
			}
			list = append(list, comm)
			_, subtype := comm.GetTypes()
			subtypeList = append(subtypeList, subtype)
		}
	}
	return &ExtCommunityAction{
		action:      a,
		list:        list,
		removeList:  removeList,
		subtypeList: subtypeList,
	}, nil
}

type MedAction struct {
	value  int
	action MedActionType
}

func (a *MedAction) Type() ActionType {
	return ACTION_MED
}

func (a *MedAction) Apply(path *Path, _ *PolicyOptions) *Path {
	var err error
	switch a.action {
	case MED_ACTION_MOD:
		err = path.SetMed(int64(a.value), false)
	case MED_ACTION_REPLACE:
		err = path.SetMed(int64(a.value), true)
	}

	if err != nil {
		log.WithFields(log.Fields{
			"Topic": "Policy",
			"Type":  "Med Action",
			"Error": err,
		}).Warn("Could not set Med on path")
	}
	return path
}

func (a *MedAction) ToConfig() config.BgpSetMedType {
	if a.action == MED_ACTION_MOD && a.value > 0 {
		return config.BgpSetMedType(fmt.Sprintf("+%d", a.value))
	}
	return config.BgpSetMedType(fmt.Sprintf("%d", a.value))
}

func NewMedAction(c config.BgpSetMedType) (*MedAction, error) {
	if string(c) == "" {
		return nil, nil
	}
	exp := regexp.MustCompile("^(\\+|\\-)?(\\d+)$")
	elems := exp.FindStringSubmatch(string(c))
	if len(elems) != 3 {
		return nil, fmt.Errorf("invalid med action format")
	}
	action := MED_ACTION_REPLACE
	switch elems[1] {
	case "+", "-":
		action = MED_ACTION_MOD
	}
	value, _ := strconv.Atoi(string(c))
	return &MedAction{
		value:  value,
		action: action,
	}, nil
}

func NewMedActionFromApiStruct(action MedActionType, value int) *MedAction {
	return &MedAction{action: action, value: value}
}

type LocalPrefAction struct {
	value uint32
}

func (a *LocalPrefAction) Type() ActionType {
	return ACTION_LOCAL_PREF
}

func (a *LocalPrefAction) Apply(path *Path, _ *PolicyOptions) *Path {
	path.setPathAttr(bgp.NewPathAttributeLocalPref(a.value))
	return path
}

func (a *LocalPrefAction) ToConfig() uint32 {
	return a.value
}

func NewLocalPrefAction(value uint32) (*LocalPrefAction, error) {
	if value == 0 {
		return nil, nil
	}
	return &LocalPrefAction{
		value: value,
	}, nil
}

type AsPathPrependAction struct {
	asn         uint32
	useLeftMost bool
	repeat      uint8
}

func (a *AsPathPrependAction) Type() ActionType {
	return ACTION_AS_PATH_PREPEND
}

func (a *AsPathPrependAction) Apply(path *Path, _ *PolicyOptions) *Path {
	var asn uint32
	if a.useLeftMost {
		aspath := path.GetAsSeqList()
		if len(aspath) == 0 {
			log.WithFields(log.Fields{
				"Topic": "Policy",
				"Type":  "AsPathPrepend Action",
			}).Warn("aspath length is zero.")
			return path
		}
		asn = aspath[0]
		if asn == 0 {
			log.WithFields(log.Fields{
				"Topic": "Policy",
				"Type":  "AsPathPrepend Action",
			}).Warn("left-most ASN is not seq")
			return path
		}
	} else {
		asn = a.asn
	}

	path.PrependAsn(asn, a.repeat)

	return path
}

func (a *AsPathPrependAction) ToConfig() *config.SetAsPathPrepend {
	return &config.SetAsPathPrepend{
		RepeatN: uint8(a.repeat),
		As: func() string {
			if a.useLeftMost {
				return "last-as"
			}
			return fmt.Sprintf("%d", a.asn)
		}(),
	}
}

// NewAsPathPrependAction creates AsPathPrependAction object.
// If ASN cannot be parsed, nil will be returned.
func NewAsPathPrependAction(action config.SetAsPathPrepend) (*AsPathPrependAction, error) {
	a := &AsPathPrependAction{
		repeat: action.RepeatN,
	}
	switch action.As {
	case "":
		if a.repeat == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("specify as to prepend")
	case "last-as":
		a.useLeftMost = true
	default:
		asn, err := strconv.Atoi(action.As)
		if err != nil {
			return nil, fmt.Errorf("As number string invalid")
		}
		a.asn = uint32(asn)
	}
	return a, nil
}

type NexthopAction struct {
	value net.IP
	self  bool
}

func (a *NexthopAction) Type() ActionType {
	return ACTION_NEXTHOP
}

func (a *NexthopAction) Apply(path *Path, options *PolicyOptions) *Path {
	if a.self {
		if options != nil && options.Info != nil && options.Info.LocalAddress != nil {
			path.SetNexthop(options.Info.LocalAddress)
		}
		return path
	}
	path.SetNexthop(a.value)
	return path
}

func (a *NexthopAction) ToConfig() config.BgpNextHopType {
	if a.self {
		return config.BgpNextHopType("self")
	}
	return config.BgpNextHopType(a.value.String())
}

func NewNexthopAction(c config.BgpNextHopType) (*NexthopAction, error) {
	switch string(c) {
	case "":
		return nil, nil
	case "self":
		return &NexthopAction{
			self: true,
		}, nil
	}
	addr := net.ParseIP(string(c))
	if addr == nil {
		return nil, fmt.Errorf("invalid ip address format: %s", string(c))
	}
	return &NexthopAction{
		value: addr,
	}, nil
}

type Statement struct {
	Name        string
	Conditions  []Condition
	RouteAction Action
	ModActions  []Action
}

// evaluate each condition in the statement according to MatchSetOptions
func (s *Statement) Evaluate(p *Path, options *PolicyOptions) bool {
	for _, c := range s.Conditions {
		if !c.Evaluate(p, options) {
			return false
		}
	}
	return true
}

func (s *Statement) Apply(path *Path, options *PolicyOptions) (RouteType, *Path) {
	result := s.Evaluate(path, options)
	if result {
		if len(s.ModActions) != 0 {
			// apply all modification actions
			path = path.Clone(path.IsWithdraw)
			for _, action := range s.ModActions {
				path = action.Apply(path, options)
			}
		}
		//Routing action
		if s.RouteAction == nil || reflect.ValueOf(s.RouteAction).IsNil() {
			log.WithFields(log.Fields{
				"Topic":      "Policy",
				"Path":       path,
				"PolicyName": s.Name,
			}).Warn("route action is nil")
			return ROUTE_TYPE_NONE, path
		}
		p := s.RouteAction.Apply(path, options)
		if p == nil {
			return ROUTE_TYPE_REJECT, path
		}
		return ROUTE_TYPE_ACCEPT, path
	}
	return ROUTE_TYPE_NONE, path
}

func (s *Statement) ToConfig() *config.Statement {
	return &config.Statement{
		Name: s.Name,
		Conditions: func() config.Conditions {
			cond := config.Conditions{}
			for _, c := range s.Conditions {
				switch c.(type) {
				case *PrefixCondition:
					v := c.(*PrefixCondition)
					cond.MatchPrefixSet = config.MatchPrefixSet{PrefixSet: v.set.Name(), MatchSetOptions: config.IntToMatchSetOptionsRestrictedTypeMap[int(v.option)]}
				case *NeighborCondition:
					v := c.(*NeighborCondition)
					cond.MatchNeighborSet = config.MatchNeighborSet{NeighborSet: v.set.Name(), MatchSetOptions: config.IntToMatchSetOptionsRestrictedTypeMap[int(v.option)]}
				case *AsPathLengthCondition:
					v := c.(*AsPathLengthCondition)
					cond.BgpConditions.AsPathLength = config.AsPathLength{Operator: config.IntToAttributeComparisonMap[int(v.operator)], Value: v.length}
				case *AsPathCondition:
					v := c.(*AsPathCondition)
					cond.BgpConditions.MatchAsPathSet = config.MatchAsPathSet{AsPathSet: v.set.Name(), MatchSetOptions: config.IntToMatchSetOptionsTypeMap[int(v.option)]}
				case *CommunityCondition:
					v := c.(*CommunityCondition)
					cond.BgpConditions.MatchCommunitySet = config.MatchCommunitySet{CommunitySet: v.set.Name(), MatchSetOptions: config.IntToMatchSetOptionsTypeMap[int(v.option)]}
				case *ExtCommunityCondition:
					v := c.(*ExtCommunityCondition)
					cond.BgpConditions.MatchExtCommunitySet = config.MatchExtCommunitySet{ExtCommunitySet: v.set.Name(), MatchSetOptions: config.IntToMatchSetOptionsTypeMap[int(v.option)]}
				case *RpkiValidationCondition:
					v := c.(*RpkiValidationCondition)
					cond.BgpConditions.RpkiValidationResult = v.result
				}
			}
			return cond
		}(),
		Actions: func() config.Actions {
			act := config.Actions{}
			if s.RouteAction != nil && !reflect.ValueOf(s.RouteAction).IsNil() {
				a := s.RouteAction.(*RoutingAction)
				act.RouteDisposition = config.RouteDisposition{AcceptRoute: a.AcceptRoute, RejectRoute: false}
			}
			for _, a := range s.ModActions {
				switch a.(type) {
				case *AsPathPrependAction:
					act.BgpActions.SetAsPathPrepend = *a.(*AsPathPrependAction).ToConfig()
				case *CommunityAction:
					act.BgpActions.SetCommunity = *a.(*CommunityAction).ToConfig()
				case *ExtCommunityAction:
					act.BgpActions.SetExtCommunity = *a.(*ExtCommunityAction).ToConfig()
				case *MedAction:
					act.BgpActions.SetMed = a.(*MedAction).ToConfig()
				case *LocalPrefAction:
					act.BgpActions.SetLocalPref = a.(*LocalPrefAction).ToConfig()
				case *NexthopAction:
					act.BgpActions.SetNextHop = a.(*NexthopAction).ToConfig()
				}
			}
			return act
		}(),
	}
}

type opType int

const (
	ADD opType = iota
	REMOVE
	REPLACE
)

func (lhs *Statement) mod(op opType, rhs *Statement) error {
	cs := make([]Condition, len(lhs.Conditions))
	copy(cs, lhs.Conditions)
	ra := lhs.RouteAction
	as := make([]Action, len(lhs.ModActions))
	copy(as, lhs.ModActions)
	for _, x := range rhs.Conditions {
		var c Condition
		i := 0
		for idx, y := range lhs.Conditions {
			if x.Type() == y.Type() {
				c = y
				i = idx
				break
			}
		}
		switch op {
		case ADD:
			if c != nil {
				return fmt.Errorf("condition %d is already set", x.Type())
			}
			if cs == nil {
				cs = make([]Condition, 0, len(rhs.Conditions))
			}
			cs = append(cs, x)
		case REMOVE:
			if c == nil {
				return fmt.Errorf("condition %d is not set", x.Type())
			}
			cs = append(cs[:i], cs[i+1:]...)
			if len(cs) == 0 {
				cs = nil
			}
		case REPLACE:
			if c == nil {
				return fmt.Errorf("condition %d is not set", x.Type())
			}
			cs[i] = x
		}
	}
	if rhs.RouteAction != nil && !reflect.ValueOf(rhs.RouteAction).IsNil() {
		switch op {
		case ADD:
			if lhs.RouteAction != nil && !reflect.ValueOf(lhs.RouteAction).IsNil() {
				return fmt.Errorf("route action is already set")
			}
			ra = rhs.RouteAction
		case REMOVE:
			if lhs.RouteAction == nil || reflect.ValueOf(lhs.RouteAction).IsNil() {
				return fmt.Errorf("route action is not set")
			}
			ra = nil
		case REPLACE:
			if lhs.RouteAction == nil || reflect.ValueOf(lhs.RouteAction).IsNil() {
				return fmt.Errorf("route action is not set")
			}
			ra = rhs.RouteAction
		}
	}
	for _, x := range rhs.ModActions {
		var a Action
		i := 0
		for idx, y := range lhs.ModActions {
			if x.Type() == y.Type() {
				a = y
				i = idx
				break
			}
		}
		switch op {
		case ADD:
			if a != nil {
				return fmt.Errorf("action %d is already set", x.Type())
			}
			if as == nil {
				as = make([]Action, 0, len(rhs.ModActions))
			}
			as = append(as, x)
		case REMOVE:
			if a == nil {
				return fmt.Errorf("action %d is not set", x.Type())
			}
			as = append(as[:i], as[i+1:]...)
			if len(as) == 0 {
				as = nil
			}
		case REPLACE:
			if a == nil {
				return fmt.Errorf("action %d is not set", x.Type())
			}
			as[i] = x
		}
	}
	lhs.Conditions = cs
	lhs.RouteAction = ra
	lhs.ModActions = as
	return nil
}

func (lhs *Statement) Add(rhs *Statement) error {
	return lhs.mod(ADD, rhs)
}

func (lhs *Statement) Remove(rhs *Statement) error {
	return lhs.mod(REMOVE, rhs)
}

func (lhs *Statement) Replace(rhs *Statement) error {
	return lhs.mod(REPLACE, rhs)
}

func NewStatement(c config.Statement) (*Statement, error) {
	if c.Name == "" {
		return nil, fmt.Errorf("empty statement name")
	}
	var ra Action
	var as []Action
	var cs []Condition
	var err error
	cfs := []func() (Condition, error){
		func() (Condition, error) {
			return NewPrefixCondition(c.Conditions.MatchPrefixSet)
		},
		func() (Condition, error) {
			return NewNeighborCondition(c.Conditions.MatchNeighborSet)
		},
		func() (Condition, error) {
			return NewAsPathLengthCondition(c.Conditions.BgpConditions.AsPathLength)
		},
		func() (Condition, error) {
			return NewRpkiValidationCondition(c.Conditions.BgpConditions.RpkiValidationResult)
		},
		func() (Condition, error) {
			return NewAsPathCondition(c.Conditions.BgpConditions.MatchAsPathSet)
		},
		func() (Condition, error) {
			return NewCommunityCondition(c.Conditions.BgpConditions.MatchCommunitySet)
		},
		func() (Condition, error) {
			return NewExtCommunityCondition(c.Conditions.BgpConditions.MatchExtCommunitySet)
		},
	}
	cs = make([]Condition, 0, len(cfs))
	for _, f := range cfs {
		c, err := f()
		if err != nil {
			return nil, err
		}
		if !reflect.ValueOf(c).IsNil() {
			cs = append(cs, c)
		}
	}
	ra, err = NewRoutingAction(c.Actions.RouteDisposition)
	if err != nil {
		return nil, err
	}
	afs := []func() (Action, error){
		func() (Action, error) {
			return NewCommunityAction(c.Actions.BgpActions.SetCommunity)
		},
		func() (Action, error) {
			return NewExtCommunityAction(c.Actions.BgpActions.SetExtCommunity)
		},
		func() (Action, error) {
			return NewMedAction(c.Actions.BgpActions.SetMed)
		},
		func() (Action, error) {
			return NewLocalPrefAction(c.Actions.BgpActions.SetLocalPref)
		},
		func() (Action, error) {
			return NewAsPathPrependAction(c.Actions.BgpActions.SetAsPathPrepend)
		},
		func() (Action, error) {
			return NewNexthopAction(c.Actions.BgpActions.SetNextHop)
		},
	}
	as = make([]Action, 0, len(afs))
	for _, f := range afs {
		a, err := f()
		if err != nil {
			return nil, err
		}
		if !reflect.ValueOf(a).IsNil() {
			as = append(as, a)
		}
	}
	return &Statement{
		Name:        c.Name,
		Conditions:  cs,
		RouteAction: ra,
		ModActions:  as,
	}, nil
}

type Policy struct {
	Name       string
	Statements []*Statement
}

// Compare path with a policy's condition in stored order in the policy.
// If a condition match, then this function stops evaluation and
// subsequent conditions are skipped.
func (p *Policy) Apply(path *Path, options *PolicyOptions) (RouteType, *Path) {
	for _, stmt := range p.Statements {
		var result RouteType
		result, path = stmt.Apply(path, options)
		if result != ROUTE_TYPE_NONE {
			return result, path
		}
	}
	return ROUTE_TYPE_NONE, path
}

func (p *Policy) ToConfig() *config.PolicyDefinition {
	ss := make([]config.Statement, 0, len(p.Statements))
	for _, s := range p.Statements {
		ss = append(ss, *s.ToConfig())
	}
	return &config.PolicyDefinition{
		Name:       p.Name,
		Statements: ss,
	}
}

func (p *Policy) FillUp(m map[string]*Statement) error {
	stmts := make([]*Statement, 0, len(p.Statements))
	for _, x := range p.Statements {
		y, ok := m[x.Name]
		if !ok {
			return fmt.Errorf("not found statement %s", x.Name)
		}
		stmts = append(stmts, y)
	}
	p.Statements = stmts
	return nil
}

func (lhs *Policy) Add(rhs *Policy) error {
	lhs.Statements = append(lhs.Statements, rhs.Statements...)
	return nil
}

func (lhs *Policy) Remove(rhs *Policy) error {
	stmts := make([]*Statement, 0, len(lhs.Statements))
	for _, x := range lhs.Statements {
		found := false
		for _, y := range rhs.Statements {
			if x.Name == y.Name {
				found = true
				break
			}
		}
		if !found {
			stmts = append(stmts, x)
		}
	}
	lhs.Statements = stmts
	return nil
}

func (lhs *Policy) Replace(rhs *Policy) error {
	lhs.Statements = rhs.Statements
	return nil
}

func NewPolicy(c config.PolicyDefinition) (*Policy, error) {
	if c.Name == "" {
		return nil, fmt.Errorf("empty policy name")
	}
	var st []*Statement
	stmts := c.Statements
	if len(stmts) != 0 {
		st = make([]*Statement, 0, len(stmts))
		for idx, stmt := range stmts {
			if stmt.Name == "" {
				stmt.Name = fmt.Sprintf("%s_stmt%d", c.Name, idx)
			}
			s, err := NewStatement(stmt)
			if err != nil {
				return nil, err
			}
			st = append(st, s)
		}
	}
	return &Policy{
		Name:       c.Name,
		Statements: st,
	}, nil
}

type Assignment struct {
	inPolicies          []*Policy
	defaultInPolicy     RouteType
	importPolicies      []*Policy
	defaultImportPolicy RouteType
	exportPolicies      []*Policy
	defaultExportPolicy RouteType
}

type RoutingPolicy struct {
	definedSetMap DefinedSetMap
	policyMap     map[string]*Policy
	statementMap  map[string]*Statement
	assignmentMap map[string]*Assignment
	mu            sync.RWMutex
}

func (r *RoutingPolicy) ApplyPolicy(id string, dir PolicyDirection, before *Path, options *PolicyOptions) *Path {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if before == nil {
		return nil
	}
	if filtered := before.Filtered(id); filtered > POLICY_DIRECTION_NONE && filtered < dir {
		return nil
	}
	if before.IsWithdraw {
		return before
	}
	result := ROUTE_TYPE_NONE
	after := before
	for _, p := range r.getPolicy(id, dir) {
		result, after = p.Apply(before, options)
		if result != ROUTE_TYPE_NONE {
			break
		}
	}
	if result == ROUTE_TYPE_NONE {
		result = r.getDefaultPolicy(id, dir)
	}
	switch result {
	case ROUTE_TYPE_ACCEPT:
		return after
	default:
		return nil
	}
}

func (r *RoutingPolicy) getPolicy(id string, dir PolicyDirection) []*Policy {
	a, ok := r.assignmentMap[id]
	if !ok {
		return nil
	}
	switch dir {
	case POLICY_DIRECTION_IN:
		return a.inPolicies
	case POLICY_DIRECTION_IMPORT:
		return a.importPolicies
	case POLICY_DIRECTION_EXPORT:
		return a.exportPolicies
	default:
		return nil
	}
}

func (r *RoutingPolicy) getDefaultPolicy(id string, dir PolicyDirection) RouteType {
	a, ok := r.assignmentMap[id]
	if !ok {
		return ROUTE_TYPE_NONE
	}
	switch dir {
	case POLICY_DIRECTION_IN:
		return a.defaultInPolicy
	case POLICY_DIRECTION_IMPORT:
		return a.defaultImportPolicy
	case POLICY_DIRECTION_EXPORT:
		return a.defaultExportPolicy
	default:
		return ROUTE_TYPE_NONE
	}

}

func (r *RoutingPolicy) setPolicy(id string, dir PolicyDirection, policies []*Policy) error {
	a, ok := r.assignmentMap[id]
	if !ok {
		a = &Assignment{}
	}
	switch dir {
	case POLICY_DIRECTION_IN:
		a.inPolicies = policies
	case POLICY_DIRECTION_IMPORT:
		a.importPolicies = policies
	case POLICY_DIRECTION_EXPORT:
		a.exportPolicies = policies
	}
	r.assignmentMap[id] = a
	return nil
}

func (r *RoutingPolicy) setDefaultPolicy(id string, dir PolicyDirection, typ RouteType) error {
	a, ok := r.assignmentMap[id]
	if !ok {
		a = &Assignment{}
	}
	switch dir {
	case POLICY_DIRECTION_IN:
		a.defaultInPolicy = typ
	case POLICY_DIRECTION_IMPORT:
		a.defaultImportPolicy = typ
	case POLICY_DIRECTION_EXPORT:
		a.defaultExportPolicy = typ
	}
	r.assignmentMap[id] = a
	return nil
}

func (r *RoutingPolicy) getAssignmentFromConfig(dir PolicyDirection, a config.ApplyPolicy) ([]*Policy, RouteType, error) {
	var names []string
	var cdef config.DefaultPolicyType
	def := ROUTE_TYPE_ACCEPT
	c := a.Config
	switch dir {
	case POLICY_DIRECTION_IN:
		names = c.InPolicyList
		cdef = c.DefaultInPolicy
	case POLICY_DIRECTION_IMPORT:
		names = c.ImportPolicyList
		cdef = c.DefaultImportPolicy
	case POLICY_DIRECTION_EXPORT:
		names = c.ExportPolicyList
		cdef = c.DefaultExportPolicy
	default:
		return nil, def, fmt.Errorf("invalid policy direction")
	}
	if cdef == config.DEFAULT_POLICY_TYPE_REJECT_ROUTE {
		def = ROUTE_TYPE_REJECT
	}
	ps := make([]*Policy, 0, len(names))
	seen := make(map[string]bool)
	for _, name := range names {
		p, ok := r.policyMap[name]
		if !ok {
			return nil, def, fmt.Errorf("not found policy %s", name)
		}
		if seen[name] {
			return nil, def, fmt.Errorf("duplicated policy %s", name)
		}
		seen[name] = true
		ps = append(ps, p)
	}
	return ps, def, nil
}

func (r *RoutingPolicy) validateCondition(v Condition) (err error) {
	switch v.Type() {
	case CONDITION_PREFIX:
		m := r.definedSetMap[DEFINED_TYPE_PREFIX]
		if i, ok := m[v.Name()]; !ok {
			return fmt.Errorf("not found prefix set %s", v.Name())
		} else {
			c := v.(*PrefixCondition)
			c.set = i.(*PrefixSet)
		}
	case CONDITION_NEIGHBOR:
		m := r.definedSetMap[DEFINED_TYPE_NEIGHBOR]
		if i, ok := m[v.Name()]; !ok {
			return fmt.Errorf("not found neighbor set %s", v.Name())
		} else {
			c := v.(*NeighborCondition)
			c.set = i.(*NeighborSet)
		}
	case CONDITION_AS_PATH:
		m := r.definedSetMap[DEFINED_TYPE_AS_PATH]
		if i, ok := m[v.Name()]; !ok {
			return fmt.Errorf("not found as path set %s", v.Name())
		} else {
			c := v.(*AsPathCondition)
			c.set = i.(*AsPathSet)
		}
	case CONDITION_COMMUNITY:
		m := r.definedSetMap[DEFINED_TYPE_COMMUNITY]
		if i, ok := m[v.Name()]; !ok {
			return fmt.Errorf("not found community set %s", v.Name())
		} else {
			c := v.(*CommunityCondition)
			c.set = i.(*CommunitySet)
		}
	case CONDITION_EXT_COMMUNITY:
		m := r.definedSetMap[DEFINED_TYPE_EXT_COMMUNITY]
		if i, ok := m[v.Name()]; !ok {
			return fmt.Errorf("not found ext-community set %s", v.Name())
		} else {
			c := v.(*ExtCommunityCondition)
			c.set = i.(*ExtCommunitySet)
		}
	case CONDITION_AS_PATH_LENGTH:
	case CONDITION_RPKI:
	}
	return nil
}

func (r *RoutingPolicy) inUse(d DefinedSet) bool {
	name := d.Name()
	for _, p := range r.policyMap {
		for _, s := range p.Statements {
			for _, c := range s.Conditions {
				if c.Set().Name() == name {
					return true
				}
			}
		}
	}
	return false
}

func (r *RoutingPolicy) statementInUse(x *Statement) bool {
	for _, p := range r.policyMap {
		for _, y := range p.Statements {
			if x.Name == y.Name {
				return true
			}
		}
	}
	return false
}

func (r *RoutingPolicy) reload(c config.RoutingPolicy) error {
	dmap := make(map[DefinedType]map[string]DefinedSet)
	dmap[DEFINED_TYPE_PREFIX] = make(map[string]DefinedSet)
	d := c.DefinedSets
	for _, x := range d.PrefixSets {
		y, err := NewPrefixSet(x)
		if err != nil {
			return err
		}
		if y == nil {
			return fmt.Errorf("empty prefix set")
		}
		dmap[DEFINED_TYPE_PREFIX][y.Name()] = y
	}
	dmap[DEFINED_TYPE_NEIGHBOR] = make(map[string]DefinedSet)
	for _, x := range d.NeighborSets {
		y, err := NewNeighborSet(x)
		if err != nil {
			return err
		}
		if y == nil {
			return fmt.Errorf("empty neighbor set")
		}
		dmap[DEFINED_TYPE_NEIGHBOR][y.Name()] = y
	}
	//	dmap[DEFINED_TYPE_TAG] = make(map[string]DefinedSet)
	//	for _, x := range c.DefinedSets.TagSets{
	//		y, err := NewTagSet(x)
	//		if err != nil {
	//			return nil, err
	//		}
	//		dmap[DEFINED_TYPE_TAG][y.Name()] = y
	//	}
	bd := c.DefinedSets.BgpDefinedSets
	dmap[DEFINED_TYPE_AS_PATH] = make(map[string]DefinedSet)
	for _, x := range bd.AsPathSets {
		y, err := NewAsPathSet(x)
		if err != nil {
			return err
		}
		if y == nil {
			return fmt.Errorf("empty as path set")
		}
		dmap[DEFINED_TYPE_AS_PATH][y.Name()] = y
	}
	dmap[DEFINED_TYPE_COMMUNITY] = make(map[string]DefinedSet)
	for _, x := range bd.CommunitySets {
		y, err := NewCommunitySet(x)
		if err != nil {
			return err
		}
		if y == nil {
			return fmt.Errorf("empty community set")
		}
		dmap[DEFINED_TYPE_COMMUNITY][y.Name()] = y
	}
	dmap[DEFINED_TYPE_EXT_COMMUNITY] = make(map[string]DefinedSet)
	for _, x := range bd.ExtCommunitySets {
		y, err := NewExtCommunitySet(x)
		if err != nil {
			return err
		}
		if y == nil {
			return fmt.Errorf("empty ext-community set")
		}
		dmap[DEFINED_TYPE_EXT_COMMUNITY][y.Name()] = y
	}
	pmap := make(map[string]*Policy)
	smap := make(map[string]*Statement)
	for _, x := range c.PolicyDefinitions {
		y, err := NewPolicy(x)
		if err != nil {
			return err
		}
		if _, ok := pmap[y.Name]; ok {
			return fmt.Errorf("duplicated policy name. policy name must be unique.")
		}
		pmap[y.Name] = y
		for _, s := range y.Statements {
			_, ok := smap[s.Name]
			if ok {
				return fmt.Errorf("duplicated statement name. statement name must be unique.")
			}
			smap[s.Name] = s
		}
	}

	// hacky
	oldMap := r.definedSetMap
	r.definedSetMap = dmap
	for _, y := range pmap {
		for _, s := range y.Statements {
			for _, c := range s.Conditions {
				if err := r.validateCondition(c); err != nil {
					r.definedSetMap = oldMap
					return err
				}
			}
		}
	}

	r.definedSetMap = dmap
	r.policyMap = pmap
	r.statementMap = smap
	r.assignmentMap = make(map[string]*Assignment)
	return nil
}

func (r *RoutingPolicy) GetDefinedSet(typ DefinedType) (*config.DefinedSets, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	set, ok := r.definedSetMap[typ]
	if !ok {
		return nil, fmt.Errorf("invalid defined-set type: %d", typ)
	}
	sets := &config.DefinedSets{
		PrefixSets:   make([]config.PrefixSet, 0),
		NeighborSets: make([]config.NeighborSet, 0),
		BgpDefinedSets: config.BgpDefinedSets{
			CommunitySets:    make([]config.CommunitySet, 0),
			ExtCommunitySets: make([]config.ExtCommunitySet, 0),
			AsPathSets:       make([]config.AsPathSet, 0),
		},
	}
	for _, s := range set {
		switch s.(type) {
		case *PrefixSet:
			sets.PrefixSets = append(sets.PrefixSets, *s.(*PrefixSet).ToConfig())
		case *NeighborSet:
			sets.NeighborSets = append(sets.NeighborSets, *s.(*NeighborSet).ToConfig())
		case *CommunitySet:
			sets.BgpDefinedSets.CommunitySets = append(sets.BgpDefinedSets.CommunitySets, *s.(*CommunitySet).ToConfig())
		case *ExtCommunitySet:
			sets.BgpDefinedSets.ExtCommunitySets = append(sets.BgpDefinedSets.ExtCommunitySets, *s.(*ExtCommunitySet).ToConfig())
		case *AsPathSet:
			sets.BgpDefinedSets.AsPathSets = append(sets.BgpDefinedSets.AsPathSets, *s.(*AsPathSet).ToConfig())
		}
	}
	return sets, nil
}

func (r *RoutingPolicy) AddDefinedSet(s DefinedSet) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if m, ok := r.definedSetMap[s.Type()]; !ok {
		return fmt.Errorf("invalid defined-set type: %d", s.Type())
	} else {
		if d, ok := m[s.Name()]; ok {
			if err := d.Append(s); err != nil {
				return err
			}
		} else {
			m[s.Name()] = s
		}
	}
	return nil
}

func (r *RoutingPolicy) DeleteDefinedSet(a DefinedSet, all bool) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if m, ok := r.definedSetMap[a.Type()]; !ok {
		err = fmt.Errorf("invalid defined-set type: %d", a.Type())
	} else {
		d, ok := m[a.Name()]
		if !ok {
			return fmt.Errorf("not found defined-set: %s", a.Name())
		}
		if all {
			if r.inUse(d) {
				err = fmt.Errorf("can't delete. defined-set %s is in use", a.Name())
			} else {
				delete(m, a.Name())
			}
		} else {
			err = d.Remove(a)
		}
	}
	return err
}

func (r *RoutingPolicy) ReplaceDefinedSet(a DefinedSet) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if m, ok := r.definedSetMap[a.Type()]; !ok {
		err = fmt.Errorf("invalid defined-set type: %d", a.Type())
	} else {
		if d, ok := m[a.Name()]; !ok {
			err = fmt.Errorf("not found defined-set: %s", a.Name())
		} else {
			err = d.Replace(a)
		}
	}
	return err
}

func (r *RoutingPolicy) GetStatement() []*config.Statement {
	r.mu.RLock()
	defer r.mu.RUnlock()

	l := make([]*config.Statement, 0, len(r.statementMap))
	for _, st := range r.statementMap {
		l = append(l, st.ToConfig())
	}
	return l
}

func (r *RoutingPolicy) AddStatement(st *Statement) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, c := range st.Conditions {
		if err = r.validateCondition(c); err != nil {
			return
		}
	}
	m := r.statementMap
	name := st.Name
	if d, ok := m[name]; ok {
		err = d.Add(st)
	} else {
		m[name] = st
	}

	return err
}

func (r *RoutingPolicy) DeleteStatement(st *Statement, all bool) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	m := r.statementMap
	name := st.Name
	if d, ok := m[name]; ok {
		if all {
			if r.statementInUse(d) {
				err = fmt.Errorf("can't delete. statement %s is in use", name)
			} else {
				delete(m, name)
			}
		} else {
			err = d.Remove(st)
		}
	} else {
		err = fmt.Errorf("not found statement: %s", name)
	}
	return err
}

func (r *RoutingPolicy) ReplaceStatement(st *Statement) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	m := r.statementMap
	name := st.Name
	if d, ok := m[name]; ok {
		err = d.Replace(st)
	} else {
		err = fmt.Errorf("not found statement: %s", name)
	}
	return err
}

func (r *RoutingPolicy) GetAllPolicy() []*config.PolicyDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()

	l := make([]*config.PolicyDefinition, 0, len(r.policyMap))
	for _, p := range r.policyMap {
		l = append(l, p.ToConfig())
	}
	return l
}

func (r *RoutingPolicy) AddPolicy(x *Policy, refer bool) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, st := range x.Statements {
		for _, c := range st.Conditions {
			if err = r.validateCondition(c); err != nil {
				return
			}
		}
	}

	pMap := r.policyMap
	sMap := r.statementMap
	name := x.Name
	y, ok := pMap[name]
	if refer {
		err = x.FillUp(sMap)
	} else {
		for _, st := range x.Statements {
			if _, ok := sMap[st.Name]; ok {
				err = fmt.Errorf("statement %s already defined", st.Name)
				return
			}
			sMap[st.Name] = st
		}
	}
	if ok {
		err = y.Add(x)
	} else {
		pMap[name] = x
	}

	return err
}

func (r *RoutingPolicy) DeletePolicy(x *Policy, all, preserve bool, activeId []string) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	pMap := r.policyMap
	sMap := r.statementMap
	name := x.Name
	y, ok := pMap[name]
	if !ok {
		err = fmt.Errorf("not found policy: %s", name)
		return
	}
	inUse := func(ids []string) bool {
		for _, id := range ids {
			for _, dir := range []PolicyDirection{POLICY_DIRECTION_IN, POLICY_DIRECTION_EXPORT, POLICY_DIRECTION_EXPORT} {
				for _, y := range r.getPolicy(id, dir) {
					if x.Name == y.Name {
						return true
					}
				}
			}
		}
		return false
	}

	if all {
		if inUse(activeId) {
			err = fmt.Errorf("can't delete. policy %s is in use", name)
			return
		}
		log.WithFields(log.Fields{
			"Topic": "Policy",
			"Key":   name,
		}).Debug("delete policy")
		delete(pMap, name)
	} else {
		err = y.Remove(x)
	}
	if err == nil && !preserve {
		for _, st := range y.Statements {
			if !r.statementInUse(st) {
				log.WithFields(log.Fields{
					"Topic": "Policy",
					"Key":   st.Name,
				}).Debug("delete unused statement")
				delete(sMap, st.Name)
			}
		}
	}
	return err
}

func (r *RoutingPolicy) ReplacePolicy(x *Policy, refer, preserve bool) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, st := range x.Statements {
		for _, c := range st.Conditions {
			if err = r.validateCondition(c); err != nil {
				return
			}
		}
	}

	pMap := r.policyMap
	sMap := r.statementMap
	name := x.Name
	y, ok := pMap[name]
	if !ok {
		err = fmt.Errorf("not found policy: %s", name)
		return
	}
	if refer {
		if err = x.FillUp(sMap); err != nil {
			return
		}
	} else {
		for _, st := range x.Statements {
			if _, ok := sMap[st.Name]; ok {
				err = fmt.Errorf("statement %s already defined", st.Name)
				return
			}
			sMap[st.Name] = st
		}
	}

	err = y.Replace(x)
	if err == nil && !preserve {
		for _, st := range y.Statements {
			if !r.statementInUse(st) {
				log.WithFields(log.Fields{
					"Topic": "Policy",
					"Key":   st.Name,
				}).Debug("delete unused statement")
				delete(sMap, st.Name)
			}
		}
	}
	return err
}

func (r *RoutingPolicy) GetPolicyAssignment(id string, dir PolicyDirection) (RouteType, []*config.PolicyDefinition, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rt := r.getDefaultPolicy(id, dir)

	ps := r.getPolicy(id, dir)
	l := make([]*config.PolicyDefinition, 0, len(ps))
	for _, p := range ps {
		l = append(l, p.ToConfig())
	}
	return rt, l, nil
}

func (r *RoutingPolicy) AddPolicyAssignment(id string, dir PolicyDirection, policies []*config.PolicyDefinition, def RouteType) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ps := make([]*Policy, 0, len(policies))
	seen := make(map[string]bool)
	for _, x := range policies {
		p, ok := r.policyMap[x.Name]
		if !ok {
			err = fmt.Errorf("not found policy %s", x.Name)
			return
		}
		if seen[x.Name] {
			err = fmt.Errorf("duplicated policy %s", x.Name)
			return
		}
		seen[x.Name] = true
		ps = append(ps, p)
	}
	cur := r.getPolicy(id, dir)
	if cur == nil {
		err = r.setPolicy(id, dir, ps)
	} else {
		seen = make(map[string]bool)
		ps = append(cur, ps...)
		for _, x := range ps {
			if seen[x.Name] {
				err = fmt.Errorf("duplicated policy %s", x.Name)
				return
			}
			seen[x.Name] = true
		}
		err = r.setPolicy(id, dir, ps)
	}
	if err == nil && def != ROUTE_TYPE_NONE {
		err = r.setDefaultPolicy(id, dir, def)
	}
	return err
}

func (r *RoutingPolicy) DeletePolicyAssignment(id string, dir PolicyDirection, policies []*config.PolicyDefinition, all bool) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ps := make([]*Policy, 0, len(policies))
	seen := make(map[string]bool)
	for _, x := range policies {
		p, ok := r.policyMap[x.Name]
		if !ok {
			err = fmt.Errorf("not found policy %s", x.Name)
			return
		}
		if seen[x.Name] {
			err = fmt.Errorf("duplicated policy %s", x.Name)
			return
		}
		seen[x.Name] = true
		ps = append(ps, p)
	}
	cur := r.getPolicy(id, dir)

	if all {
		err = r.setPolicy(id, dir, nil)
		if err != nil {
			return
		}
		err = r.setDefaultPolicy(id, dir, ROUTE_TYPE_NONE)
	} else {
		n := make([]*Policy, 0, len(cur)-len(ps))
		for _, y := range cur {
			found := false
			for _, x := range ps {
				if x.Name == y.Name {
					found = true
					break
				}
			}
			if !found {
				n = append(n, y)
			}
		}
		err = r.setPolicy(id, dir, n)
	}
	return err
}

func (r *RoutingPolicy) ReplacePolicyAssignment(id string, dir PolicyDirection, policies []*config.PolicyDefinition, def RouteType) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ps := make([]*Policy, 0, len(policies))
	seen := make(map[string]bool)
	for _, x := range policies {
		p, ok := r.policyMap[x.Name]
		if !ok {
			err = fmt.Errorf("not found policy %s", x.Name)
			return
		}
		if seen[x.Name] {
			err = fmt.Errorf("duplicated policy %s", x.Name)
			return
		}
		seen[x.Name] = true
		ps = append(ps, p)
	}
	r.getPolicy(id, dir)
	err = r.setPolicy(id, dir, ps)
	if err == nil && def != ROUTE_TYPE_NONE {
		err = r.setDefaultPolicy(id, dir, def)
	}
	return err
}

func (r *RoutingPolicy) Reset(rp *config.RoutingPolicy, ap map[string]config.ApplyPolicy) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if rp != nil {
		if err := r.reload(*rp); err != nil {
			log.WithFields(log.Fields{
				"Topic": "Policy",
			}).Errorf("failed to create routing policy: %s", err)
			return err
		}
	}

	for id, c := range ap {
		for _, dir := range []PolicyDirection{POLICY_DIRECTION_IN, POLICY_DIRECTION_IMPORT, POLICY_DIRECTION_EXPORT} {
			ps, def, err := r.getAssignmentFromConfig(dir, c)
			if err != nil {
				log.WithFields(log.Fields{
					"Topic": "Policy",
					"Dir":   dir,
				}).Errorf("failed to get policy info: %s", err)
				continue
			}
			r.setDefaultPolicy(id, dir, def)
			r.setPolicy(id, dir, ps)
		}
	}
	return nil
}

func NewRoutingPolicy() *RoutingPolicy {
	return &RoutingPolicy{
		definedSetMap: make(map[DefinedType]map[string]DefinedSet),
		policyMap:     make(map[string]*Policy),
		statementMap:  make(map[string]*Statement),
		assignmentMap: make(map[string]*Assignment),
	}
}

func CanImportToVrf(v *Vrf, path *Path) bool {
	f := func(arg []bgp.ExtendedCommunityInterface) []string {
		ret := make([]string, 0, len(arg))
		for _, a := range arg {
			ret = append(ret, fmt.Sprintf("RT:%s", a.String()))
		}
		return ret
	}
	set, _ := NewExtCommunitySet(config.ExtCommunitySet{
		ExtCommunitySetName: v.Name,
		ExtCommunityList:    f(v.ImportRt),
	})
	matchSet := config.MatchExtCommunitySet{
		ExtCommunitySet: v.Name,
		MatchSetOptions: config.MATCH_SET_OPTIONS_TYPE_ANY,
	}
	c, _ := NewExtCommunityCondition(matchSet)
	c.set = set
	return c.Evaluate(path, nil)
}
