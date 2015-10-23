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

package table

import (
	"bytes"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/armon/go-radix"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
)

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

func (t RouteType) ToApiStruct() api.RouteAction {
	switch t {
	case ROUTE_TYPE_ACCEPT:
		return api.RouteAction_ACCEPT
	case ROUTE_TYPE_REJECT:
		return api.RouteAction_REJECT
	}
	return api.RouteAction_NONE
}

type PolicyDirection int

const (
	POLICY_DIRECTION_NONE PolicyDirection = iota
	POLICY_DIRECTION_IMPORT
	POLICY_DIRECTION_EXPORT
	POLICY_DIRECTION_IN
)

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

func toConfigMatchSetOption(a api.MatchType) (config.MatchSetOptionsType, error) {
	var typ config.MatchSetOptionsType
	switch a {
	case api.MatchType_ANY:
		typ = config.MATCH_SET_OPTIONS_TYPE_ANY
	case api.MatchType_ALL:
		typ = config.MATCH_SET_OPTIONS_TYPE_ALL
	case api.MatchType_INVERT:
		typ = config.MATCH_SET_OPTIONS_TYPE_INVERT
	default:
		return typ, fmt.Errorf("invalid match type")
	}
	return typ, nil
}

func toConfigMatchSetOptionRestricted(a api.MatchType) (config.MatchSetOptionsRestrictedType, error) {
	var typ config.MatchSetOptionsRestrictedType
	switch a {
	case api.MatchType_ANY:
		typ = config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY
	case api.MatchType_INVERT:
		typ = config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_INVERT
	default:
		return typ, fmt.Errorf("invalid match type")
	}
	return typ, nil
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
)

func NewMatchOption(c interface{}) (MatchOption, error) {
	switch c.(type) {
	case config.MatchSetOptionsType:
		switch c.(config.MatchSetOptionsType) {
		case config.MATCH_SET_OPTIONS_TYPE_ANY:
			return MATCH_OPTION_ANY, nil
		case config.MATCH_SET_OPTIONS_TYPE_ALL:
			return MATCH_OPTION_ALL, nil
		case config.MATCH_SET_OPTIONS_TYPE_INVERT:
			return MATCH_OPTION_INVERT, nil
		}
	case config.MatchSetOptionsRestrictedType:
		switch c.(config.MatchSetOptionsRestrictedType) {
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
	ToApiStruct() *api.DefinedSet
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

func (p *Prefix) ToApiStruct() *api.Prefix {
	return &api.Prefix{
		IpPrefix:      p.Prefix.String(),
		MaskLengthMin: uint32(p.MasklengthRangeMin),
		MaskLengthMax: uint32(p.MasklengthRangeMax),
	}
}

func NewPrefixFromApiStruct(a *api.Prefix) (*Prefix, error) {
	addr, prefix, err := net.ParseCIDR(a.IpPrefix)
	if err != nil {
		return nil, err
	}
	rf := bgp.RF_IPv4_UC
	if addr.To4() == nil {
		rf = bgp.RF_IPv6_UC
	}
	return &Prefix{
		Prefix:             prefix,
		AddressFamily:      rf,
		MasklengthRangeMin: uint8(a.MaskLengthMin),
		MasklengthRangeMax: uint8(a.MaskLengthMax),
	}, nil
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

func (s *PrefixSet) ToApiStruct() *api.DefinedSet {
	list := make([]*api.Prefix, 0, s.tree.Len())
	s.tree.Walk(func(s string, v interface{}) bool {
		list = append(list, v.(*Prefix).ToApiStruct())
		return false
	})
	return &api.DefinedSet{
		Type:     api.DefinedType(s.Type()),
		Name:     s.name,
		Prefixes: list,
	}
}

func NewPrefixSetFromApiStruct(a *api.DefinedSet) (*PrefixSet, error) {
	if a.Name == "" {
		return nil, fmt.Errorf("empty prefix set name")
	}
	tree := radix.New()
	for _, x := range a.Prefixes {
		y, err := NewPrefixFromApiStruct(x)
		if err != nil {
			return nil, err
		}
		tree.Insert(CidrToRadixkey(y.Prefix.String()), y)
	}
	return &PrefixSet{
		name: a.Name,
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

func (s *NeighborSet) ToApiStruct() *api.DefinedSet {
	list := make([]string, 0, len(s.list))
	for _, n := range s.list {
		list = append(list, n.String())
	}
	return &api.DefinedSet{
		Type: api.DefinedType(s.Type()),
		Name: s.name,
		List: list,
	}
}

func NewNeighborSetFromApiStruct(a *api.DefinedSet) (*NeighborSet, error) {
	if a.Name == "" {
		return nil, fmt.Errorf("empty neighbor set name")
	}
	list := make([]net.IP, 0, len(a.List))
	for _, x := range a.List {
		addr := net.ParseIP(x)
		if addr == nil {
			return nil, fmt.Errorf("invalid ip address format: %s", x)
		}
		list = append(list, addr)
	}
	return &NeighborSet{
		name: a.Name,
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
		list = append(list, x.Address)
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
		return fmt.Sprintf("%d", lhs.asn)
	case LEFT_MOST:
		return fmt.Sprintf("^%d", lhs.asn)
	case ORIGIN:
		return fmt.Sprintf("%d$", lhs.asn)
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
	}
	return false
}

func NewSingleAsPathMatch(arg string) *singleAsPathMatch {
	switch {
	case len(arg) == 0:
		return nil
	case arg[0] == '^':
		if asn, err := strconv.Atoi(arg[1:]); err == nil {
			return &singleAsPathMatch{
				asn:  uint32(asn),
				mode: LEFT_MOST,
			}
		}
	case arg[len(arg)-1] == '$':
		if asn, err := strconv.Atoi(arg[:len(arg)-1]); err == nil {
			return &singleAsPathMatch{
				asn:  uint32(asn),
				mode: ORIGIN,
			}
		}
	default:
		if asn, err := strconv.Atoi(arg); err == nil {
			return &singleAsPathMatch{
				asn:  uint32(asn),
				mode: INCLUDE,
			}
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

func (s *AsPathSet) ToApiStruct() *api.DefinedSet {
	list := make([]string, 0, len(s.list)+len(s.singleList))
	for _, exp := range s.singleList {
		list = append(list, exp.String())
	}
	for _, exp := range s.list {
		list = append(list, exp.String())
	}
	return &api.DefinedSet{
		Type: api.DefinedType(s.typ),
		Name: s.name,
		List: list,
	}
}

func NewAsPathSetFromApiStruct(a *api.DefinedSet) (*AsPathSet, error) {
	c := config.AsPathSet{
		AsPathSetName: a.Name,
		AsPathList:    make([]config.AsPath, 0, len(a.List)),
	}
	for _, x := range a.List {
		c.AsPathList = append(c.AsPathList, config.AsPath{AsPath: x})
	}
	return NewAsPathSet(c)
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
		if s := NewSingleAsPathMatch(x.AsPath); s != nil {
			singleList = append(singleList, s)
		} else {
			exp, err := regexp.Compile(strings.Replace(x.AsPath, "_", ASPATH_REGEXP_MAGIC, -1))
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

func (s *regExpSet) ToApiStruct() *api.DefinedSet {
	list := make([]string, 0, len(s.list))
	for _, exp := range s.list {
		list = append(list, exp.String())
	}
	return &api.DefinedSet{
		Type: api.DefinedType(s.typ),
		Name: s.name,
		List: list,
	}
}

type CommunitySet struct {
	regExpSet
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
	elems := strings.SplitN(arg, ":", 2)
	if len(elems) < 2 {
		return nil, fmt.Errorf("invalid ext-community format([rt|soo]:<value>)")
	}
	switch strings.ToLower(elems[0]) {
	case "rt":
		subtype = bgp.EC_SUBTYPE_ROUTE_TARGET
	case "soo":
		subtype = bgp.EC_SUBTYPE_ROUTE_ORIGIN
	default:
		return nil, fmt.Errorf("unknown ext-community subtype. rt, soo is supported")
	}
	return bgp.ParseExtendedCommunity(subtype, elems[1])
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

func NewCommunitySetFromApiStruct(a *api.DefinedSet) (*CommunitySet, error) {
	c := config.CommunitySet{
		CommunitySetName: a.Name,
		CommunityList:    make([]config.Community, 0, len(a.List)),
	}
	for _, x := range a.List {
		c.CommunityList = append(c.CommunityList, config.Community{Community: x})
	}
	return NewCommunitySet(c)
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
		exp, err := ParseCommunityRegexp(x.Community)
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

func (s *ExtCommunitySet) ToApiStruct() *api.DefinedSet {
	list := make([]string, 0, len(s.list))
	f := func(idx int, arg string) string {
		switch s.subtypeList[idx] {
		case bgp.EC_SUBTYPE_ROUTE_TARGET:
			return fmt.Sprintf("rt:%s", arg)
		case bgp.EC_SUBTYPE_ROUTE_ORIGIN:
			return fmt.Sprintf("soo:%s", arg)
		default:
			return fmt.Sprintf("%d:%s", s.subtypeList[idx], arg)
		}
	}
	for idx, exp := range s.list {
		list = append(list, f(idx, exp.String()))
	}
	return &api.DefinedSet{
		Type: api.DefinedType(s.typ),
		Name: s.name,
		List: list,
	}
}

func NewExtCommunitySetFromApiStruct(a *api.DefinedSet) (*ExtCommunitySet, error) {
	c := config.ExtCommunitySet{
		ExtCommunitySetName: a.Name,
		ExtCommunityList:    make([]config.ExtCommunity, 0, len(a.List)),
	}
	for _, x := range a.List {
		c.ExtCommunityList = append(c.ExtCommunityList, config.ExtCommunity{ExtCommunity: x})
	}
	return NewExtCommunitySet(c)
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
		subtype, exp, err := ParseExtCommunityRegexp(x.ExtCommunity)
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

func NewDefinedSetFromApiStruct(a *api.DefinedSet) (DefinedSet, error) {
	switch DefinedType(a.Type) {
	case DEFINED_TYPE_PREFIX:
		return NewPrefixSetFromApiStruct(a)
	case DEFINED_TYPE_NEIGHBOR:
		return NewNeighborSetFromApiStruct(a)
	case DEFINED_TYPE_AS_PATH:
		return NewAsPathSetFromApiStruct(a)
	case DEFINED_TYPE_COMMUNITY:
		return NewCommunitySetFromApiStruct(a)
	case DEFINED_TYPE_EXT_COMMUNITY:
		return NewExtCommunitySetFromApiStruct(a)
	default:
		return nil, fmt.Errorf("invalid defined type")
	}
}

type Condition interface {
	Type() ConditionType
	Evaluate(*Path) bool
	Set() DefinedSet
}

type PrefixCondition struct {
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
func (c *PrefixCondition) Evaluate(path *Path) bool {
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

	log.WithFields(log.Fields{
		"Topic":     "Policy",
		"Condition": "prefix",
		"Path":      path,
		"Matched":   result,
	}).Debug("evaluation result")

	return result
}

func (c *PrefixCondition) ToApiStruct() *api.MatchSet {
	return &api.MatchSet{
		Type: api.MatchType(c.option),
		Name: c.set.Name(),
	}
}

func NewPrefixConditionFromApiStruct(a *api.MatchSet, m map[string]DefinedSet) (*PrefixCondition, error) {
	if a == nil {
		return nil, nil
	}
	typ, err := toConfigMatchSetOptionRestricted(a.Type)
	if err != nil {
		return nil, err
	}
	c := config.MatchPrefixSet{
		PrefixSet:       a.Name,
		MatchSetOptions: typ,
	}
	return NewPrefixCondition(c, m)
}

func NewPrefixCondition(c config.MatchPrefixSet, m map[string]DefinedSet) (*PrefixCondition, error) {
	if c.PrefixSet == "" {
		return nil, nil
	}
	i, ok := m[c.PrefixSet]
	if !ok {
		return nil, fmt.Errorf("not found prefix set %s", c.PrefixSet)
	}
	s, ok := i.(*PrefixSet)
	if !ok {
		return nil, fmt.Errorf("type assert from DefinedSet to *PrefixSet failed")
	}
	o, err := NewMatchOption(c.MatchSetOptions)
	if err != nil {
		return nil, err
	}
	return &PrefixCondition{
		set:    s,
		option: o,
	}, nil
}

type NeighborCondition struct {
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
func (c *NeighborCondition) Evaluate(path *Path) bool {

	if len(c.set.list) == 0 {
		log.Debug("NeighborList doesn't have elements")
		return true
	}

	if path.Owner == nil {
		return false
	}
	result := false
	for _, n := range c.set.list {
		if path.Owner.Equal(n) {
			result = true
			break
		}
	}

	if c.option == MATCH_OPTION_INVERT {
		result = !result
	}

	log.WithFields(log.Fields{
		"Topic":           "Policy",
		"Condition":       "neighbor",
		"NeighborAddress": path.Owner,
		"Matched":         result,
	}).Debug("evaluation result")

	return result
}

func (c *NeighborCondition) ToApiStruct() *api.MatchSet {
	return &api.MatchSet{
		Type: api.MatchType(c.option),
		Name: c.set.Name(),
	}
}

func NewNeighborConditionFromApiStruct(a *api.MatchSet, m map[string]DefinedSet) (*NeighborCondition, error) {
	if a == nil {
		return nil, nil
	}
	typ, err := toConfigMatchSetOptionRestricted(a.Type)
	if err != nil {
		return nil, err
	}
	c := config.MatchNeighborSet{
		NeighborSet:     a.Name,
		MatchSetOptions: typ,
	}
	return NewNeighborCondition(c, m)
}

func NewNeighborCondition(c config.MatchNeighborSet, m map[string]DefinedSet) (*NeighborCondition, error) {
	if c.NeighborSet == "" {
		return nil, nil
	}
	i, ok := m[c.NeighborSet]
	if !ok {
		return nil, fmt.Errorf("not found neighbor set %s", c.NeighborSet)
	}
	s, ok := i.(*NeighborSet)
	if !ok {
		return nil, fmt.Errorf("type assert from DefinedSet to *NeighborSet failed")
	}
	o, err := NewMatchOption(c.MatchSetOptions)
	if err != nil {
		return nil, err
	}
	return &NeighborCondition{
		set:    s,
		option: o,
	}, nil
}

type AsPathCondition struct {
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

func (c *AsPathCondition) ToApiStruct() *api.MatchSet {
	return &api.MatchSet{
		Type: api.MatchType(c.option),
		Name: c.set.Name(),
	}
}

func (c *AsPathCondition) Evaluate(path *Path) bool {
	result := false
	aspath := path.GetAsSeqList()
	for _, m := range c.set.singleList {
		result = m.Match(aspath)
		if c.option == MATCH_OPTION_ALL && !result {
			break
		}
		if c.option == MATCH_OPTION_ANY && result {
			break
		}
	}
	if (c.option == MATCH_OPTION_ALL && result) || (c.option == MATCH_OPTION_ANY && !result) {
		aspath := path.GetAsString()
		for _, r := range c.set.list {
			result = r.MatchString(aspath)
			if c.option == MATCH_OPTION_ALL && !result {
				break
			}
			if c.option == MATCH_OPTION_ANY && result {
				break
			}
		}
	}
	if c.option == MATCH_OPTION_INVERT {
		result = !result
	}
	log.WithFields(log.Fields{
		"Topic":       "Policy",
		"Condition":   "aspath",
		"MatchOption": c.option,
		"Matched":     result,
	}).Debug("evaluation result")
	return result
}

func NewAsPathConditionFromApiStruct(a *api.MatchSet, m map[string]DefinedSet) (*AsPathCondition, error) {
	if a == nil {
		return nil, nil
	}
	typ, err := toConfigMatchSetOption(a.Type)
	if err != nil {
		return nil, err
	}
	c := config.MatchAsPathSet{
		AsPathSet:       a.Name,
		MatchSetOptions: typ,
	}
	return NewAsPathCondition(c, m)
}

func NewAsPathCondition(c config.MatchAsPathSet, m map[string]DefinedSet) (*AsPathCondition, error) {
	if c.AsPathSet == "" {
		return nil, nil
	}
	i, ok := m[c.AsPathSet]
	if !ok {
		return nil, fmt.Errorf("not found as path set %s", c.AsPathSet)
	}
	s, ok := i.(*AsPathSet)
	if !ok {
		return nil, fmt.Errorf("type assert from DefinedSet to *AsPathSet failed")
	}
	o, err := NewMatchOption(c.MatchSetOptions)
	if err != nil {
		return nil, err
	}
	return &AsPathCondition{
		set:    s,
		option: o,
	}, nil
}

type CommunityCondition struct {
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

func (c *CommunityCondition) ToApiStruct() *api.MatchSet {
	return &api.MatchSet{
		Type: api.MatchType(c.option),
		Name: c.set.Name(),
	}
}

func (c *CommunityCondition) Evaluate(path *Path) bool {
	cs := path.GetCommunities()
	result := false
	for _, x := range cs {
		result = false
		for _, y := range c.set.list {
			if y.MatchString(fmt.Sprintf("%d:%d", x>>16, x&0x0000ffff)) {
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
	log.WithFields(log.Fields{
		"Topic":       "Policy",
		"Condition":   "community",
		"MatchOption": c.option,
		"Matched":     result,
	}).Debug("evaluation result")
	return result
}

func NewCommunityConditionFromApiStruct(a *api.MatchSet, m map[string]DefinedSet) (*CommunityCondition, error) {
	if a == nil {
		return nil, nil
	}
	typ, err := toConfigMatchSetOption(a.Type)
	if err != nil {
		return nil, err
	}
	c := config.MatchCommunitySet{
		CommunitySet:    a.Name,
		MatchSetOptions: typ,
	}
	return NewCommunityCondition(c, m)
}

func NewCommunityCondition(c config.MatchCommunitySet, m map[string]DefinedSet) (*CommunityCondition, error) {
	if c.CommunitySet == "" {
		return nil, nil
	}
	i, ok := m[c.CommunitySet]
	if !ok {
		return nil, fmt.Errorf("not found community set %s", c.CommunitySet)
	}
	s, ok := i.(*CommunitySet)
	if !ok {
		return nil, fmt.Errorf("type assert from DefinedSet to *CommunitySet failed")
	}
	o, err := NewMatchOption(c.MatchSetOptions)
	if err != nil {
		return nil, err
	}
	return &CommunityCondition{
		set:    s,
		option: o,
	}, nil
}

type ExtCommunityCondition struct {
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

func (c *ExtCommunityCondition) ToApiStruct() *api.MatchSet {
	return &api.MatchSet{
		Type: api.MatchType(c.option),
		Name: c.set.Name(),
	}
}

func (c *ExtCommunityCondition) Evaluate(path *Path) bool {
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

	log.WithFields(log.Fields{
		"Topic":       "Policy",
		"Condition":   "community",
		"MatchOption": c.option,
		"Matched":     result,
	}).Debug("evaluation result")
	return result
}

func NewExtCommunityConditionFromApiStruct(a *api.MatchSet, m map[string]DefinedSet) (*ExtCommunityCondition, error) {
	if a == nil {
		return nil, nil
	}
	typ, err := toConfigMatchSetOption(a.Type)
	if err != nil {
		return nil, err
	}
	c := config.MatchExtCommunitySet{
		ExtCommunitySet: a.Name,
		MatchSetOptions: typ,
	}
	return NewExtCommunityCondition(c, m)
}

func NewExtCommunityCondition(c config.MatchExtCommunitySet, m map[string]DefinedSet) (*ExtCommunityCondition, error) {
	if c.ExtCommunitySet == "" {
		return nil, nil
	}
	i, ok := m[c.ExtCommunitySet]
	if !ok {
		return nil, fmt.Errorf("not found ext-community set %s", c.ExtCommunitySet)
	}
	s, ok := i.(*ExtCommunitySet)
	if !ok {
		return nil, fmt.Errorf("type assert from DefinedSet to *ExtCommunitySet failed")
	}
	o, err := NewMatchOption(c.MatchSetOptions)
	if err != nil {
		return nil, err
	}
	return &ExtCommunityCondition{
		set:    s,
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
func (c *AsPathLengthCondition) Evaluate(path *Path) bool {

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

	log.WithFields(log.Fields{
		"Topic":     "Policy",
		"Condition": "aspath length",
		"Reason":    c.operator,
		"Matched":   result,
	}).Debug("evaluation result")

	return result
}

func (c *AsPathLengthCondition) Set() DefinedSet {
	return nil
}

func (c *AsPathLengthCondition) ToApiStruct() *api.AsPathLength {
	return &api.AsPathLength{
		Length: c.length,
		Type:   api.AsPathLengthType(c.operator),
	}
}

func NewAsPathLengthConditionFromApiStruct(a *api.AsPathLength) (*AsPathLengthCondition, error) {
	if a == nil {
		return nil, nil
	}
	return &AsPathLengthCondition{
		length:   a.Length,
		operator: AttributeComparison(a.Type),
	}, nil
}

func NewAsPathLengthCondition(c config.AsPathLength) (*AsPathLengthCondition, error) {
	if c.Value == 0 && c.Operator == "" {
		return nil, nil
	}
	var op AttributeComparison
	switch strings.ToLower(c.Operator) {
	case "eq":
		op = ATTRIBUTE_EQ
	case "ge":
		op = ATTRIBUTE_GE
	case "le":
		op = ATTRIBUTE_LE
	default:
		return nil, fmt.Errorf("invalid as path length operator: %s", c.Operator)
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

func (c *RpkiValidationCondition) Evaluate(path *Path) bool {
	return c.result == path.Validation
}

func (c *RpkiValidationCondition) Set() DefinedSet {
	return nil
}

func NewRpkiValidationConditionFromApiStruct(a int32) (*RpkiValidationCondition, error) {
	if a == 0 {
		return nil, nil
	}
	typ := config.RpkiValidationResultType(a)
	return NewRpkiValidationCondition(typ)
}

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
	Apply(*Path) *Path
}

type RoutingAction struct {
	AcceptRoute bool
}

func (a *RoutingAction) Type() ActionType {
	return ACTION_ROUTING
}

func (a *RoutingAction) Apply(path *Path) *Path {
	if a.AcceptRoute {
		return path
	}
	return nil
}

func (a *RoutingAction) ToApiStruct() api.RouteAction {
	if a.AcceptRoute {
		return api.RouteAction_ACCEPT
	} else {
		return api.RouteAction_REJECT
	}
}

func NewRoutingActionFromApiStruct(a api.RouteAction) (*RoutingAction, error) {
	if a == api.RouteAction_NONE {
		return nil, nil
	}
	accept := false
	if a == api.RouteAction_ACCEPT {
		accept = true
	}
	return &RoutingAction{
		AcceptRoute: accept,
	}, nil
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

func (a *CommunityAction) Apply(path *Path) *Path {
	switch a.action {
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_ADD:
		path.SetCommunities(a.list, false)
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE:
		RegexpRemoveCommunities(path, a.removeList)
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_REPLACE:
		path.SetCommunities(a.list, true)
	}
	log.WithFields(log.Fields{
		"Topic":  "Policy",
		"Action": "community",
		"Values": a.list,
		"Method": a.action,
	}).Debug("community action applied")
	return path
}

func (a *CommunityAction) ToApiStruct() *api.CommunityAction {
	cs := make([]string, 0, len(a.list)+len(a.removeList))
	for _, comm := range a.list {
		c := fmt.Sprintf("%d:%d", comm>>16, comm&0x0000ffff)
		cs = append(cs, c)
	}
	for _, exp := range a.removeList {
		cs = append(cs, exp.String())
	}
	return &api.CommunityAction{
		Type:        api.CommunityActionType(a.action),
		Communities: cs,
	}
}

func NewCommunityActionFromApiStruct(a *api.CommunityAction) (*CommunityAction, error) {
	if a == nil {
		return nil, nil
	}
	var list []uint32
	var removeList []*regexp.Regexp
	op := config.BgpSetCommunityOptionType(a.Type)
	if op == config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE {
		removeList = make([]*regexp.Regexp, 0, len(a.Communities))
	} else {
		list = make([]uint32, 0, len(a.Communities))
	}
	for _, x := range a.Communities {
		if op == config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE {
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
		action:     op,
		list:       list,
		removeList: removeList,
	}, nil
}

func NewCommunityAction(c config.SetCommunity) (*CommunityAction, error) {
	a, ok := CommunityOptionValueMap[strings.ToLower(c.Options)]
	if !ok {
		if len(c.SetCommunityMethod.Communities) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("invalid option name: %s", c.Options)
	}
	var list []uint32
	var removeList []*regexp.Regexp
	if a == config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE {
		removeList = make([]*regexp.Regexp, 0, len(c.SetCommunityMethod.Communities))
	} else {
		list = make([]uint32, 0, len(c.SetCommunityMethod.Communities))
	}
	for _, x := range c.SetCommunityMethod.Communities {
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

func (a *ExtCommunityAction) Apply(path *Path) *Path {
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

func (a *ExtCommunityAction) ToApiStruct() *api.CommunityAction {
	cs := make([]string, 0, len(a.list)+len(a.removeList))
	f := func(idx int, arg string) string {
		switch a.subtypeList[idx] {
		case bgp.EC_SUBTYPE_ROUTE_TARGET:
			return fmt.Sprintf("rt:%s", arg)
		case bgp.EC_SUBTYPE_ROUTE_ORIGIN:
			return fmt.Sprintf("soo:%s", arg)
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
	return &api.CommunityAction{
		Type:        api.CommunityActionType(a.action),
		Communities: cs,
	}
}

func NewExtCommunityActionFromApiStruct(a *api.CommunityAction) (*ExtCommunityAction, error) {
	if a == nil {
		return nil, nil
	}
	var list []bgp.ExtendedCommunityInterface
	var removeList []*regexp.Regexp
	subtypeList := make([]bgp.ExtendedCommunityAttrSubType, 0, len(a.Communities))
	op := config.BgpSetCommunityOptionType(a.Type)
	if op == config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE {
		removeList = make([]*regexp.Regexp, 0, len(a.Communities))
	} else {
		list = make([]bgp.ExtendedCommunityInterface, 0, len(a.Communities))
	}
	for _, x := range a.Communities {
		if op == config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE {
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
		action:      op,
		list:        list,
		removeList:  removeList,
		subtypeList: subtypeList,
	}, nil
}

func NewExtCommunityAction(c config.SetExtCommunity) (*ExtCommunityAction, error) {
	a, ok := CommunityOptionValueMap[strings.ToLower(c.Options)]
	if !ok {
		if len(c.SetExtCommunityMethod.Communities) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("invalid option name: %s", c.Options)
	}
	var list []bgp.ExtendedCommunityInterface
	var removeList []*regexp.Regexp
	subtypeList := make([]bgp.ExtendedCommunityAttrSubType, 0, len(c.SetExtCommunityMethod.Communities))
	if a == config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE {
		removeList = make([]*regexp.Regexp, 0, len(c.SetExtCommunityMethod.Communities))
	} else {
		list = make([]bgp.ExtendedCommunityInterface, 0, len(c.SetExtCommunityMethod.Communities))
	}
	for _, x := range c.SetExtCommunityMethod.Communities {
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

func (a *MedAction) Apply(path *Path) *Path {
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
		}).Warn(err)
	} else {
		log.WithFields(log.Fields{
			"Topic":      "Policy",
			"Action":     "med",
			"Value":      a.value,
			"ActionType": a.action,
		}).Debug("med action applied")
	}

	return path
}

func (a *MedAction) ToApiStruct() *api.MedAction {
	return &api.MedAction{
		Type:  api.MedActionType(a.action),
		Value: int64(a.value),
	}
}

func NewMedActionFromApiStruct(a *api.MedAction) (*MedAction, error) {
	if a == nil {
		return nil, nil
	}
	return &MedAction{
		action: MedActionType(a.Type),
		value:  int(a.Value),
	}, nil
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

type AsPathPrependAction struct {
	asn         uint32
	useLeftMost bool
	repeat      uint8
}

func (a *AsPathPrependAction) Type() ActionType {
	return ACTION_AS_PATH_PREPEND
}

func (a *AsPathPrependAction) Apply(path *Path) *Path {
	var asn uint32
	if a.useLeftMost {
		aspath := path.GetAsSeqList()
		if len(aspath) == 0 {
			log.WithFields(log.Fields{
				"Topic": "Policy",
				"Type":  "AsPathPrepend Action",
			}).Warnf("aspath length is zero.")
			return path
		}
		asn = aspath[0]
		if asn == 0 {
			log.WithFields(log.Fields{
				"Topic": "Policy",
				"Type":  "AsPathPrepend Action",
			}).Warnf("left-most ASN is not seq")
			return path
		}
		log.WithFields(log.Fields{
			"Topic":  "Policy",
			"Type":   "AsPathPrepend Action",
			"LastAs": asn,
			"Repeat": a.repeat,
		}).Debug("use left-most ASN")
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

func (a *AsPathPrependAction) ToApiStruct() *api.AsPrependAction {
	return &api.AsPrependAction{
		Asn:         a.asn,
		Repeat:      uint32(a.repeat),
		UseLeftMost: a.useLeftMost,
	}
}

func NewAsPathPrependActionFromApiStruct(a *api.AsPrependAction) (*AsPathPrependAction, error) {
	if a == nil {
		return nil, nil
	}
	return &AsPathPrependAction{
		asn:         a.Asn,
		useLeftMost: a.UseLeftMost,
		repeat:      uint8(a.Repeat),
	}, nil
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

type Statement struct {
	Name        string
	Conditions  []Condition
	RouteAction Action
	ModActions  []Action
}

// evaluate each condition in the statement according to MatchSetOptions
func (s *Statement) Evaluate(p *Path) bool {
	for _, c := range s.Conditions {
		if !c.Evaluate(p) {
			return false
		}
	}
	return true
}

func (s *Statement) Apply(path *Path) (RouteType, *Path) {
	result := s.Evaluate(path)
	log.WithFields(log.Fields{
		"Topic":      "Policy",
		"Path":       path,
		"PolicyName": s.Name,
	}).Debug("statement evaluate : ", result)
	if result {
		if len(s.ModActions) != 0 {
			// apply all modification actions
			path = path.Clone(path.Owner, path.IsWithdraw)
			for _, action := range s.ModActions {
				path = action.Apply(path)
			}
		}
		//Routing action
		if s.RouteAction == nil {
			log.WithFields(log.Fields{
				"Topic":      "Policy",
				"Path":       path,
				"PolicyName": s.Name,
			}).Warn("route action is nil")
			return ROUTE_TYPE_NONE, path
		}
		p := s.RouteAction.Apply(path)
		if p == nil {
			return ROUTE_TYPE_REJECT, path
		}
		return ROUTE_TYPE_ACCEPT, path
	}
	return ROUTE_TYPE_NONE, path
}

func (s *Statement) ToApiStruct() *api.Statement {
	cs := &api.Conditions{}
	for _, c := range s.Conditions {
		switch c.(type) {
		case *PrefixCondition:
			cs.PrefixSet = c.(*PrefixCondition).ToApiStruct()
		case *NeighborCondition:
			cs.NeighborSet = c.(*NeighborCondition).ToApiStruct()
		case *AsPathLengthCondition:
			cs.AsPathLength = c.(*AsPathLengthCondition).ToApiStruct()
		case *AsPathCondition:
			cs.AsPathSet = c.(*AsPathCondition).ToApiStruct()
		case *CommunityCondition:
			cs.CommunitySet = c.(*CommunityCondition).ToApiStruct()
		case *ExtCommunityCondition:
			cs.ExtCommunitySet = c.(*ExtCommunityCondition).ToApiStruct()
		case *RpkiValidationCondition:
			cs.RpkiResult = int32(c.(*RpkiValidationCondition).result)
		}
	}
	as := &api.Actions{}
	if s.RouteAction != nil && !reflect.ValueOf(s.RouteAction).IsNil() {
		as.RouteAction = s.RouteAction.(*RoutingAction).ToApiStruct()
	}
	for _, a := range s.ModActions {
		switch a.(type) {
		case *CommunityAction:
			as.Community = a.(*CommunityAction).ToApiStruct()
		case *MedAction:
			as.Med = a.(*MedAction).ToApiStruct()
		case *AsPathPrependAction:
			as.AsPrepend = a.(*AsPathPrependAction).ToApiStruct()
		case *ExtCommunityAction:
			as.ExtCommunity = a.(*ExtCommunityAction).ToApiStruct()
		}
	}
	return &api.Statement{
		Name:       s.Name,
		Conditions: cs,
		Actions:    as,
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

func NewStatementFromApiStruct(a *api.Statement, dmap DefinedSetMap) (*Statement, error) {
	if a.Name == "" {
		return nil, fmt.Errorf("empty statement name")
	}
	var ra Action
	var as []Action
	var cs []Condition
	var err error
	if a.Conditions != nil {
		cfs := []func() (Condition, error){
			func() (Condition, error) {
				return NewPrefixConditionFromApiStruct(a.Conditions.PrefixSet, dmap[DEFINED_TYPE_PREFIX])
			},
			func() (Condition, error) {
				return NewNeighborConditionFromApiStruct(a.Conditions.NeighborSet, dmap[DEFINED_TYPE_NEIGHBOR])
			},
			func() (Condition, error) {
				return NewAsPathLengthConditionFromApiStruct(a.Conditions.AsPathLength)
			},
			func() (Condition, error) {
				return NewRpkiValidationConditionFromApiStruct(a.Conditions.RpkiResult)
			},
			func() (Condition, error) {
				return NewAsPathConditionFromApiStruct(a.Conditions.AsPathSet, dmap[DEFINED_TYPE_AS_PATH])
			},
			func() (Condition, error) {
				return NewCommunityConditionFromApiStruct(a.Conditions.CommunitySet, dmap[DEFINED_TYPE_COMMUNITY])
			},
			func() (Condition, error) {
				return NewExtCommunityConditionFromApiStruct(a.Conditions.ExtCommunitySet, dmap[DEFINED_TYPE_EXT_COMMUNITY])
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
	}
	if a.Actions != nil {
		ra, err = NewRoutingActionFromApiStruct(a.Actions.RouteAction)
		if err != nil {
			return nil, err
		}
		afs := []func() (Action, error){
			func() (Action, error) {
				return NewCommunityActionFromApiStruct(a.Actions.Community)
			},
			func() (Action, error) {
				return NewExtCommunityActionFromApiStruct(a.Actions.ExtCommunity)
			},
			func() (Action, error) {
				return NewMedActionFromApiStruct(a.Actions.Med)
			},
			func() (Action, error) {
				return NewAsPathPrependActionFromApiStruct(a.Actions.AsPrepend)
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
	}
	return &Statement{
		Name:        a.Name,
		Conditions:  cs,
		RouteAction: ra,
		ModActions:  as,
	}, nil
}

func NewStatement(c config.Statement, dmap DefinedSetMap) (*Statement, error) {
	if c.Name == "" {
		return nil, fmt.Errorf("empty statement name")
	}
	var ra Action
	var as []Action
	var cs []Condition
	var err error
	cfs := []func() (Condition, error){
		func() (Condition, error) {
			return NewPrefixCondition(c.Conditions.MatchPrefixSet, dmap[DEFINED_TYPE_PREFIX])
		},
		func() (Condition, error) {
			return NewNeighborCondition(c.Conditions.MatchNeighborSet, dmap[DEFINED_TYPE_NEIGHBOR])
		},
		func() (Condition, error) {
			return NewAsPathLengthCondition(c.Conditions.BgpConditions.AsPathLength)
		},
		func() (Condition, error) {
			return NewRpkiValidationCondition(c.Conditions.BgpConditions.RpkiValidationResult)
		},
		func() (Condition, error) {
			return NewAsPathCondition(c.Conditions.BgpConditions.MatchAsPathSet, dmap[DEFINED_TYPE_AS_PATH])
		},
		func() (Condition, error) {
			return NewCommunityCondition(c.Conditions.BgpConditions.MatchCommunitySet, dmap[DEFINED_TYPE_COMMUNITY])
		},
		func() (Condition, error) {
			return NewExtCommunityCondition(c.Conditions.BgpConditions.MatchExtCommunitySet, dmap[DEFINED_TYPE_EXT_COMMUNITY])
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
			return NewAsPathPrependAction(c.Actions.BgpActions.SetAsPathPrepend)
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
	name       string
	Statements []*Statement
}

func (p *Policy) Name() string {
	return p.name
}

// Compare path with a policy's condition in stored order in the policy.
// If a condition match, then this function stops evaluation and
// subsequent conditions are skipped.
func (p *Policy) Apply(path *Path) (RouteType, *Path) {
	for _, stmt := range p.Statements {
		var result RouteType
		result, path = stmt.Apply(path)
		if result != ROUTE_TYPE_NONE {
			return result, path
		}
	}
	return ROUTE_TYPE_NONE, path
}

func (p *Policy) ToApiStruct() *api.Policy {
	ss := make([]*api.Statement, 0, len(p.Statements))
	for _, s := range p.Statements {
		ss = append(ss, s.ToApiStruct())
	}
	return &api.Policy{
		Name:       p.name,
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
	stmts := make([]*Statement, 0, len(lhs.Statements)-len(rhs.Statements))
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

func NewPolicyFromApiStruct(a *api.Policy, dmap DefinedSetMap) (*Policy, error) {
	if a.Name == "" {
		return nil, fmt.Errorf("empty policy name")
	}
	stmts := make([]*Statement, 0, len(a.Statements))
	for idx, x := range a.Statements {
		if x.Name == "" {
			x.Name = fmt.Sprintf("%s_stmt%d", a.Name, idx)
		}
		y, err := NewStatementFromApiStruct(x, dmap)
		if err != nil {
			return nil, err
		}
		stmts = append(stmts, y)
	}
	return &Policy{
		name:       a.Name,
		Statements: stmts,
	}, nil
}

func NewPolicy(c config.PolicyDefinition, dmap DefinedSetMap) (*Policy, error) {
	if c.Name == "" {
		return nil, fmt.Errorf("empty policy name")
	}
	var st []*Statement
	stmts := c.Statements.StatementList
	if len(stmts) != 0 {
		st = make([]*Statement, 0, len(stmts))
		for idx, stmt := range stmts {
			if stmt.Name == "" {
				stmt.Name = fmt.Sprintf("%s_stmt%d", c.Name, idx)
			}
			s, err := NewStatement(stmt, dmap)
			if err != nil {
				return nil, err
			}
			st = append(st, s)
		}
	}
	return &Policy{
		name:       c.Name,
		Statements: st,
	}, nil
}

type RoutingPolicy struct {
	DefinedSetMap DefinedSetMap
	PolicyMap     map[string]*Policy
	StatementMap  map[string]*Statement
}

func (r *RoutingPolicy) GetAssignmentFromConfig(dir PolicyDirection, a config.ApplyPolicy) ([]*Policy, RouteType, error) {
	var names []string
	var cdef config.DefaultPolicyType
	def := ROUTE_TYPE_ACCEPT
	c := a.ApplyPolicyConfig
	switch dir {
	case POLICY_DIRECTION_IN:
		names = c.InPolicy
		cdef = c.DefaultInPolicy
	case POLICY_DIRECTION_IMPORT:
		names = c.ImportPolicy
		cdef = c.DefaultImportPolicy
	case POLICY_DIRECTION_EXPORT:
		names = c.ExportPolicy
		cdef = c.DefaultExportPolicy
	default:
		return nil, def, fmt.Errorf("invalid policy direction")
	}
	if cdef == config.DEFAULT_POLICY_TYPE_REJECT_ROUTE {
		def = ROUTE_TYPE_REJECT
	}
	ps := make([]*Policy, 0, len(names))
	for _, name := range names {
		p, ok := r.PolicyMap[name]
		if !ok {
			return nil, def, fmt.Errorf("not found policy %s", name)
		}
		ps = append(ps, p)
	}
	return ps, def, nil
}

func (r *RoutingPolicy) InUse(d DefinedSet) bool {
	name := d.Name()
	for _, p := range r.PolicyMap {
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

func (r *RoutingPolicy) StatementInUse(x *Statement) bool {
	for _, p := range r.PolicyMap {
		for _, y := range p.Statements {
			if x.Name == y.Name {
				return true
			}
		}
	}
	return false
}

func NewRoutingPolicy(c config.RoutingPolicy) (*RoutingPolicy, error) {
	dmap := make(map[DefinedType]map[string]DefinedSet)
	dmap[DEFINED_TYPE_PREFIX] = make(map[string]DefinedSet)
	d := c.DefinedSets
	for _, x := range d.PrefixSets.PrefixSetList {
		y, err := NewPrefixSet(x)
		if err != nil {
			return nil, err
		}
		dmap[DEFINED_TYPE_PREFIX][y.Name()] = y
	}
	dmap[DEFINED_TYPE_NEIGHBOR] = make(map[string]DefinedSet)
	for _, x := range d.NeighborSets.NeighborSetList {
		y, err := NewNeighborSet(x)
		if err != nil {
			return nil, err
		}
		dmap[DEFINED_TYPE_NEIGHBOR][y.Name()] = y
	}
	//	dmap[DEFINED_TYPE_TAG] = make(map[string]DefinedSet)
	//	for _, x := range c.DefinedSets.TagSets.TagSetList {
	//		y, err := NewTagSet(x)
	//		if err != nil {
	//			return nil, err
	//		}
	//		dmap[DEFINED_TYPE_TAG][y.Name()] = y
	//	}
	bd := c.DefinedSets.BgpDefinedSets
	dmap[DEFINED_TYPE_AS_PATH] = make(map[string]DefinedSet)
	for _, x := range bd.AsPathSets.AsPathSetList {
		y, err := NewAsPathSet(x)
		if err != nil {
			return nil, err
		}
		dmap[DEFINED_TYPE_AS_PATH][y.Name()] = y
	}
	dmap[DEFINED_TYPE_COMMUNITY] = make(map[string]DefinedSet)
	for _, x := range bd.CommunitySets.CommunitySetList {
		y, err := NewCommunitySet(x)
		if err != nil {
			return nil, err
		}
		dmap[DEFINED_TYPE_COMMUNITY][y.Name()] = y
	}
	dmap[DEFINED_TYPE_EXT_COMMUNITY] = make(map[string]DefinedSet)
	for _, x := range bd.ExtCommunitySets.ExtCommunitySetList {
		y, err := NewExtCommunitySet(x)
		if err != nil {
			return nil, err
		}
		dmap[DEFINED_TYPE_EXT_COMMUNITY][y.Name()] = y
	}
	pmap := make(map[string]*Policy)
	smap := make(map[string]*Statement)
	for _, x := range c.PolicyDefinitions.PolicyDefinitionList {
		y, err := NewPolicy(x, dmap)
		if err != nil {
			return nil, err
		}
		pmap[y.Name()] = y
		for _, s := range y.Statements {
			_, ok := smap[s.Name]
			if ok {
				return nil, fmt.Errorf("duplicated statement name. statement name must be unique.")
			}
			smap[s.Name] = s
		}
	}
	return &RoutingPolicy{
		DefinedSetMap: dmap,
		PolicyMap:     pmap,
		StatementMap:  smap,
	}, nil
}

func CanImportToVrf(v *Vrf, path *Path) bool {
	f := func(arg []bgp.ExtendedCommunityInterface) []config.ExtCommunity {
		ret := make([]config.ExtCommunity, 0, len(arg))
		for _, a := range arg {
			ret = append(ret, config.ExtCommunity{
				ExtCommunity: fmt.Sprintf("RT:%s", a.String()),
			})
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
	c, _ := NewExtCommunityCondition(matchSet, map[string]DefinedSet{v.Name: set})
	return c.Evaluate(path)
}

func PoliciesToString(ps []*api.Policy) []string {
	names := make([]string, 0, len(ps))
	for _, p := range ps {
		names = append(names, p.Name)
	}
	return names
}
