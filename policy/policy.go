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
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/table"
	"net"
	"strconv"
	"strings"
)

type RouteType int

const (
	ROUTE_TYPE_NONE = iota
	ROUTE_TYPE_ACCEPT
	ROUTE_TYPE_REJECT
)

type MaskLengthRangeType int

const (
	MASK_LENGTH_RANGE_MIN MaskLengthRangeType = iota
	MASK_LENGTH_RANGE_MAX
)

type Policy struct {
	Name       string
	Statements []Statement
}

func NewPolicy(name string, pd config.PolicyDefinition, ds config.DefinedSets) *Policy {
	stmtList := pd.StatementList
	st := make([]Statement, 0)
	p := &Policy{
		Name: name,
	}
	for _, statement := range stmtList {
		prefixSetName := statement.Conditions.MatchPrefixSet

		prefixList := make([]Prefix, 0)
		for _, ps := range ds.PrefixSetList {
			if ps.PrefixSetName == prefixSetName {
				for _, pl := range ps.PrefixList {
					prefixList = append(prefixList, NewPrefix(pl.Address, pl.Masklength, pl.MasklengthRange))
				}
			}
		}

		neighborSetName := statement.Conditions.MatchNeighborSet
		neighborList := make([]net.IP, 0)
		for _, neighborSet := range ds.NeighborSetList {
			if neighborSet.NeighborSetName == neighborSetName {
				for _, nl := range neighborSet.NeighborInfoList {
					neighborList = append(neighborList, nl.Address)
				}
			}
		}
		con := &PrefixConditions{
			PrefixList:      prefixList,
			NeighborList:    neighborList,
			MatchSetOptions: statement.Conditions.MatchSetOptions,
		}

		act := &RoutingActions{
			AcceptRoute: false,
		}
		if statement.Actions.AcceptRoute {
			act.AcceptRoute = true
		}

		s := Statement{
			Name:       statement.Name,
			Conditions: con,
			Actions:    act,
		}
		st = append(st, s)
	}
	p.Statements = st
	return p
}

type Statement struct {
	Name       string
	Conditions Conditions
	Actions    Actions
}

type Conditions interface {
	evaluate(table.Path) bool
}

type DefaultConditions struct {
	CallPolicy string
}

func (c *DefaultConditions) evaluate(path table.Path) bool {
	return false
}

type PrefixConditions struct {
	DefaultConditions
	PrefixList      []Prefix
	NeighborList    []net.IP
	MatchSetOptions config.MatchSetOptionsType
}

// evaluate path's prefix and neighbor's address with conditions
// return value depends on MatchSetOptions
func (c *PrefixConditions) evaluate(path table.Path) bool {
	pref := c.evaluatePrefix(path)
	log.Debug("evaluate prefix : ", pref)
	neigh := c.evaluateNeighbor(path)
	log.Debug("evaluate neighbor : ", neigh)

	switch c.MatchSetOptions {
	case config.MATCH_SET_OPTIONS_TYPE_ALL:
		return pref && neigh
	case config.MATCH_SET_OPTIONS_TYPE_ANY:
		return pref || neigh
	case config.MATCH_SET_OPTIONS_TYPE_INVERT:
		return !(pref || neigh)
	default:
		return false
	}
}

// compare prefixes in this condition and nlri of path and
// subsequent comparison is skipped if that matches the conditions.
// If PrefixList's length is zero, return true.
func (c *PrefixConditions) evaluatePrefix(path table.Path) bool {

	if len(c.PrefixList) == 0 {
		return true
	}

	for _, cp := range c.PrefixList {
		if IpPrefixCalculate(path, cp) {
			return true
		}
	}
	return false
}

// compare neighbor ipaddress of this condition and source address of path
// and, subsequent comparisons are skipped if that matches the conditions.
// If NeighborList's length is zero, return true.
func (c *PrefixConditions) evaluateNeighbor(path table.Path) bool {

	if len(c.NeighborList) == 0 {
		return true
	}

	for _, neighbor := range c.NeighborList {
		cAddr := neighbor
		pAddr := path.GetSource().Address
		if pAddr.Equal(cAddr) {
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
	Masklength      uint8
	MasklengthRange map[MaskLengthRangeType]uint8
}

func NewPrefix(addr net.IP, maskLen uint8, maskRange string) Prefix {
	mlr := make(map[MaskLengthRangeType]uint8)
	p := Prefix{
		Address:         addr,
		Masklength:      maskLen,
		MasklengthRange: make(map[MaskLengthRangeType]uint8),
	}

	// TODO: validate mask length by using regexp

	idx := strings.Index(maskRange, "..")
	if idx == -1 {
		log.WithFields(log.Fields{
			"Topic":      "Policy",
			"Address":    addr,
			"Masklength": maskLen,
		}).Warn("mask length range of condition is invalid format. mask length is not defined.")
		return p
	}
	if idx != 0 {
		min, e := strconv.ParseUint(maskRange[:idx], 10, 8)
		if e != nil {
			log.WithFields(log.Fields{
				"Topic": "Policy",
				"Error": e,
			}).Error("failed to parse the min length of mask length range")
			return p
		}
		mlr[MASK_LENGTH_RANGE_MIN] = uint8(min)
	}
	if idx != len(maskRange)-1 {
		max, e := strconv.ParseUint(maskRange[idx+2:], 10, 8)
		if e != nil {
			log.WithFields(log.Fields{
				"Topic": "Policy",
				"Error": e,
			}).Error("failed to parse the max length of mask length range")
			return p
		}
		mlr[MASK_LENGTH_RANGE_MAX] = uint8(max)
	}
	p.MasklengthRange = mlr
	return p
}

//compare path and condition of policy
//and, subsequent comparison skip if that matches the conditions.
func (p *Policy) Apply(path table.Path) (bool, RouteType, table.Path) {
	for _, statement := range p.Statements {

		result := statement.Conditions.evaluate(path)
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

func IpPrefixCalculate(path table.Path, cPrefix Prefix) bool {
	pAddr := path.GetNlri().(*bgp.NLRInfo).IPAddrPrefix.Prefix
	pMaskLen := path.GetNlri().(*bgp.NLRInfo).IPAddrPrefix.Length
	cp := fmt.Sprintf("%s/%d", cPrefix.Address, cPrefix.Masklength)
	rMin, okMin := cPrefix.MasklengthRange[MASK_LENGTH_RANGE_MIN]
	rMax, okMax := cPrefix.MasklengthRange[MASK_LENGTH_RANGE_MAX]

	//TODO add conditional processing by RouteFamily.

	if !okMin && !okMax {
		if pAddr.Equal(cPrefix.Address) && pMaskLen == cPrefix.Masklength {
			return true
		} else {
			return false
		}
	} else if !okMin {
		rMin = uint8(0)
	} else if !okMax {
		rMax = uint8(32)
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
	if ipNet.Contains(pAddr) && (rMin <= pMaskLen && pMaskLen <= rMax) {
		return true
	}
	return false
}
