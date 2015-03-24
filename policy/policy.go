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
	MASK_LENGTH_RANGE_MIN = iota
	MASK_LENGTH_RANGE_MAX
)

type Policy struct {
	Name       string
	Statements []Statement
}

func NewPolicy(name string, pd config.PolicyDefinition, cdf config.DefinedSets) *Policy {
	cst := pd.StatementList
	st := make([]Statement, 0)
	p := &Policy{
		Name:       name,
		Statements: st,
	}
	for _, cs := range cst {
		pName := cs.Conditions.MatchPrefixSet
		npl := make([]Prefix, 0)
		for _, psl := range cdf.PrefixSetList {
			if psl.PrefixSetName == pName {
				for _, ps := range psl.PrefixList {
					npl = append(npl, NewPrefix(ps.Address, ps.Masklength, ps.MasklengthRange))
				}
			}
		}
		nName := cs.Conditions.MatchNeighborSet
		nnl := make([]net.IP, 0)
		for _, nsl := range cdf.NeighborSetList {
			if nsl.NeighborSetName == nName {
				for _, nl := range nsl.NeighborInfoList {
					nnl = append(nnl, nl.Address)
				}
			}
		}
		con := Conditions{
			PrefixList:   npl,
			NeighborList: nnl,
		}
		act := Actions{
			AcceptRoute: cs.Actions.AcceptRoute,
			RejectRoute: cs.Actions.RejectRoute,
		}
		s := Statement{
			Name:       cs.Name,
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

type Conditions struct {
	//CallPolicy       string
	PrefixList   []Prefix
	NeighborList []net.IP
}

type Actions struct {
	AcceptRoute bool
	RejectRoute bool
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
	idx := strings.Index(maskRange, "..")
	if idx == -1 {
		log.WithFields(log.Fields{
			"Topic":      "Policy",
			"Address":    addr,
			"Masklength": maskLen,
		}).Warn("mask length range of condition is invalid format")
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
		matchPrefix := false
		matchNeighbor := false
		if len(statement.Conditions.PrefixList) <= 0 && len(statement.Conditions.NeighborList) <= 0 {
			return false, ROUTE_TYPE_NONE, nil
		} else if len(statement.Conditions.PrefixList) <= 0 && len(statement.Conditions.NeighborList) > 0 {
			matchPrefix = true
			matchNeighbor = statement.compareNeighbor(path)
		} else if len(statement.Conditions.NeighborList) <= 0 && len(statement.Conditions.PrefixList) > 0 {
			matchPrefix = statement.comparePrefix(path)
			matchNeighbor = true
		} else {
			matchPrefix = statement.comparePrefix(path)
			matchNeighbor = statement.compareNeighbor(path)
		}
		an := statement.Actions

		//if match the one of the prefix list and match to any of tye neighbor list,
		//determines that matches the conditions of the statement
		if matchPrefix && matchNeighbor {
			if an.AcceptRoute {
				// accept the path
				// and return the path updated in acction definition
				// TODO update path using acction definition.
				//      implementation waiting for yang.
				newPath := path
				log.WithFields(log.Fields{
					"Topic":   "Policy",
					"Type":    "ROUTE_ACCEPT",
					"OldPath": path,
					"NewPath": newPath,
				}).Debug("Apply policy to path")
				return true, ROUTE_TYPE_ACCEPT, newPath

			} else {
				// reject the path
				// and return the path updated in acction definition
				// TODO update path using acction definition.
				//      implementation waiting for yang.
				newPath := path
				log.WithFields(log.Fields{
					"Topic":   "Policy",
					"Type":    "ROUTE_REJECT",
					"OldPath": path,
					"NewPath": newPath,
				}).Debug("Apply policy to path")
				return true, ROUTE_TYPE_REJECT, nil
			}
		}
	}
	return false, ROUTE_TYPE_NONE, nil
}

//compare prefix of condition policy and nlri of path
//and, subsequent comparison skip if that matches the conditions.
func (s *Statement) comparePrefix(path table.Path) bool {
	for _, cp := range s.Conditions.PrefixList {
		if IpPrefixCalcurate(path, cp) {
			return true
		}
	}
	return false
}

//compare neighbor ipaddress of condition policy and source of path
//and, subsequent comparison skip if that matches the conditions.
func (s *Statement) compareNeighbor(path table.Path) bool {
	for _, neighbor := range s.Conditions.NeighborList {
		cAddr := neighbor
		pAddr := path.GetSource().Address
		if pAddr.Equal(cAddr) {
			return true
		}

	}
	return false
}

func IpPrefixCalcurate(path table.Path, cPrefix Prefix) bool {
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
