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

package config

import (
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/osrg/gobgp/packet/bgp"
)

// Returns config file type by retrieving extension from the given path.
// If no corresponding type found, returns the given def as the default value.
func detectConfigFileType(path, def string) string {
	switch ext := filepath.Ext(path); ext {
	case ".toml":
		return "toml"
	case ".yaml", ".yml":
		return "yaml"
	case ".json":
		return "json"
	default:
		return def
	}
}

func IsConfederationMember(g *Global, p *Neighbor) bool {
	if p.Config.PeerAs != g.Config.As {
		for _, member := range g.Confederation.Config.MemberAsList {
			if member == p.Config.PeerAs {
				return true
			}
		}
	}
	return false
}

func IsEBGPPeer(g *Global, p *Neighbor) bool {
	return p.Config.PeerAs != g.Config.As
}

type AfiSafis []AfiSafi

func (c AfiSafis) ToRfList() ([]bgp.RouteFamily, error) {
	rfs := make([]bgp.RouteFamily, 0, len(c))
	for _, rf := range c {
		k, err := bgp.GetRouteFamily(string(rf.Config.AfiSafiName))
		if err != nil {
			return nil, fmt.Errorf("invalid address family: %s", rf.Config.AfiSafiName)
		}
		rfs = append(rfs, k)
	}
	return rfs, nil
}

func CreateRfMap(p *Neighbor) map[bgp.RouteFamily]bgp.BGPAddPathMode {
	rfs, _ := AfiSafis(p.AfiSafis).ToRfList()
	mode := bgp.BGP_ADD_PATH_NONE
	if p.AddPaths.Config.Receive {
		mode |= bgp.BGP_ADD_PATH_RECEIVE
	}
	if p.AddPaths.Config.SendMax > 0 {
		mode |= bgp.BGP_ADD_PATH_SEND
	}
	rfMap := make(map[bgp.RouteFamily]bgp.BGPAddPathMode)
	for _, rf := range rfs {
		rfMap[rf] = mode
	}
	return rfMap
}

func GetAfiSafi(p *Neighbor, family bgp.RouteFamily) *AfiSafi {
	for _, a := range p.AfiSafis {
		if string(a.Config.AfiSafiName) == family.String() {
			return &a
		}
	}
	return nil
}

func CheckAfiSafisChange(x, y []AfiSafi) bool {
	if len(x) != len(y) {
		return true
	}
	m := make(map[string]bool)
	for _, e := range x {
		m[string(e.Config.AfiSafiName)] = true
	}
	for _, e := range y {
		if !m[string(e.Config.AfiSafiName)] {
			return true
		}
	}
	return false
}

func ParseMaskLength(prefix, mask string) (int, int, error) {
	_, ipNet, err := net.ParseCIDR(prefix)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid prefix: %s", prefix)
	}
	if mask == "" {
		l, _ := ipNet.Mask.Size()
		return l, l, nil
	}
	exp := regexp.MustCompile("(\\d+)\\.\\.(\\d+)")
	elems := exp.FindStringSubmatch(mask)
	if len(elems) != 3 {
		return 0, 0, fmt.Errorf("invalid mask length range: %s", mask)
	}
	// we've already checked the range is sane by regexp
	min, _ := strconv.Atoi(elems[1])
	max, _ := strconv.Atoi(elems[2])
	if min > max {
		return 0, 0, fmt.Errorf("invalid mask length range: %s", mask)
	}
	if ipv4 := ipNet.IP.To4(); ipv4 != nil {
		f := func(i int) bool {
			return i >= 0 && i <= 32
		}
		if !f(min) || !f(max) {
			return 0, 0, fmt.Errorf("ipv4 mask length range outside scope :%s", mask)
		}
	} else {
		f := func(i int) bool {
			return i >= 0 && i <= 128
		}
		if !f(min) || !f(max) {
			return 0, 0, fmt.Errorf("ipv6 mask length range outside scope :%s", mask)
		}
	}
	return min, max, nil
}

func ExtractNeighborAddress(c *Neighbor) (string, error) {
	addr := c.State.NeighborAddress
	if addr == "" {
		addr = c.Config.NeighborAddress
		if addr == "" {
			return "", fmt.Errorf("NeighborAddress is not configured")
		}
	}
	return addr, nil
}
