// Copyright (C) 2014-2021 Nippon Telegraph and Telephone Corporation.
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

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// DumpBGPServerMap returns a JSON-serializable map with a full snapshot.
// Includes: global config, peers, route table summaries, all best paths,
// and VRF best paths (if any). This is a read-only mgmt operation.
func (s *BgpServer) DumpBGPServerMap(ctx context.Context) (map[string]any, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	type peerInfo struct {
		NeighborAddress string            `json:"neighbor_address"`
		PeerAS          uint32            `json:"peer_as"`
		LocalAS         uint32            `json:"local_as"`
		SessionState    string            `json:"session_state"`
		AdminState      string            `json:"admin_state"`
		RemoteRouterID  string            `json:"remote_router_id"`
		Flops           uint32            `json:"flops"`
		Families        []string          `json:"families"`
		Stats           map[string]uint64 `json:"stats,omitempty"`
	}

	type tableInfo struct {
		NumDestination uint64 `json:"num_destination"`
		NumPath        uint64 `json:"num_path"`
		NumAccepted    uint64 `json:"num_accepted"`
	}

	pathToObj := func(p *table.Path) map[string]any {
		if p == nil {
			return nil
		}
		src := p.GetSource()
		out := map[string]any{
			"nlri":        fmt.Sprint(p.GetNlri()),
			"family":      p.GetFamily().String(),
			"is_withdraw": p.IsWithdraw,
			"age_unix":    p.GetTimestamp().Unix(),
		}
		if src != nil {
			out["source_as"] = src.AS
			out["source_id"] = src.ID.String()
		}
		for _, a := range p.GetPathAttrs() {
			switch v := a.(type) {
			case *bgp.PathAttributeLocalPref:
				out["local_pref"] = v.Value
			case *bgp.PathAttributeMultiExitDisc:
				out["med"] = v.Value
			case *bgp.PathAttributeNextHop:
				out["nexthop"] = v.Value.String()
			case *bgp.PathAttributeMpReachNLRI:
				out["nexthop"] = v.Nexthop.String()
			case *bgp.PathAttributeCommunities:
				cs := make([]string, 0, len(v.Value))
				for _, c := range v.Value {
					cs = append(cs, fmt.Sprintf("%d:%d", c>>16, c&0xffff))
				}
				out["communities"] = cs
			}
		}
		return out
	}

	var snapshot map[string]any
	err := s.mgmtOperation(func() error {
		global := s.bgpConfig.Global

		rtSummary := map[string]tableInfo{}
		if s.globalRib != nil {
			for f, t := range s.globalRib.GetAllTablesMap() {
				info := t.Info(table.TableInfoOptions{ID: table.GLOBAL_RIB_NAME, AS: 0})
				rtSummary[f.String()] = tableInfo{
					NumDestination: uint64(info.NumDestination),
					NumPath:        uint64(info.NumPath),
					NumAccepted:    uint64(info.NumAccepted),
				}
			}
		}

		peers := make([]peerInfo, 0, len(s.neighborMap))
		for _, p := range s.neighborMap {
			state := p.State()
			adminState := p.AdminState()
			cfg := *p.fsm.pConf.ReadOnly()

			fams := p.configuredRFlist()
			famStr := make([]string, 0, len(fams))
			for _, f := range fams {
				famStr = append(famStr, f.String())
			}

			stats := map[string]uint64{}
			if state == bgp.BGP_FSM_ESTABLISHED {
				for _, f := range fams {
					stats[f.String()+":received"] = uint64(p.adjRibIn.Count([]bgp.Family{f}))
					stats[f.String()+":accepted"] = uint64(p.adjRibIn.Accepted([]bgp.Family{f}))
				}
			}

			peers = append(peers, peerInfo{
				NeighborAddress: cfg.State.NeighborAddress.String(),
				PeerAS:          cfg.State.PeerAs,
				LocalAS:         cfg.Config.LocalAs,
				SessionState:    state.String(),
				AdminState:      adminState.String(),
				RemoteRouterID:  cfg.State.RemoteRouterId.String(),
				Flops:           cfg.State.Flops,
				Families:        famStr,
				Stats:           stats,
			})
		}

		allBest := []map[string]any{}
		if s.globalRib != nil {
			for _, p := range s.globalRib.GetBestPathList(table.GLOBAL_RIB_NAME, 0, nil) {
				allBest = append(allBest, pathToObj(p))
			}
		}

		vrfData := map[string]any{}
		if s.globalRib != nil {
			for name, vrf := range s.globalRib.GetAllVrfsMap() {
				vrfBest := []map[string]any{}
				famCounts := map[string]map[string]uint64{}

				for _, p := range s.globalRib.GetBestPathList(name, 0, nil) {
					if p == nil {
						continue
					}
					po := pathToObj(p)
					po["vrf"] = name
					vrfBest = append(vrfBest, po)

					fam := p.GetFamily().String()
					st := famCounts[fam]
					if st == nil {
						st = map[string]uint64{}
					}
					st["best_paths"]++
					famCounts[fam] = st
				}

				info := map[string]any{
					"best_paths":    vrfBest,
					"family_counts": famCounts,
				}
				if vrf != nil && vrf.Rd != nil {
					info["rd"] = vrf.Rd.String()
				}
				vrfData[name] = info
			}
		}

		localAddrs := []string{}
		for _, a := range global.Config.LocalAddressList {
			localAddrs = append(localAddrs, a.String())
		}

		snapshot = map[string]any{
			"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
			"global": map[string]any{
				"asn":                global.Config.As,
				"router_id":          global.Config.RouterId.String(),
				"listen_port":        global.Config.Port,
				"listen_addresses":   localAddrs,
				"use_multiple_paths": global.UseMultiplePaths.Config.Enabled,
			},
			"route_tables": rtSummary,
			"peers":        peers,
			"best_paths":   allBest,
			"vrfs":         vrfData,
		}
		return nil
	}, false)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return snapshot, nil
}

// DumpBGPServer returns the same snapshot as DumpBGPServerMap, marshaled as indented JSON.
func (s *BgpServer) DumpBGPServer(ctx context.Context) ([]byte, error) {
	m, err := s.DumpBGPServerMap(ctx)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(m, "", "  ")
}
