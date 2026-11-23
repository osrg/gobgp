// Copyright (C) 2026 The GoBGP Authors.
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
	"net/netip"
	"sync"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// The key contains values used by outbound processing, never mutable config
// objects. Recipient addresses/IDs are checked individually before sharing.
type updateGroupKey struct {
	assignment table.ExportPolicyGroupInfo

	peerType        string
	localAS         uint32
	confederation   bool
	removePrivateAs string

	routeReflectorClusterID netip.Addr
	routeReflectorClient    bool

	localAddress netip.Addr
	zone         string
}

type updateGroupReceiver struct {
	peer *peer
	// sessionInfo is the PeerInfo snapshot captured when the group was built.
	// A different current pointer means the session changed and shared results
	// must not be used for this receiver.
	sessionInfo *table.PeerInfo
}

type updateGroup struct {
	receivers []updateGroupReceiver
}

// updateTargets is an immutable snapshot of recipients for one family,
// split into shared-processing groups and peers requiring individual processing.
type updateTargets struct {
	groups     []*updateGroup
	individual []*peer
}

// Published entries are immutable. Invalidation discards cached snapshots.
// Route results live in a single fanout, never in the registry.
type updateGroupRegistry struct {
	mu      sync.Mutex
	entries map[bgp.Family]*updateTargets
}

func (r *updateGroupRegistry) invalidate() {
	r.mu.Lock()
	defer r.mu.Unlock()
	clear(r.entries)
}

// invalidateOnConfigChange checks settings that affect grouping and can change
// without restarting the session. Policy changes are consumed by getTargets.
func (r *updateGroupRegistry) invalidateOnConfigChange(old, next *oc.Neighbor) {
	if old.AsPathOptions.State.ReplacePeerAs != next.AsPathOptions.State.ReplacePeerAs {
		r.invalidate()
	}
}

// updateGroupKeyForPeer returns the export compatibility key and whether the
// peer supports shared processing for this family. If shareable is false, the
// returned key must not be used for grouping.
func updateGroupKeyForPeer(p *peer, info *table.PeerInfo, family bgp.Family, assignment table.ExportPolicyGroupInfo) (key updateGroupKey, shareable bool) {
	conf := p.fsm.pConf.ReadOnly()
	isFamilyEnabled, mode := p.getAddPathMode(family)
	switch {
	// The session must be ready to advertise this family.
	case info == nil, !needToAdvertise(p), !isFamilyEnabled:
		return updateGroupKey{}, false
	// Per-client RIBs, secondary routes and Add-Path require individual selection.
	case info.RouteServerClient, p.isRouteServerClient(),
		p.isSecondaryRouteEnabled(), mode&bgp.BGP_ADD_PATH_SEND != 0:
		return updateGroupKey{}, false
	// VRF conversion and replace-peer-as rewrite the path for this recipient.
	case conf.Config.Vrf != "", conf.AsPathOptions.State.ReplacePeerAs:
		return updateGroupKey{}, false
	// A recipient-dependent export policy cannot share its result.
	case !assignment.Shareable:
		return updateGroupKey{}, false
	}

	key = updateGroupKey{
		assignment: assignment,

		peerType:        string(info.PeerType),
		localAS:         info.LocalAS,
		confederation:   info.Confederation,
		removePrivateAs: string(info.RemovePrivateAs),

		routeReflectorClusterID: info.RouteReflectorClusterID,
		routeReflectorClient:    info.RouteReflectorClient,

		localAddress: info.LocalAddress,
		zone:         info.Address.Zone(),
	}
	return key, true
}

// getTargets returns the cached recipient snapshot, rebuilding it after invalidation
// or a policy change. The caller must hold BgpServer.shared.mu to keep peers and
// policies stable and synchronize with policy-changing management operations.
func (r *updateGroupRegistry) getTargets(family bgp.Family, policy *table.RoutingPolicy, peers map[netip.Addr]*peer) *updateTargets {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries == nil {
		r.entries = make(map[bgp.Family]*updateTargets)
	}
	if policy.CheckAndClearChangesLocked() {
		clear(r.entries)
	}
	if targets := r.entries[family]; targets != nil {
		return targets
	}
	targets := buildUpdateTargets(family, peers)
	r.entries[family] = targets
	return targets
}

// buildUpdateTargets partitions established non-route-server peers into groups
// and individual recipients. It builds a new snapshot without accessing the cache.
func buildUpdateTargets(family bgp.Family, peers map[netip.Addr]*peer) *updateTargets {
	targets := &updateTargets{}
	groupsByKey := make(map[updateGroupKey]*updateGroup)
	policiesByID := make(map[string]table.ExportPolicyGroupInfo)
	for _, neighbor := range peers {
		if !needToAdvertise(neighbor) || neighbor.isRouteServerClient() {
			continue
		}
		policy, ok := policiesByID[neighbor.exportPolicyID]
		if !ok {
			policy = neighbor.policy.GetExportPolicyGroupInfo(neighbor.exportPolicyID)
			policiesByID[neighbor.exportPolicyID] = policy
		}
		info := neighbor.peerInfo.Load()
		key, shareable := updateGroupKeyForPeer(neighbor, info, family, policy)
		if !shareable {
			targets.individual = append(targets.individual, neighbor)
			continue
		}
		group := groupsByKey[key]
		if group == nil {
			group = &updateGroup{}
			groupsByKey[key] = group
		}
		group.receivers = append(group.receivers, updateGroupReceiver{peer: neighbor, sessionInfo: info})
	}
	for _, group := range groupsByKey {
		if len(group.receivers) == 1 {
			targets.individual = append(targets.individual, group.receivers[0].peer)
		} else {
			targets.groups = append(targets.groups, group)
		}
	}
	return targets
}

// The old path is evaluated as-is, using the options of the selected candidate.
// Next-hop conditions also read the selected candidate's OldNextHop.
type oldPathPolicyKey struct {
	path       *table.Path
	oldNextHop netip.Addr
}

// A source path can be both announced and withdrawn in the same batch.
type exportPathKey struct {
	path     *table.Path
	withdraw bool
}

type exportCache struct {
	filteredPaths map[exportPathKey]*table.Path

	// Whether export policy accepts the old path, not actual delivery state.
	sentOlds map[oldPathPolicyKey]bool
}

func (c *exportCache) filterPath(peer *peer, input, path, old *table.Path, options *table.PolicyOptions) *table.Path {
	key := exportPathKey{path: path, withdraw: path.IsWithdraw}
	switch {
	case !path.IsWithdraw:
		// Announcement: use the selected path, which may be an RTC candidate.
	case path == input:
		// Explicit withdrawal: use the input path.
	default:
		// Synthesized withdrawal: pre-policy returned old.Clone(true).
		// Use old so per-peer clones share the same cache entry.
		key.path = old
	}
	after, cached := c.filteredPaths[key]
	if !cached {
		after = table.UpdatePathAttrs(peer.fsm.logger, peer.fsm.gConf, options.Info, path)
		after = peer.policy.ApplyPolicy(peer.exportPolicyID, table.POLICY_DIRECTION_EXPORT, after, options)
		c.filteredPaths[key] = after
	}
	return after
}

// shouldWithdrawOld is used when export policy rejects the new path.
func (c *exportCache) shouldWithdrawOld(peer *peer, old *table.Path, options *table.PolicyOptions) bool {
	if old == nil {
		return false
	}
	key := oldPathPolicyKey{path: old, oldNextHop: options.OldNextHop}
	accepted, cached := c.sentOlds[key]
	if !cached {
		// Evaluate old as-is, without UpdatePathAttrs.
		accepted = peer.policy.ApplyPolicy(peer.exportPolicyID, table.POLICY_DIRECTION_EXPORT, old, options) != nil
		c.sentOlds[key] = accepted
	}
	return accepted
}
