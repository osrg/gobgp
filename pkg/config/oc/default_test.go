// Copyright (C) 2026 The GoBGP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oc

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testNeighborAddress = "192.0.2.1"

// registerConfiguredFields records the fields that the config file set for one
// neighbor. configuredFields is package state, so it is restored afterwards.
func registerConfiguredFields(t *testing.T, addr string, fields map[string]any) {
	t.Helper()
	saved := configuredFields
	t.Cleanup(func() { configuredFields = saved })
	configuredFields = map[string]any{addr: fields}
}

func TestSetNeighborAsPathOptions(t *testing.T) {
	registerConfiguredFields(t, testNeighborAddress, map[string]any{
		"as-path-options": map[string]any{"config": map[string]any{"allow-own-as": 1}},
	})
	n := &Neighbor{
		Config:        NeighborConfig{NeighborAddress: netip.MustParseAddr(testNeighborAddress), PeerType: PEER_TYPE_EXTERNAL, LocalAs: 65010, PeerAs: 65001},
		AsPathOptions: AsPathOptions{Config: AsPathOptionsConfig{AllowOwnAs: 2}},
		Timers:        Timers{Config: TimersConfig{HoldTime: 45}},
	}
	pg := &PeerGroup{
		Config:        PeerGroupConfig{LocalAs: 65020, PeerAs: 65002},
		AsPathOptions: AsPathOptions{Config: AsPathOptionsConfig{AllowOwnAs: 3, ReplacePeerAs: true, AllowAsPathLoopLocal: true}},
		Timers:        Timers{Config: TimersConfig{HoldTime: 90}},
	}
	config, timers := n.Config, n.Timers
	require.NoError(t, SetNeighborAsPathOptions(n, pg))
	want := AsPathOptionsConfig{AllowOwnAs: 2, ReplacePeerAs: true, AllowAsPathLoopLocal: true}
	assert.Equal(t, want, n.AsPathOptions.Config)
	assert.Equal(t, AsPathOptionsState(want), n.AsPathOptions.State)
	assert.Equal(t, config, n.Config)
	assert.Equal(t, timers, n.Timers)

	n.Config.PeerType = PEER_TYPE_INTERNAL
	require.EqualError(t, SetNeighborAsPathOptions(n, pg), "can't set replace-peer-as for iBGP peer")
}

func newNeighborForTcpAoInheritanceTest() *Neighbor {
	return &Neighbor{
		Config: NeighborConfig{
			NeighborAddress: netip.MustParseAddr(testNeighborAddress),
			PeerGroup:       "g",
		},
	}
}

func newPeerGroupForTcpAoInheritanceTest() *PeerGroup {
	return &PeerGroup{
		Config: PeerGroupConfig{
			PeerGroupName: "g",
		},
		TcpAo: TcpAo{
			Config: TcpAoConfig{Keychain: "group-chain", SendId: 1},
		},
	}
}

func TestOverwriteNeighborConfigWithPeerGroupTcpAo(t *testing.T) {
	// A neighbor that says nothing about TCP-AO takes the whole
	// configuration from its peer group.
	t.Run("inherited_when_not_configured", func(t *testing.T) {
		registerConfiguredFields(t, testNeighborAddress, map[string]any{
			"config": map[string]any{
				"neighbor-address": testNeighborAddress,
				"peer-group":       "g",
			},
		})

		n := newNeighborForTcpAoInheritanceTest()
		require.NoError(t, OverwriteNeighborConfigWithPeerGroup(n, newPeerGroupForTcpAoInheritanceTest()))
		assert.Equal(t, KeychainRef("group-chain"), n.TcpAo.Config.Keychain)
		assert.Equal(t, uint8(1), n.TcpAo.Config.SendId)
	})

	t.Run("kept_when_configured", func(t *testing.T) {
		registerConfiguredFields(t, testNeighborAddress, map[string]any{
			"config": map[string]any{
				"neighbor-address": testNeighborAddress,
				"peer-group":       "g",
			},
			"tcp-ao": map[string]any{
				"config": map[string]any{
					"keychain": "peer-chain",
					"send-id":  2,
				},
			},
		})

		n := newNeighborForTcpAoInheritanceTest()
		n.TcpAo.Config = TcpAoConfig{Keychain: "peer-chain", SendId: 2}
		require.NoError(t, OverwriteNeighborConfigWithPeerGroup(n, newPeerGroupForTcpAoInheritanceTest()))
		assert.Equal(t, KeychainRef("peer-chain"), n.TcpAo.Config.Keychain)
		assert.Equal(t, uint8(2), n.TcpAo.Config.SendId)
	})

	// The peer group is consulted per leaf, so a neighbor that names only a
	// keychain still takes send-id from the group.
	t.Run("send_id_inherited_when_only_keychain_is_configured", func(t *testing.T) {
		registerConfiguredFields(t, testNeighborAddress, map[string]any{
			"config": map[string]any{
				"neighbor-address": testNeighborAddress,
				"peer-group":       "g",
			},
			"tcp-ao": map[string]any{
				"config": map[string]any{
					"keychain": "peer-chain",
				},
			},
		})

		n := newNeighborForTcpAoInheritanceTest()
		n.TcpAo.Config = TcpAoConfig{Keychain: "peer-chain"}
		require.NoError(t, OverwriteNeighborConfigWithPeerGroup(n, newPeerGroupForTcpAoInheritanceTest()))
		assert.Equal(t, KeychainRef("peer-chain"), n.TcpAo.Config.Keychain)
		assert.Equal(t, uint8(1), n.TcpAo.Config.SendId)
	})
}
