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

// An unnumbered neighbor has no address in its config, so the configuration
// file record is stored under the interface name. The neighbor must still keep
// what the operator wrote, and inherit only the rest from the peer group.
func TestOverwriteNeighborConfigWithPeerGroupUnnumbered(t *testing.T) {
	const iface = "eth0"

	registerConfiguredFields(t, iface, map[string]any{
		"config": map[string]any{
			"neighbor-interface": iface,
			"peer-group":         "g",
		},
		"timers": map[string]any{
			"config": map[string]any{
				"hold-time": 180,
			},
		},
		"transport": map[string]any{
			"config": map[string]any{
				"passive-mode": false,
			},
		},
		"afi-safis": []any{
			map[string]any{
				"config": map[string]any{
					"afi-safi-name": "l3vpn-ipv4-unicast",
				},
			},
		},
	})

	pg := &PeerGroup{
		Config: PeerGroupConfig{
			PeerGroupName: "g",
			Description:   "group description",
		},
		Timers:    Timers{Config: TimersConfig{HoldTime: 90}},
		Transport: Transport{Config: TransportConfig{PassiveMode: true}},
		AfiSafis:  []AfiSafi{defaultAfiSafi(AFI_SAFI_TYPE_IPV4_UNICAST, true)},
	}
	n := &Neighbor{
		Config: NeighborConfig{
			NeighborInterface: iface,
			PeerGroup:         "g",
		},
		Timers:    Timers{Config: TimersConfig{HoldTime: 180}},
		Transport: Transport{Config: TransportConfig{PassiveMode: false}},
		AfiSafis:  []AfiSafi{defaultAfiSafi(AFI_SAFI_TYPE_L3VPN_IPV4_UNICAST, true)},
	}

	require.NoError(t, OverwriteNeighborConfigWithPeerGroup(n, pg))

	assert.Equal(t, float64(180), n.Timers.Config.HoldTime)
	// A field configured to its zero value still wins over the peer group.
	assert.False(t, n.Transport.Config.PassiveMode)
	require.Len(t, n.AfiSafis, 1)
	assert.Equal(t, AFI_SAFI_TYPE_L3VPN_IPV4_UNICAST, n.AfiSafis[0].Config.AfiSafiName)
	// Nothing was said about the description, so it comes from the peer group.
	assert.Equal(t, "group description", n.Config.Description)
}

// A neighbor that has both an address and an interface is recorded under the
// address, because RegisterConfiguredFields prefers it.
func TestOverwriteNeighborConfigWithPeerGroupAddressWins(t *testing.T) {
	registerConfiguredFields(t, testNeighborAddress, map[string]any{
		"config": map[string]any{
			"neighbor-address":   testNeighborAddress,
			"neighbor-interface": "eth0",
			"peer-group":         "g",
		},
		"timers": map[string]any{
			"config": map[string]any{
				"hold-time": 180,
			},
		},
	})

	pg := &PeerGroup{
		Config: PeerGroupConfig{PeerGroupName: "g"},
		Timers: Timers{Config: TimersConfig{HoldTime: 90}},
	}
	n := &Neighbor{
		Config: NeighborConfig{
			NeighborAddress:   netip.MustParseAddr(testNeighborAddress),
			NeighborInterface: "eth0",
			PeerGroup:         "g",
		},
		Timers: Timers{Config: TimersConfig{HoldTime: 180}},
	}

	require.NoError(t, OverwriteNeighborConfigWithPeerGroup(n, pg))

	assert.Equal(t, float64(180), n.Timers.Config.HoldTime)
}

// clearConfiguredFields drops the config file record, as if the neighbor had
// been added through the gRPC API. configuredFields is package state, so it is
// restored afterwards.
func clearConfiguredFields(t *testing.T) {
	t.Helper()
	saved := configuredFields
	t.Cleanup(func() { configuredFields = saved })
	configuredFields = nil
}

// A neighbor added through the gRPC API is not recorded in configuredFields, so
// viper reports every field as unset. Only the fields the caller left empty may
// be taken from the peer group.
func TestOverwriteNeighborConfigWithPeerGroupFromAPI(t *testing.T) {
	t.Run("caller_values_kept_and_empty_ones_inherited", func(t *testing.T) {
		clearConfiguredFields(t)

		pg := &PeerGroup{
			Config: PeerGroupConfig{
				PeerGroupName: "g",
				LocalAs:       65000,
				Description:   "group description",
				AuthPassword:  "group password",
			},
			Timers: Timers{Config: TimersConfig{HoldTime: 90, KeepaliveInterval: 30}},
		}
		n := &Neighbor{
			Config: NeighborConfig{
				NeighborAddress: netip.MustParseAddr(testNeighborAddress),
				PeerGroup:       "g",
				Description:     "neighbor description",
			},
			Timers: Timers{Config: TimersConfig{HoldTime: 180}},
		}

		require.NoError(t, OverwriteNeighborConfigWithPeerGroup(n, pg))

		assert.Equal(t, "neighbor description", n.Config.Description)
		assert.Equal(t, float64(180), n.Timers.Config.HoldTime)
		assert.Equal(t, "group password", n.Config.AuthPassword)
		assert.Equal(t, uint32(65000), n.Config.LocalAs)
		assert.Equal(t, float64(30), n.Timers.Config.KeepaliveInterval)
	})

	// TCP-AO reaches the neighbor config through the API as well.
	t.Run("tcp_ao_kept", func(t *testing.T) {
		clearConfiguredFields(t)

		n := newNeighborForTcpAoInheritanceTest()
		n.TcpAo.Config = TcpAoConfig{Keychain: "peer-chain", SendId: 2}
		require.NoError(t, OverwriteNeighborConfigWithPeerGroup(n, newPeerGroupForTcpAoInheritanceTest()))
		assert.Equal(t, KeychainRef("peer-chain"), n.TcpAo.Config.Keychain)
		assert.Equal(t, uint8(2), n.TcpAo.Config.SendId)
	})

	t.Run("afi_safis_kept", func(t *testing.T) {
		clearConfiguredFields(t)

		pg := &PeerGroup{
			Config:   PeerGroupConfig{PeerGroupName: "g"},
			AfiSafis: []AfiSafi{defaultAfiSafi(AFI_SAFI_TYPE_IPV4_UNICAST, true)},
		}
		n := &Neighbor{
			Config: NeighborConfig{
				NeighborAddress: netip.MustParseAddr(testNeighborAddress),
				PeerGroup:       "g",
			},
			AfiSafis: []AfiSafi{defaultAfiSafi(AFI_SAFI_TYPE_IPV6_UNICAST, true)},
		}

		require.NoError(t, OverwriteNeighborConfigWithPeerGroup(n, pg))

		require.Len(t, n.AfiSafis, 1)
		assert.Equal(t, AFI_SAFI_TYPE_IPV6_UNICAST, n.AfiSafis[0].Config.AfiSafiName)
	})

	t.Run("afi_safis_inherited_when_empty", func(t *testing.T) {
		clearConfiguredFields(t)

		pg := &PeerGroup{
			Config:   PeerGroupConfig{PeerGroupName: "g"},
			AfiSafis: []AfiSafi{defaultAfiSafi(AFI_SAFI_TYPE_IPV4_UNICAST, true)},
		}
		n := &Neighbor{
			Config: NeighborConfig{
				NeighborAddress: netip.MustParseAddr(testNeighborAddress),
				PeerGroup:       "g",
			},
		}

		require.NoError(t, OverwriteNeighborConfigWithPeerGroup(n, pg))

		require.Len(t, n.AfiSafis, 1)
		assert.Equal(t, AFI_SAFI_TYPE_IPV4_UNICAST, n.AfiSafis[0].Config.AfiSafiName)
	})

	// peer-as is listed in forcedOverwrittenConfig, so the peer group wins over
	// whatever the caller passed.
	t.Run("forced_fields_still_come_from_the_group", func(t *testing.T) {
		clearConfiguredFields(t)

		pg := &PeerGroup{Config: PeerGroupConfig{PeerGroupName: "g", PeerAs: 65001}}
		n := &Neighbor{
			Config: NeighborConfig{
				NeighborAddress: netip.MustParseAddr(testNeighborAddress),
				PeerGroup:       "g",
				PeerAs:          65002,
			},
		}

		require.NoError(t, OverwriteNeighborConfigWithPeerGroup(n, pg))

		assert.Equal(t, uint32(65001), n.Config.PeerAs)
	})
}

// A neighbor read from a configuration file keeps the fields the operator
// spelled out, even when they hold the zero value of their type.
func TestOverwriteNeighborConfigWithPeerGroupKeepsConfiguredZeroValues(t *testing.T) {
	registerConfiguredFields(t, testNeighborAddress, map[string]any{
		"config": map[string]any{
			"neighbor-address":   testNeighborAddress,
			"peer-group":         "g",
			"description":        "",
			"route-flap-damping": false,
		},
	})

	pg := &PeerGroup{
		Config: PeerGroupConfig{
			PeerGroupName:    "g",
			Description:      "group description",
			RouteFlapDamping: true,
			AuthPassword:     "group password",
		},
	}
	n := &Neighbor{
		Config: NeighborConfig{
			NeighborAddress: netip.MustParseAddr(testNeighborAddress),
			PeerGroup:       "g",
		},
	}

	require.NoError(t, OverwriteNeighborConfigWithPeerGroup(n, pg))

	assert.Equal(t, "", n.Config.Description)
	assert.False(t, n.Config.RouteFlapDamping)
	assert.Equal(t, "group password", n.Config.AuthPassword)
}
