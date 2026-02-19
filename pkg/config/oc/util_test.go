// Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
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

package oc

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetectConfigFileType(t *testing.T) {
	assert := assert.New(t)

	assert.Equal("toml", detectConfigFileType("bgpd.conf", "toml"))
	assert.Equal("toml", detectConfigFileType("bgpd.toml", "xxx"))
	assert.Equal("yaml", detectConfigFileType("bgpd.yaml", "xxx"))
	assert.Equal("yaml", detectConfigFileType("bgpd.yml", "xxx"))
	assert.Equal("json", detectConfigFileType("bgpd.json", "xxx"))
}

func TestIsAfiSafiChanged(t *testing.T) {
	v4 := AfiSafi{
		Config: AfiSafiConfig{
			AfiSafiName: AFI_SAFI_TYPE_IPV4_UNICAST,
		},
	}
	v6 := AfiSafi{
		Config: AfiSafiConfig{
			AfiSafiName: AFI_SAFI_TYPE_IPV6_UNICAST,
		},
	}
	old := []AfiSafi{v4}
	new := []AfiSafi{v4}
	assert.False(t, isAfiSafiChanged(old, new))

	new = append(new, v6)
	assert.True(t, isAfiSafiChanged(old, new))

	new = []AfiSafi{v6}
	assert.True(t, isAfiSafiChanged(old, new))
	v4ap := v4
	v4ap.AddPaths.Config.Receive = true
	new = []AfiSafi{v4ap}
	assert.True(t, isAfiSafiChanged(old, new))
}

func TestIsEBGPPeerWithConfederation(t *testing.T) {
	g := &Global{
		Config: GlobalConfig{
			As: 101,
		},
		Confederation: Confederation{
			Config: ConfederationConfig{
				Enabled:      true,
				Identifier:   65000,
				MemberAsList: []uint32{102},
			},
		},
	}

	tests := []struct {
		name   string
		peerAs uint32
		want   bool
	}{
		{
			name:   "same member AS is internal",
			peerAs: 101,
			want:   false,
		},
		{
			name:   "other confederation member is external",
			peerAs: 102,
			want:   true,
		},
		{
			name:   "confederation identifier non-member is external",
			peerAs: 65000,
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &Neighbor{
				Config: NeighborConfig{
					PeerAs:  tt.peerAs,
					LocalAs: 65000,
				},
			}
			assert.Equal(t, tt.want, n.IsEBGPPeer(g))
		})
	}
}

func TestSetDefaultNeighborConfigValuesConfedIdentifierPeerType(t *testing.T) {
	g := &Global{
		Config: GlobalConfig{
			As: 101,
		},
		Confederation: Confederation{
			Config: ConfederationConfig{
				Enabled:      true,
				Identifier:   65000,
				MemberAsList: []uint32{102},
			},
		},
	}
	n := &Neighbor{
		Config: NeighborConfig{
			PeerAs:          65000,
			NeighborAddress: netip.MustParseAddr("192.0.2.10"),
		},
	}

	assert.NoError(t, SetDefaultNeighborConfigValues(n, nil, g))
	assert.Equal(t, uint32(65000), n.Config.LocalAs)
	assert.Equal(t, PEER_TYPE_EXTERNAL, n.State.PeerType)
}
