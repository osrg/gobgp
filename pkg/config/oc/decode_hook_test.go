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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const rangeTestGlobal = `
[global.config]
  as = 65000
  router-id = "192.0.2.1"
`

func rangeTestNeighbor(extra string) string {
	return rangeTestGlobal + `
[[neighbors]]
  [neighbors.config]
    neighbor-address = "192.0.2.2"
    peer-as = 65001
` + extra
}

func TestIntegerRangeHookRejectsOutOfRange(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name:   "uint32 max",
			config: "[global.config]\n  router-id = \"192.0.2.1\"\n  as = 4294967295\n",
		},
		{
			name:    "uint32 overflow",
			config:  "[global.config]\n  router-id = \"192.0.2.1\"\n  as = 4294967296\n",
			wantErr: "'global.config.as' cannot parse value as 'uint32': value out of range",
		},
		{
			name:    "uint32 negative",
			config:  "[global.config]\n  router-id = \"192.0.2.1\"\n  as = -1\n",
			wantErr: "'global.config.as' cannot parse value as 'uint32': value out of range",
		},
		{
			name:   "uint16 max",
			config: rangeTestNeighbor("  [neighbors.transport.config]\n    tcp-mss = 65535\n"),
		},
		{
			name:    "uint16 overflow",
			config:  rangeTestNeighbor("  [neighbors.transport.config]\n    tcp-mss = 65536\n"),
			wantErr: "cannot parse value as 'uint16': value out of range",
		},
		{
			name:   "uint8 max",
			config: rangeTestNeighbor("  [neighbors.ttl-security.config]\n    enabled = true\n    ttl-min = 255\n"),
		},
		{
			name:    "uint8 overflow",
			config:  rangeTestNeighbor("  [neighbors.ttl-security.config]\n    enabled = true\n    ttl-min = 256\n"),
			wantErr: "cannot parse value as 'uint8': value out of range",
		},
		{
			name:    "uint8 overflow wraps without the hook",
			config:  rangeTestNeighbor("  [neighbors.ebgp-multihop.config]\n    enabled = true\n    multihop-ttl = 300\n"),
			wantErr: "cannot parse value as 'uint8': value out of range",
		},
		{
			// port is int32 and -1 means "do not listen", so a negative value
			// must stay accepted.
			name:   "int32 negative is accepted",
			config: "[global.config]\n  as = 65000\n  router-id = \"192.0.2.1\"\n  port = -1\n",
		},
		{
			name:    "int32 overflow",
			config:  "[global.config]\n  as = 65000\n  router-id = \"192.0.2.1\"\n  port = 2147483648\n",
			wantErr: "'global.config.port' cannot parse value as 'int32': value out of range",
		},
		{
			name:    "int32 underflow",
			config:  "[global.config]\n  as = 65000\n  router-id = \"192.0.2.1\"\n  port = -2147483649\n",
			wantErr: "'global.config.port' cannot parse value as 'int32': value out of range",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadConfig(strings.NewReader(tt.config), "toml")
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestIntegerRangeHookKeepsInRangeValues checks that the hook does not disturb
// the values it lets through.
func TestIntegerRangeHookKeepsInRangeValues(t *testing.T) {
	config, err := ReadConfig(strings.NewReader(rangeTestNeighbor(
		"  [neighbors.transport.config]\n    tcp-mss = 1400\n"+
			"  [neighbors.ttl-security.config]\n    enabled = true\n    ttl-min = 254\n")), "toml")
	require.NoError(t, err)

	assert.Equal(t, uint32(65000), config.Global.Config.As)
	require.Len(t, config.Neighbors, 1)
	assert.Equal(t, uint32(65001), config.Neighbors[0].Config.PeerAs)
	assert.Equal(t, uint16(1400), config.Neighbors[0].Transport.Config.TcpMss)
	assert.Equal(t, uint8(254), config.Neighbors[0].TtlSecurity.Config.TtlMin)
}

// TestIntegerRangeHookLeavesOtherInputAlone checks the input kinds the hook
// deliberately does not touch. A string is already range checked by
// mapstructure itself; float and bool keep the weak conversion they had.
func TestIntegerRangeHookLeavesOtherInputAlone(t *testing.T) {
	t.Run("string in range", func(t *testing.T) {
		config, err := ReadConfig(strings.NewReader(
			"[global.config]\n  router-id = \"192.0.2.1\"\n  as = \"65000\"\n"), "toml")
		require.NoError(t, err)
		assert.Equal(t, uint32(65000), config.Global.Config.As)
	})

	t.Run("string out of range is still rejected by mapstructure", func(t *testing.T) {
		_, err := ReadConfig(strings.NewReader(
			"[global.config]\n  router-id = \"192.0.2.1\"\n  as = \"4294967296\"\n"), "toml")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot parse value as 'uint32'")
	})

	t.Run("float", func(t *testing.T) {
		config, err := ReadConfig(strings.NewReader(
			"[global.config]\n  router-id = \"192.0.2.1\"\n  as = 6.5e4\n"), "toml")
		require.NoError(t, err)
		assert.Equal(t, uint32(65000), config.Global.Config.As)
	})
}
