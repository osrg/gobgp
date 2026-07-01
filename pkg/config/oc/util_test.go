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

	"github.com/osrg/gobgp/v4/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func newPeerFromConfigForBFDTest(t *testing.T, bfd Bfd) *api.Peer {
	t.Helper()
	n := &Neighbor{
		Config: NeighborConfig{
			NeighborAddress: netip.MustParseAddr("192.0.2.1"),
			PeerAs:          65001,
		},
		Bfd: bfd,
	}
	p := NewPeerFromConfigStruct(n)
	require.NotNil(t, p, "capabilities marshal should succeed for empty capability lists")
	return p
}

func newPeerGroupFromConfigForBFDTest(t *testing.T, bfd Bfd) *api.PeerGroup {
	t.Helper()
	pg := &PeerGroup{
		Config: PeerGroupConfig{
			PeerGroupName: "pg-bfd-test",
			PeerAs:        65001,
		},
		Bfd: bfd,
	}
	return NewPeerGroupFromConfigStruct(pg)
}

func TestNewPeerFromConfigStruct_BfdSessionState(t *testing.T) {
	cases := []struct {
		name     string
		oc       BfdSessionState
		wantAPI  api.BfdSessionState
		wantName string
	}{
		{"up", BFD_SESSION_STATE_UP, api.BfdSessionState_BFD_SESSION_STATE_UP, "BFD_SESSION_STATE_UP"},
		{"down", BFD_SESSION_STATE_DOWN, api.BfdSessionState_BFD_SESSION_STATE_DOWN, "BFD_SESSION_STATE_DOWN"},
		{"admin_down", BFD_SESSION_STATE_ADMIN_DOWN, api.BfdSessionState_BFD_SESSION_STATE_ADMIN_DOWN, "BFD_SESSION_STATE_ADMIN_DOWN"},
		{"init", BFD_SESSION_STATE_INIT, api.BfdSessionState_BFD_SESSION_STATE_INIT, "BFD_SESSION_STATE_INIT"},
		{"invalid_empty", BfdSessionState(""), api.BfdSessionState_BFD_SESSION_STATE_UNSPECIFIED, "BFD_SESSION_STATE_UNSPECIFIED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newPeerFromConfigForBFDTest(t, Bfd{
				State: BfdState{
					SessionState:       tc.oc,
					RemoteSessionState: tc.oc,
				},
			})
			got := p.GetState().GetBfdState()
			require.NotNil(t, got)
			assert.Equal(t, tc.wantAPI, got.SessionState, "session_state for %s", tc.wantName)
			assert.Equal(t, tc.wantAPI, got.RemoteSessionState, "remote_session_state for %s", tc.wantName)
		})
	}
}

func TestNewPeerFromConfigStruct_BfdDiagnosticCode(t *testing.T) {
	cases := []struct {
		name    string
		oc      BfdDiagnosticCode
		wantAPI api.BfdDiagnosticCode
	}{
		{"no_diagnostic", BFD_DIAGNOSTIC_CODE_NO_DIAGNOSTIC, api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_NO_DIAGNOSTIC},
		{"detection_timeout", BFD_DIAGNOSTIC_CODE_DETECTION_TIMEOUT, api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_DETECTION_TIMEOUT},
		{"echo_failed", BFD_DIAGNOSTIC_CODE_ECHO_FAILED, api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_ECHO_FAILED},
		{"neighbor_signaled_session_down", BFD_DIAGNOSTIC_CODE_NEIGHBOR_SIGNALED_SESSION_DOWN, api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_NEIGHBOR_SIGNALED_SESSION_DOWN},
		{"forwarding_plane_reset", BFD_DIAGNOSTIC_CODE_FORWARDING_PLANE_RESET, api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_FORWARDING_PLANE_RESET},
		{"path_down", BFD_DIAGNOSTIC_CODE_PATH_DOWN, api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_PATH_DOWN},
		{"concatenated_path_down", BFD_DIAGNOSTIC_CODE_CONCATENATED_PATH_DOWN, api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_CONCATENATED_PATH_DOWN},
		{"administratively_down", BFD_DIAGNOSTIC_CODE_ADMINISTRATIVELY_DOWN, api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_ADMINISTRATIVELY_DOWN},
		{"reverse_concatenated_path_down", BFD_DIAGNOSTIC_CODE_REVERSE_CONCATENATED_PATH_DOWN, api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_REVERSE_CONCATENATED_PATH_DOWN},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newPeerFromConfigForBFDTest(t, Bfd{
				State: BfdState{
					LocalDiagnosticCode:  tc.oc,
					RemoteDiagnosticCode: tc.oc,
				},
			})
			got := p.GetState().GetBfdState()
			require.NotNil(t, got)
			assert.Equal(t, tc.wantAPI, got.LocalDiagnosticCode)
			assert.Equal(t, tc.wantAPI, got.RemoteDiagnosticCode)
		})
	}

	t.Run("invalid_empty_maps_to_no_diagnostic", func(t *testing.T) {
		p := newPeerFromConfigForBFDTest(t, Bfd{
			State: BfdState{
				LocalDiagnosticCode:  BfdDiagnosticCode(""),
				RemoteDiagnosticCode: BfdDiagnosticCode(""),
			},
		})
		got := p.GetState().GetBfdState()
		require.NotNil(t, got)
		assert.Equal(t, api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_NO_DIAGNOSTIC, got.LocalDiagnosticCode)
		assert.Equal(t, api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_NO_DIAGNOSTIC, got.RemoteDiagnosticCode)
	})
}

func TestNewPeerFromConfigStruct_BfdConfigAndStateScalars(t *testing.T) {
	p := newPeerFromConfigForBFDTest(t, Bfd{
		Config: BfdConfig{
			Enabled:                  true,
			Port:                     4784,
			DesiredMinimumTxInterval: 111,
			RequiredMinimumReceive:   222,
			DetectionMultiplier:      5,
		},
		State: BfdState{
			SessionState:                 BFD_SESSION_STATE_UP,
			RemoteSessionState:           BFD_SESSION_STATE_INIT,
			LastFailureTime:              9001,
			FailureTransitions:           3,
			LocalDiscriminator:           10,
			RemoteDiscriminator:          20,
			LocalDiagnosticCode:          BFD_DIAGNOSTIC_CODE_PATH_DOWN,
			RemoteDiagnosticCode:         BFD_DIAGNOSTIC_CODE_ECHO_FAILED,
			RemoteMinimumReceiveInterval: 333,
			BfdAsync:                     BfdAsync{TransmittedPackets: 40, ReceivedPackets: 41},
		},
	})

	cfg := p.GetBfd()
	require.NotNil(t, cfg)
	assert.True(t, cfg.Enabled)
	assert.Equal(t, uint32(4784), cfg.Port)
	assert.Equal(t, uint32(111), cfg.DesiredMinimumTxInterval)
	assert.Equal(t, uint32(222), cfg.RequiredMinimumReceive)
	assert.Equal(t, uint32(5), cfg.DetectionMultiplier)

	st := p.GetState().GetBfdState()
	require.NotNil(t, st)
	assert.Equal(t, api.BfdSessionState_BFD_SESSION_STATE_UP, st.SessionState)
	assert.Equal(t, api.BfdSessionState_BFD_SESSION_STATE_INIT, st.RemoteSessionState)
	assert.Equal(t, uint64(9001), st.LastFailureTime)
	assert.Equal(t, uint64(3), st.FailureTransitions)
	assert.Equal(t, uint32(10), st.LocalDiscriminator)
	assert.Equal(t, uint32(20), st.RemoteDiscriminator)
	assert.Equal(t, api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_PATH_DOWN, st.LocalDiagnosticCode)
	assert.Equal(t, api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_ECHO_FAILED, st.RemoteDiagnosticCode)
	assert.Equal(t, uint32(333), st.RemoteMinimumReceiveInterval)
	require.NotNil(t, st.BfdAsync)
	assert.Equal(t, uint64(40), st.BfdAsync.TransmittedPackets)
	assert.Equal(t, uint64(41), st.BfdAsync.ReceivedPackets)
}

// api.PeerGroup carries only BfdPeerConfig (no BfdPeerState); NewPeerGroupFromConfigStruct
// maps pconf.Bfd.Config only. Bfd.State is intentionally not asserted on the API message.
func TestNewPeerGroupFromConfigStruct_BfdConfig(t *testing.T) {
	t.Run("full_config", func(t *testing.T) {
		pg := newPeerGroupFromConfigForBFDTest(t, Bfd{
			Config: BfdConfig{
				Enabled:                  true,
				Port:                     4784,
				DesiredMinimumTxInterval: 111,
				RequiredMinimumReceive:   222,
				DetectionMultiplier:      7,
			},
			State: BfdState{
				SessionState:         BFD_SESSION_STATE_UP,
				LocalDiagnosticCode:  BFD_DIAGNOSTIC_CODE_PATH_DOWN,
				RemoteDiagnosticCode: BFD_DIAGNOSTIC_CODE_ECHO_FAILED,
			},
		})
		cfg := pg.GetBfd()
		require.NotNil(t, cfg)
		assert.True(t, cfg.Enabled)
		assert.Equal(t, uint32(4784), cfg.Port)
		assert.Equal(t, uint32(111), cfg.DesiredMinimumTxInterval)
		assert.Equal(t, uint32(222), cfg.RequiredMinimumReceive)
		assert.Equal(t, uint32(7), cfg.DetectionMultiplier)
	})

	t.Run("disabled_zeroish_defaults", func(t *testing.T) {
		pg := newPeerGroupFromConfigForBFDTest(t, Bfd{})
		cfg := pg.GetBfd()
		require.NotNil(t, cfg)
		assert.False(t, cfg.Enabled)
		assert.Equal(t, uint32(0), cfg.Port)
		assert.Equal(t, uint32(0), cfg.DesiredMinimumTxInterval)
		assert.Equal(t, uint32(0), cfg.RequiredMinimumReceive)
		assert.Equal(t, uint32(0), cfg.DetectionMultiplier)
	})
}
