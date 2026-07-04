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
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
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

func TestParseMaskLength(t *testing.T) {
	assert := assert.New(t)
	cases := []struct {
		prefix string
		mask   string
		min    int
		max    int
		err    bool
	}{
		// IPv4: default mask = prefix length.
		{"10.0.0.0/24", "", 24, 24, false},
		// IPv4: range within 0..32.
		{"10.0.0.0/24", "24..32", 24, 32, false},
		// IPv4: out-of-scope (>32) rejected.
		{"10.0.0.0/24", "24..40", 0, 0, true},

		// IPv6: default mask = prefix length.
		{"2001:db8::/32", "", 32, 32, false},
		// IPv6: range within 0..128.
		{"2001:db8::/32", "32..128", 32, 128, false},
		// IPv6: out-of-scope (>128) rejected.
		{"2001:db8::/32", "32..200", 0, 0, true},

		// RTC: default mask = prefix length.
		{"65000:65000:100/96", "", 96, 96, false},
		// RTC: explicit range within 0..96.
		{"65000:65000:100/96", "32..96", 32, 96, false},
		{"0:0:0/0", "32..96", 32, 96, false},
		// RTC: out-of-scope (>96) rejected.
		{"65000:65000:100/96", "90..128", 0, 0, true},
		// RTC: malformed prefix.
		{"65000:65000", "96..96", 0, 0, true},

		// inverted range rejected for any family.
		{"10.0.0.0/24", "32..24", 0, 0, true},
		{"65000:65000:100/96", "96..32", 0, 0, true},
		// malformed range.
		{"10.0.0.0/24", "24", 0, 0, true},
	}
	for _, c := range cases {
		min, max, err := ParseMaskLength(c.prefix, c.mask)
		if c.err {
			assert.Error(err, "%s %s", c.prefix, c.mask)
			continue
		}
		assert.NoError(err, c.prefix)
		assert.Equal(c.min, min, c.prefix)
		assert.Equal(c.max, max, c.prefix)
	}
}

func TestPrefixToPrefix(t *testing.T) {
	assert := assert.New(t)
	pfx, rf, err := (&Prefix{IpPrefix: netip.MustParsePrefix("10.0.0.0/24")}).ToPrefix()
	assert.NoError(err)
	assert.Equal("10.0.0.0/24", pfx.String())
	assert.Equal(bgp.RF_IPv4_UC, rf)

	pfx, rf, err = (&Prefix{IpPrefix: netip.MustParsePrefix("2001:db8::/32")}).ToPrefix()
	assert.NoError(err)
	assert.Equal("2001:db8::/32", pfx.String())
	assert.Equal(bgp.RF_IPv6_UC, rf)

	pfx, rf, err = (&Prefix{RtcPrefix: "123:65000:100/96"}).ToPrefix()
	assert.NoError(err)
	assert.Equal(bgp.RF_RTC_UC, rf)
	assert.Equal(96, pfx.Bits())

	_, _, err = (&Prefix{IpPrefix: netip.MustParsePrefix("10.0.0.0/24"), RtcPrefix: "123:65000:100/96"}).ToPrefix()
	assert.Error(err)
	_, _, err = (&Prefix{}).ToPrefix()
	assert.Error(err)
}

func TestNewAPIPrefixFromConfigStructRtc(t *testing.T) {
	assert := assert.New(t)
	// rtc-prefix config round-trips into the api.Prefix RtcPrefix field
	out, err := newAPIPrefixFromConfigStruct(Prefix{RtcPrefix: "65000:65000:100/96", MasklengthRange: "96..96"})
	assert.NoError(err)
	assert.Equal(&api.Prefix{RtcPrefix: "65000:65000:100/96", MaskLengthMin: 96, MaskLengthMax: 96}, out)
	// ip-prefix config unchanged
	out, err = newAPIPrefixFromConfigStruct(Prefix{IpPrefix: netip.MustParsePrefix("10.0.0.0/24"), MasklengthRange: "24..24"})
	assert.NoError(err)
	assert.Equal(&api.Prefix{IpPrefix: "10.0.0.0/24", MaskLengthMin: 24, MaskLengthMax: 24}, out)
}
