// Copyright (C) 2026 Nippon Telegraph and Telephone Corporation.
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

package gr

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

const (
	peerA = "10.0.0.1"
	peerB = "10.0.0.2"
	peerC = "10.0.0.3"
)

// twoPeers returns a restart that waits for peers A and B in ipv4 and ipv6.
func twoPeers(t *testing.T) *Restart {
	t.Helper()
	r := &Restart{}
	for _, p := range []string{peerA, peerB} {
		a := r.PeerAdded(p, []bgp.Family{v4, v6})
		require.Empty(t, a.StopTimers)
		require.Empty(t, a.Released)
		require.ElementsMatch(t, []DeferralTimer{
			{p, v4},
			{p, v6},
		}, a.StartTimers)
	}
	require.True(t, r.Restarting())
	require.True(t, r.Deferred(v4))
	require.True(t, r.Deferred(v6))
	return r
}

// The zero value is a speaker that does not restart. Events of peers that
// were not added do nothing.
func TestRestart_Zero(t *testing.T) {
	r := &Restart{}
	assert.False(t, r.Restarting())
	assert.False(t, r.Deferred(v4))
	assert.Equal(t, RestartActions{}, r.PeerEstablished(peerA, grNegotiated()))
	assert.Equal(t, RestartActions{}, r.EORReceived(peerA, v4))
	assert.Equal(t, RestartActions{}, r.PeerDown(peerA))
	assert.Equal(t, RestartActions{}, r.PeerRemoved(peerA))
	assert.Equal(t, RestartActions{}, r.TimerExpired(peerA, v4))
	assert.False(t, r.Restarting())
}

// A family is released when the End-of-RIB marker of every peer that is
// waited for is received. The families are independent.
func TestRestart_EORReceived(t *testing.T) {
	r := twoPeers(t)

	a := r.EORReceived(peerA, v4)
	assert.Equal(t, RestartActions{StopTimers: []DeferralTimer{{peerA, v4}}}, a)
	assert.True(t, r.Deferred(v4))
	// A second marker does nothing.
	assert.Equal(t, RestartActions{}, r.EORReceived(peerA, v4))

	a = r.EORReceived(peerB, v4)
	assert.Equal(t, RestartActions{StopTimers: []DeferralTimer{{peerB, v4}}, Released: []bgp.Family{v4}}, a)
	assert.False(t, r.Deferred(v4))
	assert.True(t, r.Deferred(v6))
	assert.True(t, r.Restarting())
	// A marker of a released family does nothing.
	assert.Equal(t, RestartActions{}, r.EORReceived(peerA, v4))
	// The timer of a released family is ignored.
	assert.Equal(t, RestartActions{}, r.TimerExpired(peerA, v4))

	r.EORReceived(peerA, v6)
	a = r.EORReceived(peerB, v6)
	assert.Equal(t, []bgp.Family{v6}, a.Released)
	assert.False(t, r.Restarting())
}

// A peer that does not advertise the Graceful Restart Capability, or that
// has the Restart State bit set, is not waited for (RFC 4724 Section 4.1).
// The other peers are waited for in the families the session negotiated.
func TestRestart_PeerEstablished(t *testing.T) {
	tests := []struct {
		name string
		n    Negotiated
		// want is what peer A still waits in after the event.
		want []bgp.Family
	}{
		{"no capability", Negotiated{Families: both}, nil},
		{"restart state bit", Negotiated{Families: both, GR: &bgp.CapGracefulRestart{Flags: restartStateBit}}, nil},
		{"both negotiated", Negotiated{Families: both, GR: grCap(120, grTuple(v4, true))}, []bgp.Family{v4, v6}},
		{"ipv6 not negotiated", Negotiated{Families: map[bgp.Family]bool{v4: true}, GR: grCap(120)}, []bgp.Family{v4}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := twoPeers(t)
			a := r.PeerEstablished(peerA, tt.n)
			var stopped []DeferralTimer
			for _, f := range []bgp.Family{v4, v6} {
				if !contains(tt.want, f) {
					stopped = append(stopped, DeferralTimer{peerA, f})
				}
			}
			assert.ElementsMatch(t, stopped, a.StopTimers)
			// Peer B still waits, so nothing is released.
			assert.Empty(t, a.Released)
			assert.True(t, r.Deferred(v4))
			assert.True(t, r.Deferred(v6))
			for _, f := range tt.want {
				assert.Equal(t, RestartActions{StopTimers: []DeferralTimer{{peerA, f}}}, r.EORReceived(peerA, f), f.String())
			}
		})
	}
}

func contains(l []bgp.Family, f bgp.Family) bool {
	for _, x := range l {
		if x == f {
			return true
		}
	}
	return false
}

// The last peer of a family that is excluded at Established releases the
// family.
func TestRestart_PeerEstablishedReleases(t *testing.T) {
	r := twoPeers(t)
	r.EORReceived(peerB, v4)
	r.EORReceived(peerB, v6)
	a := r.PeerEstablished(peerA, Negotiated{Families: both})
	assert.ElementsMatch(t, []DeferralTimer{{peerA, v4}, {peerA, v6}}, a.StopTimers)
	assert.ElementsMatch(t, []bgp.Family{v4, v6}, a.Released)
	assert.False(t, r.Restarting())
}

// A peer whose session ends, or that is removed, is not waited for any
// more.
func TestRestart_PeerDownAndRemoved(t *testing.T) {
	for _, tt := range []struct {
		name  string
		event func(r *Restart, p string) RestartActions
	}{
		{"down", (*Restart).PeerDown},
		{"removed", (*Restart).PeerRemoved},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := twoPeers(t)
			a := tt.event(r, peerA)
			assert.ElementsMatch(t, []DeferralTimer{{peerA, v4}, {peerA, v6}}, a.StopTimers)
			assert.Empty(t, a.Released)
			assert.True(t, r.Restarting())
			assert.Equal(t, RestartActions{}, tt.event(r, peerA))

			a = tt.event(r, peerB)
			assert.ElementsMatch(t, []bgp.Family{v4, v6}, a.Released)
			assert.False(t, r.Restarting())
		})
	}
}

// A peer that is added again is waited for again in the families that are
// not released. Adding a peer that is waited for does nothing.
func TestRestart_PeerAddedAgain(t *testing.T) {
	r := twoPeers(t)
	assert.Equal(t, RestartActions{}, r.PeerAdded(peerA, []bgp.Family{v4, v6}))

	r.PeerRemoved(peerA)
	a := r.PeerAdded(peerA, []bgp.Family{v4})
	assert.Equal(t, []DeferralTimer{{peerA, v4}}, a.StartTimers)
	assert.Equal(t, RestartActions{StopTimers: []DeferralTimer{{peerA, v4}}}, r.EORReceived(peerA, v4))
}

// The timer of a peer and family removes the peer from the family. A late
// expiry, after the peer left the family, does nothing.
func TestRestart_TimerExpired(t *testing.T) {
	r := twoPeers(t)
	a := r.TimerExpired(peerA, v4)
	// The timer has fired: nothing to stop.
	assert.Equal(t, RestartActions{}, a)
	assert.True(t, r.Deferred(v4))
	assert.Equal(t, RestartActions{}, r.TimerExpired(peerA, v4))

	a = r.TimerExpired(peerB, v4)
	assert.Equal(t, RestartActions{Released: []bgp.Family{v4}}, a)
	assert.False(t, r.Deferred(v4))
}

// A peer added after a family is released is not waited for in that family.
// A family that was never waited for is, while the restart goes on.
func TestRestart_PeerAddedAfterReleased(t *testing.T) {
	r := twoPeers(t)
	r.EORReceived(peerA, v4)
	r.EORReceived(peerB, v4)
	require.False(t, r.Deferred(v4))

	evpn := bgp.RF_EVPN
	a := r.PeerAdded(peerC, []bgp.Family{v4, v6, evpn})
	assert.ElementsMatch(t, []DeferralTimer{
		{peerC, v6},
		{peerC, evpn},
	}, a.StartTimers)
	assert.False(t, r.Deferred(v4))
	assert.True(t, r.Deferred(v6))
	assert.True(t, r.Deferred(evpn))
	assert.Equal(t, RestartActions{}, r.EORReceived(peerC, v4))
}

// A peer added after the restart is over is not waited for, also in a
// family that was never waited for.
func TestRestart_PeerAddedAfterRestart(t *testing.T) {
	r := twoPeers(t)
	for _, p := range []string{peerA, peerB} {
		r.EORReceived(p, v4)
		r.EORReceived(p, v6)
	}
	require.False(t, r.Restarting())

	assert.Equal(t, RestartActions{}, r.PeerAdded(peerC, []bgp.Family{v4, bgp.RF_EVPN}))
	assert.False(t, r.Deferred(bgp.RF_EVPN))
	assert.False(t, r.Restarting())
}

// A peer without families does not start the restart: the next peer does.
func TestRestart_PeerAddedNoFamilies(t *testing.T) {
	r := &Restart{}
	assert.Equal(t, RestartActions{}, r.PeerAdded(peerA, nil))
	assert.False(t, r.Restarting())

	a := r.PeerAdded(peerB, []bgp.Family{v4})
	assert.Equal(t, []DeferralTimer{{peerB, v4}}, a.StartTimers)
	assert.True(t, r.Restarting())
}
