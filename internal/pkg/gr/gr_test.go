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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

var (
	v4 = bgp.RF_IPv4_UC
	v6 = bgp.RF_IPv6_UC

	both = map[bgp.Family]bool{v4: true, v6: true}
)

func grCap(restartTime uint16, tuples ...*bgp.CapGracefulRestartTuple) *bgp.CapGracefulRestart {
	return bgp.NewCapGracefulRestart(false, false, restartTime, tuples)
}

func grTuple(f bgp.Family, forward bool) *bgp.CapGracefulRestartTuple {
	return bgp.NewCapGracefulRestartTuple(f, forward)
}

func llgrCap(tuples ...*bgp.CapLongLivedGracefulRestartTuple) *bgp.CapLongLivedGracefulRestart {
	return bgp.NewCapLongLivedGracefulRestart(tuples)
}

func llgrTuple(f bgp.Family, forward bool, llst uint32) *bgp.CapLongLivedGracefulRestartTuple {
	return bgp.NewCapLongLivedGracefulRestartTuple(f, forward, llst)
}

// grNegotiated is what a session negotiated: graceful restart for ipv4 and
// ipv6, and long-lived graceful restart for ipv4 with an LLST of 60 seconds.
func grNegotiated() Negotiated {
	return Negotiated{
		Families: both,
		GR:       grCap(120, grTuple(v4, true), grTuple(v6, true)),
		LLGR:     llgrCap(llgrTuple(v4, true, 60)),
	}
}

func requirePhase(t *testing.T, h *Helper, f bgp.Family, want Phase) {
	t.Helper()
	require.Equal(t, want, h.Phase(f), f.String())
}

// established returns a helper whose session negotiated n.
func established(n Negotiated) *Helper {
	h := &Helper{}
	h.SessionEstablished(n)
	return h
}

// restarted returns a helper whose session (grNegotiated) ended as a graceful
// restart, with ipv4 and ipv6 stale. It also returns the ID of the Restart
// Time timer.
func restarted(t *testing.T) (*Helper, uint64) {
	t.Helper()
	h := established(grNegotiated())
	require.False(t, h.Restarting())
	a := h.SessionDown(grNegotiated())
	require.ElementsMatch(t, []bgp.Family{v4, v6}, a.MarkStale)
	require.Empty(t, a.DropStale)
	require.Empty(t, a.StopLLGRTimers)
	require.False(t, a.StopRestartTimer)
	require.NotNil(t, a.StartRestartTimer)
	require.Equal(t, 120*time.Second, a.StartRestartTimer.Duration)
	requirePhase(t, h, v4, Stale)
	requirePhase(t, h, v6, Stale)
	require.True(t, h.Restarting())
	return h, a.StartRestartTimer.ID
}

// llgrStarted returns a helper whose Restart Time expired: ipv4 is in the
// long-lived stale period, and ipv6 is done. It also returns the ID of the
// ipv4 LLST timer.
func llgrStarted(t *testing.T) (*Helper, uint64) {
	t.Helper()
	h, id := restarted(t)
	a := h.TimerExpired(id)
	require.Len(t, a.StartLLGRTimers, 1)
	return h, a.StartLLGRTimers[0].ID
}

// Only the families that the session negotiated and that are in its
// Graceful Restart Capability are kept as stale, whatever their F bit is.
func TestHelper_SessionDownFamilies(t *testing.T) {
	tests := []struct {
		name    string
		session Negotiated
		want    []bgp.Family
	}{
		{"no capability", Negotiated{Families: both}, nil},
		{"F bit clear", Negotiated{Families: both, GR: grCap(120, grTuple(v4, false))}, []bgp.Family{v4}},
		{"not negotiated", Negotiated{
			Families: map[bgp.Family]bool{v6: true},
			GR:       grCap(120, grTuple(v4, true), grTuple(v6, true)),
		}, []bgp.Family{v6}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := established(tt.session)
			a := h.SessionDown(tt.session)
			assert.ElementsMatch(t, tt.want, a.MarkStale)
			assert.Equal(t, len(tt.want) > 0, a.StartRestartTimer != nil)
			assert.Equal(t, len(tt.want) > 0, h.Restarting())
		})
	}
}

// An event out of order, or a timer ID that was never issued, is a bug of
// the caller.
func TestHelper_MisusePanics(t *testing.T) {
	tests := []struct {
		name string
		f    func(t *testing.T) func()
	}{
		{"SessionDown without a session", func(t *testing.T) func() {
			h := &Helper{}
			return func() { h.SessionDown(grNegotiated()) }
		}},
		{"SessionDown twice", func(t *testing.T) func() {
			h, _ := restarted(t)
			return func() { h.SessionDown(grNegotiated()) }
		}},
		{"SessionEstablished twice", func(t *testing.T) func() {
			h := established(grNegotiated())
			return func() { h.SessionEstablished(grNegotiated()) }
		}},
		{"EORReceived without a session", func(t *testing.T) func() {
			h, _ := restarted(t)
			return func() { h.EORReceived(v4) }
		}},
		{"TimerExpired with ID 0", func(t *testing.T) func() {
			h, _ := restarted(t)
			return func() { h.TimerExpired(0) }
		}},
		{"LLGRTimerExpired with ID 0", func(t *testing.T) func() {
			h, _ := llgrStarted(t)
			return func() { h.LLGRTimerExpired(v4, 0) }
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Panics(t, tt.f(t))
		})
	}
}

// A Restart Time of zero still starts the timer. It expires at once.
func TestHelper_SessionDownRestartTimeZero(t *testing.T) {
	n := Negotiated{Families: both, GR: grCap(0, grTuple(v4, true))}
	h := established(n)
	a := h.SessionDown(n)
	require.NotNil(t, a.StartRestartTimer)
	assert.Zero(t, a.StartRestartTimer.Duration)
}

func TestHelper_TimerExpired(t *testing.T) {
	h, id := restarted(t)

	// A timer with another ID is ignored.
	assert.Equal(t, Actions{}, h.TimerExpired(id+1))
	requirePhase(t, h, v4, Stale)

	a := h.TimerExpired(id)
	assert.Equal(t, []bgp.Family{v6}, a.DropStale)
	assert.Equal(t, []bgp.Family{v4}, a.MarkLLGRStale)
	assert.False(t, a.StopRestartTimer)
	assert.Empty(t, a.StopLLGRTimers)
	require.Len(t, a.StartLLGRTimers, 1)
	assert.Equal(t, v4, a.StartLLGRTimers[0].Family)
	assert.Equal(t, 60*time.Second, a.StartLLGRTimers[0].Duration)
	requirePhase(t, h, v4, LLGRStale)
	requirePhase(t, h, v6, None)
	assert.True(t, h.Restarting())

	// The same timer again does nothing.
	assert.Equal(t, Actions{}, h.TimerExpired(id))
}

// Without long-lived graceful restart, all families are done when the
// Restart Time expires. The LLGR Capability without the GR Capability does
// not count, and an LLST of zero means no long-lived graceful restart.
func TestHelper_TimerExpiredWithoutLLGR(t *testing.T) {
	tests := []struct {
		name string
		llgr *bgp.CapLongLivedGracefulRestart
	}{
		{"no LLGR Capability", nil},
		{"LLST of zero", llgrCap(llgrTuple(v4, true, 0))},
		{"other family", llgrCap(llgrTuple(v6, true, 60))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := Negotiated{Families: both, GR: grCap(120, grTuple(v4, true)), LLGR: tt.llgr}
			h := established(n)
			a := h.SessionDown(n)
			a = h.TimerExpired(a.StartRestartTimer.ID)
			assert.Equal(t, Actions{DropStale: []bgp.Family{v4}}, a)
			assert.False(t, h.Restarting())
		})
	}
}

func TestHelper_LLGRTimerExpired(t *testing.T) {
	h, id := llgrStarted(t)

	// A timer with another ID is ignored.
	assert.Equal(t, Actions{}, h.LLGRTimerExpired(v4, id+1))
	requirePhase(t, h, v4, LLGRStale)

	a := h.LLGRTimerExpired(v4, id)
	assert.Equal(t, Actions{DropStale: []bgp.Family{v4}}, a)
	requirePhase(t, h, v4, None)
	assert.False(t, h.Restarting())
	assert.Empty(t, h.families)

	// The same timer again does nothing.
	assert.Equal(t, Actions{}, h.LLGRTimerExpired(v4, id))
}

// A family in Stale is checked against the Graceful Restart Capability of
// the new session (RFC 4724 Section 4.2).
func TestHelper_SessionEstablished(t *testing.T) {
	tests := []struct {
		name     string
		session  Negotiated
		wantDrop []bgp.Family
	}{
		{"both preserved", grNegotiated(), nil},
		{"ipv4 F bit clear", Negotiated{Families: both, GR: grCap(120, grTuple(v4, false), grTuple(v6, true))}, []bgp.Family{v4}},
		{"ipv4 not in the capability", Negotiated{Families: both, GR: grCap(120, grTuple(v6, true))}, []bgp.Family{v4}},
		{"ipv4 not negotiated", Negotiated{
			Families: map[bgp.Family]bool{v6: true},
			GR:       grCap(120, grTuple(v4, true), grTuple(v6, true)),
		}, []bgp.Family{v4}},
		{"no capability", Negotiated{Families: both}, []bgp.Family{v4, v6}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, id := restarted(t)
			a := h.SessionEstablished(tt.session)
			assert.True(t, a.StopRestartTimer)
			assert.ElementsMatch(t, tt.wantDrop, a.DropStale)
			assert.Empty(t, a.StopLLGRTimers)
			for _, f := range []bgp.Family{v4, v6} {
				want := Stale
				for _, d := range tt.wantDrop {
					if d == f {
						want = None
					}
				}
				requirePhase(t, h, f, want)
			}

			// The Restart Time timer was stopped too late.
			assert.Equal(t, Actions{}, h.TimerExpired(id))
		})
	}
}

// The first session of the peer: nothing to do.
func TestHelper_SessionEstablishedFirst(t *testing.T) {
	h := &Helper{}
	assert.Equal(t, Actions{}, h.SessionEstablished(grNegotiated()))
	assert.False(t, h.Restarting())
}

// A family in the long-lived stale period is checked against the Long-Lived
// Graceful Restart Capability of the new session (RFC 9494 Section 4.2).
func TestHelper_SessionEstablishedLLGR(t *testing.T) {
	tests := []struct {
		name    string
		session Negotiated
		kept    bool
	}{
		{"preserved", Negotiated{Families: both, GR: grCap(120), LLGR: llgrCap(llgrTuple(v4, true, 60))}, true},
		{"F bit clear", Negotiated{Families: both, GR: grCap(120), LLGR: llgrCap(llgrTuple(v4, false, 60))}, false},
		{"not in the capability", Negotiated{Families: both, GR: grCap(120), LLGR: llgrCap(llgrTuple(v6, true, 60))}, false},
		{"no LLGR Capability", Negotiated{Families: both, GR: grCap(120, grTuple(v4, true))}, false},
		{"no GR Capability", Negotiated{Families: both, LLGR: llgrCap(llgrTuple(v4, true, 60))}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, id := llgrStarted(t)
			a := h.SessionEstablished(tt.session)
			if tt.kept {
				assert.Equal(t, Actions{}, a)
				requirePhase(t, h, v4, LLGRStale)
				assert.True(t, h.Restarting())
				return
			}
			assert.Equal(t, Actions{DropStale: []bgp.Family{v4}, StopLLGRTimers: []bgp.Family{v4}}, a)
			requirePhase(t, h, v4, None)
			assert.False(t, h.Restarting())
			assert.Equal(t, Actions{}, h.LLGRTimerExpired(v4, id))
		})
	}
}

func TestHelper_EORReceived(t *testing.T) {
	h, _ := restarted(t)
	h.SessionEstablished(grNegotiated())

	a := h.EORReceived(v4)
	assert.Equal(t, Actions{DropStale: []bgp.Family{v4}}, a)
	requirePhase(t, h, v4, None)
	assert.True(t, h.Restarting())

	// A second marker does nothing.
	assert.Equal(t, Actions{}, h.EORReceived(v4))

	h.EORReceived(v6)
	assert.False(t, h.Restarting())
}

// The End-of-RIB marker of a family in the long-lived stale period ends its
// period and stops its timer. A later expiry of that timer is ignored.
func TestHelper_EORReceivedLLGR(t *testing.T) {
	h, id := llgrStarted(t)
	h.SessionEstablished(grNegotiated())

	a := h.EORReceived(v4)
	assert.Equal(t, Actions{DropStale: []bgp.Family{v4}, StopLLGRTimers: []bgp.Family{v4}}, a)
	requirePhase(t, h, v4, None)
	assert.False(t, h.Restarting())

	assert.Equal(t, Actions{}, h.LLGRTimerExpired(v4, id))
}

// The session ends again while the families are in Stale. The stale routes
// of the first restart are removed before the routes are marked stale again
// (RFC 4724 Section 4.2). The Restart Time timer starts again.
func TestHelper_ConsecutiveRestart(t *testing.T) {
	h, _ := restarted(t)
	h.SessionEstablished(grNegotiated())

	a := h.SessionDown(Negotiated{
		Families: both,
		GR:       grCap(90, grTuple(v4, true), grTuple(v6, true)),
		LLGR:     llgrCap(llgrTuple(v4, true, 30)),
	})
	assert.ElementsMatch(t, []bgp.Family{v4, v6}, a.DropStale)
	assert.ElementsMatch(t, []bgp.Family{v4, v6}, a.MarkStale)
	assert.Empty(t, a.MarkLLGRStale)
	require.NotNil(t, a.StartRestartTimer)
	assert.Equal(t, 90*time.Second, a.StartRestartTimer.Duration)
	requirePhase(t, h, v4, Stale)
	requirePhase(t, h, v6, Stale)

	// The LLST of the session that ended is used.
	a = h.TimerExpired(a.StartRestartTimer.ID)
	require.Len(t, a.StartLLGRTimers, 1)
	assert.Equal(t, 30*time.Second, a.StartLLGRTimers[0].Duration)
}

// The session ends again while ipv4 is in the long-lived stale period. Its
// stale routes are kept, the new stale routes get LLGR_STALE, and its timer
// is not started again (RFC 9494 Section 4.2).
func TestHelper_ConsecutiveRestartLLGR(t *testing.T) {
	h, id := llgrStarted(t)
	h.SessionEstablished(grNegotiated())

	a := h.SessionDown(grNegotiated())
	assert.Empty(t, a.DropStale)
	assert.ElementsMatch(t, []bgp.Family{v4, v6}, a.MarkStale)
	assert.Equal(t, []bgp.Family{v4}, a.MarkLLGRStale)
	assert.Empty(t, a.StopLLGRTimers)
	assert.Empty(t, a.StartLLGRTimers)
	// ipv6 is stale, so the Restart Time timer starts.
	require.NotNil(t, a.StartRestartTimer)
	requirePhase(t, h, v4, LLGRStale)
	requirePhase(t, h, v6, Stale)

	a = h.TimerExpired(a.StartRestartTimer.ID)
	assert.Equal(t, []bgp.Family{v6}, a.DropStale)
	assert.Empty(t, a.StartLLGRTimers)
	requirePhase(t, h, v4, LLGRStale)

	// The first ipv4 timer still counts.
	assert.Equal(t, Actions{DropStale: []bgp.Family{v4}}, h.LLGRTimerExpired(v4, id))
	assert.False(t, h.Restarting())
}

// Only a family in the long-lived stale period is left. The Restart Time
// timer does not start.
func TestHelper_ConsecutiveRestartOnlyLLGR(t *testing.T) {
	h, _ := llgrStarted(t)
	h.SessionEstablished(grNegotiated())

	a := h.SessionDown(Negotiated{Families: both, GR: grCap(120, grTuple(v4, true))})
	assert.Nil(t, a.StartRestartTimer)
	requirePhase(t, h, v4, LLGRStale)
}

// A family that is not in the graceful restart of the session that ended is
// done. The caller has removed its routes.
func TestHelper_SessionDownFamilyRemoved(t *testing.T) {
	h, _ := llgrStarted(t)
	h.SessionEstablished(grNegotiated())

	a := h.SessionDown(Negotiated{Families: both, GR: grCap(120, grTuple(v6, true))})
	assert.Equal(t, []bgp.Family{v6}, a.MarkStale)
	assert.Equal(t, []bgp.Family{v4}, a.StopLLGRTimers)
	assert.Empty(t, a.DropStale)
	requirePhase(t, h, v4, None)
	requirePhase(t, h, v6, Stale)
}

// The session ends without a graceful restart before the last restart is
// over. The caller passes no Graceful Restart Capability. All families are
// done. The caller has removed their routes.
func TestHelper_SessionDownNotGraceful(t *testing.T) {
	h, id := llgrStarted(t)
	h.SessionEstablished(grNegotiated())

	a := h.SessionDown(Negotiated{Families: both})
	assert.Equal(t, Actions{StopLLGRTimers: []bgp.Family{v4}}, a)
	assert.False(t, h.Restarting())
	assert.Empty(t, h.families)
	assert.Equal(t, Actions{}, h.LLGRTimerExpired(v4, id))
}

func TestHelper_Abort(t *testing.T) {
	// During the Restart Time.
	h, id := restarted(t)
	assert.Equal(t, Actions{StopRestartTimer: true}, h.Abort())
	assert.False(t, h.Restarting())
	assert.Equal(t, Actions{}, h.TimerExpired(id))

	// During the long-lived stale period.
	h, id = llgrStarted(t)
	assert.Equal(t, Actions{StopLLGRTimers: []bgp.Family{v4}}, h.Abort())
	assert.False(t, h.Restarting())
	assert.Empty(t, h.families)
	assert.Equal(t, Actions{}, h.LLGRTimerExpired(v4, id))
}
