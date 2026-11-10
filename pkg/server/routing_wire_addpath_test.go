package server

import (
	"fmt"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/require"
)

func TestRoutingWireAddPathRefresh(t *testing.T) {
	for _, limit := range []uint32{1, 2} {
		t.Run(fmt.Sprintf("send-max-%d", limit), func(t *testing.T) {
			s, port := wireServer(t)
			source := wirePeer(t, s, port, "127.0.0.2", 65001, 0)
			observer := wirePeer(t, s, port, "127.0.0.3", 65002, limit)
			fallback := wirePeer(t, s, port, "127.0.0.4", 65003, 0)
			state := map[uint32]bool{}
			wireUpdate(t, source, false, 65001)
			wireRIBCount(t, s, 1)
			wireCollect(t, observer, state, true, 300*time.Millisecond)
			require.Len(t, state, 1)
			var primary uint32
			for id := range state {
				primary = id
			}
			require.NotZero(t, primary)
			wireUpdate(t, fallback, false, 65003, 65004)
			wireRIBCount(t, s, 2)
			wireCollect(t, observer, state, true, 300*time.Millisecond)
			require.Len(t, state, int(limit))
			before := map[uint32]bool{}
			for id := range state {
				before[id] = true
			}
			wireSend(t, observer, bgp.NewBGPRouteRefreshMessage(1, 0, 1))
			a, _ := wireCollect(t, observer, state, true, 500*time.Millisecond)
			require.Positive(t, a, "refresh must produce wire UPDATE")
			require.Equal(t, before, state, "refresh must preserve exact advertised Path-IDs")
			wireUpdate(t, fallback, true)
			wireRIBCount(t, s, 1)
			wireCollect(t, observer, state, true, 300*time.Millisecond)
			require.Equal(t, map[uint32]bool{primary: true}, state)
			wireUpdate(t, source, true)
			wireRIBCount(t, s, 0)
			_, w := wireCollect(t, observer, state, true, 300*time.Millisecond)
			require.Positive(t, w)
			require.Empty(t, state)
		})
	}
}
