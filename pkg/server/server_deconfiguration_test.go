package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/packet/bmp"
)

// Deleting a peer bypasses the usual FSM state-change callback. Its final
// event must still say why the peer went down and which state it left.
func TestDeletePeerDeconfigurationReason(t *testing.T) {
	for _, tc := range []struct {
		name         string
		established  bool
		notification bool
	}{
		{"established", true, true},
		{"active", false, true},
		{"without notification", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const asn, address = 65001, "10.0.0.1"
			s, p := startServerWithPassivePeer(t, asn, address)
			var conn *MockConnection
			oldState := bgp.BGP_FSM_ACTIVE
			if tc.established {
				conn = establishSession(t, s, p, asn, address)
				oldState = bgp.BGP_FSM_ESTABLISHED
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			events := make(chan apiutil.PeerState, 8)
			require.NoError(t, s.WatchEvent(ctx, WatchEventMessageCallbacks{
				OnPeerUpdate: func(e *apiutil.WatchEventMessage_PeerEvent, _ time.Time) {
					if e.Type == apiutil.PEER_EVENT_STATE {
						events <- e.Peer.State
					}
				},
			}, WatchPeer()))
			w, err := s.watch(WatchPeer())
			require.NoError(t, err)
			defer w.Stop()

			if tc.notification {
				require.NoError(t, s.DeletePeer(ctx, &api.DeletePeerRequest{Address: address}))
			} else {
				// StopBgp with graceful restart allowed uses this path to
				// delete the configuration without sending a NOTIFICATION.
				require.NoError(t, s.mgmtOperation(func() error {
					conf := p.fsm.pConf.ReadCopy()
					return s.deleteNeighbor(&conf, bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_PEER_DECONFIGURED, false)
				}, true))
			}

			select {
			case state := <-events:
				assert.Equal(t, bgp.BGP_FSM_IDLE, state.SessionState)
				assert.Equal(t, api.PeerState_DISCONNECT_REASON_DECONFIGURED, state.DisconnectReason)
				assert.Equal(t, "deconfigured", state.DisconnectMessage)
			case <-ctx.Done():
				t.Fatal("no peer deletion event")
			}

			var event *watchEventPeer
			for event == nil {
				select {
				case ev := <-w.Event():
					e := ev.(*watchEventPeer)
					if e.Type == apiutil.PEER_EVENT_STATE {
						event = e
					}
				case <-ctx.Done():
					t.Fatal("no internal peer deletion event")
				}
			}
			assert.Equal(t, oldState, event.OldState)
			require.NotNil(t, event.StateReason)
			assert.Equal(t, fsmDeConfigured, event.StateReason.Type)
			assert.False(t, event.Graceful, "configuration deletion is not a graceful session loss")
			// An established peer's old state is what makes BMP emit Peer Down.
			if tc.established {
				m := bmpPeerDown(event, bmp.BMP_PEER_TYPE_GLOBAL, false, 0)
				body := m.Body.(*bmp.BMPPeerDownNotification)
				assert.Equal(t, uint8(bmp.BMP_PEER_DOWN_REASON_PEER_DE_CONFIGURED), body.Reason)
			}
			if !tc.notification {
				assert.Nil(t, event.StateReason.BGPNotification)
				assert.Never(t, func() bool { return sentNotification(conn) != nil }, 100*time.Millisecond, 10*time.Millisecond)
			}
			assert.Never(t, func() bool { return len(events) != 0 }, 100*time.Millisecond, 10*time.Millisecond,
				"deletion must emit only one state event")
		})
	}
}
