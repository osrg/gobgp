package server

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func listASPathTestPaths(s *BgpServer, typ api.TableType, prefix string) ([]*apiutil.Path, error) {
	var result []*apiutil.Path
	name := ""
	if typ != api.TableType_TABLE_TYPE_GLOBAL {
		name = "127.0.0.1"
	}
	err := s.ListPath(apiutil.ListPathRequest{
		TableType: typ, Family: bgp.RF_IPv4_UC, Name: name, EnableFiltered: true,
		Prefixes: []*apiutil.LookupPrefix{{Prefix: prefix, LookupOption: apiutil.LOOKUP_EXACT}},
	}, func(_ bgp.NLRI, paths []*apiutil.Path) { result = append(result, paths...) })
	return result, err
}

func TestASPathOptionsKeepEstablishedSession(t *testing.T) {
	for _, groupUpdate := range []bool{false, true} {
		name := "peer"
		if groupUpdate {
			name = "peer-group"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			require.NoError(t, err)
			port := listener.Addr().(*net.TCPAddr).Port
			require.NoError(t, listener.Close())
			receiver, sender := NewBgpServer(), NewBgpServer()
			for i, s := range []*BgpServer{receiver, sender} {
				go s.Serve()
				listenPort := int32(-1)
				routerID := "192.0.2.1"
				if i == 0 {
					listenPort = int32(port)
					routerID = "192.0.2.254"
				}
				require.NoError(t, s.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
					Asn: uint32(65000 + i), RouterId: routerID, ListenPort: listenPort, ListenAddresses: []string{"127.0.0.1"},
				}}))
				t.Cleanup(s.Stop)
			}
			neighbor := &api.Peer{
				Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 65001},
				Transport: &api.Transport{PassiveMode: true, LocalAddress: "127.0.0.1"},
			}
			group := &api.PeerGroup{
				Conf:      &api.PeerGroupConf{PeerGroupName: "as-options-live", PeerAsn: 65001},
				Transport: &api.Transport{PassiveMode: true, LocalAddress: "127.0.0.1"},
			}
			if groupUpdate {
				require.NoError(t, receiver.AddPeerGroup(ctx, &api.AddPeerGroupRequest{PeerGroup: group}))
				neighbor.Conf.PeerGroup = group.Conf.PeerGroupName
			}
			require.NoError(t, receiver.AddPeer(ctx, &api.AddPeerRequest{Peer: neighbor}))
			require.NoError(t, sender.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
				Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 65000, AllowAspathLoopLocal: true, AllowOwnAsn: 10},
				Transport: &api.Transport{RemotePort: uint32(port), LocalAddress: "127.0.0.1"},
				Timers:    &api.Timers{Config: &api.TimersConfig{ConnectRetry: 1}},
			}}))
			for _, s := range []*BgpServer{receiver, sender} {
				waitPeerState(t, s, api.PeerState_SESSION_STATE_ESTABLISHED, 10*time.Second)
			}

			getPeer := func(s *BgpServer) *api.Peer {
				t.Helper()
				var p *api.Peer
				require.NoError(t, s.ListPeer(ctx, &api.ListPeerRequest{Address: "127.0.0.1"}, func(got *api.Peer) { p = got }))
				require.NotNil(t, p)
				return p
			}
			var leftEstablished atomic.Bool
			watchCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			before := []*api.Peer{getPeer(receiver), getPeer(sender)}
			for _, s := range []*BgpServer{receiver, sender} {
				require.NoError(t, s.WatchEvent(watchCtx, WatchEventMessageCallbacks{
					OnPeerUpdate: func(event *apiutil.WatchEventMessage_PeerEvent, _ time.Time) {
						if event.Type == apiutil.PEER_EVENT_STATE && event.Peer.State.SessionState != bgp.BGP_FSM_ESTABLISHED {
							leftEstablished.Store(true)
						}
					},
				}, WatchPeer()))
			}
			checkSession := func() {
				t.Helper()
				for i, s := range []*BgpServer{receiver, sender} {
					got, old := getPeer(s), before[i]
					assert.Equal(t, api.PeerState_SESSION_STATE_ESTABLISHED, got.State.SessionState)
					assert.Equal(t, old.Timers.State.Uptime.AsTime(), got.Timers.State.Uptime.AsTime())
					assert.Equal(t, old.State.Flops, got.State.Flops)
					assert.Equal(t, old.State.Messages.Received.Open, got.State.Messages.Received.Open)
					assert.Equal(t, old.State.Messages.Sent.Open, got.State.Messages.Sent.Open)
					assert.Equal(t, old.State.Messages.Received.Notification, got.State.Messages.Received.Notification)
					assert.Equal(t, old.State.Messages.Sent.Notification, got.State.Messages.Sent.Notification)
					assert.Equal(t, old.Transport.LocalPort, got.Transport.LocalPort)
					assert.Equal(t, old.Transport.RemotePort, got.Transport.RemotePort)
				}
				assert.False(t, leftEstablished.Load(), "a state event left Established")
			}
			update := func(allow uint32, replace, loopLocal bool) {
				t.Helper()
				oldAllow := getPeer(receiver).Conf.AllowOwnAsn
				var needsIn bool
				if groupUpdate {
					group.Conf.AllowOwnAsn, group.Conf.ReplacePeerAsn, group.Conf.AllowAspathLoopLocal = allow, replace, loopLocal
					rsp, err := receiver.UpdatePeerGroup(ctx, &api.UpdatePeerGroupRequest{PeerGroup: group})
					require.NoError(t, err)
					needsIn = rsp.NeedsSoftResetIn
				} else {
					neighbor.Conf.AllowOwnAsn, neighbor.Conf.ReplacePeerAsn, neighbor.Conf.AllowAspathLoopLocal = allow, replace, loopLocal
					rsp, err := receiver.UpdatePeer(ctx, &api.UpdatePeerRequest{Peer: neighbor})
					require.NoError(t, err)
					needsIn = rsp.NeedsSoftResetIn
				}
				assert.Equal(t, oldAllow != allow, needsIn)
				got := getPeer(receiver)
				assert.Equal(t, allow, got.Conf.AllowOwnAsn)
				assert.Equal(t, replace, got.Conf.ReplacePeerAsn)
				assert.Equal(t, loopLocal, got.Conf.AllowAspathLoopLocal)
				if needsIn {
					require.NoError(t, receiver.ResetPeer(ctx, &api.ResetPeerRequest{
						Address: "127.0.0.1", Soft: true, Direction: api.ResetPeerRequest_DIRECTION_IN,
					}))
				}
				checkSession()
			}
			addPath := func(s *BgpServer, prefix string, asns ...uint32) {
				t.Helper()
				nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
				require.NoError(t, err)
				nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("127.0.0.1"))
				require.NoError(t, err)
				results, err := s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{{
					Family: bgp.RF_IPv4_UC, Nlri: nlri,
					Attrs: []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh, bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, asns)})},
				}}})
				require.NoError(t, err)
				require.Len(t, results, 1)
				for _, result := range results {
					require.NoError(t, result.Error)
				}
			}
			waitPaths := func(s *BgpServer, typ api.TableType, prefix string, count int) {
				t.Helper()
				require.EventuallyWithT(t, func(c *assert.CollectT) {
					paths, err := listASPathTestPaths(s, typ, prefix)
					assert.NoError(c, err)
					assert.Len(c, paths, count)
				}, 5*time.Second, 10*time.Millisecond)
			}

			const inbound = "10.0.0.0/24"
			addPath(sender, inbound, 65000)
			waitPaths(receiver, api.TableType_TABLE_TYPE_ADJ_IN, inbound, 1)
			waitPaths(receiver, api.TableType_TABLE_TYPE_GLOBAL, inbound, 0)
			for _, allow := range []uint32{1, 0, 1} {
				update(allow, false, false)
				waitPaths(receiver, api.TableType_TABLE_TYPE_GLOBAL, inbound, int(allow))
				p := getPeer(receiver)
				require.Len(t, p.AfiSafis, 1)
				assert.Equal(t, uint64(1), p.AfiSafis[0].State.Received)
				assert.Equal(t, uint64(allow), p.AfiSafis[0].State.Accepted)
			}
			const outbound = "10.0.1.0/24"
			addPath(receiver, outbound, 65001)
			waitPaths(sender, api.TableType_TABLE_TYPE_GLOBAL, outbound, 0)
			for _, replace := range []bool{true, false} {
				update(1, replace, false)
				count := 0
				if replace {
					count = 1
				}
				waitPaths(sender, api.TableType_TABLE_TYPE_GLOBAL, outbound, count)
				if replace {
					paths, err := listASPathTestPaths(sender, api.TableType_TABLE_TYPE_GLOBAL, outbound)
					require.NoError(t, err)
					require.Len(t, paths, 1)
					found := false
					for _, attr := range paths[0].Attrs {
						if aspath, ok := attr.(*bgp.PathAttributeAsPath); ok {
							found = true
							require.Len(t, aspath.Value, 1)
							assert.Equal(t, []uint32{65000, 65000}, aspath.Value[0].GetAS())
						}
					}
					assert.True(t, found, "the received route must contain AS_PATH")
				}
			}
			for _, allowLocal := range []bool{true, false} {
				update(1, false, allowLocal)
				count := 0
				if allowLocal {
					count = 1
				}
				waitPaths(sender, api.TableType_TABLE_TYPE_GLOBAL, outbound, count)
			}
			// Check the event stream after the final route change has crossed the session.
			assert.Never(t, leftEstablished.Load, 100*time.Millisecond, 10*time.Millisecond)
			checkSession()
		})
	}
}
