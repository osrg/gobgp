# GoBGP as a Go Native BGP library

This page explains how to use GoBGP as a Go Native BGP library.

## Contents

- [Basic Example](#basic-example)
- [Watching the Best Paths](#watching-the-best-paths)
  - [Filtering With a Policy](#filtering-with-a-policy)
  - [Rebuilding the Table](#rebuilding-the-table)
  - [Defaults and Limits](#defaults-and-limits)
  - [Timestamps](#timestamps)
  - [Changes to the Policy](#changes-to-the-policy)
  - [How a Watch Ends](#how-a-watch-ends)
  - [Callbacks in Flight](#callbacks-in-flight)

## Basic Example

```go
package main

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/server"
)

func main() {
	log := slog.Default()
	lvl := &slog.LevelVar{}
	lvl.Set(slog.LevelInfo)

	s := server.NewBgpServer(server.LoggerOption(log, lvl))
	go s.Serve()

	// global configuration
	if err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65003,
			RouterId:   "10.0.255.254",
			ListenPort: -1, // gobgp won't listen on tcp:179
		},
	}); err != nil {
		log.Error("failed to start BGP", slog.String("Error", err.Error()))
	}

	// set default import policy
	s.SetPolicyAssignment(context.Background(), &api.SetPolicyAssignmentRequest{
		Assignment: &api.PolicyAssignment{
			Direction:     api.PolicyDirection_POLICY_DIRECTION_IMPORT,
			DefaultAction: api.RouteAction_ROUTE_ACTION_REJECT,
		},
	})

	// monitor the change of the peer state
	if err := s.WatchEvent(context.Background(), server.WatchEventMessageCallbacks{
		OnPeerUpdate: func(peer *apiutil.WatchEventMessage_PeerEvent, _ time.Time) {
			if peer.Type == apiutil.PEER_EVENT_STATE {
				log.Info("peer state changed", slog.Any("Peer", peer.Peer))
			}
		}}); err != nil {
		log.Error("failed to watch event", slog.String("Error", err.Error()))
	}

	// neighbor configuration
	n := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "172.17.0.2",
			PeerAsn:         65002,
		},
	}

	if err := s.AddPeer(context.Background(), &api.AddPeerRequest{
		Peer: n,
	}); err != nil {
		log.Error("failed to add peer", slog.String("Error", err.Error()))
	}

	// add routes
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
	a1 := bgp.NewPathAttributeOrigin(0)
	a2, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	a3 := bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{6762, 39919, 65000, 35753, 65000})})
	attrs := []bgp.PathAttributeInterface{a1, a2, a3}

	_, err := s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{{
		Nlri:  nlri,
		Attrs: attrs,
	}}})
	if err != nil {
		log.Error("failed to add path", slog.String("Error", err.Error()))
	}

	// add v6 route
	v6Nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:db8:1::/64"))
	aMpr, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv4_UC, []bgp.PathNLRI{{NLRI: v6Nlri}}, netip.MustParseAddr("2001:db8::1"))
	aC := bgp.NewPathAttributeCommunities([]uint32{100, 200})
	attrs = []bgp.PathAttributeInterface{aMpr, aC}

	_, err = s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{{
		Nlri:  v6Nlri,
		Attrs: attrs,
	}}})
	if err != nil {
		log.Error("failed to add v6 path", slog.String("Error", err.Error()))
	}

	s.ListPath(apiutil.ListPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
	}, func(prefix bgp.NLRI, paths []*apiutil.Path) {
		log.Info(prefix.String())
		for _, p := range paths {
			log.Info("path",
				slog.Uint64("peer_asn", uint64(p.PeerASN)),
				slog.String("peer_address", p.PeerAddress.String()),
				slog.Uint64("age", uint64(p.Age)),
				slog.Bool("best", p.Best),
			)
		}
	})

	// do something useful here instead of exiting
	time.Sleep(time.Minute * 3)
}
```

## Watching the Best Paths

`WatchEvent` calls back for the events it subscribes to. `WatchBestPath(true)`
subscribes to the changes of the best paths, preceded by the best paths the
server holds when the watch starts (the initial table). The same subscription
is available to a client of the gRPC API: see [Managing GoBGP with Your
Favorite Language](grpc-client.md#watching-the-best-paths).

### Filtering With a Policy

`WatchBestPathPolicy` names a policy definition, created with `AddPolicy`, that
filters the best paths: a path is delivered when the policy accepts it. The
paths are delivered unchanged, whatever the policy does to them while it is
evaluated. A path that was delivered and is then withdrawn, or replaced by a
path the policy does not accept, is delivered again as a withdrawal.

The example watches the paths tagged with the community 65000:100. It prints
the initial table and every change.

```go
package main

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/server"
)

func main() {
	log := slog.Default()
	lvl := &slog.LevelVar{}
	lvl.Set(slog.LevelInfo)

	s := server.NewBgpServer(server.LoggerOption(log, lvl))
	go s.Serve()
	ctx := context.Background()
	if err := s.StartBgp(ctx, &api.StartBgpRequest{
		Global: &api.Global{Asn: 65003, RouterId: "10.0.255.254", ListenPort: -1},
	}); err != nil {
		log.Error("failed to start BGP", slog.String("Error", err.Error()))
		return
	}

	// The policy: accept the paths that carry the community 65000:100.
	if err := s.AddDefinedSet(ctx, &api.AddDefinedSetRequest{DefinedSet: &api.DefinedSet{
		DefinedType: api.DefinedType_DEFINED_TYPE_COMMUNITY,
		Name:        "tagged-communities",
		List:        []string{"65000:100"},
	}}); err != nil {
		log.Error("failed to add the defined set", slog.String("Error", err.Error()))
		return
	}
	if err := s.AddPolicy(ctx, &api.AddPolicyRequest{Policy: &api.Policy{
		Name: "tagged",
		Statements: []*api.Statement{{
			Name: "tagged-accept",
			Conditions: &api.Conditions{
				CommunitySet: &api.MatchSet{Type: api.MatchSet_TYPE_ANY, Name: "tagged-communities"},
			},
			Actions: &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_ACCEPT},
		}},
	}}); err != nil {
		log.Error("failed to add the policy", slog.String("Error", err.Error()))
		return
	}

	// Watch the best paths the policy accepts, the initial table included.
	if err := s.WatchEvent(ctx, server.WatchEventMessageCallbacks{
		OnBestPath: func(paths []*apiutil.Path, ts time.Time) {
			for _, p := range paths {
				log.Info("best path", slog.String("Nlri", p.Nlri.String()), slog.Bool("Withdrawal", p.Withdrawal), slog.Time("Time", ts))
			}
		},
		OnError: func(err error) {
			log.Error("the watch ended", slog.String("Error", err.Error()))
		},
	}, server.WatchBestPath(true), server.WatchBestPathPolicy("tagged")); err != nil {
		log.Error("failed to watch", slog.String("Error", err.Error()))
		return
	}

	// A tagged path is delivered, an untagged one is not.
	nh, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	for prefix, tagged := range map[string]bool{"10.0.0.0/24": true, "10.0.1.0/24": false} {
		nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
		attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh}
		if tagged {
			attrs = append(attrs, bgp.NewPathAttributeCommunities([]uint32{65000<<16 | 100}))
		}
		if _, err := s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{{Family: bgp.RF_IPv4_UC, Nlri: nlri, Attrs: attrs}}}); err != nil {
			log.Error("failed to add path", slog.String("Error", err.Error()))
		}
	}

	time.Sleep(time.Minute)
}
```

### Rebuilding the Table

A consumer that keeps a copy of the table sets a destination on an
announcement, removes it on a withdrawal, and starts again when the watch ends
with an error. `OnBestPathBatch` is called with the paths of one event in
batches, in the order of the event; `last` is set on the final call of the
event, which carries at least one path unless the event has none. The initial
table is the first event, so the first call with `last` set completes it, even
when the table is empty (one call with no path).

The `mirror` of the example keeps a table equal to the best paths the policy
accepts. The table of a new subscription replaces the previous one when its
initial table is complete, and a callback of an earlier subscription that is
still in flight, see [Callbacks in Flight](#callbacks-in-flight), is ignored.

```go
package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/server"
)

// mirror is the table a consumer rebuilds from the events of a watch.
type mirror struct {
	mu    sync.Mutex
	paths map[string]*apiutil.Path
}

// follow keeps the mirror equal to the best paths the policy accepts, and
// subscribes again whenever the server ends the watch.
func (m *mirror) follow(ctx context.Context, s *server.BgpServer, policy string, log *slog.Logger) {
	for ctx.Err() == nil {
		// The table of this subscription, which replaces the previous one
		// when its initial table is complete; stale is set once the
		// subscription is over.
		fresh := map[string]*apiutil.Path{}
		initial, stale := true, false

		watchCtx, cancel := context.WithCancel(ctx)
		ended := make(chan error, 1)
		err := s.WatchEvent(watchCtx, server.WatchEventMessageCallbacks{
			// Batches of at most 500 paths (1000 when it is not set).
			BestPathBatchSize: 500,
			OnBestPathBatch: func(paths []*apiutil.Path, ts time.Time, last bool) {
				m.mu.Lock()
				defer m.mu.Unlock()
				if stale {
					return
				}
				table := m.paths
				if initial {
					table = fresh
				}
				for _, p := range paths {
					if p.Withdrawal {
						delete(table, p.Nlri.String())
					} else {
						table[p.Nlri.String()] = p
					}
				}
				if last && initial {
					m.paths = fresh
					initial = false
				}
			},
			// Called once, when the server ends the watch: events may have
			// been lost, and the consumer subscribes again.
			OnError: func(err error) { ended <- err },
		},
			server.WatchBestPath(true),
			server.WatchBestPathPolicy(policy),
			// At most 10000 events wait for a consumer that is slow.
			server.WatchQueueLimit(10000),
		)
		if err != nil {
			// The watch was refused (ErrWatchInvalid, ErrWatchPolicyNotFound
			// or ErrWatchIncompatible): waiting does not change that.
			log.Error("failed to watch", slog.String("Error", err.Error()))
			cancel()
			return
		}

		select {
		case err := <-ended:
			// ErrWatchQueueFull, ErrWatchPolicyRemoved or ErrWatchDestination.
			log.Warn("the watch ended, subscribing again", slog.String("Error", err.Error()))
		case <-ctx.Done():
		}
		cancel()
		m.mu.Lock()
		stale = true
		m.mu.Unlock()
	}
}

func main() {
	log := slog.Default()
	s := server.NewBgpServer()
	go s.Serve()
	ctx := context.Background()
	if err := s.StartBgp(ctx, &api.StartBgpRequest{
		Global: &api.Global{Asn: 65003, RouterId: "10.0.255.254", ListenPort: -1},
	}); err != nil {
		log.Error("failed to start BGP", slog.String("Error", err.Error()))
		return
	}
	// The policy "tagged" is defined as in the previous example.
	m := &mirror{}
	m.follow(ctx, s, "tagged", log)
}
```

### Defaults and Limits

- `BestPathBatchSize` is the largest number of paths one call of `OnBestPathBatch`
  receives. When it is zero or negative it is `DefaultBestPathBatchSize`, 1000.
  `OnBestPathBatch` takes precedence over `OnBestPath`, which is not called
  when both are set. Only the best path events are converted incrementally:
  the other callbacks receive their paths whole.
- `WatchQueueLimit(n)` bounds the events queued for a watch whose callbacks
  are slower than the server. The limit is strict, an event that would exceed
  it ends the watch with `ErrWatchQueueFull` instead of queueing, and it counts
  events, not memory: one event may carry one path or a whole table, and an
  initial table is one event. The events the server already handed over to the
  goroutine that runs the callbacks (at most nine) are not counted. Zero, the
  default, is no limit. A negative limit is refused with `ErrWatchInvalid`.
- Without `OnBestPathBatch`, a watch holds the whole of an initial table
  converted until it calls `OnBestPath`.

### Timestamps

Every callback receives the time of its event:

| Event | Time |
|-------|------|
| Best path | The time the server notified the change, or took the initial table |
| Pre-policy update (`WatchUpdate`) | The time the update was received; the time of the event for the initial table |
| Post-policy update (`WatchPostUpdate`) | For an announcement, the time the path was received, with a resolution of one second; for a withdrawal and for the initial table, the time of the event |
| End-of-RIB | The time the message was received; the time of the event for the initial ones |
| Peer | The time of the event |

The time is neither a sequence number nor a snapshot barrier. Two events may
carry the same time, an event may carry an earlier time than the one delivered
before it (a post-policy announcement carries when its path was received), and
the time of an initial table does not say which changes it includes. The
order of the events is the order of the callbacks. Use the time to measure the
lag of a path, not to order, deduplicate or resynchronize.

### Changes to the Policy

The policy is evaluated when the best path of a destination changes, with the
state it reads at that moment: its defined sets, its statements and the ROA
table. A change to that state applies to the destinations whose best path
changes after it. A destination whose best path does not change keeps its
earlier verdict, so a consumer that needs every destination evaluated again
with the new state watches again. A statement or a defined set can be added to
and removed from the policy while it is watched; the watch goes on.

A policy that is deleted and defined again under the same name by a reload
(`SetPolicies`) is another policy: the watch ends with `ErrWatchPolicyRemoved`.
A policy cannot be deleted with `DeletePolicy` while a watch uses it. Several
watches can use one policy, which stays protected until the last of them has
ended.

The policy is evaluated with the best paths of the Loc-RIB, with no peer to
send them to. A neighbor condition matches the peer the path was received from,
and never a path of the server itself. The actions that read the peer a path
is sent to, such as `next-hop self`, leave the path as it is, and only whether
the policy accepts it matters. The policy is not supported with multiple paths
(`use-multiple-paths`).

The changes of one destination are delivered in the order they were made,
except for the other destinations an EVPN MAC mobility update changes along
with the one it carries: their ordering is fixed by a separate change that is
not part of this one.

### How a Watch Ends

A watch ends when its context is cancelled, or when the server ends it with an
error, which is passed to `OnError` once. The errors that end a watch, with
`errors.Is`:

- `ErrWatchQueueFull`: the queue limit was reached.
- `ErrWatchPolicyRemoved`: the policy was removed or replaced by a reload.
- `ErrWatchDestination`: the server could not tell which destination a path
  belongs to, so it cannot keep track of what it delivered.

In every case events may have been lost: watch again, with the initial table.
`WatchEvent` itself fails, and starts nothing, when the options are not valid
(`ErrWatchInvalid`: no events, a negative limit, a policy without
`WatchBestPath`), the policy does not exist (`ErrWatchPolicyNotFound`) or the
configuration cannot support the watch (`ErrWatchIncompatible`).

Cancelling the context is not a failure and is not reported. When the watch
fails and its context is cancelled at about the same time, the failure may go
unreported: a client that cancels does not depend on `OnError`.

### Callbacks in Flight

The end of a watch is not the end of its callbacks. When `OnError` is called,
or the context is cancelled, the server queues nothing more for the watch and
releases the watcher, its queue, its policy and what it remembered at once,
without waiting for a callback that is blocked to return, and admits no
further callback. A callback admitted just before, and the one that is running,
may still run or finish afterwards. The resources the callbacks use must stay
valid until they have returned.
