# Managing GoBGP with Your Favorite Language

This page explains how to manage GoBGP with your favorite language. You can use any language supported by [gRPC](http://www.grpc.io/). This page gives an example in Python and C++.

## Contents

- [Prerequisite](#prerequisite)
- [Python](#python)
- [C++](#c)
- [Watching the Best Paths](#watching-the-best-paths)

## Prerequisite

We assume that you have the relevant tools installed to generate the server and client interface for your favorite language from proto files. Please refer to [the official docs of gRPC](http://www.grpc.io/docs/) for details.

## Python

### Generating Interface

You need to generate the server and client interface from the GoBGP proto files before running the examples. From the repository root:

```bash
$ python3 -m grpc_tools.protoc \
   -I proto \
   -I proto/api \
   --python_out=tools/grpc/python/api \
   --grpc_python_out=tools/grpc/python/api \
   proto/api/*.proto
$ ls tools/grpc/python/api/*_pb2.py
attribute_pb2.py  capability_pb2.py  common_pb2.py  extcom_pb2.py  gobgp_pb2.py  nlri_pb2.py
```

### Adding Path

[`tools/grpc/python/add_path.py`](https://github.com/osrg/gobgp/blob/master/tools/grpc/python/add_path.py)
shows an example for adding a route using the current GoBGP gRPC API (typed `NLRI` and `Attribute` messages on `GoBgpServiceStub`).
After generating the bindings, run the script from the `tools/grpc/python` directory and point `PYTHONPATH` to the generated modules.

```bash
$ cd tools/grpc/python
$ PYTHONPATH=$PYTHONPATH:./api python3 add_path.py
```

See if the route was added to the global rib.

```bash
$ gobgp g r
   Network              Next Hop             AS_PATH              Age        Attrs
*> 10.0.0.0/24          1.1.1.1              100 200              00:08:02   [{Origin: ?}]
```

### Adding BGP-SR policy

[`tools/grpc/python/sr_policy.py`](https://github.com/osrg/gobgp/blob/master/tools/grpc/python/sr_policy.py)
shows an example for advertising an SR Policy route via the same gRPC API. Customize the parameters at the bottom of the script if needed, then run it from `tools/grpc/python` after generating the bindings:

```bash
$ cd tools/grpc/python
$ PYTHONPATH=$PYTHONPATH:./api python3 sr_policy.py
```

## Result of injecting the SR policy

Once the sr policy is injected, gobgp will advertise it to the peers with SR Policy enabled address family. Below is the output collected from Nokia SROS router with enabled SR policy address family.

```log
A:R1# show router segment-routing sr-policies all color 100

===============================================================================
SR-Policies Path
===============================================================================
-------------------------------------------------------------------------------
Active          : Yes                   Owner           : bgp
Color           : 100
Head            : 0.0.0.0               Endpoint Addr   : 10.6.6.6
RD              : 2                     Preference      : 11
BSID            : 300004
TunnelId        : 917525                Age             : 7
Origin ASN      : 800                   Origin          : 10.100.1.201
NumReEval       : 0                     ReEvalReason    : none
NumActPathChange: 0                     Last Change     : 03/23/2022 11:05:48
Maintenance Policy: N/A

Path Segment Lists:
Segment-List    : 1                     Weight          : 12
S-BFD State     : Down                  S-BFD Transitio*: 0
Num Segments    : 2                     Last Change     : 03/22/2022 14:09:33
  Seg 1 Label   : 200002                State           : resolved-up
  Seg 2 Label   : 200006                State           : N/A

===============================================================================
* indicates that the corresponding row element may have been truncated.
```

### FlowSpec Mitigation via Webhook

[`tools/grpc/python/flowspec_mitigation.py`](https://github.com/osrg/gobgp/blob/master/tools/grpc/python/flowspec_mitigation.py)
shows how to use the gRPC API for automated DDoS mitigation via FlowSpec.
A lightweight HTTP server receives attack alerts and dynamically adds or
removes FlowSpec rules through GoBGP.

```bash
$ cd tools/grpc/python
$ PYTHONPATH=$PYTHONPATH:./api python3 flowspec_mitigation.py
FlowSpec mitigation webhook listening on 0.0.0.0:8080
```

Add a FlowSpec rule to discard all UDP traffic to a target prefix:

```bash
$ curl -s -X POST http://localhost:8080/mitigate \
    -H 'Content-Type: application/json' \
    -d '{"destination": "203.0.113.1/32", "protocol": 17, "action": "discard"}'
{"status": "ok", "uuid": "..."}
```

Verify the rule was installed:

```bash
$ gobgp global rib -a ipv4-flowspec
   Network                                       Next Hop             AS_PATH              Age        Attrs
*> [destination: 203.0.113.1/32][protocol: ==udp] fictitious                                00:00:01   [{Origin: i} {Extcomms: [discard]}]
```

Remove the rule when the attack clears:

```bash
$ curl -s -X POST http://localhost:8080/clear \
    -H 'Content-Type: application/json' \
    -d '{"uuid": "uuid-from-mitigate-response"}'
{"status": "ok"}
```

Supported match fields: `destination`, `source` (CIDR prefix), `protocol`
(IANA number), `destination_port`, `source_port`.
Supported actions: `discard`, `rate-limit` (with `rate` in bytes/sec),
`redirect` (with `redirect_asn` and `redirect_local_admin`), `accept`.
Both IPv4 and IPv6 FlowSpec families are detected automatically from the
prefix format.

## C++

### Generating Interface and Binary

Use [`tools/grpc/cpp/Makefile`](https://github.com/osrg/gobgp/blob/master/tools/grpc/cpp/Makefile).

```bash
$ cd tools/grpc/cpp
$ make
 ```

The above to generate the server and client interface and the binary to add a route by using `AddPath` API, ['tools/grpc/cpp/add_path.cc'](https://github.com/osrg/gobgp/blob/master/tools/grpc/cpp/add_path.cc).

### Adding Path

Let's run the binary.

```bash
$ ./add_path
```

See if the route was added to the global rib.

```bash
$ gobgp g r
   Network              Next Hop             AS_PATH              Age        Attrs
*> 10.0.0.0/24          1.1.1.1                                   00:13:26   [{Origin: i} {Communities: 0:100}]
```

## Watching the Best Paths

`WatchEvent` streams the changes of the best paths, preceded by the best paths
the server holds when the stream starts (`init`), and can filter them with a
policy defined with `AddPolicy`. The native Go interface offers the same
subscription, and the same semantics: see [GoBGP as a Go Native BGP
library](lib.md#watching-the-best-paths).

The request:

- `table.filters`: a filter of type `TYPE_BEST`, with `init` set for the initial
  table and `policy` set to the name of the policy. A policy is valid only with
  `TYPE_BEST`, in a single `TYPE_BEST` filter, and not with `use_multiple_paths`.
  It is evaluated when the best path of a destination changes; a change to
  what it reads applies to the destinations whose best path changes after
  it.
- `batch_size`: a message is sent when it holds more than `batch_size` paths, so
  every message of an event but the last carries `batch_size + 1` paths, and the
  last one the rest, possibly none: an event with an exact multiple of
  `batch_size + 1` paths ends with an empty message. The last message of an
  event is the first one that carries no more than `batch_size` paths. With `0`
  every event is one message, held whole in memory by the server.
- `max_queued_events`: the events the server queues for a client that is slow to
  read. The limit is strict and counts events, not memory; `0` is no limit.

Every table message carries the `timestamp` of its event, the same for all its
messages: the time of the best path change or of the initial table. It is
neither a sequence number nor a snapshot barrier: see the table in the [Go
documentation](lib.md#timestamps).

The stream ends with a status. Events were lost in the cases below, and the
client watches again, with `init`, to resynchronize:

| Code | Meaning |
|------|---------|
| `RESOURCE_EXHAUSTED` | `max_queued_events` was reached |
| `ABORTED` | The subscription was invalidated: the policy was removed or replaced by a reload, or a destination could not be identified |

A request the server refuses fails with `INVALID_ARGUMENT` (no events, a policy
with a filter other than `TYPE_BEST`, two `TYPE_BEST` filters with a policy, a
`max_queued_events` that does not fit an int on the server), `NOT_FOUND` (the
policy does not exist) or `FAILED_PRECONDITION` (the policy with
`use_multiple_paths`). Messages already sent or buffered when the server ends
the stream may still reach the client after it: the client resynchronizes on the
status, not on the last message it received.

### Go

```go
package main

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
)

const batchSize = 500

// watch rebuilds the table of the best paths the policy accepts and returns
// the status that ended the stream. A table starts when the stream starts
// and replaces the previous one when its initial table is complete.
func watch(ctx context.Context, client api.GoBgpServiceClient, policy string, table map[string]*api.Path) (map[string]*api.Path, error) {
	stream, err := client.WatchEvent(ctx, &api.WatchEventRequest{
		Table: &api.WatchEventRequest_Table{Filters: []*api.WatchEventRequest_Table_Filter{{
			Type:   api.WatchEventRequest_Table_Filter_TYPE_BEST,
			Init:   true,
			Policy: policy,
		}}},
		BatchSize:       batchSize,
		MaxQueuedEvents: 10000,
	})
	if err != nil {
		return table, err
	}
	fresh := map[string]*api.Path{}
	initial := true
	for {
		m, err := stream.Recv()
		if err != nil {
			return table, err
		}
		ev := m.GetTable()
		if ev == nil {
			continue
		}
		t := table
		if initial {
			t = fresh
		}
		for _, p := range ev.GetPaths() {
			nlri, err := apiutil.UnmarshalNLRI(apiutil.ToFamily(p.GetFamily()), p.GetNlri())
			if err != nil {
				return table, err
			}
			if p.GetIsWithdraw() {
				delete(t, nlri.String())
			} else {
				t[nlri.String()] = p
			}
		}
		// The last message of an event carries no more than batchSize paths.
		if initial && len(ev.GetPaths()) <= batchSize {
			table, initial = fresh, false
			log.Printf("initial table of %d paths, event time %s", len(table), ev.GetTimestamp().AsTime())
		}
	}
}

func main() {
	conn, err := grpc.NewClient("127.0.0.1:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	client := api.NewGoBgpServiceClient(conn)

	ctx := context.Background()
	var table map[string]*api.Path
	for {
		table, err = watch(ctx, client, "tagged", table)
		switch status.Code(err) {
		case codes.ResourceExhausted, codes.Aborted:
			// Events were lost: watch again.
			log.Printf("watching again: %v", err)
			time.Sleep(time.Second)
		default:
			// A request that is refused (InvalidArgument, NotFound,
			// FailedPrecondition), or a failure of the connection.
			log.Fatal(err)
		}
	}
}
```

### Python

After [generating the interface](#generating-interface), the same request in
Python:

```python
import grpc
import gobgp_pb2
import gobgp_pb2_grpc

BATCH_SIZE = 500


def watch(stub, policy):
    request = gobgp_pb2.WatchEventRequest(
        table=gobgp_pb2.WatchEventRequest.Table(
            filters=[
                gobgp_pb2.WatchEventRequest.Table.Filter(
                    type=gobgp_pb2.WatchEventRequest.Table.Filter.TYPE_BEST,
                    init=True,
                    policy=policy,
                )
            ]
        ),
        batch_size=BATCH_SIZE,
        max_queued_events=10000,
    )
    try:
        for message in stub.WatchEvent(request):
            paths = message.table.paths
            # The last message of an event carries no more than BATCH_SIZE paths.
            print(len(paths), message.table.timestamp.ToDatetime())
    except grpc.RpcError as e:
        if e.code() in (grpc.StatusCode.RESOURCE_EXHAUSTED, grpc.StatusCode.ABORTED):
            # Events were lost: watch again.
            return
        raise


with grpc.insecure_channel("127.0.0.1:50051") as channel:
    watch(gobgp_pb2_grpc.GoBgpServiceStub(channel), "tagged")
```
