# BFD

BFD (Bidirectional Forwarding Detection) is a protocol for fast liveness
detection between two network systems. In BGP deployments, it is commonly used
to detect neighbor failures faster than regular BGP hold timers.

Both sides periodically exchange small BFD control packets. If one side stops
receiving packets for the configured detection time, the BFD session goes down
and the routing protocol can react immediately.

GoBGP implements BFD for BGP neighbors using the basic control packet model from
[RFC 5880](https://datatracker.ietf.org/doc/html/rfc5880) and single-hop UDP
transport from [RFC 5881](https://datatracker.ietf.org/doc/html/rfc5881).

## Supported Features

GoBGP has an native BFD implementation scoped to fast BGP peer failure
detection. It is intended to cover single-hop asynchronous BFD for BGP
neighbors, not to replace a full-featured standalone BFD daemon.

Supported behavior:

- asynchronous BFD control packets over UDP;
- per-neighbor BFD configuration;
- peer-group BFD configuration inherited by neighbors;
- default destination UDP port `3784`;
- source UDP port selected from the RFC 5881 dynamic range `49152..65535`;
- outgoing BFD packets sent with TTL/Hop Limit `255`;
- BFD states `DOWN`, `INIT`, `UP`, and `ADMIN_DOWN`;
- Poll/Final handling in control packets;
- hard BGP peer reset when the BFD session expires or the remote peer signals
  `DOWN`;
- BFD configuration through the GoBGP config file and gRPC API;
- BFD state in peer state returned by the API.

Current scope and limitations:

- BFD authentication, echo mode, demand mode, and other advanced BFD features
  are out of scope for this implementation;
- remote interval negotiation is limited: GoBGP sends the configured intervals,
  but currently does not adjust local timers from the peer's advertised
  `DesiredMinTxInterval` or `RequiredMinRxInterval`.

## Configuration

BFD is disabled by default. Enable it under `[neighbors.bfd.config]`.

Intervals are configured in microseconds.

```toml
[global.config]
  as = 65001
  router-id = "192.0.2.1"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "192.0.2.2"
    peer-as = 65002

  [neighbors.bfd.config]
    enabled = true
    desired-minimum-tx-interval = 300000
    required-minimum-receive = 300000
    detection-multiplier = 3
```

With this example, GoBGP sends BFD control packets roughly every `300 ms`.
The local detection time is:

```text
required-minimum-receive * detection-multiplier
```

So `300000 * 3` gives about `900 ms`.

If BFD timer values are omitted, GoBGP uses these defaults:

| Option | Default | Unit |
| --- | ---: | --- |
| `enabled` | `false` | boolean |
| `port` | `3784` | UDP port |
| `desired-minimum-tx-interval` | `1000000` | microseconds |
| `required-minimum-receive` | `1000000` | microseconds |
| `detection-multiplier` | `3` | multiplier |

## Peer Groups

BFD can be configured once on a peer group and inherited by all neighbors in
that group.

```toml
[global.config]
  as = 65001
  router-id = "192.0.2.1"

[[peer-groups]]
  [peer-groups.config]
    peer-group-name = "edge"
    peer-as = 65002

  [peer-groups.bfd.config]
    enabled = true
    desired-minimum-tx-interval = 300000
    required-minimum-receive = 300000
    detection-multiplier = 3

[[neighbors]]
  [neighbors.config]
    neighbor-address = "192.0.2.2"
    peer-group = "edge"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "192.0.2.3"
    peer-group = "edge"
```

A neighbor can override BFD values inherited from its peer group by setting its
own fields under `[neighbors.bfd.config]`.

## Port Behavior

By default, BFD control packets are sent to UDP destination port `3784`.

```toml
[neighbors.bfd.config]
  enabled = true
  port = 3784
```

Use the default unless the remote system explicitly requires another destination
port. RFC 5881 specifies `3784` for single-hop BFD. In GoBGP, the local BFD
server still listens on UDP `3784`; changing `port` only changes the remote
destination port used by outgoing packets.

For firewalls and ACLs, allow:

- inbound UDP `3784` to the GoBGP host;
- outbound UDP from an ephemeral source port in `49152..65535` to the peer's
  BFD destination port, normally `3784`;
- the reverse direction on the peer.

The remote BGP speaker must also run BFD and must be configured with compatible
timers. Enabling BFD only on one side is not enough to bring the BFD session up.

## Runtime Behavior

When BFD is enabled for a neighbor, GoBGP creates a BFD peer for the neighbor
address. If the BFD session expires, or if the remote side signals `DOWN`,
GoBGP performs a hard reset of the corresponding BGP peer with the communication
string `BFD is down`.

Changing BFD configuration through `UpdatePeer` is applied at runtime:

- enabling BFD adds the BFD peer;
- disabling BFD removes the BFD peer;
- changing BFD timer or port settings recreates the BFD peer with the new
  configuration.

## Checking State

The normal text output of `gobgp neighbor` does not print a dedicated BFD
section. Use JSON output to inspect the BFD fields returned by `ListPeer`.

```bash
$ gobgp -j neighbor 192.0.2.2
```

Relevant fields:

- `bfd`: configured BFD values for the peer;
- `state.bfd_state.session_state`: current local BFD session state;
- `state.bfd_state.bfd_async.transmitted_packets`: sent BFD control packets;
- `state.bfd_state.bfd_async.received_packets`: received BFD control packets.

Abbreviated JSON example:

```json
{
  "conf": {
    "neighbor_address": "192.0.2.2",
    "peer_asn": 65002
  },
  "bfd": {
    "enabled": true,
    "port": 3784,
    "desired_minimum_tx_interval": 300000,
    "required_minimum_receive": 300000,
    "detection_multiplier": 3
  },
  "state": {
    "bfd_state": {
      "session_state": "BFD_SESSION_STATE_UP",
      "bfd_async": {
        "transmitted_packets": 100,
        "received_packets": 99
      }
    }
  }
}
```

## gRPC API

The gRPC `Peer` and `PeerGroup` messages include `BfdPeerConfig bfd`.

```protobuf
message BfdPeerConfig {
  bool enabled = 1;
  uint32 port = 2;
  uint32 desired_minimum_tx_interval = 3;
  uint32 required_minimum_receive = 4;
  uint32 detection_multiplier = 5;
}
```

For example, when adding or updating a peer:

```go
peer := &api.Peer{
    Conf: &api.PeerConf{
        NeighborAddress: "192.0.2.2",
        PeerAsn:         65002,
    },
    Bfd: &api.BfdPeerConfig{
        Enabled:                  true,
        Port:                     3784,
        DesiredMinimumTxInterval: 300000,
        RequiredMinimumReceive:   300000,
        DetectionMultiplier:      3,
    },
}
```

`ListPeer` returns peer state with `state.bfd_state`.

## Troubleshooting

If the BFD session does not come up:

- verify that both GoBGP and the remote peer have BFD enabled for the same
  neighbor address;
- verify that UDP `3784` is reachable in both directions;
- verify that the remote system accepts source ports from `49152..65535`;
- avoid setting a non-default `port` unless the remote peer is known to listen
  there;
- check JSON peer output for `state.bfd_state.session_state`;
- capture traffic and confirm that BFD control packets are being exchanged.

```bash
$ tcpdump -ni any udp port 3784
```

For production use, choose intervals conservatively. Very aggressive BFD timers
can cause unnecessary BGP resets during CPU pressure, packet loss, or control
plane congestion.
