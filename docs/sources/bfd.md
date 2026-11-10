# BFD

BFD (Bidirectional Forwarding Detection) is a protocol for fast liveness
detection between two network systems. In BGP deployments, it is commonly used
to detect neighbor failures faster than regular BGP hold timers.

Both sides periodically exchange small BFD control packets. If one side stops
receiving packets for the configured detection time, the BFD session goes down
and the routing protocol can react immediately.

GoBGP implements BFD for BGP neighbors using the basic control packet model from
[RFC 5880](https://datatracker.ietf.org/doc/html/rfc5880), single-hop UDP
transport from [RFC 5881](https://datatracker.ietf.org/doc/html/rfc5881), and
multihop UDP transport from
[RFC 5883](https://datatracker.ietf.org/doc/html/rfc5883).

## Supported Features

GoBGP has an native BFD implementation scoped to fast BGP peer failure
detection. It is intended to cover single-hop and multihop asynchronous BFD for
BGP neighbors, not to replace a full-featured standalone BFD daemon.

Supported behavior:

- asynchronous BFD control packets over UDP;
- per-neighbor BFD configuration;
- peer-group BFD configuration inherited by neighbors;
- default destination UDP port `3784`, or `4784` for a multihop session;
- source UDP port selected from the RFC 5881 dynamic range `49152..65535`;
- source IP taken from the neighbor transport `local-address` when it is set;
  otherwise, for static and dynamic neighbors alike, from the local address of
  the established BGP TCP connection;
- outgoing BFD packets sent with TTL/Hop Limit `255`;
- received BFD packets of a single-hop session discarded unless their TTL/Hop
  Limit is `255` (RFC 5881 Section 5), and those of a multihop session
  discarded if their TTL/Hop Limit is below a minimum (see
  [Multihop](#multihop)). The check is skipped on a platform where the socket
  can't report the TTL;
- received BFD packets discarded if the version is not `1`, or if the
  Multipoint (M) or Authentication Present (A) bit is set (RFC 5880 Section
  6.8.6). GoBGP does not support BFD authentication;
- BFD states `DOWN`, `INIT`, `UP`, and `ADMIN_DOWN`;
- the diagnostic code in sent packets: `1` (Control Detection Time Expired)
  after the detection time expires, and `3` (Neighbor Signaled Session Down)
  after the peer signals `DOWN` or `ADMIN_DOWN` (RFC 5880 Sections 6.8.4 and
  6.8.6). It is cleared when the session comes back up;
- transmission slows to at least one second while the session is not `UP`
  (RFC 5880 Section 6.8.3);
- transmission paced by the peer's advertised `Required Min RX Interval`:
  GoBGP never sends faster than the larger of its own interval and the peer's
  (RFC 5880 Section 6.8.7). If the peer advertises zero, GoBGP sends no
  periodic packets, only the ones for a state change or a reply to a Poll;
- Poll Sequence initiation when the transmit or receive interval changes, and
  termination on a received Final, plus an immediate reply to a received
  Poll;
- a change of `desired-minimum-tx-interval`, `required-minimum-receive` or
  `detection-multiplier` applied to the running session, without taking it
  down (RFC 5880 Section 6.8.3). While the session is `UP`, a longer transmit
  interval or a shorter receive interval takes effect when the Poll Sequence
  for it ends. A change of another BFD setting, such as `port` or `multihop`,
  still replaces the session;
- hard BGP peer reset when an `UP` BFD session expires or the remote peer
  signals `DOWN`;
- one `ADMIN_DOWN` packet, with diagnostic `7` (Administratively Down), sent
  when a session the peer knows about is removed, for example when BFD is
  disabled on the neighbor or the neighbor is deleted (RFC 5880 Section
  6.8.16). The RFC asks for packets for a Detection Time; GoBGP sends one, as
  FRR does;
- BFD configuration through the GoBGP config file and gRPC API;
- BFD state in peer state returned by the API.

Current scope and limitations:

- BFD authentication, echo mode, demand mode, and other advanced BFD features
  are out of scope for this implementation;
- remote interval negotiation is limited: GoBGP always advertises its
  configured intervals, apart from the one-second floor while the session is
  not `UP`, and never renegotiates them at runtime beyond that floor. It
  derives its detection time from the peer's advertised
  `Desired Min TX Interval` (RFC 5880 6.8.4).

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
This applies while the session is `UP` and the peer's advertised
`Required Min RX Interval` is no larger; a peer asking for a slower rate is
honored (RFC 5880 Section 6.8.7). While the session is not `UP`, transmission is
paced at no faster than one second regardless of the configured interval (RFC
5880 Section 6.8.3), so session establishment runs at the slower pace.

The local detection time is:

```text
required-minimum-receive * detection-multiplier
```

So `300000 * 3` gives about `900 ms`.

If BFD timer values are omitted, GoBGP uses these defaults:

| Option | Default | Unit |
| --- | ---: | --- |
| `enabled` | `false` | boolean |
| `port` | `3784`, or `4784` with `multihop` | UDP port |
| `multihop` | `false` | boolean |
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
port. RFC 5881 specifies `3784` for single-hop BFD, and RFC 5883 specifies
`4784` for multihop BFD. In GoBGP, the local BFD server still listens on UDP
`3784` and `4784`; changing `port` only changes the remote destination port used
by outgoing packets.

For firewalls and ACLs, allow:

- inbound UDP `3784`, or `4784` for multihop, to the GoBGP host;
- outbound UDP from an ephemeral source port in `49152..65535` to the peer's
  BFD destination port, normally `3784`, or `4784` for multihop;
- the reverse direction on the peer.

## Multihop

Set `multihop = true` for a peer that is not on the same link, for example a
route reflector or an eBGP peer reached with `ebgp-multihop`. Both sides must
agree: a multihop session sends to and receives on UDP `4784`, and a packet for
it that comes in on `3784` is discarded, and the other way around.

```toml
[[neighbors]]
  [neighbors.config]
    neighbor-address = "198.51.100.2"
    peer-as = 65002
  [neighbors.ebgp-multihop.config]
    enabled = true
    multihop-ttl = 2
  [neighbors.bfd.config]
    enabled = true
    multihop = true
```

The peer sends BFD packets with TTL/Hop Limit `255`, so a packet that crossed
`n` hops arrives with `256 - n`. GoBGP takes the TTL that BGP uses for the
neighbor as the largest number of hops, like FRR, and discards a packet that
arrives with a lower TTL:

| BGP neighbor | Lowest TTL accepted |
| --- | --- |
| eBGP with `ebgp-multihop` and `multihop-ttl = n` | `256 - n` |
| eBGP without `ebgp-multihop` | `255` |
| eBGP with `ttl-security` | any |
| iBGP | any |

In the example above, the lowest TTL accepted is `254`.

The remote BGP speaker must also run BFD and must be configured with compatible
timers. Enabling BFD only on one side is not enough to bring the BFD session up.

## Runtime Behavior

When BFD is enabled for a neighbor, GoBGP creates a BFD peer for the neighbor
address. If the BFD session expires, or if the remote side signals `DOWN`,
GoBGP closes the BGP session with the peer. It sends a NOTIFICATION with the
error code Cease and the subcode BFD Down (RFC 9384). If the BGP session is not
established, nothing is sent.

The BFD source address follows the neighbor transport `local-address` when it
is set, and that BFD peer is created as soon as the neighbor is configured.
When `local-address` is unset or unspecified, GoBGP waits until the BGP session
is `ESTABLISHED` and uses the local address of that TCP connection, so the BFD
source always matches the BGP source. The BFD peer is kept unchanged across a
BGP reconnect and is replaced only when the new connection has a different
local address. Dynamic neighbors follow the same rule, but their BFD peer is
removed when the session goes down, together with the neighbor itself.

Changing BFD configuration through `UpdatePeer` is applied at runtime:

- enabling BFD adds the BFD peer;
- disabling BFD removes the BFD peer;
- changing BFD timer, port, or multihop settings recreates the BFD peer with
  the new configuration.

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
- verify that UDP `3784`, or `4784` for multihop, is reachable in both
  directions;
- verify that both sides agree on `multihop`;
- verify that the remote system accepts source ports from `49152..65535`;
- verify that the remote system sends BFD packets with TTL/Hop Limit `255`,
  and for multihop, that `ebgp-multihop` allows the number of hops to it;
- verify that the neighbor transport `local-address`, when configured, exists on
  the host and is compatible with `bind-interface`;
- avoid setting a non-default `port` unless the remote peer is known to listen
  there;
- check JSON peer output for `state.bfd_state.session_state`;
- capture traffic and confirm that BFD control packets are being exchanged.

```bash
$ tcpdump -ni any udp port 3784 or udp port 4784
```

For production use, choose intervals conservatively. Very aggressive BFD timers
can cause unnecessary BGP resets during CPU pressure, packet loss, or control
plane congestion.
