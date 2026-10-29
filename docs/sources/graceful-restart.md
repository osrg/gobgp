# Graceful Restart

This page explains how to configure [Graceful Restart](https://tools.ietf.org/html/rfc4724),
[Graceful Restart Notification Support](https://tools.ietf.org/html/rfc8538) and
[Long Lived Graceful Restart](https://tools.ietf.org/html/draft-uttaro-idr-bgp-persistence-02).
Graceful Restart has two sides. One is restarting speaker which does restart,
the other is receiving speaker (helper speaker) which helps a restarting speaker
to do graceful restart. GoBGP supports both roles.

## Contents

- [Helper speaker](#helper-speaker)
- [Restarting speaker](#restarting-speaker)
- [Graceful Restart Notification Support](#graceful-restart-notification-support)
  - [Hard Reset](#hard-reset)
- [Long Lived Graceful Restart](#long-lived-graceful-restart)
  - [Long Lived Graceful Restart Helper Speaker Configuration](#long-lived-graceful-restart-helper-speaker-configuration)
  - [Long Lived Graceful Restart Restarting Speaker Configuration](#long-lived-graceful-restart-restarting-speaker-configuration)
  - [Combination with normal Graceful Restart](#combination-with-normal-graceful-restart)

## Helper speaker

Below is the configuration to enable helper speaker behavior.

```toml
[global.config]
  as = 64512
  router-id = "192.168.255.1"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "10.0.255.1"
    peer-as = 65001
  [neighbors.graceful-restart.config]
    enabled = true
```

Check graceful restart capability is negotiated.

```shell
$ gobgp n 10.0.255.1
BGP neighbor is 10.0.255.1, remote AS 65001
  BGP version 4, remote router ID 192.168.0.2
  BGP state = BGP_FSM_ESTABLISHED, up for 00:00:36
  BGP OutQ = 0, Flops = 0
  Hold time is 0, keepalive interval is 30 seconds
  Configured hold time is 90, keepalive interval is 30 seconds
  Neighbor capabilities:
    BGP_CAP_MULTIPROTOCOL:
        RF_IPv4_UC:     advertised and received
    BGP_CAP_ROUTE_REFRESH:      advertised and received
    BGP_CAP_GRACEFUL_RESTART:   advertised and received
        Remote: restart time 90 sec
            RF_IPv4_UC
    BGP_CAP_FOUR_OCTET_AS_NUMBER:       advertised and received
  Message statistics:
                         Sent       Rcvd
    Opens:                  1          1
    Notifications:          0          0
    Updates:                2          1
    Keepalives:             2          2
    Route Refresh:          0          0
    Discarded:              0          0
    Total:                  5          4
  Route statistics:
    Advertised:             1
    Received:               0
    Accepted:               0
```

## Restarting speaker

To support restarting speaker behavior, try the configuration below.

```toml
[global.config]
  as = 64512
  router-id = "192.168.255.1"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "10.0.255.1"
    peer-as = 65001
  [neighbors.graceful-restart.config]
    enabled = true
    restart-time = 120
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
    afi-safi-name = "ipv4-unicast"
    [neighbors.afi-safis.mp-graceful-restart.config]
        enabled = true
```

By this configuration, if graceful restart capability is negotiated with the peer,
the peer starts graceful restart helper procedure, when `gobgpd` dies involuntarily or
`SIGINT`, `SIGKILL` signal is sent to `gobgpd`.
Note when `SIGTERM` signal is sent to `gobgpd`, graceful restart negotiated peers
don't start graceful restart helper procedure, since `gobgpd` sends notification
messages to these peers before it die.

When you restart `gobgpd`, add `-r` option to let peers know `gobgpd` is
recovered from graceful restart.

```shell
$ gobgpd -f gobgpd.conf -r
```

Let's see how capability negotiation changes.

```shell
$ gobgp n 10.0.255.1
BGP neighbor is 10.0.255.1, remote AS 65001
  BGP version 4, remote router ID 192.168.0.2
  BGP state = BGP_FSM_ESTABLISHED, up for 00:00:03
  BGP OutQ = 0, Flops = 0
  Hold time is 0, keepalive interval is 30 seconds
  Configured hold time is 90, keepalive interval is 30 seconds
  Neighbor capabilities:
    BGP_CAP_MULTIPROTOCOL:
        RF_IPv4_UC:     advertised and received
    BGP_CAP_ROUTE_REFRESH:      advertised and received
    BGP_CAP_GRACEFUL_RESTART:   advertised and received
        Local: restart time 90 sec, restart flag set
            RF_IPv4_UC, forward flag set
        Remote: restart time 90 sec
            RF_IPv4_UC
    BGP_CAP_FOUR_OCTET_AS_NUMBER:       advertised and received
  Message statistics:
                         Sent       Rcvd
    Opens:                  1          1
    Notifications:          0          0
    Updates:                2          1
    Keepalives:             1          1
    Route Refresh:          0          0
    Discarded:              0          0
    Total:                  4          3
  Route statistics:
    Advertised:             1
    Received:               0
    Accepted:               0
```

You can see `restart flag` and `forward flag` is set.

Without `-r` option, the peers which are under helper procedure will
immediately withdraw all routes which were advertised from `gobgpd`.

Also, when `gobgpd` doesn't recovered within `restart-time`, the peers will
withdraw all routes.
Default value of `restart-time` is equal to `hold-time`.

### Route advertisement after the restart

After `gobgpd` is started with `-r`, it does not advertise an address family
until it receives the End-of-RIB marker of that family from every peer, as
[RFC4724](https://tools.ietf.org/html/rfc4724) Section 4.1 requires. A peer
is not waited for when its OPEN message has the restart flag set (it has
restarted too) or has no graceful restart capability, and when its session
ends. The families are independent: ipv4-unicast is advertised as soon as
its markers are in, even if ipv6-unicast is still waited for.

`deferral-time` bounds the wait for each peer. When it expires for a peer,
that peer is no longer waited for. The default is 360 seconds.

```toml
[[neighbors]]
  [neighbors.config]
    neighbor-address = "10.0.255.1"
    peer-as = 65001
  [neighbors.graceful-restart.config]
    enabled = true
    restart-time = 120
    deferral-time = 60
```

For a passive peer, `local-restart-connection-wait-time` optionally gives the
first connection its own wait, in seconds, starting when the peer is added during
local restart. If the session becomes Established before this wait expires,
`deferral-time` starts then, allowing the full interval for receiving EOR.
If the connection wait expires first, this peer stops delaying advertisement.
A late connection still receives the initial routes and EOR; it does not start
another shared EOR wait.

```toml
  [neighbors.transport.config]
    passive-mode = true
  [neighbors.graceful-restart.config]
    enabled = true
    deferral-time = 60
    local-restart-connection-wait-time = 30
```

The default, zero, preserves the existing behavior: `deferral-time` runs from
peer creation. Active peers also retain that behavior. Connection wait applies
only to the initial local restart, not to subsequent session flaps. It can be
configured on a peer group; a neighbor can override it, including with zero.
These settings delay route advertisement, not best-path selection or FIB updates.

When connection wait is enabled, allow for both the connection wait and EOR
deferral when choosing the overall restart budget.

Note that the peers keep the routes of `gobgpd` only for the `restart-time`
that `gobgpd` advertised. If `deferral-time` is longer than `restart-time`
and a peer is slow to send its marker, the other peers withdraw the routes
of `gobgpd` before the wait ends. Set `deferral-time` below `restart-time`,
or `restart-time` above `deferral-time`, when the peers must keep the routes
for the whole wait.

## Graceful Restart Notification Support

[RFC4724](https://tools.ietf.org/html/rfc4724) specifies gracful restart procedures are triggered only when
the BGP session between graceful restart capable peers turns down without
a notification message for backward compatibility.
[Graceful Restart Notification Support](https://tools.ietf.org/html/rfc8538)
expands this to trigger graceful restart procedures also with a notification message.
To turn on this feature, add `notification-enabled = true` to configuration like below.

```toml
[global.config]
  as = 64512
  router-id = "192.168.255.1"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "10.0.255.1"
    peer-as = 65001
  [neighbors.graceful-restart.config]
    enabled = true
    notification-enabled = true
```

The feature is used only when both sides advertise it (the "N" bit in the
Graceful Restart Capability). In this document, this is called "the N bit is
exchanged".

### Hard Reset

RFC 8538 adds the Hard Reset subcode of the Cease NOTIFICATION. A Hard Reset
ends the session without the graceful restart procedures: the peer removes the
routes at once. Which NOTIFICATIONs to send as a Hard Reset is up to the
implementation. RFC 8538 Section 5.1 gives suggestions only.

When the N bit is exchanged, GoBGP sends the following Cease NOTIFICATIONs as a
Hard Reset. The original NOTIFICATION (error code, error subcode and data) is
put in the data of the Hard Reset, as RFC 8538 Section 3.1 says.

| Cease subcode | Sent when |
|---|---|
| Maximum Number of Prefixes Reached | the number of received prefixes goes over the limit |
| Administrative Shutdown | `gobgp neighbor <address> shutdown` or `disable` |
| Peer De-configured | the neighbor is deleted |
| Administrative Reset | `gobgp neighbor <address> reset` |
| BFD Down | BFD detects that the path to the peer is down |

GoBGP sends the other NOTIFICATIONs as they are, for example a NOTIFICATION for
an error in a received message. The peer starts the graceful restart
procedures for them.

When the N bit is not exchanged, GoBGP does not send a Hard Reset. Every
NOTIFICATION is sent as it is, and the peer removes the routes at once.

When GoBGP receives a NOTIFICATION other than a Hard Reset and the N bit is
exchanged, it keeps the routes of the peer as stale, like when the TCP
connection is closed.

## Long Lived Graceful Restart

### Long Lived Graceful Restart Helper Speaker Configuration

```toml
[global.config]
  as = 64512
  router-id = "192.168.255.1"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "10.0.255.1"
    peer-as = 65001
  [neighbors.graceful-restart.config]
    enabled = true
    long-lived-enabled = true
```

### Long Lived Graceful Restart Restarting Speaker Configuration

Unlike normal graceful restart, long-lived graceful restart supports
restart-time as per address family.

```toml
[global.config]
  as = 64512
  router-id = "192.168.255.1"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "10.0.255.1"
    peer-as = 65001
  [neighbors.graceful-restart.config]
    enabled = true
    long-lived-enabled = true
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
    afi-safi-name = "ipv4-unicast"
    [neighbors.afi-safis.long-lived-graceful-restart.config]
        enabled = true
        restart-time = 100000
```

### Combination with normal Graceful Restart

You can also use long lived graceful restart with normal graceful restart.

```toml
[global.config]
  as = 64512
  router-id = "192.168.255.1"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "10.0.255.1"
    peer-as = 65001
  [neighbors.graceful-restart.config]
    enabled = true
    long-lived-enabled = true
    restart-time = 120
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
    afi-safi-name = "ipv4-unicast"
    [neighbors.afi-safis.mp-graceful-restart.config]
        enabled = true
    [neighbors.afi-safis.long-lived-graceful-restart.config]
        enabled = true
        restart-time = 100000
```
