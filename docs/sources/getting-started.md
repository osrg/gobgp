# Running GoBGP

This page explains how to run GoBGP. This example sets up GoBGP to
connect with two eBGP peers for IPv4 routes. Even if you are
interested in other GoBGP use cases (such as IPv6 routes, EVPN, and
Route Server), this example gives you the basics of GoBGP usage.

## Prerequisites

You need to install [Go 1.3 or later](http://golang.org/doc/install). After installing Go, make sure that `$GOPATH/bin` in included in your `$PATH`.

## Installing GoBGP

```bash
$ go get github.com/osrg/gobgp/gobgpd
$ go get github.com/osrg/gobgp/gobgp
```

Finished. No dependency hell (library, package, etc) thanks to Go.
The first command installs GoBGP daemon (speaking BGP protocol). The
second one installs GoBGP CLI. The CLI isn't a must but handy whey you
play with GoBGP.

In addition, if you use Bash shell, you can enjoy CLI's tab completion:

```bash
$ wget https://raw.githubusercontent.com/osrg/gobgp/master/tools/completion/gobgp-completion.bash
$ source gobgp-completion.bash
```

## Configuration

Currently, GoBGP can be configured via a configuration file. This example
uses the following very simple configuration file, `gobgpd.conf`:

```
$ cat gobgpd.conf
[Global]
  [Global.GlobalConfig]
    As = 64512
    RouterId = "192.168.255.1"

[Neighbors]
  [[Neighbors.NeighborList]]
    [Neighbors.NeighborList.NeighborConfig]
      NeighborAddress = "10.0.255.1"
      PeerAs = 65001

  [[Neighbors.NeighborList]]
    [Neighbors.NeighborList.NeighborConfig]
      NeighborAddress = "10.0.255.2"
      PeerAs = 65002
```

## Starting GoBGP

Let's start gobgpd:

```
$ sudo -E gobgpd -f gobgpd.conf
{"level":"info","msg":"Peer 10.0.255.1 is added","time":"2015-04-06T20:32:28+09:00"}
{"level":"info","msg":"Peer 10.0.255.2 is added","time":"2015-04-06T20:32:28+09:00"}
```

Let's show the information of all the peers.

```
$ gobgp neighbor
Peer          AS  Up/Down State       |#Advertised Received Accepted
10.0.255.1 65001 00:00:14 Establ      |          1        5        5
10.0.255.2 65002 00:00:14 Establ      |          5        2        2
```

Want to the details of a particular peer?

```
$ gobgp neighbor 10.0.255.1
BGP neighbor is 10.0.255.1, remote AS 65001
  BGP version 4, remote router ID 192.168.0.1
  BGP state = BGP_FSM_ESTABLISHED, up for 00:01:49
  BGP OutQ = 0, Flops = 0
  Neighbor capabilities:
    MULTIPROTOCOL: advertised and received
    ROUTE_REFRESH: advertised and received
    FOUR_OCTET_AS_NUMBER: advertised and received
    ROUTE_REFRESH_CISCO: received
  Message statistics:
                         Sent       Rcvd
    Opens:                  2          1
    Notifications:          0          0
    Updates:                1          1
    Keepalives:             4          5
    Route Refesh:           0          0
    Discarded:              0          0
    Total:                  7          7
```

Note that the tab completion works for both peer names and commands.

Check out the global table.
```
$ gobgp global rib
   Network            Next Hop        AS_PATH    Age        Attrs
*> 10.3.0.0/16        10.0.255.1      [65001]    00:05:41   [{Origin: 0} {Med: 0}]
*> 10.3.0.0/24        10.0.255.1      [65001]    00:05:41   [{Origin: 0} {Med: 0}]
*  10.3.0.0/24        10.0.255.2      [65002]    00:05:41   [{Origin: 0} {Med: 111} {Community: [65001:65002 NO_EXPORT]}]
*> 10.3.0.0/32        10.0.255.1      [65001]    00:05:41   [{Origin: 0} {Med: 0}]
*> 10.3.0.1/32        10.0.255.1      [65001]    00:05:41   [{Origin: 0} {Med: 0}]
*> 10.33.0.0/16       10.0.255.1      [65001]    00:05:41   [{Origin: 0} {Med: 0}]
*> 192.168.2.0/24     10.0.255.2      [65002]    00:05:41   [{Origin: 0} {Med: 111} {Community: [65001:65002 NO_EXPORT]}]
```

You also can look at adjacent rib-in and rib-out:

```
$ gobgp neighbor 10.0.255.1 adj-in
   Network            Next Hop        AS_PATH    Age        Attrs
   10.3.0.0/16        10.0.255.1      [65001]    00:06:55   [{Origin: 0} {Med: 0}]
   10.3.0.0/24        10.0.255.1      [65001]    00:06:55   [{Origin: 0} {Med: 0}]
   10.3.0.0/32        10.0.255.1      [65001]    00:06:55   [{Origin: 0} {Med: 0}]
   10.3.0.1/32        10.0.255.1      [65001]    00:06:55   [{Origin: 0} {Med: 0}]
   10.33.0.0/16       10.0.255.1      [65001]    00:06:55   [{Origin: 0} {Med: 0}]
$ gobgp neighbor 10.0.255.1 adj-out
   Network            Next Hop        AS_PATH    Attrs
   192.168.2.0/24     10.0.255.254    [64512 65002] [{Origin: 0} {Community: [65001:65002 NO_EXPORT]}]
```
