# Route Server

This page explains how to set up GoBGP as a route server.

## Prerequisites

Assumed that you finished [Getting Started](https://github.com/osrg/gobgp/blob/master/docs/sources/getting-started.md).

## Configuration

This example uses the following simple configuration file, `gobgpd.conf`. There are three changes from 
the configuration file used in [Getting Started](https://github.com/osrg/gobgp/blob/master/docs/sources/getting-started.md)

 * Peers are configured as route server clients (of course!).
 * GoBGP doesn't try to connect to peers. It only listens and accepts.
 * MD5 passwords are enabled.

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
      AuthPassword = "hoge1"
    [Neighbors.NeighborList.Transport]
      [Neighbors.NeighborList.Transport.TransportConfig]
        PassiveMode = true
    [Neighbors.NeighborList.RouteServer]
      [Neighbors.NeighborList.RouteServer.RouteServerConfig]
        RouteServerClient = true

  [[Neighbors.NeighborList]]
    [Neighbors.NeighborList.NeighborConfig]
      NeighborAddress = "10.0.255.2"
      PeerAs = 65002
      AuthPassword = "hoge2"
    [Neighbors.NeighborList.Transport]
      [Neighbors.NeighborList.Transport.TransportConfig]
        PassiveMode = true
    [Neighbors.NeighborList.RouteServer]
      [Neighbors.NeighborList.RouteServer.RouteServerConfig]
        RouteServerClient = true
```

## Starting GoBGP

Let's start gobgpd:

```
$ sudo -E gobgpd -f gobgpd.conf
{"level":"info","msg":"Peer 10.0.255.1 is added","time":"2015-04-06T22:55:57+09:00"}
{"level":"info","msg":"Peer 10.0.255.2 is added","time":"2015-04-06T22:55:57+09:00"}
```

GoBGP implements multiple RIBs, that is, each peer has own local
RIB. Let's check respectively.

```
$ gobgp neighbor 10.0.255.1 local
   Network            Next Hop        AS_PATH    Age        Attrs
*> 10.3.0.0/24        10.0.255.2      [65002]    00:05:50   [{Origin: 0} {Med: 0}]
*> 192.168.2.0/24     10.0.255.2      [65002]    00:05:50   [{Origin: 0} {Med: 0}]
```

```
$ gobgp neighbor 10.0.255.2 local
   Network            Next Hop        AS_PATH    Age        Attrs
*> 10.3.0.0/16        10.0.255.1      [65001]    00:06:12   [{Origin: 0} {Med: 0}]
*> 10.3.0.1/32        10.0.255.1      [65001]    00:06:12   [{Origin: 0} {Med: 0}]
```

Of course, you can also look at the adjacent rib-in and rib-out of each peer as done in [Getting Started](https://github.com/osrg/gobgp/blob/master/docs/sources/getting-started.md).
