# MRT route injector

This page explains how to inject MRT routes to gobgp.

## Prerequisites

Assume you finished [Getting Started](https://github.com/osrg/gobgp/blob/master/docs/sources/getting-started.md).

## Install GoMRT

In addition to gobgpd and gobgp, you have to install `gomrt`

```bash
$ go get github.com/osrg/gobgp/gomrt
```

## Configuration

you don't need any special configuration for mrt

```
$ cat gobgpd.conf
[Global]
  As = 64512
  RouterId = "192.168.255.1"
[[NeighborList]]
  NeighborAddress = "10.0.255.1"
  PeerAs = 65001
```

## Start GoBGP

```bash
$ sudo -E gobgpd -f gobgpd.conf
{"level":"info","msg":"Peer 10.0.255.1 is added","time":"2015-04-06T20:32:28+09:00"}
{"level":"info","msg":"Peer 10.0.255.2 is added","time":"2015-04-06T20:32:28+09:00"}
```

## Inject MRT Routes!

Currently gomrt supports TABLE_DUMP_V2 format ([RFC6396](https://tools.ietf.org/html/rfc6396)).
You can get the Internet full route dump from [here](http://archive.routeviews.org/)

```
$ gomrt -i rib.20150617.2000
```
