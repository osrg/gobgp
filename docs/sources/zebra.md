# FIB manipulation

This page explains how to perform FIB manipulation; kernel routing
table updates, interface lookups, and redistribution of routes between
different routing protocols. GoBGP uses zebra included in
[Quagga](http://www.nongnu.org/quagga/).

## Prerequisites

Assume you finished [Getting Started](https://github.com/osrg/gobgp/blob/master/docs/sources/getting-started.md) and installing [Quagga](http://www.nongnu.org/quagga/) on the same host with GoBGP.

## Contents
- [Configuration](#section0)
- [Check routes from zebra](#section1)

## <a name="section0"> Configuration
You need to enable the zebra feature in the Global configuration as follows.

```toml
[zebra]
    [zebra.config]
        enabled = true
        url = "unix:/var/run/quagga/zserv.api"
        redistribute-route-type-list = ["connect"]
```

You can skip Url. If it's skipped, GoBGP uses "unix:/var/run/quagga/zserv.api" as the Url.
This configuration specifies unix domain socket in its Url and you can change it to the one using TCP.
If you use TCP, Url can be like "tcp:192.168.24.1:2600".
Specify which route type you want to redistribute through bgp.
Here gobgp will redistribute connected routes which zebra has.

## <a name="section1">Check Routes from zebra

Zebra has 3 connected routes in this example's environment.
 - 172.16.1.100/30
 - 172.16.6.100/30
 - 192.168.31.0/24

Let's check these routes with GoBGP cli.

```bash
$ gobgp global rib
    Network              Next Hop             AS_PATH              Age        Attrs
*>  172.16.1.100/30      0.0.0.0                                   00:00:02   [{Origin: i} {Med: 1}]
*>  172.16.6.100/30      0.0.0.0                                   00:00:02   [{Origin: i} {Med: 1}]
*>  192.168.31.0/24      0.0.0.0                                   00:00:02   [{Origin: i} {Med: 1}]
```

You can see connected routes stored in the GoBGP global rib.

