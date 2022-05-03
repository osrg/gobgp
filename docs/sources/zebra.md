# FIB manipulation

This page explains how to perform FIB manipulation; kernel routing
table updates, interface lookups, and redistribution of routes between
different routing protocols. GoBGP uses zebra included in
[Quagga](http://www.nongnu.org/quagga/) or [FRRouting](https://frrouting.org/).

## Prerequisites

Assume you finished [Getting Started](getting-started.md)
and installing Quagga or FRRouting on the same host with GoBGP.

**Note:** For the integration with FRRouting, version 3.0.x (Zebra API
version 4), 5.0.x (Zebra API version 5), and 8.1.x (Zebra API version
6) are supported as default. If you need to integrate with other
version of FRRouting, please use `software-name` configuration.

## Contents

- [Configuration](#configuration)
- [Check routes from zebra](#check-routes-from-zebra)

## Configuration

You need to enable the zebra feature in the Global configuration as follows.

```toml
[zebra]
    [zebra.config]
        enabled = true
        url = "unix:/var/run/quagga/zserv.api"
        redistribute-route-type-list = ["connect"]
        version = 2
```

- `url` specifies the path to the unix domain socket or the TCP port for
  connecting to Zebra API.
  If omitted, GoBGP will use `"unix:/var/run/quagga/zserv.api"` by the default.
  Please note that with FRRouting, the path to the unix domain socket would be
  like `"unix:/var/run/frr/zserv.api"`.
  To specify the TCP port, `url` value would be like `"tcp:192.168.24.1:2600"`.

- `redistribute-route-type-list` specifies which route types you want to
  receive from Zebra daemon.
  For example, with `["connect"]`, GoBGP will receive the connected routes and
  redistribute them.

- `version` specifies Zebra API version.
  `2` is the version used by Quagga on Ubuntu 16.04 LTS.
  To enable the Next-Hop Tracking features, please specify `3` or later.
  For connecting to FRRouting 3.0.x, please specify `4`.
  For connecting to FRRouting 5.0.x, please specify `5`.
  For connecting to FRRouting 8.1.x, please specify `6`.

- `mpls-label-range-size` specifies mpls label range size for
  requesting to Zebra. It works with FRRouting 5.0.x, and newer versions.

- `sotware-name` specifies software name for zebra when only `version`
  configuration cannot specify software uniquely. This configuration
  is used with 'version' configuration. For connecting to FRRouting
  7.2.x, please specify `6` as `version` and `frr7.2` as
  `software-name`. For connecting to FRRouting 4.0.x, please specify
  `5` as `version` and `frr4` as `software-name`. For connecting to
  Cumulus Linux please specify `5` as `version` and `cumulus` as
  `software-name`. GoBGP is tested with Cumulus Linux VX 3.7.7 whose
  zebra version is 4.0+cl3u13 and its Zebra API version is 5.

### Summary of combination of version and software-name configrations

|version|software-name|software                        |remarks                                     |
|-------|-------------|--------------------------------|--------------------------------------------|
|2      |             |quagga                          |Ubuntu 16.04, CentOS7                       |
|3      |             |quagga                          |Ubuntu 18.04                                |
|4      |             |FRRouting 3.0.x                 |(deprecated)                                |
|5      |             |FRRouting 5.0.x                 |(deprecated)                                |
|5      |cumulus      |Cumulus Linux VX 3.7.7          |(deprecated)                                |
|5      |frr4         |FRRouting 4.0.x                 |(deprecated)                                |
|6      |             |FRRouting 8.0.x, 8.1x, and 7.5.x|Ubunut 22.04 (FRR8.1), AlmaLinux8.5 (FRR7.5)|
|6      |frr7.3       |FRRouting 7.3.x                 |(deprecated)                                |
|6      |frr7.2       |FRRouting 7.2.x                 |Ubuntu 20.04                                |
|6      |frr7         |FRRouting 7.0.x and 7.1.x       |(deprecated)                                |
|6      |frr6         |FRRouting 6.0.x                 |(deprecated)                                |

## Check Routes from zebra

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
