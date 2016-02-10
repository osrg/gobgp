# MRT

This page explains how to play with GoBGP's MRT feature.

## Prerequisites

Assume you finished [Getting Started](https://github.com/osrg/gobgp/blob/master/docs/sources/getting-started.md).

## Contents
- [Configuration](#section0)
- [Dump MRT table v2 records](#section1)
    - [Dump neighbor's local table](#section1.1)
- [Inject routes from MRT table v2 records](#section2)

## <a name="section0"> Configuration
You don't need any special configuration for MRT feature.
This page assume the configuration below.

```toml
[global.config]
  as = 64512
  router-id = "192.168.255.1"
[[neighbors]]
  [neighbors.config]
    neighbor-address = "10.0.0.1"
    peer-as = 65001
```

## <a name="section1">Dump MRT Table v2 Records

Instant dump can be done like below

```bash
$ gobgp mrt dump rib global
mrt dump: rib_ipv4_20150809_233952
$ ls -la rib*
rib_ipv4_20150809_233952
```

To dump ipv6 routes, type

```bash
$ gobgp mrt dump rib global -a ipv6
mrt dump: rib_ipv6_20150809_234012
```

If you want to dump periodically, specify dump interval (unit is second)
```bash
# dump hourly. this will block
$ gobgp mrt dump rib global $((60*60))
mrt dump: rib_ipv4_20150809_234438
...
```

You can change output directory by  `-o <outdir>` and filename format by `-f <format>`

```bash
# change the output directory and the filename of dumps
$ gobgp mrt dump rib global -o /dump/here -f mydailydump_{{.Y}}_{{.M}}_{{.D}} $((60*60*24))
mrt dump: /dump/here/rib_2015_08_09
...
```

Filename format is same as golang [text/template](http://golang.org/pkg/text/template/) package template.
Below is the supported variables you can use.

| value                 | meaning                                       |
|:---------------------:|:---------------------------------------------:|
| {{.Y}}                | Year (e.g. 2015)                              |
| {{.M}}                | Month (e.g. 08)                               |
| {{.D}}                | Day (e.g. 09)                                 |
| {{.H}}                | Hour (e.g. 23)                                |
| {{.Min}}              | Minute (e.g. 47)                              |
| {{.Sec}}              | Second (e.g. 10)                              |
| {{.Af}}               | Address Family ( `ipv4` \| `ipv6` \| `l2vpn`) |
| {{.NeighborAddress }} | Neighbor Address (e.g. 10.0.0.1)              |
| {{.Resource}}         | Resource ( `global` \| `local` )              |

### <a name="section1.1"> Dump neighbor's local table
GoBGP supports multiple RIB for route server [feature](https://github.com/osrg/gobgp/blob/master/docs/sources/route-server.md).
GoBGP can also dump these tables which is local to neighbors

```bash
$ gobgp mrt dump rib neighbor 10.0.0.1 -o /dump/local $((60*60))
rpc error: code = 2 desc = "no local rib for 10.0.0.1"
```

Oops! Before trying this feature, you must enable route server feature.
Configuration is something like below.

```toml
[global.config]
  as = 64512
  router-id = "192.168.255.1"
[[neighbors]]
  [neighbors.config]
    neighbor-address = "10.0.0.1"
    peer-as = 65001
  [neighbors.route-server.config]
    route-server-client = true
```

OK, let's try again.

```bash
$ gobgp mrt dump rib neighbor 10.0.0.1 -o /dump/local
mrt dump: /dump/local/rib_10.0.0.1_20150809_234543
```

## <a name="section2"> Inject routes from MRT table v2 records
Route injection can be done by
```bash
$ gobgp mrt inject global <dumpfile> [<number of prefix to inject>]
```
