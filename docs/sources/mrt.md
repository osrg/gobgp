# MRT

This page explains how to play with GoBGP's MRT feature.

## Prerequisites

Assume you finished [Getting Started](https://github.com/osrg/gobgp/blob/master/docs/sources/getting-started.md).

## Contents
- [Inject routes from MRT table v2 records](#section0)
- [Dump updates in MRT BGP4MP format](#section1)
    - [Configuration](#section1.1)

## <a name="section0"> Inject routes from MRT table v2 records
Route injection can be done by
```bash
$ gobgp mrt inject global <dumpfile> [<number of prefix to inject>]
```

## <a name="section1"> Dump updates in MRT BGP4MP format

### <a name="section1.1"> Configuration

With the following configuration, gobgpd continuously dumps BGP update
messages to `/tmp/updates.dump` file in the BGP4MP format and dumps
routes in the global rib to `/tmp/table.dump` file in the TABLE_DUMPv2
format every 60 seconds.

```toml
[global.config]
as = 64512
router-id = "10.0.255.254"

[[neighbors]]
  [neighbors.config]
    peer-as = 65001
    neighbor-address = "10.0.255.1"

[[mrt-dump]]
  [mrt-dump.config]
    dump-type = "updates"
    file-name = "/tmp/updates.dump"

[[mrt-dump]]
  [mrt-dump.config]
    dump-type = "table"
    file-name = "/tmp/table.dump"
    dump-interval = 60
```

Also gobgpd supports log rotation; a new dump file is created
periodically, and the old file is renamed to a different name.  With
the following configuration, gobgpd creates a new dump file every 180
seconds such as `/tmp/20160510.1546.dump`. The format of a name can be
specified in golang's
[time](https://golang.org/pkg/time/#pkg-constants) package's format.

```toml
[global.config]
as = 64512
router-id = "10.0.255.254"

[[neighbors]]
  [neighbors.config]
    peer-as = 65001
    neighbor-address = "10.0.255.1"

[[mrt-dump]]
  [mrt-dump.config]
    dump-type = "updates"
    file-name = "/tmp/log/20060102.1504.dump"
    rotation-interval = 180
```


