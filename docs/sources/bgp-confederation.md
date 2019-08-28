# BGP Confederation

This page explains how to configure BGP confederation feature when BGP peers
are part of a larger mesh representing a single autonomous system (AS).

## Prerequisites

Assume you finished [Getting Started](getting-started.md).

## Contents

- [Configuration](#configuration)

## Configuration

If AS30 is a confederation composed of AS65001 and AS65002, the confederation members must configure
the following attributes to ensure GoBGP communicates in the correct manner with other member ASNs.
Each confederated autonomous systems must configure the `[global.confederation.config]` with
`enabled = true` and `identifier = 30`. The identifier parameter is used to designate what the
confederation should present as it's ASN non-confederation members. Each member of the confederation
must also configure `member-as-list` with a list of other ASNs which compose the confederation. For
example, AS65001 would configure this attribute as `member-as-list = [ 65002 ]`.

```toml
[global]
  [global.config]
    as = 65001
    router-id = "10.0.0.1"
  [global.confederation.config]
    enabled = true
    identifier = 30
    member-as-list = [ 65002 ]

[[neighbors]]
  [neighbors.config]
    peer-as = 65002
    neighbor-address = "10.0.0.2"
```
