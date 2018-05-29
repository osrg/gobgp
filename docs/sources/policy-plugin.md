# Policy Plugin

This page explains how to implement your own policy plugin and how to configure
it.

The policy plugin enables to apply policy rules flexibly which are difficult
to define with the [OpenConfig](http://www.openconfig.net/) policy model, just
logging received paths and complex attributes manipulation for example.

## Prerequisites

The following assumes you finished [Getting Started](getting-started.md) and
bases of [GoBGP Policy Model](policy.md).

Also, the policy plugin feature uses ["plugin"](https://golang.org/pkg/plugin/)
package of Golang, which requires to use Golang version 1.8 or later.

## Contents

- [Implementation of Policy Plugin](#implementation-of-policy-plugin)
- [Build Policy Plugin](#build-policy-plugin)
- [Configuration](#configuration)
- [Verification](#verification)

## Implementation of Policy Plugin

A policy plugin must have an `Apply` function which receives `path *table.Path`
and `options *table.PolicyOptions` arguments, then returns `*table.Path` and
`error`.

```go
package main

import (
    "github.com/osrg/gobgp/table"
)

func Apply(path *table.Path, options *table.PolicyOptions) (*table.Path, error) {
    // Do some manipulation of "path".
    // Or "return nil, nil" to reject "path".
    return path, nil
}
```

`path *table.Path` includes the incoming path information and
`options *table.PolicyOptions` provides the additional information about sender
router for example.

The return value of `*table.Path` should be the updated path if successfully
manipulated (also with nothing to update) and `error` describes errors during
manipulation process. Also, to reject the given path, please `return nil, nil`.

Example: `policy_a.go`

```go
package main

import (
    "fmt"

    "github.com/osrg/gobgp/table"
)

func Apply(path *table.Path, options *table.PolicyOptions) (*table.Path, error) {
    // Just do logging
    fmt.Printf("Apply policy to %+v\n", path)
    return path, nil
}
```

## Build Policy Plugin

To generate a loadable policy plugin, execute `go build` command with
`-buildmode=plugin` option.

```bash
go build -buildmode=plugin -o <plugin name>.so <plugin name>.go
```

Example: Build `policy_a.so` with `policy_a.go`

```bash
go build -buildmode=plugin -o policy_a.so policy_a.go
```

## Configuration

To attach the policy plugin to global RIB or neighbor's local RIB (only when
the neighbor is configured as a "route-server client"), specify path to the
generated policy plugin (`.so` file) with `plugin-path` in
`[[policy-definitions]]` section.

Example: Attach `policy_a.so` to global RIB as "import policy"

```toml
[global.apply-policy.config]
  import-policy-list = ["policy_a"]
  default-import-policy = "accept-route"
  default-export-policy = "accept-route"

[[policy-definitions]]
  name = "policy_a"
  plugin-path = "/path/to/policy_a.so"
```

Example: Attach `policy_a.so` to global RIB as "export policy"

```toml
[[neighbors]]
  # ...(snip)...
  [neighbors.route-server.config]
    route-server-client = true
  [neighbors.apply-policy.config]
    export-policy-list = ["policy_a"]
    default-import-policy = "accept-route"
    default-export-policy = "accept-route"
    default-in-policy = "accept-route"

[[policy-definitions]]
  name = "policy_a"
  plugin-path = "/path/to/policy_a.so"
```

**NOTE:** When reloading the confirmation file, GoBGP will determine whether
the configured values are updated or not before calling the reloading policy
API. So if the configured value (`plugin-path`) is not changed, even if the
plugin is updated, GoBGP can't detect the change of the plugin's
implementation. Then for reloading the policy plugin, please also update the
value of `plugin-path`, for example, `/path/to/policy_a.1.0.so` to
`/path/to/policy_a.1.1.so` or appending the timestamp.

## Verification

Let's verify the example policy plugin `policy_a.so` attached to global RIB can
output log messages when `Apply` function is called.

Topology:

```text
+----------+              +----------+
| r1       |              | r2       |
| 10.0.0.1 +----(iBGP)----+ 10.0.0.2 |
| AS 65000 |              | AS 65000 |
+----------+              +----------+
```

`gobgpd.toml` on r1:

```toml
[global.config]
  as = 65000
  router-id = "1.1.1.1"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "10.0.0.2"
    peer-as = 65000
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "ipv4-unicast"

[global.apply-policy.config]
  import-policy-list = ["policy_a"]
  default-import-policy = "accept-route"
  default-export-policy = "accept-route"

[[policy-definitions]]
  name = "policy_a"
  plugin-path = "/path/to/policy_a.so"
```

`gobgpd.toml` on r2:

```toml
[global.config]
  as = 65000
  router-id = "2.2.2.2"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "10.0.0.1"
    peer-as = 65000
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "ipv4-unicast"
```

Start GoBGP on r1 and r2.

```bash
r1> gobgpd -f gobgpd.toml
{"level":"info","msg":"gobgpd started","time":"YYYY-MM-DDThh:mm:ss+09:00"}
{"Topic":"Config","level":"info","msg":"Finished reading the config file","time":"YYYY-MM-DDThh:mm:ss+09:00"}
{"level":"info","msg":"Peer 10.0.0.2 is added","time":"YYYY-MM-DDThh:mm:ss+09:00"}
{"Topic":"Peer","level":"info","msg":"Add a peer configuration for:10.0.0.2","time":"YYYY-MM-DDThh:mm:ss+09:00"}
{"Key":"10.0.0.2","State":"BGP_FSM_OPENCONFIRM","Topic":"Peer","level":"info","msg":"Peer Up","time":"YYYY-MM-DDThh:mm:ss+09:00"}
...(snip)...

r2> gobgpd -f gobgpd.toml
{"level":"info","msg":"gobgpd started","time":"YYYY-MM-DDThh:mm:ss+09:00"}
{"Topic":"Config","level":"info","msg":"Finished reading the config file","time":"YYYY-MM-DDThh:mm:ss+09:00"}
{"level":"info","msg":"Peer 10.0.0.1 is added","time":"YYYY-MM-DDThh:mm:ss+09:00"}
{"Topic":"Peer","level":"info","msg":"Add a peer configuration for:10.0.0.1","time":"YYYY-MM-DDThh:mm:ss+09:00"}
{"Key":"10.0.0.1","State":"BGP_FSM_OPENCONFIRM","Topic":"Peer","level":"info","msg":"Peer Up","time":"YYYY-MM-DDThh:mm:ss+09:00"}
...(snip)...
```

Add a route on r2.

```bash
r2> gobgp global rib -a ipv4 add 10.2.1.0/24
r2> gobgp global rib -a ipv4
   Network              Next Hop             AS_PATH              Age        Attrs
*> 10.2.1.0/24          0.0.0.0                                   00:00:00   [{Origin: ?}]
```

Then, GoBGP on r1 should output like;

```bash
r1> gobgpd -f r1_gobgpd.toml
...(snip)...
Apply policy to { 10.2.1.0/24 | src: { 10.0.0.2 | as: 65000, id: 2.2.2.2 }, nh: 10.0.0.2 }
```
