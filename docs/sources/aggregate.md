# Route Aggregation

This page explains how to configure route aggregation.
Aggregation advertises a single, less-specific route in place of the more-specific
routes it covers, reducing the number of routes propagated to peers.

## Contents

- [Configuration](#configuration)
- [CLI](#cli)

## Configuration

Aggregates are declared under the global configuration. Each aggregate generates a
locally-originated route for its prefix once at least one more-specific route exists in
the global RIB.

```toml
[global.config]
  as = 65001
  router-id = "172.40.1.2"

[[global.aggregates]]
  [global.aggregates.config]
    prefix = "10.0.0.0/8"
    summary-only = true
    as-set = true
    policy-name = "contributors"
```

- `summary-only` suppresses advertisement of the more-specific contributing routes.
- `as-set` builds an `AS_SET` from the contributing routes' AS paths; otherwise the
  aggregate carries `ATOMIC_AGGREGATE`.
- `policy-name` references a policy a route must pass to contribute to the aggregate.

## CLI

Aggregates can also be managed at runtime.

```shell
$ gobgp global aggregate add 10.0.0.0/8 --summary-only --as-set --policy contributors
$ gobgp global aggregate add 2001:db8::/32

$ gobgp global aggregate
Prefix                                   Contributors  Summary  AS-Set  Policy
10.0.0.0/8                               3             true     true    contributors
2001:db8::/32                            1             false    false   -

$ gobgp global aggregate del 10.0.0.0/8
```
