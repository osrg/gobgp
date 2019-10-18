# BGP Monitoring Protocol

GoBGP supports [BGP Monitoring Protocol (RFC 7854)](https://tools.ietf.org/html/rfc7854), which provides a convenient interface for obtaining route views.

## Prerequisites

Assume you finished [Getting Started](getting-started.md).

## Contents

- [Configuration](#configuration)
- [Verification](#verification)

## Configuration

Add `[bmp-servers]` session to enable BMP.

```toml
[global.config]
  as = 64512
  router-id = "192.168.255.1"

[[bmp-servers]]
  [bmp-servers.config]
    address = "127.0.0.1"
    port=11019
```

The supported route monitoring policy types are:

- pre-policy (Default)
- post-policy
- both (Obsoleted)
- local-rib
- all

Enable post-policy support as follows:

```toml
[[bmp-servers]]
  [bmp-servers.config]
    address = "127.0.0.1"
    port=11019
    route-monitoring-policy = "post-policy"
```

Enable all policies support as follows:

```toml
[[bmp-servers]]
  [bmp-servers.config]
    address = "127.0.0.1"
    port=11019
    route-monitoring-policy = "all"
```

To enable BMP stats reports, specify the interval seconds to send statistics messages.
The default value is 0 and no statistics messages are sent.
Please note the range of this interval is 15 though 65535 seconds.

```toml
[[bmp-servers]]
  [bmp-servers.config]
    address = "127.0.0.1"
    port=11019
    statistics-timeout = 3600
```

To enable route mirroring feature, specify `true` for `route-mirroring-enabled` option.
Please note this option is mainly for debugging purpose.

```toml
[[bmp-servers]]
  [bmp-servers.config]
    address = "127.0.0.1"
    port=11019
    route-mirroring-enabled = true
```

## Verification

Let's check if BMP works with a bmp server. You can find some OSS BMP server implementations such as [yambp](https://github.com/smartbgp/yabmp), [OpenBMP](https://github.com/SNAS/openbmp), etc.
