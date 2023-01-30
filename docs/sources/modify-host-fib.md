# modify-host-fib

**WARNING: Experimental!**

`modify-host-fib` provides experimental functionality to inject learned routes into the
routing table of the host running GoBGP. i.e. it provides a subset of something like
Zebra's functionality without requiring the external dependency of Zebra.

This could be extended in the future to support bidirectional functionality but
currently only learning routes is supported.

This currently only works on Windows, with IPv4. The initial implementation goal was
only to get BGP working on Windows desktop OSs (Windows Server has native BGP support -
if you're here for Windows Server support you should probably use that).

**This is not supported by the core GoBGP team at all. Use at your own risk.**

## Users

Add this to your config:

```toml
[experimental]
    [experimental.modify-host-fib]
        [experimental.modify-host-fib.config]
            enabled = true
```

## Developers

### Code flow

The implementation and flow mirrors the Zebra integration. The Zebra integration:

- `/tools/pyang_plugins/gobgp.yang` defines the user-facing configuration options for
  Zebra in YANG format
- pyyang converts this into Go structures in `internal/config/bgp_configs.go`
- If Zebra is enabled, `InitialConfig()` in `pkg/config/config.go` calls `EnableZebra()`
- `EnableZebra()` in `pkg/server/server.go` calls `NewZebraClient()` to create a new
  Zebra client and add it to the `BgpServer` singleton
- `NewZebraClient()` in `pkg/server/zclient.go` sets up the connection to Zebra and
  kicks off `loop()` as a goroutine
- `loop()` in `pkg/server/zclient.go` watches for events from `BgpServer` and the Zebra
  daemon and triggers a matching effect on the opposite side

Additionally a gprc request defined in `api/gobgp.proto` - rendered into `gobgp.pb.go`
and `gobgp_grpc.pb.go` by `tools/grpc/genproto.sh` - can be used to call
`EnableZebra()`.

This implementation:

- `/tools/pyang_plugins/gobgp.yang` defines the user-facing configuration options for
  this feature in YANG format
- pyyang converts this into Go structures in `internal/config/bgp_configs.go`
- If this feature is enabled, `InitialConfig()` in `pkg/config/config.go` calls
  `EnableModifyHostFIB()`
- `EnableModifyHostFIB()` in `pkg/server/server.go` calls `NewModifyHostFIBClient()` to
  create a new client and add it to the `BgpServer` singleton
- `NewModifyHostFIBClient()` in `pkg/server/modify_host_fib.go` kicks off `loop()` as a
  goroutine
- `loop()` in `pkg/server/modify_host_fib.go` watches for events from `BgpServer` and
  updates the host's routing table to match
- Some external activity (e.g. CTRL+C) triggers `stopServer()` in `main.go`
- `stopServer()` calls `Stop()` on `bgpServer` in `server.go`
- `Stop()` calls `stop()` in `modify_host_fib.go`
- `stop()` stops `loop()`, waits for it to finish, then removes all BGP routes from the
  host's routing table to clean up

Additionally a gprc request defined in `api/gobgp.proto` - rendered into `gobgp.pb.go`
and `gobgp_grpc.pb.go` by `tools/grpc/genproto.sh` - can be used to call
`EnableModifyHostFIB()`.

### Adding a new platform

To support multiple platforms this uses the `<filename>_<platform>.go` pattern used
elsewhere: each platform's specific implementation is in a separate file and Go `build:`
 parameters are used to only include the correct files for each platform.

- Add a new `pkg/server/modify_host_fib_<platform>.go` file, e.g.
   `pkg/server/modify_host_fib_linux.go`
- Set it to only build for that platform:

```go
//go:build <platform>
// +build <platform>
```

e.g.

```go
//go:build linux
// +build linux
```

- Exclude the default stub file `pkg/server/modify_host_fib_stub.go` from your platform

```go
//go:build <existing> && !<platform>
// +build <existing> && !<platform>
```

e.g.

```go
//go:build !windows && !linux
// +build !windows && !linux
```

- Copy the contents of `pkg/server/modify_host_fib_windows.go` and implement the
   functions for your platform. The only required functions are
   `newModifyHostFIBClient()` and `stop()` as these are called by other code in the
   `server` package. The rest are implementation details.
