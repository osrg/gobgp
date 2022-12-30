# modify-host-fib

**WARNING: Experimental!**

`modify-host-fib` provides experimental functionality to inject learned routes into the
routing table of the host running GoBGP. i.e. it provides a subset of something like
Zebra's functionality without requiring the external dependency of Zebra.

This could be extended in the future to support bidirectional functionality but
currently only learning routes is supported.

This currently only works on Windows. The initial implementation goal was only to get
BGP working on Windows desktop OSs (Windows Server has native BGP support - if you're
here for Windows Server support you should probably use that).

**This is not supported by the core GoBGP team at all. Use at your own risk.**

## Dev

The implementation and flow mirrors the Zebra integration. The Zebra integration:

- `/tools/pyang_plugins/gobgp.yang` defines the user-facing configuration options for
  Zebra in YANG format
- pyyang converts this into Go structures in `internal/config/bgp_configs.go`
- If Zebra is enabled, `InitialConfig()` in `pkg/config/config.go` calls `EnableZebra()`
- `EnableZebra()` in `pkg/server/zclient.go` calls `NewZebraClient()` to create a new
  Zebra client and add it to the `BgpServer` singleton
- `NewZebraClient()` in `pkg/server/zclient.go` sets up the connection to Zebra and
  kicks off `loop()` as a goroutine
- `loop()` in `pkg/server/zclient.go` watches for events from `BgpServer` and the Zebra
  daemon and triggers a matching effect on the opposite side

This implementation:

- `/tools/pyang_plugins/gobgp.yang` defines the user-facing configuration options for
  this feature in YANG format
- pyyang converts this into Go structures in `internal/config/bgp_configs.go`
- If this feature is enabled, `InitialConfig()` in `pkg/config/config.go` calls
  `EnableModifyHostFIB()`
- `EnableModifyHostFIB()` in `pkg/server/modify_host_fib.go` calls
  `NewModifyHostFIBClient()` to create a new client and add it to the `BgpServer`
  singleton
- `NewModifyHostFIBClient()` in `pkg/server/modify_host_fib.go` kicks off `loop()` as a
  goroutine
- `loop()` in `pkg/server/modify_host_fib.go` watches for events from `BgpServer` and
  updates the host's routing table to match

