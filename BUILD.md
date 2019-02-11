# Development Guide

## Building the development environment

You need a working [Go environment](https://golang.org/doc/install) (1.11 or newer).

```bash
$ go get github.com/osrg/gobgp/...
```

Now ready to modify the code and build two binaries, `cmd/gobgp` and `cmd/gobgpd`.

## Releases

GoBGP releases are time-based. Minor releases will occur every month ([Semantic Versioning](https://semver.org/)). Major releases occur only when absolutely necessary.

## Layout

The GoBGP project adopts [Standard Go Project Layout](https://github.com/golang-standards/project-layout).

## Changing the gRPC API

If you change the gRPC API, generate `api/gobgp.pb.go` in the following way:

```bash
$ protoc -I ~/protobuf/src -I ${GOBGP}/api --go_out=plugins=grpc:${GOBGP}/api \
         ${GOBGP}/api/gobgp.proto ${GOBGP}/api/attribute.proto ${GOBGP}/api/capability.proto
```
