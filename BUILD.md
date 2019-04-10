# Development Guide

## Building the development environment

You need a working [Go environment](https://golang.org/doc/install) (1.11 or newer) with the module support enabled.

```bash
$ git clone git://github.com/osrg/gobgp
$ cd gobgp && go mod download
```

Now ready to modify the code and build two binaries, `cmd/gobgp` and `cmd/gobgpd`.

## Releases

GoBGP releases are time-based. Minor releases will occur every month ([Semantic Versioning](https://semver.org/)). Major releases occur only when absolutely necessary.

## Layout

The GoBGP project adopts [Standard Go Project Layout](https://github.com/golang-standards/project-layout).

## Changing the gRPC API

If you change the gRPC API, generate `api/gobgp.pb.go` in the following way:

```bash
$ ./tools/grpc/genproto.sh
```

In order for the script to run, you'll need protoc (version 3.7.1) in your PATH.