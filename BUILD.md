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

## Versioning

GoBGP has a internal module for version information.
```internal/pkg/version/version.go``` defines the following variables

```MAJOR``` ```MINOR``` ```PATCH``` these constants are for the Semantic Versioning scheme.
These will be updated upon release by maintainer.

There is also two more variables that are ment to be changed by ldflags;

```TAG``` is supposed to be used to denote which branch the build is based upon.
```SHA``` is supposed to be used to inform about which git sha sum the build is based on.

### Examples

A normal release version of GoBGP Version 2.5.0 should should have;

```golang
const MAJOR uint = 2
const MINOR uint = 5
const PATCH uint = 0
```

If you have a non-standard release and want to have more build information there is some flags to be used.
`COMMIT`, `IDENTIFIER` and `METADATA`.

```bash
go build -ldflags \
	"-X github.com/osrg/gobgp/internal/pkg/version.COMMIT=`git rev-parse --short HEAD` \
	 -X github.com/osrg/gobgp/internal/pkg/version.METADATA="date.`date "+%Y%m%d"`" \
	 -X github.com/osrg/gobgp/internal/pkg/version.IDENTIFIER=alpha"
```

This will produce a version number of

```2.5.0-alpaha+commit.XXXYYYZZ.date.20190526```

## Layout

The GoBGP project adopts [Standard Go Project Layout](https://github.com/golang-standards/project-layout).

## Changing the gRPC API

If you change the gRPC API, generate `api/gobgp.pb.go` in the following way:

```bash
$ ./tools/grpc/genproto.sh
```

In order for the script to run, you'll need protoc (version 3.7.1) in your PATH.
