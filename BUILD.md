# Development Guide

## Building the development environment

You need a working [Go environment](https://golang.org/doc/install) (1.16 or newer).

```bash
$ git clone git://github.com/osrg/gobgp
$ cd gobgp && go mod download
```

Now ready to modify the code and build two binaries, `cmd/gobgp` and `cmd/gobgpd`.

## Testing

Before sending pull request, please make sure that your changes have passed both unit and integration tests. Check out [the tests](https://github.com/osrg/gobgp/blob/master/.github/workflows/ci.yml) triggered by a pull request. If you need to debug the integration tests, it's a good idea to run them [locally](https://github.com/osrg/gobgp/blob/master/test/scenario_test/README.md).

## Changing the gRPC API

If you change the gRPC API, generate `api/*.pb.go` in the following way:

```bash
$ ./tools/grpc/genproto.sh
```

In order for the script to run, you'll need protoc (version 3.19.1) in your PATH.

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
	"-X github.com/osrg/gobgp/v3/internal/pkg/version.COMMIT=`git rev-parse --short HEAD` \
	 -X github.com/osrg/gobgp/v3/internal/pkg/version.METADATA="date.`date "+%Y%m%d"`" \
	 -X github.com/osrg/gobgp/v3/internal/pkg/version.IDENTIFIER=alpha"
```

This will produce a version number of

```3.0.0-alpaha+commit.XXXYYYZZ.date.20211209```

## Layout

The GoBGP project adopts [Standard Go Project Layout](https://github.com/golang-standards/project-layout).

## Fuzzing

Run [Go Fuzzing](https://go.dev/security/fuzz)

```bash
go test -fuzz=FuzzParseRTR                      $PWD/pkg/packet/rtr
go test -fuzz=FuzzParseBMPMessage               $PWD/pkg/packet/bmp
go test -fuzz=FuzzParseBGPMessage               $PWD/pkg/packet/bgp
go test -fuzz=FuzzParseLargeCommunity           $PWD/pkg/packet/bgp
go test -fuzz=FuzzParseFlowSpecComponents       $PWD/pkg/packet/bgp
go test -fuzz=FuzzMRT                           $PWD/pkg/packet/mrt
go test -fuzz=FuzzZapi                          $PWD/internal/pkg/zebra
```
