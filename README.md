# GoBGP: BGP implementation in Go <p align="right">[![Build Status](https://travis-ci.org/osrg/gobgp.svg?branch=master)](https://travis-ci.org/osrg/gobgp/builds)</p>

## Introduction

GoBGP is an open source BGP implementation designed from scratch for
modern environment and implemented in a modern programming language,
[the Go Programming Language](http://golang.org/).

## Getting started

Installing GoBGP is quite easy (only two commands!):

```bash
$ go get github.com/osrg/gobgp/gobgpd
$ go get github.com/osrg/gobgp/gobgp
```

No dependency hell (library, package, etc) thanks to Go.

## Documentation

### Using GoBGP
 * [Getting Started](https://github.com/osrg/gobgp/blob/master/docs/sources/getting-started.md)
 * CLI
  * [Typical operation examples](https://github.com/osrg/gobgp/blob/master/docs/sources/cli-operations.md)
  * [Complete syntax](https://github.com/osrg/gobgp/blob/master/docs/sources/cli-command-syntax.md)
 * [Route Server](https://github.com/osrg/gobgp/blob/master/docs/sources/route-server.md)
 * [Route Reflector](https://github.com/osrg/gobgp/blob/master/docs/sources/route-reflector.md)
 * [Policy](https://github.com/osrg/gobgp/blob/master/docs/sources/policy.md)
 * [EVPN](https://github.com/osrg/gobgp/blob/master/docs/sources/evpn.md)
 * [MRT](https://github.com/osrg/gobgp/blob/master/docs/sources/mrt.md)
 * [Flowspec](https://github.com/osrg/gobgp/blob/master/docs/sources/flowspec.md)
 * [RPKI](https://github.com/osrg/gobgp/blob/master/docs/sources/rpki.md)
 * [Managing GoBGP with your favorite language](https://github.com/osrg/gobgp/blob/master/docs/sources/grpc-client.md)
 
## Community, discussion and support

We have the [the mailing
list](https://lists.sourceforge.net/lists/listinfo/gobgp-devel) for
questions, discussion, suggestions, etc.

You have code or documentation for GoBGP? Awesome! Send a pull
request. No CLA, board members, governance, or other mess.

## Licensing

GoBGP is licensed under the Apache License, Version 2.0. See
[LICENSE](https://github.com/osrg/gobgp/blob/master/LICENSE) for the full
license text.
