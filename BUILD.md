# Development Guide

## Building the development environment

You need a working [Go environment](https://golang.org/doc/install) (1.16 or newer).

```bash
$ git clone git://github.com/osrg/gobgp
$ cd gobgp && go mod download
```

Now ready to modify the code and build two binaries, `cmd/gobgp` and `cmd/gobgpd`.

## Getting your code into GoBGP

### Creating a commit

Separate each **logical change** into a separate commit.

There is no strict size limit for a single commit. This is because a simple large commit that just moves packages cannot be compared in terms of potential risk with a commit that modifies fundamental BGP functionality. However, if you're changing fundamental functionality, keep in mind that the larger the commit, the less likely it is to be merged.

A Git commit message should include enough information to explain why the change is necessary, in order to convince the maintainer to merge it.

### Submitting a pull request

Every commit that is merged must pass continuous integration (CI) checks. For this reason, each pull request should ideally contain only one commit. This is because if you push multiple commits at once and create a pull request, some of the intermediate commits may not be tested by CI.

There are exceptions where a pull request may include multiple commits, especially if the risk of breaking the code is considered low. For example, one commit may add a new feature, and a second commit may add unit tests or benchmarks for that feature. Another example is when adding a serializer and decoder for a new address family—such commits may also be treated as exceptions, since they are unlikely to affect existing GoBGP users. However, this does not apply to changes that affect fundamental parts of the code used by all users.

Please keep in mind that each pull request should represent a single logical change. If a commit has a valid standalone reason to be merged into GoBGP, it should be treated as a single logical change and submitted in its own pull request, rather than being grouped together with other commits.

If you're working on a large change, it may sometimes be unavoidable to include multiple commits in a single pull request. However, if you're modifying code in fundamental parts of the BGP implementation, please try to keep the number of commits to four or fewer, excluding tests. If the pull request exceeds that, the likelihood of it being reviewed and merged becomes significantly lower. So please take the time to split your work into as many logical and self-contained pieces as possible.

### Responding to review comments

Please treat your pull request as "frozen" once it has been created. Adding new commits or modifying the code unprompted makes review much harder. Only changes based on review comments should be made.

During the review process, you may discover that changes you didn’t originally anticipate are required. For example, modifying code X in response to review comments may reveal the need to adjust code B as well. Even in such cases, if the change to code B can be considered a separate logical change, it is expected that you do not add a new commit to the existing pull request. Instead, you should create a new pull request for the code B change and get it merged first.

## Testing

Before sending pull request, please make sure that your changes have passed both unit and integration tests. Check out [the tests](https://github.com/osrg/gobgp/blob/master/.github/workflows/ci.yml) triggered by a pull request. If you need to debug the integration tests, it's a good idea to run them [locally](https://github.com/osrg/gobgp/blob/master/test/scenario_test/README.md).

## Changing the gRPC API

To generate gRPC code from Protobuf definitions, first make sure you have [buf](https://github.com/bufbuild/buf) installed.

Then run the following:

```bash
$ cd proto
$ buf generate
```

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
	"-X github.com/osrg/gobgp/v4/internal/pkg/version.COMMIT=`git rev-parse --short HEAD` \
	 -X github.com/osrg/gobgp/v4/internal/pkg/version.METADATA="date.`date "+%Y%m%d"`" \
	 -X github.com/osrg/gobgp/v4/internal/pkg/version.IDENTIFIER=alpha"
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
