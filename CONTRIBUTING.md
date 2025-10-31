# Development Guide

## Building the development environment

```bash
$ git clone https://github.com/osrg/gobgp.git
$ cd gobgp && go mod download
```

Now ready to modify the code and build two binaries, `cmd/gobgp` and `cmd/gobgpd`.

## Design Considerations

### OpenConfig, gRPC, and native APIs

In GoBGP, multiple structures are defined to represent the same concept, in order to support multiple APIs. For example, to represent a peer, there are three different structures: `config.Neighbor`, `api.Peer`, and `apiutil.Peer`.

`config.Neighbor` is the structure used by OpenConfig and is generated from YANG files. OpenConfig is a standard that aims to make the configuration and management of vendor-neutral network devices programmable. GoBGP uses OpenConfig as its configuration file API. Since OpenConfig defines data structures in a generic, language-agnostic way, the most suitable Go data types are not always used. Although it is possible to exert some control over how certain types are mapped to Go, YANG can define constructs such as union types that Go cannot natively represent. In addition, the data layout is designed to be human-readable, which may not always be optimal for the computer in terms of concurrency and locking.

`api.Peer` is the structure used for gRPC and is generated from .proto files. gRPC is the primary API of GoBGP; all control operations can be performed through gRPC. The CLI is also implemented using gRPC. Similar to OpenConfig, gRPC defines data structures with generic, language-independent types to ensure support across different programming languages. Unlike OpenConfig, however, there is no way to customize how these types are converted into Go types, which makes it even less convenient. As a result, the most optimal Go types are not always used. For example, a peer’s IP address is represented as a string rather than the more suitable netip.Addr type.

`apiutil.Peer` is what we call the “native API.” While gRPC APIs have the advantage of supporting multiple programming languages, they also come with significant overhead. The native API, on the other hand, is a lightweight API designed specifically for Go. It defines data structures using the most appropriate Go types, such as netip.Addr, to achieve better efficiency and usability.

Finally, although it is not exposed as a public API, the `server.peer` structure also represents a peer. This structure is used internally by GoBGP to manage peers. In order to avoid the overhead of defining a new structure from scratch, we reused the OpenConfig structure within this internal component. However, this turned out to be a major design mistake. As described above, OpenConfig structures do not necessarily use the most suitable Go data types.
For example, GoBGP currently uses strings to represent peer addresses in many internal places. This is a direct consequence of relying on OpenConfig structures internally. Over time, these structures should be gradually replaced with more appropriate native Go types.
Therefore, when introducing new internal structures, we should avoid using OpenConfig types and instead define new data structures that are optimized for Go.

### Memory Usage

If your new feature requires adding members to existing data structures or creating new structures that will increase memory usage, please consider how memory consumption will change in relation to increases in both route count and peer count.

For instance, imagine an environment where 10 peers are connected, each carrying full routes. For the sake of simplicity in calculations, let's assume full routes consist of 1 million routes.

If you add an 8-byte member to the Path structure, since the number of Path structures increases proportionally to both the number of routes and the number of peers, this would result in approximately 80MB increase in memory usage."

If you add an 8-byte member to the Destination struture, since the number of Destiation structures increases proportionally to the number of routes, this would result in approximately 8MB increase in memory usage.

If you add an 8-byte member to the Peer struture, since the number of Peer structures increases proportionally to the number of peers, this would result in approximately 80 bytes increase in memory usage.

Please be cautious about changes that increase memory usage proportionally to the number of routes (and be even more cautious about changes that are proportional to both the number of routes and the number of peers). The benefits must justify such increases (for example, huge performance improvement).

### Locking

GoBGP uses a two-level mutex design to manage concurrent access to shared state. The server-level mutex (`sharedData.mu`) protects global state such as the RIB tables and peer map. All management operations (API calls) and FSM event processing which access to those data are serialized through this mutex. The per-peer mutex (`peer.fsm.lock`) protects individual peer state including configuration and capability negotiation, using a read-write lock to allow concurrent reads while maintaining exclusive writes.

To prevent deadlocks, always follow this lock ordering rule: **acquire the server-level mutex first, then acquire peer-level locks if needed**. Never acquire the server-level mutex while holding a peer-level lock. When modifying code that involves locking, ensure critical sections are kept as short as possible, and consider copying data before releasing locks to minimize contention. The server-level mutex is the primary scalability bottleneck, so any changes affecting lock duration or frequency should be carefully evaluated for performance impact, especially in environments with many peers or large routing tables.

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
