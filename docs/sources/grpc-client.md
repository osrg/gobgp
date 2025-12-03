# Managing GoBGP with Your Favorite Language

This page explains how to manage GoBGP with your favorite language. You can use any language supported by [gRPC](http://www.grpc.io/). This page gives an example in Python and C++.

## Contents

- [Prerequisite](#prerequisite)
- [Python](#python)
- [C++](#c)

## Prerequisite

We assume that you have the relevant tools installed to generate the server and client interface for your favorite language from proto files. Please refer to [the official docs of gRPC](http://www.grpc.io/docs/) for details.

## Python

### Generating Interface

You need to generate the server and client interface from the GoBGP proto files before running the examples. From the repository root:

```bash
$ python3 -m grpc_tools.protoc \
   -I proto \
   -I proto/api \
   --python_out=tools/grpc/python/api \
   --grpc_python_out=tools/grpc/python/api \
   proto/api/*.proto
$ ls tools/grpc/python/api/*_pb2.py
attribute_pb2.py  capability_pb2.py  common_pb2.py  extcom_pb2.py  gobgp_pb2.py  nlri_pb2.py
```

### Adding Path

[`tools/grpc/python/add_path.py`](https://github.com/osrg/gobgp/blob/master/tools/grpc/python/add_path.py)
shows an example for adding a route using the current GoBGP gRPC API (typed `NLRI` and `Attribute` messages on `GoBgpServiceStub`).
After generating the bindings, run the script from the `tools/grpc/python` directory and point `PYTHONPATH` to the generated modules.

```bash
$ cd tools/grpc/python
$ PYTHONPATH=$PYTHONPATH:./api python3 add_path.py
```

See if the route was added to the global rib.

```bash
$ gobgp g r
   Network              Next Hop             AS_PATH              Age        Attrs
*> 10.0.0.0/24          1.1.1.1              100 200              00:08:02   [{Origin: ?}]
```

### Adding BGP-SR policy

[`tools/grpc/python/sr_policy.py`](https://github.com/osrg/gobgp/blob/master/tools/grpc/python/sr_policy.py)
shows an example for advertising an SR Policy route via the same gRPC API. Customize the parameters at the bottom of the script if needed, then run it from `tools/grpc/python` after generating the bindings:

```bash
$ cd tools/grpc/python
$ PYTHONPATH=$PYTHONPATH:./api python3 sr_policy.py
```

## Result of injecting the SR policy

Once the sr policy is injected, gobgp will advertise it to the peers with SR Policy enabled address family. Below is the output collected from Nokia SROS router with enabled SR policy address family.

```log
A:R1# show router segment-routing sr-policies all color 100

===============================================================================
SR-Policies Path
===============================================================================
-------------------------------------------------------------------------------
Active          : Yes                   Owner           : bgp
Color           : 100
Head            : 0.0.0.0               Endpoint Addr   : 10.6.6.6
RD              : 2                     Preference      : 11
BSID            : 300004
TunnelId        : 917525                Age             : 7
Origin ASN      : 800                   Origin          : 10.100.1.201
NumReEval       : 0                     ReEvalReason    : none
NumActPathChange: 0                     Last Change     : 03/23/2022 11:05:48
Maintenance Policy: N/A

Path Segment Lists:
Segment-List    : 1                     Weight          : 12
S-BFD State     : Down                  S-BFD Transitio*: 0
Num Segments    : 2                     Last Change     : 03/22/2022 14:09:33
  Seg 1 Label   : 200002                State           : resolved-up
  Seg 2 Label   : 200006                State           : N/A

===============================================================================
* indicates that the corresponding row element may have been truncated.
```

## C++

### Generating Interface and Binary

Use [`tools/grpc/cpp/Makefile`](https://github.com/osrg/gobgp/blob/master/tools/grpc/cpp/Makefile).

```bash
$ cd tools/grpc/cpp
$ make
 ```

The above to generate the server and client interface and the binary to add a route by using `AddPath` API, ['tools/grpc/cpp/add_path.cc'](https://github.com/osrg/gobgp/blob/master/tools/grpc/cpp/add_path.cc).

### Adding Path

Let's run the binary.

```bash
$ ./add_path
```

See if the route was added to the global rib.

```bash
$ gobgp g r
   Network              Next Hop             AS_PATH              Age        Attrs
*> 10.0.0.0/24          1.1.1.1                                   00:13:26   [{Origin: i} {Communities: 0:100}]
```
