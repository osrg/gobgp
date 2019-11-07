# Managing GoBGP with Your Favorite Language

This page explains how to managing GoBGP with your favorite Language. You can use any language supported by [gRPC](http://www.grpc.io/) (10 languages are supported now). This page gives an example in Python and C++.

## Contents

- [Prerequisite](#prerequisite)
- [Python](#python)
- [C++](#cpp)

## Prerequisite

We assumes that you have the relevant tools installed to generate the server and client interface for your favorite language from proto files. Please refer to [the official docs of gRPC](http://www.grpc.io/docs/) for details.

## Python

### Generating Interface

You need to generate the server and client interface from GoBGP proto files at first.

```bash
$ python -m grpc_tools.protoc -I./ --python_out=. --grpc_python_out=. *.proto
$ ls *.py
attribute_pb2.py  attribute_pb2_grpc.py  capability_pb2.py  capability_pb2_grpc.py  gobgp_pb2.py  gobgp_pb2_grpc.py
```

### Adding Path

[`tools/grpc/python/add_path.py`](https://github.com/osrg/gobgp/blob/master/tools/grpc/python/add_path.py)
shows an example for adding a route.
Let's run this script.

```bash
$ PYTHONPATH=$PYTHONPATH:. python add_path.py
```

See if the route was added to the global rib.

```bash
$ gobgp g r
   Network              Next Hop             AS_PATH              Age        Attrs
*> 10.0.0.0/24          1.1.1.1              100 200              00:08:02   [{Origin: ?}]
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

See if he route was added to the global rib.

```bash
$ gobgp g r
   Network              Next Hop             AS_PATH              Age        Attrs
*> 10.0.0.0/24          1.1.1.1                                   00:13:26   [{Origin: i} {Communities: 0:100}]
```
