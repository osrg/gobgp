# Managing GoBGP with Your Favorite Language

This page explains how to managing GoBGP with your favorite Language. You can use any language supported by [gRPC](http://www.grpc.io/) (10 languages are supported now). This page gives an example in Python and C++.

## Contents

- [Prerequisite](#prerequisite)
- [Python](#python)
- [C++](#cpp)

## Prerequisite

We assumes that you have the relevant tools installed to generate the server and client interface for your favorite language from proto files. Please refer to [the official docs of gRPC](http://www.grpc.io/docs/) for details.

## Python

### Fix paths

Python uses different module paths, we should apply this patch first:

```
index 4cf844f..7bf9452 100644
--- a/api/attribute.proto
+++ b/api/attribute.proto
@@ -21,7 +21,7 @@

 syntax = "proto3";

-import "any/any.proto";
+import "google/protobuf/any.proto";
 import "gobgp.proto";

 package gobgpapi;
diff --git a/api/gobgp.proto b/api/gobgp.proto
index b61b475..52dd9da 100644
--- a/api/gobgp.proto
+++ b/api/gobgp.proto
@@ -21,9 +21,9 @@

 syntax = "proto3";

-import "any/any.proto";
-import "empty/empty.proto";
-import "timestamp/timestamp.proto";
+import "google/protobuf/any.proto";
+import "google/protobuf/empty.proto";
+import "google/protobuf/timestamp.proto";

 package gobgpapi;

```

You can apply it this way:

```
git apply python.patch
```

### Generating Interface

Next you need to generate the server and client interface from GoBGP proto files, create folder and generate them:

```bash
$ mkdir ./python_interfaces
$ python -m grpc_tools.protoc -I./api --python_out=./python_interfaces/ \
--grpc_python_out=./python_interfaces/ \
api/gobgp.proto api/attribute.proto api/capability.proto
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
