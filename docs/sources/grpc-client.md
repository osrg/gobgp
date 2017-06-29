# Managing GoBGP with Your Favorite Language

This page explains how to managing GoBGP with your favorite Language.
You can use any language supported by [gRPC](http://www.grpc.io/) (10
languages are supported now). This page gives an example in Python,
Ruby, C++, Node.js, and Java. It assumes that you use Ubuntu 16.04 (64bit).

## Contents

- [Prerequisite](#prerequisite)
- [Python](#python)
- [Ruby](#ruby)
- [C++](#cpp)
- [Node.js](#nodejs)
- [Java](#java)

## <a name="prerequisite"> Prerequisite
We assumes that you have finished installing `protoc` [protocol buffer](https://github.com/google/protobuf) compiler to generate stub server and client code and "protobuf runtime" for your favorite language.

Please refer to [the official docs of gRPC](http://www.grpc.io/docs/) for details.

## <a name="python"> Python

### Generating Stub Code

We need to generate stub code GoBGP at first.
```bash
$ cd $GOPATH/src/github.com/osrg/gobgp/tools/grpc/python
$ GOBGP_API=$GOPATH/src/github.com/osrg/gobgp/api
$ protoc  -I $GOBGP_API --python_out=. --grpc_out=. --plugin=protoc-gen-grpc=`which grpc_python_plugin` $GOBGP_API/gobgp.proto
```

### Get Neighbor

['tools/grpc/python/get_neighbor.py'](https://github.com/osrg/gobgp/blob/master/tools/grpc/python/get_neighbor.py) shows an example for getting neighbor's information.
Let's run this script.

```bash
$ python get_neighbor.py 172.18.0.2
BGP neighbor is 10.0.0.2, remote AS 65002
  BGP version 4, remote router ID
  BGP state = active, up for 0
  BGP OutQ = 0, Flops = 0
  Hold time is 0, keepalive interval is 0 seconds
  Configured hold time is 90, keepalive interval is 30 seconds
```

We got the neighbor information successfully.

## <a name="ruby"> Ruby

### Generating Stub Code

We need to generate stub code GoBGP at first.
```bash
$ cd $GOPATH/src/github.com/osrg/gobgp/tools/grpc/ruby
$ GOBGP_API=$GOPATH/src/github.com/osrg/gobgp/api
$ protoc  -I $GOBGP_API --ruby_out=. --grpc_out=. --plugin=protoc-gen-grpc=`which grpc_ruby_plugin` $GOBGP_API/gobgp.proto
```

### Get Neighbor

['tools/grpc/ruby/get_neighbor.py'](https://github.com/osrg/gobgp/blob/master/tools/grpc/ruby/get_neighbor.rb) shows an example for getting neighbor's information.
Let's run this script.

```bash
$ ruby -I . ./get_neighbors.rb 172.18.0.2
BGP neighbor is 10.0.0.2, remote AS 65002
	BGP version 4, remote route ID
	BGP state = active, up for 0
	BGP OutQ = 0, Flops = 0
	Hold time is 0, keepalive interval is 0 seconds
	Configured hold time is 90
```

## <a name="cpp"> C++

We use .so compilation with golang, please use only 1.5 or newer version of Go Lang.

['tools/grpc/cpp/gobgp_api_client.cc'](https://github.com/osrg/gobgp/blob/master/tools/grpc/cpp/gobgp_api_client.cc) shows an example for getting neighbor's information.

We provide ['tools/grpc/cpp/build.sh'](https://github.com/osrg/gobgp/blob/master/tools/grpc/cpp/build.sh) to build this sample code.
This script also generates stub codes and builds GoBGP shared library.

Let's build the sample code:
```bash
$ cd $GOPATH/src/github.com/osrg/gobgp/tools/grpc/cpp
$ bash build.sh
```

### Let's run it:
```bash
$ ./gobgp_api_client 172.18.0.2
BGP neighbor is: 10.0.0.2, remote AS: 1
	BGP version: 4, remote route ID
	BGP state = active, up for 0
	BGP OutQ = 0, Flops = 0
	Hold time is 0, keepalive interval is 0seconds
	Configured hold time is 90
BGP neighbor is: 10.0.0.3, remote AS: 1
	BGP version: 4, remote route ID
	BGP state = active, up for 0
	BGP OutQ = 0, Flops = 0
	Hold time is 0, keepalive interval is 0seconds
	Configured hold time is 90
```

## <a name="nodejs"> Node.js

### Example

Copy protocol definition.

```bash
$ cd $GOPATH/src/github.com/osrg/gobgp/tools/grpc/nodejs
$ ln -s $GOPATH/src/github.com/osrg/gobgp/api/gobgp.proto
```

['tools/grpc/nodejs/get_neighbor.js'](https://github.com/osrg/gobgp/blob/master/tools/grpc/nodejs/get_neighbors.js) shows an example to show neighbor information.
Let's run this:

```
$ node get_neighbors.js
BGP neighbor: 10.0.255.1 , remote AS: 65001
        BGP version 4, remote router ID: 10.0.255.1
        BGP state: BGP_FSM_ESTABLISHED , uptime: Wed Jul 20 2016 05:37:22 GMT+0900 (JST)
        BGP OutQ: 0 , Flops: 0
        Hold time: 90 , keepalive interval: 30 seconds
        Configured hold time: 90
BGP neighbor: 10.0.255.2 , remote AS: 65002
        BGP version 4, remote router ID: <nil>
        BGP state: BGP_FSM_ACTIVE , uptime: undefined
        BGP OutQ: 0 , Flops: 0
        Hold time: undefined , keepalive interval: undefined seconds
        Configured hold time: 90
```

## <a name="java"> Java
We can make a client in Java using [grpc-java](https://github.com/grpc/grpc-java).

### Install JDK:
We need to install JDK and we use Oracle JDK8 in this example.
```bash
$ sudo add-apt-repository ppa:webupd8team/java
$ sudo apt-get update
$ sudo apt-get install oracle-java8-installer
$ java -version
java version "1.8.0_72"
Java(TM) SE Runtime Environment (build 1.8.0_72-b15)
Java HotSpot(TM) 64-Bit Server VM (build 25.72-b15, mixed mode)
$ echo "export JAVA_HOME=/usr/lib/jvm/java-8-oracle" >> ~/.bashrc
$ source ~/.bashrc
```

### Create protobuf library for Java:
```bash
$ sudo apt-get install maven
$ cd ~/work/protobuf-3.0.0-beta-2/java
$ mvn package
...
[INFO]
[INFO] --- maven-bundle-plugin:3.0.1:bundle (default-bundle) @ protobuf-java ---
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time: 1:57.106s
[INFO] Finished at: Mon Feb 08 11:51:51 JST 2016
[INFO] Final Memory: 31M/228M
[INFO] ------------------------------------------------------------------------
$ ls ./target/proto*
./target/protobuf-java-3.0.0-beta-2.jar
```

### Clone grpc-java and build protoc plugin and other dependencies:
```bash
$ cd ~/work
$ git clone https://github.com/grpc/grpc-java.git
$ cd ./grpc-java
$ git checkout -b v0.12.0 v0.12.0
$ cd ./all
$ ../gradlew build
$ ls ../compiler/build/binaries/java_pluginExecutable/
protoc-gen-grpc-java
$ ls ./build/libs/grpc-all-0.12.0*
./build/libs/grpc-all-0.12.0-javadoc.jar  ./build/libs/grpc-all-0.12.0-sources.jar  ./build/libs/grpc-all-0.12.0.jar
```

### Generate stub classes:
```bash
$ cd $GOPATH/src/github.com/osrg/gobgp/tools/grpc
$ mkdir -p java/src
$ cd java
$ GOBGP_API=$GOPATH/src/github.com/osrg/gobgp/api
$ protoc --java_out=./src --proto_path="$GOBGP_API" $GOBGP_API/gobgp.proto
$ protoc --plugin=protoc-gen-grpc-java=$HOME/work/grpc-java/compiler/build/binaries/java_pluginExecutable/protoc-gen-grpc-java --grpc-java_out=./src --proto_path="$GOBGP_API" $GOBGP_API/gobgp.proto
$ ls ./src/gobgpapi/
Gobgp.java  GobgpApiGrpc.java
```

### Build sample client:

['tools/grpc/java/src/gobgp/example/GobgpSampleClient.java'](https://github.com/osrg/gobgp/blob/master/tools/grpc/java/src/gobgp/example/GobgpSampleClient.java) is an example to show neighbor information.

Let's build and run it. However we need to download and copy some dependencies beforehand.
```bash
$ cd $GOPATH/src/github.com/osrg/gobgp/tools/grpc/java
$ mkdir lib
$ cd lib
$ wget http://central.maven.org/maven2/com/google/guava/guava/18.0/guava-18.0.jar
$ wget http://central.maven.org/maven2/com/squareup/okhttp/okhttp/2.5.0/okhttp-2.5.0.jar
$ wget http://central.maven.org/maven2/com/squareup/okio/okio/1.6.0/okio-1.6.0.jar
$ cp ~/work/protobuf-3.0.0-beta-2/java/target/protobuf-java-3.0.0-beta-2.jar ./
$ cp ~/work/grpc-java/all/build/libs/grpc-all-0.12.0.jar ./
```

We are ready to build and run.
```bash
$ cd $GOPATH/src/github.com/osrg/gobgp/tools/grpc/java
$ mkdir classes
$ CLASSPATH=./lib/protobuf-java-3.0.0-beta-2.jar:./lib/grpc-all-0.12.0.jar:./lib/guava-18.0.jar:./lib/okhttp-2.5.0.jar:./lib/okio-1.6.0.jar:./classes
$ javac -classpath $CLASSPATH -d ./classes ./src/gobgpapi/*.java
$ javac -classpath $CLASSPATH -d ./classes ./src/gobgp/example/GobgpSampleClient.java
$ java -cp $CLASSPATH gobgp.example.GobgpSampleClient localhost
Feb 08, 2016 2:39:29 PM io.grpc.internal.TransportSet$1 run
INFO: Created transport io.grpc.okhttp.OkHttpClientTransport@ba4d54(localhost/127.0.0.1:8080) for localhost/127.0.0.1:8080
Feb 08, 2016 2:39:29 PM io.grpc.internal.TransportSet$TransportListener transportReady
INFO: Transport io.grpc.okhttp.OkHttpClientTransport@ba4d54(localhost/127.0.0.1:8080) for localhost/127.0.0.1:8080 is ready
BGP neighbor is 10.0.255.1, remote AS 65001
	BGP version 4, remote router ID <nil>
	BGP state = BGP_FSM_ACTIVE, up for 0
	BGP OutQ = 0, Flops = 0
	Hold time is 0, keepalive interval is 0 seconds
	Configured hold time is 90
```
