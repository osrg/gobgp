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

Here is an example for getting neighbor's information and we assumed that it's created in 'get_neighbor.py' under '$GOPATH/src/github.com/osrg/gobgp/tools/grpc/python'.
```python
import gobgp_pb2
import sys

from grpc.beta import implementations

_TIMEOUT_SECONDS = 10


def run(gobgpd_addr, neighbor_addr):
    channel = implementations.insecure_channel(gobgpd_addr, 50051)
    with gobgp_pb2.beta_create_GobgpApi_stub(channel) as stub:
        peer = stub.GetNeighbor(gobgp_pb2.Arguments(rf=4, name=neighbor_addr), _TIMEOUT_SECONDS)
        print("BGP neighbor is %s, remote AS %d" % (peer.conf.neighbor_address, peer.conf.peer_as))
        print("  BGP version 4, remote router ID %s" % (peer.conf.id))
        print("  BGP state = %s, up for %s" % (peer.info.bgp_state, peer.timers.state.uptime))
        print("  BGP OutQ = %d, Flops = %d" % (peer.info.out_q, peer.info.flops))
        print("  Hold time is %d, keepalive interval is %d seconds" % (peer.timers.state.negotiated_hold_time, peer.timers.state.keepalive_interval))
        print("  Configured hold time is %d, keepalive interval is %d seconds" % (peer.timers.config.hold_time, peer.timers.config.keepalive_interval))


if __name__ == '__main__':
    gobgp = sys.argv[1]
    neighbor = sys.argv[2]
    run(gobgp, neighbor)
```

We need to import gobgp_pb2 and call 'beta_create_GobgpApi_stub' in your code.

Let's run this script.

```bash
$ source ~/venv/bin/activate
(venv)$ python get_neighbor.py 10.0.255.1 10.0.0.1
BGP neighbor is 10.0.0.1, remote AS 65001
  BGP version 4, remote router ID 192.168.0.1
  BGP state = BGP_FSM_ESTABLISHED, up for 9042
  BGP OutQ = 0, Flops = 0
  Hold time is 30, keepalive interval is 10 seconds
  Configured hold time is 30, keepalive interval is 10 seconds

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

Here is an example for getting neighbor's information.
```ruby
require 'gobgp'
require 'gobgp_services'

host = 'localhost'
host = ARGV[0] if ARGV.length > 0

stub = Gobgpapi::GobgpApi::Stub.new("#{host}:50051")
arg = Gobgpapi::Arguments.new()
stub.get_neighbors(arg).each do |n|
    puts "BGP neighbor is #{n.conf.neighbor_address}, remote AS #{n.conf.peer_as}"
    puts "\tBGP version 4, remote route ID #{n.conf.id}"
    puts "\tBGP state = #{n.info.bgp_state}, up for #{n.timers.state.uptime}"
    puts "\tBGP OutQ = #{n.info.out_q}, Flops = #{n.info.flops}"
    puts "\tHold time is #{n.timers.state.hold_time}, keepalive interval is #{n.timers.state.keepalive_interval} seconds"
    puts "\tConfigured hold time is #{n.timers.config.hold_time}"
end
```

Let's run this script.

```bash
$ruby -I . ./get_neighbors.rb
BGP neighbor is 192.168.10.2, remote AS 65001
    BGP version 4, remote route ID <nil>
    BGP state = BGP_FSM_ACTIVE, up for 0
    BGP OutQ = 0, Flops = 0
    Hold time is 0, keepalive interval is 0 seconds
    Configured hold time is 90
BGP neighbor is 192.168.10.3, remote AS 65001
    BGP version 4, remote route ID <nil>
    BGP state = BGP_FSM_ACTIVE, up for 0
    BGP OutQ = 0, Flops = 0
    Hold time is 0, keepalive interval is 0 seconds
    Configured hold time is 90
```

## <a name="cpp"> C++

We use .so compilation with golang, please use only 1.5 or newer version of Go Lang.

Clone this repository and build API example:
```bash
export PATH="$PATH:/opt//grpc/bin:/opt/protobuf_3.0.0_alpha4/bin/"

cd /usr/src
git clone https://github.com/osrg/gobgp.git
cd gobgp/gobgp/lib
go build -buildmode=c-shared -o libgobgp.so *.go
cp libgobgp.h /usr/src/gobgp/tools/grpc/cpp
cp libgobgp.so /usr/src/gobgp/tools/grpc/cpp
cp /usr/src/gobgp/api/gobgp.proto /usr/src/gobgp/tools/grpc/cpp/gobgp_api_client.proto
cd /usr/src/gobgp/tools/grpc/cpp
make
```

### Let's run it:
```bash
LD_LIBRARY_PATH=".:/opt/grpc/lib:/opt/protobuf_3.0.0_alpha4/lib" ./gobgp_api_client

List of announced prefixes for route family: 65537

Prefix: 10.10.20.0/22
NLRI: {"nlri":{"prefix":"10.10.20.0/22"},"attrs":[{"type":1,"value":0},{"type":3,"nexthop":"0.0.0.0"}]}


List of announced prefixes for route family: 65669

Prefix: [destination:10.0.0.0/24][protocol: tcp][source:20.0.0.0/24]
NLRI: {"nlri":{"value":[{"type":1,"value":{"prefix":"10.0.0.0/24"}},{"type":3,"value":[{"op":129,"value":6}]},{"type":2,"value":{"prefix":"20.0.0.0/24"}}]},"attrs":[{"type":1,"value":0},{"type":14,"nexthop":"0.0.0.0","afi":1,"safi":133,"value":[{"value":[{"type":1,"value":{"prefix":"10.0.0.0/24"}},{"type":3,"value":[{"op":129,"value":6}]},{"type":2,"value":{"prefix":"20.0.0.0/24"}}]}]},{"type":16,"value":[{"type":128,"subtype":8,"value":"10:10"}]}]}
```

## <a name="nodejs"> Node.js

### Example

Copy protocol definition.

```bash
cp $GOPATH/src/github.com/osrg/gobgp/api/gobgp.proto .
```

Here is an example to show neighbor information.

```javascript
var grpc = require('grpc');
var api = grpc.load('gobgp.proto').gobgpapi;
var stub = new api.GobgpApi('localhost:50051', grpc.credentials.createInsecure());

stub.getNeighbor({}, function(err, neighbor) {
  neighbor.peers.forEach(function(peer) {
    if(peer.info.bgp_state == 'BGP_FSM_ESTABLISHED') {
      var date = new Date(Number(peer.timers.state.uptime)*1000);
      var holdtime = peer.timers.state.negotiated_hold_time;
      var keepalive = peer.timers.state.keepalive_interval;
    }

    console.log('BGP neighbor:', peer.conf.neighbor_address,
                ', remote AS:', peer.conf.peer_as);
    console.log("\tBGP version 4, remote router ID:", peer.conf.id);
    console.log("\tBGP state:", peer.info.bgp_state,
                ', uptime:', date);
    console.log("\tBGP OutQ:", peer.info.out_q,
                ', Flops:', peer.info.flops);
    console.log("\tHold time:", holdtime,
                ', keepalive interval:', keepalive, 'seconds');
    console.log("\tConfigured hold time:", peer.timers.config.hold_time);
  });
});
```

Let's run this:

```
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

### Create your own client and build it:
```bash
$ cd ~/go/src/github.com/osrg/gobgp/tools/grpc/java
$ mkdir -p src/gobgp/example
$ cd src/gobgp/example
$ vi GobgpSampleClient.java
```

```java
package gobgp.example;

import gobgpapi.Gobgp;
import gobgpapi.GobgpApiGrpc;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;

import java.util.Iterator;

public class GobgpSampleClient {

    private final GobgpApiGrpc.GobgpApiBlockingStub blockingStub;

    public GobgpSampleClient(String host, int port) {
        ManagedChannel channel = ManagedChannelBuilder.forAddress(host, port).usePlaintext(true).build();
        this.blockingStub = GobgpApiGrpc.newBlockingStub(channel);
    }

    public void getNeighbors(){

        Gobgp.Arguments request = Gobgp.Arguments.newBuilder().build();

        for(Iterator<Gobgp.Peer> iterator = this.blockingStub.getNeighbors(request); iterator.hasNext(); ) {
            Gobgp.Peer p = iterator.next();
            Gobgp.PeerConf conf = p.getConf();
            Gobgp.PeerState state = p.getInfo();
            Gobgp.Timers timer = p.getTimers();

            System.out.printf("BGP neighbor is %s, remote AS %d\n", conf.getNeighborAddress(), conf.getPeerAs());
            System.out.printf("\tBGP version 4, remote router ID %s\n", conf.getId());
            System.out.printf("\tBGP state = %s, up for %d\n", state.getBgpState(), timer.getState().getUptime());
            System.out.printf("\tBGP OutQ = %d, Flops = %d\n", state.getOutQ(), state.getFlops());
            System.out.printf("\tHold time is %d, keepalive interval is %d seconds\n",
                    timer.getState().getHoldTime(), timer.getState().getKeepaliveInterval());
            System.out.printf("\tConfigured hold time is %d\n", timer.getConfig().getHoldTime());

        }
    }

    public static void main(String args[]){
        new GobgpSampleClient(args[0], 8080).getNeighbors();
    }

}

```

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
