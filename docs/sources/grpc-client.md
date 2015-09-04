# Managing GoBGP with Your Favorite Language

This page explains how to managing GoBGP with your favorite Language.
You can use any language supported by [gRPC](http://www.grpc.io/) (10
languages are supported now). This page gives an example in Python,
Ruby, and C++. It assumes that you use Ubuntu 14.04 (64bit).

## Contents

- [Python](#python)
- [Ruby](#ruby)
- [C++](#cpp)

## <a name="python"> Python

### Installing LinuxBrew

We use LinuxBrew to simplify the instruction.
```bash
$ sudo apt-get update
$ sudo apt-get install -y build-essential curl git python-dev python-pip m4 ruby
$ ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/linuxbrew/go/install)"
$ export PATH=$HOME/.linuxbrew/bin:$PATH
$ brew doctor
```
It's useful to add '$HOME/.linuxbrew/bin' to your PATH environment variable.

And then add configuration to load libs under '.linuxbrew'.
```
$ echo "$HOME/.linuxbrew/lib" | sudo tee /etc/ld.so.conf.d/grpc.conf
$ sudo ldconfig
```

### Installing gRPC and Python Libraries

We install gRPC and python liblaries in python virtual environment by using LinuxBrew.
These steps are based on [gRPC HomeBrew](https://github.com/grpc/homebrew-grpc).

```bash
$ sudo apt-get update
$ sudo apt-get install python-virtualenv
$ cd $GOPATH/src/github.com/osrg/gobgp/tools/grpc/python
$ virtualenv venv
$ source ./venv/bin/activate
$ curl -fsSL https://goo.gl/getgrpc | bash -s python
$ sudo ldconfig
```

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

_TIMEOUT_SECONDS = 10


def run(gobgpd_addr, neighbor_addr):
    with gobgp_pb2.early_adopter_create_Grpc_stub(gobgpd_addr, 8080) as stub:
        peer = stub.GetNeighbor(gobgp_pb2.Arguments(rf=4, name=neighbor_addr), _TIMEOUT_SECONDS)
        print("BGP neighbor is %s, remote AS %d" % (peer.conf.remote_ip, peer.conf.remote_as))
        print("  BGP version 4, remote router ID %s" % ( peer.conf.id))
        print("  BGP state = %s, up for %s" % ( peer.info.bgp_state, peer.info.uptime))
        print("  BGP OutQ = %d, Flops = %d" % (peer.info.out_q, peer.info.flops))
        print("  Hold time is %d, keepalive interval is %d seconds" % ( peer.info.negotiated_holdtime, peer.info.keepalive_interval))
        print("  Configured hold time is %d, keepalive interval is %d seconds" % ( peer.conf.holdtime, peer.conf.keepalive_interval))
        print("")

if __name__ == '__main__':
    gobgp = sys.argv[1]
    neighbor = sys.argv[2]
    run(gobgp, neighbor)
```

We need to import gobgp_pb2 and call 'early_adopter_create_Grpc_stub' in your code.

Let's run this script.

```bash
$ source ./venv/bin/activate
(venv)$ python get_neighbor.py 10.0.255.1 10.0.0.1
BGP neighbor is 10.0.0.1, remote AS 65001
  BGP version 4, remote router ID 192.168.0.1
  BGP state = BGP_FSM_ESTABLISHED, up for 9042
  BGP OutQ = 0, Flops = 0
  Hold time is 30, keepalive interval is 10 seconds
  Configured hold time is 30, keepalive interval is 10 seconds

D0821 12:31:07.821508149   91029 iomgr.c:119]                Waiting for 1 iomgr objects to be destroyed and executing final callbacks

```

We got neighbor information successfully.

## <a name="ruby"> Ruby

### Installing LinuxBrew

See [python](#python).


### Installing gRPC and Ruby Libraries

```bash
$ curl -fsSL https://goo.gl/getgrpc | bash -s ruby
$ sudo ldconfig
```

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

stub = Api::Grpc::Stub.new("#{host}:8080")
arg = Api::Arguments.new()
stub.get_neighbors(arg).each do |n|
    puts "BGP neighbor is #{n.conf.remote_ip}, remote AS #{n.conf.remote_as}"
    puts "\tBGP version 4, remote route ID #{n.conf.id}"
    puts "\tBGP state = #{n.info.bgp_state}, up for #{n.info.uptime}"
    puts "\tBGP OutQ = #{n.info.out_q}, Flops = #{n.info.flops}"
    puts "\tHold time is #{n.info.negotiated_holdtime}, keepalive interval is #{n.info.keepalive_interval} seconds"
    puts "\tConfigured hold time is #{n.conf.holdtime}"
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
D0827 18:43:24.628846574    3379 iomgr.c:119] Waiting for 1 iomgr objects to be destroyed and executing final callbacks
```

## <a name="cpp"> C++

For gRPC we need so much dependencies, please make coffee and be ready!

### Install ProtoBuffers:
```bash
apt-get update
apt-get install -y gcc make autoconf automake git libtool g++ curl

cd /usr/src
wget https://github.com/google/protobuf/archive/v3.0.0-alpha-4.tar.gz
tar -xf v3.0.0-alpha-4.tar.gz
cd protobuf-3.0.0-alpha-4/
./autogen.sh
./configure --prefix=/opt/protobuf_3.0.0_alpha4
make -j 4
make install
```

### Install gRPC:
```bash
apt-get update
apt-get install -y gcc make autoconf automake git libtool g++ python-all-dev python-virtualenv

cd /usr/src/
git clone https://github.com/grpc/grpc.git
cd grpc
git submodule update --init
make -j 4
make install prefix=/opt/grpc
```

Add libs to the system path:
```bash
echo "/opt/grpc/lib" > /etc/ld.so.conf.d/grpc.conf
echo "/opt/protobuf_3.0.0_alpha4/lib" > /etc/ld.so.conf.d/protobuf.conf
ldconfig
```

Clone this repository and build API example:
```bash
export PATH="$PATH:/opt//grpc/bin:/opt/protobuf_3.0.0_alpha4/bin/"

cd /usr/src
git clone https://github.com/osrg/gobgp.git
cp gobgp/api/gobgp.proto gobgp/tools/grpc/cpp/gobgp_api_client.proto
cd gobgp/tools/grpc/cpp
make
```

### Let's run it:
```bash
./gobgp_api_client
We received: Peer AS: 65001
Peer router id: 213.133.111.200
Peer flops: 0
BGP state: BGP_FSM_ESTABLISHED
```
