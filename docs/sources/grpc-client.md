# Managing GoBGP with Your Favorite Language

This page explains how to create your own GoBGP client.
You can create a client using gRPC in several languages that you choose.
Currently there are instructions for making a client in Python and Ruby in this page.
It assumes that you are on Ubuntu 14.04(64bit).

## Python

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

