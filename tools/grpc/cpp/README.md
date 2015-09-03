Here you could find nice examples for gobgpd API with C++ client.

I'm using Ubuntu 14.04 LTS x86_64.

For gRPC we need so much dependencies, please make coffee and be ready!

Install ProtoBuffers:
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

Install gRPC:
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
cd gobgp/api/cpp
cp ../gobgp.proto gobgp_api_client.proto
make
```

Let's run it:
```bash
./gobgp_api_client 
We received: Peer AS: 65001
Peer router id: 213.133.111.200
Peer flops: 0
BGP state: BGP_FSM_ESTABLISHED
```
