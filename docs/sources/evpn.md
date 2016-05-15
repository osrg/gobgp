# Ethernet VPN (EVPN)

This page explains an configuration for EVPN. Note that the feature is
still very experimental.

## Contents

- [BaGpipe](#bagpipe)
- [YABGP](#yabgp)

## <a name="bagpipe"> BaGPipe

This example uses [BaGPipe
BGP](https://github.com/Orange-OpenSource/bagpipe-bgp). GoBGP receives
routes from one BaGPipe peer and advertises it to another BaGPipe peer.

If you don't want to install [BaGPipe
BGP](https://github.com/Orange-OpenSource/bagpipe-bgp) by hand, you can use [Our BaGPipe BGP Docker
image](https://registry.hub.docker.com/u/yoshima/bagpipe-bgp/).

### Configuration

BaGPipe supports only iBGP. GoBGP peer connects to two BaGPipe
peers. Two BaGPipe peers are not connected. It's incorrect from the
perspective of BGP but this example just shows two OSS BGP
implementations can interchange EVPN messages.

```toml
[global.config]
  as = 64512
  router-id = "192.168.255.1"

[[neighbors]]
[neighbors.config]
  neighbor-address = "10.0.255.1"
  peer-as = 64512
[[neighbors.afi-safis]]
  [neighbors.afi-safis.config]
  afi-safi-name = "l2vpn-evpn"

[[neighbors]]
[neighbors.config]
  neighbor-address = "10.0.255.2"
  peer-as = 64512
[[neighbors.afi-safis]]
  [neighbors.afi-safis.config]
  afi-safi-name = "l2vpn-evpn"
```

The point is that route families to be advertised need to be
specified. We expect that many people are not familiar with [BaGPipe
BGP](https://github.com/Orange-OpenSource/bagpipe-bgp), the following
is our configuration files.

```bash
bagpipe-peer1:/etc/bagpipe-bgp# cat bgp.conf
[BGP]
local_address=10.0.255.1
peers=10.0.255.254
my_as=64512
enable_rtc=True

[API]
api_host=localhost
api_port=8082

[DATAPLANE_DRIVER_IPVPN]
dataplane_driver = DummyDataplaneDriver

[DATAPLANE_DRIVER_EVPN]
dataplane_driver = DummyDataplaneDriver
```
10.0.255.254 is GoBGP peer's address.

### Advertising EVPN route

As you expect, the RIBs at 10.0.255.2 peer has nothing.

```bash
bagpipe-peer2:~# bagpipe-looking-glass bgp routes
match:IPv4/mpls-vpn,*: -
match:IPv4/rtc,*: -
match:L2VPN/evpn,*: -
```

Let's advertise something from 10.0.255.1 peer.

```bash
bagpipe-peer1:~# bagpipe-rest-attach --attach --port tap42 --mac 00:11:22:33:44:55 --ip 11.11.11.1 --gateway-ip 11.11.11.254 --network-type evpn --rt 65000:77
```

Now the RIBs at 10.0.255.2 peer has the above route. The route was interchanged via GoBGP peer.
```bash
bagpipe-peer2:~# bagpipe-looking-glass bgp routes
match:IPv4/mpls-vpn,*: -
match:IPv4/rtc,*: -
match:L2VPN/evpn,*:
  * EVPN:Multicast:[rd:10.0.255.1:1][etag:178][10.0.255.1]:
      attributes:
        next_hop: 10.0.255.1
        pmsi_tunnel: PMSITunnel:IngressReplication:0:[0]:[10.0.255.1]
        extended_community: [ target:65000:77 Encap:VXLAN ]
      afi-safi: L2VPN/evpn
      source: BGP-10.0.255.254/192.168.255.1 (...)
      route_targets:
        * target:65000:77
  * EVPN:MACAdv:[rd:10.0.255.1:1][esi:-][etag:178][00:11:22:33:44:55][11.11.11.1][label:0]:
      attributes:
        next_hop: 10.0.255.1
        extended_community: [ target:65000:77 Encap:VXLAN ]
      afi-safi: L2VPN/evpn
      source: BGP-10.0.255.254/192.168.255.1 (...)
      route_targets:
        * target:65000:77
```

## <a name="yabgp"> YABGP

Just like the last example, this example uses [YABGP](https://github.com/smartbgp/yabgp). GoBGP receives
routes from one YABGP peer and advertises it to another YABGP peer.

### Configuration

Gobgp configuration:

```toml
[global.config]
as = 100
router-id = "192.168.1.2"
local-address-list = ["10.79.45.72"]

[[neighbors]]
[neighbors.config]
neighbor-address = "10.75.44.10"
peer-as = 300
[[neighbors.afi-safis]]
[neighbors.afi-safis.config]
afi-safi-name = "l2vpn-evpn"
[neighbors.transport.config]
local-address = "10.79.45.72"
[neighbors.ebgp-multihop.config]
enabled = true

[[neighbors]]
[neighbors.config]
neighbor-address = "10.75.44.11"
peer-as = 200
[[neighbors.afi-safis]]
[neighbors.afi-safis.config]
afi-safi-name = "l2vpn-evpn"
[neighbors.transport.config]
local-address = "10.79.45.72"
[neighbors.ebgp-multihop.config]
enabled = true
```

`10.75.44.10` and `10.75.44.11` is the address of YABGP peers. We start two YABGP agents like this:

```bash
python yabgp/bin/yabgpd --bgp-local_as=300 --bgp-remote_addr=10.79.45.72 --bgp-remote_as=100 --bgp-local_addr=10.75.44.10 --bgp-afi_safi=evpn
```
``` bash
python yabgp/bin/yabgpd --bgp-local_as=200 --bgp-remote_addr=10.79.45.72 --bgp-remote_as=100 --bgp-local_addr=10.75.44.11 --bgp-afi_safi=evpn
```

From gobgp CMD:

``` bash
$ gobgp neighbor
Peer              AS  Up/Down State       |#Advertised Received Accepted
10.75.44.10      300 00:01:23 Establ      |          0        0        0
10.75.44.11      200 00:02:26 Establ      |          0        0        0
```

### Advertising EVPN route

We can advertise EVPN routes from YABGP 10.75.44.11 through its REST API,
the `Authorization` header is `admin/admin`, and the `Content-Type` is `application/json`.

``` bash
POST http://10.75.44.11:8801/v1/peer/10.79.45.72/send/update
```


We will run this API four times, each time's POST data is:

EVPN type 1:

``` json
{
    "attr":{
        "1": 0, 
        "2": [], 
        "5": 100, 
        "14": {
            "afi_safi": [25, 70],
            "nexthop": "10.75.44.254",
            "nlri": [{
                "type": 1,
                "value": {
                    "rd": "1.1.1.1:32867",
                    "esi": 0,
                    "eth_tag_id": 100,
                    "label": [10]
                }
            }]},
        "16":[[1537, 0, 500]]
}}
```

EVPN type 2:

``` json
{
    "attr":{
        "1": 0, 
        "2": [], 
        "5": 100, 
        "14": {
            "afi_safi": [25, 70],
            "nexthop": "10.75.44.254",
            "nlri": [
                {
                    "type": 2,
                    "value": {
                        "eth_tag_id": 108,
                        "ip": "11.11.11.1",
                        "label": [0],
                        "rd": "172.17.0.3:2",
                        "mac": "00-11-22-33-44-55",
                        "esi": 0}}]},
        "16":[[1536, 1, 500]]
}}
```

EVPN type 3:

``` json
{
    "attr":{
        "1": 0, 
        "2": [], 
        "5": 100, 
        "14": {
            "afi_safi": [25, 70],
            "nexthop": "10.75.44.254",
            "nlri": [
                {
                    "type": 3,
                    "value": {
                        "rd": "172.16.0.1:5904",
                        "eth_tag_id": 100,
                        "ip": "192.168.0.1"
                    }
                }
            ]
        }
}}
```
EVPN type 4:

``` json
{
    "attr":{
        "1": 0, 
        "2": [], 
        "5": 100, 
        "14": {
            "afi_safi": [25, 70],
            "nexthop": "10.75.44.254",
            "nlri": [
                {
                    "type": 4,
                    "value": {
                        "rd": "172.16.0.1:8888",
                        "esi": 0,
                        "ip": "192.168.0.1"
                    }
                }
            ]
        },
         "16":[[1538, "00-11-22-33-44-55"]]
}}
```
GoBGP will received these four routes and readvertise them to peer 10.75.44.10

``` bash
$ gobgp monitor adj-in
[ROUTE] [type:A-D][rd:1.1.1.1:32867][esi:single-homed][etag:100][label:161] via 10.75.44.254 aspath [] attrs [{Extcomms: [esi-label: 8001]} {Origin: i} {LocalPref: 100}]
[ROUTE] [type:macadv][rd:172.17.0.3:2][esi:single-homed][etag:108][mac:00:11:22:33:44:55][ip:11.11.11.1][labels:[0]] via 10.75.44.254 aspath [] attrs [{Extcomms: [mac-mobility: 500, sticky]} {Origin: i} {LocalPref: 100}]
[ROUTE] [type:multicast][rd:172.16.0.1:5904][etag:100][ip:192.168.0.1] via 10.75.44.254 aspath [] attrs [{Origin: i} {LocalPref: 100}]
[ROUTE] [type:esi][rd:172.16.0.1:8888][esi:{0 [0 0 0 0 0 0 0 0 0]}][ip:192.168.0.1] via 10.75.44.254 aspath [] attrs [{Extcomms: [es-import rt: 00:11:22:33:44:55]} {Origin: i} {LocalPref: 100}]
```

``` bash
$ gobgp neighbor 
Peer              AS  Up/Down State       |#Advertised Received Accepted
10.75.44.10      300 00:21:00 Establ      |          4        0        0
10.75.44.11      200 00:22:03 Establ      |          0        4        4
```
