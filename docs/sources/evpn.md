# Ethernet VPN (EVPN)

This page explains an configuration for EVPN. Note that the feature is
still very experimental.

## Contents

- [BaGPipe](#bagpipe)
    - [Configuration](#configuration)
    - [Advertising EVPN route](#advertising-evpn-route)
- [YABGP](#yabgp)
    - [Configuration](#configuration-1)
    - [Advertising EVPN route](#advertising-evpn-route-1)

## BaGPipe

This example uses [BaGPipe](https://github.com/openstack/networking-bagpipe). GoBGP receives
routes from one BaGPipe peer and advertises it to another BaGPipe peer.

**NOTE:** The following supposes to use BaGPipe version "7.0.0".

### Configuration

Please note BaGPipe supports only iBGP.
So here supposes a topology that GoBGP is configured as Route Reflector.
Two BaGPipe peers are Route Reflector clients and not connected to each other.
Then the following example shows two OSS BGP implementations can interchange EVPN messages.

Topology:

```
           +------------+
           | GoBGP (RR) |
     +-----| AS 65000   |-----+
     |     | 10.0.0.254 |     |
     |     +------------+     |
     |                        |
   (iBGP)                  (iBGP)
     |                        |
+----------+            +----------+
| BaGPipe  |            | BaGPipe  |
| AS 65000 |            | AS 65000 |
| 10.0.0.1 |            | 10.0.0.2 |
+----------+            +----------+
```

The following shows the sample configuration for GoBGP.
The point is that "l2vpn-evpn" families to be advertised need to be specified.

GoBGP on "10.0.0.254": `gobgpd.toml`

```toml
[global.config]
  as = 65000
  router-id = "10.0.0.254"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "10.0.0.1"
    peer-as = 65000
  [neighbors.route-reflector.config]
    route-reflector-client = true
    route-reflector-cluster-id = "10.0.0.254"
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "l2vpn-evpn"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "10.0.0.2"
    peer-as = 65000
  [neighbors.route-reflector.config]
    route-reflector-client = true
    route-reflector-cluster-id = "10.0.0.254"
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "l2vpn-evpn"
```

If you are not familiar with BaGPipe, the following shows our configuration files.

BaGPipe peer on "10.0.0.1": `/etc/bagpipe-bgp/bgp.conf`

```ini
[BGP]
local_address=10.0.0.1
peers=10.0.0.254
my_as=65000
enable_rtc=True

[API]
host=localhost
port=8082

[DATAPLANE_DRIVER_IPVPN]
dataplane_driver = DummyDataplaneDriver

[DATAPLANE_DRIVER_EVPN]
dataplane_driver = DummyDataplaneDriver
```

BaGPipe peer on "10.0.0.2": `/etc/bagpipe-bgp/bgp.conf`

```ini
[BGP]
local_address=10.0.0.2
peers=10.0.0.254
my_as=65000
enable_rtc=True

[API]
api_host=localhost
api_port=8082

[DATAPLANE_DRIVER_IPVPN]
dataplane_driver = DummyDataplaneDriver

[DATAPLANE_DRIVER_EVPN]
dataplane_driver = DummyDataplaneDriver
```

Then, run GoBGP and BaGPipe peers.

```bash
# GoBGP
$ gobgpd -f gobgpd.toml

# BaGPipe
# If bgp.conf does not locate on the default path, please specify the config file as following.
$ bagpipe-bgp --config-file /etc/bagpipe-bgp/bgp.conf
```

### Advertising EVPN route

As you expect, the RIBs at BaGPipe peer on "10.0.0.2" has nothing.

```bash
# BaGPipe peer on "10.0.0.2"
$ bagpipe-looking-glass bgp routes
l2vpn/evpn,*: -
ipv4/mpls-vpn,*: -
ipv4/rtc,*: -
ipv4/flow-vpn,*: -
```

Let's advertise EVPN routes from BaGPipe peer on "10.0.0.1".

```bash
# BaGPipe peer on "10.0.0.1"
$ bagpipe-rest-attach --attach --network-type evpn --port tap-dummy --mac 00:11:22:33:44:55 --ip 11.11.11.1 --gateway-ip 11.11.11.254 --rt 65000:77 --vni 100
request: {"import_rt": ["65000:77"], "lb_consistent_hash_order": 0, "vpn_type": "evpn", "vni": 100, "vpn_instance_id": "evpn-bagpipe-test", "ip_address": "11.11.11.1/24", "export_rt": ["65000:77"], "local_port": {"linuxif": "tap-dummy"}, "advertise_subnet": false, "attract_traffic": {}, "gateway_ip": "11.11.11.254", "mac_address": "00:11:22:33:44:55", "readvertise": null}
response: 200 null
```

Now the RIBs at GoBGP and BaGPipe peer "10.0.0.2" has the advertised routes. The route was interchanged via GoBGP peer.

```bash
# GoBGP
$ gobgp global rib -a evpn
   Network                                                                      Labels     Next Hop             AS_PATH              Age        Attrs
*> [type:macadv][rd:10.0.0.1:118][etag:0][mac:00:11:22:33:44:55][ip:11.11.11.1] [1601]     10.0.0.1                                  hh:mm:ss   [{Origin: i} {LocalPref: 100} {Extcomms: [VXLAN], [65000:77]} [ESI: single-homed]]
*> [type:multicast][rd:10.0.0.1:118][etag:0][ip:10.0.0.1]            10.0.0.1                                  hh:mm:ss   [{Origin: i} {LocalPref: 100} {Extcomms: [VXLAN], [65000:77]} {Pmsi: type: ingress-repl, label: 1600, tunnel-id: 10.0.0.1}]

# BaGPipe peer on "10.0.0.2"
$ bagpipe-looking-glass bgp routes
l2vpn/evpn,*:
  * evpn:macadv::10.0.0.1:118:-:0:00:11:22:33:44:55/48:11.11.11.1: label [ 100 ]:
      attributes:
        originator-id: 10.0.0.1
        cluster-list: [ 10.0.0.254 ]
        extended-community: [ target:65000:77 encap:VXLAN ]
      next_hop: 10.0.0.1
      afi-safi: l2vpn/evpn
      source: BGP-10.0.0.254 (...)
      route_targets:
        * target:65000:77
  * evpn:multicast::10.0.0.1:118:0:10.0.0.1:
      attributes:
        cluster-list: [ 10.0.0.254 ]
        originator-id: 10.0.0.1
        pmsi-tunnel: pmsi:ingressreplication:-:100:10.0.0.1
        extended-community: [ target:65000:77 encap:VXLAN ]
      next_hop: 10.0.0.1
      afi-safi: l2vpn/evpn
      source: BGP-10.0.0.254 (...)
      route_targets:
        * target:65000:77
ipv4/mpls-vpn,*: -
ipv4/rtc,*: -
ipv4/flow-vpn,*: -
```

## YABGP

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
