# Ethernet VPN (EVPN)

This page explains an configuration for EVPN. Note that the feature is
still very experimental. This example uses [BaGPipe
BGP](https://github.com/Orange-OpenSource/bagpipe-bgp), which only OSS
BGP implementation supporting EVPN as far as we know. GoBGP receives
routes from one BaGPipe peer and advertises it to another BaGPipe
peer.

If you don't want to install [BaGPipe
BGP](https://github.com/Orange-OpenSource/bagpipe-bgp) by hand, you can use [Our BaGPipe BGP Docker
image](https://registry.hub.docker.com/u/yoshima/bagpipe-bgp/).

## Configuration

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

## Advertising EVPN route

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
