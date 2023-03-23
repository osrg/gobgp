# BGP Extensions for the Mobile User Plane (MUP) SAFI

This feature is implementation of [the Internet-Draft, BGP Extensions for the Mobile User Plane (MUP) SAFI](https://datatracker.ietf.org/doc/html/draft-mpmz-bess-mup-safi-01).

## Contents

- [CLI Syntax](#cli-syntax)
  - [Interwork Segment Discovery route](#interwork-segment-discovery-route)
  - [Direct Segment Discovery route](#direct-segment-discovery-route)
  - [Type 1 Session Transformed (ST) Route](#type-1-session-transformed-route)
  - [Type 2 Session Transformed (ST) Route](#type-2-session-transformed-route)
- [Example setup with netns](#example-setup-with-netns)

## CLI Syntax

### Interwork Segment Discovery route

```shell
# Add a route
gobgp global rib add -a ipv4-mup isd <ip prefix> rd <rd> prefix <prefix> locator-node-length <locator-node-length> function-length <function-length> behavior <behavior> [rt <rt>...]
gobgp global rib add -a ipv6-mup isd <ip prefix> rd <rd> prefix <prefix> locator-node-length <locator-node-length> function-length <function-length> behavior <behavior> [rt <rt>...]

# Show routes
gobgp global rib -a ipv4-mup
gobgp global rib -a ipv6-mup

# Delete a route
gobgp global rib del -a ipv4-mup isd <ip prefix> rd <rd> prefix <prefix> locator-node-length <locator-node-length> function-length <function-length> behavior <behavior> [rt <rt>...]
gobgp global rib del -a ipv6-mup isd <ip prefix> rd <rd> prefix <prefix> locator-node-length <locator-node-length> function-length <function-length> behavior <behavior> [rt <rt>...]
```

#### Example - Interwork Segment Discovery route

```console
# IPv4
$ gobgp global rib add -a ipv4-mup isd 10.0.0.0/24 rd 100:100 prefix 2001:db8:1:1::/64 locator-node-length 24 function-length 16 behavior ENDM_GTP4E rt 10:10 nexthop 2001::2
$ gobgp global rib -a ipv4-mup
   Network                                    Next Hop             AS_PATH              Age        Attrs
*> [type:isd][rd:100:100][prefix:10.0.0.0/24] 2001::2                                   00:00:09   [{Origin: ?} {Extcomms: [10:10]} {Prefix SID attributes: {SRv6 L3 Service Attribute: {SRv6 Information Sub TLV: SID: 2001:db8:1:1:: Flag: 0 Endpoint Behavior: 72 {SRv6 Structure Sub Sub TLV: [ Locator Block Length: 64, Locator Node Length: 24, Function Length: 16, Argument Length: 0, Transposition Length: 0, Transposition Offset: 0] } } } }]

# IPv6
$ gobgp global rib add -a ipv6-mup isd 2001::/64 rd 100:100 prefix 2001:db8:1:1::/64 locator-node-length 24 function-length 16 behavior ENDM_GTP6E rt 10:10 nexthop 2001::2
$ gobgp global rib -a ipv6-mup
   Network                                  Next Hop             AS_PATH              Age        Attrs
*> [type:isd][rd:100:100][prefix:2001::/64] 2001::2                                   00:00:04   [{Origin: ?} {Extcomms: [10:10]} {Prefix SID attributes: {SRv6 L3 Service Attribute: {SRv6 Information Sub TLV: SID: 2001:db8:1:1:: Flag: 0 Endpoint Behavior: 71 {SRv6 Structure Sub Sub TLV: [ Locator Block Length: 64, Locator Node Length: 24, Function Length: 16, Argument Length: 0, Transposition Length: 0, Transposition Offset: 0] } } } }]
```

### Direct Segment Discovery route

```shell
# Add a route
gobgp global rib add -a ipv4-mup dsd <ip address> rd <rd> prefix <prefix> locator-node-length <locator-node-length> function-length <function-length> behavior <behavior> [rt <rt>...] [mup <segment identifier>]
gobgp global rib add -a ipv6-mup dsd <ip address> rd <rd> prefix <prefix> locator-node-length <locator-node-length> function-length <function-length> behavior <behavior> [rt <rt>...] [mup <segment identifier>]

# Show routes
gobgp global rib -a ipv4-mup
gobgp global rib -a ipv6-mup

# Delete a route
gobgp global rib del -a ipv4-mup dsd <ip address> rd <rd> prefix <prefix> locator-node-length <locator-node-length> function-length <function-length> behavior <behavior> [rt <rt>...] [mup <segment identifier>]
gobgp global rib del -a ipv6-mup dsd <ip address> rd <rd> prefix <prefix> locator-node-length <locator-node-length> function-length <function-length> behavior <behavior> [rt <rt>...] [mup <segment identifier>]
```

#### Example - Direct Segment Discovery route

```console
# IPv4
$ gobgp global rib add -a ipv4-mup dsd 10.0.0.1 rd 100:100 prefix 2001:db8:1:1::/64 locator-node-length 24 function-length 16 behavior END_DT4 rt 10:10 mup 10:10 nexthop 2001::2

$ gobgp global rib -a ipv4-mup
   Network                                 Next Hop             AS_PATH              Age        Attrs
*> [type:dsd][rd:100:100][prefix:10.0.0.1] 2001::2                                   00:00:03   [{Origin: ?} {Extcomms: [10:10], [10:10]} {Prefix SID attributes: {SRv6 L3 Service Attribute: {SRv6 Information Sub TLV: SID: 2001:db8:1:1:: Flag: 0 Endpoint Behavior: 19 {SRv6 Structure Sub Sub TLV: [ Locator Block Length: 64, Locator Node Length: 24, Function Length: 16, Argument Length: 0, Transposition Length: 0, Transposition Offset: 0] } } } }]

# IPv6
$ gobgp global rib add -a ipv6-mup dsd 2001::1 rd 100:100 prefix 2001:db8:2:2::/64 locator-node-length 24 function-length 16 behavior END_DT6 rt 10:10 mup 10:10 nexthop 2001::2

$ gobgp global rib -a ipv6-mup
   Network                                Next Hop             AS_PATH              Age        Attrs
*> [type:dsd][rd:100:100][prefix:2001::1] 2001::2                                   00:00:04   [{Origin: ?} {Extcomms: [10:10], [10:10]} {Prefix SID attributes: {SRv6 L3 Service Attribute: {SRv6 Information Sub TLV: SID: 2001:db8:2:2:: Flag: 0 Endpoint Behavior: 18 {SRv6 Structure Sub Sub TLV: [ Locator Block Length: 64, Locator Node Length: 24, Function Length: 16, Argument Length: 0, Transposition Length: 0, Transposition Offset: 0] } } } }]
```

### Type 1 Session Transformed Route

```shell
# Add a route
gobgp global rib add -a ipv4-mup t1st <ip prefix> rd <rd> [rt <rt>...] teid <teid> qfi <qfi> endpoint <endpoint>
gobgp global rib add -a ipv6-mup t1st <ip prefix> rd <rd> [rt <rt>...] teid <teid> qfi <qfi> endpoint <endpoint>

# Show routes
gobgp global rib -a ipv4-mup
gobgp global rib -a ipv6-mup

# Delete a route
gobgp global rib del -a ipv4-mup t1st <ip prefix> rd <rd> [rt <rt>...] teid <teid> qfi <qfi> endpoint <endpoint>
gobgp global rib del -a ipv6-mup t1st <ip prefix> rd <rd> [rt <rt>...] teid <teid> qfi <qfi> endpoint <endpoint>
```

The format of the TEID: hexadecimal (beginning with '0x'), decimal (uint32), or IPv4.

#### Example - Type 1 Session Transformed Route

```console
# IPv4
$ gobgp global rib add -a ipv4-mup t1st 192.168.0.1/32 rd 100:100 rt 10:10 teid 12345 qfi 9 endpoint 10.0.0.1 nexthop 10.0.0.2

$ gobgp global rib -a ipv4-mup
   Network                                                                                   Next Hop             AS_PATH              Age        Attrs
*> [type:t1st][rd:100:100][prefix:192.168.0.1/32][teid:0x00003039][qfi:9][endpoint:10.0.0.1] 10.0.0.2                                  00:00:03   [{Origin: ?} {Extcomms: [10:10]}]

# IPv6
$ gobgp global rib add -a ipv6-mup t1st 2001:db8:1:1::1/128 rd 100:100 rt 10:10 teid 12345 qfi 9 endpoint 2001::1 nexthop 10.0.0.2

$ gobgp global rib -a ipv6-mup
   Network                                                                                       Next Hop             AS_PATH              Age        Attrs
*> [type:t1st][rd:100:100][prefix:2001:db8:1:1::1/128][teid:0x00003039][qfi:9][endpoint:2001::1] 10.0.0.2                                  00:00:05   [{Origin: ?} {Extcomms: [10:10]}]
```

### Type 2 Session Transformed Route

```shell
# Add a route
gobgp global rib add -a ipv4-mup t2st <endpoint address> rd <rd> [rt <rt>...] endpoint-address-length <endpoint-address-length> teid <teid> [mup <segment identifier>]
gobgp global rib add -a ipv6-mup t2st <endpoint address> rd <rd> [rt <rt>...] endpoint-address-length <endpoint-address-length> teid <teid> [mup <segment identifier>]

# Show routes
gobgp global rib -a ipv4-mup
gobgp global rib -a ipv6-mup

# Delete a route
gobgp global rib del -a ipv4-mup t2st <endpoint address> rd <rd> [rt <rt>...] endpoint-address-length <endpoint-address-length> teid <teid> [mup <segment identifier>]
gobgp global rib del -a ipv6-mup t2st <endpoint address> rd <rd> [rt <rt>...] endpoint-address-length <endpoint-address-length> teid <teid> [mup <segment identifier>]
```

The format of the TEID: hexadecimal (beginning with '0x'), decimal (uint32), or IPv4.

#### Example - Type 2 Session Transformed Route

```console
# IPv4
$ gobgp global rib add -a ipv4-mup t2st 10.0.0.1 rd 100:100 rt 10:10 endpoint-address-length 64 teid 12345 mup 10:10 nexthop 10.0.0.2

$ gobgp global rib -a ipv4-mup
   Network                                                                                TEID       QFI        Endpoint             Next Hop             AS_PATH              Age        Attrs
*> [type:t2st][rd:100:100][endpoint-address-length:64][endpoint:10.0.0.1][teid:0.0.48.57]                                            10.0.0.2                                  00:00:21   [{Origin: ?} {Extcomms: [10:10], [10:10]}]

# IPv6
$ gobgp global rib add -a ipv6-mup t2st 2001::1 rd 100:100 rt 10:10 endpoint-address-length 160 teid 12345 mup 10:10 nexthop 10.0.0.2

$ gobgp global rib -a ipv6-mup
   Network                                                                                TEID       QFI        Endpoint             Next Hop             AS_PATH              Age        Attrs
*> [type:t2st][rd:100:100][endpoint-address-length:160][endpoint:2001::1][teid:0.0.48.57]                                            10.0.0.2                                  00:00:47   [{Origin: ?} {Extcomms: [10:10], [10:10]}]
```

## Example setup with netns

### gobgpd configuration

#### gobgpd1.toml

```toml
[global.config]
    as = 65000
    router-id = "10.0.0.1"
    local-address-list = ["10.0.0.1"]

[[neighbors]]
    [neighbors.config]
        peer-as = 65000
        local-as = 65000
        neighbor-address = "10.0.0.2"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
            afi-safi-name = "ipv4-mup"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
            afi-safi-name = "ipv6-mup"
```

#### gobgpd2.toml

```toml
[global.config]
    as = 65000
    router-id = "10.0.0.2"
    local-address-list = ["10.0.0.2"]

[[neighbors]]
    [neighbors.config]
        peer-as = 65000
        local-as = 65000
        neighbor-address = "10.0.0.1"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
            afi-safi-name = "ipv4-mup"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
            afi-safi-name = "ipv6-mup"
```

### Setup netns

```shell
sudo ip link add veth0 type veth peer name veth1

sudo ip netns add red
sudo ip link set veth0 netns red
sudo ip netns exec red ip link set up lo
sudo ip netns exec red ip link set up veth0
sudo ip netns exec red ip addr add 10.0.0.1/24 dev veth0

sudo ip netns add blue
sudo ip link set veth1 netns blue
sudo ip netns exec blue ip link set up lo
sudo ip netns exec blue ip link set up veth1
sudo ip netns exec blue ip addr add 10.0.0.2/24 dev veth1
```

### Run gobgpd

```shell
sudo ip netns exec red gobgpd -f ./gobgp1.toml
sudo ip netns exec blue gobgpd -f ./gobgp2.toml
```

### IPv4

#### Add MUP Routes (IPv4)

```shell
sudo ip netns exec red gobgp global rib add -a ipv4-mup isd 10.0.0.0/24 rd 100:100 prefix 2001:db8:1:1::/64 locator-node-length 24 function-length 16 behavior ENDM_GTP4E rt 10:10 nexthop 2001::2
sudo ip netns exec red gobgp global rib add -a ipv4-mup dsd 10.0.0.1 rd 100:100 prefix 2001:db8:1:1::/64 locator-node-length 24 function-length 16 behavior END_DT4 rt 10:10 mup 10:10 nexthop 2001::2
sudo ip netns exec red gobgp global rib add -a ipv4-mup t1st 192.168.0.1/32 rd 100:100 rt 10:10 teid 12345 qfi 9 endpoint 10.0.0.1 nexthop 10.0.0.2
sudo ip netns exec red gobgp global rib add -a ipv4-mup t2st 10.0.0.1 rd 100:100 rt 10:10 teid 12345 mup 10:10 nexthop 10.0.0.2
```

#### Show MUP Routes (IPv4)

```console
$ sudo ip netns exec red gobgp global rib -a ipv4-mup
   Network                                                                                TEID       QFI        Endpoint             Next Hop             AS_PATH              Age        Attrs
*> [type:isd][rd:100:100][prefix:10.0.0.0/24]                                                                                        2001::2                                   00:00:19   [{Origin: ?} {Extcomms: [10:10]} {Prefix SID attributes: {SRv6 L3 Service Attribute: {SRv6 Information Sub TLV: SID: 2001:db8:1:1:: Flag: 0 Endpoint Behavior: 72 {SRv6 Structure Sub Sub TLV: [ Locator Block Length: 64, Locator Node Length: 24, Function Length: 16, Argument Length: 0, Transposition Length: 0, Transposition Offset: 0] } } } }]
*> [type:dsd][rd:100:100][prefix:10.0.0.1]                                                                                           2001::2                                   00:00:18   [{Origin: ?} {Extcomms: [10:10], [10:10]} {Prefix SID attributes: {SRv6 L3 Service Attribute: {SRv6 Information Sub TLV: SID: 2001:db8:1:1:: Flag: 0 Endpoint Behavior: 19 {SRv6 Structure Sub Sub TLV: [ Locator Block Length: 64, Locator Node Length: 24, Function Length: 16, Argument Length: 0, Transposition Length: 0, Transposition Offset: 0] } } } }]
*> [type:t1st][rd:100:100][prefix:192.168.0.1/32]                                         0.0.48.57  9          10.0.0.1             10.0.0.2                                  00:00:18   [{Origin: ?} {Extcomms: [10:10]}]
*> [type:t2st][rd:100:100][endpoint-address-length:64][endpoint:10.0.0.1][teid:0.0.48.57]

$ sudo ip netns exec blue gobgp global rib -a ipv4-mup   Network                                                                              Next Hop             AS_PATH              Age        Attrs
   Network                                                                                TEID       QFI        Endpoint             Next Hop             AS_PATH              Age        Attrs
*> [type:isd][rd:100:100][prefix:10.0.0.0/24]                                                                                        2001::2                                   00:00:56   [{Origin: ?} {LocalPref: 100} {Extcomms: [10:10]} {Prefix SID attributes: {SRv6 L3 Service Attribute: {SRv6 Information Sub TLV: SID: 2001:db8:1:1:: Flag: 0 Endpoint Behavior: 72 {SRv6 Structure Sub Sub TLV: [ Locator Block Length: 64, Locator Node Length: 24, Function Length: 16, Argument Length: 0, Transposition Length: 0, Transposition Offset: 0] } } } }]
*> [type:dsd][rd:100:100][prefix:10.0.0.1]                                                                                           2001::2                                   00:00:56   [{Origin: ?} {LocalPref: 100} {Extcomms: [10:10], [10:10]} {Prefix SID attributes: {SRv6 L3 Service Attribute: {SRv6 Information Sub TLV: SID: 2001:db8:1:1:: Flag: 0 Endpoint Behavior: 19 {SRv6 Structure Sub Sub TLV: [ Locator Block Length: 64, Locator Node Length: 24, Function Length: 16, Argument Length: 0, Transposition Length: 0, Transposition Offset: 0] } } } }]
*> [type:t1st][rd:100:100][prefix:192.168.0.1/32]                                         0.0.48.57  9          10.0.0.1             10.0.0.2                                  00:00:56   [{Origin: ?} {LocalPref: 100} {Extcomms: [10:10]}]
*> [type:t2st][rd:100:100][endpoint-address-length:64][endpoint:10.0.0.1][teid:0.0.48.57]                                            10.0.0.2                                  00:00:26   [{Origin: ?} {LocalPref: 100} {Extcomms: [10:10], [10:10]}]
```

#### Delete MUP Routes (IPv4)

```shell
sudo ip netns exec red gobgp global rib del -a ipv4-mup isd 10.0.0.0/24 rd 100:100 prefix 2001:db8:1:1::/64 locator-node-length 24 function-length 16 behavior ENDM_GTP4E rt 10:10 nexthop 2001::2
sudo ip netns exec red gobgp global rib del -a ipv4-mup dsd 10.0.0.1 rd 100:100 prefix 2001:db8:1:1::/64 locator-node-length 24 function-length 16 behavior END_DT4 rt 10:10 mup 10:10 nexthop 2001::2
sudo ip netns exec red gobgp global rib del -a ipv4-mup t1st 192.168.0.1/32 rd 100:100 rt 10:10 teid 12345 qfi 9 endpoint 10.0.0.1 nexthop 10.0.0.2
sudo ip netns exec red gobgp global rib del -a ipv4-mup t2st 10.0.0.1 rd 100:100 rt 10:10 teid 12345 mup 10:10 nexthop 10.0.0.2
```

### IPv6

#### Add MUP Routes (IPv6)

```shell
sudo ip netns exec red gobgp global rib add -a ipv6-mup isd 2001::/64 rd 100:100 prefix 2001:db8:1:1::/64 locator-node-length 24 function-length 16 behavior ENDM_GTP6E rt 10:10 nexthop 2001::2
sudo ip netns exec red gobgp global rib add -a ipv6-mup dsd 2001::1 rd 100:100 prefix 2001:db8:2:2::/64 locator-node-length 24 function-length 16 behavior END_DT6 rt 10:10 mup 10:10 nexthop 2001::2
sudo ip netns exec red gobgp global rib add -a ipv6-mup t1st 2001:db8:1:1::1/128 rd 100:100 rt 10:10 teid 12345 qfi 9 endpoint 2001::1 nexthop 10.0.0.2
sudo ip netns exec red gobgp global rib add -a ipv6-mup t2st 2001::1 rd 100:100 rt 10:10 teid 12345 mup 10:10 nexthop 10.0.0.2
```

#### Show MUP Routes (IPv6)

```console
$ sudo ip netns exec red gobgp global rib -a ipv6-mup
   Network                                                                                TEID       QFI        Endpoint             Next Hop             AS_PATH              Age        Attrs
*> [type:isd][rd:100:100][prefix:2001::/64]                                                                                          2001::2                                   00:00:14   [{Origin: ?} {Extcomms: [10:10]} {Prefix SID attributes: {SRv6 L3 Service Attribute: {SRv6 Information Sub TLV: SID: 2001:db8:1:1:: Flag: 0 Endpoint Behavior: 71 {SRv6 Structure Sub Sub TLV: [ Locator Block Length: 64, Locator Node Length: 24, Function Length: 16, Argument Length: 0, Transposition Length: 0, Transposition Offset: 0] } } } }]
*> [type:dsd][rd:100:100][prefix:2001::1]                                                                                            2001::2                                   00:00:14   [{Origin: ?} {Extcomms: [10:10], [10:10]} {Prefix SID attributes: {SRv6 L3 Service Attribute: {SRv6 Information Sub TLV: SID: 2001:db8:2:2:: Flag: 0 Endpoint Behavior: 18 {SRv6 Structure Sub Sub TLV: [ Locator Block Length: 64, Locator Node Length: 24, Function Length: 16, Argument Length: 0, Transposition Length: 0, Transposition Offset: 0] } } } }]
*> [type:t1st][rd:100:100][prefix:2001:db8:1:1::1/128]                                    0.0.48.57  9          2001::1              10.0.0.2                                  00:00:14   [{Origin: ?} {Extcomms: [10:10]}]
*> [type:t2st][rd:100:100][endpoint-address-length:160][endpoint:2001::1][teid:0.0.48.57]                                            10.0.0.2                                  00:00:14   [{Origin: ?} {Extcomms: [10:10], [10:10]}]

$ sudo ip netns exec blue gobgp global rib -a ipv6-mup
   Network                                                                                TEID       QFI        Endpoint             Next Hop             AS_PATH              Age        Attrs
*> [type:isd][rd:100:100][prefix:2001::/64]                                                                                          2001::2                                   00:00:18   [{Origin: ?} {LocalPref: 100} {Extcomms: [10:10]} {Prefix SID attributes: {SRv6 L3 Service Attribute: {SRv6 Information Sub TLV: SID: 2001:db8:1:1:: Flag: 0 Endpoint Behavior: 71 {SRv6 Structure Sub Sub TLV: [ Locator Block Length: 64, Locator Node Length: 24, Function Length: 16, Argument Length: 0, Transposition Length: 0, Transposition Offset: 0] } } } }]
*> [type:dsd][rd:100:100][prefix:2001::1]                                                                                            2001::2                                   00:00:18   [{Origin: ?} {LocalPref: 100} {Extcomms: [10:10], [10:10]} {Prefix SID attributes: {SRv6 L3 Service Attribute: {SRv6 Information Sub TLV: SID: 2001:db8:2:2:: Flag: 0 Endpoint Behavior: 18 {SRv6 Structure Sub Sub TLV: [ Locator Block Length: 64, Locator Node Length: 24, Function Length: 16, Argument Length: 0, Transposition Length: 0, Transposition Offset: 0] } } } }]
*> [type:t1st][rd:100:100][prefix:2001:db8:1:1::1/128]                                    0.0.48.57  9          2001::1              10.0.0.2                                  00:00:18   [{Origin: ?} {LocalPref: 100} {Extcomms: [10:10]}]
*> [type:t2st][rd:100:100][endpoint-address-length:160][endpoint:2001::1][teid:0.0.48.57]                                            10.0.0.2                                  00:00:18   [{Origin: ?} {LocalPref: 100} {Extcomms: [10:10], [10:10]}]
```

#### Delete MUP Routes (IPv6)

```shell
sudo ip netns exec red gobgp global rib del -a ipv6-mup isd 2001::/64 rd 100:100 prefix 2001:db8:1:1::/64 locator-node-length 24 function-length 16 behavior ENDM_GTP6E rt 10:10 nexthop 2001::2
sudo ip netns exec red gobgp global rib del -a ipv6-mup dsd 2001::1 rd 100:100 prefix 2001:db8:2:2::/64 locator-node-length 24 function-length 16 behavior END_DT6 rt 10:10 mup 10:10 nexthop 2001::2
sudo ip netns exec red gobgp global rib del -a ipv6-mup t1st 2001:db8:1:1::1/128 rd 100:100 rt 10:10 teid 12345 qfi 9 endpoint 2001::1 nexthop 10.0.0.2
sudo ip netns exec red gobgp global rib del -a ipv6-mup t2st 2001::1 rd 100:100 rt 10:10 teid 12345 mup 10:10 nexthop 10.0.0.2
```
