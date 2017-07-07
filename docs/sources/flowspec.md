# Flowspec (RFC5575)

GoBGP supports [RFC5575](https://tools.ietf.org/html/rfc5575),
[RFC7674](https://tools.ietf.org/html/rfc7674), 
[draft-ietf-idr-flow-spec-v6](https://tools.ietf.org/html/draft-ietf-idr-flow-spec-v6)
and [draft-ietf-idr-flowspec-l2vpn](https://tools.ietf.org/html/draft-ietf-idr-flowspec-l2vpn).

## Prerequisites

Assume you finished [Getting Started](https://github.com/osrg/gobgp/blob/master/docs/sources/getting-started.md).

## Contents
- [Configuration](#section0)
- [Add Flowspec routes through CLI](#section1)

## <a name="section0"> Configuration

To advertise flowspec routes, enumerate each flowspec family to neighbor's
afi-safis like below.

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
  afi-safi-name = "ipv4-flowspec"
[[neighbors.afi-safis]]
  [neighbors.afi-safis.config]
  afi-safi-name = "ipv6-flowspec"
[[neighbors.afi-safis]]
  [neighbors.afi-safis.config]
  afi-safi-name = "l2vpn-flowspec"
[[neighbors.afi-safis]]
  [neighbors.afi-safis.config]
  afi-safi-name = "l3vpn-ipv4-flowspec"
[[neighbors.afi-safis]]
  [neighbors.afi-safis.config]
  afi-safi-name = "l3vpn-ipv6-flowspec"
```

## <a name="section1"> Add Flowspec routes through CLI

CLI syntax to add ipv4/ipv6 flowspec rule is

```shell
% global rib add match <MATCH_EXPR> then <THEN_EXPR> -a [ipv4-flowspec|ipv6-flowspec]
   <MATCH_EXPR> : { destination <PREFIX> [<OFFSET>] | source <PREFIX> [<OFFSET>] |
                    protocol <PROTO>... | fragment <FRAGMENT> | tcp-flags <TCPFLAG> |
                    { port | destination-port | source-port | icmp-type | icmp-code | packet-length | dscp | label } <ITEM>... }...
   <PROTO> : ospf, pim, igp, udp, igmp, tcp, egp, rsvp, gre, ipip, unknown, icmp, sctp, <VALUE>
   <FRAGMENT> : [!] [=] <FRAGMENT_TYPE> {(&| ) <FRAGMENT>}
   <FRAGMENT_TYPE> : dont-fragment, is-fragment, first-fragment, last-fragment, not-a-fragment
   <TCPFLAG> : [!] [=] <FLAGS> {(&| ) <TCPFLAG>}
   <FLAGS> : U, C, E, F, S, R, P, A
   <ITEM> : &?{<|>|>=|<=|==|!=}<value>
   <THEN_EXPR> : { accept | discard | rate-limit <value> | redirect <RT> | mark <value> | action { sample | terminal | sample-terminal } | rt <RT>... }...
   <RT> : xxx:yyy, xx.xx.xx.xx:yyy, xxx.xxx:yyy, <ipv6_address>:yyy
```

that for l2vpn flowspec rule is

``` shell
% global rib add match <MATCH_EXPR> then <THEN_EXPR> -a [l2vpn-flowspec]
   <MATCH_EXPR> : { { destination-mac | source-mac } <MAC> | ether-type <ETHER_TYPE> | { llc-dsap | llc-ssap | llc-control | snap | vid | cos | inner-vid | inner-cos } <ITEM>... }...
   <ETHER_TYPE> : arp, vmtp, ipx, snmp, net-bios, xtp, pppoe-discovery, ipv4, rarp, ipv6, pppoe-session, loopback, apple-talk, aarp
   <ITEM> : &?{<|>|>=|<=|==|!=}<value>
   <THEN_EXPR> : { accept | discard | rate-limit <value> | redirect <RT> | mark <value> | action { sample | terminal | sample-terminal } | rt <RT>... }...
   <RT> : xxx:yyy, xx.xx.xx.xx:yyy, xxx.xxx:yyy, <ipv6_address>:yyy
```

and that for ipv4/ipv6 l3vpn flowspec rule is the same with ipv4/ipv6 flowspec rule other than `rd <RD>`.

``` shell
% global rib add rd <RD> match <MATCH_EXPR> then <THEN_EXPR> -a [ipv4-l3vpn-flowspec|ipv6-l3vpn-flowspec]
   ...(the same as ipv4-flowspec|ipv6-flowspec)...
   <RD> : xxx:yyy, xx.xx.xx.xx:yyy, xxx.xxx:yyy, <ipv6_address>:yyy
```


### Decimal values and Operators

Gobgp comply with ['RFC5575'](https://tools.ietf.org/html/rfc5575).

All decimal values like ports, destination port, source port, procotol number can be married with the following operators:
```
            +----+----+----+----------------------------------+
            | lt | gt | eq | Resulting operation              |
            +----+----+----+----------------------------------+
            | 0  | 0  | 0  | true (independent of the value)  |
            | 0  | 0  | 1  | == (equal)                       |
            | 0  | 1  | 0  | > (greater than)                 |
            | 0  | 1  | 1  | >= (greater than or equal)       |
            | 1  | 0  | 0  | < (less than)                    |
            | 1  | 0  | 1  | <= (less than or equal)          |
            | 1  | 1  | 0  | != (not equal value)             |
            | 1  | 1  | 1  | false (independent of the value) |
            +----+----+----+----------------------------------+
```
### Examples

```shell
# add a flowspec rule which redirect flows whose dst 10.0.0.0/24 and src 20.0.0.0/24 to VRF with RT 10:10
% gobgp global rib -a ipv4-flowspec add match destination 10.0.0.0/24 source 20.0.0.0/24 then redirect 10:10

# add a flowspec rule wich discard flows whose dst 2001::2/128 and port equals 80 and with TCP flags not match SA (SYN/ACK) and not match U (URG)
% gobgp global rib -a ipv6-flowspec add match destination 2001::2/128 port '==80' tcp-flags '=!SA&=!U' then discard

# show ipv4 flowspec table
% gobgp global rib -a ipv4-flowspec
   Network                                       Next Hop             AS_PATH              Age        Attrs
*> [destination:10.0.0.0/24][source:20.0.0.0/24] fictitious                                00:00:06   [{Origin: ?} {Extcomms: [redirect: 10:10]}]

# add another flowspec rule which discard flows whose
  # ip protocol is tcp
  # destination port is 80 or greater than or equal to 8080 and lesser than or equal to 8888
  # packet is a first fragment or a last fragment
% gobgp global rib -a ipv4-flowspec add match protocol tcp destination-port '==80' '>=8080&<=8888' fragment '=first-fragment =last-fragment' then discard

% gobgp global rib -a ipv4-flowspec
   Network                                       Next Hop             AS_PATH              Age        Attrs
*> [destination:10.0.0.0/24][source:20.0.0.0/24] fictitious                                00:05:55   [{Origin: ?} {Extcomms: [redirect: 10:10]}]
*> [protocol:==tcp ][destination-port: ==80 >=8080&<=8888][fragment: =first-fragment =last-fragment] fictitious                                00:22:23   [{Origin: ?} {Extcomms: [discard]}]


# delete a flowspec rule
% gobgp global rib -a ipv4-flowspec del match destination 10.0.0.0/24 source 20.0.0.0/24 then redirect 10:10

% gobgp global rib -a ipv4-flowspec
   Network                                                                                           Next Hop             AS_PATH              Age        Attrs
*> [protocol:==tcp ][destination-port: ==80 >=8080&<=8888][fragment: =first-fragment =last-fragment] fictitious                                00:23:30   [{Origin: ?} {Extcomms: [discard]}]

```
