# CLI command syntax

This page explains gobgp client command syntax.



## basic command pattern
gobgp \<subcommand> \<object>  opts...

gobgp has three subcommands.
- global
- neighbor
- policy

Note: Currently gobgp supports only **global** and **neighbor** subcommand.



## global subcommand

### Operations for Global-Rib - add/del/show -
```shell
# add Route
% gobgp global rib add <prefix> [-a <address family>]
# delete a specific Route
% gobgp global rib del <prefix> [-a <address family>]
# show all Route information
% gobgp global rib [-a <address family>]
```
 - **Option**
  - \-a , \-\-address-family: specify the ipv4, ipv6, evpn, encap, or rtc

<br>


## neighbor subcommand
### Show Neighbor Status
```shell
# show neighbor's status as list
% gobgp neighbor

# show status of a specific neighbor
% gobgp neighbor <neighbor address>
```

### Operations for neighbor - shutdown/reset/softreset/enable/disable -
```shell
% gobgp neighbor <neighbor address> shutdown
% gobgp neighbor <neighbor address> reset
% gobgp neighbor <neighbor address> softreset [-a <address family>]
% gobgp neighbor <neighbor address> softresetin [-a <address family>]
% gobgp neighbor <neighbor address> softresetout [-a <address family>]
% gobgp neighbor <neighbor address> enable
% gobgp neighbor <neighbor address> disable
```
 - **Option**
  - \-a , \-\-address-family: specify the ipv4 or ipv6

### Show Rib - local-rib/adj-rib-in/adj-rib-out -
```shell
% gobgp neighbor <neighbor address> local [-a <address family>]
% gobgp neighbor <neighbor address> adj-in [-a <address family>]
% gobgp neighbor <neighbor address> adj-out [-a <address family>]
```
 - **Option**
  - \-a , \-\-address-family: specify the ipv4 or ipv6

### Operations for Policy  - add/del/show -
```shell
# add policy to import-policy configuration
% gobgp neighbor <neighbor address> policy add import <import policy name> <default import policy>
# add policy to export-policy configuration
% gobgp neighbor <neighbor address> policy add export <export policy name> <default export policy>
# delete import-policy configuration from specific neighbor
% gobgp neighbor <neighbor address> policy del import
# delete export-policy configuration from specific neighbor
% gobgp neighbor <neighbor address> policy del export
# show a specific policy information
% gobgp neighbor <neighbor address> policy
```

<br>

## policy subcommand
### Operations for PrefixSet - add/del/show -
```shell
# add PrefixSet
% gobgp policy prefix add <prefix set name> <prefix>
# delete all PrefixSet
% gobgp policy prefix del all
# delete a specific PrefixSet
% gobgp policy prefix del <prefix set name> [<prefix> <mask length range>]
# show all PrefixSet information
% gobgp policy prefix
# show a specific PrefixSet
% gobgp policy prefix <prefix set name>
```

### Operations for NeighborSet - add/del/show -
```shell
# add NeighborSet
% gobgp policy neighbor add <neighbor set name> <neighbor address>
# delete all NeighborSet
% gobgp policy neighbor del all
# delete a specific NeighborSet
% gobgp policy neighbor del <neighbor set name> [<address>]
# show all NeighborSet information
% gobgp policy neighbor
# show a specific NeighborSet information
% gobgp policy neighbor <neighbor set name>
```

### Operations for AsPathSet - add/del/show -
```shell
# add AsPathSet
% gobgp policy aspath add <aspath set name> <as path>
# delete all AsPathSet
% gobgp policy aspath del all
# delete a specific AsPathSet
% gobgp policy aspath del <aspath set name> [<as path>]
# show all AsPathSet information
% gobgp policy aspath
# show a specific AsPathSet information
% gobgp policy aspath <aspath set name>
```

### Operations for CommunitySet - add/del/show -
```shell
# add CommunitySet
% gobgp policy community add <community set name> <community>
# delete all CommunitySet
% gobgp policy community del all
# delete a specific CommunitySet
% gobgp policy community del <community set name> [<community>]
# show all CommunitySet information
% gobgp policy community
# show a specific CommunitySet information
% gobgp policy community <community set name>
```


### Operations for RoutePolicy - add/del/show -
```shell
# add RoutePolicy
% gobgp policy routepoilcy add <route policy name> <statement name> [<conditions and actions>]
# delete all RoutePolicy
% gobgp policy routepoilcy del all
# delete a specific RoutePolicy
% gobgp policy routepoilcy del <route policy name> [<statement name>]
# show all RoutePolicy information
% gobgp policy routepoilcy
# show a specific RoutePolicy information
% gobgp policy routepoilcy <route policy name>
```
 - **Option (Conditon)**

  Specify the options of condition when you use the routepolicy add subcommand.
  - \-\-c-prefix    : specify the name that added prefix set in PrefixSet subcommand
  - \-\-c-neighbor  : specify the name that added neighbor set in NeighborSet subcommand
  - \-\-c-aspath    : specify the name that added as path set in AsPathSet subcommand
  - \-\-c-community : specify the name that added community set in CommunitySet subcommand
  - \-\-c-aslen     : specify the operator(eq, ge, le) and value(numric)
  - \-\-c-option    : specify the match option(any, all, invert)

<br>
 - **Option (Action)**

  Specify the options of action when you use the routepolicy add subcommand.
  - \-\-a-route     : specify the action(accept, reject) of the route that match to the conditions
  - \-\-a-community : specify the community operation of the route that match to the conditions