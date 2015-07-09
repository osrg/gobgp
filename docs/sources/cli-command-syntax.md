# CLI command syntax

This page explains gobgp client command syntax.



## basic command pattern
gobgp \<subcommand> \<object>  opts...

gobgp has three subcommands.
- global
- neighbor
- policy


## 1. global subcommand
### 1.1. Operations for Global-Rib - add/del/show -
#### - syntax
```shell
# add Route
% gobgp global rib add <prefix> [-a <address family>]
# delete a specific Route
% gobgp global rib del <prefix> [-a <address family>]
# show all Route information
% gobgp global rib [-a <address family>]
# show a specific route information
% gobgp global rib [<prefix>|<host>] [-a <address family>]
```

#### - example
If you want to add routes with the address of the ipv4 to global rib：
```shell
% gobgp global rib add 10.33.0.0 -a ipv4
```
If you want to remove routes with the address of the ipv6 from global rib：
```shell
% gobgp global rib del 2001:123:123:1::/64 -a ipv6
```

#### - option
The following options can be specified in the global subcommand:

| short  |long           | description                                |
|--------|---------------|--------------------------------------------|
|a       |address-family |specify the ipv4, ipv6, evpn, encap, or rtc |

<br>

## 2. neighbor subcommand
### 2.1. Show Neighbor Status
#### - syntax
```shell
# show neighbor's status as list
% gobgp neighbor
# show status of a specific neighbor
% gobgp neighbor <neighbor address>
```

### 2.2. Operations for neighbor - shutdown/reset/softreset/enable/disable -
#### - syntax
```shell
% gobgp neighbor <neighbor address> shutdown
% gobgp neighbor <neighbor address> reset
% gobgp neighbor <neighbor address> softreset [-a <address family>]
% gobgp neighbor <neighbor address> softresetin [-a <address family>]
% gobgp neighbor <neighbor address> softresetout [-a <address family>]
% gobgp neighbor <neighbor address> enable
% gobgp neighbor <neighbor address> disable
```
#### - option
  The following options can be specified in the neighbor subcommand:

| short  |long           | description                  |
|--------|---------------|------------------------------|
|a       |address-family |specify the ipv4 or ipv6      |


### 2.3. Show Rib - local-rib/adj-rib-in/adj-rib-out -
#### - syntax
```shell
# show all routes in [local|adj-in|adj-out] table
% gobgp neighbor <neighbor address> [local|adj-in|adj-out] [-a <address family>]
# show a specific route in [local|adj-in|adj-out] table
% gobgp neighbor <neighbor address> [local|adj-in|adj-out] [<prefix>|<host>] [-a <address family>]
```

#### - example
If you want to show the local rib of ipv4 that neighbor(10.0.0.1) has：
```shell
% gobgp neighbor 10.0.0.1 local -a ipv4
```

#### - option
The following options can be specified in the neighbor subcommand:

| short  |long           | description                  |
|--------|---------------|------------------------------|
|a       |address-family |specify the ipv4 or ipv6      |


### 2.4. Operations for Policy  - add/del/show -
#### - syntax
```shell
# add policy to import-policy configuration
% gobgp neighbor <neighbor address> policy add import <policy names> <default policy action>
# add policy to export-policy configuration
% gobgp neighbor <neighbor address> policy add export <policy names> <default policy action>
# add policy to distribute-policy configuration
% gobgp neighbor <neighbor address> policy add distribute <policy names> <default policy action>
# delete import-policy configuration from specific neighbor
% gobgp neighbor <neighbor address> policy del import
# delete export-policy configuration from specific neighbor
% gobgp neighbor <neighbor address> policy del export
# delete distribute-policy configuration from specific neighbor
% gobgp neighbor <neighbor address> policy del distribute
# show a specific policy information
% gobgp neighbor <neighbor address> policy
```

#### - example
If you want to add the import policy to neighbor(10.0.0.1)：
```shell
% gobgp neighbor 10.0.0.1 policy add import policy1,policy2 accept
```
You can specify multiple policy to neighbor separated by commas.

\<default policy action> means the operation(accept | reject) in the case where the route does not match the conditions of the policy.


<br>

## 3. policy subcommand
### 3.1. Operations for PrefixSet - add/del/show -
#### - syntax
```shell
# add PrefixSet
% gobgp policy prefix add <prefix set name> <prefix> [<mask length range>]
# delete all PrefixSet
% gobgp policy prefix del all
# delete a specific PrefixSet
% gobgp policy prefix del <prefix set name> [<prefix> <mask length range>]
# show all PrefixSet information
% gobgp policy prefix
# show a specific PrefixSet
% gobgp policy prefix <prefix set name>
```

#### - example
If you want to add the PrefixSet：
```shell
% gobgp policy prefix add ps1 10.33.0.0/16 16..24
```
A PrefixSet it is possible to have multiple prefix, if you want to remove the PrefixSet to specify only PrefixSet name.
```shell
% gobgp policy prefix del ps1
```
If you want to remove one element(prefix) of PrefixSet, to specify a prefix in addition to the PrefixSet name.
```shell
% gobgp policy prefix del ps1 10.33.0.0/16
```

### 3.2. Operations for NeighborSet - add/del/show -
#### - syntax
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

#### - example
If you want to add the NeighborSet：
```shell
% gobgp policy neighbor add ns1 10.0.0.1
```
A NeighborSet it is possible to have multiple address, if you want to remove the NeighborSet to specify only NeighborSet name.
```shell
% gobgp policy neighbor del ns1
```
If you want to remove one element(address) of NeighborSet, to specify a address in addition to the NeighborSet name.
```shell
% gobgp policy prefix del ns1 10.0.0.1
```

### 3.3. Operations for AsPathSet - add/del/show -
#### - syntax
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

#### - example
If you want to add the AsPathSet：
```shell
% gobgp policy aspath add ass1 ^65100
```
   You can specify the position using regexp-like expression as follows:
   - From: "^65100" means the route is passed from AS 65100 directly.
   - Any: "65100" means the route comes through AS 65100.
   - Origin: "65100$" means the route is originated by AS 65100.
   - Only: "^65100$" means the route is originated by AS 65100 and comes from it directly.

An AsPathSet it is possible to have multiple as path, if you want to remove the AsPathSet to specify only AsPathSet name.
```shell
% gobgp policy aspath del ass1
```
If you want to remove one element(as path) of AsPathSet, to specify an as path in addition to the AsPathSet name.
```shell
% gobgp policy aspath del ass1 ^65100
```

### 3.4. Operations for CommunitySet - add/del/show -
#### - syntax
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

#### - example
If you want to add the CommunitySet：
```shell
% gobgp policy community add cs1 65100:10
```
   You can specify the position using regexp-like expression as follows:
   - 6[0-9]+:[0-9]+

A CommunitySet it is possible to have multiple community, if you want to remove the CommunitySet to specify only CommunitySet name.
```shell
% gobgp policy neighbor del cs1
```
If you want to remove one element(community) of CommunitySet, to specify a address in addition to the CommunitySet name.
```shell
% gobgp policy prefix del cs1 65100:10
```

### 3.5. Operations for RoutePolicy - add/del/show -
#### - syntax
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

#### - example
If you want to add the RoutePolicy：
```shell
% gobgp policy routepolicy add policy1 state1 --c-prefix=ps1 --c-neighbor=ns1 --c-aspath=ass1 --c-community=cs1 --c-aslen=eq,3 --c-option=all --a-route=reject --a-community=ADD[65100:20] --a-med=+100 --a-asprepend=65100,10
```
However, it is not necessary to specify all of the options at once.


A RoutePolicy it is possible to have multiple statement, if you want to remove the RoutePolicy to specify only RoutePolicy name.
```shell
% gobgp policy routepolicy del policy1
```
If you want to remove one element(statement) of RoutePolicy, to specify a statement name in addition to the RoutePolicy name.
```shell
% gobgp policy prefix del policy1 state1
```

#### - option
The following options can be specified in the policy subcommand:
  - options of condition

| short  |long        | description                                                        |
|--------|------------|--------------------------------------------------------------------|
|-       |c-prefix    |specify the name that added prefix set in PrefixSet subcommand      |
|-       |c-neighbor  |specify the name that added neighbor set in NeighborSet subcommand  |
|-       |c-aspath    |specify the name that added as path set in AsPathSet subcommand     |
|-       |c-community |specify the name that added community set in CommunitySet subcommand|
|-       |c-aslen     |specify the operator(eq, ge, le) and value(numric)                  |
|-       |c-option    |specify the match option(any, all, invert)                          |

  - options of action

| short  |long        | description                                                                                                   |
|--------|------------|---------------------------------------------------------------------------------------------------------------|
|-       |a-route     |specify the action(accept, reject) of the route that match to the conditions                                   |
|-       |a-community |specify the community operation of the route that match to the conditions                                      |
|-       |a-med       |specify the med operation of the route that match to the conditions                                            |
|-       |a-asprepend |specify a combination of an AS number and repeat count(e.g. 65100,10) to prepend if the path matches conditions|

