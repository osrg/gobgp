# CLI command syntax

This page explains gobgpcli command syntax.



## basic command pattern
gobgpcli \<subcommand> \<object>  opts...

gobgpcli has three subcommands.
- global
- neighbor
- policy

Note: Currently gobgpcli supports only **lobal** and **neighbor** subcommand.



## global subcommand

### show global-rib
```shell
% gobgpcli global rib
```

<br>


## neighbor subcommand
### Show Neighbor Status
```shell
# show neighbor's status as list
% gobgpcli neighbor

# show status of a specific neighbor
% gobgpcli neighbor <neighbor address>
```

### Operations for neighbor - shutdown/reset/softreset/enable/disable -
```shell
% gobgpcli neighbor <neighbor address> shutdown
% gobgpcli neighbor <neighbor address> reset
% gobgpcli neighbor <neighbor address> softreset -a <address family>
% gobgpcli neighbor <neighbor address> softresetin -a <address family>
% gobgpcli neighbor <neighbor address> softresetout -a <address family>
% gobgpcli neighbor <neighbor address> enable
% gobgpcli neighbor <neighbor address> disable
```

### Show Rib - local-rib/adj-rib-in/adj-rib-out -
```shell
% gobgpcli neighbor <neighbor address> local -a <address family>
% gobgpcli neighbor <neighbor address> adj-in -a <address family>
% gobgpcli neighbor <neighbor address> adj-out -a <address family>
```

### Operations for Policy  - add/del/show -
```shell
# add policy to import-policy configuration
% gobgpcli neighbor <neighbor address> policy add import <import policy name> <default import policy> -a <address family>
# add policy to export-policy configuration
% gobgpcli neighbor <neighbor address> policy add export <export policy name> <default export policy> -a <address family>
# delete import-policy configuration from specific neighbor
% gobgpcli neighbor <neighbor address> policy del import -a <address family>
# delete export-policy configuration from specific neighbor
% gobgpcli neighbor <neighbor address> policy del export -a <address family>
# show a specific policy  information
% gobgpcli neighbor <neighbor address> policy -a <address family>
```

### Operations for Static Route - add/del/show -
```shell
# add Route
% gobgpcli neighbor <neighbor address> route add <prefix> -a <address family>
# delete all Route
% gobgpcli neighbor <neighbor address> route del -a <address family>
# delete a specific Route
% gobgpcli neighbor <neighbor address> route del <prefix> -a <address family>
# show a specific Route information
% gobgpcli neighbor <neighbor address> route -a <address family>
```

<br>

## policy subcommand
### Operations for PrefixSet - add/del/show -
```shell
# add PrefixSet
% gobgpcli policy prefix add <prefix set name> <prefix>
# delete all PrefixSet
% gobgpcli policy prefix del
# delete a specific PrefixSet
% gobgpcli policy prefix del <prefix set name>
# show list of PrefixSet
% gobgpcli policy prefix
# show a specific PrefixSet
% gobgpcli policy prefix <prefix set name>
```
### Operations for NeighborSet - add/del/show -
```shell
# add NeighborSet
% gobgpcli policy neighbor add <neighbor-set name> <neighbor address>
# delete all NeighborSet
% gobgpcli policy neighbor del
# delete a specific NeighborSet
% gobgpcli policy neighbor del <neighbor set name>
# show all NeighborSet information
% gobgpcli policy neighbor
# show a specific NeighborSet information
% gobgpcli policy neighbor <neighbor set name>
```
### Operations for RoutePolicy - add/del/show -
```shell
# add RoutePolicy
% gobgpcli policy routepoilcy add <route policy name> condition <condtion> action <aciton>
# delete all RoutePolicy
% gobgpcli policy routepoilcy del
# delete a specific RoutePolicy
% gobgpcli policy routepoilcy del <route policy name>
# show all RoutePolicy information
% gobgpcli policy routepoilcy
# show a specific RoutePolicy information
% gobgpcli policy routepoilcy <route policy name>
```
