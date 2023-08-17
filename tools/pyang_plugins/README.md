# Generating config code from yang

## What's this ?

This is a pyang plugin to generate config/bgp_configs.go from
[openconfig yang files](https://github.com/openconfig/public).

## Prerequisites

Python 2.

## How to use

Clone the required resources by using Git:

```shell
$ cd $HOME
$ git clone https://github.com/osrg/gobgp
$ git clone https://github.com/osrg/public
$ git clone https://github.com/osrg/yang
$ git clone https://github.com/osrg/pyang
```

Generate config/bgp_configs.go from yang files:

```shell
$ export GOBGP=`pwd`
$ cd $HOME/pyang
$ source ./env.sh
$ PYTHONPATH=. ./bin/pyang \
  --plugindir $GOBGP/tools/pyang_plugins \
  -p $HOME/yang/standard/ietf/RFC \
  -p $HOME/public/release/models \
  -p $HOME/public/release/models/bgp \
  -p $HOME/public/release/models/policy \
  -f golang \
  $HOME/public/release/models/bgp/openconfig-bgp.yang \
  $HOME/public/release/models/policy/openconfig-routing-policy.yang \
  $GOBGP/tools/pyang_plugins/gobgp.yang \
  | gofmt > $GOBGP/pkg/config/oc/bgp_configs.go
```
