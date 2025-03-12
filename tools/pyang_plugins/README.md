# Generating config code from yang

## What's this ?

This is a pyang plugin to generate config/bgp_configs.go from
[openconfig yang files](https://github.com/openconfig/public).

## Prerequisites

Python 3.

## How to use

Clone the required resources by using Git:

```shell
$ export CWD=`pwd`
$ git clone https://github.com/osrg/gobgp
$ git clone https://github.com/osrg/public
$ git clone https://github.com/osrg/yang
$ git clone https://github.com/osrg/pyang
```

Generate config/bgp_configs.go from yang files:

```shell
$ cd pyang
$ source ./env.sh
$ PYTHONPATH=. ./bin/pyang \
  --plugindir $CWD/gobgp/tools/pyang_plugins \
  -p $CWD/yang/standard/ietf/RFC \
  -p $CWD/public/release/models \
  -p $CWD/public/release/models/bgp \
  -p $CWD/public/release/models/policy \
  -f golang \
  $CWD/public/release/models/policy/openconfig-routing-policy.yang \
  $CWD/public/release/models/bgp/openconfig-bgp.yang \
  $CWD/gobgp/tools/pyang_plugins/gobgp.yang \
  | gofmt > $CWD/gobgp/pkg/config/oc/bgp_configs.go
```
