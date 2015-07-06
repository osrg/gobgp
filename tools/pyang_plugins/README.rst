What's this ?
=============
This is a pyang plugin to generate config/bgp_configs.go from
openconfig yang files.

Currently, we made some modifications to the yang files:

   https://github.com/osrg/yang/tree/gobgp


How to use
==========
::

   $ git clone -b gobgp https://github.com/osrg/yang
   $ YANG_DIR=`pwd`/yang
   $ cd $PYANG_INSTALL_DIR
   $ source ./env.sh
   $ PYTHONPATH=. ./bin/pyang --plugindir $GOBGP_PATH/tools/pyang_plugins \
   -p $YANG_DIR/standard/ietf/RFC \
   -p $YANG_DIR/experimental/openconfig/bgp \
   -p $YANG_DIR/experimental/openconfig/policy \
   -f golang $YANG_DIR/experimental/openconfig/bgp/bgp.yang \
   --augment $YANG_DIR/experimental/openconfig/bgp/bgp-policy.yang \
   | gofmt > $GOBGP_PATH/config/bgp_configs.go
