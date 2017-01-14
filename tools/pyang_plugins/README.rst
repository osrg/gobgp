What's this ?
=============
This is a pyang plugin to generate config/bgp_configs.go from
openconfig yang files (see https://github.com/openconfig/public).

How to use
==========
::

   $ git clone https://github.com/osrg/public
   $ git clone https://github.com/YangModels/yang
   $ YANG_DIR=`pwd`
   $ cd $PYANG_INSTALL_DIR
   $ source ./env.sh
   $ PYTHONPATH=. ./bin/pyang --plugindir $GOBGP_PATH/tools/pyang_plugins \
   -p $YANG_DIR/yang/standard/ietf/RFC \
   -p $YANG_DIR/public/release/models \
   -p $YANG_DIR/public/release/models/bgp \
   -p $YANG_DIR/public/release/models/policy \
   -f golang $YANG_DIR/public/release/models/bgp/openconfig-bgp.yang \
   $YANG_DIR/public/release/models/policy/openconfig-routing-policy.yang \
   $GOBGP_PATH/tools/pyang_plugins/gobgp.yang \
   | gofmt > $GOBGP_PATH/config/bgp_configs.go
