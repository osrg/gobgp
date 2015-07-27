#!/bin/bash
set +e

if [ ! -v GOROOT ]; then
    if which go > /dev/null; then
        GOROOT=`dirname $(dirname $(which go))`
    else
        echo 'set $GOROOT'
        exit 1
    fi
fi

if [ ! -v GOPATH ]; then
    echo 'set $GOPATH'
    exit 1
fi

if [ ! -v GOBGP ]; then
    GOBGP=$GOPATH/src/github.com/osrg/gobgp
fi

if [ ! -v GOBGP_IMAGE ]; then
    GOBGP_IMAGE=gobgp
fi

if [ ! -v WS ]; then
    WS=`pwd`
fi

cd $GOBGP/test/scenario_test

# route server malformed message test
sudo -E python route_server_malformed_test.py --gobgp-image $GOBGP_IMAGE --go-path $GOROOT/bin -s --with-xunit --xunit-file=${WS}/nosetest_malformed.xml
RET1=$?

# route server policy test
sudo -E python route_server_policy_test.py --gobgp-image $GOBGP_IMAGE --go-path $GOROOT/bin -s --with-xunit --xunit-file=${WS}/nosetest_policy.xml
RET2=$?

# route server test
sudo -E python route_server_test.py --gobgp-image $GOBGP_IMAGE --test-prefix rs -s -x --with-xunit --xunit-file=${WS}/nosetest.xml &
PID3=$!

# route server ipv4 ipv6 test
sudo -E python route_server_ipv4_v6_test.py --gobgp-image $GOBGP_IMAGE --test-prefix v6 -s -x --with-xunit --xunit-file=${WS}/nosetest_ip.xml &
PID4=$!

# bgp router test
sudo -E python bgp_router_test.py --gobgp-image $GOBGP_IMAGE --test-prefix bgp -s -x --with-xunit --xunit-file=${WS}/nosetest_bgp.xml &
PID5=$!

# ibgp router test
sudo -E python ibgp_router_test.py --gobgp-image $GOBGP_IMAGE --test-prefix ibgp -s -x --with-xunit --xunit-file=${WS}/nosetest_ibgp.xml &
PID6=$!

wait $PID3
RET3=$?
wait $PID4
RET4=$?
wait $PID5
RET5=$?
wait $PID6
RET6=$?

if [ $RET1 != 0 ] || [ $RET2 != 0 ] || [ $RET3 != 0 ] || [ $RET4 != 0 ] || [ $RET5 != 0 ] || [ $RET6 != 0 ]; then
    exit 1
fi
echo 'all tests passed successfully'
exit 0
