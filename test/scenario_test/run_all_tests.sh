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

PIDS=()

# route server malformed message test
sudo -E python route_server_malformed_test.py --gobgp-image $GOBGP_IMAGE --go-path $GOROOT/bin -s --with-xunit --xunit-file=${WS}/nosetest_malformed.xml
RET1=$?
if [ $RET1 != 0 ]; then
    exit 1
fi

# route server policy test
NUM=`sudo -E python route_server_policy_test.py -s 2>1 | awk '/invalid/{print $NF}'`
for (( i = 1; i < $NUM; ++i ))
do
    sudo -E python route_server_policy_test.py --gobgp-image $GOBGP_IMAGE --test-prefix p$i --test-index $i -s -x --with-xunit --xunit-file=${WS}/nosetest_policy${i}.xml &
    PIDS=("${PIDS[@]}" $!)
done

# route server test
sudo -E python route_server_test.py --gobgp-image $GOBGP_IMAGE --test-prefix rs -s -x --with-xunit --xunit-file=${WS}/nosetest.xml &
PIDS=("${PIDS[@]}" $!)

# route server ipv4 ipv6 test
sudo -E python route_server_ipv4_v6_test.py --gobgp-image $GOBGP_IMAGE --test-prefix v6 -s -x --with-xunit --xunit-file=${WS}/nosetest_ip.xml &
PIDS=("${PIDS[@]}" $!)

# bgp router test
sudo -E python bgp_router_test.py --gobgp-image $GOBGP_IMAGE --test-prefix bgp -s -x --with-xunit --xunit-file=${WS}/nosetest_bgp.xml &
PIDS=("${PIDS[@]}" $!)

# ibgp router test
sudo -E python ibgp_router_test.py --gobgp-image $GOBGP_IMAGE --test-prefix ibgp -s -x --with-xunit --xunit-file=${WS}/nosetest_ibgp.xml &
PIDS=("${PIDS[@]}" $!)

# evpn router test
sudo -E python evpn_test.py --gobgp-image $GOBGP_IMAGE --test-prefix evpn -s -x --with-xunit --xunit-file=${WS}/nosetest_evpn.xml &
PIDS=("${PIDS[@]}" $!)

# flowspec test
sudo -E python flow_spec_test.py --gobgp-image $GOBGP_IMAGE --test-prefix flow -s -x --with-xunit --xunit-file=${WS}/nosetest_flow.xml &
PIDS=("${PIDS[@]}" $!)

for (( i = 0; i < ${#PIDS[@]}; ++i ))
do
    wait ${PIDS[$i]}
    if [ $? != 0 ]; then
        exit 1
    fi
done

echo 'all tests passed successfully'
exit 0
