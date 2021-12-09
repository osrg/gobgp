#!/bin/bash
set +e

if [ ! -v GOBGP ]; then
    GOBGP=`pwd`
fi

if [ ! -v GOBGP_IMAGE ]; then
    GOBGP_IMAGE=gobgp
fi

if [ ! -v WS ]; then
    WS=`pwd`
fi

export PYTHONPATH=`pwd`/test
TESTDIR=`pwd`/test/scenario_test

PIDS=()

# route server test
python3 $TESTDIR/route_server_test.py --gobgp-image $GOBGP_IMAGE --test-prefix rs -s -x --with-xunit --xunit-file=${WS}/nosetest.xml &
PIDS=("${PIDS[@]}" $!)

# route server ipv4 ipv6 test
python3 $TESTDIR/route_server_ipv4_v6_test.py --gobgp-image $GOBGP_IMAGE --test-prefix v6 -s -x --with-xunit --xunit-file=${WS}/nosetest_ip.xml &
PIDS=("${PIDS[@]}" $!)

# bgp router test
python3 $TESTDIR/bgp_router_test.py --gobgp-image $GOBGP_IMAGE --test-prefix bgp -s -x --with-xunit --xunit-file=${WS}/nosetest_bgp.xml &
PIDS=("${PIDS[@]}" $!)

# ibgp router test
python3 $TESTDIR/ibgp_router_test.py --gobgp-image $GOBGP_IMAGE --test-prefix ibgp -s -x --with-xunit --xunit-file=${WS}/nosetest_ibgp.xml &
PIDS=("${PIDS[@]}" $!)

# evpn router test
python3 $TESTDIR/evpn_test.py --gobgp-image $GOBGP_IMAGE --test-prefix evpn -s -x --with-xunit --xunit-file=${WS}/nosetest_evpn.xml &
PIDS=("${PIDS[@]}" $!)

# flowspec test
python3 $TESTDIR/flow_spec_test.py --gobgp-image $GOBGP_IMAGE --test-prefix flow -s -x --with-xunit --xunit-file=${WS}/nosetest_flow.xml &
PIDS=("${PIDS[@]}" $!)

# route reflector test
python3 $TESTDIR/route_reflector_test.py --gobgp-image $GOBGP_IMAGE --test-prefix rr -s -x --with-xunit --xunit-file=${WS}/nosetest_rr.xml &
PIDS=("${PIDS[@]}" $!)

# zebra test
python3 $TESTDIR/bgp_zebra_test.py --gobgp-image $GOBGP_IMAGE --test-prefix zebra -s -x --with-xunit --xunit-file=${WS}/nosetest_zebra.xml &
PIDS=("${PIDS[@]}" $!)

# global policy test
python3 $TESTDIR/global_policy_test.py --gobgp-image $GOBGP_IMAGE --test-prefix gpol -s -x --with-xunit --xunit-file=${WS}/nosetest_global_policy.xml &
PIDS=("${PIDS[@]}" $!)

# route server as2 test
python3 $TESTDIR/route_server_as2_test.py --gobgp-image $GOBGP_IMAGE --test-prefix as2 -s -x --with-xunit --xunit-file=${WS}/nosetest_rs_as2.xml &
PIDS=("${PIDS[@]}" $!)

# graceful restart test
python3 $TESTDIR/graceful_restart_test.py --gobgp-image $GOBGP_IMAGE --test-prefix gr -s -x --with-xunit --xunit-file=${WS}/nosetest_rs_gr.xml &
PIDS=("${PIDS[@]}" $!)

# bgp unnumbered test
python3 $TESTDIR/bgp_unnumbered_test.py --gobgp-image $GOBGP_IMAGE --test-prefix un -s -x --with-xunit --xunit-file=${WS}/nosetest_rs_un.xml &
PIDS=("${PIDS[@]}" $!)

for (( i = 0; i < ${#PIDS[@]}; ++i ))
do
    wait ${PIDS[$i]}
    if [ $? != 0 ]; then
        exit 1
    fi
done

PIDS=()

# route server malformed message test
NUM=$(python3 $TESTDIR/route_server_malformed_test.py --test-index -1 -s 2> /dev/null | awk '/invalid/{print $NF}')
PARALLEL_NUM=10
for (( i = 1; i < $(( $NUM + 1)); ++i ))
do
    python3 $TESTDIR/route_server_malformed_test.py --gobgp-image $GOBGP_IMAGE --test-prefix mal$i --test-index $i -s -x --gobgp-log-level debug --with-xunit --xunit-file=${WS}/nosetest_malform${i}.xml &
    PIDS=("${PIDS[@]}" $!)
    sleep 3
done

for (( i = 0; i < ${#PIDS[@]}; ++i ))
do
    wait ${PIDS[$i]}
    if [ $? != 0 ]; then
        exit 1
    fi
done

# route server policy test
NUM=$(python3 $TESTDIR/route_server_policy_test.py --test-index -1 -s 2> /dev/null | awk '/invalid/{print $NF}')
PARALLEL_NUM=25
for (( i = 0; i < $(( NUM / PARALLEL_NUM + 1)); ++i ))
do
    PIDS=()
    for (( j = $((PARALLEL_NUM * $i + 1)); j < $((PARALLEL_NUM * ($i+1) + 1)); ++j))
    do
        python3 $TESTDIR/route_server_policy_test.py --gobgp-image $GOBGP_IMAGE --test-prefix p$j --test-index $j -s -x --gobgp-log-level debug --with-xunit --xunit-file=${WS}/nosetest_policy${j}.xml &
        PIDS=("${PIDS[@]}" $!)
        if [ $j -eq $NUM ]; then
            break
        fi
        sleep 3
    done

    for (( j = 0; j < ${#PIDS[@]}; ++j ))
    do
        wait ${PIDS[$j]}
        if [ $? != 0 ]; then
            exit 1
        fi
    done

done

# route server policy grpc test
NUM=$(python3 $TESTDIR/route_server_policy_grpc_test.py --test-index -1 -s 2> /dev/null | awk '/invalid/{print $NF}')
PARALLEL_NUM=25
for (( i = 0; i < $(( NUM / PARALLEL_NUM + 1)); ++i ))
do
    PIDS=()
    for (( j = $((PARALLEL_NUM * $i + 1)); j < $((PARALLEL_NUM * ($i+1) + 1)); ++j))
    do
        python3 $TESTDIR/route_server_policy_grpc_test.py --gobgp-image $GOBGP_IMAGE --test-prefix pg$j --test-index $j -s -x --gobgp-log-level debug --with-xunit --xunit-file=${WS}/nosetest_policy_grpc${j}.xml &
        PIDS=("${PIDS[@]}" $!)
        if [ $j -eq $NUM ]; then
            break
        fi
        sleep 3
    done

    for (( j = 0; j < ${#PIDS[@]}; ++j ))
    do
        wait ${PIDS[$j]}
        if [ $? != 0 ]; then
            exit 1
        fi
    done

done

echo 'all tests passed successfully'
exit 0
