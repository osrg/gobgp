
SCENARIO=$1
echo "travis-build-script.sh"

export GOBGP=`pwd`

if [ "$SCENARIO" != "true" ]; then
  echo "execute unit test."
  go version
  go test -v ./... || exit "$?"
  python $GOBGP/test/scenario_test/ci-scripts/build_embeded_go.py $GOBGP/docs/sources/lib.md
  exit $?
fi

echo "Docker version"
docker version
echo ""

export GOBGP_IMAGE=gobgp

sudo apt-get -q update
sudo apt-get -q -y install iputils-arping bridge-utils lv
sudo wget https://raw.github.com/jpetazzo/pipework/master/pipework -O /usr/local/bin/pipework
sudo chmod 755 /usr/local/bin/pipework

sudo -H pip --quiet install -r $GOBGP/test/pip-requires.txt

ls -al
git log | head -20

sudo fab -f $GOBGP/test/lib/base.py make_gobgp_ctn:tag=$GOBGP_IMAGE
[ "$?" != 0 ] && exit "$?"

cd $GOBGP/test/scenario_test

PIDS=()

sudo  PYTHONPATH=$GOBGP/test python route_server_test.py --gobgp-image $GOBGP_IMAGE --test-prefix rs -x &
PIDS=("${PIDS[@]}" $!)

sudo  PYTHONPATH=$GOBGP/test python route_server_test2.py --gobgp-image $GOBGP_IMAGE --test-prefix rs2 -x &
PIDS=("${PIDS[@]}" $!)

sudo  PYTHONPATH=$GOBGP/test python route_server_softreset_test.py --gobgp-image $GOBGP_IMAGE --test-prefix rs3 -x &
PIDS=("${PIDS[@]}" $!)

sudo  PYTHONPATH=$GOBGP/test python route_server_ipv4_v6_test.py --gobgp-image $GOBGP_IMAGE --test-prefix v6 -x &
PIDS=("${PIDS[@]}" $!)

sudo  PYTHONPATH=$GOBGP/test python bgp_router_test.py --gobgp-image $GOBGP_IMAGE --test-prefix bgp -x &
PIDS=("${PIDS[@]}" $!)

sudo  PYTHONPATH=$GOBGP/test python ibgp_router_test.py --gobgp-image $GOBGP_IMAGE --test-prefix ibgp -x &
PIDS=("${PIDS[@]}" $!)

sudo  PYTHONPATH=$GOBGP/test python evpn_test.py --gobgp-image $GOBGP_IMAGE --test-prefix evpn -x &
PIDS=("${PIDS[@]}" $!)

sudo  PYTHONPATH=$GOBGP/test python flow_spec_test.py --gobgp-image $GOBGP_IMAGE --test-prefix flow -x &
PIDS=("${PIDS[@]}" $!)

sudo  PYTHONPATH=$GOBGP/test python route_reflector_test.py --gobgp-image $GOBGP_IMAGE --test-prefix rr -x &
PIDS=("${PIDS[@]}" $!)

for (( i = 0; i < ${#PIDS[@]}; ++i ))
do
    wait ${PIDS[$i]}
    if [ $? != 0 ]; then
        exit 1
    fi
done

PIDS=()

sudo  PYTHONPATH=$GOBGP/test python global_policy_test.py --gobgp-image $GOBGP_IMAGE --test-prefix gpol -x &
PIDS=("${PIDS[@]}" $!)

sudo  PYTHONPATH=$GOBGP/test python route_server_as2_test.py --gobgp-image $GOBGP_IMAGE --test-prefix as2 -x &
PIDS=("${PIDS[@]}" $!)

sudo  PYTHONPATH=$GOBGP/test python graceful_restart_test.py --gobgp-image $GOBGP_IMAGE --test-prefix gr -x &
PIDS=("${PIDS[@]}" $!)

sudo  PYTHONPATH=$GOBGP/test python bgp_zebra_test.py --gobgp-image $GOBGP_IMAGE --test-prefix zebra -x -s &
PIDS=("${PIDS[@]}" $!)

sudo  PYTHONPATH=$GOBGP/test python monitor_test.py --gobgp-image $GOBGP_IMAGE --test-prefix mon -x -s &
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
NUM=$(sudo  PYTHONPATH=$GOBGP/test python route_server_malformed_test.py --test-index -1 -s 2> /dev/null | awk '/invalid/{print $NF}')
PARALLEL_NUM=10
for (( i = 1; i < $(( $NUM + 1)); ++i ))
do
    sudo  PYTHONPATH=$GOBGP/test python route_server_malformed_test.py --gobgp-image $GOBGP_IMAGE --test-prefix mal$i --test-index $i -x --gobgp-log-level debug &
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
NUM=$(sudo  PYTHONPATH=$GOBGP/test python route_server_policy_test.py --test-index -1 -s 2> /dev/null | awk '/invalid/{print $NF}')
PARALLEL_NUM=10
for (( i = 0; i < $(( NUM / PARALLEL_NUM + 1)); ++i ))
do
    PIDS=()
    for (( j = $((PARALLEL_NUM * $i + 1)); j < $((PARALLEL_NUM * ($i+1) + 1)); ++j))
    do
        sudo  PYTHONPATH=$GOBGP/test python route_server_policy_test.py --gobgp-image $GOBGP_IMAGE --test-prefix p$j --test-index $j -x --gobgp-log-level debug &
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
NUM=$(sudo  PYTHONPATH=$GOBGP/test python route_server_policy_grpc_test.py --test-index -1 -s 2> /dev/null | awk '/invalid/{print $NF}')
PARALLEL_NUM=10
for (( i = 0; i < $(( NUM / PARALLEL_NUM + 1)); ++i ))
do
    PIDS=()
    for (( j = $((PARALLEL_NUM * $i + 1)); j < $((PARALLEL_NUM * ($i+1) + 1)); ++j))
    do
        sudo  PYTHONPATH=$GOBGP/test python route_server_policy_grpc_test.py --gobgp-image $GOBGP_IMAGE --test-prefix pg$j --test-index $j -x --gobgp-log-level debug &
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
