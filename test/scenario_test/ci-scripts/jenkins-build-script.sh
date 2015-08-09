# renew GOPATH
rm -rf /usr/local/jenkins/{bin,pkg,src}
mkdir /usr/local/jenkins/{bin,pkg,src}
mkdir -p /usr/local/jenkins/src/github.com/osrg/

export GOBGP_IMAGE=gobgp
export GOPATH=/usr/local/jenkins
export GOROOT=/usr/local/go
export GOBGP=/usr/local/jenkins/src/github.com/osrg/gobgp

WS=`pwd`
cp -r ../workspace $GOBGP
pwd
cd $GOBGP
ls -al
git log | head -20

sudo docker rmi $(sudo docker images | grep "^<none>" | awk '{print $3}')
sudo docker rm -f $(sudo docker ps -a -q)

sudo fab -f $GOBGP/test/scenario_test/lib/base.py make_gobgp_ctn --set tag=$GOBGP_IMAGE

cd $GOBGP/gobgpd
$GOROOT/bin/go get -v
cd $GOBGP/test/scenario_test
set +e

sudo -E pip install -r pip-requires.txt

# route server test
sudo -E python route_server_test.py --gobgp-image $GOBGP_IMAGE --test-prefix rs -s --with-xunit --xunit-file=${WS}/nosetest.xml
RET1=$?

# route server ipv4 ipv6 test
sudo -E python route_server_ipv4_v6_test.py --gobgp-image $GOBGP_IMAGE --test-prefix v6 -s --with-xunit --xunit-file=${WS}/nosetest_ip.xml
RET2=$?

# route server malformed message test
sudo -E python route_server_malformed_test.py --gobgp-image $GOBGP_IMAGE --go-path $GOROOT/bin -s --with-xunit --xunit-file=${WS}/nosetest_malformed.xml
RET3=$?

# route server policy test
sudo -E python route_server_policy_test.py --gobgp-image $GOBGP_IMAGE --go-path $GOROOT/bin -s --with-xunit --xunit-file=${WS}/nosetest_policy.xml
RET4=$?

if [ $RET1 != 0 ] || [ $RET2 != 0 ] || [ $RET3 != 0 ] || [ $RET4 != 0 ]; then
    exit 1
fi

PIDS=()

# bgp router test
sudo -E python bgp_router_test.py --gobgp-image $GOBGP_IMAGE --test-prefix bgp -s -x --with-xunit --xunit-file=${WS}/nosetest_bgp.xml &
PIDS=("${PIDS[@]}" $!)

# ibgp router test
sudo -E python ibgp_router_test.py --gobgp-image $GOBGP_IMAGE --test-prefix ibgp -s -x --with-xunit --xunit-file=${WS}/nosetest_ibgp.xml &
PIDS=("${PIDS[@]}" $!)

# evpn test
sudo -E python evpn_test.py --gobgp-image $GOBGP_IMAGE --test-prefix evpn -s -x --with-xunit --xunit-file=${WS}/nosetest_evpn.xml&
PIDS=("${PIDS[@]}" $!)

# flowspec test
sudo -E python flow_spec_test.py --gobgp-image $GOBGP_IMAGE --test-prefix flow -s -x --with-xunit --xunit-file=${WS}/nosetest_flow.xml&
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
