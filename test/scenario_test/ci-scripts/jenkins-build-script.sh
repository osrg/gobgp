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

sudo docker rmi $(docker images | grep "^<none>" | awk "{print $3}")

sudo fab -f $GOBGP/test/scenario_test/lib/base.py make_gobgp_ctn --set tag=$GOBGP_IMAGE

cd $GOBGP/gobgpd
$GOROOT/bin/go get -v
cd $GOBGP/test/scenario_test
set +e

sudo -E pip install -r pip-requires.txt

# route server test
sudo -E python route_server_test.py --gobgp-image $GOBGP_IMAGE --go-path $GOROOT/bin -s --with-xunit
RET1=$?
mv nosetests.xml ${WS}/nosetest.xml

# route server ipv4 ipv6 test
sudo -E python route_server_ipv4_v6_test.py --gobgp-image $GOBGP_IMAGE --go-path $GOROOT/bin -s --with-xunit
RET2=$?
mv nosetests.xml ${WS}/nosetest_ip.xml

# route server malformed message test
sudo -E python route_server_malformed_test.py --gobgp-image $GOBGP_IMAGE --go-path $GOROOT/bin -s --with-xunit
RET3=$?
mv nosetests.xml ${WS}/nosetest_malformed.xml

# bgp router test
sudo -E python bgp_router_test.py --gobgp-image $GOBGP_IMAGE --go-path $GOROOT/bin -s --with-xunit
RET4=$?
mv nosetests.xml ${WS}/nosetest_bgp.xml

# route server policy test
sudo -E python route_server_policy_test.py --gobgp-image $GOBGP_IMAGE --go-path $GOROOT/bin -s --with-xunit
RET5=$?
mv nosetests.xml ${WS}/nosetest_policy.xml

# bgp router test
sudo -E python ibgp_router_test.py --gobgp-image $GOBGP_IMAGE --go-path $GOROOT/bin -s --with-xunit
RET6=$?
mv nosetests.xml ${WS}/nosetest_ibgp.xml

if [ $RET1 != 0 ] || [ $RET2 != 0 ] || [ $RET3 != 0 ] || [ $RET4 != 0 ] || [ $RET5 != 0 ] || [ $RET6 != 0 ]; then
  exit 1
fi
exit 0
