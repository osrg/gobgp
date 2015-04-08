export GOPATH=/usr/local/jenkins
export GOROOT=/usr/local/go
export GOBGP=/usr/local/jenkins/src/github.com/osrg/gobgp

WS=`pwd`
rm -rf $GOBGP
cp -r ../workspace $GOBGP
pwd
cd $GOBGP
ls -al
git log | head -10

cd $GOBGP/gobgpd
$GOROOT/bin/go get -v
cd $GOBGP/test/scenario_test
set +e
sudo -E python route_server_test.py --use-local --go-path $GOROOT/bin -s --with-xunit
RET1=$?
mv nosetests.xml ${WS}/nosetest.xml

sudo -E python route_server_ipv4_v6_test.py --use-local --go-path $GOROOT/bin -s --with-xunit
RET2=$?
mv nosetests.xml ${WS}/nosetest_ip.xml

sudo -E python route_server_malformed_test.py --use-local --go-path $GOROOT/bin -s --with-xunit
RET3=$?
mv nosetests.xml ${WS}/nosetest_malformed.xml

sudo -E python bgp_router_test.py --use-local --go-path $GOROOT/bin -s --with-xunit
RET4=$?
mv nosetests.xml ${WS}/nosetest_bgp.xml

if [ $RET1 != 0 ] || [ $RET2 != 0 ] || [ $RET3 != 0 ] || [ $RET4 != 0 ]; then
  exit 1
fi
exit 0