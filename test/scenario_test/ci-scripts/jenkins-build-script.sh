# renew GOPATH
rm -rf /usr/local/jenkins/{bin,pkg,src}
mkdir /usr/local/jenkins/{bin,pkg,src}
mkdir -p /usr/local/jenkins/src/github.com/osrg/

export GOBGP_IMAGE=gobgp
export GOPATH=/usr/local/jenkins
export GOROOT=/usr/local/go
export GOBGP=/usr/local/jenkins/src/github.com/osrg/gobgp
export WS=`pwd`

cp -r ../workspace $GOBGP
pwd
cd $GOBGP
ls -al
git log | head -20

sudo docker rmi $(sudo docker images | grep "^<none>" | awk '{print $3}')
sudo docker rm -f $(sudo docker ps -a -q)

for link in $(ip li | awk '/(_br|veth)/{sub(":","", $2); print $2}')
do
    sudo ip li set down $link
    sudo ip li del $link
done

sudo fab -f $GOBGP/test/scenario_test/lib/base.py make_gobgp_ctn --set tag=$GOBGP_IMAGE

cd $GOBGP/gobgpd
$GOROOT/bin/go get -v

cd $GOBGP/test/scenario_test

./run_all_tests.sh
