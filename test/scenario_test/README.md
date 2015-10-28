Route Server Scenario Test
========================

Preparation
-----------
Please set up Ubuntu 14.04 Server Edition virtual machine,
and install golang environment inside the VM.

Setup
-----
Execute the following commands inside the VM:

- ##### 1. Install and setting the packages required to run the scenario test.
```shell
$ sudo apt-get update
$ sudo apt-get install git python-pip python-dev iputils-arping bridge-utils lv
$ sudo wget https://raw.github.com/jpetazzo/pipework/master/pipework -O /usr/local/bin/pipework
$ sudo chmod 755 /usr/local/bin/pipework
$ sudo apt-key adv --keyserver hkp://pgp.mit.edu:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D
$ sudo apt-get install docker-engine
$ gpasswd -a `whoami` docker
```
<br>

- ##### 2. Get each docker image from Docker Hub.
```shell
$ sudo docker pull osrg/golang:1.5
$ sudo docker pull osrg/quagga
$ sudo docker pull osrg/gobgp
```
<br>


- ##### 3. Download gobgp and install python libraries.
```shell
$ git clone https://github.com/osrg/gobgp.git
$ cd ./gobgp
$ GOBGP_DIR=`pwd`
$ cd ${GOBGP_DIR}/test/scenario_test
$ pip install -r pip-requires.txt
```
<br>


Start
-----
##### All scenario test
You can run the all scenario test in the following shell script.
```shell
./run_all_tests.sh [<option>...]
```
<br>


##### If the individual to run the scenario test

 - test of bgp_router_test only
```shell
sudo -E python bgp_router_test.py [<option>...] -s
```

 - test of bgp_zebra_test only
```shell
sudo -E python bgp_zebra_test.py [<option>...] -s
```

 - test of evpn_test only
```shell
sudo -E python evpn_test.py [<option>...] -s
```

 - test of flow_spec_test only
```shell
sudo -E python flow_spec_test.py [<option>...] -s
```

 - test of global_policy_test only
```shell
sudo -E python global_policy_test.py [<option>...] -s
```

 - test of ibgp_router_test only
```shell
sudo -E python ibgp_router_test.py [<option>...] -s
```

 - test of route_reflector_test only
```shell
sudo -E python route_reflector_test.py [<option>...] -s
```

 - test of route_server_ipv4_v6_test only
```shell
sudo -E python route_server_ipv4_v6_test.py [<option>...] -s
```

 - test of route_server_test only
```shell
sudo -E python route_server_test.py [<option>...] -s
```

 - test of route_server_policy_test only
```shell
sudo -E python route_server_policy_test.py [<option>...] -s
```

 - test of route_server_policy_grpc_test only
```shell
sudo -E python route_server_policy_grpc_test.py [<option>...] -s
```

Options
-----
| short  |long               | description                    |
|--------|-------------------|--------------------------------|
| -      | --test-prefix     | filename format                |
| -      | --gobgp-image     | output directory of dump files |
| -      | --exabgp-path     | filename format                |
| -      | --gobgp-log-level | output directory of dump files |
| -      | --test-index      | output directory of dump files |
