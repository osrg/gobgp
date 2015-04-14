Route Server Scenario Test
========================

Preparation
-----------
Please set up Ubuntu 14.04 Server Edition virtual machine,
and install golang environment inside the VM.

Setup
-----
Execute the following commands inside the VM:

install the python packages and libraries required to run the test program and clone gobgp repository.
```
% sudo su -
# apt-get update
# apt-get install git
# apt-get install python-pip
# apt-get install python-dev
# git clone https://github.com/osrg/gobgp.git
# cd ./gobgp
# GOBGP_DIR=`pwd`
# cd $GOBGP_DIR/gobgpd
# go get -v
# cd $GOBGP_DIR/test/scenario_test
# pip install -r pip-requires.txt
```


This step installs other packages such as Docker container and generates some helper scripts needed by the scenario test.
```
# fab -f docker_control.py install_docker_and_tools

```

Please make sure following packages are installed properly inside the VM.

 * docker
 * bridge-utils
 * pipework


Start
-----
Please run the test script as root.

 * route_server_test.py is scenario test script.
```
# python route_server_test.py -v [ --use-local ] [--go-path=<path>]

```


 * If you want to do malformed packet test, please run route_server_malformed_test.py
```
# python route_server_malformed_test.py -v [ --use-local ] [ --go-path=<path> ]

```

- If you want to do scenario test in ipv4 and ipv6 mixed environment, please run route_server_ipv4_v6_test.py
```
# python route_server_ipv4_v6_test.py -v [ --use-local ] [ --go-path=<path> ]

```


After the test, test results will be shown.

Options
-----
 use [ --use-local ] option when execute gobgp program of local system.

 use [ --go-path ] option when not root and use sudo command.


Examples
-----
 How to use [ --use-local ] option
```
# python route_server_test.py -v --use-local
```

 How to use [ --go-path=<path> ] option
```
$ sudo -E python route_server_test.py -v --go-path=/usr/local/go/bin
```