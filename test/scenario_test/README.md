Route Server test
========================

Preparation
-----------
Set up Ubuntu 14.04 Server Edition Virtual Machine environment.

and Please prepare in  go language execution environment.

Setup
-----
Open a terminal and execute the following commands:

We will install the python library required to run the test program.
```
% sudo su -
# apt-get install python-pip
# apt-get install python-dev
# git clone https://github.com/osrg/gobgp.git
# cd ./gobgp
# go get -v
# cd ./test/scenario_test
# pip install -r pip-requires.txt
```


We will install the package, such as Docker required to perform the test.
```
# fab -f docker_control.py install_docker_and_tools

```

Please following package is sure that it is installed.

 ・docker

 ・bridge-utils

 ・pipework


Start
-----
Please run the command nosetests.
```
# nosetests -v route_server_test.py

```

if you run the test of malformed when execute this command.
```
# nosetests -v route_server_malformed_test.py

```

After the end of the test, gobgp is normally if OK is displayed.
