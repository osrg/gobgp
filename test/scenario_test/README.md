# Scenario Test

This page explains how to set up a scenario test environment and run the test.

## Contents

- [Scenario Test](#scenario-test)
  - [Contents](#contents)
  - [Prerequisites](#prerequisites)
  - [Set up dependencies](#set-up-dependencies)
  - [Build GoBGP docker image form your source code](#build-gobgp-docker-image-form-your-source-code)
  - [Run tests](#run-tests)
  - [Clean up](#clean-up)

## Prerequisites

Go, Docker, and Python3 need to be set up.

## Set up dependencies

Execute the following commands to install the dependencies:

```shell
$ git clone https://github.com/osrg/gobgp
$ cd ./gobgp
$ python3 -m venv .test
$ source .test/bin/activate
$ pip install -r test/pip-requires.txt
```

## Build GoBGP docker image form your source code

You need to build GoBGP docker image to test from the source code that you modified. You need run the following command every time you modify the source code.

```shell
$ test/lib/make-gobgp-ctn.sh
```

Three tests need a second image built on an older Quagga. Build it too if you
run them:

```shell
$ test/lib/make-gobgp-ctn.sh --tag gobgp-oq --from-image osrg/quagga:v1.0
```

## Run tests

Run a single test file with pytest:

```shell
$ PYTHONPATH=./test python3 -m pytest test/scenario_test/<scenario test name>.py --gobgp-image gobgp -s -x
```

`-s` shows the output of the test while it runs. `-x` stops at the first
failure. See `test/scenario_test/*_test*.py` for the test files.

Three tests use zebra from an older Quagga and need the `gobgp-oq` image:
`bgp_zebra_nht_test.py`, `zapi_v3_test.py` and `zapi_v3_multipath_test.py`.
Pass `--gobgp-image gobgp-oq` for them:

```shell
$ PYTHONPATH=./test python3 -m pytest test/scenario_test/zapi_v3_test.py --gobgp-image gobgp-oq -s -x
```

Two tests need the host to be set up first. `bgp_unnumbered_test.py` needs IPv6
in Docker. Do not assign an IPv6 address to the `docker0` bridge, so that two
containers get a point to point link:

```shell
$ echo '{"ipv6": true, "fixed-cidr-v6": "2001:db8:1::/64"}' | sudo tee /etc/docker/daemon.json
$ sudo systemctl restart docker
$ sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0
$ sudo sysctl -w net.ipv6.conf.default.disable_ipv6=0
$ sudo sysctl -w net.ipv6.conf.docker0.disable_ipv6=1
```

`tcp_md5_test.py` needs the vrf module:

```shell
$ sudo apt-get install -y linux-modules-extra-$(uname -r)
$ sudo modprobe vrf
```

You can also run every test in one command:

```shell
$ PYTHONPATH=./test python3 -m pytest test/scenario_test/ --gobgp-image gobgp -s -x
```

This runs the test files one after another in a single process, so it takes a
long time. It also passes one image to every file, so the three tests that need
`gobgp-oq` fail. CI runs each test file as its own job, so opening a pull
request is the faster way to get the full result.

## Clean up

A lot of containers, networks temporary files are created during the test.
Let's clean up.

```shell
$ docker rm -f $(sudo docker ps -a -q -f "label=gobgp-test")
$ docker network prune -f --filter "label=gobgp-test"
$ rm -rf /tmp/gobgp
```
