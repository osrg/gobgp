# Scenario Test

This page explains how to set up a scenario test environment and run the test.

## Contents

- [Prerequisites](#prerequisites)
- [Check](#check)
- [Set up dependencies](#set-up-dependencies)
- [Install local source code](#install-local-source-code)
- [Run test](#run-test)
- [Clean up](#clean-up)

## Prerequisites

Assume you finished setting up [Golang](https://golang.org/doc/install) and
[Docker](https://docs.docker.com/installation/ubuntulinux/) on Ubuntu 18.04
Server VM.
We recommend allocating memory more than 8GB to the VM.
Because this scenario test runs a lot of test cases concurrently.

## Check

Please check if Golang and Docker is installed correctly and
make sure the $GOPATH is defined.

```shell
$ python --version
Python 3.6.8

$ echo $GOPATH
/home/yokoi-h/work

$ sudo docker version
Client: Docker Engine - Community
 Version:           19.03.4
 API version:       1.40
 Go version:        go1.12.10
 Git commit:        9013bf583a
 Built:             Fri Oct 18 15:54:09 2019
 OS/Arch:           linux/amd64
 Experimental:      false

Server: Docker Engine - Community
 Engine:
  Version:          19.03.4
  API version:      1.40 (minimum version 1.12)
  Go version:       go1.12.10
  Git commit:       9013bf583a
  Built:            Fri Oct 18 15:52:40 2019
  OS/Arch:          linux/amd64
  Experimental:     false
 containerd:
  Version:          1.2.10
  GitCommit:        b34a5c8af56e510852c35414db4c1f4fa6172339
 runc:
  Version:          1.0.0-rc8+dev
  GitCommit:        3e425f80a8c931f88e6d94a8c831b9d5aa481657
 docker-init:
  Version:          0.18.0
  GitCommit:        fec3683
```

## Set up dependencies

Execute the following commands inside the VM to install the dependencies:

```shell
$ mkdir -p $GOPATH/src/github.com/osrg
$ cd $GOPATH/src/github.com/osrg
$ git clone https://github.com/osrg/gobgp.git
$ cd ./gobgp/test
$ sudo pip install -r pip-requires.txt
```

## Install local source code

You need to install local source code into GoBGP docker container.
You also need this operation at every modification to the source code.

```shell
$ cd $GOPATH/src/github.com/osrg/gobgp
$ sudo fab2 -r ./test/lib make-gobgp-ctn
```

## Run test

1. Run all test.

    You can run all scenario tests with run_all_tests.sh.
    If all tests passed, you can see "all tests passed successfully" at the end of the test.

    ```shell
    $ cd $GOPATH/src/github.com/osrg/gobgp/test/scenario_test
    $ ./run_all_tests.sh
    ...
    OK
    all tests passed successfully
    ```

1. Run each test.

    You can run scenario tests individually with each test file.
    See `test/scenario_test/*.py`, for the individual test files.

    ```shell
    $ cd $GOPATH/src/github.com/osrg/gobgp/test/scenario_test
    $ sudo -E PYTHONPATH=$GOBGP/test python3 <scenario test name>.py --gobgp-image=gobgp
    ...
    OK
    ```

## Clean up

A lot of containers, networks temporary files are created during the test.
Let's clean up.

```shell
$ sudo docker rm -f $(sudo docker ps -a -q -f "label=gobgp-test")
$ sudo docker network prune -f --filter "label=gobgp-test"
$ sudo rm -rf /tmp/gobgp
```
