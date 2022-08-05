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

```shell
$ python --version
Python 3.9.7

$ go version
go version go1.17 linux/arm64

$ docker version
Client:
 Version:           20.10.7
 API version:       1.41
 Go version:        go1.13.8
 Git commit:        20.10.7-0ubuntu5.1
 Built:             Mon Nov  1 00:34:28 2021
 OS/Arch:           linux/arm64
 Context:           default
 Experimental:      true

Server:
 Engine:
  Version:          20.10.7
  API version:      1.41 (minimum version 1.12)
  Go version:       go1.13.8
  Git commit:       20.10.7-0ubuntu5.1
  Built:            Thu Oct 21 23:58:58 2021
  OS/Arch:          linux/arm64
  Experimental:     false
 containerd:
  Version:          1.5.5-0ubuntu3
  GitCommit:
 runc:
  Version:          1.0.1-0ubuntu2
  GitCommit:
 docker-init:
  Version:          0.19.0
  GitCommit:
```

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
$ fab -r ./test/lib make-gobgp-ctn
```

## Run tests

There are two ways to run tests

1. Run all tests

    You can run all scenario tests with run_all_tests.sh.
    If all tests passed, you can see "all tests passed successfully" at the end of the test.

    ```shell
    $ ./test/scenario_test/run_all_tests.sh
    ...
    OK
    all tests passed successfully
    ```

1. Run each test

    You can run scenario tests individually with each test file.
    See `test/scenario_test/*.py`, for the individual test files.

    ```shell
    $ PYTHONPATH=./test python3 test/scenario_test/<scenario test name>.py --gobgp-image=gobgp
    ...
    OK
    ```

## Clean up

A lot of containers, networks temporary files are created during the test.
Let's clean up.

```shell
$ docker rm -f $(sudo docker ps -a -q -f "label=gobgp-test")
$ docker network prune -f --filter "label=gobgp-test"
$ rm -rf /tmp/gobgp
```
