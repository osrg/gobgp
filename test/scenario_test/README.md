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
$ test/lib/make-gobgp-ctn.sh --tag gobgp --from-image osrg/quagga
$ test/lib/make-gobgp-ctn.sh --tag gobgp-oq --from-image osrg/quagga:v1.0
```

## Run tests

There are two ways to run tests

1. Run all tests

    You can run all scenario tests with run_all_tests.py.
    If all tests passed, you can see "all tests passed successfully" at the end of the test.

    ```shell
    $ python3 ./test/scenario_test/run_all_tests.py
    ...
    OK
    all tests passed successfully
    ```

    To increase default wait timeouts for slower environments, pass a timeout
    scale:

    ```shell
    $ python3 ./test/scenario_test/run_all_tests.py --timeout-scale 2
    ```

    The runner continues after failing pytest invocations and reports all
    failures at the end. To stop after the first failing invocation, pass:

    ```shell
    $ python3 ./test/scenario_test/run_all_tests.py --fail-fast
    ```

    To hide passing pytest output while still printing run/pass/fail progress,
    pass:

    ```shell
    $ python3 ./test/scenario_test/run_all_tests.py --quiet
    ```

1. Run each test

    You can run scenario tests individually with each test file.
    See `test/scenario_test/*.py`, for the individual test files.

    ```shell
    $ PYTHONPATH=./test python3 -m pytest test/scenario_test/<scenario test name>.py --gobgp-image=gobgp -x -s
    ...
    OK
    ```

    The same timeout scale option is available for individual pytest runs:

    ```shell
    $ PYTHONPATH=./test python3 -m pytest test/scenario_test/<scenario test name>.py --gobgp-image=gobgp -x -s --timeout-scale 2
    ```

## Clean up

A lot of containers, networks temporary files are created during the test.
Let's clean up.

```shell
$ python3 ./test/scenario_test/cleanup.py
```
