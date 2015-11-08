Performance Test
===

[Hoofprints](https://github.com/sspies8684/hoofprints) inspired route-server performance test suite

## Prerequisites

Follow the 'Prerequisites' and 'Set up dependencies' section of [Scenario Test](https://github.com/osrg/gobgp/blob/master/test/scenario_test/README.md).

## Create tester container

```shell
$ cd $GOPATH/src/github.com/osrg/gobgp
$ sudo fab -f ./test/lib/base.py make_gobgp_ctn:tag=gobgp
$ sudo fab -f ./test/performance_test/test.py make_tester_ctn:tag=tester,from_image=gobgp
```

## Run test

```shell
$ cd $GOPATH/src/github.com/osrg/gobgp/test/performance_test
$ sudo PYTHONPATH=../ python test.py -t gobgp -n 1000 T1
$ sudo PYTHONPATH=../ python test.py -t quagga -n 1000 T1
```
