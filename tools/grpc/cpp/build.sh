#!/bin/bash

GOBGP_PATH=${GOPATH}/src/github.com/osrg/gobgp

cd ${GOBGP_PATH}/cmd/gobgp/lib
go build -buildmode=c-shared -o libgobgp.so *.go
cd ${GOBGP_PATH}/tools/grpc/cpp
ln -sf ${GOBGP_PATH}/cmd/gobgp/lib/libgobgp.h
ln -sf ${GOBGP_PATH}/cmd/gobgp/lib/libgobgp.so
ln -sf ${GOBGP_PATH}/api/gobgp.proto gobgp_api_client.proto
make
