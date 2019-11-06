#!/usr/bin/env bash
# stolen from prometheus
#
# Generate all protobuf bindings.
# Run from repository root.

set -x
set -e
set -u

if ! [[ "$0" =~ "tools/grpc/genproto.sh" ]]; then
	echo "must be run from repository root"
	exit 255
fi

if ! [[ $(protoc --version) =~ "3.7.1" ]]; then
	echo "could not find protoc 3.7.1, is it installed + in PATH?"
	exit 255
fi

echo "installing plugins"
GO111MODULE=on go mod download

INSTALL_PKGS="github.com/golang/protobuf/protoc-gen-go"
for pkg in ${INSTALL_PKGS}; do
    GO111MODULE=on go install "$pkg"
done

GOBGP="${PWD}"

echo "generating code"
protoc -I "${GOBGP}"/api \
       --go_out=plugins=grpc:${GOBGP}/api "${GOBGP}"/api/*.proto
