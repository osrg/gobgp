#!/usr/bin/env sh

echo "travis-install-script.sh"

pip --quiet install -r test/pip-requires.txt

go get -v ./gobgp/
go get -v ./gobgpd/
