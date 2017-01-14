#!/usr/bin/env sh

echo "travis-build-script.sh"

sudo PYTHONPATH=test python test/scenario_test/$TEST --gobgp-image $DOCKER_IMAGE -x -s
