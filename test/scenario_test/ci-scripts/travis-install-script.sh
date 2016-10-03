#!/usr/bin/env sh

echo "travis-install-script.sh"

sudo -H pip --quiet install -r test/pip-requires.txt

sudo fab -f test/lib/base.py make_gobgp_ctn:tag=$DOCKER_IMAGE,from_image=$FROM_IMAGE
