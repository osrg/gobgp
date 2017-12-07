#!/bin/bash

sudo docker rm -f $(sudo docker ps -a -q -f "name=osrg-gobgp-test_*")
sudo docker network prune -f --filter "label=osrg-gobgp-test"
sudo rm -rf /tmp/gobgp
