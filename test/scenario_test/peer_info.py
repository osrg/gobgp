# Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


class Peer:
    def __init__(self, peer_ip, peer_id, peer_as, ip_version):
        self.peer_ip = peer_ip
        self.peer_id = peer_id
        self.peer_as = peer_as
        self.ip_version = ip_version
        self.neighbors = []
        self.destinations = {}


class Destination:
    def __init__(self, prefix):
        self.prefix = prefix
        self.paths = []


class Path:
    def __init__(self, network, nexthop):
        self.network = network
        self.nexthop = nexthop
        self.origin = None
        self.as_path = []
        self.metric = None
