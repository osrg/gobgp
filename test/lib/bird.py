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

from base import *

class BirdContainer(BGPContainer):

    WAIT_FOR_BOOT = 1
    SHARED_VOLUME = '/etc/bird'

    def __init__(self, name, asn, router_id, ctn_image_name='osrg/bird',
                 log_level='info'):
        super(BirdContainer, self).__init__(name, asn, router_id,
                                            ctn_image_name)
        self.log_level = log_level
        self.shared_volumes.append((self.config_dir, self.SHARED_VOLUME))

    def _start_bird(self):
        c = CmdBuffer()
        c << '#!/bin/bash'
        c << 'bird'
        cmd = 'echo "{0:s}" > {1}/start.sh'.format(c, self.config_dir)
        local(cmd)
        cmd = 'chmod 755 {0}/start.sh'.format(self.config_dir)
        local(cmd)
        self.local('{0}/start.sh'.format(self.SHARED_VOLUME))

    def run(self):
        super(BirdContainer, self).run()
        self.reload_config()
        return self.WAIT_FOR_BOOT

    def create_config(self):
        c = CmdBuffer()
        c << 'router id {0};'.format(self.router_id)
        c << 'listen bgp port 179;'
        if self.log_level == 'info':
            c << 'log "{0}/bird.log" {{error, fatal, bug, warning}};'.format(self.SHARED_VOLUME)
        elif self.log_level == 'debug':
            c << 'log "{0}/bird.log" all;'.format(self.SHARED_VOLUME)
        c << 'debug protocols all;'
        c << 'protocol device { }'
        c << 'protocol direct {'
        c << '  disabled;'
        c << '}'
        c << 'protocol kernel {'
        c << '  disabled;'
        c << '}'
        c << 'table master;'
        for peer, info in self.peers.iteritems():
            if info['is_rs_client']:
                c << 'table table_{0};'.format(peer.asn)
                c << 'protocol pipe pipe_{0} {{'.format(peer.asn)
                c << '  table master;'
                c << '  mode transparent;'
                c << '  peer table table_{0};'.format(peer.asn)
                c << '  import all;'
                c << '  export all;'
                c << '}'
            c << 'protocol bgp bgp_{0} {{'.format(peer.asn)
            c << '  local as {0};'.format(self.asn)
            n_addr = info['neigh_addr'].split('/')[0]
            c << '  neighbor {0} as {1};'.format(n_addr, peer.asn)
            c << '  import all;'
            c << '  export all;'
            if info['is_rs_client']:
                c << '  rs client;'
            c << '}'

        with open('{0}/bird.conf'.format(self.config_dir), 'w') as f:
            print colors.yellow('[{0}\'s new config]'.format(self.name))
            print colors.yellow(indent(str(c)))
            f.writelines(str(c))

    def reload_config(self):
        if len(self.peers) == 0:
            return

        def _reload():
            def _is_running():
                ps = self.local('ps', capture=True)
                running = False
                for line in ps.split('\n')[1:]:
                    if 'bird' in line:
                        running = True
                return running
            if _is_running():
                self.local('birdc configure')
            else:
                self._start_bird()
            time.sleep(1)
            if not _is_running():
                raise RuntimeError()
        try_several_times(_reload)
