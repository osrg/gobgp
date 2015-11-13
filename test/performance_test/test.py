from lib.gobgp import *
from lib.quagga import *
from lib.bird import *
from fabric.api import local
from optparse import OptionParser
import sys
import os

def make_tester_ctn(tag='tester', local_gobgp_path='', from_image='osrg/quagga'):
    if local_gobgp_path == '':
        local_gobgp_path = os.getcwd()

    c = CmdBuffer()
    c << 'FROM {0}'.format(from_image)
    c << 'ADD gobgp /go/src/github.com/osrg/gobgp/'
    c << 'RUN go get github.com/osrg/gobgp/test/performance_test'
    c << 'RUN go install github.com/osrg/gobgp/test/performance_test'

    rindex = local_gobgp_path.rindex('gobgp')
    if rindex < 0:
        raise Exception('{0} seems not gobgp dir'.format(local_gobgp_path))

    workdir = local_gobgp_path[:rindex]
    with lcd(workdir):
        local('echo \'{0}\' > Dockerfile'.format(str(c)))
        local('docker build -t {0} .'.format(tag))
        local('rm Dockerfile')


class DummyPeer(object):
    def __init__(self, asn):
        self.asn = asn

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("-t", "--target", dest="target_rs", default="gobgp")
    parser.add_option("-n", "--num-peer", dest="num_peer", type="int", default=1000)
    parser.add_option("-p", "--num-prefix", dest="num_prefix", type="int", default=1000)
    parser.add_option("-l", "--log-level", dest="log_level")
    parser.add_option("-u", "--unique", dest="unique", action="store_true")
    parser.add_option("-r", "--route-server", dest="route_server", action="store_true")
    (options, args) = parser.parse_args()

    if options.target_rs.startswith("gobgp"):
        target = GoBGPContainer("target", 1000, "10.10.0.1", log_level='info', ctn_image_name=options.target_rs)
    elif options.target_rs == "quagga":
        target = QuaggaBGPContainer("target", 1000, "10.10.0.1")
    elif options.target_rs == "bird":
        target = BirdContainer("target", 1000, "10.10.0.1")
    else:
        print 'Unknown target implementation:', options.target_rs
        sys.exit(1)

    if options.num_peer < 0 or options.num_peer > 255*255:
        print 'invalid number of peer'
        sys.exit(1)

    br = Bridge("br01", with_ip=False)
    tester = Container("tester", "tester")
    tester.shared_volumes.append(('/tmp', '/root/shared_volume'))
    tester.run()
    target.run()
    br.addif(tester)
    br.addif(target)
    target.local("ip a add 10.10.0.1/16 dev eth1")

    c = CmdBuffer()
    c << "#!/bin/sh"
    for i in range(options.num_peer):
        p = DummyPeer(i+1001)
        neigh_addr = '10.10.{0}.{1}/16'.format((i+2)/255, (i+2)%255)
        target.peers[p] = {'neigh_addr': neigh_addr,
                      'passwd': None,
                      'evpn': False,
                      'flowspec': False,
                      'is_rs_client': options.route_server,
                      'is_rr_client': False,
                      'cluster_id': None,
                      'policies': {},
                      'passive': True,
                      'local_addr': '10.10.0.1'}
        c << "ip a add {0} dev eth1".format(neigh_addr)
    with open('/tmp/setup_tester.sh', 'w') as f:
        f.write(str(c))
    local('chmod +x /tmp/setup_tester.sh')
    tester.local("/root/shared_volume/setup_tester.sh")

    c = CmdBuffer()
    c << "#!/bin/sh"
    c << "performance_test -n {0} -p {1} -l {2} {3} {4} > /root/shared_volume/test.log".format(options.num_peer, options.num_prefix, options.log_level, '-u' if options.unique else '', ' '.join(args))
    with open('/tmp/start_test.sh', 'w') as f:
        f.write(str(c))
    local('chmod +x /tmp/start_test.sh')

    target.create_config()
    target.reload_config()

    tester.local("/root/shared_volume/start_test.sh")
