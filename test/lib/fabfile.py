import os
from fabric import task
from invoke import run as local
from base import CmdBuffer


@task
def make_gobgp_ctn(ctx, tag='gobgp',
                   local_gobgp_path='',
                   from_image='osrg/quagga'):
    if local_gobgp_path == '':
        local_gobgp_path = os.getcwd()

    c = CmdBuffer()
    c << 'FROM {0}'.format(from_image)
    c << 'ENV GO111MODULE on'
    c << 'ADD gobgp /tmp/gobgp'
    c << 'RUN cd /tmp/gobgp && go install ./cmd/gobgpd ./cmd/gobgp'

    rindex = local_gobgp_path.rindex('gobgp')
    if rindex < 0:
        raise Exception('{0} seems not gobgp dir'.format(local_gobgp_path))

    workdir = local_gobgp_path[:rindex]
    os.chdir(workdir)
    local('echo \'{0}\' > Dockerfile'.format(str(c)))
    local('docker build -t {0} .'.format(tag))
    local('rm Dockerfile')
