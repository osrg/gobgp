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

    local('CGO_ENABLED=0 go build "-ldflags=-s -w -buildid=" ./cmd/gobgp')
    local('CGO_ENABLED=0 go build "-ldflags=-s -w -buildid=" ./cmd/gobgpd')

    c = CmdBuffer()
    c << 'FROM {0}'.format(from_image)
    c << 'COPY gobgp/gobgpd /go/bin/gobgpd'
    c << 'COPY gobgp/gobgp /go/bin/gobgp'

    rindex = local_gobgp_path.rindex('gobgp')
    if rindex < 0:
        raise Exception('{0} seems not gobgp dir'.format(local_gobgp_path))

    workdir = local_gobgp_path[:rindex]
    os.chdir(workdir)
    local('echo \'{0}\' > Dockerfile'.format(str(c)))
    local('docker build -t {0} .'.format(tag))
    local('rm Dockerfile')
