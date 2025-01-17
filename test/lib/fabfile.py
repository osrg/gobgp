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
    c << 'COPY gobgpd /go/bin/gobgpd'
    c << 'COPY gobgp /go/bin/gobgp'

    os.chdir(local_gobgp_path)
    local('echo \'{0}\' > Dockerfile'.format(str(c)))
    local('docker build -t {0} .'.format(tag))
    local('rm Dockerfile')
