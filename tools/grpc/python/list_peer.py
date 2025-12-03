#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import print_function

import grpc

import gobgp_pb2
import gobgp_pb2_grpc

_TIMEOUT_SECONDS = 1000


def run():
    channel = grpc.insecure_channel('localhost:50051')
    stub = gobgp_pb2_grpc.GoBgpServiceStub(channel)

    peers = stub.ListPeer(
        gobgp_pb2.ListPeerRequest(),
        timeout=_TIMEOUT_SECONDS,
    )

    for peer in peers:
        print(peer)


if __name__ == '__main__':
    run()
