#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import print_function

import grpc
from google.protobuf.any_pb2 import Any

import gobgp_pb2
import gobgp_pb2_grpc
import attribute_pb2

_TIMEOUT_SECONDS = 1000


def run():
    channel = grpc.insecure_channel('localhost:50051')
    stub = gobgp_pb2_grpc.GobgpApiStub(channel)

    peers = stub.ListPeer(
        gobgp_pb2.ListPeerRequest(
        ),
        _TIMEOUT_SECONDS,
    )

    for peer in peers:
        print(peer)


if __name__ == '__main__':
    run()
