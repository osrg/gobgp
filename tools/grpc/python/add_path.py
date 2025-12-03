#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import print_function

import grpc

import gobgp_pb2
import gobgp_pb2_grpc
import attribute_pb2
import common_pb2
import nlri_pb2

_TIMEOUT_SECONDS = 1000


def run():
    channel = grpc.insecure_channel('localhost:50051')
    stub = gobgp_pb2_grpc.GoBgpServiceStub(channel)

    nlri = nlri_pb2.NLRI(
        prefix=nlri_pb2.IPAddressPrefix(
            prefix_len=24,
            prefix="10.0.0.0",
        )
    )

    as_segment = attribute_pb2.AsSegment(
        type=attribute_pb2.AsSegment.TYPE_AS_SEQUENCE,
        numbers=[100, 200],
    )

    attributes = [
        attribute_pb2.Attribute(
            origin=attribute_pb2.OriginAttribute(origin=2)  # ORIGIN_INCOMPLETE
        ),
        attribute_pb2.Attribute(
            as_path=attribute_pb2.AsPathAttribute(segments=[as_segment])
        ),
        attribute_pb2.Attribute(
            next_hop=attribute_pb2.NextHopAttribute(next_hop="1.1.1.1")
        ),
    ]

    stub.AddPath(
        gobgp_pb2.AddPathRequest(
            table_type=gobgp_pb2.TABLE_TYPE_GLOBAL,
            path=gobgp_pb2.Path(
                nlri=nlri,
                pattrs=attributes,
                family=common_pb2.Family(
                    afi=common_pb2.Family.AFI_IP,
                    safi=common_pb2.Family.SAFI_UNICAST,
                ),
            )
        ),
        timeout=_TIMEOUT_SECONDS,
    )

if __name__ == '__main__':
    run()
