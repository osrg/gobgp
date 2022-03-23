#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import print_function

import grpc
from google.protobuf.any_pb2 import Any

import gobgp_pb2
import gobgp_pb2_grpc
import attribute_pb2

_TIMEOUT_SECONDS = 1000


def go_bgp_subnet(color, endpoint_device, target_device, sid_list, bsid_value, nh):
    """
    inject or delete an route with <ACME>-CIDR and <ACME>-SCRUBBING community
    NLRI
    ORIGIN
    AS_PATH
    LP
    EXTENDED COMMUNITIES
     RT
    TUNNEL ENCAP
     TLVs
      SR Policy
       SUB-TLVs
        Preference
        Binding-SID
        SEG-LIST
         WEIGHT
         SEGMENT(1..n)
    """
    channel = grpc.insecure_channel("localhost:50051")
    stub = gobgp_pb2_grpc.GobgpApiStub(channel)
    attributes = []
    segments = []
    # bgp-sr-te safi
    family = gobgp_pb2.Family(
        afi=gobgp_pb2.Family.AFI_IP, safi=gobgp_pb2.Family.SAFI_SR_POLICY
    )

    # sr-te policy nlri
    nlri = Any()
    nlri.Pack(
        attribute_pb2.SRPolicyNLRI(
            color=color,
            distinguisher=2,
            endpoint=bytes(map(int, endpoint_device.split("."))),
            length=96,
        )
    )

    # next-hop
    next_hop = Any()
    next_hop.Pack(
        attribute_pb2.NextHopAttribute(
            next_hop=nh,
        )
    )
    attributes.append(next_hop)

    # Origin
    origin = Any()
    origin.Pack(attribute_pb2.OriginAttribute(origin=0))
    attributes.append(origin)
    # Ext RT Communities
    rt = Any()
    rt.Pack(
        attribute_pb2.IPv4AddressSpecificExtended(
            address=target_device, local_admin=0, sub_type=0x02, is_transitive=False
        )
    )
    communities = Any()
    communities.Pack(
        attribute_pb2.ExtendedCommunitiesAttribute(
            communities=[rt],
        )
    )
    attributes.append(communities)
    # generic sid used for bsid
    sid = Any()
    sid.Pack(
        attribute_pb2.SRBindingSID(
            s_flag=False, i_flag=False, sid=(bsid_value).to_bytes(4, byteorder="big")
        )
    )
    # bsid
    bsid = Any()
    bsid.Pack(attribute_pb2.TunnelEncapSubTLVSRBindingSID(bsid=sid))

    # generic segment lbl
    for n in sid_list:
        segment = Any()
        segment.Pack(
            attribute_pb2.SegmentTypeA(
                flags=attribute_pb2.SegmentFlags(s_flag=False), label=n << 12
            )
        )
        segments.append(segment)
    # segment list
    seglist = Any()
    seglist.Pack(
        attribute_pb2.TunnelEncapSubTLVSRSegmentList(
            weight=attribute_pb2.SRWeight(flags=0, weight=12),
            segments=segments,
        )
    )
    # pref
    pref = Any()
    pref.Pack(attribute_pb2.TunnelEncapSubTLVSRPreference(flags=0, preference=11))
    # path name not used for now
    cpn = Any()
    cpn.Pack(
        attribute_pb2.TunnelEncapSubTLVSRCandidatePathName(
            candidate_path_name="test-path"
        )
    )
    # priority not used for now
    pri = Any()
    pri.Pack(attribute_pb2.TunnelEncapSubTLVSRPriority(priority=10))
    tun = Any()

    # generate tunnel
    tun.Pack(
        attribute_pb2.TunnelEncapAttribute(
            tlvs=[
                attribute_pb2.TunnelEncapTLV(
                    type=15,
                    tlvs=[
                        pref,
                        bsid,
                        seglist,
                        # cpn,
                        # pri,
                    ],
                )
            ]
        )
    )

    attributes.append(tun)

    stub.AddPath(
        gobgp_pb2.AddPathRequest(
            table_type=gobgp_pb2.GLOBAL,
            path=gobgp_pb2.Path(
                nlri=nlri,
                pattrs=attributes,
                family=family,
                best=True,
            ),
        ),
        _TIMEOUT_SECONDS,
    )


if __name__ == "__main__":
    nh = "10.100.1.201"  # gobgp ip
    endpoint_device = "10.6.6.6"  # https://datatracker.ietf.org/doc/html/draft-ietf-idr-segment-routing-te-policy-16#section-2.3
    color = 100
    target_device = "10.1.1.1"  # intended head-ends for the advertised SR Policy update
    bsid_value = 300004  # bsid
    sid_list = [200002, 200006]  # label stack
    go_bgp_subnet(
        color,
        endpoint_device=endpoint_device,
        target_device=target_device,
        bsid_value=bsid_value,
        sid_list=sid_list,
        nh=nh,
    )

