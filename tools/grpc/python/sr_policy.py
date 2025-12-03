#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import print_function

import grpc

import attribute_pb2
import common_pb2
import extcom_pb2
import gobgp_pb2
import gobgp_pb2_grpc
import nlri_pb2

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
    stub = gobgp_pb2_grpc.GoBgpServiceStub(channel)

    family = common_pb2.Family(
        afi=common_pb2.Family.AFI_IP,
        safi=common_pb2.Family.SAFI_SR_POLICY,
    )

    nlri = nlri_pb2.NLRI(
        sr_policy=nlri_pb2.SRPolicyNLRI(
            color=color,
            distinguisher=2,
            endpoint=bytes(map(int, endpoint_device.split("."))),
            length=96,
        )
    )

    attributes = [
        attribute_pb2.Attribute(
            next_hop=attribute_pb2.NextHopAttribute(next_hop=nh)
        ),
        attribute_pb2.Attribute(
            origin=attribute_pb2.OriginAttribute(origin=0)
        ),
        attribute_pb2.Attribute(
            extended_communities=attribute_pb2.ExtendedCommunitiesAttribute(
                communities=[
                    extcom_pb2.ExtendedCommunity(
                        ipv4_address_specific=extcom_pb2.IPv4AddressSpecificExtended(
                            is_transitive=False,
                            sub_type=0x02,
                            address=target_device,
                            local_admin=0,
                        )
                    )
                ]
            )
        ),
    ]

    sr_binding_sid = attribute_pb2.SRBindingSID(
        s_flag=False,
        i_flag=False,
        sid=bsid_value.to_bytes(4, byteorder="big"),
    )

    segments = [
        attribute_pb2.TunnelEncapSubTLVSRSegmentList.Segment(
            a=attribute_pb2.SegmentTypeA(
                flags=attribute_pb2.SegmentFlags(s_flag=False),
                label=label << 12,
            )
        )
        for label in sid_list
    ]

    tunnel_tlv = attribute_pb2.TunnelEncapTLV(
        type=15,
        tlvs=[
            attribute_pb2.TunnelEncapTLV.TLV(
                sr_preference=attribute_pb2.TunnelEncapSubTLVSRPreference(
                    flags=0,
                    preference=11,
                )
            ),
            attribute_pb2.TunnelEncapTLV.TLV(
                sr_binding_sid=attribute_pb2.TunnelEncapSubTLVSRBindingSID(
                    sr_binding_sid=sr_binding_sid
                )
            ),
            attribute_pb2.TunnelEncapTLV.TLV(
                sr_segment_list=attribute_pb2.TunnelEncapSubTLVSRSegmentList(
                    weight=attribute_pb2.SRWeight(flags=0, weight=12),
                    segments=segments,
                )
            ),
        ],
    )

    attributes.append(
        attribute_pb2.Attribute(
            tunnel_encap=attribute_pb2.TunnelEncapAttribute(tlvs=[tunnel_tlv])
        )
    )

    stub.AddPath(
        gobgp_pb2.AddPathRequest(
            table_type=gobgp_pb2.TABLE_TYPE_GLOBAL,
            path=gobgp_pb2.Path(
                nlri=nlri,
                pattrs=attributes,
                family=family,
                best=True,
            ),
        ),
        timeout=_TIMEOUT_SECONDS,
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

