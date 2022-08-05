# Using SR Policy in GoBGP library mode

This page explains how to use GoBGP for Injecting SR Policy. This example shows how to build new SR Policy NLRI and associated with NLRI attributes. This attributes are sent as Tunnel Encapsulation of type 15 (SR Policy) SUB TLV's.

**Note:**
Revision **11** of the draft is currently implemented in gobgp. Once draft becomes RFC, the implementation will be updated to reflect RFC changes. Here is the link to the draft [Advertising Segment Routing Policies in BGP](https://tools.ietf.org/html/draft-ietf-idr-segment-routing-te-policy-11)

## Contents

- [Basic SR Policy Example](#basic-sr-policy-example)

## Basic SR Policy Example

```go
package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"

	toolbox "github.com/sbezverk/gobgptoolbox"
	"google.golang.org/grpc"
	apb "google.golang.org/protobuf/types/known/anypb"

	api "github.com/osrg/gobgp/v3/api"
)

func AddSRPolicy(client api.GobgpApiClient) error {

	nlrisr, _ := apb.New(&api.SRPolicyNLRI{
		Length:        96,
		Distinguisher: 2,
		Color:         99,
		Endpoint:      net.ParseIP("10.0.0.15").To4(),
	})
	// Origin attribute
	origin, _ := apb.New(&api.OriginAttribute{
		Origin: 0,
	})
	// Next hop attribute
	nh, _ := apb.New(&api.NextHopAttribute{
		NextHop: net.ParseIP("192.168.20.1").To4().String(),
	})
	// Extended communities attribute
	toolbox.MarshalRTFromString("")
	rtm, err := toolbox.MarshalRTFromString("10.0.0.8:0")
	if err != nil {
		return err
	}
	rt, _ := apb.New(&api.ExtendedCommunitiesAttribute{
		Communities: []*any.Any{rtm},
	})
	// Tunnel Encapsulation Type 15 (SR Policy) sub tlvs
	s := make([]byte, 4)
	binary.BigEndian.PutUint32(s, 24321)
	sid, err := apb.New(&api.SRBindingSID{
		SFlag: true,
		IFlag: false,
		Sid:   s,
	})
	if err != nil {
		return err
	}
	bsid, err := apb.New(&api.TunnelEncapSubTLVSRBindingSID{
		Bsid: sid,
	})
	if err != nil {
		return err
	}
	segment, err := apb.New(&api.SegmentTypeA{
		Flags: &api.SegmentFlags{
			SFlag: true,
		},
		Label: 10203,
	})
	if err != nil {
		return err
	}
	seglist, err := apb.New(&api.TunnelEncapSubTLVSRSegmentList{
		Weight: &api.SRWeight{
			Flags:  0,
			Weight: 12,
		},
		Segments: []*any.Any{segment},
	})
	if err != nil {
		return err
	}
	pref, err := apb.New(&api.TunnelEncapSubTLVSRPreference{
		Flags:      0,
		Preference: 11,
	})
	if err != nil {
		return err
	}
	cpn, err := apb.New(&api.TunnelEncapSubTLVSRCandidatePathName{
		CandidatePathName: "CandidatePathName",
	})
	if err != nil {
		return err
	}
	pri, err := apb.New(&api.TunnelEncapSubTLVSRPriority{
		Priority: 10,
	})
	if err != nil {
		return err
	}
	// Tunnel Encapsulation attribute for SR Policy
	tun, err := apb.New(&api.TunnelEncapAttribute{
		Tlvs: []*api.TunnelEncapTLV{
			{
				Type: 15,
				Tlvs: []*anypb.Any{bsid, seglist, pref, cpn, pri},
			},
		},
	})
	if err != nil {
		return err
	}
	attrs := []*any.Any{origin, nh, rt, tun}
	if _, err := client.AddPath(context.TODO(), &api.AddPathRequest{
		TableType: api.TableType_GLOBAL,
		Path: &api.Path{
			Nlri:      nlrisr,
			Pattrs:    attrs,
			Family:    &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_SR_POLICY},
			Best:      true,
			SourceAsn: 65000,
		},
	}); err != nil {
		return fmt.Errorf("failed to run AddPath call with error: %v", err)
	}

	return nil
}

func main() {
	conn, err := grpc.DialContext(context.TODO(), "192.168.20.201:50051", grpc.WithInsecure())
	if err != nil {
		fmt.Printf("fail to connect to gobgp with error: %+v\n", err)
		os.Exit(1)
	}
	client := api.NewGobgpApiClient(conn)
	// Testing connection to gobgp by requesting its global config
	if _, err := client.GetBgp(context.TODO(), &api.GetBgpRequest{}); err != nil {
		fmt.Printf("fail to get gobgp info with error: %+v\n", err)
		os.Exit(1)
	}

	if err := AddSRPolicy(client); err != nil {
		fmt.Printf("fail to add SR policy to gobgp with error: %+v\n", err)
		os.Exit(1)
	}
}

```

## Result of injecting the SR policy

Once the sr policy is injected, gobgp will advertise it to the peers with SR Policy enabled address family. Below is the output collected from Cisco's XRV9K router with enabled SR policy address family. Please note since the information used such as: bsid, endpoint adress etc is not realistic, the router does not install the sr policy, but still, it correctly displays what was programmed.

```log
RP/0/RP0/CPU0:xrv9k-r1#sh bgp ipv4 sr-policy [2][99][10.0.0.15]/96
Sun Nov 29 13:05:05.293 EST
BGP routing table entry for [2][99][10.0.0.15]/96
Versions:
  Process           bRIB/RIB  SendTblVer
  Speaker                 37          37
Last Modified: Nov 29 13:01:21.251 for 00:03:44
Paths: (1 available, best #1)
  Not advertised to any peer
  Path #1: Received by speaker 0
  Not advertised to any peer
  Local, (Received from a RR-client)
    192.168.20.1 from 192.168.20.201 (192.168.20.201)
      Origin IGP, localpref 100, valid, internal, best, group-best
      Received Path ID 0, Local Path ID 1, version 37
      Extended community: RT:10.0.0.8:0
      Tunnel encap attribute type: 15 (SR policy)
       bsid 24321, preference 11, num of segment-lists 1
       segment-list 1, weight 12
        segments: {10203}
       Candidate path is not usable
       SR policy state is Down, Allocated bsid none
```
