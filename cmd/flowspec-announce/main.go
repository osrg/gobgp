// Command flowspec-announce originates (or withdraws) a single DNOS packet-content
// (type-254) BGP FlowSpec rule via the local gobgpd gRPC API.
//
// The gobgp CLI has NO syntax for the experimental content-filter component, so
// this tiny client is the supported way to announce it by hand. It mirrors the
// ddos-detector's speaker exactly: dest-prefix (type 1) + protocol (type 3) +
// content-filter (type 254), with a traffic-rate ext-community (rate 0 = drop).
//
// Build/run from the gobgp fork checkout (this file lives in it):
//
//	cd /home/dn/gobgp
//	go run ./cmd/flowspec-announce --prefix 203.0.113.0/24 --proto 17 \
//	    --offset 0 --sig ab --rate 0            # announce a drop rule
//	go run ./cmd/flowspec-announce --prefix 203.0.113.0/24 --proto 17 \
//	    --offset 0 --sig ab --withdraw          # withdraw it
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	apb "google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/proto"
)

// RFC 8955 numeric operator byte: end-of-list (0x80) | equal (0x01).
const opEndOfListEqual = 0x81

func mustAny(m proto.Message) *apb.Any {
	a, err := apb.New(m)
	if err != nil {
		log.Fatalf("pack %T: %v", m, err)
	}
	return a
}

// contentFilterFlags packs ptype (AFI, high nibble) | otype (offset anchor, low
// nibble) exactly like the detector: IPv4=1/IPv6=2; UDP-payload=2, TCP-payload=3,
// else IP-payload=1.
func contentFilterFlags(isV4 bool, proto uint32) uint32 {
	var ptype, otype uint32
	if isV4 {
		ptype = 1
	} else {
		ptype = 2
	}
	switch proto {
	case 17:
		otype = 2
	case 6:
		otype = 3
	default:
		otype = 1
	}
	return (ptype << 4) | otype
}

func main() {
	grpcAddr := flag.String("grpc", "127.0.0.1:50051", "gobgpd gRPC endpoint")
	prefix := flag.String("prefix", "203.0.113.0/24", "victim destination prefix (dest-prefix component)")
	protocol := flag.Uint("proto", 17, "IP protocol number for the protocol component (17=UDP)")
	offset := flag.Uint("offset", 0, "payload byte offset for the content-filter match")
	sigHex := flag.String("sig", "ab", "hex signature bytes to match in the payload window")
	maskHex := flag.String("mask", "", "hex mask bytes (default: all 0xff of the signature length)")
	asn := flag.Uint("asn", 65002, "local ASN stamped into the traffic-rate ext-community")
	rate := flag.Float64("rate", 0, "traffic-rate bytes/sec (0 = drop; >0 = rate-limit)")
	withdraw := flag.Bool("withdraw", false, "withdraw (DeletePath) instead of announce (AddPath)")
	flag.Parse()

	pfx, err := netip.ParsePrefix(*prefix)
	if err != nil {
		log.Fatalf("bad --prefix %q: %v", *prefix, err)
	}
	isV4 := pfx.Addr().Is4()

	content, err := hex.DecodeString(*sigHex)
	if err != nil || len(content) == 0 {
		log.Fatalf("bad --sig %q (want non-empty hex)", *sigHex)
	}
	var mask []byte
	if *maskHex == "" {
		mask = make([]byte, len(content))
		for i := range mask {
			mask[i] = 0xff
		}
	} else if mask, err = hex.DecodeString(*maskHex); err != nil || len(mask) != len(content) {
		log.Fatalf("bad --mask %q (want hex, same length as --sig)", *maskHex)
	}
	if int(*offset)+len(content) > 6 {
		log.Fatalf("offset(%d) + len(sig)(%d) > 6: past the DNOS payload window", *offset, len(content))
	}

	afi := api.Family_AFI_IP
	if !isV4 {
		afi = api.Family_AFI_IP6
	}

	nlri := mustAny(&api.FlowSpecNLRI{Rules: []*apb.Any{
		mustAny(&api.FlowSpecIPPrefix{
			Type:      1,
			PrefixLen: uint32(pfx.Bits()),
			Prefix:    pfx.Addr().String(),
		}),
		mustAny(&api.FlowSpecComponent{
			Type:  3,
			Items: []*api.FlowSpecComponentItem{{Op: opEndOfListEqual, Value: uint64(*protocol)}},
		}),
		mustAny(&api.FlowSpecContentFilter{
			Type:    254,
			Flags:   contentFilterFlags(isV4, uint32(*protocol)),
			Offset:  uint32(*offset),
			Content: content,
			Mask:    mask,
		}),
	}})

	nextHop := "0.0.0.0"
	if !isV4 {
		nextHop = "::"
	}
	pattrs := []*apb.Any{
		mustAny(&api.OriginAttribute{Origin: 0}), // IGP
		mustAny(&api.NextHopAttribute{NextHop: nextHop}),
		mustAny(&api.ExtendedCommunitiesAttribute{Communities: []*apb.Any{
			mustAny(&api.TrafficRateExtended{Asn: uint32(*asn), Rate: float32(*rate)}),
		}}),
	}

	path := &api.Path{
		Nlri:   nlri,
		Pattrs: pattrs,
		Family: &api.Family{Afi: afi, Safi: api.Family_SAFI_FLOW_SPEC_UNICAST},
	}

	conn, err := grpc.Dial(*grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial %s: %v", *grpcAddr, err)
	}
	defer conn.Close()
	client := api.NewGobgpApiClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	action := "drop"
	if *rate > 0 {
		action = fmt.Sprintf("rate-limit %.0f B/s", *rate)
	}
	if *withdraw {
		if _, err := client.DeletePath(ctx, &api.DeletePathRequest{TableType: api.TableType_GLOBAL, Path: path}); err != nil {
			log.Fatalf("DeletePath: %v", err)
		}
		fmt.Printf("withdrew content-filter rule: %s proto=%d payload[%d]=0x%s\n",
			pfx, *protocol, *offset, hex.EncodeToString(content))
		return
	}
	if _, err := client.AddPath(ctx, &api.AddPathRequest{TableType: api.TableType_GLOBAL, Path: path}); err != nil {
		log.Fatalf("AddPath: %v", err)
	}
	fmt.Printf("announced content-filter rule: %s proto=%d payload[%d]=0x%s mask=0x%s flags=0x%02x action=%s\n",
		pfx, *protocol, *offset, hex.EncodeToString(content), hex.EncodeToString(mask),
		contentFilterFlags(isV4, uint32(*protocol)), action)
}
