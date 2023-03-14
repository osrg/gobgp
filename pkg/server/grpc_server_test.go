package server

import (
	"net"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/internal/pkg/table"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestParseHost(t *testing.T) {
	tsts := []struct {
		name          string
		host          string
		expectNetwork string
		expectAddr    string
	}{
		{
			name:          "schemeless tcp host defaults to tcp",
			host:          "127.0.0.1:50051",
			expectNetwork: "tcp",
			expectAddr:    "127.0.0.1:50051",
		},
		{
			name:          "schemeless with only port defaults to tcp",
			host:          ":50051",
			expectNetwork: "tcp",
			expectAddr:    ":50051",
		},
		{
			name:          "unix socket",
			host:          "unix:///var/run/gobgp.socket",
			expectNetwork: "unix",
			expectAddr:    "/var/run/gobgp.socket",
		},
	}

	for _, tst := range tsts {
		t.Run(tst.name, func(t *testing.T) {
			gotNetwork, gotAddr := parseHost(tst.host)
			assert.Equal(t, tst.expectNetwork, gotNetwork)
			assert.Equal(t, tst.expectAddr, gotAddr)
		})
	}
}

func TestToPathApi(t *testing.T) {
	type args struct {
		path            *table.Path
		v               *table.Validation
		onlyBinary      bool
		nlriBinary      bool
		attributeBinary bool
	}
	tests := []struct {
		name string
		args args
		want *api.Path
	}{
		{
			name: "ipv4 path",
			args: args{
				path: table.NewPath(&table.PeerInfo{
					ID:           net.IP{10, 10, 10, 10},
					LocalID:      net.IP{10, 11, 11, 11},
					Address:      net.IP{10, 12, 12, 12},
					LocalAddress: net.IP{10, 13, 13, 13},
				},
					bgp.NewIPAddrPrefix(8, "10.0.0.0"),
					false,
					[]bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)},
					time.Time{},
					false),
			},
			want: &api.Path{
				Nlri:   anyNlri(bgp.NewIPAddrPrefix(8, "10.0.0.0")),
				Pattrs: anyAttrs([]bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}),
				Family: &api.Family{
					Afi:  api.Family_AFI_IP,
					Safi: api.Family_SAFI_UNICAST,
				},
				Validation: &api.Validation{},
				NeighborIp: "10.12.12.12",
				SourceId:   "10.10.10.10",
			},
		},
		{
			name: "eor ipv4 path",
			args: args{
				path: eor(bgp.RF_IPv4_UC),
			},
			want: &api.Path{
				Nlri: anyEorNlri(bgp.AFI_IP, bgp.SAFI_UNICAST),
				Family: &api.Family{
					Afi:  api.Family_AFI_IP,
					Safi: api.Family_SAFI_UNICAST,
				},
				Pattrs:     []*anypb.Any{},
				Validation: &api.Validation{},
				NeighborIp: "10.12.12.12",
				SourceId:   "10.10.10.10",
			},
		},
		{
			name: "eor vpn path",
			args: args{
				path: eor(bgp.RF_IPv4_VPN),
			},
			want: &api.Path{
				Nlri: anyEorNlri(bgp.AFI_IP, bgp.SAFI_MPLS_VPN),
				Family: &api.Family{
					Afi:  api.Family_AFI_IP,
					Safi: api.Family_SAFI_MPLS_VPN,
				},
				Pattrs:     []*anypb.Any{},
				Validation: &api.Validation{},
				NeighborIp: "10.12.12.12",
				SourceId:   "10.10.10.10",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiPath := toPathApi(tt.args.path, tt.args.v, tt.args.onlyBinary, tt.args.nlriBinary, tt.args.attributeBinary)
			assert.Equal(t, tt.want.Nlri, apiPath.Nlri, "not equal nlri")
			assert.Equal(t, tt.want.Pattrs, apiPath.Pattrs, "not equal attrs")
			assert.Equal(t, tt.want.Family, apiPath.Family, "not equal family")
			assert.Equal(t, tt.want.NeighborIp, apiPath.NeighborIp, "not equal neighbor")
		})
	}
}

func eor(f bgp.RouteFamily) *table.Path {
	p := table.NewEOR(f)
	p.SetSource(&table.PeerInfo{
		ID:           net.IP{10, 10, 10, 10},
		LocalID:      net.IP{10, 11, 11, 11},
		Address:      net.IP{10, 12, 12, 12},
		LocalAddress: net.IP{10, 13, 13, 13},
	})
	return p
}

func anyEorNlri(afi uint16, safi uint8) *anypb.Any {
	n, _ := bgp.NewPrefixFromRouteFamily(afi, safi)
	return anyNlri(n)
}

func anyNlri(nlri bgp.AddrPrefixInterface) *anypb.Any {
	anyNlri, _ := apiutil.MarshalNLRI(nlri)
	return anyNlri
}

func anyAttrs(attrs []bgp.PathAttributeInterface) []*anypb.Any {
	anyPattrs, _ := apiutil.MarshalPathAttributes(attrs)
	return anyPattrs
}
