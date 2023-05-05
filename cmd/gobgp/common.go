// Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

const globalRIBName = "global"

const (
	cmdGlobal         = "global"
	cmdNeighbor       = "neighbor"
	cmdPolicy         = "policy"
	cmdRib            = "rib"
	cmdAdd            = "add"
	cmdDel            = "del"
	cmdAll            = "all"
	cmdSet            = "set"
	cmdLocal          = "local"
	cmdAdjIn          = "adj-in"
	cmdAdjOut         = "adj-out"
	cmdReset          = "reset"
	cmdSoftReset      = "softreset"
	cmdSoftResetIn    = "softresetin"
	cmdSoftResetOut   = "softresetout"
	cmdShutdown       = "shutdown"
	cmdEnable         = "enable"
	cmdDisable        = "disable"
	cmdPrefix         = "prefix"
	cmdAspath         = "as-path"
	cmdCommunity      = "community"
	cmdExtcommunity   = "ext-community"
	cmdImport         = "import"
	cmdExport         = "export"
	cmdMonitor        = "monitor"
	cmdMRT            = "mrt"
	cmdInject         = "inject"
	cmdRPKI           = "rpki"
	cmdRPKITable      = "table"
	cmdRPKIServer     = "server"
	cmdVRF            = "vrf"
	cmdAccepted       = "accepted"
	cmdRejected       = "rejected"
	cmdStatement      = "statement"
	cmdCondition      = "condition"
	cmdAction         = "action"
	cmdUpdate         = "update"
	cmdBMP            = "bmp"
	cmdLargecommunity = "large-community"
	cmdSummary        = "summary"
	cmdLogLevel       = "log-level"
	cmdPanic          = "panic"
	cmdFatal          = "fatal"
	cmdError          = "error"
	cmdWarn           = "warn"
	cmdInfo           = "info"
	cmdDebug          = "debug"
	cmdTrace          = "trace"
)

const (
	paramFlag = iota
	paramSingle
	paramList
)

var subOpts struct {
	AddressFamily string `short:"a" long:"address-family" description:"specifying an address family"`
}

var neighborsOpts struct {
	Reason    string `short:"r" long:"reason" description:"specifying communication field on Cease NOTIFICATION message with Administrative Shutdown subcode"`
	Transport string `short:"t" long:"transport" description:"specifying a transport protocol"`
}

var mrtOpts struct {
	Filename    string `long:"filename" description:"MRT file name"`
	RecordCount int64  `long:"count" description:"Number of records to inject"`
	RecordSkip  int64  `long:"skip" description:"Number of records to skip before injecting"`
	QueueSize   int    `long:"batch-size" description:"Maximum number of updates to keep queued"`
	Best        bool   `long:"only-best" description:"only keep best path routes"`
	SkipV4      bool   `long:"no-ipv4" description:"Skip importing IPv4 routes"`
	SkipV6      bool   `long:"no-ipv4" description:"Skip importing IPv6 routes"`
	NextHop     net.IP `long:"nexthop" description:"Rewrite nexthop"`
}

var bmpOpts struct {
	StatisticsTimeout int `short:"s" long:"statistics-timeout" description:"Interval for Statistics Report"`
}

func formatTimedelta(t time.Time) string {
	d := time.Now().Unix() - t.Unix()
	u := uint64(d)
	neg := d < 0
	if neg {
		u = -u
	}
	secs := u % 60
	u /= 60
	mins := u % 60
	u /= 60
	hours := u % 24
	days := u / 24

	if days == 0 {
		return fmt.Sprintf("%02d:%02d:%02d", hours, mins, secs)
	}
	return fmt.Sprintf("%dd ", days) + fmt.Sprintf("%02d:%02d:%02d", hours, mins, secs)
}

func cidr2prefix(cidr string) string {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return cidr
	}
	var buffer bytes.Buffer
	for i := 0; i < len(n.IP); i++ {
		buffer.WriteString(fmt.Sprintf("%08b", n.IP[i]))
	}
	ones, _ := n.Mask.Size()
	return buffer.String()[:ones]
}

func extractReserved(args []string, keys map[string]int) (map[string][]string, error) {
	m := make(map[string][]string, len(keys))
	var k string
	isReserved := func(s string) bool {
		for r := range keys {
			if s == r {
				return true
			}
		}
		return false
	}
	for _, arg := range args {
		if isReserved(arg) {
			k = arg
			m[k] = make([]string, 0, 1)
		} else {
			m[k] = append(m[k], arg)
		}
	}
	for k, v := range m {
		if k == "" {
			continue
		}
		switch keys[k] {
		case paramFlag:
			if len(v) != 0 {
				return nil, fmt.Errorf("%s should not have arguments", k)
			}
		case paramSingle:
			if len(v) != 1 {
				return nil, fmt.Errorf("%s should have one argument", k)
			}
		case paramList:
			if len(v) == 0 {
				return nil, fmt.Errorf("%s should have one or more arguments", k)
			}
		}
	}
	return m, nil
}

func loadCertificatePEM(filePath string) (*x509.Certificate, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	rest := content
	var block *pem.Block
	var cert *x509.Certificate
	for len(rest) > 0 {
		block, rest = pem.Decode(content)
		if block == nil {
			// no PEM data found, rest will not have been modified
			break
		}
		content = rest
		switch block.Type {
		case "CERTIFICATE":
			cert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			return cert, err
		default:
			// not the PEM block we're looking for
			continue
		}
	}
	return nil, errors.New("no certificate PEM block found")
}

func loadKeyPEM(filePath string) (crypto.PrivateKey, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	rest := content
	var block *pem.Block
	var key crypto.PrivateKey
	for len(rest) > 0 {
		block, rest = pem.Decode(content)
		if block == nil {
			// no PEM data found, rest will not have been modified
			break
		}
		switch block.Type {
		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			return key, err
		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			return key, err
		case "EC PRIVATE KEY":
			key, err = x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			return key, err
		default:
			// not the PEM block we're looking for
			continue
		}
	}
	return nil, errors.New("no private key PEM block found")
}

func newClient(ctx context.Context) (api.GobgpApiClient, context.CancelFunc, error) {
	grpcOpts := []grpc.DialOption{grpc.WithBlock()}
	if globalOpts.TLS {
		var creds credentials.TransportCredentials
		tlsConfig := new(tls.Config)
		if len(globalOpts.CaFile) != 0 {
			pemCerts, err := os.ReadFile(globalOpts.CaFile)
			if err != nil {
				exitWithError(err)
			}
			tlsConfig.RootCAs = x509.NewCertPool()
			if !tlsConfig.RootCAs.AppendCertsFromPEM(pemCerts) {
				exitWithError(errors.New("no valid CA certificates to load"))
			}
		}
		if len(globalOpts.ClientCertFile) != 0 && len(globalOpts.ClientKeyFile) != 0 {
			cert, err := loadCertificatePEM(globalOpts.ClientCertFile)
			if err != nil {
				exitWithError(fmt.Errorf("failed to load client certificate: %w", err))
			}
			key, err := loadKeyPEM(globalOpts.ClientKeyFile)
			if err != nil {
				exitWithError(fmt.Errorf("failed to load client key: %w", err))
			}
			tlsConfig.Certificates = []tls.Certificate{
				{
					Certificate: [][]byte{cert.Raw},
					PrivateKey:  key,
				},
			}
		}
		creds = credentials.NewTLS(tlsConfig)
		grpcOpts = append(grpcOpts, grpc.WithTransportCredentials(creds))
	} else {
		grpcOpts = append(grpcOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	target := globalOpts.Target
	if target == "" {
		target = net.JoinHostPort(globalOpts.Host, strconv.Itoa(globalOpts.Port))
	} else if strings.HasPrefix(target, "unix://") {
		target = target[len("unix://"):]
		dialer := func(ctx context.Context, addr string) (net.Conn, error) {
			return net.Dial("unix", addr)
		}
		grpcOpts = append(grpcOpts, grpc.WithContextDialer(dialer))
	}
	cc, cancel := context.WithTimeout(ctx, time.Second)

	conn, err := grpc.DialContext(cc, target, grpcOpts...)
	if err != nil {
		return nil, cancel, err
	}
	return api.NewGobgpApiClient(conn), cancel, nil
}

func addr2AddressFamily(a net.IP) *api.Family {
	if a.To4() != nil {
		return &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_UNICAST,
		}
	} else if a.To16() != nil {
		return &api.Family{
			Afi:  api.Family_AFI_IP6,
			Safi: api.Family_SAFI_UNICAST,
		}
	}
	return nil
}

var (
	ipv4UC = &api.Family{
		Afi:  api.Family_AFI_IP,
		Safi: api.Family_SAFI_UNICAST,
	}
	ipv6UC = &api.Family{
		Afi:  api.Family_AFI_IP6,
		Safi: api.Family_SAFI_UNICAST,
	}
	ipv4VPN = &api.Family{
		Afi:  api.Family_AFI_IP,
		Safi: api.Family_SAFI_MPLS_VPN,
	}
	ipv6VPN = &api.Family{
		Afi:  api.Family_AFI_IP6,
		Safi: api.Family_SAFI_MPLS_VPN,
	}
	ipv4MPLS = &api.Family{
		Afi:  api.Family_AFI_IP,
		Safi: api.Family_SAFI_MPLS_LABEL,
	}
	ipv6MPLS = &api.Family{
		Afi:  api.Family_AFI_IP6,
		Safi: api.Family_SAFI_MPLS_LABEL,
	}
	evpn = &api.Family{
		Afi:  api.Family_AFI_L2VPN,
		Safi: api.Family_SAFI_EVPN,
	}
	l2vpnVPLS = &api.Family{
		Afi:  api.Family_AFI_L2VPN,
		Safi: api.Family_SAFI_VPLS,
	}
	ipv4Encap = &api.Family{
		Afi:  api.Family_AFI_IP,
		Safi: api.Family_SAFI_ENCAPSULATION,
	}
	ipv6Encap = &api.Family{
		Afi:  api.Family_AFI_IP6,
		Safi: api.Family_SAFI_ENCAPSULATION,
	}
	rtc = &api.Family{
		Afi:  api.Family_AFI_IP,
		Safi: api.Family_SAFI_ROUTE_TARGET_CONSTRAINTS,
	}
	ipv4Flowspec = &api.Family{
		Afi:  api.Family_AFI_IP,
		Safi: api.Family_SAFI_FLOW_SPEC_UNICAST,
	}
	ipv6Flowspec = &api.Family{
		Afi:  api.Family_AFI_IP6,
		Safi: api.Family_SAFI_FLOW_SPEC_UNICAST,
	}
	ipv4VPNflowspec = &api.Family{
		Afi:  api.Family_AFI_IP,
		Safi: api.Family_SAFI_FLOW_SPEC_VPN,
	}
	ipv6VPNflowspec = &api.Family{
		Afi:  api.Family_AFI_IP6,
		Safi: api.Family_SAFI_FLOW_SPEC_VPN,
	}
	l2VPNflowspec = &api.Family{
		Afi:  api.Family_AFI_L2VPN,
		Safi: api.Family_SAFI_FLOW_SPEC_VPN,
	}
	opaque = &api.Family{
		Afi:  api.Family_AFI_OPAQUE,
		Safi: api.Family_SAFI_KEY_VALUE,
	}
	ls = &api.Family{
		Afi:  api.Family_AFI_LS,
		Safi: api.Family_SAFI_LS,
	}
	ipv4MUP = &api.Family{
		Afi:  api.Family_AFI_IP,
		Safi: api.Family_SAFI_MUP,
	}
	ipv6MUP = &api.Family{
		Afi:  api.Family_AFI_IP6,
		Safi: api.Family_SAFI_MUP,
	}
)

func checkAddressFamily(def *api.Family) (*api.Family, error) {
	var f *api.Family
	var e error
	switch subOpts.AddressFamily {
	case "ipv4", "v4", "4":
		f = ipv4UC
	case "ipv6", "v6", "6":
		f = ipv6UC
	case "ipv4-l3vpn", "vpnv4", "vpn-ipv4":
		f = ipv4VPN
	case "ipv6-l3vpn", "vpnv6", "vpn-ipv6":
		f = ipv6VPN
	case "ipv4-labeled", "ipv4-labelled", "ipv4-mpls":
		f = ipv4MPLS
	case "ipv6-labeled", "ipv6-labelled", "ipv6-mpls":
		f = ipv6MPLS
	case "evpn":
		f = evpn
	case "l2vpn-vpls":
		f = l2vpnVPLS
	case "encap", "ipv4-encap":
		f = ipv4Encap
	case "ipv6-encap":
		f = ipv6Encap
	case "rtc":
		f = rtc
	case "ipv4-flowspec", "ipv4-flow", "flow4":
		f = ipv4Flowspec
	case "ipv6-flowspec", "ipv6-flow", "flow6":
		f = ipv6Flowspec
	case "ipv4-l3vpn-flowspec", "ipv4vpn-flowspec", "flowvpn4":
		f = ipv4VPNflowspec
	case "ipv6-l3vpn-flowspec", "ipv6vpn-flowspec", "flowvpn6":
		f = ipv6VPNflowspec
	case "l2vpn-flowspec":
		f = l2VPNflowspec
	case "opaque":
		f = opaque
	case "ls", "linkstate", "bgpls":
		f = ls
	case "ipv4-mup", "mup-ipv4", "mup4":
		f = ipv4MUP
	case "ipv6-mup", "mup-ipv6", "mup6":
		f = ipv6MUP
	case "":
		f = def
	default:
		e = fmt.Errorf("unsupported address family: %s", subOpts.AddressFamily)
	}
	return f, e
}

func printError(err error) {
	if globalOpts.Json {
		j, _ := json.Marshal(struct {
			Error string `json:"error"`
		}{Error: err.Error()})
		fmt.Println(string(j))
	} else {
		fmt.Println(err)
	}
}

func exitWithError(err error) {
	printError(err)
	os.Exit(1)
}

func getNextHopFromPathAttributes(attrs []bgp.PathAttributeInterface) net.IP {
	for _, attr := range attrs {
		switch a := attr.(type) {
		case *bgp.PathAttributeNextHop:
			return a.Value
		case *bgp.PathAttributeMpReachNLRI:
			return a.Nexthop
		}
	}
	return nil
}
