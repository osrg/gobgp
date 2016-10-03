package config

import (
	"fmt"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/osrg/gobgp/packet/bmp"
	"github.com/osrg/gobgp/packet/rtr"
	"github.com/spf13/viper"
	"net"
)

const (
	DEFAULT_HOLDTIME                  = 90
	DEFAULT_IDLE_HOLDTIME_AFTER_RESET = 30
	DEFAULT_CONNECT_RETRY             = 120
	DEFAULT_MPLS_LABEL_MIN            = 16000
	DEFAULT_MPLS_LABEL_MAX            = 1048575
)

func defaultAfiSafi(typ AfiSafiType, enable bool) AfiSafi {
	return AfiSafi{
		AfiSafiName: typ,
		Enabled:     enable,
		State: AfiSafiState{
			AfiSafiName: typ,
		},
	}
}

// yaml is decoded as []interface{}
// but toml is decoded as []map[string]interface{}.
// currently, viper can't hide this difference.
// handle the difference here.
func extractArray(intf interface{}) ([]interface{}, error) {
	if intf != nil {
		list, ok := intf.([]interface{})
		if ok {
			return list, nil
		}
		l, ok := intf.([]map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid configuration: neither []interface{} nor []map[string]interface{}")
		}
		list = make([]interface{}, 0, len(l))
		for _, m := range l {
			list = append(list, m)
		}
		return list, nil
	}
	return nil, nil
}

func getIPv6LinkLocalAddress(ifname string) (string, error) {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return "", err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if ip, _, err := net.ParseCIDR(addr.String()); err != nil {
			return "", err
		} else if ip.To4() == nil && ip.IsLinkLocalUnicast() {
			return fmt.Sprintf("%s%%%s", ip.String(), ifname), nil
		}
	}
	return "", fmt.Errorf("no ipv6 link local address for %s", ifname)
}

func isLocalLinkLocalAddress(ifindex int, addr net.IP) (bool, error) {
	ifi, err := net.InterfaceByIndex(ifindex)
	if err != nil {
		return false, err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return false, err
	}
	for _, a := range addrs {
		if ip, _, _ := net.ParseCIDR(a.String()); addr.Equal(ip) {
			return true, nil
		}
	}
	return false, nil
}

func SetDefaultNeighborConfigValues(n *Neighbor, asn uint32) error {
	return setDefaultNeighborConfigValuesWithViper(nil, n, asn)
}

func setDefaultNeighborConfigValuesWithViper(v *viper.Viper, n *Neighbor, asn uint32) error {
	if v == nil {
		v = viper.New()
	}

	if n.LocalAS == 0 {
		n.LocalAS = asn
	}

	if n.PeerAS != n.LocalAS {
		n.PeerType = PEER_TYPE_EXTERNAL
	} else {
		n.PeerType = PEER_TYPE_INTERNAL
	}

	if !v.IsSet("neighbor.timers.config.connect-retry") && n.Timers.ConnectRetry == 0 {
		n.Timers.ConnectRetry = float64(DEFAULT_CONNECT_RETRY)
	}
	if !v.IsSet("neighbor.timers.config.hold-time") && n.Timers.HoldTime == 0 {
		n.Timers.HoldTime = float64(DEFAULT_HOLDTIME)
	}
	if !v.IsSet("neighbor.timers.config.keepalive-interval") && n.Timers.KeepaliveInterval == 0 {
		n.Timers.KeepaliveInterval = n.Timers.HoldTime / 3
	}
	if !v.IsSet("neighbor.timers.config.idle-hold-time-after-reset") && n.Timers.IdleHoldTimeAfterReset == 0 {
		n.Timers.IdleHoldTimeAfterReset = float64(DEFAULT_IDLE_HOLDTIME_AFTER_RESET)
	}

	if n.NeighborInterface != "" {
		addr, err := GetIPv6LinkLocalNeighborAddress(n.NeighborInterface)
		if err != nil {
			return err
		}
		n.NeighborAddress = addr
	}

	if n.Transport.LocalAddress == "" {
		if n.NeighborAddress == "" {
			return fmt.Errorf("no neighbor address/interface specified")
		}
		ipAddr, err := net.ResolveIPAddr("ip", n.NeighborAddress)
		if err != nil {
			return err
		}
		localAddress := "0.0.0.0"
		if ipAddr.IP.To4() == nil {
			localAddress = "::"
			if ipAddr.Zone != "" {
				localAddress, err = getIPv6LinkLocalAddress(ipAddr.Zone)
				if err != nil {
					return err
				}
			}
		}
		n.Transport.LocalAddress = localAddress
	}

	if len(n.AfiSafis) == 0 {
		if ipAddr, err := net.ResolveIPAddr("ip", n.NeighborAddress); err != nil {
			return fmt.Errorf("invalid neighbor address: %s", n.NeighborAddress)
		} else if ipAddr.IP.To4() != nil {
			n.AfiSafis = []AfiSafi{defaultAfiSafi(AFI_SAFI_TYPE_IPV4_UNICAST, true)}
		} else {
			n.AfiSafis = []AfiSafi{defaultAfiSafi(AFI_SAFI_TYPE_IPV6_UNICAST, true)}
		}
	} else {
		afs, err := extractArray(v.Get("neighbor.afi-safis"))
		if err != nil {
			return err
		}
		for i, af := range n.AfiSafis {
			vv := viper.New()
			if len(afs) > i {
				vv.Set("afi-safi", afs[i])
			}
			af.State.AfiSafiName = af.AfiSafiName
			if !vv.IsSet("afi-safi.config") {
				af.Enabled = true
			}
			n.AfiSafis[i] = af
		}
	}

	n.State.Description = n.Description
	n.State.AdminDown = n.AdminDown

	if n.GracefulRestart.Enabled {
		if !v.IsSet("neighbor.graceful-restart.config.restart-time") && n.GracefulRestart.RestartTime == 0 {
			// RFC 4724 4. Operation
			// A suggested default for the Restart Time is a value less than or
			// equal to the HOLDTIME carried in the OPEN.
			n.GracefulRestart.RestartTime = uint16(n.Timers.HoldTime)
		}
		if !v.IsSet("neighbor.graceful-restart.config.deferral-time") && n.GracefulRestart.DeferralTime == 0 {
			// RFC 4724 4.1. Procedures for the Restarting Speaker
			// The value of this timer should be large
			// enough, so as to provide all the peers of the Restarting Speaker with
			// enough time to send all the routes to the Restarting Speaker
			n.GracefulRestart.DeferralTime = uint16(360)
		}
	}
	return nil
}

func SetDefaultGlobalConfigValues(g *Global) error {
	if len(g.AfiSafis) == 0 {
		g.AfiSafis = []AfiSafi{}
		for k, _ := range AfiSafiTypeToIntMap {
			g.AfiSafis = append(g.AfiSafis, defaultAfiSafi(k, true))
		}
	}

	if g.Port == 0 {
		g.Port = bgp.BGP_PORT
	}

	if len(g.LocalAddressList) == 0 {
		g.LocalAddressList = []string{"0.0.0.0", "::"}
	}

	if g.MPLSLabelRange.MinLabel == 0 {
		g.MPLSLabelRange.MinLabel = DEFAULT_MPLS_LABEL_MIN
	}

	if g.MPLSLabelRange.MaxLabel == 0 {
		g.MPLSLabelRange.MaxLabel = DEFAULT_MPLS_LABEL_MAX
	}
	return nil

}

func SetDefaultConfigValues(b *BgpConfigSet) error {
	return setDefaultConfigValuesWithViper(nil, b)
}

func setDefaultConfigValuesWithViper(v *viper.Viper, b *BgpConfigSet) error {
	if v == nil {
		v = viper.New()
	}

	if err := SetDefaultGlobalConfigValues(&b.Global); err != nil {
		return err
	}

	for idx, server := range b.BMPServers {
		if server.Port == 0 {
			server.Port = bmp.BMP_DEFAULT_PORT
		}
		b.BMPServers[idx] = server
	}

	if b.Zebra.URL == "" {
		b.Zebra.URL = "unix:/var/run/quagga/zserv.api"
	}

	list, err := extractArray(v.Get("neighbors"))
	if err != nil {
		return err
	}

	for idx, n := range b.Neighbors {
		vv := viper.New()
		if len(list) > idx {
			vv.Set("neighbor", list[idx])
		}
		if err := setDefaultNeighborConfigValuesWithViper(vv, &n, b.Global.AS); err != nil {
			return err
		}
		b.Neighbors[idx] = n
	}

	for _, r := range b.RPKIServers {
		if r.Port == 0 {
			r.Port = rtr.RPKI_DEFAULT_PORT
		}
	}

	return nil
}
