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
		Config: AfiSafiConfig{
			AfiSafiName: typ,
			Enabled:     enable,
		},
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

	if n.Config.LocalAs == 0 {
		n.Config.LocalAs = asn
	}

	if n.Config.PeerAs != n.Config.LocalAs {
		n.Config.PeerType = PEER_TYPE_EXTERNAL
	} else {
		n.Config.PeerType = PEER_TYPE_INTERNAL
	}

	if !v.IsSet("neighbor.timers.config.connect-retry") && n.Timers.Config.ConnectRetry == 0 {
		n.Timers.Config.ConnectRetry = float64(DEFAULT_CONNECT_RETRY)
	}
	if !v.IsSet("neighbor.timers.config.hold-time") && n.Timers.Config.HoldTime == 0 {
		n.Timers.Config.HoldTime = float64(DEFAULT_HOLDTIME)
	}
	if !v.IsSet("neighbor.timers.config.keepalive-interval") && n.Timers.Config.KeepaliveInterval == 0 {
		n.Timers.Config.KeepaliveInterval = n.Timers.Config.HoldTime / 3
	}
	if !v.IsSet("neighbor.timers.config.idle-hold-time-after-reset") && n.Timers.Config.IdleHoldTimeAfterReset == 0 {
		n.Timers.Config.IdleHoldTimeAfterReset = float64(DEFAULT_IDLE_HOLDTIME_AFTER_RESET)
	}

	if n.Config.NeighborInterface != "" {
		addr, err := GetIPv6LinkLocalNeighborAddress(n.Config.NeighborInterface)
		if err != nil {
			return err
		}
		n.Config.NeighborAddress = addr
	}

	if n.Transport.Config.LocalAddress == "" {
		if n.Config.NeighborAddress == "" {
			return fmt.Errorf("no neighbor address/interface specified")
		}
		ipAddr, err := net.ResolveIPAddr("ip", n.Config.NeighborAddress)
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
		n.Transport.Config.LocalAddress = localAddress
	}

	if len(n.AfiSafis) == 0 {
		if ipAddr, err := net.ResolveIPAddr("ip", n.Config.NeighborAddress); err != nil {
			return fmt.Errorf("invalid neighbor address: %s", n.Config.NeighborAddress)
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
			af.State.AfiSafiName = af.Config.AfiSafiName
			if !vv.IsSet("afi-safi.config") {
				af.Config.Enabled = true
			}
			n.AfiSafis[i] = af
		}
	}

	n.State.Description = n.Config.Description
	n.Config.Description = ""
	n.State.AdminDown = n.Config.AdminDown

	if n.GracefulRestart.Config.Enabled {
		if !v.IsSet("neighbor.graceful-restart.config.restart-time") && n.GracefulRestart.Config.RestartTime == 0 {
			// RFC 4724 4. Operation
			// A suggested default for the Restart Time is a value less than or
			// equal to the HOLDTIME carried in the OPEN.
			n.GracefulRestart.Config.RestartTime = uint16(n.Timers.Config.HoldTime)
		}
		if !v.IsSet("neighbor.graceful-restart.config.deferral-time") && n.GracefulRestart.Config.DeferralTime == 0 {
			// RFC 4724 4.1. Procedures for the Restarting Speaker
			// The value of this timer should be large
			// enough, so as to provide all the peers of the Restarting Speaker with
			// enough time to send all the routes to the Restarting Speaker
			n.GracefulRestart.Config.DeferralTime = uint16(360)
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

	if g.Config.Port == 0 {
		g.Config.Port = bgp.BGP_PORT
	}

	if len(g.Config.LocalAddressList) == 0 {
		g.Config.LocalAddressList = []string{"0.0.0.0", "::"}
	}

	if g.MplsLabelRange.MinLabel == 0 {
		g.MplsLabelRange.MinLabel = DEFAULT_MPLS_LABEL_MIN
	}

	if g.MplsLabelRange.MaxLabel == 0 {
		g.MplsLabelRange.MaxLabel = DEFAULT_MPLS_LABEL_MAX
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

	for idx, server := range b.BmpServers {
		if server.Config.Port == 0 {
			server.Config.Port = bmp.BMP_DEFAULT_PORT
		}
		b.BmpServers[idx] = server
	}

	if b.Zebra.Config.Url == "" {
		b.Zebra.Config.Url = "unix:/var/run/quagga/zserv.api"
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
		if err := setDefaultNeighborConfigValuesWithViper(vv, &n, b.Global.Config.As); err != nil {
			return err
		}
		b.Neighbors[idx] = n
	}

	for _, r := range b.RpkiServers {
		if r.Config.Port == 0 {
			r.Config.Port = rtr.RPKI_DEFAULT_PORT
		}
	}

	return nil
}
