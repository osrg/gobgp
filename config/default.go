package config

import (
	"fmt"
	"github.com/osrg/gobgp/packet"
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

func SetDefaultConfigValues(v *viper.Viper, b *Bgp) error {
	if v == nil {
		v = viper.New()
	}
	if !v.IsSet("global.afi-safis") {
		b.Global.AfiSafis = []AfiSafi{
			AfiSafi{AfiSafiName: "ipv4-unicast"},
			AfiSafi{AfiSafiName: "ipv6-unicast"},
			AfiSafi{AfiSafiName: "l3vpn-ipv4-unicast"},
			AfiSafi{AfiSafiName: "l3vpn-ipv6-unicast"},
			AfiSafi{AfiSafiName: "l2vpn-evpn"},
			AfiSafi{AfiSafiName: "encap"},
			AfiSafi{AfiSafiName: "rtc"},
			AfiSafi{AfiSafiName: "ipv4-flowspec"},
			AfiSafi{AfiSafiName: "l3vpn-ipv4-flowspec"},
			AfiSafi{AfiSafiName: "ipv6-flowspec"},
			AfiSafi{AfiSafiName: "l3vpn-ipv6-flowspec"},
		}
	}

	if b.Global.ListenConfig.Port == 0 {
		b.Global.ListenConfig.Port = bgp.BGP_PORT
	}

	for idx, server := range b.Global.BmpServers {
		if server.Config.Port == 0 {
			server.Config.Port = bgp.BMP_DEFAULT_PORT
		}
		b.Global.BmpServers[idx] = server
	}

	if !v.IsSet("global.mpls-label-range.min-label") {
		b.Global.MplsLabelRange.MinLabel = DEFAULT_MPLS_LABEL_MIN
	}

	if !v.IsSet("global.mpls-label-range.max-label") {
		b.Global.MplsLabelRange.MaxLabel = DEFAULT_MPLS_LABEL_MAX
	}

	// yaml is decoded as []interface{}
	// but toml is decoded as []map[string]interface{}.
	// currently, viper can't hide this difference.
	// handle the difference here.
	var list []interface{}
	intf := v.Get("neighbors")
	if intf != nil {
		var ok bool
		list, ok = intf.([]interface{})
		if !ok {
			l, ok := intf.([]map[string]interface{})
			if !ok {
				return fmt.Errorf("invalid configuration: neighborlist must be a list")
			}
			list = make([]interface{}, 0, len(l))
			for _, m := range l {
				list = append(list, m)
			}
		}
	}
	for idx, n := range b.Neighbors {
		vv := viper.New()
		if len(list) > idx {
			vv.Set("neighbor", list[idx])
		}
		if !vv.IsSet("neighbor.timers.config.connect-retry") {
			n.Timers.Config.ConnectRetry = float64(DEFAULT_CONNECT_RETRY)
		}
		if !vv.IsSet("neighbor.timers.config.hold-time") {
			n.Timers.Config.HoldTime = float64(DEFAULT_HOLDTIME)
		}
		if !vv.IsSet("neighbor.timers.config.keepalive-interval") {
			n.Timers.Config.KeepaliveInterval = n.Timers.Config.HoldTime / 3
		}
		if !vv.IsSet("neighbor.timers.config.idle-hold-time-after-reset") {
			n.Timers.Config.IdleHoldTimeAfterReset = float64(DEFAULT_IDLE_HOLDTIME_AFTER_RESET)
		}

		if !vv.IsSet("neighbor.afi-safis") {
			if ip := net.ParseIP(n.Config.NeighborAddress); ip.To4() != nil {
				n.AfiSafis = []AfiSafi{
					AfiSafi{AfiSafiName: "ipv4-unicast"},
				}
			} else if ip.To16() != nil {
				n.AfiSafis = []AfiSafi{
					AfiSafi{AfiSafiName: "ipv6-unicast"},
				}
			} else {
				return fmt.Errorf("invalid neighbor address: %s", n.Config.NeighborAddress)
			}
		}

		if !vv.IsSet("neighbor.config.peer-type") {
			if n.Config.PeerAs != b.Global.Config.As {
				n.Config.PeerType = PEER_TYPE_EXTERNAL
			} else {
				n.Config.PeerType = PEER_TYPE_INTERNAL
			}
		}
		b.Neighbors[idx] = n
	}

	for _, r := range b.RpkiServers {
		if r.Config.Port == 0 {
			r.Config.Port = bgp.RPKI_DEFAULT_PORT
		}
	}

	return nil
}
