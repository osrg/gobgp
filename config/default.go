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

	defaultAfiSafi := func(typ AfiSafiType, enable bool) AfiSafi {
		return AfiSafi{
			AfiSafiName: typ,
			Config: AfiSafiConfig{
				AfiSafiName: typ,
				Enabled:     enable,
			},
			State: AfiSafiState{
				AfiSafiName: typ,
			},
		}
	}

	if !v.IsSet("global.afi-safis") {
		b.Global.AfiSafis = []AfiSafi{}
		for k, _ := range AfiSafiTypeToIntMap {
			b.Global.AfiSafis = append(b.Global.AfiSafis, defaultAfiSafi(k, true))
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
	extractArray := func(intf interface{}) ([]interface{}, error) {
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

	list, err := extractArray(v.Get("neighbors"))
	if err != nil {
		return err
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
				n.AfiSafis = []AfiSafi{defaultAfiSafi(AFI_SAFI_TYPE_IPV4_UNICAST, true)}
			} else if ip.To16() != nil {
				n.AfiSafis = []AfiSafi{defaultAfiSafi(AFI_SAFI_TYPE_IPV6_UNICAST, true)}
			} else {
				return fmt.Errorf("invalid neighbor address: %s", n.Config.NeighborAddress)
			}
		} else {
			afs, err := extractArray(vv.Get("neighbor.afi-safis"))
			if err != nil {
				return err
			}
			for i, af := range n.AfiSafis {
				vvv := viper.New()
				if len(afs) > i {
					vvv.Set("afi-safi", afs[i])
				}
				af.Config.AfiSafiName = af.AfiSafiName
				af.State.AfiSafiName = af.AfiSafiName
				if !vvv.IsSet("afi-safi.config") {
					af.Config.Enabled = true
				}
				n.AfiSafis[i] = af
			}
		}

		if !vv.IsSet("neighbor.config.local-as") {
			n.Config.LocalAs = b.Global.Config.As
		}

		if !vv.IsSet("neighbor.config.peer-type") {
			if n.Config.PeerAs != n.Config.LocalAs {
				n.Config.PeerType = PEER_TYPE_EXTERNAL
			} else {
				n.Config.PeerType = PEER_TYPE_INTERNAL
			}
		}

		if n.GracefulRestart.Config.Enabled {
			if !vv.IsSet("neighbor.graceful-restart.config.restart-time") {
				// RFC 4724 4. Operation
				// A suggested default for the Restart Time is a value less than or
				// equal to the HOLDTIME carried in the OPEN.
				n.GracefulRestart.Config.RestartTime = uint16(n.Timers.Config.HoldTime)
			}
			if !vv.IsSet("neighbor.graceful-restart.config.deferral-time") {
				// RFC 4724 4.1. Procedures for the Restarting Speaker
				// The value of this timer should be large
				// enough, so as to provide all the peers of the Restarting Speaker with
				// enough time to send all the routes to the Restarting Speaker
				n.GracefulRestart.Config.DeferralTime = uint16(360)
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
