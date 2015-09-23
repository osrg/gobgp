package config

import (
	"github.com/BurntSushi/toml"
	"github.com/osrg/gobgp/packet"
	"strings"
)

const (
	DEFAULT_HOLDTIME                  = 90
	DEFAULT_IDLE_HOLDTIME_AFTER_RESET = 30
	DEFAULT_CONNECT_RETRY             = 120
	DEFAULT_MPLS_LABEL_MIN            = 16000
	DEFAULT_MPLS_LABEL_MAX            = 1048575
)

type neighbor struct {
	attributes map[string]bool
}

func SetDefaultConfigValues(md toml.MetaData, bt *Bgp) error {
	neighbors := []neighbor{}
	global := make(map[string]bool)

	for _, key := range md.Keys() {
		if !strings.HasPrefix(key.String(), "Global") {
			continue
		}
		if key.String() != "Global" {
			global[key.String()] = true
		}
	}

	if _, ok := global["Global.AfiSafis.AfiSafiList"]; !ok {
		bt.Global.AfiSafis.AfiSafiList = []AfiSafi{
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

	if _, ok := global["Global.MplsLabelRange.MinLabel"]; !ok {
		bt.Global.MplsLabelRange.MinLabel = DEFAULT_MPLS_LABEL_MIN
	}

	if _, ok := global["Global.MplsLabelRange.MaxLabel"]; !ok {
		bt.Global.MplsLabelRange.MaxLabel = DEFAULT_MPLS_LABEL_MAX
	}

	nidx := 0
	for _, key := range md.Keys() {
		if !strings.HasPrefix(key.String(), "Neighbors.NeighborList") {
			continue
		}
		if key.String() == "Neighbors.NeighborList" {
			neighbors = append(neighbors, neighbor{attributes: make(map[string]bool)})
			nidx++
		} else {
			neighbors[nidx-1].attributes[key.String()] = true
		}
	}
	for i, n := range neighbors {
		neighbor := &bt.Neighbors.NeighborList[i]
		timerConfig := &neighbor.Timers.TimersConfig

		if _, ok := n.attributes["Neighbors.NeighborList.Timers.TimersConfig.ConnectRetry"]; !ok {
			timerConfig.HoldTime = float64(DEFAULT_CONNECT_RETRY)
		}
		if _, ok := n.attributes["Neighbors.NeighborList.Timers.TimersConfig.HoldTime"]; !ok {
			timerConfig.HoldTime = float64(DEFAULT_HOLDTIME)
		}
		if _, ok := n.attributes["Neighbors.NeighborList.Timers.TimersConfig.KeepaliveInterval"]; !ok {
			timerConfig.KeepaliveInterval = timerConfig.HoldTime / 3
		}

		if _, ok := n.attributes["Neighbors.NeighborList.Timers.TimersConfig.IdleHoldTimeAfterReset"]; !ok {
			timerConfig.IdleHoldTimeAfterReset = float64(DEFAULT_IDLE_HOLDTIME_AFTER_RESET)
		}

		if _, ok := n.attributes["Neighbors.NeighborList.AfiSafis.AfiSafiList"]; !ok {
			if neighbor.NeighborConfig.NeighborAddress.To4() != nil {
				neighbor.AfiSafis.AfiSafiList = []AfiSafi{
					AfiSafi{AfiSafiName: "ipv4-unicast"}}
			} else {
				neighbor.AfiSafis.AfiSafiList = []AfiSafi{
					AfiSafi{AfiSafiName: "ipv6-unicast"}}
			}
		} else {
			for _, rf := range neighbor.AfiSafis.AfiSafiList {
				_, err := bgp.GetRouteFamily(rf.AfiSafiName)
				if err != nil {
					return err
				}
			}
		}

		if _, ok := n.attributes["Neighbors.NeighborList.NeighborConfig.PeerType"]; !ok {
			if neighbor.NeighborConfig.PeerAs != bt.Global.GlobalConfig.As {
				neighbor.NeighborConfig.PeerType = PEER_TYPE_EXTERNAL
			} else {
				neighbor.NeighborConfig.PeerType = PEER_TYPE_INTERNAL
			}
		}
	}
	for _, r := range bt.RpkiServers.RpkiServerList {
		if r.RpkiServerConfig.Port == 0 {
			r.RpkiServerConfig.Port = bgp.RPKI_DEFAULT_PORT
		}
	}
	return nil
}
