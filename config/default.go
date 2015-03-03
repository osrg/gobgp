package config

import (
	"github.com/BurntSushi/toml"
	"strings"
)

const (
	DEFAULT_HOLDTIME                  = 90
	DEFAULT_IDLE_HOLDTIME_AFTER_RESET = 30
)

type neighbor struct {
	attributes map[string]bool
}

func SetDefaultConfigValues(md toml.MetaData, bt *Bgp) {
	neighbors := []neighbor{}

	nidx := 0
	for _, key := range md.Keys() {
		if !strings.HasPrefix(key.String(), "NeighborList") {
			continue
		}
		if key.String() == "NeighborList" {
			neighbors = append(neighbors, neighbor{attributes: make(map[string]bool)})
			nidx++
		} else {
			neighbors[nidx-1].attributes[key.String()] = true
		}
	}
	for i, n := range neighbors {
		if _, ok := n.attributes["NeighborList.Timers.HoldTime"]; !ok {
			bt.NeighborList[i].Timers.HoldTime = float64(DEFAULT_HOLDTIME)
		}
		if _, ok := n.attributes["NeighborList.Timers.KeepaliveInterval"]; !ok {
			bt.NeighborList[i].Timers.KeepaliveInterval = bt.NeighborList[i].Timers.HoldTime / 3
		}

		if _, ok := n.attributes["NeighborList.Timers.IdleHoldTImeAfterReset"]; !ok {
			bt.NeighborList[i].Timers.IdleHoldTimeAfterReset = float64(DEFAULT_IDLE_HOLDTIME_AFTER_RESET)
		}
	}
}
