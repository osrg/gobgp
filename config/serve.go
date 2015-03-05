package config

import (
	"github.com/BurntSushi/toml"
	log "github.com/Sirupsen/logrus"
)

func ReadConfigfileServe(path string, configCh chan Bgp, reloadCh chan bool) {
	for {
		<-reloadCh

		b := Bgp{}
		md, err := toml.DecodeFile(path, &b)
		if err == nil {
			err = SetDefaultConfigValues(md, &b)
		}
		if err != nil {
			log.Fatal("can't read config file ", path, ", ", err)
		}

		configCh <- b
	}
}

func inSlice(n Neighbor, b []Neighbor) bool {
	for _, nb := range b {
		if nb.NeighborAddress.String() == n.NeighborAddress.String() {
			return true
		}
	}
	return false
}

func UpdateConfig(curC *Bgp, newC *Bgp) (*Bgp, []Neighbor, []Neighbor) {
	bgpConfig := Bgp{}
	if curC == nil {
		bgpConfig.Global = newC.Global
		curC = &bgpConfig
	} else {
		// can't update the global config
		bgpConfig.Global = curC.Global
	}
	added := []Neighbor{}
	deleted := []Neighbor{}

	for _, n := range newC.NeighborList {
		if inSlice(n, curC.NeighborList) == false {
			added = append(added, n)
		}
	}

	for _, n := range curC.NeighborList {
		if inSlice(n, newC.NeighborList) == false {
			deleted = append(deleted, n)
		}
	}

	bgpConfig.NeighborList = newC.NeighborList
	return &bgpConfig, added, deleted
}
