package config

import (
	"github.com/BurntSushi/toml"
	log "github.com/Sirupsen/logrus"
)

func ReadConfigfileServe(path string, configCh chan BgpType, reloadCh chan bool) {
	for {
		<-reloadCh

		b := BgpType{}
		_, err := toml.DecodeFile(path, &b)
		if err != nil {
			log.Fatal("can't read config file ", path)
		} else {
			// TODO: validate configuration
			for i, _ := range b.NeighborList {
				SetNeighborTypeDefault(&b.NeighborList[i])
			}
		}

		configCh <- b
	}
}

func inSlice(n NeighborType, b []NeighborType) bool {
	for _, nb := range b {
		if nb.NeighborAddress.String() == n.NeighborAddress.String() {
			return true
		}
	}
	return false
}

func UpdateConfig(curC *BgpType, newC *BgpType) (*BgpType, []NeighborType, []NeighborType) {
	bgpConfig := BgpType{}
	if curC == nil {
		bgpConfig.Global = newC.Global
		curC = &bgpConfig
	} else {
		// can't update the global config
		bgpConfig.Global = curC.Global
	}
	added := []NeighborType{}
	deleted := []NeighborType{}

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
