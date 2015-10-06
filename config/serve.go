package config

import (
	"github.com/BurntSushi/toml"
	log "github.com/Sirupsen/logrus"
	"reflect"
)

type BgpConfigSet struct {
	Bgp    Bgp
	Policy RoutingPolicy
}

func ReadConfigfileServe(path string, configCh chan BgpConfigSet, reloadCh chan bool) {
	cnt := 0
	for {
		<-reloadCh

		b := Bgp{}
		p := RoutingPolicy{}
		md, err := toml.DecodeFile(path, &b)
		if err == nil {
			err = SetDefaultConfigValues(md, &b)
			if err == nil {
				_, err = toml.DecodeFile(path, &p)
			}
		}

		if err != nil {
			if cnt == 0 {
				log.Fatal("can't read config file ", path, ", ", err)
			} else {
				log.Warning("can't read config file ", path, ", ", err)
				continue
			}
		}
		if cnt == 0 {
			log.Info("finished reading the config file")
		}
		cnt++
		bgpConfig := BgpConfigSet{Bgp: b, Policy: p}
		configCh <- bgpConfig
	}
}

func inSlice(n Neighbor, b []Neighbor) int {
	for i, nb := range b {
		if nb.NeighborConfig.NeighborAddress.String() == n.NeighborConfig.NeighborAddress.String() {
			return i
		}
	}
	return -1
}

func UpdateConfig(curC *Bgp, newC *Bgp) (*Bgp, []Neighbor, []Neighbor, []Neighbor) {
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
	updated := []Neighbor{}

	for _, n := range newC.Neighbors.NeighborList {
		if idx := inSlice(n, curC.Neighbors.NeighborList); idx < 0 {
			added = append(added, n)
		} else {
			if !reflect.DeepEqual(n.ApplyPolicy, curC.Neighbors.NeighborList[idx].ApplyPolicy) {
				updated = append(updated, n)
			}
		}
	}

	for _, n := range curC.Neighbors.NeighborList {
		if inSlice(n, newC.Neighbors.NeighborList) < 0 {
			deleted = append(deleted, n)
		}
	}

	bgpConfig.Neighbors.NeighborList = newC.Neighbors.NeighborList
	return &bgpConfig, added, deleted, updated
}

func CheckPolicyDifference(currentPolicy *RoutingPolicy, newPolicy *RoutingPolicy) bool {

	log.Debug("current policy : ", currentPolicy)
	log.Debug("newPolicy policy : ", newPolicy)

	var result bool = false
	if currentPolicy == nil && newPolicy == nil {

		result = false
	} else {
		if currentPolicy != nil && newPolicy != nil {
			// TODO: reconsider the way of policy object comparison
			result = !reflect.DeepEqual(*currentPolicy, *newPolicy)
		} else {
			result = true
		}
	}
	return result
}
