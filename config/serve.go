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

		p := RoutingPolicy{}
		md, err = toml.DecodeFile(path, &p)
		if err != nil {
			log.Fatal("can't read config file ", path, ", ", err)
		}

		bgpConfig := BgpConfigSet{Bgp: b, Policy: p}
		configCh <- bgpConfig
	}
}

func inSlice(n Neighbor, b []Neighbor) bool {
	for _, nb := range b {
		if nb.NeighborConfig.NeighborAddress.String() == n.NeighborConfig.NeighborAddress.String() {
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

	for _, n := range newC.Neighbors.NeighborList {
		if inSlice(n, curC.Neighbors.NeighborList) == false {
			added = append(added, n)
		}
	}

	for _, n := range curC.Neighbors.NeighborList {
		if inSlice(n, newC.Neighbors.NeighborList) == false {
			deleted = append(deleted, n)
		}
	}

	bgpConfig.Neighbors.NeighborList = newC.Neighbors.NeighborList
	return &bgpConfig, added, deleted
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
