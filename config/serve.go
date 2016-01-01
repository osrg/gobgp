package config

import (
	log "github.com/Sirupsen/logrus"
	"github.com/spf13/viper"
	"reflect"
)

type BgpConfigSet struct {
	Bgp    Bgp
	Policy RoutingPolicy
}

func ReadConfigfileServe(path, format string, configCh chan BgpConfigSet, reloadCh chan bool) {
	cnt := 0
	for {
		<-reloadCh

		b := Bgp{}
		p := RoutingPolicy{}
		v := viper.New()
		v.SetConfigFile(path)
		v.SetConfigType(format)
		err := v.ReadInConfig()
		if err != nil {
			goto ERROR
		}
		err = v.Unmarshal(&b)
		if err != nil {
			goto ERROR
		}
		err = SetDefaultConfigValues(v, &b)
		if err != nil {
			goto ERROR
		}
		err = v.Unmarshal(&p)
		if err != nil {
			goto ERROR
		}

		if cnt == 0 {
			log.Info("finished reading the config file")
		}
		cnt++
		configCh <- BgpConfigSet{Bgp: b, Policy: p}
		continue

	ERROR:
		if cnt == 0 {
			log.Fatal("can't read config file ", path, ", ", err)
		} else {
			log.Warning("can't read config file ", path, ", ", err)
			continue
		}

	}
}

func inSlice(n Neighbor, b []Neighbor) int {
	for i, nb := range b {
		if nb.Config.NeighborAddress == n.Config.NeighborAddress {
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

	for _, n := range newC.Neighbors {
		if idx := inSlice(n, curC.Neighbors); idx < 0 {
			added = append(added, n)
		} else {
			if !reflect.DeepEqual(n.ApplyPolicy, curC.Neighbors[idx].ApplyPolicy) {
				updated = append(updated, n)
			}
		}
	}

	for _, n := range curC.Neighbors {
		if inSlice(n, newC.Neighbors) < 0 {
			deleted = append(deleted, n)
		}
	}

	bgpConfig.Neighbors = newC.Neighbors
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
