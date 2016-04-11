package config

import (
	log "github.com/Sirupsen/logrus"
	"github.com/spf13/viper"
	"os"
	"os/signal"
	"reflect"
	"syscall"
)

type BgpConfigSet struct {
	Global            Global             `mapstructure:"global"`
	Neighbors         []Neighbor         `mapstructure:"neighbors"`
	PeerGroups        []PeerGroup        `mapstructure:"peer-groups"`
	RpkiServers       []RpkiServer       `mapstructure:"rpki-servers"`
	BmpServers        []BmpServer        `mapstructure:"bmp-servers"`
	MrtDump           []Mrt              `mapstructure:"mrt-dump"`
	DefinedSets       DefinedSets        `mapstructure:"defined-sets"`
	PolicyDefinitions []PolicyDefinition `mapstructure:"policy-definitions"`
}

func ReadConfigfileServe(path, format string, configCh chan *BgpConfigSet) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)

	cnt := 0
	for {
		c := &BgpConfigSet{}
		v := viper.New()
		v.SetConfigFile(path)
		v.SetConfigType(format)
		var err error
		if err = v.ReadInConfig(); err != nil {
			goto ERROR
		}
		if err = v.UnmarshalExact(c); err != nil {
			goto ERROR
		}
		if err = SetDefaultConfigValues(v, c); err != nil {
			goto ERROR
		}
		if cnt == 0 {
			log.Info("finished reading the config file")
		}
		cnt++
		configCh <- c
		select {
		case <-sigCh:
			log.Info("reload the config file")
		}
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

func ConfigSetToRoutingPolicy(c *BgpConfigSet) *RoutingPolicy {
	return &RoutingPolicy{
		DefinedSets:       c.DefinedSets,
		PolicyDefinitions: c.PolicyDefinitions,
	}
}

func UpdateConfig(curC *BgpConfigSet, newC *BgpConfigSet) (*BgpConfigSet, []Neighbor, []Neighbor, []Neighbor, bool) {
	bgpConfig := &BgpConfigSet{}
	if curC == nil {
		bgpConfig.Global = newC.Global
		curC = bgpConfig
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
	return bgpConfig, added, deleted, updated, CheckPolicyDifference(ConfigSetToRoutingPolicy(curC), ConfigSetToRoutingPolicy(newC))
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
