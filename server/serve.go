package server

import (
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/config"
	"github.com/spf13/viper"
	"os"
	"os/signal"
	"reflect"
	"syscall"
)

type BgpConfigSet struct {
	Bgp    config.Bgp
	Policy config.RoutingPolicy
}

func ReadConfigfileServe(path, format string, configCh chan BgpConfigSet) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)

	cnt := 0
	for {
		b := config.Bgp{}
		v := viper.New()
		v.SetConfigFile(path)
		v.SetConfigType(format)
		err := v.ReadInConfig()
		c := struct {
			Global            config.Global             `mapstructure:"global"`
			Neighbors         []config.Neighbor         `mapstructure:"neighbors"`
			RpkiServers       []config.RpkiServer       `mapstructure:"rpki-servers"`
			DefinedSets       config.DefinedSets        `mapstructure:"defined-sets"`
			PolicyDefinitions []config.PolicyDefinition `mapstructure:"policy-definitions"`
		}{}
		if err != nil {
			goto ERROR
		}
		err = v.UnmarshalExact(&c)
		if err != nil {
			goto ERROR
		}
		b.Global = c.Global
		b.Neighbors = c.Neighbors
		b.RpkiServers = c.RpkiServers
		err = config.SetDefaultConfigValues(v, &b)
		if err != nil {
			goto ERROR
		}
		if cnt == 0 {
			log.Info("finished reading the config file")
		}
		cnt++
		configCh <- BgpConfigSet{
			Bgp: b,
			Policy: config.RoutingPolicy{
				DefinedSets:       c.DefinedSets,
				PolicyDefinitions: c.PolicyDefinitions,
			},
		}
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

func inSlice(n config.Neighbor, b []config.Neighbor) int {
	for i, nb := range b {
		if nb.Config.NeighborAddress == n.Config.NeighborAddress {
			return i
		}
	}
	return -1
}

func UpdateConfig(curC *config.Bgp, newC *config.Bgp) (*config.Bgp, []config.Neighbor, []config.Neighbor, []config.Neighbor) {
	bgpConfig := config.Bgp{}
	if curC == nil {
		bgpConfig.Global = newC.Global
		curC = &bgpConfig
	} else {
		// can't update the global config
		bgpConfig.Global = curC.Global
	}
	added := []config.Neighbor{}
	deleted := []config.Neighbor{}
	updated := []config.Neighbor{}

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

func CheckPolicyDifference(currentPolicy *config.RoutingPolicy, newPolicy *config.RoutingPolicy) bool {

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
