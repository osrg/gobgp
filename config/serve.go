package config

import (
	log "github.com/Sirupsen/logrus"
	"github.com/spf13/viper"
	"os"
	"os/signal"
	"syscall"
)

type BgpConfigSet struct {
	Global            Global             `mapstructure:"global"`
	Neighbors         []Neighbor         `mapstructure:"neighbors"`
	PeerGroups        []PeerGroup        `mapstructure:"peer-groups"`
	RpkiServers       []RpkiServer       `mapstructure:"rpki-servers"`
	BmpServers        []BmpServer        `mapstructure:"bmp-servers"`
	MrtDump           []Mrt              `mapstructure:"mrt-dump"`
	Zebra             Zebra              `mapstructure:"zebra"`
	Collector         Collector          `mapstructure:"collector"`
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
		if err = setDefaultConfigValuesWithViper(v, c); err != nil {
			goto ERROR
		}
		if cnt == 0 {
			log.WithFields(log.Fields{
				"Topic": "Config",
			}).Info("Finished reading the config file")
		}
		cnt++
		configCh <- c
		goto NEXT
	ERROR:
		if cnt == 0 {
			log.WithFields(log.Fields{
				"Topic": "Config",
				"Error": err,
			}).Fatalf("Can't read config file %s", path)
		} else {
			log.WithFields(log.Fields{
				"Topic": "Config",
				"Error": err,
			}).Warningf("Can't read config file %s", path)
		}
	NEXT:
		select {
		case <-sigCh:
			log.WithFields(log.Fields{
				"Topic": "Config",
			}).Info("Reload the config file")
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

func UpdateConfig(curC, newC *BgpConfigSet) ([]Neighbor, []Neighbor, []Neighbor, bool) {

	added := []Neighbor{}
	deleted := []Neighbor{}
	updated := []Neighbor{}

	for _, n := range newC.Neighbors {
		if idx := inSlice(n, curC.Neighbors); idx < 0 {
			added = append(added, n)
		} else if !n.Equal(&curC.Neighbors[idx]) {
			log.WithFields(log.Fields{
				"Topic": "Config",
			}).Debugf("Current neighbor config:%s", curC.Neighbors[idx])
			log.WithFields(log.Fields{
				"Topic": "Config",
			}).Debugf("New neighbor config:%s", n)
			updated = append(updated, n)
		}
	}

	for _, n := range curC.Neighbors {
		if inSlice(n, newC.Neighbors) < 0 {
			deleted = append(deleted, n)
		}
	}

	return added, deleted, updated, CheckPolicyDifference(ConfigSetToRoutingPolicy(curC), ConfigSetToRoutingPolicy(newC))
}

func CheckPolicyDifference(currentPolicy *RoutingPolicy, newPolicy *RoutingPolicy) bool {

	log.WithFields(log.Fields{
		"Topic": "Config",
	}).Debugf("Current policy:%s", currentPolicy)
	log.WithFields(log.Fields{
		"Topic": "Config",
	}).Debugf("New policy:%s", newPolicy)

	var result bool = false
	if currentPolicy == nil && newPolicy == nil {

		result = false
	} else {
		if currentPolicy != nil && newPolicy != nil {
			result = !currentPolicy.Equal(newPolicy)
		} else {
			result = true
		}
	}
	return result
}
