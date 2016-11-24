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

func ConfigSetToRoutingPolicy(c *BgpConfigSet) *RoutingPolicy {
	return &RoutingPolicy{
		DefinedSets:       c.DefinedSets,
		PolicyDefinitions: c.PolicyDefinitions,
	}
}
func CheckPolicyDifference(currentPolicy, newPolicy *RoutingPolicy) bool {
	if currentPolicy == nil && newPolicy == nil {
		return false
	} else if currentPolicy != nil && newPolicy != nil {
		return !currentPolicy.Equal(newPolicy)
	}
	return true
}
