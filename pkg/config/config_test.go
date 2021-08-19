package config

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/osrg/gobgp/v3/pkg/server"
)

// ExampleUpdateConfig shows how InitialConfig can be used without UpdateConfig
func ExampleInitialConfig() {
	bgpServer := server.NewBgpServer()
	go bgpServer.Serve()

	initialConfig, err := ReadConfigFile("gobgp.conf", "toml")
	if err != nil {
		// Handle error
		return
	}

	isGracefulRestart := true
	_, err = InitialConfig(context.Background(), bgpServer, initialConfig, isGracefulRestart)

	if err != nil {
		// Handle error
		return
	}
}

// ExampleUpdateConfig shows how UpdateConfig is used in conjunction with
// InitialConfig.
func ExampleUpdateConfig() {
	bgpServer := server.NewBgpServer()
	go bgpServer.Serve()

	initialConfig, err := ReadConfigFile("gobgp.conf", "toml")
	if err != nil {
		// Handle error
		return
	}

	isGracefulRestart := true
	currentConfig, err := InitialConfig(context.Background(), bgpServer, initialConfig, isGracefulRestart)

	if err != nil {
		// Handle error
		return
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)

	for range sigCh {
		newConfig, err := ReadConfigFile("gobgp.conf", "toml")
		if err != nil {
			// Handle error
			continue
		}

		currentConfig, err = UpdateConfig(context.Background(), bgpServer, currentConfig, newConfig)
		if err != nil {
			// Handle error
			continue
		}
	}
}
