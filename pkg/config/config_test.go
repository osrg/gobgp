package config

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

func TestTcpAoKeychainConfigLifecycle(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "gobgpd.toml")

	writeConfig := func(content string) *oc.BgpConfigSet {
		require.NoError(t, os.WriteFile(configFile, []byte(content), 0o600))
		config, err := ReadConfigFile(configFile, "toml")
		require.NoError(t, err)
		return config
	}
	global := `
[global.config]
  as = 65000
  router-id = "192.0.2.1"
  port = -1
`
	initial := writeConfig(global + `
[[keychains]]
  [keychains.config]
    name = "fabric"
  [[keychains.keys]]
    [keychains.keys.config]
      key-id = 1
      receive-id = 11
      crypto-algorithm = "hmac_sha_1_96"
      secret-key = "aW5pdGlhbA=="
`)
	bgpServer := server.NewBgpServer()
	go bgpServer.Serve()
	t.Cleanup(func() {
		require.NoError(t, bgpServer.StopBgp(context.Background(), &api.StopBgpRequest{}))
	})
	current, err := InitialConfig(context.Background(), bgpServer, initial, false)
	require.NoError(t, err)

	listed := listTcpAoKeychains(t, bgpServer)
	require.Contains(t, listed, "fabric")
	require.Len(t, listed["fabric"].Keys, 1)
	assert.Equal(t, uint32(1), listed["fabric"].Keys[0].SendId)
	assert.Empty(t, listed["fabric"].Keys[0].MasterKey)

	replacement := *current
	replacement.Keychains = append([]oc.Keychain(nil), current.Keychains...)
	replacement.Keychains[0].Keys = append([]oc.Key(nil), current.Keychains[0].Keys...)
	replacement.Keychains[0].Keys[0].Config.SecretKey = "dXBkYXRlZA=="
	_, err = UpdateConfig(context.Background(), bgpServer, current, &replacement)
	require.ErrorContains(t, err, "key replacement requires separate delete + add configuration updates")

	updated := writeConfig(global + `
[[keychains]]
  [keychains.config]
    name = "fabric"
  [[keychains.keys]]
    [keychains.keys.config]
      key-id = 2
      receive-id = 12
      crypto-algorithm = "aes_128_cmac_96"
      secret-key = "dXBkYXRlZA=="

[[keychains]]
  [keychains.config]
    name = "edge"
  [[keychains.keys]]
    [keychains.keys.config]
      key-id = 3
      receive-id = 13
      crypto-algorithm = "hmac_sha_1_96"
      exclude-tcp-options = true
      secret-key = "ZWRnZS1rZXk="
`)
	current, err = UpdateConfig(context.Background(), bgpServer, current, updated)
	require.NoError(t, err)

	listed = listTcpAoKeychains(t, bgpServer)
	require.Len(t, listed, 2)
	require.Len(t, listed["fabric"].Keys, 1)
	assert.Equal(t, uint32(2), listed["fabric"].Keys[0].SendId)
	assert.Equal(t, api.TcpAoAlgorithm_TCP_AO_ALGORITHM_AES_128_CMAC_96, listed["fabric"].Keys[0].Algorithm)
	assert.True(t, listed["edge"].Keys[0].ExcludeTcpOptions)
	removed := writeConfig(global + `
[[keychains]]
  [keychains.config]
    name = "fabric"
  [[keychains.keys]]
    [keychains.keys.config]
      key-id = 2
      receive-id = 12
      crypto-algorithm = "aes_128_cmac_96"
      secret-key = "dXBkYXRlZA=="
`)
	_, err = UpdateConfig(context.Background(), bgpServer, current, removed)
	require.NoError(t, err)

	err = bgpServer.ListTcpAoKeychain(context.Background(), &api.ListTcpAoKeychainRequest{Name: "edge"}, func(*api.TcpAoKeychain) {})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func listTcpAoKeychains(t *testing.T, bgpServer *server.BgpServer) map[string]*api.TcpAoKeychain {
	t.Helper()
	result := make(map[string]*api.TcpAoKeychain)
	err := bgpServer.ListTcpAoKeychain(context.Background(), &api.ListTcpAoKeychainRequest{}, func(chain *api.TcpAoKeychain) {
		result[chain.Name] = chain
	})
	require.NoError(t, err)
	return result
}
