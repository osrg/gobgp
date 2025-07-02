package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"
	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/log"
	"github.com/osrg/gobgp/v3/pkg/server"
)

type Config struct {
	HTTP HTTPConfig `toml:"http"`
	BGP  BGPConfig  `toml:"bgp"`
}

type HTTPConfig struct {
	Endpoint string `toml:"endpoint"`
}

type BGPConfig struct {
	ASNumber *uint32 `toml:"as_number"`
	PeerIP   *string `toml:"peer_ip"`
}

// Message types for JSON export
type BGPMessage struct {
	Type      string      `json:"type"`      // Message type: "bgp_ls", "peer_state", "update"
	Timestamp string      `json:"timestamp"` // UTC timestamp in RFC3339 format
	Content   interface{} `json:"content"`   // Message content
}


type myLogger struct {
	logger *logrus.Logger
}

func (l *myLogger) Panic(msg string, fields log.Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Panic(msg)
}

func (l *myLogger) Fatal(msg string, fields log.Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Fatal(msg)
}

func (l *myLogger) Error(msg string, fields log.Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Error(msg)
}

func (l *myLogger) Warn(msg string, fields log.Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Warn(msg)
}

func (l *myLogger) Info(msg string, fields log.Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Info(msg)
}

func (l *myLogger) Debug(msg string, fields log.Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Debug(msg)
}

func (l *myLogger) SetLevel(level log.LogLevel) {
	l.logger.SetLevel(logrus.Level(level))
}

func (l *myLogger) GetLevel() log.LogLevel {
	return log.LogLevel(l.logger.GetLevel())
}

func loadConfig() (*Config, error) {
	config := &Config{
		HTTP: HTTPConfig{
			Endpoint: "http://localhost:8080/bgp",
		},
	}

	// Try to load config.toml
	if _, err := os.Stat("config.toml"); err == nil {
		data, err := os.ReadFile("config.toml")
		if err != nil {
			return nil, fmt.Errorf("error reading config file: %v", err)
		}
		if err := toml.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("error parsing config file: %v", err)
		}
	}

	return config, nil
}

func forwardToHTTP(client *http.Client, endpoint string, msgType string, content interface{}) error {
	msg := BGPMessage{
		Type:      msgType,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Content:   content,
	}

	jsonData, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("error marshaling message: %v", err)
	}

	resp, err := client.Post(endpoint, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("error sending HTTP request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status: %s", resp.Status)
	}

	return nil
}

func main() {
	var (
		peerIP   = flag.String("peer", "", "BGP peer IP address")
		asn      = flag.Uint64("as", 0, "AS number")
		endpoint = flag.String("http", "", "HTTP endpoint")
	)
	flag.Parse()

	// Load configuration
	config, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Override config with command line arguments
	if *peerIP != "" {
		config.BGP.PeerIP = peerIP
	}
	if *asn != 0 {
		asNumber := uint32(*asn)
		config.BGP.ASNumber = &asNumber
	}
	if *endpoint != "" {
		config.HTTP.Endpoint = *endpoint
	}

	// Validate configuration
	if config.BGP.PeerIP == nil {
		fmt.Fprintln(os.Stderr, "BGP peer IP not provided")
		os.Exit(1)
	}
	if config.BGP.ASNumber == nil {
		fmt.Fprintln(os.Stderr, "AS number not provided")
		os.Exit(1)
	}

	// Setup logging
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	// Create GoBGP server
	s := server.NewBgpServer(server.LoggerOption(&myLogger{logger: log}))
	go s.Serve()

	// Start BGP server
	if err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        *config.BGP.ASNumber,
			RouterId:   "1.0.0.0",
			ListenPort: -1, // Don't listen on TCP port
		},
	}); err != nil {
		log.Fatal(err)
	}

	// Setup JSON marshaller for BGP messages
	marshaller := protojson.MarshalOptions{
		Indent:        "  ",
		UseProtoNames: true,
	}

	// Create HTTP client for forwarding
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Watch for BGP events
	if err := s.WatchEvent(context.Background(), &api.WatchEventRequest{
		Peer: &api.WatchEventRequest_Peer{},
		Table: &api.WatchEventRequest_Table{
			Filters: []*api.WatchEventRequest_Table_Filter{
				{
					Type: api.WatchEventRequest_Table_Filter_BEST,
				},
			},
		},
	}, func(r *api.WatchEventResponse) {
		if p := r.GetPeer(); p != nil && p.Type == api.WatchEventResponse_PeerEvent_STATE {
			// Forward peer state changes
			peerState, err := marshaller.Marshal(p)
			if err != nil {
				log.Errorf("Failed to marshal peer state: %v", err)
				return
			}

			var content map[string]any
			if err := json.Unmarshal(peerState, &content); err != nil {
				log.Errorf("Failed to unmarshal peer state: %v", err)
				return
			}

			if err := forwardToHTTP(httpClient, config.HTTP.Endpoint, "peer_state", content); err != nil {
				log.Errorf("Failed to forward peer state: %v", err)
			}
		} else if t := r.GetTable(); t != nil {
			// Forward BGP messages
			for _, path := range t.Paths {
				pathJson, err := marshaller.Marshal(path)
				if err != nil {
					log.Errorf("Failed to marshal path: %v", err)
					continue
				}

					// Handle BGP-LS messages
					if path.Family != nil && path.Family.Afi == api.Family_AFI_LS && path.Family.Safi == api.Family_SAFI_LS {
						// Skip manual BGP-LS decoding - use protojson marshaling
						var content map[string]interface{}
						if err := json.Unmarshal(pathJson, &content); err != nil {
							log.Errorf("Failed to unmarshal path: %v", err)
							continue
						}

						// Modify @type for withdrawal updates
						if path.IsWithdraw {
							if attrs, ok := content["pattrs"].([]interface{}); ok {
								for _, attr := range attrs {
									if attrMap, ok := attr.(map[string]interface{}); ok {
										if attrMap["@type"] == "type.googleapis.com/apipb.MpReachNLRIAttribute" {
											attrMap["@type"] = "type.googleapis.com/apipb.MpUnreachNLRIAttribute"
										}
									}
								}
							}
						}

						msg := map[string]interface{}{
							"raw": content,
						}

						if err := forwardToHTTP(httpClient, config.HTTP.Endpoint, "bgp_ls", msg); err != nil {
							log.Errorf("Failed to forward BGP-LS message: %v", err)
						}
					}
			}
		}
	}); err != nil {
		log.Fatal(err)
	}

	// Add BGP neighbor
	if err := s.AddPeer(context.Background(), &api.AddPeerRequest{
		Peer: &api.Peer{
			Conf: &api.PeerConf{
				NeighborAddress: *config.BGP.PeerIP,
				PeerAsn:         *config.BGP.ASNumber,
			},
			ApplyPolicy: &api.ApplyPolicy{
				ImportPolicy: &api.PolicyAssignment{
					DefaultAction: api.RouteAction_ACCEPT,
				},
				ExportPolicy: &api.PolicyAssignment{
					DefaultAction: api.RouteAction_REJECT,
				},
			},
			AfiSafis: []*api.AfiSafi{
				{
					Config: &api.AfiSafiConfig{
						Family: &api.Family{
							Afi:  api.Family_AFI_LS,
							Safi: api.Family_SAFI_LS,
						},
						Enabled: true,
					},
				},
			},
		},
	}); err != nil {
		log.Fatal(err)
	}

	// Wait forever
	select {}
}
