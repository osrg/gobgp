package main

import (
	"context"
	"flag"
	stdlog "log"
	// "net"
	"os"
	insecure "google.golang.org/grpc/credentials/insecure"
	toml "github.com/BurntSushi/toml"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/server"
	"github.com/osrg/gobgp/v4/pkg/log"
)

type Config struct {
	GRPC GRPCConfig `toml:"grpc"`
	BGP  BGPConfig  `toml:"bgp"`
}

type GRPCConfig struct {
	Endpoint string `toml:"endpoint"` // Python gRPC server
}

type BGPConfig struct {
	ASNumber    *uint32 `toml:"as_number"`
	PeerIP      *string `toml:"peer_ip"`
	PassiveMode *bool   `toml:"passive-mode"`
}

func main() {
	var (
		peerIP   = flag.String("peer", "", "BGP peer IP address")
		asn      = flag.Uint64("as", 65000, "AS number")
		endpoint = flag.String("grpc", "localhost:50051", "gRPC endpoint")
	)
	var passiveModeFlag bool
	flag.BoolVar(&passiveModeFlag, "passive", false, "Enable passive mode")
	flag.Parse()

	// Load config from toml file if it exists
	config := &Config{
		GRPC: GRPCConfig{Endpoint: *endpoint},
		BGP: BGPConfig{},
	}
	
	// Try to load config.toml
	if _, err := os.Stat("config.toml"); err == nil {
		data, err := os.ReadFile("config.toml")
		if err != nil {
			stdlog.Fatalf("Error reading config file: %v", err)
		}
		if err := toml.Unmarshal(data, config); err != nil {
			stdlog.Fatalf("Error parsing config file: %v", err)
		}
		
		// Override with command line flags if provided
		if *peerIP != "" {
			asNum := uint32(*asn)
			config.BGP.PeerIP = peerIP
			config.BGP.ASNumber = &asNum
		} else if config.BGP.ASNumber != nil {
			asn = new(uint64)
			*asn = uint64(*config.BGP.ASNumber)
			peerIP = config.BGP.PeerIP
		}
	} else {
		asNum := uint32(*asn)
		config.BGP.ASNumber = &asNum
		config.BGP.PeerIP = peerIP
	}

	// Setup logging
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	// Create GoBGP server
	s := server.NewBgpServer(server.LoggerOption(&myLogger{logger: logger}))
	go s.Serve()

	// Start BGP server
	if err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        uint32(*asn),
			RouterId:   "1.0.0.0",
			ListenPort: -1,
		},
	}); err != nil {
		stdlog.Fatal(err)
	}
	
	// Validate peer IP provided
	if *peerIP == "" {
		stdlog.Fatal("BGP peer IP not provided")
	}

	// Connect to Python gRPC server as a CLIENT
	pythonEndpoint := config.GRPC.Endpoint
	if pythonEndpoint == "" {
		pythonEndpoint = *endpoint
	}
	
	conn, err := grpc.Dial(pythonEndpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		stdlog.Fatalf("Failed to connect to Python gRPC server at %s: %v", pythonEndpoint, err)
	}
	defer conn.Close()
	logger.Infof("Connected to Python gRPC server at %s", pythonEndpoint)
	
	// Create GoBGP gRPC client
	bgpClient := api.NewGoBgpServiceClient(conn)
	
	// Watch for BGP events and forward to Python gRPC server
	if err := s.WatchEvent(context.Background(), &api.WatchEventRequest{
		Table: &api.WatchEventRequest_Table{
			Filters: []*api.WatchEventRequest_Table_Filter{
				{Type: api.WatchEventRequest_Table_Filter_TYPE_BEST},
			},
		},
	}, func(r *api.WatchEventResponse) {
		if t := r.GetTable(); t != nil {
			for _, path := range t.Paths {
				if path.Family != nil && path.Family.Afi == api.Family_AFI_LS && path.Family.Safi == api.Family_SAFI_LS {
					// Forward BGP-LS message to Python server via AddPath
					logger.Infof("Forwarding BGP-LS message to Python gRPC server")
					_, err := bgpClient.AddPath(context.Background(), &api.AddPathRequest{
						TableType: api.TableType_TABLE_TYPE_GLOBAL,
						Path:      path,
					})
					if err != nil {
						logger.Errorf("Failed to forward BGP-LS message: %v", err)
					}
				}
			}
		}
	}); err != nil {
		stdlog.Fatal(err)
	}

	// Add BGP neighbor
	peer := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: *peerIP,
			PeerAsn:         uint32(*asn),
		},
		ApplyPolicy: &api.ApplyPolicy{
			ImportPolicy: &api.PolicyAssignment{
				DefaultAction: api.RouteAction_ROUTE_ACTION_ACCEPT,
			},
			ExportPolicy: &api.PolicyAssignment{
				DefaultAction: api.RouteAction_ROUTE_ACTION_REJECT,
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
	}

	if config.BGP.PassiveMode != nil && *config.BGP.PassiveMode {
		peer.Transport = &api.Transport{
			PassiveMode: true,
		}
	}

	if err := s.AddPeer(context.Background(), &api.AddPeerRequest{
		Peer: peer,
	}); err != nil {
		stdlog.Fatal(err)
	}

	// Wait forever
	select {}
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
	l.logger.SetLevel(logrus.Level(int(level)))
}

func (l *myLogger) GetLevel() log.LogLevel {
	return log.LogLevel(l.logger.GetLevel())
}

