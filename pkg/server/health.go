package server

import (
	"context"
	"log"
	"sync"
	"time"

	api "github.com/osrg/gobgp/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

// Health defines a health-check connection.
type Health interface {
	// Check returns if server is healthy or not
	Check(c context.Context) (bool, error)
}

type HealthCheckServer struct {
	mu sync.Mutex
	// statusMap stores the serving status of the services this Server monitors.
	statusMap map[string]api.HealthCheckResponse_ServingStatus
}

// NewHealthCheckServer returns a new Server.
func NewHealthCheckServer() *HealthCheckServer {
	return &HealthCheckServer{
		statusMap: make(map[string]api.HealthCheckResponse_ServingStatus),
	}
}

type healthClient struct {
	client api.GobgpApiClient
	conn   *grpc.ClientConn
}

// NewGrpcHealthClient returns a new grpc Client.
func NewGrpcHealthClient(conn *grpc.ClientConn) Health {
	client := new(healthClient)
	client.client = api.NewGobgpApiClient(conn)
	client.conn = conn
	return client
}

func (c *healthClient) Close() error {
	return c.conn.Close()
}

func (c *healthClient) Check(ctx context.Context) (bool, error) {
	var res *api.HealthCheckResponse
	var err error
	req := new(api.HealthCheckRequest)

	res, err = c.client.HealthCheck(ctx, req)
	if err == nil {
		if res.GetStatus() == api.HealthCheckResponse_SERVING {
			return true, nil
		}
		return false, nil
	}
	switch grpc.Code(err) {
	case
		codes.Aborted,
		codes.DataLoss,
		codes.DeadlineExceeded,
		codes.Internal,
		codes.Unavailable:
	default:
		return false, err
	}

	return false, err
}

func healthCheck(address string, checkTime time.Duration) {
	// Set up a connection to the server.
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	client := NewGrpcHealthClient(conn)

	for {
		ok, err := client.Check(context.Background())
		if !ok || err != nil {
			log.Printf("can't connect grpc server: %v, code: %v\n", err, grpc.Code(err))
		} else {
			log.Println("connect the grpc server successfully")
		}

		<-time.After(checkTime)
	}
}
