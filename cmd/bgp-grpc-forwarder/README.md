# BGP-GRPC Forwarder

Forwards BGP-LS messages from GoBGP to Python gRPC receiver.

## Differences from bgp-http-forwarder

- **Sends protobuf directly** (no JSON conversion)
- **Connects to Python gRPC server** at localhost:50051
- **Lower overhead** (binary vs text format)

## Usage

```bash
# Run with defaults
go run main.go -peer 192.168.1.1 -as 65001 -grpc localhost:50051

# Or build
go build -o bgp-grpc-forwarder
./bgp-grpc-forwarder -peer 192.168.1.1 -as 65001

# With config file
./bgp-grpc-forwarder  # reads config.toml

# Passive mode
./bgp-grpc-forwarder -peer 1.2.3.4 -as 65001 -passive
```

## With Docker

```bash
docker build -t bgp-grpc-forwarder .
docker run -it --network host bgp-grpc-forwarder
```

## Testing

1. Start Python gRPC server: `python bgp_receiver_grpc.py`
2. Start GoBGP forwarder: `./bgp-grpc-forwarder -peer <peer_ip> -as <asn>`
3. Add routes via CLI:
   ```bash
   gobgp global rib add -a ls node bgp protocol 2 ...
   ```


