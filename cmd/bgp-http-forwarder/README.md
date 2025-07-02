# BGP HTTP Forwarder

This service forwards BGP messages to an HTTP endpoint, with special support for BGP-LS messages.

## Configuration

Configuration is done via `config.toml`:

```toml
[http]
endpoint = "http://localhost:8080/bgp"  # HTTP endpoint to forward messages to

[bgp]
as_number = 65000  # Local AS number
peer_ip = "192.168.1.1"  # BGP peer IP address
```

## Message Format

Messages are sent as JSON with the following format:

```json
{
  "type": "bgp_ls",  // Message type: bgp_ls, peer_state, or update
  "timestamp": "2023-05-27T20:44:57Z",  // UTC timestamp in RFC3339 format
  "content": {
    "nlri": {
      "protocol_id": "isis_l1",
      "identifier": "000000000001",
      "local_node_descriptors": {
        "autonomous_system": 65000,
        "bgp_ls_id": "0.0.0.1",
        "igp_router_id": "0000.0000.0001",
        "ospf_area_id": "0.0.0.0"
      }
    },
    "attributes": [
      {
        "type": "ls",
        "node": {
          "flags": {
            "overload": false,
            "attached": true,
            "external": false,
            "abr": true,
            "router": true,
            "v6": false
          },
          "name": "router1.example.com",
          "isis_area": ["49.0001"],
          "local_router_id": "192.0.2.1",
          "sr_capabilities": {
            "ipv4_supported": true,
            "ipv6_supported": false,
            "ranges": [
              {
                "range": 1000,
                "flags": {"value": 0}
              }
            ]
          },
          "sr_algorithms": [0, 1],
          "sr_local_block": {
            "range_size": 1000,
            "first_label": 16000
          }
        }
      },
      {
        "type": "origin",
        "value": 0
      },
      {
        "type": "as_path",
        "segments": [
          {
            "type": 2,
            "segments": [65000, 65001]
          }
        ]
      },
      {
        "type": "next_hop",
        "value": "192.0.2.1"
      }
    ]
  }
}
```

### Link NLRI Example

```json
{
  "type": "bgp_ls",
  "timestamp": "2023-05-27T20:44:58Z",
  "content": {
    "nlri": {
      "protocol_id": "isis_l1",
      "identifier": "000000000002",
      "local_node_descriptors": {
        "autonomous_system": 65000,
        "igp_router_id": "0000.0000.0001"
      },
      "remote_node_descriptors": {
        "autonomous_system": 65000,
        "igp_router_id": "0000.0000.0002"
      },
      "link_descriptors": {
        "ipv4_interface_address": "192.0.2.1",
        "ipv4_neighbor_address": "192.0.2.2",
        "link_local_id": 1,
        "link_remote_id": 2
      }
    },
    "attributes": [
      {
        "type": "ls",
        "link": {
          "name": "link1-2",
          "local_router_id": "192.0.2.1",
          "remote_router_id": "192.0.2.2",
          "admin_group": 0,
          "default_te_metric": 10,
          "igp_metric": 10,
          "bandwidth": 10000000000,
          "reservable_bandwidth": 10000000000,
          "unreserved_bandwidth": [
            10000000000,
            10000000000,
            10000000000,
            10000000000,
            10000000000,
            10000000000,
            10000000000,
            10000000000
          ],
          "srlgs": [1, 2, 3],
          "sr_adjacency_sid": 24001
        }
      }
    ]
  }
}
```

### Prefix NLRI Example

```json
{
  "type": "bgp_ls",
  "timestamp": "2023-05-27T20:44:59Z",
  "content": {
    "nlri": {
      "protocol_id": "isis_l1",
      "identifier": "000000000003",
      "local_node_descriptors": {
        "autonomous_system": 65000,
        "igp_router_id": "0000.0000.0001"
      },
      "prefix_descriptors": {
        "ip_reachability_info": "192.0.2.0/24",
        "ospf_route_type": "intra_area",
        "prefix_sid": {
          "flags": "0x00",
          "algorithm": 0,
          "sid": 16001
        }
      }
    },
    "attributes": [
      {
        "type": "ls",
        "prefix": {
          "igp_flags": {
            "down": false,
            "no_unicast": false,
            "local_address": true,
            "propagate_nssa": false
          },
          "sr_prefix_sid": 16001
        }
      }
    ]
  }
}
```

### Peer State Change Example

```json
{
  "type": "peer_state",
  "timestamp": "2023-05-27T20:44:56Z",
  "content": {
    "conf": {
      "neighbor_address": "192.168.1.1",
      "peer_as": 65000
    },
    "state": {
      "session_state": "ESTABLISHED"
    }
  }
}
```

## Message Types

The forwarder supports three types of messages:

1. `bgp_ls`: BGP Link-State messages containing topology information
2. `peer_state`: BGP peer state changes
3. `update`: Regular BGP updates (non BGP-LS)

See `schema.json` for the complete message schema.

## Installation

```bash
cd cmd/bgp-http-forwarder
go build
```

## Running

```bash
./bgp-http-forwarder -peer 192.168.1.1 -as 65000 -http http://localhost:8080/bgp
```

Or using Docker:

```bash
docker run -d \
  --name bgp-forwarder \
  -e BGP_PEER_IP=192.168.1.1 \
  -e BGP_AS_NUMBER=65000 \
  -e BGP_HTTP_ENDPOINT=http://localhost:8080/bgp \
  bgp-http-forwarder
