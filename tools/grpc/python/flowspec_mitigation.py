#!/usr/bin/env python

"""
DDoS auto-mitigation via FlowSpec using GoBGP's gRPC API.

Runs a lightweight HTTP server that receives attack alerts from a DDoS
detection system and dynamically adds or removes FlowSpec rules through
GoBGP. When an attack is detected, the corresponding FlowSpec rule is
announced to upstream routers. When the attack clears, the rule is
withdrawn.

The webhook interface is generic and works with any system that can
POST JSON (custom sFlow analyzers, monitoring tools, etc.).

Usage:
    # Generate gRPC bindings first (see docs/sources/grpc-client.md)
    $ cd tools/grpc/python
    $ PYTHONPATH=$PYTHONPATH:./api python3 flowspec_mitigation.py

    # Add a FlowSpec rule to drop UDP traffic to 203.0.113.1/32:
    $ curl -X POST http://localhost:8080/mitigate -H 'Content-Type: application/json' -d '{
        "destination": "203.0.113.1/32",
        "protocol": 17,
        "action": "discard"
      }'

    # Add a rate-limit rule for TCP port 80 traffic:
    $ curl -X POST http://localhost:8080/mitigate -H 'Content-Type: application/json' -d '{
        "destination": "203.0.113.0/24",
        "protocol": 6,
        "destination_port": 80,
        "action": "rate-limit",
        "rate": 1000.0
      }'

    # Remove a rule by its UUID (returned from the mitigate response):
    $ curl -X POST http://localhost:8080/clear -H 'Content-Type: application/json' -d '{
        "uuid": "hex-uuid-from-mitigate-response"
      }'

    # List active FlowSpec rules:
    $ curl http://localhost:8080/rules
"""

from __future__ import absolute_import
from __future__ import print_function

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import grpc

import attribute_pb2
import common_pb2
import extcom_pb2
import gobgp_pb2
import gobgp_pb2_grpc
import nlri_pb2

_TIMEOUT_SECONDS = 10
_GOBGP_GRPC_ADDR = "localhost:50051"
_LISTEN_ADDR = "0.0.0.0"
_LISTEN_PORT = 8080

# RFC 5575 numeric operator flags (see also gobgp constant.go)
_OP_EQ = 0x01
_OP_END = 0x80

# FlowSpec component types (RFC 5575 Section 4)
_TYPE_DST_PREFIX = 1
_TYPE_SRC_PREFIX = 2
_TYPE_PROTOCOL = 3
_TYPE_DST_PORT = 5
_TYPE_SRC_PORT = 6

# Common IP protocol numbers
_PROTO_ICMP = 1
_PROTO_TCP = 6
_PROTO_UDP = 17
_PROTO_GRE = 47

# Active rules keyed by UUID for clean withdrawal
_active_rules = {}
_lock = threading.Lock()


def _build_flowspec_rules(params):
    """Build FlowSpec NLRI rules from request parameters."""
    rules = []

    if "destination" in params:
        prefix, prefix_len = params["destination"].rsplit("/", 1)
        rules.append(nlri_pb2.FlowSpecRule(
            ip_prefix=nlri_pb2.FlowSpecIPPrefix(
                type=_TYPE_DST_PREFIX,
                prefix_len=int(prefix_len),
                prefix=prefix,
            )
        ))

    if "source" in params:
        prefix, prefix_len = params["source"].rsplit("/", 1)
        rules.append(nlri_pb2.FlowSpecRule(
            ip_prefix=nlri_pb2.FlowSpecIPPrefix(
                type=_TYPE_SRC_PREFIX,
                prefix_len=int(prefix_len),
                prefix=prefix,
            )
        ))

    if "protocol" in params:
        rules.append(nlri_pb2.FlowSpecRule(
            component=nlri_pb2.FlowSpecComponent(
                type=_TYPE_PROTOCOL,
                items=[nlri_pb2.FlowSpecComponentItem(
                    op=_OP_END | _OP_EQ,
                    value=int(params["protocol"]),
                )],
            )
        ))

    if "destination_port" in params:
        rules.append(nlri_pb2.FlowSpecRule(
            component=nlri_pb2.FlowSpecComponent(
                type=_TYPE_DST_PORT,
                items=[nlri_pb2.FlowSpecComponentItem(
                    op=_OP_END | _OP_EQ,
                    value=int(params["destination_port"]),
                )],
            )
        ))

    if "source_port" in params:
        rules.append(nlri_pb2.FlowSpecRule(
            component=nlri_pb2.FlowSpecComponent(
                type=_TYPE_SRC_PORT,
                items=[nlri_pb2.FlowSpecComponentItem(
                    op=_OP_END | _OP_EQ,
                    value=int(params["source_port"]),
                )],
            )
        ))

    return rules


def _build_action(params):
    """Build the FlowSpec extended community action."""
    action = params.get("action", "discard")

    if action == "discard":
        return extcom_pb2.ExtendedCommunity(
            traffic_rate=extcom_pb2.TrafficRateExtended(rate=0.0)
        )
    elif action == "rate-limit":
        rate = float(params.get("rate", 0.0))
        return extcom_pb2.ExtendedCommunity(
            traffic_rate=extcom_pb2.TrafficRateExtended(rate=rate)
        )
    elif action == "redirect":
        asn = int(params.get("redirect_asn", 0))
        local_admin = int(params.get("redirect_local_admin", 0))
        return extcom_pb2.ExtendedCommunity(
            redirect_two_octet_as_specific=(
                extcom_pb2.RedirectTwoOctetAsSpecificExtended(
                    asn=asn,
                    local_admin=local_admin,
                )
            )
        )
    else:
        # Default to accept (no extended community needed)
        return None


def _detect_family(params):
    """Detect whether to use IPv4 or IPv6 FlowSpec based on prefixes."""
    for key in ("destination", "source"):
        if key in params and ":" in params[key].split("/")[0]:
            return common_pb2.Family(
                afi=common_pb2.Family.AFI_IP6,
                safi=common_pb2.Family.SAFI_FLOW_SPEC_UNICAST,
            )
    return common_pb2.Family(
        afi=common_pb2.Family.AFI_IP,
        safi=common_pb2.Family.SAFI_FLOW_SPEC_UNICAST,
    )


def add_flowspec_rule(stub, params):
    """Add a FlowSpec rule to GoBGP and return its UUID."""
    rules = _build_flowspec_rules(params)
    if not rules:
        raise ValueError("no match criteria specified")

    nlri = nlri_pb2.NLRI(
        flow_spec=nlri_pb2.FlowSpecNLRI(rules=rules)
    )

    attributes = [
        attribute_pb2.Attribute(
            origin=attribute_pb2.OriginAttribute(origin=0)
        ),
    ]

    action_community = _build_action(params)
    if action_community is not None:
        attributes.append(
            attribute_pb2.Attribute(
                extended_communities=(
                    attribute_pb2.ExtendedCommunitiesAttribute(
                        communities=[action_community]
                    )
                )
            )
        )

    family = _detect_family(params)

    response = stub.AddPath(
        gobgp_pb2.AddPathRequest(
            table_type=gobgp_pb2.TABLE_TYPE_GLOBAL,
            path=gobgp_pb2.Path(
                nlri=nlri,
                pattrs=attributes,
                family=family,
            ),
        ),
        timeout=_TIMEOUT_SECONDS,
    )

    uuid = response.uuid.hex()
    with _lock:
        _active_rules[uuid] = params
    return uuid


def delete_flowspec_rule(stub, uuid):
    """Remove a FlowSpec rule by its UUID."""
    stub.DeletePath(
        gobgp_pb2.DeletePathRequest(
            table_type=gobgp_pb2.TABLE_TYPE_GLOBAL,
            uuid=bytes.fromhex(uuid),
        ),
        timeout=_TIMEOUT_SECONDS,
    )

    with _lock:
        _active_rules.pop(uuid, None)


def list_flowspec_rules(stub):
    """List active FlowSpec routes from the global RIB."""
    result = []
    for family_afi in (common_pb2.Family.AFI_IP, common_pb2.Family.AFI_IP6):
        family = common_pb2.Family(
            afi=family_afi,
            safi=common_pb2.Family.SAFI_FLOW_SPEC_UNICAST,
        )
        try:
            paths = stub.ListPath(
                gobgp_pb2.ListPathRequest(
                    table_type=gobgp_pb2.TABLE_TYPE_GLOBAL,
                    family=family,
                ),
                timeout=_TIMEOUT_SECONDS,
            )
            for dest in paths:
                for path in dest.destination.paths:
                    result.append(path.nlri.flow_spec)
        except grpc.RpcError:
            pass
    return result


class MitigationHandler(BaseHTTPRequestHandler):
    stub = None

    def _send_json(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length)) if length else {}

    def do_POST(self):
        if self.path == "/mitigate":
            try:
                params = self._read_body()
                uuid = add_flowspec_rule(self.stub, params)
                print("[+] added rule %s: %s" % (uuid[:12], params))
                self._send_json(200, {"status": "ok", "uuid": uuid})
            except Exception as e:
                print("[-] error adding rule: %s" % e)
                self._send_json(400, {"status": "error", "message": str(e)})

        elif self.path == "/clear":
            try:
                params = self._read_body()
                uuid = params.get("uuid", "")
                delete_flowspec_rule(self.stub, uuid)
                print("[+] removed rule %s" % uuid[:12])
                self._send_json(200, {"status": "ok"})
            except Exception as e:
                print("[-] error removing rule: %s" % e)
                self._send_json(400, {"status": "error", "message": str(e)})

        else:
            self._send_json(404, {"status": "not found"})

    def do_GET(self):
        if self.path == "/rules":
            with _lock:
                rules = dict(_active_rules)
            self._send_json(200, {"rules": rules})
        else:
            self._send_json(404, {"status": "not found"})

    def log_message(self, format, *args):
        pass  # Suppress default access logs


def run():
    channel = grpc.insecure_channel(_GOBGP_GRPC_ADDR)
    stub = gobgp_pb2_grpc.GoBgpServiceStub(channel)
    MitigationHandler.stub = stub

    server = HTTPServer((_LISTEN_ADDR, _LISTEN_PORT), MitigationHandler)
    print("FlowSpec mitigation webhook listening on %s:%d" % (
        _LISTEN_ADDR, _LISTEN_PORT))
    print("GoBGP gRPC target: %s" % _GOBGP_GRPC_ADDR)
    print("")
    print("Endpoints:")
    print("  POST /mitigate  - add a FlowSpec rule")
    print("  POST /clear     - remove a FlowSpec rule by UUID")
    print("  GET  /rules     - list active rules")
    print("")
    print("Verify with: gobgp global rib -a ipv4-flowspec")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down")
        server.server_close()


if __name__ == "__main__":
    run()
