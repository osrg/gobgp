import gobgp_pb2
import sys

from grpc.beta import implementations
from grpc.framework.interfaces.face.face import ExpirationError

_TIMEOUT_SECONDS = 1


def run(gobgpd_addr):
    channel = implementations.insecure_channel(gobgpd_addr, 50051)
    with gobgp_pb2.beta_create_GobgpApi_stub(channel) as stub:
        try:
            peers = stub.GetNeighbor(gobgp_pb2.GetNeighborRequest(), _TIMEOUT_SECONDS).peers
            for peer in peers:
                print("BGP neighbor is %s, remote AS %d" % (peer.conf.neighbor_address, peer.conf.peer_as))
                print("  BGP version 4, remote router ID %s" % (peer.conf.id))
                print("  BGP state = %s, up for %s" % (peer.info.bgp_state, peer.timers.state.uptime))
                print("  BGP OutQ = %d, Flops = %d" % (peer.info.out_q, peer.info.flops))
                print("  Hold time is %d, keepalive interval is %d seconds" % (peer.timers.state.negotiated_hold_time, peer.timers.state.keepalive_interval))
                print("  Configured hold time is %d, keepalive interval is %d seconds" % (peer.timers.config.hold_time, peer.timers.config.keepalive_interval))
        except ExpirationError, e:
            print str(e)
            sys.exit(-1)

if __name__ == '__main__':
    gobgp = sys.argv[1]
    run(gobgp)
