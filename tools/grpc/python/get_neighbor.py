import gobgp_pb2
import sys

_TIMEOUT_SECONDS = 10


def run(gobgpd_addr, neighbor_addr):
    with gobgp_pb2.early_adopter_create_Grpc_stub(gobgpd_addr, 8080) as stub:
        peer = stub.GetNeighbor(gobgp_pb2.Arguments(rf=4, name=neighbor_addr), _TIMEOUT_SECONDS)
        print("BGP neighbor is %s, remote AS %d" % (peer.conf.remote_ip, peer.conf.remote_as))
        print("  BGP version 4, remote router ID %s" % ( peer.conf.id))
        print("  BGP state = %s, up for %s" % ( peer.info.bgp_state, peer.info.uptime))
        print("  BGP OutQ = %d, Flops = %d" % (peer.info.out_q, peer.info.flops))
        print("  Hold time is %d, keepalive interval is %d seconds" % ( peer.info.negotiated_holdtime, peer.info.keepalive_interval))
        print("  Configured hold time is %d, keepalive interval is %d seconds" % ( peer.conf.holdtime, peer.conf.keepalive_interval))


if __name__ == '__main__':
    gobgp = sys.argv[1]
    neighbor = sys.argv[2]
    run(gobgp, neighbor)

