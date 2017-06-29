package gobgp.example;

import gobgpapi.Gobgp;
import gobgpapi.GobgpApiGrpc;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;

import java.util.Iterator;

public class GobgpSampleClient {

    private final GobgpApiGrpc.GobgpApiBlockingStub blockingStub;

    public GobgpSampleClient(String host, int port) {
        ManagedChannel channel = ManagedChannelBuilder.forAddress(host, port).usePlaintext(true).build();
        this.blockingStub = GobgpApiGrpc.newBlockingStub(channel);
    }

    public void getNeighbors(){

        Gobgp.Arguments request = Gobgp.Arguments.newBuilder().build();

        for(Iterator<Gobgp.Peer> iterator = this.blockingStub.getNeighbors(request); iterator.hasNext(); ) {
            Gobgp.Peer p = iterator.next();
            Gobgp.PeerConf conf = p.getConf();
            Gobgp.PeerState state = p.getInfo();
            Gobgp.Timers timer = p.getTimers();

            System.out.printf("BGP neighbor is %s, remote AS %d\n", conf.getNeighborAddress(), conf.getPeerAs());
            System.out.printf("\tBGP version 4, remote router ID %s\n", conf.getId());
            System.out.printf("\tBGP state = %s, up for %d\n", state.getBgpState(), timer.getState().getUptime());
            System.out.printf("\tBGP OutQ = %d, Flops = %d\n", state.getOutQ(), state.getFlops());
            System.out.printf("\tHold time is %d, keepalive interval is %d seconds\n",
                    timer.getState().getHoldTime(), timer.getState().getKeepaliveInterval());
            System.out.printf("\tConfigured hold time is %d\n", timer.getConfig().getHoldTime());

        }
    }

    public static void main(String args[]){
        new GobgpSampleClient(args[0], 8080).getNeighbors();
    }

}

