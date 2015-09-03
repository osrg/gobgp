#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include <grpc/grpc.h>
#include <grpc++/channel.h>
#include <grpc++/client_context.h>
#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>
#include "gobgp_api_client.grpc.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

using api::Grpc;

class GrpcClient {
    public:
        GrpcClient(std::shared_ptr<Channel> channel) : stub_(Grpc::NewStub(channel)) {}

        std::string GetAllNeighbor(std::string neighbor_ip) {
        api::Arguments request;
        request.set_rf(4);
        request.set_name(neighbor_ip);

        ClientContext context;

        api::Peer peer;
        grpc::Status status = stub_->GetNeighbor(&context, request, &peer);

        if (status.ok()) {
            api::PeerConf peer_conf = peer.conf();
            api::PeerInfo peer_info = peer.info();

            std::stringstream buffer;
  
            buffer
                << "Peer AS: " << peer_conf.remote_as() << "\n"
                << "Peer router id: " << peer_conf.id() << "\n"
                << "Peer flops: " << peer_info.flops() << "\n"
                << "BGP state: " << peer_info.bgp_state();

            return buffer.str();
        } else {
            return "Something wrong";
        }

    }

    private:
        std::unique_ptr<Grpc::Stub> stub_;
};

int main(int argc, char** argv) {
    GrpcClient gobgp_client(grpc::CreateChannel("localhost:8080", grpc::InsecureCredentials()));
 
    std::string reply = gobgp_client.GetAllNeighbor("213.133.111.200");
    std::cout << "We received: " << reply << std::endl;

    return 0;
}
