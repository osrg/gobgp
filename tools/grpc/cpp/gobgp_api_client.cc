#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <string.h>

#include <grpc/grpc.h>
#include <grpc++/channel.h>
#include <grpc++/client_context.h>
#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>
#include "gobgp_api_client.grpc.pb.h"

extern "C" {
    // Gobgp library
    #include "libgobgp.h"
}

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

using gobgpapi::GobgpApi;

class GrpcClient {
    public:
        GrpcClient(std::shared_ptr<Channel> channel) : stub_(GobgpApi::NewStub(channel)) {}
        void GetAllActiveAnnounces(unsigned int route_family) {
            ClientContext context;
            gobgpapi::Table table;

            table.set_family(route_family);
            // We could specify certain neighbor here
            table.set_name("");
            table.set_type(gobgpapi::Resource::GLOBAL);

            gobgpapi::Table response_table; 

            auto status = stub_->GetRib(&context, table, &response_table);

            if (!status.ok()) {
                // error_message
                std::cout << "Problem with RPC: " << status.error_code() << " message " << status.error_message() << std::endl;
                return;
            } else {
                // std::cout << "RPC working well" << std::endl;
            } 

            std::cout << "List of announced prefixes for route family: " << route_family << std::endl << std::endl;
            
            for (auto current_destination : response_table.destinations()) {
                std::cout << "Prefix: " << current_destination.prefix() << std::endl;
    
                //std::cout << "Paths size: " << current_destination.paths_size() << std::endl;

                gobgpapi::Path my_path = current_destination.paths(0);

                // std::cout << "Pattrs size: " << my_path.pattrs_size() << std::endl;

                buf my_nlri;
                my_nlri.value = (char*)my_path.nlri().c_str();
                my_nlri.len = my_path.nlri().size();

                path_t gobgp_lib_path;
                gobgp_lib_path.nlri = my_nlri;
                // Not used in library code!
                gobgp_lib_path.path_attributes_cap = 0;
                gobgp_lib_path.path_attributes_len = my_path.pattrs_size();

                buf* my_path_attributes[ my_path.pattrs_size() ];
                for (int i = 0; i < my_path.pattrs_size(); i++) {
                    my_path_attributes[i] = (buf*)malloc(sizeof(buf));
                    my_path_attributes[i]->len = my_path.pattrs(i).size();
                    my_path_attributes[i]->value = (char*)my_path.pattrs(i).c_str();
                }
            
                gobgp_lib_path.path_attributes = my_path_attributes;

                std::cout << "NLRI: " << decode_path(&gobgp_lib_path) << std::endl; 
            }
        }
        
        void AnnounceFlowSpecPrefix(bool withdraw) {
            const gobgpapi::ModPathArguments current_mod_path_arguments;

            unsigned int AFI_IP = 1;
            unsigned int SAFI_FLOW_SPEC_UNICAST = 133;
            unsigned int ipv4_flow_spec_route_family = AFI_IP<<16 | SAFI_FLOW_SPEC_UNICAST;   

            gobgpapi::Path* current_path = new gobgpapi::Path;
            current_path->set_is_withdraw(withdraw);

            /*
            buf:
                char *value;
                int len;

            path:
                buf   nlri;
                buf** path_attributes;
                int   path_attributes_len;
                int   path_attributes_cap;
            */

            path* path_c_struct = serialize_path(ipv4_flow_spec_route_family, (char*)"match destination 10.0.0.0/24 protocol tcp source 20.0.0.0/24 then redirect 10:10");

            // printf("Decoded NLRI output: %s, length %d raw string length: %d\n", decode_path(path_c_struct), path_c_struct->nlri.len, strlen(path_c_struct->nlri.value));

            for (int path_attribute_number = 0; path_attribute_number < path_c_struct->path_attributes_len; path_attribute_number++) {
                current_path->add_pattrs(path_c_struct->path_attributes[path_attribute_number]->value, 
                    path_c_struct->path_attributes[path_attribute_number]->len);
            }

            current_path->set_nlri(path_c_struct->nlri.value, path_c_struct->nlri.len);

            gobgpapi::ModPathsArguments request;
            request.set_resource(gobgpapi::Resource::GLOBAL);

            google::protobuf::RepeatedPtrField< ::gobgpapi::Path >* current_path_list = request.mutable_paths(); 
            current_path_list->AddAllocated(current_path);
            request.set_name("");

            ClientContext context;

            gobgpapi::Error return_error;

            // result is a std::unique_ptr<grpc::ClientWriter<gobgpapi::ModPathArguments> >
            auto send_stream = stub_->ModPaths(&context, &return_error);

            bool write_result = send_stream->Write(request);

            if (!write_result) {
                std::cout << "Write to API failed\n";
            }

            // Finish all writes
            send_stream->WritesDone();

            auto status = send_stream->Finish();
    
            if (status.ok()) {
                //std::cout << "modpath executed correctly" << std::cout; 
            } else {
                std::cout << "modpath failed with code: " << status.error_code()
                    << " message " << status.error_message() << std::endl;
            }
        }

        void AnnounceUnicastPrefix(bool withdraw) {
            const gobgpapi::ModPathArguments current_mod_path_arguments;

            unsigned int AFI_IP = 1;
            unsigned int SAFI_UNICAST = 1;
            unsigned int ipv4_unicast_route_family = AFI_IP<<16 | SAFI_UNICAST;

            gobgpapi::Path* current_path = new gobgpapi::Path;
            current_path->set_is_withdraw(withdraw);

            /*
            buf:
                char *value;
                int len;

            path:
                buf   nlri;
                buf** path_attributes;
                int   path_attributes_len;
                int   path_attributes_cap;
            */

            // 10.10.20.33/22 nexthop 10.10.1.99/32 
            path* path_c_struct = serialize_path(ipv4_unicast_route_family, (char*)"10.10.20.33/22");

            // printf("Decoded NLRI output: %s, length %d raw string length: %d\n", decode_path(path_c_struct), path_c_struct->nlri.len, strlen(path_c_struct->nlri.value));

            for (int path_attribute_number = 0; path_attribute_number < path_c_struct->path_attributes_len; path_attribute_number++) {
                current_path->add_pattrs(path_c_struct->path_attributes[path_attribute_number]->value, 
                    path_c_struct->path_attributes[path_attribute_number]->len);
            }

            current_path->set_nlri(path_c_struct->nlri.value, path_c_struct->nlri.len);

            gobgpapi::ModPathsArguments request;
            request.set_resource(gobgpapi::Resource::GLOBAL);
            google::protobuf::RepeatedPtrField< ::gobgpapi::Path >* current_path_list = request.mutable_paths(); 
            current_path_list->AddAllocated(current_path);
            request.set_name("");

            ClientContext context;

            gobgpapi::Error return_error;

            // result is a std::unique_ptr<grpc::ClientWriter<api::ModPathArguments> >
            auto send_stream = stub_->ModPaths(&context, &return_error);

            bool write_result = send_stream->Write(request);

            if (!write_result) {
                std::cout << "Write to API failed\n";
            }

            // Finish all writes
            send_stream->WritesDone();

            auto status = send_stream->Finish();
    
            if (status.ok()) {
                //std::cout << "modpath executed correctly" << std::cout; 
            } else {
                std::cout << "modpath failed with code: " << status.error_code()
                    << " message " << status.error_message() << std::endl;
            }
        }

        std::string GetNeighbor(std::string neighbor_ip) {
            gobgpapi::Arguments request;
            request.set_family(4);
            request.set_name(neighbor_ip);

            ClientContext context;

            gobgpapi::Peer peer;
            grpc::Status status = stub_->GetNeighbor(&context, request, &peer);

            if (status.ok()) {
                gobgpapi::PeerConf peer_conf = peer.conf();
                gobgpapi::PeerState peer_info = peer.info();

                std::stringstream buffer;
  
                buffer
                    << "Peer AS: " << peer_conf.peer_as() << "\n"
                    << "Peer router id: " << peer_conf.id() << "\n"
                    << "Peer flops: " << peer_info.flops() << "\n"
                    << "BGP state: " << peer_info.bgp_state();

                return buffer.str();
            } else {
                return "Something wrong"; 
            }
    }

    private:
        std::unique_ptr<GobgpApi::Stub> stub_;
};

int main(int argc, char** argv) {
    GrpcClient gobgp_client(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials()));
 
    std::string reply = gobgp_client.GetNeighbor("213.133.111.200");
    std::cout << "Neighbor information: " << reply << std::endl;

    gobgp_client.AnnounceUnicastPrefix(false);

    gobgp_client.AnnounceFlowSpecPrefix(false);

    unsigned int AFI_IP = 1;
    unsigned int SAFI_UNICAST = 1;
    unsigned int SAFI_FLOW_SPEC_UNICAST = 133;

    unsigned int ipv4_unicast_route_family = AFI_IP<<16 | SAFI_UNICAST;
    unsigned int ipv4_flow_spec_route_family = AFI_IP<<16 | SAFI_FLOW_SPEC_UNICAST;   

    gobgp_client.GetAllActiveAnnounces(ipv4_unicast_route_family);
    std::cout << std::endl << std::endl;
    gobgp_client.GetAllActiveAnnounces(ipv4_flow_spec_route_family);
    
    return 0;
}
