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
#include "gobgp.grpc.pb.h"
#include "attribute.grpc.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

using gobgpapi::GobgpApi;

class GobgpClient
{
  public:
	GobgpClient(std::shared_ptr<Channel> channel)
		: stub_(GobgpApi::NewStub(channel)) {}
	void AddPath()
	{
		std::cout << "In addRoute \n";
		// Parameters to AddPath API
		gobgpapi::AddPathRequest request;
		ClientContext context;
		gobgpapi::AddPathResponse response;

		// Path info variable
		gobgpapi::Path *current_path = new gobgpapi::Path;

		// Updating family info of current_path
		gobgpapi::Family *current_family = new gobgpapi::Family;
		current_family->set_afi(gobgpapi::Family::AFI_IP);
		current_family->set_safi(gobgpapi::Family::SAFI_UNICAST);
		current_path->set_allocated_family(current_family);

		// Updating nlri info for current_path
		google::protobuf::Any *current_nlri = new google::protobuf::Any;
		gobgpapi::IPAddressPrefix current_ipaddrprefix;
		current_ipaddrprefix.set_prefix("10.0.0.0");
		current_ipaddrprefix.set_prefix_len(24);
		current_nlri->PackFrom(current_ipaddrprefix);
		current_path->set_allocated_nlri(current_nlri);

		// Updating OriginAttribute info for current_path
		google::protobuf::Any *current_origin = current_path->add_pattrs();
		gobgpapi::OriginAttribute current_origin_t;
		current_origin_t.set_origin(0);
		current_origin->PackFrom(current_origin_t);

		// Updating NextHopAttribute info for current_path
		google::protobuf::Any *current_next_hop = current_path->add_pattrs();
		gobgpapi::NextHopAttribute current_next_hop_t;
		current_next_hop_t.set_next_hop("1.1.1.1");
		current_next_hop->PackFrom(current_next_hop_t);
		// Updating CommunitiesAttribute for current_path
		google::protobuf::Any *current_communities = current_path->add_pattrs();
		gobgpapi::CommunitiesAttribute current_communities_t;
		current_communities_t.add_communities(100);
		current_communities->PackFrom(current_communities_t);

		// Populating the request attributes
		request.set_table_type(gobgpapi::TableType::GLOBAL);
		request.set_allocated_path(current_path);

		Status status = stub_->AddPath(&context, request, &response);
		if (status.ok())
		{
		}
		else
		{
			std::cout << status.error_code() << ": " << status.error_message()
					  << std::endl;
		}
	}

  private:
	std::unique_ptr<GobgpApi::Stub> stub_;
};

int main(int argc, char **argv)
{
	GobgpClient client(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials()));

	client.AddPath();
}
