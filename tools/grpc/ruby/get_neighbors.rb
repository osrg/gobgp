require 'gobgp'
require 'gobgp_services'

host = 'localhost'
host = ARGV[0] if ARGV.length > 0

stub = Api::Grpc::Stub.new("#{host}:8080")
arg = Api::Arguments.new()
stub.get_neighbors(arg).each do |n|
    puts "BGP neighbor is #{n.conf.remote_ip}, remote AS #{n.conf.remote_as}"
    puts "\tBGP version 4, remote route ID #{n.conf.id}"
    puts "\tBGP state = #{n.info.bgp_state}, up for #{n.info.uptime}"
    puts "\tBGP OutQ = #{n.info.out_q}, Flops = #{n.info.flops}"
    puts "\tHold time is #{n.info.negotiated_holdtime}, keepalive interval is #{n.info.keepalive_interval} seconds"
    puts "\tConfigured hold time is #{n.conf.holdtime}"
end
