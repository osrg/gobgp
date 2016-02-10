var grpc = require('grpc');
var api = grpc.load('gobgp.proto').gobgpapi;
var stub = new api.GobgpApi('localhost:50051', grpc.Credentials.createInsecure());

var call = stub.getNeighbors({});
call.on('data', function(neighbor) {
  console.log('BGP neighbor is', neighbor.conf.remote_ip,
              ', remote AS', neighbor.conf.remote_as);
  console.log("\tBGP version 4, remote route ID", neighbor.conf.id);
  console.log("\tBGP state =", neighbor.info.bgp_state,
              ', up for', neighbor.info.uptime);
  console.log("\tBGP OutQ =", neighbor.info.out_q,
              ', Flops =', neighbor.info.flops);
  console.log("\tHold time is", neighbor.info.negotiated_holdtime,
              ', keepalive interval is', neighbor.info.keepalive_interval, 'seconds');
  console.log("\tConfigured hold time is", neighbor.conf.holdtime);
});
call.on('end', function() {
  // do something when the server has finished sending
});
call.on('status', function(status) {
  // do something with the status
});

