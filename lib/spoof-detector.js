var args = require('./args.js');
var pcap = require('pcap');
var ip = require('ip');
var tcp = require('./tcp.js');
var logger = require('./logger.js');
var macaddress = require('macaddress');
const util = require('util');
const fs = require('fs');
var my_mac = '';
macaddress.one(args.params.iface, function (err, mac) {
  my_mac = mac;
});

var pendingSYNs = {};

if (!fs.existsSync(args.params.hostdb)){
    fs.writeFileSync(args.params.hostdb, JSON.stringify({}));
}
var validatedHostsRaw = fs.readFileSync(args.params.hostdb);
var validatedHosts = JSON.parse(validatedHostsRaw);

//send a TCP SYN to the host and wait for 2 sec to receive a RST or ACK
function validateHost(host_ip, host_mac){
  logger.log('[?] Validating: '+host_ip+' is at '+host_mac, 'debug');
  if(validatedHosts[host_ip] != undefined){ //host is already validated
    if(validatedHosts[host_ip] === host_mac){//lets check current situation matches with validated one
      logger.log('[+] Already Validated: '+host_ip+' is at '+validatedHosts[host_ip], 'debug');
    }else{
      logger.log('[-] Validation Failed : '+host_ip+' at '+host_mac);
    }
    return;
  }
  //Host has not validated yet, let's do it
  var host_port = parseInt(Math.random()*(65535-1024) + 1024);
  var src_ip = ip.address();
  var src_mac = my_mac;
  if(!tcp.sendSYN(args.params.iface, src_mac, host_mac, src_ip, 31337, host_ip, host_port)){
    logger.log('[?] Sent TCP SYN to '+host_ip+':'+host_port+' at '+host_mac, 'debug');
    pendingSYNs[host_ip +':'+ host_port] = [host_mac, Date.now()];
    setTimeout(handleTimedOutTCPSYNs, 2000, host_ip, host_port);
  }
}