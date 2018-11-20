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