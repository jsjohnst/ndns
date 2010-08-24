var sys = require('sys'), puts = sys.puts;
var dgram = require('dgram');
var ndns = require('../lib/ndns');
var server = ndns.createServer('udp4');
var client = ndns.createClient('udp4');

var BIND_PORT = 53;

server.on("request", function(req, res) {
    res.setHeader(req.header);

    for (var i = 0; i < req.q.length; i++)
	res.addQuestion(req.q[i]);

    if (req.q.length > 0) {
	var name = req.q[0].name;
	if (name == ".")
	    name = "";
	res.header.qr = 1;
	res.header.ra = 1;
	res.header.rd = 0;
	res.header.ancount = 3;
	res.header.nscount = 4;
	res.header.arcount = 5;
	res.addRR(name, 1, "IN", "SOA",
		  "hostmaster." + name,
		  "hostmaster." + name,
		  1, 2, 3, 4, 5);
	res.addRR(name, 2, "IN", "TXT", "Hello World");
	res.addRR(name, 3, "IN", "MX", 10, "mail." + name);
	res.addRR(name, 4, "IN", "NS", "ns1." + name);
	res.addRR(name, 5, "IN", "NS", "ns2." + name);
	res.addRR(name, 6, "IN", "NS", "ns3." + name);
	res.addRR(name, 7, "IN", "NS", "ns4." + name);
	res.addRR("mail." + name, 8, "IN", "A", "127.0.0.1");
	res.addRR("ns1." + name, 9, "IN", "A", "127.0.0.1");
	res.addRR("ns2." + name, 10, "IN", "A", "127.0.0.2");
	res.addRR("ns3." + name, 11, "IN", "A", "127.0.0.3");
	res.addRR("ns4." + name, 12, "IN", "A", "127.0.0.4");
    }
    res.send();
});

server.bind(BIND_PORT);
