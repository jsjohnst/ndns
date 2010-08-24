var sys = require('sys'), puts = sys.puts;
var ndns = require('../lib/ndns');
var resolver = ndns.createClient('udp4');

function walk (a_root_servers_net, domain) {
    puts(domain);
    var req = resolver.request(53, a_root_servers_net);

    req.setHeader({
	id: 1992,
	rd: 1,
	qdcount: 1});
    req.addQuestion (domain, "NSEC", "IN");
    req.send();

    req.on("response", function (res) {
	var rr;
	for (var i = 0; i < res.rr.length; i++) {
	    rr = res.rr[i];
	    if (rr.typeName == "NSEC") {
		walk(a_root_servers_net, rr.rdata.next_domain_name);
		break;
	    }
	}
    });
}

require('dns').resolve4("A.ROOT-SERVERS.NET", function (err, addrs) {
    if (err) throw err;
    if (addrs.length > 0)
	walk(addrs[0], ".");
});

