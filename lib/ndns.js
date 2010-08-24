var sys = require('sys');

var debug;
var debugLevel = parseInt(process.env.NODE_DEBUG, 16);
if(debugLevel & 0x4) {
    debug = function (x) { sys.error('NDNS: ' + x); };
} else {
    debug = function () { };
}

var dgram = require('dgram');
var events = require('events');
var Buffer = require('buffer').Buffer;

var FreeList = require('freelist').FreeList;

var ns_packsiz = 512;	// Default UDP Packet size
var ns_maxdname = 1025;	// Maximum domain name
var ns_maxmsg = 65535;	// Maximum message size
var ns_maxcdname = 255;	// Maximum compressed domain name
var ns_maxlabel = 63;	// Maximum compressed domain label
var ns_hfixedsz = 12;	// Bytes of fixed data in header
var ns_qfixedsz = 4;	// Bytes of fixed data in query
var ns_rrfixedsz = 10;	// Bytes of fixed data in r record
var ns_int32sz = 4;	// Bytes of data in a u_int32_t
var ns_int16sz = 2;	// Bytes of data in a u_int16_t
var ns_int8sz = 1;	// Bytes of data in a u_int8_t
var ns_inaddrsz = 4;	// IPv4 T_A
var ns_in6addrsz = 16;	// IPv6 T_AAAA
var ns_cmprsflgs = 0xc0;// Flag bits indicating name compression.
var ns_defaultport = 53;// For both UDP and TCP.

function enum (obj) {
    for (key in obj) {
	global[key] = obj[key];
    }
    return obj;
}

var ns_sect = enum({
    'ns_s_qd': 0,	// Query: Question.
    'ns_s_zn': 0,	// Update: Zone.
    'ns_s_an': 1,	// Query: Answer.
    'ns_s_pr': 1,	// Update: Prerequisites.
    'ns_s_ns': 2,	// Query: Name servers.
    'ns_s_ud': 2,	// Query: Update.
    'ns_s_ar': 3,	// Query|Update: Additional records.
    'ns_s_max': 4,
});

var ns_flag = enum({
    'ns_f_qr': 0,	// Question/Response.
    'ns_f_opcode': 1,	// Operation code.
    'ns_f_aa': 2,	// Authorative Answer.
    'ns_f_tc': 3,	// Truncation occured.
    'ns_f_rd': 4,	// Recursion Desired.
    'ns_f_ra': 5,	// Recursion Available.
    'ns_f_z': 6,	// MBZ
    'ns_f_ad': 7,	// Authentic Data (DNSSEC)
    'ns_f_cd': 8,	// Checking Disabled (DNSSEC)
    'ns_f_rcode': 9,	// Response code.
    'ns_f_max': 10,
});

// Currently defined opcodes.
var ns_opcode = enum({
    'ns_o_query': 0, 	// Standard query.
    'ns_o_iquery': 1,	// Inverse query (deprecated/unsupported).
    'ns_o_status': 2, 	// Name server status query (unsupported).
			// Opcode 3 is undefined/reserved
    'ns_o_notify': 4,	// Zone change notification.
    'ns_o_update': 5,	// Zone update message.
});

// Currently defined response codes
var ns_rcode = enum({
    'ns_r_noerror': 0,	// No error occured.
    'ns_r_formerr': 1,	// Format error.
    'ns_r_servfail': 2,	// Server failure.
    'ns_r_nxdomain': 3,	// Name error.
    'ns_r_notimpl': 4,	// Unimplemented.
    'ns_r_refused': 5,	// Operation refused.
// These are for BIND_UPDATE
    'ns_r_yxdomain': 6,	// Name exists
    'ns_r_yxrrset': 7,	// RRset exists
    'ns_r_nxrrset': 8,	// RRset does not exist
    'ns_r_notauth': 9,	// Not authoritative for zone
    'ns_r_notzone': 10,	// Zone of record different from zone section
    'ns_r_max': 11,
// The following are EDNS extended rcodes
    'ns_r_badvers': 16,
// The following are TSIG errors
    'ns_r_badsig': 16,
    'ns_r_badkey': 17,
    'ns_r_badtime': 18,
});

// BIND_UPDATE
var ns_update_operation = enum({
    'ns_oup_delete': 0,
    'ns_oup_add': 1,
    'ns_oup_max': 2,
});

var NS_TSIG = enum({
    'NS_TSIG_FUDGE': 300,
    'NS_TSIG_TCP_COUNT': 100,
    'NS_TSIG_ALG_HMAC_MD5': "HMAC-MD5.SIG-ALG.REG.INT",

    'NS_TSIG_ERROR_NO_TSIG': -10,
    'NS_TSIG_ERROR_NO_SPACE': -11,
    'NS_TSIG_ERROR_FORMERR': -12,
});

// Currently defined type values for resources and queries.
var ns_type = enum({
    'ns_t_invalid': 0,	// Cookie.
    'ns_t_a': 1,	// Host address.
    'ns_t_ns': 2,	// Authoritative server.
    'ns_t_md': 3,	// Mail destination.
    'ns_t_mf': 4,	// Mail forwarder.
    'ns_t_cname': 5,	// Canonical name.
    'ns_t_soa': 6,	// Start of authority zone.
    'ns_t_mb': 7,	// Mailbox domain name.
    'ns_t_mg': 8,	// Mail group member.
    'ns_t_mr': 9,	// Mail rename name.
    'ns_t_null': 10,	// Null resource record.
    'ns_t_wks': 11,	// Well known service.
    'ns_t_ptr': 12,	// Domain name pointer.
    'ns_t_hinfo': 13,	// Host information.
    'ns_t_minfo': 14,	// Mailbox information.
    'ns_t_mx': 15,	// Mail routing information.
    'ns_t_txt': 16,	// Text strings.
    'ns_t_rp': 17,	// Responsible person.
    'ns_t_afsdb': 18,	// AFS cell database.
    'ns_t_x25': 19,	// X_25 calling address.
    'ns_t_isdn': 20,	// ISDN calling address.
    'ns_t_rt': 21,	// Router.
    'ns_t_nsap': 22,	// NSAP address.
    'ns_t_ns_nsap_ptr': 23,	// Reverse NSAP lookup (deprecated)
    'ns_t_sig': 24,	// Security signature.
    'ns_t_key': 25,	// Security key.
    'ns_t_px': 26,	// X.400 mail mapping.
    'ns_t_gpos': 27,	// Geographical position (withdrawn).
    'ns_t_aaaa': 28,	// Ip6 Address.
    'ns_t_loc': 29,	// Location Information.
    'ns_t_nxt': 30,	// Next domain (security)
    'ns_t_eid': 31,	// Endpoint identifier.
    'ns_t_nimloc': 32,	// Nimrod Locator.
    'ns_t_srv': 33,	// Server Selection.
    'ns_t_atma': 34,	// ATM Address
    'ns_t_naptr': 35,	// Naming Authority PoinTeR
    'ns_t_kx': 36,	// Key Exchange
    'ns_t_cert': 37,	// Certification Record
    'ns_t_a6': 38,	// IPv6 Address (deprecated, use ns_t_aaaa)
    'ns_t_dname': 39,	// Non-terminal DNAME (for IPv6)
    'ns_t_sink': 40,	// Kitchen sink (experimental)
    'ns_t_opt': 41,	// EDNS0 option (meta-RR)
    'ns_t_apl': 42,	// Address prefix list (RFC3123)
    'ns_t_ds': 43,	// Delegation Signer
    'ns_t_sshfp': 44,	// SSH Fingerprint
    'ns_t_ipseckey': 45,// IPSEC Key
    'ns_t_rrsig': 46,	// RRSet Signature
    'ns_t_nsec': 47,	// Negative Security
    'ns_t_dnskey': 48,	// DNS Key
    'ns_t_dhcid': 49,	// Dynamic host configuartion identifier
    'ns_t_nsec3': 50,	// Negative security type 3
    'ns_t_nsec3param': 51,	// Negative security type 3 parameters
    'ns_t_hip': 55,	// Host Identity Protocol
    'ns_t_spf': 99,	// Sender Policy Framework
    'ns_t_tkey': 249,	// Transaction key
    'ns_t_tsig': 250,	// Transaction signature.
    'ns_t_ixfr': 251,	// Incremental zone transfer.
    'ns_t_axfr': 252,	// Transfer zone of authority.
    'ns_t_mailb': 253,	// Transfer mailbox records.
    'ns_t_maila': 254,	// Transfer mail agent records.
    'ns_t_any': 255,	// Wildcard match.
    'ns_t_zxfr': 256,	// BIND-specific, nonstandard.
    'ns_t_dlv': 32769,	// DNSSEC look-aside validation.
    'ns_t_max': 65536
});
exports.ns_type = ns_type;

// Values for class field
var ns_class = enum({
    'ns_c_invalid':  0,	// Cookie.
    'ns_c_in': 1,	// Internet.
    'ns_c_2': 2,	// unallocated/unsupported.
    'ns_c_chaos': 3,	// MIT Chaos-net.
    'ns_c_hs': 4,	// MIT Hesoid.
    // Query class values which do not appear in resource records
    'ns_c_none': 254,	// for prereq. sections in update requests
    'ns_c_any': 255,	// Wildcard match.
    'ns_c_max': 65535,
});
exports.ns_class = ns_class;

// DNSSEC constants.
var ns_key_types = enum({
    'ns_kt_rsa': 1,	// key type RSA/MD5
    'ns_kt_dh': 2,	// Diffie Hellman
    'ns_kt_dsa': 3,	// Digital Signature Standard (MANDATORY)
    'ns_kt_private': 4	// Private key type starts with OID
});

var ns_cert_type = enum({
    'cert_t_pkix': 1,	// PKIX (X.509v3)
    'cert_t_spki': 2,	// SPKI
    'cert_t_pgp': 3, 	// PGP
    'cert_t_url': 253,	// URL private type
    'cert_t_oid': 254	// OID private type
});

// Flags field of the KEY RR rdata


var ns_type_elt = 0x40; //edns0 extended label type
var dns_labeltype_bitstring = 0x41;
var digitvalue = [
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 16
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 32
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 48
    	 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1, // 64
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 80
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 96
	-1, 12, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 112
    	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 128
    	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 256
];

var hexvalue = [
    "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e", "0f", 
    "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1a", "1b", "1c", "1d", "1e", "1f", 
    "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2a", "2b", "2c", "2d", "2e", "2f", 
    "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3a", "3b", "3c", "3d", "3e", "3f", 
    "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4a", "4b", "4c", "4d", "4e", "4f", 
    "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "5a", "5b", "5c", "5d", "5e", "5f", 
    "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6a", "6b", "6c", "6d", "6e", "6f", 
    "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7a", "7b", "7c", "7d", "7e", "7f", 
    "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "8a", "8b", "8c", "8d", "8e", "8f", 
    "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9a", "9b", "9c", "9d", "9e", "9f", 
    "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "aa", "ab", "ac", "ad", "ae", "af", 
    "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "ba", "bb", "bc", "bd", "be", "bf", 
    "c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "c9", "ca", "cb", "cc", "cd", "ce", "cf", 
    "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "da", "db", "dc", "dd", "de", "df", 
    "e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8", "e9", "ea", "eb", "ec", "ed", "ee", "ef", 
    "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "fa", "fb", "fc", "fd", "fe", "ff", 
];
    
var digits = "0123456789";
var ns_flagdata = [
    { mask: 0x8000, shift: 15 }, // qr.
    { mask: 0x7800, shift: 11 }, // opcode.
    { mask: 0x0400, shift: 10 }, // aa.
    { mask: 0x0200, shift: 9 }, // tc.
    { mask: 0x0100, shift: 8 }, // rd.
    { mask: 0x0080, shift: 7 }, // ra.
    { mask: 0x0040, shift: 6 }, // z.
    { mask: 0x0020, shift: 5 }, // ad.
    { mask: 0x0010, shift: 4 }, // cd.
    { mask: 0x000f, shift: 0 }, // rcode.
    { mask: 0x0000, shift: 0 }, // expansion (1/6).
    { mask: 0x0000, shift: 0 }, // expansion (2/6).
    { mask: 0x0000, shift: 0 }, // expansion (3/6).
    { mask: 0x0000, shift: 0 }, // expansion (4/6).
    { mask: 0x0000, shift: 0 }, // expansion (5/6).
    { mask: 0x0000, shift: 0 }, // expansion (6/6).
];

var res_opcodes = [
    "QUERY",
    "IQUERY",
    "CQUERYM",
    "CQUERYU",	// experimental
    "NOTIFY",	// experimental
    "UPDATE",
    "6",
    "7",
    "8",
    "9",
    "10",
    "11",
    "12",
    "13",
    "ZONEINIT",
    "ZONEREF",
];
var res_sectioncodes = [
    "ZONE",
    "PREREQUISITES",
    "UPDATE",
    "ADDITIONAL",
];

var p_class_syms = {
    1: "IN",
    3: "CHAOS",
    4: "HESOID",
    254: "ANY",
    255: "NONE"
};

var p_default_section_syms = {
    0: "QUERY",
    1: "ANSWER",
    2: "AUTHORITY",
    3: "ADDITIONAL"
};

var p_key_syms = {
    1: ["RSA", "RSA KEY with MD5 hash"],
    2: ["DH", "Diffie Hellman"],
    3: ["DSA", "Digital Signature Algorithm"],
    4: ["PRIVATE", "Algorithm obtained from OID"]
};

var p_cert_syms = {
    1: ["PKIX", "PKIX (X.509v3) Certificate"],
    2: ["SKPI", "SPKI Certificate"],
    3: ["PGP", "PGP Certificate"],
    253: ["URL", "URL Private"],
    254: ["OID", "OID Private"]
};

var p_type_syms = {
    1: "A",
    2: "NS",
    3: "MD",
    4: "MF",
    5: "CNAME",
    6: "SOA",
    7: "MB",
    8: "MG",
    9: "MR",
    10: "NULL",
    11: "WKS",
    12: "PTR",
    13: "HINFO",
    14: "MINFO",
    15: "MX",
    16: "TXT",
    17: "RP",
    18: "AFSDB",
    19: "X25",
    20: "ISDN",
    21: "RT",
    22: "NSAP",
    23: "NSAP_PTR",
    24: "SIG",
    25: "KEY",
    26: "PX",
    27: "GPOS",
    28: "AAAA",
    29: "LOC",
    30: "NXT",
    31: "EID",
    32: "NIMLOC",
    33: "SRV",
    34: "ATMA",
    35: "NAPTR",
    36: "KX",
    37: "CERT",
    38: "A6",
    39: "DNAME",
    40: "SINK",
    41: "OPT",
    42: "APL",
    43: "DS",
    44: "SSHFP",
    45: "IPSECKEY",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    49: "DHCID",
    50: "NSEC3",
    51: "NSEC3PARAM",
    55: "HIP",
    99: "SPF",
    249: "TKEY",
    250: "TSIG",
    251: "IXFR",
    252: "AXFR",
    253: "MAILB",
    254: "MAILA",
    255: "ANY",
    32769: "DLV",
    256: "ZXFR",
};



var p_rcode_syms = {
    0: ["NOERROR", "no error"],
    1: ["FORMERR", "format error"],
    2: ["SERVFAIL", "server failed"],
    3: ["NXDOMAIN", "no such domain name"],
    4: ["NOTIMP", "not implemented"],
    5: ["REFUSED", "refused"],
// These are for BIND_UPDATE
    6: ["YXDOMAIN", "domain name exist"],
    7: ["YXRRSET", "rrset exists"],
    8: ["NXRRSET", "rrset doesn't exist"],
    9: ["NOTAUTH", "not authoritative"],
    10: ["NOTZONE", "not in zone"],
    11: ["", ""],
// The following are EDNS extended rcodes
// The following are TSIG errors
    16: ["BADSIG", "bad signature"],
    17: ["BADKEY", "bad key"],
    18: ["BADTIME", "bad time"]
};

var n_type_syms = {};
for (var k in p_type_syms)
    n_type_syms[p_type_syms[k]] = k;

var n_class_syms = {};
for (var k in p_class_syms)
    n_class_syms[p_class_syms[k]] = k;

function Ptr () {
    this.p = (arguments.length == 1) ? arguments[0] : null;
}
exports.Ptr = Ptr;

Ptr.prototype.get = function () {
    return this.p;
};

Ptr.prototype.set = function (val) {
    return this.p = val;
};

function ns_name_ntop(src, dst, dstsiz) {
    var cp;
    var dn, eom;
    var c;
    var n;
    var l;

    cp = 0;
    dn = 0;
    eom = dstsiz;

    while((n = src[cp++]) != 0) {
	if((n & ns_cmprsflgs) == ns_cmprsflgs) {
	    /* some kind of compression pointer */
	    errno.set('EMSGSIZE');
	    return (-1);
	}
	if(dn != 0) {
	    if(dn >= eom) {
		errno.set('EMSGSIZE');
		return (-1);
	    }
	    dst[dn++] = 0x2e; /* '.' */
	}
	if ((l = labellen(src, cp - 1)) < 0) {
	    errno.set('EMSGSIZE');
	    return (-1);
	}
	if(dn + l >= eom) {
	    errno.set('EMSGSIZE');
	    return (-1);
	}
	if((n & ns_cmprsflgs) == ns_type_elt) {
	    var m;

	    if(n != dns_labeltype_bitstring) {
		/* labellen should reject this case */
		return (-1);
	    }
	    var cpp = new Ptr(cp);
	    if ((m = decode_bitstring(src, cpp, dst, dn, eom)) < 0) {
		errno.set('EMSGSIZE');
		return (-1);
	    }
	    cp = cpp.get();
	    dn += m;
	    continue;
	}
	for(; l > 0; l--) {
	    c = src[cp++];
	    if(special(c)) {
		if(dn + 1 >= eom) {
		    errno.set('EMSGSIZE');
		    return (-1);
		}
		dst[dn++] = 0x5c; /* '\\' */
		dst[dn++] = c;
	    }
	    else if(!printable(c)) {
		if(dn + 3 >= eom) {
		    errno.set('EMSGSIZE');
		    return (-1);
		}
		dst[dn++] = 0x5c; /* '\\' */
		dst[dn++] = digits[c / 100];
		dst[dn++] = digits[(c % 100) / 10];
		dst[dn++] = digits[c % 10];
	    }
	    else {
		if(dn >= eom) {
		    errno.set('EMSGSIZE');
		    return (-1);
		}
		dst[dn++] = c;
	    }
	}
    }
    if (dn == 0) {
	if (dn >= eom) {
	    errno.set('EMSGSIZE');
	    return (-1);
	}
	dst[dn++] = 0x2e; // '.'
    }
    if (dn >= eom) {
	errno.set('EMSGSIZE');
	return (-1);
    }
    dst[dn] = 0;
    return (dn);
}
exports.ns_name_ntop = ns_name_ntop;

function ns_name_pton (src, dst, dstsiz) {
    return ns_name_pton2(src, dst, dstsiz, null);
}
exports.ns_name_pton = ns_name_pton;

function ns_name_pton2(src, dst, dstsiz, dstlenp) {
    var label, bp, epm
    var c, n, escaped, e = 0;
    var cp;

    escaped = 0;
    bp = 0;
    eom = dstsiz;
    label = bp++;

    var srcn = 0;
    var done = false; // instead of goto
    while ((c = src[srcn++]) != 0) {
	if (escaped) {
	    if (c == 91) { // '['; start a bit string label
		if ((cp = strchr(src, srcn, 93)) == null) { // ']'
		    errno.set('EINVAL');
		    return(-1);
		}
		var srcp = new Ptr(srcn);
		var bpp = new Ptr(bp);
		var labelp = new Ptr(label);
		if ((e = encode_bitstring (src, srcp, cp + 2,
					   labelp, dst, bpp, eom)
		     != 0)) {
		    errno.set(e);
		    return(-1);
		}
		label = labelp.get();
		bp = bpp.get();
		srcn = srcp.get();
		escaped = 0;
		label = bp++;
		if ((c = src[srcn++]) == 0) {
		    done = true;
		    break;
		}
	    }
	    else if ((cp = digits.indexOf(String.fromCharCode(c))) != -1) {
		n = (cp * 100);
		if ((c = src[srcn++]) ||
		    (cp = digits.indexOf(String.fromCharCode(c))) == -1) {
		    errno.set('EMSGSIZE');
		    return (-1);
		}
		n += (cp) * 10;
		if ((c = src[srcn++]) == 0 ||
		    (cp = digits.indexOf(String.fromCharCode(c))) == -1) {
		    errno.set('EMSGSIZE');
		    return (-1);
		}
		n += cp;
		if (n > 255) {
		    errno.set('EMSGSIZE');
		    return (-1);
		}
		c = n;
	    }
	    escaped = 0;
	} else if (c == 92) { // '\\'
	    escaped = 1;
	    continue;
	} else if (c == 46) { // '.'
	    c = (bp - label - 1)
	    if ((c & ns_cmprsflgs) != 0) { // label too big
		errno.set('EMSGSIZE');
		return (-1);
	    }
	    if (label >= eom) {
		errno.set('EMSGSIZE');
		return (-1);
	    }
	    dst[label] = c;
	    // Fully qualified?
	    if (src[srcn] == 0) {
		if (c != 0) {
		    if (bp >= eom) {
			errno.set('EMSGSIZE');
			return (-1);
		    }
		    dst[bp++] = 0;
		}
		if ((bp) > ns_maxcdname) {
		    errno.set('EMSGSIZE');
		    return (-1);
		}
		if (dstlenp != null) {
		    dstlenp.set(bp);
		}
		return (1);
	    }
	    if (c == 0 || src[srcn] == 46) { // '.'
		errno.set('EMSGSIZE');
		return (-1);
	    }
	    label = bp++;
	    continue;
	}
	if (bp >= eom) {
	    errno.set('EMSGSIZE');
	    return (-1);
	}
	dst[bp++] = c;
    }
    if (!done) {
	c = (bp - label - 1);
	if ((c & ns_cmprsflgs) != 0) {
	    errno.set('EMSGSIZE');
	    return (-1);
	}
    }
// done:
    if (label >= eom) {
	errno.set('EMSGSIZE');
	return (-1);
    }
    dst[label] = c;
    if (c != 0) {
	if (bp >= eom) {
	    errno.set('EMSGSIZE');
	    return (-1);
	}
	dst[bp++] = 0;
    }
    if (bp > ns_maxcdname) { // src too big
	errno.set('EMSGSIZE');
	return (-1);
    }
    if (dstlenp != null) {
	dstlenp.set(bp);
    }
    return (0);
}

function strchr (src, off, n) {
    while (off < buf.length && buf[off] != 0) {
	if (buf[off] == n)
	    return off;
	off++;
    }
    return null;
}

function ns_name_unpack (msg, offset, len, dst, dstsiz) {
    return ns_name_unpack2 (msg, offset, len, dst, dstsiz, null);
}
exports.ns_name_unpack = ns_name_unpack;

function ns_name_unpack2 (msg, offset, len, dst, dstsiz, dstlenp) {
    var n, l;

    var llen = -1;
    var checked = 0;
    var dstn = 0;
    var srcn = offset;
    var dstlim = dstsiz;
    var eom = offset + len;
    if(srcn < 0 || srcn >= eom) {
	errno.set('EMSGSIZE');
	return (-1);
    }
    /* Fetch next label in domain name */
    while((n = msg[srcn++]) != 0 && !isNaN(srcn)) {
	/* Check for indirection */
	switch(n & ns_cmprsflgs) {
	case 0:
	case ns_type_elt:
	    /* Limit checks */
	    
	    if((l = labellen(msg, srcn - 1)) < 0) {
		errno.set('EMSGSIZE');
		return (-1);
	    }
	    if(dstn + l + 1 >= dstlim || srcn + l >= eom) {
		errno.set('EMSGSIZE');
		return (-1);
	    }
	    checked += l + 1;
	    dst[dstn++] = n;
	    msg.copy(dst, dstn, srcn, srcn + l);
	    dstn += l;
	    srcn += l;
	    break;

	case ns_cmprsflgs:
	    if(srcn >= eom) {
		errno.set('EMSGSIZE');
		return (-1);
	    }
	    if(llen < 0) {
		llen = (srcn - offset) + 1;
	    }
	    
	    srcn = (((n & 0x3F) * 256) | (msg[srcn] & 0xFF));

	    if(srcn < 0 || srcn >= eom) { /* Out of range */
		errno.set('EMSGSIZE');
		return (-1);
	    }
	    
	    checked += 2;
	    /* check for loops in compressed name */
	    if(checked >= eom) {
		errno.set('EMSGSIZE');
		return (-1);
	    }
	    break;

	default:
	    errno.set('EMSGSIZE');
	    return (-1); // flag error
	}
    }
    dst[dstn] = 0;
    if (dstlenp != null)
	dstlenp.set(dstn);
    if(llen < 0)
	llen = srcn - offset;
    return (llen);
}

function ns_name_pack (src, dst, dstn, dstsiz, dnptrs, lastdnptr) {
    var dstp;
    var cpp, lpp, eob, msgp;
    var srcp;
    var n, l, first = 1;

    srcp = 0;
    dstp = dstn;
    eob = dstp + dstsiz;
    lpp = cpp = null;
    var ndnptr = 0;
    if (dnptrs != null) {
	msg = dst;
	//if ((msg = dnptrs[ndnptr++]) != null) {
	    for (cpp = 0; dnptrs[cpp] != null; cpp++);
	    lpp = cpp; // end of list to search
	//}
    } else
	msg = null;

    // make sure the domain we are about to add is legal
    l = 0;
    do {
	var l0;

	n = src[srcp];
	if ((n & ns_cmprsflgs) == ns_cmprsflgs) {
	    errno.set('EMSGSIZE');
	    return (-1);
	}
	if ((l0 = labellen(src, srcp)) < 0) {
	    errno.set('EINVAL');
	    return (-1);
	}
	l += l0 + 1;
	if (l > ns_maxcdname) {
	    errno.set('EMSGSIZE');
	    return (-1);
	}
	srcp += l0 + 1;
    } while (n != 0);

    // from here on we need to reset compression pointer array on error
    srcp = 0;
    var cleanup = false; // instead of goto
    do {
	// look to see if we can use pointers
	n = src[srcp];
	if (n != 0 && msg != null) {
	    l = dn_find(src, srcp, msg, dnptrs, ndnptr, lpp);
	    if (l >= 0) {
		if (dstp + 1 >= eob) {
		    cleanup = true;
		    break;
		}
		dst[dstp++] = (l >> 8) | ns_cmprsflgs;
		dst[dstp++] = l & 0xff;
		return (dstp - dstn);
	    }
	    // Not found, save it.
	    if (lastdnptr != null && cpp < lastdnptr - 1 &&
		(dstp) < 0x4000 && first) {
		dnptrs[cpp++] = dstp;
		dnptrs[cpp++] = null;
		first = 0;
	    }
	}
	// copy label to buffer
	if ((n & ns_cmprsflgs) == ns_cmprsflgs) {
	    // should not happen
	    cleanup = true;
	    break;
	}
	n = labellen(src, srcp);
	if (dstp + 1 + n >= eob) {
	    cleanup = true;
	    break;
	}
	src.copy(dst, dstp, srcp, srcp + (n + 1));
	srcp += n + 1;
	dstp += n + 1;
	
    } while (n != 0);

    if (dstp > eob ||
// cleanup:
	cleanup) {
	if (msg != null) {
	    dnptrs[lpp] = null;
	}
	errno.set('EMSGSIZE');
	return (-1);
    }
    return (dstp - dstn);
}
exports.ns_name_pack = ns_name_pack;

function ns_name_skip (b, ptrptr, eom) {
    var cp;
    var n;
    var l;

    cp = ptrptr.get();
    while (cp < eom && (n = b[cp++]) != 0) {
	switch (n & ns_cmprsflgs) {
	case 0: // normal case, n == len
	    cp += n;
	    continue;
	case ns_type_elt: // edns0 extended label
	    if ((l = labellen(b, cp - 1)) < 0) {
		errno.set('EMSGSIZE');
		return (-1);
	    }
	    cp += l;
	    continue;
	case ns_cmprsflgs: // indirection
	    cp++;
	    break;
	default: // illegal type
	    errno.set('EMSGSIZE');
	    return (-1);
	}
	break;
    }
    if (cp > eom) {
	errno.set('EMSGSIZE');
	return (-1);
    }
    ptrptr.set(cp);
    return (0);
}
exports.ns_name_skip = ns_name_skip;

function special(ch) {
    switch(ch) {
    case 0x22: /* '"' */
    case 0x2E: /* '.' */
    case 0x3B: /* ';' */
    case 0x5C: /* '\\' */
    case 0x28: /* '(' */
    case 0x29: /* ')' */
    /* special modifiers in the zone file */
    case 0x40: /* '@' */
    case 0x24: /* '$' */
	return (1);
    default:
	return (0);
    }
}

function printable (ch) {
    return (ch > 0x20 && ch < 0x7F);
}

function mklower (ch) {
    if (ch >= 0x41 && ch <= 0x5A)
	return (ch + 0x20);
    return (ch);
}

function dn_find(src, domain, msg, dnptrs, ndnptr, lastdnptr) {
    var dn, cp, sp;
    var cpp;
    var n;

    var next = false; // instead of goto
    for (cpp = ndnptr; cpp < lastdnptr; cpp++) {
	sp = dnptrs[cpp];
	//
	// terminate search on:
	// root label
	// compression pointer
	// unusable offset
	//
	while (msg[sp] != 0 && (msg[sp] & ns_cmprsflgs) == 0 &&
	       (sp) < 0x4000) {
	    dn = domain;
	    cp = sp;
	    while ((n = msg[cp++]) != 0) {
		//
		// check for indirection
		//
		switch (n & ns_cmprsflgs) {
		case 0: // normal case, n == len
		    n = labellen(msg, cp - 1) // XXX
		    if (n != src[dn++]) {
			next = true;
			break;
		    }
		    for (null; n > 0; n--) {
			if (mklower(src[dn++]) !=
			    mklower(msg[cp++])) {
			    next = true;
			    break;
			}
		    }
		    if (next) {
			break;
		    }
		    // Is next root for both ?
		    if (src[dn] == 0 && msg[cp] == 0) {
			return (sp);
		    }
		    if (src[dn])  {
			continue;
		    }
		    next = true;
		    break;
		case ns_cmprsflgs: // indirection
		    cp = (((n & 0x3f) * 256) | msg[cp]);
		    break;

		default: // illegal type
		    errno.set('EMSGSIZE');
		    return (-1);
		}
		if (next) {
		    break;
		}
	    }
	    sp += msg[sp] + 1;
	    if (next)
		next = false;
	}
    }
    errno.set('ENOENT');
    return (-1);
}
exports.dn_find = dn_find;

function decode_bitstring (b, cpp, d, dn, eom) {
    var cp = cpp.get();
    var beg = dn, tc;
    var b, blen, plen, i;

    if ((blen = (b[cp] & 0xff)) == 0)
	blen = 256;
    plen = (blen + 3) / 4;
    plen += "\\[x/]".length + (blen > 99 ? 3 : (blen > 9) ? 2 : 1);
    if (dn + plen >= eom)
	return (-1);

    cp++;
    i = d.write("\\[x", dn);
    if (i != 3)
	return (-1);
    dn += i;
    for (b = blen; b > 7; b -= 8, cp++) {
	if (dn + 2 >= eom)
	    return (-1);
    }
}
exports.decode_bitstring = decode_bitstring;

function encode_bitstring (src, bp, end, labelp, dst, dstp, eom) {
    var afterslash = 0;
    var cp = bp.get();
    var tp;
    var c;
    var beg_blen;
    var end_blen = null;
    var value = 0, count = 0, tbcount = 0, blen = 0;

    beg_blen = end_blen = null;

    // a bitstring must contain at least two bytes
    if (end - cp < 2)
	return errno.EINVAL;

    // currently, only hex strings are supported
    if (src[cp++] != 120) // 'x'
	return errno.EINVAL;
    if (!isxdigit((src[cp]) & 0xff)) // reject '\[x/BLEN]'
	return errno.EINVAL;

    var done = false;
    for (tp = dstp.get() + 1; cp < end && tp < eom; cp++) {
	switch (c = src[cp++]) {
	case 93: // ']'
	    if (afterslash) {
		if (beg_blen == null)
		    return errno.EINVAL;
		blen = strtol(src, beg_blen, 10);
		// todo:
		// if ( char after string == ']' )
		// return errno.EINVAL;
	    }
	    if (count)
		dst[tp++] = ((value << 4) & 0xff);
	    cp++; // skip ']'
	    done = true;
	    break;
	case 47: // '/'
	    afterslash = 1;
	    break;
	default:
	    if (afterslash) {
		if (!isxdigit(c&0xff))
		    return errno.EINVAL;
		if (beg_blen == null) {

		    if (c == 48) { // '0'
			// blen never begins with 0
			return errno.EINVAL;
		    }
		    beg_blen = cp;
		}
	    } else {
		if (!isxdigit(c&0xff))
		    return errno.EINVAL;
		value <<= 4;
		value += digitvalue[c];
		count += 4;
		tbcount += 4;
		if (tbcount > 256)
		    return errno.EINVAL;
		if (count == 8) {
		    dst[tp++] = value;
		    count = 0;
		}
	    }
	    break;
	}
	if (done) {
	    break;
	}
    }
    // done:
    if (cp >= end || tp >= eom)
	return errno.EMSGSIZE;
    // bit length validation:
    // If a <length> is present, the number of digits in the <bit-data>
    // MUST be just sufficient to contain the number of bits specified
    // by the <length>. If there are insufficient bits in a final
    // hexadecimal or octal digit, they MUST be zero.
    // RFC2673, Section 3.2
    if (blen && (blen > 0)) {
	var traillen;

	if (((blen + 3) & ~3) != tbcount)
	    return errno.EINVAL;
	traillen = tbcount - blen; // between 0 and 3
	if (((value << (8 - traillen)) & 0xFF) != 0)
	    return errno.EINVAL;
    }
    else
	blen = tbcount;
    if (blen == 256)
	blen = 0;

    // encode the type and the significant bit fields
    src[labelp.get()] = dns_labeltype_bitstring;
    dst[dstp.get()] = blen;

    bp.set(cp);
    dstp.set(tp);

    return (0);
}
exports.encode_bitstring = encode_bitstring;

function isxdigit (ch) {
    return ((ch >= 48 && ch <= 57)
	    || (ch >= 97 && ch <= 102)
	    || (ch >= 65 && ch <= 70));
}

function isspace (ch) {
    return (ch == 32 || ch == 12 || ch == 10 || ch == 13 || ch == 9 || ch == 12);
}

function strtol (b, off, end, base) {
    // todo: port from C
    return parseInt(b.toString(off, end), base);
}

function labellen (b, off) {
    var bitlen;
    var l = b[off];

    if((l & ns_cmprsflgs) == ns_cmprsflgs) {
	return (-1);
    }
    if((l & ns_cmprsflgs) == ns_type_elt) {
	if(l == dns_labeltype_bitstring) {
	    bitlen = b[off + 1];
	    if(bitlen == 0) {
		bitlen = 256;
	    }
	    return (1 + (bitlen + 7) / 8);
	}
    }
    return (l);
}

var errno = {
    val: {
	"ENOENT": 2,
	"EINVAL": 22,
	"EMSGSIZE": 90,
    },
    errno: null,
    set: function (name) {
	if (typeof name === 'string' && this.val[name]) {
	    this.errno = name;
	}
    },
    get: function () {
	return this.errno;
    },
};
exports.errno = errno;

function DNSParser(buf, start, end) {
    if (arguments.length < 3) {
	this.initialized = false;
	return;
    }

    if (!(buf instanceof Buffer)) {
	throw new Error("Argument should be a buffer");
    }
    if (start > buf.length) {
	throw new Error("Offset is out of bounds");
    }
    if (end > buf.length) {
	throw new Error("Length extends beyond buffer");
    }

    this.buf = buf;
    this.bufStart = start;
    this.bufEnd = end;

    this.parseStart = 0;
    this.parseEnd = 0;

    this.initialized = true;

    this.err = false;
}
exports.DNSParser = DNSParser;

DNSParser.prototype.reinitialize = function() {
    DNSParser.apply (this, arguments);
};

DNSParser.prototype.parseMessage = function () {
    var qdcount, ancount, nscount, arcount, rrcount;

    // todo: streaming parser
    if(typeof this.onMessageBegin === 'function')
	this.onMessageBegin ();

    try {
	this.skipHeader(this.onHeader);
    } catch (err) { this.err = err; return; }

    qdcount = this.buf[this.parseStart-8] * 256 + this.buf[this.parseStart-7];
    ancount = this.buf[this.parseStart-6] * 256 + this.buf[this.parseStart-5];
    nscount = this.buf[this.parseStart-4] * 256 + this.buf[this.parseStart-3];
    arcount = this.buf[this.parseStart-2] * 256 + this.buf[this.parseStart-1];
    rrcount = ancount + nscount + arcount;

    for (var i = 0; i < qdcount; i++)
	try {
	    this.skipQuestion(this.onQuestion);
	} catch (err) { this.err = err; return; }

    for (var i = 0; i < rrcount; i++) {
	if (i == 0 && typeof this.onAnswerBegin === 'function')
	    this.onAnswerBegin();

	else if (i == ancount && typeof this.onAuthorityBegin === 'function')
	    this.onAuthorityBegin();

	else if (i == ancount + nscount && typeof this.onAdditionalBegin === 'function')
	    this.onAdditionalBegin();

	try {
	    this.skipRR(this.onRR);
	} catch (err) { this.err = err; return; }
    }

    if(typeof this.onMessageComplete === 'function')
	this.onMessageComplete ();
}

DNSParser.prototype.skipHeader = function (cb) {
    this.parseEnd = this.parseStart + ns_hfixedsz;
    if (this.parseEnd > this.bufEnd)
	throw new Error();

    if (typeof cb === 'function')
	cb (this.buf, this.parseStart, this.parseEnd);

    this.parseStart = this.parseEnd;
};

DNSParser.prototype.skipQuestion = function (cb) {
    var ptr = new Ptr(this.parseStart);
    if (ns_name_skip(this.buf, ptr, this.bufEnd) != 0)
	throw new Error();

    this.parseEnd = ptr.get() + ns_qfixedsz;
    if (this.parseEnd > this.bufEnd)
	throw new Error();
    
    if (typeof cb === 'function')
	cb (this.buf, this.parseStart, this.parseEnd);

    this.parseStart = this.parseEnd;
};

DNSParser.prototype.skipRR = function (cb) {
    var rrcount;
    var ptr = new Ptr(this.parseStart);

    if (ns_name_skip(this.buf, ptr, this.bufEnd) != 0)
	throw new Error();
    
    this.parseEnd = ptr.get() + ns_rrfixedsz;
    if (this.parseEnd > this.bufEnd)
	throw new Error();
    
    this.parseEnd += this.buf[this.parseEnd - 2] * 256 + this.buf[this.parseEnd - 1];
    if (this.parseEnd > this.bufEnd)
	throw new Error();

    if (typeof cb === 'function')
	cb (this.buf, this.parseStart, this.parseEnd);

    this.parseStart = this.parseEnd;
};

DNSParser.prototype._cdname = new Buffer(ns_maxcdname);

DNSParser.prototype._dname = new Buffer(ns_maxdname);

DNSParser.prototype._string = new Buffer(ns_maxdname);

DNSParser.prototype.parseName = function () {
    var n, len;

    if ((n = ns_name_unpack(this.buf, this.parseStart, this.parseEnd - this.parseStart, this._dname, this._dname.length)) == -1)
	throw new Error();
    if ((len = ns_name_ntop(this._dname, this._string, this._string.length)) == -1)
	throw new Error();

    this.parseStart += n;
    return this._string.toString('ascii', 0, len);
};

DNSParser.prototype.parseUInt8 = function () {
    if (this.parseStart + 1 > this.parseEnd)
	throw new Error();
    this.parseStart++;
    return this.buf[this.parseStart-1];
};

DNSParser.prototype.parseUInt16 = function () {
    if (this.parseStart + 2 > this.parseEnd)
	throw new Error();
    this.parseStart += 2;
    return this.buf[this.parseStart-2] * 256 + this.buf[this.parseStart-1];
};

DNSParser.prototype.parseUInt32 = function () {
    if (this.parseStart + 4 > this.parseEnd)
	throw new Error();
    this.parseStart += 4;
    return (this.buf[this.parseStart-4] * 16777216 +
	    this.buf[this.parseStart-3] * 65536 + 
	    this.buf[this.parseStart-2] * 256 +
	    this.buf[this.parseStart-1] );
};

DNSParser.prototype.parseHeader = function (header) {
    var tmp;
    header.id = this.parseUInt16();
    tmp = this.parseUInt16();
    header.qr = (tmp & 0x8000) >> 15;
    header.opcode = (tmp & 0x7800) >> 11;
    header.aa = (tmp & 0x0400) >> 10;
    header.tc = (tmp & 0x0200) >> 9;
    header.rd = (tmp & 0x0100) >> 8;
    header.ra = (tmp & 0x0080) >> 7;
    header.z = (tmp & 0x0040) >> 6;
    header.ad = (tmp & 0x0020) >> 5;
    header.cd = (tmp & 0x0010) >> 4;
    header.rcode = (tmp & 0x000f) >> 0;

    header.qdcount = this.parseUInt16();
    header.ancount = this.parseUInt16();
    header.nscount = this.parseUInt16();
    header.arcount = this.parseUInt16();
};

DNSParser.prototype.parseQuestion = function (question) {
    question.name = this.parseName();
    question.type = this.parseUInt16();
    question.class = this.parseUInt16();
    question.typeName = p_type_syms[question.type];
    question.className = p_class_syms[question.class];
};

DNSParser.prototype.parseA = function () {
    if (this.parseStart + 4 > this.parseEnd)
	throw new Error();
    this.parseStart += 4;
    return [this.buf[this.parseStart-4],
	    this.buf[this.parseStart-2],
	    this.buf[this.parseStart-1],
	    this.buf[this.parseStart-1]].join('.');
};

function BufferReference (buf, start, end) {
    if (!(buf instanceof Buffer)) {
	throw new Error("Argument should be a buffer");
    }
    if (start > end) {
	throw new Error("Start extends beyond end");
    }
    if (start > buf.length) {
	throw new Error("Offset is out of bounds");
    }
    if (end > buf.length) {
	throw new Error("Length extends beyond buffer");
    }
    this.buf = buf;
    this.start = start;
    this.end = end;
};
exports.BufferReference = BufferReference;

BufferReference.prototype.toString = function () {
    return this.buf.toString('ascii', this.start, this.end);
};

BufferReference.prototype.toBuffer = function () {
    return this.buf.slice(this.start, this.end);
};

DNSParser.prototype.parseSOA = function (soa) {
    soa.mname = this.parseName();
    soa.rname = this.parseName();
    soa.serial = this.parseUInt32();
    soa.refresh = this.parseUInt32();
    soa.retry = this.parseUInt32();
    soa.expire = this.parseUInt32();
    soa.minimum = this.parseUInt32();

    soa[0] = soa.mname;
    soa[1] = soa.rname;
    soa[2] = soa.serial;
    soa[3] = soa.refresh;
    soa[4] = soa.retry;
    soa[5] = soa.expire;
    soa[6] = soa.minimum;
    soa.length = 7;

    return soa;
};

DNSParser.prototype.parseMX = function (mx) {
    mx.preference = this.parseUInt16();
    mx.exchange = this.parseName();

    mx[0] = mx.preference;
    mx[1] = mx.exchange;
    mx.length = 2;

    return mx;
};

DNSParser.prototype.parseAAAA = function () {
    if (this.parseStart + 16 > this.parseEnd)
	throw new Error();
    this.parseStart += 16;
    return [(hexvalue[this.buf[this.parseStart-16]]+
	     hexvalue[this.buf[this.parseStart-15]]),
	    (hexvalue[this.buf[this.parseStart-14]]+
	     hexvalue[this.buf[this.parseStart-13]]),
	    (hexvalue[this.buf[this.parseStart-12]]+
	     hexvalue[this.buf[this.parseStart-11]]),
	    (hexvalue[this.buf[this.parseStart-10]]+
	     hexvalue[this.buf[this.parseStart-9]]),
	    (hexvalue[this.buf[this.parseStart-8]]+
	     hexvalue[this.buf[this.parseStart-7]]),
	    (hexvalue[this.buf[this.parseStart-6]]+
	     hexvalue[this.buf[this.parseStart-5]]),
	    (hexvalue[this.buf[this.parseStart-4]]+
	     hexvalue[this.buf[this.parseStart-3]]),
	    (hexvalue[this.buf[this.parseStart-2]]+
	     hexvalue[this.buf[this.parseStart-1]])].join(":");
}

DNSParser.prototype.parseNSEC = function (nsec) {
    nsec.next_domain_name = this.parseName();
    nsec.type_bit_maps = new BufferReference (this.buf, this.parseStart, this.parseEnd);

    nsec[0] = nsec.next_domain_name;
    nsec[1] = nsec.type_bit_maps;
    nsec.length = 2;

    this.parseStart = this.parseEnd;
};

function Rdata () {
}

Rdata.prototype.length = 0;

DNSParser.prototype.parseRR = function (rr) {
    var parseEnd;
    rr.name = this.parseName();
    rr.type = this.parseUInt16();
    rr.class = this.parseUInt16();
    rr.ttl = this.parseUInt32();
    rr.rdlength = this.parseUInt16();

    rr.typeName = p_type_syms[rr.type];
    rr.className = p_class_syms[rr.class];

    if (this.parseStart + rr.rdlength != this.parseEnd)
	throw new Error();

    rr.rdata = new Rdata();
    rr.rdata.length = 1;

    switch (rr.type) {
    case 1: // a
	rr.rdata.a = this.parseA();
	rr.rdata[0] = rr.rdata.a;
	break;
    case 2: // ns
	rr.rdata.ns = this.parseName();
	rr.rdata[0] = rr.rdata.ns;
	break;
    case 5: // cname
	rr.rdata.cname = this.parseName();
	rr.rdata[0] = rr.rdata.cname;
	break;
    case 6: // soa
	this.parseSOA(rr.rdata);
	break;
    case 12: // ptr
	rr.rdata.ptrdname = this.parseName();
	rr.rdata[0] = rr.rdata.ptrdname;
	break;
    case 15: // mx
	this.parseMX(rr.rdata);
	break;
    case 16: // txt
	rr.rdata.txt = new BufferReference (this.buf, this.parseStart, this.parseEnd);
	//rr.rdata.txt = this.buf.slice(this.parseStart, this.parseEnd);
	rr.rdata[0] = rr.rdata.txt;
	this.parseStart += rr.rdlength;
	break;
    case 28: // aaaa
	rr.rdata.aaaa = this.parseAAAA();
	rr.rdata[0] = rr.rdata.aaaa;
	break;
    case 47: // nsec
	this.parseNSEC(rr.rdata);
	break;
    default:
	rr.rdata = new BufferReference(this.parseStart, this.parseEnd);
	break;
    }

    if (this.parseStart != this.parseEnd)
	throw new Error();
};

DNSParser.prototype.finish = function () {
    if (arguments.length == 3 && (arguments[0] instanceof Buffer)){
	this.parseOnce.apply(this, arguments);
    }
};

function DNSWriter (buf, start, end) {
    if (arguments.length < 3) {
	this.initialized = false;
	return;
    }

    if (!(buf instanceof Buffer)) {
	throw new Error("Argument should be a buffer");
    }
    if (start > end) {
	throw new Error("Start extends beyond end");
    }
    if (start > buf.length) {
	throw new Error("Offset is out of bounds");
    }
    if (end > buf.length) {
	throw new Error("Length extends beyond buffer");
    }

    this.dnptrs = new Array(20);
    this.dnptrs[0] = null;
    this.lastdnptr = this.dnptrs.length;

    this.rdstart = 0;
    this.trstart = 0;

    this.buf = buf;
    this.bufStart = start;
    this.bufEnd = end;

    this.writeStart = 0;
    this.writeEnd = this.bufEnd;

    this.initialized = true;

    this.truncated = false;
}
exports.DNSWriter = DNSWriter;

DNSWriter.prototype.reinitialize = function() {
    DNSWriter.apply (this, arguments);
};

DNSWriter.prototype.startRdata = function () {
    if (this.truncated)
	return;

    this.writeUInt16(0);
    this.rdstart = this.writeStart;
};

DNSWriter.prototype.endRdata = function () {
    if (this.truncated)
	return;

    var rdlength = this.writeStart - this.rdstart;
    this.buf[this.rdstart-2] = (rdlength >> 8) & 0xff;
    this.buf[this.rdstart-1] = (rdlength) & 0xff;
};

DNSWriter.prototype.startTruncate = function () {
    if (this.truncated)
	return;

    this.trstart = this.writeStart;
};

DNSWriter.prototype.endTruncate = function () {
    debug('DNSWriter.prototype.endTruncate');
    // todo: figure out truncate
    this.writeStart = this.trstart;
};

DNSWriter.prototype._cdname = new Buffer(ns_maxcdname);

DNSWriter.prototype._dname = new Buffer(ns_maxdname);

DNSWriter.prototype.writeNameBuffer = function (name) {
    if (this.truncated)
	return;

    var n, len;

    if ((len = ns_name_pton(name, this._dname, this._dname.length)) == -1) {
	if (errno.get() == 'EMSGSIZE') {
	    this.truncated = true;
	    return;
	}
	throw new Error("ns_name_pton");
    }
    if ((n = ns_name_pack(this._dname, this.buf, this.writeStart, this.writeEnd - this.writeStart, this.dnptrs, this.lastdnptr)) == -1) {
	if (errno.get() == 'EMSGSIZE') {
	    this.truncated = true;
	    return;
	}
	throw new Error("ns_name_pack");
    }
    this.writeStart += n;
};

DNSWriter.prototype._string = new Buffer(ns_maxdname);

DNSWriter.prototype.writeNameString = function (name) {
    if (this.truncated)
	return;

    var len;
    // copy string to buffer
    len = this._string.write(name);
    if (len == this._string.length)
	throw new Error("Name string is too long");

    this._string[len] = 0; // terminate string

    this.writeNameBuffer(this._string);
};

DNSWriter.prototype.writeName = function (name) {
    if (typeof name === 'string')
	this.writeNameString(name);
    else if (name instanceof Buffer) {
	this.writeNameBuffer(name);
    }
};

DNSWriter.prototype.writeUInt8 = function (uint) {
    if (this.truncated)
	return;

    if (this.writeStart + 1 > this.writeEnd)
	this.truncated = true;
    else {
	this.buf[this.writeStart++] = (uint) & 0xff;
    }
};

DNSWriter.prototype.writeUInt16 = function (uint) {
    if (this.truncated)
	return;

    if (this.writeStart + 2 > this.writeEnd)
	this.truncated = true;
    else {
	this.buf[this.writeStart++] = (uint >> 8) & 0xff;
	this.buf[this.writeStart++] = (uint >> 0) & 0xff;
    }
};

DNSWriter.prototype.writeUInt32 = function (uint) {
    if (this.truncated)
	return;

    if (this.writeStart + 4 > this.writeEnd)
	this.truncated = true;
    else {
	this.buf[this.writeStart++] = (uint >> 24) & 0xff;
	this.buf[this.writeStart++] = (uint >> 16) & 0xff;
	this.buf[this.writeStart++] = (uint >> 8) & 0xff;
	this.buf[this.writeStart++] = (uint >> 0) & 0xff;
    }
};

DNSWriter.prototype.writeHeader = function (header) {
    var tmp = 0;
    tmp = 0;
    tmp |= (header.qr << 15) & 0x8000;
    tmp |= (header.opcode << 11) & 0x7800;
    tmp |= (header.aa << 10) & 0x0400;
    tmp |= (header.tc << 9) & 0x0200;
    tmp |= (header.rd << 8) & 0x0100;
    tmp |= (header.ra << 7) & 0x0080;
    tmp |= (header.z << 6) & 0x0040;
    tmp |= (header.ad << 5) & 0x0020;
    tmp |= (header.cd << 4) & 0x0010;
    tmp |= (header.rcode << 0) & 0x000f;

    this.writeUInt16(header.id);
    this.writeUInt16(tmp);
    this.writeUInt16(header.qdcount);
    this.writeUInt16(header.ancount);
    this.writeUInt16(header.nscount);
    this.writeUInt16(header.arcount);
};

DNSWriter.prototype.writeQuestion = function (question) {
    debug('DNSWriter.prototype.writeQuestion');
    this.writeName(question.name);
    this.writeUInt16(question.type);
    this.writeUInt16(question.class);
};

DNSWriter.prototype.writeBuffer = function (buf) {
    if (this.truncated)
	return;

    if (this.writeStart + buf.length > this.writeEnd)
	this.truncated = true;
    else {
	buf.copy(this.buf, this.writeStart, 0, buf.length);
	this.writeStart += buf.length;
    }
};

DNSWriter.prototype.writeString = function (str) {
    if (this.truncated)
	return;

    if (this.writeString + Buffer.byteLength(str, 'ascii') > this.writeEnd)
	this.truncated = true;
    else {
	this.writeStart += this.buf.write(str, this.writeStart);
    }
};

DNSWriter.prototype.writeA = function (a) {
    var tmp;

    if (this.truncated)
	return;

    if (this.writeStart + 4 > this.writeEnd)
	this.truncated = true;
    else {
	tmp = a.split('.');
	this.buf[this.writeStart++] = tmp[0];
	this.buf[this.writeStart++] = tmp[1];
	this.buf[this.writeStart++] = tmp[2];
	this.buf[this.writeStart++] = tmp[3];
    }
};

DNSWriter.prototype.writeSOA = function (soa) {
    debug('DNSWriter.prototype.writeSOA');
    this.writeName(soa[0]); // mname
    this.writeName(soa[1]); // rname
    this.writeUInt32(soa[2]); // serial
    this.writeUInt32(soa[3]); // refresh
    this.writeUInt32(soa[4]); // retry
    this.writeUInt32(soa[5]); // expire
    this.writeUInt32(soa[6]); // minumum
};

DNSWriter.prototype.writeMX = function (mx) {
    this.writeUInt16(mx[0]); // preference
    this.writeName(mx[1]); // exchange
};

DNSWriter.prototype.writeAAAA = function (aaaa) {
    if (this.truncated)
	return;

    var n, tmp;

    if (this.writeStart + 16 > this.writeEnd) {
	this.truncated = true;
	return;
    }
    tmp = aaaa.split(":");
    if (tmp.length != 8) 
	throw new Error("IPV6 String must have exactly 7 colons");
    for (var i = 0; i < 8; i++)
	this.writeUInt16(parseInt(tmp[i], 16));
};

DNSWriter.prototype.writeRR = function (rr) {
    debug('DNSWriter.prototype.writeRR');

    this.writeName(rr.name);
    this.writeUInt16(rr.type);
    this.writeUInt16(rr.class);
    this.writeUInt32(rr.ttl);

    this.startRdata();

    if (rr.type == 1) { // a
	this.writeA(rr.rdata[0]);
    }
    else if (rr.type == 2) { // ns
	this.writeName(rr.rdata[0]);
    }
    else if (rr.type == 5) { // cname
	this.writeName(rr.rdata[0]);
    }
    else if (rr.type == 6) { // soa
	this.writeSOA(rr.rdata);
    }
    else if (rr.type == 12) { // ptr
	this.writeName(rr.rdata[0]);
    }
    else if (rr.type == 15) { // mx
	this.writeMX(rr.rdata);
    }
    else if (rr.type == 16) { // txt
	this.writeUInt8(rr.rdata[0].length);
	if (typeof rr.rdata[0] === 'string')
	    this.writeString(rr.rdata[0]);
	else if (rr.rdata[0] instanceof Buffer)
	    this.writeBuffer(rr.rdata[0]);
    }
    else if (rr.type == 28) { // aaaa
	this.writeAAAA(rr.rdata[0]);
    }
    else {
	if (typeof rr.rdata[0] === 'string')
	    this.writeString(rr.rdata[0]);
	else if (rr.rdata[0] instanceof Buffer)
	    this.writeBuffer(rr.rdata[0]);
    }

    this.endRdata();
};

DNSWriter.prototype.writeMessage = function (message) {
    this.writeHeader(message.header);

    for (var i = 0; i < message.q.length; i++)
	this.writeQuestion(message.q[i]);

    this.startTruncate();

    for (var i = 0; i < message.rr.length; i++) {
	this.writeRR(message.rr[i]);
    }

    if (this.truncated)
	this.endTruncate();
};

var parsers = new FreeList('parsers', 1000, function() {
    var parser = new DNSParser();

    parser.onMessageBegin = function () {
	debug('parser.onMessageBegin');

	parser.incoming = new IncomingMessage(parser.socket, parser.rinfo);
    }
    parser.onHeader = function () {
	debug('parser.onHeader');

	try {
	    parser.parseHeader(parser.incoming.header);
	} catch (err) { parser.onError (err); }
    };
    parser.onQuestion = function () {
	debug('parser.onQuestion');

	try {
	    parser.parseQuestion(parser.incoming.q.add());
	} catch (err) { parser.onError (err); }
    };
    parser.onAnswerBegin = function () {
	debug('parser.onAnswerBegin');
    };
    parser.onAuthorityBegin = function () {
	debug('parser.onAuthorityBegin');
    };
    parser.onAdditionalBegin = function () {
	debug('parser.onAdditionalBegin');
    };
    parser.onRR = function () {
	debug('parser.onRR');

	try {
	    parser.parseRR(parser.incoming.rr.add());
	} catch (err) { parser.onError (err); }
    };
    parser.onMessageComplete = function () {
	debug('parser.onMessageComplete');

	parser.onIncoming(parser.incoming);
    };

    return parser;
});

function MessageHeader () {
}

MessageHeader.prototype.id = 0;
MessageHeader.prototype.qr = 0;
MessageHeader.prototype.opcode = 0;
MessageHeader.prototype.aa = 0;
MessageHeader.prototype.tc = 0;
MessageHeader.prototype.rd = 0;
MessageHeader.prototype.ra = 0;
MessageHeader.prototype.a = 0;
MessageHeader.prototype.ad = 0;
MessageHeader.prototype.cd = 0;
MessageHeader.prototype.rcode = 0;

MessageHeader.prototype.set = function (obj) {
    for (var k in obj)
	this[k] = obj[k];
};

function MessageRecord () {
}

MessageRecord.prototype.set = MessageHeader.prototype.set;

function MessageObject () {
    this.length = 0;
}

MessageObject.prototype.add = function () {
    var obj = this[this.length++] = new MessageRecord();
    if (arguments.length > 0)
	obj.set(arguments[0]);
    return obj;
};

function Message (socket, rinfo) {
    events.EventEmitter.call(this);

    this.socket = socket;
    this.rinfo = rinfo;

    this.length = 0;
    this.header = new MessageHeader();
    this.q = new MessageObject();
    this.rr = new MessageObject();
}
sys.inherits(Message, events.EventEmitter);
exports.Message = Message;

Message.prototype.addRR = function (name, ttl, className, typeName) {
    if (arguments.length >= 4) {
	if (n_type_syms.hasOwnProperty(typeName.toUpperCase()) &&
	    n_class_syms.hasOwnProperty(className.toUpperCase())) {
	    var rr = this.rr.add();
	    rr.name = name;
	    rr.ttl = ttl
	    rr.type = n_type_syms[typeName.toUpperCase()];
	    rr.class = n_class_syms[className.toUpperCase()];
	    rr.rdata = Array.prototype.slice.call(arguments, 4);
	    return rr;
	}
    }
};

Message.prototype.setHeader = function (obj) {
    for (k in obj)
	this.header[k] = obj[k];
};

Message.prototype.addQuestion = function (name, typeName, className) {
    var question;
    if (arguments.length == 1 && typeof arguments[0] === 'object') {
	this.q.add(arguments[0]);
    }
    else {
	if (typeof name !== 'string' &&
	    !(name instanceof Buffer)) {
	    throw new Error ("Name argument should be string or buffer")
	}
	if (n_type_syms.hasOwnProperty(typeName.toUpperCase()) &&
	    n_class_syms.hasOwnProperty(className.toUpperCase())) {
	    question = this.q.add();
	    question.name = name;
	    question.type = n_type_syms[typeName.toUpperCase()];
	    question.class = n_class_syms[className.toUpperCase()];
	}
    }
};

function IncomingMessage (socket, rinfo) {
    Message.call(this, socket, rinfo);
};
sys.inherits(IncomingMessage, Message);
exports.IncomingMessage = IncomingMessage;

function OutgoingMessage (socket, rinfo) {
    Message.call(this, socket, rinfo);
    this.maxSend = 512;
}
sys.inherits(OutgoingMessage, Message);
exports.OutgoingMessage = OutgoingMessage;

OutgoingMessage.prototype._Buffer = new Buffer(ns_maxmsg);

OutgoingMessage.prototype._Writer = new DNSWriter();

OutgoingMessage.prototype.setMaxSend = function (n) {
    if (n > ns_maxmsg)
	throw new Error ("Size must be < 65535");

    this.maxSend = n;
};

OutgoingMessage.prototype.send = function (message) {
    debug('ServerResponse.prototype.send');

    if (arguments.length == 0)
	message = this;

    this._Writer.reinitialize (this._Buffer, 0, Math.min(this.maxSend, this._Buffer.length));

    this._Writer.writeMessage(message);


    this.socket.send(this._Buffer, 0, this._Writer.writeStart, this.rinfo.port, this.rinfo.address, function (err, bytesSent) {
	debug (err || 'bytesSent: ' + bytesSent);
    });
};

function ServerResponse (req) {
    OutgoingMessage.call(this, req.socket, req.rinfo);
}
sys.inherits(ServerResponse, OutgoingMessage);
exports.ServerResponse = ServerResponse;

function ClientRequest(client, socket, port, host) {
    OutgoingMessage.call(this, socket, { port: port, address: host });

    this.client = client;
    this.socket = socket;

    this.port = port;
    this.host = host;
}
sys.inherits(ClientRequest, OutgoingMessage);
exports.ClientRequest = ClientRequest;

ClientRequest.prototype.send = function (message) {
    debug('ClientRequest.prototype.send');

    if (arguments.length == 0)
	message = this;

    this.client.pending.push({
	time: new Date(),
	request: this,
	id: message.header.id,
	rinfo: this.rinfo
    });

    this._Writer.reinitialize (this._Buffer, 0, Math.min(this._Buffer.length, this.maxSend));

    this._Writer.writeMessage(message);

    this.socket.send(this._Buffer, 0, this._Writer.writeStart, this.rinfo.port, this.rinfo.address, function (err, bytesSent) {
	debug (err || 'bytesSent: ' + bytesSent);
    });
};

function Server(type, requestListener) {
    dgram.Socket.call(this, type);

    if(requestListener) {
	this.on("request", requestListener);
    }

    this.on("message", messageListener);
};
sys.inherits(Server, dgram.Socket);
exports.Server = Server;

Server.prototype._Parser = parsers.alloc();

exports.createServer = function() {
    var type = 'udp4';
    var requestListener = null;
    if(typeof arguments[0] === 'string') {
	type = arguments[0];
	if(typeof arguments[1] === 'function') {
	    requestListener = arguments[1];
	}
    }
    else if(typeof arguments[0] === 'function') {
	requestListener = arguments[0];
    }
    return new Server(type, requestListener);
};

function messageListener(msg, rinfo) {
    var self = this;

    debug("new message");

    this._Parser.reinitialize(msg, 0, msg.length);
    this._Parser.socket = this;
    this._Parser.rinfo = rinfo;

    this._Parser.onIncoming = function (req) {
	var res = new ServerResponse(req);
	self.emit('request', req, res);
    };
    this._Parser.onError = debug;

    this._Parser.parseMessage();
}

function Client(type, responseListener) {
    dgram.Socket.call(this, type);

    this.pending = [];

    if (responseListener) {
	this.on("response", responseListener);
    }

    this.on("message", clientMessageListener);
    this.bind();
}
sys.inherits(Client, dgram.Socket);
exports.Client = Client;

Client.prototype.request = function (port, host) {
    var req = new ClientRequest(this, this, port, host);
    return req;
};

Client.prototype.defaultType = 'udp4';

Client.prototype.parser = parsers.alloc();

exports.createClient = function() {
    var type = this.defaultType;
    var responseListener = null;
    if(typeof arguments[0] === 'string') {
	type = arguments[0];
	if(typeof arguments[1] === 'function') {
	    responseListener = arguments[1];
	}
    }
    else if(typeof arguments[0] === 'function') {
	requestListener = arguments[0];
    }
    return new Client(type, responseListener);
};

function clientMessageListener(msg, rinfo) {
    var self = this;

    debug("new message");

    this.parser.reinitialize(msg, 0, msg.length);
    this.parser.socket = this;
    this.parser.rinfo = rinfo;

    this.parser.onIncoming = function (res) {
	var i, item;
	self.emit("response", res);
	for (i = 0; i < self.pending.length; i++) {
	    item = self.pending[i];
	    if (item.id == res.header.id &&
		item.rinfo.address == rinfo.address &&
		item.rinfo.port == rinfo.port) {

		item.request.emit("response", res);
		self.pending.splice(i, 1);
	    }
	}
    };
    this.parser.onError = debug;

    this.parser.parseMessage();
}
