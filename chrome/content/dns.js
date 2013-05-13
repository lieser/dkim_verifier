/*
 * DNS LIBRARY IN JAVASCRIPT
 *
 * Copyright 2005 Joshua Tauberer <http://razor.occams.info>
 *
 * Feel free to use this file however you want, but
 * credit would be nice.
 *
 * A major limitation of this library is that Mozilla
 * only provides TCP sockets, and DNS servers sometimes
 * only respond on UDP. Especially public DNS servers
 * that have the authoritative information for their
 * domain. In that case, we really need a "local" server
 * that responds to TCP.
 *
 * We have a few options.  First, we could try the public
 * DNS system starting at one of the root servers of the
 * world and hope the name servers on the path to the final
 * answer all respond to TCP. For that, the root name server
 * could be, e.g., J.ROOT-SERVERS.NET.
 *
 * Or we can just go with Google's new public DNS service
 * at 8.8.8.8 or 8.8.4.4 which responds on TCP. Good solution!
 *
 * The next option is to ask the user for a local name server
 * that responds to TCP. Some routers cause trouble for this.
 * It would be nice to have a local server so that it caches
 * nicely. The user can override the otherwise default root
 * server by setting the dns.nameserver option.
 *
 * We can also try to auto-detect the user's local name server.
 * The Windows registry and the file /etc/resolv.conf (on Linux)
 * can be scanned for a DNS server to use.
 */

var DNS_ROOT_NAME_SERVER = "8.8.8.8"; // This is Google Public DNS. Could be "J.ROOT-SERVERS.NET", but public DNS may not respond to TCP. 
var DNS_FOUND_NAME_SERVER_AUTOMATICALLY = 0;

// Any settings changes aren't going to be picked up later.
DNS_LoadPrefs();

function DNS_LoadPrefs() {
	var prefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch);

	if (prefs.getPrefType("dns.nameserver") == prefs.PREF_STRING
		&& prefs.getCharPref("dns.nameserver") != null && prefs.getCharPref("dns.nameserver") != "" && prefs.getCharPref("dns.nameserver") != "occams.info:9053") {
		DNS_ROOT_NAME_SERVER = prefs.getCharPref("dns.nameserver");
		//DNS_Log("DNS: Got server from user preference: " + DNS_ROOT_NAME_SERVER);
	} else if (false) {
		// Try getting a nameserver from /etc/resolv.conf.
		
		// No need to do this while Google Public DNS is running.
		
		try {
			var resolvconf = Components.classes["@mozilla.org/file/local;1"].createInstance(Components.interfaces.nsILocalFile);
			resolvconf.initWithPath("/etc/resolv.conf");
			
			var stream = Components.classes["@mozilla.org/network/file-input-stream;1"].createInstance();
			var stream_filestream = stream.QueryInterface(Components.interfaces.nsIFileInputStream);
			stream_filestream.init(resolvconf, 0, 0, 0); // don't know what the flags are...
			
			var stream_reader = stream.QueryInterface(Components.interfaces.nsILineInputStream);
			
			var out_line = Object();
			while (stream_reader.readLine(out_line)) {
				if (DNS_StartsWith(out_line.value, "nameserver ")) {
					DNS_ROOT_NAME_SERVER = out_line.value.substring("nameserver ".length);
					DNS_FOUND_NAME_SERVER_AUTOMATICALLY = 1;
					break;
				}
			}
			
			stream_filestream.close();
			
			//DNS_Log("DNS: Got server from resolv.conf: " + DNS_ROOT_NAME_SERVER);
		} catch (e) {
			//DNS_Log("DNS: Reading resolv.conf: " + e);
		}
		
		// Try getting a nameserver from the windows registry
		try {
			var registry_class = Components.classes["@mozilla.org/windows-registry-key;1"];
			if (registry_class != null) {
			var registry_object = registry_class.createInstance();
			var registry = registry_object.QueryInterface(Components.interfaces.nsIWindowsRegKey);
			
			registry.open(registry.ROOT_KEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", registry.ACCESS_QUERY_VALUE);
			var ns = "";
			if (registry.hasValue("DhcpNameServer")) ns = registry.readStringValue("DhcpNameServer");
			if (ns == "" && registry.hasValue("NameServer")) ns = registry.readStringValue("NameServer");
			registry.close();
			
			if (ns != "") {
				var servers = ns.split(' ');
				if (servers.length > 0 && servers[0] != "") {
					DNS_ROOT_NAME_SERVER = servers[0];
					DNS_FOUND_NAME_SERVER_AUTOMATICALLY = 1;
					//DNS_Log("DNS: Got server from Windows registry: " + DNS_ROOT_NAME_SERVER);
				}
			}
			}
		} catch (e) {
			//DNS_Log("DNS: Reading Registry: " + e);
		}
		
		//DNS_Log("DNS: Autoconfigured server: " + DNS_ROOT_NAME_SERVER);
	}
}

var dns_test_domains = Array("for.net", "www.for.net", "yy.for.net", "www.gmail.net");
var dns_test_domidx = 0;
//DNS_Test();
function DNS_Test() {
	queryDNS(dns_test_domains[dns_test_domidx], "MX",
		function(data) {
			var str;
			var i;
			if (data == null) { str = "no data"; }
			else {
				for (i = 0; i < data.length; i++) {
					if (data[i].host != null)
						data[i] = "host=" + data[i].host + ";address=" + data[i].address;
					
					if (str != null) str += ", "; else str = "";
					str += data[i];
				}
			}
			
			alert(dns_test_domains[dns_test_domidx] + " => " + str);
			dns_test_domidx++;
			DNS_Test();
		} );
}

//queryDNS("www.example.com", "A", function(data) { alert(data); } );
//reverseDNS("123.456.789.123", function(addrs) { for (var i = 0; i < addrs.length; i++) { alert(addrs[i]); } } );

// queryDNS: This is the main entry point for external callers.
function queryDNS(host, recordtype, callback, callbackdata) {
	queryDNSRecursive(DNS_ROOT_NAME_SERVER, host, recordtype, callback, callbackdata, 0);
}

function reverseDNS(ip, callback, callbackdata) {
	// Get a list of reverse-DNS hostnames,
	// and then make sure that each hostname
	// resolves to the original IP.
	
	queryDNS(DNS_ReverseIPHostname(ip), "PTR",
		function(hostnames, mydata, queryError) {
			// No reverse DNS info available.
			if (hostnames == null) { callback(null, callbackdata, queryError); return; }
			
			var obj = new Object();
			obj.ret = Array(0);
			obj.retctr = 0;
			obj.resolvectr = 0;
			
			var i;
			
			// Check that each one resolves forward.
			for (i = 0; i < hostnames.length; i++) {
				var o2 = new Object();
				o2.retobj = obj;
				o2.curhostname = hostnames[i];
				
				queryDNS(hostnames[i], "A",
				function(arecs, cb) {
					if (arecs != null) {
						var j;
						var matched = false;
						for (j = 0; j < arecs.length; j++) {
							if (arecs[j] == ip) { matched = true; break; }
						}
					}
					
					if (matched)
						cb.retobj.ret[cb.retobj.retctr++] = cb.curhostname;
					
					if (++cb.retobj.resolvectr == hostnames.length) {
						if (cb.retobj.retctr == 0)
							callback(null, callbackdata);
						else
							callback(cb.retobj.ret, callbackdata);
					}
				}, o2);
			}
		});
}

function DNS_ReverseIPHostname(ip) {
	var q = ip.split(".");
	return q[3] + "." + q[2] + "." + q[1] + "." + q[0] + ".in-addr.arpa";
}

function queryDNSRecursive(server, host, recordtype, callback, callbackdata, hops) {
	if (hops == 10) {
		DNS_Debug("DNS: Maximum number of recursive steps taken in resolving " + host);
		callback(null, callbackdata, DNS_STRINGS.TOO_MANY_HOPS);
		return;
	}
	
	DNS_Debug("DNS: Resolving " + host + " " + recordtype + " by querying " + server);
		
	var query =
		// HEADER
		  "00" // ID
		+ String.fromCharCode(1) // QR=0, OPCODE=0, AA=0, TC=0, RD=1 (Recursion desired)
		+ String.fromCharCode(0) // all zeroes
		+ DNS_wordToStr(1) // 1 query
		+ DNS_wordToStr(0) // ASCOUNT=0
		+ DNS_wordToStr(0) // NSCOUNT=0
		+ DNS_wordToStr(0) // ARCOUNT=0
		;
		
	var hostparts = host.split(".");
	for (var hostpartidx = 0; hostpartidx < hostparts.length; hostpartidx++)
		query += DNS_octetToStr(hostparts[hostpartidx].length) + hostparts[hostpartidx];
	query += DNS_octetToStr(0);
	if (recordtype == "A")
		query += DNS_wordToStr(1);
	else if (recordtype == "NS")
		query += DNS_wordToStr(2); 
	else if (recordtype == "CNAME")
		query += DNS_wordToStr(5); 
	else if (recordtype == "PTR")
		query += DNS_wordToStr(12); 
	else if (recordtype == "MX")
		query += DNS_wordToStr(15); 
	else if (recordtype == "TXT")
		query += DNS_wordToStr(16); 
	else
		throw "Invalid record type.";
	query += DNS_wordToStr(1); // IN
		
	// Prepend query message length
	query = DNS_wordToStr(query.length) + query;
	
	var listener = {
		msgsize : null,
		readcount : 0,
		responseHeader : "",
		responseBody : "",
		done : false,
		finished : function(data, status) {
			if (status != 0) {
				if (status == 2152398861) {
					DNS_Debug("DNS: Resolving " + host + "/" + recordtype + ": DNS server " + server + " refused a TCP connection.");
					callback(null, callbackdata, DNS_STRINGS.CONNECTION_REFUSED(server));
				} else if (status == 2152398868) {
					DNS_Debug("DNS: Resolving " + host + "/" + recordtype + ": DNS server " + server + " timed out on a TCP connection.");
					callback(null, callbackdata, DNS_STRINGS.TIMED_OUT(server));
				} else {
					DNS_Debug("DNS: Resolving " + host + "/" + recordtype + ": Failed to connect to DNS server " + server + " with error code " + status + ".");
					callback(null, callbackdata, DNS_STRINGS.SERVER_ERROR(server));
				}
				return;
			}
			
			this.process(data);
			if (!this.done) {
				DNS_Debug("DNS: Resolving " + host + "/" + recordtype + ": Response was incomplete.");
				callback(null, callbackdata, DNS_STRINGS.INCOMPLETE_RESPONSE(server));
			}
		},
		process : function(data){
			if (this.done) return false;
			
			this.readcount += data.length;
			
			while (this.responseHeader.length < 14 && data.length > 0) {
				this.responseHeader += data.charAt(0);
				data = data.substr(1);
			}
			if (this.responseHeader.length == 14) {
				this.msgsize = DNS_strToWord(this.responseHeader.substr(0, 2));
				this.responseBody += data;

				//DNS_Debug("DNS: Received Reply: " + (this.readcount-2) + " of " + this.msgsize + " bytes");

				if (this.readcount >= this.msgsize+2) {
					this.responseHeader = this.responseHeader.substr(2); // chop the length field
					this.done = true;
					DNS_getRDData(this.responseHeader + this.responseBody, server, host, recordtype, callback, callbackdata, hops);
					return false;
				}
			}
			return true;
		}
	}
	
	// allow server to be either a hostname or hostname:port
	var server_hostname = server;
	var port = 53;
	if (server.indexOf(':') != -1) {
		server_hostname = server.substring(0, server.indexOf(':'));
		port = server.substring(server.indexOf(':')+1);
	}

	var ex = DNS_readAllFromSocket(server_hostname, port, query, listener);
	if (ex != null) {
	  alert(ex);
	}
}

function DNS_readDomain(ctx) {
	var domainname = "";
	var ctr = 20;
	while (ctr-- > 0) {
		var l = ctx.str.charCodeAt(ctx.idx++);
		if (l == 0) break;
		
		if (domainname != "") domainname += ".";
		
		if ((l >> 6) == 3) {
			// Pointer
			var ptr = ((l & 63) << 8) + ctx.str.charCodeAt(ctx.idx++);
			var ctx2 = { str : ctx.str, idx : ptr };
			domainname += DNS_readDomain(ctx2);
			break;
		} else {
			domainname += ctx.str.substr(ctx.idx, l);
			ctx.idx += l;
		}
	}
	return domainname;
}

function DNS_readRec(ctx) {
	var rec = new Object();
	var ctr;
	var txtlen;
	
	rec.dom = DNS_readDomain(ctx);
	rec.type = DNS_strToWord(ctx.str.substr(ctx.idx, 2)); ctx.idx += 2;
	rec.cls = DNS_strToWord(ctx.str.substr(ctx.idx, 2)); ctx.idx += 2;
	rec.ttl = DNS_strToWord(ctx.str.substr(ctx.idx, 2)); ctx.idx += 4; // 32bit
	rec.rdlen = DNS_strToWord(ctx.str.substr(ctx.idx, 2)); ctx.idx += 2;
	rec.recognized = 1;
	
	var ctxnextidx = ctx.idx + rec.rdlen;
	
	if (rec.type == 16) {
		rec.type = "TXT";
		rec.rddata = "";
		ctr = 10;
		while (rec.rdlen > 0 && ctr-- > 0) {
			txtlen = DNS_strToOctet(ctx.str.substr(ctx.idx,1)); ctx.idx++; rec.rdlen--;
			rec.rddata += ctx.str.substr(ctx.idx, txtlen); ctx.idx += txtlen; rec.rdlen -= txtlen;
		}
	} else if (rec.type == 1) {
		// Return as a dotted-quad
		rec.type = "A";
		rec.rddata = ctx.str.substr(ctx.idx, rec.rdlen);
		rec.rddata = rec.rddata.charCodeAt(0) + "." + rec.rddata.charCodeAt(1) + "." + rec.rddata.charCodeAt(2) + "." + rec.rddata.charCodeAt(3);
	} else if (rec.type == 15) {
		rec.type = "MX";
		rec.rddata = new Object();
		rec.rddata.preference = DNS_strToWord(ctx.str.substr(ctx.idx,2)); ctx.idx += 2;
		rec.rddata.host = DNS_readDomain(ctx);
	} else if (rec.type == 2) {
		rec.type = "NS";
		rec.rddata = DNS_readDomain(ctx);
	} else if (rec.type == 12) {
		rec.type = "PTR";
		rec.rddata = DNS_readDomain(ctx);
	} else {
		rec.recognized = 0;
	}
	
	ctx.idx = ctxnextidx;
	
	return rec;
}

function DNS_getRDData(str, server, host, recordtype, callback, callbackdata, hops) {
	var qcount = DNS_strToWord(str.substr(4, 2));
	var ancount = DNS_strToWord(str.substr(6, 2));
	var aucount = DNS_strToWord(str.substr(8, 2));
	var adcount = DNS_strToWord(str.substr(10, 2));
	
	var ctx = { str : str, idx : 12 };
	
	var i;
	var j;
	var dom;
	var type;
	var cls;
	var ttl;
	var rec;
	
	if (qcount != 1) throw "Invalid response: Question section didn't have exactly one record.";
	if (ancount > 128) throw "Invalid response: Answer section had more than 128 records.";
	if (aucount > 128) throw "Invalid response: Authority section had more than 128 records.";
	if (adcount > 128) throw "Invalid response: Additional section had more than 128 records.";
	
	for (i = 0; i < qcount; i++) {
		dom = DNS_readDomain(ctx);
		type = DNS_strToWord(str.substr(ctx.idx, 2)); ctx.idx += 2;
		cls = DNS_strToWord(str.substr(ctx.idx, 2)); ctx.idx += 2;
	}
	
	var debugstr = "DNS: " + host + "/" + recordtype + ": ";
	
	var results = Array(ancount);
	for (i = 0; i < ancount; i++) {
		rec = DNS_readRec(ctx);
		if (!rec.recognized) throw "Record type is not one that this library can understand.";
		results[i] = rec.rddata;		
		DNS_Debug(debugstr + "Answer: " + rec.rddata);
	}

	var authorities = Array(aucount);
	for (i = 0; i < aucount; i++) {
		rec = DNS_readRec(ctx);
		authorities[i] = rec;
		if (rec.recognized)
			DNS_Debug(debugstr + "Authority: " + rec.type + " " + rec.rddata);
		// Assuming the domain for this record is the domain we are asking about.
	}
	
	for (i = 0; i < adcount; i++) {
		rec = DNS_readRec(ctx);
		if (rec.recognized)
			DNS_Debug(debugstr + "Additional: " + rec.dom + " " + rec.type + " " + rec.rddata);
		if (rec.type == "A") {
			for (j = 0; j < results.length; j++) {
				if (results[j].host && results[j].host == rec.dom) {
					if (results[j].address == null) results[j].address = Array(0);
					results[j].address[results[j].address.length] = rec.rddata;
				}
			}
		}
	}
	
	if (results.length > 0) {
		// We have an answer.
		callback(results, callbackdata);
		
	} else {
		// No answer.  If there is an NS authority, recurse.
		// Note that we can do without the IP address of the NS authority (given in the additional
		// section) because we're able to do DNS lookups without knowing the IP address
		// of the DNS server -- Thunderbird and the OS take care of that.
		for (var i = 0; i < aucount; i++) {
			if (authorities[i].type == "NS" && authorities[i].rddata != server) {
				DNS_Debug(debugstr + "Recursing on Authority: " + authorities[i].rddata);
				queryDNSRecursive(authorities[i].rddata, host, recordtype, callback, callbackdata, hops+1);
				return;
			}
		}

		// No authority was able to help us.
		DNS_Debug(debugstr + "No answer, no authority to recurse on.  DNS lookup failed.");
		callback(null, callbackdata);
	}
}

function DNS_strToWord(str) {
	return str.charCodeAt(1) + (str.charCodeAt(0) << 8);
}

function DNS_strToOctet(str) {
	return str.charCodeAt(0);
}

function DNS_wordToStr(word) {
	return DNS_octetToStr((word >> 8) % 256) + DNS_octetToStr(word % 256);
}

function DNS_octetToStr(octet) {
	return String.fromCharCode(octet);
}

// This comes from http://xulplanet.com/tutorials/mozsdk/sockets.php

function DNS_readAllFromSocket(host,port,outputData,listener)
{
  try {
    var transportService =
      Components.classes["@mozilla.org/network/socket-transport-service;1"]
        .getService(Components.interfaces.nsISocketTransportService);
		
    var transport = transportService.createTransport(null,0,host,port,null);

    var outstream = transport.openOutputStream(0,0,0);
    outstream.write(outputData,outputData.length);

    var stream = transport.openInputStream(0,0,0);
    var instream = Components.classes["@mozilla.org/binaryinputstream;1"]
      .createInstance(Components.interfaces.nsIBinaryInputStream);
    instream.setInputStream(stream);

    var dataListener = {
		data : "",
		onStartRequest: function(request, context){},
		onStopRequest: function(request, context, status){
			if (listener.finished != null) {
				listener.finished(this.data, status);
			}
			outstream.close();
			stream.close();
			//DNS_Debug("DNS: Connection closed (" + host + ")");
		},
		onDataAvailable: function(request, context, inputStream, offset, count){
			//DNS_Debug("DNS: Got data (" + host + ")");
			for (var i = 0; i < count; i++) {
			  this.data += String.fromCharCode(instream.read8());
			}
			if (listener.process != null) {
				if (!listener.process(this.data)) {
					outstream.close();
					stream.close();
				}
				this.data = "";
			}
      }
    };
	
    var pump = Components.
      classes["@mozilla.org/network/input-stream-pump;1"].
        createInstance(Components.interfaces.nsIInputStreamPump);
    pump.init(stream, -1, -1, 0, 0, false);
    pump.asyncRead(dataListener,null);
  } catch (ex) {
    return ex;
  }
  return null;
}

function DNS_Debug(message) {
	if (false) {
		DNS_Log(message);
	}
}

function DNS_Log(message) {
	var consoleService = Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService);
	consoleService.logStringMessage(message);
}

function DNS_StartsWith(a, b) {
	if (b.length > a.length) return false;
	return a.substring(0, b.length) == b;
}

function DNS_IsDottedQuad(ip) {
	var q = ip.split(".");
	if (q.length != 4)
		return false;
	if (isNaN(parseInt(q[0])) || isNaN(parseInt(q[1])) || isNaN(parseInt(q[2])) || isNaN(parseInt(q[3])))
		return false;
	return true;
}
