/*
 * JSDNS.jsm
 *
 * Based on Joshua Tauberer's DNS LIBRARY IN JAVASCRIPT
 * from "Sender Verification Extension" version 0.9.0.6
 *
 * Version: 2.0.0 (31 May 2020)
 *
 * Copyright (c) 2013-2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

/* ***** BEGIN ORIGINAL LICENSE/COPYRIGHT NOTICE ***** */
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
/* ***** END ORIGINAL LICENSE/COPYRIGHT NOTICE ***** */

/*
 * Changelog:
 * ==========
 *
 * 2.0.0
 * -----
 * - configure preferences from outside
 * - removed unused code
 * - requires at least Gecko 69
 * - some ESLint and TS fixes
 * - use console.createInstance() for logging
 *
 * 1.4.4
 * -----
 * - add defaults for preferences
 *
 * 1.4.3
 * -----
 * - fixed proxy support
 *
 * 1.4.2
 * -----
 *  - requires at least Gecko 68
 *  - fixed incompatibility with Gecko 68/69
 *
 * 1.4.1
 * -----
 *  - fixed a problem getting the default DNS servers on Windows
 *
 * 1.4.0
 * -----
 *  - fixed incompatibility with Gecko 57
 *  - no longer needs ModuleGetter.jsm
 *  - fixed ESLint warnings, removed options for JSHint
 *
 * 1.3.0
 * -----
 *  - added support for rcode
 *
 * 1.2.0
 * -----
 *  - added support to use a proxy
 *
 * 1.1.1
 * -----
 *  - fixed incompatibility with Gecko 46
 *
 * 1.1.0
 * -----
 *  - no longer get the DNS servers from deactivated interfaces under windows
 *
 * 1.0.3
 * -----
 *  - increased max read length of TXT record
 *
 * 1.0.2
 * -----
 *  - fixed last line of /etc/resolv.conf not being read
 *
 * 1.0.1
 * -----
 *  - fixed use of stringbundle
 *  - added read and write timeout
 *  - added option to automatically reset all server to alive if all are marked down
 *
 * 1.0.0
 * -----
 *  - added close() calls in catch blocks
 *  - now uses Log.jsm for logging
 *  - preferences are no longer set form the outside,
 *    but are loaded by the module itself
 *  - now uses stringbundle
 *
 * 0.6.3
 * -----
 *  - fixed bug for detection of configured DNS Servers in Windows
 *    (if more then one DNS server was configured for an adapter)
 *
 * 0.6.1
 * -----
 *  - better detection of configured DNS Servers in Windows
 *
 * 0.5.1
 * -----
 *  - reenabled support to get DNS Servers from OS
 *   - modified and renamed DNS_LoadPrefs() to DNS_get_OS_DNSServers()
 *  - fixed jshint errors/warnings
 *
 * 0.5.0
 * -----
 *  - added support of multiple DNS servers
 *
 * 0.3.4
 * -----
 *  - CNAME record type partial supported
 *   - doesn't throw a exception anymore
 *   - data not read, and not included in the returned result
 *
 * 0.3.0
 * -----
 *  - changed to a JavaScript code module
 *  - DNS_LoadPrefs() not executed
 *  - added debug on/off setting
 *
 * 0.1.0
 * -----
 *  original DNS LIBRARY IN JAVASCRIPT by Joshua Tauberer
 *  from "Sender Verification Extension" version 0.9.0.6
 */

//@ts-check
// options for ESLint
/* eslint-env worker */
/* eslint-disable prefer-template */
/* eslint-disable no-use-before-define */
/* eslint-disable camelcase */
/* eslint-disable no-var */
/* eslint strict: ["warn", "function"] */
/* eslint complexity: "off" */
/* eslint no-magic-numbers: "off" */
/* global Components */
/* exported EXPORTED_SYMBOLS, JSDNS */


var EXPORTED_SYMBOLS = [
	"JSDNS"
];

// @ts-ignore
const Cc = Components.classes;
// @ts-ignore
const Ci = Components.interfaces;


// @ts-ignore
const LOG_NAME = "DKIM_Verifier.JSDNS";


var JSDNS = {};

/** @type {ChromeConsole} */
// @ts-ignore
const chromeConsole = console;
var log = chromeConsole.createInstance({
	prefix: LOG_NAME,
	maxLogLevel: "Warn",
	maxLogLevelPref: "extensions.dkim_verifier.experiments.logging",
});


/**
 * @typedef {Object} DnsServer
 * @property {string} server - IP of server as string
 * @property {boolean} alive -  whether the server is alive
 */

// Preferences
/** @type {DnsServer[]} */
var DNS_ROOT_NAME_SERVERS = [];
var timeout_connect = 0xFFFF;
/** @type {number|null} */
var timeout_read_write = null;
var PROXY_CONFIG = {
	enable: false,
	type: "",
	host: "",
	port: 0
};
var AUTO_RESET_SERVER_ALIVE = false;

/**
 * Set preferences to use.
 *
 * @param {boolean} getNameserversFromOS
 * @param {string} nameServer
 * @param {number} timeoutConnect
 * @param {{ enable: boolean, type: string, host: string, port: number }} proxy
 * @param {boolean} autoResetServerAlive
 * @returns {void}
 */
function configureDNS(getNameserversFromOS, nameServer, timeoutConnect, proxy, autoResetServerAlive) {
	"use strict";

	/** @type {DnsServer[]} */
	const prefDnsRootNameServers = [];
	nameServer.split(";").forEach(function (element /*, index, array*/) {
		if (element.trim() !== "") {
			prefDnsRootNameServers.push({
				server: element.trim(),
				alive: true
			});
		}
	});
	if (getNameserversFromOS) {
		const osDnsRootNameServers = getOsDnsServers();
		DNS_ROOT_NAME_SERVERS = arrayUniqBy(
			osDnsRootNameServers.concat(prefDnsRootNameServers),
			function (e) { return e.server; }
		);
	} else {
		DNS_ROOT_NAME_SERVERS = prefDnsRootNameServers;
	}

	log.info("changed DNS Servers to :", DNS_ROOT_NAME_SERVERS);

	timeout_connect = timeoutConnect;
	timeout_read_write = timeoutConnect;

	PROXY_CONFIG = proxy;

	AUTO_RESET_SERVER_ALIVE = autoResetServerAlive;
}

/**
 * Remove Duplicates from Array
 *
 * from http://stackoverflow.com/questions/9229645/remove-duplicates-from-javascript-array/9229821#9229821
 *
 * @template T
 * @param {T[]} ary
 * @param {function(T): string} key
 *        Function to generate key from element
 * @return {T[]}
 */
function arrayUniqBy(ary, key) {
	"use strict";

	/** @type {Object.<string, number>} */
	var seen = {};
	return ary.filter(function (elem) {
		var k = key(elem);
		if (seen[k] === 1) {
			return false;
		}
		seen[k] = 1;
		return true;
	});
}

/**
 * get DNS Servers from OS configuration
 *
 * @return {DnsServer[]}
 */
function getOsDnsServers() {
	"use strict";

	/** @type {DnsServer[]} */
	const OS_DNS_ROOT_NAME_SERVERS = [];

	if ("@mozilla.org/windows-registry-key;1" in Components.classes) {
		// Firefox 1.5 or newer on Windows
		// Try getting a nameserver from the windows registry
		var reg;
		/** @type {nsIWindowsRegKey} */
		var registry;
		var registryLinkage;
		var registryInterfaces;
		try {
			var registry_class = Components.classes["@mozilla.org/windows-registry-key;1"];
			var registry_object = registry_class.createInstance();
			registry = registry_object.QueryInterface(Components.interfaces.nsIWindowsRegKey);

			registry.open(registry.ROOT_KEY_LOCAL_MACHINE,
				"SYSTEM\\CurrentControlSet",
				registry.ACCESS_QUERY_VALUE);

			// get interfaces in routing order
			registryLinkage = registry.openChild("Services\\Tcpip\\Linkage",
				registry.ACCESS_READ);
			// nsIWindowsRegKey doesn't support REG_MULTI_SZ type out of the box
			// from http://mxr.mozilla.org/comm-central/source/mozilla/browser/components/migration/src/IEProfileMigrator.js#129
			// slice(1,-1) to remove the " at the beginning and end
			var str = registryLinkage.readStringValue("Route");
			var interfaces = str.split("\0").map(function (e) {
				return e.slice(1, -1);
			}).filter(function (e) {
				return e;
			});
			log.debug("Found " + interfaces.length + " interfaces.");

			// filter out deactivated interfaces
			var registryNetworkAdapters = registry.openChild(
				"Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}",
				registry.ACCESS_QUERY_VALUE);
			var registryDevInterfaces = registry.openChild(
				"Control\\DeviceClasses\\{cac88484-7515-4c03-82e6-71a87abac361}",
				registry.ACCESS_QUERY_VALUE);
			var interfacesOnline = interfaces.filter(function (element /*, index, array*/) {
				reg = registryNetworkAdapters.openChild(element + "\\Connection",
					registry.ACCESS_READ);
				if (!reg.hasValue("PnpInstanceID")) {
					log.debug("Network Adapter has no PnpInstanceID: " + element);
					return false;
				}
				var interfaceID = reg.readStringValue("PnpInstanceID");
				reg.close();
				var interfaceID_ = interfaceID.replace(/\\/g, "#");
				interfaceID_ = "##?#" + interfaceID_ +
					"#{cac88484-7515-4c03-82e6-71a87abac361}";
				var linked;
				if (registryDevInterfaces.hasChild(interfaceID_ + "\\#\\Control")) {
					reg = registryDevInterfaces.openChild(interfaceID_ + "\\#\\Control",
						registry.ACCESS_READ);
					if (reg.hasValue("Linked")) {
						linked = reg.readIntValue("Linked");
					}
					reg.close();
				}
				if (linked === 1) {
					return true;
				}
				log.debug("Interface deactivated: " + interfaceID);
				return false;
			});
			if (interfacesOnline.length === 0) {
				interfacesOnline = interfaces;
			}

			// get NameServer and DhcpNameServer of all interfaces
			registryInterfaces = registry.openChild(
				"Services\\Tcpip\\Parameters\\Interfaces",
				registry.ACCESS_READ);
			var ns = "";
			for (var i = 0; i < interfacesOnline.length; i++) {
				reg = registryInterfaces.openChild(interfaces[i], registry.ACCESS_READ);
				if (reg.hasValue("NameServer")) {
					ns += " " + reg.readStringValue("NameServer");
				}
				if (reg.hasValue("DhcpNameServer")) {
					ns += " " + reg.readStringValue("DhcpNameServer");
				}
				reg.close();
			}

			if (ns !== "") {
				var servers = ns.split(/ |,/);
				servers.forEach(function (element /*, index, array*/) {
					if (element !== "") {
						OS_DNS_ROOT_NAME_SERVERS.push({
							server: element.trim(),
							alive: true
						});
					}
				});
				log.info("Got servers from Windows registry: ", OS_DNS_ROOT_NAME_SERVERS);
			}
		} catch (e) {
			log.error("Error reading Registry: " + e + "\n" + e.stack);
		} finally {
			// @ts-ignore
			if (registry) {
				registry.close();
			}
			if (registryLinkage) {
				registryLinkage.close();
			}
			if (registryInterfaces) {
				registryInterfaces.close();
			}
			if (reg) {
				reg.close();
			}
		}
	} else {
		// Try getting a nameserver from /etc/resolv.conf.
		/** @type {nsIFileInputStream} */
		var stream_filestream;
		try {
			var resolvconf = Components.classes["@mozilla.org/file/local;1"].createInstance(Components.interfaces.nsIFile);
			resolvconf.initWithPath("/etc/resolv.conf");

			var stream = Components.classes["@mozilla.org/network/file-input-stream;1"].createInstance();
			stream_filestream = stream.QueryInterface(Components.interfaces.nsIFileInputStream);
			stream_filestream.init(resolvconf, 0, 0, 0); // don't know what the flags are...

			var stream_reader = stream.QueryInterface(Components.interfaces.nsILineInputStream);

			var out_line = { value: "" };
			var hasmore = false;
			do {
				hasmore = stream_reader.readLine(out_line);
				if (DNS_StartsWith(out_line.value, "nameserver ")) {
					OS_DNS_ROOT_NAME_SERVERS.push({
						server: out_line.value.substring("nameserver ".length).trim(),
						alive: true
					});
				}
			} while (hasmore);

			stream_filestream.close();

			log.info("Got servers from resolv.conf: ", OS_DNS_ROOT_NAME_SERVERS);
		} catch (e) {
			log.error("Error reading resolv.conf: " + e + "\n" + e.stack);

			// @ts-ignore
			if (stream_filestream) {
				stream_filestream.close();
			}
		}
	}
	return OS_DNS_ROOT_NAME_SERVERS;
}

/**
 * @template T
 * @callback QueryDnsCallback
 * @param {any[]|null} results
 * @param {T} callbackdata
 * @param {string|string[]} [queryError]
 * @param {number} [rcode]
 * @return {void}
 */

/**
 * Query a DNS server.
 * This is the main entry point for external callers.
 *
 * @param {string} host
 * @param {string} recordtype
 * @template T
 * @param {QueryDnsCallback<T>} callback
 * @param {T} callbackdata
 * @returns {void}
 */
function queryDNS(host, recordtype, callback, callbackdata) {
	"use strict";

	queryDNSRecursive(null, host, recordtype, callback, callbackdata, 0, DNS_ROOT_NAME_SERVERS);
}

/**
 * @param {string|null} server
 * @param {string} host
 * @param {string} recordtype
 * @template T
 * @param {QueryDnsCallback<T>} callback
 * @param {T} callbackdata
 * @param {number} hops
 * @param {DnsServer[]} [servers]
 * @returns {void}
 */
function queryDNSRecursive(server, host, recordtype, callback, callbackdata, hops, servers) {
	"use strict";

	// if more when one server is given
	if (servers !== undefined) {
		// set server to next alive DNS server
		var i;
		/** @type {DnsServer|null} */
		var serverObj = null;
		server = null;
		for (i = 0; i < servers.length; i++) {
			if (servers[i].alive) {
				server = servers[i].server;
				serverObj = servers[i];
				break;
			}
		}

		if (server === null) {
			log.debug("no DNS Server alive");
			if (AUTO_RESET_SERVER_ALIVE) {
				servers.forEach(function (element /*, index, array*/) {
					element.alive = true;
				});
				log.debug("set all servers to alive");
			}
			callback(null, callbackdata, "no DNS Server alive");
			return;
		}
	}
	if (!server) {
		throw new Error("no server given to query from");
	}

	if (hops === 10) {
		log.debug("Maximum number of recursive steps taken in resolving " + host);
		callback(null, callbackdata, "TOO_MANY_HOPS");
		return;
	}

	log.info("Resolving " + host + " " + recordtype + " by querying " + server);

	var query =
		// HEADER
		"00" + // ID
		String.fromCharCode(1) + // QR=0, OPCODE=0, AA=0, TC=0, RD=1 (Recursion desired)
		String.fromCharCode(0) + // all zeroes
		DNS_wordToStr(1) + // 1 query
		DNS_wordToStr(0) + // ASCOUNT=0
		DNS_wordToStr(0) + // NSCOUNT=0
		DNS_wordToStr(0) // ARCOUNT=0
		;

	var hostparts = host.split(".");
	for (var hostpartidx = 0; hostpartidx < hostparts.length; hostpartidx++) {
		query += DNS_octetToStr(hostparts[hostpartidx].length) + hostparts[hostpartidx];
	}
	query += DNS_octetToStr(0);
	if (recordtype === "A") {
		query += DNS_wordToStr(1);
	} else if (recordtype === "NS") {
		query += DNS_wordToStr(2);
	} else if (recordtype === "CNAME") {
		query += DNS_wordToStr(5);
	} else if (recordtype === "PTR") {
		query += DNS_wordToStr(12);
	} else if (recordtype === "MX") {
		query += DNS_wordToStr(15);
	} else if (recordtype === "TXT") {
		query += DNS_wordToStr(16);
	} else {
		throw new Error("Invalid record type.");
	}
	query += DNS_wordToStr(1); // IN

	// Prepend query message length
	query = DNS_wordToStr(query.length) + query;

	var listener = {
		/** @type {number|null} */
		msgsize: null,
		readcount: 0,
		responseHeader: "",
		responseBody: "",
		done: false,
		/**
		 * @param {string} data
		 * @param {number} status
		 * @returns {void}
		 */
		finished: function (data, status) {
			if (!server) {
				server = "unknown";
			}
			if (status !== 0) {
				if (status === 2152398861) { // NS_ERROR_CONNECTION_REFUSED
					log.debug("Resolving " + host + "/" + recordtype + ": DNS server " + server + " refused a TCP connection.");
					if (servers === undefined) {
						callback(null, callbackdata, ["CONNECTION_REFUSED", server]);
					}
				} else if (status === 2152398868) { // NS_ERROR_NET_RESET
					log.debug("Resolving " + host + "/" + recordtype + ": DNS server " + server + " timed out on a TCP connection.");
					if (servers === undefined) {
						callback(null, callbackdata, ["TIMED_OUT", server]);
					}
				} else if (status === Components.results.NS_ERROR_NET_TIMEOUT) {
					log.debug("Resolving " + host + "/" + recordtype + ": DNS server " + server + " timed out on a TCP connection (NS_ERROR_NET_TIMEOUT).");
					if (servers === undefined) {
						callback(null, callbackdata, ["TIMED_OUT", server]);
					}
				} else {
					log.debug("Resolving " + host + "/" + recordtype + ": Failed to connect to DNS server " + server + " with error code " + status + ".");
					if (servers === undefined) {
						callback(null, callbackdata, ["SERVER_ERROR", server]);
					}
				}

				// if more when one server is given
				if (servers !== undefined) {
					// set current server to not alive
					serverObj.alive = false;

					// start query again for next server
					queryDNSRecursive(null, host, recordtype, callback, callbackdata, hops, servers);
				}
				return;
			}

			this.process(data);
			if (!this.done) {
				log.debug("Resolving " + host + "/" + recordtype + ": Response was incomplete.");
				callback(null, callbackdata, ["INCOMPLETE_RESPONSE", server]);
			}
		},
		/**
		 * @param {string} data
		 * @returns {boolean}
		 */
		process: function (data) {
			if (this.done) {
				return false;
			}

			this.readcount += data.length;

			while (this.responseHeader.length < 14 && data.length > 0) {
				this.responseHeader += data.charAt(0);
				data = data.substr(1);
			}
			if (this.responseHeader.length === 14) {
				this.msgsize = DNS_strToWord(this.responseHeader.substr(0, 2));
				this.responseBody += data;

				//DNS_Debug("DNS: Received Reply: " + (this.readcount-2) + " of " + this.msgsize + " bytes");

				if (this.readcount >= this.msgsize + 2) {
					this.responseHeader = this.responseHeader.substr(2); // chop the length field
					this.done = true;
					DNS_getRDData(this.responseHeader + this.responseBody, server, host, recordtype, callback, callbackdata, hops);
					return false;
				}
			}
			return true;
		}
	};

	// allow server to be either a hostname or hostname:port
	var server_hostname = server;
	var port = 53;
	if (server.indexOf(':') !== -1) {
		server_hostname = server.substring(0, server.indexOf(':'));
		port = parseInt(server.substring(server.indexOf(':') + 1), 10);
	}

	var ex = DNS_readAllFromSocket(server_hostname, port, query, listener);
	if (ex !== null) {
		log.error(`${ex}\n${ex.stack}`);
	}
}

/**
 * @param {{str: string, idx: number}} ctx
 * @returns {string}
 */
function DNS_readDomain(ctx) {
	"use strict";

	var domainname = "";
	var ctr = 20;
	while (ctr-- > 0) {
		var l = ctx.str.charCodeAt(ctx.idx++);
		if (l === 0) {
			break;
		}

		if (domainname !== "") {
			domainname += ".";
		}

		if ((l >> 6) === 3) {
			// Pointer
			var ptr = ((l & 63) << 8) + ctx.str.charCodeAt(ctx.idx++);
			var ctx2 = { str: ctx.str, idx: ptr };
			domainname += DNS_readDomain(ctx2);
			break;
		} else {
			domainname += ctx.str.substr(ctx.idx, l);
			ctx.idx += l;
		}
	}
	return domainname;
}

/**
 * @typedef {Object} DnsRecord
 * @property {string} dom
 * @property {string|number} type
 * @property {number} cls
 * @property {number} ttl
 * @property {number} rdlen
 * @property {number} recognized
 * @property {string|{preference: number, host: string}} rddata
 */

/**
 * @param {{str: string, idx: number}} ctx
 * @returns {DnsRecord}
 */
function DNS_readRec(ctx) {
	"use strict";

	/** @type {DnsRecord} */
	var rec = {};
	var ctr;
	var txtlen;

	rec.dom = DNS_readDomain(ctx);
	rec.type = DNS_strToWord(ctx.str.substr(ctx.idx, 2)); ctx.idx += 2;
	rec.cls = DNS_strToWord(ctx.str.substr(ctx.idx, 2)); ctx.idx += 2;
	rec.ttl = DNS_strToWord(ctx.str.substr(ctx.idx, 2)); ctx.idx += 4; // 32bit
	rec.rdlen = DNS_strToWord(ctx.str.substr(ctx.idx, 2)); ctx.idx += 2;
	rec.recognized = 1;

	var ctxnextidx = ctx.idx + rec.rdlen;

	if (rec.type === 16) {
		rec.type = "TXT";
		rec.rddata = "";
		ctr = 1000;
		while (rec.rdlen > 0 && ctr-- > 0) {
			txtlen = DNS_strToOctet(ctx.str.substr(ctx.idx, 1)); ctx.idx++; rec.rdlen--;
			rec.rddata += ctx.str.substr(ctx.idx, txtlen); ctx.idx += txtlen; rec.rdlen -= txtlen;
		}
		if (ctr < 0) {
			log.error("TXT record exceeds configured max read length");
		}
	} else if (rec.type === 1) {
		// Return as a dotted-quad
		rec.type = "A";
		rec.rddata = ctx.str.substr(ctx.idx, rec.rdlen);
		rec.rddata = rec.rddata.charCodeAt(0) + "." + rec.rddata.charCodeAt(1) + "." + rec.rddata.charCodeAt(2) + "." + rec.rddata.charCodeAt(3);
	} else if (rec.type === 15) {
		rec.type = "MX";
		rec.rddata = {};
		rec.rddata.preference = DNS_strToWord(ctx.str.substr(ctx.idx, 2)); ctx.idx += 2;
		rec.rddata.host = DNS_readDomain(ctx);
	} else if (rec.type === 2) {
		rec.type = "NS";
		rec.rddata = DNS_readDomain(ctx);
	} else if (rec.type === 12) {
		rec.type = "PTR";
		rec.rddata = DNS_readDomain(ctx);
	} else if (rec.type === 5) {
		rec.type = "CNAME";
		// no complete support of CNAME (data is not read)
		rec.rddata = "";
	} else {
		rec.recognized = 0;
	}

	ctx.idx = ctxnextidx;

	return rec;
}

/**
 * @param {string} str
 * @param {string} server
 * @param {string} host
 * @param {string} recordtype
 * @template T
 * @param {QueryDnsCallback<T>} callback
 * @param {T} callbackdata
 * @param {number} hops
 * @returns {void}
 */
function DNS_getRDData(str, server, host, recordtype, callback, callbackdata, hops) {
	"use strict";

	const debugstr = `${host}/${recordtype}: `;

	var flags = DNS_strToWord(str.substr(2, 2));
	var qcount = DNS_strToWord(str.substr(4, 2));
	var ancount = DNS_strToWord(str.substr(6, 2));
	var aucount = DNS_strToWord(str.substr(8, 2));
	var adcount = DNS_strToWord(str.substr(10, 2));

	var rcode = flags & 0xF;
	if (rcode !== 0) {
		log.debug(debugstr + "Lookup failed with rcode " + rcode);
		callback(null, callbackdata, "Lookup failed with rcode " + rcode, rcode);
		return;
	}

	var ctx = { str: str, idx: 12 };

	var i;
	var j;

	if (qcount !== 1) {
		throw new Error("Invalid response: Question section didn't have exactly one record.");
	}
	if (ancount > 128) {
		throw new Error("Invalid response: Answer section had more than 128 records.");
	}
	if (aucount > 128) {
		throw new Error("Invalid response: Authority section had more than 128 records.");
	}
	if (adcount > 128) {
		throw new Error("Invalid response: Additional section had more than 128 records.");
	}

	for (i = 0; i < qcount; i++) {
		// eslint-disable-next-line no-unused-vars
		const dom = DNS_readDomain(ctx);
		// eslint-disable-next-line no-unused-vars
		const type = DNS_strToWord(str.substr(ctx.idx, 2)); ctx.idx += 2;
		// eslint-disable-next-line no-unused-vars
		const cls = DNS_strToWord(str.substr(ctx.idx, 2)); ctx.idx += 2;
	}

	var results = [];
	for (i = 0; i < ancount; i++) {
		const rec = DNS_readRec(ctx);
		if (!rec.recognized) {
			throw new Error("Record type is not one that this library can understand.");
		}
		// ignore CNAME records
		if (rec.type !== "CNAME") {
			results.push(rec.rddata);
		} else {
			log.debug(debugstr + "CNAME ignored :" + rec.rddata);
		}
		log.debug(debugstr + "Answer: " + rec.rddata);
	}

	/** @type {DnsRecord[]} */
	var authorities = Array(aucount);
	for (i = 0; i < aucount; i++) {
		const rec = DNS_readRec(ctx);
		authorities[i] = rec;
		if (rec.recognized) {
			log.debug(debugstr + "Authority: " + rec.type + " " + rec.rddata);
		}
		// Assuming the domain for this record is the domain we are asking about.
	}

	for (i = 0; i < adcount; i++) {
		const rec = DNS_readRec(ctx);
		if (rec.recognized) {
			log.debug(debugstr + "Additional: " + rec.dom + " " + rec.type + " " + rec.rddata);
		}
		if (rec.type === "A") {
			for (j = 0; j < results.length; j++) {
				if (results[j].host && results[j].host === rec.dom) {
					if (results[j].address === null) {
						results[j].address = Array(0);
					}
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
		for (i = 0; i < aucount; i++) {
			if (authorities[i].type === "NS" && authorities[i].rddata !== server) {
				log.debug(debugstr + "Recursing on Authority: " + authorities[i].rddata);
				queryDNSRecursive(authorities[i].rddata, host, recordtype, callback, callbackdata, hops + 1);
				return;
			}
		}

		// No authority was able to help us.
		log.debug(debugstr + "No answer, no authority to recurse on.  DNS lookup failed.");
		callback(null, callbackdata);
	}
}

/**
 * @param {string} str
 * @returns {number}
 */
function DNS_strToWord(str) {
	"use strict";

	var res = str.charCodeAt(1) + (str.charCodeAt(0) << 8);
	return res;
}

/**
 * @param {string} str
 * @returns {number}
 */
function DNS_strToOctet(str) {
	"use strict";

	return str.charCodeAt(0);
}

/**
 * @param {number} word
 * @returns {string}
 */
function DNS_wordToStr(word) {
	"use strict";

	var res = DNS_octetToStr((word >> 8) % 256) + DNS_octetToStr(word % 256);
	return res;
}

/**
 * @param {number} octet
 * @returns {string}
 */
function DNS_octetToStr(octet) {
	"use strict";

	return String.fromCharCode(octet);
}

/**
 * This comes from http://xulplanet.com/tutorials/mozsdk/sockets.php
 *
 * @param {string} host
 * @param {number} port
 * @param {string} outputData
 * @param {{finished: function(string, number): void, process: function(string): boolean}} listener
 * @returns {Error|null}
 */
function DNS_readAllFromSocket(host, port, outputData, listener) {
	"use strict";

	try {
		var proxy = null;
		if (PROXY_CONFIG.enable) {
			var pps = Cc["@mozilla.org/network/protocol-proxy-service;1"].
				getService(Ci.nsIProtocolProxyService);
			proxy = pps.newProxyInfo(
				PROXY_CONFIG.type,
				PROXY_CONFIG.host,
				PROXY_CONFIG.port,
				"", "", 0, 0xffffffff, null
			);
		}

		var transportService =
			Cc["@mozilla.org/network/socket-transport-service;1"].
				getService(Ci.nsISocketTransportService);
		const transport = transportService.createTransport([], host, port, proxy);

		// change timeout for connection
		transport.setTimeout(transport.TIMEOUT_CONNECT, timeout_connect);
		if (timeout_read_write) {
			transport.setTimeout(transport.TIMEOUT_READ_WRITE, timeout_read_write);
		}

		var outstream = transport.openOutputStream(0, 0, 0);
		outstream.write(outputData, outputData.length);

		var stream = transport.openInputStream(0, 0, 0);
		var instream = Components.classes["@mozilla.org/binaryinputstream;1"].
			createInstance(Components.interfaces.nsIBinaryInputStream);
		instream.setInputStream(stream);

		/** @type {nsIStreamListener & {data: string}} */
		var dataListener = {
			data: "",
			// eslint-disable-next-line no-empty-function
			onStartRequest: function (/* request, context */) { },
			onStopRequest: function (request, status) {
				if (listener.finished !== null) {
					listener.finished(this.data, status);
				}
				outstream.close();
				stream.close();
				//DNS_Debug("DNS: Connection closed (" + host + ")");
			},
			onDataAvailable: function (request, inputStream, offset, count) {
				//DNS_Debug("DNS: Got data (" + host + ")");
				for (var i = 0; i < count; i++) {
					this.data += String.fromCharCode(instream.read8());
				}
				if (listener.process !== null) {
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
		pump.init(stream, 0, 0, false);
		pump.asyncRead(dataListener, null);
	} catch (ex) {
		return ex;
	}
	return null;
}

/**
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function DNS_StartsWith(a, b) {
	"use strict";

	if (b.length > a.length) {
		return false;
	}
	return a.substring(0, b.length) === b;
}

JSDNS.configureDNS = configureDNS;
JSDNS.queryDNS = queryDNS;
