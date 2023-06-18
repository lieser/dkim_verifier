/*
 * JSDNS.jsm
 *
 * Based on Joshua Tauberer's DNS LIBRARY IN JAVASCRIPT
 * from "Sender Verification Extension" version 0.9.0.6
 *
 * Copyright (c) 2013-2023 Philippe Lieser
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

//@ts-check
///<reference path="./mozilla.d.ts" />
// options for ESLint
/* eslint-disable prefer-template */
/* eslint-disable no-use-before-define */
/* eslint-disable camelcase */
/* eslint-disable no-var */
/* eslint strict: ["warn", "function"] */
/* eslint complexity: "off" */
/* eslint no-magic-numbers: "off" */
/* eslint mozilla/mark-exported-symbols-as-used: "error" */


var EXPORTED_SYMBOLS = [
	"JSDNS"
];


// @ts-expect-error
var { Services } = ChromeUtils.import("resource://gre/modules/Services.jsm");


const LOG_NAME = "DKIM_Verifier.JSDNS";


var JSDNS = {};

/** @type {ChromeConsole} */
// @ts-expect-error
const chromeConsole = console;
var log = chromeConsole.createInstance({
	prefix: LOG_NAME,
	maxLogLevel: "Warn",
});


/**
 * @typedef {object} DnsServer
 * @property {string} server IP of server as string.
 * @property {boolean} alive Whether the server is alive.
 */

/**
 * Preferences that are set from outside.
 */
const prefs = {
	getServerFromOS: false,
	additionalNameServer: "",

	autoResetServerToAlive: true,

	timeoutConnect: 0xFFFF,
	/** @type {number|null} */
	timeoutReadWrite: null,

	proxy: {
		enable: false,
		type: "",
		host: "",
		port: 0
	},
};

/**
 * The current DNS servers to use.
 *
 * @type {DnsServer[]}
 */
var DNS_ROOT_NAME_SERVERS = [];

/**
 * Set preferences to use.
 *
 * @param {boolean} getNameserversFromOS
 * @param {string} nameServer
 * @param {number} timeoutConnect
 * @param {{ enable: boolean, type: string, host: string, port: number }} proxy
 * @param {boolean} autoResetServerAlive
 * @param {boolean} debug
 * @returns {void}
 */
function configureDNS(getNameserversFromOS, nameServer, timeoutConnect, proxy, autoResetServerAlive, debug) {
	"use strict";

	/** @type {Parameters<typeof chromeConsole.createInstance>[0]["maxLogLevel"]} */
	let maxLogLevel = "Warn";
	if (debug) {
		maxLogLevel = "All";
	}
	log = chromeConsole.createInstance({
		prefix: LOG_NAME,
		maxLogLevel,
	});

	updateDnsServers(getNameserversFromOS, nameServer);

	prefs.getServerFromOS = getNameserversFromOS;
	prefs.additionalNameServer = nameServer;
	prefs.timeoutConnect = timeoutConnect;
	prefs.timeoutReadWrite = timeoutConnect;
	prefs.proxy = proxy;
	prefs.autoResetServerToAlive = autoResetServerAlive;
}

/**
 * Update the DNS server to use.
 *
 * @param {boolean} getNameserversFromOS
 * @param {string} nameServer
 * @returns {void}
 */
function updateDnsServers(getNameserversFromOS, nameServer) {
	"use strict";

	/** @type {DnsServer[]} */
	const prefDnsRootNameServers = [];
	nameServer.split(";").forEach((element /*, index, array*/) => {
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
			(e) => e.server
		);
	} else {
		DNS_ROOT_NAME_SERVERS = prefDnsRootNameServers;
	}

	log.info("Changed DNS Servers to:", DNS_ROOT_NAME_SERVERS);
}

/**
 * Remove Duplicates from an Array.
 *
 * From http://stackoverflow.com/questions/9229645/remove-duplicates-from-javascript-array/9229821#9229821.
 *
 * @template T
 * @param {T[]} ary
 * @param {function(T): string} key - Function to generate key from element
 * @returns {T[]}
 */
function arrayUniqBy(ary, key) {
	"use strict";

	/** @type {{[x: string]: number}} */
	var seen = {};
	return ary.filter((elem) => {
		var k = key(elem);
		if (seen[k] === 1) {
			return false;
		}
		seen[k] = 1;
		return true;
	});
}

/**
 * Get DNS Servers from OS configuration.
 *
 * @returns {DnsServer[]}
 */
function getOsDnsServers() {
	"use strict";

	/** @type {DnsServer[]} */
	const OS_DNS_ROOT_NAME_SERVERS = [];

	if ("@mozilla.org/windows-registry-key;1" in Cc) {
		// Firefox 1.5 or newer on Windows
		// Try getting a nameserver from the windows registry
		var reg;
		/** @type {nsIWindowsRegKey} */
		var registry;
		var registryLinkage;
		var registryInterfaces;
		try {
			var registry_class = Cc["@mozilla.org/windows-registry-key;1"];
			if (!registry_class) {
				throw new Error("Could not get windows-registry-key class");
			}
			var registry_object = registry_class.createInstance();
			registry = registry_object.QueryInterface(Ci.nsIWindowsRegKey);

			registry.open(registry.ROOT_KEY_LOCAL_MACHINE,
				"SYSTEM\\CurrentControlSet",
				registry.ACCESS_QUERY_VALUE);

			// get interfaces in routing order
			registryLinkage = registry.openChild("Services\\Tcpip\\Linkage",
				registry.ACCESS_READ);
			// nsIWindowsRegKey doesn't support REG_MULTI_SZ type out of the box
			// from http://mxr.mozilla.org/comm-central/source/mozilla/browser/components/migration/src/IEProfileMigrator.js#129
			// slice(1,-1) to remove the " at the beginning and end
			const linkageRoute = registryLinkage.readStringValue("Route");
			const interfaceGUIDs = linkageRoute.split("\0").
				map((e) => e.slice(1, -1)).
				filter((e) => e);

			// Get Name and PnpInstanceID of interfaces
			const registryNetworkAdapters = registry.openChild(
				"Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}",
				registry.ACCESS_QUERY_VALUE);
			let interfaces = interfaceGUIDs.map(interfaceGUID => {
				reg = registryNetworkAdapters.openChild(interfaceGUID + "\\Connection",
					registry.ACCESS_READ);
				let Name = null;
				if (reg.hasValue("Name")) {
					Name = reg.readStringValue("Name");
				}
				let PnpInstanceID = null;
				if (reg.hasValue("PnpInstanceID")) {
					PnpInstanceID = reg.readStringValue("PnpInstanceID");
				}
				reg.close();
				return {
					guid: interfaceGUID,
					Name,
					PnpInstanceID,
				};
			});
			registryNetworkAdapters.close();
			log.debug("Found interfaces: ", interfaces);

			// Filter out interfaces without PnpInstanceID
			interfaces = interfaces.filter(element => element.PnpInstanceID);

			// get NameServer and DhcpNameServer of all interfaces
			registryInterfaces = registry.openChild(
				"Services\\Tcpip\\Parameters\\Interfaces",
				registry.ACCESS_READ);
			var ns = "";
			for (const intf of interfaces) {
				reg = registryInterfaces.openChild(intf.guid, registry.ACCESS_READ);
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
				servers.forEach((element /*, index, array*/) => {
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
			// @ts-expect-error
			log.error("Error reading Registry: " + e + "\n" + e.stack);
		} finally {
			// @ts-expect-error
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
			var resolvconf = Cc["@mozilla.org/file/local;1"]?.createInstance(Ci.nsIFile);
			if (!resolvconf) {
				throw new Error("Could not create nsIFile instance");
			}
			resolvconf.initWithPath("/etc/resolv.conf");

			var stream = Cc["@mozilla.org/network/file-input-stream;1"]?.createInstance();
			if (!stream) {
				throw new Error("Could not create file-input-stream instance");
			}
			stream_filestream = stream.QueryInterface(Ci.nsIFileInputStream);
			stream_filestream.init(resolvconf, 0, 0, 0); // don't know what the flags are...

			var stream_reader = stream.QueryInterface(Ci.nsILineInputStream);

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
			// @ts-expect-error
			log.error("Error reading resolv.conf: " + e + "\n" + e.stack);

			// @ts-expect-error
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
 * @returns {void}
 */

/**
 * Query a DNS server.
 * This is the main entry point for external callers.
 *
 * @param {string} host
 * @param {string} recordtype
 * @returns {Promise<{results?: any[]|null, queryError?: string|string[], rcode?: number}>}
 */
async function queryDNS(host, recordtype) {
	"use strict";

	DNS_ROOT_NAME_SERVERS = DNS_ROOT_NAME_SERVERS.filter(server => server.alive);
	if (DNS_ROOT_NAME_SERVERS.length === 0) {
		log.debug("No DNS Server alive.");
		if (prefs.autoResetServerToAlive) {
			updateDnsServers(prefs.getServerFromOS, prefs.additionalNameServer);
		}
	}

	for (const server of DNS_ROOT_NAME_SERVERS) {
		const res = await querySingleDNSRecursive(server.server, host, recordtype, 0);
		if (res.queryError) {
			// Set current server to not alive and query next server.
			server.alive = false;
			continue;
		}
		return res;
	}

	return {
		queryError: "no DNS Server alive",
	};
}

/**
 * @param {string} server
 * @param {string} host
 * @param {string} recordtype
 * @param {number} hops
 * @returns {Promise<{results?: any[]|null, queryError?: string|string[], rcode?: number}>}
 */
async function querySingleDNSRecursive(server, host, recordtype, hops) {
	"use strict";

	if (hops === 10) {
		log.debug("Maximum number of recursive steps taken in resolving " + host);
		return {
			queryError: "TOO_MANY_HOPS",
		};
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
	for (const hostpart of hostparts) {
		query += DNS_octetToStr(hostpart.length) + hostpart;
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
		 * Check the error state if no DNS reply is received before the stream is closed.
		 *
		 * @param {number} status
		 * @returns {{queryError?: string|string[]}}
		 */
		checkErrorState(status) {
			if (status !== 0) {
				if (status === 2152398861) { // NS_ERROR_CONNECTION_REFUSED
					log.debug("Resolving " + host + "/" + recordtype + ": DNS server " + server + " refused a TCP connection.");
					return {
						queryError: ["CONNECTION_REFUSED", server],
					};
				} else if (status === 2152398868) { // NS_ERROR_NET_RESET
					log.debug("Resolving " + host + "/" + recordtype + ": DNS server " + server + " timed out on a TCP connection.");
					return {
						queryError: ["TIMED_OUT", server],
					};
				} else if (status === Cr.NS_ERROR_NET_TIMEOUT) {
					log.debug("Resolving " + host + "/" + recordtype + ": DNS server " + server + " timed out on a TCP connection (NS_ERROR_NET_TIMEOUT).");
					return {
						queryError: ["TIMED_OUT", server],
					};
				}
				log.debug("Resolving " + host + "/" + recordtype + ": Failed to connect to DNS server " + server + " with error code " + status + ".");
				return {
					queryError: ["SERVER_ERROR", server],
				};
			}

			if (!this.done) {
				log.debug("Resolving " + host + "/" + recordtype + ": Response was incomplete.");
				return {
					queryError: ["INCOMPLETE_RESPONSE", server],
				};
			}
			throw new Error("Process was done but finished called. This should never happen.");
		},
		/**
		 * Process the incoming data.
		 *
		 * Will return the DNS result if the reply is completely read.
		 * Will return null if the reply is still incomplete.
		 *
		 * @param {string} data
		 * @returns {Promise<{results?: any[]|null, rcode?: number}|null>}
		 */
		process(data) {
			if (this.done) {
				throw new Error("Process called after it was already done.");
			}

			this.readcount += data.length;

			let remainingData = data;
			while (this.responseHeader.length < 14 && remainingData.length) {
				this.responseHeader += remainingData.charAt(0);
				remainingData = remainingData.substr(1);
			}
			if (this.responseHeader.length === 14) {
				this.msgsize = DNS_strToWord(this.responseHeader.substr(0, 2));
				this.responseBody += remainingData;

				//DNS_Debug("DNS: Received Reply: " + (this.readcount-2) + " of " + this.msgsize + " bytes");

				if (this.readcount >= this.msgsize + 2) {
					this.responseHeader = this.responseHeader.substr(2); // chop the length field
					this.done = true;
					return DNS_getRDData(this.responseHeader + this.responseBody, server, host, recordtype, hops);
				}
			}
			return Promise.resolve(null);
		}
	};

	// allow server to be either a hostname or hostname:port
	// Note: Port is not supported for IPv6 addresses.
	var server_hostname = server;
	var port = 53;
	if ((server.match(/:/g) ?? []).length === 1) {
		server_hostname = server.substring(0, server.indexOf(":"));
		port = parseInt(server.substring(server.indexOf(":") + 1), 10);
	}

	const socket = new Socket(server_hostname, port);
	socket.write(query);
	for await (const data of socket.read()) {
		const res = await listener.process(data);
		if (res) {
			socket.close();
			return res;
		}
	}
	socket.close();
	return listener.checkErrorState(socket.status ?? -1);
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
 * @typedef {object} DnsRecord
 * @property {string} dom
 * @property {string|number} type
 * @property {number} cls
 * @property {number} ttl
 * @property {number} rdlen
 * @property {number} recognized
 * @property {string|{preference: number, host: string, address?: DnsRecord["rddata"][]}} rddata
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
		const preference = DNS_strToWord(ctx.str.substr(ctx.idx, 2)); ctx.idx += 2;
		const host = DNS_readDomain(ctx);
		rec.rddata = {
			preference,
			host,
		};
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
 * Parse the RD data and return the results if available.
 *
 * If no results are included but a NS authority is returned,
 * will recurs on the NS authority.
 *
 * @param {string} str
 * @param {string} server
 * @param {string} host
 * @param {string} recordtype
 * @param {number} hops
 * @returns {Promise<{results?: any[]|null, rcode?: number}>}
 */
async function DNS_getRDData(str, server, host, recordtype, hops) {
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
		return {
			rcode,
		};
	}

	var ctx = { str, idx: 12 };

	var i;

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
		// @ts-expect-error
		// eslint-disable-next-line no-unused-vars
		const dom = DNS_readDomain(ctx);
		// @ts-expect-error
		// eslint-disable-next-line no-unused-vars
		const type = DNS_strToWord(str.substr(ctx.idx, 2)); ctx.idx += 2;
		// @ts-expect-error
		// eslint-disable-next-line no-unused-vars
		const cls = DNS_strToWord(str.substr(ctx.idx, 2)); ctx.idx += 2;
	}

	/** type {(DnsRecord["rddata"]&{address: DnsRecord|undefined})[]} */
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
			for (const result of results) {
				if (typeof result === "object" && result.host && result.host === rec.dom) {
					if (result.address === undefined) {
						result.address = Array(0);
					}
					result.address[result.address.length] = rec.rddata;
				}
			}
		}
	}

	if (results.length) {
		// We have an answer.
		return {
			results,
		};
	}

	// No answer. If there is an NS authority, recurse.
	// Note that we can do without the IP address of the NS authority (given in the additional
	// section) because we're able to do DNS lookups without knowing the IP address
	// of the DNS server -- Thunderbird and the OS take care of that.
	for (const authority of authorities) {
		if (authority.type === "NS" && authority.rddata !== server) {
			log.debug(debugstr + "Recursing on Authority: " + authority.rddata);
			// @ts-expect-error
			const res = await querySingleDNSRecursive(authority.rddata, host, recordtype, hops + 1);
			if (res.results) {
				return res;
			}
			// We only try one NS authority, and ignore any errors for the query.
			return {
				results: null,
			};
		}
	}

	// No authority was able to help us.
	log.debug(debugstr + "No answer, no authority to recurse on. DNS lookup failed.");
	return {
		results: null,
	};
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

class Socket {
	/**
	 * Status of the socket.
	 *
	 * - null: Socket is still open.
	 * - 0: Socket is closed and all data read.
	 * - number: Socket failed with error number.
	 *
	 * @type {number|null}
	 */
	status = null;

	#outStream;
	#inStream;

	/**
	 * Open a socket.
	 *
	 * @param {string} host
	 * @param {number} port
	 */
	constructor(host, port) {
		let proxy = null;
		if (prefs.proxy.enable) {
			const pps = Cc["@mozilla.org/network/protocol-proxy-service;1"]?.
				getService(Ci.nsIProtocolProxyService);
			if (!pps) {
				throw new Error("Could not get protocol-proxy-service service");
			}
			proxy = pps.newProxyInfo(
				prefs.proxy.type,
				prefs.proxy.host,
				prefs.proxy.port,
				"", "", 0, 0xffffffff, null
			);
		}

		const transportService =
			Cc["@mozilla.org/network/socket-transport-service;1"]?.
				getService(Ci.nsISocketTransportService);
		if (!transportService) {
			throw new Error("Could not get socket-transport-service service");
		}
		const transport = transportService.createTransport([], host, port, proxy, null);

		// change timeout for connection
		transport.setTimeout(transport.TIMEOUT_CONNECT, prefs.timeoutConnect);
		if (prefs.timeoutReadWrite) {
			transport.setTimeout(transport.TIMEOUT_READ_WRITE, prefs.timeoutReadWrite);
		}

		// Open output and input streams.
		this.#outStream = transport.openOutputStream(0, 0, 0);
		this.#inStream = transport.openInputStream(0, 0, 0).
			QueryInterface(Ci.nsIAsyncInputStream);
	}

	/**
	 * Synchronously write data to the socket.
	 *
	 * @param {string} data
	 * @returns {number}
	 */
	write(data) {
		return this.#outStream.write(data, data.length);
	}

	/**
	 * Asynchronously read data from the socket.
	 *
	 * @yields
	 * @returns {AsyncGenerator<string, void, void>}
	 */
	async * read() {
		const binaryInputStream = Cc["@mozilla.org/binaryinputstream;1"]?.
			createInstance(Ci.nsIBinaryInputStream);
		if (!binaryInputStream) {
			throw new Error("Could not create binaryinputstream instance");
		}
		binaryInputStream.setInputStream(this.#inStream);

		while (true) {
			// Wait for the stream to be readable or closed.
			// eslint-disable-next-line no-extra-parens
			await /** @type {Promise<void>} */ (new Promise(resolve => {
				this.#inStream.asyncWait({
					QueryInterface: ChromeUtils.generateQI([
						Ci.nsIInputStreamCallback]),
					onInputStreamReady() {
						resolve();
					}
				}, 0, 0, Services.tm.mainThreadEventTarget);
			}));

			// Get number of bytes available in the stream.
			let count;
			try {
				count = binaryInputStream.available();
			} catch (error) {
				// @ts-expect-error
				if (!("result" in error)) {
					log.warn("available() failed with unexpected exception", error);
					this.status = Cr.NS_ERROR_FAILURE ?? -1;
				} else if (error.result === Cr.NS_BASE_STREAM_CLOSED) {
					this.status = 0;
				} else {
					// @ts-expect-error
					this.status = error.result;
				}
				return;
			}
			if (count === 0) {
				log.debug("asyncWait was triggered but no data available");
				continue;
			}

			// Read the data from the stream.
			let data = "";
			for (var i = 0; i < count; i++) {
				data += String.fromCharCode(binaryInputStream.read8());
			}

			yield data;
		}
	}

	/**
	 * Close the socket.
	 */
	close() {
		this.#outStream.close();
		this.#inStream.close();
	}
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
