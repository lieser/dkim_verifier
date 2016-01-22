/*
 * libunbound.jsm
 * 
 * Wrapper for the libunbound DNS library. The actual work is done in the
 * ChromeWorker libunboundWorker.jsm.
 *
 * Version: 2.0.0pre1 (22 January 2016)
 * 
 * Copyright (c) 2013-2016 Philippe Lieser
 * 
 * This software is licensed under the terms of the MIT License.
 * 
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// options for JSHint
/* jshint strict:true, moz:true */
/* jshint unused:true */ // allow unused parameters that are followed by a used parameter.
/* global Components, OS, Services, ChromeWorker */
/* global ModuleGetter, Logging, exceptionToStr */
/* exported EXPORTED_SYMBOLS, libunbound */

const module_version = "2.0.0";

var EXPORTED_SYMBOLS = [
	"libunbound"
];

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cu = Components.utils;

Cu.import("resource://gre/modules/Services.jsm");

Cu.import("resource://dkim_verifier/ModuleGetter.jsm");
ModuleGetter.getosfile(this);
ModuleGetter.getPromise(this);

Cu.import("resource://dkim_verifier/logging.jsm");
Cu.import("resource://dkim_verifier/helper.jsm");


const PREF_BRANCH = "extensions.dkim_verifier.dns.";


/**
 * @public
 */
var Constants = {
	RR_TYPE_A: 1,
	RR_TYPE_A6: 38,
	RR_TYPE_AAAA: 28,
	RR_TYPE_AFSDB: 18,
	RR_TYPE_ANY: 255,
	RR_TYPE_APL: 42,
	RR_TYPE_ATMA: 34,
	RR_TYPE_AXFR: 252,
	RR_TYPE_CERT: 37,
	RR_TYPE_CNAME: 5,
	RR_TYPE_DHCID: 49,
	RR_TYPE_DLV: 32769,
	RR_TYPE_DNAME: 39,
	RR_TYPE_DNSKEY: 48,
	RR_TYPE_DS: 43,
	RR_TYPE_EID: 31,
	RR_TYPE_GID: 102,
	RR_TYPE_GPOS: 27,
	RR_TYPE_HINFO: 13,
	RR_TYPE_IPSECKEY: 45,
	RR_TYPE_ISDN: 20,
	RR_TYPE_IXFR: 251,
	RR_TYPE_KEY: 25,
	RR_TYPE_KX: 36,
	RR_TYPE_LOC: 29,
	RR_TYPE_MAILA: 254,
	RR_TYPE_MAILB: 253,
	RR_TYPE_MB: 7,
	RR_TYPE_MD: 3,
	RR_TYPE_MF: 4,
	RR_TYPE_MG: 8,
	RR_TYPE_MINFO: 14,
	RR_TYPE_MR: 9,
	RR_TYPE_MX: 15,
	RR_TYPE_NAPTR: 35,
	RR_TYPE_NIMLOC: 32,
	RR_TYPE_NS: 2,
	RR_TYPE_NSAP: 22,
	RR_TYPE_NSAP_PTR: 23,
	RR_TYPE_NSEC: 47,
	RR_TYPE_NSEC3: 50,
	RR_TYPE_NSEC3PARAMS: 51,
	RR_TYPE_NULL: 10,
	RR_TYPE_NXT: 30,
	RR_TYPE_OPT: 41,
	RR_TYPE_PTR: 12,
	RR_TYPE_PX: 26,
	RR_TYPE_RP: 17,
	RR_TYPE_RRSIG: 46,
	RR_TYPE_RT: 21,
	RR_TYPE_SIG: 24,
	RR_TYPE_SINK: 40,
	RR_TYPE_SOA: 6,
	RR_TYPE_SRV: 33,
	RR_TYPE_SSHFP: 44,
	RR_TYPE_TSIG: 250,
	RR_TYPE_TXT: 16,
	RR_TYPE_UID: 101,
	RR_TYPE_UINFO: 100,
	RR_TYPE_UNSPEC: 103,
	RR_TYPE_WKS: 11,
	RR_TYPE_X25: 19,
};

var prefs = Services.prefs.getBranch(PREF_BRANCH);
var log = Logging.getLogger("libunbound");

var libunboundWorker =
	new ChromeWorker("resource://dkim_verifier/libunboundWorker.jsm");
var maxCallId = 0;
var openCalls = new Map();

let libunbound = {
	get version() {"use strict"; return module_version; },

	/**
	 * The result of the query.
	 * Does differ from the original ub_result a bit.
	 * 
	 * @typedef {Object} ub_result
	 * @property {String} qname
	 *           text string, original question
	 * @property {Number} qtype
	 *           type code asked for
	 * @property {Number} qclass
	 *           class code (CLASS IN (internet))
	 * @property {Object[]} data
	 *           Array of converted rdata items. Empty for unsupported RR types.
	 *           Currently supported types: TXT
	 * @property {Number[][]} data_raw
	 *           Array of rdata items as byte array
	 * @property {String} canonname
	 *           canonical name of result
	 * @property {Number} rcode
	 *           additional error code in case of no data
	 * @property {Boolean} havedata
	 *           true if there is data
	 * @property {Boolean} nxdomain
	 *           true if nodata because name does not exist
	 * @property {Boolean} secure
	 *           true if result is secure.
	 * @property {Boolean} bogus
	 *           true if a security failure happened.
	 * @property {String} why_bogus
	 *           string with error if bogus
	 * @property {Number} ttl
	 *           number of seconds the result is valid
	 */

	/**
	 * Perform resolution of the target name.
	 * 
	 * @param {String} name
	 * @param {Number} [rrtype=libunbound.Constants.RR_TYPE_A]
	 * 
	 * @return {Promise<ub_result>}
	 */
	resolve: function libunbound_resolve(name, rrtype=Constants.RR_TYPE_A) {
		"use strict";

		let defer = Promise.defer();
		openCalls.set(++maxCallId, defer);
		
		libunboundWorker.postMessage({
			callId: maxCallId,
			method: "resolve",
			name: name,
			rrtype: rrtype,
		});
		
		return defer.promise;
	},
};

/**
 * init
 */
function init() {
	"use strict";

	let path;
	if (prefs.getBoolPref("libunbound.path.relToProfileDir")) {
		path = OS.Path.join(OS.Constants.Path.profileDir,
			prefs.getCharPref("libunbound.path"));
	} else {
		path = prefs.getCharPref("libunbound.path");
	}
	
	libunboundWorker.postMessage({
		callId: ++maxCallId,
		method: "load",
		path: path,
	});

	update_ctx();

	log.debug("initialized");
}

/**
 * updates ctx by deleting old an creating new
 */
function update_ctx() {
	"use strict";
	
	// read config file if specified
	let conf;
	if (prefs.getPrefType("libunbound.conf") === prefs.PREF_STRING) {
		conf = prefs.getCharPref("libunbound.conf");
	}

	// set debuglevel if specified
	let debuglevel;
	if (prefs.getPrefType("libunbound.debuglevel") === prefs.PREF_INT) {
		debuglevel = prefs.getIntPref("libunbound.debuglevel");
	}
	
	// get DNS servers form OS
	let getNameserversFromOS = prefs.getBoolPref("getNameserversFromOS");
	
	// set additional DNS servers
	let nameservers = prefs.getCharPref("nameserver").split(";");
	nameservers = nameservers.map(function(element /*, index, array*/) {
		return element.trim();
	});
	nameservers = nameservers.filter(function(element /*, index, array*/) {
		if (element !== "") {
			return true;
		} else {
			return false;
		}
	});
	
	// add root trust anchor
	let trustAnchor = prefs.getCharPref("dnssec.trustAnchor");

	libunboundWorker.postMessage({
		callId: ++maxCallId,
		method: "update_ctx",
		conf: conf,
		debuglevel: debuglevel,
		getNameserversFromOS: getNameserversFromOS,
		nameservers: nameservers,
		trustAnchor: trustAnchor,
	});
}

/**
 * Handle the callbacks form the ChromeWorker
 */
libunboundWorker.onmessage = function(msg) {
	"use strict";

	try {
		log.trace("Message received from worker: " + msg.data.toSource());

		// handle log messages
		if (msg.data.type === "log") {
			switch (msg.data.subType) {
				case "fatal":
					log.fatal(msg.data.message);
					break;
				case "error":
					log.error(msg.data.message);
					break;
				case "warn":
					log.warn(msg.data.message);
					break;
				case "info":
					log.info(msg.data.message);
					break;
				case "config":
					log.config(msg.data.message);
					break;
				case "debug":
					log.debug(msg.data.message);
					break;
				case "trace":
					log.trace(msg.data.message);
					break;
				default:
					throw new Error("Unknown log type: " + msg.data.subType);
			}
			return;
		}

		let defer = openCalls.get(msg.data.callId);
		if (defer === undefined) {
			if (msg.data.exception) {
				log.fatal(msg.data.exception);
			} else {
				log.error("Got unexpected callback: " + msg.data);
			}
			return;
		}
		openCalls.delete(msg.data.callId);
		if (msg.data.exception) {
			defer.reject(msg.data.exception);
			return;
		}
		defer.resolve(msg.data.result);
	} catch (e) {
		log.fatal(exceptionToStr(e));
	}
};

libunbound.Constants = Constants;

init();
