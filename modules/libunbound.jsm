/*
 * libunbound.jsm
 * 
 * Wrapper for the libunbound DNS library. The actual work is done in the
 * ChromeWorker libunboundWorker.jsm.
 *
 * Version: 2.2.0 (02 January 2018)
 * 
 * Copyright (c) 2013-2018 Philippe Lieser
 * 
 * This software is licensed under the terms of the MIT License.
 * 
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// options for ESLint
/* global Components, OS, Services, ChromeWorker */
/* global Logging, Deferred, DKIM_InternalError */
/* exported EXPORTED_SYMBOLS, libunbound */

"use strict";

// @ts-ignore
const module_version = "2.2.0";

var EXPORTED_SYMBOLS = [
	"libunbound"
];

// @ts-ignore
const Cu = Components.utils;

Cu.import("resource://gre/modules/osfile.jsm");
Cu.import("resource://gre/modules/Services.jsm");

Cu.import("resource://dkim_verifier/logging.jsm");
Cu.import("resource://dkim_verifier/helper.jsm");


// @ts-ignore
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
 *           canonical name of result (empty string if missing in response)
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

// @ts-ignore
var prefs = Services.prefs.getBranch(PREF_BRANCH);
// @ts-ignore
var log = Logging.getLogger("libunbound");

/** @type {Libunbound.LibunboundWorker} */
var libunboundWorker =
	new ChromeWorker("resource://dkim_verifier/libunboundWorker.jsm");
var maxCallId = 0;
/** @type {Map<number, IDeferred<ub_result>>} */
var openCalls = new Map();

let libunbound = {
	get version() {return module_version; },

	/**
	 * Perform resolution of the target name.
	 * 
	 * @param {String} name
	 * @param {Number} [rrtype=libunbound.Constants.RR_TYPE_A]
	 * 
	 * @return {Promise<ub_result>}
	 */
	resolve: function libunbound_resolve(name, rrtype=Constants.RR_TYPE_A) {
		/** @type {IDeferred<ub_result>} */
		let defer = new Deferred();
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
 * @return {void}
 */
function init() {
	load();
	update_ctx();

	// Register to receive notifications of preference changes
	prefs.addObserver("", prefObserver, false);

	log.debug("initialized");
}

/**
 * load library
 * @return {void}
 */
function load() {
	let path;
	if (prefs.getBoolPref("libunbound.path.relToProfileDir")) {
		path = prefs.getCharPref("libunbound.path").
			split(";").
			map(e => {return OS.Path.join(OS.Constants.Path.profileDir, e);}).
			join(";");
	} else {
		path = prefs.getCharPref("libunbound.path");
	}
	
	libunboundWorker.postMessage({
		callId: ++maxCallId,
		method: "load",
		path: path,
	});
}

/**
 * updates ctx by deleting old an creating new
 * @return {void}
 */
function update_ctx() {
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
		}
		return false;
	});
	
	// add root trust anchor
	let trustAnchors = prefs.getCharPref("dnssec.trustAnchor").split(";");

	libunboundWorker.postMessage({
		callId: ++maxCallId,
		method: "update_ctx",
		conf: conf,
		debuglevel: debuglevel,
		getNameserversFromOS: getNameserversFromOS,
		nameservers: nameservers,
		trustAnchors: trustAnchors,
	});
}

/**
 * Handle the callbacks from the ChromeWorker
 * @param {Libunbound.WorkerResponse} msg
 * @return {void}
 */
libunboundWorker.onmessage = function(msg) {
	try {
		log.trace("Message received from worker: " + msg.data.toSource());

		// handle log messages
		if (msg.data.type && msg.data.type === "log") {
			/** @type {Libunbound.Log} */
			// @ts-ignore
			let logMsg = msg.data;
			switch (logMsg.subType) {
				case "fatal":
					log.fatal(logMsg.message);
					break;
				case "error":
					log.error(logMsg.message);
					break;
				case "warn":
					log.warn(logMsg.message);
					break;
				case "info":
					log.info(logMsg.message);
					break;
				case "config":
					log.config(logMsg.message);
					break;
				case "debug":
					log.debug(logMsg.message);
					break;
				case "trace":
					log.trace(logMsg.message);
					break;
				default:
					throw new Error("Unknown log type: " + logMsg.subType);
			}
			return;
		}
		/** @type {Libunbound.Response} */
		// @ts-ignore
		let response = msg.data;

		let exception;
		if (response.type && response.type === "error") {
			/** @type {Libunbound.Exception} */
			// @ts-ignore
			let ex = response;
			exception = new DKIM_InternalError(ex.message, ex.subType);
		}

		let defer = openCalls.get(response.callId);
		if (defer === undefined) {
			if (exception) {
				log.fatal("Exception in libunboundWorker", exception);
			} else {
				log.error("Got unexpected callback: " + response);
			}
			return;
		}
		openCalls.delete(response.callId);
		if (exception) {
			defer.reject(exception);
			return;
		}
		/** @type {Libunbound.Result} */
		// @ts-ignore
		let res = response;
		defer.resolve(res.result);
	} catch (e) {
		log.fatal(e);
	}
};

var prefObserver = {
	/*
	 * gets called called whenever an event occurs on the preference
	 */
	observe: function Verifier_observe(subject, topic, data) {
		// subject is the nsIPrefBranch we're observing (after appropriate QI)
		// data is the name of the pref that's been changed (relative to aSubject)

		if (topic !== "nsPref:changed") {
			return;
		}

		switch(data) {
			case "libunbound.path.relToProfileDir":
			case "libunbound.path":
				load();
				update_ctx();
				break;
			case "libunbound.conf":
			case "libunbound.debuglevel":
			case "getNameserversFromOS":
			case "nameserver":
			case "dnssec.trustAnchor":
				update_ctx();
				break;
			default:
				// ignore other options
		}
	},
};

libunbound.Constants = Constants;

init();
