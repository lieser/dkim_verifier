/*
 * DNSWrapper.jsm
 *
 * Wrapper to resolve DNS lookups via the following libraries:
 *  - JSDNS.jsm
 *  - libunbound.jsm
 * 
 * Version: 2.3.0 (28 January 2018)
 * 
 * Copyright (c) 2013-2018 Philippe Lieser
 * 
 * This software is licensed under the terms of the MIT License.
 * 
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// options for ESLint
/* global Components, Services, XPCOMUtils */
/* global Logging, PREF, JSDNS, libunbound */
/* exported EXPORTED_SYMBOLS, DNS */

"use strict";

// @ts-ignore
const module_version = "2.3.0";

var EXPORTED_SYMBOLS = [
	"DNS"
];

// @ts-ignore
const Cu = Components.utils;

Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");

Cu.import("resource://dkim_verifier/logging.jsm");
Cu.import("resource://dkim_verifier/helper.jsm");
XPCOMUtils.defineLazyModuleGetter(this, "JSDNS", // eslint-disable-line no-invalid-this
	"resource://dkim_verifier_3p/dns/JSDNS.jsm");
XPCOMUtils.defineLazyModuleGetter(this, "libunbound", // eslint-disable-line no-invalid-this
	"resource://dkim_verifier/libunbound.jsm");


// @ts-ignore
const PREF_BRANCH = "extensions.dkim_verifier.dns.";


// @ts-ignore
var prefs = Services.prefs.getBranch(PREF_BRANCH);
// @ts-ignore
var log = Logging.getLogger("DNSWrapper");

// This variable is set to true in case of an switch-to-online-mode event, so DNS config will be updated before the next query
var doUpdateDNSConfig = false;
// This variable will be set to true, when the observer for the network online event is in place
var isNetworkObserverAdded = false;

/**
 * The result of the query.
 * 
 * @typedef {Object} DNSResult
 * @property {Object[]|Null} data Array of rdata items, or null if error or no entry in DNS
 * @property {Number} rcode DNS error code
 * @property {Boolean} secure true if result is secure.
 * @property {Boolean} bogus true if a security failure happened.
 */

const RCODE = {
	NoError: 0, // No Error [RFC1035]
	FormErr: 1, // Format Error [RFC1035]
	ServFail: 2, // Server Failure [RFC1035]
	NXDomain: 3, // Non-Existent Domain [RFC1035]
	NotImp: 4, // Non-Existent Domain [RFC1035]
	Refused: 5, // Query Refused [RFC1035]
};

var DNS = {
	get version() {return module_version; },

	get RCODE() {return RCODE; },

	/**
	 * Perform resolution of the target name.
	 * 
	 * @param {String} name
	 * @param {String} [rrtype="TXT"]
	 * 
	 * @return {Promise<DNSResult>}
	 */
	resolve: async function DNS_resolve(name, rrtype="A") {
		
		if (Services.netUtils.offline) {
			throw new DKIM_InternalError(null, "DKIM_DNSERROR_OFFLINE");
		}
				
		switch (prefs.getIntPref("resolver")) {
			case PREF.DNS.RESOLVER.JSDNS:
				if (doUpdateDNSConfig) { 
					JSDNS.updateConfig(); 
					doUpdateDNSConfig = false; 
				}
				return asyncJSDNS_QueryDNS(name, rrtype);
			case PREF.DNS.RESOLVER.LIBUNBOUND: {
				if (doUpdateDNSConfig) { 
					libunbound.updateConfig(); 
					doUpdateDNSConfig = false; 
				}
				let res = await libunbound.
					resolve(name, libunbound.Constants["RR_TYPE_"+rrtype]);
				/** @type {DNSResult} */
				let result = {};
				if (res !== null) {
					if (res.havedata) {
						result.data = res.data;
					} else {
						result.data = null;
					}					
					result.rcode = res.rcode;
					result.secure = res.secure;
					result.bogus = res.bogus;					
				} else {
					// error in libunbound
					result.data = null;
					result.rcode = RCODE.ServFail;
					result.secure = false;
					result.bogus = false;
				}

				log.debug("result: "+result.toSource());
				return result;
			}
			default:
				throw new Error("invalid resolver preference");
		}
	},
};


/**
 * Promise wrapper for the dns result of JSDNS.jsm
 * @param {string} name
 * @param {string} rrtype
 * @return {Promise<DNSResult>}
 */
function asyncJSDNS_QueryDNS(name, rrtype) {
	function dnsCallback(dnsResult, defer, queryError, rcode) {
		try {
			log.trace("dnsCallback begin");
			
			let result = {};
			result.data = dnsResult;
			if (rcode !== undefined) {
				result.rcode = rcode;
			} else if (queryError !== undefined) {
				result.rcode = RCODE.ServFail;				
			} else {
				result.rcode = RCODE.NoError;
			}
			if (result.rcode != RCODE.NoError && queryError) {
				throw new DKIM_InternalError(queryError, "DKIM_DNSERROR_SERVER_ERROR");
			}
			result.secure = false;
			result.bogus = false;
			
			log.debug("result: "+result.toSource());
			defer.resolve(result);
		
			log.trace("dnsCallback end");
		} catch (e) {
			defer.reject(e);
		}
	}

	return new Promise((resolve, reject) => JSDNS.queryDNS(
		name, rrtype, dnsCallback, {resolve: resolve, reject: reject}));
}

function observeNetworkChange(subject, topic, data) {
	if (data == "online") {
		log.debug("Thunderbird switched to online mode, resetting DNS configuration before next query");
		doUpdateDNSConfig = true;
	}
}

if (!isNetworkObserverAdded) {
	Services.obs.addObserver(observeNetworkChange, "network:offline-status-changed", false);
	isNetworkObserverAdded = true;
}