/*
 * dnsWrapper.jsm.js
 *
 * Wrapper to resolve DNS lookups via the following libraries:
 *  - JSDNS.jsm.js
 *  - libunbound.jsm.js
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
/* global Logging, PREF, JSDNS, libunbound, DKIM_TempError */
/* exported EXPORTED_SYMBOLS, DNS */

"use strict";

// @ts-expect-error
const module_version = "2.3.0";

var EXPORTED_SYMBOLS = [
	"DNS"
];

// @ts-expect-error
const Cu = Components.utils;

Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");

Cu.import("resource://dkim_verifier/logging.jsm.js");
Cu.import("resource://dkim_verifier/helper.jsm.js");
XPCOMUtils.defineLazyModuleGetter(this, "JSDNS", // eslint-disable-line no-invalid-this
	"resource://dkim_verifier_3p/dns/JSDNS.jsm.js");
XPCOMUtils.defineLazyModuleGetter(this, "libunbound", // eslint-disable-line no-invalid-this
	"resource://dkim_verifier/libunbound.jsm.js");


// @ts-expect-error
const PREF_BRANCH = "extensions.dkim_verifier.dns.";


// @ts-expect-error
var prefs = Services.prefs.getBranch(PREF_BRANCH);
// @ts-expect-error
var log = Logging.getLogger("dnsWrapper");

// This variable is set to true in case of an switch-to-online-mode event, so DNS config will be updated before the next query
var doUpdateDNSConfig = false;

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
	 * @throws {DKIM_TempError|Error}
	 */
	resolve: async function DNS_resolve(name, rrtype="A") {

		// @ts-expect-error
		if (Services.netUtils.offline) {
			throw new DKIM_TempError("DKIM_DNSERROR_OFFLINE");
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
				// @ts-expect-error
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

	/**
	 * Throws error on bogus result or if result contains a DNS error.
	 *
	 * @param {DNSResult} dnsResult
	 * @throws {DKIM_SigError}
	 * @throws {DKIM_TempError}
	 * @returns {void}
	 */
	checkForErrors: function(dnsResult) {
		if (dnsResult.bogus) {
			throw new DKIM_TempError("DKIM_DNSERROR_DNSSEC_BOGUS");
		}
		if (dnsResult.rcode !== DNS.RCODE.NoError && dnsResult.rcode !== DNS.RCODE.NXDomain) {
			log.info("DNS query failed with result:", dnsResult);
			throw new DKIM_TempError("DKIM_DNSERROR_SERVER_ERROR");
		}
	}
};

/**
 * Promise wrapper for the dns result of JSDNS.jsm.js
 * @param {string} name
 * @param {string} rrtype
 * @return {Promise<DNSResult>}
 * @throws {DKIM_TempError}
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
			if (result.rcode !== RCODE.NoError && queryError) {
				throw new DKIM_TempError("DKIM_DNSERROR_SERVER_ERROR");
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
	if (data === "online") {
		log.debug("Thunderbird switched to online mode, resetting DNS configuration before next query");
		doUpdateDNSConfig = true;
	}
}

// @ts-expect-error
Services.obs.addObserver(observeNetworkChange, "network:offline-status-changed", false);
