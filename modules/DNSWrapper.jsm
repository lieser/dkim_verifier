/*
 * DNSWrapper.jsm
 *
 * Wrapper to resolve DNS lookups via the following libraries:
 *  - JSDNS.jsm
 *  - libunbound.jsm
 * 
 * Version: 2.3.0pre1 (14 November 2017)
 * 
 * Copyright (c) 2013-2017 Philippe Lieser
 * 
 * This software is licensed under the terms of the MIT License.
 * 
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// options for JSHint
/* jshint strict:true, moz:true */
/* jshint unused:true */ // allow unused parameters that are followed by a used parameter.
/* global Components, Services, XPCOMUtils */
/* global ModuleGetter, Logging, JSDNS, libunbound */
/* exported EXPORTED_SYMBOLS, DNS */

"use strict";

const module_version = "2.3.0pre1";

var EXPORTED_SYMBOLS = [
	"DNS"
];

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cu = Components.utils;

Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");

Cu.import("resource://dkim_verifier/ModuleGetter.jsm");

Cu.import("resource://dkim_verifier/logging.jsm");
XPCOMUtils.defineLazyModuleGetter(this, "JSDNS",
	"resource://dkim_verifier/JSDNS.jsm");
XPCOMUtils.defineLazyModuleGetter(this, "libunbound",
	"resource://dkim_verifier/libunbound.jsm");


const PREF_BRANCH = "extensions.dkim_verifier.dns.";


var prefs = Services.prefs.getBranch(PREF_BRANCH);
var log = Logging.getLogger("DNSWrapper");

var DNS = {
	get version() {return module_version; },

	/**
	 * The result of the query.
	 * 
	 * @typedef {Object} DNSResult
	 * @property {Object[]|Null} data Array of rdata items, or null if error or no entry in DNS
	 * @property {Number} rcode DNS error code
	 * @property {Boolean} secure true if result is secure.
	 * @property {Boolean} bogus true if a security failure happened.
	 */
	
	/*
	 * some DNS rcodes:
	 *   0  NoError   No Error [RFC1035]
	 *   1  FormErr   Format Error [RFC1035]
	 *   2  ServFail  Server Failure [RFC1035]
	 *   3  NXDomain  Non-Existent Domain [RFC1035]
	 *   4  NotImp    Not Implemented [RFC1035]
	 *   5  Refused   Query Refused [RFC1035]
	 */

	/**
	 * Perform resolution of the target name.
	 * 
	 * @param {String} name
	 * @param {String} [rrtype="TXT"]
	 * 
	 * @return {Promise<DNSResult>}
	 */
	resolve: async function DNS_resolve(name, rrtype="A") {
		switch (prefs.getIntPref("resolver")) {
			case 1:
				return asyncJSDNS_QueryDNS(name, rrtype);
			case 2:
				let res = await libunbound.
					resolve(name, libunbound.Constants["RR_TYPE_"+rrtype]);
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
					result.rcode = 2; // ServFail
					result.secure = false;
					result.bogus = false;
				}

				log.debug("result: "+result.toSource());
				return result;
			default:
				throw new Error("invalid resolver preference");
		}
	},
};


/**
 * Promise wrapper for the dns result of JSDNS.jsm
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
				result.rcode = 2; // ServFail
			} else {
				result.rcode = 0; // NoError
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
