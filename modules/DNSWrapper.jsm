/*
 * DNSWrapper.jsm
 * 
 * Version: 1.0.0 (21 November 2013)
 * 
 * Copyright (c) 2013 Philippe Lieser
 * 
 * This software is licensed under the terms of the MIT License.
 * 
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// options for JSHint
/* jshint strict:true, moz:true */
/* jshint unused:true */ // allow unused parameters that are followed by a used parameter.
/* global Components, Services, Task, Promise, XPCOMUtils */
/* global ModuleGetter, Logging, JSDNS, libunbound */
/* exported EXPORTED_SYMBOLS, DNS */

var EXPORTED_SYMBOLS = [
	"DNS"
];

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cu = Components.utils;

Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/Task.jsm"); // Requires Gecko 17.0
Cu.import("resource://gre/modules/XPCOMUtils.jsm");

Cu.import("resource://dkim_verifier/ModuleGetter.jsm");
ModuleGetter.getPromise(this);

Cu.import("resource://dkim_verifier/logging.jsm");
XPCOMUtils.defineLazyModuleGetter(this, "JSDNS",
	"resource://dkim_verifier/JSDNS.jsm");
XPCOMUtils.defineLazyModuleGetter(this, "libunbound",
	"resource://dkim_verifier/libunbound.jsm");


const PREF_BRANCH = "extensions.dkim_verifier.dns.";


var prefs = Services.prefs.getBranch(PREF_BRANCH);
var log = Logging.getLogger("DNSWrapper");

var DNS = {
	/**
	 * The result of the query.
	 * 
	 * @typedef {Object} DNSResult
	 * @property {Object[]|Null} data Array of rdata items, or null if no entry in DNS
	 * @property {String|Undefined} error undefined if no error; otherwise an error description
	 * @property {Boolean} secure true if result is secure.
	 * @property {Boolean} bogus true if a security failure happened.
	 */

	/**
	 * Perform resolution of the target name.
	 * 
	 * @param {String} name
	 * @param {String} [rrtype="TXT"]
	 * 
	 * @return {Promise<DNSResult>}
	 */
	resolve: function DNS_resolve(name, rrtype="A") {
		"use strict";

		let defer = Promise.defer();

		Task.spawn(function () {
			log.trace("DNS_resolve Task begin");
			
			switch (prefs.getIntPref("resolver")) {
				case 1:
					JSDNS.queryDNS(name, rrtype, dnsCallback, defer);
					break;
				case 2:
					let res = libunbound.resolve(name, libunbound.Constants["RR_TYPE_"+rrtype]);
					let result = {};
					if (res !== null) {
						if (res.havedata) {
							result.data = res.data;
						} else {
							result.data = null;
						}
						if (res.rcode !== 0) {
							result.error = "DNS rcode: "+res.rcode;
						}
						result.secure = res.secure;
						result.bogus = res.bogus;
					} else {
						result.data = null;
						result.error = "error";
						result.secure = false;
						result.bogus = false;
					}

					defer.resolve(result);
					break;
				default:
					throw new Error("invalid resolver preference");
			}

			log.trace("DNS_resolve Task end");
		}).then(null, function onReject(exception) {
			// Failure!  We can inspect or report the exception.
			defer.reject(exception);
		});
		
		return defer.promise;
	},
};

/**
 * callback for the dns result of JSDNS.jsm
 */
function dnsCallback(dnsResult, defer, queryError) {
	"use strict";

	log.trace("dnsCallback begin");

	let result = {};
	result.data = dnsResult;
	result.error = queryError;
	result.secure = false;
	result.bogus = false;
	
	defer.resolve(result);

	log.trace("dnsCallback end");
}
