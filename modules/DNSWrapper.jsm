/*
 * DNSWrapper.jsm
 * 
 * Version: 1.0.0pre1 (27 October 2013)
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
/* global Components, Services, Task, Promise */
/* global ModuleGetter, Logging, libunbound */
/* global queryDNS, dnsChangeDebug, dnsChangeNameserver, dnsChangeGetNameserversFromOS, dnsChangeTimeoutConnect */
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
Cu.import("resource://dkim_verifier/dns.js");
XPCOMUtils.defineLazyModuleGetter(this, "libunbound",
	"resource://dkim_verifier/libunbound.jsm");


const PREF_BRANCH = "extensions.dkim_verifier.dns.";
const PREF_BRANCH2 = "extensions.dkim_verifier.";


var prefs = Services.prefs.getBranch(PREF_BRANCH);
var prefs2 = Services.prefs.getBranch(PREF_BRANCH2);
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
					queryDNS(name, rrtype, dnsCallback, defer);
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
 * callback for the dns result of dns.js
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

var prefObserver = {
	/*
	 * gets called called whenever an event occurs on the preference
	 */
	observe: function Verifier_observe(subject, topic, data) {
		"use strict";

		// subject is the nsIPrefBranch we're observing (after appropriate QI)
		// data is the name of the pref that's been changed (relative to aSubject)
		
		if (topic !== "nsPref:changed") {
			return;
		}
		
		switch(data) {
			case "debug":
				dnsChangeDebug(prefs2.getBoolPref("debug"));
				break;
			case "dns.getNameserversFromOS":
				dnsChangeGetNameserversFromOS(
					prefs2.getBoolPref("dns.getNameserversFromOS")
				);
				break;
			case "dns.nameserver":
				dnsChangeNameserver(prefs2.getCharPref("dns.nameserver"));
				break;
			case "dns.timeout_connect":
				dnsChangeTimeoutConnect(prefs2.getIntPref("dns.timeout_connect"));
				break;
		}
	},
};

/**
 * init
 */
function init() {
	"use strict";

	// Register to receive notifications of preference changes
	prefs2.addObserver("", prefObserver, false);
	
	// load preferences
	dnsChangeDebug(prefs2.getBoolPref("debug"));
	dnsChangeNameserver(prefs2.getCharPref("dns.nameserver"));
	dnsChangeGetNameserversFromOS(
		prefs2.getBoolPref("dns.getNameserversFromOS")
	);
	dnsChangeTimeoutConnect(prefs2.getIntPref("dns.timeout_connect"));
}

init();
