/*
 * dkimKey.jsm
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
/* global Logging */
/* global exceptionToStr, DKIM_SigError, DKIM_InternalError */
/* global queryDNS, dnsChangeDebug, dnsChangeNameserver, dnsChangeGetNameserversFromOS, dnsChangeTimeoutConnect */
/* exported EXPORTED_SYMBOLS, Key */

var EXPORTED_SYMBOLS = [
	"Key"
];

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cu = Components.utils;

// Cu.import("resource://gre/modules/osfile.jsm"); // Requires Gecko 16.0
Cu.import("resource://gre/modules/Promise.jsm");
Cu.import("resource://gre/modules/Services.jsm");
// Cu.import("resource://gre/modules/Sqlite.jsm"); // Requires Gecko 20.0
Cu.import("resource://gre/modules/Task.jsm"); // Requires Gecko 17.0
// Cu.import("resource://services-common/utils.js");

Cu.import("resource://dkim_verifier/logging.jsm");
Cu.import("resource://dkim_verifier/helper.jsm");
Cu.import("resource://dkim_verifier/dns.js");


// const PREF_BRANCH = "extensions.dkim_verifier.key.";
const PREF_BRANCH = "extensions.dkim_verifier.";


var prefs = Services.prefs.getBranch(PREF_BRANCH);
var log = Logging.getLogger("Key");

var Key = {
	/**
	 * Get the DKIM key in its textual Representation.
	 * 
	 * @param {String} d_val domain of the Signer
	 * @param {String} s_val selector
	 * 
	 * @return {Promise<String>}
	 * 
	 * @throws {DKIM_SigError|DKIM_InternalError}
	 */
	getKey: function Key_getKey(d_val, s_val) {
		"use strict";

		var defer = Promise.defer();

		Task.spawn(function () {
			log.trace("getKey Task begin");
			
			// get the DKIM key
			// this function will continue the verification
			queryDNS(
				s_val+"._domainkey."+d_val,
				"TXT",
				dnsCallback,
				defer
			);
			
			log.trace("getKey Task end");
		}).then(null, function onReject(exception) {
			// Failure!  We can inspect or report the exception.
			log.fatal(exceptionToStr(exception));
			defer.reject(exception);
		});
		
		return defer.promise;
	},
	
};

/**
 * callback for the dns result
 */
function dnsCallback(dnsResult, defer, queryError) {
	"use strict";

	log.trace("dnsCallback begin");

	if (queryError !== undefined) {
		defer.reject(new DKIM_InternalError(queryError, "DKIM_DNSERROR_SERVER_ERROR"));
		return;
	}
	if (dnsResult === null) {
		defer.reject(new DKIM_SigError("DKIM_SIGERROR_NOKEY"));
		return;
	}
		
	defer.resolve(dnsResult[0]);

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
				dnsChangeDebug(prefs.getBoolPref("debug"));
				break;
			case "dns.getNameserversFromOS":
				dnsChangeGetNameserversFromOS(
					prefs.getBoolPref("dns.getNameserversFromOS")
				);
				break;
			case "dns.nameserver":
				dnsChangeNameserver(prefs.getCharPref("dns.nameserver"));
				break;
			case "dns.timeout_connect":
				dnsChangeTimeoutConnect(prefs.getIntPref("dns.timeout_connect"));
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
	prefs.addObserver("", prefObserver, false);
	
	// load preferences
	dnsChangeDebug(prefs.getBoolPref("debug"));
	dnsChangeNameserver(prefs.getCharPref("dns.nameserver"));
	dnsChangeGetNameserversFromOS(
		prefs.getBoolPref("dns.getNameserversFromOS")
	);
	dnsChangeTimeoutConnect(prefs.getIntPref("dns.timeout_connect"));
}

init();
