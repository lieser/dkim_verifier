/*
 * logging.jsm
 *
 * Verifies the DKIM-Signatures as specified in RFC 6376
 * http://tools.ietf.org/html/rfc6376
 *
 * version: 1.0.0pre3 (16 October 2013)
 *
 * Copyright (c) 2013 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */
 
// options for JSHint
/* jshint strict:true, esnext:true */
/* jshint unused:true */ // allow unused parameters that are followed by a used parameter.
/* jshint -W069 */ // "['{a}'] is better written in dot notation."
/* global Components, Services, Log4Moz */
/* exported EXPORTED_SYMBOLS, Logging */

var EXPORTED_SYMBOLS = [ "Logging" ];

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cu = Components.utils;

Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://services-common/log4moz.js");


// "Fatal", "Error", "Warn", "Info", "Config", "Debug", "Trace", "All"
const LOG_LEVEL = "Error";
const LOG_NAME = "DKIM_Verifier";
const PREF_BRANCH = "extensions.dkim_verifier.";

var prefs = Services.prefs.getBranch(PREF_BRANCH);
var log;
var capp;
var dapp;

var Logging = {
	getLogger: function (loggerName){
		"use strict";

		if (loggerName) {
			return Log4Moz.repository.getLogger(LOG_NAME + "." + loggerName);
		} else {
			return Log4Moz.repository.getLogger(LOG_NAME);
		}
	},
	
	/**
	 * @param {String} loggerName
	 * @param {String} subPrefBranch
	 * 
	 * @return {Array} [capp, dapp]
	 */
	addAppenderTo: function (loggerName, subPrefBranch){
		"use strict";

		var logger = Log4Moz.repository.getLogger(loggerName);
		var formatter = new SimpleFormatter();
		var cappender;
		var dappender;
		if (prefs.getPrefType(subPrefBranch+"logging.console") === prefs.PREF_STRING) {
			// A console appender outputs to the JS Error Console
			cappender = new Log4Moz.ConsoleAppender(formatter);
			cappender.level = Log4Moz.Level[prefs.getCharPref(subPrefBranch+"logging.console")];
			logger.addAppender(cappender);
		}
		if (prefs.getPrefType(subPrefBranch+"logging.dump") === prefs.PREF_STRING) {
			// A dump appender outputs to standard out
			dappender = new Log4Moz.DumpAppender(formatter);
			dappender.level = Log4Moz.Level[prefs.getCharPref(subPrefBranch+"logging.dump")];
			logger.addAppender(dappender);
		}
		
		return [cappender, dappender];
	},
};

function init() {
	"use strict";
	
	setupLogging(LOG_NAME);

	log = Logging.getLogger(LOG_NAME+".Logging");
	log.debug("initialized");
}

function SimpleFormatter(dateFormat) {
		"use strict";
	
	if (dateFormat)
		this.dateFormat = dateFormat;
}
SimpleFormatter.prototype = {
	__proto__: Log4Moz.Formatter.prototype,

	_dateFormat: null,

	get dateFormat() {
		"use strict";
	
		if (!this._dateFormat)
			this._dateFormat = "%Y-%m-%d %H:%M:%S";
		return this._dateFormat;
	},

	set dateFormat(format) {
		"use strict";
	
		this._dateFormat = format;
	},

	format: function(message) {
		"use strict";
	
		var date = new Date(message.time);
		var formatMsg = new String(
			date.toLocaleFormat(this.dateFormat) + "\t" +
			message.loggerName + "\t" + message.levelDesc + "\t" +
			message.message + "\n");
		formatMsg.level = message.level;
		return formatMsg;
	}
};

// https://wiki.mozilla.org/Labs/JS_Modules#Logging
function setupLogging(loggerName) {
		"use strict";
	
		// Loggers are hierarchical, lowering this log level will affect all output
		var logger = Log4Moz.repository.getLogger(loggerName);
		if (prefs.getBoolPref("debug")) {
			logger.level = Log4Moz.Level["All"];
		} else {
			logger.level = Log4Moz.Level[LOG_LEVEL];
		}

		[capp, dapp] = Logging.addAppenderTo(loggerName, "");

		prefs.addObserver("", prefObserver, false);
}

var prefObserver = {
	/*
	 * gets called called whenever an event occurs on the preference
	 */
	observe: function(subject, topic, data) {
		"use strict";
	
		// subject is the nsIPrefBranch we're observing (after appropriate QI)
		// data is the name of the pref that's been changed (relative to aSubject)
		
		if (topic !== "nsPref:changed") {
			return;
		}
		
		switch(data) {
			case "debug":
				if (prefs.getBoolPref("debug")) {
					log.level = Log4Moz.Level["All"];
				} else {
					log.level = Log4Moz.Level[LOG_LEVEL];
				}
				break;
			case "logging.console":
				capp.level = Log4Moz.Level[prefs.getCharPref("logging.console")];
				break;
			case "logging.dump":
				dapp.level = Log4Moz.Level[prefs.getCharPref("logging.dump")];
				break;
		}
	},
};

init();
