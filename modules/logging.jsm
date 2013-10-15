/*
 * logging.jsm
 *
 * Verifies the DKIM-Signatures as specified in RFC 6376
 * http://tools.ietf.org/html/rfc6376
 *
 * version: 1.0.0pre2 (15 October 2013)
 *
 * Copyright (c) 2013 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */
 
// options for JSHint
/* global Components, Log4Moz */
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
var logger;
var capp;
var dapp;

var Logging = {
	getLogger: function(loggerName){
		if (loggerName) {
			return Log4Moz.repository.getLogger(LOG_NAME + "." + loggerName);
		} else {
			return Log4Moz.repository.getLogger(LOG_NAME);
		}
	}
};

function init() {
		setupLogging(LOG_NAME);

		let log = Logging.getLogger(LOG_NAME+".Logging");
		log.debug("initialized");
}

function SimpleFormatter(dateFormat) {
	if (dateFormat)
		this.dateFormat = dateFormat;
}
SimpleFormatter.prototype = {
	__proto__: Log4Moz.Formatter.prototype,

	_dateFormat: null,

	get dateFormat() {
		if (!this._dateFormat)
			this._dateFormat = "%Y-%m-%d %H:%M:%S";
		return this._dateFormat;
	},

	set dateFormat(format) {
		this._dateFormat = format;
	},

	format: function(message) {
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
		// The basic formatter will output lines like:
		// DATE/TIME	LoggerName	LEVEL	(log message) 
		var formatter = new SimpleFormatter();

		// Loggers are hierarchical, lowering this log level will affect all output
		logger = Log4Moz.repository.getLogger(loggerName);
		if (prefs.getBoolPref("debug")) {
			logger.level = Log4Moz.Level["All"];
		} else {
			logger.level = Log4Moz.Level[LOG_LEVEL];
		}

		// A console appender outputs to the JS Error Console
		capp = new Log4Moz.ConsoleAppender(formatter);
		capp.level = Log4Moz.Level[prefs.getCharPref("logging.console")];
		logger.addAppender(capp);

		// A dump appender outputs to standard out
		dapp = new Log4Moz.DumpAppender(formatter);
		dapp.level = Log4Moz.Level[prefs.getCharPref("logging.dump")];
		logger.addAppender(dapp);
		
		prefs.addObserver("", prefObserver, false);
}

var prefObserver = {
	/*
	 * gets called called whenever an event occurs on the preference
	 */
	observe: function(subject, topic, data) {
		// subject is the nsIPrefBranch we're observing (after appropriate QI)
		// data is the name of the pref that's been changed (relative to aSubject)
		
		if (topic !== "nsPref:changed") {
			return;
		}
		
		switch(data) {
			case "debug":
					if (prefs.getBoolPref("debug")) {
						logger.level = Log4Moz.Level["All"];
					} else {
						logger.level = Log4Moz.Level[LOG_LEVEL];
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
}

init();
