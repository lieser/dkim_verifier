/*
 * logging.jsm
 *
 * Version: 1.1.0pre1 (19 November 2017)
 *
 * Copyright (c) 2013-2017 Philippe Lieser
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
/* global Components, Services, Log */
/* exported EXPORTED_SYMBOLS, Logging */

var EXPORTED_SYMBOLS = [ "Logging" ];

// @ts-ignore
const Cc = Components.classes;
// @ts-ignore
const Ci = Components.interfaces;
// @ts-ignore
const Cu = Components.utils;

Cu.import("resource://gre/modules/Log.jsm");
Cu.import("resource://gre/modules/Services.jsm");


// "Fatal", "Error", "Warn", "Info", "Config", "Debug", "Trace", "All"
const LOG_LEVEL = "Error";
// @ts-ignore
const LOG_NAME = "DKIM_Verifier";
// @ts-ignore
const PREF_BRANCH = "extensions.dkim_verifier.";


// @ts-ignore
var prefs = Services.prefs.getBranch(PREF_BRANCH);
// @ts-ignore
var log;

var Logging = {
	/**
	 * getLogger
	 * 
	 * @param {String} loggerName
	 * 
	 * @return {Logger} Logger
	 */
	getLogger: function Logging_getLogger(loggerName){
		"use strict";

		if (loggerName) {
			return Log.repository.getLogger(LOG_NAME + "." + loggerName);
		} else {
			return Log.repository.getLogger(LOG_NAME);
		}
	},
	
	/**
	 * addAppenderTo
	 * 
	 * @param {String} loggerName
	 * @param {String} subPrefBranch
	 * 
	 * @return {Array} [capp, dapp]
	 */
	addAppenderTo: function Logging_addAppenderTo(loggerName, subPrefBranch){
		"use strict";

		var logger = Log.repository.getLogger(loggerName);
		var formatter = new SimpleFormatter();
		var cappender;
		var dappender;
		if (prefs.getPrefType(subPrefBranch+"logging.console") === prefs.PREF_STRING) {
			// A console appender outputs to the JS Error Console
			cappender = new Log.ConsoleAppender(formatter);
			cappender.level = Log.Level[prefs.getCharPref(subPrefBranch+"logging.console")];
			logger.addAppender(cappender);
		}
		if (prefs.getPrefType(subPrefBranch+"logging.dump") === prefs.PREF_STRING) {
			// A dump appender outputs to standard out
			dappender = new Log.DumpAppender(formatter);
			dappender.level = Log.Level[prefs.getCharPref(subPrefBranch+"logging.dump")];
			logger.addAppender(dappender);
		}
		
		return [cappender, dappender];
	},
};

/**
 * init
 * 
 * @return {void}
 */
function init() {
	"use strict";
	
	setupLogging(LOG_NAME);

	log = Logging.getLogger("Logging");
	log.debug("initialized");
}

/**
 * SimpleFormatter
 * 
 * @extends Formatter
 */
function SimpleFormatter(dateFormat) {
		"use strict";
	
	if (dateFormat)
		this.dateFormat = dateFormat;
}
SimpleFormatter.prototype = Object.create(Log.Formatter.prototype, {
	dateFormat: {
		get: function() {
			"use strict";
			if (!this._dateFormat)
				this._dateFormat = "%Y-%m-%d %H:%M:%S";
			return this._dateFormat;
		},
		set: function(format) {
			"use strict";
			this._dateFormat = format;
		}
	},

	format: {
		value: function SimpleFormatter_format(message) {
			"use strict";
			var date = new Date(message.time);
			var formatMsg = new String(
				date.toLocaleFormat(this.dateFormat) + "\t" +
				message.loggerName + "\t" + message.levelDesc + "\t" +
				message.message + "\n");
			formatMsg.level = message.level;
			return formatMsg;
		}
	}
});

// https://wiki.mozilla.org/Labs/JS_Modules#Logging
/**
 * setupLogging
 * 
 * @param {String} loggerName
 * 
 * @return {Logger}
 */
function setupLogging(loggerName) {
		"use strict";
	
		// Loggers are hierarchical, lowering this log level will affect all output
		var logger = Log.repository.getLogger(loggerName);
		if (prefs.getBoolPref("debug")) {
			logger.level = Log.Level["All"];
		} else {
			logger.level = Log.Level[LOG_LEVEL];
		}

		var capp;
		var dapp;
		[capp, dapp] = Logging.addAppenderTo(loggerName, "");

		prefs.addObserver("", new PrefObserver(logger, capp, dapp), false);
		
		return logger;
}

/**
 * Preference observer for a Logger, ConsoleAppender and DumpAppender
 * 
 * @param {Logger} logger
 * @param {ConsoleAppender} capp
 * @param {DumpAppender} dapp
 */
function PrefObserver(logger, capp, dapp) {
	"use strict";
	
	this.logger = logger;
	this.capp = capp;
	this.dapp = dapp;
}
PrefObserver.prototype = {
	/*
	 * gets called called whenever an event occurs on the preference
	 */
	observe: function PrefObserver_observe(subject, topic, data) {
		"use strict";
	
		// subject is the nsIPrefBranch we're observing (after appropriate QI)
		// data is the name of the pref that's been changed (relative to aSubject)
		
		if (topic !== "nsPref:changed") {
			return;
		}
		
		switch(data) {
			case "debug":
				if (this.logger) {
					if (prefs.getBoolPref("debug")) {
						this.logger.level = Log.Level["All"];
					} else {
						this.logger.level = Log.Level[LOG_LEVEL];
					}
				}
				break;
			case "logging.console":
				if (this.capp) {
					this.capp.level = Log.Level[prefs.getCharPref("logging.console")];
				}
				break;
			case "logging.dump":
				if (this.dapp) {
					this.dapp.level = Log.Level[prefs.getCharPref("logging.dump")];
				}
				break;
		}
	},
};

init();
