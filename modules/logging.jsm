/*
 * logging.jsm
 *
 * Version: 1.1.0 (31 December 2017)
 *
 * Copyright (c) 2013-2017 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */
 
// options for ESLint
/* eslint strict: ["warn", "function"] */
/* eslint no-magic-numbers: ["warn", { "ignoreArrayIndexes": true, "ignore": [0, 1, 2, 3] }] */
/* global Components, Services, Log */
/* exported EXPORTED_SYMBOLS, Logging */

var EXPORTED_SYMBOLS = [ "Logging" ];

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

var _Logging = {
	/**
	 * getLogger
	 * 
	 * @param {String} loggerName
	 * 
	 * @return {Log.Logger} Logger
	 */
	getLogger: function Logging_getLogger(loggerName){
		"use strict";

		if (loggerName) {
			return Log.repository.getLogger(LOG_NAME + "." + loggerName);
		}
		return Log.repository.getLogger(LOG_NAME);
	},
	
	/**
	 * addAppenderTo
	 * 
	 * @param {String} loggerName
	 * @param {String} subPrefBranch
	 * 
	 * @return {Array} [consoleAppender, dumpAppender]
	 */
	addAppenderTo: function Logging_addAppenderTo(loggerName, subPrefBranch){
		"use strict";

		var logger = Log.repository.getLogger(loggerName);
		var formatter = new SimpleFormatter();
		var cappender;
		var dappender;
		if (prefs.getPrefType(subPrefBranch+"logging.console") === prefs.PREF_STRING) {
			// A console appender outputs to the JS Error Console
			cappender = new SimpleConsoleAppender(formatter);
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
//@ts-ignore
var Logging = _Logging;

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
 */
class SimpleFormatter extends Log.BasicFormatter {
	/**
	 * @param {Log.LogMessage} message
	 * @return {string}
	 */
	format(message) {
		var date = new Date(message.time);
		var formatMsg =
			date.toLocaleString(undefined, { hour12: false }) + "\t" +
			message.loggerName + "\t" +
			message.levelDesc + "\t" +
			this.formatText(message) + "\n";
		return formatMsg;
	}
}

/**
 * SimpleConsoleAppender
 * 
 * An improved version of Mozilla's ConsoleAppender, using the nsIConsoleAPIStorage interface.
 */
class SimpleConsoleAppender extends Log.ConsoleAppender {
	constructor(formatter) {
		super(formatter);
		this._name = "SimpleConsoleAppender";
		this.consoleAPIStorage = Components.classes["@mozilla.org/consoleAPI-storage;1"].
			getService(Components.interfaces.nsIConsoleAPIStorage);
		if (!this.consoleAPIStorage) {
			throw new Error("Failed to get nsIConsoleAPIStorage");
		}
	}

	/**
	 * @param {Log.LogMessage} message
	 * @return {void}
	 */
	append(message) {
		if (message) {
			let level = "";
			if (message.level >= Log.Level.Error) {
				level = "error";
			} else if (message.level >= Log.Level.Warn) {
				level = "warn";
			} else if (message.level >= Log.Level.Info) {
				level = "info";
			} else if(message.level >= Log.Level.Config) {
				level = "log";
			} else if(message.level >= Log.Level.Debug) {
				level = "debug";
			} else {
				level = "trace";
			}

			/** @type {any[]} */
			let args = [this._formatter.format(message)];
			if (!message.message && this.isError(message.params)) {
				// @ts-ignore
				let trace = this.parseStack(message.params.stack);
				if (this.level <= Log.Level.Trace) {
					let logTrace = this.getStack(Components.stack.caller).slice(2);
					args.push("Logged in");
					args.push(logTrace);
				}
				this.sendConsoleAPIMessage(level, trace[0], args, {stacktrace: trace, timeStamp: message.time});
			} else {
				let frame = this.getStack(Components.stack.caller, 3)[2];
				this.sendConsoleAPIMessage(level, frame, args, {timeStamp: message.time});
			}
		}
	}
	
	/**
	 * A stack frame in the format used by the Browser Console,
	 * via console-api-log-event notifications.
	 * @typedef StackFrame
	 * @property {string} filename
	 * @property {number} lineNumber
	 * @property {number} [columnNumber]
	 * @property {string} functionName
	 * @property {number} [language]
	 */
	
	/**
	 * @typedef MessageOptions
	 * @property {StackFrame[]} [stacktrace]
	 * @property {number} [timeStamp]
	 */

	/**
	 * Send a Console API message. This function will send a console-api-log-event
	 * notification through the nsIObserverService.
	 * 
	 * Based on the one from Mozilla's https://dxr.mozilla.org/mozilla-central/source/toolkit/modules/Console.jsm
	 * @param {string} aLevel Level of the message ("error", "exception", "warn", "info", "log", "debug", "trace", ...)
	 * @param {StackFrame} aFrame The youngest stack frame coming from Components.stack, as formatted by getStack().
	 * @param {any[]} aArgs The arguments given to the console method.
	 * @param {MessageOptions} [aOptions]
	 * @return {void}
	 */
	sendConsoleAPIMessage(aLevel, aFrame, aArgs, aOptions = {}) {
		let aConsole = {
			innerID: null,
			consoleID: "",
			prefix: ""
		};
		let consoleEvent = {
			ID: "jsm",
			innerID: aConsole.innerID || aFrame.filename,
			consoleID: aConsole.consoleID,
			category: "JS",
			level: aLevel,
			filename: aFrame.filename,
			lineNumber: aFrame.lineNumber,
			columnNumber: aFrame.columnNumber,
			functionName: aFrame.functionName,
			timeStamp: aOptions.timeStamp || Date.now(),
			arguments: aArgs,
			prefix: aConsole.prefix,
		};
	  
		consoleEvent.wrappedJSObject = consoleEvent;
	  
		consoleEvent.stacktrace = aOptions.stacktrace;

		this.consoleAPIStorage.recordEvent("jsm", null, consoleEvent);
	}
	
	/**
	 * Format a frame coming from Components.stack.
	 *
	 * Based on the one from Mozilla's https://dxr.mozilla.org/mozilla-central/source/toolkit/modules/Console.jsm
	 * @param {nsIStackFrame} [aFrame]
	 *        The stack frame from which to begin the walk.
	 * @param {number} [aMaxDepth]
	 *        Maximum stack trace depth. Default is 0 - no depth limit.
	 * @return {StackFrame[]}
	 */
	getStack(aFrame, aMaxDepth = 0) {
		if (!aFrame) {
			aFrame = Components.stack.caller;
		}
		/** @type {StackFrame[]} */
		let trace = [];
		while (aFrame) {
			trace.push({
				filename: aFrame.filename,
				lineNumber: aFrame.lineNumber,
				functionName: aFrame.name,
				language: aFrame.language,
			});
			if (aMaxDepth === trace.length) {
				break;
			}
			aFrame = aFrame.caller;
		}
		return trace;
	}

	/**
	 * Parse Error.prototype.stack
	 * 
	 * Based on the one from Mozilla's https://dxr.mozilla.org/mozilla-central/source/toolkit/modules/Console.jsm
	 * @param {string} aStack
	 * @return {StackFrame[]}
	 */
	parseStack(aStack) {
		let trace = [];
		aStack.split("\n").forEach(function (line) {
			if (!line) {
				return;
			}
			let at = line.lastIndexOf("@");
			let functionPosition = line.substring(at + 1).split(":");
			trace.push({
				columnNumber: parseInt(functionPosition.pop() || "", 10),
				lineNumber: parseInt(functionPosition.pop() || "", 10),
				filename: functionPosition.join(":"),
				functionName: line.substring(0, at)
			});
		});
		return trace;
	}

	/**
	 * Test an object to see if it is a Mozilla JS Error.
	 * 
	 * From Mozilla's https://dxr.mozilla.org/mozilla-central/source/toolkit/modules/Log.jsm
	 * @param {Object} aObj
	 * @return {boolean}
	 */
	isError(aObj) {
		return (
			aObj &&
			typeof aObj === "object" &&
			"name" in aObj &&
			"message" in aObj &&
			"fileName" in aObj &&
			"lineNumber" in aObj &&
			"stack" in aObj
		);
	}
}

// https://wiki.mozilla.org/Labs/JS_Modules#Logging
/**
 * setupLogging
 * 
 * @param {String} loggerName
 * 
 * @return {Log.Logger}
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
 * @param {Log.Logger} logger
 * @param {Log.ConsoleAppender} capp
 * @param {Log.DumpAppender} dapp
 * @return {PrefObserver}
 */
function PrefObserver(logger, capp, dapp) {
	"use strict";
	
	this.logger = logger;
	this.capp = capp;
	this.dapp = dapp;

	return this;
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
			default:
				// ignore other pref changes
		}
	},
};

init();
