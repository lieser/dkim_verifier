/**
 * Copyright (c) 2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="./logging.d.ts" />
/* eslint-env shared-node-browser, webextensions */
/* eslint no-use-before-define: ["error", { "classes": false }] */
/* eslint-disable no-empty-function */

const LOG_NAME = "DKIM_Verifier";

class Logger {
	/**
	 * Creates an instance of Logger.
	 *
	 * @param {string} loggerName
	 * @memberof Logger
	 */
	constructor(loggerName) {
		this.name = loggerName;
		this._logLevel = Logging.logLevel;
		this.logLevel = Logging.logLevel;
	}

	/**
	 * Set the log level of the logger.
	 *
	 * @param {number} logLevel
	 * @memberof Logger
	 */
	set logLevel(logLevel) {
		this._logLevel = logLevel;
		if (logLevel <= Logging.Level.Fatal) {
			this.fatal = console.error.bind(console, `${this.name}\tFATAL\t`);
		} else {
			this.fatal = function () { };
		}
		if (logLevel <= Logging.Level.Error) {
			this.error = console.error.bind(console, `${this.name}\tERROR\t`);
		} else {
			this.error = function () { };
		}
		if (logLevel <= Logging.Level.Warn) {
			this.warn = console.warn.bind(console, `${this.name}\tWARN\t`);
		} else {
			this.warn = function () { };
		}
		if (logLevel <= Logging.Level.Info) {
			this.info = console.info.bind(console, `${this.name}\tINFO\t`);
		} else {
			this.info = function () { };
		}
		if (logLevel <= Logging.Level.Config) {
			this.config = console.info.bind(console, `${this.name}\tCONFIG\t`);
		} else {
			this.config = function () { };
		}
		if (logLevel <= Logging.Level.Debug) {
			this.debug = console.debug.bind(console, `${this.name}\tDEBUG\t`);
		} else {
			this.debug = function () { };
		}
		if (logLevel <= Logging.Level.Trace) {
			this.trace = console.debug.bind(console, `${this.name}\tTRACE\t`);
		} else {
			this.trace = function () { };
		}
	}
	get logLevel() {
		return this._logLevel;
	}
}

export default class Logging {
	static get Level() {
		return {
			Fatal: 70,
			Error: 60,
			Warn: 50,
			Info: 40,
			Config: 30,
			Debug: 20,
			Trace: 10,
			All: -1,
		};
	}

	/**
	 * Get a logger with the given optional name
	 *
	 * @static
	 * @param {string|void} loggerName
	 * @returns {LoggerI} Logger
	 * @memberof Logging
	 */
	static getLogger(loggerName) {
		const name = loggerName ? `${LOG_NAME}.${loggerName}` : `${LOG_NAME}`;
		const logger = new Logger(name);
		Logging._loggers.push(logger);
		// @ts-ignore
		return logger;
	}

	/**
	 * Sets the default log level.
	 * Also sets the log level for all loggers gotten via getLogger().
	 *
	 * @static
	 * @param {number} logLevel
	 * @returns {void}
	 * @memberof Logging
	 */
	static setLogLevel(logLevel) {
		Logging._logLevel = logLevel;
		Logging._loggers.forEach(logger => {
			logger.logLevel = logLevel;
		});
	}
	static get logLevel() {
		return Logging._logLevel;
	}

	/**
	 * Initialize the log level from preferences.
	 * Also adds a change listener to adapt log level if setting changes.
	 *
	 * @static
	 * @returns {Promise<void>}
	 * @memberof Logging
	 */
	static async initLogLevelFromPrefs() {
		const setLogLevelFromPrefs = async () => {
			const prefs = await browser.storage.local.get(["debug", "logging.console"]);
			const debug = prefs.debug ?? false;
			if (debug) {
				/** @type {number|undefined} */
				// @ts-expect-error
				let logLevel = Logging.Level[prefs["logging.console"]];
				if (!logLevel) {
					logLevel = Logging.Level.Debug;
				}
				Logging.setLogLevel(logLevel);
			} else {
				Logging.setLogLevel(Logging.Level.Error);
			}
		};

		await setLogLevelFromPrefs();
		browser.storage.onChanged.addListener((changes, areaName) => {
			if (areaName !== "local") {
				return;
			}
			if (Object.keys(changes).some(name => name === "debug") ||
				Object.keys(changes).some(name => name === "logging.console")
			) {
				setLogLevelFromPrefs();
			}
		});
	}
}
Logging._logLevel = Logging.Level.Debug;
/** @type {Logger[]} */
Logging._loggers = [];
