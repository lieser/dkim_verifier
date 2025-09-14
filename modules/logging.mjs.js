/**
 * Copyright (c) 2020-2023;2025 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="./logging.d.ts" />
/* eslint no-use-before-define: ["error", { "classes": false }] */
/* eslint-disable no-empty-function */

const LOG_NAME = "DKIM_Verifier";

class Logger {
	/**
	 * Creates an instance of Logger.
	 *
	 * @param {string} loggerName
	 */
	constructor(loggerName) {
		this.name = loggerName;
		/** @private */
		this._logLevel = Logging.logLevel;
		this.logLevel = Logging.logLevel;
	}

	/**
	 * Set the log level of the logger.
	 *
	 * @param {number} logLevel
	 */
	set logLevel(logLevel) {
		this._logLevel = logLevel;
		this.fatal = logLevel <= Logging.Level.Fatal ? console.error.bind(console, `${this.name}\tFATAL\t`) : function () { };
		this.error = logLevel <= Logging.Level.Error ? console.error.bind(console, `${this.name}\tERROR\t`) : function () { };
		this.warn = logLevel <= Logging.Level.Warn ? console.warn.bind(console, `${this.name}\tWARN\t`) : function () { };
		this.info = logLevel <= Logging.Level.Info ? console.info.bind(console, `${this.name}\tINFO\t`) : function () { };
		this.config = logLevel <= Logging.Level.Config ? console.info.bind(console, `${this.name}\tCONFIG\t`) : function () { };
		this.debug = logLevel <= Logging.Level.Debug ? console.debug.bind(console, `${this.name}\tDEBUG\t`) : function () { };
		this.trace = logLevel <= Logging.Level.Trace ? console.debug.bind(console, `${this.name}\tTRACE\t`) : function () { };
	}

	get logLevel() {
		return this._logLevel;
	}
}

export default class Logging {
	static get Level() {
		return /** @type {const} */ ({
			Fatal: 70,
			Error: 60,
			Warn: 50,
			Info: 40,
			Config: 30,
			Debug: 20,
			Trace: 10,
			All: -1,
		});
	}

	/**
	 * Get a logger with the given optional name.
	 *
	 * @param {string|void} loggerName
	 * @returns {LoggerI} Logger
	 */
	static getLogger(loggerName) {
		const name = loggerName ? `${LOG_NAME}.${loggerName}` : `${LOG_NAME}`;
		const logger = new Logger(name);
		Logging.#loggers.push(logger);
		// @ts-expect-error
		return logger;
	}

	/**
	 * Sets the default log level.
	 * Also sets the log level for all loggers gotten via getLogger().
	 *
	 * @param {number} logLevel
	 * @returns {void}
	 */
	static setLogLevel(logLevel) {
		Logging.#logLevel = logLevel;
		for (const logger of Logging.#loggers) {
			logger.logLevel = logLevel;
		}
	}

	static get logLevel() {
		return Logging.#logLevel;
	}

	/**
	 * Initialize the log level from preferences.
	 * Also adds a change listener to adapt log level if setting changes.
	 *
	 * @returns {Promise<void>}
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
			if (Object.keys(changes).includes("debug") ||
				Object.keys(changes).includes("logging.console")
			) {
				setLogLevelFromPrefs();
			}
		});
	}

	/** @type {number} */
	static #logLevel = Logging.Level.Debug;
	/**
	 * @type {Logger[]}
	 */
	static #loggers = [];
}
