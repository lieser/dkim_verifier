/**
 * Wrapper for the libunbound DNS library. The actual work is done in the
 * ChromeWorker libunboundWorker.jsm.js.
 *
 * Copyright (c) 2013-2018;2020-2023 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="./libunbound.d.ts" />
///<reference path="./mozilla.d.ts" />
/* global ExtensionCommon */

"use strict";

// @ts-expect-error
// eslint-disable-next-line no-var
var { Services } = ChromeUtils.import("resource://gre/modules/Services.jsm");
// @ts-expect-error
// eslint-disable-next-line no-var
var OS;
if (typeof PathUtils === "undefined") {
	// TB < 115
	({ OS } = ChromeUtils.import("resource://gre/modules/osfile.jsm"));
}

/**
 * The result of the query.
 * Does differ from the original ub_result a bit.
 *
 * @typedef {object} ub_result
 * @property {string} qname
 * Text string, the original question.
 * @property {number} qtype
 * The type code asked for.
 * @property {number} qclass
 * Class code (CLASS IN (internet)).
 * @property {any[]} data
 * Array of converted rdata items. Empty for unsupported RR types.
 * Currently supported types: TXT
 * @property {number[][]} data_raw
 * Array of rdata items as byte array.
 * @property {string} canonname
 * Canonical name of result (empty string if missing in response).
 * @property {number} rcode
 * Additional error code in case of no data.
 * @property {boolean} havedata
 * True if there is data.
 * @property {boolean} nxdomain
 * True if nodata because name does not exist.
 * @property {boolean} secure
 * True if result is secure.
 * @property {boolean} bogus
 * True if a security failure happened.
 * @property {string} why_bogus
 * String with error if the result is bogus.
 * @property {number} ttl
 * Number of seconds the result is valid.
 */

/**
 * Deferred Promise
 *
 * @template T
 */
class Deferred {
	constructor() {
		/** @type {Promise<T>} */
		this.promise = new Promise((resolve, reject) => {
			/** @type {(reason: T) => void} */
			this.resolve = resolve;
			/** @type {(reason: Error) => void} */
			this.reject = reject;
		});
	}
}

class LibunboundWorker {
	constructor() {
		/** @private */
		this._maxCallId = 0;
		/**
		 * @private
		 * @type {Map<number, Deferred<ub_result|void>>}
		 */
		this._openCalls = new Map();

		/** @type {Libunbound.LibunboundWorker} */
		this.worker =
			//@ts-expect-error
			new ChromeWorker("chrome://dkim_verifier_libunbound/content/libunboundWorker.jsm.js");
		this.worker.onmessage = (msg) => this.#onmessage(msg);

		this.config = {
			getNameserversFromOS: true,
			nameServer: "",
			dnssecTrustAnchor: "",
			path: "",
			pathRelToProfileDir: false,
			debug: false,
		};

		this.prefs = Services.prefs.getBranch("extensions.dkim_verifier.dns.");
	}

	/**
	 * Load library.
	 *
	 * @returns {Promise<void>}
	 */
	load() {
		/** @type {Deferred<void>} */
		const defer = new Deferred();
		// @ts-expect-error
		this._openCalls.set(++this._maxCallId, defer);

		/** @type {string} */
		let path;
		if (this.config.pathRelToProfileDir) {
			path = this.config.path.
				split(";").
				map(e => {
					if (OS) {
						return OS.Path.join(OS.Constants.Path.profileDir, e);
					}
					return PathUtils.join(PathUtils.profileDir, e);
				}).
				join(";");
		} else {
			path = this.config.path;
		}

		this.worker.postMessage({
			callId: this._maxCallId,
			method: "load",
			path,
		});

		this.isLoaded = defer.promise;
		return defer.promise;
	}

	/**
	 * Updates ctx by deleting the old an creating a new one.
	 *
	 * @returns {Promise<void>}
	 */
	updateCtx() {
		/** @type {Deferred<void>} */
		const defer = new Deferred();
		// @ts-expect-error
		this._openCalls.set(++this._maxCallId, defer);

		// read config file if specified
		let conf;
		if (this.prefs.getPrefType("libunbound.conf") === this.prefs.PREF_STRING) {
			conf = this.prefs.getCharPref("libunbound.conf");
		}

		// set debuglevel if specified
		let debuglevel;
		if (this.prefs.getPrefType("libunbound.debuglevel") === this.prefs.PREF_INT) {
			debuglevel = this.prefs.getIntPref("libunbound.debuglevel");
		}

		// set additional DNS servers
		let nameservers = this.config.nameServer.split(";");
		nameservers = nameservers.map((element /*, index, array*/) => {
			return element.trim();
		});
		nameservers = nameservers.filter((element /*, index, array*/) => {
			if (element !== "") {
				return true;
			}
			return false;
		});

		// add root trust anchor
		const trustAnchors = this.config.dnssecTrustAnchor.split(";");

		this.worker.postMessage({
			callId: this._maxCallId,
			method: "update_ctx",
			conf,
			debuglevel,
			getNameserversFromOS: this.config.getNameserversFromOS,
			nameservers,
			trustAnchors,
		});

		return defer.promise;
	}

	/**
	 * Perform resolution of the target name.
	 *
	 * @param {string} name
	 * @param {number} rrtype
	 * @returns {Promise<ub_result>}
	 */
	resolve(name, rrtype) {
		/** @type {Deferred<ub_result>} */
		const defer = new Deferred();
		// @ts-expect-error
		this._openCalls.set(++this._maxCallId, defer);

		this.worker.postMessage({
			callId: this._maxCallId,
			method: "resolve",
			name,
			rrtype,
		});

		return defer.promise;
	}

	/**
	 * Handle the callbacks from the ChromeWorker.
	 *
	 * @param {Libunbound.WorkerResponse} msg
	 * @returns {void}
	 */
	#onmessage(msg) {
		try {
			// handle log messages
			if (msg.data.type && msg.data.type === "log") {
				/** @type {Libunbound.Log} */
				// @ts-expect-error
				const logMsg = msg.data;
				switch (logMsg.subType) {
					case "error":
						console.error(logMsg.message);
						break;
					case "warn":
						console.warn(logMsg.message);
						break;
					case "info":
						console.info(logMsg.message);
						break;
					case "debug":
						if (this.config.debug) {
							console.debug(logMsg.message);
						}
						break;
					default:
						throw new Error(`Unknown log type: ${logMsg.subType}`);
				}
				return;
			}
			/** @type {Libunbound.Response} */
			// @ts-expect-error
			const response = msg.data;

			let exception;
			if (response.type && response.type === "error") {
				/** @type {Libunbound.Exception} */
				// @ts-expect-error
				const ex = response;
				exception = new Error(`Error in libunboundWorker: ${ex.message}; subType: ${ex.subType}; stack: ${ex.stack}`);
			}

			const defer = this._openCalls.get(response.callId);
			if (defer === undefined) {
				if (exception) {
					console.error("Exception in libunboundWorker", exception);
				} else {
					console.error("Got unexpected callback:", response);
				}
				return;
			}
			this._openCalls.delete(response.callId);
			if (exception) {
				defer.reject(exception);
				return;
			}
			/** @type {Libunbound.Result} */
			// @ts-expect-error
			const res = response;
			defer.resolve(res.result);
		} catch (e) {
			console.error(e);
		}
	}
}
LibunboundWorker.Constants = {
	RR_TYPE_A: 1,
	RR_TYPE_A6: 38,
	RR_TYPE_AAAA: 28,
	RR_TYPE_AFSDB: 18,
	RR_TYPE_ANY: 255,
	RR_TYPE_APL: 42,
	RR_TYPE_ATMA: 34,
	RR_TYPE_AXFR: 252,
	RR_TYPE_CERT: 37,
	RR_TYPE_CNAME: 5,
	RR_TYPE_DHCID: 49,
	RR_TYPE_DLV: 32769,
	RR_TYPE_DNAME: 39,
	RR_TYPE_DNSKEY: 48,
	RR_TYPE_DS: 43,
	RR_TYPE_EID: 31,
	RR_TYPE_GID: 102,
	RR_TYPE_GPOS: 27,
	RR_TYPE_HINFO: 13,
	RR_TYPE_IPSECKEY: 45,
	RR_TYPE_ISDN: 20,
	RR_TYPE_IXFR: 251,
	RR_TYPE_KEY: 25,
	RR_TYPE_KX: 36,
	RR_TYPE_LOC: 29,
	RR_TYPE_MAILA: 254,
	RR_TYPE_MAILB: 253,
	RR_TYPE_MB: 7,
	RR_TYPE_MD: 3,
	RR_TYPE_MF: 4,
	RR_TYPE_MG: 8,
	RR_TYPE_MINFO: 14,
	RR_TYPE_MR: 9,
	RR_TYPE_MX: 15,
	RR_TYPE_NAPTR: 35,
	RR_TYPE_NIMLOC: 32,
	RR_TYPE_NS: 2,
	RR_TYPE_NSAP: 22,
	RR_TYPE_NSAP_PTR: 23,
	RR_TYPE_NSEC: 47,
	RR_TYPE_NSEC3: 50,
	RR_TYPE_NSEC3PARAMS: 51,
	RR_TYPE_NULL: 10,
	RR_TYPE_NXT: 30,
	RR_TYPE_OPT: 41,
	RR_TYPE_PTR: 12,
	RR_TYPE_PX: 26,
	RR_TYPE_RP: 17,
	RR_TYPE_RRSIG: 46,
	RR_TYPE_RT: 21,
	RR_TYPE_SIG: 24,
	RR_TYPE_SINK: 40,
	RR_TYPE_SOA: 6,
	RR_TYPE_SRV: 33,
	RR_TYPE_SSHFP: 44,
	RR_TYPE_TSIG: 250,
	RR_TYPE_TXT: 16,
	RR_TYPE_UID: 101,
	RR_TYPE_UINFO: 100,
	RR_TYPE_UNSPEC: 103,
	RR_TYPE_WKS: 11,
	RR_TYPE_X25: 19,
};


this.libunbound = class extends ExtensionCommon.ExtensionAPI {
	/**
	 * @param {ExtensionCommon.Extension} extension
	 */
	constructor(extension) {
		super(extension);

		const aomStartup = Cc[
			"@mozilla.org/addons/addon-manager-startup;1"
		]?.getService(Ci.amIAddonManagerStartup);
		if (!aomStartup) {
			throw new Error("Failed to get amIAddonManagerStartup");
		}
		const manifestURI = Services.io.newURI(
			"manifest.json",
			null,
			this.extension.rootURI
		);
		this.chromeHandle = aomStartup.registerChrome(manifestURI, [
			["content", "dkim_verifier_libunbound", "experiments/"],
		]);

		this.libunboundWorker = new LibunboundWorker();
		this.extension.callOnClose(this);
	}

	/**
	 * @param {ExtensionCommon.Context} _context
	 * @returns {{libunbound: browser.libunbound}}
	 */
	getAPI(_context) {
		const libunboundWorker = this.libunboundWorker;
		return {
			libunbound: {
				async configure(getNameserversFromOS, nameServer, dnssecTrustAnchor, path, pathRelToProfileDir, debug) {
					libunboundWorker.config.getNameserversFromOS = getNameserversFromOS;
					libunboundWorker.config.nameServer = nameServer;
					libunboundWorker.config.dnssecTrustAnchor = dnssecTrustAnchor;
					libunboundWorker.config.debug = debug;
					if (libunboundWorker.config.path !== path
						|| libunboundWorker.config.pathRelToProfileDir !== pathRelToProfileDir) {
						libunboundWorker.config.path = path;
						libunboundWorker.config.pathRelToProfileDir = pathRelToProfileDir;
						await libunboundWorker.load();
					}
					await libunboundWorker.isLoaded;
					return libunboundWorker.updateCtx();
				},
				async txt(name) {
					const res = await libunboundWorker.resolve(name, LibunboundWorker.Constants.RR_TYPE_TXT);
					const data = res.havedata ? res.data.map(rdata => {
						if (typeof rdata !== "string") {
							throw Error(`DNS result has unexpected type ${typeof rdata}`);
						}
						return rdata;
					}) : null;
					return {
						data,
						rcode: res.rcode,
						secure: res.secure,
						bogus: res.bogus,
					};
				},
			},
		};
	}

	close() {
		this.libunboundWorker.worker.terminate();

		this.chromeHandle.destruct();
		// @ts-expect-error
		this.chromeHandle = null;

		Services.obs.notifyObservers(null, "startupcache-invalidate");
	}
};
