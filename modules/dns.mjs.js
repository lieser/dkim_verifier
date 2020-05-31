/*
 * Wrapper to resolve DNS lookups via the following libraries:
 *  - JSDNS.jsm
 *  - libunbound.jsm
 *
 * Copyright (c) 2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="../WebExtensions.d.ts" />
///<reference path="../experiments/jsdns.d.ts" />
/* eslint-env webextensions */

import Logging from "../modules/logging.mjs.js";
import prefs from "../modules/preferences.mjs.js";

const log = Logging.getLogger("dns");

/**
 * The result of a TXT query.
 *
 * @typedef {Object} DnsTxtResult
 * @property {string[]|null} data Array of txt rdata items, or null if error or no entry in DNS
 * @property {number} rcode DNS error code
 * @property {boolean} secure true if result is secure.
 * @property {boolean} bogus true if a security failure happened.
 */

const RESOLVER_JSDNS = 1;
const RESOLVER_LIBUNBOUND = 2;

/** @type {Promise<void>?} */
let jsdnsIsConfigured = null;

/**
 * Configure the JSDNS resolver if needed.
 *
 * @returns {Promise<void>}
 */
function configureJsdns() {
	if (!jsdnsIsConfigured) {
		jsdnsIsConfigured = browser.jsdns.configure(
			prefs["dns.getNameserversFromOS"],
			prefs["dns.nameserver"],
			prefs["dns.timeout_connect"],
			{
				enable: prefs["dns.proxy.enable"],
				type: prefs["dns.proxy.type"],
				host: prefs["dns.proxy.host"],
				port: prefs["dns.proxy.port"],
			},
			prefs["dns.jsdns.autoResetServerAlive"],
		);
	}
	return jsdnsIsConfigured;
}

browser.storage.onChanged.addListener((changes, areaName) => {
	if (areaName !== "local") {
		return;
	}
	if (Object.keys(changes).some(name => name.startsWith("dns."))) {
		jsdnsIsConfigured = null;
	}
});

export default class DNS {
	static get RCODE() {
		return {
			NoError: 0, // No Error [RFC1035]
			FormErr: 1, // Format Error [RFC1035]
			ServFail: 2, // Server Failure [RFC1035]
			NXDomain: 3, // Non-Existent Domain [RFC1035]
			NotImp: 4, // Non-Existent Domain [RFC1035]
			Refused: 5, // Query Refused [RFC1035]
		};
	}

	/**
	 * Perform TXT resolution of the target name.
	 *
	 * @param {String} name
	 * @returns {Promise<DnsTxtResult>}
	 */
	static async txt(name) {
		switch (prefs["dns.resolver"]) {
			case RESOLVER_JSDNS:
				await configureJsdns();
				return browser.jsdns.txt(name);
			case RESOLVER_LIBUNBOUND: {
				throw new Error("libunbound not yet available");
				let res = await libunbound.
					resolve(name, libunbound.Constants["RR_TYPE_" + rrtype]);
				/** @type {DNSResult} */
				let result = {};
				if (res !== null) {
					if (res.havedata) {
						result.data = res.data;
					} else {
						result.data = null;
					}
					result.rcode = res.rcode;
					result.secure = res.secure;
					result.bogus = res.bogus;
				} else {
					// error in libunbound
					result.data = null;
					result.rcode = RCODE.ServFail;
					result.secure = false;
					result.bogus = false;
				}

				log.debug("result: " + result.toSource());
				return result;
			}
			default:
				throw new Error("invalid resolver preference");
		}
	}
}
