/**
 * Wrapper to resolve DNS lookups via the following experiment libraries:
 *  - JSDNS
 *  - libunbound
 *
 * Copyright (c) 2020-2023 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="../experiments/jsdns.d.ts" />
///<reference path="../experiments/libunbound.d.ts" />
/* eslint-env webextensions, browser */

import { DKIM_InternalError } from "./error.mjs.js";
import Logging from "../modules/logging.mjs.js";
import prefs from "../modules/preferences.mjs.js";

const log = Logging.getLogger("dns");

/**
 * The result of a TXT query.
 *
 * @typedef {object} DnsTxtResult
 * @property {string[]|null} data Array of txt rdata items, or null if error or no entry in DNS
 * @property {number} rcode DNS error code
 * @property {boolean} secure true if result is secure.
 * @property {boolean} bogus true if a security failure happened.
 */

const RESOLVER_JSDNS = 1;
const RESOLVER_LIBUNBOUND = 2;

/** @type {Promise<void>?} */
let jsdnsIsConfigured = null;
/** @type {Promise<void>?} */
let libunboundIsConfigured = null;

/**
 * Reset configuration of the DNS resolvers.
 *
 * @returns {void}
 */
function resetDNSConfiguration() {
	jsdnsIsConfigured = null;
	libunboundIsConfigured = null;
}

let listenerAdded = false;
/**
 * Add various listener for the configuration of the DNS resolvers.
 *
 * @returns {void}
 */
function addListeners() {
	if (listenerAdded) {
		return;
	}
	listenerAdded = true;

	// Monitor preference changes for the DNS resolvers
	browser.storage.onChanged.addListener((changes, areaName) => {
		if (areaName !== "local") {
			return;
		}
		if (Object.keys(changes).some(name => name.startsWith("dns."))) {
			resetDNSConfiguration();
		}
		if (Object.keys(changes).some(name => name === "debug")) {
			resetDNSConfiguration();
		}
	});

	// Monitor online status
	addEventListener("online", (_event) => {
		log.debug("Online event fired, resetting DNS configuration");
		resetDNSConfiguration();
	});
}

/**
 * Configure the JSDNS resolver if needed.
 *
 * @returns {Promise<void>}
 */
function configureJsdns() {
	if (!jsdnsIsConfigured) {
		log.debug("configure jsdns");
		addListeners();
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
			prefs.debug,
		);
	}
	return jsdnsIsConfigured;
}

/**
 * Configure the libunbound resolver if needed.
 *
 * @returns {Promise<void>}
 */
function configureLibunbound() {
	if (!libunboundIsConfigured) {
		log.debug("configure libunbound");
		addListeners();
		libunboundIsConfigured = browser.libunbound.configure(
			prefs["dns.getNameserversFromOS"],
			prefs["dns.nameserver"],
			prefs["dns.dnssec.trustAnchor"],
			prefs["dns.libunbound.path"],
			prefs["dns.libunbound.path.relToProfileDir"],
			prefs.debug,
		);
	}
	return libunboundIsConfigured;
}

/**
 * Check that Thunderbird is online.
 *
 * @throws {DKIM_InternalError} if Thunderbird is offline.
 */
function checkOnlineStatus() {
	if (!navigator.onLine) {
		throw new DKIM_InternalError(null, "DKIM_DNSERROR_OFFLINE");
	}
}

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
	 * @param {string} name
	 * @returns {Promise<DnsTxtResult>}
	 * @throws {DKIM_InternalError} if no DNS response could be retrieved.
	 */
	static async txt(name) {
		switch (prefs["dns.resolver"]) {
			case RESOLVER_JSDNS: {
				await configureJsdns();
				checkOnlineStatus();
				const res = await browser.jsdns.txt(name);
				if ("error" in res) {
					throw new DKIM_InternalError(res.error, "DKIM_DNSERROR_SERVER_ERROR");
				}
				return res;
			}
			case RESOLVER_LIBUNBOUND: {
				await configureLibunbound();
				checkOnlineStatus();
				return browser.libunbound.txt(name);
			}
			default:
				throw new Error("invalid resolver preference");
		}
	}
}
