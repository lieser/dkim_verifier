/**
 * Abstract DKIM key store for key retrieval.
 * Will get the key either from DNS or an internal cache.
 *
 * Copyright (c) 2013-2018;2021 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="../../WebExtensions.d.ts" />
///<reference path="../../RuntimeMessage.d.ts" />
///<reference path="../dns.d.ts" />
/* eslint-env webextensions */

import { DKIM_InternalError, DKIM_SigError } from "../error.mjs.js";
import DNS from "../dns.mjs.js";
import { Deferred } from "../utils.mjs.js";
import Logging from "../logging.mjs.js";
import prefs from "../preferences.mjs.js";

const log = Logging.getLogger("KeyStore");

/**
 * Get the date as a string in the form of `YYYY-MM-DD`
 *
 * @param {Date} date
 * @returns {string}
 */
function dateToString(date) {
	return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
}

/**
 * @typedef {object} StoredDkimKey
 * @property {number} id
 * @property {string} sdid
 * @property {string} selector
 * @property {string} key - DKIM key in its textual Representation.
 * @property {string} insertedAt - Date in the form of `YYYY-MM-DD`
 * @property {string} lastUsedAt - Date in the form of `YYYY-MM-DD`
 * @property {boolean} secure
 */

/**
 * @typedef {object} StoredDkimKeys
 * @property {number} maxId
 * @property {StoredDkimKey[]} keys
 */

/** @type {Deferred<void>?} */
let storedKeysLoaded = null;
let storedKeysMaxId = 0;
/** @type {StoredDkimKey[]} */
let storedKeys = [];

/**
 * Key database backed by browser.storage.local
 */
export class KeyDb {
	static async getKeys() {
		await KeyDb._loadKeys();
		return storedKeys;
	}

	/**
	 * Fetch the DKIM key.
	 * Also updated last used time.
	 *
	 * @param {string} sdid
	 * @param {string} selector
	 * @return {Promise<DkimKeyResult|null>} The key if it's in the storage; null otherwise
	 */
	static async fetch(sdid, selector) {
		await KeyDb._loadKeys();

		const storedKey = storedKeys.find(key => key.sdid === sdid && key.selector === selector);
		if (storedKey === undefined) {
			return null;
		}

		storedKey.lastUsedAt = dateToString(new Date());
		KeyDb._storeKeys(true).catch(error => log.fatal("Storing keys failed", error));

		log.debug("got key from storage");
		return { key: storedKey.key, secure: storedKey.secure };
	}

	/**
	 * Store the DKIM key.
	 *
	 * @param {string} sdid
	 * @param {string} selector
	 * @param {string} key DKIM key
	 * @param {Boolean} secure
	 * @return {Promise<void>}
	 */
	static async store(sdid, selector, key, secure) {
		await KeyDb._loadKeys();
		const currentDate = dateToString(new Date());
		storedKeys.push({
			id: ++storedKeysMaxId,
			sdid: sdid,
			selector: selector,
			key: key,
			secure: secure,
			insertedAt: currentDate,
			lastUsedAt: currentDate,
		});
		await KeyDb._storeKeys(true);
		log.debug("inserted key into storage");
	}

	/**
	 * Mark stored DKIM key as secure.
	 *
	 * @param {string} sdid
	 * @param {string} selector
	 * @return {Promise<void>}
	 */
	static async markAsSecure(sdid, selector) {
		await KeyDb._loadKeys();
		const storedKey = storedKeys.find(key => key.sdid === sdid && key.selector === selector);
		if (storedKey === undefined) {
			throw new Error(`Can not update non existing key (${sdid}, ${selector})`);
		}
		storedKey.secure = true;
		await KeyDb._storeKeys(true);
		log.debug(`Marked key (${storedKey.sdid}, ${storedKey.selector}) to be secure`);
	}

	/**
	 * Update the key with the given id.
	 *
	 * @param {number} id
	 * @param {string} propertyName
	 * @param {any} newValue
	 * @returns {Promise<void>}
	 */
	static async update(id, propertyName, newValue) {
		await KeyDb._loadKeys();
		const key = storedKeys.find(keyEntry => keyEntry.id === id);
		if (!key) {
			throw new Error(`Can not update non existing key with id '${id}'`);
		}
		switch (propertyName) {
			case "sdid":
			case "selector":
			case "key":
				if (typeof newValue !== "string") {
					throw new Error(`Can not set ${propertyName} to value '${newValue}' with type ${typeof newValue}`);
				}
				key[propertyName] = newValue;
				break;
			case "insertedAt":
			case "lastUsedAt":
				if (typeof newValue !== "string") {
					throw new Error(`Can not set ${propertyName} to value '${newValue}' with type ${typeof newValue}`);
				}
				key[propertyName] = newValue;
				break;
			case "secure":
				if (typeof newValue !== "boolean") {
					throw new Error(`Can not set domain to value '${newValue}' with type ${typeof newValue}`);
				}
				key[propertyName] = newValue;
				break;
			default:
				throw new Error(`Can not update unknown property '${propertyName}'`);
		}
		return KeyDb._storeKeys();
	}

	/**
	 * Delete stored DKIM key.
	 *
	 * @param {number?} id
	 * @param {string} [sdid]
	 * @param {string} [selector]
	 * @return {Promise<void>}
	 */
	static async delete(id, sdid, selector) {
		await KeyDb._loadKeys();
		let keyIndex;
		let notify = false;
		if (id === null) {
			keyIndex = storedKeys.findIndex(key => key.sdid === sdid && key.selector === selector);
			notify = true;
		} else {
			keyIndex = storedKeys.findIndex(key => key.id === id);
		}
		if (keyIndex === -1) {
			throw new Error(`Can not delete non existing key with id '${id}'`);
		}
		const deletedKey = storedKeys.splice(keyIndex, 1);
		await KeyDb._storeKeys(notify);
		log.debug(`deleted key (${deletedKey[0].sdid}, ${deletedKey[0].selector}) from storage`);
	}

	/**
	 * Clear the keys.
	 *
	 * @returns {Promise<void>}
	 */
	static clear() {
		storedKeysLoaded = null;
		storedKeys = [];
		storedKeysMaxId = 0;
		return browser.storage.local.remove("keyStore");
	}

	/**
	 * Loads the stored DKIM keys if needed.
	 *
	 * @private
	 * @returns {Promise<void>}
	 */
	static async _loadKeys() {
		if (storedKeysLoaded !== null) {
			return storedKeysLoaded.promise;
		}
		storedKeysLoaded = new Deferred();
		try {
			/** @type {StoredDkimKeys=} */
			const keyStore = (await browser.storage.local.get("keyStore")).keyStore;
			if (keyStore !== undefined) {
				storedKeysMaxId = keyStore.maxId;
				storedKeys = keyStore.keys;
			}
			storedKeysLoaded.resolve();
		} catch (error) {
			storedKeysLoaded.reject(error);
		}
		return storedKeysLoaded.promise;
	}

	/**
	 * Store the DKIM keys.
	 *
	 * @private
	 * @param {boolean} [notify]
	 * @returns {Promise<void>}
	 */
	static async _storeKeys(notify = false) {
		/** @type {StoredDkimKeys} */
		const keyStore = { maxId: storedKeysMaxId, keys: storedKeys };
		await browser.storage.local.set({ keyStore: keyStore });

		if (notify) {
			browser.runtime.sendMessage({ event: "keysUpdated" }).
				catch(error => log.debug("Error sending keysUpdated event", error));
		}
	}


	/**
	 * Setup listening for the calls done through KeyDbProxy.
	 * IMPORTANT: must only be called once.
	 *
	 * @returns {void}
	 */
	static initProxy() {
		browser.runtime.onMessage.addListener((runtimeMessage, sender, /*sendResponse*/) => {
			if (sender.id !== "dkim_verifier@pl") {
				return;
			}
			if (typeof runtimeMessage !== 'object' || runtimeMessage === null) {
				return;
			}
			/** @type {RuntimeMessage.Messages} */
			const request = runtimeMessage;
			if (request.module !== "KeyDb") {
				return;
			}
			if (request.method === "getKeys") {
				// eslint-disable-next-line consistent-return
				return KeyDb.getKeys();
			}
			if (request.method === "updateKey") {
				// eslint-disable-next-line consistent-return
				return KeyDb.update(request.parameters.id, request.parameters.propertyName, request.parameters.newValue);
			}
			if (request.method === "deleteKey") {
				// eslint-disable-next-line consistent-return
				return KeyDb.delete(request.parameters.id);
			}
		});
	}

}

/**
 * The DKIM key with some meta information.
 *
 * @typedef {object} DkimKeyResult
 * @property {string} key - DKIM key in its textual Representation.
 * @property {boolean} secure
 */

/**
 * Abstract DKIM key store for key retrieval.
 * Will get the key either from DNS or an internal cache (KeyDb).
 */
export default class KeyStore {
	/** @readonly */
	static get KEY_STORING() {
		return {
			/** @readonly */
			DISABLED: 0,
			/** @readonly */
			STORE: 1,
			/** @readonly */
			COMPARE: 2,
		};
	}

	/**
	 * @param {queryDnsTxtCallback} [queryDnsTxt]
	 */
	constructor(queryDnsTxt) {
		/** @private */
		this._queryDnsTxt = queryDnsTxt ?? DNS.txt;
	}

	/**
	 * Fetch the DKIM key via the configured method.
	 *
	 * @param {string} sdid
	 * @param {string} selector
	 * @return {Promise<DkimKeyResult>}
	 */
	async fetchKey(sdid, selector) {
		switch (prefs["key.storing"]) {
			// don't store DKIM keys
			case KeyStore.KEY_STORING.DISABLED:
				return this._getKeyFromDNS(sdid, selector);
			// store DKIM keys
			case KeyStore.KEY_STORING.STORE: {
				let key = await KeyDb.fetch(sdid, selector);
				if (key) {
					return key;
				}
				key = await this._getKeyFromDNS(sdid, selector);
				KeyDb.store(sdid, selector, key.key, key.secure).
					catch(error => log.fatal("Storing keys failed", error));
				return key;
			}
			// store DKIM keys and compare with current key
			case KeyStore.KEY_STORING.COMPARE: {
				const keyStored = await KeyDb.fetch(sdid, selector);
				const keyDns = await this._getKeyFromDNS(sdid, selector);
				if (keyStored) {
					if (keyStored.key !== keyDns.key) {
						throw new DKIM_SigError("DKIM_POLICYERROR_KEYMISMATCH");
					}
					keyDns.secure = keyDns.secure || keyStored.secure;
				} else {
					KeyDb.store(sdid, selector, keyDns.key, keyDns.secure).
						catch(error => log.fatal("Storing keys failed", error));
				}
				return keyDns;
			}
			default:
				throw new Error("invalid key.storing setting");
		}
	}

	/**
	 * Get the DKIM key from DNS.
	 *
	 * @private
	 * @param {string} sdid
	 * @param {string} selector
	 * @return {Promise<DkimKeyResult>}
	 */
	async _getKeyFromDNS(sdid, selector) {
		const dnsRes = await this._queryDnsTxt(`${selector}._domainkey.${sdid}`);
		log.debug("dns result", dnsRes);

		if (dnsRes.bogus) {
			throw new DKIM_InternalError(null, "DKIM_DNSERROR_DNSSEC_BOGUS");
		}
		if (dnsRes.rcode !== DNS.RCODE.NoError && dnsRes.rcode !== DNS.RCODE.NXDomain) {
			log.info("DNS query failed with result:", dnsRes);
			throw new DKIM_InternalError(`rcode: ${dnsRes.rcode}`,
				"DKIM_DNSERROR_SERVER_ERROR");
		}
		if (dnsRes.data === null || dnsRes.data[0] === "") {
			throw new DKIM_SigError("DKIM_SIGERROR_NOKEY");
		}

		return {
			key: dnsRes.data[0],
			secure: dnsRes.secure,
		};
	}
}
