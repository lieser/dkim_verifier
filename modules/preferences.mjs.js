/**
 * Provides access to the add-ons preferences.
 *
 * Copyright (c) 2020-2023 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-env webextensions */
/* eslint no-magic-numbers: "off" */
/* eslint-disable jsdoc/match-description */

import { Deferred } from "./utils.mjs.js";
import ExtensionUtils from "./extensionUtils.mjs.js";
import Logging from "./logging.mjs.js";

const log = Logging.getLogger("Verifier");

/**
 * Defines the interface for accessing the preferences and
 * defines the default values of the preferences.
 */
export class BasePreferences {
	/**
	 * @callback ValueGetter
	 * @param {string} name
	 * @returns {boolean|number|string|undefined}
	 */
	/**
	 * @callback ValueSetter
	 * @param {string} name
	 * @param {boolean|number|string} value
	 * @returns {Promise<void>}
	 */

	/**
	 * Creates an instance of BasePreferences.
	 *
	 * @param {ValueGetter} valueGetter
	 * @param {ValueSetter} valueSetter
	 */
	constructor(valueGetter, valueSetter) {
		/**
		 * @protected
		 * @type {{[prefName: string]: boolean|number|string|undefined}}
		 */
		this._prefs = {};

		/** @private */
		this._valueGetter = valueGetter;
		/** @private */
		this._valueSetter = valueSetter;
	}

	/**
	 * Initialize the preference instance if needed.
	 * Must be waited on before the instance can be used.
	 *
	 * @returns {Promise<void>}
	 */
	init() {
		return Promise.resolve();
	}

	/**
	 * Clear the stored preferences.
	 *
	 * @returns {Promise<void>}
	 */
	clear() {
		this._prefs = {};
		return Promise.resolve();
	}

	/**
	 * @param {string} name
	 * @param {boolean} defaultValue
	 * @returns {boolean}
	 */
	#tryGetBoolValue(name, defaultValue) {
		const value = this._valueGetter(name);
		if (typeof value === "boolean") {
			return value;
		}
		if (typeof value === "undefined") {
			return defaultValue;
		}
		throw new Error(`Preference ${name} has unexpected type ${typeof value}`);
	}

	/**
	 * @param {string} name
	 * @param {number} defaultValue
	 * @returns {number}
	 */
	#tryGetNumberValue(name, defaultValue) {
		const value = this._valueGetter(name);
		if (typeof value === "number") {
			return value;
		}
		if (typeof value === "undefined") {
			return defaultValue;
		}
		throw new Error(`Preference ${name} has unexpected type ${typeof value}`);
	}

	/**
	 * @param {string} name
	 * @param {string} defaultValue
	 * @returns {string}
	 */
	#tryGetStringValue(name, defaultValue) {
		const value = this._valueGetter(name);
		if (typeof value === "string") {
			return value;
		}
		if (typeof value === "undefined") {
			return defaultValue;
		}
		throw new Error(`Preference ${name} has unexpected type ${typeof value}`);
	}

	/**
	 * @param {string} name
	 * @returns {boolean|number|string}
	 */
	getValue(name) {
		if (!Object.prototype.hasOwnProperty.call(BasePreferences.prototype, name)) {
			throw new Error(`Can not get nonexisting preference "${name}"`);
		}
		/** @type {any} */
		const that = this;
		return that[name];
	}

	/**
	 * @param {string} name
	 * @returns {boolean}
	 */
	getBool(name) {
		const value = this.getValue(name);
		if (typeof value !== "boolean") {
			throw new Error(`Preference ${name} has unexpected type ${typeof value}`);
		}
		return value;
	}

	/**
	 * @param {string} name
	 * @returns {number}
	 */
	getNumber(name) {
		const value = this.getValue(name);
		if (typeof value !== "number") {
			throw new Error(`Preference ${name} has unexpected type ${typeof value}`);
		}
		return value;
	}

	/**
	 * @param {string} name
	 * @returns {string}
	 */
	getString(name) {
		const value = this.getValue(name);
		if (typeof value !== "string") {
			throw new Error(`Preference ${name} has unexpected type ${typeof value}`);
		}
		return value;
	}

	/**
	 * @param {string} name
	 * @param {boolean|number|string} value
	 * @returns {Promise<void>}
	 */
	async setValue(name, value) {
		if (typeof value !== typeof this.getValue(name)) {
			throw new Error(`Can not set preference with type ${typeof this.getValue(name)} to a ${typeof value}`);
		}
		await this._valueSetter(name, value);
	}

	////////////////////////////////////////////////////////////////////////////
	//#region General preferences
	////////////////////////////////////////////////////////////////////////////

	get "dkim.enable"() {
		return this.#tryGetBoolValue("dkim.enable", true);
	}
	/**
	 * - 0: don't store DKIM keys
	 * - 1: store DKIM keys
	 * - 2: store DKIM keys and compare with current key
	 */
	get "key.storing"() {
		return this.#tryGetNumberValue("key.storing", 0);
	}
	get "saveResult"() {
		return this.#tryGetBoolValue("saveResult", false);
	}

	get "arh.read"() {
		return this.#tryGetBoolValue("arh.read", false);
	}
	get "arh.replaceAddonResult"() {
		return this.#tryGetBoolValue("arh.replaceAddonResult", true);
	}
	get "arh.relaxedParsing"() {
		return this.#tryGetBoolValue("arh.relaxedParsing", false);
	}

	get "internationalized.enable"() {
		return this.#tryGetBoolValue("internationalized.enable", false);
	}
	//#endregion

	////////////////////////////////////////////////////////////////////////////
	//#region Error preferences
	////////////////////////////////////////////////////////////////////////////

	/**
	 * - 0: error
	 * - 1: warning
	 * - 2: ignore
	 */
	get "error.illformed_i.treatAs"() {
		return this.#tryGetNumberValue("error.illformed_i.treatAs", 1);
	}
	/**
	 * - 0: error
	 * - 1: warning
	 * - 2: ignore
	 */
	get "error.illformed_s.treatAs"() {
		return this.#tryGetNumberValue("error.illformed_s.treatAs", 1);
	}
	/**
	 * - 0: error
	 * - 1: warning
	 * - 2: ignore
	 */
	get "error.policy.key_insecure.treatAs"() {
		return this.#tryGetNumberValue("error.policy.key_insecure.treatAs", 2);
	}
	get "error.key_testmode.ignore"() {
		return this.#tryGetBoolValue("error.key_testmode.ignore", false);
	}
	/**
	 * - 0: error
	 * - 1: warning
	 * - 2: ignore
	 */
	get "error.algorithm.sign.rsa-sha1.treatAs"() {
		return this.#tryGetNumberValue("error.algorithm.sign.rsa-sha1.treatAs", 1);
	}
	/**
	 * - 0: error
	 * - 1: warning
	 * - 2: ignore
	 */
	get "error.algorithm.rsa.weakKeyLength.treatAs"() {
		return this.#tryGetNumberValue("error.algorithm.rsa.weakKeyLength.treatAs", 2);
	}

	get "error.detailedReasons"() {
		return this.#tryGetBoolValue("error.detailedReasons", false);
	}
	//#endregion

	////////////////////////////////////////////////////////////////////////////
	//#region DNS preferences
	////////////////////////////////////////////////////////////////////////////

	/**
	 * - 1 JS DNS
	 * - 2 libunbound
	 */
	get "dns.resolver"() {
		return this.#tryGetNumberValue("dns.resolver", 1);
	}
	get "dns.getNameserversFromOS"() {
		return this.#tryGetBoolValue("dns.getNameserversFromOS", true);
	}
	get "dns.nameserver"() {
		return this.#tryGetStringValue("dns.nameserver", "8.8.8.8");
	}
	get "dns.timeout_connect"() {
		return this.#tryGetNumberValue("dns.timeout_connect", 5);
	}
	get "dns.dnssec.trustAnchor"() {
		return this.#tryGetStringValue("dns.dnssec.trustAnchor",
			". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D");
	}
	get "dns.proxy.enable"() {
		return this.#tryGetBoolValue("dns.proxy.enable", false);
	}
	/**
	 * - socks
	 * - socks4
	 */
	get "dns.proxy.type"() {
		return this.#tryGetStringValue("dns.proxy.type", "socks");
	}
	get "dns.proxy.host"() {
		return this.#tryGetStringValue("dns.proxy.host", "");
	}
	get "dns.proxy.port"() {
		return this.#tryGetNumberValue("dns.proxy.port", 1080);
	}
	get "dns.jsdns.autoResetServerAlive"() {
		return this.#tryGetBoolValue("dns.jsdns.autoResetServerAlive", true);
	}
	get "dns.libunbound.path"() {
		return this.#tryGetStringValue("dns.libunbound.path", "");
	}
	get "dns.libunbound.path.relToProfileDir"() {
		return this.#tryGetBoolValue("dns.libunbound.path.relToProfileDir", true);
	}
	//#endregion

	////////////////////////////////////////////////////////////////////////////
	//#region Policy preferences
	////////////////////////////////////////////////////////////////////////////

	get "policy.signRules.enable"() {
		return this.#tryGetBoolValue("policy.signRules.enable", false);
	}
	get "policy.signRules.checkDefaultRules"() {
		return this.#tryGetBoolValue("policy.signRules.checkDefaultRules", true);
	}
	get "policy.signRules.autoAddRule.enable"() {
		return this.#tryGetBoolValue("policy.signRules.autoAddRule.enable", false);
	}
	get "policy.signRules.autoAddRule.onlyIfFromAddressInSDID"() {
		return this.#tryGetBoolValue("policy.signRules.autoAddRule.onlyIfFromAddressInSDID", true);
	}
	/**
	 * - 0: from address
	 * - 1: subdomain
	 * - 2: base domain
	 */
	get "policy.signRules.autoAddRule.for"() {
		return this.#tryGetNumberValue("policy.signRules.autoAddRule.for", 0);
	}
	get "policy.signRules.sdid.allowSubDomains"() {
		return this.#tryGetBoolValue("policy.signRules.sdid.allowSubDomains", true);
	}
	get "policy.signRules.error.wrong_sdid.asWarning"() {
		return this.#tryGetBoolValue("policy.signRules.error.wrong_sdid.asWarning", false);
	}

	get "policy.DMARC.shouldBeSigned.enable"() {
		return this.#tryGetBoolValue("policy.DMARC.shouldBeSigned.enable", false);
	}
	/**
	 * - none
	 * - quarantine
	 * - reject
	 */
	get "policy.DMARC.shouldBeSigned.neededPolicy"() {
		return this.#tryGetStringValue("policy.DMARC.shouldBeSigned.neededPolicy", "none");
	}

	/**
	 * @enum {number}
	 * @readonly
	 */
	static POLICY_DKIM_UNSIGNED_HEADERS_WARNING_MODE = {
		/** @readonly */
		RELAXED: 10,
		/** @readonly */
		RECOMMENDED: 20,
		/** @readonly */
		STRICT: 30,
	};
	/**
	 * @returns {POLICY_DKIM_UNSIGNED_HEADERS_WARNING_MODE}
	 */
	get "policy.dkim.unsignedHeadersWarning.mode"() {
		return this.#tryGetNumberValue("policy.dkim.unsignedHeadersWarning.mode", 10);
	}
	//#endregion

	////////////////////////////////////////////////////////////////////////////
	//#region Display preferences
	////////////////////////////////////////////////////////////////////////////

	/**
	 * -  0:  never
	 * - 10:  when an e-mail with a valid DKIM signature is viewed  (SUCCESS)
	 * - 20:  when an e-mail with a valid DKIM signature is viewed (including TEMPFAIL) (SUCCESS, TEMPFAIL)
	 * - 30:  when an e-mail with a DKIM signature is viewed (SUCCESS, TEMPFAIL, PERMFAIL, loading)
	 * - 40:  when an e-mail is viewed
	 * - 50:  when a message is viewed
	 */
	get "showDKIMHeader"() {
		return this.#tryGetNumberValue("showDKIMHeader", 30);
	}
	/**
	 * -  0:  never
	 * - 10:  when an e-mail with a valid DKIM signature is viewed  (SUCCESS)
	 * - 20:  when an e-mail with a valid DKIM signature is viewed (including TEMPFAIL) (SUCCESS, TEMPFAIL)
	 * - 30:  when an e-mail with a DKIM signature is viewed (SUCCESS, TEMPFAIL, PERMFAIL, loading)
	 * - 40:  when an e-mail is viewed
	 * - 50:  when a message is viewed
	 */
	get "showDKIMFromTooltip"() {
		return this.#tryGetNumberValue("showDKIMFromTooltip", 0);
	}

	get "colorFrom"() {
		return this.#tryGetBoolValue("colorFrom", false);
	}
	get "color.success.text"() {
		return this.#tryGetStringValue("color.success.text", "windowtext");
	}
	get "color.success.background"() {
		return this.#tryGetStringValue("color.success.background", "#00FF00");
	}
	get "color.warning.text"() {
		return this.#tryGetStringValue("color.warning.text", "windowtext");
	}
	get "color.warning.background"() {
		return this.#tryGetStringValue("color.warning.background", "orange");
	}
	get "color.permfail.text"() {
		return this.#tryGetStringValue("color.permfail.text", "windowtext");
	}
	get "color.permfail.background"() {
		return this.#tryGetStringValue("color.permfail.background", "red");
	}
	get "color.tempfail.text"() {
		return this.#tryGetStringValue("color.tempfail.text", "unset");
	}
	get "color.tempfail.background"() {
		return this.#tryGetStringValue("color.tempfail.background", "unset");
	}
	get "color.nosig.text"() {
		return this.#tryGetStringValue("color.nosig.text", "unset");
	}
	get "color.nosig.background"() {
		return this.#tryGetStringValue("color.nosig.background", "unset");
	}

	get "display.favicon.show"() {
		return this.#tryGetBoolValue("display.favicon.show", true);
	}

	get "display.keySecure"() {
		return this.#tryGetBoolValue("display.keySecure", true);
	}
	//#endregion

	////////////////////////////////////////////////////////////////////////////
	//#region Other preferences
	////////////////////////////////////////////////////////////////////////////

	get "debug"() {
		return this.#tryGetBoolValue("debug", false);
	}
	/**
	 * - Fatal
	 * - Error
	 * - Warn
	 * - Info
	 * - Config
	 * - Debug
	 * - Trace
	 * - All
	 */
	get "logging.console"() {
		return this.#tryGetStringValue("logging.console", "Debug");
	}
	//#endregion

	////////////////////////////////////////////////////////////////////////////
	//#region Account preferences
	////////////////////////////////////////////////////////////////////////////

	/**
	 * @param {string} name
	 * @param {string} account
	 * @param {boolean|number|string} value
	 * @returns {Promise<void>}
	 */
	setAccountValue(name, account, value) {
		if (!Object.prototype.hasOwnProperty.call(BasePreferences.prototype, `account.${name}`)) {
			throw new Error(`Can not set nonexisting account preference "${name}"`);
		}
		if (name === "dkim.enable" || name === "arh.read") {
			if (typeof value !== "number") {
				throw new Error(`Can not set account preference ${name} with type number to a ${typeof value}`);
			}
			if (value < 0 || value > 2) {
				throw new Error(`Can not set account preference ${name} to value ${value}`);
			}
		}
		if (name === "arh.allowedAuthserv") {
			if (typeof value !== "string") {
				throw new Error(`Can not set account preference ${name} with type number to a ${typeof value}`);
			}
		}
		return this._valueSetter(`account.${account}.${name}`, value);
	}

	/**
	 * @param {string} name
	 * @param {string} account
	 * @returns {boolean|number|string}
	 */
	getAccountValue(name, account) {
		if (!Object.prototype.hasOwnProperty.call(BasePreferences.prototype, `account.${name}`)) {
			throw new Error(`Can not get nonexisting account preference "${name}"`);
		}
		if (name === "dkim.enable" || name === "arh.read") {
			return this.#tryGetNumberValue(`account.${account}.${name}`, 0);
		}
		/** @type {any} */
		const that = this;
		return that[`account.${name}`](account);
	}

	/**
	 * Get an boolean account preference that has a global default.
	 *
	 * @param {string} name
	 * @param {string|undefined} account
	 * @returns {boolean}
	 */
	#getAccountBoolWithDefault(name, account) {
		if (!account) {
			return this.getBool(name);
		}
		// 0: default, 1: yes, 2: no
		const accBool = this.#tryGetNumberValue(`account.${account}.${name}`, 0);
		switch (accBool) {
			case 0:
				return this.getBool(name);
			case 1:
				return true;
			case 2:
				return false;
			default:
				throw new Error(`Account preference ${name} has unexpected value ${accBool}`);
		}
	}

	/**
	 * @param {string|undefined} account
	 * @returns {boolean}
	 */
	"account.dkim.enable"(account) {
		return this.#getAccountBoolWithDefault("dkim.enable", account);
	}

	/**
	 * @param {string|undefined} account
	 * @returns {boolean}
	 */
	"account.arh.read"(account) {
		return this.#getAccountBoolWithDefault("arh.read", account);
	}

	/**
	 * @param {string|undefined} account
	 * @returns {string}
	 */
	"account.arh.allowedAuthserv"(account) {
		return this.#tryGetStringValue(`account.${account}.arh.allowedAuthserv`, "");
	}
	//#endregion
}

/**
 * Preference implementation backed by a simple Object.
 * Used for testing only.
 */
export class ObjPreferences extends BasePreferences {
	constructor() {
		super(
			(name) => { return this._prefs[name]; },
			(name, value) => { this._prefs[name] = value; return Promise.resolve(); },
		);
	}
}

/**
 * Preference implementation backed by browser.storage.local.
 * Keeps itself in sync with the storage.
 */
export class StorageLocalPreferences extends BasePreferences {
	constructor() {
		const checkInitialized = () => {
			if (!this._isInitialized) {
				throw new Error("StorageLocalPreferences is not yet initialized");
			}
		};
		super(
			(name) => {
				checkInitialized();
				return this._prefs[name];
			},
			(name, value) => {
				checkInitialized();
				this._prefs[name] = value;
				const promise = browser.storage.local.set({ [name]: value });
				promise.catch(error => log.fatal("Storing preferences in browser.storage.local failed", error));
				return promise;
			},
		);
		/** @private */
		this._isInitialized = false;
	}

	/**
	 * @override
	 */
	async init() {
		if (this._isInitializedDeferred) {
			return this._isInitializedDeferred.promise;
		}
		/**
		 * @private
		 * @type {Deferred<void>}
		 */
		this._isInitializedDeferred = new Deferred();
		try {
			const preferences = await ExtensionUtils.safeGetLocalStorage();
			if (preferences) {
				for (const dataStorageScope of StorageLocalPreferences.dataStorageScopes) {
					delete preferences[dataStorageScope];
				}
				this._prefs = preferences;
			}
			browser.storage.onChanged.addListener((changes, areaName) => {
				if (areaName !== "local") {
					return;
				}
				for (const [name, change] of Object.entries(changes)) {
					this._prefs[name] = change.newValue;
				}
			});
			this._isInitialized = true;
			this._isInitializedDeferred.resolve();
		} catch (error) {
			this._isInitializedDeferred.reject(error);
		}
		return this._isInitializedDeferred.promise;
	}

	/**
	 * @override
	 */
	async clear() {
		/** @type {{scope: string, data: any}[]} */
		const dataStorages = [];
		for (const dataStorageScope of StorageLocalPreferences.dataStorageScopes) {
			const data = (await browser.storage.local.get(dataStorageScope))[dataStorageScope];
			if (data) {
				dataStorages.push({
					scope: dataStorageScope,
					data,
				});
			}
		}

		this._prefs = {};
		await browser.storage.local.clear();

		for (const dataStorage of dataStorages) {
			await browser.storage.local.set({ [dataStorage.scope]: dataStorage.data });
		}
	}
}
/**
 * List of scope names that contain other data than preferences in browser.storage
 */
StorageLocalPreferences.dataStorageScopes = [
	"signRulesUser",
	"keyStore"
];

const prefs = new StorageLocalPreferences();
export default prefs;
