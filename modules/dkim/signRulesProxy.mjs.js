/**
 * Proxy to a singleton SignRules to avoid problems with race conditions
 * when accessing browser.storage.local.
 *
 * Copyright (c)2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="../../WebExtensions.d.ts" />
/* eslint-env webextensions */

export default class SignRulesProxy {
	/** @readonly */
	static get TYPE() {
		return {
			ALL: 1, // all e-mails must be signed
			NEUTRAL: 2,
			HIDEFAIL: 3, // treat invalid signatures as nosig
		};
	}

	/** @readonly */
	static get PRIORITY() {
		return {
			AUTOINSERT_RULE_ALL: 1100,
			DEFAULT_RULE_ALL0: 2000, // used for e-mail providers
			USERINSERT_RULE_HIDEFAIL: 2050,
			DEFAULT_RULE_ALL: 2100,
			DEFAULT_RULE_ALL_2: 2110, // used for different SDID for subdomains
			DEFAULT_RULE_NEUTRAL: 2200,
			USERINSERT_RULE_ALL: 3100,
			USERINSERT_RULE_NEUTRAL: 3200,
		};
	}

	// eslint-disable-next-line valid-jsdoc
	/**
	 * @returns {Promise<import("./signRules.mjs").DkimSignRuleDefault[]>}
	 */
	static getDefaultRules() {
		return browser.runtime.sendMessage({
			method: "getDefaultRules"
		});
	}

	// eslint-disable-next-line valid-jsdoc
	/**
	 * @returns {Promise<import("./signRules.mjs").DkimSignRuleUser[]>}
	 */
	static getUserRules() {
		return browser.runtime.sendMessage({
			method: "getUserRules"
		});
	}

	/**
	 * Add user rule.
	 *
	 * @param {string?} domain
	 * @param {string?} listId
	 * @param {string} addr
	 * @param {string} sdid
	 * @param {number} type
	 * @param {number?} priority
	 * @param {boolean} enabled
	 * @returns {Promise<void>}
	 */
	static addRule(domain, listId, addr, sdid, type, priority, enabled) {
		return browser.runtime.sendMessage({
			method: "addRule",
			parameters: {
				domain: domain,
				listId: listId,
				addr: addr,
				sdid: sdid,
				type: type,
				priority: priority,
				enabled: enabled,
			},
		});
	}

	/**
	 * Update the user rule with the given id.
	 *
	 * @param {number} id
	 * @param {string} propertyName
	 * @param {any} newValue
	 * @returns {Promise<void>}
	 */
	static updateRule(id, propertyName, newValue) {
		return browser.runtime.sendMessage({
			method: "updateRule",
			parameters: {
				id: id,
				propertyName: propertyName,
				newValue: newValue,
			},
		});
	}

	/**
	 * Delete the user rule with the given id.
	 *
	 * @param {number} id
	 * @returns {Promise<void>}
	 */
	static deleteRule(id) {
		return browser.runtime.sendMessage({
			method: "deleteRule",
			parameters: {
				id: id,
			},
		});
	}
}
