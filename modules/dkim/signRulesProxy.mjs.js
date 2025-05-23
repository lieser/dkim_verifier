/**
 * Proxy to a singleton SignRules to avoid problems with race conditions
 * when accessing browser.storage.local.
 *
 * Copyright (c) 2020-2021;2024 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="../../RuntimeMessage.d.ts" />

export default class SignRulesProxy {
	/**
	 * @returns {Promise<import("./signRules.mjs.js").DkimSignRuleDefault[]>}
	 */
	static getDefaultRules() {
		/** @type {RuntimeMessage.SignRules.getDefaultRules} */
		const message = {
			module: "SignRules",
			method: "getDefaultRules",
		};
		return browser.runtime.sendMessage(message);
	}

	/**
	 * @returns {Promise<import("./signRules.mjs.js").DkimSignRuleUser[]>}
	 */
	static getUserRules() {
		/** @type {RuntimeMessage.SignRules.getUserRules} */
		const message = {
			module: "SignRules",
			method: "getUserRules",
		};
		return browser.runtime.sendMessage(message);
	}

	/**
	 * Get the user sign rules in the export format.
	 *
	 * @returns {Promise<import("./signRules.mjs.js").DkimExportedUserSignRules>}
	 */
	static exportUserRules() {
		/** @type {RuntimeMessage.SignRules.exportUserRules} */
		const message = {
			module: "SignRules",
			method: "exportUserRules",
		};
		return browser.runtime.sendMessage(message);
	}

	/**
	 * Import the given user sign rules.
	 *
	 * @param {any} data
	 * @param {boolean} replace
	 * @returns {Promise<void>}
	 */
	static importUserRules(data, replace) {
		/** @type {RuntimeMessage.SignRules.importUserRules} */
		const message = {
			module: "SignRules",
			method: "importUserRules",
			parameters: {
				data,
				replace,
			},
		};
		return browser.runtime.sendMessage(message);
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
		/** @type {RuntimeMessage.SignRules.addRule} */
		const message = {
			module: "SignRules",
			method: "addRule",
			parameters: {
				domain,
				listId,
				addr,
				sdid,
				type,
				priority,
				enabled,
			},
		};
		return browser.runtime.sendMessage(message);
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
		/** @type {RuntimeMessage.SignRules.updateRule} */
		const message = {
			module: "SignRules",
			method: "updateRule",
			parameters: {
				id,
				propertyName,
				newValue,
			},
		};
		return browser.runtime.sendMessage(message);
	}

	/**
	 * Delete the user rules with the given IDs.
	 *
	 * @param {number[]} ids
	 * @returns {Promise<void>}
	 */
	static deleteRules(ids) {
		/** @type {RuntimeMessage.SignRules.deleteRules} */
		const message = {
			module: "SignRules",
			method: "deleteRules",
			parameters: {
				ids,
			},
		};
		return browser.runtime.sendMessage(message);
	}
}
