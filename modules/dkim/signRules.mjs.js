/**
 * Check DKIM signing rules.
 *
 * Copyright (c) 2013-2018;2020-2023 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="../../RuntimeMessage.d.ts" />
///<reference path="../../experiments/mailUtils.d.ts" />
/* eslint-env webextensions */

import { Deferred, addrIsInDomain, copy, stringEndsWith, stringEqual } from "../utils.mjs.js";
import { DKIM_InternalError } from "../error.mjs.js";
import ExtensionUtils from "../extensionUtils.mjs.js";
import Logging from "../logging.mjs.js";
import prefs from "../preferences.mjs.js";

const log = Logging.getLogger("SignRules");

/** @typedef {import("./verifier.mjs.js").dkimSigResultV2} dkimSigResultV2 */

/**
 * DKIM signing policy for a message.
 *
 * @typedef {object} DKIMSignPolicy
 * @property {boolean} shouldBeSigned True if message should be signed.
 * @property {string[]} sdid Signing Domain Identifier.
 * @property {boolean} foundRule True if enabled rule for message was found.
 * @property {boolean} hideFail True if HIDEFAIL rule was found.
 */

/**
 * rule types
 *
 * @public
 */
const RULE_TYPE = {
	ALL: 1, // all e-mails must be signed
	NEUTRAL: 2,
	HIDEFAIL: 3, // treat invalid signatures as nosig
};

/**
 * default rule priorities
 *
 * @public
 */
const PRIORITY = {
	AUTOINSERT_RULE_ALL: 1100,
	DEFAULT_RULE_ALL0: 2000, // used for e-mail providers
	USERINSERT_RULE_HIDEFAIL: 2050,
	DEFAULT_RULE_ALL: 2100,
	DEFAULT_RULE_ALL_2: 2110, // used for different SDID for subdomains
	DEFAULT_RULE_NEUTRAL: 2200,
	USERINSERT_RULE_ALL: 3100,
	USERINSERT_RULE_NEUTRAL: 3200,
};

const AUTO_ADD_RULE_FOR = {
	FROM_ADDRESS: 0,
	SUB_DOMAIN: 1,
	BASE_DOMAIN: 2,
};

/**
 * Exported DKIM user signing rule.
 *
 * @typedef {object} DkimExportedUserSignRule
 * @property {string} domain
 * @property {string} listId
 * @property {string} addr
 * @property {string} sdid - space separated list of SDIDs
 * @property {number} type
 * @property {number} priority
 * @property {boolean} enabled
 */

/**
 * Exported DKIM user signing rules.
 *
 * @typedef {object} DkimExportedUserSignRules
 * @property {"DkimExportedUserSignRules"} dataId
 * @property {1} dataFormatVersion
 * @property {DkimExportedUserSignRule[]} rules
 */

/**
 * DKIM user signing rule.
 *
 * @typedef {object} DkimSignRuleUser
 * @property {number} id
 * @property {string} domain
 * @property {string} listId
 * @property {string} addr
 * @property {string} sdid - space separated list of SDIDs
 * @property {number} type
 * @property {number} priority
 * @property {boolean} enabled
 */

/**
 * DKIM default signing rule.
 *
 * @typedef {object} DkimSignRuleDefault
 * @property {string} domain
 * @property {string} addr
 * @property {string} sdid - space separated list of SDIDs
 * @property {number} type
 * @property {number} priority
 */

/**
 * Stored DKIM user signing rules.
 *
 * @typedef {object} DkimStoredUserSignRules
 * @property {number} maxId
 * @property {DkimSignRuleUser[]} rules
 */

/** @type {Deferred<void>?} */
let defaultRulesLoaded = null;
/** @type {DkimSignRuleDefault[]} */
let defaultRules = [];
/** @type {Deferred<void>?} */
let userRulesLoaded = null;
let userRulesMaxId = 0;
/** @type {DkimSignRuleUser[]} */
let userRules = [];

/**
 * Loads the default rules if needed.
 *
 * @returns {Promise<void>}
 */
async function loadDefaultRules() {
	if (defaultRulesLoaded !== null) {
		return defaultRulesLoaded.promise;
	}
	defaultRulesLoaded = new Deferred();
	try {
		const signersDefaultStr = await ExtensionUtils.readFile("data/signersDefault.json");
		/** @type {{rules: {domain: string, addr: string, sdid: string, ruletype: string, priority: string}[]}} */
		const signersDefaultData = JSON.parse(signersDefaultStr);
		defaultRules = signersDefaultData.rules.map((rule) => {
			/** @type {number|undefined} */
			// @ts-expect-error
			const type = RULE_TYPE[rule.ruletype];
			if (type === undefined) {
				throw new Error(`unknown rule type ${rule.ruletype}`);
			}

			/** @type {number|undefined} */
			// @ts-expect-error
			const priority = PRIORITY[rule.priority];
			if (priority === undefined) {
				throw new Error(`unknown priority ${rule.priority}`);
			}

			return {
				domain: rule.domain,
				addr: rule.addr,
				sdid: rule.sdid,
				type,
				priority,
			};
		});
		defaultRulesLoaded.resolve();
	} catch (error) {
		defaultRulesLoaded.reject(error);
	}
	return defaultRulesLoaded.promise;
}

/**
 * Loads the user rules if needed.
 *
 * @returns {Promise<void>}
 */
async function loadUserRules() {
	if (userRulesLoaded !== null) {
		return userRulesLoaded.promise;
	}
	userRulesLoaded = new Deferred();
	try {
		/** @type {DkimStoredUserSignRules|undefined} */
		const storedUserRules = (await browser.storage.local.get("signRulesUser")).signRulesUser;
		if (storedUserRules !== undefined) {
			userRulesMaxId = storedUserRules.maxId;
			userRules = storedUserRules.rules;
		}
		userRulesLoaded.resolve();
	} catch (error) {
		userRulesLoaded.reject(error);
	}
	return userRulesLoaded.promise;
}

/**
 * Store the user rules.
 *
 * @returns {Promise<void>}
 */
async function storeUserRules() {
	await browser.storage.local.set({ signRulesUser: { maxId: userRulesMaxId, rules: userRules } });
}

/**
 * Match a pattern to a string there '*' matches zero or more characters.
 *
 * @param {string} str
 * @param {string} pattern
 * @returns {boolean}
 */
function glob(str, pattern) {
	// escape all special regex charters besides *
	let regexpPattern = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
	// replace * with correct regex
	regexpPattern = regexpPattern.replace("*", ".*");

	const regexp = new RegExp(`^${regexpPattern}$`, "i");
	return regexp.test(str);
}

/**
 * @typedef { import("./dmarc.mjs.js").default } DMARC
 */

/**
 * Determinate if an e-mail by fromAddress should be signed.
 *
 * @param {string} fromAddress
 * @param {string?} [listId]
 * @param {DMARC} [dmarc]
 * @returns {Promise<DKIMSignPolicy>}
 */
async function checkIfShouldBeSigned(fromAddress, listId, dmarc) {
	await loadUserRules();
	/** @type {(DkimSignRuleDefault|DkimSignRuleUser)[]} */
	let matchedRules = userRules.filter(rule => {
		if (!rule.enabled) {
			return false;
		}
		if (!addrIsInDomain(fromAddress, rule.domain) &&
			(!rule.listId || listId !== rule.listId)
		) {
			return false;
		}
		if (!glob(fromAddress, rule.addr)) {
			return false;
		}
		return true;
	});
	if (prefs["policy.signRules.checkDefaultRules"]) {
		await loadDefaultRules();
		matchedRules = matchedRules.concat(defaultRules.filter(rule => {
			if (!addrIsInDomain(fromAddress, rule.domain)) {
				return false;
			}
			if (!glob(fromAddress, rule.addr)) {
				return false;
			}
			return true;
		}));
	}
	/** @type {DkimSignRuleDefault|DkimSignRuleUser|undefined} */
	const rule = matchedRules.sort((a, b) => b.priority - a.priority)[0];
	if (!rule) {
		if (dmarc) {
			const dmarcRes = await dmarc.shouldBeSigned(fromAddress);
			return {
				shouldBeSigned: dmarcRes.shouldBeSigned,
				sdid: dmarcRes.sdid,
				foundRule: false,
				hideFail: false,
			};
		}
		return {
			shouldBeSigned: false,
			sdid: [],
			foundRule: false,
			hideFail: false,
		};
	}

	let shouldBeSigned;
	let hideFail;
	switch (rule.type) {
		case RULE_TYPE.ALL:
			shouldBeSigned = true;
			hideFail = false;
			break;
		case RULE_TYPE.NEUTRAL:
			shouldBeSigned = false;
			hideFail = false;
			break;
		case RULE_TYPE.HIDEFAIL:
			shouldBeSigned = false;
			hideFail = true;
			break;
		default:
			throw new Error(`unknown rule type ${rule.type}`);
	}
	return {
		shouldBeSigned,
		sdid: rule.sdid.split(" ").filter(x => x),
		foundRule: true,
		hideFail,
	};
}

/**
 * Checks the SDID and AUID of a DKIM signatures.
 *
 * @param {dkimSigResultV2} dkimResult
 * @param {string[]} allowedSDIDs
 * @returns {dkimSigResultV2}
 */
function checkSDID(dkimResult, allowedSDIDs) {
	const result = copy(dkimResult);
	// Nothing to check if there are no allowed SDIDs defined
	if (allowedSDIDs.length === 0) {
		return result;
	}
	if (!dkimResult.sdid) {
		// this can happen if e.g. the parsing fails
		log.debug("skipped SDID/AUID check, as at least one is undefined");
		return result;
	}
	const sdid = dkimResult.sdid;
	if (result.warnings === undefined) {
		result.warnings = [];
	}

	// Remove potential warning that address is not in SDID or AUID,
	// as the allowed SDIDs are explicitly stated via the sign rules
	result.warnings = result.warnings.filter(warning => {
		return warning.name !== "DKIM_SIGWARNING_FROM_NOT_IN_SDID" &&
			warning.name !== "DKIM_SIGWARNING_FROM_NOT_IN_AUID";
	});

	// error/warning if there is a SDID in the sign rule
	// that is different from the SDID in the signature
	if (!allowedSDIDs.some((element/*, index, array*/) => {
		if (prefs["policy.signRules.sdid.allowSubDomains"]) {
			return stringEndsWith(sdid, element);
		}
		return stringEqual(sdid, element);
	})) {
		if (prefs["policy.signRules.error.wrong_sdid.asWarning"]) {
			result.warnings.push(
				{ name: "DKIM_POLICYERROR_WRONG_SDID", params: [allowedSDIDs] });
			log.debug("Warning: DKIM_POLICYERROR_WRONG_SDID");
		} else {
			return {
				version: "2.0",
				result: "PERMFAIL",
				errorType: "DKIM_POLICYERROR_WRONG_SDID",
				errorStrParams: allowedSDIDs,
			};
		}
	}

	return result;
}

export default class SignRules {
	/** @readonly */
	static get TYPE() {
		return RULE_TYPE;
	}

	/** @readonly */
	static get PRIORITY() {
		return PRIORITY;
	}

	static async getDefaultRules() {
		await loadDefaultRules();
		return defaultRules;
	}

	static async getUserRules() {
		await loadUserRules();
		return userRules;
	}

	/**
	 * Get the user sign rules in the export format.
	 *
	 * @returns {Promise<DkimExportedUserSignRules>}
	 */
	static async exportUserRules() {
		/** @type {{id?: number, domain: string, listId: string, addr: string, sdid: string, type: number, priority: number, enabled: boolean }[]} */
		const rules = copy(await this.getUserRules());
		rules.map(rule => { delete rule.id; return rule; });
		return {
			dataId: "DkimExportedUserSignRules",
			dataFormatVersion: 1,
			rules,
		};
	}

	/**
	 * Import the given user sign rules.
	 *
	 * @param {{dataId: string, dataFormatVersion: number}} data
	 * @param {boolean} replace
	 * @returns {Promise<void>}
	 */
	static async importUserRules(data, replace) {
		if (data.dataId !== "DkimExportedUserSignRules") {
			throw new Error("ERROR_IMPORT_RULES_UNKNOWN_DATA");
		}
		if (data.dataFormatVersion !== 1) {
			throw new Error("ERROR_IMPORT_RULES_UNSUPPORTED_FORMAT");
		}
		/** @type {DkimExportedUserSignRules} */
		// @ts-expect-error
		const exportedRules = data;

		// Costly but easy way to ensure a race condition with loading the rules does not happen.
		await loadUserRules();

		let maxId = userRulesMaxId;
		if (replace) {
			maxId = 0;
			userRules = [];
		}
		userRules = userRules.concat(exportedRules.rules.map(rule => ({ id: ++maxId, ...rule })));
		userRulesMaxId = maxId;

		await storeUserRules();

		browser.runtime.sendMessage({ event: "ruleAdded" }).
			catch(error => log.debug("Error sending ruleAdded event", error));
	}

	/**
	 * Checks the DKIM result against the sign rules.
	 *
	 * @param {dkimSigResultV2} dkimResult
	 * @param {string} from
	 * @param {string?} [listId]
	 * @param {function(void): Promise<boolean>} [isOutgoingCallback]
	 * @param {DMARC} [dmarc]
	 * @returns {Promise<dkimSigResultV2>}
	 */
	static async check(dkimResult, from, listId, isOutgoingCallback, dmarc) {
		await prefs.init();

		const policy = await checkIfShouldBeSigned(from, listId, dmarc);
		log.debug("shouldBeSigned: ", policy);
		if (dkimResult.result === "none") {
			if (policy.shouldBeSigned && !(isOutgoingCallback && await isOutgoingCallback())) {
				return {
					version: "2.0",
					result: "PERMFAIL",
					errorType: "DKIM_POLICYERROR_MISSING_SIG",
					errorStrParams: policy.sdid,
					hideFail: policy.hideFail,
				};
			}
			return copy(dkimResult);
		}

		const result = checkSDID(dkimResult, policy.sdid);
		if (policy.hideFail) {
			result.hideFail = true;
		}
		if (!policy.foundRule) {
			await SignRules.#autoAddRule(from, dkimResult);
		}
		return result;
	}

	/**
	 * Clear the user rules.
	 *
	 * @returns {Promise<void>}
	 */
	static clearRules() {
		userRulesLoaded = null;
		userRules = [];
		userRulesMaxId = 0;
		return browser.storage.local.remove("signRulesUser");
	}

	/**
	 * Add user rule.
	 *
	 * @param {string?} domain
	 * @param {string?} listId
	 * @param {string} addr
	 * @param {string} sdid - space separated list of SDIDs
	 * @param {number} type
	 * @param {number?} priority
	 * @param {boolean} enabled
	 * @returns {Promise<void>}
	 */
	static async addRule(domain, listId, addr, sdid, type, priority = null, enabled = true) {
		let ruleDomain = domain;
		if (!ruleDomain && !listId) {
			ruleDomain = await browser.mailUtils.getBaseDomainFromAddr(addr);
		}

		if (!Object.values(RULE_TYPE).includes(type)) {
			throw new Error(`unknown rule type ${type}`);
		}

		let rulePriority = priority;
		if (rulePriority === null) {
			switch (type) {
				case RULE_TYPE.ALL:
					rulePriority = PRIORITY.USERINSERT_RULE_ALL;
					break;
				case RULE_TYPE.NEUTRAL:
					rulePriority = PRIORITY.USERINSERT_RULE_NEUTRAL;
					break;
				case RULE_TYPE.HIDEFAIL:
					rulePriority = PRIORITY.USERINSERT_RULE_HIDEFAIL;
					break;
				default:
					throw new Error(`unknown rule type ${type}`);
			}
		}

		await loadUserRules();
		userRules.push({
			id: ++userRulesMaxId,
			domain: ruleDomain ?? "",
			listId: listId ?? "",
			addr,
			sdid,
			type,
			priority: rulePriority,
			enabled,
		});
		await storeUserRules();

		browser.runtime.sendMessage({ event: "ruleAdded" }).
			catch(error => log.debug("Error sending ruleAdded event", error));
	}

	/**
	 * Adds neutral rule for fromAddress with priority USERINSERT_RULE_NEUTRAL.
	 *
	 * @param {string} fromAddress
	 * @returns {Promise<void>}
	 */
	static async addException(fromAddress) {
		await loadUserRules();
		const foundUserException = userRules.some(rule => {
			if (!rule.enabled) {
				return false;
			}
			if (rule.type !== RULE_TYPE.NEUTRAL) {
				return false;
			}
			if (rule.priority !== PRIORITY.USERINSERT_RULE_NEUTRAL) {
				return false;
			}
			if (!addrIsInDomain(fromAddress, rule.domain)) {
				return false;
			}
			if (!stringEqual(fromAddress, rule.addr)) {
				return false;
			}
			return true;
		});

		if (!foundUserException) {
			await SignRules.addRule(null, null, fromAddress, "", RULE_TYPE.NEUTRAL, PRIORITY.USERINSERT_RULE_NEUTRAL);
		}
	}

	/**
	 * Update the user rule with the given id.
	 *
	 * @param {number} id
	 * @param {string} propertyName
	 * @param {any} newValue
	 * @returns {Promise<void>}
	 */
	static async updateRule(id, propertyName, newValue) {
		await loadUserRules();
		const userRule = userRules.find(rule => rule.id === id);
		if (!userRule) {
			throw new Error(`Can not update non existing rule with id '${id}'`);
		}
		switch (propertyName) {
			case "domain":
			case "listId":
			case "addr":
			case "sdid":
				if (typeof newValue !== "string") {
					throw new Error(`Can not set ${propertyName} to value '${newValue}' with type ${typeof newValue}`);
				}
				userRule[propertyName] = newValue;
				break;
			case "type":
			case "priority":
				if (typeof newValue !== "number") {
					throw new Error(`Can not set ${propertyName} to value '${newValue}' with type ${typeof newValue}`);
				}
				userRule[propertyName] = newValue;
				break;
			case "enabled":
				if (typeof newValue !== "boolean") {
					throw new Error(`Can not set domain to value '${newValue}' with type ${typeof newValue}`);
				}
				userRule[propertyName] = newValue;
				break;
			default:
				throw new Error(`Can not update unknown property '${propertyName}'`);
		}
		return storeUserRules();
	}

	/**
	 * Delete the user rule with the given id.
	 *
	 * @param {number} id
	 * @returns {Promise<void>}
	 */
	static async deleteRule(id) {
		await loadUserRules();
		const ruleIndex = userRules.findIndex(rule => rule.id === id);
		if (ruleIndex === -1) {
			throw new Error(`Can not delete non existing rule with id '${id}'`);
		}
		userRules.splice(ruleIndex, 1);
		return storeUserRules();
	}

	/**
	 * Adds should be signed rule if no enabled rule for fromAddress is found.
	 *
	 * @param {string} fromAddress
	 * @param {dkimSigResultV2} dkimResult
	 * @returns {Promise<void>}
	 */
	static #autoAddRule(fromAddress, dkimResult) {
		const promise = (async () => {
			if (dkimResult.result !== "SUCCESS") {
				return;
			}

			// return if autoAddRule is disabled
			if (!prefs["policy.signRules.autoAddRule.enable"]) {
				return;
			}

			if (!dkimResult.sdid || !dkimResult.auid) {
				throw new Error("DKIM result has no sdid or auid");
			}
			const sdid = dkimResult.sdid;

			// return if fromAddress is not in SDID
			// and options state it should
			if (!addrIsInDomain(fromAddress, sdid) &&
				prefs["policy.signRules.autoAddRule.onlyIfFromAddressInSDID"]
			) {
				return;
			}

			const shouldBeSignedRes = await checkIfShouldBeSigned(fromAddress);
			if (!shouldBeSignedRes.foundRule) {
				let domain = null;
				let fromAddressToAdd;

				switch (prefs["policy.signRules.autoAddRule.for"]) {
					case AUTO_ADD_RULE_FOR.FROM_ADDRESS:
						fromAddressToAdd = fromAddress;
						break;
					case AUTO_ADD_RULE_FOR.SUB_DOMAIN:
						fromAddressToAdd = `*${fromAddress.substr(fromAddress.lastIndexOf("@"))}`;
						break;
					case AUTO_ADD_RULE_FOR.BASE_DOMAIN:
						domain = await browser.mailUtils.getBaseDomainFromAddr(fromAddress);
						fromAddressToAdd = "*";
						break;
					default:
						throw new DKIM_InternalError("invalid signRules.autoAddRule.for");
				}
				await SignRules.addRule(domain, null, fromAddressToAdd, sdid, RULE_TYPE.ALL, PRIORITY.AUTOINSERT_RULE_ALL);
			}
		})();
		promise.then(null, (exception) => {
			// Failure!  We can inspect or report the exception.
			log.fatal("Error adding an automatic rule:", exception);
		});
		return promise;
	}
}

/**
 * Setup listening for the calls done through SignRulesProxy.
 * IMPORTANT: must only be called once.
 *
 * @returns {void}
 */
export function initSignRulesProxy() {
	browser.runtime.onMessage.addListener((runtimeMessage, sender /*, sendResponse*/) => {
		if (sender.id !== "dkim_verifier@pl") {
			return;
		}
		if (typeof runtimeMessage !== "object" || runtimeMessage === null) {
			return;
		}
		/** @type {RuntimeMessage.Messages} */
		const request = runtimeMessage;
		if (request.module !== "SignRules") {
			return;
		}
		if (request.method === "getDefaultRules") {
			// eslint-disable-next-line consistent-return
			return SignRules.getDefaultRules();
		}
		if (request.method === "getUserRules") {
			// eslint-disable-next-line consistent-return
			return SignRules.getUserRules();
		}
		if (request.method === "exportUserRules") {
			// eslint-disable-next-line consistent-return
			return SignRules.exportUserRules();
		}
		if (request.method === "importUserRules") {
			// eslint-disable-next-line consistent-return
			return SignRules.importUserRules(request.parameters.data, request.parameters.replace);
		}
		if (request.method === "updateRule") {
			// eslint-disable-next-line consistent-return
			return SignRules.updateRule(request.parameters.id, request.parameters.propertyName, request.parameters.newValue);
		}
		if (request.method === "addRule") {
			// eslint-disable-next-line consistent-return
			return SignRules.addRule(
				request.parameters.domain,
				request.parameters.listId,
				request.parameters.addr,
				request.parameters.sdid,
				request.parameters.type,
				request.parameters.priority,
				request.parameters.enabled,
			);
		}
		if (request.method === "deleteRule") {
			// eslint-disable-next-line consistent-return
			return SignRules.deleteRule(request.parameters.id);
		}
		log.error("SignRules proxy receiver got unknown request.", request);
		throw new Error("SignRules proxy receiver got unknown request.");
	});
}
