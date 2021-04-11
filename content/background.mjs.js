/**
 * Copyright (c) 2020-2021 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="../WebExtensions.d.ts" />
///<reference path="../RuntimeMessage.d.ts" />
///<reference path="../experiments/dkimHeader.d.ts" />
/* eslint-env browser, webextensions */

import KeyStore, { KeyDb } from "../modules/dkim/keyStore.mjs.js";
import SignRules, { initSignRulesProxy } from "../modules/dkim/signRules.mjs.js";
import { migrateKeyStore, migratePrefs, migrateSignRulesUser } from "../modules/migration.mjs.js";
import AuthVerifier from "../modules/authVerifier.mjs.js";
import Logging from "../modules/logging.mjs.js";
import MsgParser from "../modules/msgParser.mjs.js";
import prefs from "../modules/preferences.mjs.js";

const log = Logging.getLogger("background");

async function init() {
	await Logging.initLogLevelFromPrefs();

	await migratePrefs();
	await prefs.init();

	await migrateSignRulesUser();
	initSignRulesProxy();

	await migrateKeyStore();
	KeyDb.initProxy();
}
const isInitialized = init();
isInitialized.catch(error => log.fatal("Initializing failed with:", error));

/**
 * A cache of the current results displayed in the tabs.
 * Needed for the actions triggered by the user in the display header.
 */
/** @type {Map.<number, import("../modules/authVerifier.mjs.js").AuthResult>} */
const displayedResultsCache = new Map();
browser.tabs.onRemoved.addListener((tabId) => {
	displayedResultsCache.delete(tabId);
});

const SHOW = {
	NEVER: 0,
	DKIM_VALID: 10,
	DKIM_VALID_ALL: 20,
	DKIM_SIGNED: 30,
	EMAIL: 40,
	MSG: 50,
};

/**
 * Verify a message in a specific tab and display the result.
 *
 * @param {number} tabId
 * @param {browser.messageDisplay.MessageHeader} message
 * @returns {Promise<void>}
 */
// eslint-disable-next-line complexity
async function verifyMessage(tabId, message) {
	try {
		// show from tooltip if not completely disabled
		if (prefs.showDKIMFromTooltip > SHOW.NEVER) {
			browser.dkimHeader.showFromTooltip(tabId, message.id, true);
		}

		const verifier = new AuthVerifier();
		const res = await verifier.verify(message);
		displayedResultsCache.set(tabId, res);
		const warnings = res.dkim[0].warnings_str || [];
		/** @type {Parameters<typeof browser.dkimHeader.setDkimHeaderResult>[5]} */
		const arh = {};
		if (res.arh && res.arh.dkim && res.arh.dkim[0]) {
			arh.dkim = res.arh.dkim[0].result_str;
		}
		if (res.spf && res.spf[0]) {
			arh.spf = res.spf[0].result;
		}
		if (res.dmarc && res.dmarc[0]) {
			arh.dmarc = res.dmarc[0].result;
		}

		const messageStillDisplayed = await browser.dkimHeader.setDkimHeaderResult(
			tabId,
			message.id,
			res.dkim[0].result_str,
			warnings,
			res.dkim[0].favicon ?? "",
			arh
		);
		if (!messageStillDisplayed) {
			log.debug("Showing of DKIM result skipped because message is no longer displayed");
			return;
		}
		browser.dkimHeader.showDkimHeader(tabId, message.id, prefs.showDKIMHeader >= res.dkim[0].res_num);
		if (prefs.showDKIMFromTooltip > SHOW.NEVER && prefs.showDKIMFromTooltip < res.dkim[0].res_num) {
			browser.dkimHeader.showFromTooltip(tabId, message.id, false);
		}
		if (prefs.colorFrom) {
			switch (res.dkim[0].res_num) {
				case AuthVerifier.DKIM_RES.SUCCESS: {
					const dkim = res.dkim[0];
					if (!dkim.warnings_str || dkim.warnings_str.length === 0) {
						browser.dkimHeader.highlightFromAddress(tabId, message.id, prefs["color.success.text"], prefs["color.success.background"]);
					} else {
						browser.dkimHeader.highlightFromAddress(tabId, message.id, prefs["color.warning.text"], prefs["color.warning.background"]);
					}
					break;
				}
				case AuthVerifier.DKIM_RES.TEMPFAIL:
					browser.dkimHeader.highlightFromAddress(tabId, message.id, prefs["color.tempfail.text"], prefs["color.tempfail.background"]);
					break;
				case AuthVerifier.DKIM_RES.PERMFAIL:
					browser.dkimHeader.highlightFromAddress(tabId, message.id, prefs["color.permfail.text"], prefs["color.permfail.background"]);
					break;
				case AuthVerifier.DKIM_RES.PERMFAIL_NOSIG:
				case AuthVerifier.DKIM_RES.NOSIG:
					browser.dkimHeader.highlightFromAddress(tabId, message.id, prefs["color.nosig.text"], prefs["color.nosig.background"]);
					break;
				default:
					throw new Error(`unknown res_num: ${res.dkim[0].res_num}`);
			}
		}
	} catch (e) {
		log.fatal("Unexpected error during verifyMessage", e);
		browser.dkimHeader.showDkimHeader(tabId, message.id, true);
		browser.dkimHeader.setDkimHeaderResult(
			tabId, message.id, browser.i18n.getMessage("DKIM_INTERNALERROR_NAME"), [], "", {});
	}
}

/**
 * Triggered then a new message is viewed.
 * Will start the verification if needed.
 */
browser.messageDisplay.onMessageDisplayed.addListener(async (tab, message) => {
	try {
		await isInitialized;
		displayedResultsCache.delete(tab.id);

		// Nothing to verify if msg is RSS feed or news
		const account = await browser.accounts.get(message.folder.accountId);
		if (account && (account.type === "rss" || account.type === "nntp")) {
			browser.dkimHeader.showDkimHeader(tab.id, message.id, prefs.showDKIMHeader >= SHOW.MSG);
			browser.dkimHeader.setDkimHeaderResult(
				tab.id, message.id, browser.i18n.getMessage("NOT_EMAIL"), [], "", {});
			return;
		}

		// If we already know that the header should be shown, show it now
		if (prefs.showDKIMHeader >= SHOW.EMAIL) {
			browser.dkimHeader.showDkimHeader(tab.id, message.id, true);
		}
		else {
			const { headers } = await browser.messages.getFull(message.id);
			if (headers && Object.keys(headers).includes("dkim-signature")) {
				if (prefs.showDKIMHeader >= SHOW.DKIM_SIGNED) {
					browser.dkimHeader.showDkimHeader(tab.id, message.id, true);
				}
			}
		}

		await verifyMessage(tab.id, message);
	} catch (e) {
		log.fatal("Unexpected error during onMessageDisplayed", e);
		browser.dkimHeader.showDkimHeader(tab.id, message.id, true);
		browser.dkimHeader.setDkimHeaderResult(
			tab.id, message.id, browser.i18n.getMessage("DKIM_INTERNALERROR_NAME"), [], "", {});
	}
});

/**
 * User actions triggered in the mail header.
 */
class DisplayAction {
	/**
	 * Determinate which user actions should be enabled.
	 *
	 * @param {number} tabId
	 * @returns {RuntimeMessage.DisplayAction.queryButtonStateResult}
	 */
	static queryButtonState(tabId) {
		const res = displayedResultsCache.get(tabId);
		const keyStored = prefs["key.storing"] !== KeyStore.KEY_STORING.DISABLED &&
			res?.dkim[0].sdid !== undefined && res?.dkim[0].selector !== undefined;
		/** @type {RuntimeMessage.DisplayAction.queryButtonStateResult} */
		const state = {
			reverifyDKIMSignature: res !== undefined,
			policyAddUserException:
				res?.dkim[0].errorType === "DKIM_POLICYERROR_MISSING_SIG" ||
				res?.dkim[0].errorType === "DKIM_POLICYERROR_WRONG_SDID" || (
					res?.dkim[0].warnings !== undefined &&
					res?.dkim[0].warnings.findIndex((e) => {
						return e.name === "DKIM_POLICYERROR_WRONG_SDID";
					}) !== -1
				),
			markKeyAsSecure: keyStored && res?.dkim[0].keySecure === false,
			updateKey: keyStored,
		};
		return state;
	}

	/**
	 * Reverify a message in a specific tab and display the result.
	 *
	 * @private
	 * @param {number} tabId
	 * @param {browser.messageDisplay.MessageHeader} message
	 * @returns {Promise<void>}
	 */
	static async _reverifyMessage(tabId, message) {
		browser.dkimHeader.reset(tabId, message.id);
		AuthVerifier.resetResult(message);
		await verifyMessage(tabId, message);
	}

	/**
	 * Reverify the DKIM signature.
	 *
	 * @param {number} tabId
	 * @returns {Promise<void>}
	 */
	static async reverifyDKIMSignature(tabId) {
		const message = await browser.messageDisplay.getDisplayedMessage(tabId);
		await DisplayAction._reverifyMessage(tabId, message);
	}

	/**
	 * Add a user exception to the from address and reverify the message.
	 *
	 * @param {number} tabId
	 * @returns {Promise<void>}
	 */
	static async policyAddUserException(tabId) {
		const message = await browser.messageDisplay.getDisplayedMessage(tabId);

		const from = MsgParser.parseFromHeader(`From: ${message.author}\r\n`);
		await SignRules.addException(from);

		await DisplayAction._reverifyMessage(tabId, message);
	}

	/**
	 * Mark the DKIM key as secure and reverify the message.
	 *
	 * @param {number} tabId
	 * @returns {Promise<void>}
	 */
	static async markKeyAsSecure(tabId) {
		const res = displayedResultsCache.get(tabId);
		const sdid = res?.dkim[0].sdid;
		const selector = res?.dkim[0].selector;
		if (sdid === undefined || selector === undefined) {
			log.error("Can not mark key as secure, result does not contain an sdid or selector", res);
			return;
		}
		await KeyDb.markAsSecure(sdid, selector);

		const message = await browser.messageDisplay.getDisplayedMessage(tabId);
		await DisplayAction._reverifyMessage(tabId, message);
	}

	/**
	 * Update the DKIM key and reverify the message.
	 *
	 * @param {number} tabId
	 * @returns {Promise<void>}
	 */
	static async updateKey(tabId) {
		const res = displayedResultsCache.get(tabId);
		for (const dkimResult of res?.dkim ?? []) {
			await KeyDb.delete(null, dkimResult.sdid, dkimResult.selector);
		}

		const message = await browser.messageDisplay.getDisplayedMessage(tabId);
		await DisplayAction._reverifyMessage(tabId, message);
	}
}

/**
 * Handel the actions triggered by the user in the display header.
 */
browser.runtime.onMessage.addListener((runtimeMessage, sender, /*sendResponse*/) => {
	if (sender.id !== "dkim_verifier@pl") {
		return;
	}
	if (typeof runtimeMessage !== 'object' || runtimeMessage === null) {
		return;
	}
	/** @type {RuntimeMessage.Messages} */
	const request = runtimeMessage;
	if (request.module !== "DisplayAction") {
		return;
	}
	if (request.method === "queryButtonState") {
		// eslint-disable-next-line consistent-return
		return Promise.resolve(DisplayAction.queryButtonState(request.parameters.tabId));
	}
	if (request.method === "reverifyDKIMSignature") {
		const promise = DisplayAction.reverifyDKIMSignature(request.parameters.tabId);
		promise.catch(error => log.error("Display action reverifyDKIMSignature failed", error));
		// eslint-disable-next-line consistent-return
		return promise;
	}
	if (request.method === "policyAddUserException") {
		const promise = DisplayAction.policyAddUserException(request.parameters.tabId);
		promise.catch(error => log.error("Display action policyAddUserException failed", error));
		// eslint-disable-next-line consistent-return
		return promise;
	}
	if (request.method === "markKeyAsSecure") {
		const promise = DisplayAction.markKeyAsSecure(request.parameters.tabId);
		promise.catch(error => log.error("Display action markKeyAsSecure failed", error));
		// eslint-disable-next-line consistent-return
		return promise;
	}
	if (request.method === "updateKey") {
		const promise = DisplayAction.updateKey(request.parameters.tabId);
		promise.catch(error => log.error("Display action updateKey failed", error));
		// eslint-disable-next-line consistent-return
		return promise;
	}
});
