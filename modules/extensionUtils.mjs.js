/*
 * Utility functions related to WebExtensions/MailExtensions.
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
/* eslint-env browser, webextensions */

import { promiseWithTimeout, sleep } from "./utils.mjs.js";
import Logging from "./logging.mjs.js";

const log = Logging.getLogger("ExtensionUtils");

/**
 * Create popup window, or raise it if already open.
 *
 * @param {string} url
 * @param {string} title
 * @param {number} [height]
 * @param {number} [width]
 * @return {Promise<browser.windows.Window>}
 */
async function createOrRaisePopup(url, title, height = undefined, width = undefined) {
	const popupWindows = await browser.windows.getAll({
		populate: true,
		windowTypes: ["popup"],
	});
	const popupWindow = popupWindows.find(popup => popup.title === `${title} - Mozilla Thunderbird`);
	if (popupWindow?.id !== undefined) {
		await browser.windows.update(popupWindow.id, { focused: true });
		return popupWindow;
	}
	return browser.windows.create({
		url: url,
		type: "popup",
		allowScriptsToClose: true,
		height: height,
		width: width,
	});
}

/**
 * Checks if a message is outgoing.
 *
 * @param {browser.messageDisplay.MessageHeader} message
 * @param {string} fromAddr
 * @returns {Promise<boolean>}
 */
async function isOutgoing(message, fromAddr) {
	if (!message.folder) {
		// msg is external
		return false;
	}
	if (["drafts", "sent", "templates", "outbox"].includes(message.folder.type ?? "")) {
		// msg is in an outgoing type folder
		log.debug("email is in outgoing type folder, no need fo it to be signed");
		return true;
	}

	// return true if one of the accounts identities contain the from address
	const account = await browser.accounts.get(message.folder.accountId);
	const identities = account?.identities;
	if (identities) {
		for (const identity of identities) {
			if (fromAddr === identity.email) {
				log.debug("email is from own identity, no need fo it to be signed");
				return true;
			}
		}
	}

	// default to false
	return false;
}

/**
 * Reads a file included in the extension as a string.
 *
 * @param {string} path - path inside the extension of the file to read
 * @return {Promise<string>}
 */
async function readFile(path) {
	const url = browser.runtime.getURL(path);
	const req = new Request(url);
	const response = await fetch(req);
	const text = await response.text();
	return text;
}

/**
 * Wrapper around browser.storage.local.get() to workaround the following issues:
 * - TransactionInactiveError resulting in PRomise never being resolved
 * - Getting rejected with "An unexpected error occurred"
 *
 * @returns {Promise<Object.<string, any>>}
 */
async function safeGetLocalStorage() {
	const overallTimeout = 15000;
	const storageTimeout = 3000;
	let retrySleepTime = 100;
	const retrySleepTimeIncrease = 50;
	const retrySleepTimeMax = 500;

	let timeout = false;
	const timeoutId = setTimeout(() => {
		timeout = true;
	}, overallTimeout);
	// eslint-disable-next-line no-unmodified-loop-condition
	while (!timeout) {
		try {
			const result = await promiseWithTimeout(storageTimeout, browser.storage.local.get());
			clearTimeout(timeoutId);
			return result;
		} catch (error) {
			log.debug("browser.storage.local.get() failed (will retry) with", error);
			await sleep(retrySleepTime);
			retrySleepTime = Math.max(retrySleepTime + retrySleepTimeIncrease, retrySleepTimeMax);
		}
	}
	throw Error("browser.storage.local.get() failed");
}

const ExtensionUtils = {
	createOrRaisePopup: createOrRaisePopup,
	isOutgoing: isOutgoing,
	safeGetLocalStorage: safeGetLocalStorage,
	readFile: readFile,
};
export default ExtensionUtils;
