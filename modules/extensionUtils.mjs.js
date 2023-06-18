/**
 * Utility functions related to WebExtensions/MailExtensions.
 *
 * Copyright (c) 2020-2023 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-env browser, webextensions */

import { dateToString, promiseWithTimeout, sleep } from "./utils.mjs.js";
import Logging from "./logging.mjs.js";

const log = Logging.getLogger("ExtensionUtils");

/**
 * Create popup window, or raise it if already open.
 *
 * @param {string} url - must be the absolute path starting with /
 * @param {number} [height]
 * @param {number} [width]
 * @returns {Promise<void>}
 */
async function createOrRaisePopup(url, height = undefined, width = undefined) {
	const [popupTab] = await browser.tabs.query({ url: browser.runtime.getURL(url) });
	const popupWindowId = popupTab?.windowId;
	if (popupWindowId !== undefined) {
		await browser.windows.update(popupWindowId, { focused: true });
		return;
	}
	/** @type {Parameters<browser.windows.create>[0]} */
	const createData = {
		url,
		type: "popup",
		allowScriptsToClose: true,
		titlePreface: `${browser.i18n.getMessage("about_name")} - `,
	};
	if (height) {
		createData.height = height;
	}
	if (width) {
		createData.width = width;
	}
	browser.windows.create(createData);
}

/**
 * Download data as JSON.
 *
 * @param {object} data
 * @param {string} dataName
 * @returns {void}
 */
function downloadDataAsJSON(data, dataName) {
	const jsonBlob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
	browser.downloads.download({
		"url": URL.createObjectURL(jsonBlob),
		"filename": `${dataName}_${dateToString(new Date())}.json`,
		"saveAs": true,
	});
}

/**
 * Checks if a message is outgoing.
 *
 * @param {browser.messages.MessageHeader} message
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
 * @returns {Promise<string>}
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
 * - TransactionInactiveError resulting in Promise never being resolved.
 * - Getting rejected with "An unexpected error occurred".
 *
 * @returns {Promise<{[x: string]: any}>}
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
	createOrRaisePopup,
	downloadDataAsJSON,
	isOutgoing,
	safeGetLocalStorage,
	readFile,
};
export default ExtensionUtils;
