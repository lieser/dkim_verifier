/**
 * Copyright (c) 2021 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="../WebExtensions.d.ts" />
///<reference path="../RuntimeMessage.d.ts" />
/* eslint-env browser, webextensions */

import { getElementById } from "./domUtils.mjs.js";

async function getCurrentTabId() {
	const tab = await browser.tabs.query({ currentWindow: true, active: true });
	const tabId = tab[0].id;
	if (tabId === undefined) {
		throw new Error("active tab has no id");
	}
	return tabId;
}

/**
 * Trigger a display action and close the popup.
 *
 * @param {string} action
 * @returns {Promise<void>}
 */
async function triggerDisplayAction(action) {
	const tabId = await getCurrentTabId();
	/** @type {RuntimeMessage.DisplayAction.DisplayActionMessage} */
	const message = {
		module: "DisplayAction",
		method: action,
		parameters: {
			tabId: tabId,
		},
	};
	browser.runtime.sendMessage(message);
	window.close();
}

/**
 * Query which buttons should be enabled.
 *
 * @returns {Promise<RuntimeMessage.DisplayAction.queryButtonStateResult>}
 */
async function queryButtonState() {
	const tabId = await getCurrentTabId();
	/** @type {RuntimeMessage.DisplayAction.DisplayActionMessage} */
	const message = {
		module: "DisplayAction",
		method: "queryButtonState",
		parameters: {
			tabId: tabId,
		},
	};
	return browser.runtime.sendMessage(message);
}

document.addEventListener("DOMContentLoaded", async () => {
	const buttonState = await queryButtonState();

	const reverifyDKIMSignature = getElementById("reverifyDKIMSignature");
	if (!(reverifyDKIMSignature instanceof HTMLButtonElement)) {
		throw Error("reverifyDKIMSignature element is not a button");
	}
	reverifyDKIMSignature.addEventListener("click", async () => {
		await triggerDisplayAction("reverifyDKIMSignature");
	});
	if (buttonState.reverifyDKIMSignature) {
		reverifyDKIMSignature.disabled = false;
	}

	const policyAddUserException = getElementById("policyAddUserException");
	if (!(policyAddUserException instanceof HTMLButtonElement)) {
		throw Error("policyAddUserException element is not a button");
	}
	policyAddUserException.addEventListener("click", async () => {
		await triggerDisplayAction("policyAddUserException");
	});
	if (buttonState.policyAddUserException) {
		policyAddUserException.disabled = false;
	}

	const markKeyAsSecure = getElementById("markKeyAsSecure");
	if (!(markKeyAsSecure instanceof HTMLButtonElement)) {
		throw Error("markKeyAsSecure element is not a button");
	}
	markKeyAsSecure.addEventListener("click", async () => {
		await triggerDisplayAction("markKeyAsSecure");
	});
	if (buttonState.markKeyAsSecure) {
		markKeyAsSecure.disabled = false;
	}

	const updateKey = getElementById("updateKey");
	if (!(updateKey instanceof HTMLButtonElement)) {
		throw Error("updateKey element is not a button");
	}
	updateKey.addEventListener("click", async () => {
		await triggerDisplayAction("updateKey");
	});
	if (buttonState.updateKey) {
		updateKey.disabled = false;
	}

}, { once: true });
