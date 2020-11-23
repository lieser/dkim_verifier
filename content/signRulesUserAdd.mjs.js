/**
 * Copyright (c) 2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-env browser, webextensions */

import Logging from "../modules/logging.mjs.js";
import SignRulesProxy from "../modules/dkim/signRulesProxy.mjs.js";

const log = Logging.getLogger("signRulesUserAdd");

async function closeCurrentWindow() {
	const windowId = (await browser.windows.getCurrent()).id;
	if (windowId === undefined) {
		throw new Error("Failed to get current window id");
	}
	await browser.windows.remove(windowId);
}

/**
 * @param {string} id
 * @returns {HTMLElement}
 */
function getElementById(id) {
	const element = document.getElementById(id);
	if (!element) {
		throw new Error(`Could not find element with id '${id}'.`);
	}
	return element;
}

/**
 * @param {string} id
 * @returns {string}
 */
function getInputValue(id) {
	const inputElement = getElementById(id);
	if (!(inputElement instanceof HTMLInputElement || inputElement instanceof HTMLSelectElement)) {
		throw new Error(`Element with id '${id}' is not an HTMLInputElement or HTMLSelectElement`);
	}
	return inputElement.value;
}

/**
 * @param {string} name
 * @returns {string}
 */
function getRadioGroupValue(name) {
	const checkedRadio = document.querySelector(`input[name="${name}"]:checked`);
	if (!(checkedRadio instanceof HTMLInputElement)) {
		throw new Error(`Element with name '${name}' is not an HTMLInputElement`);
	}
	return checkedRadio.value;
}

/**
 * @param {string} id
 * @returns {boolean}
 */
function getCheckbox(id) {
	const inputElement = getElementById(id);
	if (!(inputElement instanceof HTMLInputElement)) {
		throw new Error(`Element with id '${id}' is not an HTMLInputElement`);
	}
	return inputElement.checked;
}

async function onAccept() {
	try {
		const domain = getInputValue("domain");
		const listId = getInputValue("listId");
		const addr = getInputValue("addr");
		const sdid = getInputValue("sdid");
		const ruleType = parseInt(getInputValue("ruletype"), 10);
		const priorityMode = getRadioGroupValue("priorityMode");
		let priority = null;
		if (priorityMode === "2") {
			const value = getInputValue("priority");
			priority = parseInt(value, 10);
			if (isNaN(priority) || priority.toString() !== value) {
				throw new Error(`value '${value}' is not a valid number`);
			}
		}
		const enabled = getCheckbox("enabled");

		await SignRulesProxy.addRule(domain, listId, addr, sdid, ruleType, priority, enabled);
		closeCurrentWindow();
	} catch (exception) {
		log.error(exception);
	}
}

function onCancel() {
	closeCurrentWindow();
}

function updatePriorityMode() {
	const priorityElement = getElementById("priority");
	if (!(priorityElement instanceof HTMLInputElement)) {
		throw new Error(`Element with id 'priority' is not an HTMLInputElement`);
	}
	console.log("priorityMode:", getRadioGroupValue("priorityMode"));
	priorityElement.disabled = getRadioGroupValue("priorityMode") === "1";
}

document.addEventListener("DOMContentLoaded", () => {
	updatePriorityMode();
	const priorityModeManual = getElementById("priorityModeManual");
	priorityModeManual.onchange = updatePriorityMode;
	const priorityModeAuto = getElementById("priorityModeAuto");
	priorityModeAuto.onchange = updatePriorityMode;

	const accept = getElementById("accept");
	accept.addEventListener("click", () => {
		onAccept();
	});

	const cancel = getElementById("cancel");
	cancel.addEventListener("click", () => {
		onCancel();
	});
});
