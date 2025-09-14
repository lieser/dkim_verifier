/**
 * Copyright (c) 2020-2023;2025 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check

import Logging from "../modules/logging.mjs.js";
import SignRulesProxy from "../modules/dkim/signRulesProxy.mjs.js";
import { getElementById } from "./domUtils.mjs.js";

const log = Logging.getLogger("signRulesUserAdd");

/**
 * @param {string} id
 * @returns {string}
 */
function getInputValue(id) {
	const inputElement = getElementById(id);
	if (!(inputElement instanceof HTMLInputElement || inputElement instanceof HTMLSelectElement)) {
		throw new TypeError(`Element with id '${id}' is not an HTMLInputElement or HTMLSelectElement`);
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
		throw new TypeError(`Element with name '${name}' is not an HTMLInputElement`);
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
		throw new TypeError(`Element with id '${id}' is not an HTMLInputElement`);
	}
	return inputElement.checked;
}

/**
 * @returns {Promise<void>}
 */
async function onAccept() {
	try {
		const domain = getInputValue("domain");
		const listId = getInputValue("listId");
		const addr = getInputValue("addr");
		const sdid = getInputValue("sdid");
		const ruleType = Number.parseInt(getInputValue("ruletype"), 10);
		const priorityMode = getRadioGroupValue("priorityMode");
		let priority = null;
		if (priorityMode === "2") {
			const value = getInputValue("priority");
			priority = Number.parseInt(value, 10);
			if (Number.isNaN(priority) || priority.toString() !== value) {
				throw new Error(`value '${value}' is not a valid number`);
			}
		}
		const enabled = getCheckbox("enabled");

		await SignRulesProxy.addRule(domain, listId, addr, sdid, ruleType, priority, enabled);
		window.close();
	} catch (error) {
		log.error("Error adding the user sign rule", error);
	}
}

/**
 * @returns {void}
 */
function onCancel() {
	window.close();
}

/**
 * @returns {void}
 */
function updatePriorityMode() {
	const priorityElement = getElementById("priority");
	if (!(priorityElement instanceof HTMLInputElement)) {
		throw new TypeError("Element with id 'priority' is not an HTMLInputElement");
	}
	priorityElement.disabled = getRadioGroupValue("priorityMode") === "1";
}

document.addEventListener("DOMContentLoaded", () => {
	updatePriorityMode();
	const priorityModeManual = getElementById("priorityModeManual");
	priorityModeManual.addEventListener("change", updatePriorityMode);
	const priorityModeAuto = getElementById("priorityModeAuto");
	priorityModeAuto.addEventListener("change", updatePriorityMode);

	const accept = getElementById("accept");
	accept.addEventListener("click", () => {
		onAccept();
	});

	const cancel = getElementById("cancel");
	cancel.addEventListener("click", () => {
		onCancel();
	});
}, { once: true });
