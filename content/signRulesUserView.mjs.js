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
/* eslint-disable no-magic-numbers */

import DataTable from "./table.mjs.js";
import ExtensionUtils from "../modules/extensionUtils.mjs.js";
import SignRulesProxy from "../modules/dkim/signRulesProxy.mjs.js";

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

document.addEventListener("DOMContentLoaded", async () => {
	const tableElement = getElementById("rulesTable");
	if (!(tableElement instanceof HTMLTableElement)) {
		throw new Error("element rulesTable is not a HTMLTableElement");
	}

	const userRules = await SignRulesProxy.getUserRules();
	const table = new DataTable(tableElement, true,
		(rowId, columnName, value) => SignRulesProxy.updateRule(rowId, columnName, value),
		(rowId) => SignRulesProxy.deleteRule(rowId),
	);
	table.showData(userRules, ["domain"]);

	browser.runtime.onMessage.addListener((request, sender, /*sendResponse*/) => {
		if (sender.id !== "dkim_verifier@pl") {
			return;
		}
		if (typeof request !== 'object' || request === null) {
			return;
		}
		if (request.event === "ruleAdded") {
			(async () => {
				const rules = await SignRulesProxy.getUserRules();
				table.showData(rules, ["domain"]);
			})();
		}
	});

	const addSignersRule = getElementById("addSignersRule");
	addSignersRule.addEventListener("click", () => {
		ExtensionUtils.createOrRaisePopup(
			"./signRulesUserAdd.html",
			browser.i18n.getMessage("addSignersRule.title"),
			425,
			375,
		);
	});

	const deleteSelectedRows = getElementById("deleteSelectedRows");
	deleteSelectedRows.addEventListener("click", () => {
		table.deleteSelectedRows();
	});

	const buttonHelp = getElementById("buttonHelp");
	buttonHelp.addEventListener("click", () => {
		ExtensionUtils.createOrRaisePopup(
			"./signRulesHelp.html",
			browser.i18n.getMessage("signersRuleHelp.title"),
		);
	});
});
