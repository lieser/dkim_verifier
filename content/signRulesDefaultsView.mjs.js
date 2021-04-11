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

import DataTable from "./table.mjs.js";
import ExtensionUtils from "../modules/extensionUtils.mjs.js";
import SignRulesProxy from "../modules/dkim/signRulesProxy.mjs.js";
import { getElementById } from "./domUtils.mjs.js";

document.addEventListener("DOMContentLoaded", async () => {
	const tableElement = getElementById("rulesTable");
	if (!(tableElement instanceof HTMLTableElement)) {
		throw new Error("element rulesTable is not a HTMLTableElement");
	}

	const data = await SignRulesProxy.getDefaultRules();
	const table = new DataTable(tableElement);
	table.showData(data);

	const buttonHelp = getElementById("buttonHelp");
	buttonHelp.addEventListener("click", () => {
		ExtensionUtils.createOrRaisePopup(
			"./signRulesHelp.html",
			browser.i18n.getMessage("signersRuleHelp.title"),
		);
	});
}, { once: true });
