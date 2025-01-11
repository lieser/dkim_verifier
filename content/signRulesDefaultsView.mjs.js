/**
 * Copyright (c) 2020-2022;2024 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-env webextensions */

import ExtensionUtils from "../modules/extensionUtils.mjs.js";
import SignRulesProxy from "../modules/dkim/signRulesProxy.mjs.js";
import { TabulatorFull as Tabulator } from "../thirdparty/tabulator-tables/dist/js/tabulator_esm.js";
import { getElementById } from "./domUtils.mjs.js";

document.addEventListener("DOMContentLoaded", async () => {
	// Initialize table

	const data = await SignRulesProxy.getDefaultRules();

	const table = new Tabulator("#rulesTable", {
		height: "100%",
		data,
		// Note: The virtual renderer would be nicer, but there are multiple scrolling issues.
		renderVertical: "basic",
		layout: "fitColumns",
		columns: [
			{
				title: browser.i18n.getMessage("treeviewSigners.treecol.domain"),
				field: "domain",
				formatter: "textarea",
			},
			{
				title: browser.i18n.getMessage("treeviewSigners.treecol.addr"),
				field: "addr",
				formatter: "textarea",
			},
			{
				title: browser.i18n.getMessage("treeviewSigners.treecol.sdid"),
				field: "sdid",
				formatter: "textarea",
			},
			{
				title: browser.i18n.getMessage("treeviewSigners.treecol.ruletype"),
				field: "type",
				maxWidth: 130,
			},
			{
				title: browser.i18n.getMessage("treeviewSigners.treecol.priority"),
				field: "priority",
				maxWidth: 130,
			},
		],
		initialSort: [
			{ column: "domain", dir: "asc" },
		],
	});

	// Workaround for https://github.com/olifolkerd/tabulator/issues/4277
	table.eventBus?.subscribe("table-redraw", (/** @type {boolean} */ force) => {
		if (!force) {
			for (const row of table.getRows()) {
				row.normalizeHeight();
			}
		}
	});

	// Initialize buttons

	const buttonHelp = getElementById("buttonHelp");
	buttonHelp.addEventListener("click", () => {
		ExtensionUtils.createOrRaisePopup(
			"/content/signRulesHelp.html",
		);
	});
}, { once: true });
