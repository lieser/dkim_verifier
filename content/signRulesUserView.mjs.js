/**
 * Copyright (c) 2020-2024 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-env webextensions */
/* eslint-disable no-magic-numbers */

import { getElementById, uploadJsonData } from "./domUtils.mjs.js";
import ExtensionUtils from "../modules/extensionUtils.mjs.js";
import Logging from "../modules/logging.mjs.js";
import SignRulesProxy from "../modules/dkim/signRulesProxy.mjs.js";
import { TabulatorFull as Tabulator } from "../thirdparty/tabulator-tables/dist/js/tabulator_esm.js";

const log = Logging.getLogger("signRulesUserView");

/**
 * Notify the user about an error importing the sign rules.
 *
 * @param {unknown} error
 */
function showImportError(error) {
	log.error("Error importing sing rules.", error);
	let message;
	if (error instanceof Error) {
		message = browser.i18n.getMessage(error.message);
	}
	if (!message) {
		message = browser.i18n.getMessage("DKIM_INTERNALERROR_DEFAULT");
	}
	browser.notifications.create({
		type: "basic",
		title: browser.i18n.getMessage("ERROR_IMPORT_RULES"),
		message,
	});
}

document.addEventListener("DOMContentLoaded", async () => {
	// Initialize table

	const userRules = await SignRulesProxy.getUserRules();

	/** @type {import("tabulator-tables").Tabulator} */
	// @ts-expect-error
	const table = new Tabulator("#rulesTable", {
		height: "100%",
		data: userRules,
		// Note: basic renderVertical does not remember the scroll position
		// during adding/deleting rows, so we have to do it ourself.
		// The virtual renderer would be nicer, but there are multiple scrolling issues.
		renderVertical: "basic",
		layout: "fitColumns",
		columnDefaults: {
			editable: false,
			cellDblClick: /** @type {import("tabulator-tables").CellEventCallback} */ (_e, cell) => {
				cell.edit(true);
			},
		},
		columns: [
			{
				formatter: "rowSelection",
				titleFormatter: "rowSelection",
				align: "center",
				headerSort: false,
				width: 1,
			},
			{
				field: "id",
				visible: false,
			},
			{
				title: browser.i18n.getMessage("treeviewSigners.treecol.domain"),
				field: "domain",
				formatter: "textarea",
				editor: true,
			},
			{
				title: browser.i18n.getMessage("treeviewSigners.treecol.listId"),
				field: "listId",
				formatter: "textarea",
				editor: true,
			},
			{
				title: browser.i18n.getMessage("treeviewSigners.treecol.addr"),
				field: "addr",
				formatter: "textarea",
				editor: true,
			},
			{
				title: browser.i18n.getMessage("treeviewSigners.treecol.sdid"),
				field: "sdid",
				formatter: "textarea",
				editor: true,
			},
			{
				title: browser.i18n.getMessage("treeviewSigners.treecol.ruletype"),
				field: "type",
				editor: "number",
				editorParams: {
					min: 1,
					max: 3,
					verticalNavigation: "table",
				},
				validator: [
					"required",
					"integer",
					"numeric",
					"min:1",
					"max:3",
				],
				maxWidth: 130,
			},
			{
				title: browser.i18n.getMessage("treeviewSigners.treecol.priority"),
				field: "priority",
				editor: "number",
				editorParams: {
					min: 0,
					verticalNavigation: "table",
				},
				validator: [
					"required",
					"integer",
					"numeric",
					"min:0",
				],
				maxWidth: 130,
			},
			{
				title: browser.i18n.getMessage("treeviewSigners.treecol.enabled"),
				field: "enabled",
				formatter: "tickCross",
				editor: true,
				maxWidth: 130,
			},
		],
		initialSort: [
			{ column: "domain", dir: "asc" },
		],
		selectable: true,
		selectableRangeMode: "click",
	});

	// Workaround for https://github.com/olifolkerd/tabulator/issues/4277
	// @ts-expect-error
	table.eventBus?.subscribe("table-redraw", (/** @type {boolean} */ force) => {
		if (!force) {
			for (const row of table.getRows()) {
				row.normalizeHeight();
			}
		}
	});

	table.on("cellEdited", async (cell) => {
		await SignRulesProxy.updateRule(cell.getRow().getIndex(), cell.getColumn().getField(), cell.getValue());
	});

	browser.runtime.onMessage.addListener((request, sender /*, sendResponse*/) => {
		if (sender.id !== "dkim_verifier@pl") {
			return;
		}
		if (typeof request !== "object" || request === null) {
			return;
		}
		if (request.event === "ruleAdded") {
			(async () => {
				const rules = await SignRulesProxy.getUserRules();
				const scrollLeft = table.rowManager.element.scrollLeft;
				const scrollTop = table.rowManager.element.scrollTop;
				table.replaceData(rules);
				table.rowManager.element.scrollTo(scrollLeft, scrollTop);
			})();
		}
	});

	// Initialize buttons

	const addSignersRule = getElementById("addSignersRule");
	addSignersRule.addEventListener("click", () => {
		ExtensionUtils.createOrRaisePopup(
			"/content/signRulesUserAdd.html",
			475,
			400,
		);
	});

	const deleteSelectedRows = getElementById("deleteSelectedRows");
	deleteSelectedRows.addEventListener("click", async () => {
		const rows = table.getSelectedRows();
		const rowIDs = rows.map(row => row.getIndex());
		await SignRulesProxy.deleteRules(rowIDs);
		const scrollLeft = table.rowManager.element.scrollLeft;
		const scrollTop = table.rowManager.element.scrollTop;
		table.deleteRow(rows);
		table.rowManager.element.scrollTo(scrollLeft, scrollTop);
	});

	const buttonHelp = getElementById("buttonHelp");
	buttonHelp.addEventListener("click", () => {
		ExtensionUtils.createOrRaisePopup(
			"/content/signRulesHelp.html",
		);
	});

	const exportRules = getElementById("exportRules");
	exportRules.addEventListener("click", async () => {
		const exportedUserRules = await SignRulesProxy.exportUserRules();
		ExtensionUtils.downloadDataAsJSON(exportedUserRules, "dkim_sign_rules");
	});

	const importRulesDialog = getElementById("importRulesDialog");
	const importRules = getElementById("importRules");
	importRules.addEventListener("click", () => {
		importRulesDialog.style.display = "flex";
	});

	const importRulesDialogAdd = getElementById("importRulesDialogAdd");
	importRulesDialogAdd.addEventListener("click", async () => {
		try {
			importRulesDialog.style.display = "none";
			const data = await uploadJsonData();
			await SignRulesProxy.importUserRules(data, false);
		} catch (error) {
			showImportError(error);
		}
	});

	const importRulesDialogReplace = getElementById("importRulesDialogReplace");
	importRulesDialogReplace.addEventListener("click", async () => {
		try {
			importRulesDialog.style.display = "none";
			const data = await uploadJsonData();
			await SignRulesProxy.importUserRules(data, true);
		} catch (error) {
			showImportError(error);
		}
	});

	const importRulesDialogCancel = getElementById("importRulesDialogCancel");
	importRulesDialogCancel.addEventListener("click", () => {
		importRulesDialog.style.display = "none";
	});
}, { once: true });
