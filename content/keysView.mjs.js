/**
 * Copyright (c) 2021;2023-2024 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-env webextensions */

import KeyDbProxy from "../modules/dkim/keyDbProxy.mjs.js";
import { TabulatorFull as Tabulator } from "../thirdparty/tabulator-tables/dist/js/tabulator_esm.js";
import { getElementById } from "./domUtils.mjs.js";

document.addEventListener("DOMContentLoaded", async () => {
	// Initialize table

	const keys = await KeyDbProxy.getKeys();

	/** @type {import("tabulator-tables").Tabulator} */
	// @ts-expect-error
	const table = new Tabulator("#keysTable", {
		height: "100%",
		data: keys,
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
				title: browser.i18n.getMessage("treeviewKeys.treecol.SDID"),
				field: "sdid",
				formatter: "textarea",
				editor: true,
			},
			{
				title: browser.i18n.getMessage("treeviewKeys.treecol.selector"),
				field: "selector",
				formatter: "textarea",
				editor: true,
			},
			{
				title: browser.i18n.getMessage("treeviewKeys.treecol.key"),
				field: "key",
				editor: true,
			},
			{
				title: browser.i18n.getMessage("treeviewKeys.treecol.insertedAt"),
				field: "insertedAt",
				editor: true,
				maxWidth: 130,
			},
			{
				title: browser.i18n.getMessage("treeviewKeys.treecol.lastUsedAt"),
				field: "lastUsedAt",
				editor: true,
				maxWidth: 130,
			},
			{
				title: browser.i18n.getMessage("treeviewKeys.treecol.secure"),
				field: "secure",
				formatter: "tickCross",
				editor: true,
				maxWidth: 130,
			},
		],
		initialSort: [
			{ column: "sdid", dir: "asc" },
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
		await KeyDbProxy.update(cell.getRow().getIndex(), cell.getColumn().getField(), cell.getValue());
	});

	browser.runtime.onMessage.addListener((request, sender /*, sendResponse*/) => {
		if (sender.id !== "dkim_verifier@pl") {
			return;
		}
		if (typeof request !== "object" || request === null) {
			return;
		}
		if (request.event === "keysUpdated") {
			(async () => {
				const updatedKeys = await KeyDbProxy.getKeys();
				const scrollLeft = table.rowManager.element.scrollLeft;
				const scrollTop = table.rowManager.element.scrollTop;
				table.replaceData(updatedKeys);
				table.rowManager.element.scrollTo(scrollLeft, scrollTop);
			})();
		}
	});

	// Initialize buttons

	const deleteSelectedRows = getElementById("deleteSelectedRows");
	deleteSelectedRows.addEventListener("click", async () => {
		const rows = table.getSelectedRows();
		const rowIDs = rows.map(row => row.getIndex());
		await KeyDbProxy.delete(rowIDs);
		const scrollLeft = table.rowManager.element.scrollLeft;
		const scrollTop = table.rowManager.element.scrollTop;
		table.deleteRow(rows);
		table.rowManager.element.scrollTo(scrollLeft, scrollTop);
	});
}, { once: true });
