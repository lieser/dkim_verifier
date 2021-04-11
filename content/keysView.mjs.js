/**
 * Copyright (c) 2021 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-env browser, webextensions */

import DataTable from "./table.mjs.js";
import KeyDbProxy from "../modules/dkim/keyDbProxy.mjs.js";
import { getElementById } from "./domUtils.mjs.js";

document.addEventListener("DOMContentLoaded", async () => {
	const tableElement = getElementById("keysTable");
	if (!(tableElement instanceof HTMLTableElement)) {
		throw new Error("element keysTable is not a HTMLTableElement");
	}

	const keys = await KeyDbProxy.getKeys();
	const table = new DataTable(tableElement, true,
		(rowId, columnName, value) => KeyDbProxy.update(rowId, columnName, value),
		(rowId) => KeyDbProxy.delete(rowId),
	);
	table.showData(keys, ["sdid"]);

	browser.runtime.onMessage.addListener((request, sender, /*sendResponse*/) => {
		if (sender.id !== "dkim_verifier@pl") {
			return;
		}
		if (typeof request !== 'object' || request === null) {
			return;
		}
		if (request.event === "keysUpdated") {
			(async () => {
				const updatedKeys = await KeyDbProxy.getKeys();
				table.showData(updatedKeys, ["sdid"]);
			})();
		}
	});

	const deleteSelectedRows = getElementById("deleteSelectedRows");
	deleteSelectedRows.addEventListener("click", () => {
		table.deleteSelectedRows();
	});
}, { once: true });
