// @ts-nocheck
/* eslint-env browser */
/* eslint strict: ["warn", "function"] */
/* global Components */
/* global BIMIDB, SQLiteTreeView */
/* exported setView, changeSelection, removeBimiIndicator */

const Cu = Components.utils;

Cu.import("resource://dkim_verifier/SQLiteTreeView.jsm.js");
Cu.import("resource://dkim_verifier/bimi.jsm.js");

var treeView;
var columns;

function setView() {
	"use strict";
	treeView = new SQLiteTreeView("dkimBimi.sqlite", "domains", ["domain"], null);
	document.getElementById('my-tree').view = treeView;
	columns = document.getElementById('my-tree').columns;
}

async function changeSelection() {
	"use strict";
	let removeBtn = document.getElementById("removeIndicator");
	let domainCol = columns.getNamedColumn("domain");
	let imageEl = document.getElementById("my-image");
	let selected = false;
	imageEl.src = "";
	for (let i=0; i<treeView.rowCount; i++) {
		if (treeView.selection.isSelected(i)) {
			let domain = treeView.getCellText(i, domainCol);
			imageEl.src = "data:image/svg+xml;base64," + await BIMIDB.getBimiIndicator(domain);
			selected = true;
			break; // in case of a multi selection
		}
	}
	removeBtn.disabled = !selected;
}

async function removeBimiIndicator() {
	"use strict";
	let domainCol = columns.getNamedColumn("domain");
	let toRemove = [];
	for (let i=0; i<treeView.rowCount; i++) {
		if (treeView.selection.isSelected(i)) {
			let domain = treeView.getCellText(i, domainCol);
			toRemove.push(domain);
		}
	}
	for (const indicator of toRemove) {
		await BIMIDB.removeBimiIndicator(indicator);
	}
	treeView.update(-1 * toRemove.length);
	changeSelection();
}