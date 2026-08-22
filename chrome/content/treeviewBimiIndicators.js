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
var cssRules;

function addBimiIndicatorCss(indicatorId, indicatorData) {
	"use strict";
	let cssIndicatorRule = "treechildren::-moz-tree-image(" + indicatorId + ") {  list-style-image:url('data:image/svg+xml;base64," + indicatorData + "'); width:20px; height:20px; }";
	let cssTextRule = "treechildren::-moz-tree-cell-text(" + indicatorId + ") { color:transparent }";
	cssRules.insertRule(cssIndicatorRule, cssRules.cssRules.length);
	cssRules.insertRule(cssTextRule, cssRules.cssRules.length);
}

function setView() {
	"use strict";

	if (document.styleSheets && document.styleSheets.length > 0) {
	  cssRules = document.styleSheets[0];
	}

	let indiView = new SQLiteTreeView("dkimBimi.sqlite", "indicators", ["idx","data"], null);
	let indiElement = document.getElementById('hidden-indicator-tree');
	indiElement.view = indiView;

	for (let i=0; i<indiView.rowCount; i++) {
		let indicatorIndex = indiView.getCellText(i, indiElement.columns.getNamedColumn("idx"));
		let indicatorData = indiView.getCellText(i, indiElement.columns.getNamedColumn("data"));
		addBimiIndicatorCss("bimiidx" + indicatorIndex, indicatorData);
	}

	let cssHideRule = "#hidden-indicator-tree { display:none }";
	cssRules.insertRule(cssHideRule, cssRules.cssRules.length);

	treeView = new SQLiteTreeView("dkimBimi.sqlite", "domains", ["domain","indicator"], null);
	document.getElementById('my-tree').view = treeView;
	columns = document.getElementById('my-tree').columns;
}

function changeSelection() {
	"use strict";
	let removeBtn = document.getElementById("removeIndicator");
	removeBtn.disabled = treeView.selection.count === 0;
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