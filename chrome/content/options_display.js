// @ts-nocheck
/* eslint-env browser */
/* eslint strict: ["warn", "function"] */
/* exported toggleDetailsOptionsEnabled */

let checkBox = {
	showAdvancedInfo : null,
	allSignatures : null,
	includeHeaders : null
};

function init() {
	"use strict";
	checkBox.showAdvancedInfo = document.getElementById("display.advancedInfo.show");
	checkBox.allSignatures = document.getElementById("display.advancedInfo.allSignatures");
	checkBox.includeHeaders = document.getElementById("display.advancedInfo.includeHeaders");
	toggleDetailsOptionsEnabled();
}

function toggleDetailsOptionsEnabled() {
	"use strict";
	let disabled = !checkBox.showAdvancedInfo.checked;
	checkBox.allSignatures.disabled = disabled;
	checkBox.includeHeaders.disabled = disabled;
}

window.addEventListener("load", init, false);