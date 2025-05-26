// @ts-nocheck
/* eslint-env browser */
/* eslint strict: ["warn", "function"] */
/* exported gDKIMOptionsDisplayPane.toggleDetailsOptionsEnabled */

let gDKIMOptionsDisplayPane = {
	initDone : false,

	checkBox : {
		showAdvancedInfo : null,
		allSignatures : null,
		includeHeaders : null
	},

	init: function() {
		"use strict";
		if (gDKIMOptionsDisplayPane.initDone) { return; }
		gDKIMOptionsDisplayPane.checkBox.showAdvancedInfo = document.getElementById("display.advancedInfo.show");
		gDKIMOptionsDisplayPane.checkBox.allSignatures = document.getElementById("display.advancedInfo.allSignatures");
		gDKIMOptionsDisplayPane.checkBox.includeSelector = document.getElementById("display.advancedInfo.includeSelector");
		gDKIMOptionsDisplayPane.checkBox.includeHeaders = document.getElementById("display.advancedInfo.includeHeaders");
		gDKIMOptionsDisplayPane.toggleDetailsOptionsEnabled();
		gDKIMOptionsDisplayPane.initDone = true;
	},

	toggleDetailsOptionsEnabled: function() {
		"use strict";
		let disabled = !gDKIMOptionsDisplayPane.checkBox.showAdvancedInfo.checked;
		gDKIMOptionsDisplayPane.checkBox.allSignatures.disabled = disabled;
		gDKIMOptionsDisplayPane.checkBox.includeSelector.disabled = disabled;
		gDKIMOptionsDisplayPane.checkBox.includeHeaders.disabled = disabled;
	}

};

window.addEventListener("paneload", gDKIMOptionsDisplayPane.init, false);