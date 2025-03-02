// @ts-nocheck
/* eslint-env browser */
/* eslint strict: ["warn", "function"] */
/* exported gDKIMOptionsAdvancedPane.toggleARHOptionsEnabled */

let gDKIMOptionsAdvancedPane = {
	initDone : false,

	checkBox : {
		replaceAddonResult : null,
		showDKIMResults : null
	},

	init : function() {
		"use strict";
		if (gDKIMOptionsAdvancedPane.initDone) { return; }
		gDKIMOptionsAdvancedPane.checkBox.replaceAddonResult = document.getElementById("advanced.arh.replaceAddonResult");
		gDKIMOptionsAdvancedPane.checkBox.showDKIMResults = document.getElementById("advanced.arh.showDKIMResults");
		gDKIMOptionsAdvancedPane.toggleARHOptionsEnabled();
		gDKIMOptionsAdvancedPane.initDone = true;
	},

	toggleARHOptionsEnabled : function() {
		"use strict";
		if (gDKIMOptionsAdvancedPane.checkBox.replaceAddonResult.checked) { gDKIMOptionsAdvancedPane.checkBox.showDKIMResults.checked = true; }
		gDKIMOptionsAdvancedPane.checkBox.showDKIMResults.disabled = gDKIMOptionsAdvancedPane.checkBox.replaceAddonResult.checked;
	}

};

window.addEventListener("paneload", gDKIMOptionsAdvancedPane.init, false);