// @ts-nocheck
/* eslint-env browser */
/* eslint strict: ["warn", "function"] */
/* exported gDKIMOptionsDisplayPane.toggleDetailsOptionsEnabled */

let gDKIMOptionsDisplayPane = {
	initDone : false,

	domElements : {
		// Advanced info
		showAdvancedInfo : null,
		allSignatures : null,
		includeHeaders : null,
		// FavIcons
		showFavIcon : null,
		preferFavIcon : null,
		bimiEnable : null,
		cacheBimi : null,
		reloadBimi : null,
		addBimiCa : null
	},

	init: function() {
		"use strict";
		if (gDKIMOptionsDisplayPane.initDone) { return; }
		gDKIMOptionsDisplayPane.domElements.showAdvancedInfo = document.getElementById("display.advancedInfo.show");
		gDKIMOptionsDisplayPane.domElements.allSignatures = document.getElementById("display.advancedInfo.allSignatures");
		gDKIMOptionsDisplayPane.domElements.includeSelector = document.getElementById("display.advancedInfo.includeSelector");
		gDKIMOptionsDisplayPane.domElements.includeHeaders = document.getElementById("display.advancedInfo.includeHeaders");
		gDKIMOptionsDisplayPane.toggleDetailsOptionsEnabled();

		gDKIMOptionsDisplayPane.domElements.showFavIcon = document.getElementById("display.icons.showFavIcon");
		gDKIMOptionsDisplayPane.domElements.preferFavIcon = document.getElementById("display.icons.preferFavIcon");
		gDKIMOptionsDisplayPane.domElements.bimiEnable = document.getElementById("display.icons.bimiEnable");
		gDKIMOptionsDisplayPane.domElements.cacheBimi = document.getElementById("display.icons.cacheBimi");
		gDKIMOptionsDisplayPane.domElements.reloadBimi = document.getElementById("display.icons.reloadBimi");
		gDKIMOptionsDisplayPane.domElements.addBimiCa = document.getElementById("display.icons.addBimiCa");
		gDKIMOptionsDisplayPane.toggleIconsOptionsEnabled();

		gDKIMOptionsDisplayPane.initDone = true;
	},

	toggleDetailsOptionsEnabled: function() {
		"use strict";
		let disabled = !gDKIMOptionsDisplayPane.domElements.showAdvancedInfo.checked;
		gDKIMOptionsDisplayPane.domElements.allSignatures.disabled = disabled;
		gDKIMOptionsDisplayPane.domElements.includeSelector.disabled = disabled;
		gDKIMOptionsDisplayPane.domElements.includeHeaders.disabled = disabled;
	},

	toggleIconsOptionsEnabled: function() {
		"use strict";
		let allDisabled = !gDKIMOptionsDisplayPane.domElements.showFavIcon.checked;
		let bimiOnlineDisabled = gDKIMOptionsDisplayPane.domElements.bimiEnable.selectedIndex < 2;
		let bimiCacheDisabled = !gDKIMOptionsDisplayPane.domElements.cacheBimi.checked;
		gDKIMOptionsDisplayPane.domElements.preferFavIcon.disabled = allDisabled;
		gDKIMOptionsDisplayPane.domElements.bimiEnable.disabled = allDisabled;
		gDKIMOptionsDisplayPane.domElements.cacheBimi.disabled = allDisabled || bimiOnlineDisabled;
		gDKIMOptionsDisplayPane.domElements.reloadBimi.disabled = allDisabled || bimiOnlineDisabled || bimiCacheDisabled;
		gDKIMOptionsDisplayPane.domElements.addBimiCa.disabled = allDisabled || bimiOnlineDisabled;
	}
};

window.addEventListener("paneload", gDKIMOptionsDisplayPane.init, false);