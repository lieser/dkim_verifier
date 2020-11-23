/**
 * dkim.js - DKIM Verifier Extension for Mozilla Thunderbird
 * 
 * Verifies the DKIM signature if a new message is viewed,
 * and displays the result.
 *
 * Copyright (c) 2013-2018 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// options for ESLint
/* eslint-env browser */
/* eslint strict: ["warn", "function"] */
/* eslint no-console: "off"*/
/* eslint no-magic-numbers: ["warn", { "ignoreArrayIndexes": true, "ignore": [-1, 0, 1,] }] */
/* global Components, Cu, Services, gMessageListeners, gFolderDisplay, gExpandedHeaderView, createHeaderEntry, syncGridColumnWidths, currentHeaderData, gMessageDisplay */
/* global MozXULElement, XULPopupElement */

// namespace
// @ts-ignore
var DKIM_Verifier = {};
Cu.import("resource://dkim_verifier/logging.jsm", DKIM_Verifier);
Cu.import("resource://dkim_verifier/helper.jsm", DKIM_Verifier);
Cu.import("resource://dkim_verifier/AuthVerifier.jsm", DKIM_Verifier);
Cu.import("resource://dkim_verifier/dkimPolicy.jsm", DKIM_Verifier);
Cu.import("resource://dkim_verifier/dkimKey.jsm", DKIM_Verifier);


// @ts-ignore
const PREF_BRANCH = "extensions.dkim_verifier.";


/**
 * DKIM header field
 */
class DKIMHeaderfield extends MozXULElement {
	constructor() {
		super();

		/** @type{IAuthVerifier.AuthResultDKIM[]} */
		this.dkimResults = [];

		this.setAttribute("context", "copyPopup");

		this._content = document.createXULElement("hbox");

		// DKIM result
		this._dkimValue = document.createXULElement("description");
		this._dkimValue.classList.add("headerValue");

		// DKIM warning icon
		this._dkimWarningIcon = document.createXULElement("image");
		this._dkimWarningIcon.classList.add("alert-icon");
		this._dkimWarningIcon.setAttribute("anonid", "dkimWarningIcon");
		this._dkimWarningIcon.setAttribute("tooltip", "dkim-verifier-header-tooltip-warnings");

		/**
		 * Create element for ARH result
		 *
		 * @param {String} anonid
		 * @param {String} labelValue
		 * @returns {{box: Element, value: Element}}
		 */
		function createArh(anonid, labelValue) {
			let box = document.createXULElement("hbox");
			box.setAttribute("anonid", anonid);

			let label = document.createXULElement("description");
			label.classList.add("headerValue");
			label.setAttribute("style", "text-align: right");
			label.textContent = labelValue;

			let value = document.createXULElement("description");
			value.classList.add("headerValue");

			box.appendChild(label);
			box.appendChild(value);

			return {
				box: box,
				value: value,
			};
		}

		// ARH result
		this._arhDkim = createArh("arhDkim", "DKIM:");
		this._arhSpf = createArh("spf", "SPF:");
		this._arhDmarc = createArh("dmarc", "DMARC:");

		this._separator = document.createXULElement("separator");
		this._separator.setAttribute("flex", "1");

		this.appendChild(this._content);
		this._content.appendChild(this._dkimValue);
		this._content.appendChild(this._dkimWarningIcon);
		this._content.appendChild(this._arhDkim.box);
		this._content.appendChild(this._arhSpf.box);
		this._content.appendChild(this._arhDmarc.box);
		this._content.appendChild(this._separator);
	}

	/**
	 * Set the DKIM result
	 *
	 * @memberof DKIMHeaderfield
	 * @param {String} val
	 */
	set value(val) {
		this._dkimValue.textContent = val;
	}

	/**
	 * Set the DKIM warnings
	 *
	 * @memberof DKIMHeaderfield
	 * @param {String[]} warnings
	 */
	set warnings(warnings) {
		this.setAttribute("warnings", (warnings.length > 0).toString() );
	}

	/**
	 * Set the SPF result
	 *
	 * @memberof DKIMHeaderfield
	 * @param {String} val
	 */
	set spfValue(val) {
		if (val) {
			this.setAttribute("spf", "true");
		} else {
			this.setAttribute("spf", "false");
		}
		this._arhSpf.value.textContent = val;
	}

	/**
	 * Set the DMARC result
	 *
	 * @memberof DKIMHeaderfield
	 * @param {String} val
	 */
	set dmarcValue(val) {
		if (val) {
			this.setAttribute("dmarc", "true");
		} else {
			this.setAttribute("dmarc", "false");
		}
		this._arhDmarc.value.textContent = val;
	}

	/**
	 * Set the DKIM result from the ARH
	 *
	 * @memberof DKIMHeaderfield
	 * @param {String} val
	 */
	set arhDkimValue(val) {
		if (val) {
			this.setAttribute("arhDkim", "true");
		} else {
			this.setAttribute("arhDkim", "false");
		}
		this._arhDkim.value.textContent = val;
	}
}

customElements.define("dkim-verifier-headerfield", DKIMHeaderfield);

/**
 * Base class for DKIM tooltips
 */
class DKIMTooltip extends XULPopupElement {
	constructor() {
		super();

		// whether a separator should be added before the warnings
		this._warningsSeparator = false;

		// The DKIM result
		this._value = document.createXULElement("label");
		// A box containing the warnings
		this._warningsBox = document.createXULElement("vbox");
	}

	/**
	 * Set the DKIM result
	 *
	 * @memberof DKIMTooltip
	 * @param {String} val
	 */
	set value(val) {
		this._value.textContent = val;
	}

	/**
	 * Set the warnings for the tooltip
	 *
	 * @memberof DKIMTooltip
	 * @param {String[]} warnings
	 */
	set warnings(warnings) {
		// delete old warnings from tooltips
		while (this._warningsBox.firstChild) {
			this._warningsBox.removeChild(this._warningsBox.firstChild);
		}

		if (this._warningsSeparator && warnings.length > 0) {
			let sep = document.createXULElement("separator");
			sep.setAttribute("class", "thin");
			this._warningsBox.appendChild(sep);
		}

		// add warnings to warning tooltip
		for (let w of warnings) {
			let des;
			des = document.createXULElement("description");
			des.textContent = w;
			this._warningsBox.appendChild(des);
		}
	}
}

/**
 * Tooltip showing the DKIM warnings.
 *
 * @extends {DKIMTooltip}
 */
class DKIMWarningsTooltip extends DKIMTooltip {
	constructor() {
		super();

		this.appendChild(this._warningsBox);
	}
}

/**
 * Tooltip showing both the DKIM result and the warnings.
 * The tooltip contains the label "DKIM:".
 *
 * @extends {DKIMTooltip}
 */
class DKIMTooltipFrom extends DKIMTooltip {
	constructor() {
		super();

		this._warningsSeparator = true;

		// Outer box and label
		this._outerBox = document.createXULElement("hbox");
		this._outerBoxLabel = document.createXULElement("label");
		this._outerBoxLabel.setAttribute("value", "DKIM:");

		// The inner box, containing the DKIM result and optional the warnings
		this._innerBox = document.createXULElement("vbox");
		this._innerBox.setAttribute("flex", "1");

		this.appendChild(this._outerBox);
		this._outerBox.appendChild(this._outerBoxLabel);
		this._outerBox.appendChild(this._innerBox);
		this._innerBox.appendChild(this._value);
		this._innerBox.appendChild(this._warningsBox);
	}
}

/**
 * Tooltip showing both the DKIM result and the warnings.
 *
 * @extends {DKIMTooltip}
 */
class DKIMTooltipStatus extends DKIMTooltip {
	constructor() {
		super();

		this._warningsSeparator = true;

		// The DKIM result
		this._value = document.createXULElement("label");

		this.appendChild(this._value);
		this.appendChild(this._warningsBox);
	}
}

customElements.define("dkim-tooltip-warnings", DKIMWarningsTooltip, { extends: 'tooltip' });
customElements.define("dkim-tooltip-from", DKIMTooltipFrom, { extends: 'tooltip' });
customElements.define("dkim-tooltip-status", DKIMTooltipStatus, { extends: 'tooltip' });

/**
 * DKIM statusbar
 */
class DKIMStatusbarpanel extends MozXULElement {
	constructor() {
		super();

		this._label = document.createXULElement("label");
		this._label.classList.add("statusbarpanel-text");
		this._label.textContent = "DKIM:";

		// DKIM result
		this._dkimValue = document.createXULElement("label");
		this._dkimValue.classList.add("statusbarpanel-text");
		this._dkimValue.setAttribute("anonid", "statusValue");
		this._dkimValue.setAttribute("context", "copyPopup");

		// DKIM warning icon
		this._dkimWarningIcon = document.createXULElement("image");
		this._dkimWarningIcon.classList.add("alert-icon");
		this._dkimWarningIcon.setAttribute("anonid", "warning-icon");
		this._dkimWarningIcon.setAttribute("tooltip", "dkim-verifier-header-tooltip-warnings");

		// DKIM status icon
		this._dkimStatusIconBox = document.createXULElement("vbox");
		let separatorTop = document.createXULElement("separator");
		separatorTop.setAttribute("flex", "1");
		separatorTop.style.height="0px";
		let separatorBottom = separatorTop.cloneNode();
		this._dkimStatusIcon = document.createXULElement("image");
		this._dkimStatusIcon.setAttribute("anonid", "status-icon");
		this._dkimStatusIcon.setAttribute("tooltip", "dkim-verifier-tooltip-status");
		this._dkimStatusIconBox.appendChild(separatorTop);
		this._dkimStatusIconBox.appendChild(this._dkimStatusIcon);
		this._dkimStatusIconBox.appendChild(separatorBottom);

		this.appendChild(this._label);
		this.appendChild(this._dkimValue);
		this.appendChild(this._dkimWarningIcon);
		this.appendChild(this._dkimStatusIconBox);
	}

	/**
	 * Set the DKIM result
	 *
	 * @memberof DKIMStatusbarpanel
	 * @param {String} val
	 */
	set value(val) {
		this._dkimValue.textContent = val;
	}

	/**
	 * Set the DKIM warnings
	 *
	 * @memberof DKIMStatusbarpanel
	 * @param {String[]} warnings
	 */
	set warnings(warnings) {
		this.setAttribute("warnings", (warnings.length > 0).toString() );
	}

	/**
	 * Set the current status of DKIM validation
	 *
	 * @memberof DKIMStatusbarpanel
	 * @param {String} status
	 */
	set dkimStatus(status) {
		this.setAttribute('dkimStatus', status);
	}

	/**
	 * Set whether to only show an icon for the DKIM result
	 *
	 * @memberof DKIMStatusbarpanel
	 * @param {Boolean} useIcons
	 */
	set useIcons(useIcons) {
		this._dkimValue.hidden = useIcons;
		this._dkimWarningIcon.hidden = useIcons;
		this._dkimStatusIcon.hidden = !useIcons;
  }
}

customElements.define("dkim-verifier-statusbarpanel", DKIMStatusbarpanel, {extends: 'statusbarpanel'});

/*
 * DKIM Verifier display module
 */
DKIM_Verifier.Display = (function() {
	"use strict";
	
/*
 * preferences
 */
	var prefs = Services.prefs.getBranch(PREF_BRANCH);
	
 /*
 * private variables
 */
	const entry = "dkim-verifier";
	var log = DKIM_Verifier.Logging.getLogger("Display");
	/** @type {DKIMHeaderfield} */
	var header;
	var row;
	/** @type {DKIMWarningsTooltip} */
	var headerTooltipWarnings;
	/** @type {DKIMTooltipFrom} */
	var headerTooltipFrom;
	/** @type {DKIMTooltipStatus} */
	var statusbarTooltip;
	/** @type {DKIMStatusbarpanel} */
	var statusbarPanel;
	var expandedFromBox;
	var collapsed1LfromBox; // for CompactHeader addon
	var collapsed2LfromBox; // for CompactHeader addon
	var policyAddUserExceptionButton;
	var markKeyAsSecureButton;
	var updateKeyButton;
	var dkimStrings;

/*
 * private methods
 */

	/**
	 * Sets the result value for headerTooltips and statusbar panel.
	 * 
	 * @param {String} value
	 * @return {void}
	 */
	function setValue(value) {
		headerTooltipFrom.value = value;
		statusbarTooltip.value = value;
		statusbarPanel.value = value;
	}
	
	/**
	 * Sets the warnings for header, headerTooltips and statusbar panel.
	 * 
	 * @param {String[]} warnings
	 * @return {void}
	 */
	function setWarnings(warnings) {
		header.warnings = warnings;
		headerTooltipWarnings.warnings = warnings;
		headerTooltipFrom.warnings = warnings;
		statusbarTooltip.warnings = warnings;
		statusbarPanel.warnings = warnings;
	}
	
	/*
	 * highlight header
	 */
	function highlightHeader(status) {
		function highlightEmailAddresses(headerBox) {
			if (!headerBox.emailAddresses.firstChild) {
				log.trace("Skipped highlightEmailAddresses (!firstChild)");
				return;
			}
			var emailValue = headerBox.emailAddresses.firstChild.
				getElementsByClassName("emaillabel")[0];
			if (status !== "clearHeader") {
				emailValue.style.borderRadius = "3px";
				emailValue.style.color = prefs.
					getCharPref("color."+status+".text");
				emailValue.style.backgroundColor = prefs.
					getCharPref("color."+status+".background");
			} else {
				emailValue.style.color = "";
				emailValue.style.backgroundColor = "";
			}
		}
		
		// highlight or reset header
		if (prefs.getBoolPref("colorFrom") || status === "clearHeader") {
			highlightEmailAddresses(expandedFromBox);

			// for CompactHeader addon
			if (collapsed1LfromBox) {
				highlightEmailAddresses(collapsed1LfromBox);
			}
			if (collapsed2LfromBox) {
				highlightEmailAddresses(collapsed2LfromBox);
			}
		}
	}

	/**
	 * Sets the url to the favicon. Empty string to reset it.
	 * 
	 * @param {String} faviconUrl
	 * @return {void}
	 */
	function setFaviconUrl(faviconUrl) {
		/**
		 * Helper function to create and set properties of the favicon element
		 *
		 * @param {MozMailMultiEmailheaderfield} emailheaderfield
		 * @param {string} url
		 * @return {void}
		 */
		function setDkimFavicon(emailheaderfield, url) {
			if (!emailheaderfield._dkimFavicon) {
				emailheaderfield._dkimFavicon = document.createXULElement("description");
				emailheaderfield._dkimFavicon.classList.add("headerValue");
				emailheaderfield._dkimFavicon.setAttribute("anonid", "dkimFavicon");
				emailheaderfield._dkimFavicon.setAttribute("tooltip", "dkim-verifier-header-tooltip-from");
				// dummy text for align baseline
				emailheaderfield._dkimFavicon.textContent = "";
				emailheaderfield.longEmailAddresses.prepend(emailheaderfield._dkimFavicon);
			}

			emailheaderfield._dkimFavicon.style.backgroundImage = "url('" + url + "')";
			if (url) {
				emailheaderfield.setAttribute("dkimFavicon", "true");
			} else {
				emailheaderfield.setAttribute("dkimFavicon", "false");
			}
		}

		setDkimFavicon(expandedFromBox, faviconUrl);

		// for CompactHeader addon
		if (collapsed1LfromBox) {
			setDkimFavicon(collapsed1LfromBox, faviconUrl);
		}
		if (collapsed2LfromBox) {
			setDkimFavicon(collapsed2LfromBox, faviconUrl);
		}
	}

	/*
	 * handle Exception
	 */
	function handleException(e) {
		try {
			// log error
			if (e instanceof DKIM_Verifier.DKIM_InternalError) {
				log.error(e);
			} else {
				log.fatal(e);
			}

			// show error
			let authResultDKIM = {
				version : "2.0",
				result : "TEMPFAIL",
				errorType : e.errorType,
				res_num : 20,
				result_str : dkimStrings.getString("DKIM_INTERNALERROR_NAME"),
			};
			let authResult = {
				version: "2.0",
				dkim: [authResultDKIM],
			};
			displayResult(authResult);
		} catch (e) {
			log.fatal(e);
		}
	}
		
	/**
	 * display result
	 * 
	 * @param {IAuthVerifier.IAuthResult} result
	 * @return {void}
	 */
	function displayResult(result) {
		log.trace("displayResult begin");
		header.dkimResults = result.dkim;
		statusbarPanel.dkimStatus = result.dkim[0].result;
		that.setCollapsed(result.dkim[0].res_num);
		header.value = result.dkim[0].result_str;
		setValue(result.dkim[0].result_str);

		switch(result.dkim[0].res_num) {
			case DKIM_Verifier.AuthVerifier.DKIM_RES.SUCCESS: {
				let dkim = result.dkim[0];
				if (!dkim.warnings_str ||
					dkim.warnings_str.length === 0)
				{
					highlightHeader("success");
				} else {
					setWarnings(dkim.warnings_str);
					highlightHeader("warning");
				}

				// if enabled and available, set url to favicon
				if (prefs.getBoolPref("display.favicon.show") &&
					dkim.favicon)
				{
					setFaviconUrl(dkim.favicon);
				}
				break;
			}
			case DKIM_Verifier.AuthVerifier.DKIM_RES.TEMPFAIL:
				highlightHeader("tempfail");
				break;
			case DKIM_Verifier.AuthVerifier.DKIM_RES.PERMFAIL:
				highlightHeader("permfail");
				break;
			case DKIM_Verifier.AuthVerifier.DKIM_RES.PERMFAIL_NOSIG:
			case DKIM_Verifier.AuthVerifier.DKIM_RES.NOSIG:
				highlightHeader("nosig");
				break;
			default:
				throw new DKIM_Verifier.DKIM_InternalError("unknown res_num: " +
					result.dkim[0].res_num);
		}

		// policyAddUserExceptionButton
		if ((
				result.dkim[0].errorType === "DKIM_POLICYERROR_MISSING_SIG" ||
				result.dkim[0].errorType === "DKIM_POLICYERROR_WRONG_SDID" ||
				(
					result.dkim[0].warnings &&
					result.dkim[0].warnings.findIndex((e) => {
						return e.name === "DKIM_POLICYERROR_WRONG_SDID";}) !== -1
				)
			) && policyAddUserExceptionButton)
		{
			policyAddUserExceptionButton.disabled = false;
		}

		// markKeyAsSecureButton / updateKeyButton
		if (prefs.getIntPref("key.storing") !== DKIM_Verifier.PREF.KEY.STORING.DISABLED &&
		    result.dkim[0].sdid && result.dkim[0].selector) {
			if (updateKeyButton) {
				updateKeyButton.disabled = false;
			}
			if (!result.dkim[0].keySecure && markKeyAsSecureButton) {
				markKeyAsSecureButton.disabled = false;
			}
		}

		// SPF result
		if (result.spf && result.spf[0]) {
			header.spfValue = result.spf[0].result;
		}
		// DMARC result
		if (result.dmarc && result.dmarc[0]) {
			header.dmarcValue = result.dmarc[0].result;
		}
		// ARH DKIM result
		if (result.arh && result.arh.dkim && result.arh.dkim[0]) {
			header.arhDkimValue = result.arh.dkim[0].result_str;
		}
		log.trace("displayResult end");
	}
	
var that = {
/*
 * public methods/variables
 */
 
	/*
	 * Initializes the DKIM header entry
	 */
	initHeaderEntry: function Display_initHeaderEntry() {
		if (header && document.getElementById(header.id) !== header) {
			return;
		}
		var e = {
			name: entry,
			outputFunction: that.onOutput.bind(that)
		};
		var view = gExpandedHeaderView[entry] = new createHeaderEntry("expanded", e);
		header = view.enclosingBox;
		row = view.enclosingRow;
	},
	
	/*
	 * Sets visibility of DKIM header, DKIM statusbar panel and DKIM tooltip
	 * based on current state and preferences.
	 *
	 * Gets called every time the current state changes.
	 */
	setCollapsed: function Display_setCollapsed(state) {
		function setDKIMFromTooltip(headerBox) {
			var emailDisplayButton = headerBox.emailAddresses.getElementsByClassName("emaillabel")[0];
			if (emailDisplayButton) {
				emailDisplayButton.tooltip = "dkim-verifier-header-tooltip-from";
				emailDisplayButton.setAttribute("tooltiptextSaved", 
					emailDisplayButton.getAttribute("tooltiptext")
				);
				emailDisplayButton.removeAttribute("tooltiptext");
			}
		}
		function removeDKIMFromTooltip(headerBox) {
			var emailDisplayButton = headerBox.emailAddresses.getElementsByClassName("emaillabel")[0];
			if (emailDisplayButton) {
				if (emailDisplayButton.tooltip === "dkim-verifier-header-tooltip-from") {
					emailDisplayButton.tooltip = "";
					emailDisplayButton.setAttribute("tooltiptext", 
						emailDisplayButton.getAttribute("tooltiptextSaved")
					);
				}
			}
		}

		// DKIM header
		if (prefs.getIntPref("showDKIMHeader") >= state ) {
			// show DKIM header
			
			if (row.collapsed === true) {
				row.collapsed = false;
				syncGridColumnWidths();
			}
		} else {
			// don't show DKIM header
			
			if (row.collapsed === false) {
				row.collapsed = true;
				syncGridColumnWidths();
			}
		}
		
		// DKIM statusbar panel
		if (prefs.getIntPref("showDKIMStatusbarpanel") >= state ) {
			// show DKIM statusbar panel
			
			statusbarPanel.hidden = false;
		} else {
			// don't show DKIM statusbar panel
			
			statusbarPanel.hidden = true;
		}

		// DKIM tooltip for From header
		if (prefs.getIntPref("showDKIMFromTooltip") >= state ) {
			// show tooltip for From header
			setDKIMFromTooltip(expandedFromBox);
			// for CompactHeader addon
			if (collapsed1LfromBox) {
				setDKIMFromTooltip(collapsed1LfromBox);
			}
			if (collapsed2LfromBox) {
				setDKIMFromTooltip(collapsed2LfromBox);
			}
		} else {
			// don't show tooltip for From header
			removeDKIMFromTooltip(expandedFromBox);
			// for CompactHeader addon
			if (collapsed1LfromBox) {
				removeDKIMFromTooltip(collapsed1LfromBox);
			}
			if (collapsed2LfromBox) {
				removeDKIMFromTooltip(collapsed2LfromBox);
			}
		}
	},

	/*
	 * gets called on startup
	 */
	startup : function Display_startup() {
		try {
			log.trace("startup begin");
			// get xul elements
			// @ts-ignore
			headerTooltipWarnings = document.getElementById("dkim-verifier-header-tooltip-warnings");
			console.assert(headerTooltipWarnings !== null, "dkim-verifier-header-tooltip-warnings not found");
			// @ts-ignore
			headerTooltipFrom = document.getElementById("dkim-verifier-header-tooltip-from");
			console.assert(headerTooltipFrom !== null, "dkim-verifier-header-tooltip-from not found");
			// @ts-ignore
			statusbarTooltip = document.getElementById("dkim-verifier-tooltip-status");
			console.assert(statusbarTooltip !== null, "dkim-verifier-tooltip-status not found");
			// @ts-ignore
			statusbarPanel = document.getElementById("dkim-verifier-statusbarpanel");
			expandedFromBox = document.getElementById("expandedfromBox");
			collapsed1LfromBox = document.getElementById("CompactHeader_collapsed1LfromBox");
			collapsed2LfromBox = document.getElementById("CompactHeader_collapsed2LfromBox");
			policyAddUserExceptionButton = document.
				getElementById("dkim_verifier.policyAddUserException");
			markKeyAsSecureButton = document.getElementById("dkim_verifier.markKeyAsSecure");
			updateKeyButton = document.getElementById("dkim_verifier.updateKey");
			dkimStrings = document.getElementById("dkimStrings");

			// Register to receive notifications of preference changes
			prefs.addObserver("", that, false);

			// convert old preferences
			// 0.5.2
			if (prefs.prefHasUserValue("alwaysShowDKIMHeader")) {
				prefs.clearUserPref("alwaysShowDKIMHeader");
				if (!prefs.prefHasUserValue("showDKIMHeader")) {
					prefs.setIntPref("showDKIMHeader", DKIM_Verifier.PREF.SHOW.MSG);
				}
			}

			// load preferences
			if (prefs.getIntPref("statusbarpanel.result.style") ===
				DKIM_Verifier.PREF.STATUSBARPANEL.RESULT.STYLE.TEST)
			{
				if (statusbarPanel) {
					statusbarPanel["useIcons"] = false;
				}
			} else {
				if (statusbarPanel) {
					statusbarPanel["useIcons"] = true;
				}
			}

			that.initHeaderEntry();

			// register monitors for message displaying
			gMessageListeners.push(that);

			// register monitors for tab switch
			var tabmail = document.getElementById("tabmail");
			if (tabmail) {
				that.tabMonitor = {
					onTabTitleChanged: function(/* aTab */) {
						if (statusbarPanel) {
							statusbarPanel.hidden = true;
						}
					},
					onTabSwitched: function(/* aTab, aOldTab */) {
						if (statusbarPanel) {
							statusbarPanel.hidden = true;
						}
					}
				};
				// @ts-ignore
				tabmail.registerTabMonitor(that.tabMonitor);
			}
			log.trace("startup end");
		} catch (e) {
			log.fatal(e);
		}
	},

	/*
	 * gets called on shutdown
	 */
	shutdown : function Display_shutdown() {
		// remove preference observer
		prefs.removeObserver("", that);
		
		// remove event listener for message display
		var pos = gMessageListeners.indexOf(that);
		if (pos !== -1) {
			gMessageListeners.splice(pos, 1);
		}

		// unregister monitors for tab switch
		var tabmail = document.getElementById("tabmail");
		if (tabmail) {
			// @ts-ignore
			tabmail.unregisterTabMonitor(that.tabMonitor);
		}
	},

	/*
	 * gets called called whenever an event occurs on the preference
	 */
	observe: function Display_observe(subject, topic, data) {
		try {
			// subject is the nsIPrefBranch we're observing (after appropriate QI)
			// data is the name of the pref that's been changed (relative to aSubject)

			if (topic !== "nsPref:changed") {
				return;
			}

			switch(data) {
				case "statusbarpanel.result.style":
					if (prefs.getIntPref("statusbarpanel.result.style") ===
						DKIM_Verifier.PREF.STATUSBARPANEL.RESULT.STYLE.TEST)
					{
						statusbarPanel.useIcons = false;
					} else {
						statusbarPanel.useIcons = true;
					}
					break;
				default:
					// ignore other options
			}
		} catch (e) {
			log.fatal(e);
		}
	},
	
	/*
	 * Initializes the header and statusbarpanel
	 * gets called after onStartHeaders
	 * gets called before onEndHeaders
	 */
	onBeforeShowHeaderPane : function Display_onBeforeShowHeaderPane() {
		try {
			log.trace("onBeforeShowHeaderPane begin");
			that.initHeaderEntry();
			var reverifyDKIMSignature = document.
				getElementById("dkim_verifier.reverifyDKIMSignature");

			// if msg is RSS feed or news
			if (gFolderDisplay.selectedMessageIsFeed || gFolderDisplay.selectedMessageIsNews) {
				currentHeaderData[entry] = {
					headerName: entry,
					headerValue: dkimStrings.getString("NOT_EMAIL")
				};
				setValue(dkimStrings.getString("NOT_EMAIL"));
				statusbarPanel.dkimStatus = "none";
				if (reverifyDKIMSignature) {
					reverifyDKIMSignature["disabled"] = true;
				}
			} else {
				currentHeaderData[entry] = {
					headerName: entry,
					headerValue: dkimStrings.getString("loading")
				};
				setValue(dkimStrings.getString("loading"));
				statusbarPanel.dkimStatus = "loading";
				if (reverifyDKIMSignature) {
					reverifyDKIMSignature["disabled"] = false;
				}
			}
			log.trace("onBeforeShowHeaderPane end");
		} catch (e) {
			log.fatal(e);
		}
	},

	/*
	 * Resets the header and statusbarpanel
	 */
	onStartHeaders: function Display_onStartHeaders() {
		try {
			log.trace("onStartHeaders begin");
			setWarnings([]);
			header.spfValue = "";
			header.dmarcValue = "";
			header.arhDkimValue = "";

			// reset highlight from header
			highlightHeader("clearHeader");

			// reset favicon
			setFaviconUrl("");

			if (policyAddUserExceptionButton) {
				policyAddUserExceptionButton.disabled = true;
			}
			if (markKeyAsSecureButton) {
				markKeyAsSecureButton.disabled = true;
			}
			if (updateKeyButton) {
				updateKeyButton.disabled = true;
			}
			log.trace("onStartHeaders end");
		} catch (e) {
			log.fatal(e);
		}
	},

	/*
	 * starts verification
	 */
	onEndHeaders: function Display_onEndHeaders() {
		let promise = (async () => {
			log.trace("onEndHeaders Task begin");
			// return if msg is RSS feed or news
			if (gFolderDisplay.selectedMessageIsFeed || gFolderDisplay.selectedMessageIsNews) {
				that.setCollapsed(DKIM_Verifier.PREF.SHOW.MSG);
				return;
			}
			that.setCollapsed(DKIM_Verifier.PREF.SHOW.DKIM_VALID);
			
			// get msg uri
			var msgURI = gFolderDisplay.selectedMessageUris[0];
			// get msgHdr
			var msgHdr = gFolderDisplay.selectedMessage;
			
			// get authentication result
			let authResult = await DKIM_Verifier.AuthVerifier.verify(msgHdr, msgURI);
			
			// only show result if it's for the currently viewed message
			var currentMsgURI = gFolderDisplay.selectedMessageUris[0];
			if (currentMsgURI === msgURI) {
				displayResult(authResult);
			}
			log.trace("onEndHeaders Task end");
		})();
		promise.then(null, function onReject(exception) {
			handleException(exception);
		});
	},
	onEndAttachments: function Display_onEndAttachments() {}, // eslint-disable-line no-empty-function

	/*
	 * outputFunction for DKIM header (sets the DKIM header value)
	 */
	onOutput: function Display_onOutput(headerEntry, headerValue) {
		header.value = headerValue;
	},
	
	/*
	 * Reverify DKIM Signature
	 */
	reverify : function Display_reverify() {
		log.trace("reverify");
		// get msgHdr
		var msgHdr = gFolderDisplay.selectedMessage;

		header.value = dkimStrings.getString("loading");
		setValue("loading");
		that.onStartHeaders();
		DKIM_Verifier.AuthVerifier.resetResult(msgHdr).then(function () {
			that.onEndHeaders();
		}, function (exception) {
			log.fatal(exception);
		});
	},

	/*
	 * policyAddUserException
	 */
	policyAddUserException : function Display_policyAddUserException() {
		let promise = (async () => {
			log.trace("policyAddUserException Task");
			// get from address
			var mime2DecodedAuthor = gMessageDisplay.displayedMessage.author;
			var msgHeaderParser = Components.classes["@mozilla.org/messenger/headerparser;1"].
				createInstance(Components.interfaces.nsIMsgHeaderParser);
			var from = msgHeaderParser.extractHeaderAddressMailboxes(mime2DecodedAuthor);

			await DKIM_Verifier.Policy.addUserException(from);
			
			that.reverify();
		})();
		promise.then(null, function onReject(exception) {
			log.fatal(exception);
		});
	},

	/*
	 * mark the stored DKIM key of the shown DKIM signature as secure
	 */
	markKeyAsSecure : function Display_markKeyAsSecure() {
		let promise = (async () => {
			log.trace("markKeyAsSecure Task");
			await DKIM_Verifier.Key.markKeyAsSecure(
				header.dkimResults[0].sdid, header.dkimResults[0].selector);
			
			that.reverify();
		})();
		promise.then(null, function onReject(exception) {
			log.fatal(exception);
		});
	},

	/*
	 * update the stored DKIM key of all DKIM signatures
	 */
	updateKey : function Display_updateKey() {
		let promise = (async () => {
			log.trace("updateKey Task");
			for (let dkimResult of header.dkimResults) {
				await DKIM_Verifier.Key.deleteKey(
					dkimResult.sdid, dkimResult.selector);
			}
			
			that.reverify();
		})();
		promise.then(null, function onReject(exception) {
			log.fatal(exception);
		});
	},
};
return that;
}()); // the parens here cause the anonymous function to execute and return

addEventListener("load", function dkim_load() {
	"use strict";
	
	removeEventListener("load", dkim_load, false);
	DKIM_Verifier.Display.startup();
}, false);
addEventListener("unload", function dkim_unload() {
	"use strict";
	
	removeEventListener("unload", dkim_unload, false);
	DKIM_Verifier.Display.shutdown();
}, false);
