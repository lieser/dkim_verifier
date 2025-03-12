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
/* global Components, Cu, Services, gMessageListeners, gFolderDisplay, gExpandedHeaderView, createHeaderEntry, syncGridColumnWidths, currentHeaderData, gMessageDisplay */

// namespace
var DKIM_Verifier = {};
Cu.import("resource://dkim_verifier/logging.jsm.js", DKIM_Verifier);
Cu.import("resource://dkim_verifier/helper.jsm.js", DKIM_Verifier);
Cu.import("resource://dkim_verifier/authVerifier.jsm.js", DKIM_Verifier);
Cu.import("resource://dkim_verifier/dkimPolicy.jsm.js", DKIM_Verifier);
Cu.import("resource://dkim_verifier/dkimKey.jsm.js", DKIM_Verifier);


// @ts-expect-error
const PREF_BRANCH = "extensions.dkim_verifier.";

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
	/** @type {AuthResultElement} */
	var header;
	var row;
	var headerTooltips;
	var statusbarPanel;
	var expandedFromBox;
	var collapsed1LfromBox; // for CompactHeader addon
	var collapsed2LfromBox; // for CompactHeader addon
	var verifierBox;
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
	 * @param {String|undefined} [details]
	 * @return {void}
	 */
	function setValue(value, details) {
		headerTooltips.value = value;
		statusbarPanel.value = value;

		let emailBox = expandedFromBox ? expandedFromBox.emailAddresses.boxObject.firstChild : undefined;
		let emailBoxCH1 = collapsed1LfromBox ? collapsed1LfromBox.emailAddresses.boxObject.firstChild : undefined; // for CompactHeader addon
		let emailBoxCH2 = collapsed2LfromBox ? collapsed2LfromBox.emailAddresses.boxObject.firstChild : undefined; // for CompactHeader addon

		let showFromToolTip =
			(emailBox && emailBox.tooltip === "dkim-verifier-header-tooltip-from")
			|| (emailBoxCH1 && emailBoxCH1.tooltip === "dkim-verifier-header-tooltip-from")
			|| (emailBoxCH2 && emailBoxCH2.tooltip === "dkim-verifier-header-tooltip-from");

		if (details) {
			if (showFromToolTip && emailBox) { emailBox.tooltipText = details; }
			if (showFromToolTip && emailBoxCH1) { emailBoxCH1.tooltipText = details; }
			if (showFromToolTip && emailBoxCH2) { emailBoxCH2.tooltipText = details; }
			verifierBox.boxObject.firstChild.tooltipText = details;
			statusbarPanel.tooltipText = details;
		} else {
			if (emailBox) { emailBox.tooltipText = ""; }
			if (emailBoxCH1) { emailBoxCH1.tooltipText = ""; }
			if (emailBoxCH2) { emailBoxCH2.tooltipText = ""; }
			verifierBox.boxObject.firstChild.tooltipText = "";
			statusbarPanel.tooltipText = "";
		}
	}

	/**
	 * Sets the warnings for header, headerTooltips and statusbar panel.
	 *
	 * @param {String[]} warnings
	 * @return {void}
	 */
	function setWarnings(warnings) {
		header.warnings = warnings;
		headerTooltips.warnings = warnings;
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
				getPart("emailValue");
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

		let activeTheme = Services.prefs.getBranch("general.skins.").getCharPref("selectedSkin");

		if (activeTheme && activeTheme.match(/^(?:silvermel|charamel)$/i)) {
		// using the theme's contact icon for the DKIM symbol
			if (faviconUrl === "") {
				expandedFromBox.style.backgroundImage = '';
				expandedFromBox.style.backgroundSize = '';
				if (collapsed1LfromBox) {
					collapsed1LfromBox.style.backgroundImage = '';
					collapsed1LfromBox.style.backgroundSize = '';
				}
				if (collapsed2LfromBox) {
					collapsed2LfromBox.style.backgroundImage = '';
					collapsed2LfromBox.style.backgroundSize = '';
				}
			} else {
				expandedFromBox.style.backgroundImage = 'url("'+faviconUrl+'")';
				expandedFromBox.style.backgroundSize = '16px 16px';
				if (collapsed1LfromBox) {
					collapsed1LfromBox.style.backgroundImage = 'url("'+faviconUrl+'")';
					collapsed1LfromBox.style.backgroundSize = '16px 16px';
				}
				if (collapsed2LfromBox) {
					collapsed2LfromBox.style.backgroundImage = 'url("'+faviconUrl+'")';
					collapsed2LfromBox.style.backgroundSize = '16px 16px';
				}
			}
		} else {
		// default behavior for all skins: using DKIM verifier icon
			expandedFromBox.dkimFaviconUrl = faviconUrl;

			// for CompactHeader addon
			if (collapsed1LfromBox) {
				collapsed1LfromBox.dkimFaviconUrl = faviconUrl;
			}
			if (collapsed2LfromBox) {
				collapsed2LfromBox.dkimFaviconUrl = faviconUrl;
			}
		}
	}

	/*
	 * handle Exception
	 */
	function handleException(e) {
		try {
			// log error
			if (e instanceof DKIM_Verifier.DKIM_TempError) {
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
	 * @throws {Error}
	 */
	// eslint-disable-next-line complexity
	function displayResult(result) {
		log.trace("displayResult begin");
		header.dkimResults = result.dkim;
		statusbarPanel.dkimStatus = result.dkim[0].result;
		that.setCollapsed(result.dkim[0].res_num);
		header.value = result.dkim[0].result_str;

		let resultCount = 0;
		let detailsHint;
		if (prefs.getBoolPref("advancedInfo.show")) {
			detailsHint	= "";
			if (prefs.getBoolPref("advancedInfo.allSignatures")) {
				result.dkim.forEach(dkim => {
					if (dkim.details_str) {
						detailsHint += "\n----\n" + dkim.details_str;
						resultCount += 1;
					}
				});
				if (resultCount === 0) {
					// the check resulted in an error, because the signature wasn't well formed
					// or there was no signature
					detailsHint = undefined;
				}
			} else {
				detailsHint = result.dkim[0].details_str;
			}
			if (detailsHint) {
				// there is extended information to display
				let caption = "";
				if (prefs.getBoolPref("advancedInfo.allSignatures")) {
					let resultStr = "DKIM_RESULT_DETAILS_SIG_COUNT";
					if (prefs.getBoolPref("arh.replaceAddonResult")) {
						resultStr = "DKIM_RESULT_DETAILS_HEADER_COUNT";
					}
					caption = dkimStrings.getFormattedString(resultStr, [resultCount]);
				}
				detailsHint = caption + detailsHint;
			}
		}
		setValue(result.dkim[0].result_str, detailsHint);

		switch(result.dkim[0].res_num) {
			case DKIM_Verifier.authVerifier.DKIM_RES.SUCCESS: {
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
			case DKIM_Verifier.authVerifier.DKIM_RES.TEMPFAIL:
				highlightHeader("tempfail");
				break;
			case DKIM_Verifier.authVerifier.DKIM_RES.PERMFAIL:
				highlightHeader("permfail");
				break;
			case DKIM_Verifier.authVerifier.DKIM_RES.PERMFAIL_NOSIG:
			case DKIM_Verifier.authVerifier.DKIM_RES.NOSIG:
				highlightHeader("nosig");
				break;
			default:
				throw new Error(`unknown res_num: ${result.dkim[0].res_num}`);
		}

		// policyAddUserExceptionButton
		if ((
				result.dkim[0].errorType === "DKIM_POLICYERROR_MISSING_SIG" ||
				result.dkim[0].errorType === "DKIM_POLICYERROR_WRONG_SDID" ||
				(
					result.dkim[0].warnings &&
					result.dkim[0].warnings.findIndex(e => e.name === "DKIM_POLICYERROR_WRONG_SDID") !== -1
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
			var emailDisplayButton = headerBox.emailAddresses.boxObject.firstChild;
			if (emailDisplayButton) {
				emailDisplayButton.tooltip = "dkim-verifier-header-tooltip-from";
				emailDisplayButton.setAttribute("tooltiptextSaved",
					emailDisplayButton.getAttribute("tooltiptext")
				);
				emailDisplayButton.removeAttribute("tooltiptext");
			}
		}
		function removeDKIMFromTooltip(headerBox) {
			var emailDisplayButton = headerBox.emailAddresses.boxObject.firstChild;
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
			headerTooltips = document.getElementById("dkim-verifier-header-tooltips");
			statusbarPanel = document.getElementById("dkim-verifier-statusbarpanel");
			expandedFromBox = document.getElementById("expandedfromBox");
			collapsed1LfromBox = document.getElementById("CompactHeader_collapsed1LfromBox");
			collapsed2LfromBox = document.getElementById("CompactHeader_collapsed2LfromBox");
			verifierBox = document.getElementById("expandeddkim-verifierBox");
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
				// @ts-expect-error
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
			// @ts-expect-error
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
			let authResult = await DKIM_Verifier.authVerifier.verify(msgHdr, msgURI);

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
		DKIM_Verifier.authVerifier.resetResult(msgHdr).then(function () {
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
			const sdid = header.dkimResults[0].sdid;
			const selector = header.dkimResults[0].selector;
			if (sdid === undefined || selector === undefined) {
				log.error("Can not mark key as secure, result does not contain an sdid or selector");
				return;
			}
			await DKIM_Verifier.Key.markKeyAsSecure(
				sdid, selector);

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
				const sdid = dkimResult.sdid;
				const selector = dkimResult.selector;
				if (sdid === undefined || selector === undefined) {
					log.error("Can not delete key, result does not contain an sdid or selector");
					return;
				}
				await DKIM_Verifier.Key.deleteKey(sdid, selector);
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
