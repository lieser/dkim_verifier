/*
 * dkim.js - DKIM Verifier Extension for Mozilla Thunderbird
 * 
 * Verifies the DKIM signature if a new message is viewed,
 * and displays the result.
 *
 * Copyright (c) 2013-2014 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// options for JSHint
/* jshint strict:true, moz:true */
/* jshint unused:true */ // allow unused parameters that are followed by a used parameter.
/* global Components, Cu, Services, gMessageListeners, gFolderDisplay, gExpandedHeaderView, createHeaderEntry, syncGridColumnWidths, currentHeaderData, gMessageDisplay */
/* global Task */

Cu.import("resource://gre/modules/Task.jsm"); // Requires Gecko 17.0

// namespace
var DKIM_Verifier = {};
Cu.import("resource://dkim_verifier/logging.jsm", DKIM_Verifier);
Cu.import("resource://dkim_verifier/helper.jsm", DKIM_Verifier);
Cu.import("resource://dkim_verifier/AuthVerifier.jsm", DKIM_Verifier);
Cu.import("resource://dkim_verifier/dkimPolicy.jsm", DKIM_Verifier);
Cu.import("resource://dkim_verifier/dkimKey.jsm", DKIM_Verifier);


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
	var header;
	var row;
	var headerTooltips;
	var statusbarpanel;
	var policyAddUserExceptionButton;
	var markKeyAsSecureButton;
	var updateKeyButton;
	var dkimStrings;

/*
 * private methods
 */

	/**
	 * Sets the result value for headerTooltips and statusbarpanel.
	 * 
	 * @param {String} value
	 */
	function setValue(value) {
		headerTooltips.value = value;
		statusbarpanel.value = value;
	}
	
	/**
	 * Sets the warnings for header, headerTooltips and statusbarpanel.
	 * 
	 * @param {String[]} warnings
	 */
	function setWarnings(warnings) {
		header.warnings = warnings;
		headerTooltips.warnings = warnings;
		statusbarpanel.warnings = warnings;
	}
	
	/*
	 * highlight header
	 */
	function highlightHeader(status) {
		function highlightEmailAddresses(headerBox) {
			if (status !== "clearHeader") {
				headerBox.emailAddresses.style.borderRadius = "3px";
				headerBox.emailAddresses.style.color = prefs.
					getCharPref("color."+status+".text");
				headerBox.emailAddresses.style.backgroundColor = prefs.
					getCharPref("color."+status+".background");
			} else {
				headerBox.emailAddresses.style.color = "";
				headerBox.emailAddresses.style.backgroundColor = "";
			}
		}
		
		// highlight or reset header
		if (prefs.getBoolPref("colorFrom") || status === "clearHeader") {
			var expandedfromBox = document.getElementById("expandedfromBox");
			highlightEmailAddresses(expandedfromBox);

			// for CompactHeader addon
			var collapsed1LfromBox = document.getElementById("CompactHeader_collapsed1LfromBox");
			if (collapsed1LfromBox) {
				highlightEmailAddresses(collapsed1LfromBox);
			}
			var collapsed2LfromBox = document.getElementById("CompactHeader_collapsed2LfromBox");
			if (collapsed2LfromBox) {
				highlightEmailAddresses(collapsed2LfromBox);
			}
		}
	}

	/*
	 * handeles Exeption
	 */
	function handleExeption(e) {
		// log error
		if (e instanceof DKIM_Verifier.DKIM_InternalError) {
			log.error(DKIM_Verifier.exceptionToStr(e));
		} else {
			log.fatal(DKIM_Verifier.exceptionToStr(e));
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
	}
		
	/**
	 * display result
	 * 
	 * @param {AuthResult} result
	 */
	function displayResult(result) {
		header.dkimResult = result.dkim[0];
		statusbarpanel.dkimStatus = result.dkim[0].result;
		that.setCollapsed(result.dkim[0].res_num);
		header.value = result.dkim[0].result_str;
		setValue(result.dkim[0].result_str);

		switch(result.dkim[0].res_num) {
			case 10:
				if (result.dkim[0].warnings_str.length === 0) {
					highlightHeader("success");
				} else {
					setWarnings(result.dkim[0].warnings_str);
					highlightHeader("warning");
				}
				break;
			case 20:
				highlightHeader("tempfail");
				break;
			case 30:
				highlightHeader("permfail");
				break;
			case 35:
			case 40:
				highlightHeader("nosig");
				break;
			default:
				throw new DKIM_Verifier.DKIM_InternalError("unkown res_num: " +
					result.dkim[0].res_num);
		}

		// policyAddUserExceptionButton
		if ((result.dkim[0].errorType === "DKIM_POLICYERROR_MISSING_SIG" ||
		     result.dkim[0].errorType === "DKIM_POLICYERROR_WRONG_SDID" ||
		     ( result.dkim[0].warnings &&
		       result.dkim[0].warnings.indexOf("DKIM_POLICYERROR_WRONG_SDID") !== -1
		     )
		    ) && policyAddUserExceptionButton) {
			policyAddUserExceptionButton.disabled = false;
		}

		// markKeyAsSecureButton / updateKeyButton
		if (prefs.getIntPref("key.storing") !== 0 &&
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
		/* jshint -W055 */
		var view = gExpandedHeaderView[entry] = new createHeaderEntry("expanded", e);
		/* jshint -W055 */
		header = view.enclosingBox;
		row = view.enclosingRow;
	},
	
	/*
	 * Sets visibility of DKIM header, DKIM statusbarpanel and DKIM tooltip
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
		
		// DKIM statusbarpanel
		if (prefs.getIntPref("showDKIMStatusbarpanel") >= state ) {
			// show DKIM statusbarpanel
			
			statusbarpanel.hidden = false;
		} else {
			// don't show DKIM statusbarpanel
			
			statusbarpanel.hidden = true;
		}

		// DKIM tooltip for From header
		var expandedfromBox = document.getElementById("expandedfromBox");
		// for CompactHeader addon
		var collapsed1LfromBox = document.getElementById("CompactHeader_collapsed1LfromBox");
		var collapsed2LfromBox = document.getElementById("CompactHeader_collapsed2LfromBox");
		if (prefs.getIntPref("showDKIMFromTooltip") >= state ) {
			// show tooltip for From header
			setDKIMFromTooltip(expandedfromBox);
			// for CompactHeader addon
			if (collapsed1LfromBox) {
				setDKIMFromTooltip(collapsed1LfromBox);
			}
			if (collapsed2LfromBox) {
				setDKIMFromTooltip(collapsed2LfromBox);
			}
		} else {
			// don't show tooltip for From header
			removeDKIMFromTooltip(expandedfromBox);
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
		// get xul elements
		headerTooltips = document.getElementById("dkim-verifier-header-tooltips");
		statusbarpanel = document.getElementById("dkim-verifier-statusbarpanel");
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
				prefs.setIntPref("showDKIMHeader", 50);
			}
		}
		
		// load preferences
		if (prefs.getIntPref("statusbarpanel.result.style") === 1) {
			statusbarpanel.useIcons = false;
		} else {
			statusbarpanel.useIcons = true;
		}

		that.initHeaderEntry();

		// register monitors for message displaying
		gMessageListeners.push(that);
		
		// register monitors for tabswitch
		var tabmail = document.getElementById("tabmail");
		if (tabmail) {
			that.tabMonitor = {
				onTabTitleChanged: function(/* aTab */) {
					if (statusbarpanel) {
						statusbarpanel.hidden = true;
					}
				},
				onTabSwitched: function(/* aTab, aOldTab */) {
					if (statusbarpanel) {
						statusbarpanel.hidden = true;
					}
				}
			};
			tabmail.registerTabMonitor(that.tabMonitor);
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

		// unregister monitors for tabswitch
		var tabmail = document.getElementById("tabmail");
		if (tabmail) {
			tabmail.unregisterTabMonitor(that.tabMonitor);
		}
	},

	/*
	 * gets called called whenever an event occurs on the preference
	 */
	observe: function Display_observe(subject, topic, data) {
		// subject is the nsIPrefBranch we're observing (after appropriate QI)
		// data is the name of the pref that's been changed (relative to aSubject)
		
		if (topic !== "nsPref:changed") {
			return;
		}
		
		switch(data) {
			case "statusbarpanel.result.style":
				if (prefs.getIntPref("statusbarpanel.result.style") === 1) {
					statusbarpanel.useIcons = false;
				} else {
					statusbarpanel.useIcons = true;
				}
				break;
		}
	},
	
	/*
	 * Initializes the header and statusbarpanel
	 * gets called after onStartHeaders
	 * gets called before onEndHeaders
	 */
	onBeforeShowHeaderPane : function Display_onBeforeShowHeaderPane() {
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
			statusbarpanel.dkimStatus = "none";
			if (reverifyDKIMSignature) {
				reverifyDKIMSignature.disabled = true;
			}
		} else {
			currentHeaderData[entry] = {
				headerName: entry,
				headerValue: dkimStrings.getString("loading")
			};
			setValue(dkimStrings.getString("loading"));
			statusbarpanel.dkimStatus = "loading";
			if (reverifyDKIMSignature) {
				reverifyDKIMSignature.disabled = false;
			}
		}
	},

	/*
	 * Resets the header and statusbarpanel
	 */
	onStartHeaders: function Display_onStartHeaders() {
		setWarnings([]);
		header.spfValue = "";
		header.dmarcValue = "";

		// reset highlight from header
		highlightHeader("clearHeader");
		
		if (policyAddUserExceptionButton) {
			policyAddUserExceptionButton.disabled = true;
		}
		if (markKeyAsSecureButton) {
			markKeyAsSecureButton.disabled = true;
		}
		if (updateKeyButton) {
			updateKeyButton.disabled = true;
		}
	},

	/*
	 * starts verification
	 */
	onEndHeaders: function Display_onEndHeaders() {
		let promise = Task.spawn(function () {
			// return if msg is RSS feed or news
			if (gFolderDisplay.selectedMessageIsFeed || gFolderDisplay.selectedMessageIsNews) {
				that.setCollapsed(50);
				return;
			}
			that.setCollapsed(10);
			
			// get msg uri
			var msgURI = gFolderDisplay.selectedMessageUris[0];
			// get msgHdr
			var msgHdr = gFolderDisplay.selectedMessage;
			
			// get authentication result
			let authResult = yield DKIM_Verifier.AuthVerifier.verify(msgHdr, msgURI);
			
			// only show result if it's for the currently viewed message
			var currentMsgURI = gFolderDisplay.selectedMessageUris[0];
			if (currentMsgURI === msgURI) {
				displayResult(authResult);
			}
		});
		promise.then(null, function onReject(exception) {
			handleExeption(exception);
		});
	},
	onEndAttachments: function Display_onEndAttachments() {},

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
		// get msgHdr
		var msgHdr = gFolderDisplay.selectedMessage;

		header.value = dkimStrings.getString("loading");
		setValue("loading");
		that.onStartHeaders();
		DKIM_Verifier.AuthVerifier.resetResult(msgHdr).then(function () {
			that.onEndHeaders();
		}, function (exception) {
			handleExeption(exception);
		});
	},

	/*
	 * policyAddUserException
	 */
	policyAddUserException : function Display_policyAddUserException() {
		Task.spawn(function () {
			// get from address
			var mime2DecodedAuthor = gMessageDisplay.displayedMessage.author;
			var msgHeaderParser = Components.classes["@mozilla.org/messenger/headerparser;1"].
				createInstance(Components.interfaces.nsIMsgHeaderParser);
			var from = msgHeaderParser.extractHeaderAddressMailboxes(mime2DecodedAuthor);

			yield DKIM_Verifier.Policy.addUserException(from);
			
			that.reverify();
		});
	},

	/*
	 * mark stored DKIM key as secure
	 */
	markKeyAsSecure : function Display_markKeyAsSecure() {
		Task.spawn(function () {
			yield DKIM_Verifier.Key.markKeyAsSecure(
				header.dkimResult.SDID, header.dkimResult.selector);
			
			that.reverify();
		});
	},

	/*
	 * update stored DKIM key
	 */
	updateKey : function Display_updateKey() {
		Task.spawn(function () {
			yield DKIM_Verifier.Key.deleteKey(
				header.dkimResult.SDID, header.dkimResult.selector);
			
			that.reverify();
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
