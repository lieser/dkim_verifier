/*
 * dkim.js - DKIM Verifier Extension for Mozilla Thunderbird
 * 
 * Verifies the DKIM signature if a new message is viewed,
 * and displays the result.
 *
 * Copyright (c) 2013 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// options for JSHint
/* jshint strict:true, moz:true */
/* jshint unused:true */ // allow unused parameters that are followed by a used parameter.
/* global Components, Cu, Services, messenger, gMessageListeners, gDBView, gFolderDisplay, gExpandedHeaderView, createHeaderEntry, syncGridColumnWidths, currentHeaderData, gMessageDisplay */

// namespace
var DKIM_Verifier = {};

Cu.import("resource://dkim_verifier/logging.jsm", DKIM_Verifier);
Cu.import("resource://dkim_verifier/helper.jsm", DKIM_Verifier);
Cu.import("resource://dkim_verifier/dkimVerifier.jsm", DKIM_Verifier);
Cu.import("resource://dkim_verifier/dkimPolicy.jsm", DKIM_Verifier);


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
	var statusbarpanel;
	var policyAddUserExceptionButton;
	var dkimStrings;

/*
 * private methods
 */

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
	function handleExeption(e, msg) {
		var result;
		
		// show result
		result = {
			version : "1.0",
			result : "TEMPFAIL",
			errorType : e.errorType
		};
		displayResult(result);
	
		if (e instanceof DKIM_Verifier.DKIM_InternalError) {
			log.error(DKIM_Verifier.exceptionToStr(e));
		} else {
			log.fatal(DKIM_Verifier.exceptionToStr(e));
		}
	}
	
	/*
	 * save result
	 */
	function saveResult(msgURI, result) {
		if (prefs.getBoolPref("saveResult")) {
			// don't save result if message is external
			if (gFolderDisplay.selectedMessageIsExternal) {
				return;
			}
		
			var msgHdr = messenger.messageServiceFromURI(msgURI).
				messageURIToMsgHdr(msgURI);
			
			if (result === "") {
				log.debug("reset result");
				msgHdr.setStringProperty("dkim_verifier@pl-result", "");
			} else {
				log.debug("save result");
				msgHdr.setStringProperty("dkim_verifier@pl-result", JSON.stringify(result));
			}
		}
	}
	
	/*
	 * get result
	 */
	function getResult(msgURI) {
		if (prefs.getBoolPref("saveResult")) {
			// don't read result if message is external
			if (gFolderDisplay.selectedMessageIsExternal) {
				return null;
			}

			var msgHdr = messenger.messageServiceFromURI(msgURI).
				messageURIToMsgHdr(msgURI);
			
			var result = msgHdr.getStringProperty("dkim_verifier@pl-result");
			
			if (result !== "") {
				log.debug("result found: "+result);
			
				result = JSON.parse(result);

				if (result.version.match(/^[0-9]+/)[0] !== "1") {
					throw new DKIM_Verifier.DKIM_InternalError("Result has wrong Version ("+result.version+")");
				}
			
				return result;
			}
		}
		
		return null;
	}
	
	/*
	 * display result
	 */
	function displayResult(result) {
		var str;
	
		statusbarpanel.dkimStatus = result.result;
		switch(result.result) {
			case "none":
				header.value = dkimStrings.getString("NOSIG");
				that.setCollapsed(40);
				statusbarpanel.value = dkimStrings.getString("NOSIG");

				// highlight from header
				highlightHeader("nosig");
				
				break;
			case "SUCCESS":
				that.setCollapsed(10);
				str = dkimStrings.getFormattedString("SUCCESS", [result.SDID]);
				header.value = str;
				statusbarpanel.value = str;
				
				// show warnings
				if (result.warnings.length > 0) {
					var warnings = result.warnings.map(function(e) {
						if (e === "DKIM_POLICYWARNING_WRONG_SDID") {
							return DKIM_Verifier.
								tryGetFormattedString(dkimStrings, e, [result.shouldBeSignedBy]) || e;
						} else {
							return DKIM_Verifier.tryGetString(dkimStrings, e) || e;
						}
					});
					header.warnings = warnings;
					statusbarpanel.warnings = warnings;
				}
				
				// highlight from header
				if (result.warnings.length === 0) {
					highlightHeader("success");
				} else {
					highlightHeader("warning");
				}
				
				break;
			case "PERMFAIL":
				that.setCollapsed(30);
				var errorMsg;
				if (result.errorType === "DKIM_POLICYERROR_MISSING_SIG") {
					errorMsg = DKIM_Verifier.
						tryGetFormattedString(dkimStrings, result.errorType, [result.shouldBeSignedBy]) ||
						result.errorType;
					policyAddUserExceptionButton.disabled = false;
				} else {
					errorMsg = DKIM_Verifier.tryGetString(dkimStrings, result.errorType) ||
						result.errorType;
				}
				str = dkimStrings.getFormattedString("PERMFAIL", [errorMsg]);
				header.value = str;
				statusbarpanel.value = str;

				// if domain is testing DKIM, treat msg as not signed
				if (result.errorType === "DKIM_SIGERROR_KEY_TESTMODE") {
					that.setCollapsed(40);
					// highlight from header
					highlightHeader("nosig");
					break;
				}
				
				// highlight from header
				highlightHeader("permfail");
				
				break;
			case "TEMPFAIL":
				that.setCollapsed(20);
				
				str = DKIM_Verifier.tryGetString(dkimStrings, result.errorType) ||
					result.errorType ||
					dkimStrings.getString("DKIM_INTERNALERROR_NAME");
				header.value = str;
				statusbarpanel.value = str;
				
				// highlight from header
				highlightHeader("tempfail");
				
				break;
			default:
				throw new DKIM_Verifier.DKIM_InternalError("unkown result");
		}
	}
	
var that = {
/*
 * public methods/variables
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
	setCollapsed: function Display_setCollapsed(state) {
		function setDKIMFromTooltip(headerBox) {
			var emailDisplayButton = headerBox.emailAddresses.boxObject.firstChild;
			if (emailDisplayButton) {
				emailDisplayButton.tooltip = "dkim-verifier-tooltip-from";
				emailDisplayButton.setAttribute("tooltiptextSaved", 
					emailDisplayButton.getAttribute("tooltiptext")
				);
				emailDisplayButton.removeAttribute("tooltiptext");
			}
		}
		function removeDKIMFromTooltip(headerBox) {
			var emailDisplayButton = headerBox.emailAddresses.boxObject.firstChild;
			if (emailDisplayButton) {
				if (emailDisplayButton.tooltip === "dkim-verifier-tooltip-from") {
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
		statusbarpanel = document.getElementById("dkim-verifier-statusbarpanel");
		policyAddUserExceptionButton = document.
			getElementById("dkim_verifier.policyAddUserException");
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
	 * gets called if a new message ist viewed
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
			statusbarpanel.value = dkimStrings.getString("NOT_EMAIL");
			statusbarpanel.dkimStatus = "none";
			if (reverifyDKIMSignature) {
				reverifyDKIMSignature.disabled = true;
			}
		} else {
			currentHeaderData[entry] = {
				headerName: entry,
				headerValue: dkimStrings.getString("loading")
			};
			statusbarpanel.value = dkimStrings.getString("loading");
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
		header.warnings = [];
		statusbarpanel.warnings = [];

		// reset highlight from header
		highlightHeader("clearHeader");
		
		policyAddUserExceptionButton.disabled = true;
	},

	/*
	 * starts verification
	 */
	onEndHeaders: function Display_onEndHeaders() {
		try {
			// return if msg is RSS feed or news
			if (gFolderDisplay.selectedMessageIsFeed || gFolderDisplay.selectedMessageIsNews) {
				that.setCollapsed(50);
				return;
			}
			that.setCollapsed(10);
			
			// get msg uri
			var msgURI = gFolderDisplay.selectedMessageUris[0];

			// check for saved result
			var result = getResult(msgURI);
			if (result !== null) {
				displayResult(result);
				return;
			}
			
			// parse msg into msg.header and msg.body
			// this function will continue the verification
			DKIM_Verifier.Verifier.verify(msgURI, that.dkimResultCallback);
		} catch(e) {
			handleExeption(e, {"msgURI": msgURI});
		}
	},
	onEndAttachments: function Display_onEndAttachments() {},

	/*
	 * Initializes the DKIM header
	 */
	onOutput: function Display_onOutput(headerEntry, headerValue) {
		header.value = headerValue;
	},

	/**
	 * Callback for the result of the verification.
	 * 
	 * @param {String} msgURI
	 * @param {dkimResult} result
	 */
	dkimResultCallback: function Display_dkimResultCallback(msgURI, result) {
		try {
			// don't save result if it's a TEMPFAIL
			if (result.result !== "TEMPFAIL") {
				saveResult(msgURI, result);
			}
			// only show result if it's for the currently viewed message
			var currentMsgURI = gFolderDisplay.selectedMessageUris[0];
			if (currentMsgURI === msgURI) {
				displayResult(result);
			}
		} catch(e) {
			handleExeption(e, {"msgURI": msgURI});
		}
	},
	
	/*
	 * Reverify DKIM Signature
	 */
	reverify : function Display_reverify() {
		// get msg uri
		var msgURI = gDBView.URIForFirstSelectedMessage;

		header.value = dkimStrings.getString("loading");
		that.onStartHeaders();
		saveResult(msgURI, "");
		that.onEndHeaders();
	},

	/*
	 * policyAddUserException
	 */
	policyAddUserException : function Display_policyAddUserException() {
		// get from address
		var mime2DecodedAuthor = gMessageDisplay.displayedMessage.author;
		var msgHeaderParser = Components.classes["@mozilla.org/messenger/headerparser;1"].
			createInstance(Components.interfaces.nsIMsgHeaderParser);
		var from = msgHeaderParser.extractHeaderAddressMailboxes(mime2DecodedAuthor);

		DKIM_Verifier.Policy.addUserException(from);
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
