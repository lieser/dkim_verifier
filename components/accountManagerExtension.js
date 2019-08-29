/*
 * accountManagerExtension.js
 * 
 * Implements a nsIAccountManagerExtension.
 *
 * Version: 1.0.0 (26 January 2016)
 * 
 * Copyright (c) 2016 Philippe Lieser
 * 
 * This software is licensed under the terms of the MIT License.
 * 
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

/* eslint strict: ["warn", "function"] */
/* global Components, ChromeUtils, XPCOMUtils */

var { XPCOMUtils } = ChromeUtils.import("resource://gre/modules/XPCOMUtils.jsm");

//class constructor
function DkimVerifierAccountManagerExtension() {"use strict";}

// class definition
DkimVerifierAccountManagerExtension.prototype = {
	name : "dkim_verifier-prefs",
	chromePackageName : "dkim_verifier",
	classID: Components.ID("{850258f2-ae8b-421a-8a9c-bd99fdcc8097}"),
	classDescription: "DKIM Verifier Account Manager Extension",
	contractID: "@mozilla.org/accountmanager/extension;1?name=dkim_verifier-prefs",

	QueryInterface: ChromeUtils.generateQI([
		Components.interfaces.nsIMsgAccountManagerExtension
	]),
	showPanel: function(server) 
	{
		"use strict";

		// this panel is only shown for imap and pop3 accounts
		if (server.type === "imap" || server.type === "pop3") {
			return true;
		}
		return false;
	},
};

// create factory for account setting extension
var components = [DkimVerifierAccountManagerExtension];
const NSGetFactory = XPCOMUtils.generateNSGetFactory(components);
