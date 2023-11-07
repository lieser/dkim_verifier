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

Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");

//class constructor
function DkimVerifierAccountManagerExtension() {}

// class definition
DkimVerifierAccountManagerExtension.prototype = {
	name : "dkim_verifier-prefs",
	chromePackageName : "dkim_verifier",
	// @ts-expect-error
	classID: Components.ID("{850258f2-ae8b-421a-8a9c-bd99fdcc8097}"),
	classDescription: "DKIM Verifier Account Manager Extension",
	contractID: "@mozilla.org/accountmanager/extension;1?name=dkim_verifier-prefs",
	_xpcom_categories: [{
		category: "mailnews-accountmanager-extensions",
		entry: "DKIM Verifier Account Manager Extension",
		service: false
	}],

	QueryInterface: XPCOMUtils.generateQI([
		Components.interfaces.nsIMsgAccountManagerExtension
	]),
	showPanel: function(server) 
	{
		// this panel is only shown for imap and pop3 accounts
		if (server.type === "imap" || server.type === "pop3") {
			return true;
		}
		return false;
	},
};

var components = [DkimVerifierAccountManagerExtension];
const NSGetFactory = XPCOMUtils.generateNSGetFactory(components);
