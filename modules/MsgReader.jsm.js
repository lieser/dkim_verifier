/*
 * MsgReader.jsm.js
 * 
 * Reads and parses a message.
 *
 * Version: 2.1.0 (02 January 2018)
 * 
 * Copyright (c) 2014-2018 Philippe Lieser
 * 
 * This software is licensed under the terms of the MIT License.
 * 
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// options for ESLint
/* global Components */
/* global Logging */
/* global Deferred, DKIM_Error */
/* exported EXPORTED_SYMBOLS, MsgReader */

"use strict";

// @ts-ignore
const module_version = "2.1.0";

var EXPORTED_SYMBOLS = [
	"MsgReader"
];

// @ts-ignore
const Cc = Components.classes;
// @ts-ignore
const Ci = Components.interfaces;
// @ts-ignore
const Cu = Components.utils;

Cu.import("resource://dkim_verifier/logging.jsm.js");
Cu.import("resource://dkim_verifier/helper.jsm.js");

// @ts-ignore
let log = Logging.getLogger("MsgReader");


var MsgReader = {
	get version() { return module_version; },

	/**
	 * Reads the message and parse it into header and body
	 *
	 * @param {String} msgURI
	 * @return {Promise<{headerPlain: string, bodyPlain: string}>}
	 * @throws {DKIM_Error}
	 */
	read: function _MsgReader_read(msgURI) {
		/** @type {IDeferred<{headerPlain: string, bodyPlain: string}>} */
		let res_defer = new Deferred();
		let raw = "";
		let res = {
			headerPlain: "",
			bodyPlain: "",
		};

		let StreamListener =
		{
			QueryInterface : function(iid) {
						if (iid.equals(Components.interfaces.nsIStreamListener) ||
							iid.equals(Components.interfaces.nsISupports)) {
							return this;
						}

						throw Components.results.NS_NOINTERFACE;
			},

			onDataAvailable: function ( request , context , inputStream , offset , count ) {
				try {
					var scriptableInputStream = Components.classes["@mozilla.org/scriptableinputstream;1"].
						createInstance(Components.interfaces.nsIScriptableInputStream);
					scriptableInputStream.init(inputStream);
						raw += scriptableInputStream.read(count);
				} catch (e) {
					log.warn(e);
					res_defer.reject(e);
				}
			},

			onStartRequest: function (/* request , context */) {}, // eslint-disable-line no-empty-function

			onStopRequest: function (/* aRequest , aContext , aStatusCode */) {
				try {
					// convert all EOLs to CRLF
					const str = raw.replace(/(\r\n|\n|\r)/g, "\r\n");
					const newlineLength = 2;
					
					const posEndHeader = str.indexOf("\r\n\r\n");
					
					// check if header end was detected and split header and body				
					if (posEndHeader === -1) {
						// in this case, the message has no body, but headers must end with a newline
						if (!str.endsWith("\r\n")) {
							throw new DKIM_Error("Message is not in correct e-mail format");
						}
						res.headerPlain = str;
						res.bodyPlain = "";
					} else {
						res.headerPlain = str.substr(0, posEndHeader + newlineLength);
						res.bodyPlain = str.substr(posEndHeader + 2 * newlineLength);
					}

					res_defer.resolve(res);
				} catch (e) {
					log.warn(e);
					res_defer.reject(e);
				}
			}
		};

		let messenger = Cc["@mozilla.org/messenger;1"].
			createInstance(Ci.nsIMessenger);
		let messageService = messenger.messageServiceFromURI(msgURI);
		messageService.CopyMessage(
			msgURI,
			StreamListener,
			false,
			null /* aUrlListener */,
			null /* aMsgWindow */,
			{}
		);

		return res_defer.promise;
	},

	/**
	 * Parses the header of a message.
	 *
	 * @param {String} headerPlain
	 * @return {Map}
	 *           key: {String} <header name>
	 *           value: {Array[String]}
	 * @throws {DKIM_Error}
	 */
	parseHeader: function _MsgReader_parseHeader(headerPlain) {
		var headerFields = new Map();

		// split header fields
		var headerArray = headerPlain.split(/\r\n(?=\S|$)/);
		// The last newline will result in an empty entry, remove it
		headerArray.pop();
		var hName;
		for(var i = 0; i < headerArray.length; i++) {
			// store fields under header field name (in lower case) in an array
			hName = headerArray[i].match(/[!-9;-~]+(?=:)/);
			if (hName !== null && hName[0]) {
				hName = hName[0].toLowerCase();
				if (!headerFields.has(hName)) {
					headerFields.set(hName, []);
				}
				headerFields.get(hName).push(headerArray[i]+"\r\n");
			} else {
				throw new DKIM_Error("Could not split header into name and value");
			}
		}

		return headerFields;
	},
};
