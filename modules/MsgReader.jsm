/*
 * MsgReader.jsm
 * 
 * Reads and parses a message.
 *
 * Version: 2.1.1 (29 August 2019)
 * 
 * Copyright (c) 2014-2019 Philippe Lieser
 * 
 * This software is licensed under the terms of the MIT License.
 * 
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// options for ESLint
/* global Components */
/* global Logging */
/* global Deferred, DKIM_InternalError */
/* exported EXPORTED_SYMBOLS, MsgReader */

"use strict";

// @ts-ignore
const module_version = "2.1.1";

var EXPORTED_SYMBOLS = [
	"MsgReader"
];

// @ts-ignore
const Cc = Components.classes;
// @ts-ignore
const Ci = Components.interfaces;
// @ts-ignore
const Cu = Components.utils;

Cu.import("resource://dkim_verifier/logging.jsm");
Cu.import("resource://dkim_verifier/helper.jsm");

// @ts-ignore
let log = Logging.getLogger("MsgReader");


var MsgReader = {
	get version() { return module_version; },

	/**
	 * Reads the message and parse it into header and body
	 *
	 * @param {String} msgURI
	 * @return {Promise<{headerPlain: string, bodyPlain: string}>}
	 * @throws DKIM_InternalError
	 */
	read: function _MsgReader_read(msgURI) {
		/** @type {IDeferred<{headerPlain: string, bodyPlain: string}>} */
		let res_defer = new Deferred();
		let res = {
			headerPlain: "",
			bodyPlain: "",
		};

		let StreamListener =
		{
			headerFinished: false,

			QueryInterface : function(iid) {
						if (iid.equals(Components.interfaces.nsIStreamListener) ||
							iid.equals(Components.interfaces.nsISupports)) {
							return this;
						}

						throw Components.results.NS_NOINTERFACE;
			},

			onDataAvailable: function ( request, inputStream, offset, count ) {
				let str;
				let NewlineLength = 2;

				try {

					var scriptableInputStream = Components.classes["@mozilla.org/scriptableinputstream;1"].
						createInstance(Components.interfaces.nsIScriptableInputStream);
					scriptableInputStream.init(inputStream);

					if (!this.headerFinished) {
						// read header
						str = scriptableInputStream.read(count);
						let posEndHeader = str.indexOf("\r\n\r\n");

						// check for LF line ending
						if (posEndHeader === -1) {
							posEndHeader = str.indexOf("\n\n");
							if (posEndHeader !== -1) {
								NewlineLength = 1;
								log.debug("LF line ending detected");
							}
						}
						// check for CR line ending
						if (posEndHeader === -1) {
							posEndHeader = str.indexOf("\r\r");
							if (posEndHeader !== -1) {
								NewlineLength = 1;
								log.debug("CR line ending detected");
							}
						}

						// check for end of header
						if (posEndHeader === -1) {
							// end of header not yet reached
							res.headerPlain += str;
						} else {
							// end of header reached
							res.headerPlain += str.substr(0, posEndHeader + NewlineLength);
							res.bodyPlain = str.substr(posEndHeader + 2*NewlineLength);
							this.headerFinished = true;
						}
					} else {
						// read body
						res.bodyPlain += scriptableInputStream.read(count);
					}
				} catch (e) {
					log.warn(e);
					res_defer.reject(e);
				}
			},

			onStartRequest: function (/* request , context */) {}, // eslint-disable-line no-empty-function

			onStopRequest: function (/* aRequest , aContext , aStatusCode */) {
				try {
					// if end of msg is reached before end of header,
					// it is no in correct e-mail format
					if (!this.headerFinished) {
						throw new DKIM_InternalError("Message is not in correct e-mail format",
							"DKIM_INTERNALERROR_INCORRECT_EMAIL_FORMAT");
					}

					// convert all EOLs to CRLF
					res.headerPlain = res.headerPlain.replace(/(\r\n|\n|\r)/g, "\r\n");
					res.bodyPlain = res.bodyPlain.replace(/(\r\n|\n|\r)/g, "\r\n");

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
	 */
	parseHeader: function _MsgReader_parseHeader(headerPlain) {
		var headerFields = new Map();

		// split header fields
		var headerArray = headerPlain.split(/\r\n(?=\S|$)/);
		var hName;
		for(var i = 0; i < headerArray.length; i++) {
			// store fields under header field name (in lower case) in an array
			hName = headerArray[i].match(/[!-9;-~]+(?=:)/);
			if (hName !== null) {
				hName = hName[0].toLowerCase();
				if (!headerFields.has(hName)) {
					headerFields.set(hName, []);
				}
				headerFields.get(hName).push(headerArray[i]+"\r\n");
			}
		}

		return headerFields;
	},
};
