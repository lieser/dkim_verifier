/*
 * AuthVerifier.jsm
 * 
 * Authentication Verifier.
 *
 * Version: 1.0.0pre1 (06 September 2014)
 * 
 * Copyright (c) 2014 Philippe Lieser
 * 
 * This software is licensed under the terms of the MIT License.
 * 
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// options for JSHint
/* jshint strict:true, moz:true, smarttabs:true, unused:true */
/* global Components, Services, Task */
/* global Logging, MsgReader, ARHParser */
/* global exceptionToStr, DKIM_InternalError */
/* exported EXPORTED_SYMBOLS, AuthVerifier */

"use strict";

const module_version = "1.0.0pre1";

var EXPORTED_SYMBOLS = [
	"AuthVerifier"
];

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cu = Components.utils;

Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/Task.jsm");

Cu.import("resource://dkim_verifier/logging.jsm");
Cu.import("resource://dkim_verifier/helper.jsm");
Cu.import("resource://dkim_verifier/MsgReader.jsm");
Cu.import("resource://dkim_verifier/ARHParser.jsm");
let DKIM = {};
Cu.import("resource://dkim_verifier/dkimPolicy.jsm", DKIM);
Cu.import("resource://dkim_verifier/dkimVerifier.jsm", DKIM);

const PREF_BRANCH = "extensions.dkim_verifier.";

let log = Logging.getLogger("AuthVerifier");
let prefs = Services.prefs.getBranch(PREF_BRANCH);


var AuthVerifier = {
	get version() { return module_version; },

	/**
	 * Verifies the authentication of the msg.
	 *
	 * @param {nsIMsgDBHdr} msgHdr
	 * @param {String} [msgURI=""] Required if msg is external.
	 * @return {Promise<AuthResult>}
	 */
	verify: function _authVerifier_verify(msgHdr, msgURI) {
		var promise = Task.spawn(function () {
			// check for saved DKIM result
			let dkimResult = loadDKIMResult(msgHdr);
			if (dkimResult !== null) {
				throw new Task.Result(dkimResultToAuthResult(dkimResult));
			}

			// get msgURI if not specified
			if (!msgURI) {
				msgURI = msgHdr.folder.getUriForMsg(msgHdr);
			}

			// read msg
			let msg = yield MsgReader.read(msgURI);
			msg.msgURI = msgURI;

			// parse the header
			msg.headerFields = MsgReader.parseHeader(msg.headerPlain);

			let msgHeaderParser = Cc["@mozilla.org/messenger/headerparser;1"].
				createInstance(Ci.nsIMsgHeaderParser);

			// get from address
			let author = msg.headerFields.from[msg.headerFields.from.length-1];
			author = author.replace(/^From[ \t]*:/i,"");
			msg.from = msgHeaderParser.extractHeaderAddressMailboxes(author);

			// get list-id
			let listId = null;
			if (msg.headerFields["list-id"]) {
				listId = msg.headerFields["list-id"][0];
				listId = msgHeaderParser.extractHeaderAddressMailboxes(listId);
			}

			// check if msg should be signed by DKIM
			msg.DKIM = {};
			msg.DKIM.signPolicy = yield DKIM.Policy.shouldBeSigned(msg.from, listId);

			// read Authentication-Results header
			if (prefs.getBoolPref("arh.read") &&
			    msg.headerFields["authentication-results"]) {
				for (let i = 0; i < msg.headerFields["authentication-results"].length; i++) {
					let arh = ARHParser.parse(msg.headerFields["authentication-results"][i]);
					let arhDKIM = arh.resinfo.find(function (element) {
						return element.method === "dkim";
					});
					let arhSPF = arh.resinfo.find(function (element) {
						return element.method === "spf";
					});
					let arhDMARC = arh.resinfo.find(function (element) {
						return element.method === "dmarc";
					});
					if (arhDKIM) {
						throw new Task.Result(dkimResultToAuthResult(
							arhDKIMToDkimResult(arhDKIM)));
					}
				}
			}

			// verify DKIM signature
			let dkimResultV2 = yield DKIM.Verifier.verify2(msg);

			// check if DKIMSignatureHeader exist
			if (dkimResultV2.signatures.length === 0) {
				if (!msg.DKIM.signPolicy.shouldBeSigned) {
					dkimResult = {
						version : "1.0",
						result : "none"
					};
					return;
				} else {
					dkimResult = {
						version : "1.1",
						result : "PERMFAIL",
						errorType : "DKIM_POLICYERROR_MISSING_SIG",
						shouldBeSignedBy : msg.DKIM.signPolicy.sdid,
						hideFail : msg.DKIM.signPolicy.hideFail,
					};

					log.warn("verify: DKIM_POLICYERROR_MISSING_SIG");
				}
			} else {
				dkimResult = {
					version : "1.1",
					result : dkimResultV2.signatures[0].result,
					SDID : dkimResultV2.signatures[0].SDID,
					selector : dkimResultV2.signatures[0].selector,
					warnings : dkimResultV2.signatures[0].warnings,
					errorType : dkimResultV2.signatures[0].errorType,
					shouldBeSignedBy : msg.DKIM.signPolicy.sdid,
					hideFail : msg.DKIM.signPolicy.hideFail,
				};
			}

			// save DKIM result
			saveDKIMResult(msgHdr, dkimResult);

			throw new Task.Result(dkimResultToAuthResult(dkimResult));
		});
		promise.then(null, function onReject(exception) {
			log.warn(exceptionToStr(exception));
		});
		return promise;
	},

	/**
	 * Resets the stored authentication result of the msg.
	 *
	 * @param {nsIMsgDBHdr} msgHdr
	 * @return {Promise<Undefined>}
	 */
	resetResult: function _authVerifier_resetResult(msgHdr) {
		var promise = Task.spawn(function () {
			saveDKIMResult(msgHdr, "");
		});
		promise.then(null, function onReject(exception) {
			log.warn(exceptionToStr(exception));
		});
		return promise;
	},
};

/**
 * Save DKIM result
 * 
 * @param {nsIMsgDBHdr} msgHdr
 * @param {dkimResult} dkimResult
 */
function saveDKIMResult(msgHdr, dkimResult) {
	if (prefs.getBoolPref("saveResult")) {
		// don't save result if message is external
		if (!msgHdr.folder) {
			return;
		}
		// don't save DKIM result if it's a TEMPFAIL
		if (dkimResult.result !== "TEMPFAIL") {
			return;
		}

		if (dkimResult === "") {
			log.debug("reset DKIM result");
			msgHdr.setStringProperty("dkim_verifier@pl-result", "");
		} else {
			log.debug("save DKIM result");
			msgHdr.setStringProperty("dkim_verifier@pl-result", JSON.stringify(dkimResult));
		}
	}
}

/**
 * Get saved DKIM result
 * 
 * @param {nsIMsgDBHdr} msgHdr
 * @return {dkimResult|Null} dkimResult
 */
function loadDKIMResult(msgHdr) {
	if (prefs.getBoolPref("saveResult")) {
		// don't read result if message is external
		if (!msgHdr.folder) {
			return;
		}

		let dkimResult = msgHdr.getStringProperty("dkim_verifier@pl-result");

		if (dkimResult !== "") {
			log.debug("DKIM result found: "+dkimResult);

			dkimResult = JSON.parse(dkimResult);

			if (dkimResult.version.match(/^[0-9]+/)[0] !== "1") {
				throw new DKIM_InternalError("DKIM result has wrong Version ("+dkimResult.version+")");
			}

			return dkimResult;
		}
	}

	return null;
}

/**
 * Convert DKIM ARHresinfo to dkimResult
 * 
 * @param {ARHresinfo} arhDKIM
 * @return {dkimResult}
 */
function arhDKIMToDkimResult(arhDKIM) {
	let dkimResult = {};
	dkimResult.version = "1.0";
	switch (arhDKIM.result) {
		case "none":
			dkimResult.result = "none";
			break;
		case "pass":
			dkimResult.result = "SUCCESS";
			let SDID = arhDKIM.propertys.find(function (property) {
				return (property.type === "header" &&
					(property.name === "d" || property.name === "i"));
			});
			if (SDID) {
				dkimResult.SDID = SDID.value;
			}
			dkimResult.warnings = [];
			break;
		case "fail":
		case "policy":
		case "neutral":
		case "permerror":
			dkimResult.result = "PERMFAIL";
			if (arhDKIM.reason) {
				dkimResult.errorType = arhDKIM.reason;
			} else {
				dkimResult.errorType = "";
			}
			break;
		case "temperror":
			dkimResult.result = "TEMPFAIL";
			if (arhDKIM.reason) {
				dkimResult.errorType = arhDKIM.reason;
			} else {
				dkimResult.errorType = "";
			}
			break;
		default:
			throw new DKIM_InternalError("invalid dkim result in arh");
	}
	return dkimResult;
}

/**
 * Convert dkimResult to AuthResult
 * 
 * @param {dkimResult} dkimResult
 * @return {AuthResult}
 */
function dkimResultToAuthResult(dkimResult) {
	return dkimResult;
}
