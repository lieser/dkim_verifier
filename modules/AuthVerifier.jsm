/*
 * AuthVerifier.jsm
 * 
 * Authentication Verifier.
 *
 * Version: 1.3.2 (29 January 2017)
 * 
 * Copyright (c) 2014-2017 Philippe Lieser
 * 
 * This software is licensed under the terms of the MIT License.
 * 
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// options for JSHint
/* jshint strict:true, moz:true, smarttabs:true, unused:true */
/* global Components, Services, Task, MailServices, fixIterator */
/* global Logging, ARHParser */
/* global dkimStrings, domainIsInDomain, exceptionToStr, getDomainFromAddr, tryGetFormattedString, DKIM_InternalError */
/* exported EXPORTED_SYMBOLS, AuthVerifier */

"use strict";

const module_version = "1.3.2";

var EXPORTED_SYMBOLS = [
	"AuthVerifier"
];

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cu = Components.utils;

Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/Task.jsm");
Cu.import("resource:///modules/mailServices.js");
Cu.import("resource:///modules/iteratorUtils.jsm");

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
	 * @typedef {Object} AuthResult|AuthResultV2
	 * @property {String} version
	 *           result version ("2.1")
	 * @property {AuthResultDKIM[]} dkim
	 * @property {ARHResinfo[]} [spf]
	 * @property {ARHResinfo[]} [dmarc]
	 * @property {Object} [arh]
	 *           added in version 2.1
	 * @property {AuthResultDKIM[]} [arh.dkim]
	 *           added in version 2.1
	 */

	/**
	 * @typedef {Object} SavedAuthResult|SavedAuthResultV3
	 * @property {String} version
	 *           result version ("3.0")
	 * @property {dkimSigResultV2[]} dkim
	 * @property {ARHResinfo[]} [spf]
	 * @property {ARHResinfo[]} [dmarc]
	 * @property {Object} [arh]
	 * @property {dkimSigResultV2[]} [arh.dkim]
	 */

	/**
	 * @typedef {Object} AuthResultDKIM|AuthResultDKIMV2
	 * @extends dkimSigResultV2
	 * @property {Number} res_num
	 *           10: SUCCESS
	 *           20: TEMPFAIL
	 *           30: PERMFAIL
	 *           35: PERMFAIL treat as no sig
	 *           40: no sig
	 * @property {String} result_str
	 *           localized result string
	 * @property {String[]} [warnings_str]
	 *           localized warnings
	 * @property {String} [favicon]
	 *           url to the favicon of the sdid
	 */

	/**
	 * Verifies the authentication of the msg.
	 *
	 * @param {nsIMsgDBHdr} msgHdr
	 * @param {String} [msgURI=""] Required if msg is external.
	 * @return {Promise<AuthResult>}
	 */
	verify: function _authVerifier_verify(msgHdr, msgURI) {
		var promise = Task.spawn(function () {
			// check for saved AuthResult
			let savedAuthResult = loadAuthResult(msgHdr);
			if (savedAuthResult) {
				throw new Task.Result(
					yield SavedAuthResult_to_AuthResult(savedAuthResult));
			}

			// get msgURI if not specified
			if (!msgURI) {
				msgURI = msgHdr.folder.getUriForMsg(msgHdr);
			}

			// create msg object
			let msg = yield DKIM.Verifier.createMsg(msgURI);

			// ignore must be signed for outgoing messages
			if (msg.DKIMSignPolicy.shouldBeSigned && isOutgoing(msgHdr)) {
				log.debug("ignored must be signed for outgoing message");
				msg.DKIMSignPolicy.shouldBeSigned = false;
			}

			// read Authentication-Results header
			let arhResult = getARHResult(msgHdr, msg);

			if (arhResult) {
				if (prefs.getBoolPref("arh.replaceAddonResult")) {
					savedAuthResult = arhResult;
				} else {
					savedAuthResult = {
						version: "3.0",
						spf: arhResult.spf,
						dmarc: arhResult.dmarc,
						arh: {},
					};
					savedAuthResult.arh.dkim = arhResult.dkim;
				}
			} else {
				savedAuthResult = {
					version: "3.0",
				};
			}

			if (!savedAuthResult.dkim || savedAuthResult.dkim.length === 0) {
				// DKIM Verification enabled?
				let dkimEnable = false;
				if (!msgHdr.folder) {
					// message is external
					dkimEnable = prefs.getBoolPref("dkim.enable");
				} else if (msgHdr.folder.server.getIntValue("dkim_verifier.dkim.enable") === 0) {
					// account uses global default
					dkimEnable = prefs.getBoolPref("dkim.enable");
				} else if (msgHdr.folder.server.getIntValue("dkim_verifier.dkim.enable") === 1) {
					// dkim enabled for account
					dkimEnable = true;
				}
				if (dkimEnable) {
					// verify DKIM signatures
					let dkimResultV2 = yield DKIM.Verifier.verify2(msg);
					savedAuthResult.dkim = dkimResultV2.signatures;
				} else {
					savedAuthResult.dkim = [{version: "2.0", result: "none"}];
				}
			}

			// save AuthResult
			saveAuthResult(msgHdr, savedAuthResult);

			let authResult = yield SavedAuthResult_to_AuthResult(savedAuthResult)
			log.debug("authResult: " + authResult.toSource());
			throw new Task.Result(authResult);
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
			saveAuthResult(msgHdr, "");
		});
		promise.then(null, function onReject(exception) {
			log.warn(exceptionToStr(exception));
		});
		return promise;
	},
};

/**
 * Get the Authentication-Results header as an SavedAuthResult.
 * 
 * @param {Object} msg
 * @return {SavedAuthResult|Null}
 */
function getARHResult(msgHdr, msg) {
	function testAllowedAuthserv(e) {
		if (this.authserv_id === e) {
			return true;
		}
		if (e.charAt(0) === "@") {
			return domainIsInDomain(this.authserv_id, e.substr(1));
		}
		return false;
	}

	if (!msg.headerFields.has("authentication-results") ||
	    ( ( !msgHdr.folder ||
	        msgHdr.folder.server.getIntValue("dkim_verifier.arh.read") === 0) &&
	      !prefs.getBoolPref("arh.read")) ||
	    ( msgHdr.folder &&
		  msgHdr.folder.server.getIntValue("dkim_verifier.arh.read") === 2)) {
		return null;
	}

	// get DKIM, SPF and DMARC res
	let arhDKIM = [];
	let arhSPF = [];
	let arhDMARC = [];
	for (let i = 0; i < msg.headerFields.get("authentication-results").length; i++) {
		let arh;
		try {
			arh = ARHParser.parse(msg.headerFields.get("authentication-results")[i]);
		} catch (exception) {
			log.error(exceptionToStr(exception));
			continue;
		}

		// only use header if the authserv_id is in the allowed servers
		let allowedAuthserv;
		if (msgHdr.folder) {
			allowedAuthserv = msgHdr.folder.server.
				getCharValue("dkim_verifier.arh.allowedAuthserv").split(" ").
				filter(function (e) {return e;});
		} else {
			// no option exist for external messages, allow all
			allowedAuthserv = [];
		}
		if (allowedAuthserv.length > 0 &&
		    !allowedAuthserv.some(testAllowedAuthserv, arh)) {
			continue;
		}

		arhDKIM = arhDKIM.concat(arh.resinfo.filter(function (element) {
			return element.method === "dkim";
		}));
		arhSPF = arhSPF.concat(arh.resinfo.filter(function (element) {
			return element.method === "spf";
		}));
		arhDMARC = arhDMARC.concat(arh.resinfo.filter(function (element) {
			return element.method === "dmarc";
		}));
	}

	// convert DKIM results
	let dkimSigResults = arhDKIM.map(arhDKIM_to_dkimSigResultV2);

	// if ARH result is replacing the add-ons,
	// check SDID and AUID of DKIM results
	if (prefs.getBoolPref("arh.replaceAddonResult")) {
		for (let i = 0; i < dkimSigResults.length; i++) {
			if (dkimSigResults[i].result === "SUCCESS") {
				try {
					DKIM.Policy.checkSDID(
						msg.DKIMSignPolicy.sdid,
						msg.from,
						dkimSigResults[i].sdid,
						dkimSigResults[i].auid,
						dkimSigResults[i].warnings
					);
				} catch(exception) {
					dkimSigResults[i] = DKIM.Verifier.handleExeption(
						exception,
						msg,
						{d: dkimSigResults[i].sdid, i: dkimSigResults[i].auid}
					);
				}
			}
		}
	}

	// sort signatures
	DKIM.Verifier.sortSignatures(msg, dkimSigResults);

	let savedAuthResult = {
		version: "3.0",
		dkim: dkimSigResults,
		spf: arhSPF,
		dmarc: arhDMARC,
	};
	return savedAuthResult;
}

/**
 * Save authentication result
 * 
 * @param {nsIMsgDBHdr} msgHdr
 * @param {SavedAuthResult} savedAuthResult
 */
function saveAuthResult(msgHdr, savedAuthResult) {
	if (prefs.getBoolPref("saveResult")) {
		// don't save result if message is external
		if (!msgHdr.folder) {
			log.debug("result not saved because message is external");
			return;
		}

		if (savedAuthResult === "") {
			// reset result
			log.debug("reset AuthResult result");
			msgHdr.setStringProperty("dkim_verifier@pl-result", "");
		} else if (savedAuthResult.dkim[0].result === "TEMPFAIL") {
			// don't save result if DKIM result is a TEMPFAIL
			log.debug("result not saved because DKIM result is a TEMPFAIL");
		} else {
			log.debug("save AuthResult result");
			msgHdr.setStringProperty("dkim_verifier@pl-result",
				JSON.stringify(savedAuthResult));
		}
	}
}

/**
 * Get saved authentication result
 * 
 * @param {nsIMsgDBHdr} msgHdr
 * @return {SavedAuthResult|Null} savedAuthResult
 */
function loadAuthResult(msgHdr) {
	if (prefs.getBoolPref("saveResult")) {
		// don't read result if message is external
		if (!msgHdr.folder) {
			return null;
		}

		let savedAuthResult = msgHdr.getStringProperty("dkim_verifier@pl-result");

		if (savedAuthResult !== "") {
			log.debug("AuthResult result found: " + savedAuthResult);

			savedAuthResult = JSON.parse(savedAuthResult);

			if (savedAuthResult.version.match(/^[0-9]+/)[0] === "1") {
				// old dkimResultV1 (AuthResult version 1)
				let res = {
					version: "3.0",
					dkim: [dkimResultV1_to_dkimSigResultV2(savedAuthResult)],
				};
				return res;
			}
			if (savedAuthResult.version.match(/^[0-9]+/)[0] === "2") {
				// AuthResult version 2
				savedAuthResult.version = "3.0";
				savedAuthResult.dkim = savedAuthResult.dkim.map(
					AuthResultDKIMV2_to_dkimSigResultV2);
				if (savedAuthResult.arh && savedAuthResult.arh.dkim) {
					savedAuthResult.arh.dkim = savedAuthResult.arh.dkim.map(
						AuthResultDKIMV2_to_dkimSigResultV2);
				}
				return savedAuthResult;
			}
			if (savedAuthResult.version.match(/^[0-9]+/)[0] === "3") {
				// SavedAuthResult version 3
				return savedAuthResult;
			}

			throw new DKIM_InternalError("AuthResult result has wrong Version (" +
				savedAuthResult.version + ")");
		}
	}

	return null;
}

/**
 * Convert DKIM ARHresinfo to dkimResult
 * 
 * @param {ARHresinfo} arhDKIM
 * @return {dkimSigResultV2}
 */
function arhDKIM_to_dkimSigResultV2(arhDKIM) {
	let dkimSigResult = {};
	dkimSigResult.version = "2.0";
	switch (arhDKIM.result) {
		case "none":
			dkimSigResult.result = "none";
			break;
		case "pass":
			dkimSigResult.result = "SUCCESS";
			dkimSigResult.warnings = [];
			let sdid = arhDKIM.propertys.header.d;
			let auid = arhDKIM.propertys.header.i;
			if (sdid || auid) {
				if (!sdid) {
					sdid = getDomainFromAddr(auid);
				} else if (!auid) {
					auid = "@" + sdid;
				}
				dkimSigResult.sdid = sdid;
				dkimSigResult.auid = auid;
			}
			break;
		case "fail":
		case "policy":
		case "neutral":
		case "permerror":
			dkimSigResult.result = "PERMFAIL";
			if (arhDKIM.reason) {
				dkimSigResult.errorType = arhDKIM.reason;
			} else {
				dkimSigResult.errorType = "";
			}
			break;
		case "temperror":
			dkimSigResult.result = "TEMPFAIL";
			if (arhDKIM.reason) {
				dkimSigResult.errorType = arhDKIM.reason;
			} else {
				dkimSigResult.errorType = "";
			}
			break;
		default:
			throw new DKIM_InternalError("invalid dkim result in arh: " +
				arhDKIM.result);
	}
	return dkimSigResult;
}

/**
 * Convert dkimResultV1 to dkimSigResultV2
 * 
 * @param {dkimResultV1} dkimResult
 * @return {dkimSigResultV2}
 */
function dkimResultV1_to_dkimSigResultV2(dkimResultV1) {
	let dkimSigResultV2 = {
		version: "2.0",
		result: dkimResultV1.result,
		sdid: dkimResultV1.SDID,
		selector: dkimResultV1.selector,
		errorType: dkimResultV1.errorType,
		hideFail: dkimResultV1.hideFail,
	};
	if (dkimResultV1.warnings) {
		dkimSigResultV2.warnings = dkimResultV1.warnings.map(
			function (w) {
				if (w === "DKIM_POLICYERROR_WRONG_SDID") {
					return {name: w, params: [dkimResultV1.shouldBeSignedBy]};
				}
				return {name: w};
			}
		);
	}
	if (dkimResultV1.errorType === "DKIM_POLICYERROR_WRONG_SDID" ||
	    dkimResultV1.errorType === "DKIM_POLICYERROR_MISSING_SIG") {
		dkimSigResultV2.errorStrParams = [dkimResultV1.shouldBeSignedBy];
	}
	return dkimSigResultV2;
}

/**
 * Convert dkimSigResultV2 to AuthResultDKIM
 * 
 * @param {dkimSigResultV2} dkimSigResult
 * @return {AuthResultDKIM}
 * @throws DKIM_InternalError
 */
function dkimSigResultV2_to_AuthResultDKIM(dkimSigResult) {
	let authResultDKIM = dkimSigResult;
	switch(dkimSigResult.result) {
		case "SUCCESS":
			authResultDKIM.res_num = 10;
			let keySecureStr = "";
			if (dkimSigResult.keySecure &&
			    prefs.getBoolPref("display.keySecure")) {
				keySecureStr = " \uD83D\uDD12";
			}
			authResultDKIM.result_str = dkimStrings.getFormattedString("SUCCESS",
				[dkimSigResult.sdid + keySecureStr]);
			authResultDKIM.warnings_str = dkimSigResult.warnings.map(function(e) {
				return tryGetFormattedString(dkimStrings, e.name, e.params) || e.name;
			});
			break;
		case "TEMPFAIL":
			authResultDKIM.res_num = 20;
			authResultDKIM.result_str =
				tryGetFormattedString(dkimStrings, dkimSigResult.errorType,
					dkimSigResult.errorStrParams) ||
				dkimSigResult.errorType ||
				dkimStrings.getString("DKIM_INTERNALERROR_NAME");
			break;
		case "PERMFAIL":
			if (dkimSigResult.hideFail) {
				authResultDKIM.res_num = 35;
			} else {
				authResultDKIM.res_num = 30;
			}
			let errorType = dkimSigResult.errorType;
			if (!prefs.getBoolPref("error.detailedReasons")) {
				switch (errorType) {
					case "DKIM_SIGERROR_ILLFORMED_TAGSPEC":
					case "DKIM_SIGERROR_DUPLICATE_TAG":
					case "DKIM_SIGERROR_MISSING_V":
					case "DKIM_SIGERROR_ILLFORMED_V":
					case "DKIM_SIGERROR_MISSING_A":
					case "DKIM_SIGERROR_ILLFORMED_A":
					case "DKIM_SIGERROR_MISSING_B":
					case "DKIM_SIGERROR_ILLFORMED_B":
					case "DKIM_SIGERROR_MISSING_BH":
					case "DKIM_SIGERROR_ILLFORMED_BH":
					case "DKIM_SIGERROR_ILLFORMED_C":
					case "DKIM_SIGERROR_MISSING_D":
					case "DKIM_SIGERROR_ILLFORMED_D":
					case "DKIM_SIGERROR_MISSING_H":
					case "DKIM_SIGERROR_ILLFORMED_H":
					case "DKIM_SIGERROR_SUBDOMAIN_I":
					case "DKIM_SIGERROR_DOMAIN_I":
					case "DKIM_SIGERROR_ILLFORMED_I":
					case "DKIM_SIGERROR_ILLFORMED_L":
					case "DKIM_SIGERROR_ILLFORMED_Q":
					case "DKIM_SIGERROR_MISSING_S":
					case "DKIM_SIGERROR_ILLFORMED_S":
					case "DKIM_SIGERROR_ILLFORMED_T":
					case "DKIM_SIGERROR_TIMESTAMPS":
					case "DKIM_SIGERROR_ILLFORMED_X":
					case "DKIM_SIGERROR_ILLFORMED_Z":
						errorType = "DKIM_SIGERROR_ILLFORMED";
						break;
					case "DKIM_SIGERROR_VERSION":
					case "DKIM_SIGERROR_UNKNOWN_A":
					case "DKIM_SIGERROR_UNKNOWN_C_H":
					case "DKIM_SIGERROR_UNKNOWN_C_B":
					case "DKIM_SIGERROR_UNKNOWN_Q":
						errorType = "DKIM_SIGERROR_UNSUPPORTED";
						break;
					case "DKIM_SIGERROR_KEY_ILLFORMED_TAGSPEC":
					case "DKIM_SIGERROR_KEY_DUPLICATE_TAG":
					case "DKIM_SIGERROR_KEY_ILLFORMED_V":
					case "DKIM_SIGERROR_KEY_ILLFORMED_H":
					case "DKIM_SIGERROR_KEY_ILLFORMED_K":
					case "DKIM_SIGERROR_KEY_ILLFORMED_N":
					case "DKIM_SIGERROR_KEY_MISSING_P":
					case "DKIM_SIGERROR_KEY_ILLFORMED_P":
					case "DKIM_SIGERROR_KEY_ILLFORMED_S":
					case "DKIM_SIGERROR_KEY_ILLFORMED_T":
						errorType = "DKIM_SIGERROR_KEY_ILLFORMED";
						break;
					case "DKIM_SIGERROR_KEY_INVALID_V":
					case "DKIM_SIGERROR_KEY_HASHNOTINCLUDED":
					case "DKIM_SIGERROR_KEY_UNKNOWN_K":
					case "DKIM_SIGERROR_KEY_HASHMISMATCH":
					case "DKIM_SIGERROR_KEY_NOTEMAILKEY":
					case "DKIM_SIGERROR_KEYDECODE":
						errorType = "DKIM_SIGERROR_KEY_INVALID";
						break;
					case "DKIM_SIGERROR_BADSIG":
					case "DKIM_SIGERROR_CORRUPT_BH":
					case "DKIM_SIGERROR_MISSING_FROM":
					case "DKIM_SIGERROR_TOOLARGE_L":
					case "DKIM_SIGERROR_NOKEY":
					case "DKIM_SIGERROR_KEY_REVOKED":
					case "DKIM_SIGERROR_KEY_TESTMODE":
						break;
				}
			}
			let errorMsg =
				tryGetFormattedString(dkimStrings, errorType,
					dkimSigResult.errorStrParams) ||
				errorType;
			if (errorMsg) {
				authResultDKIM.result_str = dkimStrings.getFormattedString("PERMFAIL",
					[errorMsg]);
			} else {
				authResultDKIM.result_str = dkimStrings.getString("PERMFAIL_NO_REASON");
			}
			break;
		case "none":
			authResultDKIM.res_num = 40;
			authResultDKIM.result_str = dkimStrings.getString("NOSIG");
			break;
		default:
			throw new DKIM_InternalError("unkown result: " + dkimSigResult.result);
	}

	return authResultDKIM;
}

/**
 * Convert SavedAuthResult to AuthResult
 * 
 * Generator function.
 * 
 * @param {SavedAuthResult} savedAuthResult
 * @return {Promise<AuthResult>} authResult
 */
function SavedAuthResult_to_AuthResult(savedAuthResult) {
	let authResult = savedAuthResult;
	authResult.version = "2.1";
	authResult.dkim = authResult.dkim.map(dkimSigResultV2_to_AuthResultDKIM);
	if (authResult.arh && authResult.arh.dkim) {
		authResult.arh.dkim = authResult.arh.dkim.map(
			dkimSigResultV2_to_AuthResultDKIM);
	}
	authResult = yield addFavicons(authResult);
	throw new Task.Result(authResult);
}

/**
 * Convert AuthResultV2 to dkimSigResultV2
 * 
 * @param {AuthResultDKIMV2} authResultDKIM
 * @return {Promise<dkimSigResultV2>} dkimSigResultV2
 */
function AuthResultDKIMV2_to_dkimSigResultV2(authResultDKIM) {
	let dkimSigResult = authResultDKIM;
	dkimSigResult.res_num = undefined;
	dkimSigResult.result_str = undefined;
	dkimSigResult.warnings_str = undefined;
	dkimSigResult.favicon = undefined;
	return dkimSigResult;
}

/**
 * Add favicons to the DKIM results.
 * 
 * Generator function.
 * 
 * @param {AuthResult} authResult
 * @return {Promise<AuthResult>} authResult
 */
function addFavicons(authResult) {
	if (!prefs.getBoolPref("display.favicon.show")) {
		throw new Task.Result(authResult);
	}
	for (let i = 0; i < authResult.dkim.length; i++) {
		authResult.dkim[i].favicon =
			yield DKIM.Policy.getFavicon(authResult.dkim[i].sdid);
	}
	throw new Task.Result(authResult);
}

/**
 * Checks if a message is outgoing
 * 
 * @param {nsIMsgDBHdr} msgHdr
 * @return Boolean
 */
function isOutgoing(msgHdr) {
	if (!msgHdr.folder) {
		// msg is external
		return false;
	}
	if (msgHdr.folder.getFlag(Ci.nsMsgFolderFlags.SentMail)) {
		// msg is in sent folder
		return true;
	}

	// return true if one of the servers identities contain the from address
	let author = msgHdr.mime2DecodedAuthor;
	let identities;
	if (MailServices.accounts.getIdentitiesForServer) {
		identities = MailServices.accounts.
			getIdentitiesForServer(msgHdr.folder.server);
	} else {
		// for older versions of Thunderbird
		identities = MailServices.accounts.
			GetIdentitiesForServer(msgHdr.folder.server);
	}
	for (let identity in fixIterator(identities, Ci.nsIMsgIdentity)) {
		if (author.includes) {
			if (author.includes(identity.email)) {
				return true;
			}
		} else if (author.search(identity.email) !== -1){
			// for older versions of Thunderbird
			return true;
		}
	}

	// default to false
	return false;
}
