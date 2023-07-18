/*
 * AuthVerifier.jsm
 * 
 * Authentication Verifier.
 *
 * Version: 1.4.0 (28 January 2018)
 * 
 * Copyright (c) 2014-2018 Philippe Lieser
 * 
 * This software is licensed under the terms of the MIT License.
 * 
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// options for ESLint
/* global Components, Services, MailServices, fixIterator */
/* global Logging, ARHParser */
/* global PREF, dkimStrings, domainIsInDomain, getDomainFromAddr, tryGetFormattedString, DKIM_InternalError */
/* exported EXPORTED_SYMBOLS, AuthVerifier */

"use strict";

// @ts-ignore
const module_version = "1.4.0";

var EXPORTED_SYMBOLS = [
	"AuthVerifier"
];

// @ts-ignore
const Cc = Components.classes;
// @ts-ignore
const Ci = Components.interfaces;
// @ts-ignore
const Cu = Components.utils;

Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource:///modules/mailServices.js");
Cu.import("resource:///modules/iteratorUtils.jsm");

Cu.import("resource://dkim_verifier/logging.jsm");
Cu.import("resource://dkim_verifier/helper.jsm");
Cu.import("resource://dkim_verifier/MsgReader.jsm");
Cu.import("resource://dkim_verifier/ARHParser.jsm");
// @ts-ignore
let DKIM = {};
Cu.import("resource://dkim_verifier/dkimPolicy.jsm", DKIM);
Cu.import("resource://dkim_verifier/dkimVerifier.jsm", DKIM);

// @ts-ignore
const PREF_BRANCH = "extensions.dkim_verifier.";

// @ts-ignore
let log = Logging.getLogger("AuthVerifier");
// @ts-ignore
let prefs = Services.prefs.getBranch(PREF_BRANCH);

/**
 * @typedef {Object} AuthResult|AuthResultV2
 * @property {String} version
 *           result version ("2.1")
 * @property {AuthResultDKIM[]} dkim
 * @property {ARHResinfo[]} [spf]
 * @property {ARHResinfo[]} [dmarc]
 * @property {{dkim?: AuthResultDKIM[]}} [arh]
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
// @ts-ignore

var AuthVerifier = {
	get version() { return module_version; },

	DKIM_RES: {
		SUCCESS: 10,
		TEMPFAIL: 20,
		PERMFAIL: 30,
		PERMFAIL_NOSIG: 35,
		NOSIG: 40,
	},

	/**
	 * Verifies the authentication of the msg.
	 *
	 * @param {nsIMsgDBHdr} msgHdr
	 * @param {String} [msgURI=""] Required if msg is external.
	 * @return {Promise<AuthResult>}
	 */
	verify: function _authVerifier_verify(msgHdr, msgURI) {
		let promise = (async () => {
			// check for saved AuthResult
			const msgHeaderParser = Cc["@mozilla.org/messenger/headerparser;1"].createInstance(Ci.nsIMsgHeaderParser);
			let savedAuthResult = loadAuthResult(msgHdr);
			let author = msgHdr.mime2DecodedAuthor;
			let fromAddress = msgHeaderParser.extractHeaderAddressMailboxes(author);
			fromAddress = fromAddress.toLowerCase();
			if (savedAuthResult) {
				return SavedAuthResult_to_AuthResult(savedAuthResult, fromAddress);
			}

			// get msgURI if not specified
			if (!msgURI) {
				msgURI = msgHdr.folder.getUriForMsg(msgHdr);
			}

			// create msg object
			let msg = await DKIM.Verifier.createMsg(msgURI);

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
				} else if (msgHdr.folder.server.getIntValue("dkim_verifier.dkim.enable") === PREF.ENABLE.DEFAULT) {
					// account uses global default
					dkimEnable = prefs.getBoolPref("dkim.enable");
				} else if (msgHdr.folder.server.getIntValue("dkim_verifier.dkim.enable") === PREF.ENABLE.TRUE) {
					// dkim enabled for account
					dkimEnable = true;
				}
				if (dkimEnable) {
					// verify DKIM signatures
					let dkimResultV2 = await DKIM.Verifier.verify2(msg);
					savedAuthResult.dkim = dkimResultV2.signatures;
				} else {
					savedAuthResult.dkim = [{version: "2.0", result: "none"}];
				}
			}

			// save AuthResult
			saveAuthResult(msgHdr, savedAuthResult);

			let authResult = await SavedAuthResult_to_AuthResult(savedAuthResult, fromAddress);
			// @ts-ignore
			log.debug("authResult: " + authResult.toSource());
			return authResult;
		})();
		promise.then(null, function onReject(exception) {
			log.warn(exception);
		});
		return promise;
	},

	/**
	 * Resets the stored authentication result of the msg.
	 *
	 * @param {nsIMsgDBHdr} msgHdr
	 * @return {Promise<void>}
	 */
	resetResult: function _authVerifier_resetResult(msgHdr) {
		var promise = (async () => {
			saveAuthResult(msgHdr, null);
		})();
		promise.then(null, function onReject(exception) {
			log.warn(exception);
		});
		return promise;
	},
};

/**
 * Get the Authentication-Results header as an SavedAuthResult.
 * 
 * @param {nsIMsgDBHdr} msgHdr
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
		( // disabled via default setting
			(
				!msgHdr.folder ||
				msgHdr.folder.server.getIntValue("dkim_verifier.arh.read") === PREF.ENABLE.DEFAULT
			) &&
			!prefs.getBoolPref("arh.read")
		) ||
		( // disabled for the folder
			msgHdr.folder &&
			msgHdr.folder.server.getIntValue("dkim_verifier.arh.read") === PREF.ENABLE.FALSE
		))
	{
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
			log.error("Ignoring error in parsing of ARH", exception);
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
	if (prefs.getBoolPref("arh.replaceAddonResult")) {
		// check SDID and AUID of DKIM results
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
					dkimSigResults[i] = DKIM.Verifier.handleException(
						exception,
						msg,
						{d: dkimSigResults[i].sdid, i: dkimSigResults[i].auid}
					);
				}
			}
		}
		// check for weak signature type rsa-sha1
		for (let i = 0; i < dkimSigResults.length; i++) {
			if (arhDKIM[i] && arhDKIM[i].propertys.header.a === "rsa-sha1") {
				switch (prefs["error.algorithm.sign.rsa-sha1.treatAs"]) {
					case 0: { // error
						dkimSigResults[i] = {
							version: "2.0",
							result: "PERMFAIL",
							sdid: dkimSigResults[i] ? dkimSigResults[i].sdid : "",
							auid: dkimSigResults[i] ? dkimSigResults[i].auid : "",
							selector: dkimSigResults[i] ? dkimSigResults[i].selector : null,
							errorType: "DKIM_SIGERROR_INSECURE_A",
						};
						break;
					}
					case 1: // warning
						if (dkimSigResults[i] && dkimSigResults[i].warnings) {
							dkimSigResults[i].warnings.push({ name: "DKIM_SIGERROR_INSECURE_A" });
						}
						break;
					case 2: // ignore
						break;
					default:
						throw new DKIM_InternalError("invalid error.algorithm.sign.rsa-sha1.treatAs");
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
	log.debug("ARH result:", savedAuthResult);
	return savedAuthResult;
}

/**
 * Save authentication result
 * 
 * @param {nsIMsgDBHdr} msgHdr
 * @param {SavedAuthResult|Null} savedAuthResult
 * @return {void}
 */
function saveAuthResult(msgHdr, savedAuthResult) {
	if (prefs.getBoolPref("saveResult")) {
		// don't save result if message is external
		if (!msgHdr.folder) {
			log.debug("result not saved because message is external");
			return;
		}

		if (savedAuthResult === null) {
			// reset result
			log.debug("reset AuthResult result");
			msgHdr.setStringProperty("dkim_verifier@pl-result", "");
		} else if (savedAuthResult.dkim.some(res => res.result === "TEMPFAIL")) {
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

		let savedAuthResultJSON = msgHdr.getStringProperty("dkim_verifier@pl-result");

		if (savedAuthResultJSON !== "") {
			log.debug("AuthResult result found: " + savedAuthResultJSON);

			/** @type {SavedAuthResult} */
			let savedAuthResult = JSON.parse(savedAuthResultJSON);

			let majorVersion = savedAuthResult.version.match(/^[0-9]+/)[0];
			if (majorVersion === "1") {
				// old dkimResultV1 (AuthResult version 1)
				/** @type {dkimResultV1} */
				// @ts-ignore
				let resultV1 = savedAuthResult;
				let res = {
					version: "3.0",
					dkim: [dkimResultV1_to_dkimSigResultV2(resultV1)],
				};
				return res;
			}
			if (majorVersion === "2") {
				// AuthResult version 2
				/** @type {AuthResultV2} */
				// @ts-ignore
				let resultV2 = savedAuthResult;
				savedAuthResult.version = "3.0";
				savedAuthResult.dkim = resultV2.dkim.map(
					AuthResultDKIMV2_to_dkimSigResultV2);
				if (resultV2.arh && resultV2.arh.dkim) {
					savedAuthResult.arh.dkim = resultV2.arh.dkim.map(
						AuthResultDKIMV2_to_dkimSigResultV2);
				}
				return savedAuthResult;
			}
			if (majorVersion === "3") {
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
 * @param {ARHResinfo} arhDKIM
 * @return {dkimSigResultV2}
 */
function arhDKIM_to_dkimSigResultV2(arhDKIM) {
	/** @type {dkimSigResultV2} */
	let dkimSigResult = {};
	dkimSigResult.version = "2.0";
	switch (arhDKIM.result) {
		case "none":
			dkimSigResult.result = "none";
			break;
		case "pass": {
			dkimSigResult.result = "SUCCESS";
			dkimSigResult.warnings = [];
			break;
		}
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
	
	return dkimSigResult;
}

/**
 * Convert dkimResultV1 to dkimSigResultV2
 * 
 * @param {dkimResultV1} dkimResultV1
 * @return {dkimSigResultV2}
 */
function dkimResultV1_to_dkimSigResultV2(dkimResultV1) {
	/** @type {dkimSigResultV2} */
	let sigResultV2 = {
		version: "2.0",
		result: dkimResultV1.result,
		sdid: dkimResultV1.SDID,
		selector: dkimResultV1.selector,
		errorType: dkimResultV1.errorType,
		hideFail: dkimResultV1.hideFail,
	};
	if (dkimResultV1.warnings) {
		sigResultV2.warnings = dkimResultV1.warnings.map(
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
		sigResultV2.errorStrParams = [dkimResultV1.shouldBeSignedBy];
	}
	return sigResultV2;
}

/**
 * Convert dkimSigResultV2 to AuthResultDKIM
 * 
 * @param {dkimSigResultV2} dkimSigResult
 * @return {AuthResultDKIM}
 * @throws DKIM_InternalError
 */
function dkimSigResultV2_to_AuthResultDKIM(dkimSigResult) { // eslint-disable-line complexity
	/** @type {IAuthVerifier.AuthResultDKIM} */
	let authResultDKIM = dkimSigResult;
	switch(dkimSigResult.result) {
		case "SUCCESS": {
			authResultDKIM.res_num = AuthVerifier.DKIM_RES.SUCCESS;
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
		}
		case "TEMPFAIL":
			authResultDKIM.res_num = AuthVerifier.DKIM_RES.TEMPFAIL;
			authResultDKIM.result_str =
				tryGetFormattedString(dkimStrings, dkimSigResult.errorType,
					dkimSigResult.errorStrParams) ||
				dkimSigResult.errorType ||
				dkimStrings.getString("DKIM_INTERNALERROR_NAME");
			break;
		case "PERMFAIL": {
			if (dkimSigResult.hideFail) {
				authResultDKIM.res_num = AuthVerifier.DKIM_RES.PERMFAIL_NOSIG;
			} else {
				authResultDKIM.res_num = AuthVerifier.DKIM_RES.PERMFAIL;
			}
			let errorType = dkimSigResult.errorType;
			let errorMsg;
			if (errorType) {
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
						case "DKIM_SIGERROR_KEY_MISMATCHED_K":
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
						default:
							log.warn("unknown errorType: " + errorType);
					}
				}
				errorMsg =
				tryGetFormattedString(dkimStrings, errorType,
					dkimSigResult.errorStrParams) ||
				errorType;
				authResultDKIM.error_str = errorMsg;
			}			
			if (errorMsg) {
				authResultDKIM.result_str = dkimStrings.getFormattedString("PERMFAIL",
					[errorMsg]);
			} else {
				authResultDKIM.result_str = dkimStrings.getString("PERMFAIL_NO_REASON");
			}
			break;
		}
		case "none":
			authResultDKIM.res_num = AuthVerifier.DKIM_RES.NOSIG;
			authResultDKIM.result_str = dkimStrings.getString("NOSIG");
			break;
		default:
			throw new DKIM_InternalError("unknown result: " + dkimSigResult.result);
	}

	return authResultDKIM;
}


/**
 * Convert SavedAuthResult to AuthResult
 * 
 * @param {SavedAuthResult} savedAuthResult
 * @param {String|undefined} from
 * @return {Promise<AuthResult>} authResult
 */
async function SavedAuthResult_to_AuthResult(savedAuthResult, from) { // eslint-disable-line require-await
	/** @type {AuthResult} */
	let authResult = savedAuthResult;
	authResult.version = "2.1";
	authResult.dkim = authResult.dkim.map(dkimSigResultV2_to_AuthResultDKIM);
	if (authResult.arh && authResult.arh.dkim) {
		authResult.arh.dkim = authResult.arh.dkim.map(
			dkimSigResultV2_to_AuthResultDKIM);
	}
	return addFavicons(authResult, from);
}

/**
 * Convert AuthResultV2 to dkimSigResultV2
 * 
 * @param {AuthResultDKIMV2} authResultDKIM
 * @return {dkimSigResultV2} dkimSigResultV2
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
 * @param {AuthResult} authResult
 * @param {String|undefined} from
 * @return {Promise<AuthResult>} authResult
 */
async function addFavicons(authResult, from) {
	if (!prefs.getBoolPref("display.favicon.show")) {
		return authResult;
	}
	for (let i = 0; i < authResult.dkim.length; i++) {
		if (authResult.dkim[i].sdid) {
			authResult.dkim[i].favicon =
				await DKIM.Policy.getFavicon(authResult.dkim[i].sdid, authResult.dkim[i].auid, from);
		}
	}
	return authResult;
}

/**
 * Checks if a message is outgoing
 * 
 * @param {nsIMsgDBHdr} msgHdr
 * @return {boolean}
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
	if (msgHdr.folder.getFlag(Ci.nsMsgFolderFlags.Junk)) {
		// msg is in junk folder
		return false;
	}

	// return true
	// - if one of the servers identities contains the from address
	// - if another account's inbox is redirected to this server and an originating account's identity matches
	// - if the mail is in local folders and the from address matches any identity

	const accMgr = MailServices.accounts;
	const msgHeaderParser = Cc["@mozilla.org/messenger/headerparser;1"].createInstance(Ci.nsIMsgHeaderParser);
	const lfAcc = accMgr.FindAccountForServer(accMgr.localFoldersServer);
	const lfKey = lfAcc ? lfAcc.key : null;

	let accountAddressMap = new Map();
	let allAccounts = accMgr.accounts;
	for (let i = 0; i < allAccounts.length; i++) {
		let account = allAccounts.queryElementAt(i, Ci.nsIMsgAccount);
		let key = account.key;
		let thisAccAddr = accountAddressMap.has(key) ? accountAddressMap.get(key) : new Array();
		let allIdentities = account.identities;
		for (let j = 0; j < allIdentities.length; j++) {
			let identity = allIdentities.queryElementAt(j, Ci.nsIMsgIdentity);
			if (identity.email) {
				let email = identity.email.toLowerCase();
				thisAccAddr.push(email);
			}
		}
		if (thisAccAddr.length > 0) {
			// add email addresses to current server
			accountAddressMap.set(key, thisAccAddr);

			// check if INBOX is redirected to another account
			// if so, add all email addresses from this account to the redirected account
			if (account.incomingServer && account.incomingServer.rootFolder != account.incomingServer.rootMsgFolder) {
				let rAccount = accMgr.FindAccountForServer(account.incomingServer.rootMsgFolder.server);
				let rKey = rAccount.key;
				let rAccAddr = accountAddressMap.has(rKey) ? accountAddressMap.get(rKey) : new Array();
				rAccAddr = rAccAddr.concat(thisAccAddr);
				accountAddressMap.set(rKey, rAccAddr);
			}

			// Add email addresses to Local Folders
			if (lfKey) {
				let lfAccAddr = accountAddressMap.has(lfKey) ? accountAddressMap.get(lfKey) : new Array();
				lfAccAddr = lfAccAddr.concat(thisAccAddr);
				accountAddressMap.set(lfKey, lfAccAddr);
			}
		}
	}

	let author = msgHdr.mime2DecodedAuthor;
	let fromAddress = msgHeaderParser.extractHeaderAddressMailboxes(author);
	fromAddress = fromAddress.toLowerCase();
	let key = accMgr.FindAccountForServer(msgHdr.folder.server).key;

	return accountAddressMap.has(key) ? (accountAddressMap.get(key)).includes(fromAddress) : false;
}
