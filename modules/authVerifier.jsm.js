/*
 * authVerifier.jsm.js
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
/* global Components, Services, MailServices */
/* global Logging */
/* global PREF, dkimStrings, tryGetFormattedString, addrIsInDomain, saveAuthResult, loadAuthResult, getARHResult */
/* exported EXPORTED_SYMBOLS, authVerifier */

"use strict";

// @ts-ignore
const module_version = "1.4.0";

var EXPORTED_SYMBOLS = [
	"authVerifier"
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

Cu.import("resource://dkim_verifier/logging.jsm.js");
Cu.import("resource://dkim_verifier/helper.jsm.js");
Cu.import("resource://dkim_verifier/resultStorage.jsm.js");
Cu.import("resource://dkim_verifier/arhVerifier.jsm.js");
// @ts-ignore
let DKIM = {};
Cu.import("resource://dkim_verifier/dkimPolicy.jsm.js", DKIM);
Cu.import("resource://dkim_verifier/dkimVerifier.jsm.js", DKIM);

// @ts-ignore
const PREF_BRANCH = "extensions.dkim_verifier.";

// @ts-ignore
let log = Logging.getLogger("authVerifier");
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
 *           result version ("3.1")
 * @property {dkimSigResultV2[]} dkim
 * @property {ARHResinfo[]} [spf]
 * @property {ARHResinfo[]} [dmarc]
 * @property {Object} [arh]
 * @property {dkimSigResultV2[]} [arh.dkim]
 * @property {string|undefined} [bimiIndicator] Since version 3.1
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
 * @property {String} details_str
 *           localized details block
 * @property {string} [error_str] localized error string
 * @property {String[]} [warnings_str]
 *           localized warnings
 * @property {String} [favicon]
 *           url to the favicon of the sdid
 */
// @ts-ignore

var authVerifier = {
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
			let msg = null;
			try {
				msg = await DKIM.Verifier.createMsg(msgURI);
			}
			catch (error) {
				log.error("Parsing of message failed", error);
				return Promise.resolve({
					version: "2.1",
					dkim: [{
						version: "2.0",
						result: "PERMFAIL",
						res_num: this.DKIM_RES.PERMFAIL,
						result_str: dkimStrings.getString("DKIM_INTERNALERROR_INCORRECT_EMAIL_FORMAT"),
					}],
				});
			}

			// ignore must be signed for outgoing messages
			if (msg.DKIMSignPolicy.shouldBeSigned && isOutgoing(msgHdr)) {
				log.debug("ignored must be signed for outgoing message");
				msg.DKIMSignPolicy.shouldBeSigned = false;
			}

			// read Authentication-Results header
			let arhResult = getARHResult(msgHdr, msg);

			if (arhResult) {
				// sort signatures
				DKIM.Verifier.sortSignatures(msg, arhResult.dkim);
				if (prefs.getBoolPref("arh.replaceAddonResult")) {
					savedAuthResult = arhResult;
				} else {
					let arhProperty = {};
					if (prefs.getBoolPref("arh.showDKIMResults")) {
						arhProperty.dkim = arhResult.dkim;
					}
					savedAuthResult = {
						version: "3.1",
						dkim: [],
						spf: arhResult.spf,
						dmarc: arhResult.dmarc,
						arh: arhProperty,
						bimiIndicator: arhResult.bimiIndicator,
					};
				}
			} else {
				savedAuthResult = {
					version: "3.0",
					dkim: [],
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
		// eslint-disable-next-line require-await
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
 * Convert dkimSigResultV2 to AuthResultDKIM
 *
 * @param {dkimSigResultV2} dkimSigResult
 * @return {AuthResultDKIM}
 * @throws {Error}
 */
function dkimSigResultV2_to_AuthResultDKIM(dkimSigResult) { // eslint-disable-line complexity
	/** @type {IAuthVerifier.AuthResultDKIM} */
	// @ts-expect-error
	let authResultDKIM = dkimSigResult;
	switch(dkimSigResult.result) {
		case "SUCCESS": {
			authResultDKIM.res_num = authVerifier.DKIM_RES.SUCCESS;
			authResultDKIM.result_str = dkimStrings.getString("SUCCESS");
			let keySecureStr = "";
			if (dkimSigResult.keySecure &&
			    prefs.getBoolPref("display.keySecure")) {
				keySecureStr = " \uD83D\uDD12";
			}
			let successInfos = [];
			if (dkimSigResult.sdid) {
				successInfos.push(dkimStrings.getFormattedString("SUCCESS_INFO_SIGNEDBY", [dkimSigResult.sdid + keySecureStr]));
			}
			if (dkimSigResult.verifiedBy) {
				successInfos.push(dkimStrings.getFormattedString("SUCCESS_INFO_VERIFIEDBY", [dkimSigResult.verifiedBy]));
			}
			if (successInfos.length > 0) {
				authResultDKIM.result_str += " (";
				authResultDKIM.result_str += successInfos.join(", ");
				authResultDKIM.result_str += ")";
			}
			if (!dkimSigResult.warnings) {
				throw new Error("expected warnings to be defined on SUCCESS result");
			}
			authResultDKIM.warnings_str = dkimSigResult.warnings.map(function(e) {
				return tryGetFormattedString(dkimStrings, e.name, e.params) || e.name;
			});
			break;
		}
		case "TEMPFAIL":
			authResultDKIM.res_num = authVerifier.DKIM_RES.TEMPFAIL;
			authResultDKIM.result_str =
				(dkimSigResult.errorType &&
					tryGetFormattedString(dkimStrings, dkimSigResult.errorType,
							dkimSigResult.errorStrParams)) ||
				dkimSigResult.errorType ||
				dkimStrings.getString("DKIM_INTERNALERROR_NAME");
			break;
		case "PERMFAIL": {
			if (dkimSigResult.hideFail) {
				authResultDKIM.res_num = authVerifier.DKIM_RES.PERMFAIL_NOSIG;
			} else {
				authResultDKIM.res_num = authVerifier.DKIM_RES.PERMFAIL;
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
			authResultDKIM.res_num = authVerifier.DKIM_RES.NOSIG;
			authResultDKIM.result_str = dkimStrings.getString("NOSIG");
			break;
		default:
			throw new Error(`unknown result: ${dkimSigResult.result}`);
	}

	if (dkimSigResult.errorType !== "DKIM_POLICYERROR_MISSING_SIG" && authResultDKIM.res_num !== authVerifier.DKIM_RES.NOSIG) {
		let sdid = dkimSigResult.sdid;
		let auid = dkimSigResult.auid;
		let verifiedBy = dkimSigResult.verifiedBy;
		let result = authResultDKIM.result_str;
		let sigAlgo = dkimSigResult.algorithmSignature ? dkimSigResult.algorithmSignature.toUpperCase() : undefined;
		let keyLength = dkimSigResult.keyLength ? dkimSigResult.keyLength.toString() : undefined;
		let hashAlgo = dkimSigResult.algorithmHash ? dkimSigResult.algorithmHash.toUpperCase() : undefined;
		let signingTime = dkimSigResult.timestamp ? new Date(dkimSigResult.timestamp*1000).toLocaleString() : undefined;
		let expirationTime = dkimSigResult.expiration ? new Date(dkimSigResult.expiration*1000).toLocaleString() : undefined;
		let signedHeaders = dkimSigResult.signedHeaders ? dkimSigResult.signedHeaders.join(", ") : undefined;
		let warnings = authResultDKIM.warnings_str && authResultDKIM.warnings_str.length > 0 ? authResultDKIM.warnings_str.join("\n- ") : undefined;

		authResultDKIM.details_str = result;
		if (sdid && auid) {
			authResultDKIM.details_str += "\n" + dkimStrings.getFormattedString("DKIM_RESULT_DETAILS_SIGNED_BY_FOR", [sdid, auid]);
		}
		if (verifiedBy) {
			// exists only for ARH
			authResultDKIM.details_str += "\n" + dkimStrings.getFormattedString("DKIM_RESULT_DETAILS_VERIFIED_BY", [verifiedBy]);
		}
		if (signingTime) {
			// exists only in Addon verified signatures
			if (expirationTime) {
				authResultDKIM.details_str += "\n" + dkimStrings.getFormattedString("DKIM_RESULT_DETAILS_TIME_EXPIRY", [signingTime, expirationTime]);
			} else {
				authResultDKIM.details_str += "\n" + dkimStrings.getFormattedString("DKIM_RESULT_DETAILS_TIME_NO_EXPIRY", [signingTime]);
			}
		} else if (!verifiedBy) {
			// Show this line only, if we're not using ARH (which contains a verifier)
			authResultDKIM.details_str += "\n" + dkimStrings.getString("DKIM_RESULT_DETAILS_NO_TIME");
		}
		if ( sigAlgo && hashAlgo) {
			if (keyLength) {
				authResultDKIM.details_str += "\n" + dkimStrings.getFormattedString("DKIM_RESULT_DETAILS_ALGORITHM_WITH_LENGTH", [sigAlgo, keyLength, hashAlgo]);
			} else {
				authResultDKIM.details_str += "\n" + dkimStrings.getFormattedString("DKIM_RESULT_DETAILS_ALGORITHM", [sigAlgo, hashAlgo]);
			}
		}
		if (prefs.getBoolPref("advancedInfo.includeHeaders") && signedHeaders) {
			// exists only in Addon verified signatures
			authResultDKIM.details_str += "\n" + dkimStrings.getFormattedString("DKIM_RESULT_DETAILS_HEADERS", [signedHeaders]);
		}
		if (warnings) {
			authResultDKIM.details_str += "\n" + dkimStrings.getFormattedString("DKIM_RESULT_DETAILS_WARNINGS", [warnings]);
		}
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
	return addFavicons(authResult, from, savedAuthResult.bimiIndicator);
}

/**
 * Add favicons to the DKIM results.
 *
 * @param {AuthResult} authResult
 * @param {String|undefined} from
 * @param {String|undefined} bimiIndicator
 * @return {Promise<AuthResult>} authResult
 */
async function addFavicons(authResult, from, bimiIndicator) {
	if (!prefs.getBoolPref("display.favicon.show")) {
		return authResult;
	}
	for (let i = 0; i < authResult.dkim.length; i++) {
		if (authResult.dkim[i].sdid) {
			if (bimiIndicator && from && addrIsInDomain(from, authResult.dkim[i].sdid)) {
				authResult.dkim[i].favicon = `data:image/svg+xml;base64,${bimiIndicator}`;
			} else {
			authResult.dkim[i].favicon =
				await DKIM.Policy.getFavicon(authResult.dkim[i].sdid, authResult.dkim[i].auid, from);
			}
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
			if (account.incomingServer && account.incomingServer.rootFolder !== account.incomingServer.rootMsgFolder) {
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

	return accountAddressMap.has(key) ? accountAddressMap.get(key).includes(fromAddress) : false;
}
