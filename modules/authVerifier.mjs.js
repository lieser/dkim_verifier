/**
 * Authentication Verifier.
 *
 * Copyright (c) 2014-2025 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="./authVerifier.d.ts" />
///<reference path="../experiments/storageMessage.d.ts" />
/* eslint-disable camelcase */
/* eslint-disable no-use-before-define */

export const moduleVersion = "2.0.0";

import { addrIsInDomain, addrIsInDomain2, domainIsInDomain } from "./utils.mjs.js";
import { loadAuthResult, saveAuthResult } from "./resultStorage.mjs.js";
import DMARC from "./dkim/dmarc.mjs.js";
import ExtensionUtils from "./extensionUtils.mjs.js";
import Logging from "./logging.mjs.js";
import MsgParser from "./msgParser.mjs.js";
import SignRules from "./dkim/signRules.mjs.js";
import Verifier from "./dkim/verifier.mjs.js";
import getArhResult from "./arhVerifier.mjs.js";
import { getFavicon } from "./dkim/favicon.mjs.js";
import prefs from "./preferences.mjs.js";

/** @import {ArhResInfo} from "./arhParser.mjs.js" */
/** @import {dkimSigResultV2} from "./dkim/verifier.mjs.js" */

const log = Logging.getLogger("AuthVerifier");


/**
 * @typedef {object} AuthResultV2
 * @property {string} version Result version ("2.1").
 * @property {AuthResultDKIM[]} dkim
 * @property {ArhResInfo[]} [spf]
 * @property {ArhResInfo[]} [dmarc]
 * @property {{dkim?: AuthResultDKIM[]}} [arh]
 * added in version 2.1
 */
/**
 * @typedef {AuthResultV2} AuthResult
 */

/**
 * @typedef {object} SavedAuthResultV3
 * @property {string} version Result version ("3.1").
 * @property {dkimSigResultV2[]} dkim
 * @property {ArhResInfo[]|undefined} [spf]
 * @property {ArhResInfo[]|undefined} [dmarc]
 * @property {{dkim?: dkimSigResultV2[]}|undefined} [arh]
 * @property {string|undefined} [bimiIndicator] Since version 3.1
 */
/**
 * @typedef {SavedAuthResultV3} SavedAuthResult
 */

/**
 * @typedef {IAuthVerifier.AuthResultDKIMV2} AuthResultDKIMV2
 * extends dkimSigResultV2
 * @property {number} res_num
 * - 10: SUCCESS
 * - 20: TEMPFAIL
 * - 30: PERMFAIL
 * - 35: PERMFAIL treat as no sig
 * - 40: no sig
 * @property {string} result_str Localized result string.
 * @property {string} [error_str] Localized error string.
 * @property {string[]} [warnings_str] Localized warnings.
 * @property {string} [favicon] URL to the favicon of the SDID.
 */
/**
 * @typedef {AuthResultDKIMV2} AuthResultDKIM
 */

export default class AuthVerifier {
	/**
	 * @param {Verifier} [dkimVerifier]
	 * @param {DMARC} [dmarc]
	 */
	constructor(dkimVerifier, dmarc) {
		/** @private */
		this._dkimVerifier = dkimVerifier ?? new Verifier();
		/** @private */
		this._dmarc = dmarc ?? new DMARC();
	}

	static get DKIM_RES() {
		return /** @type {const} */ ({
			SUCCESS: 10,
			TEMPFAIL: 20,
			PERMFAIL: 30,
			PERMFAIL_NOSIG: 35,
			NOSIG: 40,
		});
	}

	/**
	 * Verifies the authentication of the msg.
	 *
	 * @param {browser.messages.MessageHeader} message
	 * @returns {Promise<AuthResult>}
	 */
	async verify(message) {
		await prefs.init();
		// check for saved AuthResult
		let savedAuthResult = await loadAuthResult(message);
		if (savedAuthResult) {
			let from = null;
			try {
				from = MsgParser.parseAuthor(message.author);
			} catch (error) {
				log.warn("Parsing of from header failed", error);
			}
			return SavedAuthResult_to_AuthResult(savedAuthResult, from);
		}

		// create msg object
		const rawMessage = /** @type {string} */(await browser.messages.getRaw(message.id));
		let msgParsed;
		try {
			msgParsed = MsgParser.parseMsg(rawMessage);
		} catch (error) {
			log.error("Parsing of message failed", error);
			return {
				version: "2.1",
				dkim: [{
					version: "2.0",
					result: "PERMFAIL",
					res_num: 30,
					result_str: browser.i18n.getMessage("DKIM_INTERNALERROR_INCORRECT_EMAIL_FORMAT"),
				}],
			};
		}
		const fromHeader = msgParsed.headers.get("from");
		if (!fromHeader || !fromHeader[0]) {
			throw new Error("message does not contain a from header");
		}
		let from;
		try {
			from = MsgParser.parseFromHeader(fromHeader[0], prefs["internationalized.enable"]);
		} catch (error) {
			log.error("Parsing of from header failed", error);
			return {
				version: "2.1",
				dkim: [{
					version: "2.0",
					result: "PERMFAIL",
					res_num: 30,
					result_str: browser.i18n.getMessage("DKIM_INTERNALERROR_INCORRECT_FROM"),
				}],
			};
		}
		const msg = {
			headerFields: msgParsed.headers,
			bodyPlain: msgParsed.body,
			from,
		};
		const listIdHeader = msgParsed.headers.get("list-id");
		let listId = null;
		if (listIdHeader && listIdHeader[0]) {
			try {
				listId = MsgParser.parseListIdHeader(listIdHeader[0]);
			} catch (error) {
				log.error("Ignoring error in parsing of list-id header", error);
			}
		}

		// read Authentication-Results header
		const arhResult = getArhResult(msg.headerFields, msg.from, message.folder?.accountId);

		if (arhResult) {
			if (prefs["arh.replaceAddonResult"]) {
				savedAuthResult = arhResult;
				await checkSignRules(message, savedAuthResult.dkim, msg.from, listId, this._dmarc);
				sortSignatures(savedAuthResult.dkim, msg.from, listId);
			} else {
				sortSignatures(arhResult.dkim, msg.from, listId);
				savedAuthResult = {
					version: "3.1",
					dkim: [],
					spf: arhResult.spf,
					dmarc: arhResult.dmarc,
					arh: {
						dkim: arhResult.dkim,
					},
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
			if (prefs["account.dkim.enable"](message.folder?.accountId)) {
				// verify DKIM signatures
				const dkimResultV2 = await this._dkimVerifier.verify(msg);

				await checkSignRules(message, dkimResultV2.signatures, msg.from, listId, this._dmarc);
				sortSignatures(dkimResultV2.signatures, msg.from, listId);

				savedAuthResult.dkim = dkimResultV2.signatures;
			} else {
				savedAuthResult.dkim = [{ version: "2.0", result: "none" }];
			}
		}

		// save AuthResult
		saveAuthResult(message, savedAuthResult).
			catch(error => log.fatal("Failed to store result", error));

		const authResult = await SavedAuthResult_to_AuthResult(savedAuthResult, msg.from);
		log.debug("authResult: ", authResult);
		return authResult;
	}

	/**
	 * Resets the stored authentication result of the msg.
	 *
	 * @param {browser.messages.MessageHeader} message
	 * @returns {Promise<void>}
	 */
	static resetResult(message) {
		return saveAuthResult(message, null);
	}
}

/**
 * Checks the DKIM results against the sign rules.
 *
 * @param {browser.messages.MessageHeader} message
 * @param {dkimSigResultV2[]} dkimResults
 * @param {string} from
 * @param {string?} listId
 * @param {DMARC} dmarc
 * @returns {Promise<void>}
 */
async function checkSignRules(message, dkimResults, from, listId, dmarc) {
	if (!prefs["policy.signRules.enable"]) {
		return;
	}

	const isOutgoingCallback = () => {
		return ExtensionUtils.isOutgoing(message, from);
	};
	const dmarcToUse = prefs["policy.DMARC.shouldBeSigned.enable"] ? dmarc : undefined;

	for (let i = 0; i < dkimResults.length; i++) {
		// eslint-disable-next-line require-atomic-updates
		dkimResults[i] = await SignRules.check(
			/** @type {dkimSigResultV2} */(dkimResults[i]), from, listId, isOutgoingCallback, dmarcToUse);
	}
}

/**
 * Sort the given DKIM signatures.
 *
 * @param {dkimSigResultV2[]} signatures
 * @param {string} from
 * @param {string?} listId
 * @returns {void}
 */
function sortSignatures(signatures, from, listId) {
	/**
	 * Compare the results of two signatures.
	 *
	 * @param {dkimSigResultV2} sig1
	 * @param {dkimSigResultV2} sig2
	 * @returns {number}
	 */
	// eslint-disable-next-line unicorn/consistent-function-scoping
	function result_compare(sig1, sig2) {
		if (sig1.result === sig2.result) {
			return 0;
		}

		if (sig1.result === "SUCCESS") {
			return -1;
		} else if (sig2.result === "SUCCESS") {
			return 1;
		}

		if (sig1.result === "TEMPFAIL") {
			return -1;
		} else if (sig2.result === "TEMPFAIL") {
			return 1;
		}

		if (sig1.result === "PERMFAIL") {
			return -1;
		} else if (sig2.result === "PERMFAIL") {
			return 1;
		}

		throw new Error(`result_compare: sig1.result: ${sig1.result}; sig2.result: ${sig2.result}`);
	}

	/**
	 * Compare the warnings of two signatures.
	 *
	 * @param {dkimSigResultV2} sig1
	 * @param {dkimSigResultV2} sig2
	 * @returns {number}
	 */
	// eslint-disable-next-line unicorn/consistent-function-scoping
	function warnings_compare(sig1, sig2) {
		if (sig1.result !== "SUCCESS") {
			return 0;
		}
		if (!sig1.warnings || sig1.warnings.length === 0) {
			// sig1 has no warnings
			if (!sig2.warnings || sig2.warnings.length === 0) {
				// both signatures have no warnings
				return 0;
			}
			// sig2 has warnings
			return -1;
		}
		// sig1 has warnings
		if (!sig2.warnings || sig2.warnings.length === 0) {
			// sig2 has no warnings
			return 1;
		}
		// both signatures have warnings
		return 0;
	}

	/**
	 * Compare the SDIDs of two signatures in regards to the from and list-id header.
	 *
	 * @param {dkimSigResultV2} sig1
	 * @param {dkimSigResultV2} sig2
	 * @returns {number}
	 */
	function sdid_compare(sig1, sig2) {
		if (sig1.sdid === sig2.sdid) {
			return 0;
		}

		if (sig1.sdid && addrIsInDomain2(from, sig1.sdid)) {
			return -1;
		} else if (sig2.sdid && addrIsInDomain2(from, sig2.sdid)) {
			return 1;
		}

		if (listId) {
			if (sig1.sdid && domainIsInDomain(listId, sig1.sdid)) {
				return -1;
			} else if (sig2.sdid && domainIsInDomain(listId, sig2.sdid)) {
				return 1;
			}
		}

		return 0;
	}

	/**
	 * Compare the error reason of two signatures.
	 *
	 * @param {dkimSigResultV2} sig1
	 * @param {dkimSigResultV2} sig2
	 * @returns {number}
	 */
	// eslint-disable-next-line unicorn/consistent-function-scoping
	function error_compare(sig1, sig2) {
		if (sig1.result !== "PERMFAIL") {
			return 0;
		}
		if (sig1.errorType) {
			// sig1 has an error type
			if (sig2.errorType) {
				// both signatures have an error type
				return 0;
			}
			// sig2 has no error type
			return -1;
		}
		// sig1 has no error type
		if (sig2.errorType) {
			// sig2 has an error type
			return 1;
		}
		// both signatures have no error type
		return 0;
	}

	signatures.sort((sig1, sig2) => {
		let cmp;
		cmp = result_compare(sig1, sig2);
		if (cmp !== 0) {
			return cmp;
		}
		cmp = warnings_compare(sig1, sig2);
		if (cmp !== 0) {
			return cmp;
		}
		cmp = sdid_compare(sig1, sig2);
		if (cmp !== 0) {
			return cmp;
		}
		cmp = error_compare(sig1, sig2);
		if (cmp !== 0) {
			return cmp;
		}
		return 0;
	});
}

/**
 * Convert dkimSigResultV2 to AuthResultDKIM.
 *
 * @param {dkimSigResultV2} dkimSigResult
 * @returns {AuthResultDKIM}
 */
function dkimSigResultV2_to_AuthResultDKIM(dkimSigResult) { // eslint-disable-line complexity
	/** @type {AuthResultDKIM} */
	// @ts-expect-error
	const authResultDKIM = dkimSigResult;
	switch (dkimSigResult.result) {
		case "SUCCESS": {
			authResultDKIM.res_num = AuthVerifier.DKIM_RES.SUCCESS;
			let keySecureStr = "";
			if (dkimSigResult.keySecure &&
				prefs["display.keySecure"]) {
				keySecureStr = " \uD83D\uDD12";
			}
			authResultDKIM.result_str = browser.i18n.getMessage("SUCCESS",
				[dkimSigResult.sdid + keySecureStr]);
			if (!dkimSigResult.warnings) {
				throw new Error("expected warnings to be defined on SUCCESS result");
			}
			authResultDKIM.warnings_str = dkimSigResult.warnings.map((e) => {
				return browser.i18n.getMessage(e.name, e.params) || e.name;
			});
			break;
		}
		case "TEMPFAIL": {
			authResultDKIM.res_num = AuthVerifier.DKIM_RES.TEMPFAIL;
			authResultDKIM.result_str =
				(
					dkimSigResult.errorType &&
					browser.i18n.getMessage(dkimSigResult.errorType, dkimSigResult.errorStrParams)
				) ||
				dkimSigResult.errorType ||
				browser.i18n.getMessage("DKIM_INTERNALERROR_NAME");
			break;
		}
		case "PERMFAIL": {
			authResultDKIM.res_num = dkimSigResult.hideFail ? AuthVerifier.DKIM_RES.PERMFAIL_NOSIG : AuthVerifier.DKIM_RES.PERMFAIL;
			let errorType = dkimSigResult.errorType;
			let errorMsg;
			if (errorType) {
				if (!prefs["error.detailedReasons"]) {
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
						case "DKIM_SIGERROR_ILLFORMED_Z": {
							errorType = "DKIM_SIGERROR_ILLFORMED";
							break;
						}
						case "DKIM_SIGERROR_VERSION":
						case "DKIM_SIGERROR_UNKNOWN_A":
						case "DKIM_SIGERROR_UNKNOWN_C_H":
						case "DKIM_SIGERROR_UNKNOWN_C_B":
						case "DKIM_SIGERROR_UNKNOWN_Q": {
							errorType = "DKIM_SIGERROR_UNSUPPORTED";
							break;
						}
						case "DKIM_SIGERROR_KEY_ILLFORMED_TAGSPEC":
						case "DKIM_SIGERROR_KEY_DUPLICATE_TAG":
						case "DKIM_SIGERROR_KEY_ILLFORMED_V":
						case "DKIM_SIGERROR_KEY_ILLFORMED_H":
						case "DKIM_SIGERROR_KEY_ILLFORMED_K":
						case "DKIM_SIGERROR_KEY_ILLFORMED_N":
						case "DKIM_SIGERROR_KEY_MISSING_P":
						case "DKIM_SIGERROR_KEY_ILLFORMED_P":
						case "DKIM_SIGERROR_KEY_ILLFORMED_S":
						case "DKIM_SIGERROR_KEY_ILLFORMED_T": {
							errorType = "DKIM_SIGERROR_KEY_ILLFORMED";
							break;
						}
						case "DKIM_SIGERROR_KEY_INVALID_V":
						case "DKIM_SIGERROR_KEY_HASHNOTINCLUDED":
						case "DKIM_SIGERROR_KEY_UNKNOWN_K":
						case "DKIM_SIGERROR_KEY_MISMATCHED_K":
						case "DKIM_SIGERROR_KEY_NOTEMAILKEY":
						case "DKIM_SIGERROR_KEYDECODE": {
							errorType = "DKIM_SIGERROR_KEY_INVALID";
							break;
						}
						case "DKIM_SIGERROR_BADSIG":
						case "DKIM_SIGERROR_CORRUPT_BH":
						case "DKIM_SIGERROR_MISSING_FROM":
						case "DKIM_SIGERROR_TOOLARGE_L":
						case "DKIM_SIGERROR_NOKEY":
						case "DKIM_SIGERROR_KEY_REVOKED":
						case "DKIM_SIGERROR_KEY_TESTMODE":
						case "DKIM_POLICYERROR_MISSING_SIG":
						case "DKIM_POLICYERROR_KEYMISMATCH":
						case "DKIM_POLICYERROR_KEY_INSECURE":
						case "DKIM_POLICYERROR_WRONG_SDID": {
							break;
						}
						default: {
							log.warn(`unknown errorType: ${errorType}`);
						}
					}
				}
				errorMsg =
					browser.i18n.getMessage(errorType, dkimSigResult.errorStrParams) ||
					errorType;
				authResultDKIM.error_str = errorMsg;
			}
			authResultDKIM.result_str = errorMsg
				? browser.i18n.getMessage("PERMFAIL", [errorMsg])
				: browser.i18n.getMessage("PERMFAIL_NO_REASON");
			break;
		}
		case "none": {
			authResultDKIM.res_num = AuthVerifier.DKIM_RES.NOSIG;
			authResultDKIM.result_str = browser.i18n.getMessage("NOSIG");
			break;
		}
		default: {
			throw new Error(`unknown result: ${dkimSigResult.result}`);
		}
	}

	return authResultDKIM;
}

/**
 * Convert SavedAuthResult to AuthResult.
 *
 * @param {SavedAuthResult} savedAuthResult
 * @param {string?} from
 * @returns {Promise<AuthResult>} authResult
 */
function SavedAuthResult_to_AuthResult(savedAuthResult, from) {
	/** @type {AuthResult} */
	const authResult = {
		version: "2.1",
		dkim: savedAuthResult.dkim.map((element) => dkimSigResultV2_to_AuthResultDKIM(element)),
	};
	if (savedAuthResult.spf) {
		authResult.spf = savedAuthResult.spf;
	}
	if (savedAuthResult.dmarc) {
		authResult.dmarc = savedAuthResult.dmarc;
	}
	if (savedAuthResult.arh && savedAuthResult.arh.dkim) {
		authResult.arh = {
			dkim: savedAuthResult.arh.dkim.map(
				(element) => dkimSigResultV2_to_AuthResultDKIM(element)),
		};
	}
	return addFavicons(authResult, from, savedAuthResult.bimiIndicator);
}

/**
 * Add favicons to the DKIM results.
 *
 * @param {AuthResult} authResult
 * @param {string?} from
 * @param {string|undefined} bimiIndicator
 * @returns {Promise<AuthResult>} authResult
 */
async function addFavicons(authResult, from, bimiIndicator) {
	if (!prefs["display.favicon.show"]) {
		return authResult;
	}
	if (authResult.dkim[0]?.res_num !== AuthVerifier.DKIM_RES.SUCCESS) {
		return authResult;
	}
	for (const dkim of authResult.dkim) {
		if (dkim.sdid) {
			dkim.favicon = bimiIndicator && from && addrIsInDomain(from, dkim.sdid)
				? `data:image/svg+xml;base64,${bimiIndicator}`
				: await getFavicon(dkim.sdid, dkim.auid, from);
		}
	}
	return authResult;
}
