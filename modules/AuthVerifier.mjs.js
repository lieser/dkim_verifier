/*
 * AuthVerifier.mjs.js
 *
 * Authentication Verifier.
 *
 * Version: 2.0.0pre1 (04 April 2020)
 *
 * Copyright (c) 2014-2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="./AuthVerifier.d.ts" />
///<reference path="../WebExtensions.d.ts" />
///<reference path="../experiments/storageMessage.d.ts" />
/* eslint-env webextensions */
/* eslint-disable camelcase */
/* eslint-disable no-use-before-define */
/* eslint no-unused-vars: ["error", { "varsIgnorePattern": "ArhParserModule|VerifierModule" }]*/

export const moduleVersion = "2.0.0";

import ArhParser, * as ArhParserModule from "./arhParser.mjs.js";
import Verifier, * as VerifierModule from "./dkim/verifier.mjs.js";
import { domainIsInDomain, getDomainFromAddr } from "./utils.mjs.js";
import { DKIM_InternalError } from "./error.mjs.js";
import DMARC from "./dkim/dmarc.mjs.js";
import ExtensionUtils from "./extensionUtils.mjs.js";
import Logging from "./logging.mjs.js";
import MsgParser from "./msgParser.mjs.js";
import SignRules from "./dkim/signRules.mjs.js";
import { getFavicon } from "./dkim/favicon.mjs.js";
import prefs from "./preferences.mjs.js";

const log = Logging.getLogger("AuthVerifier");

/**
 * @typedef {Object} AuthResultV2
 * @property {String} version
 *           result version ("2.1")
 * @property {AuthResultDKIM[]} dkim
 * @property {ArhParserModule.ArhResInfo[]=} [spf]
 * @property {ArhParserModule.ArhResInfo[]=} [dmarc]
 * @property {{dkim?: AuthResultDKIM[]}=} [arh]
 *           added in version 2.1
 */
/**
 * @typedef {AuthResultV2} AuthResult
 */

/**
 * @typedef {Object} SavedAuthResultV3
 * @property {String} version
 *           result version ("3.0")
 * @property {VerifierModule.dkimSigResultV2[]} dkim
 * @property {ArhParserModule.ArhResInfo[]=} [spf]
 * @property {ArhParserModule.ArhResInfo[]=} [dmarc]
 * @property {{dkim?: VerifierModule.dkimSigResultV2[]}=} [arh]
 */
/**
 * @typedef {SavedAuthResultV3} SavedAuthResult
 */

/**
 * @typedef {IAuthVerifier.AuthResultDKIMV2} AuthResultDKIMV2
 * extends dkimSigResultV2
 * @property {Number} res_num
 *           10: SUCCESS
 *           20: TEMPFAIL
 *           30: PERMFAIL
 *           35: PERMFAIL treat as no sig
 *           40: no sig
 * @property {String} result_str
 *           localized result string
 * @property {String[]=} [warnings_str]
 *           localized warnings
 * @property {String=} [favicon]
 *           url to the favicon of the sdid
 */
/**
 * @typedef {AuthResultDKIMV2} AuthResultDKIM
 */

export default class AuthVerifier {
	/**
	 * @param {DMARC} [dmarc]
	 */
	constructor(dmarc) {
		/** @private */
		this._dmarc = dmarc ?? new DMARC();
	}

	static get DKIM_RES() {
		return {
			SUCCESS: 10,
			TEMPFAIL: 20,
			PERMFAIL: 30,
			PERMFAIL_NOSIG: 35,
			NOSIG: 40,
		};
	}

	/**
	 * Verifies the authentication of the msg.
	 *
	 * @param {browser.messageDisplay.MessageHeader} message
	 * @return {Promise<AuthResult>}
	 */
	async verify(message) {
		await prefs.init();
		// check for saved AuthResult
		let savedAuthResult = await loadAuthResult(message);
		if (savedAuthResult) {
			return SavedAuthResult_to_AuthResult(savedAuthResult);
		}

		// create msg object
		const rawMessage = await browser.messages.getRaw(message.id);
		const msgParsed = MsgParser.parseMsg(rawMessage);
		const fromHeader = msgParsed.headers.get("from");
		if (!fromHeader) {
			throw new Error("message does not contain a from header");
		}
		const msg = {
			headerFields: msgParsed.headers,
			bodyPlain: msgParsed.body,
			from: MsgParser.parseFromHeader(fromHeader[0]),
			listId: "",
		};
		const listId = msgParsed.headers.get("list-id");
		if (listId) {
			msg.listId = MsgParser.parseListIdHeader(listId[0]);
		}

		// read Authentication-Results header
		const arhResult = await getARHResult(message, msg.headerFields, msg.from, msg.listId, message.folder.accountId, this._dmarc);

		if (arhResult) {
			if (prefs["arh.replaceAddonResult"]) {
				savedAuthResult = arhResult;
			} else {
				savedAuthResult = {
					version: "3.0",
					dkim: [],
					spf: arhResult.spf,
					dmarc: arhResult.dmarc,
					arh: {
						dkim: arhResult.dkim
					},
				};
			}
		} else {
			savedAuthResult = {
				version: "3.0",
				dkim: [],
			};
		}

		if (!savedAuthResult.dkim || savedAuthResult.dkim.length === 0) {
			if (prefs["account.dkim.enable"](message.folder.accountId)) {
				// verify DKIM signatures
				const dkimResultV2 = await new Verifier().verify(msg);

				await checkSignRules(message, dkimResultV2.signatures, msg.from, msg.listId, this._dmarc);
				VerifierModule.sortSignatures(dkimResultV2.signatures, msg.from, msg.listId);

				savedAuthResult.dkim = dkimResultV2.signatures;
			} else {
				savedAuthResult.dkim = [{ version: "2.0", result: "none" }];
			}
		}

		// save AuthResult
		saveAuthResult(message, savedAuthResult).
			catch(error => log.fatal("Failed to store result", error));

		const authResult = await SavedAuthResult_to_AuthResult(savedAuthResult);
		log.debug("authResult: ", authResult);
		return authResult;
	}

	/**
	 * Resets the stored authentication result of the msg.
	 *
	 * @param {any} messageId
	 * @return {Promise<void>}
	 */
	resetResult(messageId) {
		const promise = saveAuthResult(messageId, null);
		promise.then(null, function onReject(exception) {
			log.warn(exception);
		});
		return saveAuthResult(messageId, null);
	}
}

/**
 * Get the Authentication-Results header as an SavedAuthResult.
 *
 * @param {browser.messageDisplay.MessageHeader} message
 * @param {Map<string, string[]>} headers
 * @param {string} from
 * @param {string} listId
 * @param {string} account
 * @param {DMARC} dmarc
 * @return {Promise<SavedAuthResult|Null>}
 */
async function getARHResult(message, headers, from, listId, account, dmarc) {
	const arHeaders = headers.get("authentication-results");
	if (!arHeaders || !prefs["account.arh.read"](account)) {
		return null;
	}

	// get DKIM, SPF and DMARC res
	/** @type {ArhParserModule.ArhResInfo[]} */
	let arhDKIM = [];
	/** @type {ArhParserModule.ArhResInfo[]} */
	let arhSPF = [];
	/** @type {ArhParserModule.ArhResInfo[]} */
	let arhDMARC = [];
	for (let i = 0; i < arHeaders.length; i++) {
		/** @type {ArhParserModule.ArhHeader} */
		let arh;
		try {
			arh = ArhParser.parse(arHeaders[i], prefs["arh.relaxedParsing"]);
		} catch (exception) {
			log.error("Ignoring error in parsing of ARH", exception);
			continue;
		}

		// only use header if the authserv_id is in the allowed servers
		const allowedAuthserv = prefs["account.arh.allowedAuthserv"](account).
			split(" ").
			filter(server => server);
		if (allowedAuthserv.length > 0 &&
			!allowedAuthserv.some(server => {
				if (arh.authserv_id === server) {
					return true;
				}
				if (server.charAt(0) === "@") {
					return domainIsInDomain(arh.authserv_id, server.substr(1));
				}
				return false;
			})) {
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
	const dkimSigResults = arhDKIM.map(arhDKIM_to_dkimSigResultV2);

	// if ARH result is replacing the add-ons,
	// check SDID and AUID of DKIM results
	if (prefs["arh.replaceAddonResult"]) {
		await checkSignRules(message, dkimSigResults, from, listId, dmarc);
	}

	// sort signatures
	VerifierModule.sortSignatures(dkimSigResults, from);

	const savedAuthResult = {
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
 * @param {browser.messageDisplay.MessageHeader} message
 * @param {SavedAuthResult|Null} savedAuthResult
 * @return {Promise<void>}
 */
async function saveAuthResult(message, savedAuthResult) {
	// don't save result if disabled or message is external
	if (!prefs.saveResult || !message.folder) {
		return;
	}

	if (savedAuthResult === null) {
		// reset result
		log.debug("reset AuthResult result");
		await browser.storageMessage.set(message.id, "dkim_verifier@pl-result", "");
	} else if (savedAuthResult.dkim[0].result === "TEMPFAIL") {
		// don't save result if DKIM result is a TEMPFAIL
		log.debug("result not saved because DKIM result is a TEMPFAIL");
	} else {
		log.debug("save AuthResult result");
		await browser.storageMessage.set(message.id, "dkim_verifier@pl-result",
			JSON.stringify(savedAuthResult));
	}
}

/**
 * Get saved authentication result
 *
 * @param {browser.messageDisplay.MessageHeader} message
 * @return {Promise<SavedAuthResult|null>} savedAuthResult
 */
async function loadAuthResult(message) {
	// don't load result if disabled or message is external
	if (!prefs.saveResult || !message.folder) {
		return null;
	}

	const savedAuthResultJSON = await browser.storageMessage.
		get(message.id, "dkim_verifier@pl-result");

	if (savedAuthResultJSON === "") {
		return null;
	}
	log.debug("AuthResult result found: ", savedAuthResultJSON);

	/** @type {VerifierModule.dkimResultV1|AuthResultV2|SavedAuthResultV3} */
	const savedAuthResult = JSON.parse(savedAuthResultJSON);

	const versionMatch = savedAuthResult.version.match(/^[0-9]+/);
	if (!versionMatch) {
		throw new Error("No version found in AuthResult");
	}
	const majorVersion = versionMatch[0];
	if (majorVersion === "1") {
		// old dkimResultV1 (AuthResult version 1)
		/** @type {VerifierModule.dkimResultV1} */
		// @ts-expect-error
		const resultV1 = savedAuthResult;
		/** @type {SavedAuthResultV3} */
		const res = {
			version: "3.0",
			dkim: [dkimResultV1_to_dkimSigResultV2(resultV1)],
		};
		return res;
	}
	if (majorVersion === "2") {
		// AuthResult version 2
		/** @type {AuthResultV2} */
		// @ts-expect-error
		const resultV2 = savedAuthResult;
		/** @type {SavedAuthResultV3} */
		const res = {
			version: "3.0",
			dkim: resultV2.dkim.map(AuthResultDKIMV2_to_dkimSigResultV2),
		};
		if (resultV2.spf) {
			res.spf = resultV2.spf;
		}
		if (resultV2.dmarc) {
			res.dmarc = resultV2.dmarc;
		}
		if (resultV2.arh && resultV2.arh.dkim) {
			res.arh = {
				dkim: resultV2.arh.dkim.map(AuthResultDKIMV2_to_dkimSigResultV2),
			};
		}
		return res;
	}
	if (majorVersion === "3") {
		// SavedAuthResult version 3
		// @ts-expect-error
		return savedAuthResult;
	}

	throw new Error(`AuthResult result has wrong Version (${savedAuthResult.version})`);
}

/**
 * Checks the DKIM results against the sign rules.
 *
 * @param {browser.messageDisplay.MessageHeader} message
 * @param {VerifierModule.dkimSigResultV2[]} dkimResults
 * @param {string} from
 * @param {string} listId
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
		dkimResults[i] = await SignRules.check(dkimResults[i], from, listId, isOutgoingCallback, dmarcToUse);
	}
}

/**
 * Convert DKIM ARHresinfo to dkimResult
 *
 * @param {ArhParserModule.ArhResInfo} arhDKIM
 * @return {VerifierModule.dkimSigResultV2}
 */
function arhDKIM_to_dkimSigResultV2(arhDKIM) {
	/** @type {VerifierModule.dkimSigResultV2} */
	const dkimSigResult = {};
	dkimSigResult.version = "2.0";
	switch (arhDKIM.result) {
		case "none":
			dkimSigResult.result = "none";
			break;
		case "pass": {
			dkimSigResult.result = "SUCCESS";
			dkimSigResult.warnings = [];
			let sdid = arhDKIM.propertys.header.d;
			let auid = arhDKIM.propertys.header.i;
			if (sdid || auid) {
				if (!sdid) {
					// @ts-expect-error
					sdid = getDomainFromAddr(auid);
				} else if (!auid) {
					auid = `@${sdid}`;
				}
				dkimSigResult.sdid = sdid;
				dkimSigResult.auid = auid;
			}
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
			throw new DKIM_InternalError(`invalid dkim result in arh: ${arhDKIM.result}`);
	}
	return dkimSigResult;
}

/**
 * Convert dkimResultV1 to dkimSigResultV2
 *
 * @param {VerifierModule.dkimResultV1} dkimResultV1
 * @return {VerifierModule.dkimSigResultV2}
 */
function dkimResultV1_to_dkimSigResultV2(dkimResultV1) {
	/** @type {VerifierModule.dkimSigResultV2} */
	const sigResultV2 = {
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
					return { name: w, params: [dkimResultV1.shouldBeSignedBy ?? ""] };
				}
				return { name: w };
			}
		);
	}
	if (dkimResultV1.errorType === "DKIM_POLICYERROR_WRONG_SDID" ||
		dkimResultV1.errorType === "DKIM_POLICYERROR_MISSING_SIG") {
		sigResultV2.errorStrParams = [dkimResultV1.shouldBeSignedBy ?? ""];
	}
	return sigResultV2;
}

/**
 * Convert dkimSigResultV2 to AuthResultDKIM
 *
 * @param {VerifierModule.dkimSigResultV2} dkimSigResult
 * @return {AuthResultDKIM}
 * @throws DKIM_InternalError
 */
function dkimSigResultV2_to_AuthResultDKIM(dkimSigResult) { // eslint-disable-line complexity
	/** @type {AuthResultDKIM} */
	// @ts-expect-error
	const authResultDKIM = dkimSigResult;
	switch (dkimSigResult.result) {
		case "SUCCESS": {
			authResultDKIM.res_num = 10;
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
			authResultDKIM.warnings_str = dkimSigResult.warnings.map(function (e) {
				return browser.i18n.getMessage(e.name, e.params) || e.name;
			});
			break;
		}
		case "TEMPFAIL":
			authResultDKIM.res_num = 20;
			authResultDKIM.result_str =
				(dkimSigResult.errorType &&
					browser.i18n.getMessage(dkimSigResult.errorType, dkimSigResult.errorStrParams)) ||
				dkimSigResult.errorType ||
				browser.i18n.getMessage("DKIM_INTERNALERROR_NAME");
			break;
		case "PERMFAIL": {
			if (dkimSigResult.hideFail) {
				authResultDKIM.res_num = 35;
			} else {
				authResultDKIM.res_num = 30;
			}
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
						case "DKIM_POLICYERROR_MISSING_SIG":
						case "DKIM_POLICYERROR_KEYMISMATCH":
						case "DKIM_POLICYERROR_KEY_INSECURE":
						case "DKIM_POLICYERROR_WRONG_SDID":
							break;
						default:
							log.warn(`unknown errorType: ${errorType}`);
					}
				}
				errorMsg =
					browser.i18n.getMessage(errorType,
						dkimSigResult.errorStrParams) ||
					errorType;
			}
			if (errorMsg) {
				authResultDKIM.result_str = browser.i18n.getMessage("PERMFAIL",
					[errorMsg]);
			} else {
				authResultDKIM.result_str = browser.i18n.getMessage("PERMFAIL_NO_REASON");
			}
			break;
		}
		case "none":
			authResultDKIM.res_num = 40;
			authResultDKIM.result_str = browser.i18n.getMessage("NOSIG");
			break;
		default:
			throw new DKIM_InternalError(`unknown result: ${dkimSigResult.result}`);
	}

	return authResultDKIM;
}

/**
 * Convert SavedAuthResult to AuthResult
 *
 * @param {SavedAuthResult} savedAuthResult
 * @return {Promise<AuthResult>} authResult
 */
function SavedAuthResult_to_AuthResult(savedAuthResult) {
	/** @type {AuthResult} */
	const authResult = {
		version: "2.1",
		dkim: savedAuthResult.dkim.map(dkimSigResultV2_to_AuthResultDKIM),
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
				dkimSigResultV2_to_AuthResultDKIM)
		};
	}
	return addFavicons(authResult);
}

/**
 * Convert AuthResultV2 to dkimSigResultV2
 *
 * @param {AuthResultDKIMV2} authResultDKIM
 * @return {VerifierModule.dkimSigResultV2} dkimSigResultV2
 */
function AuthResultDKIMV2_to_dkimSigResultV2(authResultDKIM) {
	/** @type {VerifierModule.dkimSigResultV2} */
	const dkimSigResult = authResultDKIM;
	// @ts-ignore
	dkimSigResult.res_num = undefined;
	// @ts-ignore
	dkimSigResult.result_str = undefined;
	// @ts-ignore
	dkimSigResult.warnings_str = undefined;
	// @ts-ignore
	dkimSigResult.favicon = undefined;
	return dkimSigResult;
}


/**
 * Add favicons to the DKIM results.
 *
 * @param {AuthResult} authResult
 * @return {Promise<AuthResult>} authResult
 */
async function addFavicons(authResult) {
	if (!prefs["display.favicon.show"]) {
		return authResult;
	}
	if (authResult.dkim[0].res_num !== AuthVerifier.DKIM_RES.SUCCESS) {
		return authResult;
	}
	for (const dkim of authResult.dkim) {
		if (dkim.sdid) {
			dkim.favicon = await getFavicon(dkim.sdid);
		}
	}
	return authResult;
}
