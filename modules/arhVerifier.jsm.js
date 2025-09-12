/**
 * Get the verification results from the Authentication-Results header if reading of it is enabled.
 *
 * If the DKIM result from the ARH replaces our own verification,
 * we do similar sanity/policy checks as the internal DKIM Verifier.
 *
 * Copyright (c) 2025 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// options for ESLint
/* global Components, Services */
/* global Logging, arhParser, BIMI */
/* global PREF, domainIsInDomain, getDomainFromAddr, stringEndsWith, copy, DKIM_SigError, stringEqual */
/* exported EXPORTED_SYMBOLS, arhVerifier, getARHResult */

"use strict";

var EXPORTED_SYMBOLS = [
	"getARHResult"
];

// @ts-expect-error
const Cu = Components.utils;

Cu.import("resource://gre/modules/Services.jsm");

Cu.import("resource://dkim_verifier/logging.jsm.js");
Cu.import("resource://dkim_verifier/helper.jsm.js");
Cu.import("resource://dkim_verifier/arhParser.jsm.js");
Cu.import("resource://dkim_verifier/bimi.jsm.js");
// @ts-expect-error
let DKIM = {};
Cu.import("resource://dkim_verifier/dkimPolicy.jsm.js", DKIM);

// @ts-expect-error
const PREF_BRANCH = "extensions.dkim_verifier.";

// @ts-expect-error
let log = Logging.getLogger("arhVerifier");
// @ts-expect-error
let prefs = Services.prefs.getBranch(PREF_BRANCH);

/**
 * Converts an ARH result Keyword to a sorted number.
 *
 * @param {string} result
 * @returns {number}
 */
function resultToNumber(result) {
	if (stringEqual(result, "pass")) {
		return 0;
	}

	if (stringEqual(result, "neutral")) {
		return 10;
	}
	if (stringEqual(result, "declined")) {
		return 11;
	}
	if (stringEqual(result, "policy")) {
		return 12;
	}

	if (stringEqual(result, "hardfail")) {
		return 20;
	}
	if (stringEqual(result, "fail")) {
		return 21;
	}
	if (stringEqual(result, "softfail")) {
		return 22;
	}

	if (stringEqual(result, "permerror")) {
		return 30;
	}
	if (stringEqual(result, "temperror")) {
		return 31;
	}

	if (stringEqual(result, "skipped")) {
		return 40;
	}
	if (stringEqual(result, "none")) {
		return 41;
	}

	return 99;
}

/**
 * Sort the given ArhResInfo.
 *
 * @param {ARHResinfo[]} arhResInfo
 * @returns {void}
 */
function sortResultKeyword(arhResInfo) {
	arhResInfo.sort((resInfo1, resInfo2) => {
		return resultToNumber(resInfo1.result) - resultToNumber(resInfo2.result);
	});
}

/**
 * Get the Authentication-Results header as an SavedAuthResult.
 *
 * @param {nsIMsgDBHdr} msgHdr
 * @param {Object} msg
 * @returns {SavedAuthResult|Null}
 * @throws Error
 */
// eslint-disable-next-line complexity
function getARHResult(msgHdr, msg) {
	function testAllowedAuthserv(e) {
		// eslint-disable-next-line no-invalid-this
		if (this.authserv_id === e) {
			return true;
		}
		if (e && e.charAt(0) === "@") {
			// eslint-disable-next-line no-invalid-this
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

	// only use header if the authserv_id is in the allowed servers
	let allowedAuthserv;
	if (msgHdr.folder) {
		allowedAuthserv = msgHdr.folder.server.
			getCharValue("dkim_verifier.arh.allowedAuthserv").split(" ").filter(e => e);
	} else {
		// no option exist for external messages
		allowedAuthserv = [];
	}

	// get DKIM, SPF and DMARC res
	let arhDKIMAuthServ = [];
	let arhDKIM = [];
	let arhSPF = [];
	let arhDMARC = [];
	let arhBIMI = [];
	for (let i = 0; i < msg.headerFields.get("authentication-results").length; i++) {
		let arh;
		try {
			arh = arhParser.parse(msg.headerFields.get("authentication-results")[i]);
		} catch (exception) {
			if (!allowedAuthserv.length) {
				if (exception instanceof Error && "authserv_id" in exception && typeof exception.authserv_id === "string") {
					allowedAuthserv.push(exception.authserv_id);
				} else {
					allowedAuthserv.push(null);
				}
			}
			log.error("Ignoring error in parsing of ARH", exception);
			continue;
		}

		// If no authserv_id is configured we implicitly only trust the newest one.
		if (!allowedAuthserv.length) {
			allowedAuthserv.push(arh.authserv_id);
		}

		// Only use the header if the authserv_id is in the allowed servers.
		if (!allowedAuthserv.some(testAllowedAuthserv, arh)) {
			log.debug("Ignoring ARH added by "+arh.authserv_id);
			continue;
		}

		log.debug("Using ARH added by "+arh.authserv_id);

		arhDKIM = arhDKIM.concat(arh.resinfo.filter(e => e.method === "dkim"));
		arhSPF = arhSPF.concat(arh.resinfo.filter(e => e.method === "spf"));
		arhDMARC = arhDMARC.concat(arh.resinfo.filter(e => e.method === "dmarc"));
		arhBIMI = arhBIMI.concat(arh.resinfo.filter(e => e.method === "bimi"));

		let newArhDkimCount = arhDKIM.length - arhDKIMAuthServ.length;
		for (let i = 0; i < newArhDkimCount; i++) {
			arhDKIMAuthServ.push(arh.authserv_id);
		}
	}

	// convert DKIM results
	let dkimSigResults = arhDKIM.map(arhDKIM_to_dkimSigResultV2);
	for (let i = 0; i < dkimSigResults.length; i++) {
		dkimSigResults[i].verifiedBy = arhDKIMAuthServ[i];
	}

	if (prefs.getBoolPref("arh.replaceAddonResult")) {
		// Additional checks from DKIM Verifier
		for (let i = 0; i < dkimSigResults.length; i++) {
			let arhResult = dkimSigResults[i].result;
			checkAndSetSdidAndAuid(dkimSigResults[i]);
			checkSignPolicy(msg, dkimSigResults[i]);
			checkSignatureAlgorithm(dkimSigResults[i]);

			if (arhResult !== dkimSigResults[i].result
				// @ts-expect-error
				|| (dkimSigResults[i].warnings && dkimSigResults[i].warnings.length > 0)
			   ) {
				if (dkimSigResults[i].verifiedBy !== "") {
					// if authserv_id is empty (may only happen if relaxed parsing is enabled)
					// dont't add the internal verifier, even if result was modified by internal verification
					// so, no verifier will be shown in the GUI
					dkimSigResults[i].verifiedBy += " & DKIM Verifier";
				}
				if (dkimSigResults[i].result !== "SUCCESS") { dkimSigResults[i].warnings = []; }
			}
		}
	}

	let savedAuthResult = {
		version: "3.1",
		dkim: dkimSigResults,
		spf: arhSPF,
		dmarc: arhDMARC,
		bimiIndicator: BIMI.getBimiIndicator(msg.headerFields, arhBIMI) || undefined,
	};
	sortResultKeyword(savedAuthResult.spf);
	sortResultKeyword(savedAuthResult.dmarc);
	log.debug("ARH result:", copy(savedAuthResult));
	return savedAuthResult;
}

/**
 * Convert DKIM ARHresinfo to dkimResult
 *
 * @param {ARHResinfo} arhDKIM
 * @returns {dkimSigResultV2}
 * @throws {Error}
 */
function arhDKIM_to_dkimSigResultV2(arhDKIM) {
	/** @type {dkimSigResultV2} */
	let dkimSigResult = {};
	dkimSigResult.version = "2.1";

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
			throw new Error(`invalid dkim result in arh: ${arhDKIM.result}`);
	}

	// SDID and AUID
	let sdid = arhDKIM.properties.header.d;
	let auid = arhDKIM.properties.header.i;
	if (!sdid && auid) {
		// Avoid showing "Signed by undefined" if only an AUID is included.
		sdid = getDomainFromAddr(auid);
	}
	if (sdid) { dkimSigResult.sdid = sdid; }
	if (auid) { dkimSigResult.auid = auid; }

	if (arhDKIM.properties.header.a) {
		// get signature algorithm (plain-text;REQUIRED)
		// currently only "rsa-sha1" or "rsa-sha256" or "ed25519-sha256"
		let sig_a_tag_k = "(rsa|ed25519|[A-Za-z](?:[A-Za-z]|[0-9])*)";
		let sig_a_tag_h = "(sha1|sha256|[A-Za-z](?:[A-Za-z]|[0-9])*)";
		let sig_a_tag_alg = sig_a_tag_k+"-"+sig_a_tag_h;
		let sig_hash_alg = arhDKIM.properties.header.a.match(sig_a_tag_alg);
		if (sig_hash_alg[1] && sig_hash_alg[2]) {
			dkimSigResult.algorithmSignature = sig_hash_alg[1];
			dkimSigResult.algorithmHash = sig_hash_alg[2];
		}
	}

	return dkimSigResult;
}

/**
 * Check and set SDID and AUID.
 *
 * @param {dkimSigResultV2} dkimSigResult
 * @returns {void}
 */
function checkAndSetSdidAndAuid(dkimSigResult) {
	if (dkimSigResult.sdid && dkimSigResult.auid) {
		if (!stringEndsWith(getDomainFromAddr(dkimSigResult.auid), dkimSigResult.sdid)) {
			dkimSigResult.result = "PERMFAIL";
			dkimSigResult.errorType = "DKIM_SIGERROR_SUBDOMAIN_I";
			dkimSigResult.warnings = [];
		}
	} else if (dkimSigResult.sdid) {
		dkimSigResult.auid = `@${dkimSigResult.sdid}`;
	}
}

/**
 * Check the signature algorithm.
 *
 * @param {dkimSigResultV2} dkimSigResult
 * @returns {void}
 */
function checkSignatureAlgorithm(dkimSigResult) {
	if (dkimSigResult.result !== "SUCCESS") {
		return;
	}
	if (!dkimSigResult.warnings) {
		dkimSigResult.warnings = [];
	}

	if (dkimSigResult.algorithmSignature === "rsa" && dkimSigResult.algorithmHash === "sha1") {
		switch (prefs.getIntPref("error.algorithm.sign.rsa-sha1.treatAs")) {
			case PREF.TREATAS.ERROR: {
				dkimSigResult.result = "PERMFAIL";
				dkimSigResult.errorType = "DKIM_SIGERROR_INSECURE_A";
				dkimSigResult.warnings = [];
				break;
			}
			case PREF.TREATAS.WARNING:
				dkimSigResult.warnings.push({ name: "DKIM_SIGERROR_INSECURE_A" });
				break;
			case PREF.TREATAS.NOTHING:
				break;
			default: // should not happen
				throw new Error("invalid error.algorithm.sign.rsa-sha1.treatAs");
		}
	}
}

/**
 * Check signing policies and alignment of the from address.
 *
 * @param {Object} msg
 * @param {dkimSigResultV2} dkimSigResult
 * @returns {void}
 */
function checkSignPolicy(msg, dkimSigResult) {
	if (!dkimSigResult.warnings) {
		dkimSigResult.warnings = [];
	}

	try {
		DKIM.Policy.checkSDID(msg.DKIMSignPolicy.sdid,
							  msg.from,
							  dkimSigResult.sdid ? dkimSigResult.sdid : "",
							  dkimSigResult.warnings);
	} catch(e) {
		if (e instanceof DKIM_SigError) {
			dkimSigResult.result = "PERMFAIL";
			dkimSigResult.errorType = e.errorType;
			dkimSigResult.errorStrParams = e.errorStrParams;
			dkimSigResult.warnings = [];
			log.warn("Exception in sign policy check on ARH : " + dkimSigResult.verifiedBy);
		} else {
			dkimSigResult.result = "TEMPFAIL";
			log.fatal("Error during ARH sign policy check:", e);
		}
	}
}