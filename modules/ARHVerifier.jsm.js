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
/* global Logging, ARHParser, BIMI */
/* global PREF, domainIsInDomain, getDomainFromAddr, copy */
/* exported EXPORTED_SYMBOLS, ARHVerifier, getARHResult */

"use strict";

var EXPORTED_SYMBOLS = [
	"getARHResult"
];

// @ts-ignore
const Cu = Components.utils;

Cu.import("resource://gre/modules/Services.jsm");

Cu.import("resource://dkim_verifier/logging.jsm.js");
Cu.import("resource://dkim_verifier/helper.jsm.js");
Cu.import("resource://dkim_verifier/ARHParser.jsm.js");
Cu.import("resource://dkim_verifier/bimi.jsm.js");
// @ts-ignore
let DKIM = {};
Cu.import("resource://dkim_verifier/dkimPolicy.jsm.js", DKIM);
Cu.import("resource://dkim_verifier/dkimVerifier.jsm.js", DKIM);

// @ts-ignore
const PREF_BRANCH = "extensions.dkim_verifier.";

// @ts-ignore
let log = Logging.getLogger("ARHVerifier");
// @ts-ignore
let prefs = Services.prefs.getBranch(PREF_BRANCH);

/**
 * Get the Authentication-Results header as an SavedAuthResult.
 *
 * @param {nsIMsgDBHdr} msgHdr
 * @param {Object} msg
 * @return {SavedAuthResult|Null}
 * @throws Error
 */
// eslint-disable-next-line complexity
function getARHResult(msgHdr, msg) {
	function testAllowedAuthserv(e) {
		// eslint-disable-next-line no-invalid-this
		if (this.authserv_id === e) {
			return true;
		}
		if (e.charAt(0) === "@") {
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

	// get DKIM, SPF and DMARC res
	let arhDKIMAuthServ = [];
	let arhDKIM = [];
	let arhSPF = [];
	let arhDMARC = [];
	let arhBIMI = [];
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
				getCharValue("dkim_verifier.arh.allowedAuthserv").split(" ").filter(e => e);
		} else {
			// no option exist for external messages, allow all
			allowedAuthserv = [];
		}
		if (allowedAuthserv.length > 0 &&
		    !allowedAuthserv.some(testAllowedAuthserv, arh)) {
			continue;
		}

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

	// if ARH result is replacing the add-ons,
	if (prefs.getBoolPref("arh.replaceAddonResult")) {
		// check SDID and AUID of DKIM results
		for (let i = 0; i < dkimSigResults.length; i++) {
			if (dkimSigResults[i].result === "SUCCESS") {
				try {
					DKIM.Policy.checkSDID(
						msg.DKIMSignPolicy.sdid,
						msg.from,
						dkimSigResults[i].sdid || "",
						dkimSigResults[i].auid || "",
						dkimSigResults[i].warnings || []
					);
				} catch(exception) {
					let authServ_id = dkimSigResults[i].verifiedBy + " & DKIM Verifier";
					dkimSigResults[i] = DKIM.Verifier.handleException(
						exception,
						msg,
						{d: dkimSigResults[i].sdid, i: dkimSigResults[i].auid}
					);
					dkimSigResults[i].verifiedBy = authServ_id;
				}
			}
		}
		// check for weak signature type rsa-sha1
		for (let i = 0; i < dkimSigResults.length; i++) {
			if (arhDKIM[i] && arhDKIM[i].properties.header.a === "rsa-sha1") {
				switch (prefs.getIntPref("error.algorithm.sign.rsa-sha1.treatAs")) {
					case 0: { // error
						dkimSigResults[i] = {
							version: "2.1",
							result: "PERMFAIL",
							sdid: dkimSigResults[i] ? dkimSigResults[i].sdid : "",
							auid: dkimSigResults[i] ? dkimSigResults[i].auid : "",
							algorithmSignature: dkimSigResults[i] ? dkimSigResults[i].algorithmSignature : undefined,
							algorithmHash: dkimSigResults[i] ? dkimSigResults[i].algorithmHash : undefined,
							selector: dkimSigResults[i] ? dkimSigResults[i].selector : undefined,
							verifiedBy: dkimSigResults[i] ? dkimSigResults[i].verifiedBy + " & DKIM Verifier" : undefined,
							errorType: "DKIM_SIGERROR_INSECURE_A",
						};
						break;
					}
					case 1: // warning
						if (dkimSigResults[i] && dkimSigResults[i].warnings) {
							// @ts-expect-error
							dkimSigResults[i].warnings.push({ name: "DKIM_SIGERROR_INSECURE_A" });
						}
						break;
					case 2: // ignore
						break;
					default:
						throw new Error("invalid error.algorithm.sign.rsa-sha1.treatAs");
				}
			}
		}
	}

	// sort signatures
	DKIM.Verifier.sortSignatures(msg, dkimSigResults);

	let savedAuthResult = {
		version: "3.1",
		dkim: dkimSigResults,
		spf: arhSPF,
		dmarc: arhDMARC,
		bimiIndicator: BIMI.getBimiIndicator(msg.headerFields, arhBIMI) || undefined,
	};
	log.debug("ARH result:", copy(savedAuthResult));
	return savedAuthResult;
}

/**
 * Convert DKIM ARHresinfo to dkimResult
 *
 * @param {ARHResinfo} arhDKIM
 * @return {dkimSigResultV2}
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

	let sdid = arhDKIM.properties.header.d;
	let auid = arhDKIM.properties.header.i;
	if (sdid || auid) {
		if (!sdid) {
			sdid = getDomainFromAddr(auid);
		} else if (!auid) {
			auid = "@" + sdid;
		}
		dkimSigResult.sdid = sdid;
		dkimSigResult.auid = auid;
	}

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
