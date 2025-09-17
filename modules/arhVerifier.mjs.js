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

// @ts-check
/* eslint-disable camelcase */
/* eslint-disable no-magic-numbers */

import { addrIsInDomain, copy, domainIsInDomain, getDomainFromAddr, stringEndsWith, stringEqual } from "./utils.mjs.js";
import ArhParser from "./arhParser.mjs.js";
import Logging from "./logging.mjs.js";
import { getBimiIndicator } from "./bimi.mjs.js";
import prefs from "./preferences.mjs.js";

/** @import {ArhResInfo} from "./arhParser.mjs.js" */
/** @import {SavedAuthResult} from "./authVerifier.mjs.js" */
/** @import {dkimSigResultV2} from "./dkim/verifier.mjs.js" */

const log = Logging.getLogger("ArhVerifier");


/**
 * Read the Authentication-Results from the headers with allowed authentication service identifier.
 *
 * @param {string[]} arHeaders
 * @param {string|undefined} account
 * @returns {{dkim: ArhResInfo[], spf:ArhResInfo[], dmarc:ArhResInfo[], bimi:ArhResInfo[]}}
 */
function readARHs(arHeaders, account) {
	// get DKIM, SPF and DMARC res
	const result = {
		/** @type {ArhResInfo[]} */
		dkim: [],
		/** @type {ArhResInfo[]} */
		spf: [],
		/** @type {ArhResInfo[]} */
		dmarc: [],
		/** @type {ArhResInfo[]} */
		bimi: [],
	};

	/** @type {(string|null)[]} */
	const allowedAuthserv = prefs["account.arh.allowedAuthserv"](account).
		split(" ").
		filter(Boolean);

	for (const header of arHeaders) {
		/** @type {import("./arhParser.mjs.js").ArhHeader} */
		let arh;
		try {
			arh = ArhParser.parse(header, prefs["arh.relaxedParsing"], prefs["internationalized.enable"]);
		} catch (error) {
			log.error("Ignoring error in parsing of ARH", error);
			if (allowedAuthserv.length === 0) {
				if (error instanceof Error && "authserv_id" in error && typeof error.authserv_id === "string") {
					allowedAuthserv.push(error?.authserv_id);
				} else {
					allowedAuthserv.push(null);
				}
			}
			continue;
		}

		// If no authserv_id is configured we implicitly only trust the newest one.
		if (allowedAuthserv.length === 0) {
			allowedAuthserv.push(arh.authserv_id);
		}

		// Only use the header if the authserv_id is in the allowed servers.
		if (!allowedAuthserv.some(server => {
			if (arh.authserv_id === server) {
				return true;
			}
			if (server?.charAt(0) === "@") {
				return domainIsInDomain(arh.authserv_id, server.slice(1));
			}
			return false;
		})) {
			continue;
		}

		result.dkim = [...result.dkim, ...arh.resinfo.filter((element) => {
			return element.method === "dkim";
		})];
		result.spf = [...result.spf, ...arh.resinfo.filter((element) => {
			return element.method === "spf";
		})];
		result.dmarc = [...result.dmarc, ...arh.resinfo.filter((element) => {
			return element.method === "dmarc";
		})];
		result.bimi = [...result.bimi, ...arh.resinfo.filter((element) => {
			return element.method === "bimi";
		})];
	}

	return result;
}

/**
 * Convert DKIM ArhResInfo to dkimSigResultV2.
 *
 * @param {ArhResInfo} arhDKIM
 * @returns {dkimSigResultV2}
 */
function arhDKIM_to_dkimSigResultV2(arhDKIM) {
	/** @type {dkimSigResultV2} */
	const dkimSigResult = {};
	dkimSigResult.version = "2.0";
	switch (arhDKIM.result) {
		case "none": {
			dkimSigResult.result = "none";
			break;
		}
		case "pass": {
			dkimSigResult.result = "SUCCESS";
			dkimSigResult.warnings = [];
			break;
		}
		case "fail":
		case "policy":
		case "neutral":
		case "permerror": {
			dkimSigResult.result = "PERMFAIL";
			dkimSigResult.errorType = arhDKIM.reason ?? "";
			break;
		}
		case "temperror": {
			dkimSigResult.result = "TEMPFAIL";
			dkimSigResult.errorType = arhDKIM.reason ?? "";
			break;
		}
		default: {
			dkimSigResult.result = "PERMFAIL";
			dkimSigResult.errorType = arhDKIM.reason ?? arhDKIM.result;
		}
	}

	// SDID and AUID
	if (arhDKIM.properties.header.d) {
		dkimSigResult.sdid = arhDKIM.properties.header.d;
	}
	if (arhDKIM.properties.header.i) {
		dkimSigResult.auid = arhDKIM.properties.header.i;
	}

	// Used signature and hash algorithm
	if (arhDKIM.properties.header.a) {
		const [algorithmSignature, algorithmHash] = arhDKIM.properties.header.a.split("-");
		if (algorithmSignature) {
			dkimSigResult.algorithmSignature = algorithmSignature;
		}
		if (algorithmHash) {
			dkimSigResult.algorithmHash = algorithmHash;
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
	} else if (dkimSigResult.auid) {
		dkimSigResult.sdid = getDomainFromAddr(dkimSigResult.auid);
	}
}

/**
 * Check alignment of the from address.
 *
 * @param {string} from
 * @param {dkimSigResultV2} dkimSigResult
 * @returns {void}
 */
function checkFromAlignment(from, dkimSigResult) {
	if (dkimSigResult.result !== "SUCCESS") {
		return;
	}
	if (!dkimSigResult.warnings) {
		dkimSigResult.warnings = [];
	}

	// warning if from is not in SDID or AUID
	if (!addrIsInDomain(from, dkimSigResult.sdid ?? "")) {
		dkimSigResult.warnings.push({ name: "DKIM_SIGWARNING_FROM_NOT_IN_SDID" });
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
		switch (prefs["error.algorithm.sign.rsa-sha1.treatAs"]) {
			case 0: { // error
				dkimSigResult.result = "PERMFAIL";
				dkimSigResult.errorType = "DKIM_SIGERROR_INSECURE_A";
				dkimSigResult.warnings = [];
				break;
			}
			case 1: { // warning
				dkimSigResult.warnings.push({ name: "DKIM_SIGERROR_INSECURE_A" });
				break;
			}
			case 2: { // ignore
				break;
			}
			default: {
				throw new Error("invalid error.algorithm.sign.rsa-sha1.treatAs");
			}
		}
	}
}

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
 * @param {ArhResInfo[]} arhResInfo
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
 * @param {Map<string, string[]>} headers
 * @param {string} from
 * @param {string|undefined} account
 * @returns {SavedAuthResult|null}
 */
export default function getArhResult(headers, from, account) {
	const arHeaders = headers.get("authentication-results");
	if (!arHeaders || !prefs["account.arh.read"](account)) {
		return null;
	}

	const authenticationResults = readARHs(arHeaders, account);

	// convert DKIM results
	const dkimSigResults = authenticationResults.dkim.map((element) => arhDKIM_to_dkimSigResultV2(element));

	// if ARH result is replacing the add-ons,
	// do some checks we also do for verification
	if (prefs["arh.replaceAddonResult"]) {
		for (const dkimSigResult of dkimSigResults) {
			checkAndSetSdidAndAuid(dkimSigResult);
			checkSignatureAlgorithm(dkimSigResult);
			checkFromAlignment(from, dkimSigResult);
		}
	} else {
		for (const dkimSigResult of dkimSigResults) {
			// Avoid showing "Signed by undefined" if only an AUID is included.
			if (!dkimSigResult.sdid && dkimSigResult.auid) {
				dkimSigResult.sdid = getDomainFromAddr(dkimSigResult.auid);
			}
		}
	}

	const savedAuthResult = {
		version: "3.1",
		dkim: dkimSigResults,
		spf: authenticationResults.spf,
		dmarc: authenticationResults.dmarc,
		bimiIndicator: getBimiIndicator(headers, authenticationResults.bimi) ?? undefined,
	};
	sortResultKeyword(savedAuthResult.spf);
	sortResultKeyword(savedAuthResult.dmarc);
	log.debug("ARH result:", copy(savedAuthResult));
	return savedAuthResult;
}
