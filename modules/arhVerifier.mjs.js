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

import { addrIsInDomain, copy, domainIsInDomain, getDomainFromAddr, stringEndsWith } from "./utils.mjs.js";
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

	for (const header of arHeaders) {
		/** @type {import("./arhParser.mjs.js").ArhHeader} */
		let arh;
		try {
			arh = ArhParser.parse(header, prefs["arh.relaxedParsing"], prefs["internationalized.enable"]);
		} catch (exception) {
			log.error("Ignoring error in parsing of ARH", exception);
			continue;
		}

		// only use header if the authserv_id is in the allowed servers
		const allowedAuthserv = prefs["account.arh.allowedAuthserv"](account).
			split(" ").
			filter(server => server);
		if (allowedAuthserv.length &&
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

		result.dkim = result.dkim.concat(arh.resinfo.filter((element) => {
			return element.method === "dkim";
		}));
		result.spf = result.spf.concat(arh.resinfo.filter((element) => {
			return element.method === "spf";
		}));
		result.dmarc = result.dmarc.concat(arh.resinfo.filter((element) => {
			return element.method === "dmarc";
		}));
		result.bimi = result.bimi.concat(arh.resinfo.filter((element) => {
			return element.method === "bimi";
		}));
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
	let sdid = arhDKIM.propertys.header.d;
	let auid = arhDKIM.propertys.header.i;
	if (sdid && auid) {
		if (!stringEndsWith(getDomainFromAddr(auid), sdid)) {
			dkimSigResult.result = "PERMFAIL";
			dkimSigResult.errorType = "DKIM_SIGERROR_SUBDOMAIN_I";
		}
	} else if (sdid) {
		auid = `@${sdid}`;
	} else if (auid) {
		sdid = getDomainFromAddr(auid);
	}
	if (sdid) {
		dkimSigResult.sdid = sdid;
	}
	if (auid) {
		dkimSigResult.auid = auid;
	}

	// Used signature and hash algorithm
	if (arhDKIM.propertys.header.a) {
		const [algorithmSignature, algorithmHash] = arhDKIM.propertys.header.a.split("-");
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
			case 1: // warning
				dkimSigResult.warnings.push({ name: "DKIM_SIGERROR_INSECURE_A" });
				break;
			case 2: // ignore
				break;
			default:
				throw new Error("invalid error.algorithm.sign.rsa-sha1.treatAs");
		}
	}
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
	const dkimSigResults = authenticationResults.dkim.map(arhDKIM_to_dkimSigResultV2);

	// if ARH result is replacing the add-ons,
	// do some checks we also do for verification
	if (prefs["arh.replaceAddonResult"]) {
		for (const dkimSigResult of dkimSigResults) {
			checkSignatureAlgorithm(dkimSigResult);
			checkFromAlignment(from, dkimSigResult);
		}
	}

	const savedAuthResult = {
		version: "3.1",
		dkim: dkimSigResults,
		spf: authenticationResults.spf,
		dmarc: authenticationResults.dmarc,
		bimiIndicator: getBimiIndicator(headers, authenticationResults.bimi) ?? undefined,
	};
	log.debug("ARH result:", copy(savedAuthResult));
	return savedAuthResult;
}
