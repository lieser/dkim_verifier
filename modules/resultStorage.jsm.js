/**
 * Safe and load authentication result.
 *
 * Copyright (c) 2025 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// options for ESLint
/* global Components, Services, Logging */
/* exported EXPORTED_SYMBOLS, resultStorage, saveAuthResult, loadAuthResult */

"use strict";

var EXPORTED_SYMBOLS = [
	"saveAuthResult",
	"loadAuthResult"
];

// @ts-ignore
const Cu = Components.utils;

Cu.import("resource://gre/modules/Services.jsm");

Cu.import("resource://dkim_verifier/logging.jsm.js");

// @ts-ignore
const PREF_BRANCH = "extensions.dkim_verifier.";
// @ts-ignore
let log = Logging.getLogger("resultStorage");
// @ts-ignore
let prefs = Services.prefs.getBranch(PREF_BRANCH);

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
					return {name: w, params: [dkimResultV1.shouldBeSignedBy || ""]};
				}
				return {name: w};
			}
		);
	}
	if (dkimResultV1.errorType === "DKIM_POLICYERROR_WRONG_SDID" ||
	    dkimResultV1.errorType === "DKIM_POLICYERROR_MISSING_SIG") {
		sigResultV2.errorStrParams = [dkimResultV1.shouldBeSignedBy || ""];
	}
	return sigResultV2;
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
	dkimSigResult.details_str = undefined;
	dkimSigResult.warnings_str = undefined;
	dkimSigResult.favicon = undefined;
	return dkimSigResult;
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
 * @throws {Error}
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

			const versionMatch = savedAuthResult.version.match(/^[0-9]+/);
			if (!versionMatch) {
				throw new Error("No version found in AuthResult");
			}
			const majorVersion = versionMatch[0];
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
					// @ts-expect-error
					savedAuthResult.arh.dkim = resultV2.arh.dkim.map(
						AuthResultDKIMV2_to_dkimSigResultV2);
				}
				return savedAuthResult;
			}
			if (majorVersion === "3") {
				// SavedAuthResult version 3
				return savedAuthResult;
			}

			throw new Error(`AuthResult result has wrong Version (${savedAuthResult.version})`);
		}
	}

	return null;
}
