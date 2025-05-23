/**
 * Safe and load authentication result to/from a persistent storage.
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

import Logging from "./logging.mjs.js";
import prefs from "./preferences.mjs.js";

/** @import {AuthResultDKIMV2, AuthResultV2, SavedAuthResult, SavedAuthResultV3} from "./authVerifier.mjs.js" */
/** @import {dkimResultV1, dkimSigResultV2} from "./dkim/verifier.mjs.js" */

const log = Logging.getLogger("ResultStorage");


/**
 * Convert dkimResultV1 to dkimSigResultV2.
 *
 * @param {dkimResultV1} dkimResultV1
 * @returns {dkimSigResultV2}
 */
function dkimResultV1_to_dkimSigResultV2(dkimResultV1) {
	/** @type {dkimSigResultV2} */
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
			(w) => {
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
 * Convert AuthResultDKIMV2 to dkimSigResultV2.
 *
 * @param {AuthResultDKIMV2} authResultDKIM
 * @returns {dkimSigResultV2} dkimSigResultV2
 */
function AuthResultDKIMV2_to_dkimSigResultV2(authResultDKIM) {
	/** @type {dkimSigResultV2} */
	const dkimSigResult = authResultDKIM;
	// @ts-expect-error
	dkimSigResult.res_num = undefined;
	// @ts-expect-error
	dkimSigResult.result_str = undefined;
	// @ts-expect-error
	dkimSigResult.warnings_str = undefined;
	// @ts-expect-error
	dkimSigResult.favicon = undefined;
	return dkimSigResult;
}

/**
 * Save authentication result.
 *
 * @param {browser.messages.MessageHeader} message
 * @param {SavedAuthResult|null} savedAuthResult
 * @returns {Promise<void>}
 */
export async function saveAuthResult(message, savedAuthResult) {
	// don't save result if disabled or message is external
	if (!prefs.saveResult || !message.folder) {
		return;
	}

	if (savedAuthResult === null) {
		// reset result
		log.debug("reset AuthResult result");
		await browser.storageMessage.set(message.id, "dkim_verifier@pl-result", "");
	} else if (savedAuthResult.dkim.some(res => res.result === "TEMPFAIL")) {
		// don't save result if DKIM result contains a TEMPFAIL
		log.debug("result not saved because DKIM result is a TEMPFAIL");
	} else {
		log.debug("save AuthResult result");
		await browser.storageMessage.set(message.id, "dkim_verifier@pl-result",
			JSON.stringify(savedAuthResult));
	}
}

/**
 * Get saved authentication result.
 *
 * @param {browser.messages.MessageHeader} message
 * @returns {Promise<SavedAuthResult|null>} savedAuthResult
 */
export async function loadAuthResult(message) {
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

	/** @type {dkimResultV1|AuthResultV2|SavedAuthResultV3} */
	const savedAuthResult = JSON.parse(savedAuthResultJSON);

	const versionMatch = savedAuthResult.version.match(/^[0-9]+/);
	if (!versionMatch) {
		throw new Error("No version found in AuthResult");
	}
	const majorVersion = versionMatch[0];
	if (majorVersion === "1") {
		// old dkimResultV1 (AuthResult version 1)
		/** @type {dkimResultV1} */
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
