/**
 * Brand Indicators for Message Identification (BIMI).
 * https://datatracker.ietf.org/doc/draft-brand-indicators-for-message-identification/04/
 *
 * BIMI implementation for a Mail User Agent (MUA).
 * Gets the BIMI Indicator based on the information the receiving
 * Mail Transfer Agent (MTA) writes into the headers of the message.
 *
 * This is not a complete implementation of BIMI.
 *
 * Copyright (c) 2023 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check

import Logging from "./logging.mjs.js";
import RfcParser from "./rfcParser.mjs.js";

const log = Logging.getLogger("BIMI");


/**
 * Try to get the BIMI Indicator if available.
 *
 * @param {Map<string, string[]>} headers
 * @param {import("./arhParser.mjs.js").ArhResInfo[]} arhBIMI - Trusted ARHs containing a BIMI result.
 * @returns {string|null}
 */
export function getBimiIndicator(headers, arhBIMI) {
	// Assuming:
	// 1. We only get ARHs that can be trusted (i.e. from the receiving MTA).
	// 2. If the receiving MTA does not supports BIMI,
	//    we will not see an ARH with a BIMI result (because of 1)
	// 3. If the receiving MTA supports BIMI,
	//    it will make sure we only see his BIMI-Indicator headers (as required by the RFC).
	//
	// Given the above, it should be safe to trust the BIMI indicator from the BIMI-Indicator header
	// if we have a passing BIMI result there the MTA claims to have checked the Authority Evidence.
	const hasAuthorityPassBIMI = arhBIMI.some(
		arh => arh.method === "bimi" &&
			arh.result === "pass" &&
			arh.propertys.policy.authority === "pass"
	);
	if (!hasAuthorityPassBIMI) {
		return null;
	}

	const bimiIndicators = headers.get("bimi-indicator") ?? [];
	if (bimiIndicators.length > 1) {
		log.warn("Message contains more than one BIMI-Indicator header");
		return null;
	}
	let bimiIndicator = bimiIndicators[0];
	if (!bimiIndicator) {
		log.warn("Message contains an ARH with passing BIMI but does not have a BIMI-Indicator header");
		return null;
	}

	// TODO: If in the future we support ARC we might want to check the policy.indicator-hash

	// Remove header name and new line at end
	bimiIndicator = bimiIndicator.slice("bimi-indicator:".length, -"\r\n".length);
	// Remove all whitespace
	bimiIndicator = bimiIndicator.replace(new RegExp(`${RfcParser.FWS}`, "g"), "");

	return bimiIndicator;
}
