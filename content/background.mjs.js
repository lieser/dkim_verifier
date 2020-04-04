/**
 * Copyright (c) 2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="../WebExtensions.d.ts" />

/* eslint-env browser, webextensions */

import { DKIM_InternalError, DKIM_SigError } from "../modules/error.mjs.js";
import AuthVerifier from "../modules/AuthVerifier.mjs.js";
import Logging from "../modules/logging.mjs.js";
import { setKeyFetchFunction } from "../modules/dkim/verifier.mjs.js";

Logging.setLogLevel(Logging.Level.Debug);
const log = Logging.getLogger("background");

async function getKey(sdid, selector) {
	const RCODE = {
		NoError: 0, // No Error [RFC1035]
		FormErr: 1, // Format Error [RFC1035]
		ServFail: 2, // Server Failure [RFC1035]
		NXDomain: 3, // Non-Existent Domain [RFC1035]
		NotImp: 4, // Non-Existent Domain [RFC1035]
		Refused: 5, // Query Refused [RFC1035]
	};

	const dnsRes = await browser.jsdns.txt(`${selector}._domainkey.${sdid}`);


	if (dnsRes.bogus) {
		throw new DKIM_InternalError(null, "DKIM_DNSERROR_DNSSEC_BOGUS");
	}
	if (dnsRes.rcode !== RCODE.NoError && dnsRes.rcode !== RCODE.NXDomain) {
		log.info("DNS query failed with result:", dnsRes);
		throw new DKIM_InternalError(`rcode: ${dnsRes.rcode}`,
			"DKIM_DNSERROR_SERVER_ERROR");
	}
	if (dnsRes.data === null || dnsRes.data[0] === "") {
		throw new DKIM_SigError("DKIM_SIGERROR_NOKEY");
	}
	console.log("dd");


	if (!dnsRes.data) {
		throw new DKIM_SigError("DKIM_SIGERROR_NOKEY");
	}
	return {
		key: dnsRes.data[0],
		secure: false,
	};
}

setKeyFetchFunction(getKey);

browser.messageDisplay.onMessageDisplayed.addListener(async (tabId, message) => {
	const rawMessage = await browser.messages.getRaw(message.id);
	const verifier = new AuthVerifier();
	const res = await verifier.verify(rawMessage);
	const warnings = res.dkim[0].warnings_str || [];
	await browser.dkimHeader.setDkimHeaderResult(tabId, res.dkim[0].result_str, warnings);
});
