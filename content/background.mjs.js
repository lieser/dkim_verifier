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
///<reference path="../experiments/dkimHeader.d.ts" />
/* eslint-env browser, webextensions */

import { DKIM_InternalError, DKIM_SigError } from "../modules/error.mjs.js";
import { migratePrefs, migrateSignRulesUser } from "../modules/migration.mjs.js";
import AuthVerifier from "../modules/AuthVerifier.mjs.js";
import DNS from "../modules/dns.mjs.js";
import Logging from "../modules/logging.mjs.js";
import { initSignRulesProxy } from "../modules/dkim/signRules.mjs.js";
import prefs from "../modules/preferences.mjs.js";
import { setKeyFetchFunction } from "../modules/dkim/verifier.mjs.js";

const log = Logging.getLogger("background");

async function init() {
	await Logging.initLogLevelFromPrefs();

	await migratePrefs();
	await prefs.init();

	await migrateSignRulesUser();
	initSignRulesProxy();
}
const isInitialized = init();
isInitialized.catch(error => log.fatal("Initializing failed with:", error));

// eslint-disable-next-line valid-jsdoc
/** @type {import("../modules/dkim/verifier.mjs.js").KeyFetchFunction} */
async function getKey(sdid, selector) {
	const dnsRes = await DNS.txt(`${selector}._domainkey.${sdid}`);
	log.debug("dns result", dnsRes);

	if (dnsRes.bogus) {
		throw new DKIM_InternalError(null, "DKIM_DNSERROR_DNSSEC_BOGUS");
	}
	if (dnsRes.rcode !== DNS.RCODE.NoError && dnsRes.rcode !== DNS.RCODE.NXDomain) {
		log.info("DNS query failed with result:", dnsRes);
		throw new DKIM_InternalError(`rcode: ${dnsRes.rcode}`,
			"DKIM_DNSERROR_SERVER_ERROR");
	}
	if (dnsRes.data === null || dnsRes.data[0] === "") {
		throw new DKIM_SigError("DKIM_SIGERROR_NOKEY");
	}

	if (!dnsRes.data) {
		throw new DKIM_SigError("DKIM_SIGERROR_NOKEY");
	}
	return {
		key: dnsRes.data[0],
		secure: dnsRes.secure,
	};
}

setKeyFetchFunction(getKey);

const SHOW = {
	NEVER: 0,
	DKIM_VALID: 10,
	DKIM_VALID_ALL: 20,
	DKIM_SIGNED: 30,
	EMAIL: 40,
	MSG: 50,
};

// eslint-disable-next-line complexity
browser.messageDisplay.onMessageDisplayed.addListener(async (tab, message) => {
	try {
		await isInitialized;

		// return if msg is RSS feed or news
		const account = await browser.accounts.get(message.folder.accountId);
		if (account && (account.type === "rss" || account.type === "nntp")) {
			browser.dkimHeader.showDkimHeader(tab.id, message.id, prefs.showDKIMHeader >= SHOW.MSG);
			browser.dkimHeader.setDkimHeaderResult(
				tab.id, message.id, browser.i18n.getMessage("NOT_EMAIL"), [], "", {});
			return;
		}

		// If we already know if the header should be shown, trigger it now
		if (prefs.showDKIMHeader >= SHOW.EMAIL) {
			browser.dkimHeader.showDkimHeader(tab.id, message.id, true);
		}
		else {
			const { headers } = await browser.messages.getFull(message.id);
			if (headers && Object.keys(headers).includes("dkim-signature")) {
				if (prefs.showDKIMHeader >= SHOW.DKIM_SIGNED) {
					browser.dkimHeader.showDkimHeader(tab.id, message.id, true);
				}
			}
		}
		// show from tooltip if not completely disabled
		if (prefs.showDKIMFromTooltip > SHOW.NEVER) {
			browser.dkimHeader.showFromTooltip(tab.id, message.id, true);
		}

		const verifier = new AuthVerifier();
		const res = await verifier.verify(message);
		const warnings = res.dkim[0].warnings_str || [];
		/** @type {Parameters<typeof browser.dkimHeader.setDkimHeaderResult>[5]} */
		const arh = {};
		if (res.arh && res.arh.dkim && res.arh.dkim[0]) {
			arh.dkim = res.arh.dkim[0].result_str;
		}
		if (res.spf && res.spf[0]) {
			arh.spf = res.spf[0].result;
		}
		if (res.dmarc && res.dmarc[0]) {
			arh.dmarc = res.dmarc[0].result;
		}

		const messageStillDisplayed = await browser.dkimHeader.setDkimHeaderResult(
			tab.id,
			message.id,
			res.dkim[0].result_str,
			warnings,
			res.dkim[0].favicon ?? "",
			arh
		);
		if (!messageStillDisplayed) {
			log.debug("Showing of DKIM result skipped because message is no longer displayed");
			return;
		}
		browser.dkimHeader.showDkimHeader(tab.id, message.id, prefs.showDKIMHeader >= res.dkim[0].res_num);
		if (prefs.showDKIMFromTooltip > SHOW.NEVER && prefs.showDKIMFromTooltip < res.dkim[0].res_num) {
			browser.dkimHeader.showFromTooltip(tab.id, message.id, false);
		}
		if (prefs.colorFrom) {
			switch (res.dkim[0].res_num) {
				case AuthVerifier.DKIM_RES.SUCCESS: {
					const dkim = res.dkim[0];
					if (!dkim.warnings_str || dkim.warnings_str.length === 0) {
						browser.dkimHeader.highlightFromAddress(tab.id, message.id, prefs["color.success.text"], prefs["color.success.background"]);
					} else {
						browser.dkimHeader.highlightFromAddress(tab.id, message.id, prefs["color.warning.text"], prefs["color.warning.background"]);
					}
					break;
				}
				case AuthVerifier.DKIM_RES.TEMPFAIL:
					browser.dkimHeader.highlightFromAddress(tab.id, message.id, prefs["color.tempfail.text"], prefs["color.tempfail.background"]);
					break;
				case AuthVerifier.DKIM_RES.PERMFAIL:
					browser.dkimHeader.highlightFromAddress(tab.id, message.id, prefs["color.permfail.text"], prefs["color.permfail.background"]);
					break;
				case AuthVerifier.DKIM_RES.PERMFAIL_NOSIG:
				case AuthVerifier.DKIM_RES.NOSIG:
					browser.dkimHeader.highlightFromAddress(tab.id, message.id, prefs["color.nosig.text"], prefs["color.nosig.background"]);
					break;
				default:
					throw new Error(`unknown res_num: ${res.dkim[0].res_num}`);
			}
		}
	} catch (e) {
		log.fatal("Unexpected error during onMessageDisplayed", e);
		browser.dkimHeader.showDkimHeader(tab.id, message.id, true);
		browser.dkimHeader.setDkimHeaderResult(
			tab.id, message.id, browser.i18n.getMessage("DKIM_INTERNALERROR_NAME"), [], "", {});
	}
});
