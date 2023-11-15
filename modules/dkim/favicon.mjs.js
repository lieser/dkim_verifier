/**
 * Copyright (c) 2020-2022 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-env webextensions */

import { addrIsInDomain, domainIsInDomain } from "../utils.mjs.js";
import ExtensionUtils from "../extensionUtils.mjs.js";

/** @type {{[x: string]: string|undefined}} */
let favicons;

/**
 * Get the URL to the favicon of the sdid, if available.
 *
 * @param {string} sdid
 * @param {string|undefined} auid
 * @param {string?} from
 * @returns {Promise<string|undefined>} url to favicon
 */
export async function getFavicon(sdid, auid, from) {
	if (!favicons) {
		const faviconsStr = await ExtensionUtils.readFile("data/favicon.json");
		// eslint-disable-next-line require-atomic-updates
		favicons = JSON.parse(faviconsStr);
	}

	// Check if enabled for SDID.
	let url = favicons[sdid.toLowerCase()];
	if (!url) {
		// Check if enabled for the base domain of the SDID.
		const baseDomain = Object.keys(favicons).find(domain => domainIsInDomain(sdid, domain));
		if (baseDomain) {
			url = favicons[baseDomain];
		}
	}
	if (!url) {
		// Check if enabled for AUID.
		if (auid) {
			url = favicons[auid.toLowerCase()];
		}
	}
	if (!url) {
		// Check if enabled for from.
		if (from && addrIsInDomain(from, sdid)) {
			url = favicons[from.toLowerCase()];
		}
	}

	if (url) {
		url = browser.runtime.getURL(`data/favicon/${url}`);
	}

	return url;
}
