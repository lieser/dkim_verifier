/**
 * Copyright (c) 2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="../../WebExtensions.d.ts" />
/* eslint-env webextensions */

import ExtensionUtils from "../extensionUtils.mjs.js";
import { domainIsInDomain } from "../utils.mjs.js";

/** @type {Object.<string, string|undefined>} */
let favicons;

/**
 * Get the URL to the favicon of the sdid, if available.
 *
 * @param {String} sdid
 * @return {Promise<String|undefined>} url to favicon
 */
export async function getFavicon(sdid) {
	if (!favicons) {
		const faviconsStr = await ExtensionUtils.readFile("data/favicon.json");
		// eslint-disable-next-line require-atomic-updates
		favicons = JSON.parse(faviconsStr);
	}

	let url = favicons[sdid];
	if (!url) {
		const baseDomain = Object.keys(favicons).find(domain => domainIsInDomain(sdid, domain));
		if (baseDomain) {
			url = favicons[baseDomain];
		}
	}

	if (url) {
		url = browser.runtime.getURL(`data/favicon/${url}`);
	}

	return url;
}
