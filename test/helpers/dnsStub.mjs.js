/**
 * Copyright (c) 2020-2021 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="../../modules/dns.d.ts" />

import DNS from "../../modules/dns.mjs.js";

/** @type {Map.<string, string>} */
const txtRecords = new Map([
	["brisbane._domainkey.example.com", "v=DKIM1; p=" +
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkM" +
		"oGeLnQg1fWn7/zYtIxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/R" +
		"tdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToI" +
		"MmPSPDdQPNUYckcQ2QIDAQAB"],
	["_dmarc.paypal.com", "v=DMARC1; p=reject; rua=mailto:d@rua.agari.com; ruf=mailto:d@ruf.agari.com"],
]);

/**
 * @typedef {import("../../modules/dns.mjs.js").DnsTxtResult} DnsTxtResult
 */

/**
 * @param {Map<string, string>} entries
 * @param {string} name
 * @returns {Promise<DnsTxtResult>}
 */
function txtQuery(entries, name) {
	const entry = entries.get(name);
	if (entry !== undefined) {
		return Promise.resolve({
			rcode: DNS.RCODE.NoError,
			data: [entry],
			secure: false,
			bogus: false,
		});
	}
	return Promise.resolve({
		rcode: DNS.RCODE.NXDomain,
		data: null,
		secure: false,
		bogus: false,
	});
}

/**
 * Create a TXT DNS callback that resolves the given entries.
 *
 * @param {Map<string, string>} entries
 * @returns {queryDnsTxtCallback}
 */
export function createTxtQueryCallback(entries) {
	return name => {
		return txtQuery(entries, name);
	};
}

/**
 * A TXT DNS callback that resolves a default set of test entries.
 *
 * @param {string} name
 * @returns {Promise<DnsTxtResult>}
 */
export function queryDnsTxt(name) {
	return txtQuery(txtRecords, name);
}
