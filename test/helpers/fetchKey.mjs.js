/**
 * Copyright (c) 2020-2021 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check

import DNS from "../../modules/dns.mjs.js";
import KeyStore from "../../modules/dkim/keyStore.mjs.js";
import { setKeyFetchFunction } from "../../modules/dkim/verifier.mjs.js";

/** @type {Object.<string, string|undefined>} */
const txtRecords = {
	"brisbane._domainkey.example.com": "v=DKIM1; p=" +
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkM" +
		"oGeLnQg1fWn7/zYtIxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/R" +
		"tdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToI" +
		"MmPSPDdQPNUYckcQ2QIDAQAB",
	"_dmarc.paypal.com": "v=DMARC1; p=reject; rua=mailto:d@rua.agari.com; ruf=mailto:d@ruf.agari.com",
};

/** @type {import("../../modules/dkim/keyStore.mjs.js").queryDnsTxtCallback} */
// eslint-disable-next-line require-await
export async function queryDnsTxt(name) {
	const record = txtRecords[name];
	if (!record) {
		return {
			data: null,
			rcode: DNS.RCODE.NXDomain,
			secure: false,
			bogus: false,
		};
	}
	return {
		data: [record],
		rcode: DNS.RCODE.NoError,
		secure: false,
		bogus: false,
	};
}

const keyStore = new KeyStore(queryDnsTxt);
setKeyFetchFunction((...args) => keyStore.fetchKey(...args));
