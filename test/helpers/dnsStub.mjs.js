/**
 * Copyright (c) 2020-2022;2025 Philippe Lieser
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
	// RFC 6376 Appendix A Example
	["brisbane._domainkey.example.com", "v=DKIM1; p=" +
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkM" +
		"oGeLnQg1fWn7/zYtIxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/R" +
		"tdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToI" +
		"MmPSPDdQPNUYckcQ2QIDAQAB"],

	// RFC 8463 Appendix A Example
	["brisbane._domainkey.football.example.com", "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="],
	["test._domainkey.football.example.com",
		"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWR" +
		"iGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutAC" +
		"DfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3" +
		"Ip3G+2kryOTIKT+l/K4w3QIDAQAB"],

	// The following DKIM key use the same RSA key as in RFC 6376
	// AUID MUST NOT be a subdomain of SDID
	["s.flags._domainkey.example.com", "v=DKIM1; t=s; p=" +
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkM" +
		"oGeLnQg1fWn7/zYtIxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/R" +
		"tdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToI" +
		"MmPSPDdQPNUYckcQ2QIDAQAB"],

	["_dmarc.paypal.com", "v=DMARC1; p=reject; rua=mailto:d@rua.agari.com; ruf=mailto:d@ruf.agari.com"],

	// Real world examples
	["yg4mwqurec7fkhzutopddd3ytuaqrvuz._domainkey.amazon.com", "p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5bK96ORNNFosbAaVNZU/gVzhANHyd00o1O7qbEeMNLKPNpS8/TYwdlrVnQ7JtJHjIR9EPj61jgtS604XpAltDMYvic2I40AaKgSfr4dDlRcALRtlVqmG7U5MdLiMyabxXPl2s/oqkevALySg0sr/defHC+qAhmdot9Ii/ZQ3YcQIDAQAB"],
	["v2._domainkey.newsletters.cnn.com", "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqd2EItai1ml2NEcqHw2LVvPcAk47vsawT1VefsguODwAiEMVwZxICrfqRlaZ7HC//r42raw9ZOCk48ymgvsR9vLVXEHcBL0cHiOi1AS57GUNcMzBd3SqxSJTQbt5RWfqas4p2mf2PAcvI/pmCCGJg+8zPimNnFZrarZyuUZCdzI7N6pp3TJVXpfDyNEKa1S/wl8W1tufjkwr8As8LQgoxw7/zQyMOm1fyFyxmPh+wd1dMHOBG7a1vV/UvH8QA8ou7BINPUcmGctdCglGtXme4FONjp4jJYCfGGoxicydIKXlgUyaLIT52mhnGYmfaXQyq7ZscvXD3ygIKmTY6a+mvwIDAQAB"],
	["v2._domainkey.emailalerts.cnn.com", "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2c1CEPSZ2BZXPmjt//RXAU/DVIV6gouJ399kcM4oOhwLj1z1fsETHU1uXTTbdyAKBqkI0LXC1Po2f1PtPxomkUwZ39SxDpvHgmzXp0+6O/XHeu9nZtx3YXsIEN65ELqAqN4aKDrM5Dhgs/5ZJibU6YtUfqm2CbRaVQ/9Mj07gEOYXYqSkwtQcqGf1Mxq2Q3y90L7MghdavHCpz/vtvcQCBu9oZhc6thHr4+maPJghNCLDJkQRQpjMqX7oZii9oXtAAbwuSjuIauEWQqVEmSxFekXgbVMOSgBnLwlzBL5/RH/CwaZf2//GqDlMK7EgSNRY+5nyUJjbjpfu5Iy1T12rwIDAQAB"],
	["fm3._domainkey.fastmail.com", "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr2KQLQU8JamLSgEKT5oooh+WmyLrLJZzR4IaNqrIiBin3rCHH3wJfWck95fJQ+MXoWnMOSTon24DxD4Pfkit5ugZvcrO8BH06F9HNcGhqEBhNtarD0rsyOfc+6YDZEGXA0WiiW6z2oIEz6aGtVotp8mRY77GY2uM8Ke5wz27ZDb3BMjNkTOxrNquIrvOfXdLCY81mPtRpEKQA3GLL1Qa4uFLvXgT3VEZApthFW2rBywSCJnKCn6fPveK3iraeTqFh0Ye3BLEGPGzfNPg5QadOPt8RrCVQ0/kF47sMg1lHkT2MrGPTCOTxcfPJKkKzHo7/XF3bqAWk6wxqK5Jq0NmIQIDAQAB"],
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
