/**
 * DNS Queries over HTTPS (DoH) according to RFC 8484
 * https://datatracker.ietf.org/doc/html/rfc8484
 *
 * Copyright (c) 2026 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-disable no-magic-numbers */

// options for ESLint
/* global Components, Services, URLSearchParams */
/* global Logging, encodeBase64Url, encode, decode, PacketType, PacketFlag, RecordType, DKIM_TempError */
/* exported EXPORTED_SYMBOLS, DoH */

/** @import {DNSResult} from "./dnsWrapper.mjs" */

"use strict";
var EXPORTED_SYMBOLS = [
	"DoH"
];

// @ts-expect-error
const Cu = Components.utils;

Cu.import("resource://gre/modules/Services.jsm");

Cu.import("resource://dkim_verifier_3p/dns-message/dist/dns-message.jsm.js");
Cu.import("resource://dkim_verifier/helper.jsm.js");
Cu.import("resource://dkim_verifier/logging.jsm.js");

// @ts-expect-error
const PREF_BRANCH = "extensions.dkim_verifier.dns.";
// @ts-expect-error
var prefs = Services.prefs.getBranch(PREF_BRANCH);

const log = Logging.getLogger("dns");

/**
 * The part the DNS header containing the flags and codes (third and fourth byte).
 *
 * @typedef {object} DnsHeaderFlagsAndCodes
 * @property {boolean} QR
 * @property {number} Opcode
 * @property {boolean} AA
 * @property {boolean} TC
 * @property {boolean} RD
 * @property {boolean} RA
 * @property {boolean} Z
 * @property {boolean} AD
 * @property {boolean} CD
 * @property {number} RCODE
 */

/**
 * Decode DNS flags and codes.
 *
 * See the following for the flags definition:
 * - <https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1>.
 * - <https://datatracker.ietf.org/doc/html/rfc2065#section-6.1>.
 *
 * @param {number} flags - The two bytes of flags as a big endian number.
 * @returns {DnsHeaderFlagsAndCodes}
 */
function flagsDecode(flags) {
	return {
		QR: ((flags >> 15) & 0x1) === 1,
		Opcode: (flags >> 11) & 0x7,
		AA: ((flags >> 10) & 0x1) === 1,
		TC: ((flags >> 9) & 0x1) === 1,
		RD: ((flags >> 8) & 0x1) === 1,
		RA: ((flags >> 7) & 0x1) === 1,
		Z: ((flags >> 6) & 0x1) === 1,
		AD: ((flags >> 5) & 0x1) === 1,
		CD: ((flags >> 4) & 0x1) === 1,
		RCODE: flags & 0xF,
	};
}

/**
 * Query a DoH server using the using the GET method.
 *
 * @param {Uint8Array} query - Encoded DNS query.
 * @returns {Promise<ArrayBuffer>} Encoded DNS response.
 */
async function dnsGetQuery(query) {
	const params = new URLSearchParams();
	// RFC 8484 section 6:
	// When using the GET method, the data payload for this media type MUST
	// be encoded with base64url [RFC4648] and then provided as a variable
	// named "dns" to the URI Template expansion. Padding characters for
	// base64url MUST NOT be included.
	params.append("dns", encodeBase64Url(query, true));
	const server = prefs.getCharPref("doh.server");
	let httpResponse;
	try {
		httpResponse = await new Promise(function (resolve, reject) {
			const XMLHttpRequest  = Components.Constructor("@mozilla.org/xmlextras/xmlhttprequest;1", "nsIXMLHttpRequest");
			let xhr = new XMLHttpRequest();
			xhr.responseType = "arraybuffer";
			xhr.open("GET", `${server}?${params}`);
			xhr.onload = function () {
				if (this.status >= 200 && this.status < 300) {
					resolve({
						status: this.status,
						contentType: this.getResponseHeader('content-type'),
						result: this.response
					});
				} else {
					// eslint-disable-next-line prefer-promise-reject-errors
					reject({
						status: this.status,
						statusText: this.statusText
					});
				}
			};
			xhr.onerror = function () {
				// eslint-disable-next-line prefer-promise-reject-errors
				reject({
					status: this.status,
					statusText: this.statusText
				});
			};
			xhr.send();
		});
	} catch (error) {
		log.error("Failed to fetch DoH server", error);
		throw new DKIM_TempError("DKIM_DNSERROR_SERVER_ERROR");
	}
	if (httpResponse.status < 200 || httpResponse.status >= 300) {
		log.error(`DNS server responded with response status: ${httpResponse.statusText} (${httpResponse.status})`);
		throw new DKIM_TempError("DKIM_DNSERROR_UNKNOWN");
	}
	if (!httpResponse.contentType || !httpResponse.contentType.includes("application/dns-message")) {
		log.error(`DNS server responded with unexpected content type: ${httpResponse.contentType}`);
		throw new DKIM_TempError("DKIM_DNSERROR_UNKNOWN");
	}
	return httpResponse.result;
}

/**
 * @typedef {(query: Uint8Array<ArrayBufferLike>) => Promise<ArrayBuffer>} QueryFunction
 */

/**
 * Perform TXT resolution of the target name.
 *
 * @param {string} name
 * @param {QueryFunction} queryFunction
 * @returns {Promise<DNSResult>}
 * @throws {DKIM_TempError} if no DNS response could be retrieved.
 */
async function txt(name, queryFunction = dnsGetQuery) {
	const query = encode({
		// RFC 8484 section 4.1 - DoH clients [...] SHOULD use a DNS ID of 0 in every DNS request.
		id: 0,
		type: PacketType.QUERY,
		flags: PacketFlag.RECURSION_DESIRED | PacketFlag.AUTHENTIC_DATA,
		questions: [{
			name,
			type: RecordType.TXT,
		}],
	});
	const encodedResponse = await queryFunction(query);
	const response = decode(encodedResponse);

	if (response.type !== PacketType.RESPONSE) {
		log.error(`DNS server responded with unexpected packet type: ${response.type}`);
		throw new DKIM_TempError("DKIM_DNSERROR_UNKNOWN");
	}

	let txtData = null;
	if (response.answers) {
		txtData = [];
		for (const answer of response.answers) {
			if (answer && answer.type === RecordType.CNAME) {
				// Ignore CNAME records.
				continue;
			}
			if (answer && answer.type !== RecordType.TXT) {
				log.error(`DNS answer has unexpected type: ${answer.type}`);
				throw new DKIM_TempError("DKIM_DNSERROR_UNKNOWN");
			}
			txtData.push(answer.data.join(""));
		}
	}

	const flags = flagsDecode(response.flags !== undefined ? response.flags : 0);

	return {
		data: txtData,
		rcode: response.rtype !== undefined ? response.rtype : PacketFlag.SERVFAIL,
		secure: flags.AD,
		bogus: false,
	};
}

var DoH = {}
DoH.resolve = txt;