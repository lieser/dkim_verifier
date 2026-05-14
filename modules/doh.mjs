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

/** @import {DnsTxtResult} from "./dns.mjs" */

import { PacketFlag, PacketType, RecordType, decode, encode } from "../thirdparty/dns-message/dist/dns-message.mjs";
import { DKIM_TempError } from "./error.mjs.js";
import Logging from "./logging.mjs.js";
import { encodeBase64Url } from "./utils.mjs.js";
import prefs from "./preferences.mjs.js";

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

	const server = prefs["dns.doh.server"];
	let httpResponse;
	try {
		httpResponse = await fetch(`${server}?${params}`, {
			method: "GET",
			headers: {
				Accept: "application/dns-message",
			},
		});
	} catch (error) {
		log.error("Failed to fetch DoH server", error);
		throw new DKIM_TempError("DKIM_DNSERROR_SERVER_ERROR");
	}
	if (!httpResponse.ok) {
		log.error(`DNS server responded with response status: ${httpResponse.status}`);
		throw new DKIM_TempError("DKIM_DNSERROR_UNKNOWN");
	}
	const contentType = httpResponse.headers.get("content-type");
	if (!contentType || !contentType.includes("application/dns-message")) {
		log.error(`DNS server responded with unexpected content type: ${contentType}`);
		throw new DKIM_TempError("DKIM_DNSERROR_UNKNOWN");
	}
	return httpResponse.arrayBuffer();
}

/**
 * @typedef {(query: Uint8Array<ArrayBufferLike>) => Promise<ArrayBuffer>} QueryFunction
 */

/**
 * Perform TXT resolution of the target name.
 *
 * @param {string} name
 * @param {QueryFunction} queryFunction
 * @returns {Promise<DnsTxtResult>}
 * @throws {DKIM_TempError} if no DNS response could be retrieved.
 */
export default async function txt(name, queryFunction = dnsGetQuery) {
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
			if (answer?.type === RecordType.CNAME) {
				// Ignore CNAME records.
				continue;
			}
			if (answer?.type !== RecordType.TXT) {
				log.error(`DNS answer has unexpected type: ${answer?.type}`);
				throw new DKIM_TempError("DKIM_DNSERROR_UNKNOWN");
			}
			txtData.push(answer.data.join(""));
		}
	}

	const flags = flagsDecode(response.flags ?? 0);

	return {
		data: txtData,
		rcode: response.rtype ?? PacketFlag.SERVFAIL,
		secure: flags.AD,
		bogus: false,
	};
}
