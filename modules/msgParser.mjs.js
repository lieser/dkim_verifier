/**
 * Reads and parses a message.
 *
 * Copyright (c) 2014-2023 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check

import RfcParser, { RfcParserI } from "./rfcParser.mjs.js";
import { DKIM_InternalError } from "./error.mjs.js";
import Logging from "./logging.mjs.js";
import { decodeBinaryString } from "./utils.mjs.js";

const log = Logging.getLogger("msgParser");


export default class MsgParser {
	/**
	 * Parse given message into parsed header and body.
	 *
	 * @param {string} rawMsg - binary string
	 * @returns {{headers: Map<string, string[]>, body: string}}
	 * @throws DKIM_InternalError
	 */
	static parseMsg(rawMsg) {
		const newlineLength = 2;

		// convert all EOLs to CRLF
		const msg = rawMsg.replace(/(\r\n|\n|\r)/g, "\r\n");

		// get header end
		const posEndHeader = msg.indexOf("\r\n\r\n");

		// split header and body
		let headerPlain;
		let body;
		if (posEndHeader === -1) {
			if (!msg.endsWith("\r\n")) {
				throw new DKIM_InternalError("Last header is not ending with a newline",
					"DKIM_INTERNALERROR_INCORRECT_EMAIL_FORMAT");
			}
			headerPlain = msg;
			body = "";
		} else {
			headerPlain = msg.substr(0, posEndHeader + newlineLength);
			body = msg.substr(posEndHeader + 2 * newlineLength);
		}

		return {
			headers: MsgParser.parseHeader(headerPlain),
			body,
		};
	}

	/**
	 * Parses the header of a message.
	 *
	 * @param {string} headerPlain - binary string
	 * @returns {Map<string, string[]>}
	 * - key - Header name in lower case.
	 * - value - Array of complete headers, including the header name at the beginning (binary string).
	 */
	static parseHeader(headerPlain) {
		const headerFields = new Map();

		// split header fields
		const headerArray = headerPlain.split(/\r\n(?=\S|$)/);
		// The last newline will result in an empty entry, remove it
		headerArray.pop();

		// store valid fields under header field name (in lower case) in an array
		for (const header of headerArray) {
			const hNameMatch = header.match(/[!-9;-~]+(?=:)/);
			if (hNameMatch !== null && hNameMatch[0]) {
				const hName = hNameMatch[0].toLowerCase();
				if (!headerFields.has(hName)) {
					headerFields.set(hName, []);
				}
				headerFields.get(hName).push(`${header}\r\n`);
			} else {
				throw new DKIM_InternalError("Could not split header into name and value",
					"DKIM_INTERNALERROR_INCORRECT_EMAIL_FORMAT");
			}
		}

		return headerFields;
	}

	/**
	 * Extract the address from a mailbox-list (RFC 5322).
	 *
	 * Note: Will only return the first address of the mailbox-list.
	 * Note: Some obsolete patterns are not supported.
	 * Note: Using a domain-literal as domain is not supported.
	 *
	 * @param {string} headerValue - binary string
	 * @param {boolean} [internationalized] - Enable internationalized support
	 * @returns {string|null}
	 */
	static #tryParseMailboxList(headerValue, internationalized) {
		const parser = internationalized ? RfcParserI : RfcParser;

		const dotAtomC = `(?:${RfcParser.CFWS_op}(${parser.dot_atom_text})${RfcParser.CFWS_op})`;
		const quotedStringC = `(?:${RfcParser.CFWS_op}("(?:${RfcParser.FWS_op}${parser.qcontent})*${RfcParser.FWS_op}")${RfcParser.CFWS_op})`;
		const localPartC = `(?:${dotAtomC}|${quotedStringC})`;
		// Capturing address pattern there
		// 1. Group is the local part as dot-atom-text (can be undefined)
		// 2. Group is the local part as quoted-string (can be undefined)
		// 3. Group is the domain part
		const addrSpecC = `(?:${localPartC}@${dotAtomC})`;

		/**
		 * Join together the local and domain part of the address.
		 *
		 * @param {RegExpMatchArray} regExpMatchArray - binary strings
		 * @returns {string}
		 */
		const joinAddress = (regExpMatchArray) => {
			const localDotAtom = regExpMatchArray[1];
			const localQuotedString = regExpMatchArray[2];
			const domain = regExpMatchArray[3];

			let local = localDotAtom;
			if (local === undefined) {
				local = localQuotedString;
			}
			return decodeBinaryString(`${local}@${domain}`);
		};

		const angleAddrC = `(?:${RfcParser.CFWS_op}<${addrSpecC}>${RfcParser.CFWS_op})`;
		const nameAddrC = `(?:${parser.display_name}?${angleAddrC})`;
		const mailboxC = `(?:${nameAddrC}|${addrSpecC})`;

		// Try to parse as address that is in <> (name-addr)
		let regExpMatch = headerValue.match(new RegExp(`^${nameAddrC}(?:,${mailboxC})*\r\n$`));
		if (regExpMatch !== null) {
			return joinAddress(regExpMatch);
		}

		// Try to parse as address without <> (addr-spec)
		regExpMatch = headerValue.match(new RegExp(`^${addrSpecC}(?:,${mailboxC})*\r\n$`));
		if (regExpMatch !== null) {
			return joinAddress(regExpMatch);
		}

		return null;
	}

	/**
	 * Extract the address from author in Thunderbirds MessageHeader.
	 *
	 * @param {string} author - binary string
	 * @param {boolean} [internationalized] - Enable internationalized support
	 * @returns {string}
	 */
	static parseAuthor(author, internationalized) {
		const from = MsgParser.#tryParseMailboxList(`${author}\r\n`, internationalized);
		if (from === null) {
			throw new Error("From header (author) does not contain an address");
		}
		return from;
	}
	/**
	 * Extract the address from the From header (RFC 5322).
	 *
	 * @param {string} header - binary string
	 * @param {boolean} [internationalized] - Enable internationalized support
	 * @returns {string}
	 */
	static parseFromHeader(header, internationalized) {
		const headerStart = "from:";
		if (!header.toLowerCase().startsWith(headerStart)) {
			throw new Error("Unexpected start of from header");
		}
		const headerValue = header.substr(headerStart.length);

		const from = MsgParser.#tryParseMailboxList(headerValue, internationalized);
		if (from === null) {
			throw new Error("From header does not contain an address");
		}
		return from;
	}

	/**
	 * Extract the address from the Reply-To header (RFC 5322).
	 *
	 * Note: group pattern is not supported.
	 *
	 * @param {string} header - binary string
	 * @param {boolean} [internationalized] - Enable internationalized support
	 * @returns {string}
	 */
	static parseReplyToHeader(header, internationalized) {
		const headerStart = "reply-to:";
		if (!header.toLowerCase().startsWith(headerStart)) {
			throw new Error("Unexpected start of from header");
		}
		const headerValue = header.substr(headerStart.length);

		const replyTo = MsgParser.#tryParseMailboxList(headerValue, internationalized);
		if (replyTo === null) {
			throw new Error("Reply-To header does not contain an address");
		}
		return replyTo;
	}

	/**
	 * Extract the list identifier from the List-Id header (RFC 2919).
	 *
	 * Note: Some obsolete patterns are not supported.
	 *
	 * @param {string} header
	 * @returns {string}
	 */
	static parseListIdHeader(header) {
		const headerStart = "list-id:";
		if (!header.toLowerCase().startsWith(headerStart)) {
			throw new Error("Unexpected start of List-Id header");
		}
		const headerValue = header.substr(headerStart.length);

		const listId = `${RfcParser.dot_atom_text}\\.${RfcParser.dot_atom_text}`;
		// Note: adapted according to Errata ID: 3951
		const regExpMatch = headerValue.match(new RegExp(`^(?:${RfcParser.phrase}|${RfcParser.CFWS})?<(${listId})>\r\n$`));
		if (regExpMatch !== null && regExpMatch[1]) {
			return regExpMatch[1];
		}
		throw new Error("Cannot extract the list identifier from the List-Id header.");
	}

	/**
	 * Tries to extract the date time information from a Received header (RFC 2919).
	 *
	 * @param {string} header
	 * @returns {Date|null}
	 */
	static tryExtractReceivedTime(header) {
		const dateTimeStart = header.lastIndexOf(";");
		if (dateTimeStart === -1) {
			log.warn("Could not find the date time in the Received header");
			return null;
		}
		const dateTimeStr = header.substring(dateTimeStart + 1);
		const dateTime = new Date(dateTimeStr);
		if (dateTime.toString() === "Invalid Date") {
			log.warn("Could not parse the date time in the Received header");
			return null;
		}
		return dateTime;
	}
}
