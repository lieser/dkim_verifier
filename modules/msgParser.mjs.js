/**
 * Reads and parses a message.
 *
 * Copyright (c) 2014-2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check

import { DKIM_InternalError } from "./error.mjs.js";
import Logging from "./logging.mjs.js";
import RfcParser from "./rfcParser.mjs.js";

const log = Logging.getLogger("msgParser");


export default class MsgParser {
	/**
	 * Parse given message into parsed header and body
	 *
	 * @static
	 * @param {string} msg
	 * @return {{headers: Map<string, string[]>, body: string}}
	 * @throws DKIM_InternalError
	 * @memberof MsgParser
	 */
	static parseMsg(msg) {
		let newlineLength = 2;

		// get header end
		let posEndHeader = msg.indexOf("\r\n\r\n");
		// check for LF line ending
		if (posEndHeader === -1) {
			posEndHeader = msg.indexOf("\n\n");
			if (posEndHeader !== -1) {
				newlineLength = 1;
				log.debug("LF line ending detected");
			}
		}
		// check for CR line ending
		if (posEndHeader === -1) {
			posEndHeader = msg.indexOf("\r\r");
			if (posEndHeader !== -1) {
				newlineLength = 1;
				log.debug("CR line ending detected");
			}
		}

		// check that end of header was detected
		if (posEndHeader === -1) {
			throw new DKIM_InternalError("Message is not in correct e-mail format",
				"DKIM_INTERNALERROR_INCORRECT_EMAIL_FORMAT");
		}

		// get header and body
		let headerPlain = msg.substr(0, posEndHeader + newlineLength);
		let body = msg.substr(posEndHeader + 2 * newlineLength);

		// convert all EOLs to CRLF
		headerPlain = headerPlain.replace(/(\r\n|\n|\r)/g, "\r\n");
		body = body.replace(/(\r\n|\n|\r)/g, "\r\n");

		return {
			headers: MsgParser.parseHeader(headerPlain),
			body: body,
		};
	}

	/**
	 * Parses the header of a message.
	 *
	 * @static
	 * @param {String} headerPlain
	 * @return {Map<string, string[]>}
	 *          key - header name in lower case
	 *          value - array of complete headers, including the header name at the beginning
	 * @memberof MsgParser
	 */
	static parseHeader(headerPlain) {
		const headerFields = new Map();

		// split header fields
		const headerArray = headerPlain.split(/\r\n(?=\S|$)/);

		// store valid fields under header field name (in lower case) in an array
		for (let i = 0; i < headerArray.length; i++) {
			const hNameMatch = headerArray[i].match(/[!-9;-~]+(?=:)/);
			if (hNameMatch !== null) {
				const hName = hNameMatch[0].toLowerCase();
				if (!headerFields.has(hName)) {
					headerFields.set(hName, []);
				}
				headerFields.get(hName).push(`${headerArray[i]}\r\n`);
			}
		}

		return headerFields;
	}

	/**
	 * Extract the address from the From header (RFC 5322).
	 *
	 * Note: The RFC also allows a list of addresses (mailbox-list).
	 * This is currently not supported, and will throw a parsing error.
	 * Note: Some obsolete patterns are not supported.
	 * Note: Using a domain-literal as domain is not supported.
	 *
	 * @static
	 * @param {string} header
	 * @returns {string}
	 * @memberof MsgParser
	 */
	static parseFromHeader(header) {
		const headerStart = "from:";
		if (!header.toLowerCase().startsWith(headerStart)) {
			throw new Error("Unexpected start of from header");
		}
		const headerValue = header.substr(headerStart.length);

		const dotAtomC = `(?:${RfcParser.CFWS_op}(${RfcParser.dot_atom_text})${RfcParser.CFWS_op})`;
		const quotedStringC = `(?:${RfcParser.CFWS_op}("(?:${RfcParser.FWS_op}${RfcParser.qcontent})*${RfcParser.FWS_op}")${RfcParser.CFWS_op})`;
		const localPartC = `(?:${dotAtomC}|${quotedStringC})`;
		// Capturing address pattern there
		// 1. Group is the local part as dot-atom-text (can be undefined)
		// 2. Group is the local part as quoted-string (can be undefined)
		// 3. Group is the domain part
		const addrSpecC = `(?:${localPartC}@${dotAtomC})`;

		/**
		 * Join together the local and domain part of the address.
		 *
		 * @param {RegExpMatchArray} regExpMatchArray
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
			return `${local}@${domain}`;
		};

		// Try to parse as address that is in <> (name-addr)
		const angleAddrC = `(?:${RfcParser.CFWS_op}<${addrSpecC}>${RfcParser.CFWS_op})`;
		const nameAddrC = `(?:${RfcParser.display_name}?${angleAddrC})`;
		let regExpMatch = headerValue.match(new RegExp(`^${nameAddrC}\r\n$`));
		if (regExpMatch !== null) {
			return joinAddress(regExpMatch);
		}

		// Try to parse as address without <> (addr-spec)
		regExpMatch = headerValue.match(new RegExp(`^${addrSpecC}\r\n$`));
		if (regExpMatch !== null) {
			return joinAddress(regExpMatch);
		}

		throw new Error("From header does not contain an address");
	}

	/**
	 * Extract the list identifier from the List-Id header (RFC 2919).
	 *
	 * Note: Some obsolete patterns are not supported.
	 *
	 * @static
	 * @param {string} header
	 * @returns {string}
	 * @memberof MsgParser
	 */
	static parseListIdHeader(header) {
		const headerStart = "list-id:";
		if (!header.toLowerCase().startsWith(headerStart)) {
			throw new Error("Unexpected start of List-Id header");
		}
		const headerValue = header.substr(headerStart.length);

		const listId = `${RfcParser.dot_atom_text}.(?:${RfcParser.dot_atom_text}`;
		// Note: adapted according to Errata ID: 3951
		const regExpMatch = headerValue.match(new RegExp(`^(?:${RfcParser.phrase}|${RfcParser.CFWS})?<(${listId}))>\r\n$`));
		if (regExpMatch !== null) {
			return regExpMatch[1];
		}
		throw new Error("Cannot extract the list identifier from the List-Id header.");
	}
}
