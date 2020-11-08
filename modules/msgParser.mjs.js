/*
 * msgParser.mjs.js
 *
 * Reads and parses a message.
 *
 * Version: 3.0.0 (23 February 2020)
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
	 * Extract the first address from a header which matches the RFC 5322 address-list production.
	 * Must be called with the header value only.
	 *
	 * @static
	 * @param {string} header
	 * @returns {string}
	 * @memberof MsgParser
	 */
	static parseAddressingHeader(header) {
		// TODO: improve extraction of address
		const mail = `${RfcParser.dot_atom_text}@(${RfcParser.domain_name})`;
		let regExpMatch = header.match(new RegExp(`<(${mail})>`));
		if (regExpMatch !== null) {
			return regExpMatch[1];
		}
		regExpMatch = header.trim().match(new RegExp(`^(${mail})$`));
		if (regExpMatch !== null) {
			return regExpMatch[1];
		}
		throw new Error("header does not contain an address");
	}

	/**
	 * Extract the first address from the From header.
	 *
	 * @static
	 * @param {string} header
	 * @returns {string}
	 * @memberof MsgParser
	 */
	static parseFromHeader(header) {
		const headerStart = "from: ";
		if (!header.toLowerCase().startsWith(headerStart)) {
			throw new Error("Unexpected start of from header");
		}
		return this.parseAddressingHeader(header.substr(headerStart.length));
	}

	/**
	 * Extract the list identifier from the List-Id header (RFC 2919).
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
		// TODO: Currently simply tries to ignore the optional leading phrase.
		// This can lead to the wrong list identifier being returned.
		const regExpMatch = header.match(new RegExp(`<(${RfcParser.dot_atom_text}.(?:${RfcParser.dot_atom_text}))>`));
		if (regExpMatch !== null) {
			return regExpMatch[1];
		}
		throw new Error("Cannot extract the list identifier from the List-Id header.");
	}
}
