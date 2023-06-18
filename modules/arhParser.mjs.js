/**
 * Parser for the Authentication-Results header as specified in RFC 7601/8601.
 *
 * Internationalized Email support (RFC 8601) is incomplete:
 * - IDNA A-labels and U-labels are not verified to be valid.
 * - A-labels are not converted into U-labels (e.g. to compare "authserv-id")
 *
 * Email Authentication Parameters:
 * https://www.iana.org/assignments/email-auth/email-auth.xhtml
 *
 * Copyright (c) 2014-2023 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-disable camelcase */
/* eslint-disable no-use-before-define */

import RfcParser, { RfcParserI } from "./rfcParser.mjs.js";
import Logging from "./logging.mjs.js";
import { decodeBinaryString } from "./utils.mjs.js";

const log = Logging.getLogger("ArhParser");


class Token {
	/**
	 * "Keyword" as specified in Section 4.1.2 of RFC 5321 [SMTP].
	 *
	 * @readonly
	 */
	static Keyword = RfcParser.Keyword;

	/**
	 * @param {boolean} internationalized
	 */
	constructor(internationalized) {
		const parser = internationalized ? RfcParserI : RfcParser;

		/**
		 * "CFWS" as specified in Section 3.2.2 of RFC 5322 [MAIL].
		 *
		 * @readonly
		 */
		this.CFWS = RfcParserI.CFWS;
		/**
		 * Optional "CFWS" as specified in Section 3.2.2 of RFC 5322 [MAIL].
		 *
		 * @readonly
		 */
		this.CFWS_op = RfcParserI.CFWS_op;

		/**
		 * "quoted-string" as specified in Section 3.2.4 of RFC 5322.
		 * Capturing.
		 *
		 * @readonly
		 */
		this.quoted_string_cp = `(?:${RfcParser.CFWS_op}"((?:${RfcParser.FWS_op}${parser.qcontent})*)${RfcParser.FWS_op}"${RfcParser.CFWS_op})`;

		/**
		 * "local-part" as specified in Section 3.4.1 of RFC 5322.
		 *
		 * @readonly
		 */
		this.local_part = parser.local_part;

		/**
		 * "value" as specified in Section 5.1 of RFC 2045.
		 * Capturing.
		 *
		 * @readonly
		 */
		this.value_cp = `(?:(${RfcParser.token})|${this.quoted_string_cp})`;

		/**
		 * "domain-name" as specified in Section 3.5 of RFC 6376 [DKIM].
		 *
		 * @readonly
		 */
		this.domain_name = parser.domain_name;
	}
}

/**
 * @typedef {object} ArhHeader
 * @property {string} authserv_id
 * @property {number} authres_version
 * @property {ArhResInfo[]} resinfo
 */

/**
 * @typedef {{[x: string]: string|undefined}} ArhProperty
 */
/**
 * @typedef {{[x: string]: ArhProperty|undefined, smtp: ArhProperty, header: ArhProperty, body: ArhProperty, policy: ArhProperty }} ArhProperties
 */

/**
 * @typedef {object} ArhResInfo
 * @property {string} method
 * @property {number} method_version
 * @property {string} result
 * none|pass|fail|softfail|policy|neutral|temperror|permerror
 * @property {string} [reason]
 * @property {ArhProperties} propertys
 */

export default class ArhParser {
	/**
	 * Parses an Authentication-Results header.
	 *
	 * @param {string} authResHeader - Authentication-Results header
	 * @param {boolean} [relaxedParsing] - Enable relaxed parsing
	 * @param {boolean} [internationalized] - Enable internationalized support
	 * @returns {ArhHeader} Parsed Authentication-Results header
	 */
	static parse(authResHeader, relaxedParsing = false, internationalized = false) {
		const token = new Token(internationalized);

		// remove header name
		const authResHeaderRef = new RefString(authResHeader.replace(
			new RegExp(`^Authentication-Results:${token.CFWS_op}`, "i"), ""));

		/** @type {ArhHeader} */
		const res = {};
		res.resinfo = [];
		let reg_match;

		// get authserv-id and authres-version
		reg_match = match(authResHeaderRef, `${token.value_cp}(?:${token.CFWS}([0-9]+)${token.CFWS_op})?`, token);
		const authserv_id = reg_match[1] ?? reg_match[2];
		if (!authserv_id) {
			throw new Error("Error matching the ARH authserv-id.");
		}
		res.authserv_id = decodeBinaryString(authserv_id);
		if (reg_match[3]) {
			res.authres_version = parseInt(reg_match[3], 10);
		} else {
			res.authres_version = 1;
		}

		// check if message authentication was performed
		reg_match = match_o(authResHeaderRef, `;${token.CFWS_op}?none`, token);
		if (reg_match !== null) {
			log.debug("no-result");
			return res;
		}

		// get the resinfos
		while (authResHeaderRef.value !== "") {
			const arhResInfo = parseResInfo(authResHeaderRef, relaxedParsing, token);
			if (arhResInfo) {
				res.resinfo.push(arhResInfo);
			}
		}

		return res;
	}
}

/**
 * Parses the next resinfo in str. The parsed part of str is removed from str.
 *
 * @param {RefString} str
 * @param {boolean} relaxedParsing - Enable relaxed parsing
 * @param {Token} token - Token to use for parsing; depends on internationalized support
 * @returns {ArhResInfo|null} Parsed resinfo
 */
function parseResInfo(str, relaxedParsing, token) {
	let reg_match;
	/** @type {ArhResInfo} */
	const res = {};

	// get methodspec
	const method_version_p = `${token.CFWS_op}/${token.CFWS_op}([0-9]+)`;
	const method_p = `(${Token.Keyword})(?:${method_version_p})?`;
	let Keyword_result_p = "none|pass|fail|softfail|policy|neutral|temperror|permerror";
	// older SPF specs (e.g. RFC 4408) use mixed case
	Keyword_result_p += "|None|Pass|Fail|SoftFail|Neutral|TempError|PermError";
	const result_p = `=${token.CFWS_op}(${Keyword_result_p})`;
	const methodspec_p = `;${token.CFWS_op}${method_p}${token.CFWS_op}${result_p}`;
	try {
		reg_match = match(str, methodspec_p, token);
	} catch (exception) {
		if (relaxedParsing) {
			// allow trailing ";" at the end
			match_o(str, ";", token);
			if (str.value.trim() === "") {
				str.value = "";
				return null;
			}
		}
		throw exception;
	}
	if (!reg_match[1]) {
		throw new Error("Error matching the ARH method.");
	}
	if (!reg_match[3]) {
		throw new Error("Error matching the ARH result.");
	}
	res.method = reg_match[1];
	if (reg_match[2]) {
		res.method_version = parseInt(reg_match[2], 10);
	} else {
		res.method_version = 1;
	}
	res.result = reg_match[3].toLowerCase();

	// get reasonspec (optional)
	const reasonspec_p = `reason${token.CFWS_op}=${token.CFWS_op}${token.value_cp}`;
	reg_match = match_o(str, reasonspec_p, token);
	if (reg_match !== null) {
		const value = reg_match[1] || reg_match[2];
		if (!value) {
			throw new Error(`Error matching the ARH reason value for "${res.method}".`);
		}
		res.reason = decodeBinaryString(value);
	}

	// get propspec (optional)
	let pvalue_p = `${token.value_cp}|((?:${token.local_part}?@)?${token.domain_name})`;
	if (relaxedParsing) {
		// allow "/" in the header.b (or other) property, even if it is not in a quoted-string
		pvalue_p += "|([^ \\x00-\\x1F\\x7F()<>@,;:\\\\\"[\\]?=]+)";
	}
	const special_smtp_verb_p = "mailfrom|rcptto";
	const property_p = `${special_smtp_verb_p}|${Token.Keyword}`;
	const propspec_p = `(${Token.Keyword})${token.CFWS_op}\\.${token.CFWS_op}(${property_p})${token.CFWS_op}=${token.CFWS_op}(?:${pvalue_p})`;
	res.propertys = {};
	res.propertys.smtp = {};
	res.propertys.header = {};
	res.propertys.body = {};
	res.propertys.policy = {};
	while ((reg_match = match_o(str, propspec_p, token)) !== null) {
		if (!reg_match[1]) {
			throw new Error("Error matching the ARH property name.");
		}
		if (!reg_match[2]) {
			throw new Error("Error matching the ARH property sub-name.");
		}
		let property = res.propertys[reg_match[1]];
		if (!property) {
			property = {};
			res.propertys[reg_match[1]] = property;
		}
		const value = reg_match[3] ?? reg_match[4] ?? reg_match[5] ?? reg_match[6];
		if (!value) {
			throw new Error(`Error matching the ARH property value for "${reg_match[1]}.${reg_match[2]}".`);
		}
		property[reg_match[2]] = decodeBinaryString(value);
	}

	return res;
}

/**
 * Object wrapper around a string.
 */
class RefString {
	/**
	 * Object wrapper around a string.
	 *
	 * @param {string} s
	 */
	constructor(s) {
		this.value = s;
	}
	/**
	 * @param {RegExp} regexp
	 * @returns {RegExpMatchArray?}
	 */
	match(regexp) {
		return this.value.match(regexp);
	}
	/**
	 * @param {number} from
	 * @param {number} [length]
	 * @returns {string}
	 */
	substr(from, length) {
		return this.value.substr(from, length);
	}
}

/**
 * Matches a pattern to the beginning of str.
 * Adds CFWS_op to the beginning of pattern.
 * pattern must be followed by string end, ";" or CFWS_p.
 * Removes the found match from str.
 *
 * @param {RefString} str
 * @param {string} pattern
 * @param {Token} token - Token to use for parsing; depends on internationalized support
 * @returns {string[]} An Array, containing the matches
 * @throws if match no match found
 */
function match(str, pattern, token) {
	const reg_match = match_o(str, pattern, token);
	if (reg_match === null) {
		throw new Error("Parsing error");
	}
	return reg_match;
}

/**
 * Tries to matches a pattern to the beginning of str.
 * Adds CFWS_op to the beginning of pattern.
 * pattern must be followed by string end, ";" or CFWS_p.
 * If match is found, removes it from str.
 *
 * @param {RefString} str
 * @param {string} pattern
 * @param {Token} token - Token to use for parsing; depends on internationalized support
 * @returns {string[]|null} Null if no match for the pattern is found, else
 * an Array, containing the matches.
 */
function match_o(str, pattern, token) {
	const regexp = new RegExp(`^${token.CFWS_op}(?:${pattern})` +
		`(?:(?:${token.CFWS_op}\r\n$)|(?=;)|(?=${token.CFWS}))`);
	const reg_match = str.match(regexp);
	if (reg_match === null || !reg_match[0]) {
		return null;
	}
	str.value = str.substr(reg_match[0].length);
	return reg_match;
}
