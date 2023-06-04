/**
 * RegExp pattern for ABNF definitions in various RFCs.
 *
 * Copyright (c) 2020-2023 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-disable camelcase */

import { DKIM_InternalError, DKIM_SigError } from "./error.mjs.js";

export default class RfcParser {
	////// RFC 2045 - Multipurpose Internet Mail Extensions (MIME) Part One: Format of Internet Message Bodies
	//// 5.1.  Syntax of the Content-Type Header Field
	static get token() { return "[^ \\x00-\\x1F\\x7F()<>@,;:\\\\\"/[\\]?=\\u0080-\\uFFFF]+"; }

	////// RFC 5234 - Augmented BNF for Syntax Specifications: ABNF
	//// Appendix B.1.  Core Rules
	static get VCHAR() { return "[!-~]"; }
	static get WSP() { return "[ \t]"; }

	////// RFC 5321 - Simple Mail Transfer Protocol
	//// 4.1.2.  Command Argument Syntax
	static get Keyword() { return this.Ldh_str; }
	static get sub_domain() { return `(?:${this.Let_dig}${this.Ldh_str}?)`; }
	static get Let_dig() { return "[A-Za-z0-9]"; }
	static get Ldh_str() { return `(?:[A-Za-z0-9-]*${this.Let_dig})`; }

	////// RFC 5322 - Internet Message Format
	//// 3.2.1.  Quoted characters
	// Note: this is incomplete (obs-qp is missing)
	static get quoted_pair() { return `(?:\\\\(?:${this.VCHAR}|${this.WSP}))`; }
	//// 3.2.2.  Folding White Space and Comments
	// Note: this is incomplete (obs-FWS is missing)
	// Note: this is as specified in Section 2.8. of RFC 6376 [DKIM]
	static get FWS() { return `(?:${this.WSP}*(?:\r\n)?${this.WSP}+)`; }
	// Note: helper only, not part of the RFC
	static get FWS_op() { return `${this.FWS}?`; }
	// Note: this is incomplete (obs-ctext is missing)
	static get ctext() { return "[!-'*-[\\]-~]"; }
	// Note: this is incomplete (comment is missing)
	static get ccontent() { return `(?:${this.ctext}|${this.quoted_pair})`; }
	static get comment() { return `\\((?:${this.FWS_op}${this.ccontent})*${this.FWS_op}\\)`; }
	static get CFWS() { return `(?:(?:(?:${this.FWS_op}${this.comment})+${this.FWS_op})|${this.FWS})`; }
	// Note: helper only, not part of the RFC
	static get CFWS_op() { return `${this.CFWS}?`; }
	//// 3.2.3.  Atom
	static get atext() { return "[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]"; }
	static get atom() { return `(?:${this.CFWS_op}${this.atext}+${this.CFWS_op})`; }
	// Note: helper only, not part of the RFC: an atom without the optional surrounding CFWS. dot is included for obs-phrase
	static get atom_b_obs() { return `(?:(?:${this.atext}|\\.)+)`; }
	static get dot_atom_text() { return `(?:${this.atext}+(?:\\.${this.atext}+)*)`; }
	static get dot_atom() { return `(?:${this.CFWS_op}${this.dot_atom_text}${this.CFWS_op})`; }
	//// 3.2.4.  Quoted Strings
	// Note: this is incomplete (obs-qtext is missing)
	static get qtext() { return "[!#-[\\]-~]"; }
	static get qcontent() { return `(?:${this.qtext}|${this.quoted_pair})`; }
	static get quoted_string() { return `(?:${this.CFWS_op}"(?:${this.FWS_op}${this.qcontent})*${this.FWS_op}"${this.CFWS_op})`; }
	//// 3.2.5.  Miscellaneous Tokens
	static get word() { return `(?:${this.atom}|${this.quoted_string})`; }
	// Note: helper only, not part of the RFC: chain of word (including dot for obs-phrase) without whitespace between, or quoted string chain
	static get word_chain() { return `(?:(?:${this.atom_b_obs}|(?:${this.atom_b_obs}?${this.quoted_string})+${this.atom_b_obs}?))`; }
	// Note: this is incomplete (obs-phrase is missing)
	// Note: this is rewritten to avoid backtracking issues (in RFC specified as `1*word / obs-phrase`)
	static get phrase() { return `(?:${this.CFWS_op}${this.word_chain}(?:${this.CFWS}${this.word_chain})*${this.CFWS_op})`; }
	//// 3.4.  Address Specification
	static get name_addr() { return `(?:${this.display_name}?${this.angle_addr})`; }
	// Note: this is incomplete (obs-angle-addr is missing)
	static get angle_addr() { return `(?:${this.CFWS_op}<${this.addr_spec}>${this.CFWS_op})`; }
	static get display_name() { return `(?:${this.phrase})`; }
	//// 3.4.1.  Addr-Spec Specification
	static get addr_spec() { return `(?:${this.local_part}@${this.domain})`; }
	// Note: this is incomplete (obs-local-part is missing)
	static get local_part() { return `(?:${this.dot_atom}|${this.quoted_string})`; }
	// Note: this is incomplete (domain-literal and obs-domain are missing)
	static get domain() { return `(?:${this.dot_atom})`; }

	////// RFC 6376 - DomainKeys Identified Mail (DKIM) Signatures
	//// 3.5.  The DKIM-Signature Header Field
	static get domain_name() { return `(?:${this.sub_domain}(?:\\.${this.sub_domain})+)`; }

	/** @readonly */
	static TAG_PARSE_ERROR = {
		/** @readonly */
		ILL_FORMED: -1,
		/** @readonly */
		DUPLICATE: -2,
	};

	/**
	 * Parses a Tag=Value list.
	 * Specified in Section 3.2 of RFC 6376.
	 *
	 * @param {string} str
	 * @returns {Map<string, string>|number} Map of the parsed list or:
	 * - -1 if a tag-spec is ill-formed.
	 * - -2 duplicate tag names.
	 */
	static parseTagValueList(str) {
		const tval = "[!-:<-~]+";
		const tagName = "[A-Za-z][A-Za-z0-9_]*";
		const tagValue = `(?:${tval}(?:(${this.WSP}|${this.FWS})+${tval})*)?`;

		// delete optional semicolon at end
		let listStr = str;
		if (listStr.charAt(listStr.length - 1) === ";") {
			listStr = listStr.substr(0, listStr.length - 1);
		}

		const array = listStr.split(";");
		/** @type {Map<string, string>} */
		const map = new Map();
		for (const elem of array) {
			// get tag name and value
			const tmp = elem.match(new RegExp(
				`^${this.FWS}?(${tagName})${this.FWS}?=${this.FWS}?(${tagValue})${this.FWS}?$`
			));
			if (tmp === null || !tmp[1] || tmp[2] === undefined) {
				return RfcParser.TAG_PARSE_ERROR.ILL_FORMED;
			}
			const name = tmp[1];
			const value = tmp[2];

			// check that tag is no duplicate
			if (map.has(name)) {
				return RfcParser.TAG_PARSE_ERROR.DUPLICATE;
			}

			// store Tag=Value pair
			map.set(name, value);
		}

		return map;
	}

	/**
	 * Parse a tag value stored in a Map.
	 *
	 * @param {ReadonlyMap<string, string>} map
	 * @param {string} tagName - name of the tag
	 * @param {string} patternTagValue - Pattern for the tag-value
	 * @param {number} [expType] - Type of exception to throw. 1 for DKIM header, 2 for DKIM key, 3 for general.
	 * @returns {[string, ...string[]]|null} The match from the RegExp if tag_name exists, otherwise null
	 * @throws {DKIM_SigError|DKIM_InternalError} Throws if tag_value does not match.
	 */
	static parseTagValue(map, tagName, patternTagValue, expType = 1) {
		const tagValue = map.get(tagName);
		// return null if tag_name doesn't exists
		if (tagValue === undefined) {
			return null;
		}

		const res = tagValue.match(new RegExp(`^${patternTagValue}$`));

		// throw DKIM_SigError if tag_value is ill-formed
		if (res === null) {
			if (expType === 1) {
				throw new DKIM_SigError(`DKIM_SIGERROR_ILLFORMED_${tagName.toUpperCase()}`);
			} else if (expType === 2) {
				throw new DKIM_SigError(`DKIM_SIGERROR_KEY_ILLFORMED_${tagName.toUpperCase()}`);
			} else {
				throw new DKIM_InternalError(`illformed tag ${tagName}`);
			}
		}

		// @ts-expect-error
		return res;
	}
}

export class RfcParserI extends RfcParser {
	////// RFC 3629 - UTF-8, a transformation format of ISO 10646
	//// 4.  Syntax of UTF-8 Byte Sequences
	//// https://datatracker.ietf.org/doc/html/rfc3629#section-4
	static get UTF8_tail() { return "[\x80-\xBF]"; }
	static get UTF8_2() { return `(?:[\xC2-\xDF]${this.UTF8_tail})`; }
	static get UTF8_3() { return `(?:(?:\xE0[\xA0-\xBF]${this.UTF8_tail})|(?:[\xE1-\xEC]${this.UTF8_tail}${this.UTF8_tail})|(?:\xED[\x80-\x9F]${this.UTF8_tail})|(?:[\xEE-\xEF]${this.UTF8_tail}${this.UTF8_tail}))`; }
	static get UTF8_4() { return `(?:(?:\xF0[\x90-\xBF]${this.UTF8_tail}${this.UTF8_tail})|(?:[\xF1-\xF3]${this.UTF8_tail}${this.UTF8_tail}${this.UTF8_tail})|(?:\xF4[\x80-\x8F]${this.UTF8_tail}${this.UTF8_tail}))`; }

	////// RFC 5890 - Internationalized Domain Names for Applications (IDNA): Definitions and Document Framework
	//// 2.3.2.1.  IDNA-valid strings, A-label, and U-label
	//// https://datatracker.ietf.org/doc/html/rfc5890#section-2.3.2.1
	// IMPORTANT: This does not validate if the label is valid.
	// E.g. the character "⒈" (U+2488) should be disallowed but matches UTF8_non_ascii
	static get u_label() { return `(?:(?:${this.Let_dig}|${this.UTF8_non_ascii})(?:${this.Let_dig}|-|${this.UTF8_non_ascii})*(?:${this.Let_dig}|${this.UTF8_non_ascii})?)`; }

	////// RFC 6531 - SMTP Extension for Internationalized Email
	//// 3.3.  Extended Mailbox Address Syntax
	//// https://datatracker.ietf.org/doc/html/rfc6531#section-3.3
	/** @override */
	static get sub_domain() {
		return `(?:${RfcParser.sub_domain}|${this.u_label})`;
	}

	////// RFC 6532 - Internationalized Email Headers
	//// 3.1.  UTF-8 Syntax and Normalization
	//// https://datatracker.ietf.org/doc/html/rfc6532#section-3.1
	static get UTF8_non_ascii() { return `(?:${this.UTF8_2}|${this.UTF8_3}|${this.UTF8_4})`; }
	//// 3.2.  Syntax Extensions to RFC 5322
	//// https://datatracker.ietf.org/doc/html/rfc6532#section-3.2
	/** @override */
	static get VCHAR() { return `(?:${RfcParser.VCHAR}|${this.UTF8_non_ascii})`; }
	/** @override */
	static get ctext() { return `(?:${RfcParser.ctext}|${this.UTF8_non_ascii})`; }
	/** @override */
	static get atext() { return `(?:${RfcParser.atext}|${this.UTF8_non_ascii})`; }
	/** @override */
	static get qtext() { return `(?:${RfcParser.qtext}|${this.UTF8_non_ascii})`; }
}
