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

// options for ESLint
/* global Components, Services */
/* global DKIM_SigError, DKIM_Error */
/* exported EXPORTED_SYMBOLS, rfcParser */

"use strict";

var EXPORTED_SYMBOLS = [
	"rfcParser"
];

// @ts-ignore
const Cu = Components.utils;

Cu.import("resource://gre/modules/Services.jsm");

Cu.import("resource://dkim_verifier/helper.jsm.js");

let rfcParser = (function() {

	let RfcParserStd = {};

	////// RFC 2045 - Multipurpose Internet Mail Extensions (MIME) Part One: Format of Internet Message Bodies
	//// 5.1.  Syntax of the Content-Type Header Field
	RfcParserStd.token = "[^ \\x00-\\x1F\\x7F()<>@,;:\\\\\"/[\\]?=\\u0080-\\uFFFF]+";

	////// RFC 5234 - Augmented BNF for Syntax Specifications: ABNF
	//// Appendix B.1.	Core Rules
	RfcParserStd.VCHAR = "[!-~]";
	RfcParserStd.WSP = "[ \t]";

	////// RFC 5321 - Simple Mail Transfer Protocol
	//// 4.1.2.	 Command Argument Syntax
	RfcParserStd.Let_dig = "[A-Za-z0-9]";
	RfcParserStd.Ldh_str = `(?:[A-Za-z0-9-]*${RfcParserStd.Let_dig})`;
	RfcParserStd.Keyword = RfcParserStd.Ldh_str;
	RfcParserStd.sub_domain = `(?:${RfcParserStd.Let_dig}${RfcParserStd.Ldh_str}?)`;

	////// RFC 5322 - Internet Message Format
	//// 3.2.1.	 Quoted characters
	// Note: this is incomplete (obs-qp is missing)
	RfcParserStd.quoted_pair = `(?:\\\\(?:${RfcParserStd.VCHAR}|${RfcParserStd.WSP}))`;
	//// 3.2.2.	 Folding White Space and Comments
	// Note: this is incomplete (obs-FWS is missing)
	// Note: this is as specified in Section 2.8. of RFC 6376 [DKIM]
	RfcParserStd.FWS = `(?:${RfcParserStd.WSP}*(?:\r\n)?${RfcParserStd.WSP}+)`;
	// Note: helper only, not part of the RFC
	RfcParserStd.FWS_op = `${RfcParserStd.FWS}?`;
	// Note: this is incomplete (obs-ctext is missing)
	RfcParserStd.ctext = "[!-'*-[\\]-~]";
	// Note: this is incomplete (comment is missing)
	RfcParserStd.ccontent = `(?:${RfcParserStd.ctext}|${RfcParserStd.quoted_pair})`;
	RfcParserStd.comment = `\\((?:${RfcParserStd.FWS_op}${RfcParserStd.ccontent})*${RfcParserStd.FWS_op}\\)`;
	RfcParserStd.CFWS = `(?:(?:(?:${RfcParserStd.FWS_op}${RfcParserStd.comment})+${RfcParserStd.FWS_op})|${RfcParserStd.FWS})`;
	// Note: helper only, not part of the RFC
	RfcParserStd.CFWS_op = `${RfcParserStd.CFWS}?`;
	//// 3.2.3.	 Atom
	RfcParserStd.atext = "[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]";
	RfcParserStd.atom = `(?:${RfcParserStd.CFWS_op}${RfcParserStd.atext}+${RfcParserStd.CFWS_op})`;
	// Note: helper only, not part of the RFC: an atom without the optional surrounding CFWS. dot is included for obs-phrase
	RfcParserStd.atom_b_obs = `(?:(?:${RfcParserStd.atext}|\\.)+)`;
	RfcParserStd.dot_atom_text = `(?:${RfcParserStd.atext}+(?:\\.${RfcParserStd.atext}+)*)`;
	RfcParserStd.dot_atom = `(?:${RfcParserStd.CFWS_op}${RfcParserStd.dot_atom_text}${RfcParserStd.CFWS_op})`;
	//// 3.2.4.	 Quoted Strings
	// Note: this is incomplete (obs-qtext is missing)
	RfcParserStd.qtext = "[!#-[\\]-~]";
	RfcParserStd.qcontent = `(?:${RfcParserStd.qtext}|${RfcParserStd.quoted_pair})`;
	RfcParserStd.quoted_string = `(?:${RfcParserStd.CFWS_op}"(?:${RfcParserStd.FWS_op}${RfcParserStd.qcontent})*${RfcParserStd.FWS_op}"${RfcParserStd.CFWS_op})`;
	//// 3.2.5.	 Miscellaneous Tokens
	RfcParserStd.word = `(?:${RfcParserStd.atom}|${RfcParserStd.quoted_string})`;
	// Note: helper only, not part of the RFC: chain of word (including dot for obs-phrase) without whitespace between, or quoted string chain
	RfcParserStd.word_chain = `(?:(?:${RfcParserStd.atom_b_obs}|(?:${RfcParserStd.atom_b_obs}?${RfcParserStd.quoted_string})+${RfcParserStd.atom_b_obs}?))`;
	// Note: this is incomplete (obs-phrase is missing)
	// Note: this is rewritten to avoid backtracking issues (in RFC specified as `1*word / obs-phrase`)
	RfcParserStd.phrase = `(?:${RfcParserStd.CFWS_op}${RfcParserStd.word_chain}(?:${RfcParserStd.CFWS}${RfcParserStd.word_chain})*${RfcParserStd.CFWS_op})`;
	//// 3.4.  Address Specification
	RfcParserStd.name_addr = `(?:${RfcParserStd.display_name}?${RfcParserStd.angle_addr})`;
	// Note: this is incomplete (obs-angle-addr is missing)
	RfcParserStd.angle_addr = `(?:${RfcParserStd.CFWS_op}<${RfcParserStd.addr_spec}>${RfcParserStd.CFWS_op})`;
	RfcParserStd.display_name = `(?:${RfcParserStd.phrase})`;
	//// 3.4.1.	 Addr-Spec Specification
	RfcParserStd.addr_spec = `(?:${RfcParserStd.local_part}@${RfcParserStd.domain})`;
	// Note: this is incomplete (obs-local-part is missing)
	RfcParserStd.local_part = `(?:${RfcParserStd.dot_atom}|${RfcParserStd.quoted_string})`;
	// Note: this is incomplete (domain-literal and obs-domain are missing)
	RfcParserStd.domain = `(?:${RfcParserStd.dot_atom})`;
	////// RFC 6376 - DomainKeys Identified Mail (DKIM) Signatures
	//// 3.5.  The DKIM-Signature Header Field
	RfcParserStd.domain_name = `(?:${RfcParserStd.sub_domain}(?:\\.${RfcParserStd.sub_domain})+)`;

	/* Customs - not in 5.x branch */
	// "value" as specified in Section 5.1 of RFC 2045.
	RfcParserStd.quoted_string_cp = `(?:${RfcParserStd.CFWS_op}"((?:${RfcParserStd.FWS_op}${RfcParserStd.qcontent})*)${RfcParserStd.FWS_op}"${RfcParserStd.CFWS_op})`;
	RfcParserStd.value_cp = `(?:(${RfcParserStd.token})|${RfcParserStd.quoted_string_cp})`;
	// Pattern for hyphenated-word as specified in Section 2.10 of RFC 6376
	RfcParserStd.hyphenated_word = "(?:[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?)";
	// Pattern for ALPHADIGITPS as specified in Section 2.10 of RFC 6376
	RfcParserStd.ALPHADIGITPS = "[A-Za-z0-9+/]";
	// Pattern for base64string as specified in Section 2.10 of RFC 6376
	RfcParserStd.base64string = `(?:${RfcParserStd.ALPHADIGITPS}(?:${RfcParserStd.FWS}?${RfcParserStd.ALPHADIGITPS})*(?:${RfcParserStd.FWS}?=){0,2})`;
	// Pattern for dkim-safe-char as specified in Section 2.11 of RFC 6376
	RfcParserStd.dkim_safe_char = "[!-:<>-~]";
	// Pattern for hex-octet as specified in Section 6.7 of RFC 2045
	// we also allow added FWS (needed for Copied header fields)
	RfcParserStd.hex_octet = `(?:=${RfcParserStd.FWS}?[0-9ABCDEF]${RfcParserStd.FWS}?[0-9ABCDEF])`;
	// Pattern for qp-hdr-value as specified in Section 2.10 of RFC 6376
	// same as dkim-quoted-printable with "|" encoded as specified in Section 2.11 of RFC 6376
	RfcParserStd.qp_hdr_value = `(?:(?:${RfcParserStd.FWS}|${RfcParserStd.hex_octet}|[!-:<>-{}-~])*)`;
	// Pattern for field-name as specified in Section 3.6.8 of RFC 5322 without ";"
	// used as hdr-name in RFC 6376
	RfcParserStd.hdr_name = "(?:[!-9<-~]+)";


	let RfcParserI = {};
	////// RFC 3629 - UTF-8, a transformation format of ISO 10646
	//// 4.	 Syntax of UTF-8 Byte Sequences
	//// https://datatracker.ietf.org/doc/html/rfc3629#section-4
	RfcParserI.UTF8_tail = "[\x80-\xBF]";
	RfcParserI.UTF8_2 = `(?:[\xC2-\xDF]${RfcParserI.UTF8_tail})`;
	RfcParserI.UTF8_3 = `(?:(?:\xE0[\xA0-\xBF]${RfcParserI.UTF8_tail})|(?:[\xE1-\xEC]${RfcParserI.UTF8_tail}${RfcParserI.UTF8_tail})|(?:\xED[\x80-\x9F]${RfcParserI.UTF8_tail})|(?:[\xEE-\xEF]${RfcParserI.UTF8_tail}${RfcParserI.UTF8_tail}))`;
	RfcParserI.UTF8_4 = `(?:(?:\xF0[\x90-\xBF]${RfcParserI.UTF8_tail}${RfcParserI.UTF8_tail})|(?:[\xF1-\xF3]${RfcParserI.UTF8_tail}${RfcParserI.UTF8_tail}${RfcParserI.UTF8_tail})|(?:\xF4[\x80-\x8F]${RfcParserI.UTF8_tail}${RfcParserI.UTF8_tail}))`;
	////// RFC 5890 - Internationalized Domain Names for Applications (IDNA): Definitions and Document Framework
	//// 2.3.2.1.  IDNA-valid strings, A-label, and U-label
	//// https://datatracker.ietf.org/doc/html/rfc5890#section-2.3.2.1
	// IMPORTANT: This does not validate if the label is valid.
	// E.g. the character "⒈" (U+2488) should be disallowed but matches UTF8_non_ascii
	RfcParserI.u_label = `(?:(?:${RfcParserI.Let_dig}|${RfcParserI.UTF8_non_ascii})(?:${RfcParserI.Let_dig}|-|${RfcParserI.UTF8_non_ascii})*(?:${RfcParserI.Let_dig}|${RfcParserI.UTF8_non_ascii})?)`;
	////// RFC 6531 - SMTP Extension for Internationalized Email
	//// 3.3.  Extended Mailbox Address Syntax
	//// https://datatracker.ietf.org/doc/html/rfc6531#section-3.3
	/** @override */
	RfcParserI.sub_domain = `(?:${RfcParserStd.sub_domain}|${RfcParserI.u_label})`;
	////// RFC 6532 - Internationalized Email Headers
	//// 3.1.  UTF-8 Syntax and Normalization
	//// https://datatracker.ietf.org/doc/html/rfc6532#section-3.1
	RfcParserI.UTF8_non_ascii = `(?:${RfcParserI.UTF8_2}|${RfcParserI.UTF8_3}|${RfcParserI.UTF8_4})`;
	//// 3.2.  Syntax Extensions to RFC 5322
	//// https://datatracker.ietf.org/doc/html/rfc6532#section-3.2
	/** @override */
	RfcParserI.VCHAR = `(?:${RfcParserStd.VCHAR}|${RfcParserI.UTF8_non_ascii})`;
	/** @override */
	RfcParserI.ctext = `(?:${RfcParserStd.ctext}|${RfcParserI.UTF8_non_ascii})`;
	/** @override */
	RfcParserI.atext = `(?:${RfcParserStd.atext}|${RfcParserI.UTF8_non_ascii})`;
	/** @override */
	RfcParserI.qtext = `(?:${RfcParserStd.qtext}|${RfcParserI.UTF8_non_ascii})`;

	/** @readonly */
	const TAG_PARSE_ERROR = {
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
	function parseTagValueList(str) {
		const tval = "[!-:<-~]+";
		const tagName = "[A-Za-z][A-Za-z0-9_]*";
		const tagValue = `(?:${tval}(?:(${RfcParserStd.WSP}|${RfcParserStd.FWS})+${tval})*)?`;

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
				`^${RfcParserStd.FWS}?(${tagName})${RfcParserStd.FWS}?=${RfcParserStd.FWS}?(${tagValue})${RfcParserStd.FWS}?$`
			));
			if (tmp === null || !tmp[1] || tmp[2] === undefined) {
				return TAG_PARSE_ERROR.ILL_FORMED;
			}
			const name = tmp[1];
			const value = tmp[2];

			// check that tag is no duplicate
			if (map.has(name)) {
				return TAG_PARSE_ERROR.DUPLICATE;
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
	* @throws {DKIM_SigError|DKIM_Error} Throws if tag_value does not match.
	*/
	function parseTagValue(map, tagName, patternTagValue, expType = 1) {
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
				throw new DKIM_Error(`illformed tag ${tagName}`);
			}
		}

		// @ts-expect-error
		return res;
	}

	const PREF_BRANCH = "extensions.dkim_verifier.";

	const prefs = Services.prefs.getBranch(PREF_BRANCH);
	const isInternationalized = prefs.getBoolPref("internationalized.enable");

	let that = {
		/**
		 * @param {string} token
		 * @returns {string}
		 */
		get: function(token) {
				if (isInternationalized && RfcParserI[token]) {
					return RfcParserI[token];
				}
				if (RfcParserStd[token]) {
					return RfcParserStd[token];
				}
				throw new Error(`Illegal RFC token: ${token}`);
		},

		TAG_PARSE_ERROR: TAG_PARSE_ERROR,
		parseTagValueList: parseTagValueList,
		parseTagValue: parseTagValue
	};

	return that;

}());