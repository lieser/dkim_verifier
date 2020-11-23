/*
 * Parser for the Authentication-Results header as specified in RFC 7601.
 *
 * Copyright (c) 2014-2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-disable camelcase */
/* eslint-disable no-use-before-define */

import Logging from "./logging.mjs.js";
import RfcParser from "./rfcParser.mjs.js";

const log = Logging.getLogger("ArhParser");


// WSP as specified in Appendix B.1 of RFC 5234
const WSP_p = "[ \t]";
// VCHAR as specified in Appendix B.1 of RFC 5234
const VCHAR_p = "[!-~]";
// Let-dig  as specified in Section 4.1.2 of RFC 5321 [SMTP].
const Let_dig_p = "[A-Za-z0-9]";
// Ldh-str  as specified in Section 4.1.2 of RFC 5321 [SMTP].
const Ldh_str_p = `(?:[A-Za-z0-9-]*${Let_dig_p})`;
// "Keyword" as specified in Section 4.1.2 of RFC 5321 [SMTP].
const Keyword_p = Ldh_str_p;
// obs-FWS as specified in Section 4.2 of RFC 5322
const obs_FWS_p = `(?:${WSP_p}+(?:\r\n${WSP_p}+)*)`;
// quoted-pair as specified in Section 3.2.1 of RFC 5322
// Note: obs-qp is not included, so this pattern matches less then specified!
const quoted_pair_p = `(?:\\\\(?:${VCHAR_p}|${WSP_p}))`;
// FWS as specified in Section 3.2.2 of RFC 5322
const FWS_p = `(?:(?:(?:${WSP_p}*\r\n)?${WSP_p}+)|${obs_FWS_p})`;
const FWS_op = `${FWS_p}?`;
// ctext as specified in Section 3.2.2 of RFC 5322
const ctext_p = "[!-'*-[\\]-~]";
// ccontent as specified in Section 3.2.2 of RFC 5322
// Note: comment is not included, so this pattern matches less then specified!
const ccontent_p = `(?:${ctext_p}|${quoted_pair_p})`;
// comment as specified in Section 3.2.2 of RFC 5322
const comment_p = `\\((?:${FWS_op}${ccontent_p})*${FWS_op}\\)`;
// CFWS as specified in Section 3.2.2 of RFC 5322 [MAIL]
const CFWS_p = `(?:(?:(?:${FWS_op}${comment_p})+${FWS_op})|${FWS_p})`;
const CFWS_op = `${CFWS_p}?`;
// dot-atom-text as specified in Section 3.2.3 of RFC 5322
const dot_atom_text_p = RfcParser.dot_atom_text;
// dot-atom as specified in Section 3.2.3 of RFC 5322
// dot-atom        =   [CFWS] dot-atom-text [CFWS]
const dot_atom_p = `(?:${CFWS_op}${dot_atom_text_p}${CFWS_op})`;
// qtext as specified in Section 3.2.4 of RFC 5322
// Note: obs-qtext is not included, so this pattern matches less then specified!
const qtext_p = "[!#-[\\]-~]";
// qcontent as specified in Section 3.2.4 of RFC 5322
const qcontent_p = `(?:${qtext_p}|${quoted_pair_p})`;
// quoted-string as specified in Section 3.2.4 of RFC 5322
const quoted_string_p = `(?:${CFWS_op}"(?:${FWS_op}${qcontent_p})*${FWS_op}"${CFWS_op})`;
const quoted_string_cp = `(?:${CFWS_op}"((?:${FWS_op}${qcontent_p})*)${FWS_op}"${CFWS_op})`;
// local-part as specified in Section 3.4.1 of RFC 5322
// Note: obs-local-part is not included, so this pattern matches less then specified!
const local_part_p = `(?:${dot_atom_p}|${quoted_string_p})`;
// token as specified in Section 5.1 of RFC 2045.
const token_p = "[^ \\x00-\\x1F\\x7F()<>@,;:\\\\\"/[\\]?=]+";
// "value" as specified in Section 5.1 of RFC 2045.
const value_p = `(?:${token_p}|${quoted_string_p})`;
const value_cp = `(?:(${token_p})|${quoted_string_cp})`;
// domain-name as specified in Section 3.5 of RFC 6376 [DKIM].
const domain_name_p = RfcParser.domain_name;


/**
 * @typedef {Object} ArhHeader
 * @property {string} authserv_id
 * @property {number} authres_version
 * @property {ArhResInfo[]} resinfo
 */

/**
 * @typedef {Object.<string, string|undefined>} ArhProperty
 */
/**
 * @typedef {{[x: string]: ArhProperty|undefined, smtp: ArhProperty, header: ArhProperty, body: ArhProperty, policy: ArhProperty }} ArhProperties
 */

/**
 * @typedef {Object} ArhResInfo
 * @property {string} method
 * @property {number} method_version
 * @property {string} result
 *           none|pass|fail|softfail|policy|neutral|temperror|permerror
 * @property {string=} [reason]
 * @property {ArhProperties} propertys
 * property {ArhProperty} propertys.smtp
 * property {ArhProperty} propertys.header
 * property {ArhProperty} propertys.body
 * property {ArhProperty} propertys.policy
 * property {ArhProperty=} [propertys._Keyword_]
 *           ArhResInfo can also include other propertys besides the aboves.
 */

export default class ArhParser {
	/**
	 *  Parses an Authentication-Results header.
	 *
	 *  @param {string} authResHeader Authentication-Results header
	 *  @param {boolean} [relaxedParsing] Enable relaxed parsing
	 *  @return {ArhHeader} Parsed Authentication-Results header
	 */
	static parse(authResHeader, relaxedParsing = false) {
		// remove header name
		const authResHeaderRef = new RefString(authResHeader.replace(
			new RegExp(`^Authentication-Results:${CFWS_op}`, "i"), ""));

		/** @type {ArhHeader} */
		const res = {};
		res.resinfo = [];
		let reg_match;

		// get authserv-id and authres-version
		reg_match = match(authResHeaderRef, `${value_cp}(?:${CFWS_p}([0-9]+)${CFWS_op})?`);
		res.authserv_id = reg_match[1] || reg_match[2];
		if (reg_match[3]) {
			res.authres_version = parseInt(reg_match[3], 10);
		} else {
			res.authres_version = 1;
		}

		// check if message authentication was performed
		reg_match = match_o(authResHeaderRef, `;${CFWS_op}?none`);
		if (reg_match !== null) {
			log.debug("no-result");
			return res;
		}

		// get the resinfos
		while (authResHeaderRef.value !== "") {
			const arhResInfo = parseResInfo(authResHeaderRef, relaxedParsing);
			if (arhResInfo) {
				res.resinfo.push(arhResInfo);
			}
		}

		return res;
	}
}

/**
 *  Parses the next resinfo in str. The parsed part of str is removed from str.
 *
 *  @param {RefString} str
 *  @param {boolean} relaxedParsing Enable relaxed parsing
 *  @return {ArhResInfo|null} Parsed resinfo
 */
function parseResInfo(str, relaxedParsing) {
	log.trace("parse str: ", str);

	let reg_match;
	/** @type {ArhResInfo} */
	const res = {};

	// get methodspec
	const method_version_p = `${CFWS_op}/${CFWS_op}([0-9]+)`;
	const method_p = `(${Keyword_p})(?:${method_version_p})?`;
	let Keyword_result_p = "none|pass|fail|softfail|policy|neutral|temperror|permerror";
	// older SPF specs (e.g. RFC 4408) use mixed case
	Keyword_result_p += "|None|Pass|Fail|SoftFail|Neutral|TempError|PermError";
	const result_p = `=${CFWS_op}(${Keyword_result_p})`;
	const methodspec_p = `;${CFWS_op}${method_p}${CFWS_op}${result_p}`;
	try {
		reg_match = match(str, methodspec_p);
	} catch (exception) {
		if (relaxedParsing) {
			// allow trailing ";" at the end
			match_o(str, ";");
			if (str.value.trim() === "") {
				str.value = "";
				return null;
			}
		}
		throw exception;
	}
	res.method = reg_match[1];
	if (reg_match[2]) {
		res.method_version = parseInt(reg_match[2], 10);
	} else {
		res.method_version = 1;
	}
	res.result = reg_match[3].toLowerCase();

	// get reasonspec (optional)
	const reasonspec_p = `reason${CFWS_op}=${CFWS_op}${value_cp}`;
	reg_match = match_o(str, reasonspec_p);
	if (reg_match !== null) {
		res.reason = reg_match[1] || reg_match[2];
	}

	// get propspec (optional)
	let pvalue_p = `${value_p}|(?:(?:${local_part_p}?@)?${domain_name_p})`;
	if (relaxedParsing) {
		// allow "/" in the header.b (or other) property, even if it is not in a quoted-string
		pvalue_p += "|[^ \\x00-\\x1F\\x7F()<>@,;:\\\\\"[\\]?=]+";
	}
	const special_smtp_verb_p = "mailfrom|rcptto";
	const property_p = `${special_smtp_verb_p}|${Keyword_p}`;
	const propspec_p = `(${Keyword_p})${CFWS_op}\\.${CFWS_op}(${property_p})${CFWS_op}=${CFWS_op}(${pvalue_p})`;
	res.propertys = {};
	res.propertys.smtp = {};
	res.propertys.header = {};
	res.propertys.body = {};
	res.propertys.policy = {};
	while ((reg_match = match_o(str, propspec_p)) !== null) {
		let property = res.propertys[reg_match[1]];
		if (!property) {
			property = {};
			res.propertys[reg_match[1]] = property;
		}
		property[reg_match[2]] = reg_match[3];
	}

	log.trace("parseResInfo res:", res);
	return res;
}

/**
 * Object wrapper around a string.
 */
class RefString {
	/**
	 * Object wrapper around a string.
	 * @constructor
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
 *  Matches a pattern to the beginning of str.
 *  Adds CFWS_op to the beginning of pattern.
 *  pattern must be followed by string end, ";" or CFWS_p.
 *  Removes the found match from str.
 *
 *  @param {RefString} str
 *  @param {string} pattern
 *  @return {string[]} An Array, containing the matches
 *  @throws if match no match found
 */
function match(str, pattern) {
	const reg_match = match_o(str, pattern);
	if (reg_match === null) {
		log.trace("str to match against:", JSON.stringify(str));
		throw new Error("Parsing error");
	}
	return reg_match;
}

/**
 *  Tries to matches a pattern to the beginning of str.
 *  Adds CFWS_op to the beginning of pattern.
 *  pattern must be followed by string end, ";" or CFWS_p.
 *  If match is found, removes it from str.
 *
 *  @param {RefString} str
 *  @param {string} pattern
 *  @return {string[]|Null} Null if no match for the pattern is found, else
 *                        an Array, containing the matches
 */
function match_o(str, pattern) {
	const regexp = new RegExp(`^${CFWS_op}(?:${pattern})` +
		`(?:(?:${CFWS_op}\r\n$)|(?=;)|(?=${CFWS_p}))`);
	const reg_match = str.match(regexp);
	if (reg_match === null) {
		return null;
	}
	log.trace("matched: ", JSON.stringify(reg_match[0]));
	str.value = str.substr(reg_match[0].length);
	return reg_match;
}
