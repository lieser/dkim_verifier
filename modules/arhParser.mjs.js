/*
 * ARHParser.jsm
 * 
 * Parser for the Authentication-Results header as specified in RFC 7601.
 *
 * Version: 1.2.1 (13 January 2019)
 * 
 * Copyright (c) 2014-2019 Philippe Lieser
 * 
 * This software is licensed under the terms of the MIT License.
 * 
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// options for ESLint
/* global Components, Services */
/* global Logging */
/* exported EXPORTED_SYMBOLS, ARHParser */

"use strict";

// @ts-ignore
const module_version = "1.2.1";

var EXPORTED_SYMBOLS = [
	"ARHParser"
];

// @ts-ignore
const PREF_BRANCH = "extensions.dkim_verifier.arh.";

// @ts-ignore
const Cu = Components.utils;

Cu.import("resource://gre/modules/Services.jsm");

Cu.import("resource://dkim_verifier/logging.jsm");


// @ts-ignore
var prefs = Services.prefs.getBranch(PREF_BRANCH);
// @ts-ignore
let log = Logging.getLogger("ARHParser");


// WSP as specified in Appendix B.1 of RFC 5234
let WSP_p = "[ \t]";
// VCHAR as specified in Appendix B.1 of RFC 5234
let VCHAR_p = "[!-~]";
// Let-dig  as specified in Section 4.1.2 of RFC 5321 [SMTP].
let Let_dig_p = "[A-Za-z0-9]";
// Ldh-str  as specified in Section 4.1.2 of RFC 5321 [SMTP].
let Ldh_str_p = "(?:[A-Za-z0-9-]*" + Let_dig_p + ")";
// "Keyword" as specified in Section 4.1.2 of RFC 5321 [SMTP].
let Keyword_p = Ldh_str_p;
// sub-domain as specified in Section 4.1.2 of RFC 5321 [SMTP].
let sub_domain_p = "(?:" + Let_dig_p + Ldh_str_p + "?)";
// obs-FWS as specified in Section 4.2 of RFC 5322
let obs_FWS_p = "(?:" + WSP_p + "+(?:\r\n" + WSP_p + "+)*)";
// quoted-pair as specified in Section 3.2.1 of RFC 5322
// Note: obs-qp is not included, so this pattern matches less then specified!
let quoted_pair_p = "(?:\\\\(?:" + VCHAR_p + "|" + WSP_p + "))";
// FWS as specified in Section 3.2.2 of RFC 5322
let FWS_p = "(?:(?:(?:" + WSP_p + "*\r\n)?" + WSP_p + "+)|" + obs_FWS_p + ")";
let FWS_op = FWS_p + "?";
// ctext as specified in Section 3.2.2 of RFC 5322
let ctext_p = "[!-'*-[\\]-~]";
// ccontent as specified in Section 3.2.2 of RFC 5322
// Note: comment is not included, so this pattern matches less then specified!
let ccontent_p = "(?:" + ctext_p + "|" + quoted_pair_p + ")";
// comment as specified in Section 3.2.2 of RFC 5322
let comment_p = "\\((?:" + FWS_op + ccontent_p + ")*" + FWS_op + "\\)";
// CFWS as specified in Section 3.2.2 of RFC 5322 [MAIL]
let CFWS_p = "(?:(?:(?:" + FWS_op + comment_p + ")+" + FWS_op + ")|" + FWS_p + ")";
let CFWS_op = CFWS_p + "?";
// atext as specified in Section 3.2.3 of RFC 5322
let atext_p = "[!#-'*-+/-9=?A-Z^-~-]";
// dot-atom-text as specified in Section 3.2.3 of RFC 5322
let dot_atom_text_p = "(?:" + atext_p + "+(?:\\." + atext_p + "+)*)";
// dot-atom as specified in Section 3.2.3 of RFC 5322
// dot-atom        =   [CFWS] dot-atom-text [CFWS]
let dot_atom_p = "(?:" + CFWS_op + dot_atom_text_p + CFWS_op + ")";
// qtext as specified in Section 3.2.4 of RFC 5322
// Note: obs-qtext is not included, so this pattern matches less then specified!
let qtext_p = "[!#-[\\]-~]";
// qcontent as specified in Section 3.2.4 of RFC 5322
let qcontent_p = "(?:" + qtext_p + "|" + quoted_pair_p + ")";
// quoted-string as specified in Section 3.2.4 of RFC 5322
let quoted_string_p = "(?:" + CFWS_op +
	"\"(?:" + FWS_op + qcontent_p + ")*" + FWS_op + "\"" +
	CFWS_op + ")";
let quoted_string_cp = "(?:" + CFWS_op +
	"\"((?:" + FWS_op + qcontent_p + ")*)" + FWS_op + "\"" +
	CFWS_op + ")";
// local-part as specified in Section 3.4.1 of RFC 5322
// Note: obs-local-part is not included, so this pattern matches less then specified!
let local_part_p = "(?:" + dot_atom_p + "|" + quoted_string_p + ")";
// token as specified in Section 5.1 of RFC 2045.
let token_p = "[^ \\x00-\\x1F\\x7F()<>@,;:\\\\\"/[\\]?=]+";
// "value" as specified in Section 5.1 of RFC 2045.
let value_p = "(?:" + token_p + "|" + quoted_string_p + ")";
let value_cp = "(?:(" + token_p + ")|" + quoted_string_cp + ")";
// domain-name as specified in Section 3.5 of RFC 6376 [DKIM].
let domain_name_p = "(?:" + sub_domain_p + "(?:\\." + sub_domain_p + ")+)";


/**
 * @typedef {Object} ARHHeader
 * @property {String} authserv_id
 * @property {Number} [authres_version]
 * @property {ARHResinfo[]} resinfo
 */

/**
 * @typedef {Object} ARHResinfo
 * @property {String} method
 * @property {Number} [method_version]
 * @property {String} result
 *           none|pass|fail|softfail|policy|neutral|temperror|permerror
 * @property {String} [reason]
 * @property {Object} propertys
 * @property {Object} propertys.smtp
 * @property {Object} propertys.header
 * @property {Object} propertys.body
 * @property {Object} propertys.policy
 * @property {Object} [propertys._Keyword_]
 *           ARHResinfo can also include other propertys besides the aboves.
 */

let ARHParser = {
	get version() { return module_version; },

	/**
	 *  Parses an Authentication-Results header.
	 *  
	 *  @param {String} authresHeader Authentication-Results header
	 *  @return {ARHHeader} Parsed Authentication-Results header
	 */
	parse: function _ARHParser_parse(authresHeader) {
		// remove header name
		authresHeader = authresHeader.replace(
			new RegExp("^Authentication-Results:"+CFWS_op, "i"), "");
		let authresHeaderRef = new RefString(authresHeader);

		/** @type {ARHHeader} */
		let res = {};
		res.resinfo = [];
		let reg_match;

		// get authserv-id and authres-version
		reg_match = match(authresHeaderRef,
			value_cp + "(?:" + CFWS_p + "([0-9]+)" + CFWS_op +" )?");
		res.authserv_id = reg_match[1] || reg_match[2];
		if (reg_match[3]) {
			res.authres_version = parseInt(reg_match[3], 10);
		} else {
			res.authres_version = 1;
		}

		// check if message authentication was performed
		reg_match = match_o(authresHeaderRef, ";" + CFWS_op+"?none");
		if (reg_match !== null) {
			log.debug("no-result");
			return res;
		}

		// get the resinfos
		while (authresHeaderRef.value !== "") {
			let arhResInfo = parseResinfo(authresHeaderRef);
			if (arhResInfo) {
				res.resinfo.push(arhResInfo);
			}
		}

		log.debug(res.toSource());
		return res;
	},
};

/**
 *  Parses the next resinfo in str. The parsed part of str is removed from str.
 *  
 *  @param {RefString} str
 *  @return {ARHResinfo|null} Parsed resinfo
 */
function parseResinfo(str) {
	log.trace("parse str: " + str.toSource());

	let reg_match;
	/** @type {ARHResinfo} */
	let res = {};
	
	// get methodspec
	let method_version_p = CFWS_op + "/" + CFWS_op + "([0-9]+)";
	let method_p = "(" + Keyword_p + ")(?:" + method_version_p + ")?";
	let Keyword_result_p = "none|pass|fail|softfail|policy|neutral|temperror|permerror";
	// older SPF specs (e.g. RFC 4408) use mixed case
	Keyword_result_p += "|None|Pass|Fail|SoftFail|Neutral|TempError|PermError";
	let result_p = "=" + CFWS_op + "(" + Keyword_result_p + ")";
	let methodspec_p = ";" + CFWS_op + method_p + CFWS_op + result_p;
	try {
		reg_match = match(str, methodspec_p);
	} catch (exception) {
		if (prefs.getBoolPref("relaxedParsing"))
		{
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
	let reasonspec_p = "reason" + CFWS_op + "=" + CFWS_op + value_cp;
	reg_match = match_o(str, reasonspec_p);
	if (reg_match !== null) {
		res.reason = reg_match[1] || reg_match[2];
	}

	// get propspec (optional)
	let pvalue_p = value_p + "|(?:(?:" + local_part_p + "?@)?" + domain_name_p + ")";
	if (prefs.getBoolPref("relaxedParsing")) {
		// allow "/" in the header.b (or other) property, even if it is not in a quoted-string
		pvalue_p += "|[^ \\x00-\\x1F\\x7F()<>@,;:\\\\\"[\\]?=]+";
	}
	let special_smtp_verb_p = "mailfrom|rcptto";
	let property_p = special_smtp_verb_p + "|" + Keyword_p;
	let propspec_p = "(" + Keyword_p + ")" + CFWS_op + "\\." + CFWS_op +
		"(" + property_p + ")" + CFWS_op + "=" + CFWS_op + "(" + pvalue_p + ")";
	res.propertys = {};
	res.propertys.smtp = {};
	res.propertys.header = {};
	res.propertys.body = {};
	res.propertys.policy = {};
	while ((reg_match = match_o(str, propspec_p)) !== null) {
		if (!res.propertys[reg_match[1]]) {
			res.propertys[reg_match[1]] = {};
		}
		res.propertys[reg_match[1]][reg_match[2]] = reg_match[3];
	}

	log.trace(res.toSource());
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
	match() {
		return this.value.match.apply(this.value, arguments);
	}
	substr() {
		return this.value.substr.apply(this.value, arguments);
	}
	toSource() {
		return this.value.toSource.apply(this.value, arguments);
	}
}

/**
 *  Matches a pattern to the beginning of str.
 *  Adds CFWS_op to the beginning of pattern.
 *  pattern must be followed by string end, ";" or CFWS_p.
 *  Removes the found match from str.
 *  
 *  @param {RefString} str
 *  @param {String} pattern
 *  @return {String[]} An Array, containing the matches
 *  @throws if match no match found
 */
function match(str, pattern) {
	let reg_match = match_o(str, pattern);
	if (reg_match === null) {
		log.trace("str to match against:" + str.toSource());
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
 *  @param {String} pattern
 *  @return {String[]|Null} Null if no match for the pattern is found, else
 *                        an Array, containing the matches
 */
function match_o(str, pattern) {
	let regexp = new RegExp("^" + CFWS_op + "(?:" + pattern + ")" +
		"(?:(?:" + CFWS_op + "\r\n$)|(?=;)|(?=" + CFWS_p + "))");
	let reg_match = str.match(regexp);
	if (reg_match === null) {
		return null;
	}
	log.trace("matched: " + reg_match[0].toSource());
	str.value = str.substr(reg_match[0].length);
	return reg_match;
}
