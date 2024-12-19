/*
 * ARHParser.jsm.js
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
/* global Logging, rfcParser, DKIM_Error */
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

Cu.import("resource://dkim_verifier/logging.jsm.js");
Cu.import("resource://dkim_verifier/helper.jsm.js");
Cu.import("resource://dkim_verifier/rfcParser.jsm.js");

// @ts-ignore
var prefs = Services.prefs.getBranch(PREF_BRANCH);
// @ts-ignore
const log = Logging.getLogger("ARHParser");

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
 * @property {String} authserv_id
 */

let ARHParser = {
	get version() { return module_version; },

	/**
	 *  Parses an Authentication-Results header.
	 *  
	 *  @param {String} authresHeader Authentication-Results header
	 *  @return {ARHHeader} Parsed Authentication-Results header
	 *  @throws {DKIM_Error}
	 */
	parse: function _ARHParser_parse(authresHeader) {
		// remove header name
		authresHeader = authresHeader.replace(
			new RegExp(`^Authentication-Results:${rfcParser.get("CFWS_op")}`, "i"), "");
		let authresHeaderRef = new RefString(authresHeader);

		/** @type {ARHHeader} */
		let res = {};
		res.resinfo = [];
		let reg_match;

		// get authserv-id and authres-version
		reg_match = match(authresHeaderRef, `${rfcParser.get("value_cp")}(?:${rfcParser.get("CFWS")}([0-9]+)${rfcParser.get("CFWS_op")})?`);
		const authserv_id = reg_match[1] || reg_match[2];
		if (!authserv_id) {
			throw new DKIM_Error("Error matching the ARH authserv-id.");
		}
		res.authserv_id = authserv_id;
		if (reg_match[3]) {
			res.authres_version = parseInt(reg_match[3], 10);
		} else {
			res.authres_version = 1;
		}

		// check if message authentication was performed
		reg_match = match_o(authresHeaderRef, `;${rfcParser.get("CFWS_op")}?none`);
		if (reg_match !== null) {
			log.debug("no-result");
			return res;
		}

		// get the resinfos
		while (authresHeaderRef.value !== "") {
			const arhResInfo = parseResinfo(authresHeaderRef);
			if (arhResInfo) {
				arhResInfo.authserv_id = authserv_id;
				res.resinfo.push(arhResInfo);
			}
		}

		log.debug(res.toSource());
		return res;
	}
};

/**
 *  Parses the next resinfo in str. The parsed part of str is removed from str.
 *  
 *  @param {RefString} str
 *  @return {ARHResinfo|null} Parsed resinfo
 *  @throws {DKIM_Error|Error}
 */
function parseResinfo(str) {
	log.trace("parse str: " + str.toSource());

	let reg_match;
	/** @type {ARHResinfo} */
	let res = {};
	
	// get methodspec
	const method_version_p = `${rfcParser.get("CFWS_op")}/${rfcParser.get("CFWS_op")}([0-9]+)`;
	const method_p = `(${rfcParser.get("Keyword")})(?:${method_version_p})?`;
	const result_p = `=${rfcParser.get("CFWS_op")}(${rfcParser.get("Keyword")})`;
	const methodspec_p = `;${rfcParser.get("CFWS_op")}${method_p}${rfcParser.get("CFWS_op")}${result_p}`;
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
	if (!reg_match[1]) {
		throw new DKIM_Error("Error matching the ARH method.");
	}
	if (!reg_match[3]) {
		throw new DKIM_Error("Error matching the ARH result.");
	}
	res.method = reg_match[1];
	if (reg_match[2]) {
		res.method_version = parseInt(reg_match[2], 10);
	} else {
		res.method_version = 1;
	}
	res.result = reg_match[3].toLowerCase();
	checkResultKeyword(res.method, reg_match[3]);

	// get reasonspec (optional)
	const reasonspec_p = `reason${rfcParser.get("CFWS_op")}=${rfcParser.get("CFWS_op")}${rfcParser.get("value_cp")}`;
	reg_match = match_o(str, reasonspec_p);
	if (reg_match !== null) {
		res.reason = reg_match[1] || reg_match[2];
	}

	// get propspec (optional)
	let pvalue_p = `${rfcParser.get("value_cp")}|((?:${rfcParser.get("local_part")}?@)?${rfcParser.get("domain_name")})`;
	if (prefs.getBoolPref("relaxedParsing")) {
		// allow "/" and ":" in properties, even if it is not in a quoted-string
		pvalue_p += "|([^ \\x00-\\x1F\\x7F()<>@,;\\\\\"[\\]?=]+)";
	}
	const special_smtp_verb_p = "mailfrom|rcptto";
	const property_p = `${special_smtp_verb_p}|${rfcParser.get("Keyword")}`;
	const propspec_p = `(${rfcParser.get("Keyword")})${rfcParser.get("CFWS_op")}\\.${rfcParser.get("CFWS_op")}(${property_p})${rfcParser.get("CFWS_op")}=${rfcParser.get("CFWS_op")}(?:${pvalue_p})`;
	res.propertys = {};
	res.propertys.smtp = {};
	res.propertys.header = {};
	res.propertys.body = {};
	res.propertys.policy = {};
	while ((reg_match = match_o(str, propspec_p)) !== null) {
		if (!reg_match[1]) {
			throw new DKIM_Error("Error matching the ARH property name.");
		}
		if (!reg_match[2]) {
			throw new DKIM_Error("Error matching the ARH property sub-name.");
		}		
		let property = res.propertys[reg_match[1]];
		if (!property) {
			property = {};
			res.propertys[reg_match[1]] = property;
		}
		property[reg_match[2]] = reg_match[3] ? reg_match[3] : reg_match[4] ? reg_match[4] : reg_match[5] ? reg_match[5] : reg_match[6];
	}

	log.trace(res.toSource());
	return res;
}

/**
 * Check that a result keyword is valid for a known method.
 *
 * See also https://www.iana.org/assignments/email-auth/email-auth.xhtml.
 *
 * @param {string} method
 * @param {string} resultKeyword
 * @returns {void}
 * @throws {DKIM_Error} if result keyword is invalid for the method.
 */
function checkResultKeyword(method, resultKeyword) {
	let allowedKeywords;

	// DKIM and DomainKeys (RFC 8601 section 2.7.1.)
	if (method === "dkim" || method === "domainkeys") {
		allowedKeywords = ["none", "pass", "fail", "policy", "neutral", "temperror", "permerror"];
	}

	// SPF and Sender ID (RFC 8601 section 2.7.2.)
	if (method === "spf" || method === "sender-id") {
		allowedKeywords = ["none", "pass", "fail", "softfail", "policy", "neutral", "temperror", "permerror"
			// Deprecated from older ARH RFC 5451.
			, "hardfail"
			// Older SPF specs (e.g. RFC 4408) used mixed case.
			, "None", "Pass", "Fail", "SoftFail", "Neutral", "TempError", "PermError"
		];
	}

	// DMARC (RFC 7489 section 11.2.)
	if (method === "dmarc") {
		allowedKeywords = ["none", "pass", "fail", "temperror", "permerror"];
	}

	// BIMI (https://datatracker.ietf.org/doc/draft-brand-indicators-for-message-identification/04/ section 7.7.)
	if (method === "bimi") {
		allowedKeywords = ["pass", "none", "fail", "temperror", "declined", "skipped"];
	}

	// Note: Both the ARH RFC and the IANA registry contain keywords for more than the above methods.
	// As we don't really care about them, for simplicity we treat them the same as unknown methods,
	// And don't restrict the keyword.

	if (allowedKeywords && !allowedKeywords.includes(resultKeyword)) {
		throw new DKIM_Error(`Result keyword "${resultKeyword}" is not allowed for method "${method}"`);
	}
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
 *  @throws {DKIM_Error} if match no match found
 */
function match(str, pattern) {
	const reg_match = match_o(str, pattern);
	if (reg_match === null) {
		log.trace("str to match against:" + str.toSource());
		throw new DKIM_Error("Parsing error");
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
	const regexp = new RegExp(`^${rfcParser.get("CFWS_op")}(?:${pattern})(?:(?:${rfcParser.get("CFWS_op")}\r\n$)|(?=;)|(?=${rfcParser.get("CFWS")}))`);
	const reg_match = str.match(regexp);
	if (reg_match === null || !reg_match[0]) {
		return null;
	}
	log.trace("matched: " + reg_match[0].toSource());
	str.value = str.substr(reg_match[0].length);
	return reg_match;
}
