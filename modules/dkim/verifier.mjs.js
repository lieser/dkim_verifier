/*
 * Verifies the DKIM-Signatures as specified in RFC 6376
 * http://tools.ietf.org/html/rfc6376
 * Update done by RFC 8301 included https://tools.ietf.org/html/rfc8301
 *
 * Copyright (c) 2013-2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

/*
 * Violations against RFC 6376:
 * ============================
 *  - at the moment, only a subset of valid Local-part in the i-Tag is recognized
 *  - no test for multiple key records in an DNS RRset (Section 3.6.2.2)
 *  - no test that the version tag of the DKIM key is the first tag in the record
 *
 */

// @ts-check
/* eslint-disable camelcase */
/* eslint-disable no-magic-numbers */

import {DKIM_InternalError, DKIM_SigError} from "../error.mjs.js";
import {addrIsInDomain, addrIsInDomain2, domainIsInDomain, stringEndsWith, stringEqual} from "../utils.mjs.js";
import DkimCrypto from "./crypto.mjs.js";
import Logging from "../logging.mjs.js";
import RfcParser from "../rfcParser.mjs.js";
import prefs from "../preferences.mjs.js";

/**
 * The result of the verification (Version 1).
 *
 * @typedef {Object} dkimResultV1
 * @property {String} version
 *           result version ("1.0" / "1.1")
 * @property {String} result
 *           "none" / "SUCCESS" / "PERMFAIL" / "TEMPFAIL"
 * @property {String=} [SDID]
 *           required if result="SUCCESS
 * @property {String=} [selector]
 *           added in version 1.1
 * @property {String[]=} [warnings]
 *           required if result="SUCCESS
 * @property {String=} [errorType]
 *           if result="PERMFAIL: DKIM_SigError.errorType
 *           if result="TEMPFAIL: DKIM_InternalError.errorType or Undefined
 * @property {String=} [shouldBeSignedBy]
 *           added in version 1.1
 * @property {Boolean=} [hideFail]
 *           added in  version 1.1
 */

/**
 * @typedef {Object} dkimSigWarningV2
 * @property {string} name - Name of the warning
 * @property {(string|string[])[]|undefined} [params] - optional params for formatted string
 */

/**
 * The result of the verification of a single DKIM signature (Version 2).
 *
 * @typedef {Object} dkimSigResultV2
 * @property {String} version
 *           result version ("2.0")
 * @property {String} result
 *           "none" / "SUCCESS" / "PERMFAIL" / "TEMPFAIL"
 * @property {String|undefined} [sdid]
 * @property {String|undefined} [auid]
 * @property {String|undefined} [selector]
 * @property {dkimSigWarningV2[]|undefined} [warnings]
 *           Array of warning_objects.
 *           required if result="SUCCESS"
 * @property {String|undefined} [errorType]
 *           if result="PERMFAIL: DKIM_SigError.errorType
 *           if result="TEMPFAIL: DKIM_InternalError.errorType or Undefined
 * @property {String[]|undefined} [errorStrParams]
 * @property {Boolean|undefined} [hideFail]
 * @property {Boolean|undefined} [keySecure]
 */

/**
 * The result of the verification (Version 2).
 *
 * @typedef {Object} dkimResultV2
 * @property {String} version
 *           result version ("2.0")
 * @property {dkimSigResultV2[]} signatures
 */

/**
 * @typedef {dkimSigWarningV2} dkimSigWarning
 */

const log = Logging.getLogger("Verifier");


// Pattern for hyphenated-word as specified in Section 2.10 of RFC 6376
const hyphenated_word = "(?:[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?)";
// Pattern for ALPHADIGITPS as specified in Section 2.10 of RFC 6376
const ALPHADIGITPS = "[A-Za-z0-9+/]";
// Pattern for base64string as specified in Section 2.10 of RFC 6376
const base64string = `(?:${ALPHADIGITPS}(?:${RfcParser.FWS}?${ALPHADIGITPS})*(?:${RfcParser.FWS}?=){0,2})`;
// Pattern for dkim-safe-char as specified in Section 2.11 of RFC 6376
const dkim_safe_char = "[!-:<>-~]";
// Pattern for hex-octet as specified in Section 6.7 of RFC 2045
// we also allow added FWS (needed for Copied header fields)
const hex_octet = `(?:=${RfcParser.FWS}?[0-9ABCDEF]${RfcParser.FWS}?[0-9ABCDEF])`;
// Pattern for qp-hdr-value as specified in Section 2.10 of RFC 6376
// same as dkim-quoted-printable with "|" encoded as specified in Section 2.11 of RFC 6376
const qp_hdr_value = `(?:(?:${RfcParser.FWS}|${hex_octet}|[!-:<>-{}-~])*)`;
// Pattern for field-name as specified in Section 3.6.8 of RFC 5322 without ";"
// used as hdr-name in RFC 6376
const hdr_name = "(?:[!-9<-~]+)";

/**
 * Callback for retrieving a DKIM key.
 *
 * @callback KeyFetchFunction
 * @param {string} sdid
 * @param {string} selector
 * @return {Promise<{key: string, secure: boolean}>} result
 * @throws {DKIM_SigError|DKIM_InternalError}
*/

// TODO: consider making it a member of Verifier
// TODO: consider providing default implementation
/** @type {KeyFetchFunction} */
let getKey;

/**
 * Set a callback function that will be used to retrieve the DKIM key.
 *
 * @param {KeyFetchFunction} keyFetchFunction
 * @returns {void}
 */
export function setKeyFetchFunction(keyFetchFunction) {
	getKey = keyFetchFunction;
}

class DkimSignature {
	/**
	 * parse the DKIM-Signature header field
	 * header field is specified in Section 3.5 of RFC 6376
	 *
	 * @param {string} dkimSignatureHeader
	 */
	constructor( dkimSignatureHeader ) {
		this.original_header = dkimSignatureHeader;
		/** @type {dkimSigWarningV2[]} */
		this.warnings = [];
		/** @type {boolean=} */
		this.keySecure = undefined;

		// strip DKIM-Signature header name
		let dkimHeader = dkimSignatureHeader.replace(/^DKIM-Signature[ \t]*:/i,"");
		// strip the \r\n at the end
		dkimHeader = dkimHeader.substr(0, dkimHeader.length-2);
		// parse tag-value list
		const tagMap = RfcParser.parseTagValueList(dkimHeader);
		if (tagMap === -1) {
			throw new DKIM_SigError("DKIM_SIGERROR_ILLFORMED_TAGSPEC");
		} else if (tagMap === -2) {
			throw new DKIM_SigError("DKIM_SIGERROR_DUPLICATE_TAG");
		}
		if (!(tagMap instanceof Map)) {
			throw new DKIM_InternalError(`unexpected return value from RfcParser.parseTagValueList: ${tagMap}`);
		}

		// Version
		this.v = DkimSignature._parseVersion(tagMap);

		const signatureAlgorithms = DkimSignature._parseSignatureAlgorithms(tagMap, this.warnings);
		// signature algorithm (signing part)
		this.a_sig = signatureAlgorithms.signature;
		// signature algorithm (hashing part)
		this.a_hash = signatureAlgorithms.hash;

		const signatureData = DkimSignature._parseSignatureData(tagMap);
		// signature (unfolded)
		this.b = signatureData.b;
		// signature (still folded)
		this.b_folded = signatureData.bFolded;

		// body hash
		this.bh = DkimSignature._parseBodyHash(tagMap);

		const canonicalization = DkimSignature._parseCanonicalization(tagMap);
		// canonicalization for header
		this.c_header = canonicalization.header;
		// canonicalization for body
		this.c_body = canonicalization.body;

		// Signing Domain Identifier (SDID) claiming responsibility
		this.d = DkimSignature._parseSdid(tagMap);

		// array of Signed header fields
		this.h_array = DkimSignature._parseSignedHeaders(tagMap);

		const auid = DkimSignature._parseAuid(tagMap, this.d, this.warnings);
		// Agent or User Identifier (AUID) on behalf of which the SDID is taking responsibility
		this.i = auid.auid;
		// domain part of AUID
		this.i_domain = auid.auidDomain;

		// Body length count
		this.l = DkimSignature._parseBodyLength(tagMap);

		// query methods for public key retrieval
		this.q = DkimSignature._parseQueryMethod(tagMap);

		// selector
		this.s = DkimSignature._parseSelector(tagMap, this.warnings);

		// Signature Timestamp
		this.t = DkimSignature._parseSignatureTimestamp(tagMap);
		// Signature Expiration
		this.x = DkimSignature._parseSignatureExpiration(tagMap, this.t);

		// Copied header fields
		this.z = DkimSignature._parseCopiedHeaders(tagMap);
	}

	/**
	 * @param {Map<string, string>} tagMap
	 * @returns {string}
	 */
	static _parseVersion(tagMap) {
		// get Version (plain-text; REQUIRED)
		// must be "1"
		const versionTag = RfcParser.parseTagValue(tagMap, "v", "[0-9]+");
		if (versionTag === null) {
			throw new DKIM_SigError("DKIM_SIGERROR_MISSING_V");
		}
		if (versionTag[0] !== "1") {
			throw new DKIM_InternalError(null, "DKIM_SIGERROR_VERSION");
		}
		return "1";
	}

	/**
	 * @param {Map<string, string>} tagMap
	 * @param {dkimSigWarningV2[]} warnings
	 * @returns {{signature: string, hash: string}}
	 */
	static _parseSignatureAlgorithms(tagMap, warnings) {
		// get signature algorithm (plain-text;REQUIRED)
		// currently only "rsa-sha1" or "rsa-sha256"
		const sig_a_tag_k = "(rsa|[A-Za-z](?:[A-Za-z]|[0-9])*)";
		const sig_a_tag_h = "(sha1|sha256|[A-Za-z](?:[A-Za-z]|[0-9])*)";
		const sig_a_tag_alg = `${sig_a_tag_k}-${sig_a_tag_h}`;
		const algorithmTag = RfcParser.parseTagValue(tagMap, "a", sig_a_tag_alg);
		if (algorithmTag === null) {
			throw new DKIM_SigError("DKIM_SIGERROR_MISSING_A");
		}
		if (algorithmTag[0] === "rsa-sha256") {
			return {
				signature: algorithmTag[1],
				hash: algorithmTag[2],
			};
		} else if (algorithmTag[0] === "rsa-sha1") {
			switch (prefs["error.algorithm.sign.rsa-sha1.treatAs"]) {
				case 0: // error
					throw new DKIM_SigError("DKIM_SIGERROR_INSECURE_A");
				case 1: // warning
					warnings.push({ name: "DKIM_SIGERROR_INSECURE_A" });
					break;
				case 2: // ignore
					break;
				default:
					throw new DKIM_InternalError("invalid error.algorithm.sign.rsa-sha1.treatAs");
			}
			return {
				signature: algorithmTag[1],
				hash: algorithmTag[2],
			};
		}
		throw new DKIM_SigError("DKIM_SIGERROR_UNKNOWN_A");
	}

	/**
	 * @param {Map<string, string>} tagMap
	 * @returns {{b: string, bFolded: string}}
	 */
	static _parseSignatureData(tagMap) {
		// get signature data (base64;REQUIRED)
		const signatureDataTag = RfcParser.parseTagValue(tagMap, "b", base64string);
		if (signatureDataTag === null) {
			throw new DKIM_SigError("DKIM_SIGERROR_MISSING_B");
		}
		return {
			b: signatureDataTag[0].replace(new RegExp(RfcParser.FWS,"g"), ""),
			bFolded: signatureDataTag[0],
		};
	}

	/**
	 * @param {Map<string, string>} tagMap
	 * @returns {string}
	 */
	static _parseBodyHash(tagMap) {
		// get body hash (base64;REQUIRED)
		const bodyHashTag = RfcParser.parseTagValue(tagMap, "bh", base64string);
		if (bodyHashTag === null) {
			throw new DKIM_SigError("DKIM_SIGERROR_MISSING_BH");
		}
		return bodyHashTag[0].replace(new RegExp(RfcParser.FWS,"g"), "");
	}

	/**
	 * @param {Map<string, string>} tagMap
	 * @returns {{header: string, body: string}}
	 */
	static _parseCanonicalization(tagMap) {
		// get Message canonicalization (plain-text; OPTIONAL, default is "simple/simple")
		// currently only "simple" or "relaxed" for both header and body
		const sig_c_tag_alg = `(simple|relaxed|${hyphenated_word})`;
		const msCanonTag = RfcParser.parseTagValue(tagMap, "c", `${sig_c_tag_alg}(?:/${sig_c_tag_alg})?`);
		if (msCanonTag === null) {
			return {
				header: "simple",
				body: "simple",
			};
		}

		// canonicalization for header
		let canonicalizationHeader;
		if (msCanonTag[1] === "simple" || msCanonTag[1] === "relaxed") {
			canonicalizationHeader = msCanonTag[1];
		} else {
			throw new DKIM_SigError("DKIM_SIGERROR_UNKNOWN_C_H");
		}

		// canonicalization for body
		let canonicalizationBody;
		if (msCanonTag[2] === undefined) {
			canonicalizationBody = "simple";
		} else {
			if (msCanonTag[2] === "simple" || msCanonTag[2] === "relaxed") {
				canonicalizationBody = msCanonTag[2];
			} else {
				throw new DKIM_SigError("DKIM_SIGERROR_UNKNOWN_C_B");
			}
		}
		return {
			header: canonicalizationHeader,
			body: canonicalizationBody,
		};
	}

	/**
	 * @param {Map<string, string>} tagMap
	 * @returns {string}
	 */
	static _parseSdid(tagMap) {
		// get SDID (plain-text; REQUIRED)
		const SDIDTag = RfcParser.parseTagValue(tagMap, "d", RfcParser.domain_name);
		if (SDIDTag === null) {
			throw new DKIM_SigError("DKIM_SIGERROR_MISSING_D");
		}
		return SDIDTag[0];
	}

	/**
	 * @param {Map<string, string>} tagMap
	 * @returns {string[]}
	 */
	static _parseSignedHeaders(tagMap) {
		// get Signed header fields (plain-text, but see description; REQUIRED)
		const sig_h_tag = `(${hdr_name})(?:${RfcParser.FWS}?:${RfcParser.FWS}?${hdr_name})*`;
		const signedHeadersTag = RfcParser.parseTagValue(tagMap, "h", sig_h_tag);
		if (signedHeadersTag === null) {
			throw new DKIM_SigError("DKIM_SIGERROR_MISSING_H");
		}
		const signedHeaderFields = signedHeadersTag[0].replace(new RegExp(RfcParser.FWS,"g"), "");
		// get the header field names and store them in lower case in an array
		const signedHeaderFieldsArray = signedHeaderFields.split(":").
			map(function (x) {return x.trim().toLowerCase();}).
			filter(function (x) {return x;});
		// check that the from header is included
		if (signedHeaderFieldsArray.indexOf("from") === -1) {
			throw new DKIM_SigError("DKIM_SIGERROR_MISSING_FROM");
		}
		return signedHeaderFieldsArray;
	}

	/**
	 * @param {Map<string, string>} tagMap
	 * @param {string} sdid
	 * @param {dkimSigWarningV2[]} warnings
	 * @returns {{auid: string, auidDomain: string}}
	 */
	static _parseAuid(tagMap, sdid, warnings) {
		// get AUID (dkim-quoted-printable; OPTIONAL, default is an empty local-part
		// followed by an "@" followed by the domain from the "d=" tag)
		// The domain part of the address MUST be the same as, or a subdomain of,
		// the value of the "d=" tag
		/*
		RFC 5321 (the one specified to be used in RFC 5322)
		========

		Local-part = Dot-string / Quoted-string
		Dot-string = Atom *("." Atom)
		Atom = 1*atext
		Quoted-string = DQUOTE *QcontentSMTP DQUOTE
		QcontentSMTP = qtextSMTP / quoted-pairSMTP
		quoted-pairSMTP = %d92 %d32-126
		qtextSMTP = %d32-33 / %d35-91 / %d93-126

		RFC 5322
		========

		local-part = dot-atom / quoted-string / obs-local-part
		quoted-string = [CFWS]
						DQUOTE *([FWS] qcontent) [FWS] DQUOTE
						[CFWS]
		dot-atom = [CFWS] dot-atom-text [CFWS]
		atext = ALPHA / DIGIT / ; Printable US-ASCII
				"!" / "#" / ; characters not including
				"$" / "%" / ; specials. Used for atoms.
				"&" / "'" /
				"*" / "+" /
				"-" / "/" /
				"=" / "?" /
				"^" / "_" /
				"`" / "{" /
				"|" / "}" /
				"~"
		DQUOTE, ASCII value 34
		qcontent = qtext / quoted-pair
		qtext = %d33 / ; Printable US-ASCII
				%d35-91 / ; characters not including
				%d93-126 / ; "\" or the quote character
				obs-qtext	obs-local-part = word *("." word)
		word = atom / quoted-string
		atom = [CFWS] 1*atext [CFWS]
		CFWS = (1*([FWS] comment) [FWS]) / FWS
		quoted-pair = ("\" (VCHAR / WSP)) / obs-qp
		VCHAR          =  %x21-7E ; visible (printing) characters
		obs-qtext = obs-NO-WS-CTL
		obs-NO-WS-CTL = %d1-8 / ; US-ASCII control
						%d11 / ; characters that do not
						%d12 / ; include the carriage
						%d14-31 / ; return, line feed, and
						%d127 ; white space characters

		about RegEx and valid mail addresses:
		http://stackoverflow.com/questions/201323/using-a-regular-expression-to-validate-an-email-address
		*/

		const local_part = RfcParser.dot_atom_text;
		const sig_i_tag = `${local_part}?@(${RfcParser.domain_name})`;
		let AUIDTag = null;
		try {
			AUIDTag = RfcParser.parseTagValue(tagMap, "i", sig_i_tag);
		} catch (exception) {
			if (exception instanceof DKIM_SigError &&
				exception.errorType === "DKIM_SIGERROR_ILLFORMED_I")
			{
				switch (prefs["error.illformed_i.treatAs"]) {
					case 0: // error
						throw exception;
					case 1: // warning
						warnings.push({ name: "DKIM_SIGERROR_ILLFORMED_I" });
						break;
					case 2: // ignore
						break;
					default:
						throw new DKIM_InternalError("invalid error.illformed_i.treatAs");
				}
			} else {
				throw exception;
			}
		}
		if (AUIDTag === null) {
			return {
				auid: `@${sdid}`,
				auidDomain: sdid,
			};
		}
		const auid = AUIDTag[0];
		const auidDomain = AUIDTag[1];
		if (!stringEndsWith(auidDomain, sdid)) {
			throw new DKIM_SigError("DKIM_SIGERROR_SUBDOMAIN_I");
		}
		return {
			auid: auid,
			auidDomain: auidDomain,
		};
	}

	/**
	 * @param {Map<string, string>} tagMap
	 * @returns {number?}
	 */
	static _parseBodyLength(tagMap) {
		// get Body length count (plain-text unsigned decimal integer; OPTIONAL, default is entire body)
		const BodyLengthTag = RfcParser.parseTagValue(tagMap, "l", "[0-9]{1,76}");
		if (BodyLengthTag !== null) {
			return parseInt(BodyLengthTag[0], 10);
		}
		return null;
	}

	/**
	 * @param {Map<string, string>} tagMap
	 * @returns {string}
	 */
	static _parseQueryMethod(tagMap) {
		// get query methods (plain-text; OPTIONAL, default is "dns/txt")
		const sig_q_tag_method = `(?:dns/txt|${hyphenated_word}(?:/${qp_hdr_value})?)`;
		const sig_q_tag = `${sig_q_tag_method}(?:${RfcParser.FWS}?:${RfcParser.FWS}?${sig_q_tag_method})*`;
		const QueryMetTag = RfcParser.parseTagValue(tagMap, "q", sig_q_tag);
		if (QueryMetTag === null) {
			return "dns/txt";
		}
		if (!new RegExp("dns/txt").test(QueryMetTag[0])) {
			throw new DKIM_SigError("DKIM_SIGERROR_UNKNOWN_Q");
		}
		return "dns/txt";
	}

	/**
	 * @param {Map<string, string>} tagMap
	 * @param {dkimSigWarningV2[]} warnings
	 * @returns {string}
	 */
	static _parseSelector(tagMap, warnings) {
		// get selector subdividing the namespace for the "d=" (domain) tag (plain-text; REQUIRED)
		let SelectorTag;
		try {
			SelectorTag = RfcParser.parseTagValue(tagMap, "s", `${RfcParser.sub_domain}(?:\\.${RfcParser.sub_domain})*`);
		} catch (exception) {
			if (exception instanceof DKIM_SigError &&
				exception.errorType === "DKIM_SIGERROR_ILLFORMED_S")
			{
				// try to parse selector in a more relaxed way
				const sub_domain_ = "(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?)";
				SelectorTag = RfcParser.parseTagValue(tagMap, "s", `${sub_domain_}(?:\\.${sub_domain_})*`);
				switch (prefs["error.illformed_s.treatAs"]) {
					case 0: // error
						throw exception;
					case 1: // warning
						warnings.push({name: "DKIM_SIGERROR_ILLFORMED_S"});
						break;
					case 2: // ignore
						break;
					default:
						throw new DKIM_InternalError("invalid error.illformed_s.treatAs");
				}
			} else {
				throw exception;
			}
		}
		if (SelectorTag === null) {
			throw new DKIM_SigError("DKIM_SIGERROR_MISSING_S");
		}
		return SelectorTag[0];
	}

	/**
	 * @param {Map<string, string>} tagMap
	 * @returns {number?}
	 */
	static _parseSignatureTimestamp(tagMap) {
		// get Signature Timestamp (plain-text unsigned decimal integer; RECOMMENDED,
		// default is an unknown creation time)
		const SigTimeTag = RfcParser.parseTagValue(tagMap, "t", "[0-9]+");
		if (SigTimeTag === null) {
			return null;
		}
		return parseInt(SigTimeTag[0], 10);
	}

	/**
	 * @param {Map<string, string>} tagMap
	 * @param {number?} signatureTimestamp
	 * @returns {number?}
	 */
	static _parseSignatureExpiration(tagMap, signatureTimestamp) {
		// get Signature Expiration (plain-text unsigned decimal integer;
		// RECOMMENDED, default is no expiration)
		// The value of the "x=" tag MUST be greater than the value of the "t=" tag if both are present
		const ExpTimeTag = RfcParser.parseTagValue(tagMap, "x", "[0-9]+");
		if (ExpTimeTag === null) {
			return null;
		}
		const signatureExpiration = parseInt(ExpTimeTag[0], 10);
		if (signatureTimestamp !== null && signatureExpiration < signatureTimestamp) {
			throw new DKIM_SigError("DKIM_SIGERROR_TIMESTAMPS");
		}
		return signatureExpiration;
	}

	/**
	 * @param {Map<string, string>} tagMap
	 * @returns {string?}
	 */
	static _parseCopiedHeaders(tagMap) {
		// get Copied header fields (dkim-quoted-printable, but see description; OPTIONAL, default is null)
		const hdr_name_FWS = `(?:(?:[!-9<-~]${RfcParser.FWS}?)+)`;
		const sig_z_tag_copy = `${hdr_name_FWS+RfcParser.FWS}?:${qp_hdr_value}`;
		const sig_z_tag = `${sig_z_tag_copy}(\\|${RfcParser.FWS}?${sig_z_tag_copy})*`;
		const CopyHeaderFieldsTag = RfcParser.parseTagValue(tagMap, "z", sig_z_tag);
		if (CopyHeaderFieldsTag === null) {
			return null;
		}
		return CopyHeaderFieldsTag[0].replace(new RegExp(RfcParser.FWS,"g"), "");
	}
}

class DkimKey {
	/**
	 * parse the DKIM key record
	 * key record is specified in Section 3.6.1 of RFC 6376
	 *
	 * @param {string} DkimKeyRecord
	 */
	constructor(DkimKeyRecord) {
		// parse tag-value list
		const tagMap = RfcParser.parseTagValueList(DkimKeyRecord);
		if (tagMap === -1) {
			throw new DKIM_SigError("DKIM_SIGERROR_KEY_ILLFORMED_TAGSPEC");
		} else if (tagMap === -2) {
			throw new DKIM_SigError("DKIM_SIGERROR_KEY_DUPLICATE_TAG");
		}
		if (!(tagMap instanceof Map)) {
			throw new DKIM_InternalError(`unexpected return value from RfcParser.parseTagValueList: ${tagMap}`);
		}

		// Version
		this.v = DkimKey._parseVersion(tagMap);
		// array hash algorithms
		this.h_array = DkimKey._parseAcceptableHash(tagMap);
		// key type
		this.k = DkimKey._parseKeyType(tagMap);
		// notes
		this.n = DkimKey._parseNotes(tagMap);
		// Public-key data
		this.p = DkimKey._parsePublicKey(tagMap);
		// Service Type
		this.s = DkimKey._parseServiceType(tagMap);
		// array of all flags
		this.t_array = DkimKey._parseFlags(tagMap);
	}

	/**
	 * @param {Map<string, string>} tagMap
	 * @returns {string}
	 */
	static _parseVersion(tagMap) {
		// get version (plain-text; RECOMMENDED, default is "DKIM1")
		// If specified, this tag MUST be set to "DKIM1"
		// This tag MUST be the first tag in the record
		const key_v_tag_value = `${dkim_safe_char}*`;
		const versionTag = RfcParser.parseTagValue(tagMap, "v", key_v_tag_value, 2);
		if (versionTag === null || versionTag[0] === "DKIM1") {
			return "DKIM1";
		}
		throw new DKIM_SigError("DKIM_SIGERROR_KEY_INVALID_V");
	}

	/**
	 * @param {Map<string, string>} tagMap
	 * @returns {string[]|null}
	 */
	static _parseAcceptableHash(tagMap) {
		// get Acceptable hash algorithms (plain-text; OPTIONAL, defaults to allowing all algorithms)
		const key_h_tag_alg = `(?:sha1|sha256|${hyphenated_word})`;
		const key_h_tag = `${key_h_tag_alg}(?:${RfcParser.FWS}?:${RfcParser.FWS}?${key_h_tag_alg})*`;
		const algorithmTag = RfcParser.parseTagValue(tagMap, "h", key_h_tag, 2);
		if (algorithmTag === null) {
			return null;
		}
		return algorithmTag[0].split(":").map(s => s.trim()).filter(function (x) {return x;});
	}

	/**
	 * @param {Map<string, string>} tagMap
	 * @returns {string}
	 */
	static _parseKeyType(tagMap) {
		// get Key type (plain-text; OPTIONAL, default is "rsa")
		const key_k_tag_type = `(?:rsa|${hyphenated_word})`;
		const keyTypeTag = RfcParser.parseTagValue(tagMap, "k", key_k_tag_type, 2);
		if (keyTypeTag === null || keyTypeTag[0] === "rsa") {
			return "rsa";
		}
		throw new DKIM_SigError("DKIM_SIGERROR_KEY_UNKNOWN_K");
	}

	/**
	 * @param {Map<string, string>} tagMap
	 * @returns {string?}
	 */
	static _parseNotes(tagMap) {
		// get Notes (qp-section; OPTIONAL, default is empty)
		const ptext = `(?:${hex_octet}|[!-<>-~])`;
		const qp_section = `(?:(?:${ptext}| |\t)*${ptext})?`;
		const notesTag = RfcParser.parseTagValue(tagMap, "n", qp_section, 2);
		if (notesTag === null) {
			return null;
		}
		return notesTag[0];
	}

	/**
	 * @param {Map<string, string>} tagMap
	 * @returns {string}
	 */
	static _parsePublicKey(tagMap) {
		// get Public-key data (base64; REQUIRED)
		// empty value means that this public key has been revoked
		const keyTag = RfcParser.parseTagValue(tagMap, "p", `${base64string}?`, 2);
		if (keyTag === null) {
			throw new DKIM_SigError("DKIM_SIGERROR_KEY_MISSING_P");
		}
		if (keyTag[0] === "") {
			throw new DKIM_SigError("DKIM_SIGERROR_KEY_REVOKED");
		}
		return keyTag[0];
	}

	/**
	 * @param {Map<string, string>} tagMap
	 * @returns {string}
	 */
	static _parseServiceType(tagMap) {
		// get Service Type (plain-text; OPTIONAL; default is "*")
		const key_s_tag_type = `(?:email|\\*|${hyphenated_word})`;
		const key_s_tag = `${key_s_tag_type}(?:${RfcParser.FWS}?:${RfcParser.FWS}?${key_s_tag_type})*`;
		const serviceTypeTag = RfcParser.parseTagValue(tagMap, "s", key_s_tag, 2);
		if (serviceTypeTag === null) {
			return "*";
		}
		const service_types = serviceTypeTag[0].split(":").map(s => s.trim());
		if (service_types.some(s => s === "*" || s === "email")) {
			return serviceTypeTag[0];
		}
		throw new DKIM_SigError("DKIM_SIGERROR_KEY_NOTEMAILKEY");
	}

	/**
	 * @param {Map<string, string>} tagMap
	 * @returns {string[]}
	 */
	static _parseFlags(tagMap) {
		// get Flags (plaintext; OPTIONAL, default is no flags set)
		const key_t_tag_flag = `(?:y|s|${hyphenated_word})`;
		const key_t_tag = `${key_t_tag_flag}(?:${RfcParser.FWS}?:${RfcParser.FWS}?${key_t_tag_flag})*`;
		const flagsTag = RfcParser.parseTagValue(tagMap, "t", key_t_tag, 2);
		if (flagsTag === null) {
			return [];
		}
		// get the flags and store them in an array
		return flagsTag[0].split(":").map(s => s.trim()).filter(function (x) {return x;});
	}
}

	/**
	 * canonicalize a single header field using the relaxed algorithm
	 * specified in Section 3.4.2 of RFC 6376
	 *
	 * @param {string} headerField
	 * @returns {string}
	 */
	function canonicalizationHeaderFieldRelaxed(headerField) {
		// Convert header field name (not the header field values) to lowercase
		let headerCanonicalized = headerField.replace(
			/^\S[^:]*/,
			function(match) {
				return match.toLowerCase();
			}
		);

		// Unfold header field continuation lines
		headerCanonicalized = headerCanonicalized.replace(/\r\n[ \t]/g," ");

		// Convert all sequences of one or more WSP characters to a single SP character.
		// WSP characters here include those before and after a line folding boundary.
		headerCanonicalized = headerCanonicalized.replace(/[ \t]+/g," ");

		// Delete all WSP characters at the end of each unfolded header field value.
		headerCanonicalized = headerCanonicalized.replace(/[ \t]+\r\n/,"\r\n");

		// Delete any WSP characters remaining before and after the colon
		// separating the header field name from the header field value.
		// The colon separator MUST be retained.
		headerCanonicalized = headerCanonicalized.replace(/[ \t]*:[ \t]*/,":");

		return headerCanonicalized;
	}

	/**
	 * canonicalize the body using the simple algorithm
	 * specified in Section 3.4.3 of RFC 6376
	 *
	 * @param {string} body
	 * @returns {string}
	 */
	function canonicalizationBodySimple(body) {
		// Ignore all empty lines at the end of the message body
		// If there is no body or no trailing CRLF on the message body, a CRLF is added
		// for some reason /(\r\n)*$/ doesn't work all the time
		// (especially in large strings; matching only last "\r\n")
		const bodyCanonicalized = body.replace(/((\r\n)+)?$/,"\r\n");

		return bodyCanonicalized;
	}

	/**
	 * canonicalize the body using the relaxed algorithm
	 * specified in Section 3.4.4 of RFC 6376
	 *
	 * @param {string} body
	 * @returns {string}
	 */
	function canonicalizationBodyRelaxed(body) {
		// Ignore all whitespace at the end of lines
		let bodyCanonicalized = body.replace(/[ \t]+\r\n/g,"\r\n");
		// Reduce all sequences of WSP within a line to a single SP character
		bodyCanonicalized = bodyCanonicalized.replace(/[ \t]+/g," ");

		// Ignore all empty lines at the end of the message body
		// If the body is non-empty but does not end with a CRLF, a CRLF is added
		// for some reason /(\r\n)*$/ doesn't work all the time
		// (especially in large strings; matching only last "\r\n")
		bodyCanonicalized = bodyCanonicalized.replace(/((\r\n)+)?$/,"\r\n");

		// If only one \r\n rests, there were only empty lines or body was empty.
		if (bodyCanonicalized === "\r\n") {
			return "";
		}
		return bodyCanonicalized;
	}

	/**
	 * Computing the Message Hash for the body
	 * specified in Section 3.7 of RFC 6376
	 *
	 * @param {Msg} msg
	 * @param {DkimSignature} DKIMSignature
	 * @returns {Promise<string>}
	 */
	async function computeBodyHash(msg, DKIMSignature) {
		// canonicalize body
		let bodyCanon;
		switch (DKIMSignature.c_body) {
			case "simple":
				bodyCanon = canonicalizationBodySimple(msg.bodyPlain);
				break;
			case "relaxed":
				bodyCanon = canonicalizationBodyRelaxed(msg.bodyPlain);
				break;
			default:
				throw new DKIM_InternalError("unsupported canonicalization algorithm got parsed");
		}
		// if a body length count is given
		if (DKIMSignature.l !== null) {
			// check the value of the body length tag
			if (DKIMSignature.l > bodyCanon.length) {
				// length tag exceeds body size
				log.debug(`bodyCanon.length: ${bodyCanon.length}`);
				throw new DKIM_SigError("DKIM_SIGERROR_TOOLARGE_L");
			} else if (DKIMSignature.l < bodyCanon.length){
				// length tag smaller when body size
				DKIMSignature.warnings.push({name: "DKIM_SIGWARNING_SMALL_L"});
				log.debug("Warning: DKIM_SIGWARNING_SMALL_L");
			}

			// truncated body to the length specified in the "l=" tag
			bodyCanon = bodyCanon.substr(0, DKIMSignature.l);
		}

		// compute body hash
		const bodyHash = await DkimCrypto.digest(DKIMSignature.a_hash, bodyCanon);
		return bodyHash;
	}

	/**
	 * Computing the input for the header Hash
	 * specified in Section 3.7 of RFC 6376
	 *
	 * @param {Msg} msg
	 * @param {DkimSignature} DKIMSignature
	 * @returns {string}
	 */
	function computeHeaderHashInput(msg, DKIMSignature) {
		let hashInput = "";

		// set header canonicalization algorithm
		let headerCanonAlgo;
		switch (DKIMSignature.c_header) {
			case "simple":
				// @ts-expect-error
				headerCanonAlgo = function (headerField) {return headerField;};
				break;
			case "relaxed":
				headerCanonAlgo = canonicalizationHeaderFieldRelaxed;
				break;
			default:
				throw new DKIM_InternalError("unsupported canonicalization algorithm (header) got parsed");
		}

		// copy header fields
		/** @type {Map<string, string[]>} */
		const headerFields = new Map();
		for (const [key, val] of msg.headerFields) {
			headerFields.set(key, val.slice());
		}

		// get header fields specified by the "h=" tag
		// and join their canonicalized form
		for(let i = 0; i < DKIMSignature.h_array.length; i++) {
			// if multiple instances of the same header field are signed
			// include them in reverse order (from bottom to top)
			const headerFieldArray = headerFields.get(DKIMSignature.h_array[i]);
			// nonexisting header field MUST be treated as the null string
			if (headerFieldArray !== undefined) {
				const headerField = headerFieldArray.pop();
				if (headerField) {
					hashInput += headerCanonAlgo(headerField);
				}
			}
		}

		// add DKIM-Signature header to the hash input
		// with the value of the "b=" tag (including all surrounding whitespace) deleted
		const pos_bTag = DKIMSignature.original_header.indexOf(DKIMSignature.b_folded);
		let tempBegin = DKIMSignature.original_header.substr(0, pos_bTag);
		tempBegin = tempBegin.replace(new RegExp(`${RfcParser.FWS}?$`), "");
		let tempEnd = DKIMSignature.original_header.substr(pos_bTag+DKIMSignature.b_folded.length);
		tempEnd = tempEnd.replace(new RegExp(`^${RfcParser.FWS}?`), "");
		let temp = tempBegin + tempEnd;
		// canonicalized using the header canonicalization algorithm specified in the "c=" tag
		temp = headerCanonAlgo(temp);
		// without a trailing CRLF
		hashInput += temp.substr(0, temp.length - 2);

		return hashInput;
	}

	/**
	 * handles Exception
	 *
	 * @param {Error} e
	 * @param {DkimSignature|Object.<string, undefined>} [dkimSignature]
	 * @return {dkimSigResultV2}
	 */
	function handleException(e, dkimSignature = {} ) {
		if (e instanceof DKIM_SigError) {
			// return result
			const result = {
				version : "2.0",
				result : "PERMFAIL",
				sdid : dkimSignature.d,
				auid : dkimSignature.i,
				selector : dkimSignature.s,
				errorType : e.errorType,
				errorStrParams : e.errorStrParams,
				hideFail : e.errorType === "DKIM_SIGERROR_KEY_TESTMODE",
				keySecure : dkimSignature.keySecure,
			};

			log.warn(e);

			return result;
		}
		// return result
		/** @type {dkimSigResultV2} */
		const result = {
			version : "2.0",
			result : "TEMPFAIL",
			sdid : dkimSignature.d,
			auid : dkimSignature.i,
			selector : dkimSignature.s,
		};

		if (e instanceof DKIM_InternalError) {
			result.errorType = e.errorType;
			log.error(e);
		} else {
			log.fatal(e);
		}

		return result;
	}

	/**
	 * Verifying a single DKIM signature
	 *
	 * @param {Msg} msg
	 * @param {DkimSignature} DKIMSignature
	 * @return {Promise<dkimSigResultV2>}
	 * @throws DKIM_SigError
	 * @throws DKIM_InternalError
	 */
	async function verifySignature(msg, DKIMSignature) { // eslint-disable-line complexity
		// warning if from is not in SDID or AUID
		if (!addrIsInDomain(msg.from, DKIMSignature.d)) {
			DKIMSignature.warnings.push({ name: "DKIM_SIGWARNING_FROM_NOT_IN_SDID" });
			log.debug("Warning: DKIM_SIGWARNING_FROM_NOT_IN_SDID");
		} else if (!stringEndsWith(msg.from, DKIMSignature.i)) {
			DKIMSignature.warnings.push({ name: "DKIM_SIGWARNING_FROM_NOT_IN_AUID" });
			log.debug("Warning: DKIM_SIGWARNING_FROM_NOT_IN_AUID");
		}

		const time = Math.round(Date.now() / 1000);
		// warning if signature expired
		if (DKIMSignature.x !== null && DKIMSignature.x < time) {
			DKIMSignature.warnings.push({name: "DKIM_SIGWARNING_EXPIRED"});
			log.debug("Warning: DKIM_SIGWARNING_EXPIRED");
		}
		// warning if signature in future
		if (DKIMSignature.t !== null && DKIMSignature.t > time) {
			DKIMSignature.warnings.push({name: "DKIM_SIGWARNING_FUTURE"});
			log.debug("Warning: DKIM_SIGWARNING_FUTURE");
		}

		// Compute the Message hash for the body
		const bodyHash = await computeBodyHash(msg, DKIMSignature);
		log.debug("computed body hash:", bodyHash);

		// compare body hash
		if (bodyHash !== DKIMSignature.bh) {
			throw new DKIM_SigError("DKIM_SIGERROR_CORRUPT_BH");
		}

		log.trace("Receiving DNS key for DKIM-Signature ...");
		const keyQueryResult = await getKey(DKIMSignature.d, DKIMSignature.s);
		// eslint-disable-next-line require-atomic-updates
		DKIMSignature.keySecure = keyQueryResult.secure;
		log.trace("Received DNS key for DKIM-Signature");

		// if key is not signed by DNSSEC
		if (!keyQueryResult.secure) {
			switch (prefs["error.policy.key_insecure.treatAs"]) {
				case 0: // error
					throw new DKIM_SigError("DKIM_POLICYERROR_KEY_INSECURE");
				case 1: // warning
					DKIMSignature.warnings.push({name: "DKIM_POLICYERROR_KEY_INSECURE"});
					log.debug("Warning: DKIM_POLICYERROR_KEY_INSECURE");
					break;
				case 2: // ignore
					break;
				default:
					throw new DKIM_InternalError("invalid error.policy.key_insecure.treatAs");
			}
		}

		const dkimKey = new DkimKey(keyQueryResult.key);
		log.debug("Parsed DKIM-Key:", dkimKey);

		// check that the testing flag is not set
		if (dkimKey.t_array.indexOf("y") !== -1) {
			if (prefs["error.key_testmode.ignore"]) {
				DKIMSignature.warnings.push({name: "DKIM_SIGERROR_KEY_TESTMODE"});
				log.debug("Warning: DKIM_SIGERROR_KEY_TESTMODE");
			} else {
				throw new DKIM_SigError( "DKIM_SIGERROR_KEY_TESTMODE" );
			}
		}

		// if s flag is set in DKIM key record
		// AUID must be from the same domain as SDID (and not a subdomain)
		if (dkimKey.t_array.indexOf("s") !== -1 &&
		    !stringEqual(DKIMSignature.i_domain, DKIMSignature.d)) {
			throw new DKIM_SigError("DKIM_SIGERROR_DOMAIN_I");
		}

		// If the "h=" tag exists in the DKIM key record
		// the hash algorithm implied by the "a=" tag in the DKIM-Signature header field
		// must be included in the contents of the "h=" tag
		if (dkimKey.h_array &&
		    dkimKey.h_array.indexOf(DKIMSignature.a_hash) === -1) {
			throw new DKIM_SigError( "DKIM_SIGERROR_KEY_HASHNOTINCLUDED" );
		}

		// Compute the input for the header hash
		const headerHashInput = computeHeaderHashInput(msg,DKIMSignature);
		log.debug(`Header hash input:\n${headerHashInput}`);

		// verify Signature
		const [isValid, keyLength] = await DkimCrypto.verifyRSA(
			dkimKey.p,
			DKIMSignature.a_hash,
			DKIMSignature.b,
			headerHashInput
		);
		if (!isValid) {
			throw new DKIM_SigError("DKIM_SIGERROR_BADSIG");
		}

		if (keyLength < 1024) {
			// error if key is too short
			log.debug(`rsa key size: ${keyLength}`);
			throw new DKIM_SigError( "DKIM_SIGWARNING_KEYSMALL" );
		} else if (keyLength < 2048) {
			// weak key
			log.debug(`rsa key size: ${keyLength}`);
			switch (prefs["error.algorithm.rsa.weakKeyLength.treatAs"]) {
				case 0: // error
					throw new DKIM_SigError("DKIM_SIGWARNING_KEY_IS_WEAK");
				case 1: // warning
					DKIMSignature.warnings.push({name: "DKIM_SIGWARNING_KEY_IS_WEAK"});
					log.debug("Warning: DKIM_SIGWARNING_KEY_IS_WEAK");
					break;
				case 2: // ignore
					break;
				default:
					throw new DKIM_InternalError("invalid error.algorithm.rsa.weakKeyLength.treatAs");
			}
		}

		// return result
		log.trace("Everything is fine");
		const verification_result = {
			version : "2.0",
			result : "SUCCESS",
			sdid : DKIMSignature.d,
			auid : DKIMSignature.i,
			selector : DKIMSignature.s,
			warnings : DKIMSignature.warnings,
			keySecure : keyQueryResult.secure,
		};
		return verification_result;
	}

	/**
	 * processes signatures
	 *
	 * @param {Msg} msg
	 * @return {Promise<dkimSigResultV2[]>}
	 */
	async function processSignatures(msg) {
		let iDKIMSignatureIdx = 0;
		let dkimSignature;
		// contains the result of all DKIM-Signatures which have been verified
		/** @type {dkimSigResultV2[]} */
		const sigResults = [];

		const dkimSignatureHeaders = msg.headerFields.get("dkim-signature");
		if (dkimSignatureHeaders) {
			log.debug(`${dkimSignatureHeaders.length} DKIM-Signatures found.`);
		} else {
			return sigResults;
		}

		// RFC6376 - 3.5.  The DKIM-Signature Header Field
		// "The DKIM-Signature header field SHOULD be treated as though it were a
		// trace header field as defined in Section 3.6 of [RFC5322] and hence
		// SHOULD NOT be reordered and SHOULD be prepended to the message."
		//
		// The first added signature is verified first.
		for (iDKIMSignatureIdx = dkimSignatureHeaders.length - 1;
		     iDKIMSignatureIdx >=0; iDKIMSignatureIdx--) {
			let sigRes;
			try {
				log.debug(`Verifying DKIM-Signature ${iDKIMSignatureIdx+1} ...`);
				dkimSignature = new DkimSignature(dkimSignatureHeaders[iDKIMSignatureIdx]);
				log.debug(`Parsed DKIM-Signature ${iDKIMSignatureIdx+1}:`, dkimSignature);
				sigRes = await verifySignature(msg, dkimSignature);
				log.debug(`Verified DKIM-Signature ${iDKIMSignatureIdx+1}`);
			} catch(e) {
				sigRes = handleException(e, dkimSignature);
				log.debug(`Exception on DKIM-Signature ${iDKIMSignatureIdx+1}`);
			}

			log.trace(`Adding DKIM-Signature ${iDKIMSignatureIdx+1} result to result list`);
			sigResults.push(sigRes);
		}

		return sigResults;
	}

	/**
	 * Checks if at least on signature exists.
	 * If not, adds one to signatures with result "no sig"
	 *
	 * @param {Msg} msg
	 * @param {dkimSigResultV2[]} signatures
	 * @return {void}
	 */
	function checkForSignatureExistence(msg, signatures) {
		// check if a DKIM signature exists
		if (signatures.length === 0) {
			const dkimSigResultV2 = {
					version: "2.0",
					result: "none",
			};
			signatures.push(dkimSigResultV2);
		}
	}

export default class Verifier {
	/**
	 * @typedef {Object} Msg
	 * @property {Map<String, String[]>} headerFields
	 * @property {String} bodyPlain
	 * @property {String} from
	 * @property {String} listId
	 */

	/**
	 * Verifies the message given message.
	 *
	 * @param {Msg} msg
	 * @return {Promise<dkimResultV2>}
	 */
	verify(msg) {
		const promise = (async () => {
			await prefs.init();
			const res = {
				version: "2.0",
				signatures: await processSignatures(msg),
			};
			checkForSignatureExistence(msg, res.signatures);
			// eslint-disable-next-line no-use-before-define
			sortSignatures(res.signatures, msg.from, msg.listId);
			return res;
		})();
		promise.then(null, function onReject(exception) {
			log.warn("verify failed", exception);
		});
		return promise;
	}
}

	/**
	 * Creates a message object given the msgURI.
	 *
	 * @param {String} msgURI
	 * @return {Promise<Msg>}
	 */
	function createMsg(msgURI) {
		const promise = (async () => {
			// read msg
			/** @type {Msg} */
			const msg = await MsgReader.read(msgURI);
			msg.msgURI = msgURI;

			// parse the header
			msg.headerFields = MsgReader.parseHeader(msg.headerPlain);

			const msgHeaderParser = Cc["@mozilla.org/messenger/headerparser;1"].
				createInstance(Ci.nsIMsgHeaderParser);

			// get last from address
			if (msg.headerFields.has("from")) {
				// @ts-ignore
				const numFrom = msg.headerFields.get("from").length;
				// @ts-ignore
				let author = msg.headerFields.get("from")[numFrom-1];
				author = author.replace(/^From[ \t]*:/i,"");
				msg.from = msgHeaderParser.extractHeaderAddressMailboxes(author);
			} else {
				throw new DKIM_InternalError("E-Mail has no from address");
			}

			// get list-id
			if (msg.headerFields.has("list-id")) {
				// @ts-ignore
				msg.listId = msg.headerFields.get("list-id")[0];
				msg.listId = msgHeaderParser.extractHeaderAddressMailboxes(msg.listId);
			}

			// check if msg should be signed by DKIM
			msg.DKIMSignPolicy = await Policy.shouldBeSigned(msg.from, msg.listId);

			return msg;
		})();
		promise.then(null, function onReject(exception) {
			log.warn("createMsg failed", exception);
		});
		return promise;
	}

	/**
	 * Sorts the given signatures.
	 *
	 * @param {dkimSigResultV2[]} signatures
	 * @param {string} from
	 * @param {string} [listId]
	 * @return {void}
	 */
	export function sortSignatures(signatures, from, listId) {
		/**
		 * @param {dkimSigResultV2} sig1
		 * @param {dkimSigResultV2} sig2
		 * @returns {number}
		 */
		function result_compare(sig1, sig2) {
			if (sig1.result === sig2.result) {
				return 0;
			}

			if (sig1.result === "SUCCESS") {
				return -1;
			} else if (sig2.result === "SUCCESS") {
				return 1;
			}

			if (sig1.result === "TEMPFAIL") {
				return -1;
			} else if (sig2.result === "TEMPFAIL") {
				return 1;
			}

			if (sig1.result === "PERMFAIL") {
				return -1;
			} else if (sig2.result === "PERMFAIL") {
				return 1;
			}

			throw new DKIM_InternalError(`result_compare: sig1.result: ${sig1.result}; sig2.result: ${sig2.result}`);
		}

		/**
		 * @param {dkimSigResultV2} sig1
		 * @param {dkimSigResultV2} sig2
		 * @returns {number}
		 */
		function warnings_compare(sig1, sig2) {
			if (sig1.result !== "SUCCESS") {
				return 0;
			}
			if (!sig1.warnings || sig1.warnings.length === 0) {
				// sig1 has no warnings
				if (!sig2.warnings || sig2.warnings.length === 0) {
					// both signatures have no warnings
					return 0;
				}
				// sig2 has warnings
				return -1;
			}
			// sig1 has warnings
			if (!sig2.warnings || sig2.warnings.length === 0) {
				// sig2 has no warnings
				return 1;
			}
			// both signatures have warnings
			return 0;
		}

		/**
		 * @param {dkimSigResultV2} sig1
		 * @param {dkimSigResultV2} sig2
		 * @returns {number}
		 */
		function sdid_compare(sig1, sig2) {
			if (sig1.sdid === sig2.sdid) {
				return 0;
			}

			if (sig1.sdid && addrIsInDomain2(from, sig1.sdid)) {
				return -1;
			} else if (sig2.sdid && addrIsInDomain2(from, sig2.sdid)) {
				return 1;
			}

			if (listId) {
				if (sig1.sdid && domainIsInDomain(listId, sig1.sdid)) {
					return -1;
				} else if (sig2.sdid && domainIsInDomain(listId, sig2.sdid)) {
					return 1;
				}
			}

			return 0;
		}

		signatures.sort(function (sig1, sig2) {
			let cmp;
			cmp = result_compare(sig1, sig2);
			if (cmp !== 0) {
				return cmp;
			}
			cmp = warnings_compare(sig1, sig2);
			if (cmp !== 0) {
				return cmp;
			}
			cmp = sdid_compare(sig1, sig2);
			if (cmp !== 0) {
				return cmp;
			}
			return -1;
		});
	}
