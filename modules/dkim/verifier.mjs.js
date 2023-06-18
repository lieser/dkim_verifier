/**
 * Verifies the DKIM-Signatures as specified in RFC 6376.
 * https://www.rfc-editor.org/rfc/rfc6376.html
 *
 * Included Updates to the RFC:
 * - RFC 8301 https://www.rfc-editor.org/rfc/rfc8301.html
 * - RFC 8463 https://www.rfc-editor.org/rfc/rfc8463.html
 *
 * Copyright (c) 2013-2023 Philippe Lieser
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

import { DKIM_InternalError, DKIM_SigError } from "../error.mjs.js";
import { addrIsInDomain, copy, stringEndsWith, stringEqual } from "../utils.mjs.js";
import prefs, { BasePreferences } from "../preferences.mjs.js";
import DkimCrypto from "./crypto.mjs.js";
import KeyStore from "./keyStore.mjs.js";
import Logging from "../logging.mjs.js";
import MsgParser from "../msgParser.mjs.js";
import RfcParser from "../rfcParser.mjs.js";

/**
 * The result of the verification (Version 1).
 *
 * @typedef {object} dkimResultV1
 * @property {string} version
 * Result version ("1.0" / "1.1").
 * @property {string} result
 * "none" / "SUCCESS" / "PERMFAIL" / "TEMPFAIL"
 * @property {string} [SDID]
 * Required if result="SUCCESS".
 * @property {string} [selector]
 * Added in version 1.1.
 * @property {string[]} [warnings]
 * Required if result="SUCCESS".
 * @property {string} [errorType]
 * - if result="PERMFAIL: DKIM_SigError.errorType
 * - if result="TEMPFAIL: DKIM_InternalError.errorType or Undefined
 * @property {string} [shouldBeSignedBy]
 * Added in version 1.1.
 * @property {boolean} [hideFail]
 * Added in version 1.1.
 */

/**
 * @typedef {object} dkimSigWarningV2
 * @property {string} name - Name of the warning
 * @property {(string|string[])[]} [params] - optional params for formatted string
 */

/**
 * The result of the verification of a single DKIM signature (Version 2).
 *
 * @typedef {object} dkimSigResultV2
 * @property {string} version
 * Result version ("2.0").
 * @property {string} result
 * "none" / "SUCCESS" / "PERMFAIL" / "TEMPFAIL"
 * @property {string|undefined} [sdid]
 * @property {string|undefined} [auid]
 * @property {string|undefined} [selector]
 * @property {dkimSigWarningV2[]} [warnings]
 * Array of warning_objects.
 * Required if result="SUCCESS".
 * @property {string|undefined} [errorType]
 * - if result="PERMFAIL: DKIM_SigError.errorType or Undefined
 * - if result="TEMPFAIL: DKIM_InternalError.errorType or Undefined
 * @property {string[]} [errorStrParams]
 * @property {boolean|undefined} [hideFail]
 * @property {boolean} [keySecure]
 */

/**
 * The result of the verification (Version 2).
 *
 * @typedef {object} dkimResultV2
 * @property {string} version
 * Result version ("2.0").
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
 * Parse and represent the raw DKIM-Signature header.
 */
class DkimSignatureHeader {
	/**
	 * Parse the DKIM-Signature header field.
	 * The header field is specified in Section 3.5 of RFC 6376.
	 *
	 * @param {string} dkimSignatureHeader
	 */
	constructor(dkimSignatureHeader) {
		/**
		 * The unparsed original header.
		 *
		 * @readonly
		 */
		this.original_header = dkimSignatureHeader;

		// strip DKIM-Signature header name
		let dkimHeader = dkimSignatureHeader.replace(/^DKIM-Signature[ \t]*:/i, "");
		// strip the \r\n at the end
		dkimHeader = dkimHeader.substr(0, dkimHeader.length - 2);
		// parse tag-value list
		const tagMap = RfcParser.parseTagValueList(dkimHeader);
		if (tagMap === RfcParser.TAG_PARSE_ERROR.ILL_FORMED) {
			throw new DKIM_SigError("DKIM_SIGERROR_ILLFORMED_TAGSPEC");
		} else if (tagMap === RfcParser.TAG_PARSE_ERROR.DUPLICATE) {
			throw new DKIM_SigError("DKIM_SIGERROR_DUPLICATE_TAG");
		}
		if (!(tagMap instanceof Map)) {
			throw new DKIM_InternalError(`unexpected return value from RfcParser.parseTagValueList: ${tagMap}`);
		}

		/** @type {dkimSigWarningV2[]} */
		const warnings = [];

		/**
		 * Version.
		 *
		 * @readonly
		 */
		this.v = DkimSignatureHeader.#parseVersion(tagMap);

		const signatureAlgorithms = DkimSignatureHeader.#parseSignatureAlgorithms(tagMap, warnings);
		/**
		 * Signature algorithm (signing part).
		 *
		 * @readonly
		 */
		this.a_sig = signatureAlgorithms.signature;
		/**
		 * Signature algorithm (hashing part).
		 *
		 * @readonly
		 */
		this.a_hash = signatureAlgorithms.hash;

		const signatureData = DkimSignatureHeader.#parseSignatureData(tagMap);
		/**
		 * Signature (unfolded).
		 *
		 * @readonly
		 */
		this.b = signatureData.b;
		/**
		 * Signature (still folded).
		 *
		 * @readonly
		 */
		this.b_folded = signatureData.bFolded;

		/**
		 * Body hash.
		 *
		 * @readonly
		 */
		this.bh = DkimSignatureHeader.#parseBodyHash(tagMap);

		const canonicalization = DkimSignatureHeader.#parseCanonicalization(tagMap);
		/**
		 * Canonicalization for header.
		 *
		 * @readonly
		 */
		this.c_header = canonicalization.header;
		/**
		 * Canonicalization for body.
		 *
		 * @readonly
		 */
		this.c_body = canonicalization.body;

		/**
		 * Signing Domain Identifier (SDID) claiming responsibility.
		 *
		 * @readonly
		 */
		this.d = DkimSignatureHeader.#parseSdid(tagMap);

		/**
		 * Array of Signed header fields.
		 *
		 * @readonly
		 * @type {Readonly<string[]>}
		 */
		this.h_array = DkimSignatureHeader.#parseSignedHeaders(tagMap);

		const auid = DkimSignatureHeader.#parseAuid(tagMap, this.d, warnings);
		/**
		 * Agent or User Identifier (AUID) on behalf of which the SDID is taking responsibility.
		 *
		 * @readonly
		 */
		this.i = auid.auid;
		/**
		 * Domain part of AUID.
		 *
		 * @readonly
		 */
		this.i_domain = auid.auidDomain;

		/**
		 * Body length count.
		 *
		 * @readonly
		 */
		this.l = DkimSignatureHeader.#parseBodyLength(tagMap);

		/**
		 * Query methods for public key retrieval.
		 *
		 * @readonly
		 */
		this.q = DkimSignatureHeader.#parseQueryMethod(tagMap);

		/**
		 * Selector.
		 *
		 * @readonly
		 */
		this.s = DkimSignatureHeader.#parseSelector(tagMap, warnings);

		/**
		 * Signature Timestamp.
		 *
		 * @readonly
		 */
		this.t = DkimSignatureHeader.#parseSignatureTimestamp(tagMap);
		/**
		 * Signature Expiration.
		 *
		 * @readonly
		 */
		this.x = DkimSignatureHeader.#parseSignatureExpiration(tagMap, this.t);

		/**
		 * Copied header fields.
		 *
		 * @readonly
		 */
		this.z = DkimSignatureHeader.#parseCopiedHeaders(tagMap);

		/** @type {Readonly<dkimSigWarningV2[]>} */
		this.warnings = warnings;
	}

	/**
	 * @param {ReadonlyMap<string, string>} tagMap
	 * @returns {string}
	 */
	static #parseVersion(tagMap) {
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
	 * @param {ReadonlyMap<string, string>} tagMap
	 * @param {dkimSigWarningV2[]} warnings
	 * @returns {{signature: string, hash: string}}
	 */
	static #parseSignatureAlgorithms(tagMap, warnings) {
		// get signature algorithm (plain-text;REQUIRED)
		// currently only "rsa-sha1" or "rsa-sha256" or "ed25519-sha256"
		const sig_a_tag_k = "(rsa|ed25519|[A-Za-z](?:[A-Za-z]|[0-9])*)";
		const sig_a_tag_h = "(sha1|sha256|[A-Za-z](?:[A-Za-z]|[0-9])*)";
		const sig_a_tag_alg = `${sig_a_tag_k}-${sig_a_tag_h}`;
		const algorithmTag = RfcParser.parseTagValue(tagMap, "a", sig_a_tag_alg);
		if (algorithmTag === null) {
			throw new DKIM_SigError("DKIM_SIGERROR_MISSING_A");
		}
		if (!algorithmTag[1] || !algorithmTag[2]) {
			throw new DKIM_InternalError("Error matching the a-tag.");
		}
		if (algorithmTag[0] === "rsa-sha256" || algorithmTag[0] === "ed25519-sha256") {
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
	 * @param {ReadonlyMap<string, string>} tagMap
	 * @returns {{b: string, bFolded: string}}
	 */
	static #parseSignatureData(tagMap) {
		// get signature data (base64;REQUIRED)
		const signatureDataTag = RfcParser.parseTagValue(tagMap, "b", base64string);
		if (signatureDataTag === null) {
			throw new DKIM_SigError("DKIM_SIGERROR_MISSING_B");
		}
		return {
			b: signatureDataTag[0].replace(new RegExp(RfcParser.FWS, "g"), ""),
			bFolded: signatureDataTag[0],
		};
	}

	/**
	 * @param {ReadonlyMap<string, string>} tagMap
	 * @returns {string}
	 */
	static #parseBodyHash(tagMap) {
		// get body hash (base64;REQUIRED)
		const bodyHashTag = RfcParser.parseTagValue(tagMap, "bh", base64string);
		if (bodyHashTag === null) {
			throw new DKIM_SigError("DKIM_SIGERROR_MISSING_BH");
		}
		return bodyHashTag[0].replace(new RegExp(RfcParser.FWS, "g"), "");
	}

	/**
	 * @param {ReadonlyMap<string, string>} tagMap
	 * @returns {{header: string, body: string}}
	 */
	static #parseCanonicalization(tagMap) {
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
	 * @param {ReadonlyMap<string, string>} tagMap
	 * @returns {string}
	 */
	static #parseSdid(tagMap) {
		// get SDID (plain-text; REQUIRED)
		const SDIDTag = RfcParser.parseTagValue(tagMap, "d", RfcParser.domain_name);
		if (SDIDTag === null) {
			throw new DKIM_SigError("DKIM_SIGERROR_MISSING_D");
		}
		return SDIDTag[0];
	}

	/**
	 * @param {ReadonlyMap<string, string>} tagMap
	 * @returns {string[]}
	 */
	static #parseSignedHeaders(tagMap) {
		// get Signed header fields (plain-text, but see description; REQUIRED)
		const sig_h_tag = `(${hdr_name})(?:${RfcParser.FWS}?:${RfcParser.FWS}?${hdr_name})*`;
		const signedHeadersTag = RfcParser.parseTagValue(tagMap, "h", sig_h_tag);
		if (signedHeadersTag === null) {
			throw new DKIM_SigError("DKIM_SIGERROR_MISSING_H");
		}
		const signedHeaderFields = signedHeadersTag[0].replace(new RegExp(RfcParser.FWS, "g"), "");
		// get the header field names and store them in lower case in an array
		const signedHeaderFieldsArray = signedHeaderFields.split(":").
			map((x) => x.trim().toLowerCase()).
			filter((x) => x);
		// check that the from header is included
		if (!signedHeaderFieldsArray.includes("from")) {
			throw new DKIM_SigError("DKIM_SIGERROR_MISSING_FROM");
		}
		return signedHeaderFieldsArray;
	}

	/**
	 * @param {ReadonlyMap<string, string>} tagMap
	 * @param {string} sdid
	 * @param {dkimSigWarningV2[]} warnings
	 * @returns {{auid: string, auidDomain: string}}
	 */
	static #parseAuid(tagMap, sdid, warnings) {
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
			if (exception instanceof DKIM_SigError && exception.errorType === "DKIM_SIGERROR_ILLFORMED_I") {
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
		if (!AUIDTag[1]) {
			throw new DKIM_InternalError("Error matching the i-tag.");
		}
		const auid = AUIDTag[0];
		const auidDomain = AUIDTag[1];
		if (!stringEndsWith(auidDomain, sdid)) {
			throw new DKIM_SigError("DKIM_SIGERROR_SUBDOMAIN_I");
		}
		return {
			auid,
			auidDomain,
		};
	}

	/**
	 * @param {ReadonlyMap<string, string>} tagMap
	 * @returns {number?}
	 */
	static #parseBodyLength(tagMap) {
		// get Body length count (plain-text unsigned decimal integer; OPTIONAL, default is entire body)
		const BodyLengthTag = RfcParser.parseTagValue(tagMap, "l", "[0-9]{1,76}");
		if (BodyLengthTag !== null) {
			return parseInt(BodyLengthTag[0], 10);
		}
		return null;
	}

	/**
	 * @param {ReadonlyMap<string, string>} tagMap
	 * @returns {string}
	 */
	static #parseQueryMethod(tagMap) {
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
	 * @param {ReadonlyMap<string, string>} tagMap
	 * @param {dkimSigWarningV2[]} warnings
	 * @returns {string}
	 */
	static #parseSelector(tagMap, warnings) {
		// get selector subdividing the namespace for the "d=" (domain) tag (plain-text; REQUIRED)
		let SelectorTag;
		try {
			SelectorTag = RfcParser.parseTagValue(tagMap, "s", `${RfcParser.sub_domain}(?:\\.${RfcParser.sub_domain})*`);
		} catch (exception) {
			if (exception instanceof DKIM_SigError && exception.errorType === "DKIM_SIGERROR_ILLFORMED_S") {
				// try to parse selector in a more relaxed way
				const sub_domain_ = "(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?)";
				SelectorTag = RfcParser.parseTagValue(tagMap, "s", `${sub_domain_}(?:\\.${sub_domain_})*`);
				switch (prefs["error.illformed_s.treatAs"]) {
					case 0: // error
						throw exception;
					case 1: // warning
						warnings.push({ name: "DKIM_SIGERROR_ILLFORMED_S" });
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
	 * @param {ReadonlyMap<string, string>} tagMap
	 * @returns {number?}
	 */
	static #parseSignatureTimestamp(tagMap) {
		// get Signature Timestamp (plain-text unsigned decimal integer; RECOMMENDED,
		// default is an unknown creation time)
		const SigTimeTag = RfcParser.parseTagValue(tagMap, "t", "[0-9]+");
		if (SigTimeTag === null) {
			return null;
		}
		return parseInt(SigTimeTag[0], 10);
	}

	/**
	 * @param {ReadonlyMap<string, string>} tagMap
	 * @param {number?} signatureTimestamp
	 * @returns {number?}
	 */
	static #parseSignatureExpiration(tagMap, signatureTimestamp) {
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
	 * @param {ReadonlyMap<string, string>} tagMap
	 * @returns {string?}
	 */
	static #parseCopiedHeaders(tagMap) {
		// get Copied header fields (dkim-quoted-printable, but see description; OPTIONAL, default is null)
		const hdr_name_FWS = `(?:(?:[!-9<-~]${RfcParser.FWS}?)+)`;
		const sig_z_tag_copy = `${hdr_name_FWS + RfcParser.FWS}?:${qp_hdr_value}`;
		const sig_z_tag = `${sig_z_tag_copy}(\\|${RfcParser.FWS}?${sig_z_tag_copy})*`;
		const CopyHeaderFieldsTag = RfcParser.parseTagValue(tagMap, "z", sig_z_tag);
		if (CopyHeaderFieldsTag === null) {
			return null;
		}
		return CopyHeaderFieldsTag[0].replace(new RegExp(RfcParser.FWS, "g"), "");
	}
}

/**
 * Parse and represent the raw DKIM key record.
 */
class DkimKey {
	/**
	 * Parse the DKIM key record.
	 * The key record is specified in Section 3.6.1 of RFC 6376.
	 *
	 * @param {string} DkimKeyRecord
	 */
	constructor(DkimKeyRecord) {
		// parse tag-value list
		const tagMap = RfcParser.parseTagValueList(DkimKeyRecord);
		if (tagMap === RfcParser.TAG_PARSE_ERROR.ILL_FORMED) {
			throw new DKIM_SigError("DKIM_SIGERROR_KEY_ILLFORMED_TAGSPEC");
		} else if (tagMap === RfcParser.TAG_PARSE_ERROR.DUPLICATE) {
			throw new DKIM_SigError("DKIM_SIGERROR_KEY_DUPLICATE_TAG");
		}
		if (!(tagMap instanceof Map)) {
			throw new DKIM_InternalError(`unexpected return value from RfcParser.parseTagValueList: ${tagMap}`);
		}

		/**
		 * Version.
		 *
		 * @readonly
		 */
		this.v = DkimKey.#parseVersion(tagMap);
		/**
		 * Array hash algorithms.
		 *
		 * @readonly
		 * @type {Readonly<string[]|null>}
		 */
		this.h_array = DkimKey.#parseAcceptableHash(tagMap);
		/**
		 * Key type.
		 *
		 * @readonly
		 */
		this.k = DkimKey.#parseKeyType(tagMap);
		/**
		 * Notes.
		 *
		 * @readonly
		 */
		this.n = DkimKey.#parseNotes(tagMap);
		/**
		 * Public-key data.
		 *
		 * @readonly
		 */
		this.p = DkimKey.#parsePublicKey(tagMap);
		/**
		 * Service Type.
		 *
		 * @readonly
		 */
		this.s = DkimKey.#parseServiceType(tagMap);
		/**
		 * Array of all flags.
		 *
		 * @readonly
		 * @type {Readonly<string[]>}
		 */
		this.t_array = DkimKey.#parseFlags(tagMap);
	}

	/**
	 * @param {ReadonlyMap<string, string>} tagMap
	 * @returns {string}
	 */
	static #parseVersion(tagMap) {
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
	 * @param {ReadonlyMap<string, string>} tagMap
	 * @returns {string[]|null}
	 */
	static #parseAcceptableHash(tagMap) {
		// get Acceptable hash algorithms (plain-text; OPTIONAL, defaults to allowing all algorithms)
		const key_h_tag_alg = `(?:sha1|sha256|${hyphenated_word})`;
		const key_h_tag = `${key_h_tag_alg}(?:${RfcParser.FWS}?:${RfcParser.FWS}?${key_h_tag_alg})*`;
		const algorithmTag = RfcParser.parseTagValue(tagMap, "h", key_h_tag, 2);
		if (algorithmTag === null) {
			return null;
		}
		return algorithmTag[0].split(":").map(s => s.trim()).filter((x) => x);
	}

	/**
	 * @param {ReadonlyMap<string, string>} tagMap
	 * @returns {string}
	 */
	static #parseKeyType(tagMap) {
		// get Key type (plain-text; OPTIONAL, default is "rsa")
		const key_k_tag_type = `(?:rsa|ed25519|${hyphenated_word})`;
		const keyTypeTag = RfcParser.parseTagValue(tagMap, "k", key_k_tag_type, 2);
		if (keyTypeTag === null || keyTypeTag[0] === "rsa") {
			return "rsa";
		} else if (keyTypeTag[0] === "ed25519") {
			return "ed25519";
		}
		throw new DKIM_SigError("DKIM_SIGERROR_KEY_UNKNOWN_K");
	}

	/**
	 * @param {ReadonlyMap<string, string>} tagMap
	 * @returns {string?}
	 */
	static #parseNotes(tagMap) {
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
	 * @param {ReadonlyMap<string, string>} tagMap
	 * @returns {string}
	 */
	static #parsePublicKey(tagMap) {
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
	 * @param {ReadonlyMap<string, string>} tagMap
	 * @returns {string}
	 */
	static #parseServiceType(tagMap) {
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
	 * @param {ReadonlyMap<string, string>} tagMap
	 * @returns {string[]}
	 */
	static #parseFlags(tagMap) {
		// get Flags (plaintext; OPTIONAL, default is no flags set)
		const key_t_tag_flag = `(?:y|s|${hyphenated_word})`;
		const key_t_tag = `${key_t_tag_flag}(?:${RfcParser.FWS}?:${RfcParser.FWS}?${key_t_tag_flag})*`;
		const flagsTag = RfcParser.parseTagValue(tagMap, "t", key_t_tag, 2);
		if (flagsTag === null) {
			return [];
		}
		// get the flags and store them in an array
		return flagsTag[0].split(":").map(s => s.trim()).filter((x) => x);
	}
}

/**
 * A single DKIM signature that can be verified.
 */
class DkimSignature {
	/**
	 * @param {import("ts-essentials").DeepReadonly<Msg>} msg
	 * @param {DkimSignatureHeader} header
	 */
	constructor(msg, header) {
		/**
		 * @private
		 * @readonly
		 */
		this._msg = msg;
		/**
		 * @private
		 * @readonly
		 */
		this._header = header;
	}

	/**
	 * Canonicalize a single header field using the relaxed algorithm
	 * specified in Section 3.4.2 of RFC 6376.
	 *
	 * @param {string} headerField
	 * @returns {string}
	 */
	static #canonicalizationHeaderFieldRelaxed(headerField) {
		// Convert header field name (not the header field values) to lowercase
		let headerCanonicalized = headerField.replace(
			/^\S[^:]*/,
			(match) => match.toLowerCase()
		);

		// Unfold header field continuation lines
		headerCanonicalized = headerCanonicalized.replace(/\r\n[ \t]/g, " ");

		// Convert all sequences of one or more WSP characters to a single SP character.
		// WSP characters here include those before and after a line folding boundary.
		headerCanonicalized = headerCanonicalized.replace(/[ \t]+/g, " ");

		// Delete all WSP characters at the end of each unfolded header field value.
		headerCanonicalized = headerCanonicalized.replace(/[ \t]+\r\n/, "\r\n");

		// Delete any WSP characters remaining before and after the colon
		// separating the header field name from the header field value.
		// The colon separator MUST be retained.
		headerCanonicalized = headerCanonicalized.replace(/[ \t]*:[ \t]*/, ":");

		return headerCanonicalized;
	}

	/**
	 * Canonicalize the body using the simple algorithm
	 * specified in Section 3.4.3 of RFC 6376.
	 *
	 * @param {string} body
	 * @returns {string}
	 */
	static #canonicalizationBodySimple(body) {
		// Ignore all empty lines at the end of the message body
		// If there is no body or no trailing CRLF on the message body, a CRLF is added
		// for some reason /(\r\n)*$/ doesn't work all the time
		// (especially in large strings; matching only last "\r\n")
		const bodyCanonicalized = body.replace(/((\r\n)+)?$/, "\r\n");

		return bodyCanonicalized;
	}

	/**
	 * Canonicalize the body using the relaxed algorithm
	 * specified in Section 3.4.4 of RFC 6376.
	 *
	 * @param {string} body
	 * @returns {string}
	 */
	static #canonicalizationBodyRelaxed(body) {
		// Ignore all whitespace at the end of lines
		let bodyCanonicalized = body.replace(/[ \t]+\r\n/g, "\r\n");
		// Reduce all sequences of WSP within a line to a single SP character
		bodyCanonicalized = bodyCanonicalized.replace(/[ \t]+/g, " ");

		// Ignore all empty lines at the end of the message body
		// If the body is non-empty but does not end with a CRLF, a CRLF is added
		// for some reason /(\r\n)*$/ doesn't work all the time
		// (especially in large strings; matching only last "\r\n")
		bodyCanonicalized = bodyCanonicalized.replace(/((\r\n)+)?$/, "\r\n");

		// If only one \r\n rests, there were only empty lines or body was empty.
		if (bodyCanonicalized === "\r\n") {
			return "";
		}
		return bodyCanonicalized;
	}

	/**
	 * Computing the Message Hash for the body
	 * specified in Section 3.7 of RFC 6376.
	 *
	 * @param {dkimSigWarningV2[]} warnings
	 * @returns {Promise<string>}
	 */
	async #computeBodyHash(warnings) {
		// canonicalize body
		let bodyCanon;
		switch (this._header.c_body) {
			case "simple":
				bodyCanon = DkimSignature.#canonicalizationBodySimple(this._msg.bodyPlain);
				break;
			case "relaxed":
				bodyCanon = DkimSignature.#canonicalizationBodyRelaxed(this._msg.bodyPlain);
				break;
			default:
				throw new DKIM_InternalError("unsupported canonicalization algorithm got parsed");
		}

		// if a body length count is given
		if (this._header.l !== null) {
			// check the value of the body length tag
			if (this._header.l > bodyCanon.length) {
				// length tag exceeds body size
				log.debug(`bodyCanon.length: ${bodyCanon.length}`);
				throw new DKIM_SigError("DKIM_SIGERROR_TOOLARGE_L");
			} else if (this._header.l < bodyCanon.length) {
				// length tag smaller when body size
				warnings.push({ name: "DKIM_SIGWARNING_SMALL_L" });
				log.debug("Warning: DKIM_SIGWARNING_SMALL_L");
			}

			// truncated body to the length specified in the "l=" tag
			bodyCanon = bodyCanon.substr(0, this._header.l);
		}

		// compute body hash
		const bodyHash = await DkimCrypto.digest(this._header.a_hash, bodyCanon);
		return bodyHash;
	}

	/**
	 * Computing the input for the header Hash
	 * specified in Section 3.7 of RFC 6376.
	 *
	 * @returns {string}
	 */
	#computeHeaderHashInput() {
		let hashInput = "";

		// set header canonicalization algorithm
		let headerCanonAlgo;
		switch (this._header.c_header) {
			case "simple":
				// @ts-expect-error
				headerCanonAlgo = function (headerField) { return headerField; };
				break;
			case "relaxed":
				headerCanonAlgo = DkimSignature.#canonicalizationHeaderFieldRelaxed;
				break;
			default:
				throw new DKIM_InternalError("unsupported canonicalization algorithm (header) got parsed");
		}

		// copy header fields
		/** @type {Map<string, string[]>} */
		const headerFields = new Map();
		for (const [key, val] of this._msg.headerFields) {
			headerFields.set(key, val.slice());
		}

		// get header fields specified by the "h=" tag
		// and join their canonicalized form
		for (const header of this._header.h_array) {
			// if multiple instances of the same header field are signed
			// include them in reverse order (from bottom to top)
			const headerFieldArray = headerFields.get(header);
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
		const pos_bTag = this._header.original_header.indexOf(this._header.b_folded);
		let tempBegin = this._header.original_header.substr(0, pos_bTag);
		tempBegin = tempBegin.replace(new RegExp(`${RfcParser.FWS}?$`), "");
		let tempEnd = this._header.original_header.substr(pos_bTag + this._header.b_folded.length);
		tempEnd = tempEnd.replace(new RegExp(`^${RfcParser.FWS}?`), "");
		let temp = tempBegin + tempEnd;
		// canonicalized using the header canonicalization algorithm specified in the "c=" tag
		temp = headerCanonAlgo(temp);
		// without a trailing CRLF
		hashInput += temp.substr(0, temp.length - 2);

		return hashInput;
	}

	/**
	 * Check alignment of the from address.
	 *
	 * @param {dkimSigWarningV2[]} warnings
	 * @returns {void}
	 */
	#checkFromAlignment(warnings) {
		// warning if from is not in SDID or AUID
		if (!addrIsInDomain(this._msg.from, this._header.d)) {
			warnings.push({ name: "DKIM_SIGWARNING_FROM_NOT_IN_SDID" });
			log.debug("Warning: DKIM_SIGWARNING_FROM_NOT_IN_SDID");
		} else if (!stringEndsWith(this._msg.from, this._header.i)) {
			warnings.push({ name: "DKIM_SIGWARNING_FROM_NOT_IN_AUID" });
			log.debug("Warning: DKIM_SIGWARNING_FROM_NOT_IN_AUID");
		}
	}

	/**
	 * Check the validity period of the signature.
	 *
	 * @param {dkimSigWarningV2[]} warnings
	 * @returns {void}
	 */
	#checkValidityPeriod(warnings) {
		let receivedTime = null;
		const receivedHeaders = this._msg.headerFields.get("received") ?? [];
		if (receivedHeaders[0]) {
			receivedTime = MsgParser.tryExtractReceivedTime(receivedHeaders[0]);
		}

		const verifyTime = receivedTime ?? new Date();
		const time = Math.round(verifyTime.getTime() / 1000);
		// warning if signature expired
		if (this._header.x !== null && this._header.x < time) {
			warnings.push({ name: "DKIM_SIGWARNING_EXPIRED" });
			log.debug("Warning: DKIM_SIGWARNING_EXPIRED");
		}
		// warning if signature in future
		// We allow a difference of 15 min so small clock differenzess between
		// sender and receiver are not causing any issues
		const allowedDifference = 15 * 60;
		if (this._header.t !== null && this._header.t > time + allowedDifference) {
			warnings.push({ name: "DKIM_SIGWARNING_FUTURE" });
			log.debug("Warning: DKIM_SIGWARNING_FUTURE");
		}
	}

	/**
	 * Check that the list of signed headers satisfy our policies.
	 * - Warn if recommended headers are not signed.
	 * - Try detecting maliciously added unsigned headers.
	 *
	 * @param {dkimSigWarningV2[]} warnings
	 * @returns {void}
	 */
	#checkSignedHeaders(warnings) {
		// The list of recommended headers to sign is mostly based on
		// https://www.rfc-editor.org/rfc/rfc6376.html#section-5.4.

		// The detection for maliciously added unsigned headers only considers all the recommended signed headers.
		// It simply ensures that a message does not contain both signed and unsigned values of a header.
		// Using the same mechanism for all signed headers will cause problems there added headers is normal
		// e.g. the Received header.

		/**
		 * Headers that we required to be signed in relaxed, recommended or strict mode.
		 *
		 * @type {string[]}
		 */
		const required = [
			"From",
			"Subject",
		];
		/**
		 * Headers that we required to be signed in recommended or strict mode.
		 *
		 * @type {string[]}
		 */
		const recommended = [
			"Date",
			"To", "Cc",
			"Resent-Date", "Resent-From", "Resent-To", "Resent-Cc",
			"In-Reply-To", "References",
			"List-Id", "List-Help", "List-Unsubscribe", "List-Subscribe", "List-Post", "List-Owner", "List-Archive",
		];
		/**
		 * Headers that we required to be signed in strict mode.
		 *
		 * @type {string[]}
		 */
		const desired = [
			"Message-ID",
			"Sender",
			"MIME-Version",
			"Content-Transfer-Encoding",
			"Content-Disposition",
			"Content-ID",
			"Content-Description",
		];

		// We would like Reply-To to be in the recommended list.
		// As some bigger domains violate this, we only enforce it if the Reply-To is not in the signing domain.
		const replyTo = this._msg.headerFields.get("reply-to");
		let replyToAddress;
		if (replyTo && replyTo[0]) {
			try {
				replyToAddress = MsgParser.parseReplyToHeader(replyTo[0]);
			} catch (error) {
				log.warn("Ignoring error in parsing of Reply-To header:", error);
			}
		}
		if (replyToAddress && addrIsInDomain(replyToAddress, this._header.d)) {
			desired.push("Reply-To");
		} else {
			recommended.push("Reply-To");
		}

		// If the body is not completely signed, a manipulated Content-Type header
		// can cause completely different content to be shown.
		if (warnings.some(warning => warning.name === "DKIM_SIGWARNING_SMALL_L")) {
			required.push("Content-Type");
		} else if (this._header.l !== null) {
			recommended.push("Content-Type");
		} else {
			desired.push("Content-Type");
		}

		/**
		 * @param {string} header
		 * @param {boolean} warnIfUnsigned
		 * @returns {void}
		 */
		const checkSignedHeader = (header, warnIfUnsigned) => {
			const headerLowerCase = header.toLowerCase();
			const signedCount = this._header.h_array.filter(e => e === headerLowerCase).length;
			const unsignedCount = this._msg.headerFields.get(headerLowerCase)?.length ?? 0;
			if (signedCount > 0 && signedCount < unsignedCount) {
				throw new DKIM_SigError("DKIM_POLICYERROR_UNSIGNED_HEADER_ADDED", [header]);
			}
			if (warnIfUnsigned && signedCount < unsignedCount) {
				warnings.push({ name: "DKIM_SIGWARNING_UNSIGNED_HEADER", params: [header] });
				log.debug(`Warning: DKIM_SIGWARNING_UNSIGNED_HEADER (${header})`);
			}
		};

		for (const header of required) {
			checkSignedHeader(header, prefs["policy.dkim.unsignedHeadersWarning.mode"] >=
				BasePreferences.POLICY_DKIM_UNSIGNED_HEADERS_WARNING_MODE.RELAXED);
		}
		for (const header of recommended) {
			checkSignedHeader(header, prefs["policy.dkim.unsignedHeadersWarning.mode"] >=
				BasePreferences.POLICY_DKIM_UNSIGNED_HEADERS_WARNING_MODE.RECOMMENDED);
		}
		for (const header of desired) {
			checkSignedHeader(header, prefs["policy.dkim.unsignedHeadersWarning.mode"] >=
				BasePreferences.POLICY_DKIM_UNSIGNED_HEADERS_WARNING_MODE.STRICT);
		}
	}

	/**
	 * Verify that the body of the message is unmodified.
	 *
	 * @param {dkimSigWarningV2[]} warnings
	 * @returns {Promise<void>}
	 * @throws {DKIM_SigError}
	 * @throws {DKIM_InternalError}
	 */
	async #verifyBody(warnings) {
		// Compute the Message hash for the body
		const bodyHash = await this.#computeBodyHash(warnings);
		log.debug("computed body hash:", bodyHash);

		// compare body hash
		if (bodyHash !== this._header.bh) {
			throw new DKIM_SigError("DKIM_SIGERROR_CORRUPT_BH");
		}
	}

	/**
	 * Fetch the DKIM key.
	 *
	 * @param {KeyStore} keyStore
	 * @param {dkimSigWarningV2[]} warnings
	 * @returns {Promise<import("./keyStore.mjs.js").DkimKeyResult>}
	 * @throws {DKIM_SigError}
	 * @throws {DKIM_InternalError}
	 */
	async #fetchKey(keyStore, warnings) {
		const keyQueryResult = await keyStore.fetchKey(this._header.d, this._header.s);

		// if key is not signed by DNSSEC
		if (!keyQueryResult.secure) {
			switch (prefs["error.policy.key_insecure.treatAs"]) {
				case 0: // error
					throw new DKIM_SigError("DKIM_POLICYERROR_KEY_INSECURE");
				case 1: // warning
					warnings.push({ name: "DKIM_POLICYERROR_KEY_INSECURE" });
					log.debug("Warning: DKIM_POLICYERROR_KEY_INSECURE");
					break;
				case 2: // ignore
					break;
				default:
					throw new DKIM_InternalError("invalid error.policy.key_insecure.treatAs");
			}
		}

		return keyQueryResult;
	}

	/**
	 * Sanity checks for the key, including if it matches the data in the signature.
	 *
	 * @param {DkimKey} dkimKey
	 * @param {dkimSigWarningV2[]} warnings
	 * @throws {DKIM_SigError}
	 */
	#checkKey(dkimKey, warnings) {
		// check that the testing flag is not set
		if (dkimKey.t_array.includes("y")) {
			if (prefs["error.key_testmode.ignore"]) {
				warnings.push({ name: "DKIM_SIGERROR_KEY_TESTMODE" });
				log.debug("Warning: DKIM_SIGERROR_KEY_TESTMODE");
			} else {
				throw new DKIM_SigError("DKIM_SIGERROR_KEY_TESTMODE");
			}
		}

		// Signature algo musst match the key type.
		if (this._header.a_sig !== dkimKey.k) {
			throw new DKIM_SigError("DKIM_SIGERROR_KEY_MISMATCHED_K");
		}

		// if s flag is set in DKIM key record
		// AUID must be from the same domain as SDID (and not a subdomain)
		if (dkimKey.t_array.includes("s") &&
			!stringEqual(this._header.i_domain, this._header.d)) {
			throw new DKIM_SigError("DKIM_SIGERROR_DOMAIN_I");
		}

		// If the "h=" tag exists in the DKIM key record
		// the hash algorithm implied by the "a=" tag in the DKIM-Signature header field
		// must be included in the contents of the "h=" tag
		if (dkimKey.h_array &&
			!dkimKey.h_array.includes(this._header.a_hash)) {
			throw new DKIM_SigError("DKIM_SIGERROR_KEY_HASHNOTINCLUDED");
		}
	}

	/**
	 * Verify the actual signature.
	 *
	 * @param {string} publicKey
	 * @param {dkimSigWarningV2[]} warnings
	 */
	async #verifySignature(publicKey, warnings) {
		// Compute the input for the header hash
		const headerHashInput = this.#computeHeaderHashInput();
		log.debug(`Header hash input:\n${headerHashInput}`);

		// verify Signature
		const [isValid, keyLength] = await DkimCrypto.verify(
			this._header.a_sig,
			publicKey,
			this._header.a_hash,
			this._header.b,
			headerHashInput
		);
		if (!isValid) {
			throw new DKIM_SigError("DKIM_SIGERROR_BADSIG");
		}

		if (this._header.a_sig === "rsa") {
			// Check strength of RSA keys.
			if (keyLength < 1024) {
				// error if key is too short
				log.debug(`rsa key size: ${keyLength}`);
				throw new DKIM_SigError("DKIM_SIGWARNING_KEYSMALL");
			} else if (keyLength < 2048) {
				// weak key
				log.debug(`rsa key size: ${keyLength}`);
				switch (prefs["error.algorithm.rsa.weakKeyLength.treatAs"]) {
					case 0: // error
						throw new DKIM_SigError("DKIM_SIGWARNING_KEY_IS_WEAK");
					case 1: // warning
						warnings.push({ name: "DKIM_SIGWARNING_KEY_IS_WEAK" });
						log.debug("Warning: DKIM_SIGWARNING_KEY_IS_WEAK");
						break;
					case 2: // ignore
						break;
					default:
						throw new DKIM_InternalError("invalid error.algorithm.rsa.weakKeyLength.treatAs");
				}
			}
		}
	}

	/**
	 * Verifying a single DKIM signature.
	 *
	 * @param {KeyStore} keyStore
	 * @returns {Promise<dkimSigResultV2>}
	 * @throws {DKIM_SigError}
	 * @throws {DKIM_InternalError}
	 */
	async verify(keyStore) {
		/** @type {dkimSigWarningV2[]} */
		const warnings = copy(this._header.warnings);

		this.#checkFromAlignment(warnings);
		this.#checkValidityPeriod(warnings);
		this.#checkSignedHeaders(warnings);

		await this.#verifyBody(warnings);

		const keyQueryResult = await this.#fetchKey(keyStore, warnings);
		const dkimKey = new DkimKey(keyQueryResult.key);
		log.debug("Parsed DKIM-Key:", dkimKey);
		this.#checkKey(dkimKey, warnings);

		await this.#verifySignature(dkimKey.p, warnings);

		// return result
		const verification_result = {
			version: "2.0",
			result: "SUCCESS",
			sdid: this._header.d,
			auid: this._header.i,
			selector: this._header.s,
			warnings,
			keySecure: keyQueryResult.secure,
		};
		return verification_result;
	}
}

/**
 * Verifies all DKIM signatures in a message.
 */
export default class Verifier {
	/**
	 * @param {KeyStore} [keyStore]
	 */
	constructor(keyStore) {
		/** @private */
		this._keyStore = keyStore ?? new KeyStore();
	}

	/**
	 * Create a DKIM fail result for an exception.
	 *
	 * @param {unknown} e
	 * @param {DkimSignatureHeader|{[x: string]: undefined}} dkimSignature
	 * @returns {dkimSigResultV2}
	 */
	static #handleException(e, dkimSignature = {}) {
		if (e instanceof DKIM_SigError) {
			const result = {
				version: "2.0",
				result: "PERMFAIL",
				sdid: dkimSignature.d,
				auid: dkimSignature.i,
				selector: dkimSignature.s,
				errorType: e.errorType,
				errorStrParams: e.errorStrParams,
				hideFail: e.errorType === "DKIM_SIGERROR_KEY_TESTMODE",
			};

			log.warn("Error verifying the signature", e);

			return result;
		}
		/** @type {dkimSigResultV2} */
		const result = {
			version: "2.0",
			result: "TEMPFAIL",
			sdid: dkimSignature.d,
			auid: dkimSignature.i,
			selector: dkimSignature.s,
		};

		if (e instanceof DKIM_InternalError) {
			result.errorType = e.errorType;
			log.error("Internal error during DKIM verification:", e);
		} else {
			log.fatal("Error during DKIM verification:", e);
		}

		return result;
	}

	/**
	 * Processes signatures.
	 *
	 * @param {import("ts-essentials").DeepReadonly<Msg>} msg
	 * @returns {Promise<dkimSigResultV2[]>}
	 */
	async #processSignatures(msg) {
		let iDKIMSignatureIdx = 0;
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
		for (iDKIMSignatureIdx = dkimSignatureHeaders.length - 1; iDKIMSignatureIdx >= 0; iDKIMSignatureIdx--) {
			let dkimHeader;
			let sigRes;
			try {
				log.debug(`Verifying DKIM-Signature ${iDKIMSignatureIdx + 1} ...`);
				dkimHeader = new DkimSignatureHeader(dkimSignatureHeaders[iDKIMSignatureIdx] ?? "");
				log.debug(`Parsed DKIM-Signature ${iDKIMSignatureIdx + 1}:`, dkimHeader);
				const dkimSignature = new DkimSignature(msg, dkimHeader);
				sigRes = await dkimSignature.verify(this._keyStore);
				log.debug(`Verified DKIM-Signature ${iDKIMSignatureIdx + 1}`);
			} catch (e) {
				sigRes = Verifier.#handleException(e, dkimHeader);
				log.debug(`Exception on DKIM-Signature ${iDKIMSignatureIdx + 1}`);
			}

			sigResults.push(sigRes);
		}

		return sigResults;
	}

	/**
	 * Checks if at least on signature exists.
	 * If not, adds one to signatures with result "no sig".
	 *
	 * @param {dkimSigResultV2[]} signatures
	 * @returns {void}
	 */
	static #checkForSignatureExistence(signatures) {
		// check if a DKIM signature exists
		if (signatures.length === 0) {
			const dkimSigResultV2 = {
				version: "2.0",
				result: "none",
			};
			signatures.push(dkimSigResultV2);
		}
	}

	/**
	 * @typedef {object} Msg
	 * @property {Map<string, string[]>} headerFields
	 * @property {string} bodyPlain
	 * @property {string} from
	 */

	/**
	 * Verifies the DKIM signatures in the given message.
	 *
	 * @param {import("ts-essentials").DeepReadonly<Msg>} msg
	 * @returns {Promise<dkimResultV2>}
	 */
	verify(msg) {
		const promise = (async () => {
			await prefs.init();
			const res = {
				version: "2.0",
				signatures: await this.#processSignatures(msg),
			};
			Verifier.#checkForSignatureExistence(res.signatures);
			return res;
		})();
		promise.then(null, (exception) => {
			log.warn("verify failed", exception);
		});
		return promise;
	}
}
