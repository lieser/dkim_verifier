/*
 * dkimVerifier.jsm.js
 *
 * Verifies the DKIM-Signatures as specified in RFC 6376
 * http://tools.ietf.org/html/rfc6376
 * Update done by RFC 8301 included https://tools.ietf.org/html/rfc8301
 *
 * Version: 2.3.0 (18 Mai 2019)
 *
 * Copyright (c) 2013-2019 Philippe Lieser
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

// options for ESLint
/* eslint strict: ["warn", "function"] */
/* global Components, Services */
/* global Logging, Key, Policy, msgReader, rfcParser */
/* global dkimStrings, addrIsInDomain2, domainIsInDomain, stringEndsWith, stringEqual, writeStringToTmpFile, toType, DKIM_SigError, DKIM_TempError, DKIM_Error, copy */
/* exported EXPORTED_SYMBOLS, Verifier */

// @ts-expect-error
const module_version = "2.3.0";

var EXPORTED_SYMBOLS = [
	"Verifier"
];

// @ts-expect-error
const Cc = Components.classes;
// @ts-expect-error
const Ci = Components.interfaces;
// @ts-expect-error
const Cu = Components.utils;

Cu.import("resource://gre/modules/Services.jsm");

Cu.import("resource://dkim_verifier/logging.jsm.js");
Cu.import("resource://dkim_verifier/helper.jsm.js");
Cu.import("resource://dkim_verifier/dkimKey.jsm.js");
Cu.import("resource://dkim_verifier/dkimPolicy.jsm.js");
Cu.import("resource://dkim_verifier/msgReader.jsm.js");
Cu.import("resource://dkim_verifier/rfcParser.jsm.js");

// namespaces
var RSA = {};
var ED25519 = {};
// for jsbn.js
RSA.navigator = {};
RSA.navigator.appName = "Netscape";

// ASN.1
Services.scriptloader.loadSubScript("resource://dkim_verifier_3p/rsasign/asn1hex-1.1.js",
                                    RSA, "UTF-8" /* The script's encoding */);
// base64 converter
Services.scriptloader.loadSubScript("resource://dkim_verifier_3p/jsbn/base64.js",
                                    RSA, "UTF-8" /* The script's encoding */);
// RSA
Services.scriptloader.loadSubScript("resource://dkim_verifier_3p/jsbn/jsbn.js",
                                    RSA, "UTF-8" /* The script's encoding */);
Services.scriptloader.loadSubScript("resource://dkim_verifier_3p/jsbn/jsbn2.js",
                                    RSA, "UTF-8" /* The script's encoding */);
Services.scriptloader.loadSubScript("resource://dkim_verifier_3p/jsbn/rsa.js",
                                    RSA, "UTF-8" /* The script's encoding */);
Services.scriptloader.loadSubScript("resource://dkim_verifier_3p/rsasign/rsasign-1.2.js",
                                    RSA, "UTF-8" /* The script's encoding */);
// ED25519
Services.scriptloader.loadSubScript("resource://dkim_verifier_3p/tweetnacl/nacl-fast.js", ED25519, "UTF-8");
Services.scriptloader.loadSubScript("resource://dkim_verifier_3p/tweetnacl-util/nacl-util.js", ED25519, "UTF-8");

// @ts-expect-error
const PREF_BRANCH = "extensions.dkim_verifier.";


/**
 * The result of the verification (Version 1).
 *
 * @typedef {Object} dkimResultV1
 * @property {String} version
 *           result version ("1.0" / "1.1")
 * @property {String} result
 *           "none" / "SUCCESS" / "PERMFAIL" / "TEMPFAIL"
 * @property {String} [SDID]
 *           required if result="SUCCESS
 * @property {String} [selector]
 *           added in version 1.1
 * @property {String[]} [warnings]
 *           required if result="SUCCESS
 * @property {String|undefined} [errorType]
 *           if result="PERMFAIL: DKIM_SigError.errorType or Undefined
 *           if result="TEMPFAIL: DKIM_TempError.errorType or Undefined
 * @property {String} [shouldBeSignedBy]
 *           added in version 1.1
 * @property {Boolean} [hideFail]
 *           added in  version 1.1
 */

/**
 * @typedef {Object} dkimSigWarningV2
 * @property {string} name - Name of the warning (strings from dkim.properties)
 * @property {(string|string[])[]|undefined} [params] - optional params for formatted string
 */

/**
 * The result of the verification of a single DKIM signature (Version 2).
 *
 * @typedef {Object} dkimSigResultV2
 * @property {String} version
 *           result version ("2.1")
 * @property {String} result
 *           "none" / "SUCCESS" / "PERMFAIL" / "TEMPFAIL"
 * @property {String} [sdid]
 * @property {String} [auid]
 * @property {String} [selector]
 * @property {dkimSigWarningV2[]} [warnings]
 *           Array of warning_objects.
 *           required if result="SUCCESS"
 * @property {String} [errorType]
 *           if result="PERMFAIL: DKIM_SigError.errorType
 *           if result="TEMPFAIL: DKIM_TempError.errorType or Undefined
 * @property {String[]} [errorStrParams]
 * @property {Boolean} [hideFail]
 * @property {Boolean} [keySecure]
 * @property {number|undefined} [keyLength]
 * @property {number|null} [timestamp]
 * @property {number|null} [expiration]
 * @property {string} [algorithmSignature]
 * @property {string} [algorithmHash]
 * @property {string[]} [signedHeaders]
 * @property {String|undefined} [verifiedBy]
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

/*
 * DKIM Verifier module
 */
var Verifier = (function() {
	"use strict";

	// set hash functions used by rsasign-1.2.js
	RSA.KJUR = {};
	RSA.KJUR.crypto = {};
	RSA.KJUR.crypto.Util = {};
    RSA.KJUR.crypto.Util.DIGESTINFOHEAD = {
		'sha1':      "3021300906052b0e03021a05000414",
		'sha224':    "302d300d06096086480165030402040500041c",
		'sha256':    "3031300d060960864801650304020105000420",
		'sha384':    "3041300d060960864801650304020205000430",
		'sha512':    "3051300d060960864801650304020305000440",
		'md2':       "3020300c06082a864886f70d020205000410",
		'md5':       "3020300c06082a864886f70d020505000410",
		'ripemd160': "3021300906052b2403020105000414",
	};
	RSA.KJUR.crypto.Util.hashString = (s, algName) => dkim_hash(s, algName, "hex");

/*
 * preferences
 */
	var prefs = Services.prefs.getBranch(PREF_BRANCH);

/*
 * private variables
 */
	var log = Logging.getLogger("Verifier");

/*
 * private methods
 */

	/*
	 * wrapper for hash functions
	 * hashAlgorithm: "md2", "md5", "sha1", "sha256", "sha384", "sha512"
	 * outputFormat: "hex", "b64"
	 *
	 * from https://developer.mozilla.org/en-US/docs/XPCOM_Interface_Reference/nsICryptoHash
	 *
	 * @throws {Error}
	 */
	function dkim_hash(str, hashAlgorithm, outputFormat) {
		/*
		 * Converts a string to an array bytes
		 * characters >255 have their hi-byte silently ignored.
		 */
		function rstr2byteArray(str) {
			var res = new Array(str.length);
			for (var i = 0; i < str.length; i++) {
				res[i] = str.charCodeAt(i) & 0xFF;
			}

			return res;
		}

		// return the two-digit hexadecimal code for a byte
		function toHexString(charCode)
		{
			return ("0" + charCode.toString(16)).slice(-2);
		}

		var hasher = Components.classes["@mozilla.org/security/hash;1"].
			createInstance(Components.interfaces.nsICryptoHash);
		hasher.initWithString(hashAlgorithm);

/*
		var converter = Components.classes["@mozilla.org/intl/scriptableunicodeconverter"].
			createInstance(Components.interfaces.nsIScriptableUnicodeConverter);
		converter.charset = "iso-8859-1";

		// data is an array of bytes
		var data = converter.convertToByteArray(str, {});
*/
		// convert input str
		var data = rstr2byteArray(str);

		hasher.update(data, data.length);

		switch (outputFormat) {
			case "hex":
				// true for base-64, false for binary data output
				var hash = hasher.finish(false);

				// convert the binary hash data to a hex string.
				hash = hash.split("").map(e => toHexString(e.charCodeAt(0))).join("");
				return hash;
			case "b64":
				// true for base-64, false for binary data output
				return hasher.finish(true);
			default:
				throw new Error("unsupported hash output selected");

		}
	}

	/**
	 * Verifies an RSA signature.
	 *
	 * @param {String} key
	 *        b64 encoded RSA key in ASN.1 DER format
	 * @param {String} str
	 *        plain string to be verified
	 * @param {String} hash_algo
	 *        algorithm that should be used to calculate the hash
	 *        (but is not used in this implementation)
	 * @param {String} signature
	 *        b64 encoded signature
	 * @param {dkimSigWarning[]} warnings - out param
	 * @param {Object} [keyInfo] - out param
	 * @return {Boolean}
	 * @throws {DKIM_SigError|Error}
	 */
	function verifyRSASig(key, str, hash_algo, signature, warnings, keyInfo = {}) {
		// get RSA-key
		/*
		the rsa key must be in the following ASN.1 DER format

		SEQUENCE(2 elem) -- our posTopArray
			SEQUENCE(2 elem)
				OBJECT IDENTIFIER 1.2.840.113549.1.1.1 (Comment: PKCS #1; Description: rsaEncryption)
				NULL
			BIT STRING(1 elem)
				SEQUENCE(2 elem) -- our posKeyArray
					INTEGER (modulus)
					INTEGER (publicExponent)
		*/
		let asnKey = RSA.b64tohex(key);
		let posTopArray = null;
		let posKeyArray = null;

		// check format by comparing the 1. child in the top element
		posTopArray = RSA.ASN1HEX.getChildIdx(asnKey,0);
		if (posTopArray === null || posTopArray.length !== 2) {
			throw new DKIM_SigError("DKIM_SIGERROR_KEYDECODE");
		}
		if (RSA.ASN1HEX.getTLV(asnKey, posTopArray[0]) !==
		    "300d06092a864886f70d0101010500") {
			throw new DKIM_SigError("DKIM_SIGERROR_KEYDECODE");
		}

		// get pos of SEQUENCE under BIT STRING
		// asn1hex does not support BIT STRING, so we will compute the position
		let pos = RSA.ASN1HEX.getVidx(asnKey, posTopArray[1]) + 2;

		// get pos of modulus and publicExponent
		posKeyArray = RSA.ASN1HEX.getChildIdx(asnKey, pos);
		if (posKeyArray === null || posKeyArray.length !== 2) {
			throw new DKIM_SigError("DKIM_SIGERROR_KEYDECODE");
		}

		// get modulus
		let m_hex = RSA.ASN1HEX.getV(asnKey,posKeyArray[0]);
		// get public exponent
		let e_hex = RSA.ASN1HEX.getV(asnKey,posKeyArray[1]);

		// trim leading zeros from modulus
		let m_hex_trimmed = m_hex.replace(/^0+/, '');
		// one hex digit represents 4 bit
		keyInfo.keyLength = m_hex_trimmed.length * 4;
		log.debug("rsa key length: " + keyInfo.keyLength);
		if (keyInfo.keyLength < 1024) {
			// error if key is too short
			throw new DKIM_SigError("DKIM_SIGWARNING_KEYSMALL");
		} else if (keyInfo.keyLength < 2048) {
			// weak key
			switch (prefs.getIntPref("error.algorithm.rsa.weakKeyLength.treatAs")) {
				case 0: // error
					throw new DKIM_SigError("DKIM_SIGWARNING_KEY_IS_WEAK");
				case 1: // warning
					warnings.push({name: "DKIM_SIGWARNING_KEY_IS_WEAK"});
					log.debug("Warning: DKIM_SIGWARNING_KEY_IS_WEAK");
					break;
				case 2: // ignore
					break;
				default:
					throw new Error("invalid error.algorithm.rsa.weakKeyLength.treatAs");
			}
		}

		// set RSA-key
		let rsa = new RSA.RSAKey();
		rsa.setPublic(m_hex, e_hex);

		// verify Signature
		return rsa.verify(str, RSA.b64tohex(signature), keyInfo);
	}

	/**
	 * Verifies an ed25519 signature.
	 *
	 * @param {String} key
	 *        b64 encoded ed25519 key
	 * @param {String} str
	 *        b64 encoded string to be verified
	 * @param {String} hash_algo
	 *        algorithm that should be used to calculate the hash
	 * @param {String} signature
	 *        b64 encoded signature
	 * @param {dkimSigWarning[]} warnings - out param
	 * @param {Object} [_keyInfo] - out param
	 * @return {Boolean}
	 */
	function verifyED25519Sig(key, str, hash_algo, signature, warnings, _keyInfo = {}) {
		let result = false;
		let hashedStr = dkim_hash(str, hash_algo, "b64");
		let hashedStr_byte = ED25519.nacl.util.decodeBase64(hashedStr);
		let signature_byte = ED25519.nacl.util.decodeBase64(signature);
		let key_byte = ED25519.nacl.util.decodeBase64(key);
		// each byte has 8 bit (a valid key_byte array has a length of 32)
		_keyInfo.keyLength = key_byte.length * 8;
		log.debug("ed25519 key length: " + _keyInfo.keyLength);
		if (hash_algo !== "sha256") {
			throw new DKIM_SigError("DKIM_SIGERROR_KEY_HASHNOTINCLUDED");
		}
		if (_keyInfo.keyLength !== 256) {
			throw new DKIM_SigError("DKIM_SIGERROR_KEYDECODE");
		}
		try {
			result = ED25519.nacl.sign.detached.verify(hashedStr_byte, signature_byte, key_byte);
		} catch(ex){
			throw new DKIM_SigError(ex.message);
		}
		return result;
	}

	function newDKIMSignature( DKIMSignatureHeader ) {
		var DKIMSignature = {
			original_header : DKIMSignatureHeader,
			warnings: [],
			v : null, // Version
			a_sig : null, // signature algorithm (signing part)
			a_hash : null, // signature algorithm (hashing part)
			a_keylength : null, // signature algorithm: signing key length
			b : null, // signature (unfolded)
			b_folded : null, // signature (still folded)
			bh : null, // body hash
			c_header : null, // canonicalization for header
			c_body : null, // canonicalization for body
			d : null, // Signing Domain Identifier (SDID) claiming responsibility
			h : null, // Signed header fields
			h_array : [], // array of Signed header fields
			i : null, // Agent or User Identifier (AUID) on behalf of which the SDID is taking responsibility
			i_domain : null, // domain part of AUID
			l : null, // Body length count
			q : null, // query methods for public key retrieval
			s : null, // selector
			t : null, // Signature Timestamp
			x : null, // Signature Expiration
			z : null // Copied header fields
		};
		return DKIMSignature;
	}

	/*
	 * parse the DKIM-Signature header field
	 * header field is specified in Section 3.5 of RFC 6376
	 *
	 * @throws {DKIM_SigError|DKIM_Error|Error}
	 */
	function parseDKIMSignature(DKIMSignature) { // eslint-disable-line complexity
		var DKIMSignatureHeader = DKIMSignature.original_header;

		// strip DKIM-Signatur header name
		DKIMSignatureHeader = DKIMSignatureHeader.replace(/^DKIM-Signature[ \t]*:/i,"");
		// strip the \r\n at the end
		DKIMSignatureHeader = DKIMSignatureHeader.substr(0, DKIMSignatureHeader.length-2);
		// parse tag-value list
		let parsedTagMap = rfcParser.parseTagValueList(DKIMSignatureHeader);
		if (parsedTagMap === -1) {
			throw new DKIM_SigError("DKIM_SIGERROR_ILLFORMED_TAGSPEC");
		} else if (parsedTagMap === -2) {
			throw new DKIM_SigError("DKIM_SIGERROR_DUPLICATE_TAG");
		}
		if (!(toType(parsedTagMap) === "Map")) {
			throw new Error(`unexpected return value from parseTagValueList: ${parsedTagMap}`);
		}
		/** @type {Map} */
		// @ts-expect-error
		let tagMap = parsedTagMap;

		// get Version (plain-text; REQUIRED)
		// must be "1"
		var versionTag = rfcParser.parseTagValue(tagMap, "v", "[0-9]+");
		if (versionTag === null) {
			throw new DKIM_SigError("DKIM_SIGERROR_MISSING_V");
		}
		if (versionTag[0] === "1") {
			DKIMSignature.v = "1";
		} else {
			throw new DKIM_SigError("DKIM_SIGERROR_VERSION");
		}

		// get signature algorithm (plain-text;REQUIRED)
		// currently only "rsa-sha1" or "rsa-sha256" or "ed25519-sha256"
		var sig_a_tag_k = "(rsa|ed25519|[A-Za-z](?:[A-Za-z]|[0-9])*)";
		var sig_a_tag_h = "(sha1|sha256|[A-Za-z](?:[A-Za-z]|[0-9])*)";
		var sig_a_tag_alg = sig_a_tag_k+"-"+sig_a_tag_h;
		var algorithmTag = rfcParser.parseTagValue(tagMap, "a", sig_a_tag_alg);
		if (algorithmTag === null) {
			throw new DKIM_SigError("DKIM_SIGERROR_MISSING_A");
		}
		if (!algorithmTag[1] || !algorithmTag[2]) {
			throw new Error("Error matching the a-tag.");
		}
		// Detailed hints will contain the algorithm in any case
		DKIMSignature.a_sig = algorithmTag[1];
		DKIMSignature.a_hash = algorithmTag[2];
		if (algorithmTag[0] === "ed25519-sha256" || algorithmTag[0] === "rsa-sha256") {
			// all is fine, nothing to do at the moment
		} else if (algorithmTag[0] === "rsa-sha1") {
			switch (prefs.getIntPref("error.algorithm.sign.rsa-sha1.treatAs")) {
				case 0: // error
					throw new DKIM_SigError("DKIM_SIGERROR_INSECURE_A");
				case 1: // warning
					DKIMSignature.warnings.push({ name: "DKIM_SIGERROR_INSECURE_A" });
					break;
				case 2: // ignore
					break;
				default:
					throw new Error("invalid error.algorithm.sign.rsa-sha1.treatAs");
			}
		} else {
			throw new DKIM_SigError("DKIM_SIGERROR_UNKNOWN_A");
		}

		// get signature data (base64;REQUIRED)
		var signatureDataTag = rfcParser.parseTagValue(tagMap, "b", rfcParser.get("base64string"));
		if (signatureDataTag === null) {
			throw new DKIM_SigError("DKIM_SIGERROR_MISSING_B");
		}
		DKIMSignature.b = signatureDataTag[0].replace(new RegExp(rfcParser.get("FWS"),"g"), "");
		DKIMSignature.b_folded = signatureDataTag[0];

		// get body hash (base64;REQUIRED)
		var bodyHashTag = rfcParser.parseTagValue(tagMap, "bh", rfcParser.get("base64string"));
		if (bodyHashTag === null) {
			throw new DKIM_SigError("DKIM_SIGERROR_MISSING_BH");
		}
		DKIMSignature.bh = bodyHashTag[0].replace(new RegExp(rfcParser.get("FWS"),"g"), "");

		// get Message canonicalization (plain-text; OPTIONAL, default is "simple/simple")
		// currently only "simple" or "relaxed" for both header and body
		var sig_c_tag_alg = `(simple|relaxed|${rfcParser.get("hyphenated_word")})`;
		var msCanonTag = rfcParser.parseTagValue(tagMap, "c", `${sig_c_tag_alg}(?:/${sig_c_tag_alg})?`);
		if (msCanonTag === null) {
			DKIMSignature.c_header = "simple";
			DKIMSignature.c_body = "simple";
		} else {
			// canonicalization for header
			if (msCanonTag[1] === "simple" || msCanonTag[1] === "relaxed") {
				DKIMSignature.c_header = msCanonTag[1];
			} else {
				throw new DKIM_SigError("DKIM_SIGERROR_UNKNOWN_C_H");
			}

			// canonicalization for body
			if (msCanonTag[2] === undefined) {
				DKIMSignature.c_body = "simple";
			} else {
				if (msCanonTag[2] === "simple" || msCanonTag[2] === "relaxed") {
					DKIMSignature.c_body = msCanonTag[2];
				} else {
					throw new DKIM_SigError("DKIM_SIGERROR_UNKNOWN_C_B");
				}
			}
		}

		// get SDID (plain-text; REQUIRED)
		var SDIDTag = rfcParser.parseTagValue(tagMap, "d", rfcParser.get("domain_name"));
		if (SDIDTag === null) {
			throw new DKIM_SigError("DKIM_SIGERROR_MISSING_D");
		}
		DKIMSignature.d = SDIDTag[0];

		// get Signed header fields (plain-text, but see description; REQUIRED)
		var sig_h_tag = `(${rfcParser.get("hdr_name")})(?:${rfcParser.get("FWS")}?:${rfcParser.get("FWS")}?${rfcParser.get("hdr_name")})*`;
		var signedHeadersTag = rfcParser.parseTagValue(tagMap, "h", sig_h_tag);
		if (signedHeadersTag === null) {
			throw new DKIM_SigError("DKIM_SIGERROR_MISSING_H");
		}
		DKIMSignature.h = signedHeadersTag[0].replace(new RegExp(rfcParser.get("FWS"),"g"), "");
		// get the header field names and store them in lower case in an array
		DKIMSignature.h_array = DKIMSignature.h.split(":").
			map(x => x.trim().toLowerCase()).
			filter(x => x);
		// check that the from header is included
		if (!DKIMSignature.h_array.includes("from")) {
			throw new DKIM_SigError("DKIM_SIGERROR_MISSING_FROM");
		}

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

		var sig_i_tag = `${rfcParser.get("local_part")}?@(${rfcParser.get("domain_name")})`;
		var AUIDTag = null;
		try {
			AUIDTag = rfcParser.parseTagValue(tagMap, "i", sig_i_tag);
		} catch (exception) {
			if (exception instanceof DKIM_SigError &&
				exception.errorType === "DKIM_SIGERROR_ILLFORMED_I")
			{
				switch (prefs.getIntPref("error.illformed_i.treatAs")) {
					case 0: // error
						throw exception;
					case 1: // warning
						DKIMSignature.warnings.push({ name: "DKIM_SIGERROR_ILLFORMED_I" });
						break;
					case 2: // ignore
						break;
					default:
						throw new Error("invalid error.illformed_i.treatAs");
				}
			} else {
				throw exception;
			}
		}
		if (AUIDTag === null) {
			DKIMSignature.i = "@"+DKIMSignature.d;
			DKIMSignature.i_domain = DKIMSignature.d;
		} else {
			if (!AUIDTag[1]) {
				throw new Error("Error matching the i-tag.");
			}
			DKIMSignature.i = AUIDTag[0];
			DKIMSignature.i_domain = AUIDTag[1];
			if (!stringEndsWith(DKIMSignature.i_domain, DKIMSignature.d)) {
				throw new DKIM_SigError("DKIM_SIGERROR_SUBDOMAIN_I");
			}
		}

		// get Body length count (plain-text unsigned decimal integer; OPTIONAL, default is entire body)
		var BodyLengthTag = rfcParser.parseTagValue(tagMap, "l", "[0-9]{1,76}");
		if (BodyLengthTag !== null) {
			DKIMSignature.l = parseInt(BodyLengthTag[0], 10);
		}

		// get query methods (plain-text; OPTIONAL, default is "dns/txt")
		var sig_q_tag_method = `(?:dns/txt|${rfcParser.get("hyphenated_word")}(?:/${rfcParser.get("qp_hdr_value")})?)`;
		var sig_q_tag = `${sig_q_tag_method}(?:${rfcParser.get("FWS")}?:${rfcParser.get("FWS")}?${sig_q_tag_method})*`;
		var QueryMetTag = rfcParser.parseTagValue(tagMap, "q", sig_q_tag);
		if (QueryMetTag === null) {
			DKIMSignature.q = "dns/txt";
		} else {
			if (!new RegExp("dns/txt").test(QueryMetTag[0])) {
				throw new DKIM_SigError("DKIM_SIGERROR_UNKNOWN_Q");
			}
			DKIMSignature.q = "dns/txt";
		}

		// get selector subdividing the namespace for the "d=" (domain) tag (plain-text; REQUIRED)
		var SelectorTag;
		try {
			SelectorTag = rfcParser.parseTagValue(tagMap, "s", `${rfcParser.get("sub_domain")}(?:\\.${rfcParser.get("sub_domain")})*`);
		} catch (exception) {
			if (exception instanceof DKIM_SigError &&
				exception.errorType === "DKIM_SIGERROR_ILLFORMED_S")
			{
				// TODO: Find an internationalized more relaxed version, if needed
				// try to parse selector in a more relaxed way
				var sub_domain_ = "(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?)";
				SelectorTag = rfcParser.parseTagValue(tagMap, "s", `${sub_domain_}(?:\\.${sub_domain_})*`);
				switch (prefs.getIntPref("error.illformed_s.treatAs")) {
					case 0: // error
						throw exception;
					case 1: // warning
						DKIMSignature.warnings.push({name: "DKIM_SIGERROR_ILLFORMED_S"});
						break;
					case 2: // ignore
						break;
					default:
						throw new Error("invalid error.illformed_s.treatAs");
				}
			} else {
				throw exception;
			}
		}
		if (SelectorTag === null) {
			throw new DKIM_SigError("DKIM_SIGERROR_MISSING_S");
		}
		DKIMSignature.s = SelectorTag[0];

		// get Signature Timestamp (plain-text unsigned decimal integer; RECOMMENDED,
		// default is an unknown creation time)
		var SigTimeTag = rfcParser.parseTagValue(tagMap, "t", "[0-9]+");
		if (SigTimeTag !== null) {
			DKIMSignature.t = parseInt(SigTimeTag[0], 10);
		}

		// get Signature Expiration (plain-text unsigned decimal integer;
		// RECOMMENDED, default is no expiration)
		// The value of the "x=" tag MUST be greater than the value of the "t=" tag if both are present
		var ExpTimeTag = rfcParser.parseTagValue(tagMap, "x", "[0-9]+");
		if (ExpTimeTag !== null) {
			DKIMSignature.x = parseInt(ExpTimeTag[0], 10);
			if (DKIMSignature.t !== null && DKIMSignature.x < DKIMSignature.t) {
				throw new DKIM_SigError("DKIM_SIGERROR_TIMESTAMPS");
			}
		}

		// get Copied header fields (dkim-quoted-printable, but see description; OPTIONAL, default is null)
		var hdr_name_FWS = `(?:(?:[!-9<-~]${rfcParser.get("FWS")}?)+)`;
		var sig_z_tag_copy = `${hdr_name_FWS}${rfcParser.get("FWS")}?:${rfcParser.get("qp_hdr_value")}`;
		var sig_z_tag = `${sig_z_tag_copy}(\\|${rfcParser.get("FWS")}?${sig_z_tag_copy})*`;
		var CopyHeaderFieldsTag = rfcParser.parseTagValue(tagMap, "z", sig_z_tag);
		if (CopyHeaderFieldsTag !== null) {
			DKIMSignature.z = CopyHeaderFieldsTag[0].replace(new RegExp(rfcParser.get("FWS"),"g"), "");
		}

		return DKIMSignature;
	}

	/**
	 * Get a DKIM result with some information from the header already in it.
	 *
	 * @param {string} result
	 * @param {Object} dkimSignature | null
	 * @returns {dkimSigResultV2}
	 */
	function createBaseResult(result, dkimSignature) {
		let baseResult;
		if (dkimSignature) {
			baseResult = {
				version : "2.1",
				result : result,
				sdid : dkimSignature.d,
				auid : dkimSignature.i,
				selector : dkimSignature.s,
				timestamp : dkimSignature.t,
				expiration : dkimSignature.x,
				algorithmSignature : dkimSignature.a_sig,
				algorithmHash : dkimSignature.a_hash,
				signedHeaders : dkimSignature.h_array ? copy(dkimSignature.h_array) : undefined,
				keyLength : dkimSignature.a_keylength
			};
		} else {
			baseResult = {
				version : "2.1",
				result : result,
			};
		}
		return baseResult;
	}

	/*
	 * parse the DKIM key record
	 * key record is specified in Section 3.6.1 of RFC 6376
	 *
	 * @throws {Error|DKIM_SigError}
	 */
	function parseDKIMKeyRecord(DKIMKeyRecord) {
		var DKIMKey = {
			/** @type {string} */
			v : "", // Version
			/** @type {string?} */
			h : null, // hash algorithms
			/** @type {string[]?} */
			h_array : null, // array hash algorithms
			/** @type {string} */
			k : "", // key type
			/** @type {string?} */
			n : null, // notes
			p : "", // Public-key data
			/** @type {string?} */
			s : null, // Service Type
			/** @type {string?} */
			t : null, // flags
			/** @type {string[]?} */
			t_array : [] // array of all flags
		};

		// parse tag-value list
		var parsedTagMap = rfcParser.parseTagValueList(DKIMKeyRecord);
		if (parsedTagMap === -1) {
			throw new DKIM_SigError("DKIM_SIGERROR_KEY_ILLFORMED_TAGSPEC");
		} else if (parsedTagMap === -2) {
			throw new DKIM_SigError("DKIM_SIGERROR_KEY_DUPLICATE_TAG");
		}
		if (!(toType(parsedTagMap) === "Map")) {
			throw new Error(`unexpected return value from parseTagValueList: ${parsedTagMap}`);
		}
		/** @type {Map} */
		// @ts-expect-error
		let tagMap = parsedTagMap;

		// get version (plain-text; RECOMMENDED, default is "DKIM1")
		// If specified, this tag MUST be set to "DKIM1"
		// This tag MUST be the first tag in the record
		var key_v_tag_value = `${rfcParser.get("dkim_safe_char")}*`;
		var versionTag = rfcParser.parseTagValue(tagMap, "v", key_v_tag_value, 2);
		if (versionTag === null || versionTag[0] === "DKIM1") {
			DKIMKey.v = "DKIM1";
		} else {
			throw new DKIM_SigError("DKIM_SIGERROR_KEY_INVALID_V");
		}

		// get Acceptable hash algorithms (plain-text; OPTIONAL, defaults toallowing all algorithms)
		var key_h_tag_alg = `(?:sha1|sha256|${rfcParser.get("hyphenated_word")})`;
		var key_h_tag = `${key_h_tag_alg}(?:${rfcParser.get("FWS")}?:${rfcParser.get("FWS")}?${key_h_tag_alg})*`;
		var algorithmTag = rfcParser.parseTagValue(tagMap, "h", key_h_tag, 2);
		if (algorithmTag !== null) {
			DKIMKey.h = algorithmTag[0];
			DKIMKey.h_array = DKIMKey.h.split(":").map(s => s.trim()).filter(x => x);
		}

		// get Key type (plain-text; OPTIONAL, default is "rsa")
		var key_k_tag_type = `(?:rsa|ed25519|${rfcParser.get("hyphenated_word")})`;
		var keyTypeTag = rfcParser.parseTagValue(tagMap, "k", key_k_tag_type, 2);
		if (keyTypeTag === null) {
			DKIMKey.k = "rsa";
		} else if (keyTypeTag[0] === "ed25519" || keyTypeTag[0] === "rsa") {
			DKIMKey.k = keyTypeTag[0];
		} else {
			throw new DKIM_SigError("DKIM_SIGERROR_KEY_UNKNOWN_K");
		}

		// get Notes (qp-section; OPTIONAL, default is empty)
		var ptext = `(?:${rfcParser.get("hex_octet")}|[!-<>-~])`;
		var qp_section = `(?:(?:${ptext}| |\t)*${ptext})?`;
		var notesTag = rfcParser.parseTagValue(tagMap, "n", qp_section, 2);
		if (notesTag !== null) {
			DKIMKey.n = notesTag[0];
		}

		// get Public-key data (base64; REQUIRED)
		// empty value means that this public key has been revoked
		var keyTag = rfcParser.parseTagValue(tagMap, "p", `${rfcParser.get("base64string")}?`, 2);
		if (keyTag === null) {
			throw new DKIM_SigError("DKIM_SIGERROR_KEY_MISSING_P");
		} else {
			if (keyTag[0] === "") {
				throw new DKIM_SigError("DKIM_SIGERROR_KEY_REVOKED");
			} else {
				DKIMKey.p = keyTag[0];
			}
		}

		// get Service Type (plain-text; OPTIONAL; default is "*")
		var key_s_tag_type = `(?:email|\\*|${rfcParser.get("hyphenated_word")})`;
		var key_s_tag = `${key_s_tag_type}(?:${rfcParser.get("FWS")}?:${rfcParser.get("FWS")}?${key_s_tag_type})*`;
		var serviceTypeTag = rfcParser.parseTagValue(tagMap, "s", key_s_tag, 2);
		if (serviceTypeTag === null) {
			DKIMKey.s = "*";
		} else {
			let service_types = serviceTypeTag[0].split(":").map(s => s.trim());
			if (service_types.some(s => s === "*" || s === "email")) {
				DKIMKey.s = serviceTypeTag[0];
			} else {
				throw new DKIM_SigError("DKIM_SIGERROR_KEY_NOTEMAILKEY");
			}
		}

		// get Flags (plaintext; OPTIONAL, default is no flags set)
		var key_t_tag_flag = `(?:y|s|${rfcParser.hyphenated_word})`;
		var key_t_tag = `${key_t_tag_flag}(?:${rfcParser.get("FWS")}?:${rfcParser.get("FWS")}?${key_t_tag_flag})*`;
		var flagsTag = rfcParser.parseTagValue(tagMap, "t", key_t_tag, 2);
		if (flagsTag !== null) {
			DKIMKey.t = flagsTag[0];
			// get the flags and store them in an array
			DKIMKey.t_array = DKIMKey.t.split(":").map(s => s.trim()).filter(x => x);
		} else {
			DKIMKey.t = "";
		}

		return DKIMKey;
	}

	/*
	 * canonicalize a single header field using the relaxed algorithm
	 * specified in Section 3.4.2 of RFC 6376
	 */
	function canonicalizationHeaderFieldRelaxed(headerField) {
		// Convert header field name (not the header field values) to lowercase
		headerField = headerField.replace(
			/^\S[^:]*/,
			function(match) {
				return match.toLowerCase();
			}
		);

		// Unfold header field continuation lines
		headerField = headerField.replace(/\r\n[ \t]/g," ");

		// Convert all sequences of one or more WSP characters to a single SP character.
		// WSP characters here include those before and after a line folding boundary.
		headerField = headerField.replace(/[ \t]+/g," ");

		// Delete all WSP characters at the end of each unfolded header field value.
		headerField = headerField.replace(/[ \t]+\r\n/,"\r\n");

		// Delete any WSP characters remaining before and after the colon
		// separating the header field name from the header field value.
		// The colon separator MUST be retained.
		headerField = headerField.replace(/[ \t]*:[ \t]*/,":");

		return headerField;
	}

	/*
	 * canonicalize the body using the simple algorithm
	 * specified in Section 3.4.3 of RFC 6376
	 */
	function canonicalizationBodySimple(body) {
		// Ignore all empty lines at the end of the message body
		// If there is no body or no trailing CRLF on the message body, a CRLF is added
		// for some reason /(\r\n)*$/ doesn't work all the time
		// (especially in large strings; matching only last "\r\n")
		body = body.replace(/((\r\n)+)?$/,"\r\n");

		return body;
	}

	/*
	 * canonicalize the body using the relaxed algorithm
	 * specified in Section 3.4.4 of RFC 6376
	 */
	function canonicalizationBodyRelaxed(body) {
		// Ignore all whitespace at the end of lines
		body = body.replace(/[ \t]+\r\n/g,"\r\n");
		// Reduce all sequences of WSP within a line to a single SP character
		body = body.replace(/[ \t]+/g," ");

		// Ignore all empty lines at the end of the message body
		// If the body is non-empty but does not end with a CRLF, a CRLF is added
		// for some reason /(\r\n)*$/ doesn't work all the time
		// (especially in large strings; matching only last "\r\n")
		body = body.replace(/((\r\n)+)?$/,"\r\n");

		// If only one \r\n rests, there were only empty lines or body was empty.
		if (body === "\r\n") {
			return "";
		}
		return body;
	}

	/*
	 * Computing the Message Hash for the body
	 * specified in Section 3.7 of RFC 6376
	 *
	 * @throws {DKIM_SigError}
	 */
	function computeBodyHash(msg, DKIMSignature) {
		// canonicalize body
		var bodyCanon;
		switch (DKIMSignature.c_body) {
			case "simple":
				bodyCanon = canonicalizationBodySimple(msg.bodyPlain);
				break;
			case "relaxed":
				bodyCanon = canonicalizationBodyRelaxed(msg.bodyPlain);
				break;
			default:
				throw new Error("unsupported canonicalization algorithm got parsed");
		}

		if (prefs.getIntPref("debugLevel") >= 2) {
			writeStringToTmpFile(bodyCanon, "bodyCanon.txt");
		}

		// if a body length count is given
		if (DKIMSignature.l !== null) {
			// check the value of the body length tag
			if (DKIMSignature.l > bodyCanon.length) {
				// length tag exceeds body size
				log.debug("bodyCanon.length: " + bodyCanon.length);
				throw new DKIM_SigError("DKIM_SIGERROR_TOOLARGE_L");
			} else if (DKIMSignature.l < bodyCanon.length){
				// length tag smaller when body size
				DKIMSignature.warnings.push({name: "DKIM_SIGWARNING_SMALL_L"});
				log.debug("Warning: DKIM_SIGWARNING_SMALL_L ("+
					dkimStrings.getString("DKIM_SIGWARNING_SMALL_L")+")");
			}

			// truncated body to the length specified in the "l=" tag
			bodyCanon = bodyCanon.substr(0, DKIMSignature.l);
		}

		// compute body hash
		var bodyHash;
		switch (DKIMSignature.a_hash) {
			case "sha1":
				bodyHash = dkim_hash(bodyCanon, "sha1", "b64");
				break;
			case "sha256":
				bodyHash = dkim_hash(bodyCanon, "sha256", "b64");
				break;
			default:
				throw new Error("unsupported hash algorithm (body) got parsed");
		}

		return bodyHash;
	}

	/*
	 * Computing the input for the header Hash
	 * specified in Section 3.7 of RFC 6376
	 *
	 * @throws {Error}
	 */
	function computeHeaderHashInput(msg, DKIMSignature) {
		var hashInput = "";
		var headerFieldArray, headerField;

		// set header canonicalization algorithm
		var headerCanonAlgo;
		switch (DKIMSignature.c_header) {
			case "simple":
				headerCanonAlgo = function (/** @type {string} */ headerField) {return headerField;};
				break;
			case "relaxed":
				headerCanonAlgo = canonicalizationHeaderFieldRelaxed;
				break;
			default:
				throw new Error("unsupported canonicalization algorithm (header) got parsed");
		}

		// copy header fields
		var headerFields = new Map();
		for (var [key, val] of msg.headerFields) {
			headerFields.set(key, val.slice());
		}

		// get header fields specified by the "h=" tag
		// and join their canonicalized form
		for(var i = 0; i < DKIMSignature.h_array.length; i++) {
			// if multiple instances of the same header field are signed
			// include them in reverse order (from bottom to top)
			headerFieldArray = headerFields.get(DKIMSignature.h_array[i]);
			// nonexisting header field MUST be treated as the null string
			if (headerFieldArray !== undefined) {
				headerField = headerFieldArray.pop();
				if (headerField) {
					hashInput += headerCanonAlgo(headerField);
				}
			}
		}

		// add DKIM-Signature header to the hash input
		// with the value of the "b=" tag (including all surrounding whitespace) deleted
		var pos_bTag = DKIMSignature.original_header.indexOf(DKIMSignature.b_folded);
		var tempBegin = DKIMSignature.original_header.substr(0, pos_bTag);
		tempBegin = tempBegin.replace(new RegExp(`${rfcParser.get("FWS")}?$`), "");
		var tempEnd = DKIMSignature.original_header.substr(pos_bTag+DKIMSignature.b_folded.length);
		tempEnd = tempEnd.replace(new RegExp(`^${rfcParser.get("FWS")}?`), "");
		var temp = tempBegin + tempEnd;
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
	 * @param {Object} msg
	 * @param {Object} [dkimSignature]
	 * @return {dkimSigResultV2}
	 */
	function handleException(e, msg, dkimSignature = {} ) {
		let result = createBaseResult("", dkimSignature);

		if (e instanceof DKIM_SigError) {
			result.result = "PERMFAIL";
			result.errorType = e.errorType;
			result.errorStrParams = e.errorStrParams;
			result.hideFail = e.errorType === "DKIM_SIGERROR_KEY_TESTMODE" ||
				msg.DKIMSignPolicy.hideFail;
			result.keySecure = dkimSignature.keyQueryResult &&
				dkimSignature.keyQueryResult.secure;

			log.warn(e);
		} else if (e instanceof DKIM_TempError) {
			result.result = "TEMPFAIL";
			result.errorType = e.errorType;

			log.error("Temporary error during DKIM verification:", e);
		} else {
			result.result = "TEMPFAIL";

			log.fatal("Error during DKIM verification:", e);
		}

		return result;
	}

	/**
	 * Verifying a single DKIM signature
	 *
	 * @param {Object} msg
	 * @param {Object} DKIMSignature
	 * @return {Promise<dkimSigResultV2>}
	 * @throws {DKIM_SigError|Error}
	 */
	// eslint-disable-next-line complexity
	async function verifySignature(msg, DKIMSignature) {
		// check SDID and AUID
		Policy.checkSDID(msg.DKIMSignPolicy.sdid, msg.from, DKIMSignature.d, DKIMSignature.warnings);

		// check signed headers
		Policy.checkHeadersSigned(msg.headerFields, DKIMSignature);

		// get time of received header or use system time as reference for signature expiration check
		let receivedTime = null;
		const receivedHeaders = msg.headerFields.get("received");
		if (receivedHeaders && receivedHeaders[0]) {
			const recDateTimeStart = receivedHeaders[0].lastIndexOf(";");
			if (recDateTimeStart === -1) {
				log.warn("Could not find the date time in the Received header: "+receivedHeaders[0]);
			} else {
				// Trim all surrounding whitespace to avoid parsing problems.
				const recDateTimeStr = receivedHeaders[0].substring(recDateTimeStart + 1).trim();
				receivedTime = new Date(recDateTimeStr);
				if (receivedTime.toString() === "Invalid Date") {
					log.warn("Could not parse the date time in the Received header");
					receivedTime = null;
				}
			}
		}

		const verifyTime = receivedTime ? receivedTime : new Date();
		const time = Math.round(verifyTime.getTime() / 1000);
		log.debug(`Info: Using '${verifyTime}' as timestamp for expiration check`);

		// warning if signature expired
		if (DKIMSignature.x !== null && DKIMSignature.x < time) {
			DKIMSignature.warnings.push({name: "DKIM_SIGWARNING_EXPIRED"});
			log.debug("Warning: DKIM_SIGWARNING_EXPIRED");
		}
		// warning if signature in future
		// We allow a difference of 15 min so small clock differences between
		// sender and receiver are not causing any issues
		const allowedDifference = 15 * 60;
		if (DKIMSignature.t !== null && DKIMSignature.t > time + allowedDifference) {
			DKIMSignature.warnings.push({name: "DKIM_SIGWARNING_FUTURE"});
			log.debug("Warning: DKIM_SIGWARNING_FUTURE");
		}

		// Compute the Message Hash for the body
		var bodyHash = computeBodyHash(msg, DKIMSignature);
		log.debug("computed body hash: " + bodyHash);

		// compare body hash
		if (bodyHash !== DKIMSignature.bh) {
			throw new DKIM_SigError("DKIM_SIGERROR_CORRUPT_BH");
		}

		log.trace("Receiving DNS key for DKIM-Signature ...");
		DKIMSignature.keyQueryResult = await Key.getKey(DKIMSignature.d, DKIMSignature.s);
		log.trace("Received DNS key for DKIM-Signature");

		// if key is not signed by DNSSEC
		if (!DKIMSignature.keyQueryResult.secure) {
			switch (prefs.getIntPref("error.policy.key_insecure.treatAs")) {
				case 0: // error
					throw new DKIM_SigError("DKIM_POLICYERROR_KEY_INSECURE");
				case 1: // warning
					DKIMSignature.warnings.push({name: "DKIM_POLICYERROR_KEY_INSECURE"});
					log.debug("Warning: DKIM_POLICYERROR_KEY_INSECURE");
					break;
				case 2: // ignore
					break;
				default:
					throw new Error("invalid error.policy.key_insecure.treatAs");
			}
		}

		DKIMSignature.DKIMKey = parseDKIMKeyRecord(DKIMSignature.keyQueryResult.key);
		log.debug("Parsed DKIM-Key: " + DKIMSignature.DKIMKey.toSource());

		// check that the testing flag is not set
		if (DKIMSignature.DKIMKey.t_array.includes("y")) {
			if (prefs.getBoolPref("error.key_testmode.ignore")) {
				DKIMSignature.warnings.push({name: "DKIM_SIGERROR_KEY_TESTMODE"});
				log.debug("Warning: DKIM_SIGERROR_KEY_TESTMODE");
			} else {
				throw new DKIM_SigError("DKIM_SIGERROR_KEY_TESTMODE");
			}
		}

		// if s flag is set in DKIM key record
		// AUID must be from the same domain as SDID (and not a subdomain)
		if (DKIMSignature.DKIMKey.t_array.includes("s") &&
		    !stringEqual(DKIMSignature.i_domain, DKIMSignature.d)) {
			throw new DKIM_SigError("DKIM_SIGERROR_DOMAIN_I");
		}

		// If the "h=" tag exists in the DKIM key record
		// the hash algorithm implied by the "a=" tag in the DKIM-Signature header field
		// must be included in the contents of the "h=" tag
		if (DKIMSignature.DKIMKey.h_array &&
		    !DKIMSignature.DKIMKey.h_array.includes(DKIMSignature.a_hash)) {
			throw new DKIM_SigError("DKIM_SIGERROR_KEY_HASHNOTINCLUDED");
		}

		// Compute the input for the header hash
		var headerHashInput = computeHeaderHashInput(msg,DKIMSignature);
		log.debug("Header hash input:\n" + headerHashInput);

		// verify Signature
		var keyInfo = {};

		// Selecting verification function depending on used signature algorithm
		var verifyFunction = null;
		switch (DKIMSignature.a_sig) {
			case "ed25519":
				verifyFunction = verifyED25519Sig;
				break;
			case "rsa":
				verifyFunction = verifyRSASig;
				break;
			default:
			// this should never happen, as it's already handled in newDKIMSignature
				throw new DKIM_SigError("DKIM_SIGERROR_UNKNOWN_A");
		}

		var isValid = false;
		try {
			isValid = verifyFunction(DKIMSignature.DKIMKey.p, headerHashInput, DKIMSignature.a_hash,
			DKIMSignature.b, DKIMSignature.warnings, keyInfo);
		} finally {
			DKIMSignature.a_keylength = keyInfo.keyLength;
		}
		if (!isValid && prefs.getIntPref("error.contentTypeCharsetAddedQuotes.treatAs") > 0) {
				log.debug("Try with removed quotes in Content-Type charset.");
			const contentTypeField = msg.headerFields.get("content-type")[0];
			const sanitizedContentTypeField = contentTypeField.replace(/charset="([^"]+)"/i, "charset=$1");

			if (contentTypeField !== sanitizedContentTypeField) {
				msg.headerFields.get("content-type")[0] = sanitizedContentTypeField;
				// Compute the input for the header hash
				headerHashInput = computeHeaderHashInput(msg,DKIMSignature);
				log.debug("Header hash input:\n" + headerHashInput);
				// verify Signature
				keyInfo = {};
				isValid = verifyFunction(DKIMSignature.DKIMKey.p, headerHashInput,
						DKIMSignature.a_hash, DKIMSignature.b, DKIMSignature.warnings, keyInfo);
				if (prefs.getIntPref("error.contentTypeCharsetAddedQuotes.treatAs") === 1) {
					DKIMSignature.warnings.push({name: "DKIM_SIGERROR_CONTENT_TYPE_CHARSET_ADDED_QUOTES"});
					log.debug("Warning: DKIM_SIGERROR_CONTENT_TYPE_CHARSET_ADDED_QUOTES");
				}
			} else {
				log.debug("Nothing changed, no need to reverify...");
			}
		}
		if (!isValid && prefs.getBoolPref("error.sanitizeSubject")) {
			log.debug("Trying to sanitize the subject header field");
			const subjectField = msg.headerFields.get("subject")[0];
			const sanitizeRegexp = /(Subject:\s)(?:\*|\[).+(?:\*|\])\s(.*)/;
			const sanitizedSubject = subjectField.replace(sanitizeRegexp, "$2").trim();
			const sanitizedSubjectField = subjectField.replace(sanitizeRegexp, "$1$2");

			if (subjectField !== sanitizedSubjectField) {
				msg.headerFields.get("subject")[0] = sanitizedSubjectField;
				// Compute the input for the header hash
				headerHashInput = computeHeaderHashInput(msg,DKIMSignature);
				log.debug("Header hash input:\n" + headerHashInput);
				// verify Signature
				keyInfo = {};
				isValid = verifyFunction(DKIMSignature.DKIMKey.p, headerHashInput,
						DKIMSignature.a_hash, DKIMSignature.b, DKIMSignature.warnings, keyInfo);
				if (isValid) {
					// Adding a warning, that the subject was changed
					DKIMSignature.warnings.push({ name: "DKIM_SIGERROR_SUBJECT_MODIFIED", params: [sanitizedSubject] });
					log.debug("Sanitized subject: " + sanitizedSubject);
				} else {
					// Restoring the original subject field
					msg.headerFields.get("subject")[0] = subjectField;
				}
			} else {
				log.debug("Nothing changed, no need to reverify...");
			}
		}

		if (!isValid) {
				throw new DKIM_SigError("DKIM_SIGERROR_BADSIG");
		}

		if (DKIMSignature.a_sig !== DKIMSignature.DKIMKey.k) {
			throw new DKIM_SigError("DKIM_SIGERROR_KEY_MISMATCHED_K");
		}

		// hash algorithm defined in public-key data must be the same as in the header
		// RSA verifier uses the algo defined in the ASN1 structure, not the one defined in dkim header
		if (DKIMSignature.a_sig === "rsa" && keyInfo.algName !== DKIMSignature.a_hash) {
			throw new DKIM_SigError("DKIM_SIGERROR_KEY_HASHMISMATCH");
		}

		// add should be signed rule
		if (!msg.DKIMSignPolicy.foundRule) {
			Policy.signedBy(msg.from, DKIMSignature.d);
		}

		// return result
		log.trace("Everything is fine");
		var verification_result = createBaseResult("SUCCESS", DKIMSignature);
		verification_result.warnings = DKIMSignature.warnings;
		verification_result.keySecure = DKIMSignature.keyQueryResult.secure;
		return verification_result;
	}

	/**
	 * processes signatures
	 *
	 * @param {Object} msg
	 * @return {Promise<dkimSigResultV2[]>}
	 */
	async function processSignatures(msg) {
		let iDKIMSignatureIdx = 0;
		let DKIMSignature;
		// contains the result of all DKIM-Signatures which have been verified
		let sigResults = [];

		if (msg.headerFields.get("dkim-signature")) {
			log.debug(msg.headerFields.get("dkim-signature").length +
				" DKIM-Signatures found.");
		} else {
			return sigResults;
		}

		// RFC6376 - 3.5.  The DKIM-Signature Header Field
		// "The DKIM-Signature header field SHOULD be treated as though it were a
		// trace header field as defined in Section 3.6 of [RFC5322] and hence
		// SHOULD NOT be reordered and SHOULD be prepended to the message."
		//
		// The first added signature is verified first.
		for (iDKIMSignatureIdx = msg.headerFields.get("dkim-signature").length - 1;
		     iDKIMSignatureIdx >=0; iDKIMSignatureIdx--) {
			let sigRes;
			try {
				log.debug("Verifying DKIM-Signature " + (iDKIMSignatureIdx+1) + " ...");
				DKIMSignature = newDKIMSignature(
					msg.headerFields.get("dkim-signature")[iDKIMSignatureIdx]);
				parseDKIMSignature(DKIMSignature);
				log.debug("Parsed DKIM-Signature " + (iDKIMSignatureIdx+1) + ": " +
					DKIMSignature.toSource());
				sigRes = await verifySignature(msg, DKIMSignature);
				log.debug("Verified DKIM-Signature " + (iDKIMSignatureIdx+1));
			} catch(e) {
				sigRes = handleException(e, msg, DKIMSignature);
				log.debug("Exception on DKIM-Signature " + (iDKIMSignatureIdx+1));
			}

			log.trace("Adding DKIM-Signature " + (iDKIMSignatureIdx+1) +
				" result to result list");
			sigResults.push(sigRes);
		}

		return sigResults;
	}

	/**
	 * Checks if at least on signature exists.
	 * If not, adds one to signatures with result "no sig" or "missing sig".
	 *
	 * @param {Object} msg
	 * @param {dkimSigResultV2[]} signatures
	 * @return {void}
	 */
	function checkForSignatureExistence(msg, signatures) {
		// check if a DKIM signature exists
		if (signatures.length === 0) {
			let dkimSigResultV2;
			if (!msg.DKIMSignPolicy.shouldBeSigned) {
				dkimSigResultV2 = {
					version: "2.0",
					result: "none",
				};
			} else {
				dkimSigResultV2 = handleException(
					new DKIM_SigError(
						"DKIM_POLICYERROR_MISSING_SIG",
						[msg.DKIMSignPolicy.sdid]
					),
					msg
				);
			}

			signatures.push(dkimSigResultV2);
		}
	}

var that = {
/*
 * public methods/variables
 */

	/*
	 * init
	 */
	init : function Verifier_init() {}, // eslint-disable-line no-empty-function

	/**
	 * Callback for the result of the verification.
	 *
	 * @callback dkimResultCallback
	 * @param {String} msgURI
	 * @param {dkimResultV1} result
	 */

	/**
	 * Verifies the message with the given msgURI.
	 *
	 * @deprecated Use verify2() or authVerifier.verify() instead.
	 * @param {String} msgURI
	 * @param {dkimResultCallback} dkimResultCallback
	 * @return {void}
	 */
	verify: function Verifier_verify(msgURI, dkimResultCallback) {
		let promise = (async () => {
			let msg;
			let result;
			try {
				msg = await that.createMsg(msgURI);

				let sigResults = await processSignatures(msg);

				// check if DKIMSignatureHeader exist
				checkForSignatureExistence(msg, sigResults);
				that.sortSignatures(msg, sigResults);

				result = {
					version : "1.1",
					result : sigResults[0].result,
					SDID : sigResults[0].sdid,
					selector : sigResults[0].selector,
					warnings : sigResults[0].warnings &&
						sigResults[0].warnings.map(e => e.name),
					errorType : sigResults[0].errorType,
					shouldBeSignedBy : msg.DKIMSignPolicy.sdid[0],
					hideFail : sigResults[0].hideFail,
				};
			} catch (exception) {
				if (!msg) {
					msg = {"msgURI": msgURI};
				}
				result = {
					version : "1.0",
					result : "TEMPFAIL",
					errorType : exception.errorType
				};
				log.warn(exception);
			}

			dkimResultCallback(msg.msgURI, result);
		})();
		promise.then(null, function onReject(exception) {
			log.fatal("verify failed", exception);
		});
	},

	/**
	 * @typedef {Object} Msg
	 * @property {String} msgURI
	 * @property {Map<String, String[]>} headerFields
	 * @property {String} headerPlain
	 * @property {String} bodyPlain
	 * @property {String} from
	 * @property {String} listId
	 * @property {DKIMSignPolicy} DKIMSignPolicy
	 */

	/**
	 * Verifies the message given message.
	 *
	 * @param {Msg} msg
	 * @return {Promise<dkimResultV2>}
	 */
	verify2: function Verifier_verify2(msg) {
		var promise = (async () => {
			let res = {
				version: "2.0",
				signatures: await processSignatures(msg),
			};
			checkForSignatureExistence(msg, res.signatures);
			that.sortSignatures(msg, res.signatures);
			return res;
		})();
		promise.then(null, function onReject(exception) {
			log.warn("verify2 failed", exception);
		});
		return promise;
	},

	/**
	 * Creates a message object given the msgURI.
	 *
	 * @param {String} msgURI
	 * @return {Promise<Msg>}
	 * @throws {DKIM_Error}
	 */
	createMsg: function Verifier_createMsg(msgURI) {
		var promise = (async () => {
			// read msg
			/** @type {Msg} */
			// @ts-expect-error
			let msg = await msgReader.read(msgURI);
			msg.msgURI = msgURI;

			// parse the header
			msg.headerFields = msgReader.parseHeader(msg.headerPlain);

			let msgHeaderParser = Cc["@mozilla.org/messenger/headerparser;1"].
				createInstance(Ci.nsIMsgHeaderParser);

			// get last from address
			if (msg.headerFields.has("from")) {
				// @ts-expect-error
				let numFrom = msg.headerFields.get("from").length;
				// @ts-expect-error
				let author = msg.headerFields.get("from")[numFrom-1];
				author = author.replace(/^From[ \t]*:/i,"");
				let from;
				try {
					from = msgHeaderParser.extractHeaderAddressMailboxes(author);
				} catch (error) {
					throw new DKIM_Error("From address is ill-formed");
				}
				msg.from = from;
			} else {
				throw new DKIM_Error("E-Mail has no from address");
			}

			// get list-id
			if (msg.headerFields.has("list-id")) {
				let listId = "";
				try {
					// @ts-expect-error
					listId = msg.headerFields.get("list-id")[0];
					listId = msgHeaderParser.extractHeaderAddressMailboxes(listId);
				} catch (error) {
					log.error("Ignoring error in parsing of list-id header", error);
				}
				msg.listId = listId;
			}

			// check if msg should be signed by DKIM
			msg.DKIMSignPolicy = await Policy.shouldBeSigned(msg.from, msg.listId);

			return msg;
		})();
		promise.then(null, function onReject(exception) {
			log.warn("createMsg failed", exception);
		});
		return promise;
	},

	/**
	 * Sorts the given signatures.
	 *
	 * @param {Object} msg
	 * @param {dkimSigResultV2[]} signatures
	 * @return {void}
	 * @throws {Error}
	 */
	sortSignatures: function Verifier_sortSignatures(msg, signatures) {
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

			throw new Error(`result_compare: sig1.result: ${sig1.result}; sig2.result: ${sig2.result}`);
		}

		function warnings_compare(sig1, sig2) {
			if (sig1.result !== "SUCCESS") {
				return 0;
			}
			if (!sig1.warnings || sig1.warnings.length === 0) {
				// sig1 has no warnings
				if (!sig2.warnings || sig2.warnings.length === 0) {
					// both sigs have no warnings
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
			// both sigs have warnings
			return 0;
		}

		function sdid_compare(sig1, sig2) {
			if (sig1.sdid === sig2.sdid) {
				return 0;
			}

			if (addrIsInDomain2(msg.from, sig1.sdid)) {
				return -1;
			} else if (addrIsInDomain2(msg.from, sig2.sdid)) {
				return 1;
			}

			if (msg.listId) {
				if (domainIsInDomain(msg.listId, sig1.sdid)) {
					return -1;
				} else if (domainIsInDomain(msg.listId, sig2.sdid)) {
					return 1;
				}
			}

			return 0;
		}

		function algo_compare(sig1, sig2) {
			// prefer ed25519 over rsa
			if (sig1.algorithmSignature	=== sig2.algorithmSignature) {
				// both algorithms are equal
				return 0;
			}
			if (sig1.algorithmSignature === "ed25519") {
				// there are only ed25519 and rsa allowed, so sig2.a is rsa
				return -1;
			}
			// there are only ed25519 and rsa allowed, so sig2.a is ed25519
			return 1;
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
			cmp = algo_compare(sig1, sig2);
			if (cmp !== 0) {
				return cmp;
			}
			return -1;
		});
	},

	/*
	 * make log public
	 */
	log : log,

	/*
	 * make handleException public
	 */
	handleException : handleException,

	/*
	 * make checkForSignatureExistence public
	 */
	checkForSignatureExistence : checkForSignatureExistence,

	version: module_version,
};
return that;
}()); // the parens here cause the anonymous function to execute and return

// for logging in rsasign
// @ts-expect-error
var DKIMVerifier = {};
DKIMVerifier.log = Verifier.log;

Verifier.init();
