/*
 * dkimVerifier.jsm
 *
 * Verifies the DKIM-Signatures as specified in RFC 6376
 * http://tools.ietf.org/html/rfc6376
 * 
 * Version: 1.3.0pre1 (23 August 2014)
 * 
 * Copyright (c) 2013-2014 Philippe Lieser
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

// options for JSHint
/* jshint strict:true, moz:true, smarttabs:true */
/* jshint unused:true */ // allow unused parameters that are followed by a used parameter.
/* global Components, Dict, Services, Task */
/* global Logging, Key, Policy, MsgReader */
/* global dkimStrings, exceptionToStr, stringEndsWith, stringEqual, writeStringToTmpFile, DKIM_SigError, DKIM_InternalError */
/* exported EXPORTED_SYMBOLS, Verifier */

var EXPORTED_SYMBOLS = [
	"Verifier"
];

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cu = Components.utils;

Cu.import("resource://gre/modules/Dict.jsm");
Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/Task.jsm"); // Requires Gecko 17.0

Cu.import("resource://dkim_verifier/logging.jsm");
Cu.import("resource://dkim_verifier/helper.jsm");
Cu.import("resource://dkim_verifier/dkimKey.jsm");
Cu.import("resource://dkim_verifier/dkimPolicy.jsm");
Cu.import("resource://dkim_verifier/MsgReader.jsm");

// namespaces
var RSA = {};
// for jsbn.js
RSA.navigator = {};
RSA.navigator.appName = "Netscape";

// ASN.1
Services.scriptloader.loadSubScript("resource://dkim_verifier/asn1hex-1.1.js",
                                    RSA, "UTF-8" /* The script's encoding */);
// base64 converter
Services.scriptloader.loadSubScript("resource://dkim_verifier/base64.js",
                                    RSA, "UTF-8" /* The script's encoding */);
// RSA
Services.scriptloader.loadSubScript("resource://dkim_verifier/jsbn.js",
                                    RSA, "UTF-8" /* The script's encoding */);
Services.scriptloader.loadSubScript("resource://dkim_verifier/jsbn2.js",
                                    RSA, "UTF-8" /* The script's encoding */);
Services.scriptloader.loadSubScript("resource://dkim_verifier/rsa.js",
                                    RSA, "UTF-8" /* The script's encoding */);
Services.scriptloader.loadSubScript("resource://dkim_verifier/rsasign-1.2.js",
                                    RSA, "UTF-8" /* The script's encoding */);


const PREF_BRANCH = "extensions.dkim_verifier.";


var messenger;
var msgHeaderParser;

/*
 * DKIM Verifier module
 */
var Verifier = (function() {
	"use strict";
	
	// set hash funktions used by rsasign-1.2.js
	RSA._RSASIGN_HASHHEXFUNC.sha1 = function(s){return dkim_hash(s, "sha1", "hex");};
	RSA._RSASIGN_HASHHEXFUNC.sha256 = function(s){return dkim_hash(s, "sha256", "hex");};

/*
 * preferences
 */
	var prefs = Services.prefs.getBranch(PREF_BRANCH);
	
 /*
 * private variables
 */
	var log = Logging.getLogger("Verifier");

	// WSP help pattern as specified in Section 2.8 of RFC 6376
	var pattWSP = "[ \t]";
	// FWS help pattern as specified in Section 2.8 of RFC 6376
	var pattFWS = "(?:" + pattWSP + "*(?:\r\n)?" + pattWSP + "+)";
	// Pattern for hyphenated-word as specified in Section 2.10 of RFC 6376
	var hyphenated_word = "(?:[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?)";
	// Pattern for ALPHADIGITPS as specified in Section 2.10 of RFC 6376
	var ALPHADIGITPS = "[A-Za-z0-9+/]";
	// Pattern for base64string as specified in Section 2.10 of RFC 6376
	var base64string = "(?:"+ALPHADIGITPS+"(?:"+pattFWS+"?"+ALPHADIGITPS+")*(?:"+pattFWS+"?=){0,2})";
	// Pattern for dkim-safe-char as specified in Section 2.11 of RFC 6376
	var dkim_safe_char = "[!-:<>-~]";
	// Pattern for hex-octet as specified in Section 6.7 of RFC 2045
	var hex_octet = "(?:=[0-9ABCDEF]{2})";
	// Pattern for qp-hdr-value as specified in Section 2.10 of RFC 6376
	// same as dkim-quoted-printable with "|" encoded as specified in Section 2.11 of RFC 6376
	var qp_hdr_value = "(?:(?:"+pattFWS+"|"+hex_octet+"|[!-:<>-{}-~])*)";
	// Pattern for field-name as specified in Section 3.6.8 of RFC 5322 without ";"
	// used as hdr-name in RFC 6376
	var hdr_name = "(?:[!-9<-~]+)";

/*
 * private methods
 */

	/*
	 * wrapper for hash functions
	 * hashAlgorithm: "md2", "md5", "sha1", "sha256", "sha384", "sha512"
	 * outputFormat: "hex", "b64"
	 * 
	 * from https://developer.mozilla.org/en-US/docs/XPCOM_Interface_Reference/nsICryptoHash
	 */
	function dkim_hash(str, hashAlgorithm, outputFormat) {
		/*
		 * Converts a string to an array bytes
		 * characters >255 have their hi-byte silently ignored.
		 */
		function rstr2byteArray(str) {
			var res = new Array(str.length);
			for (var i = 0; i < str.length; i++) {
				/* jshint -W016 */
				res[i] = str.charCodeAt(i) & 0xFF;
				/* jshint +W016 */
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
				return [toHexString(hash.charCodeAt(i)) for (i in hash)].join("");
			case "b64":
				// true for base-64, false for binary data output
				return hasher.finish(true);
			default:
				throw new DKIM_InternalError("unsupported hash output selected");

		}
	}

	/**
	 * Parses a Tag=Value list.
	 * Specified in Section 3.2 of RFC 6376.
	 * 
	 * @param {String} str
	 * 
	 * @return {Dict|Number} Dict
	 *                       -1 if a tag-spec is ill-formed
	 *                       -2 duplicate tag names
	 */
	function parseTagValueList(str) {
		var tval = "[!-:<-~]+";
		var tag_name = "[A-Za-z][A-Za-z0-9_]*";
		var tag_value = "(?:"+tval+"(?:("+pattWSP+"|"+pattFWS+")+"+tval+")*)?";
		
		// delete optional semicolon at end
		if (str.charAt(str.length-1) === ";") {
			str = str.substr(0, str.length-1);
		}
		
		var array = str.split(";");
		var dict = new Dict();
		var tmp;
		var name;
		var value;
		for (var elem of array) {
			// get tag name and value
			tmp = elem.match(new RegExp(
				"^"+pattFWS+"?("+tag_name+")"+pattFWS+"?="+pattFWS+"?("+tag_value+")"+pattFWS+"?$"
			));
			if (tmp === null) {
				return -1;
			}
			name = tmp[1];
			value = tmp[2];
			
			// check that tag is no duplicate
			if (dict.has(name)) {
				return -2;
			}
			
			// store Tag=Value pair
			dict.set(name, value);
		}
		
		return dict;
	}
	
	/**
	 * Parse a tag value stored in a Dict
	 * 
	 * @param {Dict} dict
	 * @param {String} tag_name name of the tag
	 * @param {String} pattern_tag_value Pattern for the tag-value
	 * @param {Number} [expType=1] Type of exception to throw. 1 for DKIM header, 2 for DKIM key.
	 * 
	 * @return {Array|Null} The match from the RegExp if tag_name exists, otherwise null
	 * 
	 * @throws {DKIM_SigError|DKIM_InternalError} Throws if tag_value does not match.
	 */
	function parseTagValue(dict, tag_name, pattern_tag_value, expType = 1) {
		var tag_value = dict.get(tag_name);
		// return null if tag_name doesn't exists
		if (tag_value === undefined) {
			return null;
		}
		
		var res = tag_value.match(new RegExp("^"+pattern_tag_value+"$"));
		
		// throw DKIM_SigError if tag_value is ill-formed
		if (res === null) {
			if (expType === 1) {
				throw new DKIM_SigError("DKIM_SIGERROR_ILLFORMED_"+tag_name.toUpperCase());
			} else if (expType === 2) {
				throw new DKIM_SigError("DKIM_SIGERROR_KEY_ILLFORMED_"+tag_name.toUpperCase());
			} else {
				throw new DKIM_InternalError("illformed tag "+tag_name);
			}
		}
		
		return res;
	}

	function newDKIMSignature( DKIMSignatureHeader ) {
		var DKIMSignature = {
			original_header : DKIMSignatureHeader,
			warnings: [],
			verification_result: {}, // dkimResult object populated by verifySignaturePart2 or by exception handlers
			v : null, // Version
			a_sig : null, // signature algorithm (signing part)
			a_hash : null, // signature algorithm (hashing part)
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
			q : null, // query methods for public key retrievel
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
	 */
	function parseDKIMSignature(DKIMSignature) {
		var DKIMSignatureHeader = DKIMSignature.original_header;

		// strip DKIM-Signatur header name
		DKIMSignatureHeader = DKIMSignatureHeader.replace(/^DKIM-Signature[ \t]*:/i,"");
		// strip the \r\n at the end
		DKIMSignatureHeader = DKIMSignatureHeader.substr(0, DKIMSignatureHeader.length-2);
		// parse tag-value list
		var dict = parseTagValueList(DKIMSignatureHeader);
		if (dict === -1) {
			throw new DKIM_SigError("DKIM_SIGERROR_ILLFORMED_TAGSPEC");
		} else if (dict === -2) {
			throw new DKIM_SigError("DKIM_SIGERROR_DUPLICATE_TAG");
		}
		
		// get Version (plain-text; REQUIRED)
		// must be "1"
		var versionTag = parseTagValue(dict, "v", "[0-9]+");
		if (versionTag === null) {
			throw new DKIM_SigError("DKIM_SIGERROR_MISSING_V");
		}
		if (versionTag[0] === "1") {
			DKIMSignature.v = "1";
		} else {
			throw new DKIM_SigError("DKIM_SIGERROR_VERSION");
		}

		// get signature algorithm (plain-text;REQUIRED)
		// currently only "rsa-sha1" or "rsa-sha256"
		var sig_a_tag_k = "(rsa|[A-Za-z](?:[A-Za-z]|[0-9])*)";
		var sig_a_tag_h = "(sha1|sha256|[A-Za-z](?:[A-Za-z]|[0-9])*)";
		var sig_a_tag_alg = sig_a_tag_k+"-"+sig_a_tag_h;
		var algorithmTag = parseTagValue(dict, "a", sig_a_tag_alg);
		if (algorithmTag === null) {
			throw new DKIM_SigError("DKIM_SIGERROR_MISSING_A");
		}
		if (algorithmTag[0] === "rsa-sha1" || algorithmTag[0] === "rsa-sha256") {
			DKIMSignature.a_sig = algorithmTag[1];
			DKIMSignature.a_hash = algorithmTag[2];
		} else {
			throw new DKIM_SigError("DKIM_SIGERROR_UNKNOWN_A");
		}

		// get signature data (base64;REQUIRED)
		var signatureDataTag = parseTagValue(dict, "b", base64string);
		if (signatureDataTag === null) {
			throw new DKIM_SigError("DKIM_SIGERROR_MISSING_B");
		}
		DKIMSignature.b = signatureDataTag[0].replace(new RegExp(pattFWS,"g"), "");
		DKIMSignature.b_folded = signatureDataTag[0];

		// get body hash (base64;REQUIRED)
		var bodyHashTag = parseTagValue(dict, "bh", base64string);
		if (bodyHashTag === null) {
			throw new DKIM_SigError("DKIM_SIGERROR_MISSING_BH");
		}
		DKIMSignature.bh = bodyHashTag[0].replace(new RegExp(pattFWS,"g"), "");

		// get Message canonicalization (plain-text; OPTIONAL, default is "simple/simple")
		// currently only "simple" or "relaxed" for both header and body
		var sig_c_tag_alg = "(simple|relaxed|"+hyphenated_word+")";
		var msCanonTag = parseTagValue(dict, "c", sig_c_tag_alg+"(?:/"+sig_c_tag_alg+")?");
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
		// Pattern for sub-domain as specified in Section 4.1.2 of RFC 5321
		var sub_domain = "(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)";
		var domain_name = "(?:"+sub_domain+"(?:\\."+sub_domain+")+)";
		var SDIDTag = parseTagValue(dict, "d", domain_name);
		if (SDIDTag === null) {
			throw new DKIM_SigError("DKIM_SIGERROR_MISSING_D");
		}
		DKIMSignature.d = SDIDTag[0];

		// get Signed header fields (plain-text, but see description; REQUIRED)
		var sig_h_tag = "("+hdr_name+")"+"(?:"+pattFWS+"?:"+pattFWS+"?"+hdr_name+")*";
		var signedHeadersTag = parseTagValue(dict, "h", sig_h_tag);
		if (signedHeadersTag === null) {
			throw new DKIM_SigError("DKIM_SIGERROR_MISSING_H");
		}
		DKIMSignature.h = signedHeadersTag[0].replace(new RegExp(pattFWS,"g"), "");
		// get the header field names and store them in lower case in an array
		DKIMSignature.h_array = DKIMSignature.h.split(":").
			map(function (x) {return x.trim().toLowerCase();}).
			filter(function (x) {return x;});
		// check that the from header is included
		if (DKIMSignature.h_array.indexOf("from") === -1) {
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
		
		var atext = "[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]";
		var local_part = "(?:"+atext+"+(?:\\."+atext+"+)*)";
		var sig_i_tag = local_part+"?@("+domain_name+")";
		var AUIDTag = null;
		try {
			AUIDTag = parseTagValue(dict, "i", sig_i_tag);
		} catch (exception if exception instanceof DKIM_SigError &&
		         exception.errorType === "DKIM_SIGERROR_ILLFORMED_I") {
			switch (prefs.getIntPref("error.illformed_i.treatAs")) {
				case 0: // error
					throw exception;
				case 1: // warning
					DKIMSignature.warnings.push("DKIM_SIGERROR_ILLFORMED_I");
					break;
				case 2: // ignore
					break;
				default:
					throw new DKIM_InternalError("invalid error.illformed_i.treatAs");
			}
		}
		if (AUIDTag === null) {
			DKIMSignature.i = "@"+DKIMSignature.d;
			DKIMSignature.i_domain = DKIMSignature.d;
		} else {
			DKIMSignature.i = AUIDTag[0];
			DKIMSignature.i_domain = AUIDTag[1];
			if (!stringEndsWith(DKIMSignature.i_domain, DKIMSignature.d)) {
				throw new DKIM_SigError("DKIM_SIGERROR_SUBDOMAIN_I");
			}
		}

		// get Body length count (plain-text unsigned decimal integer; OPTIONAL, default is entire body)
		var BodyLengthTag = parseTagValue(dict, "l", "[0-9]{1,76}");
		if (BodyLengthTag !== null) {
			DKIMSignature.l = parseInt(BodyLengthTag[0], 10);
		}

		// get query methods (plain-text; OPTIONAL, default is "dns/txt")
		var sig_q_tag_method = "(?:dns/txt|"+hyphenated_word+"(?:/"+qp_hdr_value+")?)";
		var sig_q_tag = sig_q_tag_method+"(?:"+pattFWS+"?:"+pattFWS+"?"+sig_q_tag_method+")*";
		var QueryMetTag = parseTagValue(dict, "q", sig_q_tag);
		if (QueryMetTag === null) {
			DKIMSignature.q = "dns/txt";
		} else {
			if (!(new RegExp("dns/txt")).test(QueryMetTag[0])) {
				throw new DKIM_SigError("DKIM_SIGERROR_UNKNOWN_Q");
			}
			DKIMSignature.q = "dns/txt";
		}

		// get selector subdividing the namespace for the "d=" (domain) tag (plain-text; REQUIRED)
		var SelectorTag;
		try {
			SelectorTag = parseTagValue(dict, "s", sub_domain+"(?:\\."+sub_domain+")*");
		} catch (exception if exception instanceof DKIM_SigError &&
		         exception.errorType === "DKIM_SIGERROR_ILLFORMED_S") {
			// try to parse selector in a more relaxed way
			var sub_domain_ = "(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?)";
			SelectorTag = parseTagValue(dict, "s", sub_domain_+"(?:\\."+sub_domain_+")*");
			switch (prefs.getIntPref("error.illformed_s.treatAs")) {
				case 0: // error
					throw exception;
				case 1: // warning
					DKIMSignature.warnings.push("DKIM_SIGERROR_ILLFORMED_S");
					break;
				case 2: // ignore
					break;
				default:
					throw new DKIM_InternalError("invalid error.illformed_s.treatAs");
			}
		}
		if (SelectorTag === null) {
			throw new DKIM_SigError("DKIM_SIGERROR_MISSING_S");
		}
		DKIMSignature.s = SelectorTag[0];
		
		// get Signature Timestamp (plain-text unsigned decimal integer; RECOMMENDED,
		// default is an unknown creation time)
		var SigTimeTag = parseTagValue(dict, "t", "[0-9]+");
		if (SigTimeTag !== null) {
			DKIMSignature.t = parseInt(SigTimeTag[0], 10);
		}

		// get Signature Expiration (plain-text unsigned decimal integer; 
		// RECOMMENDED, default is no expiration)
		// The value of the "x=" tag MUST be greater than the value of the "t=" tag if both are present
		var ExpTimeTag = parseTagValue(dict, "x", "[0-9]+");
		if (ExpTimeTag !== null) {
			DKIMSignature.x = parseInt(ExpTimeTag[0], 10);
			if (DKIMSignature.t !== null && DKIMSignature.x < DKIMSignature.t) {
				throw new DKIM_SigError("DKIM_SIGERROR_TIMESTAMPS");
			}
		}
		
		// get Copied header fields (dkim-quoted-printable, but see description; OPTIONAL, default is null)
		var sig_z_tag_copy = hdr_name+pattFWS+"?:"+qp_hdr_value;
		var sig_z_tag = sig_z_tag_copy+"(\\|"+pattFWS+"?"+sig_z_tag_copy+")*";
		var CopyHeaderFieldsTag = parseTagValue(dict, "z", sig_z_tag);
		if (CopyHeaderFieldsTag !== null) {
			DKIMSignature.z = CopyHeaderFieldsTag[0].replace(new RegExp(pattFWS,"g"), "");
		}
		
		return DKIMSignature;
	}

	/*
	 * parse the DKIM key record
	 * key record is specified in Section 3.6.1 of RFC 6376
	 */
	function parseDKIMKeyRecord(DKIMKeyRecord) {
		var DKIMKey = {
			v : null, // Version
			h : null, // hash algorithms
			h_array : null, // array hash algorithms
			k : null, // key type
			n : null, // notes
			p : null, // Public-key data
			s : null, // Service Type
			t : null, // flags
			t_array : [] // array of all flags
		};
		
		// parse tag-value list
		var dict = parseTagValueList(DKIMKeyRecord);
		if (dict === -1) {
			throw new DKIM_SigError("DKIM_SIGERROR_KEY_ILLFORMED_TAGSPEC");
		} else if (dict === -2) {
			throw new DKIM_SigError("DKIM_SIGERROR_KEY_DUPLICATE_TAG");
		}

		// get version (plain-text; RECOMMENDED, default is "DKIM1")
		// If specified, this tag MUST be set to "DKIM1"
		// This tag MUST be the first tag in the record
		var key_v_tag_value = dkim_safe_char+"*";
		var versionTag = parseTagValue(dict, "v", key_v_tag_value, 2);
		if (versionTag === null || versionTag[0] === "DKIM1") {
			DKIMKey.v = "DKIM1";
		} else {
			throw new DKIM_SigError("DKIM_SIGERROR_KEY_INVALID_V");
		}
		
		// get Acceptable hash algorithms (plain-text; OPTIONAL, defaults toallowing all algorithms)
		var key_h_tag_alg = "(?:sha1|sha256|"+hyphenated_word+")";
		var key_h_tag = key_h_tag_alg+"(?:"+pattFWS+"?:"+pattFWS+"?"+key_h_tag_alg+")*";
		var algorithmTag = parseTagValue(dict, "h", key_h_tag, 2);
		if (algorithmTag !== null) {
			DKIMKey.h = algorithmTag[0];
			DKIMKey.h_array = DKIMKey.h.split(":").map(String.trim).filter(function (x) {return x;});
		} 
		
		// get Key type (plain-text; OPTIONAL, default is "rsa")
		var key_k_tag_type = "(?:rsa|"+hyphenated_word+")";
		var keyTypeTag = parseTagValue(dict, "k", key_k_tag_type, 2);
		if (keyTypeTag === null || keyTypeTag[0] === "rsa") {
			DKIMKey.k = "rsa";
		} else {
			throw new DKIM_SigError("DKIM_SIGERROR_KEY_UNKNOWN_K");
		}

		// get Notes (qp-section; OPTIONAL, default is empty)
		var ptext = "(?:"+hex_octet+"|[!-<>-~])";
		var qp_section = "(?:(?:"+ptext+"| |\t)*"+ptext+")?";
		var notesTag = parseTagValue(dict, "n", qp_section, 2);
		if (notesTag !== null) {
			DKIMKey.n = notesTag[0];
		}
		
		// get Public-key data (base64; REQUIRED)
		// empty value means that this public key has been revoked
		var keyTag = parseTagValue(dict, "p", base64string+"?", 2);
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
		var key_s_tag_type = "(?:email|\\*|"+hyphenated_word+")";
		var key_s_tag = key_s_tag_type+"(?:"+pattFWS+"?:"+pattFWS+"?"+key_s_tag_type+")*";
		var serviceTypeTag = parseTagValue(dict, "s", key_s_tag, 2);
		if (serviceTypeTag === null) {
			DKIMKey.s = "*";
		} else {
			if (/email/.test(serviceTypeTag[0])) {
				DKIMKey.s = serviceTypeTag[0];
			} else {
				throw new DKIM_SigError("DKIM_SIGERROR_KEY_NOTEMAILKEY");
			}
		}

		// get Flags (plaintext; OPTIONAL, default is no flags set)
		var key_t_tag_flag = "(?:y|s|"+hyphenated_word+")";
		var key_t_tag = key_t_tag_flag+"(?:"+pattFWS+"?:"+pattFWS+"?"+key_t_tag_flag+")*";
		var flagsTag = parseTagValue(dict, "t", key_t_tag, 2);
		if (flagsTag !== null) {
			DKIMKey.t = flagsTag[0];
			// get the flags and store them in an array
			DKIMKey.t_array = DKIMKey.t.split(":").map(String.trim).filter(function (x) {return x;});
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
		
		// If only one \r\n rests, there were only emtpy lines or body was empty.
		if (body === "\r\n") {
			return "";
		} else {
			return body;
		}
	}

	/*
	 * Computing the Message Hash for the body 
	 * specified in Section 3.7 of RFC 6376
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
				throw new DKIM_InternalError("unsupported canonicalization algorithm got parsed");
		}
		
		if (prefs.getIntPref("debugLevel") >= 2) {
			writeStringToTmpFile(bodyCanon, "bodyCanon.txt");
		}
		
		// if a body length count is given
		if (DKIMSignature.l !== null) {
			// check the value of the body lenght tag
			if (DKIMSignature.l > bodyCanon.length) {
				// lenght tag exceeds body size
				throw new DKIM_SigError("DKIM_SIGERROR_TOOLARGE_L");
			} else if (DKIMSignature.l < bodyCanon.length){
				// lenght tag smaller when body size
				DKIMSignature.warnings.push("DKIM_SIGWARNING_SMALL_L");
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
				throw new DKIM_InternalError("unsupported hash algorithm (body) got parsed");
		}

		return bodyHash;
	}
	
	/*
	 * Computing the input for the header Hash
	 * specified in Section 3.7 of RFC 6376
	 */
	function computeHeaderHashInput(msg, DKIMSignature) {
		var hashInput = "";
		var headerFieldArray, headerField;

		// set header canonicalization algorithm
		var headerCanonAlgo;
		switch (DKIMSignature.c_header) {
			case "simple":
				headerCanonAlgo = function (headerField) {return headerField;};
				break;
			case "relaxed":
				headerCanonAlgo = canonicalizationHeaderFieldRelaxed;
				break;
			default:
				throw new DKIM_InternalError("unsupported canonicalization algorithm (header) got parsed");
		}
		
		// get header fields specified by the "h=" tag
		// and join their canonicalized form
		for(var i = 0; i <  DKIMSignature.h_array.length; i++) {
			// if multiple instances of the same header field are signed
			// include them in reverse order (from bottom to top)
			headerFieldArray = msg.headerFields[DKIMSignature.h_array[i]];
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
		tempBegin = tempBegin.replace(new RegExp(pattFWS+"?$"), "");
		var tempEnd = DKIMSignature.original_header.substr(pos_bTag+DKIMSignature.b_folded.length);
		tempEnd = tempEnd.replace(new RegExp("^"+pattFWS+"?"), "");
		var temp = tempBegin + tempEnd;
		// canonicalized using the header canonicalization algorithm specified in the "c=" tag
		temp = headerCanonAlgo(temp);
		// without a trailing CRLF
		hashInput += temp.substr(0, temp.length - 2);
		
		return hashInput;
	}
	
	/*
	 * handeles Exeption
	 * returns dkimResult object
	 */
	function handleExeption(e, msg, DKIMSignature = {} ) {
		if (e instanceof DKIM_SigError) {
			// return result
			let result = {
				version : "1.1",
				result : "PERMFAIL",
				errorType : e.errorType,
				SDID : DKIMSignature.d,
				selector : DKIMSignature.s,
				shouldBeSignedBy : msg.shouldBeSigned.sdid,
				hideFail : msg.shouldBeSigned.hideFail,
			};

			log.warn(exceptionToStr(e));
			
			return result;
		} else {
			// return result
			let result = {
				version : "1.0",
				result : "TEMPFAIL",
				errorType : e.errorType
			};

			if (e instanceof DKIM_InternalError) {
				log.error(exceptionToStr(e));
			} else {
				log.fatal(exceptionToStr(e));
			}

			return result;
		}
	}
	
	/*
	 * checks if msg is signed, and begins verification if it is
	 * 
	 * Generator function.
	 */
	function verifyBegin(msg) {
		// check if DKIMSignatureHeader exist
		if (msg.headerFields["dkim-signature"] === undefined) {
			if (!msg.shouldBeSigned.shouldBeSigned) {
				// return result
				msg.result = {
					version : "1.0",
					result : "none"
				};
				return;
			} else {
				throw new DKIM_SigError("DKIM_POLICYERROR_MISSING_SIG");
			}
		}

		yield processSignatures(msg);
	}

	/*
	 * 1. part of verifying the signature (key query excluded)
	 */
	function verifySignaturePart1(msg, DKIMSignature) {
		// error/warning if there is a SDID in the sign rule
		// that is different from the SDID in the signature
		if (msg.shouldBeSigned.sdid.length > 0 &&
		    !msg.shouldBeSigned.sdid.some(function (element/*, index, array*/) {
		      if (prefs.getBoolPref("policy.signRules.sdid.allowSubDomains")) {
		        return stringEndsWith(DKIMSignature.d, element);
		      } else {
		        return stringEqual(DKIMSignature.d, element);
		      }
		    })) {
			if (prefs.getBoolPref("error.policy.wrong_sdid.asWarning")) {
				DKIMSignature.warnings.push("DKIM_POLICYERROR_WRONG_SDID");
			} else {
				throw new DKIM_SigError( "DKIM_POLICYERROR_WRONG_SDID" );
			}
		}
		
		// if there is no SDID in the sign rule
		if (msg.shouldBeSigned.sdid.length === 0) {
			// warning if from is not in SDID or AUID
			if (!(stringEndsWith(msg.from, "@"+DKIMSignature.d) ||
			    stringEndsWith(msg.from, "."+DKIMSignature.d))) {
				DKIMSignature.warnings.push("DKIM_SIGWARNING_FROM_NOT_IN_SDID");
				log.debug("Warning: DKIM_SIGWARNING_FROM_NOT_IN_SDID ("+
					dkimStrings.getString("DKIM_SIGWARNING_FROM_NOT_IN_SDID")+")");
			} else if (!stringEndsWith(msg.from, DKIMSignature.i)) {
				DKIMSignature.warnings.push("DKIM_SIGWARNING_FROM_NOT_IN_AUID");
				log.debug("Warning: DKIM_SIGWARNING_FROM_NOT_IN_AUID ("+
					dkimStrings.getString("DKIM_SIGWARNING_FROM_NOT_IN_AUID")+")");
			}
		}

		var time = Math.round(Date.now() / 1000);
		// warning if signature expired
		if (DKIMSignature.x !== null && DKIMSignature.x < time) {
			DKIMSignature.warnings.push("DKIM_SIGWARNING_EXPIRED");
			log.debug("Warning: DKIM_SIGWARNING_EXPIRED ("+
				dkimStrings.getString("DKIM_SIGWARNING_EXPIRED")+")");
		}
		// warning if signature in future
		if (DKIMSignature.t !== null && DKIMSignature.t > time) {
			DKIMSignature.warnings.push("DKIM_SIGWARNING_FUTURE");
			log.debug("Warning: DKIM_SIGWARNING_FUTURE ("+
				dkimStrings.getString("DKIM_SIGWARNING_FUTURE")+")");
		}
		
		// Compute the Message Hashe for the body
		var bodyHash = computeBodyHash(msg,DKIMSignature);
		log.debug("computed body hash: "+bodyHash);
		
		// compare body hash
		if (bodyHash !== DKIMSignature.bh) {
			throw new DKIM_SigError( "DKIM_SIGERROR_CORRUPT_BH" );
		}
	}
	
	/*
	 * 2. part of verifying the signature
	 * will continue verifying after key is received
	 */
	function verifySignaturePart2(msg,DKIMSignature) {
		// if key is not signed by DNSSEC
		if (!DKIMSignature.keyQueryResult.secure) {
			switch (prefs.getIntPref("error.policy.key_insecure.treatAs")) {
				case 0: // error
					throw new DKIM_SigError( "DKIM_POLICYERROR_KEY_INSECURE" );
				case 1: // warning
					DKIMSignature.warnings.push("DKIM_POLICYERROR_KEY_INSECURE");
					break;
				case 2: // ignore
					break;
				default:
					throw new DKIM_InternalError("invalid error.policy.key_insecure.treatAs");
			}
		}

		DKIMSignature.DKIMKey = parseDKIMKeyRecord(DKIMSignature.keyQueryResult.key);
		log.debug("Parsed DKIM-Key: "+DKIMSignature.DKIMKey.toSource());
		
		// check that the testing flag is not set
		if (DKIMSignature.DKIMKey.t_array.indexOf("y") !== -1) {
			if (prefs.getBoolPref("error.key_testmode.ignore")) {
				DKIMSignature.warnings.push("DKIM_SIGERROR_KEY_TESTMODE");
				log.debug("Warning: DKIM_SIGERROR_KEY_TESTMODE ("+
					dkimStrings.getString("DKIM_SIGERROR_KEY_TESTMODE")+")");
			} else {
				throw new DKIM_SigError( "DKIM_SIGERROR_KEY_TESTMODE" );
			}
		}

		// if s flag is set in DKIM key record
		// AUID must be from the same domain as SDID (and not a subdomain)
		if (DKIMSignature.DKIMKey.t_array.indexOf("s") !== -1 &&
		    !stringEqual(DKIMSignature.i_domain, DKIMSignature.d)) {
			throw new DKIM_SigError( "DKIM_SIGERROR_DOMAIN_I" );
		}

		// If the "h=" tag exists in the DKIM key record
		// the hash algorithm implied by the "a=" tag in the DKIM-Signature header field
		// must be included in the contents of the "h=" tag
		if (DKIMSignature.DKIMKey.h_array &&
		    DKIMSignature.DKIMKey.h_array.indexOf(DKIMSignature.a_hash) === -1) {
			throw new DKIM_SigError( "DKIM_SIGERROR_KEY_HASHNOTINCLUDED" );
		}
		
		// Compute the input for the header hash
		var headerHashInput = computeHeaderHashInput(msg,DKIMSignature);
		log.debug("Header hash input:\n" + headerHashInput);

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
		var asnKey = RSA.b64tohex(DKIMSignature.DKIMKey.p);
		var posTopArray = null;
		var posKeyArray = null;
		
		// check format by comparing the 1. child in the top element
		posTopArray = RSA.ASN1HEX.getPosArrayOfChildren_AtObj(asnKey,0);
		if (posTopArray === null || posTopArray.length !== 2) {
			throw new DKIM_SigError( "DKIM_SIGERROR_KEYDECODE" );
		}
		if (RSA.ASN1HEX.getHexOfTLV_AtObj(asnKey, posTopArray[0]) !==
		    "300d06092a864886f70d0101010500") {
			throw new DKIM_SigError( "DKIM_SIGERROR_KEYDECODE" );
		}
		
		// get pos of SEQUENCE under BIT STRING
		// asn1hex does not support BIT STRING, so we will compute the position
		var pos = RSA.ASN1HEX.getStartPosOfV_AtObj(asnKey, posTopArray[1]) + 2;
		
		// get pos of modulus and publicExponent
		posKeyArray = RSA.ASN1HEX.getPosArrayOfChildren_AtObj(asnKey, pos);
		if (posKeyArray === null || posKeyArray.length !== 2) {
			throw new DKIM_SigError( "DKIM_SIGERROR_KEYDECODE" );
		}
		
		// get modulus
		var m_hex = RSA.ASN1HEX.getHexOfV_AtObj(asnKey,posKeyArray[0]);
		// get public exponent
		var e_hex = RSA.ASN1HEX.getHexOfV_AtObj(asnKey,posKeyArray[1]);

		// warning if key is short
		if (m_hex.length * 4 < 1024) {
			DKIMSignature.warnings.push("DKIM_SIGWARNING_KEYSMALL");
			log.debug("Warning: DKIM_SIGWARNING_KEYSMALL ("+
				dkimStrings.getString("DKIM_SIGWARNING_KEYSMALL")+")");
		}

		// set RSA-key
		var rsa = new RSA.RSAKey();
		rsa.setPublic(m_hex, e_hex);
		
		// verify Signature
		var keyInfo = {};
		log.debug( "verifyString " + DKIMSignature.b );
		var isValid = rsa.verifyString(headerHashInput, RSA.b64tohex(DKIMSignature.b), keyInfo);
			
		if (!isValid) {
			throw new DKIM_SigError( "DKIM_SIGERROR_BADSIG" );
		}
			
		// hash algorithm defined in public-key data must be the same as in the header
		if (keyInfo.algName !== DKIMSignature.a_hash) {
			throw new DKIM_SigError( "DKIM_SIGERROR_KEY_HASHMISMATCH" );
		}
			
		// add should be signed rule
		if (!msg.shouldBeSigned.foundRule) {
			Policy.signedBy(msg.from, DKIMSignature.d);
		}
		
		// return result
		log.debug("Everything is fine");
		DKIMSignature.verification_result = {
			version : "1.1",
			result : "SUCCESS",
			SDID : DKIMSignature.d,
			selector : DKIMSignature.s,
			warnings : DKIMSignature.warnings,
			shouldBeSignedBy : msg.shouldBeSigned.sdid,
		};
	}

	/*
	 * processes signatures
	 * 
	 * Generator function.
	 */
	function processSignatures(msg) {
		var iDKIMSignatureIdx = 0;
		var DKIMSignature;

		log.debug( msg.headerFields["dkim-signature"].length + " DKIM-Signatures found." );

		// contains all DKIM-Signatures which have been parsed and, in case, verified
		msg.DKIMSignatures = [];

		// RFC6376 - 3.5.  The DKIM-Signature Header Field
		// "The DKIM-Signature header field SHOULD be treated as though it were a
		// trace header field as defined in Section 3.6 of [RFC5322] and hence
		// SHOULD NOT be reordered and SHOULD be prepended to the message."
		//
		// The first added signature is verified first.
		for (iDKIMSignatureIdx = msg.headerFields["dkim-signature"].length - 1; iDKIMSignatureIdx >=0; iDKIMSignatureIdx--) {
			DKIMSignature = newDKIMSignature( msg.headerFields["dkim-signature"][iDKIMSignatureIdx] );

			try {
				log.debug("Parsing DKIM-Signature " + (iDKIMSignatureIdx+1) + "...");
				parseDKIMSignature( DKIMSignature );
				log.debug("Parsed DKIM-Signature: " + DKIMSignature.toSource());
				
				log.debug("Verifying DKIM-Signature " + (iDKIMSignatureIdx+1) + " - part 1...");
				verifySignaturePart1(msg, DKIMSignature);
				log.debug("Verified DKIM-Signature " + (iDKIMSignatureIdx+1) + " - part 1");
				
				log.debug("Receiving DNS key for DKIM-Signature " + (iDKIMSignatureIdx+1) + "...");
				DKIMSignature.keyQueryResult = yield Key.getKey(DKIMSignature.d, DKIMSignature.s);
				log.debug("Received DNS key for DKIM-Signature " + (iDKIMSignatureIdx+1));
				
				log.debug("Verifying DKIM-Signature " + (iDKIMSignatureIdx+1) + " - part 2...");
				verifySignaturePart2(msg, DKIMSignature);
				log.debug("Verified DKIM-Signature " + (iDKIMSignatureIdx+1) + " - part 2: " + DKIMSignature.verification_result.toSource());
			} catch(e) {
				DKIMSignature.verification_result = handleExeption(e, msg, DKIMSignature);
				log.debug("Exception on DKIM-Signature " + (iDKIMSignatureIdx+1));
			}

			log.debug("Adding DKIM-Signature " + (iDKIMSignatureIdx+1) + " to message's signatures list");
			msg.DKIMSignatures.push( DKIMSignature );
		}

		// at this point all message's DKIM-Signatures are loaded in .DKIMSignatures
		for (iDKIMSignatureIdx = 0; iDKIMSignatureIdx <= msg.DKIMSignatures.length - 1; iDKIMSignatureIdx++) {
			DKIMSignature = msg.DKIMSignatures[iDKIMSignatureIdx];

			msg.result = DKIMSignature.verification_result;
			if (msg.result.result === "SUCCESS") {
				log.debug("Returning SUCCESS: " + msg.result.toSource());
				return;
			}
		}

		log.debug("Returning last processed result: " + msg.result.toSource());
		return;
	}
	
	/**
	 * The result of the verification.
	 * 
	 * @typedef {Object} dkimResult
	 * @property {String} version result version ("1.1")
	 * @property {String} result "none" / "SUCCESS" / "PERMFAIL" / "TEMPFAIL"
	 * @property {String} SDID (only if result="SUCCESS" or "PERMFAIL")
	 * @property {String} selector (only if result="SUCCESS" or "PERMFAIL")
	 * @property {String[]} warnings (only if result="SUCCESS")
	 * @property {String} errorType
	 * @property {String} shouldBeSignedBy
	 * @property {Boolean} hideFail
	 */
	/*
		result format:
		{
			version : "1.1",
			result : "none" / "SUCCESS" / "PERMFAIL" / "TEMPFAIL",
			SDID : string (only if result="SUCCESS" or "PERMFAIL" (since 1.1)),
			selector : string (only if result="SUCCESS" or "PERMFAIL"; since 1.1),
			warnings : array (only if result="SUCCESS"),
			errorType :
				DKIM_SigError.errorType (only if result="PERMFAIL")
				DKIM_InternalError.errorType (only if result="TEMPFAIL"; optional)
			shouldBeSignedBy : string[] (SDID; since 1.1)
			hideFail : Boolean
		}
	*/

var that = {
/*
 * public methods/variables
 */
 
	/*
	 * init
	 */
	init : function Verifier_init() {
		messenger = Components.classes["@mozilla.org/messenger;1"]
			.createInstance(Components.interfaces.nsIMessenger);
		msgHeaderParser = Components.classes["@mozilla.org/messenger/headerparser;1"].
			createInstance(Components.interfaces.nsIMsgHeaderParser);
	},

	/**
	 * Callback for the result of the verification.
	 * 
	 * @callback dkimResultCallback
	 * @param {String} msgURI
	 * @param {dkimResult} result
	 */
	
	/**
	 * Verifies the message with the given msgURI.
	 * 
	 * @deprecated Use verify2() or AuthVerifier.verify() instead.
	 * @param {String} msgURI
	 * @param {dkimResultCallback} dkimResultCallback
	 */
	verify: function Verifier_verify(msgURI, dkimResultCallback) {
		var promise = Task.spawn(function () {
			let msg;
			try {
				msg = yield MsgReader.read(msgURI);
				msg.msgURI = msgURI;

				// parse the header
				msg.headerFields = MsgReader.parseHeader(msg.headerPlain);

				// get from address
				var author = msg.headerFields.from[msg.headerFields.from.length-1];
				author = author.replace(/^From[ \t]*:/i,"");
				msg.from = msgHeaderParser.extractHeaderAddressMailboxes(author);

				// get list-id
				var listId = null;
				if (msg.headerFields["list-id"]) {
					listId = msg.headerFields["list-id"][0];
					listId = msgHeaderParser.extractHeaderAddressMailboxes(listId);
				}

				// check if msg should be signed
				msg.shouldBeSigned = yield Policy.shouldBeSigned(msg.from, listId);

				yield verifyBegin(msg);
			} catch (exception) {
				if (!msg) {
					msg = {"msgURI": msgURI};
				}
				msg.result = handleExeption(exception, msg);
			}

			dkimResultCallback(msg.msgURI, msg.result);
		});
		promise.then(null, function onReject(exception) {
			log.fatal("verify: "+exception);
		});
	},

	/**
	 * Verifies the message given message.
	 * 
	 * @param {Object} msg
	 *        .headerFields {Object}
	 *                      .<header name> {Array[String]}
	 *        .bodyPlain {String}
	 *        .from {String}
	 *        .DKIM.signPolicy {Object}
	 * @return {Promise<dkimResult>}
	 */
	verify2: function Verifier_verify2(msg) {
		var promise = Task.spawn(function () {
			try {
				msg.shouldBeSigned = msg.DKIM.signPolicy;
				yield verifyBegin(msg);
			} catch (exception) {
				msg.result = handleExeption(exception, msg);
			}

			throw new Task.Result(msg.result);
		});
		promise.then(null, function onReject(exception) {
			log.warn("verify: "+exception);
		});
		return promise;
	},
	
	/*
	 * make log public
	 */
	log : log,
	
	/*
	 * make parsing of the tag-value list public
	 */
	parseTagValueList : parseTagValueList,
	parseTagValue : parseTagValue
};
return that;
}()); // the parens here cause the anonymous function to execute and return

// for logging in rsasign
var DKIMVerifier = {};
DKIMVerifier.log = Verifier.log;

Verifier.init();
