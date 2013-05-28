/*
 * dkim.js - DKIM Verifier Extension for Mozilla Thunderbird
 *
 * Verifies the DKIM-Signatures as specified in RFC 6376
 * http://tools.ietf.org/html/rfc6376
 *
 * version: 0.3.0 (29 May 2013)
 *
 * Copyright (c) 2013 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be 
 * included in all copies or substantial portions of the Software.
 */

/*
 * Depends (directly) on:
 *  - dns.js
 *  - rsa.js
 *  - rsasign-1.2.js
 *  - base64.js
 *  - asn1hex-1.1.js
 */

/*
 * Violations against RFC 6376:
 * ============================
 *  - validate tag list as specified in Section 3.2 of RFC 6376
 *    - Tags with duplicate names MUST NOT occur within a single tag-list;
 *      if a tag name does occur more than once, the entire tag-list is invalid
 *  - at the moment, only a subset of valid Local-part in the i-Tag is recognised
 *  - no test for multiple key records in an DNS RRset (Section 3.6.2.2)
 *  - message with bad signature is treated differently from a message with no signature
 *    (result is shown) (Section 6.1)
 *  - DNS Server not reachable is treated as a PERMFAIL, not as a TEMPFAIL (Section 6.1.2)
 *  - no check that hash declared in DKIM-Signature is included in the hashs 
 *    declared in the key record (Section 6.1.2)
 *  - check that the hash function in the public key is the same as in the header (Section 6.1.2)
 *
 * possible feature  additions
 * ===========================
 *  - read and write Authentication-Results header (http://tools.ietf.org/html/rfc5451)
 *  - at the moment, the message must be in "network normal" format (more in Section 5.3 of RFC 6376);
 *    there is no check that this applies
 *  - option to show all signed header fields
 *  - at the moment, no differentiation between missing or ill-formed tags
 *  - support multiple signatures (more in Section 4 of RFC 6376)
 *  - differentiation between DNS errors
 *  - make verifying non blocking
 *  - and support concurrent verifications
 *  - display warnings
 *  - warning if the Signature is expired
 *  - warning if the Signature is in the future
 *  - warning if SDID and from are different
 *
 */
 
// options for JSHint
/* global Components, messenger, msgWindow, Application, gMessageListeners, gDBView, Services */ 
/* global DKIM_STRINGS */ 

// namespace
var DKIM_Verifier = {};

// load locale strings
Components.utils.import("chrome://dkim_verifier/locale/dkim.js");

// load modules
// DNS
Components.utils.import("chrome://dkim_verifier/content/dns.js", DKIM_Verifier);
// ASN.1
Services.scriptloader.loadSubScript("chrome://dkim_verifier/content/asn1hex-1.1.js",
                                    DKIM_Verifier, "UTF-8" /* The script's encoding */);
// base64 converter
Services.scriptloader.loadSubScript("chrome://dkim_verifier/content/base64.js",
                                    DKIM_Verifier, "UTF-8" /* The script's encoding */);
// RSA
Services.scriptloader.loadSubScript("chrome://dkim_verifier/content/jsbn.js",
                                    DKIM_Verifier, "UTF-8" /* The script's encoding */);
Services.scriptloader.loadSubScript("chrome://dkim_verifier/content/jsbn2.js",
                                    DKIM_Verifier, "UTF-8" /* The script's encoding */);
Services.scriptloader.loadSubScript("chrome://dkim_verifier/content/rsa.js",
                                    DKIM_Verifier, "UTF-8" /* The script's encoding */);
Services.scriptloader.loadSubScript("chrome://dkim_verifier/content/rsasign-1.2.js",
                                    DKIM_Verifier, "UTF-8" /* The script's encoding */);

/*
 * DKIM Verifier module
 */
DKIM_Verifier.DKIMVerifier = (function() {
	"use strict";
	
	// set hash funktions used by rsasign-1.2.js
	DKIM_Verifier._RSASIGN_HASHHEXFUNC['sha1'] = function(s){return dkim_hash(s, "sha1", "hex");};
	DKIM_Verifier._RSASIGN_HASHHEXFUNC['sha256'] = function(s){return dkim_hash(s, "sha256", "hex");};

/*
 * preferences
 */
	var prefs = null;

	// DKIM debug on/off
	var prefDKIMDebug;
	
 /*
 * private variables
 */
	// all warnings about the signature will go in her
	var warnings = [];
	
	var messageListener;

	// WSP help pattern as specified in Section 2.8 of RFC 6376
	var pattWSP = "[ \t]";
	// FWS help pattern as specified in Section 2.8 of RFC 6376
	var pattFWS = "(?:" + pattWSP + "*(?:\r\n)?" + pattWSP + "+)";
	// Pattern for hyphenated-word as specified in Section 2.10 of RFC 6376
	var hyphenated_word = "(?:[A-z](?:[A-z0-9-]*[A-z0-9])?)";
	// Pattern for ALPHADIGITPS as specified in Section 2.10 of RFC 6376
	var ALPHADIGITPS = "[A-z0-9+/]";
	// Pattern for base64string as specified in Section 2.10 of RFC 6376
	var base64string = "(?:"+ALPHADIGITPS+"(?:"+pattFWS+"?"+ALPHADIGITPS+")*(?:"+pattFWS+"?=){0,2})";
	// Pattern for dkim-safe-char as specified in Section 2.11 of RFC 6376
	var dkim_safe_char = "[33-:<>-~]";
	// Pattern for hex-octet as specified in Section 6.7 of RFC 2045
	var hex_octet = "(?:=[0-9ABCDEF]{2})";
	// Pattern for qp-hdr-value as specified in Section 2.10 of RFC 6376
	// same as dkim-quoted-printable as specified in Section 2.11 of RFC 6376
	var qp_hdr_value = "(?:"+pattFWS+"|"+hex_octet+"|"+dkim_safe_char+")";
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
				return [toHexString(hash.charCodeAt(i)) for (i in hash)].join("");
			case "b64":
				// true for base-64, false for binary data output
				return hasher.finish(true);
			default:
				throw new DKIM_InternalError("unsupported hash output selected");

		}
	}

	/*
	 * reads the message and parse it into header and body
	 * returns msg.headerPlain and msg.bodyPlain
	 */
	function parseMsg(msgURI) {
		var header = "";
		var c;
		var body = "";
		// return value
		var msg = {};

		// get inputStream for msg
		var messageService = messenger.messageServiceFromURI(msgURI);
		var nsIInputStream = Components.classes["@mozilla.org/network/sync-stream-listener;1"].
			createInstance(Components.interfaces.nsIInputStream);
		var inputStream = Components.classes["@mozilla.org/scriptableinputstream;1"].
			createInstance(Components.interfaces.nsIScriptableInputStream);
		inputStream.init(nsIInputStream);
		messageService.streamMessage(msgURI, nsIInputStream, msgWindow, null, false, null);
		
		// read header
		while(true) {
			// read one character
			c = inputStream.read(1);
			
			// if end of line
			if (c === "\n") {
				header += "\n";
				// check for following empty line (end of header)
				c = inputStream.read(2);
				if (c === "\r\n") {
					// empty line found, stop
					break;
				}
				header += c;
			} else {
				header += c;
			}
		}
		
		// read body
		var i;
		while ((i = inputStream.available()) !== 0) {
			body = body + inputStream.read(i);
		}
		
		// close inputStream
		inputStream.close();
		nsIInputStream.close();
		
		msg.headerPlain = header;
		msg.bodyPlain = body;
		
		return msg;
	}

	/*
	 * parse the message header
	 */
	function parseHeader(header) {
		var headerFields = {};

		// split header fields
		var headerArray = header.split(/\r\n(?=\S|$)/);
		var hName;
		for(var i = 0; i < headerArray.length; i++) {
			// store fields under header field name (in lower case) in an array
			hName = headerArray[i].match(/\S+(?=\s*:)/);
			if (hName !== null) {
				hName = hName[0].toLowerCase();
				if (headerFields[hName] === undefined) {
					headerFields[hName] = [];
				}
				headerFields[hName].push(headerArray[i]+"\r\n");
			}
		}
		
		return headerFields;
	}

	/*
	 * construct RegExp for finding Tag=Value Pair in tag list as specified in Section 3.2 of RFC 6376
	 */
	function tag_spec(tag_name, tag_value) {
		return new RegExp("(?:^|;)"+pattFWS+"?"+tag_name+pattFWS+"?="+pattFWS+"?("+tag_value+")"+pattFWS+"?(?:;|\r\n$|$)"); 
	}

	/*
	 * parse the DKIM-Signature header field
	 * header field is specified in Section 3.5 of RFC 6376
	 */
	function parseDKIMSignature(DKIMSignatureHeader) {
		var DKIMSignature = {
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
			l : null, // Body length count
			q : null, // query methods for public key retrievel
			s : null, // selector
			t : null, // Signature Timestamp
			x : null, // Signature Expiration
			z : null // Copied header fields
		};
		
		// strip DKIM-Signatur header name
		DKIMSignatureHeader = DKIMSignatureHeader.replace(/^DKIM-Signature[ \t]*:/,"");
		
		// get Version (plain-text; REQUIRED)
		// must be "1"
		var versionTag = DKIMSignatureHeader.match(tag_spec("v","[0-9]+"));
		if (versionTag === null) {
			throw new DKIM_SigError(DKIM_STRINGS.DKIM_SIGERROR_MISSING_V);
		}
		if (versionTag[1] === "1") {
			DKIMSignature.v = "1";
		} else {
			throw new DKIM_SigError(DKIM_STRINGS.DKIM_SIGERROR_VERSION);
		}

		// get signature algorithm (plain-text;REQUIRED)
		// currently only "rsa-sha1" or "rsa-sha256"
		var sig_a_tag_k = "(rsa|[A-z](?:[A-z]|[0-9])*)";
		var sig_a_tag_h = "(sha1|sha256|[A-z](?:[A-z]|[0-9])*)";
		var sig_a_tag_alg = sig_a_tag_k+"-"+sig_a_tag_h;
		var algorithmTag = DKIMSignatureHeader.match(tag_spec("a",sig_a_tag_alg));
		if (algorithmTag === null) {
			throw new DKIM_SigError(DKIM_STRINGS.DKIM_SIGERROR_MISSING_A);
		}
		if (algorithmTag[1] === "rsa-sha1" || algorithmTag[1] === "rsa-sha256") {
			DKIMSignature.a_sig = algorithmTag[2];
			DKIMSignature.a_hash = algorithmTag[3];
		} else {
			throw new DKIM_SigError(DKIM_STRINGS.DKIM_SIGERROR_UNKNOWN_A);
		}

		// get signature data (base64;REQUIRED)
		var signatureDataTag = DKIMSignatureHeader.match(tag_spec("b",base64string));
		if (signatureDataTag === null) {
			throw new DKIM_SigError(DKIM_STRINGS.DKIM_SIGERROR_MISSING_B);
		}
		DKIMSignature.b = signatureDataTag[1].replace(new RegExp(pattFWS,"g"), "");
		DKIMSignature.b_folded = signatureDataTag[1];

		// get body hash (base64;REQUIRED)
		var bodyHashTag = DKIMSignatureHeader.match(tag_spec("bh",base64string));
		if (bodyHashTag === null) {
			throw new DKIM_SigError(DKIM_STRINGS.DKIM_SIGERROR_MISSING_BH);
		}
		DKIMSignature.bh = bodyHashTag[1].replace(new RegExp(pattFWS,"g"), "");

		// get Message canonicalization (plain-text; OPTIONAL, default is "simple/simple")
		// currently only "simple" or "relaxed" for both header and body
		var sig_c_tag_alg = "(simple|relaxed|"+hyphenated_word+")";
		var msCanonTag = DKIMSignatureHeader.match(tag_spec("c",sig_c_tag_alg+"(?:/"+sig_c_tag_alg+")?"));
		if (msCanonTag === null) {
			DKIMSignature.c_header = "simple";
			DKIMSignature.c_body = "simple";
		} else {
			// canonicalization for header
			if (msCanonTag[2] === "simple" || msCanonTag[2] === "relaxed") {
				DKIMSignature.c_header = msCanonTag[2];
			} else {
				throw new DKIM_SigError(DKIM_STRINGS.DKIM_SIGERROR_UNKNOWN_C_H);
			}
				
			// canonicalization for body
			if (msCanonTag[3] === null) {
				DKIMSignature.c_body = "simple";
			} else {
				if (msCanonTag[3] === "simple" || msCanonTag[3] === "relaxed") {
					DKIMSignature.c_body = msCanonTag[3];
				} else {
					throw new DKIM_SigError(DKIM_STRINGS.DKIM_SIGERROR_UNKNOWN_C_B);
				}
			}
		}
		
		// get SDID (plain-text; REQUIRED)	
		// Pattern for sub-domain as specified in Section 4.1.2 of RFC 5321
		var sub_domain = "(?:[A-z0-9](?:[A-z0-9-]*[A-z0-9])?)";
		var domain_name = "(?:"+sub_domain+"(?:\\."+sub_domain+")+)";
		var SDIDTag = DKIMSignatureHeader.match(tag_spec("d",sub_domain+"(?:."+sub_domain+")*"));
		if (SDIDTag === null) {
			throw new DKIM_SigError(DKIM_STRINGS.DKIM_SIGERROR_MISSING_D);
		}
		DKIMSignature.d = SDIDTag[1];

		// get Signed header fields (plain-text, but see description; REQUIRED)
		var sig_h_tag = "("+hdr_name+")"+"(?:"+pattFWS+"?:"+pattFWS+"?"+hdr_name+")*";
		var signedHeadersTag = DKIMSignatureHeader.match(tag_spec("h",sig_h_tag));
		if (signedHeadersTag === null) {
			throw new DKIM_SigError(DKIM_STRINGS.DKIM_SIGERROR_MISSING_H);
		}
		DKIMSignature.h = signedHeadersTag[1].replace(new RegExp(pattFWS,"g"), "");
		// get the header field names and store them in lower case in an array
		var regExpHeaderName = new RegExp(pattFWS+"?("+hdr_name+")"+pattFWS+"?(?::|$)", "g");
		while (true) {
			var tmp = regExpHeaderName.exec(signedHeadersTag[1]);
			if (tmp === null) {
				break;
			} else {
				DKIMSignature.h_array.push(tmp[1].toLowerCase());
			}
		}
		// check that the from header is included
		if (DKIMSignature.h_array.indexOf("from") === -1) {
			throw new DKIM_SigError(DKIM_STRINGS.DKIM_SIGERROR_MISSING_FROM);
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
				"&" / "’" /
				"*" / "+" /
				"-" / "/" /
				"=" / "?" /
				"^" / "_" /
				"‘" / "{" /
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
		
		var atext = "[A-z0-9!#$%&'*+/=?^_`{|}~-]";
		var local_part = "(?:"+atext+"(?:."+atext+")*)";
		var sig_i_tag = local_part+"?@"+domain_name;
		var AUIDTag = DKIMSignatureHeader.match(tag_spec("i", sig_i_tag));
		if (AUIDTag === null) {
			DKIMSignature.i = "@"+DKIMSignature.d;
		} else {
			if (!(new RegExp(DKIMSignature.d+"$")).test(AUIDTag[1])) {
				throw new DKIM_SigError(DKIM_STRINGS.DKIM_SIGERROR_SUBDOMAIN_I);
			}
			DKIMSignature.i = AUIDTag[1];
		}

		// get Body length count (plain-text unsigned decimal integer; OPTIONAL, default is entire body)
		var BodyLengthTag = DKIMSignatureHeader.match(tag_spec("l", "[0-9]{1,76}"));
		if (BodyLengthTag !== null) {
			DKIMSignature.l = parseInt(BodyLengthTag[1], 10);
		}

		// get query methods (plain-text; OPTIONAL, default is "dns/txt")
		var sig_q_tag_method = "(?:dns/txt|"+hyphenated_word+"(?:/"+qp_hdr_value+")?)";
		var sig_q_tag = sig_q_tag_method+"(?:"+pattFWS+"?:"+pattFWS+"?"+sig_q_tag_method+")*";
		var QueryMetTag = DKIMSignatureHeader.match(tag_spec("q", sig_q_tag));
		if (QueryMetTag === null) {
			DKIMSignature.q = "dns/txt";
		} else {
			if (!(new RegExp("dns/txt")).test(QueryMetTag[1])) {
				throw new DKIM_SigError(DKIM_STRINGS.DKIM_SIGERROR_UNKNOWN_Q);
			}
			DKIMSignature.q = "dns/txt";
		}

		// get selector subdividing the namespace for the "d=" (domain) tag (plain-text; REQUIRED)
		var SelectorTag = DKIMSignatureHeader.match(tag_spec("s", sub_domain+"(?:."+sub_domain+")*"));
		if (SelectorTag === null) {
			throw new DKIM_SigError(DKIM_STRINGS.DKIM_SIGERROR_MISSING_S);
		}
		DKIMSignature.s = SelectorTag[1];
		
		// get Signature Timestamp (plain-text unsigned decimal integer; RECOMMENDED,
		// default is an unknown creation time)
		var SigTimeTag = DKIMSignatureHeader.match(tag_spec("t", "[0-9]+"));
		if (SigTimeTag !== null) {
			DKIMSignature.t = parseInt(SigTimeTag[1], 10);
		}

		// get Signature Expiration (plain-text unsigned decimal integer; 
		// RECOMMENDED, default is no expiration)
		// The value of the "x=" tag MUST be greater than the value of the "t=" tag if both are present
		var ExpTimeTag = DKIMSignatureHeader.match(tag_spec("x", "[0-9]+"));
		if (ExpTimeTag !== null) {
			DKIMSignature.x = parseInt(ExpTimeTag[1], 10);
			if (DKIMSignature.t !== null && DKIMSignature.x < DKIMSignature.t) {
				throw new DKIM_SigError(DKIM_STRINGS.DKIM_SIGERROR_TIMESTAMPS);
			}
		}
		
		// get Copied header fields (dkim-quoted-printable, but see description; OPTIONAL, default is null)
		var sig_z_tag_copy = hdr_name+pattFWS+"?:"+qp_hdr_value;
		var sig_z_tag = sig_z_tag_copy+"(\\|"+pattFWS+"?"+sig_z_tag_copy+")*";
		var CopyHeaderFieldsTag = DKIMSignatureHeader.match(tag_spec("z", sig_z_tag));
		if (CopyHeaderFieldsTag !== null) {
			DKIMSignature.z = CopyHeaderFieldsTag[1].replace(new RegExp(pattFWS,"g"), "");
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
			k : null, // key type
			n : null, // notes
			p : null, // Public-key data
			s : null, // Service Type
			t : null, // flags
			t_array : [] // array of all flags
		};
		
		// get version (plain-text; RECOMMENDED, default is "DKIM1")
		// If specified, this tag MUST be set to "DKIM1"
		// This tag MUST be the first tag in the record
		var key_v_tag = "^"+pattFWS+"?v"+pattFWS+"?="+pattFWS+"?("+dkim_safe_char+")*;";
		var versionTag = DKIMKeyRecord.match(new RegExp(key_v_tag));
		if (versionTag === null || versionTag[1] === "DKIM1") {
			DKIMKey.v = "DKIM1";
		} else {
			throw new DKIM_SigError(DKIM_STRINGS.DKIM_SIGERROR_KEY_INVALID_V);
		}
		
		// get Acceptable hash algorithms (plain-text; OPTIONAL, defaults toallowing all algorithms)
		var key_h_tag_alg = "(?:sha1|sha256|"+hyphenated_word+")";
		var key_h_tag = key_h_tag_alg+"(?:"+pattFWS+"?:"+pattFWS+"?"+key_h_tag_alg+")*";
		var algorithmTag = DKIMKeyRecord.match(tag_spec("h",key_h_tag));
		if (algorithmTag !== null) {
			DKIMKey.h = algorithmTag[1];
		} 
		
		// get Key type (plain-text; OPTIONAL, default is "rsa")
		var key_k_tag_type = "(?:rsa|"+hyphenated_word+")";
		var keyTypeTag = DKIMKeyRecord.match(tag_spec("k",key_k_tag_type));
		if (keyTypeTag === null || keyTypeTag[1] === "rsa") {
			DKIMKey.k = "rsa";
		} else {
			throw new DKIM_SigError(DKIM_STRINGS.DKIM_SIGERROR_KEY_UNKNOWN_K);
		}

		// get Notes (qp-section; OPTIONAL, default is empty)
		var notesTag = DKIMKeyRecord.match(tag_spec("n",dkim_safe_char+"*"));
		if (notesTag !== null) {
			DKIMKey.n = notesTag[1];
		}
		
		// get Public-key data (base64; REQUIRED)
		// empty value means that this public key has been revoked
		var keyTag = DKIMKeyRecord.match(tag_spec("p",base64string+"?"));
		if (keyTag === null) {
			throw new DKIM_SigError(DKIM_STRINGS.DKIM_SIGERROR_KEY_MISSING_P);
		} else {
			if (keyTag[1] === "") {
				throw new DKIM_SigError(DKIM_STRINGS.DKIM_SIGERROR_KEY_REVOKED);
			} else {
				DKIMKey.p = keyTag[1];
			}
		}

		// get Service Type (plain-text; OPTIONAL; default is "*")
		var key_s_tag_type = "(?:email|\\*|"+hyphenated_word+")";
		var key_s_tag = key_s_tag_type+"(?:"+pattFWS+"?:"+pattFWS+"?"+key_s_tag_type+")*";
		var serviceTypeTag = DKIMKeyRecord.match(tag_spec("s",key_s_tag));
		if (serviceTypeTag === null) {
			DKIMKey.s = "*";
		} else {
			if (/email/.test(serviceTypeTag[1])) {
				DKIMKey.s = serviceTypeTag[1];
			} else {
				throw new DKIM_SigError(DKIM_STRINGS.DKIM_SIGERROR_KEY_NOTEMAILKEY);
			}
		}

		// get Flags (plaintext; OPTIONAL, default is no flags set)
		var key_t_tag_flag = "(?:y|s|"+hyphenated_word+")";
		var key_t_tag = key_t_tag_flag+"(?:"+pattFWS+"?:"+pattFWS+"?"+key_t_tag_flag+")*";
		var flagsTag = DKIMKeyRecord.match(tag_spec("t",key_t_tag));
		if (flagsTag !== null) {
			DKIMKey.t = flagsTag[1];

			// get the flags and store them in an array
			var regFlagName = new RegExp(pattFWS+"?("+key_t_tag_flag+")"+pattFWS+"?(?::|$)", "g");
			while (true) {
				var tmp = regFlagName.exec(flagsTag[1]);
				if (tmp === null) {
					break;
				} else {
					DKIMKey.t_array.push(tmp[1]);
				}
			}
			// check that the testing flag is not set
			if (DKIMKey.t_array.indexOf("y") !== -1) {
				throw new DKIM_SigError(DKIM_STRINGS.DKIM_SIGERROR_KEY_TESTMODE);
			}
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
		body = body.replace(/(\r\n)*$/,"\r\n");
		
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
		body = body.replace(/(\r\n)+$/,"\r\n");
		
		return body;
	}

	/*
	 * Computing the Message Hash for the body 
	 * specified in Section 3.7 of RFC 6376
	 */
	function computeBodyHash(msg) {
		// canonicalize body
		var bodyCanon;
		switch (msg.DKIMSignature.c_body) {
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
		if (msg.DKIMSignature.l !== null) {
			// check the value of the body lenght tag
			if (msg.DKIMSignature.l > bodyCanon.length) {
				// lenght tag exceeds body size
				throw new DKIM_SigError(DKIM_STRINGS.DKIM_SIGERROR_TOOLARGE_L);
			} else if (msg.DKIMSignature.l < bodyCanon.length){
				// lenght tag smaller when body size
				warnings.push(DKIM_STRINGS.DKIM_SIGWARNING_SMALL_L);
				dkimDebugMsg("Warning: "+DKIM_STRINGS.DKIM_SIGWARNING_SMALL_L);
			}

			// truncated body to the length specified in the "l=" tag
			bodyCanon = bodyCanon.substr(0, msg.DKIMSignature.l);
		}
		
		// compute body hash
		var bodyHash;
		switch (msg.DKIMSignature.a_hash) {
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
	function computeHeaderHashInput(msg) {
		var hashInput = "";
		var temp;

		// set header canonicalization algorithm
		var headerCanonAlgo;
		switch (msg.DKIMSignature.c_header) {
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
		for(var i = 0; i <  msg.DKIMSignature.h_array.length; i++) {
			// if multiple instances of the same header field are signed
			// include them in reverse order (from bottom to top)
			temp = msg.headerFields[msg.DKIMSignature.h_array[i]].pop();
			if (temp) {
				hashInput += headerCanonAlgo(temp);
			}
		}
		
		// add DKIM-Signature header to the hash input
		// with the value of the "b=" tag (including all surrounding whitespace) deleted
		var pos = msg.headerFields["dkim-signature"][0].indexOf(msg.DKIMSignature.b_folded);
		var tempBegin = msg.headerFields["dkim-signature"][0].substr(0, pos);
		tempBegin = tempBegin.replace(new RegExp(pattFWS+"?$"), "");
		var tempEnd = msg.headerFields["dkim-signature"][0].substr(pos+msg.DKIMSignature.b_folded.length);
		tempEnd = tempEnd.replace(new RegExp("^"+pattFWS+"?"), "");
		temp = tempBegin + tempEnd;
		// canonicalized using the header canonicalization algorithm specified in the "c=" tag
		temp = headerCanonAlgo(temp);
		// without a trailing CRLF
		hashInput += temp.substr(0, temp.length - 2);
		
		return hashInput;
	}
	
	/*
	 * 1. part of verifying the signature
	 * will verify until key query, the rest is in verifySignaturePart2
	 */
	function verifySignaturePart1(msg) {
		try {
			// parse the DKIMSignatureHeader
			msg.DKIMSignature = parseDKIMSignature(msg.headerFields["dkim-signature"][0]);
			dkimDebugMsg("Parsed DKIM-Signature: "+msg.DKIMSignature.toSource());
			
			// Compute the Message Hashe for the body 
			var bodyHash = computeBodyHash(msg);
			dkimDebugMsg("computed body hash: "+bodyHash);
			
			// compare body hash
			if (bodyHash !== msg.DKIMSignature.bh) {
				throw new DKIM_SigError(DKIM_STRINGS.DKIM_SIGERROR_CORRUPT_BH);
			}

			// get the DKIM key
			// this function will continue the verification
			DKIM_Verifier.queryDNS(
				msg.DKIMSignature.s+"._domainkey."+msg.DKIMSignature.d,
				"TXT",
				that.dnsCallback,
				msg
			);
		} catch(e) {
			var dkimMsgHdrRes = document.getElementById("dkim_verifier_msgHdrRes");
			if (e instanceof DKIM_SigError) {				
				dkimMsgHdrRes.value = DKIM_STRINGS.PERMFAIL + " (" + e.message + ")";
			} else {
				dkimMsgHdrRes.value = "Internal Error";
			}
			if (prefDKIMDebug) {
				Components.utils.reportError(e+"\n"+e.stack);
			}
		}
	}
	
	/*
	 * 2. part of verifying the signature
	 * will continue verifying after key is received
	 */
	function verifySignaturePart2(msg) {
		try {
			msg.DKIMKey = parseDKIMKeyRecord(msg.keyQueryResult);
			dkimDebugMsg("Parsed DKIM-Key: "+msg.DKIMKey.toSource());
			
			// if s flag is set in DKIM key record
			// AUID must be from the same domain as SDID (and not a subdomain)
			if (msg.DKIMKey.t_array.indexOf("s") !== -1 &&
				msg.DKIMSignature.i.indexOf("@"+msg.DKIMSignature.d)) {
				throw new DKIM_SigError(DKIM_STRINGS.DKIM_SIGERROR_DOMAIN_I);
			}
			
			// Compute the input for the header hash
			var headerHashInput = computeHeaderHashInput(msg);
			dkimDebugMsg("Header hash input:\n" + headerHashInput);

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
			var asnKey = DKIM_Verifier.b64tohex(msg.DKIMKey.p);
			var posTopArray = null;
			var posKeyArray = null;
			
			// check format by comparing the 1. child in the top element
			posTopArray = DKIM_Verifier.ASN1HEX.getPosArrayOfChildren_AtObj(asnKey,0);
			if (posTopArray === null || posTopArray.length !== 2) {
				throw new DKIM_SigError(DKIM_STRINGS.DKIM_SIGERROR_KEYDECODE);
			}
			if (DKIM_Verifier.ASN1HEX.getHexOfTLV_AtObj(asnKey, posTopArray[0]) !==
				"300d06092a864886f70d0101010500") {
				throw new DKIM_SigError(DKIM_STRINGS.DKIM_SIGERROR_KEYDECODE);
			}
			
			// get pos of SEQUENCE under BIT STRING
			// asn1hex does not support BIT STRING, so we will compute the position
			var pos = DKIM_Verifier.ASN1HEX.getStartPosOfV_AtObj(asnKey, posTopArray[1]) + 2;
			
			// get pos of modulus and publicExponent
			posKeyArray = DKIM_Verifier.ASN1HEX.getPosArrayOfChildren_AtObj(asnKey, pos);
			if (posKeyArray === null || posKeyArray.length !== 2) {
				throw new DKIM_SigError(DKIM_STRINGS.DKIM_SIGERROR_KEYDECODE);
			}
			
			// get modulus
			var m_hex = DKIM_Verifier.ASN1HEX.getHexOfV_AtObj(asnKey,posKeyArray[0]);
			// get public exponent
			var e_hex = DKIM_Verifier.ASN1HEX.getHexOfV_AtObj(asnKey,posKeyArray[1]);

			// set RSA-key
			var rsa = new DKIM_Verifier.RSAKey();
			rsa.setPublic(m_hex, e_hex);
			
			// verify Signature
			var isValid = rsa.verifyString(headerHashInput, DKIM_Verifier.b64tohex(msg.DKIMSignature.b));
			
			if (!isValid) {
				throw new DKIM_SigError(DKIM_STRINGS.DKIM_SIGERROR_CORRUPT_B);
			}
			
			// show result
			var dkimMsgHdrRes = document.getElementById("dkim_verifier_msgHdrRes");
			dkimMsgHdrRes.value = DKIM_STRINGS.SUCCESS(msg.DKIMSignature.d);
			
		} catch(e) {
			var dkimMsgHdrRes = document.getElementById("dkim_verifier_msgHdrRes");
			
			if (e instanceof DKIM_SigError) {
				// if domain is testing DKIM, treat msg as not signed
				if (e.message === DKIM_STRINGS.DKIM_SIGERROR_KEY_TESTMODE) {
					var dkimVerifierBox = document.getElementById("dkim_verifier_msgHdrBox");
					dkimVerifierBox.collapsed = true;
				}
				
				dkimMsgHdrRes.value = DKIM_STRINGS.PERMFAIL + " (" + e.message + ")";
			} else {
				dkimMsgHdrRes.value = "Internal Error";
			}
			
			if (prefDKIMDebug) {
				Components.utils.reportError(e+"\n"+e.stack);
			}
		}
	}

	/*
	 * DKIM_SIGERROR
	 */
	function DKIM_SigError(message) {
		this.name = DKIM_STRINGS.DKIM_SIGERROR;
		this.message = message || DKIM_STRINGS.DKIM_SIGERROR_DEFAULT;

		// modify stack and lineNumber, to show where this object was created,
		// not where Error() was
		var err = new Error();
		this.stack = err.stack.substring(err.stack.indexOf('\n')+1);
		this.lineNumber = parseInt(this.stack.match(/[^:]*$/m), 10);
	}
	DKIM_SigError.prototype = new Error();
	DKIM_SigError.prototype.constructor = DKIM_SigError;

	/*
	 * DKIM internal error
	 */
	function DKIM_InternalError(message) {
		this.name = DKIM_STRINGS.DKIM_INTERNALERROR;
		this.message = message || DKIM_STRINGS.DKIM_INTERNALERROR_DEFAULT;
		
		// modify stack and lineNumber, to show where this object was created,
		// not where Error() was
		var err = new Error();
		this.stack = err.stack.substring(err.stack.indexOf('\n')+1);
		this.lineNumber = parseInt(this.stack.match(/[^:]*$/m), 10);
	}
	DKIM_InternalError.prototype = new Error();
	DKIM_InternalError.prototype.constructor = DKIM_InternalError;

	/*
	 * dkimDebugMsg
	 */
	function dkimDebugMsg(message) {
		if (prefDKIMDebug) {
			Application.console.log("DKIM: "+message);
		}
	}
	
var that = {
/*
 * public methods/variables
 */
 
	/*
	 * gets called on startup
	 */
	startup : function () {
		// Register to receive notifications of preference changes
		prefs = Components.classes["@mozilla.org/preferences-service;1"].
			getService(Components.interfaces.nsIPrefService).
			getBranch("extensions.dkim_verifier.");
		prefs.QueryInterface(Components.interfaces.nsIPrefBranch2);
		prefs.addObserver("", that, false);
		
		// load preferences
		prefDKIMDebug = prefs.getBoolPref("debug");
		DKIM_Verifier.dnsChangeDebug(prefs.getBoolPref("debug"));
		DKIM_Verifier.dnsChangeNameserver(prefs.getCharPref("dns.nameserver"));
		
		// add event listener for message display
		messageListener = {
			// onStartHeaders: function () {},
			// onEndHeaders: function () {},
			// onEndAttachments: function () {},
			// onBeforeShowHeaderPane: function () {}
			onStartHeaders: that.clearHeader,
			onEndHeaders: that.messageLoaded
		};
		gMessageListeners.push(messageListener);
	},

	/*
	 * gets called on shutdown
	 * so far, this never happens
	 */
	shutdown : function() {
		// remove preference observer
		prefs.removeObserver("", that);
		
		// remove event listener for message display
		var pos = gMessageListeners.indexOf(messageListener);
		if (pos !== -1) {
			gMessageListeners.splice(pos, 1);
		}
	},

	/*
	 * gets called called whenever an event occurs on the preference
	 */
	observe: function(subject, topic, data) {
		// subject is the nsIPrefBranch we're observing (after appropriate QI)
		// data is the name of the pref that's been changed (relative to aSubject)
		
		if (topic !== "nsPref:changed") {
			return;
		}
		
		switch(data) {
			case "debug":
				prefDKIMDebug = prefs.getBoolPref("debug");
				DKIM_Verifier.dnsChangeDebug(prefs.getBoolPref("debug"));
				break;
			case "dns.nameserver":
				DKIM_Verifier.dnsChangeNameserver(prefs.getCharPref("dns.nameserver"));
				break;
		}
	},
	
	/*
	 * gets called if a new message ist viewed
	 */
	messageLoaded : function () {	
		// get msg uri
		var msgURI = gDBView.URIForFirstSelectedMessage ;
		
		// parse msg into msg.header and msg.body
		var msg = parseMsg(msgURI);
		msg.msgURI = msgURI;
		
		// parse the header
		msg.headerFields = parseHeader(msg.headerPlain);

		// check if DKIMSignatureHeader exist
		if (msg.headerFields["dkim-signature"] === undefined) {
			// no signature to check, return
			return;
		}
		
		// show the dkim verifier header box
		var dkimVerifierBox = document.getElementById("dkim_verifier_msgHdrBox");
		dkimVerifierBox.collapsed = false;
		
		verifySignaturePart1(msg);
	},

	/*
	 * collapse the dkim verifier header box
	 */
	clearHeader : function () {
		var dkimMsgHdrBox = document.getElementById("dkim_verifier_msgHdrBox");
		dkimMsgHdrBox.collapsed = "true";
		var dkimMsgHdrRes = document.getElementById("dkim_verifier_msgHdrRes");
		dkimMsgHdrRes.value = DKIM_STRINGS.loading;
	},
	
	/*
	 * callback for the dns result
	 * the message to be verified is passed as the 2. parameter
	 */
	dnsCallback : function (dnsResult, msg) {
		try {
			dkimDebugMsg("DNS result: " + dnsResult);
			if (dnsResult === null) {
				throw new DKIM_SigError(DKIM_STRINGS.DKIM_SIGERROR_KEYFAIL);
			}
			
			msg.keyQueryResult = dnsResult[0];
			
			verifySignaturePart2(msg);
		} catch(e) {
			var dkimMsgHdrRes = document.getElementById("dkim_verifier_msgHdrRes");
			if (e instanceof DKIM_SigError) {				
				dkimMsgHdrRes.value = DKIM_STRINGS.PERMFAIL + " (" + e.message + ")";
			} else {
				dkimMsgHdrRes.value = "Internal Error";
			}
			if (prefDKIMDebug) {
				Components.utils.reportError(e+"\n"+e.stack);
			}
		}
	}
};
return that;
}()); // the parens here cause the anonymous function to execute and return

DKIM_Verifier.DKIMVerifier.startup();
