/**
 * Brand Indicators for Message Identification (BIMI).
 * https://datatracker.ietf.org/doc/draft-brand-indicators-for-message-identification/04/
 *
 * BIMI implementation for a Mail User Agent (MUA).
 * - Gets the BIMI Indicator based on the information the receiving
 * Mail Transfer Agent (MTA) writes into the headers of the message.
 * - Gets the BIMI Indicator from DNS if it's protected with a trusted certificate
 *
 * This is not a complete implementation of BIMI.
 *
 * Copyright (c) 2023 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// options for ESLint
/* global Components, Services, atob, btoa, Sqlite */
/* global Logging, rfcParser, DNS */
/* global Deferred, toType, stringEqual, readStringFrom, PREF */
/* exported EXPORTED_SYMBOLS, BIMI, BIMIDB */

/**
 * @typedef {Object} BimiRecord
 * @property {String} version version of the BimiRecord structure
 * @property {String} bimiVersion the v tag of the BIMI DNS record
 * @property {String} location the l tag of the BIMI DNS record
 * @property {String} [authorization]  the a tag of the BIMI DNS record
 */

/**
 * @typedef {Object} HashData
 * @property {String} algo
 * @property {String} hash
 */

"use strict";

var EXPORTED_SYMBOLS = [
	"BIMI", "BIMIDB"
];

// @ts-expect-error
const Cc = Components.classes;
// @ts-expect-error
const Ci = Components.interfaces;
// @ts-expect-error
const Cu = Components.utils;

Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/Sqlite.jsm");

Cu.import("resource://dkim_verifier/logging.jsm.js");
Cu.import("resource://dkim_verifier/arhParser.jsm.js");
Cu.import("resource://dkim_verifier/rfcParser.jsm.js");
Cu.import("resource://dkim_verifier/dnsWrapper.jsm.js");
Cu.import("resource://dkim_verifier/helper.jsm.js");

// @ts-expect-error
const PREF_BRANCH = "extensions.dkim_verifier.bimi.";
// @ts-expect-error
var prefs = Services.prefs.getBranch(PREF_BRANCH);

let CERTTOOLS = (function() {

	const log = Logging.getLogger("BIMI.CERT");
	const RSA ={};
	RSA.navigator = {};
	RSA.navigator.appName = "Netscape";
	Services.scriptloader.loadSubScript("resource://dkim_verifier_3p/jsbn/jsbn.js", RSA, "UTF-8");
	Services.scriptloader.loadSubScript("resource://dkim_verifier_3p/jsbn/jsbn2.js", RSA, "UTF-8");
	Services.scriptloader.loadSubScript("resource://dkim_verifier_3p/jsbn/base64.js", RSA, "UTF-8");
	Services.scriptloader.loadSubScript("resource://dkim_verifier_3p/rsasign/base64x-1.1.js", RSA, "UTF-8");
	Services.scriptloader.loadSubScript("resource://dkim_verifier_3p/rsasign/asn1-1.0.js", RSA, "UTF-8");
	Services.scriptloader.loadSubScript("resource://dkim_verifier_3p/rsasign/asn1hex-1.1.js", RSA, "UTF-8");
	Services.scriptloader.loadSubScript("resource://dkim_verifier_3p/rsasign/asn1x509-1.0.js", RSA, "UTF-8");
	Services.scriptloader.loadSubScript("resource://dkim_verifier_3p/rsasign/x509-1.1.js", RSA, "UTF-8");

	/**
	 * Computes the hash for a given string value and using algorithm and returns the hex value
	 *
	 * @param {String} str a value
	 * @param {String} hashAlgorithm
	 * @returns {String}
	 */
	let _getHash = function(str, hashAlgorithm) {
		/*
		 * Converts a string to an array bytes
		 * characters >255 have their hi-byte silently ignored.
		 */
		function __rstr2byteArray(str) {
			const res = new Array(str.length);
			for (let i = 0; i < str.length; i++) {
				res[i] = str.charCodeAt(i) & 0xFF;
			}
			return res;
		}

		// return the two-digit hexadecimal code for a byte
		function __toHexString(charCode) {
			return ("0" + charCode.toString(16)).slice(-2);
		}

		const hasher = Components.classes["@mozilla.org/security/hash;1"].createInstance(Components.interfaces.nsICryptoHash);
		hasher.initWithString(hashAlgorithm);
		const data = __rstr2byteArray(str);
		hasher.update(data, data.length);
		// true for base-64, false for binary data output
		let hash = hasher.finish(false);
		// convert the binary hash data to a hex string.
		hash = hash.split("").map(e => __toHexString(e.charCodeAt(0))).join("");
		return hash;
	};

	/**
	 * Takes a Base64 encoded cert, returns the certificates fingerprint
	 *
	 * @param {String} certString
	 * @returns {String}
	 */
	let _getFingerprint = function(certString) {
		const derCert = _testPEMformat(certString) ? _convertPEMtoDER(certString) : certString;
		let rawFP = _getHash(atob(derCert), "sha256");
		rawFP = rawFP.toUpperCase();
		let fingerprint = "";
		for (let i=0; i < rawFP.length; i++) {
			if (i>0 && i%2 === 0) { fingerprint += ":"; }
			fingerprint += rawFP[i];
		}
		return fingerprint;
	};

	/**
	 * Takes a Base64 encoded cert, returns true, if it's in PEM format, else false
	 *
	 * @param {String} certString
	 * @returns {Boolean}
	 */
	let _testPEMformat = function(certString) {
		return certString.match(/-----BEGIN [A-Z0-9 ]+-----/) !== null;
	};

	/**
	 * Takes a PEM cert (also chain) string and returns an array of DER strings (one for each certificate)
	 * PEM: Base64 encoded certificate(s) with
	 * -----BEGIN CERTIFICATE----- / -----END CERTIFICATE----- marker
	 * DER: Base64 encoded certificate without markers
	 *
	 * @param {String} certString PEM cert(s) string
	 * @returns {String[]} Array of Base64 encoded certificate strings
	 */
	let _convertPEMtoDERArray = function(certString) {
		if (!certString) { return []; }
		certString = certString.replace(/-----BEGIN [A-Z0-9 ]+-----/g, '----');
		certString = certString.replace(/-----END [A-Z0-9 ]+-----/g, '----');
		certString = certString.replace(/\s+/g, '');
		const res = [];
		for (const cert of certString.split('----')) {
			if (cert.trim()) {
				res.push(cert);
			}
		}
		return res;
	};

	/**
	 * Takes a PEM cert string and returns a DER string
	 * PEM: Base64 encoded certificate(s) with
	 * -----BEGIN CERTIFICATE----- / -----END CERTIFICATE----- marker
	 * DER: Base64 encoded certificate without markers
	 *
	 * @param {String} certString PEM cert(s) string
	 * @returns {String} Base64 encoded certificate string
	 */
	let _convertPEMtoDER = function(certString) {
		return _convertPEMtoDERArray(certString)[0];
	};

	/**
	 * Takes a DER cert string and returns PEM string
	 * PEM: Base64 encoded certificate with
	 * -----BEGIN CERTIFICATE----- / -----END CERTIFICATE----- marker
	 * DER: Base64 encoded certificate without markers
	 *
	 * @param {String} certString DER cert String
	 * @returns {String} PEM cert String
	 */
	let _convertDERtoPEM = function(certString) {
		if (_testPEMformat(certString)) { return certString; }
		let wrappedString = "-----BEGIN CERTIFICATE-----\n";
		while (certString.length >= 64) {
			wrappedString += certString.substring(0, 64) + "\n";
			certString = certString.substring(64);
		}
		if (certString.length > 0) { wrappedString += certString + "\n"; }
		wrappedString += "-----END CERTIFICATE-----\n";
		return wrappedString;
	};

	/**
	 * Takes an array of B64 encoded certs and returns the end entity certificate
	 *
	 * @param {String[]} certArray
	 * @returns {String|null}
	 */
	let _getEndEntitityCert = function(certArray) {
		for (const cert of certArray) {
			const certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);
			const derCert = _testPEMformat(cert) ? _convertPEMtoDER(cert) : cert;
			let certObj;
			try {
				certObj = certDB.constructX509FromBase64(derCert);
			} catch (error) {
				log.error("The certificate data is corrupt", error);
				return null;
			}
			// an end entity is not a CA
			// @ts-expect-error
			if (certObj.certType !== Ci.nsIX509Cert.CA_CERT) {
				return cert;
			}
		}
		return null;
	};

	/**
	 * Takes a Base64 cert and a domain name and checks, if the cert is a BIMI cert for this domain
	 *
	 * @param {String} bimiCert
	 * @param {String} domain
	 * @returns {Boolean}
	 */
	let _testBIMICert = function(bimiCert, domain) {
		const BIMI_KEY_USAGE_OID = "1.3.6.1.5.5.7.3.31";
		const BIMI_LOGOTYPE_OID = "1.3.6.1.5.5.7.1.12";
		const BIMI_TYPE_OID = "1.3.6.1.4.1.53087.1.13";
		// we need a certificate in DER format
		let derCert = !_testPEMformat(bimiCert) ? _convertDERtoPEM(bimiCert) : bimiCert;
		const certObj = new RSA.X509();
		try {
			certObj.readCertPEM(derCert);
		} catch (error) {
			log.error("The certificate data is corrupt", error);
			return false;
		}
		let isBIMI = false;
		let isValidForDomain = false;
		// Check for ExtendedKeyUsage => BIMI
		for (const ext of certObj.getExtExtKeyUsage().array) {
			if (stringEqual(ext, BIMI_KEY_USAGE_OID)) {
				isBIMI = true;
				break;
			}
		}
		// Get Common Name and BIMI Logo Type
		let cn = certObj.getSubject().array.filter(el => stringEqual(el[0].type, "CN"));
		if (cn) { cn = cn[0][0].value; }
		let type = certObj.getSubject().array.filter(el => stringEqual(el[0].type, BIMI_TYPE_OID));
		if (type) { type = type[0][0].value; }
		if (isBIMI && type && certObj.getCriticalExtV(BIMI_LOGOTYPE_OID)) {
			// The certificate has the correct extendedKeyUsage and contains the needed information
			log.debug(`Certificate "${cn}" is a valid BIMI certificate of type ${type} and contains logo information`);
		} else {
			isBIMI = false;
		}
		// Check domain is in SAN field
		for (const altName of certObj.getExtSubjectAltName().array) {
			let dnsDomain = altName.dns;
			let testDomain = domain;
			// *. means just one level in certificates
			if (dnsDomain.startsWith("*.")) {
				dnsDomain = dnsDomain.substring(2);
				testDomain = testDomain.substring(testDomain.indexOf(".") + 1);
			}
			if (stringEqual(dnsDomain, testDomain)) {
				isValidForDomain = true;
				break;
			}
		}
		if (!isBIMI) {
			log.debug(`Certificate "${cn}" is not a BIMI certificate`);
		}
		if (!isValidForDomain) {
			log.debug(`Certificate "${cn}" is not valid for domain ${domain}`);
		}
		return isBIMI && isValidForDomain;
	};

	/**
	 * Extracts all alternative domains from the certificate
	 *
	 * @param {String} bimiCert
	 * @returns {String[]}
	 */
	let _getAlternativeDomainNames = function(bimiCert) {
		let derCert = !_testPEMformat(bimiCert) ? _convertDERtoPEM(bimiCert) : bimiCert;
		const certObj = new RSA.X509();
		try {
			certObj.readCertPEM(derCert);
		} catch (error) {
			log.error("The certificate data is corrupt", error);
			return [];
		}
		let san = [];
		for (const altName of certObj.getExtSubjectAltName().array) {
			san.push(altName.dns.toLowerCase());
		}
		return san;
	};

	/**
	 * Extracts embedded SVG images from BIMI certs
	 *
	 * For information about the Logotype extension, look at
	 * See https://datatracker.ietf.org/doc/html/rfc3709.html
	 *
	 * @param {String} bimiCert
	 * @returns {String[]}
	 */
	let _getBimiSVGData = function(bimiCert) {
		const BIMI_LOGOTYPE_OID = "1.3.6.1.5.5.7.1.12";
		const derCert = !_testPEMformat(bimiCert) ? _convertDERtoPEM(bimiCert) : bimiCert;
		const certObj = new RSA.X509();
		try {
			certObj.readCertPEM(derCert);
		} catch (error) {
			log.error("The certificate data is corrupt", error);
			return [];
		}
		let logoExtHex = certObj.getCriticalExtV(BIMI_LOGOTYPE_OID);
		if (!logoExtHex) { return []; }
		const logoExt = RSA.ASN1HEX.parse(logoExtHex[0]);

		let svgImgs = [];
		try {
			// Check, if we have direct embedded logo information
			if (logoExt.seq[0].tag.tag.toLowerCase() !== "a2" || // subjectLogo
				logoExt.seq[0].tag.obj.tag.tag.toLowerCase() !== "a0") { // direct LogotypeData
				return [];
			}
			// path to the logo information
			const logotypeDataSets = logoExt.seq[0].tag.obj.tag.obj.seq[0]; // image data
			// loop through all image sets here
			for (const resourceSet of logotypeDataSets.seq) {
				for (const resource of resourceSet.seq) {
					if (resource.seq && resource.seq[0].ia5str) {
						let imageData = resource.seq[0].ia5str.str;
						// remove data:image/svg+xml;base64,
						imageData = imageData.substring(imageData.indexOf("64,")+3);
						// simple test, since some images are SVGZ, which can't be displayed
						if (atob(imageData).toLowerCase().includes("</svg>")) {
							log.debug("Found logo in certificate");
							svgImgs.push(imageData);
						}
					}
				}
			}
		} catch (error) {
				log.debug("Logotype structure of certificate is not supported");
		}
		return svgImgs;
	};

	/**
	 * Extracts embedded BIMI control hashes from BIMI certs
	 *
	 * For information about the Logotype extension, look at
	 * See https://datatracker.ietf.org/doc/html/rfc3709.html
	 *
	 * @param {String} bimiCert
	 * @returns {HashData[]}
	 */
	let _getBimiHashData = function(bimiCert) {
		const BIMI_LOGOTYPE_OID = "1.3.6.1.5.5.7.1.12";
		const derCert = !_testPEMformat(bimiCert) ? _convertDERtoPEM(bimiCert) : bimiCert;
		const certObj = new RSA.X509();
		try {
			certObj.readCertPEM(derCert);
		} catch (error) {
			log.error("The certificate data is corrupt", error);
			return [];
		}
		const logoExtHex = certObj.getCriticalExtV(BIMI_LOGOTYPE_OID);
		if (!logoExtHex) { return []; }
		const logoExt = RSA.ASN1HEX.parse(logoExtHex[0]);

		let hashObj = [];
		try {
			// Check, if we have direct embedded logo information
			if (logoExt.seq[0].tag.tag.toLowerCase() !== "a2" || // subjectLogo
				logoExt.seq[0].tag.obj.tag.tag.toLowerCase() !== "a0") { // direct LogotypeData
				return [];
			}
			// path to the indicator information
			const logotypeDataSets = logoExt.seq[0].tag.obj.tag.obj.seq[0]; // image data
			// loop through all image sets here
			for (const resourceSet of logotypeDataSets.seq) {
				for (const resource of resourceSet.seq) {
					if (resource.seq && resource.seq[0].seq) {
						let algo = resource.seq[0].seq[0].seq[0].oid;
						let hash = resource.seq[0].seq[1].octstr.hex;
						log.debug("Found logo hash in certificate");
						hashObj.push({algo: algo, hash: hash});
					}
				}
			}
		} catch (error) {
			log.debug("Logotype structure of certificate is not supported");
		}
		return hashObj;
	};

	/**
	 * Takes a cert array and checks,
	 * - if it's a certificate chain, which ends at a trusted CA
	 * - if the current time is in the validity period
	 * - WARNING: We don't do any revocation checks
	 *
	 * Remark: Native Thunderbird mechanisms don't work, as they check validity depending on keyUsage
	 * and the BIMI OID 1.3.6.1.5.5.7.3.31 is unknown to Thunderbird, so it will always fail
	 *
	 * @param {String[]} certArray array with Base64 cert strings
	 * @returns {Promise<Boolean>} true if the certificate chain is deemed valid and trusted
	 */
	let _testValidity = async function _testValidity(certArray) {
		const caCerts = await BIMIDB.getTrustedCAs();
		const certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);
		const caCertArray = [];
		const certChainArray = [];
		const now = Date.now() * 1000;
		try {
			// Load certificate chain into memory
			for (const cert of certArray) {
				const derCert = _testPEMformat(cert) ? _convertPEMtoDER(cert) : cert;
				const certObj = certDB.constructX509FromBase64(derCert);
				// is any certificate expired => fail
				if (certObj.validity.notAfter < now || certObj.validity.notBefore > now) {
					log.debug(`${certObj.commonName} is expired: ${certObj.validity.notBeforeLocalTime} - ${certObj.validity.notAfterLocalTime}`);
					return false;
				}
				certChainArray.push(certObj);
			}
			// Load trusted CAs into memory
			for (const cert of caCerts) {
				const certObj = certDB.constructX509FromBase64(cert);
				caCertArray.push(certObj);
			}
		} catch (error) {
			log.error("Error creating certificate objects from B64 certificate strings");
			return false;
		}

		let endEntity = _getEndEntitityCert(certArray);
		// endEntity === null should never happen in a PKI scenario, as it means any cert is a CA
		endEntity = endEntity ? endEntity : certArray[0];
		endEntity = _testPEMformat(endEntity) ? _convertPEMtoDER(endEntity) : endEntity;
		let endEntityObj;
		try {
			endEntityObj = certDB.constructX509FromBase64(endEntity);
		} catch (error) {
			log.error("The certificate data is corrupt", error);
			return false;
		}
		const certChain = endEntityObj.getChain().enumerate();
		let topCert;
		// find the root CA
		while (certChain.hasMoreElements()) { topCert = certChain.getNext(); }
		topCert = topCert.QueryInterface(Ci.nsIX509Cert);
		if (topCert.validity.notAfter < now || topCert.validity.notBefore > now) {
			// the most top cert of the chain (probably the root CA cert) is expired
			log.debug(`${topCert.commonName} is expired: ${topCert.validity.notBeforeLocalTime} - ${topCert.validity.notAfterLocalTime}`);
			return false;
		}
		let isTrusted = false;
		for (const cert of caCertArray) {
			// check if the rootCert is in the trusted list
			if (stringEqual(cert.sha256Fingerprint, topCert.sha256Fingerprint)) {
				log.debug(`Trusted Certificate: ${cert.commonName} >> ${certChainArray[0].commonName}`);
				isTrusted = true;
				break;
			}
		}
		if (!isTrusted) {
			// there was no trusted CA in caCertArray
			log.debug(`Issuing CA ${topCert.issuerCommonName} / ${topCert.sha256Fingerprint} is NOT TRUSTED!`);
			if (prefs.getBoolPref("addUnknownCAs")) {
				for (const cert of certArray) {
					if (CERTTOOLS.getFingerprint(cert) === topCert.sha256Fingerprint) {
						BIMIDB.addCA(cert, false);
						break;
					}
				}
			}
		}
		return isTrusted;
	};

	let that = {
		getHash: _getHash,
		getFingerprint: _getFingerprint,
		getEndEntitityCert: _getEndEntitityCert,
		getBimiHashData: _getBimiHashData,
		getBimiSVGData: _getBimiSVGData,
		getAlternativeDomainNames: _getAlternativeDomainNames,

		convertPEMtoDERArray: _convertPEMtoDERArray,
		convertPEMtoDER: _convertPEMtoDER,
		convertDERtoPEM: _convertDERtoPEM,

		testBIMICert: _testBIMICert,
		testValidity: _testValidity,
		testPEMformat: _testPEMformat
	};

	return that;

}());

let BIMI = (function() {

	const log = Logging.getLogger("BIMI");

	/**
	 * Parses a BIMI DNS record
	 *
	 * @param {String} bimiRecord BIMI DNS record
	 * @returns {BimiRecord|null} Parsed BIMI DNS record
	 */
	let _parseBimiRecord = function(bimiRecord) {

		/** @type {BimiRecord} */
		const res = {
			version: "1.0",
			bimiVersion: "",
			location: ""
		};

		const parsedObj = rfcParser.parseTagValueList(bimiRecord);
		if (!(toType(parsedObj) === "Map")) {
			log.error(`unexpected return value from parseTagValueList: ${parsedObj}`);
			return res;
		}

		/** @type {Map} */
		// @ts-expect-error
		const parsedMap = parsedObj;
		if (parsedMap.has("v"))	{ res.bimiVersion = parsedMap.get("v"); } else { return null; }
		if (parsedMap.has("l"))	{ res.location = parsedMap.get("l"); } else { return null; }
		if (parsedMap.has("a"))	{ res.authorization = parsedMap.get("a"); }
		log.debug(res.toSource());

		return res;
	};

	/**
	 * Fetches text data from a given url
	 *
	 * @param {String} url location
	 * @returns {Promise<String|undefined>}
	 */
	let _fetchTextResource = async function _fetchTextResource(url) {
		let httpResponse;
		try {
			httpResponse = await new Promise(function (resolve, reject) {
				// @ts-expect-error
				const XMLHttpRequest = Components.Constructor("@mozilla.org/xmlextras/xmlhttprequest;1", "nsIXMLHttpRequest");
				const xhr = new XMLHttpRequest();
				xhr.responseType = "text";
				xhr.open("GET", url);
				xhr.onload = function () {
					if (this.status >= 200 && this.status < 300) {
						resolve({
							status: this.status,
							result: this.response
						});
					} else {
						// eslint-disable-next-line prefer-promise-reject-errors
						reject({
							status: this.status,
							statusText: this.statusText
						});
					}
				};
				xhr.onerror = function () {
					// eslint-disable-next-line prefer-promise-reject-errors
					reject({
						status: this.status,
						statusText: this.statusText
					});
				};
				xhr.send();
			});
		} catch (error) {
			log.error(`Failed to fetch resource from ${url}`, error);
		}
		if (httpResponse.status < 200 || httpResponse.status >= 300) {
			log.error(`DNS server responded with response status: ${httpResponse.statusText} (${httpResponse.status})`);
		}
		return httpResponse.result;
	};

	/**
	 * @param {dkimSigResultV2[]} dkimSigResults
	 * @returns {Boolean}
	 */
	let _checkBasicRequirementsForOnlineBIMI = function(dkimSigResults) {
		return prefs.getIntPref("enable") > PREF.BIMI.OFF
				&& dkimSigResults.length > 0
				&& dkimSigResults[0].result === "SUCCESS"
				&& toType(dkimSigResults[0].sdid) === "String";
	};

	/*
	 * Computes a hash of "text" using the algo from hashElement
	 * and compares it to the hash in hashElement
	 *
	 * @param {String} text cleartext to compare the hash
	 * @param {Object} hashElement has the properties algo and hash
	 * @returns {Boolean}
	 */
	let _compareHash = function(text, hashElement) {
		return stringEqual(CERTTOOLS.getHash(text, hashElement.algo), hashElement.hash);
	};

	/**
	 * Add all non wildcard domains from a bimi cert to the database
	 *
	 * @param {String} bimiCert
	 * @param {String} indicator
	 * @returns {Promise<void>}
	 */
	let _addAllSANtoDB = async function _addAllSANtoDB(bimiCert, indicator) {
		for (const name of CERTTOOLS.getAlternativeDomainNames(bimiCert)) {
			if (name.substring(0,2) !== "*.") {
				await BIMIDB.addBimiIndicator(name, indicator);
			}
		}
	};

	let that = {
		/**
		* Try to get the BIMI Indicator if available.
		*
		* @param {Map<string, string[]>} headers
		* @param {ARHResinfo[]} arhBIMI - Trusted ARHs containing a BIMI result.
		* @returns {string|null}
		*/
		getBimiIndicatorFromHeader: function (headers, arhBIMI) {
			// Assuming:
			// 1. We only get ARHs that can be trusted (i.e. from the receiving MTA).
			// 2. If the receiving MTA does not supports BIMI,
			//    we will not see an ARH with a BIMI result (because of 1)
			// 3. If the receiving MTA supports BIMI,
			//    it will make sure we only see his BIMI-Indicator headers (as required by the RFC).
			//
			// Given the above, it should be safe to trust the BIMI indicator from the BIMI-Indicator header
			// if we have a passing BIMI result there the MTA claims to have checked the Authority Evidence.

			if (prefs.getIntPref("enable") === PREF.BIMI.OFF) { return null; }

			const hasAuthorityPassBIMI = arhBIMI.some(
				arh => arh.method === "bimi" &&
					arh.result === "pass" &&
					arh.properties.policy.authority === "pass"
			);
			if (!hasAuthorityPassBIMI) {
				return null;
			}

			const bimiIndicators = headers.get("bimi-indicator") || [];
			if (bimiIndicators.length > 1) {
				log.warn("Message contains more than one BIMI-Indicator header");
				return null;
			}
			let bimiIndicator = bimiIndicators[0];
			if (!bimiIndicator) {
				log.warn("Message contains an ARH with passing BIMI but does not have a BIMI-Indicator header");
				return null;
			}

			// TODO: If in the future we support ARC we might want to check the policy.indicator-hash

			// Remove header name and new line at end
			bimiIndicator = bimiIndicator.slice("bimi-indicator:".length, -"\r\n".length);
			// Remove all whitespace
			bimiIndicator = bimiIndicator.replace(new RegExp(`${rfcParser.get("FWS")}`, "g"), "");

			return bimiIndicator;
		},

		/**
		* Try to get the BIMI Indicator if available.
		*
		* @param {dkimSigResultV2[]} dkimSigResults - result of the dkim verification
		* @returns {Promise<String|Null>}
		*/
		getBimiIndicatorOnline: async function getBimiIndicatorOnline(dkimSigResults) {
			// Only try to fetch BIMI information if enabled and DKIM is valid
			if (!_checkBasicRequirementsForOnlineBIMI(dkimSigResults)) { return null; }

			// We already check in checkBasicRequirementsForOnlineBIMI, that sdid is defined
			let domain = String(dkimSigResults[0].sdid).toLowerCase();
			// Lookup BIMI indicator in cache
			log.debug("Try to get BIMI logo for " + domain);
			let cachedBimiIndicator = await BIMIDB.getBimiIndicator(domain);
			if (cachedBimiIndicator) {
				log.debug("Got BIMI logo from database");
				return cachedBimiIndicator;
			}

			// Lookup Online
			if (prefs.getIntPref("enable") < PREF.BIMI.MAIL_ONLINE) { return null; }
			let parsedBimiRecord;
			try {
				let dnsResult = await DNS.resolve(`default._bimi.${domain}`, "TXT");
				if (dnsResult && dnsResult.data) {
					let bimiRecord = dnsResult.data[0];
					parsedBimiRecord = _parseBimiRecord(bimiRecord);
				}
			} catch (error) {
				log.error(`Error resolving default._bimi.${domain}`);
			}

			// Only try to get the indicator if authorization information is present
			if (!parsedBimiRecord || !parsedBimiRecord.authorization) { return null; }

			let pemCertChain = await _fetchTextResource(parsedBimiRecord.authorization);

			// Testing certificates...
			if (!pemCertChain) { return null; }
			const b64Certs = CERTTOOLS.convertPEMtoDERArray(pemCertChain);
			const bimiCert = CERTTOOLS.getEndEntitityCert(b64Certs);
			if (!bimiCert
				|| !CERTTOOLS.testBIMICert(bimiCert, domain)
				|| !await CERTTOOLS.testValidity(b64Certs)
			) { return null; }

			// Fetching BIMI indicator from certificate
			const svgData = CERTTOOLS.getBimiSVGData(bimiCert);
			if (svgData.length > 0) {
				let result = svgData[0];
				if (prefs.getBoolPref("cacheIndicators")) {
					await BIMIDB.addBimiIndicator(domain, result); // in case of a wildcard san
					_addAllSANtoDB(bimiCert, result);
				}
				return result;
			}

			// Fetching BIMI indicator from internet and compare to hash
			const svgHash = CERTTOOLS.getBimiHashData(bimiCert);
			if (svgHash.length > 0) {
				const bimiIndicator = await _fetchTextResource(parsedBimiRecord.location);
				if (bimiIndicator) {
					let hashMatch = svgHash.filter(entry => _compareHash(bimiIndicator, entry));
					if (hashMatch.length > 0) {
						let result = btoa(bimiIndicator);
						if (prefs.getBoolPref("cacheIndicators")) {
							await BIMIDB.addBimiIndicator(domain, result); // in case of a wildcard san
							_addAllSANtoDB(bimiCert, result);
						}
						return result;
					}
				}
			}
			return null;
		}
	};
	return that;
}());

let BIMIDB = (function() {

	const log = Logging.getLogger("BIMI.DB");
	const BIMI_DB_NAME = "dkimBimi.sqlite";
	let dbInitialized = false;
	// Deferred<boolean>
	/** @type {IDeferred<boolean>} */
	let dbInitializedDefer = new Deferred();

	/**
	 * init DB
	 * May be called more then once
	 *
	 * @returns {Promise<boolean>} initialized
	 * @throws {Error}
	 */
	let _initDB = function() {

		if (dbInitialized) {
			return dbInitializedDefer.promise;
		}
		dbInitialized = true;

		let promise = (async () => {

			Logging.addAppenderTo("Sqlite.Connection." + BIMI_DB_NAME, "sql.");

			const conn = await Sqlite.openConnection({path: BIMI_DB_NAME});

			try {
				// get version numbers
				await conn.execute(
					"CREATE TABLE IF NOT EXISTS version (\n" +
					"  name TEXT PRIMARY KEY NOT NULL,\n" +
					"  version INTEGER NOT NULL\n" +
					");"
				);

				const sqlRes = await conn.execute(
					"SELECT * FROM version;"
				);

				const versionTable = { certs: 0, domains: 0, indicators: 0, caData: 0 };
				sqlRes.forEach(function(element /*, index, array*/ ) {
					switch(element.getResultByName("name")) {
						case "TableCerts":
							versionTable.certs = element.getResultByName("version");
							break;
						case "TableDomains":
							versionTable.domains = element.getResultByName("version");
							break;
						case "TableIndicators":
							versionTable.indicators = element.getResultByName("version");
							break;
						case "DataCA":
							versionTable.caData = element.getResultByName("version");
							break;
						default:
							log.warn("Version table contains unknown entry: " + element.getResultByName("name"));
					}
				});

				// table certs
				if (versionTable.certs === 0) {
					// create table
					await conn.execute(
						"CREATE TABLE IF NOT EXISTS certs (\n" +
						"  commonName TEXT NOT NULL,\n" +
						"  fingerprint TEXT NOT NULL,\n" +
						"  expiresOn INTEGER NOT NULL,\n" +
						"  trusted INTEGER NOT NULL,\n" +
						"  internal INTEGER NOT NULL,\n" +
						"  data TEXT NOT NULL,\n" +
						"  PRIMARY KEY (fingerprint)\n" +
						");"
					);
					// add version number
					await conn.execute(
						"INSERT INTO version (name, version)" +
						"VALUES ('TableCerts', 1);"
					);
					versionTable.certs = 1;
				}
				if (versionTable.certs > 1) {
					throw new Error("unsupported version for table 'certs'");
				}

				// table indicator
				if (versionTable.indicators === 0) {
					// create table
					await conn.execute(
						"CREATE TABLE IF NOT EXISTS indicators (\n" +
						"  idx INTEGER NOT NULL,\n" +
						"  insertedAt TEXT NOT NULL,\n" +
						"  lastUsedAt TEXT NOT NULL,\n" +
						"  data TEXT NOT NULL,\n" +
						"  PRIMARY KEY (idx)\n" +
						");"
					);
					// add version number
					await conn.execute(
						"INSERT INTO version (name, version)" +
						"VALUES ('TableIndicators', 1);"
					);
					versionTable.indicators = 1;
				}
				if (versionTable.Indicators > 1) {
					throw new Error("unsupported version for table 'indicators'");
				}

				// table domains
				if (versionTable.domains === 0) {
					// create table
					await conn.execute(
						"CREATE TABLE IF NOT EXISTS domains (\n" +
						"  domain TEXT NOT NULL,\n" +
						"  indicator INTEGER NOT NULL,\n" +
						"  PRIMARY KEY (domain),\n" +
						"  FOREIGN KEY (indicator) REFERENCES indicators(idx)\n" +
						");"
					);
					// add version number
					await conn.execute(
						"INSERT INTO version (name, version)" +
						"VALUES ('TableDomains', 1);"
					);
					versionTable.domains = 1;
				}
				if (versionTable.domains > 1) {
					throw new Error("unsupported version for table 'domains'");
				}

				// import extensions BIMI CA certs
				const certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);
				// read CAs from file
				const jsonStr = await readStringFrom("resource://dkim_verifier_data/bimiCAs.json");
				const bimiCAs = JSON.parse(jsonStr);
				// check data version
				// get timestamp of extension file
				let currentDataVersion = (new Date).getTime();
				const extensionFile = Cc["@mozilla.org/file/directory_service;1"].getService(Ci.nsIProperties).get("ProfD", Components.interfaces.nsIFile);
				extensionFile.append("extensions");
				extensionFile.append("dkim_verifier@pl.xpi");
				if (extensionFile.exists()) {
					currentDataVersion = extensionFile.lastModifiedTime;
				}
				if (versionTable.caData < currentDataVersion) {
					log.debug("Update BIMI CAs after update");
					// create new internal CA objects
					let newInternalCAs = bimiCAs.CAList.map(
						function (b64cert) {
							let cert;
							try {
								cert = certDB.constructX509FromBase64(b64cert);
							} catch (error) {
								log.error("Internal certificate data is corrupt", error);
								return null;
							}
							return {
								"cn" : cert.commonName,
								"fingerprint" : cert.sha256Fingerprint,
								"notAfter" : cert.validity.notAfter,
								"b64cert" : b64cert
							};
						}
					);
					newInternalCAs = newInternalCAs.filter(el => el !== null);
					// delete old internal CAs
					await conn.execute("DELETE FROM certs WHERE internal = 1;");
					// insert new internal CAs
					await conn.execute(
						"INSERT OR REPLACE INTO certs (commonName, fingerprint, expiresOn, trusted, internal, data)\n" +
						"VALUES (:cn, :fingerprint, :notAfter, 1, 1, :b64cert);",
						newInternalCAs
					);
					// update data version number
					await conn.execute(
						"INSERT OR REPLACE INTO version (name, version)\n" +
						"VALUES ('DataCA', :version);",
						{"version": currentDataVersion}
					);
				}
			} finally {
				await conn.close();
			}
			dbInitializedDefer.resolve(true);
			log.debug("DB initialized");
			return true;
		})();
		promise.then(null, function onReject(exception) {
			// Failure! We can inspect or report the exception.
			log.fatal(exception);
			dbInitializedDefer.reject(exception);
		});
		return dbInitializedDefer.promise;
	};

	_initDB();

	let that = {
		/**
		 * Gets all trusted, not expired from the database
		 *
		 * @returns {Promise<String[]>}
		 */
		getTrustedCAs: async function getTrustedCAs() {
			// wait for DB init
			await _initDB();
			const conn = await Sqlite.openConnection({path: BIMI_DB_NAME});

			let sqlRes = [];
			try {
				sqlRes = await conn.execute(
					"SELECT data FROM certs\n" +
					"WHERE\n" +
					"  trusted = 1 AND\n" +
					"  expiresOn >= :now;",
					{ "now": Date.now() * 1000 }
				);
			} finally {
				await conn.close();
			}

			let trustedCAs = [];
			for(const res of sqlRes) {
				trustedCAs.push(res.getResultByName("data"));
			}
			log.debug(`Found ${trustedCAs.length} BIMI CAs`);
			return trustedCAs;
		},

		/**
		 * Gets a specific CA certificate
		 *
		 * @param {String} fingerprint
		 * @returns {Promise<String|null>}
		 */
		getCA: async function getCA(fingerprint) {
			// wait for DB init
			await _initDB();
			const conn = await Sqlite.openConnection({path: BIMI_DB_NAME});

			let sqlRes = [];
			try {
				sqlRes = await conn.execute(
					"SELECT data FROM certs\n" +
					"WHERE\n" +
					"  fingerprint = :fingerprint;",
					{ "fingerprint": fingerprint }
				);
			} finally {
				await conn.close();
			}
			if (sqlRes.length > 0) {
				return sqlRes[0].getResultByName("data");
			}
			return null;
		},

		/**
		 * Adds a certificate to the database
		 *
		 * @param {String} certString Base64 encoded certificate string
		 * @param {Boolean} trust
		 * @returns {Promise<void>}
		 */
		addCA: async function addCA(certString, trust) {
			// wait for DB init
			await _initDB();
			const conn = await Sqlite.openConnection({path: BIMI_DB_NAME});
			const certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);
			const derCert = CERTTOOLS.testPEMformat(certString) ? CERTTOOLS.convertPEMtoDER(certString) : certString;
			let cert;
			try {
				cert = certDB.constructX509FromBase64(derCert);
			} catch (error) {
				log.error("The certificate data is corrupt", error);
				return;
			}
			try {
				let sqlRes = await conn.execute(
					"SELECT data FROM certs\n" +
					"WHERE\n" +
					"  data = :certData;",
					{ "certData": derCert }
				);
				// test if certificate is already in DB (then do nothing to not change the trust value or internal certs)
				if (!sqlRes || sqlRes.length === 0) {
					await conn.execute(
						"INSERT INTO certs (commonName, fingerprint, expiresOn, trusted, internal, data)\n" +
						"VALUES (:cn, :fingerprint, :notAfter, :trust, 0, :b64cert);",
						{
							"cn": cert.commonName,
							"fingerprint": cert.sha256Fingerprint,
							"notAfter": cert.validity.notAfter,
							"trust": trust ? 1 : 0,
							"b64cert": derCert
						}
					);
					log.debug(`Added CA with fingerprint ${cert.sha256Fingerprint}`);
				} else {
					log.debug(`CA was already in database`);
				}
			} finally {
				await conn.close();
			}
		},

		/**
		 * Removes a certificate from the database
		 *
		 * @param {String} fingerprint Fingerprint of the certificate
		 * @returns {Promise<void>}
		 */
		removeCA: async function removeCA(fingerprint) {
			// wait for DB init
			await _initDB();
			const conn = await Sqlite.openConnection({path: BIMI_DB_NAME});

			try {
				await conn.execute(
					"DELETE FROM certs WHERE\n" +
					"  fingerprint = :fingerprint AND\n" +
					"  internal = 0;",
					{ "fingerprint": fingerprint.toUpperCase() }
				);
				log.debug(`Removed CA with fingerprint ${fingerprint}`);
			} finally {
				await conn.close();
			}
		},

		/**
		 * Sets the certificate trust
		 *
		 * @param {String} fingerprint Fingerprint of the certificate
		 * @param {Boolean} trust
		 * @returns {Promise<void>}
		 */
		setCATrust: async function setCATrust(fingerprint, trust) {
			// wait for DB init
			await _initDB();
			const conn = await Sqlite.openConnection({path: BIMI_DB_NAME});

			try {
				await conn.execute(
					"UPDATE certs\n" +
					"  SET trusted = :trust\n" +
					"WHERE\n" +
					"  fingerprint = :fingerprint AND\n" +
					"  internal = 0;",
					{ "trust": trust ? 1 : 0, "fingerprint": fingerprint.toUpperCase() }
				);
				log.debug(`Updated trust for CA with fingerprint ${fingerprint}`);
			} finally {
				await conn.close();
			}
		},

		/**
		 * Gets a BIMI indicator from the database
		 *
		 * @param {String} domain
		 * @returns {Promise<String|null>}
		 */
		getBimiIndicator: async function getBimiIndicator(domain) {
			// wait for DB init
			await _initDB();
			const conn = await Sqlite.openConnection({path: BIMI_DB_NAME});

			let bimiIndicator = null;
			let sqlRes = [];
			try {
				sqlRes = await conn.execute(
					"SELECT indicators.data, indicators.idx, indicators.insertedAt FROM\n" +
					"domains INNER JOIN indicators ON domains.indicator = indicators.idx\n" +
					"WHERE\n" +
					"  domains.domain = :domain;",
					{ "domain": domain.toLowerCase() }
				);
				if (sqlRes.length > 0) {
					bimiIndicator = sqlRes[0].getResultByName("data");
					await conn.executeCached(
						"UPDATE indicators\n" +
						"  SET lastUsedAt = DATE('now')\n" +
						"WHERE\n" +
						"  idx = :index;",
						{ "index": sqlRes[0].getResultByName("idx") }
					);
					log.debug(`Found BIMI logo for ${domain}`);
					if (prefs.getIntPref("updateInterval") > 0) {
						let inserted = new Date(sqlRes[0].getResultByName("insertedAt"));
						let today = new Date();
						if ((today.getFullYear() - inserted.getFullYear()) * 12 + today.getMonth() - inserted.getMonth() > prefs.getIntPref("updateInterval")) {
							bimiIndicator = null;
							log.debug("BIMI logo is outdated, triggering refresh...");
						}
					}
				}
			} finally {
				await conn.close();
			}
			return bimiIndicator;
		},

		/**
		 * Adds a BIMI indicator to the database
		 *
		 * @param {String} domain
		 * @param {String} bimiIndicator
		 * @returns {Promise<void>}
		 */
		addBimiIndicator: async function addBimiIndicator(domain, bimiIndicator) {
			// wait for DB init
			await _initDB();
			const conn = await Sqlite.openConnection({path: BIMI_DB_NAME});

			try {
				let indIdx = -1;
				let sqlRes = [];
				// test if image is already in DB
				sqlRes = await conn.execute(
					"SELECT idx FROM indicators\n" +
					"WHERE\n" +
					"  data = :indicator;",
					{ "indicator": bimiIndicator }
				);
				if (sqlRes.length > 0) {
					indIdx = sqlRes[0].getResultByName("idx");
					// update existing BIMI indicator
					await conn.execute(
						"UPDATE indicators\n" +
						"  SET data = :data,\n" +
						"      insertedAt = DATE('now'),\n" +
						"      lastUsedAt = DATE('now')\n" +
						"WHERE\n" +
						"  idx = :index;",
						{ "index": indIdx, "data": bimiIndicator }
					);
					log.debug("Updated BIMI logo");
				} else {
					// get next index
					sqlRes = await conn.execute(
						"SELECT MAX(idx) FROM indicators;"
					);
					if (sqlRes.length > 0) {
						indIdx = sqlRes[0].getResultByName("MAX(idx)") + 1;
					} else {
						indIdx = 1;
					}
					// inserting new BIMI indicator
					await conn.execute(
						"INSERT INTO indicators (idx, insertedAt, lastUsedAt, data)\n" +
						"VALUES (:index, DATE('now'), DATE('now'), :data);",
						{ "index": indIdx, "data": bimiIndicator }
					);
					log.debug("Added new BIMI logo to database");
				}
				// update domain info
				if (indIdx >= 0) {
					await conn.execute(
						"INSERT OR REPLACE INTO domains (domain, indicator)\n" +
						"VALUES (:domain, :index);",
						{ "domain": domain.toLowerCase(), "index": indIdx }
					);
				}
			} finally {
				await conn.close();
			}
		},
		/**
		 * Removes a BIMI indicator from the database
		 *
		 * @param {String} domain
		 * @returns {Promise<void>}
		 */
		removeBimiIndicator: async function removeBimiIndicator(domain) {
			// wait for DB init
			await _initDB();
			const conn = await Sqlite.openConnection({path: BIMI_DB_NAME});

			try {
				let indIdx = -1;
				let sqlRes = [];
				sqlRes = await conn.execute(
					"SELECT indicator FROM domains\n" +
					"WHERE\n" +
					"  domain = :domain;",
					{ "domain": domain.toLowerCase() }
				);
				if (sqlRes.length > 0) { indIdx = sqlRes[0].getResultByName("indicator"); }
				await conn.execute(
					"DELETE FROM domains WHERE\n" +
					"  domain = :domain;",
					{ "domain": domain.toLowerCase() }
				);
				log.debug(`Removed ${domain}`);
				let otherDomains = await conn.execute(
					"SELECT domain FROM domains\n" +
					"WHERE\n" +
					"  indicator = :index;",
					{ "index": indIdx }
				);
				if (indIdx !== -1 && otherDomains.length === 0) {
					// there are no other domains using this indicator
					await conn.execute(
						"DELETE FROM indicators WHERE\n" +
						"  idx = :index;",
						{ "index": indIdx }
					);
					log.debug("BIMI logo is not associated with any domains, removed logo");
				}
			} finally {
				await conn.close();
			}
		}
	};

	return that;
}());
