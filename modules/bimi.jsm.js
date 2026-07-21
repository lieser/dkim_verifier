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
/* global Components, Services, atob, btoa */
/* global Logging, rfcParser, DNS */
/* global toType, stringEqual */
/* exported EXPORTED_SYMBOLS, BIMI */

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
	"BIMI"
];

// @ts-expect-error
const Cc = Components.classes;
// @ts-expect-error
const Ci = Components.interfaces;
// @ts-expect-error
const Cu = Components.utils;

Cu.import("resource://gre/modules/Services.jsm");

Cu.import("resource://dkim_verifier/logging.jsm.js");
Cu.import("resource://dkim_verifier/arhParser.jsm.js");
Cu.import("resource://dkim_verifier/rfcParser.jsm.js");
Cu.import("resource://dkim_verifier/dnsWrapper.jsm.js");
Cu.import("resource://dkim_verifier/helper.jsm.js");

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
		function rstr2byteArray(str) {
			const res = new Array(str.length);
			for (let i = 0; i < str.length; i++) {
				res[i] = str.charCodeAt(i) & 0xFF;
			}
			return res;
		}

		// return the two-digit hexadecimal code for a byte
		function toHexString(charCode) {
			return ("0" + charCode.toString(16)).slice(-2);
		}

		const hasher = Components.classes["@mozilla.org/security/hash;1"].createInstance(Components.interfaces.nsICryptoHash);
		hasher.initWithString(hashAlgorithm);

		const data = rstr2byteArray(str);
		hasher.update(data, data.length);

		// true for base-64, false for binary data output
		let hash = hasher.finish(false);

		// convert the binary hash data to a hex string.
		hash = hash.split("").map(e => toHexString(e.charCodeAt(0))).join("");
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
			const certObj = certDB.constructX509FromBase64(derCert);
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
		certObj.readCertPEM(derCert);
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
		certObj.readCertPEM(derCert);
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
							log.debug("Found indicator image in certificate");
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
		certObj.readCertPEM(derCert);
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
			// path to the logo information
			const logotypeDataSets = logoExt.seq[0].tag.obj.tag.obj.seq[0]; // image data
			// loop through all image sets here
			for (const resourceSet of logotypeDataSets.seq) {
				for (const resource of resourceSet.seq) {
					if (resource.seq && resource.seq[0].seq) {
						let algo = resource.seq[0].seq[0].seq[0].oid;
						let hash = resource.seq[0].seq[1].octstr.hex;
						log.debug("Found indicator hash in certificate");
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
	 * @returns {Boolean} true if the certificate chain is deemed valid and trustet
	 */
	let _testValidity = function(certArray) {
		// @ToDo implement a way to handle trusted CAs
		const caCerts = [
			"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",
		];

		const certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);
		const caCertArray = [];
		const certChainArray = [];
		const now = new Date().getTime() * 1000;
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
		const endEntityObj = certDB.constructX509FromBase64(endEntity);
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
		}
		return isTrusted;
	};

	let that = {
		getHash: _getHash,
		getFingerprint: _getFingerprint,
		getEndEntitityCert: _getEndEntitityCert,
		getBimiHashData: _getBimiHashData,
		getBimiSVGData: _getBimiSVGData,

		convertPEMtoDERArray: _convertPEMtoDERArray,
		convertPEMtoDER: _convertPEMtoDER,
		convertDERtoPEM: _convertDERtoPEM,

		testBIMICert: _testBIMICert,
		testValidity: _testValidity,
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
	let parseBimiRecord = function(bimiRecord) {

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
	let fetchTextResource = async function fetchTextResource(url) {
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
			if (dkimSigResults.length === 0) { return null; }
			let mainResult = dkimSigResults[0];
			// Only try to fetch BIMI information if DKIM is valid
			if (mainResult.result === "SUCCESS") {
				log.debug("Try to get BIMI indicator for " + mainResult.sdid);
				let parsedBimiRecord;
				try {
					let dnsResult = await DNS.resolve(`default._bimi.${mainResult.sdid}`, "TXT");
					if (dnsResult && dnsResult.data) {
						let bimiRecord = dnsResult.data[0];
						parsedBimiRecord = parseBimiRecord(bimiRecord);
					}
				} catch (error) {
					log.error(`Error resolving default._bimi.${mainResult.sdid}`);
				}
				// Only try to get the indicator if authorization information is present
				if (parsedBimiRecord && parsedBimiRecord.authorization) {
					let pemCertChain = await fetchTextResource(parsedBimiRecord.authorization);
					if (pemCertChain) {
						const b64Certs = CERTTOOLS.convertPEMtoDERArray(pemCertChain);
						const bimiCert = CERTTOOLS.getEndEntitityCert(b64Certs);
						// @ts-expect-error
						if (!bimiCert || !CERTTOOLS.testBIMICert(bimiCert, mainResult.sdid)) { return null; }
						if (!CERTTOOLS.testValidity(b64Certs)) { return null; }
						const svgData = CERTTOOLS.getBimiSVGData(bimiCert);
						if (svgData.length > 0) { return svgData[0]; }
						const svgHash = CERTTOOLS.getBimiHashData(bimiCert);
						if (svgHash.length > 0) {
							const bimiIndicator = await fetchTextResource(parsedBimiRecord.location);
							if (bimiIndicator) {
								for (const entry of svgHash) {
									const testHash = CERTTOOLS.getHash(bimiIndicator, entry.algo);
									if (stringEqual(testHash, entry.hash)) { return btoa(bimiIndicator); }
								}
							}
						}
					}
				}
			}
			return null;
		}
	};
	return that;
}());
