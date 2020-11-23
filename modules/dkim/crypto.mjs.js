/**
 * crypto.mjs.js
 *
 * Version: 0.1.0 (02 February 2020)
 *
 * Copyright (c) 2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-env browser, node */

import { DKIM_SigError } from "../error.mjs.js";
import Logging from "../logging.mjs.js";

const log = Logging.getLogger("Crypto");

/**
 * Interface for Crypto operations needed for DKIM
 */
class DkimCryptoI {
	/**
	 * Generate a hash.
	 *
	 * @static
	 * @param {string} algorithm - sha1 / sha256
	 * @param {string} message - binary string
	 * @returns {Promise<string>} b64 encoded hash
	 * @memberof DkimCryptoI
	 */
	static digest(algorithm, message) { // eslint-disable-line no-unused-vars
		throw new Error("Not implemented");
	}

	/**
	 * Verify an RSA signature.
	 *
	 * @static
	 * @param {string} key - b64 encoded RSA key in ASN.1 DER format
	 * @param {string} digestAlgorithm - sha1 / sha256
	 * @param {string} signature - b64 encoded signature
	 * @param {string} data - data whose signature is to be verified (binary string)
	 * @return {Promise<[Boolean, number]>} - valid, key length
	 * @throws DKIM_SigError
	 * @memberof DkimCryptoI
	 */
	static verifyRSA(key, digestAlgorithm, signature, data) { // eslint-disable-line no-unused-vars
		throw new Error("Not implemented");
	}
}

/**
 * Convert a digest name used in DKIM to the one used by the Web Crypto API.
 *
 * @param {string} algorithm - algorithm name used by DKIM
 * @returns {string} - algorithm name used by the Web Crypto API
 */
function getWebDigestName(algorithm) {
	switch (algorithm.toLowerCase()) {
		case "sha1":
			return "SHA-1";
		case "sha256":
			return "SHA-256";
		default:
			throw new Error(`unknown digest algorithm ${algorithm}`);
	}
}

/**
 * Converts a string to an ArrayBuffer.
 * Characters >255 have their hi-byte silently ignored.
 *
 * @param {string} str - b64 encoded string
 * @returns {ArrayBuffer}
 */
function strToArrayBuffer(str) {
	const buffer = new ArrayBuffer(str.length);
	const bufferView = new Uint8Array(buffer);
	for (let i = 0; i < str.length; i++) {
		// eslint-disable-next-line no-magic-numbers
		bufferView[i] = str.charCodeAt(i) & 0xFF;
	}
	return buffer;
}

/**
 * Crypto implementation using the Web Crypto API
 */
class DkimCryptoWeb extends DkimCryptoI {
	/**
	 * Generate a hash.
	 *
	 * @static
	 * @param {string} algorithm - sha1 / sha256
	 * @param {string} message - binary string
	 * @returns {Promise<string>} b64 encoded hash
	 * @memberof DkimCryptoI
	 */
	static async digest(algorithm, message) {
		const digestName = getWebDigestName(algorithm);
		const data = strToArrayBuffer(message);
		const digest = await crypto.subtle.digest(digestName, data);
		const digestArray = new Uint8Array(digest);
		const digestB64 = btoa(String.fromCharCode(...digestArray));
		return digestB64;
	}

	/**
	 * Verify an RSA signature.
	 *
	 * @static
	 * @param {string} key - b64 encoded RSA key in ASN.1 DER encoded SubjectPublicKeyInfo
	 * @param {string} digestAlgorithm - sha1 / sha256
	 * @param {string} signature - b64 encoded signature
	 * @param {string} data - data whose signature is to be verified (binary string)
	 * @return {Promise<[Boolean, number]>} - valid, key length
	 * @throws DKIM_SigError
	 * @memberof DkimCryptoI
	 */
	static async verifyRSA(key, digestAlgorithm, signature, data) {
		let cryptoKey;
		try {
			cryptoKey = await crypto.subtle.importKey(
				"spki",
				strToArrayBuffer(atob(key)),
				{
					name: "RSASSA-PKCS1-v1_5",
					hash: getWebDigestName(digestAlgorithm)
				},
				true,
				["verify"]
			);
		} catch (e) {
			log.debug("error in importKey: ", e);
			throw new DKIM_SigError("DKIM_SIGERROR_KEYDECODE");
		}
		/** @type {RsaHashedKeyGenParams} */
		// @ts-ignore
		const rsaKeyParams = cryptoKey.algorithm;
		const valid = await crypto.subtle.verify(
			"RSASSA-PKCS1-v1_5",
			cryptoKey,
			strToArrayBuffer(atob(signature)),
			new TextEncoder().encode(data)
		);
		return [valid, rsaKeyParams.modulusLength];
	}
}

/**
 * Crypto implementation using Node's Crypto API
 */
class DkimCryptoNode extends DkimCryptoI {
	/**
	 * Generate a hash.
	 *
	 * @static
	 * @param {string} algorithm - sha1 / sha256
	 * @param {string} message - binary string
	 * @returns {Promise<string>} b64 encoded hash
	 * @memberof DkimCryptoI
	 */
	static async digest(algorithm, message) {
		const crypto = await import("crypto");
		const hash = crypto.createHash(algorithm);
		hash.update(message, "latin1");
		return hash.digest("base64");
	}

	/**
	 * Verify an RSA signature.
	 *
	 * @static
	 * @param {string} key - b64 encoded RSA key in ASN.1 DER encoded SubjectPublicKeyInfo
	 * @param {string} digestAlgorithm - sha1 / sha256
	 * @param {string} signature - b64 encoded signature
	 * @param {string} data - data whose signature is to be verified (binary string)
	 * @return {Promise<[Boolean, number]>} - valid, key length
	 * @throws DKIM_SigError
	 * @memberof DkimCryptoI
	 */
	static async verifyRSA(key, digestAlgorithm, signature, data) {
		const crypto = await import("crypto");
		/** @type {import("crypto").VerifyKeyWithOptions} */
		let cryptoKey;
		try {
			cryptoKey = crypto.createPublicKey({
				key: Buffer.from(key, "base64"),
				format: "der",
				type: "spki"
			});
		} catch (e) {
			log.error("error in createPublicKey: ", e);
			throw new DKIM_SigError("DKIM_SIGERROR_KEYDECODE");
		}
		cryptoKey.padding = crypto.constants.RSA_PKCS1_PADDING;
		const valid = crypto.verify(
			digestAlgorithm,
			Buffer.from(data, "latin1"),
			cryptoKey,
			Buffer.from(signature, "base64")
		);
		// TODO: get key size, e.g. with asn.1 parser in https://www.npmjs.com/package/node-forge
		return [valid, 1024];
	}
}

let DkimCrypto = DkimCryptoI;
if (globalThis.crypto) {
	DkimCrypto = DkimCryptoWeb;
} else {
	DkimCrypto = DkimCryptoNode;
}
export default DkimCrypto;
