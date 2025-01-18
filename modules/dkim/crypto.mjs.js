/**
 * Unified crypto interface for Thunderbird/Browser and Node.
 *
 * Copyright (c) 2020-2023;2025 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check

import { DKIM_SigError } from "../error.mjs.js";
import Logging from "../logging.mjs.js";
import nacl from "../../thirdparty/tweetnacl-es6/nacl-fast-es.js";

const log = Logging.getLogger("Crypto");

/**
 * Converts a string to an ArrayBuffer.
 * Characters >255 have their hi-byte silently ignored.
 *
 * @param {string} str - binary string
 * @returns {Uint8Array}
 */
function strToArrayBuffer(str) {
	const buffer = new Uint8Array(str.length);
	for (let i = 0; i < str.length; i++) {
		// eslint-disable-next-line no-magic-numbers
		buffer[i] = str.charCodeAt(i) & 0xFF;
	}
	return buffer;
}

/**
 * @protected
 * @param {string} str
 * @returns {Uint8Array}
 */
function decodeBase64(str) {
	return strToArrayBuffer(atob(str));
}

/**
 * @param {Uint8Array} data
 * @returns {string}
 */
function encodeBase64(data) {
	return btoa(String.fromCharCode(...data));
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
 * Crypto operations needed for DKIM.
 *
 * Tries to be mostly just a wrapper around the Web Crypto API.
 */
export default class DkimCrypto {
	/**
	 * Generate a hash.
	 *
	 * @param {string} algorithm - sha1 / sha256
	 * @param {string} message - binary string
	 * @returns {Promise<string>} b64 encoded hash
	 */
	static async digest(algorithm, message) {
		const digest = await this.digestRaw(algorithm, message);
		return encodeBase64(digest);
	}

	/**
	 * Generate a hash.
	 *
	 * @param {string} algorithm - sha1 / sha256
	 * @param {string} message - binary string
	 * @returns {Promise<Uint8Array>} hash
	 */
	static async digestRaw(algorithm, message) {
		const digestName = getWebDigestName(algorithm);
		const data = strToArrayBuffer(message);
		const digest = await crypto.subtle.digest(digestName, data);
		const digestArray = new Uint8Array(digest);
		return digestArray;
	}

	/**
	 * Verify a signature.
	 *
	 * @param {string} signAlgorithm - rsa / ed25519
	 * @param {string} key - b64 encoded key
	 * @param {string} digestAlgorithm - sha1 / sha256
	 * @param {string} signature - b64 encoded signature
	 * @param {string} data - data whose signature is to be verified (binary string)
	 * @returns {Promise<[boolean, number]>} - valid, key length
	 * @throws {DKIM_SigError}
	 */
	static verify(signAlgorithm, key, digestAlgorithm, signature, data) {
		if (signAlgorithm === "rsa") {
			return this.verifyRSA(key, digestAlgorithm, signature, data);
		} else if (signAlgorithm === "ed25519") {
			return this.verifyEd25519(key, digestAlgorithm, signature, data);
		}
		throw new Error("Signing algorithm not implemented");
	}

	/**
	 * Verify an RSA signature.
	 *
	 * @param {string} key - b64 encoded RSA key in ASN.1 DER encoded SubjectPublicKeyInfo
	 * @param {string} digestAlgorithm - sha1 / sha256
	 * @param {string} signature - b64 encoded signature
	 * @param {string} data - data whose signature is to be verified (binary string)
	 * @returns {Promise<[boolean, number]>} - valid, key length
	 * @throws {DKIM_SigError}
	 */
	static async verifyRSA(key, digestAlgorithm, signature, data) {
		let cryptoKey;
		try {
			cryptoKey = await crypto.subtle.importKey(
				"spki",
				decodeBase64(key),
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
		// @ts-expect-error
		const rsaKeyParams = cryptoKey.algorithm;
		const valid = await crypto.subtle.verify(
			"RSASSA-PKCS1-v1_5",
			cryptoKey,
			decodeBase64(signature),
			strToArrayBuffer(data)
		);
		return [valid, rsaKeyParams.modulusLength];
	}

	/**
	 * Verify an Ed25519 signature.
	 *
	 * @param {string} key - b64 encoded public key
	 * @param {string} digestAlgorithm - sha256
	 * @param {string} signature - b64 encoded signature
	 * @param {string} data - data whose signature is to be verified (binary string)
	 * @returns {Promise<[boolean, 256]>} - valid, key length
	 */
	static async verifyEd25519(key, digestAlgorithm, signature, data) {
		const hashValue = await this.digestRaw(digestAlgorithm, data);

		const valid = nacl.sign.detached.verify(
			hashValue,
			decodeBase64(signature),
			decodeBase64(key));

		const ed25519PublicKeyLenght = 256;
		return Promise.resolve([valid, ed25519PublicKeyLenght]);
	}
}
