/**
 * Unified crypto interface for Thunderbird/Browser and Node
 *
 * Copyright (c) 2020-2023 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
/* eslint-env browser, node */
/* eslint-disable jsdoc/require-returns-check */

import { DKIM_SigError } from "../error.mjs.js";
import Logging from "../logging.mjs.js";
import nacl from "../../thirdparty/tweetnacl-es6/nacl-fast-es.js";

const log = Logging.getLogger("Crypto");

/**
 * Base class for Crypto operations needed for DKIM.
 */
class DkimCryptoBase {
	/**
	 * @protected
	 * @param {string} _str
	 * @returns {Uint8Array}
	 */
	_decodeBase64(_str) {
		throw new Error("Not implemented");
	}

	/**
	 * Generate a hash.
	 *
	 * @param {string} _algorithm - sha1 / sha256
	 * @param {string} _message - binary string
	 * @returns {Promise<string>} b64 encoded hash
	 */
	digest(_algorithm, _message) {
		throw new Error("Not implemented");
	}

	/**
	 * Generate a hash.
	 *
	 * @param {string} _algorithm - sha1 / sha256
	 * @param {string} _message - binary string
	 * @returns {Promise<Uint8Array>} hash
	 */
	digestRaw(_algorithm, _message) {
		throw new Error("Not implemented");
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
	 * @throws DKIM_SigError
	 */
	verify(signAlgorithm, key, digestAlgorithm, signature, data) {
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
	 * @param {string} _key - b64 encoded RSA key in ASN.1 DER format
	 * @param {string} _digestAlgorithm - sha1 / sha256
	 * @param {string} _signature - b64 encoded signature
	 * @param {string} _data - data whose signature is to be verified (binary string)
	 * @returns {Promise<[boolean, number]>} - valid, key length
	 * @throws DKIM_SigError
	 */
	verifyRSA(_key, _digestAlgorithm, _signature, _data) {
		throw new Error("Not implemented");
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
	async verifyEd25519(key, digestAlgorithm, signature, data) {
		const hashValue = await this.digestRaw(digestAlgorithm, data);

		const valid = nacl.sign.detached.verify(
			hashValue,
			this._decodeBase64(signature),
			this._decodeBase64(key));

		const ed25519PublicKeyLenght = 256;
		return Promise.resolve([valid, ed25519PublicKeyLenght]);
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
 * Crypto implementation using the Web Crypto API
 */
class DkimCryptoWeb extends DkimCryptoBase {
	/**
	 * @override
	 * @protected
	 * @param {string} str
	 * @returns {Uint8Array}
	 */
	 _decodeBase64(str) {
		return strToArrayBuffer(atob(str));
	}

	/**
	 * @param {Uint8Array} data
	 * @returns {string}
	 */
	#encodeBase64(data) {
		return btoa(String.fromCharCode(...data));
	}

	/**
	 * Generate a hash.
	 *
	 * @override
	 * @param {string} algorithm - sha1 / sha256
	 * @param {string} message - binary string
	 * @returns {Promise<string>} b64 encoded hash
	 */
	async digest(algorithm, message) {
		const digest = await this.digestRaw(algorithm, message);
		return this.#encodeBase64(digest);
	}

	/**
	 * Generate a hash.
	 *
	 * @override
	 * @param {string} algorithm - sha1 / sha256
	 * @param {string} message - binary string
	 * @returns {Promise<Uint8Array>} b64 encoded hash
	 */
	async digestRaw(algorithm, message) {
		const digestName = getWebDigestName(algorithm);
		const data = strToArrayBuffer(message);
		const digest = await crypto.subtle.digest(digestName, data);
		const digestArray = new Uint8Array(digest);
		return digestArray;
	}

	/**
	 * Verify an RSA signature.
	 *
	 * @override
	 * @param {string} key - b64 encoded RSA key in ASN.1 DER encoded SubjectPublicKeyInfo
	 * @param {string} digestAlgorithm - sha1 / sha256
	 * @param {string} signature - b64 encoded signature
	 * @param {string} data - data whose signature is to be verified (binary string)
	 * @returns {Promise<[boolean, number]>} - valid, key length
	 * @throws DKIM_SigError
	 */
	async verifyRSA(key, digestAlgorithm, signature, data) {
		let cryptoKey;
		try {
			cryptoKey = await crypto.subtle.importKey(
				"spki",
				this._decodeBase64(key),
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
			this._decodeBase64(signature),
			new TextEncoder().encode(data)
		);
		return [valid, rsaKeyParams.modulusLength];
	}
}

/**
 * Crypto implementation using Node's Crypto API
 */
class DkimCryptoNode extends DkimCryptoBase {
	/**
	 * @returns {Promise<typeof import("crypto")>}
	 */
	async #crypto() {
		if (!this.crypto) {
			this.crypto = await import("crypto");
		}
		return this.crypto;
	}

	/**
	 * @override
	 * @protected
	 * @param {string} str
	 * @returns {Uint8Array}
	 */
	_decodeBase64(str) {
		return Buffer.from(str, "base64");
	}

	/**
	 * Generate a hash.
	 *
	 * @override
	 * @param {string} algorithm - sha1 / sha256
	 * @param {string} message - binary string
	 * @returns {Promise<string>} b64 encoded hash
	 */
	async digest(algorithm, message) {
		const crypto = await this.#crypto();
		const hash = crypto.createHash(algorithm);
		hash.update(message, "latin1");
		return hash.digest("base64");
	}

	/**
	 * Generate a hash.
	 *
	 * @override
	 * @param {string} algorithm - sha1 / sha256
	 * @param {string} message - binary string
	 * @returns {Promise<Uint8Array>} b64 encoded hash
	 */
	async digestRaw(algorithm, message) {
		const crypto = await this.#crypto();
		const hash = crypto.createHash(algorithm);
		hash.update(message, "latin1");
		return hash.digest();
	}

	/**
	 * Verify an RSA signature.
	 *
	 * @override
	 * @param {string} key - b64 encoded RSA key in ASN.1 DER encoded SubjectPublicKeyInfo
	 * @param {string} digestAlgorithm - sha1 / sha256
	 * @param {string} signature - b64 encoded signature
	 * @param {string} data - data whose signature is to be verified (binary string)
	 * @returns {Promise<[boolean, number]>} - valid, key length
	 * @throws DKIM_SigError
	 */
	async verifyRSA(key, digestAlgorithm, signature, data) {
		const crypto = await this.#crypto();
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
		const valid = crypto.verify(
			digestAlgorithm,
			Buffer.from(data, "latin1"),
			{
				key: cryptoKey,
				padding: crypto.constants.RSA_PKCS1_PADDING,
			},
			Buffer.from(signature, "base64")
		);
		// TODO: get key size, e.g. with asn.1 parser in https://www.npmjs.com/package/node-forge
		// eslint-disable-next-line no-magic-numbers
		return [valid, 1024];
	}
}

/** @type {DkimCryptoBase} */
let DkimCrypto;
if (globalThis.crypto) {
	DkimCrypto = new DkimCryptoWeb();
} else {
	DkimCrypto = new DkimCryptoNode();
}
export default DkimCrypto;
