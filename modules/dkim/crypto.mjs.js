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

/**
 * Interface for Crypto operations needed for DKIM
 */
class DkimCryptoI {
	/**
	 *
	 * @param {string} algorithm - SHA-1 / SHA-256 / SHA-384 / SHA-512
	 * @param {string} message
	 * @returns {Promise<string>} b64 encoded hash
	 */
	static async digest(algorithm, message) { // eslint-disable-line require-await, no-unused-vars
		throw new Error("Not implemented");
	}
}

/**
 * Crypto implementation using the Web Crypto API
 *
 * @implements {DkimCrypto}
 */
class DkimCryptoWeb extends DkimCryptoI {
	static async digest(algorithm, message) {
		let digestName = "";
		switch (algorithm.toLowerCase()) {
			case "sha1":
				digestName = "SHA-1";
				break;
			case "sha256":
				digestName = "SHA-256";
				break;
			default:
				throw new Error();
		}
		const data = new TextEncoder().encode(message);
		const digest = await crypto.subtle.digest(digestName, data);
		const digest_array = new Uint8Array(digest);
		const digest_b64 = btoa(String.fromCharCode(...digest_array));
		return digest_b64;
	}
}

/**
 * Crypto implementation using Node's Crypto API
 *
 * @implements {DkimCrypto}
 */
class DkimCryptoNode extends DkimCryptoI {
	static async digest(algorithm, message) { // eslint-disable-line require-await
		const crypto = require('crypto');
		const hash = crypto.createHash(algorithm);
		hash.update(message);
		return hash.digest("base64");
	}
}

let DkimCrypto = DkimCryptoI;
if (globalThis.crypto){
	DkimCrypto = DkimCryptoWeb;
} else {
	DkimCrypto = DkimCryptoNode;
}
export default DkimCrypto;
