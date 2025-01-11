/**
 * Copyright (c) 2020-2022 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check

/** @type {Chai.ExpectStatic} */
// @ts-expect-error
const expect = globalThis.expect;
export default expect;

import { DKIM_SigError } from "../../modules/error.mjs.js";
import Logging from "../../modules/logging.mjs.js";

// disable logging in tests
Logging.setLogLevel(Logging.Level.Fatal);

/**
 * Assert that the given promise is rejected with a certain type of DKIM_SigError.
 *
 * @param {Promise<any>} promise
 * @param {string} errorType - expected error type
 * @returns {Promise<void>}
 */
export function expectAsyncDkimSigError(promise, errorType) {
	return new Promise((resolve, reject) => {
		// TODO: Use Chai Plugin Utilities instead of expect.fail
		promise.then(
			value => {
				try {
					expect.fail(`${value}`, errorType, "expected a DKIM_SigError to be thrown, got a value instead");
				} catch (e) {
					// @ts-expect-error
					e.showDiff = true;
					reject(e);
				}
			},
			reason => {
				try {
					if (reason instanceof DKIM_SigError) {
						if (reason.errorType !== errorType) {
							expect.fail(`${reason}`, errorType, "expected a different error type of DKIM_SigError");
						}
						resolve();
					}
					expect.fail(`${reason}`, errorType, "expected a DKIM_SigError to be thrown, got a different Error instead");
				} catch (e) {
					// @ts-expect-error
					e.showDiff = true;
					reject(e);
				}
			}
		);
	});
}

/**
 * Assert that the given promise is rejected.
 *
 * @param {Promise<any>} promise
 * @param {any} errorType - expected error type
 * @returns {Promise<void>}
 */
export function expectAsyncError(promise, errorType = Error) {
	return new Promise((resolve, reject) => {
		// TODO: Use Chai Plugin Utilities instead of expect.fail
		promise.then(
			value => {
				try {
					expect.fail(`${value}`, errorType, "expected an Error to be thrown, got a value instead");
				} catch (e) {
					// @ts-expect-error
					e.showDiff = true;
					reject(e);
				}
			},
			reason => {
				try {
					if (reason instanceof errorType) {
						resolve();
					}
					expect.fail(`${reason}`, errorType, "expected an Error to be thrown, got a different Type instead");
				} catch (e) {
					// @ts-expect-error
					e.showDiff = true;
					reject(e);
				}
			}
		);
	});
}
