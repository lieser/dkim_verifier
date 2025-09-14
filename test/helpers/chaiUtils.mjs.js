/**
 * Copyright (c) 2020-2022;2025 Philippe Lieser
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

import { DKIM_SigError, DKIM_TempError } from "../../modules/error.mjs.js";
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
				} catch (error) {
					// @ts-expect-error
					error.showDiff = true;
					reject(error);
				}
			},
			thrownError => {
				try {
					if (thrownError instanceof DKIM_SigError) {
						if (thrownError.errorType !== errorType) {
							expect.fail(`${thrownError}`, errorType, "expected a different error type of DKIM_SigError");
						}
						resolve();
					}
					expect.fail(`${thrownError}`, errorType, "expected a DKIM_SigError to be thrown, got a different Error instead");
				} catch (error) {
					// @ts-expect-error
					error.showDiff = true;
					reject(error);
				}
			}
		);
	});
}

/**
 * Assert that the given promise is rejected with a certain type of DKIM_TempError.
 *
 * @param {Promise<any>} promise
 * @param {string} errorType - expected error type
 * @returns {Promise<void>}
 */
export function expectAsyncDkimTempError(promise, errorType) {
	return new Promise((resolve, reject) => {
		// TODO: Use Chai Plugin Utilities instead of expect.fail
		promise.then(
			value => {
				try {
					expect.fail(`${value}`, errorType, "expected a DKIM_TempError to be thrown, got a value instead");
				} catch (error) {
					// @ts-expect-error
					error.showDiff = true;
					reject(error);
				}
			},
			thrownError => {
				try {
					if (thrownError instanceof DKIM_TempError) {
						if (thrownError.errorType !== errorType) {
							expect.fail(`${thrownError}`, errorType, "expected a different error type of DKIM_TempError");
						}
						resolve();
					}
					expect.fail(`${thrownError}`, errorType, "expected a DKIM_TempError to be thrown, got a different Error instead");
				} catch (error) {
					// @ts-expect-error
					error.showDiff = true;
					reject(error);
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
				} catch (error) {
					// @ts-expect-error
					error.showDiff = true;
					reject(error);
				}
			},
			thrownError => {
				try {
					if (thrownError instanceof errorType) {
						resolve();
					}
					expect.fail(`${thrownError}`, errorType, "expected an Error to be thrown, got a different Type instead");
				} catch (error) {
					// @ts-expect-error
					error.showDiff = true;
					reject(error);
				}
			}
		);
	});
}
