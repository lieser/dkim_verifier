// @ts-check

/** @type{Chai.ExpectStatic} */
// @ts-ignore
const expect = globalThis.expect;
export default expect;

import { DKIM_SigError } from "../../modules/error.mjs.js";

/**
 * Assert that the given promise is rejected with a certain type of DKIM_SigError
 *
 * @param {Promise<any>} promise
 * @param {string} errorType -  expected error type
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
					e.showDiff = true;
					reject(e);
				}
			}
		);
	});
}
