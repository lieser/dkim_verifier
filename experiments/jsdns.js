/**
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="../globals.d.ts" />
/* global ChromeUtils, ExtensionCommon */

"use strict";

// eslint-disable-next-line no-invalid-this
this.jsdns = class extends ExtensionCommon.ExtensionAPI {
	getAPI(context) {
		// console.log("context:", context);
		const RCODE = {
			NoError: 0, // No Error [RFC1035]
			FormErr: 1, // Format Error [RFC1035]
			ServFail: 2, // Server Failure [RFC1035]
			NXDomain: 3, // Non-Existent Domain [RFC1035]
			NotImp: 4, // Non-Existent Domain [RFC1035]
			Refused: 5, // Query Refused [RFC1035]
		};
		const { JSDNS } = ChromeUtils.import(`${context.extension.baseURL}/experiments/JSDNS.jsm.js`);
		return {
			jsdns: {
				txt(name) {
					function dnsCallback(dnsResult, defer, queryError, rcode) {
						try {
							let resRcode = RCODE.NoError;
							if (rcode !== undefined) {
								resRcode = rcode;
							} else if (queryError !== undefined) {
								resRcode = RCODE.ServFail;
							}

							defer.resolve({
								data: dnsResult,
								rcode: resRcode,
								secure: false,
								bogus: false,
							});
						} catch (e) {
							defer.reject(e);
						}
					}

					return new Promise((resolve, reject) => JSDNS.queryDNS(
						name, "TXT", dnsCallback, { resolve: resolve, reject: reject }));
				},
			}
		};
	}
};
