/**
 * Copyright (c) 2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */


// @ts-check
///<reference path="../mozilla.d.ts" />
/* eslint-env worker */
/* global ChromeUtils, Components, ExtensionCommon */

"use strict";

function toType(obj) {
	return Object.prototype.toString.call(obj).match(/\s([a-zA-Z]+)/)[1];
}

// eslint-disable-next-line no-invalid-this
this.jsdns = class extends ExtensionCommon.ExtensionAPI {
	/**
	 * @param {ExtensionCommon.Extension} extension
	 */
	constructor(extension) {
		super(extension);
	}

	/**
	 * @param {ExtensionCommon.Context} context
	 * @returns {{}}
	 */
	getAPI(context) {
		const RCODE = {
			NoError: 0, // No Error [RFC1035]
			FormErr: 1, // Format Error [RFC1035]
			ServFail: 2, // Server Failure [RFC1035]
			NXDomain: 3, // Non-Existent Domain [RFC1035]
			NotImp: 4, // Non-Existent Domain [RFC1035]
			Refused: 5, // Query Refused [RFC1035]
		};
		const { JSDNS } = ChromeUtils.import(this.extension.rootURI.resolve("experiments/JSDNS.jsm.js"));
		this.extension.callOnClose(this);
		return {
			jsdns: {
				txt(name) {
					function dnsCallback(dnsResult, defer, queryError, rcode) {
						try {
							let resRcode = RCODE.NoError;
							if (rcode !== undefined) {
								resRcode = rcode;
							} else if (queryError !== undefined) {
								let error = "";
								if (toType(queryError) === "String") {
									error = context.extension.localeData.localizeMessage(queryError);
								} else if (toType(queryError) === "Array") {
									error = context.extension.localeData.localizeMessage(queryError[0], queryError[1]);
									console.warn("error",error);
								}
								if (!error) {
									error = queryError;
								}
								console.warn(`JSDNS failed with: ${error}`);
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

	close() {
		Components.utils.unload(this.extension.rootURI.resolve("experiments/JSDNS.jsm.js"));
	}
};
