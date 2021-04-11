/**
 * Copyright (c) 2020 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */


// @ts-check
///<reference path="./jsdns.d.ts" />
///<reference path="../mozilla.d.ts" />
/* eslint-env worker */
/* global ChromeUtils, Components, ExtensionCommon */

"use strict";

// @ts-ignore
// eslint-disable-next-line no-var
var { Services } = ChromeUtils.import("resource://gre/modules/Services.jsm");

/**
 * From https://javascriptweblog.wordpress.com/2011/08/08/fixing-the-javascript-typeof-operator/
 * @param {any} obj
 * @returns {string}
 */
function toType(obj) {
	const typeMatch = Object.prototype.toString.call(obj).match(/\s([a-zA-Z]+)/);
	if (!typeMatch) {
		throw new Error(`Failed to get type for ${obj}`);
	}
	return typeMatch[1];
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
	 * @returns {{jsdns: browser.jsdns}}
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
		/** @type {{JSDNS: {configureDNS: typeof configureDNS, queryDNS: typeof queryDNS}}} */
		const { JSDNS } = ChromeUtils.import(this.extension.rootURI.resolve("experiments/JSDNS.jsm.js"));
		this.extension.callOnClose(this);
		return {
			jsdns: {
				configure(getNameserversFromOS, nameServer, timeoutConnect, proxy, autoResetServerAlive, debug) {
					JSDNS.configureDNS(getNameserversFromOS, nameServer, timeoutConnect, proxy, autoResetServerAlive, debug);
					return Promise.resolve();
				},
				txt(name) {
					// eslint-disable-next-line valid-jsdoc
					/** @type {QueryDnsCallback<{resolve: function(browser.jsdns.TxtResult): void, reject: function(Error): void}>} */
					function dnsCallback(dnsResult, defer, queryError, rcode) {
						try {
							let resRcode = RCODE.NoError;
							if (rcode !== undefined) {
								resRcode = rcode;
							} else if (queryError !== undefined) {
								/** @type {string|string[]} */
								let error = "";
								if (typeof queryError === "string") {
									error = context.extension.localeData.localizeMessage(queryError);
								} else if (toType(queryError) === "Array") {
									error = context.extension.localeData.localizeMessage(queryError[0], queryError[1]);
								}
								if (!error) {
									error = queryError;
								}
								console.warn(`JSDNS failed with: ${error}`);
								resRcode = RCODE.ServFail;
							}

							const results = dnsResult && dnsResult.map(rdata => {
								if (typeof rdata !== "string") {
									throw Error(`DNS result has unexpected type ${typeof rdata}`);
								}
								return rdata;
							});

							defer.resolve({
								data: results,
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
			},
		};
	}

	close() {
		Components.utils.unload(this.extension.rootURI.resolve("experiments/JSDNS.jsm.js"));
		Services.obs.notifyObservers(null, "startupcache-invalidate");
	}
};
