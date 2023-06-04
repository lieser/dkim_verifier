/**
 * Copyright (c) 2020-2023 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */


// @ts-check
///<reference path="./jsdns.d.ts" />
///<reference path="./mozilla.d.ts" />
/* global ExtensionCommon */

"use strict";

// @ts-expect-error
// eslint-disable-next-line no-var
var { Services } = ChromeUtils.import("resource://gre/modules/Services.jsm");

this.jsdns = class extends ExtensionCommon.ExtensionAPI {
	/**
	 * @param {ExtensionCommon.Extension} extension
	 */
	constructor(extension) {
		super(extension);

		const aomStartup = Cc[
			"@mozilla.org/addons/addon-manager-startup;1"
		]?.getService(Ci.amIAddonManagerStartup);
		if (!aomStartup) {
			throw new Error("Failed to get amIAddonManagerStartup");
		}
		const manifestURI = Services.io.newURI(
			"manifest.json",
			null,
			this.extension.rootURI
		);
		this.chromeHandle = aomStartup.registerChrome(manifestURI, [
			["content", "dkim_verifier_jsdns", "experiments/"],
		]);
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
		const { JSDNS } = ChromeUtils.import("chrome://dkim_verifier_jsdns/content/JSDNS.jsm.js");
		this.extension.callOnClose(this);
		return {
			jsdns: {
				configure(getNameserversFromOS, nameServer, timeoutConnect, proxy, autoResetServerAlive, debug) {
					JSDNS.configureDNS(getNameserversFromOS, nameServer, timeoutConnect, proxy, autoResetServerAlive, debug);
					return Promise.resolve();
				},
				async txt(name) {
					const res = await JSDNS.queryDNS(name, "TXT");

					let resRcode = RCODE.NoError;
					if (res.rcode !== undefined) {
						resRcode = res.rcode;
					} else if (res.queryError !== undefined) {
						let error = "";
						if (typeof res.queryError === "string") {
							error = res.queryError;
						} else {
							error = context.extension.localeData.localizeMessage(res.queryError[0] ?? "DKIM_DNSERROR_UNKNOWN", res.queryError[1]) ||
								(res.queryError[0] ?? "Unknown DNS error");
						}
						console.warn(`JSDNS failed with: ${error}`);
						return {
							error,
						};
					}

					const results = res.results?.map(rdata => {
						if (typeof rdata !== "string") {
							throw Error(`DNS result has unexpected type ${typeof rdata}`);
						}
						return rdata;
					});

					return {
						data: results ?? null,
						rcode: resRcode,
						secure: false,
						bogus: false,
					};
				},
			},
		};
	}

	close() {
		Cu.unload("chrome://dkim_verifier_jsdns/content/JSDNS.jsm.js");

		this.chromeHandle.destruct();
		// @ts-expect-error
		this.chromeHandle = null;

		Services.obs.notifyObservers(null, "startupcache-invalidate");
	}
};
