/**
 * Copyright (c) 2020-2023;2025 Philippe Lieser
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
		/** @enum {number} */
		const RCODE = /** @type {const} */ ({
			NoError: 0, // No Error [RFC1035]
			FormErr: 1, // Format Error [RFC1035]
			ServFail: 2, // Server Failure [RFC1035]
			NXDomain: 3, // Non-Existent Domain [RFC1035]
			NotImp: 4, // Non-Existent Domain [RFC1035]
			Refused: 5, // Query Refused [RFC1035]
		});
		/** @type {import("./JSDNS.mjs")} */
		const { JSDNS } = ChromeUtils.importESModule(`chrome://dkim_verifier_jsdns/content/JSDNS.mjs?${Date.now()}`);
		this.extension.callOnClose(this);
		return {
			jsdns: {
				configure(getNameserversFromOS, nameServer, timeoutConnect, proxy, autoResetServerAlive, debug) {
					JSDNS.configureDNS(getNameserversFromOS, nameServer, timeoutConnect, proxy, autoResetServerAlive, debug);
					return Promise.resolve();
				},
				async txt(name) {
					const res = await JSDNS.queryDNS(name, "TXT");

					/** @type {number} */
					let resRcode = RCODE.NoError;
					if (res.rcode !== undefined) {
						resRcode = res.rcode;
					} else if (res.queryError !== undefined) {
						let error = "";
						error = typeof res.queryError === "string"
							? res.queryError
							: context.extension.localeData.localizeMessage(res.queryError[0] ?? "DKIM_DNSERROR_UNKNOWN", res.queryError[1]) || (res.queryError[0] ?? "Unknown DNS error");
						console.warn(`JSDNS failed with: ${error}`);
						return {
							error,
						};
					}

					const results = res.results?.map(rdata => {
						if (typeof rdata !== "string") {
							throw new TypeError(`DNS result has unexpected type ${typeof rdata}`);
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
		this.chromeHandle.destruct();
		// @ts-expect-error
		this.chromeHandle = null;

		Services.obs.notifyObservers(null, "startupcache-invalidate");
	}
};
