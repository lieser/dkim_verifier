/**
 * Copyright (c) 2020-2022 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check
///<reference path="./mailUtils.d.ts" />
///<reference path="./mozilla.d.ts" />
/* global ExtensionCommon */

"use strict";

// @ts-expect-error
// eslint-disable-next-line no-var
var { Services } = ChromeUtils.import("resource://gre/modules/Services.jsm");

this.mailUtils = class extends ExtensionCommon.ExtensionAPI {
	/**
	 * @param {ExtensionCommon.Context} _context
	 * @returns {{mailUtils: browser.mailUtils}}
	 */
	getAPI(_context) {
		return {
			mailUtils: {
				/**
				 * Returns the base domain for an e-mail address.
				 *
				 * @param {string} addr
				 * @returns {Promise<string>}
				 */
				// eslint-disable-next-line require-await
				getBaseDomainFromAddr: async (addr) => {
					// var fullDomain = addr.substr(addr.lastIndexOf("@")+1);
					const nsiURI = Services.io.newURI(`http://${addr}`);
					try {
						return Services.eTLD.getBaseDomain(nsiURI);
					} catch (e) {
						// domains like "blogspot.co.uk", "blogspot.com", "googlecode.com"
						// are on the public suffix list, but should be valid base domains
						// because e-mails may be send from them
						// @ts-expect-error
						if (e.result === Cr.NS_ERROR_INSUFFICIENT_DOMAIN_LEVELS) {
							// add "invalid" subdomain to avoid error
							const invalidSub = "invalid.";
							const host = invalidSub + nsiURI.asciiHost;
							const res = Services.eTLD.getBaseDomainFromHost(host, 0);
							// remove "invalid" subdomain from result
							return res.substr(invalidSub.length);
						}
						throw e;
					}
				},
			},
		};
	}
};
