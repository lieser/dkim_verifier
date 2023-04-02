/**
 * Copyright (c) 2020-2021 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check

import expect from "../helpers/chaiUtils.mjs.js";
import { getFavicon } from "../../modules/dkim/favicon.mjs.js";
import { hasWebExtensions } from "../helpers/initWebExtensions.mjs.js";

/**
 * Get the fake URL of an icon.
 *
 * @param {string} fileName
 * @returns {string}
 */
function iconUrl(fileName) {
	return `moz-extension://fake/data/favicon/${fileName}`;
}

describe("Favicons [unittest]", function () {
	before(function () {
		if (!hasWebExtensions) {
			// eslint-disable-next-line no-invalid-this
			this.skip();
		}
	});

	it("Domain is in known favicons", async function () {
		expect(await getFavicon("paypal.com")).to.be.equal(iconUrl("paypal.com.ico"));
		expect(await getFavicon("news.paypal.com")).to.be.equal(iconUrl("paypal.com.ico"));
	});
	it("Domain is not in known favicons", async function () {
		expect(await getFavicon("foo.com")).to.be.undefined;
		expect(await getFavicon("evilpaypal.com")).to.be.undefined;
	});
	it("Favicon is only defined for subdomain", async function () {
		expect(await getFavicon("comms.yahoo.net")).to.be.equal(iconUrl("yahoo.com.png"));
		expect(await getFavicon("yahoo.net")).to.be.undefined;
		expect(await getFavicon("foo.yahoo.net")).to.be.undefined;
	});
	it("Top domain has multiple parts", async function () {
		expect(await getFavicon("homeaffairs.gov.au")).to.be.equal(iconUrl("homeaffairs.gov.au.ico"));
		expect(await getFavicon("foo.homeaffairs.gov.au")).to.be.equal(iconUrl("homeaffairs.gov.au.ico"));
	});
	it("Casing should not matter", async function () {
		expect(await getFavicon("PayPal.com")).to.be.equal(iconUrl("paypal.com.ico"));
	});
});
