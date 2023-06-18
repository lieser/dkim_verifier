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
		expect(await getFavicon("paypal.com", undefined, null)).to.be.equal(iconUrl("paypal.com.ico"));
		expect(await getFavicon("news.paypal.com", undefined, null)).to.be.equal(iconUrl("paypal.com.ico"));
	});
	it("Domain is not in known favicons", async function () {
		expect(await getFavicon("foo.com", undefined, null)).to.be.undefined;
		expect(await getFavicon("evilpaypal.com", undefined, null)).to.be.undefined;
	});
	it("Favicon is only defined for subdomain", async function () {
		expect(await getFavicon("comms.yahoo.net", undefined, null)).to.be.equal(iconUrl("yahoo.com.png"));
		expect(await getFavicon("yahoo.net", undefined, null)).to.be.undefined;
		expect(await getFavicon("foo.yahoo.net", undefined, null)).to.be.undefined;
	});
	it("Top domain has multiple parts", async function () {
		expect(await getFavicon("homeaffairs.gov.au", undefined, null)).to.be.equal(iconUrl("homeaffairs.gov.au.ico"));
		expect(await getFavicon("foo.homeaffairs.gov.au", undefined, null)).to.be.equal(iconUrl("homeaffairs.gov.au.ico"));
	});
	it("Favicon is only defined for from or auid address", async function () {
		expect(await getFavicon("posteo.de", "@posteo.de", "support@posteo.de")).to.be.equal(iconUrl("posteo.de.png"));
		expect(await getFavicon("posteo.de", "support@posteo.de", "support@posteo.de")).to.be.equal(iconUrl("posteo.de.png"));
		expect(await getFavicon("posteo.de", undefined, "support@posteo.de")).to.be.equal(iconUrl("posteo.de.png"));
		expect(await getFavicon("posteo.de", "support@posteo.de", null)).to.be.equal(iconUrl("posteo.de.png"));

		expect(await getFavicon("posteo.de", undefined, "foo@posteo.de")).to.be.undefined;
		expect(await getFavicon("foo.de", undefined, "support@posteo.de")).to.be.undefined;
		expect(await getFavicon("posteo.de", "@posteo.de", null)).to.be.undefined;
		expect(await getFavicon("posteo.de", "foo@posteo.de", null)).to.be.undefined;
		expect(await getFavicon("posteo.de", undefined, null)).to.be.undefined;
	});
	it("Casing should not matter", async function () {
		expect(await getFavicon("PayPal.com", undefined, null)).to.be.equal(iconUrl("paypal.com.ico"));
		expect(await getFavicon("pOsteo.de", undefined, "SupPort@posTeo.de")).to.be.equal(iconUrl("posteo.de.png"));
		expect(await getFavicon("poSteo.de", "Support@Posteo.De", null)).to.be.equal(iconUrl("posteo.de.png"));
	});
});
