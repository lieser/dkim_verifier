/**
 * Copyright (c) 2021 Philippe Lieser
 *
 * This software is licensed under the terms of the MIT License.
 *
 * The above copyright and license notice shall be
 * included in all copies or substantial portions of the Software.
 */

// @ts-check

import DMARC from "../../modules/dkim/dmarc.mjs.js";
import { createTxtQueryCallback } from "../helpers/dnsStub.mjs.js";
import expect from "../helpers/chaiUtils.mjs.js";
import { hasWebExtensions } from "../helpers/initWebExtensions.mjs.js";
import prefs from "../../modules/preferences.mjs.js";

describe("DMARC [unittest]", function () {
	before(async function () {
		if (!hasWebExtensions) {
			// eslint-disable-next-line no-invalid-this
			this.skip();
		}
		await prefs.init();
	});

	describe("RFC 7489 Appendix B Example", function () {
		it("B.2.1.  Entire Domain, Monitoring Only", async function () {
			const dmarc = new DMARC(createTxtQueryCallback(new Map([
				["_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com"]
			])));

			let res = await dmarc.shouldBeSigned("foo@example.com");
			expect(res.shouldBeSigned).to.be.true;
			expect(res.sdid).to.be.deep.equal(["example.com"]);

			res = await dmarc.shouldBeSigned("foo@sub.example.com");
			expect(res.shouldBeSigned).to.be.true;
			expect(res.sdid).to.be.deep.equal(["sub.example.com", "example.com"]);

			res = await dmarc.shouldBeSigned("foo@example.org");
			expect(res.shouldBeSigned).to.be.false;
			expect(res.sdid).to.be.deep.equal([]);
		});
		it("B.2.2.  Entire Domain, Monitoring Only, Per-Message Reports", async function () {
			const dmarc = new DMARC(createTxtQueryCallback(new Map([
				["_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com; ruf=mailto:auth-reports@example.com"]
			])));

			let res = await dmarc.shouldBeSigned("foo@example.com");
			expect(res.shouldBeSigned).to.be.true;
			expect(res.sdid).to.be.deep.equal(["example.com"]);

			res = await dmarc.shouldBeSigned("foo@example.org");
			expect(res.shouldBeSigned).to.be.false;
			expect(res.sdid).to.be.deep.equal([]);
		});
		it("B.2.3.  Per-Message Failure Reports Directed to Third Party", async function () {
			const dmarc = new DMARC(createTxtQueryCallback(new Map([
				["_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com; ruf=mailto:auth-reports@thirdparty.example.net"]
			])));

			let res = await dmarc.shouldBeSigned("foo@example.com");
			expect(res.shouldBeSigned).to.be.true;
			expect(res.sdid).to.be.deep.equal(["example.com"]);

			res = await dmarc.shouldBeSigned("foo@example.org");
			expect(res.shouldBeSigned).to.be.false;
			expect(res.sdid).to.be.deep.equal([]);
		});
		it("B.2.4.  Subdomain, Sampling, and Multiple Aggregate Report URIs", async function () {
			const dmarc = new DMARC(createTxtQueryCallback(new Map([
				["_dmarc.example.com", "v=DMARC1; p=quarantine; rua=mailto:dmarc-feedback@example.com,mailto:tld-test@thirdparty.example.net!10m; pct=25"]
			])));

			let res = await dmarc.shouldBeSigned("foo@example.com");
			expect(res.shouldBeSigned).to.be.true;
			expect(res.sdid).to.be.deep.equal(["example.com"]);

			res = await dmarc.shouldBeSigned("foo@example.org");
			expect(res.shouldBeSigned).to.be.false;
			expect(res.sdid).to.be.deep.equal([]);
		});
		it("B.3.1.  Processing of SMTP Time", async function () {
			const dmarc = new DMARC(createTxtQueryCallback(new Map([
				["_dmarc.example.com", "v=DMARC1; p=reject; aspf=r; rua=mailto:dmarc-feedback@example.com"]
			])));

			let res = await dmarc.shouldBeSigned("foo@example.com");
			expect(res.shouldBeSigned).to.be.true;
			expect(res.sdid).to.be.deep.equal(["example.com"]);

			res = await dmarc.shouldBeSigned("foo@example.org");
			expect(res.shouldBeSigned).to.be.false;
			expect(res.sdid).to.be.deep.equal([]);
		});
	});
});
